use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, CompressedPublicKey, KnownHrp, Network};
use bip39::{Language, Mnemonic};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use std::str::FromStr;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid entropy length: expected 128 or 256 bits, got {0}")]
    InvalidEntropyLength(usize),
    #[error("BIP-39 error: {0}")]
    Bip39Error(#[from] bip39::Error),
    #[error("BIP-32 error: {0}")]
    Bip32Error(#[from] bitcoin::bip32::Error),
    #[error("Secp256k1 error: {0}")]
    Secp256k1Error(#[from] bitcoin::secp256k1::Error),
    #[error("HMAC key error")]
    HmacError,
}

/// Secure container for master entropy with automatic memory zeroization on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretEntropy {
    bytes: Vec<u8>,
}

impl SecretEntropy {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        if bytes.len() != 16 && bytes.len() != 32 {
            return Err(CryptoError::InvalidEntropyLength(bytes.len() * 8));
        }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone)]
pub struct GeneratedSeed {
    pub mnemonic: String,
    pub fingerprint: String,
    pub descriptor: String,
    pub vpub: String,
    pub addresses: Vec<String>,
    pub entropy_type: String,
}

#[derive(Debug, Clone)]
pub struct Bip85Child {
    pub label: String,
    pub index: u32,
    pub path: String,
    pub mnemonic: String,
}

/// Convert sanitized binary ("010101...") or dice ("164235...") input into 128-bit entropy bytes.
pub fn parse_physical_entropy(raw_input: &str) -> Result<(Vec<u8>, &'static str), CryptoError> {
    let clean: String = raw_input.chars().filter(|c| !c.is_whitespace() && *c != ',' && *c != '-').collect();
    
    // Binary Coin Flips (128 bits minimum for 12-word seed)
    if clean.chars().all(|c| c == '0' || c == '1') {
        if clean.len() < 128 {
            return Err(CryptoError::InvalidEntropyLength(clean.len()));
        }
        let take_128 = &clean[..128];
        let mut bytes = Vec::with_capacity(16);
        for chunk in take_128.as_bytes().chunks(8) {
            let byte_str = std::str::from_utf8(chunk).unwrap();
            let byte_val = u8::from_str_radix(byte_str, 2).map_err(|_| CryptoError::InvalidEntropyLength(clean.len()))?;
            bytes.push(byte_val);
        }
        return Ok((bytes, "Physical Coin Flips (128-bit Bin)"));
    }

    // 6-sided Dice Rolls (Base-6 to SHA-256 entropy whitening)
    if clean.chars().all(|c| ('1'..='6').contains(&c)) {
        if clean.len() < 50 {
            return Err(CryptoError::InvalidEntropyLength(clean.len()));
        }
        let hash = Sha256::digest(clean.as_bytes());
        return Ok((hash[..16].to_vec(), "Casino Dice Rolls (50+ Rolls)"));
    }

    // Hex string (16 bytes = 32 hex chars)
    if clean.len() == 32 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = hex::decode(&clean).map_err(|_| CryptoError::InvalidEntropyLength(clean.len()))?;
        return Ok((bytes, "Hardware TRNG / Raw Hex"));
    }

    Err(CryptoError::InvalidEntropyLength(clean.len()))
}

pub fn process_physical_entropy(raw_input: &str) -> Result<GeneratedSeed, CryptoError> {
    let (entropy_bytes, mode) = parse_physical_entropy(raw_input)?;
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy_bytes)?;
    let mnemonic_str = mnemonic.to_string();

    let seed = mnemonic.to_seed("");
    let secp = Secp256k1::new();
    let master_xprv = Xpriv::new_master(Network::Bitcoin, &seed)?;
    let master_fingerprint = master_xprv.fingerprint(&secp).to_string();

    let account_path = DerivationPath::from_str("m/84'/0'/0'")?;
    let account_xprv = master_xprv.derive_priv(&secp, &account_path)?;
    let account_xpub = Xpub::from_priv(&secp, &account_xprv);
    let vpub = account_xpub.to_string();

    let mut addresses = Vec::with_capacity(5);
    for idx in 0..5 {
        let recv_path = DerivationPath::from_str(&format!("m/84'/0'/0'/0/{}", idx))?;
        let key = master_xprv.derive_priv(&secp, &recv_path)?;
        let compressed_pk = CompressedPublicKey(key.to_keypair(&secp).public_key());
        let addr = Address::p2wpkh(&compressed_pk, KnownHrp::Mainnet);
        addresses.push(addr.to_string());
    }

    let descriptor = format!("wpkh([{}/84'/0'/0']{}/<0;1>/*)", master_fingerprint, account_xpub);

    Ok(GeneratedSeed {
        mnemonic: mnemonic_str,
        fingerprint: master_fingerprint,
        descriptor,
        vpub,
        addresses,
        entropy_type: mode.to_string(),
    })
}

pub fn derive_bip85_children(master_mnemonic_str: &str, count: u32) -> Result<Vec<Bip85Child>, CryptoError> {
    let mnemonic = Mnemonic::from_str(master_mnemonic_str)?;
    let seed = mnemonic.to_seed("");
    let secp = Secp256k1::new();
    let master_xprv = Xpriv::new_master(Network::Bitcoin, &seed)?;

    let mut children = Vec::new();
    for i in 1..=count {
        let path_str = format!("m/83696968'/39'/0'/12'/{}'", i);
        let path = DerivationPath::from_str(&path_str)?;
        let derived = master_xprv.derive_priv(&secp, &path)?;

        let mut hmac = HmacSha512::new_from_slice(b"bip-entropy-from-k").map_err(|_| CryptoError::HmacError)?;
        hmac.update(&derived.private_key.secret_bytes());
        let result = hmac.finalize().into_bytes();

        let child_entropy = &result[..16];
        let child_mnemonic = Mnemonic::from_entropy_in(Language::English, child_entropy)?;
        children.push(Bip85Child {
            label: format!("Heir / Vault #{i}"),
            index: i,
            path: path_str,
            mnemonic: child_mnemonic.to_string(),
        });
    }

    Ok(children)
}
