use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, CompressedPublicKey, KnownHrp, Network};
use bip39::{Language, Mnemonic};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::str::FromStr;
use zeroize::{Zeroize, ZeroizeOnDrop};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::prelude::*;
use serde::{Deserialize, Serialize};

type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid entropy length: expected 128 or 256 bits, got {0}")]
    InvalidEntropyLength(usize),
    #[error("Entropy failed Markov transition audit: {0}")]
    MarkovAuditFailed(String),
    #[error("Entropy contains repetitive substrings")]
    RepetitivePatternDetected,
    #[error("BIP-39 error: {0}")]
    Bip39Error(#[from] bip39::Error),
    #[error("BIP-32 error: {0}")]
    Bip32Error(#[from] bitcoin::bip32::Error),
    #[error("Secp256k1 error: {0}")]
    Secp256k1Error(#[from] bitcoin::secp256k1::Error),
    #[error("HMAC key error")]
    HmacError,
    #[error("Vault decryption error: {0}")]
    DecryptionError(String),
    #[error("Vault serialization error: {0}")]
    SerializationError(String),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bip85Child {
    pub label: String,
    pub index: u32,
    pub path: String,
    pub mnemonic: String,
}

#[derive(Debug, Clone)]
pub struct MarkovResult {
    pub passed: bool,
    pub max_cond_prob: f64,
    pub details: String,
}

/// Encrypted vault JSON container matching Node.js `subzero-keyosk` schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedVaultJson {
    pub format: String,
    pub cipher: String,
    pub kdf: String,
    pub iterations: u32,
    pub salt: String,
    pub iv: String,
    pub ciphertext: String,
}

/// Decrypted payload structure inside `vault.json`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedVaultPayload {
    pub version: String,
    pub created_utc: String,
    pub master_root_mnemonic: String,
    pub descriptor: String,
    pub heir_treasuries: Vec<Bip85Child>,
}

/// Encrypt an estate vault payload into WebCrypto-compatible AES-256-GCM + PBKDF2 JSON
pub fn encrypt_vault_payload(
    payload: &DecryptedVaultPayload,
    passphrase_mnemonic: &str,
) -> Result<String, CryptoError> {
    use rand::RngCore;

    let plaintext = serde_json::to_string_pretty(payload)
        .map_err(|e| CryptoError::SerializationError(e.to_string()))?;

    let mut salt = [0u8; 16];
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut iv);

    let normalized_pass = passphrase_mnemonic.trim().to_lowercase();
    let mut derived_key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        normalized_pass.as_bytes(),
        &salt,
        600_000,
        &mut derived_key,
    );

    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
    let nonce = Nonce::from_slice(&iv);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

    let vault = EncryptedVaultJson {
        format: "subzero-vault-v1".to_string(),
        cipher: "AES-256-GCM".to_string(),
        kdf: "PBKDF2-HMAC-SHA256".to_string(),
        iterations: 600_000,
        salt: BASE64_STANDARD.encode(salt),
        iv: BASE64_STANDARD.encode(iv),
        ciphertext: BASE64_STANDARD.encode(ciphertext),
    };

    serde_json::to_string_pretty(&vault)
        .map_err(|e| CryptoError::SerializationError(e.to_string()))
}

/// Decrypt an estate vault JSON container using the 12-word Decoupled Estate Passphrase
pub fn decrypt_vault_json(
    vault_json_str: &str,
    passphrase_mnemonic: &str,
) -> Result<DecryptedVaultPayload, CryptoError> {
    let vault: EncryptedVaultJson = serde_json::from_str(vault_json_str)
        .map_err(|e| CryptoError::SerializationError(format!("Invalid vault JSON format: {e}")))?;

    let salt = BASE64_STANDARD
        .decode(&vault.salt)
        .map_err(|e| CryptoError::DecryptionError(format!("Invalid base64 salt: {e}")))?;
    let iv = BASE64_STANDARD
        .decode(&vault.iv)
        .map_err(|e| CryptoError::DecryptionError(format!("Invalid base64 iv: {e}")))?;
    let ciphertext = BASE64_STANDARD
        .decode(&vault.ciphertext)
        .map_err(|e| CryptoError::DecryptionError(format!("Invalid base64 ciphertext: {e}")))?;

    if iv.len() != 12 {
        return Err(CryptoError::DecryptionError("IV must be 12 bytes for AES-GCM".into()));
    }

    let normalized_pass = passphrase_mnemonic.trim().to_lowercase();
    let mut derived_key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        normalized_pass.as_bytes(),
        &salt,
        vault.iterations,
        &mut derived_key,
    );

    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
    let nonce = Nonce::from_slice(&iv);

    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionError("Authentication failed: incorrect passphrase or corrupt ciphertext.".into()))?;

    let payload: DecryptedVaultPayload = serde_json::from_slice(&plaintext_bytes)
        .map_err(|e| CryptoError::SerializationError(format!("Corrupt payload JSON: {e}")))?;

    Ok(payload)
}

/// Run first-order Markov chain transition audit on physical entropy stream.
/// Rejects entropy if any transition probability is >= 0.85 (85%).
pub fn run_markov_audit(input: &str) -> MarkovResult {
    if input.len() < 16 {
        return MarkovResult {
            passed: false,
            max_cond_prob: 1.0,
            details: "Input length insufficient for statistical analysis (<16)".to_string(),
        };
    }

    let chars: Vec<char> = input.chars().collect();
    let mut counts: HashMap<char, HashMap<char, usize>> = HashMap::new();
    let mut totals: HashMap<char, usize> = HashMap::new();

    for i in 0..chars.len() - 1 {
        let prev = chars[i];
        let next = chars[i + 1];

        *counts.entry(prev).or_default().entry(next).or_insert(0) += 1;
        *totals.entry(prev).or_insert(0) += 1;
    }

    let mut max_cond_prob = 0.0f64;
    for (prev, next_map) in &counts {
        let total = totals[prev] as f64;
        for (_next, &cnt) in next_map {
            let prob = (cnt as f64) / total;
            if prob > max_cond_prob {
                max_cond_prob = prob;
            }
        }
    }

    let passed = max_cond_prob < 0.85;
    let pct = (max_cond_prob * 100.0).round() as u32;
    let details = if passed {
        format!("Markov audit passed: Max conditional probability {}% (<85%)", pct)
    } else {
        format!("Markov audit failed: Extreme transition bias detected ({}% >= 85%)", pct)
    };

    MarkovResult {
        passed,
        max_cond_prob,
        details,
    }
}

/// Detect repeating substring patterns or long runs of human typing bias.
/// For binary bitstreams, checking tiny 3-bit chunks produces ~70% false positives on pure entropy.
/// We check single-character runs >= 12, or alternating chunks of size 2..8 repeating 4-8 times.
pub fn has_repetitive_substrings(input: &str, min_chunk: usize, max_chunk: usize) -> bool {
    let chars: Vec<char> = input.chars().collect();
    if chars.len() < min_chunk * 3 {
        return false;
    }

    let is_bin = chars.iter().all(|&c| c == '0' || c == '1');
    if is_bin {
        if input.contains("000000000000") || input.contains("111111111111") {
            return true;
        }
        for size in 2..=8 {
            let reps = if size == 2 { 8 } else if size == 3 { 6 } else if size == 4 { 5 } else { 4 };
            if chars.len() < size * reps {
                continue;
            }
            for i in 0..=chars.len() - (size * reps) {
                let chunk = &chars[i..i + size];
                let mut match_found = true;
                for rep in 1..reps {
                    let next_chunk = &chars[i + (rep * size)..i + (rep * size) + size];
                    if chunk != next_chunk {
                        match_found = false;
                        break;
                    }
                }
                if match_found {
                    return true;
                }
            }
        }
        return false;
    }

    // Casino dice rolls (1-6) or general base: 3 consecutive repetitions of chunks size 3..6
    for size in min_chunk..=max_chunk {
        if chars.len() < size * 3 {
            continue;
        }
        for i in 0..=chars.len() - (size * 3) {
            let chunk = &chars[i..i + size];
            let mut match_found = true;
            for rep in 1..3 {
                let next_chunk = &chars[i + (rep * size)..i + (rep * size) + size];
                if chunk != next_chunk {
                    match_found = false;
                    break;
                }
            }
            if match_found {
                return true;
            }
        }
    }
    false
}

/// Canonical BIP-380 Descriptor Checksum polymod generator.
/// Matches Bitcoin Core src/script/descriptor.cpp DescriptorChecksum implementation.
pub fn get_descriptor_checksum(desc: &str) -> String {
    const INPUT_CHARSET: &[u8] = b"0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const POLYMOD_GEN: [u64; 5] = [
        0xf5dee51989,
        0xa9fdca3312,
        0x1bab10e32d,
        0x3706b1677a,
        0x644d626ffd,
    ];

    fn polymod(mut c: u64, val: u64) -> u64 {
        let c0 = c >> 35;
        c = ((c & 0x7ffffffff) << 5) ^ val;
        for i in 0..5 {
            if ((c0 >> i) & 1) != 0 {
                c ^= POLYMOD_GEN[i];
            }
        }
        c
    }

    let mut c = 1u64;
    let mut cls = 0u64;
    let mut clscount = 0;

    for &b in desc.as_bytes() {
        let pos = match INPUT_CHARSET.iter().position(|&x| x == b) {
            Some(p) => p as u64,
            None => return String::new(),
        };
        c = polymod(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        clscount += 1;
        if clscount == 3 {
            c = polymod(c, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if clscount > 0 {
        c = polymod(c, cls);
    }
    for _ in 0..8 {
        c = polymod(c, 0);
    }
    c ^= 1;

    let mut ret = String::with_capacity(8);
    for j in 0..8 {
        let idx = ((c >> (5 * (7 - j))) & 31) as usize;
        ret.push(CHECKSUM_CHARSET[idx] as char);
    }
    ret
}

/// Canonical Test Vectors (test0 .. test9) from SubZero Testnet4 specification
pub fn get_test_vector(id: u8) -> Result<(Vec<u8>, &'static str), CryptoError> {
    match id {
        0 => Ok((vec![0x00; 16], "TEST VECTOR 0 (BIP-39 BASELINE: ALL ZEROS 0x00)")),
        1 => Ok((vec![0x55; 16], "TEST VECTOR 1 (ALTERNATING 0x55)")),
        2 => Ok((vec![0xAA; 16], "TEST VECTOR 2 (ALTERNATING 0xAA)")),
        3 => Ok((vec![0x7F; 16], "TEST VECTOR 3 (SIGNED BYTE BOUNDARY 0x7F)")),
        4 => Ok((vec![0x80; 16], "TEST VECTOR 4 (HIGH-BIT BOUNDARY 0x80)")),
        5 => Ok((vec![0xFF; 16], "TEST VECTOR 5 (ALL-ONES BOUNDARY 0xFF / ZOO)")),
        6 => Ok((
            vec![0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef],
            "TEST VECTOR 6 (INCREMENTAL NIBBLES 0x0123...)"
        )),
        7 => Ok((
            vec![0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f],
            "TEST VECTOR 7 (SEQUENTIAL BYTES 0x0001...)"
        )),
        8 => {
            let hash = Sha256::digest(b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks");
            Ok((hash[..16].to_vec(), "TEST VECTOR 8 (SATOSHI GENESIS LORE: TIMES 2009)"))
        },
        9 => {
            let hash = Sha256::digest(b"Running bitcoin - Hal Finney 10 Jan 2009");
            Ok((hash[..16].to_vec(), "TEST VECTOR 9 (HAL FINNEY LORE: RUNNING BITCOIN)"))
        },
        _ => Err(CryptoError::InvalidEntropyLength(0)),
    }
}

/// Generate 128 pseudo-random bits from device PRNG (Testing Only) formatted as a binary string.
/// Convenience utility for testing dynamic wallets without pre-funded test vectors.
pub fn generate_random_128bit_binary() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut bits = String::with_capacity(128);
    for b in bytes {
        for i in (0..8).rev() {
            bits.push(if (b >> i) & 1 == 1 { '1' } else { '0' });
        }
    }
    bits
}

/// Convert sanitized binary ("010101...") or dice ("164235...") input into 128-bit entropy bytes.
pub fn parse_physical_entropy(raw_input: &str) -> Result<(Vec<u8>, &'static str), CryptoError> {
    let clean: String = raw_input.chars().filter(|c| !c.is_whitespace() && *c != ',' && *c != '-').collect();
    let lower = clean.to_lowercase();

    // Check for test0..test9 keywords
    if lower == "test" || lower == "test0" {
        return get_test_vector(0);
    }
    if lower.starts_with("test") && lower.len() == 5 {
        if let Some(digit) = lower.chars().nth(4).and_then(|c| c.to_digit(10)) {
            if digit <= 9 {
                return get_test_vector(digit as u8);
            }
        }
    }

    // Mathematical Quality Hard-Blocks (ENTROPY_QUALITY_HARD_BLOCK)
    // Run Markov and repetition checks on raw streams >= 16 chars
    if clean.len() >= 16 {
        let markov = run_markov_audit(&clean);
        if !markov.passed {
            return Err(CryptoError::MarkovAuditFailed(markov.details));
        }
        if has_repetitive_substrings(&clean, 3, 6) {
            return Err(CryptoError::RepetitivePatternDetected);
        }
    }
    
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

/// Process physical entropy to generate a Testnet4 (BIP-84 Native SegWit `tb1q...`) vault suite.
pub fn process_physical_entropy(raw_input: &str) -> Result<GeneratedSeed, CryptoError> {
    let (entropy_bytes, mode) = parse_physical_entropy(raw_input)?;
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy_bytes)?;
    let mnemonic_str = mnemonic.to_string();

    let seed = mnemonic.to_seed("");
    let secp = Secp256k1::new();
    
    // Default network: Testnet4 (bip-0094 / testnet)
    let master_xprv = Xpriv::new_master(Network::Testnet4, &seed)?;
    let master_fingerprint = master_xprv.fingerprint(&secp).to_string();

    // BIP-84 Native SegWit Testnet path: m/84'/1'/0'
    let account_path = DerivationPath::from_str("m/84'/1'/0'")?;
    let account_xprv = master_xprv.derive_priv(&secp, &account_path)?;
    let account_xpub = Xpub::from_priv(&secp, &account_xprv);
    let vpub = account_xpub.to_string();

    // Derive first 5 tb1q Receive Addresses: m/84'/1'/0'/0/{0..4}
    let mut addresses = Vec::with_capacity(5);
    for idx in 0..5 {
        let recv_path = DerivationPath::from_str(&format!("m/84'/1'/0'/0/{}", idx))?;
        let key = master_xprv.derive_priv(&secp, &recv_path)?;
        let compressed_pk = CompressedPublicKey(key.to_keypair(&secp).public_key());
        let addr = Address::p2wpkh(&compressed_pk, KnownHrp::Testnets);
        addresses.push(addr.to_string());
    }

    let raw_descriptor = format!("wpkh([{}/84'/1'/0']{}/<0;1>/*)", master_fingerprint, account_xpub);
    let checksum = get_descriptor_checksum(&raw_descriptor);
    let descriptor = if checksum.is_empty() {
        raw_descriptor
    } else {
        format!("{}#{}", raw_descriptor, checksum)
    };

    Ok(GeneratedSeed {
        mnemonic: mnemonic_str,
        fingerprint: master_fingerprint,
        descriptor,
        vpub,
        addresses,
        entropy_type: mode.to_string(),
    })
}

/// Derive BIP-85 child keys, explicitly starting with Index 0 (Decoupled Estate Passphrase)
/// followed by indices 1..=count (Heir & Vault Keys).
pub fn derive_bip85_children(master_mnemonic_str: &str, count: u32) -> Result<Vec<Bip85Child>, CryptoError> {
    let mnemonic = Mnemonic::from_str(master_mnemonic_str)?;
    let seed = mnemonic.to_seed("");
    let secp = Secp256k1::new();
    let master_xprv = Xpriv::new_master(Network::Testnet4, &seed)?;

    let mut children = Vec::new();

    // Index 0: Dedicated Decoupled Estate Passphrase
    {
        let path_str = "m/83696968'/39'/0'/12'/0'".to_string();
        let path = DerivationPath::from_str(&path_str)?;
        let derived = master_xprv.derive_priv(&secp, &path)?;
        let mut hmac: HmacSha512 = Mac::new_from_slice(b"bip-entropy-from-k").map_err(|_| CryptoError::HmacError)?;
        hmac.update(&derived.private_key.secret_bytes());
        let result = hmac.finalize().into_bytes();
        let child_entropy = &result[..16];
        let child_mnemonic = Mnemonic::from_entropy_in(Language::English, child_entropy)?;
        children.push(Bip85Child {
            label: "Decoupled Estate Passphrase (Index 0)".to_string(),
            index: 0,
            path: path_str,
            mnemonic: child_mnemonic.to_string(),
        });
    }

    // Indices 1..=count: Heir & Vault keys
    for i in 1..=count {
        let path_str = format!("m/83696968'/39'/0'/12'/{}'", i);
        let path = DerivationPath::from_str(&path_str)?;
        let derived = master_xprv.derive_priv(&secp, &path)?;

        let mut hmac: HmacSha512 = Mac::new_from_slice(b"bip-entropy-from-k").map_err(|_| CryptoError::HmacError)?;
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
