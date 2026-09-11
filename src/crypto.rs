use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, CompressedPublicKey, KnownHrp, Network};
use bip39::{Language, Mnemonic};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::str::FromStr;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
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
    #[error("Entropy failed Chi-squared uniformity audit: {0}")]
    ChiSquaredAuditFailed(String),
    #[error("Entropy contains repetitive substrings")]
    RepetitivePatternDetected,
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),
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
#[allow(dead_code)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretEntropy {
    bytes: Vec<u8>,
}

#[allow(dead_code)]
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

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct GeneratedSeed {
    pub mnemonic: String,
    pub fingerprint: String,
    pub descriptor: String,
    pub vpub: String,          // Raw BIP-32 account extended public key (tpub...)
    pub vpub_slip132: String, // SLIP-0132 Native SegWit BIP-84 account key (vpub...)
    pub addresses: Vec<String>,
    pub entropy_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Bip85Child {
    pub label: String,
    pub index: u32,
    pub path: String,
    pub mnemonic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bip85ChildPublic {
    pub index: u32,
    pub path: String,
    pub label: String,
    pub fingerprint: String,
    pub xpub: String,          // BIP-32 account extended public key (tpub...)
    pub vpub_slip132: String,  // SLIP-0132 Native SegWit BIP-84 account key (vpub...)
    pub descriptor: String,    // BIP-380 Native SegWit watch-only descriptor
    pub first_address: String, // First receive address (tb1q...)
}

impl Bip85Child {
    /// Derive watch-only public keys (xpub, SLIP-0132 vpub, descriptor) from child mnemonic.
    /// Security invariant: Zero private keys are exposed or retained in the output.
    pub fn derive_public_keys(&self) -> Result<Bip85ChildPublic, CryptoError> {
        let mnemonic = Mnemonic::from_str(&self.mnemonic)?;
        let seed = Zeroizing::new(mnemonic.to_seed(""));
        let secp = Secp256k1::new();
        let master_xprv = Xpriv::new_master(Network::Testnet4, seed.as_ref())?;
        let master_fingerprint = master_xprv.fingerprint(&secp).to_string();

        let account_path = DerivationPath::from_str("m/84'/1'/0'")?;
        let account_xprv = master_xprv.derive_priv(&secp, &account_path)?;
        let account_xpub = Xpub::from_priv(&secp, &account_xprv);
        let _ = account_xprv;
        let _ = master_xprv;

        let xpub_str = account_xpub.to_string();

        let mut raw_bytes = account_xpub.encode();
        raw_bytes[0] = 0x04;
        raw_bytes[1] = 0x5f;
        raw_bytes[2] = 0x1c;
        raw_bytes[3] = 0xf6;
        let vpub_slip132 = bitcoin::base58::encode_check(&raw_bytes);

        let recv_branch = account_xpub.derive_pub(&secp, &DerivationPath::from_str("0")?)?;
        let child_key = recv_branch.derive_pub(&secp, &DerivationPath::from_str("0")?)?;
        let compressed_pk = CompressedPublicKey(child_key.public_key);
        let first_address = Address::p2wpkh(&compressed_pk, KnownHrp::Testnets).to_string();

        let raw_descriptor = format!("wpkh([{}/84'/1'/0']{}/<0;1>/*)", master_fingerprint, account_xpub);
        let checksum = get_descriptor_checksum(&raw_descriptor);
        let descriptor = if checksum.is_empty() {
            raw_descriptor
        } else {
            format!("{}#{}", raw_descriptor, checksum)
        };

        Ok(Bip85ChildPublic {
            index: self.index,
            path: self.path.clone(),
            label: self.label.clone(),
            fingerprint: master_fingerprint,
            xpub: xpub_str,
            vpub_slip132,
            descriptor,
            first_address,
        })
    }
}

#[allow(dead_code)]
pub fn derive_bip85_child_public_keys(child_mnemonic: &str) -> Result<Bip85ChildPublic, CryptoError> {
    let dummy = Bip85Child {
        label: "Child Public Derivation".to_string(),
        index: 1,
        path: "m/83696968'/39'/0'/12'/1'".to_string(),
        mnemonic: child_mnemonic.to_string(),
    };
    dummy.derive_public_keys()
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
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
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
    let plaintext = zeroize::Zeroizing::new(serde_json::to_string_pretty(payload)
        .map_err(|e| CryptoError::SerializationError(e.to_string()))?);

    // Pure Physical Entropy Invariant:
    // Do NOT call rand::thread_rng() or /dev/urandom.
    // Derive AES-256-GCM IV (12 bytes) and PBKDF2 Salt (16 bytes) deterministically from
    // HMAC-SHA256 over master_root_mnemonic keyed by domain separation tags.
    let mut hmac_salt: Hmac<Sha256> = Mac::new_from_slice(b"subzero:vault:pbkdf2:salt:v1")
        .map_err(|_| CryptoError::HmacError)?;
    hmac_salt.update(payload.master_root_mnemonic.trim().as_bytes());
    let salt_hash = hmac_salt.finalize().into_bytes();
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&salt_hash[..16]);

    let mut hmac_iv: Hmac<Sha256> = Mac::new_from_slice(b"subzero:vault:aes-gcm:iv:v1")
        .map_err(|_| CryptoError::HmacError)?;
    hmac_iv.update(payload.master_root_mnemonic.trim().as_bytes());
    hmac_iv.update(passphrase_mnemonic.trim().as_bytes());
    let iv_hash = hmac_iv.finalize().into_bytes();
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_hash[..12]);

    let normalized_pass: String = passphrase_mnemonic
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();

    let mut derived_key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        normalized_pass.as_bytes(),
        &salt,
        600_000,
        &mut derived_key,
    );

    let cipher_res = Aes256Gcm::new_from_slice(&derived_key);
    derived_key.zeroize();
    let cipher = cipher_res.map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
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

    let normalized_pass: String = passphrase_mnemonic
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();

    let mut derived_key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        normalized_pass.as_bytes(),
        &salt,
        vault.iterations,
        &mut derived_key,
    );

    let cipher_res = Aes256Gcm::new_from_slice(&derived_key);
    derived_key.zeroize();
    let cipher = cipher_res.map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
    let nonce = Nonce::from_slice(&iv);

    let plaintext_bytes = zeroize::Zeroizing::new(cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionError("Authentication failed: incorrect passphrase or corrupt ciphertext.".into()))?);

    let payload: DecryptedVaultPayload = serde_json::from_slice(&plaintext_bytes)
        .map_err(|e| CryptoError::SerializationError(format!("Corrupt payload JSON: {e}")))?;

    Ok(payload)
}

/// Run first-order Markov chain transition audit on physical entropy stream.
/// Alphabet-aware:
/// - Binary coin flips (0/1): Max allowed conditional transition probability is 80% (0.80).
/// - 6-sided dice rolls (1-6): Max allowed conditional transition probability is 75% (0.75) for transitions with >= 2 occurrences.
/// - Generic streams: Max allowed conditional transition probability is 85% (0.85).
pub fn run_markov_audit(input: &str) -> MarkovResult {
    if input.len() < 16 {
        return MarkovResult {
            passed: false,
            max_cond_prob: 1.0,
            details: "Input length insufficient for statistical analysis (<16)".to_string(),
        };
    }

    let is_bin = input.chars().all(|c| c == '0' || c == '1');
    let is_dice = input.chars().all(|c| ('1'..='6').contains(&c));
    let threshold = if is_bin {
        0.80
    } else if is_dice {
        0.75
    } else {
        0.85
    };

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
    let min_obs = if is_dice { 3.0 } else { 2.0 };
    for (prev, next_map) in &counts {
        let total = totals[prev] as f64;
        if total < min_obs {
            continue;
        }
        for (_next, &cnt) in next_map {
            let prob = (cnt as f64) / total;
            if prob > max_cond_prob {
                max_cond_prob = prob;
            }
        }
    }

    let passed = max_cond_prob <= threshold;
    let pct = (max_cond_prob * 100.0).round() as u32;
    let thresh_pct = (threshold * 100.0).round() as u32;
    let details = if passed {
        format!("Markov audit passed: Max conditional probability {}% (<= {}%)", pct, thresh_pct)
    } else {
        format!("Markov audit failed: Extreme transition bias detected ({}% > {}%)", pct, thresh_pct)
    };

    MarkovResult {
        passed,
        max_cond_prob,
        details,
    }
}

/// Run Pearson's Chi-squared goodness-of-fit uniformity audit on physical entropy stream.
/// For binary (coin flips, df=1), critical value at p=0.001 is 10.828.
/// For 6-sided dice (df=5), critical value at p=0.001 is 20.515.
pub fn run_chi_squared_audit(input: &str) -> (bool, f64, String) {
    let clean: String = input.chars().filter(|c| !c.is_whitespace() && *c != ',' && *c != '-').collect();
    let n = clean.len();
    if n < 16 {
        return (true, 0.0, "Input length insufficient (<16) for Chi-squared audit".into());
    }

    let is_bin = clean.chars().all(|c| c == '0' || c == '1');
    let is_dice = clean.chars().all(|c| ('1'..='6').contains(&c));

    if is_bin {
        let count_1 = clean.chars().filter(|&c| c == '1').count() as f64;
        let count_0 = (n as f64) - count_1;
        let expected = (n as f64) / 2.0;
        let chi2 = ((count_0 - expected).powi(2) / expected) + ((count_1 - expected).powi(2) / expected);
        let crit = 10.828; // p = 0.001, df = 1
        let passed = chi2 <= crit;
        let details = if passed {
            format!("Chi-squared passed: χ² = {:.2} (<= {:.2}, p=0.001)", chi2, crit)
        } else {
            format!("Chi-squared failed: Non-uniform bit distribution (χ² = {:.2} > {:.2})", chi2, crit)
        };
        (passed, chi2, details)
    } else if is_dice {
        let mut counts = [0usize; 6];
        for c in clean.chars() {
            if let Some(digit) = c.to_digit(10) {
                if (1..=6).contains(&digit) {
                    counts[(digit - 1) as usize] += 1;
                }
            }
        }
        let expected = (n as f64) / 6.0;
        let mut chi2 = 0.0;
        for &cnt in &counts {
            chi2 += ((cnt as f64 - expected).powi(2)) / expected;
        }
        let crit = 20.515; // p = 0.001, df = 5
        let passed = chi2 <= crit;
        let details = if passed {
            format!("Chi-squared passed: χ² = {:.2} (<= {:.2}, p=0.001)", chi2, crit)
        } else {
            format!("Chi-squared failed: Non-uniform dice distribution (χ² = {:.2} > {:.2})", chi2, crit)
        };
        (passed, chi2, details)
    } else {
        (true, 0.0, "Non-standard alphabet skipped Chi-squared".into())
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
        // Block large repeated blocks (e.g., 16..=64 bits repeated >= 2 times)
        for size in 16..=(chars.len() / 2) {
            for i in 0..=chars.len() - (size * 2) {
                if chars[i..i + size] == chars[i + size..i + (2 * size)] {
                    return true;
                }
            }
        }
        return false;
    }

    // Standard dice rolls (1-6) or general base: 3 consecutive repetitions of chunks size 3..6
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

    // Block structured period patterns for dice/general (chunks size 8..=len/2 repeated >= 2 times)
    for size in 8..=(chars.len() / 2) {
        for i in 0..=chars.len() - (size * 2) {
            if chars[i..i + size] == chars[i + size..i + (2 * size)] {
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

/// Derive 128 pseudo-random bits from human keystroke timing jitter.
/// Takes a slice of (key_char, elapsed_nanos) collected during user typing.
/// Hashed with SHA-256 into 128 binary coin flips (0/1).
/// ZERO hardware/kernel PRNG queries: pure userspace human timing jitter.
pub fn harvest_keystroke_jitter_to_binary(samples: &[(char, u64)]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"subzero:entropy:keystroke_jitter:v1");
    for (ch, nanos) in samples {
        hasher.update(ch.to_string().as_bytes());
        hasher.update(&nanos.to_le_bytes());
    }
    let hash = hasher.finalize();
    let mut bits = String::with_capacity(128);
    // Use first 16 bytes (128 bits) of the 256-bit SHA-256 digest
    for &b in &hash[..16] {
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
    // Run Markov, Chi-squared, and repetition checks on raw streams >= 16 chars
    if clean.len() >= 16 {
        let markov = run_markov_audit(&clean);
        if !markov.passed {
            return Err(CryptoError::MarkovAuditFailed(markov.details));
        }
        let (chi2_pass, _chi2_val, chi2_details) = run_chi_squared_audit(&clean);
        if !chi2_pass {
            return Err(CryptoError::ChiSquaredAuditFailed(chi2_details));
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

    // 6-sided Dice Rolls (Base-6 to SHA-256 entropy hashing, 50 rolls minimum for >= 129 bits min-entropy)
    if clean.chars().all(|c| ('1'..='6').contains(&c)) {
        if clean.len() < 50 {
            return Err(CryptoError::InvalidEntropyLength(clean.len()));
        }
        let hash = Sha256::digest(clean.as_bytes());
        return Ok((hash[..16].to_vec(), "Standard Dice Rolls (50+ Rolls)"));
    }

    // Hex string (16 bytes = 32 hex chars, or 32 bytes = 64 hex chars)
    if (clean.len() == 32 || clean.len() == 64) && clean.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = hex::decode(&clean).map_err(|_| CryptoError::InvalidEntropyLength(clean.len()))?;
        let label = if clean.len() == 32 {
            "Hardware TRNG / Raw Hex (128-bit)"
        } else {
            "Hardware TRNG / Raw Hex (256-bit)"
        };
        return Ok((bytes, label));
    }

    Err(CryptoError::InvalidEntropyLength(clean.len()))
}

/// Process physical entropy to generate a Testnet4 (BIP-84 Native SegWit `tb1q...`) vault suite.
pub fn process_physical_entropy(raw_input: &str) -> Result<GeneratedSeed, CryptoError> {
    let (entropy_bytes, mode) = parse_physical_entropy(raw_input)?;
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy_bytes)?;
    let mnemonic_str = mnemonic.to_string();

    let seed = Zeroizing::new(mnemonic.to_seed(""));
    let secp = Secp256k1::new();
    
    // Default network: Testnet4 (bip-0094 / testnet)
    let master_xprv = Xpriv::new_master(Network::Testnet4, seed.as_ref())?;
    let master_fingerprint = master_xprv.fingerprint(&secp).to_string();

    // BIP-84 Native SegWit Testnet path: m/84'/1'/0'
    let account_path = DerivationPath::from_str("m/84'/1'/0'")?;
    let account_xprv = master_xprv.derive_priv(&secp, &account_path)?;
    let account_xpub = Xpub::from_priv(&secp, &account_xprv);
    let vpub = account_xpub.to_string(); // raw BIP-32 tpub...

    // SLIP-0132 VPUB for Native SegWit (vpub... version bytes 0x045f1cf6)
    let mut raw_bytes = account_xpub.encode();
    raw_bytes[0] = 0x04;
    raw_bytes[1] = 0x5f;
    raw_bytes[2] = 0x1c;
    raw_bytes[3] = 0xf6;
    let vpub_slip132 = bitcoin::base58::encode_check(&raw_bytes);

    // Derive first 50 tb1q Receive Addresses using account_xpub public derivation (zero private child keys on stack)
    let recv_branch = account_xpub.derive_pub(&secp, &DerivationPath::from_str("0")?)?;
    let mut addresses = Vec::with_capacity(50);
    for idx in 0..50 {
        let child_key = recv_branch.derive_pub(&secp, &DerivationPath::from_str(&format!("{}", idx))?)?;
        let compressed_pk = CompressedPublicKey(child_key.public_key);
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
        vpub_slip132,
        addresses,
        entropy_type: mode.to_string(),
    })
}

/// Derive BIP-85 child keys, explicitly starting with Index 0 (Decoupled Estate Passphrase)
/// followed by indices 1..=count (Heir & Vault Keys).
pub fn derive_bip85_children(master_mnemonic_str: &str, count: u32) -> Result<Vec<Bip85Child>, CryptoError> {
    let mnemonic = Mnemonic::from_str(master_mnemonic_str)?;
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    let secp = Secp256k1::new();
    let master_xprv = Xpriv::new_master(Network::Testnet4, seed.as_ref())?;

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
            label: format!("Seed #{:02}", i),
            index: i,
            path: path_str,
            mnemonic: child_mnemonic.to_string(),
        });
    }

    Ok(children)
}

/// Convert a 12-word BIP-39 mnemonic into a 48-digit CompactSeedQR string (4 digits per word, 0000-2047).
pub fn mnemonic_to_compact_seed_qr(mnemonic: &str) -> Result<String, CryptoError> {
    let clean = mnemonic.split_whitespace().collect::<Vec<_>>();
    if clean.len() != 12 {
        return Err(CryptoError::InvalidMnemonic(format!(
            "CompactSeedQR requires exactly 12 words (got {})",
            clean.len()
        )));
    }
    let wordlist = bip39::Language::English.word_list();
    let mut digits = String::with_capacity(48);
    for w in &clean {
        let lower = w.to_lowercase();
        match wordlist.iter().position(|&x| x == lower) {
            Some(idx) => digits.push_str(&format!("{:04}", idx)),
            None => {
                return Err(CryptoError::InvalidMnemonic(format!(
                    "'{}' is not in BIP-39 English dictionary",
                    w
                )))
            }
        }
    }
    Ok(digits)
}

/// Convert a 48-digit CompactSeedQR string into a 12-word BIP-39 mnemonic.
pub fn compact_seed_qr_to_mnemonic(digits: &str) -> Result<String, CryptoError> {
    let clean: String = digits.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    if clean.len() != 48 || !clean.chars().all(|c| c.is_ascii_digit()) {
        return Err(CryptoError::InvalidMnemonic(format!(
            "CompactSeedQR must be exactly 48 decimal digits (got {})",
            clean.len()
        )));
    }
    let wordlist = bip39::Language::English.word_list();
    let mut words = Vec::with_capacity(12);
    for i in 0..12 {
        let chunk = &clean[i * 4..(i + 1) * 4];
        let idx: usize = chunk.parse().map_err(|_| {
            CryptoError::InvalidMnemonic(format!("Invalid numeric chunk in CompactSeedQR: {}", chunk))
        })?;
        if idx >= wordlist.len() {
            return Err(CryptoError::InvalidMnemonic(format!(
                "Word index {} exceeds BIP-39 dictionary size (2048)",
                idx
            )));
        }
        words.push(wordlist[idx]);
    }
    let phrase = words.join(" ");
    let _ = bip39::Mnemonic::from_str(&phrase)?;
    Ok(phrase)
}

/// Process an existing offline 12-word BIP-39 mnemonic, 48-digit CompactSeedQR, or BIP-380 Output Descriptor.
pub fn process_mnemonic_phrase(raw_input: &str) -> Result<GeneratedSeed, CryptoError> {
    let trimmed = raw_input.trim();
    if trimmed.starts_with("wpkh(") || trimmed.starts_with("tpub") || trimmed.starts_with("vpub") {
        return process_watch_only_descriptor(trimmed);
    }
    let digits_only: String = trimmed.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    let (clean, was_compact) = if digits_only.len() == 48 && digits_only.chars().all(|c| c.is_ascii_digit()) {
        (compact_seed_qr_to_mnemonic(&digits_only)?, true)
    } else {
        (
            raw_input
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase(),
            false,
        )
    };

    let words: Vec<&str> = clean.split_whitespace().collect();
    if words.len() != 12 {
        return Err(CryptoError::InvalidMnemonic(format!(
            "Mnemonic must be exactly 12 words (got {})",
            words.len()
        )));
    }

    let wordlist = bip39::Language::English.word_list();
    for w in &words {
        if !wordlist.contains(w) {
            return Err(CryptoError::InvalidMnemonic(format!(
                "'{}' is not a valid BIP-39 English dictionary word",
                w
            )));
        }
    }

    let mnemonic = Mnemonic::from_str(&clean)?;
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    let secp = Secp256k1::new();

    let master_xprv = Xpriv::new_master(Network::Testnet4, seed.as_ref())?;
    let master_fingerprint = master_xprv.fingerprint(&secp).to_string();

    let account_path = DerivationPath::from_str("m/84'/1'/0'")?;
    let account_xprv = master_xprv.derive_priv(&secp, &account_path)?;
    let account_xpub = Xpub::from_priv(&secp, &account_xprv);
    let vpub = account_xpub.to_string();

    let mut raw_bytes = account_xpub.encode();
    raw_bytes[0] = 0x04;
    raw_bytes[1] = 0x5f;
    raw_bytes[2] = 0x1c;
    raw_bytes[3] = 0xf6;
    let vpub_slip132 = bitcoin::base58::encode_check(&raw_bytes);

    let recv_branch = account_xpub.derive_pub(&secp, &DerivationPath::from_str("0")?)?;
    let mut addresses = Vec::with_capacity(50);
    for idx in 0..50 {
        let child_key = recv_branch.derive_pub(&secp, &DerivationPath::from_str(&format!("{}", idx))?)?;
        let compressed_pk = CompressedPublicKey(child_key.public_key);
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

    let mode_label = if was_compact {
        "Imported Offline CompactSeedQR (48-Digit Numeric)".to_string()
    } else {
        "Imported Offline 12-Word BIP-39 Mnemonic".to_string()
    };

    Ok(GeneratedSeed {
        mnemonic: clean,
        fingerprint: master_fingerprint,
        descriptor,
        vpub,
        vpub_slip132,
        addresses,
        entropy_type: mode_label,
    })
}

/// Process a watch-only BIP-380 Output Descriptor or raw tpub/vpub without private keys.
pub fn process_watch_only_descriptor(raw_input: &str) -> Result<GeneratedSeed, CryptoError> {
    let clean = raw_input.trim();
    if clean.is_empty() {
        return Err(CryptoError::InvalidMnemonic("Input descriptor cannot be empty".into()));
    }

    // Strip and verify checksum if present (after '#')
    let base_desc = if let Some(idx) = clean.find('#') {
        let (desc_part, check_part) = clean.split_at(idx);
        let check_part = &check_part[1..]; // skip '#'
        let expected = get_descriptor_checksum(desc_part);
        if !expected.is_empty() && !check_part.is_empty() && check_part != expected {
            return Err(CryptoError::InvalidMnemonic(format!(
                "Descriptor checksum mismatch: expected #{} (got #{})",
                expected, check_part
            )));
        }
        desc_part
    } else {
        clean
    };

    // Extract key origin [fingerprint/path] and xpub string
    let secp = Secp256k1::new();
    let (fingerprint, xpub_str) = if base_desc.starts_with("wpkh(") && base_desc.ends_with(')') {
        let inner = &base_desc[5..base_desc.len() - 1]; // inside wpkh(...)
        let key_expr = if let Some(slash_idx) = inner.rfind("/<0;1>/*") {
            &inner[..slash_idx]
        } else if let Some(slash_idx) = inner.rfind("/*") {
            &inner[..slash_idx]
        } else {
            inner
        };

        if key_expr.starts_with('[') {
            if let Some(bracket_end) = key_expr.find(']') {
                let origin = &key_expr[1..bracket_end];
                let key = &key_expr[bracket_end + 1..];
                let fprint = origin.split('/').next().unwrap_or("00000000").to_string();
                (fprint, key.to_string())
            } else {
                return Err(CryptoError::InvalidMnemonic("Malformed key origin in descriptor".into()));
            }
        } else {
            ("00000000".to_string(), key_expr.to_string())
        }
    } else if base_desc.starts_with("tpub") || base_desc.starts_with("vpub") {
        ("00000000".to_string(), base_desc.to_string())
    } else {
        return Err(CryptoError::InvalidMnemonic(
            "Unsupported descriptor format. Expected wpkh([fingerprint/84'/1'/0']tpub.../<0;1>/*) or tpub..."
                .into(),
        ));
    };

    // If key is SLIP-132 vpub, convert to standard tpub bytes for rust-bitcoin parsing
    let account_xpub = if xpub_str.starts_with("vpub") {
        let mut decoded = bitcoin::base58::decode_check(&xpub_str)
            .map_err(|e| CryptoError::InvalidMnemonic(format!("Invalid vpub Base58: {}", e)))?;
        if decoded.len() != 78 {
            return Err(CryptoError::InvalidMnemonic("Invalid vpub length (expected 78 bytes)".into()));
        }
        // Replace SLIP-132 version 0x045f1cf6 with Testnet4 BIP-84/BIP-32 version 0x043587cf (tpub)
        decoded[0] = 0x04;
        decoded[1] = 0x35;
        decoded[2] = 0x87;
        decoded[3] = 0xcf;
        let tpub_b58 = bitcoin::base58::encode_check(&decoded);
        Xpub::from_str(&tpub_b58).map_err(CryptoError::Bip32Error)?
    } else {
        Xpub::from_str(&xpub_str).map_err(CryptoError::Bip32Error)?
    };

    let fprint_final = if fingerprint == "00000000" {
        account_xpub.fingerprint().to_string()
    } else {
        fingerprint
    };

    let vpub_raw = account_xpub.to_string();
    let mut raw_bytes = account_xpub.encode();
    raw_bytes[0] = 0x04;
    raw_bytes[1] = 0x5f;
    raw_bytes[2] = 0x1c;
    raw_bytes[3] = 0xf6;
    let vpub_slip132 = bitcoin::base58::encode_check(&raw_bytes);

    let recv_branch = account_xpub.derive_pub(&secp, &DerivationPath::from_str("0")?)?;
    let mut addresses = Vec::with_capacity(50);
    for idx in 0..50 {
        let child_key = recv_branch.derive_pub(&secp, &DerivationPath::from_str(&format!("{}", idx))?)?;
        let compressed_pk = CompressedPublicKey(child_key.public_key);
        let addr = Address::p2wpkh(&compressed_pk, KnownHrp::Testnets);
        addresses.push(addr.to_string());
    }

    let canonical_desc = format!("wpkh([{}/84'/1'/0']{}/<0;1>/*)", fprint_final, account_xpub);
    let checksum = get_descriptor_checksum(&canonical_desc);
    let final_descriptor = if checksum.is_empty() {
        canonical_desc
    } else {
        format!("{}#{}", canonical_desc, checksum)
    };

    Ok(GeneratedSeed {
        mnemonic: "[WATCH-ONLY DESCRIPTOR: ZERO PRIVATE KEYS IN MEMORY]".to_string(),
        fingerprint: fprint_final,
        descriptor: final_descriptor,
        vpub: vpub_raw,
        vpub_slip132,
        addresses,
        entropy_type: "Imported Watch-Only BIP-380 Descriptor".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_offline_mnemonic_12_words() {
        // Test vector 0 mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = process_mnemonic_phrase(phrase).expect("Failed to process 12-word mnemonic");

        assert_eq!(seed.mnemonic, phrase);
        assert_eq!(seed.fingerprint, "73c5da0a");
        assert!(seed.descriptor.starts_with("wpkh([73c5da0a/84'/1'/0']tpub"));
        assert!(seed.descriptor.contains('#'));
        assert!(seed.vpub.starts_with("tpub"));
        assert!(seed.vpub_slip132.starts_with("vpub"));
        assert_eq!(seed.addresses.len(), 50);
        assert!(seed.addresses[0].starts_with("tb1q"));
        assert_eq!(seed.entropy_type, "Imported Offline 12-Word BIP-39 Mnemonic");

        // Derive BIP-85 children from imported seed
        let children = derive_bip85_children(&seed.mnemonic, 5).expect("Failed to derive BIP-85");
        assert_eq!(children.len(), 6); // Index 0 + 5 heir keys
        assert_eq!(children[0].index, 0);
        assert_eq!(children[0].label, "Decoupled Estate Passphrase (Index 0)");
    }

    #[test]
    fn test_import_offline_mnemonic_rejects_non_12_words() {
        // 24-word phrase must be rejected
        let phrase_24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let err_24 = process_mnemonic_phrase(phrase_24);
        assert!(err_24.is_err(), "24 words must be rejected");

        // 11-word phrase must be rejected
        let phrase_11 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let err_11 = process_mnemonic_phrase(phrase_11);
        assert!(err_11.is_err(), "11 words must be rejected");
    }

    #[test]
    fn test_import_offline_mnemonic_rejects_non_english_word() {
        let phrase_non_english = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon nonbipword";
        let err = process_mnemonic_phrase(phrase_non_english);
        assert!(err.is_err(), "Non-English word must be rejected");
    }

    #[test]
    fn test_import_offline_mnemonic_invalid_checksum() {
        // Change final word to invalid checksum
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let err = process_mnemonic_phrase(phrase);
        assert!(err.is_err(), "Invalid checksum must fail");
    }

    #[test]
    fn test_raw_hex_128_bit_entropy() {
        // 32 hex chars = 16 bytes = 128-bit entropy -> exactly 12 words
        let hex_128 = "483ed0cebd5ac3dfad854b9a4a191452";
        let (bytes, label) = parse_physical_entropy(hex_128).expect("Failed 128-bit hex");
        assert_eq!(bytes.len(), 16);
        assert!(label.contains("128-bit"));
        let seed = process_physical_entropy(hex_128).expect("Failed process 128-bit hex");
        assert_eq!(seed.mnemonic.split_whitespace().count(), 12);
    }

    #[test]
    fn test_compact_seed_qr_roundtrip() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let digits = mnemonic_to_compact_seed_qr(phrase).expect("Failed to encode CompactSeedQR");
        assert_eq!(digits.len(), 48);
        assert_eq!(digits, "000000000000000000000000000000000000000000000003");

        let recovered = compact_seed_qr_to_mnemonic(&digits).expect("Failed to decode CompactSeedQR");
        assert_eq!(recovered, phrase);

        // Process directly via process_mnemonic_phrase
        let seed = process_mnemonic_phrase(&digits).expect("Failed process CompactSeedQR directly");
        assert_eq!(seed.mnemonic, phrase);
        assert_eq!(seed.fingerprint, "73c5da0a");
        assert!(seed.entropy_type.contains("CompactSeedQR"));
    }

    #[test]
    fn test_process_watch_only_descriptor() {
        let reference_seed = process_physical_entropy("test0").unwrap();
        
        let watch_only = process_watch_only_descriptor(&reference_seed.descriptor).expect("Failed watch only");
        assert_eq!(watch_only.fingerprint, reference_seed.fingerprint);
        assert_eq!(watch_only.vpub, reference_seed.vpub);
        assert_eq!(watch_only.vpub_slip132, reference_seed.vpub_slip132);
        assert_eq!(watch_only.addresses[0], reference_seed.addresses[0]);
        assert_eq!(watch_only.addresses.len(), 50);
        assert!(watch_only.mnemonic.contains("WATCH-ONLY"));
        assert!(watch_only.entropy_type.contains("Watch-Only"));

        // Also test dispatching via process_mnemonic_phrase
        let via_mnemonic_fn = process_mnemonic_phrase(&reference_seed.descriptor).expect("Failed via mnemonic dispatch");
        assert_eq!(via_mnemonic_fn.fingerprint, reference_seed.fingerprint);
        assert_eq!(via_mnemonic_fn.addresses[0], reference_seed.addresses[0]);
    }
}
