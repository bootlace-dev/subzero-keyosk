//! Deterministic SIV-Committed Estate Vault (`subzero-vault-v2` + Legacy `v1` Decrypt).
//!
//! WHY SIV-COMMITTED IVs & PBKDF2-SPLIT KEYS (`[C-04]` + `[H-04]` FIXES):
//! 1. Zero `(Key, Nonce)` Reuse Without OS RNG:
//!    On an amnesic airgapped appliance that forbids OS `/dev/urandom` queries, deriving a
//!    deterministic AES-256-GCM IV solely from `(master_mnemonic, passphrase)` caused `(Key, IV)`
//!    reuse if the operator ever updated `vault.json`.
//! 2. Zero Unstretched Salt/IV Oracles:
//!    In `subzero-vault-v2`:
//!    - `salt = SHA256("subzero:vault:v2:salt:" || master_xfp)[0..16]` (public, zero passphrase
//!      dependency, preventing fast unstretched salt-matching attacks).
//!    - `PBKDF2-HMAC-SHA256(passphrase, salt, 600_000)` derives **64 bytes** (`enc_key = okm[0..32]`,
//!      `siv_key = okm[32..64]`).
//!    - `iv = HMAC-SHA256(siv_key, canonical_plaintext_bytes)[0..12]`, so testing ANY passphrase
//!      guess against either `iv` or the GCM tag requires all `600,000` PBKDF2 iterations, while
//!      any 1-bit edit to `plaintext` produces a fresh 96-bit synthetic IV.
//!    - Envelope metadata (`format|cipher|kdf|iterations`) is authenticated as AES-256-GCM AAD.

use std::collections::BTreeSet;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::prelude::*;
use bip39::{Language, Mnemonic};
use bitcoin::bip32::Xpriv;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::SubZeroError;
use crate::keys::Bip85Child;

type HmacSha256 = Hmac<Sha256>;

pub const VAULT_PBKDF2_ITERATIONS: u32 = 600_000;
pub const MIN_ACCEPTED_ITERATIONS: u32 = 100_000;
pub const MAX_ACCEPTED_ITERATIONS: u32 = 2_000_000;

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

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DecryptedVaultPayload {
    pub version: String,
    pub created_utc: String,
    pub master_root_mnemonic: String,
    pub descriptor: String,
    pub heir_treasuries: Vec<Bip85Child>,
}

impl core::fmt::Debug for DecryptedVaultPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DecryptedVaultPayload")
            .field("version", &self.version)
            .field("created_utc", &self.created_utc)
            .field("master_root_mnemonic", &"[REDACTED]")
            .field("descriptor", &self.descriptor)
            .field("heir_treasuries_count", &self.heir_treasuries.len())
            .finish()
    }
}

fn normalize_passphrase(passphrase_mnemonic: &str) -> Zeroizing<String> {
    Zeroizing::new(
        passphrase_mnemonic
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase(),
    )
}

fn vault_v2_aad(iterations: u32) -> Vec<u8> {
    format!("subzero-vault-v2|AES-256-GCM|PBKDF2-HMAC-SHA256|{iterations}").into_bytes()
}

fn derive_public_xfp_salt(master_mnemonic: &str) -> Result<[u8; 16], SubZeroError> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, master_mnemonic.trim())
        .map_err(|e| SubZeroError::Vault(format!("Invalid master_root_mnemonic in payload: {e}")))?;
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    let secp = Secp256k1::new();
    let master_xprv = Xpriv::new_master(Network::Testnet4, seed.as_ref())
        .map_err(|e| SubZeroError::Vault(format!("BIP-32 master error: {e}")))?;
    let xfp = master_xprv.fingerprint(&secp).to_string();

    let mut sha = Sha256::new();
    sha.update(b"subzero:vault:v2:salt:");
    sha.update(xfp.as_bytes());
    let digest = sha.finalize();
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&digest[..16]);
    Ok(salt)
}

fn compute_siv_iv(siv_key: &[u8], plaintext_bytes: &[u8]) -> Result<[u8; 12], SubZeroError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(siv_key)
        .map_err(|_| SubZeroError::Vault("HMAC SIV init failed".into()))?;
    mac.update(b"subzero:vault:v2:siv:");
    mac.update(plaintext_bytes);
    let full = mac.finalize().into_bytes();
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&full[..12]);
    Ok(iv)
}

pub fn encrypt_vault_payload(
    payload: &DecryptedVaultPayload,
    passphrase_mnemonic: &str,
) -> Result<String, SubZeroError> {
    let norm_pass = normalize_passphrase(passphrase_mnemonic);
    let words: Vec<&str> = norm_pass.split_whitespace().collect();
    let distinct_words: BTreeSet<&str> = words.iter().copied().collect();
    if words.len() < 6 || distinct_words.len() < 4 || norm_pass.len() < 24 {
        return Err(SubZeroError::Vault(
            "Estate passphrase is too weak: provide at least 6 non-repeating words (>=24 chars; 12-word BIP-85 Index 0 passphrase recommended)."
                .into(),
        ));
    }

    let plaintext = Zeroizing::new(
        serde_json::to_string_pretty(payload)
            .map_err(|e| SubZeroError::Vault(format!("Payload serialization error: {e}")))?,
    );

    let salt = derive_public_xfp_salt(&payload.master_root_mnemonic)?;

    let mut okm = Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2_hmac::<Sha256>(
        norm_pass.as_bytes(),
        &salt,
        VAULT_PBKDF2_ITERATIONS,
        okm.as_mut(),
    );
    let enc_key = &okm[0..32];
    let siv_key = &okm[32..64];

    let iv = compute_siv_iv(siv_key, plaintext.as_bytes())?;
    let aad = vault_v2_aad(VAULT_PBKDF2_ITERATIONS);

    let cipher = Aes256Gcm::new_from_slice(enc_key)
        .map_err(|e| SubZeroError::Vault(format!("Cipher init failed: {e}")))?;
    let nonce = Nonce::from_slice(&iv);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| SubZeroError::Vault("AES-256-GCM encryption failed.".into()))?;

    let envelope = EncryptedVaultJson {
        format: "subzero-vault-v2".to_string(),
        cipher: "AES-256-GCM".to_string(),
        kdf: "PBKDF2-HMAC-SHA256".to_string(),
        iterations: VAULT_PBKDF2_ITERATIONS,
        salt: BASE64_STANDARD.encode(salt),
        iv: BASE64_STANDARD.encode(iv),
        ciphertext: BASE64_STANDARD.encode(ciphertext),
    };

    serde_json::to_string_pretty(&envelope)
        .map_err(|e| SubZeroError::Vault(format!("Envelope serialization failed: {e}")))
}

pub fn decrypt_vault_json(
    vault_json_str: &str,
    passphrase_mnemonic: &str,
) -> Result<DecryptedVaultPayload, SubZeroError> {
    if vault_json_str.len() > 2 * 1024 * 1024 {
        return Err(SubZeroError::Vault("Vault JSON exceeds 2 MB safety limit.".into()));
    }
    let vault: EncryptedVaultJson = serde_json::from_str(vault_json_str)
        .map_err(|e| SubZeroError::Vault(format!("Invalid vault JSON format: {e}")))?;

    if vault.format != "subzero-vault-v2" && vault.format != "subzero-vault-v1" {
        return Err(SubZeroError::Vault(format!(
            "Unsupported vault format '{}' (expected subzero-vault-v2 or subzero-vault-v1).",
            vault.format
        )));
    }
    if vault.cipher != "AES-256-GCM" || vault.kdf != "PBKDF2-HMAC-SHA256" {
        return Err(SubZeroError::Vault(format!(
            "Unsupported cipher/KDF pair ({} / {}).",
            vault.cipher, vault.kdf
        )));
    }
    if !(MIN_ACCEPTED_ITERATIONS..=MAX_ACCEPTED_ITERATIONS).contains(&vault.iterations) {
        return Err(SubZeroError::Vault(format!(
            "PBKDF2 iteration count {} outside safe bounds [{}..={}].",
            vault.iterations, MIN_ACCEPTED_ITERATIONS, MAX_ACCEPTED_ITERATIONS
        )));
    }

    let salt = BASE64_STANDARD
        .decode(vault.salt.trim())
        .map_err(|e| SubZeroError::Vault(format!("Invalid Base64 salt: {e}")))?;
    if salt.len() < 16 || salt.len() > 64 {
        return Err(SubZeroError::Vault("Salt must be between 16 and 64 bytes.".into()));
    }

    let iv = BASE64_STANDARD
        .decode(vault.iv.trim())
        .map_err(|e| SubZeroError::Vault(format!("Invalid Base64 IV: {e}")))?;
    if iv.len() != 12 {
        return Err(SubZeroError::Vault("AES-256-GCM IV must be 12 bytes.".into()));
    }

    let ciphertext = BASE64_STANDARD
        .decode(vault.ciphertext.trim())
        .map_err(|e| SubZeroError::Vault(format!("Invalid Base64 ciphertext: {e}")))?;

    let norm_pass = normalize_passphrase(passphrase_mnemonic);
    let nonce = Nonce::from_slice(&iv);

    let plaintext_bytes = if vault.format == "subzero-vault-v2" {
        let mut okm = Zeroizing::new([0u8; 64]);
        pbkdf2::pbkdf2_hmac::<Sha256>(
            norm_pass.as_bytes(),
            &salt,
            vault.iterations,
            okm.as_mut(),
        );
        let enc_key = &okm[0..32];
        let siv_key = &okm[32..64];
        let aad = vault_v2_aad(vault.iterations);

        let cipher = Aes256Gcm::new_from_slice(enc_key)
            .map_err(|e| SubZeroError::Vault(format!("Cipher init failed: {e}")))?;
        let pt = Zeroizing::new(
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: ciphertext.as_ref(),
                        aad: &aad,
                    },
                )
                .map_err(|_| {
                    SubZeroError::Vault(
                        "Authentication failed: incorrect 12-word estate passphrase or tampered vault.json."
                            .into(),
                    )
                })?,
        );
        let expected_iv = compute_siv_iv(siv_key, &pt)?;
        if expected_iv.as_slice() != iv.as_slice() {
            return Err(SubZeroError::Vault(
                "Vault SIV commitment mismatch (tampered IV or envelope)."
                    .into(),
            ));
        }
        pt
    } else {
        // Legacy `subzero-vault-v1` backward-compatible decryption (32B PBKDF2 key, empty AAD)
        let mut derived_key = Zeroizing::new([0u8; 32]);
        pbkdf2::pbkdf2_hmac::<Sha256>(
            norm_pass.as_bytes(),
            &salt,
            vault.iterations,
            derived_key.as_mut(),
        );
        let cipher = Aes256Gcm::new_from_slice(derived_key.as_ref())
            .map_err(|e| SubZeroError::Vault(format!("Cipher init failed: {e}")))?;
        Zeroizing::new(cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| {
            SubZeroError::Vault(
                "Authentication failed: incorrect 12-word estate passphrase or tampered vault.json."
                    .into(),
            )
        })?)
    };

    serde_json::from_slice(&plaintext_bytes)
        .map_err(|e| SubZeroError::Vault(format!("Decrypted payload JSON invalid: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{derive_bip85_children, load_rehearsal_preset};

    #[test]
    fn test_siv_vault_roundtrip_and_nonce_uniqueness_on_edit() {
        let prof = load_rehearsal_preset(2).unwrap();
        let children = derive_bip85_children(prof.mnemonic.as_deref().unwrap(), 2).unwrap();
        let passphrase = children[0].mnemonic.clone();

        let p1 = DecryptedVaultPayload {
            version: "2.0.0".into(),
            created_utc: "2026-11-15T00:00:00Z".into(),
            master_root_mnemonic: prof.mnemonic.clone().unwrap(),
            descriptor: prof.wpkh_descriptor.clone(),
            heir_treasuries: children[1..].to_vec(),
        };
        let enc1 = encrypt_vault_payload(&p1, &passphrase).unwrap();
        let enc1_repeat = encrypt_vault_payload(&p1, &passphrase).unwrap();
        // Deterministic: identical input -> identical output
        assert_eq!(enc1, enc1_repeat);

        // Mutating plaintext MUST produce a fresh IV (preventing AES-GCM nonce reuse!)
        let mut p2 = p1.clone();
        p2.created_utc = "2026-11-15T00:00:01Z".into();
        let enc2 = encrypt_vault_payload(&p2, &passphrase).unwrap();
        let v1_env: EncryptedVaultJson = serde_json::from_str(&enc1).unwrap();
        let v2_env: EncryptedVaultJson = serde_json::from_str(&enc2).unwrap();
        assert_ne!(v1_env.iv, v2_env.iv);

        // Decrypt roundtrip + wrong passphrase rejection + iteration downgrade block
        let dec = decrypt_vault_json(&enc1, &passphrase).unwrap();
        assert_eq!(dec.master_root_mnemonic, p1.master_root_mnemonic);
        assert!(decrypt_vault_json(&enc1, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").is_err());

        let mut downgraded = v1_env.clone();
        downgraded.iterations = 10;
        let bad_json = serde_json::to_string(&downgraded).unwrap();
        assert!(decrypt_vault_json(&bad_json, &passphrase).is_err());

        // Regression (`[H-04]`): Weak passphrase ("a a a a a a") rejected; salt has zero passphrase dependency;
        // format label downgrade (`v2` -> `v1`) fails AAD check; Debug output redacts mnemonics!
        assert!(encrypt_vault_payload(&p1, "a a a a a a").is_err());
        let alt_pass = children[1].mnemonic.clone();
        let enc_alt = encrypt_vault_payload(&p1, &alt_pass).unwrap();
        let alt_env: EncryptedVaultJson = serde_json::from_str(&enc_alt).unwrap();
        assert_eq!(
            v1_env.salt, alt_env.salt,
            "Salt must depend solely on public XFP, never leaking passphrase!"
        );
        assert_ne!(v1_env.iv, alt_env.iv);

        let mut swapped_fmt = v1_env.clone();
        swapped_fmt.format = "subzero-vault-v1".into();
        assert!(
            decrypt_vault_json(&serde_json::to_string(&swapped_fmt).unwrap(), &passphrase).is_err(),
            "AAD must block v2 -> v1 label swap!"
        );

        let dbg = format!("{p1:?}");
        assert!(!dbg.contains("legal"), "Debug impl must redact mnemonics: {dbg}");
    }
}
