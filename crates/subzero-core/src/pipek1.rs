//! Native `pipe-k1` (`m/83696968'/128002'`) Operational Key Derivation & BIP-340 Release Signer.
//!
//! WHY THIS LIVES IN `subzero-core`:
//! `bootlace-dev/pipe-k1` defines a stateless 105-byte detached BIP-340 Schnorr signature
//! format (`PKSG\x01` + 4B big-endian timestamp + 32B x-only pubkey + 64B signature) over
//! BIP-85 application `128002'`. Embedding exact wire compatibility in `subzero-core` lets an
//! airgapped SubZero vault derive operational `npub` release-signing identities and produce or
//! verify `.pk1` / ASCII-armored `-----BEGIN PIPE-K1 SIGNATURE-----` attestations offline.

use std::str::FromStr;

use base64::prelude::*;
use bech32::{Bech32, Hrp};
use bip39::{Language, Mnemonic};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use hmac::{Hmac, Mac};
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::SubZeroError;
use crate::keys::ZeroizingXpriv;

type HmacSha512 = Hmac<Sha512>;

pub const MAGIC_SIGNATURE: &[u8; 4] = b"PKSG";
pub const SIGNATURE_PAYLOAD_SIZE: usize = 105;
pub const TAG_SIGN: &[u8] = b"pipe-k1/v1/sign";
pub const TAG_SIGN_LEGACY: &[u8] = b"pipek1/v1/sign";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeK1IdentityPublic {
    pub identity: u32,
    pub index: u32,
    pub derivation_path: String,
    pub pubkey_hex: String,
    pub npub: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeK1SignedArtifact {
    pub derivation_path: String,
    pub pubkey_hex: String,
    pub npub: String,
    pub timestamp: u32,
    pub message_sha256_hex: String,
    pub raw_base64: String,
    pub armored: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeK1Verification {
    pub valid: bool,
    pub pubkey_pinned: bool,
    pub legacy_tag_used: bool,
    pub pubkey_hex: String,
    pub npub: String,
    pub timestamp: u32,
    pub message_sha256_hex: String,
}

fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(msg);
    h.finalize().into()
}

pub fn encode_npub(pk_x: &[u8; 32]) -> Result<String, SubZeroError> {
    let hrp = Hrp::parse("npub").map_err(|e| SubZeroError::PipeK1(e.to_string()))?;
    bech32::encode::<Bech32>(hrp, pk_x).map_err(|e| SubZeroError::PipeK1(e.to_string()))
}

pub fn encode_nsec(sk: &[u8; 32]) -> Result<Zeroizing<String>, SubZeroError> {
    let hrp = Hrp::parse("nsec").map_err(|e| SubZeroError::PipeK1(e.to_string()))?;
    let s = bech32::encode::<Bech32>(hrp, sk).map_err(|e| SubZeroError::PipeK1(e.to_string()))?;
    Ok(Zeroizing::new(s))
}

pub fn parse_pubkey_bytes(input: &str) -> Result<[u8; 32], SubZeroError> {
    let trimmed = input.trim();
    if trimmed.starts_with("npub1") {
        let (hrp, data) =
            bech32::decode(trimmed).map_err(|e| SubZeroError::PipeK1(format!("Bech32 error: {e}")))?;
        if hrp.as_str() != "npub" || data.len() != 32 {
            return Err(SubZeroError::PipeK1(
                "Invalid npub1 key (expected 32-byte x-only pubkey).".into(),
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&data);
        Ok(out)
    } else {
        let bytes =
            hex::decode(trimmed).map_err(|e| SubZeroError::PipeK1(format!("Hex error: {e}")))?;
        if bytes.len() != 32 {
            return Err(SubZeroError::PipeK1(format!(
                "Expected 32-byte hex public key (got {} bytes).",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

/// Derive the 32-byte operational `pipe-k1` secret scalar at `m/83696968'/128002'/{identity}'/{index}'`.
/// Matches `pipe-k1::derive_bip85_operational_key` byte-for-byte (note BIP-32 master seed derivation
/// from BIP-39 seed is network-independent: `HMAC-SHA512("Bitcoin seed", seed)`).
fn derive_operational_secret(
    mnemonic_str: &str,
    passphrase_str: &str,
    identity: u32,
    index: u32,
) -> Result<(Zeroizing<[u8; 32]>, String), SubZeroError> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_str.trim())
        .map_err(|e| SubZeroError::PipeK1(format!("Invalid BIP-39 mnemonic: {e}")))?;
    let seed = Zeroizing::new(mnemonic.to_seed(passphrase_str.trim()));

    let secp = Secp256k1::new();
    let root_xprv = ZeroizingXpriv(
        Xpriv::new_master(Network::Testnet4, seed.as_ref())
            .map_err(|e| SubZeroError::PipeK1(format!("BIP-32 master error: {e}")))?,
    );

    let path_str = format!("m/83696968'/128002'/{identity}'/{index}'");
    let path =
        DerivationPath::from_str(&path_str).map_err(|e| SubZeroError::PipeK1(e.to_string()))?;
    let child_xprv = ZeroizingXpriv(
        root_xprv
            .0
            .derive_priv(&secp, &path)
            .map_err(|e| SubZeroError::PipeK1(format!("BIP-85 child error: {e}")))?,
    );

    let mut child_priv = child_xprv.0.private_key.secret_bytes();
    let mut mac = HmacSha512::new_from_slice(b"bip-entropy-from-k")
        .map_err(|_| SubZeroError::PipeK1("HMAC init error".into()))?;
    mac.update(&child_priv);
    child_priv.zeroize();
    let mut hmac_res = mac.finalize().into_bytes();

    let mut sk = Zeroizing::new([0u8; 32]);
    sk.copy_from_slice(&hmac_res[..32]);
    hmac_res.zeroize();

    if *sk == [0u8; 32] {
        return Err(SubZeroError::PipeK1("Derived BIP-85 scalar is zero.".into()));
    }
    let _ = SigningKey::from_bytes(sk.as_ref())
        .map_err(|e| SubZeroError::PipeK1(format!("Invalid secp256k1 scalar: {e}")))?;

    Ok((sk, path_str))
}

pub fn derive_pipek1_public(
    mnemonic_str: &str,
    identity: u32,
    index: u32,
) -> Result<PipeK1IdentityPublic, SubZeroError> {
    let (sk, path_str) = derive_operational_secret(mnemonic_str, "", identity, index)?;
    let signing_key =
        SigningKey::from_bytes(sk.as_ref()).map_err(|e| SubZeroError::PipeK1(e.to_string()))?;
    let pk_bytes: [u8; 32] = signing_key.verifying_key().to_bytes().into();
    let npub = encode_npub(&pk_bytes)?;
    Ok(PipeK1IdentityPublic {
        identity,
        index,
        derivation_path: path_str,
        pubkey_hex: hex::encode(pk_bytes),
        npub,
    })
}

/// Export the operational `nsec1...` Bech32 secret key ONLY when explicitly requested on the cold console.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ExportedOperationalNsec {
    pub derivation_path: String,
    pub npub: String,
    pub nsec: String,
}

pub fn export_pipek1_nsec(
    mnemonic_str: &str,
    identity: u32,
    index: u32,
) -> Result<ExportedOperationalNsec, SubZeroError> {
    let (sk, derivation_path) = derive_operational_secret(mnemonic_str, "", identity, index)?;
    let signing_key =
        SigningKey::from_bytes(sk.as_ref()).map_err(|e| SubZeroError::PipeK1(e.to_string()))?;
    let pk_bytes: [u8; 32] = signing_key.verifying_key().to_bytes().into();
    let npub = encode_npub(&pk_bytes)?;
    let nsec = encode_nsec(&sk)?;
    Ok(ExportedOperationalNsec {
        derivation_path,
        npub,
        nsec: (*nsec).clone(),
    })
}

/// Sign arbitrary bytes deterministically (`aux_rand = [0u8; 32]`, zero OS RNG) in exact `pipe-k1` wire format.
pub fn sign_pipek1_detached(
    mnemonic_str: &str,
    identity: u32,
    index: u32,
    message: &[u8],
    timestamp: u32,
) -> Result<PipeK1SignedArtifact, SubZeroError> {
    let (sk, derivation_path) = derive_operational_secret(mnemonic_str, "", identity, index)?;
    let signing_key =
        SigningKey::from_bytes(sk.as_ref()).map_err(|e| SubZeroError::PipeK1(e.to_string()))?;

    let msg_digest: [u8; 32] = Sha256::digest(message).into();
    let mut ts_and_digest = [0u8; 36];
    ts_and_digest[0..4].copy_from_slice(&timestamp.to_be_bytes());
    ts_and_digest[4..36].copy_from_slice(&msg_digest);

    let m_hash = tagged_hash(TAG_SIGN, &ts_and_digest);
    let sig = signing_key
        .sign_raw(&m_hash, &[0u8; 32])
        .map_err(|e| SubZeroError::PipeK1(format!("Schnorr sign error: {e}")))?;

    let pk_bytes: [u8; 32] = signing_key.verifying_key().to_bytes().into();
    let mut payload = [0u8; SIGNATURE_PAYLOAD_SIZE];
    payload[0..4].copy_from_slice(MAGIC_SIGNATURE);
    payload[4] = 0x01;
    payload[5..9].copy_from_slice(&timestamp.to_be_bytes());
    payload[9..41].copy_from_slice(&pk_bytes);
    payload[41..105].copy_from_slice(&sig.to_bytes());

    let raw_base64 = BASE64_STANDARD.encode(payload);
    let armored = format!(
        "-----BEGIN PIPE-K1 SIGNATURE-----\n\n{raw_base64}\n-----END PIPE-K1 SIGNATURE-----\n"
    );
    let npub = encode_npub(&pk_bytes)?;

    Ok(PipeK1SignedArtifact {
        derivation_path,
        pubkey_hex: hex::encode(pk_bytes),
        npub,
        timestamp,
        message_sha256_hex: hex::encode(msg_digest),
        raw_base64,
        armored,
    })
}

/// Decode either raw 105-byte `PKSG`, raw Base64, or `-----BEGIN PIPE-K1/PGP SIGNATURE-----` armor.
pub fn decode_pipek1_signature_bytes(sig_input: &[u8]) -> Result<[u8; SIGNATURE_PAYLOAD_SIZE], SubZeroError> {
    if sig_input.len() == SIGNATURE_PAYLOAD_SIZE && &sig_input[0..4] == MAGIC_SIGNATURE {
        let mut arr = [0u8; SIGNATURE_PAYLOAD_SIZE];
        arr.copy_from_slice(sig_input);
        return Ok(arr);
    }

    let text = core::str::from_utf8(sig_input)
        .map_err(|_| SubZeroError::PipeK1("Signature is neither 105-byte PKSG nor valid UTF-8 armor.".into()))?;
    let mut b64_clean = String::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("-----BEGIN ") || t.starts_with("-----END ") {
            continue;
        }
        b64_clean.push_str(t);
    }
    let decoded = BASE64_STANDARD
        .decode(&b64_clean)
        .map_err(|e| SubZeroError::PipeK1(format!("Base64 signature decode error: {e}")))?;
    if decoded.len() != SIGNATURE_PAYLOAD_SIZE {
        return Err(SubZeroError::PipeK1(format!(
            "Expected 105-byte PKSG signature payload, got {} bytes.",
            decoded.len()
        )));
    }
    let mut arr = [0u8; SIGNATURE_PAYLOAD_SIZE];
    arr.copy_from_slice(&decoded);
    Ok(arr)
}

/// Verify a detached `pipe-k1` signature against `message` and an optional pinned `expected_pubkey` (`npub1...` or 64-char hex).
pub fn verify_pipek1_detached(
    message: &[u8],
    sig_input: &[u8],
    expected_pubkey: Option<&str>,
) -> Result<PipeK1Verification, SubZeroError> {
    let payload = decode_pipek1_signature_bytes(sig_input)?;
    if &payload[0..4] != MAGIC_SIGNATURE {
        return Err(SubZeroError::PipeK1("Invalid PKSG magic header.".into()));
    }
    if payload[4] != 0x01 {
        return Err(SubZeroError::PipeK1(format!(
            "Unsupported PKSG wire version 0x{:02x}.",
            payload[4]
        )));
    }

    let timestamp = u32::from_be_bytes(payload[5..9].try_into().unwrap());
    let msg_digest: [u8; 32] = Sha256::digest(message).into();
    let mut ts_and_digest = [0u8; 36];
    ts_and_digest[0..4].copy_from_slice(&timestamp.to_be_bytes());
    ts_and_digest[4..36].copy_from_slice(&msg_digest);

    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&payload[9..41]);
    let sig_bytes = &payload[41..105];

    let mut pubkey_pinned = false;
    if let Some(exp) = expected_pubkey {
        if !exp.trim().is_empty() {
            let exp_bytes = parse_pubkey_bytes(exp)?;
            if exp_bytes != pk_bytes {
                return Err(SubZeroError::PipeK1(format!(
                    "Signer pubkey mismatch: signature carries {}, expected {}.",
                    encode_npub(&pk_bytes)?,
                    encode_npub(&exp_bytes)?
                )));
            }
            pubkey_pinned = true;
        }
    }

    let vk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| SubZeroError::PipeK1(format!("Invalid x-only pubkey: {e}")))?;
    let sig = Signature::try_from(sig_bytes)
        .map_err(|e| SubZeroError::PipeK1(format!("Invalid 64-byte Schnorr signature: {e}")))?;

    let mut legacy_tag_used = false;
    let m_hash = tagged_hash(TAG_SIGN, &ts_and_digest);
    if vk.verify_raw(&m_hash, &sig).is_err() {
        let m_legacy = tagged_hash(TAG_SIGN_LEGACY, &ts_and_digest);
        vk.verify_raw(&m_legacy, &sig)
            .map_err(|_| SubZeroError::PipeK1("BIP-340 Schnorr signature verification FAILED.".into()))?;
        legacy_tag_used = true;
    }

    Ok(PipeK1Verification {
        valid: true,
        pubkey_pinned,
        legacy_tag_used,
        pubkey_hex: hex::encode(pk_bytes),
        npub: encode_npub(&pk_bytes)?,
        timestamp,
        message_sha256_hex: hex::encode(msg_digest),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipek1_sign_verify_and_real_attestation_vectors() {
        // 1. Verify official bootlace-dev/pipe-k1 ATTESTATION.md live cross-signatures!
        let stmt1 = b"PIPEK1 ATTESTATION: Master identity npub1e94hqt3fuu7rvy9rpl85h3339vtn8psgewq4u05r7q4nup2kwp4q0flgay authorizes child key npub1mvlht4wj3lvfmw96qxakaln862r27nn7z84ak089zjuvavkppeeq79a4j7 as legitimate pipek1 testing and release signer under BIP-85.";
        let sig1_b64 = b"UEtTRwFqoE1IyWtwLinnPDYQow/PS8YxKxczhgjLgV4+g/ArPgVWcGpn8mX4iYjPz2IMdg8tHsqa9sW5OS/bYR2hiNzx9Q7/d6BFzJO20bs3ezeZOgVcLTZKdIIxfZl9+lux6XrUPGE4";
        let v1 = verify_pipek1_detached(
            stmt1,
            sig1_b64,
            Some("npub1e94hqt3fuu7rvy9rpl85h3339vtn8psgewq4u05r7q4nup2kwp4q0flgay"),
        )
        .unwrap();
        assert!(v1.valid);

        let stmt2 = b"PIPEK1 ATTESTATION: Child key npub1mvlht4wj3lvfmw96qxakaln862r27nn7z84ak089zjuvavkppeeq79a4j7 acknowledges derivation from and attests allegiance to master identity npub1e94hqt3fuu7rvy9rpl85h3339vtn8psgewq4u05r7q4nup2kwp4q0flgay.";
        let sig2_b64 = b"UEtTRwFqoE1I2z911dKP2J24ugG7bv5n0oavTn4R69s85RS4zrLBDnIsdSu5HqRmts1fCHkD682D9ROp5xxCtdj3HFrJP4/4oQ33oZhrziFDSSpVCJ/AUFRV1rwZK+aKnf0hwp2ouHOi";
        let v2 = verify_pipek1_detached(
            stmt2,
            sig2_b64,
            Some("npub1mvlht4wj3lvfmw96qxakaln862r27nn7z84ak089zjuvavkppeeq79a4j7"),
        )
        .unwrap();
        assert!(v2.valid);

        // 2. Roundtrip BIP-85 128002' sign + verify + tamper detection
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let signed = sign_pipek1_detached(phrase, 0, 0, b"SHA256SUMS test payload\n", 1_700_000_000).unwrap();
        let ver = verify_pipek1_detached(
            b"SHA256SUMS test payload\n",
            signed.armored.as_bytes(),
            Some(&signed.npub),
        )
        .unwrap();
        assert!(ver.valid);
        assert_eq!(ver.timestamp, 1_700_000_000);

        // Tampered message MUST fail
        assert!(verify_pipek1_detached(
            b"SHA256SUMS tampered payload\n",
            signed.armored.as_bytes(),
            Some(&signed.npub),
        )
        .is_err());
    }
}
