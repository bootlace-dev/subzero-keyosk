//! Testnet4 Key Derivation, BIP-84/BIP-86 Descriptors, BIP-85 Vaults, and Watch-Only Importers.
//!
//! SECURITY INVARIANTS:
//! 1. Hard-locked to `Network::Testnet4` (`m/84'/1'/0'` Native SegWit `tb1q...` and
//!    `m/86'/1'/0'` Taproot `tb1p...`). Any mainnet prefix (`bc1`, `xpub`, `ypub`, `zpub`,
//!    `xprv`) is rejected at the boundary.
//! 2. Watch-only exports (`SparrowWatchOnlyJson`) NEVER serialize mnemonics or private keys.
//! 3. Both Receive (`0/*`) and Internal Change (`1/*`) address sets are derived so funded
//!    change UTXOs (e.g. `Preset 0` `1/12..14`, `Preset 1` `1/1`, `Preset 9` `1/1`) are
//!    immediately inspectable in both TUI and HTML Kiosk.

use std::str::FromStr;

use bip39::{Language, Mnemonic};
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, CompressedPublicKey, KnownHrp, Network, XOnlyPublicKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::descriptor::{attach_descriptor_checksum, verify_and_strip_checksum};
use crate::entropy::{is_known_public_preset_entropy, ConditionedEntropy, EntropyTrustTier};
use crate::error::SubZeroError;
use crate::presets::get_preset;

type HmacSha512 = Hmac<Sha512>;

/// Overwrite an `Xpriv` in memory with dummy material via volatile writes so
/// both its `private_key` and `chain_code` are scrubbed cleanly on drop.
pub(crate) fn erase_xpriv(xprv: &mut Xpriv) {
    if let Ok(dummy) = Xpriv::new_master(Network::Testnet4, &[0u8; 16]) {
        unsafe {
            core::ptr::write_volatile(xprv, dummy);
        }
    }
}

pub(crate) struct ZeroizingXpriv(pub(crate) Xpriv);

impl Drop for ZeroizingXpriv {
    fn drop(&mut self) {
        erase_xpriv(&mut self.0);
    }
}

pub const DEFAULT_ADDRESS_GAP: u32 = 50;
pub const DEFAULT_TAPROOT_GAP: u32 = 20;

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct WalletProfile {
    pub fingerprint: String,
    /// `None` when loaded from a Watch-Only descriptor or redacted before crossing WASM boundary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    #[zeroize(skip)]
    pub is_watch_only: bool,
    #[zeroize(skip)]
    pub trust_tier: EntropyTrustTier,
    pub trust_badge: String,
    pub entropy_label: String,
    pub audit_summary: String,
    pub repro_formula_hint: String,
    // BIP-84 Native SegWit (m/84'/1'/0')
    pub bip84_tpub: String,
    pub bip84_vpub_slip132: String,
    pub wpkh_descriptor: String,
    pub receive_addresses: Vec<String>,
    pub change_addresses: Vec<String>,
    // BIP-86 Taproot (m/86'/1'/0', available when derived from mnemonic; optional for watch-only wpkh)
    pub bip86_tpub: Option<String>,
    pub tr_descriptor: Option<String>,
    pub tr_receive_addresses: Vec<String>,
    pub tr_change_addresses: Vec<String>,
}

impl core::fmt::Debug for WalletProfile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WalletProfile")
            .field("fingerprint", &self.fingerprint)
            .field("is_watch_only", &self.is_watch_only)
            .field("trust_tier", &self.trust_tier)
            .field("wpkh_descriptor", &self.wpkh_descriptor)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Bip85Child {
    pub label: String,
    #[zeroize(skip)]
    pub index: u32,
    pub path: String,
    pub mnemonic: String,
}

impl core::fmt::Debug for Bip85Child {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Bip85Child")
            .field("label", &self.label)
            .field("index", &self.index)
            .field("path", &self.path)
            .field("mnemonic", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bip85ChildPublic {
    pub index: u32,
    pub path: String,
    pub label: String,
    pub fingerprint: String,
    pub xpub: String,
    pub vpub_slip132: String,
    pub descriptor: String,
    pub first_receive_address: String,
    pub first_change_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparrowAccountExport {
    pub derivation: String,
    pub xpub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpub: Option<String>,
    pub descriptor: String,
    pub first_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparrowWatchOnlyJson {
    pub format: String,
    pub network: String,
    pub xfp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bip84: Option<SparrowAccountExport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bip86: Option<SparrowAccountExport>,
}

fn encode_slip132_vpub(account_xpub: &Xpub) -> String {
    let mut raw = account_xpub.encode();
    // SLIP-0132 Testnet P2WPKH public version bytes: 0x045f1cf6 ("vpub...")
    raw[0] = 0x04;
    raw[1] = 0x5f;
    raw[2] = 0x1c;
    raw[3] = 0xf6;
    bitcoin::base58::encode_check(&raw)
}

fn decode_slip132_vpub_to_xpub(vpub_str: &str) -> Result<Xpub, SubZeroError> {
    let mut decoded = bitcoin::base58::decode_check(vpub_str)
        .map_err(|e| SubZeroError::Descriptor(format!("Invalid SLIP-0132 vpub Base58: {e}")))?;
    if decoded.len() != 78 {
        return Err(SubZeroError::Descriptor(format!(
            "Invalid vpub payload length (expected 78 bytes, got {}).",
            decoded.len()
        )));
    }
    if decoded[0..4] != [0x04, 0x5f, 0x1c, 0xf6] {
        return Err(SubZeroError::Descriptor(
            "Key carries non-Testnet SLIP-0132 version bytes.".into(),
        ));
    }
    // Convert to standard BIP-32 Testnet tpub version 0x043587cf
    decoded[0] = 0x04;
    decoded[1] = 0x35;
    decoded[2] = 0x87;
    decoded[3] = 0xcf;
    let tpub = bitcoin::base58::encode_check(&decoded);
    Xpub::from_str(&tpub).map_err(|e| SubZeroError::Bip32(e.to_string()))
}

fn derive_wpkh_branch(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    account_xpub: &Xpub,
    change: u32,
    count: u32,
) -> Result<Vec<String>, SubZeroError> {
    let branch_path = DerivationPath::from_str(&change.to_string())
        .map_err(|e| SubZeroError::Bip32(e.to_string()))?;
    let branch_xpub = account_xpub
        .derive_pub(secp, &branch_path)
        .map_err(|e| SubZeroError::Bip32(e.to_string()))?;
    let mut out = Vec::with_capacity(count as usize);
    for idx in 0..count {
        let idx_path = DerivationPath::from_str(&idx.to_string())
            .map_err(|e| SubZeroError::Bip32(e.to_string()))?;
        let child = branch_xpub
            .derive_pub(secp, &idx_path)
            .map_err(|e| SubZeroError::Bip32(e.to_string()))?;
        let cpk = CompressedPublicKey(child.public_key);
        out.push(Address::p2wpkh(&cpk, KnownHrp::Testnets).to_string());
    }
    Ok(out)
}

fn derive_tr_branch(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    account_xpub: &Xpub,
    change: u32,
    count: u32,
) -> Result<Vec<String>, SubZeroError> {
    let branch_path = DerivationPath::from_str(&change.to_string())
        .map_err(|e| SubZeroError::Bip32(e.to_string()))?;
    let branch_xpub = account_xpub
        .derive_pub(secp, &branch_path)
        .map_err(|e| SubZeroError::Bip32(e.to_string()))?;
    let mut out = Vec::with_capacity(count as usize);
    for idx in 0..count {
        let idx_path = DerivationPath::from_str(&idx.to_string())
            .map_err(|e| SubZeroError::Bip32(e.to_string()))?;
        let child = branch_xpub
            .derive_pub(secp, &idx_path)
            .map_err(|e| SubZeroError::Bip32(e.to_string()))?;
        let (xonly, _parity) = XOnlyPublicKey::from_slice(&child.public_key.serialize()[1..33])
            .map(|k| (k, ()))
            .map_err(|e| SubZeroError::Bip32(e.to_string()))?;
        out.push(Address::p2tr(secp, xonly, None, KnownHrp::Testnets).to_string());
    }
    Ok(out)
}

pub fn wallet_from_mnemonic_with_meta(
    mnemonic_phrase: &str,
    trust_tier: EntropyTrustTier,
    entropy_label: &str,
    audit_summary: &str,
    repro_formula_hint: &str,
) -> Result<WalletProfile, SubZeroError> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_phrase)
        .map_err(|e| SubZeroError::Mnemonic(format!("Invalid BIP-39 mnemonic: {e}")))?;
    if mnemonic.word_count() != 12 {
        return Err(SubZeroError::Mnemonic(format!(
            "SubZero requires a 12-word BIP-39 mnemonic (got {} words).",
            mnemonic.word_count()
        )));
    }
    let canonical_phrase = Zeroizing::new(mnemonic.to_string());
    let mut ent_arr = [0u8; 16];
    let raw_ent = Zeroizing::new(mnemonic.to_entropy());
    if raw_ent.len() == 16 {
        ent_arr.copy_from_slice(&raw_ent);
    }

    // Automatically re-badge any imported known public rehearsal vector so it can NEVER masquerade as live Tier 1!
    let (effective_tier, effective_label, effective_summary) =
        if let Some(preset_id) = is_known_public_preset_entropy(&ent_arr) {
            if trust_tier != EntropyTrustTier::DeterministicRehearsalPreset {
                (
                    EntropyTrustTier::DeterministicRehearsalPreset,
                    format!("Imported Public Rehearsal Preset #{preset_id} ({entropy_label})"),
                    format!("WARNING: Matches public Testnet4 Preset #{preset_id} (0 bits secret entropy; rehearsal only)."),
                )
            } else {
                (
                    trust_tier,
                    entropy_label.to_string(),
                    audit_summary.to_string(),
                )
            }
        } else {
            (
                trust_tier,
                entropy_label.to_string(),
                audit_summary.to_string(),
            )
        };
    ent_arr.zeroize();

    let seed = Zeroizing::new(mnemonic.to_seed(""));

    let secp = Secp256k1::new();
    let master_xprv = ZeroizingXpriv(
        Xpriv::new_master(Network::Testnet4, seed.as_ref())
            .map_err(|e| SubZeroError::Bip32(e.to_string()))?,
    );
    let master_fp = master_xprv.0.fingerprint(&secp).to_string();

    // 1. BIP-84 Native SegWit (m/84'/1'/0')
    let path84 =
        DerivationPath::from_str("m/84'/1'/0'").map_err(|e| SubZeroError::Bip32(e.to_string()))?;
    let acct84_xprv = ZeroizingXpriv(
        master_xprv
            .0
            .derive_priv(&secp, &path84)
            .map_err(|e| SubZeroError::Bip32(e.to_string()))?,
    );
    let acct84_xpub = Xpub::from_priv(&secp, &acct84_xprv.0);
    let bip84_tpub = acct84_xpub.to_string();
    let bip84_vpub_slip132 = encode_slip132_vpub(&acct84_xpub);

    let raw_wpkh = format!("wpkh([{master_fp}/84'/1'/0']{bip84_tpub}/<0;1>/*)");
    let wpkh_descriptor = attach_descriptor_checksum(&raw_wpkh)?;

    let receive_addresses = derive_wpkh_branch(&secp, &acct84_xpub, 0, DEFAULT_ADDRESS_GAP)?;
    let change_addresses = derive_wpkh_branch(&secp, &acct84_xpub, 1, DEFAULT_ADDRESS_GAP)?;

    // 2. BIP-86 Taproot (m/86'/1'/0')
    let path86 =
        DerivationPath::from_str("m/86'/1'/0'").map_err(|e| SubZeroError::Bip32(e.to_string()))?;
    let acct86_xprv = ZeroizingXpriv(
        master_xprv
            .0
            .derive_priv(&secp, &path86)
            .map_err(|e| SubZeroError::Bip32(e.to_string()))?,
    );
    let acct86_xpub = Xpub::from_priv(&secp, &acct86_xprv.0);
    let bip86_tpub = acct86_xpub.to_string();

    let raw_tr = format!("tr([{master_fp}/86'/1'/0']{bip86_tpub}/<0;1>/*)");
    let tr_descriptor = attach_descriptor_checksum(&raw_tr)?;

    let tr_receive_addresses = derive_tr_branch(&secp, &acct86_xpub, 0, DEFAULT_TAPROOT_GAP)?;
    let tr_change_addresses = derive_tr_branch(&secp, &acct86_xpub, 1, DEFAULT_TAPROOT_GAP)?;

    Ok(WalletProfile {
        fingerprint: master_fp,
        mnemonic: Some((*canonical_phrase).clone()),
        is_watch_only: false,
        trust_tier: effective_tier,
        trust_badge: effective_tier.badge().to_string(),
        entropy_label: effective_label,
        audit_summary: effective_summary,
        repro_formula_hint: repro_formula_hint.to_string(),
        bip84_tpub,
        bip84_vpub_slip132,
        wpkh_descriptor,
        receive_addresses,
        change_addresses,
        bip86_tpub: Some(bip86_tpub),
        tr_descriptor: Some(tr_descriptor),
        tr_receive_addresses,
        tr_change_addresses,
    })
}

pub fn wallet_from_conditioned_entropy(ent: &ConditionedEntropy) -> Result<WalletProfile, SubZeroError> {
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &ent.bytes)
        .map_err(|e| SubZeroError::Mnemonic(format!("BIP-39 entropy error: {e}")))?;
    let phrase = Zeroizing::new(mnemonic.to_string());
    wallet_from_mnemonic_with_meta(
        &phrase,
        ent.trust_tier,
        &ent.method_label,
        &ent.audit_summary,
        &ent.repro_formula_hint,
    )
}

pub fn load_rehearsal_preset(id: u8) -> Result<WalletProfile, SubZeroError> {
    let preset = get_preset(id)?;
    let bytes = crate::presets::preset_entropy(id)?;
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &bytes)
        .map_err(|e| SubZeroError::Mnemonic(e.to_string()))?;
    let phrase = Zeroizing::new(mnemonic.to_string());
    wallet_from_mnemonic_with_meta(
        &phrase,
        EntropyTrustTier::DeterministicRehearsalPreset,
        &format!("{} ({})", preset.title, preset.formula),
        preset.live_utxo_note,
        &format!("Deterministic Public Testnet4 Entropy Hex: {}", preset.entropy_hex),
    )
}

/// Encode a 12-word BIP-39 mnemonic into a 48-digit SeedSigner CompactSeedQR decimal string.
pub fn mnemonic_to_compact_seed_qr(mnemonic: &str) -> Result<String, SubZeroError> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    if words.len() != 12 {
        return Err(SubZeroError::Mnemonic(format!(
            "CompactSeedQR requires a 12-word mnemonic (got {} words).",
            words.len()
        )));
    }
    let wordlist = Language::English.word_list();
    let mut digits = String::with_capacity(48);
    for w in words {
        let low = w.to_lowercase();
        let idx = wordlist.iter().position(|&x| x == low).ok_or_else(|| {
            SubZeroError::Mnemonic(format!("Word '{}' is not in the BIP-39 English wordlist.", w))
        })?;
        digits.push_str(&format!("{idx:04}"));
    }
    Ok(digits)
}

/// Decode a 48-digit decimal SeedSigner CompactSeedQR string back into a validated 12-word BIP-39 mnemonic.
pub fn compact_seed_qr_to_mnemonic(digits: &str) -> Result<String, SubZeroError> {
    let clean: String = digits
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    if clean.len() != 48 || !clean.chars().all(|c| c.is_ascii_digit()) {
        return Err(SubZeroError::Mnemonic(format!(
            "CompactSeedQR must be 48 decimal digits (got {} chars).",
            clean.len()
        )));
    }
    let wordlist = Language::English.word_list();
    let mut words = Vec::with_capacity(12);
    for i in 0..12 {
        let idx: usize = clean[i * 4..(i + 1) * 4]
            .parse()
            .map_err(|_| SubZeroError::Mnemonic("Invalid 4-digit word index.".into()))?;
        if idx >= wordlist.len() {
            return Err(SubZeroError::Mnemonic(format!(
                "CompactSeedQR index {} exceeds BIP-39 wordlist size (2048).",
                idx
            )));
        }
        words.push(wordlist[idx]);
    }
    let phrase = words.join(" ");
    let _ = Mnemonic::parse_in_normalized(Language::English, &phrase)
        .map_err(|e| SubZeroError::Mnemonic(format!("CompactSeedQR checksum invalid: {e}")))?;
    Ok(phrase)
}

/// Import a 12-word mnemonic, 4-letter metal-plate BIP-39 punch prefixes, 48-digit CompactSeedQR,
/// or Watch-Only Testnet4 descriptor (`wpkh`, `tr`, `tpub`, `vpub`).
pub fn import_wallet_material(raw_input: &str) -> Result<WalletProfile, SubZeroError> {
    let trimmed = raw_input.trim();
    if trimmed.is_empty() {
        return Err(SubZeroError::Mnemonic(
            "Enter a 12-word mnemonic, 4-letter punch prefixes, 48-digit SeedQR, or Testnet4 watch-only descriptor."
                .into(),
        ));
    }

    // Hard-block mainnet or raw private extended-key tokens at token boundaries (avoids substring false-positives inside valid Base58 tpubs)
    for tok in trimmed.split(['(', ')', '[', ']', '/', ',', ' ', '\t', '\r', '\n', '#']) {
        for forbidden in ["xpub", "ypub", "zpub", "xprv", "yprv", "zprv", "tprv", "uprv", "vprv", "bc1q", "bc1p"] {
            if tok.starts_with(forbidden) {
                return Err(SubZeroError::Descriptor(format!(
                    "Rejected '{}': SubZero v2.0 is locked to Bitcoin Testnet4 public watch-only descriptors (`tpub`/`vpub`/`tb1`) and 12-word mnemonics.",
                    forbidden
                )));
            }
        }
    }

    if trimmed.starts_with("wpkh(")
        || trimmed.starts_with("tr(")
        || trimmed.starts_with("tpub")
        || trimmed.starts_with("vpub")
    {
        return import_watch_only_descriptor(trimmed);
    }

    // Check 48-digit CompactSeedQR
    let digits_only: String = trimmed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    if digits_only.len() == 48 && digits_only.chars().all(|c| c.is_ascii_digit()) {
        let phrase = Zeroizing::new(compact_seed_qr_to_mnemonic(&digits_only)?);
        return wallet_from_mnemonic_with_meta(
            &phrase,
            EntropyTrustTier::SecondDeviceReproducible,
            "Imported 48-Digit CompactSeedQR",
            "BIP-39 checksum verified from 48-digit decimal SeedQR.",
            "SeedQR 4-digit word indices (0000..2047)",
        );
    }

    // Otherwise resolve 12 words or 3-4 letter unambiguous BIP-39 prefixes
    let tokens: Vec<String> = trimmed
        .split_whitespace()
        .map(|t| t.to_lowercase())
        .collect();
    if tokens.len() != 12 {
        return Err(SubZeroError::Mnemonic(format!(
            "Expected 12 BIP-39 words (got {}). Use SeedFix if your 12th checksum word is missing.",
            tokens.len()
        )));
    }

    let wordlist = Language::English.word_list();
    let mut resolved = Vec::with_capacity(12);
    let mut used_punch_prefix = false;

    for (pos, tok) in tokens.iter().enumerate() {
        if wordlist.contains(&tok.as_str()) {
            resolved.push(tok.clone());
        } else if (3..=4).contains(&tok.len()) {
            let matches: Vec<&&str> = wordlist.iter().filter(|w| w.starts_with(tok.as_str())).collect();
            match matches.len() {
                1 => {
                    resolved.push((*matches[0]).to_string());
                    used_punch_prefix = true;
                }
                0 => {
                    return Err(SubZeroError::Mnemonic(format!(
                        "Word #{} ('{}') does not match any BIP-39 English word.",
                        pos + 1,
                        tok
                    )));
                }
                _ => {
                    let opts: Vec<&str> = matches.into_iter().copied().collect();
                    return Err(SubZeroError::Mnemonic(format!(
                        "Word #{} prefix '{}' is ambiguous ({}); enter all 4 letters.",
                        pos + 1,
                        tok,
                        opts.join(", ")
                    )));
                }
            }
        } else {
            return Err(SubZeroError::Mnemonic(format!(
                "Word #{} ('{}') is not in the BIP-39 English dictionary.",
                pos + 1,
                tok
            )));
        }
    }

    let phrase = Zeroizing::new(resolved.join(" "));
    let label = if used_punch_prefix {
        "Imported 12-Word Metal Punch Prefixes (BIP-39)"
    } else {
        "Imported 12-Word BIP-39 Mnemonic"
    };
    wallet_from_mnemonic_with_meta(
        &phrase,
        EntropyTrustTier::SecondDeviceReproducible,
        label,
        "12-word BIP-39 checksum verified.",
        "Standard BIP-39 PBKDF2-HMAC-SHA512 (2048 rounds, empty passphrase) -> Testnet4",
    )
}

/// Import a Testnet4 watch-only `wpkh(...)`, `tr(...)`, `tpub...`, or `vpub...` without private keys.
pub fn import_watch_only_descriptor(raw_input: &str) -> Result<WalletProfile, SubZeroError> {
    let body = verify_and_strip_checksum(raw_input)?;
    let norm_h = body.replace(['h', 'H'], "'");
    if norm_h.contains("/0'/") || norm_h.ends_with("/0'") {
        return Err(SubZeroError::Descriptor(
            "Mainnet derivation path (`/0'`) rejected on Testnet4 appliance.".into(),
        ));
    }

    let is_tr = body.starts_with("tr(") && body.ends_with(')');
    let is_wpkh = body.starts_with("wpkh(") && body.ends_with(')');

    let mut parsed_acct_idx: u32 = 0;
    let mut has_origin = false;

    let (fp_str, key_str) = if is_wpkh || is_tr {
        let inner = if is_wpkh {
            &body[5..body.len() - 1]
        } else {
            &body[3..body.len() - 1]
        };
        if inner.ends_with("/1/*") {
            return Err(SubZeroError::Descriptor(
                "Internal-only `/1/*` descriptor rejected; provide an account descriptor (`/<0;1>/*` or `/0/*`)."
                    .into(),
            ));
        }
        let key_expr = if let Some(s) = inner.strip_suffix("/<0;1>/*") {
            s
        } else if let Some(s) = inner.strip_suffix("/0/*") {
            s
        } else if inner.contains("/*") {
            return Err(SubZeroError::Descriptor(
                "Unsupported wildcard branch suffix; expected `/<0;1>/*` or `/0/*` on an account-level xpub."
                    .into(),
            ));
        } else {
            inner
        };

        if let Some(rest) = key_expr.strip_prefix('[') {
            let (origin, xpub_part) = rest.split_once(']').ok_or_else(|| {
                SubZeroError::Descriptor("Malformed `[fingerprint/path]` origin in descriptor.".into())
            })?;
            let origin_norm = origin.replace(['h', 'H'], "'");
            let segs: Vec<&str> = origin_norm.split('/').collect();
            let fp = segs[0];
            if fp.len() != 8 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(SubZeroError::Descriptor(format!(
                    "Invalid 8-hex master fingerprint '{}' in descriptor.",
                    fp
                )));
            }
            if segs.len() != 4 {
                return Err(SubZeroError::Descriptor(format!(
                    "Descriptor origin `[{}]` must be an account-level depth-3 path (`[xfp/{}'/1'/acct']`), not depth {}.",
                    origin,
                    if is_tr { 86 } else { 84 },
                    segs.len().saturating_sub(1)
                )));
            }
            let expected_purpose = if is_tr { "86'" } else { "84'" };
            if segs[1] != expected_purpose {
                return Err(SubZeroError::Descriptor(format!(
                    "Descriptor purpose `{}` does not match wrapper (`{}` expected).",
                    segs[1], expected_purpose
                )));
            }
            if segs[2] != "1'" {
                return Err(SubZeroError::Descriptor(format!(
                    "Descriptor coin_type `{}` rejected; expected Testnet4 `1'`.",
                    segs[2]
                )));
            }
            let acct_str = segs[3].strip_suffix('\'').ok_or_else(|| {
                SubZeroError::Descriptor("Account index in descriptor origin must be hardened (`'`).".into())
            })?;
            parsed_acct_idx = acct_str.parse::<u32>().map_err(|_| {
                SubZeroError::Descriptor(format!("Invalid account index `{}` in descriptor origin.", segs[3]))
            })?;
            has_origin = true;
            (fp.to_lowercase(), xpub_part.to_string())
        } else {
            ("00000000".to_string(), key_expr.to_string())
        }
    } else if body.starts_with("tpub") || body.starts_with("vpub") {
        ("00000000".to_string(), body.to_string())
    } else {
        return Err(SubZeroError::Descriptor(
            "Expected Testnet4 `wpkh(...)`, `tr(...)`, `tpub...`, or `vpub...` descriptor.".into(),
        ));
    };

    if is_tr && key_str.starts_with("vpub") {
        return Err(SubZeroError::Descriptor(
            "SLIP-0132 `vpub` keys are BIP-84 P2WPKH only and cannot be wrapped in `tr(...)`.".into(),
        ));
    }

    let account_xpub = if key_str.starts_with("vpub") {
        decode_slip132_vpub_to_xpub(&key_str)?
    } else {
        Xpub::from_str(&key_str).map_err(|e| SubZeroError::Bip32(e.to_string()))?
    };

    if account_xpub.network != bitcoin::NetworkKind::Test {
        return Err(SubZeroError::Descriptor(
            "Mainnet extended public key rejected on Testnet4 appliance.".into(),
        ));
    }
    if account_xpub.depth != 3 && has_origin {
        return Err(SubZeroError::Descriptor(format!(
            "Extended public key depth is {} (expected account-level depth 3).",
            account_xpub.depth
        )));
    }

    let secp = Secp256k1::new();
    let tpub_str = account_xpub.to_string();

    if is_tr {
        let raw_tr = if has_origin {
            format!("tr([{fp_str}/86'/1'/{parsed_acct_idx}']{tpub_str}/<0;1>/*)")
        } else {
            format!("tr({tpub_str}/<0;1>/*)")
        };
        let tr_desc = attach_descriptor_checksum(&raw_tr)?;
        let tr_recv = derive_tr_branch(&secp, &account_xpub, 0, DEFAULT_ADDRESS_GAP)?;
        let tr_chg = derive_tr_branch(&secp, &account_xpub, 1, DEFAULT_ADDRESS_GAP)?;
        Ok(WalletProfile {
            fingerprint: fp_str,
            mnemonic: None,
            is_watch_only: true,
            trust_tier: EntropyTrustTier::WatchOnlyNoSecrets,
            trust_badge: EntropyTrustTier::WatchOnlyNoSecrets.badge().to_string(),
            entropy_label: "Imported Watch-Only BIP-86 Taproot Descriptor".to_string(),
            audit_summary: "BIP-380 checksum verified; zero private keys in memory.".to_string(),
            repro_formula_hint: format!("Public BIP-86 Taproot watch-only account (m/86'/1'/{parsed_acct_idx}')"),
            bip84_tpub: String::new(),
            bip84_vpub_slip132: String::new(),
            wpkh_descriptor: String::new(),
            receive_addresses: Vec::new(),
            change_addresses: Vec::new(),
            bip86_tpub: Some(tpub_str),
            tr_descriptor: Some(tr_desc),
            tr_receive_addresses: tr_recv,
            tr_change_addresses: tr_chg,
        })
    } else {
        let vpub_slip132 = encode_slip132_vpub(&account_xpub);
        let raw_wpkh = if has_origin {
            format!("wpkh([{fp_str}/84'/1'/{parsed_acct_idx}']{tpub_str}/<0;1>/*)")
        } else {
            format!("wpkh({tpub_str}/<0;1>/*)")
        };
        let wpkh_desc = attach_descriptor_checksum(&raw_wpkh)?;
        let recv = derive_wpkh_branch(&secp, &account_xpub, 0, DEFAULT_ADDRESS_GAP)?;
        let chg = derive_wpkh_branch(&secp, &account_xpub, 1, DEFAULT_ADDRESS_GAP)?;
        Ok(WalletProfile {
            fingerprint: fp_str,
            mnemonic: None,
            is_watch_only: true,
            trust_tier: EntropyTrustTier::WatchOnlyNoSecrets,
            trust_badge: EntropyTrustTier::WatchOnlyNoSecrets.badge().to_string(),
            entropy_label: "Imported Watch-Only BIP-84 Descriptor".to_string(),
            audit_summary: "BIP-380 checksum verified; zero private keys in memory.".to_string(),
            repro_formula_hint: format!("Public BIP-84 Native SegWit watch-only account (m/84'/1'/{parsed_acct_idx}')"),
            bip84_tpub: tpub_str,
            bip84_vpub_slip132: vpub_slip132,
            wpkh_descriptor: wpkh_desc,
            receive_addresses: recv,
            change_addresses: chg,
            bip86_tpub: None,
            tr_descriptor: None,
            tr_receive_addresses: Vec::new(),
            tr_change_addresses: Vec::new(),
        })
    }
}

/// Export a clean Sparrow / Bitcoin Core watch-only JSON containing ZERO private keys (`[C-5]` + `[M-3]` fix).
pub fn export_sparrow_watch_only_json(profile: &WalletProfile) -> Result<String, SubZeroError> {
    let bip84 = if !profile.bip84_tpub.is_empty() {
        Some(SparrowAccountExport {
            derivation: "m/84'/1'/0'".to_string(),
            xpub: profile.bip84_tpub.clone(),
            vpub: Some(profile.bip84_vpub_slip132.clone()),
            descriptor: profile.wpkh_descriptor.clone(),
            first_address: profile
                .receive_addresses
                .first()
                .cloned()
                .unwrap_or_default(),
        })
    } else {
        None
    };

    let bip86 = match (&profile.bip86_tpub, &profile.tr_descriptor) {
        (Some(tpub), Some(desc)) => Some(SparrowAccountExport {
            derivation: "m/86'/1'/0'".to_string(),
            xpub: tpub.clone(),
            vpub: None,
            descriptor: desc.clone(),
            first_address: profile
                .tr_receive_addresses
                .first()
                .cloned()
                .unwrap_or_default(),
        }),
        _ => None,
    };

    let export = SparrowWatchOnlyJson {
        format: "subzero-watch-only-v2".to_string(),
        network: "testnet4".to_string(),
        xfp: profile.fingerprint.clone(),
        bip84,
        bip86,
    };

    serde_json::to_string_pretty(&export)
        .map_err(|e| SubZeroError::Descriptor(format!("JSON serialization failed: {e}")))
}

/// Derive BIP-85 child mnemonics (`m/83696968'/39'/0'/12'/{0..=count}'`):
/// - Index `0`: Decoupled Estate Vault Passphrase (12 words)
/// - Indices `1..=count`: Independent Heir / Sub-Treasury Vaults
pub fn derive_bip85_children(master_mnemonic: &str, count: u32) -> Result<Vec<Bip85Child>, SubZeroError> {
    let capped = count.min(20);
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, master_mnemonic)
        .map_err(|e| SubZeroError::Mnemonic(format!("Invalid master mnemonic: {e}")))?;
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    let secp = Secp256k1::new();
    let master_xprv = ZeroizingXpriv(
        Xpriv::new_master(Network::Testnet4, seed.as_ref())
            .map_err(|e| SubZeroError::Bip32(e.to_string()))?,
    );

    let mut children = Vec::with_capacity((capped + 1) as usize);
    for idx in 0..=capped {
        let path_str = format!("m/83696968'/39'/0'/12'/{idx}'");
        let path =
            DerivationPath::from_str(&path_str).map_err(|e| SubZeroError::Bip32(e.to_string()))?;
        let derived = ZeroizingXpriv(
            master_xprv
                .0
                .derive_priv(&secp, &path)
                .map_err(|e| SubZeroError::Bip32(e.to_string()))?,
        );

        let mut mac = HmacSha512::new_from_slice(b"bip-entropy-from-k")
            .map_err(|_| SubZeroError::Bip32("HMAC error".into()))?;
        let mut sk_bytes = derived.0.private_key.secret_bytes();
        mac.update(&sk_bytes);
        sk_bytes.zeroize();
        let mut digest = mac.finalize().into_bytes();

        let child_mnemonic = Mnemonic::from_entropy_in(Language::English, &digest[..16])
            .map_err(|e| SubZeroError::Mnemonic(e.to_string()))?;
        digest.zeroize();

        let label = if idx == 0 {
            "Decoupled Estate Passphrase (Index 0)".to_string()
        } else {
            format!("Heir / Sub-Treasury Seed #{idx:02}")
        };
        children.push(Bip85Child {
            label,
            index: idx,
            path: path_str,
            mnemonic: child_mnemonic.to_string(),
        });
    }
    Ok(children)
}

impl Bip85Child {
    pub fn derive_public_summary(&self) -> Result<Bip85ChildPublic, SubZeroError> {
        let prof = wallet_from_mnemonic_with_meta(
            &self.mnemonic,
            EntropyTrustTier::SecondDeviceReproducible,
            &self.label,
            &self.path,
            "BIP-85 child m/83696968'/39'/0'/12'/i'",
        )?;
        Ok(Bip85ChildPublic {
            index: self.index,
            path: self.path.clone(),
            label: self.label.clone(),
            fingerprint: prof.fingerprint.clone(),
            xpub: prof.bip84_tpub.clone(),
            vpub_slip132: prof.bip84_vpub_slip132.clone(),
            descriptor: prof.wpkh_descriptor.clone(),
            first_receive_address: prof.receive_addresses.first().cloned().unwrap_or_default(),
            first_change_address: prof.change_addresses.first().cloned().unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presets::list_presets;

    #[test]
    fn test_all_10_unified_testnet4_presets_match_fingerprints_and_mnemonics() {
        let presets = list_presets();
        assert_eq!(presets.len(), 10);
        for p in presets {
            let prof = load_rehearsal_preset(p.id).unwrap();
            assert_eq!(
                prof.fingerprint, p.expected_fingerprint,
                "Fingerprint mismatch on Preset {}",
                p.id
            );
            assert_eq!(
                prof.mnemonic.as_deref(),
                Some(p.expected_mnemonic),
                "Mnemonic mismatch on Preset {}",
                p.id
            );
            assert_eq!(prof.trust_tier, EntropyTrustTier::DeterministicRehearsalPreset);
            assert!(prof.receive_addresses[0].starts_with("tb1q"));
            assert!(prof.change_addresses[0].starts_with("tb1q"));
            assert!(prof.tr_receive_addresses[0].starts_with("tb1p"));

            // Watch-only export MUST NOT leak any word of the mnemonic!
            let json = export_sparrow_watch_only_json(&prof).unwrap();
            assert!(!json.contains(p.expected_mnemonic));
            assert!(json.contains(&prof.bip84_tpub));
        }
    }

    #[test]
    fn test_compact_seed_qr_punch_and_watch_only_roundtrip() {
        let p0 = load_rehearsal_preset(0).unwrap();
        let digits = mnemonic_to_compact_seed_qr(p0.mnemonic.as_deref().unwrap()).unwrap();
        assert_eq!(digits, "000000000000000000000000000000000000000000000003");

        let from_qr = import_wallet_material(&digits).unwrap();
        assert_eq!(from_qr.fingerprint, "73c5da0a");
        // Importing known public Preset 0 MUST automatically downgrade badge to DeterministicRehearsalPreset!
        assert_eq!(from_qr.trust_tier, EntropyTrustTier::DeterministicRehearsalPreset);

        let from_punch =
            import_wallet_material("aban aban aban aban aban aban aban aban aban aban aban abou")
                .unwrap();
        assert_eq!(from_punch.fingerprint, "73c5da0a");
        assert_eq!(from_punch.trust_tier, EntropyTrustTier::DeterministicRehearsalPreset);

        // Official BIP-84 / SLIP-0132 Testnet4 Vector 0 (`abandon...about`, `73c5da0a`)
        let p0 = load_rehearsal_preset(0).unwrap();
        assert_eq!(
            p0.receive_addresses[0],
            "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"
        );
        assert_eq!(
            p0.bip84_vpub_slip132,
            "vpub5Y6cjg78GGuNLsaPhmYsiw4gYX3HoQiRBiSwDaBXKUafCt9bNwWQiitDk5VZ5BVxYnQdwoTyXSs2JHRPAgjAvtbBrf8ZhDYe2jWAqvZVnsc"
        );

        let watch = import_wallet_material(&p0.wpkh_descriptor).unwrap();
        assert!(watch.is_watch_only);
        assert!(watch.mnemonic.is_none());
        assert_eq!(watch.receive_addresses[0], p0.receive_addresses[0]);

        // Watch-only Taproot (`tr(...)`) export MUST NOT mislabel tr descriptors/addresses as BIP-84 wpkh!
        let watch_tr = import_wallet_material(p0.tr_descriptor.as_deref().unwrap()).unwrap();
        assert!(watch_tr.wpkh_descriptor.is_empty());
        assert!(watch_tr.receive_addresses.is_empty());
        assert_eq!(watch_tr.tr_receive_addresses[0], p0.tr_receive_addresses[0]);
        let tr_json = export_sparrow_watch_only_json(&watch_tr).unwrap();
        assert!(!tr_json.contains("\"bip84\""), "TR-only watch wallet must not emit bip84: {tr_json}");
        assert!(tr_json.contains("\"bip86\""));

        // Mainnet `84h/0h/0h` descriptor origin and branch-level `84'/1'/0'/0` origin MUST be rejected!
        let bad_h_mainnet = format!("wpkh([73c5da0a/84h/0h/0h]{}/<0;1>/*)", p0.bip84_tpub);
        assert!(import_wallet_material(&bad_h_mainnet).is_err());
        let bad_branch = format!("wpkh([73c5da0a/84'/1'/0'/0]{}/*)", p0.bip84_tpub);
        assert!(import_wallet_material(&bad_branch).is_err());

        // Mainnet xpub/bc1 must be rejected
        assert!(import_wallet_material("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8").is_err());
    }
}
