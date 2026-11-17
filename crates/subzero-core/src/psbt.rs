//! Verified Two-Way PSBT Audit & Airgap Signer (`P2WPKH` BIP-84 + `P2TR` BIP-86 Key-Path).
//!
//! SECURITY INVARIANTS (`[C-02]`, `[H-03]`, `[M-01]` FIXES):
//! 1. Cryptographic Change Verification (`[C-02]`): NEVER trust `output.bip32_derivation` or
//!    `output.tap_key_origins` metadata on faith. Any output claiming our master fingerprint MUST
//!    have its expected `script_pubkey` independently derived from our own `master_xprv` / `xpub`
//!    along the claimed path (`m/84'/1'/0'/<0|1>/<idx>` or `m/86'/1'/0'/<0|1>/<idx>`) and matched
//!    byte-for-byte against `txout.script_pubkey`. Any mismatch triggers a fatal change-spoofing
//!    block and refuses to sign.
//! 2. SegWit v0 Fee-Lie Defense (`[H-03]` / `CVE-2020-14199`): Every SegWit v0 (`P2WPKH`) input MUST
//!    include a full `non_witness_utxo` whose `compute_txid()` matches `txin.previous_output.txid`
//!    and whose `output[vout]` exists and matches `witness_utxo` (if present). Taproot (`P2TR`)
//!    commits to `Prevouts::All` directly inside the BIP-341 Schnorr sighash.
//! 3. Zero Blind Signing: Every input MUST supply a verified UTXO value (`witness_utxo` or
//!    verified `non_witness_utxo`), `total_output_sat <= total_input_sat`, and sighash MUST be
//!    `SIGHASH_ALL` (SegWit v0) or `SIGHASH_DEFAULT` / `SIGHASH_ALL` (Taproot).
//! 4. Mainnet Derivation Hard-Block: Rejects any `m/.../0'/...` BIP-32 coin-type path on inputs or outputs.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use base64::prelude::*;
use bip39::{Language, Mnemonic};
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv};
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{Address, CompressedPublicKey, KnownHrp, Network, ScriptBuf, TxOut};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::SubZeroError;
use crate::keys::ZeroizingXpriv;

pub const MAX_PSBT_RAW_BYTES: usize = 2 * 1024 * 1024;
pub const ADDRESS_SCAN_WINDOW: u32 = 100;
pub const MAX_ALLOWED_DERIVATION_INDEX: u32 = 999;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtInputReport {
    pub index: usize,
    pub outpoint: String,
    pub amount_sat: Option<u64>,
    pub address: Option<String>,
    pub script_type: String,
    pub is_ours: bool,
    pub verified_path: Option<String>,
    pub sighash_label: String,
    pub rbf_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtOutputReport {
    pub index: usize,
    pub address: String,
    pub address_chunked: String,
    pub script_type: String,
    pub amount_sat: u64,
    pub is_verified_change: bool,
    pub is_verified_self_receive: bool,
    pub verified_path: Option<String>,
    pub derivation_index: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtInspection {
    pub txid: String,
    pub inputs: Vec<PsbtInputReport>,
    pub outputs: Vec<PsbtOutputReport>,
    pub total_input_sat: Option<u64>,
    pub total_output_sat: u64,
    pub net_external_spend_sat: u64,
    pub fee_sat: Option<u64>,
    pub fee_rate_sat_vb: Option<f64>,
    pub fee_pct: Option<f64>,
    pub vsize: usize,
    pub locktime: u32,
    pub is_rbf_active: bool,
    pub can_sign: bool,
    pub warnings: Vec<String>,
    pub fatal_blocks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPsbtArtifact {
    pub signatures_added: usize,
    pub txid: String,
    pub signed_psbt_base64: String,
    pub signed_psbt_hex: String,
    pub bbqr_parts: Vec<String>,
    pub inspection: PsbtInspection,
}

pub fn parse_psbt_any(raw: &[u8]) -> Result<Psbt, SubZeroError> {
    if raw.is_empty() {
        return Err(SubZeroError::Psbt("Empty PSBT input.".into()));
    }
    if raw.len() > MAX_PSBT_RAW_BYTES {
        return Err(SubZeroError::Psbt("PSBT exceeds 2 MB safety limit.".into()));
    }
    if let Ok(psbt) = Psbt::deserialize(raw) {
        return Ok(psbt);
    }
    if let Ok(text) = core::str::from_utf8(raw) {
        let trimmed: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if let Ok(bytes) = BASE64_STANDARD.decode(&trimmed) {
            if let Ok(psbt) = Psbt::deserialize(&bytes) {
                return Ok(psbt);
            }
        }
        if let Ok(bytes) = hex::decode(&trimmed) {
            if let Ok(psbt) = Psbt::deserialize(&bytes) {
                return Ok(psbt);
            }
        }
    }
    Err(SubZeroError::Psbt(
        "Failed to parse PSBT (expected binary PSBTv0, Base64 'cHNidP...', or hexadecimal)."
            .into(),
    ))
}

pub fn classify_script(script: &ScriptBuf) -> &'static str {
    if script.is_p2wpkh() {
        "P2WPKH (Native SegWit)"
    } else if script.is_p2tr() {
        "P2TR (Taproot)"
    } else if script.is_p2wsh() {
        "P2WSH (SegWit Script)"
    } else if script.is_p2sh() {
        "P2SH (Nested/Legacy Script)"
    } else if script.is_p2pkh() {
        "P2PKH (Legacy)"
    } else if script.is_op_return() {
        "OP_RETURN (Data)"
    } else {
        "Unknown Script"
    }
}

pub fn chunk_address(addr: &str) -> String {
    let mut out = String::with_capacity(addr.len() + addr.len() / 4);
    for (i, ch) in addr.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push(' ');
        }
        out.push(ch);
    }
    out
}

fn is_mainnet_derivation_path(path: &DerivationPath) -> bool {
    let comps: Vec<ChildNumber> = path.into_iter().copied().collect();
    matches!(
        comps.get(1),
        Some(ChildNumber::Hardened { index: 0 } | ChildNumber::Normal { index: 0 })
    )
}

/// Validate a claimed BIP-84 (`m/84'/1'/0'/<0|1>/<idx>`) or BIP-86 (`m/86'/1'/0'/<0|1>/<idx>`) path
/// and derive the exact expected `ScriptBuf` directly from `master_xprv`.
fn derive_expected_script_for_path(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    master_xprv: &Xpriv,
    path: &DerivationPath,
) -> Option<(ScriptBuf, u32, u32)> {
    let comps: Vec<ChildNumber> = path.into_iter().copied().collect();
    if comps.len() != 5 {
        return None;
    }
    let purpose = match comps[0] {
        ChildNumber::Hardened { index: 84 } => 84,
        ChildNumber::Hardened { index: 86 } => 86,
        _ => return None,
    };
    if comps[1] != (ChildNumber::Hardened { index: 1 })
        || comps[2] != (ChildNumber::Hardened { index: 0 })
    {
        return None;
    }
    let change = match comps[3] {
        ChildNumber::Normal { index: c } if c <= 1 => c,
        _ => return None,
    };
    let addr_idx = match comps[4] {
        ChildNumber::Normal { index: idx } if idx <= MAX_ALLOWED_DERIVATION_INDEX => idx,
        _ => return None,
    };

    let mut derived = master_xprv.derive_priv(secp, path).ok()?;
    let script = if purpose == 84 {
        let pk = derived.private_key.public_key(secp);
        Address::p2wpkh(&CompressedPublicKey(pk), KnownHrp::Testnets).script_pubkey()
    } else {
        let (xonly, _) = derived.private_key.x_only_public_key(secp);
        Address::p2tr(secp, xonly, None, KnownHrp::Testnets).script_pubkey()
    };
    if let Ok(dummy) = Xpriv::new_master(Network::Testnet4, &[0u8; 16]) {
        unsafe {
            core::ptr::write_volatile(&mut derived, dummy);
        }
    }
    Some((script, change, addr_idx))
}

struct VaultKeyOracle {
    secp: Secp256k1<bitcoin::secp256k1::All>,
    master_xprv: Xpriv,
    master_fp: Fingerprint,
    // Precomputed lookup: ScriptBuf -> (path_string, change_branch, index)
    known_scripts: BTreeMap<ScriptBuf, (String, u32, u32)>,
}

impl Drop for VaultKeyOracle {
    fn drop(&mut self) {
        if let Ok(dummy) = Xpriv::new_master(Network::Testnet4, &[0u8; 16]) {
            unsafe {
                core::ptr::write_volatile(&mut self.master_xprv, dummy);
            }
        }
    }
}

impl VaultKeyOracle {
    fn from_mnemonic(mnemonic_str: &str) -> Result<Self, SubZeroError> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_str)
            .map_err(|e| SubZeroError::Mnemonic(format!("Invalid mnemonic: {e}")))?;
        let seed = Zeroizing::new(mnemonic.to_seed(""));
        let secp = Secp256k1::new();
        let master_xprv = Xpriv::new_master(Network::Testnet4, seed.as_ref())
            .map_err(|e| SubZeroError::Bip32(e.to_string()))?;
        let master_fp = master_xprv.fingerprint(&secp);

        let mut known_scripts = BTreeMap::new();
        for purpose in [84u32, 86u32] {
            for change in [0u32, 1u32] {
                for idx in 0..ADDRESS_SCAN_WINDOW {
                    let path_str = format!("m/{purpose}'/1'/0'/{change}/{idx}");
                    if let Ok(path) = DerivationPath::from_str(&path_str) {
                        if let Some((script, c, k)) =
                            derive_expected_script_for_path(&secp, &master_xprv, &path)
                        {
                            known_scripts.insert(script, (path_str, c, k));
                        }
                    }
                }
            }
        }

        Ok(Self {
            secp,
            master_xprv,
            master_fp,
            known_scripts,
        })
    }
}

/// Inspect and cryptographically audit an unsigned or partially signed PSBT.
pub fn inspect_psbt(
    psbt: &Psbt,
    mnemonic_opt: Option<&str>,
    session_recipient_history: Option<&BTreeSet<String>>,
) -> Result<PsbtInspection, SubZeroError> {
    if psbt.inputs.len() != psbt.unsigned_tx.input.len()
        || psbt.outputs.len() != psbt.unsigned_tx.output.len()
    {
        return Err(SubZeroError::Psbt(
            "Malformed PSBT: input/output metadata count does not match unsigned_tx.".into(),
        ));
    }

    let oracle = match mnemonic_opt {
        Some(m) if !m.trim().is_empty() => Some(VaultKeyOracle::from_mnemonic(m)?),
        _ => None,
    };

    let mut warnings = Vec::new();
    let mut fatal_blocks = Vec::new();

    if psbt.inputs.is_empty() {
        fatal_blocks.push("PSBT has zero inputs.".to_string());
    }
    if psbt.outputs.is_empty() {
        fatal_blocks.push("PSBT has zero outputs.".to_string());
    }

    let mut input_reports = Vec::with_capacity(psbt.inputs.len());
    let mut total_in_sat = 0u64;
    let mut all_inputs_have_value = true;
    let mut spent_scripts: Vec<(usize, ScriptBuf)> = Vec::new();
    let mut any_ours = false;

    for (i, psbt_in) in psbt.inputs.iter().enumerate() {
        let txin = &psbt.unsigned_tx.input[i];
        let outpoint = format!("{}:{}", txin.previous_output.txid, txin.previous_output.vout);
        let rbf_enabled = txin.sequence.0 < 0xffff_fffe;

        // Check mainnet coin_type on bip32_derivation and tap_key_origins
        for (_pk, (fp, path)) in &psbt_in.bip32_derivation {
            if is_mainnet_derivation_path(path) {
                fatal_blocks.push(format!(
                    "Mainnet derivation path ({path}, fp {fp}) detected on Input #{i}; blocked on Testnet4 appliance."
                ));
            }
        }
        for (_xpk, (_leaves, (fp, path))) in &psbt_in.tap_key_origins {
            if is_mainnet_derivation_path(path) {
                fatal_blocks.push(format!(
                    "Mainnet Taproot derivation path ({path}, fp {fp}) detected on Input #{i}; blocked on Testnet4 appliance."
                ));
            }
        }

        // Verify non_witness_utxo TXID & vout bounds if present (prevents SegWit fee-lie attack)
        let vout_idx = txin.previous_output.vout as usize;
        let mut verified_nw_txout: Option<&TxOut> = None;
        if let Some(ref full_prev_tx) = psbt_in.non_witness_utxo {
            let computed_txid = full_prev_tx.compute_txid();
            if computed_txid != txin.previous_output.txid {
                fatal_blocks.push(format!(
                    "Input #{i} non_witness_utxo TXID mismatch (got {computed_txid}, expected {}). Possible fee-spoofing attack!",
                    txin.previous_output.txid
                ));
            }
            match full_prev_tx.output.get(vout_idx) {
                Some(prev_out) => {
                    verified_nw_txout = Some(prev_out);
                }
                None => {
                    fatal_blocks.push(format!(
                        "Input #{i} outpoint vout {} is out of range for non_witness_utxo ({} outputs)!",
                        vout_idx,
                        full_prev_tx.output.len()
                    ));
                }
            }
        }

        // Extract authoritative TxOut (requiring cross-check when both witness_utxo and non_witness_utxo exist)
        let resolved_txout: Option<&TxOut> = match (&psbt_in.witness_utxo, verified_nw_txout) {
            (Some(w_utxo), Some(prev_out)) => {
                if prev_out.value != w_utxo.value || prev_out.script_pubkey != w_utxo.script_pubkey {
                    fatal_blocks.push(format!(
                        "Input #{i} witness_utxo contradicts non_witness_utxo value/script!"
                    ));
                }
                Some(prev_out)
            }
            (Some(_), None) if psbt_in.non_witness_utxo.is_some() => None,
            (Some(w_utxo), None) => Some(w_utxo),
            (None, Some(prev_out)) => Some(prev_out),
            (None, None) => None,
        };

        let (amount_sat, script_opt) = match resolved_txout {
            Some(txo) => {
                let v = txo.value.to_sat();
                match total_in_sat.checked_add(v) {
                    Some(sum) => total_in_sat = sum,
                    None => fatal_blocks.push("Input satoshi sum overflowed u64.".into()),
                }
                spent_scripts.push((i, txo.script_pubkey.clone()));
                (Some(v), Some(&txo.script_pubkey))
            }
            None => {
                all_inputs_have_value = false;
                fatal_blocks.push(format!(
                    "Input #{i} is missing UTXO amount/script (blind signing is hard-blocked)."
                ));
                (None, None)
            }
        };

        let (address, script_type, is_tr_script, is_wpkh_script) = match script_opt {
            Some(sp) => {
                let st = classify_script(sp).to_string();
                let addr = Address::from_script(sp, Network::Testnet4)
                    .ok()
                    .map(|a| a.to_string());
                (addr, st, sp.is_p2tr(), sp.is_p2wpkh())
            }
            None => (None, "Missing UTXO".to_string(), false, false),
        };

        if is_wpkh_script && psbt_in.non_witness_utxo.is_none() {
            fatal_blocks.push(format!(
                "Input #{i} is SegWit v0 (P2WPKH) without non_witness_utxo; full previous transaction is required to prevent BIP-143 fee-spoofing attacks."
            ));
        }

        if script_opt.is_some() && !is_wpkh_script && !is_tr_script {
            warnings.push(format!(
                "Input #{i} uses {script_type}; SubZero signs single-sig BIP-84 P2WPKH and BIP-86 Taproot key-path inputs."
            ));
        }

        // Enforce safe sighash type
        let sighash_label = match psbt_in.sighash_type {
            None => {
                if is_tr_script {
                    "SIGHASH_DEFAULT (Taproot All)".to_string()
                } else {
                    "SIGHASH_ALL (Default)".to_string()
                }
            }
            Some(st) => {
                let raw_u32 = st.to_u32();
                let allowed = if is_tr_script {
                    raw_u32 == TapSighashType::Default as u32 || raw_u32 == TapSighashType::All as u32
                } else {
                    raw_u32 == EcdsaSighashType::All as u32
                };
                if !allowed {
                    fatal_blocks.push(format!(
                        "Input #{i} requests unsafe sighash type ({st:?}); only SIGHASH_ALL / SIGHASH_DEFAULT is permitted."
                    ));
                }
                format!("{st:?}")
            }
        };

        // Verify ownership if VaultKeyOracle is loaded
        let mut is_ours = false;
        let mut verified_path = None;
        if let (Some(ref orc), Some(sp)) = (&oracle, script_opt) {
            for (_pk, (fp, path)) in &psbt_in.bip32_derivation {
                if *fp == orc.master_fp {
                    if let Some((exp_sp, _, _)) =
                        derive_expected_script_for_path(&orc.secp, &orc.master_xprv, path)
                    {
                        if &exp_sp == sp {
                            is_ours = true;
                            verified_path = Some(format!("m/{}", path));
                            break;
                        }
                    }
                }
            }
            if !is_ours {
                for (_xpk, (_leaves, (fp, path))) in &psbt_in.tap_key_origins {
                    if *fp == orc.master_fp {
                        if let Some((exp_sp, _, _)) =
                            derive_expected_script_for_path(&orc.secp, &orc.master_xprv, path)
                        {
                            if &exp_sp == sp {
                                is_ours = true;
                                verified_path = Some(format!("m/{}", path));
                                break;
                            }
                        }
                    }
                }
            }
            if !is_ours {
                if let Some((p_str, _, _)) = orc.known_scripts.get(sp) {
                    is_ours = true;
                    verified_path = Some(p_str.clone());
                }
            }
        }
        if is_ours {
            any_ours = true;
        }

        input_reports.push(PsbtInputReport {
            index: i,
            outpoint,
            amount_sat,
            address,
            script_type,
            is_ours,
            verified_path,
            sighash_label,
            rbf_enabled,
        });
    }

    if oracle.is_some() && !any_ours {
        fatal_blocks.push(
            "None of the PSBT inputs belong to the active SubZero wallet fingerprint.".to_string(),
        );
    }

    // 2. Audit Outputs (with strict cryptographic self-change verification!)
    let mut output_reports = Vec::with_capacity(psbt.outputs.len());
    let mut total_out_sat = 0u64;
    let mut verified_self_sat = 0u64;
    let mut has_verified_change = false;
    let mut seen_scripts: BTreeMap<ScriptBuf, usize> = BTreeMap::new();

    for (j, txout) in psbt.unsigned_tx.output.iter().enumerate() {
        let amt = txout.value.to_sat();
        match total_out_sat.checked_add(amt) {
            Some(sum) => total_out_sat = sum,
            None => fatal_blocks.push("Output satoshi sum overflowed u64.".into()),
        }

        let script = &txout.script_pubkey;
        let script_type = classify_script(script).to_string();

        for (in_idx, in_sp) in &spent_scripts {
            if in_sp == script {
                warnings.push(format!(
                    "Address reuse warning: Output #{j} sends funds back to spending Input #{in_idx}."
                ));
            }
        }
        if let Some(prev_j) = seen_scripts.get(script) {
            warnings.push(format!(
                "Duplicate output script: Output #{j} pays the exact same script as Output #{prev_j}."
            ));
        } else {
            seen_scripts.insert(script.clone(), j);
        }

        let out_psbt = &psbt.outputs[j];
        for (_pk, (fp, path)) in &out_psbt.bip32_derivation {
            if is_mainnet_derivation_path(path) {
                fatal_blocks.push(format!(
                    "Mainnet derivation path ({path}, fp {fp}) on Output #{j}; signing blocked."
                ));
            }
        }
        for (_xpk, (_leaves, (fp, path))) in &out_psbt.tap_key_origins {
            if is_mainnet_derivation_path(path) {
                fatal_blocks.push(format!(
                    "Mainnet Taproot derivation path ({path}, fp {fp}) on Output #{j}; signing blocked."
                ));
            }
        }

        let address = Address::from_script(script, Network::Testnet4)
            .map(|a| a.to_string())
            .unwrap_or_else(|_| format!("script:{}", hex::encode(script.as_bytes())));

        let mut is_verified_change = false;
        let mut is_verified_self_receive = false;
        let mut verified_path = None;
        let mut derivation_index = None;

        if let Some(ref orc) = oracle {
            // (a) Verify EVERY explicit PSBT metadata entry claiming our master fingerprint -
            //     one valid entry never excuses a spoofed sibling entry in either map!
            let mut claimed_our_fp = false;
            let mut metadata_verified = false;
            let mut spoof_detected = false;

            let metadata_entries = out_psbt
                .bip32_derivation
                .values()
                .map(|(fp, path)| (*fp, path))
                .chain(
                    out_psbt
                        .tap_key_origins
                        .values()
                        .map(|(_leaves, (fp, path))| (*fp, path)),
                );

            for (fp, path) in metadata_entries {
                if fp == orc.master_fp {
                    claimed_our_fp = true;
                    if let Some((_exp_sp, chg, idx)) =
                        derive_expected_script_for_path(&orc.secp, &orc.master_xprv, path)
                            .filter(|(exp_sp, _, _)| exp_sp == script)
                    {
                        if !metadata_verified {
                            metadata_verified = true;
                            derivation_index = Some(idx);
                            verified_path = Some(format!("m/{}", path));
                            if chg == 1 {
                                is_verified_change = true;
                            } else {
                                is_verified_self_receive = true;
                            }
                        }
                    } else {
                        spoof_detected = true;
                    }
                }
            }

            if (claimed_our_fp && !metadata_verified) || spoof_detected {
                fatal_blocks.push(format!(
                    "[CRITICAL CHANGE-SPOOFING BLOCKED] Output #{j} ({address}) claims our wallet fingerprint ({}) in PSBT metadata, but its locking script does NOT match our derived key! Refusing to sign.",
                    orc.master_fp
                ));
            }

            // (b) Fallback: check precomputed 0..100 BIP-84/86 receive/change scripts
            if !metadata_verified && !claimed_our_fp {
                if let Some((p_str, chg, idx)) = orc.known_scripts.get(script) {
                    verified_path = Some(p_str.clone());
                    derivation_index = Some(*idx);
                    if *chg == 1 {
                        is_verified_change = true;
                    } else {
                        is_verified_self_receive = true;
                    }
                }
            }

            if let Some(idx) = derivation_index {
                if idx > 20 {
                    warnings.push(format!(
                        "Gap limit warning: Output #{j} uses derivation index #{idx} (>20 standard wallet gap limit)."
                    ));
                }
            }
        }

        if is_verified_change {
            has_verified_change = true;
            verified_self_sat = verified_self_sat.saturating_add(amt);
        } else if is_verified_self_receive {
            verified_self_sat = verified_self_sat.saturating_add(amt);
        } else if let Some(hist) = session_recipient_history {
            if hist.contains(&address) {
                warnings.push(format!(
                    "Session address reuse: External recipient Output #{j} ({address}) was already paid earlier in this session."
                ));
            }
        }

        let address_chunked = chunk_address(&address);
        output_reports.push(PsbtOutputReport {
            index: j,
            address,
            address_chunked,
            script_type,
            amount_sat: amt,
            is_verified_change,
            is_verified_self_receive,
            verified_path,
            derivation_index,
        });
    }

    if !has_verified_change && !output_reports.is_empty() {
        warnings.push(
            "No verified internal change output detected (100% of inputs minus miner fee leave internal change branch)."
                .to_string(),
        );
    }

    let total_input_sat = if all_inputs_have_value {
        if total_out_sat > total_in_sat {
            fatal_blocks.push(format!(
                "Invalid PSBT: total outputs ({total_out_sat} sats) exceed total inputs ({total_in_sat} sats)."
            ));
        }
        Some(total_in_sat)
    } else {
        None
    };

    let fee_sat = total_input_sat.and_then(|tin| tin.checked_sub(total_out_sat));

    // Estimate final signed virtual size (adding SegWit witness weight for unsigned inputs)
    let mut weight_wu = psbt.unsigned_tx.weight().to_wu();
    let has_any_witness = psbt
        .unsigned_tx
        .input
        .iter()
        .any(|txin| !txin.witness.is_empty());
    let mut added_witness = false;
    for (i, txin) in psbt.unsigned_tx.input.iter().enumerate() {
        if txin.witness.is_empty() {
            if let Some((_, sp)) = spent_scripts.iter().find(|(idx, _)| *idx == i) {
                if sp.is_p2wpkh() {
                    weight_wu = weight_wu.saturating_add(107);
                    added_witness = true;
                } else if sp.is_p2tr() {
                    weight_wu = weight_wu.saturating_add(66);
                    added_witness = true;
                }
            }
        }
    }
    if !has_any_witness && added_witness {
        weight_wu = weight_wu.saturating_add(2);
    }
    let vsize = (weight_wu.div_ceil(4) as usize).max(1);
    let fee_rate_sat_vb = fee_sat.map(|f| (f as f64) / (vsize as f64));
    let fee_pct = match (fee_sat, total_input_sat) {
        (Some(f), Some(tin)) if tin > 0 => Some((f as f64) * 100.0 / (tin as f64)),
        _ => None,
    };

    if let Some(pct) = fee_pct {
        if pct > 25.0 {
            warnings.push(format!(
                "High fee warning: Network fee burns {pct:.1}% of total input value ({} sats).",
                fee_sat.unwrap_or(0)
            ));
        }
    }
    if let Some(rate) = fee_rate_sat_vb {
        if rate > 200.0 {
            warnings.push(format!(
                "High fee-rate warning: {rate:.1} sat/vB exceeds normal Testnet4 mempool rates."
            ));
        }
    }

    let net_external_spend_sat = total_input_sat
        .unwrap_or(total_out_sat)
        .saturating_sub(verified_self_sat);
    let is_rbf_active = input_reports.iter().any(|r| r.rbf_enabled);
    let can_sign = oracle.is_some() && fatal_blocks.is_empty();

    Ok(PsbtInspection {
        txid: psbt.unsigned_tx.compute_txid().to_string(),
        inputs: input_reports,
        outputs: output_reports,
        total_input_sat,
        total_output_sat: total_out_sat,
        net_external_spend_sat,
        fee_sat,
        fee_rate_sat_vb,
        fee_pct,
        vsize,
        locktime: psbt.unsigned_tx.lock_time.to_consensus_u32(),
        is_rbf_active,
        can_sign,
        warnings,
        fatal_blocks,
    })
}

/// Deterministically sign all owned `P2WPKH` (BIP-84) and `P2TR` (BIP-86 key-path) inputs on a
/// verified Testnet4 PSBT. Refuses to sign if `inspect_psbt` reports any `fatal_blocks` or if
/// `signatures_added == 0`.
pub fn sign_psbt(
    psbt: &mut Psbt,
    mnemonic_str: &str,
    session_recipient_history: Option<&BTreeSet<String>>,
) -> Result<SignedPsbtArtifact, SubZeroError> {
    let inspection = inspect_psbt(psbt, Some(mnemonic_str), session_recipient_history)?;
    if !inspection.fatal_blocks.is_empty() {
        return Err(SubZeroError::Psbt(format!(
            "PSBT signing blocked by security policy: {}",
            inspection.fatal_blocks.join(" | ")
        )));
    }

    let oracle = VaultKeyOracle::from_mnemonic(mnemonic_str)?;
    let unsigned_tx = psbt.unsigned_tx.clone();

    // Collect authoritative prevouts across all inputs (preferring TXID-verified non_witness_utxo)
    let mut prevouts_vec: Vec<TxOut> = Vec::with_capacity(psbt.inputs.len());
    for (i, psbt_in) in psbt.inputs.iter().enumerate() {
        if let Some(ref nw) = psbt_in.non_witness_utxo {
            let vout = unsigned_tx.input[i].previous_output.vout as usize;
            let txo = nw.output.get(vout).ok_or_else(|| {
                SubZeroError::Psbt(format!("Input #{i} outpoint vout out of range."))
            })?;
            prevouts_vec.push(txo.clone());
        } else if let Some(ref w_utxo) = psbt_in.witness_utxo {
            prevouts_vec.push(w_utxo.clone());
        } else {
            return Err(SubZeroError::Psbt(format!(
                "Input #{i} missing UTXO prevout."
            )));
        }
    }

    let mut signatures_added = 0usize;

    for (i, psbt_in) in psbt.inputs.iter_mut().enumerate() {
        let prev_txout = &prevouts_vec[i];
        let sp = &prev_txout.script_pubkey;

        // Resolve matching DerivationPath for this input
        let mut matched_path: Option<DerivationPath> = None;
        for (_pk, (fp, path)) in &psbt_in.bip32_derivation {
            if *fp == oracle.master_fp {
                if let Some((exp_sp, _, _)) =
                    derive_expected_script_for_path(&oracle.secp, &oracle.master_xprv, path)
                {
                    if &exp_sp == sp {
                        matched_path = Some(path.clone());
                        break;
                    }
                }
            }
        }
        if matched_path.is_none() {
            for (_xpk, (_leaves, (fp, path))) in &psbt_in.tap_key_origins {
                if *fp == oracle.master_fp {
                    if let Some((exp_sp, _, _)) =
                        derive_expected_script_for_path(&oracle.secp, &oracle.master_xprv, path)
                    {
                        if &exp_sp == sp {
                            matched_path = Some(path.clone());
                            break;
                        }
                    }
                }
            }
        }
        if matched_path.is_none() {
            if let Some((p_str, _, _)) = oracle.known_scripts.get(sp) {
                matched_path = DerivationPath::from_str(p_str).ok();
            }
        }

        let Some(path) = matched_path else {
            continue;
        };

        let child_xprv = ZeroizingXpriv(
            oracle
                .master_xprv
                .derive_priv(&oracle.secp, &path)
                .map_err(|e| SubZeroError::Bip32(e.to_string()))?,
        );

        if sp.is_p2wpkh() {
            let sighash_type = EcdsaSighashType::All;
            let mut cache = SighashCache::new(&unsigned_tx);
            let sighash = cache
                .p2wpkh_signature_hash(i, sp, prev_txout.value, sighash_type)
                .map_err(|e| SubZeroError::Psbt(format!("BIP-143 sighash error: {e}")))?;
            let msg = Message::from_digest(sighash.to_byte_array());
            let sig = oracle.secp.sign_ecdsa(&msg, &child_xprv.0.private_key);
            let pubkey = child_xprv.0.private_key.public_key(&oracle.secp);
            psbt_in.partial_sigs.insert(
                pubkey.into(),
                bitcoin::ecdsa::Signature {
                    signature: sig,
                    sighash_type,
                },
            );
            signatures_added += 1;
        } else if sp.is_p2tr() {
            let tap_sighash_type = match psbt_in.sighash_type {
                Some(st) if st.to_u32() == TapSighashType::All as u32 => TapSighashType::All,
                _ => TapSighashType::Default,
            };
            let mut cache = SighashCache::new(&unsigned_tx);
            let sighash = cache
                .taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts_vec), tap_sighash_type)
                .map_err(|e| SubZeroError::Psbt(format!("BIP-341 Taproot sighash error: {e}")))?;
            let msg = Message::from_digest(sighash.to_byte_array());
            let mut keypair = Keypair::from_secret_key(&oracle.secp, &child_xprv.0.private_key);
            let mut tweaked = keypair.tap_tweak(&oracle.secp, None).to_keypair();
            // Deterministic BIP-340 Schnorr (`no_aux_rand` -> zero OS RNG!)
            let schnorr_sig = oracle.secp.sign_schnorr_no_aux_rand(&msg, &tweaked);
            keypair.non_secure_erase();
            tweaked.non_secure_erase();
            psbt_in.tap_key_sig = Some(bitcoin::taproot::Signature {
                signature: schnorr_sig,
                sighash_type: tap_sighash_type,
            });
            signatures_added += 1;
        }
    }

    if signatures_added == 0 {
        return Err(SubZeroError::Psbt(
            "Zero signatures were added (no signable P2WPKH or P2TR inputs matched the loaded wallet)."
                .into(),
        ));
    }

    let raw_signed = Psbt::serialize(&*psbt);
    let signed_psbt_base64 = BASE64_STANDARD.encode(&raw_signed);
    let signed_psbt_hex = hex::encode(&raw_signed);
    let bbqr_parts = crate::qr_codec::encode_bbqr_psbt(&raw_signed, 1)?;

    Ok(SignedPsbtArtifact {
        signatures_added,
        txid: inspection.txid.clone(),
        signed_psbt_base64,
        signed_psbt_hex,
        bbqr_parts,
        inspection,
    })
}

/// Deterministic boot-time Known-Answer Self-Test (`--self-test`) verifying:
/// 1. BIP-84 SegWit v0 (`P2WPKH`) ECDSA + BIP-86 Taproot (`P2TR`) Schnorr deterministic signing,
/// 2. SegWit v0 missing `non_witness_utxo` (`CVE-2020-14199`) and OOB `vout` fatal blocks, and
/// 3. Spoofed internal change (`bip32_derivation` mismatch) fatal block.
pub fn verify_psbt_self_test() -> Result<(), SubZeroError> {
    use crate::keys::load_rehearsal_preset;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, Txid, Witness};

    let p0 = load_rehearsal_preset(0)?;
    let mnemonic = p0
        .mnemonic
        .as_deref()
        .ok_or_else(|| SubZeroError::Psbt("Preset 0 missing mnemonic".into()))?;
    let oracle = VaultKeyOracle::from_mnemonic(mnemonic)?;

    let in0_addr = Address::from_str(&p0.receive_addresses[0])
        .map_err(|e| SubZeroError::Psbt(e.to_string()))?
        .require_network(Network::Testnet4)
        .map_err(|e| SubZeroError::Psbt(e.to_string()))?;
    let in1_tr_addr = Address::from_str(&p0.tr_receive_addresses[0])
        .map_err(|e| SubZeroError::Psbt(e.to_string()))?
        .require_network(Network::Testnet4)
        .map_err(|e| SubZeroError::Psbt(e.to_string()))?;
    let real_change_addr = Address::from_str(&p0.change_addresses[0])
        .map_err(|e| SubZeroError::Psbt(e.to_string()))?
        .require_network(Network::Testnet4)
        .map_err(|e| SubZeroError::Psbt(e.to_string()))?;

    let p1 = load_rehearsal_preset(1)?;
    let recip_addr = Address::from_str(&p1.receive_addresses[0])
        .map_err(|e| SubZeroError::Psbt(e.to_string()))?
        .require_network(Network::Testnet4)
        .map_err(|e| SubZeroError::Psbt(e.to_string()))?;

    let prev_tx_in0 = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([0x99; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: in0_addr.script_pubkey(),
        }],
    };
    let prev_txid_in0 = prev_tx_in0.compute_txid();

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint::new(prev_txid_in0, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(),
            },
            TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([0x22; 32]), 1),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(),
            },
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(60_000),
                script_pubkey: recip_addr.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(39_500),
                script_pubkey: real_change_addr.script_pubkey(),
            },
        ],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| SubZeroError::Psbt(e.to_string()))?;
    psbt.inputs[0].non_witness_utxo = Some(prev_tx_in0);
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: in0_addr.script_pubkey(),
    });
    psbt.inputs[1].witness_utxo = Some(TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: in1_tr_addr.script_pubkey(),
    });

    // 1. SegWit v0 without non_witness_utxo MUST be blocked
    let mut missing_nw = psbt.clone();
    missing_nw.inputs[0].non_witness_utxo = None;
    let insp_missing_nw = inspect_psbt(&missing_nw, Some(mnemonic), None)?;
    if insp_missing_nw.can_sign || sign_psbt(&mut missing_nw, mnemonic, None).is_ok() {
        return Err(SubZeroError::Psbt(
            "KAT failure: SegWit v0 missing non_witness_utxo was not blocked.".into(),
        ));
    }

    // 2. Out-of-range vout in non_witness_utxo MUST be blocked
    let mut oob_vout = psbt.clone();
    oob_vout.unsigned_tx.input[0].previous_output.vout = 5;
    let insp_oob = inspect_psbt(&oob_vout, Some(mnemonic), None)?;
    if insp_oob.can_sign || !insp_oob.fatal_blocks.iter().any(|b| b.contains("out of range")) {
        return Err(SubZeroError::Psbt(
            "KAT failure: Out-of-range vout in non_witness_utxo was not blocked.".into(),
        ));
    }

    // 3. Valid PSBT signs BOTH P2WPKH and P2TR deterministically
    let mut clean_psbt = psbt.clone();
    let signed = sign_psbt(&mut clean_psbt, mnemonic, None)?;
    if signed.signatures_added != 2
        || signed.inspection.fee_sat != Some(500)
        || signed.inspection.net_external_spend_sat != 60_500
        || clean_psbt.inputs[0].partial_sigs.len() != 1
        || clean_psbt.inputs[1].tap_key_sig.is_none()
    {
        return Err(SubZeroError::Psbt(
            "KAT failure: Valid P2WPKH + P2TR PSBT signing mismatch.".into(),
        ));
    }

    // 4. Spoofed internal change metadata MUST be blocked
    let mut spoofed_psbt = psbt.clone();
    let fake_chg_path =
        DerivationPath::from_str("m/84'/1'/0'/1/0").map_err(|e| SubZeroError::Psbt(e.to_string()))?;
    let derived = ZeroizingXpriv(
        oracle
            .master_xprv
            .derive_priv(&oracle.secp, &fake_chg_path)
            .map_err(|e| SubZeroError::Psbt(e.to_string()))?,
    );
    let mut map = BTreeMap::new();
    map.insert(
        derived.0.private_key.public_key(&oracle.secp),
        (oracle.master_fp, fake_chg_path.clone()),
    );
    spoofed_psbt.outputs[0].bip32_derivation = map;

    let spoof_insp = inspect_psbt(&spoofed_psbt, Some(mnemonic), None)?;
    if spoof_insp.can_sign
        || !spoof_insp
            .fatal_blocks
            .iter()
            .any(|b| b.contains("CHANGE-SPOOFING BLOCKED"))
        || sign_psbt(&mut spoofed_psbt, mnemonic, None).is_ok()
    {
        return Err(SubZeroError::Psbt(
            "KAT failure: Spoofed internal change output was not blocked.".into(),
        ));
    }

    // 5. Mixed valid + spoofed sibling `bip32_derivation` entries on the SAME output MUST still be blocked!
    let mut mixed_psbt = psbt;
    let real_chg_path =
        DerivationPath::from_str("m/84'/1'/0'/1/12").map_err(|e| SubZeroError::Psbt(e.to_string()))?;
    let real_derived = ZeroizingXpriv(
        oracle
            .master_xprv
            .derive_priv(&oracle.secp, &real_chg_path)
            .map_err(|e| SubZeroError::Psbt(e.to_string()))?,
    );
    mixed_psbt.outputs[1].bip32_derivation.insert(
        real_derived.0.private_key.public_key(&oracle.secp),
        (oracle.master_fp, real_chg_path),
    );
    mixed_psbt.outputs[1].bip32_derivation.insert(
        derived.0.private_key.public_key(&oracle.secp),
        (oracle.master_fp, fake_chg_path),
    );
    let mixed_insp = inspect_psbt(&mixed_psbt, Some(mnemonic), None)?;
    if mixed_insp.can_sign
        || !mixed_insp
            .fatal_blocks
            .iter()
            .any(|b| b.contains("CHANGE-SPOOFING BLOCKED"))
        || sign_psbt(&mut mixed_psbt, mnemonic, None).is_ok()
    {
        return Err(SubZeroError::Psbt(
            "KAT failure: Mixed valid+spoofed bip32_derivation was not blocked.".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psbt_p2wpkh_and_p2tr_signing_and_spoofed_change_block() {
        verify_psbt_self_test().expect("PSBT KAT must pass");
    }
}
