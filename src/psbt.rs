use bitcoin::psbt::Psbt;
use bitcoin::Address;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use bip39::Mnemonic;
use zeroize::Zeroizing;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::io::{BufRead, BufReader};
use std::str::FromStr;

pub fn parse_psbt_bytes(raw: &[u8]) -> Result<Psbt, String> {
    // 1. Direct binary deserialization
    if let Ok(psbt) = Psbt::deserialize(raw) {
        return Ok(psbt);
    }

    // 2. Try as string (Base64 or Hex or JSON)
    if let Ok(text) = std::str::from_utf8(raw) {
        let trimmed = text.trim();
        // Base64
        if let Ok(bytes) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, trimmed) {
            if let Ok(psbt) = Psbt::deserialize(&bytes) {
                return Ok(psbt);
            }
        }
        // Hex
        if let Ok(bytes) = hex::decode(trimmed) {
            if let Ok(psbt) = Psbt::deserialize(&bytes) {
                return Ok(psbt);
            }
        }
    }

    Err("Failed to parse PSBT: invalid format (expected binary wire format, base64, or hex)".into())
}

pub fn parse_psbt(input: &str) -> Result<Psbt, String> {
    parse_psbt_bytes(input.trim().as_bytes())
}

#[derive(Debug, Clone)]
pub enum CameraEvent {
    QrData(String),
    Diagnostic(String),
    FatalError(String),
}

pub struct CameraScanner {
    pub child: Option<Child>,
    pub receiver: Receiver<CameraEvent>,
    pub device_path: String,
}

impl CameraScanner {
    pub fn spawn() -> Self {
        let (tx, rx) = mpsc::channel();

        // 1. Locate available video capture device (/dev/video0 through /dev/video9)
        let find_dev = || {
            (0..=9)
                .map(|i| format!("/dev/video{i}"))
                .find(|p| std::path::Path::new(p).exists())
        };

        let mut dev_opt = find_dev();

        // If no device exists, attempt to load uvcvideo driver and populate device nodes quietly
        if dev_opt.is_none() {
            let _ = Command::new("modprobe")
                .arg("uvcvideo")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = Command::new("mdev")
                .arg("-s")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            dev_opt = find_dev();
        }

        let device_path = match dev_opt {
            Some(p) => p,
            None => {
                let _ = tx.send(CameraEvent::FatalError(
                    "No video capture device found (/dev/video*). Camera hardware missing or disabled.".into(),
                ));
                return Self {
                    child: None,
                    receiver: rx,
                    device_path: "/dev/video0".into(),
                };
            }
        };

        let mut cmd = Command::new("zbarcam");
        cmd.args(["--raw", "--nodisplay", &device_path])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = match cmd.spawn() {
            Ok(mut c) => {
                let stdout = c.stdout.take();
                let stderr = c.stderr.take();
                let tx_out = tx.clone();

                if let Some(out) = stdout {
                    thread::spawn(move || {
                        let reader = BufReader::new(out);
                        for line in reader.lines() {
                            if let Ok(l) = line {
                                let trimmed = l.trim().to_string();
                                if !trimmed.is_empty() {
                                    let _ = tx_out.send(CameraEvent::QrData(trimmed));
                                }
                            }
                        }
                    });
                }

                if let Some(err) = stderr {
                    let tx_err = tx.clone();
                    thread::spawn(move || {
                        let reader = BufReader::new(err);
                        for line in reader.lines() {
                            if let Ok(l) = line {
                                let trimmed = l.trim().to_string();
                                if !trimmed.is_empty() {
                                    let _ = tx_err.send(CameraEvent::Diagnostic(trimmed));
                                }
                            }
                        }
                    });
                }

                Some(c)
            }
            Err(e) => {
                let _ = tx.send(CameraEvent::FatalError(format!(
                    "Failed to launch zbarcam on {device_path}: {e}"
                )));
                None
            }
        };

        Self {
            child,
            receiver: rx,
            device_path,
        }
    }

    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for CameraScanner {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Sign a PSBT using the active master mnemonic.
/// Performs standard BIP-84/BIP-32 key derivation for inputs with matching derivation paths.
pub fn sign_psbt(psbt: &mut Psbt, mnemonic_str: &str) -> Result<usize, String> {
    let mnemonic = Mnemonic::from_str(mnemonic_str).map_err(|e| format!("Mnemonic error: {e}"))?;
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    let secp = Secp256k1::new();
    let master_xprv = Xpriv::new_master(Network::Testnet4, seed.as_ref())
        .map_err(|e| format!("BIP-32 error: {e}"))?;
    let master_fp = master_xprv.fingerprint(&secp);

    let mut signatures_added = 0;

    for (i, input) in psbt.inputs.iter_mut().enumerate() {
        // Collect matching keys for this input
        let mut matching_keys = Vec::new();

        for (pubkey, (fingerprint, path)) in &input.bip32_derivation {
            if *fingerprint == master_fp {
                if let Ok(derived_xprv) = master_xprv.derive_priv(&secp, path) {
                    if derived_xprv.private_key.public_key(&secp) == *pubkey {
                        matching_keys.push(derived_xprv.private_key);
                    }
                }
            }
        }

        // If no explicit bip32_derivation match, try standard m/84'/1'/0'/0/k and m/84'/1'/0'/1/k
        if matching_keys.is_empty() {
            for change in 0..=1 {
                for idx in 0..100 {
                    let path_str = format!("m/84'/1'/0'/{change}/{idx}");
                    if let Ok(path) = DerivationPath::from_str(&path_str) {
                        if let Ok(derived_xprv) = master_xprv.derive_priv(&secp, &path) {
                            let pk = derived_xprv.private_key.public_key(&secp);
                            // Check if this input matches the pubkey hash (P2WPKH)
                            if let Some(witness_utxo) = &input.witness_utxo {
                                let addr = bitcoin::Address::p2wpkh(&bitcoin::CompressedPublicKey(pk), bitcoin::KnownHrp::Testnets);
                                if witness_utxo.script_pubkey == addr.script_pubkey() {
                                    matching_keys.push(derived_xprv.private_key);
                                    break;
                                }
                            }
                        }
                    }
                }
                if !matching_keys.is_empty() {
                    break;
                }
            }
        }

        // Sign using matching private keys
        for privkey in matching_keys {
            let secp_priv = privkey;
            let pubkey = privkey.public_key(&secp);

            // Calculate sighash for SegWit v0 (P2WPKH)
            if let Some(witness_utxo) = &input.witness_utxo {
                let sighash_type = bitcoin::sighash::EcdsaSighashType::All;
                let mut sighash_cache = bitcoin::sighash::SighashCache::new(&psbt.unsigned_tx);
                if let Ok(hash) = sighash_cache.p2wpkh_signature_hash(
                    i,
                    &witness_utxo.script_pubkey,
                    witness_utxo.value,
                    sighash_type,
                ) {
                    let msg = bitcoin::secp256k1::Message::from_digest_slice(hash.as_ref())
                        .map_err(|e| format!("Message error: {e}"))?;
                    let sig = secp.sign_ecdsa(&msg, &secp_priv);
                    let final_sig = bitcoin::ecdsa::Signature {
                        signature: sig,
                        sighash_type,
                    };
                    input.partial_sigs.insert(pubkey.into(), final_sig);
                    signatures_added += 1;
                }
            }
        }
    }

    Ok(signatures_added)
}

pub fn serialize_psbt_base64(psbt: &Psbt) -> String {
    let bytes = psbt.serialize();
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PsbtOutputDetail {
    pub index: usize,
    pub address: String,
    pub script_type: String,
    pub amount_sat: u64,
    pub is_change: bool,
    pub is_self_receive: bool,
    pub derivation_index: Option<u32>,
    pub bip32_path: Option<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PsbtInputDetail {
    pub index: usize,
    pub outpoint: String,
    pub amount_sat: Option<u64>,
    pub address: Option<String>,
    pub script_type: String,
    pub is_ours: bool,
    pub derivation_path: Option<String>,
    pub sighash_type: String,
    pub sequence: u32,
    pub rbf_enabled: bool,
    pub is_p2wpkh: bool,
}

#[derive(Debug, Clone)]
pub struct PsbtInspection {
    pub inputs: Vec<PsbtInputDetail>,
    pub outputs: Vec<PsbtOutputDetail>,
    pub total_input_sat: Option<u64>,
    pub total_output_sat: u64,
    pub fee_sat: Option<u64>,
    pub fee_rate_sat_vb: Option<f64>,
    pub fee_pct: Option<f64>,
    pub locktime: u32,
    pub is_rbf_active: bool,
    pub unknown_global_count: usize,
    pub unknown_input_count: usize,
    pub unknown_output_count: usize,
    pub proprietary_field_count: usize,
    pub warnings: Vec<String>,
    pub fatal_blocks: Vec<String>,
}

pub fn classify_script(script: &bitcoin::ScriptBuf) -> String {
    if script.is_p2wpkh() {
        "P2WPKH (Native SegWit)".to_string()
    } else if script.is_p2tr() {
        "P2TR (Taproot)".to_string()
    } else if script.is_p2wsh() {
        "P2WSH (SegWit Script/Multisig)".to_string()
    } else if script.is_p2sh() {
        "P2SH (Nested SegWit/Legacy Script)".to_string()
    } else if script.is_p2pkh() {
        "P2PKH (Legacy)".to_string()
    } else if script.is_op_return() {
        "OP_RETURN (Data Carrier)".to_string()
    } else {
        "Unknown Script".to_string()
    }
}

pub fn format_address_chunked(addr: &str) -> String {
    let mut out = String::new();
    for (i, ch) in addr.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push(' ');
        }
        out.push(ch);
    }
    out
}

pub fn inspect_psbt(psbt: &Psbt, mnemonic_opt: Option<&str>) -> PsbtInspection {
    let mut warnings = Vec::new();
    let mut fatal_blocks = Vec::new();

    let mut our_fingerprint = None;
    let mut our_receive_addrs = std::collections::HashMap::new();
    let mut our_change_addrs = std::collections::HashMap::new();

    if let Some(m_str) = mnemonic_opt {
        if let Ok(m) = Mnemonic::from_str(m_str) {
            let seed = Zeroizing::new(m.to_seed(""));
            let secp = Secp256k1::new();
            if let Ok(master_xprv) = Xpriv::new_master(Network::Testnet4, seed.as_ref()) {
                let fp = master_xprv.fingerprint(&secp);
                our_fingerprint = Some(fp);

                // Precompute 0..50 receive and change addresses
                for idx in 0..50 {
                    let recv_path_str = format!("m/84'/1'/0'/0/{idx}");
                    if let Ok(path) = DerivationPath::from_str(&recv_path_str) {
                        if let Ok(child) = master_xprv.derive_priv(&secp, &path) {
                            let pk = child.private_key.public_key(&secp);
                            let addr = bitcoin::Address::p2wpkh(&bitcoin::CompressedPublicKey(pk), bitcoin::KnownHrp::Testnets);
                            our_receive_addrs.insert(addr.script_pubkey(), idx);
                        }
                    }

                    let chg_path_str = format!("m/84'/1'/0'/1/{idx}");
                    if let Ok(path) = DerivationPath::from_str(&chg_path_str) {
                        if let Ok(child) = master_xprv.derive_priv(&secp, &path) {
                            let pk = child.private_key.public_key(&secp);
                            let addr = bitcoin::Address::p2wpkh(&bitcoin::CompressedPublicKey(pk), bitcoin::KnownHrp::Testnets);
                            our_change_addrs.insert(addr.script_pubkey(), idx);
                        }
                    }
                }
            }
        }
    }

    // 1. Audit Inputs
    let mut input_details = Vec::new();
    let mut total_in_sat = 0u64;
    let mut all_inputs_known = true;

    for (i, input) in psbt.inputs.iter().enumerate() {
        let txin = &psbt.unsigned_tx.input[i];
        let outpoint = format!("{}:{}", txin.previous_output.txid, txin.previous_output.vout);
        let sequence = txin.sequence.0;
        let rbf_enabled = sequence < 0xffff_fffe;

        // Check bip32_derivation for Mainnet coin type
        for (_pk, (fp, path)) in &input.bip32_derivation {
            let path_str = path.to_string();
            if path_str.contains("/0'/") {
                fatal_blocks.push(format!(
                    "[CRITICAL FOOTGUN] MAINNET COIN TYPE (m/.../0'/...) DETECTED ON INPUT #{i}! Path: {path_str} (Fingerprint: {fp}). Signing is blocked on Testnet4 appliance."
                ));
            }
        }

        // Sighash check
        let (sighash_str, is_standard_sighash) = match input.sighash_type {
            Some(st) => {
                let s = format!("{:?}", st);
                let standard = st.to_u32() == bitcoin::sighash::EcdsaSighashType::All as u32;
                (s, standard)
            }
            None => ("SIGHASH_ALL (Default)".to_string(), true),
        };
        if !is_standard_sighash {
            warnings.push(format!(
                "[DANGER: SIGHASH] Input #{i} uses non-standard {sighash_str}! Transaction can be altered after signing."
            ));
        }

        // Value & script
        let (amount_sat, script_opt) = if let Some(ref utxo) = input.witness_utxo {
            (Some(utxo.value.to_sat()), Some(&utxo.script_pubkey))
        } else if let Some(ref non_wit) = input.non_witness_utxo {
            let vout = txin.previous_output.vout as usize;
            if let Some(txout) = non_wit.output.get(vout) {
                (Some(txout.value.to_sat()), Some(&txout.script_pubkey))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        if let Some(amt) = amount_sat {
            total_in_sat = total_in_sat.saturating_add(amt);
        } else {
            all_inputs_known = false;
            warnings.push(format!(
                "[BLIND SIGNING RISK] Input #{i} lacks UTXO amount! Total fee cannot be verified."
            ));
        }

        let (address, script_type, is_p2wpkh) = if let Some(script) = script_opt {
            let st = classify_script(script);
            let p2wpkh = script.is_p2wpkh();
            if !p2wpkh {
                warnings.push(format!(
                    "[UNSUPPORTED SCRIPT TYPE] Input #{i} is {st}. SubZero single-sig only signs BIP-84 P2WPKH."
                ));
            }
            let addr = Address::from_script(script, Network::Testnet4).ok().map(|a| a.to_string());
            (addr, st, p2wpkh)
        } else {
            (None, "Missing UTXO Script".to_string(), false)
        };

        // Check ownership
        let mut is_ours = false;
        let mut deriv_path = None;

        if let Some(our_fp) = our_fingerprint {
            for (_pk, (fp, path)) in &input.bip32_derivation {
                if *fp == our_fp {
                    is_ours = true;
                    deriv_path = Some(path.to_string());
                    break;
                }
            }
        }

        if !is_ours {
            if let Some(script) = script_opt {
                if let Some(idx) = our_receive_addrs.get(script) {
                    is_ours = true;
                    deriv_path = Some(format!("m/84'/1'/0'/0/{idx}"));
                } else if let Some(idx) = our_change_addrs.get(script) {
                    is_ours = true;
                    deriv_path = Some(format!("m/84'/1'/0'/1/{idx}"));
                }
            }
        }

        input_details.push(PsbtInputDetail {
            index: i,
            outpoint,
            amount_sat,
            address,
            script_type,
            is_ours,
            derivation_path: deriv_path,
            sighash_type: sighash_str,
            sequence,
            rbf_enabled,
            is_p2wpkh,
        });
    }

    // 2. Audit Outputs
    let mut output_details = Vec::new();
    let mut total_out_sat = 0u64;
    let mut has_internal_change = false;

    for (j, out) in psbt.unsigned_tx.output.iter().enumerate() {
        let amt = out.value.to_sat();
        total_out_sat = total_out_sat.saturating_add(amt);
        let script = &out.script_pubkey;
        let script_type = classify_script(script);

        // Check bip32_derivation for Mainnet coin type
        if let Some(out_psbt) = psbt.outputs.get(j) {
            for (_pk, (fp, path)) in &out_psbt.bip32_derivation {
                let path_str = path.to_string();
                if path_str.contains("/0'/") {
                    fatal_blocks.push(format!(
                        "[CRITICAL FOOTGUN] MAINNET COIN TYPE (m/.../0'/...) ON OUTPUT #{j}! Path: {path_str} (Fingerprint: {fp}). Signing blocked."
                    ));
                }
            }
        }

        let address = Address::from_script(script, Network::Testnet4)
            .ok()
            .map(|a| a.to_string())
            .unwrap_or_else(|| script.to_string());

        // Check if address starts with mainnet markers bc1, 1, 3 (extra check)
        if address.starts_with("bc1") || address.starts_with('1') || address.starts_with('3') {
            fatal_blocks.push(format!(
                "[CRITICAL FOOTGUN] MAINNET ADDRESS DETECTED ON OUTPUT #{j} ({address})! SubZero is running in Testnet4 mode."
            ));
        }

        let mut is_change = false;
        let mut is_self_receive = false;
        let mut deriv_idx = None;
        let mut bip32_path = None;

        // Check against our change cache
        if let Some(idx) = our_change_addrs.get(script) {
            is_change = true;
            has_internal_change = true;
            deriv_idx = Some(*idx);
            bip32_path = Some(format!("m/84'/1'/0'/1/{idx}"));
            if *idx >= 20 {
                warnings.push(format!(
                    "[GAP LIMIT NOTICE] Change Output #{j} uses index #{idx}, which exceeds standard 20-address gap limit."
                ));
            }
        } else if let Some(idx) = our_receive_addrs.get(script) {
            is_self_receive = true;
            deriv_idx = Some(*idx);
            bip32_path = Some(format!("m/84'/1'/0'/0/{idx}"));
            if *idx >= 20 {
                warnings.push(format!(
                    "[GAP LIMIT NOTICE] Self-receive Output #{j} uses index #{idx}, which exceeds standard 20-address gap limit."
                ));
            }
        } else if let Some(out_psbt) = psbt.outputs.get(j) {
            // Check bip32_derivation
            if let Some(our_fp) = our_fingerprint {
                for (_pk, (fp, path)) in &out_psbt.bip32_derivation {
                    if *fp == our_fp {
                        let p_str = path.to_string();
                        if p_str.contains("/1/") {
                            is_change = true;
                            has_internal_change = true;
                            bip32_path = Some(p_str);
                        } else if p_str.contains("/0/") {
                            is_self_receive = true;
                            bip32_path = Some(p_str);
                        }
                        break;
                    }
                }
            }
        }

        output_details.push(PsbtOutputDetail {
            index: j,
            address,
            script_type,
            amount_sat: amt,
            is_change,
            is_self_receive,
            derivation_index: deriv_idx,
            bip32_path,
        });
    }

    if !has_internal_change && !output_details.is_empty() {
        if output_details.len() == 1 {
            warnings.push(
                "[100% SWEEP WARNING] No internal change output detected. Entire input balance (minus fee) is transferred to external recipient.".into()
            );
        } else {
            warnings.push(
                "[ALL EXTERNAL RECIPIENTS] No internal change output detected. All outputs are going to external addresses.".into()
            );
        }
    }

    // 3. Fee, Fee Rate, Locktime, Unknown Fields
    let total_input_sat = if all_inputs_known { Some(total_in_sat) } else { None };
    let fee_sat = total_input_sat.map(|tin| tin.saturating_sub(total_out_sat));
    let fee_pct = match (fee_sat, total_input_sat) {
        (Some(fee), Some(tin)) if tin > 0 => Some((fee as f64 / tin as f64) * 100.0),
        _ => None,
    };
    let vsize = psbt.unsigned_tx.vsize();
    let fee_rate_sat_vb = fee_sat.map(|fee| (fee as f64) / (vsize as f64));

    if let Some(pct) = fee_pct {
        if pct > 20.0 {
            warnings.push(format!(
                "[CRITICAL HIGH FEE] Network fee represents {pct:.1}% of total input value! Verify miner fee before signing."
            ));
        } else if pct > 5.0 {
            warnings.push(format!(
                "[HIGH FEE WARNING] Network fee is {pct:.1}% of total input value."
            ));
        }
    }

    if let Some(rate) = fee_rate_sat_vb {
        if rate > 100.0 {
            warnings.push(format!(
                "[HIGH FEE RATE] Fee rate is {rate:.1} sat/vB (significantly above typical mempool rates)."
            ));
        } else if rate < 1.0 {
            warnings.push(format!(
                "[LOW FEE RATE] Fee rate is {rate:.1} sat/vB (risk of mempool eviction)."
            ));
        }
    }

    let locktime = psbt.unsigned_tx.lock_time.to_consensus_u32();
    if locktime > 0 && locktime >= 500_000_000 {
        warnings.push(format!(
            "[TIME-LOCK NOTICE] Transaction locktime is timestamp {locktime} (Unix epoch). Cannot be mined before this time."
        ));
    }

    let is_rbf_active = psbt.unsigned_tx.input.iter().any(|i| i.sequence.0 < 0xffff_fffe);

    let unknown_global = psbt.unknown.len();
    let unknown_input = psbt.inputs.iter().map(|i| i.unknown.len()).sum();
    let unknown_output = psbt.outputs.iter().map(|o| o.unknown.len()).sum();
    let proprietary_count = psbt.proprietary.len()
        + psbt.inputs.iter().map(|i| i.proprietary.len()).sum::<usize>()
        + psbt.outputs.iter().map(|o| o.proprietary.len()).sum::<usize>();

    if unknown_global + unknown_input + unknown_output + proprietary_count > 0 {
        warnings.push(format!(
            "[PROPRIETARY PSBT FIELDS] Detected {} unknown / proprietary metadata field(s) in PSBT.",
            unknown_global + unknown_input + unknown_output + proprietary_count
        ));
    }

    PsbtInspection {
        inputs: input_details,
        outputs: output_details,
        total_input_sat,
        total_output_sat: total_out_sat,
        fee_sat,
        fee_rate_sat_vb,
        fee_pct,
        locktime,
        is_rbf_active,
        unknown_global_count: unknown_global,
        unknown_input_count: unknown_input,
        unknown_output_count: unknown_output,
        proprietary_field_count: proprietary_count,
        warnings,
        fatal_blocks,
    }
}
