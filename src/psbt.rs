use bitcoin::psbt::Psbt;
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

pub struct CameraScanner {
    pub child: Option<Child>,
    pub receiver: Receiver<String>,
}

impl CameraScanner {
    pub fn spawn() -> Self {
        let (tx, rx) = mpsc::channel();
        let child = match Command::new("zbarcam")
            .args(["--raw", "--nodisplay", "/dev/video0"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(mut c) => {
                let stdout = c.stdout.take();
                thread::spawn(move || {
                    if let Some(out) = stdout {
                        let reader = BufReader::new(out);
                        for line in reader.lines() {
                            if let Ok(l) = line {
                                let trimmed = l.trim().to_string();
                                if !trimmed.is_empty() {
                                    let _ = tx.send(trimmed);
                                }
                            }
                        }
                    }
                });
                Some(c)
            }
            Err(e) => {
                let _ = tx.send(format!("ERROR: Failed to launch zbarcam on /dev/video0: {e}"));
                None
            }
        };

        Self {
            child,
            receiver: rx,
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
