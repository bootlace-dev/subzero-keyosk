//! Zero-Import WebAssembly Bridge (`subzero-wasm`).
//!
//! WHY RAW C-ABI + WASM-RESIDENT VAULT ISOLATION:
//! 1. Zero Host Imports: Eliminates npm / `wasm-bindgen-cli` version skew so
//!    `cargo build --target wasm32-unknown-unknown` emits a standalone `.wasm` module with
//!    ZERO imports (`WebAssembly.Module.imports(m) == []`).
//! 2. Privilege Separation Against JS Garbage Collection (`[H-01]` Fix):
//!    JavaScript strings are immutable and managed by a non-deterministic browser GC. Therefore
//!    `ACTIVE_VAULT` and `UNLOCKED_VAULT` keep master mnemonics and BIP-85 child mnemonics inside
//!    zeroizable Rust linear memory (`ZeroizeOnDrop`) rather than eagerly serializing them across
//!    JSON RPC responses. Signing (`sign_psbt`, `pipek1_sign`, `encrypt_vault`) reads keys directly
//!    inside WASM without round-tripping mnemonics through JS strings, and secrets cross to the DOM
//!    strictly when the operator clicks an explicit Reveal action.
//! 3. Sound Exact-Sized `Box<[u8]>` Allocation (`[M-04]` Fix):
//!    Uses `Vec::into_boxed_slice` + `Box::from_raw` (guaranteed exact `len` layout) with volatile
//!    zeroization in `sz_dealloc` before returning blocks to the WASM allocator.

use std::collections::BTreeSet;
use std::sync::Mutex;

use base64::prelude::*;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use subzero_core::entropy::{
    evaluate_keystroke_health, generate_obstacle_prompt, harvest_coins, harvest_dice,
    harvest_freeform_entropy, harvest_keystroke_course, harvest_raw_hex, KeystrokeSample,
};
use subzero_core::keys::{
    derive_bip85_children, export_sparrow_watch_only_json, import_wallet_material,
    load_rehearsal_preset, mnemonic_to_compact_seed_qr, wallet_from_conditioned_entropy,
    Bip85Child, Bip85ChildPublic, WalletProfile,
};
use subzero_core::pipek1::{
    derive_pipek1_public, export_pipek1_nsec, sign_pipek1_detached, verify_pipek1_detached,
    PipeK1IdentityPublic,
};
use subzero_core::presets::list_presets;
use subzero_core::psbt::{inspect_psbt, parse_psbt_any, sign_psbt};
use subzero_core::qr_codec::{
    decode_qr_luma, encode_bbqr_unicode, encode_qr_svg, AirgapQrAssembler, ScannedAirgapPayload,
};
use subzero_core::seedfix::{search_bip39_wordlist, solve_twelfth_word};
use subzero_core::vault::{decrypt_vault_json, encrypt_vault_payload, DecryptedVaultPayload};

#[derive(Zeroize, ZeroizeOnDrop)]
struct ActiveVaultState {
    mnemonic: String,
    compact_seed_qr: String,
    bip85_children: Vec<Bip85Child>,
}

static QR_ASSEMBLER: Mutex<Option<AirgapQrAssembler>> = Mutex::new(None);
static ACTIVE_VAULT: Mutex<Option<ActiveVaultState>> = Mutex::new(None);
static MASTER_MNEMONIC_BACKUP: Mutex<Option<Zeroizing<String>>> = Mutex::new(None);
static UNLOCKED_VAULT: Mutex<Option<DecryptedVaultPayload>> = Mutex::new(None);

#[derive(Serialize)]
struct RpcResponse<T: Serialize> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct EnrichedWalletView {
    profile: WalletProfile,
    has_signing_seed: bool,
    has_master_backup: bool,
    sparrow_watch_only_json: String,
    wpkh_qr_svg: String,
    vpub_qr_svg: String,
    bbqr_descriptor_parts: Vec<String>,
    bbqr_descriptor_svgs: Vec<String>,
    bip85_public: Vec<Bip85ChildPublic>,
    pipek1_default: Option<PipeK1IdentityPublic>,
}

fn enrich_and_install_wallet_inner(
    mut profile: WalletProfile,
    preserve_master_backup: bool,
) -> Result<EnrichedWalletView, String> {
    if !preserve_master_backup {
        if let Ok(mut b_guard) = MASTER_MNEMONIC_BACKUP.lock() {
            *b_guard = None;
        }
    }
    let has_master_backup = MASTER_MNEMONIC_BACKUP
        .lock()
        .map(|g| g.is_some())
        .unwrap_or(false);

    let sparrow_watch_only_json =
        export_sparrow_watch_only_json(&profile).map_err(|e| e.to_string())?;
    let wpkh_qr_svg = encode_qr_svg(&profile.wpkh_descriptor).map_err(|e| e.to_string())?;
    let vpub_target = if !profile.bip84_vpub_slip132.is_empty() {
        &profile.bip84_vpub_slip132
    } else {
        &profile.wpkh_descriptor
    };
    let vpub_qr_svg = encode_qr_svg(vpub_target).map_err(|e| e.to_string())?;
    let bbqr_descriptor_parts =
        encode_bbqr_unicode(&profile.wpkh_descriptor, 2).map_err(|e| e.to_string())?;
    let mut bbqr_descriptor_svgs = Vec::with_capacity(bbqr_descriptor_parts.len());
    for p in &bbqr_descriptor_parts {
        bbqr_descriptor_svgs.push(encode_qr_svg(p).map_err(|e| e.to_string())?);
    }

    let (has_signing_seed, bip85_public, pipek1_default) =
        if let Some(mut m) = profile.mnemonic.take() {
            let csq = mnemonic_to_compact_seed_qr(&m).unwrap_or_default();
            let children = derive_bip85_children(&m, 4).map_err(|e| {
                m.zeroize();
                e.to_string()
            })?;
            let mut pub_views = Vec::with_capacity(children.len());
            for c in &children {
                pub_views.push(c.derive_public_summary().map_err(|e| e.to_string())?);
            }
            let pk1 = derive_pipek1_public(&m, 0, 0).ok();
            if let Ok(mut guard) = ACTIVE_VAULT.lock() {
                *guard = Some(ActiveVaultState {
                    mnemonic: m,
                    compact_seed_qr: csq,
                    bip85_children: children,
                });
            }
            (true, pub_views, pk1)
        } else {
            if let Ok(mut guard) = ACTIVE_VAULT.lock() {
                *guard = None;
            }
            (false, Vec::new(), None)
        };

    Ok(EnrichedWalletView {
        profile,
        has_signing_seed,
        has_master_backup,
        sparrow_watch_only_json,
        wpkh_qr_svg,
        vpub_qr_svg,
        bbqr_descriptor_parts,
        bbqr_descriptor_svgs,
        bip85_public,
        pipek1_default,
    })
}

fn enrich_and_install_wallet(profile: WalletProfile) -> Result<EnrichedWalletView, String> {
    enrich_and_install_wallet_inner(profile, false)
}

fn with_active_mnemonic<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce(&ActiveVaultState) -> Result<R, String>,
{
    let guard = ACTIVE_VAULT
        .lock()
        .map_err(|_| "Active vault mutex poisoned.".to_string())?;
    let state = guard
        .as_ref()
        .ok_or_else(|| "Load a 12-word signing seed first.".to_string())?;
    f(state)
}

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum RpcRequest {
    ListPresets,
    LoadPreset {
        id: u8,
    },
    GenerateObstaclePrompt {
        round: u32,
        #[serde(default)]
        length: Option<usize>,
    },
    EvaluateKeystrokeHealth {
        samples: Vec<KeystrokeSample>,
    },
    HarvestKeystrokeCourse {
        expected_prompt: String,
        final_transcribed: String,
        samples: Vec<KeystrokeSample>,
    },
    HarvestFreeform {
        samples: Vec<KeystrokeSample>,
        pointer_deltas: Vec<(i32, i32, u64)>,
    },
    HarvestTier1 {
        kind: String,
        input: String,
    },
    ImportWallet {
        input: String,
    },
    RevealMasterSecret,
    DeriveBip85 {
        count: u32,
        #[serde(default)]
        reveal_secrets: bool,
    },
    PivotBip85Child {
        index: u32,
    },
    ReturnMasterRoot,
    GetEstatePassphrase,
    EncodeQr {
        data: String,
        #[serde(default)]
        bbqr_min_parts: Option<usize>,
    },
    ResetAirgapScanner,
    IngestAirgapQr {
        part: String,
    },
    InspectPsbt {
        psbt_input: String,
        #[serde(default)]
        session_recipients: Vec<String>,
    },
    SignPsbt {
        psbt_input: String,
        #[serde(default)]
        session_recipients: Vec<String>,
    },
    Pipek1Derive {
        identity: u32,
        index: u32,
        #[serde(default)]
        reveal_nsec: bool,
    },
    Pipek1Sign {
        identity: u32,
        index: u32,
        #[serde(default)]
        message_utf8: Option<String>,
        #[serde(default)]
        message_base64: Option<String>,
        timestamp: u32,
    },
    Pipek1Verify {
        #[serde(default)]
        message_utf8: Option<String>,
        #[serde(default)]
        message_base64: Option<String>,
        signature: String,
        #[serde(default)]
        expected_pubkey: Option<String>,
    },
    EncryptVault {
        created_utc: String,
        descriptor: String,
        passphrase: String,
    },
    DecryptVault {
        vault_json: String,
        passphrase: String,
    },
    RevealUnlockedVault,
    ActivateUnlockedVault,
    SeedfixSolve {
        eleven_words: String,
        #[serde(default)]
        typo_hint: Option<String>,
    },
    WordlistSearch {
        query: String,
        #[serde(default)]
        limit: Option<usize>,
    },
}

fn ok_json<T: Serialize>(val: T) -> String {
    serde_json::to_string(&RpcResponse {
        ok: true,
        data: Some(val),
        error: None,
    })
    .unwrap_or_else(|e| format!(r#"{{"ok":false,"error":"Serialization error: {e}"}}"#))
}

fn err_json(msg: impl Into<String>) -> String {
    serde_json::to_string(&RpcResponse::<()> {
        ok: false,
        data: None,
        error: Some(msg.into()),
    })
    .unwrap_or_else(|_| r#"{"ok":false,"error":"Internal error"}"#.to_string())
}

pub fn dispatch_rpc_json(raw_json: &str) -> String {
    let req: RpcRequest = match serde_json::from_str(raw_json) {
        Ok(r) => r,
        Err(e) => return err_json(format!("Invalid RPC request JSON: {e}")),
    };

    match req {
        RpcRequest::ListPresets => ok_json(list_presets()),
        RpcRequest::LoadPreset { id } => {
            match load_rehearsal_preset(id)
                .map_err(|e| e.to_string())
                .and_then(enrich_and_install_wallet)
            {
                Ok(v) => ok_json(v),
                Err(e) => err_json(e),
            }
        }
        RpcRequest::GenerateObstaclePrompt { round, length } => {
            let len = length
                .unwrap_or(subzero_core::entropy::OBSTACLE_COURSE_LEN)
                .clamp(32, 4096);
            ok_json(serde_json::json!({
                "prompt": generate_obstacle_prompt(round, len),
                "required_min_entropy_bits": subzero_core::entropy::MIN_TIER2_ENTROPY_BITS,
            }))
        }
        RpcRequest::EvaluateKeystrokeHealth { mut samples } => {
            let res = match evaluate_keystroke_health(&samples) {
                Ok(rep) => ok_json(rep),
                Err(e) => err_json(e.to_string()),
            };
            samples.zeroize();
            res
        }
        RpcRequest::HarvestKeystrokeCourse {
            expected_prompt,
            mut final_transcribed,
            mut samples,
        } => {
            let res = match harvest_keystroke_course(&expected_prompt, &final_transcribed, &samples)
                .and_then(|ent| wallet_from_conditioned_entropy(&ent))
                .map_err(|e| e.to_string())
                .and_then(enrich_and_install_wallet)
            {
                Ok(v) => ok_json(v),
                Err(e) => err_json(e),
            };
            final_transcribed.zeroize();
            samples.zeroize();
            res
        }
        RpcRequest::HarvestFreeform {
            mut samples,
            mut pointer_deltas,
        } => {
            let res = match harvest_freeform_entropy(&samples, &pointer_deltas)
                .and_then(|ent| wallet_from_conditioned_entropy(&ent))
                .map_err(|e| e.to_string())
                .and_then(enrich_and_install_wallet)
            {
                Ok(v) => ok_json(v),
                Err(e) => err_json(e),
            };
            samples.zeroize();
            pointer_deltas.zeroize();
            res
        }
        RpcRequest::HarvestTier1 { kind, mut input } => {
            let ent_res = match kind.as_str() {
                "coins" => harvest_coins(&input),
                "dice" => harvest_dice(&input),
                "hex" => harvest_raw_hex(&input),
                other => Err(subzero_core::error::SubZeroError::Entropy(format!(
                    "Unknown Tier 1 entropy mode '{other}'."
                ))),
            };
            input.zeroize();
            match ent_res
                .and_then(|ent| wallet_from_conditioned_entropy(&ent))
                .map_err(|e| e.to_string())
                .and_then(enrich_and_install_wallet)
            {
                Ok(v) => ok_json(v),
                Err(e) => err_json(e),
            }
        }
        RpcRequest::ImportWallet { mut input } => {
            let res = match import_wallet_material(&input)
                .map_err(|e| e.to_string())
                .and_then(enrich_and_install_wallet)
            {
                Ok(v) => ok_json(v),
                Err(e) => err_json(e),
            };
            input.zeroize();
            res
        }
        RpcRequest::RevealMasterSecret => match with_active_mnemonic(|st| {
            Ok(serde_json::json!({
                "mnemonic": st.mnemonic,
                "compact_seed_qr": st.compact_seed_qr,
            }))
        }) {
            Ok(v) => ok_json(v),
            Err(e) => err_json(e),
        },
        RpcRequest::DeriveBip85 {
            count,
            reveal_secrets,
        } => {
            let capped = count.clamp(1, 20);
            let mut guard = match ACTIVE_VAULT.lock() {
                Ok(g) => g,
                Err(_) => return err_json("Active vault mutex poisoned."),
            };
            let Some(ref mut st) = *guard else {
                return err_json("Load a 12-word signing seed first.");
            };
            match derive_bip85_children(&st.mnemonic, capped) {
                Ok(children) => {
                    let mut pub_views = Vec::with_capacity(children.len());
                    for c in &children {
                        if let Ok(pv) = c.derive_public_summary() {
                            pub_views.push(pv);
                        }
                    }
                    st.bip85_children = children;
                    let secret_out = if reveal_secrets {
                        Some(&st.bip85_children)
                    } else {
                        None
                    };
                    ok_json(serde_json::json!({
                        "children": secret_out,
                        "public_summaries": pub_views,
                    }))
                }
                Err(e) => err_json(e.to_string()),
            }
        }
        RpcRequest::PivotBip85Child { index } => {
            if index == 0 {
                return err_json(
                    "Index 0 is the Decoupled Estate Encryption Passphrase - never fund on-chain! Select Index 1..4.",
                );
            }
            if index > 20 {
                return err_json("BIP-85 child index out of range (1..=20).");
            }
            let pivot_res: Result<Zeroizing<String>, String> = {
                let b_guard = MASTER_MNEMONIC_BACKUP
                    .lock()
                    .map_err(|_| "Master backup mutex poisoned.".to_string());
                let a_guard = ACTIVE_VAULT
                    .lock()
                    .map_err(|_| "Active vault mutex poisoned.".to_string());
                match (b_guard, a_guard) {
                    (Ok(mut bg), Ok(ag)) => {
                        let root_mnem = if let Some(ref saved_root) = *bg {
                            saved_root.as_str().to_string()
                        } else if let Some(ref st) = *ag {
                            let s = st.mnemonic.clone();
                            *bg = Some(Zeroizing::new(s.clone()));
                            s
                        } else {
                            return err_json("Load a 12-word signing seed first.");
                        };
                        let root_z = Zeroizing::new(root_mnem);
                        derive_bip85_children(&root_z, index + 1)
                            .map_err(|e| e.to_string())
                            .and_then(|list| {
                                list.into_iter()
                                    .find(|c| c.index == index)
                                    .map(|c| Zeroizing::new(c.mnemonic.clone()))
                                    .ok_or_else(|| "Requested BIP-85 child missing.".to_string())
                            })
                    }
                    _ => Err("Vault mutex poisoned.".to_string()),
                }
            };
            match pivot_res
                .and_then(|cm| import_wallet_material(&cm).map_err(|e| e.to_string()))
                .and_then(|prof| enrich_and_install_wallet_inner(prof, true))
            {
                Ok(wv) => ok_json(wv),
                Err(e) => err_json(e),
            }
        }
        RpcRequest::ReturnMasterRoot => {
            let root_opt = match MASTER_MNEMONIC_BACKUP.lock() {
                Ok(mut bg) => bg.take(),
                Err(_) => return err_json("Master backup mutex poisoned."),
            };
            let Some(root_m) = root_opt else {
                return err_json("Already at top-level wallet (no Master Root backup stored).");
            };
            match import_wallet_material(&root_m)
                .map_err(|e| e.to_string())
                .and_then(|prof| enrich_and_install_wallet_inner(prof, false))
            {
                Ok(wv) => ok_json(wv),
                Err(e) => err_json(e),
            }
        }
        RpcRequest::GetEstatePassphrase => match with_active_mnemonic(|st| {
            let first = st
                .bip85_children
                .first()
                .ok_or_else(|| "BIP-85 Index 0 passphrase unavailable.".to_string())?;
            Ok(serde_json::json!({ "passphrase": first.mnemonic }))
        }) {
            Ok(v) => ok_json(v),
            Err(e) => err_json(e),
        },
        RpcRequest::EncodeQr {
            data,
            bbqr_min_parts,
        } => {
            let res = (|| -> Result<serde_json::Value, String> {
                let single_svg = encode_qr_svg(&data).map_err(|e| e.to_string())?;
                let min_p = bbqr_min_parts.unwrap_or(1).max(1);
                let parts = encode_bbqr_unicode(&data, min_p).map_err(|e| e.to_string())?;
                let mut part_svgs = Vec::with_capacity(parts.len());
                for p in &parts {
                    part_svgs.push(encode_qr_svg(p).map_err(|e| e.to_string())?);
                }
                Ok(serde_json::json!({
                    "single_svg": single_svg,
                    "bbqr_parts": parts,
                    "bbqr_svgs": part_svgs,
                }))
            })();
            match res {
                Ok(v) => ok_json(v),
                Err(e) => err_json(e),
            }
        }
        RpcRequest::ResetAirgapScanner => {
            if let Ok(mut guard) = QR_ASSEMBLER.lock() {
                *guard = Some(AirgapQrAssembler::new());
            }
            ok_json(serde_json::json!({"reset": true}))
        }
        RpcRequest::IngestAirgapQr { part } => {
            let mut guard = match QR_ASSEMBLER.lock() {
                Ok(g) => g,
                Err(_) => return err_json("Scanner mutex poisoned."),
            };
            let asm = guard.get_or_insert_with(AirgapQrAssembler::new);
            match asm.ingest_qr_string(&part) {
                Ok(ScannedAirgapPayload::InProgress {
                    parts_received,
                    parts_total,
                }) => ok_json(serde_json::json!({
                    "status": "in_progress",
                    "parts_received": parts_received,
                    "parts_total": parts_total,
                })),
                Ok(ScannedAirgapPayload::CompleteText(text)) => ok_json(serde_json::json!({
                    "status": "complete_text",
                    "text": text,
                })),
                Ok(ScannedAirgapPayload::CompleteBinary(bytes)) => ok_json(serde_json::json!({
                    "status": "complete_binary_base64",
                    "base64": BASE64_STANDARD.encode(&bytes),
                })),
                Err(e) => err_json(e.to_string()),
            }
        }
        RpcRequest::InspectPsbt {
            psbt_input,
            session_recipients,
        } => {
            let hist: BTreeSet<String> = session_recipients.into_iter().collect();
            let guard = match ACTIVE_VAULT.lock() {
                Ok(g) => g,
                Err(_) => return err_json("Active vault mutex poisoned."),
            };
            let mnem_opt = guard.as_ref().map(|s| s.mnemonic.as_str());
            match parse_psbt_any(psbt_input.as_bytes())
                .and_then(|psbt| inspect_psbt(&psbt, mnem_opt, Some(&hist)))
            {
                Ok(insp) => ok_json(insp),
                Err(e) => err_json(e.to_string()),
            }
        }
        RpcRequest::SignPsbt {
            psbt_input,
            session_recipients,
        } => {
            let hist: BTreeSet<String> = session_recipients.into_iter().collect();
            match with_active_mnemonic(|st| {
                let art = parse_psbt_any(psbt_input.as_bytes())
                    .and_then(|mut psbt| sign_psbt(&mut psbt, &st.mnemonic, Some(&hist)))
                    .map_err(|e| e.to_string())?;
                let mut svgs = Vec::with_capacity(art.bbqr_parts.len());
                for p in &art.bbqr_parts {
                    if let Ok(s) = encode_qr_svg(p) {
                        svgs.push(s);
                    }
                }
                Ok(serde_json::json!({
                    "artifact": art,
                    "bbqr_svgs": svgs,
                }))
            }) {
                Ok(v) => ok_json(v),
                Err(e) => err_json(e),
            }
        }
        RpcRequest::Pipek1Derive {
            identity,
            index,
            reveal_nsec,
        } => match with_active_mnemonic(|st| {
            if reveal_nsec {
                let sec = export_pipek1_nsec(&st.mnemonic, identity, index)
                    .map_err(|e| e.to_string())?;
                let pub_info = derive_pipek1_public(&st.mnemonic, identity, index).ok();
                Ok(serde_json::json!({
                    "public": pub_info,
                    "nsec": sec.nsec,
                }))
            } else {
                let pub_info = derive_pipek1_public(&st.mnemonic, identity, index)
                    .map_err(|e| e.to_string())?;
                Ok(serde_json::json!({
                    "public": pub_info,
                    "nsec": serde_json::Value::Null,
                }))
            }
        }) {
            Ok(v) => ok_json(v),
            Err(e) => err_json(e),
        },
        RpcRequest::Pipek1Sign {
            identity,
            index,
            message_utf8,
            message_base64,
            timestamp,
        } => {
            let msg_bytes_res: Result<Vec<u8>, String> = if let Some(b64) = message_base64 {
                BASE64_STANDARD.decode(b64.trim()).map_err(|e| e.to_string())
            } else if let Some(txt) = message_utf8 {
                Ok(txt.into_bytes())
            } else {
                Err("Provide message_utf8 or message_base64.".into())
            };
            match msg_bytes_res.and_then(|bytes| {
                with_active_mnemonic(|st| {
                    let sig_art =
                        sign_pipek1_detached(&st.mnemonic, identity, index, &bytes, timestamp)
                            .map_err(|e| e.to_string())?;
                    let qr_svg = encode_qr_svg(&sig_art.armored).ok();
                    Ok(serde_json::json!({
                        "signed": sig_art,
                        "qr_svg": qr_svg,
                    }))
                })
            }) {
                Ok(v) => ok_json(v),
                Err(e) => err_json(e),
            }
        }
        RpcRequest::Pipek1Verify {
            message_utf8,
            message_base64,
            signature,
            expected_pubkey,
        } => {
            let msg_bytes_res: Result<Vec<u8>, String> = if let Some(b64) = message_base64 {
                BASE64_STANDARD.decode(b64.trim()).map_err(|e| e.to_string())
            } else if let Some(txt) = message_utf8 {
                Ok(txt.into_bytes())
            } else {
                Err("Provide message_utf8 or message_base64.".into())
            };
            match msg_bytes_res.and_then(|bytes| {
                verify_pipek1_detached(
                    &bytes,
                    signature.as_bytes(),
                    expected_pubkey.as_deref(),
                )
                .map_err(|e| e.to_string())
            }) {
                Ok(ver) => ok_json(ver),
                Err(e) => err_json(e),
            }
        }
        RpcRequest::EncryptVault {
            created_utc,
            descriptor,
            mut passphrase,
        } => {
            let res = with_active_mnemonic(|st| {
                let heirs = if st.bip85_children.len() > 1 {
                    st.bip85_children[1..].to_vec()
                } else {
                    Vec::new()
                };
                let payload = DecryptedVaultPayload {
                    version: "2.0.0-testnet4".to_string(),
                    created_utc,
                    master_root_mnemonic: st.mnemonic.clone(),
                    descriptor,
                    heir_treasuries: heirs,
                };
                let json_str =
                    encrypt_vault_payload(&payload, &passphrase).map_err(|e| e.to_string())?;
                Ok(serde_json::json!({ "vault_json": json_str }))
            });
            passphrase.zeroize();
            match res {
                Ok(v) => ok_json(v),
                Err(e) => err_json(e),
            }
        }
        RpcRequest::DecryptVault {
            vault_json,
            mut passphrase,
        } => {
            let res = match decrypt_vault_json(&vault_json, &passphrase) {
                Ok(payload) => {
                    let prof_opt = import_wallet_material(&payload.master_root_mnemonic).ok();
                    let fingerprint = prof_opt
                        .as_ref()
                        .map(|p| p.fingerprint.clone())
                        .unwrap_or_else(|| "verified".to_string());
                    let wpkh_qr_svg = encode_qr_svg(&payload.descriptor).ok();
                    let mut heir_public = Vec::with_capacity(payload.heir_treasuries.len());
                    for h in &payload.heir_treasuries {
                        if let Ok(pv) = h.derive_public_summary() {
                            heir_public.push(pv);
                        }
                    }
                    let created_utc = payload.created_utc.clone();
                    let descriptor = payload.descriptor.clone();
                    let heir_count = payload.heir_treasuries.len();
                    if let Ok(mut u_guard) = UNLOCKED_VAULT.lock() {
                        *u_guard = Some(payload);
                    }
                    ok_json(serde_json::json!({
                        "fingerprint": fingerprint,
                        "created_utc": created_utc,
                        "descriptor": descriptor,
                        "wpkh_qr_svg": wpkh_qr_svg,
                        "heir_count": heir_count,
                        "heir_public": heir_public,
                    }))
                }
                Err(e) => err_json(e.to_string()),
            };
            passphrase.zeroize();
            res
        }
        RpcRequest::RevealUnlockedVault => {
            let guard = match UNLOCKED_VAULT.lock() {
                Ok(g) => g,
                Err(_) => return err_json("Unlocked vault mutex poisoned."),
            };
            let Some(ref payload) = *guard else {
                return err_json("Unlock an encrypted vault.json first.");
            };
            ok_json(serde_json::json!({
                "master_root_mnemonic": payload.master_root_mnemonic,
                "heir_treasuries": payload.heir_treasuries,
            }))
        }
        RpcRequest::ActivateUnlockedVault => {
            let mnem_res = {
                let guard = match UNLOCKED_VAULT.lock() {
                    Ok(g) => g,
                    Err(_) => return err_json("Unlocked vault mutex poisoned."),
                };
                guard
                    .as_ref()
                    .map(|p| Zeroizing::new(p.master_root_mnemonic.clone()))
                    .ok_or_else(|| "Unlock an encrypted vault.json first.".to_string())
            };
            match mnem_res
                .and_then(|m| import_wallet_material(&m).map_err(|e| e.to_string()))
                .and_then(enrich_and_install_wallet)
            {
                Ok(wv) => ok_json(wv),
                Err(e) => err_json(e),
            }
        }
        RpcRequest::SeedfixSolve {
            mut eleven_words,
            typo_hint,
        } => {
            let res = match solve_twelfth_word(&eleven_words, typo_hint.as_deref()) {
                Ok(cands) => ok_json(cands),
                Err(e) => err_json(e.to_string()),
            };
            eleven_words.zeroize();
            res
        }
        RpcRequest::WordlistSearch { query, limit } => {
            ok_json(search_bip39_wordlist(&query, limit.unwrap_or(36)))
        }
    }
}

fn pack_output(bytes: Vec<u8>) -> u64 {
    let boxed: Box<[u8]> = bytes.into_boxed_slice();
    let len = boxed.len() as u64;
    let ptr = Box::into_raw(boxed) as *mut u8 as usize as u64;
    (ptr << 32) | len
}

#[no_mangle]
pub extern "C" fn sz_alloc(len: usize) -> *mut u8 {
    if len == 0 || len > 16 * 1024 * 1024 {
        return core::ptr::null_mut();
    }
    let boxed: Box<[u8]> = vec![0u8; len].into_boxed_slice();
    Box::into_raw(boxed) as *mut u8
}

/// Scrubs the exact-sized `Box<[u8]>` slice with volatile zero writes BEFORE freeing linear memory.
#[no_mangle]
pub unsafe extern "C" fn sz_dealloc(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let raw_slice = core::ptr::slice_from_raw_parts_mut(ptr, len);
    let mut boxed: Box<[u8]> = Box::from_raw(raw_slice);
    boxed.zeroize();
    drop(boxed);
}

#[no_mangle]
pub extern "C" fn sz_wipe_memory() {
    if let Ok(mut guard) = ACTIVE_VAULT.lock() {
        *guard = None;
    }
    if let Ok(mut guard) = MASTER_MNEMONIC_BACKUP.lock() {
        *guard = None;
    }
    if let Ok(mut guard) = UNLOCKED_VAULT.lock() {
        *guard = None;
    }
    if let Ok(mut guard) = QR_ASSEMBLER.lock() {
        *guard = None;
    }
    // Scrub small/medium WASM dlmalloc bins without triggering mmap growth
    for sz in [64usize, 256, 1024, 4096, 16384, 65536] {
        let mut blocks: Vec<Box<[u8]>> = (0..16)
            .map(|_| vec![0xAAu8; sz].into_boxed_slice())
            .collect();
        for b in &mut blocks {
            b.zeroize();
        }
        drop(blocks);
    }
}

#[no_mangle]
pub unsafe extern "C" fn sz_invoke(ptr: *const u8, len: usize) -> u64 {
    if ptr.is_null() || len == 0 || len > 8 * 1024 * 1024 {
        return pack_output(err_json("Invalid or oversized RPC payload.").into_bytes());
    }
    let slice = core::slice::from_raw_parts(ptr, len);
    let req_str = match core::str::from_utf8(slice) {
        Ok(s) => Zeroizing::new(s.to_string()),
        Err(_) => return pack_output(err_json("Invalid UTF-8 in RPC payload.").into_bytes()),
    };
    let mut resp = dispatch_rpc_json(&req_str);
    let out_bytes = resp.as_bytes().to_vec();
    resp.zeroize();
    pack_output(out_bytes)
}

/// Zero-copy greyscale frame QR decoder for live webcam scanning (`< 2ms` per frame).
#[no_mangle]
pub unsafe extern "C" fn sz_decode_qr_luma(ptr: *const u8, width: usize, height: usize) -> u64 {
    if ptr.is_null() || width < 21 || height < 21 || width > 4096 || height > 4096 {
        return pack_output(err_json("Invalid image dimensions for QR scan.").into_bytes());
    }
    let expected = width * height;
    let luma = core::slice::from_raw_parts(ptr, expected);
    match decode_qr_luma(width, height, luma) {
        Ok(Some(text)) => pack_output(ok_json(serde_json::json!({ "qr": text })).into_bytes()),
        Ok(None) => pack_output(ok_json(serde_json::json!({ "qr": serde_json::Value::Null })).into_bytes()),
        Err(e) => pack_output(err_json(e.to_string()).into_bytes()),
    }
}
