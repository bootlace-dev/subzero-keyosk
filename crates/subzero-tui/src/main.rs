//! `subzero` - Bare-Metal Linux TTY1 Airgapped Cold Vault Console (`crates/subzero-tui`).
//!
//! SECURITY & APPLIANCE LIFECYCLE INVARIANTS:
//! 1. Zero OS-RNG & Zero Network: Every cryptographic operation delegates to `subzero_core`.
//! 2. Process Hardening: Disables core dumps (`RLIMIT_CORE = 0`, `PR_SET_DUMPABLE = 0`) and locks
//!    virtual memory pages (`mlockall(MCL_CURRENT | MCL_FUTURE)`) so secrets never touch swap.
//! 3. Clean Amnesic Exit (`[C-03]` Fix): Pressing `Esc` twice (or `Ctrl+W`) explicitly zeroizes
//!    all in-memory state (`AppState::zeroize_sensitive`), purges the Linux console framebuffer
//!    and scrollback (`\x1b[3J`), restores TTY state, and returns `0` from `main()` WITHOUT calling
//!    `poweroff -f` directly - so `/opt/subzero/launch.sh` on the bare-metal appliance can execute
//!    its SHA-256-verified `/usr/bin/memtester-static` single-pass physical RAM scrub + `init_on_free=1`
//!    page release before shutdown.

mod qr_tui;
mod storage;

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::prelude::*;
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs, Wrap};
use ratatui::{Frame, Terminal};
use zeroize::Zeroize;

use qr_tui::{render_console_qr_lines, TuiQrMode};
use storage::{
    read_and_unlock_estate_partition, write_estate_partition, CameraEvent, CameraScanner,
};
use subzero_core::descriptor::verify_and_strip_checksum;
use subzero_core::entropy::{
    evaluate_keystroke_health, generate_obstacle_prompt, harvest_coins, harvest_dice,
    harvest_keystroke_course, harvest_raw_hex, KeystrokeHealthReport,
    KeystrokeSample, MIN_TIER2_ENTROPY_BITS, OBSTACLE_COURSE_LEN,
};
use subzero_core::keys::{
    derive_bip85_children, import_wallet_material, load_rehearsal_preset,
    mnemonic_to_compact_seed_qr, wallet_from_conditioned_entropy, Bip85Child, Bip85ChildPublic,
    WalletProfile,
};
use subzero_core::pipek1::{
    derive_pipek1_public, sign_pipek1_detached, verify_pipek1_detached, PipeK1IdentityPublic,
    PipeK1SignedArtifact,
};
use subzero_core::presets::list_presets;
use subzero_core::psbt::{
    inspect_psbt, parse_psbt_any, sign_psbt, verify_psbt_self_test, PsbtInspection,
    SignedPsbtArtifact,
};
use subzero_core::qr_codec::encode_bbqr_unicode;
use subzero_core::seedfix::{
    search_bip39_wordlist, solve_twelfth_word, SeedFixCandidate, WordlistEntry,
};
use subzero_core::vault::{decrypt_vault_json, encrypt_vault_payload, DecryptedVaultPayload};
use subzero_core::{SUBZERO_NETWORK, SUBZERO_VERSION};

const PRESET_COUNT: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Intake = 0,
    Wallet = 1,
    Bip85 = 2,
    Psbt = 3,
    PipeK1 = 4,
    Estate = 5,
    SeedFix = 6,
}

impl ActiveTab {
    const ALL: [ActiveTab; 7] = [
        ActiveTab::Intake,
        ActiveTab::Wallet,
        ActiveTab::Bip85,
        ActiveTab::Psbt,
        ActiveTab::PipeK1,
        ActiveTab::Estate,
        ActiveTab::SeedFix,
    ];

    fn title(&self) -> &'static str {
        match self {
            Self::Intake => "F1:Entropy",
            Self::Wallet => "F2:Watch-Only",
            Self::Bip85 => "F3:BIP-85",
            Self::Psbt => "F4:PSBT Sign",
            Self::PipeK1 => "F5:pipe-k1",
            Self::Estate => "F6:Estate USB",
            Self::SeedFix => "F7:SeedFix",
        }
    }

    fn next(&self) -> Self {
        Self::ALL[(*self as usize + 1) % Self::ALL.len()]
    }

    fn prev(&self) -> Self {
        let idx = *self as usize;
        Self::ALL[(idx + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntakeMethod {
    Presets,
    Coins,
    Dice,
    ObstacleCourse,
    ImportOrScan,
}

impl IntakeMethod {
    const ALL: [IntakeMethod; 5] = [
        IntakeMethod::Presets,
        IntakeMethod::Coins,
        IntakeMethod::Dice,
        IntakeMethod::ObstacleCourse,
        IntakeMethod::ImportOrScan,
    ];

    fn label(&self) -> &'static str {
        match self {
            Self::Presets => "1:Presets(0..9)",
            Self::Coins => "2:Tier1 Coins(128+)",
            Self::Dice => "3:Tier1 Dice(50+)",
            Self::ObstacleCourse => "4:Tier2 Keystroke Course",
            Self::ImportOrScan => "5:Import / QR Scan",
        }
    }

    fn next(&self) -> Self {
        let idx = Self::ALL.iter().position(|m| m == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }

    fn prev(&self) -> Self {
        let idx = Self::ALL.iter().position(|m| m == self).unwrap_or(0);
        Self::ALL[(idx + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressChainView {
    Bip84Receive,
    Bip84Change,
    Bip86Taproot,
}

impl AddressChainView {
    fn next(&self) -> Self {
        match self {
            Self::Bip84Receive => Self::Bip84Change,
            Self::Bip84Change => Self::Bip86Taproot,
            Self::Bip86Taproot => Self::Bip84Receive,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Bip84Receive => "BIP-84 Receive m/84'/1'/0'/0/* (tb1q)",
            Self::Bip84Change => "BIP-84 Internal Change m/84'/1'/0'/1/* (tb1q)",
            Self::Bip86Taproot => "BIP-86 Taproot Receive m/86'/1'/0'/0/* (tb1p)",
        }
    }
}

struct AppState {
    tab: ActiveTab,
    hardening_badge: String,
    status_line: String,
    status_is_error: bool,
    esc_armed_at: Option<Instant>,

    // Intake & Cooperative Two-Tier Entropy
    intake_method: IntakeMethod,
    selected_preset: u8,
    tier1_buffer: String,
    import_buffer: String,
    obstacle_round: u32,
    obstacle_prompt: String,
    obstacle_typed: String,
    obstacle_last_instant: Option<Instant>,
    obstacle_samples: Vec<KeystrokeSample>,
    obstacle_health: Option<KeystrokeHealthReport>,

    // Loaded Wallet & Master Root Backup (for BIP-85 child pivot)
    wallet: Option<WalletProfile>,
    master_backup: Option<WalletProfile>,
    compact_seed_qr: Option<String>,
    reveal_secrets: bool,
    addr_chain: AddressChainView,
    addr_page: usize,
    qr_mode: TuiQrMode,
    show_wallet_qr: bool,
    bbqr_descriptor_parts: Vec<String>,
    anim_frame: usize,
    last_anim_tick: Instant,

    // BIP-85 Child Vaults
    bip85_children: Vec<Bip85Child>,
    bip85_public: Vec<Bip85ChildPublic>,
    selected_bip85_idx: usize,

    // PSBT Audit & Airgap BBQr Signer
    psbt_buffer: String,
    psbt_inspection: Option<PsbtInspection>,
    signed_psbt: Option<SignedPsbtArtifact>,
    show_signed_psbt_qr: bool,
    session_recipients: BTreeSet<String>,

    // pipe-k1 Operational Identity & Detached Signer
    pipek1_index: u32,
    pipek1_verify_mode: bool,
    pipek1_msg_buffer: String,
    pipek1_sig_buffer: String,
    pipek1_expected_pub_buf: String,
    pipek1_focus: u8,
    pipek1_pub: Option<PipeK1IdentityPublic>,
    pipek1_signed: Option<PipeK1SignedArtifact>,
    pipek1_verify_result: Option<String>,
    show_pipek1_qr: bool,

    // Partition 2 (SUBZERO_EST) Estate Writer / Unlock
    estate_unlock_mode: bool,
    estate_passphrase_buf: String,
    estate_stamp_buf: String,
    estate_editing_stamp: bool,

    // SeedFix & BIP-39 Wordlist Search
    seedfix_wordlist_mode: bool,
    seedfix_eleven_buf: String,
    seedfix_hint_buf: String,
    seedfix_editing_hint: bool,
    seedfix_candidates: Vec<SeedFixCandidate>,
    wordlist_matches: Vec<WordlistEntry>,

    // V4L2 Optical Camera Scanner (`zbarcam`)
    camera: Option<CameraScanner>,
    camera_target_psbt: bool,
}

impl AppState {
    fn new(hardening_badge: String) -> Self {
        let prompt = generate_obstacle_prompt(0, OBSTACLE_COURSE_LEN);
        Self {
            tab: ActiveTab::Intake,
            hardening_badge,
            status_line: "Ready. Choose a funded Testnet4 preset (0..9) or harvest physical / timing entropy."
                .into(),
            status_is_error: false,
            esc_armed_at: None,
            intake_method: IntakeMethod::Presets,
            selected_preset: 0,
            tier1_buffer: String::new(),
            import_buffer: String::new(),
            obstacle_round: 0,
            obstacle_prompt: prompt,
            obstacle_typed: String::new(),
            obstacle_last_instant: None,
            obstacle_samples: Vec::new(),
            obstacle_health: None,
            wallet: None,
            master_backup: None,
            compact_seed_qr: None,
            reveal_secrets: false,
            addr_chain: AddressChainView::Bip84Receive,
            addr_page: 0,
            qr_mode: TuiQrMode::BbqrAnimated,
            show_wallet_qr: false,
            bbqr_descriptor_parts: Vec::new(),
            anim_frame: 0,
            last_anim_tick: Instant::now(),
            bip85_children: Vec::new(),
            bip85_public: Vec::new(),
            selected_bip85_idx: 0,
            psbt_buffer: String::new(),
            psbt_inspection: None,
            signed_psbt: None,
            show_signed_psbt_qr: false,
            session_recipients: BTreeSet::new(),
            pipek1_index: 0,
            pipek1_verify_mode: false,
            pipek1_msg_buffer: String::new(),
            pipek1_sig_buffer: String::new(),
            pipek1_expected_pub_buf: String::new(),
            pipek1_focus: 0,
            pipek1_pub: None,
            pipek1_signed: None,
            pipek1_verify_result: None,
            show_pipek1_qr: false,
            estate_unlock_mode: false,
            estate_passphrase_buf: String::new(),
            estate_stamp_buf: "2026_v2_cold".into(),
            estate_editing_stamp: false,
            seedfix_wordlist_mode: false,
            seedfix_eleven_buf: String::new(),
            seedfix_hint_buf: String::new(),
            seedfix_editing_hint: false,
            seedfix_candidates: Vec::new(),
            wordlist_matches: search_bip39_wordlist("aban", 24),
            camera: None,
            camera_target_psbt: false,
        }
    }

    fn set_ok(&mut self, msg: impl Into<String>) {
        self.status_line = msg.into();
        self.status_is_error = false;
    }

    fn set_err(&mut self, msg: impl Into<String>) {
        self.status_line = msg.into();
        self.status_is_error = true;
    }

    fn install_wallet(&mut self, profile: WalletProfile, preserve_master_backup: bool) {
        if !preserve_master_backup {
            self.master_backup = None;
        }
        self.reveal_secrets = false;
        self.show_wallet_qr = false;
        self.addr_page = 0;
        self.selected_bip85_idx = 0;
        // CRITICAL-01 & Cross-Session Isolation: purge ALL prior wallet PSBT/Estate/pipe-k1 state!
        self.psbt_inspection = None;
        if let Some(ref mut sp) = self.signed_psbt {
            sp.signed_psbt_base64.zeroize();
            sp.signed_psbt_hex.zeroize();
        }
        self.signed_psbt = None;
        self.show_signed_psbt_qr = false;
        self.session_recipients.clear();
        if let Some(ref mut pk) = self.pipek1_signed {
            pk.armored.zeroize();
            pk.raw_base64.zeroize();
        }
        self.pipek1_signed = None;
        self.show_pipek1_qr = false;
        self.pipek1_verify_result = None;
        self.estate_passphrase_buf.zeroize();
        self.estate_passphrase_buf.clear();
        if let Some(ref mut csq) = self.compact_seed_qr {
            csq.zeroize();
        }
        self.compact_seed_qr = None;
        for c in &mut self.bip85_children {
            c.zeroize();
        }
        self.bip85_children.clear();
        self.bip85_public.clear();

        self.bbqr_descriptor_parts =
            encode_bbqr_unicode(&profile.wpkh_descriptor, 2).unwrap_or_default();

        if let Some(ref m) = profile.mnemonic {
            self.compact_seed_qr = mnemonic_to_compact_seed_qr(m).ok();
            self.bip85_children = derive_bip85_children(m, 4).unwrap_or_default();
            self.bip85_public = self
                .bip85_children
                .iter()
                .filter_map(|c| c.derive_public_summary().ok())
                .collect();
            if let Some(first_child) = self.bip85_children.first() {
                self.estate_passphrase_buf = first_child.mnemonic.clone();
            }
            self.pipek1_pub = derive_pipek1_public(m, 0, self.pipek1_index).ok();
        } else {
            self.pipek1_pub = None;
        }

        let summary = format!(
            "Loaded XFP [{}] ({})",
            profile.fingerprint, profile.entropy_label
        );
        self.wallet = Some(profile);
        self.set_ok(summary);
    }

    fn reset_obstacle_course(&mut self, bump_round: bool) {
        if bump_round {
            self.obstacle_round = self.obstacle_round.wrapping_add(1);
        }
        self.obstacle_prompt = generate_obstacle_prompt(self.obstacle_round, OBSTACLE_COURSE_LEN);
        self.obstacle_typed.zeroize();
        self.obstacle_typed.clear();
        self.obstacle_last_instant = None;
        self.obstacle_samples.zeroize();
        self.obstacle_samples.clear();
        self.obstacle_health = None;
    }

    fn stop_camera(&mut self) {
        if let Some(mut cam) = self.camera.take() {
            cam.stop();
        }
    }

    fn zeroize_sensitive(&mut self) {
        self.stop_camera();
        self.status_line.zeroize();
        self.status_line.clear();
        self.tier1_buffer.zeroize();
        self.import_buffer.zeroize();
        self.obstacle_typed.zeroize();
        self.obstacle_samples.zeroize();
        self.wallet = None;
        self.master_backup = None;
        if let Some(ref mut csq) = self.compact_seed_qr {
            csq.zeroize();
        }
        self.compact_seed_qr = None;
        for c in &mut self.bip85_children {
            c.zeroize();
        }
        self.bip85_children.clear();
        self.bip85_public.clear();
        self.psbt_buffer.zeroize();
        self.psbt_inspection = None;
        if let Some(ref mut sp) = self.signed_psbt {
            sp.signed_psbt_base64.zeroize();
            sp.signed_psbt_hex.zeroize();
        }
        self.signed_psbt = None;
        self.session_recipients.clear();
        self.pipek1_msg_buffer.zeroize();
        self.pipek1_sig_buffer.zeroize();
        self.pipek1_expected_pub_buf.zeroize();
        self.pipek1_pub = None;
        if let Some(ref mut pk) = self.pipek1_signed {
            pk.armored.zeroize();
            pk.raw_base64.zeroize();
        }
        self.pipek1_signed = None;
        if let Some(ref mut vr) = self.pipek1_verify_result {
            vr.zeroize();
        }
        self.pipek1_verify_result = None;
        self.estate_passphrase_buf.zeroize();
        self.estate_stamp_buf.zeroize();
        self.seedfix_eleven_buf.zeroize();
        self.seedfix_hint_buf.zeroize();
        self.seedfix_candidates.clear();

        // Sweep small/medium allocator bins + 2 MB buffer so heap free-lists are overwritten
        for sz in [64usize, 256, 1024, 4096, 16384, 65536] {
            let mut blocks: Vec<Box<[u8]>> = (0..16)
                .map(|_| vec![0xAAu8; sz].into_boxed_slice())
                .collect();
            for b in &mut blocks {
                b.zeroize();
            }
            drop(blocks);
        }
        let mut sweep = vec![0u8; 2 * 1024 * 1024];
        sweep.fill(0x55);
        sweep.fill(0xAA);
        sweep.zeroize();
    }
}

fn harden_linux_process() -> String {
    let mut notes = Vec::new();
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 {
            notes.push("nodump");
        }
        let zero_lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &zero_lim) == 0 {
            notes.push("nocore");
        }
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) == 0 {
            notes.push("mlockall");
        } else {
            notes.push("mlock:unpriv");
        }
    }
    notes.join("+")
}

/// Deterministic, zero-OS-RNG Known-Answer Self-Test (`subzero --self-test`).
/// Executes across every `subzero-core` subsystem so both reproducible container builds and
/// bare-metal `launch.sh` boot scripts can cryptographically verify binary integrity before use.
fn run_self_test() -> Result<(), String> {
    println!("SubZero v{SUBZERO_VERSION} ({SUBZERO_NETWORK}) - Deterministic KAT Self-Test");

    // 1. All 10 Unified Funded Testnet4 Presets + BIP-380 Descriptor Checksums
    for id in 0..PRESET_COUNT as u8 {
        let p = load_rehearsal_preset(id).map_err(|e| format!("Preset {id} failed: {e}"))?;
        verify_and_strip_checksum(&p.wpkh_descriptor)
            .map_err(|e| format!("Preset {id} wpkh BIP-380 checksum failed: {e}"))?;
        if let Some(ref tr) = p.tr_descriptor {
            verify_and_strip_checksum(tr)
                .map_err(|e| format!("Preset {id} tr BIP-380 checksum failed: {e}"))?;
        }
    }
    let p0 = load_rehearsal_preset(0).map_err(|e| e.to_string())?;
    if p0.fingerprint != "73c5da0a" {
        return Err(format!("Preset 0 fingerprint mismatch: {}", p0.fingerprint));
    }
    println!("  [PASS] Presets 0..9 + BIP-380 wpkh/tr descriptor checksums verified.");

    // 2. Tier 1 Physical Discrete Entropy (Coins + Dice)
    let coin_128 = "1011001001101101010011100010110110100110010110101100100101110010"
        .to_string()
        + "0101100110100100110100110011010110101100010101101001101001101001";
    let ce_coins = harvest_coins(&coin_128).map_err(|e| format!("Coin KAT failed: {e}"))?;
    let w_coins = wallet_from_conditioned_entropy(&ce_coins).map_err(|e| e.to_string())?;
    assert!(!w_coins.receive_addresses[0].is_empty());

    let dice_60 = "314156265352164336324626433132565124163526145362154362514263";
    let ce_dice = harvest_dice(dice_60).map_err(|e| format!("Dice KAT failed: {e}"))?;
    let _ = wallet_from_conditioned_entropy(&ce_dice).map_err(|e| e.to_string())?;

    println!("  [PASS] Tier 1 Coins and Dice guards verified.");

    // 3. Tier 2 Obstacle Course Prompt Determinism + Clamped-Timer Hard Block
    let prompt_a = generate_obstacle_prompt(0, OBSTACLE_COURSE_LEN);
    let prompt_b = generate_obstacle_prompt(0, OBSTACLE_COURSE_LEN);
    if prompt_a != prompt_b || prompt_a.len() != OBSTACLE_COURSE_LEN {
        return Err("Obstacle prompt determinism check failed.".into());
    }
    let clamped_samples: Vec<KeystrokeSample> = (0..40)
        .map(|i| KeystrokeSample {
            key: "a".into(),
            delta_us: ((i % 3) + 1) * 100_000, // Tor Browser 100ms clamped timer simulation
            is_backspace: false,
            was_typo: false,
            is_repeat: false,
        })
        .collect();
    if evaluate_keystroke_health(&clamped_samples).is_ok() {
        return Err("Clamped 100ms clock simulation was NOT blocked!".into());
    }
    println!("  [PASS] Tier 2 zero-OS-RNG obstacle course & clamped-clock blocker verified.");

    // 4. pipe-k1 Sign & Verify Round-Trip
    let p0_mnem = p0.mnemonic.as_deref().unwrap();
    let msg = b"subzero-v2-self-test-manifest";
    let sig = sign_pipek1_detached(p0_mnem, 0, 0, msg, 1_700_000_000)
        .map_err(|e| format!("pipe-k1 sign failed: {e}"))?;
    let ver = verify_pipek1_detached(msg, sig.armored.as_bytes(), Some(&sig.npub))
        .map_err(|e| format!("pipe-k1 verify failed: {e}"))?;
    if !ver.valid {
        return Err("pipe-k1 verification returned false.".into());
    }
    println!("  [PASS] pipe-k1 (m/83696968'/128002') BIP-340 Schnorr sign/verify verified.");

    // 5. SIV-Committed Vault v2 Round-Trip + SeedFix 128-Candidate Solver
    let children = derive_bip85_children(p0_mnem, 2).map_err(|e| e.to_string())?;
    let payload = DecryptedVaultPayload {
        version: SUBZERO_VERSION.into(),
        created_utc: "2026-11-15T00:00:00Z".into(),
        master_root_mnemonic: p0_mnem.to_string(),
        descriptor: p0.wpkh_descriptor.clone(),
        heir_treasuries: children[1..].to_vec(),
    };
    let enc_a = encrypt_vault_payload(&payload, &children[0].mnemonic).map_err(|e| e.to_string())?;
    let enc_b = encrypt_vault_payload(&payload, &children[0].mnemonic).map_err(|e| e.to_string())?;
    if enc_a != enc_b {
        return Err("SIV vault encryption is not deterministic!".into());
    }
    let dec = decrypt_vault_json(&enc_a, &children[0].mnemonic).map_err(|e| e.to_string())?;
    if dec.master_root_mnemonic != p0_mnem {
        return Err("Vault decryption mismatch!".into());
    }
    let cands = solve_twelfth_word(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        Some("abou"),
    )
    .map_err(|e| e.to_string())?;
    if cands.len() != 128 || cands[0].twelfth_word != "about" {
        return Err("SeedFix 12th-word solver failed baseline KAT.".into());
    }
    println!("  [PASS] SIV-committed AES-256-GCM Vault (600k PBKDF2) & SeedFix verified.");

    // 6. BIP-84 P2WPKH + BIP-86 P2TR PSBT Signing, CVE-2020-14199 & Change-Spoofing KAT
    verify_psbt_self_test().map_err(|e| format!("PSBT KAT failed: {e}"))?;
    println!("  [PASS] BIP-84 P2WPKH + BIP-86 P2TR PSBT signing & anti-spoofing guards verified.");

    println!("ALL SELF-TESTS PASSED.");
    Ok(())
}

fn chunk_grouped(s: &str, group: usize) -> String {
    let clean: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
    clean
        .chunks(group)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

fn poll_camera_events(app: &mut AppState) {
    let mut events = Vec::new();
    if let Some(ref cam) = app.camera {
        while let Ok(ev) = cam.receiver.try_recv() {
            events.push(ev);
        }
    }
    let mut stop_now = false;
    for ev in events {
        match ev {
            CameraEvent::Progress { received, total } => {
                app.set_ok(format!(
                    "Optical BBQr scan in progress: {received}/{total} unique frames captured..."
                ));
            }
            CameraEvent::CompleteText(text) => {
                stop_now = true;
                if app.camera_target_psbt {
                    app.psbt_buffer = text;
                    run_psbt_inspect(app);
                } else {
                    app.import_buffer = text;
                    match import_wallet_material(&app.import_buffer) {
                        Ok(w) => {
                            app.install_wallet(w, false);
                            app.tab = ActiveTab::Wallet;
                        }
                        Err(e) => app.set_err(format!("Scanned QR import error: {e}")),
                    }
                }
            }
            CameraEvent::CompleteBinary(bytes) => {
                stop_now = true;
                app.psbt_buffer = BASE64_STANDARD.encode(&bytes);
                app.tab = ActiveTab::Psbt;
                run_psbt_inspect(app);
            }
            CameraEvent::Diagnostic(msg) => {
                app.set_ok(format!("Camera: {msg}"));
            }
            CameraEvent::FatalError(err) => {
                stop_now = true;
                app.set_err(err);
            }
        }
    }
    if stop_now {
        app.stop_camera();
    }
}

fn run_psbt_inspect(app: &mut AppState) {
    let mnem = app.wallet.as_ref().and_then(|w| w.mnemonic.as_deref());
    match parse_psbt_any(app.psbt_buffer.as_bytes())
        .and_then(|psbt| inspect_psbt(&psbt, mnem, Some(&app.session_recipients)))
    {
        Ok(insp) => {
            let msg = if insp.can_sign {
                format!(
                    "PSBT verified: {} in -> {} out, fee {} sats. Press Ctrl+G to sign.",
                    insp.inputs.len(),
                    insp.outputs.len(),
                    insp.fee_sat.unwrap_or(0)
                )
            } else {
                format!(
                    "PSBT BLOCKED ({} fatal issue(s)). Review red security flags below.",
                    insp.fatal_blocks.len()
                )
            };
            let is_err = !insp.can_sign;
            app.psbt_inspection = Some(insp);
            app.signed_psbt = None;
            app.show_signed_psbt_qr = false;
            if is_err {
                app.set_err(msg);
            } else {
                app.set_ok(msg);
            }
        }
        Err(e) => {
            app.psbt_inspection = None;
            app.set_err(format!("PSBT parse/audit error: {e}"));
        }
    }
}

fn handle_obstacle_key(app: &mut AppState, key: KeyEvent) {
    // Reject OS auto-repeat events so holding down a key can never inflate sample count
    if key.kind != KeyEventKind::Press {
        return;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('r') {
        app.reset_obstacle_course(true);
        app.set_ok(format!(
            "Reset cooperative obstacle course to Round #{}.",
            app.obstacle_round
        ));
        return;
    }

    let now = Instant::now();
    let delta_us = app
        .obstacle_last_instant
        .map(|prev| now.duration_since(prev).as_micros() as u64)
        .unwrap_or(0);

    let prompt_chars: Vec<char> = app.obstacle_prompt.chars().collect();
    let typed_chars: Vec<char> = app.obstacle_typed.chars().collect();
    let has_mismatch = typed_chars
        .iter()
        .zip(prompt_chars.iter())
        .any(|(a, b)| a != b);

    match key.code {
        KeyCode::Backspace => {
            if !app.obstacle_typed.is_empty() {
                app.obstacle_typed.pop();
                app.obstacle_samples.push(KeystrokeSample {
                    key: "Backspace".into(),
                    delta_us,
                    is_backspace: true,
                    was_typo: false,
                    is_repeat: false,
                });
                app.obstacle_last_instant = Some(now);
                app.obstacle_health = evaluate_keystroke_health(&app.obstacle_samples).ok();
            }
        }
        KeyCode::Enter => {
            match harvest_keystroke_course(
                &app.obstacle_prompt,
                &app.obstacle_typed,
                &app.obstacle_samples,
            )
            .and_then(|ent| wallet_from_conditioned_entropy(&ent))
            {
                Ok(wallet) => {
                    app.reset_obstacle_course(true);
                    app.install_wallet(wallet, false);
                    app.tab = ActiveTab::Wallet;
                }
                Err(e) => app.set_err(e.to_string()),
            }
        }
        KeyCode::Char(ch)
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT) =>
        {
            if has_mismatch {
                app.set_err(
                    "Red typo active! Press Backspace to clear the mismatch before typing ahead.",
                );
                return;
            }
            if typed_chars.len() < prompt_chars.len() {
                let expected = prompt_chars[typed_chars.len()];
                let was_typo = ch != expected;
                app.obstacle_typed.push(ch);
                app.obstacle_samples.push(KeystrokeSample {
                    key: ch.to_string(),
                    delta_us,
                    is_backspace: false,
                    was_typo,
                    is_repeat: false,
                });
                app.obstacle_last_instant = Some(now);
                match evaluate_keystroke_health(&app.obstacle_samples) {
                    Ok(rep) => {
                        if !rep.timer_quantum_ok {
                            app.set_err(rep.timer_diagnostic.clone());
                        } else if was_typo {
                            app.set_err(
                                "Typo recorded (great timing jitter!) - press Backspace to fix it.",
                            );
                        } else {
                            app.set_ok(format!(
                                "Progress {}/{} chars | Conservative 90B Entropy: {:.1} / {:.0} bits",
                                app.obstacle_typed.len(),
                                OBSTACLE_COURSE_LEN,
                                rep.estimated_min_entropy_bits,
                                MIN_TIER2_ENTROPY_BITS
                            ));
                        }
                        app.obstacle_health = Some(rep);
                    }
                    Err(e) => {
                        if app.obstacle_samples.len() >= 16 {
                            app.set_err(e.to_string());
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

fn handle_key_event(app: &mut AppState, key: KeyEvent) -> bool {
    if key.kind != KeyEventKind::Press {
        return false;
    }

    // Double-Esc or Ctrl+W triggers immediate amnesic RAM scrub & exit
    if key.code == KeyCode::Esc {
        if app.camera.is_some() {
            app.stop_camera();
            app.set_ok("Stopped V4L2 optical scanner.");
            return false;
        }
        if let Some(prev) = app.esc_armed_at {
            if prev.elapsed() <= Duration::from_secs(3) {
                return true;
            }
        }
        app.esc_armed_at = Some(Instant::now());
        app.set_err("AMNESIC WIPE ARMED: Press Esc again within 3s (or Ctrl+W) to scrub RAM & exit.");
        return false;
    } else {
        app.esc_armed_at = None;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('w') {
        return true;
    }

    // Function-key direct tab navigation works from EVERY screen, including raw obstacle typing
    match key.code {
        KeyCode::F(1) => {
            app.tab = ActiveTab::Intake;
            return false;
        }
        KeyCode::F(2) => {
            app.tab = ActiveTab::Wallet;
            return false;
        }
        KeyCode::F(3) => {
            app.tab = ActiveTab::Bip85;
            return false;
        }
        KeyCode::F(4) => {
            app.tab = ActiveTab::Psbt;
            return false;
        }
        KeyCode::F(5) => {
            app.tab = ActiveTab::PipeK1;
            return false;
        }
        KeyCode::F(6) => {
            app.tab = ActiveTab::Estate;
            return false;
        }
        KeyCode::F(7) => {
            app.tab = ActiveTab::SeedFix;
            return false;
        }
        KeyCode::Tab => {
            app.tab = app.tab.next();
            return false;
        }
        KeyCode::BackTab => {
            app.tab = app.tab.prev();
            return false;
        }
        _ => {}
    }

    match app.tab {
        ActiveTab::Intake => {
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('n') {
                app.intake_method = app.intake_method.next();
                return false;
            }
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('p') {
                app.intake_method = app.intake_method.prev();
                return false;
            }
            if key.modifiers.contains(KeyModifiers::ALT) {
                if let KeyCode::Char(c @ '1'..='6') = key.code {
                    app.intake_method = IntakeMethod::ALL[(c as usize) - ('1' as usize)];
                    return false;
                }
            }

            match app.intake_method {
                IntakeMethod::Presets => match key.code {
                    KeyCode::Up => {
                        app.selected_preset = if app.selected_preset == 0 {
                            (PRESET_COUNT - 1) as u8
                        } else {
                            app.selected_preset - 1
                        };
                    }
                    KeyCode::Down => {
                        app.selected_preset = (app.selected_preset + 1) % (PRESET_COUNT as u8);
                    }
                    KeyCode::Char(d @ '0'..='9') => {
                        app.selected_preset = (d as u8) - b'0';
                    }
                    KeyCode::Enter => match load_rehearsal_preset(app.selected_preset) {
                        Ok(w) => {
                            app.install_wallet(w, false);
                            app.tab = ActiveTab::Wallet;
                        }
                        Err(e) => app.set_err(e.to_string()),
                    },
                    _ => {}
                },
                IntakeMethod::Coins | IntakeMethod::Dice => match key.code {
                    KeyCode::Backspace => {
                        app.tier1_buffer.pop();
                    }
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.tier1_buffer.zeroize();
                        app.tier1_buffer.clear();
                    }
                    KeyCode::Enter => {
                        let res = match app.intake_method {
                            IntakeMethod::Coins => harvest_coins(&app.tier1_buffer),
                            IntakeMethod::Dice => harvest_dice(&app.tier1_buffer),
                            _ => unreachable!(),
                        };
                        match res.and_then(|ent| wallet_from_conditioned_entropy(&ent)) {
                            Ok(w) => {
                                app.tier1_buffer.zeroize();
                                app.tier1_buffer.clear();
                                app.install_wallet(w, false);
                                app.tab = ActiveTab::Wallet;
                            }
                            Err(e) => app.set_err(e.to_string()),
                        }
                    }
                    KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.tier1_buffer.push(c);
                    }
                    _ => {}
                },
                IntakeMethod::ObstacleCourse => handle_obstacle_key(app, key),
                IntakeMethod::ImportOrScan => match key.code {
                    KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.stop_camera();
                        app.camera_target_psbt = false;
                        let cam = CameraScanner::spawn();
                        let dev = cam.device_path.clone();
                        app.camera = Some(cam);
                        app.set_ok(format!(
                            "Started V4L2 optical scanner on {dev} (Esc to cancel)."
                        ));
                    }
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.import_buffer.zeroize();
                        app.import_buffer.clear();
                    }
                    KeyCode::Backspace => {
                        app.import_buffer.pop();
                    }
                    KeyCode::Enter => {
                        let trimmed = app.import_buffer.trim();
                        let res = if trimmed.len() == 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                            harvest_raw_hex(trimmed).and_then(|ent| wallet_from_conditioned_entropy(&ent))
                        } else {
                            import_wallet_material(trimmed)
                        };
                        match res {
                            Ok(w) => {
                                app.import_buffer.zeroize();
                                app.import_buffer.clear();
                                app.install_wallet(w, false);
                                app.tab = ActiveTab::Wallet;
                            }
                            Err(e) => app.set_err(e.to_string()),
                        }
                    }
                    KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.import_buffer.push(c);
                    }
                    _ => {}
                },
            }
        }
        ActiveTab::Wallet => match key.code {
            KeyCode::Char(']') => {
                app.addr_chain = app.addr_chain.next();
                app.addr_page = 0;
            }
            KeyCode::Up => {
                app.addr_page = app.addr_page.saturating_sub(1);
            }
            KeyCode::Down => {
                app.addr_page = app.addr_page.saturating_add(1);
            }
            KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if !app.show_wallet_qr {
                    app.show_wallet_qr = true;
                } else {
                    app.qr_mode = app.qr_mode.next();
                }
            }
            KeyCode::Char('x') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.show_wallet_qr = false;
            }
            KeyCode::Char('v') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.reveal_secrets = !app.reveal_secrets;
            }
            KeyCode::Char('b') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if let Some(master) = app.master_backup.take() {
                    app.install_wallet(master, false);
                    app.set_ok("Returned from BIP-85 child vault to Master Root.");
                }
            }
            _ => {}
        },
        ActiveTab::Bip85 => match key.code {
            KeyCode::Up => {
                app.selected_bip85_idx = app.selected_bip85_idx.saturating_sub(1);
            }
            KeyCode::Down => {
                if !app.bip85_children.is_empty() {
                    app.selected_bip85_idx =
                        (app.selected_bip85_idx + 1).min(app.bip85_children.len() - 1);
                }
            }
            KeyCode::Char('v') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.reveal_secrets = !app.reveal_secrets;
            }
            KeyCode::Char('b') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if let Some(master) = app.master_backup.take() {
                    app.install_wallet(master, false);
                    app.set_ok("Returned to Master Root wallet.");
                }
            }
            KeyCode::Enter => {
                if let Some(child) = app.bip85_children.get(app.selected_bip85_idx).cloned() {
                    if child.index == 0 {
                        app.set_err(
                            "Index 0 is the Decoupled Estate Encryption Passphrase - DO NOT fund on-chain! Select Index 1..4.",
                        );
                    } else if let Ok(child_wallet) = import_wallet_material(&child.mnemonic) {
                        if app.master_backup.is_none() {
                            app.master_backup = app.wallet.clone();
                        }
                        app.install_wallet(child_wallet, true);
                        app.tab = ActiveTab::Wallet;
                        app.set_ok(format!(
                            "Pivoted into BIP-85 Child #{} (Ctrl+B to return to Master Root).",
                            child.index
                        ));
                    }
                }
            }
            _ => {}
        },
        ActiveTab::Psbt => match key.code {
            KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.stop_camera();
                app.camera_target_psbt = true;
                app.camera = Some(CameraScanner::spawn());
                app.set_ok("Scanning animated BBQr / Base64 PSBT from V4L2 camera (Esc to stop)...");
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.psbt_buffer.zeroize();
                app.psbt_buffer.clear();
                app.psbt_inspection = None;
                if let Some(ref mut sp) = app.signed_psbt {
                    sp.signed_psbt_base64.zeroize();
                    sp.signed_psbt_hex.zeroize();
                }
                app.signed_psbt = None;
                app.show_signed_psbt_qr = false;
            }
            KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if app.signed_psbt.is_some() {
                    app.show_signed_psbt_qr = !app.show_signed_psbt_qr;
                }
            }
            KeyCode::Char('g') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if !app.psbt_inspection.as_ref().is_some_and(|i| i.can_sign) {
                    app.set_err("Press Enter to inspect and verify the current PSBT buffer before signing (Ctrl+G).");
                    return false;
                }
                let Some(mnem) = app.wallet.as_ref().and_then(|w| w.mnemonic.clone()) else {
                    app.set_err("Cannot sign: load a private-key wallet first (current session is empty or Watch-Only).");
                    return false;
                };
                match parse_psbt_any(app.psbt_buffer.as_bytes())
                    .and_then(|mut psbt| sign_psbt(&mut psbt, &mnem, Some(&app.session_recipients)))
                {
                    Ok(art) => {
                        for out in &art.inspection.outputs {
                            if !out.is_verified_change && !out.is_verified_self_receive {
                                app.session_recipients.insert(out.address.clone());
                            }
                        }
                        app.set_ok(format!(
                            "Signed {} input(s) for TXID {}! Showing animated BBQr ({} frames).",
                            art.signatures_added,
                            art.txid,
                            art.bbqr_parts.len()
                        ));
                        app.psbt_inspection = Some(art.inspection.clone());
                        app.signed_psbt = Some(art);
                        app.show_signed_psbt_qr = true;
                        app.anim_frame = 0;
                    }
                    Err(e) => app.set_err(format!("PSBT signing refused: {e}")),
                }
            }
            KeyCode::Backspace => {
                app.psbt_buffer.pop();
                app.psbt_inspection = None;
                app.signed_psbt = None;
                app.show_signed_psbt_qr = false;
            }
            KeyCode::Enter => run_psbt_inspect(app),
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.psbt_buffer.push(c);
                app.psbt_inspection = None;
                app.signed_psbt = None;
                app.show_signed_psbt_qr = false;
            }
            _ => {}
        },
        ActiveTab::PipeK1 => match key.code {
            KeyCode::Char(']') if key.modifiers.contains(KeyModifiers::ALT) => {
                app.pipek1_index = app.pipek1_index.saturating_add(1);
                if let Some(mnem) = app.wallet.as_ref().and_then(|w| w.mnemonic.as_deref()) {
                    app.pipek1_pub = derive_pipek1_public(mnem, 0, app.pipek1_index).ok();
                }
            }
            KeyCode::Char('[') if key.modifiers.contains(KeyModifiers::ALT) => {
                app.pipek1_index = app.pipek1_index.saturating_sub(1);
                if let Some(mnem) = app.wallet.as_ref().and_then(|w| w.mnemonic.as_deref()) {
                    app.pipek1_pub = derive_pipek1_public(mnem, 0, app.pipek1_index).ok();
                }
            }
            KeyCode::Up if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.pipek1_index = app.pipek1_index.saturating_add(1);
                if let Some(mnem) = app.wallet.as_ref().and_then(|w| w.mnemonic.as_deref()) {
                    app.pipek1_pub = derive_pipek1_public(mnem, 0, app.pipek1_index).ok();
                }
            }
            KeyCode::Down if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.pipek1_index = app.pipek1_index.saturating_sub(1);
                if let Some(mnem) = app.wallet.as_ref().and_then(|w| w.mnemonic.as_deref()) {
                    app.pipek1_pub = derive_pipek1_public(mnem, 0, app.pipek1_index).ok();
                }
            }
            KeyCode::Char('t') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.pipek1_verify_mode = !app.pipek1_verify_mode;
                app.pipek1_focus = 0;
            }
            KeyCode::Char('f') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if app.pipek1_verify_mode {
                    app.pipek1_focus = (app.pipek1_focus + 1) % 3;
                }
            }
            KeyCode::Char('j') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if app.pipek1_verify_mode && app.pipek1_focus == 1 {
                    app.pipek1_sig_buffer.push('\n');
                } else if !app.pipek1_verify_mode || app.pipek1_focus == 0 {
                    app.pipek1_msg_buffer.push('\n');
                }
            }
            KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if app.pipek1_signed.is_some() {
                    app.show_pipek1_qr = !app.show_pipek1_qr;
                }
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.pipek1_msg_buffer.zeroize();
                app.pipek1_msg_buffer.clear();
                app.pipek1_sig_buffer.zeroize();
                app.pipek1_sig_buffer.clear();
                app.pipek1_expected_pub_buf.zeroize();
                app.pipek1_expected_pub_buf.clear();
                app.pipek1_verify_result = None;
            }
            KeyCode::Backspace => {
                if app.pipek1_verify_mode {
                    match app.pipek1_focus {
                        1 => {
                            app.pipek1_sig_buffer.pop();
                        }
                        2 => {
                            app.pipek1_expected_pub_buf.pop();
                        }
                        _ => {
                            app.pipek1_msg_buffer.pop();
                        }
                    }
                } else {
                    app.pipek1_msg_buffer.pop();
                }
            }
            KeyCode::Enter => {
                if app.pipek1_verify_mode {
                    let expected_opt = if app.pipek1_expected_pub_buf.trim().is_empty() {
                        None
                    } else {
                        Some(app.pipek1_expected_pub_buf.trim())
                    };
                    match verify_pipek1_detached(
                        app.pipek1_msg_buffer.as_bytes(),
                        app.pipek1_sig_buffer.as_bytes(),
                        expected_opt,
                    ) {
                        Ok(v) => {
                            let pin_badge = if v.pubkey_pinned {
                                "PINNED PUBKEY MATCH"
                            } else {
                                "UNPINNED SELF-SIGNED (enter expected npub in field 3 to pin)"
                            };
                            let legacy_note = if v.legacy_tag_used {
                                " [LEGACY TAG]"
                            } else {
                                ""
                            };
                            let summary = format!(
                                "VALID pipe-k1 signature from {} (ts={}) [{pin_badge}]{legacy_note}",
                                v.npub, v.timestamp
                            );
                            app.pipek1_verify_result = Some(summary.clone());
                            app.set_ok(summary);
                        }
                        Err(e) => {
                            let msg = format!("INVALID pipe-k1 signature: {e}");
                            app.pipek1_verify_result = Some(msg.clone());
                            app.set_err(msg);
                        }
                    }
                } else {
                    let Some(mnem) = app.wallet.as_ref().and_then(|w| w.mnemonic.clone()) else {
                        app.set_err("Load a mnemonic wallet first to sign with pipe-k1.");
                        return false;
                    };
                    let ts = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs().min(u32::MAX as u64) as u32)
                        .unwrap_or(0);
                    match sign_pipek1_detached(
                        &mnem,
                        0,
                        app.pipek1_index,
                        app.pipek1_msg_buffer.as_bytes(),
                        ts,
                    ) {
                        Ok(art) => {
                            app.set_ok(format!("Signed message under {} (ts={ts})!", art.npub));
                            app.pipek1_signed = Some(art);
                        }
                        Err(e) => app.set_err(e.to_string()),
                    }
                }
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                if app.pipek1_verify_mode {
                    match app.pipek1_focus {
                        1 => app.pipek1_sig_buffer.push(c),
                        2 => app.pipek1_expected_pub_buf.push(c),
                        _ => app.pipek1_msg_buffer.push(c),
                    }
                } else {
                    app.pipek1_msg_buffer.push(c);
                }
            }
            _ => {}
        },
        ActiveTab::Estate => match key.code {
            KeyCode::Char('t') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.estate_unlock_mode = !app.estate_unlock_mode;
            }
            KeyCode::Char('f') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.estate_editing_stamp = !app.estate_editing_stamp;
            }
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if let Some(first) = app.bip85_children.first() {
                    app.estate_passphrase_buf = first.mnemonic.clone();
                    app.set_ok("Filled BIP-85 Index 0 Decoupled Estate Passphrase.");
                }
            }
            KeyCode::Backspace => {
                if app.estate_editing_stamp && !app.estate_unlock_mode {
                    app.estate_stamp_buf.pop();
                } else {
                    app.estate_passphrase_buf.pop();
                }
            }
            KeyCode::Enter => {
                if app.estate_unlock_mode {
                    match read_and_unlock_estate_partition(&app.estate_passphrase_buf)
                        .and_then(|p| import_wallet_material(&p.master_root_mnemonic).map_err(|e| e.to_string()))
                    {
                        Ok(w) => {
                            app.install_wallet(w, false);
                            app.tab = ActiveTab::Wallet;
                            app.set_ok("Unlocked Partition 2 SUBZERO_EST vault.json into memory!");
                        }
                        Err(e) => app.set_err(e),
                    }
                } else {
                    let Some(ref w) = app.wallet else {
                        app.set_err("Load a wallet before writing Partition 2 SUBZERO_EST.");
                        return false;
                    };
                    let Some(ref mnem) = w.mnemonic else {
                        app.set_err("Watch-only profile has no master mnemonic to seal.");
                        return false;
                    };
                    let payload = DecryptedVaultPayload {
                        version: SUBZERO_VERSION.into(),
                        created_utc: app.estate_stamp_buf.clone(),
                        master_root_mnemonic: mnem.clone(),
                        descriptor: w.wpkh_descriptor.clone(),
                        heir_treasuries: if app.bip85_children.len() > 1 {
                            app.bip85_children[1..].to_vec()
                        } else {
                            Vec::new()
                        },
                    };
                    match write_estate_partition(
                        &payload,
                        &app.estate_passphrase_buf,
                        &app.estate_stamp_buf,
                    ) {
                        Ok(msg) => app.set_ok(msg),
                        Err(e) => app.set_err(e),
                    }
                }
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                if app.estate_editing_stamp && !app.estate_unlock_mode {
                    app.estate_stamp_buf.push(c);
                } else {
                    app.estate_passphrase_buf.push(c);
                }
            }
            _ => {}
        },
        ActiveTab::SeedFix => match key.code {
            KeyCode::Char('t') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.seedfix_wordlist_mode = !app.seedfix_wordlist_mode;
            }
            KeyCode::Char('f') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.seedfix_editing_hint = !app.seedfix_editing_hint;
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.seedfix_eleven_buf.zeroize();
                app.seedfix_eleven_buf.clear();
                app.seedfix_hint_buf.zeroize();
                app.seedfix_hint_buf.clear();
            }
            KeyCode::Backspace => {
                if app.seedfix_editing_hint && !app.seedfix_wordlist_mode {
                    app.seedfix_hint_buf.pop();
                } else {
                    app.seedfix_eleven_buf.pop();
                }
                if app.seedfix_wordlist_mode {
                    app.wordlist_matches = search_bip39_wordlist(&app.seedfix_eleven_buf, 36);
                }
            }
            KeyCode::Enter => {
                if app.seedfix_wordlist_mode {
                    app.wordlist_matches = search_bip39_wordlist(&app.seedfix_eleven_buf, 36);
                } else {
                    let hint = if app.seedfix_hint_buf.trim().is_empty() {
                        None
                    } else {
                        Some(app.seedfix_hint_buf.trim())
                    };
                    match solve_twelfth_word(&app.seedfix_eleven_buf, hint) {
                        Ok(cands) => {
                            app.set_ok(format!(
                                "Computed all {} valid 12th checksum words (<50us).",
                                cands.len()
                            ));
                            app.seedfix_candidates = cands;
                        }
                        Err(e) => app.set_err(e.to_string()),
                    }
                }
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                if app.seedfix_editing_hint && !app.seedfix_wordlist_mode {
                    app.seedfix_hint_buf.push(c);
                } else {
                    app.seedfix_eleven_buf.push(c);
                }
                if app.seedfix_wordlist_mode {
                    app.wordlist_matches = search_bip39_wordlist(&app.seedfix_eleven_buf, 36);
                }
            }
            _ => {}
        },
    }

    false
}

fn handle_paste_event(app: &mut AppState, raw: String) {
    let mut raw = raw;
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    raw.zeroize();
    let single_line = || -> String {
        normalized
            .chars()
            .map(|c| if c == '\n' || c == '\t' { ' ' } else { c })
            .filter(|c| !c.is_control())
            .collect()
    };
    let multi_line = || -> String {
        normalized
            .chars()
            .filter(|&c| c == '\n' || c == '\t' || !c.is_control())
            .collect()
    };

    match app.tab {
        ActiveTab::Intake => match app.intake_method {
            IntakeMethod::Coins | IntakeMethod::Dice => {
                app.tier1_buffer.push_str(&single_line());
            }
            IntakeMethod::ImportOrScan => {
                app.import_buffer.push_str(&multi_line());
            }
            IntakeMethod::ObstacleCourse => {
                app.set_err(
                    "Paste blocked in Tier 2 Obstacle Course: human keystroke timing is required.",
                );
            }
            IntakeMethod::Presets => {}
        },
        ActiveTab::Psbt => {
            app.psbt_buffer.push_str(&single_line());
            app.psbt_inspection = None;
            app.signed_psbt = None;
            app.show_signed_psbt_qr = false;
            app.set_ok("Pasted PSBT into buffer - press Enter to inspect.");
        }
        ActiveTab::PipeK1 => {
            if app.pipek1_verify_mode {
                match app.pipek1_focus {
                    1 => app.pipek1_sig_buffer.push_str(&multi_line()),
                    2 => app.pipek1_expected_pub_buf.push_str(single_line().trim()),
                    _ => app.pipek1_msg_buffer.push_str(&multi_line()),
                }
            } else {
                app.pipek1_msg_buffer.push_str(&multi_line());
            }
        }
        ActiveTab::Estate => {
            if app.estate_editing_stamp && !app.estate_unlock_mode {
                app.estate_stamp_buf.push_str(single_line().trim());
            } else {
                app.estate_passphrase_buf.push_str(&single_line());
            }
        }
        ActiveTab::SeedFix => {
            if app.seedfix_editing_hint && !app.seedfix_wordlist_mode {
                app.seedfix_hint_buf.push_str(single_line().trim());
            } else {
                app.seedfix_eleven_buf.push_str(&single_line());
                if app.seedfix_wordlist_mode {
                    app.wordlist_matches = search_bip39_wordlist(&app.seedfix_eleven_buf, 36);
                }
            }
        }
        ActiveTab::Wallet | ActiveTab::Bip85 => {}
    }
}

fn draw_ui(f: &mut Frame<'_>, app: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(f.area());

    let xfp_tag = app
        .wallet
        .as_ref()
        .map(|w| format!("XFP:{}", w.fingerprint))
        .unwrap_or_else(|| "NO-WALLET".into());

    let titles: Vec<Line<'_>> = ActiveTab::ALL
        .iter()
        .map(|t| Line::from(Span::raw(t.title())))
        .collect();
    let header = Tabs::new(titles)
        .select(app.tab as usize)
        .block(Block::default().borders(Borders::ALL).title(format!(
            " SubZero v{SUBZERO_VERSION} | {SUBZERO_NETWORK} | [{xfp_tag}] | [{}] ",
            app.hardening_badge
        )))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(header, chunks[0]);

    match app.tab {
        ActiveTab::Intake => draw_intake(f, chunks[1], app),
        ActiveTab::Wallet => draw_wallet(f, chunks[1], app),
        ActiveTab::Bip85 => draw_bip85(f, chunks[1], app),
        ActiveTab::Psbt => draw_psbt(f, chunks[1], app),
        ActiveTab::PipeK1 => draw_pipek1(f, chunks[1], app),
        ActiveTab::Estate => draw_estate(f, chunks[1], app),
        ActiveTab::SeedFix => draw_seedfix(f, chunks[1], app),
    }

    let status_style = if app.status_is_error {
        Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::LightGreen)
    };
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(&app.status_line, status_style),
        Span::raw("  |  F1..F7/Tab: Switch  |  Esc x2 / Ctrl+W: Amnesic RAM Scrub & Exit"),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, chunks[2]);
}

fn draw_intake(f: &mut Frame<'_>, area: Rect, app: &AppState) {
    let sub = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(6)])
        .split(area);

    let mode_spans: Vec<Span<'_>> = IntakeMethod::ALL
        .iter()
        .flat_map(|m| {
            let st = if *m == app.intake_method {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            vec![Span::styled(format!(" {} ", m.label()), st), Span::raw(" ")]
        })
        .collect();
    f.render_widget(
        Paragraph::new(Line::from(mode_spans)).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Intake Mode (Ctrl+N / Ctrl+P or Alt+1..6) "),
        ),
        sub[0],
    );

    let lines: Vec<Line<'static>> = match app.intake_method {
        IntakeMethod::Presets => {
            let mut v = vec![Line::from(Span::styled(
                "PUBLIC TESTNET4 REHEARSAL PRESETS (0 Bits Secret Entropy - Never Use For Real Funds):",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ))];
            for p in list_presets() {
                let marker = if p.id == app.selected_preset { ">>" } else { "  " };
                let style = if p.id == app.selected_preset {
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                v.push(Line::from(Span::styled(
                    format!(
                        "{marker} [{}] XFP {} | {} ({})",
                        p.id, p.expected_fingerprint, p.title, p.live_utxo_note
                    ),
                    style,
                )));
            }
            v.push(Line::from(""));
            v.push(Line::from("Up/Down or 0..9 to select, Enter to load into Cold Vault."));
            v
        }
        IntakeMethod::Coins => {
            let count = app
                .tier1_buffer
                .chars()
                .filter(|c| matches!(c, '0' | '1' | 'h' | 'H' | 't' | 'T'))
                .count();
            vec![
                Line::from(Span::styled(
                    "Tier 1A: Physical Coin Flips [2nd-Device Verifiable - 0% Host Clock Trust]",
                    Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD),
                )),
                Line::from(format!(
                    "Enter 128+ flips using 1/0 or H/T (128 = direct BIP-39 binary; >128 = SHA-256). Count: {count}/128"
                )),
                Line::from(""),
                Line::from(chunk_grouped(&app.tier1_buffer, 4)),
                Line::from(""),
                Line::from("Press Enter to run pre-hash Markov + Chi-squared checks & derive wallet (Ctrl+U clears)."),
            ]
        }
        IntakeMethod::Dice => {
            let count = app
                .tier1_buffer
                .chars()
                .filter(|c| ('1'..='6').contains(c))
                .count();
            vec![
                Line::from(Span::styled(
                    "Tier 1B: Physical 6-Sided Casino Dice [2nd-Device Verifiable - 0% Host Clock Trust]",
                    Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD),
                )),
                Line::from(format!(
                    "Enter 50+ rolls (60 recommended) using digits 1..6. Current count: {count}/60"
                )),
                Line::from(""),
                Line::from(chunk_grouped(&app.tier1_buffer, 5)),
                Line::from(""),
                Line::from("Press Enter to run pre-hash Markov + Chi-squared checks & derive wallet (Ctrl+U clears)."),
            ]
        }
        IntakeMethod::ObstacleCourse => {
            let mut prompt_spans = Vec::new();
            let p_chars: Vec<char> = app.obstacle_prompt.chars().collect();
            let t_chars: Vec<char> = app.obstacle_typed.chars().collect();
            for (i, &pc) in p_chars.iter().enumerate() {
                let st = if i < t_chars.len() {
                    if t_chars[i] == pc {
                        Style::default().fg(Color::Black).bg(Color::Green)
                    } else {
                        Style::default()
                            .fg(Color::White)
                            .bg(Color::Red)
                            .add_modifier(Modifier::BOLD)
                    }
                } else if i == t_chars.len() {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                };
                prompt_spans.push(Span::styled(pc.to_string(), st));
            }
            let bits = app
                .obstacle_health
                .as_ref()
                .map(|h| h.estimated_min_entropy_bits)
                .unwrap_or(0.0);
            let backspaces = app
                .obstacle_health
                .as_ref()
                .map(|h| h.backspace_events)
                .unwrap_or(0);
            vec![
                Line::from(Span::styled(
                    "Tier 2: Cooperative 200-Char Cross-Row Obstacle Course [Unclamped Host Clock Required]",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                )),
                Line::from(
                    "We are on the same team: transcribe accurately! Red typos lock forward progress until fixed with Backspace,",
                ),
                Line::from(format!(
                    "naturally pacing your hands and adding high-entropy recovery jitter. Typed: {}/{} | Backspaces: {} | 90B Bits: {:.1}/{:.0}",
                    t_chars.len(),
                    OBSTACLE_COURSE_LEN,
                    backspaces,
                    bits,
                    MIN_TIER2_ENTROPY_BITS
                )),
                Line::from(""),
                Line::from(prompt_spans),
                Line::from(""),
                Line::from("When 200/200 green & >=192 bits, press Enter to derive wallet (Ctrl+R new round)."),
            ]
        }
        IntakeMethod::ImportOrScan => vec![
            Line::from(Span::styled(
                "Offline Wallet Import / V4L2 Optical QR Scan",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )),
            Line::from(
                "Paste 12/24 BIP-39 words, 4-letter punch prefixes, CompactSeedQR digits, 32-char TRNG hex, or Watch-Only wpkh/tr/vpub:",
            ),
            Line::from("(Press Ctrl+S to scan from USB webcam via V4L2 + pure-Rust rqrr, Enter to import, Ctrl+U to clear)"),
            Line::from(""),
            Line::from(app.import_buffer.clone()),
        ],
    };

    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL)),
        sub[1],
    );
}

fn draw_wallet(f: &mut Frame<'_>, area: Rect, app: &AppState) {
    let Some(ref w) = app.wallet else {
        f.render_widget(
            Paragraph::new("No wallet loaded. Use F1 (Intake & Entropy) to load a preset or derive a seed.")
                .block(Block::default().borders(Borders::ALL).title(" Watch-Only & Addresses ")),
            area,
        );
        return;
    };

    if app.show_wallet_qr {
        let payload = match app.qr_mode {
            TuiQrMode::BbqrAnimated => app
                .bbqr_descriptor_parts
                .get(app.anim_frame % app.bbqr_descriptor_parts.len().max(1))
                .cloned()
                .unwrap_or_else(|| w.wpkh_descriptor.clone()),
            TuiQrMode::StaticWpkh => w.wpkh_descriptor.clone(),
            TuiQrMode::StaticVpub => w.bip84_vpub_slip132.clone(),
            TuiQrMode::StaticTaproot => w
                .tr_descriptor
                .clone()
                .unwrap_or_else(|| w.wpkh_descriptor.clone()),
        };
        let mut lines = vec![Line::from(Span::styled(
            format!("{}  (Ctrl+Q next mode | Ctrl+X close QR)", app.qr_mode.title()),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ))];
        match render_console_qr_lines(&payload) {
            Ok(qr_lines) => lines.extend(qr_lines),
            Err(e) => lines.push(Line::from(format!("QR error: {e}"))),
        }
        f.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title(" Airgap Watch-Only QR ")),
            area,
        );
        return;
    }

    let mut lines = vec![
        Line::from(Span::styled(
            format!("TRUST TIER: {}", w.trust_badge),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            "Master XFP: [{}]  |  Source: {}  |  {}",
            w.fingerprint, w.entropy_label, w.audit_summary
        )),
        Line::from(format!("BIP-84 wpkh: {}", w.wpkh_descriptor)),
        Line::from(format!("SLIP-132 vpub: {}", w.bip84_vpub_slip132)),
    ];
    if let Some(ref tr) = w.tr_descriptor {
        lines.push(Line::from(format!("BIP-86 tr:   {tr}")));
    }
    if app.reveal_secrets {
        if let Some(ref m) = w.mnemonic {
            lines.push(Line::from(Span::styled(
                format!("SECRET MNEMONIC: {m}"),
                Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
            )));
        }
    } else if w.mnemonic.is_some() {
        lines.push(Line::from(
            "Secret Mnemonic: [REDACTED - press Ctrl+V to toggle reveal | Ctrl+Q show Watch-Only QR]",
        ));
    }

    let list = match app.addr_chain {
        AddressChainView::Bip84Receive => &w.receive_addresses,
        AddressChainView::Bip84Change => &w.change_addresses,
        AddressChainView::Bip86Taproot => &w.tr_receive_addresses,
    };
    let page_size = 10usize;
    let max_page = list.len().saturating_sub(1) / page_size;
    let page = app.addr_page.min(max_page);
    let start = page * page_size;
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!(
            "{} - Page {}/{} (']' switch chain, Up/Down page, Ctrl+Q QR):",
            app.addr_chain.label(),
            page + 1,
            max_page + 1
        ),
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )));
    for (idx, addr) in list.iter().enumerate().skip(start).take(page_size) {
        lines.push(Line::from(format!("  #{idx:02}: {addr}")));
    }

    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" Watch-Only & Addresses ")),
        area,
    );
}

fn draw_bip85(f: &mut Frame<'_>, area: Rect, app: &AppState) {
    if app.bip85_children.is_empty() {
        f.render_widget(
            Paragraph::new("Load a private mnemonic wallet in F1 first to derive BIP-85 child vaults.")
                .block(Block::default().borders(Borders::ALL).title(" BIP-85 Child Vaults ")),
            area,
        );
        return;
    }
    let mut lines = vec![
        Line::from("Deterministic BIP-85 Child Vaults (Up/Down select, Enter pivot into Index 1..4, Ctrl+V reveal, Ctrl+B Master):"),
        Line::from(""),
    ];
    for (i, child) in app.bip85_children.iter().enumerate() {
        let sel = if i == app.selected_bip85_idx { ">>" } else { "  " };
        let pub_sum = app.bip85_public.get(i);
        let warn = if child.index == 0 {
            " [ESTATE AES PASSPHRASE ONLY - NEVER FUND ON-CHAIN]"
        } else {
            ""
        };
        let st = if i == app.selected_bip85_idx {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(
            format!("{sel} Index {} ({}) - {}{warn}", child.index, child.path, child.label),
            st,
        )));
        if let Some(ps) = pub_sum {
            lines.push(Line::from(format!(
                "     XFP [{}] | 0/0: {} | 1/0: {}",
                ps.fingerprint, ps.first_receive_address, ps.first_change_address
            )));
        }
        if app.reveal_secrets {
            lines.push(Line::from(Span::styled(
                format!("     Words: {}", child.mnemonic),
                Style::default().fg(Color::LightRed),
            )));
        }
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" BIP-85 Child Vaults ")),
        area,
    );
}

fn draw_psbt(f: &mut Frame<'_>, area: Rect, app: &AppState) {
    if app.show_signed_psbt_qr {
        if let Some(ref art) = app.signed_psbt {
            let part = &art.bbqr_parts[app.anim_frame % art.bbqr_parts.len().max(1)];
            let mut lines = vec![Line::from(Span::styled(
                format!(
                    "Signed PSBT Coinkite BBQr Frame {}/{} | TXID {} (Ctrl+Q return to audit details)",
                    (app.anim_frame % art.bbqr_parts.len().max(1)) + 1,
                    art.bbqr_parts.len(),
                    art.txid
                ),
                Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD),
            ))];
            if let Ok(qr) = render_console_qr_lines(part) {
                lines.extend(qr);
            }
            f.render_widget(
                Paragraph::new(lines)
                    .block(Block::default().borders(Borders::ALL).title(" Signed PSBT BBQr ")),
                area,
            );
            return;
        }
    }

    let char_count = app.psbt_buffer.chars().count();
    let preview = if char_count > 96 {
        format!("{}...", app.psbt_buffer.chars().take(96).collect::<String>())
    } else {
        app.psbt_buffer.clone()
    };
    let mut lines = vec![
        Line::from("Paste Base64/Hex PSBT + Enter to audit | Ctrl+S V4L2 camera scan | Ctrl+G Sign | Ctrl+Q BBQr | Ctrl+U Clear:"),
        Line::from(format!("Input buffer ({char_count} chars): {preview}")),
        Line::from(""),
    ];

    if let Some(ref insp) = app.psbt_inspection {
        lines.push(Line::from(Span::styled(
            format!(
                "TXID: {} | Net External Spend: {} sats | Fee: {} sats ({:.2} sat/vB)",
                insp.txid,
                insp.net_external_spend_sat,
                insp.fee_sat.unwrap_or(0),
                insp.fee_rate_sat_vb.unwrap_or(0.0)
            ),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )));
        for fb in &insp.fatal_blocks {
            lines.push(Line::from(Span::styled(
                format!("  [FATAL BLOCK] {fb}"),
                Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
            )));
        }
        for w in &insp.warnings {
            lines.push(Line::from(Span::styled(
                format!("  [WARNING] {w}"),
                Style::default().fg(Color::Yellow),
            )));
        }
        for inp in &insp.inputs {
            lines.push(Line::from(format!(
                "  IN #{}: {} | {} sats | ours={} {:?}",
                inp.index,
                inp.outpoint,
                inp.amount_sat.unwrap_or(0),
                inp.is_ours,
                inp.verified_path
            )));
        }
        for out in &insp.outputs {
            let badge = if out.is_verified_change {
                format!("VERIFIED SELF-CHANGE ({})", out.verified_path.as_deref().unwrap_or(""))
            } else if out.is_verified_self_receive {
                format!("VERIFIED SELF-RECEIVE ({})", out.verified_path.as_deref().unwrap_or(""))
            } else {
                "EXTERNAL RECIPIENT".into()
            };
            let color = if out.is_verified_change || out.is_verified_self_receive {
                Color::LightGreen
            } else {
                Color::Yellow
            };
            lines.push(Line::from(Span::styled(
                format!("  OUT #{}: {} sats -> {} [{}]", out.index, out.amount_sat, out.address_chunked, badge),
                Style::default().fg(color),
            )));
        }
    }
    if let Some(ref signed) = app.signed_psbt {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("SIGNED PSBT BASE64: {}", signed.signed_psbt_base64),
            Style::default().fg(Color::LightGreen),
        )));
    }

    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" PSBT Audit & Airgap Signer ")),
        area,
    );
}

fn draw_pipek1(f: &mut Frame<'_>, area: Rect, app: &AppState) {
    if app.show_pipek1_qr {
        if let Some(ref art) = app.pipek1_signed {
            let mut lines = vec![Line::from("pipe-k1 Detached Signature QR (Ctrl+Q to return):")];
            if let Ok(qr) = render_console_qr_lines(&art.armored) {
                lines.extend(qr);
            }
            f.render_widget(
                Paragraph::new(lines).block(Block::default().borders(Borders::ALL)),
                area,
            );
            return;
        }
    }

    let mut lines = vec![Line::from(format!(
        "Mode: {} (Ctrl+T Sign/Verify | Alt+[ / Alt+] child index {} | Ctrl+J newline | Ctrl+Q QR | Ctrl+U clear)",
        if app.pipek1_verify_mode {
            "VERIFY DETACHED SIGNATURE"
        } else {
            "SIGN MESSAGE / SHA256SUMS"
        },
        app.pipek1_index
    ))];

    if let Some(ref pk) = app.pipek1_pub {
        lines.push(Line::from(Span::styled(
            format!("Active Identity ({}): {}  (hex: {})", pk.derivation_path, pk.npub, pk.pubkey_hex),
            Style::default().fg(Color::Cyan),
        )));
    }
    lines.push(Line::from(""));
    let f0 = if !app.pipek1_verify_mode || app.pipek1_focus == 0 { ">> " } else { "   " };
    lines.push(Line::from(format!("{f0}[1] Message UTF-8: {}", app.pipek1_msg_buffer)));
    if app.pipek1_verify_mode {
        let f1 = if app.pipek1_focus == 1 { ">> " } else { "   " };
        let f2 = if app.pipek1_focus == 2 { ">> " } else { "   " };
        lines.push(Line::from(format!(
            "{f1}[2] Detached .pk1 Signature (Ctrl+F cycle field): {}",
            app.pipek1_sig_buffer
        )));
        lines.push(Line::from(format!(
            "{f2}[3] Expected Pubkey (npub1... or 64-hex, optional pin): {}",
            app.pipek1_expected_pub_buf
        )));
        if let Some(ref res) = app.pipek1_verify_result {
            lines.push(Line::from(Span::styled(
                res.clone(),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )));
        }
    } else if let Some(ref art) = app.pipek1_signed {
        lines.push(Line::from(""));
        for l in art.armored.lines() {
            lines.push(Line::from(Span::styled(
                l.to_string(),
                Style::default().fg(Color::LightGreen),
            )));
        }
    }

    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" pipe-k1 (m/83696968'/128002') ")),
        area,
    );
}

fn draw_estate(f: &mut Frame<'_>, area: Rect, app: &AppState) {
    let lines = vec![
        Line::from(Span::styled(
            format!(
                "Partition 2 (LABEL=SUBZERO_EST) - Mode: {} (Ctrl+T toggle Seal vs Unlock)",
                if app.estate_unlock_mode {
                    "UNLOCK EXISTING VAULT.JSON"
                } else {
                    "ATOMIC VFAT SEAL (SIV AES-256-GCM, 600,000 PBKDF2 ROUNDS)"
                }
            ),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from("Ctrl+D fills BIP-85 Index 0 Decoupled Passphrase | Ctrl+F switches snapshot stamp field | Enter executes:"),
        Line::from(""),
        Line::from(format!(
            "12-Word Decoupled Estate Passphrase: {}",
            if app.reveal_secrets {
                app.estate_passphrase_buf.clone()
            } else {
                format!("[{} chars entered - press F2/F3 Ctrl+V to reveal]", app.estate_passphrase_buf.len())
            }
        )),
        Line::from(format!("VFAT Snapshot Stamp: {}", app.estate_stamp_buf)),
        Line::from(""),
        Line::from("Writes atomically (.tmp -> fsync -> rename): vault.json, vault_<stamp>.json, decrypt.html, README.txt, SHA256SUMS."),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" Estate USB Partition 2 ")),
        area,
    );
}

fn draw_seedfix(f: &mut Frame<'_>, area: Rect, app: &AppState) {
    let mut lines = vec![Line::from(format!(
        "Mode: {} (Ctrl+T toggle SeedFix 12th-Word Solver vs 2048-Word Reference | Ctrl+U clear)",
        if app.seedfix_wordlist_mode {
            "BIP-39 2048-WORD PREFIX / INDEX SEARCH"
        } else {
            "SEEDFIX 128-CANDIDATE 12TH CHECKSUM WORD SOLVER"
        }
    ))];

    if app.seedfix_wordlist_mode {
        lines.push(Line::from(format!("Query: {}", app.seedfix_eleven_buf)));
        lines.push(Line::from(""));
        let formatted: Vec<String> = app
            .wordlist_matches
            .iter()
            .map(|e| format!("#{} {}", e.seedqr_code, e.word))
            .collect();
        for row in formatted.chunks(6) {
            lines.push(Line::from(row.join("   ")));
        }
    } else {
        lines.push(Line::from(format!("First 11 Words: {}", app.seedfix_eleven_buf)));
        lines.push(Line::from(format!(
            "Optional Damaged 12th Hint (Ctrl+F focus={}): {}",
            app.seedfix_editing_hint, app.seedfix_hint_buf
        )));
        lines.push(Line::from("Press Enter to compute all 128 valid checksum words:"));
        let top: Vec<String> = app
            .seedfix_candidates
            .iter()
            .take(36)
            .map(|c| format!("{} (#{:04}, d={})", c.twelfth_word, c.word_index, c.distance))
            .collect();
        for row in top.chunks(4) {
            lines.push(Line::from(row.join("   ")));
        }
    }

    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" SeedFix & BIP-39 Wordlist ")),
        area,
    );
}

fn run_tui(hardening_badge: String) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(
        stdout,
        EnterAlternateScreen,
        EnableBracketedPaste,
        Clear(ClearType::All)
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = AppState::new(hardening_badge);

    loop {
        poll_camera_events(&mut app);
        if app.last_anim_tick.elapsed() >= Duration::from_millis(400) {
            app.anim_frame = app.anim_frame.wrapping_add(1);
            app.last_anim_tick = Instant::now();
        }

        terminal.draw(|f| draw_ui(f, &app))?;

        if event::poll(Duration::from_millis(80))? {
            match event::read()? {
                Event::Key(key) => {
                    if handle_key_event(&mut app, key) {
                        break;
                    }
                }
                Event::Paste(pasted) => handle_paste_event(&mut app, pasted),
                _ => {}
            }
        }
    }

    // Amnesic wipe BEFORE restoring terminal and returning `0` to `launch.sh` (`memtester-static` RAM scrub)
    app.zeroize_sensitive();
    let _ = terminal.clear();
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableBracketedPaste,
        Clear(ClearType::All),
        Clear(ClearType::Purge),
        LeaveAlternateScreen
    )?;
    let _ = terminal.show_cursor();
    let _ = io::stdout().write_all(b"\x1b[2J\x1b[3J\x1b[H");
    let _ = io::stdout().flush();
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("subzero {SUBZERO_VERSION} ({SUBZERO_NETWORK})");
        return;
    }
    if args.iter().any(|a| a == "--self-test") {
        if let Err(e) = run_self_test() {
            eprintln!("SELF-TEST FAILED: {e}");
            std::process::exit(1);
        }
        return;
    }

    let badge = harden_linux_process();
    if let Err(e) = run_tui(badge) {
        eprintln!("SubZero TUI error: {e}");
        std::process::exit(1);
    }
}
