use std::time::Duration;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};
use zeroize::Zeroize;
use sha2::{Digest, Sha256};
use crate::crypto::{
    self, has_repetitive_substrings, run_markov_audit, run_chi_squared_audit, Bip85Child,
    DecryptedVaultPayload, GeneratedSeed, decrypt_vault_json,
    process_physical_entropy, derive_bip85_children, mnemonic_to_compact_seed_qr,
    compact_seed_qr_to_mnemonic, get_descriptor_checksum,
};
use crate::qr::{
    create_bbqr_frames, render_full_block_qr, QrMode,
};
use crate::seedfix::{search_wordlist, solve_twelfth_word};
use crate::storage::{
    locate_estate_partition, write_estate_partition, read_estate_partition, export_descriptor_external_usb,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    RoleSelect,
    MasterSeed,
    Passphrase,
    Descriptor,
    VpubQr,
    FaucetQr,
    Addresses,
    Bip85Children,
    EstateProvisioner,
    VaultUnlock,
    SeedFix,
    WordlistInspector,
    DrillGuide,
    Provenance,
}

impl Page {
    pub const ALL: [Page; 14] = [
        Page::RoleSelect,
        Page::MasterSeed,
        Page::Passphrase,
        Page::Descriptor,
        Page::VpubQr,
        Page::FaucetQr,
        Page::Addresses,
        Page::Bip85Children,
        Page::EstateProvisioner,
        Page::VaultUnlock,
        Page::SeedFix,
        Page::WordlistInspector,
        Page::DrillGuide,
        Page::Provenance,
    ];

    #[allow(dead_code)]
    pub fn title(&self) -> &'static str {
        match self {
            Page::RoleSelect => "Tab 0. Welcome / Operator Role Selection",
            Page::MasterSeed => "Tab 1. Master Mnemonic",
            Page::Passphrase => "Tab 2. Decoupled Passphrase",
            Page::Descriptor => "Tab 3. Output Descriptor",
            Page::VpubQr => "Tab 4. Watch-Only QR",
            Page::FaucetQr => "Tab 5. Faucet QR",
            Page::Addresses => "Tab 6. Receive Addresses",
            Page::Bip85Children => "Tab 7. BIP-85 Heir Keys",
            Page::EstateProvisioner => "Tab 8. Benefactor Estate Vault Provisioner",
            Page::VaultUnlock => "Tab 9. Unlock & Decrypt Estate Vault",
            Page::SeedFix => "Tab 10. SeedFix Recovery Tool",
            Page::WordlistInspector => "Tab 11. BIP-39 Canonical English Wordlist Inspector",
            Page::DrillGuide => "Tab 12. Metal Punch Grid",
            Page::Provenance => "Tab 13. Provenance & Spec",
        }
    }

    #[allow(dead_code)]
    pub fn short_title(&self) -> &'static str {
        match self {
            Page::RoleSelect => "Role Select",
            Page::MasterSeed => "Master Seed",
            Page::Passphrase => "Passphrase",
            Page::Descriptor => "Descriptor",
            Page::VpubQr => "VPUB QR",
            Page::FaucetQr => "Faucet QR",
            Page::Addresses => "Addresses",
            Page::Bip85Children => "BIP-85 Keys",
            Page::EstateProvisioner => "Provisioner",
            Page::VaultUnlock => "Vault Unlock",
            Page::SeedFix => "SeedFix",
            Page::WordlistInspector => "Wordlist",
            Page::DrillGuide => "Metal Grid",
            Page::Provenance => "Provenance",
        }
    }

    pub fn page_num(&self) -> usize {
        Page::ALL.iter().position(|p| *p == *self).unwrap_or(0)
    }

    pub fn next(&self) -> Self {
        let idx = Page::ALL.iter().position(|p| *p == *self).unwrap_or(0);
        Page::ALL[(idx + 1) % Page::ALL.len()]
    }

    pub fn prev(&self) -> Self {
        let idx = Page::ALL.iter().position(|p| *p == *self).unwrap_or(0);
        Page::ALL[(idx + Page::ALL.len() - 1) % Page::ALL.len()]
    }
}

pub struct AppState {
    pub current_page: Page,
    pub seed: Option<GeneratedSeed>,
    pub decoupled_passphrase: Option<Bip85Child>,
    pub bip85_children: Vec<Bip85Child>,
    pub build_timestamp: String,
    pub git_commit: String,
    pub entropy_input: String,
    pub is_entering_entropy: bool,
    pub address_page_offset: usize,
    pub heir_page_offset: usize,
    pub estate_write_status: String,
    pub seedfix_input: String,
    pub wordlist_query: String,
    pub vault_passphrase_input: String,
    pub decrypted_vault: Option<DecryptedVaultPayload>,
    pub vault_status_msg: String,
    pub status_message: String,
    pub qr_mode: QrMode,
    pub bbqr_frame_index: usize,
    pub external_export_status: String,
    pub is_harvesting_jitter: bool,
    pub jitter_samples: Vec<(char, u64)>,
    pub last_jitter_instant: Option<std::time::Instant>,
    pub is_selecting_test_vector: bool,
    pub is_importing_mnemonic: bool,
    pub mnemonic_import_input: String,
    pub wipe_confirmation_instant: Option<std::time::Instant>,
    pub pending_exit_instant: Option<std::time::Instant>,
    pub vault_mask_passphrase: bool,
    pub last_activity_instant: std::time::Instant,
    pub vault_unlocked_instant: Option<std::time::Instant>,
}

impl AppState {
    pub fn new(build_timestamp: String, git_commit: String) -> Self {
        Self {
            current_page: Page::RoleSelect,
            seed: None,
            decoupled_passphrase: None,
            bip85_children: Vec::new(),
            build_timestamp,
            git_commit,
            entropy_input: String::new(),
            is_entering_entropy: false,
            address_page_offset: 0,
            heir_page_offset: 0,
            estate_write_status: "Press [P] to provision Partition 2 (SUBZERO_EST).".into(),
            seedfix_input: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            wordlist_query: String::new(),
            vault_passphrase_input: String::new(),
            decrypted_vault: None,
            vault_status_msg: "Enter 12-word passphrase or 'test0'..'test9' test vectors.".into(),
            status_message: "[1] Benefactor  [2] Heir  [3] Tools  [Tab] Nav".into(),
            qr_mode: QrMode::BbqrAnimated,
            bbqr_frame_index: 0,
            external_export_status: "Press [E] to export descriptor to separate USB drive.".into(),
            is_harvesting_jitter: false,
            jitter_samples: Vec::new(),
            last_jitter_instant: None,
            is_selecting_test_vector: false,
            is_importing_mnemonic: false,
            mnemonic_import_input: String::new(),
            wipe_confirmation_instant: None,
            pending_exit_instant: None,
            vault_mask_passphrase: false,
            last_activity_instant: std::time::Instant::now(),
            vault_unlocked_instant: None,
        }
    }
}

impl Drop for AppState {
    fn drop(&mut self) {
        self.wipe_memory();
    }
}

impl AppState {
    pub fn wipe_memory(&mut self) {
        self.seed = None;
        self.decoupled_passphrase = None;
        self.bip85_children.clear();
        self.entropy_input.zeroize();
        self.entropy_input.clear();
        self.is_entering_entropy = false;
        self.is_importing_mnemonic = false;
        self.mnemonic_import_input.zeroize();
        self.mnemonic_import_input.clear();
        self.is_harvesting_jitter = false;
        for s in &mut self.jitter_samples {
            s.0 = '\0';
            s.1.zeroize();
        }
        self.jitter_samples.clear();
        self.last_jitter_instant = None;
        self.decrypted_vault = None;
        self.vault_unlocked_instant = None;
        self.vault_passphrase_input.zeroize();
        self.vault_passphrase_input.clear();
        self.vault_mask_passphrase = false;
        self.seedfix_input.zeroize();
        self.seedfix_input.clear();
        self.vault_status_msg = "Enter 12-word passphrase or 'test0'..'test9' / 't0'..'t9'.".into();
        self.address_page_offset = 0;
        self.heir_page_offset = 0;
        self.estate_write_status = "Press [P] to provision Partition 2 (SUBZERO_EST).".into();
        self.external_export_status = "Press [E] to export descriptor to separate USB drive.".into();
        self.wipe_confirmation_instant = Some(std::time::Instant::now());
        self.status_message = "[✓] MEMORY WIPED: All private keys and entropy zeroized in RAM.".into();
    }

    pub fn set_seed(&mut self, seed: GeneratedSeed, mut children: Vec<Bip85Child>) {
        if !children.is_empty() && children[0].index == 0 {
            self.decoupled_passphrase = Some(children.remove(0));
        }
        self.bip85_children = children;
        self.seed = Some(seed);
        self.is_entering_entropy = false;
        self.is_importing_mnemonic = false;
        self.mnemonic_import_input.zeroize();
        self.mnemonic_import_input.clear();
        self.status_message = "Keys generated securely in amnesic memory.".into();
    }

    pub fn push_entropy_char(&mut self, c: char) {
        if self.entropy_input.len() < 256 {
            self.entropy_input.push(c);
            self.update_entropy_status();
        }
    }

    pub fn pop_entropy_char(&mut self) {
        self.entropy_input.pop();
        self.update_entropy_status();
    }

    pub fn set_entropy_input(&mut self, input: &str) {
        self.entropy_input = input.to_string();
        self.update_entropy_status();
    }

    pub fn update_entropy_status(&mut self) {
        let len = self.entropy_input.len();
        if len == 0 {
            self.status_message = "Enter coin flips (0/1) or dice rolls (1-6)...".into();
            return;
        }

        let is_bin = self.entropy_input.chars().all(|c| c == '0' || c == '1');
        let is_dice = self.entropy_input.chars().all(|c| ('1'..='6').contains(&c));

        if is_bin {
            let markov = run_markov_audit(&self.entropy_input);
            let (chi2_pass, _, _) = run_chi_squared_audit(&self.entropy_input);
            let repeats = has_repetitive_substrings(&self.entropy_input, 3, 6);
            if len >= 128 && markov.passed && chi2_pass && !repeats {
                self.status_message = "Entropy 128-bit threshold valid! Press [ENTER] to derive keys.".into();
            } else if len >= 128 {
                self.status_message = "[BLOCKED] 128 bits met, but failed Markov, Chi-squared, or repeat checks!".into();
            } else {
                self.status_message = format!("Collecting coin flips: {}/128 bits...", len);
            }
        } else if is_dice {
            let markov = run_markov_audit(&self.entropy_input);
            let (chi2_pass, _, _) = run_chi_squared_audit(&self.entropy_input);
            let repeats = has_repetitive_substrings(&self.entropy_input, 3, 6);
            if len >= 50 && markov.passed && chi2_pass && !repeats {
                self.status_message = format!("Dice entropy valid ({}/50 rolls)! Tip: Rolling multiple dice blends out individual defect bias. Press [ENTER] to derive.", len);
            } else if len >= 50 {
                self.status_message = "[BLOCKED] 50 rolls met, but failed Markov, Chi-squared, or repeat checks!".into();
            } else {
                self.status_message = format!("Collecting dice rolls: {}/50 rolls (Tip: Roll 2-5 dice together to soften physical bias)...", len);
            }
        } else {
            self.status_message = "Mixed entropy input detected. Use only 0/1 or 1-6.".into();
        }
    }

    pub fn check_inactivity_autolock(&mut self) {
        if self.decrypted_vault.is_some() {
            // 30 minutes = 1,800 seconds of inactivity
            if self.last_activity_instant.elapsed() >= std::time::Duration::from_secs(1800) {
                self.decrypted_vault = None;
                self.vault_unlocked_instant = None;
                self.vault_status_msg = "[!] Auto-Lock: Vault locked after 30 minutes of inactivity to protect amnesic RAM.".into();
            }
        }
    }

    pub fn write_estate_vault(&mut self) {
        let seed = match &self.seed {
            Some(s) => s,
            None => {
                self.estate_write_status = "[!] Error: Generate master seed first before exporting vault.".into();
                return;
            }
        };
        let pass = match &self.decoupled_passphrase {
            Some(p) => &p.mnemonic,
            None => {
                self.estate_write_status = "[!] Error: Decoupled estate passphrase missing.".into();
                return;
            }
        };

        let payload = DecryptedVaultPayload {
            version: "1.0.0".into(),
            created_utc: "2026-09-04T05:00:00Z".into(),
            master_root_mnemonic: seed.mnemonic.clone(),
            descriptor: seed.descriptor.clone(),
            heir_treasuries: self.bip85_children.clone(),
        };

        self.estate_write_status = "Writing encrypted vault to Partition 2 (SUBZERO_EST)...".into();
        match write_estate_partition(&payload, pass, &self.build_timestamp) {
            Ok(msg) => {
                self.estate_write_status = format!("[✓] SUCCESS: {msg}");
                self.status_message = "Partition 2 provisioned successfully with encrypted vault.".into();
            }
            Err(err) => {
                self.estate_write_status = format!("[!] FAILED: {err}");
                self.status_message = "Partition 2 write error.".into();
            }
        }
    }

    pub fn export_external_usb(&mut self) {
        let seed = match &self.seed {
            Some(s) => s,
            None => {
                self.external_export_status = "[!] Error: Generate master seed first.".into();
                return;
            }
        };

        self.external_export_status = "Scanning for external USB drive (not SubZero media)...".into();
        match export_descriptor_external_usb(
            &seed.descriptor,
            &seed.fingerprint,
            &seed.vpub,
            &seed.addresses,
            &self.bip85_children,
        ) {
            Ok(msg) => {
                self.external_export_status = format!("[✓] {msg}");
                self.status_message = "[✓] Public airgap suite exported to external USB.".into();
            }
            Err(err) => {
                self.external_export_status = format!("[!] {err}");
                self.status_message = "External USB export failed.".into();
            }
        }
    }

    pub fn attempt_vault_decrypt(&mut self) {
        let input = self.vault_passphrase_input.trim();
        if input.is_empty() {
            self.vault_status_msg = "[!] Passphrase cannot be empty.".into();
            return;
        }

        // 1. Resolve test vector shortcuts ('t0'..'t9' or 'test0'..'test9' or 'test')
        let test_vec_id: Option<u8> = if input.len() == 2 && (input.starts_with('t') || input.starts_with('T')) {
            input.chars().nth(1).and_then(|c| c.to_digit(10).map(|d| d as u8))
        } else if (input.starts_with("test") || input.starts_with("TEST")) && input.len() >= 5 {
            input[4..].chars().next().and_then(|c| c.to_digit(10).map(|d| d as u8))
        } else if input.eq_ignore_ascii_case("test") {
            Some(0)
        } else {
            None
        };

        if let Some(id) = test_vec_id {
            if let Ok(seed) = process_physical_entropy(&format!("test{}", id)) {
                let mut children = derive_bip85_children(&seed.mnemonic, 20).unwrap_or_default();
                if !children.is_empty() && children[0].index == 0 {
                    children.remove(0);
                }

                let test_payload = DecryptedVaultPayload {
                    version: "1.0.0".into(),
                    created_utc: "2026-09-04T05:00:00Z".into(),
                    master_root_mnemonic: seed.mnemonic.clone(),
                    descriptor: seed.descriptor.clone(),
                    heir_treasuries: children,
                };
                self.decrypted_vault = Some(test_payload);
                self.vault_unlocked_instant = Some(std::time::Instant::now());
                self.last_activity_instant = std::time::Instant::now();
                self.vault_status_msg = format!("[✓] TEST VECTOR {} VAULT DECRYPTED: Master root keys restored in amnesic RAM.", id);
                return;
            }
        }

        // 2. Attempt real decryption against Partition 2 (SUBZERO_EST) if vault.json exists
        match read_estate_partition() {
            Ok(vault_json_str) => {
                match decrypt_vault_json(&vault_json_str, input) {
                    Ok(payload) => {
                        self.decrypted_vault = Some(payload);
                        self.vault_unlocked_instant = Some(std::time::Instant::now());
                        self.last_activity_instant = std::time::Instant::now();
                        self.vault_status_msg = "[✓] VAULT DECRYPTED FROM PARTITION 2: Master root keys restored in amnesic RAM.".into();
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("parse") || err_str.contains("JSON") {
                            self.vault_status_msg = format!("[!] Corrupted vault file: vault.json is damaged or invalid ({}). Please verify media integrity.", e);
                        } else {
                            self.vault_status_msg = format!("[!] Authentication failed: Incorrect passphrase ({}). Please verify your 12 words; funds are safe.", e);
                        }
                    }
                }
            }
            Err(e) => {
                self.vault_status_msg = format!("[!] Partition 2 error: {}. Insert estate USB/SD card.", e);
            }
        }
    }

    pub fn is_test_entropy(&self) -> bool {
        if let Some(ref s) = self.seed {
            s.entropy_type.contains("PRNG") || s.entropy_type.contains("TEST VECTOR") || s.entropy_type.contains("Untrusted")
        } else {
            false
        }
    }
}

pub fn render_app(frame: &mut Frame, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Header Status Line
            Constraint::Min(10),   // Content
            Constraint::Length(3), // Footer / Status Bar & Global Nav (1 line nav, 1 line status with top border)
        ])
        .split(frame.area());

    render_header(frame, chunks[0], state);
    render_content(frame, chunks[1], state);
    render_footer(frame, chunks[2], state);
}

fn render_header(frame: &mut Frame, area: Rect, state: &AppState) {
    let is_narrow = area.width < 120;

    let fp_str = if let Some(ref s) = state.seed {
        if is_narrow {
            format!("[fp:{}]", s.fingerprint)
        } else {
            format!("[Master fp: {}]", s.fingerprint)
        }
    } else {
        if is_narrow {
            "[NO KEYS]".to_string()
        } else {
            "[NO KEYS IN RAM]".to_string()
        }
    };

    let (source_badge, source_style) = if state.is_test_entropy() {
        if is_narrow {
            ("[TEST]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
        } else {
            ("[TEST PRNG]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
        }
    } else if state.seed.is_some() {
        ("[PHYSICAL]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
    } else {
        if is_narrow {
            ("[AWAITING]", Style::default().fg(Color::DarkGray))
        } else {
            ("[AWAITING ENTROPY]", Style::default().fg(Color::DarkGray))
        }
    };

    let net_badge = "[TESTNET4]";
    let sep = " | ";
    let title_text = if is_narrow {
        state.current_page.short_title()
    } else {
        state.current_page.title()
    };

    let line = Line::from(vec![
        Span::styled(format!(" [{}/{}] ", state.current_page.page_num(), Page::ALL.len()), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled(title_text, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw(sep),
        Span::styled(fp_str, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(sep),
        Span::styled(source_badge, source_style),
        Span::raw(sep),
        Span::styled(net_badge, Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
    ]);

    let block = Block::default().borders(Borders::BOTTOM).style(Style::default().fg(Color::Cyan));
    frame.render_widget(Paragraph::new(line).block(block), area);
}

fn render_footer(frame: &mut Frame, area: Rect, state: &AppState) {
    let sub_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(2)])
        .split(area);

    let nav_spans = vec![
        Span::styled("NAV: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled("[Tab/→]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" Next "),
        Span::styled("[Shift+Tab/←]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" Prev "),
        Span::styled("[Home/Esc]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" Tab 0 "),
        Span::styled("[C/D]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw(" Coins/Dice "),
        Span::styled("[T]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Test "),
        Span::styled("[W]", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
        Span::raw(" Wipe "),
        Span::styled("[Q]", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
        Span::raw(" Exit"),
    ];
    let nav_line = Line::from(nav_spans);
    frame.render_widget(Paragraph::new(nav_line), sub_chunks[0]);

    let left_status = Span::styled(
        format!(" [{}] ", state.status_message),
        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
    );

    let right_info = Span::styled(
        format!("BUILD: {} ({}) | TESTNET4 ", state.build_timestamp, state.git_commit),
        Style::default().fg(Color::DarkGray),
    );

    let footer_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(sub_chunks[1]);

    let left_para = Paragraph::new(Line::from(left_status))
        .block(Block::default().borders(Borders::TOP));
    let right_para = Paragraph::new(Line::from(right_info))
        .alignment(Alignment::Right)
        .block(Block::default().borders(Borders::TOP));

    frame.render_widget(left_para, footer_layout[0]);
    frame.render_widget(right_para, footer_layout[1]);
}

fn render_content(frame: &mut Frame, area: Rect, state: &AppState) {
    match state.current_page {
        Page::RoleSelect => render_role_select(frame, area, state),
        Page::MasterSeed => render_master_seed(frame, area, state),
        Page::Passphrase => render_passphrase(frame, area, state),
        Page::Descriptor => render_descriptor(frame, area, state),
        Page::VpubQr => render_vpub_qr(frame, area, state),
        Page::FaucetQr => render_faucet_qr(frame, area, state),
        Page::Addresses => render_addresses(frame, area, state),
        Page::Bip85Children => render_bip85(frame, area, state),
        Page::EstateProvisioner => render_estate_provisioner(frame, area, state),
        Page::VaultUnlock => render_vault_unlock(frame, area, state),
        Page::SeedFix => render_seedfix(frame, area, state),
        Page::WordlistInspector => render_wordlist_inspector(frame, area, state),
        Page::DrillGuide => render_drill_guide(frame, area, state),
        Page::Provenance => render_provenance(frame, area, state),
    }
}

fn render_role_select(frame: &mut Frame, area: Rect, _state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 0. Welcome to SubZero Keyosk — Select Your Operator Role ")
        .style(Style::default().fg(Color::Cyan));

    let mut lines = Vec::new();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  SOVEREIGN BITCOIN COLD STORAGE & ESTATE RECOVERY APPLIANCE",
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from("  Running 100% in volatile temporary memory (RAM). Zero internet access. Zero hard drive writes."));
    lines.push(Line::from(""));
    lines.push(Line::from("  Please select your role to jump directly to your workflow:"));
    lines.push(Line::from(""));

    // Option 1: Benefactor
    lines.push(Line::from(vec![
        Span::styled("  [1] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled("I AM THE BENEFACTOR (VAULT CREATOR)", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from("      • Purpose: I am setting up cold storage, creating private keys on steel,"));
    lines.push(Line::from("        and preparing an encrypted estate recovery package for my heirs."));
    lines.push(Line::from("      • Next Step: Jump to Tab 1 to flip coins or roll dice for master key creation."));
    lines.push(Line::from("      • Action: Press key [1] or press [ENTER]"));
    lines.push(Line::from(""));

    // Option 2: Heir
    lines.push(Line::from(vec![
        Span::styled("  [2] ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled("I AM AN HEIR OR EXECUTOR (ESTATE RECOVERY)", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from("      • Purpose: I received this laptop/media and a 12-word Passphrase from my"));
    lines.push(Line::from("        parent or benefactor, and I need to unlock and recover our family funds."));
    lines.push(Line::from("      • Next Step: Jump directly to Tab 9 (Vault Unlock) to type the 12-word passphrase."));
    lines.push(Line::from("      • Action: Press key [2]"));
    lines.push(Line::from(""));

    // Option 3: Tools
    lines.push(Line::from(vec![
        Span::styled("  [3] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled("EMERGENCY TOOLS & SEED REPAIR (SEEDFIX / WORDLIST)", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from("      • Purpose: I have a damaged or misspelled 12th seed word, or I need to inspect"));
    lines.push(Line::from("        the BIP-39 canonical English dictionary and 4-letter punch codes."));
    lines.push(Line::from("      • Action: Press key [3] to open SeedFix (Tab 10)"));
    lines.push(Line::from(""));

    // Option 4: Ingest Materials
    lines.push(Line::from(vec![
        Span::styled("  [4] ", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
        Span::styled("INGEST EXISTING MATERIALS (12 WORDS / COMPACTSEEDQR / DESCRIPTOR)", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from("      • Purpose: I have an offline 12-word seed phrase, a 48-digit CompactSeedQR string,"));
    lines.push(Line::from("        or a watch-only BIP-380 output descriptor (wpkh/tpub/vpub) to audit in RAM."));
    lines.push(Line::from("      • Next Step: Jump to Tab 1 Ingestion Mode to verify checksums and derive keys."));
    lines.push(Line::from("      • Action: Press key [4] or [I]"));
    lines.push(Line::from(""));

    lines.push(Line::from("  --------------------------------------------------------------------------------"));
    lines.push(Line::from(Span::styled("  QUICK NAVIGATION HINT:", Style::default().fg(Color::White).add_modifier(Modifier::BOLD))));
    lines.push(Line::from("  You can always press [Tab] or [→] to cycle forward through all tabs, or press [Home] or [ESC]"));
    lines.push(Line::from("  to return to this welcome screen. To power off at any time, press [Q]."));

    let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    frame.render_widget(p, area);
}

fn render_master_seed(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 1. BIP-39 Primary Master Secret [TESTNET4 ONLY] ")
        .style(Style::default().fg(Color::White));

    if let Some(ref seed) = state.seed {
        let words: Vec<&str> = seed.mnemonic.split_whitespace().collect();
        let mut lines = Vec::new();

        lines.push(Line::from(""));
        if state.is_test_entropy() {
            lines.push(Line::from(Span::styled(
                "  [! TEST SEED — PREDICTABLE / MOCK ENTROPY — NEVER FUND ON MAINNET]",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "  [✓ PHYSICAL ENTROPY (SHA-256 HASHED) — FOR TESTNET4 USE ONLY]",
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            )));
        }
        lines.push(Line::from(""));

        lines.push(Line::from(vec![
            Span::styled("  12-WORD SEED PHRASE (SPACE-SEPARATED STRING WITH NUMBERING GUIDES):", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]));
        // Two-line layout: line 1 subtle numbers, line 2 space-separated words
        let num_line = words.iter().enumerate().map(|(idx, w)| {
            let width = std::cmp::max(w.len(), 4);
            format!("{:<width$}", format!("#{:02}", idx + 1), width = width)
        }).collect::<Vec<_>>().join(" ");
        let word_line = words.iter().map(|w| {
            let width = std::cmp::max(w.len(), 4);
            format!("{:<width$}", w, width = width)
        }).collect::<Vec<_>>().join(" ");

        lines.push(Line::from(Span::styled(format!("  {}", num_line), Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD))));
        lines.push(Line::from(Span::styled(format!("  {}", word_line), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))));
        lines.push(Line::from(""));

        lines.push(Line::from(vec![
            Span::styled("  METAL PUNCH / COLUMN GUIDANCE: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled("Read Column 1 DOWN (01-06), then Column 2 DOWN (07-12).", Style::default().fg(Color::White)),
        ]));
        lines.push(Line::from("  --------------------------------------------------------------------------"));
        lines.push(Line::from(vec![
            Span::styled(format!("  {:<35}", "COLUMN 1: (Words 01 through 06)"), Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD)),
            Span::styled("COLUMN 2: (Words 07 through 12)", Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::from("  --------------------------------------------------------------------------"));

        for i in 0..6 {
            let w1 = words.get(i).unwrap_or(&"");
            let w2 = words.get(i + 6).unwrap_or(&"");
            let p1 = if w1.len() >= 4 { &w1[..4] } else { w1 }.to_uppercase();
            let p2 = if w2.len() >= 4 { &w2[..4] } else { w2 }.to_uppercase();

            let left = format!("  Word #{:02}: {:<8} [Punch: {:<4}]", i + 1, w1, p1);
            let right = format!("   Word #{:02}: {:<8} [Punch: {:<4}]", i + 7, w2, p2);
            lines.push(Line::from(vec![
                Span::styled(left, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(right, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]));
        }

        lines.push(Line::from("  --------------------------------------------------------------------------"));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::raw("  Master Fingerprint:   "),
            Span::styled(&seed.fingerprint, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("    (BIP-32 root key identifier)"),
        ]));
        if let Ok(cseed_digits) = mnemonic_to_compact_seed_qr(&seed.mnemonic) {
            let chunked: Vec<String> = (0..12).map(|i| cseed_digits[i*4..(i+1)*4].to_string()).collect();
            lines.push(Line::from(vec![
                Span::raw("  CompactSeedQR:        "),
                Span::styled(chunked.join(" "), Style::default().fg(Color::Yellow)),
                Span::raw(" (48-digit numeric)"),
            ]));
        }
        lines.push(Line::from(vec![
            Span::raw("  Entropy Mode:         "),
            Span::styled(&seed.entropy_type, Style::default().fg(Color::Green)),
            Span::raw("   (Raw Coins/Dice -> SHA-256 Hashed)"),
        ]));
        lines.push(Line::from(vec![
            Span::raw("  Protocol Network:     "),
            Span::styled("Bitcoin Testnet4", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
            Span::raw("       (BIP-94, tb1q..., m/84'/1'/0')"),
        ]));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  [!] RECOVERY INVARIANT: Standard BIP-39 requires only the FIRST 4 LETTERS of each word.",
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(Span::styled(
            "  Advance to Tab 2 for the Decoupled Estate Passphrase (BIP-85 Index 0).",
            Style::default().fg(Color::DarkGray),
        )));

        let p = Paragraph::new(lines).block(block);
        frame.render_widget(p, area);
    } else if state.is_importing_mnemonic {
        render_mnemonic_import_view(frame, area, state, block);
    } else {
        render_entropy_input_view(frame, area, state, block);
    }
}

fn render_entropy_input_view(frame: &mut Frame, area: Rect, state: &AppState, block: Block) {
    let mut lines = Vec::new();

    if state.is_harvesting_jitter {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  ╔══════════════════════════════════════════════════════════════════════════════╗",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            "  ║  HUMAN KEYSTROKE JITTER HARVESTER — HARDWARE PRNG PURGED                     ║",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            "  ║  Mash any keys on your keyboard rapidly! Watch nanosecond timing deltas.     ║",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            "  ╚══════════════════════════════════════════════════════════════════════════════╝",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));

        let count = state.jitter_samples.len();
        let target = 32;
        let filled = (count * 30) / target;
        let empty = 30usize.saturating_sub(filled);
        let bar = format!("[{}{}] {} / {} Keystrokes", "█".repeat(filled), "░".repeat(empty), count, target);
        
        lines.push(Line::from(vec![
            Span::styled("  Harvest Progress: ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled(bar, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("  Live Keystroke Micro-Timing Telemetry (Nanosecond Clock Jitter):", Style::default().fg(Color::Cyan))));
        lines.push(Line::from("  --------------------------------------------------------------------------------"));

        let start_idx = state.jitter_samples.len().saturating_sub(6);
        for (i, (ch, nanos)) in state.jitter_samples[start_idx..].iter().enumerate() {
            let ms = (*nanos as f64) / 1_000_000.0;
            let display_ch = if *ch == '\'' { "'''".to_string() } else { format!("'{}'", ch) };
            let line_str = format!(
                "    Sample #{:02}:  Key: {:<5}  |  Interval: {:>12} ns ({:>6.2} ms)",
                start_idx + i + 1,
                display_ch,
                nanos,
                ms
            );
            lines.push(Line::from(Span::styled(line_str, Style::default().fg(Color::Yellow))));
        }
        for _ in (state.jitter_samples.len() - start_idx)..6 {
            lines.push(Line::from(Span::styled("    Sample --:  Key: --     |  Interval: ------------ ns (------ ms)", Style::default().fg(Color::DarkGray))));
        }

        lines.push(Line::from("  --------------------------------------------------------------------------------"));
        lines.push(Line::from(Span::styled("  WHY THIS WORKS & ELIMINATES HARDWARE SILICON TRUST:", Style::default().fg(Color::White).add_modifier(Modifier::BOLD))));
        lines.push(Line::from("  Even when you try to type at a fixed rhythm, human neuromuscular jitter varies by"));
        lines.push(Line::from("  millions of nanoseconds between keys. SubZero hashes these micro-timing intervals"));
        lines.push(Line::from("  into 128 binary coin flips via SHA-256 with ZERO hardware or kernel PRNG queries."));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("  Keep typing rapidly on any keys... (or press [ESC] to cancel)", Style::default().fg(Color::LightCyan))));

        let p = Paragraph::new(lines).block(block);
        frame.render_widget(p, area);
        return;
    }
    let raw = &state.entropy_input;
    let len = raw.len();

    let is_bin = !raw.is_empty() && raw.chars().all(|c| c == '0' || c == '1');
    let is_dice = !raw.is_empty() && raw.chars().all(|c| ('1'..='6').contains(&c));


    let mode_str = if is_bin {
        "BINARY COIN FLIPS (0/1)"
    } else if is_dice {
        "STANDARD DICE ROLLS (1-6)"
    } else if raw.is_empty() {
        "AWAITING INPUT (Coin 0/1, Dice 1-6, [T] Test Vector, or [C/D/K])"
    } else {
        "TEST VECTOR OR ARBITRARY STREAM"
    };

    let markov = run_markov_audit(raw);
    let repeats = has_repetitive_substrings(raw, 3, 6);

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  Entropy Ingestion Mode: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(mode_str, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from(vec![
        Span::raw("  Collected Count:        "),
        Span::styled(format!("{} chars", len), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
    ]));

    let markov_style = if len < 16 {
        Style::default().fg(Color::DarkGray)
    } else if markov.passed {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)
    };
    lines.push(Line::from(vec![
        Span::raw("  Markov Transition Audit: "),
        Span::styled(if len < 16 { "Awaiting 16+ chars..." } else if markov.passed { "[PASS - ENTROPY HEALTHY]" } else { "[FAIL - BIASED TRANSITIONS]" }, markov_style),
        Span::styled(format!(" (Max cond prob: {:.1}%)", markov.max_cond_prob * 100.0), Style::default().fg(Color::DarkGray)),
    ]));

    let (chi2_pass, chi2_val, _) = run_chi_squared_audit(raw);
    let chi2_style = if len < 16 {
        Style::default().fg(Color::DarkGray)
    } else if chi2_pass {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)
    };
    lines.push(Line::from(vec![
        Span::raw("  Chi-Squared Uniformity:  "),
        Span::styled(if len < 16 { "Awaiting 16+ chars..." } else if chi2_pass { "[PASS - FREQUENCY UNIFORM]" } else { "[FAIL - SKEWED FREQUENCY]" }, chi2_style),
        Span::styled(format!(" (χ² = {:.2})", chi2_val), Style::default().fg(Color::DarkGray)),
    ]));

    let repeat_style = if len < 16 {
        Style::default().fg(Color::DarkGray)
    } else if repeats {
        Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Green)
    };
    lines.push(Line::from(vec![
        Span::raw("  Repetitive Pattern Block: "),
        Span::styled(
            if len < 16 {
                "Awaiting 16+ chars..."
            } else if repeats {
                "[FAIL - REPEATING CHUNKS DETECTED]"
            } else {
                "[PASS - NO REPEATS]"
            },
            repeat_style,
        ),
    ]));

    lines.push(Line::from("  -----------------------------------------------------------------------"));
    lines.push(Line::from(Span::styled("  MILLER'S LAW CHUNKING & REAL-TIME INPUT STREAM:", Style::default().fg(Color::Cyan))));
    lines.push(Line::from(""));

    if is_bin {
        let mut words = Vec::new();
        for i in 0..11 {
            let start = i * 11;
            if start < len {
                let end = std::cmp::min(len, start + 11);
                let chunk = &raw[start..end];
                let c1 = &chunk[0..std::cmp::min(4, chunk.len())];
                let c2 = if chunk.len() > 4 { &chunk[4..std::cmp::min(8, chunk.len())] } else { "" };
                let c3 = if chunk.len() > 8 { &chunk[8..chunk.len()] } else { "" };
                let formatted = format!("{:<4} {:<4} {:<3}", c1, c2, c3);
                words.push(format!("W{:02}: {}", i + 1, formatted));
            } else {
                words.push(format!("W{:02}: ---- ---- ---", i + 1));
            }
        }
        if len > 121 {
            let chunk12 = &raw[121..std::cmp::min(128, len)];
            let c1 = &chunk12[0..std::cmp::min(4, chunk12.len())];
            let c2 = if chunk12.len() > 4 { &chunk12[4..chunk12.len()] } else { "" };
            let formatted = format!("{:<4} {:<3} [chk]", c1, c2);
            words.push(format!("W12: {}", formatted));
        } else {
            words.push("W12: ---- --- [chk]".to_string());
        }

        for r in 0..6 {
            let left = words.get(r).cloned().unwrap_or_default();
            let right = words.get(r + 6).cloned().unwrap_or_default();
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(format!("{:<26}", left), Style::default().fg(Color::Yellow)),
                Span::raw("    "),
                Span::styled(right, Style::default().fg(Color::Yellow)),
            ]));
        }
    } else if is_dice {
        let chars: Vec<char> = raw.chars().collect();
        for row in 0..6 {
            let mut spans = vec![Span::raw("    ")];
            for col in 0..10 {
                let idx = row * 10 + col;
                if idx < 60 {
                    if idx < chars.len() {
                        spans.push(Span::styled(format!("{} ", chars[idx]), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
                    } else {
                        spans.push(Span::styled("- ", Style::default().fg(Color::DarkGray)));
                    }
                    if col == 4 {
                        spans.push(Span::raw("  "));
                    }
                }
            }
            lines.push(Line::from(spans));
        }
    } else {
        lines.push(Line::from(Span::styled(
            format!("  Buffer: {}", if raw.is_empty() { "[EMPTY]" } else { raw }),
            Style::default().fg(Color::Yellow),
        )));
    }

    lines.push(Line::from(""));
    if (is_bin && len >= 128 && markov.passed && chi2_pass && !repeats) || (is_dice && len >= 50 && markov.passed && chi2_pass && !repeats) {
        lines.push(Line::from(Span::styled(
            "  [CRITERIA MET] Press [ENTER] to derive master keys and BIP-85 suite.",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )));
    } else if !raw.is_empty() {
        let needed = if is_dice {
            format!("{} rolls (50 min floor)", 50usize.saturating_sub(len))
        } else {
            format!("{} bits", 128usize.saturating_sub(len))
        };
        lines.push(Line::from(Span::styled(
            format!("  Awaiting physical entropy ({} needed)...", needed),
            Style::default().fg(Color::Cyan),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from("  --------------------------------------------------------------------------------"));
    lines.push(Line::from(Span::styled("  HOW THIS WORKS (PURE PHYSICAL ENTROPY):", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
    lines.push(Line::from("  1. Flip a coin 128 times (type '0' for Heads, '1' for Tails) or roll a 6-sided die 50+ times."));
    lines.push(Line::from("  2. Zero Hardware PRNG: Your private keys come 100% from physical chance, not a computer chip."));
    lines.push(Line::from("  3. Real-Time Math Audit: SubZero monitors Markov transitions, Chi-squared uniformity, and blocks repeats."));
    lines.push(Line::from("  4. Dice Hashing: 50+ rolls are hashed with SHA-256. Tip: Rolling 2-5 dice together blends out individual die flaws."));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("  TEST VECTORS & HUMAN JITTER HARVESTER (Amnesic RAM Testing Only):", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))));
    lines.push(Line::from("  - Press [T] to select a deterministic test vector (0=All-Zeros, 8=Genesis Lore, 9=Hal Finney)."));
    lines.push(Line::from("  - Press [C] to load 128 real coin flips into the buffer for instant review."));
    lines.push(Line::from("  - Press [D] to load 52 real dice rolls into the buffer for instant review."));
    lines.push(Line::from("  - Press [K] to harvest human keystroke timing jitter (unique test seed, zero PRNG)."));
    lines.push(Line::from("  - Press [I] to import an existing 12 or 24-word offline seed phrase."));
    lines.push(Line::from("  - Press [W] at any time to wipe and clear all input buffers."));

    let p = Paragraph::new(lines).block(block);
    frame.render_widget(p, area);
}

fn render_mnemonic_import_view(frame: &mut Frame, area: Rect, state: &AppState, block: Block) {
    let mut lines = Vec::new();

    let trimmed = state.mnemonic_import_input.trim();
    let digits_only: String = trimmed.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    let is_compact = digits_only.len() == 48 && digits_only.chars().all(|c| c.is_ascii_digit());
    let is_descriptor = trimmed.starts_with("wpkh(") || trimmed.starts_with("tpub") || trimmed.starts_with("vpub");

    lines.push(Line::from(Span::styled(
        "  INGESTION: 12 WORDS (BIP-39) | COMPACTSEEDQR (48 DIGITS) | BIP-380 DESCRIPTOR",
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from("  Type 12 words, 48-digit CompactSeedQR, or wpkh([fprint/path]tpub.../<0;1>/*)#checksum."));

    // User input display box
    let char_count = state.mnemonic_import_input.len();
    let words: Vec<&str> = state.mnemonic_import_input.split_whitespace().collect();
    let word_count = words.len();

    let display_str = if state.mnemonic_import_input.is_empty() {
        "Type 12 English words, 48 digits, or wpkh(tpub...)...".to_string()
    } else {
        state.mnemonic_import_input.clone()
    };

    let input_label = if is_descriptor {
        format!("(Descriptor | {} chars)", char_count)
    } else if is_compact {
        format!("(CompactSeedQR | {} / 48 digits)", digits_only.len())
    } else {
        format!("({} / 12 words | {} chars)", word_count, char_count)
    };

    lines.push(Line::from(vec![
        Span::styled("  Input Buffer: ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled(input_label, Style::default().fg(Color::DarkGray)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  > ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(display_str, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
    ]));

    let wordlist = bip39::Language::English.word_list();

    if is_descriptor {
        lines.push(Line::from("  Descriptor Validation:"));
        lines.push(Line::from("  --------------------------------------------------------------------------"));
        if let Some(pound_idx) = trimmed.find('#') {
            let (desc_part, check_part) = trimmed.split_at(pound_idx);
            let check_part = &check_part[1..];
            let expected = get_descriptor_checksum(desc_part);
            if check_part == expected {
                lines.push(Line::from(Span::styled(
                    format!("  [✓ BIP-380 CHECKSUM VALID: #{}] Press [ENTER] to audit watch-only keys in RAM.", expected),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                )));
            } else {
                lines.push(Line::from(Span::styled(
                    format!("  [!] CHECKSUM MISMATCH: expected #{} (got #{})", expected, check_part),
                    Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                )));
            }
        } else {
            let expected = get_descriptor_checksum(trimmed);
            if !expected.is_empty() {
                lines.push(Line::from(Span::styled(
                    format!("  [NO CHECKSUM] Expected checksum: #{} — Press [ENTER] to audit watch-only keys.", expected),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                )));
            } else {
                lines.push(Line::from(Span::styled(
                    "  [!] INVALID DESCRIPTOR: Unable to calculate BIP-380 checksum.",
                    Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                )));
            }
        }
        lines.push(Line::from("  --------------------------------------------------------------------------"));
    } else if is_compact {
        lines.push(Line::from("  CompactSeedQR 48-Digit Numeric Decoding:"));
        lines.push(Line::from("  --------------------------------------------------------------------------"));
        match compact_seed_qr_to_mnemonic(&digits_only) {
            Ok(recovered_phrase) => {
                lines.push(Line::from(Span::styled(
                    format!("  [✓ VALID COMPACTSEEDQR]: Decoded to 12 valid BIP-39 words."),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(Span::styled(
                    format!("  Words: {}", recovered_phrase),
                    Style::default().fg(Color::Cyan),
                )));
            }
            Err(e) => {
                lines.push(Line::from(Span::styled(
                    format!("  [!] INVALID COMPACTSEEDQR: {}", e),
                    Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                )));
            }
        }
        lines.push(Line::from("  --------------------------------------------------------------------------"));
    } else {
        // Standard 12-word validation table
        if !words.is_empty() {
            lines.push(Line::from("  Word Validation & Metal Punch Breakdown:"));
            lines.push(Line::from("  --------------------------------------------------------------------------"));

            let half = 6;
            for i in 0..half {
                let mut left_spans = Vec::new();
                left_spans.push(Span::raw("    "));
                if i < words.len() {
                    let w = words[i];
                    let is_valid = wordlist.contains(&w);
                    let punch = if w.len() >= 4 { &w[..4] } else { w }.to_uppercase();
                    if is_valid {
                        left_spans.push(Span::styled(
                            format!("Word #{:02}: {:<8} [✓ {:<4}]", i + 1, w, punch),
                            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                        ));
                    } else {
                        left_spans.push(Span::styled(
                            format!("Word #{:02}: {:<8} [? UNKNOWN]", i + 1, w),
                            Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                        ));
                    }
                } else {
                    left_spans.push(Span::styled(
                        format!("Word #{:02}: -------- [------]", i + 1),
                        Style::default().fg(Color::DarkGray),
                    ));
                }

                let mut right_spans = Vec::new();
                right_spans.push(Span::raw("      "));
                let r_idx = i + half;
                if r_idx < words.len() {
                    let w = words[r_idx];
                    let is_valid = wordlist.contains(&w);
                    let punch = if w.len() >= 4 { &w[..4] } else { w }.to_uppercase();
                    if is_valid {
                        right_spans.push(Span::styled(
                            format!("Word #{:02}: {:<8} [✓ {:<4}]", r_idx + 1, w, punch),
                            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                        ));
                    } else {
                        right_spans.push(Span::styled(
                            format!("Word #{:02}: {:<8} [? UNKNOWN]", r_idx + 1, w),
                            Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                        ));
                    }
                } else {
                    right_spans.push(Span::styled(
                        format!("Word #{:02}: -------- [------]", r_idx + 1),
                        Style::default().fg(Color::DarkGray),
                    ));
                }

                let mut combined = left_spans;
                combined.extend(right_spans);
                lines.push(Line::from(combined));
            }
            lines.push(Line::from("  --------------------------------------------------------------------------"));
        }

        // Mathematical Checksum Audit
        if word_count == 12 {
            let all_english = words.iter().all(|w| wordlist.contains(w));
            if !all_english {
                lines.push(Line::from(Span::styled(
                    "  [!] UNKNOWN WORDS: One or more words not in BIP-39 English dictionary.",
                    Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                )));
            } else {
                match bip39::Mnemonic::parse_in_normalized(bip39::Language::English, trimmed) {
                    Ok(_) => {
                        lines.push(Line::from(Span::styled(
                            "  [✓ BIP-39 CHECKSUM VALID] Press [ENTER] to derive master keys and BIP-85 suite in RAM.",
                            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                        )));
                    }
                    Err(e) => {
                        lines.push(Line::from(Span::styled(
                            format!("  [!] INVALID BIP-39 CHECKSUM: {} (Check final word or press [3] for SeedFix).", e),
                            Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                        )));
                    }
                }
            }
        } else if word_count < 12 {
            lines.push(Line::from(Span::styled(
                format!("  [AWAITING WORDS] Entered {} of 12 words. Keep typing...", word_count),
                Style::default().fg(Color::Cyan),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                format!("  [!] EXCEEDED 12 WORDS: Entered {} words (SubZero requires exactly 12 words).", word_count),
                Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
            )));
        }
    }

    lines.push(Line::from("  --------------------------------------------------------------------------------"));
    lines.push(Line::from(Span::styled(
        "  CONTROLS: [ENTER] Derive/Audit | [ESC] Cancel | [W] Zeroize RAM | [Amnesic RAM Only]",
        Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
    )));

    let p = Paragraph::new(lines).block(block);
    frame.render_widget(p, area);
}

fn render_passphrase(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 2. Decoupled Estate Passphrase (BIP-85 Index 0) [TESTNET4 ONLY] ")
        .style(Style::default().fg(Color::White));

    if let Some(ref pass) = state.decoupled_passphrase {
        let words: Vec<&str> = pass.mnemonic.split_whitespace().collect();
        let mut lines = Vec::new();

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  [NON-COLOCATED ENCRYPTION KEY & ESTATE DEAD-MAN SWITCH]",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(vec![
            Span::raw("  BIP-85 Path: "),
            Span::styled(&pass.path, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(" (Deterministic child derivation)"),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  12-WORD PASSPHRASE (SPACE-SEPARATED STRING WITH NUMBERING GUIDES):", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]));
        let pass_num_line = words.iter().enumerate().map(|(idx, w)| {
            let width = std::cmp::max(w.len(), 4);
            format!("{:<width$}", format!("#{:02}", idx + 1), width = width)
        }).collect::<Vec<_>>().join(" ");
        let pass_word_line = words.iter().map(|w| {
            let width = std::cmp::max(w.len(), 4);
            format!("{:<width$}", w, width = width)
        }).collect::<Vec<_>>().join(" ");

        lines.push(Line::from(Span::styled(format!("  {}", pass_num_line), Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD))));
        lines.push(Line::from(Span::styled(format!("  {}", pass_word_line), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))));
        lines.push(Line::from(vec![
            Span::styled("  METAL PUNCH / COLUMN GUIDANCE: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled("Read Column 1 DOWN (01-06), then Column 2 DOWN (07-12).", Style::default().fg(Color::White)),
        ]));
        lines.push(Line::from("  --------------------------------------------------------------------------"));
        lines.push(Line::from(vec![
            Span::styled(format!("  {:<35}", "COLUMN 1: (Words 01 through 06)"), Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD)),
            Span::styled("COLUMN 2: (Words 07 through 12)", Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::from("  --------------------------------------------------------------------------"));

        for i in 0..6 {
            let w1 = words.get(i).unwrap_or(&"");
            let w2 = words.get(i + 6).unwrap_or(&"");
            let p1 = if w1.len() >= 4 { &w1[..4] } else { w1 }.to_uppercase();
            let p2 = if w2.len() >= 4 { &w2[..4] } else { w2 }.to_uppercase();

            let left = format!("  Word #{:02}: {:<8} [Punch: {:<4}]", i + 1, w1, p1);
            let right = format!("   Word #{:02}: {:<8} [Punch: {:<4}]", i + 7, w2, p2);
            lines.push(Line::from(vec![
                Span::styled(left, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::styled(right, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            ]));
        }

        lines.push(Line::from("  --------------------------------------------------------------------------"));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("  DECOUPLED ESTATE PASSING ARCHITECTURE:", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
        lines.push(Line::from("  1. Location A (Master Seed on Steel): Direct spending control of your master root cold wallet."));
        lines.push(Line::from("  2. Location B (This Decoupled Passphrase): Encrypts Partition 2 estate vault (vault.json)."));
        lines.push(Line::from("  3. Heirs need Location B + Partition 2 to decrypt individual heir treasuries on Tab 9."));
        lines.push(Line::from("  4. Never co-locate Location B with the physical SubZero appliance or SD card."));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("  ESTATE RECOVERY ARCHITECTURE:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))));
        lines.push(Line::from("    [Partition 2: Encrypted vault.json] + [Location B: Passphrase] = HEIR TREASURIES"));
        lines.push(Line::from("    (Location B alone or Partition 2 alone is cryptographically useless without the other)"));

        let p = Paragraph::new(lines).block(block);
        frame.render_widget(p, area);
    } else {
        frame.render_widget(Paragraph::new("Generate a seed first on Tab 1.").block(block), area);
    }
}

fn render_descriptor(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 3. Output Descriptor (BIP-380 Native SegWit) [TESTNET4 ONLY] ")
        .style(Style::default().fg(Color::White));

    if let Some(ref seed) = state.seed {
        let desc = &seed.descriptor;
        let vpub = &seed.vpub;

        let mut lines = Vec::new();
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("  WATCH-ONLY OUTPUT DESCRIPTOR (BIP-380 / BIP-84):", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
        lines.push(Line::from(Span::styled(format!("  {}", desc), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  BIP-32 Account Public Key (tpub... / BIP-84 m/84'/1'/0'):", Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::from(Span::styled(format!("  {}", vpub), Style::default().fg(Color::White))));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  SLIP-0132 Native SegWit Key (vpub... for Blockstream Green & Electrum):", Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::from(Span::styled(format!("  {}", &seed.vpub_slip132), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))));
        lines.push(Line::from(""));
        lines.push(Line::from("  --------------------------------------------------------------------------------"));
        lines.push(Line::from(Span::styled("  WALLET IMPORT PROTOCOL & COMPATIBILITY MATRIX:", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
        lines.push(Line::from("  +-------------------+----------------------------+-----------------------------+"));
        lines.push(Line::from("  | TARGET WALLET     | RECOMMENDED EXPORT MODE    | FORMAT ACCEPTED             |"));
        lines.push(Line::from("  +-------------------+----------------------------+-----------------------------+"));
        lines.push(Line::from("  | Nunchuk (Mobile)  | Tab 4, Mode 1 (BBQR)       | BIP-380 Output Descriptor   |"));
        lines.push(Line::from("  | Sparrow (Desktop) | Tab 4, Mode 1 or Mode 2    | BIP-380 Output Descriptor   |"));
        lines.push(Line::from("  | Bitcoin Keeper    | Tab 4, Mode 2 (Descriptor) | BIP-380 Output Descriptor   |"));
        lines.push(Line::from("  | Blockstream Green | Tab 4, Mode 3 (Static VPUB)| SLIP-0132 Raw Extended Key  |"));
        lines.push(Line::from("  | Electrum          | Tab 4, Mode 3 (Static VPUB)| SLIP-0132 Raw Extended Key  |"));
        lines.push(Line::from("  | Bitcoin Core CLI  | USB File: descriptor.txt   | importdescriptors JSON      |"));
        lines.push(Line::from("  +-------------------+----------------------------+-----------------------------+"));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("  [✓] Zero Private Keys: Watch-only descriptors contain no signing entropy and are safe to export.", Style::default().fg(Color::Green))));

        let p = Paragraph::new(lines).block(block);
        frame.render_widget(p, area);
    } else {
        frame.render_widget(Paragraph::new("Generate a seed first on Tab 1.").block(block), area);
    }
}

fn render_vpub_qr(frame: &mut Frame, area: Rect, state: &AppState) {
    let (mode_banner, target_wallet, raw_payload) = match state.qr_mode {
        QrMode::BbqrAnimated => {
            let frames = if let Some(ref s) = state.seed {
                create_bbqr_frames(&s.descriptor, 3)
            } else {
                Vec::new()
            };
            let frame_idx = if frames.is_empty() { 0 } else { state.bbqr_frame_index % frames.len() };
            let cur_frame = frames.get(frame_idx).cloned().unwrap_or_default();
            (
                format!("MODE 1 OF 3: Animated BBQr ({}/{})", frame_idx + 1, frames.len()),
                "Nunchuk (Mobile)",
                cur_frame,
            )
        }
        QrMode::FullBlockSpace => (
            "MODE 2 OF 3: Static BIP-380 Descriptor".to_string(),
            "Sparrow Desktop & Keeper",
            state.seed.as_ref().map(|s| s.descriptor.clone()).unwrap_or_default(),
        ),
        QrMode::StaticVpub => (
            "MODE 3 OF 3: Static SLIP-0132 VPUB".to_string(),
            "Blockstream Green & Electrum",
            state.seed.as_ref().map(|s| s.vpub_slip132.clone()).unwrap_or_default(),
        ),
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Tab 4. Watch-Only QR [{} | Target: {}] [M=Rotate Mode | E=USB] ", mode_banner, target_wallet))
        .style(Style::default().fg(Color::White));

    if let Some(ref seed) = state.seed {
        let qr_result = match state.qr_mode {
            QrMode::BbqrAnimated => {
                let frames = create_bbqr_frames(&seed.descriptor, 3);
                let current_frame = frames.get(state.bbqr_frame_index % frames.len()).unwrap();
                render_full_block_qr(current_frame)
            }
            QrMode::FullBlockSpace => render_full_block_qr(&seed.descriptor),
            QrMode::StaticVpub => render_full_block_qr(&seed.vpub_slip132),
        };

        let mut lines = Vec::new();
        match qr_result {
            Ok(qr_lines) => {
                for l in qr_lines {
                    lines.push(l);
                }
            }
            Err(e) => {
                lines.push(Line::from(Span::styled(format!("QR Render Error: {}", e), Style::default().fg(Color::LightRed))));
            }
        }

        let is_usb_active = state.external_export_status.starts_with("[✓]") || state.external_export_status.starts_with("[!]");
        // For displays with width <= 165 (including standard 80x24, 80x25, 100x30, 120x40, 128x48, and 160x50),
        // 154-char output descriptors wrap across multiple lines (+ 1 mode banner + 1 top border = 5 lines, or 6 with USB status).
        // For widescreen displays with width > 165 (such as the Dell amnesic live framebuffer console),
        // the 163-char 'CONTENT: <descriptor>' fits on a single line (+ 1 mode banner + 1 top border = 3 lines, or 4 with USB status),
        // completely eliminating the spare wasted blank line between CONTENT and NAV while maximizing vertical QR area.
        let bottom_height = if is_usb_active {
            if area.width <= 165 { 6 } else { 4 }
        } else if area.width <= 165 {
            5
        } else {
            3
        };

        let sub_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(10),                 // Full QR code area
                Constraint::Length(bottom_height),   // Compact wrapped CONTENT area (Mode banner + CONTENT + optional USB)
            ])
            .split(area);

        let p_qr = Paragraph::new(lines).alignment(Alignment::Center);
        frame.render_widget(p_qr, sub_chunks[0]);

        let checksum = {
            let digest = Sha256::digest(raw_payload.as_bytes());
            hex::encode(&digest[..4]).to_uppercase()
        };

        let mut bottom_lines = Vec::new();
        bottom_lines.push(Line::from(vec![
            Span::styled(format!("[{}] [M=Rotate | E=USB]", mode_banner), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  [SHA-256: {}]", checksum), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        ]));
        bottom_lines.push(Line::from(vec![
            Span::styled("CONTENT: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled(raw_payload, Style::default().fg(Color::Yellow)),
        ]));

        if is_usb_active {
            bottom_lines.push(Line::from(Span::styled(
                format!("USB Status: {}", state.external_export_status),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )));
        }

        let p_bottom = Paragraph::new(bottom_lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::TOP));
        frame.render_widget(p_bottom, sub_chunks[1]);
    } else {
        frame.render_widget(Paragraph::new("Generate a seed first on Tab 1.").block(block), area);
    }
}

fn render_faucet_qr(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 5. Faucet QR Code (Receive Address #0) [TESTNET4 ONLY] ")
        .style(Style::default().fg(Color::White));

    if let Some(ref seed) = state.seed {
        if let Some(addr) = seed.addresses.first() {
            match render_full_block_qr(addr) {
                Ok(qr_lines) => {
                    let sub_chunks = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([
                            Constraint::Min(10),   // QR code
                            Constraint::Length(4), // Address Info + Content (compacted)
                        ])
                        .split(area);

                    let p_qr = Paragraph::new(qr_lines)
                        .alignment(Alignment::Center);
                    frame.render_widget(p_qr, sub_chunks[0]);

                    let checksum = {
                        let digest = Sha256::digest(addr.as_bytes());
                        hex::encode(&digest[..4]).to_uppercase()
                    };

                    let mut info_lines = Vec::new();
                    info_lines.push(Line::from(vec![
                        Span::styled("Tab 5. Faucet QR Code (Receive Address #0)", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                        Span::styled(format!("  [SHA-256: {}]", checksum), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                    ]));
                    info_lines.push(Line::from(vec![
                        Span::styled("CONTENT: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                        Span::styled(addr, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                        Span::styled("  (Scan to fund test sats)", Style::default().fg(Color::Green)),
                    ]));
                    let p_info = Paragraph::new(info_lines)
                        .wrap(Wrap { trim: false })
                        .block(Block::default().borders(Borders::TOP));
                    frame.render_widget(p_info, sub_chunks[1]);
                }
                Err(e) => {
                    let p = Paragraph::new(format!("QR Render Error: {}", e)).block(block);
                    frame.render_widget(p, area);
                }
            }
        } else {
            frame.render_widget(Paragraph::new("No addresses available.").block(block), area);
        }
    } else {
        frame.render_widget(Paragraph::new("Generate a seed first on Tab 1.").block(block), area);
    }
}

fn render_addresses(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 6. Receive Addresses (BIP-84 Native SegWit tb1q... [Testnet4]) ")
        .style(Style::default().fg(Color::White));

    if let Some(ref seed) = state.seed {
        let total = seed.addresses.len();
        let page_size = 25;
        let start = state.address_page_offset;
        let end = std::cmp::min(start + page_size, total);
        let cur_page = (start / page_size) + 1;
        let total_pages = (total + page_size - 1) / page_size;

        let mut lines = Vec::new();
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(format!("  Showing Addresses #{}-#{} (Page {} of {}):", start, end.saturating_sub(1), cur_page, total_pages), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("    [Controls: UP/DOWN / PgUp/PgDn to Page]"),
        ]));
        lines.push(Line::from(Span::styled(
            "  [!] ALL ADDRESSES ARE TESTNET4 (tb1q...). NEVER SEND REAL MAINNET ASSETS.",
            Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));

        for idx in start..end {
            if let Some(addr) = seed.addresses.get(idx) {
                lines.push(Line::from(vec![
                    Span::styled(format!("  m/84'/1'/0'/0/{:<2}: ", idx), Style::default().fg(Color::Cyan)),
                    Span::styled(addr, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                ]));
            }
        }

        lines.push(Line::from(""));
        lines.push(Line::from("  --------------------------------------------------------------------------------"));
        lines.push(Line::from(Span::styled("  PURPOSE & ADDRESS INTEGRITY (GAP LIMIT & REUSE ADVISORY):", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
        lines.push(Line::from("  1. Wallet Cross-Check: This list is for cross-checking: 'Is my phone in the right wallet?'"));
        lines.push(Line::from("     Verify that the first address displayed on your phone matches Address #0 above."));
        lines.push(Line::from("  2. Do NOT manually pick random addresses from this list for deposits:"));
        lines.push(Line::from("     - Address Reuse: Reusing addresses degrades financial privacy on-chain."));
        lines.push(Line::from("     - Gap Limits: If you skip ahead (e.g. deposit to #15 while #1-#14 are empty), standard"));
        lines.push(Line::from("       wallets may fail to detect your balance (20-address derivation gap limit)."));
        lines.push(Line::from("  3. Best Practice: Always allow your paired phone wallet (Nunchuk/Sparrow) to generate"));
        lines.push(Line::from("     fresh receive addresses automatically as needed."));

        let p = Paragraph::new(lines).block(block);
        frame.render_widget(p, area);
    } else {
        frame.render_widget(Paragraph::new("Generate a seed first on Tab 1.").block(block), area);
    }
}

fn render_bip85(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 7. BIP-85 Heir Keys (Deterministic Child Seeds) [TESTNET4 ONLY] ")
        .style(Style::default().fg(Color::White));

    if !state.bip85_children.is_empty() {
        let total = state.bip85_children.len();
        let page_size = 10;
        let start = state.heir_page_offset;
        let end = std::cmp::min(start + page_size, total);
        let cur_page = (start / page_size) + 1;
        let total_pages = (total + page_size - 1) / page_size;

        let mut lines = Vec::new();
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(format!("  Deterministic Child Seeds #{}-#{} (Page {} of {}):", start + 1, end, cur_page, total_pages), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("  [UP/DOWN to Page 10 Seeds at a time]"),
        ]));
        lines.push(Line::from(""));

        for i in start..end {
            if let Some(child) = state.bip85_children.get(i) {
                let prefix = format!("  Seed #{:02}:  ", child.index);
                lines.push(Line::from(vec![
                    Span::styled(prefix, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Span::styled(&child.mnemonic, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                ]));
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::from("  --------------------------------------------------------------------------------"));
        lines.push(Line::from(Span::styled("  VERSATILE BIP-85 USE CASES (MASTER SEED REMAINS AIRGAPPED & COLD):", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
        lines.push(Line::from("  1. Hot Mobile & Daily Spending: Fund a child seed on mobile (Phoenix/Breez) without risking vault funds."));
        lines.push(Line::from("  2. Sovereign Heir Allocations: Provide a sovereign child seed to each heir/family member."));
        lines.push(Line::from("  3. High-Entropy Passphrases & PKI: Use 12-word child seeds as unhackable master passwords, Age keys, or Nostr IDs."));
        lines.push(Line::from("  4. Business / Project Sub-Treasuries: Isolate company, homelab, or testing budgets with independent accounting."));
        lines.push(Line::from("  5. One-Way Derivation Invariant: Compromising any child seed mathematically reveals ZERO info about your master seed."));

        let p = Paragraph::new(lines).block(block);
        frame.render_widget(p, area);
    } else {
        frame.render_widget(Paragraph::new("Generate a seed first on Tab 1.").block(block), area);
    }
}

fn render_estate_provisioner(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 8. Benefactor Estate Vault Provisioner (SUBZERO_EST) ")
        .style(Style::default().fg(Color::White));

    let mut lines = Vec::new();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  AIRGAPPED ENCRYPTED ESTATE STORAGE PROVISIONER",
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from("  This utility mounts the second partition of the SubZero USB card"));
    lines.push(Line::from("  (labeled SUBZERO_EST) and writes the encrypted payload:"));
    lines.push(Line::from("    - vault.json (AES-256-GCM encrypted master + heir BIP-85 suite)"));
    lines.push(Line::from("    - README.txt (Physical recovery protocol for heirs & attorneys)"));
    lines.push(Line::from("    - SHA256SUMS (Cryptographic manifest for tamper verification)"));
    lines.push(Line::from(""));

    let part_info = locate_estate_partition().unwrap_or_else(|| "NONE (Not Found)".into());
    let part_style = if part_info.contains("NONE") {
        Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
    };

    lines.push(Line::from(vec![
        Span::raw("  Target Partition: "),
        Span::styled(part_info, part_style),
    ]));
    lines.push(Line::from(vec![
        Span::raw("  Passphrase Status: "),
        Span::styled(
            if state.decoupled_passphrase.is_some() { "PRESENT IN RAM" } else { "MISSING" },
            if state.decoupled_passphrase.is_some() { Style::default().fg(Color::Green) } else { Style::default().fg(Color::LightRed) }
        ),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("  Status: {}", state.estate_write_status),
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Controls: Press [P] to encrypt and write estate files to Partition 2.",
        Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from("  --------------------------------------------------------------------------------"));
    lines.push(Line::from(Span::styled("  PLAIN-ENGLISH ESTATE PROTOCOL:", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
    lines.push(Line::from("  1. What is written? An encrypted vault file (vault.json) containing your root seed & heir keys."));
    lines.push(Line::from("  2. Who can read it? ONLY someone who enters the 12-word Passphrase from Tab 2."));
    lines.push(Line::from("  3. Burglar / Loss Safety: If this SD card is lost or stolen, it is mathematically unbreakable"));
    lines.push(Line::from("     without the Tab 2 Passphrase (protected by 600,000 PBKDF2 rounds + AES-256-GCM)."));
    lines.push(Line::from("  4. Pure Determinism: All encryption salts and keys derive from your physical entropy, with"));
    lines.push(Line::from("     zero reliance on hardware random number generators."));

    let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    frame.render_widget(p, area);
}

fn render_vault_unlock(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 9. Unlock & Decrypt Estate Vault (vault.json) ")
        .style(Style::default().fg(Color::White));

    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        "  INHERITANCE RECOVERY & VAULT AUTHENTICATION ENGINE",
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from("  Enter your 12-Word Decoupled Estate Passphrase below to decrypt vault.json:"));

    let char_count = state.vault_passphrase_input.len();
    let word_count = if state.vault_passphrase_input.trim().is_empty() {
        0
    } else {
        state.vault_passphrase_input.split_whitespace().count()
    };

    let (input_display, mask_badge) = if state.vault_passphrase_input.is_empty() {
        ("Type 12-word passphrase or 't0'..'t9' / 'test'...".to_string(), "[AWAITING INPUT]")
    } else if state.vault_mask_passphrase {
        ("•".repeat(char_count.min(48)), "[MASKED - Press Ctrl+M to Unmask]")
    } else {
        (state.vault_passphrase_input.clone(), "[VISIBLE - Press Ctrl+M to Mask]")
    };

    lines.push(Line::from(vec![
        Span::styled("  > ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(input_display, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from(vec![
        Span::styled(format!("    Passphrase Metrics: {} word(s) entered | {} character(s)  ", word_count, char_count), Style::default().fg(Color::DarkGray)),
        Span::styled(mask_badge, Style::default().fg(Color::Cyan)),
    ]));
    lines.push(Line::from(Span::styled(
        format!("  Status: {}", state.vault_status_msg),
        Style::default().fg(Color::Cyan),
    )));
    lines.push(Line::from(Span::styled(
        "  Note: Press [ENTER] to authenticate. Press [Ctrl+M] to toggle visual masking.",
        Style::default().fg(Color::DarkGray),
    )));

    if let Some(ref payload) = state.decrypted_vault {
        let remaining_mins = 30u64.saturating_sub(state.last_activity_instant.elapsed().as_secs() / 60);
        lines.push(Line::from(Span::styled(
            "  [✓] RECOVERY SUCCESSFUL: Decrypted into amnesic RAM.",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            format!("  [Auto-Lock: 30m idle timer active ({}m remaining)]", remaining_mins),
            Style::default().fg(Color::Yellow),
        )));
        lines.push(Line::from(Span::styled(
            "  Key Location Guidance: Mnemonic below. Optical QR codes on Tab 4. Addresses on Tab 6.",
            Style::default().fg(Color::Cyan),
        )));
        lines.push(Line::from(format!("  Master Root Mnemonic: {}", payload.master_root_mnemonic)));
        lines.push(Line::from(format!("  Output Descriptor:    {}", payload.descriptor)));
        lines.push(Line::from("  Heir Treasuries:"));
        for heir in payload.heir_treasuries.iter().take(2) {
            lines.push(Line::from(format!("    - {} (Index {}): {}", heir.label, heir.index, heir.mnemonic)));
        }
        lines.push(Line::from(Span::styled(
            "  Next Actions: Write down words on steel or paper. Press [Tab] to view Tab 4 (Optical QR exports).",
            Style::default().fg(Color::Yellow),
        )));
    } else {
        lines.push(Line::from("  Press [ENTER] to attempt AES-256-GCM / PBKDF2 authentication against Partition 2."));
    }

    lines.push(Line::from("  --------------------------------------------------------------------------"));
    lines.push(Line::from(Span::styled("  OPERATOR GUIDANCE (IF YOU ARE AN HEIR OR EXECUTOR):", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))));
    lines.push(Line::from("  1. Welcome: This tab is your recovery workstation. Insert media into laptop."));
    lines.push(Line::from("  2. Enter Passphrase: Type the 12 words provided in your estate letter."));
    lines.push(Line::from("  3. Unknown Passphrase? Check benefactor estate planning packet or will."));
    lines.push(Line::from("     SubZero cannot bypass the 12-word passphrase."));
    lines.push(Line::from("  4. Press [ENTER]: The vault unlocks in amnesic memory."));
    lines.push(Line::from("  5. Zero Footprint: Nothing is ever saved to disk. Power off purges RAM."));

    let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    frame.render_widget(p, area);
}

fn render_seedfix(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 10. SeedFix Recovery Tool (Interactive Candidate Solver) ")
        .style(Style::default().fg(Color::White));

    let mut lines = Vec::new();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  11-WORD PREFIX CHECKSUM SOLVER (Levenshtein Error Correction)",
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from("  Enter 11 or 12 words (with typo/missing 12th word):"));
    lines.push(Line::from(""));

    let input_display = if state.seedfix_input.is_empty() {
        "Type words..."
    } else {
        &state.seedfix_input
    };
    lines.push(Line::from(vec![
        Span::styled("  Input: ", Style::default().fg(Color::Cyan)),
        Span::styled(input_display, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from(""));

    let words: Vec<&str> = state.seedfix_input.split_whitespace().collect();
    if words.len() >= 11 {
        let prefix = words[..11].join(" ");
        let target = words.get(11).copied();
        let candidates_res = solve_twelfth_word(&prefix, target);

        if let Ok(candidates) = candidates_res {
            lines.push(Line::from(Span::styled(
                format!("  Found {} Mathematically Valid Checksum Candidate(s):", candidates.len()),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));

            for (idx, cand) in candidates.iter().take(6).enumerate() {
                let dist_str = if cand.distance < 99 {
                    format!("(Typo Match - Levenshtein Distance: {})", cand.distance)
                } else {
                    "(Valid Checksum)".to_string()
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("    {:2}. {:<12} ", idx + 1, cand.twelfth_word), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Span::styled(dist_str, Style::default().fg(Color::DarkGray)),
                ]));
            }
        } else if let Err(e) = candidates_res {
            lines.push(Line::from(Span::styled(
                format!("  Error: {}", e),
                Style::default().fg(Color::Red),
            )));
        }
    } else {
        lines.push(Line::from(Span::styled(
            format!("  Enter {} more word(s) to solve 12th word checksum...", 11usize.saturating_sub(words.len())),
            Style::default().fg(Color::DarkGray),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from("  --------------------------------------------------------------------------------"));
    lines.push(Line::from(Span::styled("  WHY IS THIS POSSIBLE? (THE 12TH WORD CHECKSUM):", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
    lines.push(Line::from("  - In a standard 12-word Bitcoin seed, the 12th word contains a built-in mathematical checksum."));
    lines.push(Line::from("  - Out of 2,048 possible BIP-39 words, exactly 128 words can mathematically fit the 12th slot."));
    lines.push(Line::from("  - If your 12th word was smudged or has a typo, this tool computes all 128 valid candidates"));
    lines.push(Line::from("    and sorts them by spelling similarity to your input."));

    let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    frame.render_widget(p, area);
}

fn render_wordlist_inspector(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 11. BIP-39 Canonical English Wordlist Inspector (2048 Words) ")
        .style(Style::default().fg(Color::White));

    let mut lines = Vec::new();
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  Search Prefix/Substrings: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(
            if state.wordlist_query.is_empty() { "Type letters..." } else { &state.wordlist_query },
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(""));

    let matches = search_wordlist(&state.wordlist_query);
    lines.push(Line::from(Span::styled(
        format!("  Matching Words ({} total):", matches.len()),
        Style::default().fg(Color::Green),
    )));
    lines.push(Line::from(""));

    for chunk in matches.chunks(4).take(8) {
        let mut spans = vec![Span::raw("    ")];
        for w in chunk {
            spans.push(Span::styled(format!("{:<14} ", w), Style::default().fg(Color::White)));
        }
        lines.push(Line::from(spans));
    }

    lines.push(Line::from(""));
    lines.push(Line::from("  --------------------------------------------------------------------------------"));
    lines.push(Line::from(Span::styled("  THE 4-LETTER BIP-39 RULE:", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
    lines.push(Line::from("  - In the official 2,048-word Bitcoin dictionary, every single word is uniquely identified"));
    lines.push(Line::from("    by its FIRST 4 LETTERS. No two words share the same first 4 letters."));
    lines.push(Line::from("  - If a word only has 3 letters (like 'cat' or 'dog'), the entire word is punched."));
    lines.push(Line::from("  - This is why metal backup plates only have 4 character slots per word."));

    let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    frame.render_widget(p, area);
}

fn render_drill_guide(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 12. 24x4 Metal Punch / Cold Storage Guide [TESTNET4 ONLY] ")
        .style(Style::default().fg(Color::White));

    if let Some(ref seed) = state.seed {
        let words: Vec<&str> = seed.mnemonic.split_whitespace().collect();
        let mut lines = Vec::new();
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  READING ORDER GUIDANCE: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled("Punch Column 1 (Word 01 -> 06) DOWN, then Column 2 (Word 07 -> 12) DOWN.", Style::default().fg(Color::White)),
        ]));
        lines.push(Line::from("  --------------------------------------------------------------------------------"));
        lines.push(Line::from(vec![
            Span::styled(format!("  {:<42}", "COLUMN 1: (Words 01 through 06)"), Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD)),
            Span::styled("COLUMN 2: (Words 07 through 12)", Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::from("  --------------------------------------------------------------------------------"));

        for i in 0..6 {
            let w1 = words.get(i).unwrap_or(&"");
            let w2 = words.get(i + 6).unwrap_or(&"");
            let p1 = if w1.len() >= 4 { &w1[..4] } else { w1 }.to_uppercase();
            let p2 = if w2.len() >= 4 { &w2[..4] } else { w2 }.to_uppercase();

            let left = format!("  Slot #{:02}:  {:<12} -> [ {:<4} ]", i + 1, w1, p1);
            let right = format!("    Slot #{:02}:  {:<12} -> [ {:<4} ]", i + 7, w2, p2);
            lines.push(Line::from(vec![
                Span::styled(left, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(right, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]));
        }

        lines.push(Line::from("  --------------------------------------------------------------------------------"));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("  STEEL PUNCHING BEST PRACTICES:", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
        lines.push(Line::from("  1. Use stainless steel or titanium plates (fireproof to 2,000°F+)."));
        lines.push(Line::from("  2. Center punch firmly into the 4 letters indicated in the brackets [ ABCD ]."));
        lines.push(Line::from("  3. Check each stamped word against Tab 1 before erasing memory or powering down."));

        let p = Paragraph::new(lines).block(block);
        frame.render_widget(p, area);
    } else {
        frame.render_widget(Paragraph::new("Generate a seed first on Tab 1.").block(block), area);
    }
}

fn render_provenance(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 13. Appliance Build Provenance & Cryptographic Spec ")
        .style(Style::default().fg(Color::White));

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("  Appliance Engine:     "),
            Span::styled("subzero-rs (Pure Rust Bare-Metal Self-Contained Binary)", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::raw("  Target Architecture:  "),
            Span::styled("x86_64-unknown-linux-musl / Linux Framebuffer (tty1)", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::raw("  OS Execution Model:   "),
            Span::styled("Amnesic Alpine Linux 3.20 (SquashFS + RAM tmpfs, Zero-Persistence)", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::raw("  Protocol Scope:       "),
            Span::styled("Bitcoin Testnet4 ONLY (m/84'/1'/0', tb1q..., tpub...)", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::raw("  Optical Airgap Suite: "),
            Span::styled("3-Mode Carousel: Mode 1 BBQR, Mode 2 Full-Block, Mode 3 Compact VPUB", Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::raw("  Wallet Interop:       "),
            Span::styled("Nunchuk, Keeper, Blockstream Green (SLIP-0132 Native SegWit), Sparrow", Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::raw("  Physical USB Export:  "),
            Span::styled("Auto-detects external USB drives; exports single-line descriptors & BMP QRs", Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::raw("  Core Cryptography:    "),
            Span::styled("rust-bitcoin 0.32, bip39 2.1, zeroize 1.8, sha2 0.10, aes-gcm 0.10", Style::default().fg(Color::Green)),
        ]),
        Line::from(vec![
            Span::raw("  Dual-Partition Model: "),
            Span::styled("Part 1: Read-Only EFI/SquashFS | Part 2: SUBZERO_EST Encrypted Vault", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::raw("  Build Timestamp:      "),
            Span::styled(&state.build_timestamp, Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::raw("  Git Commit SHA:       "),
            Span::styled(&state.git_commit, Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::raw("  Memory Hygiene:       "),
            Span::styled("ZeroizeOnDrop on all entropy buffers, private keys, and master seeds", Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::raw("  Entropy Invariant:    "),
            Span::styled("Zero Hardware PRNG: Deterministic keys from coins/dice + human keystroke jitter", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::raw("  OS Hardware Shield:   "),
            Span::styled("/dev/random & /dev/urandom physically unlinked from filesystem before launch", Style::default().fg(Color::Green)),
        ]),
    ];

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// Centralized key event handler for interactive terminal and headless test suites.
/// Returns true if the application should terminate (break main loop), false to continue.
pub fn handle_key_event(state: &mut AppState, key: KeyEvent) -> bool {
    state.last_activity_instant = std::time::Instant::now();
    state.check_inactivity_autolock();

    // 1. Unconditional Emergency Exit: Ctrl+c
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return true;
    }

    // 2. High-Priority Mode: Active Keystroke Jitter Harvesting
    // INVARIANT 3 (JITTER ISOLATION):
    // When is_harvesting_jitter is active, pressing Tab, Left, Right, or digits MUST NOT
    // silently switch pages or corrupt background state without cancelling or finishing jitter.
    // INVARIANT 1: 'w' or 'W' during jitter harvest MUST NEVER wipe memory or clear the seed.
    // INVARIANT 2: 'q' or 'Q' during jitter harvest MUST NEVER trigger exit confirmation.
    if state.is_harvesting_jitter {
        if key.code == KeyCode::Esc {
            state.is_harvesting_jitter = false;
            for s in &mut state.jitter_samples {
                s.0 = '\0';
                s.1.zeroize();
            }
            state.jitter_samples.clear();
            state.last_jitter_instant = None;
            state.status_message = "Keystroke jitter harvest canceled.".into();
            return false;
        }

        if let KeyCode::Char(c) = key.code {
            let now = std::time::Instant::now();
            let delta_nanos = if let Some(prev) = state.last_jitter_instant {
                now.duration_since(prev).as_nanos() as u64
            } else {
                150_000_000 // default ~150ms for initial sample
            };
            state.last_jitter_instant = Some(now);
            state.jitter_samples.push((c, delta_nanos));

            if state.jitter_samples.len() >= 32 {
                let bits = crypto::harvest_keystroke_jitter_to_binary(&state.jitter_samples);
                for s in &mut state.jitter_samples {
                    s.0 = '\0';
                    s.1.zeroize();
                }
                state.jitter_samples.clear();
                state.last_jitter_instant = None;
                state.is_harvesting_jitter = false;

                match crypto::process_physical_entropy(&bits) {
                    Ok(seed) => {
                        let children = crypto::derive_bip85_children(&seed.mnemonic, 20).unwrap_or_default();
                        state.set_seed(seed, children);
                        state.status_message = "[HUMAN JITTER HARVESTED] 12-word seed generated from keystroke timing deltas. [W] Wipe".into();
                    }
                    Err(e) => {
                        state.status_message = format!("[JITTER FAILED] {}. Try again.", e);
                    }
                }
            }
        }
        // All non-char keys (Tab, Left, Right, Up, Down, Home, etc.) are swallowed to enforce jitter isolation
        return false;
    }

    // 3. High-Priority Mode: Test Vector Selection Modal
    if state.is_selecting_test_vector {
        match key.code {
            KeyCode::Char(c) if ('0'..='9').contains(&c) => {
                let digit = c.to_digit(10).unwrap() as u8;
                state.is_selecting_test_vector = false;
                if let Ok((_bytes, label)) = crypto::get_test_vector(digit) {
                    let seed = crypto::process_physical_entropy(&format!("test{}", digit)).unwrap();
                    let children = crypto::derive_bip85_children(&seed.mnemonic, 20).unwrap_or_default();
                    state.set_seed(seed, children);
                    state.status_message = format!("[{}] Loaded. [W] Wipe", label);
                }
            }
            KeyCode::Esc => {
                state.is_selecting_test_vector = false;
                state.status_message = "Test vector selection canceled.".into();
            }
            _ => {
                state.status_message = "Select test vector 0-9, or press [Esc] to cancel.".into();
            }
        }
        return false;
    }

    // Helper: Determine if user is in an active typing input field
    let is_typing_input = match state.current_page {
        Page::MasterSeed => state.seed.is_none(),
        Page::SeedFix => true,
        Page::WordlistInspector => true,
        Page::VaultUnlock => state.decrypted_vault.is_none(),
        _ => false,
    };

    // 4. Two-Stroke Exit [Q] Confirmation
    // INVARIANT 2 (NO ACCIDENTAL EXIT): Typing 'q' or 'Q' in an input field MUST NEVER trigger exit confirmation.
    // INVARIANT 4 (TWO-STROKE EXIT INTEGRITY): Pressing [Q] once sets pending_exit_instant;
    // pressing ANY OTHER KEY cancels it; pressing [Q] again within 3 seconds confirms exit;
    // pressing [Q] after 3 seconds resets the timer.
    let is_plain_q = (key.code == KeyCode::Char('q') || key.code == KeyCode::Char('Q'))
        && !key.modifiers.contains(KeyModifiers::CONTROL);

    if is_plain_q && !is_typing_input {
        if let Some(t) = state.pending_exit_instant {
            if t.elapsed() < Duration::from_secs(3) {
                return true; // Confirmed exit
            }
        }
        state.pending_exit_instant = Some(std::time::Instant::now());
        state.status_message = "[!] PRESS [Q] AGAIN WITHIN 3 SECONDS TO CONFIRM EXIT & PURGE RAM.".into();
        return false;
    } else if state.pending_exit_instant.is_some() {
        // Any other key (or Q inside an input field) cancels pending exit confirmation
        state.pending_exit_instant = None;
    }

    // 5. Global Home / Esc: Return to RoleSelect and reset ephemeral input buffers
    // In input fields, Esc cancels text entry and returns to Tab 0
    if key.code == KeyCode::Esc || key.code == KeyCode::Home {
        if state.current_page == Page::MasterSeed && state.is_importing_mnemonic && key.code == KeyCode::Esc {
            state.is_importing_mnemonic = false;
            state.mnemonic_import_input.zeroize();
            state.mnemonic_import_input.clear();
            state.status_message = "Returned to coin/dice physical entropy mode.".into();
            return false;
        }
        state.vault_passphrase_input.zeroize();
        state.vault_passphrase_input.clear();
        state.seedfix_input.zeroize();
        state.seedfix_input.clear();
        state.wordlist_query.clear();
        state.is_entering_entropy = false;
        state.is_selecting_test_vector = false;
        state.is_importing_mnemonic = false;
        state.mnemonic_import_input.zeroize();
        state.mnemonic_import_input.clear();
        state.current_page = Page::RoleSelect;
        return false;
    }

    // 6. Global Tab Navigation
    // INVARIANT: When entering mnemonic/materials or entropy, Tab and arrow keys must NOT navigate away.
    if state.current_page == Page::MasterSeed && (state.is_importing_mnemonic || state.is_entering_entropy) {
        // Suppress Tab and arrow navigation while actively typing in MasterSeed
    } else {
        match key.code {
            KeyCode::Tab | KeyCode::Right => {
                state.current_page = state.current_page.next();
                return false;
            }
            KeyCode::BackTab | KeyCode::Left => {
                state.current_page = state.current_page.prev();
                return false;
            }
            _ => {}
        }
    }

    // 7. Global Memory Wipe [W]
    // INVARIANT 1 (NO ACCIDENTAL WIPE): Typing 'w' or 'W' while entering text MUST NEVER wipe memory or clear the seed.
    let is_plain_w = (key.code == KeyCode::Char('w') || key.code == KeyCode::Char('W'))
        && !key.modifiers.contains(KeyModifiers::CONTROL);

    if is_plain_w && !is_typing_input {
        state.wipe_memory();
        return false;
    }

    // 8. Contextual Page Handlers
    match state.current_page {
        Page::RoleSelect => {
            match key.code {
                KeyCode::Char('1') | KeyCode::Enter => {
                    state.current_page = Page::MasterSeed;
                    state.is_importing_mnemonic = false;
                }
                KeyCode::Char('2') => {
                    state.current_page = Page::VaultUnlock;
                }
                KeyCode::Char('3') => {
                    state.current_page = Page::SeedFix;
                }
                KeyCode::Char('4') | KeyCode::Char('i') | KeyCode::Char('I') => {
                    state.current_page = Page::MasterSeed;
                    state.is_importing_mnemonic = true;
                    state.mnemonic_import_input.clear();
                    state.status_message = "INGESTION MODE: Enter 12 words, 48 digits, or descriptor.".into();
                }
                _ => {}
            }
        }
        Page::MasterSeed => {
            let has_ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
            if state.is_importing_mnemonic {
                match key.code {
                    KeyCode::Backspace | KeyCode::Char('h') if key.code == KeyCode::Backspace || has_ctrl => {
                        state.mnemonic_import_input.pop();
                    }
                    KeyCode::Enter => {
                        let trimmed = state.mnemonic_import_input.trim();
                        if !trimmed.is_empty() {
                            match crypto::process_mnemonic_phrase(trimmed) {
                                Ok(seed) => {
                                    let children = if seed.mnemonic.starts_with("[WATCH-ONLY") {
                                        Vec::new()
                                    } else {
                                        crypto::derive_bip85_children(&seed.mnemonic, 20).unwrap_or_default()
                                    };
                                    state.set_seed(seed, children);
                                    state.status_message = "[✓] MATERIALS INGESTED: Ready in amnesic RAM.".into();
                                }
                                Err(e) => {
                                    state.status_message = format!("[!] INGESTION FAILED: {}", e);
                                }
                            }
                        }
                    }
                    KeyCode::Char(c) if !has_ctrl => {
                        // Allow letters, digits, spaces, and BIP-380 descriptor characters (including < and > for multipath)
                        if state.mnemonic_import_input.len() < 300
                            && (c.is_alphanumeric() || c == ' ' || "[]/'*()#;:-_.<>{}".contains(c))
                        {
                            state.mnemonic_import_input.push(c);
                        }
                    }
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Char('i' | 'I') if !has_ctrl && state.seed.is_none() && state.entropy_input.is_empty() => {
                        state.is_importing_mnemonic = true;
                        state.mnemonic_import_input.clear();
                        state.status_message = "INGESTION MODE: Enter 12 words, 48 digits, or descriptor.".into();
                    }
                    KeyCode::Char('t' | 'T') if !has_ctrl => {
                        if state.seed.is_none() {
                            state.is_selecting_test_vector = true;
                            state.status_message = "SELECT TEST VECTOR: Press [0-9] (e.g. 0=All-Zeros, 8=Satoshi Lore, 9=Hal Finney) or [Esc] to cancel:".into();
                        }
                    }
                    KeyCode::Char('k' | 'K') if !has_ctrl => {
                        if state.seed.is_none() {
                            state.is_harvesting_jitter = true;
                            state.jitter_samples.clear();
                            state.last_jitter_instant = Some(std::time::Instant::now());
                            state.status_message = "Harvesting human keystroke timing jitter. Mash any keys rapidly!".into();
                        }
                    }
                    KeyCode::Char('c' | 'C') if !has_ctrl => {
                        if state.seed.is_none() {
                            let coin_entropy = "10100110110010111000101011110011011110100010101101111010101100111000101011110011011110100010101101111010101100111000101011110011";
                            state.set_entropy_input(coin_entropy);
                            state.status_message = "[COIN VECTOR LOADED] 128 physical coin flips populated. Review & press [ENTER].".into();
                        }
                    }
                    KeyCode::Char('d' | 'D') if !has_ctrl => {
                        if state.seed.is_none() {
                            let dice_entropy = "4231246132541623514263514231652413625143625143625132";
                            state.set_entropy_input(dice_entropy);
                            state.status_message = "[DICE VECTOR LOADED] 52 dice rolls populated. Review & press [ENTER].".into();
                        }
                    }
                    KeyCode::Backspace | KeyCode::Char('h') if key.code == KeyCode::Backspace || has_ctrl => {
                        if state.seed.is_none() {
                            state.pop_entropy_char();
                        }
                    }
                    KeyCode::Enter => {
                        if state.seed.is_none() && !state.entropy_input.is_empty() {
                            match crypto::process_physical_entropy(&state.entropy_input) {
                                Ok(seed) => {
                                    let children = crypto::derive_bip85_children(&seed.mnemonic, 20).unwrap_or_default();
                                    state.set_seed(seed, children);
                                }
                                Err(e) => {
                                    state.status_message = format!("[BLOCKED] {}", e);
                                }
                            }
                        }
                    }
                    KeyCode::Char(c) if !has_ctrl && c.is_ascii_alphanumeric() => {
                        if state.seed.is_none() {
                            state.push_entropy_char(c);
                        }
                    }
                    _ => {}
                }
            }
        }
        Page::VpubQr => {
            let has_ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
            match key.code {
                KeyCode::Char('m' | 'M') if !has_ctrl => {
                    state.qr_mode = state.qr_mode.next();
                    state.bbqr_frame_index = 0;
                }
                KeyCode::Char('e' | 'E') if !has_ctrl => {
                    state.export_external_usb();
                }
                _ => {}
            }
        }
        Page::Addresses => {
            match key.code {
                KeyCode::Down | KeyCode::PageDown => {
                    if let Some(ref s) = state.seed {
                        if state.address_page_offset + 25 < s.addresses.len() {
                            state.address_page_offset += 25;
                        }
                    }
                }
                KeyCode::Up | KeyCode::PageUp => {
                    state.address_page_offset = state.address_page_offset.saturating_sub(25);
                }
                _ => {}
            }
        }
        Page::Bip85Children => {
            match key.code {
                KeyCode::Down | KeyCode::PageDown => {
                    if state.heir_page_offset + 10 < state.bip85_children.len() {
                        state.heir_page_offset += 10;
                    }
                }
                KeyCode::Up | KeyCode::PageUp => {
                    state.heir_page_offset = state.heir_page_offset.saturating_sub(10);
                }
                _ => {}
            }
        }
        Page::EstateProvisioner => {
            if !key.modifiers.contains(KeyModifiers::CONTROL) && (key.code == KeyCode::Char('p') || key.code == KeyCode::Char('P')) {
                state.write_estate_vault();
            }
        }
        Page::SeedFix => {
            let has_ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
            match key.code {
                KeyCode::Backspace | KeyCode::Char('h') if key.code == KeyCode::Backspace || has_ctrl => {
                    state.seedfix_input.pop();
                }
                KeyCode::Char(c) if !has_ctrl && (c.is_alphanumeric() || c == ' ') => {
                    state.seedfix_input.push(c);
                }
                _ => {}
            }
        }
        Page::WordlistInspector => {
            let has_ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
            match key.code {
                KeyCode::Backspace | KeyCode::Char('h') if key.code == KeyCode::Backspace || has_ctrl => {
                    state.wordlist_query.pop();
                }
                KeyCode::Char(c) if !has_ctrl && c.is_alphabetic() => {
                    state.wordlist_query.push(c);
                }
                _ => {}
            }
        }
        Page::VaultUnlock => {
            let has_ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
            if has_ctrl && (key.code == KeyCode::Char('m') || key.code == KeyCode::Char('M')) {
                state.vault_mask_passphrase = !state.vault_mask_passphrase;
            } else {
                match key.code {
                    KeyCode::Backspace | KeyCode::Char('h') if key.code == KeyCode::Backspace || has_ctrl => {
                        state.vault_passphrase_input.pop();
                    }
                    KeyCode::Enter => {
                        state.attempt_vault_decrypt();
                    }
                    KeyCode::Char(c) if !has_ctrl && (c.is_alphanumeric() || c == ' ') => {
                        state.vault_passphrase_input.push(c);
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    false
}
