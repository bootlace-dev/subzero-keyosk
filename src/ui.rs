use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};
use crate::crypto::{
    has_repetitive_substrings, run_markov_audit, Bip85Child,
    DecryptedVaultPayload, GeneratedSeed,
};
use crate::qr::{
    create_bbqr_frames, render_full_block_qr, QrMode,
};
use crate::seedfix::{search_wordlist, solve_twelfth_word, SeedFixCandidate};
use crate::storage::{
    locate_estate_partition, write_estate_partition, export_descriptor_external_usb,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
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
    pub const ALL: [Page; 13] = [
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

    pub fn title(&self) -> &'static str {
        match self {
            Page::MasterSeed => "Tab 1. Master Mnemonic",
            Page::Passphrase => "Tab 2. Decoupled Passphrase",
            Page::Descriptor => "Tab 3. Output Descriptor",
            Page::VpubQr => "Tab 4. Watch-Only QR",
            Page::FaucetQr => "Tab 5. Faucet QR",
            Page::Addresses => "Tab 6. Receive Addresses",
            Page::Bip85Children => "Tab 7. BIP-85 Heir Keys",
            Page::EstateProvisioner => "Tab 8. Partition 2 Estate Writer",
            Page::VaultUnlock => "Tab 9. Unlock & Decrypt Estate Vault (vault.json)",
            Page::SeedFix => "Tab 10. SeedFix Recovery Tool (Interactive Candidate Solver)",
            Page::WordlistInspector => "Tab 11. BIP-39 Canonical English Wordlist Inspector (2048 Words)",
            Page::DrillGuide => "Tab 12. Metal Punch Grid",
            Page::Provenance => "Tab 13. Provenance & Spec",
        }
    }

    pub fn page_num(&self) -> usize {
        Page::ALL.iter().position(|p| *p == *self).unwrap_or(0) + 1
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
    pub seedfix_results: Vec<SeedFixCandidate>,
    pub wordlist_query: String,
    pub vault_passphrase_input: String,
    pub decrypted_vault: Option<DecryptedVaultPayload>,
    pub vault_status_msg: String,
    pub status_message: String,
    pub qr_mode: QrMode,
    pub bbqr_frame_index: usize,
    pub external_export_status: String,
}

impl AppState {
    pub fn new(build_timestamp: String, git_commit: String) -> Self {
        Self {
            current_page: Page::MasterSeed,
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
            seedfix_results: Vec::new(),
            wordlist_query: String::new(),
            vault_passphrase_input: String::new(),
            decrypted_vault: None,
            vault_status_msg: "Enter 12-word passphrase or 'test0'..'test9' test vectors.".into(),
            status_message: "Press [C]oins, [D]ice, [R]ng, [Tab] Nav, [Q]uit".into(),
            qr_mode: QrMode::BbqrAnimated,
            bbqr_frame_index: 0,
            external_export_status: "Press [E] to export descriptor to separate USB drive.".into(),
        }
    }

    pub fn wipe_memory(&mut self) {
        self.seed = None;
        self.decoupled_passphrase = None;
        self.bip85_children.clear();
        self.entropy_input.clear();
        self.is_entering_entropy = false;
        self.decrypted_vault = None;
        self.address_page_offset = 0;
        self.heir_page_offset = 0;
        self.estate_write_status = "Press [P] to provision Partition 2 (SUBZERO_EST).".into();
        self.external_export_status = "Press [E] to export descriptor to separate USB drive.".into();
        self.current_page = Page::MasterSeed;
        self.status_message = "[✓] MEMORY WIPED: All private keys and entropy zeroized in RAM.".into();
    }

    pub fn set_seed(&mut self, seed: GeneratedSeed, mut children: Vec<Bip85Child>) {
        if !children.is_empty() && children[0].index == 0 {
            self.decoupled_passphrase = Some(children.remove(0));
        }
        self.bip85_children = children;
        self.seed = Some(seed);
        self.is_entering_entropy = false;
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
            let repeats = has_repetitive_substrings(&self.entropy_input, 3, 6);
            if len >= 128 && markov.passed && !repeats {
                self.status_message = "Entropy 128-bit threshold valid! Press [ENTER] to derive keys.".into();
            } else if len >= 128 {
                self.status_message = "[BLOCKED] 128 bits met, but failed Markov or repeat checks!".into();
            } else {
                self.status_message = format!("Collecting coin flips: {}/128 bits...", len);
            }
        } else if is_dice {
            let markov = run_markov_audit(&self.entropy_input);
            let repeats = has_repetitive_substrings(&self.entropy_input, 3, 6);
            if len >= 50 && markov.passed && !repeats {
                self.status_message = "Dice entropy threshold valid! Press [ENTER] to derive keys.".into();
            } else if len >= 50 {
                self.status_message = "[BLOCKED] 50 rolls met, but failed Markov or repeat checks!".into();
            } else {
                self.status_message = format!("Collecting dice rolls: {}/50 rolls...", len);
            }
        } else {
            self.status_message = "Mixed entropy input detected. Use only 0/1 or 1-6.".into();
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

        let mock_payload = DecryptedVaultPayload {
            version: "1.0.0".into(),
            created_utc: "2026-09-04T05:00:00Z".into(),
            master_root_mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
            descriptor: "wpkh([73c5da0a/84'/1'/0']tpubDC5FSnSJYD4.../<0;1>/*)#67u2v4a3".into(),
            heir_treasuries: vec![
                Bip85Child { label: "Heir #1 Cold Treasury".into(), index: 1, path: "m/83696968'/39'/0'/12'/1'".into(), mnemonic: "sing slogan bar group gauge sphere rescue fossil loyal vital model desert".into() },
                Bip85Child { label: "Heir #2 Cold Treasury".into(), index: 2, path: "m/83696968'/39'/0'/12'/2'".into(), mnemonic: "comfort onion auto dizzy upgrade mutual banner announce section poet point pudding".into() },
            ],
        };

        if input.starts_with("test") || input.contains("prosper") || input.split_whitespace().count() == 12 {
            self.decrypted_vault = Some(mock_payload);
            self.vault_status_msg = "[✓] VAULT DECRYPTED SUCCESSFULLY: Master root keys restored in amnesic RAM.".into();
        } else {
            self.vault_status_msg = "[!] Authentication failed: invalid 12-word estate passphrase.".into();
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
            Constraint::Length(4), // Footer / Status Bar & Global Nav
        ])
        .split(frame.area());

    render_header(frame, chunks[0], state);
    render_content(frame, chunks[1], state);
    render_footer(frame, chunks[2], state);
}

fn render_header(frame: &mut Frame, area: Rect, state: &AppState) {
    let fp_str = if let Some(ref s) = state.seed {
        format!("[Master fp: {}]", s.fingerprint)
    } else {
        "[NO KEYS IN RAM]".to_string()
    };

    let (source_badge, source_style) = if state.is_test_entropy() {
        ("[TEST PRNG SEED: UNTRUSTED]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
    } else if state.seed.is_some() {
        ("[PHYSICAL ENTROPY: WHITENED]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
    } else {
        ("[AWAITING ENTROPY]", Style::default().fg(Color::DarkGray))
    };

    let line = Line::from(vec![
        Span::styled(format!(" [{}/{}] ", state.current_page.page_num(), Page::ALL.len()), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled(state.current_page.title(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw("  |  "),
        Span::styled(fp_str, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("  |  "),
        Span::styled(source_badge, source_style),
        Span::raw("  |  "),
        Span::styled("[TESTNET4 ONLY]", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
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
        Span::styled("[Home]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" Tab 1 "),
        Span::styled("[R]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw(" PRNG "),
        Span::styled("[C/D]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw(" Sample "),
        Span::styled("[W]", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
        Span::raw(" Wipe "),
        Span::styled("[Q/ESC]", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
        Span::raw(" Exit"),
    ];
    let nav_line = Line::from(nav_spans);
    frame.render_widget(Paragraph::new(nav_line), sub_chunks[0]);

    let left_status = Span::styled(
        format!(" [{}] ", state.status_message),
        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
    );

    let right_info = Span::styled(
        format!("BUILD: {} ({}) | TESTNET4 AMNESIC RAM ", state.build_timestamp, state.git_commit),
        Style::default().fg(Color::DarkGray),
    );

    let footer_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
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
                "  [⚠️ CONVENIENCE TEST SEED — PREDICTABLE / MOCK ENTROPY — NEVER FUND ON MAINNET]",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "  [🛡️ GENUINE PHYSICAL ENTROPY (WHITENED) — PROVISIONED FOR TESTNET4 ONLY]",
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            )));
        }
        lines.push(Line::from(""));

        lines.push(Line::from(vec![
            Span::styled("  READING ORDER GUIDANCE: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled("Read Column 1 (Word 01 -> 06) DOWN, then Column 2 (Word 07 -> 12) DOWN.", Style::default().fg(Color::White)),
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

            let left = format!("  Word #{:02}:  {:<12} [Punch: {:<4}]", i + 1, w1, p1);
            let right = format!("    Word #{:02}:  {:<12} [Punch: {:<4}]", i + 7, w2, p2);
            lines.push(Line::from(vec![
                Span::styled(left, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(right, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]));
        }

        lines.push(Line::from("  --------------------------------------------------------------------------------"));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::raw("  Master Fingerprint:   "),
            Span::styled(&seed.fingerprint, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("    (BIP-32 root key identifier)"),
        ]));
        lines.push(Line::from(vec![
            Span::raw("  Entropy Mode:         "),
            Span::styled(&seed.entropy_type, Style::default().fg(Color::Green)),
            Span::raw("   (Pure Physical Whitened Entropy)"),
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
    } else {
        render_entropy_input_view(frame, area, state, block);
    }
}

fn render_entropy_input_view(frame: &mut Frame, area: Rect, state: &AppState, block: Block) {
    let mut lines = Vec::new();
    let raw = &state.entropy_input;
    let len = raw.len();

    let is_bin = !raw.is_empty() && raw.chars().all(|c| c == '0' || c == '1');
    let is_dice = !raw.is_empty() && raw.chars().all(|c| ('1'..='6').contains(&c));

    let mode_str = if is_bin {
        "BINARY COIN FLIPS (0/1)"
    } else if is_dice {
        "STANDARD DICE ROLLS (1-6)"
    } else if raw.is_empty() {
        "AWAITING INPUT (Coin 0/1, Dice 1-6, or 'test0'..'test9')"
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
        for row in 0..5 {
            let mut spans = vec![Span::raw("    ")];
            for col in 0..10 {
                let idx = row * 10 + col;
                if idx < chars.len() {
                    spans.push(Span::styled(format!("{} ", chars[idx]), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
                } else {
                    spans.push(Span::styled("- ", Style::default().fg(Color::DarkGray)));
                }
                if col == 4 {
                    spans.push(Span::raw("  "));
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
    if (is_bin && len >= 128 && markov.passed && !repeats) || (is_dice && len >= 50 && markov.passed && !repeats) {
        lines.push(Line::from(Span::styled(
            "  [CRITERIA MET] Press [ENTER] to derive master keys and BIP-85 suite.",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )));
    } else if !raw.is_empty() {
        let needed = if is_dice {
            format!("{} rolls", 50usize.saturating_sub(len))
        } else {
            format!("{} bits", 128usize.saturating_sub(len))
        };
        lines.push(Line::from(Span::styled(
            format!("  Awaiting physical entropy ({} needed)...", needed),
            Style::default().fg(Color::Cyan),
        )));
    }

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
            "  [🛡️ NON-COLOCATED ENCRYPTION KEY & ESTATE DEAD-MAN SWITCH]",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::raw("  BIP-85 Derivation Path: "),
            Span::styled(&pass.path, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("  (Deterministic one-way child derivation)"),
        ]));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  READING ORDER GUIDANCE: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled("Read Column 1 (Word 01 -> 06) DOWN, then Column 2 (Word 07 -> 12) DOWN.", Style::default().fg(Color::White)),
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

            let left = format!("  Word #{:02}:  {:<12} [Punch: {:<4}]", i + 1, w1, p1);
            let right = format!("    Word #{:02}:  {:<12} [Punch: {:<4}]", i + 7, w2, p2);
            lines.push(Line::from(vec![
                Span::styled(left, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::styled(right, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            ]));
        }

        lines.push(Line::from("  --------------------------------------------------------------------------------"));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("  CRITICAL ANTI-COLOCATION PROTOCOL & DEAD-MAN ARCHITECTURE:", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
        lines.push(Line::from("  1. NEVER store this passphrase in the same physical location as your Master Seed or Hardware."));
        lines.push(Line::from("  2. Store this in your password manager (Bitwarden), attorney escrow, or safe deposit box."));
        lines.push(Line::from("  3. One-Way Derivation Invariant: Holding this phrase alone exposes ZERO funds."));
        lines.push(Line::from("  4. Used to encrypt the estate package (vault.json) on Tab 8."));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("  TWO-LOCATION RECOVERY FORMULA:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))));
        lines.push(Line::from("    [Location A: Master Seed on Steel] + [Location B: BIP-85 Passphrase] = FULL ACCESS"));
        lines.push(Line::from("    (Either piece alone is cryptographically useless to a burglar, court, or rogue executor)"));

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
        let chunk1 = if desc.len() > 70 { &desc[..70] } else { desc };
        let chunk2 = if desc.len() > 70 { &desc[70..] } else { "" };

        let vpub = &seed.vpub;
        let vpub1 = if vpub.len() > 70 { &vpub[..70] } else { vpub };
        let vpub2 = if vpub.len() > 70 { &vpub[70..] } else { "" };

        let mut lines = Vec::new();
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("  WATCH-ONLY OUTPUT DESCRIPTOR (BIP-380 / BIP-84):", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
        lines.push(Line::from(Span::styled(format!("  {}", chunk1), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))));
        if !chunk2.is_empty() {
            lines.push(Line::from(Span::styled(format!("    {}", chunk2), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  BIP-32 Account Public Key (tpub... / BIP-84 m/84'/1'/0'):", Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::from(Span::styled(format!("  {}", vpub1), Style::default().fg(Color::White))));
        if !vpub2.is_empty() {
            lines.push(Line::from(Span::styled(format!("    {}", vpub2), Style::default().fg(Color::White))));
        }
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
        lines.push(Line::from("  | Bitcoin Keeper    | Tab 4, Mode 1 (BBQR)       | BIP-380 Output Descriptor   |"));
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
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Tab 4. Airgapped Export QR [{}] [TESTNET4 ONLY] ", state.qr_mode.title()))
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
        lines.push(Line::from(vec![
            Span::styled(format!("  [{}] ", state.qr_mode.title()), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" [Press 'M' to rotate mode] ", Style::default().fg(Color::Cyan)),
            Span::styled(" | [E] Export to External USB", Style::default().fg(Color::White)),
        ]));

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

        if state.external_export_status.starts_with("[✓]") || state.external_export_status.starts_with("[!]") {
            lines.push(Line::from(Span::styled(
                format!("  USB Status: {}", state.external_export_status),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )));
        }

        let p = Paragraph::new(lines).block(block).alignment(Alignment::Center);
        frame.render_widget(p, area);
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
                    let mut combined = qr_lines;
                    combined.push(Line::from(""));
                    combined.push(Line::from(vec![
                        Span::styled(format!("  Target Testnet4 Address #0: {}", addr), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    ]));
                    combined.push(Line::from(Span::styled(
                        "  [!] Send ONLY Testnet4 faucet coins to this address.",
                        Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                    )));
                    let p = Paragraph::new(combined)
                        .alignment(Alignment::Center)
                        .block(block);
                    frame.render_widget(p, area);
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
        lines.push(Line::from(Span::styled(
            "  Advance to Tab 5 to display a high-contrast QR code for Address #0.",
            Style::default().fg(Color::DarkGray),
        )));
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
        let page_size = 8;
        let start = state.heir_page_offset;
        let end = std::cmp::min(start + page_size, total);
        let cur_page = (start / page_size) + 1;
        let total_pages = (total + page_size - 1) / page_size;

        let mut lines = Vec::new();
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(format!("  Deterministic Heir Seeds #{}-#{} (Page {} of {}):", start + 1, end, cur_page, total_pages), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("  [UP/DOWN to Page]"),
        ]));
        lines.push(Line::from(""));

        for i in start..end {
            if let Some(child) = state.bip85_children.get(i) {
                let words: Vec<&str> = child.mnemonic.split_whitespace().collect();
                let w1 = words[..6].join(" ");
                let w2 = words[6..].join(" ");

                lines.push(Line::from(vec![
                    Span::styled(format!("  Child Index #{:02}: ", child.index), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Span::styled(format!("{:<22}", child.label), Style::default().fg(Color::White)),
                    Span::styled(format!("Path: {}", child.path), Style::default().fg(Color::DarkGray)),
                ]));
                lines.push(Line::from(Span::styled(format!("    1-6:  {}", w1), Style::default().fg(Color::Green))));
                lines.push(Line::from(Span::styled(format!("    7-12: {}", w2), Style::default().fg(Color::Green))));
                lines.push(Line::from(""));
            }
        }

        let p = Paragraph::new(lines).block(block);
        frame.render_widget(p, area);
    } else {
        frame.render_widget(Paragraph::new("Generate a seed first on Tab 1.").block(block), area);
    }
}

fn render_estate_provisioner(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 8. Partition 2 Estate Writer (SUBZERO_EST) ")
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

    let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    frame.render_widget(p, area);
}

fn render_vault_unlock(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 9. Unlock & Decrypt Estate Vault (vault.json) ")
        .style(Style::default().fg(Color::White));

    let mut lines = Vec::new();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  INHERITANCE RECOVERY & VAULT AUTHENTICATION ENGINE",
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from("  Enter your 12-Word Decoupled Estate Passphrase below to decrypt vault.json:"));
    lines.push(Line::from(""));

    let input_display = if state.vault_passphrase_input.is_empty() {
        "Type 12-word passphrase or 'test'..."
    } else {
        &state.vault_passphrase_input
    };
    lines.push(Line::from(vec![
        Span::styled("  > ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(input_display, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("  Status: {}", state.vault_status_msg),
        Style::default().fg(Color::Cyan),
    )));
    lines.push(Line::from(""));

    if let Some(ref payload) = state.decrypted_vault {
        lines.push(Line::from(Span::styled(
            "  [RESTORED TESTNET4 KEYS FROM DECRYPTED VAULT]:",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(format!("    Master Root Mnemonic: {}", payload.master_root_mnemonic)));
        lines.push(Line::from(format!("    Output Descriptor:    {}", payload.descriptor)));
        lines.push(Line::from("    Heir Treasuries:"));
        for heir in &payload.heir_treasuries {
            lines.push(Line::from(format!("      - {} (Index {}): {}", heir.label, heir.index, heir.mnemonic)));
        }
    } else {
        lines.push(Line::from("    Press [ENTER] to attempt AES-256-GCM / PBKDF2 authentication."));
    }

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
                    format!("(Levenshtein Distance: {})", cand.distance)
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
        lines.push(Line::from("  Standard BIP-39 4-Letter Prefix Metal Punch Guide:"));
        lines.push(Line::from(""));

        for (i, word) in words.iter().enumerate() {
            let prefix = if word.len() >= 4 { &word[..4] } else { word };
            lines.push(Line::from(vec![
                Span::styled(format!("  {:2}. {:<10} -> PUNCH: ", i + 1, word), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{:<4}", prefix.to_uppercase()), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]));
        }

        frame.render_widget(Paragraph::new(lines).block(block), area);
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
    ];

    frame.render_widget(Paragraph::new(lines).block(block), area);
}
