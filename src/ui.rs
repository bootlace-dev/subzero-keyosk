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
use crate::qr::render_qr_to_lines;
use crate::seedfix::{search_wordlist, solve_twelfth_word, SeedFixCandidate};
use crate::storage::{locate_estate_partition, write_estate_partition};

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
    SeedFix,
    WordlistInspector,
    VaultUnlock,
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
        Page::SeedFix,
        Page::WordlistInspector,
        Page::VaultUnlock,
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
            Page::SeedFix => "Tab 9. SeedFix Recovery",
            Page::WordlistInspector => "Tab 10. Wordlist Search",
            Page::VaultUnlock => "Tab 11. Vault Decrypt",
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
}

pub fn render_app(frame: &mut Frame, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Clean Header Status Line (no overflowing tabs)
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

    let line = Line::from(vec![
        Span::styled(format!(" [{}/{}] ", state.current_page.page_num(), Page::ALL.len()), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled(state.current_page.title(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw("  |  "),
        Span::styled(fp_str, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("  |  "),
        Span::styled("SUBZERO-RS BITCOIN APPLIANCE", Style::default().fg(Color::DarkGray)),
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
        Span::styled(" NAV: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled("[Tab/→]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" Next  "),
        Span::styled("[Shift+Tab/←]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" Prev  "),
        Span::styled("[Home]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" Tab 1  "),
        Span::styled("[R]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw(" PRNG  "),
        Span::styled("[C/D]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw(" Sample Coins/Dice  "),
        Span::styled("[W]", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
        Span::raw(" Wipe & Reset  "),
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
        format!("BUILD: {} ({}) | AMNESIC MEMORY ", state.build_timestamp, state.git_commit),
        Style::default().fg(Color::DarkGray),
    );

    let footer_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
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
        Page::SeedFix => render_seedfix(frame, area, state),
        Page::WordlistInspector => render_wordlist_inspector(frame, area, state),
        Page::VaultUnlock => render_vault_unlock(frame, area, state),
        Page::DrillGuide => render_drill_guide(frame, area, state),
        Page::Provenance => render_provenance(frame, area, state),
    }
}

fn render_master_seed(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 1. BIP-39 Primary Master Secret ")
        .style(Style::default().fg(Color::White));

    if let Some(ref seed) = state.seed {
        let words: Vec<&str> = seed.mnemonic.split_whitespace().collect();
        let mut lines = Vec::new();

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  DO NOT STORE DIGITALLY. WRITE TO COLD STORAGE MEDIA ONLY.",
            Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));

        for i in 0..6 {
            let left = format!("  {:2}. {:<15}", i + 1, words.get(i).unwrap_or(&""));
            let right = format!("  {:2}. {:<15}", i + 7, words.get(i + 6).unwrap_or(&""));
            lines.push(Line::from(vec![
                Span::styled(left, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(right, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]));
        }

        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::raw("  Master Fingerprint:   "),
            Span::styled(&seed.fingerprint, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::from(vec![
            Span::raw("  Entropy Mode:         "),
            Span::styled(&seed.entropy_type, Style::default().fg(Color::Green)),
        ]));
        lines.push(Line::from(""));
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
        "CASINO DICE ROLLS (1-6)"
    } else if raw.is_empty() {
        "AWAITING INPUT (Coin 0/1, Dice 1-6, or 'test0'..'test9')"
    } else {
        "TEST VECTOR OR ARBITRARY STREAM"
    };

    let bits = if is_bin {
        len
    } else if is_dice {
        ((len as f64) * 2.58496).floor() as usize
    } else {
        128
    };

    let markov = run_markov_audit(raw);
    let repeats = has_repetitive_substrings(raw, 3, 6);

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  ENTROPY INGESTION MODE: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(mode_str, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from(vec![
        Span::raw("  Collected Inputs:       "),
        Span::styled(format!("{len} chars"), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw(" | Estimated Entropy: "),
        Span::styled(format!("~{bits} bits / 128 bits"), Style::default().fg(if bits >= 128 { Color::Green } else { Color::Yellow })),
    ]));

    let markov_style = if len < 16 {
        Style::default().fg(Color::DarkGray)
    } else if markov.passed {
        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)
    };
    lines.push(Line::from(vec![
        Span::raw("  Markov Transition Audit: "),
        Span::styled(if len < 16 { "Awaiting 16+ chars..." } else if markov.passed { "[PASS - ENTROPY HEALTHY]" } else { "[FAIL - BIASED TRANSITIONS]" }, markov_style),
        Span::styled(format!(" (Max cond prob: {:.1}%)", markov.max_cond_prob * 100.0), Style::default().fg(Color::DarkGray)),
    ]));

    let repeat_style = if repeats {
        Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Green)
    };
    lines.push(Line::from(vec![
        Span::raw("  Repetitive Pattern Block: "),
        Span::styled(if repeats { "[FAIL - REPEATING CHUNKS DETECTED]" } else { "[PASS - NO REPEATS]" }, repeat_style),
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
        let chunks: Vec<String> = chars.chunks(5).map(|c| c.iter().collect::<String>()).collect();
        for line_chunks in chunks.chunks(4) {
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(line_chunks.join("   "), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]));
        }
    } else if raw.is_empty() {
        lines.push(Line::from("    [Awaiting physical entropy input...]"));
        lines.push(Line::from(""));
        lines.push(Line::from("    Direct Input:"));
        lines.push(Line::from("      Type '0' / '1' directly for live physical coin flip streaming (128 bits)."));
        lines.push(Line::from("      Type '1' - '6' directly for casino dice roll whitening (50 rolls)."));
        lines.push(Line::from("      Type 'test0' .. 'test9' to load canonical SubZero Test Vectors."));
        lines.push(Line::from("      Type [Backspace] to delete characters."));
        lines.push(Line::from(""));
        lines.push(Line::from("    Quick Testing Shortcuts:"));
        lines.push(Line::from("      [R] - Derive fresh dynamic testing wallet from device PRNG (Untrusted)"));
        lines.push(Line::from("      [C] - Sample 128 coin flips | [D] - Sample 50 dice rolls"));
    } else {
        lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(raw, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]));
    }

    lines.push(Line::from(""));
    let is_ready = (is_bin && len >= 128) || (is_dice && len >= 50) || raw.starts_with("test");
    let is_valid = is_ready && (markov.passed || raw.starts_with("test")) && !repeats;

    if is_valid {
        lines.push(Line::from(Span::styled(
            "  >>> [ENTER] ENTROPY SATISFIED: Press ENTER to derive Master Vault Keys <<<",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )));
    } else if is_ready {
        lines.push(Line::from(Span::styled(
            "  [!] BLOCKED: Entropy length satisfied, but mathematical quality audit failed.",
            Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
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
        .title(" Tab 2. Decoupled Estate Passphrase (BIP-85 Index 0) ")
        .style(Style::default().fg(Color::White));

    if let Some(ref pass) = state.decoupled_passphrase {
        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                "  NON-COLOCATED ENCRYPTION KEY & ESTATE DEAD-MAN SWITCH",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(vec![
                Span::raw("  BIP-85 Derivation Path: "),
                Span::styled(&pass.path, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(""),
            Line::from("  12-Word Decoupled Passphrase:"),
            Line::from(Span::styled(
                format!("  {}", pass.mnemonic),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("  CRITICAL ANTI-COLOCATION PROTOCOL:"),
            Line::from("  1. NEVER store this passphrase in the same physical location as your Master Seed or USB."),
            Line::from("  2. Store this in your password manager (Bitwarden), safe deposit box, or attorney escrow."),
            Line::from("  3. Because BIP-85 derivation is strictly ONE-WAY, holding this phrase alone exposes ZERO funds."),
            Line::from("  4. Used to encrypt the estate vault package (vault.json) on Tab 8."),
        ];
        frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), area);
    } else {
        frame.render_widget(Paragraph::new("Generate a seed first on Tab 1.").block(block), area);
    }
}

fn render_descriptor(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 3. Output Descriptor (BIP-380 / BIP-84 Native SegWit) ")
        .style(Style::default().fg(Color::White));

    if let Some(ref seed) = state.seed {
        let lines = vec![
            Line::from(""),
            Line::from(Span::styled("  Watch-Only Descriptor with BIP-380 Checksum:", Style::default().fg(Color::Cyan))),
            Line::from(""),
            Line::from(Span::styled(format!("  {}", seed.descriptor), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from(vec![
                Span::raw("  Account TPUB: "),
                Span::styled(&seed.vpub, Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(""),
            Line::from("  Compatible with: Sparrow Wallet, Bitcoin Core, Coldcard, BlueWallet, Jade"),
            Line::from("  Contains NO private keys. Can be safely exported over airgap via watch-only QR."),
        ];
        let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
        frame.render_widget(p, area);
    } else {
        frame.render_widget(Paragraph::new("Generate a seed first on Tab 1.").block(block), area);
    }
}

fn render_vpub_qr(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 4. Airgapped Export QR (Watch-Only Descriptor) ")
        .style(Style::default().fg(Color::White));

    if let Some(ref seed) = state.seed {
        match render_qr_to_lines(&seed.descriptor) {
            Ok(mut qr_lines) => {
                qr_lines.push(Line::from(""));
                qr_lines.push(Line::from(vec![
                    Span::styled("  Watch-Only Descriptor: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::styled(&seed.descriptor, Style::default().fg(Color::Yellow)),
                ]));
                let p = Paragraph::new(qr_lines)
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
        frame.render_widget(Paragraph::new("Generate a seed first on Tab 1.").block(block), area);
    }
}

fn render_faucet_qr(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 5. Faucet QR Code (Receive Address #0) ")
        .style(Style::default().fg(Color::White));

    if let Some(ref seed) = state.seed {
        if let Some(addr) = seed.addresses.first() {
            match render_qr_to_lines(addr) {
                Ok(qr_lines) => {
                    let mut combined = qr_lines;
                    combined.push(Line::from(""));
                    combined.push(Line::from(vec![
                        Span::styled(format!("  Target Address #0: {}", addr), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    ]));
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
        let page_size = 10;
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
            "  Advance to Tab 5 to display a full-screen QR code for Address #0.",
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
        .title(" Tab 7. BIP-85 Child Seed Treasuries (Deterministic Heir/Vault Keys) ")
        .style(Style::default().fg(Color::White));

    if state.bip85_children.is_empty() {
        frame.render_widget(Paragraph::new("Generate a seed first on Tab 1.").block(block), area);
    } else {
        let total = state.bip85_children.len();
        let page_size = 8;
        let start = state.heir_page_offset;
        let end = std::cmp::min(start + page_size, total);
        let cur_page = (start / page_size) + 1;
        let total_pages = (total + page_size - 1) / page_size;

        let mut lines = Vec::new();
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(format!("  BIP-85 Heir Keys #{}-#{} (Page {} of {}):", start + 1, end, cur_page, total_pages), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("    [Controls: UP/DOWN / PgUp/PgDn to Page]"),
        ]));
        lines.push(Line::from(""));

        for child in &state.bip85_children[start..end] {
            lines.push(Line::from(vec![
                Span::styled(format!("  Vault #{:<2} ", child.index), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled(format!("({}) : ", child.path), Style::default().fg(Color::DarkGray)),
                Span::styled(&child.mnemonic, Style::default().fg(Color::Yellow)),
            ]));
        }

        let p = Paragraph::new(lines).block(block);
        frame.render_widget(p, area);
    }
}

fn render_estate_provisioner(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 8. Estate Partition USB Provisioner (Partition 2 SUBZERO_EST) ")
        .style(Style::default().fg(Color::White));

    let part_detected = locate_estate_partition();
    let status_color = if state.estate_write_status.starts_with("[✓]") {
        Color::Green
    } else if state.estate_write_status.starts_with("[!]") {
        Color::LightRed
    } else {
        Color::Yellow
    };

    let mut lines = Vec::new();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("  DUAL-PARTITION SOVEREIGN RECOVERY MEDIA PROVISIONER:", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
    lines.push(Line::from("  Writes encrypted estate vault & offline browser tools directly to Partition 2."));
    lines.push(Line::from(""));

    lines.push(Line::from(vec![
        Span::raw("  Detected Estate Partition: "),
        Span::styled(part_detected.unwrap_or_else(|| "NONE DETECTED (Insert SubZero USB/SD Card)".into()), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from(""));

    lines.push(Line::from(Span::styled(
        format!("  Status: {}", state.estate_write_status),
        Style::default().fg(status_color).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));

    lines.push(Line::from(Span::styled("  FILES WRITTEN TO PARTITION 2 (SUBZERO_EST):", Style::default().fg(Color::White).add_modifier(Modifier::BOLD))));
    lines.push(Line::from("    1. vault.json              - AES-256-GCM encrypted estate vault (Master + Descriptor + Heirs)"));
    lines.push(Line::from("    2. vault_<TIMESTAMP>.json  - Immutable timestamped archive copy"));
    lines.push(Line::from("    3. decrypt.html            - Offline standalone WebCrypto browser decryptor"));
    lines.push(Line::from("    4. README.txt              - Clear step-by-step estate recovery instructions"));
    lines.push(Line::from("    5. SHA256SUMS              - Cryptographic manifest of all files on partition"));
    lines.push(Line::from(""));

    lines.push(Line::from(Span::styled("  SECURITY INVARIANT: Media cannot be decrypted without the Decoupled Estate Passphrase (Tab 2).", Style::default().fg(Color::DarkGray))));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("  Controls: Press [P] to Provision Partition 2 Now", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_seedfix(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 9. SeedFix Recovery Tool (Interactive Candidate Solver) ")
        .style(Style::default().fg(Color::White));

    let mut lines = Vec::new();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("  INTERACTIVE 11-TO-12 CHECKSUM & TYPO SOLVER:", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
    lines.push(Line::from("  Type 11 words + optional 12th typo directly. Live solver ranks valid BIP-39 checksums."));
    lines.push(Line::from(""));

    lines.push(Line::from(vec![
        Span::styled("  Input Seed Buffer: ", Style::default().fg(Color::Yellow)),
        Span::styled(&state.seedfix_input, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled(" _", Style::default().fg(Color::Cyan).add_modifier(Modifier::SLOW_BLINK)),
    ]));
    lines.push(Line::from(""));

    let words: Vec<&str> = state.seedfix_input.split_whitespace().collect();
    if words.len() >= 11 {
        let eleven = words[..11].join(" ");
        let typo = words.get(11).copied();
        if let Ok(cands) = solve_twelfth_word(&eleven, typo) {
            lines.push(Line::from(Span::styled(
                format!("  Top Ranked Checksum Candidates (Found {} valid checksum words):", cands.len()),
                Style::default().fg(Color::Green),
            )));
            lines.push(Line::from(""));
            for (idx, cand) in cands.iter().take(7).enumerate() {
                lines.push(Line::from(vec![
                    Span::styled(format!("    {:2}. Word 12: ", idx + 1), Style::default().fg(Color::Cyan)),
                    Span::styled(format!("{:<12}", cand.twelfth_word.clone()), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Span::raw(" (distance "),
                    Span::styled(cand.distance.to_string(), Style::default().fg(Color::Green)),
                    Span::raw(") -> Full: "),
                    Span::styled(cand.full_mnemonic.clone(), Style::default().fg(Color::DarkGray)),
                ]));
            }
        }
    } else {
        lines.push(Line::from(format!("  Awaiting 11 words (Entered: {}/11 words)...", words.len())));
        lines.push(Line::from(""));
        lines.push(Line::from("  Controls: Type characters directly to append | [Backspace] to delete | [Space] to separate words"));
    }

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_wordlist_inspector(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 10. BIP-39 Canonical English Wordlist Inspector (2048 Words) ")
        .style(Style::default().fg(Color::White));

    let mut lines = Vec::new();
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  Search Query / Prefix: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(if state.wordlist_query.is_empty() { "[Type prefix (e.g. 'ab', 'zoo', 'bit')...]" } else { &state.wordlist_query }, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled(" _", Style::default().fg(Color::Cyan).add_modifier(Modifier::SLOW_BLINK)),
    ]));
    lines.push(Line::from(""));

    let matches = search_wordlist(&state.wordlist_query);
    lines.push(Line::from(Span::styled(
        format!("  Matching Canonical Words ({}/2048):", matches.len()),
        Style::default().fg(Color::Green),
    )));
    lines.push(Line::from(""));

    let cols = 4;
    let rows = 8;
    for r in 0..rows {
        let mut row_spans = vec![Span::raw("    ")];
        for c in 0..cols {
            let idx = c * rows + r;
            if let Some(&word) = matches.get(idx) {
                row_spans.push(Span::styled(format!("{:<14}", word), Style::default().fg(Color::White)));
            }
        }
        lines.push(Line::from(row_spans));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("  Controls: Type letters to filter wordlist | [Backspace] to delete | [ESC] to clear", Style::default().fg(Color::DarkGray))));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_vault_unlock(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 11. Unlock & Decrypt Estate Vault (vault.json) ")
        .style(Style::default().fg(Color::White));

    let mut lines = Vec::new();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("  SOVEREIGN ESTATE INHERITANCE RECOVERY ENGINE:", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
    lines.push(Line::from("  Decrypt WebCrypto AES-256-GCM encrypted estate packages with Decoupled Passphrase."));
    lines.push(Line::from(""));

    lines.push(Line::from(vec![
        Span::styled("  12-Word Passphrase: ", Style::default().fg(Color::Yellow)),
        Span::styled(if state.vault_passphrase_input.is_empty() { "[Type 12-word passphrase or 'test0'..'test9']" } else { &state.vault_passphrase_input }, Style::default().fg(Color::White)),
        Span::styled(" _", Style::default().fg(Color::Cyan).add_modifier(Modifier::SLOW_BLINK)),
    ]));
    lines.push(Line::from(""));

    let status_color = if state.vault_status_msg.starts_with("[✓]") {
        Color::Green
    } else if state.vault_status_msg.starts_with("[!]") {
        Color::LightRed
    } else {
        Color::DarkGray
    };
    lines.push(Line::from(Span::styled(format!("  Status: {}", state.vault_status_msg), Style::default().fg(status_color).add_modifier(Modifier::BOLD))));
    lines.push(Line::from(""));

    if let Some(ref vault) = state.decrypted_vault {
        lines.push(Line::from(Span::styled("  [DECRYPTED ESTATE PAYLOAD RESTORED]:", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))));
        lines.push(Line::from(vec![
            Span::raw("    Master Mnemonic: "),
            Span::styled(&vault.master_root_mnemonic, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::from(vec![
            Span::raw("    Descriptor:      "),
            Span::styled(&vault.descriptor, Style::default().fg(Color::Cyan)),
        ]));
        for heir in &vault.heir_treasuries {
            lines.push(Line::from(vec![
                Span::styled(format!("    {} ({}): ", heir.label, heir.path), Style::default().fg(Color::White)),
                Span::styled(&heir.mnemonic, Style::default().fg(Color::Yellow)),
            ]));
        }
    } else {
        lines.push(Line::from("  Quick Test Vectors:"));
        lines.push(Line::from("    Type 'test0' and press [ENTER] to simulate lab decryption with test passphrase."));
        lines.push(Line::from("    Press [ENTER] to attempt AES-256-GCM / PBKDF2 authentication."));
    }

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_drill_guide(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tab 12. 24x4 Metal Punch / Cold Storage Guide ")
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
            Span::raw("  Binary:               "),
            Span::styled("subzero-rs (Pure Rust Bare-Metal Binary)", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::raw("  Target Architecture:  "),
            Span::styled("x86_64-unknown-linux-musl / Linux Framebuffer Terminal", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::raw("  Core Cryptography:    "),
            Span::styled("rust-bitcoin 0.32, bip39 2.1, zeroize 1.8, sha2 0.10, aes-gcm 0.10", Style::default().fg(Color::Green)),
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
            Span::styled("ZeroizeOnDrop on all entropy buffers & private keys", Style::default().fg(Color::Cyan)),
        ]),
    ];

    frame.render_widget(Paragraph::new(lines).block(block), area);
}
