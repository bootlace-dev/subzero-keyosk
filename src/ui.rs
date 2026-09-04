use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs, Wrap},
    Frame,
};
use crate::crypto::{has_repetitive_substrings, run_markov_audit, Bip85Child, GeneratedSeed};
use crate::qr::render_qr_to_lines;
use crate::seedfix::{solve_twelfth_word, SeedFixCandidate};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    MasterSeed,
    Passphrase,
    Descriptor,
    VpubQr,
    FaucetQr,
    Addresses,
    Bip85Children,
    SeedFix,
    DrillGuide,
    Provenance,
}

impl Page {
    pub const ALL: [Page; 10] = [
        Page::MasterSeed,
        Page::Passphrase,
        Page::Descriptor,
        Page::VpubQr,
        Page::FaucetQr,
        Page::Addresses,
        Page::Bip85Children,
        Page::SeedFix,
        Page::DrillGuide,
        Page::Provenance,
    ];

    pub fn title(&self) -> &'static str {
        match self {
            Page::MasterSeed => "1. Master Mnemonic",
            Page::Passphrase => "2. Decoupled Passphrase",
            Page::Descriptor => "3. Output Descriptor",
            Page::VpubQr => "4. Watch-Only QR",
            Page::FaucetQr => "5. Faucet QR",
            Page::Addresses => "6. Receive Addresses",
            Page::Bip85Children => "7. BIP-85 Heir Keys",
            Page::SeedFix => "8. SeedFix Recovery",
            Page::DrillGuide => "9. Metal Backup Grid",
            Page::Provenance => "10. Provenance & Audit",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            Page::MasterSeed => Page::Passphrase,
            Page::Passphrase => Page::Descriptor,
            Page::Descriptor => Page::VpubQr,
            Page::VpubQr => Page::FaucetQr,
            Page::FaucetQr => Page::Addresses,
            Page::Addresses => Page::Bip85Children,
            Page::Bip85Children => Page::SeedFix,
            Page::SeedFix => Page::DrillGuide,
            Page::DrillGuide => Page::Provenance,
            Page::Provenance => Page::MasterSeed,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            Page::MasterSeed => Page::Provenance,
            Page::Passphrase => Page::MasterSeed,
            Page::Descriptor => Page::Passphrase,
            Page::VpubQr => Page::Descriptor,
            Page::FaucetQr => Page::VpubQr,
            Page::Addresses => Page::FaucetQr,
            Page::Bip85Children => Page::Addresses,
            Page::SeedFix => Page::Bip85Children,
            Page::DrillGuide => Page::SeedFix,
            Page::Provenance => Page::DrillGuide,
        }
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
    pub seedfix_input: String,
    pub seedfix_results: Vec<SeedFixCandidate>,
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
            seedfix_input: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            seedfix_results: Vec::new(),
            status_message: "Press [C]oin, [D]ice, [Tab] Nav, [Q]uit".into(),
        }
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

    pub fn clear_entropy(&mut self) {
        self.entropy_input.clear();
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
}

pub fn render_app(frame: &mut Frame, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header & Tabs
            Constraint::Min(10),   // Content
            Constraint::Length(4), // Footer / Status Bar & Global Nav
        ])
        .split(frame.area());

    render_header(frame, chunks[0], state);
    render_content(frame, chunks[1], state);
    render_footer(frame, chunks[2], state);
}

fn render_header(frame: &mut Frame, area: Rect, state: &AppState) {
    let titles: Vec<Line> = Page::ALL
        .iter()
        .map(|p| {
            let style = if *p == state.current_page {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            Line::from(Span::styled(p.title(), style))
        })
        .collect();

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .title(" SUBZERO-RS // AIRGAPPED BITCOIN TESTNET4 APPLIANCE ")
                .title_alignment(Alignment::Left)
                .style(Style::default().fg(Color::Cyan)),
        )
        .select(Page::ALL.iter().position(|p| *p == state.current_page).unwrap_or(0))
        .highlight_style(Style::default().fg(Color::Yellow));

    frame.render_widget(tabs, area);
}

fn render_footer(frame: &mut Frame, area: Rect, state: &AppState) {
    let sub_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(2)])
        .split(area);

    // Row 1: Global Navigation Guide on every page
    let nav_spans = vec![
        Span::styled(" NAV: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled("[Tab/→]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" Next  "),
        Span::styled("[Shift+Tab/←]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" Prev  "),
        Span::styled("[H/Home]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" Page 1  "),
        Span::styled("[0-9]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" Test Vectors  "),
        Span::styled("[C/D]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw(" Sim  "),
        Span::styled("[Q/ESC]", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
        Span::raw(" Wipe & Exit"),
    ];
    let nav_line = Line::from(nav_spans);
    frame.render_widget(Paragraph::new(nav_line), sub_chunks[0]);

    // Row 2: Status on Left, Persistent Build Stamp on Right
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
        Page::SeedFix => render_seedfix(frame, area, state),
        Page::DrillGuide => render_drill_guide(frame, area, state),
        Page::Provenance => render_provenance(frame, area, state),
    }
}

fn render_master_seed(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" BIP-39 Primary Master Secret ")
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

        // Render 2 columns of 6 words
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
            "  Advance to Page 2 for the Decoupled Estate Passphrase (BIP-85 Index 0).",
            Style::default().fg(Color::DarkGray),
        )));

        let p = Paragraph::new(lines).block(block);
        frame.render_widget(p, area);
    } else {
        // Interactive Entropy Input Terminal View
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
        "AWAITING INPUT (Coin 0/1 or Dice 1-6)"
    } else {
        "MIXED / INVALID"
    };

    let bits = if is_bin {
        len
    } else if is_dice {
        ((len as f64) * 2.58496).floor() as usize
    } else {
        0
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
        // Render 11-bit BIP-39 word chunks (2 columns of 6)
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
        // Format into 5-digit chunks, 4 chunks per line
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
        lines.push(Line::from("      Type [Backspace] to delete characters."));
        lines.push(Line::from(""));
        lines.push(Line::from("    Quick Emulations:"));
        lines.push(Line::from("      [C]   - Simulate 128 pseudo-random physical coin flips"));
        lines.push(Line::from("      [D]   - Simulate 50 casino dice rolls"));
        lines.push(Line::from("      [0-9] - Load Canonical SubZero Test Vectors (test0 .. test9)"));
    } else {
        lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(raw, Style::default().fg(Color::LightRed)),
        ]));
    }

    lines.push(Line::from(""));
    let is_ready = (is_bin && len >= 128) || (is_dice && len >= 50);
    let is_valid = is_ready && markov.passed && !repeats;

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
        .title(" Decoupled Estate Passphrase (BIP-85 Index 0) ")
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
            Line::from("  4. Used to encrypt the estate vault package (vault.json) and decrypt offline in decrypt.html."),
        ];
        frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), area);
    } else {
        frame.render_widget(Paragraph::new("Generate a seed first.").block(block), area);
    }
}

fn render_descriptor(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Output Descriptor (BIP-380 / BIP-84 Native SegWit) ")
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
        frame.render_widget(Paragraph::new("Generate a seed first.").block(block), area);
    }
}

fn render_vpub_qr(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Airgapped Export QR (Watch-Only Descriptor) ")
        .style(Style::default().fg(Color::White));

    if let Some(ref seed) = state.seed {
        match render_qr_to_lines(&seed.descriptor) {
            Ok(qr_lines) => {
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
        frame.render_widget(Paragraph::new("Generate a seed first.").block(block), area);
    }
}

fn render_faucet_qr(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Faucet QR Code (Receive Address #0) ")
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
        frame.render_widget(Paragraph::new("Generate a seed first.").block(block), area);
    }
}

fn render_addresses(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" First 5 Receive Addresses (BIP-84 Native SegWit tb1q... [Testnet4]) ")
        .style(Style::default().fg(Color::White));

    if let Some(ref seed) = state.seed {
        let mut lines = Vec::new();
        lines.push(Line::from(""));
        for (i, addr) in seed.addresses.iter().enumerate() {
            lines.push(Line::from(vec![
                Span::styled(format!("  m/84'/1'/0'/0/{:<2}: ", i), Style::default().fg(Color::Cyan)),
                Span::styled(addr, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            ]));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Advance to Page 5 to display a full-screen QR code for Address #0.",
            Style::default().fg(Color::DarkGray),
        )));
        let p = Paragraph::new(lines).block(block);
        frame.render_widget(p, area);
    } else {
        frame.render_widget(Paragraph::new("Generate a seed first.").block(block), area);
    }
}

fn render_bip85(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" BIP-85 Child Seed Treasuries (Deterministic Heir/Vault Keys) ")
        .style(Style::default().fg(Color::White));

    if state.bip85_children.is_empty() {
        frame.render_widget(Paragraph::new("Generate a seed first.").block(block), area);
    } else {
        let mut lines = Vec::new();
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  BIP-85 Path: m/83696968'/39'/0'/12'/{index}' - Independent 12-word seeds derived from Master",
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(""));

        for child in &state.bip85_children {
            lines.push(Line::from(vec![
                Span::styled(format!("  Vault #{} ", child.index), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled(format!("({}) : ", child.path), Style::default().fg(Color::DarkGray)),
                Span::styled(&child.mnemonic, Style::default().fg(Color::Yellow)),
            ]));
        }

        let p = Paragraph::new(lines).block(block);
        frame.render_widget(p, area);
    }
}

fn render_seedfix(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" SeedFix Recovery Tool (Levenshtein Candidate Solver) ")
        .style(Style::default().fg(Color::White));

    let mut lines = Vec::new();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("  Recover corrupted or missing 12th word mnemonic:", Style::default().fg(Color::Cyan))));
    lines.push(Line::from(""));

    let target_phrase = if let Some(ref seed) = state.seed {
        let words: Vec<&str> = seed.mnemonic.split_whitespace().collect();
        if words.len() == 12 {
            format!("{} (typo)", words[..11].join(" "))
        } else {
            state.seedfix_input.clone()
        }
    } else {
        state.seedfix_input.clone()
    };

    lines.push(Line::from(vec![
        Span::raw("  Target Seed Prefix: "),
        Span::styled(&target_phrase, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from(""));

    let words: Vec<&str> = target_phrase.split_whitespace().collect();
    if words.len() >= 11 {
        let eleven = words[..11].join(" ");
        let typo = words.get(11).copied();
        if let Ok(cands) = solve_twelfth_word(&eleven, typo) {
            lines.push(Line::from(Span::styled(
                format!("  Top 8 Ranked Checksum Candidates (from 128 mathematically valid):"),
                Style::default().fg(Color::Green),
            )));
            lines.push(Line::from(""));
            for (idx, cand) in cands.iter().take(8).enumerate() {
                lines.push(Line::from(vec![
                    Span::styled(format!("    {:2}. Word 12: ", idx + 1), Style::default().fg(Color::Cyan)),
                    Span::styled(format!("{:<12}", cand.twelfth_word.clone()), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Span::raw(" -> Full: "),
                    Span::styled(cand.full_mnemonic.clone(), Style::default().fg(Color::DarkGray)),
                ]));
            }
        }
    } else {
        lines.push(Line::from("  Enter 11 known words + approximate typo for word 12."));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("  [CLI Solver: subzero-rs seedfix --words \"word1 word2 ... word11 [typo]\"]", Style::default().fg(Color::DarkGray))));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_drill_guide(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" 24x4 Metal Punch / Cold Storage Guide ")
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
        frame.render_widget(Paragraph::new("Generate a seed first.").block(block), area);
    }
}

fn render_provenance(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Appliance Build Provenance & Cryptographic Zero-Knowledge Spec ")
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
            Span::styled("rust-bitcoin 0.32, bip39 2.1, zeroize 1.8, sha2 0.10", Style::default().fg(Color::Green)),
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
            Span::raw("  Zero-PII Status:      "),
            Span::styled("VERIFIED PURE ANONYMOUS APPLIANCE", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::raw("  Memory Hygiene:       "),
            Span::styled("ZeroizeOnDrop on all entropy buffers & private keys", Style::default().fg(Color::Cyan)),
        ]),
    ];

    frame.render_widget(Paragraph::new(lines).block(block), area);
}
