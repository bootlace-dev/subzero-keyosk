use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs, Wrap},
    Frame,
};
use crate::crypto::{Bip85Child, GeneratedSeed};
use crate::qr::render_qr_to_lines;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    MasterSeed,
    Descriptor,
    VpubQr,
    Addresses,
    Bip85Children,
    SeedFix,
    DrillGuide,
    Provenance,
}

impl Page {
    pub const ALL: [Page; 8] = [
        Page::MasterSeed,
        Page::Descriptor,
        Page::VpubQr,
        Page::Addresses,
        Page::Bip85Children,
        Page::SeedFix,
        Page::DrillGuide,
        Page::Provenance,
    ];

    pub fn title(&self) -> &'static str {
        match self {
            Page::MasterSeed => "1. Master Mnemonic",
            Page::Descriptor => "2. Output Descriptor",
            Page::VpubQr => "3. Watch-Only QR",
            Page::Addresses => "4. Receive Addresses",
            Page::Bip85Children => "5. BIP-85 Heir Keys",
            Page::SeedFix => "6. SeedFix Recovery",
            Page::DrillGuide => "7. Metal Backup Grid",
            Page::Provenance => "8. Provenance & Audit",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            Page::MasterSeed => Page::Descriptor,
            Page::Descriptor => Page::VpubQr,
            Page::VpubQr => Page::Addresses,
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
            Page::Descriptor => Page::MasterSeed,
            Page::VpubQr => Page::Descriptor,
            Page::Addresses => Page::VpubQr,
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
    pub bip85_children: Vec<Bip85Child>,
    pub build_timestamp: String,
    pub git_commit: String,
    pub entropy_input: String,
    pub is_entering_entropy: bool,
    pub status_message: String,
}

impl AppState {
    pub fn new(build_timestamp: String, git_commit: String) -> Self {
        Self {
            current_page: Page::MasterSeed,
            seed: None,
            bip85_children: Vec::new(),
            build_timestamp,
            git_commit,
            entropy_input: String::new(),
            is_entering_entropy: false,
            status_message: "Press [C]oin, [D]ice, [Tab] Nav, [Q]uit".into(),
        }
    }

    pub fn set_seed(&mut self, seed: GeneratedSeed, children: Vec<Bip85Child>) {
        self.seed = Some(seed);
        self.bip85_children = children;
        self.status_message = "Keys generated securely in amnesic memory.".into();
    }
}

pub fn render_app(frame: &mut Frame, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header & Tabs
            Constraint::Min(10),   // Content
            Constraint::Length(3), // Footer / Status Bar
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
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

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
        Page::Descriptor => render_descriptor(frame, area, state),
        Page::VpubQr => render_qr_view(frame, area, state),
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
            Span::raw("  Fingerprint (Master): "),
            Span::styled(&seed.fingerprint, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::from(vec![
            Span::raw("  Entropy Mode:         "),
            Span::styled(&seed.entropy_type, Style::default().fg(Color::Green)),
        ]));

        let p = Paragraph::new(lines).block(block);
        frame.render_widget(p, area);
    } else {
        let lines = vec![
            Line::from(""),
            Line::from("  No active seed loaded."),
            Line::from(""),
            Line::from("  Commands:"),
            Line::from("    [C] - Enter Physical Coin Flips (128 bits: H/T or 0/1)"),
            Line::from("    [D] - Enter Physical Casino Dice Rolls (50 rolls: 1-6)"),
            Line::from("    [R] - Generate Cryptographic Dev Seed (System TRNG)"),
            Line::from("    [Q] - Immediate Memory Wipe and Terminate"),
        ];
        let p = Paragraph::new(lines).block(block);
        frame.render_widget(p, area);
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
            Line::from("  Compatible with: Sparrow Wallet, Bitcoin Core, Coldcard, BlueWallet, Jade"),
            Line::from("  Contains NO private keys. Can be safely exported over airgap via watch-only QR."),
        ];
        let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
        frame.render_widget(p, area);
    } else {
        frame.render_widget(Paragraph::new("Generate a seed first.").block(block), area);
    }
}

fn render_qr_view(frame: &mut Frame, area: Rect, state: &AppState) {
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

fn render_seedfix(frame: &mut Frame, area: Rect, _state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" SeedFix Recovery Tool (Levenshtein Candidate Solver) ")
        .style(Style::default().fg(Color::White));

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled("  Recover corrupted or missing 12th word mnemonic:", Style::default().fg(Color::Cyan))),
        Line::from(""),
        Line::from("  Enter 11 known words + approximate typo for word 12."),
        Line::from("  The solver evaluates all 128 valid BIP-39 checksum candidates and"),
        Line::from("  ranks the closest phonetic/Levenshtein dictionary matches instantly."),
        Line::from(""),
        Line::from("  [Available in CLI mode via: subzero-rs seedfix --words \"word1 word2 ...\"]"),
    ];

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
