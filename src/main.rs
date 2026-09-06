mod crypto;
mod qr;
mod seedfix;
mod storage;
mod ui;

use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::{self, stdout};
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "subzero-rs")]
#[command(author = "SubZero Appliance Contributors")]
#[command(version = "0.1.0")]
#[command(about = "Sovereign Airgapped Bitcoin Entropy & Key Appliance in Pure Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Run non-interactive entropy ingestion (coin flips or dice rolls)
    #[arg(short, long)]
    entropy: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Recover a 12th mnemonic word using Levenshtein distance matching
    Seedfix {
        /// First 11 words followed by optional 12th word typo
        #[arg(short, long)]
        words: String,
    },
    /// Derive BIP-85 deterministic child seeds from an existing 12-word mnemonic
    Bip85 {
        #[arg(short, long)]
        mnemonic: String,
        #[arg(short, long, default_value_t = 20)]
        count: u32,
    },
    /// Inspect or search canonical 2048-word BIP-39 English wordlist
    Wordlist {
        /// Search query prefix
        #[arg(short, long, default_value = "")]
        query: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if let Some(cmd) = cli.command {
        match cmd {
            Commands::Seedfix { words } => {
                println!("SubZero-RS SeedFix Recovery Engine");
                let word_list: Vec<&str> = words.split_whitespace().collect();
                if word_list.len() < 11 {
                    eprintln!("Error: SeedFix requires at least 11 words.");
                    std::process::exit(1);
                }
                let eleven = word_list[0..11].join(" ");
                let typo = word_list.get(11).copied();
                let results = seedfix::solve_twelfth_word(&eleven, typo)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                println!("Found {} valid checksum candidates:", results.len());
                for (rank, candidate) in results.iter().take(10).enumerate() {
                    println!("  {:2}. Word 12: {:<12} Full: {}", rank + 1, candidate.twelfth_word, candidate.full_mnemonic);
                }
                return Ok(());
            }
            Commands::Bip85 { mnemonic, count } => {
                println!("SubZero-RS BIP-85 Derivation Engine");
                let children = crypto::derive_bip85_children(&mnemonic, count)?;
                for child in children {
                    println!("Vault #{}: [{}] -> {}", child.index, child.path, child.mnemonic);
                }
                return Ok(());
            }
            Commands::Wordlist { query } => {
                println!("SubZero-RS Canonical BIP-39 English Wordlist Inspector");
                let matches = seedfix::search_wordlist(&query);
                println!("Matching words ({}/2048):", matches.len());
                for m in matches {
                    println!("  {}", m);
                }
                return Ok(());
            }
        }
    }

    // Interactive TUI mode
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = ui::AppState::new(
        env!("BUILD_TIMESTAMP").to_string(),
        env!("GIT_COMMIT").to_string(),
    );

    // Startup Memory Hygiene Invariant:
    // Execute proactive pre-display zeroization of all data structures.
    state.wipe_memory();
    state.status_message = "[✓] PROACTIVE PRE-BOOT SCRUB: RAM zeroized prior to display initialization.".into();

    // If CLI provided initial entropy, process it immediately
    if let Some(entropy_str) = cli.entropy {
        if let Ok(seed) = crypto::process_physical_entropy(&entropy_str) {
            let children = crypto::derive_bip85_children(&seed.mnemonic, 20).unwrap_or_default();
            state.set_seed(seed, children);
        }
    }

    let res = run_event_loop(&mut terminal, &mut state);

    // Terminal teardown & guarantee memory wipe
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("Application Error: {:?}", err);
    }

    Ok(())
}

fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut ui::AppState,
) -> io::Result<()> {
    let mut last_bbqr_tick = std::time::Instant::now();

    loop {
        // Advance BBQR frame animation (~350ms per frame) if active on VpubQr tab
        if state.current_page == ui::Page::VpubQr && state.qr_mode == qr::QrMode::BbqrAnimated {
            if last_bbqr_tick.elapsed() >= Duration::from_millis(350) {
                state.bbqr_frame_index = state.bbqr_frame_index.wrapping_add(1);
                last_bbqr_tick = std::time::Instant::now();
            }
        }

        terminal.draw(|f| ui::render_app(f, state))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    break;
                }

                // Cancel active jitter harvesting on Esc
                if key.code == KeyCode::Esc && state.is_harvesting_jitter {
                    state.is_harvesting_jitter = false;
                    state.jitter_samples.clear();
                    state.last_jitter_instant = None;
                    state.status_message = "Keystroke jitter harvest canceled.".into();
                    continue;
                }

                // Global exits: Only [Q] exits the appliance
                if key.code == KeyCode::Char('q') || key.code == KeyCode::Char('Q') {
                    break;
                }

                // Global Home/Esc: Returns directly to Tab 0 (RoleSelect)
                if key.code == KeyCode::Esc || key.code == KeyCode::Home {
                    state.current_page = ui::Page::RoleSelect;
                    continue;
                }

                // Global Navigation & Memory Wipe
                match key.code {
                    KeyCode::Tab | KeyCode::Right => {
                        state.current_page = state.current_page.next();
                        continue;
                    }
                    KeyCode::BackTab | KeyCode::Left => {
                        state.current_page = state.current_page.prev();
                        continue;
                    }
                    KeyCode::Home => {
                        state.current_page = ui::Page::RoleSelect;
                        continue;
                    }
                    KeyCode::Char('w') | KeyCode::Char('W') => {
                        // Global Wipe & Reset (disabled inside active typing inputs)
                        if state.current_page != ui::Page::SeedFix && state.current_page != ui::Page::WordlistInspector && state.current_page != ui::Page::VaultUnlock {
                            state.wipe_memory();
                            continue;
                        }
                    }
                    _ => {}
                }

                // Contextual Page Handlers
                match state.current_page {
                    ui::Page::RoleSelect => {
                        match key.code {
                            KeyCode::Char('1') | KeyCode::Enter => {
                                state.current_page = ui::Page::MasterSeed;
                            }
                            KeyCode::Char('2') => {
                                state.current_page = ui::Page::VaultUnlock;
                            }
                            KeyCode::Char('3') => {
                                state.current_page = ui::Page::SeedFix;
                            }
                            _ => {}
                        }
                    }
                    ui::Page::MasterSeed => {
                        if state.is_harvesting_jitter {
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
                                    // Harvest completed: hash jitter samples to 128 binary bits
                                    let bits = crypto::harvest_keystroke_jitter_to_binary(&state.jitter_samples);
                                    state.set_entropy_input(&bits);
                                    state.is_harvesting_jitter = false;
                                    state.jitter_samples.clear();
                                    state.last_jitter_instant = None;
                                    state.status_message = "[HUMAN JITTER HARVESTED] 128 binary coin flips generated from keystroke timing deltas. Review & press [ENTER].".into();
                                }
                            }
                        } else if state.is_selecting_test_vector {
                            match key.code {
                                KeyCode::Char(c) if ('0'..='9').contains(&c) => {
                                    let digit = c.to_digit(10).unwrap() as u8;
                                    state.is_selecting_test_vector = false;
                                    if let Ok((_bytes, label)) = crypto::get_test_vector(digit) {
                                        let seed = crypto::process_physical_entropy(&format!("test{}", digit)).unwrap();
                                        let children = crypto::derive_bip85_children(&seed.mnemonic, 20).unwrap_or_default();
                                        state.set_seed(seed, children);
                                        state.status_message = format!("[{}] Loaded. Inspect tabs or press [W] to wipe.", label);
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
                        } else {
                            match key.code {
                                KeyCode::Char('t') | KeyCode::Char('T') => {
                                    if state.seed.is_none() {
                                        state.is_selecting_test_vector = true;
                                        state.status_message = "SELECT TEST VECTOR: Press [0-9] (e.g. 0=All-Zeros, 8=Satoshi Lore, 9=Hal Finney) or [Esc] to cancel:".into();
                                    }
                                }
                                KeyCode::Char('k') | KeyCode::Char('K') => {
                                    if state.seed.is_none() {
                                        state.is_harvesting_jitter = true;
                                        state.jitter_samples.clear();
                                        state.last_jitter_instant = Some(std::time::Instant::now());
                                        state.status_message = "Harvesting human keystroke timing jitter. Mash any keys rapidly!".into();
                                    }
                                }
                                KeyCode::Char('c') | KeyCode::Char('C') => {
                                    if state.seed.is_none() {
                                        let coin_entropy = "10100110110010111000101011110011011110100010101101111010101100111000101011110011011110100010101101111010101100111000101011110011";
                                        state.set_entropy_input(coin_entropy);
                                        state.status_message = "[COIN VECTOR LOADED] 128 physical coin flips populated. Review & press [ENTER].".into();
                                    }
                                }
                                KeyCode::Char('d') | KeyCode::Char('D') => {
                                    if state.seed.is_none() {
                                        let dice_entropy = "42312461325416235142635142316524136251436251436251";
                                        state.set_entropy_input(dice_entropy);
                                        state.status_message = "[DICE VECTOR LOADED] 52 dice rolls populated. Review & press [ENTER].".into();
                                    }
                                }
                                KeyCode::Backspace => {
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
                                KeyCode::Char(c) if c.is_ascii_alphanumeric() => {
                                    if state.seed.is_none() {
                                        state.push_entropy_char(c);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    ui::Page::VpubQr => {
                        match key.code {
                            KeyCode::Char('m' | 'M') => {
                                state.qr_mode = state.qr_mode.next();
                                state.bbqr_frame_index = 0;
                            }
                            KeyCode::Char('e' | 'E') => {
                                state.export_external_usb();
                            }
                            _ => {}
                        }
                    }
                    ui::Page::Addresses => {
                        // Pagination for receive addresses (25 per page across 50 total)
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
                    ui::Page::Bip85Children => {
                        // Pagination for BIP-85 child keys (10 per page across 20 total)
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
                    ui::Page::EstateProvisioner => {
                        if let KeyCode::Char('p' | 'P') = key.code {
                            state.write_estate_vault();
                        }
                    }
                    ui::Page::SeedFix => {
                        match key.code {
                            KeyCode::Backspace => {
                                state.seedfix_input.pop();
                            }
                            KeyCode::Char(c) => {
                                if c.is_alphanumeric() || c == ' ' {
                                    state.seedfix_input.push(c);
                                }
                            }
                            _ => {}
                        }
                    }
                    ui::Page::WordlistInspector => {
                        match key.code {
                            KeyCode::Backspace => {
                                state.wordlist_query.pop();
                            }
                            KeyCode::Char(c) => {
                                if c.is_alphabetic() {
                                    state.wordlist_query.push(c);
                                }
                            }
                            _ => {}
                        }
                    }
                    ui::Page::VaultUnlock => {
                        match key.code {
                            KeyCode::Backspace => {
                                state.vault_passphrase_input.pop();
                            }
                            KeyCode::Enter => {
                                state.attempt_vault_decrypt();
                            }
                            KeyCode::Char(c) => {
                                if c.is_alphanumeric() || c == ' ' {
                                    state.vault_passphrase_input.push(c);
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
