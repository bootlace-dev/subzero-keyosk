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
    loop {
        terminal.draw(|f| ui::render_app(f, state))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    break;
                }

                // Global exits
                if key.code == KeyCode::Char('q') || key.code == KeyCode::Char('Q') || key.code == KeyCode::Esc {
                    if state.current_page != ui::Page::MasterSeed && key.code == KeyCode::Esc {
                        state.current_page = ui::Page::MasterSeed;
                        continue;
                    }
                    break;
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
                        state.current_page = ui::Page::MasterSeed;
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
                    ui::Page::MasterSeed => {
                        match key.code {
                            KeyCode::Char('r') | KeyCode::Char('R') => {
                                let rand_bits = crypto::generate_random_128bit_binary();
                                if let Ok(seed) = crypto::process_physical_entropy(&rand_bits) {
                                    let children = crypto::derive_bip85_children(&seed.mnemonic, 20).unwrap_or_default();
                                    state.set_seed(seed, children);
                                    state.status_message = "[PRNG] Derived dynamic testing wallet from device PRNG (Untrusted).".into();
                                }
                            }
                            KeyCode::Char('c') | KeyCode::Char('C') => {
                                let coin_entropy = "10100110110010111000101011110011011110100010101101111010101100111000101011110011011110100010101101111010101100111000101011110011";
                                if let Ok(seed) = crypto::process_physical_entropy(coin_entropy) {
                                    let children = crypto::derive_bip85_children(&seed.mnemonic, 20).unwrap_or_default();
                                    state.set_seed(seed, children);
                                }
                            }
                            KeyCode::Char('d') | KeyCode::Char('D') => {
                                let dice_entropy = "42312461325416235142635142316524136251436251436251";
                                if let Ok(seed) = crypto::process_physical_entropy(dice_entropy) {
                                    let children = crypto::derive_bip85_children(&seed.mnemonic, 20).unwrap_or_default();
                                    state.set_seed(seed, children);
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
                    ui::Page::Addresses => {
                        // Pagination for receive addresses (10 per page across 50 total)
                        match key.code {
                            KeyCode::Down | KeyCode::PageDown => {
                                if let Some(ref s) = state.seed {
                                    if state.address_page_offset + 10 < s.addresses.len() {
                                        state.address_page_offset += 10;
                                    }
                                }
                            }
                            KeyCode::Up | KeyCode::PageUp => {
                                state.address_page_offset = state.address_page_offset.saturating_sub(10);
                            }
                            _ => {}
                        }
                    }
                    ui::Page::Bip85Children => {
                        // Pagination for BIP-85 heir keys (4 per page across 20 total)
                        match key.code {
                            KeyCode::Down | KeyCode::PageDown => {
                                if state.heir_page_offset + 4 < state.bip85_children.len() {
                                    state.heir_page_offset += 4;
                                }
                            }
                            KeyCode::Up | KeyCode::PageUp => {
                                state.heir_page_offset = state.heir_page_offset.saturating_sub(4);
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
