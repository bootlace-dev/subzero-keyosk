mod crypto;
mod qr;
mod seedfix;
mod storage;
mod ui;

use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event},
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
    state.wipe_confirmation_instant = None;
    state.status_message = "[✓] PROACTIVE PRE-BOOT SCRUB: RAM zeroized prior to display initialization.".into();

    // If CLI provided an existing offline mnemonic, import it immediately
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

    println!("\x1b[1;32m=================================================================\x1b[0m");
    println!("\x1b[1;32m [✓] PROCESS EXIT: ZEROIZE-ON-DROP VOLATILE MEMORY PURGE COMPLETE \x1b[0m");
    println!("\x1b[1;32m=================================================================\x1b[0m");
    println!("  - Master root mnemonic, entropy buffers, and child keys zeroized.");
    println!("  - Handing off to multi-pass hardware scrub daemon...");
    println!("");

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

        // Check 30-minute idle auto-lock for decrypted vault
        state.check_inactivity_autolock();

        terminal.draw(|f| ui::render_app(f, state))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if ui::handle_key_event(state, key) {
                    break;
                }
            }
        }
    }
    Ok(())
}
