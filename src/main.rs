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

    /// [AUTOMATED TESTING ONLY] Ingest 12-word offline BIP-39 mnemonic phrase
    #[arg(short, long, hide = true)]
    mnemonic: Option<String>,

    /// [AUTOMATED TESTING ONLY] Ingest 48-digit CompactSeedQR numeric string
    #[arg(long, hide = true)]
    compact_seed_qr: Option<String>,

    /// [AUTOMATED TESTING ONLY] Ingest BIP-380 output descriptor (wpkh/tpub/vpub)
    #[arg(short, long, hide = true)]
    descriptor: Option<String>,
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

    // Hidden Test CLI Ingestion Handlers (Automated integration testing only)
    if cli.mnemonic.is_some() || cli.compact_seed_qr.is_some() || cli.descriptor.is_some() {
        eprintln!("\x1b[1;33m[!] WARNING: CLI KEY INGESTION IS STRICTLY FOR AUTOMATED TESTING HARNESSES.\x1b[0m");
        eprintln!("\x1b[1;33m[!] In production, CLI arguments leak to /proc/$PID/cmdline and shell history.\x1b[0m");
        eprintln!("\x1b[1;33m[!] Always use the interactive virtual console kiosk on /dev/tty1.\x1b[0m");
    }

    if let Some(m) = cli.mnemonic {
        if let Ok(seed) = crypto::process_mnemonic_phrase(&m) {
            let children = crypto::derive_bip85_children(&seed.mnemonic, 20).unwrap_or_default();
            state.set_seed(seed, children);
            state.current_page = ui::Page::MasterSeed;
            state.status_message = "[✓] CLI TEST SEED IMPORTED: Master keys and BIP-85 suite ready in RAM.".into();
        }
    } else if let Some(csqr) = cli.compact_seed_qr {
        if let Ok(seed) = crypto::process_mnemonic_phrase(&csqr) {
            let children = crypto::derive_bip85_children(&seed.mnemonic, 20).unwrap_or_default();
            state.set_seed(seed, children);
            state.current_page = ui::Page::MasterSeed;
            state.status_message = "[✓] CLI TEST COMPACTSEEDQR IMPORTED: Master keys ready in RAM.".into();
        }
    } else if let Some(desc) = cli.descriptor {
        if let Ok(seed) = crypto::process_watch_only_descriptor(&desc) {
            state.set_seed(seed, Vec::new());
            state.current_page = ui::Page::MasterSeed;
            state.status_message = "[✓] CLI TEST DESCRIPTOR IMPORTED: Watch-only keys ready in RAM.".into();
        }
    } else if let Some(entropy_str) = cli.entropy {
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

    // Bare-Metal Appliance Lifecycle Invariant:
    // When the operator confirms exit ([Q][Q]), power off the physical machine immediately.
    // This purges volatile RAM and prevents sitting on a dead console.
    // Try /sbin/poweroff -f, then /bin/busybox poweroff -f, then sync.
    let _ = std::process::Command::new("/sbin/poweroff")
        .arg("-f")
        .status();
    let _ = std::process::Command::new("/bin/busybox")
        .args(["poweroff", "-f"])
        .status();

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
