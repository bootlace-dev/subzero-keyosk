//! Target Audience UX & Heir Stress Usability Test Suite for SubZero-rs
//!
//! Evaluates application UX across:
//! 1. Old COTS Laptop Terminal Dimensions & Zero-Clipping Invariants (80x24, 80x25, 100x30, 128x48)
//! 2. Non-Technical Heir Recovery Workflow Usability (Tabs 8 & 9, USB prompts, masking, calm errors)
//! 3. Panic-Operator Keyboard Chaos Fuzzing (Rapid key mashing, 2-stroke [Q] exit within 3s, amnesic [W] wipes)

use subzero::ui::{AppState, Page, render_app, handle_key_event};
use subzero::qr::{QrMode, render_full_block_qr, create_bbqr_frames, encode_qr_bmp};
use subzero::crypto::{
    process_physical_entropy, derive_bip85_children, Bip85Child,
};
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, KeyEventKind, KeyEventState};

/// Standard legacy COTS laptop geometries:
/// - 80x24: Classic VT100 / BIOS console
/// - 80x25: IBM standard VGA text mode
/// - 100x30: Small 1024x768 framebuffer scaled font
/// - 128x48: Standard 1366x768 console
const COTS_RESOLUTIONS: [(u16, u16); 4] = [
    (80, 24),
    (80, 25),
    (100, 30),
    (128, 48),
];

/// Helper to render AppState into a TestBackend of given dimensions,
/// verifying that no line exceeds the printable terminal width.
fn render_to_screen(state: &AppState, w: u16, h: u16) -> (Vec<String>, String) {
    let backend = TestBackend::new(w, h);
    let mut terminal = Terminal::new(backend).expect("Failed to initialize TestBackend");
    terminal.draw(|f| render_app(f, state)).expect("Drawing failed");

    let buffer = terminal.backend().buffer();
    let mut lines = Vec::with_capacity(h as usize);
    let mut full_text = String::with_capacity((w as usize + 1) * h as usize);

    for y in 0..h {
        let mut line_str = String::with_capacity(w as usize);
        for x in 0..w {
            let cell = &buffer[(x, y)];
            line_str.push_str(cell.symbol());
        }
        let trimmed = line_str.trim_end();
        assert!(
            trimmed.chars().count() <= w as usize,
            "Terminal buffer overflow on page {:?} at ({}, {}) in resolution {}x{}: '{}'",
            state.current_page, trimmed.chars().count(), y, w, h, trimmed
        );
        lines.push(trimmed.to_string());
        full_text.push_str(trimmed);
        full_text.push('\n');
    }

    (lines, full_text)
}

/// Helper to construct a crossterm KeyEvent
fn make_key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
    KeyEvent {
        code,
        modifiers,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

/// Helper to seed AppState with deterministic test data
fn create_test_state() -> AppState {
    let mut state = AppState::new("2026-09-07 12:00:00Z".to_string(), "c0ffee1".to_string());
    let coin_entropy = "00100000100000001011001110010010111010101100001000111101101000011101000111001011101001111001000001011110011011010100100100110011";
    let seed = process_physical_entropy(coin_entropy).expect("Valid coin entropy failed");
    let children = derive_bip85_children(&seed.mnemonic, 20).expect("Derivation failed");
    state.set_seed(seed, children);
    state
}

// ============================================================================
// VECTOR 1: OLD COTS LAPTOP TERMINAL DIMENSIONS & ZERO-CLIPPING INVARIANTS
// ============================================================================

#[test]
fn test_cots_geometries_zero_clipping_uninitialized_app_state() {
    for &(w, h) in &COTS_RESOLUTIONS {
        for page in Page::ALL {
            let mut page_state = AppState::new("2026-09-07 12:00:00Z".to_string(), "c0ffee1".to_string());
            page_state.current_page = page;

            let (_lines, screen_text) = render_to_screen(&page_state, w, h);

            // Assert header elements render
            assert!(
                screen_text.contains("NO KEYS") || screen_text.contains("AWAITING"),
                "Expected uninitialized RAM indicator on page {:?} at {}x{}",
                page, w, h
            );

            // Assert footer navigation renders
            assert!(
                screen_text.contains("NAV:"),
                "Missing NAV footer on page {:?} at {}x{}",
                page, w, h
            );
        }
    }
}

#[test]
fn test_cots_geometries_zero_clipping_populated_master_seed() {
    let mut state = create_test_state();

    for &(w, h) in &COTS_RESOLUTIONS {
        for page in Page::ALL {
            state.current_page = page;
            let (_lines, screen_text) = render_to_screen(&state, w, h);

            // Verify Master Fingerprint in header
            let expected_fp = &state.seed.as_ref().unwrap().fingerprint;
            assert!(
                screen_text.contains(expected_fp),
                "Master fingerprint '{}' missing on page {:?} at {}x{}",
                expected_fp, page, w, h
            );

            // Verify Testnet4 badge
            assert!(
                screen_text.contains("TESTNET4"),
                "Testnet4 safety badge missing on page {:?} at {}x{}",
                page, w, h
            );
        }
    }
}

#[test]
fn test_zero_clipping_and_no_wrap_master_and_passphrase_mnemonics() {
    let state = create_test_state();
    let seed = state.seed.as_ref().unwrap();
    let words: Vec<&str> = seed.mnemonic.split_whitespace().collect();
    assert_eq!(words.len(), 12);

    let pass = state.decoupled_passphrase.as_ref().unwrap();
    let pass_words: Vec<&str> = pass.mnemonic.split_whitespace().collect();
    assert_eq!(pass_words.len(), 12);

    for &(w, h) in &COTS_RESOLUTIONS {
        // 1. Tab 1: Master Seed
        let mut test_state = create_test_state();
        test_state.current_page = Page::MasterSeed;
        let (_lines, screen_text) = render_to_screen(&test_state, w, h);

        // Assert every single one of the 12 master mnemonic words is visible on screen
        for (i, word) in words.iter().enumerate() {
            assert!(
                screen_text.contains(word),
                "Master word #{} ('{}') clipped on Tab 1 at {}x{}",
                i + 1, word, w, h
            );
        }
        // Assert metal punch 4-letter prefixes are displayed
        for word in &words {
            let prefix = if word.len() >= 4 { &word[..4] } else { word }.to_uppercase();
            assert!(
                screen_text.contains(&prefix),
                "Metal punch prefix '{}' missing on Tab 1 at {}x{}",
                prefix, w, h
            );
        }

        // 2. Tab 2: Decoupled Passphrase
        test_state.current_page = Page::Passphrase;
        let (_lines, screen_text_pass) = render_to_screen(&test_state, w, h);

        // Assert every single one of the 12 passphrase words is visible on screen
        for (i, word) in pass_words.iter().enumerate() {
            assert!(
                screen_text_pass.contains(word),
                "Passphrase word #{} ('{}') clipped on Tab 2 at {}x{}",
                i + 1, word, w, h
            );
        }
    }
}

#[test]
fn test_zero_clipping_maximum_length_bip39_words_worst_case() {
    let mut state = AppState::new("2026-09-07 12:00:00Z".to_string(), "c0ffee1".to_string());
    
    // In BIP-39, the longest words are 8 letters each:
    // umbrella, scissors, abstract, accident, daughter, dinosaur, elevator, hospital, mountain, practice, remember, transfer
    let longest_words = "umbrella scissors abstract accident daughter dinosaur elevator hospital mountain practice remember transfer";
    
    // Create a mock seed and decoupled passphrase using the longest words
    let mut fake_seed = process_physical_entropy("00100000100000001011001110010010111010101100001000111101101000011101000111001011101001111001000001011110011011010100100100110011").unwrap();
    fake_seed.mnemonic = longest_words.to_string();

    let fake_child = Bip85Child {
        index: 0,
        path: "m/83696968'/39'/0'/12/0'".to_string(),
        mnemonic: longest_words.to_string(),
        label: "Decoupled Estate Passphrase".to_string(),
    };

    let mut fake_children = vec![fake_child];
    for i in 1..=5 {
        fake_children.push(Bip85Child {
            index: i,
            path: format!("m/83696968'/39'/0'/12/{}'", i),
            mnemonic: longest_words.to_string(),
            label: format!("Heir Vault #{:02}", i),
        });
    }

    state.set_seed(fake_seed, fake_children);

    // Test tightest legacy bounds (80x24 and 80x25)
    for &(w, h) in &COTS_RESOLUTIONS[..2] {
        state.current_page = Page::MasterSeed;
        let (lines, screen_text) = render_to_screen(&state, w, h);

        for line in &lines {
            assert!(
                line.chars().count() <= w as usize,
                "Longest BIP-39 words overflowed width {} on Tab 1: '{}'",
                w, line
            );
        }
        for word in longest_words.split_whitespace() {
            assert!(
                screen_text.contains(word),
                "Longest word '{}' missing on Tab 1 at {}x{}",
                word, w, h
            );
        }

        // Test Tab 2 Passphrase with longest words
        state.current_page = Page::Passphrase;
        let (lines_pass, screen_pass) = render_to_screen(&state, w, h);
        for line in &lines_pass {
            assert!(
                line.chars().count() <= w as usize,
                "Longest BIP-39 words overflowed width {} on Tab 2: '{}'",
                w, line
            );
        }
        for word in longest_words.split_whitespace() {
            assert!(
                screen_pass.contains(word),
                "Longest word '{}' missing on Tab 2 at {}x{}",
                word, w, h
            );
        }
    }
}

#[test]
fn test_zero_clipping_and_no_wrap_receive_addresses_pagination() {
    let mut state = create_test_state();
    state.current_page = Page::Addresses;

    let addresses = state.seed.as_ref().unwrap().addresses.clone();
    assert_eq!(addresses.len(), 50);

    for &(w, h) in &COTS_RESOLUTIONS {
        // Test Page 1 (Addresses 0..25)
        state.address_page_offset = 0;
        let (lines_p1, screen_text_p1) = render_to_screen(&state, w, h);
        assert!(screen_text_p1.contains("Showing Addresses #0-#24 (Page 1 of 2):"));
        assert!(screen_text_p1.contains(&addresses[0]));

        // Verify native segwit format
        assert!(addresses[0].starts_with("tb1q"));

        // Assert all rendered lines fit strictly within terminal width w
        for line in &lines_p1 {
            assert!(
                line.chars().count() <= w as usize,
                "Address line exceeded width {} at {}x{}: '{}'",
                w, w, h, line
            );
        }

        // On terminals with sufficient vertical height (h >= 32), verify last address on page
        if h >= 32 {
            assert!(screen_text_p1.contains(&addresses[24]));
        }

        // Test Page 2 (Addresses 25..50)
        state.address_page_offset = 25;
        let (lines_p2, screen_text_p2) = render_to_screen(&state, w, h);
        assert!(screen_text_p2.contains("Showing Addresses #25-#49 (Page 2 of 2):"));
        assert!(screen_text_p2.contains(&addresses[25]));

        for line in &lines_p2 {
            assert!(
                line.chars().count() <= w as usize,
                "Address line exceeded width {} at {}x{}: '{}'",
                w, w, h, line
            );
        }

        if h >= 32 {
            assert!(screen_text_p2.contains(&addresses[49]));
        }
    }
}

#[test]
fn test_zero_clipping_output_descriptor_and_vpub_export() {
    let mut state = create_test_state();
    let seed = state.seed.as_ref().unwrap();
    let desc = &seed.descriptor;
    let vpub = &seed.vpub_slip132;

    for &(w, h) in &COTS_RESOLUTIONS {
        // 1. Tab 3: Output Descriptor
        state.current_page = Page::Descriptor;
        let (_lines, screen_text_desc) = render_to_screen(&state, w, h);
        assert!(screen_text_desc.contains("WATCH-ONLY OUTPUT DESCRIPTOR (BIP-380 / BIP-84):"));
        assert!(screen_text_desc.contains("BIP-32 Account Public Key"));
        assert!(screen_text_desc.contains("SLIP-0132 Native SegWit Key"));

        // 2. Tab 4: Watch-Only QR (Static VPUB mode)
        state.current_page = Page::VpubQr;
        state.qr_mode = QrMode::StaticVpub;
        let (_lines, screen_text_vpub) = render_to_screen(&state, w, h);
        let cleaned_screen: String = screen_text_vpub.chars().filter(|c| !c.is_whitespace()).collect();
        let cleaned_vpub: String = vpub.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            cleaned_screen.contains(&cleaned_vpub),
            "Full SLIP-0132 VPUB truncated on Tab 4 at {}x{}! Expected: {}",
            w, h, vpub
        );

        // 3. Tab 4: Watch-Only QR (Full Descriptor mode)
        state.qr_mode = QrMode::FullBlockSpace;
        let (_lines, screen_text_full) = render_to_screen(&state, w, h);
        let cleaned_screen_full: String = screen_text_full.chars().filter(|c| !c.is_whitespace()).collect();
        let cleaned_desc: String = desc.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            cleaned_screen_full.contains(&cleaned_desc),
            "Full descriptor truncated on Tab 4 at {}x{}! Expected: {}",
            w, h, desc
        );
    }
}

#[test]
fn test_optical_qr_quiet_zone_and_finder_patterns_all_modes() {
    let state = create_test_state();
    let seed = state.seed.as_ref().unwrap();

    // 1. Test Mode 1: BBQr animated frames
    let frames = create_bbqr_frames(&seed.descriptor, 3);
    assert!(!frames.is_empty());
    for frame in &frames {
        let qr_lines = render_full_block_qr(frame).expect("BBQr frame QR render failed");
        assert_qr_quiet_zone_and_finder_pattern_invariants(&qr_lines);
    }

    // 2. Test Mode 2: Static Full-Block Descriptor
    let desc_lines = render_full_block_qr(&seed.descriptor).expect("Descriptor QR render failed");
    assert_qr_quiet_zone_and_finder_pattern_invariants(&desc_lines);

    // 3. Test Mode 3: Static VPUB
    let vpub_lines = render_full_block_qr(&seed.vpub_slip132).expect("VPUB QR render failed");
    assert_qr_quiet_zone_and_finder_pattern_invariants(&vpub_lines);

    // 4. Test Tab 5: Faucet QR
    let faucet_lines = render_full_block_qr(&seed.addresses[0]).expect("Faucet QR render failed");
    assert_qr_quiet_zone_and_finder_pattern_invariants(&faucet_lines);
}

/// Verifies ISO/IEC 18004 quiet zone and finder pattern requirements on rendered terminal QR lines
fn assert_qr_quiet_zone_and_finder_pattern_invariants(qr_lines: &[ratatui::text::Line]) {
    assert!(qr_lines.len() >= 23, "QR code too small: {} rows", qr_lines.len());
    let total_rows = qr_lines.len();

    // Invariant 1: Quiet Zone (Top Row)
    // The top row must be 100% white background (light modules)
    let top_line = &qr_lines[0];
    for span in &top_line.spans {
        if let Some(bg) = span.style.bg {
            assert_eq!(bg, ratatui::style::Color::White, "Top quiet zone row must be white");
        }
    }

    // Invariant 2: Quiet Zone (Bottom Row)
    let bottom_line = &qr_lines[total_rows - 1];
    for span in &bottom_line.spans {
        if let Some(bg) = span.style.bg {
            assert_eq!(bg, ratatui::style::Color::White, "Bottom quiet zone row must be white");
        }
    }

    // Invariant 3: Left and Right Quiet Zones
    // Every middle row must begin and end with at least 1 module (2 spaces) of white background
    for row_idx in 1..(total_rows - 1) {
        let row = &qr_lines[row_idx];
        let first_span = row.spans.first().expect("Empty QR row");
        assert_eq!(first_span.style.bg, Some(ratatui::style::Color::White), "Left quiet zone must be white at row {}", row_idx);
        assert!(first_span.content.len() >= 2, "Left quiet zone must be at least 2 chars wide");

        let last_span = row.spans.last().expect("Empty QR row");
        assert_eq!(last_span.style.bg, Some(ratatui::style::Color::White), "Right quiet zone must be white at row {}", row_idx);
        assert!(last_span.content.len() >= 2, "Right quiet zone must be at least 2 chars wide");
    }

    // Invariant 4: Finder Pattern Structure (Top-Left Finder Pattern, 7x7 modules)
    // Module row 1 (first row inside quiet zone): Top-left finder pattern begins with 7 dark modules (14 chars of Black)
    let row1 = &qr_lines[1];
    // Span 0 is left quiet zone (2 chars white), Span 1 should be dark finder pattern outer border
    let dark_finder_border = &row1.spans[1];
    assert_eq!(
        dark_finder_border.style.bg,
        Some(ratatui::style::Color::Black),
        "Finder pattern top-left outer border must be black"
    );
    assert!(
        dark_finder_border.content.len() >= 14,
        "Finder pattern top-left outer border must be at least 7 modules (14 chars) wide"
    );
}

#[test]
fn test_optical_qr_bmp_export_format_and_headers() {
    let state = create_test_state();
    let seed = state.seed.as_ref().unwrap();

    // Generate BMP for descriptor
    let bmp_bytes = encode_qr_bmp(&seed.descriptor, 8, 4).expect("BMP encoding failed");
    assert!(bmp_bytes.len() > 62, "BMP header size invalid");

    // Assert Magic Header b"BM"
    assert_eq!(&bmp_bytes[0..2], b"BM", "Invalid BMP magic bytes");

    // Assert File Size in header matches buffer length
    let file_size = u32::from_le_bytes(bmp_bytes[2..6].try_into().unwrap()) as usize;
    assert_eq!(file_size, bmp_bytes.len(), "BMP header file size mismatch");

    // Assert Pixel Data Offset = 62 (14-byte BMP header + 40-byte DIB header + 8-byte color table)
    let offset = u32::from_le_bytes(bmp_bytes[10..14].try_into().unwrap());
    assert_eq!(offset, 62, "BMP pixel offset must be 62 for 1-bit monochrome");

    // Assert 1 bit per pixel
    let bpp = u16::from_le_bytes(bmp_bytes[28..30].try_into().unwrap());
    assert_eq!(bpp, 1, "BMP must be 1-bit monochrome");
}

// ============================================================================
// VECTOR 2: NON-TECHNICAL HEIR RECOVERY WORKFLOW USABILITY
// ============================================================================

#[test]
fn test_tab8_benefactor_provisioner_plain_english_estate_protocol() {
    let mut state = create_test_state();
    state.current_page = Page::EstateProvisioner;

    for &(w, h) in &COTS_RESOLUTIONS {
        let (lines, screen_text) = render_to_screen(&state, w, h);

        // Assert non-jargony plain English protocol guidance
        assert!(screen_text.contains("AIRGAPPED ENCRYPTED ESTATE STORAGE PROVISIONER"));
        assert!(screen_text.contains("Target Partition:"));
        assert!(screen_text.contains("Passphrase Status: PRESENT IN RAM"));
        assert!(screen_text.contains("Controls: Press [P] to encrypt and write estate files to Partition 2."));

        for line in &lines {
            assert!(
                line.chars().count() <= w as usize,
                "Line overflow on Tab 8 at {}x{}: '{}'",
                w, h, line
            );
        }

        if h >= 30 {
            assert!(screen_text.contains("PLAIN-ENGLISH ESTATE PROTOCOL:"));
            assert!(screen_text.contains("1. What is written? An encrypted vault file"));
            assert!(screen_text.contains("2. Who can read it? ONLY someone who enters the 12-word Passphrase"));
            assert!(screen_text.contains("3. Burglar / Loss Safety: If this SD card is lost or stolen"));
            assert!(screen_text.contains("4. Pure Determinism: All encryption salts and keys"));
        }
    }
}

#[test]
fn test_tab9_heir_guidance_and_usb_insertion_prompts() {
    let mut state = AppState::new("2026-09-07 12:00:00Z".to_string(), "c0ffee1".to_string());
    state.current_page = Page::VaultUnlock;

    for &(w, h) in &COTS_RESOLUTIONS {
        let (lines, screen_text) = render_to_screen(&state, w, h);

        // Operator guidance prompts
        assert!(screen_text.contains("INHERITANCE RECOVERY & VAULT AUTHENTICATION ENGINE"));
        assert!(screen_text.contains("Enter your 12-Word Decoupled Estate Passphrase below to decrypt vault.json:"));

        for line in &lines {
            assert!(
                line.chars().count() <= w as usize,
                "Line overflow on Tab 9 at {}x{}: '{}'",
                w, h, line
            );
        }

        if h >= 30 {
            assert!(screen_text.contains("OPERATOR GUIDANCE (IF YOU ARE AN HEIR OR EXECUTOR):"));
            assert!(screen_text.contains("1. Welcome: This tab is your recovery workstation."));
            assert!(screen_text.contains("2. Enter Passphrase: Type the 12 words provided in your estate letter."));
            assert!(screen_text.contains("3. Unknown Passphrase? Check benefactor estate planning packet"));
            assert!(screen_text.contains("4. Press [ENTER]: The vault unlocks in amnesic memory."));
            assert!(screen_text.contains("5. Zero Footprint: Nothing is ever saved to disk."));
        }
    }
}

#[test]
fn test_tab9_passphrase_entry_metrics_and_visual_masking() {
    let mut state = AppState::new("2026-09-07 12:00:00Z".to_string(), "c0ffee1".to_string());
    state.current_page = Page::VaultUnlock;

    // 1. Initial empty state
    let (_lines, screen_empty) = render_to_screen(&state, 100, 30);
    assert!(screen_empty.contains("Type 12-word passphrase or 't0'..'t9' / 'test'..."));
    assert!(screen_empty.contains("0 word(s) entered | 0 character(s)"));
    assert!(screen_empty.contains("[AWAITING INPUT]"));

    // 2. Typed words in plaintext visible mode
    let phrase = "prosper voice ladder drill rich sugar direct shrug cycle fossil visual hollow";
    state.vault_passphrase_input = phrase.to_string();
    assert_eq!(state.vault_mask_passphrase, false);

    let (_lines, screen_visible) = render_to_screen(&state, 100, 30);
    assert!(screen_visible.contains(phrase));
    assert!(screen_visible.contains("12 word(s) entered | 77 character(s)"));
    assert!(screen_visible.contains("[VISIBLE - Press Ctrl+M to Mask]"));

    // 3. Toggle visual masking via Ctrl+M keypress
    let ctrl_m = make_key(KeyCode::Char('m'), KeyModifiers::CONTROL);
    let exit = handle_key_event(&mut state, ctrl_m);
    assert!(!exit);
    assert_eq!(state.vault_mask_passphrase, true);

    let (_lines, screen_masked) = render_to_screen(&state, 100, 30);
    assert!(!screen_masked.contains(phrase), "Plaintext leaked when masked!");
    assert!(screen_masked.contains("••••••••"));
    assert!(screen_masked.contains("12 word(s) entered | 77 character(s)"));
    assert!(screen_masked.contains("[MASKED - Press Ctrl+M to Unmask]"));

    // 4. Toggle back to unmasked
    let exit2 = handle_key_event(&mut state, ctrl_m);
    assert!(!exit2);
    assert_eq!(state.vault_mask_passphrase, false);
    let (_lines, screen_unmasked) = render_to_screen(&state, 100, 30);
    assert!(screen_unmasked.contains(phrase));
    assert!(screen_unmasked.contains("[VISIBLE - Press Ctrl+M to Mask]"));
}

#[test]
fn test_tab9_decryption_success_state_calm_guidance_and_export_pointers() {
    let mut state = AppState::new("2026-09-07 12:00:00Z".to_string(), "c0ffee1".to_string());
    state.current_page = Page::VaultUnlock;

    // Use test vector 0 shortcut to simulate successful decryption
    state.vault_passphrase_input = "test0".to_string();
    state.attempt_vault_decrypt();

    assert!(state.decrypted_vault.is_some());
    let payload = state.decrypted_vault.as_ref().unwrap();

    for &(w, h) in &COTS_RESOLUTIONS {
        let (lines, screen_text) = render_to_screen(&state, w, h);

        // Assert calm, reassuring success message
        assert!(screen_text.contains("[✓] RECOVERY SUCCESSFUL"));
        assert!(screen_text.contains("Master Root Mnemonic:"));
        assert!(screen_text.contains("Output Descriptor:"));

        for line in &lines {
            assert!(
                line.chars().count() <= w as usize,
                "Line overflow on Tab 9 success at {}x{}: '{}'",
                w, h, line
            );
        }

        // Assert all 12 master mnemonic words are visible on screen
        for word in payload.master_root_mnemonic.split_whitespace() {
            assert!(
                screen_text.contains(word),
                "Mnemonic word '{}' missing on Tab 9 at {}x{}",
                word, w, h
            );
        }

        if w >= 128 {
            assert!(screen_text.contains(&payload.master_root_mnemonic));
        }

        if h >= 30 {
            assert!(screen_text.contains("Key Location Guidance:"));
            assert!(screen_text.contains("Next Actions:"));
        }
    }
}

#[test]
fn test_tab9_decryption_failure_states_panic_prevention_messages() {
    let mut state = AppState::new("2026-09-07 12:00:00Z".to_string(), "c0ffee1".to_string());
    state.current_page = Page::VaultUnlock;

    // Failure 1: Empty passphrase
    state.vault_passphrase_input = "".to_string();
    state.attempt_vault_decrypt();
    assert!(state.decrypted_vault.is_none());
    assert!(state.vault_status_msg.contains("[!] Passphrase cannot be empty."));

    // Failure 2: Missing USB drive partition
    state.vault_passphrase_input = "prosper voice ladder drill rich sugar direct shrug cycle fossil visual hollow".to_string();
    state.attempt_vault_decrypt();
    assert!(state.decrypted_vault.is_none());
    // Since Partition 2 is not mounted in normal test container:
    assert!(
        state.vault_status_msg.contains("Partition 2 error") || state.vault_status_msg.contains("SUBZERO_EST"),
        "Missing USB message missing: '{}'", state.vault_status_msg
    );
    assert!(
        state.vault_status_msg.contains("Insert estate USB/SD card"),
        "USB insertion guidance missing: '{}'", state.vault_status_msg
    );
}

// ============================================================================
// VECTOR 3: PANIC-OPERATOR KEYBOARD CHAOS FUZZING
// ============================================================================

#[test]
fn test_panic_operator_random_keystroke_chaos_fuzzing_all_tabs() {
    let mut state = create_test_state();

    let chaos_keys = [
        // Function keys
        KeyCode::F(1), KeyCode::F(2), KeyCode::F(5), KeyCode::F(10), KeyCode::F(12),
        // Arrow bursts
        KeyCode::Up, KeyCode::Down, KeyCode::Left, KeyCode::Right,
        KeyCode::PageUp, KeyCode::PageDown, KeyCode::Home, KeyCode::End,
        // Alphanumeric keys
        KeyCode::Char('a'), KeyCode::Char('z'), KeyCode::Char('1'), KeyCode::Char('9'),
        KeyCode::Char(' '), KeyCode::Char('!'), KeyCode::Char('@'), KeyCode::Char('\n'),
        // Boundary controls
        KeyCode::Backspace, KeyCode::Delete, KeyCode::Tab, KeyCode::BackTab, KeyCode::Enter,
    ];

    let modifiers_pool = [
        KeyModifiers::NONE,
        KeyModifiers::SHIFT,
        KeyModifiers::ALT,
        KeyModifiers::CONTROL,
    ];

    // Simulate 2,000 chaotic keystrokes across all 14 pages
    for i in 0..2000 {
        let code = chaos_keys[i % chaos_keys.len()];
        let mods = modifiers_pool[(i / 3) % modifiers_pool.len()];

        // Filter out Ctrl+C which intentionally breaks the loop
        if mods.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
            continue;
        }

        let key = make_key(code, mods);
        let _exit = handle_key_event(&mut state, key);

        // Every 50 strokes, verify headless rendering at standard 80x25 VGA without crashing
        if i % 50 == 0 {
            let (lines, _screen) = render_to_screen(&state, 80, 25);
            assert_eq!(lines.len(), 25, "Rendered rows must match buffer height");
        }
    }
}

#[test]
fn test_panic_operator_emergency_exit_q_two_stroke_confirmation_timing() {
    let mut state = create_test_state();
    state.current_page = Page::RoleSelect;

    let q_key = make_key(KeyCode::Char('q'), KeyModifiers::NONE);

    // Stroke 1: Single [Q] press must NOT exit and must set confirmation timer
    let exit1 = handle_key_event(&mut state, q_key);
    assert!(!exit1, "First [Q] press must never exit immediately");
    assert!(state.pending_exit_instant.is_some());
    assert!(state.status_message.contains("[!] PRESS [Q] AGAIN WITHIN 3 SECONDS TO CONFIRM EXIT & PURGE RAM."));

    // Interrupt with random key (e.g. Right arrow)
    let right_key = make_key(KeyCode::Right, KeyModifiers::NONE);
    let exit_intr = handle_key_event(&mut state, right_key);
    assert!(!exit_intr);
    assert!(state.pending_exit_instant.is_none(), "Interrupt key must reset pending exit");

    // Stroke 1 again
    let exit2 = handle_key_event(&mut state, q_key);
    assert!(!exit2);
    assert!(state.pending_exit_instant.is_some());

    // Stroke 2 within 3 seconds: MUST confirm exit
    let exit3 = handle_key_event(&mut state, q_key);
    assert!(exit3, "Second [Q] press within 3 seconds must trigger exit confirmation");

    // Test typing pages immunity:
    // On VaultUnlock, 'q' should type the character 'q' and NOT trigger exit
    let mut typing_state = AppState::new("2026-09-07".to_string(), "commit".to_string());
    typing_state.current_page = Page::VaultUnlock;
    typing_state.vault_passphrase_input.clear();

    let exit_type1 = handle_key_event(&mut typing_state, q_key);
    assert!(!exit_type1);
    assert_eq!(typing_state.vault_passphrase_input, "q");
    assert!(typing_state.pending_exit_instant.is_none());

    let exit_type2 = handle_key_event(&mut typing_state, q_key);
    assert!(!exit_type2);
    assert_eq!(typing_state.vault_passphrase_input, "qq");
    assert!(typing_state.pending_exit_instant.is_none());
}

#[test]
fn test_panic_operator_rapid_w_wipe_memory_hygiene_and_typing_protection() {
    let mut state = create_test_state();
    let w_key = make_key(KeyCode::Char('w'), KeyModifiers::NONE);

    // 1. Verify [W] wipes memory on RoleSelect
    state.current_page = Page::RoleSelect;
    assert!(state.seed.is_some());
    let _ = handle_key_event(&mut state, w_key);
    assert!(state.seed.is_none());
    assert!(state.decoupled_passphrase.is_none());
    assert!(state.bip85_children.is_empty());
    assert!(state.status_message.contains("MEMORY WIPED"));

    // 2. Repopulate seed
    let coin_entropy = "00100000100000001011001110010010111010101100001000111101101000011101000111001011101001111001000001011110011011010100100100110011";
    let seed = process_physical_entropy(coin_entropy).unwrap();
    let children = derive_bip85_children(&seed.mnemonic, 20).unwrap();
    state.set_seed(seed, children);
    assert!(state.seed.is_some());

    // 3. Navigate to SeedFix typing page
    // Typing words like 'word', 'water', 'wait' must NOT trigger memory wipe!
    state.current_page = Page::SeedFix;
    state.seedfix_input.clear();
    let _ = handle_key_event(&mut state, w_key);
    assert!(state.seed.is_some(), "W wipe must be disabled on active typing pages");
    assert_eq!(state.seedfix_input, "w");

    // 4. Navigate to WordlistInspector typing page
    state.current_page = Page::WordlistInspector;
    state.wordlist_query.clear();
    let _ = handle_key_event(&mut state, w_key);
    assert!(state.seed.is_some(), "W wipe must be disabled on wordlist inspector");
    assert_eq!(state.wordlist_query, "w");

    // 5. Rapid wipe mashing on MasterSeed tab: first 'w' wipes loaded keys;
    // subsequent 'w' strokes are protected by Invariant 1 and typed as entropy input.
    state.current_page = Page::MasterSeed;
    let _ = handle_key_event(&mut state, w_key);
    assert!(state.seed.is_none(), "First 'w' must wipe loaded keys from memory");
    assert!(state.vault_passphrase_input.is_empty());
    assert!(state.status_message.contains("MEMORY WIPED"));

    // Subsequent 'w' when uninitialized must type safely into entropy without crashing
    for _ in 0..49 {
        let _ = handle_key_event(&mut state, w_key);
    }
    assert!(state.seed.is_none());
    assert_eq!(state.entropy_input.len(), 49, "Subsequent 'w' safely appended to entropy_input");
}

#[test]
fn test_panic_operator_esc_and_home_recovery_invariants() {
    let mut state = create_test_state();
    let esc_key = make_key(KeyCode::Esc, KeyModifiers::NONE);
    let home_key = make_key(KeyCode::Home, KeyModifiers::NONE);

    for page in Page::ALL {
        state.current_page = page;
        state.vault_passphrase_input = "partial input".to_string();
        state.seedfix_input = "partial seedfix".to_string();
        state.wordlist_query = "query".to_string();

        let _ = handle_key_event(&mut state, esc_key);
        assert_eq!(state.current_page, Page::RoleSelect, "Esc must always return to Tab 0 from {:?}", page);
        assert!(state.vault_passphrase_input.is_empty(), "Esc must clear transient input buffers");
        assert!(state.seedfix_input.is_empty(), "Esc must clear transient input buffers");
        assert!(state.wordlist_query.is_empty(), "Esc must clear transient input buffers");

        // Test Home key
        state.current_page = page;
        let _ = handle_key_event(&mut state, home_key);
        assert_eq!(state.current_page, Page::RoleSelect, "Home must always return to Tab 0 from {:?}", page);
    }
}

#[test]
fn test_non_technical_heir_end_to_end_emergency_recovery_journey() {
    // Simulate non-technical heir sitting in front of the laptop with their estate letter:
    let mut state = AppState::new("2026-09-07 12:00:00Z".to_string(), "c0ffee1".to_string());
    assert_eq!(state.current_page, Page::RoleSelect);

    // Step 1: Heir presses '2' ("I AM AN HEIR OR EXECUTOR")
    let key_2 = make_key(KeyCode::Char('2'), KeyModifiers::NONE);
    handle_key_event(&mut state, key_2);
    assert_eq!(state.current_page, Page::VaultUnlock);

    // Step 2: Heir inspects instructions and types their 12-word estate passphrase
    let heir_words = "test0"; // Using deterministic test vector shortcut for test isolation
    for c in heir_words.chars() {
        handle_key_event(&mut state, make_key(KeyCode::Char(c), KeyModifiers::NONE));
    }
    assert_eq!(state.vault_passphrase_input, "test0");

    // Step 3: Heir presses [ENTER] to authenticate
    let enter_key = make_key(KeyCode::Enter, KeyModifiers::NONE);
    handle_key_event(&mut state, enter_key);
    assert!(state.decrypted_vault.is_some());
    assert!(state.vault_status_msg.contains("[✓]"));

    // Step 4: Heir verifies keys rendered on screen at standard 80x25 VGA
    let (_lines, screen) = render_to_screen(&state, 80, 25);
    assert!(screen.contains("[✓] RECOVERY SUCCESSFUL"));
    assert!(screen.contains("Master Root Mnemonic:"));

    // Step 5: Heir follows on-screen advice and presses Tab to navigate to Tab 4 (Watch-Only QR)
    // First heir presses Esc to exit typing mode
    handle_key_event(&mut state, make_key(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(state.current_page, Page::RoleSelect);

    // Step 6: When done, heir wipes memory with [W]
    let w_key = make_key(KeyCode::Char('w'), KeyModifiers::NONE);
    handle_key_event(&mut state, w_key);
    assert!(state.decrypted_vault.is_none());
    assert!(state.status_message.contains("MEMORY WIPED"));
}

#[test]
fn test_tab9_30min_inactivity_autolock_and_reset() {
    let mut state = AppState::new("2026-09-07 12:00:00Z".to_string(), "c0ffee1".to_string());
    state.current_page = Page::VaultUnlock;
    state.vault_passphrase_input = "test0".to_string();
    state.attempt_vault_decrypt();
    assert!(state.decrypted_vault.is_some());

    // 1. Simulating 29 minutes elapsed (no autolock yet)
    state.last_activity_instant = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(29 * 60))
        .unwrap();
    state.check_inactivity_autolock();
    assert!(state.decrypted_vault.is_some(), "Vault must remain unlocked at 29 minutes");

    // 2. Simulating keystroke resets last_activity_instant
    handle_key_event(&mut state, make_key(KeyCode::Right, KeyModifiers::NONE));
    assert!(state.last_activity_instant.elapsed() < std::time::Duration::from_secs(2));

    // 3. Simulating 30 minutes + 1 second elapsed without activity
    state.last_activity_instant = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(1801))
        .unwrap();
    state.check_inactivity_autolock();
    assert!(state.decrypted_vault.is_none(), "Vault must auto-lock after 30 minutes of inactivity");
    assert!(state.vault_status_msg.contains("Auto-Lock: Vault locked after 30 minutes"));
}
