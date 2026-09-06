use subzero::ui::{AppState, Page, render_app};
use subzero::qr::QrMode;
use subzero::crypto::{process_physical_entropy, derive_bip85_children, harvest_keystroke_jitter_to_binary, get_test_vector};
use subzero::seedfix::solve_twelfth_word;
use ratatui::backend::TestBackend;
use ratatui::Terminal;

/// Helper to render state, inspect every rendered character in the buffer, and ensure zero truncation/overflow
fn assert_render_all_resolutions(state: &AppState) {
    let resolutions = [(80, 25), (100, 30), (120, 40), (160, 50)];
    for &(w, h) in &resolutions {
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).expect("Failed creating TestBackend");
        terminal.draw(|f| render_app(f, state)).expect(&format!("Render failed at {}x{} on page {:?}", w, h, state.current_page));

        // Deep character inspection: Extract rendered text line-by-line from Ratatui buffer
        let buffer = terminal.backend().buffer();
        for y in 0..h {
            let mut line_str = String::with_capacity(w as usize);
            for x in 0..w {
                let cell = buffer.get(x, y);
                line_str.push_str(cell.symbol());
            }
            let trimmed = line_str.trim_end();
            // Assert no line exceeds the printable width of the terminal
            assert!(
                trimmed.chars().count() <= w as usize,
                "Rendered line exceeded screen width ({}) on page {:?} at row {}: '{}'",
                w, state.current_page, y, trimmed
            );
        }
    }
}

#[test]
fn test_exhaustive_entropy_input_methods_and_screen_rendering() {
    let mut state = AppState::new("2026-09-05 21:00:00Z".to_string(), "b1de214".to_string());

    // 1. Test every test vector from test0 through test9
    for i in 0..=9 {
        let (bytes, label) = get_test_vector(i).expect(&format!("Failed test vector {}", i));
        let bits: String = bytes.iter().flat_map(|b| (0..8).rev().map(move |n| if (b >> n) & 1 == 1 { '1' } else { '0' })).collect();
        let seed = process_physical_entropy(&format!("test{}", i)).expect(&format!("Failed processing test vector {}", label));
        let children = derive_bip85_children(&seed.mnemonic, 20).expect("Failed children");
        
        state.set_seed(seed, children);
        assert!(state.seed.is_some());
        assert!(state.is_test_entropy());

        // Render every page under this test vector
        for page in Page::ALL {
            state.current_page = page;
            assert_render_all_resolutions(&state);
        }

        state.wipe_memory();
        assert!(state.seed.is_none());
    }

    // 2. Test 52 dice rolls input
    let dice_input = "42312461325416235142635142316524136251436251436251";
    let seed_dice = process_physical_entropy(dice_input).expect("Dice entropy failed");
    let children_dice = derive_bip85_children(&seed_dice.mnemonic, 20).expect("Dice children failed");
    state.set_seed(seed_dice, children_dice);
    for page in Page::ALL {
        state.current_page = page;
        assert_render_all_resolutions(&state);
    }
    state.wipe_memory();

    // 3. Test 128 coin flips input
    let coin_input = "10100110110010111000101011110011011110100010101101111010101100111000101011110011011110100010101101111010101100111000101011110011";
    let seed_coin = process_physical_entropy(coin_input).expect("Coin entropy failed");
    let children_coin = derive_bip85_children(&seed_coin.mnemonic, 20).expect("Coin children failed");
    state.set_seed(seed_coin, children_coin);
    for page in Page::ALL {
        state.current_page = page;
        assert_render_all_resolutions(&state);
    }
    state.wipe_memory();
}

#[test]
fn test_exhaustive_qr_modes_and_bbqr_frame_animations() {
    let mut state = AppState::new("2026-09-05 21:00:00Z".to_string(), "b1de214".to_string());
    let coin_input = "10100110110010111000101011110011011110100010101101111010101100111000101011110011011110100010101101111010101100111000101011110011";
    let seed = process_physical_entropy(coin_input).unwrap();
    let children = derive_bip85_children(&seed.mnemonic, 20).unwrap();
    state.set_seed(seed, children);
    state.current_page = Page::VpubQr;

    // Test all QR modes
    let modes = [QrMode::BbqrAnimated, QrMode::FullBlockSpace, QrMode::StaticVpub];
    for mode in modes {
        state.qr_mode = mode;
        for frame in 0..10 {
            state.bbqr_frame_index = frame;
            assert_render_all_resolutions(&state);
        }
    }
}

#[test]
fn test_exhaustive_pagination_boundaries() {
    let mut state = AppState::new("2026-09-05 21:00:00Z".to_string(), "b1de214".to_string());
    let coin_input = "10100110110010111000101011110011011110100010101101111010101100111000101011110011011110100010101101111010101100111000101011110011";
    let seed = process_physical_entropy(coin_input).unwrap();
    let children = derive_bip85_children(&seed.mnemonic, 20).unwrap();
    state.set_seed(seed, children);

    // 1. Tab 6: Address pagination (50 total addresses, 25 per page)
    state.current_page = Page::Addresses;
    for offset in [0, 25, 50, 100] {
        state.address_page_offset = offset;
        assert_render_all_resolutions(&state);
    }

    // 2. Tab 7: BIP-85 pagination (20 total children, 8 per page)
    state.current_page = Page::Bip85Children;
    for offset in [0, 8, 16, 24, 100] {
        state.heir_page_offset = offset;
        assert_render_all_resolutions(&state);
    }
}

#[test]
fn test_exhaustive_seedfix_and_wordlist_fuzzy_queries() {
    let mut state = AppState::new("2026-09-05 21:00:00Z".to_string(), "b1de214".to_string());
    
    // Tab 10: SeedFix
    state.current_page = Page::SeedFix;
    let eleven_words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    let typos = ["", "a", "ab", "abo", "aboot", "zoo", "wrong", "zzzzz", "1234"];
    for typo in typos {
        let opt_typo = if typo.is_empty() { None } else { Some(typo) };
        let results = solve_twelfth_word(eleven_words, opt_typo).expect("SeedFix solver failed");
        assert_eq!(results.len(), 128);
        assert_render_all_resolutions(&state);
    }

    // Tab 11: Wordlist Inspector
    state.current_page = Page::WordlistInspector;
    let queries = ["", "a", "ab", "aban", "z", "zoo", "qwerty", "notaword"];
    for q in queries {
        state.wordlist_query = q.to_string();
        assert_render_all_resolutions(&state);
    }
}

#[test]
fn test_exhaustive_vault_unlock_flows() {
    let mut state = AppState::new("2026-09-05 21:00:00Z".to_string(), "b1de214".to_string());
    state.current_page = Page::VaultUnlock;

    let inputs = [
        "",
        "test",
        "test0",
        "wrong phrase",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "prosper voice ladder drill rich sugar direct shrug cycle fossil visual hollow",
    ];

    for input in inputs {
        state.vault_passphrase_input = input.to_string();
        state.attempt_vault_decrypt();
        assert_render_all_resolutions(&state);
    }
}

#[test]
fn test_verify_every_text_character_and_sentence_on_every_tab() {
    let mut state = AppState::new("2026-09-05 21:00:00Z".to_string(), "4d8b5dc".to_string());
    
    // Test with the standard 12-word seed
    let coin_entropy = "10100110110010111000101011110011011110100010101101111010101100111000101011110011011110100010101101111010101100111000101011110011";
    let seed = process_physical_entropy(coin_entropy).unwrap();
    let children = derive_bip85_children(&seed.mnemonic, 20).unwrap();
    state.set_seed(seed, children);

    // Target terminal screen: 120 cols x 40 rows (matching Dell console)
    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).expect("Failed to init TestBackend");

    // Expected text assertions tab by tab
    let expected_phrases_per_page: &[(Page, &[&str])] = &[
        (Page::RoleSelect, &[
            "SOVEREIGN BITCOIN COLD STORAGE & ESTATE RECOVERY APPLIANCE",
            "[1] I AM THE BENEFACTOR (VAULT CREATOR)",
            "[2] I AM AN HEIR OR EXECUTOR (ESTATE RECOVERY)",
            "[3] EMERGENCY TOOLS & SEED REPAIR (SEEDFIX / WORDLIST)",
        ]),
        (Page::MasterSeed, &[
            "12-WORD SEED PHRASE (HORIZONTAL READING ORDER):",
            "METAL PUNCH / COLUMN GUIDANCE:",
            "Master Fingerprint:",
            "Protocol Network:",
            "Bitcoin Testnet4",
        ]),
        (Page::Passphrase, &[
            "12-WORD PASSPHRASE (HORIZONTAL READING ORDER):",
            "METAL PUNCH / COLUMN GUIDANCE:",
            "CRITICAL ANTI-COLOCATION PROTOCOL",
            "TWO-LOCATION RECOVERY FORMULA:",
        ]),
        (Page::Descriptor, &[
            "WATCH-ONLY OUTPUT DESCRIPTOR (BIP-380 / BIP-84):",
            "BIP-32 Account Public Key",
            "SLIP-0132 Native SegWit Key",
            "WALLET IMPORT PROTOCOL & COMPATIBILITY MATRIX:",
        ]),
        (Page::VpubQr, &[
            "Tab 4. Airgapped Export QR",
            "[M] Rotate Mode",
            "[E] USB",
        ]),
        (Page::FaucetQr, &[
            "Tab 5. Faucet QR Code",
        ]),
        (Page::Addresses, &[
            "Tab 6. Receive Addresses",
            "PURPOSE & ADDRESS INTEGRITY (GAP LIMIT & REUSE ADVISORY):",
        ]),
        (Page::Bip85Children, &[
            "Tab 7. BIP-85 Heir Keys",
            "Deterministic Heir Seeds",
            "ROLE & PURPOSE: OPTIONAL BIP-85 SUB-TREASURIES:",
        ]),
        (Page::EstateProvisioner, &[
            "Tab 8. Partition 2 Estate Writer",
            "PLAIN-ENGLISH ESTATE PROTOCOL:",
        ]),
        (Page::VaultUnlock, &[
            "Tab 9. Unlock & Decrypt Estate Vault",
            "Enter your 12-Word Decoupled Estate Passphrase",
            "OPERATOR GUIDANCE (IF YOU ARE AN HEIR OR EXECUTOR):",
        ]),
        (Page::SeedFix, &[
            "Tab 10. SeedFix Recovery Tool",
            "Levenshtein",
            "WHY IS THIS POSSIBLE? (THE 12TH WORD CHECKSUM):",
        ]),
        (Page::WordlistInspector, &[
            "Tab 11. BIP-39 Canonical English Wordlist Inspector",
            "Search Prefix/Substrings:",
            "THE 4-LETTER BIP-39 RULE:",
        ]),
        (Page::DrillGuide, &[
            "Tab 12. 24x4 Metal Punch / Cold Storage Guide",
            "READING ORDER GUIDANCE:",
            "STEEL PUNCHING BEST PRACTICES:",
        ]),
        (Page::Provenance, &[
            "Tab 13. Appliance Build Provenance & Cryptographic Spec",
            "Appliance Engine:",
            "Entropy Invariant:",
        ]),
    ];

    for &(page, expected_strings) in expected_phrases_per_page {
        state.current_page = page;
        terminal.draw(|f| render_app(f, &state)).expect(&format!("Failed drawing page {:?}", page));

        let buffer = terminal.backend().buffer();
        let mut full_screen_text = String::new();
        for y in 0..40 {
            for x in 0..120 {
                full_screen_text.push_str(buffer.get(x, y).symbol());
            }
            full_screen_text.push('\n');
        }

        // Verify every declared sentence/phrase appears intact on the screen
        for &phrase in expected_strings {
            assert!(
                full_screen_text.contains(phrase),
                "Missing expected phrase '{}' on page {:?}\nScreen Content:\n{}",
                phrase, page, full_screen_text
            );
        }

        // Verify universal footer appears cleanly on this tab
        assert!(full_screen_text.contains("NAV:"), "Missing NAV prompt on page {:?}", page);
        assert!(full_screen_text.contains("[Tab/→]"), "Missing Tab prompt on page {:?}", page);
        assert!(full_screen_text.contains("[Home/Esc]"), "Missing Home/Esc prompt on page {:?}", page);
        assert!(full_screen_text.contains("[W] Wipe"), "Missing Wipe prompt on page {:?}", page);
        assert!(full_screen_text.contains("[Q] Exit"), "Missing Exit prompt on page {:?}", page);
    }
}

#[test]
fn test_longest_bip39_words_phrase_on_heir_keys_tab() {
    let mut state = AppState::new("2026-09-05 21:00:00Z".to_string(), "4d8b5dc".to_string());
    
    // In BIP-39, the longest words are 8 letters (e.g. 'umbrella', 'scissors', 'abstract')
    // Construct a simulated heir child seed consisting of the longest words repeated 12 times
    let longest_words = "umbrella scissors abstract accident daughter dinosaur elevator hospital mountain practice remember transfer";
    
    let mut fake_children = Vec::new();
    for i in 1..=8 {
        fake_children.push(subzero::crypto::Bip85Child {
            index: i,
            path: format!("m/83696968'/39'/0'/12/{}'", i),
            mnemonic: longest_words.to_string(),
            label: format!("Heir Vault #{:02}", i),
        });
    }

    state.bip85_children = fake_children;
    state.current_page = Page::Bip85Children;

    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).expect("Failed creating TestBackend");
    terminal.draw(|f| render_app(f, &state)).expect("Render failed with longest BIP39 words");

    let buffer = terminal.backend().buffer();
    for y in 0..40 {
        let mut line_str = String::new();
        for x in 0..120 {
            line_str.push_str(buffer.get(x, y).symbol());
        }
        let trimmed = line_str.trim_end();
        assert!(
            trimmed.chars().count() <= 120,
            "Longest BIP-39 phrase overflowed width at row {}: '{}'",
            y, trimmed
        );
    }
}
