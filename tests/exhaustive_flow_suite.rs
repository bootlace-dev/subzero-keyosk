use subzero::ui::{AppState, Page, render_app};
use subzero::qr::QrMode;
use subzero::crypto::{process_physical_entropy, derive_bip85_children, harvest_keystroke_jitter_to_binary, get_test_vector};
use subzero::seedfix::solve_twelfth_word;
use ratatui::backend::TestBackend;
use ratatui::Terminal;

/// Helper to render state and ensure zero panics across multiple screen dimensions
fn assert_render_all_resolutions(state: &AppState) {
    let resolutions = [(80, 25), (100, 30), (120, 40), (160, 50)];
    for &(w, h) in &resolutions {
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).expect("Failed creating TestBackend");
        terminal.draw(|f| render_app(f, state)).expect(&format!("Render failed at {}x{} on page {:?}", w, h, state.current_page));
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
