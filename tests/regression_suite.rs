use subzero::ui::{AppState, Page, render_app};
use subzero::crypto::{process_physical_entropy, derive_bip85_children, harvest_keystroke_jitter_to_binary, encrypt_vault_payload, decrypt_vault_json, DecryptedVaultPayload};
use subzero::seedfix::solve_twelfth_word;
use ratatui::backend::TestBackend;
use ratatui::Terminal;

#[test]
fn test_headless_tui_render_all_14_tabs_no_panics() {
    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).expect("Failed to init TestBackend");

    let mut state = AppState::new("2026-09-05 21:00:00Z".to_string(), "b1de214".to_string());

    // 1. Render Tab 0 (RoleSelect)
    assert_eq!(state.current_page, Page::RoleSelect);
    terminal.draw(|f| render_app(f, &state)).expect("Failed drawing Tab 0");

    // 2. Generate a valid master seed via 128 coin flips
    let coin_entropy = "10100110110010111000101011110011011110100010101101111010101100111000101011110011011110100010101101111010101100111000101011110011";
    let seed = process_physical_entropy(coin_entropy).expect("Valid coin entropy failed");
    let children = derive_bip85_children(&seed.mnemonic, 20).expect("BIP-85 derivation failed");
    state.set_seed(seed, children);

    // 3. Render every single page in Page::ALL to ensure zero panics, bounds issues, or formatting faults
    for page in Page::ALL {
        state.current_page = page;
        terminal.draw(|f| render_app(f, &state)).expect(&format!("Failed drawing page {:?}", page));
    }
}

#[test]
fn test_keystroke_jitter_harvest_lifecycle_and_transition() {
    let mut state = AppState::new("2026-09-05 21:00:00Z".to_string(), "b1de214".to_string());
    state.current_page = Page::MasterSeed;
    state.is_harvesting_jitter = true;
    state.jitter_samples.clear();

    // Simulate 32 keystrokes with variable human millisecond jitter
    let mock_keys = ['a', 's', 'd', 'f', 'j', 'k', 'l', ';', 'q', 'w', 'e', 'r', 'u', 'i', 'o', 'p',
                     'z', 'x', 'c', 'v', 'm', ',', '.', '/', '1', '2', '3', '4', '7', '8', '9', '0'];

    for (i, &k) in mock_keys.iter().enumerate() {
        let delta = 85_000_000 + (i as u64 * 3_141_592); // varying nanosecond jitter
        state.jitter_samples.push((k, delta));
    }

    assert_eq!(state.jitter_samples.len(), 32);

    // Run the harvester to produce 128 bits
    let bits = harvest_keystroke_jitter_to_binary(&state.jitter_samples);
    assert_eq!(bits.len(), 128);
    assert!(bits.chars().all(|c| c == '0' || c == '1'));

    // Populate state and verify Miller's law chunking & Markov audit pass
    state.set_entropy_input(&bits);
    state.is_harvesting_jitter = false;

    assert_eq!(state.entropy_input.len(), 128);
    assert!(state.status_message.contains("128-bit threshold valid"));

    // Derive seed from the jitter entropy
    let seed = process_physical_entropy(&state.entropy_input).expect("Jitter bits failed entropy processing");
    let children = derive_bip85_children(&seed.mnemonic, 20).expect("BIP85 derivation failed");
    state.set_seed(seed, children);

    assert!(state.seed.is_some());
    assert_eq!(state.seed.as_ref().unwrap().mnemonic.split_whitespace().count(), 12);
    assert!(state.decoupled_passphrase.is_some());
    assert_eq!(state.bip85_children.len(), 20);
}

#[test]
fn test_vault_encryption_decryption_full_roundtrip() {
    let payload = DecryptedVaultPayload {
        version: "1.0.0".to_string(),
        created_utc: "2026-09-05T20:00:00Z".to_string(),
        master_root_mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        descriptor: "wpkh([1c23b5f0/84'/1'/0']tpubDC59.../<0;1>/*)#12345678".to_string(),
        heir_treasuries: vec![],
    };

    let passphrase = "prosper voice ladder drill rich sugar direct shrug cycle fossil visual hollow";

    // 1. Encrypt payload
    let encrypted = encrypt_vault_payload(&payload, passphrase).expect("Encryption failed");

    // 2. Decrypt with correct passphrase
    let decrypted = decrypt_vault_json(&encrypted, passphrase).expect("Decryption failed");
    assert_eq!(decrypted.master_root_mnemonic, payload.master_root_mnemonic);
    assert_eq!(decrypted.descriptor, payload.descriptor);

    // 3. Attempt decrypt with wrong passphrase -> must fail cleanly
    let wrong_passphrase = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
    assert!(decrypt_vault_json(&encrypted, wrong_passphrase).is_err());
}

#[test]
fn test_seedfix_levenshtein_checksum_exhaustion() {
    let eleven_words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    
    // Typo query
    let typo = "aboot";
    let matches = solve_twelfth_word(eleven_words, Some(typo)).expect("SeedFix solver failed");

    assert_eq!(matches.len(), 128);
    // Closest match should be "about" with Levenshtein distance 1
    assert_eq!(matches[0].twelfth_word, "about");
    assert_eq!(matches[0].distance, 1);
}

#[test]
fn test_amnesic_wipe_hygiene() {
    let mut state = AppState::new("2026-09-05".to_string(), "b1de214".to_string());
    
    let coin_entropy = "10100110110010111000101011110011011110100010101101111010101100111000101011110011011110100010101101111010101100111000101011110011";
    let seed = process_physical_entropy(coin_entropy).unwrap();
    let children = derive_bip85_children(&seed.mnemonic, 20).unwrap();
    state.set_seed(seed, children);
    state.set_entropy_input(coin_entropy);
    state.vault_passphrase_input = "test phrase".to_string();

    assert!(state.seed.is_some());
    assert!(!state.entropy_input.is_empty());

    // Trigger Wipe
    state.wipe_memory();

    assert!(state.seed.is_none());
    assert!(state.decoupled_passphrase.is_none());
    assert!(state.bip85_children.is_empty());
    assert!(state.entropy_input.is_empty());
    assert!(!state.is_harvesting_jitter);
    assert_eq!(state.current_page, Page::RoleSelect);
    assert!(state.status_message.contains("MEMORY WIPED"));
}
