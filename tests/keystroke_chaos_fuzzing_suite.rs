//! Keystroke Chaos & State Machine Fuzzing Suite
//! Exhaustive adversarial verification of all 14 tabs across all sub-states,
//! sensitive single-stroke shortcuts, control sequences, and 100,000+ pseudo-random keystroke sequences.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use std::time::{Duration, Instant};
use subzero::crypto::{derive_bip85_children, process_physical_entropy};
use subzero::qr::QrMode;
use subzero::ui::{handle_key_event, render_app, AppState, Page};

/// Exact test harness delegating to the centralized key-handling state machine logic
pub fn simulate_key_event(state: &mut AppState, key: KeyEvent) -> bool {
    handle_key_event(state, key)
}

/// Helper: construct a standard KeyEvent with no modifiers
fn make_key(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

/// Helper: construct a KeyEvent with explicit modifiers
fn make_key_mods(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
    KeyEvent {
        code,
        modifiers,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

/// Helper: construct a char KeyEvent
fn make_char_key(c: char) -> KeyEvent {
    make_key(KeyCode::Char(c))
}

/// Helper: construct a Ctrl+char KeyEvent
fn make_ctrl_key(c: char) -> KeyEvent {
    make_key_mods(KeyCode::Char(c), KeyModifiers::CONTROL)
}

/// Helper: create a fresh AppState
fn fresh_state() -> AppState {
    AppState::new("2026-09-07T12:00:00Z".to_string(), "b0071ace".to_string())
}

/// Helper: create an AppState populated with valid test vector seed and BIP-85 children
fn seeded_state() -> AppState {
    let mut state = fresh_state();
    let seed = process_physical_entropy("test0").expect("Failed to process test0 entropy");
    let children = derive_bip85_children(&seed.mnemonic, 20).expect("Failed to derive children");
    state.set_seed(seed, children);
    state
}

/// Helper: generate a comprehensive list of all KeyCode variants
fn get_all_test_keys() -> Vec<KeyEvent> {
    let mut keys = Vec::with_capacity(512);

    // 1. Lowercase letters 'a'..='z'
    for c in 'a'..='z' {
        keys.push(make_char_key(c));
    }

    // 2. Uppercase letters 'A'..='Z'
    for c in 'A'..='Z' {
        keys.push(make_char_key(c));
    }

    // 3. Digits '0'..='9'
    for c in '0'..='9' {
        keys.push(make_char_key(c));
    }

    // 4. ASCII punctuation & symbols
    let punctuation = [
        ' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
        ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~', '\t',
    ];
    for &p in &punctuation {
        keys.push(make_char_key(p));
    }

    // 5. Navigation keys
    keys.push(make_key(KeyCode::Tab));
    keys.push(make_key(KeyCode::BackTab));
    keys.push(make_key(KeyCode::Left));
    keys.push(make_key(KeyCode::Right));
    keys.push(make_key(KeyCode::Up));
    keys.push(make_key(KeyCode::Down));
    keys.push(make_key(KeyCode::PageUp));
    keys.push(make_key(KeyCode::PageDown));
    keys.push(make_key(KeyCode::Home));
    keys.push(make_key(KeyCode::End));

    // 6. Escape & Editing action keys
    keys.push(make_key(KeyCode::Esc));
    keys.push(make_key(KeyCode::Backspace));
    keys.push(make_key(KeyCode::Delete));
    keys.push(make_key(KeyCode::Enter));
    keys.push(make_key(KeyCode::Insert));

    // 7. Function keys F1 - F12
    for f in 1..=12 {
        keys.push(make_key(KeyCode::F(f)));
    }

    // 8. Control key combinations
    let ctrl_chars = ['c', 'w', 'q', 'h', 'd', 'm', 'a', 'z', 't', 'k', 'p', 'e', 'r', 'l'];
    for &c in &ctrl_chars {
        keys.push(make_ctrl_key(c));
    }

    // 9. Alt key combinations
    keys.push(make_key_mods(KeyCode::Char('w'), KeyModifiers::ALT));
    keys.push(make_key_mods(KeyCode::Char('q'), KeyModifiers::ALT));
    keys.push(make_key_mods(KeyCode::Tab, KeyModifiers::ALT));

    keys
}

// ============================================================================
// INVARIANT 1: NO ACCIDENTAL WIPE
// Typing 'w' or 'W' while entering text or during jitter harvest MUST NEVER wipe memory
// ============================================================================

#[test]
fn test_invariant_1_no_accidental_wipe_while_entering_entropy() {
    let mut state = fresh_state();
    state.current_page = Page::MasterSeed;
    assert!(state.seed.is_none());

    // Enter partial entropy
    state.set_entropy_input("1010101");
    let prev_input = state.entropy_input.clone();

    // Type 'w'
    simulate_key_event(&mut state, make_char_key('w'));
    assert!(state.seed.is_none(), "Seed was unexpectedly set on 'w'");
    assert!(state.wipe_confirmation_instant.is_none(), "Wipe was triggered on 'w'");
    assert!(state.entropy_input.starts_with(&prev_input), "Entropy input was cleared");
    assert!(state.entropy_input.ends_with('w'), "'w' was not accepted into input");

    // Type 'W'
    simulate_key_event(&mut state, make_char_key('W'));
    assert!(state.seed.is_none());
    assert!(state.wipe_confirmation_instant.is_none(), "Wipe was triggered on 'W'");
    assert!(state.entropy_input.ends_with("wW"), "'W' was not accepted into input");
}

#[test]
fn test_invariant_1_no_accidental_wipe_during_jitter_harvest() {
    for initial_samples in [0usize, 10, 30] {
        let mut state = fresh_state();
        state.current_page = Page::MasterSeed;
        state.is_harvesting_jitter = true;
        state.jitter_samples.clear();
        for i in 0..initial_samples {
            state.jitter_samples.push(('x', 150_000_000 + (i as u64) * 1000));
        }

        // Press 'w'
        simulate_key_event(&mut state, make_char_key('w'));
        assert!(state.wipe_confirmation_instant.is_none(), "Wipe triggered during jitter on 'w'");
        assert_eq!(state.jitter_samples.len(), initial_samples + 1, "Sample not added");
        assert_eq!(state.jitter_samples.last().unwrap().0, 'w');

        // If not completed (len < 32), press 'W'
        if state.is_harvesting_jitter {
            let cur_len = state.jitter_samples.len();
            simulate_key_event(&mut state, make_char_key('W'));
            assert!(state.wipe_confirmation_instant.is_none(), "Wipe triggered during jitter on 'W'");
            if cur_len + 1 >= 32 {
                assert!(!state.is_harvesting_jitter, "Jitter should complete at 32 samples");
                assert!(
                    state.seed.is_some() || state.status_message.contains("[JITTER FAILED]"),
                    "Seed derived or statistical check reported: {}",
                    state.status_message
                );
            } else {
                assert_eq!(state.jitter_samples.len(), cur_len + 1);
                assert_eq!(state.jitter_samples.last().unwrap().0, 'W');
            }
        }
    }

    // Now test with 31 initial samples: pressing 'w' is sample 32, which completes harvest and generates seed
    let mut state = fresh_state();
    state.current_page = Page::MasterSeed;
    state.is_harvesting_jitter = true;
    state.jitter_samples.clear();
    for i in 0..31 {
        state.jitter_samples.push(('x', 150_000_000 + (i as u64) * 1000));
    }
    simulate_key_event(&mut state, make_char_key('w'));
    assert!(state.wipe_confirmation_instant.is_none());
    assert!(!state.is_harvesting_jitter, "Jitter should be completed on sample 32");
    assert!(
        state.seed.is_some() || state.status_message.contains("[JITTER FAILED]"),
        "Seed derived or statistical check reported: {}",
        state.status_message
    );
}

#[test]
fn test_invariant_1_no_accidental_wipe_in_seedfix_and_wordlist() {
    let mut state = seeded_state();

    // Tab 10 SeedFix
    state.current_page = Page::SeedFix;
    let initial_seedfix = state.seedfix_input.clone();
    simulate_key_event(&mut state, make_char_key('w'));
    simulate_key_event(&mut state, make_char_key('W'));
    assert!(state.seed.is_some(), "Master seed was wiped on SeedFix tab by 'w'/'W'");
    assert!(state.wipe_confirmation_instant.is_none());
    assert_eq!(state.seedfix_input, format!("{}wW", initial_seedfix));

    // Tab 11 WordlistInspector
    state.current_page = Page::WordlistInspector;
    state.wordlist_query = "ab".to_string();
    simulate_key_event(&mut state, make_char_key('w'));
    simulate_key_event(&mut state, make_char_key('W'));
    assert!(state.seed.is_some(), "Master seed was wiped on Wordlist tab by 'w'/'W'");
    assert!(state.wipe_confirmation_instant.is_none());
    assert_eq!(state.wordlist_query, "abwW");
}

#[test]
fn test_invariant_1_no_accidental_wipe_in_vault_unlock_passphrase() {
    let mut state = seeded_state();
    state.current_page = Page::VaultUnlock;
    assert!(state.decrypted_vault.is_none());

    state.vault_passphrase_input = "word".to_string();
    simulate_key_event(&mut state, make_char_key('w'));
    simulate_key_event(&mut state, make_char_key('W'));
    assert!(state.seed.is_some(), "Master seed was wiped on VaultUnlock tab by 'w'/'W'");
    assert!(state.wipe_confirmation_instant.is_none());
    assert_eq!(state.vault_passphrase_input, "wordwW");
}

#[test]
fn test_invariant_1_ctrl_w_never_wipes_memory() {
    for page in Page::ALL {
        let mut state = seeded_state();
        state.current_page = page;

        simulate_key_event(&mut state, make_ctrl_key('w'));
        assert!(state.seed.is_some(), "Ctrl+w wiped memory on page {:?}", page);
        assert!(state.wipe_confirmation_instant.is_none(), "Ctrl+w set wipe instant on {:?}", page);
    }
}

// ============================================================================
// INVARIANT 2: NO ACCIDENTAL EXIT
// Typing 'q' or 'Q' in an input field MUST NEVER trigger exit confirmation
// ============================================================================

#[test]
fn test_invariant_2_no_accidental_exit_in_entropy_input() {
    let mut state = fresh_state();
    state.current_page = Page::MasterSeed;
    assert!(state.seed.is_none());

    let exit1 = simulate_key_event(&mut state, make_char_key('q'));
    assert!(!exit1, "simulate_key_event returned exit=true on 'q' in entropy input");
    assert!(state.pending_exit_instant.is_none(), "pending_exit_instant set on 'q' in entropy input");
    assert!(state.entropy_input.contains('q'));

    let exit2 = simulate_key_event(&mut state, make_char_key('Q'));
    assert!(!exit2, "simulate_key_event returned exit=true on 'Q' in entropy input");
    assert!(state.pending_exit_instant.is_none(), "pending_exit_instant set on 'Q' in entropy input");
    assert!(state.entropy_input.contains('Q'));
}

#[test]
fn test_invariant_2_no_accidental_exit_in_seedfix_and_wordlist() {
    let mut state = seeded_state();

    // SeedFix
    state.current_page = Page::SeedFix;
    let exit_sf_q = simulate_key_event(&mut state, make_char_key('q'));
    assert!(!exit_sf_q);
    assert!(state.pending_exit_instant.is_none(), "pending_exit_instant set on SeedFix 'q'");
    assert!(state.seedfix_input.ends_with('q'));

    let exit_sf_uq = simulate_key_event(&mut state, make_char_key('Q'));
    assert!(!exit_sf_uq);
    assert!(state.pending_exit_instant.is_none(), "pending_exit_instant set on SeedFix 'Q'");
    assert!(state.seedfix_input.ends_with('Q'));

    // WordlistInspector
    state.current_page = Page::WordlistInspector;
    let exit_wl_q = simulate_key_event(&mut state, make_char_key('q'));
    assert!(!exit_wl_q);
    assert!(state.pending_exit_instant.is_none(), "pending_exit_instant set on Wordlist 'q'");
    assert!(state.wordlist_query.ends_with('q'));

    let exit_wl_uq = simulate_key_event(&mut state, make_char_key('Q'));
    assert!(!exit_wl_uq);
    assert!(state.pending_exit_instant.is_none(), "pending_exit_instant set on Wordlist 'Q'");
    assert!(state.wordlist_query.ends_with('Q'));
}

#[test]
fn test_invariant_2_no_accidental_exit_in_vault_passphrase_input() {
    let mut state = seeded_state();
    state.current_page = Page::VaultUnlock;
    assert!(state.decrypted_vault.is_none());

    let exit_v_q = simulate_key_event(&mut state, make_char_key('q'));
    assert!(!exit_v_q);
    assert!(state.pending_exit_instant.is_none(), "pending_exit_instant set on VaultUnlock 'q'");
    assert!(state.vault_passphrase_input.ends_with('q'));

    let exit_v_uq = simulate_key_event(&mut state, make_char_key('Q'));
    assert!(!exit_v_uq);
    assert!(state.pending_exit_instant.is_none(), "pending_exit_instant set on VaultUnlock 'Q'");
    assert!(state.vault_passphrase_input.ends_with('Q'));
}

#[test]
fn test_invariant_2_no_accidental_exit_during_jitter_and_modal() {
    let mut state = fresh_state();
    state.current_page = Page::MasterSeed;

    // Jitter harvesting
    state.is_harvesting_jitter = true;
    let exit_jitter_q = simulate_key_event(&mut state, make_char_key('q'));
    assert!(!exit_jitter_q);
    assert!(state.pending_exit_instant.is_none(), "Exit armed during jitter harvesting!");
    assert_eq!(state.jitter_samples.last().unwrap().0, 'q');

    // Test vector selection modal
    state.is_harvesting_jitter = false;
    state.is_selecting_test_vector = true;
    let exit_modal_q = simulate_key_event(&mut state, make_char_key('q'));
    assert!(!exit_modal_q);
    assert!(state.pending_exit_instant.is_none(), "Exit armed during test vector modal!");
    assert!(state.is_selecting_test_vector, "Modal was dismissed by 'q'");
}

// ============================================================================
// INVARIANT 3: JITTER ISOLATION
// When is_harvesting_jitter is active, Tab, Left, Right, Home, digits MUST NOT switch pages
// ============================================================================

#[test]
fn test_invariant_3_jitter_isolation_navigation_and_digits() {
    for initial_samples in [0usize, 10, 30] {
        let mut state = fresh_state();
        state.current_page = Page::MasterSeed;
        state.is_harvesting_jitter = true;
        for i in 0..initial_samples {
            state.jitter_samples.push(('a', 150_000_000 + (i as u64) * 1000));
        }

        // 1. Tab navigation MUST NOT switch page
        simulate_key_event(&mut state, make_key(KeyCode::Tab));
        assert_eq!(state.current_page, Page::MasterSeed, "Tab navigated away during jitter!");
        assert!(state.is_harvesting_jitter, "Jitter canceled by Tab");

        // 2. Right arrow MUST NOT switch page
        simulate_key_event(&mut state, make_key(KeyCode::Right));
        assert_eq!(state.current_page, Page::MasterSeed, "Right arrow navigated away during jitter!");
        assert!(state.is_harvesting_jitter);

        // 3. BackTab MUST NOT switch page
        simulate_key_event(&mut state, make_key(KeyCode::BackTab));
        assert_eq!(state.current_page, Page::MasterSeed, "BackTab navigated away during jitter!");
        assert!(state.is_harvesting_jitter);

        // 4. Left arrow MUST NOT switch page
        simulate_key_event(&mut state, make_key(KeyCode::Left));
        assert_eq!(state.current_page, Page::MasterSeed, "Left arrow navigated away during jitter!");
        assert!(state.is_harvesting_jitter);

        // 5. Home key MUST NOT switch page to RoleSelect
        simulate_key_event(&mut state, make_key(KeyCode::Home));
        assert_eq!(state.current_page, Page::MasterSeed, "Home key navigated away during jitter!");
        assert!(state.is_harvesting_jitter);

        // 6. Digits MUST NOT switch page or trigger test vector modal
        let cur_len = state.jitter_samples.len();
        simulate_key_event(&mut state, make_char_key('1'));
        assert_eq!(state.current_page, Page::MasterSeed, "Digit '1' navigated away during jitter!");
        assert_eq!(state.jitter_samples.len(), cur_len + 1);
        assert_eq!(state.jitter_samples.last().unwrap().0, '1');
    }

    // Also test with 31 samples: digit '1' finishes jitter harvest without switching pages
    let mut state = fresh_state();
    state.current_page = Page::MasterSeed;
    state.is_harvesting_jitter = true;
    for i in 0..31 {
        state.jitter_samples.push(('a', 150_000_000 + (i as u64) * 1000));
    }
    simulate_key_event(&mut state, make_char_key('1'));
    assert_eq!(state.current_page, Page::MasterSeed, "32nd sample must remain on MasterSeed");
    assert!(!state.is_harvesting_jitter);
    assert!(state.seed.is_some());
}

#[test]
fn test_invariant_3_jitter_cancellation_and_completion() {
    let mut state = fresh_state();
    state.current_page = Page::MasterSeed;
    state.is_harvesting_jitter = true;
    state.jitter_samples.push(('x', 150_000_000));

    // Esc cancels jitter
    simulate_key_event(&mut state, make_key(KeyCode::Esc));
    assert!(!state.is_harvesting_jitter, "Esc failed to cancel jitter");
    assert!(state.jitter_samples.is_empty(), "Jitter samples not cleared on Esc");
    assert!(state.last_jitter_instant.is_none());
    assert_eq!(state.current_page, Page::MasterSeed);

    // Re-engage jitter and complete with 32 keystrokes
    state.is_harvesting_jitter = true;
    for i in 0..32 {
        let c = (b'a' + (i % 26) as u8) as char;
        simulate_key_event(&mut state, make_char_key(c));
    }
    assert!(!state.is_harvesting_jitter, "Jitter should finish at 32 samples");
    assert!(state.seed.is_some(), "Master seed should be generated after 32 samples");
    assert_eq!(state.bip85_children.len(), 20, "20 BIP-85 heir keys should be derived");
}

// ============================================================================
// INVARIANT 4: TWO-STROKE EXIT INTEGRITY
// Pressing [Q] once sets pending_exit_instant; any other key cancels;
// pressing [Q] again within 3s confirms exit; pressing [Q] after 3s resets timer
// ============================================================================

#[test]
fn test_invariant_4_two_stroke_exit_full_lifecycle() {
    let mut state = seeded_state();
    state.current_page = Page::RoleSelect;

    // 1. First [Q] stroke: sets pending_exit_instant and returns false
    let exit1 = simulate_key_event(&mut state, make_char_key('q'));
    assert!(!exit1, "First [Q] should not exit");
    assert!(state.pending_exit_instant.is_some(), "pending_exit_instant was not set");

    // 2. Any other key cancels pending_exit_instant
    simulate_key_event(&mut state, make_key(KeyCode::Down));
    assert!(state.pending_exit_instant.is_none(), "Non-Q key failed to cancel pending_exit_instant");

    // 3. Set pending exit, then press [Q] again within 3 seconds -> confirms exit
    simulate_key_event(&mut state, make_char_key('q'));
    assert!(state.pending_exit_instant.is_some());
    let exit_confirm = simulate_key_event(&mut state, make_char_key('q'));
    assert!(exit_confirm, "Second [Q] within 3s must confirm exit");

    // 4. Uppercase 'Q' behaves identically
    state.pending_exit_instant = None;
    let exit_uq1 = simulate_key_event(&mut state, make_char_key('Q'));
    assert!(!exit_uq1);
    assert!(state.pending_exit_instant.is_some());
    let exit_uq2 = simulate_key_event(&mut state, make_char_key('Q'));
    assert!(exit_uq2, "Second uppercase 'Q' within 3s must confirm exit");

    // 5. Pressing [Q] after 3 seconds resets the timer and does NOT exit
    state.pending_exit_instant = Some(Instant::now() - Duration::from_secs(4));
    let exit_expired = simulate_key_event(&mut state, make_char_key('q'));
    assert!(!exit_expired, "Expired [Q] stroke must not exit");
    assert!(state.pending_exit_instant.is_some(), "Timer was not refreshed on expired [Q]");
    assert!(state.pending_exit_instant.unwrap().elapsed() < Duration::from_secs(1));
}

// ============================================================================
// CONTEXTUAL TAB KEY ACTIONS
// ============================================================================

#[test]
fn test_contextual_tab_role_select_keys() {
    let mut state = fresh_state();
    state.current_page = Page::RoleSelect;

    simulate_key_event(&mut state, make_char_key('1'));
    assert_eq!(state.current_page, Page::MasterSeed);

    state.current_page = Page::RoleSelect;
    simulate_key_event(&mut state, make_char_key('2'));
    assert_eq!(state.current_page, Page::VaultUnlock);

    state.current_page = Page::RoleSelect;
    simulate_key_event(&mut state, make_char_key('3'));
    assert_eq!(state.current_page, Page::SeedFix);
}

#[test]
fn test_contextual_tab_master_seed_vector_shortcuts() {
    let mut state = fresh_state();
    state.current_page = Page::MasterSeed;

    // 'c' loads coin vector
    simulate_key_event(&mut state, make_char_key('c'));
    assert_eq!(state.entropy_input.len(), 128);

    // Backspace pops char
    simulate_key_event(&mut state, make_key(KeyCode::Backspace));
    assert_eq!(state.entropy_input.len(), 127);

    // 'd' loads dice vector
    simulate_key_event(&mut state, make_char_key('d'));
    assert_eq!(state.entropy_input.len(), 52);

    // 't' enters test vector modal
    simulate_key_event(&mut state, make_char_key('t'));
    assert!(state.is_selecting_test_vector);

    // Digit '8' selects test vector 8 (Satoshi Lore)
    simulate_key_event(&mut state, make_char_key('8'));
    assert!(!state.is_selecting_test_vector);
    assert!(state.seed.is_some());
    assert!(state.status_message.to_uppercase().contains("SATOSHI"));
}

#[test]
fn test_contextual_tab_vpub_qr_and_offsets() {
    let mut state = seeded_state();

    // Tab 4 VpubQr: 'm' cycles QR mode
    state.current_page = Page::VpubQr;
    assert_eq!(state.qr_mode, QrMode::BbqrAnimated);
    simulate_key_event(&mut state, make_char_key('m'));
    assert_eq!(state.qr_mode, QrMode::FullBlockSpace);
    simulate_key_event(&mut state, make_char_key('m'));
    assert_eq!(state.qr_mode, QrMode::StaticVpub);
    simulate_key_event(&mut state, make_char_key('m'));
    assert_eq!(state.qr_mode, QrMode::BbqrAnimated);

    // Tab 6 Addresses: Down/Up pagination
    state.current_page = Page::Addresses;
    assert_eq!(state.address_page_offset, 0);
    simulate_key_event(&mut state, make_key(KeyCode::Down));
    assert_eq!(state.address_page_offset, 25);
    simulate_key_event(&mut state, make_key(KeyCode::Down)); // Already at max (50 total, 25+25=50)
    assert_eq!(state.address_page_offset, 25);
    simulate_key_event(&mut state, make_key(KeyCode::Up));
    assert_eq!(state.address_page_offset, 0);

    // Tab 7 Bip85Children: Down/Up pagination
    state.current_page = Page::Bip85Children;
    assert_eq!(state.heir_page_offset, 0);
    simulate_key_event(&mut state, make_key(KeyCode::Down));
    assert_eq!(state.heir_page_offset, 10);
    simulate_key_event(&mut state, make_key(KeyCode::Down)); // Max offset
    assert_eq!(state.heir_page_offset, 10);
    simulate_key_event(&mut state, make_key(KeyCode::Up));
    assert_eq!(state.heir_page_offset, 0);
}

#[test]
fn test_contextual_tab_vault_unlock_mask_and_decrypt() {
    let mut state = fresh_state();
    state.current_page = Page::VaultUnlock;

    // Ctrl+M toggles mask
    assert!(!state.vault_mask_passphrase);
    simulate_key_event(&mut state, make_ctrl_key('m'));
    assert!(state.vault_mask_passphrase);
    simulate_key_event(&mut state, make_ctrl_key('m'));
    assert!(!state.vault_mask_passphrase);

    // Type shortcut 't0' and press Enter to decrypt
    simulate_key_event(&mut state, make_char_key('t'));
    simulate_key_event(&mut state, make_char_key('0'));
    simulate_key_event(&mut state, make_key(KeyCode::Enter));
    assert!(state.decrypted_vault.is_some(), "Vault decrypt failed for t0");

    // Once decrypted, 'w' wipes vault
    simulate_key_event(&mut state, make_char_key('w'));
    assert!(state.decrypted_vault.is_none(), "Decrypted vault was not wiped by 'w'");
}

// ============================================================================
// EXHAUSTIVE MATRIX: ALL 14 TABS x ALL SUB-STATES x ALL KEYCODES
// ============================================================================

#[test]
fn test_exhaustive_matrix_all_14_tabs_all_substates_all_keycodes() {
    let all_keys = get_all_test_keys();
    let backend = TestBackend::new(80, 25);
    let mut terminal = Terminal::new(backend).expect("Terminal failed");

    for page in Page::ALL {
        for seed_present in [false, true] {
            for is_jitter in [false, true] {
                // Jitter is only valid on MasterSeed when seed is None
                if is_jitter && (page != Page::MasterSeed || seed_present) {
                    continue;
                }

                for is_modal in [false, true] {
                    // Modal only valid on MasterSeed when seed is None
                    if is_modal && (page != Page::MasterSeed || seed_present) {
                        continue;
                    }

                    for pending_exit in [false, true] {
                        let mut state = if seed_present { seeded_state() } else { fresh_state() };
                        state.current_page = page;
                        state.is_harvesting_jitter = is_jitter;
                        state.is_selecting_test_vector = is_modal;
                        if pending_exit {
                            state.pending_exit_instant = Some(Instant::now());
                        }

                        // Inject each key
                        for &key in &all_keys {
                            // Run key event - MUST NOT PANIC
                            let _exit = simulate_key_event(&mut state, key);

                            // Assert safe offsets (no underflow/overflow)
                            assert!(state.address_page_offset <= 100);
                            assert!(state.heir_page_offset <= 100);

                            // Render after key - MUST NOT PANIC
                            terminal.draw(|f| render_app(f, &state)).expect("Render crashed in matrix");
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// INVARIANT 5: 100,000+ CHAOTIC RANDOM SEQUENCES
// Deterministic pseudo-random keystroke sequences across all tabs; zero panics,
// zero index-out-of-bounds, zero arithmetic underflow on pagination offsets.
// ============================================================================

/// Deterministic 64-bit XorShift pseudo-random number generator
struct DeterministicPrng {
    state: u64,
}

impl DeterministicPrng {
    fn new(seed: u64) -> Self {
        Self { state: if seed == 0 { 0xCAFE_BABE_DEAD_BEEF } else { seed } }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() % (bound as u64)) as usize
    }
}

#[test]
fn test_invariant_5_100k_chaotic_random_sequences() {
    let all_keys = get_all_test_keys();
    let num_keys = all_keys.len();
    assert!(num_keys > 50, "Test key pool is too small");

    let mut prng = DeterministicPrng::new(0xDEAD_CAFE_B007_1ACE);
    let mut state = fresh_state();

    let backend = TestBackend::new(80, 25);
    let mut terminal = Terminal::new(backend).expect("Terminal failed");

    let total_iterations = 105_000;
    let mut exit_count = 0;

    for step in 1..=total_iterations {
        let key_idx = prng.next_usize(num_keys);
        let key = all_keys[key_idx];

        let should_exit = simulate_key_event(&mut state, key);
        if should_exit {
            exit_count += 1;
            // On exit, reset pending_exit_instant and randomly re-seed or wipe to continue fuzzing
            state.pending_exit_instant = None;
            if prng.next_usize(2) == 0 {
                state = seeded_state();
            } else {
                state = fresh_state();
            }
        }

        // Invariants asserted on every single step:
        assert!(state.address_page_offset <= 50, "address_page_offset out of bounds: {}", state.address_page_offset);
        assert!(state.heir_page_offset <= 20, "heir_page_offset out of bounds: {}", state.heir_page_offset);
        assert!(state.entropy_input.len() <= 256, "entropy_input exceeded 256 chars: {}", state.entropy_input.len());
        assert!(state.vault_passphrase_input.len() <= 2048, "vault_passphrase_input exploded: {}", state.vault_passphrase_input.len());

        // Periodic rendering check at standard resolutions to assert zero render panics under chaotic state
        if step % 15_000 == 0 {
            terminal.draw(|f| render_app(f, &state)).expect(&format!("Render failed at step {} on page {:?}", step, state.current_page));
        }
    }

    assert!(exit_count > 0, "Chaos fuzzing should have exercised two-stroke exit or Ctrl+c at least once in 100k steps");
}
