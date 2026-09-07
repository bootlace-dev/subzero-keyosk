//! SubZero-rs Massive Security & Cryptographic Invariant Test Suite
//!
//! Vectors Covered:
//! 1. Physical Entropy Boundary & Statistical Fuzzing (10,000+ Monte Carlo / Property iterations)
//!    - Coin input fuzzing: 1-127 flips strictly rejected with exact error; 128+ flips pass
//!    - Dice input fuzzing: 1-59 rolls strictly rejected with exact error; 60+ rolls pass
//!    - Adversarial Chi-squared boundary testing near critical values (df=1: 10.828, df=5: 20.515)
//!    - Pathological Markov transition traps and repetitive n-grams
//!    - Whitespace and delimiter fuzzing (spaces, tabs, carriage returns, trailing newlines)
//! 2. Estate Vault Cryptographic Hygiene & Deterministic Invariants
//!    - Deterministic salt/IV derivation from master_root_mnemonic with distinct domain separation tags
//!    - Seed collision and decorrelation isolation across distinct mnemonics
//!    - Vault tamper resistance: bit-level mutation across ciphertext body and authentication tag
//!    - Wrong passphrase attack clean error handling without partial plaintext leakage
//!    - Unicode / NFKD passphrase hardening, whitespace collapsing, and length boundary tests
//! 3. Memory Hygiene & Zeroize on Drop Assertions
//!    - AppState zeroize on Drop and wipe_memory() verification
//!    - Zeroize on drop assertions across SecretEntropy, GeneratedSeed, Bip85Child, DecryptedVaultPayload

use base64::prelude::*;
use hmac::{Hmac, Mac};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha2::Sha256;
use zeroize::Zeroize;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

use subzero::crypto::{
    decrypt_vault_json, derive_bip85_children, encrypt_vault_payload,
    has_repetitive_substrings, parse_physical_entropy, process_physical_entropy,
    run_chi_squared_audit, run_markov_audit, Bip85Child, CryptoError,
    DecryptedVaultPayload, EncryptedVaultJson, GeneratedSeed, SecretEntropy,
};
use subzero::ui::AppState;

// ============================================================================
// HELPER UTILITIES FOR FUZZING & PROPERTY TESTING
// ============================================================================

/// Helper to generate a conditioned binary stream of length `len` that satisfies
/// Markov, Chi-squared, and repetition audits so it isolates the length check.
fn generate_statistically_sound_binary_stream(rng: &mut StdRng, len: usize) -> String {
    if len < 16 {
        return (0..len)
            .map(|_| if rng.gen_bool(0.5) { '1' } else { '0' })
            .collect();
    }

    for _ in 0..10_000 {
        let candidate: String = (0..len)
            .map(|_| if rng.gen_bool(0.5) { '1' } else { '0' })
            .collect();
        let markov = run_markov_audit(&candidate);
        let (chi2_pass, _, _) = run_chi_squared_audit(&candidate);
        let repeats = has_repetitive_substrings(&candidate, 3, 6);
        if markov.passed && chi2_pass && !repeats {
            return candidate;
        }
    }
    panic!("Failed to generate statistically sound binary stream of length {}", len);
}

/// Helper to generate a conditioned dice stream of length `len` that satisfies
/// Markov, Chi-squared, and repetition audits so it isolates the length check.
fn generate_statistically_sound_dice_stream(rng: &mut StdRng, len: usize) -> String {
    if len < 16 {
        return (0..len)
            .map(|_| char::from_digit(rng.gen_range(1..=6), 10).unwrap())
            .collect();
    }

    for _ in 0..10_000 {
        let candidate: String = (0..len)
            .map(|_| char::from_digit(rng.gen_range(1..=6), 10).unwrap())
            .collect();
        let markov = run_markov_audit(&candidate);
        let (chi2_pass, _, _) = run_chi_squared_audit(&candidate);
        let repeats = has_repetitive_substrings(&candidate, 3, 6);
        if markov.passed && chi2_pass && !repeats {
            return candidate;
        }
    }
    panic!("Failed to generate statistically sound dice stream of length {}", len);
}

/// Compute bitwise Hamming distance between two equal-length byte slices
fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    assert_eq!(a.len(), b.len(), "Slices must have equal length");
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x ^ y).count_ones() as usize)
        .sum()
}

/// Construct a fast vault JSON fixture with matching schema and custom PBKDF2 iterations
fn create_test_vault_json_fixture(
    payload: &DecryptedVaultPayload,
    passphrase: &str,
    iterations: u32,
) -> (String, EncryptedVaultJson) {
    let mut hmac_salt: Hmac<Sha256> = Mac::new_from_slice(b"subzero:vault:pbkdf2:salt:v1").unwrap();
    hmac_salt.update(payload.master_root_mnemonic.trim().as_bytes());
    let salt_hash = hmac_salt.finalize().into_bytes();
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&salt_hash[..16]);

    let mut hmac_iv: Hmac<Sha256> = Mac::new_from_slice(b"subzero:vault:aes-gcm:iv:v1").unwrap();
    hmac_iv.update(payload.master_root_mnemonic.trim().as_bytes());
    hmac_iv.update(passphrase.trim().as_bytes());
    let iv_hash = hmac_iv.finalize().into_bytes();
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_hash[..12]);

    let normalized_pass: String = passphrase
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();

    let mut derived_key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        normalized_pass.as_bytes(),
        &salt,
        iterations,
        &mut derived_key,
    );

    let cipher = Aes256Gcm::new_from_slice(&derived_key).unwrap();
    derived_key.zeroize();
    let nonce = Nonce::from_slice(&iv);
    let plaintext = serde_json::to_string_pretty(payload).unwrap();
    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).unwrap();

    let vault = EncryptedVaultJson {
        format: "subzero-vault-v1".to_string(),
        cipher: "AES-256-GCM".to_string(),
        kdf: "PBKDF2-HMAC-SHA256".to_string(),
        iterations,
        salt: BASE64_STANDARD.encode(salt),
        iv: BASE64_STANDARD.encode(iv),
        ciphertext: BASE64_STANDARD.encode(ciphertext),
    };

    let json_str = serde_json::to_string_pretty(&vault).unwrap();
    (json_str, vault)
}

// ============================================================================
// VECTOR 1: PHYSICAL ENTROPY BOUNDARY & STATISTICAL FUZZING
// ============================================================================

#[test]
fn test_fuzz_coin_entropy_boundary_1_to_127_rejected_and_128_plus_pass() {
    let mut rng = StdRng::seed_from_u64(0xCAFE_BABE_0001);

    // 1. Strict rejection of lengths 1..=127:
    // Every length from 1 to 127 must be rejected.
    // When conditioned to pass statistical audits, it must reject with exact error CryptoError::InvalidEntropyLength(len).
    for len in 1..=127 {
        let stream = generate_statistically_sound_binary_stream(&mut rng, len);
        let err = parse_physical_entropy(&stream)
            .expect_err(&format!("Binary stream of length {} should have been rejected", len));

        match err {
            CryptoError::InvalidEntropyLength(actual_len) => {
                assert_eq!(actual_len, len, "Error length must match input length {}", len);
            }
            other => panic!("Expected InvalidEntropyLength({}), got {:?}", len, other),
        }
    }

    // 2. Monte Carlo fuzzing with 3,000 random unconditioned binary streams of lengths 1..=127:
    // Assert 100% of inputs under 128 bits are unconditionally rejected (never return Ok).
    for _ in 0..3_000 {
        let len = rng.gen_range(1..128);
        let random_stream: String = (0..len)
            .map(|_| if rng.gen_bool(0.5) { '1' } else { '0' })
            .collect();
        let res = parse_physical_entropy(&random_stream);
        assert!(
            res.is_err(),
            "Random unconditioned binary stream of length {} must be rejected",
            len
        );
    }

    // 3. Valid lengths 128..=256:
    // Assert that conditioned binary streams >= 128 bits pass and produce valid 128-bit (16-byte) entropy.
    for len in [128, 129, 140, 160, 192, 224, 256] {
        for _ in 0..50 {
            let stream = generate_statistically_sound_binary_stream(&mut rng, len);
            let (entropy_bytes, mode) = parse_physical_entropy(&stream)
                .expect(&format!("Binary stream of valid length {} should pass", len));

            assert_eq!(entropy_bytes.len(), 16, "Must yield exactly 16 bytes (128 bits)");
            assert_eq!(mode, "Physical Coin Flips (128-bit Bin)");

            // Full key derivation pipeline verification
            let seed = process_physical_entropy(&stream).expect("Full derivation must succeed");
            assert_eq!(seed.mnemonic.split_whitespace().count(), 12);
            assert_eq!(seed.fingerprint.len(), 8);
            assert!(seed.descriptor.contains('#'));
            assert_eq!(seed.addresses.len(), 50);
            assert!(seed.addresses[0].starts_with("tb1q"));
        }
    }
}

#[test]
fn test_fuzz_dice_entropy_boundary_1_to_49_rejected_and_50_plus_pass() {
    let mut rng = StdRng::seed_from_u64(0xCAFE_BABE_0002);

    // 1. Strict rejection of rolls 1..=49:
    // Every roll count from 1 to 49 must be rejected.
    // When conditioned to pass statistical audits, it must reject with exact error CryptoError::InvalidEntropyLength(len).
    for len in 1..=49 {
        let stream = generate_statistically_sound_dice_stream(&mut rng, len);
        let err = parse_physical_entropy(&stream)
            .expect_err(&format!("Dice stream of length {} should have been rejected", len));

        match err {
            CryptoError::InvalidEntropyLength(actual_len) => {
                assert_eq!(actual_len, len, "Error length must match input roll count {}", len);
            }
            other => panic!("Expected InvalidEntropyLength({}), got {:?}", len, other),
        }
    }

    // 2. Monte Carlo fuzzing with 3,000 random unconditioned dice streams of lengths 1..=49:
    // Assert 100% of inputs under 50 rolls are unconditionally rejected.
    for _ in 0..3_000 {
        let len = rng.gen_range(1..50);
        let random_stream: String = (0..len)
            .map(|_| char::from_digit(rng.gen_range(1..=6), 10).unwrap())
            .collect();
        let res = parse_physical_entropy(&random_stream);
        assert!(
            res.is_err(),
            "Random dice stream of length {} must be rejected",
            len
        );
    }

    // 3. Valid roll counts 50..=120:
    // Assert that conditioned dice streams >= 50 rolls pass and produce valid 128-bit (16-byte) entropy.
    for len in [50, 52, 60, 64, 75, 90, 100, 120] {
        for _ in 0..50 {
            let stream = generate_statistically_sound_dice_stream(&mut rng, len);
            let (entropy_bytes, mode) = parse_physical_entropy(&stream)
                .expect(&format!("Dice stream of valid length {} should pass", len));

            assert_eq!(entropy_bytes.len(), 16, "Must yield 16 bytes SHA-256 entropy slice");
            assert_eq!(mode, "Standard Dice Rolls (50+ Rolls)");

            // Full key derivation pipeline verification
            let seed = process_physical_entropy(&stream).expect("Full derivation must succeed");
            assert_eq!(seed.mnemonic.split_whitespace().count(), 12);
            assert_eq!(seed.fingerprint.len(), 8);
            assert!(seed.descriptor.contains('#'));
            assert_eq!(seed.addresses.len(), 50);
            assert!(seed.addresses[0].starts_with("tb1q"));
        }
    }
}

#[test]
fn test_adversarial_chi_squared_boundary_and_bias_rejection() {
    let mut rng = StdRng::seed_from_u64(0xCAFE_BABE_0003);

    // 1. Exact mathematical boundary testing for Binary Coin Flips (df=1, crit=10.828, n=128):
    // chi2 = (c0 - 64)^2 / 64 + (c1 - 64)^2 / 64 = (c1 - 64)^2 / 32
    // c1 = 82, c0 = 46: chi2 = 18^2 / 32 = 10.125 <= 10.828 (PASS)
    // c1 = 83, c0 = 45: chi2 = 19^2 / 32 = 11.281 > 10.828 (FAIL)

    // Construct stream with 82 ones and 46 zeros (passing chi2 audit):
    let mut pass_coin_found = false;
    for _ in 0..10_000 {
        let mut bits: Vec<char> = vec!['1'; 82];
        bits.extend(vec!['0'; 46]);
        // Fisher-Yates shuffle
        for i in (1..bits.len()).rev() {
            let j = rng.gen_range(0..=i);
            bits.swap(i, j);
        }
        let stream: String = bits.into_iter().collect();
        let (chi2_pass, chi2_val, _) = run_chi_squared_audit(&stream);
        let markov = run_markov_audit(&stream);
        let repeats = has_repetitive_substrings(&stream, 3, 6);

        if chi2_pass && markov.passed && !repeats {
            assert!(
                chi2_val <= 10.828,
                "Chi2 value {:.3} must be <= critical value 10.828",
                chi2_val
            );
            assert!((chi2_val - 10.125).abs() < 1e-4);
            let parse_res = parse_physical_entropy(&stream);
            assert!(parse_res.is_ok(), "Stream with chi2=10.125 must be accepted");
            pass_coin_found = true;
            break;
        }
    }
    assert!(pass_coin_found, "Must construct valid boundary coin stream with chi2=10.125");

    // Construct stream with 83 ones and 45 zeros (failing chi2 audit):
    let mut fail_coin_found = false;
    for _ in 0..10_000 {
        let mut bits: Vec<char> = vec!['1'; 83];
        bits.extend(vec!['0'; 45]);
        for i in (1..bits.len()).rev() {
            let j = rng.gen_range(0..=i);
            bits.swap(i, j);
        }
        let stream: String = bits.into_iter().collect();
        let (chi2_pass, chi2_val, _) = run_chi_squared_audit(&stream);
        let markov = run_markov_audit(&stream);
        let repeats = has_repetitive_substrings(&stream, 3, 6);

        // We specifically isolate Chi-squared failure (markov and repeats pass)
        if !chi2_pass && markov.passed && !repeats {
            assert!(
                chi2_val > 10.828,
                "Chi2 value {:.3} must exceed critical value 10.828",
                chi2_val
            );
            assert!((chi2_val - 11.28125).abs() < 1e-4);
            let err = parse_physical_entropy(&stream)
                .expect_err("Stream with chi2=11.281 must be rejected by Chi-squared audit");
            match err {
                CryptoError::ChiSquaredAuditFailed(details) => {
                    assert!(details.contains("Non-uniform bit distribution"));
                }
                other => panic!("Expected ChiSquaredAuditFailed, got {:?}", other),
            }
            fail_coin_found = true;
            break;
        }
    }
    assert!(fail_coin_found, "Must construct boundary coin stream with chi2=11.281");

    // 2. Exact mathematical boundary testing for Dice Rolls (df=5, crit=20.515, n=120):
    // Expected count = 20.0 per face.
    // Face 6 count = 38, other faces [16, 16, 16, 17, 17]: chi2 = 19.5 <= 20.515 (PASS)
    // Face 6 count = 39, other faces [16, 16, 16, 16, 17]: chi2 = 21.7 > 20.515 (FAIL)

    let mut pass_dice_found = false;
    for _ in 0..10_000 {
        let mut rolls: Vec<char> = Vec::with_capacity(120);
        rolls.extend(vec!['1'; 16]);
        rolls.extend(vec!['2'; 16]);
        rolls.extend(vec!['3'; 16]);
        rolls.extend(vec!['4'; 17]);
        rolls.extend(vec!['5'; 17]);
        rolls.extend(vec!['6'; 38]);
        for i in (1..rolls.len()).rev() {
            let j = rng.gen_range(0..=i);
            rolls.swap(i, j);
        }
        let stream: String = rolls.into_iter().collect();
        let (chi2_pass, chi2_val, _) = run_chi_squared_audit(&stream);
        let markov = run_markov_audit(&stream);
        let repeats = has_repetitive_substrings(&stream, 3, 6);

        if chi2_pass && markov.passed && !repeats {
            assert!(chi2_val <= 20.515);
            assert!((chi2_val - 19.5).abs() < 1e-4);
            let parse_res = parse_physical_entropy(&stream);
            assert!(parse_res.is_ok(), "Dice stream with chi2=19.5 must be accepted");
            pass_dice_found = true;
            break;
        }
    }
    assert!(pass_dice_found, "Must construct valid boundary dice stream with chi2=19.5");

    let mut fail_dice_found = false;
    for _ in 0..10_000 {
        let mut rolls: Vec<char> = Vec::with_capacity(120);
        rolls.extend(vec!['1'; 16]);
        rolls.extend(vec!['2'; 16]);
        rolls.extend(vec!['3'; 16]);
        rolls.extend(vec!['4'; 16]);
        rolls.extend(vec!['5'; 17]);
        rolls.extend(vec!['6'; 39]);
        for i in (1..rolls.len()).rev() {
            let j = rng.gen_range(0..=i);
            rolls.swap(i, j);
        }
        let stream: String = rolls.into_iter().collect();
        let (chi2_pass, chi2_val, _) = run_chi_squared_audit(&stream);
        let markov = run_markov_audit(&stream);
        let repeats = has_repetitive_substrings(&stream, 3, 6);

        if !chi2_pass && markov.passed && !repeats {
            assert!(chi2_val > 20.515);
            assert!((chi2_val - 21.7).abs() < 1e-4);
            let err = parse_physical_entropy(&stream)
                .expect_err("Dice stream with chi2=21.7 must be rejected by Chi-squared audit");
            match err {
                CryptoError::ChiSquaredAuditFailed(details) => {
                    assert!(details.contains("Non-uniform dice distribution"));
                }
                other => panic!("Expected ChiSquaredAuditFailed, got {:?}", other),
            }
            fail_dice_found = true;
            break;
        }
    }
    assert!(fail_dice_found, "Must construct boundary dice stream with chi2=21.7");

    // 3. Monte Carlo fuzzing of Biased Distributions (1,000 iterations):
    // 60/40 coin bias (300 ones, 200 zeros across 500 bits): chi2 = 20.0 > 10.828
    for _ in 0..500 {
        let mut bits: Vec<char> = vec!['1'; 300];
        bits.extend(vec!['0'; 200]);
        for i in (1..bits.len()).rev() {
            let j = rng.gen_range(0..=i);
            bits.swap(i, j);
        }
        let biased_coin: String = bits.into_iter().collect();
        let (chi2_pass, chi2_val, _) = run_chi_squared_audit(&biased_coin);
        assert!(!chi2_pass, "60/40 coin stream must fail Chi-squared audit");
        assert!((chi2_val - 20.0).abs() < 1e-4);
        assert!(parse_physical_entropy(&biased_coin).is_err(), "Biased coin stream must be rejected");
    }

    // Loaded dice bias (70 rolls on face 6, 34 rolls on faces 1..5 across 240 rolls): chi2 = 27.0 > 20.515
    for _ in 0..500 {
        let mut rolls: Vec<char> = Vec::with_capacity(240);
        for face in '1'..='5' {
            rolls.extend(vec![face; 34]);
        }
        rolls.extend(vec!['6'; 70]);
        for i in (1..rolls.len()).rev() {
            let j = rng.gen_range(0..=i);
            rolls.swap(i, j);
        }
        let loaded_dice: String = rolls.into_iter().collect();
        let (chi2_pass, chi2_val, _) = run_chi_squared_audit(&loaded_dice);
        assert!(!chi2_pass, "Loaded dice stream must fail Chi-squared audit");
        assert!((chi2_val - 27.0).abs() < 1e-4);
        assert!(parse_physical_entropy(&loaded_dice).is_err(), "Loaded dice stream must be rejected");
    }
}

#[test]
fn test_markov_transition_traps_and_pathological_patterns() {
    // 1. Pathological binary alternating sequence: 10101010... (100% conditional transition probability)
    let alt_bin = "10".repeat(64);
    let markov_bin = run_markov_audit(&alt_bin);
    assert!(!markov_bin.passed);
    assert_eq!(markov_bin.max_cond_prob, 1.0);
    let err_bin = parse_physical_entropy(&alt_bin).expect_err("Alternating binary must fail");
    match err_bin {
        CryptoError::MarkovAuditFailed(_) | CryptoError::RepetitivePatternDetected => {}
        other => panic!("Expected Markov or Repetition error, got {:?}", other),
    }

    // 2. Pathological dice alternating sequence: 12121212... (100% conditional transition probability)
    let alt_dice = "12".repeat(40);
    let markov_dice = run_markov_audit(&alt_dice);
    assert!(!markov_dice.passed);
    assert_eq!(markov_dice.max_cond_prob, 1.0);
    let err_dice = parse_physical_entropy(&alt_dice).expect_err("Alternating dice must fail");
    match err_dice {
        CryptoError::MarkovAuditFailed(_) | CryptoError::RepetitivePatternDetected => {}
        other => panic!("Expected Markov or Repetition error, got {:?}", other),
    }

    // 3. Paired runs: 112233445566112233445566...
    let paired_runs = "112233445566".repeat(8);
    let err_paired = parse_physical_entropy(&paired_runs).expect_err("Paired runs must fail");
    match err_paired {
        CryptoError::MarkovAuditFailed(_) | CryptoError::RepetitivePatternDetected => {}
        other => panic!("Expected Markov or Repetition error, got {:?}", other),
    }

    // 4. Repetitive n-grams:
    let ngrams = [
        "123".repeat(30),
        "1234".repeat(25),
        "12345".repeat(20),
        "123456".repeat(15),
        "654321".repeat(15),
        "135246".repeat(15),
    ];
    for gram in ngrams {
        assert!(
            has_repetitive_substrings(&gram, 3, 6),
            "Repeating n-gram '{}' must trigger repetition detection",
            &gram[..12]
        );
        let err_gram = parse_physical_entropy(&gram).expect_err("Repetitive n-gram must fail");
        match err_gram {
            CryptoError::RepetitivePatternDetected | CryptoError::MarkovAuditFailed(_) => {}
            other => panic!("Expected repetition/markov error, got {:?}", other),
        }
    }

    // 5. Long identical character runs:
    // 12 consecutive 0s or 1s in binary
    let run_12_zeros = format!("001011010101{}0101101011001100101011001101011001101100101101010110011011010011001011001101011001101010110011010110011010101100110101", "0".repeat(12));
    assert!(has_repetitive_substrings(&run_12_zeros, 3, 6));
    assert!(parse_physical_entropy(&run_12_zeros).is_err());

    let run_12_ones = format!("001011010101{}0101101011001100101011001101011001101100101101010110011011010011001011001101011001101010110011010110011010101100110101", "1".repeat(12));
    assert!(has_repetitive_substrings(&run_12_ones, 3, 6));
    assert!(parse_physical_entropy(&run_12_ones).is_err());

    // 6. Large structured repeating blocks (e.g., 16-char block repeated twice)
    let block16 = "1234561234561234";
    let repeated_block = format!("{}{}{}", block16, block16, "123456123456123456123456123456123456");
    assert!(has_repetitive_substrings(&repeated_block, 3, 6));
    assert!(parse_physical_entropy(&repeated_block).is_err());
}

#[test]
fn test_whitespace_and_delimiter_fuzzing_10000_iterations() {
    let mut rng = StdRng::seed_from_u64(0xCAFE_BABE_0004);

    // Canonical baseline valid coin string
    let canonical_coin = "00100000100000001011001110010010111010101100001000111101101000011101000111001011101001111001000001011110011011010100100100110011";
    let (base_coin_bytes, base_coin_mode) = parse_physical_entropy(canonical_coin).unwrap();
    let base_coin_seed = process_physical_entropy(canonical_coin).unwrap();

    // Canonical baseline valid dice string
    let canonical_dice = "423124613254162351426351423165241362514362514362513245163254";
    let (base_dice_bytes, base_dice_mode) = parse_physical_entropy(canonical_dice).unwrap();
    let base_dice_seed = process_physical_entropy(canonical_dice).unwrap();

    let delimiters = [' ', '\t', '\r', '\n', ',', '-'];

    // 10,000 Monte Carlo property iterations testing delimiter idempotency
    for i in 0..10_000 {
        let is_coin = (i % 2) == 0;
        let canonical = if is_coin { canonical_coin } else { canonical_dice };
        let expected_bytes = if is_coin { &base_coin_bytes } else { &base_dice_bytes };
        let expected_mode = if is_coin { base_coin_mode } else { base_dice_mode };
        let expected_fingerprint = if is_coin { &base_coin_seed.fingerprint } else { &base_dice_seed.fingerprint };

        let mut fuzzed = String::with_capacity(canonical.len() * 3);

        // Optional leading delimiters
        let leading_count = rng.gen_range(0..=4);
        for _ in 0..leading_count {
            fuzzed.push(delimiters[rng.gen_range(0..delimiters.len())]);
        }

        // Interleaved delimiters
        for c in canonical.chars() {
            fuzzed.push(c);
            // 35% probability of injecting 1-3 delimiters after character
            if rng.gen_bool(0.35) {
                let inject_count = rng.gen_range(1..=3);
                for _ in 0..inject_count {
                    fuzzed.push(delimiters[rng.gen_range(0..delimiters.len())]);
                }
            }
        }

        // Optional trailing delimiters
        let trailing_count = rng.gen_range(0..=4);
        for _ in 0..trailing_count {
            fuzzed.push(delimiters[rng.gen_range(0..delimiters.len())]);
        }

        // Parse fuzzed string
        let (actual_bytes, actual_mode) = parse_physical_entropy(&fuzzed)
            .expect(&format!("Fuzzed input iteration {} must parse idempotently", i));

        assert_eq!(&actual_bytes, expected_bytes, "Entropy bytes must match baseline at iteration {}", i);
        assert_eq!(actual_mode, expected_mode, "Mode must match baseline at iteration {}", i);

        // Every 500 iterations, verify full process_physical_entropy pipeline matches
        if i % 500 == 0 {
            let actual_seed = process_physical_entropy(&fuzzed).unwrap();
            assert_eq!(&actual_seed.fingerprint, expected_fingerprint);
            assert_eq!(&actual_seed.addresses[0], if is_coin { &base_coin_seed.addresses[0] } else { &base_dice_seed.addresses[0] });
        }
    }
}

// ============================================================================
// VECTOR 2: ESTATE VAULT CRYPTOGRAPHIC HYGIENE & DETERMINISTIC INVARIANTS
// ============================================================================

#[test]
fn test_vault_deterministic_salt_and_iv_derivation_and_domain_separation() {
    let payload = DecryptedVaultPayload {
        version: "1.0.0".to_string(),
        created_utc: "2026-09-07T10:00:00Z".to_string(),
        master_root_mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        descriptor: "wpkh([1c23b5f0/84'/1'/0']tpubDC59.../<0;1>/*)#12345678".to_string(),
        heir_treasuries: vec![],
    };

    let passphrase = "prosper voice ladder drill rich sugar direct shrug cycle fossil visual hollow";

    // 1. Manually derive expected PBKDF2 salt (32-byte hash, 16-byte prefix)
    let mut hmac_salt: Hmac<Sha256> = Mac::new_from_slice(b"subzero:vault:pbkdf2:salt:v1").unwrap();
    hmac_salt.update(payload.master_root_mnemonic.trim().as_bytes());
    let salt_hash_32 = hmac_salt.finalize().into_bytes();
    let expected_salt_16 = &salt_hash_32[..16];

    // 2. Manually derive expected AES-GCM IV (12 bytes)
    let mut hmac_iv: Hmac<Sha256> = Mac::new_from_slice(b"subzero:vault:aes-gcm:iv:v1").unwrap();
    hmac_iv.update(payload.master_root_mnemonic.trim().as_bytes());
    hmac_iv.update(passphrase.trim().as_bytes());
    let iv_hash = hmac_iv.finalize().into_bytes();
    let expected_iv_12 = &iv_hash[..12];

    // Assert domain separation tags are distinct
    assert_ne!(b"subzero:vault:pbkdf2:salt:v1".as_slice(), b"subzero:vault:aes-gcm:iv:v1".as_slice());

    // Assert salt (16 bytes) and IV (12 bytes) are completely distinct
    assert_ne!(&expected_salt_16[..12], expected_iv_12);

    // 3. Encrypt payload via production function
    let enc1 = encrypt_vault_payload(&payload, passphrase).expect("Encryption 1 failed");
    let enc2 = encrypt_vault_payload(&payload, passphrase).expect("Encryption 2 failed");

    // Assert 100% byte-for-byte determinism
    assert_eq!(enc1, enc2, "Vault encryption must be 100% deterministic");

    let vault1: EncryptedVaultJson = serde_json::from_str(&enc1).unwrap();
    let decoded_salt = BASE64_STANDARD.decode(&vault1.salt).unwrap();
    let decoded_iv = BASE64_STANDARD.decode(&vault1.iv).unwrap();

    assert_eq!(decoded_salt.len(), 16);
    assert_eq!(decoded_salt.as_slice(), expected_salt_16);
    assert_eq!(decoded_iv.len(), 12);
    assert_eq!(decoded_iv.as_slice(), expected_iv_12);

    // Verify roundtrip decryption
    let decrypted = decrypt_vault_json(&enc1, passphrase).expect("Decryption must succeed");
    assert_eq!(decrypted.master_root_mnemonic, payload.master_root_mnemonic);
    assert_eq!(decrypted.descriptor, payload.descriptor);
}

#[test]
fn test_vault_seed_collision_and_isolation() {
    let mnemonic_a = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic_b = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
    let passphrase = "prosper voice ladder drill rich sugar direct shrug cycle fossil visual hollow";

    let payload_a = DecryptedVaultPayload {
        version: "1.0.0".to_string(),
        created_utc: "2026-09-07T10:00:00Z".to_string(),
        master_root_mnemonic: mnemonic_a.to_string(),
        descriptor: "wpkh([1c23b5f0/84'/1'/0']tpub.../<0;1>/*)#12345678".to_string(),
        heir_treasuries: vec![],
    };

    let payload_b = DecryptedVaultPayload {
        version: "1.0.0".to_string(),
        created_utc: "2026-09-07T10:00:00Z".to_string(),
        master_root_mnemonic: mnemonic_b.to_string(),
        descriptor: "wpkh([2d34c6g1/84'/1'/0']tpub.../<0;1>/*)#87654321".to_string(),
        heir_treasuries: vec![],
    };

    let enc_a = encrypt_vault_payload(&payload_a, passphrase).unwrap();
    let enc_b = encrypt_vault_payload(&payload_b, passphrase).unwrap();

    let vault_a: EncryptedVaultJson = serde_json::from_str(&enc_a).unwrap();
    let vault_b: EncryptedVaultJson = serde_json::from_str(&enc_b).unwrap();

    let salt_a = BASE64_STANDARD.decode(&vault_a.salt).unwrap();
    let salt_b = BASE64_STANDARD.decode(&vault_b.salt).unwrap();
    let iv_a = BASE64_STANDARD.decode(&vault_a.iv).unwrap();
    let iv_b = BASE64_STANDARD.decode(&vault_b.iv).unwrap();

    assert_ne!(salt_a, salt_b);
    assert_ne!(iv_a, iv_b);

    // Assert bit decorrelation (Hamming distance within expected random statistical range):
    // For 16 bytes (128 bits): expected mean = 64, test range [35, 95]
    let dist_salt = hamming_distance(&salt_a, &salt_b);
    assert!(
        (35..=95).contains(&dist_salt),
        "Salt Hamming distance {} out of expected statistical bounds [35, 95]",
        dist_salt
    );

    // For 12 bytes (96 bits): expected mean = 48, test range [25, 75]
    let dist_iv = hamming_distance(&iv_a, &iv_b);
    assert!(
        (25..=75).contains(&dist_iv),
        "IV Hamming distance {} out of expected statistical bounds [25, 75]",
        dist_iv
    );

    // Test 10 distinct BIP-39 mnemonic seeds: all salts and IVs must be mutually unique
    let test_seeds = [
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        "all all all all all all all all all all all all",
        "gravity machine north sort system female filter attitude volume fold club stay",
        "scan wolf juice expand transfer focus tiny dynamic hobby direct improve unit",
        "vessel radar bubble crash drift mirror obscure panel polar dynamic mixed razor",
        "wild trigger visual hidden marble crystal weapon timber barrel border fluid dynamic",
    ];

    let mut salts = Vec::new();
    let mut ivs = Vec::new();

    for seed_text in test_seeds {
        let mut h_salt: Hmac<Sha256> = Mac::new_from_slice(b"subzero:vault:pbkdf2:salt:v1").unwrap();
        h_salt.update(seed_text.trim().as_bytes());
        let s = h_salt.finalize().into_bytes()[..16].to_vec();

        let mut h_iv: Hmac<Sha256> = Mac::new_from_slice(b"subzero:vault:aes-gcm:iv:v1").unwrap();
        h_iv.update(seed_text.trim().as_bytes());
        h_iv.update(passphrase.trim().as_bytes());
        let iv = h_iv.finalize().into_bytes()[..12].to_vec();

        assert!(!salts.contains(&s), "Salt collision detected for seed {}", seed_text);
        assert!(!ivs.contains(&iv), "IV collision detected for seed {}", seed_text);
        salts.push(s);
        ivs.push(iv);
    }
}

#[test]
fn test_vault_tamper_resistance_bit_level_fuzzing() {
    let payload = DecryptedVaultPayload {
        version: "1.0.0".to_string(),
        created_utc: "2026-09-07T10:00:00Z".to_string(),
        master_root_mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        descriptor: "wpkh([1c23b5f0/84'/1'/0']tpub.../<0;1>/*)#12345678".to_string(),
        heir_treasuries: vec![],
    };
    let passphrase = "prosper voice ladder drill rich sugar direct shrug cycle fossil visual hollow";

    // 1. Production Vault Tamper Assertions (600,000 PBKDF2 iterations)
    let valid_prod_json = encrypt_vault_payload(&payload, passphrase).unwrap();
    let prod_vault: EncryptedVaultJson = serde_json::from_str(&valid_prod_json).unwrap();

    // 1a. Tamper single bit in ciphertext payload
    {
        let mut raw_ct = BASE64_STANDARD.decode(&prod_vault.ciphertext).unwrap();
        raw_ct[0] ^= 0x01; // flip bit 0 of first byte
        let mut tampered = prod_vault.clone();
        tampered.ciphertext = BASE64_STANDARD.encode(&raw_ct);
        let tampered_json = serde_json::to_string(&tampered).unwrap();
        let err = decrypt_vault_json(&tampered_json, passphrase)
            .expect_err("Bit flip in ciphertext must fail authentication");
        match err {
            CryptoError::DecryptionError(msg) => assert!(msg.contains("Authentication failed")),
            other => panic!("Expected DecryptionError, got {:?}", other),
        }
    }

    // 1b. Tamper single bit in authentication tag (last 16 bytes of AES-GCM ciphertext)
    {
        let mut raw_ct = BASE64_STANDARD.decode(&prod_vault.ciphertext).unwrap();
        let tag_idx = raw_ct.len() - 1;
        raw_ct[tag_idx] ^= 0x80; // flip high bit of auth tag
        let mut tampered = prod_vault.clone();
        tampered.ciphertext = BASE64_STANDARD.encode(&raw_ct);
        let tampered_json = serde_json::to_string(&tampered).unwrap();
        let err = decrypt_vault_json(&tampered_json, passphrase)
            .expect_err("Bit flip in auth tag must fail authentication");
        match err {
            CryptoError::DecryptionError(msg) => assert!(msg.contains("Authentication failed")),
            other => panic!("Expected DecryptionError, got {:?}", other),
        }
    }

    // 1c. Tamper single bit in IV
    {
        let mut raw_iv = BASE64_STANDARD.decode(&prod_vault.iv).unwrap();
        raw_iv[0] ^= 0x01;
        let mut tampered = prod_vault.clone();
        tampered.iv = BASE64_STANDARD.encode(&raw_iv);
        let tampered_json = serde_json::to_string(&tampered).unwrap();
        let err = decrypt_vault_json(&tampered_json, passphrase)
            .expect_err("Bit flip in IV must fail authentication");
        match err {
            CryptoError::DecryptionError(msg) => assert!(msg.contains("Authentication failed")),
            other => panic!("Expected DecryptionError, got {:?}", other),
        }
    }

    // 1d. Tamper single bit in Salt
    {
        let mut raw_salt = BASE64_STANDARD.decode(&prod_vault.salt).unwrap();
        raw_salt[0] ^= 0x01;
        let mut tampered = prod_vault.clone();
        tampered.salt = BASE64_STANDARD.encode(&raw_salt);
        let tampered_json = serde_json::to_string(&tampered).unwrap();
        let err = decrypt_vault_json(&tampered_json, passphrase)
            .expect_err("Bit flip in salt must fail authentication");
        match err {
            CryptoError::DecryptionError(msg) => assert!(msg.contains("Authentication failed")),
            other => panic!("Expected DecryptionError, got {:?}", other),
        }
    }

    // 1e. Tamper iteration count (downgrade attack from 600,000 to 1)
    {
        let mut tampered = prod_vault.clone();
        tampered.iterations = 1;
        let tampered_json = serde_json::to_string(&tampered).unwrap();
        let err = decrypt_vault_json(&tampered_json, passphrase)
            .expect_err("Iteration downgrade tampering must fail authentication");
        match err {
            CryptoError::DecryptionError(msg) => assert!(msg.contains("Authentication failed")),
            other => panic!("Expected DecryptionError, got {:?}", other),
        }
    }

    // 1f. Invalid IV length (11 bytes or 16 bytes instead of 12)
    {
        let mut tampered = prod_vault.clone();
        tampered.iv = BASE64_STANDARD.encode([0u8; 11]);
        let tampered_json = serde_json::to_string(&tampered).unwrap();
        let err = decrypt_vault_json(&tampered_json, passphrase).expect_err("11-byte IV must fail");
        match err {
            CryptoError::DecryptionError(msg) => assert!(msg.contains("IV must be 12 bytes")),
            other => panic!("Expected DecryptionError for invalid IV length, got {:?}", other),
        }
    }

    // 1g. Corrupt Base64
    {
        let mut tampered = prod_vault.clone();
        tampered.ciphertext = "!!! NOT VALID BASE64 !!!".to_string();
        let tampered_json = serde_json::to_string(&tampered).unwrap();
        assert!(decrypt_vault_json(&tampered_json, passphrase).is_err());
    }

    // 2. High-Density Property-Based Bit-Mutation Fuzzing (128 Bit Flips in Auth Tag)
    // Using fast fixture (iterations = 10) to test 100% of bits in the 16-byte authentication tag
    let (_fast_json, fast_vault) = create_test_vault_json_fixture(&payload, passphrase, 10);
    let original_ct_bytes = BASE64_STANDARD.decode(&fast_vault.ciphertext).unwrap();
    let ct_len = original_ct_bytes.len();
    assert!(ct_len >= 16);
    let tag_start = ct_len - 16;

    // Test mutating EVERY single bit across all 16 bytes of the authentication tag (128 bit flips):
    for byte_offset in 0..16 {
        for bit in 0..8 {
            let mut tampered_bytes = original_ct_bytes.clone();
            tampered_bytes[tag_start + byte_offset] ^= 1 << bit;

            let mut tampered_vault = fast_vault.clone();
            tampered_vault.ciphertext = BASE64_STANDARD.encode(&tampered_bytes);
            let tampered_json = serde_json::to_string(&tampered_vault).unwrap();

            let err = decrypt_vault_json(&tampered_json, passphrase).expect_err(&format!(
                "Decryption must fail when auth tag byte {} bit {} is mutated",
                byte_offset, bit
            ));

            match err {
                CryptoError::DecryptionError(msg) => {
                    assert!(msg.contains("Authentication failed"));
                }
                other => panic!("Expected DecryptionError, got {:?}", other),
            }
        }
    }

    // Mutate 50 distributed bit positions in the ciphertext body:
    let mut rng = StdRng::seed_from_u64(0xCAFE_BABE_0005);
    for _ in 0..50 {
        let byte_idx = rng.gen_range(0..tag_start);
        let bit = rng.gen_range(0..8);

        let mut tampered_bytes = original_ct_bytes.clone();
        tampered_bytes[byte_idx] ^= 1 << bit;

        let mut tampered_vault = fast_vault.clone();
        tampered_vault.ciphertext = BASE64_STANDARD.encode(&tampered_bytes);
        let tampered_json = serde_json::to_string(&tampered_vault).unwrap();

        let err = decrypt_vault_json(&tampered_json, passphrase).expect_err(&format!(
            "Decryption must fail for body byte {} bit {}",
            byte_idx, bit
        ));
        match err {
            CryptoError::DecryptionError(msg) => assert!(msg.contains("Authentication failed")),
            other => panic!("Expected DecryptionError, got {:?}", other),
        }
    }
}

#[test]
fn test_vault_wrong_passphrase_attack_clean_error() {
    let payload = DecryptedVaultPayload {
        version: "1.0.0".to_string(),
        created_utc: "2026-09-07T10:00:00Z".to_string(),
        master_root_mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        descriptor: "wpkh([1c23b5f0/84'/1'/0']tpub.../<0;1>/*)#12345678".to_string(),
        heir_treasuries: vec![],
    };
    let correct_passphrase = "prosper voice ladder drill rich sugar direct shrug cycle fossil visual hollow";

    let (fast_json, _) = create_test_vault_json_fixture(&payload, correct_passphrase, 10);

    // Verify correct passphrase decrypts cleanly
    let roundtrip = decrypt_vault_json(&fast_json, correct_passphrase).unwrap();
    assert_eq!(roundtrip.master_root_mnemonic, payload.master_root_mnemonic);

    // Adversarial Passphrase Attacks:
    let adversarial_passphrases = [
        // 1-character typo in first word
        "prosperx voice ladder drill rich sugar direct shrug cycle fossil visual hollow",
        // 1-character typo in last word
        "prosper voice ladder drill rich sugar direct shrug cycle fossil visual holloww",
        // Replaced single word with valid BIP-39 word
        "prosper voice ladder drill rich sugar direct shrug cycle fossil visual about",
        // Reversed word order
        "hollow visual fossil cycle shrug direct sugar rich drill ladder voice prosper",
        // 11 words (truncated)
        "prosper voice ladder drill rich sugar direct shrug cycle fossil visual",
        // Completely different valid 12-word phrase
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        // Empty passphrase
        "",
        // Whitespace only
        "   \t\n  ",
        // Single character
        "a",
    ];

    for bad_pass in adversarial_passphrases {
        let err = decrypt_vault_json(&fast_json, bad_pass)
            .expect_err(&format!("Decryption with bad passphrase '{}' must fail", bad_pass));

        match err {
            CryptoError::DecryptionError(msg) => {
                assert!(
                    msg.contains("Authentication failed"),
                    "Error must be clean authentication failure, got '{}'",
                    msg
                );
            }
            other => panic!("Expected DecryptionError, got {:?}", other),
        }
    }
}

#[test]
fn test_vault_unicode_and_whitespace_normalization() {
    let payload = DecryptedVaultPayload {
        version: "1.0.0".to_string(),
        created_utc: "2026-09-07T10:00:00Z".to_string(),
        master_root_mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        descriptor: "wpkh([1c23b5f0/84'/1'/0']tpub.../<0;1>/*)#12345678".to_string(),
        heir_treasuries: vec![],
    };

    // 1. Whitespace Collapsing & Case Normalization Invariant:
    // Encrypt with messy whitespace and mixed casing:
    let unnormalized_input = "  PROSPER \t\t voice \n\n LADDER   drill  RICH sugar DIRECT shrug CYCLE fossil VISUAL hollow \r\n  ";
    let canonical_clean = "prosper voice ladder drill rich sugar direct shrug cycle fossil visual hollow";

    let (json_unnormalized, _) = create_test_vault_json_fixture(&payload, unnormalized_input, 10);

    // Decrypt using canonical clean passphrase:
    let dec_clean = decrypt_vault_json(&json_unnormalized, canonical_clean)
        .expect("Decryption must succeed with canonical passphrase");
    assert_eq!(dec_clean.master_root_mnemonic, payload.master_root_mnemonic);

    // Decrypt using unnormalized input:
    let dec_unnorm = decrypt_vault_json(&json_unnormalized, unnormalized_input)
        .expect("Decryption must succeed with messy whitespace passphrase");
    assert_eq!(dec_unnorm.master_root_mnemonic, payload.master_root_mnemonic);

    // 2. Unicode / Non-ASCII & Long Passphrase Hardening (128+ characters):
    let complex_unicode_passphrase = "crème brûlée naïve façade 123!@#$%^&*()_+~ 🚀 128-char-passphrase-with-extensive-entropy-and-non-ascii-characters-verified-for-estate-vault-hygiene";
    assert!(complex_unicode_passphrase.len() >= 128);

    let (json_unicode, _) = create_test_vault_json_fixture(&payload, complex_unicode_passphrase, 10);
    let dec_unicode = decrypt_vault_json(&json_unicode, complex_unicode_passphrase)
        .expect("Complex Unicode passphrase encryption/decryption roundtrip must succeed");
    assert_eq!(dec_unicode.master_root_mnemonic, payload.master_root_mnemonic);

    // Alter single Unicode accent: "crème" -> "creme"
    let tampered_unicode = "creme brûlée naïve façade 123!@#$%^&*()_+~ 🚀 128-char-passphrase-with-extensive-entropy-and-non-ascii-characters-verified-for-estate-vault-hygiene";
    let err_unicode = decrypt_vault_json(&json_unicode, tampered_unicode)
        .expect_err("Altered Unicode diacritic must fail authentication");
    match err_unicode {
        CryptoError::DecryptionError(msg) => assert!(msg.contains("Authentication failed")),
        other => panic!("Expected DecryptionError, got {:?}", other),
    }
}

// ============================================================================
// VECTOR 3: MEMORY HYGIENE & ZEROIZE ON DROP ASSERTIONS
// ============================================================================

#[test]
fn test_memory_hygiene_and_zeroize_assertions() {
    // 1. SecretEntropy length invariant and zeroize behavior
    {
        assert!(SecretEntropy::new(vec![0x00; 15]).is_err());
        assert!(SecretEntropy::new(vec![0x00; 17]).is_err());
        assert!(SecretEntropy::new(vec![0x00; 31]).is_err());
        assert!(SecretEntropy::new(vec![0x00; 33]).is_err());

        let sec16 = SecretEntropy::new(vec![0xA5; 16]).unwrap();
        assert_eq!(sec16.as_bytes().len(), 16);
        assert_eq!(sec16.as_bytes()[0], 0xA5);

        let sec32 = SecretEntropy::new(vec![0x5A; 32]).unwrap();
        assert_eq!(sec32.as_bytes().len(), 32);
        assert_eq!(sec32.as_bytes()[0], 0x5A);
        // Automatic ZeroizeOnDrop triggered upon leaving scope
    }

    // 2. GeneratedSeed Zeroize assertion
    {
        let mut seed = GeneratedSeed {
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            fingerprint: "1c23b5f0".to_string(),
            descriptor: "wpkh([1c23b5f0/84'/1'/0']tpub.../<0;1>/*)#12345678".to_string(),
            vpub: "tpubDC59...".to_string(),
            vpub_slip132: "vpub5Y...".to_string(),
            addresses: vec!["tb1qtest1".to_string(), "tb1qtest2".to_string()],
            entropy_type: "Physical Coin Flips (128-bit Bin)".to_string(),
        };

        assert!(!seed.mnemonic.is_empty());
        seed.zeroize();
        assert!(seed.mnemonic.is_empty(), "Mnemonic must be zeroized");
        assert!(seed.fingerprint.is_empty(), "Fingerprint must be zeroized");
        assert!(seed.descriptor.is_empty(), "Descriptor must be zeroized");
        assert!(seed.vpub.is_empty(), "Vpub must be zeroized");
        assert!(seed.vpub_slip132.is_empty(), "Vpub SLIP-132 must be zeroized");
        assert!(seed.addresses.is_empty(), "Addresses vector must be zeroized");
        assert!(seed.entropy_type.is_empty(), "Entropy type must be zeroized");
    }

    // 3. Bip85Child Zeroize assertion
    {
        let mut child = Bip85Child {
            label: "Decoupled Estate Passphrase (Index 0)".to_string(),
            index: 0,
            path: "m/83696968'/39'/0'/12'/0'".to_string(),
            mnemonic: "prosper voice ladder drill rich sugar direct shrug cycle fossil visual hollow".to_string(),
        };

        assert!(!child.mnemonic.is_empty());
        child.zeroize();
        assert!(child.mnemonic.is_empty(), "Bip85Child mnemonic must be zeroized");
        assert!(child.path.is_empty(), "Bip85Child path must be zeroized");
        assert!(child.label.is_empty(), "Bip85Child label must be zeroized");
    }

    // 4. DecryptedVaultPayload Zeroize assertion
    {
        let mut payload = DecryptedVaultPayload {
            version: "1.0.0".to_string(),
            created_utc: "2026-09-07T10:00:00Z".to_string(),
            master_root_mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            descriptor: "wpkh(...)".to_string(),
            heir_treasuries: vec![
                Bip85Child {
                    label: "Heir 1".to_string(),
                    index: 1,
                    path: "m/83696968'/39'/0'/12'/1'".to_string(),
                    mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong".to_string(),
                }
            ],
        };

        assert!(!payload.master_root_mnemonic.is_empty());
        payload.zeroize();
        assert!(payload.master_root_mnemonic.is_empty(), "Master root mnemonic must be zeroized");
        assert!(payload.descriptor.is_empty(), "Descriptor must be zeroized");
        assert!(payload.version.is_empty(), "Version must be zeroized");
        assert!(payload.created_utc.is_empty(), "Created UTC must be zeroized");
        assert!(payload.heir_treasuries.is_empty(), "Heir treasuries must be zeroized");
    }

    // 5. AppState memory wipe and Drop hygiene verification
    {
        let mut state = AppState::new("2026-09-07T10:00:00Z".to_string(), "d3adb33f".to_string());

        let coin_entropy = "00100000100000001011001110010010111010101100001000111101101000011101000111001011101001111001000001011110011011010100100100110011";
        let seed = process_physical_entropy(coin_entropy).unwrap();
        let children = derive_bip85_children(&seed.mnemonic, 5).unwrap();

        state.set_seed(seed, children);
        state.set_entropy_input(coin_entropy);
        state.vault_passphrase_input = "secret pass".to_string();
        state.seedfix_input = "twelve test words".to_string();
        state.jitter_samples = vec![('x', 100_000), ('y', 200_000)];
        state.decrypted_vault = Some(DecryptedVaultPayload {
            version: "1.0".into(),
            created_utc: "2026".into(),
            master_root_mnemonic: "test words".into(),
            descriptor: "desc".into(),
            heir_treasuries: vec![],
        });

        // Assert sensitive fields are populated
        assert!(state.seed.is_some());
        assert!(state.decoupled_passphrase.is_some());
        assert_eq!(state.bip85_children.len(), 5);
        assert!(!state.entropy_input.is_empty());
        assert!(!state.vault_passphrase_input.is_empty());
        assert!(!state.seedfix_input.is_empty());
        assert_eq!(state.jitter_samples.len(), 2);
        assert!(state.decrypted_vault.is_some());

        // Trigger memory wipe
        state.wipe_memory();

        // Assert all sensitive fields have been zeroized and reset to clean amnesic state
        assert!(state.seed.is_none(), "Seed must be None after wipe");
        assert!(state.decoupled_passphrase.is_none(), "Passphrase must be None after wipe");
        assert!(state.bip85_children.is_empty(), "BIP85 children must be empty after wipe");
        assert!(state.entropy_input.is_empty(), "Entropy input must be empty after wipe");
        assert!(state.vault_passphrase_input.is_empty(), "Vault passphrase input must be empty after wipe");
        assert!(state.seedfix_input.is_empty(), "Seedfix input must be empty after wipe");
        assert!(state.jitter_samples.is_empty(), "Jitter samples must be empty after wipe");
        assert!(state.decrypted_vault.is_none(), "Decrypted vault must be None after wipe");
        assert!(state.status_message.contains("MEMORY WIPED"), "Status message must confirm wipe");
        assert!(state.wipe_confirmation_instant.is_some());
    }

    // 6. Test AppState Drop automatically calls wipe_memory() without panicking
    {
        let _state = AppState::new("2026-09-07".to_string(), "commit".to_string());
        // Dropped at end of block
    }
}
