use subzero::crypto::{process_physical_entropy, derive_bip85_children, CryptoError};
use subzero::seedfix::solve_twelfth_word;

#[test]
fn test_coin_entropy_to_bip39_testnet4() {
    // 128-bit realistic binary entropy passing Markov and repetition tests
    let binary_str = "00100000100000001011001110010010111010101100001000111101101000011101000111001011101001111001000001011110011011010100100100110011";
    let seed = process_physical_entropy(binary_str).expect("Failed to process coin entropy");

    assert_eq!(seed.mnemonic.split_whitespace().count(), 12);
    assert_eq!(seed.fingerprint.len(), 8);
    assert!(seed.descriptor.starts_with("wpkh(["));
    assert!(seed.descriptor.contains("/84'/1'/0'"));
    assert!(seed.descriptor.contains('#')); // BIP-380 Checksum present!
    assert_eq!(seed.addresses.len(), 50);
    for addr in &seed.addresses {
        assert!(addr.starts_with("tb1q"));
    }
}

#[test]
fn test_dice_entropy_to_bip39_testnet4() {
    // 60 realistic dice rolls passing Markov, Chi-squared, and repetition tests
    let dice_str = "423124613254162351426351423165241362514362514362513245163254";
    let seed = process_physical_entropy(dice_str).expect("Failed to process dice entropy");

    assert_eq!(seed.mnemonic.split_whitespace().count(), 12);
    assert_eq!(seed.fingerprint.len(), 8);
    assert!(seed.descriptor.contains("/84'/1'/0'"));
    assert!(seed.descriptor.contains('#')); // BIP-380 Checksum present!
    for addr in &seed.addresses {
        assert!(addr.starts_with("tb1q"));
    }
}

#[test]
fn test_entropy_quality_hard_block() {
    // Patterned alternating coin flips (10101010...) MUST fail Markov audit
    let biased_str = "10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010";
    let err = process_physical_entropy(biased_str).expect_err("Should have failed Markov audit");
    match err {
        CryptoError::MarkovAuditFailed(_) => {},
        _ => panic!("Expected MarkovAuditFailed, got {:?}", err),
    }

    // Short dice rolls (56 rolls < 60) MUST fail length check
    let short_dice = "42312461325243625522323266341621355533154531632254132415";
    let err_short = process_physical_entropy(short_dice).expect_err("Should have failed <60 rolls");
    match err_short {
        CryptoError::InvalidEntropyLength(56) => {},
        _ => panic!("Expected InvalidEntropyLength(56), got {:?}", err_short),
    }

    // Severely skewed frequency (84 ones and 44 zeros) passing Markov but failing Chi-squared audit
    let skewed = "01010111101011101111011111110010111011111110110111110111001001101111001011111101100100110111111001110110110101100000010100111011";
    let err_chi2 = process_physical_entropy(skewed).expect_err("Should have failed Chi-squared audit");
    match err_chi2 {
        CryptoError::ChiSquaredAuditFailed(_) => {},
        _ => panic!("Expected ChiSquaredAuditFailed, got {:?}", err_chi2),
    }

    // Repetitive chunk string (123123123...) MUST fail repetition check
    let repeat_str = "123123123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
    let err2 = process_physical_entropy(repeat_str).expect_err("Should have failed repetition check");
    match err2 {
        CryptoError::RepetitivePatternDetected | CryptoError::MarkovAuditFailed(_) | CryptoError::ChiSquaredAuditFailed(_) => {},
        _ => panic!("Expected repetition/markov error, got {:?}", err2),
    }
}

#[test]
fn test_bip85_derivation() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let children = derive_bip85_children(mnemonic, 3).expect("BIP-85 derivation failed");

    // Index 0 (passphrase) + Indices 1..=3 (heirs) = 4 keys total
    assert_eq!(children.len(), 4);
    assert_eq!(children[0].index, 0);
    assert!(children[0].label.contains("Passphrase"));
    assert_eq!(children[0].mnemonic.split_whitespace().count(), 12);

    for child in &children[1..] {
        assert_eq!(child.mnemonic.split_whitespace().count(), 12);
    }
}

#[test]
fn test_seedfix_levenshtein() {
    let eleven_words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    let results = solve_twelfth_word(eleven_words, Some("aboot")).expect("SeedFix solver failed");

    assert_eq!(results.len(), 128);
    // "about" has distance 1 from "aboot", should be ranked first
    assert_eq!(results[0].twelfth_word, "about");
    assert_eq!(results[0].distance, 1);
}

#[test]
fn test_deterministic_vault_encryption_roundtrip() {
    use subzero::crypto::{encrypt_vault_payload, decrypt_vault_json, DecryptedVaultPayload};

    let payload = DecryptedVaultPayload {
        version: "1.0.0".to_string(),
        created_utc: "2026-09-04T05:00:00Z".to_string(),
        master_root_mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        descriptor: "wpkh([1c23b5f0/84'/1'/0']tpubDC59.../<0;1>/*)#12345678".to_string(),
        heir_treasuries: vec![],
    };

    let passphrase = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
    
    // Encrypt twice - must be 100% deterministic (identical ciphertext, salt, and iv derived from physical root entropy)
    let encrypted1 = encrypt_vault_payload(&payload, passphrase).expect("Encryption failed");
    let encrypted2 = encrypt_vault_payload(&payload, passphrase).expect("Encryption failed");
    assert_eq!(encrypted1, encrypted2, "Vault encryption must be deterministic from physical root entropy");

    // Decrypt and verify payload matches original
    let decrypted = decrypt_vault_json(&encrypted1, passphrase).expect("Decryption failed");
    assert_eq!(decrypted.master_root_mnemonic, payload.master_root_mnemonic);
    assert_eq!(decrypted.descriptor, payload.descriptor);
}

#[test]
fn test_harvest_keystroke_jitter_to_binary() {
    use subzero::crypto::{harvest_keystroke_jitter_to_binary, process_physical_entropy};

    let samples = vec![
        ('a', 142839120),
        ('s', 89412045),
        ('d', 210183991),
        ('f', 73501230),
        ('j', 118924402),
        ('k', 95210340),
        ('l', 160411205),
        (';', 84129031),
    ];

    let bits1 = harvest_keystroke_jitter_to_binary(&samples);
    let bits2 = harvest_keystroke_jitter_to_binary(&samples);

    assert_eq!(bits1.len(), 128);
    assert_eq!(bits1, bits2, "Jitter hashing must be deterministic for identical sample sequence");
    assert!(bits1.chars().all(|c| c == '0' || c == '1'));

    // Verify it parses cleanly into a 12-word BIP-39 mnemonic
    let seed = process_physical_entropy(&bits1).expect("Failed to process jitter entropy");
    assert_eq!(seed.mnemonic.split_whitespace().count(), 12);
}
