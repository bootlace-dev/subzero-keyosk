use subzero::crypto::{process_physical_entropy, derive_bip85_children};
use subzero::seedfix::solve_twelfth_word;

#[test]
fn test_coin_entropy_to_bip39_testnet4() {
    // 128-bit binary entropy (alternating 1s and 0s)
    let binary_str = "10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010";
    let seed = process_physical_entropy(binary_str).expect("Failed to process coin entropy");

    assert_eq!(seed.mnemonic.split_whitespace().count(), 12);
    assert_eq!(seed.fingerprint.len(), 8);
    assert!(seed.descriptor.starts_with("wpkh(["));
    assert!(seed.descriptor.contains("/84'/1'/0'"));
    assert_eq!(seed.addresses.len(), 5);
    for addr in &seed.addresses {
        assert!(addr.starts_with("tb1q"));
    }
}

#[test]
fn test_dice_entropy_to_bip39_testnet4() {
    // 50 dice rolls (1-6)
    let dice_str = "12345612345612345612345612345612345612345612345612";
    let seed = process_physical_entropy(dice_str).expect("Failed to process dice entropy");

    assert_eq!(seed.mnemonic.split_whitespace().count(), 12);
    assert_eq!(seed.fingerprint.len(), 8);
    assert!(seed.descriptor.contains("/84'/1'/0'"));
    for addr in &seed.addresses {
        assert!(addr.starts_with("tb1q"));
    }
}

#[test]
fn test_bip85_derivation() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let children = derive_bip85_children(mnemonic, 3).expect("BIP-85 derivation failed");

    assert_eq!(children.len(), 3);
    for child in children {
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
