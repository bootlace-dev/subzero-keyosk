//! Layer 3 adversarial / fuzz-style tests: ensure malformed inputs never panic.

use subzero_core::entropy::{harvest_coins, harvest_dice, harvest_raw_hex};
use subzero_core::vault::decrypt_vault_json;

#[test]
fn test_malformed_inputs_never_panic() {
    for bad in ["", "   ", "0", "zzzz", "\x00\x01\x7f", &"a".repeat(10_000)] {
        let _ = harvest_coins(bad);
        let _ = harvest_dice(bad);
        let _ = harvest_raw_hex(bad);
        let _ = bitcoin::psbt::Psbt::deserialize(bad.as_bytes());
        let _ = decrypt_vault_json(
            bad,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        );
    }
}

#[test]
fn test_malformed_vault_json_variants_never_panic() {
    let cases = [
        "{}",
        r#"{"format":"subzero-vault-v2"}"#,
        r#"{"format":"subzero-vault-v2","cipher":"AES-256-GCM","kdf":"PBKDF2-HMAC-SHA256","iterations":1,"salt_hex":"00","iv_hex":"00","ciphertext_b64":"!!!"}"#,
    ];
    for c in cases {
        assert!(decrypt_vault_json(c, "wrong passphrase").is_err());
    }
}
