use std::fs;
use bitcoin::secp256k1::{Secp256k1, Keypair, Message, XOnlyPublicKey};
use bitcoin::hashes::{sha256, Hash};

#[test]
fn test_generate_nostr_release_signatures() {
    let secp = Secp256k1::new();

    // Bootlace Nostr private key (from assets/bootlace_nostr_identity.json)
    let hex_priv = "bc84a4c97080f4c7746e742b286742a51ae80c5b70245cc8681762b454aa5400";
    let expected_pub = "8cdc4bc23ae651e239092bed7bcba6bac2a7061b3d41599f0ab19a91ac8a0c48";
    let priv_bytes = hex::decode(hex_priv).expect("Invalid hex private key");

    let keypair = Keypair::from_seckey_slice(&secp, &priv_bytes).expect("Failed to create keypair");
    let (xonly_pub, _parity) = XOnlyPublicKey::from_keypair(&keypair);
    assert_eq!(xonly_pub.to_string(), expected_pub, "Derived pubkey must match bootlace npub hex!");

    // 1. Read RELEASE_NOTES_v0.4.0.md
    let notes_path = "docs/RELEASE_NOTES_v0.4.0.md";
    let notes_bytes = fs::read(notes_path).expect("Failed to read release notes");
    let notes_hash = sha256::Hash::hash(&notes_bytes);
    let notes_msg = Message::from_digest_slice(notes_hash.as_ref()).expect("Valid message digest");

    // 2. Sign with BIP-340 Schnorr (deterministic, zero aux rand)
    let schnorr_sig = secp.sign_schnorr_no_aux_rand(&notes_msg, &keypair);
    secp.verify_schnorr(&schnorr_sig, &notes_msg, &xonly_pub).expect("Signature verification failed!");

    let sig_hex = schnorr_sig.to_string();
    println!(">>> RELEASE NOTES SHA-256: {}", notes_hash);
    println!(">>> NOSTR BIP-340 SIGNATURE: {}", sig_hex);

    // Write detached Nostr signature manifest
    let nostrsig_content = format!(
        "-----BEGIN NOSTR BIP-340 SIGNED MESSAGE-----\n\
         Algorithm: BIP-340 Schnorr (secp256k1)\n\
         Identity: bootlace-dev\n\
         Npub: npub13nwyhs36ueg7ywgf90khhjaxhtp2wpsm84q4n8c2kxdfrty2p3yqfd8fcn\n\
         Pubkey: {}\n\
         Target-File: RELEASE_NOTES_v0.4.0.md\n\
         Target-SHA256: {}\n\
         Signature: {}\n\
         -----END NOSTR BIP-340 SIGNED MESSAGE-----\n",
        expected_pub, notes_hash, sig_hex
    );
    fs::write("docs/RELEASE_NOTES_v0.4.0.md.nostrsig", nostrsig_content).expect("Failed to write .nostrsig");

    // 3. Construct standard Nostr NIP-01 Kind 1 Release Announcement Event
    let created_at = 1789233131u64; // Deterministic timestamp matching release
    let content = format!(
        "Announcement: SubZero-rs v0.4.0 Release — Stateless Amnesic Two-Way Optical Airgap Bitcoin Vault Appliance.\n\n\
         • COTS Over Honeypots: Airgap signing on generic commodity laptops.\n\
         • Stateless Optical Loop: Webcam PSBT QR ingestion (zbarcam) + animated BBQR signing.\n\
         • Substrate Hardened: Network and bluetooth kernel modules completely stripped.\n\
         • DRAM Remanence Protection: kexec into memtest86+ v8.10 actively scrubs all RAM before power cut.\n\
         • 5-Section Deep Ledger: Gap limit audits, offline address reuse, RFC 6979 nonce badge, USD converter.\n\
         • 100% Deterministic Reproducible Musl Build.\n\n\
         Git: https://github.com/bootlace-dev/subzero-keyosk/releases/tag/v0.4.0-testnet4\n\
         Commit: d4fd7a9\n\
         SHA-256 (subzero-x86_64-musl): {}\n\
         Signed by bootlace-dev GPG (F18173E554644BB59018AE50F6E96FADCA2E8E0F)",
        "7000d6eac0bb6943b966002c2efdf9fb8fc6a08574d933268ce16338b0ceda52"
    );

    let tags = serde_json::json!([
        ["t", "bitcoin"],
        ["t", "subzero"],
        ["t", "airgap"],
        ["t", "cots"],
        ["t", "release"],
        ["e", "d4fd7a9"]
    ]);

    let event_payload = serde_json::json!([
        0,
        expected_pub,
        created_at,
        1,
        tags,
        content
    ]);

    let serialized = event_payload.to_string();
    let event_id_hash = sha256::Hash::hash(serialized.as_bytes());
    let event_msg = Message::from_digest_slice(event_id_hash.as_ref()).expect("Valid event digest");
    let event_sig = secp.sign_schnorr_no_aux_rand(&event_msg, &keypair);
    secp.verify_schnorr(&event_sig, &event_msg, &xonly_pub).expect("Event signature failed");

    let nostr_event = serde_json::json!({
        "id": event_id_hash.to_string(),
        "pubkey": expected_pub,
        "created_at": created_at,
        "kind": 1,
        "tags": tags,
        "content": content,
        "sig": event_sig.to_string()
    });

    fs::write("docs/nostr_release_event.json", serde_json::to_string_pretty(&nostr_event).unwrap()).expect("Failed to write nostr event");
    println!(">>> NOSTR EVENT ID: {}", event_id_hash);
    println!(">>> NOSTR EVENT SIG: {}", event_sig);
}
