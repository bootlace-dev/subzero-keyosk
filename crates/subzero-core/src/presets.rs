//! Unified Testnet4 Rehearsal Presets (`Preset 0..9`).
//!
//! WHY THESE EXACT 10 PRESETS:
//! Earlier iterations maintained divergent preset lists between the Rust TUI (10 presets)
//! and the HTML Kiosk (8 presets). A live Fulcrum scan over 5,000+ derived Testnet4
//! addresses (`84'/1'/0'/<0;1>/*`, `86'/1'/0'/*`, and `BIP85[0..9]`) identified these exact
//! 10 deterministic public seeds holding 3,137,903 confirmed Testnet4 sats for safe,
//! zero-value rehearsal of watch-only wallet imports, UTXO discovery, BIP-85 child
//! vaults, and PSBT airgap signing.
//!
//! SECURITY INVARIANT:
//! Presets carry `EntropyTrustTier::DeterministicRehearsalPreset` (0 bits of secret entropy)
//! and are strictly labeled as public Testnet4 test vectors across every screen and export.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::SubZeroError;

pub const PRESET_COUNT: usize = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RehearsalPreset {
    pub id: u8,
    pub code: &'static str,
    pub title: &'static str,
    pub formula: &'static str,
    pub expected_fingerprint: &'static str,
    pub expected_mnemonic: &'static str,
    pub live_utxo_note: &'static str,
    pub entropy_hex: String,
}

pub fn preset_entropy(id: u8) -> Result<[u8; 16], SubZeroError> {
    let mut out = [0u8; 16];
    match id {
        0 => {
            // 0x00 * 16 (BIP-39 Zero Baseline) -> 73c5da0a
            out = [0x00; 16];
        }
        1 => {
            // 0x55 * 16 (Alternating 01010101) -> 3ce38a29
            out = [0x55; 16];
        }
        2 => {
            // 0x7F * 16 (Signed Byte Boundary + Funded BIP-85 [1..4]) -> b8688df1
            out = [0x7f; 16];
        }
        3 => {
            // 0xFF * 16 (All-Ones Max Boundary) -> 3f635a63
            out = [0xff; 16];
        }
        4 => {
            // 0x0123456789abcdef * 2 (Incremental Nibbles) -> 5b0417d1
            out = [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef,
            ];
        }
        5 => {
            // 0x000102030405060708090a0b0c0d0e0f (Sequential Bytes) -> 05d027a5
            out = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ];
        }
        6 => {
            // Official BIP-39 Reference Vector ("vessel ladder ... picture") -> bc2b7c36
            out = [
                0xf3, 0x0f, 0x8c, 0x1d, 0xa6, 0x65, 0x47, 0x8f, 0x49, 0xb0, 0x01, 0xd9, 0x4c, 0x5f,
                0xc4, 0x52,
            ];
        }
        7 => {
            // SHA256("correct horse battery staple")[..16] -> 4bd30500
            let digest = Sha256::digest(b"correct horse battery staple");
            out.copy_from_slice(&digest[..16]);
        }
        8 => {
            // SHA256("The Times 03/Jan/2009 Chancellor on brink of second bailout for banks")[..16] -> a9148b7e
            let digest = Sha256::digest(
                b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
            );
            out.copy_from_slice(&digest[..16]);
        }
        9 => {
            // SHA256("Running bitcoin - Hal Finney 10 Jan 2009")[..16] -> 1efb5645
            let digest = Sha256::digest(b"Running bitcoin - Hal Finney 10 Jan 2009");
            out.copy_from_slice(&digest[..16]);
        }
        _ => {
            return Err(SubZeroError::Entropy(format!(
                "Invalid preset index {id} (expected 0..=9)."
            )));
        }
    }
    Ok(out)
}

pub fn list_presets() -> Vec<RehearsalPreset> {
    const META: [(
        u8,
        &str,
        &str,
        &str,
        &str,
        &str,
        &str,
    ); PRESET_COUNT] = [
        (
            0,
            "test0",
            "Preset 0: BIP-39 Zero Baseline",
            "0x00 * 16",
            "73c5da0a",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "Live Testnet4 UTXOs on 0/1 and change 1/12..14 (375+ historical txs)",
        ),
        (
            1,
            "test1",
            "Preset 1: Alternating Bits",
            "0x55 * 16",
            "3ce38a29",
            "fetch primary fetch primary fetch primary fetch primary fetch primary fetch problem",
            "Live Testnet4 UTXO on change 1/1",
        ),
        (
            2,
            "test2",
            "Preset 2: Signed Byte Boundary + BIP-85 Heirs",
            "0x7F * 16",
            "b8688df1",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "Live Testnet4 UTXOs on 0/1..4, 0/6..8 plus funded BIP-85 child seeds [1..4]",
        ),
        (
            3,
            "test3",
            "Preset 3: All-Ones Max Boundary",
            "0xFF * 16",
            "3f635a63",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "Live Testnet4 UTXOs across 0/0, 0/8..9, 1/0, and 1/2",
        ),
        (
            4,
            "test4",
            "Preset 4: Incremental Nibbles",
            "0x0123456789abcdef * 2",
            "5b0417d1",
            "abuse boss fly battle rubber wasp afraid hamster guide essence vibrant tattoo",
            "Live Testnet4 UTXO on 0/1",
        ),
        (
            5,
            "test5",
            "Preset 5: Sequential Bytes",
            "0x000102030405060708090a0b0c0d0e0f",
            "05d027a5",
            "abandon amount liar amount expire adjust cage candy arch gather drum buyer",
            "Live Testnet4 UTXO on 0/0",
        ),
        (
            6,
            "test6",
            "Preset 6: BIP-39 Reference Vector",
            "0xf30f8c1da665478f49b001d94c5fc452",
            "bc2b7c36",
            "vessel ladder alter error federal sibling chat ability sun glass valve picture",
            "Live Testnet4 UTXO on 0/0",
        ),
        (
            7,
            "test7",
            "Preset 7: XKCD 936 Passphrase Hash",
            "SHA256('correct horse battery staple')[0..16]",
            "4bd30500",
            "seven tattoo side laugh oil ready word deposit frame grant merry shell",
            "Live Testnet4 UTXOs on 0/0..1",
        ),
        (
            8,
            "test8",
            "Preset 8: Genesis Block Headline",
            "SHA256('The Times 03/Jan/2009...')[0..16]",
            "a9148b7e",
            "plug rich tunnel kiwi mosquito fix what brief marine income autumn car",
            "Live Testnet4 UTXOs on 0/0..1",
        ),
        (
            9,
            "test9",
            "Preset 9: Hal Finney First Tweet",
            "SHA256('Running bitcoin - Hal Finney 10 Jan 2009')[0..16]",
            "1efb5645",
            "fuel zone cycle muffin sun glad august disagree river token consider board",
            "Live Testnet4 UTXO on change 1/1",
        ),
    ];

    META.into_iter()
        .map(
            |(id, code, title, formula, expected_fingerprint, expected_mnemonic, live_utxo_note)| {
                let ent = preset_entropy(id).expect("valid preset id");
                RehearsalPreset {
                    id,
                    code,
                    title,
                    formula,
                    expected_fingerprint,
                    expected_mnemonic,
                    live_utxo_note,
                    entropy_hex: hex::encode(ent),
                }
            },
        )
        .collect()
}

pub fn get_preset(id: u8) -> Result<RehearsalPreset, SubZeroError> {
    list_presets()
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| SubZeroError::Entropy(format!("Invalid preset index {id} (expected 0..=9).")))
}
