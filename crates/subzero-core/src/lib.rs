//! `subzero-core` - Unified Pure-Rust Cryptographic Engine for SubZero v2.0.
//!
//! Compiles with zero OS-RNG (`getrandom`) and zero network dependencies across:
//! - `x86_64-unknown-linux-musl` (`crates/subzero-tui` Bare-Metal Linux Cold Vault)
//! - `wasm32-unknown-unknown` (`crates/subzero-wasm` Standalone Single-File HTML Kiosk)

pub mod descriptor;
pub mod entropy;
pub mod error;
pub mod keys;
pub mod pipek1;
pub mod presets;
pub mod psbt;
pub mod qr_codec;
pub mod seedfix;
pub mod vault;

pub const SUBZERO_VERSION: &str = "2.0.0-testnet4";
pub const SUBZERO_NETWORK: &str = "Bitcoin Testnet4 (BIP-94)";
