# SubZero Defensive Rationale Index

This document explicitly outlines the architectural trade-offs, security mechanics, and structural rationale for the SubZero appliance.

## 1. Physical Entropy Reliance
Silicon-based True Random Number Generators (TRNGs) inside MCU chips are black boxes subject to silent failures, backdoor implants, and physical degradation. SubZero exclusively relies on observable, physical physical entropy (dice, coins) subjected to real-time Markov and Chi-squared audits in the TUI, shifting trust to verifiable physics.

## 2. COTS Hardware Selection
Specialized security operating systems (Tails) and niche hardware wallets function as targeted watering holes. By deploying a radically minimized amnesic OS on ubiquitous Commercial Off-The-Shelf (COTS) x86_64 hardware (e.g., used ThinkPads), we disrupt supply chain targeting while maximizing physical hardware availability (integrated screen, keyboard, battery, and webcam in a single non-descript chassis). Dedicated single-board computers (Raspberry Pi / ARM) are deliberately omitted from official releases; the codebase remains 100% portable Rust, allowing downstream community forks to cross-compile to `aarch64-unknown-linux-musl` or `armv7-unknown-linux-musleabihf` with zero core code modifications.

## 3. Alpine Substrate Hardening
Broad hardware compatibility requires standard distribution kernels with loadable kernel modules. To guarantee mathematical impossibility of exfiltration without sacrificing webcam/USB compatibility, the OS build script deterministicly prunes all `net` and `bluetooth` kernel modules from the Alpine root filesystem prior to deployment. The appliance boots physically deaf and blind to radio interfaces.

## 4. RAM Remanence (Cold Boot) Mitigation
System DRAM can retain sensitive key material for minutes post-shutdown if physically chilled. SubZero overrides standard ACPI power hooks by loading a statically compiled RAM-wiping kernel (`memtest86+`) via `kexec` during the exit sequence, proactively overwriting all memory banks before motherboard power cut.

## 5. Development Automation
I aggressively leverage AI-autonomous agents and tools to write code, design test suites, and execute development tasks for this architecture. The token-efficient prompts used to verify and build this exact configuration are intended for peer audit to guarantee reproducibility.

## 6. Evil Maid / Doctored Media Defense
Physical storage tampering (swapping a genuine boot medium with a backdoored SD/USB drive) is defended via:
- Amnesic `toram` execution: The entire Alpine rootfs is loaded into volatile RAM and unmounted before entropy entry. The user is prompted on Tab 0 to physically disconnect the boot media prior to key derivation.
- Detached multi-key verification: Every release publishes `SHA256SUMS` with detached GPG (`.asc`) and BIP-340 Schnorr Nostr (`.nostrsig` / `.pk1`) signatures.
- Zero persistence: Private keys exist solely in DRAM; when powered off, RAM loses charge with no persistent flash medium attached.

## 7. Zero Custom Cryptography Invariant
SubZero introduces zero novel elliptic curves, zero proprietary cipher schemes, and zero hand-rolled primitive implementations. All cryptographic operations delegate strictly to Bitcoin Core's `libsecp256k1` via `rust-secp256k1` and battle-tested RustCrypto primitives:
- Deterministic signatures: RFC 6979 via `secp256k1::SecretKey::sign_ecdsa`
- Schnorr signatures: BIP-340 via `secp256k1::Keypair::sign_schnorr`
- Key derivation: BIP-32 / BIP-84 / BIP-85 via `bitcoin::bip32`
- Hashing: FIPS 180-4 SHA-256 via `sha2::Sha256` and RFC 2104 HMAC-SHA512
- AEAD: NIST SP 800-38D AES-256-GCM via `aes-gcm`

## 8. Testnet4 Sovereign Sandbox Hard Lock
To eliminate catastrophic mainnet loss during operator drills, rehearsal, and software evaluation, all derivation paths and addresses are cryptographically locked to Bitcoin Testnet4 (`Network::Testnet4` / BIP-94). Any attempt to ingest or derive mainnet keys (`bc1q...`, `m/84'/0'/...`) triggers an immediate unrecoverable error at the validation boundary.
