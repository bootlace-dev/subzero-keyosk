# SubZero-rs v0.3.0 Release Notes
### Stateless Amnesic Two-Way Optical Airgap Bitcoin Appliance
**Release Tag:** `v0.3.0`  
**Git Commit:** `1709160`  
**Identity:** `bootlace-dev` (`bootlace-dev@users.noreply.github.com`)  
**Nostr Identity:** `npub13nwyhs36ueg7ywgf90khhjaxhtp2wpsm84q4n8c2kxdfrty2p3yqfd8fcn`  
**GPG Key ID:** `F18173E554644BB59018AE50F6E96FADCA2E8E0F`  

---

## 1. Executive Summary: "COTS Over Honeypots"

Dedicated hardware wallets and specialized security devices have become high-liability operational security hazards:
- **E-Commerce Supply Chain Leaks:** Breaches of customer databases (Ledger, Trezor, Shopify) permanently link real-world home addresses, names, and phone numbers to Bitcoin ownership, painting high-visibility targets for physical coercion and home invasions.
- **Physical Interdiction & Targeted Watermarks:** Custom hardware kits (e.g. Raspberry Pi Zero assemblies, custom acrylic enclosures, monocle displays) immediately flag baggage at international borders and customs inspections.
- **Microcontroller PRNG Opacity:** Microcontroller hardware true random number generators (TRNGs) and proprietary secure element black-boxes cannot be visually audited for backdoors, silent entropy failure, or physical aging.

**SubZero inverts this paradigm through Commercial Off-The-Shelf (COTS) ubiquity:**
Any generic, used x86_64 laptop (purchased for $20–$40 in cash at a thrift store or secondhand market—e.g. Lenovo ThinkPad, Dell Chromebook, Acer) functions as an enterprise-grade cold-storage signing appliance. In transit or storage, a commodity laptop is completely unremarkable. When booted from an SD card, it transforms into an amnesic, airgapped Bitcoin terminal running 100% in volatile RAM with zero network drivers loaded.

---

## 2. Why SubZero vs. Closest Historical Analogues

| Dimension | SeedSigner (RPi Zero) | Krux (K210 RISC-V) | Dedicated HW (Coldcard / Jade / Passport) | Cold Laptop / Tails OS | **SubZero-rs v0.3.0** |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Hardware Supply Chain** | Specialized RPi Zero + Waveshare LCD Hat + camera module; online paper trail. | Specialized Chinese K210 AI board; vendor trail. | Dedicated commercial crypto device; customer database leaks (Shopify/Ledger). | Standard laptop, but general-purpose OS. | **100% COTS:** Any commodity x86_64 laptop purchased for cash. Zero crypto association. |
| **Visual & Keyboard Surface** | 1.3"–2.0" 240x240 display, tiny 5-way joystick. High friction on seed entry. | Tiny touchscreen or 3 capacitive buttons. | Keypad or scroll-wheel on 1"–2.8" screen. | Full GUI display and keyboard, but heavy attack surface. | **Full Ergonomic TUI:** Full keyboard, 14" screen, Terminus 12px font (45–50 rows), Miller's Law chunking. |
| **Entropy Auditing** | Dice rolls / camera hash. No real-time statistical tests. | Dice / camera. No statistical bounds enforcement. | Black-box TRNG in Secure Element; user cannot audit raw entropy bits. | Software PRNG via `/dev/urandom` / OS entropy pool. | **Physical Entropy + Audit:** 128-bit coins, 50-roll dice, raw hex, jitter; real-time Markov & Chi-squared rejection. |
| **Kernel / Network Attack Surface** | Microcontroller Linux or bare metal; minimal. | MicroPython runtime on K210. | Microcontroller firmware with proprietary SE blobs. | Full general OS (4GB+ ISO); Wi-Fi, BT, Ethernet drivers loaded. | **Substrate Hardened:** Ephemeral Alpine Linux with `net` and `bluetooth` kernel modules physically deleted. |
| **RAM Remanence Mitigation** | Power pull (DRAM capacitor bleed). | Power pull (0.5MB internal SRAM). | Power pull. | Standard shutdown/reboot leaves DRAM pages readable for minutes. | **Active `kexec` Wiper:** `[Q][Q]` executes `kexec` into `memtest86+` v8.10, systematically zeroing all RAM banks. |
| **PSBT Inspection Depth** | Basic summary (amount, fee, outputs). | Basic summary. | Standard summary; limited derivation path audit. | Full Sparrow/Electrum GUI, but requires active OS and display stack. | **5-Section Deep Ledger:** Multi-level gap limits, offline address reuse, RFC 6979 nonce badge, USD conversion. |
| **Deterministic Builds** | Yes (Buildroot). | Yes (Docker). | Vendor reproducible builds. | Debian reproducible builds. | **100% Byte-for-Byte:** Static musl binary via Docker with fixed `SOURCE_DATE_EPOCH` and path remapping. |

---

## 3. Major Features in v0.3.0

### A. Stateless Two-Way Optical Airgap (Tab 14: `PsbtSigner`)
- **Native Webcam Ingestion:** Auto-detects laptop camera (`/dev/video*`) via `zbarcam` runtime, reading PSBT QR codes from Sparrow, Nunchuk, Specter, or BlueWallet without physical cables or USB mounts.
- **Multiframe BBQR Reassembly:** Reassembles animated high-density BBQR frames in real-time with frame-progress indicators.
- **Animated BBQR Export:** Upon signing, displays high-contrast animated BBQR on the laptop screen for the coordinator wallet to scan back.
- **Optical Scan Hygiene:** Clean buffer clearing (`[N]` for Next, `[X]` for Clear) prevents cross-transaction confusion on screen.

### B. 5-Section Deep Transaction Ledger & Footgun Prevention
1. **Transaction Overview & Metrics:** Total inputs, total outputs, miner fee, fee rate (sat/vB), fee percentage of input, sequence/RBF status, and locktime.
2. **Offline USD Fiat Estimator (`[P]`):** Press `[P]` anytime to enter the current BTC spot price (e.g. `$60,000`). Immediately computes estimated fiat conversions across all inputs, outputs, and fees.
3. **Destination Outputs Ledger:** Categorizes all outputs into `[INTERNAL CHANGE]`, `[EXTERNAL RECIPIENT]`, and `[SELF-SEND]` with 4-character Miller's Law visual chunking.
4. **Granular Address Gap Limit Auditing:**
   - Indices $1..20$: Displays `[GAP CAUTION]` to alert user to skipped change indices.
   - Indices $>20$: Hard-flags `[CRITICAL GAP EXCEEDED]` warning that standard BIP-44 recovery scans will miss funds.
5. **Offline Address Reuse Detection:**
   - Flags intra-transaction input-to-output address reuse.
   - Flags duplicate recipient outputs within the same transaction.
   - Tracks external recipient addresses in volatile RAM across the signing session to detect address reuse across multiple sequential transactions.
6. **Anti-Kleptography Verification:** Displays explicit RFC 6979 deterministic nonce badge, mathematically certifying that private keys cannot be leaked through biased signature nonces.
7. **Derivation Path Coin Type Enforcement:** Inspects derivation position 1 (`coin_type`) on all inputs and outputs; hard-blocks any transaction containing Mainnet coin type (`m/84'/0'/...`) on the Testnet4 appliance.

### C. Multi-Vector Physical Entropy Intake Engine (Tab 1: `MasterSeed`)
- **[1] Physical Coin Flips:** 128 binary flips (`0` = Heads, `1` = Tails) with real-time Markov transition matrix audit, Chi-squared uniformity test, and repetitive pattern blocking.
- **[2] Physical Dice Rolls:** 50+ six-sided rolls (`1`–`6`) arranged in a 6x10 visual grid with live uniformity auditing.
- **[3] Raw Hexadecimal:** 32 bytes (64 hex characters) formatted in an 8-byte hex editor view.
- **[4] CompactSeedQR Digits:** 48 decimal digits (4-digit BIP-39 word indices).
- **[5] 12 BIP-39 English Words:** Full words or 4-letter punch codes with autocomplete.
- **[6] Watch-Only Descriptor:** Ingestion of `wpkh(tpub...#checksum)` for airgapped audit workflows without private keys.
- **[7] Keystroke Jitter Harvester:** 32 nanosecond keyboard timing interval samples utilizing human physiological variability with zero reliance on hardware PRNGs.
- **[8] Deterministic Test Vectors:** BIP-39 canonical vectors (All-Zeros, Satoshi Genesis, Hal Finney First TX).

### D. Substrate Hardening & Anti-Cold-Boot Remanence
- **Stripped Kernel Drivers:** OS build pipeline (`scripts/deploy_appliance.sh`) removes all `kernel/net`, `drivers/net`, and `bluetooth` kernel modules from the Alpine root squashfs image.
- **Active Memory Wiper on Exit:** Pressing `[Q][Q]` triggers `kexec` directly into a statically packaged `memtest86+` v8.10 kernel, systematically writing bit patterns and zeros across all physical DRAM channels before powering off the motherboard.
- **High-Density Typography:** Bundles Terminus 12px font (`ter-v12n`), providing 45–50 text rows and 113+ horizontal columns on standard 768p panels for full descriptor and QR display without line wrapping.

---

## 4. Deterministic Build Verification

This release is 100% reproducible. To verify byte-for-byte SHA-256 equivalence from source:

```bash
git clone https://github.com/bootlace-dev/subzero-keyosk.git
cd subzero-keyosk
git checkout 1709160

docker run --rm --user 0:0 \
  -v "$(pwd)":/home/rust/src \
  -e SOURCE_DATE_EPOCH=1700000000 \
  -e TZ=UTC \
  -e RUSTFLAGS="--remap-path-prefix /home/rust/src=/subzero" \
  -e SUBZERO_GIT_COMMIT="1709160" \
  messense/rust-musl-cross:x86_64-musl \
  bash -c "cd /home/rust/src && cargo build --release"

sha256sum target/x86_64-unknown-linux-musl/release/subzero
```

**Expected Binary Checksum:**
```
c6ff634f5eba32f3db7d3a7f7bfb472b4cc4bcba3dc01b0000a0fba08ac8d9b7  target/x86_64-unknown-linux-musl/release/subzero
```

**Alpine Appliance Manifest Checksums:**
```
890de41b7cd760b3dc81ee70030321738cd0273b21206bc7b7178dd7b2efc5c4  rootfs.squashfs
b29ff73145a8ea1b4838c24947e46194f415a0f416a889a74019e96a95c84400  EFI/BOOT/BOOTX64.EFI
e6f94d01b19a0033dabb6caaba42f2c3a6f969ae282e6c4a7c9e854e4a6941b2  EFI/BOOT/grub.cfg
2ca6b25e67f16bea1cccd9695dc585d4547ce0f9414c2e3c1a5cfd247f7e2a1a  startup.nsh
```

---

## 5. Development Automation & Authorship Disclosure

In compliance with project transparency invariants:
- **AI Autonomy:** The author aggressively leverages AI-autonomous agents and pairing tools to write code, design test suites, evaluate statistical properties, and execute development tasks for this architecture.
- **Zero-Knowledge Authorship Proof:** To mathematically prove authorship of this release without exposing personal identifying information, the following SHA-256 commitment is embedded into the project tree:
  - **Commitment Hash:** `69e9c8e1a1bdfd94d30623d38ee5d0a6c081e649060037a544be82688846c4f0`
  - **Pre-image Scheme:** `SHA256("SubZero-rs authored by bootlace-dev on 2026-09-12 with secret salt [REDACTED]")`

---

## 6. Cryptographic Signatures

### PGP Detached Signature
Signed with dedicated pseudonymous GPG release key:
`F18173E554644BB59018AE50F6E96FADCA2E8E0F` (`bootlace-dev <bootlace-dev@users.noreply.github.com>`).
Detached signature file: `docs/RELEASE_NOTES_v0.3.0.md.asc`

### Nostr BIP-340 Schnorr Signature
Signed with dedicated pseudonymous Nostr key:
`npub13nwyhs36ueg7ywgf90khhjaxhtp2wpsm84q4n8c2kxdfrty2p3yqfd8fcn` (`8cdc4bc23ae651e239092bed7bcba6bac2a7061b3d41599f0ab19a91ac8a0c48`).
Signature file: `docs/RELEASE_NOTES_v0.3.0.md.nostrsig`
