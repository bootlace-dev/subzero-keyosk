# SubZero-rs v0.3.0 Release Notes
### Stateless Amnesic Two-Way Optical Airgap Bitcoin Appliance
**Release Tag:** `v0.3.0`  
**Git Commit:** `1709160`  
**Identity:** `bootlace-dev` (`bootlace-dev@users.noreply.github.com`)  
**Nostr Identity:** `npub13nwyhs36ueg7ywgf90khhjaxhtp2wpsm84q4n8c2kxdfrty2p3yqfd8fcn`  
**GPG Key ID:** `F18173E554644BB59018AE50F6E96FADCA2E8E0F`  

---

## 1. Design Philosophy: The Commodity Hardware (COTS) Advantage

SubZero is engineered around a simple premise: **enterprise-grade, airgapped Bitcoin self-custody should run on ubiquitous, generic hardware that users already own or can easily acquire locally.**

By repurposing standard off-the-shelf x86_64 laptops (such as surplus Lenovo ThinkPads, Dell Chromebooks, or Acer laptops), SubZero delivers key structural advantages:

- **Universal Hardware Availability:** Millions of reliable commodity laptops exist worldwide. SubZero allows anyone to stand up an airgapped cold vault immediately using standard USB or SD boot media, without waiting for or relying on specialized hardware shipments.
- **Natural Hardware Discretion:** A standard commodity laptop is entirely generic and non-descript. It carries no outward markers, branding, or indicators associated with cryptocurrency storage.
- **Human-Scale Ergonomics:** Real-world custody security fundamentally depends on human verification. Full-size physical keyboards and standard laptop displays eliminate the cognitive fatigue and input friction often encountered when managing complex cryptographic material on miniature screens.
- **Physical Amnesia:** Running as a purely ephemeral live system entirely in volatile memory (`toram`), SubZero leaves zero persistent data on disk, converting commodity laptops into dedicated, single-purpose signing appliances for the duration of a session.

---

## 2. Core Architectural Benefits of SubZero

### A. Ergonomic Visual Space & Miller's Law Chunking
- **High-Density Typography:** Bundles the Terminus 12-pixel font (`ter-v12n`, 6x12 pixel cell), providing 45–50 text rows and 113+ columns on standard laptop screens.
- **Cognitive Verification:** Full addresses, derivation paths, and entropy streams are formatted in 4-character and 5-character blocks (Miller's Law) for easy, error-free visual cross-checking against paper records.
- **Full Tactile Keyboard Input:** Fast, fluid, and accurate entry of 12-word seeds, 4-letter punch codes, 128 binary coin flips, or 50+ dice rolls without joystick navigation or touchscreen inaccuracy.

### B. Observable Physical Entropy with Real-Time Mathematical Audits
- **Beyond Black-Box Randomness:** Allows users to supply verifiable physical entropy directly via coins, dice, raw hex, or nanosecond keyboard timing jitter.
- **Cryptographic Boundary Audits:** Real-time Markov transition matrix analysis and Chi-squared uniformity tests actively verify incoming entropy streams, blocking biased, skewed, or repetitive inputs before any key derivation can occur.

### C. Stateless Two-Way Optical Airgap Loop
- **Webcam Ingestion (`zbarcam`):** Auto-detects integrated laptop webcams across `/dev/video*`, ingesting PSBT QR codes directly from Sparrow, Nunchuk, Specter, or BlueWallet without physical data cables.
- **Continuous BBQR Reassembly:** Seamlessly reconstructs multiframe animated BBQRs with real-time frame-tracking metrics.
- **Animated BBQR Export:** Displays high-contrast animated BBQR on the laptop screen for the software coordinator to scan back, completing a 100% cable-free signing loop.

### D. Comprehensive 5-Section Transaction Ledger
- **Transaction Metrics:** Explicit overview of total inputs, total outputs, miner fees, fee rate (sat/vB), fee percentage of input, sequence/RBF status, and locktime.
- **Offline USD Fiat Estimator (`[P]`):** Press `[P]` anytime to input a reference BTC spot price (e.g. `$60,000`), calculating estimated fiat values for all inputs, outputs, and miner fees.
- **Destination Categorization:** Output ledger clearly differentiates `[INTERNAL CHANGE]`, `[EXTERNAL RECIPIENT]`, and `[SELF-SEND]` destinations.
- **Granular Gap Limit Auditing:** Warns on change derivation indices $1..20$ (`[GAP CAUTION]`) and alerts on indices $>20$ (`[CRITICAL GAP EXCEEDED]`) to prevent fund invisibility during standard BIP-44 wallet recoveries.
- **Offline Address Reuse Interception:** Detects intra-transaction input-to-output address reuse, duplicate recipient outputs in a single transaction, and tracks external recipients in volatile RAM across sequential transactions during a session.
- **Anti-Kleptography Verification:** Prominently badges RFC 6979 deterministic nonce enforcement, verifying that private keys cannot be exfiltrated via signature nonces.
- **Derivation Path Coin Type Guard:** Enforces strict derivation path network alignment (hard-blocks Mainnet `m/84'/0'/...` coin types on Testnet4 appliances).

### E. Substrate Hardening & Active DRAM Remanence Protection
- **Stripped Network Drivers:** OS build pipeline removes all `kernel/net`, `drivers/net`, and `bluetooth` kernel modules from the Alpine squashfs image, ensuring the kernel boots physically unable to load networking stacks.
- **Active Memory Scrubbing on Exit:** Pressing `[Q][Q]` triggers `kexec` directly into `memtest86+` v8.10, systematically writing bit patterns and zeros across all physical DRAM channels before cutting motherboard power, mitigating cold-boot memory remanence.

---

## 3. Supported Intake Vectors in v0.3.0

1. **Physical Coin Flips:** 128 binary flips (`0` = Heads, `1` = Tails) with real-time statistical audits.
2. **Physical Dice Rolls:** 50+ six-sided rolls (`1`–`6`) formatted in a 6x10 visual grid.
3. **Raw Hexadecimal:** 32 bytes (64 hex characters) formatted in an 8-byte hex editor view.
4. **CompactSeedQR Digits:** 48 decimal digits (4-digit BIP-39 word indices).
5. **12 BIP-39 English Words:** Full word entry or 4-letter punch codes with autocomplete.
6. **Watch-Only Descriptor:** Ingestion of `wpkh(tpub...#checksum)` for airgapped audit workflows.
7. **Keystroke Jitter Harvester:** 32 nanosecond keyboard interval samples utilizing human physiological variability.
8. **Deterministic Test Vectors:** BIP-39 canonical vectors (All-Zeros, Satoshi Genesis, Hal Finney First TX).

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
