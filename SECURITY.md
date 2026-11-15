# Security Model, Audit Fixes & Verification Log (`SubZero v2.0`)

## 1. Threat Model & Trust Boundaries

SubZero Keyosk v2.0 is a **Bitcoin Testnet4 (`BIP-94`)** airgapped key ceremony, PSBT signing, and estate-vault rehearsal system built around one pure-Rust cryptographic core (`crates/subzero-core`).

### In-Scope Protections
* **Zero OS-RNG Reliance**: Neither `subzero-core`, `subzero-tui`, nor `subzero-wasm` imports `getrandom`, `/dev/urandom`, `HashMap` `RandomState`, or `window.crypto.getRandomValues()`. Verified via `strace -e trace=getrandom,socket`: `0` calls at runtime. All secret keys derive strictly from user-supplied physical symbols (**Tier 1**) or unclamped monotonic inter-keystroke intervals (**Tier 2**).
* **Zero Network Stack**: `subzero-core` and `subzero-wasm` contain zero socket/HTTP dependencies (`WebAssembly.Module.imports(wasm) == []`), `subzero-keyosk.html` and `decrypt.html` enforce `default-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'`, and `scripts/deploy_appliance.sh` strips `kernel/net`, `drivers/net`, `bluetooth`, `firewire`, and `thunderbolt` modules from the bare-metal initramfs.
* **WASM Secret Privilege Separation**: Browser JavaScript strings are immutable and managed by a non-deterministic garbage collector. `subzero-wasm` isolates active mnemonics, BIP-85 child seeds, and unlocked estate vaults inside zeroizable Rust linear memory (`ACTIVE_VAULT` / `UNLOCKED_VAULT`) so PSBT signing, `pipe-k1` signing, child-vault pivoting, and `vault.json` encryption run without serializing mnemonics through JS strings unless the operator explicitly clicks `Reveal`.
* **Cryptographic Self-Change & `non_witness_utxo` Verification (`[C-02]` + `CVE-2020-14199` Defenses)**: When inspecting or signing a PSBT, SubZero never trusts unsigned `bip32_derivation` or `tap_key_origins` metadata to label an output as `"change"`. It independently derives the expected `script_pubkey` from its own in-memory `master_xprv` along `m/84'/1'/0'/<0|1>/<idx>` or `m/86'/1'/0'/<0|1>/<idx>` (`idx < 1,000`), requires a TXID-verified `non_witness_utxo` full previous transaction on all `SegWit v0` (`P2WPKH`) inputs, and invalidates UI signing approval immediately if the PSBT input buffer is edited after inspection.
* **SIV-Committed Deterministic Estate Encryption (`subzero-vault-v2`)**: Derives `64` bytes of keying material from `600,000` `PBKDF2-HMAC-SHA256` iterations over a passphrase-independent salt (`SHA256("subzero:vault:v2:salt:" || master_xfp)[0..16]`), splitting `enc_key = okm[0..32]` and `siv_key = okm[32..64]`. Computes the `96`-bit `AES-256-GCM` IV as `HMAC-SHA256(siv_key, canonical_plaintext)[0..12]` with AAD `subzero-vault-v2|AES-256-GCM|PBKDF2-HMAC-SHA256|<iterations>`, so re-sealing an updated vault under the same decoupled passphrase never reuses a `(Key, Nonce)` pair.

### Explicit Non-Goals & Operator Responsibilities
* **Testnet4 Only**: v2.0 is intentionally locked to Testnet4 (`tb1q` / `tb1p`). Do not modify version bytes for mainnet production storage without an independent formal cryptographic audit.
* **Tier 2 Clock Trust vs Tier 1 Physical Reproducibility**: Tier 2 keystroke timing defends a cooperative human user against rhythm bias and clamped browser timers (`Tor Browser` `100ms` / Firefox `resistFingerprinting` `16.67ms` / `2ms`..`10ms` quantized timers), but relies on an honest monotonic host clock (`Instant::now()` / `performance.now()`). For high-assurance ceremonies requiring independent 2nd-device seed verification with `0%` host clock trust, use **Tier 1** (`128+` coin flips, `60` casino dice rolls, or a washed + 7x riffle-shuffled `52-card` deck).
* **COTS Hardware & Browser GC Limits**: General-purpose `x86_64` PCs have firmware (BIOS/ME/PSP) and lack potted secure elements. On browser HTML builds, clicking `Reveal` renders secret words into DOM text nodes managed by browser GC; always close the browser tab completely after `Amnesic Wipe`.

---

## 2. Summary of v2.0 Clean-Slate Security Remediations

Earlier pre-v2 prototypes maintained separate Rust and TypeScript cryptographic implementations that drifted out of sync. In v2.0, the entire TypeScript/npm crypto layer and unverified binary blobs were deleted and replaced by `crates/subzero-core` (`Rust -> musl + WASM`), resolving the following classes of defects:

| ID | Pre-v2 / Audit Issue | v2.0 Resolution in Unified Rust Workspace |
| :--- | :--- | :--- |
| **`C-01`** | Browser UI called `crypto.getRandomValues()` for prompt generation, left `checkTimerPrecision()` unwired, and ran Markov/Chi-squared tests *after* `SHA-256`. | Replaced with `subzero_core::entropy`: zero-OS-RNG deterministic obstacle course (`generate_obstacle_prompt`), mandatory red-typo `Backspace` lock, full key+`Backspace` transcript replay, pre-hash Markov/Chi-squared/90B estimators, affine step concentration checks against faro/pile-deal decks, and coarse/clamped-timer hard block. |
| **`C-02`** | PSBT inspector trusted unverified `bip32_derivation` fingerprint tags on change outputs and allowed `SegWit v0` signing without `non_witness_utxo`. | `subzero_core::psbt` re-derives expected `P2WPKH` and `P2TR` output scripts directly from `master_xprv`, requires TXID-verified `non_witness_utxo` on `P2WPKH` inputs (`CVE-2020-14199`), checks `vout` bounds, and locks UI signing against post-inspection input edits. |
| **`C-03`** | Bare-metal TUI invoked `/sbin/poweroff -f` directly on exit, bypassing exit RAM scrubbing, and `deploy_appliance.sh` referenced missing `memtest86+` / unverified `zbarcam` blobs. | `subzero-tui` scrubs `AppState` (`Zeroize`), clears TTY1 scrollback (`\x1b[3J`), and returns `0` cleanly to PID-1 `launch.sh`, which verifies APK-installed `memtester-static` (`memtester.sha256`) and overwrites free RAM alongside `init_on_free=1` before poweroff. Optical scanning uses APK-verified `v4l2-ctl` + pure-Rust `rqrr`. |
| **`H-01`** | `deploy_appliance.sh` used an unquoted `EOF` heredoc and `--privileged` loop assumptions. | Digest-pinned `alpine@sha256:d9e853...` unprivileged image builder using single-quoted `'EOF'` blocks, `parted` + `mtools`, explicit `mkinitfs` USB/VFAT/UVC features, and stripped `net`/`bluetooth`/`thunderbolt`/`firewire` trees. |
| **`H-02`** | Legacy TypeScript descriptor exporter appended raw `SHA-256` hex instead of Bitcoin Core `BIP-380` polymod checksums, and used custom `"1/N:"` QR strings instead of Coinkite `BBQr`. | Both TUI and WASM HTML call `subzero_core::descriptor::attach_descriptor_checksum` (verified against official `BIP-380` vectors) and `bbqr 0.6` split/join codecs with header consistency and splice guards. |
| **`H-03`** | `decrypt.html` relied on `window.crypto.subtle` (restricted on `file://` origins), used `210,000` PBKDF2 rounds in JS vs `600,000` in Rust, and mixed passphrase into salt. | Both `subzero-keyosk.html` and `decrypt.html` run pure-Rust `subzero_core::vault` (`600,000` PBKDF2 rounds, `64`-byte split `enc_key || siv_key`, `XFP`-bound salt, and GCM AAD) inside offline zero-import WASM on `file://`. |
| **`M-01`** | Partition 2 backup filenames used ISO-8601 colons (`:`), failing on `FAT32`/`VFAT` USB drives, and switching wallets could retain prior session passphrase state. | `storage::sanitize_vfat_stamp` + non-clobbering `atomic_write_vfat` (`.tmp` -> `fsync` -> `rename` + `SHA256SUMS`), exact `LABEL="SUBZERO_EST"` matching, and complete cross-wallet state reset in both TUI and HTML. |

---

## 3. Verification Provenance (`Prototype -> Cold Breakers -> Regression Suite`)

Rather than fabricating retroactive test-first commit theatre, SubZero v2.0 follows a transparent three-stage verification workflow:

1. **Specification-Driven Pure-Rust Implementation**: Implemented `subzero-core`, `subzero-tui`, and `subzero-wasm` with unit and integration tests covering `BIP-380` vectors, all `10` Testnet4 presets (plus live-ceremony preset blocking), Tier 1 & Tier 2 entropy boundary rejections (including faro shuffles and pile deals), `P2WPKH`/`P2TR` PSBT signing + `CVE-2020-14199` + change-spoof blocking, `pipe-k1` wire vectors, and SIV vault round-trips (`cargo test --workspace` + `subzero --self-test`).
2. **Headless Browser `file://`, Appliance Image & Clean-Room Build Verification**: Automated headless Chromium `file://` E2E verification over `dist/subzero-keyosk.html` and `dist/decrypt.html` (`0` CSP/console errors), unprivileged `deploy_appliance.sh` UEFI GPT image verification, `strace` zero-`getrandom`/zero-`socket` verification, and clean-room Docker builds across separate host directories proving identical `SHA256SUMS`.
3. **Dual Cross-Vendor Cold-Context Adversarial Review**: Audited by independent zero-context adversarial reviewers (`Gemini` + `Claude Opus`) running live shell, WASM ABI, entropy, PSBT, and appliance breakage probes against the repository and documentation prior to release signing, with 100% of findings remediated and covered by regression tests.

---

## 4. Vulnerability Reporting

Report security issues via GitHub Issues on `bootlace-dev/subzero-keyosk` or encrypted to the repository OpenPGP key (`bootlace-dev-pgp.asc`, fingerprint `F181 73E5 5464 4BB5 9018  AE50 F6E9 6FAD CA2E 8E0F`).
