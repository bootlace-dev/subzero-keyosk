# SubZero Keyosk v2.0 Architecture (`One Pure-Rust Core -> Two Runtimes`)

## 1. Workspace Crate Topology

SubZero v2.0 eliminates dual-language cryptographic drift by compiling both the Bare-Metal Linux Console (`subzero-tui`) and the Single-File Browser Kiosk (`subzero-wasm`) from a single `Cargo.toml` workspace:

* **`crates/subzero-core`**: Pure-Rust cryptographic engine with zero `getrandom` (`BTreeMap`/`BTreeSet` throughout) and zero network dependencies.
  * `entropy.rs`: Tier 1 discrete entropy (`harvest_coins`, `harvest_dice`, `harvest_raw_hex`) and Tier 2 cooperative biomechanical timing (`generate_obstacle_prompt`, coarse/clamped-clock detector, full key+`Backspace` transcript replay, `harvest_freeform_entropy` for `64+` mixed keys/arrows + pointer jitter, conservative `2ms`-binned MCV timing estimator + octave transition rhythm guard `>= 144` bits, and `HMAC-SHA512` conditioning).
  * `presets.rs`: Unified `Preset 0..9` funded Testnet4 rehearsal seeds (`73c5da0a` .. `1efb5645`) and live-ceremony preset blocklist.
  * `descriptor.rs`: Exact Bitcoin Core `BIP-380` `INPUT_CHARSET` + `CHECKSUM_CHARSET` polymod checksum generator and verifier.
  * `keys.rs`: Testnet4 `BIP-84` (`m/84'/1'/0'`, `tb1q`) and `BIP-86` (`m/86'/1'/0'`, `tb1p`) derivation across both receive (`0/*`) and internal change (`1/*`), `SLIP-0132` `vpub`, `CompactSeedQR`, 4-letter punch prefix resolution, account-validated watch-only descriptor importer, Sparrow JSON exporter, and `BIP-85` child derivation (`Index 0..4+`).
  * `psbt.rs`: Two-way `P2WPKH` (`ECDSA`) and `P2TR` (`BIP-340` Schnorr) PSBT inspector and signer with cryptographic `master_xprv` self-change verification (`idx < 1,000`), `SegWit v0` `non_witness_utxo` full-tx requirement (`CVE-2020-14199`), witness-weighted `vsize` fee rate calculation, and mainnet path rejection.
  * `pipek1.rs`: Stateless `BIP-85` application `128002'` (`m/83696968'/128002'/<identity>'/<index>'`) operational key derivation and `105`-byte `PKSG\x01` / ASCII-armored `BIP-340` detached release signing (`bootlace-dev/pipe-k1` wire format) with pinned-pubkey verification reporting.
  * `vault.rs`: `subzero-vault-v2` SIV-committed `AES-256-GCM` estate encryption (`600,000` `PBKDF2-HMAC-SHA256` rounds outputting `64` bytes `enc_key || siv_key`, deterministic `XFP`-bound salt, GCM AAD, bounded `[100k..2M]` decrypt guard, and legacy `v1` read support).
  * `qr_codec.rs`: Coinkite `BBQr` encoder (`encode_bbqr_unicode`) and `AirgapQrAssembler` (with frame deduplication and mid-stream header splice reset), pure-Rust SVG/matrix QR renderer, and Bradley-Roth integral-image adaptive-threshold `rqrr` greyscale frame scanner (mitigating glossy screen glare).
  * `seedfix.rs`: Direct `SHA-256` `128`-candidate 12th `BIP-39` checksum word solver (`< 50us`) and `2,048`-word prefix/index lookup.

* **`crates/subzero-wasm`**: Compiles `subzero-core` to `wasm32-unknown-unknown` with **zero host imports** (`WebAssembly.Module.imports(module) == []`).
  * Exposes an exact-sized `Box<[u8]>` C-ABI (`sz_alloc`, `sz_dealloc`, `sz_invoke`, `sz_decode_qr_luma`, `sz_wipe_memory`).
  * Isolates active mnemonics, BIP-85 children, and unlocked vaults inside zeroizable Rust static state (`ACTIVE_VAULT`, `MASTER_MNEMONIC_BACKUP`, `UNLOCKED_VAULT`) so signing, child pivoting, and vault encryption never pass secret mnemonics across JavaScript GC strings.
  * Every buffer freed through `sz_dealloc` is overwritten via `Zeroize` (`write_volatile`) before returning memory to the WASM linear allocator, and `sz_wipe_memory` sweeps allocator bins (`64..65536` bytes) on `Amnesic Wipe`.
  * `scripts/bundle_html.py` normalizes line endings, Base64-embeds `subzero_wasm.wasm` into `web/subzero-keyosk.template.html` and `web/decrypt.template.html`, and computes exact `sha256-...` Content Security Policy hashes over `<style id="sz-style">` and `<script id="sz-script">` (`0` inline `onclick=` or `style=` attributes).

* **`crates/subzero-tui`**: Compiles `subzero-core` + `ratatui` + `crossterm` to a static `x86_64-unknown-linux-musl` ELF binary (`dist/subzero-x86_64-musl`).
  * `main.rs` & `cli.rs`: Process hardening (`PR_SET_DUMPABLE = 0`, `RLIMIT_CORE = 0`, `mlockall`), `--self-test` KAT runner, headless zero-OS-RNG UNIX CLI subcommands (`derive`, `inspect-psbt`, `sign-psbt`, `vault-seal`, `vault-unseal`, `seedfix`, `descriptor-checksum`) reading secrets only via stdin or `--*-fd`, bracketed paste support, 7-tab console interface, and `Drop`-guaranteed userland `Zeroize` + `\x1b[3J` TTY scrollback purge on exit.
  * `qr_tui.rs`: Font-independent reverse-video ASCII space QR renderer (`ter-v12n.psf.gz` compatible).
  * `storage.rs`: V4L2 (`v4l2-ctl` `YUYV` luma stream -> pure-Rust `decode_qr_luma`) multi-frame `BBQr` optical scanner and VFAT-sanitized, non-clobbering atomic `.tmp` -> `fsync` -> `rename` writer for Partition 2 (`LABEL="SUBZERO_EST"`), embedding `assets/decrypt.html` at compile time so USB recovery media matches `dist/decrypt.html` bit-for-bit.

---

## 2. Deterministic Build Ordering & Path Remapping

`scripts/build_reproducible.sh` runs inside the digest-pinned `Dockerfile.reproducible` image (`messense/rust-musl-cross@sha256:ce75e9174325d4fbb3de85c309e2d7ca29f7500169bc4b5d2c611ff7e86d549a`) in four strict stages:

1. Build `subzero-wasm` (`wasm32-unknown-unknown`, `clang` + `llvm-ar`, `--remap-path-prefix=/work=/subzero`, `--remap-path-prefix=/cargo-cache=/cargo`).
2. Bundle `dist/decrypt.html` and `dist/subzero-keyosk.html`, syncing `assets/decrypt.html` before compiling the TUI.
3. Build `subzero-tui` (`x86_64-unknown-linux-musl`, `+crt-static`, `-Wl,--build-id=none`, `--remap-path-prefix=/work=/subzero`).
4. Run `dist/subzero-x86_64-musl --self-test` and verify `dist/SHA256SUMS` bit-for-bit against committed `SHA256SUMS`.

---

## 3. Bare-Metal UEFI Appliance Boot & Amnesic Scrubbing (`scripts/deploy_appliance.sh`)

`subzero-v2.0.0-testnet4-x86_64.img` is a `256 MB` GPT disk image with two `FAT32` partitions assembled inside digest-pinned `alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc` without `--privileged` or host loop-mounts (`mtools`):

* **Partition 1 (`SUBZERO_ESP`, UEFI `x86_64` ESP)**: Boots Alpine Linux `linux-lts` directly into a RAM-resident `initramfs` (`rdinit=/opt/subzero/launch.sh`) with `slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 iommu=force intel_iommu=on` and all `net`, `bluetooth`, `firewire`, `thunderbolt`, and `sound` kernel modules physically deleted.
* **PID-1 Verification (`launch.sh`)**: Mounts `/proc`, `/sys`, `/dev`, `/tmp`, and `/run`, loads USB HID/storage, VFAT, and UVC camera drivers (`mdev -s`), sets Terminus `ter-v12n` console typography on `/dev/tty1`, executes `/opt/subzero/subzero --self-test` (powering off immediately on failure), and launches `/opt/subzero/subzero`.
* **Exit RAM Scrub**: When the operator triggers `Esc x2` or `Ctrl+W`, `subzero` scrubs its own heap and returns `0` to `launch.sh`, which verifies `/opt/subzero/memtester.sha256` and runs APK-installed `/opt/subzero/memtester-static` single-pass RAM overwrite paired with kernel `init_on_free=1` page zeroing before `poweroff -f`.
* **Partition 2 (`SUBZERO_EST`, VFAT)**: Pre-populated with `decrypt.html`, `README.txt`, and `SHA256SUMS` for encrypted `vault.json` storage.
