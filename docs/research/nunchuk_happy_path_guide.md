# Subzero Sovereign Vault: End-to-End Happy Path Guide

---

## Phase 0: Hardware Procurement, App Verification & Flashing

### 1. Hardware Procurement (Cheap Commodity Media)
- **Target Media**: 2-pack or 5-pack of standard 32GB/64GB USB 3.0 flash drives (e.g. SanDisk Ultra Flair, Kingston DataTraveler) or standard Full-Size SD / MicroSD cards (>= 512MB).
- *Purchase Rule*: Avoid boutique "hardware wallet" brands. Use generic, widely available commodity storage from major retail (Amazon, Micro Center, Best Buy).

---

### 2. Verified Mobile App Installation (Avoid Fake Impersonators)

To prevent phishing or fake wallet clones, verify the official store metadata before installing:

* **Android (Google Play Store)**:
  - **App Name**: `Nunchuk Bitcoin Wallet`
  - **Developer / Vendor**: `Nunchuk Inc.`
  - **Package ID**: `io.nunchuk.android`
  - **Stats**: 4.x★, >750 reviews, >10K+ downloads.
  - **Official URL**: `https://play.google.com/store/apps/details?id=io.nunchuk.android`
* **iOS (Apple App Store)**:
  - **App Name**: `Nunchuk Bitcoin Wallet`
  - **Seller / Vendor**: `Nunchuk Inc.`
  - **Apple App ID**: `1588665033`
  - **Official URL**: `https://apps.apple.com/app/nunchuk-bitcoin-wallet/id1588665033`

---

### 3. Download & Flash Boot Media (Online Computer)

1. **Download the Verified Release Image**:
   - Repository Releases: `https://github.com/bootlace-dev/subzero-keyosk/releases`
   - Download `subzero-vault-pc.img` (421MB) and `SHA256SUMS.asc`.

2. **Verify Cryptographic SHA-256 Checksum**:
   ```bash
   sha256sum subzero-vault-pc.img
   ```
   *Verify the output matches the published release hash.*

3. **Insert Target USB Drive or SD Card (>= 512MB)**:
   - Identify device path (e.g. `/dev/sdb` or `/dev/sdc`):
     ```bash
     lsblk
     ```
   *Caution: Double check device letter to avoid overwriting your system disk.*

4. **Flash the Boot Image**:
   - **Linux / macOS (Terminal)**:
     ```bash
     sudo dd if=subzero-vault-pc.img of=/dev/sdX bs=4M status=progress conv=fsync
     ```
   - **Windows / Cross-Platform**: Use Rufus or Raspberry Pi Imager to write raw image.

5. **Flush Buffers & Safely Eject**:
   ```bash
   sync
   sudo eject /dev/sdX
   ```

---

## Phase 1: Boot & Physical Entropy Generation (Airgapped Laptop)

1. **Insert Boot USB/SD & Power On**:
   - Insert flashed card into target commodity laptop/PC (Dell, ThinkPad, etc.) and power on.
   - Press boot menu key (`F12` on Dell/Lenovo, `F8`/`F11` on others) and select the UEFI USB/SD drive.
   - Select `1. SubZero Keyosk`.
   - Watch the visual progress dots as the 322MB system loads into volatile RAM (`toram`).
   - *Physical Isolation Guarantee*: The boot media is automatically unmounted before the UI launches.
2. **Launch Physical Entropy Generator**:
   - At the main menu, press `[1]` to select **Sovereign Physical Entropy & Cold Treasury Generator**.
3. **Entropy Entry**:
   - Flip 128 physical coins (e.g. `0` for Tails, `1` for Heads) or roll dice (`1`–`6`).
   - For fast drill testing, you can type `test0` through `test9`.
   - Press `[ENTER]` once 128+ bits are reached.

---

## Phase 2: Carousel Review & USB Estate Export

1. **Page 1/9 (Master Root Seed)**:
   - Transcribe your 12 master words to physical paper/steel. Keep strictly private.
2. **Page 2/9 (Decoupled Estate Passphrase — Index 0)**:
   - Transcribe the 12-word passphrase.
   - *Storage Location*: Place into your Bitwarden vault and Dead-Man's Switch configuration (`~/.dms_heartbeat` on your GCP VM).
3. **Page 3/9 (Heir Child Treasuries — Indices 1 to 5)**:
   - Transcribe individual 12-word cold seeds for Heirs 1 through 5 if distributing disposable spending wallets.
4. **Page 7/9 (Automatic USB Batch Write & Single-Drive In-Place Conversion)**:
   - **Option A (Separate Target USB)**: Insert any spare USB flash drive or SD card into the laptop and press **`[W]`**.
   - **Option B (Single-Drive Burn-After-Boot)**: Simply leave the **same boot USB/SD card** inserted and press **`[W]`**. Because the OS runs 100% inside RAM (`toram`), the kiosk safely formats the boot media to clean FAT32, destroying the Linux bootloader and converting the single card into an unbootable, encrypted inheritance token (`vault.json`, `decrypt.html`, `README.txt`, `SHA256SUMS`).
5. **Page 9/9 (About & Build Provenance)**:
   - Verify deterministic build metadata, version (`v0.2.0-vault-testnet4`), and memory footprint.

---

## Phase 3: Mobile Watch-Only Verification (Nunchuk v2.8.4+ Android/iOS)

1. **Launch Nunchuk & Switch to Testnet Server**:
   - Open **Nunchuk** on your phone.
   - When prompted for an email address, scroll to the bottom and tap **"Continue as guest"**.
   - At the bottom navigation bar, tap **Profile** (bottom right icon).
   - Tap **Network settings**.
   - Tap the **Testnet server** radio button (`testnet.nunchuk.io:50001`).
   - Tap **Save network settings**.
   - In the *"App restart required"* popup, tap **Restart**.
   - Upon relaunch, tap **"Continue as guest"** again. You are now running on Bitcoin Testnet!

2. **Import Watch-Only Output Descriptor**:
   - From the Nunchuk **Home** tab (or **Wallets** tab):
     - Tap **"Recover existing wallet"** (down-arrow card at bottom of Home screen).
   - In the slide-up menu, tap **"Recover via QR code"** (first option).
   - If prompted for camera permission, tap *"While using the app"*.
   - Advance your Subzero laptop screen to **Page 4/9 (BIP-380 Output Descriptor QR)**.
   - Align the phone camera viewfinder with the QR code on the laptop screen.
   - In the **Wallet config** screen:
     - Verify Single-sig / Native segwit, XFP master fingerprint (`3F635A63`), and path (`m/84h/1h/0h`).
     - Tap the pencil icon to rename the wallet (e.g. `test5zoo` or `Subzero Vault Drill`).
     - Tap the checkmark to save.

3. **Verify First Receive Address**:
   - On your recovered wallet dashboard, tap **Receive** (middle circle button).
   - Compare the on-screen `tb1q...` address with **Page 6/9 (Testnet4 Receive Addresses)** on the Subzero laptop:
     - Verify it matches Receive Address #0 character-for-character.

4. **Fund via Live Testnet4 Faucet**:
   - Navigate to the **Testnet4 Faucet Hub**:
     - `https://testnet4.dev` (directory of active community faucets)
   - Working 1-Click Faucets:
     - **Coinfaucet EU**: `https://coinfaucet.eu/en/btc-testnet4/` (~0.0022 BTC, no login, instant send)
     - **Testnet4 Dev Direct**: `https://faucet.testnet4.dev` (complete hCaptcha and click *Get Testnet Bitcoins*)
   - Paste your `tb1q...` address and submit.
   - Return to Nunchuk: Watch the incoming transaction pop up live and increment your confirmed unspent balance!

---

## Phase 4: Amnesic RAM Zeroization & Power Off

1. On the airgapped laptop, press **`[ESC]`** to return to the menu.
2. Select **`[Q]`** (or press `[Q]` directly on the carousel footer).
3. All master seeds, child keys, framebuffers, and volatile memory allocations are zeroized in RAM and the system powers off.

---

## Phase 5: Heir Recovery Simulation (Zero-Dependency Browser Applet)

1. Take the USB drive written in Phase 2 and plug it into any standard computer (Mac, Linux, Chromebook).
2. Double-click **`decrypt.html`** in Chrome, Firefox, Safari, or Brave (100% offline; works with WiFi disconnected).
3. Drag and drop **`vault.json`** into the browser window.
4. Enter the 12-word Decoupled Estate Passphrase (from Phase 2, Page 2).
5. Click **Decrypt Estate Vault**:
   - Browser WebCrypto unlocks the payload locally in milliseconds.
   - Master root seed, BIP-380 output descriptor, and all 5 heir cold treasuries are instantly revealed.
