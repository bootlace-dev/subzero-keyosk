# Master Specification: Sovereign Family Inheritance Appliance & Recovery Protocol

---

## 1. The Real-World Hardware Baseline

### The Flaw in Modern Personal Laptops
Modern consumer computers are hostile to sovereign offline inheritance:

- **Apple Silicon Macs (M1/M2/M3/M4)**: Enforce proprietary Apple `iBoot` firmware and APFS security policies. They **cannot and will not boot standard external x86 Linux USBs**.
- **Windows 11 Laptops**: Enforce Microsoft Secure Boot / SBAT revocations and TPM 2.0 BitLocker measurement locks, triggering 48-digit recovery key lockouts on boot tampering.
- **Daily-Driver Operating Systems**: Infostealers and resident malware record keystrokes and clipboard data into persistent local caches (`%TEMP%`, `/var/tmp/`), exfiltrating decrypted master seeds the moment Wi-Fi is reconnected.

---

## 2. The Solution: The $20 Dedicated Family Appliance

To eliminate all boot friction and prevent host malware exposure, each heir has already been provisioned with a **dedicated, commodity x86 laptop** (e.g. $20 Dell Chromebook 3180 reflashed with standard UEFI firmware / MrChromebox):

```
                                [THE FAMILY RECOVERY KIT]
┌──────────────────────────────────────────────────┐     ┌──────────────────────────────────────────┐
│ THE DEDICATED RECOVERY LAPTOP (IN HEIR'S HOME)   │     │ THE PHYSICAL DUAL-PAYLOAD SD / USB TOKEN │
│ • $20 Dell Chromebook (MrChromebox open UEFI)    │  +  │ • Partition 1: Amnesic SubZero OS        │
│ • Powers on and boots standard SD/USB directly   │     │   (loads 100% into RAM, 0 network drivers)│
│ • Internal SSD is NEVER mounted or touched       │     │ • Partition 2: AES-256 encrypted vault   │
│ • 4.5mm power charger included in kit            │     │ • Backup duplicate card kept offsite     │
└──────────────────────────────────────────────────┘     └──────────────────────────────────────────┘
```

*Hardware Portability Rule*: If the dedicated Dell laptop is lost or damaged, the heir can boot the exact same SD/USB card on **any random $30 PC or old laptop** from a thrift store, eBay, or friend's house.

---

## 3. The 3-Factor Sovereign Distribution Model

The architecture decouples the physical hardware, the encrypted digital data, and the decryption key across three separate domains:

```
┌──────────────────────────────────────┐     ┌──────────────────────────────────────┐     ┌──────────────────────────────────────┐
│ FACTOR 1: PHYSICAL APPLIANCE TOKEN   │     │ FACTOR 2: FULL BOOTABLE IMAGE BACKUP │     │ FACTOR 3: OUT-OF-BAND DEAD-MAN KEY   │
│ Handed in advance to each heir.      │  +  │ Cloud / Off-Site Digital Redundancy. │  +  │ Automated time-delay delivery.       │
│ • Bootable amnesic SubZero OS.       │     │ • Complete, self-contained .img.gz   │     │ • Delivers ONLY the 12-Word Pass.    │
│ • Pre-embedded encrypted vault.json. │     │   containing OS + encrypted vault.   │     │ • Multi-channel: Automated Email +   │
│ • Theft value = Exactly $0.00.       │     │ • Stored in Bitwarden / GDrive.      │     │   SMS + sealed paper escrow envelope │
│ • Stored in safe / heir's home.      │     │ • Emergency Last Resort: Heir burns  │     │   with estate trustee / attorney.    │
│                                      │     │   image to fresh SD card via Etcher. │     │ • Reveals ZERO keys without vault.   │
└──────────────────────────────────────┘     └──────────────────────────────────────┘     └──────────────────────────────────────┘
```

> [!IMPORTANT]
> **Anti-Theft Invariant (Zero Plaintext Steel)**: The safe contains **zero plaintext seed words on metal or paper**. All physical media stored at home consists exclusively of AES-256 encrypted `vault.json` payloads. If the safe is breached, the attacker gets **$0.00**.

---

## 4. The Heir's 5-Step Execution Workflow

```
[Step 1: Dead-Man's Switch Fires]
   │ Heir receives the 12-word Decoupled Passphrase (BIP-85 Index 0) via Dead-Man's Switch (Email/SMS/Trustee).
   ▼
[Step 2: Insert SD Card / USB into Dedicated Dell Laptop]
   │ Heir grabs the small Dell laptop, plugs in power charger, inserts SubZero SD Card/USB.
   │ Heir powers on and taps ESC (or F12) repeatedly to display the MrChromebox Boot Menu.
   │ Heir selects the USB/SD device. System boots directly into SubZero in RAM (internal SSD is NEVER mounted).
   ▼
[Step 3: In-Memory Isolation]
   │ 1. Alpine Linux loads kernel and rootfs 100% into RAM (toram tmpfs).
   │ 2. System copies vault.json into volatile /run/subzero/ (tmpfs).
   │ 3. System unmounts Partition 2 and unbinds physical USB block device.
   │ 4. Media is now 100% offline; all network drivers are physically purged.
   ▼
[Step 4: Framebuffer Decryption]
   │ SubZero UI renders on raw screen (/dev/fb0 via SimpleDRM).
   │ Heir types the 12-word Passphrase (real-time BIP-39 wordlist validation prevents typos).
   │ Kiosk performs in-kernel PBKDF2 (600k iters) + AES-256-GCM decryption in <200ms.
   │ Screen displays:
   │   • Plain-English estate guidance and executor instructions.
   │   • Specific Heir Child Treasury Seed (12 words, BIP-85 Index N).
   │   • BIP-380 Output Descriptor QR Code (<0;1>/* Native SegWit).
   ▼
[Step 5: Verification & Cold Custody Ownership]
   │ Phase 5A (Watch-Only Balance Verification):
   │   • Heir opens Nunchuk on iPhone (App Store ID: 1588665033).
   │   • Heir scans the BIP-380 Descriptor QR code from the laptop screen.
   │   • Nunchuk verifies full balance and UTXO history on iPhone.
   │ Phase 5B (Permanent Custody / Cold Storage):
   │   • Heir copies/stamps their 12-word Child Treasury Seed for permanent cold storage, OR
   │   • Imports seed directly into their own hardware/mobile signing device when ready to sweep.
   │ Heir presses [Q] on laptop -> Confirmation dialog -> System wipes all RAM buffers and powers down.
```

---

## 5. Explicit Threat Model Boundary: Friendly Heirs Presumption

> [!WARNING]
> **Operational Scope & Front-Running Invariant**:
> This inheritance protocol **strictly assumes a cooperative, high-trust family environment with multiple friendly heirs**.
>
> 1. **The Shared Vault Race Condition**: Because the master estate bundle decrypts all heir child treasuries (or the master root seed) under the single 12-word Dead-Man's passphrase, **the fastest heir to execute decryption technically has the cryptographic ability to sweep or front-run the entire estate**.
> 2. **Scope Limitation**: Cryptographic trustless multi-party escrow, timelocked heir-specific outputs (Miniscript / `OP_CHECKLOCKTIMEVERIFY`), or Shamir multi-sig threshold schemes designed for adversarial/unfriendly heirs are intentionally **out of scope** for this release.
> 3. **Protocol Presumption**: Heirs act honorably according to written estate guidelines and only claim their designated BIP-85 Child Index.

---

## 6. Summary of Sovereign Guarantees

1. **Zero Browser Execution**: The 12-word passphrase is **never typed into any web browser or desktop OS**.
2. **Zero Plaintext Steel Risk in Safe**: No unencrypted seeds exist in physical safes to be stolen in a burglary.
3. **Zero Host Hard Drive Touching**: The laptop's internal drive is never mounted. Keystrokes execute strictly in RAM.
4. **Zero Network Attack Surface**: All Wi-Fi, Ethernet, and Bluetooth firmware blobs are physically deleted from the Linux kernel.
5. **Universal Portability**: If the Dell laptop breaks, any commodity x86 PC boots the exact same card.
