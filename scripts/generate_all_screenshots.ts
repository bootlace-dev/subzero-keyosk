import { Framebuffer, RGB } from '../src/framebuffer';
import { sha256 } from '@noble/hashes/sha2';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { BIP32Node, getSegWitAddress, getDescriptorChecksum, deriveBip85Mnemonic } from '../src/crypto';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

const outDir = path.resolve(process.cwd(), 'docs/screenshots');
fs.mkdirSync(outDir, { recursive: true });

const fb = new Framebuffer('/dev/null');
fb.geometry = { width: 1024, height: 768, bpp: 32, stride: 1024 * 4 };
fb.backBuffer = Buffer.alloc(768 * 4096);

const COLOR_BG: RGB = { r: 10, g: 15, b: 24 };
const COLOR_CARD: RGB = { r: 18, g: 26, b: 42 };
const COLOR_CARD_BORDER: RGB = { r: 40, g: 55, b: 85 };
const COLOR_BADGE_BG: RGB = { r: 25, g: 38, b: 62 };
const COLOR_WHITE: RGB = { r: 255, g: 255, b: 255 };
const COLOR_ACCENT: RGB = { r: 0, g: 200, b: 255 };
const COLOR_GOLD: RGB = { r: 255, g: 190, b: 40 };
const COLOR_WARN: RGB = { r: 255, g: 80, b: 80 };
const COLOR_GREEN: RGB = { r: 80, g: 255, b: 120 };
const COLOR_MUTED: RGB = { r: 176, g: 194, b: 222 };

function renderHeader(title: string, subtitle: string, isAlert: boolean = false) {
    fb.clear(COLOR_BG);
    fb.drawRect(20, 18, 1024 - 40, 68, isAlert ? { r: 35, g: 20, b: 25 } : { r: 16, g: 24, b: 40 });
    fb.drawRect(20, 18, 1024 - 40, 2, isAlert ? COLOR_GOLD : COLOR_ACCENT);
    fb.drawRect(20, 84, 1024 - 40, 2, isAlert ? COLOR_GOLD : COLOR_ACCENT);
    fb.drawTextCentered(28, title, 1, isAlert ? COLOR_GOLD : COLOR_ACCENT);
    fb.drawTextCentered(54, subtitle, 1, COLOR_WHITE);
}

function renderFooter(navText: string) {
    const footY = 768 - 40;
    fb.drawRect(20, footY - 8, 1024 - 40, 36, { r: 16, g: 24, b: 40 });
    fb.drawRect(20, footY - 8, 1024 - 40, 1, COLOR_CARD_BORDER);
    fb.drawTextCentered(footY, navText, 1, COLOR_MUTED);
}

function savePage(filename: string) {
    const ppm = `/dev/shm/${filename}.ppm`;
    const png = path.join(outDir, `${filename}.png`);
    fb.saveToPPM(ppm);
    execSync(`convert ${ppm} ${png}`);
    fs.unlinkSync(ppm);
    console.log(`[✓] Generated screenshot: ${png}`);
}

// 1. Screen 01: Main Menu
renderHeader("SUBZERO KEYOSK: SOVEREIGN RECOVERY APPLIANCE", "AIRGAPPED MEMORY-ONLY BITCOIN COLD VAULT // v0.1.0-testnet4");
let y = 110;
const menuItems = [
    { key: "[1]", title: "GENERATE SOVEREIGN HEIR TREASURY & ENCRYPTED VAULT", desc: "Pure Physical Coin/Dice Entropy -> BIP-85 Children + AES-256 Encrypted vault.json" },
    { key: "[2]", title: "DECRYPT & RECOVER INHERITANCE VAULT (vault.json)", desc: "Mount Partition 2 /dev/sdb2 -> Decrypt with 12-Word Passphrase -> Restore Treasury" },
    { key: "[3]", title: "BIP-85 MULTI-PROTOCOL KEY FACTORY", desc: "Deterministic Offshoots for Nostr npub/nsec, Decoupled Passphrase & Child Seeds" },
    { key: "[4]", title: "SEEDFIX BIP-39 12TH-WORD CHECKSUM & CANDIDATE SOLVER", desc: "Enter 11 Words -> Solve all 128 Valid 12th Words & Fix Single-Word Typos" },
    { key: "[5]", title: "STORAGE DEVICE HASHER & INTEGRITY SCANNER", desc: "Direct Hardware Sector Integrity Audit & SHA-256 Master Checksum Verification" },
    { key: "[Q]", title: "SECURE MEMORY ZEROIZATION & HARDWARE POWER OFF", desc: "3-Pass RAM/VRAM Scrub -> Unmount Block Devices -> Instant ACPI Cutoff" }
];
menuItems.forEach((item, idx) => {
    const cardY = y + idx * 82;
    fb.drawRect(40, cardY, 1024 - 80, 70, COLOR_CARD);
    fb.drawRectBorder(40, cardY, 1024 - 80, 70, 1, idx === 0 ? COLOR_ACCENT : COLOR_CARD_BORDER);
    fb.drawText(60, cardY + 12, `${item.key} ${item.title}`, 1, idx === 0 ? COLOR_GOLD : COLOR_ACCENT);
    fb.drawText(60, cardY + 38, item.desc, 1, COLOR_MUTED);
});
renderFooter("Select Mode: [1] Treasury Gen | [2] Decrypt | [3] BIP-85 | [4] SeedFix | [5] Storage Hasher | [Q] Power Off");
savePage("01_main_menu");

// 2. Screen 02: Physical Entropy Ingestion
renderHeader("[1] GENERATE SOVEREIGN HEIR TREASURY", "PHYSICAL ENTROPY INGESTION // 128 COIN FLIPS OR 50 DICE ROLLS");
y = 110;
fb.drawRect(40, y, 1024 - 80, 60, COLOR_BADGE_BG);
fb.drawRectBorder(40, y, 1024 - 80, 60, 1, COLOR_ACCENT);
fb.drawText(60, y + 10, "STRICT AIRGAP INVARIANT: Physical Coin (H/T), Dice (1-6) or Hex (0-F)", 1, COLOR_GOLD);
fb.drawText(60, y + 32, "Markov transition matrix continuously audits for mechanical bias or human fatigue.", 1, COLOR_MUTED);

y += 80;
fb.drawText(40, y, "INPUT PHYSICAL ENTROPY STREAM (Chunked in 4-bit blocks):", 1, COLOR_WHITE);
y += 24;
fb.drawRect(40, y, 1024 - 80, 75, COLOR_CARD);
fb.drawRectBorder(40, y, 1024 - 80, 75, 1, COLOR_GREEN);
fb.drawTextWrapped(60, y + 16, 1024 - 120, "HTTH THTH HHTT TTHH HHTH TTTH HHHH TTTT HTHT THTH HHTT TTHH HHTH TTTH HHHH TTTT (128 Flips)", 1, COLOR_GREEN);

y += 95;
fb.drawRect(40, y, 1024 - 80, 110, COLOR_CARD);
fb.drawRectBorder(40, y, 1024 - 80, 110, 1, COLOR_CARD_BORDER);
fb.drawText(60, y + 12, "REAL-TIME CRYPTOGRAPHIC INVARIANTS AUDIT:", 1, COLOR_GOLD);
fb.drawText(60, y + 36, " * Total Entropy Bits : 128.0 Bits (Target >= 128.0 Bits)  [✓ PASS]", 1, COLOR_GREEN);
fb.drawText(60, y + 56, " * Markov Entropy Rate: 0.998 Bits/Symbol (Randomness > 0.85) [✓ PASS]", 1, COLOR_GREEN);
fb.drawText(60, y + 76, " * NIST SP 800-22 Test : Monobit Frequency Delta: 0.015       [✓ PASS]", 1, COLOR_GREEN);

renderFooter("Controls: [TYPE] = Add Entropy | [ENTER] = Derive Sovereign Vault | [ESC] = Menu | [Q] = Power Off");
savePage("02_entropy_input");

// 3. Screen 03: Master Seed Carousel
const rawEntropy = new Uint8Array(16).fill(0xFF);
const rootMnemonic = bip39.entropyToMnemonic(rawEntropy, wordlist);
const rootSeed = bip39.mnemonicToSeedSync(rootMnemonic, '');
const rootNode = BIP32Node.fromSeed(rootSeed);
const passphrase = deriveBip85Mnemonic(rootNode, 0, 12);
const heir1 = deriveBip85Mnemonic(rootNode, 1, 12);

renderHeader("[PAGE 1/5] SOVEREIGN MASTER ROOT SEED & DECOUPLED PASSPHRASE", "MASTER RECOVERY CAROUSEL // AIRGAPPED MEMORY ONLY");
y = 110;
fb.drawRect(40, y, 1024 - 80, 110, COLOR_CARD);
fb.drawRectBorder(40, y, 1024 - 80, 110, 2, COLOR_WARN);
fb.drawText(60, y + 12, "MASTER ROOT MNEMONIC (12 WORDS) - STAMP TO STAINLESS STEEL:", 1, COLOR_WARN);
fb.drawTextWrapped(60, y + 42, 1024 - 120, rootMnemonic, 1, COLOR_WHITE);

y += 130;
fb.drawRect(40, y, 1024 - 80, 95, COLOR_CARD);
fb.drawRectBorder(40, y, 1024 - 80, 95, 1, COLOR_ACCENT);
fb.drawText(60, y + 12, "DECOUPLED ESTATE PASSPHRASE (BIP-85 INDEX 0) - SEPARATE ESCROW:", 1, COLOR_ACCENT);
fb.drawTextWrapped(60, y + 40, 1024 - 120, passphrase, 1, COLOR_GOLD);

y += 115;
fb.drawRect(40, y, 1024 - 80, 95, COLOR_CARD);
fb.drawRectBorder(40, y, 1024 - 80, 95, 1, COLOR_CARD_BORDER);
fb.drawText(60, y + 12, "HEIR #1 COLD TREASURY (BIP-85 INDEX 1):", 1, COLOR_GREEN);
fb.drawTextWrapped(60, y + 40, 1024 - 120, heir1, 1, COLOR_WHITE);

renderFooter("Carousel: [SPACE/RIGHT] = Next Page | [LEFT] = Prev | [ESC] = Menu | [Q] = Power Off");
savePage("03_master_seed_carousel");

// 4. Screen 04: BIP-380 Output Descriptor QR Code
renderHeader("[PAGE 4/5] BIP-380 OUTPUT DESCRIPTOR QR CODE", "WATCH-ONLY COORDINATOR EXPORT // SCAN IN SPARROW & NUNCHUK");
const rawDesc = "wpkh([d5f2a10b/84'/1'/0']tpubDC5WBw.../<0;1>/*)";
const cksum = getDescriptorChecksum(rawDesc);
const fullDesc = `${rawDesc}#${cksum}`;
const qrCenterY = Math.floor(768 / 2) + 15;
fb.drawQRCode(fullDesc, qrCenterY, 5, 4);
fb.drawTextCentered(768 - 80, `Descriptor: ${fullDesc}`, 1, COLOR_MUTED);
renderFooter("Scan with Sparrow / Nunchuk | [SPACE] = Next | [ESC] = Menu | [Q] = Power Off");
savePage("04_descriptor_qr");

// 5. Screen 05: BIP-85 Multi-Protocol Key Factory
renderHeader("[3] BIP-85 MULTI-PROTOCOL KEY FACTORY", "DETERMINISTIC OFFSHOOTS FOR NOSTR, SSH & CHILD TREASURIES");
y = 110;
fb.drawRect(40, y, 1024 - 80, 75, COLOR_CARD);
fb.drawRectBorder(40, y, 1024 - 80, 75, 1, COLOR_ACCENT);
fb.drawText(60, y + 12, "NOSTR IDENTITY KEYPAIR (m/83696968'/1237'/0'):", 1, COLOR_ACCENT);
fb.drawText(60, y + 38, "npub180cvv07tjdrrgpa0j7j7tmn0am2fmu65nvhp7w88kpvd2pjhw9as897v76", 1, COLOR_GREEN);

y += 95;
fb.drawRect(40, y, 1024 - 80, 75, COLOR_CARD);
fb.drawRectBorder(40, y, 1024 - 80, 75, 1, COLOR_ACCENT);
fb.drawText(60, y + 12, "DECOUPLED ESTATE PASSPHRASE (Index 0):", 1, COLOR_ACCENT);
fb.drawText(60, y + 38, passphrase, 1, COLOR_GOLD);

y += 95;
fb.drawRect(40, y, 1024 - 80, 140, COLOR_CARD);
fb.drawRectBorder(40, y, 1024 - 80, 140, 1, COLOR_CARD_BORDER);
fb.drawText(60, y + 12, "DERIVED CHILD HEIR TREASURIES (INDICES 1 TO 3):", 1, COLOR_GOLD);
fb.drawText(60, y + 36, " * Heir #1 (Index 1): also voice raise tray tree detail exchange run start still cube actual", 1, COLOR_WHITE);
fb.drawText(60, y + 60, " * Heir #2 (Index 2): round arrive move excess fame base six immune prevent stomach mouse dirt", 1, COLOR_WHITE);
fb.drawText(60, y + 84, " * Heir #3 (Index 3): marine praise chase clean impulse infant caution young coin few banner bench", 1, COLOR_WHITE);

renderFooter("Controls: [0]..[9] = Load Test Vector | [1] = Physical Entropy | [ESC] = Menu | [Q] = Power Off");
savePage("05_bip85_factory");

// 6. Screen 06: SeedFix Checksum & Candidate Solver
renderHeader("[4] SEEDFIX BIP-39 12TH-WORD CHECKSUM & CANDIDATE SOLVER", "RECOVER UNKNOWN 12TH WORD OR FIX TYPOGRAPHICAL ERRORS");
y = 110;
fb.drawRect(40, y, 1024 - 80, 50, COLOR_CARD);
fb.drawRectBorder(40, y, 1024 - 80, 50, 1, COLOR_ACCENT);
fb.drawText(60, y + 16, "ENTER 11 WORDS (OR 12 WORDS WITH TYPO): zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo", 1, COLOR_WHITE);

y += 70;
fb.drawRect(40, y, 1024 - 80, 180, COLOR_BADGE_BG);
fb.drawRectBorder(40, y, 1024 - 80, 180, 1, COLOR_GREEN);
fb.drawText(60, y + 14, "SOLVED: 128 MATHEMATICALLY VALID 12TH WORDS (RANKED BY CHECKSUM):", 1, COLOR_GOLD);
const candidates = ["wrong", "abstract", "access", "achieve", "action", "address", "adult", "agent", "airport", "alien", "alpha", "amateur", "ancient", "angry", "annual", "apple"];
let cx = 60, cy = y + 42;
candidates.forEach((w, i) => {
    fb.drawText(cx, cy, `[${i+1}] ${w}`, 1, i === 0 ? COLOR_GREEN : COLOR_WHITE);
    cx += 220;
    if ((i + 1) % 4 === 0) { cx = 60; cy += 26; }
});

renderFooter("Controls: [TYPE] = 4-Char Autocomplete | [ENTER] = Calculate | [ESC] = Menu | [Q] = Power Off");
savePage("06_seedfix_solver");

// 7. Screen 07: Storage Device Hasher
renderHeader("[5] STORAGE DEVICE HASHER & INTEGRITY SCANNER", "REAL BLOCK-LEVEL SECTOR LATENCY & SHA-256 INTEGRITY AUDIT");
y = 110;
fb.drawRect(40, y, 1024 - 80, 70, COLOR_CARD);
fb.drawRectBorder(40, y, 1024 - 80, 70, 1, COLOR_ACCENT);
fb.drawText(60, y + 12, "ACTIVE STORAGE DEVICE: /dev/sdb (SanDisk Ultra 32GB MicroSD)", 1, COLOR_ACCENT);
fb.drawText(60, y + 38, "SHA-256: 7f3b89a24c10e5d8f99e120b334aa789c098df12345e678912345678abcdef01", 1, COLOR_GREEN);

y += 90;
fb.drawText(40, y, "64MB SECTOR READ LATENCY MAP (64 x 1MB BLOCKS):", 1, COLOR_GOLD);
y += 24;
// Draw 64 latency blocks (8 rows x 8 cols)
for (let r = 0; r < 8; r++) {
    for (let c = 0; c < 8; c++) {
        const bx = 60 + c * 38;
        const by = y + r * 22;
        const isFast = (r * 8 + c) % 7 !== 0;
        fb.drawRect(bx, by, 32, 16, isFast ? COLOR_GREEN : COLOR_GOLD);
    }
}
fb.drawText(420, y + 20, "LATENCY BENCHMARKS:", 1, COLOR_WHITE);
fb.drawText(420, y + 45, " * Fast (<15ms)   : [GREEN]  60 Blocks (93.7%)", 1, COLOR_GREEN);
fb.drawText(420, y + 70, " * Medium (<50ms) : [YELLOW]  4 Blocks ( 6.3%)", 1, COLOR_GOLD);
fb.drawText(420, y + 95, " * Throughput Rate: 28.4 MB/s (Optimal)", 1, COLOR_ACCENT);

renderFooter("Controls: [H] = Run Real 64MB Scan | [ESC] = Menu | [Q] = Power Off");
savePage("07_storage_hasher");

// 8. Screen 08: Vault Decrypt Screen
renderHeader("[2] DECRYPT & RECOVER INHERITANCE VAULT", "LOCATE vault.json ON PARTITION 2 & DECRYPT VIA 12-WORD PASSPHRASE");
y = 110;
fb.drawRect(40, y, 1024 - 80, 50, COLOR_CARD);
fb.drawRectBorder(40, y, 1024 - 80, 50, 1, COLOR_GREEN);
fb.drawText(60, y + 16, "[✓] DETECTED: /media/subzero_p2/vault.json (4,128 bytes - AES-256-GCM)", 1, COLOR_GREEN);

y += 70;
fb.drawText(40, y, "ENTER 12-WORD ESTATE PASSPHRASE (12/12 WORDS):", 1, COLOR_WHITE);
y += 24;
fb.drawRect(40, y, 1024 - 80, 65, COLOR_CARD);
fb.drawRectBorder(40, y, 1024 - 80, 65, 1, COLOR_GREEN);
fb.drawTextWrapped(60, y + 14, 1024 - 120, passphrase, 1, COLOR_GOLD);

y += 85;
fb.drawRect(40, y, 1024 - 80, 125, COLOR_BADGE_BG);
fb.drawRectBorder(40, y, 1024 - 80, 125, 1, COLOR_CARD_BORDER);
fb.drawText(60, y + 12, "DEMO SHORTCUTS: 10 SATOSHI LORE TEST VECTORS (INSTANT LAB RECOVERY):", 1, COLOR_GOLD);
fb.drawText(60, y + 32, " * 'test0': Genesis (All Zeros)       | * 'test5': All-Ones Boundary (Zoo)", 1, COLOR_WHITE);
fb.drawText(60, y + 50, " * 'test1': Faucet Spender (Vector 1) | * 'test6': Satoshi Genesis Lore (2009)", 1, COLOR_WHITE);
fb.drawText(60, y + 68, " * 'test2': Watch Treasury (Vector 2) | * 'test7': Hal Finney 2009 Tribute", 1, COLOR_WHITE);
fb.drawText(60, y + 86, " * 'test3': Hot Wallet Pair (Vector 3)| * 'test8': Correct Horse Battery", 1, COLOR_WHITE);
fb.drawText(60, y + 104, " * 'test4': Edge Descriptor (Vector 4)| * 'test9': 256-Bit Stress Matrix", 1, COLOR_WHITE);

renderFooter("Controls: [TYPE] = 4-Char Autocomplete | [ENTER] = Decrypt | [ESC] = Menu | [Q] = Power Off");
savePage("08_vault_decrypt");

console.log("[✓] All 8 high-resolution documentation screenshots successfully generated!");
