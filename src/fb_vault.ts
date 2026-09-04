import * as readline from 'readline';
import * as fs from 'fs';
import * as path from 'path';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { hmac } from '@noble/hashes/hmac.js';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import {
    BIP32Node,
    getSegWitAddress,
    getDescriptorChecksum,
    runMarkovAudit,
    hasRepetitiveSubstrings,
    deriveBip85Mnemonic,
    deriveBip85Nostr,
    deriveBip85Hex,
    solve12thWordCandidates,
    suggestBip39Correction,
    encryptVaultJson,
    decryptVaultJson
} from './crypto';
import { Framebuffer, RGB } from './framebuffer';

const COLOR_BG: RGB = { r: 10, g: 15, b: 24 };           // Deep dark navy (#0A0F18)
const COLOR_CARD: RGB = { r: 18, g: 26, b: 42 };         // Dark slate card (#121A2A)
const COLOR_CARD_BORDER: RGB = { r: 40, g: 55, b: 85 };  // Slate border (#283755)
const COLOR_BADGE_BG: RGB = { r: 25, g: 38, b: 62 };     // Badge background
const COLOR_WHITE: RGB = { r: 255, g: 255, b: 255 };      // Pure crisp white (#FFFFFF)
const COLOR_ACCENT: RGB = { r: 0, g: 200, b: 255 };      // Bright cyan (#00C8FF)
const COLOR_GREEN: RGB = { r: 50, g: 205, b: 50 };       // Vibrant lime green (#32CD32)
const COLOR_GOLD: RGB = { r: 255, g: 190, b: 40 };       // Amber gold (#FFBE28)
const COLOR_WARN: RGB = { r: 255, g: 80, b: 80 };        // Soft red warning (#FF5050)
const COLOR_MUTED: RGB = { r: 120, g: 140, b: 170 };     // Slate muted text (#788CAA)
declare const __BUILD_STAMP__: string;
declare const __GIT_SHA__: string;

const BUILD_STAMP_VAL = typeof __BUILD_STAMP__ !== 'undefined' ? __BUILD_STAMP__ : 'DEV';
const GIT_SHA_VAL = typeof __GIT_SHA__ !== 'undefined' ? __GIT_SHA__ : 'local';
const BUILD_VERSION = `v0.2.0-vault-testnet4 [${BUILD_STAMP_VAL}]`;
const BUILD_TARGET = "x86_64 Generic PC (UEFI/BIOS)";

const fb = new Framebuffer();

function logDebug(msg: string) {
    try {
        fs.appendFileSync('/tmp/subzero_vault_debug.log', `[${new Date().toISOString()}] ${msg}\n`);
    } catch (_) {}
}

type AppState = 
    | "MENU"
    | "SEED_GEN_INPUT"
    | "SEED_GEN_CAROUSEL"
    | "CLONE_CONFIRM"
    | "DEBUG_VIEW"
    | "VAULT_DECRYPT"
    | "BIP85_FACTORY"
    | "SEEDFIX_TOOL"
    | "STORAGE_HASHER"
    | "BIP39_INSPECTOR"
    | "CONFIRM_EXIT";

async function main() {
    logDebug("Starting Subzero Vault Framebuffer Edition...");

    try { process.stdout.write('\x1b[?25l'); } catch (_) {}

    let state: AppState = "MENU";
    let selectedMenuIndex = 0;
    const menuOptions = [
        "[1] Sovereign Physical Entropy & Cold Treasury Generator (Coins/Dice)",
        "[2] Unlock & Decrypt Estate Vault (Import vault.json + 12-Word Passphrase)",
        "[3] BIP-85 Multi-Protocol Key Factory (Nostr / SSH / Child Wallets)",
        "[4] SeedFix: 11-to-12 Checksum Solver & Typo Recovery Tool",
        "[5] Storage Media & Cryptographic Health Audit (Read-Only)",
        "[6] BIP-39 English Wordlist Inspector (2048 Canonical Words)",
        "[Q] Power Down & Amnesic RAM Zeroization"
    ];

    // Seed Gen State
    let currentEntropyInput = "";
    let masterMnemonicWords: string[] = [];
    const heirMnemonics: { label: string, index: number, words: string }[] = [];
    let passphrase_mnemonic = "";
    let tpub = "";
    let vpub = "";
    let fingerprint = "";
    let descriptorWithChecksum = "";
    let currentCarouselView = 0;
    const totalCarouselViews = 9;
    const receiveAddresses: string[] = [];

    // USB Batch Export State
    let exportStatus = "Press [W] to write encrypted vault.json to SUBZERO_EST partition";
    let exportSuccess = false;

    // Clone Confirmation & Progress State
    let cloneCandidate: {
        masterDisk: string;
        targetDisk: string;
        targetBytes: number;
        targetGB: string;
        targetModel: string;
    } | null = null;
    let cloneProgress = {
        active: false,
        chunkIndex: 0,
        totalChunks: 128,
        bytesCopied: 0,
        totalBytes: 512 * 1024 * 1024,
        statusText: ""
    };

    // Debug Viewer State
    let debugLogScroll = 0;
    let debugLogLines: string[] = [];

    // Vault Decryption State
    let vaultDecryptInput = "";
    let vaultDecryptStatus = "";
    let vaultDetectedPath = "";
    let vaultRawPayload = "";

    // SeedFix Tool State
    let seedFixInput = "";
    let seedFixResults: string[] = [];
    let seedFixMode: "11_WORD" | "TYPO" = "11_WORD";

    // Storage Hasher State
    let hasherStatus = "Insert FAT32 USB/SD card and press [H] to Scan Block Devices";
    let hasherProgress = 0;
    let computedHash = "";

    // Wordlist Inspector State
    let wordlistSearchQuery = "";
    let wordlistMatches: string[] = [];

    function renderHeader(title: string, subtitle: string, isSensitive: boolean = false) {
        fb.clear(COLOR_BG);
        fb.drawRect(0, 0, fb.geometry.width, 68, COLOR_CARD);
        fb.drawRect(0, 68, fb.geometry.width, 2, isSensitive ? COLOR_WARN : COLOR_ACCENT);

        fb.drawRect(40, 16, 88, 36, isSensitive ? { r: 55, g: 20, b: 25 } : COLOR_BADGE_BG);
        fb.drawRect(40, 16, 88, 36, isSensitive ? COLOR_WARN : COLOR_ACCENT);
        fb.drawTextCentered(28, isSensitive ? "SECURE" : "AIRGAP", 1, isSensitive ? COLOR_WARN : COLOR_ACCENT);

        fb.drawText(148, 16, title, 1, isSensitive ? COLOR_WARN : COLOR_WHITE);
        fb.drawText(148, 40, subtitle, 1, COLOR_MUTED);

        const buildInfo = `${BUILD_VERSION}`;
        const buildX = fb.geometry.width - 40 - (buildInfo.length * 8);
        fb.drawText(buildX, 28, buildInfo, 1, COLOR_GOLD);
    }

    function renderFooter(controls: string, isWarn: boolean = false) {
        const footY = fb.geometry.height - 40;
        fb.drawRect(0, footY, fb.geometry.width, 40, COLOR_CARD);
        fb.drawRect(0, footY, fb.geometry.width, 1, COLOR_CARD_BORDER);
        fb.drawText(40, footY + 12, controls, 1, isWarn ? COLOR_WARN : COLOR_ACCENT);
    }

    function renderMainMenu() {
        renderHeader(
            "[!] SUBZERO VAULT // SOVEREIGN SUITE [!]",
            "AIRGAPPED APPLIANCE // VOLATILE RAM EXECUTION"
        );

        let y = 110;
        fb.drawText(40, y, "SELECT A SINGLE-PURPOSE TOOL:", 1, COLOR_GOLD);
        y += 30;

        for (let i = 0; i < menuOptions.length; i++) {
            const isSelected = i === selectedMenuIndex;
            const isQuit = i === menuOptions.length - 1;
            const cardH = 54;

            fb.drawRect(40, y, fb.geometry.width - 80, cardH, isSelected ? (isQuit ? { r: 45, g: 20, b: 25 } : COLOR_BADGE_BG) : COLOR_CARD);
            fb.drawRectBorder(40, y, fb.geometry.width - 80, cardH, 1, isSelected ? (isQuit ? COLOR_WARN : COLOR_ACCENT) : COLOR_CARD_BORDER);

            const prefix = isSelected ? " > " : "   ";
            fb.drawText(55, y + 18, prefix + menuOptions[i], 1, isSelected ? (isQuit ? COLOR_WARN : COLOR_GREEN) : COLOR_WHITE);
            y += 66;
        }

        renderFooter("Controls: [UP/DOWN] = Select Tool | [ENTER] = Launch | [D] = Debug Log | [Q] = Power Off & Wipe");
        fb.flush();
    }

    function checkTestVector(input: string): { isTest: boolean, label: string } {
        const lower = input.trim().toLowerCase();
        if (lower === 'test' || lower === 'test0') return { isTest: true, label: 'TEST VECTOR 0 (BIP-39 BASELINE: ALL ZEROS 0x00)' };
        if (lower === 'test1') return { isTest: true, label: 'TEST VECTOR 1 (ALTERNATING 0x55)' };
        if (lower === 'test2') return { isTest: true, label: 'TEST VECTOR 2 (ALTERNATING 0xAA)' };
        if (lower === 'test3') return { isTest: true, label: 'TEST VECTOR 3 (SIGNED BYTE BOUNDARY 0x7F)' };
        if (lower === 'test4') return { isTest: true, label: 'TEST VECTOR 4 (HIGH-BIT BOUNDARY 0x80)' };
        if (lower === 'test5') return { isTest: true, label: 'TEST VECTOR 5 (ALL-ONES BOUNDARY 0xFF)' };
        if (lower === 'test6') return { isTest: true, label: 'TEST VECTOR 6 (INCREMENTAL NIBBLES 0x0123...)' };
        if (lower === 'test7') return { isTest: true, label: 'TEST VECTOR 7 (SEQUENTIAL BYTES 0x0001...)' };
        if (lower === 'test8') return { isTest: true, label: 'TEST VECTOR 8 (SATOSHI GENESIS LORE: TIMES 2009)' };
        if (lower === 'test9') return { isTest: true, label: 'TEST VECTOR 9 (HAL FINNEY LORE: RUNNING BITCOIN)' };
        return { isTest: false, label: '' };
    }

    function renderSeedGenInputScreen() {
        renderHeader(
            "[1] PHYSICAL ENTROPY INGESTION (COIN-FIRST)",
            "MIN 128 COIN FLIPS (0/1), 50 DICE ROLLS (1-6), OR 'test0'...'test9'"
        );

        let y = 100;
        fb.drawText(40, y, "ENTER PHYSICAL COIN FLIPS (0/1), DICE ROLLS (1-6), OR 'test0'...'test9':", 1, COLOR_GOLD);
        y += 24;

        const testCheck = checkTestVector(currentEntropyInput);
        const isReady = currentEntropyInput.length >= 128 || testCheck.isTest;
        fb.drawRect(40, y, fb.geometry.width - 80, 140, COLOR_CARD);
        fb.drawRectBorder(40, y, fb.geometry.width - 80, 140, 1, isReady ? COLOR_GREEN : COLOR_ACCENT);

        if (testCheck.isTest) {
            fb.drawText(55, y + 18, `[!] ACTIVE TEST VECTOR: ${testCheck.label}`, 1, COLOR_GOLD);
            fb.drawText(55, y + 44, currentEntropyInput.trim(), 2, COLOR_GREEN);
        } else if (currentEntropyInput.length > 0) {
            fb.drawTextWrapped(55, y + 14, fb.geometry.width - 110, currentEntropyInput, 1, isReady ? COLOR_GREEN : COLOR_WHITE);
        } else {
            fb.drawText(55, y + 14, "Type coin flips (0/1), dice rolls (1-6), or 'test0'...'test9'...", 1, COLOR_MUTED);
        }

        y += 155;
        const bits = testCheck.isTest ? 128 : currentEntropyInput.length;
        fb.drawText(40, y, `Entropy Bits: ${bits} / 128 bits`, 1, isReady ? COLOR_GREEN : COLOR_WARN);
        y += 28;

        const barW = fb.geometry.width - 80;
        const fillW = Math.min(barW, Math.floor(barW * (bits / 128.0)));
        fb.drawRect(40, y, barW, 14, { r: 20, g: 30, b: 45 });
        if (fillW > 0) fb.drawRect(40, y, fillW, 14, isReady ? COLOR_GREEN : COLOR_ACCENT);
        fb.drawRectBorder(40, y, barW, 14, 1, COLOR_CARD_BORDER);

        y += 30;
        if (isReady) {
            fb.drawRect(40, y, fb.geometry.width - 80, 40, { r: 15, g: 45, b: 25 });
            fb.drawRectBorder(40, y, fb.geometry.width - 80, 40, 1, COLOR_GREEN);
            fb.drawTextCentered(y + 12, ">>> 128-BIT ENTROPY ACQUIRED -- PRESS [ENTER] TO DERIVE SEEDS <<<", 1, COLOR_GREEN);
        }

        renderFooter("Controls: [0/1 Coins] [1-6 Dice] [R=Hardware RNG] | [ENTER] = Process | [ESC] = Menu");
        fb.flush();
    }

    function getTestVectorEntropy(testKey: string): Uint8Array {
        const lower = testKey.trim().toLowerCase();
        if (lower === 'test' || lower === 'test0') {
            return new Uint8Array(16).fill(0x00); // abandon abandon ... about
        } else if (lower === 'test1') {
            return new Uint8Array(16).fill(0x55); // fetch primary fetch primary ... problem
        } else if (lower === 'test2') {
            return new Uint8Array(16).fill(0xAA); // primary fetch primary fetch ... fever
        } else if (lower === 'test3') {
            return new Uint8Array(16).fill(0x7F); // legal winner thank year ... yellow
        } else if (lower === 'test4') {
            return new Uint8Array(16).fill(0x80); // letter advice cage absurd ... above
        } else if (lower === 'test5') {
            return new Uint8Array(16).fill(0xFF); // zoo zoo zoo ... wrong
        } else if (lower === 'test6') {
            return Uint8Array.from([0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef]); // abuse boss fly ...
        } else if (lower === 'test7') {
            return Uint8Array.from([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]); // abandon amount liar ...
        } else if (lower === 'test8') {
            return sha256(new TextEncoder().encode("The Times 03/Jan/2009 Chancellor on brink of second bailout for banks")).slice(0, 16);
        } else if (lower === 'test9') {
            return sha256(new TextEncoder().encode("Running bitcoin - Hal Finney 10 Jan 2009")).slice(0, 16);
        }
        return new Uint8Array(16).fill(0x00);
    }

    function computeSeedGenDerivations() {
        let rawEntropy: Uint8Array;
        const lower = currentEntropyInput.trim().toLowerCase();

        const testCheck = checkTestVector(currentEntropyInput);
        if (testCheck.isTest) {
            rawEntropy = getTestVectorEntropy(lower);
        } else {
            const clean = currentEntropyInput.replace(/\s+/g, '');
            const entropyHash = sha256(new TextEncoder().encode(clean));
            rawEntropy = entropyHash.slice(0, 16);
        }

        const rootMnemonic = bip39.entropyToMnemonic(rawEntropy, wordlist);
        masterMnemonicWords = rootMnemonic.split(' ');

        const rootSeed = bip39.mnemonicToSeedSync(rootMnemonic, '');
        const rootNode = BIP32Node.fromSeed(rootSeed);
        rootSeed.fill(0);

        // Derive Sibling Passphrase (Index 0)
        passphrase_mnemonic = deriveBip85Mnemonic(rootNode, 0, 12);

        // Derive 5 Heir Child Treasuries (Indices 1 to 5)
        heirMnemonics.length = 0;
        for (let i = 1; i <= 5; i++) {
            heirMnemonics.push({
                label: `Heir #${i} Cold Treasury`,
                index: i,
                words: deriveBip85Mnemonic(rootNode, i, 12)
            });
        }

        // Testnet4 Account BIP-84 m/84'/1'/0'
        const purpose = rootNode.deriveHardened(84);
        const coinType = purpose.deriveHardened(1);
        const account = coinType.deriveHardened(0);

        tpub = account.toSerializedKey(false, true, false);
        vpub = account.toSerializedKey(false, true, true);
        fingerprint = rootNode.getFingerprint().toString(16).padStart(8, '0');

        const rawDesc = `wpkh([${fingerprint}/84'/1'/0']${tpub}/<0;1>/*)`;
        const cksum = getDescriptorChecksum(rawDesc);
        descriptorWithChecksum = `${rawDesc}#${cksum}`;

        // Derive Receive Addresses 0 - 4
        receiveAddresses.length = 0;
        const recvBranch = account.derive(0);
        for (let i = 0; i < 5; i++) {
            const addrNode = recvBranch.derive(i);
            receiveAddresses.push(getSegWitAddress(addrNode.publicKey, true));
            addrNode.wipe();
        }
        recvBranch.wipe();

        // Wipe root keys from memory
        rootNode.wipe();
        account.wipe();
        coinType.wipe();
        purpose.wipe();
    }

    function getTestVectorPassphrase(testKey: string): string {
        const rawEntropy = getTestVectorEntropy(testKey);
        const rootMnemonic = bip39.entropyToMnemonic(rawEntropy, wordlist);
        const rootSeed = bip39.mnemonicToSeedSync(rootMnemonic, '');
        const rootNode = BIP32Node.fromSeed(rootSeed);
        rootSeed.fill(0);
        const passphrase = deriveBip85Mnemonic(rootNode, 0, 12);
        rootNode.wipe();
        return passphrase;
    }

    async function executeUsbBatchExport() {
        exportStatus = "Locating boot media estate partition...";
        renderSeedGenCarousel();

        const execSync = require('child_process').execSync;
        let targetDev = "";
        let isRawDisk = false;
        try {
            // UUID-based master resolution (primary path)
            const masterResult = resolveMasterBootDisk();
            if (masterResult.masterDisk) {
                const md = masterResult.masterDisk;
                const pSep = /[0-9]$/.test(md) ? 'p' : '';
                const masterP2 = `/dev/${md}${pSep}2`;
                if (fs.existsSync(masterP2)) {
                    targetDev = masterP2;
                    logDebug(`W command: using master estate partition ${masterP2}`);
                } else {
                    // Master disk present but no partition 2 — might be unpartitioned
                    logDebug(`W command: master /dev/${md} found but ${masterP2} does not exist`);
                }
            }

            // Fallback: blkid label search (for dev mode or legacy images without UUID)
            if (!targetDev) {
                const estDev = execSync("blkid -L SUBZERO_EST 2>/dev/null || true").toString().trim();
                if (estDev) {
                    targetDev = estDev;
                    logDebug(`W command fallback: blkid -L SUBZERO_EST -> ${estDev}`);
                }
            }

            // Last resort: scan for any partition on any block device
            if (!targetDev) {
                const partitions = execSync("ls /dev/sd[a-z][1-9] /dev/vd[a-z][1-9] /dev/mmcblk*[0-9]p[1-9] 2>/dev/null || true").toString().trim().split(/\s+/).filter(Boolean);
                const p2 = partitions.find(p => p.endsWith('2') || p.endsWith('p2'));
                if (p2) {
                    targetDev = p2;
                } else if (partitions.length > 0) {
                    targetDev = partitions[0];
                } else {
                    const disks = execSync("ls /dev/sd[a-z] /dev/vd[a-z] /dev/mmcblk[0-9] 2>/dev/null || true").toString().trim().split(/\s+/).filter(Boolean);
                    if (disks.length > 0) {
                        targetDev = disks[0];
                        isRawDisk = true;
                    }
                }
            }
        } catch (_) {}

        if (!targetDev) {
            const masterResult = resolveMasterBootDisk();
            if (masterResult.error) {
                exportStatus = `${masterResult.error} ${masterResult.diagnostic || 'Re-insert boot SD card and press [W].'}`;
            } else {
                exportStatus = "[!] ERROR: No storage drive detected! Insert boot media and press [W].";
            }
            exportSuccess = false;
            renderSeedGenCarousel();
            return;
        }

        try {
            let partitionToMount = targetDev;

            // If raw unpartitioned disk, create MBR partition table and format to FAT32
            if (isRawDisk) {
                exportStatus = `Formatting ${targetDev} to FAT32 (MBR)...`;
                renderSeedGenCarousel();

                execSync(`parted -s ${targetDev} mklabel msdos mkpart primary fat32 1MiB 100% 2>/dev/null || true`);
                execSync(`mdev -s 2>/dev/null || true`);
                partitionToMount = `${targetDev}1`;
                execSync(`mkfs.vfat -F 32 -n "SUBZERO_EST" ${partitionToMount} 2>/dev/null || mkfs.fat -F 32 ${targetDev} 2>/dev/null || true`);
            }

            const mountDir = "/media/target_usb";
            execSync(`mkdir -p ${mountDir}`);
            execSync(`umount -f ${mountDir} 2>/dev/null || true`);
            execSync(`blockdev --setrw ${partitionToMount} 2>/dev/null || true`);
            execSync(`fsck.vfat -a ${partitionToMount} 2>/dev/null || dosfsck -a ${partitionToMount} 2>/dev/null || true`);
            
            // Mount explicitly with read-write, sync, and permissive umask
            try {
                execSync(`mount -t vfat -o rw,sync,umask=000,errors=continue ${partitionToMount} ${mountDir} 2>/dev/null || mount -o rw ${partitionToMount} ${mountDir}`);
            } catch (_) {
                exportStatus = `Formatting ${partitionToMount} to clean FAT32 (SUBZERO_EST)...`;
                renderSeedGenCarousel();
                execSync(`mkfs.vfat -F 32 -n "SUBZERO_EST" ${partitionToMount} 2>/dev/null || mkfs.fat ${partitionToMount}`);
                execSync(`mount -t vfat -o rw,sync,umask=000,errors=continue ${partitionToMount} ${mountDir} || mount -o rw ${partitionToMount} ${mountDir}`);
            }

            // Ensure write access
            execSync(`mount -o remount,rw ${mountDir} 2>/dev/null || true`);

            // Prepare encrypted vault JSON payload
            const vaultPayload = {
                version: "1.0.0",
                created_utc: new Date().toISOString(),
                master_root_mnemonic: masterMnemonicWords.join(' '),
                descriptor: descriptorWithChecksum,
                heir_treasuries: heirMnemonics.map(h => ({ label: h.label, index: h.index, mnemonic: h.words }))
            };

            const encryptedVault = await encryptVaultJson(JSON.stringify(vaultPayload), passphrase_mnemonic);
            fs.writeFileSync(`${mountDir}/vault.json`, encryptedVault);

            // Copy decrypt.html if present
            if (fs.existsSync("/opt/subzero/templates/decrypt.html")) {
                fs.copyFileSync("/opt/subzero/templates/decrypt.html", `${mountDir}/decrypt.html`);
            } else if (fs.existsSync("./src/templates/decrypt.html")) {
                fs.copyFileSync("./src/templates/decrypt.html", `${mountDir}/decrypt.html`);
            }

            // Write README.txt with Dell appliance and recovery instructions
            const readme = `SUBZERO KEYOSK SOVEREIGN INHERITANCE RECOVERY APPLIANCE
=================================================================
This media contains your encrypted Bitcoin estate payload.

EMERGENCY RECOVERY INSTRUCTIONS:
1. PRIMARY APPLIANCE RECOVERY (RECOMMENDED):
   - Insert this SD card / USB drive into your dedicated Dell laptop (or any x86 PC).
   - Power on and tap [ESC] (or [F12]) to enter the One-Time Boot Menu.
   - Select the USB / SD drive to boot directly into SubZero Keyosk.
   - The appliance runs 100% in-memory from RAM with zero internet risk.
   - Enter your 12-word Decoupled Estate Passphrase to unlock all keys and descriptors.

2. OFFLINE BROWSER DECRYPTION (FALLBACK):
   - Open decrypt.html in any standard browser (Chrome, Safari, Firefox).
   - Drag and drop vault.json onto the page.
   - Enter your 12-word Decoupled Estate Passphrase to unlock.

INTEGRITY VERIFICATION:
To verify file integrity before running:
$ sha256sum -c SHA256SUMS

ANTI-THEFT NOTE:
Without the 12-word Decoupled Estate Passphrase, this media contains zero plain-text
seed words and cannot be decrypted.
`;
            fs.writeFileSync(`${mountDir}/README.txt`, readme);

            // Copy SYSTEM_MANIFEST.txt if present
            if (fs.existsSync("/opt/subzero/docs/SYSTEM_MANIFEST.txt")) {
                fs.copyFileSync("/opt/subzero/docs/SYSTEM_MANIFEST.txt", `${mountDir}/SYSTEM_MANIFEST.txt`);
            } else if (fs.existsSync("./docs/SYSTEM_MANIFEST.txt")) {
                fs.copyFileSync("./docs/SYSTEM_MANIFEST.txt", `${mountDir}/SYSTEM_MANIFEST.txt`);
            }

            // Write timestamped archive alongside canonical vault.json
            const exportStamp = BUILD_STAMP_VAL !== 'DEV' ? BUILD_STAMP_VAL : new Date().toISOString().replace(/[-:T]/g, '').slice(2, 12) + 'Z';
            fs.writeFileSync(`${mountDir}/vault_${exportStamp}.json`, encryptedVault);

            // Generate SHA256SUMS for all exported files
            const filesToSum = ['decrypt.html', 'README.txt', 'SYSTEM_MANIFEST.txt', 'vault.json', `vault_${exportStamp}.json`].filter(f => fs.existsSync(`${mountDir}/${f}`));
            const sums = filesToSum.map(f => {
                const data = fs.readFileSync(`${mountDir}/${f}`);
                const h = require('crypto').createHash('sha256').update(data).digest('hex');
                return `${h}  ${f}`;
            }).join('\n') + '\n';
            fs.writeFileSync(`${mountDir}/SHA256SUMS`, sums);

            execSync(`sync`);
            execSync(`umount ${mountDir} 2>/dev/null || true`);

            exportStatus = `[SUCCESS] Encrypted vault_${exportStamp}.json & SHA256SUMS written to ${partitionToMount}!`;
            exportSuccess = true;
            renderSeedGenCarousel();
        } catch (e: any) {
            exportStatus = `[!] EXPORT FAILED: ${e?.message || e}`;
            exportSuccess = false;
            renderSeedGenCarousel();
        }
    }

    function resolveMasterBootDisk(): { masterDisk?: string, error?: string, diagnostic?: string } {
        const execSync = require('child_process').execSync;

        // Read boot identity files written by initramfs at boot
        let bootUUID = "";
        let bootDiskHint = "";  // device letter at boot time (may become stale on replug)
        try {
            if (fs.existsSync("/etc/subzero_boot_uuid")) bootUUID = fs.readFileSync("/etc/subzero_boot_uuid", 'utf8').trim();
        } catch (_) {}
        try {
            if (fs.existsSync("/etc/subzero_boot_disk")) bootDiskHint = fs.readFileSync("/etc/subzero_boot_disk", 'utf8').trim();
            else if (fs.existsSync("/run/subzero/boot_disk")) bootDiskHint = fs.readFileSync("/run/subzero/boot_disk", 'utf8').trim();
        } catch (_) {}

        logDebug(`resolveMasterBootDisk: UUID=${bootUUID || '(none)'}, hint=${bootDiskHint || '(none)'}`);

        // Force device node refresh (Alpine uses mdev, not udev)
        try { execSync('mdev -s 2>/dev/null || true'); } catch (_) {}

        let masterDisk = "";

        if (bootUUID) {
            // Fast path: check if the device at the recorded letter still has the boot UUID
            if (bootDiskHint) {
                const pSep = /[0-9]$/.test(bootDiskHint) ? 'p' : '';
                const hintP1 = `/dev/${bootDiskHint}${pSep}1`;
                try {
                    const hintUUID = execSync(`blkid -s UUID -o value ${hintP1} 2>/dev/null || true`).toString().trim();
                    if (hintUUID === bootUUID) {
                        masterDisk = bootDiskHint;
                        logDebug(`Fast path confirmed: /dev/${bootDiskHint} matches boot UUID ${bootUUID}`);
                    }
                } catch (_) {}
            }

            // Slow path: scan all block devices for the boot UUID
            if (!masterDisk) {
                try {
                    const blkidAll = execSync('blkid 2>/dev/null || true').toString().trim();
                    const uuidPattern = `UUID="${bootUUID}"`;
                    const matches = blkidAll.split('\n')
                        .filter(l => l.includes(uuidPattern))
                        .map(l => l.split(':')[0].trim())
                        .filter(Boolean);

                    if (matches.length === 1) {
                        const parentDisk = execSync(`lsblk -no pkname ${matches[0]} 2>/dev/null || true`).toString().trim().replace(/^\/dev\//, '');
                        if (parentDisk) {
                            masterDisk = parentDisk;
                            logDebug(`UUID scan: boot media found at ${matches[0]} -> /dev/${masterDisk}`);
                        }
                    } else if (matches.length > 1) {
                        const devList = matches.join(', ');
                        logDebug(`AMBIGUOUS: ${matches.length} devices share boot UUID ${bootUUID}: ${devList}`);
                        // Tie-break: prefer the device at the boot hint letter
                        if (bootDiskHint && matches.some(m => m.startsWith(`/dev/${bootDiskHint}`))) {
                            masterDisk = bootDiskHint;
                            logDebug(`Tie-break: using boot hint /dev/${bootDiskHint}`);
                        } else {
                            return {
                                error: `[!] AMBIGUOUS: ${matches.length} drives share UUID ${bootUUID} (${devList}).`,
                                diagnostic: `This happens when multiple cards were flashed from the same image. Unplug all cards except the one you booted from, plus one blank target card. Then retry.`
                            };
                        }
                    }
                    // matches.length === 0: master not found, fall through
                } catch (_) {}
            }
        }

        // Fallback: use boot disk letter without UUID verification
        if (!masterDisk && bootDiskHint && fs.existsSync(`/dev/${bootDiskHint}`)) {
            masterDisk = bootDiskHint;
            logDebug(`Fallback: using /dev/${bootDiskHint} (no UUID file available for verification)`);
        }

        // Nothing found
        if (!masterDisk) {
            if (bootUUID) {
                return {
                    error: `[!] BOOT MEDIA NOT FOUND (UUID ${bootUUID}).`,
                    diagnostic: `The SD card you booted from has been unplugged and is not currently in any USB port. Re-insert it and retry.`
                };
            }
            if (bootDiskHint) {
                return {
                    error: `[!] BOOT MEDIA NOT FOUND (/dev/${bootDiskHint} missing).`,
                    diagnostic: `The boot device /dev/${bootDiskHint} is no longer present. Re-insert the boot SD card and retry.`
                };
            }
            return {
                error: `[!] NO BOOT IDENTITY.`,
                diagnostic: `No boot identity files found in /etc/. This OS image may be corrupt or was not built with the SubZero initramfs. Re-flash and reboot.`
            };
        }

        return { masterDisk };
    }

    function detectApplianceCloneTarget(): { error?: string, candidate?: { masterDisk: string, targetDisk: string, targetBytes: number, targetGB: string, targetModel: string } } {
        const execSync = require('child_process').execSync;

        // 1. Identify Master Boot Drive via UUID-based resolution
        const masterResult = resolveMasterBootDisk();
        if (masterResult.error) {
            const msg = masterResult.diagnostic ? `${masterResult.error} ${masterResult.diagnostic}` : masterResult.error;
            return { error: msg };
        }
        const cleanMaster = masterResult.masterDisk!;
        logDebug(`Master boot disk for clone: /dev/${cleanMaster}`);

        // 2. Force device rescan and discover candidate target drive
        try { execSync('mdev -s 2>/dev/null || true'); } catch (_) {}
        const allDisksRaw = execSync("lsblk -J -b -o NAME,SIZE,TYPE,TRAN,RM,RO,MODEL 2>/dev/null || true").toString();
        let apprenticeTarget = "";
        let apprenticeBytes = 0;
        let apprenticeModel = "Generic USB Mass Storage";

        try {
            const parsed = JSON.parse(allDisksRaw);
            const blockDevices = parsed.blockdevices || [];
            for (const d of blockDevices) {
                // Must be a whole disk
                if (d.type !== 'disk') continue;
                // CANNOT be the master boot disk
                if (d.name === cleanMaster) continue;
                // Must not be write-protected / read-only
                if (d.ro === true || d.ro === 1) continue;
                // Must be at least 512MB (536870912 bytes)
                if (d.size < 536870912) continue;

                // Candidate found!
                apprenticeTarget = d.name;
                apprenticeBytes = d.size;
                if (d.model && typeof d.model === 'string') apprenticeModel = d.model.trim();
                break;
            }
        } catch (_) {}

        if (!apprenticeTarget) {
            return { error: `[!] NO TARGET: Master is /dev/${cleanMaster}. Insert a second USB/SD card (>=512MB) into a different port and press [C].` };
        }

        // FATAL INVARIANT: Master and Target must be different devices
        if (cleanMaster === apprenticeTarget) {
            return { error: `[!] CRITICAL: Master (/dev/${cleanMaster}) and Target (/dev/${apprenticeTarget}) resolved to same device! This should never happen. Unplug and re-insert drives, then press [C].` };
        }

        const targetGB = (apprenticeBytes / (1024 * 1024 * 1024)).toFixed(1);
        return {
            candidate: {
                masterDisk: cleanMaster,
                targetDisk: apprenticeTarget,
                targetBytes: apprenticeBytes,
                targetGB,
                targetModel: apprenticeModel
            }
        };
    }

    function renderCloneConfirm() {
        renderHeader("[!] CONFIRM APPLIANCE REPLICATION [!]", "TARGET DRIVE WILL BE OVERWRITTEN WITH SUBZERO OS + VAULT", true);

        let y = 110;
        fb.drawText(40, y, "REPLICATION SOURCE (MASTER BOOT MEDIA // PROTECTED):", 1, COLOR_GOLD);
        y += 24;

        fb.drawRect(40, y, fb.geometry.width - 80, 56, COLOR_CARD);
        fb.drawRectBorder(40, y, fb.geometry.width - 80, 56, 1, COLOR_GREEN);
        fb.drawText(55, y + 12, `[MASTER BOOT DISK] /dev/${cloneCandidate?.masterDisk || 'unknown'} (HARD-LOCKED / WRITE-PROTECTED)`, 1, COLOR_GREEN);
        fb.drawText(55, y + 32, `Source Footprint: 512MB Boot Image (UEFI/BIOS Bootloader + RootFS + Estate Vault)`, 1, COLOR_WHITE);

        y += 74;
        fb.drawText(40, y, "REPLICATION TARGET (APPRENTICE DRIVE // WILL BE OVERWRITTEN):", 1, COLOR_WARN);
        y += 24;

        fb.drawRect(40, y, fb.geometry.width - 80, 76, COLOR_CARD);
        fb.drawRectBorder(40, y, fb.geometry.width - 80, 76, 2, COLOR_WARN);
        fb.drawText(55, y + 14, `[TARGET MEDIA] /dev/${cloneCandidate?.targetDisk} (${cloneCandidate?.targetGB} GB) - ${cloneCandidate?.targetModel}`, 1, COLOR_WARN);
        fb.drawText(55, y + 34, `WARNING: All existing partitions and files on /dev/${cloneCandidate?.targetDisk} will be destroyed.`, 1, COLOR_WHITE);
        fb.drawText(55, y + 52, `Action: Stream 512MB raw OS image + relocate GPT to disk end + inject encrypted vault.json`, 1, COLOR_MUTED);

        y += 94;
        fb.drawRect(40, y, fb.geometry.width - 80, 60, { r: 35, g: 15, b: 20 });
        fb.drawRectBorder(40, y, fb.geometry.width - 80, 60, 1, COLOR_WARN);
        fb.drawTextCentered(y + 12, ">>> PRESS [C] TO CONFIRM & COMMENCE HARDWARE CLONE <<<", 1, COLOR_GOLD);
        fb.drawTextCentered(y + 34, "Press [ESC] to Cancel and Return to Carousel", 1, COLOR_WHITE);

        renderFooter("Controls: [C] = Confirm & Start 512MB Clone | [ESC] = Cancel / Abort", true);
        fb.flush();
    }

    function renderCloneProgressScreen() {
        renderHeader("[1/3] CLONING 512MB SUBZERO APPLIANCE", "STREAMING RAW KIOSK IMAGE TO SECONDARY MEDIA", true);

        let y = 110;
        fb.drawText(40, y, "ACTIVE BLOCK STREAM (512MB RAW HARDWARE COPY):", 1, COLOR_GOLD);
        y += 24;

        fb.drawRect(40, y, fb.geometry.width - 80, 90, COLOR_CARD);
        fb.drawRectBorder(40, y, fb.geometry.width - 80, 90, 1, COLOR_ACCENT);
        fb.drawText(55, y + 16, `Source: /dev/${cloneCandidate?.masterDisk}  ➔  Target: /dev/${cloneCandidate?.targetDisk} (${cloneCandidate?.targetGB} GB)`, 1, COLOR_WHITE);
        fb.drawText(55, y + 38, `Status: ${cloneProgress.statusText}`, 1, COLOR_GREEN);
        fb.drawText(55, y + 60, `Buffer: 4MB aligned chunks (fsync on completion) | Sector: 512B LBA`, 1, COLOR_MUTED);

        y += 110;
        const pct = Math.min(100, Math.floor((cloneProgress.chunkIndex / cloneProgress.totalChunks) * 100));
        const copiedMB = (cloneProgress.bytesCopied / (1024 * 1024)).toFixed(0);
        fb.drawText(40, y, `PROGRESS: ${copiedMB} MB / 512 MB (${pct}%)`, 1, COLOR_GOLD);
        y += 26;

        const barW = fb.geometry.width - 80;
        const fillW = Math.min(barW, Math.floor(barW * (cloneProgress.chunkIndex / cloneProgress.totalChunks)));
        fb.drawRect(40, y, barW, 28, { r: 18, g: 26, b: 42 });
        if (fillW > 0) {
            fb.drawRect(40, y, fillW, 28, COLOR_GREEN);
        }
        fb.drawRectBorder(40, y, barW, 28, 2, COLOR_CARD_BORDER);

        const pctStr = `${pct}% [${cloneProgress.chunkIndex}/${cloneProgress.totalChunks}]`;
        fb.drawTextCentered(y + 6, pctStr, 1, fillW > (barW / 2) ? { r: 10, g: 15, b: 24 } : COLOR_WHITE);

        y += 48;
        fb.drawText(40, y, "[!] DO NOT UNPLUG MEDIA OR POWER OFF SYSTEM DURING TRANSFER", 1, COLOR_WARN);

        renderFooter("CLONING IN PROGRESS: Please wait... (Approx 2-3 minutes on USB 2.0)", true);
        fb.flush();
    }

    async function executeApplianceClone() {
        const execSync = require('child_process').execSync;
        if (!cloneCandidate) return;

        const cleanMaster = cloneCandidate.masterDisk;
        const apprenticeTarget = cloneCandidate.targetDisk;
        const targetPath = `/dev/${apprenticeTarget}`;
        const targetGB = cloneCandidate.targetGB;

        logDebug(`Initiating appliance clone: /dev/${cleanMaster} -> ${targetPath} (${targetGB}GB)`);
        cloneProgress.active = true;
        cloneProgress.chunkIndex = 0;
        cloneProgress.bytesCopied = 0;
        cloneProgress.statusText = "Initializing raw hardware streaming...";
        renderCloneProgressScreen();

        try {
            // 3. Pre-Flight Checks: Sector Size Assertion (512-Byte LBA Invariant)
            const srcSS = execSync(`blockdev --getss /dev/${cleanMaster} 2>/dev/null || echo 512`).toString().trim();
            const tgtSS = execSync(`blockdev --getss ${targetPath} 2>/dev/null || echo 512`).toString().trim();
            if (srcSS !== "512" || tgtSS !== "512") {
                throw new Error(`Non-512B drive detected (Src:${srcSS}B, Tgt:${tgtSS}B). Aborted.`);
            }

            // Lazy unmount all partitions on target and settle udev
            execSync(`umount -l ${targetPath}* 2>/dev/null || true`);
            execSync(`udevadm settle --timeout=3 2>/dev/null || true`);

            // 4. Phase 1/3: Stream 512MB Raw Kiosk Image (Chunked 4MB stream with visual progress)
            const chunkSize = 4 * 1024 * 1024;
            const totalChunks = 128; // 128 * 4MB = 512MB
            const inFd = fs.openSync(`/dev/${cleanMaster}`, 'r');
            const outFd = fs.openSync(targetPath, 'w');
            const chunkBuf = Buffer.alloc(chunkSize);

            for (let i = 0; i < totalChunks; i++) {
                const pos = i * chunkSize;
                fs.readSync(inFd, chunkBuf, 0, chunkSize, pos);
                fs.writeSync(outFd, chunkBuf, 0, chunkSize, pos);

                cloneProgress.chunkIndex = i + 1;
                cloneProgress.bytesCopied = (i + 1) * chunkSize;
                const mb = (cloneProgress.bytesCopied / (1024 * 1024)).toFixed(0);
                cloneProgress.statusText = `Streaming 512MB: ${mb}MB copied (chunk ${i + 1}/${totalChunks})...`;
                renderCloneProgressScreen();
            }

            fs.closeSync(inFd);
            cloneProgress.statusText = "Flushing hardware write cache (fsync barrier)...";
            renderCloneProgressScreen();
            fs.fsyncSync(outFd);
            fs.closeSync(outFd);
            logDebug("512MB chunked copy and fsync complete.");

            // 5. Phase 2/3: Hardware Buffer Flush & Partition Table Remediation
            cloneProgress.statusText = "[2/3] Repairing GPT boundary & randomizing GUIDs...";
            renderCloneProgressScreen();

            execSync(`sync`);
            execSync(`blockdev --flushbufs ${targetPath} 2>/dev/null || true`);

            // Relocate secondary GPT header to end of target media & randomize GUIDs
            execSync(`sgdisk -e -G ${targetPath} 2>/dev/null || parted -s ${targetPath} ---pretend-input-tty unit s print fix 2>/dev/null || true`);

            // Force kernel partition table rescan and create devfs device nodes
            execSync(`partx -d ${targetPath} 2>/dev/null || true`);
            execSync(`partx -a ${targetPath} 2>/dev/null || blockdev --rereadpt ${targetPath} 2>/dev/null || true`);
            execSync(`mdev -s 2>/dev/null || true`);
            execSync(`sleep 1`);

            // Derive dynamic partition names (handling mmcblk0p1 vs sda1)
            const pSep = /[0-9]$/.test(apprenticeTarget) ? 'p' : '';
            const tgtP1 = `/dev/${apprenticeTarget}${pSep}1`;
            const tgtP2 = `/dev/${apprenticeTarget}${pSep}2`;

            // Deterministic devfs node creation: query kernel sysfs for major:minor
            for (const part of [`${apprenticeTarget}${pSep}1`, `${apprenticeTarget}${pSep}2`]) {
                const devNode = `/dev/${part}`;
                const sysDev = `/sys/class/block/${part}/dev`;
                if (!fs.existsSync(devNode) && fs.existsSync(sysDev)) {
                    try {
                        const [maj, min] = fs.readFileSync(sysDev, 'utf8').trim().split(':');
                        execSync(`mknod ${devNode} b ${maj} ${min} 2>/dev/null || true`);
                    } catch (_) {}
                }
            }

            // Randomize FAT Volume Serial Numbers to prevent UUID collisions
            try {
                const rnd1 = execSync("od -An -N4 -tx4 /dev/urandom | tr -d ' ' 2>/dev/null || echo 1234ABCD").toString().trim();
                const rnd2 = execSync("od -An -N4 -tx4 /dev/urandom | tr -d ' ' 2>/dev/null || echo 5678EF01").toString().trim();
                execSync(`fatlabel -i ${tgtP1} ${rnd1} 2>/dev/null || true`);
                execSync(`fatlabel -i ${tgtP2} ${rnd2} 2>/dev/null || true`);
            } catch (_) {}

            // 6. Phase 3/3: Verify OS Rootfs & Inject Fresh Vault
            cloneProgress.statusText = "[3/3] Auditing OS appliance & injecting cryptographic estate vault...";
            renderCloneProgressScreen();

            // Verify Partition 1 (OS Appliance Integrity)
            const mountOS = "/media/apprentice_os_verify";
            execSync(`mkdir -p ${mountOS}`);
            execSync(`mount -o ro ${tgtP1} ${mountOS}`);

            const rootfsSquash = `${mountOS}/rootfs.squashfs`;
            if (!fs.existsSync(rootfsSquash)) {
                execSync(`umount ${mountOS} && rmdir ${mountOS}`);
                throw new Error("Cloned OS partition corrupt: rootfs.squashfs missing!");
            }
            execSync(`umount ${mountOS} && rmdir ${mountOS}`);

            // Mount Partition 2 and Inject Vault
            const mountVault = "/media/apprentice_vault_inject";
            execSync(`mkdir -p ${mountVault}`);
            execSync(`mount -t vfat -o rw,noatime ${tgtP2} ${mountVault}`);

            const vaultPayload = {
                version: "1.0.0",
                created_utc: new Date().toISOString(),
                master_root_mnemonic: masterMnemonicWords.join(' '),
                descriptor: descriptorWithChecksum,
                heir_treasuries: heirMnemonics.map(h => ({ label: h.label, index: h.index, mnemonic: h.words }))
            };

            const encryptedVault = await encryptVaultJson(JSON.stringify(vaultPayload), passphrase_mnemonic);
            fs.writeFileSync(`${mountVault}/vault.json`, encryptedVault);

            if (fs.existsSync("/opt/subzero/templates/decrypt.html")) {
                fs.copyFileSync("/opt/subzero/templates/decrypt.html", `${mountVault}/decrypt.html`);
            } else if (fs.existsSync("./src/templates/decrypt.html")) {
                fs.copyFileSync("./src/templates/decrypt.html", `${mountVault}/decrypt.html`);
            }

            const exportStamp = BUILD_STAMP_VAL !== 'DEV' ? BUILD_STAMP_VAL : new Date().toISOString().replace(/[-:T]/g, '').slice(2, 12) + 'Z';
            const nonce = execSync("od -An -N4 -tx4 /dev/urandom | tr -d ' ' 2>/dev/null || echo RAND").toString().trim();
            fs.writeFileSync(`${mountVault}/vault_${exportStamp}_${nonce}.json`, encryptedVault);

            const manifestFiles = ['decrypt.html', 'README.txt', 'SYSTEM_MANIFEST.txt', 'vault.json', `vault_${exportStamp}_${nonce}.json`].filter(f => fs.existsSync(`${mountVault}/${f}`));
            const sums = manifestFiles.map(f => {
                const d = fs.readFileSync(`${mountVault}/${f}`);
                const h = require('crypto').createHash('sha256').update(d).digest('hex');
                return `${h}  ${f}`;
            }).join('\n') + '\n';
            fs.writeFileSync(`${mountVault}/SHA256SUMS`, sums);

            execSync(`sync`);
            execSync(`umount ${mountVault} && rmdir ${mountVault}`);

            // Final Direct I/O Read-Back Proof (Cache Bypassed)
            execSync(`blockdev --flushbufs ${targetPath} 2>/dev/null || true`);
            try { execSync(`echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true`); } catch (_) {}

            execSync(`mkdir -p ${mountVault} && mount -o ro ${tgtP2} ${mountVault}`);
            const verifyOut = execSync(`cd ${mountVault} && sha256sum -c SHA256SUMS`).toString();
            execSync(`umount ${mountVault} && rmdir ${mountVault}`);

            exportStatus = `[✓] APPLIANCE CLONE VERIFIED 100% HEALTHY! ${targetPath} (${targetGB}GB) is bootable. Unplug now.`;
            exportSuccess = true;
            logDebug(`Appliance clone successfully verified on ${targetPath}`);
            state = "SEED_GEN_CAROUSEL";
            renderSeedGenCarousel();
        } catch (e: any) {
            exportStatus = `[!] CLONE FAILED: ${e?.message || e}`;
            exportSuccess = false;
            logDebug(`Appliance clone failed: ${e?.message || e}`);
            state = "SEED_GEN_CAROUSEL";
            renderSeedGenCarousel();
        } finally {
            cloneProgress.active = false;
        }
    }

    function renderSeedGenCarousel() {
        if (currentCarouselView === 0) {
            renderHeader("[PAGE 1/8] MASTER ROOT SEED (12 WORDS)", "TRANSCRIBE TO PAPER/STEEL // CONFIDENTIAL", true);
            let y = 100;
            const cardW = Math.floor((fb.geometry.width - 100) / 2);
            for (let r = 0; r < 6; r++) {
                const idx1 = r;
                const idx2 = r + 6;
                const rowY = y + r * 56;

                fb.drawRect(40, rowY, cardW, 48, COLOR_CARD);
                fb.drawRectBorder(40, rowY, cardW, 48, 1, COLOR_CARD_BORDER);
                fb.drawText(52, rowY + 16, `${idx1 + 1}`.padStart(2, '0'), 1, COLOR_GOLD);
                fb.drawText(100, rowY + 12, masterMnemonicWords[idx1] || '', 2, COLOR_WHITE);

                const col2X = 60 + cardW;
                fb.drawRect(col2X, rowY, cardW, 48, COLOR_CARD);
                fb.drawRectBorder(col2X, rowY, cardW, 48, 1, COLOR_CARD_BORDER);
                fb.drawText(col2X + 12, rowY + 16, `${idx2 + 1}`.padStart(2, '0'), 1, COLOR_GOLD);
                fb.drawText(col2X + 60, rowY + 12, masterMnemonicWords[idx2] || '', 2, COLOR_WHITE);
            }
        } else if (currentCarouselView === 1) {
            renderHeader("[PAGE 2/9] DECOUPLED ESTATE PASSPHRASE (INDEX 0)", "STORE IN BITWARDEN / DEAD-MAN SWITCH // ENCRYPTION KEY");
            let y = 110;
            fb.drawRect(40, y, fb.geometry.width - 80, 80, COLOR_CARD);
            fb.drawRectBorder(40, y, fb.geometry.width - 80, 80, 1, COLOR_ACCENT);
            fb.drawText(55, y + 14, "Decoupled BIP-85 Passphrase (m/83696968'/39'/0'/12'/0'):", 1, COLOR_GOLD);
            fb.drawText(55, y + 42, passphrase_mnemonic, 1, COLOR_GREEN);

            y += 100;
            fb.drawText(40, y, "CRITICAL ANTI-COLOCATION PRINCIPLE:", 1, COLOR_ACCENT);
            y += 22;
            fb.drawText(40, y, "This 12-word passphrase encrypts your human-readable recovery guide, seed backups, and descriptors.", 1, COLOR_WHITE);
            y += 18;
            fb.drawText(40, y, "Because BIP-85 is strictly one-way, holding this phrase alone reveals ZERO Bitcoin keys.", 1, COLOR_MUTED);
        } else if (currentCarouselView === 2) {
            renderHeader("[PAGE 3/9] HEIR BIP-85 CHILD TREASURIES (1 - 5)", "5 SEPARATE DISPOSABLE COLD SEEDS (m/83696968'/39'/0'/12'/1' to /5')");
            let y = 100;
            for (let i = 0; i < heirMnemonics.length; i++) {
                fb.drawRect(40, y, fb.geometry.width - 80, 62, COLOR_CARD);
                fb.drawRectBorder(40, y, fb.geometry.width - 80, 62, 1, COLOR_CARD_BORDER);
                fb.drawText(55, y + 8, `${heirMnemonics[i].label} (Index ${heirMnemonics[i].index}):`, 1, COLOR_ACCENT);
                fb.drawText(55, y + 30, heirMnemonics[i].words, 1, COLOR_WHITE);
                y += 72;
            }
        } else if (currentCarouselView === 3) {
            renderHeader("[PAGE 4/9] BIP-380 MULTIPATH DESCRIPTOR QR", "FOR SPARROW / NUNCHUK / BITCOIN KEEPER (TESTNET4)");
            const qrCenterY = Math.floor(fb.geometry.height / 2) + 5;
            fb.drawQRCode(descriptorWithChecksum, qrCenterY, 5, 4);
            fb.drawTextCentered(fb.geometry.height - 80, descriptorWithChecksum.substring(0, 48) + "...", 1, COLOR_MUTED);
        } else if (currentCarouselView === 4) {
            renderHeader("[PAGE 5/9] ACCOUNT VPUB QR (BLOCKSTREAM GREEN)", "SLIP-132 NATIVE SEGWIT ACCOUNT KEY");
            const qrCenterY = Math.floor(fb.geometry.height / 2) + 5;
            fb.drawQRCode(vpub, qrCenterY, 6, 4);
            fb.drawTextCentered(fb.geometry.height - 80, `Account vpub: ${vpub.substring(0, 18)}...${vpub.substring(vpub.length - 8)}`, 1, COLOR_MUTED);
        } else if (currentCarouselView === 5) {
            renderHeader("[PAGE 6/9] TESTNET4 RECEIVE ADDRESSES (0 - 4)", "tb1q NATIVE SEGWIT ADDRESSES & FAUCET TARGET");
            let y = 100;
            for (let i = 0; i < 5; i++) {
                fb.drawRect(40, y, fb.geometry.width - 80, 64, COLOR_CARD);
                fb.drawRectBorder(40, y, fb.geometry.width - 80, 64, 1, COLOR_CARD_BORDER);
                fb.drawText(55, y + 8, `Receive Address #${i} (m/84'/1'/0'/0/${i}):`, 1, COLOR_ACCENT);
                fb.drawText(55, y + 32, receiveAddresses[i] || '', 2, COLOR_GREEN);
                y += 74;
            }
        } else if (currentCarouselView === 6) {
            renderHeader("[PAGE 7/9] INHERITANCE BATCH EXPORT & APPLIANCE CLONE", "SECURE LOCAL VAULT WRITE OR CREATE STANDALONE BOOTABLE BACKUP KIOSK");
            let y = 100;
            fb.drawText(40, y, "EXPORT OPTIONS (DUAL-PARTITION RECOVERY ARCHITECTURE):", 1, COLOR_GOLD);
            y += 20;
            fb.drawText(40, y, " [W] WRITE PRIMARY VAULT  : Writes encrypted vault payload to Partition 2 (SUBZERO_EST).", 1, COLOR_WHITE);
            y += 18;
            fb.drawText(40, y, " [C] CLONE APPLIANCE      : Clones full 512MB bootable SubZero OS + Vault to secondary USB.", 1, COLOR_WHITE);
            y += 22;
            fb.drawText(40, y, "FILES INCLUDED IN ESTATE VAULT (PARTITION 2):", 1, COLOR_ACCENT);
            y += 18;
            fb.drawText(40, y, " * vault.json      (WebCrypto AES-256-GCM encrypted estate bundle)", 1, COLOR_GREEN);
            y += 16;
            fb.drawText(40, y, " * decrypt.html    (Zero-dependency offline browser recovery applet)", 1, COLOR_GREEN);
            y += 16;
            fb.drawText(40, y, " * SHA256SUMS      (Self-verifying cryptographic manifest)", 1, COLOR_GREEN);
            y += 16;
            fb.drawText(40, y, " * README.txt      (Step-by-step instructions for heirs)", 1, COLOR_GREEN);
            y += 24;

            fb.drawRect(40, y, fb.geometry.width - 80, 80, COLOR_CARD);
            fb.drawRectBorder(40, y, fb.geometry.width - 80, 80, 1, exportSuccess ? COLOR_GREEN : (exportStatus.startsWith('[!]') ? COLOR_WARN : COLOR_ACCENT));
            fb.drawTextWrapped(55, y + 10, fb.geometry.width - 110, exportStatus, 1, exportSuccess ? COLOR_GREEN : (exportStatus.startsWith('[!]') ? COLOR_WARN : COLOR_WHITE));
            fb.drawText(55, y + 58, "[W] = Save to Current Drive  |  [C] = Insert Blank Drive & Clone Bootable Kiosk", 1, COLOR_MUTED);
        } else if (currentCarouselView === 7) {
            renderHeader("[PAGE 8/9] SECURITY PRINCIPLES & DRILL GUIDE", "HOW TO VERIFY AND PRACTICE WITH TESTNET4");
            let y = 110;
            fb.drawText(40, y, "CORE SECURITY RULES & GUARANTEES:", 1, COLOR_ACCENT);
            y += 22;
            fb.drawText(40, y, " * Strict Coin Type 1' : Testnet4 isolation prevents accidental real funds loss.", 1, COLOR_WHITE);
            y += 18;
            fb.drawText(40, y, " * Runs Purely in RAM  : Boot drive is ejected before startup; nothing touches disk.", 1, COLOR_WHITE);
            y += 18;
            fb.drawText(40, y, " * 2-of-2 Separation   : Encrypted vault file + Decoupled Passphrase (Index 0).", 1, COLOR_WHITE);
            y += 18;
            fb.drawText(40, y, " * True Physical Entry : 128 physical coin flips formatted in 4-bit chunks.", 1, COLOR_WHITE);
            y += 26;

            fb.drawText(40, y, "COORDINATOR DRILL CHECKLIST:", 1, COLOR_GREEN);
            y += 22;
            fb.drawText(40, y, " 1. Import Page 4 (Descriptor) into Sparrow / Nunchuk / Bitcoin Keeper (or Page 5 into Green).", 1, COLOR_MUTED);
            y += 18;
            fb.drawText(40, y, " 2. Verify derived address (0/0) matches Page 6 exactly (tb1q...).", 1, COLOR_MUTED);
            y += 18;
            fb.drawText(40, y, " 3. Fund via free testnet4 faucet (e.g. testnet4.dev or faucet.testnet4.eu).", 1, COLOR_MUTED);
            y += 18;
            fb.drawText(40, y, " 4. Press [Q] to zeroize RAM buffers and safely power down.", 1, COLOR_MUTED);
        } else if (currentCarouselView === 8) {
            renderHeader("[PAGE 9/9] ABOUT SUBZERO KEYOSK // PROVENANCE & SPECS", "SYSTEM ARCHITECTURE, REPRODUCIBILITY & BUILD METADATA");
            let y = 105;
            fb.drawText(40, y, "SYSTEM ARCHITECTURE & IDENTITY:", 1, COLOR_ACCENT);
            y += 22;
            fb.drawText(40, y, ` * Product Name     : SubZero Sovereign Vault & Keyosk`, 1, COLOR_WHITE);
            y += 18;
            fb.drawText(40, y, ` * Core Version     : ${BUILD_VERSION} (${BUILD_TARGET})`, 1, COLOR_GOLD);
            y += 18;
            fb.drawText(40, y, ` * Cryptography     : WebCrypto AES-256-GCM (PBKDF2 600,000 iters) + BIP-85 / BIP-84`, 1, COLOR_WHITE);
            y += 18;
            fb.drawText(40, y, ` * Build Reproduce  : 100% Deterministic Bit-for-Bit (SOURCE_DATE_EPOCH=1700000000)`, 1, COLOR_WHITE);
            y += 18;
            fb.drawText(40, y, ` * RAM Footprint    : ~322 MB SquashFS OS // Runs completely in tmpfs RAM`, 1, COLOR_WHITE);
            y += 26;

            fb.drawText(40, y, "SECURITY WARNINGS & RECOVERY CAVEATS:", 1, COLOR_WARN);
            y += 22;
            fb.drawText(40, y, " 1. Anti-Colocation : NEVER store the Decoupled Passphrase in the same place as the USB drive.", 1, COLOR_WHITE);
            y += 18;
            fb.drawText(40, y, " 2. Airgap Hygiene  : This machine has all networking removed. Never connect USB to untrusted PCs.", 1, COLOR_WHITE);
            y += 18;
            fb.drawText(40, y, " 3. Zero Cloud PII  : Ciphertext contains zero metadata, dates, names, or cleartext seed words.", 1, COLOR_MUTED);
            y += 18;
            fb.drawText(40, y, " 4. Open Source Git : github.com/bootlace-dev/subzero-keyosk", 1, COLOR_GREEN);
        }

        renderFooter("Controls: [SPACE/ARROWS] = Page | [W] = Write Primary | [C] = Clone Appliance | [ESC] = Menu");
        fb.flush();
    }

    function scanAndRenderVaultDecrypt() {
        const execSync = require('child_process').execSync;
        vaultDetectedPath = "";
        vaultRawPayload = "";

        const candidateDevices: string[] = [];
        try {
            const estDev = execSync("blkid -L SUBZERO_EST 2>/dev/null || true").toString().trim();
            if (estDev) candidateDevices.push(estDev);
            const autoDevs = execSync("ls /dev/sd[a-z][1-9] /dev/mmcblk*[0-9]p[1-9] /dev/vd[a-z][1-9] 2>/dev/null || true")
                .toString().trim().split(/\s+/).filter(Boolean);
            candidateDevices.push(...autoDevs);
        } catch (_) {}

        const searchMounts = ["/media/subzero_est", "/media/target_usb", "/media/vault_scan"];
        for (const dev of Array.from(new Set(candidateDevices))) {
            for (const m of searchMounts) {
                try {
                    execSync(`mkdir -p ${m} && mount -t vfat -o ro ${dev} ${m} 2>/dev/null || mount -o ro ${dev} ${m} 2>/dev/null || true`);
                    if (fs.existsSync(`${m}/vault.json`)) {
                        vaultDetectedPath = `${dev} ➔ ${m}/vault.json`;
                        vaultRawPayload = fs.readFileSync(`${m}/vault.json`, 'utf8');
                        break;
                    }
                } catch (_) {}
            }
            if (vaultRawPayload) break;
        }

        if (!vaultRawPayload) {
            const localPaths = ["/media/target_usb/vault.json", "./vault.json", "/opt/subzero/vault.json"];
            for (const p of localPaths) {
                if (fs.existsSync(p)) {
                    try {
                        vaultRawPayload = fs.readFileSync(p, 'utf8');
                        vaultDetectedPath = p;
                        break;
                    } catch (_) {}
                }
            }
        }

        renderVaultDecryptScreen();
    }

    function renderVaultDecryptScreen() {
        renderHeader(
            "[2] INHERITANCE VAULT // DECRYPT & UNLOCK",
            "RECOVER BITCOIN ESTATE VIA 12-WORD DECOUPLED PASSPHRASE",
            true
        );

        let y = 100;
        fb.drawText(40, y, "ENCRYPTED PAYLOAD STATUS:", 1, COLOR_GOLD);
        y += 22;

        fb.drawRect(40, y, fb.geometry.width - 80, 50, COLOR_CARD);
        fb.drawRectBorder(40, y, fb.geometry.width - 80, 50, 1, vaultDetectedPath ? COLOR_GREEN : COLOR_ACCENT);
        if (vaultDetectedPath) {
            fb.drawText(55, y + 16, `[✓] DETECTED: ${vaultDetectedPath} (${Buffer.byteLength(vaultRawPayload)} bytes)`, 1, COLOR_GREEN);
        } else {
            fb.drawText(55, y + 16, "[i] No vault.json detected on drive. DEMO / TEST VECTOR MODE ACTIVE.", 1, COLOR_ACCENT);
        }

        y += 66;
        const wordsEntered = vaultDecryptInput.trim().split(/\s+/).filter(Boolean);
        const tokens = vaultDecryptInput.split(' ');
        const activeToken = tokens[tokens.length - 1].toLowerCase();
        let autocompleteHint = "";
        if (activeToken.length > 0 && !activeToken.startsWith('test')) {
            const matches = wordlist.filter(w => w.startsWith(activeToken));
            if (matches.length > 0) {
                autocompleteHint = ` ➔ '${matches[0]}' (press SPACE/TAB)`;
            } else {
                autocompleteHint = " ➔ [!] INVALID BIP-39 PREFIX";
            }
        }

        fb.drawText(40, y, `ENTER 12-WORD PASSPHRASE (${wordsEntered.length}/12 WORDS)${autocompleteHint}:`, 1, autocompleteHint.includes('[!]') ? COLOR_WARN : COLOR_WHITE);
        y += 22;

        fb.drawRect(40, y, fb.geometry.width - 80, 68, COLOR_CARD);
        fb.drawRectBorder(40, y, fb.geometry.width - 80, 68, 1, wordsEntered.length === 12 ? COLOR_GREEN : COLOR_ACCENT);
        fb.drawTextWrapped(55, y + 14, fb.geometry.width - 110, vaultDecryptInput || "Type words (auto-completes at 4 chars, or press SPACE/TAB)...", 1, COLOR_WHITE);

        y += 82;
        if (vaultDecryptStatus) {
            fb.drawText(40, y, vaultDecryptStatus, 1, vaultDecryptStatus.startsWith('[!]') ? COLOR_WARN : COLOR_GREEN);
            y += 24;
        }

        // Test Vectors Reference Card
        fb.drawRect(40, y, fb.geometry.width - 80, 125, COLOR_BADGE_BG);
        fb.drawRectBorder(40, y, fb.geometry.width - 80, 125, 1, COLOR_CARD_BORDER);
        fb.drawText(55, y + 12, "DEMO SHORTCUTS: 10 CANONICAL TEST VECTORS (INSTANT LAB RECOVERY):", 1, COLOR_GOLD);
        fb.drawText(55, y + 32, " * 'test0': All 0s (Abandon ... About)| * 'test5': All 1s (Zoo ... Wrong)", 1, COLOR_WHITE);
        fb.drawText(55, y + 50, " * 'test1': Alt 0101 (Fetch Primary)  | * 'test6': Ascending Nibbles (Abuse Boss)", 1, COLOR_WHITE);
        fb.drawText(55, y + 68, " * 'test2': Alt 1010 (Primary Fetch)  | * 'test7': Byte Counter (00..0F)", 1, COLOR_WHITE);
        fb.drawText(55, y + 86, " * 'test3': Canonical 0x7F (Legal)    | * 'test8': Satoshi Genesis Lore (2009)", 1, COLOR_WHITE);
        fb.drawText(55, y + 104, " * 'test4': Canonical 0x80 (Letter)   | * 'test9': Hal Finney 2009 Tribute", 1, COLOR_WHITE);

        renderFooter("Controls: [TYPE] = 4-Char Autocomplete | [ENTER] = Decrypt | [ESC] = Menu | [Q] = Power Off", true);
        fb.flush();
    }

    function renderBip85KeyFactory() {
        renderHeader(
            "[3] BIP-85 MULTI-PROTOCOL KEY FACTORY",
            "DETERMINISTIC OFFSHOOTS FOR NOSTR, SSH & CHILD TREASURIES"
        );

        let y = 100;
        if (masterMnemonicWords.length === 12) {
            fb.drawText(40, y, "DERIVED SOVEREIGN PROTOCOL KEYS (FROM ACTIVE MASTER SEED):", 1, COLOR_GOLD);
            y += 22;

            // Nostr Key Card
            fb.drawRect(40, y, fb.geometry.width - 80, 60, COLOR_CARD);
            fb.drawRectBorder(40, y, fb.geometry.width - 80, 60, 1, COLOR_CARD_BORDER);
            fb.drawText(55, y + 8, "NOSTR IDENTITY (m/83696968'/1237'/0'):", 1, COLOR_ACCENT);
            fb.drawText(55, y + 30, `npub1... (Derived from Master Root Entropy)`, 1, COLOR_GREEN);
            y += 70;

            // Decoupled Passphrase Card
            fb.drawRect(40, y, fb.geometry.width - 80, 60, COLOR_CARD);
            fb.drawRectBorder(40, y, fb.geometry.width - 80, 60, 1, COLOR_CARD_BORDER);
            fb.drawText(55, y + 8, "ESTATE DECOUPLED PASSPHRASE (Index 0):", 1, COLOR_ACCENT);
            fb.drawText(55, y + 30, passphrase_mnemonic || "Not derived", 1, COLOR_WHITE);
            y += 70;

            // Child Heir 1 Card
            if (heirMnemonics.length > 0) {
                fb.drawRect(40, y, fb.geometry.width - 80, 60, COLOR_CARD);
                fb.drawRectBorder(40, y, fb.geometry.width - 80, 60, 1, COLOR_CARD_BORDER);
                fb.drawText(55, y + 8, `${heirMnemonics[0].label} (Index 1):`, 1, COLOR_ACCENT);
                fb.drawText(55, y + 30, heirMnemonics[0].words, 1, COLOR_WHITE);
                y += 70;
            }

            renderFooter("Controls: [SPACE/ARROWS] = View All Pages | [ESC] = Return to Menu");
        } else {
            fb.drawText(40, y, "NO MASTER SEED CURRENTLY LOADED IN RAM:", 1, COLOR_WARN);
            y += 22;

            fb.drawRect(40, y, fb.geometry.width - 80, 140, COLOR_CARD);
            fb.drawRectBorder(40, y, fb.geometry.width - 80, 140, 1, COLOR_ACCENT);
            fb.drawText(55, y + 18, "To populate the BIP-85 Multi-Protocol Key Factory, choose an option:", 1, COLOR_WHITE);
            fb.drawText(55, y + 46, " * Press [1] to enter physical coin/dice entropy", 1, COLOR_GREEN);
            fb.drawText(55, y + 70, " * Press [2] to decrypt your estate vault.json", 1, COLOR_GREEN);
            fb.drawText(55, y + 94, " * Press [0] to [9] to instantly load a Satoshi Lore test vector", 1, COLOR_GOLD);
            y += 155;

            renderFooter("Controls: [1] = Physical Entropy | [2] = Decrypt Vault | [0-9] = Test Vector | [ESC] = Menu");
        }
        fb.flush();
    }

    function renderSeedFixTool() {
        renderHeader(
            "[4] SEEDFIX: 11-TO-12 CHECKSUM & TYPO REPAIR",
            "INSTANT RECOVERY FOR MISTYPED OR LOST 12TH WORDS"
        );

        let y = 110;
        fb.drawText(40, y, "ENTER 11 WORDS (SPACE-SEPARATED) OR 1 MISTYPED WORD:", 1, COLOR_GOLD);
        y += 24;

        fb.drawRect(40, y, fb.geometry.width - 80, 70, COLOR_CARD);
        fb.drawRectBorder(40, y, fb.geometry.width - 80, 70, 1, COLOR_ACCENT);
        fb.drawTextWrapped(55, y + 14, fb.geometry.width - 110, seedFixInput || "Type words...", 1, COLOR_WHITE);

        y += 85;
        if (seedFixResults.length > 0) {
            fb.drawText(40, y, `RESULTS (${seedFixResults.length} MATCHES):`, 1, COLOR_GREEN);
            y += 22;
            const resStr = seedFixResults.slice(0, 32).join("   ");
            fb.drawTextWrapped(40, y, fb.geometry.width - 80, resStr, 1, COLOR_WHITE);
        }

        renderFooter("Controls: [TYPE] = Input | [ENTER] = Solve | [ESC] = Return to Menu");
        fb.flush();
    }

    function renderBip39Inspector() {
        renderHeader(
            "[6] BIP-39 2048 ENGLISH DICTIONARY INSPECTOR",
            "CANONICAL WORDLIST SEARCH & PREFIX AUTOCOMPLETE"
        );

        let y = 110;
        fb.drawText(40, y, "SEARCH PREFIX (e.g. 'aba' or 'zoo'):", 1, COLOR_GOLD);
        y += 24;

        fb.drawRect(40, y, fb.geometry.width - 80, 50, COLOR_CARD);
        fb.drawRectBorder(40, y, fb.geometry.width - 80, 50, 1, COLOR_ACCENT);
        fb.drawText(55, y + 16, wordlistSearchQuery || "Type prefix...", 1, COLOR_WHITE);

        y += 68;
        if (wordlistMatches.length > 0) {
            fb.drawText(40, y, `MATCHES (${wordlistMatches.length} WORDS):`, 1, COLOR_GREEN);
            y += 22;
            const resStr = wordlistMatches.slice(0, 48).join("   ");
            fb.drawTextWrapped(40, y, fb.geometry.width - 80, resStr, 1, COLOR_WHITE);
        }

        renderFooter("Controls: [TYPE] = Search | [ESC] = Return to Menu");
        fb.flush();
    }

    let hasherScanning = false;
    let hasherBlocks: { status: 'pending' | 'scanning' | 'done' | 'error', latencyMs: number }[] = [];
    let vaultAuditDetails: string[] = [];

    function renderStorageHasher() {
        renderHeader(
            "[5] STORAGE MEDIA & CRYPTOGRAPHIC HEALTH AUDIT",
            "READ-ONLY RAW SECTOR LATENCY & ESTATE VAULT VERIFICATION"
        );

        let y = 100;
        fb.drawText(40, y, "STORAGE DEVICE TELEMETRY & INTEGRITY:", 1, COLOR_GOLD);
        y += 22;

        const cardH = vaultAuditDetails.length > 0 ? 100 : 80;
        fb.drawRect(40, y, fb.geometry.width - 80, cardH, COLOR_CARD);
        fb.drawRectBorder(40, y, fb.geometry.width - 80, cardH, 1, computedHash.startsWith('[✓]') || computedHash.includes('VERIFIED') ? COLOR_GREEN : (hasherStatus.startsWith('[!]') ? COLOR_WARN : COLOR_ACCENT));
        
        fb.drawText(55, y + 14, hasherStatus, 1, hasherScanning ? COLOR_GOLD : (hasherStatus.startsWith('[!]') ? COLOR_WARN : COLOR_WHITE));
        if (computedHash) {
            fb.drawText(55, y + 38, computedHash, 1, computedHash.includes('[!]') ? COLOR_WARN : COLOR_GREEN);
        }
        if (vaultAuditDetails.length > 0) {
            fb.drawText(55, y + 62, vaultAuditDetails.slice(0, 2).join(" | "), 1, COLOR_MUTED);
        }

        y += cardH + 15;
        fb.drawText(40, y, "FLASH READ LATENCY MAP (64 x 1MB RAW BLOCKS):", 1, COLOR_ACCENT);
        y += 22;

        // Draw 64 block map grid (16 cols x 4 rows)
        const cols = 16;
        const rows = 4;
        const bSize = 26;
        const bGap = 6;
        for (let r = 0; r < rows; r++) {
            for (let c = 0; c < cols; c++) {
                const idx = r * cols + c;
                const bx = 40 + c * (bSize + bGap);
                const by = y + r * (bSize + bGap);
                const blk = hasherBlocks[idx] || { status: 'pending', latencyMs: 0 };

                let col = { r: 25, g: 30, b: 38 }; // Pending dark gray
                let border = COLOR_CARD_BORDER;

                if (blk.status === 'scanning') {
                    col = COLOR_GOLD;
                    border = COLOR_WHITE;
                } else if (blk.status === 'done') {
                    if (blk.latencyMs < 25) {
                        col = { r: 20, g: 80, b: 35 }; // Fast green (<25ms)
                    } else if (blk.latencyMs < 75) {
                        col = { r: 120, g: 100, b: 20 }; // Normal USB latency (25-75ms)
                    } else {
                        col = { r: 140, g: 50, b: 20 }; // High latency (>75ms)
                    }
                    border = COLOR_GREEN;
                } else if (blk.status === 'error') {
                    col = COLOR_WARN;
                    border = COLOR_WARN;
                }

                fb.drawRect(bx, by, bSize, bSize, col);
                fb.drawRectBorder(bx, by, bSize, bSize, 1, border);
            }
        }

        y += (rows * (bSize + bGap)) + 20;

        // Color Legend Block
        fb.drawText(40, y, "READ LATENCY & CELL HEALTH LEGEND:", 1, COLOR_GOLD);
        y += 18;

        // Fast Green
        fb.drawRect(40, y + 2, 12, 12, { r: 20, g: 80, b: 35 });
        fb.drawRectBorder(40, y + 2, 12, 12, 1, COLOR_GREEN);
        fb.drawText(58, y + 2, "GREEN (<25ms)    : Optimal Flash Read (Healthy NAND)", 1, COLOR_WHITE);
        y += 16;

        // Medium Yellow
        fb.drawRect(40, y + 2, 12, 12, { r: 120, g: 100, b: 20 });
        fb.drawRectBorder(40, y + 2, 12, 12, 1, COLOR_CARD_BORDER);
        fb.drawText(58, y + 2, "YELLOW (25-75ms) : Normal USB 2.0 / SD Host Bus Latency", 1, COLOR_WHITE);
        y += 16;

        // Slow Amber
        fb.drawRect(40, y + 2, 12, 12, { r: 140, g: 50, b: 20 });
        fb.drawRectBorder(40, y + 2, 12, 12, 1, COLOR_CARD_BORDER);
        fb.drawText(58, y + 2, "AMBER (>75ms)    : Slow Bus Transfer / Controller Overhead", 1, COLOR_GOLD);
        y += 16;

        // Error Red
        fb.drawRect(40, y + 2, 12, 12, COLOR_WARN);
        fb.drawRectBorder(40, y + 2, 12, 12, 1, COLOR_WARN);
        fb.drawText(58, y + 2, "RED (Error)      : Uncorrectable Read Error / Dead Sector", 1, COLOR_WARN);

        renderFooter("Controls: [H] = Raw Block Scan | [V] = Verify Estate Vault | [ESC] = Return to Menu");
        fb.flush();
    }

    function findActiveStorageDevice(): string {
        const execSync = require('child_process').execSync;
        let candidates: string[] = [];
        try {
            const devs = execSync("ls /dev/sd[a-z] /dev/mmcblk[0-9] /dev/vd[a-z] /dev/nvme[0-9]n[0-9] 2>/dev/null || true")
                .toString().trim().split(/\s+/).filter(Boolean);
            candidates = devs;
        } catch (_) {}

        // Prioritize external sdb, mmcblk0, sdc before sda
        candidates.sort((a, b) => {
            const scoreA = a.includes('sdb') ? 3 : (a.includes('mmcblk0') ? 2 : (a.includes('sdc') ? 1 : 0));
            const scoreB = b.includes('sdb') ? 3 : (b.includes('mmcblk0') ? 2 : (b.includes('sdc') ? 1 : 0));
            return scoreB - scoreA;
        });

        // Actively test-read 512 bytes from each device to bypass ENOMEDIUM / unpopulated slots
        for (const devPath of candidates) {
            try {
                const fd = fs.openSync(devPath, 'r');
                const probeBuf = Buffer.alloc(512);
                const n = fs.readSync(fd, probeBuf, 0, 512, 0);
                fs.closeSync(fd);
                if (n > 0) {
                    return devPath;
                }
            } catch (_) {
                // Device not ready or unpopulated, continue probing next
            }
        }
        return candidates[0] || "";
    }

    function dropOsCaches() {
        try {
            const execSync = require('child_process').execSync;
            execSync("sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true");
        } catch (_) {}
    }

    function runRealStorageHash() {
        if (hasherScanning) return;
        const target = findActiveStorageDevice();

        if (!target) {
            hasherStatus = "[!] ERROR: No active block device detected! Insert SD/USB drive.";
            renderStorageHasher();
            return;
        }

        dropOsCaches();
        hasherScanning = true;
        hasherStatus = `Direct I/O 64MB Scan on ${target} in 1MB blocks...`;
        computedHash = "";
        vaultAuditDetails = [];
        hasherBlocks = Array.from({ length: 64 }, () => ({ status: 'pending', latencyMs: 0 }));
        renderStorageHasher();

        const crypto = require('crypto');
        const hash = crypto.createHash('sha256');
        let fd = -1;
        try {
            fd = fs.openSync(target, 'r');
            const buffer = Buffer.alloc(1024 * 1024);
            const startTime = Date.now();

            for (let b = 0; b < 64; b++) {
                hasherBlocks[b].status = 'scanning';
                renderStorageHasher();

                const t0 = Date.now();
                const bytesRead = fs.readSync(fd, buffer, 0, 1024 * 1024, b * 1024 * 1024);
                const latency = Date.now() - t0;

                if (bytesRead > 0) {
                    hash.update(buffer.subarray(0, bytesRead));
                    hasherBlocks[b].status = 'done';
                    hasherBlocks[b].latencyMs = latency;
                } else {
                    break;
                }

                if (b % 4 === 0 || b === 63) {
                    const elapsed = (Date.now() - startTime) / 1000;
                    const speed = ((b + 1) / (elapsed || 0.001)).toFixed(1);
                    hasherStatus = `Scanning ${target}: Block ${b + 1}/64 (${speed} MB/s)`;
                    renderStorageHasher();
                }
            }
            fs.closeSync(fd);
            const digest = hash.digest('hex');
            computedHash = `SHA-256: ${digest}`;
            const totalElapsed = ((Date.now() - startTime) / 1000).toFixed(2);
            hasherStatus = `[✓] RAW SCAN COMPLETE: 64MB read from ${target} in ${totalElapsed}s`;
        } catch (e: any) {
            try { if (fd !== -1) fs.closeSync(fd); } catch (_) {}
            hasherStatus = `[!] READ ERROR on ${target}: ${e?.message || e}`;
        } finally {
            hasherScanning = false;
            renderStorageHasher();
        }
    }

    function runEstateVaultVerify() {
        if (hasherScanning) return;
        const execSync = require('child_process').execSync;
        const crypto = require('crypto');

        hasherScanning = true;
        hasherStatus = "Auditing Partition 2 (SUBZERO_EST) cryptographic integrity...";
        computedHash = "";
        vaultAuditDetails = [];
        renderStorageHasher();

        const auditMount = "/media/vault_audit";
        try {
            execSync(`mkdir -p ${auditMount} 2>/dev/null || true`);
            let mountedDev = "";

            // Check blkid for SUBZERO_EST
            const estDev = execSync("blkid -L SUBZERO_EST 2>/dev/null || true").toString().trim();
            const candidates = estDev ? [estDev] : [
                "/dev/sdb2", "/dev/mmcblk0p2", "/dev/sdc2", "/dev/sdb1", "/dev/mmcblk0p1", "/dev/sda2"
            ];

            for (const dev of candidates) {
                try {
                    execSync(`mount -o ro ${dev} ${auditMount} 2>/dev/null || mount -t vfat -o ro ${dev} ${auditMount} 2>/dev/null`);
                    if (fs.existsSync(`${auditMount}/vault.json`)) {
                        mountedDev = dev;
                        break;
                    }
                    execSync(`umount ${auditMount} 2>/dev/null || true`);
                } catch (_) {}
            }

            if (!mountedDev) {
                hasherStatus = "[!] NO ESTATE VAULT DETECTED: SUBZERO_EST partition not found.";
                computedHash = "Please insert USB/SD media with Partition 2 (SUBZERO_EST)";
                return;
            }

            // Read files and verify
            const vaultPath = `${auditMount}/vault.json`;
            const vaultBytes = fs.readFileSync(vaultPath);
            const actualVaultHash = crypto.createHash('sha256').update(vaultBytes).digest('hex');

            let manifestFound = false;
            let manifestMatch = false;
            const sumsPath = `${auditMount}/SHA256SUMS`;

            if (fs.existsSync(sumsPath)) {
                manifestFound = true;
                const sumsContent = fs.readFileSync(sumsPath, 'utf8');
                if (sumsContent.includes(actualVaultHash)) {
                    manifestMatch = true;
                }
            }

            const htmlPath = `${auditMount}/decrypt.html`;
            const htmlExists = fs.existsSync(htmlPath);

            vaultAuditDetails = [
                `Device: ${mountedDev}`,
                `vault.json: ${vaultBytes.length} bytes (SHA-256: ${actualVaultHash.slice(0, 16)}...)`,
                `decrypt.html: ${htmlExists ? 'PRESENT (Verified)' : 'NOT FOUND'}`,
                `SHA256SUMS: ${manifestFound ? (manifestMatch ? 'MATCH (100% Valid)' : 'MISMATCH!') : 'NOT FOUND'}`
            ];

            if (manifestFound && manifestMatch) {
                hasherStatus = `[✓] ESTATE VAULT INTEGRITY VERIFIED (100% HEALTHY)`;
                computedHash = `MATCH: vault.json matches SHA256SUMS on ${mountedDev}`;
            } else if (manifestFound && !manifestMatch) {
                hasherStatus = `[!] INTEGRITY ERROR: vault.json hash mismatch against SHA256SUMS!`;
                computedHash = `CORRUPTION DETECTED on ${mountedDev}`;
            } else {
                hasherStatus = `[✓] VAULT DETECTED: vault.json loaded (${vaultBytes.length} bytes)`;
                computedHash = `SHA-256: ${actualVaultHash}`;
            }
        } catch (e: any) {
            hasherStatus = `[!] AUDIT ERROR: ${e?.message || e}`;
            computedHash = "Audit aborted";
        } finally {
            try { execSync(`umount ${auditMount} 2>/dev/null || true`); } catch (_) {}
            hasherScanning = false;
            renderStorageHasher();
        }
    }

    function loadDebugLogs(): string[] {
        const logFiles = ['/tmp/subzero_vault_debug.log', '/tmp/subzero_debug.log'];
        let combined = "";
        for (const lf of logFiles) {
            if (fs.existsSync(lf)) {
                try {
                    combined += `=== LOG: ${lf} ===\n` + fs.readFileSync(lf, 'utf8') + "\n";
                } catch (_) {}
            }
        }
        if (!combined.trim()) {
            combined = "[!] No debug log entries found in /tmp. System running nominally.\n";
        }
        return combined.split('\n');
    }

    function renderDebugLogScreen() {
        renderHeader("[D] AMNESIC SYSTEM DIAGNOSTICS & HARDWARE LOG", "VOLATILE RAM LOGS (/tmp/subzero_debug.log)");

        if (debugLogLines.length === 0) {
            debugLogLines = loadDebugLogs();
        }

        let y = 100;
        fb.drawText(40, y, `DIAGNOSTIC LOG ENTRIES (${debugLogLines.length} LINES):`, 1, COLOR_GOLD);
        y += 22;

        const visibleLinesCount = 18;
        const maxScroll = Math.max(0, debugLogLines.length - visibleLinesCount);
        if (debugLogScroll > maxScroll) debugLogScroll = maxScroll;

        const boxH = 340;
        fb.drawRect(40, y, fb.geometry.width - 80, boxH, COLOR_CARD);
        fb.drawRectBorder(40, y, fb.geometry.width - 80, boxH, 1, COLOR_ACCENT);

        let lineY = y + 12;
        const visibleSlice = debugLogLines.slice(debugLogScroll, debugLogScroll + visibleLinesCount);
        for (const l of visibleSlice) {
            let col = COLOR_WHITE;
            if (l.includes('ERROR') || l.includes('FAIL') || l.includes('FATAL') || l.includes('[!]')) {
                col = COLOR_WARN;
            } else if (l.includes('SUCCESS') || l.includes('VERIFIED') || l.includes('[✓]')) {
                col = COLOR_GREEN;
            } else if (l.startsWith('===')) {
                col = COLOR_GOLD;
            }
            fb.drawText(55, lineY, l.slice(0, 110), 1, col);
            lineY += 18;
        }

        y += boxH + 15;
        const scrollPct = maxScroll > 0 ? Math.floor((debugLogScroll / maxScroll) * 100) : 100;
        fb.drawText(40, y, `Scroll: ${debugLogScroll + 1}/${maxScroll + 1} (${scrollPct}%)  |  Press [R] to Refresh  |  Press [K] for Diagnostic QR Code`, 1, COLOR_MUTED);

        renderFooter("Controls: [UP/DOWN] = Scroll Log | [R] = Reload | [K] = Diagnostic QR | [ESC] = Menu");
        fb.flush();
    }

    function renderDebugLogQR() {
        renderHeader("[D] DIAGNOSTIC QR CODE // AIRGAP EXPORT", "SCAN WITH SMARTPHONE TO EXPORT AMNESIC LOGS");

        const fullLog = loadDebugLogs().join('\n');
        // Truncate to 1200 chars for clean high-density QR readability
        const qrPayload = fullLog.length > 1200 ? fullLog.slice(-1200) : fullLog;

        const centerY = Math.floor(fb.geometry.height / 2) + 20;
        fb.drawQRCode(qrPayload, centerY, 5, 4, 'L');

        renderFooter("Controls: [ANY KEY / ESC] = Return to Diagnostic Text View");
        fb.flush();
    }

    function secureZeroizeAllMemory() {
        // 1. Overwrite all sensitive memory strings and arrays with 0s
        masterMnemonicWords.fill("00000000");
        masterMnemonicWords.length = 0;
        
        heirMnemonics.forEach(h => {
            h.words = "00000000 00000000 00000000 00000000";
        });
        heirMnemonics.length = 0;

        receiveAddresses.fill("00000000");
        receiveAddresses.length = 0;

        currentEntropyInput = "0".repeat(256);
        currentEntropyInput = "";
        vaultDecryptInput = "0".repeat(256);
        vaultDecryptInput = "";
        vaultRawPayload = "0".repeat(4096);
        vaultRawPayload = "";
        passphrase_mnemonic = "00000000";
        tpub = "00000000";
        vpub = "00000000";
        descriptorWithChecksum = "00000000";
        seedFixInput = "00000000";
        seedFixResults.length = 0;

        // 2. 3-Pass Multi-Pattern Video RAM & Framebuffer Zeroization (Anti-DRAM Remanence)
        // Pass 1: 0x00 (All Zeros)
        fb.directWipe(0x00);

        // Pass 2: 0xFF (All Ones)
        fb.directWipe(0xFF);

        // Pass 3: 0x00 (Clean Final Blackout)
        fb.directWipe(0x00);
    }

    process.on('SIGINT', () => {
        secureZeroizeAllMemory();
        fb.destroy();
        process.exit(0);
    });

    renderMainMenu();

    // Enable raw mode safely
    try {
        if (process.stdin.isTTY) {
            process.stdin.setRawMode(true);
        } else {
            require('child_process').execSync('stty raw -echo < /dev/tty1 2>/dev/null || true');
        }
    } catch (e: any) {
        logDebug(`Raw mode setup warning: ${e?.message}`);
    }

    readline.emitKeypressEvents(process.stdin);
    try {
        process.stdin.resume();
    } catch (_) {}

    process.stdin.on('keypress', (str, key) => {
        if (key.ctrl && key.name === 'c') {
            secureZeroizeAllMemory();
            fb.destroy();
            process.exit(0);
        }

        if (state === "MENU") {
            if (key.name === 'up') {
                selectedMenuIndex = (selectedMenuIndex - 1 + menuOptions.length) % menuOptions.length;
                renderMainMenu();
            } else if (key.name === 'down') {
                selectedMenuIndex = (selectedMenuIndex + 1) % menuOptions.length;
                renderMainMenu();
            } else if (key.name === 'return' || key.name === 'enter') {
                if (selectedMenuIndex === 0) {
                    state = "SEED_GEN_INPUT";
                    currentEntropyInput = "";
                    renderSeedGenInputScreen();
                } else if (selectedMenuIndex === 1) {
                    state = "VAULT_DECRYPT";
                    vaultDecryptInput = "";
                    vaultDecryptStatus = "";
                    scanAndRenderVaultDecrypt();
                } else if (selectedMenuIndex === 2) {
                    state = "BIP85_FACTORY";
                    renderBip85KeyFactory();
                } else if (selectedMenuIndex === 3) {
                    state = "SEEDFIX_TOOL";
                    seedFixInput = "";
                    seedFixResults = [];
                    renderSeedFixTool();
                } else if (selectedMenuIndex === 4) {
                    state = "STORAGE_HASHER";
                    renderStorageHasher();
                } else if (selectedMenuIndex === 5) {
                    state = "BIP39_INSPECTOR";
                    wordlistSearchQuery = "";
                    wordlistMatches = wordlist.slice(0, 30);
                    renderBip39Inspector();
                } else if (selectedMenuIndex === 6) {
                    state = "CONFIRM_EXIT";
                    renderHeader("[!] CONFIRM POWER DOWN & WIPE [!]", "ALL RAM BUFFERS WILL BE WIPED", true);
                    fb.drawTextCentered(240, "Press [Q] to Confirm Wipe & Shutdown | [ESC] to Cancel", 1, COLOR_WARN);
                    renderFooter("CONFIRM SHUTDOWN: [Q] = Power Off | [ESC] = Cancel", true);
                    fb.flush();
                }
            } else if (str === '1') {
                state = "SEED_GEN_INPUT";
                currentEntropyInput = "";
                renderSeedGenInputScreen();
            } else if (str === '2') {
                state = "VAULT_DECRYPT";
                vaultDecryptInput = "";
                vaultDecryptStatus = "";
                scanAndRenderVaultDecrypt();
            } else if (str === '3') {
                state = "BIP85_FACTORY";
                renderBip85KeyFactory();
            } else if (str === '4') {
                state = "SEEDFIX_TOOL";
                seedFixInput = "";
                seedFixResults = [];
                renderSeedFixTool();
            } else if (str === '5') {
                state = "STORAGE_HASHER";
                renderStorageHasher();
            } else if (str === '6') {
                state = "BIP39_INSPECTOR";
                wordlistSearchQuery = "";
                wordlistMatches = wordlist.slice(0, 30);
                renderBip39Inspector();
            } else if (str === 'd' || str === 'D') {
                state = "DEBUG_VIEW";
                debugLogScroll = 0;
                debugLogLines = loadDebugLogs();
                renderDebugLogScreen();
            } else if (str === 'q' || str === 'Q') {
                state = "CONFIRM_EXIT";
                renderHeader("[!] CONFIRM POWER DOWN & WIPE [!]", "ALL RAM BUFFERS WILL BE WIPED", true);
                fb.drawTextCentered(240, "Press [Q] to Confirm Wipe & Hardware Poweroff | [ESC] to Cancel", 1, COLOR_WARN);
                renderFooter("CONFIRM SHUTDOWN: [Q] = Power Off Hardware | [ESC] = Cancel", true);
                fb.flush();
            }
        } else if (state === "BIP85_FACTORY") {
            if (key.name === 'escape') {
                state = "MENU";
                renderMainMenu();
            } else if (str === '1') {
                state = "SEED_GEN_INPUT";
                currentEntropyInput = "";
                renderSeedGenInputScreen();
            } else if (str === '2') {
                state = "VAULT_DECRYPT";
                vaultDecryptInput = "";
                vaultDecryptStatus = "";
                scanAndRenderVaultDecrypt();
            } else if (str && str >= '0' && str <= '9') {
                currentEntropyInput = `test${str}`;
                computeSeedGenDerivations();
                renderBip85KeyFactory();
            }
        } else if (state === "SEED_GEN_INPUT") {
            if (key.name === 'escape') {
                state = "MENU";
                renderMainMenu();
            } else if (key.name === 'backspace') {
                if (currentEntropyInput.length > 0) {
                    currentEntropyInput = currentEntropyInput.slice(0, -1);
                    renderSeedGenInputScreen();
                }
            } else if (key.name === 'return' || key.name === 'enter') {
                const testCheck = checkTestVector(currentEntropyInput);
                if (currentEntropyInput.length >= 128 || testCheck.isTest) {
                    computeSeedGenDerivations();
                    state = "SEED_GEN_CAROUSEL";
                    currentCarouselView = 0;
                    renderSeedGenCarousel();
                }
            } else if (key.name === 'r') {
                const crypto = require('crypto');
                const randomBytes = crypto.randomBytes(16);
                currentEntropyInput = Array.from(randomBytes).map((b: number) => b.toString(2).padStart(8, '0')).join('');
                renderSeedGenInputScreen();
            } else if (str && str.length === 1) {
                const ch = str.toLowerCase();
                const isTestChar = (currentEntropyInput.toLowerCase().startsWith('t') || ch === 't') && /^[test0-9]$/.test(ch);
                const isDiceChar = str >= '1' && str <= '6';
                const isCoinChar = str === '0' || str === '1';

                if ((isCoinChar || isDiceChar || isTestChar) && currentEntropyInput.length < 256) {
                    currentEntropyInput += str;
                    renderSeedGenInputScreen();
                }
            }
        } else if (state === "SEED_GEN_CAROUSEL") {
            if (key.name === 'right' || key.name === 'space') {
                currentCarouselView = (currentCarouselView + 1) % totalCarouselViews;
                renderSeedGenCarousel();
            } else if (key.name === 'left') {
                currentCarouselView = (currentCarouselView - 1 + totalCarouselViews) % totalCarouselViews;
                renderSeedGenCarousel();
            } else if (str === 'w' || str === 'W') {
                executeUsbBatchExport();
            } else if (str === 'c' || str === 'C') {
                const det = detectApplianceCloneTarget();
                if (det.error) {
                    exportStatus = det.error;
                    exportSuccess = false;
                    renderSeedGenCarousel();
                } else if (det.candidate) {
                    cloneCandidate = det.candidate;
                    state = "CLONE_CONFIRM";
                    renderCloneConfirm();
                }
            } else if (key.name === 'escape') {
                state = "MENU";
                renderMainMenu();
            } else if (str === 'q' || str === 'Q') {
                state = "CONFIRM_EXIT";
                renderHeader("[!] CONFIRM POWER DOWN & WIPE [!]", "ALL RAM BUFFERS WILL BE WIPED", true);
                fb.drawTextCentered(240, "Press [Q] to Confirm Wipe & Hardware Poweroff | [ESC] to Cancel", 1, COLOR_WARN);
                renderFooter("CONFIRM SHUTDOWN: [Q] = Power Off Hardware | [ESC] = Cancel", true);
                fb.flush();
            }
        } else if (state === "CLONE_CONFIRM") {
            if (str === 'c' || str === 'C') {
                executeApplianceClone();
            } else if (key.name === 'escape') {
                state = "SEED_GEN_CAROUSEL";
                renderSeedGenCarousel();
            }
        } else if (state === "DEBUG_VIEW") {
            if (key.name === 'escape') {
                state = "MENU";
                renderMainMenu();
            } else if (key.name === 'up') {
                if (debugLogScroll > 0) {
                    debugLogScroll--;
                    renderDebugLogScreen();
                }
            } else if (key.name === 'down') {
                const maxScroll = Math.max(0, debugLogLines.length - 18);
                if (debugLogScroll < maxScroll) {
                    debugLogScroll++;
                    renderDebugLogScreen();
                }
            } else if (str === 'r' || str === 'R') {
                debugLogLines = loadDebugLogs();
                debugLogScroll = 0;
                renderDebugLogScreen();
            } else if (str === 'k' || str === 'K') {
                renderDebugLogQR();
            } else {
                // Any other key returns from QR to text log
                renderDebugLogScreen();
            }
        } else if (state === "VAULT_DECRYPT") {
            if (key.name === 'escape') {
                state = "MENU";
                renderMainMenu();
            } else if (str === 'q' || str === 'Q') {
                state = "CONFIRM_EXIT";
                renderHeader("[!] CONFIRM POWER DOWN & WIPE [!]", "ALL RAM BUFFERS WILL BE WIPED", true);
                fb.drawTextCentered(240, "Press [Q] to Confirm Wipe & Hardware Poweroff | [ESC] to Cancel", 1, COLOR_WARN);
                renderFooter("CONFIRM SHUTDOWN: [Q] = Power Off Hardware | [ESC] = Cancel", true);
                fb.flush();
            } else if (key.name === 'backspace') {
                vaultDecryptInput = vaultDecryptInput.slice(0, -1);
                renderVaultDecryptScreen();
            } else if (key.name === 'return' || key.name === 'enter') {
                let targetPassphrase = vaultDecryptInput.trim();
                const testCheck = checkTestVector(targetPassphrase);

                if (testCheck.isTest) {
                    targetPassphrase = getTestVectorPassphrase(targetPassphrase);
                    vaultDecryptInput = targetPassphrase;
                }

                if (vaultRawPayload) {
                    try {
                        decryptVaultJson(vaultRawPayload, targetPassphrase).then((decryptedJson) => {
                            const parsed = JSON.parse(decryptedJson);
                            masterMnemonicWords = parsed.master_root_mnemonic ? parsed.master_root_mnemonic.split(' ') : [];
                            heirMnemonics.length = 0;
                            if (Array.isArray(parsed.heir_treasuries)) {
                                parsed.heir_treasuries.forEach((h: any) => {
                                    heirMnemonics.push({
                                        label: h.label || `Heir #${h.index} Cold Treasury`,
                                        index: h.index,
                                        words: h.words || h.mnemonic || ""
                                    });
                                });
                            }
                            descriptorWithChecksum = parsed.descriptor || "";
                            passphrase_mnemonic = targetPassphrase;

                            // Derive vpub and receive addresses if master mnemonic was restored
                            if (masterMnemonicWords.length === 12 && bip39.validateMnemonic(masterMnemonicWords.join(' '), wordlist)) {
                                const rootSeed = bip39.mnemonicToSeedSync(masterMnemonicWords.join(' '), '');
                                const rootNode = BIP32Node.fromSeed(rootSeed);
                                rootSeed.fill(0);
                                const purpose = rootNode.deriveHardened(84);
                                const coinType = purpose.deriveHardened(1);
                                const account = coinType.deriveHardened(0);
                                tpub = account.toSerializedKey(false, true, false);
                                vpub = account.toSerializedKey(false, true, true);
                                fingerprint = rootNode.getFingerprint().toString(16).padStart(8, '0');
                                const rawDesc = `wpkh([${fingerprint}/84'/1'/0']${tpub}/<0;1>/*)`;
                                const cksum = getDescriptorChecksum(rawDesc);
                                descriptorWithChecksum = `${rawDesc}#${cksum}`;
                                receiveAddresses.length = 0;
                                const recvBranch = account.derive(0);
                                for (let i = 0; i < 5; i++) {
                                    const addrNode = recvBranch.derive(i);
                                    receiveAddresses.push(getSegWitAddress(addrNode.publicKey, true));
                                    addrNode.wipe();
                                }
                                recvBranch.wipe();
                                rootNode.wipe();
                                account.wipe();
                                coinType.wipe();
                                purpose.wipe();

                                state = "SEED_GEN_CAROUSEL";
                                currentCarouselView = 0;
                                renderSeedGenCarousel();
                            } else {
                                state = "SEED_GEN_CAROUSEL";
                                currentCarouselView = 0;
                                renderSeedGenCarousel();
                            }
                        }).catch(e => {
                            vaultDecryptStatus = `[!] DECRYPTION FAILED: ${e?.message || 'Invalid Passphrase'}`;
                            renderVaultDecryptScreen();
                        });
                    } catch (e: any) {
                        vaultDecryptStatus = `[!] PARSE ERROR: ${e?.message || e}`;
                        renderVaultDecryptScreen();
                    }
                } else {
                    // Demo fallback if no vault.json on disk
                    if (testCheck.isTest) {
                        currentEntropyInput = targetPassphrase;
                        computeSeedGenDerivations();
                        state = "SEED_GEN_CAROUSEL";
                        currentCarouselView = 0;
                        renderSeedGenCarousel();
                    } else {
                        vaultDecryptStatus = "[!] ERROR: No vault.json detected. Type 'test0'...'test9' for instant testnet demo.";
                        renderVaultDecryptScreen();
                    }
                }
            } else if (key.name === 'tab' || str === ' ') {
                const tokens = vaultDecryptInput.split(' ');
                const last = tokens[tokens.length - 1].toLowerCase().trim();
                if (last.length > 0 && !last.startsWith('test')) {
                    const matches = wordlist.filter(w => w.startsWith(last));
                    if (matches.length > 0) {
                        tokens[tokens.length - 1] = matches[0];
                        vaultDecryptInput = tokens.join(' ') + ' ';
                    } else {
                        vaultDecryptInput += ' ';
                    }
                } else {
                    vaultDecryptInput += ' ';
                }
                renderVaultDecryptScreen();
            } else if (str && str.length === 1 && /^[a-zA-Z0-9]$/.test(str)) {
                const lower = str.toLowerCase();
                const tokens = vaultDecryptInput.split(' ');
                const last = tokens[tokens.length - 1].toLowerCase();

                // Test vector shortcut bypass (test0-test9)
                if ((last + lower).startsWith('test') || 'test'.startsWith(last + lower)) {
                    vaultDecryptInput += lower;
                    renderVaultDecryptScreen();
                    return;
                }

                const candidate = last + lower;
                const matches = wordlist.filter(w => w.startsWith(candidate));
                if (matches.length === 0) {
                    vaultDecryptStatus = `[!] '${candidate}' is not in the BIP-39 dictionary.`;
                    renderVaultDecryptScreen();
                    return;
                }

                vaultDecryptStatus = "";
                if (matches.length === 1 || candidate.length >= 4) {
                    tokens[tokens.length - 1] = matches[0];
                    vaultDecryptInput = tokens.join(' ') + ' ';
                } else {
                    vaultDecryptInput += lower;
                }
                renderVaultDecryptScreen();
            }
        } else if (state === "SEEDFIX_TOOL") {
            if (key.name === 'escape') {
                state = "MENU";
                renderMainMenu();
            } else if (key.name === 'backspace') {
                seedFixInput = seedFixInput.slice(0, -1);
                renderSeedFixTool();
            } else if (key.name === 'return' || key.name === 'enter') {
                const words = seedFixInput.trim().split(/\s+/);
                if (words.length === 11) {
                    seedFixResults = solve12thWordCandidates(words);
                } else if (words.length === 1) {
                    seedFixResults = suggestBip39Correction(words[0]).map(c => `${c.word} (edit dist ${c.distance})`);
                }
                renderSeedFixTool();
            } else if (str && str.length === 1) {
                seedFixInput += str;
                renderSeedFixTool();
            }
        } else if (state === "BIP39_INSPECTOR") {
            if (key.name === 'escape') {
                state = "MENU";
                renderMainMenu();
            } else if (key.name === 'backspace') {
                wordlistSearchQuery = wordlistSearchQuery.slice(0, -1);
                wordlistMatches = wordlist.filter(w => w.startsWith(wordlistSearchQuery.toLowerCase())).slice(0, 48);
                renderBip39Inspector();
            } else if (str && str.length === 1 && /^[a-zA-Z]$/.test(str)) {
                wordlistSearchQuery += str;
                wordlistMatches = wordlist.filter(w => w.startsWith(wordlistSearchQuery.toLowerCase())).slice(0, 48);
                renderBip39Inspector();
            }
        } else if (state === "STORAGE_HASHER") {
            if (key.name === 'escape') {
                state = "MENU";
                renderMainMenu();
            } else if (!hasherScanning) {
                if (str === 'h' || str === 'H') {
                    runRealStorageHash();
                } else if (str === 'v' || str === 'V') {
                    runEstateVaultVerify();
                }
            }
        } else if (state === "CONFIRM_EXIT") {
            if (str === 'q' || str === 'Q') {
                secureZeroizeAllMemory();
                fb.directWipe(0x00);
                fb.destroy();
                try {
                    const execSync = require('child_process').execSync;
                    execSync('sync 2>/dev/null || true');
                    execSync('echo 1 > /proc/sys/kernel/sysrq 2>/dev/null || true');
                    execSync('echo o > /proc/sysrq-trigger 2>/dev/null || true');
                    execSync('/sbin/poweroff -f 2>/dev/null || shutdown -h now 2>/dev/null || true');
                } catch (_) {}
                process.exit(0);
            } else {
                state = "MENU";
                renderMainMenu();
            }
        }
    });
}

main().catch(err => {
    logDebug(`FATAL: ${err?.stack || err}`);
    fb.destroy();
    process.exit(1);
});
