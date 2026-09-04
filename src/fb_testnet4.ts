import * as readline from 'readline';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { hmac } from '@noble/hashes/hmac.js';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import {
    BIP32Node,
    getSegWitAddress,
    getDescriptorChecksum,
    runMarkovAudit,
    hasRepetitiveSubstrings
} from './crypto';
import { Framebuffer, RGB } from './framebuffer';

const COLOR_BG: RGB = { r: 10, g: 15, b: 24 };           // Deep dark navy (#0A0F18)
const COLOR_CARD: RGB = { r: 18, g: 26, b: 42 };         // Dark slate card (#121A2A)
const COLOR_CARD_BORDER: RGB = { r: 40, g: 55, b: 85 };  // Slate border (#283755)
const COLOR_BADGE_BG: RGB = { r: 25, g: 38, b: 62 };     // Badge background
const COLOR_WHITE: RGB = { r: 255, g: 255, b: 255 };      // Pure crisp white (#FFFFFF)
const COLOR_ACCENT: RGB = { r: 0, g: 200, b: 255 };      // Bright cyan (#00C8FF)
const COLOR_GOLD: RGB = { r: 255, g: 190, b: 40 };       // Amber gold (#FFBE28)
const COLOR_WARN: RGB = { r: 255, g: 80, b: 80 };        // Soft red warning (#FF5050)
const COLOR_MUTED: RGB = { r: 120, g: 140, b: 170 };     // Slate muted text (#788CAA)
declare const __BUILD_STAMP__: string;
declare const __GIT_SHA__: string;

const BUILD_STAMP_VAL = typeof __BUILD_STAMP__ !== 'undefined' ? __BUILD_STAMP__ : 'DEV';
const GIT_SHA_VAL = typeof __GIT_SHA__ !== 'undefined' ? __GIT_SHA__ : 'local';
const BUILD_VERSION = `v0.1.0-testnet4 [${BUILD_STAMP_VAL}]`;
const BUILD_TARGET = "x86_64 Generic PC (UEFI/BIOS)";
const PROVENANCE_HASH_SHORT = "3ff8cdb9";
const PROVENANCE_HASH_FULL = "3ff8cdb90f66a25880903a73b431cf0e1debff02e1731d2338c9199de903da41";

const fb = new Framebuffer();

function logDebug(msg: string) {
    try {
        const fs = require('fs');
        fs.appendFileSync('/tmp/subzero_debug.log', `[${new Date().toISOString()}] ${msg}\n`);
        try {
            const fd = fs.openSync('/dev/ttyS0', 'a');
            fs.writeSync(fd, `[SUBZERO_DEBUG] ${msg}\n`);
            fs.closeSync(fd);
        } catch (_) {}
    } catch (_) {}
}

process.on('uncaughtException', (err) => {
    logDebug(`UNCAUGHT EXCEPTION: ${err?.stack || err}`);
    fb.destroy();
    process.exit(1);
});

process.on('unhandledRejection', (reason) => {
    logDebug(`UNHANDLED REJECTION: ${reason}`);
    fb.destroy();
    process.exit(1);
});

async function main() {
    logDebug("Starting SubZero Keyosk (BIP-380 Descriptor QR & Safe Modal)...");
    
    try {
        process.stdout.write('\x1b[?25l');
    } catch (_) {}

    let currentInput = "";
    let state: "INPUT" | "CAROUSEL" | "CONFIRM_EXIT" = "INPUT";
    let currentView = 0;
    const totalViews = 9;

    // Cryptographic State Buffers
    let masterSeed: Uint8Array | null = null;
    const mnemonicWords: string[] = [];
    let tpub = "";
    let vpub = "";
    let fingerprint = "";
    let descChecksum = "";
    let descriptorWithChecksum = "";
    const receiveAddresses: string[] = [];
    const bip85Children: string[] = [];

    function renderHeader(title: string, subtitle: string, isAlert: boolean = false) {
        fb.clear(COLOR_BG);
        fb.drawRect(20, 18, fb.geometry.width - 40, 68, isAlert ? { r: 35, g: 20, b: 25 } : { r: 16, g: 24, b: 40 });
        fb.drawRect(20, 18, fb.geometry.width - 40, 2, isAlert ? COLOR_GOLD : COLOR_ACCENT);
        fb.drawRect(20, 84, fb.geometry.width - 40, 2, isAlert ? COLOR_GOLD : COLOR_ACCENT);

        fb.drawTextCentered(28, title, 1, isAlert ? COLOR_GOLD : COLOR_ACCENT);
        fb.drawTextCentered(54, subtitle, 1, COLOR_WHITE);
    }

    function renderFooter(navText: string, alert: boolean = false) {
        const footY = fb.geometry.height - 40;
        fb.drawRect(20, footY - 8, fb.geometry.width - 40, 36, alert ? { r: 40, g: 20, b: 25 } : { r: 16, g: 24, b: 40 });
        fb.drawRect(20, footY - 8, fb.geometry.width - 40, 1, alert ? COLOR_WARN : COLOR_CARD_BORDER);
        fb.drawTextCentered(footY, navText, 1, alert ? COLOR_WARN : COLOR_MUTED);
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

    function getSanitizedEntropy(raw: string): string {
        return raw.replace(/[\s,\-_]/g, '');
    }

    function formatChunkedEntropyLines(clean: string, isCoins: boolean): string[] {
        const lines: string[] = [];
        if (isCoins) {
            // Chunking into rows of 11 characters (4 4 3 format)
            let i = 0;
            while (i < clean.length) {
                const row = clean.substring(i, i + 11);
                let formatted = "";
                if (row.length <= 4) {
                    formatted = row;
                } else if (row.length <= 8) {
                    formatted = `${row.substring(0, 4)}  ${row.substring(4)}`;
                } else {
                    formatted = `${row.substring(0, 4)}  ${row.substring(4, 8)}  ${row.substring(8)}`;
                }
                lines.push(formatted);
                i += 11;
            }
        } else {
            // Chunking into rows of 10 characters (5 5 format for dice)
            let i = 0;
            while (i < clean.length) {
                const row = clean.substring(i, i + 10);
                let formatted = "";
                if (row.length <= 5) {
                    formatted = row;
                } else {
                    formatted = `${row.substring(0, 5)}  ${row.substring(5)}`;
                }
                lines.push(formatted);
                i += 10;
            }
        }
        return lines;
    }

    function renderInputScreen() {
        renderHeader(
            "[!] SUBZERO KEYOSK // TESTNET4 EDITION [!]",
            `AIRGAPPED PHYSICAL INTAKE // BUILD: ${PROVENANCE_HASH_SHORT} // COIN TYPE 1'`
        );

        let mode = 'WAITING FOR PHYSICAL INPUT';
        let bits = 0;
        let isCoins = false;
        const testCheck = checkTestVector(currentInput);
        const clean = getSanitizedEntropy(currentInput);
        const len = clean.length;

        if (testCheck.isTest) {
            mode = testCheck.label;
            bits = 128;
        } else if (len > 0) {
            const uniqueChars = new Set(clean.split(''));
            const hasBinOnly = Array.from(uniqueChars).every(c => c === '0' || c === '1');
            const hasDiceOnly = Array.from(uniqueChars).every(c => c >= '1' && c <= '6');

            if (hasBinOnly) {
                mode = 'BINARY (COIN FLIPS: 1 BIT / CHAR)';
                bits = len;
                isCoins = true;
            } else if (hasDiceOnly) {
                mode = 'DICE (BASE-6: 2.58 BITS / ROLL)';
                bits = Math.floor(len * 2.58496);
                isCoins = false;
            } else {
                mode = 'KEYBOARD INPUT';
                bits = len * 4;
            }
        }

        const markov = runMarkovAudit(clean);
        const repeats = hasRepetitiveSubstrings(clean);
        const isReady = testCheck.isTest || (bits >= 128 && markov.passed && !repeats);

        let y = 100;
        fb.drawText(40, y, "PHYSICAL ENTROPY GUIDELINES & BIAS CONDITIONING:", 1, COLOR_GOLD);
        y += 22;
        fb.drawText(40, y, " * Coins (0/1) : Min 128 flips (chunked 4 4 3 per row; extra flips conditioned via SHA-256)", 1, COLOR_MUTED);
        y += 18;
        fb.drawText(40, y, " * Dice  (1-6) : Min 50 rolls  (chunked 5 5 per row; extra rolls absorb physical die bias)", 1, COLOR_MUTED);
        y += 18;
        fb.drawText(40, y, " * Test Vectors: Type 'test0' through 'test9' for pre-funded live testnet4 wallets", 1, COLOR_MUTED);
        y += 26;

        // Input Box
        fb.drawRect(40, y, fb.geometry.width - 80, 150, COLOR_CARD);
        fb.drawRect(40, y, fb.geometry.width - 80, 1, isReady ? COLOR_GREEN : COLOR_ACCENT);

        if (testCheck.isTest) {
            fb.drawText(55, y + 18, currentInput.trim(), 2, COLOR_GREEN);
        } else if (currentInput.length > 0) {
            const lines = formatChunkedEntropyLines(clean, isCoins);
            let textY = y + 12;
            const maxVisibleLines = 6;
            const startIndex = Math.max(0, lines.length - maxVisibleLines);
            for (let li = startIndex; li < lines.length; li++) {
                fb.drawText(55, textY, lines[li], 1, isReady ? COLOR_GREEN : COLOR_WHITE);
                textY += 22;
            }
        } else {
            fb.drawText(55, y + 16, "Waiting for physical coin flips (0/1), dice rolls (1-6), or 'test0'...", 1, COLOR_MUTED);
        }

        y += 162;
        fb.drawText(40, y, `Mode: ${mode}`, 1, COLOR_ACCENT);
        y += 22;
        fb.drawText(40, y, `Entropy: ${bits} / 128 bits`, 1, bits >= 128 ? COLOR_GREEN : COLOR_WARN);
        fb.drawText(340, y, `Markov Audit: ${markov.passed ? "PASS" : "FAIL"}`, 1, markov.passed ? COLOR_GREEN : COLOR_WARN);
        fb.drawText(620, y, `Repetition: ${!repeats ? "PASS" : "FAIL"}`, 1, !repeats ? COLOR_GREEN : COLOR_WARN);

        y += 28;
        const barW = fb.geometry.width - 80;
        const progressFrac = Math.min(1.0, bits / 128.0);
        const fillW = Math.floor(barW * progressFrac);
        fb.drawRect(40, y, barW, 14, { r: 20, g: 30, b: 45 });
        if (fillW > 0) {
            fb.drawRect(40, y, fillW, 14, isReady ? COLOR_GREEN : COLOR_ACCENT);
        }
        fb.drawRect(40, y, barW, 1, COLOR_CARD_BORDER);

        y += 26;
        if (isReady) {
            fb.drawRect(40, y, fb.geometry.width - 80, 44, { r: 15, g: 45, b: 25 });
            fb.drawRect(40, y, fb.geometry.width - 80, 1, COLOR_GREEN);
            fb.drawTextCentered(y + 14, ">>> 128-BIT ENTROPY QUALITY GATE PASSED -- PRESS [ENTER] TO PROCESS <<<", 1, COLOR_GREEN);
        } else {
            fb.drawRect(40, y, fb.geometry.width - 80, 44, { r: 35, g: 25, b: 15 });
            fb.drawRect(40, y, fb.geometry.width - 80, 1, COLOR_GOLD);
            const needed = Math.max(0, 128 - bits);
            fb.drawTextCentered(y + 14, `[!] Need ${needed} more bits of physical entropy before proceeding [!]`, 1, COLOR_GOLD);
        }

        renderFooter("Controls: [0/1 Coins] [1-6 Dice] | [ESC] = Clear | [ENTER] = Process | [CTRL+C] = Exit");
        fb.flush();
    }

    function computeDerivations(entropyRaw: string) {
        let finalEntropy: Uint8Array;
        const testCheck = checkTestVector(entropyRaw);
        const lower = entropyRaw.trim().toLowerCase();

        if (lower === 'test' || lower === 'test0') {
            finalEntropy = new Uint8Array(16).fill(0x00);
        } else if (lower === 'test1') {
            finalEntropy = new Uint8Array(16).fill(0x55);
        } else if (lower === 'test2') {
            finalEntropy = new Uint8Array(16).fill(0xAA);
        } else if (lower === 'test3') {
            finalEntropy = new Uint8Array(16).fill(0x7F);
        } else if (lower === 'test4') {
            finalEntropy = new Uint8Array(16).fill(0x80);
        } else if (lower === 'test5') {
            finalEntropy = new Uint8Array(16).fill(0xFF);
        } else if (lower === 'test6') {
            finalEntropy = Uint8Array.from([0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef]);
        } else if (lower === 'test7') {
            finalEntropy = Uint8Array.from([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]);
        } else if (lower === 'test8') {
            finalEntropy = sha256(new TextEncoder().encode("The Times 03/Jan/2009 Chancellor on brink of second bailout for banks")).slice(0, 16);
        } else if (lower === 'test9') {
            finalEntropy = sha256(new TextEncoder().encode("Running bitcoin - Hal Finney 10 Jan 2009")).slice(0, 16);
        } else {
            const clean = getSanitizedEntropy(entropyRaw);
            finalEntropy = sha256(new TextEncoder().encode(clean)).slice(0, 16);
        }

        const mnemonicStr = bip39.entropyToMnemonic(finalEntropy, wordlist);
        mnemonicWords.length = 0;
        mnemonicWords.push(...mnemonicStr.split(' '));
        if (masterSeed) { masterSeed.fill(0); masterSeed = null; }
        masterSeed = bip39.mnemonicToSeedSync(mnemonicStr);
        finalEntropy.fill(0);

        const rootNode = BIP32Node.fromSeed(masterSeed);
        // BIP84 Testnet4 Account Node: m/84'/1'/0'
        const purposeNode = rootNode.deriveHardened(84);
        const coinTypeNode = purposeNode.deriveHardened(1);
        const accountNode = coinTypeNode.deriveHardened(0);

        tpub = accountNode.toSerializedKey(false, true, false);
        vpub = accountNode.toSerializedKey(false, true, true);
        const fp = rootNode.getFingerprint();
        fingerprint = (fp >>> 0).toString(16).padStart(8, '0');

        const rawDescriptor = `wpkh([${fingerprint}/84'/1'/0']${tpub}/<0;1>/*)`;
        descChecksum = getDescriptorChecksum(rawDescriptor);
        descriptorWithChecksum = `${rawDescriptor}#${descChecksum}`;

        receiveAddresses.length = 0;
        const recvBranchNode = accountNode.derive(0);
        for (let i = 0; i < 15; i++) {
            const node = recvBranchNode.derive(i);
            receiveAddresses.push(getSegWitAddress(node.publicKey, true));
            node.wipe();
        }
        recvBranchNode.wipe();

        bip85Children.length = 0;
        const b85AppNode = rootNode.deriveHardened(83696968);
        const b85Bip39Node = b85AppNode.deriveHardened(39);
        const b85LangNode = b85Bip39Node.deriveHardened(0);
        const b85LenNode = b85LangNode.deriveHardened(12);

        for (let i = 0; i < 10; i++) {
            const b85Node = b85LenNode.deriveHardened(i);
            const hmacKey = new TextEncoder().encode("bip-entropy-from-k");
            const cEntropy = hmac(sha512, hmacKey, b85Node.privateKey!).slice(0, 16);
            b85Node.wipe();
            bip85Children.push(bip39.entropyToMnemonic(cEntropy, wordlist));
            cEntropy.fill(0);
        }

        b85LenNode.wipe();
        b85LangNode.wipe();
        b85Bip39Node.wipe();
        b85AppNode.wipe();
        accountNode.wipe();
        coinTypeNode.wipe();
        purposeNode.wipe();
        rootNode.wipe();
    }

    function renderCarouselPage() {
        if (state === "CONFIRM_EXIT") {
            renderHeader(
                "[!] CONFIRM AMNESIC RAM WIPE & POWER OFF [!]",
                "ALL CRYPTOGRAPHIC BUFFERS WILL BE DESTROYED",
                true
            );
            let y = 180;
            fb.drawRect(80, y, fb.geometry.width - 160, 220, { r: 45, g: 20, b: 25 });
            fb.drawRect(80, y, fb.geometry.width - 160, 2, COLOR_WARN);

            fb.drawTextCentered(y + 35, "ARE YOU SURE YOU WANT TO WIPE AND POWER OFF?", 1, COLOR_WARN);
            fb.drawTextCentered(y + 75, "This will zeroize master seeds, child keys, and video buffers in RAM.", 1, COLOR_WHITE);
            fb.drawTextCentered(y + 110, "Make sure you have transcribed your 12-word seed and verified in Sparrow.", 1, COLOR_MUTED);
            fb.drawTextCentered(y + 160, "Press [Q] to CONFIRM WIPE & SHUTDOWN | Press [ESC] or [ANY KEY] to Cancel", 1, COLOR_GREEN);

            renderFooter("CONFIRM SHUTDOWN: [Q] = Wipe & Power Off | [ESC / ANY KEY] = Cancel", true);
            fb.flush();
            return;
        }

        if (currentView === 0) {
            // Page 1: Private Master Seed
            renderHeader(
                "[PAGE 1/9] TESTNET4 MASTER SEED (CONFIDENTIAL)",
                "BIP-84 NATIVE SEGWIT // COIN TYPE 1' // DO NOT PHOTOGRAPH",
                true
            );
            let y = 100;
            fb.drawText(40, y, "CRITICAL PHYSICAL BACKUP WARNING:", 1, COLOR_GOLD);
            y += 22;
            fb.drawText(40, y, "Transcribe these 12 words onto paper or stainless steel. Zero QR codes are rendered.", 1, COLOR_MUTED);
            y += 30;

            const cardW = Math.floor((fb.geometry.width - 100) / 2);
            const cardH = 64;
            const rowGap = 14;

            for (let r = 0; r < 6; r++) {
                const idx1 = r;
                const idx2 = r + 6;
                const word1 = mnemonicWords[idx1] || "";
                const word2 = mnemonicWords[idx2] || "";
                const rowY = y + r * (cardH + rowGap);

                // Column 1
                fb.drawRect(40, rowY, cardW, cardH, COLOR_CARD);
                fb.drawRect(40, rowY, cardW, cardH, COLOR_CARD_BORDER);
                fb.drawRect(40, rowY, 60, cardH, COLOR_BADGE_BG);
                fb.drawRect(40, rowY, 60, cardH, COLOR_CARD_BORDER);
                fb.drawText(52, rowY + 24, `${String(idx1 + 1).padStart(2, '0')}`, 1, COLOR_GOLD);
                fb.drawText(120, rowY + 16, word1, 2, COLOR_WHITE);

                // Column 2
                const col2X = 60 + cardW;
                fb.drawRect(col2X, rowY, cardW, cardH, COLOR_CARD);
                fb.drawRect(col2X, rowY, cardW, cardH, COLOR_CARD_BORDER);
                fb.drawRect(col2X, rowY, 60, cardH, COLOR_BADGE_BG);
                fb.drawRect(col2X, rowY, 60, cardH, COLOR_CARD_BORDER);
                fb.drawText(col2X + 12, rowY + 24, `${String(idx2 + 1).padStart(2, '0')}`, 1, COLOR_GOLD);
                fb.drawText(col2X + 80, rowY + 16, word2, 2, COLOR_WHITE);
            }

            y += 6 * (cardH + rowGap) + 15;
            fb.drawText(40, y, "Advance to Page 4/5 to export public watch-only coordinator data.", 1, COLOR_MUTED);
        } else if (currentView === 1) {
            // Page 2: BIP-85 Child Seeds (0 - 4)
            renderHeader(
                "[PAGE 2/9] PRIVATE BIP-85 CHILD SEEDS (0 - 4)",
                "DISPOSABLE TESTNET4 HOT WALLETS (m/83696968'/39'/0'/12'/index')"
            );
            let y = 100;
            for (let i = 0; i < 5; i++) {
                fb.drawRect(40, y, fb.geometry.width - 80, 72, COLOR_CARD);
                fb.drawRect(40, y, fb.geometry.width - 80, 1, COLOR_CARD_BORDER);
                fb.drawText(55, y + 10, `Child #${i} (12 Words):`, 1, COLOR_ACCENT);
                fb.drawText(55, y + 36, bip85Children[i], 1, COLOR_WHITE);
                y += 82;
            }
        } else if (currentView === 2) {
            // Page 3: BIP-85 Child Seeds (5 - 9)
            renderHeader(
                "[PAGE 3/9] PRIVATE BIP-85 CHILD SEEDS (5 - 9)",
                "DISPOSABLE TESTNET4 HOT WALLETS (m/83696968'/39'/0'/12'/index')"
            );
            let y = 100;
            for (let i = 5; i < 10; i++) {
                fb.drawRect(40, y, fb.geometry.width - 80, 72, COLOR_CARD);
                fb.drawRect(40, y, fb.geometry.width - 80, 1, COLOR_CARD_BORDER);
                fb.drawText(55, y + 10, `Child #${i} (12 Words):`, 1, COLOR_ACCENT);
                fb.drawText(55, y + 36, bip85Children[i], 1, COLOR_WHITE);
                y += 82;
            }
        } else if (currentView === 3) {
            // Page 4: Watch-Only Descriptor (Text)
            renderHeader(
                "[PAGE 4/9] TESTNET4 WATCH-ONLY ACCOUNT (TEXT)",
                "PUBLIC DATA ONLY // SAFE TO IMPORT INTO NUNCHUK / KEEPER / SPARROW / GREEN"
            );
            let y = 98;
            fb.drawText(40, y, "ACCOUNT VPUB (SLIP-132 NATIVE SEGWIT):", 1, COLOR_ACCENT);
            y += 20;
            fb.drawRect(40, y, fb.geometry.width - 80, 48, COLOR_CARD);
            fb.drawRect(40, y, fb.geometry.width - 80, 1, COLOR_CARD_BORDER);
            fb.drawText(55, y + 16, vpub, 1, COLOR_GREEN);
            y += 62;

            fb.drawText(40, y, "FIRST RECEIVE ADDRESS (0/0):", 1, COLOR_ACCENT);
            y += 20;
            fb.drawRect(40, y, fb.geometry.width - 80, 60, COLOR_CARD);
            fb.drawRect(40, y, fb.geometry.width - 80, 1, COLOR_CARD_BORDER);
            fb.drawText(55, y + 14, receiveAddresses[0], 2, COLOR_GREEN);
            y += 74;

            fb.drawText(40, y, "BIP-380 MULTIPATH DESCRIPTOR (WITH CHECKSUM):", 1, COLOR_ACCENT);
            y += 20;
            fb.drawRect(40, y, fb.geometry.width - 80, 80, COLOR_CARD);
            fb.drawRect(40, y, fb.geometry.width - 80, 1, COLOR_CARD_BORDER);
            fb.drawTextWrapped(55, y + 14, fb.geometry.width - 110, descriptorWithChecksum, 1, COLOR_WHITE);
            y += 95;

            fb.drawText(40, y, "Advance to Page 5 for vpub QR (Green) or Page 6 for Descriptor QR (Nunchuk / Keeper / Sparrow).", 1, COLOR_MUTED);
        } else if (currentView === 4) {
            // Page 5: Account Extended Public Key (vpub) QR Code (Enforces Native SegWit in Blockstream Green)
            renderHeader(
                "[PAGE 5/9] ACCOUNT VPUB QR (BLOCKSTREAM GREEN)",
                "FOR GREEN // DO NOT SCAN IN NUNCHUK / KEEPER (ADVANCE TO PAGE 6)"
            );
            const qrCenterY = Math.floor(fb.geometry.height / 2) + 10;
            fb.drawQRCode(vpub, qrCenterY, 6, 4);
            fb.drawTextCentered(fb.geometry.height - 85, `Account vpub: ${vpub.substring(0, 16)}...${vpub.substring(vpub.length - 8)}`, 1, COLOR_MUTED);
            fb.drawTextCentered(fb.geometry.height - 65, "[!] Nunchuk & Keeper require Page 6 (BIP-380 Descriptor). Do not scan this page. [!]", 1, COLOR_GOLD);
        } else if (currentView === 5) {
            // Page 6: Full BIP-380 Output Descriptor QR Code (Nunchuk / Keeper / Sparrow Desktop / Bitcoin Core)
            renderHeader(
                "[PAGE 6/9] BIP-380 DESCRIPTOR QR (NUNCHUK / KEEPER / SPARROW)",
                "PRIMARY IMPORT FOR NUNCHUK / KEEPER MOBILE & SPARROW DESKTOP"
            );
            const qrCenterY = Math.floor(fb.geometry.height / 2) + 5;
            fb.drawQRCode(descriptorWithChecksum, qrCenterY, 5, 4);
            const shortPayload = `wpkh([${fingerprint}/84'/1'/0']${tpub.substring(0, 8)}.../<0;1>/*)#${descChecksum}`;
            fb.drawTextCentered(fb.geometry.height - 88, `Descriptor: ${shortPayload}`, 1, COLOR_MUTED);
            fb.drawTextCentered(fb.geometry.height - 68, "Nunchuk: Tap 'Recover existing' -> 'Recover via QR code' -> Scan above QR", 1, COLOR_GREEN);
            fb.drawTextCentered(fb.geometry.height - 50, "* Tip: If scanner previously errored on another page, tap 'X' in Nunchuk to restart camera.", 1, COLOR_MUTED);
        } else if (currentView === 6) {
            // Page 7: Receive Addresses 0 - 4
            renderHeader(
                "[PAGE 7/9] TESTNET4 RECEIVE ADDRESSES (0 - 4)",
                "NATIVE SEGWIT (tb1q) // FUND VIA TESTNET4 FAUCETS"
            );
            let y = 98;
            for (let i = 0; i < 5; i++) {
                fb.drawRect(40, y, fb.geometry.width - 80, 76, COLOR_CARD);
                fb.drawRect(40, y, fb.geometry.width - 80, 1, COLOR_CARD_BORDER);
                fb.drawText(55, y + 8, `[m/84'/1'/0'/0/${i}]:`, 1, COLOR_ACCENT);
                fb.drawText(55, y + 32, receiveAddresses[i], 2, COLOR_GREEN);
                y += 86;
            }
            y += 4;
            fb.drawText(40, y, "Advance to Page 8 for Address #0 Faucet QR Code.", 1, COLOR_MUTED);
        } else if (currentView === 7) {
            // Page 8: Address #0 QR Code
            renderHeader(
                "[PAGE 8/9] RECEIVE ADDRESS #0 QR (FAUCET TARGET)",
                `TARGET: ${receiveAddresses[0]}`
            );
            const qrCenterY = Math.floor(fb.geometry.height / 2) + 15;
            fb.drawQRCode(receiveAddresses[0], qrCenterY, 8, 4);
            fb.drawTextCentered(fb.geometry.height - 80, `Target: ${receiveAddresses[0]}`, 1, COLOR_GREEN);
        } else if (currentView === 8) {
            // Page 9: Colophon & Invariants
            renderHeader(
                "[PAGE 9/9] ARCHITECTURAL INVARIANTS & DRILL CHECKLIST",
                "SECURITY SPECIFICATIONS // MEMORY HYGIENE"
            );
            let y = 105;
            fb.drawText(40, y, "ARCHITECTURAL INVARIANTS:", 1, COLOR_ACCENT);
            y += 22;
            fb.drawText(40, y, " * Strict Coin Type 1  : Mathematically isolated from mainnet.", 1, COLOR_WHITE);
            y += 18;
            fb.drawText(40, y, " * Native SegWit Only   : 100% universal coordinator support (BIP-84).", 1, COLOR_WHITE);
            y += 18;
            fb.drawText(40, y, " * Run-From-RAM (toram) : Boot storage unmounted prior to execution.", 1, COLOR_WHITE);
            y += 18;
            fb.drawText(40, y, " * Direct Framebuffer   : Pixel-perfect vector QR codes without font dependencies.", 1, COLOR_WHITE);
            y += 24;

            fb.drawText(40, y, "BUILD PROVENANCE & IMAGE IDENTITY:", 1, COLOR_ACCENT);
            y += 22;
            fb.drawText(40, y, ` * Build Version        : ${BUILD_VERSION} (${BUILD_TARGET})`, 1, COLOR_GOLD);
            y += 18;
            fb.drawText(40, y, ` * Image Provenance SHA : ${PROVENANCE_HASH_FULL}`, 1, COLOR_GOLD);
            y += 24;

            fb.drawText(40, y, "COORDINATOR DRILL CHECKLIST:", 1, COLOR_GREEN);
            y += 22;
            fb.drawText(40, y, " 1. Import Page 6 (Descriptor) into Nunchuk/Keeper/Sparrow, or Page 5 (vpub) into Green.", 1, COLOR_MUTED);
            y += 18;
            fb.drawText(40, y, " 2. Confirm address (0/0) matches Page 7 exactly (tb1q...).", 1, COLOR_MUTED);
            y += 18;
            fb.drawText(40, y, " 3. Fund via testnet4 faucet (mempool.space/testnet4).", 1, COLOR_MUTED);
            y += 18;
            fb.drawText(40, y, " 4. Press Q to zeroize all RAM buffers and power off.", 1, COLOR_MUTED);
        }

        renderFooter("Controls: [SPACE / ARROWS] = Page | [ESC / R] = New Entropy | [Q] = Power Off");
        fb.flush();
    }

    renderInputScreen();

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
            fb.destroy();
            process.exit(0);
        }

        if (state === "INPUT") {
            if (key.name === 'return' || key.name === 'enter') {
                const testCheck = checkTestVector(currentInput);
                const clean = getSanitizedEntropy(currentInput);
                let isReady = false;

                if (testCheck.isTest) {
                    isReady = true;
                } else if (clean.length > 0) {
                    const uniqueChars = new Set(clean.split(''));
                    const hasBinOnly = Array.from(uniqueChars).every(c => c === '0' || c === '1');
                    const hasDiceOnly = Array.from(uniqueChars).every(c => c >= '1' && c <= '6');

                    let bits = 0;
                    if (hasBinOnly) bits = clean.length;
                    else if (hasDiceOnly) bits = Math.floor(clean.length * 2.58496);
                    else bits = clean.length * 4;

                    const markov = runMarkovAudit(clean);
                    const repeats = hasRepetitiveSubstrings(clean);
                    if (bits >= 128 && markov.passed && !repeats) {
                        isReady = true;
                    }
                }

                if (isReady) {
                    computeDerivations(currentInput);
                    state = "CAROUSEL";
                    currentView = 0;
                    renderCarouselPage();
                } else {
                    renderInputScreen();
                }
            } else if (key.name === 'escape') {
                // One-touch clear / reset or exit
                if (currentInput.length > 0) {
                    currentInput = "";
                    renderInputScreen();
                } else {
                    state = "CONFIRM_EXIT";
                    renderCarouselPage();
                }
            } else if (key.name === 'backspace') {
                currentInput = currentInput.slice(0, -1);
                renderInputScreen();
            } else if (str && str.length === 1) {
                const ch = str.toLowerCase();
                const isDelimiter = str === ' ' || str === ',' || str === '-' || str === '_';
                
                const isTestChar = (currentInput.toLowerCase().startsWith('t') || ch === 't') && /^[test0-9]$/.test(ch);
                const isDiceChar = str >= '1' && str <= '6';
                const isCoinChar = str === '0' || str === '1';

                if ((isCoinChar || isDiceChar || isTestChar || isDelimiter) && currentInput.length < 256) {
                    currentInput += str;
                    renderInputScreen();
                }
            }
        } else if (state === "CAROUSEL") {
            if (key.name === 'right' || key.name === 'space') {
                currentView = (currentView + 1) % totalViews;
                renderCarouselPage();
            } else if (key.name === 'left') {
                currentView = (currentView - 1 + totalViews) % totalViews;
                renderCarouselPage();
            } else if (key.name === 'escape' || key.name === 'r' || key.name === 'backspace') {
                // Wipe cryptographic RAM buffers and return directly to Entropy Input screen
                if (masterSeed) { masterSeed.fill(0); masterSeed = null; }
                mnemonicWords.length = 0;
                bip85Children.length = 0;
                receiveAddresses.length = 0;
                tpub = "";
                vpub = "";
                fingerprint = "";
                descChecksum = "";
                descriptorWithChecksum = "";
                currentInput = "";
                state = "INPUT";
                renderInputScreen();
            } else if (key.name === 'q') {
                state = "CONFIRM_EXIT";
                renderCarouselPage();
            }
        } else if (state === "CONFIRM_EXIT") {
            if (key.name === 'q') {
                logDebug("Wiping RAM and powering down kiosk...");
                if (masterSeed) { masterSeed.fill(0); masterSeed = null; }
                mnemonicWords.length = 0;
                bip85Children.length = 0;
                receiveAddresses.length = 0;
                tpub = "";
                vpub = "";
                fingerprint = "";
                descChecksum = "";
                descriptorWithChecksum = "";
                currentInput = "";
                fb.destroy();
                try {
                    require('child_process').execSync('poweroff -f 2>/dev/null || reboot -f 2>/dev/null');
                } catch (_) {}
                process.exit(0);
            } else {
                state = currentInput ? "CAROUSEL" : "INPUT";
                if (state === "CAROUSEL") renderCarouselPage();
                else renderInputScreen();
            }
        }
    });
}

main().catch(err => {
    logDebug(`FATAL: ${err?.stack || err}`);
    fb.destroy();
    process.exit(1);
});
