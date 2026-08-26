import * as readline from 'readline';
import * as fs from 'fs';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { hmac } from '@noble/hashes/hmac.js';
import { 
    BIP32Node, 
    getSegWitAddress, 
    runMarkovAudit, 
    hasRepetitiveSubstrings,
    getDescriptorChecksum
} from './crypto';
import QRCode from 'qrcode';

function renderTwoSpaceGaplessQR(text: string): string {
    const qr = QRCode.create(text, { errorCorrectionLevel: 'L' });
    const size = qr.modules.size;
    const data = qr.modules.data;
    const border = 2;
    const totalSize = size + border * 2;
    
    function isDark(r: number, c: number): boolean {
        if (r < border || r >= size + border || c < border || c >= size + border) {
            return false; // 2-module White quiet zone
        }
        return !!data[(r - border) * size + (c - border)];
    }
    
    const white = '\x1b[47m  \x1b[0m';
    const black = '\x1b[40m  \x1b[0m';
    
    const lines: string[] = [];
    for (let r = 0; r < totalSize; r++) {
        let line = '  '; // 2-space left margin to center
        for (let c = 0; c < totalSize; c++) {
            line += isDark(r, c) ? black : white;
        }
        lines.push(line);
    }
    return lines.join('\n');
}

function logDebug(msg: string) {
    try {
        fs.appendFileSync('/tmp/subzero_debug.log', `[${new Date().toISOString()}] ${msg}\n`);
    } catch (_) {}
}

process.on('uncaughtException', (err) => {
    logDebug(`UNCAUGHT EXCEPTION: ${err?.stack || err}`);
    console.error(`\n[FATAL ERROR] ${err?.message || err}`);
    process.exit(1);
});

process.on('unhandledRejection', (reason) => {
    logDebug(`UNHANDLED REJECTION: ${reason}`);
    console.error(`\n[FATAL ERROR] Unhandled rejection: ${reason}`);
    process.exit(1);
});

readline.emitKeypressEvents(process.stdin);
try {
    if (process.stdin.isTTY) process.stdin.setRawMode(true);
} catch (e) {
    logDebug(`setRawMode failed: ${e}`);
}

let currentBits = '';
let isTestVector = false;
let secretBuffer = '';

function renderUI() {
    process.stdout.write('\x1b[2J\x1b[H'); // Clean clear
    process.stdout.write('\x1b[?25h');     // Ensure cursor visible on input screen

    console.log("==================================================");
    console.log("   SUBZERO KEYOSK - TESTNET4 TDD EDITION (v0.1.0) ");
    console.log("         [ COIN TYPE 1' // tb1q ADDRESSES ]       ");
    console.log("==================================================\n");
    console.log("Type coin flips (0/1) or dice rolls (1-6) directly.");
    console.log("Type 'test' to populate sample entropy for testing.");
    console.log("Press ESC or Ctrl+C to abort.\n");
    
    let mode = 'NONE';
    let bits = 0;
    const len = currentBits.length;
    
    if (len > 0) {
        const uniqueChars = new Set(currentBits.split(''));
        const hasBinOnly = Array.from(uniqueChars).every(c => c === '0' || c === '1');
        const hasDiceOnly = Array.from(uniqueChars).every(c => c >= '1' && c <= '6');

        if (hasBinOnly && (uniqueChars.has('0') || !hasDiceOnly || len < 3)) {
            mode = 'BINARY';
            bits = len;
        } else if (hasDiceOnly && !hasBinOnly) {
            mode = 'DICE';
            bits = Math.floor(len * 2.58496);
        } else {
            mode = 'MIXED';
            bits = len;
        }
    }

    const { transitionScore, passed } = runMarkovAudit(currentBits);
    const repeats = hasRepetitiveSubstrings(currentBits);

    // Format display string
    function renderInputFormatted(): string {
        if (!currentBits) return '';
        if (mode === 'DICE') {
            const blocks = currentBits.match(/.{1,5}/g) || [];
            const lines: string[] = [];
            for (let i = 0; i < blocks.length; i += 5) {
                lines.push(blocks.slice(i, i + 5).join(' '));
            }
            return lines.join('\n                ');
        } else if (mode === 'BINARY' && len <= 128) {
            const words: string[] = [];
            for (let i = 0; i < 11; i++) {
                const chunk = currentBits.slice(i * 11, (i + 1) * 11);
                if (chunk.length > 0) {
                    const c1 = chunk.slice(0, 4);
                    const c2 = chunk.slice(4, 8);
                    const c3 = chunk.slice(8, 11);
                    const formatted = [c1, c2, c3].filter(Boolean).join(' ');
                    words.push(`W${String(i + 1).padStart(2, '0')}: ${formatted.padEnd(12, ' ')}`);
                }
            }
            if (len > 121) {
                const chunk12 = currentBits.slice(121, 128);
                const c1 = chunk12.slice(0, 4);
                const c2 = chunk12.slice(4, 7);
                const formatted = [c1, c2].filter(Boolean).join(' ');
                const label = len === 128 ? `${formatted} [chk]` : formatted;
                words.push(`W12: ${label.padEnd(12, ' ')}`);
            }

            const col1 = words.slice(0, 6);
            const col2 = words.slice(6, 12);
            const lines: string[] = [];
            const maxRows = Math.max(col1.length, col2.length);
            for (let r = 0; r < maxRows; r++) {
                const left = col1[r] || ''.padEnd(17, ' ');
                const right = col2[r] || '';
                lines.push(`${left}    ${right}`.trimEnd());
            }
            return '\n  ' + lines.join('\n  ');
        }
        return currentBits;
    }

    console.log(`Detected Mode : ${mode}`);
    console.log(`Total Inputs  : ${len} chars`);
    console.log(`Entropy Level : ~${bits} bits / 128 bits`);
    console.log(`Quality Audit : Markov Transition Score: ${transitionScore} ${passed ? '[PASS]' : '[FAIL - LOW ENTROPY]'}`);
    if (repeats) {
        console.log(`Pattern Block : [FAIL - REPETITIVE SUBSTRING DETECTED]`);
    }
    console.log("--------------------------------------------------");
    console.log(`Raw Sequence  : ${renderInputFormatted()}`);
    console.log("--------------------------------------------------");

    const isReady = (mode === 'BINARY' && len >= 128) || (mode === 'DICE' && len >= 50);
    const isValid = isReady && passed && !repeats;

    if (isValid) {
        console.log("\n[SUCCESS] Entropy threshold satisfied!");
        console.log("Press [ENTER] to execute Testnet4 cryptographic key derivation.");
    } else if (isReady) {
        console.log("\n[BLOCKED] Threshold met, but entropy failed mathematical quality audit.");
        console.log("Do NOT use biased or patterned physical inputs.");
    } else {
        const remaining = mode === 'DICE' ? `${Math.max(0, 50 - len)} rolls` : `${Math.max(0, 128 - len)} flips`;
        console.log(`\nStatus: Awaiting physical entropy (${remaining} needed)...`);
    }
}

function processEntropy() {
    process.stdout.write('\x1b[2J\x1b[H');
    console.log("Executing SHA-256 entropy normalization and BIP32 derivation (Testnet4)...\n");

    let finalEntropy: Uint8Array;
    if (isTestVector) {
        const hash = sha256(new TextEncoder().encode(currentBits));
        finalEntropy = hash;
    } else {
        const hash = sha256(new TextEncoder().encode(currentBits));
        finalEntropy = hash;
    }
    
    // Slice 16 bytes for exactly 12 words (128-bit symmetric security level)
    const entropy16 = finalEntropy.slice(0, 16);
    const mnemonicStr = bip39.entropyToMnemonic(entropy16, wordlist);
    
    const seedBytes = bip39.mnemonicToSeedSync(mnemonicStr);
    const rootNode = BIP32Node.fromSeed(seedBytes);
    
    // m/84'/1'/0' Native SegWit Testnet4
    const p1 = rootNode.deriveHardened(84);
    const p2 = p1.deriveHardened(1); // Coin Type 1 for Testnet
    const accountNode = p2.deriveHardened(0);
    
    // tpub (Testnet4 extended public key)
    const tpub = accountNode.toSerializedKey(false, true);
    const fp = rootNode.getFingerprint();
    const fingerprint = (fp >>> 0).toString(16).padStart(8, '0');
    
    const rawDescriptor = `wpkh([${fingerprint}/84'/1'/0']${tpub}/<0;1>/*)`;
    const descChecksum = getDescriptorChecksum(rawDescriptor);
    const descriptorWithChecksum = `${rawDescriptor}#${descChecksum}`;

    // Pre-calculate first 15 receive addresses (3 pages of 5) - tb1q...
    const receiveAddresses: string[] = [];
    const receiveNodes: BIP32Node[] = [];
    for (let i = 0; i < 15; i++) {
        const node = accountNode.derive(0).derive(i);
        receiveNodes.push(node);
        receiveAddresses.push(getSegWitAddress(node.publicKey, true));
    }

    // Pre-calculate first 15 BIP85 child mnemonics (English language index 0')
    const bip85Children: string[] = [];
    const b85AppNode = rootNode.deriveHardened(83696968);
    const b85Bip39Node = b85AppNode.deriveHardened(39);
    const b85LangNode = b85Bip39Node.deriveHardened(0); // 0' = English wordlist
    const b85LenNode = b85LangNode.deriveHardened(12);

    for (let i = 0; i < 15; i++) {
        const childEntropyLength = 16; // 12 words
        const b85Node = b85LenNode.deriveHardened(i);
        const hmacKey = new TextEncoder().encode("bip-entropy-from-k");
        const cEntropy = hmac(sha512, hmacKey, b85Node.privateKey!).slice(0, childEntropyLength);
        b85Node.wipe();
        bip85Children.push(bip39.entropyToMnemonic(cEntropy, wordlist));
        cEntropy.fill(0);
    }
    b85LenNode.wipe();
    b85LangNode.wipe();
    b85Bip39Node.wipe();
    b85AppNode.wipe();

    let currentView = 0;
    const totalViews = 8;

    function renderOutputView() {
        process.stdout.write('\x1b[2J\x1b[H'); // Clean clear
        process.stdout.write('\x1b[?25l');     // Hide cursor on output carousel

        if (currentView === 0) {
            console.log("==================================================");
            console.log("   [!] SUBZERO KEYOSK // TESTNET4 TDD EDITION [!] ");
            console.log("     COIN TYPE 1' // tb1q ADDRESSES // TEST SATS  ");
            console.log("==================================================\n");
            console.log("==================================================");
            console.log(" [PAGE 1/8] TESTNET4 MASTER SEED (CONFIDENTIAL)   ");
            console.log("==================================================");
            console.log(" [!] CRITICAL OPSEC WARNING:");
            console.log("     THIS IS A TESTNET4 SEED (COIN TYPE 1').");
            console.log("     USE FOR MULTISIG & COORDINATOR DRILLS ONLY.\n");
            console.log("BIP39 MASTER SEED (12 WORDS):");
            console.log("--------------------------------------------------");
            console.log(mnemonicStr);
            console.log("--------------------------------------------------");
            console.log("\nNote: Zero QR codes are rendered on this page.");
            console.log("Advance to Page 4/5 to export public watch-only data.");
        } else if (currentView === 1) {
            console.log("==================================================");
            console.log("   [!] SUBZERO KEYOSK // TESTNET4 TDD EDITION [!] ");
            console.log("     COIN TYPE 1' // tb1q ADDRESSES // TEST SATS  ");
            console.log("==================================================\n");
            console.log("==================================================");
            console.log(" [PAGE 2/8] PRIVATE BIP85 CHILD SEEDS (0 - 4)     ");
            console.log(" Path: m/83696968'/39'/0'/12'/index'             ");
            console.log("==================================================");
            console.log(" [!] TESTNET4 DISPOSABLE HOT SEEDS:");
            console.log("     Import into mobile testnet wallets for spending.\n");
            for (let i = 0; i < 5; i++) {
                console.log(`Child #${i} (12w): ${bip85Children[i]}`);
            }
        } else if (currentView === 2) {
            console.log("==================================================");
            console.log("   [!] SUBZERO KEYOSK // TESTNET4 TDD EDITION [!] ");
            console.log("     COIN TYPE 1' // tb1q ADDRESSES // TEST SATS  ");
            console.log("==================================================\n");
            console.log("==================================================");
            console.log(" [PAGE 3/8] PRIVATE BIP85 CHILD SEEDS (5 - 9)     ");
            console.log(" Path: m/83696968'/39'/0'/12'/index'             ");
            console.log("==================================================");
            console.log(" [!] TESTNET4 DISPOSABLE HOT SEEDS:");
            console.log("     Import into mobile testnet wallets for spending.\n");
            for (let i = 5; i < 10; i++) {
                console.log(`Child #${i} (12w): ${bip85Children[i]}`);
            }
        } else if (currentView === 3) {
            console.log("==================================================");
            console.log("   [!] SUBZERO KEYOSK // TESTNET4 TDD EDITION [!] ");
            console.log("     COIN TYPE 1' // tb1q ADDRESSES // TEST SATS  ");
            console.log("==================================================\n");
            console.log("==================================================");
            console.log(" [PAGE 4/8] TESTNET4 WATCH-ONLY DESCRIPTOR        ");
            console.log("==================================================");
            console.log(" [PUBLIC DATA ONLY - SAFE TO IMPORT INTO SPARROW]\n");
            console.log("TPUB (m/84'/1'/0'):");
            console.log(tpub);
            console.log("\nFIRST RECEIVE ADDRESS (0/0):");
            console.log(receiveAddresses[0]);
            console.log("\nBIP-380 MULTIPATH DESCRIPTOR (with Checksum):");
            console.log(descriptorWithChecksum);
            console.log("\nAdvance to Page 5 for TPUB QR Code.");
        } else if (currentView === 4) {
            console.log(" [PAGE 5/8] ACCOUNT TPUB QR (WATCH-ONLY EXPORT) - SCAN IN SPARROW");
            console.log(renderTwoSpaceGaplessQR(tpub));
        } else if (currentView === 5) {
            console.log("==================================================");
            console.log("   [!] SUBZERO KEYOSK // TESTNET4 TDD EDITION [!] ");
            console.log("     COIN TYPE 1' // tb1q ADDRESSES // TEST SATS  ");
            console.log("==================================================\n");
            console.log("==================================================");
            console.log(" [PAGE 6/8] TESTNET4 RECEIVE ADDRESSES (0 - 4)    ");
            console.log("==================================================");
            console.log(" [PUBLIC DATA ONLY - USE TO FUND FROM FAUCETS]\n");
            for (let i = 0; i < 5; i++) {
                console.log(`[m/84'/1'/0'/0/${i}] : ${receiveAddresses[i]}`);
            }
            console.log("\nAdvance to Page 7 for Address #0 Faucet QR Code.");
        } else if (currentView === 6) {
            console.log(` [PAGE 7/8] RECEIVE ADDRESS #0 QR (FAUCET TARGET: ${receiveAddresses[0]})`);
            console.log(renderTwoSpaceGaplessQR(receiveAddresses[0]));
        } else if (currentView === 7) {
            console.log("==================================================");
            console.log("   [!] SUBZERO KEYOSK // TESTNET4 TDD EDITION [!] ");
            console.log("     COIN TYPE 1' // tb1q ADDRESSES // TEST SATS  ");
            console.log("==================================================\n");
            console.log("==================================================");
            console.log(" [PAGE 8/8] COLOPHON & ARCHITECTURAL INVARIANTS   ");
            console.log("==================================================");
            console.log("TESTNET4 ARCHITECTURAL INVARIANTS:");
            console.log(" * Strict Coin Type 1: Prevents mainnet address leaks.");
            console.log(" * Native SegWit Only (BIP84): 100% universal support.");
            console.log(" * Run-From-RAM (toram): Boot USB unmounted at startup.");
            console.log(" * Network Demolition: Wi-Fi/NIC firmware purged.");
            console.log(" * Memory Hygiene: Volatile tmpfs; zeroized on exit.");
            console.log("\nDRILL PROTOCOL:");
            console.log(" 1. Import Page 5 TPUB into Sparrow (Testnet mode).");
            console.log(" 2. Confirm address (0/0) matches Page 6 exactly.");
            console.log(" 3. Fund via testnet4 faucet (mempool.space/testnet4).");
            console.log(" 4. Press Q or ESC to zeroize all RAM and power off.");
        }

        console.log("--------------------------------------------------");
        console.log("Controls: [LEFT / RIGHT / SPACE] = Change Page | [Q / ESC] = Wipe & Exit");
    }

    renderOutputView();

    process.stdin.removeAllListeners('keypress');
    process.stdin.on('keypress', (str, key) => {
        if (!key) return;
        if (key.name === 'right' || key.name === 'space' || key.name === 'down') {
            currentView = (currentView + 1) % totalViews;
            renderOutputView();
        } else if (key.name === 'left' || key.name === 'up') {
            currentView = (currentView - 1 + totalViews) % totalViews;
            renderOutputView();
        } else if (key.name === 'q' || key.name === 'escape' || (key.ctrl && key.name === 'c')) {
            wipeAndExit();
        }
    });

    function wipeAndExit() {
        process.stdout.write('\x1b[?25h\x1b[2J\x1b[H');
        if (process.stdin.isTTY) {
            try { process.stdin.setRawMode(false); } catch (e) {}
        }
        console.log("Zeroizing private cryptographic buffers in volatile memory...");
        
        rootNode.wipe();
        accountNode.wipe();
        p1.wipe();
        p2.wipe();
        receiveNodes.forEach(n => n.wipe());
        
        finalEntropy.fill(0);
        entropy16.fill(0);
        seedBytes.fill(0);
        
        currentBits = '';
        secretBuffer = '';
        
        console.log("Cryptographic state destroyed.");
        console.log("Safe to power off appliance.\n");
        process.exit(0);
    }
}

renderUI();

process.stdin.on('keypress', (str, key) => {
    if (!key) return;
    if (key.name === 'escape' || (key.ctrl && key.name === 'c')) {
        process.stdout.write('\x1b[?25h\x1b[2J\x1b[H');
        if (process.stdin.isTTY) {
            try { process.stdin.setRawMode(false); } catch (e) {}
        }
        process.exit(0);
    }

    if (key.name === 'return' || key.name === 'enter') {
        const len = currentBits.length;
        const uniqueChars = new Set(currentBits.split(''));
        const hasBinOnly = Array.from(uniqueChars).every(c => c === '0' || c === '1');
        const hasDiceOnly = Array.from(uniqueChars).every(c => c >= '1' && c <= '6');
        const isReady = (hasBinOnly && len >= 128) || (hasDiceOnly && len >= 50);

        const { passed } = runMarkovAudit(currentBits);
        const repeats = hasRepetitiveSubstrings(currentBits);

        if (isReady && passed && !repeats) {
            processEntropy();
        }
        return;
    }

    if (key.name === 'backspace') {
        if (currentBits.length > 0) {
            currentBits = currentBits.slice(0, -1);
            renderUI();
        }
        return;
    }

    if (str) {
        secretBuffer += str;
        if (secretBuffer.length > 32) secretBuffer = secretBuffer.slice(-16);

        if (secretBuffer.toLowerCase().includes('test')) {
            isTestVector = true;
            currentBits = '10110100110101011100010100111010110100010101101001011110100101011001010101110100101001011101010101101010110010100101101010110101';
            secretBuffer = '';
            renderUI();
            return;
        }

        if (currentBits.length >= 256) return;

        const validChars = str.split('').filter(c => (c >= '0' && c <= '6') || c === ' ' || c === '\n' || c === '\t');
        if (validChars.length > 0) {
            for (const c of validChars) {
                if (c >= '0' && c <= '6' && currentBits.length < 256) {
                    currentBits += c;
                }
            }
            renderUI();
        }
    }
});
