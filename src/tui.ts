import * as readline from 'readline';
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
import qrcode from 'qrcode-terminal';

readline.emitKeypressEvents(process.stdin);
if (process.stdin.isTTY) process.stdin.setRawMode(true);

let currentBits = '';
let isTestVector = false;
let secretBuffer = '';

function renderUI() {
    process.stdout.write('\x1b[2J\x1b[H'); // Clean clear
    process.stdout.write('\x1b[?25h');     // Ensure cursor visible on input screen

    console.log("==================================================");
    console.log("    SUBZERO KEYOSK - TERMINAL UI (v0.0.1-rc1)     ");
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
            // 5-digit chunks
            const blocks = currentBits.match(/.{1,5}/g) || [];
            const lines: string[] = [];
            for (let i = 0; i < blocks.length; i += 5) {
                lines.push(blocks.slice(i, i + 5).join(' '));
            }
            return lines.join('\n                ');
        } else if (mode === 'BINARY' && len <= 128) {
            // BIP39 11-bit Word Grid (2 Columns: W01..W06 and W07..W12)
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
            // Word 12 (7 bits entropy + 4 bits checksum placeholder)
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
        } else {
            // Over-sampled Raw Stream Mode (>128 flips or mixed)
            const blocks = currentBits.match(/.{1,4}/g) || [];
            const lines: string[] = [];
            for (let i = 0; i < blocks.length; i += 8) {
                lines.push(blocks.slice(i, i + 8).join(' '));
            }
            const label = len > 128 ? ' [Over-sampled: SHA-256 Hash Pool Mode]' : '';
            return '\n  ' + lines.join('\n  ') + label;
        }
    }

    const displayFormatted = renderInputFormatted();
    const markovStr = len === 0 ? 'PENDING' : `${transitionScore} (${passed ? 'PASS' : 'FAIL'})`;
    const repeatsStr = len === 0 ? 'PENDING' : (repeats ? 'FAIL' : 'PASS');

    console.log(`Current Input : ${displayFormatted}`);
    console.log(`\nDetected Mode : ${mode}`);
    console.log(`Entropy Size  : ${len} sym | ${bits} / 128 bits`);
    console.log(`Markov Check  : ${markovStr}`);
    console.log(`Repeats Check : ${repeatsStr}`);
    if (isTestVector) {
        console.log("--------------------------------------------------");
        console.log(" [!] NOTICE: PUBLIC TEST VECTOR ACTIVE");
        console.log("     FOR TESTING ONLY! NEVER DEPOSIT REAL FUNDS!");
    }
    console.log("--------------------------------------------------");

    if (bits >= 128 && passed && !repeats) {
        if (isTestVector) {
            console.log("\n[READY - TEST MODE] Press ENTER to Generate Test Keys.");
        } else {
            console.log("\n[READY] Minimum 128 bits reached. Press ENTER to Generate Keys.");
        }
    } else if (bits >= 128) {
        console.log("\n[LOCKED] 128 bits reached, but entropy quality checks failed.");
    }
}

function generateKeys() {
    console.clear();
    console.log("Deriving Keys... Please Wait.\n");

    const manualInputBytes = new TextEncoder().encode(currentBits);
    const manualHash = sha256(manualInputBytes);
    
    const finalEntropy = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        finalEntropy[i] = manualHash[i];
    }
    
    // Slice 16 bytes for exactly 12 words (128-bit symmetric security level)
    const entropy16 = finalEntropy.slice(0, 16);
    const mnemonicStr = bip39.entropyToMnemonic(entropy16, wordlist);
    
    const seedBytes = bip39.mnemonicToSeedSync(mnemonicStr);
    const rootNode = BIP32Node.fromSeed(seedBytes);
    
    // m/84'/0'/0' Native SegWit Mainnet
    const p1 = rootNode.deriveHardened(84);
    const p2 = p1.deriveHardened(0);
    const accountNode = p2.deriveHardened(0);
    
    const xpub = accountNode.toSerializedKey(false, false);
    const fp = rootNode.getFingerprint();
    const fingerprint = (fp >>> 0).toString(16).padStart(8, '0');
    
    const rawDescriptor = `wpkh([${fingerprint}/84'/0'/0']${xpub}/<0;1>/*)`;
    const descChecksum = getDescriptorChecksum(rawDescriptor);
    const descriptorWithChecksum = `${rawDescriptor}#${descChecksum}`;

    // Pre-calculate first 15 receive addresses (3 pages of 5)
    const receiveAddresses: string[] = [];
    const receiveNodes: BIP32Node[] = [];
    for (let i = 0; i < 15; i++) {
        const node = accountNode.derive(0).derive(i);
        receiveNodes.push(node);
        receiveAddresses.push(getSegWitAddress(node.publicKey));
    }

    // Pre-calculate first 15 BIP85 child mnemonics
    const bip85Children: string[] = [];
    const b85AppNode = rootNode.deriveHardened(83696968);
    const b85Bip39Node = b85AppNode.deriveHardened(39);
    const b85CoinNode = b85Bip39Node.deriveHardened(0);
    const b85LenNode = b85CoinNode.deriveHardened(12);

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
    b85CoinNode.wipe();
    b85Bip39Node.wipe();
    b85AppNode.wipe();

    let currentView = 0;
    const totalViews = 8;

    function renderOutputView() {
        process.stdout.write('\x1b[2J\x1b[H'); // Clean clear
        process.stdout.write('\x1b[?25l');     // Hide cursor on output carousel

        if (isTestVector && currentView !== 3 && currentView !== 4) {
            console.log("**************************************************");
            console.log(" [!] WARNING: TEST-DERIVED ENTROPY - DO NOT FUND! ");
            console.log("     FOR APPLICATION TESTING PURPOSES ONLY!       ");
            console.log("**************************************************\n");
        }

        // ==========================================================
        // [AUDIT-REMEDIATION: AD-12]
        // Auditor Warning: Phone scanning on combined pages causes accidental seed photo capture.
        // Remediation: Enforce strict separation: Pages 1-3 are PRIVATE ONLY with zero QR codes.
        // Ref: docs/AUDIT_REMEDIATION_LOG.md#AD-12
        // ==========================================================
        // DOMAIN 1: PRIVATE SECRETS (PAGES 1 - 3: DO NOT PHOTOGRAPH)
        // ==========================================================
        if (currentView === 0) {
            console.log("==================================================");
            console.log(" [PAGE 1/8] PRIVATE MASTER SEED (CONFIDENTIAL)    ");
            console.log("==================================================");
            console.log(" [!] CRITICAL OPSEC WARNING:");
            console.log("     DO NOT PHOTOGRAPH THIS SCREEN WITH A PHONE!");
            console.log("     STAMP DIRECTLY ONTO STAINLESS STEEL ONLY.\n");
            console.log("BIP39 MASTER SEED (12 WORDS):");
            console.log("--------------------------------------------------");
            console.log(mnemonicStr);
            console.log("--------------------------------------------------");
            console.log("\nNote: Zero QR codes are rendered on this page.");
            console.log("Advance to Page 4 to export public watch-only data.");
        } else if (currentView === 1) {
            console.log("==================================================");
            console.log(" [PAGE 2/8] PRIVATE BIP85 CHILD SEEDS (0 - 4)     ");
            console.log(" Path: m/83696968'/39'/0'/12'/index'             ");
            console.log("==================================================");
            console.log(" [!] PRIVATE HOT SEEDS (DO NOT PHOTOGRAPH):");
            console.log("     Manually transcribe into Phoenix/Zeus/Breez.\n");
            for (let i = 0; i < 5; i++) {
                console.log(`Child #${i} (12w): ${bip85Children[i]}`);
            }
        } else if (currentView === 2) {
            console.log("==================================================");
            console.log(" [PAGE 3/8] PRIVATE BIP85 CHILD SEEDS (5 - 9)     ");
            console.log(" Path: m/83696968'/39'/0'/12'/index'             ");
            console.log("==================================================");
            console.log(" [!] PRIVATE HOT SEEDS (DO NOT PHOTOGRAPH):");
            console.log("     Manually transcribe into Phoenix/Zeus/Breez.\n");
            for (let i = 5; i < 10; i++) {
                console.log(`Child #${i} (12w): ${bip85Children[i]}`);
            }
        // ==========================================================
        // DOMAIN 2: PUBLIC WATCH-ONLY EXPORTS (PAGES 4 - 6: SAFE QR)
        // ==========================================================
        } else if (currentView === 3) {
            console.log("==================================================");
            console.log(" [PAGE 4/8] PUBLIC WATCH-ONLY DESCRIPTOR EXPORT   ");
            console.log("==================================================");
            console.log(" [PUBLIC DATA ONLY - SAFE TO SCAN WITH PHONE]\n");
            console.log("XPUB / ZPUB (m/84'/0'/0'):");
            console.log(xpub);
            console.log("\nFIRST RECEIVE ADDRESS (0/0):");
            console.log(receiveAddresses[0]);
            console.log("\nDESCRIPTOR (BIP380 with Checksum):");
            console.log(descriptorWithChecksum);
            console.log("XPUB QR CODE (Scan with BlueWallet/Green/Sparrow):");
            console.log("\n\n"); // Vertical quiet zone
            qrcode.generate(xpub, {small: true}, (code) => {
                console.log(code.split('\n').map(line => '    ' + line).join('\n'));
                console.log("\n\n");
            });
        } else if (currentView === 4) {
            console.log("==================================================");
            console.log(" [PAGE 5/8] PUBLIC RECEIVE ADDRESSES (0 - 4)      ");
            console.log("==================================================");
            console.log(" [PUBLIC DATA ONLY - SAFE TO SCAN/VERIFY]\n");
            for (let i = 0; i < 5; i++) {
                console.log(`[m/84'/0'/0'/0/${i}] : ${receiveAddresses[i]}`);
            }
            console.log("First Address (0/0) QR:");
            console.log("\n\n"); // Vertical quiet zone
            qrcode.generate(receiveAddresses[0], {small: true}, (code) => {
                console.log(code.split('\n').map(line => '    ' + line).join('\n'));
                console.log("\n\n");
            });
        } else if (currentView === 5) {
            console.log("==================================================");
            console.log(" [PAGE 6/8] PUBLIC RECEIVE ADDRESSES (5 - 9)      ");
            console.log("==================================================");
            console.log(" [PUBLIC DATA ONLY - SAFE TO SCAN/VERIFY]\n");
            for (let i = 5; i < 10; i++) {
                console.log(`[m/84'/0'/0'/0/${i}] : ${receiveAddresses[i]}`);
            }
        // ==========================================================
        // DOMAIN 3: AUDIT & CHECKLIST PROTOCOL (PAGES 7 - 8)
        // ==========================================================
        } else if (currentView === 6) {
            console.log("==================================================");
            console.log(" [PAGE 7/8] COLOPHON & DEFENSIVE RATIONALE       ");
            console.log("==================================================");
            console.log("ARCHITECTURAL PRINCIPLES:");
            console.log(" * 12 Words (128-bit): Matches secp256k1 curve margin.");
            console.log("   Reduces steel-stamp transcription errors by 50%.");
            console.log(" * No 13th Word/Passphrase: Eliminates unchecksummed");
            console.log("   typos that create phantom unrecoverable wallets.");
            console.log(" * Run-From-RAM (toram): Boot USB unmounted at startup.");
            console.log(" * Bare-Metal TTY: Zero browser engine attack surface.");
            console.log(" * Network Demolition: Wi-Fi/NIC firmware & stacks purged.");
            console.log(" * Memory Hygiene: Volatile tmpfs; cryptographic buffer");
            console.log("   zeroization & ANSI scrollback purge on exit.");
            console.log("\nSOURCE & BUILD METADATA:");
            console.log(" * Repo      : github.com/bootlace-dev/subzero-keyosk");
            console.log(" * Release   : v0.0.1-rc1 (MIT Open Source License)");
            console.log(" * Build UTC : 2026-08-21T00:00:00Z | Reproducible");
            console.log(" * Engine    : Alpine LTS 6.6 | @scure/bip39 | noble");
        } else if (currentView === 7) {
            console.log("==================================================");
            console.log(" [PAGE 8/8] COORDINATOR VERIFICATION PROTOCOL    ");
            console.log("==================================================");
            console.log("ANTI-FOOTGUN COLD-STORAGE CHECKLIST:");
            console.log(" 1. STEEL BACKUP: Stamp the 12 words from Page 1.");
            console.log("    Physical possession equals total wallet control.");
            console.log(" 2. WATCH-ONLY: Scan Page 4 QR into phone coordinator");
            console.log("    (Sparrow / BlueWallet / Blockstream Green).");
            console.log(" 3. ADDRESS MATCH PROOF: Verify first receive address");
            console.log("    on your phone matches Page 4 (0/0) EXACTLY.");
            console.log(" 4. TEST DEPOSIT: Send a tiny amount ($5) and verify");
            console.log("    it appears on phone before sending major funds.");
            console.log(" 5. EPHEMERAL HOT WALLETS: Use BIP85 child seeds");
            console.log("    (Pages 2-3) for lightning/mobile daily spending.");
            console.log(" 6. AMNESIC POWER-OFF: Press Q or ESC to wipe RAM;");
            console.log("    physically power down laptop to clear VRAM.");
        }

        console.log("--------------------------------------------------");
        console.log("Controls: [LEFT / RIGHT / SPACE] = Change Page | [Q / ESC] = Wipe & Exit");
    }

    renderOutputView();

    process.stdin.removeAllListeners('keypress');
    process.stdin.on('keypress', (str, key) => {
        if (key.name === 'right' || key.name === 'space' || key.name === 'down') {
            currentView = (currentView + 1) % totalViews;
            renderOutputView();
        } else if (key.name === 'left' || key.name === 'up') {
            currentView = (currentView - 1 + totalViews) % totalViews;
            renderOutputView();
        } else if (key.name === 'escape' || key.name === 'q' || (key.ctrl && key.name === 'c')) {
            // [AUDIT-REMEDIATION: AD-07]
            // Auditor Warning: Key objects left in managed runtime heap can leak to swap or lingering memory.
            // Remediation: Explicit zeroization (.fill(0) / .wipe()) on all raw buffers and BIP32 private keys.
            // Ref: docs/AUDIT_REMEDIATION_LOG.md#AD-07
            // 1. Explicitly zeroize all cryptographic buffers in RAM
            manualInputBytes.fill(0);
            manualHash.fill(0);
            finalEntropy.fill(0);
            entropy16.fill(0);
            seedBytes.fill(0);
            rootNode.wipe();
            accountNode.wipe();
            p1.wipe();
            p2.wipe();
            for (const n of receiveNodes) n.wipe();
            currentBits = '';

            // 2. Wipe full console and scrollback buffer via ANSI codes
            process.stdout.write('\x1b[2J\x1b[H\x1b[3J');
            process.stdout.write('\x1b[?25h'); // Restore cursor
            
            if (process.stdin.isTTY) process.stdin.setRawMode(false);
            process.exit(0);
        }
    });
}

process.stdin.on('keypress', (str, key) => {
    if (key.ctrl && key.name === 'c') {
        process.stdout.write('\x1b[?25h');
        if (process.stdin.isTTY) process.stdin.setRawMode(false);
        process.exit();
    }

    if (key.name === 'escape') {
        process.stdout.write('\x1b[?25h');
        if (process.stdin.isTTY) process.stdin.setRawMode(false);
        process.exit();
    } else if (key.name === 'return' || key.name === 'enter') {
        let bits = 0;
        const len = currentBits.length;
        if (len > 0) {
            const uniqueChars = new Set(currentBits.split(''));
            const hasBinOnly = Array.from(uniqueChars).every(c => c === '0' || c === '1');
            const hasDiceOnly = Array.from(uniqueChars).every(c => c >= '1' && c <= '6');
            if (hasBinOnly && (uniqueChars.has('0') || !hasDiceOnly || len < 3)) {
                bits = len;
            } else if (hasDiceOnly && !hasBinOnly) {
                bits = Math.floor(len * 2.58496);
            } else {
                bits = len;
            }
        }
        
        const { passed } = runMarkovAudit(currentBits);
        const repeats = hasRepetitiveSubstrings(currentBits);

        if (bits >= 128 && passed && !repeats) {
            generateKeys();
        }
    } else if (key.name === 'backspace') {
        currentBits = currentBits.slice(0, -1);
        secretBuffer = '';
        renderUI();
    } else if (key.name === 'space' || str === ' ' || str === '\t') {
        renderUI();
    } else if (str) {
        // [AUDIT-REMEDIATION: AD-13]
        // Auditor Warning: Single-keypress test triggers cause accidental public seed funding losses.
        // Remediation: Require explicit typed sequential 'test' keyword + persistent session-sticky warnings.
        // Ref: docs/AUDIT_REMEDIATION_LOG.md#AD-13
        // Track secret trigger
        secretBuffer += str.toLowerCase();
        if (secretBuffer.endsWith('test')) {
            currentBits = '42312461325243625522323266341621355533154531632254';
            isTestVector = true;
            secretBuffer = '';
            renderUI();
            return;
        }

        const cleanStr = str.replace(/\s+/g, '');
        for (const char of cleanStr) {
            if (!['0','1','2','3','4','5','6'].includes(char)) continue;

            const hasZero = currentBits.includes('0');
            const hasDiceSpecific = /[2-6]/.test(currentBits);

            if (hasZero) {
                if (char === '0' || char === '1') currentBits += char;
            } else if (hasDiceSpecific) {
                if (['1','2','3','4','5','6'].includes(char)) currentBits += char;
            } else {
                currentBits += char;
            }
        }
        renderUI();
    }
});

renderUI();
