// ZERO-KNOWLEDGE AUTHORSHIP PROOF (ZK-AP):
// SHA-256 hash of secret pre-image proving authorship: 14a48b8d6f518c45edfd4edb21ce57657a6b4e762369a8a18d5151a526bcc577
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { hmac } from '@noble/hashes/hmac.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import QRCode from 'qrcode';

import { polymod, hrpExpand, createChecksum, getSegWitAddress, BIP32Node, deriveBip85Mnemonic, runMarkovAudit, hasRepetitiveSubstrings } from "./crypto";

function updateUI() {
    const len = currentBits.length;

    // Mode Detection & Bit Strength Calculation
    let mode = 'NONE';
    let isBin = len > 0 && currentBits.replace(/[01]/g, '').length === 0;
    let isDice = len > 0 && currentBits.replace(/[1-6]/g, '').length === 0;
    let isHex = len > 0 && currentBits.replace(/[0-9a-fA-F]/g, '').length === 0;

    let bits = 0;
    if (isBin) {
        mode = 'BINARY';
        bits = len;
    } else if (isDice) {
        mode = 'DICE';
        bits = Math.floor(len * 2.58496);
    } else if (isHex) {
        mode = 'HEXADECIMAL';
        bits = len * 4;
    } else if (len > 0) {
        mode = 'MIXED';
        bits = len;
    }

    if (valMode) valMode.textContent = mode;
    if (bitsCountText) bitsCountText.textContent = `${bits} / 128 bits`;
    
    const percentage = Math.min(100, (bits / 128) * 100);
    if (progressBarFill) progressBarFill.style.width = `${percentage}%`;



    // Input log update
    if (inputLog) inputLog.textContent = currentBits || 'No inputs recorded. Type in the input field above.';

    // Shannon calculation (symbol-based frequency)
    let shannon = 0;
    if (len > 0) {
        const freq: { [key: string]: number } = {};
        for (let i = 0; i < len; i++) {
            freq[currentBits[i]] = (freq[currentBits[i]] || 0) + 1;
        }
        for (const char in freq) {
            const p = freq[char] / len;
            shannon -= p * Math.log2(p);
        }
    }
    if (valShannon) valShannon.textContent = `${Math.round(shannon * 100) / 100} bits/sym`;

    // Markov transition check
    const markov = runMarkovAudit(currentBits);
    if (valTransition) {
        valTransition.textContent = len < 10 ? 'N/A' : `${markov.passed ? 'PASSED' : 'WEAK'} (${markov.transitionScore})`;
        valTransition.style.color = len < 10 ? 'var(--text-secondary)' : (markov.passed ? 'var(--accent-green)' : 'var(--accent-red)');
    }

    // Substring repetition check
    const repeats = hasRepetitiveSubstrings(currentBits);

    // Lock/Unlock check
    const enoughBits = bits >= 128;
    const isQualitySafe = markov.passed && !repeats;

    if (enoughBits && isQualitySafe) {
        isLocked = false;
        if (valStatus) {
            valStatus.textContent = 'UNLOCKED';
            valStatus.style.color = 'var(--accent-green)';
        }
        if (btnGenerate) btnGenerate.disabled = false;
    } else {
        isLocked = true;
        if (valStatus) {
            valStatus.textContent = !enoughBits ? 'LOCKED (INSUFFICIENT)' : 'LOCKED (PATTERN FLAGGED)';
            valStatus.style.color = 'var(--accent-red)';
        }
        if (btnGenerate) btnGenerate.disabled = true;
    }
}

// Bind UI event listeners only if elements are present (e.g. running in browser)
if (typeof document !== 'undefined' && gateCheck && gateBtn && gateOverlay && mainApp) {
    gateCheck.addEventListener('change', () => {
        if (gateCheck && gateBtn) gateBtn.disabled = !gateCheck.checked;
    });

    gateBtn.addEventListener('click', () => {
        if (gateOverlay && mainApp) {
            gateOverlay.classList.add('hidden');
            mainApp.classList.remove('hidden');
            if (entropyInput) entropyInput.focus();
        }
    });

    if (entropyInput) {
        entropyInput.addEventListener('input', () => {
            const rawVal = entropyInput.value;
            let sanitized = '';
            if (rawVal.length > 0) {
                const first = rawVal[0];
                if (first === '0' || first === '1') {
                    sanitized = rawVal.replace(/[^01]/g, '');
                } else if (['2','3','4','5','6'].includes(first)) {
                    sanitized = rawVal.replace(/[^1-6]/g, '');
                } else {
                    sanitized = rawVal.replace(/[^0-9a-fA-F]/g, '');
                }
            }
            currentBits = sanitized;
            entropyInput.value = sanitized;
            updateUI();
        });
    }

    if (useTestnet) {
        useTestnet.addEventListener('change', () => {
            if (useTestnet && testnetInfo) {
                if (useTestnet.checked) {
                    testnetInfo.classList.remove('hidden');
                } else {
                    testnetInfo.classList.add('hidden');
                }
            }
            triggerReset(true);
        });
    }

    if (btnClear) {
        btnClear.addEventListener('click', () => {
            currentBits = '';
            if (entropyInput) entropyInput.value = '';
            updateUI();
        });
    }

    if (btnDevFill) {
        btnDevFill.addEventListener('click', () => {
            currentBits = '11010010111011110101100011011011100101101001000101111011000101001100101010110011000011110100111001011101010010011011101100101101';
            if (entropyInput) entropyInput.value = currentBits;
            updateUI();
        });
    }

    if (btnGenerate) {
        btnGenerate.addEventListener('click', async () => {
            if (isLocked) return;

            btnGenerate.disabled = true;
            btnGenerate.innerText = 'Deriving Keys (Please Wait)...';

            setTimeout(async () => {
                let manualInputBytes: Uint8Array | null = null;
                let manualHash: Uint8Array | null = null;
                let finalEntropy: Uint8Array | null = null;
                let sysBytes: Uint8Array | null = null;
                let entropy16: Uint8Array | null = null;

                let mnemonicStr = '';
                let seedBytes = new Uint8Array(0);
                let rootNode: BIP32Node | null = null;
                let p1: BIP32Node | null = null;
                let p2: BIP32Node | null = null;
                let accountNode: BIP32Node | null = null;

                try {
                    manualInputBytes = new TextEncoder().encode(currentBits);
                    manualHash = sha256(manualInputBytes);

                    if (mixSystemEntropy && mixSystemEntropy.checked) {
                        // Collect 32 bytes of secure random entropy from CSPRNG
                        sysBytes = new Uint8Array(32);
                        window.crypto.getRandomValues(sysBytes);
                        
                        // XOR them together
                        finalEntropy = new Uint8Array(32);
                        for (let i = 0; i < 32; i++) {
                            finalEntropy[i] = manualHash[i] ^ sysBytes[i];
                        }
                    } else {
                        finalEntropy = new Uint8Array(manualHash);
                    }

                    // Slice to exactly 16 bytes (128 bits) to generate 12 words
                    entropy16 = finalEntropy.slice(0, 16);

                    mnemonicStr = bip39.entropyToMnemonic(entropy16, wordlist);
                    
                    // Derive master seed
                    seedBytes = await bip39.mnemonicToSeed(mnemonicStr);
                    rootNode = BIP32Node.fromSeed(seedBytes);
                    
                    isTestnetMode = useTestnet ? useTestnet.checked : false;

                    // Derive account node m/84'/0'/0' (Mainnet) or m/84'/1'/0' (Testnet)
                    p1 = rootNode.deriveHardened(84);
                    p2 = p1.deriveHardened(isTestnetMode ? 1 : 0);
                    accountNode = p2.deriveHardened(0);

                    const xprv = accountNode.toSerializedKey(true, isTestnetMode);
                    const xpub = accountNode.toSerializedKey(false, isTestnetMode);

                    // Compute fingerprint
                    const fp = rootNode.getFingerprint();
                    const fingerprint = fp.toString(16).padStart(8, '0');
                    const pathCoinType = isTestnetMode ? "1'" : "0'";
                    const descriptor = `wpkh([${fingerprint}/84'/${pathCoinType}/0']${xpub}/0/*)`;

                    // Derive first 25 addresses
                    const receiveNode = accountNode.derive(0);
                    derivedAddresses = [];
                    for (let i = 0; i < 25; i++) {
                        const child = receiveNode.derive(i);
                        const address = getSegWitAddress(child.publicKey, isTestnetMode);
                        derivedAddresses.push(address);
                        child.wipe();
                    }
                    receiveNode.wipe();
                    
                    // Render Addresses Page 1
                    addressPage = 0;
                    renderAddresses();

                    // Derive first 25 BIP85 child mnemonics
                    derivedBip85Mnemonics = [];
                    for (let i = 0; i < 25; i++) {
                        const childMnemonic = await deriveBip85Mnemonic(rootNode, i);
                        derivedBip85Mnemonics.push(childMnemonic);
                    }
                    
                    // Render BIP85 Page 1
                    bip85Page = 0;
                    renderBip85();

                    // Display outputs (obfuscate seed/xprv unless hovered)
                    if (dispSeed) dispSeed.textContent = Array.from(seedBytes.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join('');
                    if (dispXprv) dispXprv.textContent = xprv;
                    if (dispXpub) dispXpub.textContent = xpub;
                    if (dispDescriptor) dispDescriptor.textContent = descriptor;

                    // Render Mnemonic Words Grid
                    if (dispMnemonic) {
                        dispMnemonic.innerHTML = '';
                        const words = mnemonicStr.split(' ');
                        words.forEach((w, idx) => {
                            const item = document.createElement('div');
                            item.className = 'word-item';
                            item.innerHTML = `<span>${idx + 1}.</span> ${w}`;
                            dispMnemonic.appendChild(item);
                        });
                    }

                    // Generate QR code of watch-only descriptor
                    if (qrCanvas) {
                        QRCode.toCanvas(qrCanvas, descriptor, { width: 180, margin: 2 }, (error) => {
                            if (error) console.error(error);
                        });
                    }

                    // Toggle UI
                    if (privateOutputs) privateOutputs.classList.remove('hidden');
                    if (publicOutputs) publicOutputs.classList.remove('hidden');
                    if (btnReset) btnReset.classList.remove('hidden');

                    // Lock input field to prevent inconsistent/scary UI state
                    isLocked = true;
                    if (entropyInput) entropyInput.disabled = true;
                    if (btnClear) btnClear.classList.add('hidden');
                    if (btnGenerate) btnGenerate.classList.add('hidden');

                    // Scroll to outputs
                    if (publicOutputs) publicOutputs.scrollIntoView({ behavior: 'smooth' });

                } catch (e: any) {
                    alert('Error generating wallet: ' + e.message);
                } finally {
                    if (manualInputBytes) manualInputBytes.fill(0);
                    if (manualHash) manualHash.fill(0);
                    if (sysBytes) sysBytes.fill(0);
                    if (finalEntropy) finalEntropy.fill(0);
                    if (entropy16) entropy16.fill(0);
                    if (seedBytes) seedBytes.fill(0);
                    if (rootNode) rootNode.wipe();
                    if (p1) p1.wipe();
                    if (p2) p2.wipe();
                    if (accountNode) accountNode.wipe();

                    if (btnGenerate) {
                        btnGenerate.disabled = false;
                        btnGenerate.innerText = 'Generate 12-Word Seed';
                    }
                }
            }, 50);
        });
    }

    if (btnReset) {
        btnReset.addEventListener('click', () => {
            triggerReset(false);
        });
    }

    init();
    updateUI();
}

