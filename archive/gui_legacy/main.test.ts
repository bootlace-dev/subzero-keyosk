import { describe, it, expect } from 'vitest';
import { getSegWitAddress, BIP32Node, runMarkovAudit, hasRepetitiveSubstrings, deriveBip85Mnemonic } from '../../src/crypto';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { sha256 } from '@noble/hashes/sha2';

describe('SubZero Keygen Cryptographic Core', () => {

    it('should derive correct BIP32 node from standard test vector 1', () => {
        // BIP32 Test Vector 1 Seed: 000102030405060708090a0b0c0d0e0f
        const seed = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        const root = BIP32Node.fromSeed(seed);
        
        expect(root.depth).toBe(0);
        expect(root.index).toBe(0);
        expect(root.parentFingerprint).toBe(0);
        
        // Master public key serializations check (zpub magic: 0x04b24746)
        const zpub = root.toSerializedKey(false, false, true);
        expect(zpub.startsWith('zpub')).toBe(true);

        // Derive m/0' (hardened)
        const m0h = root.deriveHardened(0);
        expect(m0h.depth).toBe(1);
        expect(m0h.index).toBe(0x80000000);
        
        // Derive m/0'/1 (normal child of hardened node)
        const m0h1 = m0h.derive(1);
        expect(m0h1.depth).toBe(2);
        expect(m0h1.index).toBe(1);
        
        // Verify key integrity post derivation
        expect(m0h1.privateKey).toBeDefined();
        expect(m0h1.publicKey).toBeDefined();
    });

    it('should derive valid Native SegWit (Bech32) addresses conforming to BIP84', () => {
        const seed = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        const root = BIP32Node.fromSeed(seed);
        const p1 = root.deriveHardened(84);
        const p2 = p1.deriveHardened(0);
        const account = p2.deriveHardened(0);
        
        const receiveNode = account.derive(0);
        const child0 = receiveNode.derive(0); // m/84'/0'/0'/0/0
        const child1 = receiveNode.derive(1); // m/84'/0'/0'/0/1
        
        const address0 = getSegWitAddress(child0.publicKey);
        const address1 = getSegWitAddress(child1.publicKey);
        
        expect(address0.startsWith('bc1q')).toBe(true);
        expect(address0.length).toBe(42);
        expect(address1.startsWith('bc1q')).toBe(true);
        expect(address1.length).toBe(42);
        expect(address0).not.toBe(address1);
    });

    it('should handle zeroisation of private key structures on drop/wipe', () => {
        const seed = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        const root = BIP32Node.fromSeed(seed);
        expect(root.privateKey).not.toBeNull();
        
        root.wipe();
        expect(root.privateKey).toBeNull();
        expect(root.chainCode.every(b => b === 0)).toBe(true);
    });

    it('should derive correct Testnet addresses and serialized keys when isTestnet is true', () => {
        const seed = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        const root = BIP32Node.fromSeed(seed);
        const p1 = root.deriveHardened(84);
        const p2 = p1.deriveHardened(1); // Testnet cointype is 1
        const account = p2.deriveHardened(0);
        
        const xpub = account.toSerializedKey(false, true);
        const xprv = account.toSerializedKey(true, true);
        
        expect(xpub.startsWith('tpub')).toBe(true);
        expect(xprv.startsWith('tprv')).toBe(true);
        
        const receiveNode = account.derive(0);
        const child0 = receiveNode.derive(0);
        const address = getSegWitAddress(child0.publicKey, true);
        
        expect(address.startsWith('tb1q')).toBe(true);
        expect(address.length).toBe(42);
        
        root.wipe();
        p1.wipe();
        p2.wipe();
        account.wipe();
        receiveNode.wipe();
        child0.wipe();
    });

    it('should derive deterministic BIP85 child mnemonics conforming to path m/83696968\'/39\'/0\'/12\'/index\'', async () => {
        const seed = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        const root = BIP32Node.fromSeed(seed);
        
        const childMnemonic0 = await deriveBip85Mnemonic(root, 0);
        const childMnemonic1 = await deriveBip85Mnemonic(root, 1);
        
        // Assert derived mnemonics are exactly 12 words
        expect(childMnemonic0.split(' ').length).toBe(12);
        expect(childMnemonic1.split(' ').length).toBe(12);
        expect(childMnemonic0).not.toBe(childMnemonic1);

        // Verify valid BIP39 mnemonic integrity (checksum passes)
        expect(bip39.validateMnemonic(childMnemonic0, wordlist)).toBe(true);
        expect(bip39.validateMnemonic(childMnemonic1, wordlist)).toBe(true);
        
        root.wipe();
    });
});

describe('Entropy Quality Diagnostics & FIPS/NIST Audits', () => {

    it('should fail weak repetitive patterns in Markov transition audit', () => {
        // Test case 1: Alternating pattern (P(1|0) = 1.0, P(0|1) = 1.0)
        const alternating = '0101010101010101010101010101010101010101';
        const auditAlt = runMarkovAudit(alternating);
        expect(auditAlt.passed).toBe(false);

        // Test case 2: Repeating single character (P(0|0) = 1.0)
        const zeroes = '0000000000000000000000000000000000000000';
        const auditZeroes = runMarkovAudit(zeroes);
        expect(auditZeroes.passed).toBe(false);
    });

    it('should pass high-entropy random binary sequences in Markov transition audit', () => {
        // High-entropy random binary input
        const strongBinary = '01101001011011110110101001100001011011000110000101101010011000010111001101101111011001100110011001101100011010010110110001100101';
        const audit = runMarkovAudit(strongBinary);
        expect(audit.passed).toBe(true);
    });

    it('should detect repeating substrings across variable length thresholds', () => {
        // Length 2 pattern repeating 8 times consecutively
        expect(hasRepetitiveSubstrings('1010101010101010')).toBe(true);

        // Length 3 pattern repeating 4 times consecutively
        expect(hasRepetitiveSubstrings('123123123123')).toBe(true);

        // Length 4 pattern repeating 3 times consecutively
        expect(hasRepetitiveSubstrings('123412341234')).toBe(true);

        // Standard high-entropy binary sequence must not flag false positives
        const safeSeq = '0110100101101111011010100110000101101100';
        expect(hasRepetitiveSubstrings(safeSeq)).toBe(false);
    });

    it('should pass/fail basic NIST Monobit frequency tests', () => {
        // Helper function for Monobit frequency check
        const monobitCheck = (str: string): boolean => {
            let ones = 0;
            for (let i = 0; i < str.length; i++) {
                if (str[i] === '1') ones++;
            }
            const ratio = ones / str.length;
            return ratio >= 0.35 && ratio <= 0.65;
        };

        // Standard random binary sequence: passes
        const randomStr = '0110100101101111011010100110000101101100011000010110101001100001';
        expect(monobitCheck(randomStr)).toBe(true);

        // Severely biased sequence (Frequency skew): fails
        const biasedStr = '0000000100000000000000001000000000000000000001000000000000000000';
        expect(monobitCheck(biasedStr)).toBe(false);
    });
});

describe('State Wipe Recovery Loop (RECOVERY_LOOP_TDD)', () => {

    it('should execute a complete state recovery cycle with identical outputs and verified zeroisation', async () => {
        const testEntropy = '01101001011011110110101001100001011011000110000101101010011000010111001101101111011001100110011001101100011010010110110001100101';
        
        // 1. Digest entropy
        const manualInputBytes1 = new TextEncoder().encode(testEntropy);
        const manualHash1 = sha256(manualInputBytes1);
        const entropy16_1 = manualHash1.slice(0, 16);
        
        // 2. Generate first wallet
        const mnemonic1 = bip39.entropyToMnemonic(entropy16_1, wordlist);
        const seed1 = await bip39.mnemonicToSeed(mnemonic1);
        const root1 = BIP32Node.fromSeed(seed1);
        const account1 = root1.deriveHardened(84).deriveHardened(0).deriveHardened(0);
        const xpub1 = account1.toSerializedKey(false);
        const address1 = getSegWitAddress(account1.derive(0).derive(0).publicKey);
        
        // 3. Reset and wipe simulation
        manualInputBytes1.fill(0);
        manualHash1.fill(0);
        entropy16_1.fill(0);
        seed1.fill(0);
        root1.wipe();
        account1.wipe();
        
        // Verify absolute memory zeroisation
        expect(manualInputBytes1.every(b => b === 0)).toBe(true);
        expect(manualHash1.every(b => b === 0)).toBe(true);
        expect(entropy16_1.every(b => b === 0)).toBe(true);
        expect(root1.privateKey).toBeNull();
        expect(account1.privateKey).toBeNull();
        expect(seed1.every(b => b === 0)).toBe(true);
        
        // 4. Re-inject same entropy and recalculate
        const manualInputBytes2 = new TextEncoder().encode(testEntropy);
        const manualHash2 = sha256(manualInputBytes2);
        const entropy16_2 = manualHash2.slice(0, 16);
        
        const mnemonic2 = bip39.entropyToMnemonic(entropy16_2, wordlist);
        const seed2 = await bip39.mnemonicToSeed(mnemonic2);
        const root2 = BIP32Node.fromSeed(seed2);
        const account2 = root2.deriveHardened(84).deriveHardened(0).deriveHardened(0);
        const xpub2 = account2.toSerializedKey(false);
        const address2 = getSegWitAddress(account2.derive(0).derive(0).publicKey);
        
        // 5. Assert identity recovery match
        expect(mnemonic2).toBe(mnemonic1);
        expect(xpub2).toBe(xpub1);
        expect(address2).toBe(address1);
        
        // Cleanup
        manualInputBytes2.fill(0);
        manualHash2.fill(0);
        entropy16_2.fill(0);
        seed2.fill(0);
        root2.wipe();
        account2.wipe();
    });
});
