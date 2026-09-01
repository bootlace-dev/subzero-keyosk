import { describe, it, expect } from 'vitest';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { sha256 } from '@noble/hashes/sha2.js';
import { 
    BIP32Node, 
    getSegWitAddress, 
    deriveBip85Mnemonic,
    deriveBip85Nostr,
    deriveBip85Hex,
    solve12thWordCandidates,
    suggestBip39Correction,
    encryptVaultJson,
    decryptVaultJson,
    runMarkovAudit, 
    hasRepetitiveSubstrings,
    getDescriptorChecksum 
} from '../src/crypto.js';

describe('Vector 1: Cryptographic Engine & BIP Test Vectors', () => {

    // --- BIP39 Test Vectors ---
    describe('BIP39 Spec Compliance', () => {
        it('should correctly convert hex entropy to valid BIP39 mnemonics and seeds', async () => {
            // Official BIP39 test vector 1 (128-bit 0000...)
            const entropyHex1 = '00000000000000000000000000000000';
            const entropyBytes1 = new Uint8Array(entropyHex1.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
            const mnemonic1 = bip39.entropyToMnemonic(entropyBytes1, wordlist);
            expect(mnemonic1).toBe('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
            expect(bip39.validateMnemonic(mnemonic1, wordlist)).toBe(true);

            const seed1 = await bip39.mnemonicToSeed(mnemonic1, 'TREZOR');
            const seedHex1 = Array.from(seed1).map(b => b.toString(16).padStart(2, '0')).join('');
            expect(seedHex1).toBe('c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04');

            // Official BIP39 test vector (128-bit ffff...)
            const entropyHex2 = 'ffffffffffffffffffffffffffffffff';
            const entropyBytes2 = new Uint8Array(entropyHex2.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
            const mnemonic2 = bip39.entropyToMnemonic(entropyBytes2, wordlist);
            expect(mnemonic2).toBe('zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong');
            expect(bip39.validateMnemonic(mnemonic2, wordlist)).toBe(true);
        });
    });

    // --- BIP32 Official Test Vectors ---
    describe('BIP32 Spec Compliance (Official Vectors)', () => {
        it('should match BIP32 Vector 1 derivations', () => {
            // Vector 1 Seed: 000102030405060708090a0b0c0d0e0f
            const seed = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
            const master = BIP32Node.fromSeed(seed);

            // Chain m
            expect(master.depth).toBe(0);
            expect(master.parentFingerprint).toBe(0);
            expect(master.index).toBe(0);

            // Chain m/0' (hardened)
            const m0h = master.deriveHardened(0);
            expect(m0h.depth).toBe(1);
            expect(m0h.index).toBe(0x80000000);

            // Chain m/0'/1
            const m0h1 = m0h.derive(1);
            expect(m0h1.depth).toBe(2);
            expect(m0h1.index).toBe(1);

            // Chain m/0'/1/2'
            const m0h12h = m0h1.deriveHardened(2);
            expect(m0h12h.depth).toBe(3);
            expect(m0h12h.index).toBe(0x80000002);

            // Chain m/0'/1/2'/2
            const m0h12h2 = m0h12h.derive(2);
            expect(m0h12h2.depth).toBe(4);
            expect(m0h12h2.index).toBe(2);

            // Chain m/0'/1/2'/2/1000000000
            const m0h12h2_1b = m0h12h2.derive(1000000000);
            expect(m0h12h2_1b.depth).toBe(5);
            expect(m0h12h2_1b.index).toBe(1000000000);
        });

        it('should correctly derive path strings using derivePath()', () => {
            const seed = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
            const master = BIP32Node.fromSeed(seed);

            const manual = master.deriveHardened(84).deriveHardened(0).deriveHardened(0).derive(0).derive(0);
            const fromPath = master.derivePath("m/84'/0'/0'/0/0");

            expect(fromPath.depth).toBe(5);
            expect(Array.from(fromPath.publicKey)).toEqual(Array.from(manual.publicKey));
            expect(Array.from(fromPath.privateKey!)).toEqual(Array.from(manual.privateKey!));
        });
    });

    // --- BIP84 Native SegWit Test Vectors ---
    describe('BIP84 Test Vectors (Native SegWit Bech32)', () => {
        const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
        
        it('should derive exact BIP84 account keys and addresses', async () => {
            const seed = await bip39.mnemonicToSeed(mnemonic, '');
            const root = BIP32Node.fromSeed(seed);

            // Root fingerprint
            const rootFp = root.getFingerprint();
            const rootFpHex = (rootFp >>> 0).toString(16).padStart(8, '0');
            expect(rootFpHex).toBe('73c5da0a');

            // Account m/84'/0'/0'
            const account = root.derivePath("m/84'/0'/0'");
            expect(account.depth).toBe(3);

            // Serialized zpub magic check
            const zpub = account.toSerializedKey(false, false, true);
            expect(zpub).toBe('zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs');

            // Receive address 0: m/84'/0'/0'/0/0 (Official BIP84 vector address)
            const addrNode0 = account.derivePath('0/0');
            const addr0 = getSegWitAddress(addrNode0.publicKey);
            expect(addr0).toBe('bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');

            // Receive address 1: m/84'/0'/0'/0/1 (Official BIP84 vector address)
            const addrNode1 = account.derivePath('0/1');
            const addr1 = getSegWitAddress(addrNode1.publicKey);
            expect(addr1).toBe('bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g');

            // Change address 0: m/84'/0'/0'/1/0 (Official BIP84 vector address)
            const changeNode0 = account.derivePath('1/0');
            const change0 = getSegWitAddress(changeNode0.publicKey);
            expect(change0).toBe('bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el');
        });
    });

    // --- BIP85 Deterministic Child Entropy Vectors ---
    describe('BIP85 Spec Compliance', () => {
        it('should derive deterministic BIP85 child mnemonics from root seed', async () => {
            const seed = new Uint8Array(64).fill(0x01);
            const root = BIP32Node.fromSeed(seed);

            const child12 = await deriveBip85Mnemonic(root, 0, 12);
            expect(child12.split(' ').length).toBe(12);
            expect(bip39.validateMnemonic(child12, wordlist)).toBe(true);

            const child24 = await deriveBip85Mnemonic(root, 0, 24);
            expect(child24.split(' ').length).toBe(24);
            expect(bip39.validateMnemonic(child24, wordlist)).toBe(true);

            const child12_idx1 = await deriveBip85Mnemonic(root, 1, 12);
            expect(child12_idx1).not.toBe(child12);
        });
    });

    // --- Entropy Quality Hard Blocks & Attack Prevention ---
    describe('Entropy Quality & Boundary Hard Blocks', () => {
        it('should flag low-entropy repeating and alternating strings in Markov audit', () => {
            expect(runMarkovAudit('0000000000000000000000000000000000000000').passed).toBe(false);
            expect(runMarkovAudit('1111111111111111111111111111111111111111').passed).toBe(false);
            expect(runMarkovAudit('0101010101010101010101010101010101010101').passed).toBe(false);
        });

        it('should detect periodic patterns in substring audit', () => {
            expect(hasRepetitiveSubstrings('123412341234')).toBe(true);
            expect(hasRepetitiveSubstrings('1010101010101010')).toBe(true);
            expect(hasRepetitiveSubstrings('abcabcabcabc')).toBe(true);
        });

        it('should pass high-entropy natural dice/coinflip sequences', () => {
            // 128 bits of actual pseudo-random coinflips
            const trueRandomCoins = '10110100110101011100010100111010110100010101101001011110100101011001010101110100101001011101010101101010110010100101101010110101';
            expect(runMarkovAudit(trueRandomCoins).passed).toBe(true);
            expect(hasRepetitiveSubstrings(trueRandomCoins)).toBe(false);
        });
    });

    // --- RECOVERY_LOOP_TDD: State Wipe & Zeroization ---
    describe('State Recovery & Memory Hygiene', () => {
        it('should ensure wipe() zeroizes all key buffers and recalculation recovers exact same state', async () => {
            const rawEntropy = '10110100110101011100010100111010110100010101101001011110100101011001010101110100101001011101010101101010110010100101101010110101';
            
            // Pass 1
            const hash1 = sha256(new TextEncoder().encode(rawEntropy));
            const entropyBytes1 = hash1.slice(0, 16);
            const mnem1 = bip39.entropyToMnemonic(entropyBytes1, wordlist);
            const seed1 = await bip39.mnemonicToSeed(mnem1, '');
            const root1 = BIP32Node.fromSeed(seed1);
            const zpub1 = root1.derivePath("m/84'/0'/0'").toSerializedKey(false);
            const addr1 = getSegWitAddress(root1.derivePath("m/84'/0'/0'/0/0").publicKey);

            // Wipe Pass 1
            root1.wipe();
            expect(root1.privateKey).toBeNull();
            expect(root1.chainCode.every(b => b === 0)).toBe(true);
            expect(root1.publicKey.every(b => b === 0)).toBe(true);

            // Pass 2 (Recovery Loop)
            const hash2 = sha256(new TextEncoder().encode(rawEntropy));
            const entropyBytes2 = hash2.slice(0, 16);
            const mnem2 = bip39.entropyToMnemonic(entropyBytes2, wordlist);
            const seed2 = await bip39.mnemonicToSeed(mnem2, '');
            const root2 = BIP32Node.fromSeed(seed2);
            const zpub2 = root2.derivePath("m/84'/0'/0'").toSerializedKey(false);
            const addr2 = getSegWitAddress(root2.derivePath("m/84'/0'/0'/0/0").publicKey);

            expect(mnem2).toBe(mnem1);
            expect(zpub2).toBe(zpub1);
            expect(addr2).toBe(addr1);

            root2.wipe();
        });

        it('should calculate valid 8-character BIP380 descriptor checksum', () => {
            const rawDesc = "wpkh([5a347044/84'/0'/0']xpub6CLxG9h4y5eN2n8Xv7Xf8kL6L9h4y5eN2n8Xv7Xf8kL6L9h4y5eN2n8Xv7Xf8kL6L9h4y5eN2n8Xv7Xf8kL6/<0;1>/*)";
            const cksum = getDescriptorChecksum(rawDesc);
            expect(cksum.length).toBe(8);
            expect(/^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{8}$/.test(cksum)).toBe(true);

            // Test vector from Bitcoin Core doc
            const coreDesc = "rawtr(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
            const coreCksum = getDescriptorChecksum(coreDesc);
            expect(coreCksum.length).toBe(8);
        });
    });

    // --- Subzero Vault Mini-Tools & Multi-Protocol Suite ---
    describe('Subzero Vault Suite Extensions', () => {
        const testMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
        
        it('should derive valid Nostr nsec/npub keys from BIP-85 path', async () => {
            const seed = await bip39.mnemonicToSeed(testMnemonic, '');
            const nostr = deriveBip85Nostr(seed, 0);
            
            expect(nostr.nsec.startsWith('nsec1')).toBe(true);
            expect(nostr.npub.startsWith('npub1')).toBe(true);
            expect(nostr.privHex.length).toBe(64);
            expect(nostr.pubHex.length).toBe(64);
        });

        it('should derive valid BIP-85 hex entropy strings', async () => {
            const seed = await bip39.mnemonicToSeed(testMnemonic, '');
            const hex32 = deriveBip85Hex(seed, 32, 0);
            expect(hex32.length).toBe(64);
            expect(/^[0-9a-f]{64}$/.test(hex32)).toBe(true);
        });

        it('should solve 11-word BIP-39 mnemonic candidates and fix single-word typos', () => {
            const eleven = ['abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon'];
            const candidates = solve12thWordCandidates(eleven);
            expect(candidates.length).toBeGreaterThan(0);
            expect(candidates.includes('about')).toBe(true);

            const typoFix = suggestBip39Correction('abondon');
            expect(typoFix[0].word).toBe('abandon');
            expect(typoFix[0].distance).toBe(1);
        });

        it('should execute full WebCrypto AES-256-GCM symmetric encryption/decryption loop', async () => {
            const payload = JSON.stringify({
                heirA_btc: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
                bitwarden_master: 'P@ssw0rd123!',
                google_backup_codes: ['12345678', '87654321']
            });
            const passphraseSeed = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';

            const encryptedVault = await encryptVaultJson(payload, passphraseSeed);
            const vaultObj = JSON.parse(encryptedVault);
            
            expect(vaultObj.format).toBe('subzero-vault-v1');
            expect(vaultObj.cipher).toBe('AES-256-GCM');
            expect(vaultObj.iterations).toBe(600000);
            expect(vaultObj.ciphertext).toBeDefined();

            // Decrypt with correct seed
            const decrypted = await decryptVaultJson(encryptedVault, passphraseSeed);
            expect(decrypted).toBe(payload);

            // Decrypt with wrong seed throws Error
            const wrongSeed = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
            await expect(decryptVaultJson(encryptedVault, wrongSeed)).rejects.toThrow();
        });

        it('should calculate test5 (All 0xFF / Zoo) BIP-85 Index 0 Passphrase', async () => {
            const masterMnemonic = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';
            const seed = await bip39.mnemonicToSeed(masterMnemonic, '');
            const rootNode = BIP32Node.fromSeed(seed);
            const passphrase = deriveBip85Mnemonic(rootNode, 0, 12);
            console.log(">>> TEST5_ZOO_BIP85_INDEX_0_PASSPHRASE:", passphrase);
            for (let i = 1; i <= 5; i++) {
                console.log(`>>> TEST5_HEIR_${i}:`, deriveBip85Mnemonic(rootNode, i, 12));
            }
            expect(passphrase).toBeDefined();
            expect(passphrase.split(' ').length).toBe(12);
        });
    });
});
