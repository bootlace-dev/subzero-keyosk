import { describe, it, expect } from 'vitest';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { sha256 } from '@noble/hashes/sha2.js';
import { 
    BIP32Node, 
    getSegWitAddress, 
    deriveBip85Mnemonic, 
    getDescriptorChecksum 
} from '../src/crypto.js';

describe('Testnet4 TDD Edition: Cryptographic Vector Suite', () => {

    const testMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

    it('should derive valid Testnet4 BIP-84 account (m/84\'/1\'/0\') with tpub prefix', async () => {
        const seed = await bip39.mnemonicToSeed(testMnemonic, '');
        const root = BIP32Node.fromSeed(seed);

        const rootFp = root.getFingerprint();
        const rootFpHex = (rootFp >>> 0).toString(16).padStart(8, '0');
        expect(rootFpHex).toBe('73c5da0a');

        // Derive Testnet4 account path: m/84'/1'/0'
        const accountNode = root.derivePath("m/84'/1'/0'");
        expect(accountNode.depth).toBe(3);

        // Serialize as Testnet Extended Public Key (tpub)
        const tpub = accountNode.toSerializedKey(false, true);
        expect(tpub.startsWith('tpub')).toBe(true);
        expect(tpub.length).toBeGreaterThan(100);
    });

    it('should derive valid Testnet Bech32 (tb1q...) receive addresses', async () => {
        const seed = await bip39.mnemonicToSeed(testMnemonic, '');
        const root = BIP32Node.fromSeed(seed);
        const accountNode = root.derivePath("m/84'/1'/0'");

        // First receive address: m/84'/1'/0'/0/0
        const addrNode0 = accountNode.derivePath('0/0');
        const addr0 = getSegWitAddress(addrNode0.publicKey, true);
        expect(addr0.startsWith('tb1q')).toBe(true);
        expect(addr0.length).toBe(42);

        // Second receive address: m/84'/1'/0'/0/1
        const addrNode1 = accountNode.derivePath('0/1');
        const addr1 = getSegWitAddress(addrNode1.publicKey, true);
        expect(addr1.startsWith('tb1q')).toBe(true);
        expect(addr1).not.toBe(addr0);

        // Verify mainnet flag produces bc1q and testnet flag produces tb1q for same pubkey
        const mainnetAddr = getSegWitAddress(addrNode0.publicKey, false);
        expect(mainnetAddr.startsWith('bc1q')).toBe(true);
        expect(addr0.startsWith('tb1q')).toBe(true);
        // Payload before 6-char checksum is identical
        expect(addr0.slice(4, -6)).toBe(mainnetAddr.slice(4, -6));
    });

    it('should generate valid BIP-380 multipath output descriptor for Testnet4 with checksum', async () => {
        const seed = await bip39.mnemonicToSeed(testMnemonic, '');
        const root = BIP32Node.fromSeed(seed);
        const accountNode = root.derivePath("m/84'/1'/0'");
        const tpub = accountNode.toSerializedKey(false, true);

        const fp = root.getFingerprint();
        const fingerprint = (fp >>> 0).toString(16).padStart(8, '0');

        const rawDescriptor = `wpkh([${fingerprint}/84'/1'/0']${tpub}/<0;1>/*)`;
        const checksum = getDescriptorChecksum(rawDescriptor);
        expect(checksum.length).toBe(8);
        expect(/^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{8}$/.test(checksum)).toBe(true);

        expect(getDescriptorChecksum('raw(deadbeef)')).toBe('89f8spxm');

        const fullDescriptor = `${rawDescriptor}#${checksum}`;
        expect(fullDescriptor).toContain('tpub');
        expect(fullDescriptor).toContain('/84\'/1\'/0\'');
    });

    it('should execute full state wipe and recover identical Testnet4 state', async () => {
        const rawEntropy = '10110100110101011100010100111010110100010101101001011110100101011001010101110100101001011101010101101010110010100101101010110101';
        
        // Pass 1
        const hash1 = sha256(new TextEncoder().encode(rawEntropy));
        const mnem1 = bip39.entropyToMnemonic(hash1.slice(0, 16), wordlist);
        const seed1 = await bip39.mnemonicToSeed(mnem1, '');
        const root1 = BIP32Node.fromSeed(seed1);
        const tpub1 = root1.derivePath("m/84'/1'/0'").toSerializedKey(false, true);
        const addr1 = getSegWitAddress(root1.derivePath("m/84'/1'/0'/0/0").publicKey, true);

        // Wipe Pass 1
        root1.wipe();
        expect(root1.privateKey).toBeNull();

        // Pass 2 (Recovery Loop)
        const hash2 = sha256(new TextEncoder().encode(rawEntropy));
        const mnem2 = bip39.entropyToMnemonic(hash2.slice(0, 16), wordlist);
        const seed2 = await bip39.mnemonicToSeed(mnem2, '');
        const root2 = BIP32Node.fromSeed(seed2);
        const tpub2 = root2.derivePath("m/84'/1'/0'").toSerializedKey(false, true);
        const addr2 = getSegWitAddress(root2.derivePath("m/84'/1'/0'/0/0").publicKey, true);

        expect(mnem2).toBe(mnem1);
        expect(tpub2).toBe(tpub1);
        expect(addr2).toBe(addr1);
        expect(addr2.startsWith('tb1q')).toBe(true);

        root2.wipe();
    });
});
