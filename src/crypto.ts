import { secp256k1 } from '@noble/curves/secp256k1';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { hmac } from '@noble/hashes/hmac.js';
import * as bech32 from '@scure/base';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

const N = secp256k1.CURVE.n;

// Base58Check encoding table
const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Encode(payload: Uint8Array): string {
    let zeros = 0;
    while (zeros < payload.length && payload[zeros] === 0) {
        zeros++;
    }

    let num = 0n;
    for (let i = 0; i < payload.length; i++) {
        num = (num << 8n) + BigInt(payload[i]);
    }

    let encoded = '';
    while (num > 0n) {
        const rem = Number(num % 58n);
        num = num / 58n;
        encoded = B58_ALPHABET[rem] + encoded;
    }

    return '1'.repeat(zeros) + encoded;
}

export function base58CheckEncode(version: number[], payload: Uint8Array): string {
    const data = new Uint8Array(version.length + payload.length);
    data.set(version, 0);
    data.set(payload, version.length);

    const hash1 = sha256(data);
    const hash2 = sha256(hash1);
    const checksum = hash2.slice(0, 4);

    const full = new Uint8Array(data.length + 4);
    full.set(data, 0);
    full.set(checksum, data.length);

    return base58Encode(full);
}

export class BIP32Node {
    public chainCode: Uint8Array;
    public privateKey: Uint8Array | null;
    public publicKey: Uint8Array;
    public depth: number;
    public parentFingerprint: number;
    public index: number;

    constructor(
        chainCode: Uint8Array,
        privateKey: Uint8Array | null,
        publicKey: Uint8Array,
        depth: number = 0,
        parentFingerprint: number = 0,
        index: number = 0
    ) {
        this.chainCode = new Uint8Array(chainCode);
        this.privateKey = privateKey ? new Uint8Array(privateKey) : null;
        this.publicKey = new Uint8Array(publicKey);
        this.depth = depth;
        this.parentFingerprint = parentFingerprint;
        this.index = index;
    }

    static fromSeed(seed: Uint8Array): BIP32Node {
        const key = new TextEncoder().encode("Bitcoin seed");
        const I = hmac(sha512, key, seed);
        const IL = I.slice(0, 32);
        const IR = I.slice(32, 64);

        const ILBig = BigInt('0x' + Array.from(IL).map(b => b.toString(16).padStart(2, '0')).join(''));
        if (ILBig === 0n || ILBig >= N) {
            throw new Error("Invalid master key derived from seed");
        }

        const pubKey = secp256k1.getPublicKey(IL, true);
        return new BIP32Node(IR, IL, pubKey, 0, 0, 0);
    }

    getIdentifier(): Uint8Array {
        return ripemd160(sha256(this.publicKey));
    }

    getFingerprint(): number {
        const id = this.getIdentifier();
        return ((id[0] << 24) | (id[1] << 16) | (id[2] << 8) | id[3]) >>> 0;
    }

    derive(index: number): BIP32Node {
        const isHardened = index >= 0x80000000;
        const data = new Uint8Array(37);

        if (isHardened) {
            if (!this.privateKey) {
                throw new Error("Cannot derive hardened child from public key only");
            }
            data[0] = 0x00;
            data.set(this.privateKey, 1);
        } else {
            data.set(this.publicKey, 0);
        }
        
        data[33] = (index >>> 24) & 0xff;
        data[34] = (index >>> 16) & 0xff;
        data[35] = (index >>> 8) & 0xff;
        data[36] = index & 0xff;

        const I = hmac(sha512, this.chainCode, data);
        const IL = I.slice(0, 32);
        const IR = I.slice(32, 64);

        if (this.privateKey) {
            const ki = BigInt('0x' + Array.from(this.privateKey).map(b => b.toString(16).padStart(2, '0')).join(''));
            const ILBig = BigInt('0x' + Array.from(IL).map(b => b.toString(16).padStart(2, '0')).join(''));
            
            const childBig = (ki + ILBig) % N;
            if (ILBig >= N || childBig === 0n) {
                throw new Error(`Invalid child key derived at index ${index} (IL >= N or key is zero)`);
            }
            
            const childKey = new Uint8Array(32);
            const hex = childBig.toString(16).padStart(64, '0');
            for (let j = 0; j < 32; j++) {
                childKey[j] = parseInt(hex.slice(j * 2, j * 2 + 2), 16);
            }
            
            const childPubKey = secp256k1.getPublicKey(childKey, true);
            const parentFp = this.getFingerprint();
            
            return new BIP32Node(IR, childKey, childPubKey, this.depth + 1, parentFp, index);
        } else {
            if (isHardened) throw new Error("Cannot derive hardened child from public parent");
            
            const ILBig = BigInt('0x' + Array.from(IL).map(b => b.toString(16).padStart(2, '0')).join(''));
            if (ILBig >= N) {
                throw new Error(`Invalid public child key derived at index ${index} (IL >= N)`);
            }
            
            const PointClass: any = (secp256k1 as any).ProjectivePoint || (secp256k1 as any).Point;
            const pubPoint = PointClass.fromHex(this.publicKey);
            const ILNum = BigInt('0x' + Array.from(IL).map(b => b.toString(16).padStart(2, '0')).join(''));
            const ilPoint = PointClass.BASE.multiply(ILNum);
            const childPoint = pubPoint.add(ilPoint);
            
            if (childPoint.equals(PointClass.ZERO)) {
                throw new Error(`Invalid public child key derived at index ${index} (point at infinity)`);
            }
            
            const childPubKey = childPoint.toBytes(true);
            const parentFp = this.getFingerprint();
            
            return new BIP32Node(IR, null, childPubKey, this.depth + 1, parentFp, index);
        }
    }

    deriveHardened(index: number): BIP32Node {
        return this.derive(index + 0x80000000);
    }

    derivePath(path: string): BIP32Node {
        const cleanPath = path.startsWith('m/') ? path.slice(2) : (path === 'm' ? '' : path);
        if (!cleanPath) return this;
        const segments = cleanPath.split('/').filter(s => s.length > 0);
        let curr: BIP32Node = this;
        for (const seg of segments) {
            const isHardened = seg.endsWith("'") || seg.endsWith("h") || seg.endsWith("H");
            const idxStr = isHardened ? seg.slice(0, -1) : seg;
            const idx = parseInt(idxStr, 10);
            if (isNaN(idx)) throw new Error(`Invalid path segment: ${seg}`);
            curr = isHardened ? curr.deriveHardened(idx) : curr.derive(idx);
        }
        return curr;
    }

    toSerializedKey(isPrivate: boolean = false, isTestnet: boolean = false, isZpub: boolean = false): string {
        const payload = new Uint8Array(74);
        
        payload[0] = this.depth & 0xff;
        payload[1] = (this.parentFingerprint >>> 24) & 0xff;
        payload[2] = (this.parentFingerprint >>> 16) & 0xff;
        payload[3] = (this.parentFingerprint >>> 8) & 0xff;
        payload[4] = this.parentFingerprint & 0xff;
        
        payload[5] = (this.index >>> 24) & 0xff;
        payload[6] = (this.index >>> 16) & 0xff;
        payload[7] = (this.index >>> 8) & 0xff;
        payload[8] = this.index & 0xff;
        
        payload.set(this.chainCode, 9);
        
        if (isPrivate) {
            if (!this.privateKey) throw new Error("No private key to serialize");
            payload[41] = 0x00;
            payload.set(this.privateKey, 42);
        } else {
            payload.set(this.publicKey, 41);
        }

        let version: number[];
        if (isTestnet) {
            if (isZpub) {
                version = isPrivate ? [0x04, 0x5f, 0x18, 0xbc] : [0x04, 0x5f, 0x1c, 0xf6]; // vprv / vpub
            } else {
                version = isPrivate ? [0x04, 0x35, 0x83, 0x94] : [0x04, 0x35, 0x87, 0xcf]; // tprv / tpub
            }
        } else {
            if (isZpub) {
                version = isPrivate ? [0x04, 0xb2, 0x43, 0x0c] : [0x04, 0xb2, 0x47, 0x46]; // zprv / zpub
            } else {
                version = isPrivate ? [0x04, 0x88, 0xad, 0xe4] : [0x04, 0x88, 0xb2, 0x1e]; // xprv / xpub
            }
        }

        return base58CheckEncode(version, payload);
    }

    wipe(): void {
        if (this.privateKey) {
            this.privateKey.fill(0);
            this.privateKey = null;
        }
        this.chainCode.fill(0);
        this.publicKey.fill(0);
    }
}

export function getSegWitAddress(pubKey: Uint8Array, isTestnet: boolean = false): string {
    const pubHash = ripemd160(sha256(pubKey));
    const hrp = isTestnet ? 'tb' : 'bc';
    const words = bech32.bech32.toWords(pubHash);
    const versionedWords = new Uint8Array(words.length + 1);
    versionedWords[0] = 0; // Witness Version 0
    versionedWords.set(words, 1);
    return bech32.bech32.encode(hrp, versionedWords);
}

export function deriveBIP85Child(masterSeedOrRoot: Uint8Array | BIP32Node, index: number, wordCount: number = 12): Uint8Array {
    const root = masterSeedOrRoot instanceof BIP32Node ? masterSeedOrRoot : BIP32Node.fromSeed(masterSeedOrRoot);
    const purpose = root.deriveHardened(83696968);
    const app = purpose.deriveHardened(39);
    const lang = app.deriveHardened(0);
    const lengthNode = lang.deriveHardened(wordCount);
    const childNode = lengthNode.deriveHardened(index);

    const entropyBytes = wordCount === 24 ? 32 : 16;
    const key = new TextEncoder().encode("bip-entropy-from-k");
    const childEntropy = hmac(sha512, key, childNode.privateKey!).slice(0, entropyBytes);

    childNode.wipe();
    lengthNode.wipe();
    lang.wipe();
    app.wipe();
    purpose.wipe();
    if (!(masterSeedOrRoot instanceof BIP32Node)) {
        root.wipe();
    }

    return childEntropy;
}

export function deriveBip85Mnemonic(masterSeedOrRoot: Uint8Array | BIP32Node, index: number, wordCount: number = 12): string {
    const entropy = deriveBIP85Child(masterSeedOrRoot, index, wordCount);
    const mnem = bip39.entropyToMnemonic(entropy, wordlist);
    entropy.fill(0);
    return mnem;
}

export function runMarkovAudit(input: string): { passed: boolean, maxCondProb: number, details: string } {
    if (input.length < 16) {
        return { passed: false, maxCondProb: 1.0, details: "Input length insufficient for statistical analysis (<16)" };
    }

    const counts: { [prev: string]: { [next: string]: number } } = {};
    const totals: { [prev: string]: number } = {};

    for (let i = 0; i < input.length - 1; i++) {
        const prev = input[i];
        const next = input[i + 1];

        if (!counts[prev]) counts[prev] = {};
        counts[prev][next] = (counts[prev][next] || 0) + 1;
        totals[prev] = (totals[prev] || 0) + 1;
    }

    let maxCondProb = 0;
    for (const prev in counts) {
        for (const next in counts[prev]) {
            const prob = counts[prev][next] / totals[prev];
            if (prob > maxCondProb) {
                maxCondProb = prob;
            }
        }
    }

    const passed = maxCondProb < 0.85;
    return {
        passed,
        maxCondProb,
        details: passed 
            ? `Markov audit passed: Max conditional probability ${Math.round(maxCondProb * 100)}% (<85%)`
            : `Markov audit failed: Extreme transition bias detected (${Math.round(maxCondProb * 100)}% >= 85%)`
    };
}

export function hasRepetitiveSubstrings(input: string, minChunk: number = 3, maxChunk: number = 6): boolean {
    if (input.length < minChunk * 3) return false;

    for (let size = minChunk; size <= maxChunk; size++) {
        for (let i = 0; i <= input.length - (size * 3); i++) {
            const chunk = input.slice(i, i + size);
            let match = true;
            for (let rep = 1; rep < 3; rep++) {
                if (input.slice(i + (rep * size), i + (rep * size) + size) !== chunk) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
    }
    return false;
}

// [AUDIT-REMEDIATION: CANONICAL BIP-380 DESCRIPTOR CHECKSUM]
// Ref: Bitcoin Core src/script/descriptor.cpp DescriptorChecksum implementation
export function getDescriptorChecksum(desc: string): string {
    const INPUT_CHARSET =
        "0123456789()[],'/*abcdefgh@:$%{}" +
        "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" +
        "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    
    const POLYMOD_GEN: bigint[] = [
        0xf5dee51989n,
        0xa9fdca3312n,
        0x1bab10e32dn,
        0x3706b1677an,
        0x644d626ffdn
    ];

    function polymod(c: bigint, val: number): bigint {
        const c0 = Number(c >> 35n);
        c = ((c & 0x7ffffffffn) << 5n) ^ BigInt(val);
        for (let i = 0; i < 5; i++) {
            if ((c0 >> i) & 1) {
                c ^= POLYMOD_GEN[i];
            }
        }
        return c;
    }

    let c = 1n;
    let cls = 0;
    let clscount = 0;

    for (let i = 0; i < desc.length; i++) {
        const pos = INPUT_CHARSET.indexOf(desc[i]);
        if (pos === -1) return '';
        c = polymod(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        if (++clscount === 3) {
            c = polymod(c, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if (clscount > 0) c = polymod(c, cls);
    for (let j = 0; j < 8; ++j) c = polymod(c, 0);
    c ^= 1n;

    let ret = '';
    for (let j = 0; j < 8; ++j) {
        ret += CHECKSUM_CHARSET[Number((c >> BigInt(5 * (7 - j))) & 31n)];
    }
    return ret;
}
