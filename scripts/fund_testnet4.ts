import { secp256k1 } from '@noble/curves/secp256k1';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha2';
import * as bech32 from '@scure/base';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { BIP32Node } from '../src/crypto';

function dsha256(data: Uint8Array): Uint8Array {
    return sha256(sha256(data));
}

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, (i * 2) + 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function decodeBech32Address(addr: string): Uint8Array {
    const decoded = bech32.bech32.decode(addr);
    const data = bech32.bech32.fromWords(decoded.words.slice(1));
    return new Uint8Array(data);
}

function addressToScriptPubKey(addr: string): Uint8Array {
    const hash = decodeBech32Address(addr);
    const script = new Uint8Array(22);
    script[0] = 0x00;
    script[1] = 0x14;
    script.set(hash, 2);
    return script;
}

async function main() {
    console.log("=== SUBZERO TESTNET4 TRANSACTION DISPATCHER ===");

    const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    const root = BIP32Node.fromSeed(seed);
    const acct = root.deriveHardened(84).deriveHardened(1).deriveHardened(0);
    const key0 = acct.derive(0).derive(0); // m/84'/1'/0'/0/0
    const pubKey0 = key0.publicKey;
    const privKey0 = key0.privateKey!;
    const pubKeyHash0 = ripemd160(sha256(pubKey0));

    const targets = [
        { id: "test1", addr: "tb1qmmz6jhzz8a9z5u2a30qzr0ghea49t2hxy7032a", amount: 1800 },
        { id: "test2", addr: "tb1qucaluu78c4e3plek2hat0nf6gsmzzuzc4l0ucs", amount: 1800 },
        { id: "test3", addr: "tb1qp65tg6lrlazrhkf0c2nran498hchfsaafszxgx", amount: 1800 },
        { id: "test4", addr: "tb1qgwqny4t80fjrwtzeek4q0flvjjz52m8tj07amj", amount: 1800 },
        { id: "test5", addr: "tb1qc74th7kymdhva56ntt26yzzsn5ujz2wtqcyjz8", amount: 1800 },
        { id: "test6", addr: "tb1qqujk5789ke2hxs8n4xt3wxvlkmeu287p642pnv", amount: 1800 },
        { id: "test7", addr: "tb1qvcxqx2vk6m39sqlhvtxtmmy99379tctqjkeu6c", amount: 1800 },
        { id: "test8", addr: "tb1q2t50xdr9cxg95085ge7v6m7pyf29efvarak0z4", amount: 1800 },
        { id: "test9", addr: "tb1q6fqc4n33jccj4yd7vawqfls6uns5ahg3grrusk", amount: 1800 },
        { id: "test0_change", addr: "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl", amount: 3300 }
    ];

    const utxoRes = await fetch("https://mempool.space/testnet4/api/address/tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl/utxo");
    const utxos = await utxoRes.json() as any[];
    if (utxos.length === 0) {
        console.log("No UTXOs found for test0.");
        return;
    }
    const utxo = utxos[0];
    console.log(`Using UTXO: ${utxo.txid}:${utxo.vout} (${utxo.value} sats)`);

    const txVersion = 2;
    const lockTime = 0;
    const sequence = 0xffffffff;
    const sighashType = 1;

    const prevoutBuf = new Uint8Array(36);
    const txidBytes = hexToBytes(utxo.txid).reverse();
    prevoutBuf.set(txidBytes, 0);
    const view = new DataView(prevoutBuf.buffer);
    view.setUint32(32, utxo.vout, true);
    const hashPrevouts = dsha256(prevoutBuf);

    const seqBuf = new Uint8Array(4);
    new DataView(seqBuf.buffer).setUint32(0, sequence, true);
    const hashSequence = dsha256(seqBuf);

    const outBufs: Uint8Array[] = [];
    for (const t of targets) {
        const spk = addressToScriptPubKey(t.addr);
        const b = new Uint8Array(8 + 1 + spk.length);
        const dv = new DataView(b.buffer);
        dv.setBigUint64(0, BigInt(t.amount), true);
        b[8] = spk.length;
        b.set(spk, 9);
        outBufs.push(b);
    }
    let totalOutLen = outBufs.reduce((a, c) => a + c.length, 0);
    const allOuts = new Uint8Array(totalOutLen);
    let offset = 0;
    for (const b of outBufs) {
        allOuts.set(b, offset);
        offset += b.length;
    }
    const hashOutputs = dsha256(allOuts);

    const scriptCode = new Uint8Array(26);
    scriptCode[0] = 0x19;
    scriptCode[1] = 0x76;
    scriptCode[2] = 0xa9;
    scriptCode[3] = 0x14;
    scriptCode.set(pubKeyHash0, 4);
    scriptCode[24] = 0x88;
    scriptCode[25] = 0xac;

    const preimage = new Uint8Array(4 + 32 + 32 + 36 + 26 + 8 + 4 + 32 + 4 + 4);
    const pDv = new DataView(preimage.buffer);
    let pOff = 0;

    pDv.setUint32(pOff, txVersion, true); pOff += 4;
    preimage.set(hashPrevouts, pOff); pOff += 32;
    preimage.set(hashSequence, pOff); pOff += 32;
    preimage.set(prevoutBuf, pOff); pOff += 36;
    preimage.set(scriptCode, pOff); pOff += 26;
    pDv.setBigUint64(pOff, BigInt(utxo.value), true); pOff += 8;
    pDv.setUint32(pOff, sequence, true); pOff += 4;
    preimage.set(hashOutputs, pOff); pOff += 32;
    pDv.setUint32(pOff, lockTime, true); pOff += 4;
    pDv.setUint32(pOff, sighashType, true); pOff += 4;

    const sigHash = dsha256(preimage);

    const sig = secp256k1.sign(sigHash, privKey0);
    const derSig = sig.toDERRawBytes();
    const sigWithHashType = new Uint8Array(derSig.length + 1);
    sigWithHashType.set(derSig, 0);
    sigWithHashType[derSig.length] = sighashType;

    const rawTxParts: Uint8Array[] = [];
    const vB = new Uint8Array(4);
    new DataView(vB.buffer).setUint32(0, txVersion, true);
    rawTxParts.push(vB);
    rawTxParts.push(new Uint8Array([0x00, 0x01]));
    rawTxParts.push(new Uint8Array([0x01]));
    rawTxParts.push(prevoutBuf);
    rawTxParts.push(new Uint8Array([0x00]));
    rawTxParts.push(seqBuf);
    rawTxParts.push(new Uint8Array([targets.length]));
    rawTxParts.push(allOuts);

    const witnessBuf = new Uint8Array(1 + 1 + sigWithHashType.length + 1 + pubKey0.length);
    witnessBuf[0] = 0x02;
    witnessBuf[1] = sigWithHashType.length;
    witnessBuf.set(sigWithHashType, 2);
    witnessBuf[2 + sigWithHashType.length] = pubKey0.length;
    witnessBuf.set(pubKey0, 3 + sigWithHashType.length);
    rawTxParts.push(witnessBuf);

    const ltB = new Uint8Array(4);
    new DataView(ltB.buffer).setUint32(0, lockTime, true);
    rawTxParts.push(ltB);

    const totalTxLen = rawTxParts.reduce((a, c) => a + c.length, 0);
    const rawTx = new Uint8Array(totalTxLen);
    let txOff = 0;
    for (const p of rawTxParts) {
        rawTx.set(p, txOff);
        txOff += p.length;
    }

    const rawTxHex = bytesToHex(rawTx);
    console.log("Raw Signed Transaction (Hex):", rawTxHex);

    console.log("Broadcasting to Testnet4...");
    const postRes = await fetch("https://mempool.space/testnet4/api/tx", {
        method: "POST",
        body: rawTxHex
    });
    const txid = await postRes.text();
    console.log("Broadcast Result:", txid);
}

main().catch(err => console.error("FATAL:", err));
