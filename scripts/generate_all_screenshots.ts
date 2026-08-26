import { Framebuffer, RGB } from '../src/framebuffer';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { hmac } from '@noble/hashes/hmac.js';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { BIP32Node, getSegWitAddress, getDescriptorChecksum } from '../src/crypto';
import { execSync } from 'child_process';
import * as fs from 'fs';

const fb = new Framebuffer('/dev/null');
fb.geometry = { width: 1024, height: 768, bpp: 32, stride: 1024 * 4 };
fb.backBuffer = Buffer.alloc(768 * 4096);

const COLOR_BG: RGB = { r: 10, g: 15, b: 24 };           // Deep dark navy (#0A0F18)
const COLOR_CARD: RGB = { r: 18, g: 26, b: 42 };         // Dark slate card (#121A2A)
const COLOR_CARD_BORDER: RGB = { r: 40, g: 55, b: 85 };  // Slate border (#283755)
const COLOR_BADGE_BG: RGB = { r: 25, g: 38, b: 62 };     // Badge background
const COLOR_WHITE: RGB = { r: 255, g: 255, b: 255 };      // Pure crisp white (#FFFFFF)
const COLOR_ACCENT: RGB = { r: 0, g: 200, b: 255 };      // Bright cyan (#00C8FF)
const COLOR_GOLD: RGB = { r: 255, g: 190, b: 40 };       // Amber gold (#FFBE28)
const COLOR_WARN: RGB = { r: 255, g: 80, b: 80 };        // Soft red warning (#FF5050)
const COLOR_GREEN: RGB = { r: 80, g: 255, b: 120 };      // Success green (#50FF78)
const COLOR_MUTED: RGB = { r: 176, g: 194, b: 222 };     // Light slate gray (#B0C2DE - WCAG AAA)

function renderHeader(title: string, subtitle: string, isAlert: boolean = false) {
    fb.clear(COLOR_BG);
    fb.drawRect(20, 18, 1024 - 40, 68, isAlert ? { r: 35, g: 20, b: 25 } : { r: 16, g: 24, b: 40 });
    fb.drawRect(20, 18, 1024 - 40, 2, isAlert ? COLOR_GOLD : COLOR_ACCENT);
    fb.drawRect(20, 84, 1024 - 40, 2, isAlert ? COLOR_GOLD : COLOR_ACCENT);
    fb.drawTextCentered(28, title, 1, isAlert ? COLOR_GOLD : COLOR_ACCENT);
    fb.drawTextCentered(54, subtitle, 1, COLOR_WHITE);
}

function renderFooter(navText: string) {
    const footY = 768 - 40;
    fb.drawRect(20, footY - 8, 1024 - 40, 36, { r: 16, g: 24, b: 40 });
    fb.drawRect(20, footY - 8, 1024 - 40, 1, COLOR_CARD_BORDER);
    fb.drawTextCentered(footY, navText, 1, COLOR_MUTED);
}

const finalEntropy = sha256(new TextEncoder().encode("subzero-testnet4-tdd-deterministic-vector")).slice(0, 16);
const mnemonicStr = bip39.entropyToMnemonic(finalEntropy, wordlist);
const mnemonicWords = mnemonicStr.split(' ');
const masterSeed = bip39.mnemonicToSeedSync(mnemonicStr);
const rootNode = BIP32Node.fromSeed(masterSeed);
const purposeNode = rootNode.deriveHardened(84);
const coinTypeNode = purposeNode.deriveHardened(1);
const accountNode = coinTypeNode.deriveHardened(0);
const tpub = accountNode.toSerializedKey(false, true);
const fp = rootNode.getFingerprint();
const fingerprint = (fp >>> 0).toString(16).padStart(8, '0');
const rawDescriptor = `wpkh([${fingerprint}/84'/1'/0']${tpub}/<0;1>/*)`;
const descChecksum = getDescriptorChecksum(rawDescriptor);
const descriptorWithChecksum = `${rawDescriptor}#${descChecksum}`;

function savePage(name: string) {
    const ppm = `/dev/shm/${name}.ppm`;
    const png = `/dev/shm/${name}.png`;
    fb.saveToPPM(ppm);
    execSync(`convert ${ppm} ${png}`);
    fs.unlinkSync(ppm);
    console.log(`Exported: ${png}`);
}

// Page 5: Full BIP-380 Descriptor QR (Guaranteed tb1q Native SegWit in Green/Sparrow)
renderHeader(
    "[PAGE 5/8] BIP-380 DESCRIPTOR QR (WATCH-ONLY EXPORT)",
    "SCAN IN SPARROW / BLUEWALLET / BLOCKSTREAM GREEN (tb1q)"
);
const qrCenterY = Math.floor(768 / 2) + 15;
fb.drawQRCode(descriptorWithChecksum, qrCenterY, 5, 4);
fb.drawTextCentered(768 - 80, `Payload: ${descriptorWithChecksum}`, 1, COLOR_MUTED);
renderFooter("Controls: [LEFT / RIGHT / SPACE] = Page | [Q / ESC] = Power Off & Exit");
fb.flush();
savePage("screenshot_page_5_descriptor_qr");
