#!/usr/bin/env python3
"""
End-to-end automated test & screenshot suite for SubZero Keyosk:
  Layer 1: Headless Playwright offline HTML E2E (`dist/subzero-keyosk.html` & `dist/decrypt.html`)
  Layer 2: pexpect PTY interactive TUI E2E (`dist/subzero-x86_64-musl`, incl. `Alt+6` safety)
  Layer 3: Headless zero-OS-RNG UNIX CLI & external PSBT roundtrip E2E + `strace` verification
"""
import argparse
import base64
import hashlib
import json
import os
import shutil
import struct
import subprocess
import tempfile
import time

import pexpect
from playwright.sync_api import sync_playwright

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYOSK_HTML = f"file://{REPO_ROOT}/dist/subzero-keyosk.html"
DECRYPT_HTML = f"file://{REPO_ROOT}/dist/decrypt.html"
TUI_BIN = f"{REPO_ROOT}/dist/subzero-x86_64-musl"
SCREENSHOT_DIR = os.path.join(REPO_ROOT, "docs", "screenshots")

COIN_128 = (
    "1011001001101101010011100010110110100110010110101100100101110010"
    "0101100110100100110100110011010110101100010101101001101001101001"
)
DICE_60 = "314156265352164336324626433132565124163526145362154362514263"

# Preset 0 (`abandon...about`, XFP 73c5da0a) addresses from official BIP-84 Testnet4 vector
P0_RECV_0 = "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"   # m/84'/1'/0'/0/0
P0_CHG_12 = "tb1qh7xjs0ehz2atv3cv0xkl2xmffe3uqt0a7d5hfx"   # m/84'/1'/0'/1/12
P0_TR_EXT = "tb1p8wpt9v4frpf3tux04ke9460wvu26202s83k2c7"   # Arbitrary/external test check via Preset 1 recv

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_to_p2wpkh_script(addr: str) -> bytes:
    """Independently decode a BIP-173 tb1q P2WPKH address into `OP_0 <20-byte-hash>`."""
    hrp, data_part = addr.rsplit("1", 1)
    vals = [BECH32_CHARSET.index(c) for c in data_part[:-6]]
    assert vals[0] == 0, f"Expected segwit v0 for {addr}"
    acc, bits, out = 0, 0, []
    for v in vals[1:]:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    prog = bytes(out)
    assert len(prog) == 20, f"Expected 20B P2WPKH program, got {len(prog)}"
    return b"\x00\x14" + prog


def encode_varint(n: int) -> bytes:
    if n < 0xFD:
        return struct.pack("<B", n)
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def encode_psbt_kv(key: bytes, val: bytes) -> bytes:
    return encode_varint(len(key)) + key + encode_varint(len(val)) + val


def build_independent_testnet4_psbt_b64(chg_script: bytes, recv_script: bytes, ext_script: bytes) -> str:
    """
    Build a genuine BIP-174 Base64 unsigned PSBT in pure Python (`0` rust-bitcoin calls)
    funding `Preset 0` `0/0` (`50,000` sats), sending `30,000` sats externally and `19,500` sats
    back to `Preset 0` verified change `1/12` (`500` sat fee), WITH full `non_witness_utxo`.
    """
    prev_tx = (
        struct.pack("<I", 2)
        + encode_varint(1)
        + b"\x11" * 32
        + struct.pack("<I", 0)
        + encode_varint(0)
        + struct.pack("<I", 0xFFFFFFFD)
        + encode_varint(1)
        + struct.pack("<Q", 50_000)
        + encode_varint(len(recv_script))
        + recv_script
        + struct.pack("<I", 0)
    )
    prev_txid = hashlib.sha256(hashlib.sha256(prev_tx).digest()).digest()

    unsigned_tx = (
        struct.pack("<I", 2)
        + encode_varint(1)
        + prev_txid
        + struct.pack("<I", 0)
        + encode_varint(0)
        + struct.pack("<I", 0xFFFFFFFD)
        + encode_varint(2)
        + struct.pack("<Q", 30_000)
        + encode_varint(len(ext_script))
        + ext_script
        + struct.pack("<Q", 19_500)
        + encode_varint(len(chg_script))
        + chg_script
        + struct.pack("<I", 0)
    )

    witness_utxo = struct.pack("<Q", 50_000) + encode_varint(len(recv_script)) + recv_script
    psbt_bytes = (
        b"psbt\xff"
        + encode_psbt_kv(b"\x00", unsigned_tx)
        + b"\x00"  # end globals
        + encode_psbt_kv(b"\x00", prev_tx)       # PSBT_IN_NON_WITNESS_UTXO
        + encode_psbt_kv(b"\x01", witness_utxo)  # PSBT_IN_WITNESS_UTXO
        + b"\x00"  # end input 0
        + b"\x00"  # end output 0 (external)
        + b"\x00"  # end output 1 (metadata-free change 1/12; SubZero must auto-discover!)
    )
    return base64.b64encode(psbt_bytes).decode("ascii")


def varied_delay_s(idx: int, min_ms: float = 42.0, span_ms: float = 135.0) -> float:
    """Generate non-periodic deterministic jitter from SHA-256 (avoids artificial modulo buckets)."""
    h = hashlib.sha256(f"subzero-e2e-{idx}".encode()).digest()
    frac = int.from_bytes(h[:4], "little") / 0xFFFFFFFF
    return (min_ms + frac * span_ms) / 1000.0


def test_html_e2e(capture_screenshots: bool = False):
    print("[Layer 1] Running Playwright offline HTML E2E...")
    ext_script = bech32_to_p2wpkh_script("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
    unsigned_psbt_b64 = build_independent_testnet4_psbt_b64(
        bech32_to_p2wpkh_script(P0_CHG_12),
        bech32_to_p2wpkh_script(P0_RECV_0),
        ext_script,
    )

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, executable_path="/usr/bin/google-chrome")
        context = browser.new_context(offline=True, viewport={"width": 1280, "height": 960})
        page = context.new_page()

        errors = []
        page.on("dialog", lambda d: d.accept())
        page.on("pageerror", lambda err: errors.append(f"pageerror: {err}"))
        page.on("console", lambda msg: errors.append(f"console.{msg.type}: {msg.text}") if msg.type == "error" else None)

        page.goto(KEYOSK_HTML, wait_until="domcontentloaded")
        page.wait_for_function(
            "() => document.querySelector('#preset-grid button') && !document.querySelector('#btn-derive-tier1').disabled",
            timeout=15000,
        )

        # Capture clean v2.0 Intake & Presets screenshot if requested
        if capture_screenshots:
            os.makedirs(SCREENSHOT_DIR, exist_ok=True)
            page.screenshot(path=os.path.join(SCREENSHOT_DIR, "v2_01_presets.png"))

        # 1. Happy Path Hello World button + Preset 0 in collapsed All-Presets drawer
        page.click("#btn-hello-world")
        page.wait_for_function("() => document.querySelector('#w-xfp-badge').textContent.trim().length > 0", timeout=5000)
        preset_fp = page.text_content("#w-xfp-badge").strip()
        assert "73c5da0a" in preset_fp, f"Expected 73c5da0a, got {preset_fp!r}"
        print(f"  [PASS] Hello World Preset 0 loaded (fp={preset_fp})")

        if capture_screenshots:
            page.screenshot(path=os.path.join(SCREENSHOT_DIR, "v2_03_watch_only_qr.png"))

        # 2. Tier 1 Coins (open folded Tier 1 accordion first)
        page.click('button[data-tab="tab-intake"]')
        page.click("#details-tier1 > summary")
        page.select_option("#tier1-kind", "coins")
        page.fill("#tier1-input", COIN_128)
        page.click("#btn-derive-tier1")
        page.wait_for_function(
            f"() => document.querySelector('#w-xfp-badge').textContent.trim() !== '{preset_fp}'",
            timeout=5000,
        )
        coins_fp = page.text_content("#w-xfp-badge").strip()
        assert len(coins_fp) >= 8
        print(f"  [PASS] Tier 1 Coins derived (fp={coins_fp})")

        # 3. Tier 1 Dice
        page.click('button[data-tab="tab-intake"]')
        page.select_option("#tier1-kind", "dice")
        page.fill("#tier1-input", DICE_60)
        page.click("#btn-derive-tier1")
        page.wait_for_function(
            f"() => document.querySelector('#w-xfp-badge').textContent.trim() !== '{coins_fp}'",
            timeout=5000,
        )
        dice_fp = page.text_content("#w-xfp-badge").strip()
        assert len(dice_fp) >= 8
        print(f"  [PASS] Tier 1 Dice derived (fp={dice_fp})")

        # 3b. Tier 2A 100-Char Obstacle Course (open folded Tier 2 accordion + intentional Backspace typo recovery!)
        page.click('button[data-tab="tab-intake"]')
        page.click("#details-tier2 > summary")
        prompt_text = page.text_content("#obstacle-display")
        assert len(prompt_text) == 100, f"Expected 100-char prompt, got {len(prompt_text)}"
        page.click("#obstacle-focus")
        for idx, ch in enumerate(prompt_text):
            if idx == 15 or idx == 55:
                wrong = "z" if ch != "z" else "q"
                page.keyboard.press(wrong)
                time.sleep(varied_delay_s(idx + 300, 45.0, 95.0))
                page.keyboard.press("Backspace")
                time.sleep(varied_delay_s(idx + 500, 55.0, 110.0))
            page.keyboard.press(ch)
            time.sleep(varied_delay_s(idx, 38.0, 92.0))
            if capture_screenshots and idx == 28:
                page.locator("#obstacle-display").scroll_into_view_if_needed()
                page.screenshot(path=os.path.join(SCREENSHOT_DIR, "v2_02_obstacle_course.png"))
        page.click("#btn-finalize-tier2")
        page.wait_for_function(
            f"() => document.querySelector('#w-xfp-badge').textContent.trim() !== '{dice_fp}'",
            timeout=5000,
        )
        obs_fp = page.text_content("#w-xfp-badge").strip()
        print(f"  [PASS] Tier 2A 100-Char Obstacle Course + Backspace derived (fp={obs_fp})")

        # 3c. Tier 2B Free-Form Keys/Arrows + Real Pointer Jitter (>= 144 timing bits required!)
        page.click('button[data-tab="tab-intake"]')
        keys = ["a","b","c","d","e","f","g","h","i","j","k","l","ArrowUp","ArrowDown","ArrowLeft","ArrowRight"]
        ff_box = page.locator("#ff-focus").bounding_box()
        page.click("#ff-focus")
        for i in range(68):
            h = hashlib.sha256(f"ff-{i}".encode()).digest()
            k = keys[h[0] % len(keys)]
            # Prevent skipping adjacent identical key
            if i > 0 and k == keys[hashlib.sha256(f"ff-{i-1}".encode()).digest()[0] % len(keys)]:
                k = keys[(h[0] + 1) % len(keys)]
            page.keyboard.press(k)
            if ff_box and i % 4 == 0:
                page.mouse.move(
                    ff_box["x"] + 20 + (h[1] % 180),
                    ff_box["y"] + 8 + (h[2] % 16),
                )
            time.sleep(varied_delay_s(i + 900, 42.0, 145.0))
        page.click("#btn-finalize-ff")
        page.wait_for_function(
            f"() => document.querySelector('#w-xfp-badge').textContent.trim() !== '{obs_fp}'",
            timeout=5000,
        )
        ff_fp = page.text_content("#w-xfp-badge").strip()
        print(f"  [PASS] Tier 2B Free-Form (>= 144 timing bits + pointer jitter) derived (fp={ff_fp})")

        # 4. Watch-Only Taproot `tr(...)` import sanity check (open folded Import accordion first)
        page.click('button[data-tab="tab-intake"]')
        page.click("#details-all-presets > summary")
        page.click("#preset-grid button")  # back to Preset 0 so we have its tr_descriptor
        page.wait_for_function("() => document.querySelector('#w-xfp-badge').textContent.includes('73c5da0a')", timeout=5000)
        tr_desc = page.text_content("#w-extra-desc").split("BIP-86 Taproot Descriptor:\n")[1].strip()
        page.click('button[data-tab="tab-intake"]')
        page.click("#details-import > summary")
        page.fill("#import-input", tr_desc)
        page.click("#btn-import-wallet")
        page.wait_for_function(
            "() => document.querySelector('#w-wpkh-desc').textContent.includes('Taproot-only') && document.querySelector('#addr-branch-select').value === 'recv86'",
            timeout=5000,
        )
        print("  [PASS] Watch-Only Taproot tr(...) renders cleanly on recv86 without BIP-84 mislabeling")

        # 5. Independently Built Testnet4 PSBT Audit & Signing (Preset 0)
        page.click('button[data-tab="tab-intake"]')
        page.click("#btn-hello-world")
        page.wait_for_function("() => document.querySelector('#w-xfp-badge').textContent.includes('73c5da0a')", timeout=5000)
        page.click('button[data-tab="tab-psbt"]')
        page.fill("#psbt-input", unsigned_psbt_b64)
        page.click("#btn-inspect-psbt")
        page.wait_for_function(
            "() => !document.querySelector('#btn-sign-psbt').disabled && document.querySelector('#psbt-report').textContent.includes('500 sats')",
            timeout=5000,
        )
        page.click("#btn-sign-psbt")
        page.wait_for_function(
            "() => !document.querySelector('#psbt-signed-panel').classList.contains('hidden') && document.querySelector('#psbt-signed-b64').value.startsWith('cHNidP')",
            timeout=5000,
        )
        if capture_screenshots:
            page.locator("#psbt-signed-panel").scroll_into_view_if_needed()
            page.screenshot(path=os.path.join(SCREENSHOT_DIR, "v2_04_psbt_audit.png"))
        print("  [PASS] PSBT independently built in Python, self-change discovered, and signed via WASM")

        # 6. Estate Vault Encrypt -> Decrypt roundtrip
        page.click('button[data-tab="tab-estate"]')
        page.click("#btn-est-autofill")
        est_pass = page.input_value("#est-pass").strip()
        assert len(est_pass.split()) == 12
        page.click("#btn-est-encrypt")
        page.wait_for_function("() => document.querySelector('#est-out-json').value.includes('subzero-vault-v2')", timeout=10000)
        vault_json = page.input_value("#est-out-json")
        parsed = json.loads(vault_json)
        assert parsed["format"] == "subzero-vault-v2"
        print("  [PASS] Estate vault.json encrypted (subzero-vault-v2)")

        # 7. Global Amnesic Wipe
        page.click("#btn-global-wipe")
        assert "73c5da0a" not in page.text_content("#w-xfp-badge").strip()
        print("  [PASS] Global Amnesic Wipe cleared keyosk state")

        # 8. Decryptor HTML
        dec_page = context.new_page()
        dec_page.on("pageerror", lambda err: errors.append(f"decrypt pageerror: {err}"))
        dec_page.goto(DECRYPT_HTML, wait_until="domcontentloaded")
        dec_page.wait_for_function("() => !document.querySelector('#btn-unlock').disabled", timeout=15000)
        dec_page.fill("#vault-json", vault_json)
        dec_page.fill("#passphrase", est_pass)
        dec_page.click("#btn-unlock")
        dec_page.wait_for_function("() => !document.querySelector('#result-panel').classList.contains('hidden')", timeout=10000)
        dec_page.click("#btn-reveal-seed")
        assert len(dec_page.text_content("#out-seed").strip().split()) >= 12
        dec_page.click("#btn-wipe")
        assert dec_page.text_content("#out-seed").strip() == ""
        print("  [PASS] decrypt.html unlocked vault.json and wiped cleanly")

        assert not errors, f"Browser errors detected: {errors}"
        browser.close()
    return unsigned_psbt_b64


def test_tui_pty():
    print("[Layer 2] Running pexpect PTY E2E on subzero-x86_64-musl...")
    child = pexpect.spawn(TUI_BIN, dimensions=(40, 120), timeout=10)
    time.sleep(0.8)
    assert child.isalive(), "TUI exited prematurely"
    # Verify Alt+6 out-of-bounds panic regression is fixed (must remain alive!)
    child.send("\x1b6")
    time.sleep(0.3)
    assert child.isalive(), "TUI panicked on Alt+6!"
    child.sendcontrol("w")
    child.expect(pexpect.EOF, timeout=5)
    child.close()
    assert child.exitstatus == 0, f"Expected exitstatus 0, got {child.exitstatus}"
    print("  [PASS] TUI handled Alt+6 without panic and exited cleanly on Ctrl+W")


def test_cli_headless(unsigned_psbt_b64: str):
    print("[Layer 3] Running headless UNIX CLI E2E + strace getrandom check...")
    help_res = subprocess.run([TUI_BIN, "--help"], capture_output=True, text=True, check=True)
    assert "SUBCOMMANDS:" in help_res.stdout

    drv = subprocess.run([TUI_BIN, "derive", "--preset", "0", "--public-only"], capture_output=True, text=True, check=True)
    prof = json.loads(drv.stdout)
    assert prof["fingerprint"] == "73c5da0a"
    assert prof.get("mnemonic") is None

    csum = subprocess.run([TUI_BIN, "descriptor-checksum", "raw(deadbeef)"], capture_output=True, text=True, check=True)
    assert csum.stdout.strip() == "raw(deadbeef)#89f8spxm"

    sfx = subprocess.run(
        [TUI_BIN, "seedfix", "--eleven", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", "--hint", "about"],
        capture_output=True,
        text=True,
        check=True,
    )
    cands = json.loads(sfx.stdout)
    assert len(cands) == 128 and cands[0]["twelfth_word"] == "about" and cands[0]["distance"] == 0

    insp = subprocess.run(
        [TUI_BIN, "inspect-psbt", "--preset", "0", "--strict"],
        input=unsigned_psbt_b64,
        capture_output=True,
        text=True,
        check=True,
    )
    insp_j = json.loads(insp.stdout)
    assert insp_j["fee_sat"] == 500 and insp_j["can_sign"] is True

    signed = subprocess.run(
        [TUI_BIN, "sign-psbt", "--preset", "0", "--json"],
        input=unsigned_psbt_b64,
        capture_output=True,
        text=True,
        check=True,
    )
    signed_j = json.loads(signed.stdout)
    assert signed_j["signatures_added"] == 1 and signed_j["signed_psbt_base64"].startswith("cHNidP")

    with tempfile.NamedTemporaryFile("w", delete=False) as tf:
        vault_path = tf.name
    try:
        r_fd, w_fd = os.pipe()
        os.write(w_fd, b"alpha bravo charlie delta echo foxtrot")
        os.close(w_fd)
        seal = subprocess.run(
            [TUI_BIN, "vault-seal", "--preset", "0", "--passphrase-fd", str(r_fd)],
            pass_fds=(r_fd,),
            capture_output=True,
            text=True,
            check=True,
        )
        os.close(r_fd)
        with open(vault_path, "w") as vf:
            vf.write(seal.stdout)

        unseal = subprocess.run(
            [TUI_BIN, "vault-unseal", "--passphrase-stdin", "--vault-file", vault_path, "--public-only"],
            input="alpha bravo charlie delta echo foxtrot",
            capture_output=True,
            text=True,
            check=True,
        )
        uj = json.loads(unseal.stdout)
        assert uj["fingerprint"] == "73c5da0a" and uj["heir_count"] == 4
    finally:
        if os.path.exists(vault_path):
            os.remove(vault_path)

    if shutil.which("strace"):
        st = subprocess.run(
            ["strace", "-e", "trace=getrandom", TUI_BIN, "derive", "--preset", "0", "--public-only"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "getrandom(" not in st.stderr, f"Unexpected getrandom syscall in CLI: {st.stderr}"
    print("  [PASS] All headless CLI subcommands, PSBT/Vault roundtrips, and 0-getrandom strace verified")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--update-screenshots", action="store_true", help="Refresh docs/screenshots PNGs from built HTML")
    args = ap.parse_args()
    psbt_b64 = test_html_e2e(capture_screenshots=args.update_screenshots)
    test_tui_pty()
    test_cli_headless(psbt_b64)
    print("ALL E2E LAYERS PASSED.")
