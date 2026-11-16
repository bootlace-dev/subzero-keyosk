#!/usr/bin/env python3
"""
End-to-end automated test suite for SubZero Keyosk:
  Layer 1: Headless Playwright offline E2E on dist/subzero-keyosk.html & dist/decrypt.html
  Layer 2: pexpect PTY E2E on dist/subzero-x86_64-musl
"""
import json
import os
import sys
import time
import pexpect
from playwright.sync_api import sync_playwright

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYOSK_HTML = f"file://{REPO_ROOT}/dist/subzero-keyosk.html"
DECRYPT_HTML = f"file://{REPO_ROOT}/dist/decrypt.html"
TUI_BIN = f"{REPO_ROOT}/dist/subzero-x86_64-musl"

COIN_128 = (
    "1011001001101101010011100010110110100110010110101100100101110010"
    "0101100110100100110100110011010110101100010101101001101001101001"
)
DICE_60 = "314156265352164336324626433132565124163526145362154362514263"


def test_html_e2e():
    print("[Layer 1] Running Playwright offline HTML E2E...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, executable_path="/usr/bin/google-chrome")
        context = browser.new_context(offline=True)
        page = context.new_page()

        errors = []
        page.on("dialog", lambda d: d.accept())
        page.on("pageerror", lambda err: errors.append(f"pageerror: {err}"))
        page.on("console", lambda msg: errors.append(f"console.{msg.type}: {msg.text}") if msg.type == "error" else None)

        page.goto(KEYOSK_HTML, wait_until="domcontentloaded")
        # Wait for WASM boot
        page.wait_for_function("() => document.querySelector('#preset-grid button') && !document.querySelector('#btn-derive-tier1').disabled", timeout=15000)

        # 1. Load Preset 0
        page.click("#preset-grid button")
        page.wait_for_function("() => document.querySelector('#w-xfp-badge').textContent.trim().length > 0", timeout=5000)
        preset_fp = page.text_content("#w-xfp-badge").strip()
        assert len(preset_fp) >= 8, f"Expected fingerprint in badge, got {preset_fp!r}"
        print(f"  [PASS] Preset 0 loaded (fp={preset_fp})")

        # 2. Tier 1 Coins
        page.click('button[data-tab="tab-intake"]')
        page.select_option("#tier1-kind", "coins")
        page.fill("#tier1-input", COIN_128)
        page.click("#btn-derive-tier1")
        page.wait_for_function(
            f"() => document.querySelector('#w-xfp-badge').textContent.trim() !== '{preset_fp}'",
            timeout=5000,
        )
        coins_fp = page.text_content("#w-xfp-badge").strip()
        assert len(coins_fp) >= 8, f"Expected coins fp, got {coins_fp!r}"
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
        assert len(dice_fp) >= 8, f"Expected dice fp, got {dice_fp!r}"
        print(f"  [PASS] Tier 1 Dice derived (fp={dice_fp})")

        # 3b. Tier 2B Free-Form Keys/Arrows + Mouse Jitter
        page.click('button[data-tab="tab-intake"]')
        keys = ["a","b","c","d","e","f","g","h","i","j","k","l","ArrowUp","ArrowDown","ArrowLeft","ArrowRight"]
        page.click("#ff-focus")
        for i in range(66):
            page.keyboard.press(keys[i % len(keys)])
            time.sleep(0.040 + (i % 7) * 0.015)
        page.click("#btn-finalize-ff")
        page.wait_for_function(
            f"() => document.querySelector('#w-xfp-badge').textContent.trim() !== '{dice_fp}' && document.querySelector('#w-xfp-badge').textContent.trim().length >= 8",
            timeout=5000,
        )
        ff_fp = page.text_content("#w-xfp-badge").strip()
        print(f"  [PASS] Tier 2B Free-Form derived (fp={ff_fp})")

        # 4. Estate Vault Encrypt -> Decrypt roundtrip
        page.click('button[data-tab="tab-estate"]')
        page.click("#btn-est-autofill")
        est_pass = page.input_value("#est-pass").strip()
        assert len(est_pass.split()) == 12, "Expected 12-word BIP-85 Index 0 passphrase"
        page.click("#btn-est-encrypt")
        page.wait_for_function("() => document.querySelector('#est-out-json').value.includes('subzero-vault-v2')", timeout=10000)
        vault_json = page.input_value("#est-out-json")
        parsed = json.loads(vault_json)
        assert parsed["format"] == "subzero-vault-v2"
        print("  [PASS] Estate vault.json encrypted (subzero-vault-v2)")

        # 5. Global Amnesic Wipe
        page.click("#btn-global-wipe")
        assert dice_fp not in page.text_content("#w-xfp-badge").strip(), "Fingerprint not wiped"
        print("  [PASS] Global Amnesic Wipe cleared keyosk state")

        # 6. Decryptor HTML
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


def test_tui_pty():
    print("[Layer 2] Running pexpect PTY E2E on subzero-x86_64-musl...")
    child = pexpect.spawn(TUI_BIN, dimensions=(40, 120), timeout=10)
    time.sleep(0.8)
    assert child.isalive(), "TUI exited prematurely"
    # Send Ctrl+W to trigger amnesic wipe & clean exit
    child.sendcontrol("w")
    child.expect(pexpect.EOF, timeout=5)
    child.close()
    assert child.exitstatus == 0, f"Expected exitstatus 0, got {child.exitstatus}"
    print("  [PASS] TUI spawned in PTY and exited cleanly on Ctrl+W")


if __name__ == "__main__":
    test_html_e2e()
    test_tui_pty()
    print("ALL E2E LAYERS PASSED.")
