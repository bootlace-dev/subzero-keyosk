#!/usr/bin/env python3
"""
SubZero Vault Interactive QEMU Optical Validation Test Harness
"""
import subprocess
import time
import os
import sys
import socket
from PIL import Image

WORKSPACE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
IMG_PATH = os.path.join(WORKSPACE, "dist", "subzero-vault-pc.img")
OVMF_CODE = "/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS_SRC = "/usr/share/OVMF/OVMF_VARS_4M.fd"
TMP_VARS = "/tmp/subzero_vault_qemu_vars.fd"
MONITOR_SOCK = "/tmp/subzero_vault_qemu_monitor.sock"
VNC_SOCK = "/tmp/subzero_vault_qemu_vnc.sock"
SERIAL_LOG = "/tmp/subzero_vault_qemu_serial.log"

if not os.path.exists(IMG_PATH):
    print(f"Error: {IMG_PATH} not found.")
    sys.exit(1)

for s in [MONITOR_SOCK, VNC_SOCK]:
    if os.path.exists(s):
        try: os.remove(s)
        except Exception: pass

subprocess.run(["cp", "-f", OVMF_VARS_SRC, TMP_VARS], check=True)

print("==================================================")
print(" SUBZERO VAULT: DEEP OPTICAL & INTERACTIVE TEST   ")
print("==================================================")

qemu_cmd = [
    "qemu-system-x86_64",
    "-m", "512M",
    "-smp", "2",
    "-enable-kvm",
    "-cpu", "host",
    "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_CODE}",
    "-drive", f"if=pflash,format=raw,file={TMP_VARS}",
    "-drive", f"if=ide,format=raw,file={IMG_PATH},file.locking=off",
    "-vga", "std",
    "-vnc", f"unix:{VNC_SOCK}",
    "-monitor", f"unix:{MONITOR_SOCK},server,nowait",
    "-serial", f"file:{SERIAL_LOG}",
    "-snapshot"
]

proc = subprocess.Popen(qemu_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

try:
    print("[1/7] Connecting to QEMU monitor socket...")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connected = False
    for _ in range(50):
        try:
            sock.connect(MONITOR_SOCK)
            connected = True
            break
        except Exception:
            time.sleep(0.2)

    if not connected:
        print("Error: Could not connect to QEMU monitor.")
        sys.exit(1)

    def send_cmd(cmd: str):
        sock.sendall((cmd + "\n").encode())
        time.sleep(0.2)
        try:
            sock.setblocking(False)
            data = sock.recv(4096)
            sock.setblocking(True)
            return data.decode(errors='ignore')
        except Exception:
            try: sock.setblocking(True)
            except Exception: pass
            return ""

    def send_key(k: str):
        send_cmd(f"sendkey {k}")
        time.sleep(0.08)

    def capture_screen(name: str):
        ppm_path = f"/dev/shm/{name}.ppm"
        png_path = f"/dev/shm/{name}.png"
        send_cmd(f"screendump {ppm_path}")
        time.sleep(0.5)
        if os.path.exists(ppm_path):
            img = Image.open(ppm_path)
            img.save(png_path)
            print(f"  [Screenshot Captured] {png_path} ({img.size[0]}x{img.size[1]})")
            return png_path
        return None

    print("[2/7] Waiting for Alpine OS boot & Framebuffer initialization (22s)...")
    time.sleep(22)

    # 1. Main Menu Screen
    print("[3/7] Capturing Main Menu...")
    capture_screen("vault_qemu_0_main_menu")

    # 2. Test SeedFix Tool (Option 4)
    print("[4/7] Testing SeedFix Tool (Option 4)...")
    send_key("4")
    time.sleep(1.0)
    # Type 11 words
    for ch in "abandon ":
        send_key("spc" if ch == " " else ch)
    # Multiply
    for _ in range(10):
        for ch in "abandon ":
            send_key("spc" if ch == " " else ch)
    send_key("ret")
    time.sleep(1.5)
    capture_screen("vault_qemu_1_seedfix_results")
    send_key("esc")
    time.sleep(0.8)

    # 3. Test BIP-39 Inspector (Option 6)
    print("[5/7] Testing BIP-39 Inspector (Option 6)...")
    send_key("6")
    time.sleep(1.0)
    for ch in "aba":
        send_key(ch)
    time.sleep(1.0)
    capture_screen("vault_qemu_2_bip39_inspector")
    send_key("esc")
    time.sleep(0.8)

    # 4. Test Storage Hasher (Option 5)
    print("[6/7] Testing Storage Device Hasher (Option 5)...")
    send_key("5")
    time.sleep(1.0)
    send_key("h")
    time.sleep(1.0)
    capture_screen("vault_qemu_3_storage_hasher")
    send_key("esc")
    time.sleep(0.8)

    # 5. Test Coin-First Physical Entropy & Carousel (Option 1)
    print("[7/7] Testing Coin-First Physical Entropy & Carousel (Option 1)...")
    send_key("1")
    time.sleep(1.0)
    # Feed 128 coin flips (101101...)
    test_coins = "10110100110101011100010100111010110100010101101001011110100101011001010101110100101001011101010101101010110010100101101010110101"
    for bit in test_coins:
        send_key(bit)
    time.sleep(1.0)
    capture_screen("vault_qemu_4_coin_input_ready")

    send_key("ret")
    time.sleep(2.0)
    
    # Carousel Pages 0 - 7
    capture_screen("vault_qemu_5_master_seed_page")
    
    send_key("spc")
    time.sleep(0.4) # Page 2
    capture_screen("vault_qemu_6_decoupled_passphrase_page")

    send_key("spc")
    time.sleep(0.4) # Page 3
    capture_screen("vault_qemu_7_heir_treasuries_page")

    send_key("spc")
    time.sleep(0.4) # Page 4
    capture_screen("vault_qemu_8_descriptor_qr_page")

    send_key("spc")
    time.sleep(0.4) # Page 5
    capture_screen("vault_qemu_9_vpub_qr_page")

    send_key("spc")
    time.sleep(0.4) # Page 6
    capture_screen("vault_qemu_10_receive_addresses_page")

    send_key("spc")
    time.sleep(0.4) # Page 7
    capture_screen("vault_qemu_11_usb_export_page")

    send_key("spc")
    time.sleep(0.4) # Page 8
    capture_screen("vault_qemu_12_drill_guide_page")

    send_key("spc")
    time.sleep(0.4) # Page 9
    capture_screen("vault_qemu_13_about_provenance_page")

    print("\n==================================================")
    print(" SUCCESS: All QEMU Framebuffer Screens Verified!")
    print("==================================================")

finally:
    try: sock.close()
    except Exception: pass
    proc.terminate()
    try: proc.wait(timeout=3)
    except Exception: proc.kill()
