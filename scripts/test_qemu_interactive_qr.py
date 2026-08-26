#!/usr/bin/env python3
"""
SubZero Keyosk Interactive QEMU Optical Validation Test Harness
"""
import subprocess
import time
import os
import sys
import socket
from PIL import Image

WORKSPACE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
IMG_PATH = os.path.join(WORKSPACE, "dist", "subzero-testnet4-pc.img")
OVMF_CODE = "/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS_SRC = "/usr/share/OVMF/OVMF_VARS_4M.fd"
TMP_VARS = "/tmp/subzero_qemu_vars.fd"
MONITOR_SOCK = "/tmp/subzero_qemu_monitor.sock"
VNC_SOCK = "/tmp/subzero_qemu_vnc.sock"
SERIAL_LOG = "/tmp/subzero_qemu_serial.log"

if not os.path.exists(IMG_PATH):
    print(f"Error: {IMG_PATH} not found.")
    sys.exit(1)

for s in [MONITOR_SOCK, VNC_SOCK]:
    if os.path.exists(s):
        try: os.remove(s)
        except Exception: pass

subprocess.run(["cp", "-f", OVMF_VARS_SRC, TMP_VARS], check=True)

print("==================================================")
print(" SUBZERO KEYOSK: DEEP OPTICAL & INTERACTIVE TEST  ")
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
    print("[1/6] Connecting to QEMU monitor socket...")
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
        time.sleep(0.3)
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
        time.sleep(0.12)

    def capture_screen(name: str):
        ppm_path = f"/dev/shm/{name}.ppm"
        png_path = f"/dev/shm/{name}.png"
        send_cmd(f"screendump {ppm_path}")
        time.sleep(0.6)
        if os.path.exists(ppm_path):
            img = Image.open(ppm_path)
            img.save(png_path)
            return png_path
        return None

    print("[2/6] Waiting for OS boot and TUI initialization (15s)...")
    time.sleep(15)

    # Initial Input screen
    print("[3/6] Capturing initial input screen...")
    capture_screen("qemu_screen_0_initial")

    # Ingest 'test'
    print("[4/6] Ingesting 'test' string to populate 128-bit test vector...")
    for ch in "test":
        send_key(ch)
    time.sleep(1.0)
    capture_screen("qemu_screen_0_test_populated")

    # Press Return to process entropy and enter carousel (Page 1)
    print("[5/6] Entering carousel (Page 1 Master Seed)...")
    send_key("ret")
    time.sleep(2.0)
    capture_screen("qemu_screen_1_master_seed")

    # Page 2: Hot Seeds 0-4
    send_key("spc")
    time.sleep(0.8)
    capture_screen("qemu_screen_2_hot_seeds_0_4")

    # Page 3: Hot Seeds 5-9
    send_key("spc")
    time.sleep(0.8)
    capture_screen("qemu_screen_3_hot_seeds_5_9")

    # Page 4: Watch-Only Descriptor Text
    send_key("spc")
    time.sleep(0.8)
    capture_screen("qemu_screen_4_descriptor_text")

    # Page 5: Account VPUB QR Code
    print("[6/6] Navigating to Page 5 (Account VPUB QR), Page 6 (Descriptor QR) & Page 8 (Address #0 QR)...")
    send_key("spc")
    time.sleep(1.5)
    p5_png = capture_screen("qemu_screen_5_vpub_qr")

    # Page 6: BIP-380 Descriptor QR Code
    send_key("spc")
    time.sleep(1.5)
    p6_png = capture_screen("qemu_screen_6_descriptor_qr")

    # Page 7: Receive Addresses 0-4 Text
    send_key("spc")
    time.sleep(0.8)
    capture_screen("qemu_screen_7_receive_text")

    # Page 8: Address 0 Faucet QR
    send_key("spc")
    time.sleep(1.5)
    p8_png = capture_screen("qemu_screen_8_address_qr")

    print("\n==================================================")
    print("      OPTICAL QR CODE SCANNER RESULTS (ZBAR)      ")
    print("==================================================")

    if p5_png and os.path.exists(p5_png):
        r5 = subprocess.run(["zbarimg", "-q", "--raw", p5_png], capture_output=True, text=True)
        vpub_decoded = r5.stdout.strip()
        print(f" [Page 5 VPUB QR Decoded]      : {vpub_decoded or '[FAIL: No QR Detected]'}")
    else:
        print(" [Page 5 VPUB QR]              : Screenshot missing")

    if p6_png and os.path.exists(p6_png):
        r6 = subprocess.run(["zbarimg", "-q", "--raw", p6_png], capture_output=True, text=True)
        desc_decoded = r6.stdout.strip()
        print(f" [Page 6 Descriptor QR Decoded]: {desc_decoded or '[FAIL: No QR Detected]'}")
    else:
        print(" [Page 6 Descriptor QR]        : Screenshot missing")

    if p8_png and os.path.exists(p8_png):
        r8 = subprocess.run(["zbarimg", "-q", "--raw", p8_png], capture_output=True, text=True)
        addr_decoded = r8.stdout.strip()
        print(f" [Page 8 Address QR Decoded]   : {addr_decoded or '[FAIL: No QR Detected]'}")
    else:
        print(" [Page 8 Address QR]           : Screenshot missing")

    print("==================================================\n")

    # Clean shutdown
    send_key("q")
    time.sleep(0.5)

finally:
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except Exception:
        proc.kill()
    if os.path.exists(MONITOR_SOCK):
        try: os.remove(MONITOR_SOCK)
        except Exception: pass
    print("Test complete. Verification complete. VM halted.")
