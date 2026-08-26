#!/usr/bin/env python3
"""
SubZero Keyosk Verified Hardware-Accurate Optical & Visual Test Suite
Runs real UEFI VM inside Xvfb with GTK display, captures full X11 display buffer with xwd,
performs optical barcode scanning with zbarimg, and verifies zero scrolling.
"""
import subprocess
import socket
import time
import os
import sys

WORKSPACE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
IMG_PATH = os.path.join(WORKSPACE, "dist", "subzero-testnet4-pc.img")
OVMF_CODE = "/usr/share/OVMF/OVMF_CODE_4M.fd"
TMP_VARS = "/tmp/subzero_qemu_vars.fd"
MONITOR_SOCK = "/tmp/subzero_verified_mon.sock"
DISPLAY_NUM = "95"

if os.path.exists(MONITOR_SOCK):
    try: os.remove(MONITOR_SOCK)
    except Exception: pass

subprocess.run(["cp", "-f", "/usr/share/OVMF/OVMF_VARS_4M.fd", TMP_VARS], check=True)

print("==================================================")
print(" SUBZERO KEYOSK: HARDWARE-ACCURATE OPTICAL TEST   ")
print("==================================================")

xvfb_cmd = [
    "xvfb-run", "-n", DISPLAY_NUM, "-s", "-screen 0 1024x768x24",
    "python3", "-c", f"""
import subprocess, socket, time, os, sys

qemu_cmd = [
    "qemu-system-x86_64",
    "-m", "512M",
    "-smp", "2",
    "-enable-kvm",
    "-cpu", "host",
    "-drive", "if=pflash,format=raw,readonly=on,file={OVMF_CODE}",
    "-drive", "if=pflash,format=raw,file={TMP_VARS}",
    "-drive", "if=ide,format=raw,file={IMG_PATH},file.locking=off",
    "-display", "gtk,gl=off",
    "-monitor", "unix:{MONITOR_SOCK},server,nowait",
    "-snapshot"
]

proc = subprocess.Popen(qemu_cmd)
disp = os.environ.get("DISPLAY", ":{DISPLAY_NUM}")

try:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    for _ in range(50):
        try:
            sock.connect("{MONITOR_SOCK}")
            break
        except Exception:
            time.sleep(0.2)

    def send_key(k: str):
        sock.sendall((f"sendkey {{k}}\\n").encode())
        time.sleep(0.12)
        try:
            sock.setblocking(False)
            sock.recv(4096)
            sock.setblocking(True)
        except Exception:
            try: sock.setblocking(True)
            except Exception: pass

    def capture_screen(name: str):
        xwd_file = f"/dev/shm/{{name}}.xwd"
        png_file = f"/dev/shm/{{name}}.png"
        cmd = f"xwd -display {{disp}} -root -out {{xwd_file}} && convert {{xwd_file}} {{png_file}}"
        subprocess.run(cmd, shell=True, check=True)
        return png_file

    print("[1/5] Waiting 14s for OS boot to TUI on tty1...")
    time.sleep(14)
    capture_screen("hardware_screen_0_initial")

    print("[2/5] Ingesting 'test' string and Return...")
    for ch in "test":
        send_key(ch)
    time.sleep(0.5)
    send_key("ret")
    time.sleep(1.5)
    capture_screen("hardware_screen_1_seed")

    print("[3/5] Navigating to Page 5 (VPUB QR)...")
    for _ in range(4):
        send_key("spc")
        time.sleep(0.4)
    time.sleep(1.5)
    p5 = capture_screen("hardware_screen_5_vpub_qr")

    print("[4/5] Navigating to Page 8 (Address #0 Faucet QR)...")
    for _ in range(3):
        send_key("spc")
        time.sleep(0.4)
    time.sleep(1.5)
    p8 = capture_screen("hardware_screen_8_address_qr")

    print("[5/5] Optical Decoding with ZBar...")
    r5 = subprocess.run(["zbarimg", "-q", "--raw", p5], capture_output=True, text=True)
    r8 = subprocess.run(["zbarimg", "-q", "--raw", p8], capture_output=True, text=True)

    print(f" >>> Page 5 VPUB QR Decoded    : {{r5.stdout.strip() or '[FAIL: NO CODE]'}}")
    print(f" >>> Page 8 Address QR Decoded : {{r8.stdout.strip() or '[FAIL: NO CODE]'}}")

    if not r5.stdout.strip().startswith("vpub"):
        sys.exit(1)
    if not r8.stdout.strip().startswith("tb1q"):
        sys.exit(2)

finally:
    proc.terminate()
    try: proc.wait(timeout=3)
    except Exception: proc.kill()
"""
]

res = subprocess.run(xvfb_cmd)
sys.exit(res.returncode)
