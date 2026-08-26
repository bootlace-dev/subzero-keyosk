#!/usr/bin/env python3
import os, sys, time, socket, subprocess, shutil, glob

DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(DIR)
IMG_PATH = os.path.join(BASE_DIR, "dist", "subzero-testnet4-pc.img")
OUTPUT_GIF = os.path.join(BASE_DIR, "docs", "screenshots", "subzero_demo.gif")
FRAME_DIR = "/tmp/subzero_gif_frames"

if not os.path.exists(IMG_PATH):
    print(f"Error: {IMG_PATH} not found.")
    sys.exit(1)

if os.path.exists(FRAME_DIR):
    shutil.rmtree(FRAME_DIR)
os.makedirs(FRAME_DIR, exist_ok=True)
os.makedirs(os.path.dirname(OUTPUT_GIF), exist_ok=True)

SOCK_PATH = "/tmp/qemu_demo_sock"
if os.path.exists(SOCK_PATH):
    try: os.remove(SOCK_PATH)
    except Exception: pass

OVMF_CODE = "/usr/share/OVMF/OVMF_CODE_4M.fd"
TMP_VARS = "/tmp/qemu_demo_vars.fd"
shutil.copy("/usr/share/OVMF/OVMF_VARS_4M.fd", TMP_VARS)

qemu_cmd = [
    "qemu-system-x86_64",
    "-enable-kvm", "-cpu", "host",
    "-m", "1024M",
    "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_CODE}",
    "-drive", f"if=pflash,format=raw,file={TMP_VARS}",
    "-device", "qemu-xhci,id=xhci0",
    "-drive", f"file={IMG_PATH},format=raw,if=none,id=usbstick,file.locking=off",
    "-device", "usb-storage,bus=xhci0.0,drive=usbstick,bootindex=1",
    "-net", "none",
    "-vga", "std",
    "-vnc", "127.0.0.1:99",
    "-monitor", f"unix:{SOCK_PATH},server,nowait"
]

print("[*] Launching QEMU instance with SubZero Testnet4 image...")
proc = subprocess.Popen(qemu_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1)

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
connected = False
for attempt in range(50):
    try:
        sock.connect(SOCK_PATH)
        connected = True
        break
    except Exception:
        time.sleep(0.2)

if not connected:
    print("[-] Failed to connect to QEMU monitor socket.")
    proc.terminate()
    sys.exit(1)

print("[*] Waiting 22s for SubZero USB boot to framebuffer UI on /dev/tty1...")
time.sleep(22)

frame_idx = 0

def capture_frame(repeat=1):
    global frame_idx
    ppm_path = os.path.join(FRAME_DIR, f"frame_{frame_idx:04d}.ppm")
    sock.sendall(f"screendump {ppm_path}\n".encode())
    time.sleep(0.12)
    png_path = os.path.join(FRAME_DIR, f"frame_{frame_idx:04d}.png")
    if os.path.exists(ppm_path):
        subprocess.run(["convert", ppm_path, "-resize", "800x600", png_path], check=True)
        os.remove(ppm_path)
    for r in range(1, repeat):
        frame_idx += 1
        shutil.copy(png_path, os.path.join(FRAME_DIR, f"frame_{frame_idx:04d}.png"))
    frame_idx += 1

def send_key(k):
    sock.sendall(f"sendkey {k}\n".encode())
    time.sleep(0.08)

try:
    print("[*] Recording Initial Entropy Prompt Screen...")
    capture_frame(repeat=15)

    # Type test5 deterministic test vector
    test_str = "test5"
    print(f"[*] Typing '{test_str}' test vector (BIP39 maximum entropy: zoo zoo ... wrong)...")
    for char in test_str:
        send_key(char)
        capture_frame(repeat=4)

    print("[*] Pausing on completed test vector input...")
    capture_frame(repeat=15)

    print("[*] Pressing ENTER to derive keys...")
    send_key("ret")
    time.sleep(1.0)

    # Page 1: Private Master Seed (12 words)
    print("[*] Recording Page 1/9: Private Master Seed (12 words)...")
    capture_frame(repeat=25)

    # Page 2: BIP-85 Child Seeds (0-4)
    print("[*] Navigating to Page 2/9: BIP-85 Child Seeds (0-4)...")
    send_key("spc")
    time.sleep(0.5)
    capture_frame(repeat=20)

    # Page 3: BIP-85 Child Seeds (5-9)
    print("[*] Navigating to Page 3/9: BIP-85 Child Seeds (5-9)...")
    send_key("spc")
    time.sleep(0.5)
    capture_frame(repeat=20)

    # Page 4: Account Summary & Fingerprint
    print("[*] Navigating to Page 4/9: Watch-Only Account Summary...")
    send_key("spc")
    time.sleep(0.5)
    capture_frame(repeat=20)

    # Page 5: SLIP-132 vpub QR Code (Green & BlueWallet)
    print("[*] Navigating to Page 5/9: Account vpub QR Code (Green / BlueWallet)...")
    send_key("spc")
    time.sleep(0.8)
    capture_frame(repeat=30)

    # Page 6: BIP-380 Output Descriptor QR Code (Sparrow & Nunchuk)
    print("[*] Navigating to Page 6/9: BIP-380 Output Descriptor QR Code (Sparrow / Nunchuk)...")
    send_key("spc")
    time.sleep(0.8)
    capture_frame(repeat=35)

    # Page 7: Receive Addresses 0-14
    print("[*] Navigating to Page 7/9: First Receive Addresses...")
    send_key("spc")
    time.sleep(0.5)
    capture_frame(repeat=20)

    # Page 8: Address #0 QR Code (Faucet / Sweep Target)
    print("[*] Navigating to Page 8/9: Address #0 Receive & Faucet QR Code...")
    send_key("spc")
    time.sleep(0.8)
    capture_frame(repeat=30)

    # Page 9: Invariants & Amnesic Exit
    print("[*] Navigating to Page 9/9: Colophon, Provenance & Verification Protocol...")
    send_key("spc")
    time.sleep(0.5)
    capture_frame(repeat=25)

    # Zeroize Memory via ESC / R
    print("[*] Triggering instant memory zeroization (ESC key) back to entropy prompt...")
    send_key("esc")
    time.sleep(0.8)
    capture_frame(repeat=20)

finally:
    sock.close()
    proc.terminate()
    proc.wait()

print("[*] Compiling optimized GIF with ffmpeg & bayer dither...")
palette_path = "/tmp/palette.png"
subprocess.run([
    "ffmpeg", "-y", "-framerate", "10",
    "-i", f"{FRAME_DIR}/frame_%04d.png",
    "-vf", "fps=10,scale=800:-1:flags=lanczos,palettegen=stats_mode=diff",
    palette_path
], check=True)

subprocess.run([
    "ffmpeg", "-y", "-framerate", "10",
    "-i", f"{FRAME_DIR}/frame_%04d.png",
    "-i", palette_path,
    "-lavfi", "fps=10,scale=800:-1:flags=lanczos [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=3",
    OUTPUT_GIF
], check=True)

print(f"[+] Demo GIF successfully compiled: {OUTPUT_GIF}")
file_size_mb = os.path.getsize(OUTPUT_GIF) / (1024 * 1024)
print(f"[+] File Size: {file_size_mb:.2f} MB")

