#!/usr/bin/env python3
import os, sys, time, socket, subprocess, shutil, glob

DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(DIR)
IMG_PATH = os.path.join(BASE_DIR, "dist", "subzero-vault-pc.img")
if not os.path.exists(IMG_PATH):
    IMG_PATH = os.path.join(BASE_DIR, "dist", "subzero-alpine.img")

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

print(f"[*] Launching QEMU instance with {IMG_PATH}...")
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
    print("[*] [1/7] Recording Main Menu HUD...")
    capture_frame(repeat=20)

    # 1. Option 1: Heir Treasury Generation
    print("[*] [2/7] Entering Option [1]: Heir Treasury Generation...")
    send_key("1")
    time.sleep(0.5)
    capture_frame(repeat=15)

    test_str = "test5"
    print(f"[*] Typing '{test_str}' vector (Zoo 0xFF Boundary)...")
    for char in test_str:
        send_key(char)
        capture_frame(repeat=4)
    capture_frame(repeat=10)

    print("[*] Deriving keys (ENTER)...")
    send_key("ret")
    time.sleep(1.0)

    # View Carousel Pages
    print("[*] Carousel Page 1 (Master Seed & Decoupled Passphrase)...")
    capture_frame(repeat=25)

    send_key("spc")
    time.sleep(0.5)
    print("[*] Carousel Page 2 (Nostr Identity & BIP-85 Hex)...")
    capture_frame(repeat=20)

    send_key("spc")
    time.sleep(0.5)
    print("[*] Carousel Page 3 (Watch-Only BIP-84 & Fingerprint)...")
    capture_frame(repeat=20)

    send_key("spc")
    time.sleep(0.5)
    print("[*] Carousel Page 4 (BIP-380 Descriptor QR Code)...")
    capture_frame(repeat=30)

    send_key("spc")
    time.sleep(0.5)
    print("[*] Carousel Page 5 (Native SegWit Receive Addresses)...")
    capture_frame(repeat=20)

    # Return to Menu
    send_key("esc")
    time.sleep(0.6)
    capture_frame(repeat=12)

    # 2. Option 3: BIP-85 Key Factory
    print("[*] [3/7] Entering Option [3]: BIP-85 Key Factory...")
    send_key("3")
    time.sleep(0.6)
    capture_frame(repeat=25)

    send_key("esc")
    time.sleep(0.5)

    # 3. Option 4: SeedFix BIP-39 Solver
    print("[*] [4/7] Entering Option [4]: SeedFix Checksum & Candidate Solver...")
    send_key("4")
    time.sleep(0.6)
    capture_frame(repeat=20)

    # Type 11 words demo
    seedfix_str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo"
    print(f"[*] Typing 11 words for SeedFix solver...")
    for char in "zoo zoo zoo ":
        send_key("spc" if char == " " else char)
        capture_frame(repeat=2)
    capture_frame(repeat=20)

    send_key("esc")
    time.sleep(0.5)

    # 4. Option 5: Storage Device Hasher
    print("[*] [5/7] Entering Option [5]: Storage Device Hasher...")
    send_key("5")
    time.sleep(0.6)
    capture_frame(repeat=20)

    print("[*] Triggering 64MB live block read hash (H)...")
    send_key("h")
    time.sleep(1.2)
    capture_frame(repeat=30)

    send_key("esc")
    time.sleep(0.5)

    # 5. Return to Main Menu
    print("[*] [6/7] Main Menu HUD final state...")
    capture_frame(repeat=25)

finally:
    sock.close()
    proc.terminate()
    proc.wait()

print("[*] [7/7] Compiling optimized demo GIF with ffmpeg & bayer dither...")
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
