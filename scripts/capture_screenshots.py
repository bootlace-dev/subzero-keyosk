import os, sys, time, socket, subprocess, shutil

DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(DIR)
IMG_PATH = os.path.join(BASE_DIR, "dist", "subzero-alpine.img")
OUTPUT_DIR = os.path.join(BASE_DIR, "docs", "screenshots")
SOCK_PATH = "/tmp/qemu_screen_sock"
if os.path.exists(SOCK_PATH): os.remove(SOCK_PATH)

OVMF_CODE = "/usr/share/OVMF/OVMF_CODE_4M.fd"
TMP_VARS = "/tmp/qemu_screen_vars.fd"
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

proc = subprocess.Popen(qemu_cmd)
time.sleep(2)

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(SOCK_PATH)

print("[*] Waiting 22s for SubZero USB boot...")
time.sleep(22)

def send_qmp(cmd_str):
    s.send((cmd_str + "\n").encode())
    time.sleep(0.6)

# 1. Capture 00_input_prompt
print("[*] 00_input_prompt...")
send_qmp(f"screendump {OUTPUT_DIR}/00_input_prompt.ppm")

# 1b. Capture 50 Physical Dice Rolls
print("[*] Typing 50 Physical Dice Rolls...")
dice_str = "55262165113545636434143143466143416651161434314355"
for d in dice_str:
    s.send(f"sendkey {d}\n".encode())
    time.sleep(0.04)
time.sleep(0.8)
print("[*] 01b_entropy_physical_dice...")
send_qmp(f"screendump {OUTPUT_DIR}/01b_entropy_physical_dice.ppm")

# Clear dice input with backspaces
print("[*] Clearing input...")
for _ in range(len(dice_str)):
    s.send(b"sendkey backspace\n")
    time.sleep(0.02)
time.sleep(0.5)

# 1c. Capture 128 Physical Coin Flips
print("[*] Typing 128 Physical Coin Flips...")
coin_str = "01001101101001101110001101011100100101101100001101111010000111011100101001010011011010001111001010110100001111010110100111000110"
for bit in coin_str:
    s.send(f"sendkey {bit}\n".encode())
    time.sleep(0.03)
time.sleep(0.8)
print("[*] 01c_entropy_physical_coins...")
send_qmp(f"screendump {OUTPUT_DIR}/01c_entropy_physical_coins.ppm")

# Clear coin input with backspaces
print("[*] Clearing input...")
for _ in range(len(coin_str)):
    s.send(b"sendkey backspace\n")
    time.sleep(0.02)
time.sleep(0.5)

# 2. Trigger test vector via secret "test" keyword
print("[*] Typing 'test' to trigger sample entropy...")
for c in "test":
    s.send(f"sendkey {c}\n".encode())
    time.sleep(0.05)
time.sleep(0.8)

print("[*] 01a_entropy_test_vector...")
send_qmp(f"screendump {OUTPUT_DIR}/01a_entropy_test_vector.ppm")
send_qmp(f"screendump {OUTPUT_DIR}/01_entropy_ready.ppm")

# 3. Generate keys
print("[*] Generating keys...")
send_qmp("sendkey ret")
time.sleep(1.5)

pages = [
    ("02_page1_private_master_seed", "Page 1: Private Master Seed (Confidential)"),
    ("03_page2_private_bip85_0_4", "Page 2: Private BIP85 Child Seeds 0-4"),
    ("04_page3_private_bip85_5_9", "Page 3: Private BIP85 Child Seeds 5-9"),
    ("05_page4_public_descriptor_xpub", "Page 4: Public Watch-Only Descriptor & QR"),
    ("06_page5_public_addresses_0_4", "Page 5: Public Receive Addresses 0-4 & QR"),
    ("07_page6_public_addresses_5_9", "Page 6: Public Receive Addresses 5-9"),
    ("08_page7_colophon_rationale", "Page 7: Colophon & Defensive Rationale"),
    ("09_page8_verification_protocol", "Page 8: Anti-Footgun Verification Protocol")
]

for idx, (filename, label) in enumerate(pages):
    print(f"[*] Capturing {label} -> {filename}.ppm...")
    send_qmp(f"screendump {OUTPUT_DIR}/{filename}.ppm")
    if idx < len(pages) - 1:
        send_qmp("sendkey right")
        time.sleep(0.8)

proc.kill()

for f in os.listdir(OUTPUT_DIR):
    if f.endswith(".ppm"):
        ppm_path = os.path.join(OUTPUT_DIR, f)
        png_path = os.path.join(OUTPUT_DIR, f.replace(".ppm", ".png"))
        subprocess.run(["convert", ppm_path, png_path], check=True)
        os.remove(ppm_path)

print("[SUCCESS] All screenshots captured successfully!")
