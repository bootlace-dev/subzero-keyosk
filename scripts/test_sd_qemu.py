#!/usr/bin/env python3
import subprocess
import time
import os
import socket

SOCK_PATH = "/tmp/qemu_sd_monitor.sock"
PPM_PATH = "/dev/shm/qemu_sd_boot.ppm"
PNG_PATH = "/dev/shm/qemu_sd_boot.png"
VARS_PATH = "/tmp/OVMF_VARS_4M_sd.fd"

def send_qemu_cmd(cmd):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(SOCK_PATH)
        time.sleep(0.1)
        s.recv(1024) # Banner
        s.sendall((cmd + "\n").encode())
        time.sleep(0.2)
        resp = s.recv(4096).decode()
        s.close()
        return resp
    except Exception as e:
        return f"Error: {e}"

def main():
    print("[1] Preparing OVMF VARS...")
    subprocess.run(["cp", "/usr/share/OVMF/OVMF_VARS_4M.fd", VARS_PATH], check=True)

    if os.path.exists(SOCK_PATH):
        os.remove(SOCK_PATH)

    print("[2] Launching QEMU booting directly from physical SD card (/dev/sdb)...")
    qemu_cmd = [
        "qemu-system-x86_64",
        "-enable-kvm",
        "-m", "1024",
        "-drive", f"if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
        "-drive", f"if=pflash,format=raw,file={VARS_PATH}",
        "-drive", "file=/dev/sdb,format=raw,if=ide,cache=none",
        "-vga", "std",
        "-vnc", "127.0.0.1:99",
        "-monitor", f"unix:{SOCK_PATH},server,nowait"
    ]

    proc = subprocess.Popen(qemu_cmd)
    print(f"QEMU process spawned with PID {proc.pid}")

    try:
        print("[3] Waiting 15 seconds for UEFI boot, Alpine toram copy, and Keyosk init...")
        for i in range(15):
            time.sleep(1)
            print(f"  Booting... ({i+1}/15s)")

        print("[4] Taking initial boot screenshot...")
        send_qemu_cmd(f"screendump {PPM_PATH}")
        time.sleep(1)

        if os.path.exists(PPM_PATH):
            subprocess.run(["pnmtopng", PPM_PATH], stdout=open(PNG_PATH, "wb"))
            print(f"Screenshot saved to {PNG_PATH}")

        # Send test keystrokes to select menu option 1 (Enter)
        print("[5] Sending 'ret' key to open Entropy Generator...")
        send_qemu_cmd("sendkey ret")
        time.sleep(2)

        # Inject test lore vector 'test6'
        print("[6] Injecting Satoshi Lore test vector ('test6')...")
        for char in "test6":
            send_qemu_cmd(f"sendkey {char}")
            time.sleep(0.08)

        time.sleep(1)
        send_qemu_cmd("sendkey ret")
        time.sleep(2)

        # Take screenshot of generated keys
        PPM_KEYS = "/dev/shm/qemu_sd_keys.ppm"
        PNG_KEYS = "/dev/shm/qemu_sd_keys.png"
        send_qemu_cmd(f"screendump {PPM_KEYS}")
        time.sleep(1)
        if os.path.exists(PPM_KEYS):
            subprocess.run(["pnmtopng", PPM_KEYS], stdout=open(PNG_KEYS, "wb"))
            print(f"Keys screenshot saved to {PNG_KEYS}")

        # Trigger Write [W] to physical SD partition
        print("[7] Pressing [W] to write encrypted vault.json to physical SUBZERO_EST partition...")
        send_qemu_cmd("sendkey w")
        time.sleep(4)

        PPM_WRITE = "/dev/shm/qemu_sd_write.ppm"
        PNG_WRITE = "/dev/shm/qemu_sd_write.png"
        send_qemu_cmd(f"screendump {PPM_WRITE}")
        time.sleep(1)
        if os.path.exists(PPM_WRITE):
            subprocess.run(["pnmtopng", PPM_WRITE], stdout=open(PNG_WRITE, "wb"))
            print(f"Write screenshot saved to {PNG_WRITE}")

    finally:
        print("[8] Shutting down QEMU test harness...")
        send_qemu_cmd("quit")
        time.sleep(1)
        if proc.poll() is None:
            proc.terminate()
        print("Test complete.")

if __name__ == "__main__":
    main()
