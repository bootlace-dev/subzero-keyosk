#!/usr/bin/env python3
import os
import subprocess
import time
import socket

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG_PATH = os.path.join(BASE_DIR, "dist", "subzero-alpine.img")
OVMF_CODE = "/usr/share/OVMF/OVMF_CODE_4M.fd"
OUTPUT_DIR = "/tmp/qemu_breadth_tests"

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def create_vars(name):
    vars_path = f"/tmp/{name}_VARS.fd"
    subprocess.run(["cp", "/usr/share/OVMF/OVMF_VARS_4M.fd", vars_path], check=True)
    return vars_path

def send_qmp(cmd_str):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect('/tmp/qemu_mon')
        time.sleep(0.5)
        s.recv(1024)
        s.send((cmd_str + "\n").encode())
        time.sleep(1)
        s.close()
    except Exception as e:
        print(f"Socket error: {e}")

configs = [
    {
        "name": "virtio_native",
        "desc": "Modern Cloud / KVM (VirtIO Block)",
        "wait": 24,
        "args": ["-drive", f"file={IMG_PATH},format=raw,if=virtio,file.locking=off"]
    },
    {
        "name": "ahci_sata",
        "desc": "Standard PC SATA (AHCI)",
        "wait": 24,
        "args": ["-device", "ahci,id=ahci0", "-drive", f"file={IMG_PATH},format=raw,if=none,id=drive0,file.locking=off", "-device", "ide-hd,bus=ahci0.0,drive=drive0"]
    },
    {
        "name": "nvme",
        "desc": "Modern Laptop (NVMe)",
        "wait": 26,
        "args": ["-drive", f"file={IMG_PATH},format=raw,if=none,id=nvme0,file.locking=off", "-device", "nvme,drive=nvme0,serial=1234,bootindex=1"]
    },
    {
        "name": "usb3_xhci",
        "desc": "Standard Laptop USB 3.0 (xHCI)",
        "wait": 28,
        "args": ["-device", "qemu-xhci,id=xhci0", "-drive", f"file={IMG_PATH},format=raw,if=none,id=usbstick,file.locking=off", "-device", "usb-storage,bus=xhci0.0,drive=usbstick,bootindex=1"]
    },
    {
        "name": "usb2_ehci",
        "desc": "Legacy Laptop USB 2.0 (EHCI)",
        "wait": 36,
        "args": ["-device", "usb-ehci,id=ehci", "-drive", f"file={IMG_PATH},format=raw,if=none,id=usbstick2,file.locking=off", "-device", "usb-storage,bus=ehci.0,drive=usbstick2,bootindex=1"]
    }
]

for cfg in configs:
    name = cfg['name']
    print(f"Testing {name} ({cfg['desc']}) for {cfg['wait']}s...")
    vars_path = create_vars(name)
    mon_sock = f"/tmp/qemu_mon_{name}"
    if os.path.exists(mon_sock):
        os.remove(mon_sock)
    
    cmd = [
        "qemu-system-x86_64",
        "-machine", "q35",
        "-m", "1536",
        "-cpu", "host",
        "-enable-kvm",
        "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_CODE}",
        "-drive", f"if=pflash,format=raw,file={vars_path}",
        "-vga", "std",
        "-vnc", "127.0.0.1:91",
        "-monitor", f"unix:{mon_sock},server,nowait",
        "-snapshot"
    ] + cfg["args"]
    
    proc = subprocess.Popen(cmd)
    time.sleep(cfg['wait'])
    
    dump_path = f"{OUTPUT_DIR}/{name}.ppm"
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(mon_sock)
        s.send(f"screendump {dump_path}\n".encode())
        time.sleep(1)
        s.send(b"quit\n")
        time.sleep(0.5)
        s.close()
    except Exception as e:
        print(f"Socket error on {name}: {e}")
        
    proc.wait()
    
    jpg_path = f"{OUTPUT_DIR}/{name}.jpg"
    subprocess.run(["ffmpeg", "-y", "-i", dump_path, jpg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sz = os.path.getsize(jpg_path) if os.path.exists(jpg_path) else 0
    print(f"==> Captured {name}: {sz} bytes")

print("All tests completed.")
