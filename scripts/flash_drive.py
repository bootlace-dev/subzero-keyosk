#!/usr/bin/env python3
import os
import sys
import json
import hashlib
import subprocess
import time
import signal
signal.signal(signal.SIGINT, lambda sig, frame: (_ for _ in ()).throw(KeyboardInterrupt()))

def calculate_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def get_mounted_devices():
    """Parse /proc/mounts to find all currently mounted block devices."""
    mounted = set()
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    dev = parts[0]
                    # Only track actual physical block devices
                    if dev.startswith("/dev/"):
                        mounted.add(dev)
    except Exception as e:
        print(f"Warning: Could not parse /proc/mounts: {e}")
    return mounted

def is_system_device(dev_name, mounted_devs):
    """
    Check if a device name (e.g. sda) or its partitions are mounted.
    """
    for m in mounted_devs:
        # e.g. if /dev/sda1 is mounted, it contains "sda"
        if dev_name in m:
            return True
    return False

def get_usb_sysfs_info(dev_name):
    """
    Query the /sys directory to find the USB controller's actual manufacturer,
    product, and serial number descriptors for the target block device name (e.g. sda).
    """
    sys_path = f"/sys/block/{dev_name}/device"
    if not os.path.exists(sys_path):
        return {}
    try:
        abs_path = os.path.realpath(sys_path)
        curr = abs_path
        for _ in range(10):
            if os.path.exists(os.path.join(curr, "manufacturer")) or os.path.exists(os.path.join(curr, "product")):
                info = {}
                if os.path.exists(os.path.join(curr, "manufacturer")):
                    with open(os.path.join(curr, "manufacturer"), "r") as f:
                        info["manufacturer"] = f.read().strip()
                if os.path.exists(os.path.join(curr, "product")):
                    with open(os.path.join(curr, "product"), "r") as f:
                        info["product"] = f.read().strip()
                if os.path.exists(os.path.join(curr, "serial")):
                    with open(os.path.join(curr, "serial"), "r") as f:
                        info["serial"] = f.read().strip()
                return info
            curr = os.path.dirname(curr)
            if curr == "/sys" or curr == "/sys/devices" or curr == "/":
                break
    except Exception:
        pass
    return {}

def list_usb_devices():
    devices = []
    try:
        # Get mounted devices for active blacklisting
        mounted_devs = get_mounted_devices()

        # Run lsblk to get JSON output
        output = subprocess.check_output(
            ["lsblk", "-J", "-o", "NAME,SIZE,MODEL,VENDOR,SERIAL,TRAN,RM,MOUNTPOINT"],
            text=True
        )
        data = json.loads(output)
        
        blockdevices = data.get("blockdevices", [])
        for dev in blockdevices:
            name = dev.get("name", "")
            size = dev.get("size", "")
            model = dev.get("model") or ""
            vendor = dev.get("vendor") or ""
            serial = dev.get("serial") or ""
            tran = dev.get("tran") or ""
            rm = dev.get("rm") or False
            
            # Exclude loop/ram/virtual devices
            if name.startswith("loop") or name.startswith("ram") or name.startswith("dm-"):
                continue
                
            is_usb = "usb" in tran.lower() or rm
            
            # Verify if this device or any of its partition children are currently mounted
            has_mounts = False
            
            # Check top-level mountpoint
            if dev.get("mountpoint") or is_system_device(name, mounted_devs):
                has_mounts = True
                
            # Check children mountpoints (partitions)
            children = dev.get("children", [])
            for child in children:
                child_name = child.get("name", "")
                if child.get("mountpoint") or is_system_device(child_name, mounted_devs):
                    has_mounts = True
            
            # Shield active system drives
            if has_mounts:
                # Silently skip active system drives to protect host OS from overwrite
                continue
                
            if is_usb:
                # Retrieve USB controller level descriptor strings
                sysfs_info = get_usb_sysfs_info(name)
                brand = sysfs_info.get("manufacturer") or vendor or "Unknown"
                product = sysfs_info.get("product") or model or "USB Device"
                serial_num = sysfs_info.get("serial") or serial or "N/A"
                
                devices.append({
                    "name": f"/dev/{name}",
                    "size": size,
                    "brand": brand,
                    "product": product,
                    "serial": serial_num,
                    "is_usb": "usb" in tran.lower()
                })
        return devices
    except Exception as e:
        print(f"Error parsing block devices: {e}")
        return []

def main():
    if os.geteuid() != 0:
        print("Fatal Error: This script must be run with root privileges (sudo).")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Usage: sudo python3 flash_drive.py <path_to_image.img>")
        sys.exit(1)

    img_path = sys.argv[1]
    if not os.path.exists(img_path):
        print(f"Fatal Error: Target image file not found: {img_path}")
        sys.exit(1)

    mtime_str = time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(os.path.getmtime(img_path)))
    file_size_mb = os.path.getsize(img_path) / (1024 * 1024)

    print("==========================================")
    print("      SUBZERO SD/USB FLASH ENGINE        ")
    print("==========================================")
    print(f"Target Image: {img_path} ({file_size_mb:.1f} MB)")
    print(f"Build Date  : {mtime_str}")
    
    print("\n[Step 1] Calculating source image checksum...")
    img_hash = calculate_sha256(img_path)
    print(f"Source Image SHA-256: {img_hash}")

    print("\n[Step 2] Scanning for USB/SD storage devices...")
    devices = list_usb_devices()
    if not devices:
        print("\nNo safe, unmounted USB or removable SD card devices detected.")
        print("Note: Active boot drives and mounted partitions are excluded for safety.")
        sys.exit(1)

    print("\nDetected Target Drives:")
    for idx, dev in enumerate(devices):
        usb_tag = " (USB)" if dev["is_usb"] else ""
        print(f" [{idx}] {dev['name']} - Size: {dev['size']} | Brand: {dev['brand']} ({dev['product']}) | Serial: {dev['serial']}{usb_tag}")

    print("\n[Step 3] Selecting and confirming target device...")
    try:
        sel = input(f"Select target device index (0-{len(devices)-1}): ").strip()
        sel_idx = int(sel)
        if sel_idx < 0 or sel_idx >= len(devices):
            raise ValueError()
    except (ValueError, IndexError):
        print("Fatal Error: Invalid device selection.")
        sys.exit(1)

    target_dev = devices[sel_idx]
    
    print("\n" + "!" * 50)
    print("  WARNING: ALL DATA ON THE TARGET DEVICE WILL BE DESTROYED!")
    print(f"  Target: {target_dev['name']} | Brand: {target_dev['brand']} ({target_dev['product']}) | Serial: {target_dev['serial']}")
    print("!" * 50 + "\n")

    confirmation = input("Type 'FLASH' to proceed with block-level overwrite: ").strip()
    if confirmation != "FLASH":
        print("Flash cancelled.")
        sys.exit(0)

    print(f"\n[Step 4] Flashing {img_path} -> {target_dev['name']}...")
    chunk_size = 4 * 1024 * 1024 # 4MB block size
    total_bytes = os.path.getsize(img_path)
    written_bytes = 0

    # Double check mount status right before writing
    mounted_devs = get_mounted_devices()
    if is_system_device(target_dev["name"].replace("/dev/", ""), mounted_devs):
        print("Fatal Error: Target device partition was mounted after selection. Aborting.")
        sys.exit(1)

    # Ensure target device partitions are unmounted
    try:
        import glob
        parts = glob.glob(f"{target_dev['name']}*")
        if parts:
            subprocess.run(["umount"] + parts, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    except Exception:
        pass

    start_time = time.time()
    try:
        with open(img_path, 'rb') as src, open(target_dev['name'], 'wb') as dst:
            while chunk := src.read(chunk_size):
                dst.write(chunk)
                # Ensure data is physically written to the device to get realistic progress
                dst.flush()
                os.fsync(dst.fileno())
                written_bytes += len(chunk)
                pct = (written_bytes / total_bytes) * 100
                elapsed = time.time() - start_time
                # Prevent division by zero on very fast initial writes
                if elapsed < 0.001:
                    elapsed = 0.001
                speed = (written_bytes / (1024 * 1024)) / elapsed
                written_mb = written_bytes / (1024 * 1024)
                total_mb = total_bytes / (1024 * 1024)
                sys.stdout.write(f"\rProgress: {pct:.1f}% | Speed: {speed:.1f} MB/s | {written_mb:.1f}/{total_mb:.1f} MB")
                sys.stdout.flush()
            
            # Sync buffers
            os.fsync(dst.fileno())
    except KeyboardInterrupt:
        print("\n\n[Abort] Flashing interrupted by user. Performing cleanup...")
        subprocess.run(["sync"])
        sys.exit(1)
    except PermissionError:
        print("\nFatal Error: Permission denied. Make sure target device is not busy/locked.")
        sys.exit(1)
    except Exception as e:
        print(f"\nFatal Error during write path: {e}")
        sys.exit(1)

    print(f"\nWrite complete in {time.time() - start_time:.1f} seconds. Synchronizing buffers...")
    subprocess.run(["sync"])

    print("\n[Step 5] Verifying flashed data integrity...")
    verify_hash = hashlib.sha256()
    read_bytes = 0
    start_time = time.time()
    verify_chunk_size = 16 * 1024 * 1024 # 16MB blocks for faster reading
    
    try:
        with open(target_dev['name'], 'rb') as dst:
            while read_bytes < total_bytes:
                to_read = min(verify_chunk_size, total_bytes - read_bytes)
                chunk = dst.read(to_read)
                if not chunk:
                    break
                verify_hash.update(chunk)
                read_bytes += len(chunk)
                pct = (read_bytes / total_bytes) * 100
                elapsed = time.time() - start_time
                if elapsed < 0.001:
                    elapsed = 0.001
                speed = (read_bytes / (1024 * 1024)) / elapsed
                read_mb = read_bytes / (1024 * 1024)
                total_mb = total_bytes / (1024 * 1024)
                sys.stdout.write(f"\rVerifying: {pct:.1f}% | Speed: {speed:.1f} MB/s | {read_mb:.1f}/{total_mb:.1f} MB")
                sys.stdout.flush()
    except Exception as e:
        print(f"\nFatal Error during verification: {e}")
        sys.exit(1)

    flashed_hash = verify_hash.hexdigest()
    print(f"\nFlashed Device SHA-256: {flashed_hash}")

    if flashed_hash == img_hash:
        print("\n" + "=" * 50)
        print("  SUCCESS: FLASH INTEGRITY VERIFIED AND PASSES MATCH!")
        print("  It is now safe to unplug the drive.")
        print("=" * 50)
    else:
        print("\n" + "!" * 50)
        print("  CRITICAL ERROR: HASH MISMATCH DETECTED!")
        print("  Flashed checksum does not match source image.")
        print("  Drive may have bad blocks or corrupt sectors.")
        print("!" * 50)
        sys.exit(1)

if __name__ == '__main__':
    main()
