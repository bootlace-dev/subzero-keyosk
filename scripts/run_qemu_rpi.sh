#!/bin/bash
# ===========================================================================
#  SubZero Keyosk: QEMU Raspberry Pi ARM64 Test Harness
# ===========================================================================
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
WORKSPACE_DIR="$( cd "${DIR}/.." && pwd )"
IMG_PATH="${WORKSPACE_DIR}/dist/subzero-rpi.img"
BOOT_DIR="/tmp/subzero_rpi_boot_qemu"

if [ ! -f "$IMG_PATH" ]; then
    echo "Fatal: Image $IMG_PATH not found."
    echo "Run 'sudo ./scripts/build_rpi_kiosk.sh' or './scripts/build_rpi_containerized.sh' first."
    exit 1
fi

mkdir -p "$BOOT_DIR"
echo "Extracting kernel & device tree from image..."
7z e "$IMG_PATH" vmlinuz-rpi initramfs-rpi bcm2709-rpi-2-b.dtb -o"$BOOT_DIR" -y >/dev/null

DTB_FILE="$BOOT_DIR/bcm2709-rpi-2-b.dtb"

echo "==========================================="
echo "   LAUNCHING SUBZERO KEYOSK (RPI 32-BIT)   "
echo "==========================================="
echo " Machine:  Raspberry Pi 2B (armv7 emulation)"
echo " Kernel:   $BOOT_DIR/vmlinuz-rpi"
echo " Initrd:   $BOOT_DIR/initramfs-rpi"
echo " DTB:      $DTB_FILE"
echo " Image:    $IMG_PATH"
echo " Memory:   1024MB RAM"
echo " Airgap:   -net none (No Network Stack)"
echo "==========================================="
echo " Press Ctrl+Alt+G to release mouse if captured."
echo " Close the QEMU window or press Ctrl+C in terminal to exit."
echo "==========================================="

qemu-system-arm \
    -M raspi2b \
    -m 1024M \
    -kernel "$BOOT_DIR/vmlinuz-rpi" \
    -initrd "$BOOT_DIR/initramfs-rpi" \
    -dtb "$DTB_FILE" \
    -append "console=tty1 console=ttyAMA0,115200 root=/dev/ram0 earlycon=pl011,0x3f201000" \
    -global bcm2835-fb.xres=1280 \
    -global bcm2835-fb.yres=720 \
    -drive file="$IMG_PATH",format=raw,if=sd \
    -snapshot \
    -net none \
    -device usb-kbd \
    -serial stdio \
    -display default
