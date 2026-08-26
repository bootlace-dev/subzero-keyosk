#!/bin/bash
# ===========================================================================
#  SubZero Keyosk: QEMU UEFI Test Harness
# ===========================================================================
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
WORKSPACE_DIR="$( cd "${DIR}/.." && pwd )"

if [ -n "$1" ]; then
    IMG_PATH="$(realpath "$1")"
else
    IMG_PATH="${WORKSPACE_DIR}/dist/subzero-alpine.img"
fi

if [ ! -f "$IMG_PATH" ]; then
    echo "Fatal: Image $IMG_PATH not found."
    exit 1
fi

# Locate OVMF CODE and VARS
OVMF_CODE=""
OVMF_VARS=""

if [ -f "/usr/share/OVMF/OVMF_CODE_4M.fd" ] && [ -f "/usr/share/OVMF/OVMF_VARS_4M.fd" ]; then
    OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
    OVMF_VARS="/usr/share/OVMF/OVMF_VARS_4M.fd"
elif [ -f "/usr/share/OVMF/OVMF_CODE.fd" ] && [ -f "/usr/share/OVMF/OVMF_VARS.fd" ]; then
    OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"
    OVMF_VARS="/usr/share/OVMF/OVMF_VARS.fd"
fi

# Prepare temporary writable VARS storage
TMP_VARS="/tmp/subzero_ovmf_vars.fd"
if [ -n "$OVMF_VARS" ]; then
    cp -f "$OVMF_VARS" "$TMP_VARS"
fi

# Determine KVM support
KVM_FLAG=""
if [ -w /dev/kvm ]; then
    KVM_FLAG="-enable-kvm -cpu host"
else
    KVM_FLAG="-cpu max"
fi

IMG_HASH=$(sha256sum "$IMG_PATH" | awk '{print $1}')
IMG_SIZE=$(ls -lh "$IMG_PATH" | awk '{print $5}')
IMG_DATE=$(stat -c '%y' "$IMG_PATH" 2>/dev/null || date -r "$IMG_PATH")

echo "==========================================="
echo "   LAUNCHING SUBZERO KEYOSK IN QEMU (UEFI) "
echo "==========================================="
echo " Target:   $(basename "$IMG_PATH")"
echo " SHA-256:  $IMG_HASH"
echo " Size:     $IMG_SIZE"
echo " Built:    $IMG_DATE"
echo " UEFI:     $OVMF_CODE"
echo " Memory:   512MB RAM"
echo " Airgap:   -net none (No Network Stack)"
echo "==========================================="
echo " Press Ctrl+Alt+G to release mouse if captured."
echo " Close the QEMU window or press Ctrl+C in terminal to exit."
echo "==========================================="

if [ -n "$OVMF_CODE" ]; then
    qemu-system-x86_64 \
        $KVM_FLAG \
        -m 512M \
        -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
        -drive if=pflash,format=raw,file="$TMP_VARS" \
        -drive file="$IMG_PATH",format=raw,if=ide,file.locking=off \
        -snapshot \
        -net none \
        -vga std \
        -serial stdio 2>&1 | tee /tmp/subzero_qemu_live.log
else
    qemu-system-x86_64 \
        $KVM_FLAG \
        -m 512M \
        -bios /usr/share/ovmf/OVMF.fd \
        -drive file="$IMG_PATH",format=raw,if=ide,file.locking=off \
        -snapshot \
        -net none \
        -vga std \
        -serial stdio 2>&1 | tee /tmp/subzero_qemu_live.log
fi
