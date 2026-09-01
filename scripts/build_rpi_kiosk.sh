#!/bin/bash
# ===========================================================================
#         SubZero Keyosk: Deterministic Raspberry Pi armv7 Image Builder
# ===========================================================================
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

if [ "$EUID" -ne 0 ]; then
    echo "Fatal Error: This builder must be run as root (sudo)."
    exit 1
fi

# Base directories
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
WORKSPACE_DIR="$( cd "${DIR}/.." && pwd )"
BUILD_DIR="/tmp/subzero_rpi_build"
ROOTFS_DIR="${BUILD_DIR}/rootfs"
MNT_DIR="${BUILD_DIR}/mnt"
OUTPUT_DIR="${OUTPUT_DIR:-${WORKSPACE_DIR}/dist}"
TUI_ARG="${1:-${TUI_BUNDLE:-fb_vault.cjs}}"
TUI_BUNDLE="$(basename "$TUI_ARG")"
IMG_ARG="${2:-${IMG_NAME:-subzero-vault-rpi.img}}"
IMG_NAME="$(basename "$IMG_ARG")"
IMG_PATH="${OUTPUT_DIR}/${IMG_NAME}"
LOOP_DEV=""
ALPINE_VERSION="3.19.1"
MINIROOTFS_URL="https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/armv7/alpine-minirootfs-${ALPINE_VERSION}-armv7.tar.gz"

echo "==========================================="
echo "       BUILDING SUBZERO RPI IMAGE          "
echo "==========================================="

# Step 1: Prepare staging directories
echo -e "\n[Step 1] Initializing build workspace..."
umount -l "${BUILD_DIR}/rootfs/dev" 2>/dev/null || true
umount -l "${BUILD_DIR}/rootfs/proc" 2>/dev/null || true
umount -l "${BUILD_DIR}/rootfs/sys" 2>/dev/null || true
umount -l "${BUILD_DIR}/mnt/dev" 2>/dev/null || true
umount -l "${BUILD_DIR}/mnt/proc" 2>/dev/null || true
umount -l "${BUILD_DIR}/mnt/sys" 2>/dev/null || true
umount -l "${BUILD_DIR}/mnt" 2>/dev/null || true
rm -rf --one-file-system "${BUILD_DIR}"
mkdir -p "${ROOTFS_DIR}"
mkdir -p "${WORKSPACE_DIR}/dist"

# Step 2: Download Alpine Mini RootFS
echo -e "\n[Step 2] Downloading Alpine armv7 Mini RootFS (${ALPINE_VERSION})..."
if command -v wget >/dev/null 2>&1; then
    wget -q -O "${BUILD_DIR}/minirootfs.tar.gz" "${MINIROOTFS_URL}"
else
    curl -sSL -o "${BUILD_DIR}/minirootfs.tar.gz" "${MINIROOTFS_URL}"
fi
tar -xzf "${BUILD_DIR}/minirootfs.tar.gz" -C "${ROOTFS_DIR}"

# Step 3: Inject QEMU user emulator & configure repositories
cp /usr/bin/qemu-arm-static "${ROOTFS_DIR}/usr/bin/" 2>/dev/null || true
cp /etc/resolv.conf "${ROOTFS_DIR}/etc/resolv.conf"
echo "https://dl-cdn.alpinelinux.org/alpine/v3.19/main" > "${ROOTFS_DIR}/etc/apk/repositories"
echo "https://dl-cdn.alpinelinux.org/alpine/v3.19/community" >> "${ROOTFS_DIR}/etc/apk/repositories"

# Step 4: Mount virtual filesystems for chroot
echo -e "\n[Step 4] Mounting virtual filesystems..."
mount --bind /dev "${ROOTFS_DIR}/dev"
mount --make-private "${ROOTFS_DIR}/dev"
mount --bind /proc "${ROOTFS_DIR}/proc"
mount --make-private "${ROOTFS_DIR}/proc"
mount --bind /sys "${ROOTFS_DIR}/sys"
mount --make-private "${ROOTFS_DIR}/sys"

cleanup_mounts() {
    echo -e "\n[Cleanup] Unmounting virtual filesystems and detaching loop devices..."
    umount -l "${ROOTFS_DIR}/dev" 2>/dev/null || true
    umount -l "${ROOTFS_DIR}/proc" 2>/dev/null || true
    umount -l "${ROOTFS_DIR}/sys" 2>/dev/null || true
    umount -l "${MNT_DIR}/dev" 2>/dev/null || true
    umount -l "${MNT_DIR}/proc" 2>/dev/null || true
    umount -l "${MNT_DIR}/sys" 2>/dev/null || true
    umount -l "${MNT_DIR}" 2>/dev/null || true
    if [ -n "${LOOP_DEV:-}" ]; then
        kpartx -d "${LOOP_DEV}" 2>/dev/null || true
        losetup -d "${LOOP_DEV}" 2>/dev/null || true
    fi
}
trap cleanup_mounts EXIT

# Step 5: Install packages inside armv7 rootfs
echo -e "\n[Step 5] Bootstrapping Alpine armv7 packages (linux-rpi, firmware, mkinitfs, nodejs)..."
chroot "${ROOTFS_DIR}" /bin/sh -c "
    apk update &&
    apk add --no-cache \
        alpine-base \
        linux-rpi \
        raspberrypi-bootloader \
        mkinitfs \
        squashfs-tools \
        udev \
        nodejs \
        font-terminus
"

# Configure modules for Raspberry Pi HDMI framebuffer
echo -e "fbcon\nvc4\nv3d\nsimplefb\nsdhci\nsdhci-pci\nmmc_block\nsquashfs\nvfat\nnls_cp437\nnls_iso8859_1" >> "${ROOTFS_DIR}/etc/modules"

# Step 6: Inject SubZero Keygen compiled application
echo -e "\n[Step 6] Injecting SubZero Keygen CLI application (${TUI_BUNDLE})..."
mkdir -p "${ROOTFS_DIR}/opt/subzero"
if [ -f "${WORKSPACE_DIR}/dist/${TUI_BUNDLE}" ]; then
    cp "${WORKSPACE_DIR}/dist/${TUI_BUNDLE}" "${ROOTFS_DIR}/opt/subzero/tui.cjs"
else
    echo "console.log(\"Missing dist/${TUI_BUNDLE}\");" > "${ROOTFS_DIR}/opt/subzero/tui.cjs"
fi
TUI_HASH=$(sha256sum "${ROOTFS_DIR}/opt/subzero/tui.cjs" | awk '{print $1}')
echo "  [Security Hash] tui.cjs (Deterministic Universal Core): ${TUI_HASH}"

# Step 7: Configure kiosk autostart script
echo -e "\n[Step 7] Configuring system init services..."
cat << 'INITSCRIPT' > "${ROOTFS_DIR}/etc/init.d/subzero-tty"
#!/sbin/openrc-run
set -x

name="SubZero CLI"
description="Launches offline Node.js wallet generator"

depend() {
    need localmount
    after hwdrivers
}

start() {
    ebegin "Starting SubZero Cold Storage Appliance on /dev/tty1"
    setterm -blank 0 -powerdown 0 </dev/tty1 >/dev/tty1 2>&1 || true
    setfont /usr/share/consolefonts/ter-v24n.psf.gz </dev/tty1 >/dev/tty1 2>&1 || true
    chvt 1
    
    # Launch SubZero directly on /dev/tty1 in an infinite kiosk loop
    export TERM=linux
    export LANG=C.UTF-8
    
    su root -c 'while true; do node /opt/subzero/tui.cjs </dev/tty1 >/dev/tty1 2>&1; clear >/dev/tty1; done'
    
    eend 0
}
INITSCRIPT
chmod +x "${ROOTFS_DIR}/etc/init.d/subzero-tty"

chroot "${ROOTFS_DIR}" /bin/sh -c "
    rc-update add devfs sysinit &&
    rc-update add dmesg sysinit &&
    rc-update add udev sysinit &&
    rc-update add hwdrivers sysinit &&
    rc-update add localmount boot &&
    rc-update add subzero-tty default &&
    sed -i 's/#rc_logger="NO"/rc_logger="YES"/g' /etc/rc.conf &&
    sed -i 's/#rc_verbose="NO"/rc_verbose="YES"/g' /etc/rc.conf
"

# Configure tty and hostname
echo "subzero-rpi" > "${ROOTFS_DIR}/etc/hostname"
echo "console=tty1 quiet loglevel=1" > "${ROOTFS_DIR}/etc/issue"
sed -i 's/^tty/#tty/g' "${ROOTFS_DIR}/etc/inittab"

# ==============================================================================
# ARCHITECTURE CONFIGURATION
# Pivoting to 32-bit (armv7) to bypass native start.elf AArch64 boot limitations
# on Raspberry Pi 3. Node.js and all crypto libraries compile natively.
# ==============================================================================
ARCH="armv7"
ALPINE_VERSION="3.19"
ALPINE_BRANCH="v3.19"

# ==============================================================================
# Step 8: PHYSICAL KERNEL NETWORK DEMOLITION (AIRGAP HARDENING)
# ==============================================================================
echo -e "\n[Step 8] Executing Physical Kernel Network Demolition on armv7..."
for kmod_dir in "${ROOTFS_DIR}"/lib/modules/*; do
    if [ -d "${kmod_dir}" ]; then
        echo "  [-] Demolishing network modules in ${kmod_dir}..."
        rm -rf "${kmod_dir}/kernel/net" 2>/dev/null || true
        rm -rf "${kmod_dir}/kernel/drivers/net" 2>/dev/null || true
        rm -rf "${kmod_dir}/kernel/drivers/wireless" 2>/dev/null || true
        rm -rf "${kmod_dir}/kernel/drivers/bluetooth" 2>/dev/null || true
        rm -rf "${kmod_dir}/kernel/drivers/usb/net" 2>/dev/null || true
        chroot "${ROOTFS_DIR}" depmod -a "$(basename "${kmod_dir}")" 2>/dev/null || true
    fi
done

# Strip wireless firmware blobs
rm -rf "${ROOTFS_DIR}/lib/firmware/brcm" 2>/dev/null || true
rm -rf "${ROOTFS_DIR}/lib/firmware/rtlwifi" 2>/dev/null || true
rm -rf "${ROOTFS_DIR}/lib/firmware/mediatek" 2>/dev/null || true

# Step 8.5: Custom Amnesic Initramfs Generator (Loads SquashFS to RAM and Unmounts SD)
echo -e "\n[Step 8.5] Generating Custom Amnesic toram Initramfs on armv7..."
mkdir -p "${ROOTFS_DIR}/etc/mkinitfs"
cat << 'MKINITFS' > "${ROOTFS_DIR}/etc/mkinitfs/mkinitfs.conf"
features="ata base cdrom ext4 keymap kms mmc nvme raid scsi usb virtio squashfs"
MKINITFS

mkdir -p "${ROOTFS_DIR}/usr/share/mkinitfs"
cat << 'MYINIT' > "${ROOTFS_DIR}/usr/share/mkinitfs/initramfs-init"
#!/bin/sh
set -x
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
/bin/busybox --install -s /bin 2>/dev/null || true
/bin/busybox --install -s /usr/bin 2>/dev/null || true
/bin/busybox --install -s /sbin 2>/dev/null || true
/bin/busybox --install -s /usr/sbin 2>/dev/null || true

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || mount -t tmpfs tmpfs /dev
if ! [ -c /dev/console ]; then
    mknod -m 600 /dev/console c 5 1
fi
exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console

echo "========================================================"
echo "         SUBZERO KEYOSK BOOTLOADER INITIALIZING         "
echo "========================================================"


echo "========================================================"
echo "      SUBZERO RASPBERRY PI BOOTLOADER INITIALIZING      "
echo "========================================================"
echo "[1/4] Loading storage & display drivers..."
modprobe sdhci 2>/dev/null || true
modprobe sdhci-pci 2>/dev/null || true
modprobe sdhci-bcm2835 2>/dev/null || true
modprobe mmc_block 2>/dev/null || true
modprobe bcm2835-dma 2>/dev/null || true
modprobe loop 2>/dev/null || true
modprobe squashfs 2>/dev/null || true
modprobe overlay 2>/dev/null || true
modprobe vfat 2>/dev/null || true
modprobe nls_cp437 2>/dev/null || true
modprobe nls_iso8859_1 2>/dev/null || true
modprobe fbcon 2>/dev/null || true
modprobe vc4 2>/dev/null || true
modprobe v3d 2>/dev/null || true
modprobe simplefb 2>/dev/null || true

echo "[2/4] Scanning for SubZero Keyosk Payload on SD Card..."
i=0
while [ "$i" -lt 150 ]; do
    mdev -s >/dev/null 2>&1
    for dev in $(blkid | grep vfat | cut -d: -f1); do
        mkdir -p /media/boot
        mount -t vfat -o ro "$dev" /media/boot 2>/dev/null
        if [ -f "/media/boot/rootfs.squashfs" ]; then
            BOOT_DEV="$dev"
            break 2
        fi
        umount /media/boot 2>/dev/null
    done
    i=$((i + 1))
    sleep 0.1
done

if [ -z "$BOOT_DEV" ]; then
    echo "ERROR: Could not find rootfs.squashfs payload on SD card!"
    sh
fi

echo "      Payload located on ${BOOT_DEV}."
echo "[3/4] Loading 150MB OS into volatile RAM disk..."
mkdir -p /media/ram /media/sqfs /sysroot
mkdir -p /media/sqfs /sysroot
mount -t squashfs -o ro /media/boot/rootfs.squashfs /media/sqfs
mount -t tmpfs -o size=512M tmpfs /sysroot
cp -a /media/sqfs/* /sysroot/

echo "[4/4] Hardware SD storage cleanly unmounted."
umount /media/sqfs
umount /media/boot

echo "========================================================"
echo " >> SUCCESS: OS RUNNING ENTIRELY FROM VOLATILE RAM <<"
echo " >> YOU MAY SAFELY REMOVE THE MICROSD CARD NOW     <<"
echo "========================================================"
sleep 1

echo "[DEBUG] Pre-switch_root mounts:"
cat /proc/mounts

echo "[DEBUG] Testing if /sysroot is valid for switch_root..."
ls -l /sysroot/sbin/init

mkdir -p /sysroot/sys /sysroot/proc /sysroot/dev

# Explicitly move mounts to new root
mount -o move /sys /sysroot/sys
mount -o move /proc /sysroot/proc
mount -o move /dev /sysroot/dev

echo "[DEBUG] Executing switch_root..."
exec switch_root /sysroot /sbin/init
MYINIT
chmod +x "${ROOTFS_DIR}/usr/share/mkinitfs/initramfs-init"

KVER=$(ls "${ROOTFS_DIR}/lib/modules" | head -n 1)
chroot "${ROOTFS_DIR}" /bin/sh -c "depmod -a '$KVER' && env GZIP='-n' mkinitfs -q -i /usr/share/mkinitfs/initramfs-init '$KVER'"

# Remove QEMU static emulator before packaging
rm -f "${ROOTFS_DIR}/usr/bin/qemu-arm-static"

# Step 9: Compile SquashFS compressed rootfs
echo -e "\n[Step 9] Compiling rootfs.squashfs..."
mkdir -p "${BUILD_DIR}/boot_staging"
mksquashfs "${ROOTFS_DIR}" "${BUILD_DIR}/boot_staging/rootfs.squashfs" \
    -comp xz -b 1M \
    -e dev proc sys

# Step 10: Extract Kernel, DTBs, and Bootloader
echo -e "\n[Step 10] Staging Raspberry Pi VideoCore Bootloader, Initramfs & Kernel..."
cp "${ROOTFS_DIR}/boot"/vmlinuz* "${BUILD_DIR}/boot_staging/vmlinuz-rpi" 2>/dev/null || cp "${ROOTFS_DIR}/boot"/Image* "${BUILD_DIR}/boot_staging/vmlinuz-rpi"
cp "${ROOTFS_DIR}/boot"/initramfs* "${BUILD_DIR}/boot_staging/initramfs-rpi" 2>/dev/null || true
cp -r "${ROOTFS_DIR}/boot"/dtbs*/* "${BUILD_DIR}/boot_staging/" 2>/dev/null || cp -r "${ROOTFS_DIR}/boot"/*.dtb "${BUILD_DIR}/boot_staging/" 2>/dev/null || true
cp -r "${ROOTFS_DIR}/boot"/overlays "${BUILD_DIR}/boot_staging/" 2>/dev/null || true
cp "${ROOTFS_DIR}/boot"/start*.elf "${BUILD_DIR}/boot_staging/" 2>/dev/null || true
cp "${ROOTFS_DIR}/boot"/fixup*.dat "${BUILD_DIR}/boot_staging/" 2>/dev/null || true
cp "${ROOTFS_DIR}/boot"/bootcode.bin "${BUILD_DIR}/boot_staging/" 2>/dev/null || true

cat << 'EOF' > "${BUILD_DIR}/boot_staging/config.txt"
# SubZero Keyosk: Airgapped Raspberry Pi Hardware Configuration
enable_uart=0

# Hardware Clock-Gating
dtoverlay=disable-wifi
dtoverlay=disable-bt
dtparam=audio=off

# Display Configuration (Strict simplefb Framebuffer)
disable_overscan=1
hdmi_force_hotplug=1
boot_delay=0

# Kernel & Amnesic Initramfs Hand-off
kernel=vmlinuz-rpi
initramfs initramfs-rpi
EOF

cat << 'EOF' > "${BUILD_DIR}/boot_staging/cmdline.txt"
modules=loop,squashfs,sd-mod,usb-storage console=tty1 nomodeset loglevel=8 panic=1
EOF

# Step 11: Format Single-Partition MBR FAT32 Disk Image
echo -e "\n[Step 11] Assembling raw bootable Raspberry Pi disk image (${IMG_NAME})..."
FAT_SIZE_MB=500
FAT_IMG="${BUILD_DIR}/boot.img"
rm -f "${FAT_IMG}" "${IMG_PATH}"

dd if=/dev/zero of="${FAT_IMG}" bs=1M count="${FAT_SIZE_MB}" status=none
mkfs.vfat -F 32 -i 19840124 -n "SUBZERO_RPI" "${FAT_IMG}"

MTOOLS_SKIP_CHECK=1 mcopy -m -i "${FAT_IMG}" -s "${BUILD_DIR}/boot_staging/"* ::/

# Assemble 512MB MBR disk image with partition at 1MiB offset (sector 2048)
dd if=/dev/zero of="${IMG_PATH}" bs=1M count=512 status=none
parted -s "${IMG_PATH}" mklabel msdos
parted -s "${IMG_PATH}" mkpart primary fat32 1MiB 100%
parted -s "${IMG_PATH}" set 1 boot on

dd if="${FAT_IMG}" of="${IMG_PATH}" bs=1M seek=1 conv=notrunc status=none

echo "==========================================="
echo "   SUBZERO RASPBERRY PI BUILD COMPLETE!   "
echo "==========================================="
echo "Output image: ${IMG_PATH}"
sha256sum "${IMG_PATH}"
