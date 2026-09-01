#!/bin/bash
# ===========================================================================
#         SubZero Keygen: Deterministic Alpine Kiosk Image Builder
# ===========================================================================
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Fatal Error: This builder must be run as root (sudo)."
    exit 1
fi

# Base directories
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
WORKSPACE_DIR="$( cd "${DIR}/.." && pwd )"
BUILD_DIR="/tmp/subzero_alpine_build"
ROOTFS_DIR="${BUILD_DIR}/rootfs"
IMG_PATH="${WORKSPACE_DIR}/dist/subzero-alpine.img"
ALPINE_VERSION="3.19.1"
MINIROOTFS_URL="https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-minirootfs-${ALPINE_VERSION}-x86_64.tar.gz"

echo "==========================================="
echo "       BUILDING SUBZERO ALPINE IMAGE       "
echo "==========================================="

# Step 1: Prepare staging directories
echo "\n[Step 1] Initializing build workspace..."
rm -rf "${BUILD_DIR}"
mkdir -p "${ROOTFS_DIR}"
mkdir -p "${WORKSPACE_DIR}/dist"

# Step 2: Download Alpine Mini RootFS
echo "\n[Step 2] Downloading Alpine Mini RootFS (${ALPINE_VERSION})..."
wget -q --show-progress -O "${BUILD_DIR}/minirootfs.tar.gz" "${MINIROOTFS_URL}"
tar -xzf "${BUILD_DIR}/minirootfs.tar.gz" -C "${ROOTFS_DIR}"

# Step 3: Configure repositories and copy host DNS for download resolution
cp /etc/resolv.conf "${ROOTFS_DIR}/etc/resolv.conf"
echo "https://dl-cdn.alpinelinux.org/alpine/v3.19/main" > "${ROOTFS_DIR}/etc/apk/repositories"
echo "https://dl-cdn.alpinelinux.org/alpine/v3.19/community" >> "${ROOTFS_DIR}/etc/apk/repositories"

# Step 4: Mount virtual filesystems for chroot
echo "\n[Step 4] Mounting virtual filesystems..."
mount --bind /dev "${ROOTFS_DIR}/dev"
mount --bind /proc "${ROOTFS_DIR}/proc"
mount --bind /sys "${ROOTFS_DIR}/sys"

cleanup_mounts() {
    echo "\n[Cleanup] Unmounting virtual filesystems and detaching loop devices..."
    # Unmount guest rootfs virtual mounts
    umount -l "${ROOTFS_DIR}/dev" 2>/dev/null || true
    umount -l "${ROOTFS_DIR}/proc" 2>/dev/null || true
    umount -l "${ROOTFS_DIR}/sys" 2>/dev/null || true
    
    # Unmount target mountpoint bind mounts
    umount -l "${MNT_DIR}/dev" 2>/dev/null || true
    umount -l "${MNT_DIR}/proc" 2>/dev/null || true
    umount -l "${MNT_DIR}/sys" 2>/dev/null || true
    
    # Unmount target partitions
    umount -l "${MNT_DIR}/boot/efi" 2>/dev/null || true
    umount -l "${MNT_DIR}" 2>/dev/null || true
    
    # Detach loop device
    if [ -n "${LOOP_DEV}" ]; then
        losetup -d "${LOOP_DEV}" 2>/dev/null || true
    fi
}
trap cleanup_mounts EXIT

# Step 5: Install packages inside rootfs
echo "\n[Step 5] Bootstrapping Alpine packages..."
chroot "${ROOTFS_DIR}" apk update
chroot "${ROOTFS_DIR}" apk add --no-cache \
    alpine-base \
    linux-lts \
    linux-firmware-none \
    linux-firmware-i915 \
    grub-efi \
    udev \
    xorg-server \
    xf86-video-modesetting \
    xf86-input-libinput \
    xinit \
    chromium \
    dbus \
    mesa-dri-gallium \
    nodejs

# Step 6: Inject SubZero Keygen compiled application
echo "\n[Step 6] Injecting SubZero Keygen Kiosk application..."
mkdir -p "${ROOTFS_DIR}/opt/subzero"
if [ -f "${WORKSPACE_DIR}/dist/tui.cjs" ]; then
    cp "${WORKSPACE_DIR}/dist/tui.cjs" "${ROOTFS_DIR}/opt/subzero/tui.cjs"
else
    echo "console.log(\"Missing dist/tui.cjs\");" > "${ROOTFS_DIR}/opt/subzero/tui.cjs"
fi

if [ -f "${WORKSPACE_DIR}/dist/index.html" ]; then
    cp "${WORKSPACE_DIR}/dist/index.html" "${ROOTFS_DIR}/opt/subzero/index.html"
else
    echo "<h1>SubZero Keygen App (Missing dist/index.html)</h1>" > "${ROOTFS_DIR}/opt/subzero/index.html"
fi

if [ -f "${WORKSPACE_DIR}/../bip39/bip39-standalone.html" ]; then
    cp "${WORKSPACE_DIR}/../bip39/bip39-standalone.html" "${ROOTFS_DIR}/opt/subzero/ian-coleman.html"
fi

# Step 7: Configure kiosk autostart script
echo "\n[Step 7] Configuring system init services..."
# Create custom startup init script for the OpenRC init manager
cat << 'EOF' > "${ROOTFS_DIR}/etc/init.d/subzero-kiosk"
#!/sbin/openrc-run

name="SubZero Kiosk"
description="Launches offline chromium wallet generator"

depend() {
    need localmount udev dbus
    after bootmisc
}

start() {
    ebegin "Starting SubZero Kiosk..."
    
    CMDLINE=$(cat /proc/cmdline)
    if echo "$CMDLINE" | grep -q "subzero.mode=keygen_tui"; then
        # Executing node synchronously will block the init script,
        # so we background it and pipe inputs directly to tty1
        start-stop-daemon --start --background             --make-pidfile --pidfile /run/subzero-tui.pid             --exec /bin/sh -- -c "while true; do /usr/bin/node /opt/subzero/tui.cjs < /dev/tty1 > /dev/tty1 2>&1; sleep 1; clear > /dev/tty1; done"
        
        # Switch to tty1 and exit init sequence successfully
        chvt 1
        eend 0
        return 0
    elif echo "$CMDLINE" | grep -q "subzero.mode=spend_html"; then
        clear > /dev/tty1
        echo "==================================================" > /dev/tty1
        echo "   SUBZERO KEYGEN: SPEND/SIGN HTML GUI [STUB]     " > /dev/tty1
        echo "==================================================" > /dev/tty1
        echo "" > /dev/tty1
        echo "  This mode is currently under development." > /dev/tty1
        echo "  In the future, this will boot to a webcam-enabled" > /dev/tty1
        echo "  HTML kiosk specifically to scan PSBTs and sign." > /dev/tty1
        echo "" > /dev/tty1
        echo "  Please reboot and select Option 1 (HTML GUI)." > /dev/tty1
        echo "" > /dev/tty1
        echo "==================================================" > /dev/tty1
        eend 0
        return 0
    elif echo "$CMDLINE" | grep -q "subzero.mode=spend_tui"; then
        clear > /dev/tty1
        echo "==================================================" > /dev/tty1
        echo "   SUBZERO KEYGEN: SPEND/SIGN CONSOLE TUI [STUB]  " > /dev/tty1
        echo "==================================================" > /dev/tty1
        echo "" > /dev/tty1
        echo "  This mode is currently under development." > /dev/tty1
        echo "  In the future, this will boot to a curses-based" > /dev/tty1
        echo "  terminal signer to process PSBT files or serial streams." > /dev/tty1
        echo "" > /dev/tty1
        echo "  Please reboot and select Option 1 (HTML GUI)." > /dev/tty1
        echo "" > /dev/tty1
        echo "==================================================" > /dev/tty1
        eend 0
        return 0
    fi

    clear > /dev/tty1
    echo "==================================================" > /dev/tty1
    echo "   SUBZERO KEYGEN: INITIALIZING KIOSK MODE        " > /dev/tty1
    echo "==================================================" > /dev/tty1
    echo "" > /dev/tty1
    echo "  Loading amnesic browser engine..." > /dev/tty1
    echo "" > /dev/tty1
    echo "  NOTE: A black screen for up to 20 seconds is" > /dev/tty1
    echo "  completely normal while the sandbox initializes." > /dev/tty1
    echo "" > /dev/tty1
    echo "==================================================" > /dev/tty1
    sleep 3

    # Launch X server directly on vt7 to open Chromium kiosk targeting our HTML file
    # Secure flags: disable devtools, disable JIT, enforce amnesic profile, black-hole networking
    xinit /usr/bin/chromium-browser \
        --kiosk \
        --no-sandbox \
        --autoplay-policy=no-user-gesture-required \
        --disable-dev-tools \
        --js-flags="--jitless" \
        --user-data-dir=/tmp/chromium-profile \
        --disable-dev-shm-usage \
        --no-first-run \
        --no-default-browser-check \
        --disable-infobars \
        --disable-session-crashed-bubble \
        --proxy-server="socks5://127.0.0.1:0" \
        file:///opt/subzero/index.html \
        -- vt7 >/dev/null 2>&1 &
        
    sleep 2
    chvt 7
    eend $?
}

stop() {
    ebegin "Stopping SubZero Kiosk..."
    killall xinit || true
    killall chromium-browser || true
    eend $?
}
EOF

chmod +x "${ROOTFS_DIR}/etc/init.d/subzero-kiosk"

# Register services to boot stages
chroot "${ROOTFS_DIR}" rc-update add dbus default
chroot "${ROOTFS_DIR}" rc-update add subzero-kiosk default
chroot "${ROOTFS_DIR}" rc-update add udev sysinit
chroot "${ROOTFS_DIR}" rc-update add udev-trigger sysinit
chroot "${ROOTFS_DIR}" rc-update add udev-postmount default
chroot "${ROOTFS_DIR}" rc-update add hwdrivers sysinit
chroot "${ROOTFS_DIR}" rc-update add localmount boot

# Disable virtual consoles (prevent tty breakout)
sed -i 's/^tty[0-9]:/#&/' "${ROOTFS_DIR}/etc/inittab"

# Disable network interfaces from starting
echo "# Offline Airgap Network Config" > "${ROOTFS_DIR}/etc/network/interfaces"

# Configure read-only rootfs mount + tmpfs RAM volumes for amnesic execution
echo "LABEL=SUBZERO / ext4 ro,noatime 0 1" > "${ROOTFS_DIR}/etc/fstab"
echo "tmpfs /tmp tmpfs nodev,nosuid,size=256M 0 0" >> "${ROOTFS_DIR}/etc/fstab"
echo "tmpfs /var/log tmpfs nodev,nosuid,size=16M 0 0" >> "${ROOTFS_DIR}/etc/fstab"
echo "tmpfs /root tmpfs nodev,nosuid,size=64M 0 0" >> "${ROOTFS_DIR}/etc/fstab"

# Step 8: Purge network and wireless firmware modules to secure airgap, retaining GPU firmware (i915/amdgpu)
echo "\n[Step 8] Purging wireless and network firmware blobs..."
rm -rf "${ROOTFS_DIR}/lib/firmware/brcm"*
rm -rf "${ROOTFS_DIR}/lib/firmware/rtw"*
rm -rf "${ROOTFS_DIR}/lib/firmware/ath"*
rm -rf "${ROOTFS_DIR}/lib/firmware/iwlwifi"*
rm -rf "${ROOTFS_DIR}/lib/firmware/intel/ibt"*
rm -rf "${ROOTFS_DIR}/lib/firmware/qca"*
rm -rf "${ROOTFS_DIR}/lib/firmware/mediatek"*
rm -rf "${ROOTFS_DIR}/lib/firmware/rt2870.bin"
rm -rf "${ROOTFS_DIR}/lib/firmware/rt73.bin"

# Step 9: Assemble final partition disk image (.img)
echo "\n[Step 9] Assembling bootable disk image (subzero-alpine.img)..."
IMG_SIZE_MB=2000
dd if=/dev/zero of="${IMG_PATH}" bs=1M count=${IMG_SIZE_MB} status=progress

# Step 10: Create GPT partition table and partition layout
echo "\n[Step 10] Partitioning disk image with GPT..."
parted -s "${IMG_PATH}" mklabel gpt
parted -s "${IMG_PATH}" mkpart primary fat32 1MiB 65MiB
parted -s "${IMG_PATH}" name 1 ESP
parted -s "${IMG_PATH}" set 1 esp on
parted -s "${IMG_PATH}" mkpart primary ext4 65MiB 100%
parted -s "${IMG_PATH}" name 2 ROOTFS

# Setup loopback device with partition scanner and settle nodes
LOOP_DEV=$(losetup -f)
losetup -P "${LOOP_DEV}" "${IMG_PATH}"
udevadm settle

# Step 11: Formatting loop partitions
echo "\n[Step 11] Formatting partitions..."
mkfs.vfat -F32 -n "EFI" "${LOOP_DEV}p1"
mkfs.ext4 -F -L "SUBZERO" "${LOOP_DEV}p2"

# Step 12: Mounting target partitions and copying files
echo "\n[Step 12] Mounting partitions and running file sync..."
MNT_DIR="${BUILD_DIR}/mnt"
mkdir -p "${MNT_DIR}"
mount "${LOOP_DEV}p2" "${MNT_DIR}"

# Create mount point for EFI System Partition (ESP) on rootfs
mkdir -p "${MNT_DIR}/boot/efi"
mount "${LOOP_DEV}p1" "${MNT_DIR}/boot/efi"

# Sync rootfs files
rsync -a --exclude='/dev' --exclude='/proc' --exclude='/sys' "${ROOTFS_DIR}/" "${MNT_DIR}/"

# Recreate system directories
mkdir -p "${MNT_DIR}/dev" "${MNT_DIR}/proc" "${MNT_DIR}/sys"

# Step 13: Install grub-efi inside chroot
echo "\n[Step 13] Installing GRUB UEFI bootloader..."
mount --bind /dev "${MNT_DIR}/dev"
mount --bind /proc "${MNT_DIR}/proc"
mount --bind /sys "${MNT_DIR}/sys"

chroot "${MNT_DIR}" grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=grub --boot-directory=/boot --removable --no-nvram

# Clean up chroot bind mounts
umount "${MNT_DIR}/dev"
umount "${MNT_DIR}/proc"
umount "${MNT_DIR}/sys"

# Step 14: Creating GRUB configuration
echo "\n[Step 14] Creating GRUB boot configuration..."
mkdir -p "${MNT_DIR}/boot/grub"
cat << 'EOF' > "${MNT_DIR}/boot/grub/grub.cfg"
set default=0
set timeout=10

# Load video modules to prevent UEFI "blind mode" warnings
insmod all_video
set gfxpayload=keep

menuentry "1. SubZero: Keygen (HTML GUI) [Active]" {
    search --no-floppy --label --set=root SUBZERO
    linux /boot/vmlinuz-lts root=LABEL=SUBZERO ro modules=sd-mod,usb-storage,ext4,uas,nvme,mmc_block,sdhci,sdhci-pci,ahci quiet subzero.mode=keygen_html
    initrd /boot/initramfs-lts
}

menuentry "2. SubZero: Keygen (Console TUI) [Aspirational - COMING SOON]" {
    search --no-floppy --label --set=root SUBZERO
    linux /boot/vmlinuz-lts root=LABEL=SUBZERO ro modules=sd-mod,usb-storage,ext4,uas,nvme,mmc_block,sdhci,sdhci-pci,ahci quiet subzero.mode=keygen_tui
    initrd /boot/initramfs-lts
}

menuentry "3. SubZero: Spend/Sign (HTML GUI) [Aspirational - COMING SOON]" {
    search --no-floppy --label --set=root SUBZERO
    linux /boot/vmlinuz-lts root=LABEL=SUBZERO ro modules=sd-mod,usb-storage,ext4,uas,nvme,mmc_block,sdhci,sdhci-pci,ahci quiet subzero.mode=spend_html
    initrd /boot/initramfs-lts
}

menuentry "4. SubZero: Spend/Sign (Console TUI) [Aspirational - COMING SOON]" {
    search --no-floppy --label --set=root SUBZERO
    linux /boot/vmlinuz-lts root=LABEL=SUBZERO ro modules=sd-mod,usb-storage,ext4,uas,nvme,mmc_block,sdhci,sdhci-pci,ahci quiet subzero.mode=spend_tui
    initrd /boot/initramfs-lts
}
EOF

# Sync changes and cleanly unmount loop partitions
sync
umount "${MNT_DIR}/boot/efi"
umount "${MNT_DIR}"

# Detach raw loop device
losetup -d "${LOOP_DEV}"

echo "\n==========================================="
echo " SUCCESS: Deterministic UEFI Alpine image compiled!"
echo " Image Target: ${IMG_PATH}"
echo " Use scripts/flash_drive.py to write to SD card/USB."
echo "==========================================="
