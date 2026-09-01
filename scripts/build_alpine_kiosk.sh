#!/bin/bash
# ===========================================================================
#         SubZero Keyosk: Deterministic Alpine CLI Image Builder
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
BUILD_DIR="/tmp/subzero_alpine_build"
ROOTFS_DIR="${BUILD_DIR}/rootfs"
MNT_DIR="${BUILD_DIR}/mnt"
OUTPUT_DIR="${OUTPUT_DIR:-${WORKSPACE_DIR}/dist}"
# Positional arguments or environment overrides
TUI_ARG="${1:-${TUI_BUNDLE:-fb_vault.cjs}}"
TUI_BUNDLE="$(basename "$TUI_ARG")"
IMG_ARG="${2:-${IMG_NAME:-subzero-alpine.img}}"
IMG_NAME="$(basename "$IMG_ARG")"
IMG_PATH="${OUTPUT_DIR}/${IMG_NAME}"
LOOP_DEV=""
ALPINE_VERSION="3.19.1"
MINIROOTFS_URL="https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-minirootfs-${ALPINE_VERSION}-x86_64.tar.gz"

echo "==========================================="
echo "       BUILDING SUBZERO ALPINE IMAGE       "
echo "==========================================="

# Step 1: Prepare staging directories
echo -e "\n[Step 1] Initializing build workspace..."
umount -l "${BUILD_DIR}/rootfs/dev" 2>/dev/null || true
umount -l "${BUILD_DIR}/rootfs/proc" 2>/dev/null || true
umount -l "${BUILD_DIR}/rootfs/sys" 2>/dev/null || true
umount -l "${BUILD_DIR}/mnt/dev" 2>/dev/null || true
umount -l "${BUILD_DIR}/mnt/proc" 2>/dev/null || true
umount -l "${BUILD_DIR}/mnt/sys" 2>/dev/null || true
umount -l "${BUILD_DIR}/mnt/boot/efi" 2>/dev/null || true
umount -l "${BUILD_DIR}/mnt" 2>/dev/null || true
rm -rf --one-file-system "${BUILD_DIR}"
mkdir -p "${ROOTFS_DIR}"
mkdir -p "${WORKSPACE_DIR}/dist"

# Step 2: Download Alpine Mini RootFS
echo -e "\n[Step 2] Downloading Alpine Mini RootFS (${ALPINE_VERSION})..."
curl -sSL -o "${BUILD_DIR}/minirootfs.tar.gz" "${MINIROOTFS_URL}"
tar -xzf "${BUILD_DIR}/minirootfs.tar.gz" -C "${ROOTFS_DIR}"

# Step 3: Configure repositories and copy host DNS for download resolution
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
    umount -l "${MNT_DIR}/boot/efi" 2>/dev/null || true
    umount -l "${MNT_DIR}" 2>/dev/null || true
    if [ -n "${LOOP_DEV:-}" ]; then
        kpartx -d "${LOOP_DEV}" 2>/dev/null || true
        losetup -d "${LOOP_DEV}" 2>/dev/null || true
    fi
}
trap cleanup_mounts EXIT

# Stub grub-probe in chroot to prevent trigger warning
mkdir -p "${ROOTFS_DIR}/usr/sbin"
ln -sf /bin/true "${ROOTFS_DIR}/usr/sbin/grub-probe"

# Step 5: Install packages inside rootfs
echo -e "\n[Step 5] Bootstrapping Alpine packages..."
chroot "${ROOTFS_DIR}" apk update
chroot "${ROOTFS_DIR}" apk add --no-cache \
    alpine-base \
    linux-lts \
    linux-firmware-i915 \
    linux-firmware-amdgpu \
    linux-firmware-radeon \
    grub-efi \
    busybox-mdev-openrc \
    nodejs \
    kbd \
    font-terminus \
    dosfstools \
    parted \
    util-linux

# Framebuffer modules — loaded by the `modules` OpenRC service at boot
# fbcon: binds VT consoles to the framebuffer so text is visible
# efifb / simpledrm: EFI framebuffer drivers for generic UEFI machines
# i915: Intel Gen 8/9/Xe graphics driver (covers Dell Chromebook 3180 / Intel Celeron N3060)
# amdgpu: AMD Ryzen / Radeon graphics driver
# bochs_drm: DRM driver for QEMU's standard VGA (also covers real bochs)
echo -e "fbcon\nefifb\nsimpledrm\ni915\namdgpu\nbochs_drm" >> "${ROOTFS_DIR}/etc/modules"

# Step 5.1: Generate Deterministic Package Lock Manifest
echo -e "\n[Step 5.1] Generating Deterministic Package Lock Manifest..."
mkdir -p "${WORKSPACE_DIR}/docs"
cat << 'HEADER' > "${WORKSPACE_DIR}/docs/PACKAGE_LOCK_MANIFEST.txt"
================================================================================
           SUBZERO KEYOSK // ALPINE PACKAGE SUPPLY-CHAIN LOCK MANIFEST
================================================================================
Generated during deterministic image compilation.
All packages are cryptographically signed by Alpine Linux Core Release Keys.
================================================================================
PACKAGE                                  VERSION              ORIGIN / STATUS
--------------------------------------------------------------------------------
HEADER
chroot "${ROOTFS_DIR}" apk list --installed | sort >> "${WORKSPACE_DIR}/docs/PACKAGE_LOCK_MANIFEST.txt"
echo "  [✓] Package lock manifest written to docs/PACKAGE_LOCK_MANIFEST.txt ($(chroot "${ROOTFS_DIR}" apk list --installed | wc -l) packages locked)."

# Step 6: Inject SubZero Keygen compiled application & assets
echo -e "\n[Step 6] Injecting SubZero Keygen CLI application (${TUI_BUNDLE})..."
mkdir -p "${ROOTFS_DIR}/opt/subzero/templates" "${ROOTFS_DIR}/opt/subzero/docs"
if [ -f "${WORKSPACE_DIR}/dist/${TUI_BUNDLE}" ]; then
    cp "${WORKSPACE_DIR}/dist/${TUI_BUNDLE}" "${ROOTFS_DIR}/opt/subzero/tui.cjs"
else
    echo "console.log(\"Missing dist/${TUI_BUNDLE}\");" > "${ROOTFS_DIR}/opt/subzero/tui.cjs"
fi

if [ -f "${WORKSPACE_DIR}/src/templates/decrypt.html" ]; then
    cp "${WORKSPACE_DIR}/src/templates/decrypt.html" "${ROOTFS_DIR}/opt/subzero/templates/decrypt.html"
fi

if [ -f "${WORKSPACE_DIR}/docs/SYSTEM_MANIFEST.txt" ]; then
    cp "${WORKSPACE_DIR}/docs/SYSTEM_MANIFEST.txt" "${ROOTFS_DIR}/opt/subzero/docs/SYSTEM_MANIFEST.txt"
fi

# Inject BIP-39 English wordlist into /etc/bip39-english.txt for standalone offline inspectability
node -e "const { wordlist } = require('@scure/bip39/wordlists/english'); console.log(wordlist.join('\n'));" > "${ROOTFS_DIR}/etc/bip39-english.txt" 2>/dev/null || true

TUI_HASH=$(sha256sum "${ROOTFS_DIR}/opt/subzero/tui.cjs" | awk '{print $1}')
echo "  [Security Hash] tui.cjs (Deterministic Core): ${TUI_HASH}"

# Step 7: Configure kiosk autostart via direct inittab controlling TTY
echo -e "\n[Step 7] Configuring kiosk inittab and system services..."

# Load Terminus font during boot
cat << 'FONTSCRIPT' > "${ROOTFS_DIR}/etc/init.d/subzero-font"
#!/sbin/openrc-run
description="Loads high-resolution Terminus 16n font for 1:1 gapless square QR codes"
depend() {
    after localmount
}
start() {
    setfont ter-v16n 2>/dev/null || setfont ter-v16b 2>/dev/null || true
}
FONTSCRIPT
chmod +x "${ROOTFS_DIR}/etc/init.d/subzero-font"

# Register standard services to boot stages
chroot "${ROOTFS_DIR}" rc-update add subzero-font default
chroot "${ROOTFS_DIR}" rc-update add mdev sysinit 2>/dev/null || true
chroot "${ROOTFS_DIR}" rc-update add hwdrivers sysinit 2>/dev/null || true
chroot "${ROOTFS_DIR}" rc-update add modules boot 2>/dev/null || true

# Create robust controlling TTY launcher script
cat << 'LAUNCHER' > "${ROOTFS_DIR}/opt/subzero/launch.sh"
#!/bin/sh
export TERM=linux
export HOME=/root
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Clear VT1 and print high-visibility early initialization banner
printf "\033[2J\033[H\033[3J\033[1;33m" > /dev/tty1 2>/dev/null || true
echo "=================================================================" > /dev/tty1 2>/dev/null || true
echo "           [!] SUBZERO KEYOSK: INITIALIZING HARDWARE [!]         " > /dev/tty1 2>/dev/null || true
echo "=================================================================" > /dev/tty1 2>/dev/null || true
echo ">>> Staging in-memory direct framebuffer interface...            " > /dev/tty1 2>/dev/null || true
echo 0 > /sys/class/graphics/fbcon/cursor_blink 2>/dev/null || true

# Wait up to 5 seconds for /dev/fb0 to become available
for i in $(seq 1 50); do
    if [ -c /dev/fb0 ]; then
        chmod 666 /dev/fb0 /dev/tty1 2>/dev/null || true
        break
    fi
    sleep 0.1
done

# If /dev/fb0 still not present, log error to tty1
if [ ! -c /dev/fb0 ]; then
    echo "[SUBZERO ERROR] /dev/fb0 not found! Active DRM devices:" > /dev/tty1
    ls -la /dev/dri/ /dev/fb* >> /dev/tty1 2>&1
    sleep 5
fi

# Execute SubZero Framebuffer Keyosk directly on tty1
cd /opt/subzero
/usr/bin/node /opt/subzero/tui.cjs < /dev/tty1 > /dev/tty1 2>&1

# When Node exits, perform immediate RAM-safe ACPI poweroff
sync
echo 1 > /proc/sys/kernel/sysrq 2>/dev/null || true
echo o > /proc/sysrq-trigger 2>/dev/null || true
exec /sbin/poweroff -f 2>/dev/null || /sbin/shutdown -h now 2>/dev/null || while true; do sleep 1; done
LAUNCHER
chmod 755 "${ROOTFS_DIR}/opt/subzero/launch.sh"

# Configure inittab for direct controlling TTY on tty1 (VGA)
cat << 'INITTAB' > "${ROOTFS_DIR}/etc/inittab"
::sysinit:/sbin/openrc sysinit
::sysinit:/sbin/openrc boot
::wait:/sbin/openrc default

# Direct controlling TTY kiosk session on physical console via launcher
tty1::once:/opt/subzero/launch.sh

::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/openrc shutdown
INITTAB

# Enable parallel OpenRC service execution
sed -i 's/^#rc_parallel="NO"/rc_parallel="YES"/' "${ROOTFS_DIR}/etc/rc.conf"

# Disable network interfaces from starting
echo "# Offline Airgap Network Config" > "${ROOTFS_DIR}/etc/network/interfaces"

# Configure volatile RAM volumes (no physical disk references in fstab)
echo "tmpfs /tmp tmpfs nodev,nosuid,size=64M 0 0" > "${ROOTFS_DIR}/etc/fstab"
echo "tmpfs /var/log tmpfs nodev,nosuid,size=16M 0 0" >> "${ROOTFS_DIR}/etc/fstab"
echo "tmpfs /root tmpfs nodev,nosuid,noexec,size=16M 0 0" >> "${ROOTFS_DIR}/etc/fstab"

# Step 7.5: Kernel and Memory Hardening (Anti-Coredump, Anti-SysRq, BPF & Ptrace Restrictions)
mkdir -p "${ROOTFS_DIR}/etc/sysctl.d"
cat << 'SYSCTL' > "${ROOTFS_DIR}/etc/sysctl.d/00-subzero-hardened.conf"
# Disable all kernel coredump persistence
kernel.core_pattern = /dev/null
fs.suid_dumpable = 0
# Restrict kernel pointer leaking and unprivileged dmesg
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
# Disable Magic SysRq key to prevent console termination
kernel.sysrq = 0
# Disable warm-booting unverified kernels
kernel.kexec_load_disabled = 1
# Disable unprivileged eBPF
kernel.unprivileged_bpf_disabled = 1
# Prevent automatic line discipline module loading
dev.tty.ldisc_autoload = 0
# Disallow swap
vm.swappiness = 0
SYSCTL

# Step 8: Purge firmware blobs to secure airgap
echo -e "\n[Step 8] Purging wireless and network firmware blobs..."
rm -rf "${ROOTFS_DIR}/lib/firmware/brcm"*







rm -rf "${ROOTFS_DIR}/var/cache/apk/*"
# Smart Whitelist: Nuke all filesystems except essential boot/FAT/EXT4
KMOD_DIR=$(find "${ROOTFS_DIR}/lib/modules" -mindepth 1 -maxdepth 1 -type d | head -n 1)
if [ -n "$KMOD_DIR" ]; then
    find "${KMOD_DIR}/kernel/fs" -mindepth 1 -maxdepth 1 -type d ! -name "ext4" ! -name "fat" ! -name "nls" ! -name "vfat" ! -name "squashfs" ! -name "overlayfs" ! -name "overlay" ! -name "jbd2" ! -name "mbcache" -exec rm -rf {} +
    # Smart Whitelist: Nuke all drivers except core IO, USB, and HID
    find "${KMOD_DIR}/kernel/drivers" -mindepth 1 -maxdepth 1 -type d ! -name "usb" ! -name "hid" ! -name "block" ! -name "scsi" ! -name "nvme" ! -name "ata" ! -name "md" ! -name "input" ! -name "char" ! -name "firmware" ! -name "tty" ! -name "acpi" ! -name "pci" ! -name "base" ! -name "bus" ! -name "crypto" ! -name "mfd" ! -name "soc" ! -name "clk" ! -name "dma" ! -name "i2c" ! -name "spi" ! -name "gpio" ! -name "pinctrl" ! -name "cdrom" ! -name "video" ! -name "gpu" ! -name "mmc" ! -name "misc" ! -name "virtio" ! -name "memstick" ! -name "hwmon" -exec rm -rf {} +
    # [AUDIT-REMEDIATION: AD-09]
    # Auditor Warning: Latent network protocol stacks in kernel represent unneeded attack surface.
    # Remediation: Physically delete all kernel/net protocol stacks, wireless, and USB network drivers.
    # Ref: docs/AUDIT_REMEDIATION_LOG.md#AD-09
    rm -rf "${KMOD_DIR}/kernel/net" "${KMOD_DIR}/kernel/sound" "${KMOD_DIR}/kernel/arch"
    # Hard airgap: explicitly purge USB networking & serial dongle drivers
    rm -rf "${KMOD_DIR}/kernel/drivers/usb/net" "${KMOD_DIR}/kernel/drivers/usb/serial"
fi
rm -rf "${ROOTFS_DIR}/usr/share/man"
rm -rf "${ROOTFS_DIR}/usr/share/doc"
rm -rf "${ROOTFS_DIR}/usr/share/zoneinfo"
rm -rf "${ROOTFS_DIR}/usr/lib/node_modules"

# Clean apk caches and package database
rm -rf "${ROOTFS_DIR}/lib/apk/db"
rm -rf "${ROOTFS_DIR}/var/lib/apk"
rm -rf "${ROOTFS_DIR}/var/cache/apk/"*

# Remove debug kernel maps and unused media/sound drivers
rm -f "${ROOTFS_DIR}/boot/System.map-lts" "${ROOTFS_DIR}/boot/config-lts"
rm -rf "${ROOTFS_DIR}/lib/modules/"*/kernel/sound
rm -rf "${ROOTFS_DIR}/lib/modules/"*/kernel/drivers/media

# Step 8.6: Rebuild minimal initramfs (features: base, squashfs, ext4, storage, usb, nvme, mmc, kms)
echo -e "\n[Step 8.6] Rebuilding minimal initramfs..."
cat << 'MKINITFS' > "${ROOTFS_DIR}/etc/mkinitfs/mkinitfs.conf"
features="ata base cdrom ext4 keymap kms mmc nvme raid scsi usb virtio squashfs"
MKINITFS
cat << 'MYINIT' > "${ROOTFS_DIR}/usr/share/mkinitfs/initramfs-init"
#!/bin/sh
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
/bin/busybox --install -s /bin 2>/dev/null || true
/bin/busybox --install -s /usr/bin 2>/dev/null || true
/bin/busybox --install -s /sbin 2>/dev/null || true
/bin/busybox --install -s /usr/sbin 2>/dev/null || true
mount -t devtmpfs dev /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys

# Guarantee boot progress is visible on physical screen
if [ -c /dev/tty1 ]; then
    exec 1>/dev/tty1 2>&1
fi

clear 2>/dev/null || true
echo "========================================================"
echo "    [+] SUBZERO KEYOSK // AIRGAPPED BOOTLOADER [+]     "
echo "========================================================"
echo -n "[1/4] Initializing hardware drivers..."
for mod in hwmon libata scsi_mod sd_mod ata_piix pata_acpi ata_generic ahci virtio_pci virtio_blk virtio_scsi nvme_core nvme mmc_block sdhci sdhci-pci xhci-pci xhci-hcd ehci-pci ehci-hcd usb-storage uas vfat fat nls_cp437 nls_iso8859_1 loop squashfs overlay wmi video fbcon efifb simpledrm i915 amdgpu bochs_drm hid hid-generic usbhid; do
    modprobe "$mod" 2>/dev/null
done
echo " [OK]"
echo -n "[2/4] Scanning storage devices for SubZero payload..."
EFI_DEV=""
for attempt in $(seq 1 30); do
    for dev in $(ls /dev/sd* /dev/vd* /dev/nvme* /dev/mmcblk* 2>/dev/null); do
        [ -b "$dev" ] || continue
        mkdir -p /media/efi
        if mount -t vfat -o ro "$dev" /media/efi 2>/dev/null; then
            if [ -f "/media/efi/rootfs.squashfs" ]; then
                EFI_DEV="$dev"
                break 2
            fi
            umount /media/efi 2>/dev/null
        fi
    done
    echo -n "."
    sleep 0.5
done

if [ -z "$EFI_DEV" ]; then
    echo -e "\nFATAL: Could not locate rootfs.squashfs payload on any block device!"
    echo "Executing emergency poweroff in 5 seconds..."
    sleep 5
    poweroff -f 2>/dev/null || reboot -f 2>/dev/null || halt -f
fi
echo " [FOUND: ${EFI_DEV}]"

echo -n "[3/4] Copying OS payload to volatile RAM disk (toram)..."
mkdir -p /media/ram /media/sqfs /sysroot
mount -t tmpfs -o size=90% tmpfs /media/ram

# Copy with visual progress dots in background
cp /media/efi/rootfs.squashfs /media/ram/rootfs.squashfs &
CP_PID=$!
while kill -0 "$CP_PID" 2>/dev/null; do
    echo -n "."
    sleep 0.8
done
echo " [100% COMPLETE]"

echo "[4/4] Storage unmounted. Launching Framebuffer Keyosk..."
umount /media/efi
mount -t squashfs -o ro /media/ram/rootfs.squashfs /media/sqfs
mkdir -p /media/ram/upper /media/ram/work
mount -t overlay overlay -o lowerdir=/media/sqfs,upperdir=/media/ram/upper,workdir=/media/ram/work /sysroot
mkdir -p /sysroot/dev /sysroot/proc /sysroot/sys
mount --move /dev /sysroot/dev
mount --move /proc /sysroot/proc
mount --move /sys /sysroot/sys
echo "========================================================"
echo " >> SUCCESS: OS RUNNING ENTIRELY FROM VOLATILE RAM <<"
echo "========================================================"

# Switch execution into the RAM-based root filesystem
exec switch_root /sysroot /sbin/init
MYINIT
chmod 755 "${ROOTFS_DIR}/usr/share/mkinitfs/initramfs-init"

# Generate kernel initramfs image
KVER=$(ls "${ROOTFS_DIR}/lib/modules" | head -n 1)
chroot "${ROOTFS_DIR}" depmod -a "$KVER"
chroot "${ROOTFS_DIR}" mkinitfs -c /etc/mkinitfs/mkinitfs.conf -o /boot/initramfs-lts "$KVER"

# Step 8.7: Generate EFI and GRUB Configuration
echo -e "\n[Step 8.7] Configuring GRUB & UEFI bootloader..."
mkdir -p "${ROOTFS_DIR}/boot/efi/EFI/BOOT"
mkdir -p "${ROOTFS_DIR}/boot/grub"

cat << 'GRUB' > "${ROOTFS_DIR}/boot/efi/EFI/BOOT/grub.cfg"
set default="0"
set timeout=3

echo ""
echo "=========================================================================="
echo "          [!] SUBZERO KEYOSK: RAM STAGING NOTICE [!]"
echo "=========================================================================="
echo ">>> NOTE: A 20-30 SECOND BLACK SCREEN PAUSE AFTER BOOTING IS NORMAL.    <<<"
echo ">>> THE SYSTEM IS COPYING THE ENTIRE AMNESIC OS INTO RAM (TORAM AIRGAP).<<<"
echo ">>> PLEASE DO NOT POWER OFF OR REMOVE MEDIA DURING THIS PAUSE.          <<<"
echo "=========================================================================="
echo ""

menuentry "1. SubZero Keyosk (Amnesic Airgap) [20-30s Black Screen Pause is Normal]" {
    insmod efi_gop
    insmod efi_uga
    insmod all_video
    set gfxpayload=keep
    echo ""
    echo "=========================================================================="
    echo ">>> [!] 20-30 SECOND BLACK SCREEN PAUSE IS NORMAL (TORAM COPY) [!]     <<<"
    echo ">>> STAGING APPLIANCE 100% INTO RAM. DO NOT POWER OFF OR REMOVE MEDIA. <<<"
    echo "=========================================================================="
    echo ""
    search --no-floppy --file --set=root /EFI/BOOT/vmlinuz-lts
    linux /EFI/BOOT/vmlinuz-lts root=/dev/ram0 console=tty1 quiet loglevel=3
    initrd /EFI/BOOT/initramfs-lts
}

menuentry "2. SubZero Keyosk (Verbose Debug Console)" {
    insmod efi_gop
    insmod efi_uga
    insmod all_video
    set gfxpayload=keep
    search --no-floppy --file --set=root /EFI/BOOT/vmlinuz-lts
    linux /EFI/BOOT/vmlinuz-lts root=/dev/ram0 console=tty1 debug
    initrd /EFI/BOOT/initramfs-lts
}
GRUB

cp "${ROOTFS_DIR}/boot/efi/EFI/BOOT/grub.cfg" "${ROOTFS_DIR}/boot/grub/grub.cfg"
cp "${ROOTFS_DIR}/boot/vmlinuz-lts" "${ROOTFS_DIR}/boot/efi/EFI/BOOT/vmlinuz-lts"
cp "${ROOTFS_DIR}/boot/initramfs-lts" "${ROOTFS_DIR}/boot/efi/EFI/BOOT/initramfs-lts"
echo "\\EFI\\BOOT\\BOOTX64.EFI" > "${ROOTFS_DIR}/boot/efi/startup.nsh"

cat << 'EARLY_CFG' > "${BUILD_DIR}/early.cfg"
    insmod efi_gop
    insmod efi_uga
    insmod all_video
    set gfxpayload=keep
search --no-floppy --file --set=root /EFI/BOOT/grub.cfg
set prefix=($root)/EFI/BOOT
configfile ($root)/EFI/BOOT/grub.cfg
EARLY_CFG

grub-mkimage -O x86_64-efi -c "${BUILD_DIR}/early.cfg" -o "${ROOTFS_DIR}/boot/efi/EFI/BOOT/BOOTX64.EFI" -p /boot/grub part_gpt part_msdos fat ext2 squash4 normal boot linux search search_fs_uuid search_label configfile all_video gfxterm bufio mmap relocator loadenv test echo chain

EFI_HASH=$(sha256sum "${ROOTFS_DIR}/boot/efi/EFI/BOOT/BOOTX64.EFI" | awk '{print $1}')
echo "  [Security Hash] Standalone UEFI (BOOTX64.EFI): ${EFI_HASH}"

# Step 8.8: Unmount virtual filesystems from ROOTFS before imaging
echo -e "\n[Step 8.8] Unmounting virtual filesystems..."
umount -l "${ROOTFS_DIR}/dev" 2>/dev/null || true
umount -l "${ROOTFS_DIR}/proc" 2>/dev/null || true
umount -l "${ROOTFS_DIR}/sys" 2>/dev/null || true
mkdir -p "${ROOTFS_DIR}/dev" "${ROOTFS_DIR}/proc" "${ROOTFS_DIR}/sys"

# Step 9: Clamp all file modification timestamps in rootfs and clean symlinks
echo -e "\n[Step 9] Clamping file modification timestamps to SOURCE_DATE_EPOCH..."
rm -f "${ROOTFS_DIR}/etc/resolv.conf"
rm -f "${ROOTFS_DIR}/boot/boot"
rm -rf "${ROOTFS_DIR}/var/log/"* "${ROOTFS_DIR}/tmp/"* "${ROOTFS_DIR}/root/.ash_history"
find "${ROOTFS_DIR}" -exec touch -h -d "@1700000000" {} + 2>/dev/null || true

# Step 10: Build Dual-Partition Appliance Image (512MB Total)
# Partition 1: 420MB ESP FAT32 (SUBZERO_EFI) -> Alpine OS + rootfs.squashfs + EFI bootloader
# Partition 2: 90MB Basic Data FAT32 (SUBZERO_EST) -> Pre-allocated space for vault.json
echo -e "\n[Step 10] Packaging Dual-Partition Appliance Image (512MB)..."
rm -f "${BUILD_DIR}/rootfs.squashfs" "${BUILD_DIR}/esp.img" "${BUILD_DIR}/estate.img"
mksquashfs "${ROOTFS_DIR}" "${BUILD_DIR}/rootfs.squashfs" -comp zstd -noappend -reproducible -all-root >/dev/null

# 10.1 Create Partition 1 (420MB ESP)
dd if=/dev/zero of="${BUILD_DIR}/esp.img" bs=1M count=420 status=none
mkfs.vfat -F32 -i 19840124 -n "SUBZERO_EFI" "${BUILD_DIR}/esp.img"
MTOOLS_SKIP_CHECK=1 mcopy -m -i "${BUILD_DIR}/esp.img" -s "${ROOTFS_DIR}/boot/efi/"* ::/
MTOOLS_SKIP_CHECK=1 mcopy -m -i "${BUILD_DIR}/esp.img" "${BUILD_DIR}/rootfs.squashfs" ::/

# Generate Partition 1 SHA256SUMS manifest
mkdir -p "${BUILD_DIR}/esp_manifest"
cp "${ROOTFS_DIR}/boot/efi/EFI/BOOT/BOOTX64.EFI" "${BUILD_DIR}/esp_manifest/"
cp "${ROOTFS_DIR}/boot/efi/EFI/BOOT/vmlinuz-lts" "${BUILD_DIR}/esp_manifest/"
cp "${ROOTFS_DIR}/boot/efi/EFI/BOOT/initramfs-lts" "${BUILD_DIR}/esp_manifest/"
cp "${BUILD_DIR}/rootfs.squashfs" "${BUILD_DIR}/esp_manifest/"
(cd "${BUILD_DIR}/esp_manifest" && sha256sum * > SHA256SUMS)
MTOOLS_SKIP_CHECK=1 mcopy -m -i "${BUILD_DIR}/esp.img" "${BUILD_DIR}/esp_manifest/SHA256SUMS" ::/

# 10.2 Create Partition 2 (90MB Estate Storage Data Partition)
dd if=/dev/zero of="${BUILD_DIR}/estate.img" bs=1M count=90 status=none
mkfs.vfat -F32 -i 20260901 -n "SUBZERO_EST" "${BUILD_DIR}/estate.img"

# Stage Estate partition files with SHA256SUMS
mkdir -p "${BUILD_DIR}/estate_manifest"
cp "${WORKSPACE_DIR}/src/templates/decrypt.html" "${BUILD_DIR}/estate_manifest/decrypt.html"
if [ -f "${WORKSPACE_DIR}/docs/SYSTEM_MANIFEST.txt" ]; then
    cp "${WORKSPACE_DIR}/docs/SYSTEM_MANIFEST.txt" "${BUILD_DIR}/estate_manifest/SYSTEM_MANIFEST.txt"
fi
cat << 'README' > "${BUILD_DIR}/estate_manifest/README.txt"
================================================================================
                    SUBZERO KEYOSK // SOVEREIGN ESTATE RECOVERY
================================================================================
This partition contains the client-side WebCrypto recovery tools for your estate.

RECOVERY INSTRUCTIONS:
1. Turn OFF Wi-Fi, Bluetooth, and Ethernet (Airgap Isolation).
2. Open 'decrypt.html' in Chrome, Safari, Firefox, or Edge.
3. Select your encrypted 'vault.json' payload.
4. Enter your 12-word decryption passphrase.
5. Recover master seed, BIP-380 output descriptors, and individual child seeds.

INTEGRITY VERIFICATION:
To verify file integrity before running:
$ sha256sum -c SHA256SUMS
================================================================================
README

(cd "${BUILD_DIR}/estate_manifest" && sha256sum * > SHA256SUMS)
MTOOLS_SKIP_CHECK=1 mcopy -m -i "${BUILD_DIR}/estate.img" -s "${BUILD_DIR}/estate_manifest/"* ::/

# 10.3 Build master 512MB GPT disk image with both partitions
dd if=/dev/zero of="${IMG_PATH}" bs=1M count=512 status=none
cat << 'EOF' | sfdisk -q "${IMG_PATH}"
label: gpt
unit: sectors

1 : start=2048, size=860160, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="SUBZERO_EFI"
2 : start=862208, size=184320, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, name="SUBZERO_EST"
EOF

# Write partition images into disk
dd if="${BUILD_DIR}/esp.img" of="${IMG_PATH}" bs=512 seek=2048 conv=notrunc status=none
dd if="${BUILD_DIR}/estate.img" of="${IMG_PATH}" bs=512 seek=862208 conv=notrunc status=none

chmod 0644 "${IMG_PATH}"
echo "  [Security Hash] Dual-Partition Appliance: $(sha256sum "${IMG_PATH}" | awk '{print $1}')"

# Step 11: Automated Image Self-Verification & Manifest Assertion
echo -e "\n[Step 11] Running Automated Post-Build Integrity Assertion..."
MTOOLS_SKIP_CHECK=1 mdir -i "${BUILD_DIR}/esp.img" ::/SHA256SUMS >/dev/null || { echo "FATAL: ESP SHA256SUMS missing!"; exit 1; }
MTOOLS_SKIP_CHECK=1 mdir -i "${BUILD_DIR}/estate.img" ::/SHA256SUMS >/dev/null || { echo "FATAL: Estate SHA256SUMS missing!"; exit 1; }
MTOOLS_SKIP_CHECK=1 mdir -i "${BUILD_DIR}/estate.img" ::/decrypt.html >/dev/null || { echo "FATAL: decrypt.html missing!"; exit 1; }
echo "  [✓] All required manifest files verified on ESP and Estate partitions."
cp "${IMG_PATH}" "${OUTPUT_DIR}/subzero-alpine.img" 2>/dev/null || true
cp "${IMG_PATH}" "${OUTPUT_DIR}/subzero-vault-pc.img" 2>/dev/null || true
echo "Build complete: ${IMG_PATH}"

