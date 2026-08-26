#!/bin/bash
# ===========================================================================
#         SubZero Keyosk: Deterministic Alpine CLI Image Builder
# ===========================================================================
set -e
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
IMG_NAME="${IMG_NAME:-subzero-alpine.img}"
IMG_PATH="${OUTPUT_DIR}/${IMG_NAME}"
TUI_BUNDLE="${TUI_BUNDLE:-tui.cjs}"
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
    if [ -n "${LOOP_DEV}" ]; then
        kpartx -d "${LOOP_DEV}" 2>/dev/null || true
        losetup -d "${LOOP_DEV}" 2>/dev/null || true
    fi
}
trap cleanup_mounts EXIT

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
    font-terminus

# Framebuffer modules — loaded by the `modules` OpenRC service at boot
# fbcon: binds VT consoles to the framebuffer so text is visible
# efifb / simpledrm: EFI framebuffer drivers for generic UEFI machines
# i915: Intel Gen 8/9/Xe graphics driver (covers Dell Chromebook 3180 / Intel Celeron N3060)
# amdgpu: AMD Ryzen / Radeon graphics driver
# bochs_drm: DRM driver for QEMU's standard VGA (also covers real bochs)
echo -e "fbcon\nefifb\nsimpledrm\ni915\namdgpu\nbochs_drm" >> "${ROOTFS_DIR}/etc/modules"

# Step 6: Inject SubZero Keygen compiled application
echo -e "\n[Step 6] Injecting SubZero Keygen CLI application (${TUI_BUNDLE})..."
mkdir -p "${ROOTFS_DIR}/opt/subzero"
if [ -f "${WORKSPACE_DIR}/dist/${TUI_BUNDLE}" ]; then
    cp "${WORKSPACE_DIR}/dist/${TUI_BUNDLE}" "${ROOTFS_DIR}/opt/subzero/tui.cjs"
else
    echo "console.log(\"Missing dist/${TUI_BUNDLE}\");" > "${ROOTFS_DIR}/opt/subzero/tui.cjs"
fi
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

# Clear VT1 and hide text cursor
printf "\033[2J\033[H\033[3J\033[?25l" > /dev/tty1 2>/dev/null || true
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
exec /usr/bin/node /opt/subzero/tui.cjs < /dev/tty1 > /dev/tty1 2>&1
LAUNCHER
chmod 755 "${ROOTFS_DIR}/opt/subzero/launch.sh"

# Configure inittab for direct controlling TTY on tty1 (VGA)
cat << 'INITTAB' > "${ROOTFS_DIR}/etc/inittab"
::sysinit:/sbin/openrc sysinit
::sysinit:/sbin/openrc boot
::wait:/sbin/openrc default

# Direct controlling TTY kiosk session on physical console via launcher
tty1::respawn:/opt/subzero/launch.sh

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

echo -n "[3/4] Copying OS payload to volatile RAM disk..."
mkdir -p /media/ram /media/sqfs /sysroot
mount -t tmpfs -o size=90% tmpfs /media/ram
cp /media/efi/rootfs.squashfs /media/ram/rootfs.squashfs
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
set timeout=1

menuentry "1. SubZero Keyosk (Amnesic Airgapped Offline Engine)" {
    insmod efi_gop
    insmod efi_uga
    insmod all_video
    set gfxpayload=keep
    search --no-floppy --file --set=root /EFI/BOOT/vmlinuz-lts
    linux /EFI/BOOT/vmlinuz-lts root=/dev/ram0 console=ttyS0,115200 console=tty0 console=tty1 quiet loglevel=3
    initrd /EFI/BOOT/initramfs-lts
}

menuentry "2. SubZero Keyosk (Verbose Debug Console)" {
    insmod efi_gop
    insmod efi_uga
    insmod all_video
    set gfxpayload=keep
    search --no-floppy --file --set=root /EFI/BOOT/vmlinuz-lts
    linux /EFI/BOOT/vmlinuz-lts root=/dev/ram0 console=ttyS0,115200 console=tty0 console=tty1 debug
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

# Step 10: Build standalone Toram Single-Partition Image
echo -e "\n[Step 10] Packaging Toram Single-Partition Image..."
rm -f "${BUILD_DIR}/rootfs.squashfs" "${BUILD_DIR}/esp.img"
mksquashfs "${ROOTFS_DIR}" "${BUILD_DIR}/rootfs.squashfs" -comp zstd -noappend -reproducible -all-root >/dev/null

# Create a 400MB ESP to hold UEFI binaries and compressed rootfs.squashfs
dd if=/dev/zero of="${BUILD_DIR}/esp.img" bs=1M count=400 status=none
mkfs.vfat -F32 -i 19840124 -n "EFI" "${BUILD_DIR}/esp.img"
MTOOLS_SKIP_CHECK=1 mcopy -m -i "${BUILD_DIR}/esp.img" -s "${ROOTFS_DIR}/boot/efi/"* ::/
MTOOLS_SKIP_CHECK=1 mcopy -m -i "${BUILD_DIR}/esp.img" "${BUILD_DIR}/rootfs.squashfs" ::/

# Build raw disk image (GPT, single partition)
dd if=/dev/zero of="${IMG_PATH}" bs=1M count=420 status=none
sgdisk -o "${IMG_PATH}"
sgdisk -n 1:2048:0 -c 1:"SubZero EFI+Payload" -t 1:ef00 "${IMG_PATH}"
dd if="${BUILD_DIR}/esp.img" of="${IMG_PATH}" bs=1M seek=1 conv=notrunc status=none

chmod 0644 "${IMG_PATH}"
echo "  [Security Hash] Toram Image: $(sha256sum "${IMG_PATH}" | awk "{print $1}")"
echo "Build complete: ${IMG_PATH}"

