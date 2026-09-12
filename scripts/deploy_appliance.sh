#!/bin/bash
# SubZero Appliance Live Deployment Engine
# Copyright (c) 2026 SubZero Appliance Contributors
# SPDX-License-Identifier: Apache-2.0
set -e

TARGET_PART="${1:-/dev/sdb1}"

if [ ! -b "$TARGET_PART" ]; then
  echo "Error: Target partition '$TARGET_PART' is not a valid block device."
  echo "Usage: $0 [TARGET_PARTITION] (default: /dev/sdb1)"
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

BUILD_COMMIT="$(git rev-parse --short HEAD)"
BUILD_STAMP="$(git log -1 --format=%cI "$BUILD_COMMIT" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")"

echo "=========================================================================="
echo "          [!] SUBZERO APPLIANCE REPRODUCIBLE DEPLOYMENT [!]"
echo "=========================================================================="
echo " Commit:    $BUILD_COMMIT"
echo " Timestamp: $BUILD_STAMP"
echo " Target:    $TARGET_PART"
echo "=========================================================================="

echo ">>> [1/4] Compiling static musl binary in Docker (Deterministic Build)..."
docker run --rm --user 0:0 \
  -v "$REPO_ROOT":/home/rust/src \
  -e SOURCE_DATE_EPOCH=1700000000 \
  -e TZ=UTC \
  -e RUSTFLAGS="--remap-path-prefix /home/rust/src=/subzero" \
  -e BUILD_TIMESTAMP="$BUILD_STAMP" \
  -e SUBZERO_BUILD_TIMESTAMP="$BUILD_STAMP" \
  -e SUBZERO_GIT_COMMIT="$BUILD_COMMIT" \
  messense/rust-musl-cross:x86_64-musl \
  bash -c "cd /home/rust/src && touch build.rs src/main.rs src/ui.rs && cargo build --release"

COMPILED_BIN="$REPO_ROOT/target/x86_64-unknown-linux-musl/release/subzero"
if [ ! -f "$COMPILED_BIN" ]; then
  echo "Error: Compilation failed, binary not found at $COMPILED_BIN"
  exit 1
fi
echo ">>> Binary compiled successfully: $(ls -lh "$COMPILED_BIN" | awk '{print $5}')"

echo ">>> [2/4] Injecting binary and Terminus 12px font into Alpine squashfs..."
docker run --rm --privileged \
  -v "$REPO_ROOT":/src \
  -v /dev:/dev \
  alpine sh -c "
set -e
apk add --no-cache squashfs-tools >/dev/null 2>&1

mkdir -p /mnt/sd /mnt/sq
mount '$TARGET_PART' /mnt/sd

echo '    - Unsquashing rootfs.squashfs...'
unsquashfs -d /mnt/sq /mnt/sd/rootfs.squashfs >/dev/null

echo '    - Verifying high-density 12px Terminus font (ter-v12n)...'
if [ ! -f /mnt/sq/usr/share/consolefonts/ter-v12n.psf.gz ]; then
  echo 'Error: ter-v12n.psf.gz missing from rootfs consolefonts.'
  exit 1
fi

echo '    - Updating /usr/local/bin/subzero and /opt/subzero/subzero...'
mkdir -p /mnt/sq/usr/local/bin /mnt/sq/opt/subzero
cp /src/target/x86_64-unknown-linux-musl/release/subzero /mnt/sq/usr/local/bin/subzero
cp /src/target/x86_64-unknown-linux-musl/release/subzero /mnt/sq/opt/subzero/subzero
chmod 755 /mnt/sq/usr/local/bin/subzero /mnt/sq/opt/subzero/subzero

echo '    - Configuring high-density typography in /opt/subzero/launch.sh...'
cat << 'LAUNCH_EOF' > /mnt/sq/opt/subzero/launch.sh
#!/bin/sh
export TERM=linux
export HOME=/root
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# High-Density Typography: Set Terminus 12-pixel font for 45-50 console text rows
/usr/sbin/setfont /usr/share/consolefonts/ter-v12n.psf.gz > /dev/tty1 2>&1 || true

# Clear VT1 and reset cursor
printf \"\033[2J\033[H\033[3J\" > /dev/tty1 2>/dev/null || true
echo 0 > /sys/class/graphics/fbcon/cursor_blink 2>/dev/null || true

# Execute SubZero Pure Rust TUI directly on physical console
/usr/local/bin/subzero < /dev/tty1 > /dev/tty1 2>&1

# When SubZero exits ([Q][Q] confirmed), immediately power off hardware to purge RAM
sync
/sbin/poweroff -f >/dev/null 2>&1 || /sbin/reboot -f >/dev/null 2>&1 || true
LAUNCH_EOF
chmod 755 /mnt/sq/opt/subzero/launch.sh

echo '    - Configuring /etc/init.d/subzero-font OpenRC service...'
cat << 'FONT_EOF' > /mnt/sq/etc/init.d/subzero-font
#!/sbin/openrc-run
description=\"Loads high-density Terminus 12px (ter-v12n) font for SubZero TUI\"

depend() {
    need localmount
    after udev
}

start() {
    ebegin \"Setting console font to ter-v12n\"
    /usr/sbin/setfont /usr/share/consolefonts/ter-v12n.psf.gz > /dev/tty1 2>&1 || true
    eend 0
}
FONT_EOF
chmod 755 /mnt/sq/etc/init.d/subzero-font

echo '    - Re-compressing squashfs with deterministic xz...'
rm -f /tmp/rootfs.squashfs
mksquashfs /mnt/sq /tmp/rootfs.squashfs -comp xz -b 1048576 -all-root -no-xattrs -no-exports -noappend -reproducible -all-time 1700000000 >/dev/null
cp /tmp/rootfs.squashfs /mnt/sd/rootfs.squashfs

echo '>>> [3/4] Updating GRUB bootloader configuration on partition 1...'
cat << GCONF > /mnt/sd/EFI/BOOT/grub.cfg
set default=\"0\"
set timeout=3

echo \"\"
echo \"==========================================================================\"
echo \"    [!] SUBZERO-RS KEYOSK: BUILD $BUILD_COMMIT [$BUILD_STAMP] [!]\"
echo \"==========================================================================\"
echo \">>> NOTE: A 20-30 SECOND BLACK SCREEN PAUSE AFTER BOOTING IS NORMAL.    <<<\"
echo \">>> THE SYSTEM IS COPYING THE ENTIRE AMNESIC OS INTO RAM (TORAM AIRGAP).<<<\"
echo \"==========================================================================\"
echo \"\"

menuentry \"1. SubZero-rs v0.3.0 [$BUILD_COMMIT | $BUILD_STAMP]\" {
    insmod efi_gop
    insmod efi_uga
    insmod all_video
    set gfxpayload=keep
    echo \"\"
    echo \"==========================================================================\"
    echo \">>> [!] 20-30 SECOND BLACK SCREEN PAUSE IS NORMAL (TORAM COPY) [!]     <<<\"
    echo \">>> STAGING APPLIANCE 100% INTO RAM. DO NOT POWER OFF OR REMOVE MEDIA. <<<\"
    echo \"==========================================================================\"
    echo \"\"
    search --no-floppy --file --set=root /EFI/BOOT/vmlinuz-lts
    linux /EFI/BOOT/vmlinuz-lts root=/dev/ram0 console=tty1 quiet loglevel=3
    initrd /EFI/BOOT/initramfs-lts
}

menuentry \"2. SubZero-rs v0.3.0 (Verbose Debug Console) [$BUILD_COMMIT]\" {
    insmod efi_gop
    insmod efi_uga
    insmod all_video
    set gfxpayload=keep
    search --no-floppy --file --set=root /EFI/BOOT/vmlinuz-lts
    linux /EFI/BOOT/vmlinuz-lts root=/dev/ram0 console=tty1 debug
    initrd /EFI/BOOT/initramfs-lts
}
GCONF

echo '>>> [4/4] Updating SHA256SUMS and flushing device cache...'
cd /mnt/sd
sha256sum rootfs.squashfs EFI/BOOT/BOOTX64.EFI EFI/BOOT/grub.cfg startup.nsh > SHA256SUMS
cat SHA256SUMS

cd /
sync
umount /mnt/sd
rm -rf /mnt/sq /tmp/rootfs.squashfs
echo '=== SUCCESS: DEPLOYMENT VERIFIED AND DEVICE SYNCED ==='
"

sync
echo "Appliance media ready on $TARGET_PART."
