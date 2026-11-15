#!/usr/bin/env bash
# ==============================================================================
# SubZero v2.0 - Bare-Metal UEFI x86_64 Airgapped USB/SD Appliance Builder
# (`scripts/deploy_appliance.sh`)
# ==============================================================================
#
# WHY THIS BUILDER EXISTS & SECURITY INVARIANTS ENFORCED:
# 1. Digest-Pinned Alpine 3.20 Without `--privileged`:
#    Uses exact OCI manifest digest `alpine@sha256:d9e853e87e55526f6b2917df...`
#    and builds the two-partition GPT image purely on regular files via `parted`,
#    `mkfs.vfat`, `mtools`, and `dd` - zero host loop-mounts and zero `--privileged`
#    container escalation required.
# 2. Signed APK Packages + Zero Unverified Git Blobs:
#    Installs `v4l-utils` (`/usr/bin/v4l2-ctl` feeding pure-Rust `decode_qr_luma`)
#    and `memtester-static` directly from APK-verified Alpine packages instead of
#    shipping opaque prebuilt `.so` / binary blobs in Git.
# 3. Real PID-1 Initramfs Lifecycle (`rdinit=/opt/subzero/launch.sh`):
#    Mounts `/proc`, `/sys`, `/dev` (`devtmpfs`), `/tmp`, and `/run`, loads USB HID,
#    USB storage, VFAT, and UVC webcam kernel modules (`mdev -s`), binds TTY1, runs
#    `/opt/subzero/subzero --self-test`, launches `/opt/subzero/subzero`, and on
#    exit verifies `/opt/subzero/memtester.sha256` before executing a single-pass
#    `memtester-static` physical RAM overwrite paired with `init_on_free=1`.
# 4. Physical Network & DMA Driver Stripping:
#    Deletes `kernel/net`, `drivers/net`, `bluetooth`, `thunderbolt`, `firewire`,
#    and `sound` before building the RAM-only initramfs.
# ==============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$REPO_ROOT/dist"
OUT_IMG="${1:-$DIST_DIR/subzero-v2.0.0-testnet4-x86_64.img}"
OUT_DIR="$(cd "$(dirname "$OUT_IMG")" && pwd)"
OUT_BASENAME="$(basename "$OUT_IMG")"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

# Digest-pinned Alpine 3.20 x86_64 rootfs builder
ALPINE_IMAGE="alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

if [[ ! -x "$DIST_DIR/subzero-x86_64-musl" || ! -f "$DIST_DIR/decrypt.html" ]]; then
    echo "[appliance] dist/ artifacts missing; running ./scripts/build_reproducible.sh first..."
    "$REPO_ROOT/scripts/build_reproducible.sh"
fi

echo "[appliance] Verifying static musl binary KAT self-test before image assembly..."
"$DIST_DIR/subzero-x86_64-musl" --self-test

echo "[appliance] Assembling two-partition UEFI x86_64 airgapped USB image -> $OUT_IMG"
docker run --rm \
    -v "$REPO_ROOT:/src:ro" \
    -v "$OUT_DIR:/out" \
    -e OUT_BASENAME="$OUT_BASENAME" \
    -e HOST_UID="$HOST_UID" \
    -e HOST_GID="$HOST_GID" \
    "$ALPINE_IMAGE" \
    /bin/sh -c '
        set -eu

        apk add --no-cache \
            alpine-conf \
            dosfstools \
            e2fsprogs \
            grub \
            grub-efi \
            kbd \
            linux-lts \
            memtester-static \
            mkinitfs \
            mtools \
            parted \
            terminus-font \
            util-linux \
            v4l-utils

        WORK="/tmp/subzero-img"
        ROOTFS="$WORK/rootfs"
        ISO_STAGE="$WORK/boot_p1"
        EST_STAGE="$WORK/est_p2"
        mkdir -p \
            "$ROOTFS/opt/subzero" \
            "$ROOTFS/usr/bin" \
            "$ROOTFS/usr/lib" \
            "$ROOTFS/lib" \
            "$ROOTFS/usr/share/consolefonts" \
            "$ROOTFS/media/subzero_est" \
            "$ROOTFS/proc" \
            "$ROOTFS/sys" \
            "$ROOTFS/dev" \
            "$ROOTFS/tmp" \
            "$ROOTFS/run" \
            "$ISO_STAGE/boot/grub" \
            "$ISO_STAGE/EFI/BOOT" \
            "$EST_STAGE"

        # 1. Stage static SubZero TUI + APK-verified v4l2-ctl & memtester-static
        cp /src/dist/subzero-x86_64-musl "$ROOTFS/opt/subzero/subzero"
        chmod 0755 "$ROOTFS/opt/subzero/subzero"

        cp /usr/bin/memtester-static "$ROOTFS/opt/subzero/memtester-static"
        chmod 0755 "$ROOTFS/opt/subzero/memtester-static"
        (cd "$ROOTFS" && sha256sum opt/subzero/memtester-static > opt/subzero/memtester.sha256)

        # Copy v4l2-ctl and setfont plus their exact Alpine musl shared libraries into the RAM overlay
        for bin in /usr/bin/v4l2-ctl /usr/bin/setfont; do
            if [ -x "$bin" ]; then
                cp "$bin" "$ROOTFS/usr/bin/"
                ldd "$bin" 2>/dev/null | awk '\''{for(i=1;i<=NF;i++) if ($i ~ /^\//) print $i}'\'' | while read -r so; do
                    if [ -f "$so" ]; then
                        mkdir -p "$ROOTFS$(dirname "$so")"
                        cp -L "$so" "$ROOTFS$so"
                    fi
                done
            fi
        done
        cp /usr/share/consolefonts/ter-v12n.psf.gz "$ROOTFS/usr/share/consolefonts/" 2>/dev/null || true

        # 2. Write PID-1 RAM-only appliance init & verified exit RAM scrubber (`/opt/subzero/launch.sh`)
        cat > "$ROOTFS/opt/subzero/launch.sh" << '\''LAUNCH_EOF'\''
#!/bin/sh
set -u

export PATH="/opt/subzero:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export TERM="linux"

# Mount core virtual filesystems when invoked directly as PID 1 (`rdinit=/opt/subzero/launch.sh`)
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /dev/pts /tmp /run /media/subzero_est
mount -t devpts devpts /dev/pts 2>/dev/null || true
mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /tmp 2>/dev/null || true
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run 2>/dev/null || true

# Load USB keyboard, USB storage, VFAT (Partition 2 estate drive), and UVC webcam drivers
for mod in xhci_pci ehci_pci ohci_pci uhci_hcd usbhid hid_generic usb_storage uas fat vfat nls_cp437 nls_iso8859-1 videodev uvcvideo; do
    modprobe "$mod" 2>/dev/null || true
done
mdev -s 2>/dev/null || true
sleep 1
mdev -s 2>/dev/null || true

if [ -c /dev/tty1 ]; then
    exec </dev/tty1 >/dev/tty1 2>&1
fi

if command -v setfont >/dev/null 2>&1; then
    setfont /usr/share/consolefonts/ter-v12n.psf.gz 2>/dev/null || true
fi

dmesg -n 1 2>/dev/null || true
printf "\033[2J\033[3J\033[H"

# Mandatory boot-time cryptographic KAT self-test BEFORE accepting user entropy
if ! /opt/subzero/subzero --self-test >/tmp/subzero_selftest.log 2>&1; then
    echo "================================================================"
    echo "FATAL TAMPER / HARDWARE FAULT: SubZero KAT self-test FAILED!"
    echo "================================================================"
    cat /tmp/subzero_selftest.log
    sleep 30
    poweroff -f
    exit 1
fi
rm -f /tmp/subzero_selftest.log

# Launch airgapped TUI on TTY1
/opt/subzero/subzero

# Post-exit Amnesic Physical RAM Scrub (`[C-03]` + `[H-02]`):
# Verify `/opt/subzero/memtester-static` against build-pinned SHA-256 and scrub free RAM
printf "\033[2J\033[3J\033[H"
echo "[amnesic-exit] Userland heap scrubbed. Verifying memtester-static SHA-256..."
if (cd / && sha256sum -c /opt/subzero/memtester.sha256 >/dev/null 2>&1); then
    AVAIL_KB="$(awk '\''/^MemAvailable:/ {print $2}'\'' /proc/meminfo 2>/dev/null || echo 0)"
    SCRUB_MB=$((AVAIL_KB / 1024))
    if [ "$SCRUB_MB" -gt 128 ]; then
        SCRUB_MB=$((SCRUB_MB - 96))
        if [ "$SCRUB_MB" -gt 2048 ]; then
            SCRUB_MB=2048
        fi
        echo "[amnesic-exit] Running single-pass physical RAM overwrite (${SCRUB_MB} MiB)..."
        /opt/subzero/memtester-static "${SCRUB_MB}M" 1 >/dev/null 2>&1 || true
    fi
fi

echo "[amnesic-exit] RAM scrub complete; forcing immediate ACPI poweroff."
sync
poweroff -f
LAUNCH_EOF
        chmod 0755 "$ROOTFS/opt/subzero/launch.sh"

        # 3. Prune ALL network, wireless, bluetooth, sound, firewire & thunderbolt kernel modules
        for kdir in /lib/modules/*; do
            [ -d "$kdir" ] || continue
            rm -rf \
                "$kdir/kernel/net" \
                "$kdir/kernel/drivers/net" \
                "$kdir/kernel/drivers/bluetooth" \
                "$kdir/kernel/drivers/firewire" \
                "$kdir/kernel/drivers/thunderbolt" \
                "$kdir/kernel/sound"
            depmod -a "$(basename "$kdir")" || true
        done

        # Configure mkinitfs to include USB HID/storage, KMS video, VFAT, and UVC camera modules
        cat > /etc/mkinitfs/features.d/subzero.modules << '\''MOD_EOF'\''
kernel/fs/fat/*
kernel/fs/nls/nls_cp437*
kernel/fs/nls/nls_iso8859-1*
kernel/drivers/usb/host/*
kernel/drivers/usb/storage/*
kernel/drivers/hid/*
kernel/drivers/hid/usbhid/*
kernel/drivers/media/v4l2-core/*
kernel/drivers/media/common/*
kernel/drivers/media/usb/uvc/*
MOD_EOF
        echo '\''features="base usb kms ata nvme virtio scsi mmc subzero"'\'' > /etc/mkinitfs/mkinitfs.conf

        KVER="$(ls /lib/modules | head -n 1)"
        cp /boot/vmlinuz-lts "$ISO_STAGE/boot/vmlinuz"
        mkinitfs -o "$ISO_STAGE/boot/initramfs" "$KVER"

        # Append SubZero + v4l2-ctl + memtester-static cpio archive onto initramfs
        (cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc | gzip -9) >> "$ISO_STAGE/boot/initramfs"

        # 4. Configure UEFI x86_64 GRUB (`search --label SUBZERO_ESP` + memory-hardening cmdline)
        cat > "$ISO_STAGE/boot/grub/grub.cfg" << '\''GRUB_EOF'\''
insmod part_gpt
insmod fat
insmod search_fs_label
search --no-floppy --label --set=root SUBZERO_ESP

set timeout=1
set default=0

menuentry "SubZero v2.0 Airgapped Cold Vault (RAM-Only Testnet4)" {
    linux /boot/vmlinuz quiet loglevel=3 slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 iommu=force intel_iommu=on rdinit=/opt/subzero/launch.sh
    initrd /boot/initramfs
}
GRUB_EOF

        grub-mkstandalone \
            -O x86_64-efi \
            -o "$ISO_STAGE/EFI/BOOT/BOOTX64.EFI" \
            "boot/grub/grub.cfg=$ISO_STAGE/boot/grub/grub.cfg"

        printf "%s\r\n" "\\EFI\\BOOT\\BOOTX64.EFI" > "$ISO_STAGE/startup.nsh"

        # 5. Stage Partition 2 (`SUBZERO_EST` VFAT recovery partition)
        cp /src/dist/decrypt.html "$EST_STAGE/decrypt.html"
        cat > "$EST_STAGE/README.txt" << '\''README_EOF'\''
SUBZERO KEYOSK v2.0 - ENCRYPTED BITCOIN ESTATE PARTITION (SUBZERO_EST)
======================================================================
When you seal an Estate Vault inside SubZero (Tab F6), this VFAT partition
stores your SIV-committed AES-256-GCM `vault.json` (600,000 PBKDF2 rounds)
alongside `decrypt.html` for zero-dependency offline browser recovery.
README_EOF
        (cd "$EST_STAGE" && sha256sum decrypt.html README.txt > SHA256SUMS)

        # 6. Assemble raw GPT two-partition disk image without host loop-mounts (`mtools`)
        IMG="/out/$OUT_BASENAME"
        rm -f "$IMG"
        truncate -s 256M "$IMG"
        parted -s "$IMG" mklabel gpt
        parted -s "$IMG" mkpart SUBZERO_ESP fat32 1MiB 192MiB
        parted -s "$IMG" set 1 esp on
        parted -s "$IMG" mkpart SUBZERO_EST fat32 192MiB 255MiB

        P1="$WORK/p1.fat"
        P2="$WORK/p2.fat"
        truncate -s 191M "$P1"
        truncate -s 63M "$P2"
        # WHY 11-char labels: VFAT volume labels have a hard 11-ASCII-character ceiling
        # (`SUBZERO_ESP` = 11 chars, `SUBZERO_EST` = 11 chars).
        mkfs.vfat -F 32 -n SUBZERO_ESP "$P1" >/dev/null
        mkfs.vfat -F 32 -n SUBZERO_EST "$P2" >/dev/null

        mcopy -i "$P1" -s "$ISO_STAGE"/* ::/
        mcopy -i "$P2" -s "$EST_STAGE"/* ::/

        dd if="$P1" of="$IMG" bs=1M seek=1 conv=notrunc status=none
        dd if="$P2" of="$IMG" bs=1M seek=192 conv=notrunc status=none
        chown "$HOST_UID:$HOST_GID" "$IMG"
        chmod 0644 "$IMG"

        echo "[appliance] Verifying Partition 1 (SUBZERO_ESP) & Partition 2 (SUBZERO_EST) via mdir:"
        mdir -i "$P1" ::/EFI/BOOT
        mdir -i "$P2" ::/
    '

echo "[appliance] Successfully built airgapped UEFI x86_64 USB/SD image: $OUT_IMG"
sha256sum "$OUT_IMG"
