# Subzero Keyosk Boot Sequence & RAM Copy Architecture

---

## 1. Why Does the Initial Boot Take ~20–30 Seconds?

When Subzero boots on generic PC hardware (`subzero-vault-pc.img`), it executes an uncompromised **`toram` (Run-From-RAM) security sequence**:

```
[1. UEFI GRUB] ---> [2. Hardware Detection] ---> [3. RAM Disk Copy] ---> [4. Physical Drive Ejection] ---> [5. Framebuffer UI]
 (1 second)          (Loads storage/VGA drivers)  (Copies 315MB squashfs    (Unmounts USB / disk;          (Subzero Vault Menu
                                                   into volatile tmpfs)      zero write-persistence)        boots on /dev/fb0)
```

1. **Step 1 (UEFI Hand-off)**: GRUB executes kernel `vmlinuz-lts` and `initramfs-lts`.
2. **Step 2 (Driver Probing)**: Probes SCSI, AHCI, NVMe, USB, and DRM GPU drivers.
3. **Step 3 (The RAM Copy Phase — ~20s)**:
   - Reads the entire compressed 315MB `rootfs.squashfs` OS image from the physical flash drive and copies it into a volatile `tmpfs` RAM disk (`/media/ram`).
   - *Why this is necessary*: Allows the physical USB flash drive to be completely unmounted before any sensitive key derivation begins, guaranteeing 100% amnesic execution.
4. **Step 4 (Drive Ejection & Chroot)**: Unmounts `/media/efi` physical storage, mounts overlay on RAM tmpfs, and executes `switch_root /sysroot /sbin/init`.
5. **Step 5 (Framebuffer Launch)**: OpenRC initializes `/dev/fb0` and launches Subzero Vault directly on `tty1`.

---

## 2. Visual Progress Feedback Added

To eliminate user uncertainty during the 20–30s RAM copy phase:

- The bootloader outputs active progress indicators directly to the screen:
  ```text
  ========================================================
      [+] SUBZERO KEYOSK // AIRGAPPED BOOTLOADER [+]     
  ========================================================
  [1/4] Initializing hardware drivers... [OK]
  [2/4] Scanning storage devices for SubZero payload... [FOUND: /dev/sda1]
  [3/4] Copying OS payload to volatile RAM disk (toram)................. [100% COMPLETE]
  [4/4] Storage unmounted. Launching Framebuffer Keyosk...
  ========================================================
   >> SUCCESS: OS RUNNING ENTIRELY FROM VOLATILE RAM <<
  ========================================================
  ```
- While `cp` runs in the background, a heartbeat loop emits continuous dots (`. . . . . .`) every 800ms so the user has immediate visual confirmation that the system is actively transferring the image into RAM.
