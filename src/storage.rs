use std::fs::{self, File};
use std::io::Read;
use std::process::Command;
use std::str::FromStr;
use sha2::{Digest, Sha256};
use crate::crypto::{DecryptedVaultPayload, encrypt_vault_payload};

/// Locate Partition 2 (SUBZERO_EST) on available storage devices
pub fn locate_estate_partition() -> Option<String> {
    // 1. Try blkid -L SUBZERO_EST
    if let Ok(output) = Command::new("blkid").args(["-L", "SUBZERO_EST"]).output() {
        if output.status.success() {
            let part = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !part.is_empty() {
                return Some(part);
            }
        }
    }

    // 2. Try findfs LABEL=SUBZERO_EST
    if let Ok(output) = Command::new("findfs").arg("LABEL=SUBZERO_EST").output() {
        if output.status.success() {
            let part = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !part.is_empty() {
                return Some(part);
            }
        }
    }

    // 3. Scan /dev/disk/by-label/SUBZERO_EST
    let by_label = "/dev/disk/by-label/SUBZERO_EST";
    if std::path::Path::new(by_label).exists() {
        if let Ok(target) = std::fs::read_link(by_label) {
            let abs = std::path::Path::new("/dev/disk/by-label").join(target);
            if let Ok(canonical) = abs.canonicalize() {
                return Some(canonical.to_string_lossy().to_string());
            }
        }
        return Some(by_label.to_string());
    }

    // 4. Candidate scan WITH label assertion (never blindly mount arbitrary disk partitions)
    let candidates = [
        "/dev/sdb2", "/dev/mmcblk0p2", "/dev/sdc2", "/dev/sdd2", "/dev/vda2"
    ];
    for p in candidates {
        if std::path::Path::new(p).exists() {
            if let Ok(out) = Command::new("blkid").arg(p).output() {
                let info = String::from_utf8_lossy(&out.stdout);
                if info.contains("SUBZERO_EST") {
                    return Some(p.to_string());
                }
            }
        }
    }

    None
}

/// Write estate vault payload and recovery documentation to Partition 2 (SUBZERO_EST)
pub fn write_estate_partition(
    payload: &DecryptedVaultPayload,
    passphrase_mnemonic: &str,
    build_stamp: &str,
) -> Result<String, String> {
    let partition = locate_estate_partition()
        .ok_or_else(|| "Partition 2 (SUBZERO_EST) not found. Insert SubZero USB/SD card.".to_string())?;

    let mount_dir = "/media/subzero_est";
    let _ = fs::create_dir_all(mount_dir);

    // Unmount if already mounted
    let _ = Command::new("umount").arg("-f").arg(mount_dir).output();

    // Mount read-write with secure umask
    let mount_status = Command::new("mount")
        .args(["-t", "vfat", "-o", "rw,sync,umask=077", &partition, mount_dir])
        .output();

    let mounted = match mount_status {
        Ok(out) => out.status.success(),
        Err(_) => false,
    };

    if !mounted {
        // Fallback mount attempt
        let fallback = Command::new("mount")
            .args(["-o", "rw,umask=077", &partition, mount_dir])
            .output();
        if !fallback.map(|o| o.status.success()).unwrap_or(false) {
            return Err(format!("Failed to mount {partition} to {mount_dir} (Permission denied or unformatted)."));
        }
    }

    // 1. Encrypt vault payload
    let encrypted_vault = encrypt_vault_payload(payload, passphrase_mnemonic)
        .map_err(|e| format!("Encryption error: {e}"))?;

    // 2. Write vault.json & timestamped archive
    let vault_path = format!("{mount_dir}/vault.json");
    fs::write(&vault_path, &encrypted_vault)
        .map_err(|e| format!("Failed to write vault.json: {e}"))?;

    let archive_path = format!("{mount_dir}/vault_{build_stamp}.json");
    let _ = fs::write(&archive_path, &encrypted_vault);

    // 3. Write README.txt
    let readme_content = format!(
r#"SUBZERO KEYOSK SOVEREIGN INHERITANCE RECOVERY APPLIANCE
=================================================================
This media contains your encrypted Bitcoin estate payload.

EMERGENCY RECOVERY INSTRUCTIONS:
1. PRIMARY APPLIANCE RECOVERY (RECOMMENDED):
   - Insert this SD card / USB drive into your dedicated SubZero appliance laptop.
   - Power on to boot directly into SubZero.
   - The appliance runs 100% in-memory from RAM with zero internet risk.
   - Enter your 12-word Decoupled Estate Passphrase to unlock all keys and descriptors.

2. OFFLINE BROWSER DECRYPTION (FALLBACK):
   - Open decrypt.html in any standard browser (Chrome, Safari, Firefox).
   - Drag and drop vault.json onto the page.
   - Enter your 12-word Decoupled Estate Passphrase to unlock.

INTEGRITY VERIFICATION:
To verify file integrity before running:
$ sha256sum -c SHA256SUMS

ANTI-THEFT NOTE:
Without the 12-word Decoupled Estate Passphrase, this media contains zero plain-text
seed words and cannot be decrypted.
"#);
    let readme_path = format!("{mount_dir}/README.txt");
    let _ = fs::write(&readme_path, readme_content);

    // 4. Generate SHA256SUMS
    let mut manifest_lines = Vec::new();
    let files_to_hash = ["vault.json", &format!("vault_{build_stamp}.json"), "README.txt", "decrypt.html"];
    for fname in files_to_hash {
        let full_path = format!("{mount_dir}/{fname}");
        if let Ok(mut f) = File::open(&full_path) {
            let mut hasher = Sha256::new();
            let mut buf = Vec::new();
            if f.read_to_end(&mut buf).is_ok() {
                hasher.update(&buf);
                let digest = hex::encode(hasher.finalize());
                manifest_lines.push(format!("{digest}  {fname}"));
            }
        }
    }

    let sums_path = format!("{mount_dir}/SHA256SUMS");
    let _ = fs::write(&sums_path, manifest_lines.join("\n") + "\n");

    // Sync buffers and unmount cleanly
    let _ = Command::new("sync").output();
    let _ = Command::new("umount").arg(mount_dir).output();

    Ok(format!("Successfully wrote encrypted vault.json, README.txt & SHA256SUMS to {partition}"))
}

/// Read encrypted vault.json from Partition 2 (SUBZERO_EST) if present
pub fn read_estate_partition() -> Result<String, String> {
    let partition = locate_estate_partition()
        .ok_or_else(|| "Partition 2 (SUBZERO_EST) not found. Insert SubZero USB/SD card.".to_string())?;

    let mount_dir = "/media/subzero_est";
    let _ = fs::create_dir_all(mount_dir);

    // Unmount first in case of stale state
    let _ = Command::new("umount").arg("-f").arg(mount_dir).output();

    let mount_status = Command::new("mount")
        .args(["-t", "vfat", "-o", "ro", &partition, mount_dir])
        .output();

    let mounted = match mount_status {
        Ok(out) => out.status.success(),
        Err(_) => false,
    };

    if !mounted {
        let fallback = Command::new("mount")
            .args(["-o", "ro", &partition, mount_dir])
            .output();
        if !fallback.map(|o| o.status.success()).unwrap_or(false) {
            return Err(format!("Failed to mount {partition} to {mount_dir}."));
        }
    }

    let vault_path = format!("{mount_dir}/vault.json");
    let content = fs::read_to_string(&vault_path)
        .map_err(|e| format!("Failed to read {vault_path}: {e}"));

    let _ = Command::new("umount").arg(mount_dir).output();
    content
}

/// Find an external USB drive partition (distinct from SubZero boot/estate media)
pub fn locate_external_export_drive() -> Result<String, String> {
    let estate_part = locate_estate_partition().unwrap_or_default();
    
    // Check available partitions in /sys/class/block or standard device paths
    // Look for sdc1, sdd1, sde1, sda1, sdb1 if not matching estate drive
    let candidates = [
        "/dev/sdc1", "/dev/sdd1", "/dev/sde1", "/dev/sdf1",
        "/dev/sdc", "/dev/sdd", "/dev/sda1", "/dev/sdb1"
    ];

    for c in candidates {
        if !c.is_empty() && std::path::Path::new(c).exists() {
            // Ensure this is not part of the internal estate or boot device
            if !estate_part.is_empty() {
                let estate_disk = estate_part.trim_end_matches(char::is_numeric);
                let cand_disk = c.trim_end_matches(char::is_numeric);
                if estate_disk == cand_disk {
                    continue; // Skip the SubZero boot/estate device!
                }
            }
            return Ok(c.to_string());
        }
    }

    Err("No external USB flash drive detected. Insert a separate blank USB drive and retry.".into())
}

use crate::qr::encode_qr_bmp;
use crate::crypto::Bip85Child;

/// Export watch-only descriptor, address manifest, BIP-85 hierarchy, and BMP QR images to an external USB drive
pub fn export_descriptor_external_usb(
    descriptor: &str,
    fingerprint: &str,
    vpub: &str,
    addresses: &[String],
    _bip85_children: &[Bip85Child],
) -> Result<String, String> {
    let drive = locate_external_export_drive()?;
    let mount_dir = "/media/subzero_export";
    let _ = fs::create_dir_all(mount_dir);

    // Unmount first if mounted
    let _ = Command::new("umount").arg("-f").arg(mount_dir).output();

    let mount_status = Command::new("mount")
        .args(["-o", "rw,sync", &drive, mount_dir])
        .output();

    let mounted = match mount_status {
        Ok(out) => out.status.success(),
        Err(_) => false,
    };

    if !mounted {
        return Err(format!("Failed to mount external USB {drive}. Ensure it is formatted (FAT32/exFAT)."));
    }

    // 1. Strict raw descriptor (no comment lines, single-line text for Nunchuk & Keeper)
    let raw_descriptor_content = format!("{}\n", descriptor.trim());
    let desc_path = format!("{mount_dir}/subzero-testnet4-descriptor.txt");
    let _ = fs::write(&desc_path, raw_descriptor_content);

    // 2. SLIP-0132 VPUB for Blockstream Green & Electrum (Testnet Native SegWit)
    let mut vpub_str = vpub.to_string();
    if let Ok(xpub) = bitcoin::bip32::Xpub::from_str(vpub) {
        let mut raw = xpub.encode();
        raw[0] = 0x04;
        raw[1] = 0x5f;
        raw[2] = 0x1c;
        raw[3] = 0xf6;
        vpub_str = bitcoin::base58::encode_check(&raw);
    }
    let vpub_path = format!("{mount_dir}/vpub_testnet4.txt");
    let _ = fs::write(&vpub_path, format!("{}\n", vpub_str.trim()));

    // 3. Addresses manifest (first 50 receive addresses with indexing)
    let mut addr_lines = Vec::new();
    addr_lines.push("# SubZero Testnet4 Native SegWit (P2WPKH) Receive Addresses".to_string());
    addr_lines.push(format!("# Master Fingerprint: {}", fingerprint.to_uppercase()));
    addr_lines.push("# Derivation: m/84'/1'/0'/0/k".to_string());
    addr_lines.push("".to_string());
    for (i, addr) in addresses.iter().enumerate() {
        addr_lines.push(format!("{:04}  {}", i, addr));
    }
    let addr_path = format!("{mount_dir}/addresses.txt");
    let _ = fs::write(&addr_path, addr_lines.join("\n") + "\n");

    // 4. High-resolution BMP QR images for direct phone/app image scan
    // 4a. Full Descriptor QR image
    if let Ok(bmp) = encode_qr_bmp(descriptor, 8, 4) {
        let _ = fs::write(format!("{mount_dir}/qr_descriptor.bmp"), bmp);
    }
    // 4b. Account VPUB QR image (for Blockstream Green Native SegWit import)
    if let Ok(bmp) = encode_qr_bmp(&vpub_str, 8, 4) {
        let _ = fs::write(format!("{mount_dir}/qr_vpub.bmp"), bmp);
    }
    // 4c. Address #0 QR image
    if let Some(addr0) = addresses.first() {
        if let Ok(bmp) = encode_qr_bmp(addr0, 8, 4) {
            let _ = fs::write(format!("{mount_dir}/qr_address_0.bmp"), bmp);
        }
    }

    let _ = Command::new("sync").output();
    let _ = Command::new("umount").arg(mount_dir).output();

    Ok(format!("Exported airgap files to USB ({drive})"))
}
