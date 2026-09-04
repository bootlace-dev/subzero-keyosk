use std::fs::{self, File};
use std::io::Read;
use std::process::Command;
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

    // 2. Scan standard device paths for partition 2
    let candidates = [
        "/dev/sdb2", "/dev/mmcblk0p2", "/dev/sdc2", "/dev/sdd2", "/dev/vda2", "/dev/sda2"
    ];
    for p in candidates {
        if std::path::Path::new(p).exists() {
            return Some(p.to_string());
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

    // Mount read-write
    let mount_status = Command::new("mount")
        .args(["-t", "vfat", "-o", "rw,sync,umask=000", &partition, mount_dir])
        .output();

    let mounted = match mount_status {
        Ok(out) => out.status.success(),
        Err(_) => false,
    };

    if !mounted {
        // Fallback mount attempt
        let fallback = Command::new("mount")
            .args(["-o", "rw", &partition, mount_dir])
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
