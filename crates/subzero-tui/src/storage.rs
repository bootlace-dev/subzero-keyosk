//! Hardware Optical Scanner (`v4l2-ctl` + `decode_qr_luma` / `zbarcam`) & Partition 2 (`SUBZERO_EST`) VFAT-Safe Estate Writer.
//!
//! WHY ATOMIC WRITE-FSYNC-RENAME + PURE-RUST V4L2 QR DECODING (`[M-05]` & `[L-07]` FIXES):
//! 1. Zero Unverified Binary Blobs: On the Alpine bare-metal appliance, official APK-signed
//!    `v4l2-ctl` streams uncompressed `640x480` `YUYV` frames directly into pure-Rust
//!    `subzero_core::qr_codec::decode_qr_luma` (including the Bradley-Roth glare adaptive
//!    thresholding pass) and `AirgapQrAssembler`, falling back to `zbarcam` on desktop systems.
//! 2. Partition 2 (`SUBZERO_EST`) VFAT Safety: Restricts backup stamps to `[A-Za-z0-9_-]`, avoids
//!    overwriting prior archive snapshots, and uses `atomic_write_vfat` (`.tmp` -> `fsync` -> `rename`).

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use sha2::{Digest, Sha256};
use subzero_core::qr_codec::{decode_qr_luma, AirgapQrAssembler, ScannedAirgapPayload};
use subzero_core::vault::{decrypt_vault_json, encrypt_vault_payload, DecryptedVaultPayload};

const EMBEDDED_DECRYPT_HTML: &str = include_str!("../../../assets/decrypt.html");

#[derive(Debug, Clone)]
pub enum CameraEvent {
    Progress { received: usize, total: usize },
    CompleteText(String),
    CompleteBinary(Vec<u8>),
    Diagnostic(String),
    FatalError(String),
}

pub struct CameraScanner {
    child: Option<Child>,
    pub receiver: Receiver<CameraEvent>,
    pub device_path: String,
}

fn forward_assembled_qr(
    assembler: &mut AirgapQrAssembler,
    qr_str: &str,
    tx_out: &Sender<CameraEvent>,
) -> bool {
    match assembler.ingest_qr_string(qr_str) {
        Ok(ScannedAirgapPayload::InProgress {
            parts_received,
            parts_total,
        }) => {
            let _ = tx_out.send(CameraEvent::Progress {
                received: parts_received,
                total: parts_total,
            });
            false
        }
        Ok(ScannedAirgapPayload::CompleteText(s)) => {
            let _ = tx_out.send(CameraEvent::CompleteText(s));
            true
        }
        Ok(ScannedAirgapPayload::CompleteBinary(b)) => {
            let _ = tx_out.send(CameraEvent::CompleteBinary(b));
            true
        }
        Err(e) => {
            let _ = tx_out.send(CameraEvent::Diagnostic(e.to_string()));
            false
        }
    }
}

impl CameraScanner {
    pub fn spawn() -> Self {
        let (tx, rx) = mpsc::channel();
        let find_dev = || {
            (0..=9)
                .map(|i| format!("/dev/video{i}"))
                .find(|p| Path::new(p).exists())
        };

        let mut dev_opt = find_dev();
        if dev_opt.is_none() {
            let _ = Command::new("modprobe")
                .arg("uvcvideo")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = Command::new("mdev")
                .arg("-s")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            dev_opt = find_dev();
        }

        let Some(device_path) = dev_opt else {
            let _ = tx.send(CameraEvent::FatalError(
                "No V4L2 camera found (/dev/video0..9). Attach USB webcam or paste Base64/Hex."
                    .into(),
            ));
            return Self {
                child: None,
                receiver: rx,
                device_path: "/dev/video0".into(),
            };
        };

        // Primary path: APK-signed `v4l2-ctl` YUYV raw frame stream -> pure-Rust `decode_qr_luma`
        let mut v4l_cmd = Command::new("v4l2-ctl");
        v4l_cmd
            .args([
                "-d",
                &device_path,
                "--set-fmt-video=width=640,height=480,pixelformat=YUYV",
                "--stream-mmap",
                "--stream-to=-",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        if let Ok(mut c) = v4l_cmd.spawn() {
            if let Some(mut out) = c.stdout.take() {
                let tx_out = tx.clone();
                let dev_label = device_path.clone();
                thread::spawn(move || {
                    let _ = tx_out.send(CameraEvent::Diagnostic(format!(
                        "Streaming 640x480 YUYV on {dev_label} (Bradley-Roth glare decoder active)..."
                    )));
                    let mut assembler = AirgapQrAssembler::new();
                    let mut yuyv = vec![0u8; 640 * 480 * 2];
                    let mut luma = vec![0u8; 640 * 480];
                    while out.read_exact(&mut yuyv).is_ok() {
                        for (dst, src) in luma.iter_mut().zip(yuyv.iter().step_by(2)) {
                            *dst = *src;
                        }
                        if let Ok(Some(hit)) = decode_qr_luma(640, 480, &luma) {
                            if forward_assembled_qr(&mut assembler, &hit, &tx_out) {
                                break;
                            }
                        }
                    }
                });
            }
            return Self {
                child: Some(c),
                receiver: rx,
                device_path,
            };
        }

        // Secondary desktop fallback: `zbarcam` line stream
        let mut cmd = Command::new("zbarcam");
        cmd.args(["--raw", "--nodisplay", &device_path])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = match cmd.spawn() {
            Ok(mut c) => {
                if let Some(out) = c.stdout.take() {
                    let tx_out = tx.clone();
                    thread::spawn(move || {
                        let mut assembler = AirgapQrAssembler::new();
                        let reader = BufReader::new(out);
                        for line in reader.lines().map_while(Result::ok) {
                            let trimmed = line.trim();
                            if trimmed.is_empty() {
                                continue;
                            }
                            if forward_assembled_qr(&mut assembler, trimmed, &tx_out) {
                                break;
                            }
                        }
                    });
                }
                if let Some(err) = c.stderr.take() {
                    let tx_err = tx.clone();
                    thread::spawn(move || {
                        let reader = BufReader::new(err);
                        for line in reader.lines().map_while(Result::ok) {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() {
                                let _ = tx_err.send(CameraEvent::Diagnostic(trimmed.to_string()));
                            }
                        }
                    });
                }
                Some(c)
            }
            Err(e) => {
                let _ = tx.send(CameraEvent::FatalError(format!(
                    "Neither v4l2-ctl nor zbarcam available on {device_path}: {e}"
                )));
                None
            }
        };

        Self {
            child,
            receiver: rx,
            device_path,
        }
    }

    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for CameraScanner {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Sanitize a human/UTC timestamp into a strict VFAT-legal suffix (`[A-Za-z0-9_-]`, max 28 chars).
pub fn sanitize_vfat_stamp(raw: &str) -> String {
    let mut out = String::with_capacity(28);
    for ch in raw.chars() {
        if out.len() >= 28 {
            break;
        }
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else if ch == ':' || ch.is_whitespace() || ch == '.' {
            out.push('_');
        }
    }
    if out.is_empty() {
        "v2_snapshot".to_string()
    } else {
        out
    }
}

pub fn atomic_write_vfat(dir: &Path, filename: &str, contents: &[u8]) -> Result<(), String> {
    let tmp_path = dir.join(format!("{filename}.tmp"));
    let final_path = dir.join(filename);
    {
        let mut f = File::create(&tmp_path)
            .map_err(|e| format!("Failed creating {}: {e}", tmp_path.display()))?;
        f.write_all(contents)
            .map_err(|e| format!("Failed writing {}: {e}", tmp_path.display()))?;
        f.sync_all()
            .map_err(|e| format!("Failed fsync on {}: {e}", tmp_path.display()))?;
    }
    fs::rename(&tmp_path, &final_path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!("Failed renaming {} -> {}: {e}", tmp_path.display(), final_path.display())
    })?;
    Ok(())
}

pub struct MountGuard<'a> {
    mount_point: &'a str,
    unmounted: bool,
}

impl<'a> MountGuard<'a> {
    pub fn new(mount_point: &'a str) -> Self {
        Self {
            mount_point,
            unmounted: false,
        }
    }

    pub fn unmount(&mut self) {
        if !self.unmounted {
            let _ = Command::new("sync").output();
            let _ = Command::new("umount").arg(self.mount_point).output();
            self.unmounted = true;
        }
    }
}

impl Drop for MountGuard<'_> {
    fn drop(&mut self) {
        self.unmount();
    }
}

fn has_exact_estate_label(blkid_line: &str) -> bool {
    blkid_line.contains("LABEL=\"SUBZERO_EST\"") || blkid_line.contains("LABEL_FATBOOT=\"SUBZERO_EST\"")
}

pub fn locate_all_estate_partitions() -> Vec<String> {
    let mut parts = Vec::new();
    if let Ok(output) = Command::new("blkid").output() {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if has_exact_estate_label(line) {
                    if let Some(dev) = line.split(':').next() {
                        parts.push(dev.trim().to_string());
                    }
                }
            }
        }
    }
    for cand in ["/dev/sdb2", "/dev/mmcblk0p2", "/dev/sdc2", "/dev/sdd2", "/dev/vda2"] {
        if Path::new(cand).exists() {
            if let Ok(out) = Command::new("blkid").arg(cand).output() {
                if has_exact_estate_label(&String::from_utf8_lossy(&out.stdout)) {
                    parts.push(cand.to_string());
                }
            }
        }
    }
    parts.sort();
    parts.dedup();
    parts
}

pub fn resolve_unique_estate_partition() -> Result<String, String> {
    let parts = locate_all_estate_partitions();
    match parts.len() {
        0 => Err("Partition 2 (LABEL=SUBZERO_EST) not found. Insert SubZero USB/SD media.".into()),
        1 => Ok(parts[0].clone()),
        _ => Err(format!(
            "Multiple SUBZERO_EST partitions detected ({}). Remove duplicate drives before writing.",
            parts.join(", ")
        )),
    }
}

pub fn write_estate_bundle_to_dir(
    target_dir: &Path,
    payload: &DecryptedVaultPayload,
    passphrase_mnemonic: &str,
    raw_stamp: &str,
) -> Result<String, String> {
    let encrypted_json =
        encrypt_vault_payload(payload, passphrase_mnemonic).map_err(|e| e.to_string())?;
    let safe_stamp = sanitize_vfat_stamp(raw_stamp);
    let mut archive_name = format!("vault_{safe_stamp}.json");
    if target_dir.join(&archive_name).exists() {
        for seq in 1..=999u32 {
            let cand = format!("vault_{safe_stamp}_{seq:03}.json");
            if !target_dir.join(&cand).exists() {
                archive_name = cand;
                break;
            }
        }
    }

    let readme = "\
SUBZERO KEYOSK v2.0 - ENCRYPTED BITCOIN ESTATE RECOVERY MEDIA
=============================================================
This partition contains your SIV-committed AES-256-GCM encrypted estate vault
(`vault.json`, 600,000 PBKDF2-HMAC-SHA256 rounds) and standalone recovery app.

RECOVERY OPTIONS:
1. Bare-Metal SubZero Appliance (Recommended):
   Boot the SubZero USB/SD appliance into RAM (`toram` airgap), open Tab 6
   (Estate Storage), and enter your 12-word Decoupled Estate Passphrase.

2. Offline Browser Fallback (`decrypt.html`):
   On an offline machine (Wi-Fi / Bluetooth disabled), open `decrypt.html` in
   any modern browser (`file://`), load `vault.json`, and enter your 12-word
   Decoupled Estate Passphrase.

INTEGRITY CHECK:
  sha256sum -c SHA256SUMS
";

    atomic_write_vfat(target_dir, "vault.json", encrypted_json.as_bytes())?;
    atomic_write_vfat(target_dir, &archive_name, encrypted_json.as_bytes())?;
    atomic_write_vfat(target_dir, "decrypt.html", EMBEDDED_DECRYPT_HTML.as_bytes())?;
    atomic_write_vfat(target_dir, "README.txt", readme.as_bytes())?;

    let tracked = ["vault.json", archive_name.as_str(), "decrypt.html", "README.txt"];
    let mut sum_lines = Vec::with_capacity(tracked.len());
    for name in tracked {
        let p = target_dir.join(name);
        let mut f = File::open(&p).map_err(|e| format!("Failed opening {}: {e}", p.display()))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)
            .map_err(|e| format!("Failed reading {}: {e}", p.display()))?;
        let digest = hex::encode(Sha256::digest(&buf));
        sum_lines.push(format!("{digest}  {name}"));
    }
    let sums_body = sum_lines.join("\n") + "\n";
    atomic_write_vfat(target_dir, "SHA256SUMS", sums_body.as_bytes())?;

    Ok(format!(
        "Atomically wrote vault.json, {archive_name}, decrypt.html, README.txt & SHA256SUMS to {}",
        target_dir.display()
    ))
}

pub fn write_estate_partition(
    payload: &DecryptedVaultPayload,
    passphrase_mnemonic: &str,
    raw_stamp: &str,
) -> Result<String, String> {
    let part = resolve_unique_estate_partition()?;
    let mount_dir = "/media/subzero_est";
    fs::create_dir_all(mount_dir).map_err(|e| format!("mkdir {mount_dir} failed: {e}"))?;
    let _ = Command::new("umount").arg("-f").arg(mount_dir).output();

    let status = Command::new("mount")
        .args(["-t", "vfat", "-o", "rw,sync,umask=077", &part, mount_dir])
        .output()
        .map_err(|e| format!("mount command failed: {e}"))?;
    if !status.status.success() {
        return Err(format!(
            "Failed mounting {part} on {mount_dir}: {}",
            String::from_utf8_lossy(&status.stderr).trim()
        ));
    }

    let mut guard = MountGuard::new(mount_dir);
    let res = write_estate_bundle_to_dir(Path::new(mount_dir), payload, passphrase_mnemonic, raw_stamp);
    guard.unmount();
    res
}

pub fn read_and_unlock_estate_partition(
    passphrase_mnemonic: &str,
) -> Result<DecryptedVaultPayload, String> {
    let part = resolve_unique_estate_partition()?;
    let mount_dir = "/media/subzero_est";
    fs::create_dir_all(mount_dir).map_err(|e| format!("mkdir {mount_dir} failed: {e}"))?;
    let _ = Command::new("umount").arg("-f").arg(mount_dir).output();

    let status = Command::new("mount")
        .args(["-t", "vfat", "-o", "ro,umask=077", &part, mount_dir])
        .output()
        .map_err(|e| format!("mount command failed: {e}"))?;
    if !status.status.success() {
        return Err(format!(
            "Failed mounting {part} read-only on {mount_dir}: {}",
            String::from_utf8_lossy(&status.stderr).trim()
        ));
    }

    let mut guard = MountGuard::new(mount_dir);
    let vault_path = Path::new(mount_dir).join("vault.json");
    let raw_json = fs::read_to_string(&vault_path)
        .map_err(|e| format!("Failed reading {}: {e}", vault_path.display()))?;
    guard.unmount();

    decrypt_vault_json(&raw_json, passphrase_mnemonic).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use subzero_core::keys::{derive_bip85_children, load_rehearsal_preset};

    #[test]
    fn test_vfat_stamp_sanitization_and_atomic_estate_bundle_roundtrip() {
        assert_eq!(
            sanitize_vfat_stamp("2026-11-15T00:12:34Z"),
            "2026-11-15T00_12_34Z"
        );
        let dir = tempfile::tempdir().unwrap();
        let p0 = load_rehearsal_preset(0).unwrap();
        let children = derive_bip85_children(p0.mnemonic.as_deref().unwrap(), 2).unwrap();
        let pass = children[0].mnemonic.clone();
        let payload = DecryptedVaultPayload {
            version: "2.0.0-testnet4".into(),
            created_utc: "2026-11-15T00:12:34Z".into(),
            master_root_mnemonic: p0.mnemonic.clone().unwrap(),
            descriptor: p0.wpkh_descriptor.clone(),
            heir_treasuries: children[1..].to_vec(),
        };
        write_estate_bundle_to_dir(dir.path(), &payload, &pass, "2026-11-15T00:12:34Z").unwrap();
        assert!(dir.path().join("vault.json").exists());
        assert!(dir.path().join("vault_2026-11-15T00_12_34Z.json").exists());
        assert!(dir.path().join("decrypt.html").exists());
        assert!(dir.path().join("SHA256SUMS").exists());

        let raw_vault = fs::read_to_string(dir.path().join("vault.json")).unwrap();
        let dec = decrypt_vault_json(&raw_vault, &pass).unwrap();
        assert_eq!(dec.master_root_mnemonic, p0.mnemonic.clone().unwrap());
    }
}
