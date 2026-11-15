//! Optical Airgap Codec: Coinkite `BBQr`, Pure-Rust SVG/BMP/Matrix QR, & Adaptive `rqrr` Decoder.
//!
//! WHY ADAPTIVE BRADLEY-ROTH THRESHOLDING (`ISSUE #4` FIX):
//! Standard global Otsu thresholding (`rqrr` default) struggles when scanning animated QR codes
//! off glossy phone/laptop screens or stamped metal plates under uneven overhead lighting/glare.
//! `decode_qr_luma` runs fast standard `rqrr` first and automatically falls back to an O(W*H)
//! integral-image local Bradley-Roth adaptive binarizer + inverted polarity pass when needed.

use std::collections::BTreeSet;

use bbqr::continuous_join::{ContinuousJoinResult, ContinuousJoiner};
use bbqr::file_type::FileType;
use bbqr::qr::Version as BbqrVersion;
use bbqr::split::{Split, SplitOptions};
use qrcode::{Color as QrColor, EcLevel, QrCode};
use serde::{Deserialize, Serialize};

use crate::error::SubZeroError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrMatrix {
    pub width: usize,
    /// Row-major `width * width` booleans (`true` = dark module, `false` = light module).
    pub modules: Vec<bool>,
}

pub fn encode_qr_matrix(data: &str) -> Result<QrMatrix, SubZeroError> {
    let qr = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::L)
        .or_else(|_| QrCode::new(data.as_bytes()))
        .map_err(|e| SubZeroError::Qr(format!("QR encode failed: {e}")))?;
    let w = qr.width();
    let mut modules = Vec::with_capacity(w * w);
    for y in 0..w {
        for x in 0..w {
            modules.push(qr[(x, y)] == QrColor::Dark);
        }
    }
    Ok(QrMatrix { width: w, modules })
}

/// Render crisp, zero-dependency SVG QR string with 4-module white quiet zone.
pub fn encode_qr_svg(data: &str) -> Result<String, SubZeroError> {
    let mat = encode_qr_matrix(data)?;
    let quiet = 4usize;
    let total = mat.width + quiet * 2;
    let mut path = String::with_capacity(mat.modules.len() * 12);
    for y in 0..mat.width {
        for x in 0..mat.width {
            if mat.modules[y * mat.width + x] {
                let sx = x + quiet;
                let sy = y + quiet;
                path.push_str(&format!("M{sx},{sy}h1v1h-1z"));
            }
        }
    }
    Ok(format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total} {total}" shape-rendering="crispEdges"><rect width="{total}" height="{total}" fill="#ffffff"/><path d="{path}" fill="#000000"/></svg>"##
    ))
}

/// Render 1-bit monochrome BMP bytes (for hardware thermal printers or offline image tests).
pub fn encode_qr_bmp(data: &str, scale: usize, quiet: usize) -> Result<Vec<u8>, SubZeroError> {
    let mat = encode_qr_matrix(data)?;
    let s = scale.max(1);
    let w = mat.width;
    let img_w = (w + quiet * 2) * s;
    let img_h = img_w;
    let row_bytes = img_w.div_ceil(32) * 4;
    let img_data_len = row_bytes * img_h;
    let file_size = 62 + img_data_len;

    let mut bmp = Vec::with_capacity(file_size);
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&(file_size as u32).to_le_bytes());
    bmp.extend_from_slice(&[0u8; 4]);
    bmp.extend_from_slice(&62u32.to_le_bytes());

    bmp.extend_from_slice(&40u32.to_le_bytes());
    bmp.extend_from_slice(&(img_w as i32).to_le_bytes());
    bmp.extend_from_slice(&(img_h as i32).to_le_bytes());
    bmp.extend_from_slice(&1u16.to_le_bytes());
    bmp.extend_from_slice(&1u16.to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes());
    bmp.extend_from_slice(&(img_data_len as u32).to_le_bytes());
    bmp.extend_from_slice(&2835u32.to_le_bytes());
    bmp.extend_from_slice(&2835u32.to_le_bytes());
    bmp.extend_from_slice(&2u32.to_le_bytes());
    bmp.extend_from_slice(&2u32.to_le_bytes());

    bmp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    bmp.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0x00]);

    for py in (0..img_h).rev() {
        let mut row = vec![0u8; row_bytes];
        let qy = py / s;
        for px in 0..img_w {
            let qx = px / s;
            let is_white = if qx < quiet || qy < quiet || qx >= w + quiet || qy >= w + quiet {
                true
            } else {
                !mat.modules[(qy - quiet) * w + (qx - quiet)]
            };
            if is_white {
                row[px / 8] |= 1 << (7 - (px % 8));
            }
        }
        bmp.extend_from_slice(&row);
    }
    Ok(bmp)
}

/// Split Unicode text (descriptors, JSON) into official Coinkite `BBQr` frames (`B$...`).
pub fn encode_bbqr_unicode(text: &str, min_parts: usize) -> Result<Vec<String>, SubZeroError> {
    let mut opts = SplitOptions::default();
    opts.min_split_number = min_parts.max(1);
    opts.max_version = BbqrVersion::V14;
    let split = Split::try_from_data(text.as_bytes(), FileType::UnicodeText, opts)
        .map_err(|e| SubZeroError::Qr(format!("BBQr split failed: {e:?}")))?;
    Ok(split.parts)
}

/// Split binary PSBT bytes into official Coinkite `BBQr` `FileType::Psbt` frames (`B$...`).
pub fn encode_bbqr_psbt(psbt_bytes: &[u8], min_parts: usize) -> Result<Vec<String>, SubZeroError> {
    let mut opts = SplitOptions::default();
    opts.min_split_number = min_parts.max(1);
    opts.max_version = BbqrVersion::V14;
    let split = Split::try_from_data(psbt_bytes, FileType::Psbt, opts)
        .map_err(|e| SubZeroError::Qr(format!("BBQr PSBT split failed: {e:?}")))?;
    Ok(split.parts)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScannedAirgapPayload {
    InProgress {
        parts_received: usize,
        parts_total: usize,
    },
    CompleteText(String),
    CompleteBinary(Vec<u8>),
}

/// Parse the 8-character Coinkite `BBQr` frame header `B$<enc><ft><total_b36:2><seq_b36:2>`.
fn parse_bbqr_header(s: &str) -> Result<(char, char, usize, usize), SubZeroError> {
    if s.len() < 8 || !s.starts_with("B$") {
        return Err(SubZeroError::Qr("Malformed BBQr frame header (too short).".into()));
    }
    let bytes = s.as_bytes();
    let enc = bytes[2] as char;
    let ft = bytes[3] as char;
    let total_str = core::str::from_utf8(&bytes[4..6])
        .map_err(|_| SubZeroError::Qr("Invalid ASCII in BBQr frame count.".into()))?;
    let seq_str = core::str::from_utf8(&bytes[6..8])
        .map_err(|_| SubZeroError::Qr("Invalid ASCII in BBQr sequence index.".into()))?;
    let total = usize::from_str_radix(total_str, 36)
        .map_err(|_| SubZeroError::Qr("Invalid Base36 total in BBQr header.".into()))?;
    let seq = usize::from_str_radix(seq_str, 36)
        .map_err(|_| SubZeroError::Qr("Invalid Base36 sequence index in BBQr header.".into()))?;
    if total == 0 || seq >= total {
        return Err(SubZeroError::Qr(format!(
            "Invalid BBQr frame index ({seq}/{total})."
        )));
    }
    Ok((enc, ft, total, seq))
}

/// Stateful assembler for single-frame QR strings OR multi-part animated Coinkite `BBQr` streams.
pub struct AirgapQrAssembler {
    joiner: ContinuousJoiner,
    seen_frames: BTreeSet<String>,
    seen_seq_indices: BTreeSet<usize>,
    active_stream_meta: Option<(char, char, usize)>,
}

impl Default for AirgapQrAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl AirgapQrAssembler {
    pub fn new() -> Self {
        Self {
            joiner: ContinuousJoiner::new(),
            seen_frames: BTreeSet::new(),
            seen_seq_indices: BTreeSet::new(),
            active_stream_meta: None,
        }
    }

    pub fn reset(&mut self) {
        self.joiner = ContinuousJoiner::new();
        self.seen_frames.clear();
        self.seen_seq_indices.clear();
        self.active_stream_meta = None;
    }

    pub fn ingest_qr_string(&mut self, qr_text: &str) -> Result<ScannedAirgapPayload, SubZeroError> {
        let trimmed = qr_text.trim();
        if trimmed.is_empty() {
            return Err(SubZeroError::Qr("Empty QR payload.".into()));
        }

        if trimmed.starts_with("B$") {
            let (enc, ft, total, seq) = parse_bbqr_header(trimmed)?;

            // Deduplicate identical animated frames without advancing counters or re-feeding joiner
            if self.seen_frames.contains(trimmed) {
                return Ok(ScannedAirgapPayload::InProgress {
                    parts_received: self.seen_frames.len(),
                    parts_total: total,
                });
            }

            // Guard against cross-stream frame splicing (`[L-09]` / `[M-03]` fix)
            if let Some(prev_meta) = self.active_stream_meta {
                if prev_meta != (enc, ft, total) || self.seen_seq_indices.contains(&seq) {
                    self.reset();
                    return Err(SubZeroError::Qr(
                        "Conflicting BBQr stream frame detected mid-scan; scanner reset to prevent splice."
                            .into(),
                    ));
                }
            } else {
                self.active_stream_meta = Some((enc, ft, total));
            }

            match self.joiner.add_part(trimmed.to_string()) {
                Ok(ContinuousJoinResult::NotStarted) => Ok(ScannedAirgapPayload::InProgress {
                    parts_received: 0,
                    parts_total: total,
                }),
                Ok(ContinuousJoinResult::InProgress { parts_left }) => {
                    self.seen_frames.insert(trimmed.to_string());
                    self.seen_seq_indices.insert(seq);
                    Ok(ScannedAirgapPayload::InProgress {
                        parts_received: self.seen_frames.len(),
                        parts_total: self.seen_frames.len() + parts_left,
                    })
                }
                Ok(ContinuousJoinResult::Complete(joined)) => {
                    self.reset();
                    match joined.file_type {
                        FileType::UnicodeText | FileType::Json => {
                            let s = String::from_utf8(joined.data).map_err(|e| {
                                SubZeroError::Qr(format!("Invalid UTF-8 in BBQr text: {e}"))
                            })?;
                            Ok(ScannedAirgapPayload::CompleteText(s))
                        }
                        _ => Ok(ScannedAirgapPayload::CompleteBinary(joined.data)),
                    }
                }
                Err(e) => {
                    self.reset();
                    Err(SubZeroError::Qr(format!("BBQr frame assembly error: {e}")))
                }
            }
        } else {
            if self.active_stream_meta.is_some() {
                self.reset();
                return Err(SubZeroError::Qr(
                    "Non-BBQr QR code scanned while multi-part BBQr assembly was in progress; scanner reset."
                        .into(),
                ));
            }
            Ok(ScannedAirgapPayload::CompleteText(trimmed.to_string()))
        }
    }
}

fn try_rqrr_luma(width: usize, height: usize, luma: &[u8]) -> Option<String> {
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| {
        luma[y * width + x]
    });
    for grid in img.detect_grids() {
        if let Ok((_meta, content)) = grid.decode() {
            if !content.trim().is_empty() {
                return Some(content);
            }
        }
    }
    None
}

/// Bradley-Roth integral-image local adaptive binarizer (`O(W*H)`).
/// Handles screen glare, uneven room shadows, and low-contrast etched SeedQR plates.
fn bradley_roth_binarize(width: usize, height: usize, luma: &[u8], t_pct: u64) -> Vec<u8> {
    let mut integral = vec![0u64; (width + 1) * (height + 1)];
    let stride = width + 1;
    for y in 0..height {
        let mut row_sum = 0u64;
        for x in 0..width {
            row_sum += luma[y * width + x] as u64;
            integral[(y + 1) * stride + (x + 1)] = integral[y * stride + (x + 1)] + row_sum;
        }
    }

    let s = (width.min(height) / 16).max(4);
    let mut out = vec![255u8; width * height];
    for y in 0..height {
        let y1 = y.saturating_sub(s);
        let y2 = (y + s + 1).min(height);
        for x in 0..width {
            let x1 = x.saturating_sub(s);
            let x2 = (x + s + 1).min(width);
            let count = ((x2 - x1) * (y2 - y1)) as u64;
            let sum = integral[y2 * stride + x2] + integral[y1 * stride + x1]
                - integral[y1 * stride + x2]
                - integral[y2 * stride + x1];
            let px = (luma[y * width + x] as u64) * count * 100;
            if px <= sum * (100 - t_pct) {
                out[y * width + x] = 0;
            }
        }
    }
    out
}

/// Decode a QR string from an 8-bit greyscale frame (`width * height` bytes), falling back to
/// Bradley-Roth local adaptive thresholding and dark-mode polarity inversion if needed.
pub fn decode_qr_luma(width: usize, height: usize, luma: &[u8]) -> Result<Option<String>, SubZeroError> {
    if width < 21 || height < 21 || width > 4096 || height > 4096 {
        return Err(SubZeroError::Qr("Invalid image dimensions for QR scan.".into()));
    }
    if luma.len() != width * height {
        return Err(SubZeroError::Qr("Luma buffer length mismatch.".into()));
    }

    // Pass 1: Fast native rqrr detector
    if let Some(hit) = try_rqrr_luma(width, height, luma) {
        return Ok(Some(hit));
    }

    // Pass 2: Bradley-Roth local adaptive threshold (15% glare tolerance)
    let bin = bradley_roth_binarize(width, height, luma, 15);
    if let Some(hit) = try_rqrr_luma(width, height, &bin) {
        return Ok(Some(hit));
    }

    // Pass 3: Dark-mode / inverted QR fallback
    let inv: Vec<u8> = luma.iter().map(|&v| 255u8.wrapping_sub(v)).collect();
    if let Some(hit) = try_rqrr_luma(width, height, &inv) {
        return Ok(Some(hit));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bbqr_split_join_and_glare_qr_decode_roundtrip() {
        let payload = "wpkh([73c5da0a/84'/1'/0']tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)#26729v5h";
        let parts = encode_bbqr_unicode(payload, 3).unwrap();
        assert!(parts.len() >= 3);
        assert!(parts[0].starts_with("B$"));

        let mut asm = AirgapQrAssembler::new();
        // Re-scanning part[0] 3 times MUST NOT inflate parts_total!
        let p0_first = asm.ingest_qr_string(&parts[0]).unwrap();
        let p0_dup = asm.ingest_qr_string(&parts[0]).unwrap();
        assert_eq!(
            format!("{p0_first:?}"),
            format!("{p0_dup:?}"),
            "Duplicate BBQr frame must be deduplicated cleanly!"
        );

        // Cross-stream splice (`part[1]` from an unrelated stream) MUST reset & error!
        let other_parts = encode_bbqr_unicode("tr(tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)", parts.len()).unwrap();
        assert!(asm.ingest_qr_string(&other_parts[1]).is_err());

        let mut recovered = None;
        for part in &parts {
            if let ScannedAirgapPayload::CompleteText(s) = asm.ingest_qr_string(part).unwrap() {
                recovered = Some(s);
            }
        }
        assert_eq!(recovered.as_deref(), Some(payload));

        // Render part[0] into synthetic uneven-lighting greyscale frame with a simulated glare gradient
        let mat = encode_qr_matrix(&parts[0]).unwrap();
        let scale = 6usize;
        let quiet = 4usize;
        let dim = (mat.width + quiet * 2) * scale;
        let mut luma = vec![0u8; dim * dim];
        for py in 0..dim {
            for px in 0..dim {
                let qx = px / scale;
                let qy = py / scale;
                let is_dark = if qx >= quiet
                    && qy >= quiet
                    && qx < mat.width + quiet
                    && qy < mat.width + quiet
                {
                    mat.modules[(qy - quiet) * mat.width + (qx - quiet)]
                } else {
                    false
                };
                // Simulate strong diagonal lighting gradient across the screen
                let base_bg = 130 + ((px + py) * 110 / (2 * dim)) as u8;
                luma[py * dim + px] = if is_dark { base_bg / 4 } else { base_bg };
            }
        }

        let decoded = decode_qr_luma(dim, dim, &luma).unwrap();
        assert_eq!(decoded.as_deref(), Some(parts[0].as_str()));
    }
}
