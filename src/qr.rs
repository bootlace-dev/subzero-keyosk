use qrcode::{QrCode, Version, EcLevel, Color as QrColor};
use ratatui::text::{Line, Span};
use ratatui::style::{Color, Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrMode {
    BbqrAnimated,   // Multi-frame animated QR (small modules, works on legacy low-res screens)
    FullBlockSpace, // 2 horizontal spaces with background color (0 font glyph padding seams)
    CompactVpub,    // Plain account extended key (SLIP-0132 vpub...) with full-block spaces
}

impl QrMode {
    pub const ALL: [QrMode; 3] = [
        QrMode::BbqrAnimated,
        QrMode::FullBlockSpace,
        QrMode::CompactVpub,
    ];

    pub fn title(&self) -> &'static str {
        match self {
            QrMode::BbqrAnimated => "Mode 1: BBQR Animated Descriptor (~2.5 Hz)",
            QrMode::FullBlockSpace => "Mode 2: Full-Block Descriptor (Watch-Only)",
            QrMode::CompactVpub => "Mode 3: BBQR Animated VPUB (Native SegWit BIP-84)",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            QrMode::BbqrAnimated => "Splits descriptor into rotating full-block frames. Zero font seams.",
            QrMode::FullBlockSpace => "Renders full descriptor as seamless terminal spaces. Zero inter-cell font seams.",
            QrMode::CompactVpub => "Splits SLIP-0132 vpub into rotating full-block frames. Zero font seams, fits all consoles.",
        }
    }

    pub fn next(&self) -> Self {
        let idx = Self::ALL.iter().position(|m| *m == *self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }
}

use bbqr::split::{Split, SplitOptions};
use bbqr::file_type::FileType;

/// Official BBQr frame encoder (Coinkite / SatoshiPortal specification)
pub fn create_bbqr_frames(payload: &str, min_parts: usize) -> Vec<String> {
    let mut opts = SplitOptions::default();
    opts.min_split_number = min_parts;
    match Split::try_from_data(payload.as_bytes(), FileType::UnicodeText, opts) {
        Ok(split) => split.parts,
        Err(_) => vec![payload.to_string()],
    }
}

/// Render a QR code into standard Windows 1-bit monochrome BMP bytes (zero third-party dependencies)
pub fn encode_qr_bmp(data: &str, scale: usize, quiet: usize) -> Result<Vec<u8>, String> {
    let qr = QrCode::with_error_correction_level(data, EcLevel::L)
        .or_else(|_| QrCode::new(data))
        .map_err(|e| format!("QR encoding failed: {e}"))?;

    let w = qr.width();
    let img_w = (w + quiet * 2) * scale;
    let img_h = img_w;

    let row_bytes = ((img_w + 31) / 32) * 4;
    let img_data_len = row_bytes * img_h;
    let file_size = 54 + 8 + img_data_len;

    let mut bmp = Vec::with_capacity(file_size);
    // 1. BMP Header (14 bytes)
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&(file_size as u32).to_le_bytes());
    bmp.extend_from_slice(&[0u8; 4]);
    bmp.extend_from_slice(&62u32.to_le_bytes());

    // 2. DIB Header (40 bytes)
    bmp.extend_from_slice(&40u32.to_le_bytes());
    bmp.extend_from_slice(&(img_w as i32).to_le_bytes());
    bmp.extend_from_slice(&(img_h as i32).to_le_bytes()); // Bottom-up storage
    bmp.extend_from_slice(&1u16.to_le_bytes());
    bmp.extend_from_slice(&1u16.to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes());
    bmp.extend_from_slice(&(img_data_len as u32).to_le_bytes());
    bmp.extend_from_slice(&2835u32.to_le_bytes());
    bmp.extend_from_slice(&2835u32.to_le_bytes());
    bmp.extend_from_slice(&2u32.to_le_bytes());
    bmp.extend_from_slice(&2u32.to_le_bytes());

    // 3. Color palette (Index 0 = Black, Index 1 = White)
    bmp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    bmp.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0x00]);

    // 4. Pixel rows (bottom-up)
    for py in (0..img_h).rev() {
        let mut row = vec![0u8; row_bytes];
        let qy = py / scale;
        for px in 0..img_w {
            let qx = px / scale;
            let is_white = if qx < quiet || qy < quiet || qx >= w + quiet || qy >= w + quiet {
                true
            } else {
                qr[(qx - quiet, qy - quiet)] == QrColor::Light
            };
            if is_white {
                let byte_idx = px / 8;
                let bit_idx = 7 - (px % 8);
                row[byte_idx] |= 1 << bit_idx;
            }
        }
        bmp.extend_from_slice(&row);
    }

    Ok(bmp)
}

/// Render full-block seamless QR using reverse-video space characters
pub fn render_full_block_qr(data: &str) -> Result<Vec<Line<'static>>, String> {
    let qr = QrCode::with_version(data, Version::Normal(4), EcLevel::L)
        .or_else(|_| QrCode::new(data))
        .map_err(|e| format!("Failed to generate QR: {}", e))?;

    let width = qr.width();
    let quiet = 2;
    let total_w = width + quiet * 2;

    let mut lines = Vec::new();
    // Top quiet zone (1 row)
    let quiet_line = Line::from(Span::styled(
        " ".repeat(total_w * 2),
        Style::default().bg(Color::White),
    ));
    lines.push(quiet_line.clone());

    for y in 0..width {
        let mut spans = Vec::new();
        // Left quiet zone
        spans.push(Span::styled(" ".repeat(quiet * 2), Style::default().bg(Color::White)));

        let mut current_dark = qr[(0, y)] == QrColor::Dark;
        let mut count = 0;

        for x in 0..width {
            let dark = qr[(x, y)] == QrColor::Dark;
            if dark == current_dark {
                count += 2;
            } else {
                let bg_col = if current_dark { Color::Black } else { Color::White };
                spans.push(Span::styled(" ".repeat(count), Style::default().bg(bg_col)));
                current_dark = dark;
                count = 2;
            }
        }
        let bg_col = if current_dark { Color::Black } else { Color::White };
        spans.push(Span::styled(" ".repeat(count), Style::default().bg(bg_col)));

        // Right quiet zone
        spans.push(Span::styled(" ".repeat(quiet * 2), Style::default().bg(Color::White)));
        lines.push(Line::from(spans));
    }

    // Bottom quiet zone
    lines.push(quiet_line);
    Ok(lines)
}

