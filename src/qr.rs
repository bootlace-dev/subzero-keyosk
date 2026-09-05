use qrcode::{QrCode, Version, EcLevel, Color as QrColor};
use qrcode::render::unicode::Dense1x2;
use ratatui::text::{Line, Span};
use ratatui::style::{Color, Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrMode {
    BbqrAnimated,   // Multi-frame animated QR (small modules, works on legacy low-res screens)
    FullBlockSpace, // 2 horizontal spaces with background color (0 font glyph padding seams)
    CompactTpub,    // Plain account extended key (tpub...) only (smaller matrix)
    HalfBlockDense, // Unicode half-block Dense1x2
}

impl QrMode {
    pub const ALL: [QrMode; 4] = [
        QrMode::BbqrAnimated,
        QrMode::FullBlockSpace,
        QrMode::CompactTpub,
        QrMode::HalfBlockDense,
    ];

    pub fn title(&self) -> &'static str {
        match self {
            QrMode::BbqrAnimated => "Mode 1: BBQR Animated Frames (~2.5 Hz)",
            QrMode::FullBlockSpace => "Mode 2: Full-Block (Seamless Space Glyphs)",
            QrMode::CompactTpub => "Mode 3: Compact TPUB Only (Static)",
            QrMode::HalfBlockDense => "Mode 4: High-Density Half-Blocks (Dense1x2)",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            QrMode::BbqrAnimated => "Splits descriptor into rotating frames. Immune to console font gaps on legacy screens.",
            QrMode::FullBlockSpace => "Renders 1 module as 2 terminal spaces. Eliminates inter-cell font seams.",
            QrMode::CompactTpub => "Exports raw account tpub (~111 chars) in a single compact, high-contrast QR.",
            QrMode::HalfBlockDense => "Standard 1x2 half-block Unicode matrix. Requires edge-to-edge console font support.",
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

/// Render standard Dense1x2 half-block QR
pub fn render_half_block_qr(data: &str) -> Result<Vec<Line<'static>>, String> {
    let qr = QrCode::with_version(data, Version::Normal(4), EcLevel::L)
        .or_else(|_| QrCode::new(data))
        .map_err(|e| format!("Failed to generate QR: {}", e))?;

    let rendered = qr.render::<Dense1x2>()
        .quiet_zone(true)
        .build();

    let lines: Vec<Line<'static>> = rendered
        .lines()
        .map(|line| {
            Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(Color::Black).bg(Color::White),
            ))
        })
        .collect();

    Ok(lines)
}
