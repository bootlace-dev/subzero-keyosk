//! Console Framebuffer QR Renderer (`crates/subzero-tui/src/qr_tui.rs`).
//!
//! Renders QR matrices from `subzero_core::qr_codec::encode_qr_matrix` using reverse-video
//! two-space blocks (`"  "` with `Color::Black` / `Color::White` background). Using pure ASCII
//! spaces rather than Unicode half-blocks (`▀`/`▄`) guarantees 100% glyph-alignment fidelity
//! across bare-metal Linux `fbcon` fonts (`ter-v12n.psf.gz`) without missing-glyph boxes.

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use subzero_core::error::SubZeroError;
use subzero_core::qr_codec::encode_qr_matrix;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiQrMode {
    BbqrAnimated,
    StaticWpkh,
    StaticVpub,
    StaticTaproot,
}

impl TuiQrMode {
    pub const ALL: [TuiQrMode; 4] = [
        TuiQrMode::BbqrAnimated,
        TuiQrMode::StaticWpkh,
        TuiQrMode::StaticVpub,
        TuiQrMode::StaticTaproot,
    ];

    pub fn title(&self) -> &'static str {
        match self {
            Self::BbqrAnimated => "Mode 1: Animated Coinkite BBQr Descriptor (~2.5 Hz)",
            Self::StaticWpkh => "Mode 2: Static BIP-84 Descriptor (wpkh)",
            Self::StaticVpub => "Mode 3: Static SLIP-0132 vpub (Electrum / Green)",
            Self::StaticTaproot => "Mode 4: Static BIP-86 Taproot Descriptor (tr)",
        }
    }

    pub fn next(&self) -> Self {
        let idx = Self::ALL.iter().position(|m| m == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }
}

pub fn render_console_qr_lines(data: &str) -> Result<Vec<Line<'static>>, SubZeroError> {
    let mat = encode_qr_matrix(data)?;
    let w = mat.width;
    let quiet = 2usize;
    let total_w = w + quiet * 2;
    let mut lines = Vec::with_capacity(w + quiet * 2);

    for _ in 0..quiet {
        lines.push(Line::from(Span::styled(
            "  ".repeat(total_w),
            Style::default().bg(Color::White),
        )));
    }

    for y in 0..w {
        let mut spans = Vec::new();
        spans.push(Span::styled(
            "  ".repeat(quiet),
            Style::default().bg(Color::White),
        ));

        let mut cur_dark = mat.modules[y * w];
        let mut run_spaces = 0usize;
        for x in 0..w {
            let dark = mat.modules[y * w + x];
            if dark == cur_dark {
                run_spaces += 2;
            } else {
                let bg = if cur_dark { Color::Black } else { Color::White };
                spans.push(Span::styled(" ".repeat(run_spaces), Style::default().bg(bg)));
                cur_dark = dark;
                run_spaces = 2;
            }
        }
        let bg = if cur_dark { Color::Black } else { Color::White };
        spans.push(Span::styled(" ".repeat(run_spaces), Style::default().bg(bg)));

        spans.push(Span::styled(
            "  ".repeat(quiet),
            Style::default().bg(Color::White),
        ));
        lines.push(Line::from(spans));
    }

    for _ in 0..quiet {
        lines.push(Line::from(Span::styled(
            "  ".repeat(total_w),
            Style::default().bg(Color::White),
        )));
    }

    Ok(lines)
}
