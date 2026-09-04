use qrcode::{QrCode, Version, EcLevel};
use ratatui::text::{Line, Span};
use ratatui::style::{Color, Style};

/// Render a QR code into a vector of Ratatui Lines using Unicode half-blocks (▀, ▄, █, ' ')
/// Each character cell renders 2 vertical pixels (top half and bottom half).
pub fn render_qr_to_lines(data: &str) -> Result<Vec<Line<'static>>, String> {
    let qr = QrCode::with_version(data, Version::Normal(4), EcLevel::M)
        .or_else(|_| QrCode::new(data))
        .map_err(|e| format!("Failed to generate QR code: {}", e))?;

    let width = qr.width();
    let modules: Vec<bool> = qr.into_colors().into_iter().map(|c| c == qrcode::Color::Dark).collect();

    // Add quiet zone (border of 2 modules)
    let quiet_zone = 2;
    let total_width = width + 2 * quiet_zone;
    let total_height = total_width;

    let mut grid = vec![vec![false; total_width]; total_height];
    for y in 0..width {
        for x in 0..width {
            grid[y + quiet_zone][x + quiet_zone] = modules[y * width + x];
        }
    }

    let mut lines = Vec::new();
    
    let mut y = 0;
    while y < total_height {
        let mut row_spans = Vec::new();
        let mut current_text = String::new();

        for x in 0..total_width {
            let top = grid[y][x];
            let bottom = if y + 1 < total_height { grid[y + 1][x] } else { false };

            let ch = match (top, bottom) {
                (false, false) => '█',
                (true, true) => ' ',
                (true, false) => '▄',
                (false, true) => '▀',
            };
            current_text.push(ch);
        }

        row_spans.push(Span::styled(current_text, Style::default().fg(Color::White).bg(Color::Black)));
        lines.push(Line::from(row_spans));
        y += 2;
    }

    Ok(lines)
}
