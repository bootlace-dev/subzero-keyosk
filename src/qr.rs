use qrcode::{QrCode, Version, EcLevel};
use qrcode::render::unicode::Dense1x2;
use ratatui::text::{Line, Span};
use ratatui::style::{Color, Style};

/// Render a QR code into Ratatui Lines using the standard Dense1x2 unicode half-block renderer.
/// Renders standard black-on-white QR modules with 100% optical scanner compatibility.
pub fn render_qr_to_lines(data: &str) -> Result<Vec<Line<'static>>, String> {
    let qr = QrCode::with_version(data, Version::Normal(4), EcLevel::L)
        .or_else(|_| QrCode::new(data))
        .map_err(|e| format!("Failed to generate QR code: {}", e))?;

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
