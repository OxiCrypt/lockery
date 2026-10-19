//! A four-segment strength meter, e.g. `███░ strong · ≈ 77 bits`.

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

use crate::generator::Strength;
use crate::tui::theme;

/// The meter for `strength`, optionally followed by an entropy estimate.
#[must_use]
pub fn meter(strength: Strength, entropy_bits: Option<f64>) -> Vec<Span<'static>> {
    let filled = usize::from(strength.score.min(4));
    let color = match strength.score {
        0 | 1 => Color::Red,
        2 => Color::Yellow,
        _ => Color::Green,
    };
    let mut spans = vec![
        Span::styled("█".repeat(filled), Style::new().fg(color)),
        Span::styled("░".repeat(4 - filled), theme::DIM),
        Span::raw(format!(" {}", strength.label())),
    ];
    if let Some(bits) = entropy_bits {
        spans.push(Span::styled(format!(" · ≈ {bits:.0} bits"), theme::DIM));
    }
    spans
}

/// A labelled meter line, e.g. for under a password field.
#[must_use]
pub fn line(label: &str, strength: Strength) -> Line<'static> {
    let mut spans = vec![Span::styled(format!("{label} "), theme::DIM)];
    spans.extend(meter(strength, None));
    Line::from(spans)
}
