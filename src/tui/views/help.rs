//! The help overlay (`?` or F1): every key for the current screen,
//! including the ones the footer had no room for.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph};

use super::panel;
use crate::tui::keymap::{self, Mode};
use crate::tui::theme;

pub fn render(mode: Mode, frame: &mut Frame<'_>, area: Rect) {
    let hints: Vec<_> = keymap::hints(mode, false).collect();
    let key_width = hints
        .iter()
        .map(|b| b.label.chars().count())
        .max()
        .unwrap_or(0);

    let lines: Vec<Line<'_>> = hints
        .iter()
        .map(|b| {
            Line::from(vec![
                Span::styled(format!(" {:<key_width$}  ", b.label), theme::KEY),
                Span::raw(b.description),
            ])
        })
        .collect();

    let height = u16::try_from(lines.len() + 2).unwrap_or(u16::MAX);
    let popup = area.centered(Constraint::Max(44), Constraint::Max(height));
    frame.render_widget(Clear, popup);
    frame.render_widget(Paragraph::new(lines).block(panel("Keys")), popup);
}
