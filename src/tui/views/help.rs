//! The help overlay (`?` or F1): every key for the current screen,
//! including the ones the footer had no room for. Splits into two columns
//! when there are more keys than fit in one.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph};

use super::panel;
use crate::tui::keymap::{self, Binding, Mode};
use crate::tui::theme;

/// Width of one column of hints.
const COLUMN_WIDTH: u16 = 40;

pub fn render(mode: Mode, frame: &mut Frame<'_>, area: Rect) {
    let hints: Vec<&Binding> = keymap::hints(mode, false).collect();
    let key_width = hints
        .iter()
        .map(|b| b.label.chars().count())
        .max()
        .unwrap_or(0);

    // Rows that fit: the popup's two border lines, plus a line of margin
    // above and below so it never sits on the screen's own borders.
    let room = usize::from(area.height.saturating_sub(4)).max(1);
    let columns: u16 = if hints.len() > room { 2 } else { 1 };
    let per_column = hints.len().div_ceil(usize::from(columns));

    let height = u16::try_from(per_column + 2).unwrap_or(u16::MAX);
    let width = COLUMN_WIDTH * columns + 2;
    let popup = area.centered(Constraint::Max(width), Constraint::Max(height));
    frame.render_widget(Clear, popup);
    let block = panel("Keys");
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let areas = Layout::horizontal(vec![
        Constraint::Ratio(1, u32::from(columns));
        usize::from(columns)
    ])
    .split(inner);
    for (chunk, column) in hints.chunks(per_column.max(1)).zip(areas.iter()) {
        let lines: Vec<Line<'_>> = chunk
            .iter()
            .map(|b| {
                Line::from(vec![
                    Span::styled(format!(" {:<key_width$}  ", b.label), theme::KEY),
                    Span::raw(b.description),
                ])
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), *column);
    }
}
