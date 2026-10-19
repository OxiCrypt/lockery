//! The unlock screen: master password entry for one vault.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::panel;
use crate::tui::app::UnlockState;
use crate::tui::theme;

/// Width of the visible part of the password field.
const FIELD_WIDTH: usize = 36;

pub fn render(u: &UnlockState, busy: Option<&str>, frame: &mut Frame<'_>, area: Rect) {
    // 6 content rows + 1 blank row above and below + 2 border rows.
    let area = area.centered(Constraint::Max(50), Constraint::Length(10));
    let block = panel("Unlock");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [vault, _, label, field, _, message] = Layout::vertical([Constraint::Length(1); 6])
        .horizontal_margin(2)
        .areas(inner.inner(ratatui::layout::Margin::new(0, 1)));

    frame.render_widget(
        Line::from(vec![
            Span::styled("Vault  ", theme::DIM),
            Span::raw(&u.target.label),
        ]),
        vault,
    );
    frame.render_widget(Line::styled("Master password", theme::DIM), label);

    // One bullet per character, so typing gives feedback; Ctrl-r shows the
    // real text. Only the tail is shown if it's longer than the field.
    // The revealed text is a borrowed slice of the (wiped-on-drop) input, never
    // a copy: a copy would be freed unwiped after every frame.
    let chars = u.input.chars().count();
    let skip = chars.saturating_sub(FIELD_WIDTH);
    let visible_chars = chars - skip;
    let visible = if u.reveal {
        let start = u.input.char_indices().nth(skip).map_or(0, |(i, _)| i);
        Span::styled(&u.input[start..], theme::SECRET)
    } else {
        Span::styled("•".repeat(visible_chars), theme::SECRET)
    };
    let cursor_x = field.x + u16::try_from(visible_chars).unwrap_or(0);
    frame.render_widget(Paragraph::new(visible), field);

    let note = if let Some(busy) = busy {
        Some(Line::styled(busy.to_owned(), theme::INFO))
    } else {
        u.error
            .as_deref()
            .map(|e| Line::styled(e.to_owned(), theme::ERROR))
    };
    if let Some(note) = note {
        frame.render_widget(note, message);
    }
    if busy.is_none() {
        frame.set_cursor_position(Position::new(cursor_x, field.y));
    }
}
