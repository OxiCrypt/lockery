//! The add/edit entry form, full screen.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::Padding;

use super::{form, panel};
use crate::tui::app::{Editor, UnlockedState};
use crate::tui::{theme, widgets};

/// Width of the label column ("Field name" plus the focus marker).
const LABEL_WIDTH: u16 = 14;

pub fn render(u: &UnlockedState, editor: &Editor, frame: &mut Frame<'_>, area: Rect) {
    let title = match editor.id.and_then(|id| u.vault.entry(id)) {
        Some(entry) => format!("Edit “{}”", entry.title),
        None => "New entry".to_owned(),
    };
    let block = panel(&title).padding(Padding::horizontal(1));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [rows, strength, tip] = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);
    form::render(&editor.form, frame, rows, LABEL_WIDTH);

    // Live strength of the password, worked out when it changes (see
    // `Editor::strength`), not here on every frame.
    if let Some(score) = editor.strength {
        frame.render_widget(
            widgets::strength::line("Password strength", score),
            strength,
        );
    }

    frame.render_widget(
        Line::styled(
            "Space/←→ change toggles and choices · Enter on a button presses it",
            theme::DIM,
        ),
        tip,
    );
}
