//! Popup forms over the vault picker: create, rename and delete a vault.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Clear, Padding};

use super::{form, panel};
use crate::tui::app::{DialogKind, VaultDialog};
use crate::tui::theme;

const LABEL_WIDTH: u16 = 19;

pub fn render(dialog: &VaultDialog, busy: Option<&str>, frame: &mut Frame<'_>, area: Rect) {
    let (title, note) = match &dialog.kind {
        DialogKind::Create => ("New vault".to_owned(), None),
        DialogKind::Rename(name) => (format!("Rename “{name}”"), None),
        DialogKind::Delete(name) => (
            format!("Delete “{name}”"),
            Some("Permanently deletes the vault and its backup."),
        ),
    };
    let field_rows = u16::try_from(dialog.form.rows().len()).unwrap_or(u16::MAX);
    // Fields, a blank line, a message line, padding and borders.
    let height = field_rows + 1 + 1 + 2 + 2 + u16::from(note.is_some()) * 2;
    let popup = area.centered(Constraint::Max(64), Constraint::Length(height));
    frame.render_widget(Clear, popup);

    let block = panel(&title).padding(Padding::new(1, 1, 1, 1));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let [note_area, _, fields, _, message] = Layout::vertical([
        Constraint::Length(u16::from(note.is_some())),
        Constraint::Length(u16::from(note.is_some())),
        Constraint::Length(field_rows),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);

    if let Some(note) = note {
        frame.render_widget(Line::styled(note, theme::WARNING), note_area);
    }
    form::render(&dialog.form, frame, fields, LABEL_WIDTH);

    let message_line = match (busy, &dialog.error) {
        (Some(busy), _) => Line::styled(busy.to_owned(), theme::INFO),
        (None, Some(error)) => Line::styled(error.clone(), theme::ERROR),
        (None, None) => Line::default(),
    };
    frame.render_widget(message_line, message);
}
