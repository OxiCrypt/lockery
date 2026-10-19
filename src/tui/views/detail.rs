//! One entry, field by field. Secrets are masked until Space is pressed.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Padding, Paragraph, Wrap};

use super::{MASK, panel};
use crate::tui::app::{App, UnlockedState};
use crate::tui::theme;
use crate::vault::EntryKind;

/// Width of the label column.
const LABEL_WIDTH: usize = 11;

pub fn render(app: &App, u: &UnlockedState, frame: &mut Frame<'_>, area: Rect) {
    let (Some(entry), Some(detail)) = (u.detail_entry(), &u.detail) else {
        return;
    };
    let reveal = detail.reveal;
    let secret = |value: &str| -> Span<'static> {
        if reveal {
            Span::styled(value.to_owned(), theme::SECRET)
        } else {
            Span::styled(MASK, theme::SECRET)
        }
    };

    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut field = |label: &str, value: Span<'static>| {
        lines.push(Line::from(vec![
            Span::styled(format!("{label:<LABEL_WIDTH$}"), theme::DIM),
            value,
        ]));
    };

    let kind = match entry.kind {
        EntryKind::Login => "Login",
        EntryKind::Note => "Secure note",
    };
    field("Type", Span::raw(kind));
    if !entry.username.is_empty() {
        field("Username", Span::raw(entry.username.clone()));
    }
    if !entry.password.is_empty() {
        field("Password", secret(&entry.password));
    }
    for (i, url) in entry.urls.iter().enumerate() {
        field(if i == 0 { "URL" } else { "" }, Span::raw(url.clone()));
    }
    if !entry.totp.is_empty() {
        field("TOTP", secret(&entry.totp));
    }
    if !entry.tags.is_empty() {
        field("Tags", Span::raw(entry.tags.join(", ")));
    }
    for f in &entry.custom_fields {
        let value = if f.hidden {
            secret(&f.value)
        } else {
            Span::raw(f.value.clone())
        };
        field(&f.name, value);
    }
    let when = |ts: jiff::Timestamp| {
        ts.to_zoned(app.tz.clone())
            .strftime("%Y-%m-%d %H:%M")
            .to_string()
    };
    field("Created", Span::styled(when(entry.created), theme::DIM));
    field("Modified", Span::styled(when(entry.modified), theme::DIM));

    if !entry.notes.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled("Notes", theme::DIM));
        lines.extend(entry.notes.lines().map(|l| Line::raw(l.to_owned())));
    }

    let title = if entry.favorite {
        format!("★ {}", entry.title)
    } else {
        entry.title.clone()
    };
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel(&title).padding(Padding::horizontal(1))),
        area,
    );
}
