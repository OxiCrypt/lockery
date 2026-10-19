//! Top-level layout: header, the current screen, status line and footer,
//! plus the help overlay on top when it's open.
//!
//! ```text
//! ┌ header: app name · vault · entry count ┐
//! │                                        │
//! │            current screen              │
//! │                                        │
//! ├ status message (if any)                ┤
//! └ key hints                              ┘
//! ```

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::app::{App, Screen, StatusKind};
use super::views;
use super::{theme, widgets};

/// Draw the whole app into `frame`.
pub fn render(app: &App, frame: &mut Frame<'_>) {
    let [header, body, status, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    frame.render_widget(header_line(app), header);

    match &app.screen {
        Screen::Picker(p) => {
            views::picker::render(app, p, frame, body);
            if let Some(dialog) = &p.dialog {
                views::dialog::render(dialog, app.busy_message(), frame, body);
            }
        }
        Screen::Unlock(u) => views::unlock::render(u, app.busy_message(), frame, body),
        Screen::Unlocked(u) => {
            match (&u.editor, &u.detail) {
                (Some(editor), _) => views::edit::render(u, editor, frame, body),
                (None, Some(_)) => views::detail::render(app, u, frame, body),
                (None, None) => views::list::render(app, u, frame, body),
            }
            if let Some(generator) = &u.generator {
                views::generator::render(generator, frame, body);
            }
        }
    }

    if let Some(confirm) = &app.confirm {
        widgets::confirm::render(&confirm.question, frame, body);
    }

    if let Some(s) = &app.status {
        let style = match s.kind {
            StatusKind::Info => theme::INFO,
            StatusKind::Warning => theme::WARNING,
            StatusKind::Error => theme::ERROR,
        };
        frame.render_widget(
            Paragraph::new(Line::styled(format!(" {}", s.text), style)),
            status,
        );
    }

    frame.render_widget(widgets::footer::footer(app.mode(), footer.width), footer);

    if app.help_open {
        views::help::render(app.base_mode(), frame, body);
    }
}

/// " Lockery · work · 12 entries" / " Lockery · work · locked"
fn header_line(app: &App) -> Line<'static> {
    let mut spans = vec![Span::styled(" Lockery", theme::TITLE)];
    let mut push = |text: String| {
        spans.push(Span::styled(" · ", theme::DIM));
        spans.push(Span::raw(text));
    };
    match &app.screen {
        Screen::Picker(_) => push("choose a vault".into()),
        Screen::Unlock(u) => push(format!("{} · locked", u.target.label)),
        Screen::Unlocked(u) => {
            let n = u.vault.entries().len();
            push(format!(
                "{} · {n} {}",
                u.target.label,
                if n == 1 { "entry" } else { "entries" }
            ));
        }
    }
    Line::from(spans)
}
