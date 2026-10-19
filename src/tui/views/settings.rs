//! The vault settings screen, full screen.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Padding;

use super::{form, panel};
use crate::crypto;
use crate::tui::app::UnlockedState;
use crate::tui::settings::SettingsState;
use crate::tui::theme;

const LABEL_WIDTH: u16 = 20;

pub fn render(
    u: &UnlockedState,
    settings: &SettingsState,
    busy: Option<&str>,
    frame: &mut Frame<'_>,
    area: Rect,
) {
    let block = panel("Vault settings").padding(Padding::new(1, 1, 1, 0));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = u16::try_from(settings.form.rows().len()).unwrap_or(u16::MAX);
    let [vault, now, _, fields, _, message, _, note] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(rows),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(2),
    ])
    .areas(inner);

    let label = |text: &str| Span::styled(format!("{text:<10}"), theme::DIM);
    frame.render_widget(
        Line::from(vec![label("Vault"), Span::raw(u.target.label.clone())]),
        vault,
    );
    frame.render_widget(
        Line::from(vec![
            label("Now"),
            Span::raw(crypto::describe(u.vault.cipher(), u.vault.kdf())),
        ]),
        now,
    );

    form::render(&settings.form, frame, fields, LABEL_WIDTH);

    let message_line = match (busy, &settings.error) {
        (Some(busy), _) => Line::styled(busy.to_owned(), theme::INFO),
        (None, Some(error)) => Line::styled(error.clone(), theme::ERROR),
        (None, None) => Line::default(),
    };
    frame.render_widget(message_line, message);

    frame.render_widget(
        ratatui::widgets::Paragraph::new(vec![
            Line::styled(
                "Applying re-encrypts the vault and its backup. More memory and passes make",
                theme::DIM,
            ),
            Line::styled(
                "guessing your password slower, and unlocking slower too.",
                theme::DIM,
            ),
        ]),
        note,
    );
}
