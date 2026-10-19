//! The password/passphrase generator popup.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Padding, Paragraph, Wrap};

use super::{form, panel};
use crate::tui::generator::{GeneratorState, GeneratorTarget};
use crate::tui::{theme, widgets};

const LABEL_WIDTH: u16 = 18;

pub fn render(g: &GeneratorState, frame: &mut Frame<'_>, area: Rect) {
    let option_rows =
        u16::try_from(g.form.rows().iter().filter(|r| !r.hidden).count()).unwrap_or(u16::MAX);
    // Value (up to 3 lines), meter, blank, options, blank, hint; plus
    // padding and borders.
    let height = 3 + 1 + 1 + option_rows + 1 + 1 + 2 + 2;
    let popup = area.centered(Constraint::Max(72), Constraint::Length(height));
    frame.render_widget(Clear, popup);

    let title = match g.target {
        GeneratorTarget::Editor => "Generate password",
        GeneratorTarget::NewEntry => "Password generator",
    };
    let block = panel(title).padding(Padding::new(1, 1, 1, 1));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let [value, meter, _, options, _, hint] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(option_rows),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);

    // The value is shown in full: it's what the user is choosing. Long
    // ones wrap (passwords have no spaces, so wrap by character).
    let value_line = match &g.error {
        Some(error) => Line::styled(error.clone(), theme::ERROR),
        None => Line::styled(g.value.as_str(), theme::SECRET), // borrowed, not copied
    };
    frame.render_widget(Paragraph::new(value_line).wrap(Wrap { trim: false }), value);

    if let Some(strength) = g.strength {
        let spans = widgets::strength::meter(strength, Some(g.entropy_bits));
        frame.render_widget(Line::from(spans), meter);
    }

    form::render(&g.form, frame, options, LABEL_WIDTH);

    let use_it = match g.target {
        GeneratorTarget::Editor => "fills in the password",
        GeneratorTarget::NewEntry => "starts a new entry with it",
    };
    frame.render_widget(
        Line::from(vec![
            Span::styled("Enter", theme::KEY),
            Span::styled(
                format!(" {use_it} · changing an option regenerates"),
                theme::DIM,
            ),
        ]),
        hint,
    );
}
