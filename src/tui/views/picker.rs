//! The vault picker: every vault in the data directory.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph, Wrap};

use super::panel;
use crate::tui::app::{App, PickerState};
use crate::tui::theme;

pub fn render(app: &App, p: &PickerState, frame: &mut Frame<'_>, area: Rect) {
    let area = area.centered(Constraint::Max(50), Constraint::Max(16));
    let block = panel("Vaults");

    if p.names.is_empty() {
        let text = vec![
            Line::raw("No vaults yet."),
            Line::raw(""),
            Line::from(vec![
                Span::raw("Quit and run "),
                Span::styled("lockery init", theme::KEY),
                Span::raw(" to create one."),
            ]),
            Line::raw(""),
            Line::styled(
                format!("Looked in {}", app.data_dir().display()),
                theme::DIM,
            ),
        ];
        frame.render_widget(
            Paragraph::new(text).wrap(Wrap { trim: false }).block(block),
            area,
        );
        return;
    }

    let primary = &app.config().primary_vault;
    let items = p.names.iter().map(|name| {
        let mut spans = vec![Span::raw(name.to_string())];
        if name.as_str() == primary {
            spans.push(Span::styled("  primary", theme::DIM));
        }
        ListItem::new(Line::from(spans))
    });
    let list = List::new(items)
        .block(block)
        .highlight_style(theme::SELECTED)
        .highlight_symbol("› ");
    let mut state = ListState::default().with_selected(Some(p.selected));
    frame.render_stateful_widget(list, area, &mut state);
}
