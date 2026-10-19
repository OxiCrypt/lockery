//! The entry list, with the search line on top while filtering.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState};

use super::panel;
use crate::tui::app::{App, UnlockedState};
use crate::tui::theme;

pub fn render(app: &App, u: &UnlockedState, frame: &mut Frame<'_>, area: Rect) {
    let show_search = u.searching || !u.query.is_empty();
    let [search, list] = Layout::vertical([
        Constraint::Length(u16::from(show_search)),
        Constraint::Min(0),
    ])
    .areas(area);

    if show_search {
        let line = Line::from(vec![
            Span::styled(" / ", theme::KEY),
            Span::raw(u.query.clone()),
        ]);
        frame.render_widget(Paragraph::new(line), search);
        if u.searching {
            let x = search.x + 3 + u16::try_from(u.query.chars().count()).unwrap_or(0);
            frame.set_cursor_position(Position::new(
                x.min(search.right().saturating_sub(1)),
                search.y,
            ));
        }
    }

    let block = panel("Entries");
    if u.filtered.is_empty() {
        let message = if u.vault.entries().is_empty() {
            "This vault is empty.".to_owned()
        } else {
            format!("No entries match “{}”.", u.query)
        };
        frame.render_widget(
            Paragraph::new(Line::styled(message, theme::DIM)).block(block),
            list,
        );
        return;
    }

    let entries = u.vault.entries();
    let rows = u.filtered.iter().map(|&i| {
        let e = &entries[i];
        let title = if e.favorite {
            format!("★ {}", e.title)
        } else {
            e.title.clone()
        };
        Row::new([
            Cell::from(title),
            Cell::from(e.username.clone()),
            Cell::from(e.urls.first().cloned().unwrap_or_default()).style(theme::DIM),
        ])
    });
    let header = Row::new(["Title", "Username", "URL"]).style(theme::DIM);
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(40),
            Constraint::Percentage(30),
            Constraint::Percentage(30),
        ],
    )
    .header(header)
    .block(block)
    .row_highlight_style(theme::SELECTED)
    .highlight_symbol("› ");

    // Rows that fit: the panel's inner height minus the header row.
    app.list_height
        .set(usize::from(list.height.saturating_sub(3)));
    let mut state = TableState::default()
        .with_offset(u.scroll.get())
        .with_selected(Some(u.selected));
    frame.render_stateful_widget(table, list, &mut state);
    u.scroll.set(state.offset());
}
