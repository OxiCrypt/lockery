//! A yes/no question in a small popup.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph, Wrap};

use crate::tui::theme;

pub fn render(question: &str, frame: &mut Frame<'_>, area: Rect) {
    let popup = area.centered(Constraint::Max(56), Constraint::Length(6));
    frame.render_widget(Clear, popup);
    let block = Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::WARNING)
        .title(" Confirm ")
        .padding(Padding::horizontal(1));
    let text = vec![
        Line::raw(question.to_owned()),
        Line::raw(""),
        Line::from(vec![
            Span::styled("y", theme::KEY),
            Span::raw(" yes   "),
            Span::styled("n", theme::KEY),
            Span::raw(" no"),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: false }).block(block),
        popup,
    );
}
