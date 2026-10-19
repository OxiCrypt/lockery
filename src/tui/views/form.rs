//! Drawing a [`Form`]: one row per line (multi-line fields get several),
//! label on the left, widget on the right, scrolled so the focused row is
//! always visible.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use crate::tui::form::{Form, Row, RowId, Widget};
use crate::tui::theme;

/// Screen lines a visible row takes.
fn height(row: &Row) -> u16 {
    match &row.widget {
        Widget::Text(field) if field.is_multiline() => {
            if row.id == RowId::Notes {
                6
            } else {
                3
            }
        }
        _ => 1,
    }
}

/// Draw the visible rows of `form` into `area`, with labels `label_width`
/// columns wide.
pub fn render(form: &Form, frame: &mut Frame<'_>, area: Rect, label_width: u16) {
    let visible: Vec<usize> = (0..form.rows().len())
        .filter(|&i| !form.rows()[i].hidden)
        .collect();
    let focus_pos = visible.iter().position(|&i| i == form.focus()).unwrap_or(0);

    // Scroll just enough to keep the focused row fully on screen.
    let mut first = form.scroll.get().min(focus_pos);
    let rows_height = |from: usize, to: usize| -> u16 {
        visible[from..=to]
            .iter()
            .map(|&i| height(&form.rows()[i]))
            .sum()
    };
    while first < focus_pos && rows_height(first, focus_pos) > area.height {
        first += 1;
    }
    form.scroll.set(first);

    let mut y = area.y;
    for &i in &visible[first..] {
        let row = &form.rows()[i];
        let h = height(row).min(area.bottom().saturating_sub(y));
        if h == 0 {
            break;
        }
        let focused = i == form.focus();
        let label_area = Rect::new(area.x, y, label_width.min(area.width), 1);
        let value_area = Rect::new(
            area.x + label_width.min(area.width),
            y,
            area.width.saturating_sub(label_width),
            h,
        );

        let marker = if focused { "› " } else { "  " };
        let label_style = if focused { theme::KEY } else { theme::DIM };
        frame.render_widget(
            Line::from(vec![
                Span::styled(marker, theme::KEY),
                Span::styled(row.label.clone(), label_style),
            ]),
            label_area,
        );

        match &row.widget {
            Widget::Text(field) => frame.render_widget(field.area(), value_area),
            Widget::Toggle(on) => {
                let text = if *on { "[x] yes" } else { "[ ] no" };
                frame.render_widget(Line::raw(text), value_area);
            }
            Widget::Choice { options, selected } => {
                let style = if focused {
                    theme::SELECTED
                } else {
                    theme::HINT
                };
                frame.render_widget(
                    Line::from(vec![
                        Span::styled("‹ ", theme::DIM),
                        Span::styled(options[*selected], style),
                        Span::styled(" ›", theme::DIM),
                    ]),
                    value_area,
                );
            }
            Widget::Number { value, .. } => {
                let style = if focused {
                    theme::SELECTED
                } else {
                    theme::HINT
                };
                frame.render_widget(
                    Line::from(vec![
                        Span::styled("‹ ", theme::DIM),
                        Span::styled(value.to_string(), style),
                        Span::styled(" ›", theme::DIM),
                    ]),
                    value_area,
                );
            }
            Widget::Button => {
                // Buttons span the whole row; the label is the button text.
                let style = if focused {
                    theme::SELECTED
                } else {
                    theme::KEY.remove_modifier(Modifier::BOLD)
                };
                let button_area = Rect::new(area.x + 2, y, area.width.saturating_sub(2), 1);
                frame.render_widget(Line::styled(row.label.clone(), style), button_area);
            }
        }
        y += h;
    }
}
