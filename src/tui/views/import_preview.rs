//! Reviewing a CSV file before importing: what was found, which entries
//! are duplicates, and any warnings.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Padding, Paragraph, Wrap};

use super::panel;
use crate::tui::theme;
use crate::tui::transfer::{ImportPreview, display_path};

pub fn render(p: &ImportPreview, frame: &mut Frame<'_>, area: Rect) {
    let block = panel("Import from CSV").padding(Padding::new(1, 1, 1, 0));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let duplicates = p.duplicate_count();
    let warning_lines = u16::try_from(p.warnings.len().min(5)).unwrap_or(5);
    let [summary, _, list, warnings] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(if p.warnings.is_empty() {
            0
        } else {
            warning_lines + 2
        }),
    ])
    .areas(inner);

    let label = |text: &str| Span::styled(format!("{text:<10}"), theme::DIM);
    let found = if duplicates > 0 {
        format!(
            "{} entries · {duplicates} already in this vault",
            p.entries.len()
        )
    } else {
        format!("{} entries", p.entries.len())
    };
    let mut lines = vec![
        Line::from(vec![label("File"), Span::raw(display_path(&p.source))]),
        Line::from(vec![label("Format"), Span::raw(p.format.name())]),
        Line::from(vec![label("Found"), Span::raw(found)]),
        Line::from(vec![
            label("Enter"),
            Span::raw(format!("imports {} entries", p.import_count())),
        ]),
    ];
    if duplicates > 0 {
        let mark = if p.include_duplicates { "[x]" } else { "[ ]" };
        lines.push(Line::from(vec![
            label(""),
            Span::raw(format!("{mark} also import the duplicates  ")),
            Span::styled("Space", theme::KEY),
        ]));
    }
    frame.render_widget(Paragraph::new(lines), summary);

    // One line per entry: ✓ will be imported, = duplicate being skipped.
    let height = usize::from(list.height);
    let rows: Vec<Line<'_>> = p
        .entries
        .iter()
        .enumerate()
        .skip(p.scroll)
        .take(height)
        .map(|(i, e)| {
            let (mark, style) = if p.will_import(i) {
                ("✓ ", theme::HINT)
            } else {
                ("= ", theme::DIM)
            };
            let mut spans = vec![
                Span::styled(mark, style),
                Span::styled(format!("{:<32}", e.title), style),
                Span::styled(e.username.clone(), theme::DIM),
            ];
            if p.duplicates[i] {
                spans.push(Span::styled("  (duplicate)", theme::DIM));
            }
            Line::from(spans)
        })
        .collect();
    frame.render_widget(Paragraph::new(rows), list);

    if !p.warnings.is_empty() {
        let mut lines = vec![Line::styled(
            match p.warnings.len() {
                1 => "1 warning".to_owned(),
                n => format!("{n} warnings"),
            },
            theme::WARNING,
        )];
        lines.extend(
            p.warnings
                .iter()
                .take(5)
                .map(|w| Line::styled(format!("! {w}"), theme::DIM)),
        );
        if p.warnings.len() > 5 {
            lines.push(Line::styled(
                format!("… and {} more", p.warnings.len() - 5),
                theme::DIM,
            ));
        }
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), warnings);
    }
}
