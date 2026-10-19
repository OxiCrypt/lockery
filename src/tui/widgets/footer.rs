//! The key-hint bar at the bottom of every screen.
//!
//! Built entirely from the keymap, so it always matches what the keys do.
//! Hints are added in keymap order; any that don't fit in the space left
//! are skipped (they're all still in the help overlay). Footer hints use a
//! binding's `short` description when it has one. Room for the Help hint
//! itself is always kept, so there's always a way to find the others.

use ratatui::text::{Line, Span};

use crate::tui::keymap::{self, Action, Binding, Mode};
use crate::tui::theme;

/// Space between one hint and the next.
const GAP: &str = "  ";

/// Columns `binding` takes up, including the gap (or margin) before it.
fn cost(binding: &Binding) -> usize {
    GAP.len() + binding.label.chars().count() + 1 + text(binding).chars().count()
}

/// The description shown in the footer.
fn text(binding: &Binding) -> &'static str {
    binding.short.unwrap_or(binding.description)
}

/// The footer line for `mode`, at most `width` columns wide.
#[must_use]
pub fn footer(mode: Mode, width: u16) -> Line<'static> {
    // `cost` charges every hint a full gap, but the first one only gets a
    // one-column margin, hence the `+ 1`.
    let width = usize::from(width) + 1;
    let help = keymap::hints(mode, true).find(|b| b.action == Action::Help);
    let mut budget = width.saturating_sub(help.map_or(0, cost));

    let mut shown: Vec<&Binding> = Vec::new();
    for binding in keymap::hints(mode, true).filter(|b| b.action != Action::Help) {
        if cost(binding) > budget {
            continue;
        }
        budget -= cost(binding);
        shown.push(binding);
    }
    if let Some(help) = help.filter(|h| cost(h) <= width) {
        shown.push(help);
    }

    let mut spans = Vec::with_capacity(shown.len() * 3);
    for (i, b) in shown.into_iter().enumerate() {
        // The first hint gets a one-column margin instead of the full gap.
        spans.push(Span::raw(if i == 0 { " " } else { GAP }));
        spans.push(Span::styled(b.label, theme::KEY));
        spans.push(Span::styled(format!(" {}", text(b)), theme::HINT));
    }
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_text(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn shows_hints_for_the_mode() {
        let line = line_text(&footer(Mode::List, 200));
        assert!(line.contains("/ Search"), "{line}");
        assert!(line.contains("q Quit"), "{line}");
        assert!(!line.contains("Unlock"), "{line}");
    }

    #[test]
    fn main_list_and_detail_keys_fit_in_80_columns() {
        for (mode, keys) in [
            (
                Mode::List,
                &["Enter", "c", "/", "n", "e", "d", "L", "q", "?"][..],
            ),
            (
                Mode::Detail,
                &["Esc", "c", "u", "e", "d", "Space", "L", "q", "?"][..],
            ),
        ] {
            let line = line_text(&footer(mode, 80));
            for key in keys {
                assert!(
                    line.contains(&format!("{key} ")),
                    "{mode:?} lacks {key}: {line}"
                );
            }
        }
    }

    #[test]
    fn help_hint_survives_narrow_terminals() {
        let line = line_text(&footer(Mode::List, 30));
        assert!(line.ends_with("? Help"), "{line}");
        let line = line_text(&footer(Mode::Edit, 20));
        assert!(line.ends_with("F1 Help"), "{line}");
    }

    #[test]
    fn never_exceeds_the_width() {
        for mode in Mode::ALL {
            for width in [0, 5, 10, 30, 80] {
                let line = line_text(&footer(mode, width));
                assert!(
                    line.chars().count() <= usize::from(width),
                    "{mode:?} at {width}: {line}"
                );
            }
        }
    }
}
