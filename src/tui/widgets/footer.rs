//! The key-hint bar at the bottom of every screen.
//!
//! Built entirely from the keymap, so it always matches what the keys do.
//! Hints are added in keymap order until the line is full; the rest are
//! dropped (they're all still listed in the `?` help overlay).

use ratatui::text::{Line, Span};

use crate::tui::keymap::{self, Mode};
use crate::tui::theme;

/// Space between one hint and the next.
const GAP: &str = "  ";

/// The footer line for `mode`, at most `width` columns wide.
#[must_use]
pub fn footer(mode: Mode, width: u16) -> Line<'static> {
    let width = usize::from(width);
    let mut spans = Vec::new();
    let mut used = 0;

    for (key, description) in keymap::hints(mode, true) {
        let gap = if spans.is_empty() { 1 } else { GAP.len() }; // 1 = left margin
        let cost = gap + key.chars().count() + 1 + description.chars().count();
        if used + cost > width {
            break;
        }
        spans.push(Span::raw(if spans.is_empty() { " " } else { GAP }));
        spans.push(Span::styled(key, theme::KEY));
        spans.push(Span::styled(format!(" {description}"), theme::HINT));
        used += cost;
    }
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn shows_hints_for_the_mode() {
        let line = text(&footer(Mode::List, 200));
        assert!(line.contains("/ Search"), "{line}");
        assert!(line.contains("q Quit"), "{line}");
        assert!(!line.contains("Unlock"), "{line}");
    }

    #[test]
    fn never_exceeds_the_width() {
        for mode in Mode::ALL {
            for width in [0, 10, 30, 80] {
                let line = text(&footer(mode, width));
                assert!(
                    line.chars().count() <= usize::from(width),
                    "{mode:?} at {width}: {line}"
                );
            }
        }
    }
}
