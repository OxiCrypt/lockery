//! One module per screen. Each exposes a `render` function that only reads
//! the app state.

pub mod detail;
pub mod dialog;
pub mod edit;
pub mod form;
pub mod generator;
pub mod help;
pub mod list;
pub mod picker;
pub mod settings;
pub mod unlock;

use ratatui::style::Style;
use ratatui::widgets::{Block, BorderType, Borders};

use super::theme;

/// The standard bordered panel with a title.
pub(super) fn panel(title: &str) -> Block<'_> {
    Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::BORDER)
        .title(format!(" {title} "))
        .title_style(Style::new())
}

/// Placeholder shown instead of a secret value.
pub(super) const MASK: &str = "••••••••";
