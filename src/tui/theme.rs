//! Colours and text styles, in one place.
//!
//! Only the basic 16 ANSI colours are used, so Lockery follows the user's
//! terminal theme (light or dark) instead of fighting it.

use ratatui::style::{Color, Modifier, Style};

/// Key names in hints.
pub const KEY: Style = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);
/// Descriptions in hints.
pub const HINT: Style = Style::new();
/// The app name in the header.
pub const TITLE: Style = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);
/// Secondary text: field labels, counts, placeholders.
pub const DIM: Style = Style::new().add_modifier(Modifier::DIM);
/// The selected row in a list.
pub const SELECTED: Style = Style::new().add_modifier(Modifier::REVERSED);
/// Masked or revealed secret values.
pub const SECRET: Style = Style::new().fg(Color::Yellow);
pub const ERROR: Style = Style::new().fg(Color::Red).add_modifier(Modifier::BOLD);
pub const WARNING: Style = Style::new().fg(Color::Yellow);
pub const INFO: Style = Style::new().fg(Color::Green);
/// Borders of panels and popups.
pub const BORDER: Style = Style::new().fg(Color::DarkGray);
