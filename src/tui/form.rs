//! A generic keyboard-driven form: a vertical list of labelled rows.
//!
//! Used by the entry editor and the vault dialogs. Each row holds one
//! widget: a text field (single- or multi-line, optionally secret), an
//! on/off toggle, a choice between a few options, or a button.
//!
//! Focus moves with Tab / Shift-Tab (handled by the app through the
//! keymap); every other key goes to the focused row via [`Form::input`].
//!
//! Text fields wrap `ratatui_textarea::TextArea`, which stores plain
//! `String`s. [`TextField`] wipes them when dropped, and secret fields keep
//! no undo history, so typed passwords don't linger in memory after the
//! form closes.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::Style;
use ratatui_textarea::{CursorMove, TextArea};
use zeroize::Zeroize;

use super::theme;

/// Character shown instead of each character of a masked secret.
const MASK_CHAR: char = '•';

/// Identifies a row, so callers can read values back without caring about
/// positions (rows can be hidden or inserted).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowId {
    // Entry editor
    Kind,
    Title,
    Username,
    Password,
    Urls,
    Totp,
    Tags,
    Favorite,
    CustomName(usize),
    CustomValue(usize),
    CustomHidden(usize),
    AddCustom,
    Notes,
    // Vault dialogs
    VaultName,
    NewPassword,
    RepeatPassword,
    Cipher,
    MasterPassword,
    ConfirmName,
}

/// A text field that wipes its contents on drop.
pub struct TextField {
    area: TextArea<'static>,
    multiline: bool,
    secret: bool,
}

impl TextField {
    #[must_use]
    pub fn new(text: &str, multiline: bool, secret: bool) -> Self {
        let lines: Vec<String> = if text.is_empty() {
            vec![String::new()]
        } else {
            text.lines().map(str::to_owned).collect()
        };
        let mut area = TextArea::new(lines);
        if secret {
            // Undo history would keep old copies of the secret around.
            area.set_max_histories(0);
        }
        area.set_cursor_line_style(Style::new());
        if !multiline {
            // Single-line fields: ready to append. Multi-line ones start at
            // the top, so their first lines are what's visible.
            area.move_cursor(CursorMove::End);
        }
        Self {
            area,
            multiline,
            secret,
        }
    }

    /// Current contents; lines are joined with `\n`.
    #[must_use]
    pub fn text(&self) -> String {
        self.area.lines().join("\n")
    }

    #[must_use]
    pub fn is_multiline(&self) -> bool {
        self.multiline
    }

    #[must_use]
    pub fn is_secret(&self) -> bool {
        self.secret
    }

    pub fn set_secret(&mut self, secret: bool) {
        self.secret = secret;
    }

    /// The widget, for rendering.
    #[must_use]
    pub fn area(&self) -> &TextArea<'static> {
        &self.area
    }

    /// Show or hide the cursor, and mask the text or not.
    fn style(&mut self, focused: bool, masked: bool) {
        self.area.set_cursor_style(if focused {
            theme::SELECTED
        } else {
            Style::new()
        });
        if masked {
            self.area.set_mask_char(MASK_CHAR);
        } else {
            self.area.clear_mask_char();
        }
    }

    /// Feed a key to the field. Returns whether the text changed.
    fn input(&mut self, key: KeyEvent) -> bool {
        self.area.input(key)
    }
}

impl Drop for TextField {
    fn drop(&mut self) {
        // Best effort: wipe the text, and the cut/paste buffer, which may
        // hold a copy of part of it.
        self.area.set_yank_text(String::new());
        let mut lines = std::mem::take(&mut self.area).into_lines();
        lines.zeroize();
    }
}

/// What a row contains.
pub enum Widget {
    // Boxed: a text area is much bigger than the other variants.
    Text(Box<TextField>),
    Toggle(bool),
    Choice {
        options: &'static [&'static str],
        selected: usize,
    },
    /// Activated with Enter or Space; the form reports it to the caller.
    Button,
}

pub struct Row {
    pub id: RowId,
    pub label: String,
    pub widget: Widget,
    /// Hidden rows are skipped by focus and not drawn, but keep their value.
    pub hidden: bool,
}

impl Row {
    #[must_use]
    pub fn text(id: RowId, label: impl Into<String>, value: &str) -> Self {
        Self::new(
            id,
            label,
            Widget::Text(Box::new(TextField::new(value, false, false))),
        )
    }

    #[must_use]
    pub fn secret(id: RowId, label: impl Into<String>, value: &str) -> Self {
        Self::new(
            id,
            label,
            Widget::Text(Box::new(TextField::new(value, false, true))),
        )
    }

    #[must_use]
    pub fn multiline(id: RowId, label: impl Into<String>, value: &str) -> Self {
        Self::new(
            id,
            label,
            Widget::Text(Box::new(TextField::new(value, true, false))),
        )
    }

    #[must_use]
    pub fn toggle(id: RowId, label: impl Into<String>, on: bool) -> Self {
        Self::new(id, label, Widget::Toggle(on))
    }

    #[must_use]
    pub fn choice(
        id: RowId,
        label: impl Into<String>,
        options: &'static [&'static str],
        selected: usize,
    ) -> Self {
        Self::new(id, label, Widget::Choice { options, selected })
    }

    #[must_use]
    pub fn button(id: RowId, label: impl Into<String>) -> Self {
        Self::new(id, label, Widget::Button)
    }

    fn new(id: RowId, label: impl Into<String>, widget: Widget) -> Self {
        Self {
            id,
            label: label.into(),
            widget,
            hidden: false,
        }
    }

    #[must_use]
    /// Dim hint text shown while a text field is empty.
    pub fn with_placeholder(mut self, placeholder: &str) -> Self {
        if let Widget::Text(field) = &mut self.widget {
            field.area.set_placeholder_text(placeholder);
            field.area.set_placeholder_style(theme::DIM);
        }
        self
    }
}

/// The outcome of feeding a key to the form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormEvent {
    /// Nothing happened.
    None,
    /// The value of this row changed.
    Changed(RowId),
    /// Enter in a single-line field: move to the next field.
    Next,
    /// A button was pressed.
    Activated(RowId),
}

pub struct Form {
    rows: Vec<Row>,
    focus: usize,
    /// Show secret fields in clear text.
    reveal: bool,
    /// Set once anything is edited, so "Cancel" can ask before discarding.
    pub dirty: bool,
    /// First visible row, kept between renders for stable scrolling.
    pub scroll: std::cell::Cell<usize>,
}

impl Form {
    #[must_use]
    pub fn new(rows: Vec<Row>) -> Self {
        let mut form = Self {
            rows,
            focus: 0,
            reveal: false,
            dirty: false,
            scroll: std::cell::Cell::new(0),
        };
        if form.rows.first().is_some_and(|r| r.hidden) {
            form.focus_next();
        }
        form.restyle();
        form
    }

    #[must_use]
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    #[must_use]
    pub fn focus(&self) -> usize {
        self.focus
    }

    #[cfg(test)]
    #[must_use]
    pub fn focused_id(&self) -> Option<RowId> {
        self.rows.get(self.focus).map(|r| r.id)
    }

    pub fn toggle_reveal(&mut self) {
        self.reveal = !self.reveal;
        self.restyle();
    }

    /// Focus the row `id` (if it exists and is visible).
    pub fn focus_row(&mut self, id: RowId) {
        if let Some(i) = self.index(id).filter(|&i| !self.rows[i].hidden) {
            self.focus = i;
            self.restyle();
        }
    }

    /// Move focus to the next visible row, wrapping around.
    pub fn focus_next(&mut self) {
        self.step_focus(1);
    }

    /// Move focus to the previous visible row, wrapping around.
    pub fn focus_prev(&mut self) {
        self.step_focus(self.rows.len().saturating_sub(1));
    }

    fn step_focus(&mut self, step: usize) {
        let n = self.rows.len();
        for _ in 0..n {
            self.focus = (self.focus + step) % n;
            if !self.rows[self.focus].hidden {
                break;
            }
        }
        self.restyle();
    }

    /// Feed a key that the keymap didn't claim to the focused row.
    pub fn input(&mut self, key: KeyEvent) -> FormEvent {
        let Some(row) = self.rows.get_mut(self.focus) else {
            return FormEvent::None;
        };
        let id = row.id;
        let plain = (key.modifiers - KeyModifiers::SHIFT).is_empty();
        let event = match &mut row.widget {
            Widget::Text(field) => {
                // Keys that would start a new line: in a single-line field
                // they move on to the next field instead.
                let newline = key.code == KeyCode::Enter
                    || (key.modifiers == KeyModifiers::CONTROL
                        && matches!(key.code, KeyCode::Char('m' | 'j')));
                if newline && !field.is_multiline() {
                    FormEvent::Next
                } else if field.input(key) {
                    FormEvent::Changed(id)
                } else {
                    FormEvent::None
                }
            }
            Widget::Toggle(on) => match key.code {
                KeyCode::Char(' ') | KeyCode::Enter | KeyCode::Left | KeyCode::Right if plain => {
                    *on = !*on;
                    FormEvent::Changed(id)
                }
                _ => FormEvent::None,
            },
            Widget::Choice { options, selected } => match key.code {
                KeyCode::Char(' ') | KeyCode::Enter | KeyCode::Right if plain => {
                    *selected = (*selected + 1) % options.len();
                    FormEvent::Changed(id)
                }
                KeyCode::Left if plain => {
                    *selected = (*selected + options.len() - 1) % options.len();
                    FormEvent::Changed(id)
                }
                _ => FormEvent::None,
            },
            Widget::Button => match key.code {
                KeyCode::Char(' ') | KeyCode::Enter if plain => FormEvent::Activated(id),
                _ => FormEvent::None,
            },
        };
        if matches!(event, FormEvent::Changed(_)) {
            self.dirty = true;
        }
        event
    }

    // -- Reading and changing rows --------------------------------------------

    fn index(&self, id: RowId) -> Option<usize> {
        self.rows.iter().position(|r| r.id == id)
    }

    fn row(&self, id: RowId) -> Option<&Row> {
        self.rows.iter().find(|r| r.id == id)
    }

    /// The text of row `id` (empty if it isn't a text row).
    #[must_use]
    pub fn text(&self, id: RowId) -> String {
        match self.row(id).map(|r| &r.widget) {
            Some(Widget::Text(field)) => field.text(),
            _ => String::new(),
        }
    }

    /// The state of toggle row `id` (false if it isn't a toggle).
    #[must_use]
    pub fn toggle(&self, id: RowId) -> bool {
        matches!(self.row(id).map(|r| &r.widget), Some(Widget::Toggle(true)))
    }

    /// The selected option of choice row `id` (0 if it isn't a choice).
    #[must_use]
    pub fn choice(&self, id: RowId) -> usize {
        match self.row(id).map(|r| &r.widget) {
            Some(Widget::Choice { selected, .. }) => *selected,
            _ => 0,
        }
    }

    /// Hide or show row `id`. Focus moves off a row that gets hidden.
    pub fn set_hidden(&mut self, id: RowId, hidden: bool) {
        if let Some(i) = self.index(id) {
            self.rows[i].hidden = hidden;
            if hidden && i == self.focus {
                self.focus_next();
            }
        }
    }

    /// Mark text row `id` as secret (masked) or not.
    pub fn set_secret(&mut self, id: RowId, secret: bool) {
        if let Some(Widget::Text(field)) = self.index(id).map(|i| &mut self.rows[i].widget) {
            field.set_secret(secret);
        }
        self.restyle();
    }

    /// Insert `rows` just before row `before` (or at the end).
    pub fn insert_before(&mut self, before: RowId, rows: Vec<Row>) {
        let at = self.index(before).unwrap_or(self.rows.len());
        if at <= self.focus {
            self.focus += rows.len();
        }
        self.rows.splice(at..at, rows);
        self.restyle();
    }

    /// Re-apply cursor visibility and masking after focus or reveal changes.
    fn restyle(&mut self) {
        let reveal = self.reveal;
        for (i, row) in self.rows.iter_mut().enumerate() {
            if let Widget::Text(field) = &mut row.widget {
                let masked = field.is_secret() && !reveal;
                field.style(i == self.focus, masked);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn type_text(form: &mut Form, text: &str) {
        for c in text.chars() {
            form.input(key(KeyCode::Char(c)));
        }
    }

    fn sample() -> Form {
        Form::new(vec![
            Row::text(RowId::Title, "Title", "hello"),
            Row::secret(RowId::Password, "Password", ""),
            Row::multiline(RowId::Notes, "Notes", "a\nb"),
            Row::toggle(RowId::Favorite, "Favourite", false),
            Row::choice(RowId::Kind, "Type", &["Login", "Note"], 0),
            Row::button(RowId::AddCustom, "+ Add"),
        ])
    }

    #[test]
    fn text_fields_start_with_cursor_at_the_end() {
        let mut form = sample();
        type_text(&mut form, " world");
        assert_eq!(form.text(RowId::Title), "hello world");
        assert!(form.dirty);
    }

    #[test]
    fn enter_moves_on_in_single_line_fields_but_not_multiline() {
        let mut form = sample();
        assert_eq!(form.input(key(KeyCode::Enter)), FormEvent::Next);

        // Multi-line fields start with the cursor at the top-left.
        form.focus_row(RowId::Notes);
        type_text(&mut form, "c");
        form.input(key(KeyCode::Enter));
        assert_eq!(form.text(RowId::Notes), "c\na\nb");
    }

    #[test]
    fn toggles_choices_and_buttons() {
        let mut form = sample();
        form.focus_row(RowId::Favorite);
        assert_eq!(
            form.input(key(KeyCode::Char(' '))),
            FormEvent::Changed(RowId::Favorite)
        );
        assert!(form.toggle(RowId::Favorite));
        // Letters do nothing on a toggle.
        assert_eq!(form.input(key(KeyCode::Char('x'))), FormEvent::None);

        form.focus_row(RowId::Kind);
        form.input(key(KeyCode::Right));
        assert_eq!(form.choice(RowId::Kind), 1);
        form.input(key(KeyCode::Right));
        assert_eq!(form.choice(RowId::Kind), 0, "wraps around");
        form.input(key(KeyCode::Left));
        assert_eq!(form.choice(RowId::Kind), 1);

        form.focus_row(RowId::AddCustom);
        assert_eq!(
            form.input(key(KeyCode::Enter)),
            FormEvent::Activated(RowId::AddCustom)
        );
    }

    #[test]
    fn focus_skips_hidden_rows_and_wraps() {
        let mut form = sample();
        form.set_hidden(RowId::Password, true);
        form.focus_next();
        assert_eq!(form.focused_id(), Some(RowId::Notes));
        form.focus_prev();
        form.focus_prev();
        assert_eq!(
            form.focused_id(),
            Some(RowId::AddCustom),
            "wrapped to the end"
        );

        // Hiding the focused row moves focus along.
        form.focus_row(RowId::Notes);
        form.set_hidden(RowId::Notes, true);
        assert_eq!(form.focused_id(), Some(RowId::Favorite));
    }

    #[test]
    fn inserting_rows_keeps_focus_on_the_same_row() {
        let mut form = sample();
        form.focus_row(RowId::AddCustom);
        form.insert_before(
            RowId::AddCustom,
            vec![Row::text(RowId::CustomName(0), "Name", "")],
        );
        assert_eq!(form.focused_id(), Some(RowId::AddCustom));
        assert_eq!(form.rows()[5].id, RowId::CustomName(0));
    }

    #[test]
    fn secrets_are_masked_unless_revealed() {
        let mut form = sample();
        form.focus_row(RowId::Password);
        type_text(&mut form, "pw");
        let mask = |f: &Form| match &f.rows()[1].widget {
            Widget::Text(t) => t.area().mask_char(),
            _ => unreachable!(),
        };
        assert_eq!(mask(&form), Some(MASK_CHAR));
        form.toggle_reveal();
        assert_eq!(mask(&form), None);
        assert_eq!(form.text(RowId::Password), "pw");
    }
}
