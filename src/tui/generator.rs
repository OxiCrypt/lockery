//! State of the password/passphrase generator popup.
//!
//! Options are a [`Form`]; the value is regenerated whenever an option
//! changes (and on Ctrl-g). The popup starts from the config's generator
//! settings, and remembers changes for the rest of the session.

use zeroize::Zeroizing;

use super::form::{Form, Row, RowId};
use crate::config::GeneratorConfig;
use crate::generator::{
    PassphraseOptions, PasswordOptions, Strength, generate_passphrase, generate_password,
    passphrase, password,
};

/// Choice options for the Type row.
const KINDS: &[&str] = &["Password", "Passphrase"];

/// Rows shown only for one of the two kinds.
const PASSWORD_ROWS: [RowId; 6] = [
    RowId::Length,
    RowId::Lowercase,
    RowId::Uppercase,
    RowId::Digits,
    RowId::Symbols,
    RowId::NoAmbiguous,
];
const PASSPHRASE_ROWS: [RowId; 3] = [RowId::Words, RowId::Separator, RowId::Capitalize];

/// Where a generated value goes when the user presses Enter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeneratorTarget {
    /// Into the Password field of the open entry editor.
    Editor,
    /// Into a new entry (opened from the list or detail view).
    NewEntry,
}

pub struct GeneratorState {
    pub form: Form,
    pub target: GeneratorTarget,
    /// The current suggestion (empty if the options are invalid).
    pub value: Zeroizing<String>,
    pub entropy_bits: f64,
    pub strength: Option<Strength>,
    /// Why nothing could be generated, e.g. no character kinds chosen.
    pub error: Option<String>,
}

impl GeneratorState {
    /// A generator starting from `settings`, with a first value ready.
    #[must_use]
    pub fn new(settings: &GeneratorConfig, target: GeneratorTarget, passphrase: bool) -> Self {
        let rows = vec![
            Row::choice(RowId::GenKind, "Type", KINDS, usize::from(passphrase)),
            Row::number(
                RowId::Length,
                "Length",
                settings.password_length,
                password::MIN_LENGTH,
                password::MAX_LENGTH,
            ),
            Row::toggle(RowId::Lowercase, "a-z", settings.lowercase),
            Row::toggle(RowId::Uppercase, "A-Z", settings.uppercase),
            Row::toggle(RowId::Digits, "0-9", settings.digits),
            Row::toggle(RowId::Symbols, "Symbols", settings.symbols),
            Row::toggle(
                RowId::NoAmbiguous,
                "Avoid 0/O, 1/l",
                settings.exclude_ambiguous,
            ),
            Row::number(
                RowId::Words,
                "Words",
                settings.passphrase_words.into(),
                passphrase::MIN_WORDS.into(),
                passphrase::MAX_WORDS.into(),
            ),
            Row::text(
                RowId::Separator,
                "Separator",
                &settings.passphrase_separator,
            ),
            Row::toggle(
                RowId::Capitalize,
                "Capitalise",
                settings.passphrase_capitalize,
            ),
        ];
        let mut state = Self {
            form: Form::new(rows),
            target,
            value: Zeroizing::new(String::new()),
            entropy_bits: 0.0,
            strength: None,
            error: None,
        };
        state.show_rows();
        state.regenerate();
        state
    }

    fn is_passphrase(&self) -> bool {
        self.form.choice(RowId::GenKind) == 1
    }

    fn show_rows(&mut self) {
        let passphrase = self.is_passphrase();
        for id in PASSWORD_ROWS {
            self.form.set_hidden(id, passphrase);
        }
        for id in PASSPHRASE_ROWS {
            self.form.set_hidden(id, !passphrase);
        }
    }

    /// React to a changed option: update which rows show, and regenerate.
    pub fn on_change(&mut self, id: RowId) {
        if id == RowId::GenKind {
            self.show_rows();
        }
        self.regenerate();
    }

    /// Draw a new value with the current options.
    pub fn regenerate(&mut self) {
        let settings = self.settings();
        let result = if self.is_passphrase() {
            let options = PassphraseOptions::from(&settings);
            self.entropy_bits = options.entropy_bits();
            generate_passphrase(&options)
        } else {
            let options = PasswordOptions::from(&settings);
            self.entropy_bits = options.entropy_bits();
            generate_password(&options)
        };
        match result {
            Ok(value) => {
                self.strength = Some(Strength::of(&value, &[]));
                self.value = value; // the old value is wiped as it drops
                self.error = None;
            }
            Err(e) => {
                self.value = Zeroizing::new(String::new());
                self.strength = None;
                self.error = Some(capitalise(&e.to_string()));
            }
        }
    }

    /// The options as generator settings, to remember for next time.
    #[must_use]
    pub fn settings(&self) -> GeneratorConfig {
        let f = &self.form;
        GeneratorConfig {
            password_length: f.number(RowId::Length),
            lowercase: f.toggle(RowId::Lowercase),
            uppercase: f.toggle(RowId::Uppercase),
            digits: f.toggle(RowId::Digits),
            symbols: f.toggle(RowId::Symbols),
            exclude_ambiguous: f.toggle(RowId::NoAmbiguous),
            passphrase_words: u8::try_from(f.number(RowId::Words)).unwrap_or(u8::MAX),
            passphrase_separator: f.text(RowId::Separator),
            passphrase_capitalize: f.toggle(RowId::Capitalize),
        }
    }

    /// Whether the last generator run produced a value.
    #[must_use]
    pub fn has_value(&self) -> bool {
        !self.value.is_empty()
    }
}

fn capitalise(s: &str) -> String {
    let mut chars = s.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent};

    use super::*;

    fn state(passphrase: bool) -> GeneratorState {
        GeneratorState::new(
            &GeneratorConfig::default(),
            GeneratorTarget::NewEntry,
            passphrase,
        )
    }

    #[test]
    fn starts_with_a_value_from_the_config_defaults() {
        let s = state(false);
        assert_eq!(s.value.chars().count(), 24);
        assert!(s.entropy_bits > 150.0);
        assert_eq!(s.strength.map(|st| st.score), Some(4));

        let s = state(true);
        assert!(s.value.matches('-').count() >= 5, "{:?}", *s.value);
        assert!((s.entropy_bits - 77.5).abs() < 0.1);
    }

    #[test]
    fn switching_kind_swaps_rows_and_regenerates() {
        let mut s = state(false);
        let before = s.value.clone();
        s.form.focus_row(RowId::GenKind);
        s.form.input(KeyEvent::from(KeyCode::Right));
        s.on_change(RowId::GenKind);
        assert!(s.is_passphrase());
        assert_ne!(*s.value, *before);
        let hidden: Vec<_> = s
            .form
            .rows()
            .iter()
            .filter(|r| r.hidden)
            .map(|r| r.id)
            .collect();
        assert_eq!(hidden, PASSWORD_ROWS);
    }

    #[test]
    fn impossible_options_show_an_error() {
        let mut s = state(false);
        for id in [
            RowId::Lowercase,
            RowId::Uppercase,
            RowId::Digits,
            RowId::Symbols,
        ] {
            s.form.focus_row(id);
            s.form.input(KeyEvent::from(KeyCode::Char(' ')));
            s.on_change(id);
        }
        assert!(!s.has_value());
        assert_eq!(
            s.error.as_deref(),
            Some("Choose at least one kind of character")
        );
    }

    #[test]
    fn settings_round_trip() {
        let s = state(false);
        assert_eq!(s.settings(), GeneratorConfig::default());
    }
}
