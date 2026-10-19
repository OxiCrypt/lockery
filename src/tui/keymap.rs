//! Every key binding in the app, in one table.
//!
//! [`BINDINGS`] is the single source of truth. Input handling looks keys up
//! here ([`action_for`]), and the footer and help overlay are rendered from
//! here ([`hints`]). The hints therefore can't drift from what the keys
//! actually do.
//!
//! In text-entry modes ([`Mode::is_text_entry`]), keys that aren't bound
//! go to the focused text field instead (typing, cursor movement, ...).

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Which keys are active. Roughly one per screen, plus overlays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Choosing which vault to open.
    Picker,
    /// Typing the master password.
    Unlock,
    /// Browsing the entry list.
    List,
    /// Typing a search query above the entry list.
    Search,
    /// Looking at a single entry.
    Detail,
    /// Adding or editing an entry.
    Edit,
    /// A small form over the vault picker (create, rename, delete vault).
    Dialog,
    /// A yes/no question.
    Confirm,
    /// The help overlay is open.
    Help,
}

impl Mode {
    /// Modes where keys that aren't bound go to a text field instead.
    #[must_use]
    pub const fn is_text_entry(self) -> bool {
        matches!(
            self,
            Self::Unlock | Self::Search | Self::Edit | Self::Dialog
        )
    }

    /// Every mode, for tests and the help overlay.
    pub const ALL: [Self; 9] = [
        Self::Picker,
        Self::Unlock,
        Self::List,
        Self::Search,
        Self::Detail,
        Self::Edit,
        Self::Dialog,
        Self::Confirm,
        Self::Help,
    ];
}

/// Something the user can ask the app to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Up,
    Down,
    PageUp,
    PageDown,
    Top,
    Bottom,
    /// Open the selected vault or entry.
    Open,
    /// Submit the unlock screen or a dialog.
    Submit,
    /// Delete the character before the cursor in a text field.
    Backspace,
    /// Go back to the previous screen.
    Back,
    /// Start typing a search query.
    Search,
    /// Leave search mode, keeping the filter.
    AcceptSearch,
    /// Leave search mode and clear the filter.
    ClearSearch,
    /// Show or hide passwords and other secret fields.
    ToggleReveal,
    /// Show or hide what's being typed into password fields.
    ToggleRevealInput,
    /// Lock the vault (and stay on its unlock screen).
    Lock,
    /// Lock the vault and go to the vault picker.
    SwitchVault,
    /// Create a new entry (in a vault) or a new vault (in the picker).
    New,
    /// Edit the selected entry.
    Edit,
    /// Rename the selected vault.
    Rename,
    /// Delete the selected entry or vault (after confirmation).
    Delete,
    /// Move to the next / previous field of a form.
    NextField,
    PrevField,
    /// Save the entry being edited.
    Save,
    /// Leave a form or dialog without saving.
    Cancel,
    /// Answer a confirmation question.
    Yes,
    No,
    Help,
    CloseHelp,
    Quit,
}

/// A single key with modifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub code: KeyCode,
    pub mods: KeyModifiers,
}

impl Key {
    const fn plain(code: KeyCode) -> Self {
        Self {
            code,
            mods: KeyModifiers::NONE,
        }
    }

    const fn char(c: char) -> Self {
        Self::plain(KeyCode::Char(c))
    }

    const fn ctrl(c: char) -> Self {
        Self {
            code: KeyCode::Char(c),
            mods: KeyModifiers::CONTROL,
        }
    }

    /// Whether `event` is this key. Shift is ignored for characters and
    /// Shift-Tab (`BackTab`), since terminals disagree on whether `?`, `G`
    /// or Shift-Tab arrive with SHIFT set.
    #[must_use]
    pub fn matches(self, event: &KeyEvent) -> bool {
        let mods = match event.code {
            KeyCode::Char(_) | KeyCode::BackTab => event.modifiers - KeyModifiers::SHIFT,
            _ => event.modifiers,
        };
        self.code == event.code && self.mods == mods
    }
}

/// Where a binding's hint is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Show {
    /// In the footer and the help overlay.
    Footer,
    /// Only in the help overlay (less common keys).
    Help,
    /// Nowhere: an alias already described by another row, such as the
    /// "down" half of "↑↓/jk Move".
    Hidden,
}

/// One row of the binding table.
#[derive(Debug)]
pub struct Binding {
    /// Keys that trigger the action.
    pub keys: &'static [Key],
    /// How the keys are written in hints, e.g. `↑↓/jk`.
    pub label: &'static str,
    /// What the action does, as shown in hints.
    pub description: &'static str,
    pub action: Action,
    /// Modes this binding is active in.
    pub modes: &'static [Mode],
    pub show: Show,
}

use Mode::{Confirm, Detail, Dialog, Edit, Help, List, Picker, Search, Unlock};
use Show::{Footer, Hidden};

/// All key bindings. Order matters: it is the order of the hints, so the
/// most useful keys come first (the footer drops hints that don't fit, but
/// always keeps room for the Help hint).
pub static BINDINGS: &[Binding] = &[
    // -- Moving around --------------------------------------------------------
    Binding {
        keys: &[Key::plain(KeyCode::Up), Key::char('k')],
        label: "↑↓/jk",
        description: "Move",
        action: Action::Up,
        modes: &[Picker],
        show: Footer,
    },
    // In the list the highlight makes movement obvious, so the footer's room
    // goes to the entry commands instead.
    Binding {
        keys: &[Key::plain(KeyCode::Up), Key::char('k')],
        label: "↑↓/jk",
        description: "Move",
        action: Action::Up,
        modes: &[List],
        show: Show::Help,
    },
    Binding {
        keys: &[Key::plain(KeyCode::Down), Key::char('j')],
        label: "↓/j",
        description: "Move down",
        action: Action::Down,
        modes: &[Picker, List],
        show: Hidden,
    },
    // While searching, j and k must be typeable, so only the arrows move.
    Binding {
        keys: &[Key::plain(KeyCode::Up)],
        label: "↑↓",
        description: "Move",
        action: Action::Up,
        modes: &[Search],
        show: Footer,
    },
    Binding {
        keys: &[Key::plain(KeyCode::Down)],
        label: "↓",
        description: "Move down",
        action: Action::Down,
        modes: &[Search],
        show: Hidden,
    },
    Binding {
        keys: &[Key::plain(KeyCode::PageUp)],
        label: "PgUp/PgDn",
        description: "Page up/down",
        action: Action::PageUp,
        modes: &[List, Search],
        show: Show::Help,
    },
    Binding {
        keys: &[Key::plain(KeyCode::PageDown)],
        label: "PgDn",
        description: "Page down",
        action: Action::PageDown,
        modes: &[List, Search],
        show: Hidden,
    },
    Binding {
        keys: &[Key::plain(KeyCode::Home), Key::char('g')],
        label: "g/G",
        description: "First/last",
        action: Action::Top,
        modes: &[Picker, List],
        show: Show::Help,
    },
    Binding {
        keys: &[Key::plain(KeyCode::End), Key::char('G')],
        label: "G",
        description: "Last",
        action: Action::Bottom,
        modes: &[Picker, List],
        show: Hidden,
    },
    // -- Opening, submitting and going back -----------------------------------
    Binding {
        keys: &[
            Key::plain(KeyCode::Enter),
            Key::char('l'),
            Key::plain(KeyCode::Right),
        ],
        label: "Enter",
        description: "Open",
        action: Action::Open,
        modes: &[Picker, List],
        show: Footer,
    },
    Binding {
        keys: &[Key::plain(KeyCode::Enter)],
        label: "Enter",
        description: "Unlock",
        action: Action::Submit,
        modes: &[Unlock],
        show: Footer,
    },
    Binding {
        keys: &[Key::plain(KeyCode::Enter)],
        label: "Enter",
        description: "Confirm",
        action: Action::Submit,
        modes: &[Dialog],
        show: Footer,
    },
    Binding {
        keys: &[Key::plain(KeyCode::Backspace)],
        label: "Bksp",
        description: "Delete character",
        action: Action::Backspace,
        modes: &[Unlock, Search],
        show: Hidden,
    },
    Binding {
        keys: &[
            Key::plain(KeyCode::Esc),
            Key::char('h'),
            Key::plain(KeyCode::Left),
        ],
        label: "Esc",
        description: "Back",
        action: Action::Back,
        modes: &[Detail],
        show: Footer,
    },
    // -- Forms ----------------------------------------------------------------
    Binding {
        keys: &[Key::plain(KeyCode::Tab)],
        label: "Tab",
        description: "Next field",
        action: Action::NextField,
        modes: &[Edit, Dialog],
        show: Footer,
    },
    Binding {
        keys: &[Key::plain(KeyCode::BackTab)],
        label: "Shift-Tab",
        description: "Previous",
        action: Action::PrevField,
        modes: &[Edit, Dialog],
        show: Footer,
    },
    Binding {
        keys: &[Key::ctrl('s')],
        label: "Ctrl-s",
        description: "Save",
        action: Action::Save,
        modes: &[Edit],
        show: Footer,
    },
    Binding {
        keys: &[Key::plain(KeyCode::Esc)],
        label: "Esc",
        description: "Cancel",
        action: Action::Cancel,
        modes: &[Edit, Dialog],
        show: Footer,
    },
    // -- Confirmations --------------------------------------------------------
    Binding {
        keys: &[Key::char('y')],
        label: "y",
        description: "Yes",
        action: Action::Yes,
        modes: &[Confirm],
        show: Footer,
    },
    Binding {
        keys: &[Key::char('n'), Key::plain(KeyCode::Esc)],
        label: "n/Esc",
        description: "No",
        action: Action::No,
        modes: &[Confirm],
        show: Footer,
    },
    // -- Searching ------------------------------------------------------------
    Binding {
        keys: &[Key::char('/')],
        label: "/",
        description: "Search",
        action: Action::Search,
        modes: &[List],
        show: Footer,
    },
    Binding {
        keys: &[Key::plain(KeyCode::Enter)],
        label: "Enter",
        description: "Done",
        action: Action::AcceptSearch,
        modes: &[Search],
        show: Footer,
    },
    Binding {
        keys: &[Key::plain(KeyCode::Esc)],
        label: "Esc",
        description: "Clear search",
        action: Action::ClearSearch,
        modes: &[Search],
        show: Footer,
    },
    // Same key in the list, where it only matters if a filter is active, so
    // it stays out of the footer.
    Binding {
        keys: &[Key::plain(KeyCode::Esc)],
        label: "Esc",
        description: "Clear search",
        action: Action::ClearSearch,
        modes: &[List],
        show: Show::Help,
    },
    // -- Entries and vaults ---------------------------------------------------
    Binding {
        keys: &[Key::char('n')],
        label: "n",
        description: "New",
        action: Action::New,
        modes: &[List, Picker],
        show: Footer,
    },
    Binding {
        keys: &[Key::char('e')],
        label: "e",
        description: "Edit",
        action: Action::Edit,
        modes: &[List, Detail],
        show: Footer,
    },
    Binding {
        keys: &[Key::char('r')],
        label: "r",
        description: "Rename",
        action: Action::Rename,
        modes: &[Picker],
        show: Footer,
    },
    Binding {
        keys: &[Key::char('d')],
        label: "d",
        description: "Delete",
        action: Action::Delete,
        modes: &[List, Detail, Picker],
        show: Footer,
    },
    // -- Secrets --------------------------------------------------------------
    Binding {
        keys: &[Key::char(' ')],
        label: "Space",
        description: "Show/hide",
        action: Action::ToggleReveal,
        modes: &[Detail],
        show: Footer,
    },
    Binding {
        keys: &[Key::ctrl('r')],
        label: "Ctrl-r",
        description: "Show/hide",
        action: Action::ToggleRevealInput,
        modes: &[Unlock, Edit, Dialog],
        show: Footer,
    },
    // -- Locking and switching ------------------------------------------------
    Binding {
        keys: &[Key::char('L')],
        label: "L",
        description: "Lock",
        action: Action::Lock,
        modes: &[List, Detail],
        show: Footer,
    },
    Binding {
        keys: &[Key::char('V')],
        label: "V",
        description: "Vaults",
        action: Action::SwitchVault,
        modes: &[List, Detail],
        show: Footer,
    },
    Binding {
        keys: &[Key::plain(KeyCode::Tab)],
        label: "Tab",
        description: "Vaults",
        action: Action::SwitchVault,
        modes: &[Unlock],
        show: Footer,
    },
    // -- Quitting and help ----------------------------------------------------
    Binding {
        keys: &[Key::char('q')],
        label: "q",
        description: "Quit",
        action: Action::Quit,
        modes: &[List, Detail],
        show: Footer,
    },
    Binding {
        keys: &[Key::char('q'), Key::plain(KeyCode::Esc)],
        label: "q/Esc",
        description: "Quit",
        action: Action::Quit,
        modes: &[Picker],
        show: Footer,
    },
    // `q` must stay typeable on the unlock screen, so only Esc quits there.
    Binding {
        keys: &[Key::plain(KeyCode::Esc)],
        label: "Esc",
        description: "Quit",
        action: Action::Quit,
        modes: &[Unlock],
        show: Footer,
    },
    Binding {
        keys: &[Key::char('?'), Key::plain(KeyCode::F(1))],
        label: "?",
        description: "Help",
        action: Action::Help,
        modes: &[Picker, List, Detail],
        show: Footer,
    },
    // `?` must stay typeable in text fields, so they use F1.
    Binding {
        keys: &[Key::plain(KeyCode::F(1))],
        label: "F1",
        description: "Help",
        action: Action::Help,
        modes: &[Unlock, Search, Edit, Dialog],
        show: Footer,
    },
    Binding {
        keys: &[
            Key::plain(KeyCode::Esc),
            Key::char('?'),
            Key::char('q'),
            Key::plain(KeyCode::F(1)),
        ],
        label: "Esc",
        description: "Close help",
        action: Action::CloseHelp,
        modes: &[Help],
        show: Footer,
    },
    // Ctrl-C always quits, even while typing.
    Binding {
        keys: &[Key::ctrl('c')],
        label: "Ctrl-c",
        description: "Quit",
        action: Action::Quit,
        modes: &Mode::ALL,
        show: Show::Help,
    },
];

/// The action bound to `event` in `mode`, if any.
#[must_use]
pub fn action_for(mode: Mode, event: &KeyEvent) -> Option<Action> {
    BINDINGS
        .iter()
        .filter(|b| b.modes.contains(&mode))
        .find(|b| b.keys.iter().any(|k| k.matches(event)))
        .map(|b| b.action)
}

/// The bindings to hint at in `mode`: the footer's (`footer_only`), or
/// everything the help overlay lists.
pub fn hints(mode: Mode, footer_only: bool) -> impl Iterator<Item = &'static Binding> {
    BINDINGS.iter().filter(move |b| {
        b.modes.contains(&mode)
            && match b.show {
                Show::Footer => true,
                Show::Help => !footer_only,
                Show::Hidden => false,
            }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, mods)
    }

    /// No key may be bound twice in the same mode: the second binding would
    /// silently never fire, and its hint would lie.
    #[test]
    fn no_conflicting_bindings() {
        for mode in Mode::ALL {
            let mut seen: Vec<(Key, &str)> = Vec::new();
            for b in BINDINGS.iter().filter(|b| b.modes.contains(&mode)) {
                for key in b.keys {
                    if let Some((_, other)) = seen.iter().find(|(k, _)| k == key) {
                        panic!(
                            "{mode:?}: {key:?} bound to both {other:?} and {:?}",
                            b.description
                        );
                    }
                    seen.push((*key, b.description));
                }
            }
        }
    }

    /// Every key of every binding dispatches to that binding's action, and
    /// every mode shows at least one footer hint.
    #[test]
    fn every_binding_dispatches_and_every_mode_has_hints() {
        for b in BINDINGS {
            assert!(!b.label.is_empty() && !b.description.is_empty());
            for mode in b.modes {
                for key in b.keys {
                    let event = press(key.code, key.mods);
                    assert_eq!(
                        action_for(*mode, &event),
                        Some(b.action),
                        "{key:?} in {mode:?}"
                    );
                }
            }
        }
        for mode in Mode::ALL {
            assert!(
                hints(mode, true).next().is_some(),
                "{mode:?} has no footer hints"
            );
        }
    }

    /// Characters must not be swallowed by bindings while typing, except via
    /// Ctrl combos and the non-printable keys.
    #[test]
    fn text_modes_only_bind_non_printable_keys() {
        for b in BINDINGS {
            for mode in b.modes.iter().filter(|m| m.is_text_entry()) {
                for key in b.keys {
                    let printable = matches!(key.code, KeyCode::Char(_)) && key.mods.is_empty();
                    assert!(!printable, "{key:?} would be untypeable in {mode:?}");
                }
            }
        }
    }

    #[test]
    fn shift_is_ignored_for_characters() {
        let shifted_g = press(KeyCode::Char('G'), KeyModifiers::SHIFT);
        assert_eq!(action_for(Mode::List, &shifted_g), Some(Action::Bottom));
        let shifted_tab = press(KeyCode::Tab, KeyModifiers::SHIFT);
        assert_eq!(action_for(Mode::Unlock, &shifted_tab), None);
    }
}
