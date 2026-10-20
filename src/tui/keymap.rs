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
    /// The password/passphrase generator popup.
    Generator,
    /// The vault settings screen.
    Settings,
    /// Reviewing a CSV file before importing it.
    Preview,
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
            Self::Unlock
                | Self::Search
                | Self::Edit
                | Self::Dialog
                | Self::Generator
                | Self::Settings
        )
    }

    /// Every mode, for tests and the help overlay.
    pub const ALL: [Self; 12] = [
        Self::Picker,
        Self::Unlock,
        Self::List,
        Self::Search,
        Self::Detail,
        Self::Edit,
        Self::Dialog,
        Self::Generator,
        Self::Settings,
        Self::Preview,
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
    /// Open the password generator.
    Generate,
    /// Generate a new suggestion with the same options.
    Regenerate,
    /// Use the generated value (in the editor, or for a new entry).
    UseGenerated,
    /// Open the vault settings.
    Settings,
    /// Import entries from a CSV file.
    Import,
    /// Export entries to a CSV file.
    Export,
    /// On the import preview: also import entries that look like duplicates.
    ToggleDuplicates,
    /// Copy the entry's password / username to the clipboard.
    CopyPassword,
    CopyUsername,
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
    /// A shorter description for the footer, where space is tight (the
    /// help overlay always shows the full one).
    pub short: Option<&'static str>,
}

/// A binding hinted in the footer and the help overlay; chain
/// [`Binding::help`], [`Binding::hidden`] or [`Binding::short`] to change
/// that. Keeps each row of [`BINDINGS`] to about one line.
const fn bind(
    keys: &'static [Key],
    label: &'static str,
    description: &'static str,
    action: Action,
    modes: &'static [Mode],
) -> Binding {
    Binding {
        keys,
        label,
        description,
        action,
        modes,
        show: Show::Footer,
        short: None,
    }
}

impl Binding {
    /// Hint only in the help overlay.
    const fn help(mut self) -> Self {
        self.show = Show::Help;
        self
    }

    /// Hint nowhere (an alias described by another row).
    const fn hidden(mut self) -> Self {
        self.show = Show::Hidden;
        self
    }

    /// Use `short` as the footer description.
    const fn short(mut self, short: &'static str) -> Self {
        self.short = Some(short);
        self
    }
}

use KeyCode::{
    BackTab, Backspace, Down, End, Enter, Esc, F, Home, Left, PageDown, PageUp, Right, Tab, Up,
};
use Mode::{
    Confirm, Detail, Dialog, Edit, Generator, Help, List, Picker, Preview, Search, Settings, Unlock,
};

/// All key bindings. Order matters: it is the order of the hints, so the
/// most useful keys come first (the footer drops hints that don't fit, but
/// always keeps room for the Help hint).
// One binding per line reads as a table; rustfmt would spread each call
// over seven lines.
#[rustfmt::skip]
pub static BINDINGS: &[Binding] = &[
    // -- Moving around --------------------------------------------------------
    bind(&[Key::plain(Up), Key::char('k')], "↑↓/jk", "Move", Action::Up, &[Picker]),
    // In the list the highlight makes movement obvious, so the footer's room
    // goes to the entry commands instead.
    bind(&[Key::plain(Up), Key::char('k')], "↑↓/jk", "Move", Action::Up, &[List]).help(),
    bind(&[Key::plain(Down), Key::char('j')], "↓/j", "Move down", Action::Down, &[Picker, List]).hidden(),
    // While searching, j and k must be typeable, so only the arrows move.
    bind(&[Key::plain(Up)], "↑↓", "Move", Action::Up, &[Search, Preview]),
    bind(&[Key::plain(Down)], "↓", "Move down", Action::Down, &[Search, Preview]).hidden(),
    bind(&[Key::plain(PageUp)], "PgUp/PgDn", "Page up/down", Action::PageUp, &[List, Search]).help(),
    bind(&[Key::plain(PageDown)], "PgDn", "Page down", Action::PageDown, &[List, Search]).hidden(),
    bind(&[Key::plain(Home)], "Home/End", "First/last", Action::Top, &[Picker, List]).help(),
    bind(&[Key::plain(End), Key::char('G')], "G", "Last", Action::Bottom, &[Picker, List]).hidden(),
    // -- Opening, submitting and going back -----------------------------------
    bind(
        &[Key::plain(Enter), Key::char('l'), Key::plain(Right)],
        "Enter",
        "Open",
        Action::Open,
        &[Picker, List],
    ),
    bind(&[Key::plain(Enter)], "Enter", "Unlock", Action::Submit, &[Unlock]),
    bind(&[Key::plain(Enter)], "Enter", "Confirm", Action::Submit, &[Dialog]),
    bind(&[Key::plain(Enter)], "Enter", "Import", Action::Submit, &[Preview]),
    bind(&[Key::char(' ')], "Space", "Include duplicates", Action::ToggleDuplicates, &[Preview]),
    bind(&[Key::plain(Backspace)], "Bksp", "Delete character", Action::Backspace, &[Unlock, Search]).hidden(),
    bind(
        &[Key::plain(Esc), Key::char('h'), Key::plain(Left)],
        "Esc",
        "Back",
        Action::Back,
        &[Detail],
    ),
    // -- Copying --------------------------------------------------------------
    bind(&[Key::char('c')], "c", "Copy password", Action::CopyPassword, &[List, Detail]).short("Copy"),
    bind(&[Key::char('u')], "u", "Copy username", Action::CopyUsername, &[Detail]).short("User"),
    // No footer room in the list view; listed in its help overlay.
    bind(&[Key::char('u')], "u", "Copy username", Action::CopyUsername, &[List]).help(),
    // -- Forms ----------------------------------------------------------------
    bind(&[Key::plain(Tab)], "Tab", "Next", Action::NextField, FORMS),
    bind(&[Key::plain(BackTab)], "Shift-Tab", "Back", Action::PrevField, FORMS),
    bind(&[Key::ctrl('s')], "Ctrl-s", "Save", Action::Save, &[Edit]),
    bind(&[Key::ctrl('s')], "Ctrl-s", "Apply", Action::Save, &[Settings]),
    bind(&[Key::ctrl('g')], "Ctrl-g", "Generate", Action::Generate, &[Edit]),
    bind(&[Key::plain(Enter)], "Enter", "Use", Action::UseGenerated, &[Generator]),
    bind(&[Key::ctrl('g')], "Ctrl-g", "New", Action::Regenerate, &[Generator]),
    bind(&[Key::plain(Esc)], "Esc", "Close", Action::Cancel, &[Generator]),
    bind(&[Key::plain(Esc)], "Esc", "Cancel", Action::Cancel, &[Edit, Dialog, Settings, Preview]),
    // -- Confirmations --------------------------------------------------------
    bind(&[Key::char('y')], "y", "Yes", Action::Yes, &[Confirm]),
    bind(&[Key::char('n'), Key::plain(Esc)], "n/Esc", "No", Action::No, &[Confirm]),
    // -- Searching ------------------------------------------------------------
    bind(&[Key::char('/')], "/", "Search", Action::Search, &[List]),
    bind(&[Key::plain(Enter)], "Enter", "Done", Action::AcceptSearch, &[Search]),
    bind(&[Key::plain(Esc)], "Esc", "Clear search", Action::ClearSearch, &[Search]),
    // Same key in the list, where it only matters if a filter is active, so
    // it stays out of the footer.
    bind(&[Key::plain(Esc)], "Esc", "Clear search", Action::ClearSearch, &[List]).help(),
    // -- Entries and vaults ---------------------------------------------------
    bind(&[Key::char('n')], "n", "New", Action::New, &[List, Picker]),
    bind(&[Key::char('e')], "e", "Edit", Action::Edit, &[List, Detail]),
    bind(&[Key::char('r')], "r", "Rename", Action::Rename, &[Picker]),
    bind(&[Key::char('d')], "d", "Delete", Action::Delete, &[List, Detail, Picker]),
    // The footer has no room left in the list and detail views; it's in
    // the help overlay, and Ctrl-g in the editor is in that footer.
    bind(&[Key::char('g')], "g", "Password generator", Action::Generate, &[List, Detail]).help(),
    bind(&[Key::char('i')], "i", "Import from CSV", Action::Import, &[List, Detail]).help(),
    bind(&[Key::char('x')], "x", "Export to CSV", Action::Export, &[List, Detail]).help(),
    bind(&[Key::char('s')], "s", "Vault settings", Action::Settings, &[List, Detail]).help(),
    // -- Secrets --------------------------------------------------------------
    bind(&[Key::char(' ')], "Space", "Show/hide", Action::ToggleReveal, &[Detail]).short("Show"),
    bind(&[Key::ctrl('r')], "Ctrl-r", "Show/hide", Action::ToggleRevealInput, &[Unlock, Edit, Dialog, Settings]),
    // -- Locking and switching ------------------------------------------------
    bind(&[Key::char('L')], "L", "Lock", Action::Lock, &[List, Detail]),
    // -- Quitting and help ----------------------------------------------------
    bind(&[Key::char('q')], "q", "Quit", Action::Quit, &[List, Detail]),
    bind(&[Key::char('q'), Key::plain(Esc)], "q/Esc", "Quit", Action::Quit, &[Picker]),
    // `q` must stay typeable on the unlock screen, so only Esc quits there.
    bind(&[Key::plain(Esc)], "Esc", "Quit", Action::Quit, &[Unlock]),
    // After Quit, so that when the footer is short of room it drops this
    // rather than Quit.
    bind(&[Key::char('V')], "V", "Vaults", Action::SwitchVault, &[List, Detail]),
    bind(&[Key::plain(Tab)], "Tab", "Vaults", Action::SwitchVault, &[Unlock]),
    bind(&[Key::char('?'), Key::plain(F(1))], "?", "Help", Action::Help, &[Picker, List, Detail, Preview]),
    // `?` must stay typeable in text fields, so they use F1.
    bind(
        &[Key::plain(F(1))],
        "F1",
        "Help",
        Action::Help,
        &[Unlock, Search, Edit, Dialog, Generator, Settings],
    ),
    bind(
        &[Key::plain(Esc), Key::char('?'), Key::char('q'), Key::plain(F(1))],
        "Esc",
        "Close help",
        Action::CloseHelp,
        &[Help],
    ),
    // Ctrl-C always quits, even while typing.
    bind(&[Key::ctrl('c')], "Ctrl-c", "Quit", Action::Quit, &Mode::ALL).help(),
];

/// The modes with a focusable form, which share Tab / Shift-Tab.
const FORMS: &[Mode] = &[Edit, Dialog, Generator, Settings];

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
