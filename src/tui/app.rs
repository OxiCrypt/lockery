//! Application state and behaviour, independent of the terminal.
//!
//! [`App`] owns everything: which screen is showing, the unlocked vault (if
//! any) and the transient UI state. Key presses arrive through
//! [`App::on_key`], are turned into [`Action`]s by the keymap, and change the
//! state. Rendering (`ui.rs`) only reads it. That split keeps the behaviour
//! testable without a real terminal.
//!
//! Screens:
//!
//! ```text
//!   Picker ──Enter──▶ Unlock ──Enter (correct password)──▶ Unlocked
//!     ▲  │             │  ▲                                  │
//!     │  └─n (new)─────┼──┼─────────────────────────────────▶│
//!     └──────Tab───────┘  └──────────L (lock) / idle─────────┤
//!     └──────────────────────────V (switch vault)────────────┘
//! ```
//!
//! On top of a screen there can be a form (entry editor, vault dialog), a
//! yes/no confirmation, or the help overlay.
//!
//! Anything that runs Argon2 (unlocking, creating a vault, verifying the
//! password before deleting one) takes about a second. Those are recorded as
//! [`Pending`] work: the event loop first draws a frame with a "working"
//! message, then calls [`App::run_pending`].

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use jiff::tz::TimeZone;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::entry_form;
use super::form::{Form, FormEvent, Row, RowId};
use super::generator::{GeneratorState, GeneratorTarget};
use super::keymap::{self, Action, Mode};
use super::search::Search;
use super::settings::SettingsState;
use super::transfer::{self, ImportPreview};
use crate::clipboard::{Clipboard, Copied};
use crate::clock::{self, Mark, WallClock};
use crate::config::{Config, GeneratorConfig};
use crate::crypto::calibrate::{self, DEFAULT_TARGET};
use crate::crypto::{self, CipherId, KdfParams};
use crate::error::Error;
use crate::generator::Strength;
use crate::hardening;
use crate::paths::{self, VaultName};
use crate::vault::{Entry, Vault, manage};

/// Which vault to unlock: a display label and its file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultTarget {
    pub label: String,
    pub path: PathBuf,
}

impl VaultTarget {
    /// The target for a named vault in `data_dir`.
    #[must_use]
    pub fn named(name: &VaultName, data_dir: &Path) -> Self {
        Self {
            label: name.to_string(),
            path: name.path_in(data_dir),
        }
    }
}

/// A one-line message shown above the footer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub text: String,
    pub kind: StatusKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusKind {
    Info,
    Warning,
    Error,
}

/// How Argon2 parameters are chosen for vaults created in the app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewVaultKdf {
    /// Calibrate to about one second on this machine (the default).
    Calibrate,
    /// Use these parameters (tests use this to stay fast).
    Fixed(KdfParams),
}

/// Slow work waiting to run after the next frame is drawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pending {
    Unlock,
    CreateVault,
    DeleteVault,
    /// Tune the Argon2 fields on the settings screen.
    Calibrate,
    /// Apply the settings screen: re-encrypt the vault.
    Rekey,
    /// Check the password, then write the CSV export.
    Export,
}

/// A yes/no question over the current screen.
pub(super) struct Confirm {
    pub question: String,
    on_yes: ConfirmAction,
}

enum ConfirmAction {
    DeleteEntry(Uuid),
    DiscardEdit,
    DiscardSettings,
}

pub struct App {
    config: Config,
    data_dir: PathBuf,
    pub(super) screen: Screen,
    pub(super) help_open: bool,
    pub(super) confirm: Option<Confirm>,
    pub(super) status: Option<Status>,
    pending: Option<Pending>,
    new_vault_kdf: NewVaultKdf,
    /// Generator options, starting from the config and remembered for the
    /// rest of the session.
    gen_settings: GeneratorConfig,
    /// Whether the generator last made a passphrase (vs a password).
    gen_passphrase: bool,
    /// Copies to the system clipboard, cleared after a timeout.
    clipboard: Clipboard,
    quit: bool,
    /// The latest key press, on both clocks so that time spent suspended
    /// counts towards the idle lock (see [`crate::clock`]).
    last_activity: Mark,
    wall: WallClock,
    /// The time of the latest key press or tick, for the clipboard countdown.
    now: Instant,
    /// Time zone timestamps are shown in (UTC in tests, for stable output).
    pub(super) tz: TimeZone,
    /// Rows visible in the entry list at the last render, for paging.
    pub(super) list_height: Cell<usize>,
}

pub(super) enum Screen {
    Picker(PickerState),
    Unlock(UnlockState),
    Unlocked(Box<UnlockedState>),
}

pub(super) struct PickerState {
    pub names: Vec<VaultName>,
    pub selected: usize,
    pub dialog: Option<VaultDialog>,
}

/// A small form over the picker: create, rename or delete a vault.
pub(super) struct VaultDialog {
    pub kind: DialogKind,
    pub form: Form,
    pub error: Option<String>,
    /// The user was warned that the new password is weak and pressed Enter
    /// again; any further edit resets this.
    weak_ok: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum DialogKind {
    Create,
    Rename(VaultName),
    Delete(VaultName),
    /// Over an unlocked vault: read a CSV file.
    Import,
    /// Over an unlocked vault: write a CSV file (suggested path).
    Export(String),
}

/// Cipher options in the "new vault" dialog, matching [`CipherId::ALL`].
const CIPHERS: &[&str] = &["XChaCha20-Poly1305", "AES-256-GCM"];

pub(super) struct UnlockState {
    pub target: VaultTarget,
    /// The password being typed; wiped when this state is dropped.
    pub input: Zeroizing<String>,
    pub reveal: bool,
    pub error: Option<String>,
}

pub(super) struct UnlockedState {
    pub target: VaultTarget,
    pub vault: Vault,
    pub search: Search,
    pub query: String,
    pub searching: bool,
    /// Indices into `vault.entries()` that match `query`, in display order.
    pub filtered: Vec<usize>,
    /// Position within `filtered`.
    pub selected: usize,
    /// First visible row of the list, kept between renders for smooth
    /// scrolling.
    pub scroll: Cell<usize>,
    pub detail: Option<DetailState>,
    pub editor: Option<Editor>,
    /// The generator popup, over the list, detail view or editor.
    pub generator: Option<GeneratorState>,
    /// The vault settings screen.
    pub settings: Option<SettingsState>,
    /// A small form over the vault: CSV import or export.
    pub dialog: Option<VaultDialog>,
    /// Reviewing a CSV file before importing it.
    pub preview: Option<ImportPreview>,
}

pub(super) struct DetailState {
    pub id: Uuid,
    pub reveal: bool,
}

/// The add/edit form for one entry.
pub(super) struct Editor {
    pub form: Form,
    /// The entry being edited, or `None` for a new one.
    pub id: Option<Uuid>,
    /// Strength of the password field, or `None` if it's empty or hidden.
    /// Cached rather than worked out every frame, because zxcvbn makes
    /// copies of the password that it never wipes: once per edit is the
    /// least we can get away with.
    pub strength: Option<Strength>,
}

impl Editor {
    fn new(form: Form, id: Option<Uuid>) -> Self {
        let mut editor = Self {
            form,
            id,
            strength: None,
        };
        editor.refresh_strength();
        editor
    }

    /// Re-judge the password, against the entry's own title and username
    /// (a password containing them is weaker).
    fn refresh_strength(&mut self) {
        let shown = self
            .form
            .rows()
            .iter()
            .any(|r| r.id == RowId::Password && !r.hidden);
        let password = self.form.text(RowId::Password);
        self.strength = (shown && !password.is_empty()).then(|| {
            let hints = [
                self.form.text(RowId::Title),
                self.form.text(RowId::Username),
            ];
            let hints: Vec<&str> = hints.iter().map(|h| h.as_str()).collect();
            Strength::of(&password, &hints)
        });
    }
}

impl UnlockedState {
    fn new(target: VaultTarget, vault: Vault) -> Self {
        let mut state = Self {
            target,
            vault,
            search: Search::default(),
            query: String::new(),
            searching: false,
            filtered: Vec::new(),
            selected: 0,
            scroll: Cell::new(0),
            detail: None,
            editor: None,
            generator: None,
            settings: None,
            dialog: None,
            preview: None,
        };
        state.refilter();
        state
    }

    /// Recompute the visible entries and go back to the top.
    fn refilter(&mut self) {
        self.filtered = self.search.filter(self.vault.entries(), &self.query);
        self.selected = 0;
        self.scroll.set(0);
    }

    /// Recompute the visible entries, keeping the cursor on entry `id` if
    /// it's still listed, or near position `fallback` otherwise.
    fn refilter_keeping(&mut self, id: Option<Uuid>, fallback: usize) {
        self.filtered = self.search.filter(self.vault.entries(), &self.query);
        let entries = self.vault.entries();
        let found = id.and_then(|id| self.filtered.iter().position(|&i| entries[i].id == id));
        self.selected = found
            .unwrap_or(fallback)
            .min(self.filtered.len().saturating_sub(1));
    }

    /// The entry under the cursor in the list.
    pub fn selected_entry(&self) -> Option<&Entry> {
        let &idx = self.filtered.get(self.selected)?;
        self.vault.entries().get(idx)
    }

    /// The entry open in the detail view.
    pub fn detail_entry(&self) -> Option<&Entry> {
        self.vault.entry(self.detail.as_ref()?.id)
    }

    /// The entry an Edit/Delete command applies to: the open one in the
    /// detail view, otherwise the selected one in the list.
    fn current_entry(&self) -> Option<&Entry> {
        if self.detail.is_some() {
            self.detail_entry()
        } else {
            self.selected_entry()
        }
    }
}

impl App {
    /// Start on the unlock screen for `target`, or on the vault picker if
    /// there's no target.
    #[must_use]
    pub fn new(
        config: Config,
        data_dir: PathBuf,
        target: Option<VaultTarget>,
        now: Instant,
    ) -> Self {
        let clear_after = Duration::from_secs(config.clipboard_clear_secs.into());
        let mut app = Self {
            config,
            data_dir,
            screen: Screen::Picker(PickerState {
                names: Vec::new(),
                selected: 0,
                dialog: None,
            }),
            help_open: false,
            confirm: None,
            status: None,
            pending: None,
            new_vault_kdf: NewVaultKdf::Calibrate,
            gen_settings: GeneratorConfig::default(),
            gen_passphrase: false,
            clipboard: Clipboard::system(clear_after),
            quit: false,
            last_activity: Mark::new(now, SystemTime::now()),
            wall: clock::system_wall_clock(),
            now,
            tz: TimeZone::system(),
            list_height: Cell::new(10),
        };
        app.gen_settings = app.config.generator.clone();
        match target {
            Some(target) => app.show_unlock(target),
            None => app.show_picker(None),
        }
        app
    }

    /// Show timestamps in `tz` instead of the system time zone.
    pub fn set_time_zone(&mut self, tz: TimeZone) {
        self.tz = tz;
    }

    /// Use `clipboard` instead of the system clipboard (tests use a fake).
    pub fn set_clipboard(&mut self, mut clipboard: Clipboard) {
        clipboard.set_wall_clock(Rc::clone(&self.wall));
        self.clipboard = clipboard;
    }

    /// Read wall-clock time from `wall` instead of the system, for the idle
    /// lock and the clipboard timer (tests use this to fake a suspend).
    pub fn set_wall_clock(&mut self, wall: WallClock) {
        self.clipboard.set_wall_clock(Rc::clone(&wall));
        // Restart the idle timer on the new clock, as of the latest event.
        self.last_activity = Mark::new(self.now, wall());
        self.wall = wall;
    }

    /// What Lockery has on the clipboard, for the panic and signal handlers.
    #[must_use]
    pub fn clipboard_handle(&self) -> Copied {
        self.clipboard.copied_handle()
    }

    /// Clear anything Lockery put on the clipboard (when quitting).
    pub fn clear_clipboard(&mut self) {
        self.clipboard.clear();
    }

    /// `(what, seconds left)` while a copied value is waiting to be cleared.
    pub(super) fn clipboard_countdown(&self) -> Option<(&'static str, u64)> {
        self.clipboard.countdown(self.now)
    }

    /// Choose how Argon2 is set up for vaults created in the app.
    pub fn set_new_vault_kdf(&mut self, kdf: NewVaultKdf) {
        self.new_vault_kdf = kdf;
    }

    /// Set the status message (e.g. from `main` before the first frame).
    pub fn set_status(&mut self, kind: StatusKind, text: impl Into<String>) {
        self.status = Some(Status {
            text: text.into(),
            kind,
        });
    }

    #[must_use]
    pub fn should_quit(&self) -> bool {
        self.quit
    }

    pub(super) fn config(&self) -> &Config {
        &self.config
    }

    pub(super) fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// The active key mode, overlays included.
    #[must_use]
    pub fn mode(&self) -> Mode {
        if self.help_open {
            Mode::Help
        } else if self.confirm.is_some() {
            Mode::Confirm
        } else {
            self.base_mode()
        }
    }

    /// The mode of the screen itself, ignoring help and confirmations.
    #[must_use]
    pub fn base_mode(&self) -> Mode {
        match &self.screen {
            Screen::Picker(p) if p.dialog.is_some() => Mode::Dialog,
            Screen::Picker(_) => Mode::Picker,
            Screen::Unlock(_) => Mode::Unlock,
            Screen::Unlocked(u) if u.generator.is_some() => Mode::Generator,
            Screen::Unlocked(u) if u.settings.is_some() => Mode::Settings,
            Screen::Unlocked(u) if u.dialog.is_some() => Mode::Dialog,
            Screen::Unlocked(u) if u.preview.is_some() => Mode::Preview,
            Screen::Unlocked(u) if u.editor.is_some() => Mode::Edit,
            Screen::Unlocked(u) if u.detail.is_some() => Mode::Detail,
            Screen::Unlocked(u) if u.searching => Mode::Search,
            Screen::Unlocked(_) => Mode::List,
        }
    }

    /// Whether a vault is currently unlocked.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        matches!(self.screen, Screen::Unlocked(_))
    }

    // -- Input ----------------------------------------------------------------

    /// Handle one key press.
    pub fn on_key(&mut self, key: KeyEvent, now: Instant) {
        // Windows also reports key releases; only presses count. Keys that
        // arrive while slow work is queued are dropped.
        if key.kind != KeyEventKind::Press || self.pending.is_some() {
            return;
        }
        self.last_activity = Mark::new(now, (self.wall)());
        self.now = now;
        let mode = self.mode();

        if let Some(action) = keymap::action_for(mode, &key) {
            // A message stays up until the user does something.
            self.status = None;
            self.perform(action);
        } else if mode.is_text_entry() {
            self.text_input(key);
        }
    }

    /// Called regularly by the event loop: clears the clipboard when its
    /// time is up, and locks the vault when idle.
    pub fn tick(&mut self, now: Instant) {
        self.now = now;
        if self.clipboard.tick(now) {
            self.set_status(StatusKind::Info, "Clipboard cleared.");
        }
        let idle_secs = self.config.idle_lock_secs;
        if idle_secs == 0 || !self.is_unlocked() {
            return;
        }
        let idle = self.last_activity.elapsed(now, (self.wall)());
        if idle >= Duration::from_secs(idle_secs.into()) {
            // Unsaved edits are lost, as with closing a laptop lid on a
            // locked screen: an unattended vault must not stay open.
            self.lock();
            let minutes = idle_secs.div_ceil(60);
            self.set_status(
                StatusKind::Info,
                format!("Locked after {minutes} min of inactivity."),
            );
        }
    }

    fn perform(&mut self, action: Action) {
        match action {
            Action::Quit => self.quit = true,
            Action::Help => self.help_open = true,
            Action::CloseHelp => self.help_open = false,
            Action::Yes => self.answer(true),
            Action::No => self.answer(false),
            Action::Lock => self.lock(),
            Action::SwitchVault => self.switch_vault(),
            _ => match &self.screen {
                Screen::Picker(_) => self.picker_action(action),
                Screen::Unlock(_) => self.unlock_action(action),
                Screen::Unlocked(_) => self.unlocked_action(action),
            },
        }
    }

    /// Keys that aren't commands, in text-entry modes.
    fn text_input(&mut self, key: KeyEvent) {
        let plain_char = match key.code {
            KeyCode::Char(c) if (key.modifiers - KeyModifiers::SHIFT).is_empty() => Some(c),
            _ => None,
        };
        match &mut self.screen {
            Screen::Unlock(u) => {
                if let Some(c) = plain_char {
                    hardening::push_char(&mut u.input, c);
                    u.error = None;
                }
            }
            Screen::Unlocked(u) if u.generator.is_some() => {
                let Some(generator) = &mut u.generator else {
                    return;
                };
                match generator.form.input(key) {
                    FormEvent::Next => generator.form.focus_next(),
                    FormEvent::Changed(id) => generator.on_change(id),
                    FormEvent::Activated(_) | FormEvent::None => {}
                }
            }
            Screen::Unlocked(u) if u.dialog.is_some() => {
                let Some(d) = &mut u.dialog else { return };
                match d.form.input(key) {
                    FormEvent::Next => d.form.focus_next(),
                    FormEvent::Changed(_) => d.error = None,
                    FormEvent::Activated(_) | FormEvent::None => {}
                }
            }
            Screen::Unlocked(u) if u.settings.is_some() => {
                let Some(settings) = &mut u.settings else {
                    return;
                };
                match settings.form.input(key) {
                    FormEvent::Next => settings.form.focus_next(),
                    FormEvent::Changed(_) => settings.on_change(),
                    FormEvent::Activated(RowId::Calibrate) => {
                        self.pending = Some(Pending::Calibrate);
                    }
                    FormEvent::Activated(_) | FormEvent::None => {}
                }
            }
            Screen::Unlocked(u) if u.editor.is_some() => {
                let Some(editor) = &mut u.editor else { return };
                match editor.form.input(key) {
                    FormEvent::Next => editor.form.focus_next(),
                    FormEvent::Changed(id) => {
                        entry_form::on_change(&mut editor.form, id);
                        // Any of password, title, username or type matters.
                        editor.refresh_strength();
                    }
                    FormEvent::Activated(RowId::AddCustom) => {
                        entry_form::add_custom_field(&mut editor.form);
                    }
                    FormEvent::Activated(_) | FormEvent::None => {}
                }
            }
            Screen::Unlocked(u) if u.searching => {
                if let Some(c) = plain_char {
                    u.query.push(c);
                    u.refilter();
                }
            }
            Screen::Picker(PickerState {
                dialog: Some(d), ..
            }) => match d.form.input(key) {
                FormEvent::Next => d.form.focus_next(),
                FormEvent::Changed(_) => {
                    d.error = None;
                    d.weak_ok = false;
                }
                FormEvent::Activated(_) | FormEvent::None => {}
            },
            _ => {}
        }
    }

    // -- Picker and vault dialogs ---------------------------------------------

    fn picker_action(&mut self, action: Action) {
        let Screen::Picker(p) = &mut self.screen else {
            return;
        };

        if let Some(dialog) = &mut p.dialog {
            match action {
                Action::NextField => dialog.form.focus_next(),
                Action::PrevField => dialog.form.focus_prev(),
                Action::ToggleRevealInput => dialog.form.toggle_reveal(),
                Action::Cancel => p.dialog = None,
                Action::Submit => self.submit_dialog(),
                _ => {}
            }
            return;
        }

        let last = p.names.len().saturating_sub(1);
        let selected = p.names.get(p.selected).cloned();
        match action {
            Action::Up => p.selected = p.selected.saturating_sub(1),
            Action::Down => p.selected = (p.selected + 1).min(last),
            Action::Top => p.selected = 0,
            Action::Bottom => p.selected = last,
            Action::Open => {
                if let Some(name) = selected {
                    let target = VaultTarget::named(&name, &self.data_dir);
                    self.show_unlock(target);
                }
            }
            Action::New => p.dialog = Some(VaultDialog::new(DialogKind::Create)),
            Action::Rename => {
                p.dialog = selected.map(|n| VaultDialog::new(DialogKind::Rename(n)));
            }
            Action::Delete => {
                p.dialog = selected.map(|n| VaultDialog::new(DialogKind::Delete(n)));
            }
            _ => {}
        }
    }

    /// Enter in a vault dialog: validate, then act (or queue slow work).
    fn submit_dialog(&mut self) {
        let Screen::Picker(PickerState {
            dialog: Some(d), ..
        }) = &mut self.screen
        else {
            return;
        };
        let result = match d.kind.clone() {
            // Only shown over an unlocked vault, never on the picker.
            DialogKind::Import | DialogKind::Export(_) => return,
            DialogKind::Create => d
                .validate_create(&self.data_dir)
                .map(|()| Some(Pending::CreateVault)),
            DialogKind::Delete(name) => d
                .validate_delete(&name)
                .map(|()| Some(Pending::DeleteVault)),
            DialogKind::Rename(old) => d.validate_rename(&old).map(|new| {
                self.rename_vault(&old, &new);
                None
            }),
        };
        match result {
            Ok(pending) => self.pending = pending,
            Err(message) => {
                if let Screen::Picker(PickerState {
                    dialog: Some(d), ..
                }) = &mut self.screen
                {
                    d.error = Some(message);
                }
            }
        }
    }

    fn rename_vault(&mut self, old: &VaultName, new: &VaultName) {
        if old == new {
            self.close_dialog();
            return;
        }
        match manage::rename_vault(&self.data_dir, old, new) {
            Ok(()) => {
                self.show_picker(Some(new.as_str()));
                if old.as_str() == self.config.primary_vault {
                    self.set_status(
                        StatusKind::Warning,
                        format!(
                            "Renamed. '{old}' was your primary vault: set primary_vault = \"{new}\" in the config file."
                        ),
                    );
                } else {
                    self.set_status(StatusKind::Info, format!("Renamed '{old}' to '{new}'."));
                }
            }
            Err(e) => self.dialog_error(describe_error(&e)),
        }
    }

    fn close_dialog(&mut self) {
        if let Screen::Picker(p) = &mut self.screen {
            p.dialog = None;
        }
    }

    fn dialog_error(&mut self, message: String) {
        if let Screen::Picker(PickerState {
            dialog: Some(d), ..
        }) = &mut self.screen
        {
            d.error = Some(message);
        }
    }

    // -- Unlock screen --------------------------------------------------------

    fn unlock_action(&mut self, action: Action) {
        let Screen::Unlock(u) = &mut self.screen else {
            return;
        };
        match action {
            Action::Submit if u.input.is_empty() => {
                u.error = Some("Type the master password first.".into());
            }
            Action::Submit => {
                u.error = None;
                self.pending = Some(Pending::Unlock);
            }
            Action::Backspace => {
                hardening::pop_char(&mut u.input);
            }
            Action::ToggleRevealInput => u.reveal = !u.reveal,
            _ => {}
        }
    }

    // -- Unlocked vault: list, detail, editor ---------------------------------

    fn unlocked_action(&mut self, action: Action) {
        let page = self.list_height.get().max(1);
        let Screen::Unlocked(u) = &mut self.screen else {
            return;
        };

        if u.generator.is_some() {
            self.generator_action(action);
            return;
        }
        if u.settings.is_some() {
            self.settings_action(action);
            return;
        }
        if u.dialog.is_some() {
            self.transfer_dialog_action(action);
            return;
        }
        if u.preview.is_some() {
            self.preview_action(action);
            return;
        }
        if u.editor.is_some() {
            self.editor_action(action);
            return;
        }

        if self.entry_command(action) {
            return;
        }
        let Screen::Unlocked(u) = &mut self.screen else {
            return;
        };

        if let Some(detail) = &mut u.detail {
            match action {
                Action::Back => u.detail = None,
                Action::ToggleReveal => detail.reveal = !detail.reveal,
                _ => {}
            }
            return;
        }

        let last = u.filtered.len().saturating_sub(1);
        match action {
            Action::Up => u.selected = u.selected.saturating_sub(1),
            Action::Down => u.selected = (u.selected + 1).min(last),
            Action::PageUp => u.selected = u.selected.saturating_sub(page),
            Action::PageDown => u.selected = (u.selected + page).min(last),
            Action::Top => u.selected = 0,
            Action::Bottom => u.selected = last,
            Action::Open => {
                if let Some(id) = u.selected_entry().map(|e| e.id) {
                    u.detail = Some(DetailState { id, reveal: false });
                }
            }
            Action::Search => u.searching = true,
            Action::AcceptSearch => u.searching = false,
            Action::ClearSearch => {
                u.searching = false;
                if !u.query.is_empty() {
                    u.query.clear();
                    u.refilter();
                }
            }
            Action::Backspace => {
                u.query.pop();
                u.refilter();
            }
            _ => {}
        }
    }

    /// Keys in the generator popup.
    fn generator_action(&mut self, action: Action) {
        let Screen::Unlocked(u) = &mut self.screen else {
            return;
        };
        let Some(generator) = &mut u.generator else {
            return;
        };
        match action {
            Action::NextField => generator.form.focus_next(),
            Action::PrevField => generator.form.focus_prev(),
            Action::Regenerate => generator.regenerate(),
            Action::UseGenerated => self.use_generated(),
            Action::Cancel => {
                self.gen_settings = generator.settings();
                self.gen_passphrase = generator.form.choice(RowId::GenKind) == 1;
                u.generator = None;
            }
            _ => {}
        }
    }

    /// Commands shared by the list and the detail view. Returns whether
    /// `action` was one of them.
    fn entry_command(&mut self, action: Action) -> bool {
        let Screen::Unlocked(u) = &mut self.screen else {
            return false;
        };
        match action {
            Action::CopyPassword | Action::CopyUsername => {
                let Some(entry) = u.current_entry() else {
                    return true;
                };
                let (value, what) = if action == Action::CopyPassword {
                    (Zeroizing::new(entry.password.clone()), "password")
                } else {
                    (Zeroizing::new(entry.username.clone()), "username")
                };
                let title = entry.title.clone();
                self.copy_to_clipboard(&value, what, &title);
            }
            Action::Import => {
                u.dialog = Some(VaultDialog::new(DialogKind::Import));
            }
            Action::Export => {
                let path = transfer::default_export_path(u.vault.path());
                u.dialog = Some(VaultDialog::new(DialogKind::Export(path)));
            }
            Action::Settings => {
                u.settings = Some(SettingsState::new(&u.vault));
            }
            Action::Generate => {
                u.generator = Some(GeneratorState::new(
                    &self.gen_settings,
                    GeneratorTarget::NewEntry,
                    self.gen_passphrase,
                ));
            }
            Action::New => {
                u.editor = Some(Editor::new(entry_form::build(None), None));
            }
            Action::Edit => {
                if let Some(entry) = u.current_entry() {
                    let editor = Editor::new(entry_form::build(Some(entry)), Some(entry.id));
                    u.editor = Some(editor);
                }
            }
            Action::Delete => {
                if let Some(entry) = u.current_entry() {
                    self.confirm = Some(Confirm {
                        question: format!("Delete “{}”? This can't be undone.", entry.title),
                        on_yes: ConfirmAction::DeleteEntry(entry.id),
                    });
                }
            }
            _ => return false,
        }
        true
    }

    /// Copy `value` (the `what` of entry `title`) and say so.
    fn copy_to_clipboard(&mut self, value: &str, what: &'static str, title: &str) {
        if value.is_empty() {
            self.set_status(StatusKind::Warning, format!("“{title}” has no {what}."));
            return;
        }
        match self.clipboard.copy(value, what, self.now) {
            Ok(()) => {
                let secs = self.config.clipboard_clear_secs;
                let mut first = what.chars();
                let what = first
                    .next()
                    .map(|c| c.to_uppercase().chain(first).collect::<String>())
                    .unwrap_or_default();
                self.set_status(
                    StatusKind::Info,
                    format!("{what} copied. The clipboard clears in {secs} s."),
                );
            }
            Err(e) => self.set_status(StatusKind::Error, format!("Couldn't copy: {e}")),
        }
    }

    /// Keys in the CSV import/export dialogs.
    fn transfer_dialog_action(&mut self, action: Action) {
        let Screen::Unlocked(u) = &mut self.screen else {
            return;
        };
        let Some(dialog) = &mut u.dialog else { return };
        match action {
            Action::NextField => dialog.form.focus_next(),
            Action::PrevField => dialog.form.focus_prev(),
            Action::ToggleRevealInput => dialog.form.toggle_reveal(),
            Action::Cancel => u.dialog = None,
            Action::Submit => {
                let path_text = dialog.form.text(RowId::FilePath);
                if path_text.trim().is_empty() {
                    dialog.error = Some("Enter a file path.".into());
                    return;
                }
                let path = transfer::expand_path(&path_text);
                match dialog.kind {
                    DialogKind::Import => match ImportPreview::load(&path, u.vault.entries()) {
                        Ok(preview) => {
                            u.dialog = None;
                            u.preview = Some(preview);
                        }
                        Err(message) => dialog.error = Some(message),
                    },
                    DialogKind::Export(_) => {
                        if path.exists() {
                            dialog.error = Some(format!(
                                "{} already exists; choose another name.",
                                transfer::display_path(&path)
                            ));
                        } else if dialog.form.text(RowId::MasterPassword).is_empty() {
                            dialog.form.focus_row(RowId::MasterPassword);
                            dialog.error = Some("Enter the master password to export.".into());
                        } else {
                            self.pending = Some(Pending::Export);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// Keys on the import preview.
    fn preview_action(&mut self, action: Action) {
        let Screen::Unlocked(u) = &mut self.screen else {
            return;
        };
        let Some(preview) = &mut u.preview else {
            return;
        };
        let last = preview.entries.len().saturating_sub(1);
        match action {
            Action::Up => preview.scroll = preview.scroll.saturating_sub(1),
            Action::Down => preview.scroll = (preview.scroll + 1).min(last),
            Action::ToggleDuplicates => preview.include_duplicates = !preview.include_duplicates,
            Action::Cancel => u.preview = None,
            Action::Submit => {
                let Some(preview) = u.preview.take() else {
                    return;
                };
                let source = transfer::display_path(&preview.source);
                let entries = preview.into_entries();
                if entries.is_empty() {
                    self.set_status(StatusKind::Info, "Nothing new to import.");
                    return;
                }
                match u.vault.add_many(entries) {
                    Ok(count) => {
                        u.refilter();
                        self.set_status(
                            StatusKind::Warning,
                            format!(
                                "Imported {count} entries. Delete {source}: it holds your passwords in plain text."
                            ),
                        );
                    }
                    Err(e) => self.set_status(StatusKind::Error, format!("Not imported: {e}")),
                }
            }
            _ => {}
        }
    }

    /// Keys on the settings screen.
    fn settings_action(&mut self, action: Action) {
        let Screen::Unlocked(u) = &mut self.screen else {
            return;
        };
        let Some(settings) = &mut u.settings else {
            return;
        };
        match action {
            Action::NextField => settings.form.focus_next(),
            Action::PrevField => settings.form.focus_prev(),
            Action::ToggleRevealInput => settings.form.toggle_reveal(),
            Action::Save => match settings.validate(&u.vault) {
                Ok(_) => self.pending = Some(Pending::Rekey),
                Err(message) => settings.error = Some(message),
            },
            Action::Cancel if settings.form.dirty => {
                self.confirm = Some(Confirm {
                    question: "Discard the settings you changed?".into(),
                    on_yes: ConfirmAction::DiscardSettings,
                });
            }
            Action::Cancel => u.settings = None,
            _ => {}
        }
    }

    /// Keys in the entry editor.
    fn editor_action(&mut self, action: Action) {
        let Screen::Unlocked(u) = &mut self.screen else {
            return;
        };
        let Some(editor) = &mut u.editor else { return };
        match action {
            Action::Generate => {
                u.generator = Some(GeneratorState::new(
                    &self.gen_settings,
                    GeneratorTarget::Editor,
                    self.gen_passphrase,
                ));
            }
            Action::NextField => editor.form.focus_next(),
            Action::PrevField => editor.form.focus_prev(),
            Action::ToggleRevealInput => editor.form.toggle_reveal(),
            Action::Save => self.save_entry(),
            Action::Cancel if editor.form.dirty => {
                self.confirm = Some(Confirm {
                    question: "Discard your changes?".into(),
                    on_yes: ConfirmAction::DiscardEdit,
                });
            }
            Action::Cancel => u.editor = None,
            _ => {}
        }
    }

    /// Ctrl-s in the editor: validate and save, then show the saved entry.
    fn save_entry(&mut self) {
        let Screen::Unlocked(u) = &mut self.screen else {
            return;
        };
        let Some(editor) = &mut u.editor else { return };

        let Some(title) = entry_form::title(&editor.form) else {
            editor.form.focus_row(RowId::Title);
            self.set_status(StatusKind::Error, "A title is required.");
            return;
        };

        let result = if let Some(id) = editor.id {
            u.vault
                .update(id, |e| entry_form::apply(&editor.form, e))
                .map(|()| id)
        } else {
            // `apply` sets the real kind; Login is just a starting value.
            let mut entry = Entry::new(crate::vault::EntryKind::Login, title.clone());
            entry_form::apply(&editor.form, &mut entry);
            u.vault.add(entry)
        };

        match result {
            Ok(id) => {
                u.editor = None;
                u.refilter_keeping(Some(id), u.selected);
                u.detail = Some(DetailState { id, reveal: false });
                self.set_status(StatusKind::Info, format!("Saved “{title}”."));
            }
            // The vault (memory and disk) is unchanged; keep the form open.
            Err(e) => self.set_status(StatusKind::Error, format!("Not saved: {e}")),
        }
    }

    /// Enter in the generator: put the value where it was asked for.
    fn use_generated(&mut self) {
        let Screen::Unlocked(u) = &mut self.screen else {
            return;
        };
        let Some(generator) = u.generator.take() else {
            return;
        };
        self.gen_settings = generator.settings();
        self.gen_passphrase = generator.form.choice(RowId::GenKind) == 1;
        if !generator.has_value() {
            // Nothing to use; keep the popup open so the options can be fixed.
            u.generator = Some(generator);
            return;
        }

        match generator.target {
            GeneratorTarget::Editor => {
                if let Some(editor) = &mut u.editor {
                    editor.form.set_text(RowId::Password, &generator.value);
                    editor.form.focus_row(RowId::Password);
                    editor.refresh_strength();
                }
            }
            GeneratorTarget::NewEntry => {
                let mut form = entry_form::build(None);
                form.set_text(RowId::Password, &generator.value);
                u.detail = None;
                u.editor = Some(Editor::new(form, None));
            }
        }
        self.set_status(
            StatusKind::Info,
            "Generated value filled in; it's saved with the entry.",
        );
        // `generator` drops here, wiping its copy of the value.
    }

    /// Handle y/n on a confirmation.
    fn answer(&mut self, yes: bool) {
        let Some(confirm) = self.confirm.take() else {
            return;
        };
        if !yes {
            return;
        }
        let Screen::Unlocked(u) = &mut self.screen else {
            return;
        };
        match confirm.on_yes {
            ConfirmAction::DiscardEdit => u.editor = None,
            ConfirmAction::DiscardSettings => u.settings = None,
            ConfirmAction::DeleteEntry(id) => match u.vault.delete(id) {
                Ok(removed) => {
                    u.detail = None;
                    let at = u.selected;
                    u.refilter_keeping(None, at);
                    self.set_status(StatusKind::Info, format!("Deleted “{}”.", removed.title));
                }
                Err(e) => self.set_status(StatusKind::Error, format!("Not deleted: {e}")),
            },
        }
    }

    // -- Slow work ------------------------------------------------------------

    /// Whether slow work is queued; the event loop should draw a frame (which
    /// shows [`App::busy_message`]) and then call [`App::run_pending`].
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// What to show while the pending work runs.
    #[must_use]
    pub fn busy_message(&self) -> Option<&'static str> {
        self.pending.map(|p| match p {
            Pending::Unlock => "Unlocking…",
            Pending::CreateVault => "Creating vault (tuning Argon2)…",
            Pending::DeleteVault => "Checking password…",
            Pending::Calibrate => "Measuring this machine…",
            Pending::Rekey => "Re-encrypting the vault…",
            Pending::Export => "Checking password and exporting…",
        })
    }

    /// Run the queued slow work. Blocks while Argon2 runs.
    pub fn run_pending(&mut self) {
        match self.pending.take() {
            Some(Pending::Unlock) => self.finish_unlock(),
            Some(Pending::CreateVault) => self.finish_create_vault(),
            Some(Pending::DeleteVault) => self.finish_delete_vault(),
            Some(Pending::Calibrate) => self.finish_calibrate(),
            Some(Pending::Rekey) => self.finish_rekey(),
            Some(Pending::Export) => self.finish_export(),
            None => {}
        }
    }

    fn finish_unlock(&mut self) {
        let Screen::Unlock(u) = &mut self.screen else {
            return;
        };
        match Vault::unlock(&u.target.path, u.input.as_bytes()) {
            Ok(vault) => {
                let target = u.target.clone();
                if self.config.security.lock_memory && hardening::take_lock_failure() {
                    self.set_status(StatusKind::Warning, hardening::LOCK_FAILURE_ADVICE);
                }
                // Checked second so this more urgent message wins.
                if let Some(aside) = vault.recovered_from_backup() {
                    self.set_status(
                        StatusKind::Warning,
                        format!(
                            "Vault file was damaged and restored from its backup; damaged copy kept at {}",
                            aside.display()
                        ),
                    );
                }
                // Replacing the screen drops `u`, wiping the typed password.
                self.screen = Screen::Unlocked(Box::new(UnlockedState::new(target, vault)));
            }
            Err(e) => {
                u.input.zeroize(); // wipes, keeping the pre-sized buffer
                u.error = Some(describe_error(&e));
            }
        }
    }

    fn finish_create_vault(&mut self) {
        let Screen::Picker(PickerState {
            dialog: Some(d), ..
        }) = &self.screen
        else {
            return;
        };
        // Already validated by `validate_create`.
        let Ok(name) = VaultName::parse(d.form.text(RowId::VaultName).trim()) else {
            return;
        };
        let password = d.form.text(RowId::NewPassword);
        let cipher = CipherId::ALL[d.form.choice(RowId::Cipher)];

        let kdf = match self.new_vault_kdf {
            NewVaultKdf::Fixed(params) => Ok(params),
            NewVaultKdf::Calibrate => calibrate::calibrate(DEFAULT_TARGET),
        };
        let target = VaultTarget::named(&name, &self.data_dir);
        let created = kdf.and_then(|kdf| {
            paths::ensure_dir(&self.data_dir)?;
            Vault::create(&target.path, password.as_bytes(), kdf, cipher)
        });

        match created {
            Ok(vault) => {
                self.screen = Screen::Unlocked(Box::new(UnlockedState::new(target, vault)));
                self.set_status(
                    StatusKind::Info,
                    format!("Created vault '{name}'. Press n to add your first entry."),
                );
            }
            Err(e) => self.dialog_error(describe_error(&e)),
        }
    }

    fn finish_delete_vault(&mut self) {
        let Screen::Picker(PickerState {
            dialog: Some(d), ..
        }) = &self.screen
        else {
            return;
        };
        let DialogKind::Delete(name) = d.kind.clone() else {
            return;
        };
        let password = d.form.text(RowId::MasterPassword);

        match manage::delete_vault(&self.data_dir, &name, password.as_bytes()) {
            Ok(()) => {
                self.show_picker(None);
                self.set_status(StatusKind::Info, format!("Deleted vault '{name}'."));
            }
            Err(e) => self.dialog_error(describe_error(&e)),
        }
    }

    fn finish_export(&mut self) {
        let Screen::Unlocked(u) = &mut self.screen else {
            return;
        };
        let Some(dialog) = &mut u.dialog else { return };
        let password = dialog.form.text(RowId::MasterPassword);
        let path = transfer::expand_path(&dialog.form.text(RowId::FilePath));

        if let Err(e) = u.vault.verify_password(password.as_bytes()) {
            dialog.form.set_text(RowId::MasterPassword, "");
            dialog.error = Some(describe_error(&e));
            return;
        }
        let written = crate::csv_io::export_bitwarden(u.vault.entries()).and_then(|exported| {
            crate::csv_io::write_new_private_file(&path, &exported.csv)?;
            Ok(exported.warnings)
        });
        match written {
            Ok(warnings) => {
                u.dialog = None;
                let mut message = format!(
                    "Exported {} entries to {} in Bitwarden format. It's plain text: delete it once you've used it.",
                    u.vault.entries().len(),
                    transfer::display_path(&path)
                );
                for warning in warnings {
                    message.push(' ');
                    message.push_str(&warning);
                }
                self.set_status(StatusKind::Warning, message);
            }
            Err(e) => dialog.error = Some(e.to_string()),
        }
    }

    fn finish_calibrate(&mut self) {
        let kdf = match self.new_vault_kdf {
            NewVaultKdf::Fixed(params) => Ok(params),
            NewVaultKdf::Calibrate => calibrate::calibrate(DEFAULT_TARGET),
        };
        let Screen::Unlocked(u) = &mut self.screen else {
            return;
        };
        let Some(settings) = &mut u.settings else {
            return;
        };
        match kdf {
            Ok(kdf) => {
                settings.set_kdf(kdf);
                settings.error = None;
                self.set_status(
                    StatusKind::Info,
                    "Argon2 tuned for this machine. Ctrl-s to apply.",
                );
            }
            Err(e) => settings.error = Some(e.to_string()),
        }
    }

    fn finish_rekey(&mut self) {
        let Screen::Unlocked(u) = &mut self.screen else {
            return;
        };
        let Some(settings) = &mut u.settings else {
            return;
        };
        let change = match settings.change() {
            Ok(change) => change,
            Err(message) => {
                settings.error = Some(message);
                return;
            }
        };
        let new_password = change.new_password.as_ref().map(|p| p.as_bytes());
        let result = u.vault.rekey(
            change.current_password.as_bytes(),
            new_password,
            change.kdf,
            change.cipher,
        );
        match result {
            Ok(()) => {
                u.settings = None;
                let mut message = format!(
                    "Vault re-encrypted: {}.",
                    crypto::describe(change.cipher, change.kdf)
                );
                if change.new_password.is_some() {
                    message.push_str(" New master password set.");
                }
                self.set_status(StatusKind::Info, message);
            }
            Err(e @ Error::BackupNotRefreshed(_)) => {
                u.settings = None;
                self.set_status(StatusKind::Warning, e.to_string());
            }
            Err(Error::Decryption) => {
                settings.form.set_text(RowId::MasterPassword, "");
                settings.form.focus_row(RowId::MasterPassword);
                settings.error = Some("The current password is wrong.".into());
            }
            Err(e) => settings.error = Some(format!("Not changed: {e}")),
        }
    }

    // -- Screen changes -------------------------------------------------------

    fn show_unlock(&mut self, target: VaultTarget) {
        self.screen = Screen::Unlock(UnlockState {
            target,
            input: Zeroizing::new(String::with_capacity(256)),
            reveal: false,
            error: None,
        });
    }

    /// Show the vault picker, with `select` highlighted if it's listed.
    fn show_picker(&mut self, select: Option<&str>) {
        let names = match paths::list_vaults(&self.data_dir) {
            Ok(names) => names,
            Err(e) => {
                self.set_status(StatusKind::Error, e.to_string());
                Vec::new()
            }
        };
        let want = select.unwrap_or(&self.config.primary_vault);
        let selected = names.iter().position(|n| n.as_str() == want).unwrap_or(0);
        self.screen = Screen::Picker(PickerState {
            names,
            selected,
            dialog: None,
        });
    }

    /// Lock the open vault: drop it (wiping the key, entries and any open
    /// editor) and return to its unlock screen. Does nothing if no vault is
    /// open.
    pub fn lock(&mut self) {
        if let Screen::Unlocked(u) = &self.screen {
            let target = u.target.clone();
            self.help_open = false;
            self.confirm = None;
            self.clipboard.clear();
            self.show_unlock(target); // drops the unlocked state
        }
    }

    /// Lock the open vault (if any) and go to the picker.
    fn switch_vault(&mut self) {
        let current = match &self.screen {
            Screen::Unlock(u) => Some(u.target.label.clone()),
            Screen::Unlocked(u) => Some(u.target.label.clone()),
            Screen::Picker(_) => None,
        };
        self.help_open = false;
        self.confirm = None;
        self.clipboard.clear();
        self.show_picker(current.as_deref());
    }
}

impl VaultDialog {
    fn new(kind: DialogKind) -> Self {
        let rows = match &kind {
            DialogKind::Create => vec![
                Row::text(RowId::VaultName, "Name", "").with_placeholder("letters, digits, - or _"),
                Row::secret(RowId::NewPassword, "Master password", ""),
                Row::secret(RowId::RepeatPassword, "Repeat password", ""),
                Row::choice(RowId::Cipher, "Cipher", CIPHERS, 0),
            ],
            DialogKind::Rename(name) => {
                vec![Row::text(RowId::VaultName, "New name", name.as_str())]
            }
            DialogKind::Delete(_) => vec![
                Row::secret(RowId::MasterPassword, "Master password", ""),
                Row::text(RowId::ConfirmName, "Type its name", ""),
            ],
            DialogKind::Import => vec![
                Row::text(RowId::FilePath, "CSV file", "")
                    .with_placeholder("e.g. ~/Downloads/bitwarden_export.csv"),
            ],
            DialogKind::Export(path) => vec![
                Row::text(RowId::FilePath, "Save to", path),
                Row::secret(RowId::MasterPassword, "Master password", ""),
            ],
        };
        Self {
            kind,
            form: Form::new(rows),
            error: None,
            weak_ok: false,
        }
    }

    fn validate_create(&mut self, data_dir: &Path) -> Result<(), String> {
        let raw_name = self.form.text(RowId::VaultName);
        let name = VaultName::parse(raw_name.trim()).map_err(|e| e.to_string())?;
        if name.path_in(data_dir).exists() {
            return Err(format!("A vault named '{name}' already exists."));
        }
        let password = self.form.text(RowId::NewPassword);
        if password.is_empty() {
            return Err("The master password can't be empty.".into());
        }
        if *self.form.text(RowId::RepeatPassword) != *password {
            return Err("The passwords don't match.".into());
        }
        let weak = Strength::of(&password, &[name.as_str()]).is_weak();
        if weak && !self.weak_ok {
            self.weak_ok = true;
            return Err(
                "That password is easy to guess. Press Enter again to use it anyway.".into(),
            );
        }
        Ok(())
    }

    fn validate_rename(&self, _old: &VaultName) -> Result<VaultName, String> {
        let raw_name = self.form.text(RowId::VaultName);
        VaultName::parse(raw_name.trim()).map_err(|e| e.to_string())
    }

    fn validate_delete(&self, name: &VaultName) -> Result<(), String> {
        if self.form.text(RowId::ConfirmName).trim() != name.as_str() {
            return Err(format!("Type '{name}' exactly to confirm."));
        }
        if self.form.text(RowId::MasterPassword).is_empty() {
            return Err("Enter the vault's master password.".into());
        }
        Ok(())
    }
}

/// A short, friendly message for errors the user can cause.
fn describe_error(e: &Error) -> String {
    match e {
        Error::Decryption => "Wrong password.".into(),
        Error::VaultLocked(_) => "This vault is open in another Lockery.".into(),
        Error::VaultExists(_) => "A vault with that name already exists.".into(),
        other => other.to_string(),
    }
}
