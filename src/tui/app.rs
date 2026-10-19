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
//!     ▲                │  ▲                                  │
//!     └──────Tab───────┘  └──────────L (lock) / idle─────────┤
//!     └──────────────────────────V (switch vault)────────────┘
//! ```

use std::cell::Cell;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use jiff::tz::TimeZone;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::keymap::{self, Action, Mode};
use super::search::Search;
use crate::config::Config;
use crate::error::Error;
use crate::paths::{self, VaultName};
use crate::vault::{Entry, Vault};

/// Which vault to unlock: a display label and its file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultTarget {
    pub label: String,
    pub path: PathBuf,
}

impl VaultTarget {
    /// The target for a named vault in `data_dir`.
    #[must_use]
    pub fn named(name: &VaultName, data_dir: &std::path::Path) -> Self {
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

pub struct App {
    config: Config,
    data_dir: PathBuf,
    pub(super) screen: Screen,
    pub(super) help_open: bool,
    pub(super) status: Option<Status>,
    quit: bool,
    last_activity: Instant,
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
}

pub(super) struct UnlockState {
    pub target: VaultTarget,
    /// The password being typed; wiped when this state is dropped.
    pub input: Zeroizing<String>,
    pub reveal: bool,
    pub error: Option<String>,
    /// Enter was pressed; the (slow) unlock runs after the next redraw so
    /// "Unlocking..." is visible while Argon2 works.
    pub busy: bool,
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
}

pub(super) struct DetailState {
    pub id: Uuid,
    pub reveal: bool,
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
        };
        state.refilter();
        state
    }

    fn refilter(&mut self) {
        self.filtered = self.search.filter(self.vault.entries(), &self.query);
        self.selected = 0;
        self.scroll.set(0);
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
        let mut app = Self {
            config,
            data_dir,
            screen: Screen::Picker(PickerState {
                names: Vec::new(),
                selected: 0,
            }),
            help_open: false,
            status: None,
            quit: false,
            last_activity: now,
            tz: TimeZone::system(),
            list_height: Cell::new(10),
        };
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

    pub(super) fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    /// The active key mode (help overlay included).
    #[must_use]
    pub fn mode(&self) -> Mode {
        if self.help_open {
            Mode::Help
        } else {
            self.base_mode()
        }
    }

    /// The mode of the screen itself, ignoring the help overlay.
    #[must_use]
    pub fn base_mode(&self) -> Mode {
        match &self.screen {
            Screen::Picker(_) => Mode::Picker,
            Screen::Unlock(_) => Mode::Unlock,
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
        // Windows also reports key releases; only presses count.
        if key.kind != KeyEventKind::Press {
            return;
        }
        self.last_activity = now;
        let mode = self.mode();

        if let Some(action) = keymap::action_for(mode, &key) {
            // A message stays up until the user does something.
            self.status = None;
            self.perform(action);
        } else if mode.is_text_entry()
            && let KeyCode::Char(c) = key.code
            && (key.modifiers - KeyModifiers::SHIFT).is_empty()
        {
            self.type_char(c);
        }
    }

    /// Called regularly by the event loop; locks the vault when idle.
    pub fn tick(&mut self, now: Instant) {
        let idle_secs = self.config.idle_lock_secs;
        if idle_secs == 0 || !self.is_unlocked() {
            return;
        }
        if now.duration_since(self.last_activity) >= Duration::from_secs(idle_secs.into()) {
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
            Action::Lock => self.lock(),
            Action::SwitchVault => self.switch_vault(),
            _ => {
                let page = self.list_height.get();
                let chosen = match &mut self.screen {
                    Screen::Picker(p) => {
                        Self::picker_action(p, action, &self.data_dir, &mut self.status)
                    }
                    Screen::Unlock(u) => {
                        Self::unlock_action(u, action);
                        None
                    }
                    Screen::Unlocked(u) => {
                        Self::unlocked_action(u, action, page);
                        None
                    }
                };
                if let Some(target) = chosen {
                    self.show_unlock(target);
                }
            }
        }
    }

    /// Returns the vault to unlock if one was chosen.
    fn picker_action(
        p: &mut PickerState,
        action: Action,
        data_dir: &std::path::Path,
        status: &mut Option<Status>,
    ) -> Option<VaultTarget> {
        let last = p.names.len().saturating_sub(1);
        match action {
            Action::Up => p.selected = p.selected.saturating_sub(1),
            Action::Down => p.selected = (p.selected + 1).min(last),
            Action::Top => p.selected = 0,
            Action::Bottom => p.selected = last,
            Action::Refresh => match paths::list_vaults(data_dir) {
                Ok(names) => {
                    p.names = names;
                    p.selected = p.selected.min(p.names.len().saturating_sub(1));
                }
                Err(e) => {
                    *status = Some(Status {
                        text: e.to_string(),
                        kind: StatusKind::Error,
                    });
                }
            },
            Action::Open => {
                return p
                    .names
                    .get(p.selected)
                    .map(|n| VaultTarget::named(n, data_dir));
            }
            _ => {}
        }
        None
    }

    fn unlock_action(u: &mut UnlockState, action: Action) {
        match action {
            Action::Submit if u.input.is_empty() => {
                u.error = Some("Type the master password first.".into());
            }
            Action::Submit => {
                u.error = None;
                u.busy = true;
            }
            Action::Backspace => {
                u.input.pop();
            }
            Action::ToggleRevealInput => u.reveal = !u.reveal,
            _ => {}
        }
    }

    fn unlocked_action(u: &mut UnlockedState, action: Action, page: usize) {
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
            Action::PageUp => u.selected = u.selected.saturating_sub(page.max(1)),
            Action::PageDown => u.selected = (u.selected + page.max(1)).min(last),
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

    fn type_char(&mut self, c: char) {
        match &mut self.screen {
            Screen::Unlock(u) if !u.busy => {
                u.input.push(c);
                u.error = None;
            }
            Screen::Unlocked(u) if u.searching => {
                u.query.push(c);
                u.refilter();
            }
            _ => {}
        }
    }

    // -- Unlocking ------------------------------------------------------------

    /// Whether Enter was pressed on the unlock screen and the slow unlock
    /// should now run (after the "Unlocking..." frame has been drawn).
    #[must_use]
    pub fn unlock_pending(&self) -> bool {
        matches!(&self.screen, Screen::Unlock(u) if u.busy)
    }

    /// Run the pending unlock. Blocks for as long as Argon2 takes.
    pub fn perform_unlock(&mut self) {
        let Screen::Unlock(u) = &mut self.screen else {
            return;
        };
        if !u.busy {
            return;
        }
        u.busy = false;

        match Vault::unlock(&u.target.path, u.input.as_bytes()) {
            Ok(vault) => {
                let target = u.target.clone();
                if let Some(aside) = vault.recovered_from_backup() {
                    self.status = Some(Status {
                        kind: StatusKind::Warning,
                        text: format!(
                            "Vault file was damaged and restored from its backup; damaged copy kept at {}",
                            aside.display()
                        ),
                    });
                }
                // Replacing the screen drops `u`, wiping the typed password.
                self.screen = Screen::Unlocked(Box::new(UnlockedState::new(target, vault)));
            }
            Err(e) => {
                u.input.clear();
                u.error = Some(match e {
                    Error::Decryption => "Wrong password.".into(),
                    Error::VaultLocked(_) => {
                        "This vault is already open in another Lockery.".into()
                    }
                    other => other.to_string(),
                });
            }
        }
    }

    // -- Screen changes -------------------------------------------------------

    fn show_unlock(&mut self, target: VaultTarget) {
        self.screen = Screen::Unlock(UnlockState {
            target,
            input: Zeroizing::new(String::with_capacity(256)),
            reveal: false,
            error: None,
            busy: false,
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
        self.screen = Screen::Picker(PickerState { names, selected });
    }

    /// Lock the open vault: drop it (wiping the key and entries) and return
    /// to its unlock screen. Does nothing if no vault is open.
    pub fn lock(&mut self) {
        if let Screen::Unlocked(u) = &self.screen {
            let target = u.target.clone();
            self.help_open = false;
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
        self.show_picker(current.as_deref());
    }
}
