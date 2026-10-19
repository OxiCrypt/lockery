//! TUI tests: behaviour driven through [`App::on_key`], plus snapshots of
//! each screen rendered on ratatui's in-memory `TestBackend`.
//!
//! Snapshots live in `src/tui/snapshots/`. After an intentional UI change,
//! review and accept new ones with `cargo insta review` (or rerun the tests
//! with `INSTA_UPDATE=always` and check the diff in git).

use std::path::Path;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use jiff::Timestamp;
use jiff::tz::TimeZone;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use tempfile::TempDir;

use super::app::{App, VaultTarget};
use super::keymap::Mode;
use super::ui;
use crate::config::Config;
use crate::crypto::{CipherId, test_params};
use crate::paths::VaultName;
use crate::vault::{CustomField, Entry, EntryKind, Vault};

const PASSWORD: &str = "pw";

/// A data dir with two vaults: `default` (three entries) and `work` (empty).
fn setup() -> TempDir {
    let dir = TempDir::new().unwrap();
    let mut vault = Vault::create(
        dir.path().join("default.lockery"),
        PASSWORD.as_bytes(),
        test_params(),
        CipherId::default(),
    )
    .unwrap();
    for entry in sample_entries() {
        vault.add(entry).unwrap();
    }
    drop(vault);
    drop(
        Vault::create(
            dir.path().join("work.lockery"),
            PASSWORD.as_bytes(),
            test_params(),
            CipherId::default(),
        )
        .unwrap(),
    );
    dir
}

fn sample_entries() -> Vec<Entry> {
    let t = Timestamp::from_second(1_700_000_000).unwrap();

    let mut github = Entry::new(EntryKind::Login, "GitHub");
    github.username = "octocat".into();
    github.password = "hunter2-but-longer".into();
    github.urls = vec!["https://github.com".into()];
    github.tags = vec!["dev".into()];
    github.favorite = true;

    let mut bank = Entry::new(EntryKind::Login, "Bank");
    bank.username = "alice".into();
    bank.password = "s3cr3t".into();
    bank.urls = vec!["https://bank.example".into()];
    bank.notes = "Branch: Main St\nCall before travelling".into();
    bank.custom_fields = vec![CustomField {
        name: "PIN".into(),
        value: "4321".into(),
        hidden: true,
    }];

    let mut wifi = Entry::new(EntryKind::Note, "Wi-Fi");
    wifi.notes = "SSID: home".into();

    let mut entries = vec![github, bank, wifi];
    for e in &mut entries {
        e.created = t;
        e.modified = t;
    }
    entries
}

fn app_for(dir: &Path, vault: Option<&str>) -> App {
    let target = vault.map(|n| VaultTarget::named(&VaultName::parse(n).unwrap(), dir));
    let mut app = App::new(Config::default(), dir.to_path_buf(), target, Instant::now());
    app.set_time_zone(TimeZone::UTC);
    app
}

fn press(app: &mut App, code: KeyCode) {
    app.on_key(KeyEvent::new(code, KeyModifiers::NONE), Instant::now());
}

fn ctrl(app: &mut App, c: char) {
    app.on_key(
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL),
        Instant::now(),
    );
}

fn type_text(app: &mut App, text: &str) {
    for c in text.chars() {
        press(app, KeyCode::Char(c));
    }
}

/// Type the password, press Enter and run the unlock.
fn unlock(app: &mut App, password: &str) {
    type_text(app, password);
    press(app, KeyCode::Enter);
    assert!(app.unlock_pending());
    app.perform_unlock();
}

fn unlocked_app(dir: &Path) -> App {
    let mut app = app_for(dir, Some("default"));
    unlock(&mut app, PASSWORD);
    assert_eq!(app.mode(), Mode::List);
    app
}

/// Render `app` at `width`×`height` and return the screen as text.
fn screen(app: &App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|f| ui::render(app, f)).unwrap();
    terminal.backend().to_string()
}

// -- Behaviour ----------------------------------------------------------------

#[test]
fn wrong_then_right_password() {
    let dir = setup();
    let mut app = app_for(dir.path(), Some("default"));
    assert_eq!(app.mode(), Mode::Unlock);

    unlock(&mut app, "nope");
    assert!(!app.is_unlocked());
    insta::assert_snapshot!("unlock_wrong_password", screen(&app, 60, 16));

    unlock(&mut app, PASSWORD);
    assert!(app.is_unlocked());
}

#[test]
fn empty_password_is_not_submitted() {
    let dir = setup();
    let mut app = app_for(dir.path(), Some("default"));
    press(&mut app, KeyCode::Enter);
    assert!(!app.unlock_pending());
    assert!(screen(&app, 60, 16).contains("Type the master password first."));
}

#[test]
fn letters_are_typed_not_treated_as_commands_while_unlocking() {
    let dir = setup();
    let mut app = app_for(dir.path(), Some("default"));
    type_text(&mut app, "qLV?"); // all commands on other screens
    assert!(!app.should_quit());
    assert_eq!(app.mode(), Mode::Unlock);
    ctrl(&mut app, 'r'); // reveal what was typed
    assert!(screen(&app, 60, 16).contains("qLV?"));
}

#[test]
fn ctrl_c_quits_from_anywhere() {
    let dir = setup();
    let mut app = app_for(dir.path(), Some("default"));
    type_text(&mut app, "abc");
    ctrl(&mut app, 'c');
    assert!(app.should_quit());
}

#[test]
fn search_filters_and_escape_clears() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Char('/'));
    assert_eq!(app.mode(), Mode::Search);
    type_text(&mut app, "gh"); // `g` would jump to the top outside search
    insta::assert_snapshot!("list_searching", screen(&app, 70, 12));

    press(&mut app, KeyCode::Enter); // keep the filter, back to the list
    assert_eq!(app.mode(), Mode::List);
    assert!(screen(&app, 70, 12).contains("/ gh"));

    press(&mut app, KeyCode::Esc); // clear it
    let shown = screen(&app, 70, 12);
    assert!(!shown.contains("/ gh") && shown.contains("Bank"), "{shown}");
}

#[test]
fn detail_masks_secrets_until_space() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Down); // GitHub (favourite) is first, Bank second
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.mode(), Mode::Detail);
    let masked = screen(&app, 60, 18);
    assert!(
        !masked.contains("s3cr3t") && !masked.contains("4321"),
        "{masked}"
    );
    insta::assert_snapshot!("detail_masked", masked);

    press(&mut app, KeyCode::Char(' '));
    let revealed = screen(&app, 60, 18);
    assert!(
        revealed.contains("s3cr3t") && revealed.contains("4321"),
        "{revealed}"
    );

    press(&mut app, KeyCode::Esc);
    assert_eq!(app.mode(), Mode::List);
}

#[test]
fn reopening_an_entry_masks_it_again() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Enter);
    assert!(!screen(&app, 60, 18).contains("hunter2-but-longer"));
}

#[test]
fn lock_returns_to_unlock_screen() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Char('L'));
    assert!(!app.is_unlocked());
    assert_eq!(app.mode(), Mode::Unlock);
    // The vault's file lock was released, so it can be opened again.
    drop(Vault::unlock(dir.path().join("default.lockery"), PASSWORD.as_bytes()).unwrap());
}

#[test]
fn idle_timeout_locks() {
    let dir = setup();
    let start = Instant::now();
    let mut app = App::new(
        Config::default(),
        dir.path().to_path_buf(),
        Some(VaultTarget::named(
            &VaultName::parse("default").unwrap(),
            dir.path(),
        )),
        start,
    );
    unlock(&mut app, PASSWORD);
    let idle = Duration::from_secs(Config::default().idle_lock_secs.into());

    app.tick(start + idle / 2);
    assert!(app.is_unlocked());
    app.tick(start + idle + Duration::from_secs(1));
    assert!(!app.is_unlocked());
    assert!(screen(&app, 60, 16).contains("Locked after 5 min of inactivity."));
}

#[test]
fn switching_vaults_through_the_picker() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Char('V'));
    assert!(!app.is_unlocked());
    assert_eq!(app.mode(), Mode::Picker);
    insta::assert_snapshot!("picker", screen(&app, 60, 12));

    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    assert!(screen(&app, 60, 16).contains("work · locked"));
    unlock(&mut app, PASSWORD);
    assert!(screen(&app, 60, 12).contains("This vault is empty."));
}

#[test]
fn tab_on_unlock_opens_picker_with_current_vault_selected() {
    let dir = setup();
    let mut app = app_for(dir.path(), Some("work"));
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.mode(), Mode::Picker);
    press(&mut app, KeyCode::Enter);
    assert!(screen(&app, 60, 16).contains("work · locked"));
}

#[test]
fn picker_without_vaults_explains_what_to_do() {
    let dir = TempDir::new().unwrap();
    let mut app = app_for(dir.path(), None);
    assert!(screen(&app, 70, 14).contains("lockery init"));
    press(&mut app, KeyCode::Enter); // nothing to open: no panic, no change
    assert_eq!(app.mode(), Mode::Picker);
}

// -- Snapshots ----------------------------------------------------------------

#[test]
fn snapshot_unlock_screen() {
    let dir = setup();
    let mut app = app_for(dir.path(), Some("default"));
    type_text(&mut app, "abc");
    insta::assert_snapshot!("unlock_typing", screen(&app, 60, 16));
}

#[test]
fn snapshot_list() {
    let dir = setup();
    let app = unlocked_app(dir.path());
    insta::assert_snapshot!("list", screen(&app, 80, 12));
}

#[test]
fn snapshot_help_overlay() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Char('?'));
    assert_eq!(app.mode(), Mode::Help);
    insta::assert_snapshot!("help_list", screen(&app, 80, 24));
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.mode(), Mode::List);
}

#[test]
fn snapshot_narrow_terminal() {
    let dir = setup();
    let app = unlocked_app(dir.path());
    insta::assert_snapshot!("list_narrow", screen(&app, 40, 10));
}
