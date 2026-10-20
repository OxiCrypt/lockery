//! TUI tests: behaviour driven through [`App::on_key`], plus snapshots of
//! each screen rendered on ratatui's in-memory `TestBackend`.
//!
//! Snapshots live in `src/tui/snapshots/`. After an intentional UI change,
//! review and accept new ones with `cargo insta review` (or rerun the tests
//! with `INSTA_UPDATE=always` and check the diff in git).

use std::cell::Cell;
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime};

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

/// The default config, minus the "couldn't lock memory" warning: whether
/// `mlock` succeeds depends on the machine's limit and on how many tests run
/// at once, and it mustn't make snapshots flaky.
fn test_config() -> Config {
    let mut config = Config::default();
    config.security.lock_memory = false;
    config
}

fn app_for(dir: &Path, vault: Option<&str>) -> App {
    let target = vault.map(|n| VaultTarget::named(&VaultName::parse(n).unwrap(), dir));
    let mut app = App::new(test_config(), dir.to_path_buf(), target, Instant::now());
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
    assert!(app.has_pending());
    app.run_pending();
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
    assert!(!app.has_pending());
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
        test_config(),
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
fn time_suspended_counts_towards_the_idle_lock() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    let wall = Rc::new(Cell::new(SystemTime::now()));
    let reader = Rc::clone(&wall);
    app.set_wall_clock(Rc::new(move || reader.get()));
    let start = Instant::now();
    press_at(&mut app, KeyCode::Down, start);

    // The lid closes overnight: `Instant` stops, the wall clock doesn't.
    wall.set(wall.get() + Duration::from_secs(8 * 3600));
    app.tick(start + Duration::from_secs(1));
    assert!(!app.is_unlocked());
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
    assert!(screen(&app, 70, 14).contains("Press n to create one."));
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

// -- M4: editing entries ------------------------------------------------------

fn shift_tab(app: &mut App) {
    app.on_key(
        KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT),
        Instant::now(),
    );
}

/// Reopen the `default` vault from disk (the app must have locked it).
fn reopen(dir: &Path) -> Vault {
    Vault::unlock(dir.join("default.lockery"), PASSWORD.as_bytes()).unwrap()
}

fn find<'a>(vault: &'a Vault, title: &str) -> &'a Entry {
    vault
        .entries()
        .iter()
        .find(|e| e.title == title)
        .unwrap_or_else(|| panic!("no {title}"))
}

#[test]
fn add_entry_is_saved_to_disk() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Char('n'));
    assert_eq!(app.mode(), Mode::Edit);
    insta::assert_snapshot!("edit_new", screen(&app, 70, 22));

    type_text(&mut app, "Email"); // focus starts on Title
    press(&mut app, KeyCode::Tab);
    type_text(&mut app, "me@example.com");
    press(&mut app, KeyCode::Enter); // Enter in a single-line field moves on too
    type_text(&mut app, "pa55word");
    ctrl(&mut app, 's');

    assert_eq!(app.mode(), Mode::Detail, "the saved entry is shown");
    assert!(screen(&app, 70, 22).contains("Saved “Email”."));
    press(&mut app, KeyCode::Char('L'));

    let vault = reopen(dir.path());
    let e = find(&vault, "Email");
    assert_eq!(
        (e.username.as_str(), e.password.as_str()),
        ("me@example.com", "pa55word")
    );
    assert_eq!(vault.entries().len(), 4);
}

#[test]
fn edit_entry_changes_only_what_was_typed() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Down); // Bank
    press(&mut app, KeyCode::Char('e'));
    let masked = screen(&app, 70, 22);
    assert!(
        !masked.contains("s3cr3t") && !masked.contains("4321"),
        "{masked}"
    );
    insta::assert_snapshot!("edit_existing", masked);

    type_text(&mut app, " Ltd"); // cursor starts at the end of the title
    ctrl(&mut app, 's');
    press(&mut app, KeyCode::Char('L'));

    let vault = reopen(dir.path());
    let e = find(&vault, "Bank Ltd");
    assert_eq!(e.password, "s3cr3t");
    assert_eq!(e.notes, "Branch: Main St\nCall before travelling");
    assert_eq!(e.custom_fields[0].value, "4321");
    assert!(e.modified > e.created, "modified time was bumped");
}

#[test]
fn edit_from_detail_view_and_reveal_in_form() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter); // detail of Bank
    press(&mut app, KeyCode::Char('e'));
    assert_eq!(app.mode(), Mode::Edit);
    ctrl(&mut app, 'r');
    assert!(screen(&app, 70, 22).contains("s3cr3t"));
}

#[test]
fn title_is_required() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Char('n'));
    ctrl(&mut app, 's');
    assert_eq!(app.mode(), Mode::Edit);
    assert!(screen(&app, 70, 22).contains("A title is required."));
}

#[test]
fn cancelling_asks_only_when_something_changed() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());

    press(&mut app, KeyCode::Char('n'));
    press(&mut app, KeyCode::Esc);
    assert_eq!(
        app.mode(),
        Mode::List,
        "nothing typed: closes straight away"
    );

    press(&mut app, KeyCode::Char('n'));
    type_text(&mut app, "x");
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.mode(), Mode::Confirm);
    press(&mut app, KeyCode::Char('n'));
    assert_eq!(app.mode(), Mode::Edit, "answering no keeps the form");
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Char('y'));
    assert_eq!(app.mode(), Mode::List);
}

#[test]
fn delete_needs_confirmation() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Down); // Bank
    press(&mut app, KeyCode::Char('d'));
    assert_eq!(app.mode(), Mode::Confirm);
    insta::assert_snapshot!("confirm_delete", screen(&app, 70, 14));

    press(&mut app, KeyCode::Esc);
    assert!(screen(&app, 70, 14).contains("Bank"), "Esc means no");

    press(&mut app, KeyCode::Char('d'));
    press(&mut app, KeyCode::Char('y'));
    let shown = screen(&app, 70, 14);
    assert!(
        shown.contains("Deleted “Bank”.") && shown.contains("2 entries"),
        "{shown}"
    );
    press(&mut app, KeyCode::Char('L'));
    assert_eq!(reopen(dir.path()).entries().len(), 2);
}

#[test]
fn custom_fields_can_be_added_and_hidden() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Char('n'));
    type_text(&mut app, "Router");
    // Title → Username, Password, URLs, TOTP, Tags, Favourite, "+ Add".
    for _ in 0..7 {
        press(&mut app, KeyCode::Tab);
    }
    press(&mut app, KeyCode::Enter); // press the button
    type_text(&mut app, "Admin PIN");
    press(&mut app, KeyCode::Tab);
    type_text(&mut app, "9999");
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Char(' ')); // Hidden: yes
    ctrl(&mut app, 's');
    press(&mut app, KeyCode::Char('L'));

    let vault = reopen(dir.path());
    let field = &find(&vault, "Router").custom_fields[0];
    assert_eq!(
        (field.name.as_str(), field.value.as_str(), field.hidden),
        ("Admin PIN", "9999", true)
    );
}

#[test]
fn secure_notes_hide_login_fields() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Char('n'));
    shift_tab(&mut app); // Title → Type
    press(&mut app, KeyCode::Char(' ')); // Login → Secure note
    let shown = screen(&app, 70, 22);
    assert!(
        shown.contains("Secure note") && !shown.contains("Username"),
        "{shown}"
    );

    press(&mut app, KeyCode::Tab);
    type_text(&mut app, "Recovery codes");
    ctrl(&mut app, 's');
    press(&mut app, KeyCode::Char('L'));
    let vault = reopen(dir.path());
    assert_eq!(find(&vault, "Recovery codes").kind, EntryKind::Note);
}

// -- M4: managing vaults from the picker --------------------------------------

/// The picker over `setup()`'s vaults, with fast Argon2 for new vaults.
fn picker_app(dir: &Path) -> App {
    let mut app = app_for(dir, None);
    app.set_new_vault_kdf(super::app::NewVaultKdf::Fixed(test_params()));
    assert_eq!(app.mode(), Mode::Picker);
    app
}

const STRONG: &str = "correct-horse-battery-staple-94!";

#[test]
fn create_vault_opens_it() {
    let dir = setup();
    let mut app = picker_app(dir.path());
    press(&mut app, KeyCode::Char('n'));
    assert_eq!(app.mode(), Mode::Dialog);
    insta::assert_snapshot!("dialog_create", screen(&app, 70, 16));

    type_text(&mut app, "personal");
    press(&mut app, KeyCode::Tab);
    type_text(&mut app, STRONG);
    press(&mut app, KeyCode::Tab);
    type_text(&mut app, STRONG);
    press(&mut app, KeyCode::Enter);
    assert!(app.has_pending());
    assert!(screen(&app, 70, 16).contains("Creating vault"));
    app.run_pending();

    assert!(app.is_unlocked());
    assert!(screen(&app, 70, 16).contains("personal · 0 entries"));
    press(&mut app, KeyCode::Char('L'));
    drop(Vault::unlock(dir.path().join("personal.lockery"), STRONG.as_bytes()).unwrap());
}

#[test]
fn create_vault_validates_input() {
    let dir = setup();
    let mut app = picker_app(dir.path());
    press(&mut app, KeyCode::Char('n'));
    let submit = |app: &mut App| {
        press(app, KeyCode::Enter);
        assert!(!app.has_pending());
        screen(app, 70, 16)
    };

    type_text(&mut app, "work");
    assert!(submit(&mut app).contains("already exists"));
    for _ in 0..4 {
        press(&mut app, KeyCode::Backspace);
    }
    type_text(&mut app, "new/../x");
    assert!(submit(&mut app).contains("invalid vault name"));
    for _ in 0..8 {
        press(&mut app, KeyCode::Backspace);
    }
    type_text(&mut app, "fresh");
    press(&mut app, KeyCode::Tab);
    type_text(&mut app, "password");
    press(&mut app, KeyCode::Tab);
    type_text(&mut app, "passw0rd");
    assert!(submit(&mut app).contains("don't match"));

    for _ in 0.."0rd".len() {
        press(&mut app, KeyCode::Backspace);
    }
    type_text(&mut app, "ord"); // now both say "password"
    assert!(submit(&mut app).contains("easy to guess"));
    press(&mut app, KeyCode::Enter); // use it anyway
    assert!(app.has_pending());
}

#[test]
fn rename_vault() {
    let dir = setup();
    let mut app = picker_app(dir.path());
    press(&mut app, KeyCode::Down); // work
    press(&mut app, KeyCode::Char('r'));
    for _ in 0.."work".len() {
        press(&mut app, KeyCode::Backspace);
    }
    type_text(&mut app, "jobs");
    press(&mut app, KeyCode::Enter);

    assert_eq!(app.mode(), Mode::Picker);
    let shown = screen(&app, 70, 16);
    assert!(
        shown.contains("› jobs") && !shown.contains("│  work"),
        "{shown}"
    );
    assert!(shown.contains("Renamed 'work' to 'jobs'."), "{shown}");
    assert!(dir.path().join("jobs.lockery").is_file());
    assert!(!dir.path().join("work.lockery").exists());
}

#[test]
fn delete_vault_needs_name_and_password() {
    let dir = setup();
    let mut app = picker_app(dir.path());
    press(&mut app, KeyCode::Down); // work
    press(&mut app, KeyCode::Char('d'));
    insta::assert_snapshot!("dialog_delete", screen(&app, 70, 16));

    type_text(&mut app, "wrong");
    press(&mut app, KeyCode::Tab);
    type_text(&mut app, "wrok");
    press(&mut app, KeyCode::Enter);
    assert!(!app.has_pending());
    assert!(screen(&app, 70, 16).contains("Type 'work' exactly"));

    for _ in 0.."rok".len() {
        press(&mut app, KeyCode::Backspace);
    }
    type_text(&mut app, "ork"); // "wrok" → "work"
    press(&mut app, KeyCode::Enter);
    assert!(app.has_pending());
    app.run_pending();
    assert!(screen(&app, 70, 16).contains("Wrong password."));
    assert!(dir.path().join("work.lockery").exists());

    shift_tab(&mut app);
    for _ in 0.."wrong".len() {
        press(&mut app, KeyCode::Backspace);
    }
    type_text(&mut app, PASSWORD);
    press(&mut app, KeyCode::Enter);
    app.run_pending();
    assert_eq!(app.mode(), Mode::Picker);
    assert!(screen(&app, 70, 16).contains("Deleted vault 'work'."));
    assert!(!dir.path().join("work.lockery").exists());
}

// -- M5: generators -----------------------------------------------------------

/// The value currently suggested by the generator popup.
fn generated(app: &App) -> String {
    let super::app::Screen::Unlocked(u) = &app.screen else {
        panic!("not unlocked")
    };
    u.generator
        .as_ref()
        .expect("generator open")
        .value
        .to_string()
}

#[test]
fn ctrl_g_fills_the_password_field() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Char('n'));
    type_text(&mut app, "Generated");
    ctrl(&mut app, 'g');
    assert_eq!(app.mode(), Mode::Generator);
    let first = generated(&app);
    assert_eq!(first.chars().count(), 24, "config default length");
    assert!(screen(&app, 80, 30).contains("very strong"));

    ctrl(&mut app, 'g'); // a new suggestion
    let value = generated(&app);
    assert_ne!(value, first);

    press(&mut app, KeyCode::Enter);
    assert_eq!(app.mode(), Mode::Edit);
    ctrl(&mut app, 's');
    press(&mut app, KeyCode::Char('L'));
    assert_eq!(find(&reopen(dir.path()), "Generated").password, value);
}

#[test]
fn generator_from_the_list_starts_a_new_entry_with_a_passphrase() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Char('g'));
    assert_eq!(app.mode(), Mode::Generator);
    press(&mut app, KeyCode::Right); // Type: Password → Passphrase
    let phrase = generated(&app);
    assert!(phrase.matches('-').count() >= 5, "{phrase}");
    assert!(screen(&app, 80, 30).contains("≈ 78 bits"));

    press(&mut app, KeyCode::Enter);
    assert_eq!(app.mode(), Mode::Edit);
    type_text(&mut app, "Phrase entry");
    ctrl(&mut app, 's');
    press(&mut app, KeyCode::Char('L'));
    assert_eq!(find(&reopen(dir.path()), "Phrase entry").password, phrase);
}

#[test]
fn generator_options_change_the_value_and_are_remembered() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Char('g'));
    press(&mut app, KeyCode::Tab); // Length
    type_text(&mut app, "40"); // 240 > 128, so typing starts over: 4, then 40
    assert_eq!(generated(&app).chars().count(), 40);
    press(&mut app, KeyCode::Tab); // a-z
    press(&mut app, KeyCode::Char(' ')); // off
    assert!(!generated(&app).chars().any(|c| c.is_ascii_lowercase()));

    press(&mut app, KeyCode::Esc);
    assert_eq!(app.mode(), Mode::List);
    press(&mut app, KeyCode::Char('g'));
    let again = generated(&app);
    assert_eq!(again.chars().count(), 40, "length remembered");
    assert!(
        !again.chars().any(|c| c.is_ascii_lowercase()),
        "a-z off remembered"
    );
}

#[test]
fn generator_explains_impossible_options() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Char('g'));
    press(&mut app, KeyCode::Tab); // Length
    for _ in 0..4 {
        press(&mut app, KeyCode::Tab); // to each class toggle in turn
        press(&mut app, KeyCode::Char(' '));
    }
    assert!(screen(&app, 80, 30).contains("Choose at least one kind of character"));
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.mode(),
        Mode::Generator,
        "nothing to use, so it stays open"
    );
}

#[test]
fn editor_shows_password_strength() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Char('n'));
    assert!(
        !screen(&app, 70, 22).contains("Password strength"),
        "hidden while empty"
    );
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Tab); // Password
    type_text(&mut app, "abc");
    assert!(screen(&app, 70, 22).contains("very weak"));
    type_text(&mut app, "-Quartz-Lantern-Velvet-91");
    assert!(screen(&app, 70, 22).contains("very strong"));

    // The strength is cached, so it must follow every relevant change: a
    // secure note has no password row, so no meter either.
    for _ in 0..3 {
        press(&mut app, KeyCode::BackTab); // Username, Title, Type
    }
    press(&mut app, KeyCode::Right);
    assert!(!screen(&app, 70, 22).contains("Password strength"));
    press(&mut app, KeyCode::Left);
    assert!(screen(&app, 70, 22).contains("very strong"));
}

// -- M8: vault settings -------------------------------------------------------

/// From the first settings field (Cipher) to the others:
/// Memory, Passes, Lanes, Tune button, New, Repeat, Current.
fn tab_times(app: &mut App, n: usize) {
    for _ in 0..n {
        press(app, KeyCode::Tab);
    }
}

#[test]
fn settings_change_cipher_and_password() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Char('s'));
    assert_eq!(app.mode(), Mode::Settings);
    insta::assert_snapshot!("settings", screen(&app, 84, 24));

    press(&mut app, KeyCode::Right); // Cipher → AES-256-GCM
    tab_times(&mut app, 5);
    type_text(&mut app, STRONG);
    press(&mut app, KeyCode::Tab);
    type_text(&mut app, STRONG);
    press(&mut app, KeyCode::Tab);
    type_text(&mut app, PASSWORD);
    ctrl(&mut app, 's');
    assert!(app.has_pending());
    assert!(screen(&app, 84, 24).contains("Re-encrypting the vault…"));
    app.run_pending();

    assert_eq!(app.mode(), Mode::List);
    let shown = screen(&app, 120, 24);
    assert!(shown.contains("Vault re-encrypted: AES-256-GCM"), "{shown}");
    assert!(shown.contains("New master password set."), "{shown}");

    press(&mut app, KeyCode::Char('L'));
    let path = dir.path().join("default.lockery");
    assert!(
        Vault::unlock(&path, PASSWORD.as_bytes()).is_err(),
        "old password no longer works"
    );
    let vault = Vault::unlock(&path, STRONG.as_bytes()).unwrap();
    assert_eq!(vault.cipher(), CipherId::Aes256Gcm);
    assert_eq!(vault.entries().len(), 3, "entries survive re-encryption");
}

#[test]
fn settings_refuse_a_wrong_current_password() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    let before = std::fs::read(dir.path().join("default.lockery")).unwrap();
    press(&mut app, KeyCode::Char('s'));
    press(&mut app, KeyCode::Right);
    tab_times(&mut app, 7);
    type_text(&mut app, "not it");
    ctrl(&mut app, 's');
    app.run_pending();

    assert_eq!(app.mode(), Mode::Settings, "stays open to try again");
    assert!(screen(&app, 84, 24).contains("The current password is wrong."));
    assert_eq!(
        std::fs::read(dir.path().join("default.lockery")).unwrap(),
        before
    );
}

#[test]
fn settings_tune_button_fills_in_argon2() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    let tuned =
        crate::crypto::KdfParams::new(crate::crypto::KdfParams::MIN_M_COST_KIB * 2, 2, 1).unwrap();
    app.set_new_vault_kdf(super::app::NewVaultKdf::Fixed(tuned));

    press(&mut app, KeyCode::Char('s'));
    tab_times(&mut app, 4); // the Tune button
    press(&mut app, KeyCode::Enter);
    assert!(screen(&app, 84, 24).contains("Measuring this machine…"));
    app.run_pending();
    assert!(screen(&app, 84, 24).contains("Argon2 tuned for this machine."));

    tab_times(&mut app, 3); // Current password
    type_text(&mut app, PASSWORD);
    ctrl(&mut app, 's');
    app.run_pending();
    press(&mut app, KeyCode::Char('L'));
    assert_eq!(reopen(dir.path()).kdf(), tuned);
}

#[test]
fn settings_need_a_change_and_ask_before_discarding() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Char('s'));
    ctrl(&mut app, 's');
    assert!(!app.has_pending());
    assert!(screen(&app, 84, 24).contains("Nothing to change."));

    press(&mut app, KeyCode::Esc);
    assert_eq!(
        app.mode(),
        Mode::List,
        "nothing changed: closes straight away"
    );

    press(&mut app, KeyCode::Char('s'));
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.mode(), Mode::Confirm);
    press(&mut app, KeyCode::Char('y'));
    assert_eq!(app.mode(), Mode::List);
}

// -- M7: CSV import and export -------------------------------------------------

fn fixture_csv(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csv")
        .join(name)
        .display()
        .to_string()
}

/// `i`, type `path`, Enter: lands on the preview (or an error in the dialog).
fn open_import(app: &mut App, path: &str) {
    press(app, KeyCode::Char('i'));
    assert_eq!(app.mode(), Mode::Dialog);
    type_text(app, path);
    press(app, KeyCode::Enter);
}

#[test]
fn import_csv_through_the_preview() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    open_import(&mut app, &fixture_csv("chrome.csv"));
    assert_eq!(app.mode(), Mode::Preview);
    let shown = screen(&app, 90, 24);
    assert!(
        shown.contains("Chrome") && shown.contains("3 entries"),
        "{shown}"
    );
    assert!(shown.contains("✓ github.com"), "{shown}");

    press(&mut app, KeyCode::Enter);
    assert_eq!(app.mode(), Mode::List);
    let shown = screen(&app, 250, 24);
    assert!(
        shown.contains("Imported 3 entries.") && shown.contains("plain text"),
        "{shown}"
    );
    assert!(shown.contains("6 entries"), "{shown}");
    press(&mut app, KeyCode::Char('L'));
    assert_eq!(reopen(dir.path()).entries().len(), 6);
}

#[test]
fn reimporting_skips_duplicates_unless_asked() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    let csv = fixture_csv("keepassxc.csv");
    open_import(&mut app, &csv);
    press(&mut app, KeyCode::Enter); // 3 new entries

    open_import(&mut app, &csv);
    let shown = screen(&app, 90, 24);
    assert!(
        shown.contains("3 already in this vault") && shown.contains("= Bank"),
        "{shown}"
    );
    assert!(
        shown.contains("1 warning ") && shown.contains("not a date"),
        "{shown}"
    );
    press(&mut app, KeyCode::Enter);
    assert!(screen(&app, 90, 24).contains("Nothing new to import."));

    open_import(&mut app, &csv);
    press(&mut app, KeyCode::Char(' ')); // include duplicates
    assert!(screen(&app, 90, 24).contains("✓ Bank"));
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('L'));
    assert_eq!(reopen(dir.path()).entries().len(), 9);
}

#[test]
fn import_reports_bad_files_in_the_dialog() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    open_import(&mut app, "/no/such/file.csv");
    assert_eq!(app.mode(), Mode::Dialog);
    assert!(screen(&app, 90, 20).contains("Can't read"));

    let bogus = dir.path().join("bogus.csv");
    std::fs::write(&bogus, "a,b\n1,2\n").unwrap();
    press(&mut app, KeyCode::Esc);
    open_import(&mut app, &bogus.display().to_string());
    assert!(screen(&app, 160, 20).contains("unrecognised CSV columns"));
}

#[test]
fn export_needs_the_password_and_writes_a_private_bitwarden_csv() {
    let dir = setup();
    let mut app = unlocked_app(dir.path());
    press(&mut app, KeyCode::Char('x'));
    assert_eq!(app.mode(), Mode::Dialog);
    let shown = screen(&app, 90, 20);
    assert!(
        shown.contains("plain text") && shown.contains("lockery-default-export.csv"),
        "{shown}"
    );

    for _ in 0..60 {
        press(&mut app, KeyCode::Backspace); // clear the suggested path
    }
    let out = dir.path().join("export.csv");
    type_text(&mut app, &out.display().to_string());
    press(&mut app, KeyCode::Tab);
    type_text(&mut app, "wrong");
    press(&mut app, KeyCode::Enter);
    app.run_pending();
    assert!(screen(&app, 90, 20).contains("Wrong password."));
    assert!(!out.exists());

    type_text(&mut app, PASSWORD); // the field was cleared and kept focus
    press(&mut app, KeyCode::Enter);
    app.run_pending();
    assert_eq!(app.mode(), Mode::List);
    assert!(screen(&app, 160, 20).contains("Exported 3 entries"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let imported = crate::csv_io::parse(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(imported.format, crate::csv_io::CsvFormat::Bitwarden);
    assert_eq!(imported.entries.len(), 3);

    // Exporting again to the same file is refused.
    press(&mut app, KeyCode::Char('x'));
    for _ in 0..60 {
        press(&mut app, KeyCode::Backspace);
    }
    type_text(&mut app, &out.display().to_string());
    press(&mut app, KeyCode::Enter);
    assert!(screen(&app, 120, 20).contains("already exists"));
}

// -- M6: clipboard ------------------------------------------------------------

use crate::clipboard::FakeBackend;

/// An unlocked app whose clipboard is an in-memory fake.
fn app_with_fake_clipboard(dir: &Path) -> (App, FakeBackend) {
    let mut app = unlocked_app(dir);
    let fake = FakeBackend::default();
    let timeout = Duration::from_secs(Config::default().clipboard_clear_secs.into());
    app.set_clipboard(fake.clipboard(timeout));
    (app, fake)
}

fn press_at(app: &mut App, code: KeyCode, at: Instant) {
    app.on_key(KeyEvent::new(code, KeyModifiers::NONE), at);
}

#[test]
fn copied_password_is_cleared_after_the_timeout() {
    let dir = setup();
    let (mut app, fake) = app_with_fake_clipboard(dir.path());
    let start = Instant::now();
    press_at(&mut app, KeyCode::Down, start); // Bank
    press_at(&mut app, KeyCode::Char('c'), start);
    assert_eq!(fake.text().as_deref(), Some("s3cr3t"));
    let shown = screen(&app, 90, 12);
    assert!(
        shown.contains("Password copied. The clipboard clears in 20 s."),
        "{shown}"
    );
    assert!(
        shown.contains("password on clipboard · clears in 20s"),
        "{shown}"
    );

    app.tick(start + Duration::from_secs(12));
    assert!(screen(&app, 90, 12).contains("clears in 8s"));
    assert_eq!(fake.text().as_deref(), Some("s3cr3t"));

    app.tick(start + Duration::from_secs(20));
    assert_eq!(fake.text(), None);
    let shown = screen(&app, 90, 12);
    assert!(
        shown.contains("Clipboard cleared.") && !shown.contains("on clipboard"),
        "{shown}"
    );
}

#[test]
fn username_copies_from_the_detail_view() {
    let dir = setup();
    let (mut app, fake) = app_with_fake_clipboard(dir.path());
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('u'));
    assert_eq!(fake.text().as_deref(), Some("alice"));
    assert!(screen(&app, 90, 18).contains("Username copied."));
}

#[test]
fn locking_and_quitting_clear_the_clipboard() {
    let dir = setup();
    let (mut app, fake) = app_with_fake_clipboard(dir.path());
    press(&mut app, KeyCode::Char('c'));
    press(&mut app, KeyCode::Char('L'));
    assert_eq!(fake.text(), None, "lock clears");

    unlock(&mut app, PASSWORD);
    press(&mut app, KeyCode::Char('c'));
    assert!(fake.text().is_some());
    drop(app);
    assert_eq!(fake.text(), None, "quitting clears");
}

#[test]
fn something_copied_elsewhere_is_left_alone() {
    let dir = setup();
    let (mut app, fake) = app_with_fake_clipboard(dir.path());
    let start = Instant::now();
    press_at(&mut app, KeyCode::Char('c'), start);
    *fake.contents.borrow_mut() = Some("copied in the browser".into());
    app.tick(start + Duration::from_secs(60));
    press(&mut app, KeyCode::Char('L'));
    assert_eq!(fake.text().as_deref(), Some("copied in the browser"));
}

#[test]
fn copy_explains_missing_values_and_missing_clipboards() {
    let dir = setup();
    let (mut app, fake) = app_with_fake_clipboard(dir.path());
    press(&mut app, KeyCode::Char('G')); // Wi-Fi, a note without password
    press(&mut app, KeyCode::Char('c'));
    assert!(screen(&app, 90, 12).contains("“Wi-Fi” has no password."));
    assert_eq!(fake.text(), None);

    let broken = FakeBackend {
        broken: true,
        ..FakeBackend::default()
    };
    app.set_clipboard(broken.clipboard(Duration::from_secs(20)));
    press(&mut app, KeyCode::Home);
    press(&mut app, KeyCode::Char('c'));
    assert!(screen(&app, 90, 12).contains("Couldn't copy: no clipboard available"));
}
