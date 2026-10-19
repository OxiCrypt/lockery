//! Importing the sample CSV in `tests/fixtures/csv/` for each source.
//!
//! The samples are hand-written to match each manager's documented export
//! columns (including awkward cases: quoted commas and quotes, multi-line
//! fields, unsupported item types, bad dates). They aren't byte-for-byte
//! exports from those apps.

use std::path::Path;

use jiff::Timestamp;
use lockery::csv_io::{self, CsvFormat, Imported};
use lockery::vault::{Entry, EntryKind};

fn import(name: &str) -> Imported {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csv")
        .join(name);
    csv_io::parse(&std::fs::read(path).unwrap()).unwrap()
}

fn by_title<'a>(imported: &'a Imported, title: &str) -> &'a Entry {
    imported
        .entries
        .iter()
        .find(|e| e.title == title)
        .unwrap_or_else(|| panic!("no {title} in {:?}", imported.entries))
}

fn ts(s: &str) -> Timestamp {
    s.parse().unwrap()
}

#[test]
fn bitwarden() {
    let imported = import("bitwarden.csv");
    assert_eq!(imported.format, CsvFormat::Bitwarden);
    assert_eq!(imported.entries.len(), 3);
    assert_eq!(imported.warnings.len(), 1, "{:?}", imported.warnings);
    assert!(
        imported.warnings[0].contains("“card”"),
        "{:?}",
        imported.warnings
    );

    let twitter = by_title(&imported, "Twitter");
    assert!(twitter.favorite);
    assert_eq!(twitter.tags, ["Social"]);

    let note = by_title(&imported, "Recovery codes");
    assert_eq!(note.kind, EntryKind::Note);
    assert_eq!(note.notes, "1111-2222\n3333-4444");

    let gitlab = by_title(&imported, "GitLab");
    assert_eq!(gitlab.password, "s3c,ret\"pw");
    assert_eq!(
        gitlab.urls,
        ["https://gitlab.com", "https://gitlab.example.com"]
    );
    assert!(gitlab.totp.starts_with("otpauth://"));
    let fields: Vec<_> = gitlab
        .custom_fields
        .iter()
        .map(|f| (f.name.as_str(), f.value.as_str()))
        .collect();
    assert_eq!(fields, [("PIN", "1234"), ("Employee ID", "42")]);
}

#[test]
fn keepassxc() {
    let imported = import("keepassxc.csv");
    assert_eq!(imported.format, CsvFormat::KeePassXc);
    assert_eq!(imported.entries.len(), 3);

    let bank = by_title(&imported, "Bank");
    assert!(bank.tags.is_empty(), "the Root group isn't a tag");
    assert_eq!(bank.created, ts("2023-01-15T08:30:00Z"));
    assert_eq!(bank.modified, ts("2024-03-01T10:00:00Z"));

    let mail = by_title(&imported, "Mail");
    assert_eq!(mail.tags, ["Email/Work"]);
    assert_eq!(mail.notes, "Recovery: 123");
    assert!(mail.totp.contains("secret=ABCDEFGH"));
    assert!(
        mail.custom_fields.is_empty(),
        "Icon is known, not a custom field"
    );

    assert_eq!(imported.warnings.len(), 1);
    assert!(
        imported.warnings[0].contains("not a date"),
        "{:?}",
        imported.warnings
    );
}

#[test]
fn chrome() {
    let imported = import("chrome.csv");
    assert_eq!(imported.format, CsvFormat::Chrome);
    assert_eq!(imported.entries.len(), 3);
    assert_eq!(imported.warnings, Vec::<String>::new());
    assert_eq!(
        by_title(&imported, "accounts.google.com").notes,
        "personal account"
    );
    // No name: the title comes from the URL's host.
    assert_eq!(by_title(&imported, "example.org").username, "ex");
}

#[test]
fn firefox() {
    let imported = import("firefox.csv");
    assert_eq!(imported.format, CsvFormat::Firefox);
    assert_eq!(imported.entries.len(), 2);

    let mozilla = by_title(&imported, "mozilla.org");
    assert_eq!(mozilla.password, "f0x-pass");
    assert_eq!(
        mozilla.created,
        Timestamp::from_millisecond(1_700_000_000_000).unwrap()
    );
    assert_eq!(
        mozilla.modified,
        Timestamp::from_millisecond(1_700_000_400_000).unwrap()
    );
    let names: Vec<_> = mozilla
        .custom_fields
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(
        names,
        ["Form action origin", "Firefox GUID"],
        "empty HTTP realm skipped"
    );

    let intranet = by_title(&imported, "intranet.example");
    assert!(
        intranet
            .custom_fields
            .iter()
            .any(|f| f.name == "HTTP realm" && f.value == "Intranet")
    );
}

#[test]
fn importing_the_same_file_twice_finds_every_duplicate() {
    let first = import("keepassxc.csv");
    let second = import("keepassxc.csv");
    let flags = csv_io::duplicate_flags(&first.entries, &second.entries);
    assert!(flags.iter().all(|&dup| dup), "{flags:?}");
}
