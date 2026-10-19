//! Backwards-compatibility tests against committed vault files.
//!
//! Every format version Lockery has ever written gets a fixture in
//! `tests/fixtures/`. These files must keep opening forever. Once a version
//! has been released its fixtures must NEVER be regenerated; add new files
//! for new versions instead.
//!
//! Two kinds of fixture exist: `v<N>-*.lockery` pin the *file format*
//! (opaque payload), `schema-v<N>.lockery` pin the *entry schema*.

use std::path::{Path, PathBuf};

use lockery::crypto::{CipherId, KdfParams, VaultKey};
use lockery::vault::format;

/// Password for every fixture vault.
const PASSWORD: &[u8] = b"lockery-fixture-password";

/// Plaintext stored in the v1 fixtures. In format v1 the payload is opaque
/// bytes; the entry model (M2) gets its own schema-level fixtures.
const V1_PAYLOAD: &[u8] = b"Lockery format v1 fixture payload \xF0\x9F\x94\x92";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn v1_fixtures() -> [(&'static str, CipherId); 2] {
    [
        ("v1-xchacha20poly1305.lockery", CipherId::XChaCha20Poly1305),
        ("v1-aes256gcm.lockery", CipherId::Aes256Gcm),
    ]
}

#[test]
fn v1_fixtures_still_open() {
    for (name, cipher) in v1_fixtures() {
        let bytes = std::fs::read(fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        let opened = format::open(PASSWORD, &bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(opened.format_version, 1, "{name}");
        assert_eq!(opened.cipher, cipher, "{name}");
        assert_eq!(opened.plaintext.as_slice(), V1_PAYLOAD, "{name}");
    }
}

#[test]
fn v1_fixtures_reject_wrong_password() {
    for (name, _) in v1_fixtures() {
        let bytes = std::fs::read(fixture(name)).unwrap();
        assert!(format::open(b"not the password", &bytes).is_err(), "{name}");
    }
}

/// Writes the v1 fixtures. Only run this when *introducing* format v1:
/// `cargo test --test format_compat -- --ignored write_v1_fixtures`
#[test]
#[ignore = "regenerates committed fixtures; never run after v1 is released"]
fn write_v1_fixtures() {
    // Cheapest accepted parameters, so the compat test stays fast.
    let kdf = KdfParams::new(KdfParams::MIN_M_COST_KIB, 1, 1).unwrap();
    let key = VaultKey::derive_new(PASSWORD, kdf).unwrap();
    for (name, cipher) in v1_fixtures() {
        let bytes = format::seal(&key, cipher, V1_PAYLOAD).unwrap();
        std::fs::write(fixture(name), bytes).unwrap();
    }
}

// ---------------------------------------------------------------------------
// Schema (entry model) fixtures
// ---------------------------------------------------------------------------

mod schema {
    use jiff::Timestamp;
    use lockery::crypto::{CipherId, KdfParams, VaultKey};
    use lockery::vault::format;
    use lockery::vault::migrate;
    use lockery::vault::{CustomField, Entry, EntryKind, VaultData};
    use uuid::Uuid;

    use super::{PASSWORD, fixture};

    const SCHEMA_V1: &str = "schema-v1.lockery";

    /// The entries stored in `schema-v1.lockery`. Fixed ids and timestamps,
    /// so they can be compared exactly. Covers every field of schema 1.
    fn v1_entries() -> Vec<Entry> {
        let t = |s| Timestamp::from_second(s).unwrap();

        let mut login = Entry::new(EntryKind::Login, "Example Mail");
        login.id = Uuid::from_u128(1);
        login.username = "alice@example.com".into();
        login.password = "pässwörd-🔒-123".into();
        login.urls = vec!["https://mail.example.com".into(), "imap.example.com".into()];
        login.notes = "Recovery codes:\n  1111-2222\n  3333-4444".into();
        login.tags = vec!["email".into(), "personal".into()];
        login.custom_fields = vec![
            CustomField {
                name: "PIN".into(),
                value: "0420".into(),
                hidden: true,
            },
            CustomField {
                name: "Account no.".into(),
                value: "12345".into(),
                hidden: false,
            },
        ];
        login.totp = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP".into();
        login.favorite = true;
        login.created = t(1_700_000_000);
        login.modified = t(1_750_000_000);

        let mut note = Entry::new(EntryKind::Note, "Wi-Fi");
        note.id = Uuid::from_u128(2);
        note.notes = "SSID: home\nKey: correct horse".into();
        note.created = t(1_760_000_000);
        note.modified = t(1_760_000_000);

        vec![login, note]
    }

    #[test]
    fn schema_v1_fixture_still_loads() {
        let bytes = std::fs::read(fixture(SCHEMA_V1)).unwrap();
        let opened = format::open(PASSWORD, &bytes).unwrap();
        let data = migrate::decode(&opened.plaintext).unwrap();
        assert_eq!(data.schema_version, 1);
        assert_eq!(data.entries, v1_entries());
    }

    /// Writes `schema-v1.lockery`. Only for introducing schema 1:
    /// `cargo test --test format_compat -- --ignored write_schema_v1_fixture`
    #[test]
    #[ignore = "regenerates committed fixtures; never run after schema 1 is released"]
    fn write_schema_v1_fixture() {
        let kdf = KdfParams::new(KdfParams::MIN_M_COST_KIB, 1, 1).unwrap();
        let key = VaultKey::derive_new(PASSWORD, kdf).unwrap();
        let mut data = VaultData::new();
        data.entries = v1_entries();
        let plaintext = migrate::encode(&data).unwrap();
        let bytes = format::seal(&key, CipherId::XChaCha20Poly1305, &plaintext).unwrap();
        std::fs::write(fixture(SCHEMA_V1), bytes).unwrap();
    }
}
