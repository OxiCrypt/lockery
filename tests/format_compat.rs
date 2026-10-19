//! Backwards-compatibility tests against committed vault files.
//!
//! Every format version Lockery has ever written gets a fixture in
//! `tests/fixtures/`. These files must keep opening forever. Once a version
//! has been released its fixtures must NEVER be regenerated; add new files
//! for new versions instead.

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
