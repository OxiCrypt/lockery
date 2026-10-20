//! Turning decrypted bytes into a [`VaultData`] (and back), across schema
//! versions.
//!
//! There are two independent version numbers:
//!
//! * the *format* version in the file header (`vault::format`), covering
//!   encryption and file layout;
//! * the *schema* version inside the encrypted payload (this module),
//!   covering the shape of entries.
//!
//! Decoding first peeks at `schema_version`, then deserialises the matching
//! historical structure and upgrades it step by step to the current one.
//! Today only schema 1 exists, so there are no steps yet. When schema 2
//! arrives:
//!
//! 1. copy the current types into `v1` (frozen forever),
//! 2. change the live types and bump [`CURRENT_SCHEMA_VERSION`],
//! 3. add a `1 => v1::decode(bytes).map(upgrade_v1_to_v2)` arm below.

use std::io;

use crate::hardening::{self, SecretBuf};
use serde::Deserialize;

use super::model::VaultData;
use crate::error::{Error, Result};

/// The schema version this build writes.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Just enough of the payload to read its version; every other field is
/// skipped.
#[derive(Deserialize)]
struct SchemaPeek {
    schema_version: u32,
}

/// Deserialise a decrypted payload, upgrading it to the current schema.
///
/// # Errors
/// [`Error::UnsupportedSchema`] if the vault was written by a newer Lockery,
/// [`Error::Payload`] if the bytes aren't a valid payload.
pub fn decode(bytes: &[u8]) -> Result<VaultData> {
    let peek: SchemaPeek = ciborium::from_reader(bytes).map_err(payload_error)?;
    let data = match peek.schema_version {
        1 => ciborium::from_reader(bytes).map_err(payload_error),
        v => Err(Error::UnsupportedSchema(v)),
    };
    // ciborium decodes every string through a 4 KiB buffer on the stack,
    // in frames below this one; overwrite them now that it has returned.
    hardening::scrub_stack();
    data
}

/// Serialise `data` in the current schema.
///
/// The output buffer is sized exactly up front: letting a `Vec` grow would
/// leave stale, un-wiped copies of the plaintext behind in freed memory
/// every time it reallocates.
///
/// # Errors
/// [`Error::Payload`] if serialisation fails (it shouldn't).
pub fn encode(data: &VaultData) -> Result<SecretBuf> {
    debug_assert_eq!(data.schema_version, CURRENT_SCHEMA_VERSION);

    let mut counter = CountingWriter(0);
    ciborium::into_writer(data, &mut counter).map_err(payload_error)?;

    let mut out = SecretBuf::with_capacity(counter.0);
    ciborium::into_writer(data, &mut out).map_err(payload_error)?;
    debug_assert_eq!(out.len(), counter.0, "buffer must not have reallocated");
    Ok(out)
}

fn payload_error(e: impl std::fmt::Display) -> Error {
    Error::Payload(e.to_string())
}

/// An `io::Write` sink that only counts bytes.
struct CountingWriter(usize);

impl io::Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::{CustomField, Entry, EntryKind};

    fn sample() -> VaultData {
        let mut data = VaultData::new();
        let mut e = Entry::new(EntryKind::Login, "Example");
        e.username = "me@example.com".into();
        e.password = "p4ss".into();
        e.urls = vec!["https://example.com".into()];
        e.notes = "line one\nline two".into();
        e.tags = vec!["web".into()];
        e.custom_fields.push(CustomField {
            name: "PIN".into(),
            value: "0000".into(),
            hidden: true,
        });
        data.entries.push(e);
        data.entries.push(Entry::new(EntryKind::Note, "Wifi"));
        data
    }

    #[test]
    fn round_trip() {
        let data = sample();
        let bytes = encode(&data).unwrap();
        assert_eq!(decode(&bytes).unwrap(), data);
    }

    #[test]
    fn newer_schema_is_refused() {
        let mut data = VaultData::new();
        data.schema_version = CURRENT_SCHEMA_VERSION + 1;
        let mut bytes = Vec::new();
        ciborium::into_writer(&data, &mut bytes).unwrap();
        assert!(matches!(decode(&bytes), Err(Error::UnsupportedSchema(2))));
    }

    #[test]
    fn missing_optional_fields_get_defaults() {
        // An entry with only the required fields, as a much simpler writer
        // (or an older schema-1 build) might have produced.
        #[derive(serde::Serialize)]
        struct MinimalEntry {
            id: uuid::Uuid,
            title: &'static str,
            created: jiff::Timestamp,
            modified: jiff::Timestamp,
        }
        #[derive(serde::Serialize)]
        struct MinimalVault {
            schema_version: u32,
            created: jiff::Timestamp,
            modified: jiff::Timestamp,
            entries: Vec<MinimalEntry>,
        }
        let now = jiff::Timestamp::now();
        let minimal = MinimalVault {
            schema_version: 1,
            created: now,
            modified: now,
            entries: vec![MinimalEntry {
                id: uuid::Uuid::new_v4(),
                title: "Bare",
                created: now,
                modified: now,
            }],
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&minimal, &mut bytes).unwrap();

        let data = decode(&bytes).unwrap();
        let e = &data.entries[0];
        assert_eq!(e.title, "Bare");
        assert_eq!(e.kind, EntryKind::Login);
        assert!(e.password.is_empty() && e.urls.is_empty() && !e.favorite);
    }

    #[test]
    fn garbage_is_a_payload_error() {
        assert!(matches!(decode(b"\xff\x00garbage"), Err(Error::Payload(_))));
        assert!(matches!(decode(b""), Err(Error::Payload(_))));
    }
}
