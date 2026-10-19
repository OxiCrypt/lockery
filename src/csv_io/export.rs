//! Writing entries as a Bitwarden-format CSV.
//!
//! Bitwarden's CSV layout is the one almost every password manager can
//! import, so it's the only export format. Its columns can't hold
//! everything Lockery stores; anything that doesn't fit is reported as a
//! warning rather than silently dropped:
//!
//! * one folder per item: only an entry's first tag is exported;
//! * custom fields have no "hidden" flag, and are one per line, so a
//!   multi-line value is joined onto one line;
//! * there are no timestamps.
//!
//! The file is plaintext. It's written with owner-only permissions on unix
//! and never overwrites an existing file.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::vault::{Entry, EntryKind};

/// Bitwarden's CSV header row.
pub const BITWARDEN_COLUMNS: [&str; 11] = [
    "folder",
    "favorite",
    "type",
    "name",
    "notes",
    "fields",
    "reprompt",
    "login_uri",
    "login_username",
    "login_password",
    "login_totp",
];

/// An export, ready to write.
pub struct Exported {
    /// The CSV text; wiped from memory when dropped.
    pub csv: Zeroizing<Vec<u8>>,
    /// What couldn't be represented exactly.
    pub warnings: Vec<String>,
}

/// Turn `entries` into a Bitwarden CSV.
///
/// # Errors
/// [`Error::Export`] if the CSV writer fails (it writes to memory, so this
/// shouldn't happen).
pub fn export_bitwarden(entries: &[Entry]) -> Result<Exported> {
    // Size the buffer up front so it never reallocates and leaves unwiped
    // copies behind. Quoting at most doubles each field, plus separators.
    let estimate: usize = entries
        .iter()
        .map(|e| 2 * approx_len(e) + 64)
        .sum::<usize>()
        + 256;
    let mut csv = Zeroizing::new(Vec::with_capacity(estimate));
    // The writer keeps a small internal buffer (8 KiB) that isn't wiped when
    // freed. That's accepted: this text is about to be written to disk as
    // plaintext anyway. (A zero-size buffer makes the csv writer loop
    // forever, so it can't be avoided that way.)
    let mut writer = csv::Writer::from_writer(&mut *csv);

    let (mut extra_tags, mut hidden_fields, mut joined_values) = (0, 0, 0);
    writer
        .write_record(BITWARDEN_COLUMNS)
        .map_err(|e| export_error(&e))?;
    for e in entries {
        extra_tags += usize::from(e.tags.len() > 1);
        hidden_fields += e.custom_fields.iter().filter(|f| f.hidden).count();
        let fields: Vec<String> = e
            .custom_fields
            .iter()
            .map(|f| {
                if f.value.contains('\n') {
                    joined_values += 1;
                }
                format!("{}: {}", f.name, f.value.replace('\n', " "))
            })
            .collect();
        let is_login = e.kind == EntryKind::Login;
        let login = |value: String| if is_login { value } else { String::new() };
        let record = [
            e.tags.first().cloned().unwrap_or_default(),
            if e.favorite {
                "1".into()
            } else {
                String::new()
            },
            if is_login {
                "login".into()
            } else {
                "note".into()
            },
            e.title.clone(),
            e.notes.clone(),
            fields.join("\n"),
            "0".into(),
            login(e.urls.join(",")),
            login(e.username.clone()),
            login(e.password.clone()),
            login(e.totp.clone()),
        ];
        writer.write_record(&record).map_err(|e| export_error(&e))?;
        // Wipe this row's copies of the secrets.
        let mut record = record;
        for field in &mut record {
            zeroize::Zeroize::zeroize(field);
        }
    }

    writer.flush()?;
    drop(writer);

    let mut warnings = Vec::new();
    if extra_tags > 0 {
        warnings.push(format!(
            "{extra_tags} entries have more than one tag; Bitwarden has one folder per item, so only the first tag was exported."
        ));
    }
    if hidden_fields > 0 {
        warnings.push(format!(
            "{hidden_fields} hidden custom fields were exported as ordinary fields (Bitwarden's CSV has no hidden flag)."
        ));
    }
    if joined_values > 0 {
        warnings.push(format!(
            "{joined_values} multi-line custom field values were joined onto one line."
        ));
    }
    Ok(Exported { csv, warnings })
}

/// Rough size of an entry's text, for the buffer estimate.
fn approx_len(e: &Entry) -> usize {
    e.title.len()
        + e.username.len()
        + e.password.len()
        + e.urls.iter().map(|u| u.len() + 1).sum::<usize>()
        + e.notes.len()
        + e.totp.len()
        + e.tags.first().map_or(0, String::len)
        + e.custom_fields
            .iter()
            .map(|f| f.name.len() + f.value.len() + 3)
            .sum::<usize>()
}

fn export_error(e: &csv::Error) -> Error {
    Error::Export(e.to_string())
}

/// Write `bytes` to a new file at `path`, readable only by its owner on
/// unix. Refuses to overwrite anything.
///
/// # Errors
/// [`Error::Export`] if the file already exists, or any I/O error.
pub fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => Error::Export(format!(
            "{} already exists; choose another file name",
            path.display()
        )),
        _ => Error::Io(e),
    })?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csv_io::import::{self, CsvFormat};
    use crate::vault::CustomField;

    fn rich_entries() -> Vec<Entry> {
        let mut login = Entry::new(EntryKind::Login, "Mail, \"work\"");
        login.username = "alice@example.com".into();
        login.password = "p,a\"s\ns".into(); // every CSV special character
        login.urls = vec!["https://mail.example".into(), "imap.mail.example".into()];
        login.notes = "Line 1\nLine 2".into();
        login.totp = "otpauth://totp/x?secret=JBSWY3DP".into();
        login.tags = vec!["Work".into()];
        login.favorite = true;
        login.custom_fields = vec![CustomField {
            name: "PIN".into(),
            value: "1234".into(),
            hidden: false,
        }];

        let mut note = Entry::new(EntryKind::Note, "Wi-Fi");
        note.notes = "SSID: home".into();
        vec![login, note]
    }

    #[test]
    fn export_then_import_round_trips() {
        let original = rich_entries();
        let exported = export_bitwarden(&original).unwrap();
        assert!(exported.warnings.is_empty(), "{:?}", exported.warnings);

        let imported = import::parse(&exported.csv).unwrap();
        assert_eq!(imported.format, CsvFormat::Bitwarden);
        assert!(imported.warnings.is_empty(), "{:?}", imported.warnings);
        assert_eq!(imported.entries.len(), original.len());
        for (a, b) in original.iter().zip(&imported.entries) {
            // Ids and timestamps aren't part of the Bitwarden format.
            let mut b = b.clone();
            b.id = a.id;
            b.created = a.created;
            b.modified = a.modified;
            assert_eq!(*a, b);
        }
    }

    #[test]
    fn lossy_bits_are_reported() {
        let mut e = Entry::new(EntryKind::Login, "x");
        e.tags = vec!["a".into(), "b".into()];
        e.custom_fields = vec![CustomField {
            name: "k".into(),
            value: "multi\nline".into(),
            hidden: true,
        }];
        let warnings = export_bitwarden(&[e]).unwrap().warnings;
        assert_eq!(warnings.len(), 3, "{warnings:?}");
    }

    #[test]
    fn private_file_is_new_and_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.csv");
        write_new_private_file(&path, b"x").unwrap();
        assert!(
            write_new_private_file(&path, b"y").is_err(),
            "never overwrites"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
