//! Reading CSV exports from other password managers.
//!
//! The format is recognised from the header row, and columns are found by
//! name, never by position, so reordered or extra columns are fine. Columns
//! Lockery doesn't know become custom fields rather than being dropped.
//!
//! | Source    | Recognised by                    | Notes                                   |
//! |-----------|----------------------------------|-----------------------------------------|
//! | Bitwarden | `type`, `name`, `login_password` | folder → tag, `fields` → custom fields  |
//! | KeePassXC | `group`, `title`, `password`     | group path (minus `Root`) → tag, dates  |
//! | Firefox   | `httpRealm` or `formActionOrigin`| title from the URL's host, dates        |
//! | Chrome    | `name`, `url`, `password`        | (also Edge, Brave and other Chromiums)  |

use std::collections::HashSet;
use std::str::FromStr;

use jiff::Timestamp;

use crate::error::{Error, Result};
use crate::vault::{CustomField, Entry, EntryKind};

/// Which manager a CSV came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsvFormat {
    Bitwarden,
    KeePassXc,
    Firefox,
    Chrome,
}

impl CsvFormat {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bitwarden => "Bitwarden",
            Self::KeePassXc => "KeePassXC",
            Self::Firefox => "Firefox",
            Self::Chrome => "Chrome",
        }
    }

    /// Lower-case names of the columns this format maps to entry fields.
    /// Any other column becomes a custom field.
    const fn known_columns(self) -> &'static [&'static str] {
        match self {
            Self::Bitwarden => &[
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
            ],
            Self::KeePassXc => &[
                "group",
                "title",
                "username",
                "password",
                "url",
                "notes",
                "totp",
                "icon",
                "last modified",
                "created",
            ],
            Self::Firefox => &[
                "url",
                "username",
                "password",
                "httprealm",
                "formactionorigin",
                "guid",
                "timecreated",
                "timelastused",
                "timepasswordchanged",
            ],
            Self::Chrome => &["name", "url", "username", "password", "note"],
        }
    }

    /// Recognise the format from lower-cased header names.
    fn detect(headers: &[String]) -> Option<Self> {
        let has = |name: &str| headers.iter().any(|h| h == name);
        if has("type") && has("name") && has("login_password") {
            Some(Self::Bitwarden)
        } else if has("group") && has("title") && has("password") {
            Some(Self::KeePassXc)
        } else if (has("httprealm") || has("formactionorigin")) && has("password") {
            Some(Self::Firefox)
        } else if has("name") && has("url") && has("password") {
            Some(Self::Chrome)
        } else {
            None
        }
    }
}

/// The result of reading a CSV file.
#[derive(Debug)]
pub struct Imported {
    pub format: CsvFormat,
    /// One entry per usable row, in file order.
    pub entries: Vec<Entry>,
    /// Things the user should know: skipped rows, unreadable dates, ...
    pub warnings: Vec<String>,
}

/// Parse a CSV export.
///
/// # Errors
/// [`Error::Import`] if the file isn't CSV or its columns aren't one of the
/// supported formats.
pub fn parse(bytes: &[u8]) -> Result<Imported> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes); // UTF-8 BOM
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_reader(bytes);

    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| import_error(&e))?
        .iter()
        .map(|h| h.trim().to_lowercase())
        .collect();
    let format = CsvFormat::detect(&headers).ok_or_else(|| {
        Error::Import(
            "unrecognised CSV columns; expected an export from Bitwarden, KeePassXC, Chrome or Firefox"
                .into(),
        )
    })?;
    // The original spelling of each header, for naming custom fields.
    let original: Vec<String> = reader
        .headers()
        .map_err(|e| import_error(&e))?
        .iter()
        .map(|h| h.trim().to_owned())
        .collect();

    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    // One record, reused for every row, rather than a fresh allocation per
    // row left unwiped in freed memory. The csv crate gives no way to wipe
    // the record's (or the reader's) buffer; the whole file is plaintext
    // the user already has on disk, which the threat model notes.
    let mut record = csv::StringRecord::new();
    while reader
        .read_record(&mut record)
        .map_err(|e| import_error(&e))?
    {
        let line = record.position().map_or(0, csv::Position::line);
        let row = Row {
            headers: &headers,
            original: &original,
            record: &record,
            format,
        };
        // Rows that are skipped add their own warning.
        if let Some(entry) = row.to_entry(&mut warnings, line) {
            entries.push(entry);
        }
    }

    Ok(Imported {
        format,
        entries,
        warnings,
    })
}

fn import_error(e: &csv::Error) -> Error {
    Error::Import(e.to_string())
}

/// One CSV record, with its columns looked up by name.
struct Row<'a> {
    headers: &'a [String],
    original: &'a [String],
    record: &'a csv::StringRecord,
    format: CsvFormat,
}

impl Row<'_> {
    /// The value in column `name` (lower-case), or "" if there's no such
    /// column.
    fn get(&self, name: &str) -> &str {
        self.headers
            .iter()
            .position(|h| h == name)
            .and_then(|i| self.record.get(i))
            .unwrap_or("")
    }

    /// Non-empty columns this format doesn't know, as custom fields.
    fn extra_fields(&self) -> Vec<CustomField> {
        let known = self.format.known_columns();
        self.headers
            .iter()
            .enumerate()
            .filter(|(_, h)| !known.contains(&h.as_str()))
            .filter_map(|(i, _)| {
                let value = self.record.get(i)?;
                (!value.is_empty()).then(|| CustomField {
                    name: self.original[i].clone(),
                    value: value.to_owned(),
                    hidden: false,
                })
            })
            .collect()
    }

    fn to_entry(&self, warnings: &mut Vec<String>, line: u64) -> Option<Entry> {
        let mut entry = match self.format {
            CsvFormat::Bitwarden => self.bitwarden(warnings, line)?,
            CsvFormat::KeePassXc => self.keepassxc(warnings, line),
            CsvFormat::Firefox => self.firefox(warnings, line),
            CsvFormat::Chrome => self.chrome(),
        };
        entry.custom_fields.extend(self.extra_fields());

        let empty = entry.username.is_empty()
            && entry.password.is_empty()
            && entry.urls.is_empty()
            && entry.notes.is_empty();
        if entry.title.is_empty() && empty {
            warnings.push(format!(
                "Line {line}: skipped, it has no title, login or notes."
            ));
            return None;
        }
        if entry.title.is_empty() {
            entry.title = entry
                .urls
                .first()
                .and_then(|u| host(u))
                .unwrap_or_else(|| "Untitled".to_owned());
        }
        Some(entry)
    }

    fn bitwarden(&self, warnings: &mut Vec<String>, line: u64) -> Option<Entry> {
        let kind = match self.get("type") {
            "login" | "" => EntryKind::Login,
            "note" => EntryKind::Note,
            other => {
                warnings.push(format!(
                    "Line {line}: skipped a Bitwarden “{other}” item; only logins and notes are supported."
                ));
                return None;
            }
        };
        let mut e = Entry::new(kind, self.get("name").trim());
        self.get("login_username").clone_into(&mut e.username);
        self.get("login_password").clone_into(&mut e.password);
        e.urls = split_list(self.get("login_uri"));
        self.get("login_totp").trim().clone_into(&mut e.totp);
        self.get("notes").clone_into(&mut e.notes);
        e.favorite = self.get("favorite") == "1";
        e.tags = non_empty(self.get("folder").trim());
        // Custom fields are exported one per line as "name: value".
        e.custom_fields = self
            .get("fields")
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let (name, value) = l.split_once(": ").unwrap_or((l, ""));
                CustomField {
                    name: name.trim().to_owned(),
                    value: value.to_owned(),
                    hidden: false,
                }
            })
            .collect();
        Some(e)
    }

    fn keepassxc(&self, warnings: &mut Vec<String>, line: u64) -> Entry {
        let mut e = Entry::new(EntryKind::Login, self.get("title").trim());
        self.get("username").clone_into(&mut e.username);
        self.get("password").clone_into(&mut e.password);
        e.urls = non_empty(self.get("url").trim());
        self.get("notes").clone_into(&mut e.notes);
        self.get("totp").trim().clone_into(&mut e.totp);
        // "Root/Email/Work" → tag "Email/Work"; plain "Root" → no tag.
        let group = self.get("group").trim();
        let group = group
            .strip_prefix("Root")
            .unwrap_or(group)
            .trim_start_matches('/');
        e.tags = non_empty(group);
        let created = parse_time(self.get("created"), warnings, line);
        let modified = parse_time(self.get("last modified"), warnings, line);
        set_times(&mut e, created, modified);
        e
    }

    fn firefox(&self, warnings: &mut Vec<String>, line: u64) -> Entry {
        let url = self.get("url").trim();
        let mut e = Entry::new(EntryKind::Login, host(url).unwrap_or_default());
        self.get("username").clone_into(&mut e.username);
        self.get("password").clone_into(&mut e.password);
        e.urls = non_empty(url);
        for (column, name) in [
            ("httprealm", "HTTP realm"),
            ("formactionorigin", "Form action origin"),
            ("guid", "Firefox GUID"),
        ] {
            let value = self.get(column);
            if !value.is_empty() {
                e.custom_fields.push(CustomField {
                    name: name.to_owned(),
                    value: value.to_owned(),
                    hidden: false,
                });
            }
        }
        let created = parse_millis(self.get("timecreated"), warnings, line);
        let modified = parse_millis(self.get("timepasswordchanged"), warnings, line);
        set_times(&mut e, created, modified);
        e
    }

    fn chrome(&self) -> Entry {
        let url = self.get("url").trim();
        let mut e = Entry::new(EntryKind::Login, self.get("name").trim());
        self.get("username").clone_into(&mut e.username);
        self.get("password").clone_into(&mut e.password);
        e.urls = non_empty(url);
        self.get("note").clone_into(&mut e.notes);
        e
    }
}

/// `vec![s]`, or nothing if `s` is empty.
fn non_empty(s: &str) -> Vec<String> {
    if s.is_empty() {
        Vec::new()
    } else {
        vec![s.to_owned()]
    }
}

/// A comma- or newline-separated list, trimmed, without empty items.
fn split_list(s: &str) -> Vec<String> {
    s.split([',', '\n'])
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The host part of a URL, without `www.`: `https://www.a.com:8/x` → `a.com`.
fn host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h); // user@host
    let host = host.split(':').next()?;
    let host = host.strip_prefix("www.").unwrap_or(host);
    (!host.is_empty()).then(|| host.to_lowercase())
}

/// An RFC 3339 timestamp such as `2024-03-01T10:00:00Z`.
fn parse_time(s: &str, warnings: &mut Vec<String>, line: u64) -> Option<Timestamp> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let parsed = Timestamp::from_str(s).ok();
    if parsed.is_none() {
        warnings.push(format!(
            "Line {line}: couldn't read the date “{s}”; using today instead."
        ));
    }
    parsed
}

/// Milliseconds since 1970, as Firefox writes them.
fn parse_millis(s: &str, warnings: &mut Vec<String>, line: u64) -> Option<Timestamp> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let parsed = s
        .parse::<i64>()
        .ok()
        .and_then(|ms| Timestamp::from_millisecond(ms).ok());
    if parsed.is_none() {
        warnings.push(format!(
            "Line {line}: couldn't read the date “{s}”; using today instead."
        ));
    }
    parsed
}

/// Keep the source's dates when it has them.
fn set_times(e: &mut Entry, created: Option<Timestamp>, modified: Option<Timestamp>) {
    if let Some(created) = created {
        e.created = created;
        e.modified = created;
    }
    if let Some(modified) = modified {
        e.modified = modified;
    }
}

// ---------------------------------------------------------------------------
// Duplicates
// ---------------------------------------------------------------------------

/// What makes two entries "the same" for importing purposes: the same kind,
/// title (ignoring case), username and password, or for notes the same
/// title and text.
fn duplicate_key(e: &Entry) -> (EntryKind, String, &str, &str) {
    let detail = if e.kind == EntryKind::Note {
        e.notes.as_str()
    } else {
        e.password.as_str()
    };
    (
        e.kind,
        e.title.trim().to_lowercase(),
        e.username.as_str(),
        detail,
    )
}

/// For each of `incoming`, whether it duplicates an entry in `existing` or
/// an earlier one in `incoming` (so importing the same file twice, or a
/// file with repeated rows, doesn't create copies).
#[must_use]
pub fn duplicate_flags(existing: &[Entry], incoming: &[Entry]) -> Vec<bool> {
    let mut seen: HashSet<_> = existing.iter().map(duplicate_key).collect();
    incoming
        .iter()
        .map(|e| !seen.insert(duplicate_key(e)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_extraction() {
        assert_eq!(
            host("https://www.Example.com:8443/login?x").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            host("imap.mail.example").as_deref(),
            Some("imap.mail.example")
        );
        assert_eq!(
            host("ftp://user@files.example/x").as_deref(),
            Some("files.example")
        );
        assert_eq!(host(""), None);
    }

    #[test]
    fn unknown_formats_are_rejected() {
        let err = parse(b"foo,bar\n1,2\n").unwrap_err();
        assert!(
            err.to_string().contains("unrecognised CSV columns"),
            "{err}"
        );
    }

    #[test]
    fn bom_extra_columns_and_empty_rows() {
        let csv = "\u{feff}name,url,username,password,note,Security question\n\
                   Shop,https://shop.example,me,pw,,Mother's maiden name\n\
                   ,,,,,\n";
        let imported = parse(csv.as_bytes()).unwrap();
        assert_eq!(imported.format, CsvFormat::Chrome);
        assert_eq!(imported.entries.len(), 1);
        let field = &imported.entries[0].custom_fields[0];
        assert_eq!(
            (field.name.as_str(), field.value.as_str()),
            ("Security question", "Mother's maiden name")
        );
        assert_eq!(
            imported.warnings,
            ["Line 3: skipped, it has no title, login or notes."]
        );
    }

    #[test]
    fn duplicates_against_vault_and_within_file() {
        let mut a = Entry::new(EntryKind::Login, "Bank");
        a.username = "me".into();
        a.password = "1".into();
        let mut same = a.clone();
        same.title = "BANK ".into();
        let mut changed_password = a.clone();
        changed_password.password = "2".into();
        let flags = duplicate_flags(
            &[a],
            &[same.clone(), changed_password.clone(), changed_password],
        );
        assert_eq!(flags, [true, false, true]);
    }
}
