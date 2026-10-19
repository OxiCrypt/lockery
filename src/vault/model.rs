//! The decrypted contents of a vault: entries and their fields.
//!
//! These types are serialised to CBOR and encrypted by `vault::format`.
//! Compatibility rules for changing them:
//!
//! * Adding a field: give it `#[serde(default)]`, so older vaults that lack
//!   it still load. No schema bump needed.
//! * Renaming, removing or changing the meaning of a field: bump
//!   `migrate::CURRENT_SCHEMA_VERSION` and add a migration step.
//!
//! Every type that can hold user data wipes its strings when dropped
//! (`ZeroizeOnDrop`), and their `Debug` output hides secret values.

use std::fmt;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// What an entry represents. Serialised by name, so new kinds can be added
/// without renumbering. `Passkey` will join this list in M10.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// A website or app login: username, password, URLs.
    #[default]
    Login,
    /// Free-form secure note; only `title` and `notes` are expected.
    Note,
}

/// A user-defined extra field on an entry, e.g. "PIN" or "Security answer".
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    /// Masked in the UI (like a password) when true.
    #[serde(default)]
    pub hidden: bool,
}

impl fmt::Debug for CustomField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value: &dyn fmt::Debug = if self.hidden {
            &"<redacted>"
        } else {
            &self.value
        };
        f.debug_struct("CustomField")
            .field("name", &self.name)
            .field("value", value)
            .finish_non_exhaustive()
    }
}

/// One item in the vault.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    /// Stable identifier; never changes, even when the title does.
    #[zeroize(skip)]
    pub id: Uuid,
    #[zeroize(skip)]
    #[serde(default)]
    pub kind: EntryKind,
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub urls: Vec<String>,
    /// Free-form, multi-line notes.
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    /// TOTP secret or `otpauth://` URI, kept so imports don't lose it.
    /// (Code generation isn't planned for the first alpha.)
    #[serde(default)]
    pub totp: String,
    #[serde(default)]
    pub favorite: bool,
    #[zeroize(skip)]
    pub created: Timestamp,
    #[zeroize(skip)]
    pub modified: Timestamp,
}

impl Entry {
    /// A new, otherwise empty entry with a fresh id and timestamps.
    #[must_use]
    pub fn new(kind: EntryKind, title: impl Into<String>) -> Self {
        let now = Timestamp::now();
        Self {
            id: Uuid::new_v4(),
            kind,
            title: title.into(),
            username: String::new(),
            password: String::new(),
            urls: Vec::new(),
            notes: String::new(),
            tags: Vec::new(),
            custom_fields: Vec::new(),
            totp: String::new(),
            favorite: false,
            created: now,
            modified: now,
        }
    }
}

// Shows which secret fields are set, never their values.
impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let set = |s: &str| {
            if s.is_empty() {
                "<empty>"
            } else {
                "<redacted>"
            }
        };
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("title", &self.title)
            .field("username", &self.username)
            .field("password", &set(&self.password))
            .field("urls", &self.urls)
            .field("notes", &set(&self.notes))
            .field("tags", &self.tags)
            .field("custom_fields", &self.custom_fields)
            .field("totp", &set(&self.totp))
            .field("favorite", &self.favorite)
            .field("created", &self.created)
            .field("modified", &self.modified)
            .finish()
    }
}

/// Everything stored inside one vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultData {
    /// Version of this structure; see `vault::migrate`.
    #[zeroize(skip)]
    pub schema_version: u32,
    #[zeroize(skip)]
    pub created: Timestamp,
    /// When any entry was last added, changed or deleted.
    #[zeroize(skip)]
    pub modified: Timestamp,
    #[serde(default)]
    pub entries: Vec<Entry>,
}

impl VaultData {
    /// An empty vault in the current schema.
    #[must_use]
    pub fn new() -> Self {
        let now = Timestamp::now();
        Self {
            schema_version: super::migrate::CURRENT_SCHEMA_VERSION,
            created: now,
            modified: now,
            entries: Vec::new(),
        }
    }
}

impl Default for VaultData {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_shows_secrets() {
        let mut e = Entry::new(EntryKind::Login, "Bank");
        e.password = "hunter2".into();
        e.notes = "PIN is 1234".into();
        e.totp = "JBSWY3DPEHPK3PXP".into();
        e.custom_fields.push(CustomField {
            name: "PIN".into(),
            value: "1234".into(),
            hidden: true,
        });
        let shown = format!("{e:?}");
        for secret in ["hunter2", "1234", "JBSWY3DPEHPK3PXP"] {
            assert!(!shown.contains(secret), "{secret} leaked: {shown}");
        }
        assert!(shown.contains("Bank"));
    }

    #[test]
    fn new_entries_get_unique_ids() {
        let a = Entry::new(EntryKind::Login, "a");
        let b = Entry::new(EntryKind::Login, "a");
        assert_ne!(a.id, b.id);
        assert_eq!(a.created, a.modified);
    }
}
