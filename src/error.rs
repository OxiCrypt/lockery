//! Library-wide error type.
//!
//! The binary wraps these in `anyhow` for reporting; the library itself keeps
//! typed errors so callers (the TUI, tests) can react to specific cases such
//! as a wrong password or a vault that is already open elsewhere.

use std::path::PathBuf;

/// Convenience alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Another process (or another handle in this one) holds the vault lock.
    #[error("vault is already open in another Lockery instance: {}", .0.display())]
    VaultLocked(PathBuf),

    /// The file does not start with the Lockery magic bytes.
    #[error("not a Lockery vault file")]
    NotAVault,

    /// The file was written by a newer Lockery than this one.
    #[error("unsupported vault format version {0}; upgrade Lockery to open this vault")]
    UnsupportedVersion(u16),

    #[error("unknown key-derivation function id {0}")]
    UnknownKdf(u8),

    #[error("unknown cipher id {0}")]
    UnknownCipher(u8),

    /// Argon2 parameters outside the range Lockery accepts.
    #[error("invalid Argon2 parameters: {0}")]
    InvalidKdfParams(String),

    /// The file is structurally broken (truncated, wrong lengths, ...).
    #[error("malformed vault file: {0}")]
    Malformed(&'static str),

    /// Authentication failed. A wrong password and a tampered/corrupted file
    /// are deliberately indistinguishable here.
    #[error("wrong password, or the vault file is corrupted")]
    Decryption,

    /// A cryptographic primitive failed for a reason other than
    /// authentication (should not happen with valid inputs).
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// The OS random number generator failed.
    #[error("system random number generator failed: {0}")]
    Rng(String),

    /// A file written during save did not read back correctly, so the save
    /// was aborted and the previous vault left untouched.
    #[error("vault write could not be verified; the previous version was kept")]
    VerifyFailed(#[source] Box<Error>),

    #[error("could not read config file {}: {source}", path.display())]
    Config {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    /// No home directory could be determined, so default paths are unknown.
    #[error("could not determine the user's home directory")]
    NoHomeDir,

    /// A vault name that isn't 1-64 characters of `[A-Za-z0-9_-]`.
    #[error("invalid vault name {0:?}: use 1 to 64 letters, digits, '-' or '_'")]
    InvalidVaultName(String),

    #[error("a vault already exists at {}", .0.display())]
    VaultExists(PathBuf),

    #[error("no vault found at {}", .0.display())]
    VaultNotFound(PathBuf),

    /// The decrypted payload uses a schema newer than this build knows.
    /// Refusing (rather than ignoring unknown fields) prevents an old Lockery
    /// from silently dropping data the next time it saves.
    #[error("vault uses data schema version {0}, which is newer than this Lockery supports")]
    UnsupportedSchema(u32),

    /// The decrypted payload couldn't be (de)serialised.
    #[error("vault contents are invalid: {0}")]
    Payload(String),

    #[error("no entry with id {0}")]
    EntryNotFound(uuid::Uuid),

    /// Re-keying succeeded, but the `.bak` copy still holds the version
    /// encrypted the old way (e.g. with the old password).
    #[error(
        "the vault was re-encrypted, but its old backup couldn't be replaced ({0}); \
         the backup still opens with the previous password"
    )]
    BackupNotRefreshed(#[source] Box<Error>),

    /// Password/passphrase generator options that can't be satisfied.
    #[error("{0}")]
    Generator(String),
}
