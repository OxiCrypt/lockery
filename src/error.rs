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
}
