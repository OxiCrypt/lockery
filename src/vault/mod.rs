//! Everything about vaults.
//!
//! Layers, from the bottom up:
//!
//! * [`storage`]: crash-safe reading/writing of opaque bytes, file locking.
//! * [`format`]: the encrypted file format (header, AEAD, padding).
//! * [`model`] and [`migrate`]: the decrypted entries and their versioned
//!   serialisation.
//! * [`manage`]: renaming and deleting whole vaults.
//! * [`session`]: an unlocked [`Vault`] tying the layers together, with
//!   save-on-every-change editing.

pub mod format;
pub mod manage;
pub mod migrate;
pub mod model;
pub mod session;
pub mod storage;

pub use model::{CustomField, Entry, EntryKind, VaultData};
pub use session::Vault;
