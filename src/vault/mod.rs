//! Everything about vault files: the encrypted format and crash-safe storage.
//!
//! The entry model (`model.rs`) and payload migrations (`migrate.rs`) arrive
//! in M2, layered on top of the opaque plaintext these modules produce.

pub mod format;
pub mod storage;
