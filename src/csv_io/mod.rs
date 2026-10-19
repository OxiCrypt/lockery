//! CSV import (Bitwarden, KeePassXC, Chrome, Firefox) and Bitwarden-format
//! export.
//!
//! Named `csv_io` rather than `csv` so it doesn't clash with the `csv`
//! crate it uses.
//!
//! CSV files are plaintext: anyone who can read one has every password in
//! it. The UI says so whenever one is read or written.

pub mod export;
pub mod import;

pub use export::{Exported, export_bitwarden, write_new_private_file};
pub use import::{CsvFormat, Imported, duplicate_flags, parse};
