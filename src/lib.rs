//! Lockery: a keyboard-driven terminal password manager.
//!
//! The library holds all the logic so it can be tested (and fuzzed)
//! independently of the terminal UI; `main.rs` is a thin CLI wrapper.

pub mod config;
pub mod crypto;
pub mod csv_io;
pub mod error;
pub mod generator;
pub mod paths;
pub mod tui;
pub mod vault;

pub use error::{Error, Result};
