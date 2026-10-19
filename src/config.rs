//! User configuration, read from a TOML file.
//!
//! The file is optional: if it doesn't exist, defaults are used. Every field
//! is optional too (`#[serde(default)]`), and unknown keys are ignored, so a
//! config written for a newer or older Lockery still loads.
//!
//! Default location: `<config dir>/lockery/config.toml`, i.e.
//! `~/.config/lockery/config.toml` on Linux. `LOCKERY_CONFIG` overrides it.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Environment variable that overrides the config file location.
pub const CONFIG_ENV: &str = "LOCKERY_CONFIG";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Name of the vault opened when `lockery` is run without arguments.
    pub primary_vault: String,
    /// Seconds before a copied secret is cleared from the clipboard.
    pub clipboard_clear_secs: u32,
    /// Seconds of inactivity before the vault locks itself (0 = never).
    pub idle_lock_secs: u32,
    /// Defaults for the password / passphrase generator.
    pub generator: GeneratorConfig,
    /// Memory protection.
    pub security: SecurityConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            primary_vault: "default".into(),
            clipboard_clear_secs: 20,
            idle_lock_secs: 300,
            generator: GeneratorConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)] // these really are independent toggles
pub struct GeneratorConfig {
    pub password_length: u16,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Leave out look-alike characters such as `0`/`O` and `1`/`l`/`I`.
    pub exclude_ambiguous: bool,
    pub passphrase_words: u8,
    pub passphrase_separator: String,
    pub passphrase_capitalize: bool,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            password_length: 24,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
            passphrase_words: 6,
            passphrase_separator: "-".into(),
            passphrase_capitalize: false,
        }
    }
}

/// The `[security]` section.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Lock the vault key and decrypted vault contents in RAM (`mlock`) so
    /// they are never written to swap. Best-effort: if the OS limit
    /// (`ulimit -l`) is too small, Lockery warns once and carries on.
    /// Has no effect on Windows yet.
    pub lock_memory: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self { lock_memory: true }
    }
}

impl Config {
    /// Where the config file lives: `$LOCKERY_CONFIG` if set, otherwise the
    /// platform config directory.
    ///
    /// # Errors
    /// [`Error::NoHomeDir`] if no home directory can be determined.
    pub fn default_path() -> Result<PathBuf> {
        if let Some(path) = std::env::var_os(CONFIG_ENV) {
            return Ok(PathBuf::from(path));
        }
        let base = directories::BaseDirs::new().ok_or(Error::NoHomeDir)?;
        Ok(base.config_dir().join("lockery").join("config.toml"))
    }

    /// Load the config from [`Config::default_path`].
    ///
    /// # Errors
    /// See [`Config::load_from`].
    pub fn load() -> Result<Self> {
        Self::load_from(&Self::default_path()?)
    }

    /// Load the config from `path`, falling back to defaults if the file
    /// doesn't exist.
    ///
    /// # Errors
    /// An I/O error other than "not found", or [`Error::Config`] if the file
    /// isn't valid TOML for this structure.
    pub fn load_from(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(text) => Self::parse(&text).map_err(|source| Error::Config {
                path: path.to_path_buf(),
                source,
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Parse config TOML.
    ///
    /// # Errors
    /// Any TOML syntax or type error.
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_gives_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::load_from(&dir.path().join("nope.toml")).unwrap();
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn partial_file_fills_in_defaults_and_ignores_unknown_keys() {
        let cfg = Config::parse(
            r#"
            primary_vault = "personal"
            some_future_option = true

            [generator]
            password_length = 32
            "#,
        )
        .unwrap();
        assert_eq!(cfg.primary_vault, "personal");
        assert_eq!(cfg.clipboard_clear_secs, 20);
        assert_eq!(cfg.generator.password_length, 32);
        assert!(cfg.generator.symbols);
        assert!(
            cfg.security.lock_memory,
            "memory locking is on unless turned off"
        );
    }

    #[test]
    fn memory_locking_can_be_turned_off() {
        let cfg = Config::parse("[security]\nlock_memory = false\n").unwrap();
        assert!(!cfg.security.lock_memory);
        assert_eq!(cfg.generator, GeneratorConfig::default());
    }

    #[test]
    fn bad_types_are_reported_with_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "clipboard_clear_secs = \"soon\"").unwrap();
        assert!(matches!(
            Config::load_from(&path),
            Err(Error::Config { .. })
        ));
    }

    #[test]
    fn defaults_survive_a_toml_round_trip() {
        let text = toml::to_string(&Config::default()).unwrap();
        assert_eq!(Config::parse(&text).unwrap(), Config::default());
    }
}
