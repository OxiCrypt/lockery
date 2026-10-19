//! Command-line interface definition.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use lockery::crypto::CipherId;

/// A keyboard-driven terminal password manager.
///
/// Run without arguments to open your primary vault, or give a vault name to
/// open that one instead.
#[derive(Debug, Parser)]
#[command(version, about, args_conflicts_with_subcommands = true)]
pub struct Cli {
    /// Name of the vault to open (defaults to the primary vault).
    pub name: Option<String>,

    /// Open a vault file at an explicit path instead of by name.
    #[arg(long, value_name = "FILE", conflicts_with = "name")]
    pub path: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new vault (the primary vault if no name is given).
    Init(InitArgs),
    /// List the vaults in the data directory.
    List,
    /// Import entries from a Bitwarden, KeePassXC, Chrome or Firefox CSV.
    Import {
        /// The CSV file to import.
        csv: PathBuf,
        /// Vault to import into (defaults to the primary vault).
        #[arg(long, value_name = "NAME")]
        vault: Option<String>,
    },
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Name of the vault to create.
    pub name: Option<String>,

    /// Cipher used to encrypt the vault.
    #[arg(long, value_enum, default_value_t = CipherArg::Xchacha20poly1305)]
    pub cipher: CipherArg,

    /// Argon2 memory cost in MiB. Setting any Argon2 option skips
    /// calibration; unset ones use the defaults (256 MiB, 3, 4).
    #[arg(long, value_name = "MIB")]
    pub memory_mib: Option<u32>,

    /// Argon2 iterations (passes over memory).
    #[arg(long, value_name = "N")]
    pub iterations: Option<u32>,

    /// Argon2 parallelism (lanes).
    #[arg(long, value_name = "N")]
    pub parallelism: Option<u32>,
}

impl InitArgs {
    /// True if the user set any Argon2 option by hand.
    pub fn has_manual_kdf(&self) -> bool {
        self.memory_mib.is_some() || self.iterations.is_some() || self.parallelism.is_some()
    }
}

/// Cipher names as typed on the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum CipherArg {
    /// XChaCha20-Poly1305 (default).
    Xchacha20poly1305,
    /// AES-256-GCM.
    Aes256gcm,
}

impl From<CipherArg> for CipherId {
    fn from(arg: CipherArg) -> Self {
        match arg {
            CipherArg::Xchacha20poly1305 => Self::XChaCha20Poly1305,
            CipherArg::Aes256gcm => Self::Aes256Gcm,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_name_and_subcommands() {
        let cli = Cli::parse_from(["lockery", "work"]);
        assert_eq!(cli.name.as_deref(), Some("work"));
        assert!(cli.command.is_none());

        let cli = Cli::parse_from(["lockery", "init", "work", "--cipher", "aes256gcm"]);
        let Some(Command::Init(init)) = cli.command else {
            panic!("expected init");
        };
        assert_eq!(init.name.as_deref(), Some("work"));
        assert_eq!(CipherId::from(init.cipher), CipherId::Aes256Gcm);
        assert!(!init.has_manual_kdf());

        assert!(Cli::try_parse_from(["lockery", "work", "--path", "x.lockery"]).is_err());
    }
}
