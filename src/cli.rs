//! Command-line interface definition.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

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
    Init {
        /// Name of the vault to create.
        name: Option<String>,
    },
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

        let cli = Cli::parse_from(["lockery", "init", "work"]);
        assert!(matches!(cli.command, Some(Command::Init { name: Some(ref n) }) if n == "work"));

        assert!(Cli::try_parse_from(["lockery", "work", "--path", "x.lockery"]).is_err());
    }
}
