//! Binary entry point: parse arguments, load config, dispatch.
//!
//! Real behaviour lands milestone by milestone; until then each command says
//! which milestone will implement it.

mod cli;

use anyhow::{Context, bail};
use clap::Parser;
use lockery::config::Config;

use crate::cli::{Cli, Command};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::load().context("failed to load configuration")?;

    match cli.command {
        Some(Command::Init { .. }) => bail!("`lockery init` is not implemented yet (milestone M2)"),
        Some(Command::List) => bail!("`lockery list` is not implemented yet (milestone M2)"),
        Some(Command::Import { .. }) => {
            bail!("`lockery import` is not implemented yet (milestone M7)")
        }
        None => {
            let target = cli
                .path
                .map(|p| p.display().to_string())
                .or(cli.name)
                .unwrap_or(config.primary_vault);
            bail!("opening vault `{target}` is not implemented yet (milestones M2/M3)")
        }
    }
}
