//! Binary entry point: parse arguments, load config, dispatch.
//!
//! `lockery` with no subcommand opens the TUI on a terminal; everything
//! else is a plain command-line operation.

mod cli;
mod prompt;

use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, bail};
use clap::Parser;
use lockery::config::Config;
use lockery::crypto::calibrate::{self, DEFAULT_TARGET};
use lockery::crypto::{self, CipherId, KdfParams};
use lockery::csv_io;
use lockery::generator::Strength;
use lockery::hardening;
use lockery::paths::{self, VaultName};
use lockery::tui::{self, App, StatusKind, VaultTarget};
use lockery::vault::Vault;
use lockery::vault::format::CURRENT_FORMAT_VERSION;
use zeroize::Zeroizing;

use crate::cli::{Cli, Command, InitArgs};

/// Every freed block is wiped first, so copies of secrets that libraries
/// make and free don't linger in memory. See `hardening::WipingAllocator`.
#[global_allocator]
static ALLOCATOR: hardening::WipingAllocator = hardening::WipingAllocator;

fn main() -> anyhow::Result<()> {
    // Before anything else, so no secret is ever in a process that could
    // dump core or be read by a same-user debugger.
    let hardened = hardening::harden_process();
    if !hardened.complete() && cfg!(unix) {
        eprintln!(
            "Warning: couldn't fully protect this process from core dumps or debuggers \
             ({hardened:?}). Lockery will still work."
        );
    }

    let cli = Cli::parse();
    let config = Config::load().context("failed to load configuration")?;
    hardening::set_lock_memory(config.security.lock_memory);

    let result = match cli.command {
        Some(Command::Init(args)) => init(&config, &args),
        Some(Command::List) => list(&config),
        Some(Command::Import { csv, vault }) => import(&config, &csv, vault.as_deref()),
        None => open(&config, cli.name.as_deref(), cli.path),
    };
    // The TUI reports this itself; this covers the plain commands.
    warn_if_memory_unlocked();
    result
}

/// Tell the user (once) if secrets couldn't be locked in RAM.
fn warn_if_memory_unlocked() {
    if hardening::take_lock_failure() {
        eprintln!("Warning: {}", hardening::LOCK_FAILURE_ADVICE);
    }
}

/// `lockery init [NAME]`: create a new vault.
fn init(config: &Config, args: &InitArgs) -> anyhow::Result<()> {
    let name = vault_name(config, args.name.as_deref())?;
    let dir = paths::data_dir()?;
    let path = name.path_in(&dir);
    if path.exists() {
        bail!("vault '{name}' already exists at {}", path.display());
    }

    let kdf = if args.has_manual_kdf() {
        manual_kdf(args)?
    } else {
        eprintln!("Calibrating Argon2 for this machine (takes a few seconds)...");
        calibrate::calibrate(DEFAULT_TARGET)?
    };
    let cipher = CipherId::from(args.cipher);

    let password = prompt::password(&format!("New master password for '{name}': "))?;
    if password.is_empty() {
        bail!("the master password can't be empty");
    }
    if *prompt::password("Repeat master password: ")? != *password {
        bail!("passwords don't match; nothing was created");
    }
    // `Strength` caps how much it analyses: zxcvbn gets very slow on long
    // input, and a piped password can be any length.
    if Strength::of(&password, &[name.as_str()]).is_weak()
        && !prompt::confirm("That password is easy to guess. Use it anyway?")?
    {
        bail!("cancelled; nothing was created");
    }

    paths::ensure_dir(&dir)?;
    let vault = Vault::create(&path, password.as_bytes(), kdf, cipher)?;

    println!("Created vault '{name}' at {}", vault.path().display());
    println!("  {}", describe_crypto(&vault));
    // The name is the file name, so it is not encrypted.
    println!("Note: vault names are visible in the file name; the contents are encrypted.");
    Ok(())
}

/// Build Argon2 parameters from `--memory-mib/--iterations/--parallelism`,
/// filling in defaults for any that weren't given.
fn manual_kdf(args: &InitArgs) -> anyhow::Result<KdfParams> {
    let d = KdfParams::DEFAULT;
    let m_cost_kib = match args.memory_mib {
        Some(mib) => mib.checked_mul(1024).context("--memory-mib is too large")?,
        None => d.m_cost_kib(),
    };
    Ok(KdfParams::new(
        m_cost_kib,
        args.iterations.unwrap_or(d.t_cost()),
        args.parallelism.unwrap_or(d.p_cost()),
    )?)
}

/// `lockery list`: show the vaults in the data directory.
fn list(config: &Config) -> anyhow::Result<()> {
    let dir = paths::data_dir()?;
    let names = paths::list_vaults(&dir)?;
    if names.is_empty() {
        println!(
            "No vaults in {} yet. Create one with `lockery init`.",
            dir.display()
        );
        return Ok(());
    }
    for name in names {
        let marker = if name.as_str() == config.primary_vault {
            "  (primary)"
        } else {
            ""
        };
        println!("{name}{marker}");
    }
    Ok(())
}

/// `lockery [NAME]` / `lockery --path FILE`: unlock a vault.
///
/// On a terminal this starts the TUI. When stdin or stdout isn't a terminal
/// (scripts, tests), it unlocks the vault and prints a short summary.
fn open(config: &Config, name: Option<&str>, path: Option<PathBuf>) -> anyhow::Result<()> {
    let interactive = io::stdin().is_terminal() && io::stdout().is_terminal();
    let data_dir = paths::data_dir()?;

    let target = if let Some(path) = path {
        Some(VaultTarget {
            label: path.display().to_string(),
            path,
        })
    } else {
        let vault = vault_name(config, name)?;
        let target = VaultTarget::named(&vault, &data_dir);
        if target.path.exists() {
            Some(target)
        } else if interactive && name.is_none() {
            // No primary vault yet: let the picker show what does exist.
            None
        } else {
            let init = if vault.as_str() == config.primary_vault {
                "lockery init".to_owned()
            } else {
                format!("lockery init {vault}")
            };
            bail!("vault '{vault}' doesn't exist yet; create it with `{init}`");
        }
    };

    if interactive {
        let no_primary = target.is_none();
        let mut app = App::new(config.clone(), data_dir, target, Instant::now());
        if no_primary {
            app.set_status(
                StatusKind::Info,
                format!(
                    "Your primary vault '{}' doesn't exist yet.",
                    config.primary_vault
                ),
            );
        }
        tui::run(&mut app)?;
        return Ok(());
    }

    let Some(VaultTarget { label, path }) = target else {
        unreachable!("non-interactive runs always have a target");
    };
    let password = prompt::password(&format!("Master password for '{label}': "))?;
    let vault = Vault::unlock(&path, password.as_bytes())?;
    drop(password);

    if let Some(aside) = vault.recovered_from_backup() {
        eprintln!(
            "Warning: the vault file was damaged and has been restored from its backup.\n\
             The most recent change may be missing. The damaged file was kept at {}",
            aside.display()
        );
    }
    let count = vault.entries().len();
    println!(
        "Unlocked '{label}': {count} {}.",
        if count == 1 { "entry" } else { "entries" }
    );
    println!("  {}", describe_crypto(&vault));
    if vault.opened_format_version() < CURRENT_FORMAT_VERSION {
        println!("  This vault uses an older file format and will be upgraded on the next save.");
    }
    Ok(())
}

/// `lockery import <csv> [--vault NAME]`: add entries from another manager's
/// CSV export. Entries already in the vault are skipped.
fn import(config: &Config, csv: &Path, vault: Option<&str>) -> anyhow::Result<()> {
    let bytes = Zeroizing::new(
        std::fs::read(csv).with_context(|| format!("can't read {}", csv.display()))?,
    );
    let imported = csv_io::parse(&bytes)?;
    drop(bytes);

    let name = vault_name(config, vault)?;
    let path = name.path_in(&paths::data_dir()?);
    if !path.exists() {
        bail!("vault '{name}' doesn't exist yet; create it with `lockery init`");
    }
    let password = prompt::password(&format!("Master password for '{name}': "))?;
    let mut vault = Vault::unlock(&path, password.as_bytes())?;
    drop(password);

    println!(
        "Read {} entries from a {} export.",
        imported.entries.len(),
        imported.format.name()
    );
    for warning in &imported.warnings {
        println!("  ! {warning}");
    }
    let flags = csv_io::duplicate_flags(vault.entries(), &imported.entries);
    let duplicates = flags.iter().filter(|&&d| d).count();
    if duplicates > 0 {
        println!("{duplicates} are already in '{name}' and will be skipped.");
    }
    let new: Vec<_> = imported
        .entries
        .into_iter()
        .zip(flags)
        .filter_map(|(entry, duplicate)| (!duplicate).then_some(entry))
        .collect();
    if new.is_empty() {
        println!("Nothing new to import.");
        return Ok(());
    }
    if !prompt::confirm(&format!("Import {} entries into '{name}'?", new.len()))? {
        bail!("cancelled; nothing was imported");
    }
    let count = vault.add_many(new)?;
    println!("Imported {count} entries into '{name}'.");
    println!(
        "{} holds your passwords in plain text. Delete it once you no longer need it.",
        csv.display()
    );
    Ok(())
}

/// The vault name given on the command line, or the configured primary one.
fn vault_name(config: &Config, name: Option<&str>) -> anyhow::Result<VaultName> {
    let raw = name.unwrap_or(&config.primary_vault);
    VaultName::parse(raw).with_context(|| {
        if name.is_none() {
            "the `primary_vault` setting in the config file is not a valid vault name".to_owned()
        } else {
            "check the vault name".to_owned()
        }
    })
}

/// e.g. "XChaCha20-Poly1305, Argon2id 256 MiB × 3 passes × 4 lanes"
fn describe_crypto(vault: &Vault) -> String {
    crypto::describe(vault.cipher(), vault.kdf())
}
