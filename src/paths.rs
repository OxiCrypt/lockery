//! Where vaults live, and how vault names map to files.
//!
//! All named vaults sit side by side in one data directory:
//!
//! | Platform | Data directory                              |
//! |----------|---------------------------------------------|
//! | Linux    | `$XDG_DATA_HOME/lockery` (`~/.local/share/lockery`) |
//! | macOS    | `~/Library/Application Support/lockery`     |
//! | Windows  | `%APPDATA%\lockery`                         |
//!
//! `LOCKERY_DATA_DIR` overrides the directory (the tests rely on this).
//!
//! A vault named `work` is the file `work.lockery`. Vault names end up in
//! file names, so they are restricted to a safe character set, which also
//! rules out path traversal such as `../x`.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Environment variable that overrides the data directory.
pub const DATA_DIR_ENV: &str = "LOCKERY_DATA_DIR";

/// File extension of vault files.
pub const VAULT_EXTENSION: &str = "lockery";

/// Longest accepted vault name.
pub const MAX_NAME_LEN: usize = 64;

/// A validated vault name: 1 to [`MAX_NAME_LEN`] ASCII letters, digits, `-`
/// or `_`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VaultName(String);

impl VaultName {
    /// Validate `name`.
    ///
    /// # Errors
    /// [`Error::InvalidVaultName`] if it's empty, too long or contains any
    /// other character (including `.`, `/` and `\`).
    pub fn parse(name: &str) -> Result<Self> {
        let valid_char = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
        if name.is_empty() || name.len() > MAX_NAME_LEN || !name.chars().all(valid_char) {
            return Err(Error::InvalidVaultName(name.to_owned()));
        }
        Ok(Self(name.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// File name of this vault, e.g. `work.lockery`.
    #[must_use]
    pub fn file_name(&self) -> String {
        format!("{}.{VAULT_EXTENSION}", self.0)
    }

    /// Full path of this vault inside `dir`.
    #[must_use]
    pub fn path_in(&self, dir: &Path) -> PathBuf {
        dir.join(self.file_name())
    }
}

impl fmt::Display for VaultName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The data directory: `$LOCKERY_DATA_DIR` if set, otherwise the platform
/// default. Does not create it.
///
/// # Errors
/// [`Error::NoHomeDir`] if no home directory can be determined.
pub fn data_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(DATA_DIR_ENV) {
        return Ok(PathBuf::from(dir));
    }
    let base = directories::BaseDirs::new().ok_or(Error::NoHomeDir)?;
    Ok(base.data_dir().join("lockery"))
}

/// Create `dir` (and its parents) if it doesn't exist yet. On unix the
/// directory itself gets mode `0700`, so other users can't even see vault
/// names. An existing directory's permissions are left alone.
///
/// # Errors
/// Any I/O error from creating the directory.
pub fn ensure_dir(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(dir) {
        // Someone else created it in the meantime: fine.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        other => Ok(other?),
    }
}

/// The vaults in `dir`, sorted by name. Backups, lock files, temp files and
/// files with invalid names are ignored. A missing directory means no vaults.
///
/// # Errors
/// Any I/O error other than the directory not existing.
pub fn list_vaults(dir: &Path) -> Result<Vec<VaultName>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    let mut names = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some(VAULT_EXTENSION) {
            continue;
        }
        if let Some(name) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| VaultName::parse(s).ok())
        {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        for name in [
            "default",
            "work",
            "my-vault_2",
            "A",
            &"x".repeat(MAX_NAME_LEN),
        ] {
            assert_eq!(VaultName::parse(name).unwrap().as_str(), name);
        }
    }

    #[test]
    fn invalid_names_are_rejected() {
        let too_long = "x".repeat(MAX_NAME_LEN + 1);
        for name in [
            "",
            "../x",
            "a/b",
            "a\\b",
            ".",
            "..",
            "a.b",
            "with space",
            "ünï",
            &too_long,
        ] {
            assert!(
                matches!(VaultName::parse(name), Err(Error::InvalidVaultName(_))),
                "{name:?} should be rejected"
            );
        }
    }

    #[test]
    fn name_maps_to_file_in_dir() {
        let name = VaultName::parse("work").unwrap();
        assert_eq!(name.path_in(Path::new("/d")), Path::new("/d/work.lockery"));
    }

    #[test]
    fn list_ignores_non_vault_files() {
        let dir = tempfile::tempdir().unwrap();
        for file in [
            "work.lockery",
            "default.lockery",
            "default.lockery.bak",
            "default.lockery.lock",
            ".default.lockery.abc.tmp",
            "bad name.lockery",
            "notes.txt",
        ] {
            fs::write(dir.path().join(file), b"").unwrap();
        }
        fs::create_dir(dir.path().join("dir.lockery")).unwrap();

        let names: Vec<_> = list_vaults(dir.path()).unwrap();
        let names: Vec<_> = names.iter().map(VaultName::as_str).collect();
        assert_eq!(names, ["default", "work"]);
    }

    #[test]
    fn missing_dir_lists_nothing_and_ensure_dir_creates_it() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("a/b/lockery");
        assert_eq!(list_vaults(&dir).unwrap(), Vec::<VaultName>::new());

        ensure_dir(&dir).unwrap();
        assert!(dir.is_dir());
        ensure_dir(&dir).unwrap(); // idempotent

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }
}
