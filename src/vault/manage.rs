//! Renaming and deleting whole vaults (their files on disk).
//!
//! Both operations take the vault's lock first, so they refuse to touch a
//! vault that is open in another Lockery.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::Vault;
use super::storage::VaultFile;
use crate::error::{Error, Result};
use crate::paths::VaultName;

/// Rename vault `from` to `to` inside `dir`. The backup moves along with
/// it. The vault stays encrypted exactly as it was (no password needed).
///
/// # Errors
/// [`Error::VaultNotFound`], [`Error::VaultExists`] if `to` is taken,
/// [`Error::VaultLocked`] if either name is open elsewhere, or I/O errors.
pub fn rename_vault(dir: &Path, from: &VaultName, to: &VaultName) -> Result<()> {
    let from_path = from.path_in(dir);
    let to_path = to.path_in(dir);
    if !from_path.is_file() {
        return Err(Error::VaultNotFound(from_path));
    }
    if to_path.exists() {
        return Err(Error::VaultExists(to_path));
    }

    // Hold both locks, so nobody opens either name halfway through.
    let from_file = VaultFile::open(&from_path)?;
    let to_file = VaultFile::open(&to_path)?;

    fs::rename(&from_path, &to_path)?;
    let from_bak = from_file.backup_path();
    if from_bak.is_file() {
        fs::rename(&from_bak, to_file.backup_path())?;
    }
    sync_dir(dir)?;

    drop(from_file);
    drop(to_file);
    // The old name's lock file is now an empty leftover.
    remove_if_exists(&lock_path(&from_path))?;
    Ok(())
}

/// Permanently delete vault `name` in `dir`: the vault, its backup, any
/// damaged copies kept by recovery, and its lock file.
///
/// The master password is required, and checked by fully unlocking the
/// vault, so a vault can't be deleted by someone who merely has the app open
/// on the picker.
///
/// # Errors
/// [`Error::VaultNotFound`], [`Error::Decryption`] for a wrong password,
/// [`Error::VaultLocked`] if it's open elsewhere, or I/O errors.
pub fn delete_vault(dir: &Path, name: &VaultName, password: &[u8]) -> Result<()> {
    let path = name.path_in(dir);
    let vault = Vault::unlock(&path, password)?;

    for file in vault_files(dir, name)? {
        remove_if_exists(&file)?;
    }
    sync_dir(dir)?;

    // Release the lock before deleting the lock file (Windows can't delete a
    // file that is still open).
    drop(vault);
    remove_if_exists(&lock_path(&path))?;
    Ok(())
}

/// The vault file, its backup and any `.corrupt-*` copies.
fn vault_files(dir: &Path, name: &VaultName) -> Result<Vec<PathBuf>> {
    let file_name = name.file_name();
    let corrupt_prefix = format!("{file_name}.corrupt-");
    let mut files = vec![dir.join(&file_name), dir.join(format!("{file_name}.bak"))];
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(&corrupt_prefix)
        {
            files.push(entry.path());
        }
    }
    Ok(files)
}

fn lock_path(vault: &Path) -> PathBuf {
    let mut s = vault.as_os_str().to_owned();
    s.push(".lock");
    PathBuf::from(s)
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CipherId, test_params};
    use crate::vault::{Entry, EntryKind};

    const PW: &[u8] = b"pw";

    fn name(s: &str) -> VaultName {
        VaultName::parse(s).unwrap()
    }

    /// A vault with one entry, saved twice so it has a backup.
    fn make_vault(dir: &Path, n: &str) {
        let mut v =
            Vault::create(name(n).path_in(dir), PW, test_params(), CipherId::default()).unwrap();
        v.add(Entry::new(EntryKind::Login, "kept")).unwrap();
    }

    fn files(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn rename_moves_vault_and_backup() {
        let dir = tempfile::tempdir().unwrap();
        make_vault(dir.path(), "old");
        rename_vault(dir.path(), &name("old"), &name("new")).unwrap();

        assert_eq!(
            files(dir.path()),
            ["new.lockery", "new.lockery.bak", "new.lockery.lock"]
        );
        let v = Vault::unlock(name("new").path_in(dir.path()), PW).unwrap();
        assert_eq!(v.entries()[0].title, "kept");
    }

    #[test]
    fn rename_refuses_taken_missing_or_open_vaults() {
        let dir = tempfile::tempdir().unwrap();
        make_vault(dir.path(), "a");
        make_vault(dir.path(), "b");
        let d = dir.path();

        assert!(matches!(
            rename_vault(d, &name("a"), &name("b")),
            Err(Error::VaultExists(_))
        ));
        assert!(matches!(
            rename_vault(d, &name("zzz"), &name("c")),
            Err(Error::VaultNotFound(_))
        ));

        let open = Vault::unlock(name("a").path_in(d), PW).unwrap();
        assert!(matches!(
            rename_vault(d, &name("a"), &name("c")),
            Err(Error::VaultLocked(_))
        ));
        drop(open);
        assert!(!name("c").path_in(d).exists());
    }

    #[test]
    fn delete_needs_the_right_password_and_removes_everything() {
        let dir = tempfile::tempdir().unwrap();
        make_vault(dir.path(), "gone");
        make_vault(dir.path(), "stays");
        fs::write(dir.path().join("gone.lockery.corrupt-123"), b"x").unwrap();

        let result = delete_vault(dir.path(), &name("gone"), b"wrong");
        assert!(matches!(result, Err(Error::Decryption)));
        assert!(name("gone").path_in(dir.path()).exists());

        delete_vault(dir.path(), &name("gone"), PW).unwrap();
        assert_eq!(
            files(dir.path()),
            ["stays.lockery", "stays.lockery.bak", "stays.lockery.lock"]
        );
    }

    #[test]
    fn delete_refuses_an_open_vault() {
        let dir = tempfile::tempdir().unwrap();
        make_vault(dir.path(), "busy");
        let open = Vault::unlock(name("busy").path_in(dir.path()), PW).unwrap();
        let result = delete_vault(dir.path(), &name("busy"), PW);
        assert!(matches!(result, Err(Error::VaultLocked(_))));
        drop(open);
        assert!(name("busy").path_in(dir.path()).exists());
    }
}
