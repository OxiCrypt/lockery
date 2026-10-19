//! Crash-safe reading and writing of a single vault file.
//!
//! This layer only moves opaque bytes around; it never sees plaintext. The
//! invariant it maintains is:
//!
//! > At every instant, the vault path holds either the complete previous
//! > version or the complete new version, never a partial write.
//!
//! A save goes through these steps (see [`SaveStep`]):
//!
//! 1. Write the new bytes to a temp file in the same directory and fsync it.
//! 2. Read the temp file back and let the caller verify it decrypts.
//! 3. Copy the current vault to `<vault>.bak` (via its own temp file, so the
//!    backup is also never half-written).
//! 4. Atomically rename the temp file over the vault.
//! 5. Fsync the directory so the rename itself survives a power cut.
//!
//! A crash before step 4 leaves the old vault in place (plus a stray temp
//! file that is cleaned up on the next open). A crash after it leaves the new
//! vault in place.
//!
//! Concurrent writers are prevented with an exclusive OS lock on
//! `<vault>.lock`, held for as long as the [`VaultFile`] lives.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

use crate::error::{Error, Result};

/// Suffix of the lock file next to the vault.
const LOCK_SUFFIX: &str = ".lock";
/// Suffix of the previous-version backup next to the vault.
const BACKUP_SUFFIX: &str = ".bak";
/// Suffix of temp files written during a save.
const TEMP_SUFFIX: &str = ".tmp";

/// The steps of [`VaultFile::save`]. Exposed so tests can inject a "crash"
/// after any of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveStep {
    /// The new contents are written to the temp file and fsynced.
    TempWritten,
    /// The temp file was read back and verified.
    Verified,
    /// The previous vault was copied to the `.bak` file.
    BackupWritten,
    /// The temp file was renamed over the vault.
    Renamed,
    /// The directory was fsynced.
    DirSynced,
}

impl SaveStep {
    pub const ALL: [Self; 5] = [
        Self::TempWritten,
        Self::Verified,
        Self::BackupWritten,
        Self::Renamed,
        Self::DirSynced,
    ];
}

/// An open, exclusively locked vault path. The vault file itself may not
/// exist yet (for a brand-new vault).
#[derive(Debug)]
pub struct VaultFile {
    path: PathBuf,
    /// Held only for its OS lock, released when dropped.
    _lock: File,
}

impl VaultFile {
    /// Lock `path` for exclusive use and clean up temp files left behind by
    /// an earlier crash.
    ///
    /// # Errors
    /// [`Error::VaultLocked`] if another instance has it open, or an I/O
    /// error if the lock file can't be created.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let lock_path = with_suffix(&path, LOCK_SUFFIX);
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(Error::VaultLocked(path)),
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }

        let file = Self { path, _lock: lock };
        file.remove_stale_temp_files()?;
        Ok(file)
    }

    /// Path of the vault file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Path of the previous-version backup.
    #[must_use]
    pub fn backup_path(&self) -> PathBuf {
        with_suffix(&self.path, BACKUP_SUFFIX)
    }

    /// Whether the vault file exists yet.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Read the whole (encrypted) vault file.
    ///
    /// # Errors
    /// Any I/O error, including `NotFound` for a vault not yet saved.
    pub fn read(&self) -> Result<Vec<u8>> {
        Ok(fs::read(&self.path)?)
    }

    /// Read the previous-version backup, for recovery when the main file is
    /// unreadable.
    ///
    /// # Errors
    /// Any I/O error, including `NotFound` if there is no backup.
    pub fn read_backup(&self) -> Result<Vec<u8>> {
        Ok(fs::read(self.backup_path())?)
    }

    /// Atomically replace the vault with `bytes`.
    ///
    /// `verify` is called with the bytes *as read back from disk* before
    /// anything is replaced; the caller should decrypt them. If it fails,
    /// the save is aborted and the old vault is untouched.
    ///
    /// # Errors
    /// [`Error::VerifyFailed`] if verification fails, or any I/O error. In
    /// both cases the previous vault remains intact.
    pub fn save(&self, bytes: &[u8], verify: impl FnOnce(&[u8]) -> Result<()>) -> Result<()> {
        self.save_with_hook(bytes, verify, |_| Ok(()))
    }

    /// [`save`](Self::save), calling `hook` after each [`SaveStep`]. If the
    /// hook returns an error, the save stops right there, which lets tests
    /// simulate a crash at every point.
    pub(crate) fn save_with_hook(
        &self,
        bytes: &[u8],
        verify: impl FnOnce(&[u8]) -> Result<()>,
        mut hook: impl FnMut(SaveStep) -> io::Result<()>,
    ) -> Result<()> {
        let dir = self.dir();

        // 1. Write and fsync the temp file. `tempfile` creates it with mode
        //    0600 on unix, so the ciphertext isn't world-readable either.
        let mut tmp = self.temp_file_in(&dir)?;
        tmp.write_all(bytes)?;
        tmp.as_file().sync_all()?;
        hook(SaveStep::TempWritten)?;

        // 2. Read back what actually landed on disk and verify it.
        let written = fs::read(tmp.path())?;
        verify(&written).map_err(|e| Error::VerifyFailed(Box::new(e)))?;
        hook(SaveStep::Verified)?;

        // 3. Back up the current version, if there is one.
        if self.exists() {
            let mut bak = self.temp_file_in(&dir)?;
            io::copy(&mut File::open(&self.path)?, bak.as_file_mut())?;
            bak.as_file().sync_all()?;
            bak.persist(self.backup_path()).map_err(|e| e.error)?;
        }
        hook(SaveStep::BackupWritten)?;

        // 4. Atomic replace. On Windows `persist` uses MoveFileEx with
        //    MOVEFILE_REPLACE_EXISTING, so this works there too.
        tmp.persist(&self.path).map_err(|e| e.error)?;
        hook(SaveStep::Renamed)?;

        // 5. Make the rename durable.
        sync_dir(&dir)?;
        hook(SaveStep::DirSynced)?;
        Ok(())
    }

    /// The directory containing the vault (the current directory for a bare
    /// file name).
    fn dir(&self) -> PathBuf {
        match self.path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        }
    }

    /// Prefix shared by all temp files belonging to this vault:
    /// `.<file name>.`, so they're hidden and easy to find again.
    fn temp_prefix(&self) -> OsString {
        let mut prefix = OsString::from(".");
        prefix.push(self.path.file_name().unwrap_or_default());
        prefix.push(".");
        prefix
    }

    fn temp_file_in(&self, dir: &Path) -> io::Result<NamedTempFile> {
        tempfile::Builder::new()
            .prefix(&self.temp_prefix())
            .suffix(TEMP_SUFFIX)
            .tempfile_in(dir)
    }

    /// Delete temp files from a save that was interrupted by a crash. They
    /// only ever contain ciphertext, but there's no reason to keep them.
    fn remove_stale_temp_files(&self) -> Result<()> {
        let prefix = self.temp_prefix();
        let prefix = prefix.to_string_lossy();
        let entries = match fs::read_dir(self.dir()) {
            Ok(entries) => entries,
            // A missing directory is the caller's problem when they save.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(&*prefix) && name.ends_with(TEMP_SUFFIX) {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }
}

/// `foo/bar.lockery` + `.lock` → `foo/bar.lockery.lock`.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Fsync a directory so that renames inside it are durable. Windows has no
/// equivalent (and doesn't need one for `MoveFileEx`), so it's a no-op there.
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
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

    // Must match the `verify` callback signature, hence the always-Ok Result.
    #[allow(clippy::unnecessary_wraps)]
    fn accept(_: &[u8]) -> Result<()> {
        Ok(())
    }

    fn temp_files(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(TEMP_SUFFIX))
            .collect()
    }

    #[test]
    fn save_creates_then_replaces_with_backup() {
        let dir = tempfile::tempdir().unwrap();
        let vault = VaultFile::open(dir.path().join("v.lockery")).unwrap();
        assert!(!vault.exists());

        vault.save(b"one", accept).unwrap();
        assert_eq!(vault.read().unwrap(), b"one");
        assert!(
            !vault.backup_path().exists(),
            "nothing to back up on first save"
        );

        vault.save(b"two", accept).unwrap();
        assert_eq!(vault.read().unwrap(), b"two");
        assert_eq!(vault.read_backup().unwrap(), b"one");
        assert_eq!(temp_files(dir.path()), Vec::<String>::new());
    }

    #[test]
    fn verify_sees_written_bytes_and_failure_keeps_old_vault() {
        let dir = tempfile::tempdir().unwrap();
        let vault = VaultFile::open(dir.path().join("v.lockery")).unwrap();
        vault.save(b"good", accept).unwrap();

        let result = vault.save(b"bad", |written| {
            assert_eq!(written, b"bad");
            Err(Error::Decryption)
        });
        assert!(matches!(result, Err(Error::VerifyFailed(_))));
        assert_eq!(vault.read().unwrap(), b"good");
        assert_eq!(
            temp_files(dir.path()),
            Vec::<String>::new(),
            "aborted temp file is removed"
        );
    }

    #[test]
    fn second_open_is_refused_while_locked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.lockery");
        let first = VaultFile::open(&path).unwrap();
        assert!(matches!(VaultFile::open(&path), Err(Error::VaultLocked(_))));
        drop(first);
        VaultFile::open(&path).expect("lock is released on drop");
    }

    #[test]
    fn stale_temp_files_are_cleaned_up_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join(".v.lockery.abc123.tmp");
        let unrelated = dir.path().join(".other.lockery.abc123.tmp");
        fs::write(&stale, b"x").unwrap();
        fs::write(&unrelated, b"x").unwrap();

        let _vault = VaultFile::open(dir.path().join("v.lockery")).unwrap();
        assert!(!stale.exists());
        assert!(
            unrelated.exists(),
            "other vaults' temp files are left alone"
        );
    }

    /// Simulate a crash after every step of a save. Whatever happens, the
    /// vault path must contain either the complete old or the complete new
    /// contents, and the vault must still be usable afterwards.
    #[test]
    fn crash_at_any_step_leaves_a_complete_vault() {
        for crash_after in SaveStep::ALL {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("v.lockery");
            {
                let vault = VaultFile::open(&path).unwrap();
                vault.save(b"old contents", accept).unwrap();

                let result = vault.save_with_hook(b"new contents", accept, |step| {
                    if step == crash_after {
                        Err(io::Error::other("simulated crash"))
                    } else {
                        Ok(())
                    }
                });
                assert!(result.is_err());

                let on_disk = vault.read().unwrap();
                let renamed = matches!(crash_after, SaveStep::Renamed | SaveStep::DirSynced);
                let expected: &[u8] = if renamed {
                    b"new contents"
                } else {
                    b"old contents"
                };
                assert_eq!(on_disk, expected, "crash after {crash_after:?}");
            }

            // "Restart": reopening cleans up and a normal save works.
            let vault = VaultFile::open(&path).unwrap();
            assert_eq!(temp_files(dir.path()), Vec::<String>::new());
            vault.save(b"after restart", accept).unwrap();
            assert_eq!(vault.read().unwrap(), b"after restart");
        }
    }
}
