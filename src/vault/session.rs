//! An unlocked vault: the decrypted data plus everything needed to save it.
//!
//! Every change is written to disk immediately, before it becomes visible in
//! memory. Each mutating method builds the new state on a copy, saves that
//! copy (atomically, see `storage`), and only then replaces the in-memory
//! state. If the save fails, the vault is exactly as it was before the call,
//! both on disk and in memory.

use std::path::{Path, PathBuf};

use jiff::Timestamp;
use uuid::Uuid;

use super::format;
use super::migrate;
use super::model::{Entry, VaultData};
use super::storage::VaultFile;
use crate::crypto::{self, CipherId, KdfParams, VaultKey};
use crate::error::{Error, Result};

/// An open, unlocked vault. Holds the vault's file lock for as long as it
/// lives; dropping it wipes the key and all decrypted entries.
#[derive(Debug)]
pub struct Vault {
    file: VaultFile,
    key: VaultKey,
    cipher: CipherId,
    data: VaultData,
    /// Format version of the file as it was when opened.
    opened_format_version: u16,
    /// Set if the main file was damaged and the vault was restored from its
    /// backup; holds where the damaged file was moved to.
    recovered_from_backup: Option<PathBuf>,
}

impl Vault {
    /// Create a new, empty vault at `path` and save it.
    ///
    /// This runs Argon2 once, so it takes as long as `kdf` is tuned for.
    ///
    /// # Errors
    /// [`Error::VaultExists`] if there's already a vault at `path`,
    /// [`Error::VaultLocked`], or any key-derivation or I/O error.
    pub fn create(
        path: impl Into<PathBuf>,
        password: &[u8],
        kdf: KdfParams,
        cipher: CipherId,
    ) -> Result<Self> {
        let file = VaultFile::open(path)?;
        if file.exists() {
            return Err(Error::VaultExists(file.path().to_path_buf()));
        }
        let vault = Self {
            key: VaultKey::derive_new(password, kdf)?,
            file,
            cipher,
            data: VaultData::new(),
            opened_format_version: format::CURRENT_FORMAT_VERSION,
            recovered_from_backup: None,
        };
        vault.write(&vault.data)?;
        Ok(vault)
    }

    /// Unlock the existing vault at `path` with `password`.
    ///
    /// If the main file is structurally damaged (not merely "wrong
    /// password"), the `.bak` copy is tried. If that opens, the damaged file
    /// is moved aside to `<vault>.corrupt-<timestamp>`, the recovered data is
    /// saved as the vault, and [`Vault::recovered_from_backup`] reports it.
    ///
    /// # Errors
    /// [`Error::VaultNotFound`], [`Error::VaultLocked`],
    /// [`Error::Decryption`] for a wrong password, or any format/schema
    /// error if neither the vault nor its backup can be opened.
    pub fn unlock(path: impl Into<PathBuf>, password: &[u8]) -> Result<Self> {
        let path = path.into();
        // Check first so a typo'd path doesn't leave a stray lock file.
        if !path.is_file() {
            return Err(Error::VaultNotFound(path));
        }
        let file = VaultFile::open(path)?;

        match Self::decrypt(&file.read()?, password) {
            Ok((opened, data)) => Ok(Self::from_opened(file, opened, data, None)),
            Err(e) if is_damage(&e) && file.backup_path().is_file() => {
                // Only replace the main file if the backup really opens.
                let Ok((opened, data)) = Self::decrypt(&file.read_backup()?, password) else {
                    return Err(e);
                };
                Self::restore_from_backup(file, opened, data, |v| v.write(&v.data))
            }
            Err(e) => Err(e),
        }
    }

    /// Move the damaged main file aside and `save` the data recovered from
    /// the backup in its place. (`save` is a parameter so tests can make it
    /// fail.)
    ///
    /// The damaged file has to go first: a save copies the current main file
    /// to `.bak`, which would overwrite the good backup with the damaged one.
    /// But if the save then fails, the vault path is left empty, and the
    /// vault would look deleted ("no vault found", gone from the picker).
    /// So on failure the damaged file is put back: the next unlock fails the
    /// same way and retries recovery from the backup, which is untouched.
    fn restore_from_backup(
        file: VaultFile,
        opened: format::Opened,
        data: VaultData,
        save: impl FnOnce(&Self) -> Result<()>,
    ) -> Result<Self> {
        let aside = Self::move_aside(&file)?;
        let vault = Self::from_opened(file, opened, data, Some(aside.clone()));
        if let Err(e) = save(&vault) {
            // A save that failed after its rename (fsyncing the directory)
            // did put the recovered vault in place; keep that one.
            if !vault.path().exists() {
                // If even this fails, the original error is the one to
                // report; the damaged file is still next to the vault.
                let _ = std::fs::rename(&aside, vault.path());
            }
            return Err(e);
        }
        Ok(vault)
    }

    fn decrypt(bytes: &[u8], password: &[u8]) -> Result<(format::Opened, VaultData)> {
        let opened = format::open(password, bytes)?;
        let data = migrate::decode(&opened.plaintext)?;
        Ok((opened, data))
    }

    fn from_opened(
        file: VaultFile,
        opened: format::Opened,
        data: VaultData,
        recovered_from_backup: Option<PathBuf>,
    ) -> Self {
        Self {
            file,
            key: opened.key,
            cipher: opened.cipher,
            data,
            opened_format_version: opened.format_version,
            recovered_from_backup,
        }
    }

    /// Rename a damaged vault file out of the way (never delete it: the user
    /// may still want to try recovering it by hand).
    fn move_aside(file: &VaultFile) -> Result<PathBuf> {
        let mut aside = file.path().as_os_str().to_owned();
        aside.push(format!(".corrupt-{}", Timestamp::now().as_second()));
        let aside = PathBuf::from(aside);
        std::fs::rename(file.path(), &aside)?;
        Ok(aside)
    }

    // -- Accessors -----------------------------------------------------------

    #[must_use]
    pub fn path(&self) -> &Path {
        self.file.path()
    }

    #[must_use]
    pub fn cipher(&self) -> CipherId {
        self.cipher
    }

    #[must_use]
    pub fn kdf(&self) -> KdfParams {
        self.key.kdf()
    }

    /// The format version the file had when it was opened. Older versions
    /// are upgraded automatically by the next save.
    #[must_use]
    pub fn opened_format_version(&self) -> u16 {
        self.opened_format_version
    }

    /// `Some(path of the damaged file)` if this vault was restored from its
    /// backup when unlocking. The UI should tell the user.
    #[must_use]
    pub fn recovered_from_backup(&self) -> Option<&Path> {
        self.recovered_from_backup.as_deref()
    }

    #[must_use]
    pub fn data(&self) -> &VaultData {
        &self.data
    }

    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.data.entries
    }

    #[must_use]
    pub fn entry(&self, id: Uuid) -> Option<&Entry> {
        self.data.entries.iter().find(|e| e.id == id)
    }

    // -- Changes (each one is saved before it takes effect) ------------------

    /// Add `entry` and save. Returns its id.
    ///
    /// # Errors
    /// Any error from saving; the vault is then unchanged.
    pub fn add(&mut self, entry: Entry) -> Result<Uuid> {
        let id = entry.id;
        self.commit(|data| {
            data.entries.push(entry);
            Ok(())
        })?;
        Ok(id)
    }

    /// Change the entry `id` with `edit`, bump its `modified` time and save.
    ///
    /// # Errors
    /// [`Error::EntryNotFound`], or any error from saving; the vault is then
    /// unchanged.
    pub fn update(&mut self, id: Uuid, edit: impl FnOnce(&mut Entry)) -> Result<()> {
        self.commit(|data| {
            let entry = data
                .entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or(Error::EntryNotFound(id))?;
            edit(entry);
            entry.id = id; // the id is the one thing an edit may not change
            entry.modified = Timestamp::now();
            Ok(())
        })
    }

    /// Delete the entry `id` and save. Returns the removed entry.
    ///
    /// # Errors
    /// [`Error::EntryNotFound`], or any error from saving; the vault is then
    /// unchanged.
    pub fn delete(&mut self, id: Uuid) -> Result<Entry> {
        let removed = self.entry(id).cloned().ok_or(Error::EntryNotFound(id))?;
        self.commit(|data| {
            data.entries.retain(|e| e.id != id);
            Ok(())
        })?;
        Ok(removed)
    }

    /// Add several entries with a single save (e.g. an import). Returns how
    /// many were added.
    ///
    /// # Errors
    /// Any error from saving; the vault is then unchanged.
    pub fn add_many(&mut self, entries: Vec<Entry>) -> Result<usize> {
        let count = entries.len();
        self.commit(|data| {
            data.entries.extend(entries);
            Ok(())
        })?;
        Ok(count)
    }

    /// Check that `password` is this vault's master password, without
    /// changing anything. Runs Argon2, so it takes as long as unlocking. Used
    /// to confirm sensitive actions such as exporting or re-keying.
    ///
    /// # Errors
    /// [`Error::Decryption`] if it isn't, or a key-derivation error.
    pub fn verify_password(&self, password: &[u8]) -> Result<()> {
        let check = VaultKey::derive(password, *self.key.salt(), self.key.kdf())?;
        if crypto::keys_equal(check.key(), self.key.key()) {
            Ok(())
        } else {
            Err(Error::Decryption)
        }
    }

    // -- Settings: re-encrypting the whole vault ------------------------------

    /// Re-encrypt the vault with new settings: a new master password
    /// (`None` keeps the current one), new Argon2 parameters and/or a new
    /// cipher. A fresh salt is always generated.
    ///
    /// `current_password` must be the vault's master password; it is checked
    /// before anything is written, so an unattended unlocked vault can't be
    /// taken over.
    ///
    /// The vault is saved twice. The first save writes the new version and
    /// moves the previous one (encrypted the old way) to `.bak`; the second
    /// replaces that backup with the new version too. Otherwise, after a
    /// password change, the backup would still open with the old password,
    /// which is exactly what someone changing a leaked password must avoid.
    ///
    /// Runs Argon2 twice (to check the current password and derive the new
    /// key), so it takes about twice the unlock time.
    ///
    /// # Errors
    /// [`Error::Decryption`] if `current_password` is wrong (nothing is
    /// changed), any error from key derivation or saving (nothing is
    /// changed), or [`Error::BackupNotRefreshed`] if the vault was
    /// re-encrypted but the old backup couldn't be replaced.
    pub fn rekey(
        &mut self,
        current_password: &[u8],
        new_password: Option<&[u8]>,
        kdf: KdfParams,
        cipher: CipherId,
    ) -> Result<()> {
        self.verify_password(current_password)?;

        let new_key = VaultKey::derive_new(new_password.unwrap_or(current_password), kdf)?;
        self.write_with(&new_key, cipher, &self.data)?;
        // The file now uses the new key, so adopt it before anything else
        // can fail. The old key is wiped as it drops.
        self.key = new_key;
        self.cipher = cipher;

        self.write(&self.data)
            .map_err(|e| Error::BackupNotRefreshed(Box::new(e)))
    }

    /// Apply `change` to a copy of the data, save the copy, then adopt it.
    fn commit(&mut self, change: impl FnOnce(&mut VaultData) -> Result<()>) -> Result<()> {
        let mut next = self.data.clone();
        change(&mut next)?;
        next.modified = Timestamp::now();
        next.schema_version = migrate::CURRENT_SCHEMA_VERSION;
        self.write(&next)?;
        self.data = next; // the old copy is wiped as it drops
        Ok(())
    }

    /// Encrypt `data` and atomically replace the vault file with it. The
    /// written file is decrypted again and compared before it replaces the
    /// old one.
    fn write(&self, data: &VaultData) -> Result<()> {
        self.write_with(&self.key, self.cipher, data)
    }

    /// [`write`](Self::write) with an explicit key and cipher, for re-keying.
    fn write_with(&self, key: &VaultKey, cipher: CipherId, data: &VaultData) -> Result<()> {
        let plaintext = migrate::encode(data)?;
        let bytes = format::seal(key, cipher, &plaintext)?;
        self.file.save(&bytes, |written| {
            let reread = format::open_with_key(key, written)?;
            if *reread == *plaintext {
                Ok(())
            } else {
                Err(Error::Malformed(
                    "written vault does not match its contents",
                ))
            }
        })
    }
}

/// Whether an unlock error means the file itself is damaged, as opposed to a
/// wrong password or a vault from a newer Lockery (which must never be
/// "repaired" from an older backup).
///
/// Unknown KDF/cipher ids count as damage because new ids always come with a
/// new format version, so a version-1 file can't legitimately contain them.
fn is_damage(e: &Error) -> bool {
    matches!(
        e,
        Error::NotAVault
            | Error::Malformed(_)
            | Error::UnknownKdf(_)
            | Error::UnknownCipher(_)
            | Error::InvalidKdfParams(_)
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::crypto::test_params;
    use crate::vault::model::EntryKind;

    const PW: &[u8] = b"master password";

    fn new_vault(dir: &Path, cipher: CipherId) -> Vault {
        Vault::create(dir.join("v.lockery"), PW, test_params(), cipher).unwrap()
    }

    fn login(title: &str, password: &str) -> Entry {
        let mut e = Entry::new(EntryKind::Login, title);
        e.password = password.into();
        e
    }

    #[test]
    fn create_then_unlock_round_trip_for_both_ciphers() {
        for cipher in CipherId::ALL {
            let dir = tempfile::tempdir().unwrap();
            let path = {
                let mut v = new_vault(dir.path(), cipher);
                v.add(login("GitHub", "s3cret")).unwrap();
                v.path().to_path_buf()
            }; // dropped: lock released

            let v = Vault::unlock(&path, PW).unwrap();
            assert_eq!(v.cipher(), cipher);
            assert_eq!(v.kdf(), test_params());
            assert_eq!(v.entries().len(), 1);
            assert_eq!(v.entries()[0].password, "s3cret");
            assert!(v.recovered_from_backup().is_none());
        }
    }

    #[test]
    fn create_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        drop(new_vault(dir.path(), CipherId::default()));
        let again = Vault::create(
            dir.path().join("v.lockery"),
            PW,
            test_params(),
            CipherId::default(),
        );
        assert!(matches!(again, Err(Error::VaultExists(_))));
    }

    #[test]
    fn unlock_errors() {
        let dir = tempfile::tempdir().unwrap();
        let missing = Vault::unlock(dir.path().join("nope.lockery"), PW);
        assert!(matches!(missing, Err(Error::VaultNotFound(_))));
        assert!(!dir.path().join("nope.lockery.lock").exists());

        let v = new_vault(dir.path(), CipherId::default());
        let path = v.path().to_path_buf();
        assert!(matches!(
            Vault::unlock(&path, PW),
            Err(Error::VaultLocked(_))
        ));
        drop(v);
        assert!(matches!(
            Vault::unlock(&path, b"wrong"),
            Err(Error::Decryption)
        ));
    }

    #[test]
    fn crud_is_persisted_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(dir.path(), CipherId::default());
        let path = v.path().to_path_buf();

        let a = v.add(login("A", "1")).unwrap();
        let b = v.add(login("B", "2")).unwrap();
        let before = v.entry(a).unwrap().modified;
        v.update(a, |e| {
            e.notes = "multi\nline".into();
            e.id = Uuid::nil(); // must be ignored
        })
        .unwrap();
        assert!(v.entry(a).unwrap().modified >= before);
        let removed = v.delete(b).unwrap();
        assert_eq!(removed.title, "B");
        assert!(matches!(v.delete(b), Err(Error::EntryNotFound(_))));
        assert!(matches!(v.update(b, |_| {}), Err(Error::EntryNotFound(_))));
        drop(v);

        let v = Vault::unlock(&path, PW).unwrap();
        assert_eq!(v.entries().len(), 1);
        assert_eq!(v.entry(a).unwrap().notes, "multi\nline");
    }

    #[test]
    fn failed_save_leaves_memory_and_disk_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(dir.path(), CipherId::default());
        v.add(login("Keep", "1")).unwrap();
        let on_disk = fs::read(v.path()).unwrap();

        // Make the directory read-only so the temp file can't be created.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
            let result = v.add(login("Lost", "2"));
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

            // Root ignores directory permissions, so only assert if it failed.
            if result.is_err() {
                assert_eq!(v.entries().len(), 1);
                assert_eq!(fs::read(v.path()).unwrap(), on_disk);
            }
        }
    }

    #[test]
    fn damaged_vault_is_restored_from_backup() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(dir.path(), CipherId::default());
        v.add(login("First", "1")).unwrap(); // .bak now holds the empty vault
        v.add(login("Second", "2")).unwrap(); // .bak now holds [First]
        let path = v.path().to_path_buf();
        drop(v);

        // Truncate the main file: structural damage.
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..100]).unwrap();

        let v = Vault::unlock(&path, PW).unwrap();
        let aside = v
            .recovered_from_backup()
            .expect("should report recovery")
            .to_path_buf();
        assert_eq!(
            fs::read(&aside).unwrap(),
            &bytes[..100],
            "damaged file is kept"
        );
        let titles: Vec<_> = v.entries().iter().map(|e| e.title.as_str()).collect();
        assert_eq!(titles, ["First"]);
        drop(v);

        // The recovered data was saved as the main vault.
        assert!(
            Vault::unlock(&path, PW)
                .unwrap()
                .recovered_from_backup()
                .is_none()
        );
    }

    #[test]
    fn failed_recovery_save_puts_the_damaged_file_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(dir.path(), CipherId::default());
        v.add(login("First", "1")).unwrap(); // .bak now holds the empty vault
        let path = v.path().to_path_buf();
        drop(v);
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..100]).unwrap();

        // Recover, but make the save fail (e.g. the disk is full).
        let file = VaultFile::open(&path).unwrap();
        let (opened, data) = Vault::decrypt(&file.read_backup().unwrap(), PW).unwrap();
        let result = Vault::restore_from_backup(file, opened, data, |_| {
            Err(Error::Io(std::io::Error::other("disk full")))
        });
        assert!(result.is_err());

        // The vault hasn't vanished: the damaged file is back in place, and
        // the next unlock recovers from the untouched backup.
        assert_eq!(fs::read(&path).unwrap(), &bytes[..100]);
        let v = Vault::unlock(&path, PW).unwrap();
        assert!(v.recovered_from_backup().is_some());
    }

    #[test]
    fn rekey_changes_password_and_refreshes_the_backup() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(dir.path(), CipherId::XChaCha20Poly1305);
        v.add(login("A", "1")).unwrap();
        let path = v.path().to_path_buf();
        let new_kdf = KdfParams::new(KdfParams::MIN_M_COST_KIB * 2, 2, 1).unwrap();

        v.rekey(PW, Some(b"new password"), new_kdf, CipherId::Aes256Gcm)
            .unwrap();
        assert_eq!((v.cipher(), v.kdf()), (CipherId::Aes256Gcm, new_kdf));
        v.add(login("B", "2")).unwrap(); // later saves use the new key
        drop(v);

        assert!(matches!(Vault::unlock(&path, PW), Err(Error::Decryption)));
        let v = Vault::unlock(&path, b"new password").unwrap();
        assert_eq!(
            (v.cipher(), v.kdf(), v.entries().len()),
            (CipherId::Aes256Gcm, new_kdf, 2)
        );
        drop(v);

        // The backup no longer opens with the old password either.
        let bak = fs::read(path.with_extension("lockery.bak")).unwrap();
        assert!(matches!(format::open(PW, &bak), Err(Error::Decryption)));
        assert!(format::open(b"new password", &bak).is_ok());
    }

    #[test]
    fn add_many_and_verify_password() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(dir.path(), CipherId::default());
        assert_eq!(
            v.add_many(vec![login("A", "1"), login("B", "2")]).unwrap(),
            2
        );
        assert!(v.verify_password(PW).is_ok());
        assert!(matches!(v.verify_password(b"nope"), Err(Error::Decryption)));
        let path = v.path().to_path_buf();
        drop(v);
        assert_eq!(Vault::unlock(&path, PW).unwrap().entries().len(), 2);
    }

    #[test]
    fn rekey_keeps_the_password_when_none_is_given() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(dir.path(), CipherId::XChaCha20Poly1305);
        let path = v.path().to_path_buf();
        v.rekey(PW, None, test_params(), CipherId::Aes256Gcm)
            .unwrap();
        drop(v);
        assert_eq!(
            Vault::unlock(&path, PW).unwrap().cipher(),
            CipherId::Aes256Gcm
        );
    }

    #[test]
    fn rekey_with_wrong_current_password_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(dir.path(), CipherId::XChaCha20Poly1305);
        let before = fs::read(v.path()).unwrap();
        let result = v.rekey(b"wrong", Some(b"new"), test_params(), CipherId::Aes256Gcm);
        assert!(matches!(result, Err(Error::Decryption)));
        assert_eq!(v.cipher(), CipherId::XChaCha20Poly1305);
        assert_eq!(fs::read(v.path()).unwrap(), before);
    }

    #[test]
    fn wrong_password_never_falls_back_to_backup() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(dir.path(), CipherId::default());
        v.add(login("A", "1")).unwrap();
        let path = v.path().to_path_buf();
        drop(v);
        let before = fs::read(&path).unwrap();

        assert!(matches!(
            Vault::unlock(&path, b"wrong"),
            Err(Error::Decryption)
        ));
        assert_eq!(fs::read(&path).unwrap(), before, "vault untouched");
    }
}
