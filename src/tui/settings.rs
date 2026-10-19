//! The vault settings screen: cipher, Argon2 parameters and master
//! password, all applied together by re-encrypting the vault.
//!
//! Every change needs the current master password, so someone who finds
//! Lockery unlocked can't take the vault over.

use zeroize::Zeroizing;

use super::form::{Form, Row, RowId};
use crate::crypto::{CipherId, KdfParams};
use crate::generator::Strength;
use crate::vault::Vault;

/// Cipher options, in [`CipherId::ALL`] order.
const CIPHERS: &[&str] = &["XChaCha20-Poly1305", "AES-256-GCM"];

const MIB: u32 = 1024;

pub struct SettingsState {
    pub form: Form,
    pub error: Option<String>,
    /// The new password was reported as weak and Enter/Ctrl-s pressed
    /// again; any further edit resets this.
    weak_ok: bool,
}

/// What applying the settings will do.
pub struct Change {
    pub current_password: Zeroizing<String>,
    pub new_password: Option<Zeroizing<String>>,
    pub kdf: KdfParams,
    pub cipher: CipherId,
}

// Never print the passwords, even in test failure messages.
impl std::fmt::Debug for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Change")
            .field(
                "new_password",
                &self.new_password.as_ref().map(|_| "<redacted>"),
            )
            .field("kdf", &self.kdf)
            .field("cipher", &self.cipher)
            .finish_non_exhaustive()
    }
}

fn mib(kib: u32) -> u16 {
    u16::try_from(kib / MIB).unwrap_or(u16::MAX)
}

fn small(n: u32) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

impl SettingsState {
    /// The form, filled in with `vault`'s current settings.
    #[must_use]
    pub fn new(vault: &Vault) -> Self {
        let kdf = vault.kdf();
        let cipher = CipherId::ALL
            .iter()
            .position(|&c| c == vault.cipher())
            .unwrap_or(0);
        let rows = vec![
            Row::choice(RowId::Cipher, "Cipher", CIPHERS, cipher),
            Row::number(
                RowId::MemoryMib,
                "Memory (MiB)",
                mib(kdf.m_cost_kib()),
                mib(KdfParams::MIN_M_COST_KIB),
                mib(KdfParams::MAX_M_COST_KIB),
            ),
            Row::number(
                RowId::Iterations,
                "Passes",
                small(kdf.t_cost()),
                small(KdfParams::MIN_T_COST),
                small(KdfParams::MAX_T_COST),
            ),
            Row::number(
                RowId::Parallelism,
                "Lanes",
                small(kdf.p_cost()),
                small(KdfParams::MIN_P_COST),
                small(KdfParams::MAX_P_COST),
            ),
            Row::button(
                RowId::Calibrate,
                "Tune Argon2 for this machine (~1 s to unlock)",
            ),
            Row::secret(RowId::NewPassword, "New password", "")
                .with_placeholder("leave empty to keep the current one"),
            Row::secret(RowId::RepeatPassword, "Repeat new", ""),
            Row::secret(RowId::MasterPassword, "Current password", "")
                .with_placeholder("required to apply any change"),
        ];
        Self {
            form: Form::new(rows),
            error: None,
            weak_ok: false,
        }
    }

    /// Fill in the Argon2 fields (after calibration).
    pub fn set_kdf(&mut self, kdf: KdfParams) {
        self.form
            .set_number(RowId::MemoryMib, mib(kdf.m_cost_kib()));
        self.form.set_number(RowId::Iterations, small(kdf.t_cost()));
        self.form
            .set_number(RowId::Parallelism, small(kdf.p_cost()));
    }

    /// Something was typed or toggled: clear stale messages.
    pub fn on_change(&mut self) {
        self.error = None;
        self.weak_ok = false;
    }

    /// The Argon2 parameters currently in the form.
    ///
    /// # Errors
    /// A message if they're out of range.
    pub fn kdf(&self) -> Result<KdfParams, String> {
        KdfParams::new(
            u32::from(self.form.number(RowId::MemoryMib)) * MIB,
            u32::from(self.form.number(RowId::Iterations)),
            u32::from(self.form.number(RowId::Parallelism)),
        )
        .map_err(|e| e.to_string())
    }

    /// Check the form and work out what to change.
    ///
    /// # Errors
    /// A message to show if the form isn't ready: nothing changed, no
    /// current password, passwords that don't match, a weak new password
    /// (only the first time), or out-of-range Argon2 settings.
    pub fn validate(&mut self, vault: &Vault) -> Result<Change, String> {
        let change = self.change()?;
        let same_settings = change.kdf == vault.kdf() && change.cipher == vault.cipher();
        if same_settings && change.new_password.is_none() {
            return Err("Nothing to change.".into());
        }
        if change.current_password.is_empty() {
            self.form.focus_row(RowId::MasterPassword);
            return Err("Enter your current master password to apply the changes.".into());
        }
        if *self.form.text(RowId::RepeatPassword) != *self.form.text(RowId::NewPassword) {
            return Err("The new passwords don't match.".into());
        }
        if let Some(new) = &change.new_password
            && Strength::of(new, &[]).score < 3
            && !self.weak_ok
        {
            self.weak_ok = true;
            return Err(
                "The new password is easy to guess. Press Ctrl-s again to use it anyway.".into(),
            );
        }
        Ok(change)
    }

    /// The change described by the form, without the checks in
    /// [`validate`](Self::validate) (used again when it's applied).
    ///
    /// # Errors
    /// A message if the Argon2 settings are out of range.
    pub fn change(&self) -> Result<Change, String> {
        let new = self.form.text(RowId::NewPassword);
        Ok(Change {
            current_password: self.form.text(RowId::MasterPassword),
            new_password: (!new.is_empty()).then_some(new),
            kdf: self.kdf()?,
            cipher: CipherId::ALL[self.form.choice(RowId::Cipher)],
        })
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent};

    use super::*;
    use crate::crypto::test_params;

    fn vault(dir: &std::path::Path) -> Vault {
        Vault::create(
            dir.join("v.lockery"),
            b"pw",
            test_params(),
            CipherId::default(),
        )
        .unwrap()
    }

    fn type_into(state: &mut SettingsState, id: RowId, text: &str) {
        state.form.focus_row(id);
        for c in text.chars() {
            state.form.input(KeyEvent::from(KeyCode::Char(c)));
        }
        state.on_change();
    }

    #[test]
    fn starts_with_the_vaults_current_settings() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        let s = SettingsState::new(&v);
        assert_eq!(s.kdf().unwrap(), test_params());
        let change = s.change().unwrap();
        assert_eq!(change.cipher, CipherId::default());
        assert!(change.new_password.is_none());
    }

    #[test]
    fn validation() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        let mut s = SettingsState::new(&v);
        assert_eq!(s.validate(&v).err().as_deref(), Some("Nothing to change."));

        s.form.focus_row(RowId::Cipher);
        s.form.input(KeyEvent::from(KeyCode::Right)); // → AES-256-GCM
        assert!(
            s.validate(&v)
                .unwrap_err()
                .contains("current master password")
        );

        type_into(&mut s, RowId::MasterPassword, "pw");
        let change = s.validate(&v).unwrap();
        assert_eq!(change.cipher, CipherId::Aes256Gcm);

        type_into(&mut s, RowId::NewPassword, "abc");
        assert!(s.validate(&v).unwrap_err().contains("don't match"));
        type_into(&mut s, RowId::RepeatPassword, "abc");
        assert!(s.validate(&v).unwrap_err().contains("easy to guess"));
        assert_eq!(
            s.validate(&v)
                .unwrap()
                .new_password
                .as_deref()
                .map(String::as_str),
            Some("abc")
        );
    }

    #[test]
    fn set_kdf_fills_in_the_numbers() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        let mut s = SettingsState::new(&v);
        let kdf = KdfParams::new(256 * MIB, 7, 4).unwrap();
        s.set_kdf(kdf);
        assert_eq!(s.kdf().unwrap(), kdf);
    }
}
