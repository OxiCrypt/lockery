//! Cryptographic primitives: Argon2id key derivation and the two supported
//! AEAD ciphers.
//!
//! This module knows nothing about the vault file layout; `vault::format`
//! decides what gets authenticated and encrypted, and calls into here.

pub mod calibrate;

use std::fmt;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{self, Aead, AeadInOut, KeyInit, Payload};
use argon2::{Algorithm, Argon2, Version};
use chacha20poly1305::XChaCha20Poly1305;
use rand::TryRng;
use rand::rngs::SysRng;

use crate::error::{Error, Result};
use crate::hardening::SecretBuf;

/// Length of every symmetric key we use (256-bit).
pub const KEY_LEN: usize = 32;
/// Length of the Argon2 salt stored in the vault header.
pub const SALT_LEN: usize = 32;
/// Both ciphers append a 128-bit authentication tag.
pub const TAG_LEN: usize = 16;

/// A derived symmetric key ([`KEY_LEN`] bytes) on locked pages of its own,
/// wiped when dropped. See [`SecretBuf`].
pub type Key = SecretBuf;

// ---------------------------------------------------------------------------
// Ciphers
// ---------------------------------------------------------------------------

/// The AEAD used to encrypt a vault. The numeric ids are written to disk and
/// must never be reused or renumbered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CipherId {
    /// XChaCha20-Poly1305. The 192-bit nonce is safe to pick at random.
    #[default]
    XChaCha20Poly1305,
    /// AES-256-GCM. Fast with AES-NI; its 96-bit random nonce is fine for the
    /// handful of saves a vault sees under one key.
    Aes256Gcm,
}

impl CipherId {
    /// Every supported cipher, handy for tests and settings menus.
    pub const ALL: [Self; 2] = [Self::XChaCha20Poly1305, Self::Aes256Gcm];

    /// The on-disk identifier.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::XChaCha20Poly1305 => 1,
            Self::Aes256Gcm => 2,
        }
    }

    /// Parse an on-disk identifier.
    ///
    /// # Errors
    /// [`Error::UnknownCipher`] if `id` is not a cipher this build knows.
    pub const fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(Self::XChaCha20Poly1305),
            2 => Ok(Self::Aes256Gcm),
            other => Err(Error::UnknownCipher(other)),
        }
    }

    /// Nonce length in bytes for this cipher.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::XChaCha20Poly1305 => 24,
            Self::Aes256Gcm => 12,
        }
    }

    /// Human-readable name for UI and messages.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            Self::Aes256Gcm => "AES-256-GCM",
        }
    }
}

/// Generate a fresh random nonce of the right length for `cipher`.
///
/// # Errors
/// [`Error::Rng`] if the OS random number generator fails.
pub fn random_nonce(cipher: CipherId) -> Result<Vec<u8>> {
    let mut nonce = vec![0u8; cipher.nonce_len()];
    fill_random(&mut nonce)?;
    Ok(nonce)
}

/// Encrypt `plaintext` and authenticate it together with `aad`.
///
/// Returns `ciphertext || tag`.
///
/// # Errors
/// [`Error::Crypto`] if the nonce has the wrong length for `cipher`.
pub fn seal(
    cipher: CipherId,
    key: &Key,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    match cipher {
        CipherId::XChaCha20Poly1305 => seal_with::<XChaCha20Poly1305>(key, nonce, aad, plaintext),
        CipherId::Aes256Gcm => seal_with::<Aes256Gcm>(key, nonce, aad, plaintext),
    }
}

/// Verify and decrypt `ciphertext || tag`. It is decrypted in place in a
/// [`SecretBuf`], so the plaintext never passes through unlocked memory.
///
/// # Errors
/// [`Error::Decryption`] if the key is wrong or anything (ciphertext, tag or
/// `aad`) was modified; [`Error::Crypto`] if the nonce has the wrong length.
pub fn open(
    cipher: CipherId,
    key: &Key,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<SecretBuf> {
    match cipher {
        CipherId::XChaCha20Poly1305 => open_with::<XChaCha20Poly1305>(key, nonce, aad, ciphertext),
        CipherId::Aes256Gcm => open_with::<Aes256Gcm>(key, nonce, aad, ciphertext),
    }
}

// Both ciphers implement the same RustCrypto `Aead` traits, so one generic
// implementation covers them.

fn seal_with<C: Aead + KeyInit>(
    key: &Key,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = C::new_from_slice(key.as_slice()).map_err(|e| Error::Crypto(e.to_string()))?;
    let nonce = aead::Nonce::<C>::try_from(nonce)
        .map_err(|_| Error::Crypto("nonce has the wrong length".into()))?;
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| Error::Crypto(e.to_string()))
}

fn open_with<C: AeadInOut + KeyInit>(
    key: &Key,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<SecretBuf> {
    let cipher = C::new_from_slice(key.as_slice()).map_err(|e| Error::Crypto(e.to_string()))?;
    let nonce = aead::Nonce::<C>::try_from(nonce)
        .map_err(|_| Error::Crypto("nonce has the wrong length".into()))?;
    // The ciphertext isn't secret, but it turns into the plaintext in place.
    // On failure the buffer is wiped when dropped.
    let mut buf = SecretBuf::from_slice(ciphertext);
    cipher
        .decrypt_in_place(&nonce, aad, &mut buf)
        .map_err(|_| Error::Decryption)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// The key-derivation function recorded in the header. Only Argon2id exists
/// today; the id byte leaves room for a future KDF without a format break.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KdfId {
    /// Argon2id, version 0x13 (RFC 9106).
    #[default]
    Argon2id,
}

impl KdfId {
    /// The on-disk identifier.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::Argon2id => 1,
        }
    }

    /// Parse an on-disk identifier.
    ///
    /// # Errors
    /// [`Error::UnknownKdf`] if `id` is not a KDF this build knows.
    pub const fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(Self::Argon2id),
            other => Err(Error::UnknownKdf(other)),
        }
    }
}

/// User-configurable Argon2id cost parameters.
///
/// The bounds are checked both when creating a vault and when *reading* a
/// header, so a crafted file cannot make us allocate absurd amounts of memory
/// or spin forever before the password is even checked.
///
/// Backwards-compatibility rule: the minimums may only ever go *down*. If they
/// were raised, vaults created with the old minimum would stop opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
}

impl KdfParams {
    /// 19 MiB: the OWASP minimum recommendation for Argon2id.
    pub const MIN_M_COST_KIB: u32 = 19 * 1024;
    /// 4 GiB: more than this is almost certainly a mistake or an attack.
    pub const MAX_M_COST_KIB: u32 = 4 * 1024 * 1024;
    pub const MIN_T_COST: u32 = 1;
    pub const MAX_T_COST: u32 = 64;
    pub const MIN_P_COST: u32 = 1;
    pub const MAX_P_COST: u32 = 64;

    /// Defaults for new vaults: 256 MiB, 3 passes, 4 lanes. `init` will offer
    /// to calibrate these to the machine (M2).
    pub const DEFAULT: Self = Self {
        m_cost_kib: 256 * 1024,
        t_cost: 3,
        p_cost: 4,
    };

    /// Validate and build a parameter set.
    ///
    /// # Errors
    /// [`Error::InvalidKdfParams`] if any value is out of range.
    pub fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Result<Self> {
        let out_of_range = |what: &str, value: u32, min: u32, max: u32| {
            Error::InvalidKdfParams(format!("{what} = {value} is outside {min}..={max}"))
        };
        if !(Self::MIN_M_COST_KIB..=Self::MAX_M_COST_KIB).contains(&m_cost_kib) {
            return Err(out_of_range(
                "memory (KiB)",
                m_cost_kib,
                Self::MIN_M_COST_KIB,
                Self::MAX_M_COST_KIB,
            ));
        }
        if !(Self::MIN_T_COST..=Self::MAX_T_COST).contains(&t_cost) {
            return Err(out_of_range(
                "iterations",
                t_cost,
                Self::MIN_T_COST,
                Self::MAX_T_COST,
            ));
        }
        if !(Self::MIN_P_COST..=Self::MAX_P_COST).contains(&p_cost) {
            return Err(out_of_range(
                "parallelism",
                p_cost,
                Self::MIN_P_COST,
                Self::MAX_P_COST,
            ));
        }
        // Argon2 itself needs at least 8 KiB per lane.
        if m_cost_kib < 8 * p_cost {
            return Err(Error::InvalidKdfParams(
                "memory must be at least 8 KiB per lane".into(),
            ));
        }
        Ok(Self {
            m_cost_kib,
            t_cost,
            p_cost,
        })
    }

    /// Memory cost in KiB.
    #[must_use]
    pub const fn m_cost_kib(self) -> u32 {
        self.m_cost_kib
    }

    /// Number of passes over memory.
    #[must_use]
    pub const fn t_cost(self) -> u32 {
        self.t_cost
    }

    /// Degree of parallelism (lanes).
    #[must_use]
    pub const fn p_cost(self) -> u32 {
        self.p_cost
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Run Argon2id over `password` and `salt`, producing a 256-bit key.
///
/// # Errors
/// [`Error::Crypto`] if Argon2 rejects the inputs (it shouldn't, given
/// validated [`KdfParams`]).
pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN], params: KdfParams) -> Result<Key> {
    let argon_params = argon2::Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|e| Error::Crypto(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    // Derived straight into its final, locked home. Returning a `[u8; 32]`
    // by value would leave a copy on the stack of every caller it passed
    // through on its way to the unlocked vault.
    let mut key = SecretBuf::zeroed(KEY_LEN);
    argon
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(key)
}

/// A one-line summary, e.g. "XChaCha20-Poly1305, Argon2id 256 MiB × 3 passes ×
/// 4 lanes".
#[must_use]
pub fn describe(cipher: CipherId, kdf: KdfParams) -> String {
    let plural = |n: u32, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
    format!(
        "{}, Argon2id {} MiB × {} × {}",
        cipher.name(),
        kdf.m_cost_kib() / 1024,
        plural(kdf.t_cost(), "pass", "passes"),
        plural(kdf.p_cost(), "lane", "lanes"),
    )
}

/// Compare two keys in constant time: every byte is looked at, whatever
/// the first difference, so the time taken says nothing about the key.
#[must_use]
pub fn keys_equal(a: &Key, b: &Key) -> bool {
    let diff = a
        .iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    // Stop the optimiser from turning the fold into an early-exit compare.
    std::hint::black_box(diff) == 0
}

/// A derived key bundled with the salt and parameters that produced it.
///
/// Keeping these together lets us save repeatedly without re-running Argon2
/// (which is deliberately slow): each save gets a fresh *nonce*, while the
/// salt only changes when the password or KDF parameters change.
pub struct VaultKey {
    key: Key,
    salt: [u8; SALT_LEN],
    kdf: KdfParams,
}

impl VaultKey {
    /// Derive a key for a brand-new vault (or a password/parameter change),
    /// using a freshly generated random salt.
    ///
    /// # Errors
    /// [`Error::Rng`] or any error from [`derive_key`].
    pub fn derive_new(password: &[u8], kdf: KdfParams) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt)?;
        Self::derive(password, salt, kdf)
    }

    /// Re-derive the key for an existing vault from its stored salt.
    ///
    /// # Errors
    /// Any error from [`derive_key`].
    pub fn derive(password: &[u8], salt: [u8; SALT_LEN], kdf: KdfParams) -> Result<Self> {
        let key = derive_key(password, &salt, kdf)?;
        Ok(Self { key, salt, kdf })
    }

    /// The raw key bytes.
    #[must_use]
    pub fn key(&self) -> &Key {
        &self.key
    }

    /// The salt this key was derived with.
    #[must_use]
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    /// The parameters this key was derived with.
    #[must_use]
    pub fn kdf(&self) -> KdfParams {
        self.kdf
    }
}

// Never print key material, even in debug output or panic messages.
impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultKey")
            .field("key", &"<redacted>")
            .field("kdf", &self.kdf)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

/// Fill `buf` straight from the operating system's CSPRNG. We never use a
/// userspace RNG for key material, salts or nonces.
///
/// # Errors
/// [`Error::Rng`] if the OS refuses to provide randomness.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    SysRng
        .try_fill_bytes(buf)
        .map_err(|e| Error::Rng(e.to_string()))
}

/// The cheapest parameters the reader accepts, to keep tests fast.
#[cfg(test)]
pub(crate) fn test_params() -> KdfParams {
    KdfParams::new(KdfParams::MIN_M_COST_KIB, 1, 1).expect("minimum params are valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_ids_round_trip() {
        for cipher in CipherId::ALL {
            assert_eq!(CipherId::from_id(cipher.id()).unwrap(), cipher);
        }
        assert!(matches!(CipherId::from_id(0), Err(Error::UnknownCipher(0))));
    }

    #[test]
    fn kdf_params_bounds() {
        assert!(KdfParams::new(KdfParams::MIN_M_COST_KIB - 1, 1, 1).is_err());
        assert!(KdfParams::new(KdfParams::MAX_M_COST_KIB + 1, 1, 1).is_err());
        assert!(KdfParams::new(KdfParams::MIN_M_COST_KIB, 0, 1).is_err());
        assert!(KdfParams::new(KdfParams::MIN_M_COST_KIB, 65, 1).is_err());
        assert!(KdfParams::new(KdfParams::MIN_M_COST_KIB, 1, 0).is_err());
        assert!(KdfParams::new(KdfParams::MIN_M_COST_KIB, 1, 65).is_err());
        assert!(KdfParams::new(KdfParams::MIN_M_COST_KIB, 1, 1).is_ok());
        // DEFAULT must itself pass validation.
        let d = KdfParams::DEFAULT;
        assert_eq!(KdfParams::new(d.m_cost_kib, d.t_cost, d.p_cost).unwrap(), d);
    }

    #[test]
    fn derive_is_deterministic_and_password_sensitive() {
        let salt = [7u8; SALT_LEN];
        let a = derive_key(b"hunter2", &salt, test_params()).unwrap();
        let b = derive_key(b"hunter2", &salt, test_params()).unwrap();
        let c = derive_key(b"hunter3", &salt, test_params()).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
    }

    #[test]
    fn aead_round_trip_and_tamper() {
        let key: Key = SecretBuf::from_slice(&[42u8; KEY_LEN]);
        for cipher in CipherId::ALL {
            let nonce = random_nonce(cipher).unwrap();
            let ct = seal(cipher, &key, &nonce, b"header", b"secret").unwrap();
            assert_eq!(ct.len(), b"secret".len() + TAG_LEN);
            let pt = open(cipher, &key, &nonce, b"header", &ct).unwrap();
            assert_eq!(pt.as_slice(), b"secret");

            // Changing the associated data must break authentication.
            assert!(matches!(
                open(cipher, &key, &nonce, b"Header", &ct),
                Err(Error::Decryption)
            ));
            // Wrong nonce length is a programming error, not a decrypt error.
            assert!(matches!(
                open(cipher, &key, &[0u8; 5], b"header", &ct),
                Err(Error::Crypto(_))
            ));
        }
    }

    #[test]
    fn keys_equal_compares_every_byte() {
        let a: Key = SecretBuf::from_slice(&[1u8; KEY_LEN]);
        let mut b: Key = SecretBuf::from_slice(&[1u8; KEY_LEN]);
        assert!(keys_equal(&a, &b));
        b[KEY_LEN - 1] = 2; // differs only in the last byte
        assert!(!keys_equal(&a, &b));
    }

    #[test]
    fn vault_key_debug_is_redacted() {
        let vk = VaultKey::derive(b"pw", [1u8; SALT_LEN], test_params()).unwrap();
        let shown = format!("{vk:?}");
        assert!(shown.contains("redacted"));
        assert!(!shown.contains(&format!("{:?}", vk.key().as_slice())));
    }
}
