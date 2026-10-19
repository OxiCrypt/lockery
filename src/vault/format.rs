//! The on-disk vault file format.
//!
//! ```text
//! offset  size  field
//! ------  ----  -----------------------------------------------
//!      0     8  magic "LOCKERY\0"
//!      8     2  format_version (u16 LE)            -- currently 1
//!     10     1  kdf_id (1 = Argon2id v0x13)
//!     11     4  m_cost in KiB (u32 LE)
//!     15     4  t_cost (u32 LE)
//!     19     4  p_cost (u32 LE)
//!     23    32  salt
//!     55     1  cipher_id (1 = XChaCha20-Poly1305, 2 = AES-256-GCM)
//!     56     n  nonce (24 or 12 bytes, depending on cipher)
//!   56+n     8  ciphertext_len (u64 LE)
//!   64+n     *  ciphertext || 16-byte tag
//! ```
//!
//! Everything up to and including `ciphertext_len` is the *header* and is
//! passed to the AEAD as associated data, so changing any parameter, the
//! cipher id or the version makes decryption fail.
//!
//! The header reveals only how the vault is encrypted. Every piece of user
//! data, including titles, URLs, timestamps and the number of entries, is
//! inside the ciphertext. Before encryption the payload is framed as
//! `len (u64 LE) || payload || zero padding` up to a multiple of
//! [`PAD_BLOCK`], so the file size only loosely hints at the vault's size.
//!
//! Backwards compatibility: [`decode`] dispatches on `format_version`.
//! Readers for old versions must never be removed. New versions get a new
//! `decode_vN` and become what [`seal`] writes.

use crate::hardening::SecretBuf;

use crate::crypto::{self, CipherId, KdfId, KdfParams, SALT_LEN, TAG_LEN, VaultKey};
use crate::error::{Error, Result};

/// Every vault file starts with these bytes.
pub const MAGIC: &[u8; 8] = b"LOCKERY\0";

/// The version [`seal`] writes.
pub const CURRENT_FORMAT_VERSION: u16 = 1;

/// Plaintext is padded to a multiple of this many bytes.
pub const PAD_BLOCK: usize = 4096;

/// Size of the length prefix inside the padded plaintext.
const LEN_PREFIX: usize = 8;

/// Refuse to even look at a ciphertext bigger than this (1 GiB). A real vault
/// is a few hundred KiB at most.
const MAX_CIPHERTEXT_LEN: u64 = 1 << 30;

/// The parsed, *unauthenticated* header. Nothing in here can be trusted
/// until the ciphertext has been successfully decrypted with it as AAD.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub format_version: u16,
    pub kdf_id: KdfId,
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub cipher: CipherId,
    pub nonce: Vec<u8>,
}

/// A vault file split into its parts, borrowing from the input bytes.
#[derive(Debug)]
pub struct Parsed<'a> {
    pub header: Header,
    /// The raw header bytes, exactly as authenticated by the AEAD.
    pub aad: &'a [u8],
    /// Ciphertext including the trailing tag.
    pub ciphertext: &'a [u8],
}

/// The result of successfully opening a vault with its password.
#[derive(Debug)]
pub struct Opened {
    /// The derived key, kept so later saves can skip Argon2.
    pub key: VaultKey,
    /// The cipher the file was written with.
    pub cipher: CipherId,
    /// The format version the file was written with. If this is older than
    /// [`CURRENT_FORMAT_VERSION`], the next save upgrades the file.
    pub format_version: u16,
    /// The decrypted, un-padded payload.
    pub plaintext: SecretBuf,
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// Split a vault file into header, AAD and ciphertext, validating every
/// field. Performs no cryptography, so it is cheap and safe to fuzz.
///
/// # Errors
/// [`Error::NotAVault`], [`Error::UnsupportedVersion`],
/// [`Error::UnknownKdf`], [`Error::UnknownCipher`],
/// [`Error::InvalidKdfParams`] or [`Error::Malformed`].
pub fn decode(bytes: &[u8]) -> Result<Parsed<'_>> {
    let mut r = Reader::new(bytes);
    if r.take(MAGIC.len())? != MAGIC {
        return Err(Error::NotAVault);
    }
    match r.u16()? {
        1 => decode_v1(r),
        other => Err(Error::UnsupportedVersion(other)),
    }
}

/// Reader for format version 1. `r` is positioned just after the version.
fn decode_v1(mut r: Reader<'_>) -> Result<Parsed<'_>> {
    let kdf_id = KdfId::from_id(r.u8()?)?;
    let m_cost = r.u32()?;
    let t_cost = r.u32()?;
    let p_cost = r.u32()?;
    // Bounds are enforced here, before any expensive work happens.
    let kdf = KdfParams::new(m_cost, t_cost, p_cost)?;

    let salt: [u8; SALT_LEN] = r
        .take(SALT_LEN)?
        .try_into()
        .map_err(|_| Error::Malformed("salt"))?;
    let cipher = CipherId::from_id(r.u8()?)?;
    let nonce = r.take(cipher.nonce_len())?.to_vec();

    let ct_len = r.u64()?;
    if ct_len > MAX_CIPHERTEXT_LEN {
        return Err(Error::Malformed("ciphertext is implausibly large"));
    }
    let aad = &r.buf[..r.pos];

    // The declared length must match what is actually left: no truncation
    // and no trailing junk.
    let ciphertext = r.rest();
    if ciphertext.len() as u64 != ct_len {
        return Err(Error::Malformed("ciphertext length does not match header"));
    }
    if ciphertext.len() < TAG_LEN + PAD_BLOCK {
        return Err(Error::Malformed("ciphertext is too short"));
    }

    Ok(Parsed {
        header: Header {
            format_version: 1,
            kdf_id,
            kdf,
            salt,
            cipher,
            nonce,
        },
        aad,
        ciphertext,
    })
}

/// Open a vault file with the master password. This runs Argon2 and is
/// therefore slow by design.
///
/// # Errors
/// Anything [`decode`] returns, or [`Error::Decryption`] for a wrong password
/// or a damaged file.
pub fn open(password: &[u8], bytes: &[u8]) -> Result<Opened> {
    let parsed = decode(bytes)?;
    let key = VaultKey::derive(password, parsed.header.salt, parsed.header.kdf)?;
    let plaintext = decrypt_parsed(&key, &parsed)?;
    Ok(Opened {
        key,
        cipher: parsed.header.cipher,
        format_version: parsed.header.format_version,
        plaintext,
    })
}

/// Open a vault file with an already-derived key (no Argon2). Used to verify
/// a freshly written file before it replaces the old one.
///
/// # Errors
/// Anything [`decode`] returns, [`Error::Decryption`] if the file was not
/// written with `key` or is damaged.
pub fn open_with_key(key: &VaultKey, bytes: &[u8]) -> Result<SecretBuf> {
    let parsed = decode(bytes)?;
    if parsed.header.salt != *key.salt() || parsed.header.kdf != key.kdf() {
        // Different salt/params means a different key; don't bother trying.
        return Err(Error::Decryption);
    }
    decrypt_parsed(key, &parsed)
}

fn decrypt_parsed(key: &VaultKey, parsed: &Parsed<'_>) -> Result<SecretBuf> {
    let padded = crypto::open(
        parsed.header.cipher,
        key.key(),
        &parsed.header.nonce,
        parsed.aad,
        parsed.ciphertext,
    )?;
    unpad(padded)
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` into a complete vault file in the current format,
/// using a fresh random nonce.
///
/// # Errors
/// [`Error::Rng`] or [`Error::Crypto`].
pub fn seal(key: &VaultKey, cipher: CipherId, plaintext: &[u8]) -> Result<Vec<u8>> {
    let padded = pad(plaintext);
    let nonce = crypto::random_nonce(cipher)?;
    let ct_len = padded.len() + TAG_LEN;

    let header = Header {
        format_version: CURRENT_FORMAT_VERSION,
        kdf_id: KdfId::Argon2id,
        kdf: key.kdf(),
        salt: *key.salt(),
        cipher,
        nonce,
    };
    let mut out = encode_header(&header, ct_len as u64);
    let ciphertext = crypto::seal(cipher, key.key(), &header.nonce, &out, &padded)?;
    debug_assert_eq!(ciphertext.len(), ct_len);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Serialise a header (in the current format) followed by `ct_len`.
fn encode_header(h: &Header, ct_len: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + h.nonce.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&CURRENT_FORMAT_VERSION.to_le_bytes());
    out.push(h.kdf_id.id());
    out.extend_from_slice(&h.kdf.m_cost_kib().to_le_bytes());
    out.extend_from_slice(&h.kdf.t_cost().to_le_bytes());
    out.extend_from_slice(&h.kdf.p_cost().to_le_bytes());
    out.extend_from_slice(&h.salt);
    out.push(h.cipher.id());
    out.extend_from_slice(&h.nonce);
    out.extend_from_slice(&ct_len.to_le_bytes());
    out
}

// ---------------------------------------------------------------------------
// Padding
// ---------------------------------------------------------------------------

/// Frame `plaintext` as `len || plaintext || zeros`, rounded up to a
/// multiple of [`PAD_BLOCK`] (always at least one block).
fn pad(plaintext: &[u8]) -> SecretBuf {
    let total = (LEN_PREFIX + plaintext.len()).div_ceil(PAD_BLOCK) * PAD_BLOCK;
    let mut buf = SecretBuf::with_capacity(total);
    let fits = buf
        .extend_from_slice(&(plaintext.len() as u64).to_le_bytes())
        .and_then(|()| buf.extend_from_slice(plaintext))
        .and_then(|()| buf.resize(total));
    debug_assert!(fits.is_ok(), "`total` covers prefix and plaintext");
    buf
}

/// Reverse [`pad`]. The buffer is shrunk in place so no unwiped copy of the
/// plaintext is left behind ([`SecretBuf`] wipes its whole capacity).
fn unpad(mut buf: SecretBuf) -> Result<SecretBuf> {
    let prefix: [u8; LEN_PREFIX] = buf
        .get(..LEN_PREFIX)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Malformed("padded payload too short"))?;
    let len = usize::try_from(u64::from_le_bytes(prefix))
        .map_err(|_| Error::Malformed("payload length overflows"))?;
    if len > buf.len() - LEN_PREFIX {
        return Err(Error::Malformed("payload length exceeds padded size"));
    }
    buf.remove_prefix(LEN_PREFIX);
    buf.truncate(len);
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Byte reader
// ---------------------------------------------------------------------------

/// Minimal bounds-checked little-endian reader over a byte slice.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.buf.len())
            .ok_or(Error::Malformed("file is truncated"))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        // `take(N)` returned exactly N bytes, so the conversion cannot fail.
        self.take(N)?
            .try_into()
            .map_err(|_| Error::Malformed("file is truncated"))
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        self.array().map(u16::from_le_bytes)
    }

    fn u32(&mut self) -> Result<u32> {
        self.array().map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Result<u64> {
        self.array().map(u64::from_le_bytes)
    }

    fn rest(&mut self) -> &'a [u8] {
        let out = &self.buf[self.pos..];
        self.pos = self.buf.len();
        out
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use proptest::prelude::*;

    use super::*;
    use crate::crypto::test_params;

    /// Derived once and shared, so the proptests don't run Argon2 per case.
    static KEY: LazyLock<VaultKey> = LazyLock::new(|| {
        VaultKey::derive(b"correct horse", [9u8; SALT_LEN], test_params()).unwrap()
    });

    fn key() -> &'static VaultKey {
        &KEY
    }

    #[test]
    fn padding_round_trip_and_sizes() {
        for len in [
            0,
            1,
            PAD_BLOCK - LEN_PREFIX,
            PAD_BLOCK - LEN_PREFIX + 1,
            10_000,
        ] {
            let data = vec![0xAB; len];
            let padded = pad(&data);
            assert_eq!(padded.len() % PAD_BLOCK, 0);
            assert!(padded.len() >= PAD_BLOCK);
            assert_eq!(unpad(padded).unwrap().as_slice(), data.as_slice());
        }
    }

    #[test]
    fn small_vaults_are_indistinguishable_by_size() {
        let k = key();
        let a = seal(k, CipherId::XChaCha20Poly1305, b"x").unwrap();
        let b = seal(k, CipherId::XChaCha20Poly1305, &[0u8; 3000]).unwrap();
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn open_with_password_and_wrong_password() {
        for cipher in CipherId::ALL {
            let file = seal(key(), cipher, b"payload").unwrap();
            let opened = open(b"correct horse", &file).unwrap();
            assert_eq!(opened.plaintext.as_slice(), b"payload");
            assert_eq!(opened.cipher, cipher);
            assert_eq!(opened.format_version, CURRENT_FORMAT_VERSION);

            assert!(matches!(
                open(b"wrong horse", &file),
                Err(Error::Decryption)
            ));
        }
    }

    #[test]
    fn each_save_uses_a_new_nonce() {
        let k = key();
        let a = seal(k, CipherId::Aes256Gcm, b"same").unwrap();
        let b = seal(k, CipherId::Aes256Gcm, b"same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn header_fields_are_authenticated() {
        // Bump t_cost in the header (offset 15) from 1 to 2. The params are
        // still valid, so this is only caught by the AEAD's associated data.
        let mut file = seal(key(), CipherId::XChaCha20Poly1305, b"payload").unwrap();
        assert_eq!(file[15], 1);
        file[15] = 2;
        assert!(matches!(
            open(b"correct horse", &file),
            Err(Error::Decryption)
        ));
    }

    #[test]
    fn rejects_bad_magic_and_future_versions() {
        let mut file = seal(key(), CipherId::XChaCha20Poly1305, b"p").unwrap();
        file[8] = 99; // format_version low byte
        assert!(matches!(decode(&file), Err(Error::UnsupportedVersion(99))));
        file[0] = b'X';
        assert!(matches!(decode(&file), Err(Error::NotAVault)));
    }

    #[test]
    fn rejects_out_of_range_kdf_params_before_deriving() {
        // 5 GiB of memory: must be refused by `decode`, i.e. without Argon2.
        let mut file = seal(key(), CipherId::XChaCha20Poly1305, b"p").unwrap();
        file[11..15].copy_from_slice(&(5u32 * 1024 * 1024).to_le_bytes());
        assert!(matches!(decode(&file), Err(Error::InvalidKdfParams(_))));
        assert!(matches!(
            open(b"correct horse", &file),
            Err(Error::InvalidKdfParams(_))
        ));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut file = seal(key(), CipherId::XChaCha20Poly1305, b"p").unwrap();
        file.push(0);
        assert!(matches!(decode(&file), Err(Error::Malformed(_))));
    }

    #[test]
    fn open_with_key_rejects_other_salt() {
        let file = seal(key(), CipherId::XChaCha20Poly1305, b"p").unwrap();
        let other = VaultKey::derive(b"correct horse", [8u8; SALT_LEN], test_params()).unwrap();
        assert!(matches!(
            open_with_key(&other, &file),
            Err(Error::Decryption)
        ));
        assert_eq!(open_with_key(key(), &file).unwrap().as_slice(), b"p");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn seal_open_round_trip(
            data in proptest::collection::vec(any::<u8>(), 0..20_000),
            aes in any::<bool>(),
        ) {
            let cipher = if aes { CipherId::Aes256Gcm } else { CipherId::XChaCha20Poly1305 };
            let k = key();
            let file = seal(k, cipher, &data).unwrap();
            let opened = open_with_key(k, &file).unwrap();
            prop_assert_eq!(opened.as_slice(), data.as_slice());
        }

        #[test]
        fn any_single_byte_flip_is_rejected(idx in any::<prop::sample::Index>(), bit in 0u8..8) {
            let k = key();
            let mut file = seal(k, CipherId::XChaCha20Poly1305, b"secret").unwrap();
            let i = idx.index(file.len());
            file[i] ^= 1 << bit;
            prop_assert!(open_with_key(k, &file).is_err());
        }

        #[test]
        fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = decode(&bytes);
        }

        #[test]
        fn every_truncation_is_rejected(cut in any::<prop::sample::Index>()) {
            let file = seal(key(), CipherId::Aes256Gcm, b"secret").unwrap();
            let cut = cut.index(file.len());
            prop_assert!(decode(&file[..cut]).is_err());
        }
    }
}
