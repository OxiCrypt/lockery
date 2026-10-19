//! Process hardening and locked memory for secrets.
//!
//! Two independent defences against secrets leaking out of process memory:
//!
//! * [`harden_process`] stops the OS from writing core dumps, and on Linux
//!   marks the process non-dumpable, which also stops other processes of the
//!   same user from attaching with `ptrace` or reading `/proc/<pid>/mem`.
//! * [`SecretBuf`] is a fixed-capacity byte buffer for the most sensitive
//!   data (the vault key and the decrypted payload). It lives on whole pages
//!   of its own, is `mlock`ed so it is never written to swap (best-effort,
//!   see [`set_lock_memory`]), and is wiped before it is freed.
//!
//! This is the only module that uses `unsafe`: each libc call and the raw
//! allocation opt in locally with a comment explaining why it is sound.
//! Entry strings are *not* locked: they are many small allocations scattered
//! over the heap, and locking the whole process would put Argon2's hundreds
//! of MiB over the usual `RLIMIT_MEMLOCK`. The README's threat model says so.

use std::alloc::{self, Layout};
use std::fmt;
use std::io;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Process hardening
// ---------------------------------------------------------------------------

/// What [`harden_process`] managed to do. A `false` field means the OS
/// refused (or the platform has no such control); Lockery still runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardeningReport {
    /// The core-file size limit is 0, so a crash leaves no core dump.
    pub core_dumps_disabled: bool,
    /// Linux only: `PR_SET_DUMPABLE` is 0 (no core dumps, no same-user
    /// `ptrace`, `/proc/<pid>/mem` closed to other processes).
    pub not_dumpable: bool,
}

impl HardeningReport {
    /// Whether everything this platform supports was applied.
    #[must_use]
    pub fn complete(self) -> bool {
        let dumpable_ok = self.not_dumpable || !cfg!(target_os = "linux");
        self.core_dumps_disabled && dumpable_ok
    }
}

/// Make this process as hard as practical to read secrets out of. Call it
/// first thing in `main`, before any secret is read.
///
/// * Unix: the core-file limit is set to 0 (soft and hard, so it can't be
///   raised again).
/// * Linux: also `prctl(PR_SET_DUMPABLE, 0)`.
/// * macOS: only the core limit. `PT_DENY_ATTACH` is deliberately not used:
///   it stops debugging Lockery itself and is easily bypassed by anyone who
///   could attach in the first place.
/// * Windows: nothing yet. Crash dumps are written by Windows Error
///   Reporting, outside the process; see the threat model in the README.
///
/// Failures are reported, never fatal: a password manager that refuses to
/// start because a hardening step failed helps nobody.
#[must_use]
pub fn harden_process() -> HardeningReport {
    HardeningReport {
        core_dumps_disabled: sys::disable_core_dumps(),
        not_dumpable: sys::set_not_dumpable(),
    }
}

// ---------------------------------------------------------------------------
// Memory locking switch
// ---------------------------------------------------------------------------

/// Whether new [`SecretBuf`]s try to `mlock` their pages. On by default.
static LOCK_MEMORY: AtomicBool = AtomicBool::new(true);
/// Set when an `mlock` failed, until [`take_lock_failure`] reports it.
static LOCK_FAILED: AtomicBool = AtomicBool::new(false);

/// Turn memory locking on or off for buffers created from now on (the
/// config's `[security] lock_memory`).
///
/// This is process-wide state, unlike everything else in the library: the
/// buffers are created deep inside `crypto` and `vault`, and threading a
/// flag through every call would clutter APIs for a setting that is read
/// once at startup and never changes.
pub fn set_lock_memory(enabled: bool) {
    LOCK_MEMORY.store(enabled, Ordering::Relaxed);
}

/// Whether memory locking is switched on.
#[must_use]
pub fn lock_memory_enabled() -> bool {
    LOCK_MEMORY.load(Ordering::Relaxed)
}

/// What to tell the user when [`take_lock_failure`] returns `true`.
pub const LOCK_FAILURE_ADVICE: &str = "couldn't lock secrets in memory, so they may be written to swap. \
     Raise the limit (`ulimit -l`), or set `lock_memory = false` under [security] in the config.";

/// Returns `true` (once) if a buffer couldn't be locked since the last call,
/// usually because `RLIMIT_MEMLOCK` (`ulimit -l`) is too small. The buffer
/// still works; it just isn't kept out of swap. Callers use this to warn the
/// user a single time instead of on every save.
pub fn take_lock_failure() -> bool {
    LOCK_FAILED.swap(false, Ordering::Relaxed)
}

/// The OS page size, used to give every [`SecretBuf`] pages of its own.
fn page_size() -> usize {
    static PAGE: OnceLock<usize> = OnceLock::new();
    *PAGE.get_or_init(sys::page_size)
}

// ---------------------------------------------------------------------------
// SecretBuf
// ---------------------------------------------------------------------------

/// The buffer is full; it never grows (growing would leave an unwiped copy
/// behind in freed memory).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityError;

impl fmt::Display for CapacityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("secret buffer is full")
    }
}

impl std::error::Error for CapacityError {}

/// A fixed-capacity byte buffer for secrets: page-aligned, `mlock`ed when
/// possible, wiped on drop, and never reallocated.
///
/// The allocation is rounded up to whole pages and aligned to a page, so it
/// never shares a page with other memory. That matters because locks don't
/// nest: `munlock` on a shared page would also unlock a neighbour's secret.
pub struct SecretBuf {
    ptr: NonNull<u8>,
    /// Bytes allocated (whole pages); all of it is wiped on drop.
    alloc_len: usize,
    /// Usable capacity, as requested.
    cap: usize,
    len: usize,
    locked: bool,
}

// SAFETY: `SecretBuf` uniquely owns its allocation (like `Vec<u8>`), and all
// access goes through `&self`/`&mut self`, so moving it to or sharing it with
// another thread is as safe as it is for `Vec<u8>`.
#[allow(unsafe_code)]
unsafe impl Send for SecretBuf {}
// SAFETY: see `Send`; `&SecretBuf` only gives out `&[u8]`.
#[allow(unsafe_code)]
unsafe impl Sync for SecretBuf {}

impl SecretBuf {
    /// An empty buffer that can hold up to `cap` bytes.
    ///
    /// # Panics
    /// Only if `cap` is so large the page-rounded size overflows, or the
    /// allocation fails (which aborts, as for `Vec`).
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        let page = page_size();
        let alloc_len = cap
            .max(1)
            .checked_next_multiple_of(page)
            .expect("secret buffer size overflows");
        let layout = Layout::from_size_align(alloc_len, page).expect("page-sized layout is valid");
        let ptr = alloc_zeroed(layout);
        let locked = lock_memory_enabled() && {
            let ok = sys::lock(ptr, alloc_len);
            if !ok {
                LOCK_FAILED.store(true, Ordering::Relaxed);
            }
            ok
        };
        Self {
            ptr,
            alloc_len,
            cap,
            len: 0,
            locked,
        }
    }

    /// A buffer holding a copy of `data`, with no room to spare.
    #[must_use]
    pub fn from_slice(data: &[u8]) -> Self {
        let mut buf = Self::with_capacity(data.len());
        buf.as_spare()[..data.len()].copy_from_slice(data);
        buf.len = data.len();
        buf
    }

    /// A buffer of exactly `len` zero bytes, to be filled in place (e.g. a
    /// key derived straight into it).
    #[must_use]
    pub fn zeroed(len: usize) -> Self {
        let mut buf = Self::with_capacity(len);
        buf.len = len;
        buf
    }

    /// The contents (same as `&*buf`).
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self
    }

    /// The usable capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Whether the pages are locked in RAM.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Append `data`.
    ///
    /// # Errors
    /// [`CapacityError`] (and nothing appended) if it doesn't fit.
    pub fn extend_from_slice(&mut self, data: &[u8]) -> Result<(), CapacityError> {
        if data.len() > self.cap - self.len {
            return Err(CapacityError);
        }
        let start = self.len;
        self.as_spare()[start..start + data.len()].copy_from_slice(data);
        self.len += data.len();
        Ok(())
    }

    /// Grow (with zeros) or shrink to `len` bytes.
    ///
    /// # Errors
    /// [`CapacityError`] if `len` is beyond the capacity.
    pub fn resize(&mut self, len: usize) -> Result<(), CapacityError> {
        if len > self.cap {
            return Err(CapacityError);
        }
        if len > self.len {
            let start = self.len;
            self.as_spare()[start..len].fill(0);
        }
        self.len = len;
        Ok(())
    }

    /// Shorten to `len` bytes (no-op if already shorter). The cut-off bytes
    /// are wiped straight away rather than waiting for the drop.
    pub fn truncate(&mut self, len: usize) {
        if len < self.len {
            let end = self.len;
            self.as_spare()[len..end].zeroize();
            self.len = len;
        }
    }

    /// Remove the first `n` bytes, shifting the rest down in place.
    pub fn remove_prefix(&mut self, n: usize) {
        let n = n.min(self.len);
        let len = self.len;
        self.as_spare().copy_within(n..len, 0);
        self.truncate(len - n);
    }

    /// The whole allocation as a mutable slice, including unused capacity.
    fn as_spare(&mut self) -> &mut [u8] {
        // SAFETY: `ptr` points to `alloc_len` initialised (zeroed) bytes that
        // this value owns exclusively, and `&mut self` guarantees no other
        // reference into them exists.
        #[allow(unsafe_code)]
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.alloc_len)
        }
    }
}

/// `alloc::alloc_zeroed`, aborting on failure like `Vec` does.
fn alloc_zeroed(layout: Layout) -> NonNull<u8> {
    // SAFETY: `layout` has a non-zero size (at least one page).
    #[allow(unsafe_code)]
    let raw = unsafe { alloc::alloc_zeroed(layout) };
    NonNull::new(raw).unwrap_or_else(|| alloc::handle_alloc_error(layout))
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        // Wipe everything, not just `len`: truncated or shifted bytes may
        // still sit in the spare capacity. `zeroize` uses volatile writes the
        // optimiser can't remove.
        self.as_spare().zeroize();
        if self.locked {
            sys::unlock(self.ptr, self.alloc_len);
        }
        let layout = Layout::from_size_align(self.alloc_len, page_size())
            .expect("layout was valid when allocated");
        // SAFETY: allocated in `with_capacity` with this exact layout (the
        // page size never changes), and never freed before.
        #[allow(unsafe_code)]
        unsafe {
            alloc::dealloc(self.ptr.as_ptr(), layout);
        }
    }
}

impl Deref for SecretBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        // SAFETY: the first `len` bytes are initialised and owned by `self`;
        // `&self` rules out a concurrent `&mut`.
        #[allow(unsafe_code)]
        unsafe {
            std::slice::from_raw_parts(self.ptr.as_ptr(), self.len)
        }
    }
}

impl DerefMut for SecretBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        let len = self.len;
        &mut self.as_spare()[..len]
    }
}

impl AsRef<[u8]> for SecretBuf {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl AsMut<[u8]> for SecretBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        self
    }
}

/// Lets the AEAD decrypt and encrypt in place, so the plaintext never
/// passes through an unlocked `Vec`.
impl aes_gcm::aead::Buffer for SecretBuf {
    fn extend_from_slice(&mut self, other: &[u8]) -> aes_gcm::aead::Result<()> {
        Self::extend_from_slice(self, other).map_err(|_| aes_gcm::aead::Error)
    }

    fn truncate(&mut self, len: usize) {
        Self::truncate(self, len);
    }
}

/// Lets `ciborium` serialise straight into the buffer. Writing past the
/// capacity is an error, never a reallocation.
impl io::Write for SecretBuf {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.extend_from_slice(data)
            .map(|()| data.len())
            .map_err(|e| io::Error::new(io::ErrorKind::WriteZero, e))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl PartialEq for SecretBuf {
    /// Constant-time comparison of the contents (lengths aren't secret).
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len
            && std::hint::black_box(
                self.iter()
                    .zip(other.iter())
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b)),
            ) == 0
    }
}

impl Eq for SecretBuf {}

// Never print the contents.
impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBuf")
            .field("len", &self.len)
            .field("locked", &self.locked)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Typed secrets
// ---------------------------------------------------------------------------

/// Append `c` to a secret being typed. If it doesn't fit, the text moves to
/// a buffer twice the size and the old one is wiped first; a plain `push`
/// would leave the old buffer's copy behind, unwiped.
pub fn push_char(s: &mut String, c: char) {
    if s.len() + c.len_utf8() > s.capacity() {
        let mut bigger = String::with_capacity((s.capacity() * 2).max(s.len() + c.len_utf8()));
        bigger.push_str(s);
        s.zeroize();
        *s = bigger;
    }
    s.push(c);
}

/// Remove the last character of a secret being typed, wiping its bytes
/// (`String::pop` leaves them in the spare capacity).
///
/// # Panics
/// Never: the cut is always at a character boundary.
pub fn pop_char(s: &mut String) -> Option<char> {
    let c = s.chars().next_back()?;
    let keep = s.len() - c.len_utf8();
    // `into_bytes`/`from_utf8` reuse the same allocation: nothing is copied.
    let mut bytes = std::mem::take(s).into_bytes();
    bytes[keep..].zeroize();
    bytes.truncate(keep);
    *s = String::from_utf8(bytes).expect("cut at a char boundary");
    Some(c)
}

// ---------------------------------------------------------------------------
// Platform calls
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod sys {
    use std::ptr::NonNull;

    pub fn page_size() -> usize {
        // SAFETY: `sysconf` has no preconditions; it only reads a value.
        #[allow(unsafe_code)]
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(size)
            .ok()
            .filter(|s| s.is_power_of_two())
            .unwrap_or(4096)
    }

    pub fn disable_core_dumps() -> bool {
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `setrlimit` only reads the struct we pass by reference.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const zero) };
        rc == 0
    }

    #[cfg(target_os = "linux")]
    pub fn set_not_dumpable() -> bool {
        // SAFETY: `PR_SET_DUMPABLE` takes plain integer arguments and touches
        // no memory of ours.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        rc == 0
    }

    #[cfg(not(target_os = "linux"))]
    pub fn set_not_dumpable() -> bool {
        false
    }

    /// Lock the pages in RAM, and on Linux leave them out of core dumps too
    /// (belt and braces: `PR_SET_DUMPABLE` already prevents dumps, but a
    /// user can re-enable them with a debugger).
    pub fn lock(ptr: NonNull<u8>, len: usize) -> bool {
        // SAFETY: `ptr..ptr+len` is a live allocation we own; `mlock` and
        // `madvise` only change page attributes, never the contents.
        #[allow(unsafe_code)]
        unsafe {
            let locked = libc::mlock(ptr.as_ptr().cast(), len) == 0;
            #[cfg(target_os = "linux")]
            libc::madvise(ptr.as_ptr().cast(), len, libc::MADV_DONTDUMP);
            locked
        }
    }

    pub fn unlock(ptr: NonNull<u8>, len: usize) {
        // SAFETY: same range as passed to `lock`, still allocated. The
        // allocation owns whole pages, so no other buffer is unlocked.
        #[allow(unsafe_code)]
        unsafe {
            libc::munlock(ptr.as_ptr().cast(), len);
        }
    }
}

/// Windows (and anything else): no hardening yet. `VirtualLock` would need
/// the `windows-sys` crate; it's a follow-up after the alpha.
#[cfg(not(unix))]
mod sys {
    use std::ptr::NonNull;

    pub fn page_size() -> usize {
        4096
    }

    pub fn disable_core_dumps() -> bool {
        false
    }

    pub fn set_not_dumpable() -> bool {
        false
    }

    pub fn lock(_ptr: NonNull<u8>, _len: usize) -> bool {
        false
    }

    pub fn unlock(_ptr: NonNull<u8>, _len: usize) {}
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    #[test]
    fn grows_only_within_capacity() {
        let mut buf = SecretBuf::with_capacity(5);
        buf.extend_from_slice(b"abc").unwrap();
        assert_eq!(buf.extend_from_slice(b"def"), Err(CapacityError));
        assert_eq!(&*buf, b"abc", "a failed append changes nothing");
        buf.extend_from_slice(b"de").unwrap();
        assert_eq!(&*buf, b"abcde");
        assert!(buf.write_all(b"!").is_err());
    }

    #[test]
    fn resize_truncate_and_remove_prefix() {
        let mut buf = SecretBuf::with_capacity(8);
        buf.extend_from_slice(b"secret").unwrap();
        buf.remove_prefix(2);
        assert_eq!(&*buf, b"cret");
        buf.truncate(2);
        assert_eq!(&*buf, b"cr");
        buf.resize(4).unwrap();
        assert_eq!(&*buf, b"cr\0\0", "regrown bytes are zero, not old data");
        assert_eq!(buf.resize(9), Err(CapacityError));
    }

    #[test]
    fn buffers_get_pages_of_their_own() {
        let page = page_size();
        let a = SecretBuf::from_slice(b"one");
        let b = SecretBuf::zeroed(page + 1);
        for buf in [&a, &b] {
            assert_eq!(buf.ptr.as_ptr() as usize % page, 0);
            assert_eq!(buf.alloc_len % page, 0);
        }
        assert_eq!(b.alloc_len, 2 * page);
        assert_eq!(b.len(), page + 1);
        // An empty buffer still owns a page, so it is never a dangling one.
        assert_eq!(SecretBuf::with_capacity(0).alloc_len, page);
    }

    #[test]
    fn typed_secrets_stay_in_place_and_wipe_deletions() {
        let mut s = String::with_capacity(4);
        for c in "abc".chars() {
            push_char(&mut s, c);
        }
        let ptr = s.as_ptr();
        assert_eq!(pop_char(&mut s), Some('c'));
        assert_eq!(s, "ab");
        assert_eq!(s.as_ptr(), ptr, "popping keeps the same buffer");
        // Growing past the capacity moves to a bigger buffer.
        push_char(&mut s, 'é');
        push_char(&mut s, 'x');
        assert_eq!(s, "abéx");
        assert_eq!(pop_char(&mut s), Some('x'));
        assert_eq!(pop_char(&mut s), Some('é'));
        assert_eq!(pop_char(&mut s), Some('b'));
        assert_eq!(pop_char(&mut s), Some('a'));
        assert_eq!(pop_char(&mut s), None);
    }

    #[test]
    fn equality_and_debug() {
        assert_eq!(SecretBuf::from_slice(b"pw"), SecretBuf::from_slice(b"pw"));
        assert_ne!(SecretBuf::from_slice(b"pw"), SecretBuf::from_slice(b"pX"));
        assert_ne!(SecretBuf::from_slice(b"pw"), SecretBuf::from_slice(b"pw!"));
        let shown = format!("{:?}", SecretBuf::from_slice(b"hunter2"));
        assert!(!shown.contains("hunter2"));
    }
}
