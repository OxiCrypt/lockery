//! Copying secrets to the system clipboard, and clearing them again.
//!
//! * Copied text is cleared after a timeout (`clipboard_clear_secs` in the
//!   config, 20 s by default), and also when the vault locks, when Lockery
//!   quits, on SIGTERM/SIGHUP, and on a panic.
//! * Clearing only happens if the clipboard *still holds what Lockery put
//!   there*: anything you copied since, from anywhere, is left alone. To be
//!   able to compare, the copied text is kept (wiped when cleared); it's the
//!   same secret the unlocked vault already holds in memory.
//! * Copies ask clipboard managers not to record them in their history
//!   (Windows' clipboard history and cloud sync, macOS, and KDE on Linux
//!   honour this; other Linux clipboard managers may not).
//!
//! On Linux, X11 and Wayland clipboards are served by the program that
//! copied, so copied text disappears when Lockery exits anyway. The
//! serving happens on a thread inside this process (not a forked helper),
//! so nothing outlives Lockery holding its open files.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::clock::{self, Mark, WallClock};

use zeroize::Zeroizing;

/// Somewhere text can be copied to. The system clipboard in the app, an
/// in-memory one in tests.
pub trait Backend {
    /// Put `text` on the clipboard, marked as sensitive where possible.
    ///
    /// # Errors
    /// A description of why the clipboard couldn't be set.
    fn set_secret(&mut self, text: &str) -> Result<(), String>;

    /// The clipboard's current text, if it has any (and can be read).
    fn get(&mut self) -> Option<Zeroizing<String>>;

    /// Empty the clipboard.
    ///
    /// # Errors
    /// A description of why the clipboard couldn't be cleared.
    fn clear(&mut self) -> Result<(), String>;
}

/// The operating system's clipboard.
pub struct SystemBackend {
    inner: arboard::Clipboard,
}

impl SystemBackend {
    /// Connect to the system clipboard.
    ///
    /// # Errors
    /// A description if there is no clipboard (e.g. over SSH without a
    /// display).
    pub fn new() -> Result<Self, String> {
        arboard::Clipboard::new()
            .map(|inner| Self { inner })
            .map_err(|e| e.to_string())
    }
}

impl Backend for SystemBackend {
    fn set_secret(&mut self, text: &str) -> Result<(), String> {
        let set = self.inner.set();
        #[cfg(target_os = "linux")]
        let set = {
            use arboard::SetExtLinux;
            set.exclude_from_history()
        };
        #[cfg(target_os = "macos")]
        let set = {
            use arboard::SetExtApple;
            set.exclude_from_history()
        };
        #[cfg(windows)]
        let set = {
            use arboard::SetExtWindows;
            set.exclude_from_history()
                .exclude_from_cloud()
                .exclude_from_monitoring()
        };
        set.text(text).map_err(|e| e.to_string())
    }

    fn get(&mut self) -> Option<Zeroizing<String>> {
        self.inner.get_text().ok().map(Zeroizing::new)
    }

    fn clear(&mut self) -> Result<(), String> {
        self.inner.clear().map_err(|e| e.to_string())
    }
}

/// What's currently on the clipboard because of Lockery. Shared with the
/// panic and signal handlers, so they can clear it too.
pub type Copied = Arc<Mutex<Option<Zeroizing<String>>>>;

/// Makes a backend on first use, so starting Lockery without a clipboard
/// (e.g. over SSH) only fails when you actually try to copy.
type Connect = Box<dyn Fn() -> Result<Box<dyn Backend>, String>>;

pub struct Clipboard {
    connect: Connect,
    backend: Option<Box<dyn Backend>>,
    copied: Copied,
    /// Which field was copied ("password", "username"), for the countdown.
    what: &'static str,
    /// When the current copy was made, if it is still waiting to be cleared.
    /// Measured on both clocks, so time asleep counts (see [`clock`]).
    copied_at: Option<Mark>,
    timeout: Duration,
    wall: WallClock,
}

impl Clipboard {
    /// The system clipboard, cleared `timeout` after each copy.
    #[must_use]
    pub fn system(timeout: Duration) -> Self {
        Self::with_backend(timeout, || {
            SystemBackend::new().map(|b| Box::new(b) as Box<dyn Backend>)
        })
    }

    /// A clipboard using whatever backend `connect` makes (used by tests).
    #[must_use]
    pub fn with_backend(
        timeout: Duration,
        connect: impl Fn() -> Result<Box<dyn Backend>, String> + 'static,
    ) -> Self {
        Self {
            connect: Box::new(connect),
            backend: None,
            copied: Arc::new(Mutex::new(None)),
            what: "",
            copied_at: None,
            timeout,
            wall: clock::system_wall_clock(),
        }
    }

    /// Read wall-clock time from `wall` instead of the system (tests use
    /// this to fake a suspend).
    pub fn set_wall_clock(&mut self, wall: WallClock) {
        self.wall = wall;
    }

    fn backend(&mut self) -> Result<&mut dyn Backend, String> {
        if self.backend.is_none() {
            self.backend = Some((self.connect)()?);
        }
        Ok(self.backend.as_deref_mut().expect("just connected"))
    }

    /// Copy `text` (described as `what`, e.g. "password") and start the
    /// clear timer.
    ///
    /// # Errors
    /// A description if the clipboard isn't available.
    pub fn copy(&mut self, text: &str, what: &'static str, now: Instant) -> Result<(), String> {
        self.backend()?.set_secret(text)?;
        *lock(&self.copied) = Some(Zeroizing::new(text.to_owned()));
        self.what = what;
        self.copied_at = Some(Mark::new(now, (self.wall)()));
        Ok(())
    }

    /// Clear the clipboard if the timer ran out. Returns whether it cleared.
    pub fn tick(&mut self, now: Instant) -> bool {
        match self.copied_at {
            Some(at) if at.elapsed(now, (self.wall)()) >= self.timeout => {
                self.clear();
                true
            }
            _ => false,
        }
    }

    /// Clear now (on lock or quit), if the clipboard still holds our copy.
    pub fn clear(&mut self) {
        self.copied_at = None;
        let Some(ours) = lock(&self.copied).take() else {
            return;
        };
        if let Some(backend) = self.backend.as_deref_mut() {
            clear_if_ours(backend, &ours);
        }
    }

    /// `(what, seconds left)` while a copy is waiting to be cleared.
    #[must_use]
    pub fn countdown(&self, now: Instant) -> Option<(&'static str, u64)> {
        let elapsed = self.copied_at?.elapsed(now, (self.wall)());
        let left = self.timeout.saturating_sub(elapsed);
        // Round up, so "1s" shows until the very end rather than "0s".
        Some((
            self.what,
            left.as_millis()
                .div_ceil(1000)
                .try_into()
                .unwrap_or(u64::MAX),
        ))
    }

    /// A handle for clearing from a panic or signal handler, via
    /// [`emergency_clear`].
    #[must_use]
    pub fn copied_handle(&self) -> Copied {
        Arc::clone(&self.copied)
    }
}

impl Drop for Clipboard {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Clear the system clipboard if it still holds what's recorded in
/// `copied`. For panic and signal handlers, which can't reach the
/// [`Clipboard`] itself. Never panics, never blocks on the lock.
pub fn emergency_clear(copied: &Copied) {
    let Ok(mut guard) = copied.try_lock() else {
        return;
    };
    if let Some(ours) = guard.take()
        && let Ok(mut backend) = SystemBackend::new()
    {
        clear_if_ours(&mut backend, &ours);
    }
}

fn clear_if_ours(backend: &mut dyn Backend, ours: &str) {
    // Only clear what we put there. If reading fails, clear anyway: better
    // to lose something unrelated than to leave a password behind.
    let still_ours = backend.get().is_none_or(|now| *now == *ours);
    if still_ours {
        let _ = backend.clear();
    }
}

/// Lock the shared copy, even if a panicking thread poisoned it.
fn lock(copied: &Copied) -> std::sync::MutexGuard<'_, Option<Zeroizing<String>>> {
    copied
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// An in-memory clipboard for tests. Clones share the same contents, so a
/// test can look at (or change) what the app's clipboard holds.
#[derive(Clone, Default)]
pub struct FakeBackend {
    pub contents: std::rc::Rc<std::cell::RefCell<Option<String>>>,
    /// Make every operation fail, to test the error path.
    pub broken: bool,
}

impl Backend for FakeBackend {
    fn set_secret(&mut self, text: &str) -> Result<(), String> {
        if self.broken {
            return Err("no clipboard".into());
        }
        *self.contents.borrow_mut() = Some(text.to_owned());
        Ok(())
    }

    fn get(&mut self) -> Option<Zeroizing<String>> {
        self.contents.borrow().clone().map(Zeroizing::new)
    }

    fn clear(&mut self) -> Result<(), String> {
        *self.contents.borrow_mut() = None;
        Ok(())
    }
}

impl FakeBackend {
    /// A [`Clipboard`] backed by (a clone of) this fake.
    #[must_use]
    pub fn clipboard(&self, timeout: Duration) -> Clipboard {
        let fake = self.clone();
        Clipboard::with_backend(timeout, move || {
            if fake.broken {
                Err("no clipboard available".into())
            } else {
                Ok(Box::new(fake.clone()))
            }
        })
    }

    /// What the clipboard holds now.
    #[must_use]
    pub fn text(&self) -> Option<String> {
        self.contents.borrow().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Duration = Duration::from_secs(20);

    #[test]
    fn copies_then_clears_after_the_timeout() {
        let fake = FakeBackend::default();
        let mut clip = fake.clipboard(T);
        let start = Instant::now();
        clip.copy("hunter2", "password", start).unwrap();
        assert_eq!(fake.text().as_deref(), Some("hunter2"));
        assert_eq!(clip.countdown(start), Some(("password", 20)));
        assert_eq!(
            clip.countdown(start + Duration::from_millis(19_100)),
            Some(("password", 1))
        );

        assert!(!clip.tick(start + Duration::from_secs(19)));
        assert_eq!(fake.text().as_deref(), Some("hunter2"));
        assert!(clip.tick(start + T));
        assert_eq!(fake.text(), None);
        assert_eq!(clip.countdown(start + T), None);
    }

    #[test]
    fn time_asleep_counts_towards_the_timeout() {
        let fake = FakeBackend::default();
        let mut clip = fake.clipboard(T);
        let wall = std::rc::Rc::new(std::cell::Cell::new(std::time::SystemTime::now()));
        let reader = std::rc::Rc::clone(&wall);
        clip.set_wall_clock(std::rc::Rc::new(move || reader.get()));
        let start = Instant::now();
        clip.copy("hunter2", "password", start).unwrap();

        // A suspend: the monotonic clock barely moves, the wall clock does.
        wall.set(wall.get() + Duration::from_secs(3600));
        assert!(clip.tick(start + Duration::from_secs(1)));
        assert_eq!(fake.text(), None);
    }

    #[test]
    fn leaves_alone_whatever_the_user_copied_since() {
        let fake = FakeBackend::default();
        let mut clip = fake.clipboard(T);
        let start = Instant::now();
        clip.copy("hunter2", "password", start).unwrap();
        *fake.contents.borrow_mut() = Some("a URL from the browser".into());
        clip.tick(start + T);
        assert_eq!(fake.text().as_deref(), Some("a URL from the browser"));
    }

    #[test]
    fn a_new_copy_restarts_the_timer() {
        let fake = FakeBackend::default();
        let mut clip = fake.clipboard(T);
        let start = Instant::now();
        clip.copy("user", "username", start).unwrap();
        clip.copy("pw", "password", start + Duration::from_secs(15))
            .unwrap();
        assert!(!clip.tick(start + T));
        assert_eq!(fake.text().as_deref(), Some("pw"));
        assert!(clip.tick(start + Duration::from_secs(35)));
        assert_eq!(fake.text(), None);
    }

    #[test]
    fn clears_on_drop_and_on_request() {
        let fake = FakeBackend::default();
        let mut clip = fake.clipboard(T);
        clip.copy("x", "password", Instant::now()).unwrap();
        clip.clear();
        assert_eq!(fake.text(), None);

        clip.copy("y", "password", Instant::now()).unwrap();
        drop(clip);
        assert_eq!(fake.text(), None, "quitting clears too");
    }

    #[test]
    fn unavailable_clipboard_is_an_error_not_a_panic() {
        let fake = FakeBackend {
            broken: true,
            ..FakeBackend::default()
        };
        let mut clip = fake.clipboard(T);
        assert!(clip.copy("x", "password", Instant::now()).is_err());
        assert_eq!(clip.countdown(Instant::now()), None);
    }

    #[test]
    fn handle_sees_the_current_copy() {
        let fake = FakeBackend::default();
        let mut clip = fake.clipboard(T);
        let handle = clip.copied_handle();
        clip.copy("secret", "password", Instant::now()).unwrap();
        assert_eq!(
            handle.lock().unwrap().as_deref().map(String::as_str),
            Some("secret")
        );
        clip.clear();
        assert!(handle.lock().unwrap().is_none());
    }
}
