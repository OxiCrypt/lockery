//! Process hardening, checked from the outside.
//!
//! This is its own test binary because `harden_process` changes the whole
//! process (core limit, dumpability), and that must not leak into other
//! tests. It never forks (see CLAUDE.md).

#![cfg(unix)]

use lockery::hardening::{self, SecretBuf};

#[test]
fn hardening_disables_core_dumps_and_dumpability() {
    let report = hardening::harden_process();
    assert!(report.core_dumps_disabled, "{report:?}");
    assert!(report.complete(), "{report:?}");

    let mut limit = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    // SAFETY: `getrlimit` writes into the struct we own.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut limit) };
    assert_eq!(rc, 0);
    assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));

    #[cfg(target_os = "linux")]
    {
        // SAFETY: `PR_GET_DUMPABLE` takes no pointers.
        #[allow(unsafe_code)]
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        assert_eq!(dumpable, 0);
    }

    // Idempotent: calling it again (e.g. a second `main`-like entry) is fine.
    assert!(hardening::harden_process().core_dumps_disabled);
}

#[test]
fn secret_buffers_respect_the_lock_switch() {
    // Only this test touches the switch in this binary.
    hardening::set_lock_memory(false);
    assert!(!SecretBuf::from_slice(b"key").is_locked());
    hardening::set_lock_memory(true);
    let buf = SecretBuf::from_slice(b"key");
    // Locking a single page fits under any sane `ulimit -l`, but a failure
    // must be reported rather than silently ignored.
    assert!(buf.is_locked() || hardening::take_lock_failure());
}
