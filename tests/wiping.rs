//! With the wiping allocator installed (as in the real binary), copies of a
//! secret that libraries make and free must not survive in memory.
//!
//! One test runs every scenario in turn: tests in one binary run in
//! parallel, and one scenario's live marker would show up in another's scan.
//! `tests/wiping_control.rs` shows the same scan does find leftovers when
//! the system allocator is used.

#![cfg(target_os = "linux")]

mod common;

use common::mem_scan::{Scanner, marker};
use lockery::crypto::{CipherId, KdfParams};
use lockery::generator::Strength;
use lockery::hardening::WipingAllocator;
use lockery::vault::{Entry, EntryKind, Vault};
use ratatui_textarea::TextArea;

#[global_allocator]
static ALLOCATOR: WipingAllocator = WipingAllocator;

/// glibc reuses the first 16 bytes of a freed small block for its own
/// bookkeeping, which would destroy a leftover marker at the very start and
/// hide it from the scan. Secrets start with this pad so leftovers survive.
const PAD: &str = "padding-padding-padding-padding-";

fn secret() -> String {
    format!("{PAD}{}", marker())
}

fn assert_no_copies(scanner: &mut Scanner, scenario: &str) {
    let copies = scanner.count();
    assert_eq!(copies, 0, "{scenario}: {copies} copies left in memory");
}

#[test]
fn library_copies_are_wiped_when_freed() {
    // Allocated before any marker exists; see `Scanner`.
    let mut scanner = Scanner::new();
    let s = &mut scanner;
    assert_no_copies(s, "before anything");

    // Sanity check: a live copy is found.
    let live = marker();
    let n = s.count();
    assert_eq!(n, 1, "the scan must see exactly the live copy, saw {n}");
    drop(live);

    // A plain string, dropped without any explicit wiping.
    drop(secret());
    assert_no_copies(s, "dropped String");

    // A string that grows several times: every move leaves the old buffer.
    let mut grown = String::new();
    grown.push_str(&secret());
    for _ in 0..12 {
        grown.push_str(&"x".repeat(grown.len()));
    }
    drop(grown);
    assert_no_copies(s, "grown String");

    // The text editor widget: typed (its line grows), cut to its yank
    // buffer, pasted back, more typed, undo history.
    {
        let mut area = TextArea::default();
        for c in secret().chars() {
            area.insert_char(c);
        }
        area.select_all();
        area.cut();
        area.paste();
        area.insert_str(secret());
        area.undo();
    }
    assert_no_copies(s, "text editor widget");

    // zxcvbn copies the password into its own strings while scoring it.
    let password = secret();
    let _ = Strength::of(&password, &[]);
    drop(password);
    assert_no_copies(s, "zxcvbn");

    // A vault round trip. The marker sits inside the first 4 KiB of a long
    // note: ciborium decodes it through a stack buffer, then grows a
    // `String` past it, leaving the old buffer behind.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.lockery");
    let kdf = KdfParams::new(KdfParams::MIN_M_COST_KIB, 1, 1).unwrap();
    {
        let mut vault = Vault::create(&path, b"pw", kdf, CipherId::XChaCha20Poly1305).unwrap();
        let mut entry = Entry::new(EntryKind::Login, "Site");
        entry.password = secret();
        entry.notes = format!("{}{}{}", "n".repeat(3000), secret(), "n".repeat(6000));
        vault.add(entry).unwrap();
    }
    {
        let vault = Vault::unlock(&path, b"pw").unwrap();
        assert_eq!(vault.entries().len(), 1);
    }
    assert_no_copies(s, "vault save and unlock");
}
