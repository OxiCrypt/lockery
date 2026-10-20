//! Control for `tests/wiping.rs`: with the ordinary system allocator, a
//! freed string's contents stay in memory, and the scan finds them. Without
//! this, "no copies found" could just mean the scan doesn't work.

#![cfg(target_os = "linux")]

mod common;

use common::mem_scan::{Scanner, marker};

#[test]
fn without_the_wiping_allocator_freed_copies_remain() {
    let mut scanner = Scanner::new();
    // 8 KiB: too big for glibc's per-thread cache (whose bookkeeping would
    // overwrite the start of the block) and too small to be handed back to
    // the OS on free. The fence after it stops the freed block merging into
    // the top of the heap, where the next allocation would overwrite it.
    let mut s = String::with_capacity(8192);
    let fence = vec![1u8; 64];
    s.push_str(&"-".repeat(4000));
    s.push_str(&marker());
    assert!(scanner.count() >= 1, "the scan must see a live copy");

    drop(s);
    assert!(
        scanner.count() >= 1,
        "freed memory normally keeps its contents; the scan should find it"
    );
    drop(fence);
}
