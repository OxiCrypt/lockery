//! Search this process's own memory for a planted marker.
//!
//! Shared by `tests/wiping.rs` (wiping allocator installed) and
//! `tests/wiping_control.rs` (system allocator), so the check is shown to
//! find leftovers when they exist, not just to find nothing.
//!
//! The marker is only ever stored XOR-encoded, and compared byte by byte
//! while decoding on the fly, so the scanner itself never holds a plain copy
//! that it could then find.

use std::fs::File;
use std::os::unix::fs::FileExt;

const KEY: u8 = 0x5A;

const fn encode<const N: usize>(plain: [u8; N]) -> [u8; N] {
    let mut out = plain;
    let mut i = 0;
    while i < N {
        out[i] ^= KEY;
        i += 1;
    }
    out
}

/// The marker, encoded at compile time; the plain text never reaches the
/// binary.
const ENCODED: [u8; 40] = encode(*b"lockery-wipe-canary-7f3a9c1e5b2d8f4a6c0e");

/// A fresh heap copy of the marker, built a byte at a time.
pub fn marker() -> String {
    let mut bytes = Vec::with_capacity(ENCODED.len());
    for b in ENCODED {
        bytes.push(b ^ KEY);
    }
    String::from_utf8(bytes).expect("marker is ASCII")
}

/// Scans memory without allocating while it scans.
///
/// Create it *before* planting and freeing the marker: anything the scan
/// allocated afterwards could reuse the freed block and overwrite the
/// leftover, making "nothing found" meaningless.
pub struct Scanner {
    mem: File,
    maps: Vec<u8>,
    chunk: Vec<u8>,
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            mem: File::open("/proc/self/mem").expect("open /proc/self/mem"),
            maps: Vec::with_capacity(1 << 20),
            chunk: vec![0u8; 1 << 20],
        }
    }

    /// How many copies of the marker are in this process's writable memory.
    pub fn count(&mut self) -> usize {
        // Read the map list into the pre-sized buffer (no growth needed).
        self.maps.clear();
        let mut file = File::open("/proc/self/maps").expect("open /proc/self/maps");
        loop {
            let len = self.maps.len();
            let spare = self.maps.capacity() - len;
            assert!(spare > 0, "maps buffer too small");
            self.maps.resize(len + spare, 0);
            let n = std::io::Read::read(&mut file, &mut self.maps[len..]).unwrap();
            self.maps.truncate(len + n);
            if n == 0 {
                break;
            }
        }
        let maps = std::str::from_utf8(&self.maps).expect("maps is text");
        count_in_maps(maps, &self.mem, &mut self.chunk)
    }
}

fn count_in_maps(maps: &str, mem: &File, chunk: &mut [u8]) -> usize {
    let mut found = 0;
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let (Some(range), Some(perms)) = (parts.next(), parts.next()) else {
            continue;
        };
        // Writable private memory: heap, anonymous mappings, thread stacks,
        // .data/.bss. Read-only mappings (the binary's code and constants)
        // can't hold copies made at run time.
        if !perms.starts_with("rw") {
            continue;
        }
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            continue;
        };
        found += scan_region(mem, start, end, chunk);
    }
    found
}

fn scan_region(mem: &File, start: u64, end: u64, chunk: &mut [u8]) -> usize {
    let overlap = ENCODED.len() as u64 - 1;
    let mut found = 0;
    let mut pos = start;
    while pos < end {
        let len = usize::try_from((end - pos).min(chunk.len() as u64)).unwrap();
        let Ok(n) = mem.read_at(&mut chunk[..len], pos) else {
            return found; // unreadable (e.g. a guard page); skip the rest
        };
        if n == 0 {
            break;
        }
        found += count_in(&chunk[..n]);
        // Don't keep what was read: when the scan reaches this buffer's own
        // mapping, a leftover copy here would be counted as a real one.
        chunk[..n].fill(0);
        if pos + n as u64 >= end {
            break;
        }
        // Step back a little so a marker straddling two chunks is seen once.
        pos += (n as u64).saturating_sub(overlap).max(1);
    }
    found
}

fn count_in(hay: &[u8]) -> usize {
    let first = ENCODED[0] ^ KEY;
    let mut count = 0;
    let mut i = 0;
    while i + ENCODED.len() <= hay.len() {
        if hay[i] == first
            && hay[i..i + ENCODED.len()]
                .iter()
                .zip(ENCODED)
                .all(|(&h, e)| h == e ^ KEY)
        {
            count += 1;
            i += ENCODED.len();
        } else {
            i += 1;
        }
    }
    count
}
