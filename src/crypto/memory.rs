//! How much memory Argon2 may take before the OS would rather kill us than
//! give it.
//!
//! This only matters on Linux. Linux overcommits: a 4 GiB allocation succeeds
//! even on a 2 GiB machine, and the OOM killer ends the process (with no
//! chance to clear the clipboard) once Argon2 touches the pages. So before
//! deriving we compare the cost with what the kernel says is free.
//!
//! - **Windows** commits memory when it is allocated, so an allocation that
//!   can't be backed fails up front, and argon2 reports that as an error.
//! - **macOS** compresses memory and grows swap on demand rather than
//!   killing ordinary processes, so a too-large cost is slow, not fatal.
//!   Refusing based on physical RAM there could lock someone out of a vault
//!   that would open, so we don't check.
//!
//! Swap counts as available: Argon2 on swap is slow but still finishes, and
//! refusing could leave a user unable to open their own vault on that machine.

/// Bytes Argon2 can allocate and use without the process being killed, or
/// `None` if this platform doesn't say (or nothing limits us).
pub(crate) fn available_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        linux::available_bytes(|path| std::fs::read_to_string(path).ok())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // tested on every OS
mod linux {
    use std::path::{Path, PathBuf};

    const KIB: u64 = 1024;
    const CGROUP_ROOT: &str = "/sys/fs/cgroup";

    /// Free RAM plus free swap, lowered to the headroom left in our cgroup
    /// (and every parent cgroup), since a container or systemd unit limit
    /// triggers the OOM killer just like running out of RAM does.
    ///
    /// `read` returns a file's contents, so tests can fake the filesystem.
    pub(super) fn available_bytes(read: impl Fn(&Path) -> Option<String>) -> Option<u64> {
        let (ram, swap) = parse_meminfo(&read(Path::new("/proc/meminfo"))?)?;
        let mut available = ram.saturating_add(swap);

        // cgroup v2 only: `0::/path`. v1 hierarchies are legacy and rare now;
        // there we just use the system figures.
        let cgroup = read(Path::new("/proc/self/cgroup")).and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("0::"))
                .map(|path| PathBuf::from(CGROUP_ROOT).join(path.trim_start_matches('/')))
        });
        if let Some(leaf) = cgroup {
            for dir in leaf.ancestors().take_while(|d| d.starts_with(CGROUP_ROOT)) {
                let Some(ram_left) = headroom(&read, dir, "memory.max", "memory.current") else {
                    continue; // no memory limit at this level
                };
                // Over the limit, the kernel swaps the cgroup's pages out if
                // it may, and only kills when it can't.
                let swap_left = headroom(&read, dir, "memory.swap.max", "memory.swap.current")
                    .unwrap_or(u64::MAX)
                    .min(swap);
                available = available.min(ram_left.saturating_add(swap_left));
            }
        }
        Some(available)
    }

    /// `MemAvailable` and `SwapFree` from `/proc/meminfo`, in bytes. `None`
    /// on kernels older than 3.14, which lack `MemAvailable`.
    fn parse_meminfo(text: &str) -> Option<(u64, u64)> {
        let field = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
                .and_then(|rest| {
                    rest.trim()
                        .trim_end_matches("kB")
                        .trim()
                        .parse::<u64>()
                        .ok()
                })
                .map(|kib| kib.saturating_mul(KIB))
        };
        Some((field("MemAvailable")?, field("SwapFree").unwrap_or(0)))
    }

    /// `limit - usage` for a cgroup control pair, or `None` if there is no
    /// limit (`max`, or the controller isn't enabled here).
    fn headroom(
        read: &impl Fn(&Path) -> Option<String>,
        dir: &Path,
        limit: &str,
        usage: &str,
    ) -> Option<u64> {
        let limit: u64 = read(&dir.join(limit))?.trim().parse().ok()?; // "max" → None
        let usage: u64 = read(&dir.join(usage))
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        Some(limit.saturating_sub(usage))
    }

    #[cfg(test)]
    mod tests {
        use std::collections::HashMap;

        use super::*;

        const MIB: u64 = 1024 * 1024;

        fn fake(files: &[(&str, &str)]) -> impl Fn(&Path) -> Option<String> {
            let files: HashMap<PathBuf, String> = files
                .iter()
                .map(|(p, c)| (PathBuf::from(p), (*c).to_owned()))
                .collect();
            move |path| files.get(path).cloned()
        }

        const MEMINFO: &str = "MemTotal:       16000000 kB\n\
                               MemFree:          500000 kB\n\
                               MemAvailable:    2048000 kB\n\
                               SwapTotal:       1024000 kB\n\
                               SwapFree:        1024000 kB\n";

        #[test]
        fn ram_plus_swap_without_cgroup() {
            let read = fake(&[("/proc/meminfo", MEMINFO)]);
            assert_eq!(available_bytes(read), Some(3_072_000 * KIB));
        }

        #[test]
        fn old_kernel_without_memavailable_is_unknown() {
            let read = fake(&[("/proc/meminfo", "MemTotal: 1 kB\nMemFree: 1 kB\n")]);
            assert_eq!(available_bytes(read), None);
        }

        #[test]
        fn cgroup_limit_is_applied_at_any_level() {
            let read = fake(&[
                ("/proc/meminfo", MEMINFO),
                ("/proc/self/cgroup", "0::/app.slice/lockery.scope\n"),
                // No limit on the leaf, 512 MiB on its parent with 100 used.
                ("/sys/fs/cgroup/app.slice/lockery.scope/memory.max", "max\n"),
                ("/sys/fs/cgroup/app.slice/memory.max", "536870912\n"),
                ("/sys/fs/cgroup/app.slice/memory.current", "104857600\n"),
                ("/sys/fs/cgroup/app.slice/memory.swap.max", "0\n"),
            ]);
            assert_eq!(available_bytes(read), Some(412 * MIB));
        }

        #[test]
        fn cgroup_may_use_system_swap_beyond_its_ram_limit() {
            let read = fake(&[
                ("/proc/meminfo", MEMINFO),
                ("/proc/self/cgroup", "0::/\n"),
                ("/sys/fs/cgroup/memory.max", "268435456\n"),
                ("/sys/fs/cgroup/memory.current", "0\n"),
                // swap.max is "max", so the system's free swap is the limit.
                ("/sys/fs/cgroup/memory.swap.max", "max\n"),
            ]);
            assert_eq!(available_bytes(read), Some(256 * MIB + 1_024_000 * KIB));
        }
    }
}
