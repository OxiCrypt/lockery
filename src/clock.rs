//! Measuring "how long since" in a way that counts time spent asleep.
//!
//! [`Instant`] is the right clock for most timing, but on Linux
//! (`CLOCK_MONOTONIC`) and macOS (`CLOCK_UPTIME_RAW`) it stops while the
//! machine is suspended. A vault left unlocked before closing the lid would
//! then still be open the next morning, because only the minutes awake had
//! counted towards the idle lock. The wall clock ([`SystemTime`]) does keep
//! running through a suspend, but it can be changed or jump backwards.
//!
//! So a [`Mark`] records both, and the time elapsed is whichever clock says
//! *more*. Every caller is a security timeout, where firing early (after a
//! wall clock jumped forward) is harmless and firing late is not.

use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime};

/// Where the wall-clock time comes from. Tests replace it to fake a suspend.
pub type WallClock = Rc<dyn Fn() -> SystemTime>;

/// The real wall clock.
#[must_use]
pub fn system_wall_clock() -> WallClock {
    Rc::new(SystemTime::now)
}

/// A point in time, on both clocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mark {
    mono: Instant,
    wall: SystemTime,
}

impl Mark {
    #[must_use]
    pub fn new(mono: Instant, wall: SystemTime) -> Self {
        Self { mono, wall }
    }

    /// Time since this mark: the larger of what the two clocks measured. A
    /// wall clock set backwards counts as no time passing, not as negative.
    #[must_use]
    pub fn elapsed(&self, mono_now: Instant, wall_now: SystemTime) -> Duration {
        let mono = mono_now.saturating_duration_since(self.mono);
        let wall = wall_now.duration_since(self.wall).unwrap_or_default();
        mono.max(wall)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: Duration = Duration::from_secs(1);

    #[test]
    fn elapsed_takes_the_larger_clock() {
        let (mono, wall) = (Instant::now(), SystemTime::now());
        let mark = Mark::new(mono, wall);
        // Awake: both clocks agree.
        assert_eq!(mark.elapsed(mono + 5 * SEC, wall + 5 * SEC), 5 * SEC);
        // Suspended for an hour: only the wall clock moved.
        assert_eq!(mark.elapsed(mono + SEC, wall + 3600 * SEC), 3600 * SEC);
        // Wall clock set back: the monotonic clock still counts.
        assert_eq!(mark.elapsed(mono + 5 * SEC, wall - 3600 * SEC), 5 * SEC);
    }
}
