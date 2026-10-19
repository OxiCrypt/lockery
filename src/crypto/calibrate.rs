//! Pick Argon2 parameters that take about a target time on this machine.
//!
//! Strategy:
//!
//! 1. Use up to 4 lanes (fewer on machines with fewer cores).
//! 2. Start from the default memory cost (256 MiB) with a single pass.
//! 3. If even that is slower than the target, halve the memory until it
//!    fits (but never below the minimum).
//! 4. Otherwise add passes. Run time is roughly `fixed + passes × per_pass`,
//!    where `fixed` (allocating and first touching the memory, starting
//!    threads) is a large part of a single pass. So we time 1 and 3 passes,
//!    take the difference to get `per_pass`, and solve for the target.
//!    (Timing only one pass and dividing overestimates the per-pass cost by
//!    a lot, and lands far below the target.)
//!
//! Memory is preferred over passes because it is what makes GPU and ASIC
//! cracking expensive; passes only add time.

use std::time::{Duration, Instant};

use super::{KdfParams, SALT_LEN, derive_key};
use crate::error::Result;

/// The unlock time `lockery init` aims for by default.
pub const DEFAULT_TARGET: Duration = Duration::from_secs(1);

/// Most lanes calibration will choose.
const MAX_LANES: u32 = 4;

/// Measure this machine and return parameters that take roughly `target`.
///
/// Runs Argon2 a few times, so it takes a small multiple of `target`.
///
/// # Errors
/// Any error from [`derive_key`] while measuring.
pub fn calibrate(target: Duration) -> Result<KdfParams> {
    let lanes = std::thread::available_parallelism()
        .map_or(1, |n| u32::try_from(n.get()).unwrap_or(MAX_LANES))
        .clamp(1, MAX_LANES);
    calibrate_with(target, KdfParams::DEFAULT.m_cost_kib(), lanes, time_once)
}

/// Time a single key derivation with `params`.
fn time_once(params: KdfParams) -> Result<Duration> {
    let start = Instant::now();
    derive_key(b"calibration", &[0u8; SALT_LEN], params)?;
    Ok(start.elapsed())
}

/// The calibration algorithm, with the timer injected so it can be tested
/// without actually running Argon2.
fn calibrate_with(
    target: Duration,
    start_m_cost_kib: u32,
    lanes: u32,
    mut measure: impl FnMut(KdfParams) -> Result<Duration>,
) -> Result<KdfParams> {
    let mut m_cost = start_m_cost_kib.max(KdfParams::MIN_M_COST_KIB);

    // Find a memory cost where one pass fits in the target.
    let one_pass = loop {
        let params = KdfParams::new(m_cost, 1, lanes)?;
        let elapsed = measure(params)?;
        if elapsed <= target || m_cost == KdfParams::MIN_M_COST_KIB {
            break elapsed;
        }
        m_cost = (m_cost / 2).max(KdfParams::MIN_M_COST_KIB);
    };

    if one_pass >= target {
        // Even the minimum memory with one pass uses up the whole budget.
        return KdfParams::new(m_cost, 1, lanes);
    }

    // Split the cost into a fixed part and a per-pass part, then spend the
    // remaining budget on passes.
    let three_passes = measure(KdfParams::new(m_cost, 3, lanes)?)?;
    let per_pass = three_passes.saturating_sub(one_pass) / 2;
    let fixed = one_pass.saturating_sub(per_pass);
    let passes = if per_pass.is_zero() {
        KdfParams::MAX_T_COST
    } else {
        let ratio = target.saturating_sub(fixed).as_secs_f64() / per_pass.as_secs_f64();
        // Saturating float-to-int cast; clamped to the valid range below.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let passes = ratio.floor() as u32;
        passes
    };
    KdfParams::new(
        m_cost,
        passes.clamp(KdfParams::MIN_T_COST, KdfParams::MAX_T_COST),
        lanes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake machine where a derivation costs `nanos_per_kib_pass` per KiB
    /// per pass.
    fn fake_machine(nanos_per_kib_pass: u64) -> impl FnMut(KdfParams) -> Result<Duration> {
        move |p| {
            Ok(Duration::from_nanos(
                u64::from(p.m_cost_kib()) * u64::from(p.t_cost()) * nanos_per_kib_pass,
            ))
        }
    }

    const DEFAULT_M: u32 = 256 * 1024;

    #[test]
    fn fast_machine_keeps_memory_and_adds_passes() {
        // 256 MiB, one pass = 262144 * 1000 ns ≈ 0.26 s → 3 passes in 1 s.
        let p = calibrate_with(DEFAULT_TARGET, DEFAULT_M, 4, fake_machine(1000)).unwrap();
        assert_eq!(p.m_cost_kib(), DEFAULT_M);
        assert_eq!(p.t_cost(), 3);
        assert_eq!(p.p_cost(), 4);
    }

    #[test]
    fn fixed_cost_is_not_counted_per_pass() {
        // Like a real machine: 200 ms to set up, then 25 ms per pass. Naive
        // `target / one_pass` would pick 4 passes (~0.3 s); the right answer
        // is (1000 - 200) / 25 = 32 passes.
        let machine =
            |p: KdfParams| Ok(Duration::from_millis(200) + Duration::from_millis(25) * p.t_cost());
        let p = calibrate_with(DEFAULT_TARGET, DEFAULT_M, 4, machine).unwrap();
        assert_eq!(p.m_cost_kib(), DEFAULT_M);
        assert_eq!(p.t_cost(), 32);
    }

    #[test]
    fn slow_machine_reduces_memory() {
        // One pass at 256 MiB ≈ 2.6 s → halve twice to 64 MiB (≈ 0.66 s).
        let p = calibrate_with(DEFAULT_TARGET, DEFAULT_M, 1, fake_machine(10_000)).unwrap();
        assert_eq!(p.m_cost_kib(), DEFAULT_M / 4);
        assert_eq!(p.t_cost(), 1);
    }

    #[test]
    fn very_slow_machine_stops_at_minimum() {
        let p = calibrate_with(DEFAULT_TARGET, DEFAULT_M, 1, fake_machine(10_000_000)).unwrap();
        assert_eq!(p.m_cost_kib(), KdfParams::MIN_M_COST_KIB);
        assert_eq!(p.t_cost(), 1);
    }

    #[test]
    fn instant_machine_caps_passes() {
        let p = calibrate_with(DEFAULT_TARGET, DEFAULT_M, 4, fake_machine(0)).unwrap();
        assert_eq!(p.t_cost(), KdfParams::MAX_T_COST);
    }

    #[test]
    fn real_calibration_with_tiny_target_is_valid() {
        // Exercises the real timer path: start at the minimum and aim low.
        let p = calibrate_with(Duration::from_millis(1), 0, 1, time_once).unwrap();
        assert_eq!(p.m_cost_kib(), KdfParams::MIN_M_COST_KIB);
        assert!(p.t_cost() >= 1);
    }
}
