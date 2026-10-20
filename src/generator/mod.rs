//! Random password and passphrase generation, plus strength estimates.
//!
//! All randomness comes straight from the operating system's CSPRNG, via
//! [`random_below`], which picks uniformly using rejection sampling (no
//! modulo bias).

pub mod passphrase;
pub mod password;

use crate::crypto::fill_random;
use crate::error::Result;

pub use passphrase::{PassphraseOptions, generate_passphrase};
pub use password::{PasswordOptions, generate_password};

/// A uniformly random number in `0..n`.
///
/// Draws 64-bit values and rejects the few at the top of the range that
/// would make some results more likely than others.
///
/// # Errors
/// [`crate::Error::Rng`] if the OS random number generator fails.
///
/// # Panics
/// If `n` is 0.
pub fn random_below(n: usize) -> Result<usize> {
    assert!(n > 0, "random_below(0)");
    let n = n as u64;
    // Largest multiple of n that fits: values at or above it are rejected.
    let zone = u64::MAX - (u64::MAX % n);
    loop {
        let mut bytes = [0u8; 8];
        fill_random(&mut bytes)?;
        let x = u64::from_le_bytes(bytes);
        if x < zone {
            // x % n < n, which came from a usize, so this always fits.
            #[allow(clippy::cast_possible_truncation)]
            return Ok((x % n) as usize);
        }
    }
}

/// `log2(n)` for a count of choices (a word list, an alphabet), converted
/// without a lossy cast. Counts here are tiny, far below `u32::MAX`.
#[must_use]
pub fn log2_choices(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX)).log2()
}

/// How hard a password looks to guess, from zxcvbn's pattern analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Strength {
    /// 0 (trivial) to 4 (very strong).
    pub score: u8,
}

impl Strength {
    /// zxcvbn gets slow on long inputs, and anything this long is strong
    /// anyway, so only a prefix is analysed.
    const MAX_ANALYSED: usize = 100;

    /// Estimate the strength of `password`. `user_inputs` are words that
    /// make a password weaker if it contains them (names, the site, ...).
    #[must_use]
    pub fn of(password: &str, user_inputs: &[&str]) -> Self {
        let end = password
            .char_indices()
            .nth(Self::MAX_ANALYSED)
            .map_or(password.len(), |(i, _)| i);
        let score = zxcvbn::zxcvbn(&password[..end], user_inputs).score();
        Self { score: score as u8 }
    }

    /// Too easy to guess for a master password (below "strong"): Lockery
    /// warns, and asks before using it.
    #[must_use]
    pub fn is_weak(self) -> bool {
        self.score < 3
    }

    /// e.g. "very strong".
    #[must_use]
    pub fn label(self) -> &'static str {
        match self.score {
            0 => "very weak",
            1 => "weak",
            2 => "fair",
            3 => "strong",
            _ => "very strong",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_below_stays_in_range_and_hits_everything() {
        let mut seen = [0u32; 7];
        for _ in 0..7_000 {
            seen[random_below(7).unwrap()] += 1;
        }
        // Each bucket expects 1000; 700..1300 is far outside 6 sigma of
        // noise (sigma ≈ 29), so this only fails for a real bias.
        for (value, &count) in seen.iter().enumerate() {
            assert!((700..1300).contains(&count), "{value} drawn {count} times");
        }
        assert_eq!(random_below(1).unwrap(), 0);
    }

    #[test]
    fn strength_labels_follow_scores() {
        assert!(Strength::of("password", &[]).score <= 1);
        assert_eq!(
            Strength::of("correct-horse-battery-staple-94!", &[]).score,
            4
        );
        assert_eq!(Strength { score: 2 }.label(), "fair");
        assert!(Strength { score: 2 }.is_weak() && !Strength { score: 3 }.is_weak());
        // Very long inputs are handled (and cheap).
        let long = "x".repeat(10_000);
        let _ = Strength::of(&long, &[]);
    }
}
