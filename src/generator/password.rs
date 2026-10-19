//! Random passwords from chosen character classes.
//!
//! Every character is drawn uniformly from the union of the chosen classes.
//! To guarantee at least one character from each chosen class without
//! skewing the distribution, a password that misses a class is thrown away
//! and a new one drawn. The result is uniform over all passwords that
//! satisfy the rule.

use zeroize::Zeroizing;

use super::random_below;
use crate::config::GeneratorConfig;
use crate::error::{Error, Result};

pub const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
pub const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const DIGITS: &str = "0123456789";
/// Symbols accepted almost everywhere. Quotes, backslash, backtick and
/// space are left out because they so often break forms and shells.
pub const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
/// Characters easily confused with each other in many fonts.
pub const AMBIGUOUS: &str = "0Oo1lI|";

pub const MIN_LENGTH: u16 = 4;
pub const MAX_LENGTH: u16 = 128;

/// Give up after this many rejected drafts. Only reachable with absurd
/// settings; the expected number of tries is close to 1 for real ones.
const MAX_TRIES: u32 = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent toggles
pub struct PasswordOptions {
    pub length: u16,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl From<&GeneratorConfig> for PasswordOptions {
    fn from(c: &GeneratorConfig) -> Self {
        Self {
            length: c.password_length,
            lowercase: c.lowercase,
            uppercase: c.uppercase,
            digits: c.digits,
            symbols: c.symbols,
            exclude_ambiguous: c.exclude_ambiguous,
        }
    }
}

impl PasswordOptions {
    /// The chosen classes, with ambiguous characters removed if requested.
    fn classes(self) -> Vec<Vec<char>> {
        [
            (self.lowercase, LOWERCASE),
            (self.uppercase, UPPERCASE),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, chars)| {
            chars
                .chars()
                .filter(|c| !(self.exclude_ambiguous && AMBIGUOUS.contains(*c)))
                .collect()
        })
        .collect()
    }

    /// Number of distinct characters a password can contain.
    #[must_use]
    pub fn alphabet_size(&self) -> usize {
        self.classes().iter().map(Vec::len).sum()
    }

    /// Approximate entropy in bits: `length × log2(alphabet)`. (Requiring
    /// every class removes a tiny fraction of passwords, so the true value
    /// is very slightly lower.)
    #[must_use]
    pub fn entropy_bits(&self) -> f64 {
        let alphabet = self.alphabet_size();
        if alphabet == 0 {
            return 0.0;
        }
        f64::from(self.length) * super::log2_choices(alphabet)
    }
}

/// Generate a password. Wiped from memory when dropped.
///
/// # Errors
/// [`Error::Generator`] if no class is chosen or the length is out of
/// range, or [`Error::Rng`] if the OS random number generator fails.
pub fn generate_password(options: &PasswordOptions) -> Result<Zeroizing<String>> {
    let classes = options.classes();
    if classes.is_empty() {
        return Err(Error::Generator(
            "choose at least one kind of character".into(),
        ));
    }
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&options.length) {
        return Err(Error::Generator(format!(
            "length must be between {MIN_LENGTH} and {MAX_LENGTH}"
        )));
    }
    if usize::from(options.length) < classes.len() {
        return Err(Error::Generator(
            "length must be at least the number of character kinds".into(),
        ));
    }

    let alphabet: Vec<char> = classes.iter().flatten().copied().collect();
    let length = usize::from(options.length);
    for _ in 0..MAX_TRIES {
        // Sized up front: growing would leave unwiped copies behind.
        let mut draft = Zeroizing::new(String::with_capacity(length * 4));
        for _ in 0..length {
            draft.push(alphabet[random_below(alphabet.len())?]);
        }
        if classes
            .iter()
            .all(|class| draft.chars().any(|c| class.contains(&c)))
        {
            return Ok(draft);
        }
    }
    Err(Error::Generator(
        "couldn't satisfy the character rules".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_on(length: u16) -> PasswordOptions {
        PasswordOptions {
            length,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }

    #[test]
    fn has_the_requested_length_and_every_chosen_class() {
        for length in [MIN_LENGTH, 8, 24, MAX_LENGTH] {
            for _ in 0..50 {
                let pw = generate_password(&all_on(length)).unwrap();
                assert_eq!(pw.chars().count(), usize::from(length));
                for class in [LOWERCASE, UPPERCASE, DIGITS, SYMBOLS] {
                    assert!(
                        pw.chars().any(|c| class.contains(c)),
                        "{class} missing in {pw:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn only_chosen_classes_are_used() {
        let opts = PasswordOptions {
            uppercase: false,
            symbols: false,
            ..all_on(64)
        };
        for _ in 0..50 {
            let pw = generate_password(&opts).unwrap();
            assert!(
                pw.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "{pw:?}"
            );
        }
    }

    #[test]
    fn ambiguous_characters_can_be_excluded() {
        let opts = PasswordOptions {
            exclude_ambiguous: true,
            ..all_on(MAX_LENGTH)
        };
        for _ in 0..50 {
            let pw = generate_password(&opts).unwrap();
            assert!(!pw.chars().any(|c| AMBIGUOUS.contains(c)), "{pw:?}");
        }
        assert_eq!(
            opts.alphabet_size(),
            26 + 26 + 10 + SYMBOLS.len() - AMBIGUOUS.len()
        );
    }

    #[test]
    fn characters_are_evenly_spread() {
        // 20,000 digits: each of the 10 expects 2,000 (sigma ≈ 42).
        let opts = PasswordOptions {
            lowercase: false,
            uppercase: false,
            symbols: false,
            ..all_on(100)
        };
        let mut counts = [0u32; 10];
        for _ in 0..200 {
            for c in generate_password(&opts).unwrap().chars() {
                counts[c.to_digit(10).unwrap() as usize] += 1;
            }
        }
        for (digit, &n) in counts.iter().enumerate() {
            assert!(
                (1_700..2_300).contains(&n),
                "digit {digit} appeared {n} times"
            );
        }
    }

    #[test]
    fn bad_options_are_rejected() {
        let none = PasswordOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..all_on(16)
        };
        assert!(generate_password(&none).is_err());
        assert!(generate_password(&all_on(MIN_LENGTH - 1)).is_err());
        assert!(generate_password(&all_on(MAX_LENGTH + 1)).is_err());
    }

    #[test]
    fn entropy_matches_the_formula() {
        let opts = all_on(20);
        let expected = 20.0 * crate::generator::log2_choices(26 + 26 + 10 + SYMBOLS.len());
        assert!((opts.entropy_bits() - expected).abs() < 1e-9);
    }
}
