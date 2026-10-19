//! Diceware-style passphrases from the EFF large wordlist.
//!
//! The list (7,776 words, so 12.9 bits per word) is embedded verbatim from
//! <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt>, by the
//! Electronic Frontier Foundation, licensed CC BY 3.0 US. Each line is a
//! five-dice code, a tab, and the word; the codes are ignored here because
//! words are picked with the OS random number generator instead of dice.

use std::sync::LazyLock;

use zeroize::Zeroizing;

use super::random_below;
use crate::config::GeneratorConfig;
use crate::error::{Error, Result};

static WORDLIST_FILE: &str = include_str!("eff_large_wordlist.txt");

/// The words, parsed once.
static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    WORDLIST_FILE
        .lines()
        .filter_map(|line| line.split_once('\t').map(|(_, word)| word))
        .collect()
});

/// Number of words in the list.
pub const WORD_COUNT: usize = 7_776;

pub const MIN_WORDS: u8 = 3;
pub const MAX_WORDS: u8 = 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassphraseOptions {
    pub words: u8,
    pub separator: String,
    /// Capitalise the first letter of each word.
    pub capitalize: bool,
}

impl From<&GeneratorConfig> for PassphraseOptions {
    fn from(c: &GeneratorConfig) -> Self {
        Self {
            words: c.passphrase_words,
            separator: c.passphrase_separator.clone(),
            capitalize: c.passphrase_capitalize,
        }
    }
}

impl PassphraseOptions {
    /// Entropy in bits: `words × log2(7776)`. The separator and
    /// capitalisation are public choices, so they add nothing.
    #[must_use]
    pub fn entropy_bits(&self) -> f64 {
        f64::from(self.words) * super::log2_choices(WORD_COUNT)
    }
}

/// Generate a passphrase. Wiped from memory when dropped.
///
/// # Errors
/// [`Error::Generator`] if the word count is out of range, or
/// [`Error::Rng`] if the OS random number generator fails.
pub fn generate_passphrase(options: &PassphraseOptions) -> Result<Zeroizing<String>> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&options.words) {
        return Err(Error::Generator(format!(
            "use between {MIN_WORDS} and {MAX_WORDS} words"
        )));
    }
    let words = &*WORDS;
    // Longest word is 9 letters; sized up front so it never reallocates.
    let capacity = usize::from(options.words) * (9 + options.separator.len());
    let mut out = Zeroizing::new(String::with_capacity(capacity));
    for i in 0..options.words {
        if i > 0 {
            out.push_str(&options.separator);
        }
        let word = words[random_below(words.len())?];
        let mut chars = word.chars();
        if options.capitalize
            && let Some(first) = chars.next()
        {
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
        } else {
            out.push_str(word);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn wordlist_is_complete_and_clean() {
        assert_eq!(WORDS.len(), WORD_COUNT);
        let unique: HashSet<_> = WORDS.iter().collect();
        assert_eq!(unique.len(), WORD_COUNT, "no duplicates");
        assert!(
            WORDS
                .iter()
                .all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
        );
        assert!(
            WORDS.iter().all(|w| w.len() <= 9),
            "capacity estimate holds"
        );
        assert_eq!((WORDS[0], WORDS[WORD_COUNT - 1]), ("abacus", "zoom"));
    }

    #[test]
    fn has_the_requested_words_and_separator() {
        let opts = PassphraseOptions {
            words: 6,
            separator: "-".into(),
            capitalize: false,
        };
        let phrase = generate_passphrase(&opts).unwrap();
        // Some EFF words contain '-' themselves, so split on a separator
        // that can't appear in words instead.
        let opts = PassphraseOptions {
            separator: " ".into(),
            ..opts
        };
        let spaced = generate_passphrase(&opts).unwrap();
        let words: Vec<_> = spaced.split(' ').collect();
        assert_eq!(words.len(), 6);
        assert!(words.iter().all(|w| WORDS.contains(w)), "{spaced:?}");
        assert!(phrase.contains('-'));
    }

    #[test]
    fn capitalisation() {
        let opts = PassphraseOptions {
            words: 5,
            separator: ".".into(),
            capitalize: true,
        };
        let phrase = generate_passphrase(&opts).unwrap();
        for word in phrase.split('.') {
            assert!(
                word.starts_with(|c: char| c.is_ascii_uppercase()),
                "{phrase:?}"
            );
        }
    }

    #[test]
    fn words_are_spread_over_the_list() {
        // 4,000 words: if picks were stuck in part of the list, the first
        // and second halves would be lopsided (each expects 2,000, sigma 32).
        let opts = PassphraseOptions {
            words: 20,
            separator: " ".into(),
            capitalize: false,
        };
        let mut first_half = 0;
        for _ in 0..200 {
            for word in generate_passphrase(&opts).unwrap().split(' ') {
                let index = WORDS.iter().position(|w| *w == word).unwrap();
                first_half += usize::from(index < WORD_COUNT / 2);
            }
        }
        assert!(
            (1_800..2_200).contains(&first_half),
            "{first_half} of 4000 in the first half"
        );
    }

    #[test]
    fn word_count_is_checked_and_entropy_computed() {
        let opts = |words| PassphraseOptions {
            words,
            separator: "-".into(),
            capitalize: false,
        };
        assert!(generate_passphrase(&opts(MIN_WORDS - 1)).is_err());
        assert!(generate_passphrase(&opts(MAX_WORDS + 1)).is_err());
        assert!((opts(6).entropy_bits() - 77.548_875).abs() < 1e-3);
    }
}
