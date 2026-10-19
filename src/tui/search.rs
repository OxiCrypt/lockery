//! Fuzzy filtering of the entry list.
//!
//! Matches against an entry's title, username, URLs and tags; never against
//! passwords, notes or other secrets. With an empty query every entry is
//! shown, sorted by title (favourites first).

use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};

use crate::vault::Entry;

/// Holds the matcher's scratch buffers between searches.
pub struct Search {
    matcher: Matcher,
    buf: Vec<char>,
}

impl Default for Search {
    fn default() -> Self {
        Self {
            matcher: Matcher::new(Config::DEFAULT),
            buf: Vec::new(),
        }
    }
}

impl Search {
    /// Indices into `entries` matching `query`, best match first.
    pub fn filter(&mut self, entries: &[Entry], query: &str) -> Vec<usize> {
        let query = query.trim();
        if query.is_empty() {
            let mut all: Vec<usize> = (0..entries.len()).collect();
            all.sort_by_cached_key(|&i| {
                let e = &entries[i];
                (!e.favorite, e.title.to_lowercase())
            });
            return all;
        }

        // Smart case: lower-case queries match any case; a capital letter
        // makes the search case-sensitive.
        let pattern = Pattern::parse(query, CaseMatching::Smart, Normalization::Smart);
        let mut scored: Vec<(usize, u32)> = entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                let haystack = searchable_text(e);
                let score =
                    pattern.score(Utf32Str::new(&haystack, &mut self.buf), &mut self.matcher)?;
                Some((i, score))
            })
            .collect();
        // Highest score first; ties keep title order.
        scored.sort_by(|a, b| {
            b.1.cmp(&a.1).then_with(|| {
                entries[a.0]
                    .title
                    .to_lowercase()
                    .cmp(&entries[b.0].title.to_lowercase())
            })
        });
        scored.into_iter().map(|(i, _)| i).collect()
    }
}

/// The non-secret fields of `e`, joined into one string to match against.
fn searchable_text(e: &Entry) -> String {
    let mut text = String::new();
    text.push_str(&e.title);
    for part in std::iter::once(&e.username).chain(&e.urls).chain(&e.tags) {
        if !part.is_empty() {
            text.push(' ');
            text.push_str(part);
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::EntryKind;

    fn entry(title: &str, user: &str, url: &str) -> Entry {
        let mut e = Entry::new(EntryKind::Login, title);
        e.username = user.into();
        if !url.is_empty() {
            e.urls.push(url.into());
        }
        e.password = "zzz-secret".into();
        e
    }

    fn titles(entries: &[Entry], idx: &[usize]) -> Vec<String> {
        idx.iter().map(|&i| entries[i].title.clone()).collect()
    }

    #[test]
    fn empty_query_lists_everything_favourites_first() {
        let mut entries = vec![
            entry("beta", "", ""),
            entry("Alpha", "", ""),
            entry("zeta", "", ""),
        ];
        entries[2].favorite = true;
        let idx = Search::default().filter(&entries, "  ");
        assert_eq!(titles(&entries, &idx), ["zeta", "Alpha", "beta"]);
    }

    #[test]
    fn fuzzy_matches_title_username_and_url() {
        let entries = vec![
            entry("GitHub", "octocat", "https://github.com"),
            entry("Bank", "me", "https://bank.example"),
            entry("Mail", "alice", "imap.example.com"),
        ];
        let mut s = Search::default();
        assert_eq!(titles(&entries, &s.filter(&entries, "ghub")), ["GitHub"]);
        assert_eq!(titles(&entries, &s.filter(&entries, "octo")), ["GitHub"]);
        assert_eq!(titles(&entries, &s.filter(&entries, "imap")), ["Mail"]);
        assert_eq!(s.filter(&entries, "qqqq"), Vec::<usize>::new());
    }

    #[test]
    fn secrets_are_not_searchable() {
        let entries = vec![entry("Thing", "", "")];
        assert_eq!(
            Search::default().filter(&entries, "zzz-secret"),
            Vec::<usize>::new()
        );
    }
}
