//! CSV import and export in the TUI: the import preview, and file paths.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::csv_io::{self, CsvFormat};
use crate::vault::Entry;

/// A parsed CSV file, shown for review before anything is added.
pub struct ImportPreview {
    /// Where it was read from, for the reminder to delete it.
    pub source: PathBuf,
    pub format: CsvFormat,
    pub entries: Vec<Entry>,
    /// Parallel to `entries`: already in the vault (or earlier in the file).
    pub duplicates: Vec<bool>,
    pub warnings: Vec<String>,
    /// Import the duplicates too (off by default).
    pub include_duplicates: bool,
    /// First visible row of the entry list.
    pub scroll: usize,
}

impl ImportPreview {
    /// Read and parse `path`, comparing its entries with `existing`.
    ///
    /// # Errors
    /// A message to show if the file can't be read or isn't a supported CSV.
    pub fn load(path: &Path, existing: &[Entry]) -> Result<Self, String> {
        let bytes = Zeroizing::new(
            std::fs::read(path).map_err(|e| format!("Can't read {}: {e}", display_path(path)))?,
        );
        let imported = csv_io::parse(&bytes).map_err(|e| capitalise(&e.to_string()))?;
        let duplicates = csv_io::duplicate_flags(existing, &imported.entries);
        Ok(Self {
            source: path.to_path_buf(),
            format: imported.format,
            entries: imported.entries,
            duplicates,
            warnings: imported.warnings,
            include_duplicates: false,
            scroll: 0,
        })
    }

    #[must_use]
    pub fn duplicate_count(&self) -> usize {
        self.duplicates.iter().filter(|&&d| d).count()
    }

    /// Whether entry `i` will be imported with the current choice.
    #[must_use]
    pub fn will_import(&self, i: usize) -> bool {
        self.include_duplicates || !self.duplicates[i]
    }

    #[must_use]
    pub fn import_count(&self) -> usize {
        (0..self.entries.len())
            .filter(|&i| self.will_import(i))
            .count()
    }

    /// The entries to add, consuming the preview.
    #[must_use]
    pub fn into_entries(self) -> Vec<Entry> {
        let include = self.include_duplicates;
        self.entries
            .into_iter()
            .zip(self.duplicates)
            .filter_map(|(e, dup)| (include || !dup).then_some(e))
            .collect()
    }
}

fn home() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf())
}

/// A path as typed by the user, with a leading `~` meaning the home
/// directory.
#[must_use]
pub fn expand_path(input: &str) -> PathBuf {
    let input = input.trim();
    match (
        input
            .strip_prefix("~/")
            .or(if input == "~" { Some("") } else { None }),
        home(),
    ) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => PathBuf::from(input),
    }
}

/// `path`, with the home directory shown as `~`.
#[must_use]
pub fn display_path(path: &Path) -> String {
    match home().and_then(|h| path.strip_prefix(&h).ok().map(Path::to_path_buf)) {
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

/// Suggested export location for the vault at `vault_path`, e.g.
/// `~/lockery-work-export.csv`.
#[must_use]
pub fn default_export_path(vault_path: &Path) -> String {
    let stem = vault_path
        .file_stem()
        .map_or_else(|| "vault".to_owned(), |s| s.to_string_lossy().into_owned());
    format!("~/lockery-{stem}-export.csv")
}

fn capitalise(s: &str) -> String {
    let mut chars = s.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_expansion_round_trips() {
        let Some(home) = home() else { return };
        assert_eq!(expand_path("~/a/b.csv"), home.join("a/b.csv"));
        assert_eq!(expand_path(" /tmp/x.csv "), PathBuf::from("/tmp/x.csv"));
        assert_eq!(display_path(&home.join("a.csv")), "~/a.csv");
        assert_eq!(
            default_export_path(Path::new("/d/work.lockery")),
            "~/lockery-work-export.csv"
        );
    }
}
