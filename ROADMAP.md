# Roadmap

Lockery is built in milestones. Each one is finished, tested and committed
before the next begins. The first alpha (0.1) ships after M9; passkeys
follow in M10.

**Legend:** ✅ done · 🚧 in progress · ⏳ not started

| Milestone | Status |
|---|---|
| [M0: Project skeleton](#m0-project-skeleton) | ✅ Done |
| [M1: Crypto, file format and storage](#m1-crypto-file-format-and-storage) | ✅ Done |
| [M2: Entry model, named vaults and CLI](#m2-entry-model-named-vaults-and-cli) | ✅ Done |
| [M3: TUI core](#m3-tui-core) | ✅ Done |
| [M4: Editing](#m4-editing) | ✅ Done |
| [M5: Generators](#m5-generators) | ✅ Done |
| [M6: Clipboard](#m6-clipboard) | ⏳ Next |
| [M7: CSV import and export](#m7-csv-import-and-export) | ✅ Done (ahead of M6) |
| [M8: Settings](#m8-settings) | ✅ Done (ahead of M6–M7) |
| [M9: Hardening and alpha 0.1](#m9-hardening-and-alpha-01) | ⏳ |
| [M10: Passkeys](#m10-passkeys-post-alpha) | ⏳ After alpha |

---

## M0: Project skeleton

✅ Done

- [x] Dependencies for every milestone up to M9
- [x] `clippy::pedantic` enabled; CI treats warnings as errors
- [x] Library/binary split (`src/lib.rs` holds the logic, `src/main.rs` is a thin CLI)
- [x] Error types (`src/error.rs`)
- [x] Config file loading with defaults (`src/config.rs`)
- [x] CLI definition (`src/cli.rs`)
- [x] `cargo-deny` config (`deny.toml`)
- [x] CI: format, clippy and tests on Linux, macOS and Windows; cargo-deny; a short fuzz run (`.github/workflows/ci.yml`)

## M1: Crypto, file format and storage

✅ Done

- [x] Argon2id with bounded, configurable memory, iterations and parallelism (`src/crypto/mod.rs`)
- [x] XChaCha20-Poly1305 and AES-256-GCM
- [x] Vault file format v1 (`src/vault/format.rs`)
  - [x] whole header authenticated, so the settings can't be tampered with
  - [x] everything except the encryption settings is encrypted
  - [x] contents padded to 4 KiB blocks
  - [x] out-of-range settings rejected before Argon2 runs
- [x] Crash-safe storage (`src/vault/storage.rs`)
  - [x] atomic replace
  - [x] new file decrypted and checked before it replaces the old one
  - [x] `.bak` copy of the previous version
  - [x] exclusive lock against a second instance
  - [x] cleanup of leftover temp files
- [x] Tests: random round-trips (proptest), tamper and truncation checks, a crash simulated after every save step
- [x] Committed v1 fixture vaults (`tests/fixtures/v1-*.lockery`)
- [x] Fuzz target for the header parser (`fuzz/`)

## M2: Entry model, named vaults and CLI

✅ Done

- [x] Entry model: logins and notes, with username, password, URLs, notes, tags, custom fields, TOTP secret and favourite (`src/vault/model.rs`)
- [x] Secrets wiped from memory on drop and hidden in debug output
- [x] Schema versioning for the vault's contents; a vault from a newer Lockery is refused (`src/vault/migrate.rs`)
- [x] Unlocked vault with add, update and delete, each saved before it takes effect (`src/vault/session.rs`)
- [x] Automatic recovery from `.bak` when the vault file is damaged
- [x] Vault names and per-platform locations; `LOCKERY_DATA_DIR` override (`src/paths.rs`)
- [x] Argon2 calibration to about 1 s per unlock (`src/crypto/calibrate.rs`)
- [x] Commands:
  - [x] `lockery init [NAME]` with `--cipher`, `--memory-mib`, `--iterations` and `--parallelism`
  - [x] `lockery list`
  - [x] `lockery [NAME]` and `lockery --path FILE`
- [x] Hidden password prompt; easy-to-guess passwords need confirmation (`src/prompt.rs`)
- [x] Schema-v1 fixture (`tests/fixtures/schema-v1.lockery`) and CLI tests (`tests/cli.rs`)

## M3: TUI core

✅ Done

- [x] App state machine: vault picker, unlock, list, search, detail, help; no terminal I/O, so it's fully testable (`src/tui/app.rs`)
- [x] Single keymap table that drives both input handling and the hints (`src/tui/keymap.rs`)
- [x] Footer hint bar for the current screen; hints that don't fit are dropped (`src/tui/widgets/footer.rs`)
- [x] `?` help overlay built from the same keymap (`src/tui/views/help.rs`)
- [x] Vault picker: `Tab` from the unlock screen, `V` from an open vault (locks it first)
- [x] Unlock screen: masked input, `Ctrl-r` to show it, "Unlocking…" while Argon2 runs
- [x] Entry list with fuzzy search (`/`) over title, username, URLs and tags, never secrets (`src/tui/search.rs`)
- [x] Detail view with secrets masked; `Space` shows them, and they're masked again whenever the entry is reopened
- [x] Manual lock (`L`) and idle auto-lock (`idle_lock_secs` in the config, default 5 min)
- [x] Terminal restored on exit and on panic
- [x] Tests (`src/tui/tests.rs`):
  - [x] behaviour driven through key presses
  - [x] `insta` snapshots of every screen (`src/tui/snapshots/`)
  - [x] keymap checks: no key bound twice in a mode, every key reaches its action, and letters stay typeable in text fields

## M4: Editing

✅ Done

- [x] Add (`n`) and edit (`e`) entries in a form (`src/tui/entry_form.rs`, `src/tui/views/edit.rs`)
  - [x] `Tab`/`Shift-Tab` between fields, `Ctrl-s` to save, `Esc` to cancel
  - [x] cancelling asks first if anything was changed
  - [x] a title is required
  - [x] login-only fields hide for secure notes; their values are kept
- [x] Shared form widget: text fields, toggles, choices, buttons (`src/tui/form.rs`)
  - [x] text is wiped from memory when the form closes, and secret fields keep no undo history
- [x] Multi-line notes and URLs (`ratatui-textarea`)
- [x] Custom fields (name, value, hidden) and comma-separated tags
- [x] Delete entries (`d`), with a y/n confirmation (`src/tui/widgets/confirm.rs`)
- [x] Vault management in the picker (`src/vault/manage.rs`, `src/tui/views/dialog.rs`):
  - [x] create (`n`): name, password twice, cipher; Argon2 calibrated; easy-to-guess passwords need a second Enter
  - [x] rename (`r`); warns if it was the primary vault
  - [x] delete (`d`): needs the master password and the vault name typed out; removes the backup and damaged copies too
- [x] `F1` opens help from text fields (where `?` must stay typeable); the footer always keeps room for the Help hint
- [x] Tests: form and entry-form units, editing and vault-management flows checked against the files on disk, snapshots of the new screens

## M5: Generators

✅ Done

- [x] Password generator: length 4–128, lowercase/uppercase/digits/symbols, option to avoid look-alikes (`0`/`O`, `1`/`l`/`I`, `|`), at least one character from each chosen kind (`src/generator/password.rs`)
  - [x] uniform: a draft missing a kind is redrawn rather than patched, so no character is favoured
- [x] Passphrase generator from the EFF large wordlist: 3–20 words, separator, capitalisation (`src/generator/passphrase.rs`)
  - [x] wordlist embedded byte-for-byte as EFF publishes it (`src/generator/eff_large_wordlist.txt`, SHA-256 `addd3553…996b903e`)
- [x] All randomness from the OS, picked by rejection sampling, so there's no modulo bias (`src/generator/mod.rs`)
- [x] Generator popup (`src/tui/generator.rs`, `src/tui/views/generator.rs`)
  - [x] `Ctrl-g` in the editor fills in the password field; `g` in the list or detail view starts a new entry with the value
  - [x] regenerates whenever an option changes; `Ctrl-g` for a fresh suggestion with the same options
  - [x] options start from the config's `[generator]` section and are remembered for the session
- [x] Entropy estimate and zxcvbn strength meter in the generator, plus live strength of the password field in the editor (`src/tui/widgets/strength.rs`)
- [x] Tests: lengths, every chosen kind present, only chosen kinds used, even spread of characters and words, wordlist integrity, the popup driven by keys and checked against the vault on disk

## M6: Clipboard

⏳

- [ ] Copy username (`u`) and password (`c`) (`src/clipboard.rs`)
- [ ] Auto-clear after a configurable time (default 20 s), only if the clipboard still holds what Lockery copied
- [ ] Countdown in the footer
- [ ] Clipboard also cleared on lock, quit, panic, SIGTERM and SIGHUP
- [ ] Clipboard managers asked not to keep a history, where the OS supports it
- [ ] Manual test on Wayland, X11, macOS and Windows

## M7: CSV import and export

✅ Done (built before M6)

- [x] Import format recognised from the CSV's header row; columns found by name, not position (`src/csv_io/import.rs`)
- [x] Importers:
  - [x] Bitwarden: folder → tag, `fields` → custom fields; cards and identities skipped with a warning
  - [x] KeePassXC: group path (minus `Root`) → tag, created/modified dates kept
  - [x] Chrome (and other Chromium browsers): title from `name`, or the URL's host
  - [x] Firefox: title from the URL's host; HTTP realm, form origin and GUID → custom fields; dates kept
  - [x] unknown extra columns become custom fields instead of being dropped
- [x] Duplicates (same type, title, username and password, or the same note) are found against the vault and within the file, and skipped unless you choose otherwise
- [x] Import preview (`i` from the list or detail view): format, counts, duplicates, warnings, and the list of entries, before anything is added (`src/tui/transfer.rs`, `src/tui/views/import_preview.rs`)
- [x] `lockery import <csv> [--vault NAME]`, with the same duplicate handling and a confirmation
- [x] Bitwarden-format export (`x`) (`src/csv_io/export.rs`)
  - [x] plaintext warning; master password asked again
  - [x] written with mode 0600 on unix; never overwrites an existing file
  - [x] anything Bitwarden's CSV can't hold (extra tags, hidden flags, multi-line field values) is reported
- [x] Every import and export reminds you the CSV is plaintext and should be deleted
- [x] Hand-written sample CSVs for each source, matching their documented columns (`tests/fixtures/csv/`, `tests/csv_import.rs`), an export → re-import round-trip test, and TUI and CLI tests against the vault on disk
- [ ] Test against real exports from each manager (the samples follow their documented formats, but aren't real exports)

## M8: Settings

✅ Done (built before M6 and M7)

- [x] Settings screen (`s` from the list or detail view): cipher, Argon2 memory/passes/lanes, new master password (`src/tui/settings.rs`, `src/tui/views/settings.rs`)
- [x] "Tune Argon2 for this machine" button, using the same calibration as `lockery init`
- [x] Every change needs the current master password, compared in constant time, so an unattended unlocked vault can't be taken over
- [x] Applying re-encrypts the vault with a fresh salt (`Vault::rekey` in `src/vault/session.rs`)
  - [x] then saves a second time, so the `.bak` copy is re-encrypted too and stops opening with an old, possibly leaked, password
  - [x] a wrong current password, or any failure before the first save, changes nothing
- [x] Same validation as vault creation: new passwords must match, and an easy-to-guess one needs a second Ctrl-s; Argon2 values stay within the allowed range
- [x] Tests: re-keying (password, Argon2, cipher, backup) at library level; the screen driven by keys and checked against the vault and backup on disk

## M9: Hardening and alpha 0.1

⏳

- [ ] Core dumps disabled; `PR_SET_DUMPABLE` set to 0 on Linux
- [ ] Optional `mlock` of secret memory
- [ ] Review that every secret is wiped from memory
- [ ] `cargo audit` and `cargo deny check` clean
- [ ] README: threat model (the EFF wordlist credit was added in M5)
- [ ] Tag `v0.1.0`

## M10: Passkeys (post-alpha)

⏳ After alpha

- [ ] `Passkey` entry kind: credential ID, relying party ID, user handle, P-256 key, sign count
- [ ] Passkey import/export via Bitwarden JSON
- [ ] Experiment: act as a passkey authenticator via `passkey-authenticator`. Getting browsers to talk to a terminal app is the hard part.

---

## Before you open a pull request

Run these and make sure they all pass:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo deny check
```

To fuzz the header parser (needs the nightly toolchain and `cargo-fuzz`):

```sh
mkdir -p fuzz/corpus/header_decode && cp tests/fixtures/*.lockery fuzz/corpus/header_decode/
cargo +nightly fuzz run header_decode -- -max_total_time=300 -max_len=8192
```

**Compatibility rule:** never regenerate a fixture in `tests/fixtures/` once its version has been released. A change to the file format or the entry schema needs a new version number, a new fixture and a migration. See the comments in `src/vault/format.rs` and `src/vault/migrate.rs`.
