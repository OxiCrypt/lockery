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
| [M3: TUI core](#m3-tui-core) | ⏳ Next |
| [M4: Editing](#m4-editing) | ⏳ |
| [M5: Generators](#m5-generators) | ⏳ |
| [M6: Clipboard](#m6-clipboard) | ⏳ |
| [M7: CSV import and export](#m7-csv-import-and-export) | ⏳ |
| [M8: Settings](#m8-settings) | ⏳ |
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

⏳ Next

- [ ] App state machine: vault picker, unlock, list, detail, help (`src/tui/app.rs`)
- [ ] Single keymap table that drives both input handling and the footer hints (`src/tui/keymap.rs`)
- [ ] Footer hint bar showing the keys for the current screen (`src/tui/widgets/footer.rs`)
- [ ] `?` help overlay built from the same keymap
- [ ] Vault picker: list vaults; `Tab` from the unlock screen; `V` to switch vaults
- [ ] Unlock screen with masked password input
- [ ] Entry list with fuzzy search (`/`)
- [ ] Detail view with passwords masked; `Space` shows them
- [ ] Manual lock (`L`) and idle auto-lock
- [ ] Terminal restored on panic
- [ ] Screen snapshot tests (`insta` with ratatui's `TestBackend`) and a test that every key has a footer hint

## M4: Editing

⏳

- [ ] Add/edit form: `Tab`/`Shift-Tab` between fields, `Ctrl-s` to save, `Esc` to cancel
- [ ] Multi-line notes editor (`ratatui-textarea`)
- [ ] Custom fields and tags
- [ ] Confirmation before delete
- [ ] Rename and delete vaults from the picker (delete asks for the master password and the vault name)

## M5: Generators

⏳

- [ ] Password generator: length, character classes, option to leave out look-alike characters, at least one character from each chosen class (`src/gen/password.rs`)
- [ ] Passphrase generator from the EFF large wordlist: word count, separator, capitalisation (`src/gen/passphrase.rs`)
- [ ] Generator screen (`g`), and `Ctrl-g` to generate into the password field while editing
- [ ] Entropy estimate and zxcvbn strength meter
- [ ] Tests: lengths, that chosen classes appear, and an even spread of characters

## M6: Clipboard

⏳

- [ ] Copy username (`u`) and password (`c`) (`src/clipboard.rs`)
- [ ] Auto-clear after a configurable time (default 20 s), only if the clipboard still holds what Lockery copied
- [ ] Countdown in the footer
- [ ] Clipboard also cleared on lock, quit, panic, SIGTERM and SIGHUP
- [ ] Clipboard managers asked not to keep a history, where the OS supports it
- [ ] Manual test on Wayland, X11, macOS and Windows

## M7: CSV import and export

⏳

- [ ] Import format detected from the CSV's header row (`src/csv/import.rs`)
- [ ] Importers for Bitwarden, KeePassXC, Chrome and Firefox
- [ ] Preview screen with duplicates and warnings before anything is added
- [ ] `lockery import <csv> [--vault NAME]`
- [ ] Bitwarden-format export (`src/csv/export.rs`)
  - [ ] plaintext warning and master password asked again
  - [ ] file written with mode 0600 on unix
- [ ] Sample CSVs from each source; export → re-import round-trip test

## M8: Settings

⏳

- [ ] Change master password
- [ ] Change Argon2 settings, with calibration
- [ ] Switch cipher
- [ ] Each change re-encrypts and saves the vault

## M9: Hardening and alpha 0.1

⏳

- [ ] Core dumps disabled; `PR_SET_DUMPABLE` set to 0 on Linux
- [ ] Optional `mlock` of secret memory
- [ ] Review that every secret is wiped from memory
- [ ] `cargo audit` and `cargo deny check` clean
- [ ] README: threat model and EFF wordlist credit
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
