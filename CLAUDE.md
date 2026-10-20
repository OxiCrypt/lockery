# CLAUDE.md

Guidance for AI assistants (and humans) working on Lockery: a keyboard-driven terminal password manager in Rust. See `README.md` for what it does and `ROADMAP.md` for milestone status.

## Commands

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings   # clippy::pedantic is on (Cargo.toml [lints])
cargo test
cargo deny check
cargo audit
INSTA_UPDATE=always cargo test --lib   # rewrite TUI snapshots after an intended UI change
```

Every change must pass all of the above on **stable and nightly** (`cargo +stable …`, `cargo +nightly …`).

Fuzzing (nightly + cargo-fuzz), seeded with the fixture vaults:

```sh
mkdir -p fuzz/corpus/header_decode && cp tests/fixtures/*.lockery fuzz/corpus/header_decode/
cargo +nightly fuzz run header_decode -- -max_total_time=300 -max_len=8192
```

Manual runs without touching real vaults: set `LOCKERY_DATA_DIR` (vault dir) and `LOCKERY_CONFIG` (config file) to throwaway paths, and use `lockery init --memory-mib 19 --iterations 1 --parallelism 1` for fast Argon2.

## Architecture

Library (`src/lib.rs`) holds all logic; `src/main.rs` is a thin CLI (`cli.rs`, `prompt.rs`). Bottom-up:

- `crypto/`: Argon2id (`KdfParams` with enforced bounds), XChaCha20-Poly1305 / AES-256-GCM, `VaultKey`, `keys_equal` (constant time), `calibrate.rs`.
- `vault/storage.rs`: crash-safe file I/O on opaque bytes: OS lock on `<vault>.lock`, temp file → fsync → re-read and verify → `.bak` copy → atomic rename → dir fsync.
- `vault/format.rs`: file format v1. The whole header is AEAD associated data, and the payload is padded to 4 KiB. `decode` dispatches on `format_version`.
- `vault/model.rs` + `vault/migrate.rs`: `Entry`/`VaultData` (zeroized on drop, redacted `Debug`), CBOR with a separate `schema_version`.
- `vault/session.rs`: `Vault`, an unlocked vault. Every change saves *before* it takes effect (`commit`). Also `rekey`, `verify_password`, and recovery from `.bak`.
- `vault/manage.rs`: rename/delete whole vaults. `paths.rs`: vault names and data dir. `config.rs`: TOML config.
- `generator/`: password/passphrase generators (embedded EFF wordlist), `random_below` (rejection sampling), `Strength` (zxcvbn).
- `csv_io/`: CSV import (Bitwarden, KeePassXC, Chrome, Firefox; columns matched by name) and Bitwarden-format export. Named `csv_io` to avoid clashing with the `csv` crate.
- `hardening.rs`: core dumps off / `PR_SET_DUMPABLE` (`harden_process`, first thing in `main`), and `SecretBuf`, the page-aligned, `mlock`ed, wiped-on-drop buffer for the key and decrypted payload (`[security] lock_memory`). `WipingAllocator` (installed in `main.rs`, so all freed heap memory is zeroed; `tests/wiping.rs` proves it by searching process memory), `scrub_stack`, `read_stdin_line`. The only module with `unsafe`.
- `clipboard.rs`: copy with timed clear (only if the clipboard still holds our copy), `FakeBackend` for tests, `emergency_clear` for panic/signal handlers.
- `tui/`: `app.rs` is all state and behaviour with **no terminal I/O** (testable). `keymap.rs` is the single table of key bindings that drives input, the footer and the help overlay. `ui.rs`/`views/`/`widgets/` only read state. `form.rs` is the shared form widget (text areas wiped on drop). `mod.rs::run` owns the terminal, the panic hook and signals.

Slow Argon2 work in the TUI (unlock, create/delete vault, rekey, export, calibrate) is queued as `Pending` and run after a frame showing a busy message (`has_pending`/`run_pending`).

## Rules that must not be broken

- **Backwards compatibility:** never regenerate a committed fixture in `tests/fixtures/` (`v1-*.lockery`, `schema-v1.lockery`) once its version is released. Never remove an old format reader or schema migration. A field rename/removal/meaning change needs a schema bump plus a migration step; new fields need `#[serde(default)]`. New KDF/cipher ids need a new format version. KDF minimums may only go down.
- **Secrets:** wrap plaintext/keys in `Zeroizing`, size buffers up front so they don't reallocate, never print secrets (keep `Debug` redacted), never search or log them. Anything that may hold a secret should be wiped when dropped.
- **Keys:** add bindings only in `tui/keymap.rs`. The keymap tests forbid binding a key twice in a mode, and forbid binding printable keys in text-entry modes. Check the 80-column footer test (`widgets/footer.rs`); use the `short` label when space is tight.
- **Unsafe** is `deny` at crate level; it is allowed only in `hardening.rs` (and `tests/hardening.rs`, which reads the limits back), each site opting in locally with a SAFETY comment.
- No `#[allow(clippy::…)]` without a comment saying why; prefer fixing the lint.

## Conventions

- Explanatory comments and docs on every module and public item (`# Errors` sections required by pedantic clippy). Match the existing tone: explain *why*, especially security and crash-safety reasoning.
- User-facing text: short, plain sentences; errors say what to do next.
- Tests live next to code (`#[cfg(test)] mod tests`). TUI behaviour is tested through `App::on_key` in `src/tui/tests.rs`, and changes are verified against the vault reopened from disk. Use `test_params()` (cheapest Argon2), `FakeBackend` for the clipboard, `NewVaultKdf::Fixed` instead of calibration, and `TimeZone::UTC` for stable snapshots. Never touch the real clipboard or the real data dir in tests.
- Review insta snapshot diffs by eye before accepting them.
- For a real end-to-end check, drive the release binary in a pseudo-terminal with `script -qfec "stty cols 80 rows 24; ./target/release/lockery" log` and keystrokes piped in. Then confirm via the CLI and check that typed passwords never appear in the log.

## Gotchas

- Give test runs a timeout (`timeout 400 cargo test …`): a hang is a bug, not something to wait out.
- Never use `pgrep -f`/`pkill -f` with a pattern that also appears in your own command line; it matches (and kills) the shell running it.
- Processes forked from multi-threaded test binaries inherit vault lock fds. That's why `.cargo/config.toml` sets `INSTA_WORKSPACE_ROOT`. Don't add code that forks in tests.
- `csv::Writer` with `buffer_capacity(0)` loops forever.
- Struct literals evaluate fields in order: compute values from a field (e.g. `config`) before moving it into the struct.
- `gen` is a reserved keyword in edition 2024 (hence `generator/`).

## Workflow

- Work milestone by milestone (`ROADMAP.md`). On finishing one: tick its checklist with file pointers, update the status table and the README requirement table and status, then commit.
- Commit only when asked. Commit messages: a short summary line, a bulleted body, then `Co-Authored-By` attribution.
- The maintainer works on Linux only (NixOS, fish shell, Wayland/Hyprland; no python3 or jq). Use shell tools that exist there, give fish-compatible commands, and explain macOS/Windows behaviour rather than asking about it. Lockery still targets Linux, macOS and Windows.
