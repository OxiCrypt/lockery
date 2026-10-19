# Lockery

A keyboard-driven password manager for the terminal, written in Rust.

## Why

I couldn't find a password manager that met all of the requirements below,
so I'm building one myself, with AI assistance.

## Requirements

| Requirement | Status |
|---|---|
| Configurable Argon2 parameters | ✅ Done |
| Choice of XChaCha20-Poly1305 or AES-256-GCM | ✅ Done |
| Backwards compatibility | ✅ Done |
| Full metadata encryption | ✅ Done |
| Crash safety | 🟡 Partly done |
| CSV import (Bitwarden, KeePassXC, Chrome, Firefox) and export (Bitwarden format) | ⏳ Planned |
| Notes in entries | 🟡 Partly done |
| Fully keyboard-based navigation, with key hints at the bottom of the screen | 🟡 Partly done |
| Random password and passphrase generation | ⏳ Planned |
| Clipboard auto-clearing | ⏳ Planned |
| Intuitive TUI-based interface | 🟡 Partly done |
| Named vaults alongside a primary vault | 🟡 Partly done |
| Passkey support | ⏳ After the first alpha |

How each finished one works:

- **Argon2:** the memory, iteration and thread costs are chosen per vault. They're limited to sane bounds, so a damaged or malicious file can't use up all your memory.
- **Ciphers:** each vault picks XChaCha20-Poly1305 or AES-256-GCM.
- **Backwards compatibility:** every vault file records its format version, and support for old versions is never removed. A test vault from each released version is kept in the repo, and the test suite checks it still opens.
- **Metadata encryption:** titles, usernames, URLs, notes, timestamps and even the number of entries are all encrypted. Only the encryption settings are visible, and they're tamper-proof. Vault contents are padded so a vault's size gives little away.
- **Crash safety:** saves are atomic, so the vault file is never half-written. A new save is checked to decrypt before it replaces the old file, a `.bak` copy of the previous version is kept, and two instances can't open the same vault at once. Every change is saved the moment it's made. If the vault file is ever damaged, Lockery restores it from the `.bak` copy and keeps the damaged file. The terminal is restored even if Lockery crashes. Still to come: clearing the clipboard on a crash (M6).
- **Partly done:**
  - Entries can hold multi-line notes, and the detail view shows them; editing comes in M4.
  - Named vaults work from the command line, and `V` or `Tab` switches between them in the app; renaming and deleting them come in M4.
  - Every screen so far is fully keyboard-driven, with a hint bar at the bottom and `?` for all keys; the editing screens come in M4.

## Status

Early development; not ready for real passwords yet. The terminal UI can unlock vaults, switch between them, and browse, search and view entries, but adding and editing entries comes in the next milestone.

See [ROADMAP.md](ROADMAP.md) for the full milestone plan and progress.

## Where vaults are stored

| Platform | Location |
|---|---|
| Linux | `~/.local/share/lockery/` |
| macOS | `~/Library/Application Support/lockery/` |
| Windows | `%APPDATA%\lockery\` |

## Usage

```sh
lockery init           # create your primary vault
lockery init work      # create a named vault
lockery list           # show your vaults
lockery                # open the app on the primary vault
lockery work           # open the app on a named vault
lockery --path FILE    # open the app on a vault file anywhere else
```

`lockery init` tunes Argon2 so unlocking takes about a second on your machine. Use `--cipher aes256gcm` to pick AES-256-GCM, or `--memory-mib`, `--iterations` and `--parallelism` to set Argon2 yourself.

## Building

```sh
cargo build --release
cargo test
```
