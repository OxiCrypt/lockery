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
| Notes in entries | ⏳ Planned |
| Fully keyboard-based navigation, with key hints at the bottom of the screen | ⏳ Planned |
| Random password and passphrase generation | ⏳ Planned |
| Clipboard auto-clearing | ⏳ Planned |
| Intuitive TUI-based interface | ⏳ Planned |
| Named vaults alongside a primary vault | ⏳ Planned |
| Passkey support | ⏳ After the first alpha |

How each finished one works:

- **Argon2:** the memory, iteration and thread costs are chosen per vault. They're limited to sane bounds, so a damaged or malicious file can't use up all your memory.
- **Ciphers:** each vault picks XChaCha20-Poly1305 or AES-256-GCM.
- **Backwards compatibility:** every vault file records its format version, and support for old versions is never removed. A test vault from each released version is kept in the repo, and the test suite checks it still opens.
- **Metadata encryption:** titles, usernames, URLs, notes, timestamps and even the number of entries are all encrypted. Only the encryption settings are visible, and they're tamper-proof. Vault contents are padded so a vault's size gives little away.
- **Crash safety:** saves are atomic, so the vault file is never half-written. A new save is checked to decrypt before it replaces the old file, a `.bak` copy of the previous version is kept, and two instances can't open the same vault at once. Still to come: restoring the terminal and clearing the clipboard when Lockery crashes.

## Status

Early development; there's no usable app yet. The encrypted file format and crash-safe storage are finished and tested. The vault itself and the terminal UI come next.

## Where vaults will be stored

| Platform | Location |
|---|---|
| Linux | `~/.local/share/lockery/` |
| macOS | `~/Library/Application Support/lockery/` |
| Windows | `%APPDATA%\lockery\` |

## Building

```sh
cargo build --release
cargo test
```
