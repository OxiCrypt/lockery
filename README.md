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
| Crash safety | ✅ Done |
| CSV import (Bitwarden, KeePassXC, Chrome, Firefox) and export (Bitwarden format) | ✅ Done |
| Notes in entries | ✅ Done |
| Fully keyboard-based navigation, with key hints at the bottom of the screen | ✅ Done |
| Random password and passphrase generation | ✅ Done |
| Clipboard auto-clearing | ✅ Done |
| Intuitive TUI-based interface | ✅ Done |
| Named vaults alongside a primary vault | ✅ Done |
| Memory and process hardening | ✅ Done |
| Passkey support | ⏳ After the first alpha |

How each finished one works:

- **Argon2:** the memory, iteration and thread costs are chosen per vault: tuned automatically when the vault is created, and changeable later in the settings screen (`s`). They're limited to sane bounds, so a damaged or malicious file can't use up all your memory.
- **Ciphers:** each vault uses XChaCha20-Poly1305 or AES-256-GCM, chosen when it's created and switchable in the settings screen. Changing the cipher, the Argon2 settings or the master password re-encrypts the vault and its backup, and always needs the current master password.
- **Backwards compatibility:** every vault file records its format version, and support for old versions is never removed. A test vault from each released version is kept in the repo, and the test suite checks it still opens.
- **Metadata encryption:** titles, usernames, URLs, notes, timestamps and even the number of entries are all encrypted. Only the encryption settings are visible, and they're tamper-proof. Vault contents are padded so a vault's size gives little away.
- **Crash safety:** saves are atomic, so the vault file is never half-written. A new save is checked to decrypt before it replaces the old file, a `.bak` copy of the previous version is kept, and two instances can't open the same vault at once. Every change is saved the moment it's made. If the vault file is ever damaged, Lockery restores it from the `.bak` copy and keeps the damaged file. Even if Lockery crashes or is killed, the terminal is restored and the clipboard cleared.
- **Notes:** every entry has a multi-line notes field, plus custom fields (which can be hidden like a password) and tags.
- **Named vaults:** keep as many vaults as you like next to your primary one. Each has its own master password and settings. Create, rename, delete and switch between them in the app, or use `lockery init <name>` and `lockery <name>`.
- **Keyboard navigation:** everything is done from the keyboard. The bar at the bottom shows the keys for the current screen, and `?` (or `F1` while typing) lists all of them. Every key binding lives in one table that also produces the hints, so the hints always match what the keys do.
- **Generators:** random passwords (length, character kinds, avoiding look-alikes such as 0/O) and passphrases from the EFF wordlist (word count, separator, capitals). `Ctrl-g` in the entry editor fills in the password; `g` in the list starts a new entry with one. Each comes with a strength meter and an entropy estimate, and all randomness comes from the operating system.
- **CSV:** import exports from Bitwarden, KeePassXC, Chrome (and other Chromium browsers) or Firefox with `i` in the app or `lockery import <file>`. You see what was found, which entries are already in the vault and any warnings before anything is added. Export everything in Bitwarden format with `x`; almost every password manager can import it. The file is plaintext, so the export asks for your master password again, is readable only by you, and never overwrites an existing file.
- **Clipboard:** `c` copies the password and `u` the username. The clipboard is cleared after 20 seconds (`clipboard_clear_secs` in the config), and whenever the vault locks or Lockery quits, but only if it still holds what Lockery put there, so your own copies are left alone. Copies ask clipboard managers not to keep them in their history.
- **Hardening:** Lockery can't leave a core dump behind, and on Linux other programs running as you can't attach a debugger to it or read its memory. The vault key and the decrypted vault are kept out of swap and wiped from memory once they're no longer needed. All memory is wiped as it's freed, so copies the libraries Lockery uses make of your secrets don't linger either. See the threat model below.

## Security and threat model

Lockery is an alpha. Its design hasn't been reviewed by anyone outside the project.

**What it protects against**

- **Someone with a copy of your vault file** (a stolen laptop, a backup, a synced folder). Without the master password, the file is useless: Argon2id makes guessing slow, and everything except the encryption settings is encrypted, including titles, usernames, URLs and the number of entries. The size is padded to 4 KiB steps.
- **Tampering with the file.** The whole header, Argon2 and cipher settings included, is authenticated. A changed file doesn't open, and settings outside the allowed range are rejected before Argon2 even runs.
- **Losing data in a crash** while saving, or two copies of Lockery saving at once. See *Crash safety* above.
- **Passwords left on the clipboard.** They're cleared after a timeout, on lock and on quit, and even when Lockery crashes or is killed by a signal.
- **Secrets leaking out of a running Lockery:**
  - core dumps are turned off at startup;
  - on Linux the process is marked non-dumpable (`PR_SET_DUMPABLE`), so other programs running as you can't `ptrace` it or read `/proc/<pid>/mem`;
  - the vault key and the decrypted vault are on memory pages locked out of swap (`mlock`, on by default, see below);
  - secrets are wiped from memory when they're no longer needed, including the values an edit replaces.
- **Copies of secrets left behind in freed memory.** Programs routinely free memory without clearing it, so old copies of a password can linger until that memory happens to be reused. Libraries do this all the time: the text editor as you type, cut and undo, the strength checker as it scores a password, the vault decoder as it reads your entries. Lockery replaces the memory allocator with one that wipes every block before it's freed, so these copies are gone the moment they're let go. Strings that grow are moved and the old copy wiped, never left in place. A test (on Linux) searches Lockery's own memory for a planted secret after each of these and finds nothing; without the wiping allocator it finds several copies. The cost is a few milliseconds per unlock.
- **An unattended unlocked vault.** It locks itself after 5 minutes idle (`idle_lock_secs`), and changing the master password or encryption settings, exporting, or deleting a vault all ask for the current master password again.

**What it doesn't protect against**

- **Malware, or anyone with root or administrator rights, on your computer.** It can read Lockery's memory or log your keystrokes. No password manager can defend against that.
- **A weak master password.** Argon2 slows guessing down; it can't stop it. Lockery warns you about easy-to-guess passwords, but lets you use one if you insist.
- **What you show on screen.** A revealed password is visible to anyone looking, and may stay in your terminal's scrollback, in `tmux`/`screen` history, or in a screen recording.
- **Clipboard managers that ignore the "don't keep this" hint**, and programs that read the clipboard during the seconds a password is on it.
- **Plaintext CSV files.** An export (or a file you import) holds every password in the clear. Delete it as soon as you're done with it.
- **Copies that are still in use.** Freed memory is wiped, but a few copies are held on purpose while Lockery runs:
  - the clipboard library's copy of what you copied, until it's cleared (it needs it to paste);
  - the text editor's cut buffer and undo history, until the form closes (secret fields keep no undo history);
  - what's on screen: the terminal library's screen buffers hold a revealed password until the screen is redrawn.

  The vault decoder also uses scratch space on the stack, which no allocator sees. Lockery overwrites that part of the stack after opening a vault, but that is best effort. Outside Lockery, the kernel and your terminal see everything you type and everything shown.

  Entry contents (as opposed to the key and the decrypted vault file) are many small allocations, and they are wiped but not locked against swap. Use encrypted swap, or none, if that matters to you.

**Per platform**

| | Linux | macOS | Windows |
|---|---|---|---|
| No core dumps | ✅ | ✅ | ❌ Windows Error Reporting can still write a crash dump |
| No same-user debugger or memory reads | ✅ | ❌ | ❌ |
| Key and decrypted vault kept out of swap | ✅ | ✅ | ❌ not yet |
| Secrets wiped from memory | ✅ | ✅ | ✅ |
| All freed memory wiped, including library copies | ✅ | ✅ | ✅ |

**Memory locking.** The amount of memory a program may lock is limited (`ulimit -l`, usually 8 MiB on Linux, which is plenty). If locking fails, Lockery warns you once and carries on without it. To turn it off:

```toml
# ~/.config/lockery/config.toml
[security]
lock_memory = false
```

## Status

Lockery 0.1 is the first alpha: vaults, entries, the generator, the clipboard, CSV import and export, settings and hardening are all in place. It's an alpha, so keep a copy of your passwords in your current manager for now.

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
lockery import FILE    # import a CSV export into the primary vault (--vault NAME for another)
```

`lockery init` tunes Argon2 so unlocking takes about a second on your machine. Use `--cipher aes256gcm` to pick AES-256-GCM, or `--memory-mib`, `--iterations` and `--parallelism` to set Argon2 yourself.

## Building

```sh
cargo build --release
cargo test
```

## Credits

Passphrases use the [EFF large wordlist](https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases) by the Electronic Frontier Foundation, licensed under [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/).
