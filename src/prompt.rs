//! Terminal prompts for the CLI: hidden password entry and yes/no questions.
//!
//! On a real terminal, passwords are read in raw mode so nothing is echoed.
//! When stdin is not a terminal (a pipe, or the integration tests), each
//! answer is read as one line instead, which keeps the CLI scriptable.

use std::io::{self, IsTerminal, Write};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal;
use zeroize::Zeroizing;

/// Room reserved up front so typical passwords never make the `String`
/// reallocate (which would leave an un-wiped copy in freed memory).
const PASSWORD_CAPACITY: usize = 256;

/// Ask for a password without echoing it. Wiped from memory on drop.
///
/// # Errors
/// [`io::ErrorKind::Interrupted`] if the user presses Ctrl-C or Esc,
/// [`io::ErrorKind::UnexpectedEof`] if stdin closes, or any terminal error.
pub fn password(prompt: &str) -> io::Result<Zeroizing<String>> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    if io::stdin().is_terminal() {
        read_hidden()
    } else {
        read_line()
    }
}

/// Ask a yes/no question; anything but `y`/`yes` means no.
///
/// # Errors
/// Same as [`password`], except input is echoed.
pub fn confirm(question: &str) -> io::Result<bool> {
    eprint!("{question} [y/N] ");
    io::stderr().flush()?;
    let answer = read_line()?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// Read one line from stdin, without the trailing newline. Every answer
/// goes through the same unbuffered reader, so a piped password never sits
/// in std's stdin buffer (and answers stay in order).
fn read_line() -> io::Result<Zeroizing<String>> {
    lockery::hardening::read_stdin_line(PASSWORD_CAPACITY)
}

/// Read keystrokes in raw mode until Enter, echoing nothing.
fn read_hidden() -> io::Result<Zeroizing<String>> {
    /// Leaves raw mode again even on error or panic.
    struct RawMode;
    impl Drop for RawMode {
        fn drop(&mut self) {
            let _ = terminal::disable_raw_mode();
        }
    }

    terminal::enable_raw_mode()?;
    let guard = RawMode;

    let mut input = Zeroizing::new(String::with_capacity(PASSWORD_CAPACITY));
    let result = loop {
        let Event::Key(KeyEvent {
            code,
            modifiers,
            kind,
            ..
        }) = event::read()?
        else {
            continue;
        };
        // Windows reports key releases too; only act on presses.
        if kind != KeyEventKind::Press {
            continue;
        }
        match code {
            KeyCode::Enter => break Ok(()),
            KeyCode::Esc => break Err(io::ErrorKind::Interrupted),
            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                break Err(io::ErrorKind::Interrupted);
            }
            KeyCode::Backspace => {
                lockery::hardening::pop_char(&mut input);
            }
            KeyCode::Char(c) => lockery::hardening::push_char(&mut input, c),
            _ => {}
        }
    };

    drop(guard);
    eprintln!(); // the Enter key wasn't echoed either
    result
        .map(|()| input)
        .map_err(|kind| io::Error::new(kind, "cancelled"))
}
