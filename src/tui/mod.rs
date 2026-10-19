//! The terminal user interface.
//!
//! * [`app`]: all state and behaviour (no terminal I/O).
//! * [`keymap`]: every key binding, which also drives the hints.
//! * [`ui`], [`views`], [`widgets`]: drawing, from read-only app state.
//! * [`search`]: fuzzy filtering of entries.
//!
//! [`run`] owns the terminal: it enters raw mode and the alternate screen,
//! and puts the terminal back (and clears the clipboard) however Lockery
//! stops: quitting, a termination signal or a panic.

pub mod app;
mod entry_form;
mod form;
mod generator;
pub mod keymap;
pub mod search;
mod settings;
mod theme;
mod transfer;
mod ui;
mod views;
mod widgets;

#[cfg(test)]
mod tests;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event};
use ratatui::DefaultTerminal;

pub use app::{App, StatusKind, VaultTarget};

use crate::clipboard::{self, Copied};

/// How often the loop wakes up without input, to run the clipboard timer
/// and idle checks.
const TICK: Duration = Duration::from_millis(250);

/// Run the app in the terminal until the user quits.
///
/// However the app ends (quitting, a termination signal, or a panic), the
/// terminal is restored and anything Lockery put on the clipboard is
/// cleared.
///
/// # Errors
/// Any terminal I/O error. The terminal is restored either way.
pub fn run(app: &mut App) -> io::Result<()> {
    // Installed before ratatui's own hook, which restores the terminal and
    // then calls this one.
    install_panic_hook(app.clipboard_handle());
    let stop = termination_flag()?;

    let mut terminal = ratatui::try_init()?;
    let result = event_loop(&mut terminal, app, &stop);
    ratatui::restore();
    app.clear_clipboard();
    result
}

/// On a panic, clear the clipboard (if it still holds our copy) before the
/// usual panic message is printed.
fn install_panic_hook(copied: Copied) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        clipboard::emergency_clear(&copied);
        previous(info);
    }));
}

/// A flag that SIGTERM, SIGHUP, SIGINT and SIGQUIT set, so the event loop
/// can stop cleanly instead of being killed with secrets on the clipboard.
/// (In raw mode Ctrl-C is an ordinary key press, so SIGINT only arrives
/// from outside, e.g. `kill -INT`.)
fn termination_flag() -> io::Result<Arc<AtomicBool>> {
    let flag = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    {
        use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
        for signal in [SIGTERM, SIGHUP, SIGINT, SIGQUIT] {
            signal_hook::flag::register(signal, Arc::clone(&flag))?;
        }
    }
    Ok(flag)
}

fn event_loop(terminal: &mut DefaultTerminal, app: &mut App, stop: &AtomicBool) -> io::Result<()> {
    while !app.should_quit() && !stop.load(Ordering::Relaxed) {
        terminal.draw(|frame| ui::render(app, frame))?;

        // Unlocking, creating or deleting a vault runs Argon2 for about a
        // second. The frame just drawn shows a "working" message; now do
        // the work and redraw.
        if app.has_pending() {
            app.run_pending();
            continue;
        }

        match event::poll(TICK) {
            Ok(true) => {
                if let Event::Key(key) = event::read()? {
                    app.on_key(key, Instant::now());
                }
            }
            Ok(false) => {}
            // A signal arrived while waiting; the loop condition handles it.
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
        app.tick(Instant::now());
    }
    Ok(())
}
