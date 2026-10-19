//! The terminal user interface.
//!
//! * [`app`]: all state and behaviour (no terminal I/O).
//! * [`keymap`]: every key binding, which also drives the hints.
//! * [`ui`], [`views`], [`widgets`]: drawing, from read-only app state.
//! * [`search`]: fuzzy filtering of entries.
//!
//! [`run`] owns the terminal: it enters raw mode and the alternate screen,
//! and ratatui's panic hook puts the terminal back even if Lockery panics.

pub mod app;
pub mod keymap;
pub mod search;
mod theme;
mod ui;
mod views;
mod widgets;

#[cfg(test)]
mod tests;

use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event};
use ratatui::DefaultTerminal;

pub use app::{App, StatusKind, VaultTarget};

/// How often the loop wakes up without input, to run idle checks.
const TICK: Duration = Duration::from_millis(250);

/// Run the app in the terminal until the user quits.
///
/// # Errors
/// Any terminal I/O error. The terminal is restored either way.
pub fn run(app: &mut App) -> io::Result<()> {
    let mut terminal = ratatui::try_init()?;
    let result = event_loop(&mut terminal, app);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut DefaultTerminal, app: &mut App) -> io::Result<()> {
    while !app.should_quit() {
        terminal.draw(|frame| ui::render(app, frame))?;

        // Unlocking blocks for about a second (Argon2). The frame just drawn
        // shows "Unlocking…"; now do the work and redraw.
        if app.unlock_pending() {
            app.perform_unlock();
            continue;
        }

        if event::poll(TICK)?
            && let Event::Key(key) = event::read()?
        {
            app.on_key(key, Instant::now());
        }
        app.tick(Instant::now());
    }
    Ok(())
}
