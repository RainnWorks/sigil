//! Terminal styling: one cobalt accent, three semantic colors, mono symbols.
//!
//! The palette is the design brief's "harbor at dusk": cobalt going to ink, a
//! brass dial, rust for denial. Colors are emitted as 24-bit ANSI only when the
//! stream is a real TTY and `NO_COLOR` is unset and `TERM` is not `dumb`;
//! otherwise every helper returns the plain string, so pipes and dumb terminals
//! get clean text.

use std::os::fd::RawFd;

type Rgb = (u8, u8, u8);

const COBALT: Rgb = (92, 166, 224);
const OK: Rgb = (126, 194, 128);
const BRASS: Rgb = (206, 170, 96);
const DENY: Rgb = (214, 106, 92);
const DIM: Rgb = (128, 136, 148);
const FAINT: Rgb = (92, 100, 112);

/// A styler bound to one output stream's color decision.
#[derive(Clone, Copy)]
pub struct Style {
    color: bool,
}

impl Style {
    /// Styler for stdout.
    pub fn stdout() -> Self {
        Self {
            color: color_enabled(libc::STDOUT_FILENO),
        }
    }

    /// Force color on or off. Used by tests and reserved for callers that know
    /// their stream (e.g. a future `--color=always`).
    #[cfg(test)]
    pub fn with_color(color: bool) -> Self {
        Self { color }
    }

    fn paint(self, rgb: Rgb, s: &str) -> String {
        if self.color {
            format!("\x1b[38;2;{};{};{}m{s}\x1b[0m", rgb.0, rgb.1, rgb.2)
        } else {
            s.to_string()
        }
    }

    pub fn cobalt(self, s: &str) -> String {
        self.paint(COBALT, s)
    }
    pub fn ok(self, s: &str) -> String {
        self.paint(OK, s)
    }
    pub fn brass(self, s: &str) -> String {
        self.paint(BRASS, s)
    }
    pub fn deny(self, s: &str) -> String {
        self.paint(DENY, s)
    }
    pub fn dim(self, s: &str) -> String {
        self.paint(DIM, s)
    }
    pub fn faint(self, s: &str) -> String {
        self.paint(FAINT, s)
    }
}

fn color_enabled(fd: RawFd) -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var_os("TERM").is_some_and(|t| t == "dumb") {
        return false;
    }
    // SAFETY: isatty is a pure query on a file descriptor with no memory effects.
    unsafe { libc::isatty(fd) == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_when_color_disabled() {
        let s = Style::with_color(false);
        assert_eq!(s.cobalt("armed"), "armed");
        assert_eq!(s.deny("down"), "down");
    }

    #[test]
    fn wraps_in_ansi_when_color_enabled() {
        let s = Style::with_color(true);
        let painted = s.ok("running");
        assert!(painted.starts_with("\x1b[38;2;"));
        assert!(painted.ends_with("\x1b[0m"));
        assert!(painted.contains("running"));
    }
}
