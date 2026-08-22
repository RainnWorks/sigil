//! One daemon per runtime directory, enforced by the kernel.
//!
//! The bug this closes, reproduced on Linux: start `sigil daemon` twice against
//! the same runtime dir and the second one does not refuse. It unlinks the
//! first's socket and binds its own name in place, leaving daemon one alive,
//! holding listeners nobody can reach, writing a clean log. `sigil status` then
//! reports `down` while a fully armed daemon is running. That is the "zombie
//! mode" `docs/design/agent-operated-sigil.md` section 3 describes, arrived at
//! from the other direction: not a daemon that lost its listeners, but a daemon
//! whose listeners were taken from it.
//!
//! On macOS launchd supplied the guard for free (a LaunchAgent label is a
//! singleton, and `kickstart` heals rather than duplicates). Nothing supplies it
//! on Linux, so a supervisor that restarts the daemon needs this to be true
//! before it can be safe: a respawn racing a still-dying predecessor must lose,
//! visibly, rather than produce two daemons.
//!
//! The mechanism is `flock(LOCK_EX | LOCK_NB)` on a file beside the sockets.
//! Reasons for flock over a pidfile-with-a-pid-check:
//!
//! - The kernel releases it on process exit, including `SIGKILL` and a panic.
//!   There is no stale-lock cleanup path to get wrong, which is exactly where
//!   hand-rolled pidfiles fail.
//! - It is not advisory between our own processes in any way that matters here:
//!   every party is Sigil, and every party takes the lock the same way.
//! - A pid file read-and-`kill(0)` check races: the pid can be recycled between
//!   the read and the decision.
//!
//! The pid is still WRITTEN into the file, but only so a human and the `up`
//! report can name the holder. It is never the thing that decides.
//!
//! Deliberate limit, stated because it changes what the guard means: `flock` is
//! per open-file-description, so it does NOT survive `exec` losing the fd, and
//! it is not a cross-filesystem or NFS-safe primitive. Both are fine here, since
//! the lock lives in a local per-user runtime dir and is held by the daemon
//! process for its whole life.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::io::AsRawFd as _;
use std::path::{Path, PathBuf};

/// The lock file's name inside the runtime dir.
pub const LOCK_FILE: &str = "daemon.lock";

/// A held single-instance lock. The lock lives as long as this value: dropping
/// it (or the process exiting, however it exits) releases it.
///
/// `#[must_use]` because binding it to `_` instead of a named variable would
/// drop it immediately and silently disarm the guard, which is a bug that
/// compiles and looks right.
#[must_use = "the lock is released as soon as this value is dropped; hold it for the daemon's life"]
#[derive(Debug)]
pub struct InstanceLock {
    /// Held open for the lifetime of the lock: closing this releases it.
    _file: File,
    path: PathBuf,
}

impl InstanceLock {
    /// The lock file this lock is held on.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Why an instance lock could not be taken.
#[derive(Debug)]
pub enum Taken {
    /// Another process holds it. `pid` is what that process recorded, when the
    /// file was readable and held a parseable pid; it is for the human, not for
    /// any decision this module makes.
    Busy { pid: Option<i32> },
    /// The lock file itself could not be opened or locked for some other
    /// reason (permissions, a read-only filesystem, a directory in the way).
    Io(std::io::Error),
}

impl std::fmt::Display for Taken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Taken::Busy { pid: Some(pid) } => {
                write!(f, "another sigil daemon is already running (pid {pid})")
            }
            Taken::Busy { pid: None } => write!(f, "another sigil daemon is already running"),
            Taken::Io(e) => write!(f, "cannot take the single-instance lock: {e}"),
        }
    }
}

impl std::error::Error for Taken {}

/// Take the exclusive single-instance lock at `path`, or report who holds it.
///
/// Non-blocking by design: a daemon that finds another daemon running must say
/// so and exit, not queue behind it. Waiting would turn a duplicate start into a
/// process that silently springs to life whenever the real daemon is restarted.
///
/// On success the caller's pid is written into the file. That write is
/// best-effort reporting: failing to record it does not fail the lock, because
/// the lock is what the kernel is enforcing and the pid is what the human reads.
pub fn acquire(path: &Path) -> Result<InstanceLock, Taken> {
    if let Some(dir) = path.parent() {
        if !dir.exists() {
            std::fs::create_dir_all(dir).map_err(Taken::Io)?;
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(Taken::Io)?;

    // SAFETY: `file` owns a valid open fd for the duration of this call.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            // EWOULDBLOCK (== EAGAIN on Linux and macOS) is the "somebody else
            // holds it" answer. Anything else is a real io failure.
            Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => Err(Taken::Busy {
                pid: read_pid(path),
            }),
            _ => Err(Taken::Io(err)),
        };
    }

    // We hold it. Record our pid for the report. Truncate first: a shorter pid
    // written over a longer one would otherwise leave trailing digits.
    let mut f = &file;
    let _ = f.set_len(0);
    let _ = std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(0));
    let _ = write!(f, "{}", std::process::id());
    let _ = f.flush();

    Ok(InstanceLock {
        _file: file,
        path: path.to_path_buf(),
    })
}

/// The pid recorded in the lock file, if it is readable and parses.
///
/// Reporting only. A pid here does NOT mean a daemon is running (the file
/// outlives the process that wrote it) and its absence does not mean one is not:
/// the lock, not this, is the source of truth.
pub fn read_pid(path: &Path) -> Option<i32> {
    let mut s = String::new();
    File::open(path).ok()?.read_to_string(&mut s).ok()?;
    s.trim().parse().ok()
}

/// Whether some process currently holds the lock at `path`.
///
/// Implemented by trying to take it and immediately releasing it, so the answer
/// comes from the kernel rather than from a pid heuristic. Inherently racy as a
/// question ("is it held?" can change the instant after it is answered), which
/// is why the daemon start path calls [`acquire`] and keeps what it gets rather
/// than asking this first. Use this only for reporting.
pub fn is_held(path: &Path) -> bool {
    matches!(acquire(path), Err(Taken::Busy { .. }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sigil-lock-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The core guarantee: the second holder is refused, and is told who has it.
    #[test]
    fn a_second_instance_is_refused_and_names_the_holder() {
        let dir = scratch("second");
        let path = dir.join(LOCK_FILE);

        let first = acquire(&path).expect("the first instance takes the lock");
        assert_eq!(first.path(), path.as_path());

        match acquire(&path) {
            Err(Taken::Busy { pid }) => assert_eq!(
                pid,
                Some(std::process::id() as i32),
                "the refusal must name the holder's pid"
            ),
            Err(Taken::Io(e)) => panic!("expected Busy, got io error: {e}"),
            Ok(_) => panic!("two instances took the same lock; the guard does not guard"),
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Releasing hands it to the next caller. This is what makes a supervisor's
    /// restart work: the replacement must be able to start once, and only once,
    /// the predecessor is really gone.
    #[test]
    fn releasing_the_lock_lets_the_next_instance_take_it() {
        let dir = scratch("release");
        let path = dir.join(LOCK_FILE);

        let first = acquire(&path).expect("first");
        assert!(is_held(&path), "held while the first instance lives");
        drop(first);

        assert!(!is_held(&path), "released when the holder drops");
        let second = acquire(&path).expect("the successor takes it after release");
        drop(second);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A lock file left behind by a dead process is not a stale lock. This is
    /// the whole reason for flock over a pidfile: no cleanup path to get wrong,
    /// and no recycled-pid false positive. The file below carries a pid that is
    /// not ours and is not running; the lock must still be free.
    #[test]
    fn a_leftover_lock_file_from_a_dead_process_does_not_block_a_start() {
        let dir = scratch("stale");
        let path = dir.join(LOCK_FILE);
        // pid 0 is never a real process to kill(0); a pidfile implementation
        // would have to special-case it, and flock simply does not care.
        std::fs::write(&path, "999999999").unwrap();

        assert!(!is_held(&path), "an unlocked file is not a held lock");
        let lock = acquire(&path).expect("a leftover file must not block a start");
        assert_eq!(
            read_pid(&path),
            Some(std::process::id() as i32),
            "taking the lock rewrites the pid to the live holder"
        );
        drop(lock);

        std::fs::remove_dir_all(&dir).ok();
    }
}
