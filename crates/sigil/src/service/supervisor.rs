//! The non-Darwin supervision backend behind `sigil up`: a small supervisor
//! process that Sigil ships and `up` ensures.
//!
//! `docs/design/linux-lifecycle.md` decision 4 is the rationale and this is the
//! implementation. The short version: there is no `systemctl` on either side of
//! the target deployment (not in the container where the agents run, not on the
//! Unraid host), so there is no unit to register with. `up` ensures a process
//! instead, which is what the verb's contract says it does.
//!
//! The shape deliberately mirrors launchd's, so `up.rs` drives one seam rather
//! than two code paths:
//!
//! | launchd | here |
//! |---|---|
//! | `~/Library/LaunchAgents/works.rainn.sigil.plist` | `~/.sigil/supervisor.conf` |
//! | `launchctl bootstrap` | spawn `sigil daemon --supervise`, detached |
//! | `launchctl bootout` | `SIGTERM` the supervisor, then the daemon |
//! | `launchctl kickstart -k` | `SIGHUP` the supervisor |
//! | `launchctl print` succeeds | the supervisor holds its lock |
//! | unconditional `KeepAlive` | the respawn loop in [`supervise`] |
//!
//! The one thing launchd gives for free and this must earn is telling a
//! deliberate stop from a crash. launchd knows because a bootout unloads the
//! job; here the supervisor itself is the unit. `SIGTERM` to the supervisor
//! means stop (it terminates the daemon and exits, so nothing respawns it);
//! `SIGHUP` means cycle (terminate the daemon and start a fresh one, which is
//! how a refreshed binary takes effect). A daemon that exits on its own was not
//! asked to, and is restarted with a backoff.
//!
//! **This module is compiled on every platform and dispatched to only off
//! macOS**, for the same reason `launchd.rs` is compiled everywhere: everything
//! pure in here is unit-tested, and gating the module would silently delete
//! that coverage from whichever CI job is not the current platform.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::service::LABEL;
use crate::{instance, local, paths, service};

/// The supervisor's single-instance lock, beside the daemon's own in the
/// runtime dir. Same mechanism ([`instance`]), different file: the daemon is
/// one-per-box because of `daemon.lock`, and so is the supervisor.
pub const LOCK_FILE: &str = "supervisor.lock";

/// The definition format version. Bumped only when a reader written against an
/// older version could misread a newer file.
const DEFINITION_VERSION: u32 = 1;

/// Directories the supervised daemon searches for a real `op`, after the shim
/// dir. The macOS list plus Homebrew, minus the Apple-only entries.
///
/// This is pinned, not inherited, and that is a security property rather than
/// tidiness: `docs/security-claims.md` states that the daemon resolves the real
/// binary in its own trusted `PATH`, so a caller cannot steer what the daemon
/// spawns. Inheriting the `PATH` of whichever shell ran `sigil up` would hand
/// that back. A site whose `op` lives outside these directories names the file
/// itself — `sigil-config binary set op <absolute path>`, stored in
/// [`Config::binaries`](crate::config::Config::binaries) and honoured by
/// [`resolve_command`](crate::paths::resolve_command) — rather than widening
/// this list. Naming one file is narrower than adding a directory, which would
/// make everything later planted in that directory spawnable too.
///
/// This paragraph used to point at an `op_path` config setting that had never
/// been built, so the documented escape hatch did not exist and a site in
/// exactly this position — Tower, whose `op` lives on a NAS share — had no way
/// out at all. `binary set` is that setting, built.
const BASE_PATH_DIRS: &[&str] = &["/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/// Respawn backoff bounds. A daemon that dies instantly and repeatedly (a bad
/// binary, a port it cannot bind) must not become a fork bomb; one that dies
/// once must come back promptly.
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// How long a daemon must stay up before its predecessor's backoff is
/// forgotten. Without this, a daemon that crashes once a day would inherit the
/// escalated delay from a crash loop weeks earlier.
const HEALTHY_RUN: Duration = Duration::from_secs(60);

/// How long a `SIGTERM` has to take effect before `SIGKILL` follows. "Stop"
/// means stopped; a daemon that ignores the polite signal does not get a vote.
const STOP_GRACE: Duration = Duration::from_secs(5);

/// The supervisor's wait granularity. It polls rather than blocking in `wait()`
/// because a blocking wait cannot be interrupted (std retries `EINTR`
/// internally), and the escalation above needs to fire while a child is still
/// running. Five wakeups a second on an otherwise idle process is the price;
/// the alternative is a self-pipe, which is more machinery for the same answer.
const POLL: Duration = Duration::from_millis(200);

/// How long [`bootstrap`] waits for a freshly spawned supervisor to take its
/// lock before calling the start a failure.
const START_TIMEOUT: Duration = Duration::from_secs(5);

/// How long [`kickstart`] waits for the replacement daemon to appear, so a
/// caller that probes immediately does not meet the outgoing one.
const CYCLE_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// The definition: this backend's plist.
// ---------------------------------------------------------------------------

/// What the supervisor supervises. Rendered by `sigil up`, read by
/// `sigil daemon --supervise`.
///
/// It exists as a file rather than as arguments for the same reasons the plist
/// does: `up` can compare it byte for byte to decide whether anything changed,
/// and a human with no `launchctl print` equivalent can read what the supervisor
/// was told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    /// The install-stable binary, never a build checkout.
    pub program: PathBuf,
    /// Arguments to the program. Always `["daemon"]` today.
    pub args: Vec<String>,
    /// The `PATH` pinned into the daemon's environment.
    pub path: String,
    /// Where the daemon's stdout and stderr are appended.
    pub stdout: PathBuf,
    pub stderr: PathBuf,
}

/// Build the `PATH` value for the definition: the shim dir first, then the
/// standard tool locations, so anything the daemon spawns finds the shim ahead
/// of a real `op`.
fn definition_path_value(shim_dir: &Path) -> String {
    let mut parts = vec![shim_dir.display().to_string()];
    parts.extend(BASE_PATH_DIRS.iter().map(|s| s.to_string()));
    parts.join(":")
}

/// Render the definition for a daemon at `sigil_bin`. Pure and deterministic,
/// exactly like [`super::launchd::render_plist`]: `up` rewrites the file only
/// when the rendered bytes differ, so a no-op run must render identical bytes.
pub fn render_definition(sigil_bin: &Path, logs_dir: &Path, shim_dir: &Path) -> String {
    let out_log = logs_dir.join("daemon.out.log");
    let err_log = logs_dir.join("daemon.err.log");
    // No keystore variable is pinned, for the same reason the plist pins none:
    // the daemon and the CLI both default to the on-disk store with no
    // environment at all, and pinning one is how a supervised daemon and a plain
    // shell end up disagreeing about where the pairing lives. `SIGIL_HOME` is
    // likewise absent by design (`keystore.rs` records why).
    format!(
        "# Sigil supervision definition. Rendered by `sigil up`; do not edit by hand.\n\
         # Read by `sigil daemon --supervise`, which `sigil up` starts and stops.\n\
         version = {DEFINITION_VERSION}\n\
         label = {LABEL}\n\
         program = {program}\n\
         args = daemon\n\
         path = {path}\n\
         stdout = {out}\n\
         stderr = {err}\n",
        program = sigil_bin.display(),
        path = definition_path_value(shim_dir),
        out = out_log.display(),
        err = err_log.display(),
    )
}

impl Definition {
    /// Parse a rendered definition. Blank lines and `#` comments are skipped;
    /// unknown keys are ignored so an older supervisor can read a file that
    /// grew a field, which is the case the version number is NOT for.
    ///
    /// A version this build does not know is refused rather than guessed at: it
    /// means a newer `sigil up` wrote the file, and a security daemon started
    /// from a misread definition is worse than one that did not start.
    pub fn parse(body: &str) -> Result<Self, String> {
        let mut version: Option<u32> = None;
        let mut program: Option<PathBuf> = None;
        let mut args: Vec<String> = Vec::new();
        let mut path: Option<String> = None;
        let mut stdout: Option<PathBuf> = None;
        let mut stderr: Option<PathBuf> = None;

        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(format!("line is not `key = value`: {line}"));
            };
            let value = value.trim();
            match key.trim() {
                "version" => {
                    version = Some(
                        value
                            .parse()
                            .map_err(|_| format!("version is not a number: {value}"))?,
                    )
                }
                "program" => program = Some(PathBuf::from(value)),
                "args" => args = value.split_whitespace().map(str::to_string).collect(),
                "path" => path = Some(value.to_string()),
                "stdout" => stdout = Some(PathBuf::from(value)),
                "stderr" => stderr = Some(PathBuf::from(value)),
                _ => {}
            }
        }

        match version {
            Some(DEFINITION_VERSION) => {}
            Some(other) => {
                return Err(format!(
                    "definition version {other} was written by a newer sigil (this build knows {DEFINITION_VERSION}); run `sigil up` from the newer binary"
                ));
            }
            None => return Err("definition has no version".to_string()),
        }

        Ok(Self {
            program: program.ok_or("definition has no program")?,
            args: if args.is_empty() {
                vec!["daemon".to_string()]
            } else {
                args
            },
            path: path.ok_or("definition has no path")?,
            stdout: stdout.ok_or("definition has no stdout")?,
            stderr: stderr.ok_or("definition has no stderr")?,
        })
    }

    /// Read and parse the definition at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let body =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&body).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
    }
}

/// Where the definition lives: `~/.sigil/supervisor.conf`.
pub fn definition_path() -> Result<PathBuf> {
    paths::supervisor_definition().context("HOME is not set")
}

/// Write the definition for a daemon at `sigil_bin`, creating the logs dir.
/// Compares before writing so a no-op re-run does not touch the file. Returns
/// `(definition_path, changed)`. Does not start anything; that is [`bootstrap`].
pub fn install_definition_for(sigil_bin: &Path) -> Result<(PathBuf, bool)> {
    let logs = paths::logs_dir().context("HOME is not set")?;
    let shim_dir = paths::shim_bin_dir().context("HOME is not set")?;
    std::fs::create_dir_all(&logs).with_context(|| format!("creating {}", logs.display()))?;

    let def_path = definition_path()?;
    if let Some(dir) = def_path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let existing = std::fs::read_to_string(&def_path).ok();
    let body = render_definition(sigil_bin, &logs, &shim_dir);
    if existing.as_deref() == Some(body.as_str()) {
        return Ok((def_path, false));
    }
    std::fs::write(&def_path, body).with_context(|| format!("writing {}", def_path.display()))?;
    Ok((def_path, true))
}

// ---------------------------------------------------------------------------
// The control surface `up` drives.
// ---------------------------------------------------------------------------

/// The supervisor's lock path.
fn lock_path() -> PathBuf {
    local::runtime_dir().join(LOCK_FILE)
}

/// The daemon's own lock path (`instance::LOCK_FILE`).
fn daemon_lock_path() -> PathBuf {
    local::runtime_dir().join(instance::LOCK_FILE)
}

/// `~/.sigil/logs/supervisor.log`: the supervisor's own diagnostics, kept apart
/// from the daemon's stdout/stderr so a restart loop is readable.
fn supervisor_log() -> Option<PathBuf> {
    paths::logs_dir().map(|d| d.join("supervisor.log"))
}

/// Whether a supervisor is running, answered by the kernel: it holds its lock
/// for its whole life, and the lock is released however it exits.
///
/// The launchd counterpart is `launchctl print` succeeding. Like that one, this
/// says loaded, not healthy: a running supervisor can be watching a wedged
/// daemon, which is why `sigil up` also does a real control round trip.
pub fn is_loaded() -> bool {
    instance::is_held(&lock_path())
}

/// Start the supervisor from `definition`, detached, and wait (bounded) for it
/// to take its lock. Idempotent: an already-running supervisor is success.
pub fn bootstrap(definition: &Path) -> Result<()> {
    if is_loaded() {
        return Ok(());
    }
    let def = Definition::load(definition)?;
    let log = supervisor_log().context("HOME is not set")?;
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }

    let mut cmd = Command::new(&def.program);
    cmd.arg("daemon")
        .arg("--supervise")
        .arg("--definition")
        .arg(definition)
        .stdin(Stdio::null());
    match open_append(&log) {
        Ok(f) => {
            let dup = f
                .try_clone()
                .with_context(|| format!("duplicating {}", log.display()))?;
            cmd.stdout(Stdio::from(f)).stderr(Stdio::from(dup));
        }
        // A supervisor that cannot log is still better than no supervisor; the
        // failure it would otherwise cause is total, and the one it causes this
        // way is a missing log file.
        Err(_) => {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }
    }
    // SAFETY: `setsid` is async-signal-safe and is the only call made between
    // fork and exec. It puts the supervisor in its own session so it survives
    // the terminal that ran `sigil up` closing, and so a Ctrl-C there does not
    // reach it: the supervisor is meant to outlive the command that started it.
    // A failure means we are already a session leader, which is equally fine.
    unsafe {
        use std::os::unix::process::CommandExt as _;
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("starting the supervisor: {}", def.program.display()))?;

    // Returning Ok must mean "it is supervising", not "fork succeeded".
    let deadline = Instant::now() + START_TIMEOUT;
    while Instant::now() < deadline {
        if is_loaded() {
            return Ok(());
        }
        if let Ok(Some(status)) = child.try_wait() {
            bail!(
                "the supervisor exited immediately ({status}); see {}",
                log.display()
            );
        }
        std::thread::sleep(POLL);
    }
    bail!(
        "the supervisor did not start within {START_TIMEOUT:?}; see {}",
        log.display()
    )
}

/// Stop the supervisor and the daemon. The launchd counterpart is `bootout`.
///
/// Order matters: the supervisor first, because it is the thing that would
/// otherwise respawn the daemon a moment after it was stopped.
pub fn bootout() -> Result<()> {
    stop_holder(&lock_path(), "supervisor")?;
    // Then any daemon still holding its own lock. A daemon can be running
    // without this supervisor (started by hand, by a container restart policy,
    // or by a systemd unit a site added on a distro that has one), and `stop`
    // that leaves it running is not a stop.
    stop_holder(&daemon_lock_path(), "daemon")?;
    Ok(())
}

/// `SIGTERM` whoever holds `lock`, escalating to `SIGKILL`, and confirm it is
/// gone by watching the lock be released. The lock, not a `kill(0)` probe, is
/// the signal: the kernel drops it however the process exits, so a released
/// lock means really gone with no recycled-pid ambiguity.
fn stop_holder(lock: &Path, what: &str) -> Result<()> {
    if !instance::is_held(lock) {
        return Ok(());
    }
    let Some(pid) = instance::read_pid(lock) else {
        bail!(
            "the {what} holds {} but recorded no pid, so it cannot be stopped; kill it by hand",
            lock.display()
        );
    };
    signal(pid, libc::SIGTERM).with_context(|| format!("asking the {what} (pid {pid}) to stop"))?;
    if wait_for_release(lock, STOP_GRACE) {
        return Ok(());
    }
    signal(pid, libc::SIGKILL)
        .with_context(|| format!("forcing the {what} (pid {pid}) to stop"))?;
    if wait_for_release(lock, STOP_GRACE) {
        return Ok(());
    }
    bail!("the {what} (pid {pid}) is still running after SIGTERM and SIGKILL")
}

/// Restart the daemon in place. The launchd counterpart is `kickstart -k`.
///
/// A supervisor that is not running is started instead of signalled, which is
/// what makes this safe for `up` to call as a heal.
pub fn kickstart() -> Result<()> {
    let definition = definition_path()?;
    if !is_loaded() {
        return bootstrap(&definition);
    }
    let lock = lock_path();
    let Some(pid) = instance::read_pid(&lock) else {
        bail!(
            "a supervisor holds {} but recorded no pid, so it cannot be signalled",
            lock.display()
        );
    };
    let daemon_lock = daemon_lock_path();
    let before = instance::read_pid(&daemon_lock);
    signal(pid, libc::SIGHUP)
        .with_context(|| format!("asking the supervisor (pid {pid}) to restart the daemon"))?;

    // Best effort: wait for a daemon with a DIFFERENT pid to hold the lock, so a
    // caller that probes straight away does not get an answer from the outgoing
    // daemon and call the restart done. Not fatal on timeout, because the
    // caller's own health probe is the real signal and this is only about not
    // racing it.
    let deadline = Instant::now() + CYCLE_TIMEOUT;
    while Instant::now() < deadline {
        let now = instance::read_pid(&daemon_lock);
        if now.is_some() && now != before && instance::is_held(&daemon_lock) {
            return Ok(());
        }
        std::thread::sleep(POLL);
    }
    Ok(())
}

/// Whether `lock` became free within `within`.
fn wait_for_release(lock: &Path, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if !instance::is_held(lock) {
            return true;
        }
        std::thread::sleep(POLL);
    }
    !instance::is_held(lock)
}

/// `kill(2)`, with the errno turned into an error.
fn signal(pid: i32, sig: libc::c_int) -> std::io::Result<()> {
    // SAFETY: `kill` is a pure syscall wrapper; an invalid pid is reported
    // through errno rather than being undefined.
    if unsafe { libc::kill(pid, sig) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

// ---------------------------------------------------------------------------
// The supervisor process itself.
// ---------------------------------------------------------------------------

/// Set by the `SIGTERM`/`SIGINT` handler: a deliberate stop. The daemon is
/// terminated and NOT respawned.
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
/// Set by the `SIGHUP` handler: cycle the daemon now, with no backoff.
static CYCLE_REQUESTED: AtomicBool = AtomicBool::new(false);
/// The running daemon's pid, or 0. Read by the signal handlers.
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

/// Signal the daemon from inside a handler. Both operations here are
/// async-signal-safe: an atomic load, and `kill(2)`.
fn signal_child_from_handler() {
    let pid = CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: async-signal-safe, and the worst case of a stale pid is
        // bounded by the comment on the store in `supervise`.
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
}

extern "C" fn on_stop(_sig: libc::c_int) {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
    signal_child_from_handler();
}

extern "C" fn on_cycle(_sig: libc::c_int) {
    CYCLE_REQUESTED.store(true, Ordering::SeqCst);
    signal_child_from_handler();
}

/// Install the stop and cycle handlers.
fn install_signal_handlers() {
    // SAFETY: both handlers do nothing but store to an atomic and call `kill`,
    // which is the async-signal-safe subset. `signal(2)` under glibc gives BSD
    // semantics (the handler stays installed), which is what a long-lived
    // supervisor needs.
    unsafe {
        let stop = on_stop as extern "C" fn(libc::c_int) as libc::sighandler_t;
        let cycle = on_cycle as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGTERM, stop);
        libc::signal(libc::SIGINT, stop);
        libc::signal(libc::SIGHUP, cycle);
    }
}

/// The next backoff after a failed run: double it, capped.
fn next_backoff(current: Duration) -> Duration {
    std::cmp::min(current * 2, BACKOFF_MAX)
}

/// The value of `--definition` in `args`, if present.
fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            return it.next().map(String::as_str);
        }
        if let Some(rest) = a.strip_prefix(flag).and_then(|r| r.strip_prefix('=')) {
            return Some(rest);
        }
    }
    None
}

/// Run the supervisor. This is `sigil daemon --supervise`, the process
/// [`bootstrap`] starts; it is not a verb a human is meant to type, which is
/// why it is a flag on `daemon` rather than a new reserved verb.
pub fn run(args: &[String]) -> Result<()> {
    let definition = match flag_value(args, "--definition") {
        Some(p) => PathBuf::from(p),
        None => definition_path()?,
    };
    let def = Definition::load(&definition)?;

    // The lock lives beside the daemon's, so the runtime dir must be sound
    // before either is taken. Same check the daemon does, for the same reason.
    let dir = local::runtime_dir();
    local::ensure_private_runtime_dir(&dir).map_err(|e| anyhow::anyhow!(e))?;

    let lock = match instance::acquire(&dir.join(LOCK_FILE)) {
        Ok(lock) => lock,
        Err(instance::Taken::Busy { pid }) => {
            let who = pid.map(|p| format!(" (pid {p})")).unwrap_or_default();
            bail!("another sigil supervisor is already running{who}; not starting a second one");
        }
        Err(e) => bail!("{e}"),
    };

    install_signal_handlers();
    note(format!(
        "supervising {} (pid {}), definition {}",
        def.program.display(),
        std::process::id(),
        definition.display()
    ));

    let result = supervise(&def);
    drop(lock);
    result
}

/// The respawn loop: launchd's unconditional `KeepAlive`, plus the distinction
/// launchd gets from the job being unloaded.
fn supervise(def: &Definition) -> Result<()> {
    let mut backoff = BACKOFF_MIN;
    while !STOP_REQUESTED.load(Ordering::SeqCst) {
        CYCLE_REQUESTED.store(false, Ordering::SeqCst);
        let started = Instant::now();

        let mut child = match spawn_daemon(def) {
            Ok(child) => child,
            Err(e) => {
                // A binary that will not start at all is the crash loop the
                // backoff exists for: report every attempt, keep trying, and
                // do not spin.
                note(format!(
                    "cannot start the daemon: {e:#}; retrying in {backoff:?}"
                ));
                if !sleep_unless_stopped(backoff) {
                    break;
                }
                backoff = next_backoff(backoff);
                continue;
            }
        };

        let pid = child.id() as i32;
        CHILD_PID.store(pid, Ordering::SeqCst);
        // A stop that arrived between the loop condition and this store found
        // CHILD_PID still 0 and signalled nothing. Deliver it here rather than
        // supervising a daemon we have already been told to stop.
        if STOP_REQUESTED.load(Ordering::SeqCst) {
            let _ = signal(pid, libc::SIGTERM);
        }

        let status = await_exit(&mut child, pid).context("waiting for the daemon")?;
        // The pid could not have been recycled before now: we are its parent and
        // it stayed an unreaped zombie until the wait above returned. Clearing
        // immediately keeps the window in which a handler could signal a reused
        // pid down to these few instructions.
        CHILD_PID.store(0, Ordering::SeqCst);

        if STOP_REQUESTED.load(Ordering::SeqCst) {
            note(format!(
                "daemon {pid} exited ({status}); stopping, as asked"
            ));
            break;
        }
        if CYCLE_REQUESTED.swap(false, Ordering::SeqCst) {
            // Asked for, so not a failure: no backoff, and any escalation the
            // previous crashes earned is forgiven.
            note(format!(
                "daemon {pid} exited ({status}); restarting, as asked"
            ));
            backoff = BACKOFF_MIN;
            continue;
        }

        if started.elapsed() >= HEALTHY_RUN {
            backoff = BACKOFF_MIN;
        }
        note(format!(
            "daemon {pid} exited on its own ({status}) after {:?}; restarting in {backoff:?}",
            started.elapsed()
        ));
        if !sleep_unless_stopped(backoff) {
            break;
        }
        backoff = next_backoff(backoff);
    }

    // Belt and braces: every break above leaves the daemon already reaped, but a
    // stop must not depend on that reasoning staying true.
    let orphan = CHILD_PID.swap(0, Ordering::SeqCst);
    if orphan > 0 {
        let _ = signal(orphan, libc::SIGTERM);
    }
    note("supervisor stopped");
    Ok(())
}

/// Wait for the daemon to exit, escalating to `SIGKILL` if a requested stop or
/// cycle has not taken effect within [`STOP_GRACE`].
fn await_exit(child: &mut Child, pid: i32) -> std::io::Result<ExitStatus> {
    let mut escalate_at: Option<Instant> = None;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        let asked = STOP_REQUESTED.load(Ordering::SeqCst) || CYCLE_REQUESTED.load(Ordering::SeqCst);
        if asked {
            let now = Instant::now();
            match escalate_at {
                None => escalate_at = Some(now + STOP_GRACE),
                Some(at) if now >= at => {
                    let _ = signal(pid, libc::SIGKILL);
                    // Do not spin on kill: give the reap a moment before the
                    // next escalation would fire.
                    escalate_at = Some(now + STOP_GRACE);
                }
                _ => {}
            }
        }
        std::thread::sleep(POLL);
    }
}

/// Sleep for `d`, returning false if a stop was requested during it. A backoff
/// must not delay a stop by its own length.
fn sleep_unless_stopped(d: Duration) -> bool {
    let deadline = Instant::now() + d;
    while Instant::now() < deadline {
        if STOP_REQUESTED.load(Ordering::SeqCst) {
            return false;
        }
        std::thread::sleep(POLL.min(d));
    }
    !STOP_REQUESTED.load(Ordering::SeqCst)
}

/// Start one daemon with the definition's pinned environment and log files.
fn spawn_daemon(def: &Definition) -> Result<Child> {
    // Rotate BEFORE opening: the child inherits these descriptors for its whole
    // life, so a rotation afterwards would leave it writing into the file that
    // was rolled away. The daemon's own rotation call then finds a small file
    // and does nothing, which is the intended no-op.
    service::rotate_logs(service::LOG_ROTATE_BYTES);
    let out = open_append(&def.stdout)?;
    let err = open_append(&def.stderr)?;
    let mut cmd = Command::new(&def.program);
    cmd.args(&def.args)
        .env("PATH", &def.path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    cmd.spawn()
        .with_context(|| format!("spawning {} {}", def.program.display(), def.args.join(" ")))
}

/// Open `path` for appending, creating it and its directory.
fn open_append(path: &Path) -> Result<std::fs::File> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))
}

/// One line into the supervisor's own log (its stderr, which [`bootstrap`]
/// wires to `~/.sigil/logs/supervisor.log`). Timestamped in unix seconds to
/// keep a date formatter out of the single binary, matching `cli.rs`.
fn note(msg: impl AsRef<str>) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut err = std::io::stderr();
    let _ = writeln!(err, "[unix {secs}] sigil supervisor: {}", msg.as_ref());
    let _ = err.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> String {
        render_definition(
            Path::new("/home/tom/.sigil/bin/sigil"),
            Path::new("/home/tom/.sigil/logs"),
            Path::new("/home/tom/.sigil/bin"),
        )
    }

    #[test]
    fn a_definition_round_trips_and_names_the_stable_binary() {
        let def = Definition::parse(&sample()).expect("the rendered definition parses");
        assert_eq!(def.program, Path::new("/home/tom/.sigil/bin/sigil"));
        assert_eq!(def.args, vec!["daemon".to_string()]);
        assert_eq!(
            def.stdout,
            Path::new("/home/tom/.sigil/logs/daemon.out.log")
        );
        assert_eq!(
            def.stderr,
            Path::new("/home/tom/.sigil/logs/daemon.err.log")
        );
        // The shim dir must be the FIRST PATH entry so it wins over a real op,
        // exactly as the plist requires on macOS.
        assert!(
            def.path.starts_with("/home/tom/.sigil/bin:"),
            "shim dir first: {}",
            def.path
        );
        assert!(def.path.contains("/usr/bin"));
        // Apple-only directories have no business in a Linux PATH.
        assert!(!def.path.contains("/opt/homebrew"));
    }

    #[test]
    fn a_render_pins_no_keystore_and_no_sigil_home() {
        // The same trap the plist avoids: a daemon and a plain shell must not be
        // able to disagree about where the pairing lives.
        let body = sample();
        assert!(!body.contains("SIGIL_KEYSTORE"));
        assert!(!body.contains("SIGIL_DEV_KEYSTORE"));
        assert!(!body.contains("SIGIL_HOME"));
    }

    #[test]
    fn a_render_is_byte_stable_so_an_unchanged_up_run_rewrites_nothing() {
        // `install_definition_for` decides "changed" by comparing bytes. A
        // render that varied would rewrite the file, and `up` would then reload
        // the supervisor, on every single run.
        assert_eq!(sample(), sample());
    }

    #[test]
    fn a_definition_from_a_newer_sigil_is_refused_rather_than_guessed_at() {
        let newer = sample().replace(
            &format!("version = {DEFINITION_VERSION}"),
            &format!("version = {}", DEFINITION_VERSION + 1),
        );
        let err = Definition::parse(&newer).expect_err("an unknown version must not be run");
        assert!(err.contains("newer sigil"), "actionable reason: {err}");
    }

    #[test]
    fn an_incomplete_definition_names_what_is_missing() {
        let no_program: String = sample()
            .lines()
            .filter(|l| !l.starts_with("program"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            Definition::parse(&no_program).unwrap_err(),
            "definition has no program"
        );
        assert_eq!(
            Definition::parse("program = /x\npath = /y\nstdout = /o\nstderr = /e\n").unwrap_err(),
            "definition has no version"
        );
    }

    #[test]
    fn unknown_keys_are_ignored_but_malformed_lines_are_not() {
        let with_extra = format!("{}\nfuture_key = whatever\n", sample());
        assert!(Definition::parse(&with_extra).is_ok());
        let junk = format!("{}\nthis line has no equals sign\n", sample());
        assert!(Definition::parse(&junk).is_err());
    }

    #[test]
    fn the_respawn_backoff_doubles_and_is_capped() {
        // The fork-bomb guard: a daemon that dies instantly forever must reach a
        // ceiling, not a busy loop.
        let mut d = BACKOFF_MIN;
        for _ in 0..20 {
            d = next_backoff(d);
        }
        assert_eq!(d, BACKOFF_MAX);
        assert_eq!(next_backoff(BACKOFF_MIN), BACKOFF_MIN * 2);
        assert_eq!(next_backoff(BACKOFF_MAX), BACKOFF_MAX);
    }

    #[test]
    fn the_definition_flag_is_read_in_both_spellings() {
        let split: Vec<String> = ["--supervise", "--definition", "/tmp/d.conf"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(flag_value(&split, "--definition"), Some("/tmp/d.conf"));
        let joined: Vec<String> = ["--definition=/tmp/e.conf".to_string()].to_vec();
        assert_eq!(flag_value(&joined, "--definition"), Some("/tmp/e.conf"));
        let absent: Vec<String> = ["--supervise".to_string()].to_vec();
        assert_eq!(flag_value(&absent, "--definition"), None);
    }
}
