//! Who is on the other end of the control socket, as the kernel sees it.
//!
//! The keystore contract has verbs only the signed Sigil app may call: it hands
//! the daemon the material for a wrapped keystore, and it drives de-adoption. A
//! same-UID process can connect to the 0600 socket just as easily as the app
//! can, so "the app said so" has to mean something stronger than "something
//! connected and claimed to be the app".
//!
//! So the daemon reads the peer's pid off the socket (the kernel's answer, not
//! the client's claim, exactly as [`crate::lease::peer_pid`] does for gating),
//! then asks macOS's code-signing machinery what that pid actually is and
//! matches it against a requirement string. An unsigned binary, an ad-hoc-signed
//! one, a different team's binary, or a tampered bundle all fail.
//!
//! # What this does and does not prove
//!
//! It proves the connecting process is a live, validly signed binary from the
//! Sigil team. It does not prove that process is uncompromised at runtime: a
//! signed app can be debugged or injected into, and a same-UID attacker who can
//! do that to the app can do anything the app can. That is the same boundary the
//! rest of Sigil lives on, and the wrapped keystore's honest claim is about
//! offline copies, not a live compromised machine.
//!
//! The identity we ask about is the peer's **audit token**, not its pid. An audit
//! token names a specific process instance and is never reused, so the "was this
//! pid recycled onto a different process between the kernel telling us and us
//! asking?" window does not exist; a pid, by contrast, only narrows it. This is
//! Apple's documented way to identify the far end of a unix socket, and the
//! kernel hands us the token with the connection.
//!
//! On non-macOS builds there is no such machinery, so the gate refuses: the
//! wrapped keystore is a macOS feature and a platform that cannot verify the
//! caller must not accept material from it.

/// The code-signing requirement the keystore verbs demand of their caller.
///
/// `anchor apple generic` restricts to Apple's certificate chain (so a
/// self-signed or ad-hoc binary cannot satisfy it), and the leaf's OU is the
/// RainnWorks team identifier, so only binaries signed by this team's Developer
/// ID or App Store certificates match. The bundle identifier is deliberately NOT
/// pinned: the app has been renamed once already, and a rename must not silently
/// become a bypass or a lockout. The team is the identity that matters.
pub const SIGIL_APP_REQUIREMENT: &str =
    "anchor apple generic and certificate leaf[subject.OU] = \"53W966FBFP\"";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PeerCodeError {
    /// The peer is a real process but does not satisfy the requirement:
    /// unsigned, ad-hoc signed, another team, or tampered with.
    #[error("the calling process is not the signed Sigil app")]
    NotTheApp,
    /// The socket did not yield a peer pid at all.
    #[error("could not read the caller's process id from the socket")]
    NoPeer,
    /// The pid could not be resolved to a code object (it exited mid-check).
    #[error("the calling process could not be identified (did it exit?)")]
    Unidentifiable,
    /// The requirement string did not compile, or the API failed unexpectedly.
    /// Treated as a refusal: an unverifiable caller is not an authorized one.
    #[error("the code-identity check could not be performed")]
    CheckFailed,
    /// This platform has no code-identity machinery.
    #[error("code identity cannot be verified on this platform")]
    Unsupported,
}

#[cfg(target_os = "macos")]
extern "C" {
    fn sigil_peer_satisfies_requirement(
        pid: libc::c_int,
        requirement: *const libc::c_char,
    ) -> libc::c_int;

    fn sigil_audit_satisfies_requirement(
        token: *const libc::c_void,
        token_len: libc::size_t,
        requirement: *const libc::c_char,
    ) -> libc::c_int;

    fn sigil_guest_measure(
        pid: libc::c_int,
        out: *mut u8,
        out_len: libc::size_t,
        path_out: *mut libc::c_char,
        path_len: libc::size_t,
        adhoc_out: *mut libc::c_int,
    ) -> libc::c_int;
}

/// What the platform says about the image a live pid is running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestMeasure {
    /// The executable path of the running image, read off the same code object
    /// as the cdhash so the two cannot describe different processes.
    pub exe: std::path::PathBuf,
    /// The cdhash of the running image, as the platform reports it.
    pub cdhash: Vec<u8>,
    /// True when the signature has no signer (ad-hoc). Such a cdhash is a digest
    /// of the binary and nothing more, so a caller must not read it as a signing
    /// identity; see [`crate::lease::IdentityMeasure`].
    pub adhoc: bool,
}

/// Why the platform would not measure a pid. Carried rather than collapsed to
/// `None` because the daemon says this out loud: a human whose approvals came
/// back should be told which ancestor stopped being measurable and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestFailure {
    /// The pid does not resolve to a live code object: it exited, or its
    /// executable is gone from disk (a self-update that deleted the old binary
    /// under a running process lands here).
    NoLiveImage,
    /// The pid resolves, but the platform will not vouch for the image: the file
    /// at its path changed after it started (`-67034 errSecCSStaticCodeChanged`),
    /// or the signature is not one it will validate.
    ImageNotVouched,
    /// The image validated but reports no cdhash, or the code-identity machinery
    /// failed or is absent (every non-macOS build).
    NoIdentity,
}

impl GuestFailure {
    /// One clause, for a log line or a `sigil doctor` row. Never a status code.
    pub fn explain(self) -> &'static str {
        match self {
            GuestFailure::NoLiveImage => "its executable is gone or it has exited",
            GuestFailure::ImageNotVouched => "its executable changed after it started",
            GuestFailure::NoIdentity => "the platform reports no code identity for it",
        }
    }
}

/// Measure the image running as `pid`: what the platform calls the code the
/// kernel is executing, not what happens to sit at that process's path now.
///
/// An `Err` is the honest "could not measure", carrying which way it failed. The
/// refusal is the point. The cdhash in a signature is reported without any
/// validity check, so a caller who rewrites the file under a running process
/// gets the substituted binary's cdhash out of a static read; here the validity
/// check on the guest answers `-67034 errSecCSStaticCodeChanged` for exactly that
/// case (verified on this platform, both in-place overwrite and rename-over),
/// and this returns [`GuestFailure::ImageNotVouched`] rather than a chosen
/// identity.
///
/// This is a measurement, never an authorization. It answers "what is that pid
/// running", not "may it do anything"; the gate that authorizes is
/// [`require_sigil_app`], and it is a different question.
#[cfg(target_os = "macos")]
pub fn measure_guest(pid: i32) -> Result<GuestMeasure, GuestFailure> {
    use std::os::unix::ffi::OsStringExt;
    // A cdhash is 20 bytes today (a truncation of the CodeDirectory hash); the
    // buffer is oversized so a longer future hash returns a length rather than
    // -4. The path buffer matches the `proc_pidpath` one.
    let mut buf = [0u8; 64];
    let mut path = [0i8; 4096];
    let mut adhoc: libc::c_int = 0;
    // SAFETY: the shim writes at most `buf.len()` cdhash bytes into `buf` and a
    // NUL-terminated path of at most `path.len()` bytes into `path`, sets
    // `adhoc`, and returns the cdhash count or a negative code. All three
    // borrows outlive the call.
    let n = unsafe {
        sigil_guest_measure(
            pid,
            buf.as_mut_ptr(),
            buf.len(),
            path.as_mut_ptr(),
            path.len(),
            &mut adhoc,
        )
    };
    if n <= 0 {
        return Err(match n {
            -2 => GuestFailure::NoLiveImage,
            -5 => GuestFailure::ImageNotVouched,
            _ => GuestFailure::NoIdentity,
        });
    }
    let bytes: Vec<u8> = path
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    if bytes.is_empty() {
        return Err(GuestFailure::NoIdentity);
    }
    Ok(GuestMeasure {
        exe: std::path::PathBuf::from(std::ffi::OsString::from_vec(bytes)),
        cdhash: buf[..n as usize].to_vec(),
        adhoc: adhoc != 0,
    })
}

#[cfg(not(target_os = "macos"))]
pub fn measure_guest(_pid: i32) -> Result<GuestMeasure, GuestFailure> {
    Err(GuestFailure::NoIdentity)
}

/// The peer's `audit_token_t` (8 words) from a connected unix socket.
///
/// `LOCAL_PEERTOKEN` is the token counterpart of the `LOCAL_PEERPID` this
/// codebase already trusts for lease provenance: the kernel's answer about who
/// connected, which a client cannot influence.
#[cfg(target_os = "macos")]
pub fn peer_audit_token(fd: std::os::fd::RawFd) -> Option<[u8; 32]> {
    // <sys/un.h>: SOL_LOCAL = 0, LOCAL_PEERTOKEN = 0x006.
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERTOKEN: libc::c_int = 0x006;
    let mut token = [0u8; 32];
    let mut len = token.len() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `token`, which is
    // exactly that many bytes of owned storage.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            token.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0 && len as usize == token.len()).then_some(token)
}

/// Whether the process identified by `token` satisfies `requirement`.
#[cfg(target_os = "macos")]
pub fn audit_token_satisfies(token: &[u8; 32], requirement: &str) -> Result<(), PeerCodeError> {
    let Ok(c_req) = std::ffi::CString::new(requirement) else {
        return Err(PeerCodeError::CheckFailed);
    };
    // SAFETY: the shim reads `token_len` bytes from `token` and the
    // NUL-terminated requirement, performs Security.framework calls, and returns
    // a small int. Both borrows outlive the call.
    match unsafe {
        sigil_audit_satisfies_requirement(
            token.as_ptr() as *const libc::c_void,
            token.len(),
            c_req.as_ptr(),
        )
    } {
        0 => Ok(()),
        1 => Err(PeerCodeError::NotTheApp),
        -2 => Err(PeerCodeError::Unidentifiable),
        _ => Err(PeerCodeError::CheckFailed),
    }
}

/// Whether `pid` satisfies `requirement`. The raw check, split out so a test can
/// aim it at a requirement it can actually satisfy or fail deterministically.
#[cfg(target_os = "macos")]
pub fn pid_satisfies(pid: i32, requirement: &str) -> Result<(), PeerCodeError> {
    let Ok(c_req) = std::ffi::CString::new(requirement) else {
        return Err(PeerCodeError::CheckFailed);
    };
    // SAFETY: the shim reads the NUL-terminated requirement string and the pid,
    // performs Security.framework calls, and returns a small int. It borrows
    // nothing beyond the call and shares no Rust state.
    match unsafe { sigil_peer_satisfies_requirement(pid, c_req.as_ptr()) } {
        0 => Ok(()),
        1 => Err(PeerCodeError::NotTheApp),
        -2 => Err(PeerCodeError::Unidentifiable),
        _ => Err(PeerCodeError::CheckFailed),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn pid_satisfies(_pid: i32, _requirement: &str) -> Result<(), PeerCodeError> {
    Err(PeerCodeError::Unsupported)
}

/// The gate the keystore verbs use: the peer on `fd` must be the signed Sigil
/// app. Every failure is a refusal; there is no "could not tell, allow it".
///
/// Identity comes from the peer's audit token, so there is no pid-recycle window
/// to reason about. A socket that will not yield one is refused rather than
/// falling back to the pid: a weaker check that engages exactly when the stronger
/// one fails is a bypass with extra steps.
#[cfg(target_os = "macos")]
pub fn require_sigil_app(fd: std::os::fd::RawFd) -> Result<(), PeerCodeError> {
    let token = peer_audit_token(fd).ok_or(PeerCodeError::NoPeer)?;
    audit_token_satisfies(&token, SIGIL_APP_REQUIREMENT)
}

#[cfg(not(target_os = "macos"))]
pub fn require_sigil_app(_fd: std::os::fd::RawFd) -> Result<(), PeerCodeError> {
    Err(PeerCodeError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_requirement_names_the_team_and_pins_apples_anchor() {
        // Both halves matter. Without the anchor, a self-signed binary claiming
        // the same OU would pass; without the OU, any Apple-signed binary on the
        // machine would.
        assert!(SIGIL_APP_REQUIREMENT.contains("anchor apple generic"));
        assert!(SIGIL_APP_REQUIREMENT.contains("53W966FBFP"));
        // The bundle id is intentionally absent (a rename must not be a bypass
        // or a lockout).
        assert!(!SIGIL_APP_REQUIREMENT.contains("identifier"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn this_unsigned_test_binary_is_not_the_sigil_app() {
        // The negative half of the gate, and the one that can run headlessly: the
        // test binary is ad-hoc signed at best, so it must NOT satisfy a
        // requirement demanding Apple's anchor and our team. If this ever passes,
        // the gate is not gating.
        let me = std::process::id() as i32;
        assert_eq!(
            pid_satisfies(me, SIGIL_APP_REQUIREMENT),
            Err(PeerCodeError::NotTheApp),
            "an unsigned/ad-hoc binary must never satisfy the app requirement"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_requirement_this_process_does_satisfy_passes() {
        // Proves the plumbing actually evaluates requirements rather than always
        // refusing: every running process satisfies the always-true requirement,
        // so a pass here means pid resolution and evaluation both work, and the
        // refusal above is a real verdict rather than a broken call.
        let me = std::process::id() as i32;
        assert_eq!(
            pid_satisfies(me, "info [CFBundleIdentifier] exists or true"),
            Ok(())
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_malformed_requirement_refuses_rather_than_passing() {
        let me = std::process::id() as i32;
        assert_eq!(
            pid_satisfies(me, "this is not a requirement ((("),
            Err(PeerCodeError::CheckFailed)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_audit_token_path_refuses_this_unsigned_process() {
        // The gate as the daemon actually runs it, end to end over a real socket.
        // Both ends of a socketpair are this test binary, which is unsigned or
        // ad-hoc at best, so the peer must be refused. This is the same shape as
        // the adversary the gate exists for: a same-UID process that can open the
        // socket exactly as easily as the app can.
        use std::os::fd::AsRawFd;
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let token = peer_audit_token(a.as_raw_fd()).expect("a unix socket yields a peer token");
        assert_ne!(token, [0u8; 32], "the kernel filled the token");
        assert_eq!(
            audit_token_satisfies(&token, SIGIL_APP_REQUIREMENT),
            Err(PeerCodeError::NotTheApp)
        );
        assert_eq!(
            require_sigil_app(a.as_raw_fd()),
            Err(PeerCodeError::NotTheApp)
        );
        // And the plumbing evaluates rather than always refusing.
        assert_eq!(
            audit_token_satisfies(&token, "info [CFBundleIdentifier] exists or true"),
            Ok(())
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_socket_that_yields_no_token_is_refused_not_downgraded() {
        // A fd with no peer token (here: not a socket at all) must fail closed
        // rather than quietly falling back to the weaker pid check.
        let devnull = std::fs::File::open("/dev/null").unwrap();
        use std::os::fd::AsRawFd;
        assert!(peer_audit_token(devnull.as_raw_fd()).is_none());
        assert_eq!(
            require_sigil_app(devnull.as_raw_fd()),
            Err(PeerCodeError::NoPeer)
        );
    }

    /// A live child to measure, killed when the guard drops.
    #[cfg(target_os = "macos")]
    struct Running(std::process::Child);

    #[cfg(target_os = "macos")]
    impl Running {
        fn spawn(exe: &str) -> Self {
            let child = std::process::Command::new(exe)
                .arg("30")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn");
            // Give the child time to exec; before that it is still a fork of this
            // test binary and would measure as this binary.
            std::thread::sleep(std::time::Duration::from_millis(150));
            Self(child)
        }
        fn pid(&self) -> i32 {
            self.0.id() as i32
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_running_signed_binary_measures_as_itself_and_names_its_own_path() {
        // The measurement primitive behind the lease grant key, aimed at a LIVE
        // process rather than at a file. A platform binary has a real signature,
        // so it answers with a cdhash (20 bytes today) and reports its own
        // executable path from the same code object.
        let sleeper = Running::spawn("/bin/sleep");
        let m = measure_guest(sleeper.pid()).expect("a live signed binary measures");
        assert!(!m.cdhash.is_empty(), "a cdhash is not empty");
        assert!(!m.adhoc, "a platform binary is not ad-hoc signed");
        assert_eq!(
            m.exe,
            std::path::Path::new("/bin/sleep"),
            "the path comes off the same object as the measurement"
        );
        assert_eq!(
            measure_guest(sleeper.pid()).map(|m| m.cdhash),
            Ok(m.cdhash.clone()),
            "the same process measures the same way twice"
        );

        let other = Running::spawn("/usr/bin/yes");
        let m2 = measure_guest(other.pid()).expect("also signed");
        assert_ne!(m.cdhash, m2.cdhash, "two binaries, two cdhashes");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_ad_hoc_signature_is_reported_as_having_no_signer() {
        // This test binary is linker/ad-hoc signed: a signature with no signer.
        // It still has a cdhash, but the caller must be told it is ad-hoc so it
        // does not read it as a signing identity it does not have.
        let me = measure_guest(std::process::id() as i32).expect("this process measures");
        assert!(me.adhoc, "an ad-hoc signature must be reported as such");
        assert!(!me.cdhash.is_empty());
        assert_eq!(
            me.exe,
            std::env::current_exe().expect("current exe"),
            "and it names this binary"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_pid_that_is_not_a_live_process_measures_as_nothing() {
        // Fail closed: "cannot measure" is never a measurement, and the reason
        // is carried rather than collapsed, because the daemon reports it. pid 0
        // is not a resolvable guest, and neither is a pid that has exited.
        assert_eq!(measure_guest(0), Err(GuestFailure::NoLiveImage));
        let dead = {
            let sleeper = Running::spawn("/bin/sleep");
            sleeper.pid()
        };
        // Give the kill time to land before asking about the pid.
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(
            measure_guest(dead),
            Err(GuestFailure::NoLiveImage),
            "an exited pid measures as nothing"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_dead_pid_is_refused() {
        // pid 0 is not a resolvable guest; the point is that "cannot identify"
        // is a refusal, never a pass.
        assert!(pid_satisfies(0, SIGIL_APP_REQUIREMENT).is_err());
    }
}
