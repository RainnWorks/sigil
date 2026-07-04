//! The secret-provider seam.
//!
//! The daemon's core is generic: "run this command with the approved credential
//! injected so the command resolves its own secrets." The SOURCE of secrets is
//! pluggable. 1Password (`op` plus a service-account token) is provider #1;
//! bitwarden, aws-vault, doppler, and a plain env-file are future fills of this
//! same trait. The approval protocol ([`latch_proto::request`]) and the approver
//! (phone / softphone) are provider-blind: they carry opaque references and a
//! display hint, never provider mechanics.
//!
//! ## The invariant that shapes the trait shape
//!
//! Secret VALUES never enter daemon memory (brief invariant #2). So [`run`] is
//! deliberately **not** `fetch(refs) -> secret bytes`: a signature that returned
//! resolved secrets would pull them into the daemon and break the invariant.
//! Instead a provider injects a CREDENTIAL (for `op`, the service-account token,
//! itself a credential and not a resolved secret) into the child's environment
//! and the child streams its resolved secrets straight to the caller's fds. So
//! `run` fetches *and delivers* the secrets — to the caller, never returning them
//! here — and reports only the child exit code. This is the honest realization
//! of "fetch the secrets"; see the report accompanying this change.
//!
//! [`run`]: SecretProvider::run

use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use latch_proto::{RequestKind, SecretRef};

use crate::paths;
use crate::secrets::{self, Token};

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// The provider's backing tool could not be found.
    #[error("provider tool not found")]
    NoTool,
    /// Probing what the credential can serve failed.
    #[error("probe failed: {0}")]
    Probe(String),
}

/// One command to run with a provider's credential injected. The secret VALUES
/// stream from the child to `stdout`/`stderr` (the caller's own fds passed over
/// the socket), so they never enter daemon memory.
pub struct ProviderRun<'a> {
    /// The argv the shim intercepted (argv[0] is the tool name, e.g. `op`).
    pub command: &'a [String],
    /// The caller's working directory, or empty to inherit the daemon's.
    pub cwd: &'a str,
    /// The decrypted credential to inject (for `op`, the SA token). A credential,
    /// not a resolved secret.
    pub credential: &'a Token,
    /// The caller's stdout, wired straight to the child.
    pub stdout: Option<OwnedFd>,
    /// The caller's stderr, wired straight to the child.
    pub stderr: Option<OwnedFd>,
}

/// A pluggable source of secrets. See the module docs for the memory invariant
/// that shapes it.
pub trait SecretProvider: Send + Sync {
    /// Stable provider id, surfaced in [`SecretRef::provider`], e.g. "1password".
    fn id(&self) -> &str;

    /// The display hint for a command. A hint only; it never selects mechanism.
    fn kind(&self, command: &[String]) -> RequestKind;

    /// Describe the secrets `command` will resolve, as provider-agnostic
    /// [`SecretRef`]s for the approval screen. This is where the provider's own
    /// reference syntax is parsed; the approver never does this.
    fn describe(&self, command: &[String]) -> Vec<SecretRef>;

    /// Run the command with the credential injected, streaming resolved secrets
    /// straight to the caller's fds. Returns the child exit code. Secret VALUES
    /// never return here (invariant #2). Fails closed to a non-zero code.
    fn run(&self, run: ProviderRun) -> i32;

    /// Enumerate what `credential` can serve (for `latch account add` setup).
    fn probe(&self, credential: &[u8]) -> Result<Vec<String>, ProviderError>;
}

/// Provider #1: 1Password via `op` and a service-account token.
///
/// It understands `op://…` references and injects the token so the `op` child
/// resolves and streams the secret itself (never through the daemon). The
/// read-single-field vs get-whole-item distinction is an `op` implementation
/// detail carried in the intercepted argv (`op read` vs `op item get`) and the
/// ref's `segments` (a field-level ref has a trailing field segment); it is
/// never a protocol [`RequestKind`].
#[derive(Debug, Default, Clone)]
pub struct OpProvider {
    /// Explicit `op` binary; falls back to PATH discovery when `None`. Tests
    /// point this at a fake `op`.
    op_path: Option<PathBuf>,
}

impl OpProvider {
    pub const ID: &'static str = "1password";

    /// Discover `op` on PATH at run time.
    pub fn new() -> Self {
        Self { op_path: None }
    }

    /// Use a fixed `op` binary (tests point this at a fake `op`).
    pub fn with_binary(op_path: PathBuf) -> Self {
        Self {
            op_path: Some(op_path),
        }
    }

    fn resolve(&self) -> Option<PathBuf> {
        self.op_path.clone().or_else(paths::find_real_op)
    }
}

impl SecretProvider for OpProvider {
    fn id(&self) -> &str {
        Self::ID
    }

    fn kind(&self, _command: &[String]) -> RequestKind {
        // Both `op read` and `op item get` are secret reads for display purposes;
        // the readout well renders the refs the same way.
        RequestKind::SecretRead
    }

    fn describe(&self, command: &[String]) -> Vec<SecretRef> {
        command.iter().filter_map(|arg| op_reference(arg)).collect()
    }

    fn run(&self, run: ProviderRun) -> i32 {
        let Some(real) = self.resolve() else {
            eprintln!("latch daemon: no real `op` found on PATH");
            return 127;
        };

        let mut cmd = Command::new(&real);
        cmd.args(run.command.iter().skip(1));
        if !run.cwd.is_empty() {
            cmd.current_dir(run.cwd);
        }
        // The service-account token is the only way `op` authenticates here. It
        // is ASCII; a non-UTF-8 token is a corrupt store and fails closed.
        match std::str::from_utf8(run.credential) {
            Ok(s) => {
                cmd.env("OP_SERVICE_ACCOUNT_TOKEN", s);
            }
            Err(_) => {
                eprintln!("latch daemon: token is not valid UTF-8");
                return 1;
            }
        }
        if let Some(fd) = run.stdout {
            cmd.stdout(Stdio::from(fd));
        }
        if let Some(fd) = run.stderr {
            cmd.stderr(Stdio::from(fd));
        }

        match cmd.status() {
            Ok(s) => s
                .code()
                .or_else(|| s.signal().map(|sig| 128 + sig))
                .unwrap_or(1),
            Err(e) => {
                eprintln!("latch daemon: spawning op failed: {e}");
                127
            }
        }
    }

    fn probe(&self, credential: &[u8]) -> Result<Vec<String>, ProviderError> {
        let op = self.resolve().ok_or(ProviderError::NoTool)?;
        secrets::probe_vaults(&op, credential).map_err(|e| ProviderError::Probe(e.to_string()))
    }
}

/// Parse one argv token into a [`SecretRef`] if it carries an `op://` reference.
///
/// 1Password references are `op://<vault>/<item>/<field>` (optionally
/// `op://<account>/<vault>/<item>[/<section>]/<field>`). We keep the raw
/// reference opaque and build display `segments` from its path; this is display
/// metadata only (no secret value), so a partial parse is acceptable.
fn op_reference(arg: &str) -> Option<SecretRef> {
    let start = arg.find("op://")?;
    let rest = &arg[start..];
    // Stop at whitespace: the reference is one token.
    let reference = rest.split_whitespace().next().unwrap_or(rest).to_string();
    let path = &reference["op://".len()..];
    let segments: Vec<String> = path
        .split('/')
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect();
    if segments.is_empty() {
        return None;
    }
    // The brightest label is the item where present (second segment), else the
    // last segment.
    let label = segments
        .get(1)
        .or_else(|| segments.last())
        .cloned()
        .unwrap_or_default();
    Some(SecretRef {
        provider: OpProvider::ID.to_string(),
        reference,
        segments,
        label,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_extracts_op_references_only() {
        let p = OpProvider::new();
        let refs = p.describe(&[
            "op".into(),
            "read".into(),
            "op://Engineering/.env/password".into(),
        ]);
        assert_eq!(refs.len(), 1);
        let r = &refs[0];
        assert_eq!(r.provider, "1password");
        assert_eq!(r.reference, "op://Engineering/.env/password");
        assert_eq!(r.segments, vec!["Engineering", ".env", "password"]);
        assert_eq!(r.label, ".env");
    }

    #[test]
    fn describe_is_empty_without_a_reference() {
        assert!(OpProvider::new()
            .describe(&["op".into(), "vault".into(), "list".into()])
            .is_empty());
    }

    #[test]
    fn kind_is_a_display_hint() {
        assert_eq!(
            OpProvider::new().kind(&["op".into(), "read".into()]),
            RequestKind::SecretRead
        );
    }

    #[test]
    fn run_streams_child_output_to_the_caller_fd() {
        use std::io::Read;
        use std::os::fd::{FromRawFd, OwnedFd, RawFd};
        use std::os::unix::fs::PermissionsExt;

        // A fake `op` that echoes its token env so we can prove injection.
        let dir = std::env::temp_dir().join(format!("latch-prov-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let op = dir.join("op");
        std::fs::write(
            &op,
            "#!/bin/sh\nprintf 'tok=%s' \"$OP_SERVICE_ACCOUNT_TOKEN\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mut fds = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (read_end, write_end) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };

        let provider = OpProvider::with_binary(op);
        let credential: Token = zeroize::Zeroizing::new(b"secret-token".to_vec());
        let code = provider.run(ProviderRun {
            command: &["op".into(), "read".into()],
            cwd: "",
            credential: &credential,
            stdout: Some(write_end),
            stderr: None,
        });
        assert_eq!(code, 0);

        let mut out = String::new();
        std::fs::File::from(read_end)
            .read_to_string(&mut out)
            .unwrap();
        assert_eq!(out, "tok=secret-token");
        std::fs::remove_dir_all(&dir).ok();
    }
}
