//! The secret-provider seam and its registry.
//!
//! The daemon's core is generic: "run this command with the approved environment
//! injected so the command resolves its own secrets." The SOURCE of secrets is
//! pluggable. 1Password (`op` plus a service-account token) is provider #1; a
//! plain **env-file** is provider #2, the reference impl that proves the seam is
//! real and not op-shaped. bitwarden, aws-vault, and doppler are future fills of
//! this same trait. The approval protocol ([`latch_proto::request`]) and the
//! approver (phone / softphone) are provider-blind: they carry opaque references
//! and a display hint, never provider mechanics.
//!
//! ## Two injection shapes, one invariant, honestly distinguished
//!
//! The brief invariant (#2) is "secret VALUES never enter daemon memory." Its
//! cleanest realization is the `op` shape: inject a **credential** (the SA token,
//! itself a credential and not a resolved secret) into the child's environment
//! and let the `op` child resolve and stream the actual secrets straight to the
//! caller's fds. The daemon then never touches a resolved secret value at all.
//!
//! A direct-injection provider ([`EnvFileProvider`]) cannot fully honor that,
//! because it *is* the source: it reads KEY=VALUE pairs and must place the actual
//! values into the child's environment. Those values therefore transit the daemon
//! process — but **only** as the spawn env map, for the moment of the spawn: they
//! are held in a [`Zeroizing`] buffer, never logged, and wiped on drop; the child
//! carries its own copy in its env. This is the honest, documented difference
//! from the `op` credential-injection path, and it is why leasing is disabled for
//! such providers (a lease would hold resolved values in RAM across its TTL). See
//! [`SecretProvider::needs_account`] and the daemon's fulfillment path.

use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

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
    /// This provider does not support probing (it holds no stored credential).
    #[error("provider does not support account probing")]
    Unsupported,
}

/// One command to run with a provider's environment injected. The provider wires
/// the child's `stdout`/`stderr` to the caller's own fds (passed over the
/// socket) and returns only the child exit code.
pub struct ProviderRun<'a> {
    /// The argv the integration forwarded (argv[0] is the command name).
    pub command: &'a [String],
    /// The caller's working directory, or empty to inherit the daemon's.
    pub cwd: &'a str,
    /// The decrypted account credential to inject, for providers that need one
    /// (`op`, the SA token). `None` for providers that source their own secrets
    /// ([`EnvFileProvider`]); see [`SecretProvider::needs_account`].
    pub credential: Option<&'a Token>,
    /// The provider-specific source string from the command config (the env-file
    /// path for [`EnvFileProvider`]). Empty when unused.
    pub source: &'a str,
    /// The caller's stdin, wired straight to the child so interactive tools
    /// (`op inject`, a prompt) read the caller's terminal. Like stdout/stderr it
    /// is an fd the daemon splices to the child and NEVER reads itself, so no
    /// input byte enters daemon memory (invariant #2 holds for input too).
    pub stdin: Option<OwnedFd>,
    /// The caller's stdout, wired straight to the child.
    pub stdout: Option<OwnedFd>,
    /// The caller's stderr, wired straight to the child.
    pub stderr: Option<OwnedFd>,
}

/// A pluggable source of secrets. See the module docs for the memory invariant
/// that shapes it and the two injection shapes it spans.
pub trait SecretProvider: Send + Sync {
    /// Stable provider id, surfaced in [`SecretRef::provider`], e.g. "1password".
    fn id(&self) -> &str;

    /// The display hint for a command. A hint only; it never selects mechanism.
    fn kind(&self, command: &[String]) -> RequestKind;

    /// Describe the secrets `command` will resolve, as provider-agnostic
    /// [`SecretRef`]s for the approval screen. `source` is the command config's
    /// provider source (e.g. the env-file path); providers that do not need it
    /// ignore it. This runs *before* approval, so it must never read secret
    /// values into memory.
    fn describe(&self, command: &[String], source: &str) -> Vec<SecretRef>;

    /// Whether the daemon must decrypt a stored account token for this provider
    /// (true for `op`) or the provider sources its own secrets (false for
    /// `env-file`). When false the daemon skips the account routing, the DEK
    /// unwrap, and leasing entirely.
    fn needs_account(&self) -> bool;

    /// Run the command with the environment injected, wiring resolved output to
    /// the caller's fds. Returns the child exit code. Fails closed to a non-zero
    /// code. Secret VALUES never return here.
    fn run(&self, run: ProviderRun) -> i32;

    /// Enumerate what a credential can serve (for `latch account add` setup).
    /// Providers with no stored credential return [`ProviderError::Unsupported`].
    fn probe(&self, credential: &[u8]) -> Result<Vec<String>, ProviderError>;
}

/// The id-keyed set of providers the daemon can dispatch to. A command's config
/// names its provider by id; the daemon looks it up here. 1Password and env-file
/// ship by default; the seam is what makes "add a provider" additive.
pub struct ProviderRegistry {
    providers: Vec<Box<dyn SecretProvider>>,
}

impl ProviderRegistry {
    /// The shipping registry: `op` (provider #1) plus the `env-file` reference
    /// provider (#2) that proves the abstraction with a distinct injection shape.
    pub fn with_defaults() -> Self {
        Self {
            providers: vec![Box::new(OpProvider::new()), Box::new(EnvFileProvider)],
        }
    }

    /// Build a registry from an explicit provider set (tests point `op` at a fake
    /// binary, or exercise a single provider in isolation).
    pub fn new(providers: Vec<Box<dyn SecretProvider>>) -> Self {
        Self { providers }
    }

    /// The provider with id `id`, if registered.
    pub fn get(&self, id: &str) -> Option<&dyn SecretProvider> {
        self.providers
            .iter()
            .find(|p| p.id() == id)
            .map(|b| b.as_ref())
    }

    /// The registered provider ids (for `latch config` guidance and diagnostics).
    pub fn ids(&self) -> Vec<&str> {
        self.providers.iter().map(|p| p.id()).collect()
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
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

    fn describe(&self, command: &[String], _source: &str) -> Vec<SecretRef> {
        command.iter().filter_map(|arg| op_reference(arg)).collect()
    }

    fn needs_account(&self) -> bool {
        true
    }

    fn run(&self, run: ProviderRun) -> i32 {
        let Some(real) = self.resolve() else {
            eprintln!("latch daemon: no real `op` found on PATH");
            return 127;
        };
        // The op provider always drives the `op` binary (argv[0] is expected to
        // be `op`), injecting the SA token so the child resolves its own secrets.
        let Some(credential) = run.credential else {
            eprintln!("latch daemon: the 1password provider requires an account credential");
            return 1;
        };

        let mut cmd = Command::new(&real);
        cmd.args(run.command.iter().skip(1));
        if !run.cwd.is_empty() {
            cmd.current_dir(run.cwd);
        }
        // The service-account token is the only way `op` authenticates here. It
        // is ASCII; a non-UTF-8 token is a corrupt store and fails closed.
        match std::str::from_utf8(credential) {
            Ok(s) => {
                cmd.env("OP_SERVICE_ACCOUNT_TOKEN", s);
            }
            Err(_) => {
                eprintln!("latch daemon: token is not valid UTF-8");
                return 1;
            }
        }
        if let Some(fd) = run.stdin {
            cmd.stdin(Stdio::from(fd));
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

/// Provider #2: an env-file / static provider that injects KEY=VALUE pairs
/// directly into the child's environment.
///
/// This is the direct-injection shape (see the module docs): the configured
/// `source` file's values are read *after approval*, placed into the spawned
/// child's env, and wiped from daemon memory when the spawn env map drops. It
/// proves the generic "inject env vars after approval, then run" path — distinct
/// from op's "inject a credential and let the tool resolve" path — and needs no
/// stored account credential, so it never touches the DEK.
#[derive(Debug, Default, Clone)]
pub struct EnvFileProvider;

impl EnvFileProvider {
    pub const ID: &'static str = "env-file";
}

impl SecretProvider for EnvFileProvider {
    fn id(&self) -> &str {
        Self::ID
    }

    fn kind(&self, _command: &[String]) -> RequestKind {
        RequestKind::SecretRead
    }

    fn describe(&self, _command: &[String], source: &str) -> Vec<SecretRef> {
        if source.is_empty() {
            return Vec::new();
        }
        // Display only, and deliberately *without* reading the file: naming the
        // source shows the approver where the env comes from without pulling any
        // secret value into memory before the decision is made.
        let label = std::path::Path::new(source)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(source)
            .to_string();
        vec![SecretRef {
            provider: Self::ID.to_string(),
            reference: source.to_string(),
            segments: vec![source.to_string()],
            label,
        }]
    }

    fn needs_account(&self) -> bool {
        false
    }

    fn run(&self, run: ProviderRun) -> i32 {
        if run.command.is_empty() {
            eprintln!("latch daemon: env-file provider got an empty command");
            return 1;
        }
        if run.source.is_empty() {
            eprintln!("latch daemon: env-file provider has no source file configured");
            return 1;
        }
        // Read the source into a Zeroizing buffer and parse it. The values live
        // only here and in the child's env map, both wiped/handed off at spawn.
        let contents = match std::fs::read(run.source) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(e) => {
                eprintln!("latch daemon: reading env file {}: {e}", run.source);
                return 1;
            }
        };
        let Some(vars) = parse_env_file(&contents) else {
            // Invalid UTF-8: fail closed rather than lossy-convert (a lossy
            // conversion would allocate a non-zeroized String holding the file's
            // secret bytes). No values are injected.
            eprintln!(
                "latch daemon: env file {} is not valid UTF-8; refusing to inject",
                run.source
            );
            return 1;
        };
        if vars.is_empty() {
            eprintln!(
                "latch daemon: env file {} defined no KEY=VALUE pairs",
                run.source
            );
        }

        // Resolve the real underlying binary (skipping our own shim alias) so a
        // command named like a shimmed tool still runs the true executable.
        let Some(real) = paths::find_real(&run.command[0]) else {
            eprintln!("latch daemon: no `{}` found on PATH to run", run.command[0]);
            return 127;
        };

        let mut cmd = Command::new(&real);
        cmd.args(run.command.iter().skip(1));
        if !run.cwd.is_empty() {
            cmd.current_dir(run.cwd);
        }
        for (k, v) in vars.iter() {
            cmd.env(k, v);
        }
        if let Some(fd) = run.stdin {
            cmd.stdin(Stdio::from(fd));
        }
        if let Some(fd) = run.stdout {
            cmd.stdout(Stdio::from(fd));
        }
        if let Some(fd) = run.stderr {
            cmd.stderr(Stdio::from(fd));
        }

        let code = match cmd.status() {
            Ok(s) => s
                .code()
                .or_else(|| s.signal().map(|sig| 128 + sig))
                .unwrap_or(1),
            Err(e) => {
                eprintln!("latch daemon: spawning {} failed: {e}", run.command[0]);
                127
            }
        };
        // `vars` is Zeroizing and is wiped when it drops below. `cmd`'s own env
        // map holds a second, un-wiped copy of each value (std's `Command` stores
        // env as plain `OsString` and does not zeroize): that copy is freed, not
        // scrubbed, when `cmd` drops here. This is the same std limitation as the
        // op SA-token copy (security-claims residual #3), bounded to the spawn.
        drop(vars);
        code
    }

    fn probe(&self, _credential: &[u8]) -> Result<Vec<String>, ProviderError> {
        Err(ProviderError::Unsupported)
    }
}

/// The parsed env-file: `(KEY, VALUE)` pairs where the key is a plain var name
/// and each value lives in a [`Zeroizing`] buffer; the whole vec is `Zeroizing`
/// so it is wiped when the map drops after the spawn.
type EnvVars = Zeroizing<Vec<(String, Zeroizing<String>)>>;

/// Parse a minimal `.env`: one `KEY=VALUE` per line, `#` comments and blank lines
/// skipped, an optional leading `export `, and optional matching single/double
/// quotes stripped from the value. The values land in a [`Zeroizing`] buffer so
/// they are wiped when the returned map drops. Deliberately small; it is not a
/// full dotenv parser (no interpolation), which keeps the injected surface exact.
///
/// Returns `None` on an **invalid-UTF-8** file: we borrow the bytes with
/// [`str::from_utf8`] (a slice into the caller's `Zeroizing` buffer, no
/// allocation) rather than `String::from_utf8_lossy`, which would allocate an
/// owned, non-zeroized `String` holding the file's secret bytes. A non-UTF-8 env
/// file therefore fails closed with no un-wiped copy ever created.
fn parse_env_file(contents: &[u8]) -> Option<EnvVars> {
    let text = std::str::from_utf8(contents).ok()?;
    let mut out: Vec<(String, Zeroizing<String>)> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let mut value = value.trim();
        // Strip one layer of matching quotes.
        for q in ['"', '\''] {
            if value.len() >= 2 && value.starts_with(q) && value.ends_with(q) {
                value = &value[1..value.len() - 1];
                break;
            }
        }
        out.push((key.to_string(), Zeroizing::new(value.to_string())));
    }
    Some(Zeroizing::new(out))
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
    use std::io::Read;
    use std::os::fd::{FromRawFd, OwnedFd, RawFd};
    use std::os::unix::fs::PermissionsExt;

    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn read_all(fd: OwnedFd) -> String {
        let mut s = String::new();
        std::fs::File::from(fd).read_to_string(&mut s).unwrap();
        s
    }

    #[test]
    fn describe_extracts_op_references_only() {
        let p = OpProvider::new();
        let refs = p.describe(
            &[
                "op".into(),
                "read".into(),
                "op://Engineering/.env/password".into(),
            ],
            "",
        );
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
            .describe(&["op".into(), "vault".into(), "list".into()], "")
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
    fn registry_dispatches_by_id_and_lists_defaults() {
        let reg = ProviderRegistry::with_defaults();
        assert_eq!(reg.get(OpProvider::ID).map(|p| p.id()), Some("1password"));
        assert_eq!(
            reg.get(EnvFileProvider::ID).map(|p| p.id()),
            Some("env-file")
        );
        assert!(reg.get("bitwarden").is_none());
        assert!(reg.ids().contains(&"1password"));
        assert!(reg.ids().contains(&"env-file"));
    }

    #[test]
    fn op_provider_needs_an_account_and_env_file_does_not() {
        assert!(OpProvider::new().needs_account());
        assert!(!EnvFileProvider.needs_account());
        // A provider with no stored credential does not support probing.
        assert!(matches!(
            EnvFileProvider.probe(b"x"),
            Err(ProviderError::Unsupported)
        ));
    }

    #[test]
    fn run_streams_op_child_output_to_the_caller_fd() {
        // A fake `op` that echoes its token env so we can prove credential injection.
        let dir = std::env::temp_dir().join(format!("latch-prov-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let op = dir.join("op");
        std::fs::write(
            &op,
            "#!/bin/sh\nprintf 'tok=%s' \"$OP_SERVICE_ACCOUNT_TOKEN\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();

        let (read_end, write_end) = pipe();
        let provider = OpProvider::with_binary(op);
        let credential: Token = Zeroizing::new(b"secret-token".to_vec());
        let code = provider.run(ProviderRun {
            command: &["op".into(), "read".into()],
            cwd: "",
            credential: Some(&credential),
            source: "",
            stdin: None,
            stdout: Some(write_end),
            stderr: None,
        });
        assert_eq!(code, 0);
        assert_eq!(read_all(read_end), "tok=secret-token");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn env_file_parses_pairs_and_strips_quotes_and_comments() {
        let src = b"# a comment\nexport FOO=bar\nBAZ=\"quoted value\"\nEMPTY=\nQ='single'\n\nnot a pair line\n";
        let vars = parse_env_file(src).expect("valid utf-8 parses");
        let map: std::collections::HashMap<_, _> = vars
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect();
        assert_eq!(map.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(map.get("BAZ").map(String::as_str), Some("quoted value"));
        assert_eq!(map.get("Q").map(String::as_str), Some("single"));
        assert_eq!(map.get("EMPTY").map(String::as_str), Some(""));
        assert!(!map.contains_key("not a pair line"));
    }

    #[test]
    fn env_file_with_invalid_utf8_is_rejected() {
        // Invalid UTF-8 must fail closed to `None` rather than lossy-convert into
        // a non-zeroized String holding secret bytes (the residual this hardens).
        let src = b"API_KEY=live-key\n\xff\xfe not utf8\n";
        assert!(
            parse_env_file(src).is_none(),
            "an invalid-UTF-8 env file must be refused, not lossy-converted"
        );
    }

    #[test]
    fn env_file_run_fails_closed_on_invalid_utf8() {
        // End to end through the provider: an invalid-UTF-8 source refuses (exit 1)
        // and injects nothing, before it ever resolves or spawns a target binary.
        let dir = std::env::temp_dir().join(format!("latch-envbad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let env_path = dir.join("bad.env");
        std::fs::write(&env_path, b"API_KEY=live\n\xff\xfe\n").unwrap();

        // The refusal is reported on the provider's own stderr (eprintln), as with
        // every other run error; the caller-facing signal is exit 1 and no output.
        let (read_end, write_end) = pipe();
        let code = EnvFileProvider.run(ProviderRun {
            command: &["faketool".into()],
            cwd: "",
            credential: None,
            source: env_path.to_str().unwrap(),
            stdin: None,
            stdout: Some(write_end),
            stderr: None,
        });
        assert_eq!(code, 1, "invalid utf-8 must fail closed");
        assert_eq!(read_all(read_end), "", "no output on a refused run");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn env_file_provider_injects_the_vars_into_the_child() {
        // Prove the direct-injection path: a child sees the exact KEY=VALUEs from
        // the configured source file, and no account credential is involved.
        let dir = std::env::temp_dir().join(format!("latch-envfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let env_path = dir.join("secrets.env");
        std::fs::write(&env_path, "API_KEY=live-key-42\nREGION=eu\n").unwrap();

        // A fake target binary that echoes the two injected vars. We put it on a
        // scoped PATH so find_real resolves it.
        let bindir = dir.join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let tool = bindir.join("faketool");
        std::fs::write(
            &tool,
            "#!/bin/sh\nprintf 'key=%s region=%s' \"$API_KEY\" \"$REGION\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();

        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Prepend (not replace) bindir: faketool resolves first, but system
        // binaries stay reachable for any parallel test's `#!/bin/sh` helper (the
        // fake-`op` sshagent tests do not take TEST_ENV_LOCK and need `cat`).
        let prev = std::env::var_os("PATH");
        let mut search = vec![bindir.clone()];
        if let Some(p) = &prev {
            search.extend(std::env::split_paths(p));
        }
        std::env::set_var("PATH", std::env::join_paths(search).unwrap());

        let (read_end, write_end) = pipe();
        let code = EnvFileProvider.run(ProviderRun {
            command: &["faketool".into()],
            cwd: "",
            credential: None,
            source: env_path.to_str().unwrap(),
            stdin: None,
            stdout: Some(write_end),
            stderr: None,
        });

        match prev {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }

        assert_eq!(code, 0);
        assert_eq!(read_all(read_end), "key=live-key-42 region=eu");
        std::fs::remove_dir_all(&dir).ok();
    }
}
