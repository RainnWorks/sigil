//! The secret-provider seam and its registry.
//!
//! The daemon's core is generic: "run this command with the approved environment
//! injected so the command resolves its own secrets." The SOURCE of secrets is
//! pluggable. 1Password (`op` plus a service-account token) is provider #1; a
//! plain **env-file** is provider #2, the reference impl that proves the seam is
//! real and not op-shaped. bitwarden, aws-vault, and doppler are future fills of
//! this same trait. The approval protocol ([`sigil_proto::request`]) and the
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

use sigil_proto::{RequestKind, SecretRef};

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
    /// The value to set `SIGIL_PROXY_DEPTH` to on the spawned child: the caller's
    /// proxy depth + 1. A tool the child re-invokes through a Sigil alias sees
    /// this and the alias's own fuse bounds the chain (see [`crate::proxy`]).
    pub proxy_depth: u32,
    /// For the inline [`EnvProvider`]: the decrypted KEY=VALUE pairs the daemon
    /// opened from the source's sealed blob *after* approval, to inject into the
    /// child. `None` for every other provider (`op` injects a credential;
    /// `env-file` reads its own file). Like every direct-injection value these
    /// live only in this borrowed, zeroize-on-drop buffer for the spawn instant
    /// (see the module memory note and `EnvProvider`).
    pub env: Option<&'a EnvVars>,
}

/// The provider-specific slice of a source's config passed to
/// [`SecretProvider::describe`]. Each provider reads only the field its shape
/// uses: `op` reads neither (it works off argv plus the injected credential),
/// `env-file` reads `path`, the inline `env` provider reads `keys`. It carries
/// KEY **names** only, never values — values are sealed at rest and decrypted
/// only post-approval into [`ProviderRun::env`], never touched by `describe`.
#[derive(Default, Clone, Copy)]
pub struct SourceView<'a> {
    /// The env-file path (`env-file` provider); empty otherwise.
    pub path: &'a str,
    /// The inline env KEY names (`env` provider); empty otherwise.
    pub keys: &'a [String],
}

/// A pluggable source of secrets. See the module docs for the memory invariant
/// that shapes it and the two injection shapes it spans.
pub trait SecretProvider: Send + Sync {
    /// Stable provider id, surfaced in [`SecretRef::provider`], e.g. "1password".
    fn id(&self) -> &str;

    /// The display hint for a command. A hint only; it never selects mechanism.
    fn kind(&self, command: &[String]) -> RequestKind;

    /// Describe the secrets `command` will resolve, as provider-agnostic
    /// [`SecretRef`]s for the approval screen. `source` carries the config's
    /// provider-specific fields (env-file path, inline env KEY names); providers
    /// that do not need it ignore it. This runs *before* approval, so it must
    /// never read secret values into memory (only KEY names, which are public).
    fn describe(&self, command: &[String], source: &SourceView) -> Vec<SecretRef>;

    /// Whether the daemon must decrypt a stored account token for this provider
    /// (true for `op`) or the provider sources its own secrets (false for
    /// `env-file` and the inline `env` provider). When false the daemon skips the
    /// account routing and leasing entirely; a provider may still need the DEK to
    /// open its own sealed values (see [`needs_sealed_env`](Self::needs_sealed_env)).
    fn needs_account(&self) -> bool;

    /// Whether the daemon must open this provider's DEK-sealed inline values (the
    /// inline `env` provider). When true the daemon fetches the source's sealed
    /// blob from the account store, unwraps the DEK on approval, decrypts it, and
    /// hands the KEY=VALUE pairs to [`run`](Self::run) via [`ProviderRun::env`].
    /// Distinct from [`needs_account`](Self::needs_account) (a routed 1Password
    /// token, which leases) and from a plaintext env-file (no DEK at all). Never
    /// leases: like env-file, resolved values must not persist across a TTL.
    fn needs_sealed_env(&self) -> bool {
        false
    }

    /// Run the command with the environment injected, wiring resolved output to
    /// the caller's fds. Returns the child exit code. Fails closed to a non-zero
    /// code. Secret VALUES never return here.
    fn run(&self, run: ProviderRun) -> i32;

    /// Enumerate what a credential can serve (for `sigil account add` setup).
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
    /// The shipping registry: `op` (provider #1), the `env-file` reference
    /// provider (#2) that proves the abstraction with a distinct injection shape,
    /// and the inline `env` provider (#3) that seals KEY=VALUE pairs at rest under
    /// the DEK and injects them after approval.
    pub fn with_defaults() -> Self {
        Self {
            providers: vec![
                Box::new(OpProvider::new()),
                Box::new(EnvFileProvider),
                Box::new(EnvProvider),
            ],
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

    /// The registered provider ids (for `sigil-config` guidance and diagnostics).
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

    fn describe(&self, command: &[String], _source: &SourceView) -> Vec<SecretRef> {
        command.iter().filter_map(|arg| op_reference(arg)).collect()
    }

    fn needs_account(&self) -> bool {
        true
    }

    fn run(&self, run: ProviderRun) -> i32 {
        let Some(real) = self.resolve() else {
            eprintln!("sigil daemon: no real `op` found on PATH");
            return 127;
        };
        // The op provider always drives the `op` binary (argv[0] is expected to
        // be `op`), injecting the SA token so the child resolves its own secrets.
        let Some(credential) = run.credential else {
            eprintln!("sigil daemon: the 1password provider requires an account credential");
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
                eprintln!("sigil daemon: token is not valid UTF-8");
                return 1;
            }
        }
        // The proxy recursion fuse: the child (and anything it re-invokes through
        // a Sigil alias) carries the incremented depth so the alias's own guard
        // can bound a runaway loop. Harmless to a non-proxied tool.
        cmd.env(crate::proxy::DEPTH_ENV, run.proxy_depth.to_string());
        // Splice the caller's fds to the child. An ABSENT fd defaults to
        // Stdio::null(), never inherit: the daemon's own stdio (a same-UID
        // launchd log) must never become a sink for a tool's secret output
        // (airtight invariant #2). The conforming path always supplies all three.
        cmd.stdin(run.stdin.map_or_else(Stdio::null, Stdio::from));
        cmd.stdout(run.stdout.map_or_else(Stdio::null, Stdio::from));
        cmd.stderr(run.stderr.map_or_else(Stdio::null, Stdio::from));

        match cmd.status() {
            Ok(s) => s
                .code()
                .or_else(|| s.signal().map(|sig| 128 + sig))
                .unwrap_or(1),
            Err(e) => {
                eprintln!("sigil daemon: spawning op failed: {e}");
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

    fn describe(&self, _command: &[String], source: &SourceView) -> Vec<SecretRef> {
        let path = source.path;
        if path.is_empty() {
            return Vec::new();
        }
        // Display only, and deliberately *without* reading the file: naming the
        // source shows the approver where the env comes from without pulling any
        // secret value into memory before the decision is made.
        let label = std::path::Path::new(path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(path)
            .to_string();
        vec![SecretRef {
            provider: Self::ID.to_string(),
            reference: path.to_string(),
            segments: vec![path.to_string()],
            label,
        }]
    }

    fn needs_account(&self) -> bool {
        false
    }

    fn run(&self, run: ProviderRun) -> i32 {
        if run.command.is_empty() {
            eprintln!("sigil daemon: env-file provider got an empty command");
            return 1;
        }
        if run.source.is_empty() {
            eprintln!("sigil daemon: env-file provider has no source file configured");
            return 1;
        }
        // Read the source into a Zeroizing buffer and parse it. The values live
        // only here and in the child's env map, both wiped/handed off at spawn.
        let contents = match std::fs::read(run.source) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(e) => {
                eprintln!("sigil daemon: reading env file {}: {e}", run.source);
                return 1;
            }
        };
        let Some(vars) = parse_env_file(&contents) else {
            // Invalid UTF-8: fail closed rather than lossy-convert (a lossy
            // conversion would allocate a non-zeroized String holding the file's
            // secret bytes). No values are injected.
            eprintln!(
                "sigil daemon: env file {} is not valid UTF-8; refusing to inject",
                run.source
            );
            return 1;
        };
        if vars.is_empty() {
            eprintln!(
                "sigil daemon: env file {} defined no KEY=VALUE pairs",
                run.source
            );
        }

        spawn_with_env(run, &vars)
        // `vars` (Zeroizing) is wiped when it drops here at end of scope.
    }

    fn probe(&self, _credential: &[u8]) -> Result<Vec<String>, ProviderError> {
        Err(ProviderError::Unsupported)
    }
}

/// Provider #3: an inline **env** provider that injects KEY=VALUE pairs whose
/// VALUES are sealed at rest under the DEK (the same AES-256-GCM the account
/// tokens use) rather than sourced from a plaintext file.
///
/// It is the same direct-injection *shape* as [`EnvFileProvider`] — the resolved
/// values transit daemon RAM only as the child's spawn env, for the spawn instant,
/// and it never leases — with one difference: the values do not live in the clear
/// anywhere. The config holds only the KEY *names* (public, for the readout); the
/// VALUES are ciphertext in the account store, keyed by the source name, and are
/// decrypted by the daemon *after approval* into [`ProviderRun::env`]. So the
/// daemon-at-rest holds no plaintext value (invariant #1) even for this
/// direct-injection provider, and [`describe`](SecretProvider::describe) shows the
/// approver the KEY names ("will set FOO, BAR"), never a value (zero-knowledge).
#[derive(Debug, Default, Clone)]
pub struct EnvProvider;

impl EnvProvider {
    pub const ID: &'static str = "env";
}

impl SecretProvider for EnvProvider {
    fn id(&self) -> &str {
        Self::ID
    }

    fn kind(&self, _command: &[String]) -> RequestKind {
        RequestKind::SecretRead
    }

    fn describe(&self, _command: &[String], source: &SourceView) -> Vec<SecretRef> {
        // KEY names only. They are not secret; they come from the config, never
        // from the sealed blob, so no value is read here (pre-approval).
        source
            .keys
            .iter()
            .map(|k| SecretRef {
                provider: Self::ID.to_string(),
                reference: k.clone(),
                segments: vec![k.clone()],
                label: k.clone(),
            })
            .collect()
    }

    fn needs_account(&self) -> bool {
        false
    }

    fn needs_sealed_env(&self) -> bool {
        true
    }

    fn run(&self, run: ProviderRun) -> i32 {
        if run.command.is_empty() {
            eprintln!("sigil daemon: env provider got an empty command");
            return 1;
        }
        // The daemon opens the sealed blob after approval and hands us the pairs;
        // no values were ever read pre-approval. A missing map is a fail-closed
        // bug in the caller, not a secret to inject.
        // Copy the borrowed reference out (it points at the daemon's decrypted
        // buffer, not at `run`), so `run` can then be moved into the spawn helper.
        let Some(vars) = run.env else {
            eprintln!("sigil daemon: env provider got no sealed values to inject");
            return 1;
        };
        spawn_with_env(run, vars)
    }

    fn probe(&self, _credential: &[u8]) -> Result<Vec<String>, ProviderError> {
        Err(ProviderError::Unsupported)
    }
}

/// Spawn the caller's command with `vars` injected into the child's environment
/// and the caller's fds spliced straight to it. Shared by the two direct-injection
/// providers ([`EnvFileProvider`] reads its `vars` from a file, [`EnvProvider`]
/// from a decrypted blob) so the reviewed splice/exec discipline lives in one
/// place. Returns the child exit code; fails closed to non-zero.
///
/// The values in `vars` are `Zeroizing` (wiped by the caller on drop); `cmd`'s own
/// env map holds a second, un-wiped `OsString` copy that std frees but does not
/// scrub when `cmd` drops here (same std limitation as the op SA-token copy,
/// security-claims residual #3/#9), bounded to the spawn.
fn spawn_with_env(run: ProviderRun, vars: &[(String, Zeroizing<String>)]) -> i32 {
    // Resolve the real underlying binary (skipping our own shim alias) so a
    // command named like a shimmed tool still runs the true executable.
    let Some(real) = paths::find_real(&run.command[0]) else {
        eprintln!("sigil daemon: no `{}` found on PATH to run", run.command[0]);
        return 127;
    };

    let mut cmd = Command::new(&real);
    cmd.args(run.command.iter().skip(1));
    if !run.cwd.is_empty() {
        cmd.current_dir(run.cwd);
    }
    for (k, v) in vars.iter() {
        cmd.env(k, v.as_str());
    }
    // The proxy recursion fuse: the child (and anything it re-invokes through
    // a Sigil alias) carries the incremented depth so the alias's own guard
    // can bound a runaway loop. Harmless to a non-proxied tool.
    cmd.env(crate::proxy::DEPTH_ENV, run.proxy_depth.to_string());
    // Splice the caller's fds to the child. An ABSENT fd defaults to
    // Stdio::null(), never inherit: the daemon's own stdio (a same-UID
    // launchd log) must never become a sink for a tool's secret output
    // (airtight invariant #2). The conforming path always supplies all three.
    cmd.stdin(run.stdin.map_or_else(Stdio::null, Stdio::from));
    cmd.stdout(run.stdout.map_or_else(Stdio::null, Stdio::from));
    cmd.stderr(run.stderr.map_or_else(Stdio::null, Stdio::from));

    match cmd.status() {
        Ok(s) => s
            .code()
            .or_else(|| s.signal().map(|sig| 128 + sig))
            .unwrap_or(1),
        Err(e) => {
            eprintln!("sigil daemon: spawning {} failed: {e}", run.command[0]);
            127
        }
    }
}

/// The parsed env pairs: `(KEY, VALUE)` where the key is a plain var name and
/// each value lives in a [`Zeroizing`] buffer; the whole vec is `Zeroizing` so it
/// is wiped when the map drops after the spawn. Shared by the env-file parse and
/// the inline-env seal/open path.
pub type EnvVars = Zeroizing<Vec<(String, Zeroizing<String>)>>;

/// Serialize inline-env `(KEY, VALUE)` pairs into the plaintext the daemon seals
/// under the DEK. The wire is length-prefixed (`u32 key_len | key | u32 val_len |
/// value`, all little-endian) rather than a text/`.env` format so a VALUE may
/// contain **any** bytes (newlines, `=`, quotes) without an escaping ambiguity,
/// and so decoding can borrow slices out of the (`Zeroizing`) plaintext without
/// allocating a non-zeroized copy of any value.
///
/// The buffer is pre-sized to the exact length so it never reallocates: no
/// partial-secret bytes are left in a freed-not-scrubbed intermediate. The
/// returned buffer is `Zeroizing`, wiped on drop; the caller encrypts it and
/// drops it at once.
pub fn encode_env_pairs(pairs: &[(String, Zeroizing<String>)]) -> Zeroizing<Vec<u8>> {
    let total: usize = pairs.iter().map(|(k, v)| 8 + k.len() + v.len()).sum();
    let mut buf = Vec::with_capacity(total);
    for (k, v) in pairs {
        buf.extend_from_slice(&(k.len() as u32).to_le_bytes());
        buf.extend_from_slice(k.as_bytes());
        buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
        buf.extend_from_slice(v.as_bytes());
    }
    Zeroizing::new(buf)
}

/// Parse the plaintext [`encode_env_pairs`] produced (after the daemon or CLI has
/// AES-256-GCM-decrypted the sealed blob) back into [`EnvVars`]. Borrows key and
/// value slices out of `bytes` (which the caller holds in a `Zeroizing` buffer);
/// each value lands in a fresh `Zeroizing` string. Returns `None` on any
/// truncation or non-UTF-8 content (fail closed, no partial/lossy copy), never
/// panicking on hostile input.
pub fn decode_env_pairs(bytes: &[u8]) -> Option<EnvVars> {
    let mut out: Vec<(String, Zeroizing<String>)> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let klen = read_u32(bytes, &mut i)? as usize;
        let key = std::str::from_utf8(bytes.get(i..i.checked_add(klen)?)?)
            .ok()?
            .to_string();
        i += klen;
        let vlen = read_u32(bytes, &mut i)? as usize;
        let val = std::str::from_utf8(bytes.get(i..i.checked_add(vlen)?)?).ok()?;
        out.push((key, Zeroizing::new(val.to_string())));
        i += vlen;
    }
    Some(Zeroizing::new(out))
}

/// Read a little-endian `u32` at `*i`, advancing `*i` by 4. `None` if fewer than
/// 4 bytes remain (a truncated blob fails closed).
fn read_u32(bytes: &[u8], i: &mut usize) -> Option<u32> {
    let end = i.checked_add(4)?;
    let n = u32::from_le_bytes(bytes.get(*i..end)?.try_into().ok()?);
    *i = end;
    Some(n)
}

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
            &SourceView::default(),
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
            .describe(
                &["op".into(), "vault".into(), "list".into()],
                &SourceView::default()
            )
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
        let dir = std::env::temp_dir().join(format!("sigil-prov-{}", std::process::id()));
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
            env: None,
            proxy_depth: 1,
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
        let dir = std::env::temp_dir().join(format!("sigil-envbad-{}", std::process::id()));
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
            env: None,
            proxy_depth: 1,
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
        let dir = std::env::temp_dir().join(format!("sigil-envfile-{}", std::process::id()));
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
            env: None,
            proxy_depth: 1,
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

    fn pairs(kv: &[(&str, &str)]) -> Vec<(String, Zeroizing<String>)> {
        kv.iter()
            .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
            .collect()
    }

    #[test]
    fn env_encode_decode_round_trips_including_awkward_values() {
        // A value with '=', a newline, quotes, and unicode must survive the
        // length-prefixed wire byte-for-byte (no text-format escaping ambiguity).
        let input = pairs(&[
            ("API_KEY", "live=key\nwith-newline"),
            ("QUOTED", "\"has quotes' and spaces\""),
            ("EMPTY", ""),
            ("UNI", "héllo-世界"),
        ]);
        let blob = encode_env_pairs(&input);
        let back = decode_env_pairs(&blob).expect("valid blob decodes");
        let got: std::collections::HashMap<_, _> = back
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect();
        assert_eq!(got.get("API_KEY").unwrap(), "live=key\nwith-newline");
        assert_eq!(got.get("QUOTED").unwrap(), "\"has quotes' and spaces\"");
        assert_eq!(got.get("EMPTY").unwrap(), "");
        assert_eq!(got.get("UNI").unwrap(), "héllo-世界");
    }

    #[test]
    fn env_decode_rejects_truncated_and_bad_utf8_without_panicking() {
        // A truncated length prefix, an over-long declared length, and non-UTF-8
        // key/value bytes must all fail closed to None, never panic or over-read.
        assert!(decode_env_pairs(&[0x03, 0x00]).is_none(), "truncated len");
        // klen=4 but only 2 key bytes follow.
        assert!(decode_env_pairs(&[0x04, 0, 0, 0, b'A', b'B']).is_none());
        // klen=1, key 'A', vlen=2, but only 1 value byte -> truncated value.
        assert!(decode_env_pairs(&[0x01, 0, 0, 0, b'A', 0x02, 0, 0, 0, b'x']).is_none());
        // klen=1 but the "key" byte is invalid UTF-8.
        assert!(decode_env_pairs(&[0x01, 0, 0, 0, 0xff, 0x00, 0, 0, 0]).is_none());
    }

    #[test]
    fn env_provider_flags_and_describe_shows_keys_not_values() {
        assert_eq!(EnvProvider.id(), "env");
        // Direct-injection: no account, no leasing; but it does open a sealed blob.
        assert!(!EnvProvider.needs_account());
        assert!(EnvProvider.needs_sealed_env());
        assert!(matches!(
            EnvProvider.probe(b"x"),
            Err(ProviderError::Unsupported)
        ));
        // describe() surfaces the KEY names only (from config), never a value.
        let keys = vec!["FOO".to_string(), "BAR".to_string()];
        let refs = EnvProvider.describe(
            &["deploy".into()],
            &SourceView {
                path: "",
                keys: &keys,
            },
        );
        let labels: Vec<_> = refs.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, vec!["FOO", "BAR"]);
        assert!(refs.iter().all(|r| r.provider == "env"));
    }

    #[test]
    fn env_provider_is_a_registry_default() {
        let reg = ProviderRegistry::with_defaults();
        assert_eq!(reg.get(EnvProvider::ID).map(|p| p.id()), Some("env"));
        assert!(reg.ids().contains(&"env"));
    }

    #[test]
    fn env_provider_injects_decrypted_pairs_into_the_child() {
        // The inline provider injects the pairs the daemon hands it (as if just
        // decrypted from the sealed blob), and no account credential is involved.
        let dir = std::env::temp_dir().join(format!("sigil-envinline-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
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
        let prev = std::env::var_os("PATH");
        let mut search = vec![bindir.clone()];
        if let Some(p) = &prev {
            search.extend(std::env::split_paths(p));
        }
        std::env::set_var("PATH", std::env::join_paths(search).unwrap());

        let vars: EnvVars = Zeroizing::new(pairs(&[("API_KEY", "sealed-42"), ("REGION", "us")]));
        let (read_end, write_end) = pipe();
        let code = EnvProvider.run(ProviderRun {
            command: &["faketool".into()],
            cwd: "",
            credential: None,
            source: "",
            proxy_depth: 1,
            stdin: None,
            stdout: Some(write_end),
            stderr: None,
            env: Some(&vars),
        });

        match prev {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        assert_eq!(code, 0);
        assert_eq!(read_all(read_end), "key=sealed-42 region=us");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn env_provider_fails_closed_with_no_pairs() {
        // A missing sealed map is a fail-closed bug, not something to inject blank.
        let code = EnvProvider.run(ProviderRun {
            command: &["faketool".into()],
            cwd: "",
            credential: None,
            source: "",
            proxy_depth: 1,
            stdin: None,
            stdout: None,
            stderr: None,
            env: None,
        });
        assert_eq!(code, 1, "no sealed values must fail closed");
    }
}
