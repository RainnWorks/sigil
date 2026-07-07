//! The daemon: accept connections, gate each `op` request behind an approval,
//! then run `op` on the caller's own descriptors.
//!
//! The plumbing invariant is unchanged from v0: the `op` child's stdout and
//! stderr are the descriptors the shim passed in, so secret output never enters
//! this process's memory. What is new is the gate in front of it. For each op
//! request the daemon:
//!
//! 1. resolves the account for the requested vault (routing table in the store);
//! 2. measures the caller itself (peer pid, kernel-side ancestry) and derives a
//!    lease grant key it fully controls;
//! 3. if a live lease covers this grant key, uses its in-RAM token; otherwise
//!    requires a fresh approval (coalescing identical in-flight requests);
//! 4. on approval, unwraps the DEK, decrypts the one token, spawns `op` with the
//!    token in the child env, splices child stdout onto the caller fd, then
//!    zeroizes the DEK and token;
//! 5. on deny, timeout, or lockdown, fails closed: the shim exits like real `op`.
//!
//! Control commands (local approve/deny, lockdown, lease list/revoke) arrive on
//! the same socket and mutate this shared state.

use std::fs;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use tokio::net::UnixListener;

use crate::approve::{
    ApprovalContext, ApprovalGate, Approver, Decision, DevMode, LocalApprover, NullApprover,
    PendingRegistry,
};
use crate::config::{self, Config};
use crate::factor::{self, Factor};
use crate::keystore::{self, Keystore};
use crate::lease::{self, LeaseStore, ProcessTable, SysProcessTable};
use crate::local::{self, Frame, Reply};
use crate::paths::ShimStatus;
use crate::provider::{ProviderRegistry, ProviderRun};
use crate::remote::RemoteApprover;
use crate::secrets::{self, AccountStore};
use crate::service;
use crate::sshagent::{self, ServedIdentity, SignRequest, SshBackend, SshSigner};

use sigil_proto::{RiskLevel, SshChallenge};

use sigil_proto::identity::DeviceIdentity;
use sigil_proto::{mailbox_id, PeerIdentity};
use sigil_relay_client::DaemonRelay;

/// Default session-lease TTL granted by an "approve for this session" decision.
const DEFAULT_LEASE_TTL: Duration = Duration::from_secs(15 * 60);

/// Shared daemon state, cloned (via `Arc`) into every connection worker.
pub struct Core {
    keystore: Arc<dyn Keystore>,
    accounts: Mutex<AccountStore>,
    /// The v2 (threshold) account catalogue, loaded once at arm time, exactly as
    /// [`accounts`](Self::accounts) is. A record here is opened by the two-party
    /// combine, never a DEK; its presence (by version) chooses the decrypt path.
    threshold: Mutex<crate::threshold::ThresholdStore>,
    leases: LeaseStore,
    gate: ApprovalGate,
    pending: Arc<PendingRegistry>,
    lockdown: AtomicBool,
    proc_table: Box<dyn ProcessTable + Send + Sync>,
    /// The provider registry: a command's config names a provider by id, and the
    /// daemon dispatches the run to it. 1Password and env-file ship by default;
    /// the seam is generic and each provider owns its own tool discovery.
    providers: ProviderRegistry,
    /// The generic rule/source config: an ordered rule list matched against each
    /// invocation, resolving to a provider + source + risk. Loaded at arm time.
    /// The core holds no concept of `op`; op-ness lives in user-authored rules.
    config: Config,
    lease_ttl: Duration,
    /// The approving factor resolved at arm time (residual #1 mitigation).
    factor: Factor,
    /// The pluggable SSH key sources this daemon serves on the agent socket,
    /// resolved from `~/.sigil/ssh-keys.json` at arm time. Empty means the agent
    /// advertises no keys (and `ssh-add -l` shows none). Sigil is the phone-gate
    /// regardless of which signer holds the key.
    ssh_signers: Vec<Box<dyn SshSigner>>,
    /// Audit logging: `Some(retention_days)` appends a metadata-only line per
    /// decision to `history.jsonl` (pruned to the window); `None` disables it.
    /// The real daemon enables it; tests leave it off so they never write to a
    /// developer's `~/.sigil`.
    audit: Option<u32>,
}

/// A persisted daemon<->phone pairing: everything needed to reach the phone as
/// the approving factor over the blind relay. `sigil pair` persists this (see
/// [`crate::pairing_store`]) and [`load_remote_pairing`] reconstructs it, so a
/// paired daemon auto-selects the phone factor; a daemon with neither a pairing
/// nor a biometric fails closed unless started `--dev-insecure`.
pub struct RemotePairingConfig {
    /// The relay base URL (`http(s)://host`) the daemon attaches to.
    pub relay_url: String,
    /// The daemon's own pinned identity (signs requests, opens responses).
    pub daemon_identity: DeviceIdentity,
    /// The pinned phone identity the daemon seals to and verifies.
    pub phone: PeerIdentity,
    /// The phone's pinned v2 threshold share `F`, when this is a v2 pairing.
    /// `None` for a v1 pairing (the DEK path). Not needed per request (the record
    /// carries `E`); pinned here so v2 account-add and re-key can wrap to it.
    pub phone_share: Option<crate::threshold::PhoneShare>,
}

impl RemotePairingConfig {
    /// The shared mailbox both parties route on, derived from the pinned keys.
    pub fn mailbox(&self) -> [u8; 32] {
        mailbox_id(&self.daemon_identity.peer_identity(), &self.phone)
    }
}

/// Load a persisted phone pairing, if one exists, from `~/.sigil/pairing.json`
/// plus the daemon identity in `ks`. A present-but-unreadable pairing (corrupt
/// file, missing keystore identity) is logged and treated as "no pairing" so the
/// daemon still arms and fails closed rather than refusing to start; the fault
/// surfaces in `sigil doctor`. See [`crate::pairing_store`] for the on-disk
/// format and why it stays inert at rest.
fn load_remote_pairing(ks: &Arc<dyn Keystore>) -> Option<RemotePairingConfig> {
    match crate::pairing_store::load(ks.as_ref()) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("sigil daemon: ignoring an unreadable pairing config: {e}");
            None
        }
    }
}

/// Build the approval gate for a resolved [`Factor`]. Only [`Factor::DevInsecure`]
/// enables the dev switch and the control socket; [`Factor::NoFactor`] denies
/// every request; the real factors are the phone (sealed remote approval) and
/// the hardware biometric.
fn build_gate(
    factor: Factor,
    remote: Option<RemotePairingConfig>,
    keystore: &Arc<dyn Keystore>,
    pending: &Arc<PendingRegistry>,
) -> anyhow::Result<ApprovalGate> {
    let approver: Box<dyn Approver> = match factor {
        Factor::Phone => {
            let cfg = remote.expect("phone factor implies a pairing config");
            let relay = DaemonRelay::new(&cfg.relay_url, cfg.mailbox())
                .map_err(|e| anyhow::anyhow!("reaching relay {}: {e}", cfg.relay_url))?;
            // The disk-backed push registration store (survives restarts). The
            // phone's token, when registered, is forwarded to the relay on each
            // deposit so the RELAY rings a content-free doorbell; the daemon holds
            // no Apple secret and signs no push. Best-effort: with no token the
            // phone simply polls.
            let push_store = Arc::new(crate::push_store::PushStore::load());
            Box::new(
                RemoteApprover::new(Arc::new(relay), cfg.daemon_identity, cfg.phone)
                    .with_push(push_store),
            )
        }
        // The biometric unwrap is the only gate; an unresolved decision fails
        // closed (no control socket, no dev switch).
        Factor::Biometric => Box::new(LocalApprover::new(keystore.clone(), pending.clone())),
        // The one place the forgeable dev paths are wired.
        Factor::DevInsecure => Box::new(
            LocalApprover::new(keystore.clone(), pending.clone())
                .with_dev(DevMode::from_env())
                .with_control_socket(true),
        ),
        Factor::NoFactor => Box::new(NullApprover),
    };
    Ok(ApprovalGate::new(approver))
}

impl Core {
    /// Build the production core, resolving the approving factor from the host
    /// (a paired phone, then a hardware biometric) and `dev_insecure`. With no
    /// real factor and no `--dev-insecure`, the factor is [`Factor::NoFactor`]
    /// and every gated request fails closed.
    pub fn for_host(dev_insecure: bool) -> anyhow::Result<Self> {
        let keystore = keystore::for_host();
        let accounts = AccountStore::load().context("loading account store")?;
        // The v2 threshold accounts (if any). A missing/unreadable store is
        // logged and treated as empty so the daemon still arms on its v1 accounts.
        let threshold = match crate::threshold::ThresholdStore::load() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("sigil daemon: ignoring an unreadable threshold store: {e}");
                crate::threshold::ThresholdStore::default()
            }
        };
        let pending = Arc::new(PendingRegistry::new());

        let remote = load_remote_pairing(&keystore);
        let inputs = factor::ArmInputs {
            dev_insecure,
            phone_paired: remote.is_some(),
            biometric: keystore.is_biometric(),
        };
        let factor = factor::resolve(&inputs);
        let gate = build_gate(factor, remote, &keystore, &pending)?;

        // Load the served SSH identities from ~/.sigil/ssh-keys.json and build a
        // signer per source (op-fetch + file-based). A bad config is logged and
        // treated as "no keys" so the daemon still arms.
        let ssh_signers = match sshagent::SshKeyConfig::load() {
            Ok(cfg) => build_ssh_signers(&cfg, None),
            Err(e) => {
                eprintln!("sigil daemon: ignoring an unreadable ssh-keys config: {e}");
                Vec::new()
            }
        };

        // Load the rule/source config (which rules gate which invocations, and
        // the sources they inject from). A bad config is logged and treated as
        // empty (every command then refuses until configured).
        let config = match Config::load() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("sigil daemon: ignoring an unreadable config: {e}");
                Config::default()
            }
        };

        Ok(Self {
            keystore,
            accounts: Mutex::new(accounts),
            threshold: Mutex::new(threshold),
            leases: LeaseStore::new(),
            gate,
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(SysProcessTable),
            providers: ProviderRegistry::with_defaults(),
            config,
            lease_ttl: DEFAULT_LEASE_TTL,
            factor,
            ssh_signers,
            audit: Some(
                crate::settings::Settings::load()
                    .map(|s| s.retention_days)
                    .unwrap_or(30),
            ),
        })
    }

    /// The full status report, the daemon's answer to `Frame::Status`. It is the
    /// source of truth: the host-side facts from [`crate::report`] plus the
    /// daemon's own runtime state (lockdown + live lease count).
    fn status_report(&self) -> crate::json::StatusJson {
        crate::report::status(
            true,
            crate::report::Runtime {
                locked_down: self.lockdown.load(Ordering::SeqCst),
                leases: self.leases.active(),
            },
        )
    }

    /// The audit `via` label for a fresh grant under the resolved factor.
    fn grant_via(&self) -> &'static str {
        match self.factor {
            Factor::Phone => "phone",
            Factor::Biometric => "biometric",
            Factor::DevInsecure => "dev",
            Factor::NoFactor => "none",
        }
    }

    /// Append one metadata-only audit line, if auditing is enabled. Best-effort:
    /// never fails a request. Records names and provenance only, never a secret.
    #[allow(clippy::too_many_arguments)]
    fn record_audit(
        &self,
        id: &str,
        kind: sigil_proto::RequestKind,
        label: &str,
        account: &str,
        process: &str,
        cwd: &str,
        decision: &str,
        via: &str,
    ) {
        if let Some(retention) = self.audit {
            let entry = crate::audit::entry(
                id,
                kind,
                label,
                account,
                process,
                cwd,
                decision,
                None,
                sigil_proto::now_ms(),
                via,
            );
            crate::audit::append(&entry, retention);
        }
    }
}

/// The lease/coalesce scope for one SSH signature. The data-to-sign fingerprint
/// is part of it so the approval gate's grant-key coalescing treats different
/// challenges as different requests (each signature is its own approval); only a
/// byte-identical re-sign shares a scope.
fn ssh_sign_scope(label: &str, data_fingerprint: &str) -> String {
    format!("ssh-sign {label} {data_fingerprint}")
}

/// The vault segment of an `op://<vault>/<item>/<field>` reference, for account
/// routing on the SSH sign path.
fn vault_of_ref(reference: &str) -> Option<String> {
    reference
        .strip_prefix("op://")?
        .split('/')
        .find(|s| !s.is_empty())
        .map(str::to_string)
}

/// Build one SSH signer per configured key source: the op-fetch signer for
/// 1Password-backed keys, and the file signer for local key files. Either may be
/// empty; together they form the aggregate the agent serves. `op_path` overrides
/// `op` discovery for the op signer (tests point it at a fake `op`).
fn build_ssh_signers(
    cfg: &sshagent::SshKeyConfig,
    op_path: Option<std::path::PathBuf>,
) -> Vec<Box<dyn SshSigner>> {
    let mut signers: Vec<Box<dyn SshSigner>> = Vec::new();
    let op_ids = cfg.served_identities();
    if !op_ids.is_empty() {
        signers.push(Box::new(sshagent::OpSshSigner::new(op_ids, op_path)));
    }
    let file_keys = cfg.file_keys();
    if !file_keys.is_empty() {
        signers.push(Box::new(sshagent::FileSshSigner::new(file_keys)));
    }
    signers
}

impl SshBackend for Core {
    fn identities(&self) -> Vec<ServedIdentity> {
        self.ssh_signers
            .iter()
            .flat_map(|s| s.identities())
            .collect()
    }

    /// Gate one SSH signature on the phone and, on approval, delegate to the
    /// signer that owns the key. Sigil is the phone-gate regardless of key source:
    /// the gate here is the same approval path as an `op` secret, with two
    /// differences the security review must weigh (see `sshagent` module docs):
    /// every signature is gated (no lease short-circuit in v1), and for the
    /// op-fetch signer the private key is briefly in daemon RAM for the one
    /// signature. A file signer sources the key from a local file instead; either
    /// way the key never reaches the SSH client.
    fn approve_and_sign(&self, req: SignRequest<'_>) -> Option<Vec<u8>> {
        if self.lockdown.load(Ordering::SeqCst) {
            eprintln!("sigil daemon: ssh sign refused; sigil is locked down");
            return None;
        }

        // Route the request to the signer that owns this identity.
        let signer = self.ssh_signers.iter().find(|s| s.owns(&req.id.key_blob))?;

        // Route the account only when the signer needs a stored credential (the
        // op-fetch signer); clone what we need before the (possibly long) approval
        // wait so the store lock is released. A file signer needs no account.
        let account = if signer.needs_account() {
            let vault = vault_of_ref(&req.id.key_ref);
            let store = self.accounts.lock().expect("accounts poisoned");
            let acct = store.route(vault.as_deref()).ok()?;
            Some((acct.label.clone(), acct.ciphertext().ok()?))
        } else {
            None
        };
        let account_label = account.as_ref().map(|(l, _)| l.clone()).unwrap_or_default();

        // The approval screen shows a hash of the data to sign, never raw bytes.
        let data_fingerprint = sshagent::sha256_fingerprint(req.data);
        // The data fingerprint is folded into the scope so the gate's grant-key
        // coalescing can never let two DIFFERENT challenges share one approval: a
        // signature is a distinct auth event over distinct data, and the human
        // approved *this* data's hash. Only a byte-identical re-sign (which is
        // deterministic, so the same signature) may coalesce.
        let scope = ssh_sign_scope(&req.id.label, &data_fingerprint);
        let caller = lease::walk_ancestry(self.proc_table.as_ref(), req.caller_pid.unwrap_or(-1));
        let gk = lease::grant_key(&caller, "", &scope);

        let challenge = SshChallenge {
            key_label: req.id.label.clone(),
            host: req.host.host.clone(),
            fingerprint: data_fingerprint,
        };
        let ctx = ApprovalContext {
            id: uuid::Uuid::now_v7().to_string(),
            account: account_label.clone(),
            scope: scope.clone(),
            grant_hex: lease::hex32(&gk),
            provenance: caller.provenance(),
            cwd: String::new(),
            command: vec!["ssh-sign".to_string(), req.id.label.clone()],
            secret_refs: Vec::new(),
            kind: sigil_proto::RequestKind::SshSignature,
            // A signature is an authentication event: elevated by default.
            risk: RiskLevel::Elevated,
            ssh: Some(challenge),
            // SSH keys are v1-only for now (op-fetch / file signers).
            threshold: None,
        };

        let outcome = self.gate.decide(gk, &ctx);
        if !outcome.decision.is_grant() {
            return None;
        }

        // For a signer that needs an account, unwrap the DEK (phone-delivered on
        // approve, else from the keystore), decrypt the one token, and drop the
        // DEK at once. The credential is handed to the signer, which holds the key
        // material for the one signature (op-fetch) or reads it from a file.
        let credential = match &account {
            Some((label, ciphertext)) => {
                let dek = match outcome.dek {
                    Some(dek) => dek,
                    None => self
                        .keystore
                        .unwrap_dek(&format!("Sign with {} for {label}", req.id.label))
                        .ok()?,
                };
                let token = secrets::decrypt_token(&dek, ciphertext).ok()?;
                drop(dek);
                Some(token)
            }
            None => None,
        };

        let sig = signer.sign(req.id, req.data, credential.as_ref());
        drop(credential); // zeroized here (Token is Zeroizing)
        sig
    }
}

/// Hard cap on connections being served concurrently on the blocking pool
/// (control socket and ssh-agent socket share one gate: both compete for the
/// same pool). A stalled or hostile same-UID client opening connections
/// faster than they close cannot pin every slot and starve legitimate
/// `sigil`/ssh traffic; past the cap a new connection is refused rather than
/// queued. Generous for a personal single-user daemon.
const MAX_CONCURRENT_CONNS: usize = 32;

/// How long a spawned connection may wait for its first (or, on the ssh-agent
/// socket, next) byte before it is dropped. Any real client sends immediately;
/// this only bounds a connect-then-go-silent client. It never bounds the
/// approval wait itself, which happens strictly after a message is read, so a
/// legitimate multi-minute phone round trip is untouched.
const CONN_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// A bounded gate on concurrently-served connections. [`ConnGate::try_enter`]
/// hands back a RAII [`ConnPermit`] that frees the slot on drop; `None` means
/// the cap is hit and the caller must fail closed (drop the connection)
/// rather than queue it.
#[derive(Clone)]
struct ConnGate(Arc<AtomicUsize>);

struct ConnPermit(Arc<AtomicUsize>);

impl ConnGate {
    fn new() -> Self {
        Self(Arc::new(AtomicUsize::new(0)))
    }

    fn try_enter(&self) -> Option<ConnPermit> {
        let mut current = self.0.load(Ordering::Acquire);
        loop {
            if current >= MAX_CONCURRENT_CONNS {
                return None;
            }
            match self.0.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(ConnPermit(self.0.clone())),
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Build a runtime and serve until interrupted. Blocks the calling thread.
/// `args` are the `sigil daemon` arguments (e.g. `--dev-insecure`).
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let dev_insecure = factor::dev_insecure_requested(args);
    let core = Arc::new(Core::for_host(dev_insecure)?);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .build()
        .context("building tokio runtime")?;
    rt.block_on(serve(core))
}

async fn serve(core: Arc<Core>) -> anyhow::Result<()> {
    // Roll the launchd append-mode logs if they have grown large, before we add
    // to them. Best-effort: never blocks arming.
    service::rotate_logs(service::LOG_ROTATE_BYTES);

    let sock = local::socket_path();
    // A truncated socket path means clients and the daemon bind different names
    // and never meet; surface it loudly (the bind below would appear to succeed).
    if let Err(e) = service::socket_path_fits() {
        eprintln!("sigil daemon: {e}");
    }
    prepare_socket(&sock)?;
    let listener =
        UnixListener::bind(&sock).with_context(|| format!("binding {}", sock.display()))?;
    // 0600: only this user may speak to the daemon.
    fs::set_permissions(&sock, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", sock.display()))?;

    // The SSH agent socket, beside the daemon socket. A user points
    // SSH_AUTH_SOCK at it; `ssh`/`git` then transparently gate on the phone.
    let ssh_sock = sshagent::socket_path();
    prepare_socket(&ssh_sock)?;
    let ssh_listener =
        UnixListener::bind(&ssh_sock).with_context(|| format!("binding {}", ssh_sock.display()))?;
    fs::set_permissions(&ssh_sock, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", ssh_sock.display()))?;

    // Under the insecure dev path, print the loud warning on every start.
    if core.factor == Factor::DevInsecure {
        factor::warn_dev_insecure();
    }

    let accounts = core
        .accounts
        .lock()
        .expect("accounts poisoned")
        .accounts
        .len();
    eprintln!(
        "sigil daemon: armed on {} · {accounts} account(s) · factor: {}",
        sock.display(),
        core.factor.label()
    );
    eprintln!(
        "sigil daemon: ssh-agent on {} · {} key(s) served · export SSH_AUTH_SOCK={}",
        ssh_sock.display(),
        core.identities().len(),
        ssh_sock.display()
    );

    // Shim-drift check: if the `op` a shell resolves is no longer our shim (not
    // installed, out-ordered on PATH, or pointing at a stale binary), requests
    // would bypass the gate entirely. Warn loudly at every start.
    if let Some(issue) = ShimStatus::detect().issue() {
        eprintln!("sigil daemon: shim drift: {issue}");
    }

    // Shared across both sockets: they compete for the same blocking pool, so
    // one cap bounds both.
    let conns = ConnGate::new();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("sigil daemon: shutting down (leases zeroized)");
                core.leases.clear();
                break;
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accept")?;
                let Some(permit) = conns.try_enter() else {
                    eprintln!(
                        "sigil daemon: refusing a control connection: at the concurrency cap ({MAX_CONCURRENT_CONNS})"
                    );
                    continue; // dropping `stream` closes it
                };
                let std_stream = stream.into_std().context("into_std")?;
                std_stream.set_nonblocking(false).context("set_nonblocking")?;
                std_stream
                    .set_read_timeout(Some(CONN_READ_TIMEOUT))
                    .context("set_read_timeout")?;
                let core = core.clone();
                // Per-connection work is blocking syscalls (recvmsg, spawn,
                // waitpid) plus a possibly long approval wait; keep it off the
                // async workers.
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    if let Err(e) = handle_conn(core, std_stream) {
                        eprintln!("sigil daemon: connection error: {e}");
                    }
                });
            }
            accepted = ssh_listener.accept() => {
                let (stream, _) = accepted.context("ssh accept")?;
                let Some(permit) = conns.try_enter() else {
                    eprintln!(
                        "sigil daemon: refusing an ssh-agent connection: at the concurrency cap ({MAX_CONCURRENT_CONNS})"
                    );
                    continue;
                };
                let std_stream = stream.into_std().context("ssh into_std")?;
                std_stream.set_nonblocking(false).context("ssh set_nonblocking")?;
                std_stream
                    .set_read_timeout(Some(CONN_READ_TIMEOUT))
                    .context("ssh set_read_timeout")?;
                let core = core.clone();
                // An SSH connection is also blocking (per-signature fetch, spawn,
                // approval wait); serve it on the blocking pool with the Core as
                // the agent backend.
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    if let Err(e) = sshagent::handle_connection(core.as_ref(), std_stream) {
                        eprintln!("sigil daemon: ssh connection error: {e}");
                    }
                });
            }
        }
    }

    let _ = fs::remove_file(&sock);
    let _ = fs::remove_file(&ssh_sock);
    Ok(())
}

/// Create the socket directory 0700 and clear any stale socket file.
fn prepare_socket(sock: &Path) -> anyhow::Result<()> {
    if let Some(dir) = sock.parent() {
        fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod {}", dir.display()))?;
    }
    if sock.exists() {
        fs::remove_file(sock).with_context(|| format!("removing stale {}", sock.display()))?;
    }
    Ok(())
}

fn handle_conn(core: Arc<Core>, mut stream: UnixStream) -> anyhow::Result<()> {
    // The kernel-verified peer pid, read before we touch any passed fds.
    let peer = lease::peer_pid(stream.as_raw_fd());

    let (frame, fds) = match local::recv_frame(&stream) {
        Ok(v) => v,
        // A probe connects then hangs up; not an error.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
        Err(e) => return Err(e.into()),
    };

    // The pending subscription streams many replies on this one connection, so
    // it is handled outside the single-reply match below.
    if matches!(frame, Frame::SubscribePending) {
        return stream_pending(&core, &mut stream);
    }

    let reply = match frame {
        Frame::Run {
            argv,
            cwd,
            proxy_depth,
        } => {
            // Airtight invariant #2: a conforming shim always passes EXACTLY three
            // descriptors (stdin, stdout, stderr). Reject any other count and fail
            // closed. A short count from a non-conforming same-UID client would
            // both misassign the fd slots AND leave a child stream defaulting to
            // the daemon's own (inherited) stdio — a same-UID-readable launchd log
            // — as a sink for the tool's secret output. We never let that happen.
            if fds.len() != 3 {
                eprintln!(
                    "sigil daemon: refusing a Run frame carrying {} descriptor(s); expected 3 (stdin, stdout, stderr)",
                    fds.len()
                );
                Reply::Exit { code: 1 }
            } else {
                log_request(&argv, &cwd, peer);
                // The daemon only splices these to the child; it never reads any
                // of them, so no caller byte enters daemon memory.
                let mut fds = fds.into_iter();
                let stdin = fds.next();
                let stdout = fds.next();
                let stderr = fds.next();
                Reply::Exit {
                    code: fulfill(&core, &argv, &cwd, peer, proxy_depth, stdin, stdout, stderr),
                }
            }
        }
        Frame::Approve { id, lease } => {
            let decision = if lease {
                Decision::Lease(core.lease_ttl)
            } else {
                Decision::Approve
            };
            let ok = core.pending.resolve(&id, decision);
            control_reply(
                ok,
                if ok {
                    "approval delivered"
                } else {
                    "no pending request with that id"
                },
            )
        }
        Frame::Deny { id } => {
            let ok = core.pending.resolve(&id, Decision::Deny);
            control_reply(
                ok,
                if ok {
                    "deny delivered"
                } else {
                    "no pending request with that id"
                },
            )
        }
        Frame::Lockdown { clear } => {
            if clear {
                core.lockdown.store(false, Ordering::SeqCst);
                control_reply(true, "lockdown cleared; requests will route again")
            } else {
                core.lockdown.store(true, Ordering::SeqCst);
                let n = core.leases.clear();
                control_reply(
                    true,
                    &format!("locked down; {n} lease(s) zeroized, new requests refused"),
                )
            }
        }
        Frame::LeaseRevoke { prefix } => {
            let n = core.leases.revoke(&prefix);
            control_reply(n > 0, &format!("revoked {n} lease(s)"))
        }
        Frame::Status => json_reply(&core.status_report()),
        Frame::Doctor => json_reply(&crate::report::doctor(true)),
        Frame::LeaseList => json_reply(&leases_json(&core)),
        Frame::Pending => json_reply(&pending_json(&core)),
        Frame::History => {
            let entries: Vec<_> = crate::audit::load().iter().map(|e| e.to_json()).collect();
            json_reply(&entries)
        }
        // Handled above via an early return; the match stays exhaustive.
        Frame::SubscribePending => unreachable!("subscribe streams before the match"),
    };

    local::send_reply(&mut stream, &reply)?;
    Ok(())
}

/// Stream the pending set to a subscriber: emit the current snapshot, then
/// re-emit on every change (and as a ~30s keepalive that also detects a hung-up
/// client), until the connection breaks. Runs on the blocking pool.
fn stream_pending(core: &Core, stream: &mut UnixStream) -> anyhow::Result<()> {
    loop {
        // Read the version before snapshotting so a change during snapshotting
        // is never missed (at worst it costs one duplicate emit).
        let version = core.pending.version();
        let body = serde_json::to_string(&pending_json(core)).unwrap_or_else(|_| "[]".to_string());
        if local::send_reply(stream, &Reply::Event { body }).is_err() {
            return Ok(()); // client hung up
        }
        core.pending
            .wait_for_change(version, Duration::from_secs(30));
    }
}

fn control_reply(ok: bool, msg: &str) -> Reply {
    Reply::Control {
        ok,
        lines: vec![msg.to_string()],
    }
}

/// Wrap any serializable value as a [`Reply::Json`] (a pre-serialized body the
/// CLI prints verbatim). Serialization of these small owned structs never fails.
fn json_reply<T: serde::Serialize>(value: &T) -> Reply {
    Reply::Json {
        body: serde_json::to_string(value).unwrap_or_else(|_| "null".to_string()),
    }
}

/// The active leases as the `lease list --json` array. The store holds
/// monotonic `Instant`s, so absolute unix-ms timestamps are reconstructed from
/// `now` plus each lease's age/remaining. `caller` is empty: a lease retains the
/// grant key, not the provenance that derived it (see JSON.md).
fn leases_json(core: &Core) -> Vec<crate::json::LeaseJson> {
    let now = sigil_proto::now_ms();
    core.leases
        .list()
        .into_iter()
        .map(|l| crate::json::LeaseJson {
            grant_hex: l.grant_hex,
            caller: String::new(),
            account: l.account,
            scope: l.scope,
            granted_ms: now.saturating_sub(l.age.as_millis() as u64),
            expires_ms: now + l.remaining.as_millis() as u64,
        })
        .collect()
}

/// The parked requests as the `pending --json` array. Enumerates the local
/// control-socket queue; `risk`/`reason`/`coalesced` are the honest defaults for
/// that path (see JSON.md).
fn pending_json(core: &Core) -> Vec<crate::json::PendingJson> {
    core.pending
        .snapshot()
        .into_iter()
        .map(|s| {
            let ctx = s.ctx;
            crate::json::PendingJson {
                id: ctx.id,
                kind: crate::json::request_kind_str(ctx.kind).to_string(),
                command: ctx.command,
                secrets: ctx
                    .secret_refs
                    .into_iter()
                    .map(|r| crate::json::SecretRefJson {
                        provider: r.provider,
                        segments: r.segments,
                        label: r.label,
                    })
                    .collect(),
                ssh: ctx.ssh.map(|c| crate::json::SshJson {
                    key_label: c.key_label,
                    host: c.host,
                    fingerprint: c.fingerprint,
                }),
                provenance: crate::json::ProvJson {
                    process_chain: crate::json::split_provenance(&ctx.provenance),
                    cwd: ctx.cwd,
                    machine: crate::json::hostname(),
                    requested_ms: s.queued_at_ms,
                },
                risk: config::risk_str(ctx.risk).to_string(),
                reason: None,
                expires_ms: s.queued_at_ms + s.timeout_ms,
                timeout_ms: s.timeout_ms,
                coalesced: 0,
            }
        })
        .collect()
}

/// The gated fulfillment path for `sigil <cmd>` (and the shim alias / `sigil run`).
/// Returns the exit code to mirror to the caller. Every failure path here fails
/// closed (a non-zero code with a stderr line), so the caller behaves like a
/// denied invocation.
///
/// The command's config selects the provider; the provider decides the injection
/// shape. `op` (and any provider that [`needs_account`](crate::provider::SecretProvider::needs_account))
/// routes a 1Password account, unwraps the DEK, decrypts the one token, and
/// injects it; a direct-injection provider (`env-file`) needs no account and is
/// gated on every run (no leasing, so resolved values never sit in RAM across a
/// TTL). An *unconfigured* command is refused with a pointer to `sigil-config
/// add`, never run ungated.
#[allow(clippy::too_many_arguments)]
fn fulfill(
    core: &Core,
    argv: &[String],
    cwd: &str,
    peer: Option<i32>,
    proxy_depth: u32,
    stdin: Option<OwnedFd>,
    stdout: Option<OwnedFd>,
    stderr: Option<OwnedFd>,
) -> i32 {
    if core.lockdown.load(Ordering::SeqCst) {
        return fail_closed(stderr, "sigil is locked down; no secrets served\n");
    }

    // Proxy recursion fuse: the caller's depth reached us over the socket (the
    // daemon has no other view of it). If it is already at the limit, a runaway
    // alias -> daemon -> tool -> alias loop is in progress; fail closed rather
    // than spawn another level.
    if proxy_depth >= crate::proxy::MAX_DEPTH {
        return fail_closed(
            stderr,
            "sigil: proxy recursion limit reached; refusing to run (loop?)\n",
        );
    }
    // The depth the spawned child (and anything it re-invokes) will carry.
    let child_depth = proxy_depth.saturating_add(1);

    let Some(cmd) = argv.first() else {
        return fail_closed(stderr, "sigil: empty command\n");
    };

    // Evaluate the rules against this whole invocation. An invocation that no
    // rule matches is refused (never run ungated) with a pointer to `sigil
    // config`; the core holds no built-in rule for any command, `op` included.
    let Some(action) = core.config.resolve(argv) else {
        return fail_closed(
            stderr,
            &format!(
                "sigil: '{cmd}' is not configured (no rule matches); Sigil will not run it ungated.\n  \
                 configure it: sigil-config add {cmd} --provider <id>\n"
            ),
        );
    };
    let Some(provider) = core.providers.get(&action.provider) else {
        return fail_closed(
            stderr,
            &format!(
                "sigil: rule '{}' names an unknown provider '{}'\n",
                action.rule, action.provider
            ),
        );
    };
    let source = action.source_path.as_deref().unwrap_or("");
    let needs_account = provider.needs_account();
    let needs_sealed_env = provider.needs_sealed_env();
    // What `describe` reads: the env-file path or the inline env KEY names. Names
    // only; no secret value is read here (pre-approval, zero-knowledge readout).
    let view = crate::provider::SourceView {
        path: source,
        keys: &action.env_keys,
    };

    let scope = argv.iter().skip(1).cloned().collect::<Vec<_>>().join(" ");
    let caller = lease::walk_ancestry(core.proc_table.as_ref(), peer.unwrap_or(-1));
    let gk = lease::grant_key(&caller, cwd, &scope);

    // Route the account only for providers that inject a stored token. Routing is
    // the source's configured account label (or a legacy vault name) — never argv
    // archaeology, so the core stays provider-agnostic.
    let vault = if needs_account {
        action.account.clone()
    } else {
        None
    };

    // A v2 (threshold) account takes precedence: its token is opened per request
    // by the two-party combine (Mac share m + the phone's partial Z_F), never a
    // DEK. The decrypt path is chosen HERE, from the at-rest record (R3: never
    // from any wire field). When v1 accounts coexist (a migration store) v2 claims
    // only an EXACT vault match, so it never over-captures a v1 request; once the
    // store is fully v2 (no v1 accounts) v2 also serves the single-account
    // fallback. v1 accounts keep the byte-identical DEK path.
    let v2 = if needs_account {
        let v1_empty = core
            .accounts
            .lock()
            .expect("accounts poisoned")
            .accounts
            .is_empty();
        let store = core.threshold.lock().expect("threshold store poisoned");
        let picked = store.route_exact(vault.as_deref()).or_else(|| {
            if v1_empty {
                store.route(vault.as_deref())
            } else {
                None
            }
        });
        picked.map(|a| (a.label().to_string(), a.record.clone()))
    } else {
        None
    };

    // Clone what we need so the store lock is released before the approval wait.
    let (account_label, ciphertext) = match &v2 {
        // v2: the label comes from the record; there is no v1 ciphertext/DEK.
        Some((label, _)) => (label.clone(), None),
        None if needs_account => {
            let store = core.accounts.lock().expect("accounts poisoned");
            match store.route(vault.as_deref()) {
                Ok(acct) => match acct.ciphertext() {
                    Ok(ct) => (acct.label.clone(), Some(ct)),
                    Err(e) => return fail_closed(stderr, &format!("sigil account error: {e}\n")),
                },
                Err(e) => return fail_closed(stderr, &format!("sigil: {e}\n")),
            }
        }
        None => (String::new(), None),
    };

    // For the inline `env` provider, fetch its sealed value blob now (ciphertext,
    // safe to hold across the approval wait) and release the store lock. It is
    // decrypted only AFTER the grant, so no plaintext value crosses the wait. A
    // source with no values set fails closed rather than injecting nothing.
    let sealed_ct = if needs_sealed_env {
        let store = core.accounts.lock().expect("accounts poisoned");
        match store.env_blob(&action.source_name) {
            Some(Ok(ct)) => Some(ct),
            Some(Err(e)) => return fail_closed(stderr, &format!("sigil env store error: {e}\n")),
            None => {
                return fail_closed(
                    stderr,
                    &format!(
                        "sigil: inline env source '{0}' has no sealed values; set them with: \
                         sigil-config source env set {0} --key <KEY>\n",
                        action.source_name
                    ),
                )
            }
        }
    } else {
        None
    };

    // A live lease short-circuits the approval — only for account-backed
    // providers, whose credential is what a lease holds. Direct-injection
    // providers are gated on every run.
    if needs_account {
        if let Some(token) = core.leases.token_for(&gk, &account_label, &scope) {
            let refs = provider.describe(argv, &view);
            core.record_audit(
                &uuid::Uuid::now_v7().to_string(),
                provider.kind(argv),
                &audit_label(&refs, &scope),
                &account_label,
                &caller.provenance(),
                cwd,
                "approved",
                "lease",
            );
            return provider.run(ProviderRun {
                command: argv,
                cwd,
                credential: Some(&token),
                source,
                stdin,
                stdout,
                stderr,
                proxy_depth: child_depth,
                env: None,
            });
        }
    }

    // For a v2 account, carry the threshold challenge to the phone: the base
    // point E it key-agrees against, plus the account binding it shows and
    // consents to (R5). E is public and authenticated by the enclosing signed
    // envelope; the phone validates it on-curve before its Secure-Enclave op.
    let threshold = v2
        .as_ref()
        .map(|(label, record)| sigil_proto::ThresholdChallenge {
            account_id: record.account_id.clone(),
            label: label.clone(),
            ephemeral_pub: record.ephemeral_pub.clone(),
            se_key_id: record.se_key_id.clone(),
            ecdh_algo: crate::threshold::ecdh_algo_tag(record.ecdh_algo).to_string(),
        });

    // The provider describes the request in provider-agnostic terms; the
    // approver never sees provider semantics.
    let ctx = ApprovalContext {
        id: uuid::Uuid::now_v7().to_string(),
        account: account_label.clone(),
        scope: scope.clone(),
        grant_hex: lease::hex32(&gk),
        provenance: caller.provenance(),
        cwd: cwd.to_string(),
        command: argv.to_vec(),
        secret_refs: provider.describe(argv, &view),
        kind: provider.kind(argv),
        risk: action.risk,
        ssh: None,
        threshold,
    };
    let outcome = core.gate.decide(gk, &ctx);
    let decision = outcome.decision;
    if !decision.is_grant() {
        core.record_audit(
            &ctx.id,
            ctx.kind,
            &audit_label(&ctx.secret_refs, &scope),
            &account_label,
            &ctx.provenance,
            cwd,
            "denied",
            "",
        );
        return fail_closed(stderr, "request denied\n");
    }

    // What each provider shape needs on approval: an account-backed provider
    // needs the decrypted token (`credential`); the inline `env` provider needs
    // its sealed values opened (`sealed_env`); `env-file` needs neither. These
    // are mutually exclusive arms of one if/else so each may consume the
    // approval's key material (`outcome.dek` / `outcome.zf`) without a move
    // conflict.
    //
    // v2 accounts open the token by the two-party combine: the phone returned its
    // partial Z_F with the approval, and the daemon combines it with its Mac share
    // m (loaded into mlock'd memory for this one op) to derive K and decrypt. No
    // full private key is ever assembled; m, K, and the token are all zeroized.
    let mut sealed_env: Option<crate::provider::EnvVars> = None;
    let credential = if let Some((_, record)) = &v2 {
        let zf = match outcome.zf.as_deref() {
            Some(zf) => zf,
            // An approve with no partial cannot open a v2 token (e.g. the local
            // factor cannot produce Z_F): fail closed rather than serving nothing.
            None => {
                return fail_closed(
                    stderr,
                    "sigil: v2 approval carried no threshold partial; no phone factor?\n",
                )
            }
        };
        let m = match crate::threshold::load_mac_share(core.keystore.as_ref()) {
            Ok(Some(m)) => m,
            Ok(None) => {
                return fail_closed(
                    stderr,
                    "sigil: no Mac threshold share on this daemon; re-pair for v2\n",
                )
            }
            Err(e) => return fail_closed(stderr, &format!("sigil: {e}\n")),
        };
        let token = match crate::threshold::decrypt(record, &m, zf) {
            Ok(t) => t,
            Err(e) => return fail_closed(stderr, &format!("sigil token decrypt failed: {e}\n")),
        };
        drop(m); // the Mac share is held only for the one combine
        if let Some(ttl) = decision.lease_ttl() {
            core.leases
                .grant(gk, &account_label, &scope, token.clone(), ttl);
        }
        Some(token)
    } else if let Some(ciphertext) = &ciphertext {
        let dek = match outcome.dek {
            Some(dek) => dek,
            None => match core
                .keystore
                .unwrap_dek(&format!("Approve {scope} for {account_label}"))
            {
                Ok(dek) => dek,
                Err(e) => {
                    return fail_closed(stderr, &format!("sigil could not unwrap the key: {e}\n"))
                }
            },
        };
        let token = match secrets::decrypt_token(&dek, ciphertext) {
            Ok(t) => t,
            Err(e) => return fail_closed(stderr, &format!("sigil token decrypt failed: {e}\n")),
        };
        drop(dek);
        if let Some(ttl) = decision.lease_ttl() {
            core.leases
                .grant(gk, &account_label, &scope, token.clone(), ttl);
        }
        Some(token)
    } else if let Some(ct) = &sealed_ct {
        // Inline `env`: open the sealed value blob now that the request is
        // granted. The DEK arrives with the phone approval (or is unwrapped from
        // the keystore on a local approval, the same as `op`), is used for this
        // one decrypt, and is dropped at once. No lease: like env-file, resolved
        // values must never persist across a TTL.
        let dek = match outcome.dek {
            Some(dek) => dek,
            None => match core.keystore.unwrap_dek(&format!("Approve {scope}")) {
                Ok(dek) => dek,
                Err(e) => {
                    return fail_closed(stderr, &format!("sigil could not unwrap the key: {e}\n"))
                }
            },
        };
        let plain = match secrets::decrypt_token(&dek, ct) {
            Ok(p) => p,
            Err(e) => return fail_closed(stderr, &format!("sigil env decrypt failed: {e}\n")),
        };
        drop(dek);
        match crate::provider::decode_env_pairs(&plain) {
            Some(pairs) => sealed_env = Some(pairs),
            None => return fail_closed(stderr, "sigil: inline env blob is corrupt; re-set it\n"),
        }
        None
    } else {
        None
    };

    core.record_audit(
        &ctx.id,
        ctx.kind,
        &audit_label(&ctx.secret_refs, &scope),
        &account_label,
        &ctx.provenance,
        cwd,
        "approved",
        core.grant_via(),
    );

    // Run through the provider: it injects the credential (op), the env-file's
    // own values, or the inline env's decrypted pairs, and streams output straight
    // to the caller's fds. For op the daemon holds only the credential; for the
    // direct-injection shapes the resolved values transit only as the child's
    // spawn env (see the provider module docs).
    let code = provider.run(ProviderRun {
        command: argv,
        cwd,
        credential: credential.as_ref(),
        source,
        stdin,
        stdout,
        stderr,
        proxy_depth: child_depth,
        env: sealed_env.as_ref(),
    });
    drop(credential); // zeroized here (Token is Zeroizing) when present
    drop(sealed_env); // zeroized here (EnvVars is Zeroizing) when present
    code
}

/// The brightest audit label for an op request: the first secret ref's item
/// label, or the scope string when the provider named none.
fn audit_label(refs: &[sigil_proto::SecretRef], scope: &str) -> String {
    refs.first()
        .map(|r| r.label.clone())
        .unwrap_or_else(|| scope.to_string())
}

/// Write a fail-closed message to the caller's stderr fd (if present) and
/// return exit code 1, so the shim behaves like a denied real `op`.
fn fail_closed(stderr: Option<OwnedFd>, msg: &str) -> i32 {
    if let Some(fd) = stderr {
        let mut f = std::fs::File::from(fd);
        let _ = f.write_all(msg.as_bytes());
    }
    1
}

/// Log request metadata: argv (item names, not secret values), cwd, peer pid.
fn log_request(argv: &[String], cwd: &str, peer: Option<i32>) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    eprintln!(
        "sigil daemon: [{ts}] op {} · cwd {} · pid {}",
        argv.iter().skip(1).cloned().collect::<Vec<_>>().join(" "),
        cwd,
        peer.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approve::DevMode;
    use crate::keystore::MemoryKeystore;
    use crate::provider::{EnvFileProvider, OpProvider};
    use std::io::Read;
    use std::os::fd::{FromRawFd, RawFd};
    use std::path::PathBuf;

    /// A process table that resolves nothing, so the ancestry walk returns an
    /// empty chain instantly (the real table would hash every ancestor's
    /// executable, which is slow and irrelevant to what these tests assert).
    struct EmptyTable;
    impl ProcessTable for EmptyTable {
        fn parent(&self, _pid: i32) -> Option<i32> {
            None
        }
        fn exe(&self, _pid: i32) -> Option<PathBuf> {
            None
        }
        fn identity(&self, _pid: i32) -> [u8; 32] {
            [0u8; 32]
        }
    }

    /// A fake `op` that emits a known secret only when the expected token
    /// reached its env. Proves both the approval gate and the token-in-env
    /// delivery without ever printing the token itself.
    fn write_fake_op(dir: &Path, expected_token: &str, secret: &str) -> PathBuf {
        let path = dir.join("op");
        let script = format!(
            "#!/bin/sh\nif [ \"$OP_SERVICE_ACCOUNT_TOKEN\" = \"{expected_token}\" ]; then printf '{secret}'; else printf 'NOTOKEN'; fi\n"
        );
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// A minimal rule/source config that gates `op` to the 1Password provider
    /// with no account hint (single-account fallback) — the zero-config `op` the
    /// tests used to get for free before the rule engine replaced the built-in
    /// default. op-ness now lives entirely in this user-authored rule.
    fn op_config() -> Config {
        use crate::config::{Action, Match, Rule, Source};
        let mut cfg = Config::default();
        cfg.add_source(Source {
            name: "op".into(),
            provider: OpProvider::ID.into(),
            account: None,
            path: None,
            keys: Vec::new(),
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: "op".into(),
            match_: Match {
                command: Some("op".into()),
                ..Match::default()
            },
            action: Action {
                source: "op".into(),
                risk: RiskLevel::Routine,
                timeout_sec: None,
            },
        })
        .unwrap();
        cfg
    }

    /// A config gating `<command>` to the `env-file` provider at `path` (the
    /// direct-injection shape). Used by the env-file daemon tests in place of the
    /// old per-command store.
    fn env_file_config(command: &str, path: &str) -> Config {
        use crate::config::{Action, Match, Rule, Source};
        let mut cfg = Config::default();
        cfg.add_source(Source {
            name: command.into(),
            provider: EnvFileProvider::ID.into(),
            account: None,
            path: Some(path.into()),
            keys: Vec::new(),
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: command.into(),
            match_: Match {
                command: Some(command.into()),
                ..Match::default()
            },
            action: Action {
                source: command.into(),
                risk: RiskLevel::Routine,
                timeout_sec: None,
            },
        })
        .unwrap();
        cfg
    }

    /// The coexistence config: two op rules routing by an argv marker to two op
    /// sources, one hinting the v2 vault (`Engineering`) and one the v1 vault
    /// (`Legacy`). It stands in for the old argv `--vault` routing so the
    /// v1/v2 coexistence test still drives each token down its own path.
    fn coexist_config() -> Config {
        use crate::config::{Action, Match, Rule, Source};
        let mut cfg = Config::default();
        for (name, account, marker) in [
            ("v2", "Engineering", "Engineering"),
            ("v1", "Legacy", "Legacy"),
        ] {
            cfg.add_source(Source {
                name: name.into(),
                provider: OpProvider::ID.into(),
                account: Some(account.into()),
                path: None,
                keys: Vec::new(),
            })
            .unwrap();
            cfg.add_rule(Rule {
                name: name.into(),
                match_: Match {
                    command: Some("op".into()),
                    argv_contains: vec![marker.into()],
                    ..Match::default()
                },
                action: Action {
                    source: name.into(),
                    risk: RiskLevel::Routine,
                    timeout_sec: None,
                },
            })
            .unwrap();
        }
        cfg
    }

    /// Build a core wired to an in-memory keystore holding one account whose
    /// token decrypts to `token`, a fake `op`, the given dev mode, and the given
    /// local-approval timeout.
    fn test_core(
        dir: &Path,
        token: &str,
        secret: &str,
        dev: DevMode,
        timeout: Duration,
    ) -> (Arc<Core>, Arc<PendingRegistry>) {
        let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::with_dek());
        let dek = keystore.unwrap_dek("seed").unwrap();
        let mut accounts = AccountStore::default();
        accounts
            .add("Rowm", &dek, token.as_bytes(), vec!["Engineering".into()])
            .unwrap();
        drop(dek);

        let pending = Arc::new(PendingRegistry::new());
        // These tests exercise the dev-insecure configuration, so the dev switch
        // and the control-socket park are both enabled.
        let approver = LocalApprover::new(keystore.clone(), pending.clone())
            .with_dev(dev)
            .with_control_socket(true)
            .with_timeout(timeout);
        let core = Core {
            keystore,
            accounts: Mutex::new(accounts),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending: pending.clone(),
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::new(vec![Box::new(OpProvider::with_binary(
                write_fake_op(dir, token, secret),
            ))]),
            config: op_config(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: Vec::new(),
            audit: None,
        };
        (Arc::new(core), pending)
    }

    /// A fresh pipe; returns (read_end, write_end).
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

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sigil-daemon-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn run_frame_with_wrong_fd_count_is_refused() {
        // Airtight invariant #2: a Run frame that does not carry exactly three
        // descriptors is refused (exit 1) before any tool spawns, so a short
        // count can never misassign fd slots or let a child stream fall back to
        // the daemon's inherited stdio as a sink for secret output.
        let dir = tmpdir("fdcount");
        let (core, _) = test_core(
            &dir,
            "expected-token-xyz",
            "known-secret-42",
            DevMode::Approve,
            Duration::from_millis(50),
        );

        // Only two descriptors (stdin, stdout) — one short of the required three.
        let (read_end, write_end) = pipe();
        let (client, server) = UnixStream::pair().unwrap();
        local::send_frame(
            &client,
            &Frame::Run {
                argv: vec![
                    "op".into(),
                    "read".into(),
                    "op://Engineering/.env/password".into(),
                ],
                cwd: String::new(),
                proxy_depth: 0,
            },
            &[std::io::stdin().as_raw_fd(), write_end.as_raw_fd()],
        )
        .unwrap();
        drop(write_end);
        let h = std::thread::spawn(move || handle_conn(core, server).unwrap());
        let mut client = client;
        match local::recv_reply(&mut client).unwrap() {
            Reply::Exit { code } => assert_eq!(code, 1, "a short fd count must fail closed"),
            other => panic!("unexpected reply: {other:?}"),
        }
        h.join().unwrap();
        assert_eq!(read_all(read_end), "", "no tool output on a refused frame");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dev_autoapprove_full_loop_delivers_secret_to_caller() {
        let dir = tmpdir("loop");
        let (core, _) = test_core(
            &dir,
            "expected-token-xyz",
            "known-secret-42",
            DevMode::Approve,
            Duration::from_millis(50),
        );

        let (read_end, write_end) = pipe();
        let argv = vec![
            "op".into(),
            "read".into(),
            "op://Engineering/.env/password".into(),
        ];
        // Empty cwd: the fake op runs in the test's own directory (a real path).
        let code = fulfill(&core, &argv, "", None, 0, None, Some(write_end), None);
        assert_eq!(code, 0);
        assert_eq!(read_all(read_end), "known-secret-42");
        // No lease was requested, so none is held.
        assert_eq!(core.leases.active(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn approved_request_is_recorded_in_the_audit_log() {
        // The daemon appends one metadata-only line per decision. Build a
        // dev-approve core with auditing enabled to a private SIGIL_HOME and
        // prove the approved request lands in history.jsonl with the right
        // decision/account/via.
        let _home = HomeGuard::new("audit-approve");
        let dir = tmpdir("audit");
        let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::with_dek());
        let dek = keystore.unwrap_dek("seed").unwrap();
        let mut accounts = AccountStore::default();
        accounts
            .add("Rowm", &dek, b"tok", vec!["Engineering".into()])
            .unwrap();
        drop(dek);
        let pending = Arc::new(PendingRegistry::new());
        let approver = LocalApprover::new(keystore.clone(), pending.clone())
            .with_dev(DevMode::Approve)
            .with_control_socket(true);
        let core = Core {
            keystore,
            accounts: Mutex::new(accounts),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::new(vec![Box::new(OpProvider::with_binary(
                write_fake_op(&dir, "tok", "secret-1"),
            ))]),
            config: op_config(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: Vec::new(),
            audit: Some(30),
        };

        let (read_end, write_end) = pipe();
        let argv = vec![
            "op".into(),
            "read".into(),
            "op://Engineering/.env/password".into(),
        ];
        // Empty cwd: the fake op runs in the test's own directory (a real path).
        assert_eq!(
            fulfill(&core, &argv, "", None, 0, None, Some(write_end), None),
            0
        );
        assert_eq!(read_all(read_end), "secret-1");

        let hist = crate::audit::load();
        assert_eq!(hist.len(), 1, "one decision, one audit line");
        assert_eq!(hist[0].decision, "approved");
        assert_eq!(hist[0].account, "Rowm");
        assert_eq!(hist[0].via, "dev");
        assert_eq!(hist[0].kind, "secret_read");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Drive one request/reply frame through `handle_conn` over a socketpair and
    /// return the reply. For the non-streaming control protocol frames.
    fn query_reply(core: Arc<Core>, frame: Frame) -> Reply {
        let (client, server) = UnixStream::pair().unwrap();
        local::send_frame(&client, &frame, &[]).unwrap();
        let h = std::thread::spawn(move || handle_conn(core, server).unwrap());
        let mut client = client;
        let reply = local::recv_reply(&mut client).unwrap();
        h.join().unwrap();
        reply
    }

    fn json_body(reply: Reply) -> String {
        match reply {
            Reply::Json { body } => body,
            other => panic!("expected Reply::Json, got {other:?}"),
        }
    }

    #[test]
    fn control_read_frames_return_parseable_json() {
        // Every read/report frame must round-trip: the daemon builds a JSON body
        // that deserializes back into the matching DTO the Mac app decodes.
        let _home = HomeGuard::new("read-frames");
        let dir = tmpdir("read-frames");
        let (core, _pending) = test_core(
            &dir,
            "tok",
            "secret",
            DevMode::Approve,
            Duration::from_millis(50),
        );

        let st: crate::json::StatusJson =
            serde_json::from_str(&json_body(query_reply(core.clone(), Frame::Status))).unwrap();
        assert!(!st.socket.is_empty());

        let checks: Vec<crate::json::CheckJson> =
            serde_json::from_str(&json_body(query_reply(core.clone(), Frame::Doctor))).unwrap();
        assert!(checks
            .iter()
            .any(|c| c.label == "approving factor resolved"));

        let leases: Vec<crate::json::LeaseJson> =
            serde_json::from_str(&json_body(query_reply(core.clone(), Frame::LeaseList))).unwrap();
        assert!(leases.is_empty());

        let pend: Vec<crate::json::PendingJson> =
            serde_json::from_str(&json_body(query_reply(core.clone(), Frame::Pending))).unwrap();
        assert!(pend.is_empty());

        let hist: Vec<crate::json::HistoryJson> =
            serde_json::from_str(&json_body(query_reply(core.clone(), Frame::History))).unwrap();
        assert!(hist.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn control_approve_for_an_unknown_id_is_refused() {
        // A control client cannot conjure an approval: `Approve` only resolves a
        // genuinely-parked request. With `NullApprover`/`NoFactor` nothing ever
        // parks, so the socket can never bypass the real factor (Finding-1).
        let dir = tmpdir("approve-unknown");
        let (core, _p) = test_core(
            &dir,
            "tok",
            "secret",
            DevMode::Off,
            Duration::from_millis(50),
        );
        match query_reply(
            core,
            Frame::Approve {
                id: "not-a-real-id".into(),
                lease: false,
            },
        ) {
            Reply::Control { ok, .. } => assert!(!ok, "approving a non-pending id must fail"),
            other => panic!("unexpected {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn subscribe_pending_streams_ordered_snapshots() {
        // The live-menubar stream: emit the current snapshot, then a fresh one on
        // every change, in order. Park a request, see it appear; resolve it, see
        // it clear.
        fn read_event(client: &mut UnixStream) -> Vec<crate::json::PendingJson> {
            match local::recv_reply(client).unwrap() {
                Reply::Event { body } => serde_json::from_str(&body).unwrap(),
                other => panic!("expected Event, got {other:?}"),
            }
        }

        let dir = tmpdir("subscribe");
        let (core, pending) = test_core(
            &dir,
            "tok",
            "secret",
            DevMode::Off, // parks on the control socket and waits
            Duration::from_secs(3),
        );

        let (client, server) = UnixStream::pair().unwrap();
        local::send_frame(&client, &Frame::SubscribePending, &[]).unwrap();
        let stream_core = core.clone();
        let h = std::thread::spawn(move || {
            let _ = handle_conn(stream_core, server);
        });
        let mut client = client;

        // First event: the current (empty) snapshot.
        assert!(
            read_event(&mut client).is_empty(),
            "first snapshot is empty"
        );

        // Park a request by driving a gated fulfill on a background thread.
        let park_core = core.clone();
        let (_r, w) = pipe();
        let worker = std::thread::spawn(move || {
            let argv = vec!["op".into(), "read".into(), "op://Engineering/.env".into()];
            fulfill(&park_core, &argv, "", None, 0, None, Some(w), None)
        });

        // A subsequent event carries the parked request.
        let mut tries = 0;
        loop {
            let ev = read_event(&mut client);
            if !ev.is_empty() {
                assert_eq!(ev.len(), 1, "one parked request");
                assert_eq!(ev[0].command, vec!["op", "read", "op://Engineering/.env"]);
                break;
            }
            tries += 1;
            assert!(tries < 50, "request never appeared in the stream");
        }

        // Resolve it (deny), unblocking the worker; the stream then reports empty.
        let id = pending
            .pending_ids()
            .into_iter()
            .next()
            .expect("a parked id");
        assert!(pending.resolve(&id, Decision::Deny));
        loop {
            if read_event(&mut client).is_empty() {
                break;
            }
        }

        assert_eq!(worker.join().unwrap(), 1, "denied request fails closed");
        // Dropping the client ends the stream; the handler notices on its next
        // emit. We detach rather than join so the test does not wait out the
        // keepalive interval (a non-joined thread does not delay process exit).
        drop(client);
        drop(h);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn lease_decision_covers_the_next_identical_request() {
        let dir = tmpdir("lease");
        let (core, _) = test_core(
            &dir,
            "tok-abc",
            "secret-A",
            DevMode::Lease(Duration::from_secs(60)),
            Duration::from_millis(50),
        );

        let argv = vec!["op".into(), "read".into(), "op://Engineering/.env".into()];
        // First request approves and leases.
        let (r1, w1) = pipe();
        assert_eq!(fulfill(&core, &argv, "", None, 0, None, Some(w1), None), 0);
        assert_eq!(read_all(r1), "secret-A");
        assert_eq!(core.leases.active(), 1);

        // With a live lease the second identical request must be served from the
        // lease, not a fresh approval.
        let (r2, w2) = pipe();
        assert_eq!(fulfill(&core, &argv, "", None, 0, None, Some(w2), None), 0);
        assert_eq!(read_all(r2), "secret-A");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn denied_request_fails_closed_and_delivers_no_secret() {
        let dir = tmpdir("deny");
        // dev Off + no local resolver + short timeout -> Deny.
        let (core, _) = test_core(
            &dir,
            "tok",
            "should-not-appear",
            DevMode::Off,
            Duration::from_millis(50),
        );

        let (read_end, write_end) = pipe();
        let (err_r, err_w) = pipe();
        let argv = vec!["op".into(), "read".into(), "op://Engineering/x".into()];
        let code = fulfill(
            &core,
            &argv,
            "/p",
            None,
            0,
            None,
            Some(write_end),
            Some(err_w),
        );
        assert_eq!(code, 1, "deny must fail closed");
        assert_eq!(read_all(read_end), "", "no secret on a denied request");
        assert!(read_all(err_r).contains("denied"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn lockdown_refuses_new_requests() {
        let dir = tmpdir("lockdown");
        let (core, _) = test_core(
            &dir,
            "tok",
            "secret",
            DevMode::Approve,
            Duration::from_millis(50),
        );
        core.lockdown.store(true, Ordering::SeqCst);

        let (read_end, write_end) = pipe();
        let argv = vec!["op".into(), "read".into(), "op://Engineering/x".into()];
        assert_eq!(
            fulfill(&core, &argv, "/p", None, 0, None, Some(write_end), None),
            1
        );
        assert_eq!(read_all(read_end), "");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unconfigured_command_is_refused_with_a_config_hint() {
        // The invocation-model contract: a command with no config is never run
        // ungated; it fails closed with the exact command to configure it.
        let dir = tmpdir("unconfigured");
        let (core, _) = test_core(
            &dir,
            "tok",
            "secret",
            DevMode::Approve, // op would auto-approve, but gcloud never reaches the gate
            Duration::from_millis(50),
        );
        let (read_end, write_end) = pipe();
        let (err_r, err_w) = pipe();
        let argv = vec!["gcloud".into(), "auth".into(), "print-access-token".into()];
        let code = fulfill(
            &core,
            &argv,
            "",
            None,
            0,
            None,
            Some(write_end),
            Some(err_w),
        );
        assert_eq!(code, 1, "an unconfigured command must fail closed");
        assert_eq!(read_all(read_end), "", "and produce no output");
        let err = read_all(err_r);
        assert!(err.contains("not configured"), "err: {err}");
        assert!(err.contains("sigil-config add gcloud"), "err: {err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn env_file_command_runs_gated_and_injects_env() {
        // The direct-injection provider, end to end through the daemon: a
        // configured `env-file` command is gated, then the child sees the exact
        // KEY=VALUEs from the source file, with no account/DEK involved.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir("envcmd");
        let env_path = dir.join("s.env");
        std::fs::write(&env_path, "TOKEN=abc123\nREGION=eu\n").unwrap();
        let bindir = dir.join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let tool = bindir.join("faketool");
        std::fs::write(
            &tool,
            "#!/bin/sh\nprintf 'tok=%s region=%s' \"$TOKEN\" \"$REGION\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();

        let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());
        let pending = Arc::new(PendingRegistry::new());
        let approver = LocalApprover::new(keystore.clone(), pending.clone())
            .with_dev(DevMode::Approve)
            .with_control_socket(true);
        let config = env_file_config("faketool", env_path.to_str().unwrap());
        let core = Arc::new(Core {
            keystore,
            accounts: Mutex::new(AccountStore::default()),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            config,
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: Vec::new(),
            audit: None,
        });

        // Prepend (not replace) bindir so system binaries stay reachable for any
        // parallel test's `#!/bin/sh` helper that resolves `cat`/etc via PATH.
        let prev = std::env::var_os("PATH");
        let mut search = vec![bindir.clone()];
        if let Some(p) = &prev {
            search.extend(std::env::split_paths(p));
        }
        std::env::set_var("PATH", std::env::join_paths(search).unwrap());
        let (read_end, write_end) = pipe();
        let code = fulfill(
            &core,
            &["faketool".into()],
            "",
            None,
            0,
            None,
            Some(write_end),
            None,
        );
        match prev {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }

        assert_eq!(code, 0);
        assert_eq!(read_all(read_end), "tok=abc123 region=eu");
        // A direct-injection provider is never leased (no credential to hold in
        // RAM across a TTL), even though the decision would allow it.
        assert_eq!(core.leases.active(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A config gating `<command>` to the inline `env` provider named `<command>`
    /// with the given KEY names. The sealed values live in the account store (not
    /// here), keyed by the same name.
    fn env_inline_config(command: &str, keys: &[&str]) -> Config {
        use crate::config::{Action, Match, Rule, Source};
        let mut cfg = Config::default();
        cfg.add_source(Source {
            name: command.into(),
            provider: crate::provider::EnvProvider::ID.into(),
            account: None,
            path: None,
            keys: keys.iter().map(|k| k.to_string()).collect(),
        })
        .unwrap();
        cfg.add_rule(Rule {
            name: command.into(),
            match_: Match {
                command: Some(command.into()),
                ..Match::default()
            },
            action: Action {
                source: command.into(),
                risk: RiskLevel::Routine,
                timeout_sec: None,
            },
        })
        .unwrap();
        cfg
    }

    #[test]
    fn inline_env_command_runs_gated_and_injects_sealed_values() {
        // End to end through the daemon: a configured inline `env` command is
        // gated, the daemon opens the DEK-sealed values on approval, and the child
        // sees the exact KEY=VALUEs — no account and no lease, values only in RAM.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir("envinline");
        let bindir = dir.join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let tool = bindir.join("faketool");
        std::fs::write(
            &tool,
            "#!/bin/sh\nprintf 'tok=%s region=%s' \"$TOKEN\" \"$REGION\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();

        // Seal the values under the keystore DEK, exactly as `sigil-config source
        // env set` would, and stash the ciphertext in the account store.
        let keystore = MemoryKeystore::with_dek();
        let dek = keystore.unwrap_dek("test").unwrap();
        let pairs = vec![
            ("TOKEN".to_string(), Zeroizing::new("sealed-9".to_string())),
            ("REGION".to_string(), Zeroizing::new("eu".to_string())),
        ];
        let encoded = crate::provider::encode_env_pairs(&pairs);
        let ct = crate::secrets::encrypt_token(&dek, &encoded).unwrap();
        drop(dek);
        let mut accounts = AccountStore::default();
        accounts.set_env_blob("faketool", &ct);

        let keystore: Arc<dyn Keystore> = Arc::new(keystore);
        let pending = Arc::new(PendingRegistry::new());
        let approver = LocalApprover::new(keystore.clone(), pending.clone())
            .with_dev(DevMode::Approve)
            .with_control_socket(true);
        let core = Arc::new(Core {
            keystore,
            accounts: Mutex::new(accounts),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            config: env_inline_config("faketool", &["TOKEN", "REGION"]),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: Vec::new(),
            audit: None,
        });

        let prev = std::env::var_os("PATH");
        let mut search = vec![bindir.clone()];
        if let Some(p) = &prev {
            search.extend(std::env::split_paths(p));
        }
        std::env::set_var("PATH", std::env::join_paths(search).unwrap());
        let (read_end, write_end) = pipe();
        let code = fulfill(
            &core,
            &["faketool".into()],
            "",
            None,
            0,
            None,
            Some(write_end),
            None,
        );
        match prev {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }

        assert_eq!(code, 0);
        assert_eq!(read_all(read_end), "tok=sealed-9 region=eu");
        // Like every direct-injection shape, the inline env provider never leases.
        assert_eq!(core.leases.active(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn inline_env_with_no_sealed_values_fails_closed() {
        // A configured inline env source whose values were never set must refuse,
        // not run the child with a blank environment.
        let dir = tmpdir("envinline-empty");
        let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::with_dek());
        let pending = Arc::new(PendingRegistry::new());
        let approver = LocalApprover::new(keystore.clone(), pending.clone())
            .with_dev(DevMode::Approve)
            .with_control_socket(true);
        let core = Arc::new(Core {
            keystore,
            accounts: Mutex::new(AccountStore::default()), // no sealed blob
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            config: env_inline_config("faketool", &["TOKEN"]),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: Vec::new(),
            audit: None,
        });

        let (read_end, write_end) = pipe();
        let code = fulfill(
            &core,
            &["faketool".into()],
            "",
            None,
            0,
            None,
            Some(write_end),
            None,
        );
        assert_ne!(code, 0, "an unset inline env source must fail closed");
        assert_eq!(read_all(read_end), "", "no output on a refused run");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn caller_stdin_is_spliced_to_the_tool_child() {
        // Interactive tools must read the CALLER's stdin. Prove the fd handed to
        // fulfill reaches the child: a tool that reads a line from stdin and
        // echoes it sees exactly the bytes we wrote to the caller-side pipe. The
        // daemon only splices the fd; it never reads the bytes itself.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir("stdin-splice");
        let env_path = dir.join("s.env");
        std::fs::write(&env_path, "MARK=ok\n").unwrap();
        let bindir = dir.join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let tool = bindir.join("faketool");
        // Reads one line from stdin, echoes it back tagged so we can assert it
        // came from the caller's stdin fd (not the daemon's).
        std::fs::write(&tool, "#!/bin/sh\nread line\nprintf 'stdin=%s' \"$line\"\n").unwrap();
        std::fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();

        let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());
        let pending = Arc::new(PendingRegistry::new());
        let approver = LocalApprover::new(keystore.clone(), pending.clone())
            .with_dev(DevMode::Approve)
            .with_control_socket(true);
        let config = env_file_config("faketool", env_path.to_str().unwrap());
        let core = Arc::new(Core {
            keystore,
            accounts: Mutex::new(AccountStore::default()),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            config,
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: Vec::new(),
            audit: None,
        });

        let prev = std::env::var_os("PATH");
        let mut search = vec![bindir.clone()];
        if let Some(p) = &prev {
            search.extend(std::env::split_paths(p));
        }
        std::env::set_var("PATH", std::env::join_paths(search).unwrap());

        // The caller's stdin: write a line into the write end, hand the read end
        // to fulfill as the caller stdin fd.
        let (in_r, in_w) = pipe();
        {
            use std::io::Write as _;
            let mut w = std::fs::File::from(in_w);
            w.write_all(b"hello-from-caller\n").unwrap();
        } // drop closes the write end so the child's `read` sees EOF after the line
        let (out_r, out_w) = pipe();
        let code = fulfill(
            &core,
            &["faketool".into()],
            "",
            None,
            0,
            Some(in_r),
            Some(out_w),
            None,
        );

        match prev {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }

        assert_eq!(code, 0);
        assert_eq!(read_all(out_r), "stdin=hello-from-caller");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn proxy_depth_is_incremented_on_the_child_and_fuses_at_the_limit() {
        // The recursion fuse: the spawned child carries SIGIL_PROXY_DEPTH =
        // caller_depth + 1, and a caller already at the limit is refused before a
        // child is spawned. Prove both with an env-file faketool that echoes the
        // depth env it received.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir("proxy-depth");
        let env_path = dir.join("s.env");
        std::fs::write(&env_path, "MARK=ok\n").unwrap();
        let bindir = dir.join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let tool = bindir.join("faketool");
        std::fs::write(
            &tool,
            "#!/bin/sh\nprintf 'depth=%s' \"$SIGIL_PROXY_DEPTH\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();

        let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());
        let pending = Arc::new(PendingRegistry::new());
        let approver = LocalApprover::new(keystore.clone(), pending.clone())
            .with_dev(DevMode::Approve)
            .with_control_socket(true);
        let core = Arc::new(Core {
            keystore,
            accounts: Mutex::new(AccountStore::default()),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            config: env_file_config("faketool", env_path.to_str().unwrap()),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: Vec::new(),
            audit: None,
        });

        let prev = std::env::var_os("PATH");
        let mut search = vec![bindir.clone()];
        if let Some(p) = &prev {
            search.extend(std::env::split_paths(p));
        }
        std::env::set_var("PATH", std::env::join_paths(search).unwrap());

        // A caller at depth 5: the child must see 6.
        let (out_r, out_w) = pipe();
        let code = fulfill(
            &core,
            &["faketool".into()],
            "",
            None,
            5,
            None,
            Some(out_w),
            None,
        );
        assert_eq!(code, 0);
        assert_eq!(read_all(out_r), "depth=6");

        // A caller already at the limit is refused before any child spawns.
        let (fuse_r, fuse_w) = pipe();
        let (err_r, err_w) = pipe();
        let fused = fulfill(
            &core,
            &["faketool".into()],
            "",
            None,
            crate::proxy::MAX_DEPTH,
            None,
            Some(fuse_w),
            Some(err_w),
        );

        match prev {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }

        assert_eq!(fused, 1, "at the recursion limit the run must fail closed");
        assert_eq!(read_all(fuse_r), "", "a fused run produces no output");
        assert!(read_all(err_r).contains("recursion limit"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ssh_file_signer_signs_when_gated() {
        // The pluggable SSH signer seam through the daemon gate: a file-backed
        // signer (no account) produces a verifiable signature only after the gate
        // grants, proving Sigil is the phone-gate regardless of key source.
        let dir = tmpdir("ssh-file-signer");
        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let key_path = dir.join("id_ed25519");
        std::fs::write(&key_path, key.to_openssh(ssh_key::LineEnding::LF).unwrap()).unwrap();
        let pk = key.public_key();
        let id = ServedIdentity {
            key_blob: pk.to_bytes().unwrap(),
            comment: "tom@file".into(),
            key_ref: key_path.to_string_lossy().into_owned(),
            label: "id_ed25519".into(),
            fingerprint: pk.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        };

        let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());
        let pending = Arc::new(PendingRegistry::new());
        let approver = LocalApprover::new(keystore.clone(), pending.clone())
            .with_dev(DevMode::Approve)
            .with_control_socket(true);
        let core = Core {
            keystore,
            accounts: Mutex::new(AccountStore::default()),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            config: op_config(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: vec![Box::new(sshagent::FileSshSigner::new(vec![(
                id.clone(),
                key_path.clone(),
            )]))],
            audit: None,
        };

        // The agent advertises the file identity.
        assert_eq!(core.identities().len(), 1);

        let host = sshagent::HostContext {
            host: "(host not bound)".into(),
        };
        let data = b"gated-file-sign";
        let sig_blob = core
            .approve_and_sign(sshagent::SignRequest {
                id: &id,
                data,
                host: &host,
                caller_pid: None,
            })
            .expect("gated file-signer signature");

        // Parse the SSH signature blob (string algo + string raw_sig) and verify
        // the raw ed25519 signature against the served public key.
        fn ssh_string(buf: &[u8], pos: usize) -> (&[u8], usize) {
            let n =
                u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
            (&buf[pos + 4..pos + 4 + n], pos + 4 + n)
        }
        let (algo, p) = ssh_string(&sig_blob, 0);
        assert_eq!(algo, b"ssh-ed25519");
        let (raw, _) = ssh_string(&sig_blob, p);
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let pk_bytes = pk.key_data().ed25519().expect("ed25519 pubkey").0;
        let vk = VerifyingKey::from_bytes(&pk_bytes).unwrap();
        vk.verify(data, &Signature::from_slice(raw).unwrap())
            .expect("the gated file signature verifies");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn full_loop_over_the_socket_with_local_control_approval() {
        let dir = tmpdir("control");
        let (core, pending) = test_core(
            &dir,
            "ctl-token",
            "ctl-secret",
            DevMode::Off,
            Duration::from_secs(3),
        );

        let (client, server) = UnixStream::pair().unwrap();
        let (read_end, write_end) = pipe();
        let argv = vec!["op".into(), "read".into(), "op://Engineering/.env".into()];
        local::send_frame(
            &client,
            &Frame::Run {
                argv,
                cwd: String::new(),
                proxy_depth: 0,
            },
            &[
                std::io::stdin().as_raw_fd(),
                write_end.as_raw_fd(),
                std::io::stderr().as_raw_fd(),
            ],
        )
        .unwrap();
        drop(write_end);

        let worker_core = core.clone();
        let worker = std::thread::spawn(move || handle_conn(worker_core, server));

        // Wait for the request to park, then approve it over the control path.
        let mut tries = 0;
        let id = loop {
            let ids = pending.pending_ids();
            if let Some(id) = ids.into_iter().next() {
                break id;
            }
            std::thread::sleep(Duration::from_millis(10));
            tries += 1;
            assert!(tries < 200, "request never parked");
        };
        assert!(pending.resolve(&id, Decision::Approve));

        worker.join().unwrap().unwrap();
        assert_eq!(read_all(read_end), "ctl-secret");

        let mut client = client;
        assert_eq!(
            local::recv_reply(&mut client).unwrap(),
            Reply::Exit { code: 0 }
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- remote (phone) approval end-to-end -------------------------------
    //
    // The milestone: an approval satisfied by a PAIRED REMOTE approver (the
    // softphone) over a transport, with NO key at rest in the daemon. A request
    // flows shim -> daemon -> seal -> local transport -> softphone -> decision
    // (+ DEK on approve) -> daemon decrypts the token -> fake op -> the secret
    // reaches the caller's fd. Nothing here uses the local keystore's DEK; the
    // daemon's keystore is a fresh MemoryKeystore with no DEK provisioned.

    use crate::remote::RemoteApprover;
    use sigil_proto::identity::DeviceIdentity;
    use sigil_proto::pairing::{DaemonPairing, Dek as ProtoDek};
    use sigil_proto::{LocalRelay, PairingState};
    use sigil_relay_client::{DaemonRelay, PhoneRelay};
    use sigil_softphone::{Pairing, Policy, Softphone};
    use zeroize::Zeroizing;

    const REMOTE_NOW: u64 = 1_720_000_000_000;

    fn clone_device(id: &DeviceIdentity) -> DeviceIdentity {
        DeviceIdentity {
            signing: id.signing.clone(),
            agreement: id.agreement.clone(),
        }
    }

    /// Pair a softphone to a fresh daemon identity in-process and return the
    /// pieces the daemon side needs: the daemon identity (for the approver), the
    /// paired softphone (holding the DEK), and the raw 32-byte DEK (so the test
    /// can seal the account token under the same key).
    fn pair_softphone(policy: Policy) -> (DeviceIdentity, Softphone, [u8; 32]) {
        let daemon_id = DeviceIdentity::generate();
        let daemon_for_approver = clone_device(&daemon_id);
        let (mut daemon, payload) =
            DaemonPairing::mint(daemon_id, vec!["lan://sigil.local:4823".into()], REMOTE_NOW);

        let phone_id = DeviceIdentity::generate();
        let (mut pairing, resp) =
            Pairing::scan_payload(phone_id, payload, REMOTE_NOW + 1_000, policy).unwrap();
        daemon.receive_response(&resp, REMOTE_NOW + 2_000).unwrap();
        assert_eq!(daemon.sas_words().unwrap(), pairing.sas_words());
        daemon.confirm().unwrap();
        pairing.confirm().unwrap();

        // The one DEK: delivered to the phone via pairing, and (below) used to
        // seal the account token so the phone-returned key decrypts it.
        let dek_bytes = *ProtoDek::generate().as_bytes();
        let env = daemon
            .deliver_dek(&ProtoDek::from_bytes(dek_bytes), 1)
            .unwrap();
        assert_eq!(daemon.state(), PairingState::DekDelivered);
        let softphone = pairing.receive_dek(&env).unwrap();

        (daemon_for_approver, softphone, dek_bytes)
    }

    /// Build an inert daemon core whose approval gate is a [`RemoteApprover`]
    /// wired to `transport` (any [`Transport`]: the in-process [`LocalRelay`] or
    /// the real [`DaemonRelay`]), with the account token sealed under `dek_bytes`.
    #[allow(clippy::too_many_arguments)] // a test helper; each arg is a distinct fixture
    fn remote_core(
        dir: &Path,
        daemon_id: DeviceIdentity,
        phone: sigil_proto::PeerIdentity,
        transport: Arc<dyn sigil_proto::Transport>,
        timeout: Duration,
        dek_bytes: [u8; 32],
        token: &str,
        secret: &str,
    ) -> Arc<Core> {
        // The account store: token ciphertext sealed under the shared DEK. The
        // daemon holds NO DEK of its own.
        let sealing_dek: crate::secrets::Dek = Zeroizing::new(dek_bytes);
        let mut accounts = AccountStore::default();
        accounts
            .add(
                "Rowm",
                &sealing_dek,
                token.as_bytes(),
                vec!["Engineering".into()],
            )
            .unwrap();

        let approver = RemoteApprover::new(transport, daemon_id, phone).with_timeout(timeout);
        let pending = Arc::new(PendingRegistry::new());
        Arc::new(Core {
            keystore: Arc::new(MemoryKeystore::new()), // no DEK at rest
            accounts: Mutex::new(accounts),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::new(vec![Box::new(OpProvider::with_binary(
                write_fake_op(dir, token, secret),
            ))]),
            config: op_config(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::Phone,
            ssh_signers: Vec::new(),
            audit: None,
        })
    }

    /// Run the softphone's serve loop on a background thread until the returned
    /// flag is set. Returns the flag and the join handle.
    fn spawn_approver(
        softphone: Arc<Softphone>,
        relay: LocalRelay,
    ) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let handle = std::thread::spawn(move || {
            softphone.serve(&relay, &stop, Duration::from_millis(25));
        });
        (shutdown, handle)
    }

    #[test]
    fn remote_softphone_approval_delivers_secret_over_the_socket() {
        let dir = tmpdir("remote-approve");
        let relay = LocalRelay::new();
        let (daemon_id, softphone, dek_bytes) = pair_softphone(Policy::Approve);
        let phone_pub = softphone.phone_identity();
        let mailbox = softphone.mailbox();

        let core = remote_core(
            &dir,
            daemon_id,
            phone_pub,
            Arc::new(relay.clone()),
            Duration::from_secs(3),
            dek_bytes,
            "remote-token-xyz",
            "remote-secret-99",
        );

        let softphone = Arc::new(softphone);
        let (shutdown, approver_thread) = spawn_approver(softphone.clone(), relay.clone());

        // Drive a full op request over the socket, exactly like the shim would.
        let (client, server) = UnixStream::pair().unwrap();
        let (read_end, write_end) = pipe();
        let (err_r, err_w) = pipe();
        let argv = vec![
            "op".into(),
            "read".into(),
            "op://Engineering/.env/password".into(),
        ];
        local::send_frame(
            &client,
            &Frame::Run {
                argv,
                cwd: String::new(),
                proxy_depth: 0,
            },
            &[
                std::io::stdin().as_raw_fd(),
                write_end.as_raw_fd(),
                err_w.as_raw_fd(),
            ],
        )
        .unwrap();
        drop(write_end);
        drop(err_w);

        let worker = std::thread::spawn(move || handle_conn(core, server));
        worker.join().unwrap().unwrap();

        // The secret reached the caller's stdout fd, and only via the phone's DEK.
        assert_eq!(read_all(read_end), "remote-secret-99");
        let mut client = client;
        assert_eq!(
            local::recv_reply(&mut client).unwrap(),
            Reply::Exit { code: 0 }
        );

        // The phone->daemon queue is drained; nothing left buffered.
        assert_eq!(
            relay.depth(mailbox, sigil_proto::Direction::ToDaemon),
            0,
            "the response was consumed by the daemon"
        );
        let _ = err_r;

        shutdown.store(true, Ordering::SeqCst);
        approver_thread.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remote_softphone_denial_fails_closed_with_no_secret() {
        let dir = tmpdir("remote-deny");
        let relay = LocalRelay::new();
        let (daemon_id, softphone, dek_bytes) = pair_softphone(Policy::Deny);
        let phone_pub = softphone.phone_identity();

        let core = remote_core(
            &dir,
            daemon_id,
            phone_pub,
            Arc::new(relay.clone()),
            Duration::from_secs(3),
            dek_bytes,
            "tok",
            "should-never-appear",
        );

        let softphone = Arc::new(softphone);
        let (shutdown, approver_thread) = spawn_approver(softphone.clone(), relay.clone());

        let (read_end, write_end) = pipe();
        let (err_r, err_w) = pipe();
        let argv = vec![
            "op".into(),
            "read".into(),
            "op://Engineering/.env/password".into(),
        ];
        let code = fulfill(
            &core,
            &argv,
            "",
            None,
            0,
            None,
            Some(write_end),
            Some(err_w),
        );

        assert_eq!(code, 1, "a remote denial must fail closed");
        assert_eq!(read_all(read_end), "", "no secret on a denied request");
        assert!(read_all(err_r).contains("denied"));

        shutdown.store(true, Ordering::SeqCst);
        approver_thread.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- v2 threshold: the full daemon round trip over the socket ----------

    /// Pair a softphone as in [`pair_softphone`], then attach a software
    /// Secure-Enclave threshold share `f` to it (standing in for the real
    /// enclave). Returns the daemon identity, the v2-capable softphone, the
    /// public share `F` (ANSI X9.63) for the daemon to pin, and the SE key id.
    fn pair_softphone_v2(
        policy: Policy,
    ) -> (
        DeviceIdentity,
        Softphone,
        [u8; sigil_proto::threshold::P256_X963_POINT_LEN],
        &'static str,
    ) {
        let (daemon_for_approver, softphone, _dek) = pair_softphone(policy);
        let f = sigil_proto::threshold::MacShare::generate();
        let se_key_id = "se-key-1";
        let softphone = softphone.with_phone_share(f, se_key_id);
        let f_x963 = softphone
            .phone_share_x963()
            .expect("softphone holds an SE share");
        (daemon_for_approver, softphone, f_x963, se_key_id)
    }

    /// An inert daemon core whose one account is a **v2 threshold** account: the
    /// token is sealed under `K = combine(Z_M, Z_F, E, id)`, the Mac share `m` is
    /// generated into the (memory) keystore, and the record is held in the core's
    /// threshold store. The daemon holds NO DEK and no phone secret.
    #[allow(clippy::too_many_arguments)]
    fn remote_core_v2(
        dir: &Path,
        daemon_id: DeviceIdentity,
        phone: sigil_proto::PeerIdentity,
        transport: Arc<dyn sigil_proto::Transport>,
        timeout: Duration,
        f_x963: &[u8],
        se_key_id: &str,
        token: &str,
        secret: &str,
    ) -> Arc<Core> {
        let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());
        // Mint/seal the Mac share m in the keystore, then seal the token to
        // (m, F) as a v2 record and persist it to the threshold store on disk.
        let m = crate::threshold::load_or_create_mac_share(keystore.as_ref()).unwrap();
        let phone_share = crate::threshold::PhoneShare::from_x963(
            se_key_id,
            f_x963,
            sigil_proto::threshold::EcdhAlgo::RawX,
        )
        .unwrap();
        let mut store = crate::threshold::ThresholdStore::default();
        crate::threshold::seal_account(
            &mut store,
            "Rowm",
            &m,
            &phone_share,
            token.as_bytes(),
            vec!["Engineering".into()],
        )
        .unwrap();
        drop(m);

        let approver = RemoteApprover::new(transport, daemon_id, phone).with_timeout(timeout);
        Arc::new(Core {
            keystore,                                      // holds m (sealed); NO DEK
            accounts: Mutex::new(AccountStore::default()), // no v1 accounts
            threshold: Mutex::new(store),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending: Arc::new(PendingRegistry::new()),
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::new(vec![Box::new(OpProvider::with_binary(
                write_fake_op(dir, token, secret),
            ))]),
            config: op_config(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::Phone,
            ssh_signers: Vec::new(),
            audit: None,
        })
    }

    #[test]
    fn remote_v2_threshold_approval_decrypts_via_two_party_combine() {
        // The headline v2 loop: the phone contributes Z_F = x(f·E) under its
        // policy, the daemon combines it with its Mac share m to derive K, and the
        // token reaches the caller's fd. No DEK exists anywhere; e was destroyed at
        // account-add, so only the two parties together can open the token.
        let _home = HomeGuard::new("remote-v2");
        let dir = tmpdir("remote-v2");
        let relay = LocalRelay::new();
        let (daemon_id, softphone, f_x963, se_key_id) = pair_softphone_v2(Policy::Approve);
        let phone_pub = softphone.phone_identity();
        let mailbox = softphone.mailbox();

        let core = remote_core_v2(
            &dir,
            daemon_id,
            phone_pub,
            Arc::new(relay.clone()),
            Duration::from_secs(3),
            &f_x963,
            se_key_id,
            "v2-token-xyz",
            "v2-secret-99",
        );

        let softphone = Arc::new(softphone);
        let (shutdown, approver_thread) = spawn_approver(softphone.clone(), relay.clone());

        let (client, server) = UnixStream::pair().unwrap();
        let (read_end, write_end) = pipe();
        let (err_r, err_w) = pipe();
        let argv = vec![
            "op".into(),
            "read".into(),
            "op://Engineering/.env/password".into(),
        ];
        local::send_frame(
            &client,
            &Frame::Run {
                argv,
                cwd: String::new(),
                proxy_depth: 0,
            },
            &[
                std::io::stdin().as_raw_fd(),
                write_end.as_raw_fd(),
                err_w.as_raw_fd(),
            ],
        )
        .unwrap();
        drop(write_end);
        drop(err_w);

        let worker = std::thread::spawn(move || handle_conn(core, server));
        worker.join().unwrap().unwrap();

        // The secret reached the caller, and only via the two-party combine.
        assert_eq!(read_all(read_end), "v2-secret-99");
        let mut client = client;
        assert_eq!(
            local::recv_reply(&mut client).unwrap(),
            Reply::Exit { code: 0 }
        );
        assert_eq!(
            relay.depth(mailbox, sigil_proto::Direction::ToDaemon),
            0,
            "the v2 partial response was consumed by the daemon"
        );
        let _ = err_r;

        shutdown.store(true, Ordering::SeqCst);
        approver_thread.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remote_v2_denial_fails_closed_with_no_secret() {
        // A v2 deny carries no partial, so the combine cannot run: fail closed.
        let _home = HomeGuard::new("remote-v2-deny");
        let dir = tmpdir("remote-v2-deny");
        let relay = LocalRelay::new();
        let (daemon_id, softphone, f_x963, se_key_id) = pair_softphone_v2(Policy::Deny);
        let phone_pub = softphone.phone_identity();

        let core = remote_core_v2(
            &dir,
            daemon_id,
            phone_pub,
            Arc::new(relay.clone()),
            Duration::from_secs(3),
            &f_x963,
            se_key_id,
            "tok",
            "should-never-appear",
        );

        let softphone = Arc::new(softphone);
        let (shutdown, approver_thread) = spawn_approver(softphone.clone(), relay.clone());

        let (read_end, write_end) = pipe();
        let (err_r, err_w) = pipe();
        let argv = vec![
            "op".into(),
            "read".into(),
            "op://Engineering/.env/password".into(),
        ];
        let code = fulfill(
            &core,
            &argv,
            "",
            None,
            0,
            None,
            Some(write_end),
            Some(err_w),
        );
        assert_eq!(code, 1, "a v2 denial must fail closed");
        assert_eq!(read_all(read_end), "", "no secret on a denied v2 request");
        assert!(read_all(err_r).contains("denied"));

        shutdown.store(true, Ordering::SeqCst);
        approver_thread.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A fake `op` that echoes whatever token reached its env, so a test can
    /// assert which account's token was injected on each route.
    fn write_echo_op(dir: &Path) -> PathBuf {
        let path = dir.join("op");
        std::fs::write(
            &path,
            "#!/bin/sh\nprintf '%s' \"$OP_SERVICE_ACCOUNT_TOKEN\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn v1_and_v2_accounts_coexist_and_each_takes_its_own_path() {
        // The migration invariant (R3): a v1 account still decrypts via the DEK
        // path while a v2 account in the same store decrypts via the two-party
        // combine. The path is chosen by the at-rest record, and one paired phone
        // (holding both the DEK and the SE share f) answers either kind.
        use sigil_proto::threshold::{EcdhAlgo, MacShare};

        let dir = tmpdir("remote-mixed");
        let relay = LocalRelay::new();
        let (daemon_id, softphone, dek_bytes) = pair_softphone(Policy::Approve);
        let f = MacShare::generate();
        let se_key_id = "se-key-1";
        let softphone = softphone.with_phone_share(f, se_key_id);
        let f_x963 = softphone.phone_share_x963().unwrap();
        let phone_pub = softphone.phone_identity();

        // v1 account "Legacy", token sealed under the phone-delivered DEK.
        let sealing_dek: crate::secrets::Dek = Zeroizing::new(dek_bytes);
        let mut accounts = AccountStore::default();
        accounts
            .add("Legacy", &sealing_dek, b"v1-token", vec!["Legacy".into()])
            .unwrap();

        // v2 account "Rowm", token sealed under (m, F).
        let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());
        let m = crate::threshold::load_or_create_mac_share(keystore.as_ref()).unwrap();
        let phone_share =
            crate::threshold::PhoneShare::from_x963(se_key_id, &f_x963, EcdhAlgo::RawX).unwrap();
        let mut tstore = crate::threshold::ThresholdStore::default();
        crate::threshold::seal_account(
            &mut tstore,
            "Rowm",
            &m,
            &phone_share,
            b"v2-token",
            vec!["Engineering".into()],
        )
        .unwrap();
        drop(m);

        let approver = RemoteApprover::new(Arc::new(relay.clone()), daemon_id, phone_pub)
            .with_timeout(Duration::from_secs(3));
        let core = Arc::new(Core {
            keystore,
            accounts: Mutex::new(accounts),
            threshold: Mutex::new(tstore),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending: Arc::new(PendingRegistry::new()),
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::new(vec![Box::new(OpProvider::with_binary(
                write_echo_op(&dir),
            ))]),
            config: coexist_config(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::Phone,
            ssh_signers: Vec::new(),
            audit: None,
        });

        let softphone = Arc::new(softphone);
        let (shutdown, approver_thread) = spawn_approver(softphone.clone(), relay.clone());

        // The v2 vault routes through the threshold combine → the v2 token.
        let (r2, w2) = pipe();
        let v2_argv = vec![
            "op".into(),
            "read".into(),
            "--vault".into(),
            "Engineering".into(),
            "op://Engineering/x".into(),
        ];
        assert_eq!(
            fulfill(&core, &v2_argv, "", None, 0, None, Some(w2), None),
            0
        );
        assert_eq!(
            read_all(r2),
            "v2-token",
            "v2 vault must use the combine path"
        );

        // The v1 vault routes through the DEK path → the v1 token.
        let (r1, w1) = pipe();
        let v1_argv = vec![
            "op".into(),
            "read".into(),
            "--vault".into(),
            "Legacy".into(),
            "op://Legacy/x".into(),
        ];
        assert_eq!(
            fulfill(&core, &v1_argv, "", None, 0, None, Some(w1), None),
            0
        );
        assert_eq!(read_all(r1), "v1-token", "v1 vault must use the DEK path");

        shutdown.store(true, Ordering::SeqCst);
        approver_thread.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remote_pairing_config_derives_the_shared_mailbox() {
        // The persisted phone-factor config must derive the exact mailbox both
        // devices route on, so `build_gate(Factor::Phone, ..)` attaches to the
        // right relay queue. This also constructs the config type end to end.
        let (daemon_id, softphone, _dek) = pair_softphone(Policy::Approve);
        let cfg = RemotePairingConfig {
            relay_url: "https://relay.example".into(),
            daemon_identity: daemon_id,
            phone: softphone.phone_identity(),
            phone_share: None,
        };
        assert_eq!(cfg.mailbox(), softphone.mailbox());
    }

    // --- the FULL cross-process loop over the REAL relay -------------------
    //
    // Same milestone as `remote_softphone_approval_delivers_secret_over_the_socket`,
    // but the envelopes traverse the real blind relay (the Bun server) over plain
    // HTTP instead of the in-process LocalRelay: the daemon deposits/drains its
    // mailbox slots (`DaemonRelay`) and the softphone deposits/drains the mirror
    // (`PhoneRelay`). Pairing is done in-process (out-of-band by design); only
    // the post-pairing approval round trip is carried by the relay.

    /// A spawned Bun relay process, killed on drop.
    struct RelayServer(std::process::Child);
    impl Drop for RelayServer {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A free loopback TCP port (bind :0, read the port, release it).
    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// Locate the `bun` binary: `$BUN_PATH`, then `PATH`, then `~/.bun/bin/bun`.
    fn which_bun() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("BUN_PATH") {
            return Some(PathBuf::from(p));
        }
        if let Some(path) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path) {
                let cand = dir.join("bun");
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }
        let home = std::env::var_os("HOME")?;
        let cand = Path::new(&home).join(".bun/bin/bun");
        cand.is_file().then_some(cand)
    }

    /// Spawn the Bun relay on a specific loopback `port` and wait for it to
    /// accept connections. Returns `None` if `bun` or the server script is
    /// missing, or the port never came up.
    fn bun_relay_on(port: u16) -> Option<RelayServer> {
        let bun = which_bun()?;
        let server = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../relay/bun/server.ts");
        if !server.exists() {
            return None;
        }
        let child = std::process::Command::new(bun)
            .arg("run")
            .arg(&server)
            .env("PORT", port.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        let guard = RelayServer(child);
        for _ in 0..100 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Some(guard);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }

    /// Resolve a relay base URL for the e2e test. Prefers `$SIGIL_TEST_RELAY_URL`
    /// (an already-running relay); otherwise spawns the Bun relay if `bun` is
    /// available. Returns `None` to soft-skip when no relay can be obtained.
    fn obtain_relay() -> Option<(String, Option<RelayServer>)> {
        if let Ok(url) = std::env::var("SIGIL_TEST_RELAY_URL") {
            return Some((url, None));
        }
        let port = free_port();
        let guard = bun_relay_on(port)?;
        Some((format!("http://127.0.0.1:{port}"), Some(guard)))
    }

    #[test]
    #[cfg_attr(
        not(feature = "real-relay"),
        ignore = "spawns an external bun relay; run: cargo test -p sigil --features real-relay -- --test-threads=1"
    )]
    fn remote_approval_over_the_real_relay_delivers_the_secret() {
        let Some((base, _server)) = obtain_relay() else {
            eprintln!(
                "SKIPPED remote_approval_over_the_real_relay_delivers_the_secret: no relay. \
                 Install bun, or start one and set SIGIL_TEST_RELAY_URL, e.g.\n  \
                 PORT=8787 bun run relay/bun/server.ts   (then SIGIL_TEST_RELAY_URL=http://127.0.0.1:8787)"
            );
            return;
        };

        let dir = tmpdir("real-relay");
        let (daemon_id, softphone, dek_bytes) = pair_softphone(Policy::Approve);
        let phone_pub = softphone.phone_identity();
        let mailbox = softphone.mailbox();

        // The phone-factor config the daemon would load derives the same mailbox.
        let cfg = RemotePairingConfig {
            relay_url: base.clone(),
            daemon_identity: clone_device(&daemon_id),
            phone: phone_pub,
            phone_share: None,
        };
        assert_eq!(cfg.mailbox(), mailbox);

        // Daemon side: RemoteApprover over the real HTTP relay. No dev flag,
        // no biometric: the paired phone is the real approving factor.
        let daemon_relay = DaemonRelay::new(&base, mailbox).expect("daemon http client");
        let core = remote_core(
            &dir,
            daemon_id,
            phone_pub,
            Arc::new(daemon_relay),
            Duration::from_secs(10),
            dek_bytes,
            "real-token-abc",
            "real-secret-77",
        );
        // The inert-daemon invariant: no DEK at rest; it arrives per-approval.
        assert!(!core.keystore.has_dek(), "daemon holds no DEK at rest");

        // Phone side: the softphone serves over the real HTTP transport.
        let phone_relay = PhoneRelay::new(&base, mailbox)
            .expect("phone transport")
            .with_poll_interval(Duration::from_millis(50));
        let softphone = Arc::new(softphone);
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let phone_thread = {
            let sp = softphone.clone();
            std::thread::spawn(move || sp.serve(&phone_relay, &stop, Duration::from_millis(200)))
        };

        // Drive one op request over the socket, exactly like the shim would.
        let (client, server) = UnixStream::pair().unwrap();
        let (read_end, write_end) = pipe();
        let (err_r, err_w) = pipe();
        let argv = vec![
            "op".into(),
            "read".into(),
            "op://Engineering/.env/password".into(),
        ];
        local::send_frame(
            &client,
            &Frame::Run {
                argv,
                cwd: String::new(),
                proxy_depth: 0,
            },
            &[
                std::io::stdin().as_raw_fd(),
                write_end.as_raw_fd(),
                err_w.as_raw_fd(),
            ],
        )
        .unwrap();
        drop(write_end);
        drop(err_w);

        let worker = std::thread::spawn(move || handle_conn(core, server));
        worker.join().unwrap().unwrap();

        // The secret reached the caller's stdout fd, carried end to end by the
        // real relay and unsealed only via the phone-delivered DEK.
        assert_eq!(
            read_all(read_end),
            "real-secret-77",
            "the secret arrived over the real relay"
        );
        let mut client = client;
        assert_eq!(
            local::recv_reply(&mut client).unwrap(),
            Reply::Exit { code: 0 }
        );
        let _ = err_r;

        shutdown.store(true, Ordering::SeqCst);
        phone_thread.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg_attr(
        not(feature = "real-relay"),
        ignore = "spawns an external bun relay; run: cargo test -p sigil --features real-relay -- --test-threads=1"
    )]
    fn daemon_relay_resumes_after_the_relay_is_bounced() {
        // Relay restart tolerance: build the daemon client, drop the relay out
        // from under it, bring a fresh relay up on the same port, and prove the
        // approval loop still completes. The v4 client is connectionless (each
        // deposit/drain is its own HTTP request), so it transparently works
        // against the fresh instance with no reconnect state to rebuild.
        // Only runnable when we control the relay process (spawn path).
        if std::env::var("SIGIL_TEST_RELAY_URL").is_ok() {
            eprintln!("SKIPPED daemon_relay_resumes_after_the_relay_is_bounced: needs a bounceable relay (unset SIGIL_TEST_RELAY_URL)");
            return;
        }
        let port = free_port();
        let Some(server1) = bun_relay_on(port) else {
            eprintln!("SKIPPED daemon_relay_resumes_after_the_relay_is_bounced: bun not available");
            return;
        };
        let base = format!("http://127.0.0.1:{port}");

        let dir = tmpdir("relay-bounce");
        let (daemon_id, softphone, dek_bytes) = pair_softphone(Policy::Approve);
        let phone_pub = softphone.phone_identity();
        let mailbox = softphone.mailbox();

        // Point the daemon at the relay and let the first deposit through.
        let daemon_relay = DaemonRelay::new(&base, mailbox).expect("daemon http client");
        std::thread::sleep(Duration::from_millis(400));

        // Bounce the relay: drop the old process, start a fresh one on the port.
        drop(server1);
        std::thread::sleep(Duration::from_millis(200));
        let _server2 = bun_relay_on(port).expect("relay restart on the same port");

        // Generous timeout to absorb reconnect backoff.
        let core = remote_core(
            &dir,
            daemon_id,
            phone_pub,
            Arc::new(daemon_relay),
            Duration::from_secs(20),
            dek_bytes,
            "bounce-token",
            "bounce-secret-55",
        );

        let phone_relay = PhoneRelay::new(&base, mailbox)
            .expect("phone transport")
            .with_poll_interval(Duration::from_millis(50));
        let softphone = Arc::new(softphone);
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let phone_thread = {
            let sp = softphone.clone();
            std::thread::spawn(move || sp.serve(&phone_relay, &stop, Duration::from_millis(200)))
        };

        let (read_end, write_end) = pipe();
        let argv = vec![
            "op".into(),
            "read".into(),
            "op://Engineering/.env/password".into(),
        ];
        let code = fulfill(&core, &argv, "", None, 0, None, Some(write_end), None);

        assert_eq!(code, 0, "the loop must complete after a relay bounce");
        assert_eq!(read_all(read_end), "bounce-secret-55");

        shutdown.store(true, Ordering::SeqCst);
        phone_thread.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Build a core armed with the given `factor` and gate, holding one account
    /// whose token decrypts to `token`. Used to exercise the arm-time factor
    /// policy (residual #1) directly.
    fn factor_core(dir: &Path, token: &str, secret: &str, factor: Factor) -> Arc<Core> {
        let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::with_dek());
        let dek = keystore.unwrap_dek("seed").unwrap();
        let mut accounts = AccountStore::default();
        accounts
            .add("Rowm", &dek, token.as_bytes(), vec!["Engineering".into()])
            .unwrap();
        drop(dek);
        let pending = Arc::new(PendingRegistry::new());
        let gate = build_gate(factor, None, &keystore, &pending).unwrap();
        Arc::new(Core {
            keystore,
            accounts: Mutex::new(accounts),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate,
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::new(vec![Box::new(OpProvider::with_binary(
                write_fake_op(dir, token, secret),
            ))]),
            config: op_config(),
            lease_ttl: Duration::from_secs(60),
            factor,
            ssh_signers: Vec::new(),
            audit: None,
        })
    }

    #[test]
    fn no_factor_daemon_fails_closed_on_a_gated_request() {
        // The residual-#1 mitigation: no paired phone, no biometric, and no
        // --dev-insecure resolves to Factor::NoFactor. A gated request must be
        // refused, never silently self-approved over the control socket.
        let dir = tmpdir("no-factor");
        let core = factor_core(&dir, "tok", "should-never-appear", Factor::NoFactor);
        assert_eq!(core.factor, Factor::NoFactor);

        let (read_end, write_end) = pipe();
        let (err_r, err_w) = pipe();
        let argv = vec!["op".into(), "read".into(), "op://Engineering/x".into()];
        let code = fulfill(
            &core,
            &argv,
            "/p",
            None,
            0,
            None,
            Some(write_end),
            Some(err_w),
        );

        assert_eq!(code, 1, "a daemon with no factor must fail closed");
        assert_eq!(read_all(read_end), "", "no secret without a real factor");
        assert!(read_all(err_r).contains("denied"));
        assert_eq!(core.leases.active(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- pairing persistence -> phone factor (task #11) --------------------

    use crate::pairing_store::{self, NewPairing};

    /// A private SIGIL_HOME for one test, restored on drop. Isolates the
    /// `pairing.json` location from the real `~/.sigil` and other tests.
    struct HomeGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        prev: Option<std::ffi::OsString>,
        dir: PathBuf,
    }
    impl HomeGuard {
        fn new(tag: &str) -> Self {
            let lock = crate::TEST_ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let dir = std::env::temp_dir().join(format!(
                "sigil-daemon-home-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let prev = std::env::var_os("SIGIL_HOME");
            std::env::set_var("SIGIL_HOME", &dir);
            Self {
                _lock: lock,
                prev,
                dir,
            }
        }
    }
    impl Drop for HomeGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var("SIGIL_HOME", v),
                None => std::env::remove_var("SIGIL_HOME"),
            }
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    fn sas_of(
        daemon: &sigil_proto::PeerIdentity,
        phone: &sigil_proto::PeerIdentity,
    ) -> [String; 6] {
        let w = sigil_proto::fingerprint_words(daemon, phone);
        std::array::from_fn(|i| w[i].to_string())
    }

    #[test]
    fn build_gate_selects_the_phone_approver_from_a_persisted_config() {
        // The wiring the whole task turns on: a RemotePairingConfig (such as
        // `load_remote_pairing` reconstructs) drives `build_gate` to the phone
        // approver with no DEK at rest. No relay is dialed synchronously, so this
        // needs no network.
        let (daemon_id, softphone, _dek) = pair_softphone(Policy::Approve);
        let cfg = RemotePairingConfig {
            relay_url: "ws://127.0.0.1:1".into(),
            daemon_identity: daemon_id,
            phone: softphone.phone_identity(),
            phone_share: None,
        };
        let ks: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());
        let pending = Arc::new(PendingRegistry::new());
        // Factor resolution: a present pairing means phone_paired -> Factor::Phone.
        assert_eq!(
            factor::resolve(&factor::ArmInputs {
                dev_insecure: true,
                phone_paired: true,
                biometric: true,
            }),
            Factor::Phone
        );
        // And the gate builds the phone approver from the config.
        let gate = build_gate(Factor::Phone, Some(cfg), &ks, &pending).unwrap();
        let _ = gate; // constructed without a DEK at rest: inert.
        assert!(!ks.has_dek());
    }

    #[test]
    fn persisted_pairing_reloads_and_stays_inert_at_rest() {
        let _home = HomeGuard::new("reload-inert");
        // One keystore instance stands in for the login Keychain across save and
        // load (both go through the same trait object here).
        let ks: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());

        let (daemon_id, softphone, _dek) = pair_softphone(Policy::Approve);
        let daemon_pub = daemon_id.peer_identity();
        let phone = softphone.phone_identity();
        let np = NewPairing {
            daemon_identity: daemon_id,
            phone,
            relay_url: "ws://127.0.0.1:1".into(),
            sas_words: sas_of(&daemon_pub, &phone),
            paired_at: REMOTE_NOW,
            phone_share: None,
        };
        pairing_store::save(ks.as_ref(), &np).unwrap();

        // Reload: the config reconstructs the daemon identity and pins the phone.
        let cfg = pairing_store::load(ks.as_ref())
            .unwrap()
            .expect("a pairing was saved");
        assert_eq!(cfg.daemon_identity.peer_identity(), daemon_pub);
        assert_eq!(cfg.phone, phone);
        assert_eq!(cfg.mailbox(), softphone.mailbox());

        // Inert at rest: nothing persisted lets the daemon produce a DEK. The
        // keystore holds only the daemon identity blob, never a DEK.
        assert!(!ks.has_dek(), "no DEK is persisted by pairing");
    }

    #[test]
    #[cfg_attr(
        not(feature = "real-relay"),
        ignore = "spawns an external bun relay; run: cargo test -p sigil --features real-relay -- --test-threads=1"
    )]
    fn reloaded_pairing_serves_a_secret_over_the_real_relay() {
        // The end-to-end proof of the critical path: persist a pairing, reload
        // it from disk, and use the RELOADED daemon identity to satisfy a real
        // op request via the phone over the real relay — with NO DEK at rest. The
        // reloaded identity must still sign requests the phone verifies and open
        // the phone's sealed response.
        let Some((base, _server)) = obtain_relay() else {
            eprintln!(
                "SKIPPED reloaded_pairing_serves_a_secret_over_the_real_relay: no relay. \
                 Install bun, or set SIGIL_TEST_RELAY_URL."
            );
            return;
        };
        let _home = HomeGuard::new("reload-e2e");
        let ks: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());

        let (daemon_id, softphone, dek_bytes) = pair_softphone(Policy::Approve);
        let daemon_pub = daemon_id.peer_identity();
        let phone_pub = softphone.phone_identity();
        let mailbox = softphone.mailbox();

        // Persist, then reload the daemon identity from disk.
        let np = NewPairing {
            daemon_identity: daemon_id,
            phone: phone_pub,
            relay_url: base.clone(),
            sas_words: sas_of(&daemon_pub, &phone_pub),
            paired_at: REMOTE_NOW,
            phone_share: None,
        };
        pairing_store::save(ks.as_ref(), &np).unwrap();
        let cfg = pairing_store::load(ks.as_ref()).unwrap().expect("saved");
        assert_eq!(cfg.mailbox(), mailbox);

        // Daemon side: RemoteApprover over the real WS, keyed by the RELOADED
        // identity. The account token is sealed under the phone-held DEK; the
        // daemon holds none.
        let dir = tmpdir("reload-relay");
        let daemon_relay = DaemonRelay::new(&base, mailbox).expect("daemon http client");
        let core = remote_core(
            &dir,
            cfg.daemon_identity,
            cfg.phone,
            Arc::new(daemon_relay),
            Duration::from_secs(10),
            dek_bytes,
            "reload-token-abc",
            "reload-secret-88",
        );
        assert!(!core.keystore.has_dek(), "daemon holds no DEK at rest");

        // Phone side over the real HTTP transport.
        let phone_relay = PhoneRelay::new(&base, mailbox)
            .expect("phone transport")
            .with_poll_interval(Duration::from_millis(50));
        let softphone = Arc::new(softphone);
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let phone_thread = {
            let sp = softphone.clone();
            std::thread::spawn(move || sp.serve(&phone_relay, &stop, Duration::from_millis(200)))
        };

        let (client, server) = UnixStream::pair().unwrap();
        let (read_end, write_end) = pipe();
        let argv = vec![
            "op".into(),
            "read".into(),
            "op://Engineering/.env/password".into(),
        ];
        local::send_frame(
            &client,
            &Frame::Run {
                argv,
                cwd: String::new(),
                proxy_depth: 0,
            },
            &[
                std::io::stdin().as_raw_fd(),
                write_end.as_raw_fd(),
                std::io::stderr().as_raw_fd(),
            ],
        )
        .unwrap();
        drop(write_end);

        let worker = std::thread::spawn(move || handle_conn(core, server));
        worker.join().unwrap().unwrap();

        assert_eq!(
            read_all(read_end),
            "reload-secret-88",
            "the reloaded pairing served the secret over the relay"
        );

        shutdown.store(true, Ordering::SeqCst);
        phone_thread.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg_attr(
        not(feature = "real-relay"),
        ignore = "spawns an external bun relay; run: cargo test -p sigil --features real-relay -- --test-threads=1"
    )]
    fn sigil_pair_completes_the_ceremony_over_the_real_relay() {
        // Drive the real `sigil pair` ceremony end to end over the blind relay:
        // the daemon side uses the HTTP rendezvous (`Rendezvous::daemon` via
        // `pair::relay_channel`), the phone side the mirror (`Rendezvous::phone`),
        // and they meet on the rendezvous mailbox. Proves the pairing transport,
        // the message framing, and the QR round-trip against a real relay process.
        let Some((base, _server)) = obtain_relay() else {
            eprintln!(
                "SKIPPED sigil_pair_completes_the_ceremony_over_the_real_relay: no relay. \
                 Install bun, or set SIGIL_TEST_RELAY_URL."
            );
            return;
        };
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use sigil_proto::{now_ms, rendezvous_mailbox, Envelope, PairingPayload};
        use sigil_relay_client::Rendezvous;

        let (qr_tx, qr_rx) = std::sync::mpsc::channel::<String>();

        // The phone: scan the QR, POST its response to the rendezvous mailbox,
        // then poll for the sealed DEK.
        let base_phone = base.clone();
        let phone = std::thread::spawn(move || {
            let qr = qr_rx.recv().expect("daemon rendered a QR");
            let payload = PairingPayload::from_qr_string(&qr).unwrap();
            let mailbox = rendezvous_mailbox(&payload.daemon, &payload.secret);
            let rv = Rendezvous::phone(&base_phone, mailbox).unwrap();
            let phone_id = DeviceIdentity::generate();
            let (mut pairing, resp) =
                Pairing::scan(phone_id, &qr, now_ms(), Policy::Approve).unwrap();
            rv.send(&URL_SAFE_NO_PAD.encode(serde_json::to_vec(&resp).unwrap()))
                .unwrap();
            pairing.confirm().unwrap();
            let env_wire = rv
                .recv(Duration::from_secs(10))
                .unwrap()
                .expect("the daemon sealed the DEK back");
            let env: Envelope = serde_json::from_str(&env_wire).unwrap();
            let sp = pairing.receive_dek(&env).unwrap();
            sp.phone_identity()
        });

        let daemon_id = DeviceIdentity::generate();
        let daemon_pub = daemon_id.peer_identity();
        let mut make_channel = |mailbox: [u8; 32]| crate::pair::relay_channel(&base, mailbox);
        let mut present_qr = |_u: &str, b64: &str| qr_tx.send(b64.to_string()).unwrap();
        let mut confirm = |_w: &[&'static str; 6]| true;
        let dek = crate::secrets::generate_dek();
        let mut unwrap_dek = || -> anyhow::Result<crate::secrets::Dek> { Ok(dek.clone()) };
        let opts = crate::pair::CeremonyOpts {
            relay_url: base.clone(),
            response_timeout: Duration::from_secs(15),
            flush_grace: Duration::from_millis(750),
            now: &now_ms,
            make_channel: &mut make_channel,
            present_qr: &mut present_qr,
            confirm_sas: &mut confirm,
            unwrap_dek: &mut unwrap_dek,
        };
        let np = crate::pair::run_ceremony(daemon_id, opts).expect("pairing over the relay");

        let phone_pub = phone.join().unwrap();
        assert_eq!(
            np.phone, phone_pub,
            "the daemon pinned the phone that responded"
        );
        assert_eq!(np.daemon_identity.peer_identity(), daemon_pub);
    }

    #[test]
    fn vault_of_ref_extracts_the_vault_segment() {
        assert_eq!(
            vault_of_ref("op://Engineering/GitHub/private key").as_deref(),
            Some("Engineering")
        );
        assert_eq!(vault_of_ref("not-a-ref"), None);
    }

    #[test]
    fn different_ssh_challenges_do_not_share_a_grant_key() {
        // The coalescing-safety invariant: a signature over different data must
        // derive a different grant key, so the approval gate can never let one
        // challenge ride another challenge's approval. Same caller, same key
        // label, different data fingerprints -> different scope -> different gk.
        let caller = lease::walk_ancestry(&EmptyTable, -1);
        let fp_a = crate::sshagent::sha256_fingerprint(b"challenge-A");
        let fp_b = crate::sshagent::sha256_fingerprint(b"challenge-B");
        assert_ne!(fp_a, fp_b);
        let gk_a = lease::grant_key(&caller, "", &ssh_sign_scope("GitHub", &fp_a));
        let gk_b = lease::grant_key(&caller, "", &ssh_sign_scope("GitHub", &fp_b));
        assert_ne!(gk_a, gk_b, "different data must not coalesce");
        // A byte-identical re-sign IS allowed to coalesce (deterministic, same sig).
        let gk_a2 = lease::grant_key(&caller, "", &ssh_sign_scope("GitHub", &fp_a));
        assert_eq!(gk_a, gk_a2);
    }

    #[test]
    fn env_file_lease_decision_grants_no_lease() {
        // Leasing is disabled for a direct-injection provider even when the
        // decision would grant a session lease: resolved secret VALUES must never
        // sit in daemon RAM across a TTL. A Lease decision on an env-file command
        // runs once and leaves no lease behind (the credential block that grants a
        // lease is gated on `needs_account`, which is false for env-file).
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir("envlease");
        let env_path = dir.join("s.env");
        std::fs::write(&env_path, "TOKEN=abc123\n").unwrap();
        let bindir = dir.join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let tool = bindir.join("faketool");
        std::fs::write(&tool, "#!/bin/sh\nprintf 'tok=%s' \"$TOKEN\"\n").unwrap();
        std::fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();

        let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());
        let pending = Arc::new(PendingRegistry::new());
        // A Lease decision that *would* lease an account-backed provider.
        let approver = LocalApprover::new(keystore.clone(), pending.clone())
            .with_dev(DevMode::Lease(Duration::from_secs(60)))
            .with_control_socket(true);
        let config = env_file_config("faketool", env_path.to_str().unwrap());
        let core = Arc::new(Core {
            keystore,
            accounts: Mutex::new(AccountStore::default()),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            config,
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: Vec::new(),
            audit: None,
        });

        // Prepend (not replace) bindir so faketool resolves first while system
        // binaries stay reachable for any parallel test's `#!/bin/sh` helper.
        let prev = std::env::var_os("PATH");
        let mut search = vec![bindir.clone()];
        if let Some(p) = &prev {
            search.extend(std::env::split_paths(p));
        }
        std::env::set_var("PATH", std::env::join_paths(search).unwrap());
        let (read_end, write_end) = pipe();
        let code = fulfill(
            &core,
            &["faketool".into()],
            "",
            None,
            0,
            None,
            Some(write_end),
            None,
        );
        match prev {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }

        assert_eq!(code, 0);
        assert_eq!(read_all(read_end), "tok=abc123");
        assert_eq!(
            core.leases.active(),
            0,
            "env-file must never lease, even on a lease decision"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ssh_file_signer_denied_gate_yields_no_signature() {
        // Gate-before-sign, fail closed: no pluggable signer may produce a
        // signature unless the approval gate has granted. With dev Off + no
        // resolver + a short timeout the parked request times out to Deny, so
        // `approve_and_sign` must return None and never reach `signer.sign`.
        let dir = tmpdir("ssh-denied");
        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let key_path = dir.join("id_ed25519");
        std::fs::write(&key_path, key.to_openssh(ssh_key::LineEnding::LF).unwrap()).unwrap();
        let pk = key.public_key();
        let id = ServedIdentity {
            key_blob: pk.to_bytes().unwrap(),
            comment: "tom@file".into(),
            key_ref: key_path.to_string_lossy().into_owned(),
            label: "id_ed25519".into(),
            fingerprint: pk.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        };

        let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());
        let pending = Arc::new(PendingRegistry::new());
        let approver = LocalApprover::new(keystore.clone(), pending.clone())
            .with_dev(DevMode::Off)
            .with_control_socket(true)
            .with_timeout(Duration::from_millis(50));
        let core = Core {
            keystore,
            accounts: Mutex::new(AccountStore::default()),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            config: op_config(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: vec![Box::new(sshagent::FileSshSigner::new(vec![(
                id.clone(),
                key_path.clone(),
            )]))],
            audit: None,
        };

        let host = sshagent::HostContext {
            host: "(host not bound)".into(),
        };
        let out = core.approve_and_sign(sshagent::SignRequest {
            id: &id,
            data: b"unapproved-data",
            host: &host,
            caller_pid: None,
        });
        assert!(out.is_none(), "a denied gate must yield no signature");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn conn_gate_refuses_past_the_cap_and_frees_slots_on_drop() {
        let gate = ConnGate::new();
        let mut permits = Vec::new();
        for _ in 0..MAX_CONCURRENT_CONNS {
            permits.push(gate.try_enter().expect("under the cap must admit"));
        }
        assert!(
            gate.try_enter().is_none(),
            "the cap must refuse one more connection"
        );

        // Dropping one permit frees exactly one slot.
        permits.pop();
        assert!(
            gate.try_enter().is_some(),
            "a freed slot must admit a new connection"
        );
    }
}
