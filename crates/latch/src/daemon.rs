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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use tokio::net::UnixListener;

use crate::approve::{
    ApprovalContext, ApprovalGate, Approver, Decision, DevMode, LocalApprover, NullApprover,
    PendingRegistry,
};
use crate::command::{self, CommandStore};
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

use latch_proto::{RiskLevel, SshChallenge};

use latch_proto::identity::DeviceIdentity;
use latch_proto::{mailbox_id, PeerIdentity};
use latch_relay_client::DaemonRelay;

/// Default session-lease TTL granted by an "approve for this session" decision.
const DEFAULT_LEASE_TTL: Duration = Duration::from_secs(15 * 60);

/// Shared daemon state, cloned (via `Arc`) into every connection worker.
pub struct Core {
    keystore: Arc<dyn Keystore>,
    accounts: Mutex<AccountStore>,
    leases: LeaseStore,
    gate: ApprovalGate,
    pending: Arc<PendingRegistry>,
    lockdown: AtomicBool,
    proc_table: Box<dyn ProcessTable + Send + Sync>,
    /// The provider registry: a command's config names a provider by id, and the
    /// daemon dispatches the run to it. 1Password and env-file ship by default;
    /// the seam is generic and each provider owns its own tool discovery.
    providers: ProviderRegistry,
    /// The per-command configuration: which provider backs each command, what to
    /// inject, and its risk. Loaded at arm time; `op` resolves by default.
    commands: CommandStore,
    lease_ttl: Duration,
    /// The approving factor resolved at arm time (residual #1 mitigation).
    factor: Factor,
    /// The pluggable SSH key sources this daemon serves on the agent socket,
    /// resolved from `~/.latch/ssh-keys.json` at arm time. Empty means the agent
    /// advertises no keys (and `ssh-add -l` shows none). Latch is the phone-gate
    /// regardless of which signer holds the key.
    ssh_signers: Vec<Box<dyn SshSigner>>,
    /// Audit logging: `Some(retention_days)` appends a metadata-only line per
    /// decision to `history.jsonl` (pruned to the window); `None` disables it.
    /// The real daemon enables it; tests leave it off so they never write to a
    /// developer's `~/.latch`.
    audit: Option<u32>,
}

/// A persisted daemon<->phone pairing: everything needed to reach the phone as
/// the approving factor over the blind relay. `latch pair` persists this (see
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
}

impl RemotePairingConfig {
    /// The shared mailbox both parties route on, derived from the pinned keys.
    pub fn mailbox(&self) -> [u8; 32] {
        mailbox_id(&self.daemon_identity.peer_identity(), &self.phone)
    }
}

/// Load a persisted phone pairing, if one exists, from `~/.latch/pairing.json`
/// plus the daemon identity in `ks`. A present-but-unreadable pairing (corrupt
/// file, missing keystore identity) is logged and treated as "no pairing" so the
/// daemon still arms and fails closed rather than refusing to start; the fault
/// surfaces in `latch doctor`. See [`crate::pairing_store`] for the on-disk
/// format and why it stays inert at rest.
fn load_remote_pairing(ks: &Arc<dyn Keystore>) -> Option<RemotePairingConfig> {
    match crate::pairing_store::load(ks.as_ref()) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("latch daemon: ignoring an unreadable pairing config: {e}");
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
            let relay = DaemonRelay::connect(&cfg.relay_url, cfg.mailbox())
                .map_err(|e| anyhow::anyhow!("attaching to relay {}: {e}", cfg.relay_url))?;
            Box::new(RemoteApprover::new(
                Arc::new(relay),
                cfg.daemon_identity,
                cfg.phone,
            ))
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
        let pending = Arc::new(PendingRegistry::new());

        let remote = load_remote_pairing(&keystore);
        let inputs = factor::ArmInputs {
            dev_insecure,
            phone_paired: remote.is_some(),
            biometric: keystore.is_biometric(),
        };
        let factor = factor::resolve(&inputs);
        let gate = build_gate(factor, remote, &keystore, &pending)?;

        // Load the served SSH identities from ~/.latch/ssh-keys.json and build a
        // signer per source (op-fetch + file-based). A bad config is logged and
        // treated as "no keys" so the daemon still arms.
        let ssh_signers = match sshagent::SshKeyConfig::load() {
            Ok(cfg) => build_ssh_signers(&cfg, None),
            Err(e) => {
                eprintln!("latch daemon: ignoring an unreadable ssh-keys config: {e}");
                Vec::new()
            }
        };

        // Load the per-command config (which provider backs each command). A bad
        // config is logged and treated as empty (op still resolves by default).
        let commands = match CommandStore::load() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("latch daemon: ignoring an unreadable command config: {e}");
                CommandStore::default()
            }
        };

        Ok(Self {
            keystore,
            accounts: Mutex::new(accounts),
            leases: LeaseStore::new(),
            gate,
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(SysProcessTable),
            providers: ProviderRegistry::with_defaults(),
            commands,
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
        kind: latch_proto::RequestKind,
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
                latch_proto::now_ms(),
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
    /// signer that owns the key. Latch is the phone-gate regardless of key source:
    /// the gate here is the same approval path as an `op` secret, with two
    /// differences the security review must weigh (see `sshagent` module docs):
    /// every signature is gated (no lease short-circuit in v1), and for the
    /// op-fetch signer the private key is briefly in daemon RAM for the one
    /// signature. A file signer sources the key from a local file instead; either
    /// way the key never reaches the SSH client.
    fn approve_and_sign(&self, req: SignRequest<'_>) -> Option<Vec<u8>> {
        if self.lockdown.load(Ordering::SeqCst) {
            eprintln!("latch daemon: ssh sign refused; latch is locked down");
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
            kind: latch_proto::RequestKind::SshSignature,
            // A signature is an authentication event: elevated by default.
            risk: RiskLevel::Elevated,
            ssh: Some(challenge),
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

/// Build a runtime and serve until interrupted. Blocks the calling thread.
/// `args` are the `latch daemon` arguments (e.g. `--dev-insecure`).
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
        eprintln!("latch daemon: {e}");
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
        "latch daemon: armed on {} · {accounts} account(s) · factor: {}",
        sock.display(),
        core.factor.label()
    );
    eprintln!(
        "latch daemon: ssh-agent on {} · {} key(s) served · export SSH_AUTH_SOCK={}",
        ssh_sock.display(),
        core.identities().len(),
        ssh_sock.display()
    );

    // Shim-drift check: if the `op` a shell resolves is no longer our shim (not
    // installed, out-ordered on PATH, or pointing at a stale binary), requests
    // would bypass the gate entirely. Warn loudly at every start.
    if let Some(issue) = ShimStatus::detect().issue() {
        eprintln!("latch daemon: shim drift: {issue}");
    }

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("latch daemon: shutting down (leases zeroized)");
                core.leases.clear();
                break;
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accept")?;
                let std_stream = stream.into_std().context("into_std")?;
                std_stream.set_nonblocking(false).context("set_nonblocking")?;
                let core = core.clone();
                // Per-connection work is blocking syscalls (recvmsg, spawn,
                // waitpid) plus a possibly long approval wait; keep it off the
                // async workers.
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = handle_conn(core, std_stream) {
                        eprintln!("latch daemon: connection error: {e}");
                    }
                });
            }
            accepted = ssh_listener.accept() => {
                let (stream, _) = accepted.context("ssh accept")?;
                let std_stream = stream.into_std().context("ssh into_std")?;
                std_stream.set_nonblocking(false).context("ssh set_nonblocking")?;
                let core = core.clone();
                // An SSH connection is also blocking (per-signature fetch, spawn,
                // approval wait); serve it on the blocking pool with the Core as
                // the agent backend.
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = sshagent::handle_connection(core.as_ref(), std_stream) {
                        eprintln!("latch daemon: ssh connection error: {e}");
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
        Frame::Run { argv, cwd } => {
            log_request(&argv, &cwd, peer);
            let mut fds = fds.into_iter();
            let stdout = fds.next();
            let stderr = fds.next();
            Reply::Exit {
                code: fulfill(&core, &argv, &cwd, peer, stdout, stderr),
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
    let now = latch_proto::now_ms();
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
                risk: command::risk_str(ctx.risk).to_string(),
                reason: None,
                expires_ms: s.queued_at_ms + s.timeout_ms,
                timeout_ms: s.timeout_ms,
                coalesced: 0,
            }
        })
        .collect()
}

/// The gated fulfillment path for `latch <cmd>` (and the shim alias / `latch run`).
/// Returns the exit code to mirror to the caller. Every failure path here fails
/// closed (a non-zero code with a stderr line), so the caller behaves like a
/// denied invocation.
///
/// The command's config selects the provider; the provider decides the injection
/// shape. `op` (and any provider that [`needs_account`](crate::provider::SecretProvider::needs_account))
/// routes a 1Password account, unwraps the DEK, decrypts the one token, and
/// injects it; a direct-injection provider (`env-file`) needs no account and is
/// gated on every run (no leasing, so resolved values never sit in RAM across a
/// TTL). An *unconfigured* command is refused with a pointer to `latch config
/// add`, never run ungated.
fn fulfill(
    core: &Core,
    argv: &[String],
    cwd: &str,
    peer: Option<i32>,
    stdout: Option<OwnedFd>,
    stderr: Option<OwnedFd>,
) -> i32 {
    if core.lockdown.load(Ordering::SeqCst) {
        return fail_closed(stderr, "latch is locked down; no secrets served\n");
    }

    let Some(cmd) = argv.first() else {
        return fail_closed(stderr, "latch: empty command\n");
    };

    // Look up the command config. An unconfigured command is refused (never run
    // ungated) with the exact command to configure it.
    let Some(cfg) = core.commands.resolve(cmd) else {
        return fail_closed(
            stderr,
            &format!(
                "latch: '{cmd}' is not configured; Latch will not run it ungated.\n  \
                 configure it: latch config add {cmd} --provider <id>\n"
            ),
        );
    };
    let Some(provider) = core.providers.get(&cfg.provider) else {
        return fail_closed(
            stderr,
            &format!(
                "latch: '{cmd}' names an unknown provider '{}'\n",
                cfg.provider
            ),
        );
    };
    let source = cfg.source.as_deref().unwrap_or("");
    let needs_account = provider.needs_account();

    let scope = argv.iter().skip(1).cloned().collect::<Vec<_>>().join(" ");
    let caller = lease::walk_ancestry(core.proc_table.as_ref(), peer.unwrap_or(-1));
    let gk = lease::grant_key(&caller, cwd, &scope);

    // Route the 1Password account only for providers that inject a stored token.
    // Clone what we need so the store lock is released before the approval wait.
    let (account_label, ciphertext) = if needs_account {
        let vault = parse_vault(argv).or_else(|| cfg.account.clone());
        let store = core.accounts.lock().expect("accounts poisoned");
        match store.route(vault.as_deref()) {
            Ok(acct) => match acct.ciphertext() {
                Ok(ct) => (acct.label.clone(), Some(ct)),
                Err(e) => return fail_closed(stderr, &format!("latch account error: {e}\n")),
            },
            Err(e) => return fail_closed(stderr, &format!("latch: {e}\n")),
        }
    } else {
        (String::new(), None)
    };

    // A live lease short-circuits the approval — only for account-backed
    // providers, whose credential is what a lease holds. Direct-injection
    // providers are gated on every run.
    if needs_account {
        if let Some(token) = core.leases.token_for(&gk, &account_label, &scope) {
            let refs = provider.describe(argv, source);
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
                stdout,
                stderr,
            });
        }
    }

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
        secret_refs: provider.describe(argv, source),
        kind: provider.kind(argv),
        risk: cfg.risk,
        ssh: None,
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

    // Account-backed providers need the decrypted token; direct-injection
    // providers source their own env and need no credential. The DEK either
    // arrived with the approval (a paired phone delivered it, re-sealed to this
    // daemon) or is unwrapped from the local keystore (Touch ID on macOS). Both
    // live in `Zeroizing`, wiped on drop.
    let credential = if let Some(ciphertext) = &ciphertext {
        let dek = match outcome.dek {
            Some(dek) => dek,
            None => match core
                .keystore
                .unwrap_dek(&format!("Approve {scope} for {account_label}"))
            {
                Ok(dek) => dek,
                Err(e) => {
                    return fail_closed(stderr, &format!("latch could not unwrap the key: {e}\n"))
                }
            },
        };
        let token = match secrets::decrypt_token(&dek, ciphertext) {
            Ok(t) => t,
            Err(e) => return fail_closed(stderr, &format!("latch token decrypt failed: {e}\n")),
        };
        drop(dek);
        if let Some(ttl) = decision.lease_ttl() {
            core.leases
                .grant(gk, &account_label, &scope, token.clone(), ttl);
        }
        Some(token)
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

    // Run through the provider: it injects the credential (op) or the source
    // env-vars (env-file) and streams output straight to the caller's fds. For
    // op the daemon holds only the credential; for env-file the resolved values
    // transit only as the child's spawn env (see the provider module docs).
    let code = provider.run(ProviderRun {
        command: argv,
        cwd,
        credential: credential.as_ref(),
        source,
        stdout,
        stderr,
    });
    drop(credential); // zeroized here (Token is Zeroizing) when present
    code
}

/// The brightest audit label for an op request: the first secret ref's item
/// label, or the scope string when the provider named none.
fn audit_label(refs: &[latch_proto::SecretRef], scope: &str) -> String {
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

/// The `--vault`/`--vault=` value from an op argv, if any.
fn parse_vault(argv: &[String]) -> Option<String> {
    let mut it = argv.iter();
    while let Some(a) = it.next() {
        if let Some(v) = a.strip_prefix("--vault=") {
            return Some(v.to_string());
        }
        if a == "--vault" {
            return it.next().cloned();
        }
    }
    None
}

/// Log request metadata: argv (item names, not secret values), cwd, peer pid.
fn log_request(argv: &[String], cwd: &str, peer: Option<i32>) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    eprintln!(
        "latch daemon: [{ts}] op {} · cwd {} · pid {}",
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
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending: pending.clone(),
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::new(vec![Box::new(OpProvider::with_binary(
                write_fake_op(dir, token, secret),
            ))]),
            commands: CommandStore::default(),
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
        let d = std::env::temp_dir().join(format!("latch-daemon-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
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
        let code = fulfill(&core, &argv, "", None, Some(write_end), None);
        assert_eq!(code, 0);
        assert_eq!(read_all(read_end), "known-secret-42");
        // No lease was requested, so none is held.
        assert_eq!(core.leases.active(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn approved_request_is_recorded_in_the_audit_log() {
        // The daemon appends one metadata-only line per decision. Build a
        // dev-approve core with auditing enabled to a private LATCH_HOME and
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
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::new(vec![Box::new(OpProvider::with_binary(
                write_fake_op(&dir, "tok", "secret-1"),
            ))]),
            commands: CommandStore::default(),
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
        assert_eq!(fulfill(&core, &argv, "", None, Some(write_end), None), 0);
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
            fulfill(&park_core, &argv, "", None, Some(w), None)
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
        assert_eq!(fulfill(&core, &argv, "", None, Some(w1), None), 0);
        assert_eq!(read_all(r1), "secret-A");
        assert_eq!(core.leases.active(), 1);

        // With a live lease the second identical request must be served from the
        // lease, not a fresh approval.
        let (r2, w2) = pipe();
        assert_eq!(fulfill(&core, &argv, "", None, Some(w2), None), 0);
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
        let code = fulfill(&core, &argv, "/p", None, Some(write_end), Some(err_w));
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
        assert_eq!(fulfill(&core, &argv, "/p", None, Some(write_end), None), 1);
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
        let code = fulfill(&core, &argv, "", None, Some(write_end), Some(err_w));
        assert_eq!(code, 1, "an unconfigured command must fail closed");
        assert_eq!(read_all(read_end), "", "and produce no output");
        let err = read_all(err_r);
        assert!(err.contains("not configured"), "err: {err}");
        assert!(err.contains("latch config add gcloud"), "err: {err}");
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
        let mut commands = CommandStore::default();
        commands
            .add(crate::command::CommandConfig {
                command: "faketool".into(),
                provider: EnvFileProvider::ID.into(),
                source: Some(env_path.to_str().unwrap().to_string()),
                account: None,
                risk: RiskLevel::Routine,
            })
            .unwrap();
        let core = Arc::new(Core {
            keystore,
            accounts: Mutex::new(AccountStore::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            commands,
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
        let code = fulfill(&core, &["faketool".into()], "", None, Some(write_end), None);
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

    #[test]
    fn ssh_file_signer_signs_when_gated() {
        // The pluggable SSH signer seam through the daemon gate: a file-backed
        // signer (no account) produces a verifiable signature only after the gate
        // grants, proving Latch is the phone-gate regardless of key source.
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
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            commands: CommandStore::default(),
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
            },
            &[write_end.as_raw_fd()],
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
    use latch_proto::identity::DeviceIdentity;
    use latch_proto::pairing::{DaemonPairing, Dek as ProtoDek};
    use latch_proto::{LocalRelay, PairingState};
    use latch_relay_client::{DaemonRelay, PhoneRelay};
    use latch_softphone::{Pairing, Policy, Softphone};
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
            DaemonPairing::mint(daemon_id, vec!["lan://latch.local:4823".into()], REMOTE_NOW);

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
        phone: latch_proto::PeerIdentity,
        transport: Arc<dyn latch_proto::Transport>,
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
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::new(vec![Box::new(OpProvider::with_binary(
                write_fake_op(dir, token, secret),
            ))]),
            commands: CommandStore::default(),
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
            },
            &[write_end.as_raw_fd(), err_w.as_raw_fd()],
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
            relay.depth(mailbox, latch_proto::Direction::ToDaemon),
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
        let code = fulfill(&core, &argv, "", None, Some(write_end), Some(err_w));

        assert_eq!(code, 1, "a remote denial must fail closed");
        assert_eq!(read_all(read_end), "", "no secret on a denied request");
        assert!(read_all(err_r).contains("denied"));

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
        };
        assert_eq!(cfg.mailbox(), softphone.mailbox());
    }

    // --- the FULL cross-process loop over the REAL relay -------------------
    //
    // Same milestone as `remote_softphone_approval_delivers_secret_over_the_socket`,
    // but the envelopes traverse the real blind relay (the Bun server) over real
    // HTTP + WebSocket instead of the in-process LocalRelay: the daemon attaches
    // outbound over a WebSocket (`DaemonRelay`) and the softphone polls over HTTPS
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

    /// Resolve a relay base URL for the e2e test. Prefers `$LATCH_TEST_RELAY_URL`
    /// (an already-running relay); otherwise spawns the Bun relay if `bun` is
    /// available. Returns `None` to soft-skip when no relay can be obtained.
    fn obtain_relay() -> Option<(String, Option<RelayServer>)> {
        if let Ok(url) = std::env::var("LATCH_TEST_RELAY_URL") {
            return Some((url, None));
        }
        let port = free_port();
        let guard = bun_relay_on(port)?;
        Some((format!("http://127.0.0.1:{port}"), Some(guard)))
    }

    #[test]
    fn remote_approval_over_the_real_relay_delivers_the_secret() {
        let Some((base, _server)) = obtain_relay() else {
            eprintln!(
                "SKIPPED remote_approval_over_the_real_relay_delivers_the_secret: no relay. \
                 Install bun, or start one and set LATCH_TEST_RELAY_URL, e.g.\n  \
                 PORT=8787 bun run relay/bun/server.ts   (then LATCH_TEST_RELAY_URL=http://127.0.0.1:8787)"
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
        };
        assert_eq!(cfg.mailbox(), mailbox);

        // Daemon side: RemoteApprover over a real outbound WebSocket. No dev flag,
        // no biometric: the paired phone is the real approving factor.
        let daemon_relay = DaemonRelay::connect(&base, mailbox).expect("daemon ws attach");
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

        // Phone side: the softphone serves over the real HTTPS transport.
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
            },
            &[write_end.as_raw_fd(), err_w.as_raw_fd()],
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
    fn daemon_relay_resumes_after_the_relay_is_bounced() {
        // Reconnect/resume: attach the daemon, drop the relay out from under it,
        // bring a fresh relay up on the same port, and prove the approval loop
        // still completes. The DaemonRelay pump redials with backoff and the
        // outbound request buffered across the outage is flushed on reattach.
        // Only runnable when we control the relay process (spawn path).
        if std::env::var("LATCH_TEST_RELAY_URL").is_ok() {
            eprintln!("SKIPPED daemon_relay_resumes_after_the_relay_is_bounced: needs a bounceable relay (unset LATCH_TEST_RELAY_URL)");
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

        // Attach the daemon and let the WebSocket establish.
        let daemon_relay = DaemonRelay::connect(&base, mailbox).expect("daemon ws attach");
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
        let code = fulfill(&core, &argv, "", None, Some(write_end), None);

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
            leases: LeaseStore::new(),
            gate,
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::new(vec![Box::new(OpProvider::with_binary(
                write_fake_op(dir, token, secret),
            ))]),
            commands: CommandStore::default(),
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
        let code = fulfill(&core, &argv, "/p", None, Some(write_end), Some(err_w));

        assert_eq!(code, 1, "a daemon with no factor must fail closed");
        assert_eq!(read_all(read_end), "", "no secret without a real factor");
        assert!(read_all(err_r).contains("denied"));
        assert_eq!(core.leases.active(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- pairing persistence -> phone factor (task #11) --------------------

    use crate::pairing_store::{self, NewPairing};

    /// A private LATCH_HOME for one test, restored on drop. Isolates the
    /// `pairing.json` location from the real `~/.latch` and other tests.
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
                "latch-daemon-home-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let prev = std::env::var_os("LATCH_HOME");
            std::env::set_var("LATCH_HOME", &dir);
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
                Some(v) => std::env::set_var("LATCH_HOME", v),
                None => std::env::remove_var("LATCH_HOME"),
            }
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    fn sas_of(
        daemon: &latch_proto::PeerIdentity,
        phone: &latch_proto::PeerIdentity,
    ) -> [String; 6] {
        let w = latch_proto::fingerprint_words(daemon, phone);
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
    fn reloaded_pairing_serves_a_secret_over_the_real_relay() {
        // The end-to-end proof of the critical path: persist a pairing, reload
        // it from disk, and use the RELOADED daemon identity to satisfy a real
        // op request via the phone over the real relay — with NO DEK at rest. The
        // reloaded identity must still sign requests the phone verifies and open
        // the phone's sealed response.
        let Some((base, _server)) = obtain_relay() else {
            eprintln!(
                "SKIPPED reloaded_pairing_serves_a_secret_over_the_real_relay: no relay. \
                 Install bun, or set LATCH_TEST_RELAY_URL."
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
        };
        pairing_store::save(ks.as_ref(), &np).unwrap();
        let cfg = pairing_store::load(ks.as_ref()).unwrap().expect("saved");
        assert_eq!(cfg.mailbox(), mailbox);

        // Daemon side: RemoteApprover over the real WS, keyed by the RELOADED
        // identity. The account token is sealed under the phone-held DEK; the
        // daemon holds none.
        let dir = tmpdir("reload-relay");
        let daemon_relay = DaemonRelay::connect(&base, mailbox).expect("daemon ws attach");
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

        // Phone side over the real HTTPS transport.
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
            },
            &[write_end.as_raw_fd()],
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
    fn latch_pair_completes_the_ceremony_over_the_real_relay() {
        // Drive the real `latch pair` ceremony end to end over the blind relay:
        // the daemon side uses the raw WebSocket rendezvous (`RendezvousWs` via
        // `pair::relay_channel`), the phone side uses the HTTP `Rendezvous`
        // client, and they meet on the rendezvous mailbox. Proves the pairing
        // transport, the message framing, and the QR round-trip against a real
        // relay process.
        let Some((base, _server)) = obtain_relay() else {
            eprintln!(
                "SKIPPED latch_pair_completes_the_ceremony_over_the_real_relay: no relay. \
                 Install bun, or set LATCH_TEST_RELAY_URL."
            );
            return;
        };
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use latch_proto::{now_ms, rendezvous_mailbox, Envelope, PairingPayload};
        use latch_relay_client::Rendezvous;

        let (qr_tx, qr_rx) = std::sync::mpsc::channel::<String>();

        // The phone: scan the QR, POST its response to the rendezvous mailbox,
        // then poll for the sealed DEK.
        let base_phone = base.clone();
        let phone = std::thread::spawn(move || {
            let qr = qr_rx.recv().expect("daemon rendered a QR");
            let payload = PairingPayload::from_qr_string(&qr).unwrap();
            let mailbox = rendezvous_mailbox(&payload.daemon, &payload.secret);
            let rv = Rendezvous::new(&base_phone, mailbox).unwrap();
            let phone_id = DeviceIdentity::generate();
            let (mut pairing, resp) =
                Pairing::scan(phone_id, &qr, now_ms(), Policy::Approve).unwrap();
            rv.submit(&URL_SAFE_NO_PAD.encode(serde_json::to_vec(&resp).unwrap()))
                .unwrap();
            pairing.confirm().unwrap();
            let env_wire = rv
                .wait(Duration::from_secs(10), Duration::from_millis(50))
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
        let opts = crate::pair::CeremonyOpts {
            relay_url: base.clone(),
            response_timeout: Duration::from_secs(15),
            flush_grace: Duration::from_millis(750),
            now: &now_ms,
            make_channel: &mut make_channel,
            present_qr: &mut present_qr,
            confirm_sas: &mut confirm,
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
    fn parse_vault_reads_both_spellings() {
        assert_eq!(
            parse_vault(&["op".into(), "--vault".into(), "Engineering".into()]),
            Some("Engineering".into())
        );
        assert_eq!(
            parse_vault(&["op".into(), "--vault=Personal".into()]),
            Some("Personal".into())
        );
        assert_eq!(parse_vault(&["op".into(), "read".into()]), None);
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
        let mut commands = CommandStore::default();
        commands
            .add(crate::command::CommandConfig {
                command: "faketool".into(),
                provider: EnvFileProvider::ID.into(),
                source: Some(env_path.to_str().unwrap().to_string()),
                account: None,
                risk: RiskLevel::Routine,
            })
            .unwrap();
        let core = Arc::new(Core {
            keystore,
            accounts: Mutex::new(AccountStore::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            commands,
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
        let code = fulfill(&core, &["faketool".into()], "", None, Some(write_end), None);
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
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            commands: CommandStore::default(),
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
}
