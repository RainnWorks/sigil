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
use crate::factor::{self, Factor};
use crate::keystore::{self, Keystore};
use crate::lease::{self, LeaseStore, ProcessTable, SysProcessTable};
use crate::local::{self, Frame, Reply};
use crate::provider::{OpProvider, ProviderRun, SecretProvider};
use crate::remote::RemoteApprover;
use crate::secrets::{self, AccountStore};

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
    /// The secret provider: it describes requests, injects the credential, and
    /// runs the command streaming secrets to the caller. 1Password is provider
    /// #1; the seam is generic and owns its own tool discovery.
    provider: Box<dyn SecretProvider>,
    lease_ttl: Duration,
    /// The approving factor resolved at arm time (residual #1 mitigation).
    factor: Factor,
}

/// A persisted daemon<->phone pairing: everything needed to reach the phone as
/// the approving factor over the blind relay. `latch pair` will persist this
/// (onboarding flow, task #11); until then [`load_remote_pairing`] finds none,
/// so a daemon with no biometric fails closed unless started `--dev-insecure`.
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

/// Load a persisted phone pairing, if one exists. There is no on-disk pairing
/// format yet (see [`RemotePairingConfig`]), so today this always returns `None`
/// and the phone factor is unavailable in the shipping CLI.
fn load_remote_pairing() -> Option<RemotePairingConfig> {
    None
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

        let remote = load_remote_pairing();
        let inputs = factor::ArmInputs {
            dev_insecure,
            phone_paired: remote.is_some(),
            biometric: keystore.is_biometric(),
        };
        let factor = factor::resolve(&inputs);
        let gate = build_gate(factor, remote, &keystore, &pending)?;

        Ok(Self {
            keystore,
            accounts: Mutex::new(accounts),
            leases: LeaseStore::new(),
            gate,
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(SysProcessTable),
            provider: Box::new(OpProvider::new()),
            lease_ttl: DEFAULT_LEASE_TTL,
            factor,
        })
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
    let sock = local::socket_path();
    prepare_socket(&sock)?;
    let listener =
        UnixListener::bind(&sock).with_context(|| format!("binding {}", sock.display()))?;
    // 0600: only this user may speak to the daemon.
    fs::set_permissions(&sock, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", sock.display()))?;

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
        }
    }

    let _ = fs::remove_file(&sock);
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
        // A probe (status/doctor) connects then hangs up; not an error.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
        Err(e) => return Err(e.into()),
    };

    let reply = match frame {
        Frame::Op { argv, cwd } => {
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
        Frame::LeaseList => {
            let lines: Vec<String> = core
                .leases
                .list()
                .into_iter()
                .map(|l| {
                    format!(
                        "{}  {}  {}  {}s left",
                        &l.grant_hex[..12.min(l.grant_hex.len())],
                        l.account,
                        l.scope,
                        l.remaining.as_secs()
                    )
                })
                .collect();
            Reply::Control { ok: true, lines }
        }
        Frame::LeaseRevoke { prefix } => {
            let n = core.leases.revoke(&prefix);
            control_reply(n > 0, &format!("revoked {n} lease(s)"))
        }
    };

    local::send_reply(&mut stream, &reply)?;
    Ok(())
}

fn control_reply(ok: bool, msg: &str) -> Reply {
    Reply::Control {
        ok,
        lines: vec![msg.to_string()],
    }
}

/// The gated fulfillment path. Returns the exit code to mirror to the shim.
/// Every failure path here fails closed (exit 1 with a stderr line), so the
/// shim behaves exactly like a denied real `op`.
fn fulfill(
    core: &Core,
    argv: &[String],
    cwd: &str,
    peer: Option<i32>,
    stdout: Option<OwnedFd>,
    stderr: Option<OwnedFd>,
) -> i32 {
    if core.lockdown.load(Ordering::SeqCst) {
        return fail_closed(stderr, "op: latch is locked down; no secrets served\n");
    }

    // Resolve the account for the requested vault. Clone what we need so the
    // store lock is released before the (possibly long) approval wait.
    let vault = parse_vault(argv);
    let (account_label, ciphertext) = {
        let store = core.accounts.lock().expect("accounts poisoned");
        match store.route(vault.as_deref()) {
            Ok(acct) => match acct.ciphertext() {
                Ok(ct) => (acct.label.clone(), ct),
                Err(e) => return fail_closed(stderr, &format!("op: latch account error: {e}\n")),
            },
            Err(e) => return fail_closed(stderr, &format!("op: latch: {e}\n")),
        }
    };

    let scope = argv.iter().skip(1).cloned().collect::<Vec<_>>().join(" ");
    let caller = lease::walk_ancestry(core.proc_table.as_ref(), peer.unwrap_or(-1));
    let gk = lease::grant_key(&caller, cwd, &scope);

    // A live lease short-circuits the approval.
    if let Some(token) = core.leases.token_for(&gk, &account_label, &scope) {
        return core.provider.run(ProviderRun {
            command: argv,
            cwd,
            credential: &token,
            stdout,
            stderr,
        });
    }

    // The provider describes the request in provider-agnostic terms; the
    // approver never sees op semantics.
    let ctx = ApprovalContext {
        id: uuid::Uuid::now_v7().to_string(),
        account: account_label.clone(),
        scope: scope.clone(),
        grant_hex: lease::hex32(&gk),
        provenance: caller.provenance(),
        cwd: cwd.to_string(),
        command: argv.to_vec(),
        secret_refs: core.provider.describe(argv),
        kind: core.provider.kind(argv),
    };
    let outcome = core.gate.decide(gk, &ctx);
    let decision = outcome.decision;
    if !decision.is_grant() {
        return fail_closed(stderr, "op: request denied\n");
    }

    // The DEK either arrived with the approval (a paired phone delivered it,
    // re-sealed to this daemon) or must be unwrapped from the local keystore
    // (Touch ID on macOS). The remote path is the inert-daemon case: no key at
    // rest. Decrypt the one token and drop the DEK immediately; both live in
    // `Zeroizing`, wiped on drop.
    let dek = match outcome.dek {
        Some(dek) => dek,
        None => match core
            .keystore
            .unwrap_dek(&format!("Approve {scope} for {account_label}"))
        {
            Ok(dek) => dek,
            Err(e) => {
                return fail_closed(
                    stderr,
                    &format!("op: latch could not unwrap the key: {e}\n"),
                )
            }
        },
    };
    let token = match secrets::decrypt_token(&dek, &ciphertext) {
        Ok(t) => t,
        Err(e) => return fail_closed(stderr, &format!("op: latch token decrypt failed: {e}\n")),
    };
    drop(dek);

    if let Some(ttl) = decision.lease_ttl() {
        core.leases
            .grant(gk, &account_label, &scope, token.clone(), ttl);
    }

    // Run through the provider: it injects the credential and streams the
    // resolved secrets straight to the caller's fds. The daemon never holds a
    // secret value; it holds only the credential (token), zeroized below.
    let code = core.provider.run(ProviderRun {
        command: argv,
        cwd,
        credential: &token,
        stdout,
        stderr,
    });
    drop(token); // zeroized here; the child holds its own copy in its env
    code
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
            provider: Box::new(OpProvider::with_binary(write_fake_op(dir, token, secret))),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
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
            &Frame::Op {
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
            provider: Box::new(OpProvider::with_binary(write_fake_op(dir, token, secret))),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::Phone,
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
            &Frame::Op {
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
            &Frame::Op {
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
            provider: Box::new(OpProvider::with_binary(write_fake_op(dir, token, secret))),
            lease_ttl: Duration::from_secs(60),
            factor,
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
}
