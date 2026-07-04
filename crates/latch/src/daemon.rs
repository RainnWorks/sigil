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
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use tokio::net::UnixListener;

use crate::approve::{ApprovalContext, ApprovalGate, Decision, LocalApprover, PendingRegistry};
use crate::keystore::{self, Keystore};
use crate::lease::{self, LeaseStore, ProcessTable, SysProcessTable};
use crate::local::{self, Frame, Reply};
use crate::paths;
use crate::secrets::{self, AccountStore};

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
    /// Test override for the `op` binary; production discovers it on PATH.
    op_path: Option<PathBuf>,
    lease_ttl: Duration,
}

impl Core {
    /// Build the production core: the host keystore, the on-disk account store,
    /// and a local approver reading the dev switch once from the env.
    pub fn for_host() -> anyhow::Result<Self> {
        let keystore = keystore::for_host();
        let accounts = AccountStore::load().context("loading account store")?;
        let pending = Arc::new(PendingRegistry::new());
        let approver = LocalApprover::new(keystore.clone(), pending.clone());
        Ok(Self {
            keystore,
            accounts: Mutex::new(accounts),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(SysProcessTable),
            op_path: None,
            lease_ttl: DEFAULT_LEASE_TTL,
        })
    }
}

/// Build a runtime and serve until interrupted. Blocks the calling thread.
pub fn run() -> anyhow::Result<()> {
    let core = Arc::new(Core::for_host()?);
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

    let accounts = core
        .accounts
        .lock()
        .expect("accounts poisoned")
        .accounts
        .len();
    eprintln!(
        "latch daemon: armed on {} · {accounts} account(s) · gating active",
        sock.display()
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
        return spawn_op(core, argv, cwd, &token, stdout, stderr);
    }

    let ctx = ApprovalContext {
        id: uuid::Uuid::now_v7().to_string(),
        account: account_label.clone(),
        scope: scope.clone(),
        grant_hex: lease::hex32(&gk),
        provenance: caller.provenance(),
        cwd: cwd.to_string(),
    };
    let decision = core.gate.decide(gk, &ctx);
    if !decision.is_grant() {
        return fail_closed(stderr, "op: request denied\n");
    }

    // Unwrap the DEK (biometric on macOS), decrypt the one token, and drop the
    // DEK immediately. Both live in `Zeroizing`, wiped on drop.
    let dek = match core
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

    let code = spawn_op(core, argv, cwd, &token, stdout, stderr);
    drop(token); // zeroized here; the child holds its own copy in its env
    code
}

/// Spawn the real `op` with the token in its env and its stdout/stderr wired to
/// the caller's descriptors. Secret bytes flow child -> caller fd, never here.
fn spawn_op(
    core: &Core,
    argv: &[String],
    cwd: &str,
    token: &secrets::Token,
    stdout: Option<OwnedFd>,
    stderr: Option<OwnedFd>,
) -> i32 {
    let real = match &core.op_path {
        Some(p) => p.clone(),
        None => match paths::find_real_op() {
            Some(p) => p,
            None => {
                eprintln!("latch daemon: no real `op` found on PATH");
                return 127;
            }
        },
    };

    let mut cmd = Command::new(&real);
    cmd.args(argv.iter().skip(1));
    if !cwd.is_empty() {
        cmd.current_dir(cwd);
    }
    // The service-account token is the only way `op` authenticates here. It is
    // ASCII; a non-UTF-8 token is a corrupt store and fails closed.
    match std::str::from_utf8(token) {
        Ok(s) => {
            cmd.env("OP_SERVICE_ACCOUNT_TOKEN", s);
        }
        Err(_) => {
            eprintln!("latch daemon: token is not valid UTF-8");
            return 1;
        }
    }
    if let Some(fd) = stdout {
        cmd.stdout(Stdio::from(fd));
    }
    if let Some(fd) = stderr {
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
        let approver = LocalApprover::new(keystore.clone(), pending.clone())
            .with_dev(dev)
            .with_timeout(timeout);
        let core = Core {
            keystore,
            accounts: Mutex::new(accounts),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending: pending.clone(),
            lockdown: AtomicBool::new(false),
            proc_table: Box::new(EmptyTable),
            op_path: Some(write_fake_op(dir, token, secret)),
            lease_ttl: Duration::from_secs(60),
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
