//! The daemon: accept connections, gate each `op` request behind an approval,
//! then run `op` on the caller's own descriptors.
//!
//! The plumbing invariant is unchanged from v0: the `op` child's stdout and
//! stderr are the descriptors the shim passed in, so secret output never enters
//! this process's memory. What is new is the gate in front of it. For each op
//! request the daemon:
//!
//! 1. resolves the matching rule for the command (gate or allow);
//! 2. measures the caller itself (peer pid, kernel-side ancestry) and derives a
//!    lease grant key it fully controls, over that caller chain plus the matched
//!    RULE (not the argv, and not the cwd);
//! 3. if a live lease covers this grant key, runs without a fresh prompt, so one
//!    approval covers any command that rule matches for that caller until the TTL
//!    ends; otherwise requires a fresh approval (coalescing only in-flight
//!    requests that are identical in argv and cwd, so one readout never settles a
//!    different command);
//! 4. on approval, spawns the command on the caller's descriptors. `op` brings
//!    its own auth (Sigil injects no credential); an inline-`env` rule opens its
//!    threshold-sealed values with the phone's partial and injects them, then
//!    zeroizes;
//! 5. on deny or timeout, fails closed: the shim exits like real `op`.
//!
//! Control commands (local approve/deny, lease list/revoke) arrive on
//! the same socket and mutate this shared state.

use std::fs;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Condvar;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use tokio::net::UnixListener;

use crate::approve::{
    ApprovalContext, ApprovalGate, Approver, Decision, DevMode, LocalApprover, NullApprover,
    PendingRegistry,
};
use crate::config::Config;
use crate::factor::{self, Factor};
use crate::keystore::{self, Keystore};
use crate::lease::{self, LeaseStore, ProcessTable, SysProcessTable};
use crate::local::{self, Frame, Reply};
use crate::paths::ShimStatus;
use crate::provider::{ProviderRegistry, ProviderRun};
use crate::remote::RemoteApprover;
use crate::secrets::Token;
use crate::service;
use crate::sshagent::{self, ServedIdentity, SignRequest, SshBackend, SshSigner};

use sigil_proto::{LeasePolicy, SshChallenge};

use sigil_proto::identity::DeviceIdentity;
use sigil_proto::{mailbox_id, PeerIdentity, Transport};
use sigil_relay_client::DaemonRelay;

use sigil_direct::{DirectListener, FallbackTransport};

/// Default session-lease TTL granted by an "approve for this session" decision.
const DEFAULT_LEASE_TTL: Duration = Duration::from_secs(15 * 60);

/// How often the config watcher stat-polls `~/.sigil/config.json` for a change.
/// Modest on purpose: rule edits are human-paced, and a stat every couple of
/// seconds is free next to a gating round trip.
const CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// A hot-swappable holder for the resolved rule/source [`Config`], so a
/// `sigil-config` edit takes effect without a daemon restart (#59).
///
/// It is an `RwLock<Arc<Config>>`. A gating decision takes a *snapshot*
/// ([`Self::snapshot`]): it read-locks, clones the (cheap) `Arc`, and unlocks
/// immediately, then evaluates the whole `resolve` against that one `Arc`. A
/// reload takes a *store* ([`Self::store`]): it write-locks and swaps in a new
/// `Arc`. Because a decision holds its own `Arc` for its full duration, a reload
/// that lands mid-decision is invisible to it (no torn read): the decision sees
/// either the entire old config or, next time, the entire new one, never a blend.
struct ConfigCell(std::sync::RwLock<Arc<ConfigSnapshot>>);

/// One config plus the generation it was stored under.
///
/// The generation exists because a lease outlives the decision that created it.
/// `fulfill` snapshots the config, then blocks on the phone for as long as the
/// human takes; a config edit landing during that wait runs invalidation BEFORE
/// the lease exists, so the grant afterwards would file a window under a rule
/// that has since been rewritten. Stamping the generation into the lease binding
/// makes that impossible by construction: a lease granted against generation N
/// simply does not match lookups after a reload, whatever the rule now says.
///
/// It travels WITH the config rather than beside it so a decision cannot read
/// one and then the other across a swap.
struct ConfigSnapshot {
    config: Config,
    generation: u64,
}

impl std::ops::Deref for ConfigSnapshot {
    type Target = Config;
    fn deref(&self) -> &Config {
        &self.config
    }
}

impl ConfigCell {
    fn new(cfg: Config) -> Self {
        Self(std::sync::RwLock::new(Arc::new(ConfigSnapshot {
            config: cfg,
            generation: 0,
        })))
    }

    /// A consistent snapshot for one gating decision. Clone-and-release, so a
    /// concurrent [`store`](Self::store) can never change the config under a
    /// `resolve` in progress.
    fn snapshot(&self) -> Arc<ConfigSnapshot> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Atomically replace the live config, bumping the generation. The brief
    /// write lock means every reader observes either the whole old `Arc` or the
    /// whole new one.
    fn store(&self, cfg: Config) {
        let mut w = self.0.write().unwrap_or_else(|e| e.into_inner());
        *w = Arc::new(ConfigSnapshot {
            config: cfg,
            generation: w.generation.saturating_add(1),
        });
    }
}

impl From<Config> for ConfigCell {
    fn from(cfg: Config) -> Self {
        Self::new(cfg)
    }
}

/// A hot-swappable holder for the built SSH signers, the same shape and rationale
/// as [`ConfigCell`], so `sigil ssh add|remove` takes effect without a daemon
/// restart: the watcher rebuilds the signers from `~/.sigil/ssh-keys.json` on a
/// change. A signing request takes a *snapshot* (clone the `Arc`, release the
/// lock, then route and sign against that one set); a reload takes a *store*
/// (swap in a freshly built set). Because a request holds its own `Arc` for its
/// whole, possibly long, phone-approval duration, a reload mid-request is
/// invisible to it: it serves the entire old set or, next time, the entire new
/// one, never a blend.
struct SshSignersCell(std::sync::RwLock<Arc<Vec<Box<dyn SshSigner>>>>);

impl SshSignersCell {
    fn new(signers: Vec<Box<dyn SshSigner>>) -> Self {
        Self(std::sync::RwLock::new(Arc::new(signers)))
    }

    /// A consistent snapshot for one signing request.
    fn snapshot(&self) -> Arc<Vec<Box<dyn SshSigner>>> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Atomically replace the live signer set.
    fn store(&self, signers: Vec<Box<dyn SshSigner>>) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(signers);
    }
}

/// A hot-swappable keystore, same shape and rationale as [`ConfigCell`].
///
/// A wrapped daemon starts with a store that can read nothing (the file is
/// ciphertext) and swaps in the opened material when the app provisions it. A
/// request takes a snapshot (clone the `Arc`, release the lock) so a provision
/// landing mid-request cannot change the store underneath it.
struct KeystoreCell(std::sync::RwLock<Arc<dyn Keystore>>);

impl KeystoreCell {
    fn new(ks: Arc<dyn Keystore>) -> Self {
        Self(std::sync::RwLock::new(ks))
    }

    fn snapshot(&self) -> Arc<dyn Keystore> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Swap in the opened store. The previous one drops here, which wipes it if
    /// it held material.
    fn store(&self, ks: Arc<dyn Keystore>) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = ks;
    }
}

/// One outstanding de-adoption request, and the machinery to wake the app's
/// subscription when one appears.
///
/// Deliberately tiny: a de-adoption is a rare, human-initiated ceremony, so this
/// holds at most a handful of nonces and nothing secret.
#[derive(Default)]
struct UnwrapRequests {
    inner: Mutex<UnwrapInner>,
    changed: Condvar,
}

#[derive(Default)]
struct UnwrapInner {
    /// Nonces the app has not answered yet.
    open: Vec<String>,
    /// Bumped on every change so a subscriber can block until something moves.
    version: u64,
    /// The last outcome, for the CLI that asked.
    last: Option<(String, bool, String)>,
}

impl UnwrapRequests {
    /// Ask the app to unwrap. Returns the nonce the answer must quote.
    fn request(&self) -> String {
        let nonce = uuid::Uuid::now_v7().to_string();
        let mut inner = self.inner.lock().expect("unwrap requests poisoned");
        inner.open.push(nonce.clone());
        inner.version += 1;
        self.changed.notify_all();
        nonce
    }

    fn version(&self) -> u64 {
        self.inner.lock().expect("unwrap requests poisoned").version
    }

    /// The events a subscriber should see: one per outstanding request.
    fn pending_events(&self) -> Vec<serde_json::Value> {
        let inner = self.inner.lock().expect("unwrap requests poisoned");
        inner
            .open
            .iter()
            .map(|n| serde_json::json!({"kind": "unwrap", "nonce": n}))
            .collect()
    }

    /// Record the app's answer. `false` when no such request is outstanding,
    /// which is how a replayed or invented nonce is refused.
    fn resolve(&self, nonce: &str, ok: bool, reason: &str) -> bool {
        let mut inner = self.inner.lock().expect("unwrap requests poisoned");
        let Some(pos) = inner.open.iter().position(|n| n == nonce) else {
            return false;
        };
        inner.open.remove(pos);
        inner.last = Some((nonce.to_string(), ok, reason.to_string()));
        inner.version += 1;
        self.changed.notify_all();
        true
    }

    /// Wait for the answer to `nonce`, up to `timeout`. `None` on timeout.
    fn wait_for(&self, nonce: &str, timeout: Duration) -> Option<(bool, String)> {
        let deadline = std::time::Instant::now() + timeout;
        let mut inner = self.inner.lock().expect("unwrap requests poisoned");
        loop {
            if let Some((n, ok, reason)) = &inner.last {
                if n == nonce {
                    return Some((*ok, reason.clone()));
                }
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return None;
            }
            let (guard, _) = self
                .changed
                .wait_timeout(inner, left)
                .expect("unwrap requests poisoned");
            inner = guard;
        }
    }

    fn wait_for_change(&self, version: u64, timeout: Duration) {
        let inner = self.inner.lock().expect("unwrap requests poisoned");
        if inner.version != version {
            return;
        }
        let _ = self.changed.wait_timeout(inner, timeout);
    }
}

/// Shared daemon state, cloned (via `Arc`) into every connection worker.
pub struct Core {
    /// The keystore, swappable because a wrapped daemon starts unable to read
    /// anything and gains its material when the app provisions.
    keystore: KeystoreCell,
    /// The store of threshold-sealed secrets (inline-`env` source values), loaded
    /// once at arm time. A record here is opened by the two-party combine (the
    /// phone's partial `Z_F` plus the Mac share `m`), never a key at rest.
    threshold: Mutex<crate::threshold::ThresholdStore>,
    leases: LeaseStore,
    gate: ApprovalGate,
    pending: Arc<PendingRegistry>,
    /// The remote approvers, one per paired phone (#36 multi-device), when the
    /// phone is the factor. Held so the control handler can enumerate in-flight
    /// remote requests (and their delivery-receipt state) across all devices onto
    /// the `pending` surface the Mac reads. Empty for the local factors, which
    /// enumerate the [`pending`](Self::pending) registry alone. These are the SAME
    /// approvers the ToDaemon owner loops drive; read-only here. A single-device
    /// daemon holds exactly one, behaving as before.
    remote: Vec<Arc<RemoteApprover>>,
    proc_table: Box<dyn ProcessTable + Send + Sync>,
    /// The provider registry: a command's config names a provider by id, and the
    /// daemon dispatches the run to it. 1Password and env-file ship by default;
    /// the seam is generic and each provider owns its own tool discovery.
    providers: ProviderRegistry,
    /// The generic rule/source config: an ordered rule list matched against each
    /// invocation, resolving to a provider + source + lease policy. Loaded at arm
    /// time and hot-swappable (#59): the config watcher re-reads it when
    /// `config.json` changes so edits apply without a restart. The core holds no
    /// concept of `op`; op-ness lives in user-authored rules.
    config: ConfigCell,
    lease_ttl: Duration,
    /// The approving factor resolved at arm time (residual #1 mitigation).
    factor: Factor,
    /// The pluggable SSH key sources this daemon serves on the agent socket,
    /// resolved from `~/.sigil/ssh-keys.json` and hot-reloaded on change (so
    /// `sigil ssh add|remove` needs no restart). Empty means the agent advertises
    /// no keys (and `ssh-add -l` shows none). Sigil is the phone-gate regardless
    /// of which signer holds the key.
    ssh_signers: SshSignersCell,
    /// Audit logging: `Some(retention_days)` appends a metadata-only line per
    /// decision to `history.jsonl` (pruned to the window); `None` disables it.
    /// The real daemon enables it; tests leave it off so they never write to a
    /// developer's `~/.sigil`.
    audit: Option<u32>,
    /// What the keystore file was at startup: plaintext, Secure-Enclave wrapped,
    /// or a downgrade (plaintext where wrapped was promised).
    ///
    /// Read ONCE, before the control socket listens, and never re-read. A file
    /// swapped underneath a running daemon must not become authoritative, and
    /// every later answer (status, doctor, a provision's digest check) has to come
    /// from the same snapshot this daemon armed against.
    seal: crate::keystore_seal::SealState,
    /// Set once the Sigil app has handed over material matching [`Self::seal`]'s
    /// expected digest. A wrapped daemon serves nothing until this is true, and a
    /// plaintext daemon ignores it entirely.
    provisioned: AtomicBool,
    /// Outstanding de-adoption requests, waiting for the app to answer.
    unwrap_requests: UnwrapRequests,
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
    /// The rung-2 owned endpoint (`host:port`) this daemon binds for a direct
    /// link to this device (#51). `None` (the default) means direct transport is
    /// OFF for this device: no listener is bound, the approver keeps its bare relay
    /// transport, and the approval path is byte-identical to the relay-only daemon.
    /// `Some` opts this device into the direct ladder, still fully envelope-gated.
    pub direct_endpoint: Option<String>,
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
fn load_remote_pairing(ks: &Arc<dyn Keystore>) -> Vec<RemotePairingConfig> {
    match crate::pairing_store::load_all(ks.as_ref()) {
        Ok(cfgs) => cfgs,
        Err(e) => {
            eprintln!("sigil daemon: ignoring an unreadable pairing config: {e}");
            Vec::new()
        }
    }
}

/// Build the approval gate for a resolved [`Factor`]. Only [`Factor::DevInsecure`]
/// enables the dev switch and the control socket; [`Factor::NoFactor`] denies
/// every request; the real factors are the phone (sealed remote approval) and
/// the hardware biometric.
///
/// Returns the gate plus, for the phone factor, the live [`RemoteApprover`]
/// handles (one per paired phone) so the caller can run each device's ToDaemon
/// owner loop (the sole reader of that device's channel, which captures its
/// arm-time push token and routes its approval responses to their waiters). The
/// other factors have no relay channel and hand back an empty vector.
///
/// **N == 1 is byte-identical.** With exactly one paired device the gate is a
/// bare [`RemoteApprover`], exactly as the reviewed single-device path. A
/// [`RingApprover`] is built ONLY for N >= 2, so the common case never touches the
/// ring coordinator (#36 multi-device).
fn build_gate(
    factor: Factor,
    remote: Vec<RemotePairingConfig>,
    _keystore: &Arc<dyn Keystore>,
    pending: &Arc<PendingRegistry>,
) -> anyhow::Result<(ApprovalGate, Vec<Arc<RemoteApprover>>, Vec<DirectAcceptor>)> {
    let mut acceptors: Vec<DirectAcceptor> = Vec::new();
    let (approver, listeners): (Box<dyn Approver>, Vec<Arc<RemoteApprover>>) = match factor {
        Factor::Phone => {
            assert!(
                !remote.is_empty(),
                "phone factor implies at least one pairing config"
            );
            // The disk-backed push registration store, shared across devices: it is
            // keyed by mailbox, so N devices register N tokens under N mailboxes and
            // coexist without collision. Survives restarts.
            let push_store = Arc::new(crate::push_store::PushStore::load());
            // Build one unchanged single-device approver per paired phone.
            let mut devices: Vec<Arc<RemoteApprover>> = Vec::with_capacity(remote.len());
            for cfg in remote {
                let relay = DaemonRelay::new(&cfg.relay_url, cfg.mailbox())
                    .map_err(|e| anyhow::anyhow!("reaching relay {}: {e}", cfg.relay_url))?;
                let relay: Arc<dyn Transport> = Arc::new(relay);

                // Direct transport (#51) is OFF unless this device carries a
                // `direct_endpoint`. When set, bind a rung-2 listener and build the
                // approver over a FallbackTransport (relay + optional verified
                // direct primary); a bind failure logs and degrades to relay-only,
                // never refusing to arm. When unset, the approver is built on the
                // BARE relay exactly as the reviewed path, so it is byte-identical.
                let (transport, direct, listener): (
                    Arc<dyn Transport>,
                    Option<Arc<FallbackTransport>>,
                    Option<DirectListener>,
                ) = match cfg.direct_endpoint.as_deref() {
                    Some(endpoint) => match DirectListener::bind(endpoint) {
                        Ok(listener) => {
                            let fb = Arc::new(FallbackTransport::new(relay));
                            (fb.clone(), Some(fb), Some(listener))
                        }
                        Err(e) => {
                            eprintln!(
                                "sigil daemon: direct endpoint {endpoint} unavailable ({e}); serving this device over the relay only"
                            );
                            (relay, None, None)
                        }
                    },
                    None => (relay, None, None),
                };

                // Hold each approver in an Arc: the gate drives it (bare, or via the
                // ring) and `serve` keeps a clone to run its ToDaemon owner loop.
                // They share the waiter map, so the owner (the sole reader) routes
                // each response to the approval waiting for it.
                let mut approver = RemoteApprover::new(transport, cfg.daemon_identity, cfg.phone)
                    .with_push(push_store.clone())
                    // Share the pending registry so a remote request's arrival,
                    // delivery receipt, or completion bumps the version a
                    // `subscribe_pending` client waits on (Sent -> Delivered).
                    .with_pending(pending.clone());
                if let Some(fb) = direct {
                    // Wire the SAME FallbackTransport as the promote/demote seam.
                    approver = approver.with_direct(fb);
                }
                let approver = Arc::new(approver);
                // A device with a bound direct listener gets an acceptor thread in
                // `serve`; a relay-only device produces none.
                if let Some(listener) = listener {
                    acceptors.push(DirectAcceptor {
                        approver: approver.clone(),
                        listener,
                    });
                }
                devices.push(approver);
            }
            // N == 1: the gate is the bare approver (reviewed path, unchanged).
            // N >= 2: compose the ring-all / first-wins coordinator over them.
            let gate_approver: Box<dyn Approver> = if devices.len() == 1 {
                Box::new(devices[0].clone())
            } else {
                Box::new(crate::remote::RingApprover::new(devices.clone()))
            };
            (gate_approver, devices)
        }
        // The biometric unwrap is the only gate; an unresolved decision fails
        // closed (no control socket, no dev switch).
        Factor::Biometric => (Box::new(LocalApprover::new(pending.clone())), Vec::new()),
        // The one place the forgeable dev paths are wired.
        Factor::DevInsecure => (
            Box::new(
                LocalApprover::new(pending.clone())
                    .with_dev(DevMode::from_env())
                    .with_control_socket(true),
            ),
            Vec::new(),
        ),
        Factor::NoFactor => (Box::new(NullApprover), Vec::new()),
    };
    Ok((ApprovalGate::new(approver), listeners, acceptors))
}

/// A bound rung-2 direct listener paired with the [`RemoteApprover`] whose device
/// it serves (#51). `serve` spawns one acceptor thread per entry, which polls the
/// listener and hands each dial to
/// [`RemoteApprover::verify_and_promote`](crate::remote::RemoteApprover::verify_and_promote).
/// Only devices with a `direct_endpoint` produce one; a relay-only daemon has an
/// empty vector and spawns no acceptor, so its behavior is unchanged.
pub struct DirectAcceptor {
    /// The approver whose device this listener serves.
    approver: Arc<RemoteApprover>,
    /// The bound rung-2 listener the phone dials.
    listener: DirectListener,
}

impl Core {
    /// Build the production core, resolving the approving factor from the host
    /// (a paired phone, then a hardware biometric) and `dev_insecure`. With no
    /// real factor and no `--dev-insecure`, the factor is [`Factor::NoFactor`]
    /// and every gated request fails closed.
    pub fn for_host(
        dev_insecure: bool,
    ) -> anyhow::Result<(Self, Vec<Arc<RemoteApprover>>, Vec<DirectAcceptor>)> {
        let keystore = keystore::for_host();
        // If an older build left this machine's pairing in the login keychain,
        // say so once at startup. Nothing is moved automatically (a keychain read
        // can raise a system prompt, and a daemon that blocks on a dialog is not a
        // daemon), but silence here would read as "the pairing vanished".
        if let Some(note) = keystore::legacy_keychain_notice(keystore.as_ref()) {
            eprintln!("{note}");
        }
        // Classify the keystore file ONCE, here, before anything listens. A read
        // this daemon does later could see a file swapped underneath it; this one
        // cannot, and it is the snapshot every later answer refers to.
        let seal = read_seal_state();
        if let Some(why) = seal.explain(false) {
            eprintln!("sigil daemon: {why}");
        }
        // The threshold-sealed secrets (inline-`env` source values). A
        // missing/unreadable store is logged and treated as empty so the daemon
        // still arms (env-backed rules then refuse until their values are set).
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
            phone_paired: !remote.is_empty(),
            biometric: keystore.is_biometric(),
        };
        let factor = factor::resolve(&inputs);
        let (gate, remote_listeners, direct_acceptors) =
            build_gate(factor, remote, &keystore, &pending)?;

        // Load the served SSH identities from ~/.sigil/ssh-keys.json and build a
        // signer per source (file-based today). A bad config is logged and
        // treated as "no keys" so the daemon still arms.
        let ssh_signers = match sshagent::SshKeyConfig::load() {
            Ok(cfg) => build_ssh_signers(&cfg),
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

        let core = Self {
            keystore: KeystoreCell::new(keystore),
            threshold: Mutex::new(threshold),
            leases: LeaseStore::new(),
            gate,
            pending,
            remote: remote_listeners.clone(),
            proc_table: Box::new(SysProcessTable),
            providers: ProviderRegistry::with_defaults(),
            config: config.into(),
            lease_ttl: DEFAULT_LEASE_TTL,
            factor,
            ssh_signers: SshSignersCell::new(ssh_signers),
            audit: Some(
                crate::settings::Settings::load()
                    .map(|s| s.retention_days)
                    .unwrap_or(30),
            ),
            seal,
            provisioned: AtomicBool::new(false),
            unwrap_requests: UnwrapRequests::default(),
        };
        Ok((core, remote_listeners, direct_acceptors))
    }

    /// The full status report, the daemon's answer to `Frame::Status`. It is the
    /// source of truth for the host-side facts from [`crate::report`].
    fn status_report(&self) -> crate::json::StatusJson {
        let mut s = crate::report::status(true);
        // Only the daemon can answer these: it classified the keystore once at
        // startup and knows whether the app has provisioned it. Anyone else would
        // be guessing at a file they may not be allowed to read.
        let provisioned = self.provisioned.load(Ordering::SeqCst);
        s.keystore_sealed = Some(matches!(
            self.seal,
            crate::keystore_seal::SealState::Sealed { .. }
        ));
        s.keystore_provisioned = Some(provisioned);
        s
    }

    /// The doctor checks, plus the one only the daemon can answer: whether the
    /// sealed store it is serving from still matches the one on disk.
    ///
    /// This exists because the stale-armed-store bug was invisible from outside.
    /// `sigil status` reads `threshold.db` fresh and said "1 sealed secret(s)"
    /// while the running daemon held none, and the only symptom downstream was a
    /// gated command quietly running with nothing injected. With
    /// [`Self::reload_threshold`] wired into the watcher this state should not
    /// occur, which is exactly what makes it a doctor check: it is the regression
    /// alarm, not a routine condition.
    fn doctor_report(&self) -> Vec<crate::json::CheckJson> {
        let mut checks = crate::report::doctor(true);
        let (ok, hint) = self.sealed_store_drift();
        checks.push(crate::json::CheckJson {
            label: "sealed store matches the armed daemon".to_string(),
            ok,
            hint,
        });
        checks
    }

    /// Compare the armed sealed records against `threshold.db`. Returns the check
    /// verdict and its hint. An unreadable store is a failure, not a pass: the
    /// daemon cannot tell whether it is serving stale records.
    fn sealed_store_drift(&self) -> (bool, String) {
        let armed = self.armed_sealed_fingerprint();
        let disk = match crate::threshold::ThresholdStore::load() {
            Ok(s) => s,
            Err(e) => return (false, format!("the sealed store could not be read: {e}")),
        };
        let mut on_disk: Vec<(String, String)> = disk
            .secrets
            .iter()
            .map(|r| (r.account_id.clone(), r.ephemeral_pub.clone()))
            .collect();
        on_disk.sort();
        if armed == on_disk {
            return (true, format!("{} sealed secret(s)", armed.len()));
        }
        let hint = if armed.len() != on_disk.len() {
            format!(
                "the daemon armed {} sealed secret(s); the store on disk holds {}. \
                 Gated runs may inject nothing. Resync: sigil restart",
                armed.len(),
                on_disk.len()
            )
        } else {
            format!(
                "the daemon armed {} sealed secret(s) but they were re-sealed since. \
                 Resync: sigil restart",
                armed.len()
            )
        };
        (false, hint)
    }

    /// Reload the rule/source config from disk into the hot cell (#59).
    ///
    /// **Fail-closed by construction:** the swap ([`ConfigCell::store`]) is
    /// reached ONLY on the `Ok` arm, i.e. only after [`Config::load`] has fully
    /// parsed and validated the file. A malformed, truncated (a
    /// half-written save), or unreadable file returns `Err` here WITHOUT touching
    /// the cell, so the last-good rules stay in force and gating is never
    /// downgraded by a bad reload. The caller logs the `Err` and keeps serving.
    fn reload_config(&self) -> Result<(), String> {
        match Config::load() {
            Ok(cfg) => {
                let old = self.config.snapshot();
                self.config.store(cfg);
                self.invalidate_leases_for_config_change(&old, &self.config.snapshot());
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Kill every lease whose covering rule did not survive the reload unchanged.
    ///
    /// A lease names its rule by a *string*, and that string points at mutable
    /// config. Without this, rewriting a rule while its window is live transfers
    /// the window to the new definition: a rule renamed to match `curl` inherits
    /// an approval the human gave for `op`, and with a sealed `env` rule that is
    /// the cached credential injected into a command nobody approved. So a lease
    /// survives a reload only if its rule is still there and still *identical*.
    ///
    /// Three things invalidate:
    ///
    /// 1. the rule is gone;
    /// 2. the rule differs in any field (match, mode, source, lease policy,
    ///    timeout) by a whole-struct comparison, not a name check;
    /// 3. the SOURCE the rule injects from differs in any field, since the lease
    ///    may be holding that source's values.
    ///
    /// Fails safe by construction: anything it cannot pair up is treated as
    /// changed. A re-seal that leaves config.json byte-identical is caught
    /// elsewhere, by the lease's source-material binding.
    fn invalidate_leases_for_config_change(&self, old: &Config, new: &Config) {
        if self.leases.active() == 0 {
            return;
        }
        for rule in &old.rules {
            let survived = new.rules.iter().any(|r| r == rule)
                && source_for(old, rule) == source_for(new, rule);
            if survived {
                continue;
            }
            let killed = self.leases.revoke_scope(&rule.name);
            if killed > 0 {
                eprintln!(
                    "sigil daemon: config changed under rule '{}'; revoked {killed} lease(s) \
                     (any cached values zeroized)",
                    rule.name
                );
            }
        }
    }

    /// Rebuild the SSH signers from `~/.sigil/ssh-keys.json` and swap them in, so
    /// `sigil ssh add|remove` is served without a restart. Fail-closed like
    /// [`Self::reload_config`]: on an unreadable/malformed store it returns `Err`
    /// and the last-good signer set stays live (the watcher logs and keeps
    /// serving), never dropping to no keys on a transient half-written file.
    fn reload_ssh_signers(&self) -> Result<(), String> {
        match sshagent::SshKeyConfig::load() {
            Ok(cfg) => {
                self.ssh_signers.store(build_ssh_signers(&cfg));
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Reload the threshold-sealed store from disk into the hot cell.
    ///
    /// Without this the daemon read `threshold.db` exactly once, at arm time, and
    /// never again: sealing a value into an inline `env` source while the daemon
    /// was already up left the armed store empty, every gated run took the
    /// degrade-to-plain-gate path in [`fulfill`], and nothing was injected until a
    /// restart. config.json and ssh-keys.json already hot-reloaded; this closes
    /// the third file.
    ///
    /// Fail-closed on the same terms as [`Self::reload_config`]: the swap is
    /// reached ONLY on the `Ok` arm, so a malformed or half-written store leaves
    /// the last-good records in force rather than silently dropping injection.
    /// Returns the number of records now armed, for the caller's log line.
    ///
    /// No lease invalidation is needed here. A lease that caches values binds to
    /// the ephemeral point `E` of the exact record they came from (see
    /// [`lease::LeaseBinding::cached`]), which is fresh on every re-seal, so a
    /// reload that replaces a record makes the lease lookup miss and the run
    /// re-approves; a reload that drops one degrades the rule to a plain gate.
    fn reload_threshold(&self) -> Result<usize, String> {
        match crate::threshold::ThresholdStore::load() {
            Ok(store) => {
                let n = store.secrets.len();
                *self.threshold.lock().expect("threshold store poisoned") = store;
                Ok(n)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// The armed sealed records as `(id, ephemeral_pub)` pairs, sorted. The
    /// ephemeral point is public and is what makes a re-seal visible: it is fresh
    /// on every seal, so two stores with the same ids but different points are
    /// genuinely different stores. Used only to compare against disk.
    fn armed_sealed_fingerprint(&self) -> Vec<(String, String)> {
        let store = self.threshold.lock().expect("threshold store poisoned");
        let mut v: Vec<(String, String)> = store
            .secrets
            .iter()
            .map(|r| (r.account_id.clone(), r.ephemeral_pub.clone()))
            .collect();
        v.sort();
        v
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

/// Build one SSH signer per in-source key source. The file signer (local key
/// files) is the only in-source signer; the 1Password case is a plain gated
/// command now, not an SSH signer. The threshold-stored source is NOT an
/// [`SshSigner`] (its sign needs the phone's partial and the Mac share); it is
/// served and signed inline in [`Core`] via the threshold store.
fn build_ssh_signers(cfg: &sshagent::SshKeyConfig) -> Vec<Box<dyn SshSigner>> {
    let mut signers: Vec<Box<dyn SshSigner>> = Vec::new();
    let file_keys = cfg.file_keys();
    if !file_keys.is_empty() {
        signers.push(Box::new(sshagent::FileSshSigner::new(file_keys)));
    }
    signers
}

/// The threshold-stored SSH identities configured on disk, each with the id its
/// sealed private key lives under in the threshold store. Read fresh from
/// `~/.sigil/ssh-keys.json` (a bad/absent config yields none) so `sigil ssh
/// add-stored | remove` is reflected without a daemon restart, mirroring the file
/// signer's hot reload. Holds no key material.
fn stored_ssh_identities() -> Vec<(ServedIdentity, String)> {
    sshagent::SshKeyConfig::load()
        .map(|cfg| cfg.stored_keys())
        .unwrap_or_default()
}

impl SshBackend for Core {
    fn identities(&self) -> Vec<ServedIdentity> {
        let mut ids: Vec<ServedIdentity> = self
            .ssh_signers
            .snapshot()
            .iter()
            .flat_map(|s| s.identities())
            .collect();
        // Advertise the threshold-stored keys alongside the in-source signers.
        ids.extend(stored_ssh_identities().into_iter().map(|(id, _)| id));
        ids
    }

    /// Gate one SSH signature on the phone and, on approval, produce it from the
    /// source that owns the key. Sigil is the phone-gate regardless of key source:
    /// the gate here is the same approval path as an injected secret, with two
    /// differences the security review must weigh (see `sshagent` module docs):
    /// every signature is gated (no lease short-circuit), and the private key is
    /// briefly in daemon RAM for the one signature. Two sources are handled:
    ///
    /// * **file** — an [`SshSigner`] reads the key from a local file, signs, wipes.
    /// * **threshold-stored** — the sealed private key is opened per-signature by
    ///   combining the phone's returned partial `Z_F` with the Mac share `m` (the
    ///   same two-party combine as an inline env secret), decoded, signed, and
    ///   zeroized. This request carries a [`ThresholdChallenge`] so the phone
    ///   produces `Z_F`; an approve with no partial (e.g. a local factor) fails
    ///   closed rather than emitting a signature.
    ///
    /// Either way the key never reaches the SSH client.
    fn approve_and_sign(&self, req: SignRequest<'_>) -> Option<Vec<u8>> {
        // Same gate as the command path: a sealed keystore this daemon has not
        // been handed material for cannot sign anything, and must not pretend to.
        let provisioned = self.provisioned.load(Ordering::SeqCst);
        if self.seal.blocks_serving(provisioned) {
            if let Some(why) = self.seal.explain(provisioned) {
                eprintln!("sigil daemon: ssh sign refused; {why}");
            }
            return None;
        }
        // Route the request to the source that owns this identity. Hold the file
        // signer snapshot for the whole request so a mid-approval reload cannot
        // swap the set under us. A stored key resolves to its sealed record, held
        // for both the challenge and the per-signature decrypt.
        let signers = self.ssh_signers.snapshot();
        let file_signer = signers.iter().find(|s| s.owns(&req.id.key_blob));
        let sealed = self.stored_record_for(&req.id.key_blob);
        if file_signer.is_none() && sealed.is_none() {
            // A sign request for a key we do not serve (or whose sealed record is
            // missing): fail closed.
            return None;
        }

        // No account credential concept: a source opens its own key. Sigil is only
        // the phone-gate here.
        let account_label = String::new();

        // The approval screen shows a hash of the data to sign, never raw bytes.
        let data_fingerprint = sshagent::sha256_fingerprint(req.data);
        // The same one-line request log the op path gets (`log_request`), so a
        // sign request is always visible in the daemon log the moment it
        // arrives, before the phone answers. Metadata only: key label, derived
        // host, and the data hash the approver will see; never key material.
        log_ssh_sign_request(
            &req.id.label,
            &req.host.host,
            &data_fingerprint,
            req.caller_pid,
        );
        // The data fingerprint is folded into the scope so the gate's grant-key
        // coalescing can never let two DIFFERENT challenges share one approval: a
        // signature is a distinct auth event over distinct data, and the human
        // approved *this* data's hash. Only a byte-identical re-sign (which is
        // deterministic, so the same signature) may coalesce.
        let scope = ssh_sign_scope(&req.id.label, &data_fingerprint);
        let caller = lease::walk_ancestry(self.proc_table.as_ref(), req.caller_pid.unwrap_or(-1));
        let gk = lease::grant_key(&caller, lease::ScopeKind::SshSignature, "", &scope);

        let challenge = SshChallenge {
            key_label: req.id.label.clone(),
            host: req.host.host.clone(),
            binding: req.host.binding,
            fingerprint: data_fingerprint,
        };
        // A stored key carries its threshold challenge to the phone (the base point
        // E it key-agrees against), exactly like an inline env secret; a file key
        // sources its own material and carries none.
        let threshold = sealed
            .as_ref()
            .map(|record| sigil_proto::ThresholdChallenge {
                account_id: record.account_id.clone(),
                label: req.id.label.clone(),
                ephemeral_pub: record.ephemeral_pub.clone(),
                se_key_id: record.se_key_id.clone(),
                ecdh_algo: crate::threshold::ecdh_algo_tag(record.ecdh_algo).to_string(),
            });
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
            // Every signature is gated afresh (no lease short-circuit).
            lease: LeasePolicy::RunOnce,
            ssh: Some(challenge),
            threshold,
        };

        let outcome = self.gate.decide(gk, &ctx);
        if !outcome.decision.is_grant() {
            return None;
        }

        // The gate approved. A stored key is opened per-signature via the two-party
        // combine (phone partial Z_F + Mac share m), decoded, signed, and wiped; a
        // file key is signed from its local file.
        if let Some(record) = &sealed {
            return self.sign_stored(record, req.data, &outcome);
        }
        // A file signer sources its own key and holds it only for the one signature.
        file_signer?.sign(req.id, req.data)
    }
}

impl Core {
    /// The sealed threshold record for the stored SSH key advertising `key_blob`,
    /// or `None` if no stored entry serves it (then it is a file key or unknown).
    /// Reads `~/.sigil/ssh-keys.json` for the entry and `~/.sigil/threshold.db` for
    /// its sealed record; a missing store or record yields `None` (fail closed).
    fn stored_record_for(
        &self,
        key_blob: &[u8],
    ) -> Option<sigil_proto::threshold::ThresholdRecord> {
        let account_id = stored_ssh_identities()
            .into_iter()
            .find(|(id, _)| id.key_blob == key_blob)
            .map(|(_, account_id)| account_id)?;
        let store = crate::threshold::ThresholdStore::load().ok()?;
        store.get(&account_id).cloned()
    }

    /// Open a threshold-stored SSH private key with the phone's partial `Z_F` and
    /// the Mac share `m`, sign `data`, and zeroize. `outcome` is the approval that
    /// carried `Z_F`. The two-party combine and per-request `K` handling are the
    /// reviewed [`crate::threshold::decrypt`]; the opened key is the OpenSSH PEM,
    /// decoded and signed by [`sshagent::sign_openssh_ed25519`] in a
    /// zeroize-on-drop buffer, matching the file signer's custody. Fails closed on
    /// any missing input (no partial, no Mac share, a wrong combine) rather than
    /// emitting a signature.
    fn sign_stored(
        &self,
        record: &sigil_proto::threshold::ThresholdRecord,
        data: &[u8],
        outcome: &crate::approve::ApprovalOutcome,
    ) -> Option<Vec<u8>> {
        // The approve must carry the phone's partial Z_F; a local/dev factor cannot
        // produce one, so a stored key cannot be opened without the phone.
        let Some(zf) = outcome.zf.as_deref() else {
            eprintln!(
                "sigil daemon: ssh sign refused; approval carried no threshold partial (no phone factor?)"
            );
            return None;
        };
        let ks = self.keystore.snapshot();
        let m = match crate::threshold::load_mac_share(ks.as_ref()) {
            Ok(Some(m)) => m,
            Ok(None) => {
                eprintln!("sigil daemon: ssh sign refused; no Mac threshold share (re-pair)");
                return None;
            }
            Err(e) => {
                eprintln!("sigil daemon: ssh sign refused; {e}");
                return None;
            }
        };
        // K = combine(Z_M, Z_F, E, id); open the sealed PEM into a wiped buffer.
        let pem = match crate::threshold::decrypt(record, &m, zf) {
            Ok(pem) => pem,
            Err(e) => {
                eprintln!("sigil daemon: ssh sign refused; stored key decrypt failed: {e}");
                return None;
            }
        };
        drop(m); // the Mac share is held only for the one combine
                 // Decode and sign inside sshagent; `pem` (Zeroizing) is wiped on drop here.
        sshagent::sign_openssh_ed25519(&pem, data)
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
    let (core, remote_listeners, direct_acceptors) = Core::for_host(dev_insecure)?;
    let core = Arc::new(core);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()
        .context("building tokio runtime")?;
    let result = rt.block_on(serve(core, remote_listeners, direct_acceptors));
    // Bound the teardown instead of joining it. `Runtime::drop` waits for
    // in-flight blocking tasks, and a long-lived connection handler (the Mac
    // app's `subscribe_pending` stream never returns while its client stays
    // connected) can pin that join forever. That exact wedge shipped: serve()
    // bailed, both listeners dropped, and the process sat alive-but-deaf for a
    // day while launchd's KeepAlive saw a healthy pid and never respawned it.
    // A bounded shutdown abandons stragglers so an erroring daemon EXITS and
    // launchd brings up a clean one within seconds.
    rt.shutdown_timeout(Duration::from_secs(2));
    result
}

/// How long the accept loop pauses after a listener-level `accept` error
/// before retrying, so a persistent condition (fd exhaustion) cannot spin the
/// loop hot. Errors on an individual accepted connection do not wait.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(200);

/// Ready one accepted connection for its blocking handler: back to a std,
/// blocking stream with the read timeout armed.
///
/// An error here is a property of the ONE connection, never of the listener.
/// The caller drops the connection and MUST keep accepting; propagating this
/// out of the serve loop shipped as a daemon-killing bug (five probe races =
/// five full daemon deaths in one day's log).
fn ready_conn(stream: tokio::net::UnixStream) -> io::Result<UnixStream> {
    ready_std_conn(stream.into_std()?)
}

/// The std half of [`ready_conn`], split out so the dead-peer behavior is
/// directly testable without a tokio reactor.
///
/// On macOS, `setsockopt(SO_RCVTIMEO)` on a unix-stream socket whose peer has
/// FULLY disconnected fails with EINVAL, deterministically: an empirical
/// probe on macOS 26 measured 2000/2000 EINVAL for a closed peer, 0/2000 for
/// a live peer, and 0/500 for a half-closed (shutdown-write) peer. EINVAL
/// here is therefore a precise dead-peer detector, never a live client's
/// error, and a dead peer's connection is worthless by definition. It is also
/// ROUTINE traffic: the Mac app's `daemonRunning()` liveness probe and
/// `sigil up`'s socket checks are connect-then-close by design, every few
/// seconds. The caller treats EINVAL as a silent normal drop and logs
/// anything else loudly.
fn ready_std_conn(std_stream: UnixStream) -> io::Result<UnixStream> {
    std_stream.set_nonblocking(false)?;
    std_stream.set_read_timeout(Some(CONN_READ_TIMEOUT))?;
    Ok(std_stream)
}

/// True when a [`ready_conn`] failure is the deterministic dead-peer EINVAL
/// (see [`ready_std_conn`]): the peer hung up before we could serve it, which
/// liveness probes do by design. Silent drop; anything else deserves a log.
fn is_dead_peer(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::EINVAL)
}

async fn serve(
    core: Arc<Core>,
    remote_listeners: Vec<Arc<RemoteApprover>>,
    direct_acceptors: Vec<DirectAcceptor>,
) -> anyhow::Result<()> {
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

    let sealed = core
        .threshold
        .lock()
        .expect("threshold store poisoned")
        .secrets
        .len();
    eprintln!(
        "sigil daemon: armed on {} · {sealed} sealed secret(s) · factor: {}",
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

    // One ToDaemon owner PER paired device (#36 multi-device). Each is the sole
    // reader of ITS device's ToDaemon channel: it captures that phone's arm-time
    // push token the instant it lands (instead of letting it expire in the relay
    // before the next approval looks) and routes that device's approval responses
    // to their waiting round trips. Each runs on its own thread (its recv is a
    // blocking long-poll) and stops when the shared shutdown flag is set. Because
    // each device has exactly one reader, no two readers can steal each other's
    // messages, and an approval piggybacks the poll it is already holding, so there
    // is no lock and no latency coupling to the relay's hold. A single-device
    // daemon spawns exactly one, as before.
    let listener_shutdown = Arc::new(AtomicBool::new(false));
    let listener_handles: Vec<std::thread::JoinHandle<()>> = remote_listeners
        .into_iter()
        .enumerate()
        .map(|(i, approver)| {
            let stop = listener_shutdown.clone();
            std::thread::Builder::new()
                .name(format!("sigil-todaemon-owner-{i}"))
                .spawn(move || approver.run_todaemon_owner(&stop))
                .expect("spawning the ToDaemon owner")
        })
        .collect();

    // One direct acceptor PER device that opted into rung-2 direct transport
    // (#51), OFF by default (a device with no `direct_endpoint` produces none, so
    // a relay-only daemon spawns nothing here and is byte-identical). Each polls
    // its bound listener for a phone dial and hands each accepted link to that
    // device's `verify_and_promote`, which installs a direct primary ONLY after an
    // envelope opens as the pinned peer. A rogue LAN dial is dropped at that gate;
    // the relay serves throughout, so an acceptor never gates or delays an
    // approval. Shares the same shutdown flag as the owner loops.
    let acceptor_handles: Vec<std::thread::JoinHandle<()>> = direct_acceptors
        .into_iter()
        .enumerate()
        .map(|(i, acc)| {
            let stop = listener_shutdown.clone();
            std::thread::Builder::new()
                .name(format!("sigil-direct-acceptor-{i}"))
                .spawn(move || acc.approver.run_direct_acceptor(&acc.listener, &stop))
                .expect("spawning the direct acceptor")
        })
        .collect();

    // The config hot-reloader (#59): picks up `sigil-config` edits without a
    // restart. Shares the shutdown flag so it stops with the daemon.
    let config_watcher = spawn_config_watcher(core.clone(), listener_shutdown.clone());

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("sigil daemon: shutting down (leases zeroized)");
                core.leases.clear();
                listener_shutdown.store(true, Ordering::SeqCst);
                break;
            }
            accepted = listener.accept() => {
                // A listener-level accept error (fd exhaustion, a torn-down
                // socket) must not end the daemon: log, breathe, keep serving.
                let stream = match accepted {
                    Ok((stream, _)) => stream,
                    Err(e) => {
                        eprintln!("sigil daemon: control accept error: {e}");
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                        continue;
                    }
                };
                let Some(permit) = conns.try_enter() else {
                    eprintln!(
                        "sigil daemon: refusing a control connection: at the concurrency cap ({MAX_CONCURRENT_CONNS})"
                    );
                    continue; // dropping `stream` closes it
                };
                // A failed ready-up is the one connection's problem; drop it
                // and keep accepting. A dead-peer EINVAL is a liveness probe
                // that already hung up (routine, every few seconds): silent.
                let std_stream = match ready_conn(stream) {
                    Ok(s) => s,
                    Err(e) if is_dead_peer(&e) => continue,
                    Err(e) => {
                        eprintln!("sigil daemon: dropping a control connection: {e}");
                        continue;
                    }
                };
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
                let stream = match accepted {
                    Ok((stream, _)) => stream,
                    Err(e) => {
                        eprintln!("sigil daemon: ssh accept error: {e}");
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                        continue;
                    }
                };
                let Some(permit) = conns.try_enter() else {
                    eprintln!(
                        "sigil daemon: refusing an ssh-agent connection: at the concurrency cap ({MAX_CONCURRENT_CONNS})"
                    );
                    continue;
                };
                let std_stream = match ready_conn(stream) {
                    Ok(s) => s,
                    Err(e) if is_dead_peer(&e) => continue,
                    Err(e) => {
                        eprintln!("sigil daemon: dropping an ssh-agent connection: {e}");
                        continue;
                    }
                };
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

    // Let each device's ToDaemon owner observe the shutdown flag and exit. Each may
    // be mid-poll (up to one relay long-poll hold), so these joins are best-effort
    // and bounded by that; the process is exiting regardless.
    for handle in listener_handles {
        let _ = handle.join();
    }
    // Each direct acceptor wakes within one accept-poll of the flag being set.
    for handle in acceptor_handles {
        let _ = handle.join();
    }
    // The watcher wakes at most one poll interval after the flag is set.
    if let Some(handle) = config_watcher {
        let _ = handle.join();
    }

    let _ = fs::remove_file(&sock);
    let _ = fs::remove_file(&ssh_sock);
    Ok(())
}

/// The config file's modification time, or `None` if it is absent/unreadable.
/// The watcher compares this across polls; a change (including create/remove)
/// triggers a reload attempt.
fn config_mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Watch `~/.sigil/config.json` and hot-swap the daemon's in-memory rule set when
/// it changes, so `sigil-config` edits (and the Mac app's Rules editor) apply
/// without a restart (#59).
///
/// It stat-polls the mtime on a modest interval rather than wiring an OS file
/// watcher: rule edits are human-paced, the daemon is single-user, and a `stat`
/// every couple of seconds costs nothing. On a detected change it calls
/// [`Core::reload_config`], which is fail-closed: it swaps only on a clean parse,
/// so a malformed or half-written file leaves the last-good rules in force and we
/// log a warning here rather than downgrade gating.
///
/// Two more files ride the same tick, on the same fail-closed terms:
/// `ssh-keys.json` (so `sigil ssh add|remove` is served without a restart) and
/// `threshold.db` (so sealing a value into an inline `env` source takes effect on
/// the next request instead of on the next restart).
///
/// Runs on its own thread and exits when `shutdown` is set. Returns `None` (no
/// thread) when there is no resolvable config path (no HOME), which only happens
/// in degenerate environments.
fn spawn_config_watcher(
    core: Arc<Core>,
    shutdown: Arc<AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    let path = Config::path()?;
    // The SSH key store is watched on the same tick so `sigil ssh add|remove`
    // takes effect without a restart, mirroring the rule-config hot-reload.
    let ssh_path = sshagent::SshKeyConfig::path();
    // And the sealed store, so `sigil-config source env set` applies live. The
    // daemon-mediated seal already updates the armed store synchronously; this
    // covers every other writer (a CLI-local seal against a stopped-then-started
    // daemon, the Mac app, a restored backup).
    let threshold_path = crate::threshold::ThresholdStore::path().ok();
    let handle = std::thread::Builder::new()
        .name("sigil-config-watcher".into())
        .spawn(move || {
            let mut last = config_mtime(&path);
            let mut last_ssh = ssh_path.as_deref().map(config_mtime);
            let mut last_threshold = threshold_path.as_deref().map(config_mtime);
            while !shutdown.load(Ordering::SeqCst) {
                std::thread::sleep(CONFIG_POLL_INTERVAL);
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                let current = config_mtime(&path);
                if current != last {
                    last = current;
                    match core.reload_config() {
                        Ok(()) => {
                            eprintln!("sigil daemon: reloaded config from {}", path.display());
                        }
                        Err(e) => {
                            eprintln!(
                                "sigil daemon: config reload failed, keeping last-good rules: {e}"
                            );
                        }
                    }
                }
                if let Some(ssh_path) = ssh_path.as_deref() {
                    let current_ssh = Some(config_mtime(ssh_path));
                    if current_ssh != last_ssh {
                        last_ssh = current_ssh;
                        match core.reload_ssh_signers() {
                            Ok(()) => {
                                eprintln!(
                                    "sigil daemon: reloaded SSH keys from {}",
                                    ssh_path.display()
                                );
                            }
                            Err(e) => {
                                eprintln!(
                                    "sigil daemon: SSH key reload failed, keeping last-good keys: {e}"
                                );
                            }
                        }
                    }
                }
                if let Some(threshold_path) = threshold_path.as_deref() {
                    let current_threshold = Some(config_mtime(threshold_path));
                    if current_threshold != last_threshold {
                        last_threshold = current_threshold;
                        match core.reload_threshold() {
                            Ok(n) => {
                                eprintln!(
                                    "sigil daemon: reloaded the sealed store from {} \
                                     ({n} sealed secret(s))",
                                    threshold_path.display()
                                );
                            }
                            Err(e) => {
                                eprintln!(
                                    "sigil daemon: sealed store reload failed, \
                                     keeping the last-good records: {e}"
                                );
                            }
                        }
                    }
                }
            }
        })
        .expect("spawning the config watcher");
    Some(handle)
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

    // Read the frame AND whatever arrived behind it: the keystore verbs put raw
    // material immediately after their header, and one recvmsg can deliver both.
    // The tail buffer is `Zeroizing`, so material never rests in a plain
    // allocation even for the frames that turn out not to carry any.
    let (frame, fds, tail) = match local::recv_frame_with_tail(&stream) {
        Ok(v) => v,
        // A probe connects then hangs up; not an error.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
        Err(e) => return Err(e.into()),
    };

    // The subscriptions stream many replies on this one connection, so they are
    // handled outside the single-reply match below.
    if matches!(frame, Frame::SubscribePending) {
        return stream_pending(&core, &mut stream);
    }
    if matches!(frame, Frame::SubscribeKeystore) {
        return stream_keystore(&core, &mut stream);
    }
    // The material-carrying verbs read their payload here, where the tail is in
    // scope, rather than inside the reply match.
    if let Frame::KeystoreProvision { len } = frame {
        let reply = handle_provision(&core, &mut stream, tail, len);
        return local::send_reply(&mut stream, &reply).map_err(Into::into);
    }
    if let Frame::SealThreshold { id, len } = &frame {
        let reply = handle_seal_threshold(&core, &mut stream, tail, id, *len);
        return local::send_reply(&mut stream, &reply).map_err(Into::into);
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
        Frame::LeaseRevoke { prefix } => {
            let n = core.leases.revoke(&prefix);
            control_reply(n > 0, &format!("revoked {n} lease(s)"))
        }
        Frame::Status => json_reply(&core.status_report()),
        Frame::Doctor => json_reply(&core.doctor_report()),
        Frame::LeaseList => json_reply(&leases_json(&core)),
        Frame::Pending => json_reply(&pending_json(&core)),
        Frame::History => {
            let entries: Vec<_> = crate::audit::load().iter().map(|e| e.to_json()).collect();
            json_reply(&entries)
        }
        Frame::KeystoreUnwrapRequest => handle_unwrap_request(&core),
        Frame::KeystoreUnwrapDone { nonce, ok, reason } => {
            handle_unwrap_done(&core, stream.as_raw_fd(), &nonce, ok, &reason)
        }
        // All handled above via an early return; the match stays exhaustive.
        Frame::SubscribePending
        | Frame::SubscribeKeystore
        | Frame::KeystoreProvision { .. }
        | Frame::SealThreshold { .. } => {
            unreachable!("streamed or payload-carrying frames return before the match")
        }
    };

    local::send_reply(&mut stream, &reply)?;
    Ok(())
}

/// Accept the material for a wrapped keystore from the signed Sigil app.
///
/// The order here is the security of the thing:
///
/// 1. **Who is calling.** The peer must be the signed Sigil app
///    ([`crate::peercode`]), checked against the live socket. A same-UID process
///    can reach this socket as easily as the app can, so without this the "only
///    the app holds the material" property is a comment, not a control.
/// 2. **Is this daemon even wrapped.** A plaintext daemon has nothing to
///    provision and says so, rather than accepting material into a state where it
///    would be ignored.
/// 3. **Once per lifetime.** A second accepted provision would be a
///    material-swap primitive, so it is refused AND logged: the app has no reason
///    to provision twice, and something that tries is worth seeing. A *failed*
///    attempt deliberately does not latch, or a malformed frame from anyone would
///    wedge the daemon into never being provisionable (a denial of service that
///    is easier to mount than the attack it would prevent).
/// 4. **Is it the right material.** Digest what arrived and compare, constant
///    time, against the expectation read from the file at startup. The reply is a
///    bare ok/fail and never echoes the expected digest: a caller who does not
///    already have the material learns nothing from trying.
fn handle_provision(
    core: &Core,
    stream: &mut UnixStream,
    tail: zeroize::Zeroizing<Vec<u8>>,
    len: u64,
) -> Reply {
    let refuse = |line: &str| Reply::Control {
        ok: false,
        lines: vec![line.to_string()],
    };

    if let Err(e) = crate::peercode::require_sigil_app(stream.as_raw_fd()) {
        eprintln!("sigil daemon: keystore provision REFUSED; {e}");
        return refuse("refused: this verb is only callable by the signed Sigil app");
    }
    let crate::keystore_seal::SealState::Sealed { expected, se_pub } = &core.seal else {
        return refuse(
            "refused: this daemon's keystore is not sealed, so there is nothing to open",
        );
    };
    if core.provisioned.load(Ordering::SeqCst) {
        // Not a mistake anyone makes twice by accident.
        eprintln!(
            "sigil daemon: keystore provision REFUSED; already provisioned this lifetime. \
             Something tried to replace live keystore material."
        );
        return refuse("refused: this daemon is already provisioned");
    }

    let material = match local::read_payload(stream, tail, len) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("sigil daemon: keystore provision failed to read material: {e}");
            return refuse("refused: the material could not be read");
        }
    };
    let got = crate::keystore_seal::digest(se_pub, &material);
    if !crate::keystore_seal::digests_equal(&got, expected) {
        eprintln!(
            "sigil daemon: keystore provision REFUSED; the material does not match what the \
             keystore file commits to. Nothing was loaded."
        );
        return refuse("refused: the material does not match this keystore");
    }
    let opened = match crate::keystore::RamKeystore::from_material(&material) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("sigil daemon: keystore provision REFUSED; material is unusable: {e}");
            return refuse("refused: the material is not a keystore");
        }
    };
    let count = opened.len();
    drop(material); // wiped here; the RAM store owns its own zeroizing copies

    core.keystore.store(Arc::new(opened));
    core.provisioned.store(true, Ordering::SeqCst);
    // Only now is this machine known to serve a wrapped store, so only now is a
    // later plaintext file a downgrade rather than a normal state.
    if let Err(e) = crate::keystore_seal::set_adopted(se_pub) {
        eprintln!("sigil daemon: could not write the adoption marker: {e}");
    }
    eprintln!("sigil daemon: keystore opened by the Sigil app ({count} blob(s)); serving.");
    Reply::Control {
        ok: true,
        lines: vec!["keystore opened".to_string()],
    }
}

/// Seal bytes into the threshold store on a caller's behalf.
///
/// This exists because under a wrapped keystore the CLI cannot read the Mac share
/// it needs to seal with, and the daemon can. `len == 0` removes the record
/// instead, matching what the CLI does with an empty input.
///
/// Peer gating is same-UID only, deliberately: the caller is `sigil-config`, an
/// unsigned CLI, so there is no code identity to demand. That is the same
/// boundary every other CLI control verb has always had (a 0600 socket), and it
/// is not weakened here: the values being sealed are supplied BY that caller.
///
/// The armed store is updated as part of the write, under the same lock, so a
/// seal takes effect on the very next request rather than on the watcher's next
/// tick. The lock is held across load, mutate, and save, which makes the whole
/// read-modify-write atomic against every other reader of the armed store: no
/// request can observe a store that was saved to disk but not yet armed, and a
/// failed save leaves the armed store exactly as it was.
fn handle_seal_threshold(
    core: &Core,
    stream: &mut UnixStream,
    tail: zeroize::Zeroizing<Vec<u8>>,
    id: &str,
    len: u64,
) -> Reply {
    let fail = |line: String| Reply::Control {
        ok: false,
        lines: vec![line],
    };
    let provisioned = core.provisioned.load(Ordering::SeqCst);
    if core.seal.blocks_serving(provisioned) {
        return fail(
            core.seal
                .explain(provisioned)
                .unwrap_or("the keystore is not available")
                .to_string(),
        );
    }

    let plaintext = match local::read_payload(stream, tail, len) {
        Ok(p) => p,
        Err(e) => return fail(format!("the value could not be read: {e}")),
    };

    // Taken before the load and held to the end: everything below is one
    // read-modify-write against both disk and the armed store.
    let mut armed = core.threshold.lock().expect("threshold store poisoned");
    let mut store = match crate::threshold::ThresholdStore::load() {
        Ok(s) => s,
        Err(e) => return fail(format!("loading the threshold store: {e}")),
    };

    if plaintext.is_empty() {
        store.remove(id);
        return match store.save() {
            Ok(()) => {
                *armed = store;
                eprintln!(
                    "sigil daemon: removed the sealed record for '{id}'; {} armed",
                    armed.secrets.len()
                );
                Reply::Control {
                    ok: true,
                    lines: vec![format!("removed {id}")],
                }
            }
            Err(e) => fail(format!("saving the threshold store: {e}")),
        };
    }

    let ks = core.keystore.snapshot();
    let phone = match crate::pairing_store::load(ks.as_ref()) {
        Ok(Some(pc)) => match pc.phone_share {
            Some(s) => s,
            None => return fail("this pairing has no phone Secure-Enclave share; re-pair".into()),
        },
        Ok(None) => return fail("no phone is paired; run `sigil pair` first".into()),
        Err(e) => return fail(format!("loading the pairing: {e}")),
    };
    let m = match crate::threshold::load_mac_share(ks.as_ref()) {
        Ok(Some(m)) => m,
        Ok(None) => return fail("no Mac threshold share on this daemon; re-pair".into()),
        Err(e) => return fail(format!("loading the Mac share: {e}")),
    };
    if let Err(e) = crate::threshold::seal_secret(&mut store, id, &m, &phone, &plaintext) {
        return fail(format!("sealing: {e}"));
    }
    drop(m);
    drop(plaintext);
    match store.save() {
        Ok(()) => {
            // Live from here: the next gated run under a rule naming this source
            // opens the record just sealed, with no restart and no watcher tick.
            *armed = store;
            // The arm line reports a sealed-secret count and this is the only
            // thing that changes it mid-life, so it belongs in the same log. Its
            // absence is what left the daemon's log showing "0 sealed secret(s)"
            // with no record of the seal that had just happened.
            eprintln!(
                "sigil daemon: sealed '{id}'; {} sealed secret(s) armed",
                armed.secrets.len()
            );
            Reply::Control {
                ok: true,
                lines: vec![format!("sealed {id}")],
            }
        }
        Err(e) => fail(format!("saving the threshold store: {e}")),
    }
}

/// Stream keystore ceremony events to the Sigil app.
///
/// Only de-adoption events flow here today. The commit flow the contract sketches
/// (the daemon asking the app to re-wrap after a keystore mutation) is
/// deliberately NOT built: while the store is wrapped, nothing mutates it. The
/// daemon never wrote the keystore in the first place (every write is CLI-side,
/// in `pairing_store`), and those CLI paths now refuse upfront against a sealed
/// store. So there is no mutation to commit, and machinery with no trigger is
/// machinery that rots untested. When daemon-side mutations exist, this is the
/// stream they announce themselves on.
fn stream_keystore(core: &Core, stream: &mut UnixStream) -> anyhow::Result<()> {
    if let Err(e) = crate::peercode::require_sigil_app(stream.as_raw_fd()) {
        eprintln!("sigil daemon: keystore subscription REFUSED; {e}");
        let _ = local::send_reply(
            stream,
            &Reply::Control {
                ok: false,
                lines: vec!["refused: this stream is only for the signed Sigil app".into()],
            },
        );
        return Ok(());
    }
    loop {
        let version = core.unwrap_requests.version();
        let body = serde_json::to_string(&core.unwrap_requests.pending_events())
            .unwrap_or_else(|_| "[]".to_string());
        if local::send_reply(stream, &Reply::Event { body }).is_err() {
            return Ok(()); // the app hung up
        }
        core.unwrap_requests
            .wait_for_change(version, Duration::from_secs(30));
    }
}

/// A human asked to de-adopt. Raise the request for the app and wait for it.
///
/// The daemon cannot do this itself: unwrapping needs the enclave key, which
/// only the app has. So this is a relay with a deadline, and every way it can go
/// wrong leaves the store wrapped, which is the direction that cannot lose data.
fn handle_unwrap_request(core: &Core) -> Reply {
    /// Long enough for a human to bring the app forward and for an enclave
    /// decrypt plus a durable write; short enough that a CLI does not hang.
    const UNWRAP_WAIT: Duration = Duration::from_secs(75);

    if !matches!(core.seal, crate::keystore_seal::SealState::Sealed { .. }) {
        return Reply::Control {
            ok: false,
            lines: vec!["this keystore is not sealed; there is nothing to unwrap".into()],
        };
    }
    let nonce = core.unwrap_requests.request();
    eprintln!("sigil daemon: de-adoption requested; waiting for the Sigil app");
    match core.unwrap_requests.wait_for(&nonce, UNWRAP_WAIT) {
        Some((true, _)) => Reply::Control {
            ok: true,
            lines: vec![
                "the Sigil app returned the keystore to plaintext".into(),
                "restart the daemon to serve from it: sigil up".into(),
            ],
        },
        Some((false, reason)) => Reply::Control {
            ok: false,
            lines: vec![format!("the Sigil app could not unwrap it: {reason}")],
        },
        None => {
            core.unwrap_requests.resolve(&nonce, false, "timed out");
            Reply::Control {
                ok: false,
                lines: vec![
                    "the Sigil app did not answer; the keystore is still sealed".into(),
                    "make sure the app is running, then try again".into(),
                ],
            }
        }
    }
}

/// The app reports what happened to an unwrap it was asked to perform.
///
/// The daemon does not verify the plaintext write itself: the app wrote and
/// fsynced it, and the daemon has no key to check it with. What the daemon does
/// own is the adoption marker, and clearing it is what makes the now-plaintext
/// file a legitimate state rather than a downgrade. So the marker is cleared ONLY
/// on a reported success, and the ordering (app writes and fsyncs plaintext,
/// THEN reports, THEN the marker clears) means a crash anywhere leaves a machine
/// that still refuses to serve, never one that silently accepts plaintext.
fn handle_unwrap_done(
    core: &Core,
    fd: std::os::fd::RawFd,
    nonce: &str,
    ok: bool,
    reason: &str,
) -> Reply {
    if let Err(e) = crate::peercode::require_sigil_app(fd) {
        eprintln!("sigil daemon: unwrap report REFUSED; {e}");
        return Reply::Control {
            ok: false,
            lines: vec!["refused: this verb is only callable by the signed Sigil app".into()],
        };
    }
    if !core.unwrap_requests.resolve(nonce, ok, reason) {
        return Reply::Control {
            ok: false,
            lines: vec![format!("no unwrap request {nonce} is outstanding")],
        };
    }
    if !ok {
        eprintln!("sigil daemon: the app could not unwrap the keystore: {reason}");
        return Reply::Control {
            ok: true,
            lines: vec!["recorded".into()],
        };
    }
    match crate::keystore_seal::clear_adopted() {
        Ok(()) => {
            eprintln!(
                "sigil daemon: keystore de-adopted; it is plaintext again. \
                 Restart the daemon to serve from it."
            );
            Reply::Control {
                ok: true,
                lines: vec!["de-adopted".into()],
            }
        }
        Err(e) => Reply::Control {
            ok: false,
            lines: vec![format!("could not clear the adoption marker: {e}")],
        },
    }
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

/// The parked requests as the `pending --json` array.
///
/// Under a local factor (biometric / dev) this enumerates the control-socket
/// queue; under the phone factor it enumerates the remote approver's in-flight
/// set instead, carrying the phone's delivery-receipt state (`delivered` /
/// `delivered_at_ms`) so the Mac can render Sent -> Delivered. A daemon runs one
/// factor, so in practice exactly one of the two sources is populated. The lease
/// policy is carried through from the matched rule; `reason`/`coalesced` are the
/// honest defaults for these paths (see JSON.md).
fn pending_json(core: &Core) -> Vec<crate::json::PendingJson> {
    // Local control-socket queue: no phone, so never "delivered".
    let mut rows: Vec<crate::json::PendingJson> = core
        .pending
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
                leasable: ctx.lease.is_leasable(),
                max_lease_secs: ctx.lease.max_secs(),
                reason: None,
                expires_ms: s.queued_at_ms + s.timeout_ms,
                timeout_ms: s.timeout_ms,
                coalesced: 0,
                delivered: false,
                delivered_at_ms: None,
            }
        })
        .collect();

    // Remote (phone-factor) in-flight set across all paired devices, carrying
    // delivery state. A ring-all request is outstanding on EVERY device at once, so
    // it appears once per device; de-duplicate by `request_id` for the Mac's
    // surface, keeping the earliest `queued_at_ms` and any observed
    // `delivered_at_ms` (a delivery receipt from any device advances the readout).
    if !core.remote.is_empty() {
        let mut by_id: std::collections::HashMap<String, crate::remote::RemotePending> =
            std::collections::HashMap::new();
        for remote in &core.remote {
            for snap in remote.pending_snapshot() {
                by_id
                    .entry(snap.request.request_id.clone())
                    .and_modify(|existing| {
                        if snap.queued_at_ms < existing.queued_at_ms {
                            existing.queued_at_ms = snap.queued_at_ms;
                        }
                        if existing.delivered_at_ms.is_none() {
                            existing.delivered_at_ms = snap.delivered_at_ms;
                        }
                    })
                    .or_insert(snap);
            }
        }
        let mut deduped: Vec<crate::remote::RemotePending> = by_id.into_values().collect();
        deduped.sort_by_key(|s| std::cmp::Reverse(s.queued_at_ms));
        rows.extend(deduped.into_iter().map(remote_pending_json));
    }
    rows
}

/// Map one in-flight remote approval to the `pending` DTO. The request is a
/// plaintext snapshot (names/provenance only, never a secret); `delivered` /
/// `delivered_at_ms` reflect the phone's receipt (task #41), display only.
fn remote_pending_json(p: crate::remote::RemotePending) -> crate::json::PendingJson {
    let req = p.request;
    crate::json::PendingJson {
        id: req.request_id,
        kind: crate::json::request_kind_str(req.kind).to_string(),
        command: req.command,
        secrets: req
            .secrets
            .into_iter()
            .map(|r| crate::json::SecretRefJson {
                provider: r.provider,
                segments: r.segments,
                label: r.label,
            })
            .collect(),
        ssh: req.ssh.map(|c| crate::json::SshJson {
            key_label: c.key_label,
            host: c.host,
            fingerprint: c.fingerprint,
        }),
        provenance: crate::json::ProvJson {
            process_chain: req.provenance.process_chain,
            cwd: req.provenance.cwd,
            machine: req.provenance.machine,
            requested_ms: p.queued_at_ms,
        },
        leasable: req.lease_policy.is_leasable(),
        max_lease_secs: req.lease_policy.max_secs(),
        reason: req.reason,
        expires_ms: req.expires_at,
        timeout_ms: req.timeout_ms,
        coalesced: 0,
        delivered: p.delivered_at_ms.is_some(),
        delivered_at_ms: p.delivered_at_ms,
    }
}

/// How long the degrade-to-plain-gate notice stays quiet for a given rule+source
/// after it has been printed once. Long enough that a busy tool tree does not
/// flood the log, short enough that a human who goes looking will see it again.
const DEGRADED_NOTICE_INTERVAL: Duration = Duration::from_secs(300);

/// The one line that says a gate rule is injecting nothing, or `None` if the same
/// rule+source was already announced within [`DEGRADED_NOTICE_INTERVAL`].
///
/// A rule that declares env keys whose source has no sealed record still gates
/// (the approval happens) but injects nothing, and the tool then falls back to
/// whatever auth it has of its own. That is the intended degrade, but doing it
/// silently means the failure looks like "Sigil is fine and the tool is broken".
/// This names both halves so the fix (`source env set`) is obvious.
///
/// Rate-limit state is process-global rather than a `Core` field: it is a log
/// detail with no bearing on any decision, and every gated request funnels
/// through one daemon process.
fn degraded_gate_notice(rule: &str, source: &str) -> Option<String> {
    static LAST_SEEN: std::sync::OnceLock<
        Mutex<std::collections::HashMap<String, std::time::Instant>>,
    > = std::sync::OnceLock::new();
    let seen = LAST_SEEN.get_or_init(Default::default);
    let key = format!("{rule}\u{1f}{source}");
    let now = std::time::Instant::now();
    let mut map = seen.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(at) = map.get(&key) {
        if now.duration_since(*at) < DEGRADED_NOTICE_INTERVAL {
            return None;
        }
    }
    map.insert(key, now);
    Some(format!(
        "sigil daemon: rule '{rule}' declares env keys but source '{source}' has no sealed \
         record; running as a plain gate and injecting nothing. Seal it with: \
         sigil-config source env set {source} --stdin"
    ))
}

/// The gated fulfillment path for `sigil <cmd>` (and the shim alias / `sigil run`).
/// Returns the exit code to mirror to the caller. Every failure path here fails
/// closed (a non-zero code with a stderr line), so the caller behaves like a
/// denied invocation.
///
/// The command's config selects the provider; the provider decides the injection
/// shape. `op` is a plain gated command: Sigil injects no credential and op does
/// its own auth. An inline-`env` rule opens its threshold-sealed values with the
/// phone's partial and injects them, gated on every run (no leasing, so resolved
/// values never sit in RAM across a TTL). An *unconfigured* command is refused
/// with a pointer to `sigil-config add`, never run ungated.
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

    // A sealed-but-unprovisioned keystore (or a downgraded one) serves NOTHING.
    // Checked before the rules are even consulted: without the material this
    // daemon cannot open a sealed secret or sign as itself to the phone, so
    // running anything gated would be theatre. The message says exactly why, and
    // never that a pairing is missing.
    if let Some(why) = core
        .seal
        .explain(core.provisioned.load(Ordering::SeqCst))
        .filter(|_| {
            core.seal
                .blocks_serving(core.provisioned.load(Ordering::SeqCst))
        })
    {
        return fail_closed(stderr, &format!("sigil: {why}\n"));
    }

    let Some(cmd) = argv.first() else {
        return fail_closed(stderr, "sigil: empty command\n");
    };

    // Evaluate the rules against this whole invocation. An invocation that no
    // rule matches is refused (never run ungated) with a pointer to `sigil
    // config`; the core holds no built-in rule for any command, `op` included.
    // `snapshot()` pins one consistent config `Arc` for this whole decision, so a
    // hot-reload landing mid-`resolve` cannot tear it (#59).
    let config = core.config.snapshot();
    let action = match config.resolve(argv) {
        None => {
            return fail_closed(
                stderr,
                &format!(
                    "sigil: '{cmd}' is not configured (no rule matches); Sigil will not run it ungated.\n  \
                     configure it: sigil-config add {cmd} --provider <id>\n"
                ),
            );
        }
        // An explicit ALLOW rule: a passthrough the user deliberately authored,
        // scoped strictly to this rule's match. Run the real command directly,
        // ungated and uninjected. This is distinct from the UNMATCHED case above,
        // which still fails closed: allow is the user's choice, not a default.
        Some(crate::config::Resolution::Allow { rule }) => {
            let caller = lease::walk_ancestry(core.proc_table.as_ref(), peer.unwrap_or(-1));
            let label = argv.join(" ");
            core.record_audit(
                &uuid::Uuid::now_v7().to_string(),
                sigil_proto::RequestKind::SecretRead,
                label.trim(),
                "",
                &caller.provenance(),
                cwd,
                "allowed",
                &format!("allow:{rule}"),
            );
            return crate::provider::run_passthrough(crate::provider::ProviderRun {
                command: argv,
                cwd,
                source: "",
                stdin,
                stdout,
                stderr,
                proxy_depth: child_depth,
                env: None,
            });
        }
        Some(crate::config::Resolution::Gate(mut action)) => {
            // An inline `env` source with no sealed record is inert dead config
            // (its value was never sealed, or a migration dropped it). Rather than
            // fail closed on every invocation, the daemon treats it as the plain
            // gate it now behaves as: still gated (approval required), but injects
            // nothing. Clearing the effective env keys here, before the readout is
            // built, keeps the approval honest (it shows no env, matching what will
            // be set) and routes the rest of dispatch down the plain-gate path.
            // config.json is untouched, so `source env set` re-seals it and
            // restores injection.
            //
            // It is also logged. Silence here is what turned a one-line
            // misconfiguration into a long hunt: the command ran, exit code 0, and
            // the only evidence that nothing had been injected was the tool
            // falling back to its own auth.
            if let Some(provider) = core.providers.get(&action.provider) {
                if provider.needs_sealed_env() {
                    let store = core.threshold.lock().expect("threshold store poisoned");
                    if store.get(&action.source_name).is_none() {
                        let declared = !action.env_keys.is_empty();
                        action.env_keys.clear();
                        drop(store);
                        if declared {
                            if let Some(line) =
                                degraded_gate_notice(&action.rule, &action.source_name)
                            {
                                eprintln!("{line}");
                            }
                        }
                    }
                }
            }
            action
        }
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
    // An env provider only needs a sealed open when it still has keys to inject;
    // an unsealed env source had its keys cleared above and behaves as a plain
    // gate.
    let needs_sealed_env = provider.needs_sealed_env() && !action.env_keys.is_empty();
    // What `describe` reads: the env-file path or the inline env KEY names. Names
    // only; no secret value is read here (pre-approval, zero-knowledge readout).
    let view = crate::provider::SourceView {
        path: source,
        keys: &action.env_keys,
    };

    // Two different scopes, deliberately:
    //
    // * `scope` is this invocation's own arguments. It is what the approval
    //   screen, the daemon log, and the audit line say, so the human always sees
    //   and the log always records the ACTUAL command, never a rule name.
    // * `lease_scope` is the matched RULE's name, and the lease grant key is
    //   derived from it with an EMPTY project root. So one approval on a leasable
    //   rule opens a window in which the same caller chain may run any command
    //   that rule matches, from any directory, until the TTL runs out. Narrowing
    //   the window back down is a matter of writing a narrower rule (or making it
    //   run-once), not of retyping the same argv from the same cwd.
    //
    // The caller chain is an OUTER fence, not the command boundary. Every gated
    // command arrives through a `~/.sigil/bin` symlink to the one `sigil` binary
    // and macOS resolves that symlink, so the chain leaf is byte-identical for
    // `op`, `curl`, and everything else: the chain tells tool trees apart, never
    // commands. The rule name in the scope is the whole command-discriminating
    // boundary, which is why a config change has to kill the leases it covers
    // (see `Core::reload_config`).
    let scope = argv.iter().skip(1).cloned().collect::<Vec<_>>().join(" ");
    let lease_scope = action.rule.clone();
    let caller = lease::walk_ancestry(core.proc_table.as_ref(), peer.unwrap_or(-1));
    let gk = lease::grant_key(&caller, lease::ScopeKind::Command, "", &lease_scope);
    // Coalescing stays per-invocation (chain + cwd + argv, the pre-rule-lease
    // key). It must NOT widen with the lease: two different commands racing under
    // one rule are two distinct readouts, and a human approving one of them must
    // never silently release the other. Only byte-identical concurrent requests
    // ride one decision.
    let coalesce_key = lease::grant_key(&caller, lease::ScopeKind::Command, cwd, &scope);

    // For the inline `env` provider, fetch its threshold-sealed record now. The
    // record is public (ciphertext plus the base point E), safe to hold across the
    // approval wait; it is opened only AFTER the grant, by combining the phone's
    // partial Z_F with the Mac share m, so no plaintext value crosses the wait. A
    // source with no sealed values fails closed rather than injecting nothing.
    let sealed_record = if needs_sealed_env {
        let store = core.threshold.lock().expect("threshold store poisoned");
        match store.get(&action.source_name) {
            Some(rec) => Some(rec.clone()),
            None => {
                return fail_closed(
                    stderr,
                    &format!(
                        "sigil: inline env source '{0}' has no sealed values; set them with: \
                         sigil-config source env set {0} --stdin\n",
                        action.source_name
                    ),
                )
            }
        }
    } else {
        None
    };

    // The label shown in the audit/approval for an env source is the source name;
    // a plain gate (`op`, `env-file`) has none.
    let account_label = if needs_sealed_env {
        action.source_name.clone()
    } else {
        String::new()
    };

    // The four legs a lease must match: the grant key (chain + rule), the account
    // label, the rule scope, and, when the lease caches values, a fingerprint of
    // the exact sealed record they came from. The fingerprint is the record's
    // ephemeral point `E`, which is fresh on every re-seal, so `source env set`
    // during a live window makes the lookup miss and the run re-approves rather
    // than injecting values that no longer exist on disk.
    let binding = lease::LeaseBinding::cached(
        &account_label,
        &lease_scope,
        sealed_record
            .as_ref()
            .map(|r| r.ephemeral_pub.as_str())
            .unwrap_or(""),
        // The generation of the very snapshot this decision resolved against, so
        // a reload during the approval wait cannot leave this grant live.
        config.generation,
    );

    // A live lease short-circuits the approval: a leasable rule may open an
    // auto-approve window so a burst of work under that rule costs one glance,
    // whatever the individual commands are. What the lease releases depends on the
    // rule:
    //
    // * A plain gate (`op`, `env-file`, or an inline `env` source degraded to one)
    //   holds an empty presence marker. The run is gated-but-uninjected either
    //   way, so this only skips the phone round trip.
    // * A sealed inline `env` rule holds the unsealed values themselves, and the
    //   run injects them from RAM with no phone round trip and no second combine.
    //   This is the credential cache the design brief describes; it is why the
    //   window dies on expiry, revoke, restart, a config edit to the rule, and a
    //   re-seal of the source.
    //
    // A cached blob that no longer decodes, or whose KEY set is not exactly what
    // the rule now consents to, is refused as a cache hit: the lease is dropped
    // and the run falls through to a fresh approval rather than injecting anything
    // the human did not agree to.
    if let Some(cached) = core.leases.token_for(&gk, &binding) {
        match leased_env(&cached, needs_sealed_env, &action.env_keys) {
            Ok(leased) => {
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
                let code = run_provider(
                    provider,
                    ProviderRun {
                        command: argv,
                        cwd,
                        source,
                        stdin,
                        stdout,
                        stderr,
                        proxy_depth: child_depth,
                        env: leased.as_ref(),
                    },
                );
                drop(leased); // zeroized here (EnvVars is Zeroizing)
                return code;
            }
            Err(why) => {
                // Fail-closed on a cache we cannot trust: drop it, log why, and
                // gate this run afresh. Nothing is injected from the bad blob.
                core.leases.revoke_scope(&lease_scope);
                eprintln!(
                    "sigil daemon: dropping the lease on rule '{lease_scope}' ({why}); \
                     re-approving this run"
                );
            }
        }
    }

    // For an inline `env` request, carry the threshold challenge to the phone: the
    // base point E it key-agrees against, plus the source-name binding it shows and
    // consents to (R5). E is public and authenticated by the enclosing signed
    // envelope; the phone validates it on-curve before its Secure-Enclave op. A
    // plain gate (`op`, `env-file`) carries no challenge.
    let threshold = sealed_record
        .as_ref()
        .map(|record| sigil_proto::ThresholdChallenge {
            account_id: record.account_id.clone(),
            label: account_label.clone(),
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
        lease: action.lease,
        ssh: None,
        threshold,
    };
    let outcome = core.gate.decide(coalesce_key, &ctx);
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

    // On approval the inline `env` provider needs its sealed values opened; `op`
    // and `env-file` need nothing. The env open is the two-party combine: the
    // phone returned its partial Z_F with the approval, and the daemon combines it
    // with its Mac share m (loaded into mlock'd memory for this one op) to derive
    // the key and decrypt. No key at rest is ever assembled; m and the derived key
    // are zeroized here, and the plaintext is zeroized when this request ends or,
    // if the approval opened a window, when that window does.
    //
    // This happens BEFORE the grant below so a failed open leaves no lease behind:
    // every `fail_closed` here returns with the store untouched.
    let mut sealed_env: Option<crate::provider::EnvVars> = None;
    let mut sealed_plain: Option<Token> = None;
    if let Some(record) = &sealed_record {
        let zf = match outcome.zf.as_deref() {
            Some(zf) => zf,
            // An approve with no partial cannot open a sealed secret (e.g. the
            // local factor cannot produce Z_F): fail closed rather than serving
            // nothing.
            None => {
                return fail_closed(
                    stderr,
                    "sigil: approval carried no threshold partial; no phone factor?\n",
                )
            }
        };
        let ks = core.keystore.snapshot();
        let m = match crate::threshold::load_mac_share(ks.as_ref()) {
            Ok(Some(m)) => m,
            Ok(None) => {
                return fail_closed(
                    stderr,
                    "sigil: no Mac threshold share on this daemon; re-pair\n",
                )
            }
            Err(e) => return fail_closed(stderr, &format!("sigil: {e}\n")),
        };
        let plain = match crate::threshold::decrypt(record, &m, zf) {
            Ok(p) => p,
            Err(e) => return fail_closed(stderr, &format!("sigil env decrypt failed: {e}\n")),
        };
        drop(m); // the Mac share is held only for the one combine
        match crate::provider::decode_env_pairs(&plain) {
            Some(pairs) => {
                // Readout integrity (invariant #3): the approver consented to
                // exactly the KEY set the readout/audit was built from
                // (`action.env_keys`, i.e. `describe`). The sealed record must
                // inject that same set and nothing else. A divergence would
                // silently set a key the human never saw; fail closed on any
                // mismatch rather than inject what was not approved. The same
                // check runs again on every leased run, against the rule as it
                // stands then.
                if !env_keys_match(&pairs, &action.env_keys) {
                    return fail_closed(
                        stderr,
                        "sigil: inline env keys do not match what was approved; \
                         refusing (re-set the source's values)\n",
                    );
                }
                sealed_env = Some(pairs);
                sealed_plain = Some(plain);
            }
            None => return fail_closed(stderr, "sigil: inline env blob is corrupt; re-set it\n"),
        }
    }

    // Enforce the rule's lease policy as the SOLE authority on leasing: a run-once
    // rule yields no lease even if the approver returned one, and a leasable rule
    // is clamped to its per-rule cap. The grant is filed under the rule, so it
    // covers the rule's whole match set for this caller chain, not just the argv
    // that opened it.
    //
    // What gets stored is what a later run under this window will need: for a
    // sealed `env` rule the just-unsealed plaintext, so the burst injects from RAM
    // without another phone round trip; for a plain gate an empty marker, because
    // there is nothing to inject. The plaintext copy lives only in the store's
    // `Zeroizing` token and dies with the lease.
    let lease_ttl = decision
        .lease_ttl()
        .and_then(|ttl| {
            action
                .lease
                .clamp_secs(ttl.as_secs().min(u32::MAX as u64) as u32)
        })
        .map(|s| Duration::from_secs(u64::from(s)));
    if let Some(ttl) = lease_ttl {
        let cached = sealed_plain.unwrap_or_else(|| zeroize::Zeroizing::new(Vec::new()));
        core.leases.grant(gk, &binding, cached, ttl);
    }

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

    // Run through the provider: `op` runs the gated command injecting nothing, the
    // env-file provider injects its own file's values, and the inline env provider
    // injects the decrypted pairs. Output streams straight to the caller's fds; for
    // the direct-injection shapes the resolved values transit only as the child's
    // spawn env (see the provider module docs).
    //
    // An inline `env` source that had no sealed record degraded to a plain gate
    // above (its keys were cleared), so there is nothing to inject;
    // [`run_provider`] routes that case through the passthrough runner.
    let code = run_provider(
        provider,
        ProviderRun {
            command: argv,
            cwd,
            source,
            stdin,
            stdout,
            stderr,
            proxy_depth: child_depth,
            env: sealed_env.as_ref(),
        },
    );
    drop(sealed_env); // zeroized here (EnvVars is Zeroizing) when present
    code
}

/// Classify the keystore file against the adoption marker, once, at startup.
///
/// Fails CLOSED in the literal sense: an unreadable or self-contradictory file is
/// not "probably fine, carry on". If this machine has ever served a wrapped store
/// it is treated as a downgrade; otherwise the daemon still arms (so `status` and
/// pairing work) and the store's own read errors surface per operation.
fn read_seal_state() -> crate::keystore_seal::SealState {
    use crate::keystore_seal::{read_adoption_marker, KeystoreFile, SealState};
    let marker = read_adoption_marker();
    match KeystoreFile::read(&keystore::file_keystore_path()) {
        Ok(file) => SealState::resolve(&file, marker.as_ref()),
        Err(e) => {
            eprintln!("sigil daemon: keystore file is unreadable: {e}");
            if marker.is_some() {
                SealState::Downgraded
            } else {
                SealState::Plain
            }
        }
    }
}

/// The source a rule injects from, in `cfg`. `None` for an allow rule (which
/// names none) or a dangling reference; two `None`s compare equal, which is
/// correct here: a rule that never named a source cannot have its source change.
fn source_for<'a>(
    cfg: &'a Config,
    rule: &crate::config::Rule,
) -> Option<&'a crate::config::Source> {
    cfg.source(&rule.action.source)
}

/// Run one gated invocation through its provider.
///
/// The one wrinkle is the inline `env` provider: with nothing to inject (a source
/// whose values were never sealed, degraded to a plain gate) `EnvProvider::run`
/// refuses an empty env, which for a REAL env request is the correct fail-closed
/// bug. Route that case through the passthrough runner instead: same gated exec
/// discipline, no injection, exactly like `op`. Shared by the fresh-approval and
/// the leased paths so they cannot drift.
fn run_provider(provider: &dyn crate::provider::SecretProvider, run: ProviderRun<'_>) -> i32 {
    if run.env.is_none() && provider.id() == crate::provider::EnvProvider::ID {
        crate::provider::run_passthrough(run)
    } else {
        provider.run(run)
    }
}

/// Whether the decoded pairs carry exactly the KEY set the rule consents to.
///
/// The approval readout is built from the rule's key names, so this is the check
/// that "what was shown is what is set". Order and duplicates are irrelevant; the
/// SET must be equal, both ways.
fn env_keys_match(pairs: &crate::provider::EnvVars, consented: &[String]) -> bool {
    let injected: std::collections::BTreeSet<&str> =
        pairs.iter().map(|(k, _)| k.as_str()).collect();
    let consented: std::collections::BTreeSet<&str> =
        consented.iter().map(String::as_str).collect();
    injected == consented
}

/// What a lease's cached token releases for this run, or why it cannot be used.
///
/// A plain-gate lease caches nothing and injects nothing. A sealed `env` lease
/// caches the encoded pairs the approval unsealed; they are decoded here and
/// re-checked against the KEY set the rule consents to RIGHT NOW, so a window can
/// only ever inject what a fresh approval would have injected. Anything else
/// (corrupt blob, a key set that has moved) is refused, and the caller drops the
/// lease and re-gates rather than injecting it.
fn leased_env(
    cached: &Token,
    needs_sealed_env: bool,
    consented: &[String],
) -> Result<Option<crate::provider::EnvVars>, &'static str> {
    if !needs_sealed_env {
        return Ok(None);
    }
    let pairs =
        crate::provider::decode_env_pairs(cached).ok_or("its cached values no longer decode")?;
    if !env_keys_match(&pairs, consented) {
        return Err("its cached keys are not the keys the rule now names");
    }
    Ok(Some(pairs))
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

/// Log one SSH sign request's metadata: key label, derived host, and the
/// data-to-sign hash (never raw bytes or key material). The sign path's
/// counterpart to [`log_request`]; without it a sign request that dies on the
/// phone leg leaves no daemon-side trace at all, which made "did the request
/// ever fire?" undiagnosable from the log.
fn log_ssh_sign_request(label: &str, host: &str, data_fingerprint: &str, peer: Option<i32>) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    eprintln!(
        "sigil daemon: [{ts}] ssh-sign {label} \u{b7} host {host} \u{b7} data {data_fingerprint} \u{b7} pid {}",
        peer.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
    );
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
    // `op` is a plain gated command now: Sigil injects nothing, runs the real op,
    // and streams its output to the caller. The fake op emits `secret` on its own
    // (as the real op would resolve and stream a secret), proving the gated child's
    // output reaches the caller without transiting the daemon (invariant #2). The
    // `_expected_token` arg is retained so callers need no signature change.
    fn write_fake_op(dir: &Path, _expected_token: &str, secret: &str) -> PathBuf {
        let path = dir.join("op");
        let script = format!("#!/bin/sh\nprintf '{secret}'\n");
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    // --- per-connection ready-up: the dead-peer EINVAL must never kill serve ---

    #[test]
    #[cfg(target_os = "macos")]
    fn a_peer_that_hung_up_before_serving_reads_as_a_dead_peer() {
        // macOS returns EINVAL from setsockopt(SO_RCVTIMEO) on a unix socket
        // whose peer fully disconnected; deterministic (probe: 2000/2000).
        // This is the exact shape the Mac app's connect-then-close liveness
        // probe produces every few seconds, and the ?-propagation of it out of
        // serve() shipped as a daemon-killing bug. It must classify as a
        // dead peer (silent drop), never as an error worth ending anything.
        let dir = std::env::temp_dir().join(format!("sigil-deadpeer-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("probe.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

        let client = UnixStream::connect(&sock).unwrap();
        drop(client); // the peer is gone before we serve it
        let (accepted, _) = listener.accept().unwrap();
        let err = ready_std_conn(accepted).expect_err("a closed peer must fail ready-up");
        assert!(is_dead_peer(&err), "EINVAL classifies as dead peer: {err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_live_peer_readies_cleanly_and_a_dead_peer_storm_does_not_starve_it() {
        // The accept-loop pattern: dead peers are dropped, live clients are
        // served. 50 connect-then-close probes (each one a potential EINVAL)
        // followed by a real client must leave the real client fully served.
        let dir = std::env::temp_dir().join(format!("sigil-conjstorm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("storm.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

        let served = Arc::new(AtomicUsize::new(0));
        let served2 = served.clone();
        let acceptor = std::thread::spawn(move || {
            // Serve until the live client's one byte has been echoed.
            loop {
                let (accepted, _) = listener.accept().unwrap();
                let mut s = match ready_std_conn(accepted) {
                    Ok(s) => s,
                    Err(e) if is_dead_peer(&e) => continue, // the serve-loop pattern
                    Err(e) => panic!("unexpected ready-up error: {e}"),
                };
                let mut buf = [0u8; 1];
                match std::io::Read::read_exact(&mut s, &mut buf) {
                    Ok(()) => {
                        s.write_all(&buf).unwrap();
                        served2.fetch_add(1, Ordering::SeqCst);
                        return;
                    }
                    // A probe that raced past ready-up but sent nothing.
                    Err(_) => continue,
                }
            }
        });

        for _ in 0..50 {
            let c = UnixStream::connect(&sock).unwrap();
            drop(c);
        }
        let mut live = UnixStream::connect(&sock).unwrap();
        live.write_all(b"x").unwrap();
        let mut echo = [0u8; 1];
        std::io::Read::read_exact(&mut live, &mut echo).unwrap();
        assert_eq!(&echo, b"x", "the live client is served after the storm");
        acceptor.join().unwrap();
        assert_eq!(served.load(Ordering::SeqCst), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A minimal rule/source config that gates `op` to the 1Password provider
    /// with no account hint (single-account fallback) — the zero-config `op` the
    /// tests used to get for free before the rule engine replaced the built-in
    /// default. op-ness now lives entirely in this user-authored rule.
    fn op_config() -> Config {
        use crate::config::{Action, Match, Rule, RuleMode, Source};
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
                // Leasable so the lease-machinery tests can exercise a grant; the
                // per-rule run-once/clamp enforcement has its own focused tests.
                mode: RuleMode::Gate,
                source: "op".into(),
                lease: LeasePolicy::Leasable { max_secs: 900 },
                timeout_sec: None,
            },
        })
        .unwrap();
        cfg
    }

    /// Like [`op_config`] but with an explicit lease policy, for the tests that
    /// assert the daemon honors run-once vs. leasable at grant time.
    fn op_config_with_lease(lease: LeasePolicy) -> Config {
        let mut cfg = op_config();
        cfg.rules[0].action.lease = lease;
        cfg
    }

    /// A config gating `<command>` to the `env-file` provider at `path` (the
    /// direct-injection shape). Used by the env-file daemon tests in place of the
    /// old per-command store.
    fn env_file_config(command: &str, path: &str) -> Config {
        use crate::config::{Action, Match, Rule, RuleMode, Source};
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
                mode: RuleMode::Gate,
                source: command.into(),
                lease: LeasePolicy::RunOnce,
                timeout_sec: None,
            },
        })
        .unwrap();
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
        test_core_with_config(dir, token, secret, dev, timeout, op_config())
    }

    /// [`test_core`] but with an explicit config, so the lease-policy tests can
    /// gate the same `op` command under run-once or a specific cap.
    fn test_core_with_config(
        dir: &Path,
        token: &str,
        secret: &str,
        dev: DevMode,
        timeout: Duration,
        config: Config,
    ) -> (Arc<Core>, Arc<PendingRegistry>) {
        let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());
        let _ = (token, secret);

        let pending = Arc::new(PendingRegistry::new());
        // These tests exercise the dev-insecure configuration, so the dev switch
        // and the control-socket park are both enabled.
        let approver = LocalApprover::new(pending.clone())
            .with_dev(dev)
            .with_control_socket(true)
            .with_timeout(timeout);
        let core = Core {
            remote: Vec::new(),
            keystore: KeystoreCell::new(keystore),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending: pending.clone(),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::new(vec![Box::new(OpProvider::with_binary(
                write_fake_op(dir, token, secret),
            ))]),
            config: config.into(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: SshSignersCell::new(Vec::new()),
            audit: None,
            seal: crate::keystore_seal::SealState::Plain,
            provisioned: AtomicBool::new(false),
            unwrap_requests: UnwrapRequests::default(),
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
        let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());
        let pending = Arc::new(PendingRegistry::new());
        let approver = LocalApprover::new(pending.clone())
            .with_dev(DevMode::Approve)
            .with_control_socket(true);
        let core = Core {
            remote: Vec::new(),
            keystore: KeystoreCell::new(keystore),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::new(vec![Box::new(OpProvider::with_binary(
                write_fake_op(&dir, "tok", "secret-1"),
            ))]),
            config: op_config().into(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: SshSignersCell::new(Vec::new()),
            audit: Some(30),
            seal: crate::keystore_seal::SealState::Plain,
            provisioned: AtomicBool::new(false),
            unwrap_requests: UnwrapRequests::default(),
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
        // `op` is a plain gate: no source/account label to record.
        assert_eq!(hist[0].account, "");
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

    /// An approver that counts how often it is consulted and always grants a
    /// lease. A test can then prove a later run was served by a LIVE LEASE (the
    /// count did not move) rather than by another approval, which
    /// [`DevMode::Lease`] alone cannot show.
    struct CountingApprover {
        calls: Arc<AtomicUsize>,
        ttl: Duration,
        /// The threshold partial a phone would return. `None` stands in for a
        /// local factor, which can approve a plain gate but cannot open a sealed
        /// secret; `Some` stands in for the phone.
        zf: Option<zeroize::Zeroizing<[u8; 32]>>,
    }

    impl CountingApprover {
        fn new(calls: Arc<AtomicUsize>, ttl: Duration) -> Self {
            Self {
                calls,
                ttl,
                zf: None,
            }
        }

        fn with_partial(mut self, zf: zeroize::Zeroizing<[u8; 32]>) -> Self {
            self.zf = Some(zf);
            self
        }
    }

    impl Approver for CountingApprover {
        fn decide(&self, _ctx: &ApprovalContext) -> crate::approve::ApprovalOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match &self.zf {
                Some(zf) => crate::approve::ApprovalOutcome::with_partial(
                    Decision::Lease(self.ttl),
                    zf.clone(),
                ),
                None => crate::approve::ApprovalOutcome::local(Decision::Lease(self.ttl)),
            }
        }
    }

    /// A core gating `op` per `config`, whose approver counts its calls. Returns
    /// the core and that counter. `audit` is the retention window in days when
    /// the test wants the audit log written (it lands under `$SIGIL_HOME`).
    fn counting_core(
        dir: &Path,
        config: Config,
        audit: Option<u32>,
    ) -> (Arc<Core>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let core = Core {
            remote: Vec::new(),
            keystore: KeystoreCell::new(Arc::new(MemoryKeystore::new())),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(CountingApprover::new(
                calls.clone(),
                Duration::from_secs(60),
            ))),
            pending: Arc::new(PendingRegistry::new()),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::new(vec![Box::new(OpProvider::with_binary(
                write_fake_op(dir, "tok-abc", "secret-A"),
            ))]),
            config: config.into(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: SshSignersCell::new(Vec::new()),
            audit,
            seal: crate::keystore_seal::SealState::Plain,
            provisioned: AtomicBool::new(false),
            unwrap_requests: UnwrapRequests::default(),
        };
        (Arc::new(core), calls)
    }

    /// Two gate rules over the same `op` source, split by subcommand, so a test
    /// can prove a lease on one rule does not cover the other.
    fn two_op_rules() -> Config {
        use crate::config::{Action, Match, Rule, RuleMode, Source};
        let mut cfg = Config::default();
        cfg.add_source(Source {
            name: "op".into(),
            provider: OpProvider::ID.into(),
            account: None,
            path: None,
            keys: Vec::new(),
        })
        .unwrap();
        for sub in ["read", "item"] {
            cfg.add_rule(Rule {
                name: format!("op-{sub}"),
                match_: Match {
                    command: Some("op".into()),
                    subcommand: Some(sub.into()),
                    ..Match::default()
                },
                action: Action {
                    mode: RuleMode::Gate,
                    source: "op".into(),
                    lease: LeasePolicy::Leasable { max_secs: 900 },
                    timeout_sec: None,
                },
            })
            .unwrap();
        }
        cfg
    }

    #[test]
    fn a_lease_covers_any_command_the_same_rule_matches() {
        // The rule-scoped lease: one approval on a leasable rule opens a window
        // for the whole rule, so a DIFFERENT command under it runs with no second
        // approval. The counter is the proof (an argv-scoped lease would have
        // re-prompted).
        let dir = tmpdir("lease-rulewide");
        let (core, calls) = counting_core(&dir, op_config(), None);

        let (r1, w1) = pipe();
        let first = vec!["op".into(), "read".into(), "op://Engineering/.env".into()];
        assert_eq!(fulfill(&core, &first, "", None, 0, None, Some(w1), None), 0);
        assert_eq!(read_all(r1), "secret-A");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "the first run is approved");
        assert_eq!(core.leases.active(), 1);

        let (r2, w2) = pipe();
        let second = vec!["op".into(), "item".into(), "get".into(), "Deploy".into()];
        assert_eq!(
            fulfill(&core, &second, "", None, 0, None, Some(w2), None),
            0
        );
        assert_eq!(read_all(r2), "secret-A");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a different command under the same rule must ride the live lease"
        );
        assert_eq!(core.leases.active(), 1, "and must not open a second lease");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_lease_survives_a_change_of_directory() {
        // The project root is no longer in the grant key, so `cd` does not cost a
        // fresh approval. Real directories, since the child is spawned in them.
        let dir = tmpdir("lease-cwd");
        let (core, calls) = counting_core(&dir, op_config(), None);
        let one = dir.join("one");
        let two = dir.join("two");
        std::fs::create_dir_all(&one).unwrap();
        std::fs::create_dir_all(&two).unwrap();
        let argv = vec!["op".into(), "read".into(), "op://Engineering/.env".into()];

        let (r1, w1) = pipe();
        let a = one.to_str().unwrap();
        assert_eq!(fulfill(&core, &argv, a, None, 0, None, Some(w1), None), 0);
        assert_eq!(read_all(r1), "secret-A");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let (r2, w2) = pipe();
        let b = two.to_str().unwrap();
        assert_eq!(fulfill(&core, &argv, b, None, 0, None, Some(w2), None), 0);
        assert_eq!(read_all(r2), "secret-A");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the same rule from another directory must ride the live lease"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_lease_on_one_rule_does_not_cover_another_rule() {
        // Breadth stops at the rule boundary: a lease opened by `op read` must not
        // auto-approve `op item`, which a different rule gates.
        let dir = tmpdir("lease-rulesplit");
        let (core, calls) = counting_core(&dir, two_op_rules(), None);

        let (r1, w1) = pipe();
        let read = vec!["op".into(), "read".into(), "op://Engineering/.env".into()];
        assert_eq!(fulfill(&core, &read, "", None, 0, None, Some(w1), None), 0);
        assert_eq!(read_all(r1), "secret-A");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let (r2, w2) = pipe();
        let item = vec!["op".into(), "item".into(), "get".into(), "Deploy".into()];
        assert_eq!(fulfill(&core, &item, "", None, 0, None, Some(w2), None), 0);
        assert_eq!(read_all(r2), "secret-A");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the other rule must be approved on its own"
        );
        assert_eq!(core.leases.active(), 2, "each rule holds its own lease");
        // And the two leases are filed under the rules, one each.
        let mut scopes: Vec<String> = core.leases.list().into_iter().map(|l| l.scope).collect();
        scopes.sort();
        assert_eq!(scopes, vec!["op-item".to_string(), "op-read".to_string()]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_leased_run_audits_the_command_it_actually_ran() {
        // The lease is filed under the rule, but the audit log must still name the
        // real invocation: a rule-wide window must not blur what was run under it.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir("lease-audit");
        let home = dir.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let prev_home = std::env::var_os("SIGIL_HOME");
        std::env::set_var("SIGIL_HOME", &home);
        let (core, calls) = counting_core(&dir, op_config(), Some(30));

        let (r1, w1) = pipe();
        let first = vec!["op".into(), "read".into(), "op://Engineering/first".into()];
        assert_eq!(fulfill(&core, &first, "", None, 0, None, Some(w1), None), 0);
        assert_eq!(read_all(r1), "secret-A");

        let (r2, w2) = pipe();
        let second = vec!["op".into(), "read".into(), "op://Engineering/second".into()];
        assert_eq!(
            fulfill(&core, &second, "", None, 0, None, Some(w2), None),
            0
        );
        assert_eq!(read_all(r2), "secret-A");

        let entries = crate::audit::load();
        match prev_home {
            Some(v) => std::env::set_var("SIGIL_HOME", v),
            None => std::env::remove_var("SIGIL_HOME"),
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the second run rode the lease"
        );
        assert_eq!(entries.len(), 2, "both runs are audited");
        let labels: Vec<&str> = entries.iter().map(|e| e.label.as_str()).collect();
        assert!(
            labels.iter().any(|l| l.contains("first"))
                && labels.iter().any(|l| l.contains("second")),
            "each spawn is logged with the command it actually ran, got {labels:?}"
        );
        assert!(
            entries
                .iter()
                .any(|e| e.label.contains("second") && e.via == "lease"),
            "the lease-covered run is recorded as lease-covered"
        );
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
    fn run_once_rule_never_leases_even_when_a_lease_is_returned() {
        // A run-once rule must not install a lease even if the approver returns
        // one (DevMode::Lease here stands in for a phone/compromised approver that
        // asks for a session). The secret is still delivered, but nothing is held,
        // so the very next identical request is gated afresh.
        let dir = tmpdir("runonce");
        let (core, _) = test_core_with_config(
            &dir,
            "tok-abc",
            "secret-A",
            DevMode::Lease(Duration::from_secs(60)),
            Duration::from_millis(50),
            op_config_with_lease(LeasePolicy::RunOnce),
        );
        let argv = vec!["op".into(), "read".into(), "op://Engineering/.env".into()];
        let (r1, w1) = pipe();
        assert_eq!(fulfill(&core, &argv, "", None, 0, None, Some(w1), None), 0);
        assert_eq!(read_all(r1), "secret-A");
        assert_eq!(
            core.leases.active(),
            0,
            "a run-once rule must refuse a lease the approver tried to install"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn leasable_rule_clamps_an_over_cap_lease_to_the_rule_max() {
        // The approver asks for a 60s session but the rule caps leases at 5s; the
        // lease is granted (leasable) yet its remaining time never exceeds the cap.
        let dir = tmpdir("clamp");
        let (core, _) = test_core_with_config(
            &dir,
            "tok-abc",
            "secret-A",
            DevMode::Lease(Duration::from_secs(60)),
            Duration::from_millis(50),
            op_config_with_lease(LeasePolicy::Leasable { max_secs: 5 }),
        );
        let argv = vec!["op".into(), "read".into(), "op://Engineering/.env".into()];
        let (r1, w1) = pipe();
        assert_eq!(fulfill(&core, &argv, "", None, 0, None, Some(w1), None), 0);
        assert_eq!(read_all(r1), "secret-A");
        assert_eq!(core.leases.active(), 1, "a leasable rule grants the lease");
        let leases = core.leases.list();
        assert_eq!(leases.len(), 1);
        assert!(
            leases[0].remaining <= Duration::from_secs(5),
            "the 60s request must be clamped down to the rule's 5s cap, got {:?}",
            leases[0].remaining
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn allow_rule_runs_the_command_directly_without_gating() {
        // An allow rule is a passthrough: even with NO approver (DevMode::Off,
        // which would deny a gate rule), a matched command runs directly, injects
        // nothing, creates no pending approval, and grants no lease. Uses `true`
        // (present on every unix) so the passthrough's real-binary resolution has
        // something to exec; the exit code is what proves it actually ran.
        use crate::config::{Action, Match, Rule, RuleMode};
        let dir = tmpdir("allow");
        let mut cfg = Config::default();
        cfg.add_rule(Rule {
            name: "allow-true".into(),
            match_: Match {
                command: Some("true".into()),
                ..Match::default()
            },
            action: Action {
                mode: RuleMode::Allow,
                source: String::new(),
                lease: LeasePolicy::RunOnce,
                timeout_sec: None,
            },
        })
        .unwrap();
        let (core, pending) = test_core_with_config(
            &dir,
            "tok",
            "secret",
            DevMode::Off,
            Duration::from_millis(50),
            cfg,
        );
        let (read_end, write_end) = pipe();
        let code = fulfill(
            &core,
            &["true".to_string()],
            "",
            None,
            0,
            None,
            Some(write_end),
            None,
        );
        assert_eq!(code, 0, "allow passthrough runs the real `true`, exit 0");
        assert_eq!(read_all(read_end), "", "`true` emits nothing");
        assert_eq!(core.leases.active(), 0, "an allow rule never leases");
        assert_eq!(
            pending.snapshot().len(),
            0,
            "an allow rule creates no pending approval (never gates)"
        );
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
        let approver = LocalApprover::new(pending.clone())
            .with_dev(DevMode::Approve)
            .with_control_socket(true);
        let config = env_file_config("faketool", env_path.to_str().unwrap());
        let core = Arc::new(Core {
            remote: Vec::new(),
            keystore: KeystoreCell::new(keystore),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            config: config.into(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: SshSignersCell::new(Vec::new()),
            audit: None,
            seal: crate::keystore_seal::SealState::Plain,
            provisioned: AtomicBool::new(false),
            unwrap_requests: UnwrapRequests::default(),
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
        use crate::config::{Action, Match, Rule, RuleMode, Source};
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
                mode: RuleMode::Gate,
                source: command.into(),
                lease: LeasePolicy::RunOnce,
                timeout_sec: None,
            },
        })
        .unwrap();
        cfg
    }

    #[test]
    fn inline_env_with_no_sealed_values_runs_as_a_plain_gate() {
        // An inline env source whose value was never sealed is inert dead config.
        // Rather than fail closed on every invocation with a cryptic error, the
        // daemon treats it as the plain gate it now behaves as: the command is
        // still gated (approved here via DevMode), then run with NO injection
        // (the missing env var is simply unset), exactly like `op`. config.json is
        // untouched, so a later `source env set` re-seals it and restores
        // injection. This keeps a torn-down or never-set source from bricking the
        // command it gates.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir("envinline-empty");
        let bindir = dir.join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let tool = bindir.join("faketool");
        // Prints the (unset) TOKEN so we can prove nothing was injected.
        std::fs::write(&tool, "#!/bin/sh\nprintf 'tok=[%s]' \"$TOKEN\"\n").unwrap();
        std::fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();

        let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());
        let pending = Arc::new(PendingRegistry::new());
        let approver = LocalApprover::new(pending.clone())
            .with_dev(DevMode::Approve)
            .with_control_socket(true);
        let core = Arc::new(Core {
            remote: Vec::new(),
            keystore: KeystoreCell::new(keystore),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            config: env_inline_config("faketool", &["TOKEN"]).into(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: SshSignersCell::new(Vec::new()),
            audit: None,
            seal: crate::keystore_seal::SealState::Plain,
            provisioned: AtomicBool::new(false),
            unwrap_requests: UnwrapRequests::default(),
        });

        // The daemon's own env must not carry TOKEN, or the child would inherit it
        // and blur the "nothing injected" assertion.
        std::env::remove_var("TOKEN");
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

        assert_eq!(
            code, 0,
            "an unsealed inline env source runs as a plain gate"
        );
        assert_eq!(
            read_all(read_end),
            "tok=[]",
            "the missing value is not injected (TOKEN stays unset)"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A daemon wired to a REAL sealed inline `env` source, with a software
    /// stand-in for the phone: the values are threshold-sealed under a fresh Mac
    /// share and a software SE key, and the approver returns the matching partial
    /// `Z_F`, so the whole two-party open runs headlessly. `lease_ttl` is what the
    /// approver asks for. Returns the core, the approval counter, and the temp
    /// dir holding the fake tool (already on `PATH` by the caller).
    fn sealed_env_core(
        source: &str,
        keys: &[(&str, &str)],
        lease: LeasePolicy,
        lease_ttl: Duration,
    ) -> (Arc<Core>, Arc<AtomicUsize>) {
        use crate::config::{Action, Match, Rule, RuleMode, Source};
        use sigil_proto::threshold::{EcdhAlgo, MacShare};

        // Software phone (f, F) and this daemon's Mac share m.
        let f = MacShare::generate();
        let f_x963 = *f.public_point().as_x963();
        let phone = crate::threshold::PhoneShare::from_x963("phone-se.v2", &f_x963, EcdhAlgo::RawX)
            .expect("a valid software phone share");
        let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());
        let m = crate::threshold::load_or_create_mac_share(keystore.as_ref())
            .expect("a fresh Mac share");

        // Seal the values exactly as `sigil-config source env set` does.
        let pairs: Vec<(String, zeroize::Zeroizing<String>)> = keys
            .iter()
            .map(|(k, v)| ((*k).to_string(), zeroize::Zeroizing::new((*v).to_string())))
            .collect();
        let plain = crate::provider::encode_env_pairs(&pairs);
        let mut store = crate::threshold::ThresholdStore::default();
        crate::threshold::seal_secret(&mut store, source, &m, &phone, &plain)
            .expect("sealing the inline env values");

        // The partial the phone would return for this record.
        let record = store.get(source).expect("the sealed record").clone();
        let e_point = record.ephemeral_point().unwrap();
        let zf = f.partial(&e_point, record.ecdh_algo, e_point.as_x963());

        let mut config = Config::default();
        config
            .add_source(Source {
                name: source.into(),
                provider: crate::provider::EnvProvider::ID.into(),
                account: None,
                path: None,
                keys: keys.iter().map(|(k, _)| (*k).to_string()).collect(),
            })
            .unwrap();
        config
            .add_rule(Rule {
                name: source.into(),
                match_: Match {
                    command: Some(source.into()),
                    ..Match::default()
                },
                action: Action {
                    mode: RuleMode::Gate,
                    source: source.into(),
                    lease,
                    timeout_sec: None,
                },
            })
            .unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let core = Core {
            remote: Vec::new(),
            keystore: KeystoreCell::new(keystore),
            threshold: Mutex::new(store),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(
                CountingApprover::new(calls.clone(), lease_ttl).with_partial(zf),
            )),
            pending: Arc::new(PendingRegistry::new()),
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            config: config.into(),
            lease_ttl,
            factor: Factor::DevInsecure,
            ssh_signers: SshSignersCell::new(Vec::new()),
            audit: None,
            seal: crate::keystore_seal::SealState::Plain,
            provisioned: AtomicBool::new(false),
            unwrap_requests: UnwrapRequests::default(),
        };
        (Arc::new(core), calls)
    }

    /// Write `#!/bin/sh` at `dir/bin/<name>` echoing `$TOKEN`, and prepend that
    /// bin dir to `PATH`. Returns the previous `PATH` for the caller to restore.
    /// The caller must hold `TEST_ENV_LOCK`.
    fn fake_env_tool(dir: &Path, name: &str) -> Option<std::ffi::OsString> {
        let bindir = dir.join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let tool = bindir.join(name);
        std::fs::write(&tool, "#!/bin/sh\nprintf 'tok=[%s]' \"$TOKEN\"\n").unwrap();
        std::fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
        std::env::remove_var("TOKEN");
        let prev = std::env::var_os("PATH");
        let mut search = vec![bindir];
        if let Some(p) = &prev {
            search.extend(std::env::split_paths(p));
        }
        std::env::set_var("PATH", std::env::join_paths(search).unwrap());
        prev
    }

    fn restore_path(prev: Option<std::ffi::OsString>) {
        match prev {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
    }

    /// Run the sealed `faketool` once and return (exit code, what it printed).
    fn run_sealed(core: &Arc<Core>, args: &[&str]) -> (i32, String) {
        let mut argv = vec!["faketool".to_string()];
        argv.extend(args.iter().map(|a| (*a).to_string()));
        let (r, w) = pipe();
        let code = fulfill(core, &argv, "", None, 0, None, Some(w), None);
        (code, read_all(r))
    }

    #[test]
    fn sealing_while_the_daemon_is_armed_takes_effect_with_no_restart() {
        // The live-fire bug. The daemon read threshold.db once, at arm time, and
        // never again: a value sealed into an inline `env` source while it was
        // already up never reached the armed store, so every gated run took the
        // degrade-to-plain-gate path, injected nothing, and the tool fell back to
        // its own auth. `sigil status` read the file fresh and disagreed with the
        // running daemon. Only a restart fixed it.
        //
        // HomeGuard holds TEST_ENV_LOCK and points SIGIL_HOME at a temp dir, so
        // ThresholdStore::save writes exactly where reload_threshold reads.
        let _home = HomeGuard::new("seal-hot");
        let dir = tmpdir("seal-hot");
        let prev = fake_env_tool(&dir, "faketool");
        let (core, _calls) = sealed_env_core(
            "faketool",
            &[("TOKEN", "sealed-after-arming")],
            LeasePolicy::RunOnce,
            Duration::from_secs(60),
        );

        // Reproduce the state the daemon was in: the record is on disk, the armed
        // store is empty because the seal happened after arming.
        {
            let mut armed = core.threshold.lock().expect("threshold store");
            let store = std::mem::take(&mut *armed);
            store.save().expect("writing the sealed store to disk");
        }

        let (code, out) = run_sealed(&core, &[]);
        assert_eq!(code, 0, "the stale daemon still gates and still runs");
        assert_eq!(
            out, "tok=[]",
            "but injects nothing: the symptom that sent the tool to its own auth"
        );

        // One watcher tick, without the sleep.
        assert_eq!(
            core.reload_threshold().expect("a clean reload"),
            1,
            "the reload arms the record that was sealed after startup"
        );

        let (code, out) = run_sealed(&core, &[]);
        restore_path(prev);
        assert_eq!(code, 0);
        assert_eq!(
            out, "tok=[sealed-after-arming]",
            "and the very next run injects, with no restart"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_malformed_sealed_store_keeps_the_last_good_records() {
        // Fail-closed on the same terms as reload_config: a truncated or garbled
        // threshold.db must not disarm a daemon that is serving fine.
        let _home = HomeGuard::new("seal-badreload");
        let dir = tmpdir("seal-badreload");
        let (core, _calls) = sealed_env_core(
            "faketool",
            &[("TOKEN", "still-here")],
            LeasePolicy::RunOnce,
            Duration::from_secs(60),
        );
        let path = crate::threshold::ThresholdStore::path().expect("a store path");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{ not json").unwrap();

        assert!(
            core.reload_threshold().is_err(),
            "a malformed store is an error, not an empty store"
        );
        assert!(
            core.threshold
                .lock()
                .expect("threshold store")
                .get("faketool")
                .is_some(),
            "and the last-good record stays armed"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A core that can serve `Frame::SealThreshold`: a v2 pairing (so there is a
    /// phone share `F` to seal to) and this daemon's Mac share `m`, both held in a
    /// `MemoryKeystore`. The caller must hold a `HomeGuard`, since the pairing and
    /// the sealed store are written under `SIGIL_HOME`.
    fn seal_ready_core(dir: &Path) -> Arc<Core> {
        use sigil_proto::threshold::{EcdhAlgo, MacShare};
        let (core, _) = test_core(
            dir,
            "tok",
            "secret",
            DevMode::Approve,
            Duration::from_millis(50),
        );
        let ks = core.keystore.snapshot();
        let f = MacShare::generate();
        let daemon_id = DeviceIdentity::generate();
        let daemon_pub = daemon_id.peer_identity();
        let phone = DeviceIdentity::generate().peer_identity();
        pairing_store::save(
            ks.as_ref(),
            &NewPairing {
                daemon_identity: daemon_id,
                phone,
                relay_url: "ws://127.0.0.1:1".into(),
                sas_words: sas_of(&daemon_pub, &phone),
                paired_at: REMOTE_NOW,
                phone_share: Some(crate::pairing_store::NewPhoneShare {
                    se_key_id: "phone-se.v2".into(),
                    f_x963: f.public_point().as_x963().to_vec(),
                    ecdh_algo: EcdhAlgo::RawX,
                }),
            },
        )
        .expect("persisting the pairing");
        crate::threshold::load_or_create_mac_share(ks.as_ref()).expect("a fresh Mac share");
        core
    }

    #[test]
    fn a_daemon_mediated_seal_arms_the_record_immediately() {
        // Sealing routes through the daemon whenever one is listening, and that
        // path wrote the file without touching the armed store: the seal was on
        // disk and invisible to the very process that had just performed it. It
        // must be live on return, not on the watcher's next tick.
        let _home = HomeGuard::new("seal-mediated");
        let dir = tmpdir("seal-mediated");
        let core = seal_ready_core(&dir);

        let pairs = vec![(
            "TOKEN".to_string(),
            zeroize::Zeroizing::new("mediated-value".to_string()),
        )];
        let payload = crate::provider::encode_env_pairs(&pairs);
        let reply = control_round_trip(
            &core,
            &Frame::SealThreshold {
                id: "prod".into(),
                len: payload.len() as u64,
            },
            &payload,
        );
        assert!(control_ok(&reply), "{}", control_lines(&reply));
        assert!(
            core.threshold
                .lock()
                .expect("threshold store")
                .get("prod")
                .is_some(),
            "the armed store holds it, so the next request injects"
        );
        assert!(
            crate::threshold::ThresholdStore::load()
                .unwrap()
                .get("prod")
                .is_some(),
            "and so does disk"
        );

        // A removal is equally immediate: no window where the daemon keeps
        // injecting values the human just deleted.
        let reply = control_round_trip(
            &core,
            &Frame::SealThreshold {
                id: "prod".into(),
                len: 0,
            },
            b"",
        );
        assert!(control_ok(&reply), "{}", control_lines(&reply));
        assert!(core
            .threshold
            .lock()
            .expect("threshold store")
            .get("prod")
            .is_none());
        assert!(crate::threshold::ThresholdStore::load()
            .unwrap()
            .get("prod")
            .is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_degrade_to_a_plain_gate_announces_itself_once_per_window() {
        // The silence is what made this a long hunt: a rule declaring env keys
        // whose source has no sealed record gated, ran, exited 0, and injected
        // nothing, with not one line to say so. The notice names both halves and
        // the fix, and repeats at most once per window so a busy tool tree cannot
        // drown the log.
        let first = degraded_gate_notice("rule-alpha", "src-alpha")
            .expect("the first degraded run is announced");
        assert!(first.contains("rule-alpha"), "{first}");
        assert!(first.contains("src-alpha"), "{first}");
        assert!(first.contains("injecting nothing"), "{first}");
        assert!(
            first.contains("sigil-config source env set src-alpha"),
            "and says how to fix it: {first}"
        );
        assert!(
            degraded_gate_notice("rule-alpha", "src-alpha").is_none(),
            "a burst of gated runs does not repeat it"
        );
        assert!(
            degraded_gate_notice("rule-alpha", "src-beta").is_some(),
            "but a different source is its own notice"
        );
    }

    /// The doctor check that compares the armed sealed store against disk.
    fn drift_check(core: &Arc<Core>) -> crate::json::CheckJson {
        let checks: Vec<crate::json::CheckJson> =
            serde_json::from_str(&json_body(query_reply(core.clone(), Frame::Doctor))).unwrap();
        checks
            .into_iter()
            .find(|c| c.label == "sealed store matches the armed daemon")
            .expect("the drift check is in the doctor report")
    }

    #[test]
    fn doctor_catches_a_daemon_armed_with_a_stale_sealed_store() {
        // With the hot reload in place this state should be unreachable, which is
        // precisely why it belongs in doctor: it is the regression alarm for the
        // one condition nothing else could see.
        let _home = HomeGuard::new("doctor-drift");
        let dir = tmpdir("doctor-drift");
        let (core, _calls) = sealed_env_core(
            "faketool",
            &[("TOKEN", "v")],
            LeasePolicy::RunOnce,
            Duration::from_secs(60),
        );

        // Armed with one record, nothing on disk: a count mismatch either way is
        // the same bug, and the hint has to name the fix.
        let drift = drift_check(&core);
        assert!(!drift.ok, "a count mismatch fails the check");
        assert!(drift.hint.contains("sigil restart"), "{}", drift.hint);

        // Agreement passes, and says how many records are armed.
        core.threshold
            .lock()
            .expect("threshold store")
            .save()
            .expect("writing the armed store to disk");
        let agreed = drift_check(&core);
        assert!(agreed.ok, "{}", agreed.hint);
        assert!(agreed.hint.contains('1'), "{}", agreed.hint);

        // A re-seal keeps the count and changes the record. Comparing ids alone
        // would call that agreement, so the fingerprint carries the ephemeral
        // point, which is fresh on every seal. (A second core seals the same
        // source name afresh; only its store is used here.)
        let (resealed, _) = sealed_env_core(
            "faketool",
            &[("TOKEN", "v")],
            LeasePolicy::RunOnce,
            Duration::from_secs(60),
        );
        resealed
            .threshold
            .lock()
            .expect("threshold store")
            .save()
            .expect("writing the re-sealed store");
        let resealed_check = drift_check(&core);
        assert!(!resealed_check.ok, "a re-seal is drift too");
        assert!(
            resealed_check.hint.contains("re-sealed"),
            "{}",
            resealed_check.hint
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_sealed_env_lease_injects_from_ram_with_no_second_approval() {
        // The RAM-cache path end to end. The first run is a real two-party open
        // (phone partial + Mac share) and its plaintext is retained in the lease;
        // a later run under the same rule injects those values straight from RAM,
        // with a different argv, and never reaches the approver.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir("sealed-lease");
        let prev = fake_env_tool(&dir, "faketool");
        let (core, calls) = sealed_env_core(
            "faketool",
            &[("TOKEN", "sealed-value-42")],
            LeasePolicy::Leasable { max_secs: 900 },
            Duration::from_secs(60),
        );

        let (c1, out1) = run_sealed(&core, &[]);
        assert_eq!(c1, 0);
        assert_eq!(out1, "tok=[sealed-value-42]", "the first run unseals");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(core.leases.active(), 1, "the approval opened a window");

        let (c2, out2) = run_sealed(&core, &["--other-args"]);
        restore_path(prev);
        assert_eq!(c2, 0);
        assert_eq!(
            out2, "tok=[sealed-value-42]",
            "the leased run injects the cached values"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "and does it with no phone round trip"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_run_once_sealed_env_rule_caches_nothing() {
        // Run-once still means run-once with a cache in play: the values are
        // injected for the run that was approved and nothing is retained, so the
        // next run is gated afresh.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir("sealed-runonce");
        let prev = fake_env_tool(&dir, "faketool");
        let (core, calls) = sealed_env_core(
            "faketool",
            &[("TOKEN", "sealed-value-42")],
            LeasePolicy::RunOnce,
            Duration::from_secs(60),
        );

        let (c1, out1) = run_sealed(&core, &[]);
        assert_eq!((c1, out1.as_str()), (0, "tok=[sealed-value-42]"));
        assert_eq!(
            core.leases.active(),
            0,
            "a run-once rule retains nothing, even though the approver asked"
        );

        let (c2, _) = run_sealed(&core, &[]);
        restore_path(prev);
        assert_eq!(c2, 0);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "so the next run needs its own approval"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_sealed_env_lease_stops_injecting_when_it_expires() {
        // Expiry is the outer bound on the cache: once the window lapses the
        // values are purged and the next run goes back to the phone.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir("sealed-expiry");
        let prev = fake_env_tool(&dir, "faketool");
        let (core, calls) = sealed_env_core(
            "faketool",
            &[("TOKEN", "sealed-value-42")],
            LeasePolicy::Leasable { max_secs: 900 },
            Duration::from_secs(1),
        );

        let (_, out1) = run_sealed(&core, &[]);
        assert_eq!(out1, "tok=[sealed-value-42]");
        assert_eq!(core.leases.active(), 1);

        std::thread::sleep(Duration::from_millis(1_200));
        assert_eq!(core.leases.active(), 0, "the window lapsed and was purged");

        let (c2, out2) = run_sealed(&core, &[]);
        restore_path(prev);
        assert_eq!(c2, 0);
        assert_eq!(out2, "tok=[sealed-value-42]", "re-approved, re-opened");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the run after expiry took a fresh approval"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn revoke_and_restart_both_end_a_sealed_env_window() {
        // The two manual kill switches over cached values: `sigil lease revoke`
        // (by grant-key prefix) and the daemon restart / ctrl-c path
        // (`LeaseStore::clear`). After either, the next run is gated again.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir("sealed-revoke");
        let prev = fake_env_tool(&dir, "faketool");
        let (core, calls) = sealed_env_core(
            "faketool",
            &[("TOKEN", "sealed-value-42")],
            LeasePolicy::Leasable { max_secs: 900 },
            Duration::from_secs(60),
        );

        run_sealed(&core, &[]);
        let grant = core.leases.list()[0].grant_hex.clone();
        assert_eq!(
            core.leases.revoke(&grant[..8]),
            1,
            "revoke drops the window"
        );
        assert_eq!(core.leases.active(), 0);
        let (_, out2) = run_sealed(&core, &[]);
        assert_eq!(out2, "tok=[sealed-value-42]");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the run after a revoke took a fresh approval"
        );

        // And the restart path: clear() is what ctrl-c runs.
        assert_eq!(core.leases.clear(), 1);
        let (_, out3) = run_sealed(&core, &[]);
        restore_path(prev);
        assert_eq!(out3, "tok=[sealed-value-42]");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "a daemon that lost its leases comes up cold"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_cached_lease_is_only_used_when_it_still_matches_the_rule() {
        // What the leased path will and will not inject. The consent check is the
        // same one the fresh-approval path runs, re-run against the rule as it
        // stands now, so a window can never inject a key set the human did not
        // agree to. Anything it cannot vouch for is an error, and the caller drops
        // the lease and re-gates instead of injecting.
        let keys = |ks: &[&str]| ks.iter().map(|k| k.to_string()).collect::<Vec<_>>();
        let blob = |pairs: &[(&str, &str)]| {
            let owned: Vec<(String, zeroize::Zeroizing<String>)> = pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), zeroize::Zeroizing::new((*v).to_string())))
                .collect();
            crate::provider::encode_env_pairs(&owned)
        };

        // A plain gate caches nothing and injects nothing, whatever it holds.
        let marker: Token = zeroize::Zeroizing::new(Vec::new());
        assert!(leased_env(&marker, false, &[]).unwrap().is_none());

        // The happy path: the cached keys are exactly the rule's keys.
        let good = blob(&[("TOKEN", "v"), ("OTHER", "w")]);
        let got = leased_env(&good, true, &keys(&["OTHER", "TOKEN"]))
            .expect("a matching cache is usable")
            .expect("and carries values");
        assert_eq!(got.len(), 2, "order does not matter, the SET does");

        // A key set that has drifted either way is refused, not injected.
        assert!(
            leased_env(&good, true, &keys(&["TOKEN"])).is_err(),
            "a cache with an EXTRA key must not be injected"
        );
        assert!(
            leased_env(&good, true, &keys(&["TOKEN", "OTHER", "THIRD"])).is_err(),
            "a cache MISSING a consented key must not be injected"
        );

        // A corrupt blob is refused rather than half-parsed.
        let corrupt: Token = zeroize::Zeroizing::new(vec![0xff, 0xff, 0xff, 0xff, 0x01]);
        assert!(leased_env(&corrupt, true, &keys(&["TOKEN"])).is_err());

        // And an empty marker where values are expected (a rule that gained keys
        // while a plain-gate window was live) is refused too.
        assert!(leased_env(&marker, true, &keys(&["TOKEN"])).is_err());
    }

    #[test]
    fn a_rule_rewritten_mid_window_does_not_inherit_the_lease() {
        // The reviewer's F3 scenario, with the cache that made it mandatory: open
        // a window on the rule that gates `faketool`, then hot-swap a config whose
        // rule of the SAME NAME matches `curl` instead. Without invalidation the
        // live window (and the sealed values it holds) would transfer to `curl`
        // and inject a credential into a command nobody approved. The reload must
        // kill it, so the `curl` run is gated on its own.
        use crate::config::{Action, Match, Rule, RuleMode, Source};
        let _home = HomeGuard::new("lease-config-swap");
        let dir = tmpdir("lease-config-swap");
        let prev = fake_env_tool(&dir, "faketool");
        // A fake `curl` alongside it, so the rewritten rule has something to run.
        let curl = dir.join("bin").join("curl");
        std::fs::write(&curl, "#!/bin/sh\nprintf 'curl-tok=[%s]' \"$TOKEN\"\n").unwrap();
        std::fs::set_permissions(&curl, fs::Permissions::from_mode(0o755)).unwrap();

        let (core, calls) = sealed_env_core(
            "faketool",
            &[("TOKEN", "sealed-value-42")],
            LeasePolicy::Leasable { max_secs: 900 },
            Duration::from_secs(60),
        );
        let (_, out1) = run_sealed(&core, &[]);
        assert_eq!(out1, "tok=[sealed-value-42]");
        assert_eq!(core.leases.active(), 1, "the window is open on 'faketool'");

        // The rewrite: same rule name, same source, different match.
        let mut swapped = Config::default();
        swapped
            .add_source(Source {
                name: "faketool".into(),
                provider: crate::provider::EnvProvider::ID.into(),
                account: None,
                path: None,
                keys: vec!["TOKEN".into()],
            })
            .unwrap();
        swapped
            .add_rule(Rule {
                name: "faketool".into(),
                match_: Match {
                    command: Some("curl".into()),
                    ..Match::default()
                },
                action: Action {
                    mode: RuleMode::Gate,
                    source: "faketool".into(),
                    lease: LeasePolicy::Leasable { max_secs: 900 },
                    timeout_sec: None,
                },
            })
            .unwrap();
        swapped.save().expect("writing the rewritten config");
        core.reload_config().expect("a clean reload");

        assert_eq!(
            core.leases.active(),
            0,
            "the window must not survive the rule being rewritten under it"
        );

        // And the newly matched command is gated on its own, not auto-approved.
        let (r, w) = pipe();
        let code = fulfill(
            &core,
            &["curl".into(), "https://example.invalid".into()],
            "",
            None,
            0,
            None,
            Some(w),
            None,
        );
        let out = read_all(r);
        restore_path(prev);
        assert_eq!(code, 0);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "curl took its own approval; it did not ride the op window"
        );
        assert_eq!(out, "curl-tok=[sealed-value-42]");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_reload_during_an_approval_kills_the_grant_that_lands_after_it() {
        // Invalidation-on-reload cannot cover a lease that does not exist yet. An
        // approval blocks on the phone for as long as the human takes; a config
        // edit landing in that window is invalidated BEFORE the grant is filed,
        // so without the generation stamp the window would go live under a rule
        // that had already been rewritten. The stamp makes the late grant unusable
        // by construction, whatever the rule now says.
        let dir = tmpdir("lease-generation");
        let (core, calls) = counting_core(&dir, op_config(), None);
        let argv = vec!["op".into(), "read".into(), "op://Engineering/.env".into()];

        // A run under generation 0 opens a window.
        let (r1, w1) = pipe();
        assert_eq!(fulfill(&core, &argv, "", None, 0, None, Some(w1), None), 0);
        assert_eq!(read_all(r1), "secret-A");
        assert_eq!(core.leases.active(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Simulate the ordering of the race: the config is swapped (bumping the
        // generation) and the lease survives invalidation because the rule text
        // did not change. That is exactly the case the reviewer flagged, and the
        // binding must still refuse it.
        core.config.store(op_config());
        assert_eq!(
            core.leases.active(),
            1,
            "an unchanged rule survives invalidation, which is why the stamp matters"
        );

        let (r2, w2) = pipe();
        assert_eq!(fulfill(&core, &argv, "", None, 0, None, Some(w2), None), 0);
        assert_eq!(read_all(r2), "secret-A");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a grant decided under the previous config generation must not be served"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn config_reload_invalidates_exactly_the_leases_whose_rule_moved() {
        // The invalidation matrix, driven directly: a lease dies when its rule is
        // removed, when the rule's own definition changes in any field, and when
        // the SOURCE it injects from changes (the lease may be holding that
        // source's values). An untouched rule keeps its window.
        use crate::config::{Action, Match, Rule, RuleMode, Source};
        let dir = tmpdir("lease-invalidate");
        let (core, _) = counting_core(&dir, op_config(), None);

        // Two rules, each with a live lease.
        let base = {
            let mut cfg = op_config();
            cfg.add_source(Source {
                name: "other".into(),
                provider: OpProvider::ID.into(),
                account: None,
                path: None,
                keys: Vec::new(),
            })
            .unwrap();
            cfg.add_rule(Rule {
                name: "other".into(),
                match_: Match {
                    command: Some("other".into()),
                    ..Match::default()
                },
                action: Action {
                    mode: RuleMode::Gate,
                    source: "other".into(),
                    lease: LeasePolicy::Leasable { max_secs: 900 },
                    timeout_sec: None,
                },
            })
            .unwrap();
            cfg
        };
        let seed = |core: &Arc<Core>| {
            core.leases.clear();
            for (i, rule) in ["op", "other"].iter().enumerate() {
                core.leases.grant(
                    [i as u8; 32],
                    &lease::LeaseBinding::cached("src", rule, "E1", 0),
                    zeroize::Zeroizing::new(b"TOKEN=v".to_vec()),
                    Duration::from_secs(60),
                );
            }
            assert_eq!(core.leases.active(), 2);
        };

        // 1. The rule is gone.
        seed(&core);
        let mut removed = base.clone();
        removed.rules.retain(|r| r.name != "op");
        core.invalidate_leases_for_config_change(&base, &removed);
        assert_eq!(core.leases.active(), 1, "the removed rule's window died");
        assert_eq!(core.leases.list()[0].scope, "other");

        // 2. The rule's match changed (the F3 shape).
        seed(&core);
        let mut rewritten = base.clone();
        rewritten.rules[0].match_.command = Some("curl".into());
        core.invalidate_leases_for_config_change(&base, &rewritten);
        assert_eq!(core.leases.active(), 1);
        assert_eq!(core.leases.list()[0].scope, "other");

        // 3. Only the lease policy changed. Still a change; the window dies.
        seed(&core);
        let mut relaxed = base.clone();
        relaxed.rules[0].action.lease = LeasePolicy::Leasable { max_secs: 30 };
        core.invalidate_leases_for_config_change(&base, &relaxed);
        assert_eq!(core.leases.active(), 1);

        // 4. The rule is untouched but its SOURCE moved (new keys to inject).
        seed(&core);
        let mut resourced = base.clone();
        resourced.sources[0].keys = vec!["NEW_KEY".into()];
        core.invalidate_leases_for_config_change(&base, &resourced);
        assert_eq!(
            core.leases.active(),
            1,
            "a moved source kills its rule's window"
        );
        assert_eq!(core.leases.list()[0].scope, "other");

        // 5. A no-op reload keeps every window.
        seed(&core);
        core.invalidate_leases_for_config_change(&base, &base.clone());
        assert_eq!(
            core.leases.active(),
            2,
            "an unchanged config revokes nothing"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn leased_unsealed_inline_env_source_runs_as_a_plain_gate() {
        // A degraded (unsealed) inline env source leases like any plain gate, so a
        // later invocation short-circuits on the live lease. That path must ALSO
        // route through the passthrough runner: `EnvProvider::run` refuses an empty
        // env, so a naive `provider.run(env: None)` would exit 1 and brick the
        // command on the second run. Prove the leased run still runs as a bare gate,
        // and that the lease is rule-wide here too: the second run is a different
        // argv from a different directory, and the approver is never consulted again.
        use crate::config::{Action, Match, Rule, RuleMode, Source};
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir("envinline-leased");
        let bindir = dir.join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let tool = bindir.join("faketool");
        std::fs::write(&tool, "#!/bin/sh\nprintf 'tok=[%s]' \"$TOKEN\"\n").unwrap();
        std::fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();

        // A leasable gate rule over an unsealed inline env source.
        let mut config = Config::default();
        config
            .add_source(Source {
                name: "faketool".into(),
                provider: crate::provider::EnvProvider::ID.into(),
                account: None,
                path: None,
                keys: vec!["TOKEN".into()],
            })
            .unwrap();
        config
            .add_rule(Rule {
                name: "faketool".into(),
                match_: Match {
                    command: Some("faketool".into()),
                    ..Match::default()
                },
                action: Action {
                    mode: RuleMode::Gate,
                    source: "faketool".into(),
                    lease: LeasePolicy::Leasable { max_secs: 900 },
                    timeout_sec: None,
                },
            })
            .unwrap();

        let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());
        let pending = Arc::new(PendingRegistry::new());
        // The counting approver stands in for a phone approval that opens an
        // auto-approve window, and records how often it was asked, so a later run
        // being lease-served is provable rather than assumed.
        let calls = Arc::new(AtomicUsize::new(0));
        let core = Arc::new(Core {
            remote: Vec::new(),
            keystore: KeystoreCell::new(keystore),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(CountingApprover::new(
                calls.clone(),
                Duration::from_secs(60),
            ))),
            pending,
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            config: config.into(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: SshSignersCell::new(Vec::new()),
            audit: None,
            seal: crate::keystore_seal::SealState::Plain,
            provisioned: AtomicBool::new(false),
            unwrap_requests: UnwrapRequests::default(),
        });

        std::env::remove_var("TOKEN");
        let prev = std::env::var_os("PATH");
        let mut search = vec![bindir.clone()];
        if let Some(p) = &prev {
            search.extend(std::env::split_paths(p));
        }
        std::env::set_var("PATH", std::env::join_paths(search).unwrap());

        // First run: plain-gate approval opens the lease.
        let (r1, w1) = pipe();
        let c1 = fulfill(
            &core,
            &["faketool".into()],
            "",
            None,
            0,
            None,
            Some(w1),
            None,
        );
        assert_eq!(c1, 0, "first (approved) run is a plain gate");
        assert_eq!(read_all(r1), "tok=[]");
        assert_eq!(core.leases.active(), 1, "the plain gate opened a lease");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Second run: a DIFFERENT argv under the same rule, from a different
        // directory. It short-circuits on the rule-wide lease and must STILL run,
        // not exit 1, and still inject nothing.
        let elsewhere = dir.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let (r2, w2) = pipe();
        let c2 = fulfill(
            &core,
            &["faketool".into(), "--other".into()],
            elsewhere.to_str().unwrap(),
            None,
            0,
            None,
            Some(w2),
            None,
        );
        match prev {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        assert_eq!(
            c2, 0,
            "the leased second run is a plain gate, not an exit-1"
        );
        assert_eq!(
            read_all(r2),
            "tok=[]",
            "still no injection on the leased run"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "another command under the same rule, from another directory, rode the lease"
        );
        assert_eq!(core.leases.active(), 1, "and opened no second lease");
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
        let approver = LocalApprover::new(pending.clone())
            .with_dev(DevMode::Approve)
            .with_control_socket(true);
        let config = env_file_config("faketool", env_path.to_str().unwrap());
        let core = Arc::new(Core {
            remote: Vec::new(),
            keystore: KeystoreCell::new(keystore),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            config: config.into(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: SshSignersCell::new(Vec::new()),
            audit: None,
            seal: crate::keystore_seal::SealState::Plain,
            provisioned: AtomicBool::new(false),
            unwrap_requests: UnwrapRequests::default(),
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
        let approver = LocalApprover::new(pending.clone())
            .with_dev(DevMode::Approve)
            .with_control_socket(true);
        let core = Arc::new(Core {
            remote: Vec::new(),
            keystore: KeystoreCell::new(keystore),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            config: env_file_config("faketool", env_path.to_str().unwrap()).into(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: SshSignersCell::new(Vec::new()),
            audit: None,
            seal: crate::keystore_seal::SealState::Plain,
            provisioned: AtomicBool::new(false),
            unwrap_requests: UnwrapRequests::default(),
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
        let approver = LocalApprover::new(pending.clone())
            .with_dev(DevMode::Approve)
            .with_control_socket(true);
        let core = Core {
            remote: Vec::new(),
            keystore: KeystoreCell::new(keystore),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            config: op_config().into(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: SshSignersCell::new(vec![Box::new(sshagent::FileSshSigner::new(vec![(
                id.clone(),
                key_path.clone(),
            )]))]),
            audit: None,
            seal: crate::keystore_seal::SealState::Plain,
            provisioned: AtomicBool::new(false),
            unwrap_requests: UnwrapRequests::default(),
        };

        // The agent advertises the file identity.
        assert_eq!(core.identities().len(), 1);

        let host = sshagent::HostContext {
            host: "(host not bound)".into(),
            binding: sigil_proto::HostBinding::Unbound,
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
    use sigil_proto::pairing::DaemonPairing;
    use sigil_proto::LocalRelay;
    use sigil_relay_client::{DaemonRelay, PhoneRelay};
    use sigil_softphone::{Pairing, Policy, Softphone};

    const REMOTE_NOW: u64 = 1_720_000_000_000;

    fn clone_device(id: &DeviceIdentity) -> DeviceIdentity {
        DeviceIdentity {
            signing: id.signing.clone(),
            agreement: id.agreement.clone(),
        }
    }

    /// Pair a softphone to a fresh daemon identity in-process and return the
    /// pieces the daemon side needs: the daemon identity (for the approver) and the
    /// paired softphone. The ceremony delivers no key: `op` is a plain gate, so the
    /// softphone only decides (approve/deny), it releases nothing.
    fn pair_softphone(policy: Policy) -> (DeviceIdentity, Softphone) {
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
        let softphone = pairing.finish().unwrap();

        (daemon_for_approver, softphone)
    }

    /// Build an inert daemon core whose approval gate is a [`RemoteApprover`]
    /// wired to `transport` (any [`Transport`]: the in-process [`LocalRelay`] or
    /// the real [`DaemonRelay`]). `op` is a plain gate: the daemon injects nothing
    /// and holds no secret at rest; the gated op streams its own output.
    #[allow(clippy::too_many_arguments)] // a test helper; each arg is a distinct fixture
    fn remote_core(
        dir: &Path,
        daemon_id: DeviceIdentity,
        phone: sigil_proto::PeerIdentity,
        transport: Arc<dyn sigil_proto::Transport>,
        timeout: Duration,
        token: &str,
        secret: &str,
    ) -> (Arc<Core>, Arc<RemoteApprover>) {
        // Hold the approver in an Arc as production does: the gate takes one clone,
        // the test keeps another to run the ToDaemon owner (the sole reader that
        // routes the phone's response to the waiting round trip). Both clones point
        // at the SAME instance, so they share the one waiter map. A short poll keeps
        // the idle owner's join fast at test end.
        let approver = Arc::new(
            RemoteApprover::new(transport, daemon_id, phone)
                .with_timeout(timeout)
                .with_listen_poll(Duration::from_millis(20)),
        );
        let pending = Arc::new(PendingRegistry::new());
        let core = Arc::new(Core {
            keystore: KeystoreCell::new(Arc::new(MemoryKeystore::new())), // no DEK at rest
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver.clone())),
            remote: vec![approver.clone()],
            pending,
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::new(vec![Box::new(OpProvider::with_binary(
                write_fake_op(dir, token, secret),
            ))]),
            config: op_config().into(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::Phone,
            ssh_signers: SshSignersCell::new(Vec::new()),
            audit: None,
            seal: crate::keystore_seal::SealState::Plain,
            provisioned: AtomicBool::new(false),
            unwrap_requests: UnwrapRequests::default(),
        });
        (core, approver)
    }

    /// Run a `RemoteApprover`'s ToDaemon owner loop on a background thread,
    /// mirroring what `serve` spawns in production. The `approver` must be the same
    /// instance the gate holds so they share the one waiter map. Returns the
    /// shutdown flag and the join handle.
    fn spawn_owner(
        approver: Arc<RemoteApprover>,
    ) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let handle = std::thread::spawn(move || approver.run_todaemon_owner(&stop));
        (shutdown, handle)
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
        let (daemon_id, softphone) = pair_softphone(Policy::Approve);
        let phone_pub = softphone.phone_identity();
        let mailbox = softphone.mailbox();

        let (core, approver) = remote_core(
            &dir,
            daemon_id,
            phone_pub,
            Arc::new(relay.clone()),
            Duration::from_secs(3),
            "remote-token-xyz",
            "remote-secret-99",
        );
        // The daemon's ToDaemon owner: the sole reader that routes the phone's
        // response to the waiting round trip.
        let (owner_stop, owner) = spawn_owner(approver);

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
        owner_stop.store(true, Ordering::SeqCst);
        owner.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remote_softphone_denial_fails_closed_with_no_secret() {
        let dir = tmpdir("remote-deny");
        let relay = LocalRelay::new();
        let (daemon_id, softphone) = pair_softphone(Policy::Deny);
        let phone_pub = softphone.phone_identity();

        let (core, approver) = remote_core(
            &dir,
            daemon_id,
            phone_pub,
            Arc::new(relay.clone()),
            Duration::from_secs(3),
            "tok",
            "should-never-appear",
        );
        let (owner_stop, owner) = spawn_owner(approver);

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
        owner_stop.store(true, Ordering::SeqCst);
        owner.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- v2 threshold: the full daemon round trip over the socket ----------

    #[test]
    fn remote_pairing_config_derives_the_shared_mailbox() {
        // The persisted phone-factor config must derive the exact mailbox both
        // devices route on, so `build_gate(Factor::Phone, ..)` attaches to the
        // right relay queue. This also constructs the config type end to end.
        let (daemon_id, softphone) = pair_softphone(Policy::Approve);
        let cfg = RemotePairingConfig {
            relay_url: "https://relay.example".into(),
            daemon_identity: daemon_id,
            phone: softphone.phone_identity(),
            phone_share: None,
            direct_endpoint: None,
        };
        assert_eq!(cfg.mailbox(), softphone.mailbox());
    }

    // --- the FULL cross-process loop over the REAL relay -------------------
    //
    // Same milestone as `remote_softphone_approval_delivers_secret_over_the_socket`,
    // but the envelopes traverse the real blind relay (the native sigil-relay) over plain
    // HTTP instead of the in-process LocalRelay: the daemon deposits/drains its
    // mailbox slots (`DaemonRelay`) and the softphone deposits/drains the mirror
    // (`PhoneRelay`). Pairing is done in-process (out-of-band by design); only
    // the post-pairing approval round trip is carried by the relay.

    /// A spawned native relay process, killed on drop.
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

    /// Locate the native `sigil-relay` binary (the TS Bun relay was retired). In
    /// order: `$SIGIL_RELAY_BIN`, then the workspace `target/{debug,release}`
    /// under `$CARGO_TARGET_DIR` or `../../target` relative to this crate. Returns
    /// `None` when it has not been built, so the caller soft-skips with a hint to
    /// `cargo build -p sigil-relay`.
    fn which_native_relay() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("SIGIL_RELAY_BIN") {
            let p = PathBuf::from(p);
            return p.is_file().then_some(p);
        }
        let target_root = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"));
        for profile in ["debug", "release"] {
            let cand = target_root.join(profile).join("sigil-relay");
            if cand.is_file() {
                return Some(cand);
            }
        }
        None
    }

    /// Spawn the native `sigil-relay` on a specific loopback `port` and wait for
    /// it to accept connections. Returns `None` if the binary is missing or the
    /// port never came up.
    fn native_relay_on(port: u16) -> Option<RelayServer> {
        let bin = which_native_relay()?;
        let child = std::process::Command::new(bin)
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
    /// (an already-running relay); otherwise spawns the native `sigil-relay` if it
    /// has been built. Returns `None` to soft-skip when no relay can be obtained.
    fn obtain_relay() -> Option<(String, Option<RelayServer>)> {
        if let Ok(url) = std::env::var("SIGIL_TEST_RELAY_URL") {
            return Some((url, None));
        }
        let port = free_port();
        let guard = native_relay_on(port)?;
        Some((format!("http://127.0.0.1:{port}"), Some(guard)))
    }

    #[test]
    #[cfg_attr(
        not(feature = "real-relay"),
        ignore = "spawns the native sigil-relay; build it first (cargo build -p sigil-relay), then: cargo test -p sigil --features real-relay -- --test-threads=1"
    )]
    fn remote_approval_over_the_real_relay_delivers_the_secret() {
        let Some((base, _server)) = obtain_relay() else {
            eprintln!(
                "SKIPPED remote_approval_over_the_real_relay_delivers_the_secret: no relay. \
                 Build the native relay (cargo build -p sigil-relay), or start one and set \
                 SIGIL_TEST_RELAY_URL, e.g.\n  \
                 PORT=8787 target/debug/sigil-relay   (then SIGIL_TEST_RELAY_URL=http://127.0.0.1:8787)"
            );
            return;
        };

        let dir = tmpdir("real-relay");
        let (daemon_id, softphone) = pair_softphone(Policy::Approve);
        let phone_pub = softphone.phone_identity();
        let mailbox = softphone.mailbox();

        // The phone-factor config the daemon would load derives the same mailbox.
        let cfg = RemotePairingConfig {
            relay_url: base.clone(),
            daemon_identity: clone_device(&daemon_id),
            phone: phone_pub,
            phone_share: None,
            direct_endpoint: None,
        };
        assert_eq!(cfg.mailbox(), mailbox);

        // Daemon side: RemoteApprover over the real HTTP relay. No dev flag,
        // no biometric: the paired phone is the real approving factor.
        let daemon_relay = DaemonRelay::new(&base, mailbox).expect("daemon http client");
        let (core, approver) = remote_core(
            &dir,
            daemon_id,
            phone_pub,
            Arc::new(daemon_relay),
            Duration::from_secs(10),
            "real-token-abc",
            "real-secret-77",
        );
        // The inert-daemon invariant: no DEK at rest; it arrives per-approval.
        // The daemon's ToDaemon owner reads the real relay and routes the response.
        let (owner_stop, owner) = spawn_owner(approver);

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
        owner_stop.store(true, Ordering::SeqCst);
        owner.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg_attr(
        not(feature = "real-relay"),
        ignore = "spawns the native sigil-relay; build it first (cargo build -p sigil-relay), then: cargo test -p sigil --features real-relay -- --test-threads=1"
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
        let Some(server1) = native_relay_on(port) else {
            eprintln!("SKIPPED daemon_relay_resumes_after_the_relay_is_bounced: native sigil-relay not built (cargo build -p sigil-relay)");
            return;
        };
        let base = format!("http://127.0.0.1:{port}");

        let dir = tmpdir("relay-bounce");
        let (daemon_id, softphone) = pair_softphone(Policy::Approve);
        let phone_pub = softphone.phone_identity();
        let mailbox = softphone.mailbox();

        // Point the daemon at the relay and let the first deposit through.
        let daemon_relay = DaemonRelay::new(&base, mailbox).expect("daemon http client");
        std::thread::sleep(Duration::from_millis(400));

        // Bounce the relay: drop the old process, start a fresh one on the port.
        drop(server1);
        std::thread::sleep(Duration::from_millis(200));
        let _server2 = native_relay_on(port).expect("relay restart on the same port");

        // Generous timeout to absorb reconnect backoff.
        let (core, approver) = remote_core(
            &dir,
            daemon_id,
            phone_pub,
            Arc::new(daemon_relay),
            Duration::from_secs(20),
            "bounce-token",
            "bounce-secret-55",
        );
        let (owner_stop, owner) = spawn_owner(approver);

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
        owner_stop.store(true, Ordering::SeqCst);
        owner.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Build a core armed with the given `factor` and gate, holding one account
    /// whose token decrypts to `token`. Used to exercise the arm-time factor
    /// policy (residual #1) directly.
    fn factor_core(dir: &Path, token: &str, secret: &str, factor: Factor) -> Arc<Core> {
        let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());
        let _ = token;
        let pending = Arc::new(PendingRegistry::new());
        let (gate, _listeners, _acceptors) =
            build_gate(factor, Vec::new(), &keystore, &pending).unwrap();
        Arc::new(Core {
            remote: Vec::new(),
            keystore: KeystoreCell::new(keystore),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate,
            pending,
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::new(vec![Box::new(OpProvider::with_binary(
                write_fake_op(dir, token, secret),
            ))]),
            config: op_config().into(),
            lease_ttl: Duration::from_secs(60),
            factor,
            ssh_signers: SshSignersCell::new(Vec::new()),
            audit: None,
            seal: crate::keystore_seal::SealState::Plain,
            provisioned: AtomicBool::new(false),
            unwrap_requests: UnwrapRequests::default(),
        })
    }

    /// A core whose keystore file classified as `seal` at startup, with the
    /// given provision state. Everything else is the ordinary dev-approve core,
    /// so any refusal these tests see comes from the seal and nothing else.
    fn sealed_core(
        dir: &Path,
        seal: crate::keystore_seal::SealState,
        provisioned: bool,
    ) -> Arc<Core> {
        let (core, _) = test_core(
            dir,
            "tok",
            "should-never-appear",
            DevMode::Approve,
            Duration::from_millis(50),
        );
        let mut core = Arc::try_unwrap(core)
            .map(Box::new)
            .ok()
            .expect("sole owner");
        core.seal = seal;
        core.provisioned = AtomicBool::new(provisioned);
        Arc::new(*core)
    }

    #[test]
    fn a_sealed_unprovisioned_daemon_serves_nothing_and_says_why() {
        // The restart matrix's hard case: a wrapped keystore and no app yet. The
        // daemon is up (status, pairing, diagnostics all work) but it cannot open
        // a sealed secret or sign as itself, so it must run NOTHING gated. The
        // message is the load-bearing part: a human reading it must understand
        // the app is not running, and must not be nudged toward a re-pair.
        let dir = tmpdir("sealed-unprovisioned");
        let core = sealed_core(
            &dir,
            crate::keystore_seal::SealState::Sealed {
                expected: [1u8; 32],
                se_pub: b"spki".to_vec(),
            },
            false,
        );

        let argv = vec!["op".into(), "read".into(), "op://Engineering/.env".into()];
        let (out_r, out_w) = pipe();
        let (err_r, err_w) = pipe();
        let code = fulfill(&core, &argv, "", None, 0, None, Some(out_w), Some(err_w));
        assert_eq!(code, 1, "a sealed daemon fails closed");
        assert_eq!(read_all(out_r), "", "and delivers no secret");

        let err = read_all(err_r);
        assert!(err.contains("keystore sealed"), "{err}");
        assert!(err.contains("Sigil app must be running"), "{err}");
        let lower = err.to_lowercase();
        assert!(
            !lower.contains("no pairing"),
            "must not read as a lost pairing: {err}"
        );
        assert!(
            !lower.contains("run: sigil pair") && !lower.contains("re-pair with"),
            "must not send anyone into a re-pair: {err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_provisioned_seal_serves_normally_and_a_downgrade_never_does() {
        // Once the app has provisioned, a wrapped daemon behaves exactly like a
        // plaintext one. A downgrade (plaintext where wrapped was promised)
        // refuses regardless, since that is the shape of an attack.
        let dir = tmpdir("sealed-provisioned");
        let core = sealed_core(
            &dir,
            crate::keystore_seal::SealState::Sealed {
                expected: [1u8; 32],
                se_pub: b"spki".to_vec(),
            },
            true,
        );
        let argv = vec!["op".into(), "read".into(), "op://Engineering/.env".into()];
        let (r, w) = pipe();
        assert_eq!(fulfill(&core, &argv, "", None, 0, None, Some(w), None), 0);
        assert_eq!(
            read_all(r),
            "should-never-appear",
            "a provisioned seal serves"
        );

        let down = sealed_core(&dir, crate::keystore_seal::SealState::Downgraded, true);
        let (out_r, out_w) = pipe();
        let (err_r, err_w) = pipe();
        let code = fulfill(&down, &argv, "", None, 0, None, Some(out_w), Some(err_w));
        assert_eq!(code, 1, "a downgraded keystore serves nothing");
        assert_eq!(read_all(out_r), "");
        assert!(read_all(err_r).contains("downgraded"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn status_reports_the_keystore_seal_state_the_daemon_armed_with() {
        // Only the daemon can answer this, so it must be on the wire. The Mac app
        // reads these to explain the sealed state instead of guessing.
        let dir = tmpdir("sealed-status");
        let sealed = sealed_core(
            &dir,
            crate::keystore_seal::SealState::Sealed {
                expected: [2u8; 32],
                se_pub: Vec::new(),
            },
            false,
        );
        let st = sealed.status_report();
        assert_eq!(st.keystore_sealed, Some(true));
        assert_eq!(st.keystore_provisioned, Some(false));

        let plain = sealed_core(&dir, crate::keystore_seal::SealState::Plain, false);
        let st = plain.status_report();
        assert_eq!(st.keystore_sealed, Some(false));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Drive one control frame (plus raw payload) over a real socket pair against
    /// `handle_conn`, the way a client does. Returns the reply.
    fn control_round_trip(core: &Arc<Core>, frame: &Frame, payload: &[u8]) -> Reply {
        let (client, server) = UnixStream::pair().unwrap();
        let core = core.clone();
        let h = std::thread::spawn(move || {
            let _ = handle_conn(core, server);
        });
        local::send_frame_with_payload(&client, frame, payload).unwrap();
        let mut client = client;
        let reply = local::recv_reply(&mut client).expect("a reply");
        drop(client);
        h.join().unwrap();
        reply
    }

    fn control_ok(reply: &Reply) -> bool {
        matches!(reply, Reply::Control { ok: true, .. })
    }

    fn control_lines(reply: &Reply) -> String {
        match reply {
            Reply::Control { lines, .. } => lines.join(" "),
            other => panic!("expected a control reply, got {other:?}"),
        }
    }

    #[test]
    fn provisioning_is_refused_for_anyone_who_is_not_the_signed_app() {
        // The gate that makes "only the app holds the material" a control rather
        // than a comment. The test binary is unsigned/ad-hoc, so it stands in for
        // exactly the adversary this refuses: a same-UID process that can reach
        // the 0600 socket as easily as the app can.
        let dir = tmpdir("provision-gate");
        let material = br#"{"blobs":{}}"#;
        let core = sealed_core(
            &dir,
            crate::keystore_seal::SealState::Sealed {
                expected: crate::keystore_seal::digest(b"spki", material),
                se_pub: b"spki".to_vec(),
            },
            false,
        );
        let reply = control_round_trip(
            &core,
            &Frame::KeystoreProvision {
                len: material.len() as u64,
            },
            material,
        );
        assert!(!control_ok(&reply), "an unsigned caller must be refused");
        assert!(control_lines(&reply).contains("signed Sigil app"));
        assert!(
            !core.provisioned.load(Ordering::SeqCst),
            "and must not leave the daemon provisioned"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_wrong_digest_provision_is_refused_and_does_not_latch() {
        // Two properties in one, both load-bearing. The digest check is what stops
        // material other than what the file commits to from being adopted. And a
        // REFUSED attempt must not consume the once-per-lifetime slot, or anyone
        // able to send one bad frame could permanently deny this daemon its
        // material, which is a cheaper attack than the one the limit prevents.
        let dir = tmpdir("provision-digest");
        let material = br#"{"blobs":{}}"#;
        let core = sealed_core(
            &dir,
            crate::keystore_seal::SealState::Sealed {
                expected: crate::keystore_seal::digest(b"spki", b"DIFFERENT MATERIAL"),
                se_pub: b"spki".to_vec(),
            },
            false,
        );
        // (The peer gate refuses first here; what this asserts is the state after
        // a refusal, which must be identical either way: nothing loaded, nothing
        // latched, and no adoption marker.)
        let reply = control_round_trip(
            &core,
            &Frame::KeystoreProvision {
                len: material.len() as u64,
            },
            material,
        );
        assert!(!control_ok(&reply));
        assert!(!core.provisioned.load(Ordering::SeqCst));
        assert!(
            !crate::keystore_seal::is_adopted(),
            "a refused provision must not mark this machine as adopted"
        );
        // The daemon is still provisionable: the slot did not burn.
        let again = control_round_trip(
            &core,
            &Frame::KeystoreProvision {
                len: material.len() as u64,
            },
            material,
        );
        assert!(!control_lines(&again).contains("already provisioned"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn opened_material_becomes_the_live_read_only_keystore() {
        // What a successful provision produces, exercised directly (the socket
        // path cannot get here without a signed app). The daemon reads its
        // identity from RAM, and every WRITE refuses: while the disk copy is
        // wrapped, nothing may write a plaintext one beside it.
        let material = br#"{"blobs":{"pairing.daemon-identity.v1":"aGVsbG8="}}"#;
        let opened = crate::keystore::RamKeystore::from_material(material).unwrap();
        assert_eq!(opened.len(), 1);
        assert_eq!(
            opened.load_blob("pairing.daemon-identity.v1").unwrap(),
            Some(b"hello".to_vec())
        );
        assert!(opened.load_blob("absent").unwrap().is_none());
        assert!(matches!(
            opened.store_blob("x", b"y"),
            Err(crate::keystore::KeystoreError::Sealed)
        ));
        assert!(matches!(
            opened.delete_blob("pairing.daemon-identity.v1"),
            Err(crate::keystore::KeystoreError::Sealed)
        ));
        // Garbage in is refused rather than half-loaded.
        assert!(crate::keystore::RamKeystore::from_material(b"not json").is_err());
    }

    #[test]
    fn a_sealed_daemon_refuses_to_seal_and_says_why() {
        // The mediated seal verb inherits the same gate as everything else: with
        // no material there is no Mac share to seal with, and the refusal must
        // read as "the app is not running", not as a broken pairing.
        let dir = tmpdir("seal-sealed");
        let core = sealed_core(
            &dir,
            crate::keystore_seal::SealState::Sealed {
                expected: [3u8; 32],
                se_pub: Vec::new(),
            },
            false,
        );
        let reply = control_round_trip(
            &core,
            &Frame::SealThreshold {
                id: "src".into(),
                len: 4,
            },
            b"TOK=",
        );
        assert!(!control_ok(&reply));
        let lines = control_lines(&reply);
        assert!(lines.contains("keystore sealed"), "{lines}");
        assert!(!lines.to_lowercase().contains("no pairing"), "{lines}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_keystore_streams_and_unwrap_reports_are_app_only() {
        // Both remaining app verbs refuse an unsigned caller, so nothing but the
        // app can drive de-adoption or watch the ceremony stream.
        let dir = tmpdir("keystore-app-only");
        let core = sealed_core(&dir, crate::keystore_seal::SealState::Plain, false);
        let reply = control_round_trip(
            &core,
            &Frame::KeystoreUnwrapDone {
                nonce: "made-up".into(),
                ok: true,
                reason: String::new(),
            },
            b"",
        );
        assert!(!control_ok(&reply));
        assert!(control_lines(&reply).contains("signed Sigil app"));

        // And the subscription refuses before streaming anything.
        let reply = control_round_trip(&core, &Frame::SubscribeKeystore, b"");
        assert!(!control_ok(&reply));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_unwrap_request_against_a_plain_store_is_a_no_op() {
        // Nothing to unwrap, so it says so rather than raising a request no app
        // would ever answer (and blocking the CLI for 75 seconds).
        let dir = tmpdir("unwrap-plain");
        let core = sealed_core(&dir, crate::keystore_seal::SealState::Plain, false);
        let reply = control_round_trip(&core, &Frame::KeystoreUnwrapRequest, b"");
        assert!(!control_ok(&reply));
        assert!(control_lines(&reply).contains("not sealed"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_unwrap_answer_must_quote_an_outstanding_nonce() {
        // The registry refuses invented or replayed nonces, so a stray or repeated
        // report cannot clear the adoption marker.
        let reqs = UnwrapRequests::default();
        assert!(!reqs.resolve("never-issued", true, ""));
        let nonce = reqs.request();
        assert_eq!(reqs.pending_events().len(), 1);
        assert!(reqs.resolve(&nonce, true, ""));
        assert!(
            !reqs.resolve(&nonce, true, ""),
            "an answered request cannot be answered twice"
        );
        assert!(reqs.pending_events().is_empty());
        assert_eq!(
            reqs.wait_for(&nonce, Duration::from_millis(10)),
            Some((true, String::new()))
        );
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

    /// Small argv builder for the reload tests.
    fn av(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn config_hot_reload_swaps_in_the_on_disk_rules() {
        // #59: a `sigil-config` edit (here, a rewritten config.json) is picked up
        // by reload_config and atomically swapped in, no restart. The daemon
        // starts on the in-memory op_config; after reload it serves the on-disk
        // rules instead.
        let _home = HomeGuard::new("hot-reload");
        let dir = tmpdir("hot-reload");
        let (core, _) = test_core(
            &dir,
            "tok",
            "secret",
            DevMode::Off,
            Duration::from_millis(10),
        );

        // Before: the in-memory op rule gates `op read`.
        assert!(
            matches!(
                core.config
                    .snapshot()
                    .resolve(&av(&["op", "read", "op://V/i/f"])),
                Some(crate::config::Resolution::Gate(_))
            ),
            "op gates before the reload"
        );

        // Author a different config on disk: gate `deploy` via env-file, no op rule.
        env_file_config("deploy", "/x/.env")
            .save()
            .expect("writing the on-disk config");
        core.reload_config()
            .expect("a clean reload swaps in the on-disk rules");

        // After: the old op rule is gone (refuse), the new deploy rule gates.
        assert!(
            core.config
                .snapshot()
                .resolve(&av(&["op", "read", "x"]))
                .is_none(),
            "the retired op rule refuses after the reload"
        );
        assert!(
            matches!(
                core.config.snapshot().resolve(&av(&["deploy"])),
                Some(crate::config::Resolution::Gate(_))
            ),
            "the freshly loaded deploy rule gates"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ssh_signers_hot_reload_when_the_key_store_changes() {
        // A `sigil ssh add` edit to ~/.sigil/ssh-keys.json is picked up by
        // reload_ssh_signers and swapped in, so a newly served key is advertised
        // without a daemon restart (mirrors the rule-config hot-reload). HomeGuard
        // points SIGIL_HOME at a temp dir, so SshKeyConfig::save writes exactly
        // where reload_ssh_signers reads.
        let _home = HomeGuard::new("ssh-reload");
        let dir = tmpdir("ssh-reload");
        let (core, _) = test_core(
            &dir,
            "tok",
            "secret",
            DevMode::Off,
            Duration::from_millis(10),
        );

        // Before: the agent advertises no keys.
        assert!(
            SshBackend::identities(core.as_ref()).is_empty(),
            "no keys served at start"
        );

        // Author a file-backed key on disk and register it in ssh-keys.json.
        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let key_path = dir.join("id_ed25519");
        std::fs::write(&key_path, key.to_openssh(ssh_key::LineEnding::LF).unwrap()).unwrap();
        std::fs::write(
            format!("{}.pub", key_path.display()),
            key.public_key().to_openssh().unwrap(),
        )
        .unwrap();
        sshagent::SshKeyConfig {
            files: vec![sshagent::SshFileEntry {
                path: key_path.display().to_string(),
                comment: String::new(),
                hosts: Vec::new(),
            }],
            stored: Vec::new(),
        }
        .save()
        .expect("writing ssh-keys.json into SIGIL_HOME");

        core.reload_ssh_signers()
            .expect("a clean reload swaps in the new key");

        // After: the freshly added key is advertised, no restart.
        let ids = SshBackend::identities(core.as_ref());
        assert_eq!(ids.len(), 1, "the newly added key is served after reload");
        assert_eq!(ids[0].key_blob, key.public_key().to_bytes().unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stored_ssh_key_is_advertised_from_the_config() {
        // A `sigil ssh add-stored` entry is advertised by the agent (listing a
        // stored key needs only its public line, not the sealed record).
        let _home = HomeGuard::new("ssh-stored-adv");
        let dir = tmpdir("ssh-stored-adv");
        let (core, _) = test_core(
            &dir,
            "tok",
            "secret",
            DevMode::Off,
            Duration::from_millis(10),
        );

        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let pub_line = key.public_key().to_openssh().unwrap();
        let fp = key
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        sshagent::SshKeyConfig {
            files: Vec::new(),
            stored: vec![sshagent::SshStoredEntry {
                public_key: pub_line,
                account_id: format!("ssh:{fp}"),
                comment: "tom@stored".into(),
                hosts: Vec::new(),
            }],
        }
        .save()
        .expect("writing ssh-keys.json into SIGIL_HOME");

        let ids = SshBackend::identities(core.as_ref());
        assert_eq!(ids.len(), 1, "the stored key is advertised");
        assert_eq!(ids[0].key_blob, key.public_key().to_bytes().unwrap());
        assert_eq!(ids[0].label, "tom@stored");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stored_ssh_key_seals_opens_and_signs() {
        // The exact crypto composition `Core::sign_stored` performs: seal an
        // OpenSSH private key under threshold, then open it per-signature with the
        // phone's partial Z_F plus the Mac share m, decode, sign, and verify. Uses
        // the real reviewed primitives (a software stand-in for the phone SE key).
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use sigil_proto::threshold::{EcdhAlgo, MacShare};

        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap();

        // Software phone (f, F) and the Mac share m.
        let f = MacShare::generate();
        let f_x963 = *f.public_point().as_x963();
        let phone = crate::threshold::PhoneShare::from_x963("phone-se.v2", &f_x963, EcdhAlgo::RawX)
            .unwrap();
        let m = MacShare::generate();

        // Seal exactly as `sigil ssh add-stored` does.
        let mut store = crate::threshold::ThresholdStore::default();
        crate::threshold::seal_secret(&mut store, "ssh:test", &m, &phone, pem.as_bytes()).unwrap();
        let record = store.get("ssh:test").unwrap();
        // The private key must not survive in cleartext in the sealed record.
        let json = serde_json::to_string(record).unwrap();
        assert!(
            !json.contains("OPENSSH PRIVATE KEY"),
            "no key material in the sealed record"
        );

        // The daemon's per-signature combine: Z_F = x(f·E), then decrypt.
        let e_point = record.ephemeral_point().unwrap();
        let zf = f.partial(&e_point, record.ecdh_algo, e_point.as_x963());
        let pem_back = crate::threshold::decrypt(record, &m, &zf).unwrap();

        // Decode + sign as sign_stored does, and verify the ed25519 signature.
        let data = b"stored-ssh-challenge-bytes";
        let sig_blob = sshagent::sign_openssh_ed25519(&pem_back, data)
            .expect("stored sign produces a signature");
        // The blob is `string "ssh-ed25519"` + `string <64-byte sig>`; the raw
        // signature is its final 64 bytes.
        assert!(sig_blob.len() >= 64);
        let raw = &sig_blob[sig_blob.len() - 64..];
        let pk_bytes = key.public_key().key_data().ed25519().unwrap().0;
        let vk = VerifyingKey::from_bytes(&pk_bytes).unwrap();
        let sig = Signature::from_slice(raw).unwrap();
        vk.verify(data, &sig)
            .expect("the stored-key signature verifies");

        // Fail closed: a wrong/absent partial yields no key (so no signature).
        assert!(
            crate::threshold::decrypt(record, &m, &[0u8; 32]).is_err(),
            "a wrong Z_F fails closed"
        );
    }

    #[test]
    fn config_reload_is_fail_closed_on_a_malformed_file() {
        // #59 fail-closed proof: a malformed / half-written config.json must NOT
        // downgrade gating. reload_config errors and the last-good rules stay in
        // force; the swap is never reached on the error path.
        let _home = HomeGuard::new("hot-reload-bad");
        let dir = tmpdir("hot-reload-bad");
        let (core, _) = test_core(
            &dir,
            "tok",
            "secret",
            DevMode::Off,
            Duration::from_millis(10),
        );

        // Adopt a good on-disk config that gates op.
        op_config().save().expect("writing a good config");
        core.reload_config().expect("clean reload");
        assert!(
            core.config
                .snapshot()
                .resolve(&av(&["op", "read", "x"]))
                .is_some(),
            "op gates after the good reload"
        );

        // Corrupt config.json (a truncated save is exactly this shape).
        let path = Config::path().expect("a config path under SIGIL_HOME");
        std::fs::write(&path, b"{ this is not valid json").expect("corrupting the config");
        let err = core
            .reload_config()
            .expect_err("a malformed reload must return an error");
        assert!(!err.is_empty(), "the error is surfaced for logging");

        // The last-good config is untouched: op still gates. A bad reload never
        // falls open (nor to refuse-all): it keeps what worked.
        assert!(
            core.config
                .snapshot()
                .resolve(&av(&["op", "read", "x"]))
                .is_some(),
            "a malformed reload must not downgrade the last-good gating"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_gate_selects_the_phone_approver_from_a_persisted_config() {
        // The wiring the whole task turns on: a RemotePairingConfig (such as
        // `load_remote_pairing` reconstructs) drives `build_gate` to the phone
        // approver with no DEK at rest. No relay is dialed synchronously, so this
        // needs no network.
        let (daemon_id, softphone) = pair_softphone(Policy::Approve);
        let cfg = RemotePairingConfig {
            relay_url: "ws://127.0.0.1:1".into(),
            daemon_identity: daemon_id,
            phone: softphone.phone_identity(),
            phone_share: None,
            direct_endpoint: None,
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
        let (gate, listeners, _acceptors) =
            build_gate(Factor::Phone, vec![cfg], &ks, &pending).unwrap();
        let _ = gate; // constructed without a DEK at rest: inert.
        assert_eq!(
            listeners.len(),
            1,
            "the single-device phone factor hands back exactly one listener handle"
        );
    }

    #[test]
    fn persisted_pairing_reloads_and_stays_inert_at_rest() {
        let _home = HomeGuard::new("reload-inert");
        // One keystore instance stands in for the login Keychain across save and
        // load (both go through the same trait object here).
        let ks: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());

        let (daemon_id, softphone) = pair_softphone(Policy::Approve);
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
    }

    #[test]
    #[cfg_attr(
        not(feature = "real-relay"),
        ignore = "spawns the native sigil-relay; build it first (cargo build -p sigil-relay), then: cargo test -p sigil --features real-relay -- --test-threads=1"
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
                 Build the native relay (cargo build -p sigil-relay), or set SIGIL_TEST_RELAY_URL."
            );
            return;
        };
        let _home = HomeGuard::new("reload-e2e");
        let ks: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());

        let (daemon_id, softphone) = pair_softphone(Policy::Approve);
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
        let (core, approver) = remote_core(
            &dir,
            cfg.daemon_identity,
            cfg.phone,
            Arc::new(daemon_relay),
            Duration::from_secs(10),
            "reload-token-abc",
            "reload-secret-88",
        );
        let (owner_stop, owner) = spawn_owner(approver);

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
        owner_stop.store(true, Ordering::SeqCst);
        owner.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg_attr(
        not(feature = "real-relay"),
        ignore = "spawns the native sigil-relay; build it first (cargo build -p sigil-relay), then: cargo test -p sigil --features real-relay -- --test-threads=1"
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
                 Build the native relay (cargo build -p sigil-relay), or set SIGIL_TEST_RELAY_URL."
            );
            return;
        };
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use sigil_proto::{now_ms, rendezvous_mailbox, PairingPayload};
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
            let sp = pairing.finish().unwrap();
            sp.phone_identity()
        });

        let daemon_id = DeviceIdentity::generate();
        let daemon_pub = daemon_id.peer_identity();
        let mut make_channel = |mailbox: [u8; 32]| crate::pair::relay_channel(&base, mailbox);
        let mut present_qr = |_u: &str, b64: &str| qr_tx.send(b64.to_string()).unwrap();
        let mut confirm = |_w: &[&'static str; 6]| true;
        let mut arm_after_sas = || -> anyhow::Result<()> { Ok(()) };
        let opts = crate::pair::CeremonyOpts {
            relay_url: base.clone(),
            response_timeout: Duration::from_secs(15),
            flush_grace: Duration::from_millis(750),
            now: &now_ms,
            make_channel: &mut make_channel,
            present_qr: &mut present_qr,
            confirm_sas: &mut confirm,
            arm_after_sas: &mut arm_after_sas,
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
    fn different_ssh_challenges_do_not_share_a_grant_key() {
        // The coalescing-safety invariant: a signature over different data must
        // derive a different grant key, so the approval gate can never let one
        // challenge ride another challenge's approval. Same caller, same key
        // label, different data fingerprints -> different scope -> different gk.
        let caller = lease::walk_ancestry(&EmptyTable, -1);
        let fp_a = crate::sshagent::sha256_fingerprint(b"challenge-A");
        let fp_b = crate::sshagent::sha256_fingerprint(b"challenge-B");
        assert_ne!(fp_a, fp_b);
        let gk_a = lease::grant_key(
            &caller,
            lease::ScopeKind::SshSignature,
            "",
            &ssh_sign_scope("GitHub", &fp_a),
        );
        let gk_b = lease::grant_key(
            &caller,
            lease::ScopeKind::SshSignature,
            "",
            &ssh_sign_scope("GitHub", &fp_b),
        );
        assert_ne!(gk_a, gk_b, "different data must not coalesce");
        // A byte-identical re-sign IS allowed to coalesce (deterministic, same sig).
        let gk_a2 = lease::grant_key(
            &caller,
            lease::ScopeKind::SshSignature,
            "",
            &ssh_sign_scope("GitHub", &fp_a),
        );
        assert_eq!(gk_a, gk_a2);
    }

    #[test]
    fn env_file_lease_decision_grants_no_lease() {
        // The rule's policy is the sole authority, and this env-file rule is
        // run-once: even though the approver returns a session lease, nothing is
        // retained and the next run is gated afresh. (An env-file rule caches
        // nothing regardless: it reads its own file at run time, so a window over
        // it would hold no values, only the presence marker a plain gate holds.)
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
        let approver = LocalApprover::new(pending.clone())
            .with_dev(DevMode::Lease(Duration::from_secs(60)))
            .with_control_socket(true);
        let config = env_file_config("faketool", env_path.to_str().unwrap());
        let core = Arc::new(Core {
            remote: Vec::new(),
            keystore: KeystoreCell::new(keystore),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            config: config.into(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: SshSignersCell::new(Vec::new()),
            audit: None,
            seal: crate::keystore_seal::SealState::Plain,
            provisioned: AtomicBool::new(false),
            unwrap_requests: UnwrapRequests::default(),
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
        let approver = LocalApprover::new(pending.clone())
            .with_dev(DevMode::Off)
            .with_control_socket(true)
            .with_timeout(Duration::from_millis(50));
        let core = Core {
            remote: Vec::new(),
            keystore: KeystoreCell::new(keystore),
            threshold: Mutex::new(Default::default()),
            leases: LeaseStore::new(),
            gate: ApprovalGate::new(Box::new(approver)),
            pending,
            proc_table: Box::new(EmptyTable),
            providers: ProviderRegistry::with_defaults(),
            config: op_config().into(),
            lease_ttl: Duration::from_secs(60),
            factor: Factor::DevInsecure,
            ssh_signers: SshSignersCell::new(vec![Box::new(sshagent::FileSshSigner::new(vec![(
                id.clone(),
                key_path.clone(),
            )]))]),
            audit: None,
            seal: crate::keystore_seal::SealState::Plain,
            provisioned: AtomicBool::new(false),
            unwrap_requests: UnwrapRequests::default(),
        };

        let host = sshagent::HostContext {
            host: "(host not bound)".into(),
            binding: sigil_proto::HostBinding::Unbound,
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
