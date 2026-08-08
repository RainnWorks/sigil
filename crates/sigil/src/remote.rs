//! The remote approver: satisfy an approval by asking a paired phone over a
//! [`Transport`], instead of a local Touch ID / control-socket decision.
//!
//! This is the path that makes the daemon inert at rest. The daemon holds no
//! DEK; on each request it:
//!
//! 1. builds an [`ApprovalRequest`] from the daemon-verified [`ApprovalContext`]
//!    (never anything the client claimed),
//! 2. seals it into an [`Envelope`] (signed by the daemon's pinned key, sealed
//!    to the phone's pinned agreement key) and sends it `ToPhone`,
//! 3. blocks up to a timeout for the phone's sealed [`ApprovalResponse`]
//!    `ToDaemon`, verifying + replay-checking + decrypting it, and
//! 4. on approve, hands the DEK the phone delivered back to the gate as an
//!    [`ApprovalOutcome`]; the daemon uses it to decrypt the one token and
//!    zeroizes it.
//!
//! Every failure — seal error, transport error, timeout, an unverifiable or
//! mis-correlated response, or an "approve" that carries no DEK — fails closed
//! to a `Deny` outcome. Only a well-formed, authenticated approve carrying a DEK
//! releases a secret.
//!
//! ## One ToDaemon owner, demultiplexing to waiters
//!
//! The ToDaemon channel carries two interleaved streams from the phone: approval
//! [`ApprovalResponse`]s, and unsolicited [`PushRegister`]s (the phone deposits
//! its push token *the moment it arms*, not only alongside an approval). The relay
//! holds a deposit for a short TTL and then drops it, and it hands each deposit to
//! exactly ONE reader. So exactly one thread may ever read ToDaemon, or two
//! readers would steal each other's messages.
//!
//! That single reader is the owner loop
//! ([`run_todaemon_owner`](RemoteApprover::run_todaemon_owner)), spawned once by
//! the daemon whenever it is paired. It continuously long-polls ToDaemon,
//! [`classify`](RemoteApprover::classify)s each envelope through the one shared
//! [`ReplayGuard`] (now touched by this thread alone), and demultiplexes:
//!
//! * a [`PushRegister`] is recorded to the push store (persisted to `push.json`);
//! * an [`ApprovalResponse`] is routed to the waiting [`round_trip`], if any, via
//!   a `request_id -> Sender` map ([`waiters`](RemoteApprover::waiters)); a
//!   response with no registered waiter is stale and dropped.
//!
//! [`round_trip`](RemoteApprover::round_trip) itself never reads ToDaemon. It
//! registers a waiter under its `request_id` **before** it deposits the request,
//! then blocks on the receiver until the owner hands it the response or the
//! timeout elapses (fail closed to deny). Registering before depositing is
//! race-free: the phone only answers after it receives the deposited request, so
//! the waiter always exists by the time any response can arrive. Because the owner
//! is already parked in the long-poll that will receive that response, an approval
//! adds no latency of its own, and there is no lock coupling an approval to the
//! relay's ~25s hold. The arm-time [`PushRegister`] is still caught the instant it
//! lands, because the owner reads ToDaemon continuously.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sigil_direct::discovery::{self, VerifyError};
use sigil_direct::{DirectLink, DirectListener, FallbackTransport};
use sigil_proto::envelope::Envelope;
use sigil_proto::identity::DeviceIdentity;
use sigil_proto::ReplayGuard;
use sigil_proto::{
    mailbox_id, now_ms, ApprovalRequest, ApprovalResponse, Decision as ProtoDecision, Direction,
    LeaseListReply, LeaseRevoke, LeaseRevokeReply, LeaseRow, PeerIdentity, Provenance, PushHint,
    PushRegister, ResolutionBroadcast, ResolutionStatus, ToDaemonMessage, Transport,
};
use uuid::Uuid;

use crate::lease::LeaseControl;

use crate::approve::{ApprovalContext, ApprovalOutcome, Approver, Decision, PendingRegistry};
use crate::push_store::PushStore;

/// One in-flight remote approval, held in the [`RemoteApprover::waiters`] map. It
/// pairs the channel its `round_trip` blocks on with a read-only snapshot of the
/// sealed request (so the daemon can enumerate remote pendings for the Mac's
/// `pending` surface) and the delivery-receipt state.
struct Inflight {
    /// The sender the owner loop hands the phone's [`ApprovalResponse`] to.
    tx: Sender<ApprovalResponse>,
    /// A plaintext snapshot of the request, for the `pending` enumeration only. It
    /// carries no secret value (an [`ApprovalRequest`] never does).
    request: ApprovalRequest,
    /// When this request was deposited, unix ms (the countdown's zero point).
    queued_at_ms: u64,
    /// When the phone's delivery receipt landed, unix ms; `None` until then.
    /// Display/telemetry only: it NEVER gates a decision, only the requester's
    /// Sent -> Delivered readout.
    delivered_at_ms: Option<u64>,
}

/// A read-only view of one in-flight remote approval, for the daemon's `pending`
/// surface. Mirrors [`crate::approve::PendingSnapshot`] but adds the delivery
/// state the phone reports over the relay.
#[derive(Clone)]
pub struct RemotePending {
    /// The sealed request, snapshotted (names and provenance only, never a secret).
    pub request: ApprovalRequest,
    /// When the request was deposited, unix ms.
    pub queued_at_ms: u64,
    /// When the phone acknowledged receipt, unix ms; `None` if not yet (or never).
    pub delivered_at_ms: Option<u64>,
}

/// Default wait for a phone decision before failing closed.
pub const DEFAULT_REMOTE_TIMEOUT: Duration = Duration::from_secs(120);

/// How long each owner-loop poll of the ToDaemon channel waits before it returns
/// so the loop can re-check the shutdown flag. On the network relay a single GET
/// long-polls server-side (~25s) regardless of this value, so it mainly bounds how
/// promptly the owner notices a shutdown between holds; tests shrink it so their
/// idle owner joins quickly. It never bounds an approval's latency: the owner is
/// already parked in the poll that will deliver the response.
const OWNER_POLL_INTERVAL: Duration = Duration::from_secs(20);

/// Backoff after a transport error in the owner loop, so a persistently failing
/// poll settles instead of spinning.
const OWNER_ERROR_BACKOFF: Duration = Duration::from_millis(500);

/// How often a ring device's cancellable wait re-checks the shared cancel flag
/// while blocking on its response channel. Bounds how promptly a losing device
/// stops after a winner (and thus how fast [`RingApprover::decide`] joins its
/// threads). Small enough to feel instant, large enough not to spin.
const RING_CANCEL_TICK: Duration = Duration::from_millis(100);

/// How long a deposited request may go unanswered over a live DIRECT primary
/// before [`round_trip`](RemoteApprover::round_trip) demotes to the relay and
/// re-deposits (see [`demote_and_redeposit`](RemoteApprover::demote_and_redeposit)).
/// A short fraction of [`DEFAULT_REMOTE_TIMEOUT`]: long enough that a healthy
/// direct link answers first (so the relay is genuinely skipped), short enough
/// that an active LAN MITM black-holing an accepted deposit costs one brief retry
/// rather than a full-timeout denial. Only ever consulted when a direct primary
/// is installed; with direct OFF the wait is the reviewed single `recv_timeout`.
const DIRECT_DEMOTE_AFTER: Duration = Duration::from_secs(8);

/// How long [`verify_and_promote`](RemoteApprover::verify_and_promote) waits for
/// the first envelope on a freshly dialled/accepted direct link before failing
/// closed (never installing it). A direct-connecting phone sends its opener at
/// once; this only bounds a connect-then-silent host (honest or hostile).
const DIRECT_VERIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a rung-2 direct acceptor parks between non-blocking `accept` polls
/// while it waits for a phone to dial. Small enough to pick up a dial promptly,
/// large enough not to spin; the relay serves throughout, so this never gates an
/// approval.
const DIRECT_ACCEPT_POLL: Duration = Duration::from_millis(200);

/// How often the per-pairing lease-control token bucket gains a token: a
/// sustained ceiling of one lease-control message per second.
const LEASE_REFILL_MS: u64 = 1_000;

/// How many lease-control tokens may accumulate, i.e. the burst a human is
/// allowed on top of the sustained 1/s.
///
/// Not zero, and that is the whole point of using a bucket rather than a flat
/// minimum interval. A human revoking three rows taps three times in about a
/// second; under a flat 1/s two of those taps would be dropped in silence, which
/// is the consent theatre this feature exists to end. Four tokens cover any burst
/// a person can produce while reading, and still bound a looping client to 1/s.
const LEASE_BURST: u64 = 4;

/// How long the lease reply pump parks between queue polls, bounding how promptly
/// it notices shutdown. Never gates a reply: a queued one wakes it at once.
const LEASE_PUMP_TICK: Duration = Duration::from_millis(100);

/// How many sealed lease-control replies may await the pump before new ones are
/// dropped. Small on purpose: the queue exists to decouple the owner thread from
/// the network, not to buffer a backlog. See
/// [`RemoteApprover::queue_lease_reply`].
const LEASE_REPLY_QUEUE: usize = 8;

/// The per-pairing lease-control token bucket. See
/// [`RemoteApprover::lease_budget_allows`].
struct LeaseBudget {
    tokens: u64,
    refilled_at_ms: u64,
}

/// An approver backed by a paired phone reachable over a [`Transport`].
pub struct RemoteApprover {
    transport: Arc<dyn Transport>,
    /// The daemon's own identity: signs requests, opens responses.
    identity: DeviceIdentity,
    /// The pinned phone identity: verifies requests it receives, is sealed to.
    phone: PeerIdentity,
    /// The shared mailbox both parties route on.
    pairing_id: [u8; 32],
    /// Daemon -> phone envelope counter (monotonic).
    counter: AtomicU64,
    /// Phone -> daemon replay guard. Guards EVERY inbound envelope on the
    /// ToDaemon channel, responses and push-registrations alike, since the phone
    /// counts them on one monotonic sequence (see [`Self::classify`]). Only the
    /// owner loop reads ToDaemon, so this is touched by a single thread.
    guard: Mutex<ReplayGuard>,
    timeout: Duration,
    machine: String,
    /// Phone push registrations, keyed by mailbox. A registration arrives inline
    /// on the ToDaemon channel and is recorded here; the token is forwarded to the
    /// relay per deposit so the relay (not the daemon) rings the doorbell.
    push_store: Arc<PushStore>,
    /// In-flight approval waiters, keyed by `request_id`. [`round_trip`] inserts an
    /// [`Inflight`] here before it deposits its request and blocks on the paired
    /// receiver; the owner loop, the sole ToDaemon reader, looks up the matching
    /// entry for each [`ApprovalResponse`] and hands the response to its `tx`. A
    /// response with no entry is stale and dropped. This map is what lets one reader
    /// serve any number of concurrent approvals without a lock. It doubles as the
    /// remote `pending` enumeration (each entry snapshots its request) and holds the
    /// per-request delivery-receipt state.
    ///
    /// [`round_trip`]: Self::round_trip
    waiters: Mutex<HashMap<String, Inflight>>,
    /// The shared local pending registry, when wired (phone factor). Not read here;
    /// its version counter is bumped whenever the in-flight/delivery set changes so a
    /// `subscribe_pending` client re-emits promptly (Sent -> Delivered is reactive,
    /// not only on the 30s keepalive). `None` in the softphone/test loop.
    pending: Option<Arc<PendingRegistry>>,
    /// How long one owner-loop poll waits; a field only so tests can shrink it.
    listen_poll: Duration,
    /// The direct-transport selector for THIS device, when direct is enabled for
    /// it (#51). `Some` iff [`transport`](Self::transport) is that same
    /// [`FallbackTransport`], so [`verify_and_promote`](Self::verify_and_promote)
    /// can install a verified direct primary on it and
    /// [`demote_and_redeposit`](Self::demote_and_redeposit) can retire one.
    /// `None` is the default and means relay-only: every direct code path below is
    /// gated on `self.direct.is_some()`, so with direct OFF the approver is
    /// byte-identical to the reviewed relay-only path (single- and multi-device).
    /// A direct link is a pipe, never a trust boundary: only the same sealed
    /// envelopes ride it, opened against the same pinned key + shared guard.
    direct: Option<Arc<FallbackTransport>>,
    /// The unanswered-over-direct window before demoting to the relay; a field
    /// only so tests can shrink it. Unused when [`direct`](Self::direct) is `None`.
    demote_after: Duration,
    /// The verification read window in [`verify_and_promote`](Self::verify_and_promote);
    /// a field only so tests can shrink it.
    verify_timeout: Duration,
    /// The daemon's lease-control handle, attached by [`crate::daemon::Core`]
    /// once it exists (the approver is built first, inside `build_gate`). `None`
    /// until then, and in the softphone/test loop that never wires one; a
    /// lease-control message arriving with none attached is dropped with no reply,
    /// which is the same fail-closed shape as every other unanswerable message
    /// here.
    ///
    /// **A [`LeaseControl`], not a `LeaseStore`.** The narrow trait is what makes
    /// this path structurally unable to open or extend a window, or to read what
    /// one holds: it has exactly two methods, list and revoke-by-id, and no code
    /// reachable from an inbound envelope can call `grant`, `token_for`, or the
    /// prefix-matched CLI `revoke` at all.
    ///
    /// Set once, never replaced: a handle that could be swapped under a running
    /// daemon would be a way to make a revoke land somewhere it was not aimed.
    leases: std::sync::OnceLock<Arc<dyn LeaseControl>>,
    /// This pairing's lease-control rate budget.
    lease_budget: Mutex<LeaseBudget>,
    /// Sealed lease-control replies waiting for [`run_lease_reply_pump`]. Bounded
    /// and droppable so a reply can never block the ToDaemon owner or compete with
    /// an approval deposit.
    ///
    /// [`run_lease_reply_pump`]: Self::run_lease_reply_pump
    lease_replies: (SyncSender<Envelope>, Mutex<Receiver<Envelope>>),
}

impl RemoteApprover {
    /// Wire an approver to `transport` for the pairing between `identity` (the
    /// daemon) and `phone` (the pinned approver). The mailbox is derived from the
    /// two pinned identities, matching what the phone computes.
    pub fn new(
        transport: Arc<dyn Transport>,
        identity: DeviceIdentity,
        phone: PeerIdentity,
    ) -> Self {
        let pairing_id = mailbox_id(&identity.peer_identity(), &phone);
        Self {
            transport,
            identity,
            phone,
            pairing_id,
            // Seed the outbound envelope counter from the wall clock, not 0.
            // The phone's replay guard rejects any counter <= the highest it has
            // seen, so a daemon restart that reset this to 0 made the phone drop
            // every new request as a stale replay (fetched, never shown). The
            // clock is a persistent monotonic source: a restart always seeds a
            // value above the prior session's (millis climb far faster than we
            // issue requests), so the counter strictly advances across restarts
            // with no on-disk state. The counter is an opaque monotonic tag, so a
            // large starting value is fine. (The clean fix is to retire the
            // counter for age-windowed request-id dedup; tracked separately.)
            counter: AtomicU64::new(sigil_proto::now_ms()),
            guard: Mutex::new(ReplayGuard::new()),
            timeout: DEFAULT_REMOTE_TIMEOUT,
            machine: hostname(),
            // Default to an in-memory registration store. The production daemon
            // replaces it via `with_push` with the disk-backed one; the
            // softphone/local test loop runs with this no-op and never touches the
            // filesystem.
            push_store: Arc::new(PushStore::ephemeral()),
            waiters: Mutex::new(HashMap::new()),
            pending: None,
            listen_poll: OWNER_POLL_INTERVAL,
            direct: None,
            demote_after: DIRECT_DEMOTE_AFTER,
            verify_timeout: DIRECT_VERIFY_TIMEOUT,
            leases: std::sync::OnceLock::new(),
            lease_budget: Mutex::new(LeaseBudget {
                tokens: LEASE_BURST,
                refilled_at_ms: now_ms(),
            }),
            lease_replies: {
                let (tx, rx) = std::sync::mpsc::sync_channel(LEASE_REPLY_QUEUE);
                (tx, Mutex::new(rx))
            },
        }
    }

    /// Attach the daemon's lease-control handle so this device can answer the
    /// phone's [`LeaseQuery`] and [`LeaseRevoke`] messages. Called once by
    /// [`crate::daemon::Core`] after it is built (the approvers are constructed
    /// first, inside `build_gate`), over the SAME store `sigil lease list` and
    /// `sigil lease revoke` read and write. A second call is a no-op.
    ///
    /// The parameter is deliberately the narrow [`LeaseControl`] trait, so this
    /// path is handed the authority to see and close windows and nothing else.
    ///
    /// Until this is called the two lease-control messages are dropped with no
    /// reply, so an approver that is never wired simply has no lease surface
    /// rather than a half-working one.
    pub fn attach_leases(&self, leases: Arc<dyn LeaseControl>) {
        let _ = self.leases.set(leases);
    }

    /// Enable the direct-transport ladder for this device (#51), OFF by default.
    ///
    /// `fallback` MUST be the very same [`FallbackTransport`] this approver was
    /// constructed over (i.e. `RemoteApprover::new(fallback.clone(), ..)`), so that
    /// [`transport`](Self::transport) (which the owner loop and `round_trip` use)
    /// and the recorded [`direct`](Self::direct) selector are one object: a primary
    /// installed here is what the owner then reads and a request then rides. The
    /// caller wires this only when a device has a `direct_endpoint`; without it the
    /// approver keeps its bare relay transport and every direct path stays inert.
    pub fn with_direct(mut self, fallback: Arc<FallbackTransport>) -> Self {
        self.direct = Some(fallback);
        self
    }

    /// Wire the shared local pending registry so a change to the remote in-flight
    /// or delivery set bumps its version and wakes any `subscribe_pending` client.
    /// The production `build_gate` passes the same registry the control handler
    /// enumerates, so the Mac sees remote pendings advance Sent -> Delivered live.
    pub fn with_pending(mut self, pending: Arc<PendingRegistry>) -> Self {
        self.pending = Some(pending);
        self
    }

    /// Attach the persistent push registration store. The production `build_gate`
    /// wires the disk-backed one so a registered token survives a restart and is
    /// forwarded to the relay on each deposit.
    pub fn with_push(mut self, push_store: Arc<PushStore>) -> Self {
        self.push_store = push_store;
        self
    }

    /// Override the wait for a phone decision (tests use a short one).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The mailbox id the phone and daemon share for this pairing.
    pub fn mailbox(&self) -> [u8; 32] {
        self.pairing_id
    }

    /// Build the request from the daemon-verified context. Provider-blind: the
    /// command, secret refs, and display hint were prepared by the daemon's
    /// provider; this just packages them with the caller provenance.
    fn build_request(&self, ctx: &ApprovalContext) -> ApprovalRequest {
        let now = now_ms();
        let process_chain = ctx
            .provenance
            .split(" \u{2192} ")
            .map(str::to_string)
            .filter(|s| !s.is_empty())
            .collect();
        let timeout_ms = self.timeout.as_millis() as u64;
        ApprovalRequest {
            request_id: ctx.id.clone(),
            kind: ctx.kind,
            command: ctx.command.clone(),
            secrets: ctx.secret_refs.clone(),
            ssh: ctx.ssh.clone(),
            provenance: Provenance {
                process_chain,
                cwd: ctx.cwd.clone(),
                machine: self.machine.clone(),
                requested_at: now,
            },
            lease_policy: ctx.lease.clone(),
            reason: None,
            // A threshold-sealed secret (inline env, or a stored SSH key) carries
            // its threshold challenge to the phone; a plain gate leaves it absent
            // and approves without a partial.
            threshold: ctx.threshold.clone(),
            expires_at: now + timeout_ms,
            timeout_ms,
        }
    }

    /// The whole round trip, or `None` (fail closed) at the first misstep.
    ///
    /// This never reads ToDaemon (only the owner loop does). It registers a waiter
    /// under `req.request_id` BEFORE depositing the request, so no response can
    /// arrive before the waiter exists (the phone answers only after it receives
    /// the deposit), then blocks on the receiver until the owner hands it the
    /// correlating [`ApprovalResponse`] or the timeout elapses. A timeout, a seal
    /// error, or a deposit error all fail closed to deny, and the waiter is always
    /// removed on the way out.
    fn round_trip(&self, ctx: &ApprovalContext) -> Option<ApprovalOutcome> {
        let req = self.build_request(ctx);

        // Register our waiter first: the owner loop can then route the phone's
        // response to us the instant it arrives. Registering before the deposit
        // closes the only race (a response landing before a waiter exists) because
        // the phone cannot answer a request it has not yet received.
        let rx = self.register_waiter(&req);
        // From here every return path must drop the waiter, so wrap the body.
        let outcome = self.deposit_and_wait(&req, rx);
        self.remove_waiter(&req.request_id);
        outcome
    }

    /// Seal `req` under a fresh monotonic counter and deposit it toward the phone
    /// over the active transport, forwarding the phone's push token (if any) so the
    /// RELAY rings a content-free doorbell. The token wakes the phone to fetch the
    /// request; it is best-effort and never gates correctness (the phone's poll
    /// backstop delivers regardless), and a direct link ignores it (the phone is
    /// awake on the live connection). The daemon signs no push. `None` on a seal or
    /// deposit error, so every caller fails closed. Used for the initial deposit
    /// and for the demote re-deposit (which reseals under a NEW counter, so the
    /// phone's replay guard accepts the relay copy even if it also saw a
    /// black-holed direct copy).
    fn seal_and_deposit(&self, req: &ApprovalRequest) -> Option<()> {
        let counter = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        let env = Envelope::seal(
            req,
            self.pairing_id,
            counter,
            &self.identity.signing,
            &self.phone,
        )
        .ok()?;
        self.transport
            .deposit_to_phone(self.pairing_id, &env, self.push_hint())
            .ok()?;
        Some(())
    }

    /// Whether a verified DIRECT primary is installed on this device's selector
    /// right now. `false` when direct is disabled (`self.direct` is `None`) or
    /// enabled-but-relay-serving, i.e. exactly the states in which the wait below
    /// is the reviewed single-`recv_timeout` path.
    fn direct_primary_live(&self) -> bool {
        self.direct.as_ref().is_some_and(|d| d.has_primary())
    }

    /// Retire the direct primary and re-deposit `req` over the relay once
    /// (demote-on-silence, #51). The `clear_primary` makes the owner loop revert to
    /// reading the relay on its next poll and makes this re-deposit ride the relay
    /// (a [`FallbackTransport`] with no primary IS the relay). This is what turns
    /// the active-LAN-MITM residual (a promoted-then-black-holed link) from a
    /// full-timeout denial into a short relay retry: the LAN attacker cannot block
    /// the relay. A no-op re-deposit failure just leaves the original wait to time
    /// out and fail closed. Only ever called with `self.direct` = `Some`.
    fn demote_and_redeposit(&self, req: &ApprovalRequest) {
        if let Some(direct) = self.direct.as_ref() {
            direct.clear_primary();
        }
        let _ = self.seal_and_deposit(req);
    }

    /// Seal, deposit, and block for the owner-delivered response. Split from
    /// [`round_trip`] so the waiter cleanup there covers every exit uniformly.
    ///
    /// With direct OFF (or enabled but relay-serving) this is byte-identical to the
    /// reviewed path: one `recv_timeout(self.timeout)`, fail-closed on timeout or a
    /// dropped owner. With a direct primary live, it adds demote-on-silence: wait a
    /// short window on the direct link, and if nothing arrives, retire the primary
    /// and re-deposit over the relay, then spend the rest of the budget waiting for
    /// the relay-delivered response. Either way exactly one correlated response (or
    /// a fail-closed `None`) is returned.
    fn deposit_and_wait(
        &self,
        req: &ApprovalRequest,
        rx: Receiver<ApprovalResponse>,
    ) -> Option<ApprovalOutcome> {
        self.seal_and_deposit(req)?;

        // Reviewed single-device path, byte-identical, whenever no direct primary
        // is carrying this request (direct disabled, or enabled but relay-serving).
        if !self.direct_primary_live() {
            return match rx.recv_timeout(self.timeout) {
                Ok(resp) => self.outcome_for(req, resp),
                Err(_) => None,
            };
        }

        // A direct primary carried the deposit: give it a short window, then demote
        // to the relay on silence. The total wait budget is still `self.timeout`.
        let deadline = Instant::now() + self.timeout;
        let window = self.demote_after.min(self.timeout);
        match rx.recv_timeout(window) {
            Ok(resp) => return self.outcome_for(req, resp),
            // The owner dropped the sender (shutdown): fail closed.
            Err(RecvTimeoutError::Disconnected) => return None,
            // Silence over the direct link: demote and retry once over the relay.
            Err(RecvTimeoutError::Timeout) => self.demote_and_redeposit(req),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(resp) => self.outcome_for(req, resp),
            Err(_) => None,
        }
    }

    /// The ring-only round trip: identical to [`round_trip`](Self::round_trip),
    /// but its wait ALSO stops early when the shared [`CancelToken`] fires, so a
    /// losing device in a [`RingApprover`] does not sit out the full timeout after
    /// another device has already won.
    ///
    /// This is a SEPARATE method from `round_trip` on purpose (option (A) in
    /// `docs/design/multi-device.md`): the single-device path keeps its exact,
    /// reviewed `recv_timeout(self.timeout)` shape with no cancel check, so N == 1
    /// is byte-identical. The seal/deposit/waiter-cleanup are shared; only the wait
    /// loop differs. Every exit still removes the waiter, and a cancel returns
    /// `None` (no decision), which fails closed exactly like a timeout.
    fn round_trip_cancellable(
        &self,
        ctx: &ApprovalContext,
        cancel: &CancelToken,
    ) -> Option<ApprovalOutcome> {
        let req = self.build_request(ctx);
        let rx = self.register_waiter(&req);
        let outcome = self.deposit_and_wait_cancellable(&req, rx, cancel);
        self.remove_waiter(&req.request_id);
        outcome
    }

    /// Seal, deposit, and block for a response OR a cancel. The wait polls the
    /// waiter channel on a short tick and re-checks the cancel flag between ticks,
    /// so a cancelled loser returns within one tick (`RING_CANCEL_TICK`). A real
    /// response resolves it exactly as the single-device path does; a cancel or a
    /// full-timeout returns `None` (fail closed). Never routes another device's
    /// response: the waiter map is per-device, so `rx` only ever carries THIS
    /// device's correlated response.
    fn deposit_and_wait_cancellable(
        &self,
        req: &ApprovalRequest,
        rx: Receiver<ApprovalResponse>,
        cancel: &CancelToken,
    ) -> Option<ApprovalOutcome> {
        self.seal_and_deposit(req)?;

        let deadline = Instant::now() + self.timeout;
        // Demote schedule: a one-shot instant, present only when a direct primary
        // is actually carrying this request. `None` (direct off, or relay-serving)
        // leaves the loop byte-identical to the reviewed ring wait.
        let mut demote_at = self
            .direct_primary_live()
            .then(|| Instant::now() + self.demote_after.min(self.timeout));
        loop {
            // A winner elsewhere: stop waiting and remove our waiter (via the
            // caller). No decision -> fail closed, same as a timeout.
            if cancel.is_cancelled() {
                return None;
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            // Demote-on-silence: past the short window with no response, retire the
            // direct primary and re-deposit over the relay once, then keep waiting.
            if let Some(at) = demote_at {
                if now >= at {
                    self.demote_and_redeposit(req);
                    demote_at = None;
                }
            }
            let mut wait = RING_CANCEL_TICK.min(deadline - now);
            if let Some(at) = demote_at {
                wait = wait.min(at.saturating_duration_since(now));
            }
            match rx.recv_timeout(wait) {
                Ok(resp) => return self.outcome_for(req, resp),
                // Tick elapsed with nothing: re-check cancel, deadline, and demote.
                Err(RecvTimeoutError::Timeout) => continue,
                // The owner dropped the sender (shutdown): fail closed.
                Err(RecvTimeoutError::Disconnected) => return None,
            }
        }
    }

    /// Register an approval waiter and return the receiver [`round_trip`] blocks
    /// on. The owner loop finds the paired sender by `request_id`. The entry also
    /// snapshots the request so the daemon can enumerate remote pendings, and starts
    /// with no delivery receipt (`delivered_at_ms: None`).
    fn register_waiter(&self, req: &ApprovalRequest) -> Receiver<ApprovalResponse> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.waiters
            .lock()
            .expect("remote waiters poisoned")
            .insert(
                req.request_id.clone(),
                Inflight {
                    tx,
                    request: req.clone(),
                    queued_at_ms: now_ms(),
                    delivered_at_ms: None,
                },
            );
        // A new in-flight request changed the pending set: wake subscribers.
        self.notify_pending();
        rx
    }

    /// Drop the waiter for `request_id` (on resolve, timeout, or error).
    fn remove_waiter(&self, request_id: &str) {
        let removed = self
            .waiters
            .lock()
            .expect("remote waiters poisoned")
            .remove(request_id)
            .is_some();
        if removed {
            // The request left the in-flight set: wake subscribers.
            self.notify_pending();
        }
    }

    /// Record the phone's delivery receipt for `request_id`. Idempotent and fail
    /// closed for the display: an unknown, late, or duplicate receipt is a no-op
    /// (unknown/late => no entry; duplicate => `delivered_at_ms` already set), and
    /// it can only ever set a boolean/timestamp for the requester's readout, never
    /// touch a decision, DEK, or lease. Bumps the pending version on the first
    /// receipt so `subscribe_pending` advances Sent -> Delivered promptly.
    fn mark_delivered(&self, request_id: &str, at_ms: u64) {
        let changed = {
            let mut waiters = self.waiters.lock().expect("remote waiters poisoned");
            match waiters.get_mut(request_id) {
                Some(entry) if entry.delivered_at_ms.is_none() => {
                    entry.delivered_at_ms = Some(at_ms);
                    true
                }
                // Duplicate (already delivered) or unknown/late (no entry): drop it.
                _ => false,
            }
        };
        if changed {
            self.notify_pending();
        }
    }

    /// A read-only snapshot of every in-flight remote approval, for the daemon's
    /// `pending` enumeration. Newest-first, matching the local registry's ordering.
    pub fn pending_snapshot(&self) -> Vec<RemotePending> {
        let mut out: Vec<RemotePending> = self
            .waiters
            .lock()
            .expect("remote waiters poisoned")
            .values()
            .map(|w| RemotePending {
                request: w.request.clone(),
                queued_at_ms: w.queued_at_ms,
                delivered_at_ms: w.delivered_at_ms,
            })
            .collect();
        out.sort_by_key(|s| std::cmp::Reverse(s.queued_at_ms));
        out
    }

    /// Bump the shared pending registry's version, if wired, so a subscriber
    /// re-emits. A no-op in the softphone/test loop (no registry).
    fn notify_pending(&self) {
        if let Some(pending) = &self.pending {
            pending.notify_change();
        }
    }

    /// Verify, replay-check, decrypt, and classify one inbound envelope. Returns
    /// `None` when it fails any of those (fail closed). The single [`ReplayGuard`]
    /// covers responses and registrations together, matching the phone's single
    /// monotonic outbound counter.
    ///
    /// The envelope's uuidv7 request id comes back alongside the message because
    /// the lease-control replies must name the envelope that asked for them: a
    /// reply the phone cannot tie to an outstanding request of its own is a
    /// captured reply, and the phone has to be able to tell.
    fn classify(&self, env: Envelope) -> Option<(Uuid, ToDaemonMessage)> {
        let request_id = env.request_id;
        let value: serde_json::Value = {
            let mut guard = self.guard.lock().expect("remote guard poisoned");
            env.open(&self.phone, &self.identity.agreement, &mut guard)
                .ok()?
        };
        Some((request_id, ToDaemonMessage::from_value(value).ok()?))
    }

    /// Turn a correlated [`ApprovalResponse`] into an [`ApprovalOutcome`], applying
    /// the same fail-closed rules as before: an approve must carry a DEK (v1) or a
    /// partial for this exact account (v2); a deny carries neither.
    fn outcome_for(
        &self,
        req: &ApprovalRequest,
        resp: ApprovalResponse,
    ) -> Option<ApprovalOutcome> {
        match resp.decision {
            ProtoDecision::Denied => Some(ApprovalOutcome::local(Decision::Deny)),
            ProtoDecision::Approved => {
                let decision = match &resp.lease {
                    Some(lease) => Decision::Lease(Duration::from_millis(lease.ttl_ms)),
                    None => Decision::Approve,
                };
                if let Some(challenge) = &req.threshold {
                    // A request that opens a threshold-sealed secret: an approve
                    // MUST carry the phone's partial Z_F for this exact id. A
                    // missing/short partial, or one for a different id, fails closed
                    // rather than approving emptily.
                    let (account_id, zf) = resp.partial_zf()?;
                    if account_id != challenge.account_id {
                        return None;
                    }
                    Some(ApprovalOutcome::with_partial(decision, zf))
                } else {
                    // A plain gate: nothing sealed to open, so the approve carries
                    // no partial. The command runs with no injected secret.
                    Some(ApprovalOutcome::local(decision))
                }
            }
        }
    }

    /// Record a phone push registration for this pairing, persisted so it survives
    /// a daemon restart. Re-registration overwrites (token rotation).
    fn record_registration(&self, pr: &PushRegister) {
        self.push_store
            .register(self.pairing_id, &pr.token, &pr.platform, now_ms());
    }

    /// Seal a zero-knowledge [`ResolutionBroadcast`] to THIS device's phone and
    /// deposit it `ToPhone`, so a device that did not resolve a ring-all request
    /// dismisses its pending copy instead of lingering until its own timeout (#36
    /// multi-device). This is the daemon half of the resolution broadcast; the ring
    /// coordinator (see `docs/design/multi-device.md`) calls it on every device
    /// EXCEPT the one that resolved.
    ///
    /// **Additive to the reviewed approval path.** It shares the daemon->phone
    /// [`counter`](Self::counter) and seal, exactly like a request deposit, but
    /// registers no waiter and touches no [`ReplayGuard`], DEK, or `Z_F`. It carries
    /// only `request_id` + `status`, releases nothing, and gates nothing; the worst a
    /// (cryptographically impossible) forged one could do is hide a prompt, which
    /// only ever withholds a release. Best-effort: a seal or transport error is
    /// swallowed because the phone's own request timeout still expires the sheet, so
    /// a lost broadcast degrades to the single-device behavior, never to a release.
    pub fn broadcast_resolution(&self, request_id: &str, status: ResolutionStatus) {
        let msg = ResolutionBroadcast::new(request_id, status);
        let counter = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        let Ok(env) = Envelope::seal(
            &msg,
            self.pairing_id,
            counter,
            &self.identity.signing,
            &self.phone,
        ) else {
            return;
        };
        // Forward the push hint so the device wakes to dismiss promptly; the phone
        // opens the envelope, finds a resolution, and clears the sheet. Content-free
        // doorbell, exactly as a request deposit.
        let _ = self
            .transport
            .deposit_to_phone(self.pairing_id, &env, self.push_hint());
    }

    /// The push doorbell hint to forward to the relay for this pairing: the phone's
    /// registered token and platform, if any. `None` means no token is on file, so
    /// the deposit carries no hint and the phone relies on its poll backstop. The
    /// daemon does not interpret the platform (the relay owns push): it forwards
    /// whatever the phone registered verbatim.
    fn push_hint(&self) -> Option<PushHint> {
        self.push_store.get(self.pairing_id).map(|reg| PushHint {
            token: reg.token,
            platform: reg.platform,
        })
    }

    /// The single ToDaemon owner. Runs for the life of the daemon (until
    /// `shutdown` is set) and is the SOLE reader of the ToDaemon channel, so no two
    /// readers can ever steal each other's messages. It continuously long-polls,
    /// [`classify`](Self::classify)s each envelope through the one shared
    /// [`ReplayGuard`] (touched by this thread alone), and demultiplexes:
    ///
    /// * a [`PushRegister`] -> recorded to the push store (persisted to
    ///   `push.json`), which is how the phone's arm-time token is captured the
    ///   instant it lands, long before any command fires;
    /// * an [`ApprovalResponse`] -> routed to the waiting [`round_trip`] via the
    ///   [`waiters`](Self::waiters) map; a response with no registered waiter is
    ///   stale (its `round_trip` already timed out and removed itself) and dropped,
    ///   exactly as the old inline demux skipped a non-correlating response;
    /// * anything that fails verify/replay/decode -> dropped (fail closed).
    ///
    /// The owner grants nothing and never touches a DEK or `Z_F`; it only records
    /// tokens and forwards sealed responses. Because it is already parked in the
    /// long-poll that will receive an approval's response, an approval adds no
    /// latency of its own and nothing couples an approval to the relay's ~25s hold.
    pub fn run_todaemon_owner(&self, shutdown: &AtomicBool) {
        while !shutdown.load(Ordering::Acquire) {
            match self
                .transport
                .recv(self.pairing_id, Direction::ToDaemon, self.listen_poll)
            {
                Ok(Some(env)) => self.dispatch(env),
                // The poll returned with nothing (an empty long-poll hold elapsed,
                // or the test's short interval lapsed): loop and re-check shutdown.
                Ok(None) => {}
                // A transport fault (the network relay only errors on an exhausted
                // retry budget or a poisoned buffer): back off so a persistent
                // failure does not spin, then retry.
                Err(_) => std::thread::sleep(OWNER_ERROR_BACKOFF),
            }
        }
    }

    /// Classify one owned ToDaemon envelope and route it: registrations to the
    /// push store, responses to their waiter, everything else dropped.
    fn dispatch(&self, env: Envelope) {
        // A failed verify/replay/decode classifies as `None`: fail closed by
        // dropping it (nothing to route).
        if let Some((request_id, msg)) = self.classify(env) {
            self.route(request_id, msg);
        }
    }

    /// Route one already-classified ToDaemon message. Split from [`dispatch`] so
    /// [`verify_and_promote`](Self::verify_and_promote) can route the verifying
    /// envelope it already opened WITHOUT a second [`classify`] (which the shared
    /// replay guard would correctly reject as a replay of the same counter).
    fn route(&self, in_reply_to: Uuid, msg: ToDaemonMessage) {
        match msg {
            ToDaemonMessage::Push(pr) => self.record_registration(&pr),
            ToDaemonMessage::Response(resp) => self.route_response(resp),
            // A delivery receipt only advances the requester's display; it never
            // touches the waiter channel, so it can never be mistaken for a
            // decision. An unknown/late/duplicate receipt is dropped inside
            // `mark_delivered`.
            ToDaemonMessage::Delivered(receipt) => {
                self.mark_delivered(&receipt.request_id, now_ms())
            }
            // Lease control. Neither can release a secret, approve a request, or
            // widen anything: a list reads names and clocks, and a revoke can only
            // ever take a window away. Both name the envelope that asked, so a
            // captured reply cannot be passed off as the answer to a later request.
            ToDaemonMessage::LeaseList(_) => self.answer_lease_list(in_reply_to),
            ToDaemonMessage::LeaseRevoke(revoke) => self.answer_lease_revoke(in_reply_to, &revoke),
        }
    }

    /// Answer a phone's [`LeaseQuery`] with the daemon's live windows.
    ///
    /// Drops the query with NO reply when no lease-control handle is attached or
    /// the pairing is over its rate budget. A list is idempotent, so a dropped one
    /// costs the phone a re-ask and nothing else.
    ///
    /// Every row is built through [`LeaseRow::new`], which sanitizes the three
    /// display fields to the coverage-label allowlist and validates the id. That
    /// filter is load-bearing here and not merely defensive: `covers` is
    /// daemon-rendered and already clean, but `scope` is the RAW rule name out of
    /// `config.json` and `account` the raw source label, and config validation
    /// only rejects duplicates and empty matches. A row whose id would not
    /// validate (impossible from this store, which renders it itself) is dropped
    /// rather than sent unusable.
    ///
    /// `as_of_ms` stamps when the window clocks were read, so the phone counts
    /// down from a known instant and can show the list as stale instead of
    /// presenting an old measurement as current.
    fn answer_lease_list(&self, in_reply_to: Uuid) {
        let Some(control) = self.leases.get() else {
            return;
        };
        if !self.lease_budget_allows() {
            return;
        }
        let rows: Vec<LeaseRow> = control
            .list()
            .into_iter()
            .filter_map(|l| {
                LeaseRow::new(
                    &l.lease_id,
                    &l.scope,
                    &l.covers,
                    &l.account,
                    l.remaining.as_millis() as u64,
                )
            })
            .collect();
        self.queue_lease_reply(&LeaseListReply::new(
            in_reply_to.to_string(),
            now_ms(),
            rows,
        ));
    }

    /// Answer a phone's [`LeaseRevoke`] by killing exactly the named window.
    ///
    /// The target is an opaque [`LeaseRow::lease_id`], never a grant key: a grant
    /// key is deterministic, shared between windows, and a durable correlator, so
    /// it never reaches the phone at all (see [`LeaseRevoke`]). A captured revoke
    /// re-flown after a restart therefore names an id that no longer exists.
    ///
    /// Always replies when the message parses, including `revoked: false`. The
    /// three ways to reach `false` (already lapsed, already revoked, id names
    /// nothing) are indistinguishable, so the reply is not an oracle for what this
    /// daemon holds. A message whose target does not parse gets no reply at all,
    /// so peer-chosen bytes are never echoed back onto a screen.
    fn answer_lease_revoke(&self, in_reply_to: Uuid, revoke: &LeaseRevoke) {
        let Some(control) = self.leases.get() else {
            return;
        };
        let Some(lease_id) = revoke.target() else {
            return;
        };
        if !self.lease_budget_allows() {
            return;
        }
        let revoked = control.revoke_id(&lease_id);
        self.queue_lease_reply(&LeaseRevokeReply::new(
            in_reply_to.to_string(),
            lease_id,
            revoked,
        ));
    }

    /// Whether this pairing's lease-control budget allows handling one more
    /// message, spending a token if so.
    ///
    /// A token bucket rather than a bare minimum interval, and the shape is
    /// deliberate. The review asked for 1/s; a flat 1/s would also drop the second
    /// of two revokes a human taps in quick succession, which is precisely the
    /// silent failure this feature exists to end. So the sustained rate is
    /// [`LEASE_REFILL_MS`] (1/s) and a burst of [`LEASE_BURST`] is allowed on top,
    /// which a human can exhaust only by tapping faster than they can read.
    ///
    /// Over-budget messages are dropped silently, with no reply. For a list that
    /// costs a re-ask. For a revoke it means the phone shows the row as
    /// unconfirmed, which is the honest state: the daemon did not act.
    fn lease_budget_allows(&self) -> bool {
        let now = now_ms();
        let mut budget = self.lease_budget.lock().expect("lease budget poisoned");
        let refilled = now.saturating_sub(budget.refilled_at_ms) / LEASE_REFILL_MS;
        if refilled > 0 {
            budget.tokens = (budget.tokens + refilled).min(LEASE_BURST);
            budget.refilled_at_ms = now;
        }
        if budget.tokens == 0 {
            return false;
        }
        budget.tokens -= 1;
        true
    }

    /// Seal one lease-control reply and hand it to the reply pump.
    ///
    /// **It is queued, not deposited here.** This runs on the ToDaemon owner
    /// thread, which is the sole reader of the channel an approval RESPONSE
    /// arrives on. A synchronous deposit would park that reader for a network
    /// round trip (and spend the transport's retry budget) while a human's
    /// approval sat in the mailbox. So a lease reply never blocks, never delays,
    /// and never competes with an approval: it goes on a small bounded queue that
    /// a separate pump drains, and when that queue is full the reply is DROPPED.
    ///
    /// Dropping is the right failure. A lost list costs a re-ask; a lost revoke
    /// reply leaves the phone showing "unconfirmed", which is exactly true. The
    /// alternative -- an unbounded queue -- would let lease traffic grow the daemon
    /// and still not deliver anything useful.
    ///
    /// The seal shares the daemon->phone [`counter`](Self::counter) with every
    /// other deposit, and the payload was padded to
    /// [`LEASE_PAD_BUCKET`](sigil_proto::LEASE_PAD_BUCKET) before sealing.
    ///
    /// **What that does and does not buy, stated exactly**, because an earlier
    /// version of this comment claimed a relay "learns nothing about which of the
    /// daemon's messages it is", which was false on length:
    ///
    /// * It buys equal lengths WITHIN a bucket. A list of zero windows and a list
    ///   of five seal to one length, and a revoke reply is that same length, so a
    ///   relay cannot count open windows or tell the four messages apart by size.
    /// * It does not buy equal lengths across buckets. A reply that outgrows one
    ///   rolls to the next, so the relay learns which BAND the open-window count
    ///   falls in (first crossing: 8 rows with short labels, 6 with realistic
    ///   ones, 3 with all labels at the length bound). Never the count itself, and
    ///   never anything about which rules. Padding every list to a fixed maximum
    ///   would close that at a real cost in bytes on every exchange, and is
    ///   deliberately not done.
    /// * It does not buy anything about TIMING. A lease-control exchange is
    ///   visible as an exchange, and the relay learns that lease control was used
    ///   and when.
    ///
    /// No push hint is forwarded: a lease reply answers a screen the human is
    /// already looking at, and ringing the APNs doorbell for it would correlate
    /// lease-control use to the relay and to Apple for no benefit.
    fn queue_lease_reply<T: serde::Serialize>(&self, msg: &T) {
        let counter = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        let Ok(env) = Envelope::seal(
            msg,
            self.pairing_id,
            counter,
            &self.identity.signing,
            &self.phone,
        ) else {
            return;
        };
        // try_send, never send: a full queue drops rather than blocking the owner.
        let _ = self.lease_replies.0.try_send(env);
    }

    /// Drain queued lease-control replies to the phone until `shutdown` is set.
    ///
    /// Runs on its own thread so a deposit here can never park the ToDaemon owner
    /// (see [`queue_lease_reply`](Self::queue_lease_reply)). Transport errors are
    /// swallowed exactly as [`broadcast_resolution`](Self::broadcast_resolution)
    /// swallows them: the phone's own re-list is the recovery, and a lease reply
    /// must never escalate into anything that could disturb an approval.
    ///
    /// A no-op that returns immediately when no lease-control handle was ever
    /// attached, so the daemon can spawn it unconditionally.
    pub fn run_lease_reply_pump(&self, shutdown: &AtomicBool) {
        if self.leases.get().is_none() {
            return;
        }
        while !shutdown.load(Ordering::Acquire) {
            match self
                .lease_replies
                .1
                .lock()
                .expect("lease reply queue poisoned")
                .recv_timeout(LEASE_PUMP_TICK)
            {
                Ok(env) => {
                    let _ = self.transport.deposit_to_phone(self.pairing_id, &env, None);
                }
                // Nothing queued this tick: loop and re-check shutdown.
                Err(RecvTimeoutError::Timeout) => {}
                // Every sender is gone (impossible while `self` lives): stop.
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    }

    /// Verify a freshly dialled/accepted direct [`DirectLink`] is THIS device's
    /// pinned phone and, if so, promote it to the [`FallbackTransport`] primary and
    /// route its first envelope. Returns whether the link was promoted (#51).
    ///
    /// This is the ONLY place a direct link becomes a trusted primary, and it slots
    /// into the per-device owner model without adding a second channel reader:
    ///
    /// * It reads exactly one envelope off the RAW `link` (not the owner's
    ///   transport), through the approver's OWN pinned key + agreement key + the
    ///   SAME shared [`ReplayGuard`] (via [`classify`](Self::classify)). So there is
    ///   still exactly one guard, honoring the phone's single monotonic outbound
    ///   counter across both the relay and this link; a host that dialled in but
    ///   does not hold the phone's key cannot produce an envelope that opens, and is
    ///   never installed (fail closed on `NotPinnedPeer`, timeout, or link error).
    /// * On success it installs the link as the primary FIRST, so the owner loop's
    ///   next `recv` (the sole reader of the installed transport) reads the link,
    ///   THEN routes the verifying message. The one verifying envelope is consumed
    ///   here and routed via [`route`](Self::route) without re-opening; every later
    ///   frame on the link is read only by the owner. Thus the single-reader
    ///   invariant holds: the acceptor never reads the installed transport, and the
    ///   verify read is a one-shot handoff sequenced strictly before install.
    ///
    /// A no-op returning `false` when direct is disabled (`self.direct` is `None`),
    /// so an acceptor wired by mistake could still never promote anything.
    pub fn verify_and_promote(&self, link: Arc<DirectLink>) -> bool {
        let Some(direct) = self.direct.clone() else {
            return false;
        };
        // Open + replay-check + classify the opener exactly once, through the
        // shared guard, and stash the result to route after install. The predicate
        // returns true iff the envelope opened as our pinned peer.
        let mut opener: Option<(Uuid, ToDaemonMessage)> = None;
        let verified = discovery::verify_link(
            link.as_ref(),
            Direction::ToDaemon,
            self.verify_timeout,
            |env| match self.classify(env.clone()) {
                Some(msg) => {
                    opener = Some(msg);
                    true
                }
                None => false,
            },
        );
        match verified {
            Ok(_) => {
                // Install BEFORE routing so the owner's next recv reads the link.
                direct.install_primary(link);
                if let Some((request_id, msg)) = opener {
                    self.route(request_id, msg);
                }
                true
            }
            // Not the pinned peer, a timeout, or a link error: fail closed, never
            // install. The relay path is untouched.
            Err(VerifyError::NotPinnedPeer | VerifyError::Timeout | VerifyError::Link(_)) => false,
        }
    }

    /// Run a rung-2 direct acceptor for this device until `shutdown` is set: poll
    /// `listener` for a phone dial and hand each accepted link to
    /// [`verify_and_promote`](Self::verify_and_promote). The listener is put in
    /// non-blocking mode so the poll can observe `shutdown` promptly; the relay
    /// serves throughout, so nothing here ever gates or delays an approval. An
    /// accept error is logged and backed off, never fatal (the daemon keeps serving
    /// from the relay). A no-op that returns immediately if direct is disabled, so
    /// this can be spawned unconditionally.
    pub fn run_direct_acceptor(&self, listener: &DirectListener, shutdown: &AtomicBool) {
        if self.direct.is_none() {
            return;
        }
        if listener.set_nonblocking(true).is_err() {
            return; // cannot poll safely: decline to accept, relay still serves
        }
        while !shutdown.load(Ordering::Acquire) {
            match listener.accept_nonblocking() {
                Ok(Some(link)) => {
                    // Verify + promote (or drop). A rogue LAN host that dials and
                    // sends bytes that do not open as the pinned peer is rejected
                    // here and never installed.
                    self.verify_and_promote(link);
                }
                // No dial pending: nap and re-check shutdown.
                Ok(None) => std::thread::sleep(DIRECT_ACCEPT_POLL),
                // Transient accept fault: back off, keep serving from the relay.
                Err(_) => std::thread::sleep(OWNER_ERROR_BACKOFF),
            }
        }
    }

    /// Hand a verified response to its waiting [`round_trip`], if one is
    /// registered. No waiter means the approval already timed out and removed
    /// itself, so the response is stale and dropped. The channel is unbounded, so
    /// the send never blocks; a dropped receiver (the waiter just left) makes it a
    /// no-op.
    fn route_response(&self, resp: ApprovalResponse) {
        let waiters = self.waiters.lock().expect("remote waiters poisoned");
        if let Some(entry) = waiters.get(&resp.request_id) {
            let _ = entry.tx.send(resp);
        }
    }

    /// Shrink the owner poll interval so a test's idle owner joins quickly instead
    /// of waiting the full [`OWNER_POLL_INTERVAL`].
    #[cfg(test)]
    pub(crate) fn with_listen_poll(mut self, interval: Duration) -> Self {
        self.listen_poll = interval;
        self
    }

    /// Shrink the demote-on-silence window so a test does not wait the full
    /// [`DIRECT_DEMOTE_AFTER`].
    #[cfg(test)]
    pub(crate) fn with_demote_after(mut self, after: Duration) -> Self {
        self.demote_after = after;
        self
    }

    /// Shrink the verification read window so a test does not wait the full
    /// [`DIRECT_VERIFY_TIMEOUT`].
    #[cfg(test)]
    pub(crate) fn with_verify_timeout(mut self, timeout: Duration) -> Self {
        self.verify_timeout = timeout;
        self
    }
}

/// The non-secret mDNS `hint` a rung-1 advertisement carries for THIS daemon
/// identity (#51). It is a salted, truncated hash of the daemon's PUBLIC identity
/// (Ed25519 verifying key + X25519 agreement key), which the paired phone -- which
/// pins that identity -- recomputes to pick the right host among several on the
/// LAN before dialling. It grants nothing and is never trusted: a wrong hint only
/// wastes a dial that then fails [`RemoteApprover::verify_and_promote`] and falls
/// back to the relay. It is deliberately NOT the mailbox id (broadcasting that
/// would advertise the pairing's routing address on the LAN).
///
/// Kept here, not in `sigil-direct`, because the discovery crate holds no identity
/// or crypto types by design; the daemon (which has the pinned key + `blake2`)
/// computes the hint and hands it to a [`sigil_direct::discovery::ServiceRecord`].
pub fn direct_service_hint(daemon: &PeerIdentity) -> String {
    use blake2::digest::consts::U8;
    use blake2::{Blake2b, Digest};
    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"sigil.direct.hint.v1");
    hasher.update(daemon.verifying);
    hasher.update(daemon.agreement);
    let out = hasher.finalize();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

/// Lets the daemon share one [`RemoteApprover`] between the approval gate (which
/// needs a `Box<dyn Approver>`) and the ToDaemon owner loop (which needs a live
/// handle) by holding it in an [`Arc`] and cloning. The forwarding dereferences to
/// the inner approver rather than recursing.
impl Approver for Arc<RemoteApprover> {
    fn decide(&self, ctx: &ApprovalContext) -> ApprovalOutcome {
        (**self).decide(ctx)
    }
}

impl Approver for RemoteApprover {
    fn decide(&self, ctx: &ApprovalContext) -> ApprovalOutcome {
        self.round_trip(ctx)
            .unwrap_or_else(|| ApprovalOutcome::local(Decision::Deny))
    }
}

/// A one-shot cancel signal the ring coordinator fires the instant a winning
/// device is seen, so the N-1 losing devices stop waiting promptly instead of
/// sitting out the full timeout. It is a plain shared boolean; the single-device
/// [`RemoteApprover::round_trip`] never touches one, so that reviewed wait shape
/// is unchanged. Only [`RemoteApprover::round_trip_cancellable`] observes it.
#[derive(Clone, Default)]
struct CancelToken {
    flag: Arc<AtomicBool>,
}

impl CancelToken {
    fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Fire the signal: every device's cancellable wait returns `None` within one
    /// tick. Idempotent.
    fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

/// The ring-all / first-wins coordinator over N paired phones (#36 multi-device).
///
/// It is a thin COMPOSITION over N unchanged [`RemoteApprover`]s (one per device),
/// not a rewrite of the reviewed single-device core. Because each device is a full,
/// untouched approver, every reviewed guarantee is preserved for free:
///
/// - **Per-device replay.** Each [`RemoteApprover`] owns its own [`ReplayGuard`],
///   its own monotonic counter, and its own pinned phone key. No guard is ever
///   shared across devices, so one device's phone counters never touch another's.
/// - **No wrong-device response resolves.** A response is verified inside the
///   approver whose pinned `phone` key sealed it; another device's response fails
///   signature verification there and is dropped, never routed here.
/// - **One reader per device slot.** Each device keeps its single ToDaemon owner
///   loop ([`serve`](crate::daemon) spawns one per device), the sole reader of
///   that device's mailbox.
///
/// [`decide`](Self::decide) rings every device, waits for the FIRST real decision
/// (approve OR deny) to win, cancels the losers, dismisses them with a
/// zero-knowledge [`ResolutionBroadcast`], and returns the winner's outcome. If
/// every device times out, it denies (fail closed). Exactly one outcome reaches
/// the gate per `decide`.
pub struct RingApprover {
    /// One approver per paired phone, each an UNCHANGED single-device
    /// [`RemoteApprover`]. Held in `Arc`s so [`serve`](crate::daemon) can also run
    /// each device's ToDaemon owner loop against the same instance.
    devices: Vec<Arc<RemoteApprover>>,
}

impl RingApprover {
    /// Compose a ring over `devices` (one per paired phone). The caller builds a
    /// ring only for N >= 2; a single device is driven as a bare
    /// [`RemoteApprover`] so N == 1 stays byte-identical to the reviewed path.
    pub fn new(devices: Vec<Arc<RemoteApprover>>) -> Self {
        Self { devices }
    }

    /// The composed devices, for the caller that also spawns their owner loops.
    pub fn devices(&self) -> &[Arc<RemoteApprover>] {
        &self.devices
    }
}

impl Approver for RingApprover {
    fn decide(&self, ctx: &ApprovalContext) -> ApprovalOutcome {
        match self.devices.len() {
            // No devices: fail closed. Should not happen (the caller builds a ring
            // only for N >= 2), but deny defensively rather than release.
            0 => return ApprovalOutcome::local(Decision::Deny),
            // Exactly one device: drive it through the unchanged single-device
            // path, so a degenerate one-element ring is still byte-identical.
            1 => return self.devices[0].decide(ctx),
            _ => {}
        }

        let cancel = CancelToken::new();
        // The single committed outcome, plus the index of the device that won (so
        // the OTHER devices get the dismissal). The mutex serializes the race: the
        // first device to record a real decision wins and cancels the rest; a
        // second device that also returned a decision finds the slot taken and
        // DISCARDS its outcome, so exactly one outcome ever reaches the gate and
        // there is no double release.
        let winner: Mutex<Option<(usize, ApprovalOutcome)>> = Mutex::new(None);

        // Scoped threads so each device's round trip can borrow `ctx`, `cancel`,
        // and `winner`; the scope JOINS all N before returning, so no loser thread
        // outlives `decide` (the `ctx: &` lifetime requires it) and every waiter is
        // removed before we broadcast.
        std::thread::scope(|scope| {
            for (i, dev) in self.devices.iter().enumerate() {
                let cancel = &cancel;
                let winner = &winner;
                scope.spawn(move || {
                    // A real decision (approve or explicit deny). `None` is a
                    // timeout / cancel / dead owner and contributes nothing.
                    if let Some(outcome) = dev.round_trip_cancellable(ctx, cancel) {
                        let mut w = winner.lock().expect("ring winner poisoned");
                        if w.is_none() {
                            *w = Some((i, outcome));
                            // Wake the losers the instant the winner is committed.
                            cancel.cancel();
                        }
                        // else: we lost the race; drop our outcome (no release).
                    }
                });
            }
        });

        // All device threads have joined; the winner slot is final.
        match winner.into_inner().expect("ring winner poisoned") {
            Some((idx, outcome)) => {
                // Dismiss every OTHER device with a zero-knowledge `Settled`
                // broadcast, sent only AFTER the winner's outcome is committed
                // (never racing a real approve). Best-effort: a lost broadcast
                // degrades to that phone's own timeout, never to a release.
                for (i, dev) in self.devices.iter().enumerate() {
                    if i != idx {
                        dev.broadcast_resolution(&ctx.id, ResolutionStatus::Settled);
                    }
                }
                outcome
            }
            // Every device timed out (or died): deny. Fail closed, identical to the
            // single-device timeout. No broadcast: each phone expires on its own.
            None => ApprovalOutcome::local(Decision::Deny),
        }
    }
}

/// Best-effort machine name for the approval screen. Reads `$HOST`/`$HOSTNAME`,
/// falling back to a constant so the field is never empty.
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "this-mac".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approve::ApprovalContext;
    use sigil_proto::{LeasePolicy, RequestKind, SecretRef};

    #[test]
    fn build_request_is_provider_blind() {
        // The approver copies the provider-prepared fields verbatim; it contains
        // no op-specific parsing.
        let transport = std::sync::Arc::new(sigil_proto::LocalRelay::new());
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate().peer_identity();
        let approver = RemoteApprover::new(transport, daemon, phone);

        let ctx = ApprovalContext {
            id: "req-1".into(),
            account: "Rowm".into(),
            scope: "read op://Engineering/.env/password".into(),
            grant_hex: "dead".into(),
            provenance: "zsh \u{2192} op".into(),
            cwd: "/p".into(),
            command: vec![
                "op".into(),
                "read".into(),
                "op://Engineering/.env/password".into(),
            ],
            secret_refs: vec![SecretRef {
                provider: "1password".into(),
                reference: "op://Engineering/.env/password".into(),
                segments: vec!["Engineering".into(), ".env".into(), "password".into()],
                label: ".env".into(),
            }],
            kind: RequestKind::SecretRead,
            lease: LeasePolicy::leasable(900),
            ssh: None,
            threshold: None,
        };
        let req = approver.build_request(&ctx);
        assert_eq!(req.request_id, "req-1");
        assert_eq!(req.kind, RequestKind::SecretRead);
        assert_eq!(
            req.lease_policy,
            LeasePolicy::leasable(900),
            "lease policy is threaded from the context"
        );
        assert_eq!(req.command, ctx.command);
        assert_eq!(req.secrets, ctx.secret_refs);
        assert_eq!(req.provenance.process_chain, vec!["zsh", "op"]);
    }

    use sigil_proto::LocalRelay;

    /// Clone a device identity for a test (the approver takes ownership of one
    /// copy while the test keeps another to act as the phone's peer).
    fn clone_id(id: &DeviceIdentity) -> DeviceIdentity {
        DeviceIdentity {
            signing: id.signing.clone(),
            agreement: id.agreement.clone(),
        }
    }

    fn secret_ctx(id: &str) -> ApprovalContext {
        // A request that opens a threshold-sealed secret keyed "Rowm": the phone's
        // approve must carry a partial Z_F for that exact id. Tests use distinct
        // Z_F bytes as a per-request discriminator (they used to use distinct DEKs).
        ApprovalContext {
            id: id.into(),
            account: "Rowm".into(),
            scope: "read op://Engineering/.env/password".into(),
            grant_hex: "dead".into(),
            provenance: "op".into(),
            cwd: "/p".into(),
            command: vec!["op".into(), "read".into()],
            secret_refs: vec![],
            kind: RequestKind::SecretRead,
            lease: LeasePolicy::RunOnce,
            ssh: None,
            threshold: Some(sigil_proto::ThresholdChallenge {
                account_id: "Rowm".into(),
                label: "Rowm".into(),
                ephemeral_pub: "BAQE".into(),
                se_key_id: "se-key-1".into(),
                ecdh_algo: "raw-x".into(),
            }),
        }
    }

    /// Spawn the ToDaemon owner on its own thread with a short poll so the test's
    /// idle owner joins quickly. Returns the shutdown flag and the join handle.
    fn spawn_owner(
        approver: Arc<RemoteApprover>,
    ) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = {
            let approver = approver.clone();
            let shutdown = shutdown.clone();
            std::thread::spawn(move || approver.run_todaemon_owner(&shutdown))
        };
        (shutdown, handle)
    }

    /// The fix: a PushRegister the phone deposits while the daemon is idle (NO
    /// approval in flight) is caught by the ToDaemon owner and lands in the push
    /// store on its own. This is the arm-time path that used to be lost when the
    /// relay dropped the deposit before any command fired.
    #[test]
    fn the_owner_captures_an_arm_time_registration() {
        let relay = LocalRelay::new();
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate();
        let mailbox = mailbox_id(&daemon.peer_identity(), &phone.peer_identity());

        let store = Arc::new(PushStore::ephemeral());
        let approver = Arc::new(
            RemoteApprover::new(
                Arc::new(relay.clone()),
                clone_id(&daemon),
                phone.peer_identity(),
            )
            .with_push(store.clone())
            .with_listen_poll(Duration::from_millis(20)),
        );

        // Start the owner; nothing is armed yet.
        let (shutdown, owner) = spawn_owner(approver);

        // The phone arms: it deposits its push token with no approval outstanding.
        let pr = PushRegister::new("d00dfeed", "apns");
        let pr_env =
            Envelope::seal(&pr, mailbox, 1, &phone.signing, &daemon.peer_identity()).unwrap();
        relay.send(mailbox, Direction::ToDaemon, &pr_env).unwrap();

        // The owner records it without any round trip ever running.
        let mut tries = 0;
        let reg = loop {
            if let Some(reg) = store.get(mailbox) {
                break reg;
            }
            tries += 1;
            assert!(tries < 200, "the owner never captured the registration");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(reg.token, "d00dfeed");
        assert_eq!(reg.platform, "apns");

        shutdown.store(true, Ordering::SeqCst);
        owner.join().unwrap();
    }

    /// The correctness constraint: with the owner running, an approval receives
    /// its OWN response. The owner routes the sealed ApprovalResponse to the
    /// registered waiter rather than swallowing it (which would deny a legitimate
    /// approval). A registration deposited on the same channel is also recorded, so
    /// this covers the old "interleaved registration does not break approval" case
    /// under the new single-reader structure.
    #[test]
    fn an_approval_receives_its_own_response_via_the_owner() {
        let relay = LocalRelay::new();
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate();
        let phone_pub = phone.peer_identity();
        let mailbox = mailbox_id(&daemon.peer_identity(), &phone_pub);

        let store = Arc::new(PushStore::ephemeral());
        let approver = Arc::new(
            RemoteApprover::new(Arc::new(relay.clone()), clone_id(&daemon), phone_pub)
                .with_push(store.clone())
                .with_timeout(Duration::from_secs(2))
                .with_listen_poll(Duration::from_millis(20)),
        );

        let (shutdown, owner) = spawn_owner(approver.clone());

        // The phone registers its token first (counter 1), then waits for the
        // request and approves it (counter 2). Counters strictly advance across the
        // one ToDaemon replay guard.
        let pr = PushRegister::new("cafef00d", "apns");
        let pr_env =
            Envelope::seal(&pr, mailbox, 1, &phone.signing, &daemon.peer_identity()).unwrap();
        relay.send(mailbox, Direction::ToDaemon, &pr_env).unwrap();

        let phone_thread = {
            let relay = relay.clone();
            let daemon_pub = daemon.peer_identity();
            std::thread::spawn(move || {
                let _req = relay
                    .recv(mailbox, Direction::ToPhone, Duration::from_secs(2))
                    .unwrap()
                    .expect("the daemon sent a request");
                let resp = ApprovalResponse::approve_v2("req-live", "Rowm", &[9u8; 32], 1);
                let env = Envelope::seal(&resp, mailbox, 2, &phone.signing, &daemon_pub).unwrap();
                relay.send(mailbox, Direction::ToDaemon, &env).unwrap();
            })
        };

        let outcome = approver.decide(&secret_ctx("req-live"));
        phone_thread.join().unwrap();
        shutdown.store(true, Ordering::SeqCst);
        owner.join().unwrap();

        assert!(
            outcome.decision.is_grant(),
            "the approval must succeed; the owner must route its response to it"
        );
        assert_eq!(
            outcome.zf.as_deref().map(|z| &z[..]),
            Some(&[9u8; 32][..]),
            "the delivered DEK reaches the gate"
        );
        // The interleaved registration was still recorded off the same channel.
        let reg = store.get(mailbox).expect("the registration was stored");
        assert_eq!(reg.token, "cafef00d");
    }

    /// The demux under concurrency: two approvals with DIFFERENT request ids run at
    /// once and the single owner routes each phone response to the right waiter.
    /// Distinct DEKs prove there is no cross-delivery.
    #[test]
    fn two_concurrent_approvals_each_receive_their_own_response() {
        let relay = LocalRelay::new();
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate();
        let phone_pub = phone.peer_identity();
        let mailbox = mailbox_id(&daemon.peer_identity(), &phone_pub);

        let approver = Arc::new(
            RemoteApprover::new(Arc::new(relay.clone()), clone_id(&daemon), phone_pub)
                .with_timeout(Duration::from_secs(2))
                .with_listen_poll(Duration::from_millis(20)),
        );

        let (shutdown, owner) = spawn_owner(approver.clone());

        // The phone: wait for BOTH requests, then answer each by id with strictly
        // increasing counters (the ToDaemon replay guard is monotonic). It knows
        // both ids because the test fixes them; it need not open the requests.
        let phone_thread = {
            let relay = relay.clone();
            let daemon_pub = daemon.peer_identity();
            std::thread::spawn(move || {
                for _ in 0..2 {
                    relay
                        .recv(mailbox, Direction::ToPhone, Duration::from_secs(2))
                        .unwrap()
                        .expect("a request was deposited");
                }
                let resp_a = ApprovalResponse::approve_v2("req-A", "Rowm", &[1u8; 32], 1);
                let env_a =
                    Envelope::seal(&resp_a, mailbox, 1, &phone.signing, &daemon_pub).unwrap();
                relay.send(mailbox, Direction::ToDaemon, &env_a).unwrap();
                let resp_b = ApprovalResponse::approve_v2("req-B", "Rowm", &[2u8; 32], 1);
                let env_b =
                    Envelope::seal(&resp_b, mailbox, 2, &phone.signing, &daemon_pub).unwrap();
                relay.send(mailbox, Direction::ToDaemon, &env_b).unwrap();
            })
        };

        let a1 = approver.clone();
        let t1 = std::thread::spawn(move || a1.decide(&secret_ctx("req-A")));
        let a2 = approver.clone();
        let t2 = std::thread::spawn(move || a2.decide(&secret_ctx("req-B")));
        let out_a = t1.join().unwrap();
        let out_b = t2.join().unwrap();
        phone_thread.join().unwrap();
        shutdown.store(true, Ordering::SeqCst);
        owner.join().unwrap();

        assert!(out_a.decision.is_grant() && out_b.decision.is_grant());
        // Each waiter received exactly its own DEK: no cross-routing.
        assert_eq!(
            out_a.zf.as_deref().map(|z| &z[..]),
            Some(&[1u8; 32][..]),
            "req-A got its own DEK"
        );
        assert_eq!(
            out_b.zf.as_deref().map(|z| &z[..]),
            Some(&[2u8; 32][..]),
            "req-B got its own DEK"
        );
    }

    /// The daemon half of the #36 resolution broadcast: `broadcast_resolution`
    /// seals a zero-knowledge `ResolutionBroadcast` to the pinned phone and deposits
    /// it ToPhone, where the phone opens it (verifying signature + replay) and its
    /// demux classifies it as a `Resolution`, never a request or a decision. It
    /// carries only the request id and status, and rides the same monotonic
    /// daemon->phone counter as a request, so it passes the phone's replay guard once
    /// and cannot be replayed.
    #[test]
    fn broadcast_resolution_deposits_a_sealed_dismissal_the_phone_can_open() {
        use sigil_proto::{ReplayGuard, ToPhoneMessage};

        let relay = LocalRelay::new();
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate();
        let phone_pub = phone.peer_identity();
        let mailbox = mailbox_id(&daemon.peer_identity(), &phone_pub);
        let approver = RemoteApprover::new(Arc::new(relay.clone()), clone_id(&daemon), phone_pub);

        approver.broadcast_resolution("req-RING", ResolutionStatus::Settled);

        // The phone reads its ToPhone mailbox and opens the sealed broadcast.
        let env = relay
            .recv(mailbox, Direction::ToPhone, Duration::from_millis(50))
            .unwrap()
            .expect("a resolution was deposited toward the phone");
        let mut guard = ReplayGuard::new();
        let value: serde_json::Value = env
            .open(&daemon.peer_identity(), &phone.agreement, &mut guard)
            .expect("the phone opens the daemon-signed broadcast");
        match ToPhoneMessage::from_value(value).expect("classifies") {
            ToPhoneMessage::Resolution(rb) => {
                assert_eq!(rb.request_id, "req-RING");
                assert_eq!(rb.status, ResolutionStatus::Settled);
            }
            other => panic!("a broadcast must classify as a Resolution, got {other:?}"),
        }

        // A replay of the exact bytes is rejected by the phone's guard: a relay
        // cannot re-dismiss (or suppress a later prompt) by resending it.
        assert!(env
            .open::<serde_json::Value>(&daemon.peer_identity(), &phone.agreement, &mut guard)
            .is_err());
    }

    /// A delivery receipt advances the in-flight entry's `delivered_at_ms` and is
    /// visible on `pending_snapshot`, is idempotent (a duplicate does not move the
    /// timestamp), drops an unknown/late receipt silently, and NEVER resolves the
    /// approval (the waiter channel stays empty). This is the display-only,
    /// fail-closed contract the Mac's Sent -> Delivered readout relies on.
    #[test]
    fn a_delivery_receipt_marks_delivered_without_resolving_the_approval() {
        let transport = Arc::new(LocalRelay::new());
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate().peer_identity();
        let approver = RemoteApprover::new(transport, daemon, phone);

        let req = approver.build_request(&secret_ctx("req-D"));
        // Register an in-flight waiter as `round_trip` would, before any receipt.
        let rx = approver.register_waiter(&req);
        assert_eq!(approver.pending_snapshot().len(), 1);
        assert!(
            approver.pending_snapshot()[0].delivered_at_ms.is_none(),
            "a fresh request is not yet delivered"
        );

        // The receipt lands: the entry flips to delivered at this instant.
        approver.mark_delivered("req-D", 111);
        let snap = approver.pending_snapshot();
        assert_eq!(snap[0].delivered_at_ms, Some(111));

        // Idempotent: a duplicate receipt does not move the timestamp.
        approver.mark_delivered("req-D", 222);
        assert_eq!(approver.pending_snapshot()[0].delivered_at_ms, Some(111));

        // Unknown/late receipt: a no-op, no panic, no new entry.
        approver.mark_delivered("req-unknown", 333);
        assert_eq!(approver.pending_snapshot().len(), 1);

        // The receipt NEVER resolves the approval: the waiter channel is still
        // empty, so the gate keeps waiting for a real sealed decision.
        assert!(
            matches!(rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
            "a delivery receipt must not deliver a decision to the waiter"
        );

        // Once the round trip completes, the entry (and its delivery state) is gone.
        approver.remove_waiter("req-D");
        assert!(approver.pending_snapshot().is_empty());
    }

    /// The owner loop, reading the real ToDaemon channel, routes a sealed delivery
    /// receipt to the delivery state through the SAME replay guard as every other
    /// inbound message, and does so without disturbing the concurrent approval it is
    /// also demultiplexing. A replayed receipt is rejected by the guard (its request
    /// id is single-use), so it cannot re-touch state.
    #[test]
    fn the_owner_routes_a_sealed_delivery_receipt_over_the_channel() {
        use sigil_proto::DeliveryReceipt;

        let relay = LocalRelay::new();
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate();
        let phone_pub = phone.peer_identity();
        let mailbox = mailbox_id(&daemon.peer_identity(), &phone_pub);

        let approver = Arc::new(
            RemoteApprover::new(Arc::new(relay.clone()), clone_id(&daemon), phone_pub)
                .with_timeout(Duration::from_secs(2))
                .with_listen_poll(Duration::from_millis(20)),
        );
        let (shutdown, owner) = spawn_owner(approver.clone());

        // The phone: wait for the request, seal a delivery receipt (counter 1), then
        // approve (counter 2). Both ride the one monotonic ToDaemon counter/guard.
        let phone_thread = {
            let relay = relay.clone();
            let daemon_pub = daemon.peer_identity();
            std::thread::spawn(move || {
                relay
                    .recv(mailbox, Direction::ToPhone, Duration::from_secs(2))
                    .unwrap()
                    .expect("the daemon sent a request");
                let receipt = DeliveryReceipt::new("req-live");
                let env =
                    Envelope::seal(&receipt, mailbox, 1, &phone.signing, &daemon_pub).unwrap();
                relay.send(mailbox, Direction::ToDaemon, &env).unwrap();
                // Give the owner a moment to process the receipt before approving.
                std::thread::sleep(Duration::from_millis(60));
                let resp = ApprovalResponse::approve_v2("req-live", "Rowm", &[8u8; 32], 1);
                let env = Envelope::seal(&resp, mailbox, 2, &phone.signing, &daemon_pub).unwrap();
                relay.send(mailbox, Direction::ToDaemon, &env).unwrap();
            })
        };

        let outcome = approver.decide(&secret_ctx("req-live"));
        phone_thread.join().unwrap();
        shutdown.store(true, Ordering::SeqCst);
        owner.join().unwrap();

        // The approval still succeeded with its own DEK: the receipt did not steal
        // or short-circuit the decision.
        assert!(outcome.decision.is_grant());
        assert_eq!(outcome.zf.as_deref().map(|z| &z[..]), Some(&[8u8; 32][..]));
    }

    // --- #36 ring-all / first-wins coordinator --------------------------------

    use sigil_proto::ToPhoneMessage;

    /// One device in a test ring: its (unchanged) approver plus the phone-side
    /// keys and mailbox a test uses to answer or to inspect a dismissal.
    struct RingDevice {
        approver: Arc<RemoteApprover>,
        phone: DeviceIdentity,
        daemon_pub: PeerIdentity,
        mailbox: [u8; 32],
    }

    /// Build a ring of `n` independent devices over one shared `LocalRelay`. Each
    /// device is a full, unchanged [`RemoteApprover`] with its OWN daemon identity,
    /// pinned phone, and mailbox, matching the composition design.
    fn build_ring(relay: &LocalRelay, n: usize, timeout: Duration) -> Vec<RingDevice> {
        (0..n)
            .map(|_| {
                let daemon = DeviceIdentity::generate();
                let phone = DeviceIdentity::generate();
                let phone_pub = phone.peer_identity();
                let daemon_pub = daemon.peer_identity();
                let mailbox = mailbox_id(&daemon_pub, &phone_pub);
                let approver = Arc::new(
                    RemoteApprover::new(Arc::new(relay.clone()), daemon, phone_pub)
                        .with_timeout(timeout)
                        .with_listen_poll(Duration::from_millis(20)),
                );
                RingDevice {
                    approver,
                    phone,
                    daemon_pub,
                    mailbox,
                }
            })
            .collect()
    }

    /// Spawn every device's ToDaemon owner loop; return the shared shutdown flag
    /// and the join handles.
    fn spawn_ring_owners(
        devices: &[RingDevice],
    ) -> (Arc<AtomicBool>, Vec<std::thread::JoinHandle<()>>) {
        let shutdown = Arc::new(AtomicBool::new(false));
        let handles = devices
            .iter()
            .map(|d| {
                let approver = d.approver.clone();
                let stop = shutdown.clone();
                std::thread::spawn(move || approver.run_todaemon_owner(&stop))
            })
            .collect();
        (shutdown, handles)
    }

    /// Drain up to a few ToPhone deposits from a loser's mailbox and return the
    /// first that classifies as a resolution dismissal, if any.
    fn drain_resolution(dev: &RingDevice, relay: &LocalRelay) -> Option<ResolutionStatus> {
        let mut guard = ReplayGuard::new();
        for _ in 0..4 {
            match relay.recv(dev.mailbox, Direction::ToPhone, Duration::from_millis(200)) {
                Ok(Some(env)) => {
                    if let Ok(value) = env.open::<serde_json::Value>(
                        &dev.daemon_pub,
                        &dev.phone.agreement,
                        &mut guard,
                    ) {
                        if let Ok(ToPhoneMessage::Resolution(rb)) =
                            ToPhoneMessage::from_value(value)
                        {
                            return Some(rb.status);
                        }
                    }
                }
                _ => break,
            }
        }
        None
    }

    /// First-wins: with N devices ringing, the FIRST to approve delivers its DEK
    /// to the gate; the other N-1 are cancelled and dismissed with a `Settled`
    /// broadcast, and only the winner's DEK reaches the gate (distinct DEKs prove
    /// no cross-device delivery).
    #[test]
    fn ring_first_wins_delivers_the_winners_dek_and_dismisses_losers() {
        let relay = LocalRelay::new();
        let devices = build_ring(&relay, 3, Duration::from_secs(5));
        let (shutdown, owners) = spawn_ring_owners(&devices);

        // Device index 1 is the winner: it answers its request with a distinct DEK.
        let winner = 1usize;
        let w = &devices[winner];
        let phone = clone_id(&w.phone);
        let daemon_pub = w.daemon_pub;
        let mailbox = w.mailbox;
        let relay_w = relay.clone();
        let phone_thread = std::thread::spawn(move || {
            let _req = relay_w
                .recv(mailbox, Direction::ToPhone, Duration::from_secs(5))
                .unwrap()
                .expect("the winner received its request");
            let resp = ApprovalResponse::approve_v2("req-RING", "Rowm", &[7u8; 32], 1);
            let env = Envelope::seal(&resp, mailbox, 1, &phone.signing, &daemon_pub).unwrap();
            relay_w.send(mailbox, Direction::ToDaemon, &env).unwrap();
        });

        let ring = RingApprover::new(devices.iter().map(|d| d.approver.clone()).collect());
        let outcome = ring.decide(&secret_ctx("req-RING"));

        phone_thread.join().unwrap();

        assert!(outcome.decision.is_grant(), "the winner's approve resolves");
        assert_eq!(
            outcome.zf.as_deref().map(|z| &z[..]),
            Some(&[7u8; 32][..]),
            "exactly the winner's DEK reaches the gate"
        );

        // The two losers each received a Settled dismissal (after consuming their
        // own ring-all request deposit).
        for (i, dev) in devices.iter().enumerate() {
            if i == winner {
                continue;
            }
            let status = drain_resolution(dev, &relay);
            assert_eq!(
                status,
                Some(ResolutionStatus::Settled),
                "loser {i} must be dismissed with Settled"
            );
        }

        shutdown.store(true, Ordering::SeqCst);
        for o in owners {
            o.join().unwrap();
        }
    }

    /// First-wins covers DENY too: the first device to explicitly deny resolves the
    /// ring (deny wins), and the others are dismissed with `Settled`.
    #[test]
    fn ring_first_deny_wins_and_dismisses_losers() {
        let relay = LocalRelay::new();
        let devices = build_ring(&relay, 2, Duration::from_secs(5));
        let (shutdown, owners) = spawn_ring_owners(&devices);

        let denier = 0usize;
        let d = &devices[denier];
        let phone = clone_id(&d.phone);
        let daemon_pub = d.daemon_pub;
        let mailbox = d.mailbox;
        let relay_d = relay.clone();
        let phone_thread = std::thread::spawn(move || {
            let _req = relay_d
                .recv(mailbox, Direction::ToPhone, Duration::from_secs(5))
                .unwrap()
                .expect("the denier received its request");
            let resp = ApprovalResponse::deny("req-DENY", 1);
            let env = Envelope::seal(&resp, mailbox, 1, &phone.signing, &daemon_pub).unwrap();
            relay_d.send(mailbox, Direction::ToDaemon, &env).unwrap();
        });

        let ring = RingApprover::new(devices.iter().map(|d| d.approver.clone()).collect());
        let outcome = ring.decide(&secret_ctx("req-DENY"));
        phone_thread.join().unwrap();

        assert_eq!(outcome.decision, Decision::Deny, "the first deny wins");
        assert!(outcome.zf.is_none(), "a deny carries no DEK");

        // The other device is dismissed with Settled (not told it was a deny).
        let status = drain_resolution(&devices[1], &relay);
        assert_eq!(status, Some(ResolutionStatus::Settled));

        shutdown.store(true, Ordering::SeqCst);
        for o in owners {
            o.join().unwrap();
        }
    }

    /// All devices time out (no phone answers): the ring DENIES (fail closed),
    /// exactly like a single-device timeout, and no outcome is fabricated.
    #[test]
    fn ring_all_timeout_denies() {
        let relay = LocalRelay::new();
        // Short timeout so the test's all-timeout path resolves quickly.
        let devices = build_ring(&relay, 3, Duration::from_millis(300));
        let (shutdown, owners) = spawn_ring_owners(&devices);

        let ring = RingApprover::new(devices.iter().map(|d| d.approver.clone()).collect());
        let outcome = ring.decide(&secret_ctx("req-TIMEOUT"));

        assert_eq!(
            outcome.decision,
            Decision::Deny,
            "an all-timeout ring must fail closed to deny"
        );
        assert!(outcome.zf.is_none());

        shutdown.store(true, Ordering::SeqCst);
        for o in owners {
            o.join().unwrap();
        }
    }

    /// A one-device ring is byte-identical to the bare single-device path: it
    /// drives the unchanged `RemoteApprover::decide`, delivering that device's DEK.
    #[test]
    fn ring_of_one_matches_the_single_device_path() {
        let relay = LocalRelay::new();
        let devices = build_ring(&relay, 1, Duration::from_secs(5));
        let (shutdown, owners) = spawn_ring_owners(&devices);

        let d = &devices[0];
        let phone = clone_id(&d.phone);
        let daemon_pub = d.daemon_pub;
        let mailbox = d.mailbox;
        let relay_c = relay.clone();
        let phone_thread = std::thread::spawn(move || {
            let _req = relay_c
                .recv(mailbox, Direction::ToPhone, Duration::from_secs(5))
                .unwrap()
                .expect("the sole device received its request");
            let resp = ApprovalResponse::approve_v2("req-ONE", "Rowm", &[5u8; 32], 1);
            let env = Envelope::seal(&resp, mailbox, 1, &phone.signing, &daemon_pub).unwrap();
            relay_c.send(mailbox, Direction::ToDaemon, &env).unwrap();
        });

        let ring = RingApprover::new(vec![devices[0].approver.clone()]);
        let outcome = ring.decide(&secret_ctx("req-ONE"));
        phone_thread.join().unwrap();

        assert!(outcome.decision.is_grant());
        assert_eq!(outcome.zf.as_deref().map(|z| &z[..]), Some(&[5u8; 32][..]));

        shutdown.store(true, Ordering::SeqCst);
        for o in owners {
            o.join().unwrap();
        }
    }

    // --- #51 direct transport: promote / demote / acceptor -----------------------

    use sigil_proto::{PushRegister, Transport, TransportError};

    /// Build a phone-factor approver with direct transport ENABLED over an
    /// in-process relay, plus the shared `FallbackTransport` (the promote/demote
    /// seam) and its push store. The approver's `transport` and its `direct` field
    /// are the SAME FallbackTransport, exactly as `build_gate` wires it.
    fn direct_approver(
        daemon: &DeviceIdentity,
        phone_pub: PeerIdentity,
    ) -> (
        Arc<RemoteApprover>,
        Arc<FallbackTransport>,
        LocalRelay,
        Arc<PushStore>,
    ) {
        let relay = LocalRelay::new();
        let fb = Arc::new(FallbackTransport::new(Arc::new(relay.clone())));
        let store = Arc::new(PushStore::ephemeral());
        let approver = Arc::new(
            RemoteApprover::new(fb.clone(), clone_id(daemon), phone_pub)
                .with_push(store.clone())
                .with_timeout(Duration::from_secs(2))
                .with_listen_poll(Duration::from_millis(20))
                .with_verify_timeout(Duration::from_millis(500))
                .with_direct(fb.clone()),
        );
        (approver, fb, relay, store)
    }

    /// A connected loopback pair of direct links (daemon `server`, phone `client`).
    fn direct_pair() -> (Arc<DirectLink>, Arc<DirectLink>) {
        let listener = DirectListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let dialer =
            std::thread::spawn(move || DirectLink::connect(&addr.to_string()).expect("connect"));
        let server = listener.accept().expect("accept");
        let client = dialer.join().expect("dialer");
        (server, client)
    }

    /// Seal the phone's direct-link opener (a real `PushRegister`), which
    /// `verify_and_promote` reads as the proof of the pinned peer.
    fn phone_opener(
        phone: &DeviceIdentity,
        daemon_pub: &PeerIdentity,
        mailbox: [u8; 32],
    ) -> Envelope {
        let pr = PushRegister::new("direct-token", "apns");
        Envelope::seal(&pr, mailbox, 1, &phone.signing, daemon_pub).expect("seal opener")
    }

    /// The gate: `verify_and_promote` installs the direct link as the primary ONLY
    /// after an envelope opens as the pinned phone, and routes that first envelope
    /// (here a PushRegister -> the push store) without a second open.
    #[test]
    fn verify_and_promote_installs_a_primary_for_the_pinned_phone() {
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate();
        let (approver, fb, _relay, store) = direct_approver(&daemon, phone.peer_identity());
        let mailbox = approver.mailbox();

        let (server, client) = direct_pair();
        client
            .send(
                mailbox,
                Direction::ToDaemon,
                &phone_opener(&phone, &daemon.peer_identity(), mailbox),
            )
            .expect("phone sends its opener");

        assert!(
            approver.verify_and_promote(server),
            "an opener that opens as the pinned phone promotes the link"
        );
        assert!(
            fb.has_primary(),
            "the verified link is installed as the primary"
        );
        assert_eq!(
            store.get(mailbox).expect("opener routed").token,
            "direct-token",
            "the verifying PushRegister was routed, not re-opened"
        );
    }

    /// Fail closed: an opener sealed by some OTHER key (a rogue LAN host that
    /// dialled in) does not open as the pinned phone, so the link is never
    /// installed and the relay path is untouched.
    #[test]
    fn verify_and_promote_rejects_an_imposter() {
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate();
        let (approver, fb, _relay, _store) = direct_approver(&daemon, phone.peer_identity());
        let mailbox = approver.mailbox();

        let (server, client) = direct_pair();
        // An imposter seals with its OWN key, not the pinned phone's.
        let imposter = DeviceIdentity::generate();
        client
            .send(
                mailbox,
                Direction::ToDaemon,
                &phone_opener(&imposter, &daemon.peer_identity(), mailbox),
            )
            .expect("imposter sends bytes");

        assert!(
            !approver.verify_and_promote(server),
            "an imposter's envelope must not promote the link"
        );
        assert!(!fb.has_primary(), "no primary is installed for an imposter");
    }

    /// With direct DISABLED (no `with_direct`), `verify_and_promote` is a no-op that
    /// returns false, so an acceptor wired by mistake can never install a primary.
    #[test]
    fn verify_and_promote_is_a_noop_when_direct_is_disabled() {
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate();
        // A plain relay-only approver: no `with_direct`.
        let approver = Arc::new(RemoteApprover::new(
            Arc::new(LocalRelay::new()),
            clone_id(&daemon),
            phone.peer_identity(),
        ));
        let mailbox = approver.mailbox();
        let (server, client) = direct_pair();
        client
            .send(
                mailbox,
                Direction::ToDaemon,
                &phone_opener(&phone, &daemon.peer_identity(), mailbox),
            )
            .expect("send");
        assert!(!approver.verify_and_promote(server));
    }

    /// End to end: once a link is promoted, the owner reads it and a full approval
    /// rides the DIRECT link (never the relay). Proves the promoted primary is what
    /// both the owner's recv and the request deposit use.
    #[test]
    fn a_promoted_direct_link_carries_a_full_approval() {
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate();
        let daemon_pub = daemon.peer_identity();
        let (approver, fb, relay, _store) = direct_approver(&daemon, phone.peer_identity());
        let mailbox = approver.mailbox();

        let (server, client) = direct_pair();
        client
            .send(
                mailbox,
                Direction::ToDaemon,
                &phone_opener(&phone, &daemon_pub, mailbox),
            )
            .expect("opener");
        assert!(approver.verify_and_promote(server));

        let (shutdown, owner) = spawn_owner(approver.clone());

        // The phone answers over the DIRECT link: read the request ToPhone, seal an
        // approve ToDaemon (counter 2, after the counter-1 opener).
        let phone_thread = {
            let client = client.clone();
            std::thread::spawn(move || {
                client
                    .recv(mailbox, Direction::ToPhone, Duration::from_secs(2))
                    .unwrap()
                    .expect("the request arrived on the direct link");
                let resp = ApprovalResponse::approve_v2("req-DL", "Rowm", &[7u8; 32], 2);
                let env = Envelope::seal(&resp, mailbox, 2, &phone.signing, &daemon_pub).unwrap();
                client.send(mailbox, Direction::ToDaemon, &env).unwrap();
            })
        };

        let outcome = approver.decide(&secret_ctx("req-DL"));
        phone_thread.join().unwrap();
        shutdown.store(true, Ordering::SeqCst);
        owner.join().unwrap();

        assert!(
            outcome.decision.is_grant(),
            "the approval rode the direct link"
        );
        assert_eq!(outcome.zf.as_deref().map(|z| &z[..]), Some(&[7u8; 32][..]));
        // The relay never carried the request: it was genuinely skipped.
        assert_eq!(relay.depth(mailbox, Direction::ToPhone), 0);
        assert!(fb.has_primary(), "a healthy link stays promoted");
    }

    /// A transport that accepts deposits but never delivers a response: the shape of
    /// an active LAN MITM that got promoted then black-holes traffic. Its `recv`
    /// naps and returns empty so an owner polling it does not spin.
    #[derive(Default)]
    struct BlackHole;
    impl Transport for BlackHole {
        fn send(&self, _m: [u8; 32], _d: Direction, _e: &Envelope) -> Result<(), TransportError> {
            Ok(())
        }
        fn recv(
            &self,
            _m: [u8; 32],
            _d: Direction,
            timeout: Duration,
        ) -> Result<Option<Envelope>, TransportError> {
            std::thread::sleep(timeout.min(Duration::from_millis(30)));
            Ok(None)
        }
    }

    /// Demote-on-silence: a request deposited over a black-holed direct primary is
    /// not answered within the short window, so `round_trip` retires the primary and
    /// re-deposits over the relay, where the phone answers. The approval SUCCEEDS via
    /// the relay rather than timing out: the residual becomes a short retry.
    #[test]
    fn demote_on_silence_completes_over_the_relay() {
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate();
        let daemon_pub = daemon.peer_identity();
        let (_approver, fb, relay, _store) = direct_approver(&daemon, phone.peer_identity());
        // Shrink the demote window so the test does not wait the default.
        let approver = Arc::new(
            RemoteApprover::new(fb.clone(), clone_id(&daemon), phone.peer_identity())
                .with_timeout(Duration::from_secs(2))
                .with_listen_poll(Duration::from_millis(20))
                .with_demote_after(Duration::from_millis(60))
                .with_direct(fb.clone()),
        );
        let mailbox = approver.mailbox();
        // Install a black-holed direct primary directly (as verify_and_promote
        // would), bypassing the TCP handshake.
        fb.install_primary(Arc::new(BlackHole));

        let (shutdown, owner) = spawn_owner(approver.clone());

        // The phone waits for the RELAY re-deposit (only arrives after demote), then
        // approves over the relay.
        let phone_thread = {
            let relay = relay.clone();
            std::thread::spawn(move || {
                relay
                    .recv(mailbox, Direction::ToPhone, Duration::from_secs(2))
                    .unwrap()
                    .expect("the demote re-deposit reached the relay");
                let resp = ApprovalResponse::approve_v2("req-DEMOTE", "Rowm", &[3u8; 32], 1);
                let env = Envelope::seal(&resp, mailbox, 1, &phone.signing, &daemon_pub).unwrap();
                relay.send(mailbox, Direction::ToDaemon, &env).unwrap();
            })
        };

        let outcome = approver.decide(&secret_ctx("req-DEMOTE"));
        phone_thread.join().unwrap();
        shutdown.store(true, Ordering::SeqCst);
        owner.join().unwrap();

        assert!(
            outcome.decision.is_grant(),
            "a black-holed direct link demotes and completes over the relay"
        );
        assert_eq!(outcome.zf.as_deref().map(|z| &z[..]), Some(&[3u8; 32][..]));
        assert!(
            !fb.has_primary(),
            "the silent primary was retired on demote"
        );
    }

    /// The rung-2 acceptor loop, over real loopback TCP: a phone dials the bound
    /// listener and sends its opener; the acceptor verifies + promotes it, so the
    /// FallbackTransport gains a primary and the opener is recorded. Exercises
    /// `run_direct_acceptor` + `accept_nonblocking` + `verify_and_promote` together.
    #[test]
    fn the_acceptor_loop_promotes_a_dialled_phone() {
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate();
        let daemon_pub = daemon.peer_identity();
        let (approver, fb, _relay, store) = direct_approver(&daemon, phone.peer_identity());
        let mailbox = approver.mailbox();

        let listener = DirectListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();

        let shutdown = Arc::new(AtomicBool::new(false));
        let acceptor = {
            let approver = approver.clone();
            let shutdown = shutdown.clone();
            std::thread::spawn(move || approver.run_direct_acceptor(&listener, &shutdown))
        };

        // The phone dials and sends its opener.
        let client = DirectLink::connect(&addr).expect("phone dials");
        client
            .send(
                mailbox,
                Direction::ToDaemon,
                &phone_opener(&phone, &daemon_pub, mailbox),
            )
            .expect("phone sends opener");

        // The acceptor promotes within a few poll cycles.
        let mut tries = 0;
        while !fb.has_primary() {
            tries += 1;
            assert!(tries < 200, "the acceptor never promoted the dialled phone");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            store.get(mailbox).expect("opener routed").token,
            "direct-token"
        );

        shutdown.store(true, Ordering::SeqCst);
        acceptor.join().unwrap();
        drop(client);
    }

    /// The mDNS hint is deterministic for one identity and differs across
    /// identities, and it is NOT the mailbox id (never advertises the routing
    /// address). It grants nothing; a wrong hint only wastes a dial.
    #[test]
    fn direct_service_hint_is_stable_and_identity_specific() {
        let a = DeviceIdentity::generate().peer_identity();
        let b = DeviceIdentity::generate().peer_identity();
        assert_eq!(direct_service_hint(&a), direct_service_hint(&a));
        assert_ne!(direct_service_hint(&a), direct_service_hint(&b));
        assert!(!direct_service_hint(&a).is_empty());
    }

    // --- phone lease control ------------------------------------------------

    mod lease_control {
        use super::*;
        use crate::lease::{LeaseBinding, LeaseControl, LeaseStore};
        use sigil_proto::{
            LeaseListReply, LeaseQuery, LeaseRevoke, LeaseRevokeReply, ReplayGuard, ToPhoneMessage,
            LABEL_REJECTED,
        };
        use zeroize::Zeroizing;

        /// One pairing plus the store the daemon serves lease control from, with
        /// the reply pump running exactly as the daemon runs it.
        struct Fx {
            relay: LocalRelay,
            daemon: DeviceIdentity,
            phone: DeviceIdentity,
            mailbox: [u8; 32],
            leases: Arc<LeaseStore>,
            approver: Arc<RemoteApprover>,
            counter: AtomicU64,
            pump: Option<(Arc<AtomicBool>, std::thread::JoinHandle<()>)>,
        }

        impl Drop for Fx {
            fn drop(&mut self) {
                if let Some((stop, handle)) = self.pump.take() {
                    stop.store(true, Ordering::SeqCst);
                    let _ = handle.join();
                }
            }
        }

        impl Fx {
            fn new() -> Self {
                Self::with_store(Arc::new(LeaseStore::new()))
            }

            fn with_store(leases: Arc<LeaseStore>) -> Self {
                let relay = LocalRelay::new();
                let daemon = DeviceIdentity::generate();
                let phone = DeviceIdentity::generate();
                let mailbox = mailbox_id(&daemon.peer_identity(), &phone.peer_identity());
                let approver = Arc::new(RemoteApprover::new(
                    Arc::new(relay.clone()),
                    clone_id(&daemon),
                    phone.peer_identity(),
                ));
                let control: Arc<dyn LeaseControl> = leases.clone();
                approver.attach_leases(control);
                // The real pump on its own thread, as `Core::serve` spawns it.
                let stop = Arc::new(AtomicBool::new(false));
                let pump = {
                    let approver = approver.clone();
                    let stop = stop.clone();
                    std::thread::spawn(move || approver.run_lease_reply_pump(&stop))
                };
                Self {
                    relay,
                    daemon,
                    phone,
                    mailbox,
                    leases,
                    approver,
                    counter: AtomicU64::new(0),
                    pump: Some((stop, pump)),
                }
            }

            /// Grant one window, returning its opaque lease id.
            fn grant(&self, key: u8, scope: &str, covers: &str, account: &str) -> String {
                self.leases.grant(
                    [key; 32],
                    &LeaseBinding::presence(account, scope, 1),
                    covers,
                    Zeroizing::new(Vec::new()),
                    Duration::from_secs(300),
                );
                self.leases
                    .list()
                    .into_iter()
                    .find(|l| l.scope == scope)
                    .expect("the window was filed")
                    .lease_id
            }

            /// Seal a phone -> daemon message and return it with the envelope's
            /// uuidv7 request id, which the daemon must echo as `inReplyTo`.
            fn seal<T: serde::Serialize>(&self, msg: &T) -> (Envelope, String) {
                let counter = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
                let env = Envelope::seal(
                    msg,
                    self.mailbox,
                    counter,
                    &self.phone.signing,
                    &self.daemon.peer_identity(),
                )
                .expect("seal");
                let id = env.request_id.to_string();
                (env, id)
            }

            /// Hand one envelope to the daemon through the real inbound path:
            /// verify, replay-check, classify, route. Exactly what the owner loop
            /// does with a polled envelope.
            fn deliver(&self, env: &Envelope) {
                self.approver.dispatch(env.clone());
            }

            /// Seal, deliver, and return the request id the reply must name.
            fn ask<T: serde::Serialize>(&self, msg: &T) -> String {
                let (env, id) = self.seal(msg);
                self.deliver(&env);
                id
            }

            /// The next daemon -> phone message, opened and classified by the
            /// phone. `None` if the daemon sent nothing within `wait`.
            fn reply_within(&self, wait: Duration) -> Option<ToPhoneMessage> {
                let env = self
                    .relay
                    .recv(self.mailbox, Direction::ToPhone, wait)
                    .expect("relay")?;
                let value: serde_json::Value = env
                    .open(
                        &self.daemon.peer_identity(),
                        &self.phone.agreement,
                        &mut ReplayGuard::new(),
                    )
                    .expect("the phone opens the daemon-signed reply");
                Some(ToPhoneMessage::from_value(value).expect("classifies"))
            }

            /// A reply the daemon is expected to send.
            fn reply(&self) -> Option<ToPhoneMessage> {
                self.reply_within(Duration::from_secs(2))
            }

            /// Assert the daemon sent nothing. The drop decision is made
            /// synchronously in `dispatch`, before anything is queued, so a short
            /// wait is conclusive.
            fn expect_no_reply(&self) {
                assert!(
                    self.reply_within(Duration::from_millis(80)).is_none(),
                    "the daemon must have stayed silent"
                );
            }

            fn list_reply(&self) -> LeaseListReply {
                match self.reply().expect("a list reply was deposited") {
                    ToPhoneMessage::LeaseList(r) => r,
                    other => panic!("expected a list reply, got {other:?}"),
                }
            }

            fn revoke_reply(&self) -> LeaseRevokeReply {
                match self.reply().expect("a revoke reply was deposited") {
                    ToPhoneMessage::LeaseRevoke(r) => r,
                    other => panic!("expected a revoke reply, got {other:?}"),
                }
            }

            /// Let the token bucket refill, so a test that has spent its burst can
            /// keep going.
            fn refill(&self) {
                std::thread::sleep(Duration::from_millis(1_100));
            }
        }

        /// The happy path, end to end through the sealed envelope: the phone lists
        /// the daemon's live windows and revokes one, the reply names the request
        /// that asked, and the window is really gone from the same store
        /// `sigil lease list` reads.
        #[test]
        fn a_sealed_list_and_revoke_round_trip_and_actually_kill_the_window() {
            let fx = Fx::new();
            let id = fx.grant(0x11, "op", "op read", "rowm");

            let asked = fx.ask(&LeaseQuery::new());
            let list = fx.list_reply();
            assert_eq!(list.in_reply_to, asked, "the reply names the request");
            assert!(list.as_of_ms > 0, "and stamps when it measured the clocks");
            assert_eq!(list.leases.len(), 1);
            let row = &list.leases[0];
            assert_eq!(row.lease_id, id);
            assert_eq!(row.scope, "op");
            assert_eq!(row.covers, "op read");
            assert_eq!(row.account, "rowm");
            assert!(row.remaining_ms > 0 && row.remaining_ms <= 300_000);

            let asked = fx.ask(&LeaseRevoke::new(&id));
            let rev = fx.revoke_reply();
            assert_eq!(rev.in_reply_to, asked);
            assert_eq!(rev.lease_id, id);
            assert!(rev.revoked, "the named window was live and must be killed");
            assert_eq!(fx.leases.active(), 0, "and it is gone from the store");

            // Idempotent: the same revoke again is a clean false, not an error.
            fx.ask(&LeaseRevoke::new(&id));
            assert!(!fx.revoke_reply().revoked);
        }

        /// **F1, the replay case this design exists for.**
        ///
        /// The envelope's freshness window and single-use id are RAM-only on both
        /// ends, so a daemon restart empties the guard. A revoke captured off the
        /// wire and re-flown inside the freshness window is then authentic, fresh,
        /// and unseen -- it opens. What stops it is that it names an opaque lease
        /// id, and the window it named is gone.
        ///
        /// Both gates are proven here: rejected outright at a live daemon, inert at
        /// a restarted one.
        #[test]
        fn a_replayed_revoke_cannot_kill_a_later_window() {
            let fx = Fx::new();
            let id = fx.grant(0x22, "op", "op read", "rowm");

            // The relay captures the revoke on its way past, and it lands.
            let (captured, _) = fx.seal(&LeaseRevoke::new(&id));
            fx.deliver(&captured);
            assert!(fx.revoke_reply().revoked);
            assert_eq!(fx.leases.active(), 0);

            // The human re-approves: a NEW window, same rule, same caller, so the
            // same deterministic grant key -- and a different lease id.
            let id2 = fx.grant(0x22, "op", "op read", "rowm");
            assert_ne!(id2, id, "a new window is a new id");
            assert_eq!(
                fx.leases.list()[0].grant_hex,
                crate::lease::hex32(&[0x22; 32]),
                "while the grant key really does recur"
            );

            // Gate 1: replayed at the same daemon, the guard rejects the bytes.
            fx.deliver(&captured);
            fx.expect_no_reply();
            assert_eq!(fx.leases.active(), 1, "and must not touch the new window");

            // Gate 2: the same message at a daemon with an EMPTY guard (a restart
            // inside the freshness window). It opens and routes; the id binding is
            // what makes it inert.
            let restarted = Fx::with_store(fx.leases.clone());
            restarted.ask(&LeaseRevoke::new(&id));
            let rev = restarted.revoke_reply();
            assert!(
                !rev.revoked,
                "a revoke naming a window that has ended must be inert"
            );
            assert_eq!(
                restarted.leases.active(),
                1,
                "the window the human just opened survives a replayed revoke"
            );
        }

        /// **F3: every reply names the envelope that asked.**
        ///
        /// Without it, a relay that captured a genuine `revoked: true` could
        /// suppress a later revoke and deliver the capture instead, and the human
        /// would be told a window closed while it is open. The daemon's half of the
        /// defence is that the correlation is the ENVELOPE's uuidv7 request id,
        /// which the phone generated and can therefore check against what it has
        /// outstanding -- a check that survives its own restart, when the replay
        /// guard does not.
        #[test]
        fn a_reply_names_the_envelope_that_asked_so_a_capture_cannot_pass_for_it() {
            let fx = Fx::new();
            let id = fx.grant(0x33, "op", "op read", "rowm");

            // A first revoke, whose reply the relay captures.
            let first = fx.ask(&LeaseRevoke::new(&id));
            let captured = fx.revoke_reply();
            assert!(captured.revoked);
            assert_eq!(captured.in_reply_to, first);

            // A second, later request gets a DIFFERENT correlation, so the capture
            // cannot stand in for it. This is the property the phone keys on.
            let id2 = fx.grant(0x33, "op", "op read", "rowm");
            let second = fx.ask(&LeaseRevoke::new(&id2));
            let fresh = fx.revoke_reply();
            assert_ne!(second, first, "each envelope has its own uuidv7 id");
            assert_eq!(fresh.in_reply_to, second);
            assert_ne!(
                captured.in_reply_to, second,
                "the captured reply names a request that is no longer outstanding, \
                 so the phone drops it"
            );

            // Same for a list.
            let asked = fx.ask(&LeaseQuery::new());
            assert_eq!(fx.list_reply().in_reply_to, asked);
        }

        /// Every way to fail is the same way: `revoked: false`, never an error and
        /// never distinguishable. So the reply is not an oracle for what this
        /// daemon holds.
        #[test]
        fn revoking_an_unknown_or_expired_window_is_one_clean_false() {
            let fx = Fx::new();
            fx.grant(0x44, "op", "op read", "rowm");

            // An id this daemon has never minted.
            fx.ask(&LeaseRevoke::new("a".repeat(32)));
            let unknown = fx.revoke_reply();
            assert!(!unknown.revoked);
            assert_eq!(unknown.lease_id, "a".repeat(32), "echoed, normalized");
            assert_eq!(fx.leases.active(), 1, "and nothing was killed");

            // A window that lapsed on its own before the revoke arrived.
            let lapsed = Fx::new();
            lapsed.leases.grant(
                [0x45; 32],
                &LeaseBinding::presence("rowm", "op", 1),
                "op read",
                Zeroizing::new(Vec::new()),
                Duration::from_millis(10),
            );
            let gone = lapsed.leases.list()[0].lease_id.clone();
            std::thread::sleep(Duration::from_millis(30));
            lapsed.ask(&LeaseRevoke::new(&gone));
            let expired = lapsed.revoke_reply();
            assert!(!expired.revoked);

            // The two are the same shape on the wire: same keys, same length, same
            // boolean. Nothing distinguishes "no such window" from "already gone".
            let a = serde_json::to_vec(&unknown).unwrap();
            let b = serde_json::to_vec(&expired).unwrap();
            assert_eq!(a.len(), b.len());
            assert_eq!(fx.leases.active(), 1);
        }

        /// **F2: a malformed or prefix-shaped target is dropped whole.**
        ///
        /// The store's other revoke entry point is prefix matched, and `""` is a
        /// prefix of every string, so an empty identifier reaching it would be a
        /// silent global lease wipe reported as success. This path never reaches
        /// that API, refuses on width first, and answers nothing at all -- so
        /// peer-chosen bytes are never echoed onto a screen either.
        #[test]
        fn a_malformed_or_empty_revoke_target_is_dropped_with_no_reply() {
            let fx = Fx::new();
            let id = fx.grant(0x55, "op", "op read", "rowm");
            let grant_key = fx.leases.list()[0].grant_hex.clone();
            for bad in [
                String::new(),       // the wildcard-shaped one
                id[..8].to_string(), // a prefix is not an id
                format!("{id}0"),    // too long
                "not-hex".to_string(),
                grant_key, // a grant key is not a lease id
            ] {
                fx.ask(&LeaseRevoke::new(&bad));
                fx.expect_no_reply();
            }
            assert_eq!(fx.leases.active(), 1, "and the store is untouched");
        }

        /// **F4: the list carries no unsanitised config text.** `scope` is the raw
        /// rule name and `account` the raw source label, so both go through the
        /// coverage-label allowlist. It carries no command line, secret reference,
        /// or secret value either.
        #[test]
        fn the_list_never_carries_an_unsanitised_string() {
            let fx = Fx::new();
            fx.grant(
                0x66,
                "op\u{202e}prod",         // bidi override in a rule name
                "op read\u{200b}\u{301}", // zero-width + combining mark
                &"a".repeat(500),         // unbounded account label
            );
            fx.ask(&LeaseQuery::new());
            let list = fx.list_reply();
            let row = &list.leases[0];
            for field in [&row.scope, &row.covers, &row.account] {
                for ch in field.chars() {
                    assert!(
                        ch.is_ascii_graphic()
                            || ch == ' '
                            || ch == '\u{2026}'
                            || ch == LABEL_REJECTED,
                        "{ch:?} reached the phone's lease list"
                    );
                }
                assert!(field.chars().count() <= sigil_proto::LEASE_LABEL_MAX_CHARS);
            }
            assert!(
                row.scope.contains(LABEL_REJECTED),
                "the override was marked"
            );

            // And the payload holds no grant key, no argv, no secret reference.
            let json = serde_json::to_string(&list).unwrap();
            assert!(!json.contains(&fx.leases.list()[0].grant_hex));
            assert!(!json.contains("op://"));
            assert!(!json.contains("command"));
        }

        /// **F7: the relay cannot count the windows.** Zero rows and several rows
        /// seal to one ciphertext length, and a revoke reply is that same length,
        /// so an observer cannot tell a list from a revoke or read the row count
        /// off the wire.
        #[test]
        fn lease_control_ciphertexts_are_one_length_whatever_they_say() {
            let mut lengths = Vec::new();
            for rows in [0usize, 1, 3] {
                let fx = Fx::new();
                for i in 0..rows {
                    fx.grant(
                        0x70 + i as u8,
                        &format!("rule-{i}"),
                        "op with --account \"rowmhq.1password.eu\"",
                        "Rowm work",
                    );
                }
                fx.ask(&LeaseQuery::new());
                let env = fx
                    .relay
                    .recv(fx.mailbox, Direction::ToPhone, Duration::from_secs(2))
                    .expect("relay")
                    .expect("a list reply");
                lengths.push(env.ciphertext.len());
            }
            assert_eq!(
                lengths
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
                1,
                "row count leaked through ciphertext length: {lengths:?}"
            );

            // A revoke reply is indistinguishable from a list reply by length.
            let fx = Fx::new();
            let id = fx.grant(0x7f, "op", "op read", "rowm");
            fx.ask(&LeaseRevoke::new(&id));
            let env = fx
                .relay
                .recv(fx.mailbox, Direction::ToPhone, Duration::from_secs(2))
                .expect("relay")
                .expect("a revoke reply");
            assert_eq!(env.ciphertext.len(), lengths[0]);
        }

        /// With no lease-control handle attached (the softphone/test loop, or an
        /// approver built before the core exists) a lease message is dropped with
        /// no reply, rather than answered with a half-truth like an empty list --
        /// which the human would read as "no windows are open".
        #[test]
        fn lease_control_with_no_handle_attached_is_dropped() {
            let relay = LocalRelay::new();
            let daemon = DeviceIdentity::generate();
            let phone = DeviceIdentity::generate();
            let mailbox = mailbox_id(&daemon.peer_identity(), &phone.peer_identity());
            let approver = RemoteApprover::new(
                Arc::new(relay.clone()),
                clone_id(&daemon),
                phone.peer_identity(),
            );
            let env = Envelope::seal(
                &LeaseQuery::new(),
                mailbox,
                1,
                &phone.signing,
                &daemon.peer_identity(),
            )
            .expect("seal");
            approver.dispatch(env);
            assert!(relay
                .recv(mailbox, Direction::ToPhone, Duration::from_millis(50))
                .expect("relay")
                .is_none());
        }

        /// **F8: the rate budget bounds a looping client without costing a human a
        /// revoke.** A burst is served, a sustained flood is not, and the budget
        /// refills.
        #[test]
        fn the_rate_budget_serves_a_human_burst_and_bounds_a_flood() {
            let fx = Fx::new();
            // A human revoking several rows in a second: every tap is answered.
            let ids: Vec<String> = (0..LEASE_BURST)
                .map(|i| fx.grant(0x80 + i as u8, &format!("rule-{i}"), "op read", "rowm"))
                .collect();
            for id in &ids {
                fx.ask(&LeaseRevoke::new(id));
                assert!(
                    fx.revoke_reply().revoked,
                    "a human's burst must never be silently dropped"
                );
            }
            assert_eq!(fx.leases.active(), 0, "all of them really closed");

            // The budget is now spent, so a flood past it is dropped in silence.
            fx.ask(&LeaseQuery::new());
            fx.expect_no_reply();

            // And it refills, so the phone is served again shortly after.
            fx.refill();
            let asked = fx.ask(&LeaseQuery::new());
            assert_eq!(fx.list_reply().in_reply_to, asked);
        }
    }
}
