/**
 * A tiny observable app store exposed through useSyncExternalStore. Single
 * source of truth for every screen; the mock transport and the demo seed both
 * write here, and the UI only ever reads.
 */
import { useSyncExternalStore } from "react";

import {
  type ApprovalRequest,
  type Decision,
  type LeaseRow,
  type ResolutionStatus,
} from "@/src/protocol";
import { secretRefLabel, sshLabel } from "@/src/lib/format";
import { toActiveLeases } from "@/src/domain/leases";
import {
  type AppState,
  type HistoryEntry,
  type LeaseView,
  type PendingRequest,
  type PendingRevoke,
  type RelayOrigin,
  type RequestState,
} from "@/src/domain/types";
import { demoInitialState, emptyInitialState } from "./demo";

type Listener = () => void;

/**
 * Demo/dev seed is OFF unless explicitly enabled. The shipping build boots from
 * the REAL empty state and hydrates the stored pairing from the keystore; only an
 * explicit dev flag replaces that with the canned demo data.
 */
export const DEMO = process.env.EXPO_PUBLIC_SIGIL_DEMO === "1";

function initialState(): AppState {
  return DEMO ? demoInitialState() : emptyInitialState();
}

class Store {
  private state: AppState = initialState();
  private readonly listeners = new Set<Listener>();

  getState = (): AppState => this.state;

  subscribe = (l: Listener): (() => void) => {
    this.listeners.add(l);
    return () => this.listeners.delete(l);
  };

  private set(next: AppState): void {
    this.state = next;
    for (const l of this.listeners) l();
  }

  private patch(p: Partial<AppState>): void {
    this.set({ ...this.state, ...p });
  }

  /**
   * A new request arrived. Identical grant keys coalesce behind the pending one.
   *
   * `relayOrigin` is the transport's unverified note about where the delivery came
   * from (absent off the relay, or when it failed validation). It is held beside
   * the request for the sheet to show and is never written to history: history
   * is the audit mirror, and an unsigned relay claim has no business in it. On a
   * coalesce the first origin is kept rather than overwritten, so the row keeps
   * describing the delivery the human is actually looking at.
   */
  receive(request: ApprovalRequest, relayOrigin?: RelayOrigin): void {
    const key = grantKey(request);
    const existing = this.state.pending.find(
      (p) => p.state !== "approved" && p.state !== "denied" && grantKey(p.request) === key,
    );
    if (existing) {
      this.patch({
        pending: this.state.pending.map((p) =>
          p === existing ? { ...p, coalesced: p.coalesced + 1 } : p,
        ),
      });
      return;
    }
    const entry: PendingRequest = {
      request,
      state: "fresh",
      receivedAt: Date.now(),
      coalesced: 0,
      ...(relayOrigin ? { relayOrigin } : {}),
    };
    this.patch({ pending: [entry, ...this.state.pending] });
  }

  private transition(requestId: string, state: RequestState): void {
    this.patch({
      pending: this.state.pending.map((p) =>
        p.request.requestId === requestId ? { ...p, state } : p,
      ),
    });
  }

  markExpiring(requestId: string): void {
    const p = this.find(requestId);
    if (p && p.state === "fresh") this.transition(requestId, "expiring");
  }

  markExpired(requestId: string): void {
    const p = this.find(requestId);
    if (!p || p.state === "approved" || p.state === "denied") return;
    // A terminal request is recorded to history and drops out of the active
    // queue, rather than lingering as a dead row.
    this.record(p, "expired");
    this.remove(requestId);
  }

  decide(requestId: string, decision: Decision, note?: string): void {
    const p = this.find(requestId);
    if (!p || p.state === "approved" || p.state === "denied" || p.state === "expired") return;
    // Record the outcome, then drop the request from the active queue: once a
    // decision is made the phone is done with it, and it lives on only in history.
    this.record(p, decision, note);
    this.remove(requestId);
  }

  /**
   * #36 multi-device ring-all / first-wins: another paired device resolved this
   * request, or the daemon expired / withdrew it, so this phone dismisses its copy.
   * Records a neutral outcome to history and drops the request from the active
   * queue, exactly as {@link decide} and {@link markExpired} do.
   *
   * Zero-knowledge: the phone never learns which device resolved it, nor whether it
   * was an approve or a deny, so the recorded outcome is deliberately neutral
   * (`"superseded"`, or `"expired"` for an expiry), never approved/denied. A no-op
   * for an unknown or already-terminal request, so a duplicate or late broadcast
   * (or one for a request this device never saw) changes nothing.
   */
  dismissResolved(requestId: string, status: ResolutionStatus): void {
    const p = this.find(requestId);
    if (!p || p.state === "approved" || p.state === "denied" || p.state === "expired") return;
    if (status === "expired") {
      this.record(p, "expired");
    } else {
      this.transition(requestId, "superseded");
      const note = status === "withdrawn" ? "withdrawn" : "resolved on another device";
      this.record(p, "superseded", note);
    }
    this.remove(requestId);
  }

  // ---- lease control -------------------------------------------------------
  //
  // Every writer below records only what the DAEMON said, and when. Nothing here
  // removes a row on the phone's own initiative, because the phone holds no lease
  // state: the daemon's `LeaseStore` is the only authority, and a local edit that
  // looked like a revoke would be exactly the consent theatre this replaced. The
  // one local removal is expiry, which is arithmetic on the daemon's own number,
  // and it is never reported as a revoke.
  //
  // A reply reaches these writers only after the session controller has matched
  // it to a request THIS session issued and consumed that entry (design review
  // F3). Nothing here confirms anything on a reply's say-so alone.

  /** A list query has left this phone. */
  leaseQueryStarted(): void {
    this.patchLeases({ asking: true, noBiometric: false });
  }

  /**
   * The list query could not be sent, or nothing came back in time. Records
   * inability, never emptiness: `rows`, `answeredAt` and `asOf` are left exactly
   * as they were, so the screen goes on describing the last real snapshot (and
   * says it has aged) instead of inventing a fresh one.
   */
  leaseQueryFailed(): void {
    this.patchLeases({ asking: false, unreachable: true });
  }

  /**
   * The biometric did not pass, so no question was asked. Distinct from
   * {@link leaseQueryFailed} on purpose: nothing failed and nothing is unknown
   * that was not already unknown, so a declined check must not raise "cannot
   * check right now", which would read as a fault in the link.
   *
   * `noBiometric` separates "you cancelled" from "this device has nothing to
   * cancel with". The first needs no explanation; the second is a dead end the
   * screen has to name, because the list is gated on a biometric and this device
   * cannot produce one.
   */
  leaseQueryCancelled(noBiometric = false): void {
    this.patchLeases({ asking: false, noBiometric });
  }

  /**
   * A fresh, correlated snapshot from the daemon. This is the ONLY writer of
   * `rows`, `answeredAt` and `asOf`, and therefore the only thing that can
   * entitle the screen to say the list is complete.
   *
   * It also settles pending revokes: a window missing from a snapshot the daemon
   * took AFTER the revoke was sent is confirmed closed by the daemon's own
   * account of itself, which is stronger evidence than the revoke reply. A window
   * still present stays pending, warning and all, because it really is still open.
   */
  leaseListReceived(rows: LeaseRow[], asOf: number, sentAt: number, receivedAt: number): void {
    const live = toActiveLeases(rows, receivedAt);
    const present = new Set(live.map((l) => l.leaseId));
    const settled = this.state.leases.revokes.filter(
      (r) => r.sentAt < receivedAt && !present.has(r.leaseId),
    );
    const note =
      settled.length > 0
        ? { leaseId: settled[0]!.leaseId, outcome: "closed" as const, at: receivedAt }
        : this.state.leases.note;
    this.patchLeases({
      rows: live,
      // Aged from when the QUESTION went out, never from when the answer turned
      // up: the relay picks the delay, so arrival is a number it controls. See
      // the two-timestamp note in the session controller.
      askedAt: sentAt,
      asOf,
      asking: false,
      unreachable: false,
      noBiometric: false,
      revokes: this.state.leases.revokes.filter((r) => !settled.includes(r)),
      note,
    });
  }

  /**
   * A revoke has left this phone. The row deliberately STAYS: clearing it here
   * would be an optimistic claim that a window closed, and a relay suppressing
   * the reply must never be able to buy that claim by dropping one message.
   */
  leaseRevokeStarted(revoke: PendingRevoke): void {
    const others = this.state.leases.revokes.filter((r) => r.leaseId !== revoke.leaseId);
    this.patchLeases({ revokes: [...others, revoke], note: null });
  }

  /**
   * The daemon answered a revoke, and the controller matched that answer to a
   * request this session issued. Both verdicts are successes: `revoked` true
   * means it ended a live window, false means it had none to end. Either way that
   * window is closed, so the row goes, and the note says which it was rather than
   * letting the second case read as a failure.
   */
  leaseRevokeConfirmed(requestId: string, revoked: boolean, at: number): void {
    const p = this.state.leases.revokes.find((r) => r.requestId === requestId);
    if (!p) return;
    this.patchLeases({
      rows: this.state.leases.rows.filter((l) => l.leaseId !== p.leaseId),
      revokes: this.state.leases.revokes.filter((r) => r.requestId !== requestId),
      note: { leaseId: p.leaseId, outcome: revoked ? "closed" : "alreadyGone", at },
    });
  }

  /**
   * The revoke went out and nothing came back. The warning stays, and outlives
   * the snapshot it came from: the honest reading is that the window may still be
   * open, and saying anything else here would be the failure mode this whole
   * feature exists to avoid.
   */
  leaseRevokeUnconfirmed(requestId: string): void {
    this.patchLeases({
      revokes: this.state.leases.revokes.map((r) =>
        r.requestId === requestId ? { ...r, unconfirmed: true } : r,
      ),
    });
  }

  /**
   * Drop rows whose window has run out. Arithmetic on the daemon's own
   * `remainingMs`, so it claims nothing the daemon did not already say; a row
   * that lapses is never recorded as a revoke.
   */
  expireLeases(nowMs: number): void {
    const rows = this.state.leases.rows.filter((l) => l.expiresAt > nowMs);
    if (rows.length === this.state.leases.rows.length) return;
    this.patchLeases({ rows });
  }

  /**
   * Throw the snapshot away when the screen goes away: render and drop, never
   * persist. A held list of live auto-approve windows is a schedule of what will
   * release with no human tap, and it should not outlive the moment someone chose
   * to look at it. It returns the section to "not checked yet", which is a true
   * description of what this phone then knows.
   *
   * Unconfirmed revokes SURVIVE this. They are warnings, not an enumeration, and
   * the whole point of one is that it outlasts the screen that produced it.
   */
  clearLeaseSnapshot(): void {
    this.patchLeases({
      rows: [],
      askedAt: 0,
      asOf: 0,
      asking: false,
      unreachable: false,
      noBiometric: false,
      revokes: this.state.leases.revokes.filter((r) => r.unconfirmed),
      note: null,
    });
  }

  private patchLeases(p: Partial<LeaseView>): void {
    this.patch({ leases: { ...this.state.leases, ...p } });
  }

  setSetting<K extends keyof AppState["settings"]>(key: K, value: AppState["settings"][K]): void {
    this.patch({ settings: { ...this.state.settings, [key]: value } });
  }

  setPairingWords(words: string[] | null): void {
    this.patch({ pairingWords: words });
  }

  /**
   * Reflect a real stored pairing into the store, called once the live session is
   * armed (at boot from the keystore, or right after the pairing ceremony). Marks
   * the phone paired and arms it. Carries no machine name on purpose: the
   * pairing pins keys, and the paired Mac names itself through signed provenance
   * (see {@link pairedMacName}), never through a transport address. The
   * connection itself is deliberately untouched here: the link dot goes live
   * only when a real drain succeeds ({@link noteTransport}), never on hope.
   */
  reflectPairing(info: { ownFingerprint: string | null; pairedAt: number }): void {
    this.patch({
      paired: true,
      arm: "armed",
      ownFingerprint: info.ownFingerprint,
      pairedAt: info.pairedAt,
    });
  }

  /**
   * The transport reported a drain result: a success means the relay answered
   * just now (link), a failure means it did not (no link). This is the ONLY
   * writer of the live connection state, so the link dot always reflects the
   * last real exchange, not an assumption. Transport status only: it says
   * nothing about the Mac, and nothing here names a host.
   */
  noteTransport(connected: boolean): void {
    this.patch({
      connection: connected
        ? { rung: "relay", lastSeenAt: Date.now() }
        : { ...this.state.connection, rung: "none" },
    });
  }

  /** Drop all pairing-derived state and return to the unpaired empty boot state. */
  clearPairingState(): void {
    this.set(emptyInitialState());
  }

  private find(requestId: string): PendingRequest | undefined {
    return this.state.pending.find((p) => p.request.requestId === requestId);
  }

  /** Drop a request from the active queue (it has reached a terminal state). */
  private remove(requestId: string): void {
    this.patch({
      pending: this.state.pending.filter((p) => p.request.requestId !== requestId),
    });
  }

  private record(
    p: PendingRequest,
    decision: Decision | "expired" | "superseded",
    note?: string,
  ): void {
    const r = p.request;
    const label =
      r.secrets.length > 0
        ? r.secrets.map(secretRefLabel).join(", ")
        : r.ssh
          ? sshLabel(r.ssh)
          : (r.command.join(" ") || r.provenance.machine);
    const entry: HistoryEntry = {
      id: r.requestId,
      kind: r.kind,
      label,
      origin: r.provenance.machine,
      process: r.provenance.processChain[r.provenance.processChain.length - 1] ?? "",
      cwd: r.provenance.cwd,
      decision,
      at: Date.now(),
      via: "phone",
    };
    if (note !== undefined) entry.note = note;
    this.patch({ history: [entry, ...this.state.history] });
  }

  /**
   * Test/dev helper: seed pending requests directly. `relayOrigin` stands in for the
   * relay's hint so the network row is reachable in a demo build; it is applied
   * to every seeded request and never reaches a live pairing.
   */
  seedPending(requests: ApprovalRequest[], relayOrigin?: RelayOrigin): void {
    for (const r of requests) this.receive(r, relayOrigin);
  }

  reset(): void {
    this.set(initialState());
  }
}

/**
 * The daemon-side grant key is a hash of the resolved caller chain + project
 * root + scope. The phone cannot recompute that, so this is a display-only
 * coalescing key over the fields it can see; the real dedupe is the daemon's.
 */
function grantKey(r: ApprovalRequest): string {
  const scope =
    r.secrets.length > 0
      ? r.secrets.map((s) => s.reference).join(",")
      : r.ssh
        ? `${r.ssh.keyLabel}@${r.ssh.host}`
        : r.command.join(" ");
  return `${r.provenance.processChain.join(">")}|${r.provenance.cwd}|${scope}`;
}

export const store = new Store();

/**
 * The paired Mac's display name, as far as this phone can truthfully know it.
 * The steady-state connection carries no machine name (pairing pins keys, not
 * hostnames), so the name comes from what the Mac has actually said about
 * itself: the daemon-signed provenance on a live request, else the most recent
 * history entry. Null until a first request names it; screens fall back to
 * "your Mac". Never derived from a transport address: the relay is plumbing,
 * not a party, and its hostname must never stand in for the Mac.
 */
export function pairedMacName(s: AppState): string | null {
  for (const p of s.pending) {
    if (p.request.provenance.machine) return p.request.provenance.machine;
  }
  for (const h of s.history) {
    if (h.origin) return h.origin;
  }
  return null;
}

export function useAppState(): AppState {
  return useSyncExternalStore(store.subscribe, store.getState, store.getState);
}

/** Select a slice; re-renders only when the selected value's identity changes. */
export function useSelector<T>(selector: (s: AppState) => T): T {
  return useSyncExternalStore(
    store.subscribe,
    () => selector(store.getState()),
    () => selector(store.getState()),
  );
}
