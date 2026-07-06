/**
 * A tiny observable app store exposed through useSyncExternalStore. Single
 * source of truth for every screen; the mock transport and the demo seed both
 * write here, and the UI only ever reads. Fails closed: lockdown denies all
 * pending and refuses new requests until cleared.
 */
import { useSyncExternalStore } from "react";

import { type ApprovalRequest, type Decision } from "@/src/protocol";
import { secretRefLabel } from "@/src/lib/format";
import {
  type AppState,
  type HistoryEntry,
  type PendingRequest,
  type RequestState,
} from "@/src/domain/types";
import { demoInitialState, emptyInitialState } from "./demo";

type Listener = () => void;

/**
 * Demo/dev seed is OFF unless explicitly enabled. The shipping build boots from
 * the REAL empty state and hydrates the stored pairing from the keystore; only an
 * explicit dev flag replaces that with the canned demo data.
 */
export const DEMO = process.env.EXPO_PUBLIC_LATCH_DEMO === "1";

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

  /** A new request arrived. Identical grant keys coalesce behind the pending one. */
  receive(request: ApprovalRequest): void {
    if (this.state.arm === "lockedDown") return; // fail closed
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

  lockdown(): void {
    // Deny everything pending, refuse everything new. Denied requests are recorded
    // and cleared from the queue, so lockdown leaves nothing dangling.
    for (const p of this.state.pending) {
      if (p.state !== "approved" && p.state !== "denied" && p.state !== "expired") {
        this.record(p, "denied", "locked down");
      }
    }
    this.patch({ arm: "lockedDown", pending: [] });
  }

  clearLockdown(): void {
    this.patch({ arm: "armed" });
  }

  revokeLease(id: string): void {
    this.patch({ leases: this.state.leases.filter((l) => l.id !== id) });
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
   * the phone paired and arms it, unless it is currently locked down.
   */
  reflectPairing(info: { ownFingerprint: string | null; machine: string; seenAt: number }): void {
    this.patch({
      paired: true,
      arm: this.state.arm === "lockedDown" ? "lockedDown" : "armed",
      ownFingerprint: info.ownFingerprint,
      connection: { rung: "relay", machine: info.machine, lastSeenAt: info.seenAt },
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

  private record(p: PendingRequest, decision: Decision | "expired", note?: string): void {
    const r = p.request;
    const label =
      r.secrets.length > 0
        ? r.secrets.map(secretRefLabel).join(", ")
        : r.ssh
          ? `${r.ssh.keyLabel} → ${r.ssh.host}`
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

  /** Test/dev helper: seed pending requests directly. */
  seedPending(requests: ApprovalRequest[]): void {
    for (const r of requests) this.receive(r);
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
