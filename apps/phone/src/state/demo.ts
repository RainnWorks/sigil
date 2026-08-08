/**
 * Canned data so every screen and every approval-sheet state is reachable in a
 * dev build with no daemon and no relay. The mock transport (mock-transport.ts)
 * replays these through the real crypto path; the store can also seed them
 * directly for pure-UI iteration.
 */
import { type ApprovalRequest } from "@/src/protocol";
import { emptyLeaseView } from "@/src/domain/leases";
import {
  type ActiveLease,
  type AppState,
  type HistoryEntry,
  type LeaseView,
  type RelayOrigin,
} from "@/src/domain/types";

const now = Date.now();

/** The hero request from the brief: elevated read of a production secret. */
export function demoReadRequest(overrides: Partial<ApprovalRequest> = {}): ApprovalRequest {
  return {
    requestId: crypto.randomUUID(),
    kind: "secret_read",
    command: ["op", "read", "op://Production/AWS-prod/access-key"],
    secrets: [
      {
        provider: "1password",
        reference: "op://Production/AWS-prod/access-key",
        segments: ["Production", "AWS-prod", "access-key"],
        label: "AWS-prod",
      },
    ],
    provenance: {
      processChain: ["zsh", "claude", "op read"],
      cwd: "~/Projects/rowm-api",
      machine: "studio.local",
      requestedAt: now,
    },
    reason: "Production vault. First request from this process.",
    expiresAt: now + 60_000,
    timeoutMs: 60_000,
    ...overrides,
  };
}

/** A routine dev-vault read: tap to approve. */
export function demoRoutineRequest(): ApprovalRequest {
  return demoReadRequest({
    requestId: crypto.randomUUID(),
    command: ["op", "read", "op://Engineering/.env/graphql-api"],
    secrets: [
      {
        provider: "1password",
        reference: "op://Engineering/.env/graphql-api",
        segments: ["Engineering", ".env", "graphql-api"],
        label: ".env",
      },
    ],
    reason: undefined,
    // Leasable grant: the sheet offers approve-once vs keep-approved-for-a-window
    // (task #57). Run-once demos omit this and show approve-once only. `covers`
    // is the daemon's own description of the matched rule, which the caption
    // states verbatim; real ones range from a bare "op" to a full phrase like
    // "op read with --vault, containing \"prod\"", so exercise a middle shape.
    leasePolicy: { kind: "leasable", maxSecs: 900, covers: "op read with --vault" },
    provenance: {
      processChain: ["zsh", "claude", "op read"],
      cwd: "~/Projects/rowm",
      machine: "studio.local",
      requestedAt: now,
    },
  });
}

/**
 * A v2 threshold read: elevated, carrying a ThresholdChallenge so the approve
 * path exercises the Secure Enclave partial (Z_F). The
 * `ephemeralPub` is a real on-curve P-256 X9.63 point (from the shared combiner
 * vectors), so on-device validation and key-agreement have a valid E to work on.
 */
export function demoThresholdRequest(): ApprovalRequest {
  return demoReadRequest({
    requestId: crypto.randomUUID(),
    command: ["op", "read", "op://Production/stripe/secret-key"],
    secrets: [
      {
        provider: "1password",
        reference: "op://Production/stripe/secret-key",
        segments: ["Production", "stripe", "secret-key"],
        label: "stripe",
      },
    ],
    reason: "Production vault, two-party unlock.",
    threshold: {
      accountId: "acct-threshold-01",
      label: "Rowm work",
      ephemeralPub:
        "BDL7XFpNKQfd2BPO8UdFsbtiq03vEUbm1UKEQlvXYOB2HFHIzga7fiN4tvA07gU1Y+Djqw6GsJ5Svb3nx8x6fvw=",
      seKeyId: "se-key-1",
      ecdhAlgo: "raw-x",
    },
    provenance: {
      processChain: ["zsh", "claude", "op read"],
      cwd: "~/Projects/rowm-api",
      machine: "studio.local",
      requestedAt: now,
    },
  });
}

/** An SSH signature to a known host: the destination is a known-hosts name. */
export function demoSshRequest(): ApprovalRequest {
  return {
    requestId: crypto.randomUUID(),
    kind: "ssh_signature",
    command: ["ssh", "git@github.com"],
    secrets: [],
    ssh: {
      keyLabel: "github-deploy",
      host: "github.com",
      binding: "named",
      fingerprint: "SHA256:9Xk2p+Qm4rLt8vN0wYbZ3fJc1aDhEoRuS5iT7gUx6M",
    },
    provenance: {
      processChain: ["ssh", "git"],
      cwd: "~/Projects/infra",
      machine: "studio.local",
      requestedAt: now,
    },
    reason: "Signature to a production host.",
    expiresAt: now + 90_000,
    timeoutMs: 90_000,
  };
}

/**
 * An SSH signature with no host binding: the client sent no session-bind, so
 * the destination is unverified and the sheet must say so (F8). The `host`
 * string mirrors the daemon's plain marker and must never be rendered.
 */
export function demoUnboundSshRequest(): ApprovalRequest {
  const r = demoSshRequest();
  return {
    ...r,
    requestId: crypto.randomUUID(),
    command: ["ssh"],
    ssh: {
      keyLabel: "legacy-bastion",
      host: "(host not bound)",
      binding: "unbound",
      fingerprint: "SHA256:2vJq8wXr5tZk1mBn7cYd4fLh9aGpEsRu3iToUx0KgN",
    },
    reason: undefined,
  };
}

/**
 * A stand-in for the relay's origin hint, so the sheet's `network` row is
 * reachable in a demo build. A documentation-range address (RFC 5737), never a
 * real one. Demo only: a live pairing shows this row solely when the relay
 * actually sent a claim that passed validation.
 */
export const demoRelayOrigin: RelayOrigin = { ip: "203.0.113.7", atMs: now };

/**
 * Sample lease rows for a DEMO build only, in the same shape a real answer
 * arrives in. The identifiers are made up: they name no real window, so the
 * revoke control in a demo build has no daemon to answer it and lands in the
 * unconfirmed state, which is itself worth being able to look at. The screen labels these as
 * samples wherever they appear; they never reach a Release build.
 */
export const demoLeases: ActiveLease[] = [
  {
    leaseId: "d3m0".repeat(8),
    // A rule name, not a secret path: the lease covers every command that rule
    // matches for this caller until it lapses.
    scope: "op-eu",
    covers: 'op with --account "rowmhq.1password.eu"',
    account: "rowmhq.1password.eu",
    expiresAt: now + 41 * 60_000,
    windowMs: 41 * 60_000,
  },
];

/** A demo lease view: a snapshot taken a moment ago, so the samples read fresh. */
export function demoLeaseView(): LeaseView {
  return { ...emptyLeaseView(), rows: demoLeases, askedAt: now, asOfMs: now, arrivedAt: now };
}

export const demoHistory: HistoryEntry[] = [
  {
    id: "h1",
    kind: "secret_read",
    label: "Engineering/.env › graphql-api",
    origin: "studio.local",
    process: "claude",
    cwd: "~/Projects/rowm",
    decision: "approved",
    at: now - 55 * 60_000,
    via: "phone",
  },
  {
    id: "h2",
    kind: "ssh_signature",
    label: "github-deploy → github.com",
    origin: "studio.local",
    process: "ssh",
    cwd: "~/Projects/rowm",
    decision: "approved",
    at: now - 54 * 60_000,
    via: "rule",
  },
  {
    id: "h3",
    kind: "secret_read",
    label: "AWS-prod › access-key",
    origin: "studio.local",
    process: "zsh",
    cwd: "~/Projects/infra",
    decision: "denied",
    note: "not me",
    at: now - 30 * 60_000,
    via: "phone",
  },
  {
    id: "h4",
    kind: "secret_read",
    label: "Personal/router › password",
    origin: "studio.local",
    process: "zsh",
    cwd: "~/Projects/home",
    decision: "expired",
    at: now - 20 * 60_000,
    via: "phone",
  },
];

/** The settings every fresh install starts with; shared by both seeds. */
export function defaultSettings(): AppState["settings"] {
  return {
    faceIdBeforeApprove: true,
    reduceMotion: false,
    defaultTimeoutSec: 90,
    notificationsEnabled: true,
  };
}

/**
 * The REAL shipping boot state: unpaired, nothing seen yet. The store starts here
 * and then hydrates from the device keystore — if a real pairing is stored the
 * session controller flips `paired` on; if not, the app routes into pairing. No
 * demo data ever reaches a Release build through this path.
 */
export function emptyInitialState(): AppState {
  return {
    paired: false,
    arm: "idle",
    connection: { rung: "none", lastSeenAt: 0 },
    pairedAt: 0,
    pending: [],
    history: [],
    leases: emptyLeaseView(),
    settings: defaultSettings(),
    pairingWords: null,
    ownFingerprint: null,
  };
}

export function demoInitialState(): AppState {
  return {
    paired: true,
    arm: "armed",
    connection: { rung: "lan", lastSeenAt: now - 12_000 },
    pairedAt: now - 6 * 86_400_000,
    pending: [],
    history: demoHistory,
    leases: demoLeaseView(),
    settings: defaultSettings(),
    pairingWords: null,
    ownFingerprint: "tide brass anchor harbor reef mast",
  };
}
