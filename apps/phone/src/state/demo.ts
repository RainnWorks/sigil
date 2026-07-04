/**
 * Canned data so every screen and every approval-sheet state is reachable in a
 * dev build with no daemon and no relay. The mock transport (mock-transport.ts)
 * replays these through the real crypto path; the store can also seed them
 * directly for pure-UI iteration.
 */
import { type ApprovalRequest } from "@/src/protocol";
import {
  type Account,
  type AppState,
  type HistoryEntry,
  type Lease,
} from "@/src/domain/types";

const now = Date.now();

/** The hero request from the brief: elevated read of a production secret. */
export function demoReadRequest(overrides: Partial<ApprovalRequest> = {}): ApprovalRequest {
  return {
    requestId: crypto.randomUUID(),
    kind: "read_secret",
    accountLabel: "Rowm work",
    secret: { account: "Rowm", vault: "Production", item: "AWS-prod", field: "access-key" },
    provenance: {
      processChain: ["zsh", "claude", "op read"],
      cwd: "~/Projects/rowm-api",
      machine: "studio.local",
      requestedAt: now,
    },
    risk: "elevated",
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
    accountLabel: "Rowm work",
    secret: { account: "Rowm", vault: "Engineering", item: ".env", field: "graphql-api" },
    risk: "routine",
    reason: undefined,
    provenance: {
      processChain: ["zsh", "claude", "op read"],
      cwd: "~/Projects/rowm",
      machine: "studio.local",
      requestedAt: now,
    },
  });
}

/** A critical SSH signature to a production host: hold to approve. */
export function demoSshRequest(): ApprovalRequest {
  return {
    requestId: crypto.randomUUID(),
    kind: "ssh_signature",
    accountLabel: "Rowm work",
    ssh: {
      keyLabel: "github-deploy",
      host: "git@github.com",
      fingerprint: "SHA256:9Xk2p+Qm4rLt8vN0wYbZ3fJc1aDhEoRuS5iT7gUx6M",
    },
    provenance: {
      processChain: ["ssh", "git"],
      cwd: "~/Projects/infra",
      machine: "studio.local",
      requestedAt: now,
    },
    risk: "critical",
    reason: "Signature to a production host.",
    expiresAt: now + 90_000,
    timeoutMs: 90_000,
  };
}

export const demoAccounts: Account[] = [
  { id: "a1", label: "Rowm work", vaults: 2, health: "healthy", lastUsedAt: now - 4 * 60_000 },
  {
    id: "a2",
    label: "Personal",
    vaults: 1,
    health: "rotate",
    detail: "rotate in 6d",
    lastUsedAt: now - 2 * 24 * 3600_000,
  },
];

export const demoLeases: Lease[] = [
  {
    id: "l1",
    caller: "rowm launcher",
    scope: "Engineering/.env",
    grantedAt: now - 19 * 60_000,
    expiresAt: now + 41 * 60_000,
  },
];

export const demoHistory: HistoryEntry[] = [
  {
    id: "h1",
    kind: "read_secret",
    label: "Engineering/.env › graphql-api",
    account: "Rowm work",
    process: "claude",
    cwd: "~/Projects/rowm",
    decision: "approved",
    at: now - 55 * 60_000,
    via: "phone",
  },
  {
    id: "h2",
    kind: "ssh_signature",
    label: "github-deploy → git@github.com",
    account: "Rowm work",
    process: "ssh",
    cwd: "~/Projects/rowm",
    decision: "approved",
    at: now - 54 * 60_000,
    via: "rule",
  },
  {
    id: "h3",
    kind: "read_secret",
    label: "AWS-prod › access-key",
    account: "Rowm work",
    process: "zsh",
    cwd: "~/Projects/infra",
    decision: "denied",
    note: "not me",
    at: now - 30 * 60_000,
    via: "phone",
  },
  {
    id: "h4",
    kind: "read_secret",
    label: "Personal/router › password",
    account: "Personal",
    process: "zsh",
    cwd: "~/Projects/home",
    decision: "expired",
    at: now - 20 * 60_000,
    via: "phone",
  },
];

export function demoInitialState(): AppState {
  return {
    paired: true,
    arm: "armed",
    connection: { rung: "lan", machine: "studio.local", lastSeenAt: now - 12_000 },
    pending: [],
    history: demoHistory,
    accounts: demoAccounts,
    leases: demoLeases,
    settings: {
      faceIdBeforeApprove: true,
      reduceMotion: false,
      defaultTimeoutSec: 90,
      notificationsEnabled: true,
    },
    pairingWords: null,
    ownFingerprint: "tide brass anchor harbor reef mast",
  };
}
