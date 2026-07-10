/**
 * Poll-storm regression suite for {@link RelayMailbox.waitOne}. The relay's
 * long-poll is a single-holder-per-slot doorbell; a client that re-fires on any
 * fast-empty return (server eviction, 429, blip) becomes a network-speed
 * hammer. These checks pin the backoff floor, the 429 handling, the normal
 * ~25s-hold fast path, and the one-loop-per-slot dedupe - the four failure
 * modes behind the "~66 GET/min against a 60/min limit" pairing storm.
 *
 * House style matches src/protocol/self-test.ts: a plain `bun run` script with
 * an `ok()` harness (no `bun:test`, so tsc stays clean and no new dep). Time is
 * injected (a fake clock advanced by fetch/sleep), so the suite runs with zero
 * real waits. Run: `bun run src/transport/relay-http.selftest.ts`.
 */
import { RelayMailbox, type RelayMailboxDeps } from "./relay-http";

let failures = 0;
function ok(cond: boolean, label: string): void {
  if (cond) {
    console.log(`  ok    ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}`);
  }
}
function eq<T>(a: T, b: T, label: string): void {
  ok(JSON.stringify(a) === JSON.stringify(b), `${label} (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`);
}

/** The subset of `fetch`'s Response that the module reads. */
interface FakeResp {
  ok: boolean;
  status: number;
  headers?: Record<string, string>;
  envelopes?: string[];
}

/** One scripted `to-phone` GET outcome; `hold` is the simulated server-side hold, ms. */
type Step = { kind: "response"; hold: number; resp: FakeResp } | { kind: "throw"; hold: number };

/**
 * A deterministic harness: a monotonic fake clock, a fetch that advances it by
 * each scripted step's `hold`, and a sleep that advances it by the requested ms
 * while recording every delay the loop chose. `random: () => 0` disables jitter
 * so the floors assert exactly.
 */
function harness(steps: Step[]): { deps: RelayMailboxDeps; sleeps: number[]; fetchCount: () => number } {
  let clock = 1_000;
  let i = 0;
  const sleeps: number[] = [];
  let fetches = 0;

  const sleep = (ms: number, signal: AbortSignal): Promise<void> => {
    if (signal.aborted) return Promise.resolve();
    sleeps.push(ms);
    clock += ms;
    return Promise.resolve();
  };

  const fetchImpl = (async (_url: string, init?: { signal?: AbortSignal }) => {
    fetches += 1;
    if (init?.signal?.aborted) throw new Error("aborted");
    const step = steps[Math.min(i, steps.length - 1)];
    i += 1;
    if (!step) throw new Error("harness: no step");
    clock += step.hold;
    if (step.kind === "throw") throw new Error("network");
    const r = step.resp;
    return {
      ok: r.ok,
      status: r.status,
      headers: { get: (name: string) => r.headers?.[name.toLowerCase()] ?? null },
      json: async () => ({ envelopes: r.envelopes ?? [] }),
    };
  }) as unknown as typeof fetch;

  return { deps: { fetch: fetchImpl, now: () => clock, sleep, random: () => 0 }, sleeps, fetchCount: () => fetches };
}

/** Unique mailbox per case so the process-wide `activeWaits` slot registry never collides. */
let mailboxCounter = 0;
function freshMailbox(): Uint8Array {
  const m = new Uint8Array(4);
  const n = ++mailboxCounter;
  m[0] = n & 0xff;
  m[1] = (n >> 8) & 0xff;
  return m;
}

async function main(): Promise<void> {
  // (a) Consecutive fast-empty returns back off exponentially, never instant re-poll.
  {
    const h = harness([{ kind: "response", hold: 100, resp: { ok: true, status: 200, envelopes: [] } }]);
    const mb = new RelayMailbox("https://relay.example", freshMailbox(), h.deps);
    const out = await mb.waitOne(60_000);
    ok(out === null, "(a) fast-empty storm resolves null at deadline");
    eq(h.sleeps.slice(0, 5), [1_000, 2_000, 4_000, 8_000, 16_000], "(a) backoff curve 1,2,4,8,16s");
    ok(
      h.sleeps.every((s) => s > 0),
      "(a) never a zero/instant re-poll",
    );
  }

  // (b) A 429 backs off instead of throwing into a retry hammer.
  {
    const h = harness([{ kind: "response", hold: 50, resp: { ok: false, status: 429 } }]);
    const mb = new RelayMailbox("https://relay.example", freshMailbox(), h.deps);
    const out = await mb.waitOne(30_000);
    ok(out === null, "(b) 429 resolves null, not rejected");
    eq(h.sleeps[0], 1_000, "(b) 429 backs off from base, not instant");
  }

  // (b') A 429 with Retry-After honors the server's delay.
  {
    const h = harness([
      { kind: "response", hold: 50, resp: { ok: false, status: 429, headers: { "retry-after": "7" } } },
    ]);
    const mb = new RelayMailbox("https://relay.example", freshMailbox(), h.deps);
    await mb.waitOne(60_000);
    eq(h.sleeps[0], 7_000, "(b') Retry-After: 7 => 7s floor, not 1s base");
  }

  // (b'') A network blip backs off, does not throw.
  {
    const h = harness([{ kind: "throw", hold: 30 }]);
    const mb = new RelayMailbox("https://relay.example", freshMailbox(), h.deps);
    const out = await mb.waitOne(20_000);
    ok(out === null, "(b'') network blip resolves null, not rejected");
    eq(h.sleeps[0], 1_000, "(b'') network blip backs off from base");
  }

  // (c) A real ~25s hold that returns empty re-polls promptly (no over-throttling).
  {
    const h = harness([{ kind: "response", hold: 25_000, resp: { ok: true, status: 200, envelopes: [] } }]);
    const mb = new RelayMailbox("https://relay.example", freshMailbox(), h.deps);
    await mb.waitOne(80_000);
    ok(h.sleeps.length >= 2, "(c) multiple holds fit in the window");
    ok(
      h.sleeps.every((s) => s === 250),
      "(c) held-empty re-polls at the 250ms prompt floor, no backoff",
    );
  }

  // (c') A real hold resets backoff accrued from earlier fast returns.
  {
    const h = harness([
      { kind: "response", hold: 80, resp: { ok: true, status: 200, envelopes: [] } }, // fast -> 1000
      { kind: "response", hold: 80, resp: { ok: true, status: 200, envelopes: [] } }, // fast -> 2000
      { kind: "response", hold: 25_000, resp: { ok: true, status: 200, envelopes: [] } }, // held -> 250
      { kind: "response", hold: 25_000, resp: { ok: true, status: 200, envelopes: ["payload"] } },
    ]);
    const mb = new RelayMailbox("https://relay.example", freshMailbox(), h.deps);
    const out = await mb.waitOne(120_000);
    eq(out, "payload", "(c') payload delivered after recovery");
    eq(h.sleeps, [1_000, 2_000, 250], "(c') hold resets backoff to the prompt floor");
  }

  // Delivers the first payload immediately: no backoff, no wait.
  {
    const h = harness([{ kind: "response", hold: 200, resp: { ok: true, status: 200, envelopes: ["hi"] } }]);
    const mb = new RelayMailbox("https://relay.example", freshMailbox(), h.deps);
    const out = await mb.waitOne(30_000);
    eq(out, "hi", "payload returned on first GET");
    eq(h.sleeps, [], "no sleep before returning a payload");
  }

  // (d) Two waitOne calls on the same slot do not both run: the first is superseded.
  {
    const slot = freshMailbox();
    let releaseFirst: (() => void) | null = null;
    let firstStarted: (() => void) | null = null;
    const firstStartedP = new Promise<void>((r) => (firstStarted = r));

    let clock = 0;
    const now = () => clock;
    const sleep = (ms: number): Promise<void> => {
      clock += ms;
      return Promise.resolve();
    };

    const fetch1 = (async (_url: string, init?: { signal?: AbortSignal }) => {
      firstStarted?.();
      await new Promise<void>((resolve, reject) => {
        releaseFirst = resolve;
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      });
      return { ok: true, status: 200, headers: { get: () => null }, json: async () => ({ envelopes: [] }) };
    }) as unknown as typeof fetch;

    const fetch2 = (async () => ({
      ok: true,
      status: 200,
      headers: { get: () => null },
      json: async () => ({ envelopes: ["from-second"] }),
    })) as unknown as typeof fetch;

    const mb1 = new RelayMailbox("https://relay.example", slot, { fetch: fetch1, now, sleep, random: () => 0 });
    const mb2 = new RelayMailbox("https://relay.example", slot, { fetch: fetch2, now, sleep, random: () => 0 });

    const p1 = mb1.waitOne(60_000);
    await firstStartedP; // loop 1 owns the slot before loop 2 starts
    const p2 = mb2.waitOne(60_000);
    const [r1, r2] = await Promise.all([p1, p2]);

    ok(r1 === null, "(d) first loop was superseded/aborted, resolves null");
    eq(r2, "from-second", "(d) second loop is the sole survivor");
    ok(releaseFirst !== null, "(d) first unblocked via abort, never via a payload");
  }

  console.log(failures === 0 ? "\nrelay-http self-test: all green" : `\nrelay-http self-test: ${failures} FAILED`);
  if (failures > 0) process.exit(1);
}

void main();
