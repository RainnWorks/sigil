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
import { parseRelayOrigin, RelayMailbox, type RelayMailboxDeps } from "./relay-http";

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
  /** The optional, index-aligned origins sibling; omitted when undefined. */
  origins?: (unknown | null)[];
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
      json: async () =>
        r.origins === undefined
          ? { envelopes: r.envelopes ?? [] }
          : { envelopes: r.envelopes ?? [], origins: r.origins },
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

  // (e) The relay's origin hint: index-aligned, optional, and never able to
  // break a drain. The whole field is display-only hearsay from the adversary
  // in the threat model, so every malformed shape must cost the hint and only
  // the hint; the envelope is delivered either way.
  {
    const h = harness([
      {
        kind: "response",
        hold: 100,
        resp: {
          ok: true,
          status: 200,
          envelopes: ["first", "second", "third"],
          origins: [{ ip: "203.0.113.7", at_ms: 1_000 }, null, { ip: "198.51.100.4", at_ms: 1_000 }],
        },
      },
    ]);
    const mb = new RelayMailbox("https://relay.example", freshMailbox(), h.deps);
    const out = await mb.drain();
    eq(
      out.map((d) => d.env),
      ["first", "second", "third"],
      "(e) every envelope is delivered, order preserved",
    );
    eq(out[0]?.relayOrigin?.ip, "203.0.113.7", "(e) origins[0] lands on envelopes[0]");
    eq(out[1]?.relayOrigin, undefined, "(e) a null origin leaves that envelope without one");
    eq(out[2]?.relayOrigin?.ip, "198.51.100.4", "(e) index alignment holds past a null");
  }

  // (e') The pre-origin relay: no `origins` key at all, drain unchanged.
  {
    const h = harness([
      { kind: "response", hold: 100, resp: { ok: true, status: 200, envelopes: ["only"] } },
    ]);
    const mb = new RelayMailbox("https://relay.example", freshMailbox(), h.deps);
    const out = await mb.drain();
    eq(out.length, 1, "(e') an older relay still drains");
    eq(out[0]?.relayOrigin, undefined, "(e') absent origins yields no hint");
  }

  // (e'') A short / malformed origins array never drops or reorders envelopes.
  {
    const h = harness([
      {
        kind: "response",
        hold: 100,
        resp: {
          ok: true,
          status: 200,
          envelopes: ["a", "b"],
          origins: [{ ip: "203.0.113.7", at_ms: 1_000 }],
        },
      },
    ]);
    const mb = new RelayMailbox("https://relay.example", freshMailbox(), h.deps);
    const out = await mb.drain();
    eq(out.map((d) => d.env), ["a", "b"], "(e'') short origins array keeps both envelopes");
    eq(out[1]?.relayOrigin, undefined, "(e'') the unmatched envelope simply has no hint");
  }

  // (f) parseRelayOrigin is the hostile-input gate. A relay controls these bytes
  // completely and they land on the approval sheet, so anything that is not
  // plainly an IP literal at a plausible moment is dropped whole.
  {
    const now = 1_000_000;
    eq(parseRelayOrigin({ ip: "203.0.113.7", at_ms: now }, now)?.ip, "203.0.113.7", "(f) IPv4 accepted");
    eq(parseRelayOrigin({ ip: "2001:db8::1", at_ms: now }, now)?.ip, "2001:db8::1", "(f) IPv6 accepted");
    eq(
      parseRelayOrigin({ ip: "::ffff:192.0.2.128", at_ms: now }, now)?.ip,
      "::ffff:192.0.2.128",
      "(f) IPv4-mapped IPv6 accepted",
    );
    // Rust's IpAddr display never renders a zone, so the charset excludes it
    // rather than admitting arbitrary interface-name letters.
    eq(parseRelayOrigin({ ip: "fe80::1%en0", at_ms: now }, now), undefined, "(f) zone id rejected");
    eq(parseRelayOrigin({ ip: "203.0.113.7", at_ms: now }, now)?.atMs, now, "(f) at_ms maps to atMs");

    // The attack this gate exists for: free text buying a verified look.
    eq(
      parseRelayOrigin({ ip: "studio.local (verified)", at_ms: now }, now),
      undefined,
      "(f) spoof text rejected",
    );
    eq(parseRelayOrigin({ ip: "Tom's Mac", at_ms: now }, now), undefined, "(f) a name is not an address");
    eq(
      parseRelayOrigin({ ip: "1".repeat(46), at_ms: now }, now),
      undefined,
      "(f) over-long address rejected",
    );
    eq(parseRelayOrigin({ ip: "", at_ms: now }, now), undefined, "(f) empty address rejected");

    // Shape failures.
    eq(parseRelayOrigin(null, now), undefined, "(f) null rejected");
    eq(parseRelayOrigin("203.0.113.7", now), undefined, "(f) a bare string is not an origin");
    eq(parseRelayOrigin({ at_ms: now }, now), undefined, "(f) missing ip rejected");
    eq(parseRelayOrigin({ ip: "203.0.113.7" }, now), undefined, "(f) missing at_ms rejected");
    eq(parseRelayOrigin({ ip: "203.0.113.7", at_ms: "now" }, now), undefined, "(f) non-numeric at_ms rejected");
    eq(
      parseRelayOrigin({ ip: "203.0.113.7", at_ms: Number.NaN }, now),
      undefined,
      "(f) NaN at_ms rejected",
    );

    // Freshness: a stale or future-dated stamp describes some other moment, so
    // it is dropped rather than attached to this request.
    eq(
      parseRelayOrigin({ ip: "203.0.113.7", at_ms: now - 4 * 60_000 }, now)?.ip,
      "203.0.113.7",
      "(f) 4 minutes old still shown",
    );
    eq(
      parseRelayOrigin({ ip: "203.0.113.7", at_ms: now - 6 * 60_000 }, now),
      undefined,
      "(f) 6 minutes old dropped",
    );
    eq(
      parseRelayOrigin({ ip: "203.0.113.7", at_ms: now + 30_000 }, now)?.ip,
      "203.0.113.7",
      "(f) small forward skew tolerated",
    );
    eq(
      parseRelayOrigin({ ip: "203.0.113.7", at_ms: now + 120_000 }, now),
      undefined,
      "(f) far-future stamp dropped",
    );
  }

  console.log(failures === 0 ? "\nrelay-http self-test: all green" : `\nrelay-http self-test: ${failures} FAILED`);
  if (failures > 0) process.exit(1);
}

void main();
