/**
 * Selector suite for {@link LadderTransport}, the phone-side mirror of the
 * daemon's `sigil_direct::FallbackTransport`. It pins the downgrade-safety
 * properties: relay-identical with no direct rung, prefer-direct when the direct
 * rung is connected, fall back to the relay when a direct send throws, and
 * fan-in of inbound requests from both rungs.
 *
 * House style matches src/transport/relay-http.selftest.ts: a plain `bun run`
 * script with an `ok()` harness (no `bun:test`, so tsc stays clean and no new
 * dep). The `Transport` doubles are in-memory, so the suite runs with zero real
 * network. Run: `bun run src/transport/ladder-transport.selftest.ts`.
 */
import { type Envelope } from "@/src/protocol";
import { type Transport, type TransportStatus } from "./transport";
import { LadderTransport } from "./ladder-transport";

let failures = 0;
function ok(cond: boolean, label: string): void {
  if (cond) {
    console.log(`  ok    ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}`);
  }
}

/** A minimal fake envelope; the selector never inspects its contents. */
function fakeEnvelope(tag: string): Envelope {
  return { requestId: tag } as unknown as Envelope;
}

/**
 * An in-memory {@link Transport} double that records what it was asked to send,
 * lets a test drive inbound envelopes, and can be told to fail every send (to
 * exercise the fall-back path) and whether it reports itself connected.
 */
class FakeTransport implements Transport {
  sent: Envelope[] = [];
  started = false;
  failSend = false;
  private connected: boolean;
  private readonly rung: TransportStatus["rung"];
  private readonly listeners = new Set<(e: Envelope) => void>();

  constructor(rung: TransportStatus["rung"], connected = true) {
    this.rung = rung;
    this.connected = connected;
  }

  async start(): Promise<void> {
    this.started = true;
  }
  stop(): void {
    this.started = false;
    this.listeners.clear();
  }
  setConnected(v: boolean): void {
    this.connected = v;
  }
  status(): TransportStatus {
    return { rung: this.rung, connected: this.connected, machine: this.rung, lastSeenAt: 0 };
  }
  onEnvelope(cb: (e: Envelope) => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }
  async send(e: Envelope): Promise<void> {
    if (this.failSend) throw new Error("fake direct link down");
    this.sent.push(e);
  }
  /** Drive an inbound request as if it arrived from the daemon on this rung. */
  deliver(e: Envelope): void {
    for (const l of this.listeners) l(e);
  }
}

async function run(): Promise<void> {
  // 1. With no direct rung, the ladder is exactly the relay.
  {
    const relay = new FakeTransport("relay");
    const ladder = new LadderTransport({ relay });
    await ladder.start();
    await ladder.send(fakeEnvelope("a"));
    ok(relay.sent.length === 1, "no direct rung: send goes to the relay");
    ok(ladder.status().rung === "relay", "no direct rung: status is the relay's");
    ladder.stop();
  }

  // 2. A connected direct rung is preferred and the relay is skipped.
  {
    const relay = new FakeTransport("relay");
    const direct = new FakeTransport("lan", true);
    const ladder = new LadderTransport({ relay, direct });
    await ladder.start();
    await ladder.send(fakeEnvelope("b"));
    ok(direct.sent.length === 1, "connected direct rung: send goes direct");
    ok(relay.sent.length === 0, "connected direct rung: the relay is skipped");
    ok(ladder.status().rung === "lan", "connected direct rung: status shows the direct rung");
    ladder.stop();
  }

  // 3. A direct rung that is not connected is bypassed for the relay.
  {
    const relay = new FakeTransport("relay");
    const direct = new FakeTransport("lan", false);
    const ladder = new LadderTransport({ relay, direct });
    await ladder.start();
    await ladder.send(fakeEnvelope("c"));
    ok(direct.sent.length === 0, "disconnected direct rung: not used for send");
    ok(relay.sent.length === 1, "disconnected direct rung: relay carries the send");
    ladder.stop();
  }

  // 4. A direct send that throws falls back to the relay (no lost response).
  {
    const relay = new FakeTransport("relay");
    const direct = new FakeTransport("lan", true);
    direct.failSend = true;
    const ladder = new LadderTransport({ relay, direct });
    await ladder.start();
    await ladder.send(fakeEnvelope("d"));
    ok(relay.sent.length === 1, "direct send failure: falls back to the relay");
    ladder.stop();
  }

  // 5. mirrorSend also copies the response to the relay.
  {
    const relay = new FakeTransport("relay");
    const direct = new FakeTransport("lan", true);
    const ladder = new LadderTransport({ relay, direct, mirrorSend: true });
    await ladder.start();
    await ladder.send(fakeEnvelope("e"));
    ok(direct.sent.length === 1 && relay.sent.length === 1, "mirrorSend: both rungs carry the send");
    ladder.stop();
  }

  // 6. Inbound requests fan in from BOTH rungs.
  {
    const relay = new FakeTransport("relay");
    const direct = new FakeTransport("lan", true);
    const ladder = new LadderTransport({ relay, direct });
    const seen: string[] = [];
    ladder.onEnvelope((e) => seen.push((e as unknown as { requestId: string }).requestId));
    await ladder.start();
    relay.deliver(fakeEnvelope("via-relay"));
    direct.deliver(fakeEnvelope("via-direct"));
    ok(
      seen.includes("via-relay") && seen.includes("via-direct"),
      "inbound requests are delivered from both rungs",
    );
    ladder.stop();
  }

  if (failures > 0) {
    console.log(`\n${failures} FAILED`);
    process.exit(1);
  }
  console.log("\nall ok");
}

void run();
