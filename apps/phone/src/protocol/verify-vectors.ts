/**
 * Replays the shared test vectors exported by crates/proto through this TS
 * implementation. Run with `npm run proto:vectors` (Node with type stripping).
 * If the vector file is absent it prints how to produce it and exits 0, so the
 * suite is a no-op until rust-core wires up the export, then a hard gate.
 *
 * Intended to become a CI job: build the Rust vectors, then run this.
 */
import { createCipheriv } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { concatBytes, fromHex, toHex } from "./bytes";
import { canonicalBytes, EnvelopeOpenError, open } from "./envelope";
import { fingerprintWords, mailboxId } from "./fingerprint";
import { pairingToQrString } from "./pairing";
import { ReplayGuard, ReplayRejected } from "./replay";
import { loadSodiumForTests } from "./sodium-node";
import { combine } from "./threshold";
import { envelopeFromWire, type EnvelopeWire } from "./wire";
import { type LatchVectors, VECTORS_PATH } from "./vectors.contract";

/**
 * AES-256-GCM seal returning ciphertext‖tag, mirroring proto `aead_seal`. Uses
 * Node's crypto (this file is Node-only); the phone runtime never runs AES — the
 * Mac holds the AEAD leg — so this stays out of the app bundle. Locking token_ct
 * proves the derived K feeds the same AEAD the daemon uses.
 */
function aeadSeal(key: Uint8Array, nonce: Uint8Array, pt: Uint8Array): Uint8Array {
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ct = concatBytes(new Uint8Array(cipher.update(pt)), new Uint8Array(cipher.final()));
  return concatBytes(ct, new Uint8Array(cipher.getAuthTag()));
}

function peer(p: { verifying: string; agreement: string }) {
  return { verifying: fromHex(p.verifying), agreement: fromHex(p.agreement) };
}

async function main(): Promise<void> {
  const path = resolve(process.cwd(), VECTORS_PATH);
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    console.log(`no shared vectors at ${VECTORS_PATH} yet.`);
    console.log("produce them from the rust proto crate, then re-run:");
    console.log("  (rust-core) cargo test -p latch-proto --features export-vectors");
    console.log("  cp <exported>/latch-vectors.json apps/phone/" + VECTORS_PATH);
    process.exit(0);
    return;
  }

  const sodium = await loadSodiumForTests();
  const v = JSON.parse(raw) as LatchVectors;
  let pass = 0;
  const fails: string[] = [];
  const check = (ok: boolean, label: string) => {
    if (ok) pass++;
    else fails.push(label);
  };

  for (const c of v.canonicalBytes) {
    const got = toHex(
      canonicalBytes({
        pairingId: fromHex(c.pairingId),
        requestId: c.requestId,
        counter: c.counter,
        ts: c.ts,
        ephemeralPub: fromHex(c.ephemeralPub),
        nonce: fromHex(c.nonce),
        ciphertext: fromHex(c.ciphertext),
      }),
    );
    check(got === c.expected, `canonicalBytes/${c.name}`);
  }

  for (const [i, f] of v.fingerprint.entries()) {
    const words = fingerprintWords(sodium, peer(f.a), peer(f.b));
    const mbx = toHex(mailboxId(sodium, peer(f.a), peer(f.b)));
    check(words.join(" ") === f.words.join(" "), `fingerprint[${i}]/words`);
    check(mbx === f.mailboxId, `fingerprint[${i}]/mailbox`);
  }

  for (const [i, q] of v.pairingQr.entries()) {
    const got = pairingToQrString({
      daemon: peer(q.daemon),
      endpoints: q.endpoints,
      secret: fromHex(q.secret),
      createdAt: q.createdAt,
    });
    check(got === q.expected, `pairingQr[${i}]`);
  }

  for (const o of v.open) {
    const guard = new ReplayGuard();
    try {
      const payload = open(sodium, envelopeFromWire(o.envelope as EnvelopeWire), {
        sender: peer(o.sender),
        recipientAgreementSecret: fromHex(o.recipientAgreementSecret),
        guard,
        now: o.now,
      });
      const gotJson = JSON.stringify(payload);
      check(o.expectOk && gotJson === o.expectedPayloadJson, `open/${o.name}`);
    } catch (err) {
      const kind = err instanceof EnvelopeOpenError ? err.detail.kind : "throw";
      check(!o.expectOk && kind === o.expectError, `open/${o.name}`);
    }
  }

  for (const r of v.replay) {
    const guard = new ReplayGuard();
    let allOk = true;
    for (const [i, s] of r.steps.entries()) {
      try {
        guard.checkAndRecord(s.requestId, s.counter, s.ts, s.now, r.windowMs);
        if (!s.expectOk) allOk = false;
      } catch (err) {
        const kind = err instanceof ReplayRejected ? err.detail.kind : "throw";
        if (s.expectOk || kind !== s.expectError) allOk = false;
      }
      void i;
    }
    check(allOk, `replay/${r.name}`);
  }

  for (const c of v.combiner ?? []) {
    const k = combine(sodium, fromHex(c.zm), fromHex(c.zf), fromHex(c.ephemeralPub), c.accountId);
    check(toHex(k) === c.expectedK, `combiner/${c.name}/K`);
    const ct = aeadSeal(k, fromHex(c.aeadNonce), fromHex(c.token));
    check(toHex(ct) === c.expectedTokenCt, `combiner/${c.name}/tokenCt`);
  }

  console.log(`vectors: ${pass} passed, ${fails.length} failed`);
  if (fails.length) {
    for (const f of fails) console.log(`  FAIL ${f}`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
