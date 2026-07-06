// Tests for the shared APNs push-proxy (./push), the piece that moved from
// the daemon to the relay because the signing key is now a publisher secret.
// push.ts has zero Workers-specific imports (only Fetch and WebCrypto, both
// standard), so this one Bun-based suite fully covers it for both relay
// variants; there is no separate Worker suite for this module.
import { test, expect, afterEach } from "bun:test";
import { sendPush } from "./push";

// A throwaway P-256 PKCS#8 `.p8` PEM, generated fresh per run, so the signing
// path is exercised against a real key and no real Apple credential.
async function testKeyPem(): Promise<{ pem: string; publicKey: CryptoKey }> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const der = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
  const b64 = btoa(String.fromCharCode(...new Uint8Array(der)));
  const lines = b64.match(/.{1,64}/g) ?? [b64];
  const pem = `-----BEGIN PRIVATE KEY-----\n${lines.join("\n")}\n-----END PRIVATE KEY-----\n`;
  return { pem, publicKey: pair.publicKey };
}

function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

let stub: ReturnType<typeof Bun.serve> | undefined;
afterEach(() => {
  stub?.stop(true);
  stub = undefined;
});

test("rings a real ES256 JWT with the pinned identity, verifiable and well-formed", async () => {
  const { pem, publicKey } = await testKeyPem();
  let captured: {
    authorization: string;
    topic: string;
    pushType: string;
    priority: string;
    body: string;
  } | null = null;
  stub = Bun.serve({
    port: 0,
    fetch(req) {
      return req.text().then((body) => {
        captured = {
          authorization: req.headers.get("authorization") ?? "",
          topic: req.headers.get("apns-topic") ?? "",
          pushType: req.headers.get("apns-push-type") ?? "",
          priority: req.headers.get("apns-priority") ?? "",
          body,
        };
        return new Response(null, { status: 200 });
      });
    },
  });
  await sendPush(
    { token: "deadbeef", platform: "apns", keyPem: pem, host: `http://127.0.0.1:${stub.port}` },
    Date.now(),
  );
  expect(captured).not.toBeNull();
  const jwt = captured!.authorization.replace(/^bearer /, "");
  const [h, c, s] = jwt.split(".");
  expect(Boolean(h && c && s)).toBe(true);
  const header = JSON.parse(new TextDecoder().decode(b64urlDecode(h)));
  expect(header).toEqual({ alg: "ES256", kid: "5PCK76SDBA" });
  const claims = JSON.parse(new TextDecoder().decode(b64urlDecode(c)));
  expect(claims.iss).toBe("53W966FBFP");
  expect(typeof claims.iat).toBe("number");
  const verified = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    b64urlDecode(s),
    new TextEncoder().encode(`${h}.${c}`),
  );
  expect(verified).toBe(true);
  expect(captured!.topic).toBe("works.rainn.sigil");
  expect(captured!.pushType).toBe("alert");
  expect(captured!.priority).toBe("10");
  expect(JSON.parse(captured!.body)).toEqual({
    aps: {
      alert: { title: "Sigil", body: "Approval requested" },
      sound: "default",
      "content-available": 1,
    },
  });
});

test("carries no request-specific data: same fixed body regardless of caller input", async () => {
  const { pem } = await testKeyPem();
  const bodies: string[] = [];
  stub = Bun.serve({
    port: 0,
    fetch(req) {
      return req.text().then((b) => {
        bodies.push(b);
        return new Response(null, { status: 200 });
      });
    },
  });
  const host = `http://127.0.0.1:${stub.port}`;
  await sendPush({ token: "aa", platform: "apns", keyPem: pem, host }, Date.now());
  await sendPush({ token: "bb", platform: "apns", keyPem: pem, host }, Date.now());
  expect(bodies[0]).toBe(bodies[1]);
});

test("a rejection from Apple is swallowed: never throws", async () => {
  const { pem } = await testKeyPem();
  stub = Bun.serve({ port: 0, fetch: () => new Response("BadDeviceToken", { status: 400 }) });
  await expect(
    sendPush(
      { token: "deadbeef", platform: "apns", keyPem: pem, host: `http://127.0.0.1:${stub.port}` },
      Date.now(),
    ),
  ).resolves.toBeUndefined();
});

test("fcm is a stub: no network call is made", async () => {
  let hit = false;
  stub = Bun.serve({
    port: 0,
    fetch: () => {
      hit = true;
      return new Response(null, { status: 200 });
    },
  });
  await sendPush(
    { token: "deadbeef", platform: "fcm", keyPem: "irrelevant", host: `http://127.0.0.1:${stub.port}` },
    Date.now(),
  );
  expect(hit).toBe(false);
});

test("no configured key: no network call, never throws", async () => {
  let hit = false;
  stub = Bun.serve({
    port: 0,
    fetch: () => {
      hit = true;
      return new Response(null, { status: 200 });
    },
  });
  await sendPush(
    { token: "deadbeef", platform: "apns", keyPem: undefined, host: `http://127.0.0.1:${stub.port}` },
    Date.now(),
  );
  expect(hit).toBe(false);
});

test("undefined platform defaults to apns (matches the daemon's historical default)", async () => {
  const { pem } = await testKeyPem();
  let hit = false;
  stub = Bun.serve({
    port: 0,
    fetch: () => {
      hit = true;
      return new Response(null, { status: 200 });
    },
  });
  await sendPush(
    { token: "deadbeef", platform: undefined, keyPem: pem, host: `http://127.0.0.1:${stub.port}` },
    Date.now(),
  );
  expect(hit).toBe(true);
});
