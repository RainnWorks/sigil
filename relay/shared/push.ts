// The APNs push "doorbell": a content-free notification the relay sends on the
// PUBLISHER's behalf to wake a paired phone so it drains the real, sealed
// request waiting for it. Ported from crates/sigil/src/apns.rs (which used to
// live on the daemon) to here, because the ES256 signing key is a publisher
// secret: Sigil is a free, many-user product with one shared relay, and no
// user's Mac can be trusted to hold Rainnworks' APNs key. The relay is the one
// party positioned to hold it.
//
// Zero-knowledge payload: the push body is fixed and generic ("Approval
// requested"). It carries no caller, command, account, secret, or reason; it
// only tells the phone "check the mailbox". Best-effort, fail-open: every
// failure here is logged and swallowed. The deposit that triggered it has
// already succeeded, and the phone's own poll backstop covers a missed or
// failed push. Correctness never depends on this module.
//
// Uses only Fetch and WebCrypto (SubtleCrypto), both standard on Workers and
// on Bun, so this one module is the shared, byte-identical push behaviour for
// both relay variants; there is no per-runtime push code to keep in sync.

const APNS_HOST = "https://api.push.apple.com";
const APNS_TOPIC = "works.rainn.sigil";
const APNS_TEAM_ID = "53W966FBFP";
const APNS_KEY_ID = "5PCK76SDBA";

/** Refresh the JWT before Apple's ~60 minute cap; see crates/sigil/src/apns.rs
 * for why ~50 minutes is the sweet spot. */
const JWT_REFRESH_MS = 50 * 60 * 1000;
/** How long a single APNs POST may take before giving up (fail-open). */
const SEND_TIMEOUT_MS = 5_000;

/** The fixed, request-free push payload. Generic by design; see module docs. */
const DOORBELL_BODY = JSON.stringify({
  aps: {
    alert: { title: "Sigil", body: "Approval requested" },
    sound: "default",
    "content-available": 1,
  },
});

function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (const b of arr) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode a PKCS#8 `.p8` PEM into its raw DER bytes. */
function pemToDer(pem: string): Uint8Array<ArrayBuffer> {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  const bin = atob(body);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function importSigningKey(pem: string): Promise<CryptoKey> {
  const der = pemToDer(pem);
  return crypto.subtle.importKey("pkcs8", der, { name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
  ]);
}

/** A cached provider JWT plus the imported key it was signed with, so a
 * repeated ring() within the refresh window neither re-imports nor re-signs.
 * Keyed loosely by the PEM string; if it ever changes, the cache just misses. */
let cached: { pem: string; key: CryptoKey; bearer: string; mintedAt: number } | null = null;

/**
 * Mint (ES256, header `{alg,kid}`, claims `{iss,iat}`) or reuse a cached
 * provider JWT. WebCrypto's ECDSA signature is already the raw 64-byte `r||s`
 * that JWS ES256 requires, so no re-encoding is needed.
 */
async function bearer(pem: string, nowMs: number): Promise<string> {
  if (cached && cached.pem === pem && nowMs - cached.mintedAt < JWT_REFRESH_MS) {
    return cached.bearer;
  }
  const key = cached && cached.pem === pem ? cached.key : await importSigningKey(pem);
  const enc = new TextEncoder();
  const header = b64url(enc.encode(`{"alg":"ES256","kid":"${APNS_KEY_ID}"}`));
  const claims = b64url(enc.encode(`{"iss":"${APNS_TEAM_ID}","iat":${Math.floor(nowMs / 1000)}}`));
  const signingInput = `${header}.${claims}`;
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(signingInput));
  const jwt = `${signingInput}.${b64url(sig)}`;
  cached = { pem, key, bearer: jwt, mintedAt: nowMs };
  return jwt;
}

/**
 * Ring the doorbell for one device token (lowercase hex). Never throws: every
 * failure is logged and swallowed, because correctness never depends on the
 * push landing. `host` is overridable so tests can point this at a local stub
 * instead of the real Apple endpoint.
 */
async function ringApns(token: string, keyPem: string, nowMs: number, host: string): Promise<void> {
  try {
    const jwt = await bearer(keyPem, nowMs);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), SEND_TIMEOUT_MS);
    let resp: Response;
    try {
      resp = await fetch(`${host}/3/device/${token}`, {
        method: "POST",
        headers: {
          authorization: `bearer ${jwt}`,
          "apns-topic": APNS_TOPIC,
          "apns-push-type": "alert",
          "apns-priority": "10",
          "content-type": "application/json",
        },
        body: DOORBELL_BODY,
        signal: ctrl.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    if (!resp.ok) {
      console.error(`push: apns rejected the doorbell: ${resp.status} ${await resp.text()}`);
    }
  } catch (e) {
    console.error(`push: apns doorbell failed, relying on the poll backstop: ${e}`);
  }
}

/**
 * Best-effort doorbell dispatch for one deposit's optional push token. Never
 * throws and never blocks correctness on Apple: call it (awaited or not) and
 * move on regardless of the outcome. `platform` other than `"fcm"` is treated
 * as APNs, matching the daemon's historical default from before FCM existed.
 */
export async function sendPush(
  input: { token: string; platform: string | undefined; keyPem: string | undefined; host?: string },
  nowMs: number,
): Promise<void> {
  if (input.platform === "fcm") {
    console.error("push: fcm not implemented yet, relying on the poll backstop");
    return;
  }
  if (!input.keyPem) {
    console.error("push: no APNs signing key configured, relying on the poll backstop");
    return;
  }
  await ringApns(input.token, input.keyPem, nowMs, input.host ?? APNS_HOST);
}
