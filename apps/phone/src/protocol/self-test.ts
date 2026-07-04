/**
 * Internal-consistency proof for the protocol layer, no Rust required. Runs the
 * full envelope loop and every rejection path through libsodium-wrappers, so
 * `npm run proto:selftest` fails loudly if a refactor breaks the crypto. The
 * cross-language guarantee comes from verify-vectors.ts; this proves the JS
 * side is coherent with itself and every branch is reachable.
 */
import { bytesEqual } from "./bytes";
import { EnvelopeOpenError, open, seal } from "./envelope";
import { fingerprintWords, mailboxId } from "./fingerprint";
import { generateDeviceIdentity, peerIdentity, signingSecretKey } from "./identity";
import { pairingFromQrString, pairingToQrString } from "./pairing";
import { ReplayGuard } from "./replay";
import { loadSodiumForTests } from "./sodium-node";

let failures = 0;
function ok(cond: boolean, label: string): void {
  if (cond) {
    console.log(`  ok    ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}`);
  }
}

async function main(): Promise<void> {
  const sodium = await loadSodiumForTests();

  const phone = generateDeviceIdentity(sodium);
  const daemon = generateDeviceIdentity(sodium);
  const phonePub = peerIdentity(sodium, phone);
  const daemonPub = peerIdentity(sodium, daemon);
  const pairingId = mailboxId(sodium, phonePub, daemonPub);

  // 1. Round trip: daemon seals a request to the phone, phone opens it.
  const payload = { requestId: "demo", note: "unlock Engineering/.env" };
  const env = seal(sodium, payload, {
    pairingId,
    counter: 1,
    senderSigningSecret: signingSecretKey(sodium, daemon),
    recipient: phonePub,
  });
  const guard = new ReplayGuard();
  const got = open<typeof payload>(sodium, env, {
    sender: daemonPub,
    recipientAgreementSecret: phone.agreementSecret,
    guard,
  });
  ok(got.note === payload.note, "seal/open round trip delivers payload");

  // 2. Exact replay of the same envelope is rejected (single-use id).
  try {
    open(sodium, env, {
      sender: daemonPub,
      recipientAgreementSecret: phone.agreementSecret,
      guard,
    });
    ok(false, "replay rejected");
  } catch (e) {
    ok(e instanceof EnvelopeOpenError && e.detail.kind === "replay", "replay rejected");
  }

  // 3. A forged sender is rejected before any state changes.
  const impostor = peerIdentity(sodium, generateDeviceIdentity(sodium));
  try {
    open(sodium, seal(sodium, payload, {
      pairingId,
      counter: 2,
      senderSigningSecret: signingSecretKey(sodium, daemon),
      recipient: phonePub,
    }), {
      sender: impostor,
      recipientAgreementSecret: phone.agreementSecret,
      guard: new ReplayGuard(),
    });
    ok(false, "forged sender rejected");
  } catch (e) {
    ok(e instanceof EnvelopeOpenError && e.detail.kind === "badSignature", "forged sender rejected");
  }

  // 4. Wrong recipient verifies the signature but cannot decrypt.
  const stranger = generateDeviceIdentity(sodium);
  try {
    open(sodium, seal(sodium, payload, {
      pairingId,
      counter: 3,
      senderSigningSecret: signingSecretKey(sodium, daemon),
      recipient: phonePub,
    }), {
      sender: daemonPub,
      recipientAgreementSecret: stranger.agreementSecret,
      guard: new ReplayGuard(),
    });
    ok(false, "wrong recipient cannot decrypt");
  } catch (e) {
    ok(e instanceof EnvelopeOpenError && e.detail.kind === "decrypt", "wrong recipient cannot decrypt");
  }

  // 5. Any tampered field breaks the signature.
  const base = seal(sodium, payload, {
    pairingId,
    counter: 4,
    senderSigningSecret: signingSecretKey(sodium, daemon),
    recipient: phonePub,
  });
  const tampered = { ...base, ciphertext: Uint8Array.from(base.ciphertext) };
  tampered.ciphertext[0] = (tampered.ciphertext[0] ?? 0) ^ 1;
  try {
    open(sodium, tampered, {
      sender: daemonPub,
      recipientAgreementSecret: phone.agreementSecret,
      guard: new ReplayGuard(),
    });
    ok(false, "tampered ciphertext rejected");
  } catch (e) {
    ok(e instanceof EnvelopeOpenError && e.detail.kind === "badSignature", "tampered ciphertext rejected");
  }

  // 6. Fingerprint words are order-independent (both devices read the same).
  const wordsAB = fingerprintWords(sodium, phonePub, daemonPub).join(" ");
  const wordsBA = fingerprintWords(sodium, daemonPub, phonePub).join(" ");
  ok(wordsAB === wordsBA, `fingerprint order-independent (${wordsAB})`);

  // 7. Mailbox id is order-independent too.
  const mbxBA = mailboxId(sodium, daemonPub, phonePub);
  ok(bytesEqual(pairingId, mbxBA), "mailbox id order-independent");

  // 8. Pairing QR round trip preserves the payload.
  const secret = sodium.randombytes_buf(32);
  const qr = pairingToQrString({
    daemon: daemonPub,
    endpoints: ["lan://latch.local:4823", "https://tide.example.net:4823"],
    secret,
    createdAt: 1_720_000_000_000,
  });
  ok(!qr.includes("=") && !qr.includes("+") && !qr.includes("/"), "pairing QR is padding-free base64url");
  const back = pairingFromQrString(qr);
  ok(
    bytesEqual(back.daemon.verifying, daemonPub.verifying) &&
      bytesEqual(back.secret, secret) &&
      back.endpoints.length === 2,
    "pairing QR round trip",
  );

  console.log(failures === 0 ? "\nprotocol self-test: all green" : `\nprotocol self-test: ${failures} FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
