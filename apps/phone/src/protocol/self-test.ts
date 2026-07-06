/**
 * Internal-consistency proof for the protocol layer, no Rust required. Runs the
 * full envelope loop and every rejection path through libsodium-wrappers, so
 * `npm run proto:selftest` fails loudly if a refactor breaks the crypto. The
 * cross-language guarantee comes from verify-vectors.ts; this proves the JS
 * side is coherent with itself and every branch is reachable.
 */
import { bytesEqual, toHex } from "./bytes";
import { EnvelopeOpenError, open, seal } from "./envelope";
import { fingerprintWords, mailboxId } from "./fingerprint";
import { agreementSecretKey, generateDeviceIdentity, type PeerIdentity, peerIdentity, signingSecretKey } from "./identity";
import { type PairingPayload, pairingFromQrString, pairingToQrString } from "./pairing";
import { buildPairingResponseWithNonce, rendezvousMailbox } from "./pairing-handshake";
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
    recipientAgreementSecret: agreementSecretKey(sodium, phone),
    guard,
  });
  ok(got.note === payload.note, "seal/open round trip delivers payload");

  // 2. Exact replay of the same envelope is rejected (single-use id).
  try {
    open(sodium, env, {
      sender: daemonPub,
      recipientAgreementSecret: agreementSecretKey(sodium, phone),
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
      recipientAgreementSecret: agreementSecretKey(sodium, phone),
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
      recipientAgreementSecret: agreementSecretKey(sodium, stranger),
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
      recipientAgreementSecret: agreementSecretKey(sodium, phone),
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

  // 9. Pairing handshake parity: the rendezvous mailbox and the confirmation tag
  // over fixed inputs must equal the values the Rust proto produces. These two
  // hex constants were produced by crates/proto (rendezvous_mailbox for the
  // mailbox; the tag was accepted by the real DaemonPairing::verify), via the
  // read-only parity harness. If either drifts, the phone can no longer pair with
  // a real daemon. Pattern helper mirrors the harness's fixed key material.
  const pattern = (mul: number, add: number): Uint8Array => {
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = (i * mul + add) & 0xff;
    return out;
  };
  const pairDaemon: PeerIdentity = { verifying: pattern(7, 1), agreement: pattern(3, 5) };
  const pairSecret = pattern(5, 9);
  const pairPhone: PeerIdentity = { verifying: pattern(11, 2), agreement: pattern(13, 4) };
  const pairNonce = pattern(17, 6);
  const pairPayload: PairingPayload = {
    daemon: pairDaemon,
    endpoints: ["https://relay.latch.test"],
    secret: pairSecret,
    createdAt: 1_720_000_000_000,
  };
  const EXPECTED_MAILBOX = "f8f5836f143eed1bfb3b6cc3639f904452a3b2284f0e04f28f2b997a4f9de42e";
  const EXPECTED_TAG = "9fcaa8fc71458a31ef409b4096ea57fd12031cd5b1c4790e3f25b83fcf9a8129";
  ok(
    toHex(rendezvousMailbox(sodium, pairDaemon, pairSecret)) === EXPECTED_MAILBOX,
    "rendezvous mailbox matches proto (rust vector)",
  );
  const pairResp = buildPairingResponseWithNonce(sodium, pairPayload, pairPhone, pairNonce);
  ok(toHex(pairResp.tag) === EXPECTED_TAG, "pairing confirmation tag matches proto (rust-verified)");

  console.log(failures === 0 ? "\nprotocol self-test: all green" : `\nprotocol self-test: ${failures} FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
