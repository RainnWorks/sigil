# Pairing: the root of trust

Pairing is the one moment where Latch establishes who is who. Everything after
it (every secret release, every SSH signature, every lease) rests on the keys
pinned here. If pairing is sound, a fully hostile network can carry every byte
between the Mac and the phone and still never read a request or forge an
approval. This document describes the ceremony, the crypto that authenticates
it, and why each choice is the one made.

Implementation: `crates/proto/src/pairing.rs`. Tests: same file (`mod tests`)
plus the MITM suite the security-reviewer owns.

## The asymmetry, and why it exists

The two directions of pairing are protected by different things, on purpose.

**Mac -> phone is optical.** The Mac renders a QR code on its own screen; the
phone reads it with its camera. No network hop sits between a screen and a lens,
so this channel is authenticated *by physics*. A man-in-the-middle would have to
be physically present, pointing a second camera, replacing the image in real
time. Against that we do not defend with cryptography; we defend with the human
holding the two devices. The QR therefore safely carries the daemon's real
public keys, and the phone pins them with certainty.

**Phone -> Mac is a network message.** The phone's reply travels over whatever
transport is available (LAN, an owned endpoint, or the blind relay), and we
assume that transport is fully malicious: it can read, drop, reorder, duplicate,
mutate, and manufacture messages, and it knows both parties' *public* keys.
Nothing physical protects this leg. If it were unauthenticated, a network
attacker could substitute its own public key for the phone's, and the daemon
would pin the attacker as "the phone" — the attacker would then approve its own
requests forever. This is the one substitution the ceremony must stop.

The QR is what makes stopping it possible. Besides the daemon's public keys and
its reachable endpoints, the QR carries a **256-bit one-time pairing secret**
generated fresh from the CSPRNG. Because the QR moved optically, only the real
phone learns that secret. The phone's reply is authenticated by proving
possession of it. A network attacker who never saw the QR cannot produce a valid
proof, so it cannot pass off its own key. **The optical channel bootstraps a
secret; the secret closes the return channel.**

## The messages

| # | Name | Direction | Channel | Carries |
|---|------|-----------|---------|---------|
| 0 | `PairingPayload` | Mac -> phone | optical (QR) | daemon `PeerIdentity`, endpoints, `PairingSecret` (256-bit), `created_at` |
| 1 | `PairingResponse` | phone -> Mac | network | phone `PeerIdentity`, `nonce` (256-bit), confirmation `tag` (256-bit) |
| 2 | SAS | human | eyes / voice | six words, read off both screens and compared |
| 3 | DEK delivery | Mac -> phone | network | the 256-bit DEK, sealed to the phone's pinned key inside an `Envelope` |

Message 0 is the pre-existing `PairingPayload` (QR encode/decode unchanged).
Messages 1-3 are the handshake added here.

## The ceremony, step by step

1. **Mint (daemon, `PairingState::Init`).** `DaemonPairing::mint` generates the
   one-time secret, builds the `PairingPayload`, and keeps its own copy of the
   secret, its public identity, the endpoints, and `created_at`. The Mac renders
   the payload as a QR.

2. **Scan (phone, `PairingState::Scanned`).** `PhonePairing::scan` decodes the
   QR, rejects it if it is older than the secret lifetime, mints the phone's own
   Ed25519 + X25519 identity, and **pins the daemon's keys**. The daemon is now
   trusted absolutely by the phone, because the QR was optical.

3. **Respond (phone -> Mac).** `PhonePairing::respond` computes the transcript
   and the confirmation tag (below), packages them with the phone's public
   identity and a fresh nonce into a `PairingResponse`, and **consumes the
   phone's copy of the secret** (it is `take`-n out and zeroized as the call
   returns). The phone can respond exactly once.

4. **Verify + pin (daemon, `PairingState::ResponseReceived`).**
   `DaemonPairing::receive_response` enforces, in order: the secret has not
   already been consumed; the state is `Init`; the QR has not expired; and the
   confirmation tag verifies (constant-time). Only a cryptographically valid
   response burns the secret and pins the phone's key. A response that fails the
   tag leaves the secret intact, so a network attacker spraying garbage cannot
   exhaust it, while a *valid* one is one-time by construction.

5. **SAS (both, `PairingState::Confirmed`).** Both devices compute
   `fingerprint_words` over the two now-pinned identities and display the same
   six words. `sas_words()` on each driver returns them; `verify_sas` is the
   pure check. The human confirms the words match on both screens and calls
   `confirm()` on each side. See "Why SAS" below.

6. **DEK handoff (Mac -> phone, `PairingState::DekDelivered`).**
   `DaemonPairing::deliver_dek` seals the 256-bit DEK to the phone's pinned
   X25519 key inside a standard `Envelope` (crypto_box seal + Ed25519 signature
   + replay fields) and advances to `DekDelivered`. `PhonePairing::receive_dek`
   opens it and recovers the DEK. The daemon then erases its plaintext DEK; from
   here on the DEK arrives per-approval from the phone. The DEK may also be
   wrapped a second time to the Mac's Secure Enclave for local Touch ID
   approvals; because the Secure Enclave holds **only** P-256 keys (it cannot
   store or agree with an X25519 key), that second wrap is **P-256 ECIES**
   (`wrap_dek_for_se_p256`, see [The Mac Secure Enclave wrap](#the-mac-secure-enclave-wrap-p-256-ecies)),
   independent of the phone's X25519 envelope. `wrap_dek_for` remains available
   for wrapping to a second *X25519* recipient (e.g. a backup phone).

```mermaid
sequenceDiagram
    autonumber
    participant D as Mac daemon
    participant H as Human
    participant P as Phone
    Note over D: mint(): generate 256-bit secret,<br/>build QR payload — state Init
    D-->>H: render QR on screen
    H-->>P: point camera (OPTICAL, MITM-proof)
    Note over P: scan(): pin daemon keys,<br/>mint phone identity — state Scanned
    Note over P: respond(): tag = MAC over<br/>transcript(QR ∥ phone id ∥ nonce)<br/>secret consumed + zeroized
    P->>D: PairingResponse {phone id, nonce, tag}  (NETWORK, hostile)
    Note over D: receive_response():<br/>not-consumed → not-expired →<br/>verify tag (constant-time)<br/>pin phone — state ResponseReceived
    D-->>H: show 6 words
    P-->>H: show 6 words
    H->>H: compare (SAS backstop)
    H-->>D: confirm()
    H-->>P: confirm()
    Note over D,P: state Confirmed
    Note over D: deliver_dek(): seal DEK to phone's<br/>pinned X25519 key in an Envelope
    D->>P: Envelope(DEK)  (NETWORK, hostile)
    Note over P: receive_dek(): open, recover DEK<br/>— state DekDelivered
    Note over D: erase plaintext DEK
```

## The confirmation tag (how the secret closes the return channel)

The phone authenticates its reply with a MAC keyed by a value derived from the
pairing secret, over a transcript that binds everything that must not be
swapped.

**Transcript.** `pairing_transcript` hashes, with length-prefixed fields under a
domain separator (`latch.pairing.v1`):

```
H( domain
   ∥ daemon.verifying ∥ daemon.agreement      // who the phone thinks it is talking to
   ∥ endpoints                                 // the rest of the QR
   ∥ created_at
   ∥ phone.verifying ∥ phone.agreement         // the key being claimed
   ∥ nonce )                                   // uniqueness
```

Each binding earns its place:

- **daemon identity** — a response tagged for pairing A cannot be replayed
  against a freshly minted pairing B; B's daemon identity differs, so the
  transcript (and B's independent secret) reject it.
- **phone identity** — the tag covers exactly the key in the message. A network
  attacker who swaps `resp.phone` for its own key invalidates the tag and cannot
  recompute it without the secret. This is the core MITM defense.
- **nonce** — makes each response unique and one-shot.

The secret is deliberately **not** in the transcript; it is the MAC key, not
part of the signed message. So the transcript is a public value that leaks
nothing about the secret — a clean seam to hand a reviewer.

**Subkey then MAC.**

```
K_confirm = BLAKE2bMac(key = secret,    msg = domain ∥ "confirm-tag")   // KDF
tag       = BLAKE2bMac(key = K_confirm, msg = transcript)               // MAC
```

Verification recomputes the MAC and calls `Mac::verify_slice`, which compares in
**constant time**, so a wrong tag leaks no timing signal about how many bytes
matched.

## The Mac Secure Enclave wrap (P-256 ECIES)

The local-approval path unwraps the DEK *inside the Secure Enclave* under a live
Touch ID. The Secure Enclave can hold **only** NIST P-256 keys; it cannot store,
import, or key-agree with an X25519 key. So the Mac-SE DEK wrap cannot reuse the
phone's X25519 `crypto_box` envelope. It is a second, independent wrap of the
same DEK, using **P-256 ECIES**, and either factor (the phone's X25519 key or the
Mac SE's P-256 key) can recover the DEK on its own.

Implementation: `crates/proto/src/se_ecies.rs`
(`wrap_dek_p256` / `unwrap_dek_p256`), reached from the handshake via
`DaemonPairing::wrap_dek_for_se_p256`, which is gated on SAS `Confirmed` exactly
like the phone and X25519 wraps.

**The construction is interop-critical**: it must reproduce Apple's
`kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM` exactly so
that `SecKeyCreateDecryptedData` on the enclave side opens what the daemon
produces. The Mac app exports its SE public key in ANSI X9.63 uncompressed form
(`SecKeyCopyExternalRepresentation`, 65 bytes) at "Enable Mac approvals" time;
the daemon wraps the DEK to it as follows, for a P-256 recipient:

1. Generate an ephemeral P-256 key pair `(d_E, Q_E)`.
2. `Z = ECDH_cofactor(d_E, Q_recipient)` — the 32-byte big-endian X coordinate of
   the shared point. P-256's cofactor is 1, so cofactor ECDH equals plain ECDH.
3. ANSI-X9.63 KDF with SHA-256, deriving 32 bytes:
   `K = SHA256(Z ∥ 0x00000001 ∥ SharedInfo)`, where `SharedInfo = Q_E` in ANSI
   X9.63 uncompressed form (`0x04 ∥ X ∥ Y`, 65 bytes). 32 bytes fit one SHA-256
   block, so the KDF counter never advances past 1.
   - `aes_key = K[0..16]` — **AES-128** (Apple uses a 128-bit AES key for EC keys
     up to 256 bits, despite the `SHA256` in the algorithm name).
   - `iv = K[16..32]` — the **variable** 16-byte GCM IV. (The non-`VariableIV`
     algorithm would instead use a fixed all-zero 16-byte IV; we must match the
     `VariableIV` variant, which is what `se-selftest.swift` uses.)
4. AES-128-GCM over the 32-byte DEK with that key and 16-byte IV, empty AAD,
   producing a 16-byte tag.

**Wire format** (exactly what `SecKeyCreateDecryptedData` expects):

```text
Q_E (65 bytes, ANSI X9.63 0x04 ∥ X ∥ Y) ∥ ciphertext (== DEK len = 32) ∥ tag (16)
```

For a 32-byte DEK that is `65 + 32 + 16 = 113` bytes.

**Crypto choice, justified.** The Secure Enclave dictates P-256, so the wrap adds
the `p256` crate (RustCrypto ECDH, matching the tree's other RustCrypto
primitives). The KDF hash must be SHA-256 to interoperate with Apple, so `sha2`
is added (this crate's `blake2` cannot be substituted here). The AEAD is
AES-128-GCM with a 16-byte IV, reusing `aes-gcm` 0.10 already in the workspace
(the standard `Aes128Gcm` alias fixes a 12-byte nonce, so the IV size is named
explicitly as `AesGcm<Aes128, U16>`). Forward secrecy comes from the per-wrap
ephemeral key, as with the X25519 envelope.

**NEEDS VERIFICATION (on device).** The in-crate tests prove `wrap`/`unwrap` are
self-consistent in Rust; only real hardware proves Apple's decrypt agrees. Run
`swift apps/mac/Tools/se-selftest.swift` on Apple-silicon with an enrolled
biometric; it seals a known DEK with this same algorithm and unwraps it under
Touch ID, and its printed blob length must be 113.

## Crypto rules and the choices behind them

- **BLAKE2b for both KDF and MAC (no SHA-256, no `hkdf`/`hmac`/`sha2` crates).**
  The crate already depends on `blake2` (fingerprints and mailbox ids are
  BLAKE2b). BLAKE2b's keyed mode is a first-class PRF, so it serves as both
  HKDF-Expand and HMAC with zero new dependencies. SHA-256 would be an equally
  sound primitive but would pull three crates for no security gain. The `blake2`
  MAC type gives a constant-time `verify_slice` for free.
- **No HKDF-Extract.** RFC 5869 §3.3: extraction is only needed to condition
  non-uniform input keying material. Our IKM is a 256-bit CSPRNG output, already
  uniform, so we skip Extract and use Expand alone. `derive_subkey` is exactly
  HKDF-Expand with a single-block `info`.
- **No key reuse across purposes.** The MAC key is derived from the secret under
  a distinct label (`confirm-tag`) and is unrelated to the device signing and
  agreement keys, which are independent long-term keys. The pairing secret is
  used only to key the confirmation MAC and is then destroyed.
- **Constant-time comparison.** Tag verification is `verify_slice`, never `==`.
  `Dek`, `Envelope`, and `PairingResponse` deliberately do **not** implement
  `PartialEq`, so no accidental variable-time comparison of key or tag material
  can creep in.
- **CSPRNG everywhere.** The pairing secret, the response nonce, and the DEK all
  come from `rand_core::OsRng`.
- **Zeroization.** `PairingSecret` and `Dek` are `ZeroizeOnDrop` and redact
  their `Debug`. The phone `take`s the secret out on `respond()` so it is
  zeroized immediately, not merely when the driver drops. The `Envelope` seals
  and opens plaintext through `Zeroizing` buffers already.

## Why no PAKE

A PAKE (SPAKE2, OPAQUE, etc.) exists to turn a **low-entropy** shared secret — a
human-chosen password an attacker could guess offline — into a mutually
authenticated key without exposing it to a dictionary attack. That is not our
situation. Our shared secret is a full **256-bit CSPRNG value** transferred over
an optical channel; there is no low-entropy human input to protect and nothing
to guess. An online attacker gets one shot per response and the secret is
one-time; an offline attacker faces 2^256. A simple KDF-then-MAC proof of
possession is therefore exactly sufficient, and a PAKE would add protocol
rounds, code, and a dependency to defend against a threat (dictionary attack on
a weak password) that our secret does not have. High-entropy optical secret in,
plain MAC out.

## Why SAS is the human backstop

The tag already stops a network MITM, so what is SAS for? It is defense in
depth against the ways the tag's assumptions could fail:

- The secret leaking (a compromised QR: shoulder-surfed, photographed, screen
  captured). If someone else obtained the secret, they could forge a valid
  response. SAS catches it, because the six words are computed over the two
  *pinned* identities: if the daemon pinned an attacker's key instead of the
  phone's, the daemon's words and the phone's words differ, and the human sees
  the mismatch.
- Any future bug in the tag path. SAS is an independent check that does not
  share code with the MAC, so a mistake in one is caught by the other.

`fingerprint_words` is order-independent (it sorts the two identities before
hashing), so both devices derive the same six words iff they pinned the same
pair of keys. The words are shown on both screens; the human is the comparator.
Reading six words aloud is cheap and the failure mode is loud.

## Secret lifetime and one-time use

- **Lifetime.** `PAIRING_SECRET_TTL_MS` defaults to 180s. The phone rejects a
  stale QR at `scan`; the daemon rejects a late response at `receive_response`,
  checking expiry *before* the tag. A short window bounds how long a
  photographed QR is useful.
- **One-time (daemon side).** The first cryptographically valid response sets
  `consumed`; any later response — even a perfectly valid one from a second
  device that scanned the same QR — is refused with `SecretConsumed`. A failed
  attempt does not consume the secret, so a transient network error is
  recoverable but a second success is not possible.
- **One-time (phone side).** `respond()` `take`s the secret out and zeroizes it,
  so the phone likewise emits exactly one response.

## State machine

`PairingState` is the shared vocabulary; each driver enforces its own legal
transitions and returns `HandshakeError::WrongState` on any illegal one.

```
daemon:  Init ──receive_response──▶ ResponseReceived ──confirm──▶ Confirmed ──deliver_dek──▶ DekDelivered
phone:   Scanned ──(respond)──────────────────────────confirm──▶ Confirmed ──receive_dek──▶ DekDelivered
```

`deliver_dek` requires `Confirmed`: a key that no human ever confirmed via SAS
never receives the DEK. This is a hard gate, tested.

## Seams for the security-reviewer's MITM suite

The handshake is built to be attacked at clean, public boundaries. Each of these
is a documented place to mount an attack and assert it fails closed:

- **`PairingResponse` fields are public and mutable in a test.** Swap `phone`
  for an attacker key, flip a bit in `tag`, replace `nonce` — then assert
  `receive_response` returns `BadTag`. (`tag_rejected_when_phone_key_substituted`
  is the seed; the suite should fuzz every field.)
- **`PairingResponse::build` / `verify` are exposed.** Construct a response under
  a wrong secret, wrong daemon identity, or wrong endpoints and assert `verify`
  is `false`. Cross-pairing replay (`response_replayed_against_fresh_pairing`)
  goes here.
- **`pairing_transcript` binding.** The reviewer should confirm every bound field
  actually changes the transcript (mutate daemon id, endpoints, created_at,
  phone id, nonce independently and assert the tag no longer verifies).
- **Expiry and one-time-use gates.** Drive `receive_response` with a late clock
  (`SecretExpired`) and with a second valid response (`SecretConsumed`); confirm
  a failed attempt does *not* burn the secret.
- **SAS divergence.** `verify_sas` over mismatched daemon identities must be
  `false`; the suite should confirm the words diverge whenever the pinned pairs
  differ.
- **DEK delivery is a standard `Envelope`.** The full hostile-relay suite
  (`tests/hostile_relay.rs`) already applies: forge, tamper, replay, reorder,
  backdate. `open_dek` with a wrong sender key must be `BadSignature`; a wrong
  recipient must be `Decrypt`.
- **Constant-time.** Tag comparison is `verify_slice`; the reviewer should verify
  no `==` on tags/keys exists and that `Dek`/`PairingResponse` never gain
  `PartialEq`.

## Device-side unknowns — NEEDS VERIFICATION

This crate defines the protocol and its in-memory operations. The following
depend on platform behavior outside `crates/proto` and must be verified when the
device layers land:

- **NEEDS VERIFICATION:** the phone mints its X25519 agreement key such that the
  private half is usable for crypto_box `open` while ideally residing in
  StrongBox / Secure Enclave. If the platform keystore cannot perform X25519
  agreement in hardware, document where the private key lives in software and for
  how long.
- **NEEDS VERIFICATION (on device):** that the Mac Secure Enclave opens a DEK
  blob produced by `wrap_dek_for_se_p256` / `se_ecies::wrap_dek_p256`. The SE
  holds only a P-256 key, so the wrap is P-256 ECIES matching Apple's
  `eciesEncryptionCofactorVariableIVX963SHA256AESGCM` (see
  [The Mac Secure Enclave wrap](#the-mac-secure-enclave-wrap-p-256-ecies)). The
  Rust round-trip tests prove the construction is self-consistent, but only real
  hardware proves `SecKeyCreateDecryptedData` agrees byte-for-byte. Confirm with:

  ```sh
  swift apps/mac/Tools/se-selftest.swift
  ```

  It must run on Apple-silicon with an enrolled biometric (it cannot pass on a VM
  or the Simulator), and it prints the sealed-blob length, which must read 113
  for a 32-byte DEK.
- **NEEDS VERIFICATION:** QR camera capture fidelity and the practical upper
  bound on payload size (endpoints list length) for reliable single-frame scans.
- **NEEDS VERIFICATION:** clock skew between Mac and phone against the 180s TTL in
  the field; the envelope layer already enforces a separate 90s window on
  subsequent traffic.
