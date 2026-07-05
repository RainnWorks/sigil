# Threshold v2: per-request two-party decryption (retiring the static DEK)

**Status: DESIGN ONLY. No running code changes with this document.** v1 (the
static DEK delivered per-approval from the phone) is live in a demo and is
untouched here. Everything below is a *versioned, additive* successor gated
behind a new account-store `version` and a new pairing capability; a v1 daemon
neither reads nor is affected by any v2 field. This is the rust-core design
deliverable; per the review-integrity rule in `CLAUDE.md`, the "reviewed and
found sound" verdict is written by the independent security-reviewer, not here.
This document states behavior, the exact math and wire formats, the residuals,
and an explicit open-questions list for that reviewer.

Companion docs: `docs/design/pairing.md` (root of trust), `docs/security-claims.md`
(claim → code → test map), `crates/proto/src/se_ecies.rs` (the P-256/Apple-ECIES
prior art this reuses), `crates/proto/src/{envelope,request,identity}.rs` (the
wire types v2 extends).

---

## 1. The problem v2 solves, and the blast-radius target

**v1 today.** Account tokens are `AES-256-GCM(token; DEK)` at rest
(`secrets.rs::encrypt_token`). A single 256-bit **DEK** is generated at pairing,
sealed to the phone, and then erased from the daemon (`pairing.md` §DEK handoff).
Per request the phone returns *that same DEK* inside the sealed `ApprovalResponse`
(`request.rs::ApprovalResponse::approve` → `wrapped_dek`). The daemon decrypts the
one token and zeroizes the DEK.

**The flaw Tom named.** The phone's contribution is a *static long-term unlock
key*. The DEK is identical on every request. Capture it once — a single daemon
RAM scrape during any one approval, or the sealed-at-pairing delivery — and you
hold the key to **every account, forever, with no further approval**. The DEK is
a skeleton key that merely happens to be stored on the phone.

**The v2 target.** Decryption becomes a **per-request two-party operation** in
which:

1. No single stored value unlocks anything. The key is split into a Mac share
   and a phone share; **neither party ever holds the full private scalar**, and
   neither share alone can decrypt.
2. The phone's contribution is produced **fresh inside the Secure Enclave under
   Face ID** on each request; the phone's long-term secret **never leaves the
   SE** and is non-exportable.
3. Key material lives in daemon memory for the **minimum possible** time
   (mlock'd, zeroized immediately), and no full private key is ever assembled
   anywhere.

**Blast-radius improvement (quantified, derived in §9/§11).**

| | v1 static DEK | v2 threshold |
|---|---|---|
| One capture unlocks | **all** accounts | **one** account (the one whose partial was captured) |
| Duration | **forever**, no further approval | that account **until it re-keys** |
| Also requires | nothing (DEK is self-sufficient) | the Mac share `m` **and** a live Face-ID-approved request for that exact account |
| Obtainable from | pairing delivery, or any daemon scrape | only a daemon scrape *at the instant of an approved decrypt* — when the plaintext token is already exposed anyway |

The static skeleton key is gone. What remains is a per-account value that is only
exposed at the exact moment the token itself is, and is only *reusable* by an
attacker who already holds the separate Mac share.

---

## 2. Primitives

Fixed, and justified against the constraints of the two secure hardware
environments (iOS Secure Enclave, macOS keystore) and the crate's existing
dependency set.

- **Curve: NIST P-256 (secp256r1).** Forced by the Secure Enclave, which holds
  **P-256 only** — it cannot store, import, or key-agree with X25519 (`pairing.md`
  §"The Mac Secure Enclave wrap"; Apple `SecureEnclave.P256`). RustCrypto `p256`
  is already a workspace dependency (`se_ecies.rs`). Cofactor `h = 1`, so cofactor
  ECDH equals plain ECDH. Generator `G`; scalars are elements of the prime-order
  scalar field; points are written in ANSI X9.63 uncompressed form
  (`0x04 ∥ X ∥ Y`, 65 bytes) on the wire.
- **ECDH: raw shared secret = the 32-byte big-endian X-coordinate.** On the phone,
  `SecureEnclave.P256.KeyAgreement.sharedSecretFromKeyAgreement` (CryptoKit) or
  `SecKeyCopyKeyExchangeResult(_, .ecdhKeyExchangeStandard, _, _)` (Security
  framework) — both return the raw X-coordinate, length = key length, **no KDF**
  (Apple: "the shared secret should never be used directly … input into a KDF").
  On the Mac, `p256::ecdh::diffie_hellman(scalar, point).raw_secret_bytes()`
  returns the identical 32-byte X-coordinate. This exact-match is what makes the
  scheme in §4 work without any point reconstruction.
- **KDF: keyed BLAKE2b** (the crate's `derive_subkey`, an HKDF-Expand-shaped
  single-block PRF over a length-prefixed `info`; `pairing.md` §"Crypto rules").
  BLAKE2b everywhere is the house rule — no new `hkdf`/`hmac`/`sha2` for the
  combiner. (The one exception, `se_ecies.rs`, uses SHA-256 *only* because Apple's
  ECIES KDF is fixed to SHA-256; the combiner here is ours to choose, so it is
  BLAKE2b.) Domain separator: `latch.threshold.v2`.
- **AEAD: AES-256-GCM, unchanged from v1** (`secrets.rs::encrypt_token`), 96-bit
  random nonce per seal. v2 changes only *where the 32-byte key comes from*, not
  the token-ciphertext format. This is deliberate: the at-rest token blob is
  byte-identical to v1's, which keeps migration and code blast-radius minimal.
- **Envelope: unchanged** (`envelope.rs`): crypto_box (X25519 + XSalsa20-Poly1305)
  seal + Ed25519 signature + uuidv7 request-id + per-pairing monotonic counter +
  90 s window. The threshold partials ride *inside* this existing sealed, signed,
  replay-guarded envelope. The pairing X25519 agreement key and the new P-256
  threshold key are **independent** keys with independent jobs (transport seal vs.
  token-key share).

---

## 3. The Secure Enclave constraint, stated precisely, and the crux

The team lead flagged this as the crux, so it is stated exactly and resolved
explicitly.

**What the SE gives.** For a P-256 private key `f` resident in the Secure Enclave
and a supplied public point `E`, the SE computes `f · E` **inside the enclave**
and returns only the **X-coordinate** of that point: a 32-byte big-endian scalar
`x(f · E)` (optionally passed through Apple's ANSI-X9.63 KDF if a `…X963…`
algorithm is chosen). It does **not** return the full affine point `(x, y)`. The
private scalar `f` never leaves the enclave; the returned X-coordinate reveals
nothing about `f` (recovering `f` from `f · E` is the elliptic-curve discrete-log
problem).

**Why this breaks naive additive threshold.** A textbook two-party additive
scheme forms a combined public key `P = M + F` (with `M = m · G`, `F = f · G`),
encrypts to `P` with ephemeral `E = e · G` so the shared point is
`S = e · P = (m + f) · E = m·E + f·E`, and derives the key as `KDF(x(S))`. To
decrypt, the two parties must recombine `S = m·E + f·E`. The Mac can produce the
**full point** `m·E` (it holds `m` in software). But the phone can only return
`x(f·E)` — the **X-coordinate**, not the full point `f·E` — and **elliptic-curve
point addition requires full affine points**. From `x` alone you can recover `y`
only up to sign (two candidates `±y` via a modular square root), so additive
combination on real SE output forces: a modular sqrt, a 1-bit sign ambiguity, and
a 2-way trial decryption resolved by the GCM tag. It is *implementable* but it is
a footgun (software EC point arithmetic on SE-derived material, sign-trial logic),
and — critically — **it buys nothing**: the additive combined secret `(m+f)·E` is
just as static-per-token as the alternative, so it neither improves security nor
enables blinding (§9). Additive is the wrong tool.

**The resolution — use the SE output verbatim (recommended).** Do **not** form a
single combined point. Instead derive the token key from **two independent ECDH
secrets, AND-combined by a KDF**:

```
Z_M = x(m · E)            // Mac's partial, full software, RustCrypto p256
Z_F = x(f · E)            // phone's partial, exactly what the SE returns
K   = KDF( "latch.threshold.v2" ∥ len·Z_M ∥ len·Z_F ∥ len·E_x963 ∥ len·account_id )
```

`Z_F` is *precisely and only* the raw X-coordinate the Secure Enclave emits —
"a scheme where the phone's SE ECDH output is directly usable." No point
reconstruction, no sign ambiguity, no trial decryption, no software point
addition. This is the standard KEM-combiner (concatenate independent shared
secrets, hash) and it is a genuine **2-of-2 AND**: computing `K` requires *both*
`Z_M` and `Z_F`, i.e. the ability to run *both* ECDHs. Neither party can do the
other's. (Security reduces to computational Diffie-Hellman on P-256 for each
factor, with the KDF modeled as a random oracle / PRF; see §11.)

The rest of this document specifies the concatenative scheme. §4 keeps the
additive analysis on record because requirement 1 named `P = M + F`; the honest
finding is that the SE's X-only output makes additive strictly worse here, and
the concatenative dual-ECDH construction is the right realization of the same
goal (two parties, no skeleton key, phone share in the SE, per-request Face ID).

---

## 4. Additive (`P = M + F`) vs. concatenative — the decision

| | Additive `P = M + F` | Concatenative dual-ECDH (recommended) |
|---|---|---|
| Ciphertext | one ECIES to a single point `P` | one AES-256-GCM under `K` + a stored `E` |
| Decrypt needs from phone | **full point** `f·E` | **X-coordinate** `x(f·E)` |
| SE can supply that? | **No** (X-only) → sqrt + sign-trial workaround | **Yes, verbatim** |
| Software EC point ops on SE output | required | none |
| Security level | 2-of-2, CDH | 2-of-2, CDH (identical) |
| Enables per-request key freshness? | No (see §9) | No (see §9) |
| Third-party can encrypt to it | yes (knows only `P`) — irrelevant, encryptor is always the Mac | n/a |

Additive's only distinctive property (a third party who knows `P` but not the
split can encrypt) is worthless to Latch: the encryptor is **always the Mac**,
which holds the split. Against that non-benefit it pays SE point-reconstruction
complexity. **Decision: concatenative.**

---

## 5. Setup — minting the shares and pairing (v2)

Two new long-term keys are introduced, one per device. Both are minted the same
way whether at a fresh v2 pairing or via an upgrade ceremony on an existing v1
pairing (§12).

**Mac share `m` (software scalar, in the keystore seam).**
- `m ← p256::SecretKey::random(OsRng)`; `M = m·G`.
- `m` is stored **sealed in the platform keystore** (login Keychain on macOS),
  exactly like the daemon's long-term identity today (`pairing_store.rs`
  `store_blob(DAEMON_IDENTITY_LABEL, …)`). It is **not** put in the Mac Secure
  Enclave: the daemon must compute `m·E` in software during a *remote* (phone)
  approval, when no Touch ID is present; an SE-resident `m` would force a local
  Touch ID on every remote request, defeating the product. `m` is therefore a
  share held in Mac secure memory, per the requirement — not the Mac SE.
- `M` (the public point) never needs to leave the Mac; only the Mac ever encrypts
  to the pair (§6), so the phone does not need `M`.

**Phone share `f` (non-exportable, Secure Enclave).**
- `f` is generated **in the Secure Enclave**:
  `kSecAttrKeyType = kSecAttrKeyTypeECSECPrimeRandom`,
  `kSecAttrKeySizeInBits = 256`,
  `kSecAttrTokenID = kSecAttrTokenIDSecureEnclave`, with an access control of
  `kSecAccessControlPrivateKeyUsage | .biometryCurrentSet` (Face ID / current
  biometric set required for every key-agreement use; invalidated if the
  enrolled biometric set changes). No `kSecAttrIsExtractable` — the private half
  is non-exportable by construction. (CryptoKit equivalent:
  `SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl:…)`.)
- The phone exports `F` (the public point) in ANSI X9.63 form (65 bytes) via
  `SecKeyCopyExternalRepresentation` / `.publicKey.x963Representation`.
- `f` **never leaves the SE**. The only value that ever exits is a per-request
  X-coordinate `x(f·E)`, which is not `f`.

**Exchanging the public shares.** `F` is delivered from phone to Mac inside a
**standard sealed, signed `Envelope`** (the same crypto_box + Ed25519 + replay
path as DEK handoff), so a hostile relay can neither read nor forge it, and the
Mac pins `F` under the already-pinned phone identity. In a fresh v2 pairing this
is a new message after SAS `Confirmed` (replacing the v1 "DEK delivery" message
3 of `pairing.md`); in an upgrade it is a one-shot `latch pair upgrade` envelope
(§12). The Mac's `M` stays local.

**What the account store persists (v2 record).** Per account, at
`latch account add` (a CLI-only mutation, per the design brief — the
network-exposed daemon never mutates keys/config):

```
AccountRecordV2 {
  version:        2,
  account_id:     string,          // stable id, also folded into the KDF
  ephemeral_pub:  [u8; 65],        // E = e·G, ANSI X9.63 — the per-account ECDH base
  aead_nonce:     [u8; 12],        // AES-256-GCM nonce
  token_ct:       Vec<u8>,         // AES-256-GCM(token; K, aead_nonce) — identical format to v1
  se_key_id:      string,          // which pinned phone SE key F this was wrapped to
  kdf_algo:       "blake2b-v2",    // combiner id (future-proofing)
  ecdh_algo:      "raw-x" | "x963-sha256",  // which SE ECDH output shape Z_F is (see NV-2)
}
```

Note what is **not** stored: no `K`, no `Z_M`, no `Z_F`, and crucially **not `e`**
(the ephemeral scalar). Only `E = e·G` (public) is kept. This is the linchpin of
§11: once `e` is destroyed, `Z_F = x(f·E)` is computable *only* by the holder of
`f` (the phone SE), because recovering it from `E` and `F` is the computational
Diffie-Hellman problem.

**Encrypting the token at account-add (a pure Mac operation, no phone needed).**
```
e  ← random scalar;  E = e·G
Z_M = x(e·M)          // = x(m·E); Mac holds m, uses e·M or m·E, same value
Z_F = x(e·F)          // = x(f·E); Mac holds e and the pinned public F — no phone, no f
K   = KDF("latch.threshold.v2" ∥ Z_M ∥ Z_F ∥ E_x963 ∥ account_id)
token_ct = AES-256-GCM(token; K, nonce)
store AccountRecordV2{ E, nonce, token_ct, … };  zeroize e, Z_M, Z_F, K
```

Account-add is the **one moment** the Mac transiently holds a full `K` — exactly
as v1's pairing was the one moment the Mac held the DEK before erasing it. It is a
human-present, one-time CLI ceremony. After it, `e` is gone and the Mac holds only
a *share* (`m`); it can never re-derive `Z_F` alone.

---

## 6. Per-request decryption

Given an approved request for an account whose record is `{E, nonce, token_ct}`:

```
Mac (daemon, remote-phone approval):
  1. reads E from the account record
  2. loads m from the keystore into an mlock'd Zeroizing buffer
  3. Z_M = x(m·E)              // p256 diffie_hellman(m, E).raw_secret_bytes()
  4. seals an ApprovalRequest carrying the threshold challenge {account_id, E} to the phone

Phone (inside an approved, verified request — see §8):
  5. verifies Mac signature + replay guard on the ApprovalRequest  (BEFORE any SE op)
  6. displays the command/secret to the user; Face ID
  7. Z_F = x(f·E)             // SE key-agreement of the pinned F-private with E
  8. seals ApprovalResponse carrying {account_id, Z_F} back to the Mac (Decision=Approved)

Mac:
  9.  opens the response (verify sig + replay + decrypt)
  10. K = KDF("latch.threshold.v2" ∥ Z_M ∥ Z_F ∥ E_x963 ∥ account_id)
  11. token = AES-256-GCM^{-1}(token_ct; K, nonce)   // fails closed if K wrong
  12. inject token into the provider child env (unchanged), splice child stdout to caller
  13. zeroize m, Z_M, Z_F, K, token immediately
```

The **combine** (step 10) is a single BLAKE2b keyed hash over the length-prefixed
concatenation of the two X-coordinates plus the account's `E` and id; no point
arithmetic. `Z_M` and `Z_F` are both raw 32-byte X-coordinates that agree
byte-for-byte with the values computed at account-add (step math: `x(m·E)` at
decrypt = `x(e·M)` at encrypt; `x(f·E)` at decrypt = `x(e·F)` at encrypt — ECDH
symmetry). If `Z_F` is wrong or absent, `K` is wrong and the GCM tag fails: **fail
closed, no token**.

**Local (Mac Touch ID) approval** is symmetric with the roles reversed only in
*who runs the SE op*: `Z_F` would come from the phone as above, OR — if a
future local factor mints a Mac-SE analogue of `f` — from the Mac SE under Touch
ID. For v2 the phone is the `Z_F` source; the Mac SE `se_ecies.rs` path stays the
independent second wrap of a *v1-style DEK* it is today (§12 keeps them disjoint).

---

## 7. Wire-format changes

All additive and optional, so v1 peers ignore them and v2 peers negotiate on the
account `version`. Field names serialize `camelCase` to match
`apps/phone/src/protocol/requests.ts` (as `request.rs` already does).

**`ApprovalRequest` gains an optional threshold challenge.** For a v2 account, the
request carries the base point the phone must key-agree against:

```rust
/// The per-request threshold challenge for a v2 account. Absent on v1 requests
/// and on kinds that read no secret.
#[serde(rename_all = "camelCase")]
pub struct ThresholdChallenge {
    /// Account whose token this unlocks; the phone folds it into nothing — it is
    /// display/audit context and is echoed in the response for correlation.
    pub account_id: String,
    /// The account's fixed ECDH base point E = e·G, ANSI X9.63 (65 bytes), base64.
    /// The phone computes Z_F = x(f·E) against this.
    pub ephemeral_pub: String,
    /// Which pinned SE key F to use (a phone may hold more than one over re-pairs).
    pub se_key_id: String,
    /// Echoes the record's Z_F shape so the phone picks the matching SE algorithm.
    pub ecdh_algo: String, // "raw-x" | "x963-sha256"
}

// added to ApprovalRequest:
#[serde(skip_serializing_if = "Option::is_none", default)]
pub threshold: Option<ThresholdChallenge>,
```

A request may carry several secrets; if a command reads several v2 accounts, the
field generalizes to `Vec<ThresholdChallenge>` keyed by `account_id`. (v1's
single-DEK model had no per-account challenge; this is new surface.)

**`ApprovalResponse` carries the partial instead of the DEK.** v2 replaces
`wrapped_dek` with the phone's ECDH partial. Both fields exist during migration;
exactly one is populated per response, selected by the request's `version`:

```rust
#[serde(rename_all = "camelCase")]
pub struct ThresholdPartial {
    pub account_id: String,
    /// The SE ECDH partial Z_F = x(f·E), 32 bytes, base64. Confidential ONLY by
    /// virtue of the enclosing sealed Envelope (same as v1's wrappedDek).
    pub zf: String,
}

// added to ApprovalResponse (v1 `wrapped_dek` retained for v1 accounts):
#[serde(skip_serializing_if = "Option::is_none", default)]
pub partial: Option<ThresholdPartial>,
```

`ThresholdPartial` is present on approve, **absent on deny** — so, exactly as v1,
a denial carries no key material and can never release a token
(`request.rs::approve`/`deny` invariant, extended: `approve` sets `partial`,
`deny` leaves it `None`; a v2 `dek()`-analogue `partial()` fails closed to `None`
on any malformed/short base64, never a partial value).

**Account store** grows the `AccountRecordV2` of §5, tagged `version: 2`. v1
records keep `version: 1` (implicit) and the static-DEK path. The store is a
tagged union over `version`; loaders that predate v2 see an unknown field/variant
and (per `#[serde(default)]` / a `#[non_exhaustive]`-style version guard) treat a
v2 record as not-loadable and fail closed rather than mis-decrypting.

**Pairing** gains one message: phone→Mac `ThresholdShare { se_key_id, F_x963 }`
sealed in an `Envelope`, delivered after SAS `Confirmed`. Persisted as an
additional pinned public key on the pairing record; no secret, no `m`, no `f`
crosses the wire.

---

## 8. Request authentication, relay-blindness, and binding the partial

The phone must **never** be a blind ECDH oracle. An attacker who could get the
phone to compute `x(f·E')` for an `E'` of their choosing could turn the SE into a
decryption oracle. Three existing mechanisms, applied *before the SE op*, prevent
this:

1. **Sealed to the phone, signed by the Mac.** The `ApprovalRequest` (carrying the
   `ThresholdChallenge`) is crypto_box-sealed to the phone's pinned X25519 pairing
   key and Ed25519-signed by the Mac's pinned pairing key (`envelope.rs::seal`).
   The relay sees only the opaque envelope (no plaintext, no `E`, no `account_id`)
   — relay-blindness is inherited unchanged from v1 (`security-claims` §9).
2. **Verify-then-act ordering (load-bearing).** On receipt the phone runs
   `Envelope::open`: Ed25519 signature check against the **pinned Mac key** first,
   then the `ReplayGuard` (single-use uuidv7 request-id, strictly-monotonic
   per-pairing counter, 90 s window), then decrypt. **Only after all three pass**
   does the phone invoke Face ID and the SE key-agreement. So the phone contributes
   `Z_F` **only to a request provably originated by the paired Mac, fresh, and
   never seen before**. An attacker cannot forge such a request without the Mac's
   Ed25519 signing key, and cannot replay a captured one (replay guard).
3. **Partial bound to the request by the response envelope.** `Z_F` travels inside
   the phone's `ApprovalResponse`, itself a sealed, signed, replay-guarded
   `Envelope` whose `request_id`/`counter` are single-use. A captured response
   **cannot be replayed** to a different request: the Mac's `ReplayGuard` rejects
   the reused id/counter, and the `request_id` inside correlates the partial to
   exactly the challenge it answered (`remote.rs::round_trip` already does this
   correlation for v1). A partial for account A's request R1 is useless for a
   later request R2 (different id/counter → replay-rejected) even if R2 is also
   for account A.

**Approval visibility is preserved.** The phone still opens the request and
**displays the command, the secret reference segments, and the provenance**
(`request.rs` readout fields are unchanged), so the human approves what they can
see. The `ThresholdChallenge` is additional data the human never has to read; the
readout is the same as v1.

**Honest carry-over of residual #7.** A *live same-UID* attacker on the Mac who
holds the Ed25519 signing key can still originate a validly-signed
`ApprovalRequest` with attacker-chosen provenance and a real account's `E`
(`security-claims` residual 7). v2 does not regress this and does not fully solve
it: the last line remains the human declining a request they did not initiate.
But v2 *does* shrink what that attacker gains — a partial for one account, still
needing `m` and a human Face ID tap — versus v1, where the same attacker scraping
one DEK gets every account forever.

---

## 9. The tradeoff: per-request unforgeability vs. approval-visibility

This is requirement 5, resolved with the math that bounds it.

**Can the phone's partial be made cryptographically fresh per request (blinded),
so a captured `Z_F` is useless?** For a *fixed at-rest ciphertext*, **no** — and
the reason is exactly the SE's X-only output, proven here so the residual is
understood, not hand-waved:

- The token ciphertext is fixed at rest, so the key `K` that opens it is fixed,
  so the phone's contribution to `K` — `Z_F = x(f·E)` for the account's fixed `E`
  — is a **fixed** value. Any scheme that reconstructs `K` must reproduce that
  exact `Z_F`.
- Multiplicative blinding (Mac sends `r·E`, phone returns `f·(r·E)`, Mac strips
  `r^{-1}`) is the standard way to hide a static DH partial behind a fresh one —
  but it operates on **full points**, and the SE returns only `x(f·rE)`. The
  X-coordinate map is **not homomorphic**: `x(f·rE)` does not let the Mac recover
  `x(f·E)` by any scalar operation. And the alternative — the phone key-agreeing
  against a *fresh Mac-chosen* base `C = c·G` — yields `x(f·C) = x(c·F)`, which
  the Mac can already compute itself from `c` and the public `F`, so it carries
  **zero** information about the token. Blinding a static X-only partial into a
  fresh one is therefore not merely hard here; it is **impossible** for a
  fixed-at-rest ciphertext with an X-only SE.

**What already provides the freshness that matters.** The `Z_F` is *never on the
wire in a reusable form*: it is sealed inside the per-response `Envelope`, whose
ephemeral gives forward secrecy and whose replay guard makes the response
single-use. The **only** party who can observe `Z_F` in the clear is one who has
already compromised daemon RAM at the instant of an approved decrypt — at which
point `K`, and the plaintext token itself, are equally exposed. Additional
cryptographic blinding of `Z_F` would defend against an attacker who, by
construction, already has the prize.

**Decision (recommended): keep approval-visibility; do not add partial-blinding.**
- The phone continues to decrypt and display the command/secret (the whole point
  of remote approval is that the human sees what they authorize).
- The partial is bound to the request by the existing signature + replay guard
  (§8), not by blinding.
- No per-request key freshness is claimed (it is provably unattainable here); the
  claimed freshness is that the partial is (a) elicited only by a Mac-signed,
  fresh, human-Face-ID-approved request, and (b) transmitted only inside a
  single-use sealed envelope.

**Residual, stated honestly.** A `Z_F` captured from daemon RAM during an approved
decrypt is reusable to re-derive **that one account's** `K` *iff* the attacker also
holds the Mac share `m` (e.g. a stolen live laptop) — for as long as that account
keeps the same `E`. It does **not** generalize to other accounts (each has its own
`E` → its own `Z_F`), and the account can be re-keyed (fresh `E`, re-encrypt) to
invalidate a captured partial. This is a large improvement over v1's "one DEK =
all accounts, forever, no laptop needed" and is the deliberate, minimal residual
of choosing visibility over an unattainable blinding.

---

## 10. Minimal residency

Per requirement 6, and auditable path-by-path (the reviewer should check each):

- **`m` (Mac share).** At rest: sealed in the login Keychain, never plaintext on
  disk. Per request: loaded into an **mlock'd `Zeroizing`** buffer, used for one
  `diffie_hellman` to produce `Z_M`, then the `SecretKey`/scalar is **zeroized
  immediately** — held only for the span of step 3 in §6, not for the whole
  request. Never placed in a lease (a lease may cache a *token* under an active
  grant, never `m`).
- **`f` (phone share).** Never leaves the Secure Enclave. The SE performs
  `f·E` internally and emits only the X-coordinate. `f` is non-exportable
  (`kSecAttrTokenIDSecureEnclave`, no extractable attribute). Every use is gated
  by `.biometryCurrentSet` (Face ID), and the key is invalidated if the enrolled
  biometric set changes.
- **`Z_M`, `Z_F`, `K`.** All `Zeroizing`; they exist only between §6 steps 9–13
  and are wiped the instant `token_ct` is opened. No full private scalar `(m + f)`
  is **ever** materialized anywhere — the KDF combines two X-coordinates, it never
  reconstructs a private key.
- **The reconstructed token.** Same residual as v1 (`security-claims` residual 3):
  it transits daemon RAM to reach the provider child env, held in `Zeroizing`, with
  one un-zeroized `std::process::Command` env copy for the span of the spawn. v2
  does not change this and does not claim to.

No new long-lived plaintext secret is introduced. The v1 static DEK — a 256-bit
key that sat, recoverable, on the phone for the life of the pairing — is *removed*;
in its place the phone holds `f` (non-exportable, in hardware) and the Mac holds
`m` (a share, useless alone).

---

## 11. Security properties (proof sketch for the reviewer to verify)

Modeling the KDF as a random oracle / secure PRF over its length-prefixed input,
and P-256 as a group where computational Diffie-Hellman (CDH) is hard:

**P-1 · No skeleton key / true 2-of-2.** `K = KDF(Z_M ∥ Z_F ∥ …)` with
`Z_M = x(m·E)`, `Z_F = x(f·E)`. To learn `K` an adversary must learn *both*
`Z_M` and `Z_F` (the KDF is preimage-resistant and binds both). The Mac holds `m`
(→ `Z_M`) but not `f`; from the stored `E` and public `F` it faces CDH to get
`Z_F`. The phone holds `f` (→ `Z_F`) but not `m`; from `E` and (if it even had)
`M` it faces CDH to get `Z_M`. **Neither party alone, and no single stored value,
yields `K`.** The only value whose sole capture unlocks a token is `K` itself (or
`Z_F` *plus* `m`), and `K` is never stored and `Z_F` is never stored.

**P-2 · Share never leaves the SE.** `f` is minted in and non-exportable from the
Secure Enclave; only `x(f·E)` exits. Recovering `f` from `x(f·E)` is ECDLP. (NV-1:
device-verify non-exportability + biometric gating.)

**P-3 · Daemon inert at rest.** At rest the Mac holds `{token_ct, E, m (sealed),
F (public)}`. Decryption needs `Z_F = x(f·E)`; from `E` and `F` that is CDH →
infeasible. A powered-off/stolen laptop yields ciphertext and a useless share.
Strictly stronger than v1 at rest (v1 also inert, but v1's *phone* held a
self-sufficient DEK; v2's phone holds only `f`).

**P-4 · Forgery / oracle resistance.** The phone runs the SE op only after
verifying the Mac's Ed25519 signature and the replay guard (§8), so it is not a
chosen-`E` decryption oracle. Forging a request needs the Mac's signing key;
replaying one is caught by the single-use request-id + monotonic counter + 90 s
window (`replay.rs`, already tested by the hostile-relay suite).

**P-5 · Replay / relay powerlessness.** Both the challenge and the partial ride
inside the existing sealed, signed, replay-guarded `Envelope`; the entire
`hostile_relay.rs` attack suite (forge, tamper, replay, reorder, backdate, drop)
applies unchanged, since v2 changes only the plaintext *inside* the seal, not the
seal. A captured response is replay-rejected; a partial cannot be re-bound to a
different request.

**P-6 · Blast radius (the headline).** As tabulated in §1 and derived in §9: one
captured partial compromises **one** account, only in combination with the Mac
share, only for as long as that account keeps its `E`, and is obtainable only at
the instant the token itself is already exposed. Contrast v1: one captured DEK
compromises **all** accounts, forever, self-sufficiently.

**Open proof obligations flagged to the reviewer** are in §14; the biggest are the
RO/PRF modeling of the concatenative combiner and the on-device SE-output-shape
verification (§13).

---

## 12. Migration and non-disturbance of the v1 demo

**v1 is untouched.** v2 is gated on the account-store `version`. A v1 daemon has
no `version: 2` branch, no `threshold` request field, no `partial` response field,
and no P-256 share; it neither emits nor parses any v2 surface. This design changes
no running code — it is a document. When v2 is *implemented*, the v1 static-DEK
path (`secrets.rs` DEK, `pairing.md` DEK handoff, `wrapped_dek`) remains as-is for
`version: 1` accounts, so the live demo keeps working byte-identically.

**Coexistence, not a flag day.** The two schemes share the token-ciphertext format
(AES-256-GCM); they differ only in *where the 32-byte key comes from*. So v1 and v2
accounts can live in the same store simultaneously, each decrypted by its own path.

**Upgrade sequence (per pairing, then per account):**
1. **Add the shares to an existing pairing** via a new one-shot `latch pair upgrade`:
   the phone mints `f` in the SE and returns `F` in a sealed `Envelope`; the Mac
   mints `m`, seals it to the Keychain, and pins `F`. No DEK is involved; the v1
   DEK and the new shares coexist. (A fresh pairing does this inline after SAS.)
2. **Re-encrypt accounts on demand.** `latch account add` (or a new
   `latch account upgrade`) re-wraps a token to `(M, F)` as a `version: 2` record
   and drops the `version: 1` record for that account. Existing v1 records keep
   working until upgraded; there is **no** bulk re-encryption and no downtime.
3. **Rotation = re-key.** Rotating an account picks a fresh `e`/`E` and re-encrypts,
   which also invalidates any previously-captured `Z_F` for that account (§9
   residual mitigation).

**Phone lost / re-pair.** Because `f` is SE-resident and non-exportable, a lost
phone's `f` is unrecoverable — recovery is intentionally a rotation (consistent
with the brief's Trust model): pair a new phone (new `f`/`F`), re-key every v2
account; old `token_ct` dies because its `Z_F` is gone forever. This is the same
"recovery is rotation" posture the brief already states, now enforced by hardware.

---

## 13. NEEDS-VERIFICATION (device-specific, cannot be proven off-hardware)

- **NV-1 · SE key-agreement is usable and Face-ID-gated.** That a Secure-Enclave
  P-256 key created with `kSecAttrTokenIDSecureEnclave` +
  `kSecAccessControlBiometryCurrentSet` performs
  `SecKeyCopyKeyExchangeResult` / `sharedSecretFromKeyAgreement`, that it prompts
  Face ID on each use, that it is non-exportable, and that changing the enrolled
  biometric set invalidates it. Verify on real Apple-silicon iPhone hardware (not
  the Simulator).
- **NV-2 · The exact `Z_F` output shape.** Whether the SE permits the raw
  `.ecdhKeyExchangeStandard` (32-byte X-coordinate, `ecdh_algo = "raw-x"`) on an
  SE-resident key, or only the `…X963SHA256` KDF variants. The design supports
  **either**: if raw is disallowed, set `ecdh_algo = "x963-sha256"` and have the
  Mac apply the identical ANSI-X9.63 KDF (already implemented in
  `se_ecies.rs::x963_kdf_sha256`, with `sharedInfo` pinned to `E`'s X9.63 bytes)
  to its `Z_M` and to the account-add `Z_F` so both sides match byte-for-byte.
  Confirm which variant the SE actually returns, and pin it per record.
- **NV-3 · Byte-exact ECDH agreement Mac↔phone.** That
  `p256::ecdh::diffie_hellman(m, E).raw_secret_bytes()` on the Mac and the SE's
  X-coordinate for the same `(scalar, point)` are byte-identical (big-endian,
  32 bytes, no leading-zero trimming surprises). Prove with a shared test vector
  (a known `f`, `E`) the way the envelope layer already pins Rust↔TS vectors.
- **NV-4 · CryptoKit vs. Security-framework parity on the phone.** If the phone
  uses CryptoKit `SecureEnclave.P256.KeyAgreement`, confirm its `SharedSecret`
  bytes equal the Security-framework `.ecdhKeyExchangeStandard` output, so the
  choice of API does not change `Z_F`.
- **NV-5 · `react-native-libsodium` / phone crypto seam.** The phone already does
  X25519 crypto_box via libsodium for the envelope; confirm the SE P-256
  key-agreement is reachable from the Expo/RN layer (native module or Security
  framework bridge) alongside it.

---

## 14. Open questions for the independent crypto reviewer

1. **Combiner soundness.** Is `KDF(Z_M ∥ Z_F ∥ E ∥ account_id)` with keyed BLAKE2b
   and length-prefixed absorb an acceptable KEM-combiner here? Confirm the
   length-prefixing is injective (no concatenation ambiguity across the two
   32-byte X-coordinates + variable-length `account_id`), and that folding `E` and
   `account_id` into the KDF adds nothing exploitable (they are public; intended as
   domain/context binding, not entropy).
2. **X-coordinate-only ECDH.** Is deriving the key from the *X-coordinate*
   (co-factor 1, prime-order curve, so no small-subgroup/twist issue on P-256)
   sound, given the well-known "raw ECDH shared secret must be hashed" guidance —
   which we follow by feeding it straight into the KDF and never using it raw?
   Any twist-security concern from accepting an attacker-influenced `E`? (`E` is
   Mac-generated and stored, not attacker-supplied — but the reviewer should
   confirm the on-curve validation of `E` at load and of `F` at pairing, mirroring
   `se_ecies.rs`'s `PublicKey::from_sec1_bytes` on-curve check.)
3. **The blinding impossibility argument (§9).** Is the claim correct and complete
   that per-request cryptographic freshness of the partial is unattainable for a
   fixed-at-rest ciphertext with an X-only SE — i.e. is there a construction the
   design missed (e.g. a different at-rest layout, an SE signature instead of
   key-agreement, an OPRF) that would recover blinding without giving up the
   2-of-2 property or the phone's SE-only custody?
4. **Oracle exposure.** Does the verify-before-SE-op ordering (§8) fully close the
   chosen-`E` decryption-oracle surface, given residual #7 (a live same-UID Mac
   attacker holds the signing key)? Is there value in *additionally* binding the
   phone's Face-ID prompt copy to a hash of `E`/`account_id` so a mis-issued
   challenge is human-visible?
5. **Encrypt-time trust window.** At account-add the Mac transiently holds full `K`
   (§5). Is treating this identically to v1's DEK-generation trust window
   acceptable, or should account-add itself be a two-party operation (phone
   participates so the Mac never sees `Z_F`, at the cost of requiring the phone
   present at every `account add`)?
6. **Residual acceptance.** Is the §9 residual — captured `Z_F` + `m` ⇒ one account
   until re-key — the right point on the visibility/unforgeability curve for a
   single-user instrument, or does the reviewer want the (heavier) phone-present
   account-add of Q5 to shrink it further?
7. **Multi-secret requests.** For a command reading several v2 accounts in one
   approval, is a `Vec<ThresholdChallenge>` / `Vec<ThresholdPartial>` (one ECDH per
   account, all under one Face ID) acceptable, or should each account be a separate
   gated approval?

---

*This document is the design. Implementation is a separate, later task
(`#24`/`#26` successors) and must not land until the independent security-reviewer
has recorded a verdict per the `CLAUDE.md` review-integrity rule.*
