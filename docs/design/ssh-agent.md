# Latch SSH agent: design note

Answering Tom's question: *"How is the op ssh-agent going to work, or will it just
work out of the box?"*

Short answer: it does **not** just work out of the box, but the hard part is small
and the custody model is confirmed viable. Latch implements the SSH agent protocol
itself (a few hundred lines), serves Tom's SSH keys, and gates every signature
through the same phone approval loop as `op`. Tom points `SSH_AUTH_SOCK` at Latch's
socket; from then on `git push` / `ssh` transparently ask the phone. Two honesty
corrections to the brief are below (host name in the approval screen, and key
material in daemon RAM).

Everything marked **VERIFIED** was tested on this machine on 2026-07-04 against the
live Rowm service account. Everything marked **NEEDS VERIFICATION** was not, with the
exact confirming command given.

---

## 1. The protocol reality

The SSH agent protocol is now **RFC 9987** (published; supersedes the old
`draft-miller-ssh-agent`), plus OpenSSH's `PROTOCOL.agent` for the vendor
extensions. It is a trivial length-prefixed binary protocol over a unix socket:
each message is `uint32 length` then `byte type` then type-specific fields, where
every variable field is an SSH `string` (`uint32 len` + bytes). No TLS, no
handshake, no framing library required. The client opens the socket, writes one
request, reads one reply.

An agent that serves real clients (`ssh`, `git`, `ssh-add -l`) must handle exactly
**two** request types. Everything else can be refused with a single-byte
`SSH_AGENT_FAILURE`.

### Must implement

**`SSH2_AGENTC_REQUEST_IDENTITIES` (11) → `SSH2_AGENT_IDENTITIES_ANSWER` (12)**
The client asks "what keys do you have?". Reply is `uint32 nkeys` followed by, per
key: `string key_blob` (the public key in SSH wire format, e.g.
`ssh-ed25519` + 32-byte point) and `string comment` (human label, shown by
`ssh-add -l`). This is how the client decides which key to offer to a server. If we
do not list the key GitHub expects, auth never even reaches a signature.

**`SSH2_AGENTC_SIGN_REQUEST` (13) → `SSH2_AGENT_SIGN_RESPONSE` (14)**
The actual approval-worthy event. Request fields:
- `string key_blob` — which of our advertised public keys to sign with.
- `string data` — the exact bytes to sign. For user auth this is the SSH
  "session identifier + auth request" transcript (RFC 4252 §7); it is **opaque to
  us** and must be signed verbatim.
- `uint32 flags` — bitwise OR of signature flags. Only meaningful for RSA:
  `SSH_AGENT_RS_SHA2_256 = 0x02`, `SSH_AGENT_RS_SHA2_512 = 0x04`. Zero flags on an
  RSA key means legacy `ssh-rsa` (SHA-1), which modern servers reject; GitHub
  requires `rsa-sha2-*`. For ed25519 the flags are ignored.

Response is one field: `string signature`, itself an SSH-encoded blob of
`string sig_algorithm_name` + `string raw_signature`. For ed25519 that is
`"ssh-ed25519"` + the 64-byte Ed25519 signature. For RSA under the SHA-256 flag the
algorithm name string must be `"rsa-sha2-256"` (not `"ssh-rsa"`), which is a common
footgun.

### Can stub (reply `SSH_AGENT_FAILURE` = 5)

- `SSH_AGENTC_ADD_IDENTITY` (17), `ADD_ID_CONSTRAINED` (25),
  `ADD_SMARTCARD_KEY` (20/26) — we do not accept keys pushed in; ours come from
  1Password. `ssh-add <file>` fails cleanly, which is correct.
- `REMOVE_IDENTITY` (18), `REMOVE_ALL_IDENTITIES` (19) — nothing to remove.
- `LOCK` (22) / `UNLOCK` (23) — Latch has its own lock model (the phone); refuse.
- `SSH_AGENTC_EXTENSION` (27) — refuse **except** `session-bind@openssh.com`, which
  we should accept and record (see §4, host derivation). Refusing an unknown
  extension is protocol-legal and clients tolerate it.

`SSH_AGENT_SUCCESS` (6) is only needed as the ack for the operations we refuse to
actually perform but must not error (in practice none in v1; we can `FAILURE`
everything non-signing).

**Implication for "it just works":** for any standard OpenSSH/libssh2/Go client,
implementing exactly `REQUEST_IDENTITIES` + `SIGN_REQUEST` (+ accepting
`session-bind`) is sufficient. There is no client-visible capability negotiation we
can fail. The protocol is stable and we control both ends of what matters.

---

## 2. Where the keys and the signing actually live

Two custody models. Both were investigated against the live setup; the recommended
one is **VERIFIED end to end**.

### (a) v1 — fetch-per-signature from 1Password via the service account — VERIFIED

The question was: can the Rowm service account actually read an SSH private key item
and hand us signable material? Tested on 2026-07-04 (`OP_SERVICE_ACCOUNT_TOKEN` is
present in this environment):

- **SA vault visibility — VERIFIED.** `op vault list` as the SA returns
  `Engineering, Executive, Finance, Operations, Rowmeo`. The built-in **Personal /
  Private vault is absent**, confirming the earlier finding: an SSH key we want
  Latch to serve **must live in one of these shared vaults**, never in Personal.
- **Reading the private key — VERIFIED.** Created a throwaway `SSH Key` item
  (`ed25519`) in Engineering, then:
  - `op read "op://Engineering/<item>/private key"` returns a **PKCS#8**
    `-----BEGIN PRIVATE KEY-----` body.
  - `op read "op://Engineering/<item>/private key?ssh-format=openssh"` returns
    `-----BEGIN OPENSSH PRIVATE KEY-----` (the native OpenSSH format — use this).
  - `ssh-keygen -y -f <the openssh key>` re-derived the public key, proving the
    bytes are a **complete, usable, unencrypted private key**, not a redacted
    reference. Item deleted afterwards; vault is clean.
- **No biometric.** The SA is headless and non-interactive: the read returned key
  material with **no Touch ID prompt and no Mac window**. This is the whole point —
  it is exactly the local gate we are trying to escape, and the SA bypasses it.

So v1 works: on each `SIGN_REQUEST`, after phone approval, the daemon runs
`op read ...?ssh-format=openssh` for the matching item, decodes the OpenSSH private
key in Rust, produces the signature, zeroizes the key bytes, and returns only the
`SIGN_RESPONSE`. The SSH client never sees key material. **We** do the crypto.

What crypto we owe, by key type:
- **ed25519** — sign with `ed25519-dalek` (already a workspace dependency). This is
  the recommended and default type for Rowm's keys; GitHub supports it.
- **ecdsa-sha2-nistp256** — would need the `p256` crate. Not in v1.
- **rsa-sha2-256/512** — would need the `rsa` crate and correct flag handling. Not
  in v1.

Recommendation: **v1 serves ed25519 only** and refuses other key types in
`IDENTITIES_ANSWER` (simply do not advertise them), keeping the signing surface to
the ed25519 crate we already vet. Tom standardises his Latch-served keys on ed25519,
which is a no-op for GitHub and most hosts.

### (b) Alternative — front the 1Password SSH agent — REJECTED for v1

1Password ships its own SSH agent. Its socket exists on this machine at
`~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock` (VERIFIED to
exist, `srw-------`). We could point `SSH_AUTH_SOCK` at Latch, and have Latch proxy
`SIGN_REQUEST`s onward to that socket so 1Password does the crypto and keys never
leave 1Password.

This is rejected because it does not solve Tom's problem:
- The 1Password agent is **the desktop app**, tied to a signed-in, unlocked user,
  and **it is the thing that pops the Mac approval window** on every new
  app/key pair. Proxying it inserts our phone gate *in addition to*, not *instead
  of*, 1Password's local gate. When Tom is remote, the 1Password prompt still sits
  unanswered on the Mac and the signature still stalls — the exact failure we are
  removing. (1Password can remember an authorization per app+key for a session, so
  it is not literally every signature, but the first one of any session and any new
  process still blocks locally.)
- A **service account cannot drive the desktop agent** — it is headless; there is no
  app to unlock. So the proxy path and the SA path are mutually exclusive, and only
  the SA path is remote-capable.
- Fronting it still leaves us unable to show a meaningful approval screen, because
  the request we would forward carries no more host context than we already have.

The one thing (b) preserves that (a) gives up — keys never materialise outside
1Password — is real, and is precisely what **v2 (Secure Enclave resident keys)**
restores properly. For v1 the honest trade is: accept key material in daemon RAM for
one signature (see §5), in exchange for a gate that actually works when Tom is away.

**Recommendation: v1 = fetch-and-sign-ourselves via the service account (a).**

---

## 3. The "just works" question, answered directly

What Tom actually changes:

1. **`SSH_AUTH_SOCK`.** Point it at Latch's socket (e.g.
   `~/Library/Application Support/latch/ssh-agent.sock`, `0600`). Set via the
   launchd user environment (`launchctl setenv SSH_AUTH_SOCK ...` from the Latch
   launchd agent) plus the shell profile as a fallback. Today in this environment it
   points at `/private/tmp/com.apple.launchd.*/Listeners` — the **macOS native
   launchd ssh-agent**, not 1Password — so Latch simply becomes the new target.
2. **The key must be a SA-visible SSH Key item.** Tom's GitHub key has to exist as an
   `SSH Key` item in Engineering (or another shared vault), not only on disk and not
   in Personal. If it is only in `~/.ssh`, Latch has nothing to serve.
3. **Nothing in `git` config changes** for the basic case. `git push` shells out to
   `ssh`, which reads `SSH_AUTH_SOCK`, which is now Latch. It transparently starts
   asking the phone. Optional `IdentityAgent` in `~/.ssh/config` can scope Latch to
   specific hosts if Tom wants to keep the native agent for others.
4. **Nothing breaks** as long as `IDENTITIES_ANSWER` advertises the key the server
   expects. If it does not, auth fails the same way a missing key always does — no
   corruption, just a rejected connection.

### Host derivation — a brief correction

The brief (line 377: *"the phone shows the key label, target host, and challenge
fingerprint"*; line 518: the log line `ssh github-deploy → git@github.com`) implies
the agent knows the destination host. **It does not, from the protocol.** A
`SIGN_REQUEST` contains only the key blob, opaque data, and flags. There is **no
hostname anywhere in the agent protocol.** This must be flagged as a brief
correction.

What we *can* recover, best-effort:
- Modern OpenSSH (Tom's client here is **OpenSSH_10.2p1** — VERIFIED, well past the
  8.9 cutoff) sends the **`session-bind@openssh.com`** extension on the agent
  connection *before* the sign request. It carries the **server's host public key**
  (plus session id, the host's signature, and an is-forwarding flag) — but still
  **only the host key, never the hostname string.**
- We can reverse the host key to a name via **`~/.ssh/known_hosts`**. On this machine
  known_hosts is **unhashed** (VERIFIED — `HashKnownHosts` is off, 12 host patterns,
  and **`github.com` is present**). So for any host Tom has connected to before, and
  for `github.com` specifically **today**, host-key → hostname reverse lookup
  succeeds. We track the last `session-bind` host key per agent connection, look it
  up, and show the name.
- When the lookup misses (a brand-new host, a hashed known_hosts, or a client that
  does not send `session-bind` — e.g. some libssh2/Go clients), we **cannot** show a
  hostname. The approval screen then shows the **host key fingerprint**
  (`SHA256:...`) instead, which is still the honest, verifiable identity of the
  destination.

So the corrected UX contract: the approval screen shows **key label + destination
(hostname when known via known_hosts, else host-key fingerprint) + a fingerprint of
the data to sign**. The "signs to github.com" line is achievable for github.com in
practice, but it is a best-effort derivation, not a protocol guarantee, and the brief
should say so.

---

## 4. Security notes for the security-reviewer

- **Signatures are approval-gated identically to secrets.** A `SIGN_REQUEST` is an
  authentication event and rides the same sealed/signed envelope + single-use
  request id + monotonic counter + 90s window as an `op` release. Fail closed:
  no approval, no signature.
- **Show a fingerprint, not raw bytes.** The `data` to sign is opaque and useless to
  a human. The phone screen must show a stable **hash of the data** (e.g. the same
  Blake2 fingerprint style already used), plus the derived destination (§3). Never
  render raw sign-data.
- **Key material lifetime — the material difference from `op read`.** This is the one
  place SSH is *worse* than secret release and the reviewer must weigh it. For a
  normal secret, the invariant is "secret bytes never enter daemon memory" (op
  stdout splices straight to the client fd). **That invariant cannot hold for v1
  SSH**, because *we* are the one doing the signing: the private key must be in
  daemon RAM for the duration of one signature. Mitigations: fetch into a
  `Zeroizing` buffer, decode, sign, zeroize immediately; never write the key to
  disk; never log it; hold it for milliseconds, not a session.
- **A single approved signature can leak the whole key.** With fetch-per-signature,
  the SA token can read the **entire private key**, not just produce one signature.
  So if the daemon is compromised *at the moment of an approved request*, the
  attacker gets the key itself and can sign arbitrarily forever after — strictly
  worse than the `op`-secret case, where a compromised approved request leaks one
  secret's value but grants no lasting signing power. The brief's line
  *"SSH clients never see key material"* is true of the **client** but not of the
  **daemon** in v1; the daemon is the new trusted holder. This is the core reason v2
  (Secure Enclave resident keys, key never extractable) exists, and it should be
  framed as a known, time-boxed v1 exposure, not hidden.
- **The SA token is itself now an SSH-key-exfiltration capability.** Anyone with the
  token can `op read` the private key with no biometric (VERIFIED). Treat the token's
  storage with the same care as the DEK. This is not new (the token already reads all
  dev secrets) but SSH raises the stakes: it grants durable identity, not just data.

---

## 5. v1 build plan (for the rust-core notes)

**Crate layout: a module in `crates/latch`, not a new crate.** The SSH agent shares
the daemon's approval plumbing (envelope round-trip to the phone, `paths`, `style`,
the launchd socket lifecycle) and the multicall `latch` binary already dispatches
subcommands (daemon / shim / cli). A separate crate would only duplicate that wiring.
Add:
- `crates/latch/src/sshagent.rs` — the unix-socket listener, the RFC 9987 wire
  framing (hand-rolled length-prefixed reader/writer, same spirit as the hand-rolled
  envelope serde), `REQUEST_IDENTITIES` / `SIGN_REQUEST` handling, `session-bind`
  capture, and refusal of everything else.
- The signing + `op read` fetch can live alongside it in `latch` (it needs to shell
  out to `op`, which is a `latch` concern, not a `proto` one). `crates/proto` stays
  pure envelope/crypto; do **not** put key-fetch there.

**Signing crates:**
- `ssh-key` (RustCrypto), features `["ed25519"]` — decodes the
  `-----BEGIN OPENSSH PRIVATE KEY-----` body cleanly (bcrypt-KDF aware, though SA
  keys are unencrypted), produces the public-key wire blob for `IDENTITIES_ANSWER`,
  and signs. It uses `ed25519-dalek` underneath, matching the existing dependency, so
  no new signature primitive enters the tree. This avoids hand-parsing the OpenSSH
  private key container, which is the only genuinely fiddly part.
- `ed25519-dalek` — already vendored; `ssh-key` delegates to it.
- Optionally `ssh-encoding` for the SSH `string`/`u32` wire helpers, or hand-roll
  them (they are a few lines and match house style). Lean toward hand-rolling to keep
  the dependency surface small.
- **No** `p256` / `rsa` in v1 (ed25519-only, as in §2a).

**Effort estimate: ~1 week for a working, tested v1.**
- Wire protocol (framing + the two message types + refusals + `session-bind`
  capture): ~1.5 days.
- `op read` fetch + `ssh-key` decode + ed25519 sign + zeroize: ~1 day.
- Host derivation (session-bind host key → known_hosts reverse lookup, fingerprint
  fallback): ~1 day.
- Wiring into the existing phone approval round-trip + the SSH approval screen
  fields: ~1 day.
- launchd `SSH_AUTH_SOCK` plumbing + Mac-app config toggle (hand to mac-app): ~0.5
  day.
- Integration tests: real `ssh`/`git` against the Latch socket, `ssh-add -l`, a
  refused `ssh-add <file>`, and a wrong-key path: ~1 day.

**v2 (out of scope here):** keys become Secure Enclave resident; signing moves into
hardware; the "key in daemon RAM" exposure from §4 disappears; the fetch path is
retired.

---

## NEEDS VERIFICATION (could not confirm from this machine)

1. **1Password agent biometric-per-signature specifics.** The desktop 1P agent
   remembers authorization per app+key for a session; the exact first-prompt
   behaviour per new process was not exercised (would require driving the desktop
   app, which is locked / Tom is away). It does not change the recommendation —
   proxying it is rejected regardless — but the "not literally every signature" claim
   in §2b is from docs, not a live test. Confirm by: with 1P as `SSH_AUTH_SOCK`, run
   two `git` operations in separate shells and observe how many prompts appear.
2. **`session-bind` host key exactly matches the known_hosts entry format for
   github.com.** The reverse-lookup logic (normalising the `session-bind` hostkey
   blob to the base64 in known_hosts, handling `@cert-authority` and multiple keys
   per host) needs a live test once the listener exists. Confirm by: log the
   `session-bind` hostkey during a real `git push` and diff against the `github.com`
   line in `~/.ssh/known_hosts`.
3. **RSA/ecdsa are genuinely not needed.** Assumes Tom's Latch-served keys are all
   ed25519. Confirm by: `op item list --categories "SSH Key"` once Tom has created
   his real key items (today there are **zero** SSH Key items in any SA-visible
   vault — VERIFIED — so this is a prerequisite Tom must do before v1 can serve
   anything).

---

*Grounding: RFC 9987 (SSH agent protocol), OpenSSH `PROTOCOL.agent`
(`session-bind@openssh.com`, `restrict-destination-v00@openssh.com`), 1Password CLI
`op read` `?ssh-format=openssh`, and live tests against the Rowm service account on
2026-07-04.*
