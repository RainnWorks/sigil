# SSH signing through Sigil: pluggable key sources, per-host routing, leases

Status: design, 2026-07-12. Successor to `docs/design/ssh-agent.md` (the agent
wire protocol and the v1 fetch-per-signature build, both shipped). This doc
turns the shipped agent into a WORKING, configurable local setup with three
properties the shipped code does not yet have:

1. The key SOURCE is pluggable and first-class in config and UI. 1Password
   (an `op://` reference, fetched per signature) is the lead source and Tom's
   own setup, but a plain key file and a Secure Enclave resident key are
   equal citizens. The gate, the phone card, and the lease UX are identical
   regardless of source; only where the key material comes from differs.
2. Gating is LAYERED and per-host. The user opts specific hosts into Sigil's
   agent the same way 1Password does it today (per-Host `IdentityAgent`
   blocks in `~/.ssh/config`); every other host stays on the normal agent,
   untouched. One user can run `github.com` through a 1Password key with a
   15 minute lease, `prod-bastion` through an SE key run-once, and leave
   everything else unmanaged, simultaneously.
3. One approval can open a bounded lease window instead of a tap per
   signature, reusing the engine's existing run-once vs leasable policy.

House rules honored: no em-dashes, no emoji, implementer voice, residuals
stated plainly, no self-certified review verdicts (route to security-reviewer).

---

## 0. What already exists (verified by reading the code, 2026-07-12)

Shipped and green in `crates/sigil`:

* `sshagent.rs`: the RFC 9987 listener (REQUEST_IDENTITIES, SIGN_REQUEST,
  session-bind capture, everything else refused), hand-rolled wire helpers,
  host derivation via known_hosts reverse lookup with fingerprint fallback,
  and the pluggable `SshSigner` seam with two impls: `OpSshSigner`
  (fetch-per-signature via the SA token: `op read "...?ssh-format=openssh"`
  into a `Zeroizing` buffer, decode with `ssh-key`, sign ed25519, wipe) and
  `FileSshSigner` (local `~/.ssh/id_*`). ed25519 only.
* `daemon.rs` `impl SshBackend for Core::approve_and_sign`: lockdown check,
  signer routing by key blob, account routing by the ref's vault, phone gate
  via the same `ApprovalGate` as an `op` release, `RequestKind::SshSignature`
  + `SshChallenge {key_label, host, fingerprint}` in the sealed request, DEK
  unwrap, token decrypt, sign, zeroize. **Hard-coded `LeasePolicy::RunOnce`;
  no lease consult, no lease grant.** The scope folds the data fingerprint
  in (`ssh-sign <label> <data_fp>`) so coalescing never merges two different
  challenges.
* Config: `~/.sigil/ssh-keys.json` (`keys` = op entries, `files` = local key
  paths), loaded once at arm time. Inert at rest: public key + coordinates
  only. CLI: `sigil ssh add|add-file|list|remove`, `sigil sshagent` prints
  the export line, `sigil status`/`doctor` report the socket.
* The generic engine: `config.rs` `Config {sources, rules}` with per-rule
  `LeasePolicy {RunOnce | Leasable{max_secs}}`, hot reload (`ConfigCell` +
  2s watcher), `LeaseStore` (grant key = BLAKE2b over the kernel-verified
  caller ancestry chain + project root + scope, and the command path now
  passes an empty root plus the matched RULE's name as the scope, so a
  command lease is rule-wide rather than argv-wide; triple-scoped RAM-only
  tokens; TTL purge; lockdown clears). The op fulfillment path consults
  `leases.token_for` before gating and grants on `Decision::Lease(ttl)`
  clamped by the rule's policy, which the daemon enforces as sole authority.
* Proto: `ApprovalRequest.lease_policy` rides inside the sealed envelope;
  `ApprovalRequest.ssh: Option<SshChallenge>`; the phone returns
  `InstallLease {ttl_ms}`. The relay stays blind to all of it.
* Mac app: Rules tab (quick-start grid + reorderable rule list +
  `RuleEditorSheet` authoring match + write-once sealed env + run-once vs
  leasable with `LeaseDuration.presets` = 5m/15m/30m/1h/2h/4h), everything
  through the `sigil-config` seam (`export` to load, verbs + `import` to
  write). The menubar already renders `SshChallenge` on a pending request.
  **No SSH configuration UI exists, and the app's current IA has no
  account/source surface: "1Password is just a command you gate" and the SA
  token is a sealed inline env value.**

---

## 1. The key source seam: who holds the key during a signature

### The honest structural difference from `op read`

The op path realizes invariant #2 as: inject a credential into a child,
splice the child's stdout to the caller's fd, so the resolved secret never
enters daemon memory. A signature cannot ride that shape as-is: the output
the caller needs (the signature) is a function of the secret (the key)
computed by whoever holds it. Someone must hold key bytes during signing.
The design question is WHO holds them and for how long. The `SshSigner`
trait is the seam that makes the answer pluggable; the gate is
signer-agnostic. Sources, each analyzed:

### (a) 1Password source, in-daemon fetch (shipped today)

On an approved SIGN_REQUEST the daemon runs `op read
"op://<vault>/<item>/private key?ssh-format=openssh"` with the decrypted SA
token, captures stdout into a `Zeroizing<Vec<u8>>`, decodes, signs with
ed25519-dalek, wipes. Key in daemon RAM for milliseconds.

* Exact trust residual: (1) the private key transits the LONG-LIVED daemon's
  address space for one signature; a memory-disclosure bug, heap dump, or
  debugger attach in that window leaks it. (2) The SA token is a durable
  key-exfiltration capability: anyone holding it reads the whole key with no
  biometric (verified live, prior doc), so a daemon compromise at the moment
  of any approved request leaks lasting signing power, not one signature.
  Strictly worse than the op-secret case.
* Buys: 1Password-managed key, works remotely, zero new moving parts. The
  key item MUST live in an SA-visible shared vault (Engineering, never
  Personal; the SA cannot see Personal at all).

### (b) delegate to 1Password's own SSH agent (proxy source)

Sigil fronts `~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock`,
gates each SIGN_REQUEST on the phone, then forwards it. The key never exists
outside 1Password.

* Why it cannot be primary: the 1P agent is the desktop app. It requires a
  signed-in, unlocked app and pops its OWN local authorization prompt per
  app+key (rememberable per session, but the first use of any session and
  any new client process still blocks locally). Remote, that prompt sits
  unanswered on the Mac: the exact failure Sigil exists to remove. A
  service account cannot drive the desktop agent, and 1Password exposes no
  programmatic per-use approval hook Sigil could satisfy from the phone
  (NEEDS VERIFICATION against current 1P releases: check `agent.toml` and
  the 1P developer docs; as of everything verifiable from this machine and
  prior live testing, there is none).
* What it uniquely buys: key never materializes outside 1P, and the item may
  live in the Personal vault.
* Verdict: a legitimate FUTURE `ProxySshSigner` for at-the-desk use, not the
  primary and not in this build. Unchanged from the prior doc.

### (c) child-process confinement: the key never enters the daemon

Preserve as much of invariant #2 as physics allows: a short-lived child does
the fetch+sign and hands back ONLY the signature.

* `ssh-keygen -Y sign` **does not work**: it emits SSHSIG-format signatures
  (a namespaced wrapper over a HASH of the message), not the raw signature
  over the agent challenge that SSH authentication requires. Ruled out on
  protocol grounds.
* `openssl pkeyutl -sign -rawin` can emit the raw ed25519 signature but
  needs a PKCS#8 conversion step, fd-passing choreography, and a version
  behavior dependency. Fragile.
* **The workable shape: a helper mode of our own binary.** The daemon spawns
  `sigil ssh-sign-helper`, writes the SA token + op reference + base64 data
  on the child's STDIN (never argv, never env: same-UID processes read
  another's argv/env via `KERN_PROCARGS2`); the helper reuses the shipped
  `fetch_and_sign` path in its own address space, writes the signature blob
  to stdout, zeroizes, exits.
* Buys, honestly: key bytes never enter the long-lived daemon's address
  space; exposure confined to two transient processes alive under a second.
  Near-parity with the op-secret memory discipline.
* Does NOT buy, honestly: capability containment. The daemon still holds
  and passes the SA token; a fully compromised daemon spawns its own fetch.
  (c) hardens against memory-disclosure-class bugs, not daemon takeover.
  The durable-power residual stands.

### (d) file source (shipped) and (e) Secure Enclave source (new, staged)

* **File**: `FileSshSigner` signs from a local OpenSSH key file, read into a
  `Zeroizing` buffer per signature. No account, no DEK. Residual: the key
  sits on disk readable by any same-UID process regardless of Sigil; the
  gate governs use THROUGH THE AGENT, not the file itself. Say so in UI copy.
* **Secure Enclave**: key minted in and never leaving the Mac's SE; signing
  happens in hardware after the phone approval; removes the RAM residual
  entirely and is the strongest source. Two hard facts shape it: the SE
  signs P-256 only, so an SE key is `ecdsa-sha2-nistp256` on the wire (the
  agent must grow p256 support alongside its ed25519-only stance, a
  deliberate dependency addition), and the key is not 1Password-managed nor
  exportable (enrollment means adding a NEW public key to each server).
  It is a first-class picker entry in the UI from day one, marked clearly
  by its stage until the signer lands (see the plan).

### Decision

* **Primary source: 1Password fetch-per-signature (a), with signing confined
  to the transient helper child (c) as a hardening stage.** Implemented
  INSIDE `OpSshSigner` as an execution detail; identities, config, gating,
  and the approval card are identical.
* **Equal-citizen sources: file (shipped), Secure Enclave (staged).**
* **Documented alternates: 1P-agent proxy (b) parked; ProxySshSigner later.**
* Residual to carry into `docs/security-claims.md` verbatim: the SA token is
  durable key-exfiltration capability; a daemon compromised at the moment of
  an approved request (or during a live lease) gains lasting signing power.
  Mitigations: token ciphertext at rest, DEK per-approval from the phone,
  key bytes confined to transient children, leases bounded and RAM-only,
  lockdown kills everything.

---

## 2. Layered per-host routing: only the hosts you choose go through Sigil

### The mechanism (exactly what 1Password does today)

OpenSSH resolves per-destination options from `~/.ssh/config`; the first
obtained value wins. Three directives do all the work:

```
Host github.com gist.github.com
  IdentityAgent "/private/tmp/sigil-501/run/ssh-agent.sock"
  IdentityFile ~/.sigil/ssh/github.pub
  IdentitiesOnly yes
```

* `IdentityAgent` points THIS host at Sigil's socket. Every host without a
  matching block keeps the user's normal `SSH_AUTH_SOCK` (native agent, 1P
  agent, whatever). No global environment change, nothing else touched.
* `IdentityFile` naming the PUBLIC key file plus `IdentitiesOnly yes` pins
  which served key ssh offers to that host (a stock OpenSSH pattern: a
  `.pub` file is sufficient when the private half lives in an agent). Sigil
  writes these `.pub` files from config; they are public data.
* Patterns work (`Host *.rowm.co`), and `Match host` is available for
  anything fancier; v1 generates plain `Host` lines from the rule's host
  list, which covers the 1Password-style use exactly.

### Who writes the file

The daemon never writes user dotfiles (it is config-read-only by design).
Routing management is a `sigil-config` concern, driven by the Mac app:

* Sigil owns one generated file, `~/.sigil/ssh/config`, fully regenerated
  from the rules on every change, with a header saying so. Per-rule `.pub`
  files live beside it.
* Opt-in managed mode (`Settings.manage_ssh_config`, default OFF until the
  user flips it in the app or runs `sigil-config ssh routing enable`):
  Sigil inserts exactly one line into `~/.ssh/config`, at the TOP (ssh
  semantics: first value wins, and `Include` must sit outside any `Host`
  block), between markers it owns:

  ```
  # >>> sigil managed >>>
  Include ~/.sigil/ssh/config
  # <<< sigil managed <<<
  ```

  Insertion is idempotent (rewrite only between markers), a timestamped
  backup of `~/.ssh/config` is taken on first insertion, and disabling
  removes the marker block and leaves everything else byte-identical.
* Manual mode (managed OFF): the app and `sigil-config ssh routing show`
  print the exact block to paste, and `sigil doctor` reports whether the
  Include line is present and whether each rule's hosts actually resolve to
  Sigil's socket (`ssh -G <host> | grep identityagent`).
* The all-hosts option stays available but explicit: a rule with hosts
  `["*"]` generates a `Host *` block (the 1P-style global mode), and the
  classic `export SSH_AUTH_SOCK=$(sigil sshagent)` remains for people who
  want the environment route. Neither is the default.

### What routing does and does not promise (honesty)

Routing decides which hosts REACH Sigil's agent; it runs client-side in
OpenSSH and any local process can still connect to Sigil's socket directly.
That never widens anything: every signature through the socket is gated by
the key's own policy regardless of host. And the destination shown on the
phone remains the best-effort session-bind derivation: advisory context,
never a verified boundary. Per-host POLICY is therefore enforced by the
key: each rule owns exactly one key, `IdentitiesOnly` pins that key to the
rule's hosts, and the daemon enforces the policy attached to the key. A key
(by fingerprint) may appear in only one rule; validation rejects a
duplicate, so "which policy applies" is never ambiguous.

---

## 3. Gating and approval UX: the lease model

### Why per-signature approval fails

One `git push` is one signature, but a session is dozens. A phone round trip
per signature is unusable and trains reflexive tapping. The engine already
has the right primitive: per-rule `LeasePolicy`, phone-offered window,
daemon-clamped grant, RAM-only triple-scoped lease, lockdown/revoke/restart
kill. SSH reuses it wholesale.

### Two scopes, deliberately different

The shipped SSH path uses one scope for both coalescing and leasing, with
the data fingerprint folded in. Right for coalescing, fatal for leasing
(every challenge differs, so no lease could ever hit). Split them:

* **Approval scope (coalescing), unchanged:**
  `ssh-sign <key_label> <data_fingerprint>`. Two different challenges never
  share one pending approval; only a byte-identical re-sign coalesces (safe:
  ed25519 is deterministic, same input means same signature).
* **Lease scope, new:** `ssh <key_fingerprint>` (the served key's
  `SHA256:...`, stable where labels may collide). Lease grant key =
  `grant_key(caller_chain, "", lease_scope)`: a lease binds to (caller
  ancestry identity, key), exactly as an op lease binds to (chain, account,
  scope).

Deliberate consequences, chosen not discovered:

* A lease taken from `zsh -> git -> ssh` does not cover `zsh -> ssh`
  (different chain identity). Same as op leases; per-caller is the point.
* The HOST is not part of the lease scope, on purpose: the host line derives
  from the client-supplied session-bind blob and is advisory (the
  `derive_host` comment already says so). Folding a forgeable value into the
  scope would sell host-scoped leases the protocol cannot deliver. The
  honest boundary is (caller chain, key, TTL). Per-host differentiation is
  achieved the enforceable way: different hosts, different rules, different
  keys, different policies (section 2).

### What the lease holds

The decrypted SA token, exactly like an op lease. Within the window each
signature still fetches the key fresh into the transient helper and wipes
it; the key is never cached. Caching the decoded key for the TTL was
considered and **rejected**: it would hold durable signing power in RAM for
minutes, against the residual we already call the design's most honest
weakness, to save a sub-second `op read`. Note honestly: an SSH lease holds
the same SA token an op lease for that account already holds, so it adds no
new capability class in RAM; the marginal exposure is the auto-serve window
itself. For file and SE keys a lease stores an empty credential and is a
pure permission window (the file key is on disk regardless; the SE key
never leaves hardware); same store, same TTL/revoke/lockdown, same
`sigil lease list` row.

### The daemon flow (replaces the hard-coded run-once)

In `Core::approve_and_sign`:

1. Lockdown check (first, fails closed).
2. Route the signer by key blob; route the account if `needs_account()`.
3. Compute the lease scope and grant key. If the key's rule is leasable and
   `leases.token_for(gk_lease, account_label, lease_scope)` hits: sign via
   the signer with the leased credential, audit `approved via=lease`,
   return. No phone contact, no card.
4. Else gate exactly as today, except `ctx.lease` carries the rule's REAL
   policy instead of hard-coded `RunOnce`. The sealed request's
   `lease_policy` already reaches the phone; the phone already offers the
   window only when leasable.
5. On grant: clamp `decision.lease_ttl()` with `policy.clamp_secs` (the
   existing single authority; run-once can never lease even against a
   hostile approver), decrypt the token, `leases.grant(...)` when a window
   was chosen, sign, wipe.

### The phone approval card (exact contents)

`RequestKind::SshSignature` swaps the readout well for the challenge, per
the brief ("the two things worth verifying"). All fields already ride the
sealed `ApprovalRequest`:

* Kind chip: `SSH signature`
* Key (brightest): the rule label, e.g. `GitHub`, with `ssh-ed25519 ·
  SHA256:gz4o...` dimmed beneath. An SE key renders `ecdsa-p256 · Secure
  Enclave` in the same slot; the card is source-blind otherwise.
* Destination: `github.com` when the session-bind host key reverse-resolves
  in known_hosts; else the host-key fingerprint `SHA256:...`; else
  `host not bound`. Advisory weight, never bolded as verified, never
  fabricated.
* Challenge: `SHA256:<b64>` of the exact data-to-sign. Never raw bytes.
* Provenance: `zsh -> git -> ssh` plus machine name. cwd empty for SSH.
* Countdown gauge: full scale `timeout_ms` (per-rule `timeout_sec`, default
  60 for SSH: sshd's default LoginGraceTime is 120s, the approval must fit
  inside it).
* Controls, identical to every request: one tap Approve (Face ID releases
  the wrapped DEK), one tap Deny. When and only when the rule is leasable,
  the approve affordance also offers the window (`Approve for 15 min`, the
  rule's cap). Long-press deny offers `Deny and block git for 1 hour`
  (existing BlockDirective).

### Deny, revoke, lockdown mid-session

* Deny: the agent replies `SSH_AGENT_FAILURE`; the client prints
  `git@github.com: Permission denied (publickey).` Nothing retries silently.
* Lease revoke: phone leases screen and `sigil lease revoke <prefix>` work
  today (same store); the SSH lease shows as `ssh SHA256:... · <caller> ·
  Nm left`. Next signature gates fresh.
* Lockdown: `leases.clear()` zeroizes every lease including SSH;
  `approve_and_sign` refuses at step 1 while locked. The next signature of
  an in-flight session fails; ESTABLISHED connections are untouched (Sigil
  gates key release, it is not a session firewall; the Mac copy must say
  that rather than imply otherwise).
* Timeout: the pending request expires to deny; terminal sees the same
  permission-denied.

---

## 4. Config and the Mac app

### The unit of configuration: the SSH rule

One rule = { hosts, key source, policy }. It replaces both halves of
`~/.sigil/ssh-keys.json` and lives in the ONE hot-reloaded `config.json`
(third top-level section; rationale: the LeasePolicy serde and the hot
watcher live there, and the Mac app already loads/writes whole-config via
`sigil-config export`/verbs/`import`, so app work becomes a Codable
extension, not a second seam). SSH rules are keyed by key blob, carry no
argv match and no precedence order, so they get their own array rather than
a shoehorned `Match` variant.

```json
{
  "version": 1,
  "sources": [ ... ],
  "rules": [ ... ],
  "sshRules": [
    {
      "name": "github",
      "hosts": ["github.com", "gist.github.com"],
      "source": { "kind": "1password",
                  "vault": "Engineering", "item": "GitHub",
                  "field": "private key" },
      "publicKey": "ssh-ed25519 AAAAC3Nza... tom@rowm",
      "comment": "tom@rowm",
      "lease": { "kind": "leasable", "maxSecs": 900 },
      "timeout_sec": 60
    },
    {
      "name": "prod-bastion",
      "hosts": ["bastion.rowm.co", "*.prod.rowm.co"],
      "source": { "kind": "secure-enclave", "keyId": "sigil-se-1" },
      "publicKey": "ecdsa-sha2-nistp256 AAAA...",
      "lease": { "kind": "leasable", "maxSecs": 300 }
    },
    {
      "name": "legacy",
      "hosts": ["old.example.net"],
      "source": { "kind": "file", "path": "/Users/tom/.ssh/id_ed25519" }
    }
  ]
}
```

Field semantics:

* `name`: unique id (audit, lease display, `.pub` filename, phone label).
* `hosts`: the OpenSSH `Host` patterns this rule routes (section 2). May be
  empty: the key is served but nothing is routed (reachable only via a
  global `SSH_AUTH_SOCK` or a hand-written block). `["*"]` is the explicit
  gate-everything mode.
* `source`: internally tagged by `kind`, one per `SshSigner` impl:
  `1password {vault, item, field}` (ref derived as `op://v/i/f`, fetched
  with `?ssh-format=openssh`), `file {path}` (sibling `<path>.pub` supplies
  the public key), `secure-enclave {keyId}` (staged). Adding a source kind
  later is one enum variant + one signer, nothing else moves.
* `publicKey`: the OpenSSH public line; what IDENTITIES_ANSWER advertises
  and what SIGN_REQUEST routing matches. Required for `1password` (keeps
  the store inert: listing keys never calls `op`), derived for `file`,
  recorded at mint for `secure-enclave`.
* `lease`: the same `LeasePolicy` serde as command rules; absent means
  run-once (fail-safe default). `timeout_sec`: per-rule approval timeout,
  default 60 for SSH.
* Validation at author time (`sigil-config` and import): unique name;
  parseable public key of a supported algorithm for the source (ed25519
  for 1password/file, p256 for SE); non-empty vault/item for 1password;
  existing `.pub` for file; a key fingerprint may appear in only ONE rule
  (unambiguous policy); host patterns non-empty strings; lease cap sane.
  Rejection at author time replaces today's silent drop-at-arm-time.

Migration: on first load, if `config.json` has no `sshRules` and
`~/.sigil/ssh-keys.json` exists, migrate (all run-once, hosts empty) and
write back; the `commands.json` precedent. CLI authoring moves to
`sigil-config ssh add|remove|set-lease|set-hosts|routing enable|disable|show`
(config mutation belongs to `sigil-config` per the binary split);
`sigil ssh list` stays read-only in `sigil`. An older daemon reading a newer
config ignores `sshRules` (serde unknown-field tolerance) and serves no
keys: fails closed to "agent advertises nothing".

### The credential for the 1Password source

Today the daemon routes the account store by the ref's vault
(`store.route(vault)`), which matches Tom's live setup (`sigil account
add`). The Mac app's current IA has no account surface (its op quick start
seals `OP_SERVICE_ACCOUNT_TOKEN` as inline env). Two models:

* **A (recommended): account-store routing, unchanged.** The SSH rule
  editor requires a 1Password account in the account store and shows which
  one will fetch (`Fetches with account Rowm`). If none exists, the editor
  offers the same masked write-once token paste the env rows use, but lands
  it via `sigil account add --token-stdin` (sealed under the DEK, leasable,
  rotatable). One reviewed credential path; the account store becomes
  hidden plumbing rather than a surface.
* **B (rejected for now): per-rule sealed token blobs** (like inline env).
  Symmetric with the app's env story but forks the credential machinery
  (second sealed-token path, second rotate story, special lease carriage).
  Not worth it for a single-user instrument; revisit only if the account
  store is ever retired.

Open Question 1 for Tom, recommendation A.

### Mac app UI (concrete, buildable)

**Placement**: a new `SSH` sidebar pane (peer of Rules), because SSH rules
are host-shaped, not argv-shaped, and the layered picture needs its own
canvas. The Rules quick-start grid gains a cross-link tile (`SSH signing
key` / `Gate git push and ssh on your phone.` / symbol `signature`) that
jumps to the SSH pane's add sheet.

**The SSH pane, top to bottom:**

1. Agent status strip: `ssh-agent · 3 keys served` + the socket path, and
   the routing mode: `Sigil manages ~/.ssh/config` toggle (managed mode,
   section 2) with a `View block` affordance that shows the exact generated
   text; when OFF, the same sheet offers `Copy block to paste`.
2. The gated-hosts list, one row per rule, three columns of fact:
   * `github.com, gist.github.com` (hosts, primary)
   * source chip: `1Password · Engineering/GitHub` or `Key file ·
     ~/.ssh/id_ed25519` or `Secure Enclave`
   * policy: `Approve every time` or `Approve once, 15 min window`
   Row affordances: edit (sheet below), remove (two-step, like rules).
3. The honest floor row, always last, non-interactive:
   `Every other host · unmanaged · your normal SSH agent answers`.

**The add/edit sheet (`SshRuleEditorSheet`), field order:**

1. `Hosts`: token field, one or more patterns (`github.com`,
   `*.prod.rowm.co`). Helper: `Only these hosts route through Sigil.
   Everything else keeps your current agent.`
2. `Key source`: a segmented picker, the seam made visible:
   `1Password | Key file | Secure Enclave`.
   * 1Password: `Vault` + `Item` (+ `Field`, default `private key`), a live
     preview line `op://Engineering/GitHub/private key`, and the
     `Public key` paste well (validated ed25519, live fingerprint
     `SHA256:...` preview so what the phone will show is visible at author
     time). Helper: `Paste the public key from the 1Password item. Sigil
     never stores the private key; it is fetched per signature after your
     approval.` Below, the account line per model A.
   * Key file: a path picker for the private key (validates that
     `<path>.pub` exists and parses). Helper: `Sigil reads this file only
     at signing time, after approval. The file itself stays on disk under
     your normal permissions.`
   * Secure Enclave: `Create key` (mints a P-256 key in the SE, then shows
     the public line with a copy button and `Add this public key to the
     server before saving.`). Marked with its stage until the signer lands.
3. `Label`: defaults to the item name / file stem; the phone's brightest
   line.
4. `Approval`: the exact control the rule editor uses: `Approve every time`
   (default) vs `Approve once, keep for a window` with the
   `LeaseDuration.presets` cap picker (5m/15m/30m/1h/2h/4h).
5. Routing note (read-only): managed mode ON shows `Sigil will update
   ~/.ssh/config for these hosts on save.`; OFF shows `Copy the ssh config
   block after saving.`
6. Footer, quiet honesty: `The destination shown on your phone is
   best-effort context from the connection, not a verified boundary.`

No host-scoping control ever appears on the POLICY side (host is
client-claimed; policy binds to the key, section 2).

**Seam additions** (`DaemonClient` + `CLIDaemonClient`): `sshRules` arrive
free via `sigil-config export`; mutations via `sigil-config ssh add ...
--json` / `remove` / whole-config `import` (the export -> mutate -> import
shape rule edits already use); routing via `sigil-config ssh routing
enable|disable|show --json`. `SigilConfig.swift` gains `SshRuleConfig` +
`SshSourceConfig` mirroring the Rust structs field-for-field (hand-written
Codable for the serde-omitted fields, as `MatchConfig` does).

---

## 5. Wiring: what makes `git push` ask the phone

1. One-time, per key: put the key where its source expects it. For the lead
   path: create the SSH Key item in an SA-visible shared vault
   (Engineering; the SA cannot see Personal; today there are ZERO SSH Key
   items in SA-visible vaults, so this is Tom's prerequisite).
2. One-time: add the rule in the Mac app SSH pane (or `sigil-config ssh add
   --hosts github.com --vault Engineering --item GitHub --pubkey-file
   ~/.ssh/id_ed25519.pub --lease 900`). The config watcher hot-loads it;
   the agent advertises the key immediately, no restart.
3. One-time: enable managed routing (or paste the shown block). From then
   on `ssh -G github.com` resolves `identityagent` to Sigil's socket and
   `identitiesonly yes` with the rule's `.pub`; every other host is
   untouched. `sigil doctor` verifies the Include line, the generated file,
   and per-rule resolution.
4. Every `git push` / `ssh github.com` then: OpenSSH reads the managed
   block, connects to Sigil's socket, REQUEST_IDENTITIES answered from
   config (public data only; daemon still inert; no `op` call), server
   accepts the key, OpenSSH sends session-bind then SIGN_REQUEST, and the
   daemon runs section 3's flow: lease short-circuit (silent, sub-second)
   or the phone card (Face ID tap, optional window). On approval the helper
   child fetches `op://...?ssh-format=openssh`, signs, wipes; SIGN_RESPONSE
   completes the auth; git proceeds.
5. Terminal experience, honestly: the agent protocol has no side channel to
   the client's terminal, so a gated `git push` simply PAUSES at the auth
   step until the tap (the Mac menubar shows the pending card during the
   pause; that is the affordance), then continues. Deny or timeout prints
   `git@github.com: Permission denied (publickey).` Under a live lease
   there is no pause beyond the `op read` round trip.

Live verification checklist (carried forward, still open): a real
`ssh -T git@github.com` producing a GitHub-accepted signature with a phone
tap; the session-bind host key diffed against the known_hosts `github.com`
line; `ssh -G` resolution with the managed Include in place.

---

## 6. Security model and residuals

Mapped to the invariants:

1. **Daemon inert at rest.** Holds: config carries public keys, host
   patterns, and op coordinates; the SA token stays AES-256-GCM ciphertext;
   the DEK arrives per-approval from the phone or via a live lease.
2. **Secret bytes never in daemon memory.** Holds for key material once the
   helper child lands (key confined to transient processes); until then the
   shipped, documented exception stands (key in daemon RAM, Zeroizing,
   milliseconds). The SIGNATURE transits the daemon, which is fine: it is
   the output the client receives anyway.
3. **Relay powerless.** Unchanged: `SshChallenge` and `lease_policy` ride
   inside the sealed, signed envelope; the relay sees opaque bytes on a
   key-hash mailbox. No new relay-visible surface.
4. **Approve requires hardware biometrics; deny requires nothing.** Holds:
   same `ApprovalGate`/factor resolution; a lease opens only via an
   approved, Face-ID-gated tap on a rule the user explicitly made leasable,
   daemon clamping as sole authority.
5. **Fail closed**, enumerated: lockdown first; unknown key blob refused;
   unsupported algorithms rejected at author time; deny/timeout/parse
   failure yield `SSH_AGENT_FAILURE`; a config that fails to parse keeps
   last-good rules and serves no new keys; a leasable response for a
   run-once rule clamps to nothing; a missing account fails the sign, not
   the gate.
6. **No em-dashes, no emoji** in any string this design adds.

SSH-specific residuals, to be recorded in `docs/security-claims.md` by an
independent security-reviewer pass (never self-certified here):

* **Durable-power residual (the big one, unchanged):** the SA token reads
  the entire private key; a daemon compromise at the moment of an approved
  request or during a live lease leaks lasting signing power, not one
  signature. The helper child narrows MEMORY exposure, not this capability.
  The SE source removes it per-key; v2 makes that the headline.
* **Lease window residual:** during a lease, signatures for (caller chain,
  key) auto-serve with no per-signature human. Bounded by TTL and cap,
  RAM-only, killed by lockdown/revoke/restart. Same class as op leases; the
  brief's honest-limit language (same-user malware can imitate a caller
  during a live window) applies verbatim.
* **Advisory host line:** session-bind is client-supplied and unverified;
  the phone's host is context, not a boundary; the load-bearing fields are
  key label + challenge fingerprint + the fact of an unexpected request.
  Never build policy on the shown host. Host ROUTING (section 2) is
  client-side convenience and never widens anything: direct socket clients
  are still gated per key.
* **File-source residual:** the on-disk key is readable by same-UID
  processes regardless of Sigil; the gate governs use through the agent.
* **Token transit to the helper:** stdin only (argv/env readable same-UID
  via `KERN_PROCARGS2`); the helper is our own binary, coverable by the
  same code-identity measurement leases use.
* **`~/.ssh/config` management:** the managed Include is a user-consented
  dotfile edit with markers, a first-run backup, and byte-identical
  removal; the generated file is regenerated whole, never merged. A hostile
  same-UID process could edit ssh config anyway; Sigil's edit adds no new
  capability class.
* **Coalescing:** byte-identical challenges may share one approval, safe
  because ed25519 (and ECDSA under RFC 6979 if the SE path uses it;
  NEEDS VERIFICATION: SE ECDSA nonce behavior is hardware-internal, treat
  coalescing of P-256 challenges as approved-window semantics regardless);
  different data can never coalesce (fingerprint in the approval scope).

Hostile-client agent tests to add: forged session-bind naming a real public
host key (card must render it as advisory and the audit must record the
fingerprint), sign requests for unserved blobs, oversized frames (bounded
today by MAX_MESSAGE_LEN), connection floods against the cap, a hostile
approver returning a lease for a run-once rule (clamped to nothing).

---

## 7. Staged implementation plan

Stage 0, verify the shipped path live (0.5 day, needs Tom): create the real
GitHub key item in Engineering, `sigil ssh add`, point one host at the
socket, `ssh -T git@github.com`, tap, confirm GitHub accepts; log the
session-bind blob and diff against known_hosts. Closes the two open
NEEDS-VERIFICATION items in `docs/design/ssh-agent.md`.

Stage 1, config unification + routing (2 days, rust-core):
* `config.rs`: `SshRuleConfig` + `SshSourceConfig` (tagged enum) + `sshRules`
  on `Config`; author-time validation; migration from `ssh-keys.json`.
* `daemon.rs`: build signers from the hot `ConfigCell` snapshot (rebuild on
  watcher reload) instead of arm-time `ssh-keys.json`.
* `cli.rs`: `sigil-config ssh add|add-file|remove|set-lease|set-hosts`;
  `sigil-config ssh routing enable|disable|show` (managed Include block,
  markers, backup, generated `~/.sigil/ssh/config` + per-rule `.pub`
  files); `sigil ssh list` reads the new location; `sigil doctor` gains the
  `ssh -G` resolution checks.

Stage 2, leases for SSH (1 day, rust-core):
* `daemon.rs::approve_and_sign`: lease-scope split (`ssh <key_fp>` for
  leases, per-challenge scope for coalescing), `token_for` short-circuit,
  `ctx.lease` from the rule, clamp + `leases.grant` on a chosen window,
  audit `via=lease`, empty-credential windows for file keys.
* Tests: leasable rule signs twice on one approval inside TTL; run-once
  never leases even against a hostile approver; expiry re-gates; lockdown
  clears; a different caller chain misses the lease.

Stage 3, approver surfaces (1 day, phone-app + mac-app, display only):
* Phone: the `ssh_signature` card per section 3 (fields already in the
  request; the lease offer is the existing leasable control). Verify with
  `sigil-softphone` first.
* Mac menubar: `up to Nm` on a leasable pending SSH request; leases pane
  already lists SSH leases via the shared store.

Stage 4, Mac app SSH pane (2.5 days, mac-app):
* `SigilConfig.swift`: `SshRuleConfig`/`SshSourceConfig` Codable mirrors.
* New `SshView.swift` (pane: status strip, routing toggle + block sheet,
  gated-hosts list, unmanaged floor row) + `SshRuleEditorSheet.swift`
  (hosts, source picker, per-source fields, label, approval, routing note).
* `CLIDaemonClient.swift` + `DaemonClient`: the `sigil-config ssh` verbs.
* Rules quick-start cross-link tile; `StatusView` agent line.
* design-reviewer pass on every string and state.

Stage 5, helper-child hardening (1 day, rust-core):
* Hidden `sigil ssh-sign-helper` (stdin: token + ref + data; stdout:
  signature blob; nothing logged); `OpSshSigner::sign` spawns it; the
  in-process path stays behind a test seam.
* security-reviewer pass on stages 2 + 5 together (lease semantics, helper
  transit, routing file management); update `docs/security-claims.md`; fix
  brief drift (file signer shipped, lease + routing rows added).

Stage 6, Secure Enclave source (3 to 4 days, rust-core + mac-app, can trail
the release): p256 agent support (`ecdsa-sha2-nistp256` advertise + sign),
SE key mint/list via the keystore seam, `secure-enclave` source kind wired,
enrollment UX (copy public key). Until it lands the picker entry carries
its stage honestly.

Total for stages 0 to 5: about a week and a half including the Mac pane.

---

## 8. Open questions for Tom

1. **Credential model** (section 4): account-store routing with the Mac app
   creating the account as hidden plumbing (recommended, A), or per-rule
   sealed token blobs (B)?
2. **Managed routing default**: managed mode OFF until explicitly enabled
   (recommended: never touch dotfiles unasked), or offer it as the
   checked-by-default step of the first SSH rule's save?
3. **Lease default for the GitHub quick path**: run-once (consistent with
   rules) or leasable 15m preset on the theory that per-push tapping gets
   abandoned otherwise? Recommendation: default the CONTROL to run-once,
   pre-select 15m the moment the user flips to leasable.
4. **Helper child now or later**: stage 5 is pure hardening and can trail
   the lease UX, but should not slip past the public release given the
   brief's custody table.
5. **SE source scheduling**: ship the picker with the staged marker at
   stage 4 (recommended: the seam is the story) or hide it until stage 6
   lands?
6. **ProxySshSigner (1P desktop agent)**: park indefinitely or track as a
   future source for at-desk Personal-vault keys? Either way it needs the
   verification pass on current 1P agent authorization behavior.
