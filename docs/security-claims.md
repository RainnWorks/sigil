# Security claims → enforcing code → proving test

This is the map a skeptical adopter reads. Every row is a claim Latch makes,
the exact code that enforces it (`file::symbol`), and the test that proves it.
A claim with no test is marked **UNPROVEN** in bold; a claim proven only for a
seam that is not yet wired into the shipping daemon is marked **PARTIAL** with
the gap named.

Paths are relative to the repo root. Test names are the `#[test]` fn names;
run any with `cargo test <name>`.

Reviewed at commit `3d005aa` (the first end-to-end remote-approval loop).

---

## 1. Root of trust: pairing is MITM-safe

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| The optical QR carries the daemon's real keys + a 256-bit one-time secret; the phone pins the daemon with certainty | `proto/src/pairing.rs::PairingPayload`, `PhonePairing::scan` | `pairing.rs::qr_roundtrip_preserves_payload` |
| A network attacker who swaps the phone's **full** identity on the return channel is rejected | `proto/src/pairing.rs::PairingResponse::verify` (tag over `pairing_transcript` binding `phone.verifying`+`phone.agreement`) | `pairing_mitm.rs::full_phone_identity_substitution_is_rejected` |
| Swapping only the phone **agreement** key is rejected | same | `pairing_mitm.rs::phone_agreement_key_substitution_alone_is_rejected` |
| Swapping only the phone **verifying** key is rejected | same | `pairing_mitm.rs::phone_verifying_key_substitution_alone_is_rejected` |
| A forged / stripped / bit-flipped confirmation tag is rejected | `pairing.rs::verify_confirmation_tag` (constant-time `Mac::verify_slice`) | `pairing_mitm.rs::forged_random_tag_is_rejected`, `stripped_zero_tag_is_rejected`, `single_bit_flip_in_tag_is_rejected` |
| An attacker without the QR secret cannot forge an acceptable response | `pairing.rs::derive_subkey` (MAC key = secret) | `pairing_mitm.rs::response_built_without_the_qr_secret_is_rejected` |
| Every transcript-bound field (daemon id, endpoints, created_at, phone id, nonce) actually breaks the tag when mutated | `pairing.rs::pairing_transcript` | `pairing_mitm.rs::transcript_binds_daemon_identity`, `transcript_binds_endpoints`, `transcript_binds_created_at`, `transcript_binds_phone_identity_and_nonce`, `nonce_tamper_is_rejected` |
| A response captured from pairing A is worthless against fresh pairing B | `pairing.rs::PairingResponse::verify` | `pairing_mitm.rs::a_captured_response_is_worthless_against_a_fresh_pairing` |
| A stale/expired QR is refused, expiry checked **before** the tag | `pairing.rs::DaemonPairing::receive_response`, `PhonePairing::scan` | `pairing_mitm.rs::expired_response_is_rejected_before_the_tag`, `phone_rejects_a_stale_qr_at_scan` |
| A flood of bad responses never burns the one-time secret | `pairing.rs::receive_response` (consumes only on valid tag) | `pairing_mitm.rs::a_flood_of_bad_responses_never_burns_the_secret` |
| The secret is one-time: a second valid response is refused (daemon and phone) | `receive_response` (`consumed`), `PhonePairing::respond` (`secret.take()`) | `pairing_mitm.rs::a_second_valid_response_is_refused_after_the_first`, `the_phone_emits_exactly_one_response` |
| SAS catches a **leaked-secret** MITM (attacker forged a valid tag with its own key): the six words diverge on the two screens | `pairing.rs::sas_words`, `fingerprint.rs::fingerprint_words`, `verify_sas` | `pairing_mitm.rs::sas_catches_a_leaked_secret_mitm`, `sas_words_diverge_whenever_the_pinned_pair_differs` |
| The pairing secret is CSPRNG, zeroized, and redacts its Debug | `pairing.rs::PairingSecret` (`ZeroizeOnDrop`, custom `Debug`) | `pairing.rs::debug_does_not_leak_secret` |

## 2. DEK handoff and the DEK-return path

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| The DEK is delivered to the phone only after SAS confirmation | `pairing.rs::DaemonPairing::deliver_dek` (requires `Confirmed`) | `pairing_mitm.rs::dek_is_never_delivered_before_sas_confirmation`, `pairing.rs::dek_not_delivered_before_confirmation` |
| A DEK envelope forged by a relay key is rejected (wrong sender) | `proto/src/envelope.rs::Envelope::open` (Ed25519 over `canonical_bytes`) | `pairing_mitm.rs::dek_from_a_forged_sender_is_rejected` |
| A DEK sealed to the phone cannot be opened by any other recipient | `envelope.rs::Envelope::open` (crypto_box to pinned agreement key) | `pairing_mitm.rs::dek_to_the_wrong_recipient_cannot_be_opened` |
| A replayed DEK envelope is rejected | `envelope.rs` + `replay.rs::ReplayGuard` | `pairing_mitm.rs::a_replayed_dek_envelope_is_rejected` |
| On approve, the phone's `ApprovalResponse` carries the DEK sealed inside the Envelope; a relay/MITM can neither read nor replay it | `request.rs::ApprovalResponse::approve`, `remote.rs::RemoteApprover::round_trip` (open + `guard` + `request_id` correlation) | `daemon.rs::remote_softphone_approval_delivers_secret_over_the_socket`; envelope confidentiality by `hostile_relay.rs::relay_cannot_read_the_payload` |
| A deny response carries **no** DEK, so a denial can never release a secret | `request.rs::ApprovalResponse::deny`, `remote.rs` (approve without DEK fails closed) | `daemon.rs::remote_softphone_denial_fails_closed_with_no_secret`, `request.rs::approve_carries_the_dek_and_deny_never_does` |
| A malformed DEK base64 fails closed to `None`, never a partial key | `request.rs::ApprovalResponse::dek` | `request.rs::malformed_dek_base64_fails_closed_to_none` |
| The decoded DEK bytes do not linger in a non-zeroized heap buffer | `request.rs::ApprovalResponse::dek` (`Zeroizing` decode buffer) | *(hardening; covered by roundtrip `response_round_trips_through_json`)* |
| The daemon zeroizes the DEK immediately after decrypting the one token | `daemon.rs::fulfill` (`drop(dek)` after `decrypt_token`; `Dek` is `Zeroizing`) | **UNPROVEN** by direct observation (drop timing is not asserted); exercised end-to-end by `remote_softphone_approval_delivers_secret_over_the_socket` |

## 3. Daemon inert at rest

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| Tokens are AES-256-GCM ciphertext at rest; no plaintext token on disk | `secrets.rs::encrypt_token`, `AccountStore::save` (0600 file / 0700 dir) | `secrets.rs::store_persists_ciphertext_only` |
| AES-256-GCM nonce is random per seal; identical plaintext yields different ciphertext (no nonce reuse) | `secrets.rs::encrypt_token` (`OsRng` 96-bit nonce) | `secrets.rs::nonce_is_unique_so_ciphertext_differs` |
| Wrong DEK or tampered ciphertext is rejected (authenticated) | `secrets.rs::decrypt_token` | `secrets.rs::wrong_dek_fails_to_decrypt`, `tampered_ciphertext_is_rejected`, `truncated_ciphertext_is_rejected` |
| In the remote configuration the daemon holds **no** DEK at rest; the key arrives per-approval from the phone | `daemon.rs::Core` (MemoryKeystore with no DEK), `remote.rs` | `daemon.rs::remote_softphone_approval_delivers_secret_over_the_socket` (keystore has no DEK) |
| The DEK is CSPRNG and zeroized | `secrets.rs::generate_dek` (`Zeroizing`), `pairing.rs::Dek` (`ZeroizeOnDrop`) | `secrets.rs::dek_is_random_each_call`, `pairing.rs::dek_debug_does_not_leak` |

## 4. Secrets bypass the daemon (invariant #2)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| The `op` child's stdout/stderr are the caller's own fds; secret bytes never enter daemon memory | `daemon.rs::spawn_op` (`Stdio::from(fd)`), `local.rs::recv_with_fds` (SCM_RIGHTS) | `daemon.rs::dev_autoapprove_full_loop_delivers_secret_to_caller` (asserts secret reached the *caller* fd), `local.rs::op_fd_passing_and_reply_roundtrip_over_a_socketpair` |
| The provider seam injects a **credential** (SA token) into the child env, never fetches secret values into the daemon | `provider.rs` (describe/kind only), `daemon.rs::spawn_op` (`OP_SERVICE_ACCOUNT_TOKEN`) | `provider.rs::describe_extracts_op_references_only`; end-to-end `remote_softphone_approval_delivers_secret_over_the_socket` |
| The daemon never logs the token or secret output; only argv/cwd/pid | `daemon.rs::log_request`, `secrets.rs::probe_vaults` (suppresses token-bearing stderr) | **UNPROVEN** (no negative-logging assertion); reviewed by inspection |

## 5. Replay is impossible (post-pairing envelopes)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| Single-use uuidv7 request id | `replay.rs::ReplayGuard::check_and_record` | `replay.rs::duplicate_request_id_is_rejected`, `hostile_relay.rs::replay_of_a_delivered_envelope_is_rejected` |
| Per-pairing monotonic counter must strictly advance | `replay.rs` | `replay.rs::counter_must_strictly_advance`, `hostile_relay.rs::a_genuinely_old_lower_counter_message_is_rejected`, `reordering_queued_envelopes_is_caught` |
| 90s freshness window; held-late and skewed envelopes rejected | `replay.rs`, `lib.rs::REPLAY_WINDOW_MS` | `replay.rs::stale_timestamp_beyond_window_is_rejected`, `future_timestamp_beyond_window_is_rejected`, `hostile_relay.rs::an_envelope_held_past_the_window_is_rejected` |
| Any field tamper breaks the Ed25519 signature | `envelope.rs::canonical_bytes`, `open` | `envelope.rs::any_field_tamper_breaks_the_signature`, `hostile_relay.rs::{bit_flipped_ciphertext,swapped_ciphertext_between_envelopes,forged_envelope_from_relay_key}_is_rejected` |
| A rejected envelope never poisons later state | `replay.rs::check_and_record` (record only on full pass) | `replay.rs::rejected_envelope_does_not_advance_state` |

## 6. Biometric gating is structural (invariant #5)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| A dev/in-memory keystore can never count as the biometric approving factor | `keystore.rs::Keystore::is_biometric` (default `false`), `approve.rs::LocalApprover::decide_local` (guard `is_biometric() && has_dek()`) | `keystore.rs::memory_keystore_is_not_a_biometric_factor`, `approve.rs::dev_autoapprove_grants_without_biometrics` (grant only via explicit dev switch) |
| Only the macOS Secure Enclave keystore reports biometric, and its unwrap refuses until verified on hardware | `keystore_macos.rs::MacKeystore::is_biometric` (`true`), `unwrap_dek` (`NeedsVerification`) | `keystore_macos.rs::se_paths_refuse_until_verified` |
| Deny / timeout always fails closed (never a grant) | `approve.rs::LocalApprover::decide_local` (timeout → `Deny`), `remote.rs::RemoteApprover::decide` (`unwrap_or Deny`) | `approve.rs::local_timeout_fails_closed`, `daemon.rs::denied_request_fails_closed_and_delivers_no_secret` |
| The Secure Enclave DEK unwrap fires Touch ID on real hardware | `keystore_macos.rs::unwrap_dek` | **UNPROVEN — PARTIAL**: FFI is documented but returns `NeedsVerification`; must be exercised on a Mac (see NEEDS-VERIFICATION block). Until then, the shipping local approver falls through to the control socket (see Residuals). |

## 7. Caller identity is daemon-verified (invariant #6)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| Peer pid is read from the kernel, not the client | `lease.rs::peer_pid` (`LOCAL_PEERPID`/`SO_PEERCRED`) | **UNPROVEN — PARTIAL** on hardware (`NEEDS-VERIFICATION` in `lease.rs`); logic exercised via injected pid in daemon tests |
| Ancestry is walked kernel-side; the grant key binds code identity, never pids | `lease.rs::walk_ancestry`, `grant_key` (excludes pids) | `lease.rs::ancestry_walk_is_root_first_and_stops_at_init`, `grant_key_ignores_recycled_pids`, `grant_key_changes_with_root_scope_or_ancestry` |
| The ancestry walk terminates on cycles / bounded depth | `lease.rs::walk_ancestry` (`MAX_ANCESTRY_DEPTH`, `seen` set) | `lease.rs::ancestry_walk_terminates_on_a_cycle` |
| A phone-claimed grant key is ignored; the daemon derives and trusts its own | `daemon.rs::fulfill` (uses `gk`), `request.rs::InstallLease` (echo only), `softphone/lib.rs` (empty `grant_key`) | reviewed by inspection; exercised by `daemon.rs::lease_decision_covers_the_next_identical_request` |
| The ancestor "code identity" is a real code-signing measurement | `lease.rs::SysProcessTable::identity` | **UNPROVEN — PARTIAL**: interim BLAKE2b of the exe bytes; the design calls for the cdhash / Developer ID (NEEDS-VERIFICATION in `lease.rs`) |

## 8. Fail closed, leases bounded, lockdown (invariants #7, #8)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| Every failure path denies (deny, timeout, dead phone, decrypt failure, lockdown) | `daemon.rs::fulfill` (`fail_closed` on each branch), `remote.rs::round_trip` (`?`/`None` → Deny) | `daemon.rs::denied_request_fails_closed_and_delivers_no_secret`, `remote_softphone_denial_fails_closed_with_no_secret`, `approve.rs::local_timeout_fails_closed` |
| Leases are RAM-only, triple-scoped (grant key + account + scope) | `lease.rs::LeaseStore`, `Lease` | `lease.rs::lease_grant_lookup_and_scope_isolation` |
| Leases expire on TTL and are purged (and zeroized) | `lease.rs::token_for`/`grant` (`retain(expires>now)`; token is `Zeroizing`) | `lease.rs::lease_expires_and_is_purged` |
| Lockdown clears (zeroizes) every lease and refuses new requests | `daemon.rs::handle_conn` (`Lockdown`), `lease.rs::LeaseStore::clear`, `fulfill` (lockdown check first) | `lease.rs::lockdown_clears_all_leases`, `daemon.rs::lockdown_refuses_new_requests` |
| Daemon restart / ctrl-c zeroizes leases | `daemon.rs::serve` (`core.leases.clear()` on ctrl-c) + RAM-only storage | **UNPROVEN** by test (process-exit path); RAM-only + `clear()` reviewed by inspection |
| A revoke drops matching leases | `lease.rs::LeaseStore::revoke` | `lease.rs::revoke_by_grant_prefix` |

## 9. The relay is powerless (invariant #3)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| The relay never sees plaintext (opaque envelopes only) | `envelope.rs::Envelope`, `transport.rs` (carries opaque envelopes); the real network transport carries the same opaque `serde_json` envelope string (`relay-client/src/lib.rs::wire`, daemon-side WS `DaemonRelay`, phone-side HTTPS `PhoneRelay`) | `hostile_relay.rs::relay_cannot_read_the_payload`; end to end over the **real** Bun relay by `daemon.rs::remote_approval_over_the_real_relay_delivers_the_secret` |
| The relay cannot forge, tamper, replay, reorder, backdate, or drop-to-effect | `envelope.rs::open`, `replay.rs` (unchanged whichever transport carries the bytes) | the full `hostile_relay.rs` suite (14 attacks) |
| The mailbox id carries no identity and is order-independent | `fingerprint.rs::mailbox_id` | `fingerprint.rs::mailbox_is_order_independent`, `mailbox_differs_for_different_pairs`, `fingerprint_and_mailbox_are_domain_separated` |
| The relay has no key-distribution role (pairing is out-of-band QR) | `pairing.rs` (keys travel optically) | design invariant; the whole `pairing_mitm.rs` suite proves trust does not rest on any network party |

---

## Residuals (honest limits)

These are real and deliberately surfaced, not defects hidden.

1. **The local control-socket approver is not an adversarial gate — now gated
   behind an explicit arm-time factor policy (MITIGATED).** The control socket
   is same-UID-forgeable: an approval is granted by whoever sends
   `Frame::Approve { id }` on the 0600 unix socket, and the request `id` is only
   printed to the daemon's stderr, so a same-UID attacker who can read it can
   self-approve. A compromised same-UID agent (a rogue `claude`/`op`) is exactly
   the adversary Latch exists to stop, so this path must never be the sole gate.

   The mitigation, added with the network transport: at arm time the daemon
   resolves an explicit **approving factor** (`factor.rs::resolve`,
   `daemon.rs::build_gate`), in order:
   - a **paired phone** reachable over a `Transport` (`RemoteApprover`) — the
     sealed, signed `ApprovalResponse` a same-UID peer cannot forge;
   - a **verified hardware biometric** (`Keystore::is_biometric()` true) — the
     Secure Enclave unwrap is the gate;
   - otherwise **fail closed**: a `NullApprover` denies every gated request,
     **unless** started with `--dev-insecure` / `LATCH_DEV_INSECURE=1`.

   Only under `--dev-insecure` are `LATCH_DEV_AUTOAPPROVE` (`with_dev`) and the
   control-socket park (`with_control_socket`) wired at all, and that mode prints
   a loud multi-line stderr warning naming the same-UID risk on every start
   (`factor.rs::warn_dev_insecure`). A normal `latch daemon` with no phone and no
   biometric is **not** silently self-approvable: it runs the `NullApprover` and
   refuses. With a biometric factor, an unresolved local decision fails closed
   rather than parking on the socket (`approve.rs::LocalApprover::decide_local`
   returns `Deny` when `allow_control_socket` is false).

   Proving tests: `daemon.rs::no_factor_daemon_fails_closed_on_a_gated_request`
   (no factor + no dev flag denies, delivers no secret),
   `approve.rs::without_control_socket_an_unresolved_decision_fails_closed_at_once`
   and `null_approver_denies_every_request`, the `factor.rs::tests` suite
   (`resolve` precedence: phone > biometric > dev-insecure > fail-closed, and the
   warning names the same-UID risk), and the phone factor proven end to end over
   the real relay by
   `daemon.rs::remote_approval_over_the_real_relay_delivers_the_secret` and
   in-process by `remote_softphone_approval_delivers_secret_over_the_socket`
   (both with no dev flag set). Severity: **Medium-High reduced to a documented
   dev-only mode that fails closed by default and is loudly labelled.**

2. **Secure Enclave biometric unwrap and kernel peer/ancestry are unproven on
   hardware.** `keystore_macos.rs::{ensure_dek,unwrap_dek}`, `lease.rs::peer_pid`,
   and the code-signing `identity` all carry NEEDS-VERIFICATION and cannot be
   exercised away from a Mac. Until verified, the biometric factor is inert
   (returns `NeedsVerification`), so the effective shipping gate is either the
   phone or residual #1.

3. **The SA token transits daemon RAM (unavoidable) and one copy is not
   zeroized.** The token is the injected credential, so it must reach the child
   env. `daemon.rs::fulfill` holds it in a `Zeroizing` `Token` and `drop`s it
   after spawn, and `spawn_op` never logs it. But `std::process::Command`'s env
   map holds an ordinary `String` copy of the token until the local `cmd` drops
   at the end of `spawn_op`, and `Command` does not zeroize. So one plaintext
   copy of the token lives, un-wiped, for the span of the child spawn. This is a
   std limitation, not a logic error; it is bounded to the spawn and the value
   is the SA token (not the DEK, not the resolved secret). Documented, not
   fixed.

4. **The DEK's base64 form transits daemon RAM in a non-zeroized `String`.** The
   raw 32-byte DEK is now zeroized on every path (`Dek` is `ZeroizeOnDrop`; the
   decode buffer in `request.rs::ApprovalResponse::dek` is `Zeroizing` as of this
   review), but the `ApprovalResponse.wrapped_dek: Option<String>` still holds
   the base64 of the DEK until the response struct drops. serde deserializes into
   a plain `String`; zeroizing it would need a custom wrapper type. Low severity
   (same-process, requires scraping daemon memory).

5. **Lease-window / approved-consumer misuse (by design).** A lease is a
   time-boxed grant to a *caller code-identity + project + scope*. Within an
   active lease, the same process tree can re-fetch **the same-scope secret**
   without re-prompting; a compromised ancestor in that tree (e.g. `claude`) can
   exploit its own lease for the exact secret it was already approved for. It
   **cannot** widen scope: a different secret is a different `scope` string →
   different grant key → fresh approval (`lease.rs::grant_key`,
   `daemon.rs::fulfill`). The token itself never leaves the daemon, so the lease
   cannot be exfiltrated, only re-exercised for its one scope. Bound by TTL and
   killed by lockdown/restart.

6. **Metadata at the relay.** The relay learns that two anonymous mailbox
   parties exchange envelopes, and the sizes/timing of those envelopes. This is
   inherent to any store-and-forward transport and is the accepted trust surface
   (`docs/design/latch-design-brief.html`, Trust model).
