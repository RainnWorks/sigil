# Security claims → enforcing code → proving test

This is the map a skeptical adopter reads. Every row is a claim Sigil makes,
the exact code that enforces it (`file::symbol`), and the test that proves it.
A claim with no test is marked **UNPROVEN** in bold; a claim proven only for a
seam that is not yet wired into the shipping daemon is marked **PARTIAL** with
the gap named.

Paths are relative to the repo root. Test names are the `#[test]` fn names;
run any with `cargo test <name>`.

**Authorship convention (review integrity).** The claim/code/test rows and the
residuals are maintained by whoever touches the surface. But a *verdict*, any
"reviewed and found sound" / "CONFIRMED SOUND" statement about whether a
construction is correct, is written **only by an independent security-reviewer
that did not author the code under review**, never by the implementer
(self-certification is not a verdict). A proving-test cell reading "reviewed by
inspection" is a narrower thing: a reviewer's note that a specific claim is
verified by manual inspection because it has no automated test (and it is flagged
**UNPROVEN** where inspection is the only evidence). It is not a soundness
verdict. Sweep at `747b3a4`: the only construction verdict in this document is
§14 (P-256 SE wrap), written by the reviewer, not the implementer.

Reviewed at commit `3d005aa` (the first end-to-end remote-approval loop).
Extended at commit `ee49ee3` (any-CLI generalization: provider registry, the
`env-file` direct-injection provider, the pluggable SSH signer, and the
CLI-only pairing persistence), sections 11-13 and residuals 9-11 below.
Extended again at commit `747b3a4` (the P-256 Secure Enclave DEK wrap), section
14 and residual 12; and the env-file invalid-UTF-8 residual was fixed (see §12).

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

Two-gate guard (task #67 retired the monotonic-counter gate; see the implementer note below).

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| Single-use uuidv7 request id | `replay.rs::ReplayGuard::check_and_record` | `replay.rs::duplicate_request_id_is_rejected`, `hostile_relay.rs::replay_of_a_delivered_envelope_is_rejected`, `reordering_distinct_envelopes_is_accepted` (identical-bytes resend still rejected) |
| Freshness window (`REPLAY_WINDOW_MS`, 150s); held-late and skewed envelopes rejected | `replay.rs`, `lib.rs::REPLAY_WINDOW_MS` | `replay.rs::{stale_timestamp_beyond_window_is_rejected,future_timestamp_beyond_window_is_rejected,a_replay_after_the_id_ages_out_is_caught_by_freshness}`, `hostile_relay.rs::an_envelope_held_past_the_window_is_rejected` |
| Counter is ungated: a lower/reset counter with a fresh ts and a new id is accepted (was a false-replay drop) | `replay.rs::check_and_record` (counter param retained, not gated) | `replay.rs::lower_or_reset_counter_with_fresh_ts_and_new_id_is_accepted`, `envelope.rs::lower_counter_with_fresh_ts_and_new_id_is_accepted`, `hostile_relay.rs::a_genuinely_lower_counter_message_is_now_accepted` |
| Seen-set memory is bounded by age (plus a hard `MAX_SEEN` backstop) | `replay.rs::{evict_aged,record}` | `replay.rs::{age_eviction_keeps_the_set_bounded_over_a_moving_window,hard_cap_bounds_a_same_instant_burst}` |
| Any field tamper (incl. the ungated counter) breaks the Ed25519 signature | `envelope.rs::canonical_bytes`, `open` | `envelope.rs::any_field_tamper_breaks_the_signature`, `hostile_relay.rs::{bit_flipped_ciphertext,swapped_ciphertext_between_envelopes,forged_envelope_from_relay_key,bumped_counter,rewound_counter}_is_rejected` |
| A rejected envelope never poisons later state | `replay.rs::check_and_record` (record only on full pass) | `replay.rs::rejected_envelope_does_not_advance_state` |

### Implementer note (task #67): monotonic-counter gate retired

Behavior change (implementer statement, no verdict; independent reviewer owns the verdict):

- The `ReplayGuard` monotonic-counter gate was removed. The guard now applies exactly two gates in order: freshness (`|now - ts| <= REPLAY_WINDOW_MS`) then single-use request id. Signature verification still runs first in `Envelope::open`, so the guard only ever sees authentic envelopes.
- Motive: the counter was per-session and in-memory on both ends, seeded from the wall clock but reset on any daemon restart or phone session recreation (arm/foreground/reconnect). A guard that remembered a higher counter then dropped a genuine, user-approved envelope as a "counter regression" and the command hung. The counter was never load-bearing for replay: signature + 150s freshness + single-use uuidv7 are complete.
- Wire/format unchanged: the `counter` field still travels in the envelope and is still covered by the signed canonical bytes (so `bumped_counter`/`rewound_counter` tamper still yields `BadSignature`). The crypto vectors (`canonicalBytes`, `open`, `combiner`, `pairingTranscript`) are byte-identical; only the `replay` vector outcomes changed to match the two-gate logic, and Rust<->TS parity holds (phone `proto:vectors` 20/20).
- Seen-set eviction moved from count-based (`MAX_SEEN=4096` FIFO) to age-based: an `(id, ts)` is forgotten once `now - ts > REPLAY_WINDOW_MS`, because a replay of an aged-out id fails the freshness gate regardless. `MAX_SEEN` is retained only as a hard memory backstop for a same-instant burst of distinct authentic ids (a burst that already requires the sender's signing key).
- The daemon->phone and phone->daemon wall-clock counter seeds (`remote.rs`, `session.ts`) are intentionally left in place: harmless with the counter ungated, and still needed by the already-deployed phone build (whose old guard still gates the counter) until a rebuild ships.

Residuals for the security-reviewer to weigh:

- **Post-restart, within-window single replay.** A guard that just started (daemon restart, or a fresh phone `ReplayGuard`) has an empty seen-set. A relay that captured an authentic envelope can replay it once inside the freshness window (`REPLAY_WINDOW_MS`, 150s) and it will pass. This is **unchanged from the counter design** (the counter also reset to 0 on restart, so a lower-counter replay was accepted post-restart too), and is bounded by the window. It is not a new hole; the window is the bound.
- **Age-eviction soundness.** `evict_aged` only drops front entries with `now.saturating_sub(ts) > window_ms`; a still-in-window (incl. future-dated) entry stops the sweep, and an out-of-order older entry lingers harmlessly until it reaches the front or `MAX_SEEN` evicts it. Forgetting an aged-out id cannot open a replay because that id's only valid ts is now stale and fails freshness first. The reviewer should confirm the eviction predicate against a clock that can move non-monotonically within one guard's lifetime (the guard is in-memory and resets on restart, so cross-restart clock moves do not apply).
- **Downstream prose drift.** Several verdict rows below (e.g. the ToDaemon/route_response, delivery-receipt, and resolution-broadcast sections) still describe replay as caught by "the ReplayGuard monotonic counter". Those verdicts still hold, but the mechanism is now the single-use request-id gate, not the counter. The independent reviewer should re-audit and re-word those verdicts; the implementer did not edit reviewer verdict prose per the review-integrity rule.

## 6. Biometric gating is structural (invariant #5)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| A dev/in-memory keystore can never count as the biometric approving factor | `keystore.rs::Keystore::is_biometric` (default `false`), `approve.rs::LocalApprover::decide_local` (guard `is_biometric() && has_dek()`) | `keystore.rs::memory_keystore_is_not_a_biometric_factor`, `approve.rs::dev_autoapprove_grants_without_biometrics` (grant only via explicit dev switch) |
| Only the macOS Secure Enclave keystore reports biometric, and its unwrap refuses until verified on hardware | `keystore_macos.rs::MacKeystore::is_biometric` (`true`), `unwrap_dek` (`NeedsVerification`) | `keystore_macos.rs::se_paths_refuse_until_verified` |
| Deny / timeout always fails closed (never a grant) | `approve.rs::LocalApprover::decide_local` (timeout → `Deny`), `remote.rs::RemoteApprover::decide` (`unwrap_or Deny`) | `approve.rs::local_timeout_fails_closed`, `daemon.rs::denied_request_fails_closed_and_delivers_no_secret` |
| The Secure Enclave DEK unwrap fires Touch ID on real hardware | `keystore_macos.rs::unwrap_dek` | **UNPROVEN, PARTIAL**: FFI is documented but returns `NeedsVerification`; must be exercised on a Mac (see NEEDS-VERIFICATION block). Until then, the shipping local approver falls through to the control socket (see Residuals). |

## 7. Caller identity is daemon-verified (invariant #6)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| Peer pid is read from the kernel, not the client | `lease.rs::peer_pid` (`LOCAL_PEERPID`/`SO_PEERCRED`) | **UNPROVEN, PARTIAL** on hardware (`NEEDS-VERIFICATION` in `lease.rs`); logic exercised via injected pid in daemon tests |
| Ancestry is walked kernel-side; the grant key binds code identity, never pids | `lease.rs::walk_ancestry`, `grant_key` (excludes pids) | `lease.rs::ancestry_walk_is_root_first_and_stops_at_init`, `grant_key_ignores_recycled_pids`, `grant_key_changes_with_root_scope_or_ancestry` |
| The ancestry walk terminates on cycles / bounded depth | `lease.rs::walk_ancestry` (`MAX_ANCESTRY_DEPTH`, `seen` set) | `lease.rs::ancestry_walk_terminates_on_a_cycle` |
| A phone-claimed grant key is ignored; the daemon derives and trusts its own | `daemon.rs::fulfill` (uses `gk`), `request.rs::InstallLease` (echo only), `softphone/lib.rs` (empty `grant_key`) | reviewed by inspection; exercised by `daemon.rs::lease_decision_covers_the_next_identical_request` |
| The ancestor "code identity" is the platform's measurement of the image that ancestor is RUNNING | `lease.rs::{measure_running_image,CodeIdentity,SysProcessTable::resolve}`, `peercode.rs::measure_guest`, `peercode.m::sigil_guest_measure` (`SecCodeCopyGuestWithAttributes` by pid + `SecCodeCheckValidityWithErrors` + `kSecCodeInfoUnique`, all off one guest object) | `peercode.rs::{a_running_signed_binary_measures_as_itself_and_names_its_own_path,an_ad_hoc_signature_is_reported_as_having_no_signer,a_pid_that_is_not_a_live_process_measures_as_nothing}`, `lease.rs::{a_running_signed_binary_measures_as_the_platform_identity,an_ad_hoc_process_measures_under_its_own_tag,a_pid_that_names_no_process_yields_no_identity_at_all,swapping_the_file_under_a_running_process_does_not_change_what_it_measures_as,a_stamp_preserving_rewrite_is_never_served_the_old_identity}`. **Scope of the claim (implementer's statement, not a verdict):** it is a measurement, not an authentication, and it is **not tamper-evidence** and must not be described as such. It answers "what does the platform say this live pid is running", nothing more: it says nothing about what that process later loaded or, for an interpreter, what script it is running. The validity check is what makes the answer about the running image rather than about a file: a post-exec swap of the executable answers `-67034` and the ancestor drops to `Unmeasured`, keyed to its own process instance and to nothing the attacker chose (see the row below). It catches SUBSTITUTION, not page tampering: measured here, patching bytes under an intact CodeDirectory does not move the cdhash and the check still succeeds (the identity did not move; the kernel is what refuses to run a page-tampered image). Residual, unchanged and dominant: an attacker who can run code as this user spawns UNDER the honest ancestors instead, and that chain matches by construction. **Reviewer verdict (round 4, independent, 2026-08-07): R3-F1 CLOSED, and this row is PROVEN on its own terms.** Re-checked on `e895c5d`: `sigil_cdhash_for_path` no longer exists, no ancestor executable is read from disk by this crate outside test fixtures, and the path and the cdhash are taken off the one guest object the validity call vouched for (R3-F4 closed with it). The R3-F1 attack, replayed by the ported tests, now yields `Unmeasured` rather than a chosen identity, for in-place overwrite and for rename-over alike. The "not tamper-evidence" scoping above is accurate and was independently reproduced (see R4 §"page tampering, confirmed"). Read the row together with the residual in R4-F1: the chain a measured ancestor contributes is *reconstructible* by anyone who can exec the same binaries from the same paths, so this measure fences honest tool trees and nothing else. |
| Nothing about the measurement is cached | `lease.rs::{SysProcessTable,measure_running_image}` (no cache type exists) | Behavioural, by construction: the `FileStamp` cache and `measure_executable` are deleted, so every gated command re-measures every ancestor. This closes R3-F2 by removing what it exploited (every stamp field was owner-settable, so a same-length in-place rewrite plus `utimensat` was served the pre-rewrite identity for the daemon's lifetime) rather than by adding `ctime` to the stamp. Cost of having no cache, measured (release, M-series): 6.3ms for a real 6-deep chain per gated command, against 40-90ms for spawning `op --version` alone. |
| The four identity measures cannot collide in a grant key | `lease.rs::grant_key` (length-prefixed `IdentityMeasure::tag`: `cdhash`, `adhoc`, `bytes`, `none`) | `lease.rs::the_measures_are_domain_separated_in_the_grant_key` (all six pairs, same 32 bytes), `a_cdhash_measurement_is_stable_and_distinguishing` (an ad-hoc cdhash and a signed one share a digest and must not share a key), `an_unmeasured_ancestor_is_keyed_to_one_process_instance`. **Reviewer verdict (round 4): PROVEN, and the ad-hoc call is the right one.** Keeping an ad-hoc binary's guest cdhash under its own tag, rather than falling back to a hash of the file's bytes, is what stops R3-F1 being reinstated across the Homebrew/cargo/npm majority of a dev machine: a byte hash is a statement about a file, and re-opens the write-the-path attack the guest measurement exists to close. `IdentityMeasure::Content` is now unreachable in production and is correctly documented as a test/hypothetical-platform arm. |
| An ancestor the daemon could not measure is keyed to one process INSTANCE, never to code | `lease.rs::{CodeIdentity::unmeasured,ProcessStart,start_time}` (`BLAKE2b(domain ++ pid ++ start_sec ++ start_usec)`, both kernel-supplied) | `lease.rs::{an_unmeasured_ancestor_is_keyed_to_one_process_instance,swapping_the_file_under_a_running_process_does_not_change_what_it_measures_as}` (a swapped image drops to exactly this identity and to no other), `daemon.rs::an_unmeasured_ancestor_still_opens_and_rides_a_window`. **Scope of the claim (implementer's statement, not a verdict):** this branch is the weakest of the four and is accepted on product grounds. It asserts continuity of one process, not identity of code, so a window under it keeps serving while that process lives whatever it goes on to run. It is not attacker-reachable as a collision: to derive a victim's key an attacker must actually be a descendant of the victim's ancestors at that pid and that microsecond, which is the honest chain, and spawning under honest ancestors is the pre-existing dominant residual either way. The start time is what stops a recycled pid inheriting a window. R3-F5's overstatement is gone: the digest never claimed to "coalesce with nothing". **Reviewer verdict (round 4, independent, 2026-08-07): ACCEPTED as a bounded, documented weakening; no impersonation opening found.** Attacks run against it and their outcomes are listed under R3-F5 in the round-4 section: pid recycling is closed by a kernel-supplied microsecond start time neither half of which is caller-supplied; deliberately forcing an ancestor into this branch MOVES the grant key and so destroys a window rather than joining one; the digest is invariant across `exec`, which is exactly the "continuity of a process, not identity of code" the row already states, and reaching it needs code execution inside the ancestor, i.e. the pre-existing dominant residual. Worth recording alongside: this is the ONLY one of the four measures an attacker cannot reconstruct (see R4-F1), so on the reconstruction axis it is stronger than the measured branches, not weaker. |
| A caller the daemon could not put a single process behind gets no lease | `lease.rs::Caller::may_lease`, `daemon.rs::fulfill` (`may_lease` gates both `token_for` and the grant) | `lease.rs::{an_unmeasured_ancestor_is_keyed_to_one_process_instance,a_pid_that_names_no_process_yields_no_identity_at_all}`, `daemon.rs::a_caller_with_no_identity_at_all_gets_no_window`. The shape this refuses is an empty chain, where every unidentifiable caller would derive ONE grant key. Such a request is still gated, still runs, and is still shown to the human; only the auto-release is withheld. |
| An unmeasurable ancestor is never silent | `lease.rs::{note_unmeasured,unmeasured_notes,UnmeasuredNote}` (logged once per process instance, bounded registry), `daemon.rs::{unmeasured_ancestor_row,doctor_report}` | `daemon.rs::the_doctor_explains_an_unmeasurable_ancestor_and_stays_quiet_otherwise`, `lease.rs::swapping_the_file_under_a_running_process_does_not_change_what_it_measures_as` (asserts the note is recorded with its reason). Informational, not a failure row: leases still work, and the usual cause is a tool that updated itself. Contents are non-secret by construction (pid, start time, executable path, fixed reason) and never leave the machine. |

## 8. Fail closed, leases bounded (invariants #7, #8)

> Lockdown was removed entirely (`e16b0da`); this section no longer maps a
> lockdown claim. See Addendum 2026-07-15 (three-commit review) for why the
> removal weakens no default gate.

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| Every failure path denies (deny, timeout, dead phone, decrypt failure) | `daemon.rs::fulfill` (`fail_closed` on each branch), `remote.rs::round_trip` (`?`/`None` → Deny) | `daemon.rs::denied_request_fails_closed_and_delivers_no_secret`, `remote_softphone_denial_fails_closed_with_no_secret`, `approve.rs::local_timeout_fails_closed` |
| Leases are RAM-only, triple-scoped (grant key + account + scope, where scope is the matched RULE's name), plus a source-material fingerprint when they cache values | `lease.rs::LeaseStore`, `Lease`, `LeaseBinding` | `lease.rs::lease_grant_lookup_and_scope_isolation`, `a_reseal_of_the_source_misses_the_cached_lease` |
| A lease covers the whole matched rule for that caller chain (any argv, any cwd), and stops at the rule boundary | `daemon.rs::fulfill` (`lease_scope = action.rule`, `grant_key(&caller, ScopeKind::Command, "", &lease_scope)`) | `daemon.rs::a_lease_covers_any_command_the_same_rule_matches`, `a_lease_survives_a_change_of_directory`, `a_lease_on_one_rule_does_not_cover_another_rule`, `lease.rs::{one_rule_covers_any_command_it_matches,cwd_no_longer_splits_a_lease,different_rules_do_not_share_a_grant_key}` |
| A lease never crosses caller chains: a different tool tree (or a tampered ancestor) is a different grant | `lease.rs::grant_key` (chain code identity) | `lease.rs::different_caller_chains_do_not_share_a_rule_lease`. **UNPROVEN against a deliberate imitator, by construction, not by a missing test (round 4, R4-F1):** the grant key binds only each ancestor's path, measure tag and digest plus the chain length, and nothing instance-specific whenever every ancestor measures, so an attacker who can exec the same binaries from the same paths in the same nesting derives the same key without touching the victim's processes at all. `ps` discloses the tree to imitate. The claim holds for *honest* trees, which is what it is for. **Implementer's addendum (fix round, 2026-08-07):** the stronger statement is now written at every place the claim is made rather than only here: `lease.rs` module docs, `lease.rs::grant_key`'s doc comment, the test comment on `different_caller_chains_do_not_share_a_rule_lease`, and both chain paragraphs of the design brief (which also no longer says malware must be *running under* those ancestors to ride a window). No behaviour changed and no user-facing string claimed the stronger property. |
| The **lease coverage label** shown on the consent surface is rendered by the daemon from the matched rule's own match conditions, never read from disk and never supplied by a peer | `config.rs::Match::coverage` (built from `command`/`subcommand`/`flag_present`/`flag_equals`/`argv_contains`/`arg_regex` only, never from argv), `config.rs::Config::resolve` (the sole writer: `with_covers(rule.match_.coverage())` on every match) | `config.rs::{coverage_renders_each_match_shape,resolve_stamps_the_coverage_label_only_on_a_leasable_rule,a_hand_edited_covers_on_disk_is_ignored_by_resolve}`, `daemon.rs::{a_granted_lease_reports_the_same_coverage_the_approver_consented_to,a_run_once_rule_emits_no_coverage_label_anywhere}`. A hand-edited `covers` on disk does deserialize but is unconditionally replaced at resolve time, and `Config::save` never persists one. There is no inbound path at all: `ApprovalResponse`/`InstallLease` carry no such field. |
| The coverage label describes a window and can never define one: it is outside `LeaseBinding`, outside `grant_key`, and outside the lookup | `lease.rs::{Lease::covers,LeaseStore::grant,LeaseStore::token_for}` (the match compares `grant` + `binding` only; `covers` is written, never compared) | `lease.rs::coverage_is_carried_for_display_and_never_joins_the_lookup` (two labels, one window; a lookup that names no label still hits; a refresh re-stamps without forking) |
| The coverage label is as protected in transit as the rest of the request: relay-invisible, signature-covered, single-use, and absent from the push doorbell | `request.rs::LeasePolicy::Leasable::covers` (a field of the sealed `ApprovalRequest`, no new transport), `sigil-relay/src/push.rs::DOORBELL_BODY` (a fixed constant) | `sigil-proto/tests/hostile_relay.rs::the_lease_coverage_label_rides_inside_the_seal` (not on the wire, undecryptable by a stranger, `BadSignature` on ciphertext tamper, `DuplicateRequest` on replay) |
| The coverage label cannot deform the consent surface it rides on | `request.rs::sanitize_covers` (the single choke point: control characters and whitespace collapse, bounded to `COVERS_MAX_CHARS` = 72 counted in characters, single-character ellipsis), plus three independent renderer sanitisers: `apps/phone/src/lib/format.ts::coverageLabel`, `apps/mac/.../Domain.swift::Lease.coverage`, `cli.rs::lease_row` | `request.rs::covers_is_sanitized_bounded_and_never_set_on_run_once`, `config.rs::coverage_is_bounded_and_summarizes_a_busy_rule`, `apps/phone/src/lib/format.selftest.ts`. **UNPROVEN, and PARTIALLY FALSE as stated (round 4, R4-F4, demonstrated):** the choke point strips Unicode `Cc` and `White_Space` only. Bidi controls (`U+202A`-`U+202E`, `U+2066`-`U+2069`), zero-width and other `Cf` characters, and unbounded combining marks pass through it onto the phone's caption, where the label shares a paragraph with the fixed clause that states the breadth. The phone's regex does not close it either; the Swift mirror closes the `Cf` half only (`CharacterSet.controlCharacters` = Cc+Cf, verified) and the CLI re-sanitises nothing. See also R4-F5: the summary fallback can itself exceed the bound and be elided mid-clause. **Implementer's addendum (fix round, 2026-08-07, not a verdict):** the choke point is now `request.rs::sanitize_label`, an allowlist (printable ASCII, collapsed whitespace, `U+2026`; every other character becomes one `?` per run), called by `sanitize_covers` and re-run at the CLI render boundary by `cli.rs::cell` over `covers`, `scope` and `account`. `summarize` now bounds itself so the count clause survives (R4-F5). New tests: `request.rs::{covers_cannot_carry_a_character_that_reorders_or_hides_the_caption,sanitize_label_holds_its_bound_at_any_width}`, `cli.rs::a_lease_row_cannot_repaint_the_terminal_or_reorder_itself`, and the busy-rule case added to `config.rs::coverage_is_bounded_and_summarizes_a_busy_rule`. The phone and Mac mirrors are separate changes. Full record in the fix-round section at the end of this file; the UNPROVEN verdict above stands until an independent pass re-rates it. |
| A lease is **not** bound to a process, session, terminal, or user instance. The grant key excludes pids by design, so any *other* concurrently-running tree with the same ancestor executables (a second editor/agent session, another terminal, another project) shares the grant key and rides the window. Compounding it, every gated command arrives through a `~/.sigil/bin` symlink to the one `sigil` binary and macOS resolves symlinks, so the chain leaf is identical across commands: the chain discriminates tool trees, never commands | `lease.rs::grant_key` (pids excluded) | `lease.rs::grant_key_ignores_recycled_pids` (proves the property; the security consequence is reviewer finding **F2**). The load-bearing comment F2 called wrong is corrected at `daemon.rs::fulfill`, and the brief's "process tree key" phrasing with it |
| A rule's *name* is the lease's scope, and rule names are user-mutable config, so a config reload REVOKES (and zeroizes) every lease whose rule did not survive it unchanged: rule removed, rule differing in any field by whole-struct comparison, or the source it injects from differing in any field. A rule rewritten mid-window cannot inherit the window | `daemon.rs::reload_config` -> `Core::invalidate_leases_for_config_change` -> `lease.rs::LeaseStore::revoke_scope`; each revocation is logged | `daemon.rs::a_rule_rewritten_mid_window_does_not_inherit_the_lease` (the reviewer's F3 scenario: a rule renamed to match `curl` mid-window), `config_reload_invalidates_exactly_the_leases_whose_rule_moved` (removed / match changed / policy changed / source changed / no-op), `lease.rs::revoke_scope_kills_every_lease_on_one_rule` |
| What a lease holds depends on the rule. A plain gate (`op`, `env-file`, a degraded inline `env`) stores an empty presence marker and injects nothing on a leased run. A **sealed inline `env`** rule stores the values that approval unsealed, and leased runs inject them from RAM with no phone round trip: this is the one place a credential outlives a single request | `daemon.rs::fulfill` (the unseal runs BEFORE the grant, so a failed open leaves no lease; `sealed_plain` is what is stored, else `Zeroizing::new(Vec::new())`), `lease.rs::Lease::token` | `daemon.rs::a_sealed_env_lease_injects_from_ram_with_no_second_approval`, `leased_unsealed_inline_env_source_runs_as_a_plain_gate` (a plain gate still injects nothing) |
| A cached value is re-checked on every leased run and refused unless it is exactly what the rule now consents to: the blob must decode and its KEY set must equal the rule's `env_keys`. A refusal drops the lease and re-gates rather than injecting | `daemon.rs::{leased_env,env_keys_match}` (same check the fresh-approval path runs) | `daemon.rs::a_cached_lease_is_only_used_when_it_still_matches_the_rule` (accepts an exact match; refuses an extra key, a missing key, a corrupt blob, and an empty marker where values are expected), `a_sealed_env_lease_injects_from_ram_with_no_second_approval` (the accept path end to end) |
| Every window-ending path zeroizes the cached values: TTL expiry, `sigil lease revoke`, daemon restart/ctrl-c, and a config change to the covering rule. `Token` is `Zeroizing`, so every removal wipes | `lease.rs::{token_for,grant,revoke,revoke_scope,clear}` (all `retain`/drop paths), `daemon.rs::serve` (ctrl-c `clear()`) | `daemon.rs::{a_sealed_env_lease_stops_injecting_when_it_expires,revoke_and_restart_both_end_a_sealed_env_window,a_run_once_sealed_env_rule_caches_nothing}`, `lease.rs::an_expired_cached_lease_stops_serving_its_values` |
| A re-seal of the source (new `E`) misses the cached lease, so a stale plaintext is never injected after `source env set` | `daemon.rs::fulfill` (`LeaseBinding::cached(.., record.ephemeral_pub)`) | `lease.rs::a_reseal_of_the_source_misses_the_cached_lease` |
| The `account` leg of the triple binding is live for a cached (sealed `env`) lease, where it carries the source name, and still empty for a plain gate, which has no account to bind. It cannot bind falsely: grant and lookup derive the label identically from one pinned `config.snapshot()` | `daemon.rs::fulfill` (`account_label` = `action.source_name` for a sealed env rule) | `lease.rs::lease_grant_lookup_and_scope_isolation` (a wrong account misses); the plain-gate case remains a constant, so reviewer finding **F5** is only partly closed |
| Approval coalescing stays narrower than the lease (chain + cwd + argv), so one readout never settles a different command | `daemon.rs::fulfill` (`coalesce_key`, passed to `gate.decide`) | **UNPROVEN** by a dedicated test; the key derivation is byte-identical to the pre-rule-lease `gk` covered by `approve.rs` coalescing tests |
| Command scopes and SSH scopes are domain-separated in the key, so no rule name can collide with an SSH sign scope | `lease.rs::{ScopeKind,grant_key}` (kind tag length-prefixed into the hash) | `lease.rs::request_kinds_live_in_separate_scope_namespaces` (closes reviewer finding **F4**) |
| A lease-covered run is audited with the command it actually ran, not the rule | `daemon.rs::fulfill` (lease short-circuit logs `audit_label(describe(argv), scope)`, `via = "lease"`) | `daemon.rs::a_leased_run_audits_the_command_it_actually_ran` |
| Leases expire on TTL and are purged (and zeroized) | `lease.rs::token_for`/`grant` (`retain(expires>now)`; token is `Zeroizing`) | `lease.rs::lease_expires_and_is_purged` |
| `LeaseStore::clear()` drops and zeroizes every lease (the ctrl-c/restart path) | `lease.rs::LeaseStore::clear` | `lease.rs::clear_zeroizes_all_leases` |
| Daemon restart / ctrl-c zeroizes leases | `daemon.rs::serve` (`core.leases.clear()` on ctrl-c) + RAM-only storage | **UNPROVEN** by test (process-exit path); RAM-only + `clear()` reviewed by inspection |
| A revoke drops matching leases | `lease.rs::LeaseStore::revoke` | `lease.rs::revoke_by_grant_prefix` |
| A **run-once** rule never leases, even if the approver returns a lease | `daemon.rs::fulfill` (`action.lease.clamp_secs(...)` gates both grant sites; `LeasePolicy::RunOnce.clamp_secs` → `None`), `request.rs::LeasePolicy` | `daemon.rs::run_once_rule_never_leases_even_when_a_lease_is_returned`, `request.rs::lease_policy_defaults_to_run_once_and_clamps` |
| A **leasable** rule clamps any lease to the per-rule cap (no over-lease) | `daemon.rs::fulfill` (`clamp_secs` = `min(requested, cap)`) | `daemon.rs::leasable_rule_clamps_an_over_cap_lease_to_the_rule_max`, `request.rs::lease_policy_defaults_to_run_once_and_clamps` |
| The lease policy the approver consents to rides inside the sealed/signed envelope | `request.rs::ApprovalRequest.lease_policy` (default `RunOnce` on absence), carried by `remote.rs::build_request` | `request.rs::request_serializes_camel_case_and_stays_provider_agnostic` (asserts `leasePolicy`), `remote.rs::build_request_is_provider_blind` |
| An **allow** (passthrough) rule is a deliberate, user-authored ungating scoped strictly to its match | `config.rs::RuleMode::Allow`, `Config::resolve` (returns `Resolution::Allow` only on a matching allow rule), `add_rule` (rejects an empty match in both modes, and an allow rule that names a source or is leasable) | `config.rs::allow_rule_resolves_to_passthrough_and_layers_above_a_gate`, `add_rule_rejects_an_allow_with_a_source_or_lease_and_a_gate_without` |
| An allow rule bypasses the gate for its match ONLY; an unmatched command still refuses (fails closed) | `daemon.rs::fulfill` (`Resolution::Allow` -> `provider::run_passthrough`, no approval/injection/lease; `None` -> `fail_closed`), first-match-in-order is the only precedence | `daemon.rs::allow_rule_runs_the_command_directly_without_gating`, `config.rs::allow_rule_resolves_to_passthrough_and_layers_above_a_gate` (unmatched still `None`) |
| Mode defaults to gate: a config missing/dropping `mode` gates, never allows | `config.rs::RuleMode` (`#[default] Gate`, `#[serde(default)]`) | `config.rs::action_defaults_to_run_once_when_lease_field_absent` (same absent-field config resolves as a gate) |

## 9. The relay is powerless (invariant #3)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| The relay never sees plaintext (opaque envelopes only) | `envelope.rs::Envelope`, `transport.rs` (carries opaque envelopes); the real network transport carries the same opaque `serde_json` envelope string (`relay-client/src/lib.rs::wire`, daemon-side WS `DaemonRelay`, phone-side HTTPS `PhoneRelay`) | `hostile_relay.rs::relay_cannot_read_the_payload`; end to end over the **real** Bun relay by `daemon.rs::remote_approval_over_the_real_relay_delivers_the_secret` |
| The relay cannot forge, tamper, replay, reorder, backdate, or drop-to-effect | `envelope.rs::open`, `replay.rs` (unchanged whichever transport carries the bytes) | the full `hostile_relay.rs` suite (14 attacks) |
| The mailbox id carries no identity and is order-independent | `fingerprint.rs::mailbox_id` | `fingerprint.rs::mailbox_is_order_independent`, `mailbox_differs_for_different_pairs`, `fingerprint_and_mailbox_are_domain_separated` |
| The relay has no key-distribution role (pairing is out-of-band QR) | `pairing.rs` (keys travel optically) | design invariant; the whole `pairing_mitm.rs` suite proves trust does not rest on any network party |

## 10. Pairing persistence stays inert at rest (the `sigil pair` at-rest format)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| The persisted set is `{daemon private identity → keystore, phone PUBLIC identity, relay URL, SAS words}`; no DEK, no DEK envelope, no pairing secret is ever persisted | `pairing_store.rs::{save,PersistedPairing,NewPairing}` | `pairing_store.rs::config_file_is_0600_and_holds_no_dek` (asserts no `dek`/`secret`/`signing` substring), `daemon.rs::persisted_pairing_reloads_and_stays_inert_at_rest` (`has_dek()==false`) |
| The daemon private identity is sealed into the keystore blob seam (Keychain on macOS), never the plaintext file | `pairing_store.rs::save` (`store_blob(DAEMON_IDENTITY_LABEL, …)`), `keystore_macos.rs::MacKeystore::store_blob` | `pairing_store.rs::save_then_load_reconstructs_the_config_and_pins_the_phone` |
| The 64-byte identity serialization is `Zeroizing`, length-checked, and fails closed on a corrupt/truncated blob (no partial key) | `identity.rs::DeviceIdentity::{to_secret_bytes,from_secret_bytes}` (intermediates zeroized) | `identity.rs::secret_bytes_round_trip_preserves_the_public_identity`, `from_secret_bytes_rejects_a_wrong_length_blob` |
| The public config file is 0600 and holds no key material | `pairing_store.rs::save` (`set_permissions 0o600`) | `pairing_store.rs::config_file_is_0600_and_holds_no_dek` |
| An attacker with the whole disk cannot produce a secret: tokens are ciphertext under the DEK the daemon does not hold; the stolen state can only *ask* the phone, which requires a fresh hardware-gated approval | `pairing_store.rs` (no DEK persisted), `daemon.rs::fulfill` (DEK arrives per-approval), `remote.rs` | `daemon.rs::reloaded_pairing_serves_a_secret_over_the_real_relay` (reloaded identity serves a secret ONLY via the phone's sealed DEK, `has_dek()==false`) |
| A half-broken pairing (config present, keystore identity gone) surfaces loudly instead of silently failing | `pairing_store.rs::load` (`MissingIdentity`/`CorruptIdentity`), `daemon.rs::load_remote_pairing` (logs, treats as no-pairing → fails closed) | `pairing_store.rs::config_present_but_identity_missing_is_a_loud_error` |
| The bootstrap **rendezvous mailbox** is domain-separated and non-invertible: leaking it reveals nothing about the secret | `pairing.rs::rendezvous_mailbox` (`BLAKE2b(RENDEZVOUS_DOMAIN ‖ daemon.verifying ‖ daemon.agreement ‖ secret)`, distinct from `mailbox_id`/`fingerprint`/confirm-tag domains; secret is 256-bit CSPRNG so preimage-resistant) | reviewed by inspection (domain constants distinct; length-prefixed absorb is injective); **UNPROVEN** by a dedicated test, no negative test asserts domain separation of the rendezvous id |
| Pairing message 1 (`PairingResponse`) travels the relay as MAC-authenticated plaintext carrying only public data (phone pubkey, nonce, tag); substitution is rejected | `pairing.rs::PairingResponse::verify`, `relay-client/src/rendezvous_ws.rs` (moves opaque strings only, no envelope/key handling) | the full `pairing_mitm.rs` suite (message 1 is exactly what it attacks) |
| Persisting a pairing auto-selects the phone factor with no dev flag | `daemon.rs::{load_remote_pairing,build_gate}` (`Factor::Phone`) | `daemon.rs::build_gate_selects_the_phone_approver_from_a_persisted_config` |

### 10a. The keystore file: default store and Secure-Enclave wrapping (2026-08-04)

Behavior, not verdicts. **Independently reviewed 2026-08-04** (see the round-2
verdict at the end of this document). The two rows the reviewer found overstated
have since been corrected rather than argued: the `Zeroizing` claim now says
exactly which buffers are covered and names the serde/base64 products as a
residual (**R2-F2**), and the unrecognized-`SIGIL_KEYSTORE` case is no longer
documented, or implemented, as a silent feature (**R2-F3**). The other findings
in that round are addressed in the rows below and dated the same day.

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| The default store is the portable 0600 file on EVERY platform, resolvable with no environment at all, so the daemon and a CLI in a plain shell can never disagree about where the pairing lives | `keystore.rs::for_host` | `keystore.rs::the_default_store_is_the_on_disk_file_with_no_environment_at_all`, `file_is_the_default_for_an_empty_or_unrecognized_value` |
| An install under the older `dev-keystore.json` name is migrated in place (atomic rename, never overwriting an existing canonical file); the pairing survives with no re-pair | `keystore.rs::migrate_legacy_file_keystore` | `keystore.rs::{a_pre_default_dev_keystore_is_migrated_in_place,migration_never_overwrites_an_existing_canonical_store}` |
| The pairing-authorization presence gate survived the storage change: it now asks the HOST (`LAContext`, which never needed the keychain) when the store cannot prove presence itself | `keystore.rs::{presence_plan,verify_host_presence}`, `pairing_store.rs::gate_presence` | `keystore.rs::presence_is_asked_of_the_host_when_the_store_cannot_prove_it` |
| A wrapped (v2) keystore is classified ONCE at startup, before the control socket listens, and never re-read; a file swapped under a running daemon cannot become authoritative | `daemon.rs::read_seal_state`, `Core::seal` | reviewed by inspection (single call site in `Core::for_host`); the classification itself by `keystore_seal.rs` parse tests |
| A sealed-but-unprovisioned daemon serves NOTHING (no gated command, no SSH signature) and explains itself without ever implying a lost pairing | `daemon.rs::fulfill` (top-of-function guard), `SshBackend::approve_and_sign`, `keystore_seal.rs::SealState::explain` | `daemon.rs::a_sealed_unprovisioned_daemon_serves_nothing_and_says_why` (asserts the text contains "keystore sealed" and does NOT contain "no pairing" or a re-pair instruction), `a_provisioned_seal_serves_normally_and_a_downgrade_never_does` |
| Plaintext where wrapped was promised (including a VANISHED file) is a downgrade and refuses to serve | `keystore_seal.rs::SealState::resolve`, adoption marker | `keystore_seal.rs::seal_state_reads_the_file_and_the_marker_together`, `only_a_provisioned_seal_serves_and_a_downgrade_never_does` |
| A v2 file wrapped to a DIFFERENT Enclave key than this machine adopted resolves `KeyChanged` and serves nothing: the marker's recorded `se_pub` is compared against the file's, so a substituted-but-well-formed keystore cannot present as the real one (R2-F1) | `keystore_seal.rs::{AdoptionMarker,read_adoption_marker,SealState::resolve}`, `daemon.rs::read_seal_state` | `keystore_seal.rs::a_keystore_wrapped_to_another_enclave_key_is_refused` (also asserts an unparseable marker records an empty key, which matches nothing, so corrupting it does not clear the tripwire) |
| Only the signed Sigil app may provision, subscribe, or report an unwrap: the peer's code identity is verified live against Apple's anchor plus the RainnWorks team OU, not asserted | `peercode.rs` (+ `peercode.m`, Security.framework), `daemon.rs::{handle_provision,stream_keystore,handle_unwrap_done}` | `peercode.rs::{this_unsigned_test_binary_is_not_the_sigil_app,a_requirement_this_process_does_satisfy_passes,a_malformed_requirement_refuses_rather_than_passing,a_dead_pid_is_refused}`, `daemon.rs::{provisioning_is_refused_for_anyone_who_is_not_the_signed_app,the_keystore_streams_and_unwrap_reports_are_app_only}` |
| Provisioned material must match what the file commits to (constant-time digest compare); the reply never echoes the expected digest | `daemon.rs::handle_provision`, `keystore_seal.rs::{digest,digests_equal}` | `keystore_seal.rs::the_digest_is_domain_separated_and_length_prefixed`, `daemon.rs::a_wrong_digest_provision_is_refused_and_does_not_latch` |
| Provision is once per lifetime, but a REFUSED attempt does not latch (else one bad frame is a denial of service cheaper than the attack the limit prevents) | `daemon.rs::handle_provision` (`provisioned` set only on success) | `daemon.rs::a_wrong_digest_provision_is_refused_and_does_not_latch` |
| Material never rides inside a JSON frame: it is raw bytes after the header, read into a `Zeroizing` buffer, and no `Frame` variant carries it | `local.rs::{recv_frame_with_tail,read_payload}`, `Frame::{KeystoreProvision,SealThreshold}` (lengths only) | reviewed by inspection (no material-typed field exists to serialize); the receive path by `daemon.rs::provisioning_is_refused_for_anyone_who_is_not_the_signed_app` (payload round trip) |
| The payload buffer is pre-sized to the full declared length before any bytes are copied in, so no realloc abandons an un-wiped copy of the material (R2-F2a) | `local.rs::read_payload` (`Vec::with_capacity(len)`, then extend, then `drop(tail)`) | reviewed by inspection; the growth path no longer exists |
| **Scope of zeroization, stated exactly (R2-F2b/c):** the TRANSPORT buffers are `Zeroizing`, and `KeystoreFile::parse` classifies via an `IgnoredAny` shape so a v1 file's blobs are never materialized as `String`s. `RamKeystore::from_material` still receives base64 through serde `String`s (it wipes them after decoding, but serde allocated them first), and `FileKeystore::read` shares that pattern on every load. So: transport buffers zeroized, decoded secrets zeroized, **serde/base64 parse products are a known residual**, inside the same-UID RAM reading this design already concedes | `local.rs` (buffers), `keystore_seal.rs::KeystoreFile::parse` (`IgnoredAny`), `keystore.rs::RamKeystore::from_material` (decode into `Zeroizing`, wipe the base64) | stated, not claimed clean |
| While wrapped, NOTHING writes the keystore: the opened store refuses every mutation, and every pairing mutation refuses upfront, before any file is touched | `keystore.rs::RamKeystore::{store_blob,delete_blob}`, `pairing_store.rs::refuse_if_sealed` (first statement of `save`/`add_device`/`remove_device`/`remove`) | `daemon.rs::opened_material_becomes_the_live_read_only_keystore`, `pairing_store.rs::every_pairing_mutation_refuses_a_sealed_store_before_touching_a_file` (asserts `pairing.json` is byte-identical after four refused mutations) |
| The commit flow for daemon-side mutations is DEFERRED, not forgotten: it has no trigger, because the daemon never writes the keystore and the CLI paths refuse upfront | `daemon.rs::stream_keystore` (documented), `PROTOCOL.md` | n/a: the claim is that no such path exists. Verified by inspection of every `store_blob`/`delete_blob` call site (all in `pairing_store`, all CLI-driven) |
| De-adoption clears the adoption marker only on the app's reported success, and an invented or replayed nonce is refused | `daemon.rs::{handle_unwrap_request,handle_unwrap_done}`, `UnwrapRequests::resolve` | `daemon.rs::{an_unwrap_answer_must_quote_an_outstanding_nonce,an_unwrap_request_against_a_plain_store_is_a_no_op}` |
| The honest delta is at-rest exfiltration ONLY: offline copies (backup, snapshot, stolen disk) stop being useful; a live same-UID attacker is unchanged, and the daemon is unsigned by design | `keystore_seal.rs` module docs, `cli.rs::cmd_keystore` wording | stated, not testable; the wording is asserted by `keystore_seal.rs::the_sealed_explanation_never_tells_anyone_to_re_pair` |

**Residuals, stated rather than closed.** The adoption marker is a same-UID file,
so an attacker who can swap the keystore can also delete the marker; it stops
accidents and unsigned opportunists, not a determined local attacker (the app's
enclave key still existing is the independent alarm). A file-WRITE attacker can
still substitute a wholesale new keystore, exactly as under plaintext: what v2
removes is file-READ exfiltration. The digest does not bind the pairing
container's device-id set, so a file-write adversary could pair material with an
older `pairing.json`; that is the same adversary and a recorded follow-up. The
code-identity check names a process instance exactly (it binds the peer's audit
token, not its pid), but cannot speak to a signed app that has been debugged or
injected into at runtime. The requirement admits any binary this team signs,
Apple Development certificates included, so a dev-signed build satisfies it; the
trigger to narrow it (a bundle-identifier allowlist plus the Developer ID marker
OID `certificate leaf[field.1.2.840.113635.100.6.1.13]`) is a second signed Mac
product existing, which is not the case today (R2-F5).

## 11. The provider seam (any-CLI generalization, `ee49ee3`)

The daemon core became provider-agnostic: a command's config names a provider,
and the daemon dispatches the gated run to it. Two injection shapes ship, and
the security boundary between them is stated honestly, not blurred.

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| An **unconfigured** command is refused, never run ungated; the caller gets the exact `sigil config add` hint | `daemon.rs::fulfill` (`commands.resolve` → `None` → `fail_closed`), `command.rs::CommandStore::resolve` (only `op` resolves by default) | `daemon.rs::unconfigured_command_is_refused_with_a_config_hint`, `command.rs::an_unconfigured_command_does_not_resolve` |
| A config entry naming an **unknown provider** fails closed, never runs | `daemon.rs::fulfill` (`providers.get` → `None` → `fail_closed`) | reviewed by inspection (the `unknown provider` branch); exercised structurally by `provider.rs::registry_dispatches_by_id_and_lists_defaults` |
| The env-file **source path comes only from the CLI-side config (0600), never from the caller's argv**, so a caller cannot redirect env-file at an arbitrary file (`/etc/shadow`, a co-worker's `.env`) | `daemon.rs::fulfill` (`source = cfg.source`, argv is never consulted for the source), `command.rs` (config is a CLI-only mutation surface) | reviewed by inspection; the config-store add/get/remove path is `command.rs::add_get_remove_round_trip_and_reject_duplicates` |
| A command that **shadows a reserved verb** fails toward the built-in verb (safe), never toward ungated execution; the escape hatch is `sigil run -- <cmd>` | `cli.rs::main` dispatch + `is_reserved_verb`, `shim.rs::dispatch` (the daemon's `fulfill` is the sole injection chokepoint) | `cli.rs::reserved_verbs_take_precedence_over_command_dispatch` |
| Argv is passed to the child as **separate argv entries, never a shell string** (no shell-injection surface); the real binary is resolved via PATH skipping the shim | `provider.rs::{OpProvider,EnvFileProvider}::run` (`Command::new(real).args(...)`), `paths::{find_real,find_real_op}` | `daemon.rs::env_file_command_runs_gated_and_injects_env`, `provider.rs::run_streams_op_child_output_to_the_caller_fd` |
| A **down daemon** makes the shim exec the bare tool with **no injected secret** (fail-safe: nothing is released); a protocol error while the daemon is **up** fails closed (exit 70), never runs ungated | `shim.rs::dispatch` (`Ok`→exit code; `forward` error→exit 70; only a *down* socket → `exec_real`), `shim.rs::exec_real` (no env injected) | reviewed by inspection (the module contract; no negative test asserts the exec fallback injects nothing), **UNPROVEN** by a dedicated test |

## 12. The `env-file` direct-injection provider (invariant #2, honestly relaxed)

`env-file` is the reference provider that proves the seam is not op-shaped. It is
the **one** path where resolved secret VALUES (not a credential) transit daemon
RAM, and the doc is explicit about the exact residual that buys.

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| `describe()` names the source **without reading it**, so no secret value enters daemon memory before the decision | `provider.rs::EnvFileProvider::describe` (uses `Path::file_name` only, never `read`) | reviewed by inspection; `provider.rs::env_file_parses_pairs_and_strips_quotes_and_comments` covers the parser that runs only at `run()` time |
| The file is read into a `Zeroizing` buffer and every value lands in a `Zeroizing` string; both are wiped when the map drops at end of `run()` | `provider.rs::{EnvFileProvider::run,parse_env_file}` (`Zeroizing::new(bytes)`, `Zeroizing<Vec<(String, Zeroizing<String>)>>`) | `provider.rs::env_file_provider_injects_the_vars_into_the_child` (values reach the child), parser by `env_file_parses_pairs_and_strips_quotes_and_comments` |
| **Leasing is disabled for env-file**: a lease would hold resolved values in RAM across a TTL, so a direct-injection provider is gated on **every** run, even when the decision grants a session lease | `daemon.rs::fulfill` (the lease short-circuit and the `grant` are both inside `if needs_account` / `if let Some(ciphertext)`, and `EnvFileProvider::needs_account()==false`) | `daemon.rs::env_file_lease_decision_grants_no_lease` (Lease decision → runs once, `leases.active()==0`), `env_file_command_runs_gated_and_injects_env` (`active()==0`) |
| `needs_account()==false` correctly gates that env-file **never** routes an account, unwraps the DEK, or touches leasing | `provider.rs::EnvFileProvider::needs_account`, `daemon.rs::fulfill` (all account/DEK/lease work guarded by `needs_account`) | `provider.rs::op_provider_needs_an_account_and_env_file_does_not`, `daemon.rs::env_file_command_runs_gated_and_injects_env` |
| No value is ever logged: every env-file error line names the **path / io error only** | `provider.rs::EnvFileProvider::run` (all `eprintln!` carry `run.source` or `command[0]`, never a value) | reviewed by inspection (no negative-logging assertion), **UNPROVEN** by test |
| The parser cannot panic on hostile input, and an **invalid-UTF-8** file fails closed with no owned/un-zeroized `String` allocated (borrows with `str::from_utf8`, returns `None`; `split_once` guard; `len() >= 2` quote guard) | `provider.rs::{parse_env_file,EnvFileProvider::run}` | `provider.rs::{env_file_parses_pairs_and_strips_quotes_and_comments,env_file_with_invalid_utf8_is_rejected,env_file_run_fails_closed_on_invalid_utf8}` |

See **residual 9** for the two un-wiped copies this shape unavoidably leaves (the
`Command` env map and the child's `/proc/<pid>/environ`).

## 13. The pluggable SSH signer (invariant #5, per-signature custody)

The daemon holds `Vec<Box<dyn SshSigner>>`; after the phone gate it routes the
signature to the signer that owns the key. Two signers ship (`OpSshSigner`,
`FileSshSigner`); the gate is applied by the Core **before** `sign()` is called.

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| **No signer can sign without the gate having passed**: `Core::approve_and_sign` runs `gate.decide` and returns `None` on any non-grant *before* calling `signer.sign` | `daemon.rs::Core::approve_and_sign` (`if !outcome.decision.is_grant() { return None }` precedes the `signer.sign` call); the `ssh_signers` field is private, so `sign()` has no other daemon caller | `daemon.rs::ssh_file_signer_denied_gate_yields_no_signature` (denied gate → `None`, signer never reached), `sshagent.rs::a_denied_sign_request_yields_failure_and_no_signature` |
| The **data-to-sign hash is bound into the approval**: the scope folds in `sha256(data)`, so the gate's grant-key coalescing can never let one challenge ride another's approval; only a byte-identical re-sign coalesces | `daemon.rs::{ssh_sign_scope,approve_and_sign}` (`scope = "ssh-sign {label} {sha256(data)}"`, `gk = grant_key(caller,"",scope)`) | `daemon.rs::different_ssh_challenges_do_not_share_a_grant_key` |
| The human approves the **hash of exactly the bytes signed**: the phone shows `sha256(data)`; the signer signs the same `data` verbatim | `sshagent.rs::sign` (`data` passed through), `daemon.rs::approve_and_sign` (`fingerprint = sha256_fingerprint(req.data)`, `signer.sign(req.id, req.data, ...)`) | `sshagent.rs::sign_request_produces_a_signature_that_verifies`, `fetch_and_sign_reads_the_key_and_signs_a_verifiable_signature` |
| **Every SSH signature is gated** (no lease short-circuit in v1): the sign path never consults `leases` | `daemon.rs::approve_and_sign` (no `token_for`/`grant` call anywhere in the path) | reviewed by inspection; contrasted with the leased op path in `fulfill` |
| A **wrong / missing / non-ed25519 / passphrase-encrypted key fails closed** to no signature (both signers) | `sshagent.rs::{FileSshSigner::sign` (`find(...)?`, `fs::read(...).ok()?`), `OpSshSigner::sign` (`credential?`), `sign_openssh_ed25519` (ed25519-only, `from_openssh(...).ok()?`)}` | `sshagent.rs::{fetch_and_sign_fails_closed_when_the_token_is_wrong,op_signer_fetches_and_signs_and_requires_a_credential (no-credential branch),sign_request_for_an_unknown_key_is_refused}` |
| Both signers hold key material in a `Zeroizing` buffer for the **one** signature and wipe it; the key never reaches the SSH client | `sshagent.rs::{op_read_openssh_key` (stdout→`Zeroizing`, stderr `null`), `FileSshSigner::sign` (`Zeroizing::new(fs::read)`), `sign_openssh_ed25519` (`ssh_key::PrivateKey` zeroizes on drop)}` | `sshagent.rs::{fetch_and_sign_reads_the_key_and_signs_a_verifiable_signature,file_signer_signs_from_a_local_key_and_needs_no_account}`, `daemon.rs::ssh_file_signer_signs_when_gated` |
| The `OpSshSigner` **whole-key-in-RAM-for-one-signature** residual is unchanged but isolated to that signer; `FileSshSigner` matches the same custody discipline | `sshagent.rs` module docs §"Custody (v1)", `OpSshSigner::sign` → `fetch_and_sign` | design residual (see `docs/design/ssh-agent.md` §4); exercised by the fetch/file sign tests above |
| The `session-bind` host is **advisory context, attacker-nameable, never a boundary**; the load-bearing fields are the key label + data hash | `sshagent.rs::derive_host` (doc + honest fingerprint fallback; the host signature is not verified) | `sshagent.rs::{unknown_host_key_falls_back_to_a_fingerprint_not_a_fake_name,no_session_bind_yields_an_honest_unbound_marker}` |
| The `ssh-keys.json` store holds **only public material + op coordinates**, never key bytes (inert like the account catalogue), and is 0600 | `sshagent.rs::{SshKeyEntry,SshFileEntry,SshKeyConfig::save}` (0700 dir / 0600 file) | `sshagent.rs::config_entry_resolves_to_a_served_identity` (only public fields), reviewed by inspection for perms |

**Key-file-swap residual (Low, same-UID):** `FileSshSigner` advertises the
public key resolved from `<path>.pub` at arm time but reads the private key at
sign time, and does not re-verify that the produced signature matches the
advertised public key. A same-UID attacker who swaps the private-key file
between arm and sign makes the agent emit a signature under a *different* key,
which the SSH client then rejects (it does not match the offered identity), so
this breaks the connection rather than forging anything. A same-UID file swap is
already outside Sigil's boundary. Not a distinct escalation; noted for
completeness.

## 14. The P-256 Secure Enclave DEK wrap (`747b3a4`)

The Mac local-approval factor unwraps the DEK *inside* the Secure Enclave under
Touch ID, and the SE holds only P-256 keys, so the Mac-SE wrap is a second,
independent envelope of the same DEK (the phone path is unchanged X25519). It
reproduces Apple's `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM`
so `SecKeyCreateDecryptedData` opens it.

**Independent review verdict, CONFIRMED SOUND.** This verdict is written by the
security-reviewer, which did **not** author `se_ecies.rs` (implemented by
rust-core in `747b3a4`); per the review-integrity rule the implementer documents
behavior and residuals, and only the independent reviewer records a "reviewed"
verdict, this is not a self-certification. The adversarial pass covered the
construction against Apple's spec (the AES-128-not-256 and VariableIV gotchas),
on-curve point validation of both the recipient and ephemeral keys, per-wrap
IV/key freshness (no GCM nonce reuse), zeroization of every secret intermediate,
the SAS-Confirmed gate, and the AAD / envelope-binding question (see residual
12); no correctness issue was found and no code change to the construction was
needed. The only outstanding item is on-device interop
(`SecKeyCreateDecryptedData` opening a `wrap_dek_p256` blob), which is
**NEEDS-VERIFICATION** off-hardware and marked in the table below.

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| The construction matches Apple's ECIES exactly: ephemeral P-256 → cofactor ECDH (P-256 h=1) → ANSI-X9.63 KDF-SHA256 with sharedInfo = ephemeral X9.63 pubkey → **AES-128** key ‖ 16-byte **variable IV** → AES-128-GCM, empty AAD, 16-byte tag; wire `eph_pub(65) ‖ ct(32) ‖ tag(16) = 113` | `se_ecies.rs::{wrap_dek_p256,x963_kdf_sha256,split_key_iv,Aes128GcmVarIv}` | `se_ecies.rs::{wrap_unwrap_round_trips_the_dek,sealed_blob_has_the_apple_wire_length,x963_kdf_matches_a_known_answer}`; on-device interop is **UNPROVEN, NEEDS-VERIFICATION** (`apps/mac/Tools/se-selftest.swift`, blob must read 113) |
| The recipient and ephemeral public keys are **validated as on-curve X9.63 points** (identity/garbage refused); P-256 is prime-order so no small-subgroup surface | `se_ecies.rs::{wrap_dek_p256,unwrap_dek_p256}` (`PublicKey::from_sec1_bytes`) | `se_ecies.rs::{a_non_point_recipient_key_is_refused,a_tampered_ephemeral_key_is_rejected}` |
| Every wrap uses a **fresh ephemeral key** → fresh shared secret → fresh AES key **and** IV, so there is never a `(key, IV)` reuse across wraps (the GCM catastrophe) | `se_ecies.rs::wrap_dek_p256` (`EphemeralSecret::random` per call) | `se_ecies.rs::each_wrap_uses_a_fresh_ephemeral_key` |
| A wrong SE key or any tampered byte fails closed (GCM auth); no DEK leaks; a truncated blob is refused before any crypto | `se_ecies.rs::unwrap_dek_p256` | `se_ecies.rs::{wrong_se_key_cannot_unwrap,a_tampered_ciphertext_is_rejected,a_truncated_blob_is_rejected}` |
| Key material is zeroized: ephemeral secret (`EphemeralSecret` ZeroizeOnDrop), shared secret (`SharedSecret` zeroizes), KDF output + AES key + recovered DEK intermediate all `Zeroizing` | `se_ecies.rs::{x963_kdf_sha256,split_key_iv,unwrap_dek_p256}` | reviewed by inspection (the `Zeroizing` wrappers); `unwrap_dek_p256`'s recovered-key copy was wrapped in `Zeroizing` in this review |
| The wrap is gated on **SAS confirmation** (`Confirmed`/`DekDelivered`), same as the phone DEK delivery; it does not change pairing state | `pairing.rs::DaemonPairing::wrap_dek_for_se_p256` (state guard) | `pairing.rs` SE-wrap round-trip test (line ~1028) |
| **Empty AAD is correct, not a gap**: `SecKeyCreateDecryptedData` for this ECIES algorithm accepts no AAD, so AAD is fixed-empty on both sides; identity binding via AAD is impossible and unnecessary here (confidentiality = ECDH-to-SE-key, integrity = GCM tag, DEK↔token binding = the account store's own AES-256-GCM). Cross-device/cross-pairing replay fails closed | `se_ecies.rs` module docs §"Binding and sender authentication", `keystore_macos.rs`, `apps/mac/.../SecureEnclaveApprover.swift` (SE decrypt) | design analysis (see residual 12) |

**Wiring status:** `wrap_dek_for_se_p256` is built and unit-tested but **not yet
called by the shipping daemon/CLI**; the Mac `approve(wrappedDEK:)` path exists
and `AppModel` currently passes an empty placeholder. The at-rest storage and
delivery of the wrapped blob are the remaining integration, at which point
residual 12's local-only assumption must be re-checked.

## 15. The config rule engine + account routing (`b66404c`)

The per-command `CommandStore` became a generic if-this-then-that engine: an
ordered rule list (`Match` -> `Action`) plus named `Source`s. `parse_vault`
argv-sniffing is deleted; account routing is now the matched source's configured
`account` label, and `AccountStore::route` / `ThresholdAccountStore::{route,
route_exact}` match by **label OR vault**.

**Independent review verdict, CONFIRMED SOUND (two low-severity hardening
notes).** Written by the security-reviewer, which did **not** author `config.rs`
or the `fulfill` rewrite (rust-core, `b66404c`); per the review-integrity rule
this is not a self-certification. The adversarial pass covered: whether a crafted
argv/rule can route to the wrong account or the wrong threshold key; whether
removing the `op` hardwiring opens a fail-open path; and whether the deferred
`arg_regex` can be smuggled into an always-true match.

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| Account routing is **config-derived, never caller-argv-derived**: the hint is the matched source's `account` label; the caller's argv no longer influences which account unlocks (it only selects which of Tom's own rules matches, and every match still requires a fresh approval/lease). This is *stronger* than the old `--vault` sniff | `daemon.rs::fulfill` (`vault = action.account.clone()`; `parse_vault` deleted), `config.rs::Config::resolve` | `daemon.rs::v1_and_v2_accounts_coexist_and_each_takes_its_own_path`, `config::tests::resolve_first_match_wins_and_flattens_source` |
| The v2 threshold path selects **one** account atomically (`record.clone()`): the phone's partial `Z_F` is agreed against that record's `E` and combined with the SAME account's Mac share `m` and token ciphertext, no cross-account share splicing is reachable via label/vault confusion | `daemon.rs::fulfill` (`v2 = store.route_exact(...).map(\|a\| (label, a.record.clone()))`), `threshold.rs::route_exact` | `daemon.rs::remote_v2_threshold_approval_decrypts_via_two_party_combine`, `threshold::tests::each_account_gets_a_unique_ephemeral_and_routes`, `full_two_of_two_round_trip_{raw_x,x963}` |
| `route_exact` stays **exact** when v1 accounts coexist (v2 claims only a label/vault match, never the single-account fallback), so a migration store never lets v2 over-capture a v1 request | `daemon.rs::fulfill` (`route_exact(...).or_else(\|\| if v1_empty { route(...) } else { None })`) | `daemon.rs::v1_and_v2_accounts_coexist_and_each_takes_its_own_path` |
| An invocation that **no rule matches** is refused, never run ungated; removing `default_op`/`parse_vault` leaves **no** built-in rule for any command (a zero-config daemon refuses everything until configured) | `config.rs::Config::resolve` (`None`), `daemon.rs::fulfill` (`fail_closed`) | `daemon.rs::unconfigured_command_is_refused_with_a_config_hint`, `config::tests::empty_match_never_matches` |
| An **empty match** never matches (a malformed/partial rule fails closed, never gates every command) | `config.rs::Match::matches` (`is_empty() -> false`) | `config::tests::empty_match_never_matches`, `add_rule_rejects_unknown_source_and_empty_match` |
| The deferred **`arg_regex` cannot be smuggled into an always-true match**: `Match::matches` returns `false` whenever `arg_regex.is_some()`, independent of how the config was authored, so even a hand-edited/imported regex rule is a dead rule (fails closed), only ever *more* restrictive, never always-true | `config.rs::Match::matches` (`if self.arg_regex.is_some() { return false }`) | `config::tests::regex_condition_is_deferred_and_fails_closed` |
| Invariants #1/#2/#7 unchanged: the config only chooses provider/source/risk; token-ciphertext-at-rest, op-child-stdout->client-fd, and the fail-closed branches are the same code paths | `daemon.rs::fulfill` (unchanged token/provider handling), `config.rs` (routing only) | the full `daemon::tests` suite (inert-at-rest, denial-fails-closed) passes unchanged |

**Low-severity hardening note A (config-authoring ambiguity, not caller-exploitable).**
`route`/`route_exact` match `label == v OR vault.contains(v)` with `.find()`
returning the first hit. If one account's `label` collides with another
account's `vault` name, routing is order-dependent. The hint is config-derived
(Tom's own source label), so this is a misconfiguration foot-gun, not an attacker
primitive, and the mis-routed account still requires a fresh phone approval.
Recommend documenting that a source `account` label must be unambiguous across
the account/threshold stores.

**Low-severity hardening note B (fall-through on a dangling source).**
`Config::resolve` `continue`s past a rule whose `Match` holds but whose
`action.source` is unknown, trying the next rule rather than hard-refusing.
`add_rule`, `remove_source`, and `config import` all validate referential
integrity (`cli.rs::config_import` rejects an unknown source / empty match), so a
dangling source cannot arrive via the CLI or import; only a direct hand-edit of
the 0600 `config.json` (a same-UID write, already outside Sigil's boundary) can
reach it, and the worst effect is a *downgrade* to a later broader rule, still
gated, never ungated. Recommend a matched-rule-with-unknown-source hard
fail-closed (refuse the invocation) rather than fall through, so a misconfigured
specific rule can never silently resolve to a broader one. Informational.

## 16. The zero-knowledge phone reduction (`cdeebb7`, `ec59737`, `6e3d485`)

The phone dropped the R5 `consentConsistent` account<->secret cross-check, all
provider/account display surfaces, and all Mac-outcome reasoning, becoming a
pure provider-blind approve/deny approver that renders only the opaque
Mac-provided display fields.

**Independent review verdict, CONFIRMED SOUND.** Written by the
security-reviewer, which did **not** author the phone reduction (phone-approver);
not a self-certification. The adversarial pass covered: whether removing R5
creates a new display-spoof materially worse than the accepted residual #7;
whether the phone still learns only TRANSPORT status (never OUTCOME); and whether
the crypto is byte-identical.

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| Removing R5 creates **no** new attack worse than residual #7. A hostile relay gains nothing (the request rides the Ed25519-signed `Envelope` + replay guard; any tamper breaks the signature). A compromised Mac controls BOTH the displayed `secret_refs` AND the challenge `label`/`accountId`, so R5's fuzzy token-overlap was trivially self-satisfiable and never stopped the residual-#7 spoof; the "inconsistent request" R5 caught maps to no capable-adversary primitive | `envelope.rs::open`, `replay.rs::ReplayGuard`; phone `controller.ts::liveApproveThreshold` (no consent check, SE gate is the key release) | `proto/tests/hostile_relay.rs` (26 attacks) + `pairing_mitm.rs` pass unchanged; the phone gates the KEY not the display truth |
| The honest residual is correctly a **Mac-trust boundary, not a phone one**: a compromised Mac can spoof the display; the phone gates the SE key-agreement / DEK read behind Face ID, and the human declining an unexpected request is the backstop | `controller.ts::liveApprove{,Threshold}` (Face ID gate), residual #7 | reviewed by inspection; consistent with residual #7 |
| The phone learns only **TRANSPORT** status, never **OUTCOME**: `ApproveOutcome = sent \| refused \| no-session \| error`; "sent" means only that the response left the phone. All Mac-outcome copy ("Secret delivered" / "No secret was delivered" / "Could not reach your Mac") is removed for phone-local facts ("Approved. Sent." / "Denied." / "Request expired." / cause-neutral "That didn't go through.") | `controller.ts::liveApprove` (doc: "does not learn, and must not infer, whether the Mac then unlocked or delivered anything"), `approval-sheet.tsx::{DecisionSent,TerminalStatus}` | `bun run proto:selftest` green; grep confirms no approval-time outcome inference remains (only zero-knowledge doc-comments + legitimate pairing-msg-1 transport facts) |
| **Crypto byte-identical.** The only crypto-path edit is the Face ID `reason` string (`Approve ${label}` -> `"Approve request"`), which is a display-only `LAContext` prompt, the ECDH is `sharedSecretFromKeyAgreement(f, E)`, independent of `reason`. `requests.ts` is doc-comment only; wire fields unchanged; `ephemeralPub` is the sole crypto input, authenticated by the enclosing signed envelope; `accountId`/`seKeyId` travel in one signed challenge | phone `SigilSeModule.swift::computePartial` (reason feeds only the prompt), `controller.ts` (loadDek/computePartial/shapeEcdh/session.respond unchanged), `requests.ts` (doc only) | phone protocol **vectors 15/15**, `proto:selftest` all green (envelope, replay, forged-sender, wrong-recipient, tamper, fingerprint/mailbox, pairing tag/rendezvous vs rust); Rust `sigil-proto` 26 pass |

**Minor doc-drift (non-security, both changes).** A stale comment at
`apps/phone/modules/sigil-se/ios/SigilSeModule.swift:138` still reads "Bind the
Face-ID prompt to the account being unlocked (R5): the reason is the account
label", the reason is now the generic "Approve request". Flagged to the
phone-approver to clean; not a vulnerability.

**R5 mapping in this doc:** no §/row mapped R5 to phone code (the sweep found
none), so no stale claim to retract here; the R5 protocol doc comment on
`requests.ts` was already rewritten in `ec59737`.

## 17. Caller-stdin splice to the tool child (`538fd70`)

The `Run` frame now carries three descriptors (stdin, stdout, stderr) over
SCM_RIGHTS instead of two; the daemon splices the caller's stdin straight to the
spawned tool child so interactive tools (`op inject`, prompts) read the caller's
terminal. The claim is that the daemon only *passes* the fd (never reads it), so
invariant #2 (no caller/secret bytes in daemon memory) holds for the input
direction too.

**Independent review verdict, CONFIRMED SOUND on the happy path (two
low-severity hardening notes).** Written by the security-reviewer, which did
**not** author the splice (config-cli, `538fd70`); not a self-certification. The
adversarial pass covered: whether the daemon ever reads/buffers/inspects stdin;
fd ownership/lifetime (leak, retained readable dup, cross-request confusion);
whether stdin perturbs the stdout/stderr splice; fail-closed on a missing fd; and
new hostile surface (weird fd, blocking-stdin stall).

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| The daemon **only passes** the stdin fd, never `read()`s / buffers / inspects it: its sole consumer is `cmd.stdin(Stdio::from(fd))`. No caller/secret byte enters daemon memory for the input direction (invariant #2 holds for input) | `provider.rs::{OpProvider,EnvFileProvider}::run` (`Stdio::from(run.stdin)`), `daemon.rs::{handle_conn,fulfill}` (threads the fd through, never reads it) | `daemon.rs::caller_stdin_is_spliced_to_the_tool_child` (bytes written to the caller-side pipe reach the child; the daemon reads nothing) |
| **fd ownership/lifetime is correct**: every received fd is wrapped in `OwnedFd` (closed exactly once on drop); the daemon never `dup`s, so it retains no readable copy; on every fail-closed early return the unused stdin/stdout `OwnedFd`s drop (close) rather than splice | `local.rs::recv_with_fds` (`OwnedFd::from_raw_fd`), `daemon.rs::fulfill` (owned params dropped on early return), `provider.rs::run` (`Stdio::from` moves ownership to the child spawn) | `local.rs::op_fd_passing_and_reply_roundtrip_over_a_socketpair`, `daemon.rs::full_loop_over_the_socket_with_local_control_approval` |
| **No cross-request / cross-client fd confusion**; ordering preserved: each connection is a separate `spawn_blocking` task with its own `recv_frame` -> its own `OwnedFd` set on its own stack; the shim sends `[stdin, stdout, stderr]` and the daemon reads `next()/next()/next()` in the same order (SCM_RIGHTS preserves array order) | `daemon.rs::serve` (per-conn `spawn_blocking`), `handle_conn` (positional `fds.next()`), `shim.rs::forward` (`[inp, out, err]`) | `daemon.rs::caller_stdin_is_spliced_to_the_tool_child`, `dev_autoapprove_full_loop_delivers_secret_to_caller` |
| **Fails closed on the input path**: there is no daemon-buffered-stdin fallback anywhere, the daemon never reads stdin, so a missing/failed fd cannot fall through to daemon-read input; the child simply gets `None` for that slot | `daemon.rs::fulfill`, `provider.rs::run` (no daemon read of stdin exists) | reviewed by inspection (grep: `run.stdin`'s only use is `Stdio::from`) |
| A **malicious client passing a weird fd** as stdin gains nothing: the daemon splices it to the child (same UID as the attacker) and never acts on the fd's identity, so it is no more than what the attacker could feed a tool it ran itself | `provider.rs::run` (passthrough only) | reviewed by inspection; same trust model as the pre-existing stdout/stderr passing |

**Low-severity hardening note A (missing-fd inherit, invariant-#2-adjacent,
defense-in-depth).** The daemon does not validate that a `Run` frame carries
exactly three descriptors, and a missing fd makes the child **inherit the
daemon's** corresponding stdio (`provider.rs::run`: `if let Some(fd) = run.stdout
{ cmd.stdout(Stdio::from(fd)) }` with no `else` -> std default is *inherit*). So a
non-conforming same-UID client that sends fewer than three fds (e.g. zero) makes
an approved `op` child write its **secret to the daemon's inherited stdout**
(under launchd, a same-UID-readable log) instead of to the caller, secret bytes
leaving the intended splice path. The `None`->inherit pattern pre-dates this
change for stdout/stderr, but the stdin splice makes the three-fd positional
contract load-bearing with still no validation, and a *short* count now also
**misassigns** slots (a two-fd `[stdout, stderr]` sender is read as `[stdin,
stdout]`, leaving `stderr = None` -> inherit and shifting stdout). Bounded:
requires a crafted non-standard frame from a same-UID client **and** a granted
approval or active lease, and a same-UID attacker can read the secret more
directly, no real escalation. Cheap to close and recommended for an airtight
invariant #2: (a) reject a `Run` frame whose fd count != 3 (fail closed), and
(b) default an absent child stdio to `Stdio::null()` rather than inherit, so the
daemon's own stdio can never become a sink for tool output.

**RESOLVED (`91aab46`).** Both closes landed and are verified sound: `handle_conn`
now refuses any `Run` frame whose descriptor count != 3 (`fds.len() != 3 -> Exit
{ code: 1 }`) **before** anything spawns, so a short/long count can never
misassign slots; and both providers default an absent stdio to `Stdio::null()`
(`run.stdin.map_or_else(Stdio::null, Stdio::from)`), so the daemon's own
same-UID-readable stdio can never sink a tool's secret output. Proven by
`daemon.rs::run_frame_with_wrong_fd_count_is_refused` (a 2-fd frame -> exit 1, no
output) with the happy-path splice unchanged (`caller_stdin_is_spliced_to_the_tool_child`).

**Low-severity hardening note B (caller-stdin stall, DoS, post-approval +
same-UID).** Splicing the caller's stdin lets a compromised caller pin a daemon
blocking-thread: pre-change the child inherited the daemon's stdin (effectively
`/dev/null` under launchd, so a stdin read hit EOF); post-change the child reads
the caller's fd, which the attacker can hold open without sending data, so a
stdin-reading tool (`op inject`) blocks and holds its `spawn_blocking` thread for
as long as the caller keeps the fd open. With an active lease (approval
short-circuited) an attacker could fire many such requests and exhaust the
bounded blocking pool. Bounded (post-approval, same-UID, DoS-only, no disclosure,
fails closed) and the same class as any long-running approved child, but now
caller-triggerable via input. Optional hardening: a spawn watchdog/timeout, or
record it as an accepted same-UID residual.

**Note:** commit `538fd70`'s `shim.rs` hunk references a `crate::proxy` module
(the recursion fuse) that is part of the concurrent proxy work and was untracked
at review time, so the crate did not build standalone at that commit; the stdin
tests above were exercised by supplying the `proxy` module into a detached
worktree. Flagged to the team so the proxy module lands committed and the tree
builds clean (not a defect in the splice itself). **Update:** the proxy module is
now committed (`f5448cf`) and the tree builds (`91aab46` also landed Finding A's
fix, the `Run` fd path is now airtight); see §18.

## 18. The auto-aliasing proxy (`f5448cf`, `65d75d2`)

`~/.sigil/bin` goes first on `PATH`; each intercepted command is a symlink there
at the `sigil` runtime binary. Running `op` resolves the symlink -> `sigil`
re-enters as `sigil op ...` -> gates on the phone -> execs the **real** `op`
(resolved with the proxy excluded). Management is `sigil-config proxy
add|remove|list|status|doctor|env`. Design: `docs/design/proxy-aliasing.md`.

**Independent review verdict, CONFIRMED SOUND (two low-severity notes, neither a
distinct exploit).** Written by the security-reviewer, which did **not** author
the proxy (proxy-shim / rust-core); not a self-certification. The proxy is a
PATH/resolution convenience layer that **correctly disclaims being a containment
boundary**; the adversarial pass confirmed it fails closed on every
resolution/recursion fault, never lets the caller-controlled depth counter touch
a security decision, and does not weaken caller identity (#6) or secret handling
(#2).

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| `find_real` cannot be steered to an **attacker binary** via symlinks: `canonicalize` resolves a symlink / symlink-chain / real-looking symlink-into-the-proxy-dir to the running `sigil` binary, and rule 1 (canonical == `own_binary`) excludes it **in any directory** | `paths.rs::find_real` (skip `canon == own`), `proxy.rs::alias_target` | `proxy::a_stray_alias_symlink_outside_the_proxy_dir_is_not_the_real_tool`, `drift_when_a_real_binary_precedes_the_alias_is_a_bypass`, `healthy_when_alias_is_first_and_points_at_current` |
| The **daemon-up** path is immune to **caller PATH poisoning**: the `Run` frame carries only `argv`/`cwd`/`proxy_depth`/fds, never the caller's `PATH`/env, so the daemon resolves the real binary in its **own** trusted (launchd-pinned) `PATH`; a caller cannot redirect what the daemon spawns or steer the injected SA token to an attacker binary. The daemon-**down** path uses the caller's `PATH` but injects **no** secret (transparent exec), so a poisoned `PATH` there just runs the caller's own binary with no token, identical to no-Sigil | `local.rs::Frame::Run` (no env field), `provider.rs::OpProvider::resolve` -> `paths::find_real` (daemon env), `shim.rs::exec_real` (no env injected) | reviewed by inspection; `daemon.rs` provider tests spawn from the daemon's own resolution |
| A **hard copy** of the `sigil` binary planted as `<cmd>` (not caught by canonical equality) **fails closed**: `find_real` returns it -> re-enter -> loop, bounded by the depth fuse to exit 70 (shim) / daemon refuse at `MAX_DEPTH`. No ungated run, no secret leak, a bounded self-DoS requiring same-UID to plant a copy of the binary | `shim.rs::dispatch` (`depth_exceeded` -> exit 70), `daemon.rs::fulfill` (`proxy_depth >= MAX_DEPTH` -> `fail_closed`) | `daemon.rs::proxy_depth_is_incremented_on_the_child_and_fuses_at_the_limit`, `proxy::depth_fuse_reads_and_increments` |
| **PATH-order bypass is documented as a residual, never claimed prevented.** A real `<cmd>` before the proxy routes an *unmodified* caller ungated; `doctor` reports it as an operator convenience, and a caller that *wants* to skip the gate always can (real binary is never moved). No code treats PATH order as a control | `proxy.rs::ProxyStatus::issue` ("a real {cmd} precedes the proxy on PATH (requests would be ungated)"), `docs/design/proxy-aliasing.md` §"not a containment boundary" | `proxy::drift_when_a_real_binary_precedes_the_alias_is_a_bypass` |
| The **recursion guard cannot be cleared to escape gating.** `proxy_depth` is used in exactly one decision, `fulfill`'s `>= MAX_DEPTH -> fail_closed` (deny, safe direction), and is **never** consulted by the phone gate, account routing, caller-identity derivation, or lease keys. Setting `SIGIL_PROXY_DEPTH` high -> self-deny; setting it to 0 -> only prolongs a loop that exists solely if `find_real` is buggy (self-DoS), never a bypass; `saturating_add` prevents wrap | `daemon.rs::fulfill` (sole `proxy_depth` decision + `child_depth` env), `proxy.rs::{current_depth,depth_exceeded,next_depth_value}` | `daemon.rs::proxy_depth_is_incremented_on_the_child_and_fuses_at_the_limit`, `proxy::depth_fuse_reads_and_increments` |
| Caller identity (#6) is **not weakened**: the daemon derives identity from the kernel peer pid + ancestry walk, independent of anything the proxy supplies (argv/cwd/depth are decorative for identity) | `daemon.rs::handle_conn` (`peer = lease::peer_pid`), `lease.rs::walk_ancestry` | existing `lease.rs` ancestry/grant-key suite (unchanged) |
| Fail-closed (#7): a resolution failure execs nothing (`exit 127`); a protocol fault while the daemon is up is `exit 70`, never an ungated run; only a **down** daemon execs transparently (by design, injecting no secret) | `shim.rs::{exec_real,forward}` (127 / 70), `daemon.rs::fulfill` | reviewed by inspection; `shim.rs` module contract |

**Low-severity note A (doc-vs-code + defense-in-depth): the runtime `find_real`
implements only rule 1, not the proxy-dir exclusion (rule 2) the design claims.**
`docs/design/proxy-aliasing.md` §"hard problem 1(a)" states two exclusion rules,
(1) canonical == `current_exe` **and** (2) skip any candidate inside the proxy
dir. `paths::find_real` (the resolver that actually chooses what to exec/spawn)
implements only rule 1; rule 2 exists only in the **diagnostic** path
(`proxy.rs::ProxyStatus::detect_with`, via `is_shim_dir`). Impact: a **non-symlink**
executable resident in `~/.sigil/bin` under a tool's name (a hard copy, a script,
or a same-UID-planted non-sigil binary) is not excluded by `find_real`, so the
daemon-up path would treat it as "the real tool" and spawn it **with the injected
SA token**. Every route requires same-UID write to `~/.sigil/bin`, already
game-over (such an attacker can read the approved tool's `/proc/<pid>/environ` or
replace the real binary), so it is not a distinct escalation, but it is a real
gap between the doc's claimed guarantee and the code, and it diverges from the
diagnostic path. **Recommend implementing rule 2 in `find_real`** (skip any
candidate whose parent canonicalises to `shim_bin_dir()`): trivial, restores
doc/diagnostic parity, guarantees the daemon never injects a token into a
proxy-dir-resident binary, and as a bonus makes the hard-copy case resolve to the
real tool instead of fail-closed-looping.

**Low-severity note B (display correctness post-split, no security impact):**
`paths::find_real` keys its exclusion on `own_binary()` (= `current_exe`), while
aliases point at `alias_target()` (the sibling `sigil` runtime binary). In the
runtime `sigil` and the daemon these coincide, so **execution is correct**. But
called from `sigil-config` (`current_exe` != the runtime the aliases point at),
rule 1 fails to exclude the proxy-dir alias, so `Alias.real` (used only for
`proxy list`/`doctor` **display**) can show the alias path instead of the real
binary, disagreeing with `ProxyStatus.real` (which uses `alias_target`, correct).
Display-only; no execution/security impact. Recommend `find_real` exclude against
`alias_target()` (or both) for correct post-split diagnostics.

**RESOLVED (`0fc85a9`).** Both notes landed and are verified sound. `find_real`
now delegates to a testable pure core `find_real_in(cmd, path, own, alias_target,
proxy_dir)` that applies **rule 2** (skip any candidate whose parent dir
canonicalises to the proxy dir, so a non-symlink executable planted in
`~/.sigil/bin` is excluded, closing the daemon-up credential-injection corner and
making the hard-copy-in-proxy-dir case resolve to the real tool instead of
fail-closed-looping) **and rule 1 against both `own_binary()` and
`alias_target()`** (so from `sigil-config` the alias is excluded and `list`/`doctor`
`.real` agrees with `ProxyStatus.real`). Proven by
`paths::find_real_skips_a_non_symlink_planted_in_the_proxy_dir` and
`find_real_excludes_via_own_and_alias_target`; the design doc's rule 1/2 wording
was aligned so code and brief agree. Note A/B closed; §18 is now sound with no
open recommendations.

## 19. The inline `env` provider (sealed KEY=VALUE injection)

The inline `env` provider (provider id `env`) lets the user set secret VALUES
directly (`KEY=VALUE`) instead of pointing at a plaintext env-file. It is the
same direct-injection *shape* as §12's `env-file`, resolved values transit
daemon RAM only as the child's spawn env, for the spawn instant, and it never
leases, but unlike `env-file` the values are **sealed at rest under the DEK**,
so the daemon-at-rest holds no plaintext value (invariant #1) even here. This
section records behavior and residuals; the verdict is the independent
reviewer's.

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| VALUES are **never in `config.json`**: the config holds only the KEY names (public) plus the provider tag; the values are AES-256-GCM sealed under the DEK in the account store (`sigil.db`), keyed by the source name, exactly as a service-account token is | `config.rs::Source::keys` (names only, `#[serde skip_if empty]`), `secrets.rs::{SealedEnv,AccountStore::{set_env_blob,env_blob,remove_env_blob}}` (ciphertext, base64), `provider.rs::encode_env_pairs` (sealed plaintext) | `secrets.rs::env_blob_is_ciphertext_at_rest_and_round_trips` (greps the on-disk store: the VALUE is absent, the NAME present), `config.rs::resolve_flattens_inline_env_keys_and_source_name` (names round-trip, values were never there) |
| The value never reaches **argv** (`ps`-visible): `source env set --key` reads the VALUE from stdin into a `Zeroizing` buffer; `--stdin` reads `KEY=VALUE` lines the same way; the CLI rejects a value on argv by construction (there is no value flag) | `cli.rs::{read_secret_value_stdin,read_env_pairs_stdin,config_source_env_set}` | manual E2E (values piped on stdin); reviewed by inspection |
| `describe()` is **zero-knowledge**: it surfaces the KEY NAMES only (from config), never a value, and never reads the sealed blob (which it could not open pre-approval anyway) | `provider.rs::EnvProvider::describe` (maps `source.keys` to `SecretRef`s), `daemon.rs::fulfill` (builds `SourceView{keys}` before the decision) | `provider.rs::env_provider_flags_and_describe_shows_keys_not_values` |
| The blob is **decrypted only after the grant**: the ciphertext is fetched before the approval wait (safe to hold), the DEK arrives with the phone approval (or is unwrapped from the keystore on a local approval, the same as `op`), is used for the one decrypt, and is dropped at once | `daemon.rs::fulfill` (`sealed_ct` fetched pre-decision; the `else if let Some(ct)=&sealed_ct` arm unwraps `outcome.dek`/keystore, `decrypt_token`, `drop(dek)`) | `daemon.rs::inline_env_command_runs_gated_and_injects_sealed_values` |
| The decrypted pairs live in a `Zeroizing` map wiped at end of `run()`; the decode borrows out of the `Zeroizing` plaintext with `str::from_utf8` (no owned/un-zeroized value `String`) and fails closed on truncation or non-UTF-8 without panicking | `provider.rs::{decode_env_pairs,EnvProvider::run,spawn_with_env}`, `daemon.rs::fulfill` (`drop(sealed_env)`) | `provider.rs::{env_encode_decode_round_trips_including_awkward_values,env_decode_rejects_truncated_and_bad_utf8_without_panicking,env_provider_injects_decrypted_pairs_into_the_child}` |
| **Never leases** (`needs_account()==false`, `needs_sealed_env()==true`): like `env-file`, resolved values must not persist in daemon RAM across a TTL, so it is gated on every run | `provider.rs::EnvProvider::{needs_account,needs_sealed_env}`, `daemon.rs::fulfill` (the sealed-env arm never calls `leases.grant`; the lease short-circuit is `if needs_account`) | `daemon.rs::inline_env_command_runs_gated_and_injects_sealed_values` (`leases.active()==0`) |
| An **unset** source (no sealed blob) fails closed, never runs the child with a blank environment | `daemon.rs::fulfill` (`sealed_ct == None` → `fail_closed`) | `daemon.rs::inline_env_with_no_sealed_values_fails_closed` |
| **Readout integrity (invariant #3):** the decoded blob's KEY set is reconciled against `action.env_keys` (the set the phone readout/audit was built from) *before* injection; any divergence fails closed. This closes the two ways names could drift from values without breaking crypto, a crash between the store save and config save in `seal_env_pairs`, and an import that kept a source NAME but changed its keys while a stale blob survived, so the approver can never consent to "will set FOO" and have the child receive a hidden BAR | `daemon.rs::fulfill` (the sealed-env arm's `BTreeSet` compare of decoded keys vs `action.env_keys` → `fail_closed`) | `daemon.rs::inline_env_blob_keys_must_match_the_approved_set_or_fail_closed` (blob has an extra key vs config → refused, nothing injected) |
| Bulk `--stdin` parse errors report the **line NUMBER, never the line content**, so a mistakenly-piped secret line is not echoed to the terminal/logs | `cli.rs::read_env_pairs_stdin` (`"line {n}: no '=' found"`) | reviewed by inspection |
| `list`/`export` cannot leak a value (they render config only, which has no value), and `import` cannot round-trip a value into the clear (config carries names only); removing the source or clearing its last key **removes the sealed blob** (no orphan ciphertext), and an import that drops an env source prunes its blob | `cli.rs::{config_source_list,config_export,config_import,purge_env_blob,prune_orphan_env_blobs,seal_env_pairs}` | manual E2E (remove purges `env_sources`); reviewed by inspection |

The seal/open wire is length-prefixed (`u32 klen|key|u32 vlen|value`), pre-sized
so the encode buffer never reallocates, so a VALUE may hold any bytes (newline,
`=`, quotes) without an escaping ambiguity and decode borrows without a
non-zeroized copy. See **residual 13** for the two un-wiped copies this shape
inherits from §12 (the `Command` env map and the child's environ), identical to
`env-file`, plus the CLI-side merge copy at set time (the user is providing the
value, so it is in CLI RAM regardless; held `Zeroizing`).

**Independent review verdict, CONFIRMED SOUND for the crypto/at-rest core; one
P2 readout-integrity gap and two P2 hygiene notes, none a value leak.** Written by
the security-reviewer, which did **not** author the inline `env` provider
(rust-core); not a self-certification. The six implementer claims were verified,
not taken on faith:

- **At-rest is ciphertext (claim 1), CONFIRMED.** The on-disk `sigil.db` grep
  test proves the VALUE is absent and only the (public) source name + sealed bytes
  persist; `config.json` carries KEY names only (`Source::keys`,
  `skip_serializing_if = "Vec::is_empty"`). Values are sealed with the same
  AES-256-GCM `encrypt_token` under the DEK as service-account tokens. No value
  reaches a log/error/`{:?}` on the seal or decrypt paths (decrypt/decode failures
  print the GCM error or a fixed "corrupt" string, never plaintext).
- **list/export/import cannot leak a value (claim 2), CONFIRMED.** Export/list
  render config only (no value present to render); import carries names + provider
  tag, so it can only ever *remove* ciphertext (prune), never introduce plaintext.
- **`describe()` is zero-knowledge (claim 3), CONFIRMED for values.** The
  approval request's `secret_refs` and the audit label are built from KEY names
  only; no value crosses the wire or enters the sealed request.
- **decrypt→inject→zeroize, never leases (claim 4), CONFIRMED.** The DEK
  (`Zeroizing<[u8;32]>`) is opened only after the grant (phone-delivered
  `outcome.dek`, or a local keystore unwrap on a local approval, the same v1
  model as `op`), used for one decrypt, `drop`ped at once; the decoded pairs
  (`Zeroizing`) are dropped after the spawn instant; the sealed-env arm never
  calls `leases.grant` and the lease short-circuit is `if needs_account`. The
  reused `spawn_with_env` splice/exec path is #22's reviewed one.
- **remove/unset purges the blob (claim 5), CONFIRMED.** `remove_env_blob` on
  source-remove, empty-after-unset, and `prune_orphan_env_blobs` on import; no
  orphan accumulation.
- **DEK/value buffers zeroized on set/unset (claim 6), CONFIRMED.** `Dek` and
  `Token` are `Zeroizing`; the CLI holds value buffers as `Zeroizing<String>`,
  reads them from stdin never argv (no `ps` leak), and the merge copy is
  `Zeroizing`.
- **Hostile input, CONFIRMED fail-closed.** `decode_env_pairs` uses checked
  slicing and `str::from_utf8`, returning `None` (fail closed) on truncation, an
  over-long length, or non-UTF-8 without panicking; a tampered `sigil.db` fails the
  GCM tag on decrypt (a same-UID attacker cannot forge attacker-chosen values, only
  *relocate* an existing blob, see the P2 below); `valid_env_key` rejects `=`,
  NUL, whitespace, and control bytes; the proxy-depth env is set *after* the
  injected pairs so a supplied key cannot spoof the recursion fuse.

**P2-1 (readout-integrity gap): the phone readout (`describe`/audit, from
`config.keys`) is never reconciled with what is actually injected (the decoded
sealed blob).** `fulfill` injects whatever `decode_env_pairs` yields, while the
approver was shown `action.env_keys` from the config. Nothing checks the two key
*sets* agree. They can diverge two ways, both without breaking any crypto: (a) a
crash between `store.save()` and `save_config()` in `seal_env_pairs` (the store is
persisted with the new keys before the config is), leaving the blob ahead of the
config; (b) an `import` of a config whose env source keeps its **name** but changes
its `keys` list while a pre-existing blob under that name (with different keys)
remains, `prune_orphan_env_blobs` only drops blobs whose *name* is gone. Outcome:
the approver consents to "will set FOO" but the child is injected FOO **and** a
hidden BAR. This is **not a value leak** (values are never shown to the phone in
either case), it is a readout-*accuracy* break of invariant #3's "the approver
sees what will happen." Proven with a scratch test (config `[TOKEN]`, blob
`{TOKEN, SECRET}`): the readout showed `TOKEN`, the child received
`secret=hidden-exfil`. **Fix:** after `decode_env_pairs` in `fulfill`, assert the
decoded key set equals `action.env_keys` and `fail_closed` on mismatch (this also
closes the crash window and the import-leftover case); or inject only keys present
in `action.env_keys`. Severity **P2**: reaching it needs a crash or a same-UID
config/import manipulation, and same-UID is already outside the defended boundary,
but readout integrity is a stated approval property, so a cheap inject-time check
is warranted.

**P2-2 (terminal echo of raw stdin): `read_env_pairs_stdin` prints a malformed
line verbatim**, `eprintln!("sigil: line without '=': {:?}", line)`. On the
`--stdin` bulk path a piped line lacking `=` is reflected to stderr; if the user
accidentally pipes secret-bearing content, a bare-secret line is echoed to the
terminal/logs. Low blast radius (CLI-side, the user's own terminal, malformed
input only), but it is the one place raw stdin is reflected. **Fix:** report the
line index only, not its content.

**P2-3 (at-rest threat-model note): inline-`env` values are sealed under the
host/v1 DEK, not the v2 two-party threshold key.** Unlike a v2 `op` account (whose
token the daemon **cannot** open without the phone's partial), an inline-`env`
value is recoverable by a **local** approval, the daemon unwraps the host DEK from
the keystore itself (Touch ID / SE presence, `outcome.dek == None` path). This is
by design and identical to v1 accounts and local-approval mode, and is a strict
improvement over the plaintext `env-file` (§12), but it means inline-`env` does
**not** inherit v2's "daemon cannot open it alone" guarantee. Worth stating plainly
in residual 13 so inline-`env` is not assumed to have threshold-grade at-rest
protection.

Net: the sealing, zeroization, fail-closed decoding, no-lease, and
zero-knowledge-of-values properties all hold as claimed. The one substantive
finding (P2-1) is a readout/injection reconciliation gap that should get an
inject-time key-set check; the other two are hygiene. No P0/P1.

---

## 20. The single ToDaemon owner (demux to approval waiters)

*Implementer note (behavior + residuals only; the verdict is the independent
security-reviewer's).*

**Problem it fixes.** The phone deposits its APNs push token as a sealed
`PushRegister` on the `ToDaemon` channel the moment it arms
(`apps/phone/.../controller.ts`), not only alongside an approval. The relay holds
a deposit for `TTL_MS` (180s) and then drops it. Previously the daemon read
`ToDaemon` **only** at the start of an approval `round_trip` (`drain_pending` +
the response wait), so unless a gated command fired within 180s of arming, the
token expired unseen: `record_registration` never ran, `~/.sigil/push.json` was
never written, and every later deposit carried no `PushHint`, so the relay rang
no doorbell. The background doorbell simply never worked.

**Design: one reader, demultiplexing.** The relay hands each deposit to exactly
ONE reader, so two concurrent readers of `ToDaemon` would steal each other's
messages. The fix makes exactly one thread ever read `ToDaemon`:
`RemoteApprover::run_todaemon_owner` (spawned once by `daemon.rs::serve`, phone
factor only). It continuously long-polls `ToDaemon`, `classify`s each envelope
through the one shared `ReplayGuard` (now touched by this thread alone), and
routes by type:

- a `PushRegister` -> `record_registration` to the disk-backed `PushStore` (0600,
  survives restart via `PushStore::load`). This is how the arm-time token is
  captured the instant it lands, long before any command fires;
- an `ApprovalResponse` -> looked up in a `Mutex<HashMap<request_id,
  std::sync::mpsc::Sender<ApprovalResponse>>>` (`RemoteApprover::waiters`) and
  handed to the waiting `round_trip`; a response with no registered waiter is
  stale (its approval already timed out and removed itself) and dropped, exactly
  as the old inline demux skipped a non-correlating response;
- anything that fails verify/replay/decode -> dropped (fail closed).

`round_trip` no longer reads `ToDaemon` at all. It **registers its waiter (the
`Sender`) under `req.request_id` BEFORE it deposits the request**, then blocks on
the paired receiver (`recv_timeout(self.timeout)`); on timeout, or a seal/deposit
error, it fails closed to deny and always removes the waiter on the way out.

**Why this is race-free (no stolen responses, no lock).** Registering before
depositing closes the only window: the phone answers only after it *receives* the
deposited request, so a response can never arrive before its waiter exists. There
is exactly one `ToDaemon` reader, so no two reads ever contend for a deposit;
there is no mutex around the channel, and thus nothing couples an approval's
latency to the relay's long-poll. The owner is already parked in the very
long-poll that will receive the response, so an approval piggybacks it with no
added latency (strictly better than the pre-bug path, which issued a fresh GET per
approval). Any number of concurrent approvals with distinct `request_id`s are
served by the one reader via independent map entries; a test drives two at once
and asserts each waiter receives exactly its own DEK (no cross-delivery).

**Verify/replay semantics unchanged, and now single-threaded.** Every envelope
still goes through the same `classify` over the same single `ReplayGuard`, so the
phone's one monotonic outbound counter is enforced across responses and
registrations together exactly as before; because only the owner reads, that guard
is now touched by one thread (simpler, no lock-ordering question). The owner
grants nothing and never touches a DEK or `Z_F`; a `PushRegister` only writes
`{token, platform}`. A token is not a credential (§9 / the `push_store` module
docs): it unlocks nothing and the doorbell payload is a static string.

**Residuals for the reviewer to weigh:**

- *Stale-response drop is intentional and fail-closed.* If a `round_trip` times
  out and removes its waiter, a late response for that `request_id` finds no
  waiter and is dropped. The approval has already denied; the dropped response
  cannot resurrect a grant. A duplicate/replayed response is also stopped by the
  `ReplayGuard` counter regardless.
- *Owner liveness.* The doorbell depends on the owner thread running. If it exits
  (only on the shutdown flag) or panics, arm-time registrations stop being
  captured and, more importantly, in-flight approvals get no response and fail
  closed to deny at their timeout. It never fails open. On the network relay a
  single poll blocks inside the relay's ~25s hold, so shutdown/join can take up to
  one hold; the process is exiting regardless.
- *No relay spam.* The owner holds exactly one `ToDaemon` long-poll at a time and
  no more; approvals reuse it rather than opening a second. This respects the
  standing "NO SPAMMING, ONLY APNS wakeups" rule and adds no polling beyond the
  single idle long-poll the relay already expects.
- The relay stays powerless and anonymous: the token rides only as an opaque
  `PushHint` on a deposit, the daemon signs no push, and `push.json` stays 0600
  under `~/.sigil`. None of that changed.

**Independent review verdict, CONFIRMED SOUND (no findings; three accepted
residuals).** Written by the security-reviewer, which did **not** author the
demux-owner refactor (`7cbb24b`) or the allow-mode / lease-policy engine
(`e51b4ef`); per the review-integrity rule this is not a self-certification. The
adversarial pass covered both commits on `feat/config-rule-engine`: the
push-doorbell demux (race, stale-drop vs the replay counter, owner liveness,
token opacity) and the consent-surface changes (allow-mode fail-closed, lease
authority, passthrough splice discipline). The gate is green: `cargo test` 365
passed / 0 failed, `cargo clippy --all-targets -- -D warnings` clean, `cargo fmt
--check` clean.

**Demux owner (`7cbb24b`).**

| Claim | Enforcing code | Proving test | Verdict |
|-------|----------------|--------------|---------|
| Register-before-deposit closes the only response-loss window: the waiter is inserted under `request_id` before the request is deposited, and the phone answers only after it receives the deposit, so no response can arrive before its waiter exists | `remote.rs::round_trip` (register then `deposit_and_wait`), `remote.rs::register_waiter` | `remote::tests::an_approval_receives_its_own_response_via_the_owner` | SOUND |
| No cross-delivery: responses route by sealed, phone-signed `request_id` (uuidv7, unique); a relay cannot forge/redirect a response (fails `Envelope::open` signature) and a response for approval A can never resolve B (distinct ids) | `remote.rs::route_response` (`waiters.get(&resp.request_id)`), `envelope.rs::open` | `remote::tests::two_concurrent_approvals_each_receive_their_own_response` (distinct DEKs asserted) | SOUND |
| Stale/late/duplicate response cannot resurrect a grant: no waiter -> dropped; an exact-bytes replay is rejected by the single-use uuidv7 request-id gate (a held-late copy is caught by the freshness window), and a rejected envelope changes no guard state so it cannot desync a later legitimate response [mechanism corrected under task #67: the monotonic-counter gate is retired; see the "Independent review: #67 retire the monotonic-counter replay gate" verdict below] | `remote.rs::route_response`, `replay.rs::check_and_record` | `hostile_relay::replay_of_a_delivered_envelope_is_rejected`, `replay` unit tests | SOUND |
| Single reader: exactly one production `recv(ToDaemon)` exists (the owner); no second reader can steal a deposit | `remote.rs::run_todaemon_owner` (only `Direction::ToDaemon` `recv` in the crate) | grep-confirmed sole reader | SOUND |
| Fail-closed on owner death: a panicked/exited owner routes no responses; every `round_trip` `recv_timeout`s to `None` -> deny. No path opens fail-open | `remote.rs::deposit_and_wait` (`Err(_) => None`), `RemoteApprover::decide` (`unwrap_or_else -> Deny`) | `daemon::tests::denied_request_fails_closed_and_delivers_no_secret` | SOUND |
| The token path cannot influence a decision: a `PushRegister` only writes `{token, platform}` to the 0600 store; it never touches `waiters`, a DEK, or `Z_F`. The daemon signs no push; the token rides only as an opaque `PushHint` | `remote.rs::dispatch` / `record_registration`, `push_store.rs` (0600) | `remote::tests::the_owner_captures_an_arm_time_registration`, `push_store` 0600 test | SOUND |

**Allow-mode + lease engine (`e51b4ef`).**

| Claim | Enforcing code | Proving test | Verdict |
|-------|----------------|--------------|---------|
| Allow can never become allow-everything: an empty `Match` matches nothing in **both** modes, and an unmatched invocation resolves to `None` (refuse), never a silent passthrough | `config.rs::Match::matches` (`is_empty() -> false`), `config.rs::resolve` (`None` on no match) | `config::tests::empty_match_never_matches`, `allow_rule_resolves_to_passthrough_and_layers_above_a_gate` (unmatched refuses) | SOUND |
| Absent `mode` defaults to Gate, never Allow: `#[serde(default)]` + `#[derive(Default)] #[default] Gate`, so an older/hand-edited config that omits `mode` fails safe to gating. An **unknown** mode string fails the whole parse; the daemon then falls back to an empty config that refuses everything (stronger than gate) | `config.rs::RuleMode` (`#[default] Gate`), `Action.mode` (`#[serde(default)]`), `daemon.rs::serve` (parse error -> `Config::default()`) | `config::tests::allow_rule_..._layers_above_a_gate` (round-trips `Gate` by default) | SOUND |
| A matched **gate** rule with a missing source REFUSES (`None`), it does not fall through to a broader rule (this implements section-15 note B's recommendation: no fail-open downgrade) | `config.rs::resolve` (`let Some(src) = ... else { return None }`) | `config::tests::matched_rule_with_unknown_source_fails_closed_not_downgrade` | SOUND |
| `run_passthrough` injects no env and preserves invariant #2: it is `spawn_with_env(run, &[])`, reusing the one reviewed splice/exec path (caller fds to the child, absent fd -> `Stdio::null` never inherit, proxy-depth fuse). Allow never mints a lease, never creates a pending approval, never reaches the phone | `provider.rs::run_passthrough` -> `spawn_with_env`, `daemon.rs::fulfill` allow arm (`credential: None`, `env: None`, `source: ""`) | `daemon::tests::allow_rule_runs_the_command_directly_without_gating` (0 leases, 0 pending, exit 0) | SOUND |
| Lease authority is the daemon alone: a run-once rule yields no lease even when the approver returns one; a leasable rule clamps to `max_secs`. Every grant site consults the single clamped `lease_ttl` | `request.rs::LeasePolicy::clamp_secs`, `daemon.rs::fulfill` (`lease_secs = decision.lease_ttl().and_then(clamp)`; both `leases.grant` sites gated on `lease_ttl`) | `daemon::tests::run_once_rule_never_leases_even_when_a_lease_is_returned`, `leasable_rule_clamps_an_over_cap_lease_to_the_rule_max`, `request::tests::lease_policy_defaults_to_run_once_and_clamps` | SOUND |
| First-match-in-config-order is the only precedence; no second ordering path | `config.rs::resolve` (single `for rule in &self.rules` returning on first match) | `config::tests::resolve_first_match_wins_and_flattens_source`, `allow_rule_..._layers_above_a_gate` | SOUND |
| `lease_policy` rides inside the sealed+signed envelope (part of what the approver consents to); a relay cannot read or alter it without breaking the AEAD/signature | `remote.rs::build_request` (`lease_policy` in `ApprovalRequest`), `envelope.rs::seal/open` | `hostile_relay` tamper/forge suite (any bit flip breaks `open`), `request::tests::lease_policy_round_trips_through_json_camel_case` | SOUND |

**Accepted residuals (not defects, called out per the honesty rule):**

- *Hostile-relay reordering is never a wrong approval.* [Updated under task #67:
  the monotonic-counter gate is retired.] Reordering two **distinct** genuine
  `ToDaemon` envelopes now lets both open out of order: each carries its own
  uuidv7 and a fresh timestamp and routes by `request_id` to its own waiter, so a
  reordered real response resolves its own approval and nothing else (this is the
  fix's intent, the prior counter gate would have false-dropped the lower-counter
  one). The relay still cannot induce a **grant** (a response fails
  `Envelope::open` unless the phone actually signed it) nor a **replay**
  (identical bytes are caught by the single-use id; a held-late copy by the
  freshness window). Dropping or holding an envelope still only induces a denial,
  which is fail-closed (invariant #4/#7). Proven by
  `hostile_relay::reordering_distinct_envelopes_is_accepted` and
  `replay_of_a_delivered_envelope_is_rejected`.
- *Owner liveness is a single point of failure for the doorbell, but fail-closed.*
  A poisoned `waiters`/`guard` mutex (only reachable if a `round_trip` panics
  while holding it) or an owner panic stops response routing; all in-flight and
  future approvals then deny at timeout. It never fails open. A restart respawns
  the owner. Accepted.
- *An unknown `mode` (or any parse error) in the hand-edited 0600 `config.json`
  disables the entire rule set*, not just the malformed rule, because the daemon
  falls back to `Config::default()` (empty -> refuse all). This is fail-closed
  (safe) but an availability foot-gun: one typo bricks all gating until fixed. A
  same-UID hand-edit is already outside Sigil's trust boundary. Informational.

**Test-coverage note (informational, not a finding).** The "absent `mode`
defaults to Gate" property is guaranteed by construction (`#[serde(default)]` +
`#[default] Gate`) and exercised indirectly, but there is no focused test that
deserializes a rule JSON with the `mode` key omitted and asserts `Gate`. A
one-line test would harden the invariant against a future refactor that drops the
`#[serde(default)]`.

---

## Residuals (honest limits)

These are real and deliberately surfaced, not defects hidden.

1. **The local control-socket approver is not an adversarial gate, now gated
   behind an explicit arm-time factor policy (MITIGATED).** The control socket
   is same-UID-forgeable: an approval is granted by whoever sends
   `Frame::Approve { id }` on the 0600 unix socket, and the request `id` is only
   printed to the daemon's stderr, so a same-UID attacker who can read it can
   self-approve. A compromised same-UID agent (a rogue `claude`/`op`) is exactly
   the adversary Sigil exists to stop, so this path must never be the sole gate.

   The mitigation, added with the network transport: at arm time the daemon
   resolves an explicit **approving factor** (`factor.rs::resolve`,
   `daemon.rs::build_gate`), in order:
   - a **paired phone** reachable over a `Transport` (`RemoteApprover`), the
     sealed, signed `ApprovalResponse` a same-UID peer cannot forge;
   - a **verified hardware biometric** (`Keystore::is_biometric()` true), the
     Secure Enclave unwrap is the gate;
   - otherwise **fail closed**: a `NullApprover` denies every gated request,
     **unless** started with `--dev-insecure` / `SIGIL_DEV_INSECURE=1`.

   Only under `--dev-insecure` are `SIGIL_DEV_AUTOAPPROVE` (`with_dev`) and the
   control-socket park (`with_control_socket`) wired at all, and that mode prints
   a loud multi-line stderr warning naming the same-UID risk on every start
   (`factor.rs::warn_dev_insecure`). A normal `sigil daemon` with no phone and no
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

2. **Secure Enclave biometric unwrap and the kernel peer pid are unproven on
   hardware.** `keystore_macos.rs::{ensure_dek,unwrap_dek}` and
   `lease.rs::peer_pid` carry NEEDS-VERIFICATION and cannot be exercised away
   from a Mac. Until verified, the biometric factor is inert (returns
   `NeedsVerification`), so the effective shipping gate is either the phone or
   residual #1. The third item that used to sit here, the ancestor code-signing
   `identity`, is closed: it is now the platform's cdhash of the image each
   ancestor is RUNNING, taken off a guest code object the platform vouched for
   (ad-hoc signatures under their own tag, unmeasurable ancestors refused a
   lease), and it is exercised headlessly (see §7). It is a measurement and not
   tamper-evidence; its own residuals are stated in the `lease.rs` module docs
   and §7 rather than here.

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

5. **Lease-window / approved-consumer misuse (by design, widened
   2026-07-28).** A lease is a time-boxed grant to a *caller code-identity +
   account + matched rule*. Within an active lease, the same process tree can run
   **anything that rule matches, from any directory**, without re-prompting; it is
   no longer limited to the exact argv that opened the window. A compromised
   ancestor in that tree (e.g. `claude`) can therefore exercise the lease for any
   command the rule covers, not only the one the human read on the phone. The
   containment left is: the rule the user wrote (a narrow rule is a narrow lease),
   the rule's own lease policy (run-once never leases), the caller chain (a
   different or tampered tool tree is a different grant key), the account binding,
   and the TTL. A different rule is still a fresh approval
   (`lease.rs::grant_key`, `daemon.rs::fulfill`). The token itself never leaves
   the daemon, so the lease cannot be exfiltrated, only re-exercised inside the
   rule. Bound by TTL and killed by restart or revoke. This is a deliberate
   fatigue-versus-breadth trade the sole user asked for.

   **Independent reviewer amendment (2026-07-28).** The pass has now happened
   (verdict below); three facts the paragraph above omits, each of which a reader
   would need to size the residual honestly:

   * *It is not one secret's window, it is the rule's whole match set.* The
     approval sheet leads with one reference (`op://Engineering/.env`); with the
     shipped rule shape (`match: {command: "op"}`, no subcommand) the window
     covers every item in every vault that source can reach. Proven by reviewer
     finding **F1**.
   * *It is not "this process".* The grant key excludes pids, and every shim
     alias is a symlink to the one `sigil` binary, so the chain leaf is identical
     for every gated command and a second concurrent session with the same
     ancestor executables rides the same window. The caller chain never
     discriminated *which command*; after this change the rule name is the entire
     command-discriminating boundary. Reviewer finding **F2**.
   * *"Cannot widen its own scope" is true of the lease and false of the world
     around it.* The scope is a rule *name*, and rules are unsigned user config
     that hot-reloads; rewriting a rule mid-window widens a live lease. Reviewer
     finding **F3**. This grants an attacker nothing new (config write already
     defeats the gate via an `allow` rule) but it does mean a legitimate mid-window
     edit silently inherits a wider grant than was approved.

   The containment that genuinely survives all three: the TTL, the caller-chain
   code identity as an *outer* fence, and `run-once` rules (which never lease at
   all).

   ~~and the fact that no credential is cached, so an expired window leaves
   nothing behind.~~ **Struck by the reviewer 2026-08-04, this was true when
   written and is now false.** Since `d3887ad` a sealed inline `env` rule caches
   the unsealed values in lease RAM for the TTL, so a live window does hold a
   credential and the third bullet above (F3, config edits not invalidating a
   lease) stops being a judgment call. What still holds: the values are RAM-only,
   zeroized on every removal path, and pinned to the sealed record's ephemeral
   point, so a re-seal misses the lookup rather than injecting a stale plaintext.
   Whether that is sufficient is a Part 2 question and is not settled here.

   **Implementer note (2026-08-04), behavior change; not a verdict.** Two of the
   three bullets above have moved, and the last sentence of that paragraph no
   longer holds:

   * **F3 is now enforced.** `Core::reload_config` revokes and zeroizes every
     lease whose rule did not survive the reload byte-identical, and also when the
     source that rule injects from changed. The reviewer's rewrite-to-`curl`
     scenario is now a passing regression test
     (`daemon.rs::a_rule_rewritten_mid_window_does_not_inherit_the_lease`), and a
     re-seal of the source misses the cache via the lease's source-material
     binding. What remains true: `config.json` is unsigned, so anyone who can
     write it can still author an `allow` rule and defeat the gate outright.
   * **A credential IS now cached, by decision.** A leasable rule over a sealed
     inline `env` source retains the unsealed values in the lease's RAM slot, and
     leased runs inject them with no phone round trip. So "an expired window
     leaves nothing behind" is now a statement about *zeroization on every exit
     path* (expiry, revoke, restart, config change, re-seal miss), not about the
     window having held nothing. The blast radius of a live window on such a rule
     is the values themselves, for the TTL, to any command the rule matches from
     that caller chain. F1's point stands unchanged and gets larger: what the
     human approves is a rule's whole match set, now with the values held ready.
   * **F2's wrong comment and F4's missing domain separation are fixed**
     (`daemon.rs::fulfill`'s chain comment; `lease::ScopeKind` hashed into the
     grant key). **F5 is partly closed**: the account leg is live for cached
     leases and still a constant for plain gates.

   Not addressed here and still open for the next pass: **F1** (phone consent
   copy) and **F7** (the phone's lease list and revoke button), both owned by the
   phone surface; and `BlockDirective` ("deny and block") remains a wire type with
   no daemon consumer, so nothing in the daemon ends a window on a block.

6. **Metadata at the relay.** The relay learns that two anonymous mailbox
   parties exchange envelopes, and the sizes/timing of those envelopes. This is
   inherent to any store-and-forward transport and is the accepted trust surface
   (`docs/design/sigil-design-brief.html`, Trust model).

7. **The "inert at rest" claim is strong for cold-disk theft, weaker for live
   same-UID compromise.** Cold-disk theft yields only `pairing.json` (public);
   the daemon private identity is in the login Keychain, encrypted at rest, so a
   powered-off disk/backup reveals no key material, the strong form of the
   claim holds. But an attacker running live as Tom with the Keychain unlocked
   can read the identity blob and then originate `ApprovalRequest`s to the phone
   with **attacker-chosen provenance** (`process_chain`, `cwd`, `machine` are
   filled by whoever builds the request; the daemon normally derives them from
   kernel-verified ancestry, but a raw holder of the signing key writes them
   directly). The phone's readout cannot then distinguish an attacker's request
   from a legitimate one, so the last line of defense is the human declining a
   request they did not initiate. This is inherent to holding a signing key, not
   a defect; and a live same-UID attacker could already trigger a *real* request
   through the shim. The DEK still never releases without a fresh hardware-gated
   tap, so nothing is released automatically. Documented so the phone UX does not
   over-trust the displayed provenance.

8. **`pairing.md` doc drift (cosmetic).** The pairing design note states "the
   pairing secret is used only to key the confirmation MAC and is then
   destroyed." As of the rendezvous work the secret is *also* an input to
   `rendezvous_mailbox` (a distinct one-way BLAKE2b over `domain ‖ daemon_pub ‖
   secret`). This is a second, independent one-way use of a 256-bit CSPRNG value
, no key reuse across a shared construction, no oracle, non-invertible, so it
   is not a weakness, but the sentence in `docs/design/pairing.md` should be
   updated to name both uses. Flagged to the doc owner.

9. **The `env-file` provider relaxes invariant #2: resolved secret VALUES
   transit daemon RAM, and two copies are un-wiped (by design, bounded).** Unlike
   the `op` shape, where the daemon injects only a *credential* and the `op`
   child streams the resolved secret straight to the caller's fd, so no secret
   value ever enters the daemon, a direct-injection provider **is** the source:
   it reads KEY=VALUE pairs and places the actual values into the child's
   environment. The daemon holds those values in a `Zeroizing` buffer that is
   wiped on drop, and never logs them (`provider.rs::EnvFileProvider::run`). But
   two un-wiped copies are unavoidable:
   - **`std::process::Command`'s env map** holds a second, plain `OsString` copy
     of each value (std does not zeroize; it is freed, not scrubbed, when `cmd`
     drops at the end of the spawn). This is the *same* std limitation as the SA
     token in residual #3, except the value here is the resolved secret itself,
     not a credential. Bounded to the spawn. (The provider source comment was
     corrected in review to state this honestly rather than claim the `Zeroizing`
     buffer was the values' only in-process home.) The previously-noted
     invalid-UTF-8 lossy-`String` copy is now **FIXED**: `parse_env_file` borrows
     with `str::from_utf8` and returns `None` on non-UTF-8, so an invalid file
     fails closed with no owned `String` ever allocated (`provider.rs::{env_file_with_invalid_utf8_is_rejected,env_file_run_fails_closed_on_invalid_utf8}`).
   - **The child's `/proc/<pid>/environ`** carries the injected values for the
     child's whole lifetime, readable by a same-UID process (`ps eww`, `/proc`).
     For a short-lived child this is a blink; for a long-running one the secrets
     sit in its environment the whole time. This is inherent to *any* "inject env
     and exec" model (the `op` SA token has the same exposure in `op`'s environ),
     and same-UID is already the boundary Sigil does not defend below.

   Leasing is **disabled** for this shape precisely so resolved values never also
   persist in daemon RAM across a TTL (`daemon.rs::env_file_lease_decision_grants_no_lease`).
   Net: `env-file` is strictly more exposed than `op`, the doc says so plainly,
   and it is the reason `op`'s credential-injection shape remains the recommended
   default. Severity: **Medium, inherent to direct injection, documented not
   fixed.** The daemon-RAM copy is same-process-scrape only.

10. **The SSH agent's `op` signer holds the whole private key in RAM for one
    signature (unchanged from `0f41ee4`, now isolated behind the signer seam).**
    On an approved `SIGN_REQUEST` the `OpSshSigner` fetches the key via the
    service account into a `Zeroizing` buffer, signs once, and wipes. Because the
    SA token can read the *whole* key, a compromise at the instant of an approved
    request leaks durable signing power, not one signature, strictly worse than
    a secret release. The seam does not change this; it isolates it to that one
    signer (`FileSshSigner` reads a local file into `Zeroizing` with the same
    per-signature discipline, and a future SE-resident signer would keep the key
    in hardware). Bounded to an *approved* request. Severity: **Medium, v1
    custody exception, documented; v2 moves keys to the Secure Enclave**
    (`docs/design/ssh-agent.md` §4).

11. **The SSH `session-bind` host line is attacker-nameable (advisory only).**
    The agent protocol carries no authenticated hostname; the host key a client
    sends over `session-bind` is not verified by the agent, so a malicious
    same-UID client can label the approval screen with any destination, including
    a real public host key. The host line is therefore *context*, not a gate: the
    binding is the human approving the **data hash** for a **named key**, and an
    unexpected signature prompt is itself the signal. `derive_host` never
    fabricates a name (it falls back to the honest `SHA256:` fingerprint). Severity:
    **Low, inherent to the agent protocol; the data hash is the real binding.**

12. **The P-256 SE DEK wrap carries no sender authentication (correct for the
    local-only use; a constraint for any future remote use).** ECIES to the SE
    public key gives confidentiality and (via GCM) integrity, but not *sender*
    authentication: the SE public key is public, so anyone can wrap an arbitrary
    value to it. This is safe as designed because the wrap is produced and consumed
    **locally**, the daemon wraps the DEK to the same Mac's SE key, and the SE
    unwraps it under Touch ID, so forging or swapping the stored blob already
    requires same-UID write (outside Sigil's boundary) and yields only a fail-closed
    denial (a substituted DEK cannot decrypt the real AES-256-GCM token ciphertext),
    never a secret. AAD binding is **impossible** anyway: `SecKeyCreateDecryptedData`
    for this ECIES algorithm accepts no AAD, so any AAD would break SE interop.
    **Design constraint, recorded so it is not lost when the wrap is wired in:** if a
    wrapped-DEK-to-SE blob is ever delivered by a *remote* party (over the relay, or
    phone→different-machine), it MUST travel inside the signed `Envelope` (Ed25519
    sender auth + replay guard), never bare and never via GCM AAD the SE cannot
    validate. Severity: **None today (local-only, fail-closed); a tripwire for the
    integration step.** Enforcing code: `se_ecies.rs` module docs §"Binding and
    sender authentication".

13. **The inline `env` provider inherits §12's direct-injection RAM residual (by
    design, bounded), improved by sealing the values at rest.** Like `env-file`
    (residual 9), on an approved run the resolved VALUES transit daemon RAM as the
    child's spawn env: a second, un-wiped `OsString` copy sits in
    `std::process::Command`'s env map (std frees but does not scrub it, bounded to
    the spawn, the same std limitation as the op SA token in residual #3), and the
    child's `/proc/<pid>/environ` carries the values for its lifetime (readable by a
    same-UID process; inherent to any inject-env-and-exec model, and same-UID is
    already the boundary Sigil does not defend below). The daemon's own decrypted
    copy is `Zeroizing`, wiped on drop, and never logged; leasing is disabled so
    resolved values never persist across a TTL. **Improvement over `env-file`:** the
    values are AES-256-GCM sealed under the DEK at rest (`sigil.db`), so, unlike a
    plaintext env-file readable by any same-UID process at any time, the
    daemon-at-rest holds no plaintext value (invariant #1 holds for this provider).
    One extra transient copy exists at **set time**: `sigil-config source env set`
    decrypts the current blob, merges the new pair, and re-seals; the merged pairs
    (and the value the user is supplying, which is in CLI RAM regardless) are held
    `Zeroizing` for that CLI invocation only. Severity: **Medium at run time
    (inherent to direct injection, same as §12), reduced at rest (sealed, not
    plaintext).** Enforcing code: `provider.rs::{EnvProvider,spawn_with_env,
    decode_env_pairs}`, `daemon.rs::fulfill`, `cli.rs::seal_env_pairs`. See §19.

14. **Pairing-authorization biometric now gates the persist step, independent of
    DEK delivery (#48), implementer behavior note, awaiting an independent
    verdict.** `pairing_store::save` runs a hardware user-presence check
    (`Keystore::verify_presence`, gated on `is_biometric()`) as its FIRST action,
    before any state is written, and deny-closes: a declined or unavailable
    biometric returns an error and NOTHING is persisted (no identity blob, no
    config file). On the real macOS keystore `verify_presence` reuses the same
    Secure Enclave `.biometryCurrentSet` private-key op the approval path uses
    (`keystore_macos.rs::verify_presence` -> `unwrap_dek`), performed purely as a
    presence probe and the recovered `Zeroizing` DEK dropped immediately, no DEK
    crosses any boundary, which is what makes the gate independent of DEK
    *delivery*. **Residual A (double biometric prompt on real hardware):** the
    pairing ceremony still unwraps the DEK to seal it to the phone
    (`pair.rs::run_ceremony` step 4), and this new persist-time probe is a second
    SE op, so a real-hardware v1 pairing currently prompts Touch ID twice. The
    codebase has no `LAContext` reuse-window plumbing yet (see the
    `keystore_macos.rs::unwrap_dek` NEEDS-VERIFICATION note), so the two prompts
    cannot presently be collapsed into one; a shared `LAContext` with
    `touchIDAuthenticationAllowableReuseDuration` would reduce it to one and is the
    natural follow-up. **Residual B (default fail-closed for a mis-declared
    keystore):** the `Keystore::verify_presence` trait default returns `Err`, so a
    keystore that reports `is_biometric() == true` but omits the override refuses
    to pair rather than passing unchecked. The non-hardware stores keep
    `is_biometric() == false` and are never asked THAT way, so headless dev and
    tests still pair.

    **Behavior change (2026-08-04), keystore default.** The on-disk store is now
    the default, and it is not hardware-backed, so tying this gate to the store
    would have deleted it on every Mac. Storing blobs and proving presence are now
    separate questions: `keystore::presence_plan` sends a hardware store to its own
    `verify_presence`, sends the default file store to
    `keystore::verify_host_presence` (macOS `LAContext.evaluatePolicy`, which never
    needed the keychain, the Secure Enclave, or a signature), and sends the
    in-memory store nowhere, which is what keeps tests headless. So `sigil pair` on
    the default store still costs a live Touch ID. Proving test:
    `keystore.rs::presence_is_asked_of_the_host_when_the_store_cannot_prove_it`
    (the plan is pure and testable; the prompt itself stays manual-only).
    Enforcing code: `pairing_store.rs::save` (gate), `keystore.rs::verify_presence`
    (fail-closed default), `keystore_macos.rs::verify_presence` (SE probe). Proving
    tests: `pairing_store.rs::{a_declined_biometric_refuses_the_pairing_and_writes_nothing,
    a_biometric_keystore_that_grants_presence_persists_the_pairing,
    a_biometric_keystore_missing_a_verify_presence_override_fails_closed}`. The
    on-hardware Touch ID firing is **UNPROVEN** (shares the §6 NEEDS-VERIFICATION
    gap: the SE op is exercised only against the memory stand-in in tests).

15. **Config hot-reload swaps the rule set live and stays fail-closed (#59),
    implementer behavior note, awaiting an independent verdict.** A watcher thread
    stat-polls `~/.sigil/config.json` every 2s and, on an mtime change, calls
    `Core::reload_config`, which loads and fully parses the file and only THEN
    atomically swaps the in-memory `Arc<Config>` (`daemon.rs::{ConfigCell,
    spawn_config_watcher,reload_config}`). **Fail-closed proof:** the swap
    (`ConfigCell::store`) is on the `Ok` arm exclusively; a malformed, truncated
    (half-written save), or unreadable file returns `Err` WITHOUT touching the
    cell, so the last-good rules stay in force and gating is never downgraded by a
    bad reload, a bad reload never falls open, nor to refuse-all. **Torn-read
    safety:** a gating decision takes `ConfigCell::snapshot` (read-lock, clone the
    `Arc`, unlock) and evaluates the whole `resolve` against that one `Arc`, so a
    reload landing mid-decision is invisible to it (it sees the entire old or the
    entire new config, never a blend). **Residuals:** (a) legacy `commands.json`
    is not watched, only `config.json`, the current authoring surface, so a raw
    legacy edit still needs a restart (migration is one-time); (b) removing
    `config.json` entirely reloads to the empty default, which refuses every
    command (fail-closed, but a surprising "everything stopped" if deleted by
    accident); (c) the poll is mtime-based on APFS's high-resolution timestamps,
    a same-nanosecond rewrite of identical length is theoretically missed, but
    edits here are human-paced and single-user. Proving tests:
    `daemon.rs::{config_hot_reload_swaps_in_the_on_disk_rules,
    config_reload_is_fail_closed_on_a_malformed_file}`.

16. **One authoritative default socket, resolved with zero environment (#59),
    implementer behavior note.** `local::socket_path` and `sshagent::socket_path`
    both derive from a single `local::runtime_dir` anchored on the stable per-user
    temp dir (`confstr(_CS_DARWIN_USER_TEMP_DIR)` on macOS), not the `$TMPDIR` env
    var, so the daemon, the `op` shim, the `sigil` CLI, and a bare shell all
    resolve the SAME `daemon.sock` / `ssh-agent.sock` with no `SIGIL_SOCK`.
    `SIGIL_SOCK` / `SIGIL_SSH_SOCK` remain full-path overrides for tests and
    bespoke deployments. The confstr path is short (~50 bytes), keeping the socket
    well under `sun_path` (the existing `service::socket_path_fits` check still
    guards it). **Residual:** if the confstr lookup ever returns empty we fall back
    to `/tmp/sigil` (world-visible dir, but the socket itself is still 0600 and its
    parent dir 0700 via `prepare_socket`); this is the same posture as the prior
    `$TMPDIR`-absent fallback. Proving tests:
    `local.rs::{socket_path_honors_the_sigil_sock_override,
    daemon_and_ssh_sockets_share_one_authoritative_runtime_dir}`.

---

## Independent review verdict: pairing-security unit (f1192b6, 37035ee, 13e56c2)

**Reviewer:** independent security-reviewer (did NOT write this code). **Date:**
2026-07-06. **Scope:** the SAS-confirm stdin gate on `sigil pair --json`
(f1192b6), the real P-256 Secure Enclave DEK wrap in `keystore_macos.rs`
(37035ee) plus its uncommitted `for_test`-isolation follow-up in the working
tree, and the relocation of the DEK unwrap from ceremony-start to
post-SAS-confirm (13e56c2). Static/adversarial review only; no biometric
hardware was exercised (see residuals). This verdict is written by the
independent reviewer per the review-integrity rule; the implementer did not
self-certify.

**Bottom line: SOUND at the logic/code level, assuming the Secure Enclave FFI
behaves as Apple documents.** No P0 or P1 confirmed. The central claim holds:
**there is no path that delivers the DEK without both a genuine SAS gate and a
fresh Secure-Enclave-gated biometric.** Two P2 code findings and a set of
hardware-verification residuals are recorded below; one P2 is a data-loss
footgun in the committed hardware test that the uncommitted working-tree change
correctly fixes and that must be committed.

### CONFIRMED SOUND (static)

1. **SAS bypass on the `--json` path is closed.** `run_pairing_json`'s
   `confirm` closure (`crates/sigil/src/cli.rs:1428`-`1440`) now emits the `sas`
   event, then blocks on one line of stdin and returns `true` only for a
   trimmed, case-insensitive `"confirm"`; `Ok(0)` (EOF), any other line, and
   `Err(_)` all return `false`. `run_ceremony` (`crates/sigil/src/pair.rs:153`)
   treats `false` as `bail!` before any unwrap or deliver. The pre-fix
   auto-`true` is gone. Fail-closed on every non-confirm input.

2. **Confirm → biometric → deliver ordering is correct and has no
   pre-biometric delivery path.** In `run_ceremony`
   (`crates/sigil/src/pair.rs:149`-`177`) the strict order is: `confirm_sas`
   (human) → `daemon.confirm()` → `unwrap_dek()` (on an SE keystore, the Touch
   ID moment) → `deliver_dek` → `channel.send`. `daemon.confirm()` transmits
   nothing over the channel; the *only* `channel.send` of DEK material is at
   line 173-175, strictly after `unwrap_dek()` at line 162. A declined/EOF/error
   SAS bails before line 162; an `unwrap_dek` error (`Declined` or `Backend`,
   mapped to `anyhow` in cli.rs:1310-1312 / 1440-1442) bails before any send.
   Fail-closed throughout.

3. **The 13e56c2 relocation genuinely closes the same-UID stdin-writer
   threat.** Because the biometric now fires at `unwrap_dek` (after the stdin
   `confirm`), a process that can only write `"confirm"` to the pair
   subprocess's stdin cannot complete a pairing: it still faces a fresh
   Secure-Enclave biometric it cannot satisfy. The stdin `confirm` and the
   biometric are *not* separable into a single reusable authorization, the
   biometric is enforced by the SE key's own access control on
   `SecKeyCreateDecryptedData`, not by any token the caller holds. Encoded as a
   regression test: `pair.rs::the_dek_is_never_unwrapped_when_the_sas_is_declined`
   (added by this review) asserts `unwrap_dek` is invoked **zero** times and no
   envelope is sent when `confirm_sas` returns `false`. A refactor that moved the
   unwrap back ahead of the SAS gate fails this test.

4. **No error-code mapping can cause a fail-OPEN.** The residual flagged by the
   implementer (errSecUserCanceled `-128` vs errSecAuthFailed `-25293`) is a
   *classification* question, not a safety one: the **only** success path out of
   `unwrap_dek` is a non-null `plaintext_ref` of exactly 32 bytes
   (`keystore_macos.rs:249`-`279`). Every `CFError`, whichever code, routes
   through `cf_error_to_keystore` to either `Declined` or `Backend`, and **both**
   abort the pairing ceremony (`pair.rs:162` bails) and deny in the local-approve
   path (`approve.rs:420`-`422`: only `Ok(_dek)` approves; `Declined` denies;
   any other error falls through to a `Deny` under production config). So even a
   fully wrong `-128`/`-25293` mapping changes only the deny-vs-hard-error UX,
   never approve-vs-deny. Confirmed for both the pairing and approval surfaces.

5. **The `SecKeyCreateDecryptedData` FFI is memory-safe and leak-free (modulo
   hardware behavior).** `keystore_macos.rs:249`-`279`: the out-error is checked
   before the plaintext; a non-null `CFErrorRef` is taken under
   `wrap_under_create_rule` (create-rule ownership, no double-free/leak); a
   null-plaintext-with-null-error case is handled as a `Backend` fault; the
   `CFData` result is taken under the create rule; the recovered bytes are
   length-checked to 32 and copied into a `Zeroizing<[u8;32]>`. `key` and
   `ciphertext` are live `TCFType`s across the call. The DEK plaintext exists
   only in the `Zeroizing` buffer and is never logged or copied elsewhere.

6. **DEK protected at rest; wrap/unwrap matched.** Only the SE-wrapped blob is
   persisted (`DEK_ENVELOPE_LABEL`, ciphertext); the DEK plaintext is built in
   pure Rust (`sigil_proto::wrap_dek_p256`), used, and dropped/zeroized in
   `ensure_dek` (`keystore_macos.rs:213`-`220`). The wrap
   (`p256::ECDH` + ANSI-X9.63-SHA256 KDF + AES-128-GCM, 16-byte variable IV,
   65+32+16 = 113-byte blob) and the SE unwrap
   (`ECIESEncryptionCofactorVariableIVX963SHA256AESGCM`) are the same
   construction, already reviewed under #23; the KDF is pinned by a
   known-answer test. At the code level the access control is
   `kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet`
   (biometric mandated, **no** `.devicePasscode`/`.userPresence` fallback), so a
   passcode alone cannot unwrap.

### CONFIRMED FINDINGS (code-level, need a fix)

- **P2, the SE access control is created with a NULL protection class,
  diverging from every reference and the design's stated intent.**
  `keystore_macos.rs:186`-`189` calls
  `SecAccessControl::create_with_flags(...)`, which in security-framework 2.11.1
  is `create_with_protection(None, flags)`, it passes a **null** protection
  value to `SecAccessControlCreateWithFlags`
  (`.cargo/.../security-framework-2.11.1/src/access_control.rs:51`-`76`). Every
  Swift counterpart pins `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
  (`apps/mac/Tools/se-selftest.swift:29`,
  `apps/mac/Sigil/Security/SecureEnclaveApprover.swift:52`,
  `apps/phone/.../SigilSeModule.swift:95`) and `apps/mac/RESEARCH.md:70`
  specifies exactly that class. Consequence is **fail-closed, not
  fail-open**: on hardware this most likely makes `SecKeyCreateRandomKey`
  reject the request (ensure_dek → `Backend`, denies), or at best mints the key
  without the intended `WhenUnlocked`/`ThisDeviceOnly` guarantee the brief calls
  for. Fix: `SecAccessControl::create_with_protection(Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly), flags)`.
  Not a disclosure risk (the biometry flag and SE non-extractability are
  independent of the protection class), but it is a real divergence that should
  be corrected before the on-hardware verification, or the verification will
  test the wrong construction.

- **P2 (data-loss footgun, not disclosure), the committed 37035ee hardware
  test deletes the REAL production DEK blob.** As committed, the ignored test
  `se_dek_round_trips_through_a_real_touch_id` ran `MacKeystore::new()` (real
  labels) and `delete_blob(DEK_ENVELOPE_LABEL)` (the real production envelope),
  then `ensure_dek()`, minting a **fresh** DEK under the real label. Running it
  on Tom's Mac would have bricked every account whose token was sealed under the
  prior DEK (the new DEK cannot decrypt them; fails closed, but the tokens are
  unrecoverable without re-add). **Resolved in HEAD by df78e8f** ("make the SE
  round-trip harness isolation-safe"), which landed during this review:
  per-instance labels via `MacKeystore::for_test`, `.selftest` suffixes, and
  always-cleanup with `catch_unwind`, so the test can never touch the production
  `SE_KEY_LABEL`/`DEK_ENVELOPE_LABEL`. Recorded so the reason the isolation
  exists is not lost: never let a hardware test run against the real labels.

### RESIDUALS, require Tom's on-hardware verification (cannot be settled statically)

- **Declined-biometric error code** (`ERR_SEC_USER_CANCELED` `-128` vs
  `ERR_SEC_AUTH_FAILED` `-25293`, `keystore_macos.rs:66`-`79`): confirm which
  `SecKeyCreateDecryptedData` actually returns on a declined prompt. Per finding
  #4 this affects only deny-vs-hard-error UX, never safety.
- **SE-key re-query** (`find_se_private_key`, `keystore_macos.rs:286`-`300`):
  `ItemSearchOptions` has no `kSecUseDataProtectionKeychain`; confirm a key
  minted in the `DataProtectionKeychain` actually surfaces by label. If not, it
  returns `NoDek` → fails closed.
- **SE decrypt interop**: that Apple's `SecKeyCreateDecryptedData` opens a blob
  produced by `wrap_dek_p256` byte-for-byte. The in-crate tests only prove
  Rust-side self-consistency. Confirm with `apps/mac/Tools/se-selftest.swift`
  and the ignored round-trip test on Apple-silicon with an enrolled biometric.
- **`.biometryCurrentSet` mandates biometric with no passcode fallback** on
  macOS as documented, confirm the prompt is biometric-only and that a fresh
  evaluation fires on *each* unwrap (no LAContext is passed, so there is no
  biometric-reuse window by construction; verify the OS honors that).
- **Generic prompt copy (social-engineering residual).** `unwrap_dek` does not
  thread `reason` into an `LAContext`, so the Touch ID sheet shows default
  system copy. The biometric therefore proves *fresh human presence at DEK
  release*, not *human authorizing this specific device*, the device-binding
  backstop remains the human's SAS-word eyeball comparison, not the biometric.
  Acceptable (the SAS is the MITM gate; the biometric is presence), but until an
  `LAContext` names the action the prompt cannot itself disambiguate a
  legitimate pairing from a same-UID-triggered one to a distracted user.

### SECONDARY, relay v4 trust-model relaxation (opinion, not the primary verdict)

The end-to-end crypto **still holds** despite the relay becoming a
content-free "blind doorbell": every envelope remains opaque and sealed by
`crates/sigil-proto` (Ed25519 sender auth + `crypto_box`/threshold + replay guard),
the relay never parses one, and the push body is fixed and generic. The relay's
new powers, a shared publisher APNs signing key held as a platform secret, and
a phone push token seen transiently per deposit and never stored, do not let it
read a secret, forge an approval, or learn an outcome. Invariant #3's "powerless
and anonymous" is genuinely relaxed to "blind doorbell, holds a push secret";
the README records this honestly and defers the verdict here, which is correct.

The **per-mailbox (not per-token) push cap** (`PUSH_MAX=5/min`) is an
acceptable residual with a named limit: a party who has already obtained a
victim's push token (itself not secret-bearing) can ring that phone's doorbell
and evade the cap by rotating the `mailbox_id` in the deposit URL, since the cap
is keyed per mailbox and the push targets whatever token the body carries. Worst
case is generic "Approval requested" notification spam / battery drain, **not**
a secret disclosure and **not** an approval (the phone still needs the real
sealed request plus a biometric to approve anything). Acceptable as a
nuisance-only vector; a per-token bucket, or requiring the doorbell deposit to
be bound to the sealed envelope, would close it if push-spam becomes a concern.

**Verdict recorded by the independent security-reviewer. The pairing-security
unit is sound; fix the two P2s (commit the `for_test` isolation; give the SE
access control an explicit `WhenUnlockedThisDeviceOnly` protection class) and
clear the hardware residuals before treating the SE path as verified.**

---

## §15, relay long-poll v5.1: coexisting waiters + newest-wins delivery (commit `33b464f`)

Independent adversarial review of the delivery-semantics change in
`relay/shared/protocol.ts` (`longPoll`/`wake`/`MAX_WAITERS`). Reviewer did not
author the change. Focus: delivery integrity (no silent loss beyond honestly
stated residuals, no starvation/steal by a hostile party, no unbounded memory);
envelope crypto is unchanged and out of scope. Invariant at stake throughout is
**everything fails closed** (#5) and the relay's no-silent-drop promise, not
confidentiality (#3 holds, envelopes stay opaque, and every worst case below is
a *non-delivery*, never a disclosure).

**The change, restated adversarially.** Old `longPoll` flushed every existing
waiter empty on each new GET (`waiters.splice(0)`), manufacturing instant-empties
a client re-fired on (the poll storm). New: waiters coexist, each held its full
window; `wake` delivers a deposit to the **newest** waiter (`waiters.pop()`);
`MAX_WAITERS=8` caps memory, and past the cap a new GET drops the **oldest**
waiter (resolved empty). Both suites green locally (Bun 37 / Worker 21);
reviewer's scratch suite (`relay/scratch-adversarial.test.ts`, 4 tests) proves
the four properties below.

| Claim | Enforcing code | Proving test | Verdict |
|-------|----------------|--------------|---------|
| **Newest-wins delivers correctly for the shipped clients.** Both the daemon (blocking `reqwest`, one GET at a time) and the phone (`relay-http.ts` `activeWaits` aborts any prior poll before a new one; `phone-relay.ts` `inFlight` collapses concurrent wakes) are **strictly single-flight per slot**. Two waiters therefore only coexist via disconnect-then-reconnect, which makes the OLDER the dead orphan and the NEWER the live reconnect. `wake` → newest → the connection that can still receive. | `wake` (`protocol.ts:325`, `waiters.pop()`); `sigil-relay-client/src/http.rs` (blocking); `apps/phone/src/transport/relay-http.ts:95` (`activeWaits`) | `protocol.test.ts` disconnect/reconnect test; scratch `NOT reachable by a single-flight client…` | **SOUND** |
| **`MAX_WAITERS` drop-oldest never loses a queued deposit.** Eviction runs only on the empty-slot branch (the `drain` above returned nothing), synchronously, with no `await` between the drain and the `while` loop, so single-threaded JS guarantees the slot is provably empty at eviction; the dropped waiter is resolved `[]` with nothing to lose. | `longPoll` (`protocol.ts:249-273`) | scratch `MAX_WAITERS drop-oldest never loses a queued deposit…` | **SOUND** |
| **Neither paired party can starve the other's inbound delivery.** `toPhoneWaiters` (phone reading) and `toDaemonWaiters` (daemon reading) are disjoint arrays. A flood of GETs on one slot evicts only that slot's own oldest waiters; it cannot touch the other slot. So one misbehaving side can only self-DoS its own reads. | `Mailbox` (`protocol.ts:130-143`); slot-specific `wake`/`longPoll` calls in `src/index.ts`, `bun/server.ts` | scratch `STRUCTURAL: one party's slot-flood cannot evict the other party's delivery waiter` | **SOUND** |
| **No duplicate delivery / no misdelivery across mailboxes.** `wake` calls `drain` (empties the list) before handing off; an item leaves the queue exactly once. Waiters are per-mailbox-per-slot, so a deposit can only ever reach one of the two legitimate parties' connections. | `drain` (`protocol.ts:217`), `wake` (`protocol.ts:325`) | reviewed by inspection (drain-empties invariant); Bun/Worker `deposit and drain` | **SOUND** |

### Findings (ranked)

**No P0 or P1.** The change is a net improvement: it removes the fast-empty
hammer and introduces no new loss vector relative to the prior design (the old
evict-all design *also* delivered to the newest/only waiter, so it lost in
exactly the same "newest waiter is dead" case, see below).

**P2, the two "still open" residuals are one root cause, and honestly stated
but slightly over-decomposed.** Both open residuals in the module header reduce
to a single invariant: *`wake` loses a deposit iff the newest waiter is a dead
orphan at deposit time* (drained into a connection nobody reads).
- *Residual A (deposit in the disconnect gap):* reachable by the shipped clients
, a real disconnect whose abort didn't fire, then a deposit landing before the
  reconnect re-attaches. Proven real by the scratch `RESIDUAL IS REAL…` test.
  This is genuine, bounded (one delivery, requires an actual disconnect plus
  unlucky timing), fail-closed (a lost approval request or response just means
  no secret is released), and is what client-side resend must cover regardless.
  Correctly tracked as **task #53** (verify/mitigate at a real Cloudflare deploy).
- *Residual B ("newer connection dies while older lives"):* the header presents
  this as a second, distinct residual. **It is not reachable by any shipped
  client**, because both are strictly single-flight per slot (see row 1): they
  never hold two genuinely-live overlapping polls on one slot, so the newer of
  two coexisting waiters is never the dead one. It becomes reachable only for a
  hypothetical *future* concurrent/multi-poll client. Recommendation: keep it
  documented, but note explicitly that it is unreachable given today's clients,
  as written the README slightly overstates its current reachability (harmless
  direction: it over-warns, it does not under-warn).

**P2, MAX_WAITERS bounds per-slot waiters, not mailbox count (pre-existing,
unchanged by this commit).** `MAX_WAITERS=8` caps waiters at 16 per mailbox (8×2
slots). It does **not** cap the number of distinct mailboxes: the Bun `boxes`
Map grows one entry per distinct id seen, and the rate limiter is per-mailbox so
it does not bound distinct-id creation. An attacker who can reach the relay can
inflate the Map with random ids (each holding held GETs) until the sweep
(`TTL_MS`, only deletes idle+unwatched boxes) or the OS connection limit stops
it. The Worker variant offloads this to Cloudflare's isolate lifecycle. This is
the pre-existing "rate limiter is non-load-bearing; the front is the real bound"
posture, not a regression from v5.1, and acceptable for a personal/self-host
deployment, flagged so it is not mistaken for a bound this change added.

**Steal/eviction as a weapon, not reachable by a third party.** Forcing a
victim's legit waiter out (8 GETs past the cap) and positioning an attacker
waiter as newest to *steal* the next deposit requires registering GETs on the
victim's slot, i.e. knowing the `mailbox_id`. That id is
`BLAKE2b(domain ‖ canonical(pinned_pub_a, pinned_pub_b))` (`fingerprint.rs:83`),
a 256-bit value derived from two pinned public keys, carried inside TLS to the
relay and never published, unguessable by a third party. Only the relay
operator (who sees the id in the URL) is positioned to do this, and a hostile
relay can already deny delivery arbitrarily; the theft still yields only an
opaque sealed envelope and a non-approval (fail-closed). Acceptable; worth one
line in the module header that delivery-slot integrity rests on the mailbox id
staying unknown to third parties (it does).

**Verdict (independent security-reviewer, not the implementer of `33b464f`).
The v5.1 coexisting-waiter / newest-wins change is SOUND for delivery
integrity.** It removes the fast-empty hammer, adds no new message-loss vector,
cannot be used by one paired party to starve the other, is memory-bounded
per slot, and every worst case is a bounded, fail-closed non-delivery, never a
disclosure or a fail-open approval. The one client-reachable residual (deposit
in the disconnect gap) is real, honestly documented, and correctly deferred to
task #53 for real-edge verification plus client-side resend. Recommend two
documentation tightenings (both non-blocking): (1) mark residual B as not
reachable by today's single-flight clients rather than an open peer of residual
A; (2) note that slot-steal presupposes knowledge of the unguessable mailbox id.

## 21. The delivery receipt (task #41) + lease-window wire alignment

*Implementer note (behavior + residuals only; the verdict is the independent
security-reviewer's). This closes the daemon side of three phone-opened gaps.*

**A. Delivery receipt, a fourth-kind display-only inbound.** The phone seals a
`{ type: "delivered", requestId }` to the `ToDaemon` slot the instant it opens and
verifies an inbound request (`apps/phone/.../session.ts`). Daemon side:

- `sigil-proto` gains `DeliveryReceipt { message_type:"delivered", request_id }`
  and a `ToDaemonMessage::Delivered` variant. `ToDaemonMessage::from_value`
  classifies by the `type` tag: `"pushRegister"` -> `Push`, `"delivered"` ->
  `Delivered`, anything else (in practice its absence) -> `Response`. A `"delivered"`
  tag with no `request_id` fails the parse and the caller drops it (fail closed).
  An `ApprovalResponse` carries no `type`, so a receipt tag can never shadow a real
  decision, and a receipt carries no DEK/partial/lease, so it can never *be* one.
- The single `run_todaemon_owner` reader routes `Delivered` through the SAME one
  `classify`/`ReplayGuard` pass as every other inbound envelope, then calls
  `RemoteApprover::mark_delivered(request_id, now)`. It NEVER touches the waiter
  channel (`route_response`), so a receipt cannot deliver, forge, or short-circuit a
  decision. `mark_delivered` sets `delivered_at_ms` on the matching in-flight entry
  only if unset; an unknown/late (no entry) or duplicate (already set) receipt is a
  silent no-op. A replayed receipt is additionally rejected by the `ReplayGuard`
  (single-use request id), proven in `hostile_relay.rs::
  delivery_receipt_rides_the_sealed_signed_replay_protected_envelope`.
- **The receipt is display-only and NEVER changes gating.** It cannot move a
  decision, DEK, lease, or timeout; it only sets a boolean/timestamp the requester
  UI reads. A lost receipt leaves `delivered=false` ("couldn't confirm") while the
  approve/deny path resolves the request exactly as before.

**Surface (the DTO the Mac reads).** In-flight remote requests are now enumerated
onto the existing `pending` surface. `RemoteApprover`'s waiter map entry carries a
plaintext snapshot of its request (names/provenance only, never a secret) plus the
delivery state; `daemon.rs::pending_json` appends these under the phone factor.
`json::PendingJson` gains `delivered: bool` and `delivered_at_ms: Option<u64>`
(camel-free snake wire: `delivered`, `delivered_at_ms`). A `subscribe_pending`
client re-emits promptly because the approver bumps the shared `PendingRegistry`
version on request arrival, receipt, and completion (`PendingRegistry::
notify_change`, which resolves nothing and touches no waiter). Tests:
`remote.rs::a_delivery_receipt_marks_delivered_without_resolving_the_approval`,
`remote.rs::the_owner_routes_a_sealed_delivery_receipt_over_the_channel`,
`request.rs::to_daemon_message_classifies_a_delivery_receipt`.

**B. Lease response is a window, not a key (daemon is sole lease authority).**
`ApprovalResponse.lease` (proto `InstallLease`) dropped its `grant_key` field; it
is now `{ ttl_ms }` only, matching the phone's `lease?: { ttlMs } | null`. The
zero-knowledge phone picks only a window; nothing daemon-side ever trusted a
phone-supplied grant key (`remote.rs::outcome_for` reads only `lease.ttl_ms` and
maps it to `Decision::Lease(ttl)`; the daemon's own `lease::grant_key` over the
kernel-verified caller mints/binds the grant, and `LeasePolicy::clamp_secs`
enforces run-once => no lease / leasable => `min(requested, max_secs)`). This only
removed a field the daemon never read.

**C. `lease_policy` populated; `risk` already retired from the wire.**
`remote.rs::build_request` sets `ApprovalRequest.lease_policy` from the resolved
rule's policy (via `ApprovalContext.lease`), so the phone's "keep approved for N"
offer appears for leasable rules (`build_request_is_provider_blind` asserts it).
The proto `ApprovalRequest` already carries NO `risk` field (a prior change retired
the risk tier in favour of mode/lease); the only remaining `risk` in `crates/` is
`config.rs`'s deliberate read-and-drop of the legacy on-disk config key during
migration (not the wire), so nothing dead needed removing daemon-side.

**Residuals for the reviewer to weigh:**

- *Delivery state is best-effort and unauthenticated as to liveness.* A receipt is
  authenticated (sealed + signed + replay-guarded), so a hostile relay cannot forge
  a "delivered" the phone did not send; but its ABSENCE proves nothing (offline
  phone, lost deposit in the relay's TTL, dropped ack). The UI must treat
  `delivered=false` as "couldn't confirm", never as "not seen", and it MUST NOT gate
  on it. The generous display bound lives in the Mac UI, not the gate.
- *Remote pendings now appear in `pending`.* This is display enumeration only:
  `pending_json` reads a snapshot; the local control-socket `approve`/`deny` path
  (`core.pending.resolve`) still targets the LOCAL `PendingRegistry` and finds no
  entry for a remote `request_id`, so it cannot resolve a phone-gated request. The
  snapshot copies the (already non-secret) `ApprovalRequest`; no DEK/partial is ever
  in it.

**Phone follow-up (not in this change, for the phone-app owner):**
`apps/phone/src/protocol/requests.ts` still carries a residual `risk: RiskLevel`
on `ApprovalRequest` (and the `RiskLevel` type). It is now dead on the wire (the
daemon never sends it); drop both there to match.

## Independent review verdict: hot-reload + pairing biometric + delivery receipt + relay #53 (75932b0..518d28f)

*Written by the independent security-reviewer (did NOT implement any of this
code), per the review-integrity rule. Adversarial pass over commits `d916b2e`
(#59 hot-reload + one socket, #48 pairing biometric), `88545c3` (#41 delivery
receipt daemon side, lease-window wire alignment), and relay `a5efd0d` (#53
offer-then-drain). This section is the verdict the implementer notes in §21
(and the §14-16 notes) defer to.*

**Gate run (this reviewer, on HEAD 518d28f):** `cargo test` = **378 passed, 0
failed** across all crates; `cargo clippy --all-targets -- -D warnings` =
**clean** (no warnings); `cargo fmt --check` = **clean**. Relay: worker vitest
(`test/worker.test.ts`) = **18 passed**; bun (`bun/server.test.ts`,
`shared/push.test.ts`, `shared/protocol.test.ts`, `longpoll-adversarial.test.ts`)
= **40 passed across 4 files, 0 fail**. Em-dash/emoji scan of every added line in
`crates` and `relay` (including `landing.html` and `README.md`): **none**.

**Overall verdict: GREEN. No P0/P1/P2 findings. Ship-clear on these three
changes.** Every adversarial item below verified sound against the code, not the
implementer notes. The residuals are pre-existing, honestly documented, and
fail-closed.

### #59 config hot-reload + one authoritative socket, GREEN

- **Fail-closed swap: GREEN.** `Core::reload_config` (`daemon.rs:341`) reaches
  `ConfigCell::store` ONLY on the `Ok(cfg)` arm of `Config::load()`; the `Err`
  arm returns the error string WITHOUT touching the cell, so a malformed,
  truncated (half-written save), or unreadable file leaves the last-good `Arc`
  in force. It never falls open and never downgrades to refuse-all, it keeps
  exactly what last parsed. Proven by
  `config_reload_is_fail_closed_on_a_malformed_file` (corrupts `config.json`,
  asserts `op` still gates after the failed reload) and
  `config_hot_reload_swaps_in_the_on_disk_rules`.
- **Torn-read safety: GREEN.** `ConfigCell` is `RwLock<Arc<Config>>`. A gating
  decision takes `snapshot()` (`daemon.rs:1144`), read-lock, clone the `Arc`,
  unlock, and evaluates the entire `resolve` against that one pinned `Arc`. A
  concurrent `store()` write-swaps a *new* `Arc` and drops the caller's
  reference to the old one only when the last snapshot holder releases it. A
  reload landing mid-`resolve` is therefore invisible: whole-old or whole-new,
  never a blend. The watcher thread is the sole writer.
- **Socket: GREEN.** The default runtime dir resolves from
  `confstr(_CS_DARWIN_USER_TEMP_DIR)` (`local.rs::darwin_user_temp_dir`), the
  OS-provided per-user temp dir (`/var/folders/.../T/`), not the
  attacker-strippable `$TMPDIR` env var, this is a *reduction* in attack
  surface versus the prior `$TMPDIR` derivation, which an attacker could
  override to redirect the bind. `prepare_socket` still forces the parent dir
  0700 (`daemon.rs:822`) and both sockets 0600 (`daemon.rs:620,629`);
  `service::socket_path_fits()` still guards `sun_path` length and is asserted in
  `daemon_and_ssh_sockets_share_one_authoritative_runtime_dir`. `SIGIL_SOCK` /
  `SIGIL_SSH_SOCK` remain full-path overrides; pointing a *client* elsewhere
  requires already controlling the victim's environment (a pre-existing
  compromise at which the secret is directly interceptable), and pointing the
  *daemon* elsewhere requires controlling its launch, neither is a new lever.

### #48 pairing biometric gate, GREEN

- **First action in the single chokepoint, deny-closed: GREEN.**
  `pairing_store::save` (`pairing_store.rs:169`) runs
  `if ks.is_biometric() { ks.verify_presence(PAIRING_PRESENCE_REASON)? }` as
  step 0, before the identity blob seal (step 1) and the config write. A decline
  returns `Err` and NOTHING is written, proven by
  `a_declined_biometric_refuses_the_pairing_and_writes_nothing` (asserts no
  config file, no identity blob). `save` is the only writer of
  `DAEMON_IDENTITY_LABEL`; both production callers (`cli.rs:1392,1503`) route
  through it and each runs `ensure_dek()` first, so the SE DEK envelope
  `verify_presence` exercises exists.
- **Trait default is `Err`: GREEN.** `Keystore::verify_presence`
  (`keystore.rs`) defaults to `Err(Backend(...))`; a keystore that reports
  `is_biometric() == true` but omits the override fails closed at the gate.
  Proven by `a_biometric_keystore_missing_a_verify_presence_override_fails_closed`.
- **Real hardware check: GREEN.** `MacKeystore::verify_presence`
  (`keystore_macos.rs`) performs the same `SecKeyCreateDecryptedData` SE
  private-key op (`.biometryCurrentSet`) the approval unwrap uses, purely as a
  presence probe, and drops the recovered `Zeroizing` DEK immediately, no DEK
  crosses any boundary. The dev bypass is reachable only when
  `is_biometric() == false`, which only `SIGIL_DEV_KEYSTORE` (behind its own
  loud warning) produces; the gate simply never calls `verify_presence` in that
  case. Residual: on-hardware Touch ID actually *firing* is UNPROVEN statically
  (shares the §6 NEEDS-VERIFICATION residual; Tom's device checklist covers it).
  Not a code finding.

### #41 delivery receipt, GREEN (highest-risk new inbound; verified hardest)

- **(a) Never mistaken for / never resolves a decision: GREEN.**
  `ToDaemonMessage::from_value` classifies strictly by the `type` tag:
  `"delivered"` -> `Delivered`, `"pushRegister"` -> `Push`, else -> `Response`.
  An `ApprovalResponse` carries no `type`, so a receipt tag cannot shadow a
  decision, and `DeliveryReceipt` carries no DEK/partial/lease so it cannot *be*
  one. In the owner loop, `Delivered` dispatches ONLY to `mark_delivered`
  (`remote.rs:508`) and never touches `route_response`/the waiter `tx`. Proven
  by `a_delivery_receipt_marks_delivered_without_resolving_the_approval`
  (waiter channel stays `Empty`).
- **(b) Forge/tamper/replay rejected: GREEN.** `Delivered` rides the identical
  seal/sign/replay path via the single `classify` -> `Envelope::open` ->
  shared `ReplayGuard` pass. `hostile_relay.rs::
  delivery_receipt_rides_the_sealed_signed_replay_protected_envelope` proves a
  ciphertext bit-flip -> `BadSignature` (no forge) and an exact-bytes replay ->
  `Replay(DuplicateRequest)` (no re-mark). A hostile relay cannot fabricate one.
- **(c) Cannot desync the shared ReplayGuard: GREEN.** [Mechanism corrected
  under task #67: the monotonic-counter gate is retired; the guard is now
  freshness + single-use id, see the #67 verdict below.] The guard is consumed at
  envelope-open, before classification, identically for every inbound kind. A
  `Delivered` records its uuidv7 in the seen-set exactly as a `Response` would;
  there is no counter to regress, and reordering two *distinct* inbound envelopes
  no longer rejects either (each has its own id). A replayed `Delivered`
  (identical bytes) is still rejected as `DuplicateRequest`, and a held-late one
  by freshness, so it can never re-mark delivery. `mark_delivered` is
  additionally idempotent (sets `delivered_at_ms` only when unset;
  duplicate/unknown/late = no-op), so even a would-be re-delivery is a no-op.
  Fail-closed either way.
- **(d) `pending` surface is display-only; no local-approval bypass: GREEN.**
  Remote in-flight requests are enumerated onto `pending_json` from
  `RemoteApprover::pending_snapshot` (names/provenance only, an
  `ApprovalRequest` never carries a secret value). The control `Approve`/`Deny`
  frames call `core.pending.resolve` (`daemon.rs:885,896`), which targets the
  LOCAL `PendingRegistry`; a phone-gated request lives in the RemoteApprover
  `waiters` map, not there, so `resolve` returns false ("no pending request with
  that id"). The control socket is moreover only wired under
  `Factor::DevInsecure`, not `Factor::Phone`. No new path lets a local
  `approve/deny` resolve a phone-gated `request_id`.

### lease-response wire (daemon sole lease authority), GREEN

- **GREEN.** `InstallLease` lost its `grant_key` field entirely (proto struct is
  `{ ttl_ms }`); no code can trust a phone-supplied key because the field no
  longer exists. `remote.rs::outcome_for` reads only `lease.ttl_ms` ->
  `Decision::Lease(ttl)`. In `fulfill`, the daemon mints the grant key itself
  from the kernel-verified caller (`lease::grant_key(&caller, cwd, &scope)`,
  `daemon.rs:1208`) and clamps via `action.lease.clamp_secs`
  (`daemon.rs:1354`): run-once -> `None` -> no lease; leasable ->
  `min(requested, max_secs)`. A hostile approver cannot widen a lease past the
  rule cap nor convert run-once to a lease, the per-rule policy is re-enforced
  daemon-side regardless of what the phone returns. `leasable_rule_clamps_an_
  over_cap_lease_to_the_rule_max` and the run-once tests cover it. The softphone
  now sets only `ttl_ms`.

### relay #53 offer-then-drain, GREEN (residual judged acceptable)

- **GREEN.** `wake` (`protocol.ts:365`) now offers `list.map(i => i.blob)` and
  empties the buffer (`list.length = 0`) ONLY after a waiter returns `true`
  (was live/unsettled). A settled waiter returns `false` (`longPoll`'s waiter
  closure guards on `settled`), leaving every `Item` in place with its ORIGINAL
  `exp`, no TTL reset, no reorder, no drain-into-void for a waiter whose death
  we can observe. `MAX_WAITERS` (8), coexisting-waiters, and newest-wins
  (`waiters.pop()`) are intact; the drop-oldest-at-cap path resolves with `[]`
  on a provably-empty slot. The `Waiter: (blobs) => boolean` contract has no
  double-resolve (the `settled` latch) and no settled-but-registered drain
  beyond the documented silent-orphan case.
- **Residual (silent disconnect orphan): ACCEPTABLE, no fix required now.** A
  connection that dies WITHOUT its abort signal firing is not `settled`, so it
  still accepts the offer and the one queued deposit drains into the void. This
  is **fail-closed**: the lost delivery makes the daemon time out and *deny*, it
  never releases a secret. It is bounded by the sender's poll backstop and the
  180s item TTL, requires an actual silent disconnect on top of unlucky timing,
  and is unreachable by any shipped client (both are strictly single-flight per
  slot). For a single-user personal instrument this does not warrant the
  at-least-once/wire-receipt path yet; the module header documents it honestly
  and flags confirming edge abort-signal behaviour on a real Cloudflare deploy.
  Judged acceptable.

### Cross-cutting invariants, GREEN

Daemon-at-rest inert (config hot-reload swaps rules only; no token/DEK involved),
secret-bytes-never-in-daemon-memory (the receipt and the `pending` snapshot carry
references/labels/provenance, never a secret value), relay
powerless/anonymous (no key-distribution role added; the receipt is opaque
ciphertext to the relay), and zero em-dash/zero emoji in user-facing strings all
hold across these diffs.

## Independent review verdict: #36 resolution broadcast + #51 direct transport (merged `feat/config-rule-engine` @ `f842e0d`)

*Written by the independent security-reviewer (did NOT implement any of this
code), per the review-integrity rule. Adversarial pass over commits `ea473fc`
(#36 resolution-broadcast wire + phone dismissal) and `db2f9e7` (#51 direct
transport rungs 1-2, new crate `crates/sigil-direct`). Both features are
ADDITIVE and DORMANT: neither is wired into the shipping approval/serve path, so
the review's first job was to confirm that, then to confirm no latent flaw can
bite once deliberately enabled.*

**Gate run (this reviewer, on HEAD `f842e0d`):** `cargo test` = **401 passed, 0
failed, 7 ignored** across all crates (233 sigil-core, 90 sigil-proto, 18
sigil-direct, plus proto/relay-client/softphone integration + doctests);
`cargo clippy --all-targets -- -D warnings` = **clean**; `cargo fmt --check` =
**clean**. Em-dash (U+2014) / en-dash (U+2013) / emoji scan of every added line
in both commits: **none**.

**Overall verdict: GREEN. No P0/P1/P2 findings. Ship-clear, and, more to the
point, dormant, so nothing here can affect the shipping path until an operator
deliberately wires it.** Every scope item verified sound against the code, not
the implementer notes.

### Dormancy, CONFIRMED for both features

- **#36 `broadcast_resolution` is dormant: CONFIRMED.** `grep` across `crates`
  and `apps` finds exactly one definition (`remote.rs:466`) and callers ONLY in
  its own unit test (`remote.rs:890`). The production `serve` path and the
  ToDaemon owner loop never call it; `build_gate` (`daemon.rs:197-246`, the sole
  production approver wiring) constructs a `RemoteApprover` and never invokes any
  resolution broadcast. No `RingApprover` / ring coordinator exists yet (deferred
  with design in `docs/design/multi-device.md`). The wire type, the daemon seal
  method, and the phone `dismissResolved` handler are all present and tested but
  reachable only when a future ring coordinator calls them.
- **#51 direct transport is dormant/OFF by default: CONFIRMED.** `grep` for
  `sigil-direct` / `sigil_direct` / `DirectLink` / `FallbackTransport` /
  `verify_link` finds ZERO references outside `crates/sigil-direct/` itself. The
  crate is a workspace member (so it compiles and is tested) but is a dependency
  of no other crate, not `sigil`, not the phone. Production `build_gate`
  (`daemon.rs:219`) wires `RemoteApprover::new(Arc::new(relay), …)` on a raw
  `DaemonRelay`, never a `FallbackTransport`; no primary is ever installed and
  the relay remains the sole transport. The phone `LadderTransport` is likewise
  imported nowhere in the shipping session wiring.

### #36 resolution broadcast, GREEN (per scope item)

- **(a) Sealed + signed + replay-protected; a hostile relay can neither forge
  nor replay a dismissal: GREEN.** `ResolutionBroadcast` rides the identical
  `Envelope::seal`/`open` path as every other message (crypto_box to the phone's
  pinned agreement key, Ed25519 signature over all fields, single-use request id,
  per-pairing monotonic counter, timestamp window). Proven by
  `hostile_relay.rs::resolution_broadcast_rides_the_sealed_signed_replay_protected_envelope`:
  a stranger's agreement secret fails `Decrypt`; a ciphertext bit-flip fails
  `BadSignature`; a forge from an unpinned key fails `BadSignature` (the phone
  still pins the daemon); the exact bytes replayed fail
  `Replay(DuplicateRequest)`. The daemon-side seal is re-proven end-to-end in
  `remote.rs::broadcast_resolution_deposits_a_sealed_dismissal_the_phone_can_open`,
  including the replay rejection on the phone's guard.
- **(b) Worst a hostile relay can do is withhold/delay; never a release, never
  an approval: GREEN.** The type carries only `{request_id, status}`, no DEK, no
  Z_F, no decision detail (`ResolutionStatus` deliberately does not say approve
  vs deny). A dropped/delayed broadcast degrades to single-device behavior: the
  loser device's own request timeout still expires the sheet
  (`broadcast_resolution` doc + `deposit_and_wait` fail-closed timeout). A
  (cryptographically impossible) forged-but-valid one at most hides a prompt,
  which withholds a release, it can never cause one, because the phone's
  `dismissResolved` records a neutral outcome and touches no key.
- **(c) Touches no waiter channel, no ReplayGuard, no DEK/Z_F: GREEN.**
  `broadcast_resolution` (`remote.rs:466-484`) shares only the daemon->phone
  `counter` and `Envelope::seal`, exactly like a request deposit. It registers no
  waiter (no `waiters` map mutation), locks no `guard` (that guards the inbound
  ToDaemon direction; this is an outbound ToPhone deposit), and never constructs
  or reads a DEK or partial. A seal/transport error is swallowed (best-effort),
  which is safe precisely because it gates nothing.
- **(d) Phone `dismissResolved` records a zero-knowledge neutral entry and
  cannot release anything: GREEN.** `store.ts::dismissResolved` no-ops on an
  unknown or already-terminal request (`approved`/`denied`/`expired`), then
  records `"superseded"` (or `"expired"` for an expiry), never `approved`/
  `denied`. `HistoryEntry.decision` is widened to `Decision | "expired" |
  "superseded"`; `RequestState` gains a terminal `"superseded"`. It carries no
  DEK path and cannot transition a request into an approve. `classifyToPhone`
  fails closed: a `"resolution"` tag with a missing/blank `requestId` or an
  out-of-set `status` returns `null` and the caller drops it. `handleInbound`
  opens the envelope ONCE to a raw payload (crypto verified regardless of shape),
  then demuxes, so a resolution rides the same signature/replay/decrypt gate as
  a request, and is never acknowledged with a delivery receipt.
- **Wire-shape stability: GREEN.** `ToPhoneMessage::from_value` uses a
  hand-rolled `type`-tag peek (not `#[serde(untagged)]`), so the untagged
  `ApprovalRequest` wire shape is byte-for-byte unchanged and the pinned vectors
  / pairing transcript do not shift. Mirrors the audited ToDaemon demux.

### #51 direct transport, GREEN (per scope item)

- **(a) Carries only opaque sealed envelopes; a rogue LAN/TCP peer's frames fail
  `Envelope::open` and are dropped: GREEN.** `DirectLink` frames the exact
  `serde_json` envelope wire the relay uses (`wire::{envelope_to_wire,
  wire_to_envelope}`), authenticates nothing, decrypts nothing, grants nothing
  (module doc + `tcp.rs`). Every frame is still opened by `Envelope::open` at the
  unchanged `RemoteApprover`/phone call site. A frame that does not even decode to
  an `Envelope` is dropped while framing stays synchronised (`read_loop` consumes
  exactly `len` bytes); one that decodes but is not sealed to the pinned peer
  fails `open` downstream. No plaintext and no new network trust.
- **(b) `FallbackTransport` with no primary is byte-identical to the relay:
  GREEN.** With `primary == None` (the default and the post-failure state),
  `send`/`deposit_to_phone`/`recv` delegate straight to the relay with no added
  behavior (`fallback.rs` + `with_no_primary_it_is_exactly_the_relay`). Spoofing
  or withholding mDNS cannot affect a daemon with no installed primary, because
  discovery is never consulted on the transport path.
- **(c) A primary is installed only after `verify_link` opens an envelope as the
  pinned peer; a TCP-only imposter fails closed: GREEN.** `verify_link`
  (`discovery.rs:127`) reads exactly one envelope off the dialled link and demands
  the caller-supplied predicate (wired to the same `Envelope::open` against the
  pinned peer key) accept it; otherwise `NotPinnedPeer` / `Timeout`, and the link
  is never installed. `install_primary` doc-contracts that the caller MUST have
  verified first. Proven by `verify_link_rejects_an_envelope_the_predicate_denies`
  and `verify_link_times_out_when_nothing_arrives`. The mDNS `ServiceRecord.hint`
  is explicitly a non-secret dial discriminator, never the mailbox id, never
  trusted.
- **(d) Downgrade safety, active LAN MITM is at worst a one-timeout
  fail-closed denial, never a forge/leak: GREEN (with a named residual).** A MITM
  can complete a TCP handshake and relay the phone's genuine verification envelope
  to get promoted, then black-hole traffic. The consequence is a `recv`/`send`
  error that retires the primary (`retire_if_current`, guarded by `Arc::ptr_eq`
  so a concurrent fresh install is not clobbered) and spends the remaining budget
  on the relay; if it black-holes silently within a single window the approval
  times out and fails closed. It cannot forge a request/response (envelope) or
  read a secret. The residual (a `PreferDirect` deposit black-holed by an active
  MITM costs one timeout before the demote-on-silence retry, which lives in the
  not-yet-landed owner-loop change) is the reason the crate ships OFF; it is
  documented in `docs/design/direct-transport.md` and inherits the fail-closed
  floor. `Mirror` policy removes even the one-timeout delay at the cost of always
  touching the relay.
- **(e) Fail-closed on drop/truncation/over-cap; rung-2 listener at-rest
  inertness: GREEN.** `MAX_FRAME_BYTES` (64 KiB) caps a declared frame length
  before allocation; an over-cap length, an unknown direction byte, EOF, or a
  truncated read all break `read_loop` and `shared.close()` (latched, never
  cleared), which `shutdown(Both)` propagates so both ends fail over together.
  `recv` drains buffered frames first, then surfaces `Closed`
  (`buffered_frames_survive_a_close_and_are_delivered_before_the_error`). A
  non-UTF8 or undecodable-but-length-valid frame is dropped while the link stays
  synchronised. `DirectListener::accept` hands back an explicitly UNVERIFIED link;
  at rest it holds no keys and grants nothing until `verify_link` promotes it.
- **(f) OFF by default, relay remains default: GREEN.** Covered under Dormancy
  above, no crate depends on `sigil-direct`, and `build_gate` wires the raw
  relay.

### Cross-cutting invariants, GREEN

Daemon-at-rest inert (neither feature holds a token/DEK; the resolution broadcast
and the direct link carry only opaque ciphertext), secret-bytes-never-in-daemon-
memory (a `ResolutionBroadcast` is `{request_id, status}`; a `DirectLink` frame is
an opaque `Envelope` never parsed for secret material), relay powerless/anonymous
(no key-distribution role added, the mDNS record is untrusted and the envelope
layer is the sole trust boundary), fail-closed everywhere (verify gate, drop/
truncation, timeout, unknown tag), and zero em-dash / zero emoji in user-facing
strings all hold across these diffs.

## Independent review verdict: native Rust blind relay `crates/sigil-relay` (merged `feat/config-rule-engine` @ `4b771f2`)

**Written by the security-reviewer, which did NOT author `crates/sigil-relay`**
(rust-core / relay, `4b771f2`); per the review-integrity rule this is an
independent verdict, not a self-certification. Scope: the from-scratch
tokio/hyper reimplementation of the blind relay SERVER (the clients
`crates/sigil-relay-client` and `apps/phone/src/transport/relay-http.ts` are
unchanged), reviewed against the TS originals it replaces (`relay/shared/
protocol.ts`, `relay/shared/push.ts`, `relay/src/index.ts`) and against what the
real clients send/expect. Gate run at `4b771f2`: `cargo test -p sigil-relay` =
**23 passed** (18 integration + 5 push, plus 8 protocol unit tests in the lib
build), `cargo clippy -p sigil-relay --all-targets -- -D warnings` = **clean**,
`cargo fmt -p sigil-relay --check` = **clean**.

**Overall: GREEN with one P2 availability-only hardening note. No P0/P1. No
confidentiality or integrity finding; every failure path fails closed (a lost or
denied delivery, never a wrong/duplicate delivery, a cross-mailbox/cross-direction
leak, or an ungated release).**

### Per-item verdict

| # | Property | Verdict |
|---|----------|---------|
| 1 | Powerlessness / anonymity / zero persistence | **GREEN** |
| 2 | Wire-compat exact (routes, methods, statuses, byte shapes, constants) | **GREEN** |
| 3 | offer-then-drain wake (#53 v5.2): newest-wins, drop-oldest, no lock across await | **GREEN** |
| 4 | APNs ES256 JWT signing + fail-safe caching, key never logged | **GREEN** |
| 5 | Knock modes + `POST /knock`: opaque-only, stores nothing, no amplifier/SSRF | **GREEN** |
| 6 | Rate limiting under a hostile peer; disjoint per-direction waiter lists | **GREEN** (see P2) |
| 7 | Fail-closed, no panic-DoS on malformed input, zero em-dash/emoji user-facing | **GREEN** |

**1. Powerlessness / anonymity / zero persistence: GREEN.** No code path reads,
parses, hashes, or branches on envelope contents. `parse_to_phone` / `parse_env`
(`server.rs`) extract only `env` (moved as an opaque `String`) plus the doorbell
`pushToken`/`platform`; `enqueue`/`drain`/`wake` (`protocol.rs`) move the String
verbatim. State is a single in-memory `HashMap<mailbox_id, Arc<Mutex<Mailbox>>>`
(`server.rs::AppState`); grep confirms no `std::fs` write, no DB, no `ctx.storage`
analogue anywhere. A restart drops all mailboxes, exactly as the short TTL would.
Routing is by the URL mailbox id (shape-checked by `valid_id`), never by envelope
content.

**2. Wire-compat exact: GREEN.** Verified field-by-field against `relay/src/
index.ts` and both real clients (`http.rs::{deposit,poll_slot}` sends
`{"env",..,"pushToken"?,"platform"?}` and reads `{"envelopes":[...]}`;
`relay-http.ts` the same). Routes `GET /`, `GET /health`, `GET|POST /mailbox/{64-hex}/
to-phone|to-daemon`; invalid id and unknown top-level path both 400 `bad_mailbox`;
unknown verb / unsupported method rate-checks then 404 `not_found`, matching the
TS order (rate-check precedes routing, exactly one increment per request).
Statuses 200/400/413/429/507/404 map identically; `QueueFull -> 507
INSUFFICIENT_STORAGE`, `TooLarge -> 413`. Response bytes are typed structs so
serde emits byte-exact field order (`{"ok":true,"service":"sigil-relay"}`,
`{"ok":true}`, `{"envelopes":[...]}`, `{"ok":false,"error":".."}`), asserted by
`protocol.rs::response_bodies_match_the_ts_wire_bytes`. All constants match the TS
(`TTL_MS 180000`, `MAX_QUEUE 32`, `MAX_ENVELOPE_BYTES 16384`, `LONG_POLL_MS 25000`,
`MAX_WAITERS 8`, `RATE_MAX 60/60000`, `PUSH_MAX 5/60000`). `GET /version` and
`POST /knock` are ADDITIVE endpoints absent from the TS variants; no shipping
client depends on them for the message path, so they cannot break a live client.
One deliberate, non-breaking hardening: a hard `MAX_BODY_BYTES` (`Limited`) read
cap the TS delegated to the runtime/content-length; it converges for legitimate
traffic (env <= 16 KiB + tiny wrapper < 20 KiB) and is only stricter on abuse.
Retry-After is absent on 429 in both implementations; the client treats its
absence as "back off" (`relay-http.ts::parseRetryAfter(null) -> null`), so no
divergence.

**3. offer-then-drain wake: GREEN.** `protocol.rs::wake` offers the still-queued
blobs to the newest waiter (`waiters.pop()`) and drains (`list.clear()`) ONLY on a
positive accept; a rejecting (settled/dead) waiter leaves every `Item` untouched
(same `exp`, no TTL reset, no reorder) and the loop tries the next-newest, else
leaves the queue for the next GET. The accept/reject signal is the oneshot
`send().is_ok()` in `server.rs::poll`. `MAX_WAITERS` drop-oldest
(`waiters.remove(0); oldest.offer(&[])`) only ever evicts within the same slot and
resolves the evicted waiter empty against a provably-empty queue. No lock is held
across an await: the mailbox `MutexGuard` lives only inside the synchronous `let rx
= { .. }` block; the `tokio::select!` awaits with no guard held; the timeout branch
re-locks. `WaiterGuard::drop` reaps the waiter on a mid-poll client disconnect. The
same-tick loss window (a silent disconnect whose abort never fires, deposit landing
in the gap before any reconnect) is the documented #53 orphan-gap residual: it
fails CLOSED (one delivery lost, recovered by the sender's poll backstop + item
TTL), never a wrong or duplicated delivery, never a cross-mailbox or cross-direction
leak. The two directions are disjoint `Vec<Waiter>`s, so a flood on one slot cannot
evict or steal the paired party's waiter on the other. Ported adversarial unit
tests (`residual_newest_silently_dead_...`, `hardened_newest_settled_dead_...`,
`newest_wins_delivers_to_the_live_reconnect`, and the HTTP-level
`deposit_survives_disconnect_then_reconnect`) all pass.

**4. APNs ES256 JWT signing + caching: GREEN.** `push.rs::bearer` signs
`base64url(header).base64url(claims)` with p256 `SigningKey` (RustCrypto,
RFC6979-deterministic) and emits `sig.to_bytes()` = raw 64-byte `r||s`, exactly
JWS ES256; header `{"alg":"ES256","kid":"5PCK76SDBA"}`, claims
`{"iss":"53W966FBFP","iat":<now/1000>}`. `tests/push.rs::rings_a_real_es256_jwt_...`
mints against a throwaway key and cryptographically verifies the signature,
header, claims, topic (`works.rainn.sigil`), and fixed doorbell body. The key is
resolved from `APNS_KEY_P8` / `APNS_KEY_P8_PATH` (`lib.rs::resolve_apns_key`) and
is never logged: every `eprintln!` carries a decode-error Display (no key bytes),
a status, or a token-free message; the token goes only into the `/3/device/{token}`
URL, never a log line. The JWT cache (`JWT_CACHE: Mutex<Option<Cached>>`) fails
safe: a poisoned lock on the read path returns an error that `ring_apns` logs and
swallows (no push, poll backstop); the write path skips caching but still returns
the fresh JWT, so it degrades to re-signing, never blocks delivery and never
serves a stale/wrong token. Every push failure is best-effort: `ring_apns` and
`send_push_direct` return `()` and are `tokio::spawn`ed detached from the deposit
response, so a push outcome can never block or alter message delivery (the 200 is
already returned).

**5. Knock modes + `POST /knock`: GREEN.** `direct` signs+sends locally; `upstream`
forwards `{opaque_token, mailbox_hash, platform}` only (`push.rs::forward_knock`),
never any `env`/message content; `off` and a `direct`-with-no-key both no-op and
fall through to the client poll (fail-open doorbell, correctness intact).
`/knock` accepts only `opaque_token` + `mailbox_hash` (`valid_id`-checked) +
`platform`, rate-limits on the tight per-mailbox `push_ok` (5/min), stores
nothing, and returns `{"ok":true}`. No SSRF/amplifier: `KNOCK_UPSTREAM` is an
operator-set env var (never attacker-supplied at request time), so the forward
target is fixed; a hostile peer can at most trigger one rate-limited forward per
knock. The upstream-trust note is documented honestly in `push.rs` (an upstream
knock relay learns only the opaque token and that *some* mailbox has traffic; it
cannot read, forge, or attribute).

**6. Rate limiting under a hostile peer: GREEN (one P2 note below).** Fixed-window
`rate_ok` / `push_ok` are per-mailbox, in-memory, non-load-bearing (clients verify
everything); the classic 2x fixed-window boundary burst is documented and
harmless. Waiter lists are disjoint per direction, so a flood is self-DoS and
cannot evict/steal the other party's waiter. Addressing any mailbox at all
presupposes the 256-bit mailbox id (BLAKE2b of both pinned keys, carried only
inside TLS); an outsider who does learn one and races the phone's poll still
cannot read or forge the sealed+signed envelope, and the intended party recovers
via replay/backstop, so a stolen delivery is a denial, never a leak.

**7. Fail-closed / no panic-DoS / no em-dash-emoji: GREEN.** Every parser is
`Option`-returning with no indexing panic: `valid_id` (len+byte range), the
serde `as_object`/`as_str` chains in `parse_env`/`parse_to_phone`/`knock`,
`content_length` (parse-error -> None), `read_body` (`Limited` cap -> None ->
413), `now_ms` (`unwrap_or(0)`). Response construction never panics
(`serde_json::to_vec(..).unwrap_or_else(|_| b"{}")`; `.expect` only on a static
status+header). A poisoned mailbox lock recovers the guard rather than panicking
mid-request (`server.rs::lock`). Fuzzing the inputs mentally (bad/short/long
mailbox id, oversized/short/empty/non-JSON body, missing `env`, weird verb,
unsupported method, non-numeric content-length) yields only the correct 400/404/
413 status, never a crash. User-facing strings hold invariant #6: all error codes
are ASCII snake_case, `relay/landing.html` has zero non-ASCII bytes, the
`/version` body is ASCII. (Informational, not a violation: one em-dash exists at
`push.rs:188`, but it is inside a `///` doc comment, i.e. source, not a
user-facing string; flagged only because the repo runs an aggressive em-dash
sweep and may want it changed for consistency.)

### P2 (availability-only hardening) - unbounded mailbox-map growth under a distinct-id flood

`server.rs::AppState::get_box` inserts a new `Arc<Mutex<Mailbox>>` for ANY
shape-valid 64-hex id, and shape-validity requires no secret (any 64 hex chars
pass `valid_id`). An unauthenticated remote peer can therefore mint arbitrarily
many distinct mailbox entries by hitting `/mailbox/<random-64-hex>/to-daemon`
(a deposit leaves a TTL-lived `Item`) or `/knock` (creates the entry just to hold
the push counter); the per-mailbox rate limiter does not bound the number of
DISTINCT mailboxes, and the idle-sweep only reaps every `TTL_MS` (180 s), so the
map can grow to ~180 s of request volume before reclamation. Held long-poll GETs
similarly accumulate open connections (25 s each). This is availability-only: it
touches no secret, causes no wrong/duplicate/cross-mailbox delivery, and OOM/fd
exhaustion fails CLOSED (a dead relay denies, never releases). It also mirrors an
architectural property of the TS variant, where Cloudflare's per-name Durable
Object model + edge DDoS protection mask it; the native single-process binary,
sold as "safe to run wide open," concentrates it in one heap with no such
backstop. Recommend (not blocking): a global cap on live mailboxes and/or
concurrent held connections that refuses NEW mailbox creation past the cap (fail
closed) while leaving established pairings' existing entries untouched, plus the
usual reverse-proxy connection/rate limits in the deploy guide. Severity P2:
worth closing before a wide public deploy, but no invariant is violated and no
change is required to land the crate.

### Cross-cutting invariants, GREEN

Relay powerless/anonymous (opaque envelopes, key-hash mailboxes, opaque push
token, no key-distribution role), zero persistence (in-memory only, gone on
restart), everything fails closed (denial never release; a push failure is
best-effort and detached), and zero em-dash / zero emoji in every user-facing
string (errors, landing, version) all hold for this crate.

---

## Independent review verdict: #36 multi-device core + #64 APNs identity env-sourcing (`3a18d17`, `ed5c4b6`, merged @ `afadede`)

*Written by the independent security-reviewer, who did NOT implement any of this
change (review-integrity rule). The implementer's record is
`docs/design/multi-device.md`; its residual list was treated as a set of claims
to break, not to trust.*

**Gate:** `cargo test --workspace` PASS (sigil-core 243, hostile_relay 18,
pairing_mitm 26, sigil-relay 12, relay integration 18, relay push 8,
relay-client 13, softphone 3, sigil-proto 18, plus the crates that report per
binary; 0 failed, 7 ignored). `cargo clippy --workspace --all-targets -D
warnings` PASS (0 warnings). `cargo fmt --check` PASS (clean).

**Overall verdict: GREEN. No P0/P1/P2 findings.** The multi-device approval core
is a genuine composition over N unchanged, previously-reviewed `RemoteApprover`s,
not a rewrite; every reviewed single-device guarantee is preserved by
construction, and the one new concurrency (loser cancellation + first-wins
commit) is correct: exactly one outcome reaches the gate per `decide`, and every
failure path denies. Two honest residuals are recorded below (both already known,
neither a release path). Held to the hostile bar.

### Primary scope (#36), per item

**1. N == 1 byte-identical: GREEN.** `build_gate` (`daemon.rs:241`) constructs a
bare `Arc<RemoteApprover>` for `devices.len() == 1` and only wraps a
`RingApprover` for N >= 2, so the common case never enters the ring coordinator.
The reviewed `RemoteApprover::round_trip` / `deposit_and_wait` /
`recv_timeout(self.timeout)` shape (`remote.rs:268-315`) is untouched by this
change; `round_trip_cancellable` is a *separate* method (option A per the design)
so no cancel check leaks into the single-device wait. `RingApprover::decide`
(`remote.rs:746`) also short-circuits N == 1 to `self.devices[0].decide(ctx)`, and
`pairing_store::load` returns `devices[0]` alone. Confirmed no behavior change for
one device.

**2. Cancellation correctness / exactly one outcome: GREEN.** The race is
serialized by `winner: Mutex<Option<(usize, ApprovalOutcome)>>` (`remote.rs:757`):
the first thread whose `round_trip_cancellable` returns `Some` finds the slot
empty, commits, and fires `cancel.cancel()`; any later thread that also returned
`Some` finds `w.is_some()` and drops its outcome (`remote.rs:770-778`). So even
when two phones both approve in the same tick, EXACTLY ONE outcome is returned to
the gate; the loser's `ApprovalOutcome` (DEK/`Z_F`) is dropped and zeroized,
never consumed, so there is no double-release and no two devices both releasing a
DEK. A dropped `ApprovalOutcome` releases nothing: the token decrypt/splice
happens only on the single value `decide` returns (`daemon.rs:535`, `1460`,
`1488`). A cancelled loser returns `None` within one `RING_CANCEL_TICK` (100 ms)
and `round_trip_cancellable` then calls `remove_waiter` (`remote.rs:337`), so a
late response for that device finds no waiter and is dropped by `route_response`
(`remote.rs:635`); the remove-vs-route ordering is itself serialized by the
`waiters` mutex, and in the losing branch the channel is never read, so a
late-but-real response can reach neither the gate nor a second commit. All threads
run in a `thread::scope` that JOINS before the winner slot is read
(`remote.rs:763-784`), so no loser outlives `decide`. All-timeout / all-`None`
leaves the slot `None` and returns `Decision::Deny` (`remote.rs:799`); the N == 0
guard also denies (`remote.rs:743`). Fail-closed confirmed. Proven by
`ring_first_wins_delivers_the_winners_dek_and_dismisses_losers`,
`ring_first_deny_wins_and_dismisses_losers`, `ring_all_timeout_denies`,
`ring_of_one_matches_the_single_device_path`.

**3. Broadcast-after-commit: GREEN.** The `Settled` broadcast loop runs only in
the `Some((idx, outcome))` arm, AFTER the scope has joined every device thread and
the winner slot is final (`remote.rs:783-795`); it can never race a still-running
approve. It is sent to every device EXCEPT the winner. `broadcast_resolution`
(`remote.rs:543`) seals a `ResolutionBroadcast` carrying only `request_id` +
`status` (no key material, no which-device, no approve/deny), rides the
daemon->phone monotonic counter and the pinned seal, registers no waiter, and
touches no `ReplayGuard`/DEK/`Z_F`. A forged/lost/replayed broadcast can only hide
or dismiss a prompt (withhold a release), never cause one; the phone verifies
signature + replay and a replay is rejected (proven by
`broadcast_resolution_deposits_a_sealed_dismissal_the_phone_can_open` and the
hostile-relay proof
`resolution_broadcast_rides_the_sealed_signed_replay_protected_envelope`). A seal
or transport error is swallowed and degrades to that phone's own timeout, never to
a release.

**4. Per-device replay isolation: GREEN.** `RingApprover` holds only
`Vec<Arc<RemoteApprover>>` and adds NO shared guard. Each `RemoteApprover` owns
its own `Mutex<ReplayGuard>` (`remote.rs:140`), its own monotonic `counter`, its
own pinned `phone` key, and its own `waiters` map. Devices have distinct mailboxes
(`mailbox_id(daemon_pub_i, phone_pub_i)`, distinct per pairing;
`add_device_is_additive_and_per_device_isolated` asserts `all[0].mailbox() !=
all[1].mailbox()`). A response sealed by phone B fails signature verification
inside device A's `classify`/`Envelope::open` against A's pinned phone key and is
dropped, so device A can never resolve device B's request nor pass B's replay
counter. Each device keeps its own single ToDaemon owner (`serve` spawns one per
device, `daemon.rs:694-704`), the sole reader of that mailbox.

**5. Storage migration windows: GREEN.** `add_device` (`pairing_store.rs:423`)
runs the #48 `gate_presence` FIRST (deny-closed, nothing written on decline;
proven by `add_device_gates_on_biometric_and_writes_nothing_on_decline`), then
seals the identity blob, then rewrites the container file: blob-then-file, so a
crash between leaves an ORPHAN blob (inert, referenced by no device row), never an
armed device without a pinned phone. `remove_device` (`pairing_store.rs:519`)
rewrites the file (row gone) BEFORE deleting the blob: file-then-blob, so a crash
leaves an orphan blob, never a dangling row pointing at a deleted identity. A pin
without an identity cannot arm: `device_to_config` fails LOUD
(`MissingIdentity`/`CorruptIdentity`) rather than arming without the keystore half
(`config_present_but_identity_missing_is_a_loud_error`). The v1->v2 migration
(`read_container` -> `from_v1`) is a pure in-memory read transform that keeps the
primary's `primary` sentinel + legacy keystore label and NEVER touches the
keystore; reads never rewrite (idempotent, crash-safe), and the rewrite defers to
the next mutating call (`a_v1_file_migrates_on_read`). The #48 gate also fires on
`save`. Confirmed no window with an armed-without-pin device or a pin without
identity.

**6. load_all fail-closed: GREEN.** `load_all` (`pairing_store.rs:469`) maps
`device_to_config` over every device and `.collect()`s into `Result<Vec, _>`,
which short-circuits on the FIRST error, so one half-broken device makes the whole
load fail. `load_remote_pairing` turns that error into an empty vector
(`daemon.rs:180`), which sets `phone_paired = false` (`daemon.rs:290`) and drops
the factor to Biometric or NoFactor: the daemon never arms a SUBSET of devices,
and the phone factor is disabled entirely rather than arming past a broken row.
That is the safe (fail-closed) direction. N tokens under N mailboxes is the
single-device push posture multiplied: the relay learns it can wake N devices for
N unlinkable mailbox hashes and nothing more (`PushStore` is keyed by mailbox; no
`daemon_pub` ever reaches the relay). Recorded as residual R-#36-2 below (a single
corrupt row disables all phone approval, an availability tradeoff, never a
release).

**Cross-cutting (re-verified for the ring): GREEN.** Daemon inert at rest (no DEK
persisted; the v2 container holds only public pins in a 0600 file; the private
identity stays in the keystore; `config_file_is_0600_and_holds_no_dek`). Secret
bytes never enter daemon memory (the decrypt/splice path is untouched; the ring
returns the same `ApprovalOutcome` the single-device path does). Relay powerless
(per-device mailbox is another opaque key-hash mailbox; the broadcast is opaque
and single-use). Approve requires the phone's hardware-gated key use (unchanged;
deny and dismiss require nothing). Everything fails closed (all-timeout deny,
half-broken-load deny, non-primary v2 deny).

### Secondary scope (#64), per item

**(a) Default build byte-identical: GREEN.** `ApnsIdentity::from_env`
(`push.rs:70`) reads `APNS_TOPIC` / `APNS_TEAM_ID` / `APNS_KEY_ID`, each falling
back to the pinned `DEFAULT_APNS_*` (`works.rainn.sigil` / `53W966FBFP` /
`5PCK76SDBA`) when unset OR empty, so `kid`/`iss`/`topic` are unchanged with the
env unset. Proven by `default-equals-pinned` and the `from_env` override/default
tests (relay push suite, 8 pass).

**(b) Self-hoster identity grants no new power: GREEN.** The identity only
addresses the APNs topic and signs the operator's own provider JWT with the
operator's own `.p8` key; it never enters the opaque-envelope / key-hash-mailbox
path (which carries no identity), so it can only sign that operator's own pushes.
The doorbell body is fixed and content-free.

**(c) No identity/secret logged: GREEN.** Only error branches `eprintln!` (JWT
mint failure, APNs rejection status/text, transport error); the `.p8` PEM, the
minted bearer, and the device token are never logged. Topic/team/key-id are not
secrets.

**(d) Stale bearer not reusable across a changed kid/iss: GREEN.** The JWT cache
hit requires `c.pem == pem && &c.id == id` AND freshness (`push.rs:154`), so any
change to `key_id`/`team_id`/`topic` (or the PEM) misses the cache and re-signs a
fresh token with the new `kid`/`iss`. A token minted under one identity can never
be served for another. `overridden-identity-rides-the-wire` proves the override
reaches the header/claims.

### Residuals (honest limits, neither a release path)

- **R-#36-1 (v2 threshold under multi-device, known/deferred).** A v2 account is
  armed against the PRIMARY device's Secure-Enclave share `F` only. In a ring, a
  non-primary phone's v2 approve returns a partial for the right `account_id` but
  the wrong `F`, which the coordinator treats as a real decision that can WIN the
  race; the downstream combine then reconstructs a wrong DEK and AES-256-GCM
  authentication fails (`secrets::decrypt_token` -> `SecretsError::Aead`), so the
  request DENIES. This is fail-closed (no partial release, no plaintext), but it
  is an availability quirk: a non-primary phone answering a v2 request first can
  cause a spurious deny of a request the primary would have approved. Must stay
  surfaced in `sigil doctor` (design doc §"v2 threshold under multi-device"), not
  silent. No release path; acceptable to land, worth closing with per-device `E_i`
  wraps before v2 multi-device is advertised.
- **R-#36-2 (one broken device disables all phone approval).** Because `load_all`
  fails loud on the first bad row, a single corrupt/unreadable device row (corrupt
  file, missing/rotated keystore identity, off-curve `F`) drops the WHOLE phone
  factor to Biometric/NoFactor. This is the intended fail-closed direction (never
  arm a subset), but it means local corruption of one row is a denial-of-service
  on all phone approval. An attacker who can corrupt a pairing row already has the
  local file/keystore access that is game-over for this threat model, so this is
  availability-only; noted for honesty, not blocking.

**Verdict recorded by the independent security-reviewer (did not implement
`3a18d17` / `ed5c4b6`). #36 multi-device core and #64 APNs identity env-sourcing
are GREEN and ship-clear; the two residuals above are fail-closed availability
limits, not release paths.**

## Independent review verdict: #51 direct-transport core (`dc51b408`, merged @ `1ea1776`)

Reviewer did NOT implement this change. Scope: the OPTIONAL, OFF-BY-DEFAULT
direct (LAN/DDNS) transport that carries the same sealed envelopes and skips the
relay, integrated with the reviewed #36 multi-device per-device owner model.
Files: `crates/sigil/src/remote.rs` (`verify_and_promote`, `route`,
`deposit_and_wait` + `deposit_and_wait_cancellable` demote paths,
`demote_and_redeposit`, `direct_primary_live`, `direct_service_hint`),
`crates/sigil/src/daemon.rs` (`build_gate` per-device `direct_endpoint` wiring,
`DirectAcceptor`, `run_direct_acceptor` spawn in `serve`),
`crates/sigil/src/pairing_store.rs` (`direct_endpoint` field, default-off
round-trip), `crates/sigil-direct/src/{tcp,fallback,discovery}.rs`,
`docs/design/direct-transport.md`.

Gate: `cargo test --workspace` = 456 passed / 0 failed (sigil-direct 18,
hostile_relay 18, pairing_mitm 26, all others green); `cargo clippy --workspace
--all-targets -- -D warnings` clean; `cargo fmt --check` clean.

### Per item

**1. Byte-identical when OFF (the load-bearing claim): GREEN.** `direct` is
`None` by default (`remote.rs:235`); `with_direct` is called only when a device
carries a `direct_endpoint` (`daemon.rs:272-275`), which is `None` on every fresh
pairing, on v1 migration, and on any pairing that omits the additive field
(`pairing_store.rs:178,199,236`). `direct_primary_live()` (`remote.rs:370`) is
`self.direct.as_ref().is_some_and(|d| d.has_primary())`, so it is `false` whenever
`direct` is `None`. In `deposit_and_wait` the `!direct_primary_live()` branch
(`remote.rs:408-413`) is the reviewed single `recv_timeout(self.timeout)`, and in
`deposit_and_wait_cancellable` `demote_at` is `None` (`remote.rs:475-477`), so the
loop is the reviewed ring wait with no demote arm. `seal_and_deposit` is unchanged
and `self.transport` is the bare relay when direct is off. N==1 (bare
`RemoteApprover`) and N>=2 (`RingApprover` over unchanged approvers) both stay on
the reviewed path. No behavior change to the relay path when direct is disabled.

**2. verify_and_promote: GREEN.** Reads exactly ONE envelope off the RAW `link`
via `discovery::verify_link` -> `link.recv` (the `DirectLink`, never the owner's
`FallbackTransport`), and opens it through `self.classify`, which locks the ONE
shared `ReplayGuard` and `env.open(&self.phone, &self.identity.agreement, guard)`
(`remote.rs:600-607,794-805`). An imposter link that seals with any non-pinned key
fails signature verification in `open` -> predicate `false` -> `NotPinnedPeer` ->
never installed (`remote.rs:817`); proven by `verify_and_promote_rejects_an_imposter`.
On success it installs the primary FIRST (`install_primary`), THEN routes the
already-opened opener via `route` WITHOUT a second `classify` (`remote.rs:807-813`),
so the shared counter is consumed exactly once and a second open (which would be a
correct counter-replay reject) never happens. No SECOND ToDaemon reader is created:
the verify read is on the raw link and strictly sequenced before install, after
which the single owner loop is the sole reader of the installed transport; the
acceptor never reads a channel. No `ReplayGuard` and no `FallbackTransport` is
shared across devices (`build_gate` constructs one approver, one guard, one
selector, one listener per `cfg`; `remote.rs:963-971`). A rogue LAN/TCP peer thus
cannot inject/forge/replay a request or response: it can only send bytes that fail
`open` and are dropped.

**3. Demote-on-silence: GREEN.** `demote_and_redeposit` (`remote.rs:382-387`) calls
`clear_primary()` (owner reverts to the relay on its next poll; the re-deposit
rides the relay because a primary-less `FallbackTransport` IS the relay) then
`seal_and_deposit` which reseals under a FRESH counter (`fetch_add`,
`remote.rs:351`). Exactly one outcome resolves: the owner routes any response by
`request_id` to the single waiter `tx`; `round_trip` takes the FIRST via one
`recv_timeout` and then `remove_waiter`s, so a late/duplicate response (whether the
black-holed direct copy arrives late, or the phone answered both copies) finds no
waiter and is dropped (`route_response`, `remote.rs:857-862`), and `outcome_for`
runs once. A replayed/stale direct response after demote is also rejected by the
shared guard (its counter was already consumed) even if read. Fail-safe: the
approval is NEVER failed by a tampered/black-holed direct attempt: on silence it
re-deposits over the relay (which the LAN attacker cannot block) and spends the
remaining budget waiting, completing there; a re-deposit error is swallowed
(`let _ =`) leaving the original wait to time out -> deny (fail closed). Proven by
`demote_on_silence_completes_over_the_relay`. The fresh counter is what lets the
phone's inbound guard accept the relay copy after a black-holed direct copy.

**4. Acceptor / rung-2 bound port: GREEN.** `run_direct_acceptor` no-ops when
`direct` is `None` (`remote.rs:830`), so spawning it per device is safe; it only
polls `accept_nonblocking` honoring the shutdown flag and hands each raw link to
`verify_and_promote`, never reading any ToDaemon channel. Daemon-at-rest inertness
holds with a port open: the listener carries no secret and grants nothing; a
connect-then-silent or garbage connection is read once by `verify_link`, times out
at `DIRECT_VERIFY_TIMEOUT` (5s) or fails `open`, is dropped, and its `Arc<DirectLink>`
falls out of scope -> `Drop` -> `shutdown(Both)`, so no fd/thread leak and no wedge
of the owner (a separate thread) or of approvals (the relay serves throughout). The
frame layer fails closed on over-cap length (`MAX_FRAME_BYTES` 64 KiB), unknown
direction byte, truncation, or EOF (`tcp.rs:315-357`). Bytes that never open as the
pinned peer can never promote.

**5. Downgrade safety: GREEN (with residual R-#51-1 below).** Discovery is
untrusted (`ServiceRecord`/`hint` only choose which host to dial; `direct_service_hint`
is a salted BLAKE2b-64 of the daemon PUBLIC identity, not the mailbox id, and grants
nothing). Only `verify_and_promote` (envelope-pinned) installs a primary. An active
LAN MITM cannot forge or read (every rung carries the same sealed/signed envelope
opened against pinned keys + shared guard); the worst it achieves by relaying the
phone's genuine opener to get promoted then black-holing is a bounded denial that
demote-on-silence turns into an ~8s relay retry for every request that deposits over
the (now-primary) direct link.

### Cross-cutting re-confirmation

Inert at rest GREEN (no DEK/token added; direct carries only sealed envelopes).
Secret bytes never in daemon memory GREEN (the DEK/`Z_F` path in `outcome_for` and
the op-stdout->client-fd splice are untouched; direct changes only which bytes carry
the opaque envelope). Relay powerless/anonymous GREEN (this work is about NOT using
the relay, never weakening it; no key-distribution role added). Approve
hardware-gated GREEN (unchanged phone SE key use; deny/dismiss require nothing).
Everything fails closed GREEN (`NotPinnedPeer`/timeout/link-error never install; a
bind failure logs and degrades to relay-only rather than refusing to arm,
`daemon.rs:252-257`; all-timeout denies). N==1 and multi-device both correct.

### Residual (honest limit, fail-closed, gates a fully-confident ENABLE)

- **R-#51-1 (promotion racing an in-flight relay request -> one full-timeout
  denial).** The demote-on-silence protection is scheduled only for a request whose
  deposit went out a LIVE direct primary (`direct_primary_live()` sampled once, just
  after deposit, `remote.rs:408`/`475`). A request deposited over the relay (no
  primary yet) takes the plain `recv_timeout(self.timeout)` with NO demote arm. If a
  primary is then installed mid-flight (the phone dials in / is discovered, or an
  active LAN MITM times its promotion), the single owner loop, on its next poll,
  reads the newly-installed direct primary instead of the relay, so the relay-
  delivered response to that in-flight request is starved and the request times out
  at `DEFAULT_REMOTE_TIMEOUT` (120s) -> DENY. This is fail-closed (never a forged
  approval, leaked secret, or false release) and self-limiting (subsequent requests
  deposit over the primary and regain the 8s demote bound), but it means the design
  doc's "an active MITM costs at most one 8s demote, never a full-timeout denial"
  claim is imprecise: a promotion that races an already-in-flight relay approval
  costs THAT request a full-timeout denial. Severity: LOW (availability only, worst
  case one long deny per promotion event; an attacker who can drive it gains nothing
  beyond the already-acknowledged denial ceiling). Recommended close before enabling
  on a hostile LAN: crisper owner revert (close/interrupt the parked relay poll on
  install, symmetric to `clear_primary` on demote) or track the depositing rung per
  request and demote a relay-deposited request whose owner has switched rungs. The
  mitigation is straightforward; it is not required for the OFF-by-default ship.

**Verdict recorded by the independent security-reviewer (did not implement
`dc51b408`). The #51 direct-transport core is GREEN on all five flagged items and
on every cross-cutting invariant, with one fail-closed availability residual
(R-#51-1). It is SAFE TO SHIP as merged, because it is OFF by default and
byte-identical to the reviewed relay path when off. It is SAFE TO ENABLE on a
trusted LAN / owned endpoint today (the only attacker outcome is a bounded, fail-
closed denial). Before enabling in an actively-hostile-LAN posture, close R-#51-1
(or run `DepositPolicy::Mirror`, which removes the in-flight-starvation window
entirely at the cost of always also using the relay) so a promotion cannot cost an
in-flight relay approval a full-timeout denial.**

---

## Independent review: #67 retire the monotonic-counter replay gate (`1e5ba76`)

Reviewed by the independent security-reviewer (did **not** author this change).
Scope: the replay guard rewrite at `1e5ba76` on `feat/config-rule-engine` —
`replay.rs`, `envelope.rs`, `export-vectors.rs`, the phone mirror `replay.ts`,
and the hostile-relay / vector suites. The counter gate is removed; the guard is
now two gates in order: (1) freshness `|now - ts| <= REPLAY_WINDOW_MS`, then
(2) single-use uuidv7 request id, with the seen-set evicted by age (drop ids
whose `ts` has aged past the window) plus a `MAX_SEEN = 4096` hard backstop. The
`counter` field still rides the signed wire but is no longer gated.

**Gate results.** `cargo test --workspace` all green (250 + 92 + 18 hostile-relay
+ 26 pairing-mitm + the rest, 0 failed; one pre-existing flaky loopback-TCP test,
`remote::tests::the_acceptor_loop_promotes_a_dialled_phone`, failed once under
heavy parallel load then passed 5/5 in isolation and on the full re-run — it is in
`#51` direct-transport, untouched by #67, and passes on the parent commit too:
not a #67 regression). `cargo clippy --workspace --all-targets -- -D warnings`
clean (exit 0). `cargo fmt --check` clean. Phone: `tsc --noEmit` clean;
`proto:selftest` all green; `proto:vectors` 20 passed / 0 failed.

**1. Replay is still fully caught: GREEN.** The security question — does dropping
the counter open any replay the id+freshness gates do not catch — is answered no.
   - *Same-id replay in window* -> `DuplicateRequest` (`replay.rs::duplicate_request_id_is_rejected`,
     `envelope.rs::exact_replay_is_rejected`, `hostile_relay::replay_of_a_delivered_envelope_is_rejected`).
   - *Stale or future ts beyond the window* -> `TimestampOutOfWindow`
     (`stale_timestamp_beyond_window_is_rejected`, `future_timestamp_beyond_window_is_rejected`,
     `an_envelope_held_past_the_window_is_rejected`).
   - *Any tamper, including the ungated counter* -> `BadSignature`: `counter` is
     still in `canonical_bytes` (`envelope.rs:97`, `e.counter.to_be_bytes()`) and
     the signature is verified before the guard runs
     (`any_field_tamper_breaks_the_signature`, `hostile_relay::{bumped,rewound}_counter_is_rejected`).
   - *Force-evict-then-replay* is **not** reachable. Age-eviction drops an id only
     once `now - ts > window_ms` — at which point any replay carrying that id can
     only carry its original (now-stale) `ts`, which fails the freshness gate
     *before* the single-use check runs (`a_replay_after_the_id_ages_out_is_caught_by_freshness`,
     vector `aged-out-replay-fails-freshness`). The attacker cannot supply a fresh
     `ts` for an old id because `ts` is inside `canonical_bytes` and re-timestamping
     breaks the signature. `evict_aged` pops only front entries provably past the
     window and stops at the first still-in-window (or future-dated) entry, so an
     in-window id is never evicted by the age sweep.
   - *`MAX_SEEN` weaponization* is not feasible as a replay lever. Evicting an
     in-window target id via the backstop requires pushing `4096` **authentic,
     unforgeable, distinct** envelopes (each a valid Ed25519 signature under the
     sender's pinned key, each a distinct uuidv7) into a single freshness window
     ahead of it. The relay holds no signing key, so it cannot manufacture even
     one; only the genuine sender could, and a sender attacking its own replay
     guard gains nothing (it can already send). For a single-user personal
     instrument this is an acceptable, clearly-bounded residual, not a live hole.
   Net: every replay the retired three-gate design caught is still caught by
   signature + freshness + single-use. The counter was never the load-bearing
   gate for replay.

**2. Rust<->TS parity: GREEN, with one pre-existing out-of-scope divergence
noted (P2).** The two guards are logically identical (freshness then single-use;
age eviction; `MAX_SEEN = 4096`; no state change on reject) and the regenerated
KAT vectors drive **both** guards at the same `windowMs = 150000` (the vectors
carry `windowMs` explicitly and `verify-vectors.ts` passes `r.windowMs` into the
TS guard), so `proto:vectors` 20/20 proves accept/reject agreement across the
retired-counter cases (`counter-is-ungated`, `duplicate-request-id`,
`timestamp-out-of-window`, `aged-out-replay-fails-freshness`). No divergence lets
one guard accept a *replay* the other rejects.
   - **P2 (pre-existing, NOT introduced by #67).** The production default freshness
     window differs between sides: `sigil-proto::REPLAY_WINDOW_MS = 150_000`
     (`lib.rs:51`, bumped 90k->150k back in `4779473`) but the phone's
     `replay.ts::REPLAY_WINDOW_MS = 90_000` (unchanged since the original
     `ecafed8`), and `envelope.ts` opens with that 90s default. #67 touched
     neither constant. Direction of the mismatch is fail-safe: the daemon opens
     phone->daemon at 150s, the phone opens daemon->phone at the **stricter** 90s,
     the same envelope is never checked by both windows, and a shorter window can
     only *reject* more (never admit a replay the longer one would reject). Worst
     case is the phone rejecting a genuine daemon->phone `ResolutionBroadcast`
     whose clock skew lands in the 90–150s band — a fail-closed robustness bug, not
     a replay admission. Also the `replay.ts:23` comment "Matches proto
     REPLAY_WINDOW_MS" is now false. Recommend aligning the phone constant to
     `150_000` (or exporting one shared value) and fixing the comment; out of
     scope for #67's soundness, filed here as an honesty residual.

**3. Envelope / crypto unchanged: GREEN.** `canonical_bytes` is untouched and
still length-prefixes and covers `counter` and `ts`; `seal`/`open`'s crypto legs
are unchanged. `export-vectors.rs`'s diff is confined to the `replay` section
(removing the `CounterRegression` match arm, renaming `counter-must-advance` ->
`counter-is-ungated`, adding `aged-out-replay-fails-freshness`); the
`canonicalBytes` / `open` / `combiner` / `pairingTranscript` generators are
byte-for-byte identical, confirmed by regenerating the vectors and observing a
zero diff against the committed `sigil-vectors.json`. Only `replay`-vector
outcomes changed. `envelope.rs`'s only diff is a renamed test.

**4. Post-restart window: GREEN, unchanged residual.** A fresh guard (daemon
restart or new phone `ReplayGuard`) has an empty seen-set, so a relay that
captured an authentic envelope can replay it once within the freshness window and
it will pass. This is **identical to the retired counter design** — the in-memory
counter also reset to 0 on restart, so a captured lower-counter envelope was
equally replayable post-restart — and is bounded by `REPLAY_WINDOW_MS = 150_000`
(**150 seconds**, `lib.rs:51`). It is not a new hole; the window is the bound.
Recorded already as a residual in the §"Two-gate guard" implementer note.

**5. Stale verdict prose re-audited and corrected.** Three prior verdicts
described replay as caught by "the ReplayGuard monotonic counter"; re-audited
under the new mechanism, the *verdicts* still hold (replay is caught by the
single-use id, backed by freshness) but the *mechanism prose* was wrong and one
test reference was broken. Corrected in place:
   - **route_response row** (§Demux owner): rewritten to attribute rejection to
     the single-use uuidv7 gate; the cited test
     `hostile_relay::reordering_queued_envelopes_is_caught` did not exist (the
     current test is `reordering_distinct_envelopes_is_accepted`, opposite
     semantics) and was repointed to `replay_of_a_delivered_envelope_is_rejected`.
   - **reordering residual** (§Accepted residuals): the old text claimed reorder
     of distinct envelopes is a counter-regression **denial**; under #67 reorder
     of distinct envelopes is **accepted** (each routes by its own id), so the
     residual was inverted and is rewritten. The relay still cannot force a grant
     or a replay.
   - **#41 delivery receipt item (c)**: "shared monotonic ReplayGuard" /
     "advances `last_counter`" / "`CounterRegression` rejection" corrected to the
     single-use-id mechanism; the GREEN verdict stands.
   The resolution-broadcast section (§#36) still references the per-session
   *outbound* counter that legitimately survives on the wire, and its
   replay-rejection claim remains sound via the single-use id; left as-is (the
   counter it names is the sender's, not a receive-side gate).

**Cross-cutting invariants (spot-check): intact.** Signature-before-guard order
preserved (invariant on authenticity); a rejected envelope mutates no guard state
(`rejected_envelope_does_not_advance_state`), so it cannot poison a later
legitimate one; everything still fails closed (unknown skew / dead clock / restart
all deny by rejecting or timing out); no secret bytes touch the guard; the relay
remains powerless (it holds no signing key, so it can neither forge a fresh id nor
re-timestamp an old one). Zeroize/DEK lifetimes untouched by this change.

**VERDICT: SOUND. Retiring the monotonic counter is safe.** Replay protection is
complete without it — signature (before the guard) + a 150s freshness window +
single-use uuidv7, with age-based eviction that provably cannot open a replay and
a `MAX_SEEN` backstop that cannot be weaponized without the sender's signing key.
No replay reachable under the new guard was caught by the old three-gate design.
Green on all five scoped items and on the cross-cutting invariants. One
pre-existing, out-of-scope, fail-closed parity residual (item 2: phone freshness
window 90s vs daemon 150s) is recommended for a follow-up alignment; it is not a
replay hole and does not block this change.**


---

## 2026-07-13 -- Independent review: v1 DEK / accounts / brokering teardown (commit `01e625b`)

Reviewer: independent security-reviewer (did not write the code). Scope: the
proto + daemon refactor retiring the v1 DEK, `accounts`, and credential
brokering in favor of "gate, don't broker" -- everything at rest is
threshold-sealed, openable only with the phone's per-request partial `Z_F`. Gate
green at review time: `cargo test` (sigil/proto/softphone), `clippy -D warnings`,
`fmt --check` all clean.

### Teardown itself: SOUND

1. **No secret at rest in the clear.** Env values seal only via
   `seal_env_pairs` (cli.rs) -> `threshold::seal_secret` -> `ThresholdRecord::seal`;
   values arrive on stdin only, are `Zeroizing`, and the store persists ciphertext +
   public `E`. Opening REQUIRES the phone's partial: `fulfill` (daemon.rs ~1503)
   fails closed if `outcome.zf` is `None` and again if the Mac share `m` is absent.
   Disk alone (record + `m`) cannot open it (`a_wrong_or_missing_partial_fails_closed`).
2. **DEK deletion complete + fail-closed.** `se_ecies.rs` deleted;
   `Dek`/`seal_dek`/`open_dek`/`deliver_dek`/`receive_dek`/`wrapped_dek`/`dek()`/v1
   `approve` gone from proto; keystore `ensure_dek`/`unwrap_dek`/`has_dek` gone. No
   live references remain. Approve path is threshold-only (`approve_v2` / `approve_gate`);
   `outcome_for` (remote.rs ~632) requires `partial_zf()` AND `account_id ==
   challenge.account_id`, else collapses to Deny (remote.rs 933/1068).
3. **Kept-vs-deleted correct.** Blob storage (`store_blob`/`load_blob`) still backs
   the daemon identity keys and the Mac share `m`; `verify_presence` survived. No
   pairing/identity regression from the deletion.
4. **Threshold invariants intact.** R2 (E on-curve before scalar mult; F on-curve
   at pairing), R3 (`require_v2` at decrypt), R4 (fresh unique `E` per seal +
   `all_ephemerals_unique` enforced fail-closed across the whole store on `save`),
   R5 (challenge carries id/label, daemon re-checks the returned partial's id). Env
   re-home reuses the identical seal/combine core.
5. **Fail-closed + zeroization.** `m`, `Z_M`, combined `K` are mlock'd +
   zeroize-on-drop in `threshold::decrypt`; `m` dropped right after the one combine;
   opened plaintext and injected env are `Zeroizing`. Local Touch-ID auto-approve is
   removed; a local/control-socket approve carries `zf: None`, so even a same-UID
   forged control approval can approve a plain gate but can NEVER open a sealed secret.
6. **Provider path.** `OpProvider::run` injects nothing (splices caller fds to real
   `op`). `needs_account` gone; the credential-injecting `OpSshSigner` and the
   `credential` param on `sign()` deleted outright. No gate lost its approval;
   unmatched commands fail closed, only an explicit user `Allow` rule runs ungated.

### CONFIRMED HIGH -- `verify_presence` needs an entitlement the unsigned daemon lacks

`MacKeystore::verify_presence` (keystore_macos.rs:163) mints a **persistent
Secure Enclave key in the DataProtectionKeychain** via `ensure_presence_key`
(92) -> `SecKey::generate` with `Token::SecureEnclave` +
`Location::DataProtectionKeychain` + permanent + re-found by label
(`find_se_private_key`). Creating a DataProtectionKeychain item requires the
`keychain-access-groups` entitlement (=> app-bundle signing + provisioning
profile), which the unsigned/portable daemon lacks: `SecKey::generate` fails
errSecMissingEntitlement (-34018), or SIGKILL if signed with the group but no
profile -- both empirically observed on this machine.

Failure chain: production macOS -> `MacKeystore` with `is_biometric() == true`
-> `sigil pair` after SAS confirm calls `arm_after_sas` (cli.rs:1001), which
calls `verify_presence` with `?` -> generate fails -> pairing aborts. Pairing is
the sole path that pins phone share `F` and provisions `m`, so the entire
threshold model is unreachable in the unsigned posture. Approvals no longer call
`verify_presence`, so the blast radius is specifically reaching a paired state.
Blob storage is unaffected (legacy `set/get_generic_password`, no entitlement).

This is not newly introduced (the pre-teardown `ensure_dek` used the same
persistent-SE mechanism) but it is **reblessed** under a new name AND a new,
false correctness claim: `docs/design/secret-model.md:35-36` states
`verify_presence` "work[s] from the unsigned binary." That claim is **UNPROVEN /
false** as implemented; the code's own NEEDS-VERIFICATION markers
(keystore_macos.rs:17-20, 187-188) confirm it never ran on hardware.

**Fix direction:** replace the SE-key presence probe with
`LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`
(LocalAuthentication -- no keychain item, no SE key, no entitlement; needs an
objc2/Swift shim since `security-framework` does not expose LAContext).
Alternatively a transient SE key (`kSecAttrIsPermanent = false`, no
DataProtectionKeychain, regenerated per call, not re-found by label) MAY work
unsigned but needs its own on-hardware proof. Recommend blocking the
unsigned-daemon posture and correcting the secret-model.md claim to UNPROVEN in
the same change.

### Residual doc-drift (LOW, cosmetic, no runtime effect)

- `daemon.rs:14` module doc still says "unwraps the DEK, decrypts the one token".
- `daemon.rs:1256-1259` `fulfill` doc describes the deleted DEK/account flow and
  carries a now-broken intra-doc link `[needs_account](crate::provider::SecretProvider::needs_account)`.
- `request.rs:281-283` doc still references `wrapped_dek` / v1.
- `daemon.rs:3835` test comment references `needs_account`.

Recommend a doc-sweep. Nothing here blocks; the HIGH above does.

**VERDICT: teardown SOUND; one CONFIRMED HIGH (`verify_presence` entitlement
dependency) blocks the unsigned-daemon shipping posture until moved to
LAContext.**

---

## 2026-07-13 - Review: presence gate moved to LAContext (commit 6892bab)

Independent adversarial review (reviewer did not author the change) of the fix
for the CONFIRMED HIGH above: `verify_presence` now calls
`LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` through an
ObjC shim (`crates/sigil/src/presence.m`, compiled by `crates/sigil/build.rs`),
replacing the persistent Secure-Enclave key that an unsigned binary cannot mint.

Scope reminder: this gate is presence-only. It unwraps/derives/delivers NOTHING;
it forces a live biometric before `arm_after_sas` (cli.rs:1001) pins phone share
`F` and provisions Mac share `m`. An attacker who can forge the shim's return is
already executing in the daemon (out of scope).

- **Policy strength - SOUND.** `LAPolicyDeviceOwnerAuthenticationWithBiometrics`
  with `localizedFallbackTitle = @""` (presence.m:32,35) is biometry-only; it
  cannot silently degrade to passcode/password. Correct choice for a "physical
  presence" gate. Tradeoff residual: biometry lockout after repeated failures
  (LAErrorBiometryLockout) has no passcode escape here, so a locked-out sensor
  makes pairing impossible until the OS-level reset - fail-closed, acceptable
  for a personal instrument, worth knowing.
- **Fail-closed - SOUND.** The Rust match (keystore_macos.rs:96-107) maps ONLY
  `1 => Ok`; every other value is `Err`: `0 => Declined`; `rc <= -1000 =>
  Backend`; wildcard `rc => Backend`. `canEvaluatePolicy == false` returns
  `-1000 + code` or `-1` (presence.m:41), and `reply(success=false)` returns `0`
  (presence.m:50) - both land on Err arms. No path yields a false `Ok`. The
  caller propagates with `?` (cli.rs:1004, pairing_store.rs:396) so any Err
  aborts before anything is written.
- **Thread safety - SOUND (with a doc nit).** The production caller is the
  synchronous `sigil pair` CLI on its main thread; all `daemon.rs` invocations of
  `arm_after_sas` are test-only no-ops, so no tokio worker blocks on the
  semaphore in production. `LAContext.evaluatePolicy`'s reply block runs on
  LAContext's own private queue (not the main run loop), so the
  `dispatch_semaphore_wait(..., FOREVER)` cannot deadlock even on the main
  thread; macOS Touch ID UI is presented out-of-process and needs no main-loop
  pumping. The `__block int result` write precedes `dispatch_semaphore_signal`
  inside the reply block (presence.m:52-53), and the waiter reads `result` only
  after the wait returns - correctly ordered, no race. NIT: presence.m:47-48
  claims the daemon "never" calls this from the main queue; the actual prod
  caller IS a main thread (harmless here, but the comment's rationale is
  imprecise).
- **No secret / no spoofing - SOUND.** The shim returns a small int and reveals
  nothing; `is_biometric()` is hardcoded `true` on Mac (keystore_macos.rs:85) so
  the gate is always invoked. The only in-band bypass is `SIGIL_DEV_KEYSTORE`
  making `is_biometric()` false - the intended, loud dev switch, out of scope.
  `CString::new(reason).unwrap_or_default()` on an interior-NUL reason yields an
  empty string that the shim replaces with a default prompt (presence.m:44-45);
  `reason` is a fixed constant, no attacker input, no weakening.
- **Build integrity - SOUND.** `build.rs` compiles the object solely from
  `src/presence.m` via `cc` with `rerun-if-changed` on that file; pinning
  `/usr/bin/ar` (only when it exists) only selects the archiver that bundles that
  object, it introduces no path by which a different object is injected. The shim
  and its `extern "C"` block are `#[cfg(target_os = "macos")]`-gated
  (build.rs, lib.rs:22-23, keystore.rs:278), so non-macOS targets are unaffected.

Residual carried forward: this closes the runtime HIGH, but the on-hardware
evidence is the commit's own report (LAError -4 clamshell reaches the biometric
subsystem; real prompt with lid open); the ignored round-trip test
(`presence_check_prompts_a_real_touch_id`) is the standing manual proof.

**VERDICT: SOUND. The CONFIRMED HIGH ("verify_presence entitlement dependency")
is resolved; biometrics-only, fail-closed, no secret exposure, macOS-gated
build. Doc nit (presence.m:47-48 "worker thread") only. Unsigned-daemon pairing
posture is unblocked pending the standing manual hardware test.**

## Independent review verdict: unsealed inline-env source degrades to a plain gate (2026-07-14)

An inline `env` source that has KEY names declared in `config.json` but NO sealed
record in the threshold store used to fail closed at dispatch ("inline env source
'..' has no sealed values"). It now degrades to a PLAIN GATE: still phone-gated,
but injects nothing (the missing var is simply unset). See
`crates/sigil/src/daemon.rs` (`fulfill`: the `Gate(mut action)` arm clears
`env_keys` when `store.get(name).is_none()`; `needs_sealed_env` becomes false; the
main dispatch and the lease short-circuit both route the degraded `EnvProvider`
through `run_passthrough`) and `cli.rs` (`config_export` /
`reconcile_unsealed_env_sources` drops the dead keys in the exported VIEW only,
never writing `config.json`).

Reviewed independently (implementer did not self-certify). **VERDICT:
SOUND-WITH-RESIDUALS**, no HIGH/CRITICAL.

- **No leak, gate never bypassed (inv #2/#4/#5).** On the degraded path
  `sealed_env` is `None`, `run_passthrough` injects nothing, no secret bytes enter
  daemon RAM, and `core.gate.decide` is unconditionally reached unless a *prior*
  live lease short-circuits. Deny still fails closed.
- **Readout integrity (inv #3 / R5).** `env_keys` is cleared BEFORE the
  `SourceView`, `describe`, `account_label`, and `ThresholdChallenge` are built, so
  the phone consents to exactly the bare gate that runs; no keys are shown then
  silently dropped.
- **F1 (LOW, correctness, fixed same change).** The lease short-circuit initially
  still called `provider.run(env: None)`, which for a degraded `EnvProvider` hit
  its empty-env refusal and returned exit 1, bricking the leased second run (fails
  closed, no leak). Fixed by routing that branch through `run_passthrough` too;
  regression test `leased_unsealed_inline_env_source_runs_as_a_plain_gate`.
- **F2 (LOW residual, design-intended).** An attacker who can delete the
  `threshold.db` record but not `config.json` downgrades a secret-injecting rule to
  a bare no-injection gate. This is not an escalation (the command runs with LESS
  than intended, never a leak; previously such tampering DoS'd the command). The
  readout honestly reflects the bare gate and approval is still required. For a
  single-UID personal daemon the threshold.db/config.json write boundary is
  artificial (whoever has one has the other). Accepted residual; matches the agreed
  "unsealed env source is a plain gate" design.

---

## 2026-07-15 - Independent review: agent-operated Sigil change set (`8308fc8`, `7702fa9`, `f7e955d`, `c733b45`)

Independent adversarial review (reviewer did not author these changes) of the
agent-operated rework: serve-loop hardening + bounded teardown + ssh-sign log
(`8308fc8`), the `sigil up` keystone with the installed binary, plist rewrite,
and shim retarget (`7702fa9`), the Mac app auto-ensure (`f7e955d`), and the
agent-facing skill (`c733b45`). Design rationale reviewed alongside:
`docs/design/agent-operated-sigil.md`. Baseline held throughout: a same-UID
attacker was already game over per every prior review (unauthenticated 0600
control socket, user-writable plist, shim dir, and binaries); each finding below
is judged relative to that baseline, not against a boundary that never existed.
Tree at review: `cargo test -p sigil` green (246 passed, 0 failed, 6 ignored,
the known manual/device tests).

### Per-angle assessment

- **Serve-loop non-fatal error handling - SOUND.** Every new non-fatal path
  (listener accept error, `ready_conn` failure, concurrency-cap refusal) ends in
  the connection being dropped with no reply, which the shim/client reads as
  deny; `daemon.rs::ready_conn` errors are strictly per-connection (the macOS
  EINVAL race is a property of the one dead peer). No served request skips
  `gate.decide`; the approve/inject logic is untouched. A hostile same-UID
  client can hold the 32-connection cap (pre-existing `ConnGate`), which
  REFUSES further connections: starvation is availability-only and denies. The
  previous behavior (whole-daemon death on a probe race, killing in-flight
  approvals) was strictly worse for availability and no better for security.
- **The ssh-sign log line - CLEAN.** `daemon.rs::log_ssh_sign_request` emits
  key label, derived host, `SHA256:` fingerprint of the data-to-sign, and peer
  pid. The fingerprint is the same digest the phone readout shows; the SSH
  data-to-sign contains a random session id, so the hash is not invertible or
  confirmable offline. No key material, no raw challenge bytes, no secret
  values. Same metadata class as the pre-existing op-path `log_request`.
- **`shutdown_timeout(2s)` teardown - SOUND, one residual (F7).** With accept
  errors now non-fatal, the teardown path fires only on pre-loop bind failures
  or ctrl-c. Abandoning in-flight blocking handlers cannot release a secret:
  an abandoned handler writes no reply (client fails closed), an
  already-approved child owns its fds and env exactly as after any crash, and
  the gate state it held dies with the process.
- **Installed binary + shim retarget - no change to the tamper surface.**
  `~/.sigil/bin/sigil` is user-writable, and so was the old
  `target/release/sigil` the plist pointed at, and so is the plist itself. The
  security-relevant resolver `paths.rs::find_real` is unchanged: rule 2
  (proxy-dir residency) already excludes anything in `~/.sigil/bin` from being
  mistaken for the real tool, and rule 1's `proxy::alias_target` covers the
  sibling runtime. `ShimStatus.resolves_to_current`'s new second arm is
  diagnostics only (F4).
- **Dev-keystore pin carry-forward - no new attacker capability, one real
  visibility regression (F1).** An attacker who can plant the pin can rewrite
  `ProgramArguments` outright; the plist was never a boundary.
- **Unconditional KeepAlive - fail-closed preserved.** Daemon down is deny at
  every consumer (shim exec-fallback excepted as ever, and that path injects
  nothing). A daemon that fails at startup forever respawn-loops under
  launchd's throttle (seconds apart, logs rotated at each start by
  `rotate_logs`), a resource nuisance, never a release. `sigil stop` remains a
  bootout, which KeepAlive does not resurrect. Interaction with RAM-only
  lockdown noted as F2.
- **The skill - accurate and safety-correct, one gap (F3).** Every taught verb
  and flag was checked against `cli.rs`: `up`/`status`/`doctor`/`history`/
  `pending`, `pair --relay`, `lease list|revoke`, `lockdown [--clear]`,
  `ssh add-file --path --host` / `add-stored` (key on stdin) / `list` /
  `remove` / `config --install`, `sshagent`, `shim add`, and the
  `sigil-config` surface (`list`, `add --provider env`, `rule add --allow`
  correctly described as a passthrough to avoid, `source env set --key|--stdin`
  reading values from stdin only, `unset`, `remove`). The quoted ssh-sign log
  format and `~/.sigil/logs/daemon.err.log` path match the code. The
  secret-hygiene rules (human-run seal pipe, verify by structure, refuse pasted
  secrets, no gated commands that print secrets into the transcript, no
  `--dev-insecure`, no rule edits to bypass a gate) are consistent with
  invariants 1-6 and give an agent no path to see a secret or weaken a gate.
- **Probe/kickstart - no new capability.** `sigil up` kickstarts only when the
  Status probe fails or the binary/plist changed; a locked-down but healthy
  daemon answers Status and is NOT restarted. A restart at a chosen moment
  zeroizes leases (RAM-only, deny-direction) and orphans pending approvals
  (deny); it can never approve. A same-UID actor could always run `launchctl
  kickstart` directly. The Mac app auto-ensure runs once per app launch and
  never on a poll, so a Stop holds within an app session; a later app launch
  or `sigil up` does resurrect the daemon, which is the intended always-on
  contract but worth knowing about the Stop control's scope.

### Findings (ranked; none HIGH or CRITICAL)

- **F1 (MEDIUM, posture visibility, fix soon).** The `SIGIL_DEV_KEYSTORE` pin
  is now self-perpetuating and invisible on the operator surface. `service.rs::
  dev_keystore_pin` takes the installer env first, else carries forward the pin
  in the existing plist; an empty env value is filtered out and falls back to
  the plist, so there is NO CLI path that unpins: only hand-editing the plist,
  which the skill (correctly, for daemon health) tells agents never to do. At
  the same time the loud banner moved to once per daemon process
  (`keystore.rs::warn_dev_keystore_once`) inside `daemon.err.log`, a file the
  agent-operated model reads only during diagnosis, and neither `sigil up` nor
  `status` nor `doctor` mentions the pin. Net: the plaintext-share posture
  (`dev-keystore.json` holds the daemon identity and Mac share `m` in the
  clear) is deliberate and honestly documented in
  `docs/design/agent-operated-sigil.md` section 6, but its loudness contract
  has quietly degraded to near-zero on the surfaces anyone actually looks at.
  No attacker gain (same-UID could always write the plist). Fix: `sigil up`
  should emit a visible note or action-needed style line whenever the rendered
  plist carries the pin, until the planned keychain migration removes it.
  Reviewer did not implement this (review-only role).
- **F2 (LOW, residual).** Lockdown is a RAM-only `AtomicBool` and any daemon
  exit clears it; this change set both automates restarts (up's kickstart, the
  Mac app auto-ensure, unconditional KeepAlive) and converts the wedge into an
  error exit (`8308fc8`), so a locked-down daemon that dies for any reason
  comes back unlocked. The claims table never asserted lockdown survives
  restart (section 8 asserts leases die on restart, which is the deny
  direction), and post-restart every request still needs a phone approval, so
  the exposure is a silent return from panic mode to normal gating, never a
  release. The control-socket `Lockdown { clear }` was already unauthenticated
  same-UID. Optional hardening: persist lockdown as a flag file honored at
  startup, cleared only by an explicit `lockdown --clear`.
- **F3 (LOW, skill gap).** `.claude/skills/sigil/SKILL.md` lists
  `sigil lockdown [--clear]` in the surface map but the forbidden list
  (`--allow` passthroughs, dev switches, rule edits) does not name lifting a
  lockdown. An agent diagnosing "requests refused; locked down" could
  helpfully clear the panic switch the human threw. Add lockdown clearing to
  the human-decision-only list (the agent may run the command, but only when
  the human explicitly asks).
- **F4 (LOW, diagnostics blind spot, accepted).** `paths.rs::ShimStatus`'s new
  second arm accepts a link resolving to `~/.sigil/bin/sigil` with no
  freshness check, so `doctor` run from a build checkout no longer flags a
  stale installed runtime (the old "shim points at a stale binary" catch).
  Staleness detection moved to `sigil up`'s byte compare, which also fixes it
  in the same run; the gate-relevant drifts (shim absent, real `op` winning on
  PATH) are still caught, and `find_real` is unaffected. Acceptable given `up`
  is now habit zero; noted so nobody mistakes ShimStatus for a tamper check.
- **F5 (LOW, availability nit).** `service.rs::install_copy` is
  unlink-then-copy, not copy-to-temp-plus-rename: a crash or a concurrent
  launchd respawn inside the window can exec a missing or partially-written
  binary. Both outcomes are a failed exec, daemon down, deny; `up` re-run
  heals. Relatedly, an env-sourced pin value is embedded in the plist without
  XML escaping; a malformed value yields a plist launchd refuses to load
  (fail closed, and the value is operator-controlled). Suggest atomic rename
  when convenient.
- **F6 (INFO).** `ACCEPT_ERROR_BACKOFF` is awaited inline in the `select!`
  arm, so a persistent accept-error condition on one listener also stalls the
  other listener and ctrl-c by up to 200 ms per iteration. Availability-only
  and bounded; fine for a personal daemon.
- **F7 (INFO, residual).** The bounded teardown exits the process without
  running drops on abandoned blocking tasks, so a `Zeroizing` buffer in flight
  at that instant (a stored-key PEM mid-signature, a threshold partial) is not
  wiped before exit. This is exactly the crash/SIGKILL case the model already
  accepts: the kernel zeroes pages before reuse, and the swap residual
  pre-exists. Already-spawned approved children keep running with their
  injected env, identical to prior crash behavior; no unapproved path exists.

### Needs on-device verification (cannot be settled statically)

- Unconditional KeepAlive respawn behavior and launchd throttle pacing on a
  daemon that error-exits repeatedly (log growth stays bounded by
  `rotate_logs`).
- The `up` reload path (bootout + bootstrap on a changed plist) and the
  kickstart-then-reprobe heal loop against a genuinely wedged pid.
- That the Mac app auto-ensure does not resurrect a deliberately stopped
  daemon within an app session (and that Tom is comfortable that a fresh app
  launch does).
- The standing manual proofs carried forward from prior reviews (Touch ID
  round trip, SE/keychain items) are unaffected by this set.

**VERDICT: SOUND-WITH-RESIDUALS. No HIGH or CRITICAL findings; the gate is not
weakened anywhere, fail-closed is preserved on every new path, the new log
line is metadata-only, and the skill gives an agent no route to a secret. Act
on F1 (surface the dev-keystore pin in `sigil up` output) ahead of the planned
keychain migration, and fold F3's lockdown line into the skill.**

### Addendum 2026-07-15: dead-peer EINVAL pin (`e777758`) and the host-unbound signature call

Same independent reviewer, same baseline. Also verified (not authored):
`ea561f4` resolves F1 (an always-shown `keystore` line in `sigil up` whenever
the plist carries the pin, via `service.rs::installed_dev_keystore_pin`) and
F3 (lockdown clearing added to the skill's human-only list) as specified.

**Authorization call, host-unbound SSH signatures: CONCUR with ALLOW plus the
honest label.** The reasoning holds under adversarial scrutiny:

- `session-bind` is unauthenticated client input (`sshagent.rs::extension`
  records the host key without verifying the host's signature over it, and
  `derive_host`'s own doc calls the host line advisory). The only party who
  can reach the agent socket is same-UID, and that party can present any real
  host's PUBLIC key and render as impeccably bound to github.com. Deny-unbound
  therefore stops the adversary zero times while breaking every honest pre-8.9
  OpenSSH, Go x/crypto, libssh2, and JGit client. Worse, it would promote a
  client-claimed field into a load-bearing gate condition, which is exactly
  the decorative-identity trap invariant 6 forbids, and it would train the
  human that "bound" means "safe" when it means nothing.
- A daemon-side warn state buys nothing either: the daemon cannot distinguish
  an honest legacy client from a liar, so any warning keyed on bind presence
  has the same false-comfort failure mode, inverted.
- Fail-closed is unaffected: bound or not, every signature still requires the
  phone approval over the load-bearing fields (key label plus data
  fingerprint, folded into the scope so distinct challenges never coalesce).
- The real improvement is exactly where the implementer put it: the phone
  rendering unbound and fingerprint-only destinations as suspicious (#75).

- **F8 (LOW, protocol hygiene, do with #75).** The unbound state rides in-band
  as the sentinel string `"(host not bound)"` inside `SshChallenge.host`,
  multiplexing three states (known_hosts name, `SHA256:` fingerprint, unbound)
  through one display string. The string is daemon-authored, so sentinel
  forgery is same-UID baseline, but the phone cannot reliably key a
  "destination unverified" rendering on string parsing across app versions.
  Fold a structured discriminator into `SshChallenge` (e.g. `binding: named |
  fingerprint | unbound`) in the same protocol change as #75; an added
  optional field is a compatible migration under the durable-pairing
  principle.

**Silent dead-peer drops (`is_dead_peer`): SOUND.**

- Nothing security-relevant is hidden. The daemon log was never a control
  against the only party who can connect (0600 socket, same-UID), and the
  events that matter still log loudly: the concurrency-cap refusal (the actual
  exhaustion signal), every non-EINVAL ready-up failure, and every request
  arrival. A connect-then-close flood holds no permit past the drop and could
  previously only generate log noise; masking one's own noise is not a
  capability.
- Breadth check: `is_dead_peer` classifies ANY EINVAL from
  `set_nonblocking`/`set_read_timeout` as a dead peer. A pathological
  persistent EINVAL of some other origin would become log-silent, but not
  invisible: `sigil up`'s Status probe holds its connection open, so a daemon
  dropping live peers fails the probe and reports failed. Optional hardening,
  not required: a rate-limited drop counter. (INFO)
- Portability: on platforms where a closed peer does not EINVAL, the silent
  arm never fires; behavior is unchanged there.
- The two regression tests are sound and non-flaky as pinned. The
  classification test is correctly `cfg(target_os = "macos")` (the EINVAL
  behavior is macOS-specific and deterministic; the peer's close completes
  in-kernel before the subsequent accept). The storm test is deliberately
  portable: on a non-EINVAL platform the 50 probes pass ready-up and hit the
  immediate-EOF `Err(_) => continue` arm instead, every read is bounded by
  the 30 s `CONN_READ_TIMEOUT` so no hang is possible, and exactly one serve
  is asserted. Both pass in the suite at review (248 passed, 0 failed).

**ADDENDUM VERDICT: both items SOUND. Allow-and-label is the correct
authorization shape for unbound signatures (deny-unbound is security theater
against a same-UID adversary who can fake the bind); implement F8's structured
binding field with the #75 phone rendering. The silent dead-peer drop hides
nothing load-bearing and its tests pin the regression correctly.**

### Addendum 2026-07-15: three-commit review (`a4fd422`, `e16b0da`, `293b848`)

Independent adversarial review (reviewer did not author these commits) of the
three commits atop `feat/config-rule-engine`. Gate reproduced green: `sigil`
247 passed / 0 failed / 6 ignored, `sigil-proto` 21 passed / 0 failed.

**`a4fd422` (keystore reframing) — SOUND, framing only. Crypto unchanged;
verdict confirmed.** The diff touches only doc comments, notice strings, one
CLI label, one `up` posture line, and the notice test. No cryptographic call
changed. Confirmed independently:

- The decrypt path (`daemon.rs::fulfill`, ~L1700-1725) fails closed if the
  approval carries no threshold partial (`outcome.zf == None`), then loads `m`
  and calls `threshold::decrypt(record, &m, zf)`. `m` alone opens nothing;
  `threshold.rs::a_wrong_or_missing_partial_fails_closed` and
  `a_wrong_mac_share_fails_closed` pin both halves. So the new "`m` is inert
  without the phone's per-request partial" framing is TRUE.
- No standalone DEK remains for sealed accounts: `pairing_store.rs` L368
  confirms "there is no DEK fallback anymore"; sealed secrets are threshold-only.
- `factor.rs` is untouched by all three commits (confirmed via `git show
  --stat`); `DEV_INSECURE_WARNING` / `SIGIL_DEV_AUTOAPPROVE` keep the loud
  multi-line `RISK` banner and the `> 5 lines` test. The de-escalation is
  scoped to the keystore notice only, as claimed.
- **F9 (LOW, residual honesty — messaging understates the coupled residual,
  NOT a must-fix).** The notice frames the two on-disk blobs as separable
  ("could impersonate the daemon ... but ... no data-decryption key here"). A
  single file-read attacker holds BOTH `m` AND the daemon identity key at once,
  which couples them: the attacker can lift the pair to their own machine,
  impersonate the daemon to the phone (identity key), solicit an approval, and
  combine the returned partial `Z_F` with the `m` they already hold to decrypt
  locally — the Mac is no longer needed. The sole surviving gate is the human
  correctly rejecting a phished approval on the phone, now defending against a
  remote impersonator rather than a local Mac process. This does not falsify
  the notice (there is genuinely no standalone decryption key, and every path
  is still human-gated), and no crypto weakened, so it is a residual, not a
  blocker. Recommend the notice/`up` line acknowledge that a file reader gets
  `m` and the impersonation credential together, so a phished approval yields
  decryption off-box. Same-UID file read was always the trust boundary here;
  the residual is the honesty of the wording, not a new capability.

**`e16b0da` (remove lockdown) — SOUND. Critical claim survives attack; moots
prior residual F2.** The two deleted fail-closed checks (`fulfill` top,
`approve_and_sign` top) were additive short-circuits that only fired when
lockdown was engaged; with the engage path removed there is no state in which
they would have fired, so removing them changes no default gating. Confirmed by
inspection that both functions retain their real gates:

- `fulfill` still fails closed on the proxy-recursion fuse (L1447), the
  unconfigured/unmatched command (L1466 `None` arm), and the missing-partial
  and decrypt-failure arms (L1705, L1724).
- `approve_and_sign` still fails closed (`return None`) on a key it does not
  serve (L579), and every signature still requires the phone approval over the
  scoped key-label + data-fingerprint.
- Grep confirms NO remaining code depends on a lockdown flag. `LeaseStore::clear()`
  survives with a live caller: the ctrl-c/shutdown arm (`daemon.rs` L959-960,
  "shutting down (leases zeroized)"), so the daemon-restart lease zeroize is
  intact and still exercised by `lease.rs::clear_zeroizes_all_leases`.
- Wire-compat decision confirmed: `StatusJson.locked_down` is retained,
  hardwired `false` (`report.rs` L72, `json.rs` L359), so an older Mac app
  decodes it fine. `RequestKind::LockdownClear` was daemon->phone only, so
  dropping the variant needs no ignore-on-receive. `RequestKind` reserialization
  is exercised by `json.rs::request_kind_str` tests.
- **F10 (INFO, dead branch — cleanup, not security).** `cli.rs::cmd_status`
  L313 still renders a `st.locked_down` head branch, now permanently
  unreachable because the daemon hardwires the field to `false`. Harmless
  (status display only, no gate), but dead; fold out when the Mac-app/phone
  lockdown UI removal lands (#75). Prior F2 is now MOOTED (the feature it
  described no longer exists); prior F3 (skill lockdown-clear line) is likewise
  obsolete and should be dropped from `SKILL.md` with the phone/Mac follow-up.

**`293b848` (structured `HostBinding` on `SshChallenge`) — SOUND. Implements
prior residual F8 as specified.** Confirmed:

- Additive optional field: `#[serde(default)]` + `#[derive(Default)]` with
  `#[default] Unbound`, so an older peer that omits `binding` deserializes to
  the fail-safe Unbound and `host: String` stays populated. Pinned by
  `request.rs::ssh_challenge_host_binding_is_additive_and_defaults_unbound`
  (asserts the legacy-JSON `"(host not bound)"` payload defaults to Unbound).
- The binding is advisory context, NOT a security boundary, and the code says
  so in both `request.rs` (`HostBinding` doc: "even a Named binding is advisory
  ... a same-UID client can name any destination") and `sshagent.rs`
  (`HostContext` / `derive_host`). Grep confirms `binding` is NEVER branched on
  or gated on anywhere — it is set in `derive_host` and forwarded into the
  sealed `SshChallenge` for display only. Nowhere is Named implied to mean
  verified.
- No hostile-relay extension is warranted: `HostBinding` is not a new message
  type and adds no new trust-bearing decision. It rides inside the already
  sealed+authenticated `ApprovalRequest`, so a hostile relay can neither forge
  nor flip it undetected (covered by the existing envelope proofs); and even if
  it could, the field drives no gate. Registered here explicitly rather than
  silently skipping the suite.

**THREE-COMMIT VERDICT: SOUND-WITH-RESIDUALS. No HIGH or CRITICAL findings. No
crypto weakened; no path now serves a secret that previously would not; every
default fail-closed gate is intact and independently re-confirmed. Must-fix:
none. Residuals to act on: F9 (tighten the keystore-notice wording to admit the
coupled `m`+identity-key file-read residual) and F10 (drop the dead
`locked_down` CLI branch and the obsolete lockdown skill line with the #75
follow-up).**

## Independent review verdict: rule-scoped lease widening (uncommitted, `feat/config-rule-engine`, 2026-07-28)

Scope reviewed: the uncommitted widening of the lease grant key from
`BLAKE2b(caller chain ++ cwd ++ exact argv)` to `BLAKE2b(caller chain ++ "" ++
matched-rule-name)`, across `crates/sigil/src/{daemon,lease,approve,cli,json}.rs`,
`crates/sigil/PROTOCOL.md`, the phone approval sheet, and the three docs. Reviewer
wrote none of this code. Suite green at review time (256 passed, 6 ignored).

**VERDICT: SOUND-WITH-RESIDUALS on the enforcement code; BLOCKED on the consent
copy as written.** The mechanism does exactly what it claims, the enforcement
authority stayed in the daemon, and nothing in the change makes the daemon serve
a secret it previously would not *without an approval*. What is not shippable as
written is the human-facing description of the window: on the axis the approver
is actually looking at (which secret), the caption is silent, and on the axis it
does speak to ("from this process") it is false. Fix F1, F2, F6 and F7; F3 is a
judgment call for Tom; F4, F5, F8 are residuals.

Every HIGH finding here is about the *description* of the window, not its
enforcement. That is the honest shape of this change: the code does what it
claims, and what it claims to the human is narrower than what it does.

### Findings

**F1 — HIGH. The consent caption is silent on the axis the human is reading:
which secret.** `approval-sheet.tsx` renders `<SecretReadout secrets={...}/>`
prominently (e.g. `op://Engineering/.env`), and this change promotes "Keep
approved for 15 min" to the *primary* capsule, captioned "Also covers matching op
commands from this process, in any directory." The caption enumerates the two
axes that widened least surprisingly (command shape, directory) and says nothing
about the one under the reader's thumb: the window serves every other reference
the rule matches. Reviewer proof (written, run, passing, then reverted): approve
`op read op://Engineering/.env`, then run `op read op://Personal/bank/password` —
the approver is consulted exactly once. *Required:* the caption must name the
item axis (e.g. "…other commands and other items this rule matches…"). The exact
wording is design-reviewer's; the requirement that "other items" appear is not
negotiable, because "the readout is the consent" is a brief-level claim.

**F2 — HIGH. "from this process" is false; the window is not process-, session-,
or terminal-bound.** `lease.rs::grant_key` excludes pids deliberately
(`grant_key_ignores_recycled_pids`) and binds only the *code identity* of the
ancestor chain. A second concurrent agent session, in another terminal and
another project, has the identical chain and therefore the identical grant key.
Until this change, cwd and argv incidentally re-narrowed that; now nothing does.
Compounding it: macOS `proc_pidpath` resolves symlinks (verified empirically —
a symlink to `/bin/sleep` reports `/bin/sleep`), and every alias in `~/.sigil/bin`
is a symlink to the single `sigil` binary (`proxy.rs::install_shim_for`; on disk
`~/.sigil/bin/op -> ~/.sigil/bin/sigil`). So **the chain leaf is byte-identical
for every gated command**. The comment at `daemon.rs:1561` — "The caller-chain
binding is untouched and is now the whole boundary" — is therefore wrong in a
load-bearing way: the chain never distinguished commands and cannot; the rule
name is now the entire command-discriminating boundary, and the chain is only an
outer fence. *Required:* correct the phone caption, that daemon comment, and the
brief's "process tree key" phrasing.

**F3 — MEDIUM-HIGH. A live lease is not invalidated by a config change.**
`ConfigCell::store` (`daemon.rs:97`) swaps the rule set and `reload_config`
(`daemon.rs:445`) never touches `core.leases`. The grant key names a *mutable
rule* by a *string*, so rewriting a rule while its window is live transfers the
window to the new match. Reviewer proof (passing): open a window on rule `op`,
hot-swap a config whose rule of the same name matches `curl`, and
`curl https://evil.example` runs with the approver consulted once — for
`op read`. **Honest bounding, and it matters:** this is *not* an escalation for an
attacker, because anyone who can write `~/.sigil/config.json` can add
`mode: allow` and bypass the gate entirely (`config.rs::resolve` →
`Resolution::Allow`). The real cost is a legitimate user editing their own rules
mid-window and silently inheriting a broader grant than they approved.
*Recommended:* `reload_config` calls `core.leases.clear()` on a successful swap —
cheap, fail-closed, and consistent with "leases die when the world changes". If
Tom declines, the claim row now added to §8 must stay. *Separately surfaced:* the
gate's entire strength is bounded by the filesystem integrity of an unsigned
`config.json` (`config.rs::load` performs no integrity check); that deserves to be
stated in the residuals rather than left implicit.

**F4 — LOW. No request-kind domain separation in the grant/coalesce key.** The
SSH path (`daemon.rs:611`) and the command path (`daemon.rs:1566`, `1572`) now
both call `grant_key(caller, "", scope)` into one unseparated scope namespace. A
rule literally named `ssh-sign <label> <fp>`, or a command with empty cwd whose
`argv[1..]` joins to that string, collides with an SSH coalesce key. Impact
ceiling is one coalesced approval across request kinds — the lease store is
unreachable from the SSH path, so no lease can ever serve a signature. Contrived
and pre-existing; free to close by prefixing the scope with a kind tag
(`cmd:` / `ssh:`).

**F5 — LOW (documentation). The account leg of the triple binding is vacuous.**
Every stored lease has `account == ""`. It cannot bind falsely (grant and lookup
derive the label identically from one pinned `config.snapshot()`), and it is
redundant rather than weak, since the rule name already determines the source.
But "triple-scoped" reads as three live bindings and is today two-and-a-constant;
§8 now says so. Consequence in the CLI: `cli.rs::lease_row`'s account column is
suppressed whenever every lease has an empty account, i.e. always — harmless,
but it is dead width in practice, not a conditional.

**F6 — MEDIUM. Brief/code drift, ruled on (the lead's item 7).** The change
edited the brief's lease paragraph but kept the claim that "the unwrapped
credential is held in RAM only, scoped to that grant key, account, and rule". The
code stores `zeroize::Zeroizing::new(Vec::new())` — an empty presence marker
(`daemon.rs:1720`) — and a request that opens a sealed secret never leases at all
(`!needs_sealed_env` guards both sites). `lease.rs`'s module doc is honest about
this; the brief is not, and per CLAUDE.md the brief is the constitution.
*Ruling as written:* rewrite the clause to what the code does — the lease holds an
approval presence marker, no credential is cached, and sealed-secret requests
never lease. Do **not** mark it design-not-yet-code: there is no work item that
would make the sentence true, and a RAM-cached-credential lease is explicitly out
of scope here.

> **F6 SUPERSEDED (reviewer, 2026-08-04). Do not read the paragraph above as a
> current statement of behaviour.** The drift was closed in the *opposite*
> direction from my ruling: rather than the brief being corrected down to an empty
> marker, the code moved up to match the brief. As of `d3887ad`, a sealed inline
> `env` rule **does** lease and **does** cache the unsealed values in lease RAM for
> the TTL (`daemon.rs::fulfill`, `sealed_plain` stored via `leases.grant`;
> `lease.rs::Lease::token`), and the `!needs_sealed_env` guards I cited are gone.
> The lease binding also grew a fourth leg (`lease::LeaseBinding`: account, scope,
> and a `source` fingerprint over the sealed record's ephemeral point `E`).
>
> The claim row in §8 describing the RAM cache is the current, authoritative
> statement; this F6 paragraph is retained only as the record of what was true when
> the rule-scoped-lease review was written. Two consequences carry forward:
>
> * My §8 row asserting "no path caches a secret in a lease" was written under the
>   old behaviour and has been replaced. Any surviving copy of that sentence
>   anywhere in this document or the brief is now **false** and must go.
> * Reviewer finding **F3** (a live lease is not invalidated when config
>   hot-reloads) was raised as a judgment call for Tom while a lease held nothing.
>   With a live plaintext credential in the window it is no longer optional, and
>   the same is true of **F2**'s blast radius: the window now releases values, not
>   just a skipped prompt.
>
> **This note reconciles the contradiction only. It certifies nothing about the
> RAM-cache path**, which I have not yet reviewed adversarially. That verdict, and
> the question of whether the BLOCKED-on-consent-copy state lifts, come in the
> Part 2 pass over the settled combined change set.

**F7 — HIGH. The phone's lease list and its revoke button are a mock, and the
brief cites them as the mitigation for the widened window.** The brief's settings
row was rewritten by this change to "active leases with live TTL countdowns and
one-tap revoke, each naming the rule it covers and saying so (`launcher · op-eu,
any matching command, 41m left`)". A matching UI landed in
`apps/phone/app/(tabs)/(settings)/index.tsx` (`LeaseRow`, rendering exactly that
breadth caption) *during* this review, from a concurrent agent. It is not wired to
anything:

* `AppState.leases` is written only by the demo seed (`state/demo.ts:246`,
  `demoLeases`). No live-session path ever populates it, so the list can never
  display a real daemon lease.
* `store.revokeLease(id)` (`state/store.ts:130-132`) filters the row out of the
  phone's own array and sends nothing. There is no wire message, no envelope, and
  nothing reaches `LeaseStore::revoke`.

A revoke control that silently does nothing is worse than an absent one: the
brief's stated containment for a rule-wide window is that the human can see and
kill it from the phone, and a user who taps it will believe the window closed
while the daemon keeps honoring it for the rest of the TTL. *Required:* either
wire the list and revoke to the daemon, or mark both the UI and the brief row
`planned` and state plainly that revocation is `sigil lease revoke <prefix>` on
the Mac, only. This finding is against work that arrived mid-review and is a
moving target; re-review it once it settles.

**F8 — LOW. The hostile-relay suite carries no lease case.**
`crates/sigil-proto/tests/hostile_relay.rs` (32 tests) has zero lease coverage.
Correctly, the wire did not change and `ApprovalResponse.lease` rides inside the
sealed, counter-guarded envelope (`remote.rs::classify` → `env.open(...)`), so a
relay can neither forge nor tamper `ttl_ms`, and the daemon clamps whatever
arrives. But the blast radius of a forged grant just grew from one argv to a
rule-wide window, so the suite should hold the negative proof rather than resting
on inspection. Reviewer-owned follow-up; not a merge blocker.

### Verified clean (the lead's checklist)

- **Coalescing never widens (item 1): CONFIRMED.** Exactly two production
  `gate.decide` call sites — `daemon.rs:1684` passes `coalesce_key`
  (chain + cwd + argv, byte-identical to the pre-change key) and `daemon.rs:647`
  passes the SSH per-signature key. `PendingRegistry` is keyed by uuidv7 request
  id, never by any grant key, so the pending path cannot widen. `DevMode`
  short-circuits inside `LocalApprover::decide_local`, i.e. *below* the gate, so
  the dev-autoapprove path inherits the narrow coalesce key and its
  `Decision::Lease` is still clamped by rule policy. Only `daemon.rs:1618`
  (`token_for`) and `daemon.rs:1716` (`grant`) touch the wide key, both correct.
- **Run-once and the TTL clamp (item 3): CONFIRMED post-change.**
  `daemon.rs:1707-1714` is the sole grant site; `LeasePolicy::RunOnce.clamp_secs`
  → `None`, so a compromised approver returning a lease on a run-once rule gets
  the invocation approved and no window. Hostile `ttl_ms` extremes are safe in
  both directions: `u64::MAX` ms saturates through `.min(u32::MAX)` then
  `min(cap)`; `0` yields an already-expired lease that
  `retain(expires > now)` purges on the next touch.
- **SSH path unchanged (item 4): CONFIRMED byte-identical.** `git diff` touches
  no line of `approve_and_sign`. Still `LeasePolicy::RunOnce`, still
  `grant_key(caller, "", ssh_sign_scope(label, fingerprint))` folding the
  data-to-sign fingerprint, still no `token_for` and no `grant` on that path.
- **Audit on the lease short-circuit (item 8): CONFIRMED.** The short-circuit
  records *before* spawning (`daemon.rs:1622-1631`) with
  `audit_label(describe(argv), scope)` — the real argv, not the rule — and
  `via = "lease"`; no return path sits between the lease hit and the record.
  `a_leased_run_audits_the_command_it_actually_ran` proves both the label and the
  marker. One honest caveat: `record_audit` is a no-op when `core.audit` is
  `None`, so "the log cannot be skipped" holds only where auditing is configured
  at all. Pre-existing, not a regression.
- **TOCTOU between rule match and lease lookup: clean.** `config.snapshot()`
  pins one `Arc` for the whole decision (`daemon.rs:1468`), `action.rule` is
  cloned from it, and the lookup uses that clone, so a reload landing mid-decision
  cannot retarget the request in flight. The *cross-request* version of this
  problem is F3.
- **Zeroization: nothing to leak.** The lease token is an empty
  `Zeroizing<Vec<u8>>`; every removal path (`retain`, `clear`) drops it, and
  `token_for` clones an empty vec.
- **Store growth / DoS: strictly improved.** Grants happen only post-approval,
  `grant` de-dupes on (grant, account, scope) and purges expired entries first,
  and rule scoping collapses what used to be one lease per (argv, cwd) into one
  per rule. No cap, but no attacker-driven growth either.
- **Restart clears:** `serve` calls `core.leases.clear()` on ctrl-c
  (`daemon.rs:963`); RAM-only otherwise. Invariant #8's "killed by lockdown"
  clause remains vacuous because lockdown was removed in `e16b0da`, a prior
  decision this change does not touch.

### Reviewer proofs

Two tests were written against the real `fulfill`, run green (i.e. **both attacks
succeed**), and reverted rather than left in the implementer's file:

- `reviewer_proof_lease_covers_a_secret_the_human_never_saw` — F1.
- `reviewer_proof_lease_survives_a_config_edit_that_widens_its_rule` — F3.

If F1's caption is fixed and F3 is accepted as a residual rather than closed,
both belong in `daemon.rs` as permanent negative tests so the breadth is pinned
by the suite instead of by prose.

## Independent review verdict, round 2: rule-scoped leases + RAM cache + file-keystore default + SE wrapping (`ff926ef..`, WIP `d3887ad` plus uncommitted, 2026-08-04)

Scope: the total diff since the round-1 verdict. The F1-F8 closures, the
RAM-cached credential lease, the file-keystore default promotion, the
Secure-Enclave wrapping as built against the reviewer's design-phase S1-S10, the
relay origin hint, and §10a's claim rows. Reviewer wrote none of this code except
the four hostile-relay lease tests noted below. Findings are numbered **R2-Fn** to
avoid colliding with round-1's F1-F8 or the 2026-07-15 addendum's F9/F10.

**VERDICT: SOUND-WITH-RESIDUALS. The round-1 BLOCK on consent copy is LIFTED.
Nothing here blocks the landing.** No HIGH or CRITICAL findings. Every round-1
finding is closed, three of them better than specified. The SE wrapping implements
all ten design-phase items, and two of them (S1, S3) are resolved more soundly
than the contract asked. The residuals below are real but none of them changes a
threat class, and each is stated rather than hidden.

### Rulings requested

**The consent caption: BLOCK LIFTED.** It now reads "Also covers other {cmd}
commands and secrets this rule matches, from anywhere on this Mac." That names the
axis the human is actually looking at (other secrets, round-1 F1) and drops the
false "from this process" (round-1 F2). It is now *over*-broad rather than
under-broad: the window binds the caller chain's code identity, so a genuinely
different tool tree does not ride it. That is the correct direction to err for a
consent string, and the brief's mock-cap carries the precise version alongside.
Both halves of the round-1 block are closed.

**The source-fingerprint leg on `LeaseBinding`: SOUND, and better than what was
asked for.** Binding the sealed record's ephemeral point `E` means a re-seal, which
mints a fresh `E`, misses the cache instead of injecting a plaintext that no longer
exists on disk. That closes a gap pure config-invalidation would have left open,
because `source env set` need not touch `config.json` at all. It is also the right
*shape*: a content fingerprint rather than a version counter, so a rollback cannot
spoof it.

**The bundle identifier left unpinned: SOUND for today, with a recorded trigger.**
The rename argument is correct and a silent lockout would be worse than the
exposure. But the gate's actual meaning should be stated plainly: it authorizes
*any binary team 53W966FBFP ever signs*, not "the Sigil app". If RainnWorks ships a
second Mac product, that product silently inherits keystore-provision authority.
The rename-safe way to scope it is an allowlist rather than a pin
(`identifier "works.rainn.latch" or identifier "works.rainn.sigil"`), which keeps
a rename from ever being a lockout while still bounding the set. See R2-F5.

**The ECIES variable-IV variant: CONFIRMED sound.**
`.eciesEncryptionCofactorVariableIVX963SHA256AESGCM` is authenticated encryption
(AES-GCM), and the variable-IV form is *safer* than the fixed-IV one, which uses an
all-zero IV. The Enclave supports only the variable-IV variants, so this is a
platform constraint rather than a preference. It is nonetheless a deviation from
the libsodium-only house rule (P-256 ECDH + X9.63 KDF + AES-GCM), and the
justification is sound and should be recorded as such: the entire point is to use
hardware that speaks only its own algorithms, so every alternative means not using
the Enclave at all.

**The relay origin hint: display-only, CONFIRMED.** `Origin.ip` is rendered from a
parsed `IpAddr`, so attacker-chosen free text can never reach a UI. `client_ip`
indexes from the RIGHT of the forwarded chain, so a client prepending fake entries
only pads the left and pushes its own real address into the chosen slot;
`trusted_hops` defaults to `0`, at which the header is not read at all. It is not
persisted, not logged, and dies with the item's TTL. The phone labels it "relay
reported" and the session layer calls it "the carrier's unverified claim". Nothing
anywhere branches on it. The one real risk is the misconfiguration the module doc
already calls out loudly: `trusted_hops` set higher than the true proxy count puts
the index inside client-written text.

### Round-1 closures, verified

- **F1, F2: closed** (see the ruling above).
- **F3 (lease invalidation on config reload): closed.** `reload_config` now calls
  `invalidate_leases_for_config_change`, which kills any lease whose rule did not
  survive *identically* (whole-struct comparison, plus the resolved source), and
  fails safe by treating anything it cannot pair up as changed. Residual race in
  R2-F6.
- **F4 (kind tags): closed, better than requested.** Rather than a string prefix,
  `grant_key` takes a typed `lease::ScopeKind` (`Command` / `SshSignature`) and
  hashes its tag length-prefixed alongside every other field. The two scope
  namespaces can no longer collide by construction rather than by convention.
- **F5 (vacuous account leg): closed by the RAM-cache path.** Sealed inline `env`
  rules now lease, so `LeaseBinding.account` carries a real source name for exactly
  the leases that hold values. The binding is no longer two-legs-and-a-constant.
- **F6: superseded**, reconciled in place on 2026-08-04.
- **F7 (phone lease list): closed, beyond what was asked.** The brief marks the
  section `planned`; the phone renders no revoke control, shows sample rows only
  under `DEMO`, and deliberately refuses to render "No active leases" because a
  phone that cannot see the Mac's leases saying so is a false statement of fact.
  Both surfaces name `sigil lease revoke <prefix>` as the real mechanism.
- **F8 (hostile-relay lease case): closed by the reviewer in this pass.** Four
  tests added to `crates/sigil-proto/tests/hostile_relay.rs`:
  `relay_cannot_forge_a_lease_grant`, `relay_cannot_lengthen_a_lease_window`,
  `relay_cannot_attach_a_lease_to_a_deny`, and
  `a_lease_grant_cannot_be_replayed_to_reopen_an_expired_window`. Suite green at
  22 tests.

### The RAM-cached credential lease: SOUND

- **Unseal-before-grant ordering is correct.** Every `fail_closed` in the threshold
  open returns before `leases.grant`, so a failed open leaves no window behind.
- **The per-run consent re-check is real, not decorative.** `leased_env` re-decodes
  the cached blob on every leased run and re-runs `env_keys_match` against the rule
  *as it stands at that moment*; a corrupt blob or a moved key set is refused, the
  lease is dropped, and the run re-gates rather than injecting. A window can only
  ever inject what a fresh approval would have injected.
- **Invalidation is genuinely triple:** TTL, config change (F3), and re-seal (the
  `E` fingerprint), plus explicit revoke and daemon restart.
- **F2's blast radius, re-examined as instructed:** it is now larger in kind, not
  just degree. A live window releases credential *values* rather than skipping a
  prompt, so the caller-chain imitation residual costs unsealed secrets during the
  window. This is exactly why F3 was mandatory, and F3 closed. The values remain
  RAM-only, `Zeroizing`, and dead on every removal path.

### The SE wrapping as built, against S1-S10

All ten adopted. Two resolved better than the contract specified:

- **S1 (write-back) is resolved by construction, not by machinery.** `RamKeystore`
  refuses `store_blob`/`delete_blob` outright, and all four `pairing_store`
  mutations call `refuse_if_sealed` as their first statement. I verified the
  "by construction" claim independently: every `store_blob`/`delete_blob` call site
  in the tree is in `pairing_store` or `threshold`, all CLI-driven, all reachable
  only through those refusals or through the type's own `Sealed` error. Deferring
  the commit flow because it has no trigger is the right call; machinery with no
  trigger rots untested.
- **S3's digest binds the exact wrapped bytes rather than a canonical
  re-encoding.** This is better than what I recommended: it removes the
  cross-implementation agreement problem (ordering, escaping, whitespace, forever)
  entirely, and it commits to the bytes the daemon actually parses, which is the
  thing that must be authentic.
- S2 marker lives outside the file, with an honest same-UID residual. Worth stating
  that **the app-side alarm is the stronger of the two detectors**: it keys off the
  Enclave key's continued existence, which an attacker cannot delete without the
  app's keychain ACL, whereas `~/.sigil/adopted` is a same-UID file. S4's four
  sub-points are all present (peer gate first, once-per-lifetime checked *before*
  the payload is read, no latch on failure, constant-time bare ok/fail). S5's
  hardened runtime and `get-task-allow off` are configured in `project.yml`. S6
  reads once in `Core::for_host` before `serve` binds the listener. S7's orderings
  use fsync-then-atomic-rename, and `explain()` never says "re-pair" (pinned by
  test). S8's binary framing is in place and `KeystoreFile` deliberately derives no
  `Debug`. S9's at-rest framing is adopted verbatim and stated well. S10's field is
  gone.

### Findings

**R2-F1 (MEDIUM). The adoption marker records `se_pub` and nothing ever compares
it.** `set_adopted(se_pub)` writes the wrapping key's public half into
`~/.sigil/adopted`, but `SealState::resolve(file, adopted)` takes only a `bool` and
never compares the marker's `se_pub` against the file's. So substituting a v2
keystore wrapped to an *attacker's* Enclave key yields `Sealed` with the attacker's
expected digest, the attacker's app provisions it, and the daemon comes up paired
to the attacker's phone with no alarm on either side (the app-side detector keys on
its key still existing, which it does). This sits inside the already-admitted
file-write class and changes no threat class, but it is the one place where the
code collects exactly the evidence needed and then discards it. *Fix:* have
`resolve` take the marker's recorded `se_pub` and yield `Downgraded` (or a distinct
`KeyChanged`) on mismatch.

**R2-F2 (MEDIUM-LOW). Zeroization does not cover the JSON/base64 intermediates, and
one realloc frees material un-wiped.** Concretely: (a) `local.rs::read_payload`
does `let mut out = tail; out.reserve_exact(more)`, and Vec growth copies the tail
(for a single-`recvmsg` provision, the whole material) into a fresh allocation and
frees the old one, which `Zeroizing` never sees; (b)
`keystore.rs::RamKeystore::from_material` parses into `HashMap<String,String>`
whose Strings hold base64 of the identity key and `m`, dropped un-zeroized; (c)
`keystore_seal.rs::KeystoreFile::parse` materializes the same Strings through
`serde_json::Value` when it only needs to test for key presence. `FileKeystore::read`,
now the default store, shares the pattern on every load. Impact is modest, since
same-UID RAM reading is already conceded. But the §10a row and `local.rs`'s own
comment ("material never rests in a plain allocation") claim more than the code
delivers. *Fix:* pre-size with `Vec::with_capacity(len)` in (a), and either narrow
(b)/(c) or soften the claim to "the transport buffers are `Zeroizing`; the JSON and
base64 parse products are not, a known residual".

**R2-F3 (LOW). An unrecognized `SIGIL_KEYSTORE` value silently selects a different
security posture.** `for_host`'s `_ =>` arm routes any unknown value to the file
store with no notice, because `note_once` runs only on the recognized arms. So
`SIGIL_KEYSTORE=keychian` silently yields a plaintext file store; the user then
meets "no pairing" and, by this codebase's own hard-won principle, may re-pair and
orphan the real one. §10a currently documents this as a feature. *Fix:* print the
one-time notice for any unrecognized non-empty value, naming what was asked for and
what was selected. The machinery exists: `legacy_keychain_notice` already handles
the keychain-to-file case well, and is correctly wired into both the daemon and
`up`.

**R2-F4 (LOW). The code-identity gate could bind the audit token rather than the
pid.** `peercode.m` resolves the guest via `kSecGuestAttributePid`, and both it and
`peercode.rs` honestly document the pid-recycle limit as "the tightest binding this
API offers". It is not: macOS exposes the peer's `audit_token_t` on a unix socket
via `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)`, and `SecCodeCopyGuestWithAttributes`
accepts it as `kSecGuestAttributeAudit`. An audit token is not reusable, so it
eliminates the race rather than narrowing it, and it is Apple's documented
recommendation for exactly this case. Low severity given the window is tiny and the
connection is held open, but the doc claim should change even if the code does not.

**R2-F5 (LOW). The requirement admits any binary the team ever signs, including
development-signed ones.** See the ruling above for the bundle-id trade. Separately:
`certificate leaf[subject.OU]` matches Apple Development certificates as well as
Developer ID, so a dev-signed build by anyone with team cert access satisfies the
gate. Adding the Developer ID marker OID
(`certificate leaf[field.1.2.840.113635.100.6.1.13]`) would restrict it to
distribution builds. Optional for a single-developer team; the trigger to act is a
second signed Mac product existing.

**R2-F6 (LOW). Lease invalidation is not atomic with respect to in-flight
approvals.** `fulfill` snapshots the config, blocks on the phone for up to the
approval timeout, then grants. A config edit landing during that wait runs
invalidation *before the lease exists*, and the grant then files a window under the
rewritten rule with pre-edit material; if the rule's source is unchanged the
`LeaseBinding` still matches, so the window is live under the new definition. Same
file-write adversary as F3, so no new threat class, and the source-fingerprint leg
catches every case where the sealed source moved. *Complete fix, cheap:* stamp a
config generation counter (bumped on every successful `ConfigCell::store`) into
`LeaseBinding`, so any reload during an approval invalidates that grant by
construction.

### Process note

The tree was still being edited during this pass: `cli.rs` and `keystore.rs`
churned underneath the review, and `cargo clippy` failed transiently with two
different errors minutes apart before going clean. Gate as measured at completion:
**512 rust tests pass, 0 failures; clippy clean; `cargo fmt --check` dirty only in
`cli.rs` and `keystore.rs` from that in-flight work, not from the reviewer's
addition** (`hostile_relay.rs` was formatted). The security-critical paths this
verdict covers (`keystore_seal.rs`, `peercode.{rs,m}`, `lease.rs`, `daemon.rs`
fulfil/provision/unwrap, `keystore.rs`) were stable throughout. Re-run the gate on
the settled tree before landing; this verdict does not certify whatever `cli.rs`
becomes.

### Closure check: the R2 fix round (2026-08-04, same reviewer)

Each fix verified against the code, not the report. Gate re-measured on the
settled tree: **516 tests pass, 0 failures; clippy clean; `cargo fmt --check`
clean.** The four hostile-relay lease tests from the verdict above still pass.
**Nothing in the fix round regresses the verdict: it stands at
SOUND-WITH-RESIDUALS, and the round-1 consent-copy block stays LIFTED.**

- **R2-F1 CLOSED.** `SealState::resolve` now takes `Option<&AdoptionMarker>` and
  compares the marker's recorded `se_pub` against the file's; a mismatch is
  `KeyChanged`, which `blocks_serving` unconditionally and explains as a
  substituted keystore. The corrupt-marker path is the part worth checking and it
  is right: `read_adoption_marker` returns `Some` with an EMPTY `se_pub` rather
  than `None`, so mangling the marker cannot decay "adopted, key unknown" into
  "never adopted" and clear the tripwire; an empty key matches nothing and
  resolves to refusal. The first-run `(V2, None)` case still accepts any wrapped
  file, which is correct and necessary for adoption to ever happen, and leaves the
  already-recorded residual (marker deletion is the same same-UID file write) 
  unchanged.
- **R2-F4 CLOSED.** `require_sigil_app` reads the peer's `audit_token_t` via
  `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)` and evaluates it through
  `kSecGuestAttributeAudit`. There is no pid fallback: an unreadable token is
  `NoPeer`, a refusal. `pid_satisfies` survives only as a test entry point, and
  the negative/positive/malformed-requirement tests were kept alongside a new one
  proving a real socketpair yields a token and a non-socket fd does not. The race
  is eliminated rather than narrowed, so the honest-limit wording in both
  `peercode.rs` and `peercode.m` was corrected too.
- **R2-F6 CLOSED, and more conservatively than requested.** `ConfigCell` carries a
  generation bumped on every store, and `fulfill` stamps the generation of the
  snapshot *this decision resolved against* into `LeaseBinding`. Since the same
  binding is used for both the lookup and the grant, the practical effect is
  broader than the race I raised: **any** config write now makes **every** live
  window unusable, not only those whose rule moved. That errs closed and is fine
  here, but it is a real behavioral change worth knowing: editing one rule ends
  unrelated windows. Note the two mechanisms are complementary rather than
  redundant, and both should stay: the generation stamp makes a stale grant
  *unusable*, while `invalidate_leases_for_config_change` makes it *gone*, which
  matters because a stale sealed-`env` lease holds cached plaintext that would
  otherwise sit in RAM until its TTL. `a_reload_during_an_approval_kills_the_grant_that_lands_after_it`
  pins exactly the flagged ordering, storing an identical config so the selective
  matrix deliberately keeps the lease and only the stamp refuses it.
- **R2-F2 CLOSED (a), MITIGATED AND HONESTLY STATED (b/c).** `read_payload`
  pre-sizes with `Vec::with_capacity(len)`, extends from the tail, and drops the
  tail, so the abandoning realloc no longer exists; the exact-fit path was also
  tightened from `>` to `>=` so a tail that exactly fills the payload no longer
  falls into the growth branch. `KeystoreFile::parse` classifies through
  `serde::de::IgnoredAny`, so a v1 file's blobs are never materialized.
  `RamKeystore::from_material` still receives base64 through serde `String`s but
  wipes them after decoding, with a comment saying plainly that serde allocated
  them first. The §10a row now states the scope exactly instead of claiming the
  material never rests in a plain allocation. That is the right resolution: the
  claim matches the code, and the remainder sits inside the same-UID RAM reading
  this design already concedes.
- **R2-F3 CLOSED.** Any unrecognized non-empty value that is not `file` now prints
  a one-time notice naming what was asked for and what was selected, and warns
  that a pairing made under another store will not be found. The silent posture
  change is gone, and §10a no longer documents it as a feature.
- **R2-F5 CLOSED as a recorded residual**, with the trigger stated (a second signed
  Mac product existing) and the two tightening options noted. Correct disposition
  for a single-developer team; no action needed today.

House-rule check: the implementer's edits to this document add behavior rows to
§10a only and contain no verdict language, and the round-2 verdict section above
is untouched. Nothing further is outstanding from rounds 1 or 2; this reviewer has
no objection to the landing.

## Independent review verdict, round 3: caller code identity measured by cdhash (`6c71207`, merged `a032e6c`, 2026-08-07)

Scope: the whole of `6c71207` -- `IdentityMeasure`/`CodeIdentity` and the measure
tag in `grant_key`, the `FileStamp` measurement cache, `peercode.m::sigil_cdhash_for_path`
and its Rust wrapper, and the doc changes in `lease.rs`, the brief, and §7 above.
Reviewer wrote none of this code. Findings are numbered **R3-Fn** to avoid
colliding with F1-F8, F9/F10 or R2-F1..F6. Gate re-measured on the merged tree:
**561 tests pass, 0 failures; clippy `-D warnings` clean; `cargo fmt --check` clean.**

**VERDICT: SOUND IN CONSTRUCTION, OVERSTATED IN CLAIM. Does not block the landing;
does require the two doc corrections below and should not be described to anyone
as tamper-evidence.** The domain separation is right, the ad-hoc call is right, and
the kernel-enforcement reasoning is (independently verified) true of the image the
kernel executed. What is not true is the sentence that connects them: because the
measure is a *static read of the path* rather than a measurement of the *running
image*, a same-UID caller chooses what it is measured as, and the kernel is not in
that loop at all. One HIGH (R3-F1), one MEDIUM-HIGH regression against the code
this replaced (R3-F2), and four smaller items.

Nothing here changes the round-1 or round-2 verdicts, and nothing here weakens the
rule-scoped-lease or RAM-cached-credential conclusions on their own terms: those
rested on the caller chain telling *honest* tool trees apart, which is still what
it does. They did not rest on the chain resisting an adversary, and after this
change they still must not.

### Rulings on the three flags the implementer raised

**1. The exec-path measurement race, and the static-vs-dynamic trade: the trade is
WRONG, and it is not the trade it was described as.** The dynamic answer is not
the expensive one. Measured on this machine (M-series, macOS 26.3), per ancestor:

| measurement | cost |
|---|---|
| `SecCodeCopyGuestWithAttributes` + `SecCodeCheckValidityWithErrors` + cdhash, warm (large ad-hoc binary, `node`) | **0.08 - 0.12 ms** |
| same, cold / first call in a process | 1.5 - 7.6 ms |
| current static path measure, cold (implementer's own figures) | 0.6 ms small, ~11 ms for the 40 MB `op` |
| `SecStaticCodeCheckValidity` strict, the rejected option | ~200 ms |

So the dynamic guest lookup costs *less* than the static cdhash it would replace,
needs no measurement cache to be affordable, and closes the race instead of
conceding it. It also detects both swap flavours: with the process still running,
overwriting its path in place (`cp -f`) or renaming a new file over it both turn
`SecCodeCheckValidityWithErrors(guest, NULL)` from `0` into `-67034`
(`errSecCSStaticCodeChanged`), while the static read reports the substituted
file's identity without complaint. This is the same machinery `peercode.m`
already uses for the keystore gate, which is consequently *not* vulnerable to this
(verified: after a swap, the guest requirement check refuses).

`csops(pid, CS_OPS_CDHASH)` is not an option here: it returns `EPERM`
cross-process and `EINVAL` for self on this OS version.

**The cache stamp does not narrow the race, and it does give false confidence.**
The before/after stamp comparison guards a *benign* concurrent replacement (it
declines to file a torn measurement). It is not an adversarial check, and the
stamp itself is forgeable -- see R3-F2.

**2. Kernel enforcement: yes, the kernel is the real enforcement, and it is real
and broader than the one binary tested.** Independently verified here:

* A page-tampered copy of a *platform* binary (`/bin/ls`) is SIGKILLed at exec
  (exit 137), as reported.
* A page-tampered copy of a *non-platform, Developer-ID, hardened-runtime* binary
  (`1Password.app/Contents/MacOS/1Password`) is also SIGKILLed (exit 137). The
  generalisation past platform binaries holds on Apple Silicon.
* Appending bytes past the signed limit does not move the cdhash, but the result
  is also SIGKILLed at exec, so it collapses into the same story.
* `csops(CS_OPS_STATUS)` on a plain ad-hoc linker-signed, non-platform process
  here returns `CS_VALID|CS_KILL`, so the kill applies to the `Content` population
  too, not only to signed code.

What a signed binary whose signature the kernel does not enforce means in practice
is therefore *not* mainly about weakly-signed binaries; on this platform that set
is close to empty. It is about the three places enforcement does not reach: pages
that are never faulted; code loaded into a process after exec where library
validation and the hardened runtime are off (a cdhash names the executable, never
what it later loaded or, for an interpreter, what script it is running); and, the
one that matters, **the file being swapped after exec, which the kernel has no
opinion about because it is not the image it validated.** The docs must say that
the kernel vouches for the image it executed, not for the answer this code returns.

**3. The ad-hoc fallback is CORRECT, and the domain separation is correctly
implemented -- but it prevents confusion, not a chooser.** Treating an ad-hoc
signature as no identity is the right call: it has no signer, so its cdhash
asserts nothing a content hash does not, and tagging it `Signed` would be a lie
told in a security-relevant field. The separation itself is sound: the tag is
length-prefixed ahead of the digest in `grant_key` (`lease.rs:307-310`), exactly
as `ScopeKind` is, and the three-way separation is tested.

On the confusion attack specifically: **no, an attacker cannot use the tags to
land on a victim's grant key, because the tags are not where the weakness is.** An
attacker freely *chooses* which branch their file takes (ad-hoc sign it for
`Content`; give it a non-ad-hoc signature blob for `Signed`), so the separation
buys nothing against them; it buys correctness against accidental collision, which
is worth having. Having chosen the branch they still need the victim's path and
digest -- and R3-F1 hands them both. Worth recording: **`kSecCodeInfoUnique` is
returned without any validity check, so the cdhash a file reports is whatever its
CodeDirectory says, not a fact about its bytes.** Verified: a page-tampered copy
of `/bin/ls` reports the pristine cdhash `4f35b316...`, and a tampered copy of the
40 MB `op` reports the pristine `9c2bfc85...`. A file can therefore claim any
identity its author cares to copy; only the kernel stops it *running*.

### Findings

**R3-F1 (HIGH). The grant key measures the file at the ancestor's path, not the
code that is running there, so a caller who can write that path chooses its own
code identity -- including a victim's exactly.** `lease.rs:692-699`
(`SysProcessTable::identity` -> `exe(pid)` -> `measure_executable`),
`lease.rs:620-648`, `peercode.m:113` (`SecStaticCodeCreateWithPath` on a path).

Demonstrated end to end. A process is started from a path holding an ad-hoc binary
(measured `Content`, digest of those bytes). While it is still running, the file at
that path is replaced with `/bin/ls`. The static measure the daemon uses then
reports `IdentityMeasure::Signed` with `/bin/ls`'s cdhash
`4f35b3163233a684d47f496a1e050f518de37621` for a process that is running none of
that code. The same result via `rename(2)` as via in-place overwrite. Meanwhile the
dynamic guest check on that pid returns `-67034 errSecCSStaticCodeChanged`, i.e.
the platform can tell and this code did not ask.

Attack, concretely: the attacker wants an ancestor entry that hashes identically to
a victim's. They copy the victim binary aside, put their own executable at the
victim's path, exec it, restore the genuine file at that path, then run the gated
command. Every ancestor field the grant key binds -- path, measure tag, digest --
now matches the victim's, so `grant_key` collides with the live lease and the
release happens with **no phone round trip**, including the sealed-`env` lease that
holds unsealed credentials in daemon RAM. The paths this requires write access to
are ordinary user-writable ones on this machine: everything under `/opt/homebrew`,
`~/.local/bin`, cargo/npm shims, and `~/.sigil/bin/sigil` itself.

*Invariant:* #6 (caller identity is daemon-verified). The daemon does derive the
identity itself -- and the value it derives is attacker-selected. *Severity:* HIGH
rather than a restatement of the conceded same-UID residual, because the module
docs sell this measure as backed by kernel tamper-evidence
(`lease.rs:31-38`: "anything that actually appears in a chain under this measure is
code the kernel accepted as that cdhash"). That sentence is false as written, and
it is the sentence a future reader will lean on.

*Fix:* measure the running image. Resolve the ancestor to a guest code object
(`SecCodeCopyGuestWithAttributes` with `kSecGuestAttributePid`), call
`SecCodeCheckValidityWithErrors(code, kSecCSDefaultFlags, NULL, NULL)` and treat
anything but `errSecSuccess` as `Unmeasured` (the swap shows up as `-67034`), then
take `kSecCodeInfoUnique` from that object. Costs less than the current cold path
(table above) and removes the need for the `FileStamp` cache entirely; if a cache
is still wanted, key it on pid plus process start time, not on the file. Note the
leaf could do better still: `peercode::peer_audit_token` already gives a
recycle-proof identity for the socket peer, and only the ancestors need the pid
form.

*Failing test:* the reproduction harness is at
`/private/tmp/claude-501/-Users-tom-Projects-op-remote/f5633d91-0072-489e-a1eb-664011533f87/scratchpad/`
(`measure_probe.c`, `guest_req.c`); it is a two-process scenario, so it belongs in
an ignored integration test rather than the unit suite.

**R3-F2 (MEDIUM-HIGH, and a regression against the code this replaces). The
measurement cache serves a stale identity for a stamp-preserving rewrite; every
field of `FileStamp` is settable by the file's owner.** `lease.rs:559-586`
(`FileStamp`), `lease.rs:620-648` (`measure_executable`).

`path`, `dev`, `ino`, `size`, `mtime`, `mtime_nsec`: an in-place rewrite at the
same length preserves the first four, and `utimensat` restores the last two to the
nanosecond. `ctime` is the one field that moves, and it is not in the stamp. So a
same-UID attacker patches an ancestor executable in place, pads to the original
length, re-signs it ad-hoc so the kernel will still run it, restores mtime, and the
daemon serves the *pre-patch* identity for the rest of its lifetime. The pre-change
code re-read and re-hashed the file on every gated command and would have caught
exactly this; the cache is what introduces it. The comment at `lease.rs:559-562`
("a rebuild, a `brew upgrade`, or a swap of the binary invalidates the entry by
missing it") is true of honest change only and should say so.

Proven against the real code, not by inspection. Dropping this into
`lease.rs`'s test module fails today:

```rust
#[test]
fn a_stamp_preserving_rewrite_is_re_measured() {
    use std::os::unix::ffi::OsStrExt;
    let dir = scratch("cache-forge");
    let f = dir.join("artifact");
    std::fs::write(&f, vec![b'A'; 4096]).unwrap();
    let first = measure_executable(&f).expect("measures");
    let stamp = FileStamp::of(&f).unwrap();

    std::fs::write(&f, vec![b'B'; 4096]).unwrap(); // same length, new bytes
    let ts = libc::timespec { tv_sec: stamp.mtime, tv_nsec: stamp.mtime_nsec };
    let times = [ts, ts];
    let c = std::ffi::CString::new(f.as_os_str().as_bytes()).unwrap();
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) };
    assert_eq!(rc, 0, "the owner may always restore mtime");
    assert_eq!(Some(&stamp), FileStamp::of(&f).as_ref(), "all five fields restored");

    let second = measure_executable(&f).expect("measures");
    assert_ne!(first.digest, second.digest,
        "different bytes must not be served the old measurement");
    let _ = std::fs::remove_dir_all(&dir);
}
```

Observed: `assertion left != right failed: different bytes must not be served the
old measurement`, both sides `75dd7676...`. The existing
`replacing_the_file_at_a_path_invalidates_the_cached_measurement` passes only
because it moves the size as well as the content.

*Fix:* add `ctime`/`ctime_nsec` to `FileStamp` (available on `MetadataExt`,
un-forgeable by the owner) -- one line, and it kills the cheap version of this. The
finding disappears outright under R3-F1's fix, which stops keying identity on a
file at all.

**R3-F3 (MEDIUM, doc-correctness). "A userspace re-check does not work" is half
right, and the wrong half is the one written down.** `lease.rs:36-38`,
`peercode.m:100-105`.

Measured on a fresh, never-executed page-tampered copy of `/bin/ls`:
`SecCodeCopySigningInformation` returns the pristine cdhash;
`SecStaticCodeCheckValidity(code, kSecCSDefaultFlags, NULL)` returns `0 SUCCESS`
(the implementer's result reproduces exactly); but
`SecStaticCodeCheckValidity(code, kSecCSDefaultFlags | kSecCSCheckAllArchitectures | kSecCSStrictValidate, NULL)`
returns `-67671`, a refusal (it decodes to a generic internal error rather than a
named tamper verdict, but it is emphatically not success). `codesign -v` also
catches the same file, on `/bin/ls` (exit 1)
and on the tampered 40 MB `op` (exit 1). So the accurate statement is "a
*default-flag* validity check passes a page-tampered Mach-O, and a strict one costs
~200 ms", not "a userspace re-check still passes it". Keep the decision -- at
~200 ms per ancestor it is the right call, and R3-F1's dynamic check is both
cheaper and more relevant -- but fix the sentence in both files. The wrong version
would justify skipping validation somewhere it is the only check available.

**R3-F4 (LOW-MEDIUM). `Ancestor.exe` and `Ancestor.identity` are resolved by two
independent `proc_pidpath` calls, so they can describe two different processes.**
`lease.rs:238` (the trait takes a pid, not a path), `lease.rs:251-252` (walk
resolves the path), `lease.rs:696` (`identity` resolves it again). A pid recycled
between the two pairs one process's path with another's digest. This fails closed
-- the mismatched pair derives a key nobody holds, so the caller takes a fresh
approval -- and it is not a widening. It is worth removing anyway because it costs
nothing: pass the already-resolved path into the measurement and the window is
gone. R3-F1's fix should take the identity from the same guest object the walk
resolved, for the same reason.

**R3-F5 (LOW). `Unmeasured` does not "coalesce with nothing"; it coalesces with the
same pid at the same path.** `lease.rs:138-141`, `lease.rs:188-193`. The digest is
`BLAKE2b(pid)`, so two requests whose ancestor is unmeasurable at the same path and
the same pid derive one grant key. That reintroduces, in the one branch where the
measure failed, precisely the pid dependence the grant key excludes pids to avoid
(and which `grant_key_ignores_recycled_pids` exists to pin). A caller can force the
branch deliberately (make its own exec path unreadable after exec) and can choose
its pid by spawning; the victim would have to be `Unmeasured` at the same path too,
so this is a narrow equivalence rather than a widening, hence LOW. *Fix if touched:*
derive the unmeasured digest from pid plus process start time, or -- the
fail-closed reading -- decline to lease at all when any ancestor is `Unmeasured`.
The comment at `lease.rs:138-141` and the test name
`an_unmeasurable_ancestor_coalesces_with_nothing` both currently overstate.

**R3-F6 (LOW, pre-existing). `std::fs::read` of an ancestor executable is
unbounded.** `lease.rs:634`. A padded ad-hoc Mach-O of arbitrary size is read whole
into daemon memory on the `Content` path -- which on this machine is most of a dev
box (`cargo`, `node` and the `sigil` shim itself are all ad-hoc here, so the leaf of
every chain takes this path). The old code did the same on every request, so this is
not a regression, and the failure mode is fail-closed (daemon death takes the leases
with it). Streaming into the hasher removes it.

### Verified clean

* **Domain separation of the three measures.** Length-prefixed tag ahead of the
  digest, no shared namespace, tested three ways. No collision is constructible
  through the tags.
* **`caller_pid` is not client-supplied.** `sshagent.rs:324` reads it via
  `lease::peer_pid` off the socket; the `Option<i32>` field is populated by the
  daemon and is `None` in tests only. Invariant #6 holds on that axis.
* **Secrets, logging, relay.** `CodeIdentity` is 33 bytes of non-secret
  measurement, never persisted, never logged, never sent. Provenance to the phone
  is still file names only, the grant hex is still echo-only, and no part of this
  change touches the op child's stdout path, the envelope, or the relay.
  Invariants #2 and #3 untouched.
* **Fail-closed on every measurement error.** An unresolvable exe truncates the
  walk (a shorter chain is a different key, never a superset), an unmeasurable one
  becomes `Unmeasured` with a pid-derived digest, and a torn measurement is
  returned but not cached. No error path falls through to a wider key. Invariant #7
  holds.
* **The keystore gate is not affected by R3-F1.** It uses the audit token and a
  dynamic guest check, which refuse after a post-exec swap (verified). R2-F4's
  closure stands.
* **Ad-hoc classification.** `peercode.m:155` tests `kSecCodeSignatureAdhoc`
  explicitly and returns "no identity"; `errSecCSUnsigned` returns the same. Both
  land on `Content`. Correct, and correctly tested on both sides.

### Behaviour change worth telling the human about

Two, and the second is the one that is easy to get wrong:

1. **Grant keys moved once.** Live leases from a pre-upgrade daemon do not match
   afterwards. RAM-only, so the cost is one extra approval. Accurately stated by
   the implementer.
2. **A re-signature of unchanged code is now the same caller; a rebuild is not.**
   The cdhash covers the CodeDirectory, so it moves whenever the code moves. What
   no longer forces a fresh approval is a certificate renewal, a re-notarisation,
   or any other re-sign of byte-identical code inside a live lease window -- and
   under the old content hash that would have re-prompted, because the signature
   bytes changed. This is the correct behaviour and the window is bounded by the
   lease TTL, but "leases survive a rebuild of signed software" is the wrong way to
   describe it and should not be written anywhere: they survive a re-*sign*.

### Residuals restated, so this change is not read as narrowing them

The caller-chain imitation class is **unchanged by this commit and remains the
dominant limit**. An attacker who can run a process as this user does not need any
of the above: they can spawn under the same ancestors and run the genuine gated
command, and the chain matches by construction. The cdhash measure adds no defence
there. Its value is telling *honest* tool trees apart, and R2's consent-caption
reasoning ("a genuinely different tool tree does not ride the window") should
continue to be read as a statement about honest trees only. Alongside it stand the
already-recorded residuals this change does not touch: the shim symlink making the
chain leaf identical for every gated command, lease-window imitation, approved-
consumer misuse, and metadata at the relay.

## Independent review verdict, round 4: guest-object measurement, the process-instance branch, and the lease coverage label (`4cfb017`, `e472e4c`, `e895c5d`, `c37c776`, `8f0e76b` + the phone/Mac renderers, tip `e895c5d`, 2026-08-07)

Scope: **Part A**, the five R3 findings as fixed, plus the beyond-brief decision to
keep an ad-hoc binary's guest cdhash instead of falling back to a byte hash.
**Part B**, the daemon-rendered lease coverage label, which had had no security
pass and no row in this document. Reviewer wrote none of this code and wrote the
R3 verdict that drove most of it. Findings are numbered **R4-Fn**. Gate
re-measured on the merged tree: **477 tests pass, 0 failures** (354 `sigil`, 79
`sigil-proto`, 23 `pairing_mitm`, 21 `hostile_relay`); `cargo clippy --all-targets
-- -D warnings` clean; `cargo fmt --check` clean.

**VERDICT: LANDS. All five R3 findings are closed, and the two the implementer was
least sure of (R3-F3's page-tampering wording, R3-F5's move off fail-closed) are
both confirmed correct on independent evidence.** Part A is now the strongest form
of this measurement available without leaving Security.framework. Part B is
correctly built at the one place it should be and is provably display-only, with
one real defect on the consent surface: **R4-F4 (MEDIUM)**, the choke point that
the phone, the Mac and this document all describe as stripping control characters
strips only Unicode `Cc`, so bidi overrides and combining marks reach the caption
whose job is to state how wide the window is. That is a consent-surface integrity
defect, not a privilege escalation, and it does not block the landing; it should
be fixed before anything else is added to the label's vocabulary. Everything else
below is LOW or doc-accuracy.

### Part A: rulings on the R3 findings

**R3-F1 (was HIGH) - CLOSED.** `sigil_cdhash_for_path` is gone from `peercode.m`;
`grep` finds no `std::fs::read` of an ancestor executable anywhere outside test
fixtures; `measure_guest` resolves the live guest by pid, calls
`SecCodeCheckValidityWithErrors`, and only then reads both the cdhash and the
executable path off that same object. The swap cases demonstrated in round 3 no
longer move identity: the ported tests exercise rename-over and same-inode
overwrite and both land on `Unmeasured`, keyed to the process instance rather than
to anything the attacker chose. Nothing path-derived leaks back in: `proc_path` is
called only on the branch where the platform has already refused to describe the
image, and its answer is kernel-supplied. **R3-F4 closed with it** - one object,
one resolution, so a recycled pid can no longer pair one process's path with
another's measurement.

**R3-F2 (was MEDIUM-HIGH) - CLOSED by deletion.** No cache type exists on this
path: `FileStamp`, `measure_executable` and every memoization are gone, and the
only `OnceLock` left in `lease.rs` is the non-secret unmeasured-note registry. The
failing test is ported to the scheme that replaced the cache
(`a_stamp_preserving_rewrite_is_never_served_the_old_identity`) and asserts the
right thing: not that the forgery is detected, but that the pre-rewrite
measurement is never served again.

**R3-F3 (was MEDIUM, doc-correctness) - CLOSED, and independently reproduced.**
Measured here on this machine, not taken on trust. An ad-hoc signed copy of
`/bin/ls`, one byte flipped inside `__text`:

* default-flag `SecStaticCodeCheckValidity` returns `0` - it **passes** the
  page-tampered Mach-O, and `kSecCodeInfoUnique` still reports the unchanged
  cdhash `948936696ebc1070006ba74cf7364d9d6c6907ec`;
* `kSecCSCheckAllArchitectures | kSecCSStrictValidate` returns `-67671` - it
  refuses;
* the kernel `SIGKILL`s the image on exec (exit 137), so a page-tampered binary
  cannot be a live guest at all.

So the corrected wording is accurate, and the implementer's own finding - that the
guest check catches SUBSTITUTION but not page tampering, because a patch under an
intact CodeDirectory does not move the cdhash - is **confirmed**. The new "what
this is NOT: tamper-evidence" section describes it correctly and should stay
worded as it is. One calibration note on the cost figure: `codesign -v --strict`
is ~10ms on `/bin/zsh` here and 1.66s on a 375MB binary, so "~200ms per binary" is
representative of a large binary rather than of a typical ancestor. It does not
change the conclusion, and the conclusion is in fact stronger than the cost
argument makes it: strict validation is not a rejected trade-off, it is *moot*,
because the thing it would catch cannot be running.

**R3-F5 (was LOW; re-argued as a move off fail-closed) - ACCEPTED. No
impersonation opening found.** Attacked on each of the four axes named:

* *pid recycling against start-time granularity.* Both halves are kernel-supplied:
  the pid off `LOCAL_PEERPID`, the start time from `proc_bsdinfo.pbi_start_tvsec/
  tvusec`, which the kernel sets at fork and no process can set for itself.
  Neither is ever read from the client. To collide with a victim's key an attacker
  must present the same pid **and** the same microsecond, which is to say be that
  process instance.
* *inducing the branch deliberately.* An attacker who can write an ancestor's exec
  path can push it to `Unmeasured` at will - but doing so **moves** the grant key,
  destroying any window keyed to the old identity rather than joining one. The
  gain is denial, in the fail-closed direction.
* *"the window keeps serving whatever that process goes on to run".* The sharpest
  form is that the digest is invariant across `exec` (macOS preserves a process's
  start time through exec), so a process that is unmeasurable both before and
  after an exec keeps its window across a total change of the code it runs.
  Reaching that requires code execution inside the ancestor, which is the
  pre-existing dominant residual; and it is precisely what the module docs already
  say out loud. Documented, not hidden.
* *the leaf.* Confirmed: the shim is a fresh process per gated command, so an
  unmeasurable leaf gets a fresh instance digest every time and coalesces with
  nothing. That is fail-closed, at the cost recorded in R4-F3.
* *the empty chain.* Still refuses (`Caller::may_lease`), and both daemon tests
  pin it - the run is still gated, still shown to the human, only the auto-release
  is withheld.

The product argument is also sound on its own terms: refusing to lease an
unmeasurable chain turns a background auto-update into a silent return to one tap
per command, which is the problem leases exist to solve, and the failure would be
undiagnosable without exactly the logging and doctor row that were added. **And
one thing worth stating positively rather than as a concession: this is the only
one of the four measures an attacker cannot reconstruct** (see R4-F1). On the
reconstruction axis the process-instance branch is *stronger* than the cdhash
branches, not weaker. The honest summary is that it trades a property that never
resisted a deliberate imitator for one that does, and loses a property that only
ever held against an attacker who had already lost.

**R3-F6 (was LOW) - CLOSED.** No executable is read on this path, so the
`std::fs::read` concern has no target left.

**Beyond brief: ad-hoc binaries keep their guest cdhash under an `AdHoc` tag
rather than falling back to a byte hash - RULED CORRECT, and the important call in
the change.** A byte hash is a statement about a *file*, so falling back to one
would have reinstated R3-F1 across the branch covering most of a development
machine (Homebrew, cargo and npm binaries are ad-hoc signed). Keeping the guest
cdhash keeps the answer about the running image, and the separate tag stops it
being read as a signing identity it does not have. Four tags, all six pairs tested
for domain separation with identical 32 bytes. `IdentityMeasure::Content` is now
unreachable in production; leaving it as a documented test/other-platform arm is
right.

### Part A findings

**R4-F1 (LOW as a defect, MEDIUM as a claim correction). The caller chain is
*reconstructible*, and this document understates the residual.** `grant_key`
binds, per ancestor, only the executable path, the measure tag and the digest,
plus the chain length, the empty project root, the kind tag and the rule name
(`lease.rs:437-460`). Nothing instance-specific enters it whenever every ancestor
measures. So an attacker does not need to spawn *under* the victim's ancestors, as
the round-3 residual and the §7 row both say: they can build the chain from
nothing by exec'ing the same binaries from the same paths in the same nesting -
`/bin/zsh`, then the real `claude` at its real path, then the shim - and derive
the identical key with no access to the victim's processes at all. `ps` discloses
the tree to imitate. This is not a regression in this change; it has been true
since the chain existed. It matters because it is the sentence the consent
caption's "a genuinely different tool tree does not ride the window" reasoning
leans on. Recorded on the §7 row as UNPROVEN-by-construction against a deliberate
imitator. No fix is proposed: closing it would need a per-session secret the
ancestors cannot both hold and be measured by.

**R4-F2 (LOW, hardening; not a blocker and not exploitable today).** The cdhash is
read by `SecCodeCopySigningInformation`, which - per this code's own measured
comment at `peercode.m:96-101` - reads the file, gated by a *separate*
`SecCodeCheckValidityWithErrors` call at `peercode.m:164`. Two file-touching
operations at two moments; the guarantee that they observe the same bytes is an
undocumented memoization detail of Security.framework, not something this code
enforces. The kernel's own answer for the running image is available directly
(`csops(pid, CS_OPS_CDHASH, ...)`), needs no validity call, cannot be moved by
touching the file, and would be faster. This is *not* exploitable as things stand,
for the reason in R4-F1: an attacker who can write an ancestor's binary can simply
exec it honestly and skip the race entirely. Worth doing as hardening if this code
is ever the last fence rather than an outer one.

**R4-F3 (LOW, availability and observability).** `note_unmeasured`
(`lease.rs:829-851`) dedups on the process instance, which is right for a
long-lived ancestor and degenerate for the leaf: a fresh shim per gated command
means one stderr line and one registry entry **per command**, and the 64-entry cap
(`UNMEASURED_NOTES_MAX`, evicting oldest) then pushes out the long-lived note that
`sigil doctor` exists to surface. The reachable trigger is a build where the shim
is not validly signed - notably an x86_64 build, where an unsigned image returns
`errSecCSUnsigned` and lands on `-5` for every process. On arm64 this stays
theoretical, since everything is at least ad-hoc signed. Related and smaller:
`GuestFailure::ImageNotVouched::explain()` (`lease.rs:127`) says only "its
executable changed after it started", but `peercode.m:128-129` documents `-5` as
covering unsigned and other refusals too, so on that build the daemon tells the
human something false about why their leases stopped.

### Part B: the lease coverage label

**Choke point: sound in placement, and the "single writer" claim holds.**
`Config::resolve` is the only caller of `with_covers` outside tests and the
softphone fixture, and it stamps unconditionally on every match
(`config.rs:732-736`), so a hand-edited `covers` on disk is genuinely re-derived
and discarded - proven by `a_hand_edited_covers_on_disk_is_ignored_by_resolve`,
and `Config::save` never persists one. There is no inbound path to test: neither
`ApprovalResponse` nor `InstallLease` carries a coverage field, so the phone
cannot return one. The daemon-to-phone direction is inside the existing seal and
the hostile-relay suite proves the four properties that matter for it.

**The label cannot touch matching or lease identity. Confirmed by reading, not
only by the test.** `covers` sits on `Lease` beside `LeaseBinding` and outside it;
`LeaseStore::grant` and `token_for` compare `grant` and `binding` only
(`lease.rs:578` and `lease.rs:605`); `grant_key` never sees it. A refresh
re-stamps the label without forking the window. `coverage_is_carried_for_display_
and_never_joins_the_lookup` pins all three.

**The consent claim this reviewer lifted its round-one block on is not weakened,
with one exception.** The caption is deliberately broader than the grant on the
process axis, which is the safe direction, and replacing an argv[0]-derived guess
with the daemon's rendering of the actual rule strictly improves what the human is
told. The exception is R4-F4.

**Correction to the implementer's stated residual.** The residual is filed as "the
label echoes user-authored match tokens including `flag_equals` values, which are
already visible on the sheet inside `ApprovalRequest.command`". That is **wrong as
stated**: the sheet does not render `request.command`. It renders
`commandWord(request.command)`, the basename of argv[0] only, and says so at
`approval-sheet.tsx:103-108`. The coverage label is therefore the **first** path
by which user-authored config text (vault and account names, `argv_contains`
needles, flag values) reaches the phone screen. That is a deliberate and correct
product decision - the breadth cannot be stated without naming the conditions -
but it must be filed as a new display path, not as an existing one. It is
relay-blind (inside the seal, proven) and absent from the push doorbell, whose
body is the fixed constant `sigil-relay/src/push.rs::DOORBELL_BODY`.

### Part B findings

**R4-F4 (MEDIUM). The choke point strips Unicode `Cc` only, so bidi controls and
combining marks reach the consent caption. Demonstrated.** `sanitize_covers`
(`sigil-proto/src/request.rs:115-139`) filters on `char::is_control()` (general
category `Cc`) and `char::is_whitespace()` (the `White_Space` property). Neither
covers category `Cf` or `Mn`. Run against the shipped code:

```
LeasePolicy::leasable(900).with_covers("op with --account \"\u{202e}terces-on\u{200b}\"")
  .covers()  ==  "op with --account \"\u{202e}terces-on\u{200b}\""      // RLO and ZWSP survive
LeasePolicy::leasable(900).with_covers("op read" + "\u{0301}" * 40)
  .covers().chars().count() == 47                                        // 40 combining marks survive, under the bound
```

Why it matters on this surface specifically: the label and the fixed clause that
states the breadth share one paragraph in the phone's caption - `Covers <label>:
every command and secret that rule matches, from anywhere on this Mac`
(`approval-sheet.tsx:282-296`). An unterminated `U+202E` inside a rule's flag
value therefore reorders exactly the half of the sentence that says how wide the
window is, and a combining-mark pile obscures it. The three renderers disagree
about this and the least protected one is the one where consent is granted:

| renderer | strips | passes |
|---|---|---|
| `sanitize_covers` (daemon, the choke point) | `Cc`, `White_Space` | `Cf`, `Mn` |
| `format.ts::coverageLabel` (phone, consent surface) | `C0`/`C1`, `U+2028`/`U+2029`, `\s` | `Cf`, `Mn` |
| `Domain.swift::Lease.coverage` (Mac) | `Cc` + `Cf` (`CharacterSet.controlCharacters`, verified) | `Mn` |
| `cli.rs::lease_row` | nothing | everything |

Reachability: anything that can author a rule. That includes a config writer, who
could equally add an `allow` rule and skip the theatre - so this is **not** a
privilege escalation - but it also includes the designed agent-operated config
path (`docs/design/agent-operated-sigil.md`), where a rule is added on the human's
behalf and the human's entire defence is reading this caption correctly. A broad
rule whose caption cannot be read straight is the failure mode the caption exists
to prevent. Fix direction, not implemented: filter categories `Cc`, `Cf` and `Mn`
(or allowlist what a label may contain) at `sanitize_covers`, and widen the
phone's regex to match; the Swift mirror then only needs `Mn`.

**R4-F5 (LOW, display honesty). The summary fallback can exceed the bound it
exists to respect, and be elided mid-clause.** `Match::coverage`'s `atoms >
COVERS_MAX_ATOMS` branch returns `summarize(...)` with no length check
(`config.rs:289-291`), and `summarize` can run to 81 characters: `head` is up to
57 (two `COVERS_TOKEN_MAX`-elided tokens plus a space) and " with N match
conditions" adds 24. `with_covers` then truncates the count clause itself.
Demonstrated on the shipped code:

```
coverage() (81 chars) = "ccccccccccccccccccccccccccc… sssssssssssssssssssssssssss… with 4 match conditions"
stamped    (71 chars) = "ccccccccccccccccccccccccccc… sssssssssssssssssssssssssss… with 4 match…"
```

`coverage_is_bounded_and_summarizes_a_busy_rule` asserts the bound on three
shapes but not on this one (it never gives a long `command` and a long
`subcommand` together with more than `COVERS_MAX_ATOMS` conditions). The fallback
exists so a label never truncates into dishonesty; it can truncate itself. The
breadth is not understated - the head is still the bare command - so this is
degradation, not misrepresentation.

**R4-F6 (LOW, hygiene asymmetry). `sigil lease list` re-sanitises nothing, and the
rule name is sanitised nowhere.** `cli.rs::lease_row` (`cli.rs:816-838`) writes
`l.covers` and `l.scope` straight to a terminal. It is the only one of the three
renderers with no independent bound or filter, and it is the one writing to the
surface where control bytes historically do the most damage; its own doc comment
describes an empty-label fallback as "defensive", which is true of the empty case
and not of the contents. Separately, `scope` (the rule *name*) is equally
user-authored config and passes through no sanitiser on any surface - it does not
reach the phone, so the exposure is `lease list` and the Mac's lease row only. Low
because the daemon is the trusted party on that socket and does strip `Cc` from
`covers`.

### Doc corrections made by this reviewer

Two rows in §7 cited tests that no longer exist - `a_pid_with_no_live_image_is_
unmeasured_and_never_leases` and `an_unmeasured_ancestor_refuses_to_lease`, both
names from the fail-closed cut that `e895c5d` replaced. A claim row citing a
test that is not there reads as proven and is not, which is precisely the failure
this table exists to prevent. Both are corrected to the tests that actually run.
Part B had no rows at all; five are added above, one of them marked UNPROVEN.

### Residuals, restated

Unchanged and dominant: an attacker who can run code as this user, now stated in
its stronger form (R4-F1) - they need not spawn under the victim's ancestors, they
can reconstruct the chain. Also unchanged: the shim symlink making the chain leaf
identical for every gated command, so the rule name is the whole
command-discriminating boundary; lease-window imitation; approved-consumer misuse;
metadata at the relay. New and recorded here: the coverage label is a display path
for user-authored config text onto the phone screen (relay-blind, doorbell-free),
and until R4-F4 is fixed that text is not fully normalised.

## Round 4 fix round, daemon side (implementer's record, not a verdict)

Written by the implementer of these changes. It states what the code now does and
what remains open; whether R4-F4/F5/F6 are CLOSED is the independent reviewer's
call, not made here.

**R4-F4, the choke point (fixed).** `sanitize_covers` is now a thin call onto
`sigil_proto::sanitize_label(raw, max_chars)`, which is an **allowlist**, not a
wider blocklist. A label may contain printable ASCII (`U+0021`..=`U+007E`),
whitespace runs collapsed to one space, and `U+2026` (the elision mark this code
and `Match::coverage` emit, and the only non-ASCII character the daemon itself
produces). Every other character becomes one `?` per RUN, so forty combining marks
are one marker rather than forty, and the run collapse means a rejected pile
cannot spend the bound either. Rejected rather than dropped on purpose: a label
that had something in it must not read as though it never did.

The allowlist was chosen over the fix direction the finding proposed (filter `Cc`,
`Cf` and `Mn`) because that blocklist is incomplete in a way that is easy to
demonstrate: `U+3164 HANGUL FILLER` is category `Lo` and `U+2800 BRAILLE PATTERN
BLANK` is `So`, both render as nothing, and neither is `Cc`, `Cf` or `Mn`. An
allowlist also fails in the correct direction for anything a future Unicode
revision adds. The cost, stated rather than hidden: a legitimately non-ASCII rule
token (a vault named `Ingénierie`) renders `Ing?nierie` on the consent surface.
That is accepted for a string whose job is to state BREADTH; `sigil-config list`
is where a rule is echoed verbatim.

Tests, using the reviewer's own vectors:
`request.rs::covers_cannot_carry_a_character_that_reorders_or_hides_the_caption`
(the RLO-plus-ZWSP flag value, the 40-combining-mark case, the invisible-but-not-
control families, the collapse of a 500-character rejected run, and four ordinary
labels asserted unchanged) and
`request.rs::sanitize_label_holds_its_bound_at_any_width`. The first test renders
the phone's actual caption sentence around the label and asserts every character
of the RESULT is printable ASCII, a space or the ellipsis, which is the property
that makes reordering impossible rather than merely unlikely.

`Config::resolve` remains the only writer of a coverage label; nothing about the
choke point's placement changed.

**R4-F5, the summary fallback (fixed).** `summarize` now bounds itself: the count
clause is built first and the HEAD is elided to whatever `COVERS_MAX_CHARS`
leaves, so `... with 4 match conditions` always survives intact and the breadth
(the bare command) is still stated first. `token`'s elider was generalised to
`elide(raw, max)` and is shared. `coverage_is_bounded_and_summarizes_a_busy_rule`
gained the shape that escaped it: a long `command` AND a long `subcommand` AND
more than `COVERS_MAX_ATOMS` conditions, asserted both before and after
`with_covers`.

**R4-F6, the CLI render boundary (fixed).** `cli.rs::lease_row` now draws every
free-text cell through `cell()`, which is `sigil_proto::sanitize_label` at
`COVERS_MAX_CHARS`: the coverage label, the rule NAME (`scope`), and the account.
`LeaseCols::measure` measures the same filtered strings, so the columns stay
aligned with what is drawn. Column WIDTH is still decided separately, so an
over-long rule name steps out of its column rather than being cut to fit it. The
doc comment no longer calls the label filter "defensive"; it says what it is,
which is the terminal-facing filter for the one surface where a control byte
repaints a screen. Test:
`cli.rs::a_lease_row_cannot_repaint_the_terminal_or_reorder_itself` (an escape
sequence in a rule name, an RLO in a label, a BEL in an account, and a 4000-
character pair bounded without disturbing a healthy neighbouring row).

**Still unfiltered, and NOT fixed here: `sigil-config` list output.** A rule name
or match value carrying a control byte reaches the terminal raw from
`config_rule_list` and its siblings (sources, env keys). This is the same class as
R4-F6 and it matters for the same reason F4 does: `sigil-config rule list` is
where a human audits what an agent-operated config path wrote on their behalf, so
an escape sequence there can hide a rule from the audit. It is deliberately out of
this fix's scope rather than half-done: the config CLI has many print sites, that
surface's whole purpose is to echo config verbatim, and filtering it is a design
question (what does "verbatim" mean once a byte cannot be drawn) rather than a
one-line patch. Recorded for the reviewer to rate.

**R4-F1, the caller chain (claim correction, no behaviour change).** The stronger
statement, that a chain in which every ancestor measures is RECONSTRUCTIBLE from
`ps` by anyone who can exec the same binaries from the same paths in the same
nesting, is now written where the claim is made rather than only in this file:
`lease.rs`'s module docs (the residual is restated at full strength, and the
unmeasured branch is named as the only measure an outsider cannot restage),
`lease.rs::grant_key`'s doc comment (which previously said "a different tool chain
derives a different key" with nothing qualifying it), the test comment on
`different_caller_chains_do_not_share_a_rule_lease` (which proves separation
between honest trees and is now labelled as proving exactly that), and the design
brief's two chain paragraphs. The brief also no longer says malware must be
"running under those ancestors" to exercise a live lease; it can restage the chain
itself. No user-facing string claimed the stronger property, so none needed to
change.

**R4-F2, the two file-touching operations (narrowed, not closed).**
`sigil_guest_measure` now reads the signing information FIRST and runs
`SecCodeCheckValidityWithErrors` SECOND, using nothing from the read until the
check passes. The old order lost to ONE well-timed swap: validity passes against
the honest file, the attacker replaces it, and the cdhash read hands back the
substituted binary's identity, which the daemon then trusts. Read-then-validate
turns that same single swap into a refusal, because whatever the read produced
must still be the image the kernel executed a moment later when the check runs.
What remains: an attacker who can swap the file and swap it back, straddling both
calls, is racing a window this code cannot close from userspace. The containing
answer is the kernel's `csops(pid, CS_OPS_CDHASH)`, which touches no file and
needs no validity call; it is SPI, so it is not taken, and this is recorded as a
residual rather than claimed closed. Unchanged either way: this is not exploitable
today, because an attacker who can write an ancestor's binary can exec it honestly
and skip the race (R4-F1). All existing swap and rename-over tests still pass on
the new ordering, including
`swapping_the_file_under_a_running_process_does_not_change_what_it_measures_as`
and `a_stamp_preserving_rewrite_is_never_served_the_old_identity`.

**R4-F3, note availability and observability (fixed).** `note_unmeasured` now
dedups on the executable PATH plus the reason rather than on the process instance,
so the degenerate leaf case (a fresh shim per gated command on a build whose shim
will not measure) collapses to one log line and one registry entry instead of one
per command. The surviving entry is REFRESHED to the newest instance, so the
`sigil doctor` row keeps naming a process that is actually running rather than a
first sighting that has since exited. Eviction at `UNMEASURED_NOTES_MAX` now
prefers a note whose process is over (`doomed_index`), falling back to the oldest
only when every note is live, so a churn of dead notes can no longer push out the
long-lived one the report exists to carry. Separately,
`GuestFailure::ImageNotVouched::explain()` no longer says only "its executable
changed after it started": it now names the whole of what `-5` covers ("its
executable is unsigned, was changed after it started, or was otherwise refused"),
ending in a catch-all because `-5` is one. The unsigned case is what a build with
unsigned binaries actually hits, and it was the case the old wording described
falsely. This lengthens the `sigil doctor` row, which names up to three ancestors
with a reason each on one unwrapped line; worth a design pass, not held for one.
Tests:
`lease.rs::{a_repeating_unmeasurable_executable_collapses_to_one_note,
a_full_registry_evicts_a_finished_process_before_a_live_one}`.

**What the other two renderers must mirror** (for the phone and Mac agents; their
halves are not in this change): the daemon's filter is now an allowlist, so
`format.ts::coverageLabel` and `Domain.swift::Lease.coverage` should keep only
`U+0020`..`U+007E` plus `U+2026`, collapse whitespace runs to one space, and
replace each run of anything else with a single `?`, bounded to 72 characters
with `U+2026` as the last character when cut. Mirroring the daemon is what makes a
label that arrives from an older daemon, or from a lease that outlived the config
that named it, safe on the surface that renders it.
