# ADR 0108: Sealed new-record clean-stop terminal result

- Status: Accepted for code-only process-local terminal evidence; provider-
  terminal currentness, durable stop outcome/recovery, and effects remain absent
- Date: 2026-08-16
- Extends:
  [ADR 0099](0099-approval-bound-post-enrollment-start-and-graceful-stop.md)
  and
  [ADR 0107](0107-fail-closed-clean-stop-completion-invariant.md)
- Extended by:
  [ADR 0111](0111-dormant-operation-bound-clean-stop-supervisor-bridge.md)

## Context

ADR 0107 closed the false success in which a `CLEAN_STOP` request could report
completion without a new receipt from that exact invocation. Its paired
readback and receipt digests were a necessary rejection invariant, but the
generic attempt result and boolean background-worker close boundary still lost
the exact clean-stop record sequence, predecessor, local and confirmed counts,
intent identity, mutation disposition, receipt instant, and scheduled request
identity.

Those generic values were also directly constructible. Scalar equality alone
could not distinguish two request objects from different worker cores when
their sequence, reason, and scheduled monotonic values happened to match. A
result intended for one in-flight request therefore needed a process-private
identity binding and one-shot adoption before it could become the worker's
terminal evidence.

The new result must remain narrower than the future ADR-0099 host stop
postcondition. The exact provider GET and SQL receipt prove the newly written
record, but they do not prove that no higher provider object exists after the
request returns. They also do not durably retain a stop attempt or outcome and
cannot authorize signaling or teardown.

## Decision

### Freeze one exact new-record-only result

Application contract
`phase6d-trusted-time-head-anchor-clean-stop-terminal-result-v1` defines the
exact process-local class `TrustedTimeHeadAnchorCleanStopTerminalResult`. Its
public evidence fields are exactly:

- `request_sequence` and `request_scheduled_monotonic_ns`;
- `anchor_sequence`, `checkpoint_reason`, `confirmed_anchor_count`,
  `local_transition_count`, and
  `confirmed_anchor_local_transition_ordinal`;
- `predecessor_anchor_sha256`, `current_host_head_sha256`,
  `current_anchor_sha256`, and `current_anchor_semantic_sha256`;
- `receipt_observed_at_utc`, `full_audit_completed`, and
  `prior_pending_intent_recovered`;
- `uploaded_anchor_count` and `idempotent_duplicate_count`; and
- `current_anchor_intent_semantic_sha256`,
  `current_candidate_remote_readback_sha256`, and
  `current_receipt_semantic_sha256`.

The read-only `semantic_sha256` property commits all those fields, the exact
contract version, and semantic status
`exact_current_new_record_clean_stop_completed` in canonical JSON. It is an
in-process semantic identity only. This ADR adds no public encoder, decoder,
wire payload, stdout record, artifact, loader, or persistence schema.

Validation requires exact built-in scalar types, lowercase SHA-256 values, an
exact UTC receipt instant, reason `CLEAN_STOP`, and
`anchor_sequence == confirmed_anchor_count >= 3`. The predecessor is mandatory,
the confirmed terminal ordinal equals the local transition count and is at
least the anchor sequence, the current readback equals the current signed-
record byte digest, and the upload and idempotent-duplicate counts are each
zero or one and sum to exactly one. The recovered-pending flag may be true, but
only the separate exact current receipt supplies this result.

### Seal issuance and consume the exact request once

The result is frozen, slotted, identity-comparing, and `init=False`. A module-
private registry retains the exact result object, owner PID, canonical sealed
field tuple, semantic digest, hidden exact request object, and one-shot consumed
flag. Direct construction, a forged clone, field drift, copy, deep copy,
dataclass replacement, pickle, or use after fork is rejected. Successful
one-shot consumption does not erase the evidence; the same sealed object
remains inspectable afterward.

The private issuer
`_issue_trusted_time_head_anchor_clean_stop_terminal_result` has exactly one
production importer:
`apps/trusted_time_supervisor/head_anchor_attempt.py`. The repository-backed
attempt calls it only from the exact current `CLEAN_STOP` completion. It passes
the exact request object as hidden `request_identity` and cross-binds the
prepared candidate, reconciliation terminal, current receipt, compact SQL
snapshot and authenticated tip, counts, ordinal, predecessor, current head,
record digests, intent, readback, receipt, and prior-recovery fact.

The private consumer
`_consume_trusted_time_head_anchor_clean_stop_terminal_result` has exactly one
production importer:
`packages/application/trusted_time_head_anchor_worker.py`. After validating all
public attempt/request bindings, and before clearing the in-flight request, the
worker atomically requires the registry's hidden request object to be that
exact in-flight object and flips the consumed flag. Reuse in the same core,
cross-core use, or use with a distinct scalar-equal request fails closed and
poisons the receiving core.

`TrustedTimeHeadAnchorAttemptResult` carries an optional
`clean_stop_terminal_result`, but it is required exactly when its reason is
`CLEAN_STOP` and forbidden for every other reason. It cross-binds the request
sequence, reason, current head and anchor digests, audit and recovery flags,
paired readback and receipt digests, and receipt/completion chronology. The
worker additionally binds the hidden result to the exact request identity and
the public scheduled monotonic value.

### Preserve a bounded, non-composed handoff

`TrustedTimeHeadAnchorWorkerCore` retains the exact accepted result separately
from generic worker evidence. The background worker adds the additive method
`close_with_clean_stop_terminal_result(...) ->
TrustedTimeHeadAnchorCleanStopTerminalResult | None`. `None` means no sealed
current-request result was accepted; it is never a no-new-record success.

The existing `close(...) -> bool` API remains compatible. The supervisor main
composition continues to use only that boolean and does not call the new
exact-result accessor. No result is encoded or emitted on stdout, and no host
or cross-process consumer exists in this slice.

### Keep every broader claim false

The result explicitly reports false for authority, provider-terminal
authentication/currentness, no-new-record authentication/success, durability,
durable stop outcome, retained stop outcome, slot, admission, signal, graceful-
stop, shutdown, teardown, effect, operational-control, readiness, arming,
exposure, broker-action, automatic re-arm/resume, alert-delivery, paper-
trading, and live-trading properties.

Periodic, on-demand, and other non-clean-stop no-candidate behavior is
unchanged. This ADR adds no no-new-record disposition or proof, provider-
terminal issuer, host SQL/provider postcondition, durable stop attempt/outcome
or recovery, permanent slot, current-topology admission, signal sender, Docker
or Compose call, teardown verifier, CLI, Make target, or operational effect.
`make trusted-time-stop` remains the exact hard-closed exit-2 target.

ADR 0111 now adds a second one-shot consume bit solely for the dormant
operation-bound export. That consume returns the immutable registered nineteen-
field projection and semantic digest; the bridge never constructs from later
live getters. The worker's private take returns captured canonical ADR-0111
bytes, while the existing generic close and main paths remain unchanged.

## Consequences

The worker can now preserve the exact current new-record completion without
allowing a forged, copied, replayed, scalar-equal cross-core, or post-fork
result to set clean completion. A recovered older receipt remains visible only
as historical recovery context and can never become the current result.

This evidence is intentionally process-local and non-durable. ADR 0109 now
adds a code-only host issuer with no live or effect consumer except ADR 0111's
dormant zero-caller composition. It independently performs fresh
SQL-to-provider-to-SQL reauthentication of an arbitrary-sequence clean-stop
terminal, including a full two-pass namespace audit, late exact terminal GET,
and empty next sequence. That later result is still only a bounded point-in-time
observation with no durable operation or effect consumer. This ADR's process
seal cannot cross stdout or a process boundary. ADR 0111 supplies a separately
versioned strict structural wire, but does not authenticate transport or
origin; any live handoff must be bounded, replay-safe, authenticated, and
freshly revalidated.

Before any runtime signal, a progress-sensitive durable stop attempt/outcome
and recovery protocol must already exist so every CALL/STORE ambiguity is
terminal and non-retryable. Permanent stop reservation, current-topology
admission, signaling, source/supervisor teardown, network removal, and final
outcome confirmation remain later ordered phases. No operational stop was
executed while implementing this contract.

## Rejected alternatives

- **Return only the existing paired hashes or boolean.** They omit the record,
  request schedule, counts, predecessor, intent, and exact object identity.
- **Trust matching scalar request values.** Independent worker cores can issue
  scalar-equal requests; only the hidden exact request identity and atomic
  one-shot consume prevent replay.
- **Serialize or print the process seal.** Object identity and the registry
  cannot cross a process boundary and would provide false assurance there.
- **Call this provider-terminal or durable stop evidence.** The current receipt
  proves one exact new readback, not lasting terminality, a retained stop
  outcome, or recovery closure.
- **Add an unchanged-head success disposition.** ADR 0107 deliberately leaves
  that case unconfirmed, and this result remains new-record-only.
- **Wire the accessor into main, admission, signaling, or Docker teardown.**
  ADR 0111's dormant zero-caller composition adds no live consumer.
  Authenticated transport, same-lock admission, and a later operation-bound
  durable outcome/recovery protocol must precede those effects.
