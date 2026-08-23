# ADR 0107: Fail-closed clean-stop completion invariant

- Status: Accepted for a code-only completion invariant; graceful-stop
  admission, outcome retention, and effects remain absent
- Date: 2026-08-16
- Extends:
  [ADR 0099](0099-approval-bound-post-enrollment-start-and-graceful-stop.md)
  and
  [ADR 0106](0106-authenticated-historical-start-chain-graceful-stop-decision-candidate.md)
- Extended by:
  [ADR 0108](0108-sealed-new-record-clean-stop-terminal-result.md)
  and
  [ADR 0111](0111-dormant-operation-bound-clean-stop-supervisor-bridge.md)

## Context

The trusted-head reconciler deliberately creates a checkpoint candidate only
when the authenticated local head differs from the locally confirmed anchor.
That rule is correct for periodic and on-demand reconciliation: an unchanged
head needs no duplicate signed record, and a successful no-candidate result has
no new remote-readback or durable-receipt identity.

The same behavior was unsafe at the clean-stop boundary. A `clean_stop` request
whose local head already equaled the confirmed anchor could return a successful
reconciliation with no new candidate or receipt. The worker then treated any
otherwise valid result for that request as `clean_shutdown_completed=true`.
That process-local boolean did not prove the exact new `clean_stop` successor
required by ADR 0099.

Recovery makes the distinction sharper. One invocation may first finish an
older pending intent and then prepare its current request. The recovered
receipt is durable evidence for that older intent, but it is not a receipt
created by the current `clean_stop` request. Allowing the carried recovered
receipt to satisfy clean-stop completion would cross request identity and
checkpoint reason.

ADR 0106 identified this false-positive gap but did not choose a new no-record
terminal protocol. There is still no durable graceful-stop outcome/recovery
contract capable of safely assigning semantics to an unchanged-head shutdown.

## Decision

### Require the exact current-request receipt

The existing repository-backed attempt keeps the receipt returned by its
current `_complete_current` call distinct from any receipt recovered earlier in
the invocation. When the exact request reason is `CLEAN_STOP`, that
`current_receipt` must be present. Absence is a fatal, fail-closed result.

Consequently, successful clean-stop completion requires the current invocation
to have prepared and completed a new candidate whose checkpoint reason is
`clean_stop`, with its paired exact provider readback and durable receipt. A
prior periodic, on-demand, epoch-rotation, recovery, or other receipt cannot
substitute, even when it authenticates the same current host-head digest.

An unchanged-head `clean_stop` therefore remains unconfirmed because normal
reconciliation correctly creates no candidate and returns no current receipt.
This ADR does not reinterpret that case as success and does not invent a
special terminal disposition for it.

### Defend the invariant in the worker core

The pure worker core independently requires both existing paired result fields,
`candidate_remote_readback_sha256` and `receipt_semantic_sha256`, to be non-null
before a successful `CLEAN_STOP` request may set `stopped` and
`clean_shutdown_completed`.

This is defense in depth across the attempt/worker boundary. A custom or
incorrect attempt cannot return an otherwise well-formed no-receipt result and
cause the worker to report clean completion. The rejection is fatal and never
queues an automatic clean-stop retry.

Non-clean-stop behavior is unchanged. Periodic, on-demand, and other admitted
requests may still complete with both paired fields null when the authenticated
local head is already anchored. Their success does not claim clean shutdown.

### Historical boundary at acceptance

At acceptance, this correction added no public type, serialized field,
contract version, disposition, canonical artifact, loader, writer, CLI, or Make
target. It strengthened the existing repository-backed attempt and
`TrustedTimeHeadAnchorWorkerCore.record_success` invariants only.

[ADR 0108](0108-sealed-new-record-clean-stop-terminal-result.md) now extends
that historical boundary with one process-local, new-record-only sealed result
contract and an unused exact-result background accessor. It does not weaken
this ADR's same-request receipt rule, add a no-new-record success, or turn the
result into provider-terminal, durable, cross-process, or effect-authorizing
evidence.

In particular, it adds no no-new-record success representation, provider-
terminal issuer, currentness or freshness proof, graceful-stop authority or
signature loader, stop-attempt slot, stop admission, durable stop outcome or
recovery protocol, signal sender, Docker or Compose call, container or network
removal, teardown verification, or operational/trading authority. The
supervisor's generic `status=stopped` output remains insufficient stop evidence.

`make trusted-time-stop` remains the exact no-prerequisite, two-line hard-close
target. It reports that no effecting approved shutdown operator is implemented
and exits 2 without invoking Python, Docker, or Compose.

ADR 0111 preserves this rule while adding only an operation-bound new-record
correlation. Its request fixes `exact_new_record_required=true`; the generic
clean-stop path cannot issue its result, and no unchanged-head or
no-new-record success is introduced.

## Consequences

A clean-stop request can no longer succeed merely because the latest local head
was already anchored or because the same invocation recovered an older
receipt. This may conservatively classify an otherwise quiescent shutdown as
unconfirmed. That is intentional: absence of a same-request receipt is safer
than manufacturing the ADR-0099 successor fact from an old record.

ADR 0108 now defines the distinct exact new-record terminal result. A future
reviewed design may define an authenticated no-new-record terminal proof, but
it must do so under a separate explicit contract and bind the exact request,
current SQL head, provider terminal, and durable stop outcome. This ADR neither
anticipates that representation nor reserves names for it.

Before any permanent stop-attempt reservation or effect, the repository still
needs same-lock current topology and bounded trusted-head evidence plus a
progress-sensitive durable stop outcome/recovery protocol covering every
CALL/STORE ambiguity. Before confirmed teardown, a live workflow still needs
durable retention of the exact terminal result and an issued, bounded host
observation of the relevant SQL/provider state. ADR 0109 and ADR 0111 now
supply dormant one-shot observation and composition seams, but consumption
does not confer freshness or currentness, and ADR 0108's process-local result
is not durable retention. No operational stop was executed while implementing
this invariant.

## Rejected alternatives

- **Treat an unchanged anchored head as clean-stop success.** That proves no
  request-specific `clean_stop` record or receipt.
- **Accept the invocation's last available receipt.** A recovered receipt is
  bound to the older pending intent and cannot be relabeled as current-request
  evidence.
- **Rely only on `clean_shutdown_completed` or `status=stopped`.** Those generic
  values do not carry the required exact successor identities.
- **Add a no-new-record success disposition now.** No current protocol binds
  that disposition to same-lock SQL/provider currentness and durable stop
  recovery.
- **Reserve a stop slot or wire shutdown effects with this correction.** The
  currentness, admission, outcome/recovery, signaling, and teardown contracts
  remain absent.
