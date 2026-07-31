# ADR 0060: bounded restart-safe Alpaca position-view supervision

- Status: Accepted
- Date: 2026-07-28

## Context

Phases 4T and 4U make each authenticated position capture single-use: no plan
row is unclaimed, a plan without a receipt is permanently stalled, and a plan
with a receipt is complete. Phase 4V can compare two complete receipts, but it
does not decide which capture may run next or when the later capture becomes
eligible.

An in-memory loop or sleep would hide restart state and could accidentally
retry a stalled single-use claim. Starting both captures together would also
weaken the local separation evidence required before equality can even be
reported as unqualified.

## Decision

1. Define Phase 4W as the
   `phase4w-bounded-authenticated-position-view-supervisor-v1` application
   contract. It adds no tables and does not deploy a scheduler or worker.
2. Consume an ordered pair of distinct Phase 4T plans for the same local
   account and operator-pinned provider account UUID. Derive every action from
   repository-authenticated Phase 4U states: `ABSENT`, `STALLED`, or
   `COMPLETE`.
   Require the state loader, capture workflow, and comparison repository to
   expose the same opaque process-local durable-store identity before reading
   state or performing effects; mismatched composition fails closed.
3. Perform exactly one of four actions per invocation:
   - execute the earlier capture once when both sources are absent;
   - return an explicit no-I/O wait before the later eligibility instant;
   - execute the later capture once at or after that instant; or
   - invoke Phase 4V once after both sources are complete.
   Never loop, sleep, retry, or execute two captures in one invocation.
4. Fail before the capture workflow, trusted-clock read, or comparison append
   when either initially loaded source has a stalled durable claim. Reject a
   later source that completed before the earlier source.
5. Fix the later eligibility instant at the earlier authenticated raw
   observation's `received_at` plus two seconds. Before selecting a new later
   capture, read an injected trusted clock and return `WAITING` without I/O
   when the boundary has not arrived.
6. After a selected capture returns, reload both durable states. Accept only
   one exact `ABSENT` to `COMPLETE` transition under the supplied account
   fence, with the unselected state byte-for-byte unchanged. A workflow that
   leaves its plan stalled fails closed. A concurrent mutation of the
   unselected source is rejected after the one already-bounded selected
   capture; this application-only slice does not claim a pair-wide pre-effect
   compare-and-swap.
7. Require a newly selected later receipt's authenticated preparation to be at
   or after both the fixed eligibility instant and this invocation's trusted
   selection check. Require its request start and raw receive time at or after
   the eligibility instant, and require its raw-ingress sequence to follow the
   earlier source.
8. On restart with an already complete later source, reauthenticate the same
   preparation/request/receive boundary and raw-ingress ordering directly from
   the Phase 4U receipt. No in-process supervisor state is trusted.
9. Once both states are complete, invoke the exact Phase 4V workflow, then
   reload its receipt from the same repository and require it to bind the two
   current durable source receipts. A waiting Phase 4S disposition is
   inconsistent with the supervisor gate and fails closed.
10. Keep every result historical and non-authorizing. Supervision does not
    establish provider snapshot isolation/completeness, monotonic provider
    time, canonical positions, convergence, application, reconciliation
    completion, readiness, submission, or trading authority.

## Consequences

Position-pair progress is restart-derived and bounded to one provider read or
one comparison append per call. A stalled state observed before selection
cannot be retried through the supervisor, and the later source carries explicit
authenticated evidence that its capture started after the local scheduling
boundary. Process-local store identity rejects independently wired ports before
state is read, but is not persisted authority. A racing direct mutation of the
unselected plan is detected but may occur after that one read has begun.

The contract still has no durable pair-wide CAS or exclusive deployed
orchestrator, deployed scheduler, automatic stalled-claim recovery, combined
account/order/position barrier, activity or fill coverage, stream overlap,
provider-qualified event identities, authoritative application, convergence,
or Phase 4 readiness.
