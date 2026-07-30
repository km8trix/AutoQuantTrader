# ADR 0047: durable bounded UNKNOWN lookup scheduling

- Status: Accepted
- Date: 2026-07-27

## Context

Phase 2 durably freezes an ambiguous broker submission in `UNKNOWN`. Phase 4D
reserves protected request capacity, and Phase 4I can perform one exact
authenticated, raw-first lookup by the attempt's deterministic client order
ID. No durable policy currently decides when another lookup is eligible,
prevents two recovery workers from sending the same scheduled lookup, bounds
restart catch-up, or records that the local 60-second submission-uncertainty
budget expired.

A lookup schedule is not reconciliation. A matching Order response still lacks
the converged snapshot, execution, fee, correction, and application evidence
needed to resolve `UNKNOWN`. A 404 remains vulnerable to delayed visibility,
and elapsed time cannot prove that the original submission was not accepted.
The scheduler must therefore bound investigation while leaving the attempt and
its reservation frozen.

## Decision

1. Define Phase 4J as a durable, bounded schedule around the exact Phase 4I
   authenticated client-order lookup. The schedule performs no submission,
   cancellation, lifecycle application, UNKNOWN resolution, or resubmission.
2. Bind one immutable recovery plan to the exact canonical attempt, its
   `IN_FLIGHT` event, its terminal `UNKNOWN` event, local account and stable
   client order ID, and the Phase 4I lookup-correlation digest. The complete
   attempt history must reconstruct, the two source events must be exact
   durable facts in their canonical order, and the UNKNOWN event must remain
   the current terminal head whenever a new lookup ticket is issued.
3. Measure the unresolved hard deadline from the original `IN_FLIGHT`
   `occurred_at`, not from scheduler startup or a later UNKNOWN observation.
   The deadline is exactly 60 seconds later. Equality is expired and no lookup
   may be issued at or after it.
4. Freeze the local v1 lookup offsets at 1, 2, 4, 8, 16, and 32 seconds after
   the durable UNKNOWN event's `recorded_at`. Drop any slot whose due instant is
   at or after the dispatch deadline. This is a conservative local policy, not
   an Alpaca visibility guarantee. It encodes a first eligible lookup within
   one second of the durable UNKNOWN fact; without a deployed worker it does
   not claim that the provider request actually starts by then.
5. A late or restarted poll considers only the latest due slot and selects it
   only when it is unconsumed. It never reopens an older missed slot after a
   later slot was consumed. Earlier due slots are consumed as an explicit
   coalesced range and never replayed as a catch-up burst. Future slots remain
   unavailable until their own due instants.
6. Issue one deterministic, one-shot ticket for the selected slot under the
   shared account serialization lock. The ticket derives bounded request and
   raw-delivery idempotency keys and the expected Phase 4D demand identity from
   the plan and slot. It remains a scheduling marker, not broker authority.
7. A ticket is current for at most three seconds and never beyond the
   60-second dispatch deadline. Equality is expired. This matches the existing
   Phase 4D permit freshness horizon and prevents another worker from issuing a
   later slot while the scheduled Phase 4I request can still be current. A
   ticket is never leased again or redelivered.
8. Revalidate the current recovery fence and exact terminal UNKNOWN attempt in
   the SQL transaction that issues a ticket. Phase 4I independently repeats
   its own UNKNOWN, account-identity, permit, credential, and fence checks
   immediately around transport. Losing either layer fails closed.
9. Invoke at most one Phase 4I lookup per workflow call. The workflow must pass
   the ticket-derived request and delivery keys. A successful typed lookup may
   be attached to the ticket only when its attempt and UNKNOWN source, demand
   identity, request time, recovery fence, and durable receipt digest agree.
10. Treat a qualified `NOT_VISIBLE_INCONCLUSIVE` observation as permission only
    to wait for the next policy slot. Treat `FOUND_MATCHED` as
    `RECONCILIATION_REQUIRED`; treat `FOUND_MISMATCH` and
    `SECURITY_IDENTITY_MISMATCH` as `BLOCKED_MISMATCH`. These are terminal
    scheduler classifications, not submission outcomes.
11. A process crash, transport failure, raw-only decoder failure, lost source
    check, or any other absence of a qualified Phase 4I receipt consumes the
    issued slot. After its ticket expires, a later poll may coalesce to the
    latest newly due slot and consume a new request-budget permit. It may never
    reuse the prior ticket, demand, permit, or delivery identity.
12. At or after the hard deadline, record `EXHAUSTED_INCONCLUSIVE` once.
    An exact matching Phase 4I receipt that committed before a workflow crash
    may still be attached later as historical schedule evidence, but it cannot
    reopen issuance or replace the exhaustion classification. Exhaustion
    requires operator-visible alerting in a future deployed runtime, but it
    does not infer `NOT_SUBMITTED`, release capacity, or permit another
    submission.
13. Persist an immutable plan, a predecessor-linked event chain, and a
    lockable terminal head. Dispatch events bind the selected slot and
    coalesced range; observation events bind the exact Phase 4I receipt;
    exhaustion binds the remaining unconsumed range. Exact replay is
    idempotent. Missing or corrupt sources, conflicting reuse, chain or head
    rollback, clock regression, and concurrent issuance fail closed on write,
    read, and startup verification.
14. Keep direct Phase 4I receipts historical and non-authorizing. Phase 4J does
    not reinterpret an older unscheduled lookup as a scheduled result, and a
    scheduler event cannot become a normalized broker fact, reconciliation
    fact, lifecycle application receipt, or risk-release authority.
15. Add no deployed worker, secret resolver, alert route, normalized inbox,
    stream or paginated snapshot consumer, reconciliation reducer, submission
    transport, API/trader/startup composition, or paper readiness in this
    slice. Every global Alpaca capability flag remains false.

## Consequences

Phase 4J can durably prove which delayed UNKNOWN lookup slot was consumed,
coalesce stale restart work without a burst, prevent a second send under the
same scheduling identity, and stop local lookup scheduling at the original
60-second uncertainty deadline. A deterministic application seam can exercise
one due slot through the already restricted Phase 4I runtime.

The submission remains `UNKNOWN` for every scheduler state. Provider-qualified
stream, snapshot, execution, bust, and correction identities; a normalized
non-applying inbox; convergent reconciliation; lifecycle application; alert
delivery; and deployed paper composition remain future Phase 4 work. Phase 4
and its exit gate remain open.
