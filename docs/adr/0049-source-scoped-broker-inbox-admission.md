# ADR 0049: source-scoped broker inbox admission and non-application receipts

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4K turns one authenticated UNKNOWN-order lookup into durable,
provider-neutral historical reconciliation evidence. It deliberately does not
claim a provider revision sequence, execution identity, correction identity,
or lifecycle transition. A general broker inbox will eventually have to
deduplicate snapshots and streams, quarantine malformed or conflicting input,
and record whether a normalized fact was applied.

The reviewed Alpaca paper contract does not yet establish a stable universal
identity across REST order snapshots, trade-update stream deliveries,
executions, busts, and corrections. Arrival order, nullable `updated_at`, and
cumulative fill values are not safe substitutes. Collapsing separate Phase 4K
lookups now would therefore create an identity policy that the available
evidence cannot justify. Leaving normalization decisions implicit would be
equally unsafe because an operator could not distinguish unprocessed evidence
from evidence intentionally withheld from application.

## Decision

1. Define Phase 4L as a bounded inbox-admission layer over exact authenticated
   Phase 4K facts. It adds no broker I/O and accepts no unauthenticated payload.
2. Use an explicit versioned identity profile whose initial scope is one
   authenticated lookup source. The normalized identity is derived from the
   exact Phase 4K fact identity and digest. Separate authenticated lookups
   remain separate normalized observations even when their decoded values are
   identical. Pin both the profile ID
   `phase4l-authenticated-lookup-source-scoped-identity-v1` and its semantic
   digest; this identity is local source accounting, not a provider revision
   or general deduplication key.
3. Preserve three independent identities:
   - the Phase 4C/4K transport and normalization source;
   - the Phase 4L normalized historical observation/request;
   - the Phase 4L non-application decision receipt.
4. Map the four Phase 4K outcomes to closed Phase 4L decisions:
   - a matching order is
     `WITHHELD_UNQUALIFIED_REVISION_IDENTITY`;
   - an economic mismatch is `QUARANTINED_ECONOMIC_MISMATCH`;
   - a security mismatch is `QUARANTINED_SECURITY_MISMATCH`;
   - a qualified 404 is `INCONCLUSIVE_NOT_VISIBLE`.
5. A matching historical observation remains withheld because source
   authentication alone does not qualify a provider revision, execution, fee,
   bust, correction, or cross-channel deduplication identity.
6. Persist normalized requests separately from account-local source links.
   Source links form a contiguous predecessor chain under one terminal head;
   every link binds the exact Phase 4K reconciliation fact and exact Phase 4C
   ingress receipt. Persist one decision receipt for every request. Exact
   source retry is idempotent. Reusing an identity with changed content, gaps,
   rollback, truncation, orphan rows, source substitution, or decision
   substitution fails closed on write, read, and startup verification.
7. Authenticate each source link against the exact Phase 4K fact and its exact
   Phase 4C raw receipt. The linked Phase 4K history must itself pass source and
   predecessor verification.
8. Record one explicit non-application receipt for every admitted normalized
   request. The receipt pins policy ID
   `phase4l-authenticated-lookup-non-application-v1`, its semantic digest, and
   the closed reason. A trusted UTC decision time must not precede the source
   Phase 4K normalization; durable recording must not precede the decision.
   Exact retry returns the original receipt rather than changing its decision
   time. The receipt contains no canonical event, execution, reservation,
   ledger, UNKNOWN resolution, or reconciliation-completion target.
9. Keep every authority property false. Phase 4L cannot construct or apply a
   `BrokerOrderEvent`, resolve a submission, release a reservation, create an
   execution or fee, mutate a ledger or account projection, complete
   reconciliation, change readiness, authorize transport, or cause a trading
   effect.
10. Do not call the initial profile general inbox deduplication. Cross-channel
    identity, stream replay behavior, snapshot pagination, execution and
    correction identities, and authoritative application remain unqualified.
11. Admit no raw decoder failure in this slice. Raw decode quarantine needs its
    own bounded source/error identity and cannot be invented from a Phase 4K
    fact that was never produced.
12. Add no credential resolver, network transport, worker, API, trader,
    startup authority, or paper-readiness change.

## Consequences

Every authenticated Phase 4K observation can be durably accounted for as
withheld, quarantined, or inconclusive rather than disappearing between
normalization and future application. The source-scoped identity is
conservative and replay-safe, but intentionally gains no cross-channel
deduplication power.

Provider-qualified stream and snapshot identity profiles, raw decode
quarantine admission, execution/correction semantics, reducers, paginated
snapshots, stream buffering, convergent reconciliation, authoritative
application, and the Phase 4 paper gate remain open.
