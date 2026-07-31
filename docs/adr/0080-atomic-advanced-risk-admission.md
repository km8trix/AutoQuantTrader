# ADR 0080: atomic advanced-risk admission, cutover, and dispatch

Status: Accepted

## Context

ADR 0068 fixes the owner-approved moderate paper-risk policy, but its
assessments are evidence rather than execution authority. Phase 2 already owns
the stable batch-risk decision, reservation, authorization, and submission
contracts. Replacing or reinterpreting those contracts would split risk
authority and make retries ambiguous.

Advanced-risk enforcement also cannot be enabled while legacy approvals,
unresolved submissions, stale reconciliation, or a running strategy may still
create exposure. A successful authorization must commit its complete advanced
assessment and any operational-control trip with the unchanged Phase 2 result,
and dispatch must reject a sidecar that has become stale.

## Decision

### One-way cutover

Advanced-risk enforcement is enabled once per account under the current
account fence and a non-`RUNNING` operational-control head. Cutover requires:

- the current authenticated advanced-risk assignment;
- fresh full-policy `RUNTIME` evidence with disposition `NONE`, produced under
  the same snapshot/account transaction;
- no active reservations, unresolved `UNKNOWN` submissions, unconsumed
  unexpired authorizations, advanced admissions, or advanced outcomes;
- an injected authoritative transactional verifier that returns exact,
  fresh facts for the same fence, assignment, and control head;
- clean reconciliation with no working, `UNKNOWN`, or pending-cancel orders;
  and
- no active strategy invocation.

Missing, expired, dirty, or scope-mismatched verifier facts fail closed before
the cutover assessment or enforcement head is written. Cutover also loads the
exact current snapshot and active-capacity universe, invokes the mandatory
transactional evidence producer, and independently re-derives the
concentration/leverage/integrity observations from those inputs and the
current fence. The producer's assessment must contain those exact observation
objects and their exact retained source membership. Its context must also
match the current assignment and control head. The quiescence facts' semantic
SHA-256 remains the assessment's authenticated `evidence_context_sha256`; it
is not used as a label for unverified exposure observations. No synthetic
authority or backfill is permitted.

Cutover permanently disables the legacy `SqlBatchRiskRepository.authorize`
path for that account. The assignment present at cutover is historical
evidence, not a permanent policy pin: each new authorization binds and
rechecks the current CAS assignment.

### Atomic authorization and retry

The post-cutover repository accepts no caller-built assessment. It requires an
injected transactional evidence producer and performs one transaction in this
order:

1. revalidate the account fence and load the current enforcement, control,
   assignment, active-capacity, target, batch, and snapshot facts;
2. derive the proposed buy exposure with the unchanged Phase 2 reservation
   terms, invoke the producer under the same account transaction, and require
   its exact snapshot, capacity, batch, target, fence, assignment, control, and
   evaluation-time context;
3. independently derive runtime exposure without the proposed batch and
   pretrade exposure with the exact proposed batch, then require those exact
   observations and source sets in the producer's complete assessments;
4. authenticate and persist both retained-source assessments;
5. atomically append a `PAUSED` or `HALTED` control transition when runtime
   policy requires it, without creating Phase 2 authority;
6. stop a pretrade `REJECT` before Phase 2 evaluation, reservation, or
   admission;
7. otherwise run the unchanged Phase 2 v2 evaluator and persist its exact
   decision and holds;
8. persist an additive advanced-risk admission sidecar; and
9. recheck the fence, current assignment, and control head before commit.

The injected producer never receives the writable SQLAlchemy connection or a
generic SQL query surface. It receives a frozen, slotted domain reader
materialized from the exact assignment, control, batch, and target facts read
inside the caller-owned transaction. Both reader operations require the exact
invocation context before returning those facts. The reader stores no
connection or cursor and exposes no SQL execution, locking, commit, or rollback
capability; new authoritative source families must add similarly narrow typed
reads rather than restoring ambient SQL authority.

Only a Phase 2 `APPROVED` decision, advanced disposition `NONE`, and final
`RUNNING` control state produce an admitted sidecar. A Phase 2 rejection keeps
a non-admitted sidecar and no holds. `NO_ACTION` retains its canonical Phase 2
decision but uses the sole assessment-null, non-admitted sidecar shape.

Every terminal path persists one immutable whole-batch outcome binding the
evidence watermark, assignment, assessments, pre/final control transitions,
fence and lease, optional Phase 2 decision, and optional admission. Exact
retries authenticate and return that historical outcome before consulting
newer assignment or control heads. A prior Phase 2 decision without its
required outcome is corruption, not a retry.

### Dispatch and readiness

Submission preparation authenticates the exact admitted sidecar and whole
outcome before consuming an authorization. `mark_in_flight` repeats the same
check immediately before the broker-call boundary. Admission must still be
unexpired and bind the current lease receipt, assignment, and `RUNNING`
control head.

Operational readiness includes the outcome table and authenticates every
enforcement head and whole outcome. It also rejects any admission lacking its
atomic outcome. Tampering or incomplete history therefore prevents startup.

The base advanced-risk tables remain owned by migration
`0026_phase5_advanced_risk`. The later whole-outcome table and exact composite
foreign-key targets are owned only by `0030_phase5_adv_outcomes`, preserving a
valid `0029` to `0030` upgrade and a single fresh-install owner.

## Consequences

- Phase 2 decision IDs, digests, and economic semantics remain unchanged.
- Runtime trips, assessment facts, Phase 2 holds, admissions, and outcomes
  cannot partially commit.
- Reassignment is supported through current-head CAS semantics, while
  historical retries remain reproducible.
- Cutover and dispatch are unavailable until real authoritative reconciliation
  and strategy-activity adapters are injected.
- Cutover and authorization are also unavailable until a full-policy
  transactional evidence producer is injected; fixture or caller observations
  cannot enable the repository.
- Existing pre-cutover history is not silently promoted into advanced-risk
  authority.
