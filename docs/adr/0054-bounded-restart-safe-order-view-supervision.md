# ADR 0054: bounded restart-safe Alpaca order-view supervision

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4O can prepare, execute, and commit exactly one authenticated order page,
but deliberately provides no automatic traversal loop. Phase 4P can
reauthenticate and retain a comparison only after both traversal prefixes have
ended. A caller currently has to decide which capture to advance, when a second
capture may begin, and when the durable comparison boundary may be invoked.

That decision must not become an unbounded in-process loop or an implicit
recovery policy. In particular, a crash after Phase 4O has issued a request
permit can leave a deliberately stalled capture that must not be resent. The
supervisor also cannot promote wall-clock separation or equal order views into
provider snapshot isolation, convergence, reconciliation completion, or
readiness.

## Decision

1. Define Phase 4Q as one deterministic application invocation over an ordered
   pair of distinct Phase 4M plans. Both plans must name the same account and
   exact traversal profile. Their ordering and exact semantic digests are part
   of a deterministic supervision-round identity.
2. Reload both plans through a Phase 4O authenticated durable-state port before
   choosing an action. The state must distinguish absent, active, stalled,
   cursor-exhausted, and bounded-truncated heads and bind the exact prefix,
   preparation, and durable head digest. A plain prefix is insufficient because
   it cannot distinguish a resumable next page from a crash-stalled prepared
   page. Caller-supplied pages, page counts, cursors, completion flags, head
   state, or comparison values are never trusted.
3. Permit at most one Phase 4O page execution in an invocation. There is no
   loop, sleep, retry, background task, or catch-up behavior:
   - while the earlier prefix is active, execute only its exact next page;
   - after the earlier prefix has ended, execute only the later prefix's exact
     next page; and
   - when both prefixes have ended, invoke Phase 4P without a broker request.
4. Treat an absent plan as an executable empty page-one state, but require the
   later plan to remain absent/empty while the earlier plan is in any
   nonterminal state. A pre-existing later page in that ordering is a conflict
   rather than evidence that may be reordered or adopted.
5. Before the first later page, require a trusted injected UTC clock to reach
   the earlier prefix's final `received_at` plus the fixed Phase 4N minimum
   separation. Before that deadline, return an explicit waiting result without
   invoking either the page executor or comparison recorder. This is only a
   scheduling lower bound; it is not trusted monotonic provider timing. After
   the first later page, require its authenticated Phase 4O preparation
   `prepared_at`, transport-request `started_at`, and observation `received_at`
   to be at or beyond the same boundary. Phase 4O authenticates their ordering,
   so the preparation instant proves that the first durable operation preceded
   neither the gate nor the later request. Apply that check before adopting any
   pre-existing later prefix, so one later plan cannot be reused under another
   round whose gate it never proved.
6. Reload and authenticate both prefixes after a page executor returns. The
   selected prefix must have advanced by exactly one receipt, the old receipt
   tuple must remain its exact predecessor, the appended receipt must equal the
   executor result and bind the exact requested page, and the unselected prefix
   must remain unchanged. Substitution, no advancement, multi-page advancement,
   rewrite, cross-plan mutation, or early later-source preparation, request, or
   receive evidence fails closed. These authenticated local instants are
   conservative restart-safe scheduling evidence, not monotonic provider
   chronology or convergence qualification.
7. Preserve Phase 4O's stalled-capture behavior. A stalled durable state is an
   explicit conflict and the page executor is never invoked. The current
   Phase 4O head does not distinguish a preparation persisted just before
   permit issuance from a post-permit no-resend stall, so Phase 4Q
   conservatively refuses both rather than guessing. It adds no timeout, permit
   reuse, resend, or recovery authority. Phase 4O preparation is a single-use
   durable claim: the transaction that first persists it is the only caller
   allowed to continue, and every overlapping or restarted prepare call fails
   before credentials, permit issuance, or transport.
8. When both prefixes are terminal, call the exact Phase 4P
   reload/recompute/record workflow under the supplied account fence. Validate
   the returned receipt against the ordered plans, current terminal prefixes,
   and authenticated durable source-head digests. The Phase 4P repository must
   revalidate the exact fence supplied to the current call. On an idempotent
   retry the returned historical receipt keeps its original commit fence, so
   that receipt is not misrepresented as a new current-fence attestation.
   Bounded truncation may be recorded only with its existing incomplete
   disposition.
9. Return a proof-constructed immutable result with a closed stage vocabulary:
   earlier page committed, waiting for later-start separation, later page
   committed, or comparison recorded. Bind the stable ordered round identity,
   complete authenticated before and after states, selected
   description/receipt or comparison receipt, and trusted scheduling
   observation time as applicable.
10. Keep snapshot isolation/completeness, monotonic timing qualification,
    provider revision or cross-channel deduplication identity, convergence,
    lifecycle or reconciliation application, reconciliation completion,
    `UNKNOWN` resolution, reservation release, readiness transition, transport
    authority, submission authority, and every trading authority false.
11. Add no SQL table, API route, deployed worker, secret resolver, real provider
    call, stalled-capture recovery, or startup-readiness transition. Durable
    restart state remains entirely in the existing Phase 4O and Phase 4P
    repositories.

## Consequences

A deployment layer can repeatedly schedule one bounded Phase 4Q invocation
without keeping pagination or pair-comparison state in process memory. Every
successful call either appends one exact authenticated page, records one exact
durable comparison, or explains why the later traversal is not yet eligible.
Crashes are handled by reloading the existing durable prefixes; no automatic
resend is introduced.

This slice still does not establish an isolated or complete broker snapshot,
order-view convergence, account/position/fill/activity reconciliation, stream
overlap, canonical event identities, inbox application, paper startup, or the
Phase 4 exit gate. A production scheduler and any policy for abandoning or
operator-recovering a stalled traversal remain separate approval-bearing work.
