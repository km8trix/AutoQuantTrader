# ADR 0063: coherent process-local order-view supervision wiring

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4Q derives one bounded order-view action from a Phase 4O state loader,
one-page workflow, and Phase 4P comparison repository. It authenticates the
selected and unselected durable states before and after a page request, but the
application contract previously required only method-shaped ports. A
misconfigured composition could therefore read source states from one SQL
store, execute and persist a provider-backed page through another, or append
and reload a comparison from a copied third store.

Those substitutions are usually detected after durable reconstruction, but a
page-path failure can occur only after credentials, non-refundable request
capacity, and one provider request have already been consumed. Matching
canonical values in copied stores can also make a disconnected comparison
repository appear internally valid. This is a process-wiring failure, not the
same-store transition race left open by Phase 4Q.

## Decision

1. Advance the Phase 4Q supervisor contract and policy to version 2. Include
   the requirement for one process-local durable store in the policy digest so
   version 1 and version 2 round and result identities cannot share semantics.
2. Require the authenticated state loader, one-page workflow, and comparison
   repository to expose an opaque `runtime_store_identity`.
3. Accept only exact positive `int` identities. Reject missing, Boolean, zero,
   negative, exceptional, or unequal values through the existing Phase 4Q
   conflict taxonomy.
4. Validate all three identities before loading either source state, consulting
   the trusted clock, preparing a page, resolving credentials, allocating
   request capacity, invoking transport, or recording or loading a comparison.
5. Have the Phase 4O order-snapshot SQL repository and Phase 4P order-view
   comparison SQL repository identify the exact in-process SQLAlchemy
   `Engine` object with `id(engine)`. Distinct repository objects over the same
   engine therefore compose, while distinct engine objects are rejected
   conservatively even when their URLs happen to match.
6. Treat the page-workflow identity as a trusted composition assertion derived
   from the Phase 4O runtime repository it uses. This guards accidental
   dependency-injection splits; it is not a defense against a malicious port
   that lies about its identity.
7. Never include the opaque process-local integer in canonical material,
   durable evidence, logs, or stable identifiers. Only the versioned policy
   requirement is semantic.
8. Preserve all existing Phase 4Q bounds and evidence checks: one page or one
   comparison per invocation, no loop or sleep, stalled-state refusal,
   same-fence page evidence, exact post-page reload, unchanged unselected
   source, later-start scheduling evidence, and comparison reauthentication.
9. Add no table, migration, provider call, retry, scheduler, stalled-claim
   recovery, convergence claim, reconciliation application, readiness
   transition, or trading authority.
10. Keep the same-store time-of-check/time-of-use race explicit. A direct
    Phase 4O caller can still prepare the unselected plan after Phase 4Q reads
    both states and before the selected provider request completes. Phase 4Q
    detects that mutation afterward but cannot reclaim the spent request.
    Durable ordered-pair membership and per-page transition admission remain a
    separate phase.

## Consequences

Phase 4Q now fails closed before effects when its state, page, and comparison
ports are accidentally wired to different runtime stores. Comparisons cannot
be accepted merely because another copied database contains matching source
history, and a page workflow cannot silently persist outside the store that
the supervisor reloads.

This boundary establishes composition coherence only. It does not serialize
the two source plans across provider I/O, prevent cross-round or opposite-role
plan reuse, or make an unselected state exclusive before a selected request.
The next durable admission slice must register the ordered pair under the
shared account lock, block unscoped Phase 4O preparation of registered plans,
and bind each exact next-page claim to a consumption without holding a
transaction across provider I/O. Phase 4 and its reconciliation and readiness
exit gate remain open.
