# ADR 0083: durable authenticated account-activity comparisons

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4AF compares two supplied bounded account-activity captures without
claiming that either came from durable authenticated transport. Phase 4AG
closes that in-memory provenance gap by reloading two terminal Phase 4AE states
and recomputing the Phase 4AF result, but it defines only an application port.
Without a durable implementation, a restart loses the comparison and a caller
could attempt to substitute a source head, raw receipt, provider-account
identity, traversal profile, or derived difference.

Durable pair evidence is useful to later reconciliation work, but equal FILL
views are still not proof of complete provider history, isolation, monotonic
time, canonical execution identity, correction identity, or convergence.

## Decision

1. Define Phase 4AH as the
   `phase4ah-authenticated-account-activity-comparison-persistence-v1`
   boundary. It performs no provider I/O and accepts only exact Phase 4AG
   evidence plus the expected account fence.
2. Inside the append transaction, reload both distinct terminal Phase 4AE
   traversal states from their capture identities. Reconstruct every page from
   its immutable preparation, account binding, request permit, raw ingress
   bytes, lease and fence lineage, and predecessor before accepting either
   source.
3. Require both sources to name the same account, canonical historical
   provider-account UUID, and exact traversal profile. Preserve their distinct
   plans, terminal head digests, state/prefix/capture digests, first and
   terminal page receipts, raw ingress identities and sequences, source commit
   times, view windows, counts, and view digests.
4. Require strict source order: every earlier raw ingress position precedes
   every later position. Accept cursor-exhausted and bounded-truncated terminal
   states, but retain bounded truncation only as explicit incomplete evidence.
5. Recompute the exact Phase 4AF comparison from the reconstructed captures.
   Disposition, UTC separation, view digests, and added, removed, and changed
   opaque provider activity-ID sets are derived values; SQL rows and callers
   cannot select them independently.
6. Persist at most one immutable receipt for an exact ordered capture pair
   under the Phase 4AG authentication policy. Evidence, comparison, receipt,
   semantic, and pair identities are unique. An exact retry returns the
   historical receipt after authenticating the current call fence; conflicting
   reuse fails closed.
7. Serialize appends with the existing account lock. Bind each receipt to its
   account-local sequence and predecessor digest, and authenticate a terminal
   comparison head so insertion, deletion, fork, rollback, truncation, orphan
   rows, or cross-account substitution fails at read and startup.
8. Revalidate the exact current account fence inside the write transaction
   before deciding retry versus append and again immediately before commit.
   Both checks must retain the same lease and nonregressing valid time. This
   proves local append authority only; it does not make either historical
   provider view current.
9. Require the Phase 4AE loader and Phase 4AH repository to expose the same
   positive process-local engine identity before application composition.
   Cross-store comparison is rejected before source loading.
10. Use additive comparison and head tables in migration 0033, directly
    foreign-keyed to exact source plans, terminal heads, first and terminal
    pages, raw ingress receipts, account lease, predecessor, and terminal
    comparison receipt. Refuse downgrade while either comparison table is
    nonempty.
11. Authenticate every comparison chain during operational startup after the
    underlying Phase 4AE source verifier. Any source tamper, changed derived
    value, malformed fence, discontinuous chain, or inconsistent head makes the
    schema not ready.
12. Allow only narrow provenance facts to become true: both exact durable
    source positions were authenticated and the recomputed comparison was
    durably recorded. Source request budgets, provider evidence, raw bytes, and
    historical account identity remain inherited facts of those exact sources.
13. Keep provider I/O, current account status, complete activity history,
    snapshot isolation, monotonic timing, convergence, canonical execution or
    revision identity, deduplication, bust/correction/manual application,
    reconciliation completion, readiness, reservation release, resubmission,
    transport, broker calls, and every trading effect unauthorized.

## Consequences

The repository retains a restart-safe, tamper-evident account-local history of
exact Phase 4AG comparisons and can reconstruct both full raw-backed source
prefixes before accepting a receipt. Concurrent exact retries converge on one
receipt and one head instead of forking history.

Phase 4AH does not supervise repeated capture, recover a stalled page, prove a
complete account-activity history, qualify a canonical fill or correction,
deduplicate stream and REST events, apply ledger or inbox facts, complete
reconciliation, or establish paper startup readiness. Those remain open.
