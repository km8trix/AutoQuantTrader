# ADR 0053: durable authenticated Alpaca order-view comparisons

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4N can compare two supplied bounded order traversals, but it deliberately
does not prove that either value came from the authenticated durable runtime.
Phase 4O can reconstruct and authenticate an exact committed traversal prefix,
but it does not retain a comparison between two completed captures. A process
restart or caller-supplied value must not be able to substitute a different
capture, page, raw receipt, traversal profile, or comparison result.

Durably retaining an exact pair comparison is useful evidence for later
reconciliation work. It is not enough to qualify convergence: the order-list
endpoint is not an isolated provider snapshot, UTC receipt times are not a
trusted monotonic clock, and positions, fills, activities, and buffered stream
events are not represented.

## Decision

1. Define Phase 4P as a local, non-I/O boundary over two terminal Phase 4O
   capture prefixes. The boundary reloads both sources from durable storage and
   accepts neither caller-supplied pages nor caller-supplied comparison output.
2. Require both sources to be exact Phase 4O terminal prefixes under the same
   account and traversal profile. Their capture identities and raw ingress
   sources must be distinct, and the later capture must follow the earlier
   capture in strict account-local raw ingress order.
3. Accept both terminal shapes:
   - cursor exhaustion is retained as a non-isolated ended traversal; and
   - bounded truncation is retained only as incomplete evidence.
   An active or stalled prefix is never comparable.
4. Reauthenticate the complete Phase 4O plan, page, head, permit, raw ingress,
   provider-account identity, and fence lineage for both sources before
   deriving evidence. The evidence binds the exact source plan identities,
   terminal page receipt identities and digests, reconstructed capture
   digests, traversal profile, account, and source windows.
5. Recompute the Phase 4N result from those exact reconstructed captures.
   Added, removed, and changed provider order IDs, view digests, UTC separation,
   and disposition are derived values; callers cannot select or override them.
6. Give the comparison evidence and durable receipt deterministic identities.
   An exact retry returns the existing receipt. Reusing an identity with
   different source or derived values is an immutable conflict.
7. Append receipts under the existing account serialization boundary. Bind
   each receipt to its predecessor and retain an account-local terminal head so
   deletion, insertion, fork, rollback, or cross-account substitution fails
   startup and read-time integrity checks.
8. Revalidate the current account fence inside the commit transaction. This
   proves only that the local append occurred under the expected coordinator
   generation; it does not make the historical provider views current.
9. Allow only narrowly scoped provenance properties to become true: both
   captures and durable source positions were authenticated and the comparison
   was durably recorded. Request-budget and raw-first properties remain facts
   of the exact Phase 4O sources, not new permissions granted by Phase 4P.
10. Keep snapshot isolation/completeness, trusted monotonic timing, provider
    revision or deduplication identity, convergence, lifecycle or execution
    application, `UNKNOWN` resolution, reservation release, reconciliation
    completion, readiness transition, broker transport, and every trading
    authority false. Even two equal cursor-exhausted order views remain
    `exact_order_view_match_unqualified`.
11. Add only additive Phase 4 tables and local application/persistence
    contracts. Add no API, worker, trader composition, provider request, secret
    resolution, background supervisor, or startup readiness change.

## Consequences

The repository can retain and reconstruct a tamper-evident history of exact
authenticated order-view comparisons across restarts. A later reconciliation
barrier can consume this evidence without trusting process memory or
caller-computed differences.

This slice does not provide automatic traversal supervision or recovery for a
stalled capture. It also does not cover account, position, fill, or activity
snapshots; stream buffering and resume; provider-qualified event identities;
authoritative inbox application; whole-account convergence; paper startup; or
the Phase 4 exit gate.
