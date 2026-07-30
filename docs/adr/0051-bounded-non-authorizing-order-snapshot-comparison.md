# ADR 0051: bounded non-authorizing order-snapshot comparison

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4M can retain and validate one bounded descending Alpaca order-page
capture, but it deliberately does not treat several REST pages as an isolated
provider snapshot. The future reconciliation barrier calls for repeated views,
yet calling two equal local captures "converged" would overstate the available
evidence. Neither capture has provider snapshot isolation, a qualified provider
revision, authenticated runtime ownership, or activity/stream overlap.

A useful next local step is therefore narrower: compare two exact Phase 4M
captures deterministically, independent of their page boundaries, while
preserving every Phase 4M authority restriction. The comparison must distinguish
an ended but safety-truncated traversal from a complete cursor walk, require the
two sources to be genuinely separate and ordered, and avoid interpreting an
order-value change as a provider event or execution.

## Decision

1. Define Phase 4N as the pure
   `phase4n-bounded-order-view-comparison-v1` contract under the fixed
   `phase4n-exact-order-view-comparison-policy-v1` policy. It performs no
   persistence, credential resolution, request-budget admission, transport,
   scheduling, worker execution, or startup composition.
2. Accept only two distinct exact Phase 4M captures for the same account and
   traversal profile. The page limit and maximum-page bound must match. Both
   traversals must have ended because their cursor was exhausted or their page
   bound was reached; an in-progress capture is rejected rather than treated as a
   comparable view.
3. Require independent, strictly ordered sources:
   - the captures and their capture identities must be distinct;
   - their Phase 4C ingress receipt IDs must be disjoint;
   - the earlier capture's final ingress sequence must be less than the later
     capture's first ingress sequence; and
   - cross-account, profile-drifted, shared-source, same-capture, or reversed
     source inputs fail closed.
4. Measure observed separation as the later capture's first page
   `received_at` minus the earlier capture's last page `received_at`. The fixed
   minimum is two seconds. Exactly two seconds qualifies for comparison; a
   smaller interval produces `waiting_minimum_separation`. This local UTC
   comparison is not monotonic-clock evidence, so
   `monotonic_timing_qualified` remains false.
5. Derive each capture's page-boundary-independent view by flattening its orders
   and sorting exact pairs of
   `(provider_order_id, AlpacaOrderObservation.semantic_sha256)` by provider
   order ID. Page breaks, raw receipt identities, and local arrival position do
   not alter this value view.
6. Compare the sorted views without inferring event order:
   - `added` IDs occur only in the later view;
   - `removed` IDs occur only in the earlier view; and
   - `changed` IDs occur in both views with different order semantic digests.
   Every output ID set is exact, sorted, and disjoint from the other
   classifications.
7. Apply one closed disposition in this precedence:
   - `bounded_traversal_incomplete` when either ended traversal reached its
     Phase 4M page bound instead of exhausting its cursor;
   - `waiting_minimum_separation` when both cursors exhausted but the observed
     separation is less than two seconds;
   - `order_view_different` when a qualified pair has any added, removed, or
     changed provider order ID; or
   - `exact_order_view_match_unqualified` when the qualified sorted views are
     byte-for-byte semantically equal.
8. Treat even `exact_order_view_match_unqualified` as a local comparison result,
   never reconciliation convergence. `converged`, snapshot isolation,
   capture authentication, durable-source-position authentication,
   provider-revision qualification, provider deduplication, normalized-fact
   and inbox application, lifecycle and UNKNOWN application,
   execution/correction identity, broker-call authority, and trading-effect
   authority all remain false.
9. Keep every Alpaca paper runtime-readiness flag false. Phase 4N does not make
   Phase 4M pagination authenticated or restart-safe, does not persist a
   comparison result, and does not add account, position, activity, or stream
   evidence.

## Consequences

The repository can now describe exactly how two bounded local order captures
differ without depending on page layout. Added, removed, and value-changed
provider order IDs are deterministic review evidence, and a caller can
distinguish safety truncation from a too-soon second view and from a later exact
match.

The result is intentionally insufficient for the reconciliation barrier. Two
non-isolated REST views can match while an unseen provider change, stream
delivery, execution, bust, correction, manual action, or account/activity
change remains outstanding. Authenticated restart-safe capture, durable
comparison history, provider-qualified stream/snapshot overlap and identities,
authoritative application, genuine two-view convergence, and the Phase 4 paper
gate remain open.
