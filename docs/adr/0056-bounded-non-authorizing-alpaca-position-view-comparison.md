# ADR 0056: bounded non-authorizing Alpaca position-view comparison

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4R retains one strict open-position response but cannot determine whether
the account view is stable. The reconciliation barrier eventually needs to
compare repeated views without relying on response-array order, JSON
formatting, or capture identifiers. It must also avoid treating local receipt
time as provider chronology: `GET /v2/positions` exposes no snapshot timestamp
or revision token, and its mark-to-market values can change continuously.

## Decision

1. Define Phase 4S as a pure comparison of two exact Phase 4R persisted
   captures. It adds no storage, clock read, request, transport, worker, or
   application behavior.
2. Require both captures to use the same account and frozen Phase 4R wire
   profile, distinct capture identities, disjoint raw ingress receipt
   identities, and strictly increasing account-local ingress sequence.
3. Derive a page/order-independent view by sorting
   `(provider_asset_id, position_semantic_sha256)` pairs. The position digest
   includes every reviewed field and exact provider decimal lexeme, so a
   lexeme or live-value change remains visible even when its canonical decimal
   value is equal.
4. Report exact sorted added, removed, and changed provider asset UUIDs. An
   asset-ID substitution is one removal plus one addition rather than an
   invented revision relationship.
5. Require the later local UTC receive time to be at least two seconds after
   the earlier receive time before classifying a difference or exact match.
   Before that boundary, retain the derived differences but return an explicit
   waiting disposition.
6. After the boundary, classify any difference as
   `position_view_different`. Classify equal sorted views only as
   `exact_position_view_match_unqualified`.
7. Bind the comparison identity and semantic digest to the fixed policy,
   complete exact captures and receipts, profile, receive times, sorted view
   digests, separation, differences, and disposition.
8. Keep all authority false. Local receive separation is not monotonic provider
   timing; equal views do not prove snapshot isolation, provider completeness,
   a provider revision, canonical positions, reconciliation convergence,
   readiness, broker-call authority, or trading authority. Two empty arrays
   remain unqualified.

## Consequences

Repeated Phase 4R responses can now be compared deterministically despite
array order or raw JSON formatting differences, while exact provider lexemes
and every source remain auditable. Too-close, changed, and equal views have
closed non-authorizing meanings.

Authenticated position transport, durable typed runtime receipts, comparison
persistence, restart-safe supervision, account/order/position composition,
activity and stream overlap, authoritative application, convergence, and the
Phase 4 exit gate remain open.
