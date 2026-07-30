# ADR 0058: durable single-use Alpaca position snapshots

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4T defines the authenticated execution envelope for one Phase 4R
position capture, but only through a durable port and injected test fake. Its
safety depends on a fresh preparation being permanently single-use, exact
source evidence being authenticated again at commit and load, and an
independent account-fence check occurring inside the commit transaction.

A retryable or mutable head would add state that this one-request workflow does
not need. It could also blur the conservative distinction between a capture
that never started and one that was claimed before a crash.

## Decision

1. Define Phase 4U as the
   `phase4u-single-use-position-snapshot-persistence-v1` SQL boundary and
   advance the additive schema head to `0021_phase4_position_snapshots`.
2. Store each Phase 4T runtime plan and preparation in one immutable plan row.
   The row itself is the durable fresh-only claim. `capture_id` is globally
   unique, and `(account_id, capture_idempotency_key)` is unique, so a changed
   credential reference or account binding cannot reuse the stable Phase 4R
   capture identity.
3. Store at most one immutable authenticated receipt for that plan. The
   derived states are deliberately minimal:
   - no plan row means unclaimed;
   - a plan row without a receipt means permanently stalled;
   - a plan row with its exact one-to-one receipt means complete.
   There is no mutable head and no retry transition.
4. Serialize preparation and recording with the shared account-capacity lock.
   Only the transaction that inserts a new plan may return its preparation.
   Every later preparation for the same capture, including a changed plan,
   fails before credentials, permit issuance, or transport.
5. Foreign-key the claim to its exact durable Phase 4G account binding. Foreign
   key the receipt to the exact claim, Phase 4D permit and demand, Phase 4C raw
   ingress receipt, and the pre/post/final/commit account-lease revisions.
   Preserve the complete semantic digests and duplicated time/bound fields
   needed for independent reconstruction and corruption detection.
6. Treat account-binding continuity as identity evidence, not account-status
   freshness. Every check must occur at or after the binding qualification
   instant, but it may occur after the five-second Phase 4G status TTL. Reject
   a binding successor qualified before the relevant historical commit instant,
   and require the exact terminal binding during new preparation and commit.
7. Before inserting a receipt, reauthenticate the exact plan/preparation,
   terminal binding and identity receipts, request permit and source position,
   raw ingress receipt and source position, and all runtime fence positions.
   Independently revalidate the same fence lease inside the transaction at or
   after `authenticated_at`.
8. Insert and reconstruct the exact receipt, assert every stored value
   immutable, and revalidate the same fence again immediately before
   transaction completion. A completed capture cannot use `record` as a retry
   path.
9. Make `load` and whole-store verification reconstruct every plan,
   preparation, credential receipt, account-identity proof, permit/freshness
   proof, fence receipt, transport request/response, raw receipt, decoded
   Phase 4R observation, runtime evidence, and commit receipt. Conflicting
   plan/capture identities, duplicates, missing sources, orphans, rollback,
   successor substitution, or payload drift fail closed.
10. Include both tables and the full-history verifier in operational readiness.
    Merely carrying the Alembic revision is insufficient. Refuse downgrade
    while either a stalled claim or committed receipt remains.
11. Keep the runtime authority unchanged. Durable evidence still does not
    establish current account status, snapshot isolation or completeness,
    provider revision/deduplication identity, canonical positions/cash/ledger,
    lifecycle or reconciliation application, convergence/completion, readiness,
    UNKNOWN resolution, resubmission, or any trading authority.

## Consequences

Phase 4T now has a concrete restart-conservative SQL implementation. A crash
after the plan insert leaves an auditable stalled claim that can never resend;
a committed receipt can be reconstructed and authenticated exactly after
restart.

Durable two-view comparison, pair supervision, account/order/position
composition, activity and fill views, stream overlap, provider-qualified event
identities, authoritative application, convergence, and the Phase 4 exit gate
remain open.
