# ADR 0061: durable Alpaca position-pair transition admission

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4W derives one bounded action from two authenticated Phase 4U states, but
its application-only check cannot make the selected and unselected plan states
exclusive before the selected broker read begins. If an unscoped Phase 4T
caller prepares the other plan after Phase 4W reads both states, Phase 4W can
detect the mutation only after one bounded provider request has already
occurred.

Holding a database transaction across credentials, request admission, and
network I/O would replace that race with an unsafe long-lived lock. Rewriting
the Phase 4U plan row to carry optional supervisor authority would also change
already-authenticated single-use evidence.

## Decision

1. Define Phase 4X as the
   `phase4x-durable-position-view-transition-admission-v1` application
   contract with an additive SQL persistence boundary, and advance the schema
   head to `0023_phase4_position_transition`.
2. Register one ordered pair of distinct Phase 4T plans for the same local
   account and operator-pinned provider account UUID. Store two immutable
   membership rows, one for each fixed role. Globally unique plan, capture,
   plan-digest, and account/idempotency identities prevent either member from
   appearing in another round, including in the opposite role.
3. Admit the earlier role only while both Phase 4U sources are absent. The
   first claim inserts both memberships and the immutable earlier claim in one
   transaction under the shared account lock. If an ordinary Phase 4U
   preparation wins that lock first, transition admission observes a stalled
   source and records nothing.
4. Admit the later role only after reconstructing an exact complete earlier
   Phase 4U receipt and an absent later source. Its claim carries an exact
   composite foreign key to that earlier receipt and requires the current
   fence-validation instant to be at or after the earlier raw receive time
   plus two seconds.
5. Bind every role claim to both exact membership rows, the selected member,
   transition policy, current account fence, and historical selection time.
   New claims receive a second same-lease, nonregressing, pre-expiry fence
   validation after exact SQL readback and before transaction completion.
6. Permit exact claim lookup/retry only after authenticating the current call
   fence. Return the original historical claim without rewriting its selected
   time or fence. A historical claim alone is not provider-call authority.
7. Add one immutable consumption row per claim. Pair-aware preparation
   authenticates the exact live claim and same historical lease, proves it is
   unconsumed, inserts the unchanged Phase 4U plan-as-claim and its one-to-one
   consumption in the same account-locked transaction, reads both back
   exactly, and performs a final same-lease fence validation before commit.
8. Make the public unscoped Phase 4U `prepare` query transition membership
   under the same account lock. It rejects either registered member before
   credential resolution, request-capacity admission, or transport. Only the
   pair-aware in-transaction path may prepare a registered plan.
9. Preserve the Phase 4U `ABSENT`, `STALLED`, and `COMPLETE` meanings. A
   transition claim without a consumption is not a Phase 4U plan and therefore
   does not pre-stall both members. Once consumption commits, a missing Phase
   4U receipt remains the existing permanent stalled state and cannot be
   prepared again.
10. Do not transfer an unconsumed claim across a lease revision, renewal, or
    takeover. A crash before consumption can resume only while the exact claim
    lease remains current; otherwise it stalls conservatively. A crash after
    atomic consumption retains Phase 4U's no-resend rule. No database
    transaction remains open across provider I/O.
11. Reconstruct every membership, claim, referenced Phase 4U source,
    consumption, preparation, and fence during load and whole-store readiness.
    Reject partial rounds, cross-round reuse, substitutions, orphaned rows,
    role swaps, consumed claims without their exact Phase 4U plan, or
    registered Phase 4U plans without consumption. Refuse downgrade while any
    transition table is nonempty.
12. Keep all evidence non-authorizing beyond the exact single-use preparation
    boundary. Phase 4X performs no provider I/O and establishes no snapshot
    isolation/completeness, canonical position fact, application,
    reconciliation completion, convergence, readiness, submission, or trading
    authority.

## Consequences

For a registered position pair, account-lock ordering now gives a binary
pre-effect outcome: an unscoped Phase 4U preparation wins first and Phase 4X
records nothing, or Phase 4X registers the pair first and every unscoped
preparation of either member fails before external effects. Claim consumption
then preserves the existing Phase 4U plan evidence and no-resend semantics
without holding a transaction across the broker request.

Phase 4X does not yet compose the claim/consumption path into Phase 4T and
Phase 4W, deploy a scheduler or worker, recover a stalled claim, or coordinate
the analogous Phase 4Q order pair. Combined account/order/position
reconciliation, activity and fill coverage, stream overlap, provider-qualified
event identities, authoritative application, convergence, and the Phase 4 exit
gate remain open.
