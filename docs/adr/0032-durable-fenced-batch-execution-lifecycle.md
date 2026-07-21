# ADR 0032: durable fenced batch execution lifecycle

- Status: Accepted
- Date: 2026-07-21

## Context

ADR 0030 and ADR 0031 establish atomic batch reservations and account fencing,
but their process-local state cannot survive a restart or serialize independent
workers. Durable preparation must also make it impossible to consume one child
authorization twice, call a broker without first recording the exact request,
or release capacity merely because a local submission outcome is uncertain.

This phase needs a SQL crash boundary for those facts while retaining the
existing prohibition on paper and live trading.

## Decision

1. Persist Phase 2 execution evidence in the independent `phase2_*` SQL schema.
   Immutable lease revisions, clean releases, batch decisions and members,
   reservations and child authorizations, logical orders, authorization
   consumptions, submission attempts and events, canonical order events,
   reservation releases, canonical-ledger facts, sealed replay manifests, and
   typed simulation-horizon facts are content-bound and checked by relational
   constraints and readiness-time integrity verification. Lockable heads are
   mutable projections, not replacements for immutable history.
2. Coordinate each account through a durable lease head with a monotonically
   increasing fencing generation. Acquisition, renewal, validation, and clean
   release lock and compare the current head. Every risk, preparation, dispatch,
   and reservation mutation revalidates the exact stable fence inside its SQL
   transaction and samples the trusted coordinator clock while holding that
   lock. Caller logical event time cannot backdate an effect past real expiry.
   Renewal creates a gap-free immutable revision that names its exact
   predecessor without changing the stable fence. An additive migration retains
   authenticated legacy lease digests and downstream references; all new lease
   revisions use the chained lease-only v2 contract. Expiry blocks effects and
   does not itself authorize a new owner or automatic takeover.
3. Authorize a complete intent batch in one transaction after locking the
   coordinator and current capacity evidence. Reconstruct a canonical
   authenticated active-capacity universe, and bind its exact payload and digest
   into the decision. A partially released child contributes only its remaining
   cash, exposure, and sell-share holds; a frozen child retains that exact
   remainder; a fully released child is omitted. Allocate a gap-free account
   observation sequence under the same lock for every approved, rejected, and
   no-action decision. Every capacity-affecting submission, order, and release
   mutation takes that same account-head lock and authenticates the observation
   watermark after which it is visible. Decision `N` reconstructs exactly the
   mutation prefix with marker less than `N`, making equal-timestamp history
   unambiguous without using clocks as a tie-breaker. The additive migration
   preserves v3 decision identities and marker-zero legacy mutations; all new
   decisions and mutations use the v4 ordering contract. The
   transaction publishes the decision, ordered members, parent reservation, and
   all child authorizations, or none of them. An exact batch retry returns the
   existing decision before recalculating the capacity changed by its own
   reservation; reusing an
   identity with different batch, snapshot, policy, account, or fence evidence
   fails closed.
4. Before dispatch, atomically create the deterministic logical order, consume
   its one-shot child authorization, persist the bounded canonical adapter
   request and preparation fence receipt, and append the initial `PENDING`
   event. A failed insert rolls the complete preparation back. Existing logical-
   order and consumption identities cannot be duplicated; a new attempt retains
   the stable client-order identity and is allowed only after the prior request
   is proven unsent as `ABANDONED`. A future real reconciliation producer may
   add a separately authenticated `NOT_SUBMITTED` path in Phase 4.
5. Append submission transitions as `PENDING`, `ABANDONED`, `IN_FLIGHT`,
   `CONFIRMED`, `UNKNOWN`, and `RESOLVED` chains. Entering `IN_FLIGHT` requires a
   fresh transaction-time dispatch receipt that binds the prepared stable
   account/owner/generation fence, current immutable lease revision and policy,
   validation time, and expiry. Renewal under that same stable fence can
   dispatch with the new receipt; a later fencing generation cannot dispatch old
   preparation. Recovery may close only a stale `PENDING` head, which has no
   dispatch receipt and never crossed the broker-call boundary, as proven-unsent
   `ABANDONED`. Any expiry release must reauthenticate the complete causally
   visible attempt snapshot, prove every target attempt abandoned, reject a
   visible `UNKNOWN` sibling, and remain valid if unrelated later sibling
   activity is appended. A later confirmation or uncertainty outcome records
   what happened without pretending an expired lease can erase an already
   possible broker effect. Recovery promotes stale `IN_FLIGHT` heads to
   `UNKNOWN`.
6. Any unresolved `UNKNOWN` attempt freezes the complete parent reservation and
   prevents sibling dispatch, new attempts, and capacity release. Although the
   domain vocabulary reserves broker-reconciliation outcomes, the Phase 2 SQL
   repository rejects UNKNOWN resolution and readiness rejects every persisted
   `RESOLVED` attempt. UNKNOWN therefore remains frozen until Phase 4 provides a
   real authenticated reconciliation producer.
7. The domain vocabulary reserves five append-only release reasons: expired and
   proven unsent approval, exact broker rejection, execution already represented
   by durable accounting, independently reconciled terminal state, and an
   explicitly sealed simulation horizon. The durable runtime enables the first
   three and the narrow typed local `SIMULATION_HORIZON_FINAL` proof below. It
   rejects generic `RECONCILED_TERMINAL` facts. Releases conserve each child's
   cash, buy exposure, and sell shares and move the parent monotonically through
   active, partially released, frozen, and released projections.
8. Execution accounting releases only a positive increase over previously
   accounted quantity. Every correction requires exact cumulative accounting
   coverage of its immediate predecessor revision; only the positive
   predecessor-relative delta releases. The writer derives the exact canonical
   ledger entry from the persisted order state rather than accepting an
   arbitrary balanced digest.
   Quantity, price, fee, cash, security units, postings, source event, account,
   and time must all agree. Readiness re-derives that complete economic entry.
   At the shared SQLite/PostgreSQL boundary, posting decimals must also survive
   SQLite's ten-place `NUMERIC` float transport exactly; non-portable values fail
   before any row is inserted. Any canonical historical downward or equal-
   quantity correction freezes the reservation instead of reclaiming capacity.
   That freeze is sticky and cannot be hidden by accounting another execution
   or appending a later revision. The append-only ledger retains a complete
   economic revision chain when its predecessor is already accounted; it never
   persists only one side of a newly discovered corrected chain. New batch
   authorization for the account is quarantined until the correction has an
   authenticated closure. A terminal reservation remains released rather than
   inventing a mutable capacity hold, but it still activates that quarantine.
   Stale or skipped revision chains are rejected as malformed, and readiness
   fails closed if they are injected below the relational boundary.
9. Permit `SIMULATION_HORIZON_FINAL` only for repository-owned deterministic
   simulation through a proof with no caller-supplied hashes or finality time.
   Before dispatch, commit a typed simulation request bound to the exact replay
   manifest, calendar/session, instrument universe, model, and stable submission
   inputs. Persist the complete canonical replay input events and watermarks plus
   those committed inputs, the complete safe-retry attempt chain, and the
   derived result identity, linked to the sealed replay manifest and durable
   reservation, child
   authorization, `CONFIRMED` attempt, order, and final event. Every write,
   read, and readiness
   check reruns the market replay, reproduces the sealed manifest, reruns
   `ConservativeSimulatedBroker`, and reconstructs the typed horizon fact; all
   durable and recomputed evidence must be exactly equal, including the one
   recording instant shared by the horizon proof and release.
10. Before a simulation horizon releases residual capacity, require every final
    execution projection to be completely covered by `EXECUTION_ACCOUNTED`
    releases bound to the exact head event ID, revision, quantity, and canonical
    ledger entry. A sealed zero-fill working result requires no execution
    accounting. Unaccounted fills, correction-frozen or stale heads, arbitrary
    hash/time assertions, every persisted `RESOLVED` attempt, and every generic
    reconciled-terminal fact fail closed.

These decisions complete the durable deterministic-fixture boundary, not a
broker-reconciliation producer. Retry after an external `NOT_SUBMITTED`
classification, real terminal reconciliation, coordinator takeover, and
operator re-arm remain Phase 4 work.

## Consequences

Independent workers now share one durable account fence and capacity universe.
Batch authorization is all-or-none, idempotent, and bound to exact remaining-
capacity provenance. Broker preparation is replay-safe and atomic, ambiguous
submissions remain conservative across restarts, canonical ledger economics
cannot be replaced by a merely balanced counterfeit, and residual simulation
capacity cannot be released without reconstructing its deterministic proof.

This is a durable simulation foundation, not trading authority. There is no
paper or live broker adapter, broker-enforced fencing token, automated expired
lease takeover, real reconciliation service, operator re-arm workflow, or
paper/live runtime wiring. The local application continues to reject paper and
live startup, so those environments remain gated despite the SQL durability.
