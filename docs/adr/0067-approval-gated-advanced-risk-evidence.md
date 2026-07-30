# ADR 0067: approval-gated advanced-risk evidence boundary

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 5 requires advanced rules for session loss and drawdown, concentration,
leverage, volatility, spread and slippage, broker rejects and request pressure,
clock and data health, unresolved submissions, and reconciliation duration.
The architecture does not yet freeze the metric definitions, thresholds,
sampling windows, source authorities, or the action each breach takes. Those
choices change trading behavior and require owner approval.

The existing Phase 2 batch-risk contract is already durable. Its rule tuple,
policy digest, decisions, reservations, and exact-retry loaders depend on the
current semantic material. Phase 5A operational-control identities likewise
depend on their pinned policy digest. Adding advanced fields or defaults to
either contract would reinterpret or invalidate retained history.

Current source truth is also incomplete. The canonical account projection has
point-in-time equity and profit-and-loss values but no durable session-opening
or high-water chain. Current causal prices are close-only and cannot establish
quoted spread. Phase 4 order and position comparisons are explicitly
unqualified and cannot establish clean reconciliation or canonical broker
exposure. No authenticated clock/data-health monitor exists, and broker reject
events do not yet have an approved rolling-rate taxonomy.

## Decision

1. Add a separate `phase5b-advanced-risk-observe-only-v1` domain contract.
   Do not change the Phase 2 batch-risk contract version, rule tuple, limits,
   decisions, authorizations, or persisted digests. Do not change the Phase 5A
   operational-control policy material or treat its opaque trip digests as
   authenticated advanced-risk facts.
2. Represent each planned rule family with an immutable proposed measurement
   binding. A binding identifies a calculator artifact, source schema,
   measurement scope, and unit. It contains no threshold, comparator, enabled
   default, breach result, target control state, or authorization. A proposed
   policy remains explicitly owner-unapproved regardless of structural
   completeness.
3. Use the closed evidence-completeness vocabulary `COMPLETE`,
   `INSUFFICIENT`, `UNAVAILABLE`, and `OVERFLOWED`. `COMPLETE` means only that
   the proposed measurement is structurally reproducible from all retained
   source references. It does not mean healthy, within a limit, approved, or
   safe. Incomplete evidence cannot carry a value, and overflow remains
   incomplete.
4. Bind observations to account and environment, producer identity/version and
   authority digest, an idempotency key, one exact proposed rule binding, an
   explicit causal window, UTC observation/recording times, exact finite
   `NUMERIC(28,10)`-representable values when complete, and canonically ordered
   source identities/digests/times. Bind the versioned Decimal arithmetic
   policy into semantic material. Bound a candidate to 64 rules and one
   observation to 2,048 retained sources; an overflow records a larger exact
   count and a full-set digest but grants no authority.
5. Allow a structurally complete candidate-rule evidence bundle only when
   every retained observation is complete, exact-rule-bound, account/
   environment-consistent, canonically ordered, and available before the
   bundle time. The bundle still reports trading, control, and activation
   effects as `NONE`.
6. Expose an explicit policy-evaluation gate whose only current result is
   `OWNER_APPROVAL_REQUIRED`. A direct activation check always fails closed.
   This slice has no conversion to `RiskRuleResult`, `BatchRiskDecision`,
   reservation, authorization, operational-control `TRIP`, re-arm evidence,
   broker call, or dispatch.
7. Do not add Phase 5B SQL tables or migration revision 0026 until the owner
   approves metric semantics and actions. Premature DDL would freeze rule
   payloads, units, comparison/window boundaries, activation authority,
   idempotency, decimal/cardinality limits, and policy ordering before the
   domain is decided. Existing Phase 2 policy digests cannot be backfilled into
   reconstructable advanced policies, and existing Phase 5A trip digests have
   no evidence-safe advanced-policy foreign key.
8. After approval, add an immutable content-addressed policy registry, one
   account-local predecessor chain for policy assignment and atomic all-rule
   assessment, and an authenticated current-head projection. Policy assignment
   will use exact-head compare-and-set rather than last-writer-wins. Historical
   exact retries will be resolved before trusted time or current-head checks.
   A later exact trip-binding table will join an authenticated breached
   assessment to its operational transition in the same transaction.
9. Advanced enforcement will not be post-hoc. The future transaction must bind
   the activated policy, exact observation watermark, operational-control head,
   account fence, snapshot, active pending/unknown capacity, decision,
   reservation, and child authorizations atomically. Dispatch will recheck
   those bindings. Until that composition exists, advanced evidence is
   observational only and absence never falls back to a permissive policy.

## Consequences

The repository can now model proposed advanced-risk measurements, explicit
source insufficiency, and deterministic evidence identity without inventing
risk policy or changing durable Phase 2/5A semantics. Tests can exercise
chronology, bounds, Decimal stability, source membership, and authority
separation before production sources exist.

Phase 5B is not complete. No proposed calculator or source digest is
authenticated by this generic domain contract, no threshold or action is
approved, no policy is active, and no evidence is persisted or enforced. The
owner must approve the risk envelope before persistence, evaluation,
circuit-breaker binding, or atomic authorization integration can be frozen.
