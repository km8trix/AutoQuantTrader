# ADR 0037: configuration-bound governed segment evaluation

- Status: Accepted
- Date: 2026-07-24

## Context

ADR 0036 makes experiment families, attempt budgets, lifecycle history, and
holdout reveal reconstructable, but deliberately records completed attempts
with non-executable fixture evidence. Its initial segment receipt and test
commitment are derived from a complete `CertifiedFeatureTargetReplay`. That
object includes the target policy and runtime pin, so sealing it at family
creation also preselects target behavior before an attempt selects a strategy
configuration. An ignored configuration field could therefore appear to
distinguish attempts while every attempt retained the same target transcript.

The next bounded slice must separate immutable segment input evidence from an
attempt's configuration-specific evaluation result. It must close that exact
reference-path gap without claiming a general backtest runner, performance
metrics, renewable worker leases, process isolation, or automated promotion.

## Decision

1. Define Phase 3D as one configuration-bound, governed target-evaluation slice
   for the existing `rolling-close-mean-cross@1.0.0` reference path.
   `ExperimentSegmentEvidence` becomes configuration-neutral input evidence
   proof-constructed from an exact `CertifiedFeatureReplay`. It binds the
   scoped replay, authenticated tape and manifest lineage, feature artifact,
   feature parity receipt and transcript, and bounded step and snapshot counts.
   It does not bind a target policy, target transcript, or attempted strategy
   configuration.
2. Derive `TestSegmentCommitment` from that same configuration-neutral feature
   certification. Before reveal, the family retains only the opaque tape and
   feature-certification commitments. Reveal opens the exact test input
   evidence; it does not precompute or disclose a selected configuration's
   target result.
3. Admit only the bounded reference configuration vocabulary:
   `long_quantity` and `target_lifetime_seconds`. Both values must reproduce the
   exact `RollingCloseMeanTargetPolicy` used by the supplied
   `CertifiedFeatureTargetReplay`. The family strategy ID and version must
   match the reference runtime, and no ignored or undeclared behavior parameter
   is accepted as evaluation evidence.
4. Proof-construct a `GovernedSegmentEvaluationReceipt` only from an exact
   attempt, its family input evidence, and a successful
   `CertifiedFeatureTargetReplay` whose embedded feature certification equals
   that input evidence. The receipt binds the attempt, configuration and schema
   validation receipt, segment, feature certification, target runtime pin,
   target parity receipt and transcript, exact counts, and one recorded
   evaluator actor identifier.
5. A `COMPLETED` attempt event must carry that exact governed evaluation
   receipt. Failed, canceled, and abandoned attempts continue to carry typed
   non-executable terminal reasons. Completion must be reported by the same
   recorded worker actor identifier that recorded the attempt's current
   `RUNNING` event. A crashed worker is abandoned and a replacement uses a new
   stable, budget-counted attempt; this slice does not provide worker-identity
   issuance, steal claims, or renew claims.
6. Retain the receipt in the existing immutable
   `phase3_experiment_attempt_events.terminal_evidence_payload` and digest. The
   completion command must transiently receive the exact certification and
   reproduce the proposed domain completion inside the locked transaction. The
   closed persistence codec reconstructs the stored receipt summary, while
   existing family-head compare-and-swap, exact idempotency, audit coverage,
   repeatable reads, and readiness verification authenticate the complete
   lifecycle. Reconstruction does not rerun or retain the source transcript.
   No new SQL table or migration is necessary for this bounded payload
   evolution.
7. Extend only read-only API and browser inspection. A completed event may show
   the receipt kind, exact digests, and bounded counts. Before reveal, the
   final-test segment and replay digests remain redacted behind the opaque
   commitment; after reveal, unused exploratory budget is locked rather than
   advertised as available. Inspection does not return the underlying feature
   or target transcript, held-out observations, positions, returns, or a
   promotion decision.
8. Do not connect this receipt to the Phase 2 fixture backtest worker. That
   worker still consumes one fixed complete tape and is not a segment-aware
   evaluator. Phase 3D adds no experiment mutation endpoint, scheduler,
   parameter sweep, subprocess quota, renewable claim, P&L or benchmark
   calculation, criteria adjudication, captured/live tape, shadow runtime,
   deployment, broker access, or paper/live authority.

## Consequences

Experiment configurations can now vary the bounded reference policy without
changing or pre-reading their segment input evidence. The final holdout commits
to input data and feature evidence before selection, while its one allowed
post-reveal attempt produces target evidence only for the selected
configuration. A completed status is no longer a domain-fixture placeholder:
it identifies an exact parity-certified target evaluation and recorded
actor-identifier continuity.

This is still not a segment-aware backtest or performance result. It neither
persists the complete source/feature/target transcript as a separately
queryable artifact nor calculates the promotion criteria declared by the
family. Durable worker scheduling and resource isolation, chronological or
nested walk-forward execution, cost and benchmark stress, uncertainty,
captured-tape parity, reconnect behavior, shadow mode, and broader reporting
remain later Phase 3 work. Phase 3 and its exit gate remain open.
