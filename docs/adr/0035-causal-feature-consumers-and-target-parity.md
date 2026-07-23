# ADR 0035: causal feature consumers and target parity

- Status: Accepted
- Date: 2026-07-22

## Context

ADR 0034 establishes manifest-bound feature artifacts, causal snapshots, and
exact batch/incremental feature parity for one bounded reference feature. It
records each snapshot's `available_at`, but deliberately does not connect that
evidence to a decision consumer or prove that the two computation paths emit
the same targets. A consumer that selects by observation time, carries a value
across a gap, or accepts a loose snapshot outside the certified transcript can
still introduce look-ahead or lineage ambiguity.

The next slice must close that local causal boundary before experiment runners,
captured tapes, or shadow workflows can treat feature-derived targets as
research evidence. It must remain small enough to test the temporal and parity
contracts without introducing persistence, a general strategy API, or trading
authority.

## Decision

1. Define Phase 3B as one bounded, pure feature-to-target parity slice. It
   accepts only an exact `CertifiedFeatureReplay`; loose artifacts, snapshots,
   result paths, and digest-shaped claims are not valid inputs.
2. Proof-construct a feature decision context for every complete market-batch
   trigger. The context exposes at most the latest snapshot per expected
   instrument from the current post-reset epoch and only when
   `snapshot.available_at <= trigger.as_of`. Equality is visible. A later
   availability time is rejected even when the snapshot's observation or source
   batch is earlier.
3. Treat incomplete batches as explicit `SKIPPED_RESET` consumer steps. They
   clear both already-visible and pending delayed snapshots for every expected
   instrument. A universe change also starts a new epoch. Complete batches that
   lack one visible snapshot per expected instrument produce an audited
   `WAITING` step and no target; values are neither imputed nor carried across a
   reset.
4. Use one versioned reference rule, `rolling-close-mean-cross@1.0.0`: target a
   declared positive whole-share quantity when the current batch close is
   strictly above the latest visible rolling-close mean, and target zero
   otherwise. Its runtime configuration digest binds the rule policy, feature
   artifact, and successful Phase 3A feature-parity receipt. The emitted
   `TargetPortfolio` remains bound to the exact market-batch trigger.
5. Wrap each target in immutable decision evidence that binds its exact visible
   feature snapshots and context. A feature value is signal evidence only; it
   cannot become an order or fill reference price. Existing target-to-intent
   conversion continues to use the causal market event from the decision-time
   portfolio snapshot.
6. Implement two independent visibility traversals. The batch path builds an
   immutable reset-epoch and availability index from the full sequence, then
   resolves each prefix without reducer state. The incremental path
   authenticates the exact next feature step and advances a monotonic pending
   cursor plus visible state. Both use the same pure target constructor only
   after independently selecting eligible feature evidence.
7. Proof-construct a target-parity receipt only when the complete batch and
   incremental step transcripts agree exactly, including reset and waiting
   steps, decision contexts, feature snapshot identities, targets, ordering,
   and counts. The receipt binds the source lineage, feature artifact and parity
   receipt, target runtime configuration, both result digests, and the ordered
   step, decision, and target identities.
8. Extend the repository-owned manifest-tape adapter so the same sealed tape
   and replay-run manifest can produce the combined feature and target proof.
   Keep all Phase 3B target computation and evidence in memory. It introduces no
   SQL schema, job lifecycle, API or browser surface, provider capture, broker
   adapter, deployment, or promotion path.

## Consequences

The bounded reference path now enforces feature availability at a real target
decision boundary and proves that full-sequence-index and incremental consumers
produce the same exact target transcript. Delayed pre-gap values cannot reappear
after a reset, all no-target states remain explicit evidence, and downstream intent
construction retains market-event pricing rather than substituting the feature
value.

This decision does not complete Phase 3. The exercised manifest tape is a
repository-owned synthetic fixture, not a captured licensed or live tape.
Durable feature evidence, general and fitted features, research job/API/browser
integration, experiment and holdout governance, process/resource isolation,
captured live data, reconnect freshness, shadow replay, full trade lineage, and
research reporting conventions remain separate open work. No receipt or target
produced here grants paper or live trading authority.
