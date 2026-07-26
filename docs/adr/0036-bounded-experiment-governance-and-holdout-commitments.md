# ADR 0036: bounded experiment governance and holdout commitments

- Status: Accepted; decision 4 superseded by ADR 0037
- Date: 2026-07-23

ADR 0037 replaces decision 4's non-executable completion evidence with an exact
configuration-bound reference evaluation receipt. The family, budget,
lifecycle, tape-role, reveal, persistence, and read-only inspection decisions
remain in force.

## Context

ADRs 0034 and 0035 establish exact feature and target parity for one bounded
manifest tape, but that complete-tape evidence is not a holdout boundary. A
registry that exposes the same authenticated transcript to exploration and
final-test consumers would disclose the holdout before an audit record could
claim otherwise.

The existing experiment-family contracts declare chronological segments,
frozen promotion criteria, and trial outcomes, but they do not yet distinguish
a stable research attempt from its lifecycle revisions. They also accept a
completed-run digest without proof of the underlying result, allow any
previously attempted configuration to be selected for final-test access, and
represent authorization as an unscoped digest. Persisting those shapes would
turn caller assertions into durable evidence rather than closing the
governance boundary.

This slice must make experiment history and holdout access reconstructable
without also inventing a segment-aware backtest runner, claiming filesystem
secrecy, or granting promotion or trading authority.

## Decision

1. Define Phase 3C as a bounded experiment-governance registry under a separate
   `EXPERIMENT_GOVERNANCE_CONTRACT_VERSION`. Its
   `ExperimentGovernanceSnapshot` domain contract remains pure and
   deterministic. A SQL adapter durably stores its canonical facts, and
   query-only API and browser surfaces may inspect the reconstructed registry.
2. Bind each family to explicit, non-overlapping train, validation, and final-
   test segment declarations. Train and validation use exact
   `ExperimentSegmentEvidence`. Before reveal, the final test is represented
   only by an opaque, content-addressed `TestSegmentCommitment`; neither a
   final-test transcript nor a complete-tape feature/target certificate is
   admissible as pre-reveal evidence. A global tape-role ledger permits a
   source tape to be shared by exploratory train or validation claims, but a
   tape claimed as a holdout cannot be reused by another family or later
   reclassified as exploratory, and an exploratory tape cannot later become a
   holdout.
3. Give every `ExperimentAttempt` one stable identity and record its queued,
   running, completed, failed, canceled, or abandoned lifecycle as an
   append-only ordered `ExperimentAttemptEvent` chain. The pre-holdout budget
   counts stable attempts, not lifecycle revisions. Failed, canceled, and
   abandoned attempts remain part of the family history.
4. Accept completed status in this slice only with proof-constructed,
   explicitly non-executable domain-fixture evidence. A digest-shaped run claim
   is not completion evidence, and Phase 3C does not claim to have executed an
   evaluation segment. `StrategyConfigurationValidationReceipt` proves that
   the declared configuration conforms to the exact registered strategy schema.
5. Permit final-holdout selection only for a configuration supported by an
   exact completed validation attempt. Training-only, queued, running, failed,
   canceled, or abandoned attempts cannot nominate a final-test configuration.
6. Represent reveal permission as a `HoldoutRevealAuthorization` bound to the
   family, opaque final-test commitment, frozen criteria, selected
   configuration, exact pre-reveal registry head, actor, reason, and time.
   `AuditedHoldoutReveal` is the first object allowed to retain the exact
   certificate-derived test-evidence receipt. Reveal requires all prior
   attempts to be terminal and serializes against concurrent attempt creation.
   After reveal, exploratory attempts are forbidden and at most one stable
   final-test attempt may use the selected configuration; lifecycle events for
   that attempt do not create additional tests.
7. Persist immutable tape policies, family tape claims, families, attempts,
   attempt events, holdout reveals, and audit facts in
   `phase3_experiment_tape_policies`, `phase3_experiment_tape_claims`,
   `phase3_experiment_families`, `phase3_experiment_attempts`,
   `phase3_experiment_attempt_events`, `phase3_holdout_reveals`, and
   `phase3_experiment_audit_events`. SQL heads or projections are conveniences
   only. Reads reconstruct and authenticate the complete canonical history,
   and registration, append, and reveal commands use transactional
   compare-and-swap semantics. Exact retries are idempotent; changed reuse of
   an identity conflicts.
8. Expose only read-only experiment inspection in this slice. Queries show
   hypotheses, segment declarations, frozen criteria, attempt budgets,
   lifecycle history, and sealed or revealed holdout state while withholding
   pre-reveal final-test evidence. No experiment mutation endpoint is added.
9. Do not connect this registry to the Phase 2 fixture worker or backtest jobs.
   That runner consumes one fixed complete tape and does not bind an evaluation
   segment, so labeling its output as train, validation, or final test would be
   false evidence.

## Consequences

Experiment attempts and holdout access now have an immutable, concurrency-safe
governance record. Unsuccessful attempts cannot disappear from the declared
trial budget, lifecycle updates cannot masquerade as new trials, and a reveal
cannot silently select an unconfirmed or non-validation configuration. A
pre-reveal reader sees only the final-test commitment. Global tape-role claims
also prevent a holdout source from being recycled as exploratory evidence, or
an exploratory source from later being promoted to holdout.

This decision does not execute a parameter sweep or evaluation segment, isolate
holdout bytes from a repository owner or database administrator, persist the
complete Phase 3A/3B feature transcript as segment evidence, or integrate with
the Phase 2 job and worker lifecycle. Chronological and nested walk-forward
execution, process/resource isolation, mutation APIs, captured or licensed
tapes, reconnect handling, shadow mode, broader reporting, and automated
criteria adjudication remain later Phase 3 work.

A holdout reveal is an audited research action, not a promotion. It cannot
create a deployment, authorize paper or live execution, arm a runtime, or grant
broker access. Phase 3 remains incomplete and its exit gate stays open.
