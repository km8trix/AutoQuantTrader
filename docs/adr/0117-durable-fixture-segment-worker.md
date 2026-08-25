# ADR 0117: durable bounded fixture-segment worker

- Status: Accepted
- Date: 2026-08-25
- Supersedes: ADR 0037 decision 5 for the bounded repository-fixture path only

## Context

ADRs 0034 and 0035 proof-construct exact feature and target parity for a
repository-owned synthetic replay. ADRs 0036 and 0037 durably govern stable
attempts and require an exact configuration-bound target certification before a
recorded running actor may complete one. The two sides are intentionally not
connected: feature and target transcripts remain in memory, callers manually
construct lifecycle transitions, and ADR 0037 treats a crashed actor as an
abandoned attempt.

A general segment runner, arbitrary code executor, parameter sweep, economic
backtest, or captured-tape worker would cross several still-open Phase 3 gates.
The next slice instead needs one repository-owned fixture worker that can
recover a physical process crash without allowing a stale process to publish,
substituting a configuration or segment, exposing an unrevealed holdout, or
creating a completed governance fact separately from its transcript evidence.

## Decision

1. Define Phase 3F as a bounded durable worker for the existing
   `rolling-close-mean-cross@1.0.0` repository fixture path. A job can be
   enqueued only for an exact queued Phase 3C attempt and the exact Phase 3A
   certification already bound by that attempt's opened `ExperimentSegmentEvidence`.
   A final-test job is impossible before the audited Phase 3C reveal and must
   bind that reveal's exact opened evidence. Complete-tape or foreign-segment
   substitution is rejected before any job fact is written.
2. Give each governed attempt at most one deterministic fixture-job identity.
   The immutable job binds family, attempt, configuration and schema-validation
   receipts, segment, source evidence, queued governance event, certified
   feature evidence, feature transcript artifact, requester, and request time.
   Exact retry returns the existing job at any later lifecycle state; changed
   reuse of the attempt identity conflicts.
3. Separate one stable logical governed actor from physical worker processes.
   The logical actor is derived from the job and remains the actor on the Phase
   3D `RUNNING`, completion receipt, and terminal governance event. Physical
   workers receive bounded rotating claim tokens that bind job, worker,
   physical attempt number, and the latest authenticated job event. A current
   process may strictly extend its expiry. After expiry, a physical replacement
   increments the physical attempt and rotates the token, while every earlier
   token remains unable to renew, fail, or complete. This supersedes ADR 0037's
   abandon-and-new-stable-attempt rule only for this closed fixture worker; the
   stable research attempt and frozen trial budget do not change.
4. Retain immutable content-addressed feature and target transcript artifacts.
   Each artifact binds family, attempt, segment, source evidence, certification,
   parity receipt, ordered step identities, ordered output identities, exact
   transcript digest, and canonical payload digest. Feature artifacts are
   configuration-neutral and persist atomically with enqueue. Target artifacts
   additionally bind the attempt configuration and can exist only from an exact
   target policy certification for that configuration.
5. Record fixture scheduling as an append-only queued/running/completed/failed
   event chain. The SQL head is only a compare-and-swap lock projection and is
   rechecked against the full chain. PostgreSQL claims use row locking with
   skip-locked selection; SQLite uses its serialized immediate write
   transaction. Existing enqueue retries resolve family/attempt first, lock and
   reload the job head, then lock governance in lifecycle-command order and
   compare the immutable original queued evidence. Reads authenticate jobs,
   artifacts, events, heads, and their exact governance event linkage and fail
   closed on corruption, gaps, substitution, orphan artifacts, or divergent
   terminal status.
6. Publish success atomically. One SQL transaction inserts the target artifact,
   re-proves and stores the existing `GovernedSegmentEvaluationReceipt`, appends
   the completed fixture event, and advances the job head. A crash at any point
   rolls back all four effects. Exact terminal retry is idempotent; changed
   certification, time, token, configuration, segment, artifact, or receipt
   conflicts. No partial-success job or governance completion is admissible.
7. Classify failure with one closed reason code and its fixed digest over only
   the worker contract and classification. Exception type, raw exception text,
   and arguments are never persisted. Failure atomically appends the existing typed
   non-executable governance evidence and the fixture terminal event. A process
   death is not caught as an evaluation failure; the job remains running until
   its physical claim expires and can be safely recovered.
8. Persist the new facts in
   `phase3_fixture_segment_transcript_artifacts`,
   `phase3_fixture_segment_jobs`,
   `phase3_fixture_segment_job_events`, and
   `phase3_fixture_segment_job_heads` through additive migration 0037. Refuse
   downgrade when any new history exists. Do not mutate an earlier migration or
   reinterpret existing Phase 3C/D evidence.
9. Add no mutation API, browser surface, arbitrary fixture loader, provider I/O,
   captured-tape positive eligibility, filesystem secrecy claim, subprocess or
   resource quota, P&L, benchmark, cost model, promotion criterion evaluation,
   deployment, broker operation, source/admission authority, or paper/live
   trading authority.

## Consequences

The reference feature/target evidence can now reach a governed completion
through a restart-safe repository worker. Exact physical claims and atomic
publication prevent an expired process or crash boundary from manufacturing a
terminal receipt, while the stable logical actor preserves Phase 3D actor
continuity without consuming a second stable research attempt.

This does not make Phase 3 complete. The retained transcript artifacts are
bounded identity transcripts for repository fixtures, not economic reports or
captured-live validity. General process isolation and quotas, chronological or
nested walk-forward scheduling, performance and uncertainty analysis,
authenticated captured-tape provenance, reconnect behavior, shadow replay,
research mutation APIs, comparison UI, and promotion adjudication remain open.
