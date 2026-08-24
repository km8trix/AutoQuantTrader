# ADR 0114: fail-closed captured-tape research validity

- Status: Accepted for the bounded pure Phase 3E validity contract; v1 has no
  positive path without a separately reviewed external provenance verifier
- Date: 2026-08-24
- Extends:
  [ADR 0009](0009-fail-closed-market-data-admission.md),
  [ADR 0021](0021-manifest-replay-tapes-and-sealed-run-evidence.md),
  [ADR 0034](0034-versioned-feature-artifacts-and-differential-parity.md),
  [ADR 0035](0035-causal-feature-consumers-and-target-parity.md),
  [ADR 0036](0036-bounded-experiment-governance-and-holdout-commitments.md),
  and
  [ADR 0037](0037-configuration-bound-governed-segment-evaluation.md)

## Context

The current replay and experiment paths are intentionally fixture-only.
`ManifestReplayTape`, `DatasetPin`, and `ExperimentDatasetReplayPin` accept
repository-owned synthetic or recorded fixtures and preserve that
classification. Phase 3A through 3D bind deterministic replay, feature, target,
segment, and configuration evidence, but they do not prove that their tape was
captured from an admitted production source.

Phase 1 has two distinct gates that must remain distinct. The Wave 1A
production-evidence prerequisite inventories externally supplied identity,
calendar, corporate-action, raw-price/provenance, license, entitlement, and
review references. Its strongest result is only
`ready_for_admission_evaluation`; it creates neither a source nor an admission.
The generic source-admission evaluator can separately produce `admitted`, but a
caller can construct an `AdmissionReport` shape without rerunning its inputs.
Neither result alone proves immutable captured bytes, an exact replay, a frozen
research configuration, or review of the combined evidence.

The next safe repository-local slice must make those missing conjunctions
explicit without provider access, invented bytes, persistence, source
construction, experiment mutation, or trading authority. Existing synthetic
fixtures and the verified Tiingo research baseline must remain ineligible for a
captured-tape classification.

## Decision

1. Add a separate side-effect-free Phase 3E application gate. Do not widen the
   fixture source-kind allowlists in replay, dataset-manifest, or experiment
   contracts, and do not reinterpret an existing fixture replay or
   vendor-specific research snapshot as captured-tape evidence.
2. Require the exact Wave 1A production specification, evidence bundle, review,
   executor, and caller-observed assessment. Recompute the assessment at its
   recorded time to detect a forged or substituted result, then recompute it at
   the gate's injected evaluation time. Both must be
   `ready_for_admission_evaluation` and must match the candidate's exact source,
   provider, dataset, feed, profile, and scope. Readiness remains only a
   prerequisite and never supplies source or admission authority.
3. Separately require an exact generic admission specification, evidence, and
   caller-observed report. Re-run `evaluate_admission`, require exact report
   equality and status `admitted`, and bind its report digest and source ID into
   the capture and research specification. A loose report, a ready Wave 1A
   assessment, or either object without the other fails closed. Because the
   current admission contract has no revocation horizon, this bounded gate
   treats the report, every required technical check, and its approval as
   independently current for a half-open maximum of 30 days. Refreshing only
   `evaluated_at` cannot conceal an old check or approval. A later contract may
   replace that rule with authenticated revocation/currentness evidence.
4. Represent captured input with a new immutable evidence contract. It binds an
   explicit origin class, decision, producer and executor, production
   prerequisite and admission digests, complete source/profile/scope identity,
   content-addressed capture and dataset-manifest identities, an ordered
   immutable-object-set digest, a source-tape digest, coverage, capture times,
   seal time, and a half-open validity horizon. The explicit `vendor_captured`,
   verified, `content_addressed_immutable` combination is necessary but is only
   a caller-asserted shape and cannot authenticate origin. Synthetic,
   recorded-fixture, generic-research, contract-only, rejected, mutable, stale,
   future, or mismatched evidence is blocked, and copying fixture digests into
   a vendor-labeled object cannot upgrade it.
5. Require separate replay evidence bound to that exact capture. It freezes the
   content-addressed replay manifest/run, replay tape, input, plan, runtime, and
   research-configuration digests plus coverage, executor, start/completion
   times, and validity. Capture sealing must strictly precede
   specification/configuration freeze; freeze must strictly precede replay;
   replay completion must strictly precede review and may not follow evaluation.
   Equal timestamps do not establish causal order. Substitution of any tape,
   runtime, plan, or configuration fails closed.
6. Freeze one research specification and independent review context around the
   complete source/capture/replay/configuration tuple. The review binds the
   specification, capture, and replay semantic digests and must be externally
   classified, approved, current, causal, and performed by someone other than
   the gate executor, production-evidence producers, reviewer, or executor,
   admission approver or executor, capture producer/executor, or replay
   producer/executor. A review
   copied to another source, tape, configuration, specification, or context is
   classified as replayed or substituted and fails closed. This pure gate does
   not claim global one-shot consumption of an identical review; that would
   require persistent state and a separately reviewed migration. Reviewer
   identity and class are caller assertions in v1; structural identifier
   separation is not external authentication.
7. Require a separately authenticated capture-origin capability before any
   positive classification can exist. V1 deliberately has no issuer, trust
   root, key/signature verifier, or validation path for such a capability.
   Private Python names and unkeyed hashes are not authentication. Missing input
   therefore produces `authenticated_capture_provenance_missing`; any
   caller-supplied or `object.__new__` substitute produces
   `authenticated_capture_provenance_invalid`. A future positive path requires
   a new independently reviewed contract that authenticates the issuer and
   trust root, binds the exact capture, admission, configuration, and validity
   horizon, and includes the issuer in reviewer-independence checks.
8. Integrity-check the sealed `CapturedTapeResearchValidityAssessment` at every
   consumption property and require exactly one authenticated-provenance blocker
   in every v1 assessment. Consequently v1 cannot emit
   `eligible_as_captured_tape_research_evidence`, even if a caller recomputes the
   unkeyed assessment digest. The assessment has no `load()` or conversion
   surface and keeps historical-source, admission, canonical-market-data,
   promotion, deployment, and trading effects and authorizations permanently
   `none` or false.
9. Keep the slice in memory. Add no provider call, capture operation, credential,
   source adapter, ingestion path, database table, API, worker, experiment
   mutation, promotion path, deployment hook, broker call, or migration.

## Consequences

Repository code can now state and audit the exact structural conjunction that a
future externally authenticated captured-tape verifier must consume. Missing
layers and cross-layer substitutions produce stable, canonical blockers, every
v1 result stays blocked on authenticated provenance, and existing fixture
workflows remain compatible and permanently fixture-only.

No repository-local or external-shaped artifact can produce the positive
status. The repository still lacks an authenticated licensed source, a real
source-admission report derived from the Wave 1A external prerequisites, a
production-bound content-addressed captured dataset/tape and replay, an
externally anchored origin verifier, and an authenticated independent review of
that exact bundle. The existing Tiingo capture remains a research baseline
only. Adding a verifier or positive classification requires a separately
reviewed contract; persisting eligibility or connecting it to Phase 3 segment
evidence requires separate review, and persistence would require a centrally
reserved migration ID.
