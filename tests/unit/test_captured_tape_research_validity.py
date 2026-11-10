from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta, timezone
from itertools import permutations
from typing import Any, cast

import pytest

import packages.application.captured_tape_research_validity as validity_contract
from packages.application.captured_tape_research_validity import (
    SOURCE_ADMISSION_MAX_AGE,
    AdmittedHistoricalSourceEvidence,
    AuthenticatedCapturedTapeProvenance,
    CapturedDatasetTapeEvidence,
    CapturedTapeAuthorityEffect,
    CapturedTapeEvidenceClass,
    CapturedTapeEvidenceDecision,
    CapturedTapeReplayEvidence,
    CapturedTapeResearchBlocker,
    CapturedTapeResearchSpecification,
    CapturedTapeResearchValidityAssessment,
    CapturedTapeResearchValidityConflict,
    CapturedTapeResearchValidityStatus,
    CapturedTapeRetentionKind,
    CapturedTapeReviewClass,
    CapturedTapeReviewDecision,
    IndependentCapturedTapeResearchReview,
    ProductionEvidencePrerequisite,
    assess_captured_tape_research_validity,
    captured_tape_review_subject_sha256,
)
from packages.application.production_market_data_admission import (
    REQUIRED_PRODUCTION_EVIDENCE_ROLES,
    IndependentProductionEvidenceReview,
    ProductionEvidenceAttestation,
    ProductionEvidenceBundle,
    ProductionEvidenceClass,
    ProductionEvidenceDecision,
    ProductionEvidenceRole,
    ProductionHistoricalSourceEvidenceSpecification,
    ProductionReviewDecision,
    assess_production_market_data_evidence,
)
from packages.market_data import (
    AdmissionEvidence,
    AdmissionSpecification,
    ApprovalDecision,
    EntitlementStatus,
    IndependentApproval,
    SourceKind,
    TechnicalCheckEvidence,
    evaluate_admission,
)

PRODUCTION_FROZEN_AT = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)
PRODUCTION_OBSERVED_AT = datetime(2026, 8, 20, 13, 0, tzinfo=UTC)
PRODUCTION_REVIEWED_AT = datetime(2026, 8, 20, 14, 0, tzinfo=UTC)
PRODUCTION_ASSESSED_AT = datetime(2026, 8, 20, 15, 0, tzinfo=UTC)
ADMISSION_EVALUATED_AT = datetime(2026, 8, 20, 16, 0, tzinfo=UTC)
COVERAGE_START = datetime(2026, 8, 1, 13, 30, tzinfo=UTC)
COVERAGE_END = datetime(2026, 8, 20, 20, 0, tzinfo=UTC)
CAPTURE_STARTED_AT = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
CAPTURE_COMPLETED_AT = datetime(2026, 8, 21, 12, 5, tzinfo=UTC)
CAPTURE_SEALED_AT = datetime(2026, 8, 21, 12, 6, tzinfo=UTC)
SPECIFICATION_FROZEN_AT = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
REPLAY_STARTED_AT = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)
REPLAY_COMPLETED_AT = datetime(2026, 8, 23, 12, 1, tzinfo=UTC)
RESEARCH_REVIEWED_AT = datetime(2026, 8, 23, 13, 0, tzinfo=UTC)
EVALUATED_AT = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
VALID_THROUGH = datetime(2026, 10, 31, 0, 0, tzinfo=UTC)
GATE_EXECUTOR_ID = "captured-tape-gate-executor"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def production_specification() -> ProductionHistoricalSourceEvidenceSpecification:
    return ProductionHistoricalSourceEvidenceSpecification(
        specification_id="licensed-eod-production-prerequisite-v1",
        source_id="licensed-eod-source-v1",
        provider="licensed-provider",
        dataset="end-of-day-prices",
        feed="licensed-eod",
        profile_sha256=_digest("production-profile"),
        scope_sha256=_digest("production-scope"),
        frozen_at=PRODUCTION_FROZEN_AT,
    )


def production_attestation(
    role: ProductionEvidenceRole,
    *,
    evidence_class: ProductionEvidenceClass = ProductionEvidenceClass.EXTERNAL_AUTHORITY,
) -> ProductionEvidenceAttestation:
    specification = production_specification()
    return ProductionEvidenceAttestation(
        role=role,
        evidence_class=evidence_class,
        decision=ProductionEvidenceDecision.VERIFIED,
        evidence_id=f"production-{role.value}-v1",
        producer_id=f"producer-{role.value}",
        source_id=specification.source_id,
        provider=specification.provider,
        dataset=specification.dataset,
        feed=specification.feed,
        profile_sha256=specification.profile_sha256,
        scope_sha256=specification.scope_sha256,
        artifact_sha256=_digest(f"production-artifact-{role.value}"),
        observed_at=PRODUCTION_OBSERVED_AT,
        valid_through=VALID_THROUGH,
    )


def production_bundle(
    *,
    evidence_class: ProductionEvidenceClass = ProductionEvidenceClass.EXTERNAL_AUTHORITY,
) -> ProductionEvidenceBundle:
    return ProductionEvidenceBundle(
        tuple(
            production_attestation(role, evidence_class=evidence_class)
            for role in REQUIRED_PRODUCTION_EVIDENCE_ROLES
        )
    )


def production_review(
    bundle: ProductionEvidenceBundle,
) -> IndependentProductionEvidenceReview:
    specification = production_specification()
    return IndependentProductionEvidenceReview(
        review_id="production-prerequisite-review-v1",
        reviewer_id="production-independent-reviewer",
        evidence_class=ProductionEvidenceClass.EXTERNAL_AUTHORITY,
        decision=ProductionReviewDecision.APPROVED,
        source_id=specification.source_id,
        provider=specification.provider,
        dataset=specification.dataset,
        feed=specification.feed,
        profile_sha256=specification.profile_sha256,
        scope_sha256=specification.scope_sha256,
        evidence_bundle_sha256=bundle.semantic_sha256,
        reviewed_at=PRODUCTION_REVIEWED_AT,
        valid_through=VALID_THROUGH,
    )


def production_prerequisite(
    *,
    bundle: ProductionEvidenceBundle | None = None,
) -> ProductionEvidencePrerequisite:
    evidence = production_bundle() if bundle is None else bundle
    review = production_review(evidence)
    assessment = assess_production_market_data_evidence(
        specification=production_specification(),
        evidence=evidence,
        review=review,
        executor_id="production-prerequisite-executor",
        evaluated_at=PRODUCTION_ASSESSED_AT,
    )
    return ProductionEvidencePrerequisite(
        specification=production_specification(),
        evidence=evidence,
        review=review,
        assessment=assessment,
        executor_id="production-prerequisite-executor",
    )


def admission_specification() -> AdmissionSpecification:
    return AdmissionSpecification(
        specification_id="licensed-eod-source-admission-v1",
        source_id=production_specification().source_id,
        identifier_authority="identifier-authority-v1",
        universe_version="etf-universe-v1",
        calendar_version="calendar-v1",
        corporate_action_version="actions-v1",
        required_checks=("immutable_capture", "point_in_time"),
        frozen_at=PRODUCTION_FROZEN_AT,
    )


def admission_evidence(
    *,
    source_kind: SourceKind = SourceKind.VENDOR,
) -> AdmissionEvidence:
    specification = admission_specification()
    return AdmissionEvidence(
        source_id=specification.source_id,
        source_kind=source_kind,
        licensed=True,
        entitlement_status=EntitlementStatus.ACTIVE,
        terms_digest=_digest("licensed-terms"),
        identifier_authority=specification.identifier_authority,
        universe_version=specification.universe_version,
        calendar_version=specification.calendar_version,
        corporate_action_version=specification.corporate_action_version,
        technical_checks=tuple(
            TechnicalCheckEvidence(
                check_id=check_id,
                passed=True,
                evidence_digest=_digest(f"admission-check-{check_id}"),
                checked_at=PRODUCTION_OBSERVED_AT,
            )
            for check_id in specification.required_checks
        ),
        executor_id="source-admission-executor",
        evaluated_at=ADMISSION_EVALUATED_AT,
        approval=IndependentApproval(
            reviewer_id="source-admission-reviewer",
            decision=ApprovalDecision.APPROVED,
            reviewed_at=PRODUCTION_REVIEWED_AT,
        ),
    )


def source_admission(
    *,
    source_kind: SourceKind = SourceKind.VENDOR,
) -> AdmittedHistoricalSourceEvidence:
    evidence = admission_evidence(source_kind=source_kind)
    specification = admission_specification()
    return AdmittedHistoricalSourceEvidence(
        specification=specification,
        evidence=evidence,
        report=evaluate_admission(specification, evidence),
    )


def capture_evidence(
    prerequisite: ProductionEvidencePrerequisite,
    admission: AdmittedHistoricalSourceEvidence,
    *,
    evidence_class: CapturedTapeEvidenceClass = CapturedTapeEvidenceClass.VENDOR_CAPTURED,
    retention_kind: CapturedTapeRetentionKind = (
        CapturedTapeRetentionKind.CONTENT_ADDRESSED_IMMUTABLE
    ),
) -> CapturedDatasetTapeEvidence:
    specification = production_specification()
    capture_manifest_sha256 = _digest("capture-manifest")
    dataset_manifest_sha256 = _digest("dataset-manifest")
    return CapturedDatasetTapeEvidence(
        evidence_id="captured-dataset-tape-evidence-v1",
        evidence_class=evidence_class,
        decision=CapturedTapeEvidenceDecision.VERIFIED,
        retention_kind=retention_kind,
        producer_id="capture-evidence-producer",
        capture_executor_id="capture-executor",
        source_id=specification.source_id,
        provider=specification.provider,
        dataset=specification.dataset,
        feed=specification.feed,
        profile_sha256=specification.profile_sha256,
        scope_sha256=specification.scope_sha256,
        production_specification_sha256=specification.semantic_sha256,
        production_assessment_sha256=prerequisite.assessment.semantic_sha256,
        source_admission_report_sha256=admission.report.report_digest,
        capture_id=capture_manifest_sha256,
        capture_manifest_sha256=capture_manifest_sha256,
        dataset_manifest_id=dataset_manifest_sha256,
        dataset_manifest_sha256=dataset_manifest_sha256,
        immutable_object_set_sha256=_digest("ordered-immutable-object-set"),
        source_tape_sha256=_digest("source-tape"),
        coverage_start=COVERAGE_START,
        coverage_end=COVERAGE_END,
        capture_started_at=CAPTURE_STARTED_AT,
        capture_completed_at=CAPTURE_COMPLETED_AT,
        sealed_at=CAPTURE_SEALED_AT,
        valid_through=VALID_THROUGH,
    )


def replay_evidence(
    capture: CapturedDatasetTapeEvidence,
    *,
    research_configuration_sha256: str | None = None,
    replay_started_at: datetime = REPLAY_STARTED_AT,
    replay_completed_at: datetime = REPLAY_COMPLETED_AT,
) -> CapturedTapeReplayEvidence:
    replay_manifest_sha256 = _digest("captured-replay-manifest")
    return CapturedTapeReplayEvidence(
        evidence_id="captured-tape-replay-evidence-v1",
        decision=CapturedTapeEvidenceDecision.VERIFIED,
        producer_id="replay-evidence-producer",
        replay_executor_id="replay-executor",
        capture_evidence_sha256=capture.semantic_sha256,
        dataset_manifest_sha256=capture.dataset_manifest_sha256,
        source_tape_sha256=capture.source_tape_sha256,
        replay_run_id=replay_manifest_sha256,
        replay_manifest_sha256=replay_manifest_sha256,
        replay_tape_sha256=_digest("canonical-replay-tape"),
        replay_input_sha256=_digest("captured-replay-input"),
        replay_plan_sha256=_digest("captured-replay-plan"),
        replay_runtime_sha256=_digest("captured-replay-runtime"),
        research_configuration_sha256=(
            _digest("research-configuration")
            if research_configuration_sha256 is None
            else research_configuration_sha256
        ),
        coverage_start=capture.coverage_start,
        coverage_end=capture.coverage_end,
        replay_started_at=replay_started_at,
        replay_completed_at=replay_completed_at,
        valid_through=VALID_THROUGH,
    )


def research_specification(
    prerequisite: ProductionEvidencePrerequisite,
    admission: AdmittedHistoricalSourceEvidence,
    capture: CapturedDatasetTapeEvidence,
    replay: CapturedTapeReplayEvidence,
    *,
    review_context_id: str = "captured-tape-review-context-v1",
) -> CapturedTapeResearchSpecification:
    production = production_specification()
    return CapturedTapeResearchSpecification(
        specification_id="captured-tape-research-validity-v1",
        research_evidence_id="captured-tape-research-evidence-v1",
        review_context_id=review_context_id,
        source_id=production.source_id,
        provider=production.provider,
        dataset=production.dataset,
        feed=production.feed,
        profile_sha256=production.profile_sha256,
        scope_sha256=production.scope_sha256,
        production_specification_sha256=production.semantic_sha256,
        production_assessment_sha256=prerequisite.assessment.semantic_sha256,
        source_admission_report_sha256=admission.report.report_digest,
        capture_evidence_sha256=capture.semantic_sha256,
        capture_manifest_sha256=capture.capture_manifest_sha256,
        dataset_manifest_sha256=capture.dataset_manifest_sha256,
        source_tape_sha256=capture.source_tape_sha256,
        replay_evidence_sha256=replay.semantic_sha256,
        replay_manifest_sha256=replay.replay_manifest_sha256,
        replay_tape_sha256=replay.replay_tape_sha256,
        replay_input_sha256=replay.replay_input_sha256,
        replay_plan_sha256=replay.replay_plan_sha256,
        replay_runtime_sha256=replay.replay_runtime_sha256,
        research_configuration_sha256=replay.research_configuration_sha256,
        coverage_start=capture.coverage_start,
        coverage_end=capture.coverage_end,
        frozen_at=SPECIFICATION_FROZEN_AT,
        valid_through=VALID_THROUGH,
    )


def independent_review(
    specification: CapturedTapeResearchSpecification,
    capture: CapturedDatasetTapeEvidence,
    replay: CapturedTapeReplayEvidence,
    *,
    reviewer_id: str = "captured-tape-independent-reviewer",
    review_class: CapturedTapeReviewClass = CapturedTapeReviewClass.EXTERNAL_INDEPENDENT,
    decision: CapturedTapeReviewDecision = CapturedTapeReviewDecision.APPROVED,
    reviewed_at: datetime = RESEARCH_REVIEWED_AT,
    valid_through: datetime = VALID_THROUGH,
) -> IndependentCapturedTapeResearchReview:
    return IndependentCapturedTapeResearchReview(
        review_id="captured-tape-independent-review-v1",
        reviewer_id=reviewer_id,
        review_class=review_class,
        decision=decision,
        research_evidence_id=specification.research_evidence_id,
        review_context_id=specification.review_context_id,
        specification_sha256=specification.semantic_sha256,
        review_subject_sha256=captured_tape_review_subject_sha256(
            specification,
            capture,
            replay,
        ),
        reviewed_at=reviewed_at,
        valid_through=valid_through,
    )


def external_shaped_inputs() -> tuple[
    ProductionEvidencePrerequisite,
    AdmittedHistoricalSourceEvidence,
    CapturedDatasetTapeEvidence,
    CapturedTapeReplayEvidence,
    CapturedTapeResearchSpecification,
    IndependentCapturedTapeResearchReview,
]:
    prerequisite = production_prerequisite()
    admission = source_admission()
    capture = capture_evidence(prerequisite, admission)
    replay = replay_evidence(capture)
    specification = research_specification(
        prerequisite,
        admission,
        capture,
        replay,
    )
    review = independent_review(specification, capture, replay)
    return prerequisite, admission, capture, replay, specification, review


def assess_external_shaped_inputs(
    *,
    evaluated_at: datetime = EVALUATED_AT,
) -> CapturedTapeResearchValidityAssessment:
    prerequisite, admission, capture, replay, specification, review = external_shaped_inputs()
    return assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=evaluated_at,
    )


def test_complete_external_shaped_bundle_requires_authenticated_provenance() -> None:
    assessment = assess_external_shaped_inputs()

    assert assessment.status is CapturedTapeResearchValidityStatus.BLOCKED
    assert not assessment.counts_as_captured_tape_research_evidence
    assert assessment.blockers == (
        CapturedTapeResearchBlocker.AUTHENTICATED_CAPTURE_PROVENANCE_MISSING,
    )
    assert assessment.assessment_id.startswith("captured-tape-validity-")
    assert len(assessment.semantic_sha256) == 64
    assert assessment.historical_source_effect is CapturedTapeAuthorityEffect.NONE
    assert assessment.admission_effect is CapturedTapeAuthorityEffect.NONE
    assert assessment.canonical_market_data_effect is CapturedTapeAuthorityEffect.NONE
    assert assessment.promotion_effect is CapturedTapeAuthorityEffect.NONE
    assert assessment.deployment_effect is CapturedTapeAuthorityEffect.NONE
    assert assessment.trading_effect is CapturedTapeAuthorityEffect.NONE
    assert not assessment.historical_source_authorized
    assert not assessment.admission_authorized
    assert not assessment.canonical_market_data_authorized
    assert not assessment.promotion_authorized
    assert not assessment.deployment_authorized
    assert not assessment.trading_authorized
    assert not hasattr(assessment, "load")


def test_authenticated_provenance_cannot_be_minted_by_repository_callers() -> None:
    with pytest.raises(TypeError, match="future reviewed issuer"):
        AuthenticatedCapturedTapeProvenance()


def test_object_new_cannot_forge_authenticated_provenance() -> None:
    prerequisite, admission, capture, replay, specification, review = external_shaped_inputs()
    forged = object.__new__(AuthenticatedCapturedTapeProvenance)

    assessment = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
        authenticated_provenance=forged,
    )

    assert assessment.blockers == (
        CapturedTapeResearchBlocker.AUTHENTICATED_CAPTURE_PROVENANCE_INVALID,
    )
    assert assessment.status is CapturedTapeResearchValidityStatus.BLOCKED
    assert not assessment.counts_as_captured_tape_research_evidence


@pytest.mark.parametrize(
    ("missing_field", "expected_blocker"),
    (
        (
            "production_prerequisite",
            CapturedTapeResearchBlocker.PRODUCTION_PREREQUISITE_MISSING,
        ),
        ("source_admission", CapturedTapeResearchBlocker.SOURCE_ADMISSION_MISSING),
        ("capture", CapturedTapeResearchBlocker.CAPTURE_EVIDENCE_MISSING),
        ("replay", CapturedTapeResearchBlocker.REPLAY_EVIDENCE_MISSING),
        ("review", CapturedTapeResearchBlocker.INDEPENDENT_REVIEW_MISSING),
    ),
)
def test_each_missing_evidence_layer_fails_closed(
    missing_field: str,
    expected_blocker: CapturedTapeResearchBlocker,
) -> None:
    prerequisite, admission, capture, replay, specification, review = external_shaped_inputs()
    assessment = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=(
            None if missing_field == "production_prerequisite" else prerequisite
        ),
        source_admission=None if missing_field == "source_admission" else admission,
        capture=None if missing_field == "capture" else capture,
        replay=None if missing_field == "replay" else replay,
        review=None if missing_field == "review" else review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )

    assert assessment.status is CapturedTapeResearchValidityStatus.BLOCKED
    assert not assessment.counts_as_captured_tape_research_evidence
    assert expected_blocker in assessment.blockers


@pytest.mark.parametrize(
    "evidence_class",
    (
        CapturedTapeEvidenceClass.SYNTHETIC_FIXTURE,
        CapturedTapeEvidenceClass.RECORDED_FIXTURE,
        CapturedTapeEvidenceClass.GENERIC_RESEARCH_CAPTURE,
        CapturedTapeEvidenceClass.CONTRACT_ONLY,
    ),
)
def test_synthetic_recorded_and_generic_research_captures_never_upgrade(
    evidence_class: CapturedTapeEvidenceClass,
) -> None:
    prerequisite = production_prerequisite()
    admission = source_admission()
    capture = capture_evidence(prerequisite, admission, evidence_class=evidence_class)
    replay = replay_evidence(capture)
    specification = research_specification(prerequisite, admission, capture, replay)
    review = independent_review(specification, capture, replay)

    assessment = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )

    assert assessment.blockers == (
        CapturedTapeResearchBlocker.AUTHENTICATED_CAPTURE_PROVENANCE_MISSING,
        CapturedTapeResearchBlocker.NON_VENDOR_CAPTURE_EVIDENCE,
    )
    assert not assessment.counts_as_captured_tape_research_evidence


def test_wave1_contract_only_prerequisite_remains_blocked() -> None:
    prerequisite = production_prerequisite(
        bundle=production_bundle(evidence_class=ProductionEvidenceClass.CONTRACT_ONLY)
    )
    admission = source_admission()
    capture = capture_evidence(prerequisite, admission)
    replay = replay_evidence(capture)
    specification = research_specification(prerequisite, admission, capture, replay)
    review = independent_review(specification, capture, replay)

    assessment = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )

    assert CapturedTapeResearchBlocker.PRODUCTION_PREREQUISITE_BLOCKED in (assessment.blockers)
    assert CapturedTapeResearchBlocker.PRODUCTION_PREREQUISITE_NOT_CURRENT in (assessment.blockers)


def test_forged_wave1_assessment_is_recomputed_and_fails_closed() -> None:
    prerequisite, admission, capture, replay, specification, review = external_shaped_inputs()
    object.__setattr__(
        prerequisite.assessment,
        "executor_sha256",
        _digest("forged-production-gate-executor"),
    )

    assessment = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )

    assert (
        CapturedTapeResearchBlocker.PRODUCTION_PREREQUISITE_ASSESSMENT_MISMATCH
        in assessment.blockers
    )
    assert assessment.status is CapturedTapeResearchValidityStatus.BLOCKED


@pytest.mark.parametrize(
    "source_kind",
    (SourceKind.SYNTHETIC_FIXTURE, SourceKind.RECORDED_FIXTURE),
)
def test_fixture_source_admission_remains_blocked(source_kind: SourceKind) -> None:
    prerequisite = production_prerequisite()
    admission = source_admission(source_kind=source_kind)
    capture = capture_evidence(prerequisite, admission)
    replay = replay_evidence(capture)
    specification = research_specification(prerequisite, admission, capture, replay)
    review = independent_review(specification, capture, replay)

    assessment = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )

    assert CapturedTapeResearchBlocker.SOURCE_NOT_ADMITTED in assessment.blockers


def test_caller_constructed_admission_report_is_recomputed_and_rejected() -> None:
    prerequisite = production_prerequisite()
    genuine_admission = source_admission()
    forged_admission = replace(
        genuine_admission,
        report=replace(
            genuine_admission.report,
            report_digest=_digest("caller-authored-admission-report"),
        ),
    )
    capture = capture_evidence(prerequisite, forged_admission)
    replay = replay_evidence(capture)
    specification = research_specification(
        prerequisite,
        forged_admission,
        capture,
        replay,
    )
    review = independent_review(specification, capture, replay)

    assessment = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=forged_admission,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )

    assert assessment.blockers == (
        CapturedTapeResearchBlocker.SOURCE_ADMISSION_REPORT_MISMATCH,
        CapturedTapeResearchBlocker.AUTHENTICATED_CAPTURE_PROVENANCE_MISSING,
    )


def test_mutable_retention_never_counts_as_immutable_capture() -> None:
    prerequisite = production_prerequisite()
    admission = source_admission()
    capture = capture_evidence(
        prerequisite,
        admission,
        retention_kind=CapturedTapeRetentionKind.MUTABLE,
    )
    replay = replay_evidence(capture)
    specification = research_specification(prerequisite, admission, capture, replay)
    review = independent_review(specification, capture, replay)

    assessment = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )

    assert assessment.blockers == (
        CapturedTapeResearchBlocker.AUTHENTICATED_CAPTURE_PROVENANCE_MISSING,
        CapturedTapeResearchBlocker.CAPTURE_NOT_IMMUTABLE,
    )


@pytest.mark.parametrize(
    ("target", "changes", "expected_blocker"),
    (
        (
            "capture",
            {"decision": CapturedTapeEvidenceDecision.REJECTED},
            CapturedTapeResearchBlocker.CAPTURE_EVIDENCE_REJECTED,
        ),
        (
            "capture",
            {"sealed_at": EVALUATED_AT + timedelta(microseconds=1)},
            CapturedTapeResearchBlocker.CAPTURE_EVIDENCE_IN_FUTURE,
        ),
        (
            "capture",
            {"valid_through": EVALUATED_AT},
            CapturedTapeResearchBlocker.CAPTURE_EVIDENCE_STALE,
        ),
        (
            "replay",
            {"decision": CapturedTapeEvidenceDecision.REJECTED},
            CapturedTapeResearchBlocker.REPLAY_EVIDENCE_REJECTED,
        ),
        (
            "replay",
            {"replay_completed_at": EVALUATED_AT + timedelta(microseconds=1)},
            CapturedTapeResearchBlocker.REPLAY_EVIDENCE_IN_FUTURE,
        ),
        (
            "replay",
            {"valid_through": EVALUATED_AT},
            CapturedTapeResearchBlocker.REPLAY_EVIDENCE_STALE,
        ),
    ),
)
def test_rejected_future_and_stale_capture_or_replay_fails_closed(
    target: str,
    changes: dict[str, object],
    expected_blocker: CapturedTapeResearchBlocker,
) -> None:
    prerequisite, admission, capture, replay, specification, _ = external_shaped_inputs()
    if target == "capture":
        capture = replace(capture, **cast(Any, changes))
    else:
        replay = replace(replay, **cast(Any, changes))
    review = independent_review(specification, capture, replay)

    assessment = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )

    assert expected_blocker in assessment.blockers
    assert assessment.status is CapturedTapeResearchValidityStatus.BLOCKED


@pytest.mark.parametrize(
    ("target", "field_name", "replacement_value", "expected_blocker"),
    (
        (
            "capture",
            "provider",
            "substituted-provider",
            CapturedTapeResearchBlocker.CAPTURE_BINDING_MISMATCH,
        ),
        (
            "capture",
            "source_tape_sha256",
            _digest("substituted-source-tape"),
            CapturedTapeResearchBlocker.CAPTURE_BINDING_MISMATCH,
        ),
        (
            "replay",
            "replay_runtime_sha256",
            _digest("substituted-runtime"),
            CapturedTapeResearchBlocker.REPLAY_BINDING_MISMATCH,
        ),
        (
            "replay",
            "research_configuration_sha256",
            _digest("substituted-configuration"),
            CapturedTapeResearchBlocker.CONFIGURATION_BINDING_MISMATCH,
        ),
    ),
)
def test_each_exact_capture_replay_or_configuration_substitution_fails_closed(
    target: str,
    field_name: str,
    replacement_value: str,
    expected_blocker: CapturedTapeResearchBlocker,
) -> None:
    prerequisite, admission, capture, replay, specification, _ = external_shaped_inputs()
    if target == "capture":
        capture = replace(
            capture,
            **cast(Any, {field_name: replacement_value}),
        )
    else:
        replay = replace(
            replay,
            **cast(Any, {field_name: replacement_value}),
        )
    review = independent_review(specification, capture, replay)

    assessment = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )

    assert expected_blocker in assessment.blockers
    assert not assessment.counts_as_captured_tape_research_evidence


def test_review_cannot_be_replayed_for_another_configuration_or_context() -> None:
    prerequisite, admission, capture, _, _, old_review = external_shaped_inputs()
    changed_replay = replay_evidence(
        capture,
        research_configuration_sha256=_digest("next-configuration"),
    )
    changed_specification = research_specification(
        prerequisite,
        admission,
        capture,
        changed_replay,
        review_context_id="captured-tape-review-context-v2",
    )

    assessment = assess_captured_tape_research_validity(
        specification=changed_specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=capture,
        replay=changed_replay,
        review=old_review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )

    assert CapturedTapeResearchBlocker.REVIEW_BINDING_MISMATCH in assessment.blockers
    assert CapturedTapeResearchBlocker.REVIEW_REPLAYED_OR_SUBSTITUTED in assessment.blockers


@pytest.mark.parametrize(
    "reviewer_id",
    (
        GATE_EXECUTOR_ID,
        "production-prerequisite-executor",
        "producer-production_identity_lifecycle",
        "production-independent-reviewer",
        "source-admission-executor",
        "source-admission-reviewer",
        "capture-evidence-producer",
        "capture-executor",
        "replay-evidence-producer",
        "replay-executor",
    ),
)
def test_review_must_be_independent_of_every_producer_and_executor(
    reviewer_id: str,
) -> None:
    prerequisite, admission, capture, replay, specification, _ = external_shaped_inputs()
    review = independent_review(
        specification,
        capture,
        replay,
        reviewer_id=reviewer_id,
    )

    assessment = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )

    assert CapturedTapeResearchBlocker.SELF_APPROVED in assessment.blockers


def test_nonexternal_rejected_stale_and_future_reviews_fail_closed() -> None:
    prerequisite, admission, capture, replay, specification, _ = external_shaped_inputs()
    cases = (
        (
            independent_review(
                specification,
                capture,
                replay,
                review_class=CapturedTapeReviewClass.RESEARCH_ONLY,
            ),
            CapturedTapeResearchBlocker.NON_EXTERNAL_REVIEW,
        ),
        (
            independent_review(
                specification,
                capture,
                replay,
                decision=CapturedTapeReviewDecision.REJECTED,
            ),
            CapturedTapeResearchBlocker.REVIEW_REJECTED,
        ),
        (
            independent_review(
                specification,
                capture,
                replay,
                valid_through=EVALUATED_AT,
            ),
            CapturedTapeResearchBlocker.REVIEW_STALE,
        ),
        (
            independent_review(
                specification,
                capture,
                replay,
                reviewed_at=EVALUATED_AT + timedelta(microseconds=1),
            ),
            CapturedTapeResearchBlocker.REVIEW_OBSERVED_IN_FUTURE,
        ),
    )

    for review, expected_blocker in cases:
        assessment = assess_captured_tape_research_validity(
            specification=specification,
            production_prerequisite=prerequisite,
            source_admission=admission,
            capture=capture,
            replay=replay,
            review=review,
            executor_id=GATE_EXECUTOR_ID,
            evaluated_at=EVALUATED_AT,
        )
        assert expected_blocker in assessment.blockers


def test_out_of_order_replay_fails_temporal_binding() -> None:
    prerequisite = production_prerequisite()
    admission = source_admission()
    capture = capture_evidence(prerequisite, admission)
    replay = replay_evidence(
        capture,
        replay_started_at=SPECIFICATION_FROZEN_AT - timedelta(minutes=2),
        replay_completed_at=SPECIFICATION_FROZEN_AT - timedelta(minutes=1),
    )
    specification = research_specification(prerequisite, admission, capture, replay)
    review = independent_review(specification, capture, replay)

    assessment = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )

    assert CapturedTapeResearchBlocker.TEMPORAL_BINDING_MISMATCH in assessment.blockers


def test_equal_causal_timestamps_do_not_prove_ordering() -> None:
    prerequisite = production_prerequisite()
    admission = source_admission()
    base_capture = capture_evidence(prerequisite, admission)
    cases = (
        (
            replace(base_capture, sealed_at=SPECIFICATION_FROZEN_AT),
            None,
        ),
        (
            base_capture,
            SPECIFICATION_FROZEN_AT,
        ),
    )

    for capture, replay_started_at in cases:
        replay = replay_evidence(
            capture,
            replay_started_at=(
                REPLAY_STARTED_AT if replay_started_at is None else replay_started_at
            ),
        )
        specification = research_specification(
            prerequisite,
            admission,
            capture,
            replay,
        )
        review = independent_review(specification, capture, replay)
        assessment = assess_captured_tape_research_validity(
            specification=specification,
            production_prerequisite=prerequisite,
            source_admission=admission,
            capture=capture,
            replay=replay,
            review=review,
            executor_id=GATE_EXECUTOR_ID,
            evaluated_at=EVALUATED_AT,
        )

        assert CapturedTapeResearchBlocker.TEMPORAL_BINDING_MISMATCH in assessment.blockers


def test_review_must_strictly_follow_replay_completion() -> None:
    prerequisite, admission, capture, replay, specification, _ = external_shaped_inputs()
    review = independent_review(
        specification,
        capture,
        replay,
        reviewed_at=replay.replay_completed_at,
    )

    assessment = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )

    assert CapturedTapeResearchBlocker.REVIEW_PREDATES_EVIDENCE in assessment.blockers


def test_stale_specification_and_evaluation_before_freeze_fail_closed() -> None:
    prerequisite, admission, capture, replay, specification, review = external_shaped_inputs()
    stale_specification = replace(specification, valid_through=EVALUATED_AT)
    stale_review = independent_review(stale_specification, capture, replay)

    stale = assess_captured_tape_research_validity(
        specification=stale_specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=capture,
        replay=replay,
        review=stale_review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )
    predating = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=specification.frozen_at - timedelta(microseconds=1),
    )

    assert CapturedTapeResearchBlocker.SPECIFICATION_STALE in stale.blockers
    assert CapturedTapeResearchBlocker.EVALUATION_PREDATES_SPECIFICATION in predating.blockers


def test_source_admission_freshness_is_half_open() -> None:
    prerequisite, admission, capture, replay, specification, review = external_shaped_inputs()
    approval = admission.evidence.approval
    assert approval is not None
    oldest_admission_evidence_at = min(
        (
            admission.report.evaluated_at,
            *(check.checked_at for check in admission.evidence.technical_checks),
            approval.reviewed_at,
        )
    )
    boundary = oldest_admission_evidence_at + SOURCE_ADMISSION_MAX_AGE

    still_current = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=boundary - timedelta(microseconds=1),
    )
    stale = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=boundary,
    )

    assert CapturedTapeResearchBlocker.SOURCE_ADMISSION_STALE not in still_current.blockers
    assert CapturedTapeResearchBlocker.SOURCE_ADMISSION_STALE in stale.blockers


def test_fresh_admission_wrapper_cannot_hide_stale_checks_or_approval() -> None:
    prerequisite = production_prerequisite()
    specification = admission_specification()
    refreshed_evidence = replace(
        admission_evidence(),
        evaluated_at=EVALUATED_AT - timedelta(hours=1),
    )
    refreshed_admission = AdmittedHistoricalSourceEvidence(
        specification=specification,
        evidence=refreshed_evidence,
        report=evaluate_admission(specification, refreshed_evidence),
    )
    capture = capture_evidence(prerequisite, refreshed_admission)
    replay = replay_evidence(capture)
    research_spec = research_specification(
        prerequisite,
        refreshed_admission,
        capture,
        replay,
    )
    review = independent_review(research_spec, capture, replay)
    stale_at = PRODUCTION_OBSERVED_AT + SOURCE_ADMISSION_MAX_AGE

    assessment = assess_captured_tape_research_validity(
        specification=research_spec,
        production_prerequisite=prerequisite,
        source_admission=refreshed_admission,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=stale_at,
    )

    assert stale_at < refreshed_admission.report.evaluated_at + SOURCE_ADMISSION_MAX_AGE
    assert CapturedTapeResearchBlocker.SOURCE_ADMISSION_STALE in assessment.blockers

    approval = refreshed_evidence.approval
    assert approval is not None
    approval_only_admission = replace(
        refreshed_admission,
        evidence=replace(refreshed_evidence, technical_checks=()),
    )
    approval_capture = capture_evidence(prerequisite, approval_only_admission)
    approval_replay = replay_evidence(approval_capture)
    approval_spec = research_specification(
        prerequisite,
        approval_only_admission,
        approval_capture,
        approval_replay,
    )
    approval_review = independent_review(
        approval_spec,
        approval_capture,
        approval_replay,
    )
    approval_stale_at = approval.reviewed_at + SOURCE_ADMISSION_MAX_AGE
    approval_only_assessment = assess_captured_tape_research_validity(
        specification=approval_spec,
        production_prerequisite=prerequisite,
        source_admission=approval_only_admission,
        capture=approval_capture,
        replay=approval_replay,
        review=approval_review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=approval_stale_at,
    )

    assert (
        approval_stale_at < approval_only_admission.report.evaluated_at + SOURCE_ADMISSION_MAX_AGE
    )
    assert (
        CapturedTapeResearchBlocker.SOURCE_ADMISSION_REPORT_MISMATCH
        in approval_only_assessment.blockers
    )
    assert CapturedTapeResearchBlocker.SOURCE_ADMISSION_STALE in approval_only_assessment.blockers


def test_near_datetime_max_admission_fails_future_without_overflow() -> None:
    prerequisite = production_prerequisite()
    specification = admission_specification()
    base_evidence = admission_evidence()
    approval = base_evidence.approval
    assert approval is not None
    far_future_evaluated_at = datetime.max.replace(tzinfo=UTC) - timedelta(days=1)
    future_evidence = replace(
        base_evidence,
        technical_checks=tuple(
            replace(
                check,
                checked_at=far_future_evaluated_at - timedelta(days=2),
            )
            for check in base_evidence.technical_checks
        ),
        approval=replace(
            approval,
            reviewed_at=far_future_evaluated_at - timedelta(days=1),
        ),
        evaluated_at=far_future_evaluated_at,
    )
    future_admission = AdmittedHistoricalSourceEvidence(
        specification=specification,
        evidence=future_evidence,
        report=evaluate_admission(specification, future_evidence),
    )
    capture = capture_evidence(prerequisite, future_admission)
    replay = replay_evidence(capture)
    research_spec = research_specification(
        prerequisite,
        future_admission,
        capture,
        replay,
    )
    review = independent_review(research_spec, capture, replay)

    assessment = assess_captured_tape_research_validity(
        specification=research_spec,
        production_prerequisite=prerequisite,
        source_admission=future_admission,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )

    assert CapturedTapeResearchBlocker.SOURCE_ADMISSION_IN_FUTURE in assessment.blockers
    assert assessment.status is CapturedTapeResearchValidityStatus.BLOCKED


def test_production_role_order_is_a_determinism_property() -> None:
    base = production_bundle()
    admission = source_admission()
    prerequisite = production_prerequisite(bundle=base)
    capture = capture_evidence(prerequisite, admission)
    replay = replay_evidence(capture)
    specification = research_specification(prerequisite, admission, capture, replay)
    review = independent_review(specification, capture, replay)
    assessments = set()

    for ordering in permutations(base.attestations):
        reordered = ProductionEvidenceBundle(ordering)
        reordered_review = production_review(reordered)
        reordered_assessment = assess_production_market_data_evidence(
            specification=production_specification(),
            evidence=reordered,
            review=reordered_review,
            executor_id="production-prerequisite-executor",
            evaluated_at=PRODUCTION_ASSESSED_AT,
        )
        reordered_prerequisite = ProductionEvidencePrerequisite(
            specification=production_specification(),
            evidence=reordered,
            review=reordered_review,
            assessment=reordered_assessment,
            executor_id="production-prerequisite-executor",
        )
        result = assess_captured_tape_research_validity(
            specification=specification,
            production_prerequisite=reordered_prerequisite,
            source_admission=admission,
            capture=capture,
            replay=replay,
            review=review,
            executor_id=GATE_EXECUTOR_ID,
            evaluated_at=EVALUATED_AT,
        )
        assessments.add((result.semantic_sha256, result.blockers))

    expected = assess_external_shaped_inputs()
    assert assessments == {(expected.semantic_sha256, expected.blockers)}


def test_content_addressing_utc_and_immutability_contracts_are_strict() -> None:
    prerequisite, admission, capture, _, _, _ = external_shaped_inputs()

    with pytest.raises(ValueError, match="capture ID must equal"):
        replace(capture, capture_id=_digest("not-the-capture-manifest"))
    with pytest.raises(ValueError, match="dataset manifest ID must equal"):
        replace(capture, dataset_manifest_id=_digest("not-the-dataset-manifest"))
    with pytest.raises(ValueError, match="stored in UTC"):
        replace(
            capture,
            sealed_at=CAPTURE_SEALED_AT.astimezone(timezone(timedelta(hours=-4))),
        )
    with pytest.raises(FrozenInstanceError):
        capture.source_id = "forged"  # type: ignore[misc]

    recreated = capture_evidence(prerequisite, admission)
    assert recreated.semantic_sha256 == capture.semantic_sha256


def test_assessment_tampering_is_detected_by_its_seal() -> None:
    assessment = assess_external_shaped_inputs()
    object.__setattr__(
        assessment,
        "blockers",
        (CapturedTapeResearchBlocker.SELF_APPROVED,),
    )

    with pytest.raises(CapturedTapeResearchValidityConflict, match="seal is invalid"):
        assessment.__post_init__()


def test_blockers_cannot_be_erased_before_reading_positive_assessment_properties() -> None:
    prerequisite, admission, capture, replay, specification, _ = external_shaped_inputs()
    blocked = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=capture,
        replay=replay,
        review=None,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )
    assert blocked.status is CapturedTapeResearchValidityStatus.BLOCKED
    object.__setattr__(blocked, "blockers", ())

    with pytest.raises(CapturedTapeResearchValidityConflict, match="seal is invalid"):
        _ = blocked.status
    with pytest.raises(CapturedTapeResearchValidityConflict, match="seal is invalid"):
        _ = blocked.counts_as_captured_tape_research_evidence
    with pytest.raises(CapturedTapeResearchValidityConflict, match="seal is invalid"):
        _ = blocked.canonical_json


def test_resealing_an_empty_v1_assessment_cannot_forge_eligibility() -> None:
    assessment = assess_external_shaped_inputs()
    object.__setattr__(assessment, "blockers", ())
    material = validity_contract._assessment_material(
        specification_sha256=assessment.specification_sha256,
        production_assessment_sha256=assessment.production_assessment_sha256,
        current_production_assessment_sha256=(assessment.current_production_assessment_sha256),
        source_admission_report_sha256=assessment.source_admission_report_sha256,
        capture_evidence_sha256=assessment.capture_evidence_sha256,
        authenticated_provenance_sha256=(assessment.authenticated_provenance_sha256),
        replay_evidence_sha256=assessment.replay_evidence_sha256,
        review_sha256=assessment.review_sha256,
        executor_sha256=assessment.executor_sha256,
        evaluated_at=assessment.evaluated_at,
        blockers=assessment.blockers,
    )
    object.__setattr__(
        assessment,
        "_seal",
        validity_contract._CapturedTapeResearchValiditySeal(
            payload_sha256=validity_contract._sha256(material)
        ),
    )

    with pytest.raises(
        CapturedTapeResearchValidityConflict,
        match="external-provenance blocker",
    ):
        _ = assessment.status
