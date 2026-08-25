from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

import pytest

from packages.application.captured_tape_research_validity import (
    CapturedTapeEvidenceClass,
    CapturedTapeResearchBlocker,
    CapturedTapeResearchValidityError,
    CapturedTapeResearchValidityStatus,
    assess_captured_tape_research_validity,
)
from packages.application.production_market_data_admission import ProductionEvidenceGateStatus
from packages.market_data import AdmissionStatus
from tests.unit.test_captured_tape_research_validity import (
    EVALUATED_AT,
    GATE_EXECUTOR_ID,
    external_shaped_inputs,
    independent_review,
    replay_evidence,
    research_specification,
)
from tests.unit.test_replay_manifest import replay_manifest


def test_wave1_readiness_and_generic_admission_alone_cannot_create_capture_evidence() -> None:
    prerequisite, admission, _, _, specification, _ = external_shaped_inputs()

    assert prerequisite.assessment.status is (
        ProductionEvidenceGateStatus.READY_FOR_ADMISSION_EVALUATION
    )
    assert admission.report.status is AdmissionStatus.ADMITTED

    assessment = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=None,
        replay=None,
        review=None,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )

    assert assessment.status is CapturedTapeResearchValidityStatus.BLOCKED
    assert assessment.blockers == (
        CapturedTapeResearchBlocker.CAPTURE_EVIDENCE_MISSING,
        CapturedTapeResearchBlocker.AUTHENTICATED_CAPTURE_PROVENANCE_MISSING,
        CapturedTapeResearchBlocker.REPLAY_EVIDENCE_MISSING,
        CapturedTapeResearchBlocker.INDEPENDENT_REVIEW_MISSING,
    )
    assert not assessment.historical_source_authorized
    assert not assessment.admission_authorized
    assert not assessment.trading_authorized


def test_existing_recorded_fixture_replay_manifest_cannot_substitute_for_capture_proof() -> None:
    prerequisite, admission, _, replay, specification, review = external_shaped_inputs()
    fixture_manifest = replay_manifest()

    assert fixture_manifest.dataset.source_kind == "recorded_fixture"
    with pytest.raises(
        CapturedTapeResearchValidityError,
        match="exact captured dataset/tape evidence",
    ):
        assess_captured_tape_research_validity(
            specification=specification,
            production_prerequisite=prerequisite,
            source_admission=admission,
            capture=cast(Any, fixture_manifest),
            replay=replay,
            review=review,
            executor_id=GATE_EXECUTOR_ID,
            evaluated_at=EVALUATED_AT,
        )


def test_existing_recorded_fixture_manifest_cannot_be_relabelled_as_vendor_capture() -> None:
    prerequisite, admission, base_capture, _, _, _ = external_shaped_inputs()
    fixture_manifest = replay_manifest()
    relabelled_capture = replace(
        base_capture,
        capture_id=fixture_manifest.manifest_sha256,
        capture_manifest_sha256=fixture_manifest.manifest_sha256,
        dataset_manifest_id=fixture_manifest.dataset.manifest_sha256,
        dataset_manifest_sha256=fixture_manifest.dataset.manifest_sha256,
        immutable_object_set_sha256=(fixture_manifest.dataset.partitions[0].byte_sha256),
        source_tape_sha256=fixture_manifest.dataset.source_tape_sha256,
    )
    replay = replay_evidence(relabelled_capture)
    specification = research_specification(
        prerequisite,
        admission,
        relabelled_capture,
        replay,
    )
    review = independent_review(specification, relabelled_capture, replay)

    assessment = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=admission,
        capture=relabelled_capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )

    assert fixture_manifest.dataset.source_kind == "recorded_fixture"
    assert relabelled_capture.evidence_class is CapturedTapeEvidenceClass.VENDOR_CAPTURED
    assert assessment.blockers == (
        CapturedTapeResearchBlocker.AUTHENTICATED_CAPTURE_PROVENANCE_MISSING,
    )
    assert assessment.status is CapturedTapeResearchValidityStatus.BLOCKED


def test_existing_recorded_fixture_manifest_cannot_substitute_for_replay_evidence() -> None:
    prerequisite, admission, capture, _, specification, review = external_shaped_inputs()

    with pytest.raises(CapturedTapeResearchValidityError, match="exact replay evidence"):
        assess_captured_tape_research_validity(
            specification=specification,
            production_prerequisite=prerequisite,
            source_admission=admission,
            capture=capture,
            replay=cast(Any, replay_manifest()),
            review=review,
            executor_id=GATE_EXECUTOR_ID,
            evaluated_at=EVALUATED_AT,
        )


def test_ready_prerequisite_cannot_replace_a_separate_admitted_source_decision() -> None:
    prerequisite, _, capture, replay, specification, review = external_shaped_inputs()

    assessment = assess_captured_tape_research_validity(
        specification=specification,
        production_prerequisite=prerequisite,
        source_admission=None,
        capture=capture,
        replay=replay,
        review=review,
        executor_id=GATE_EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )

    assert CapturedTapeResearchBlocker.SOURCE_ADMISSION_MISSING in assessment.blockers
    assert not assessment.counts_as_captured_tape_research_evidence
