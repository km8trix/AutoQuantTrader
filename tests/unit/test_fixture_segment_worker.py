from __future__ import annotations

from datetime import timedelta

import pytest

from packages.domain.experiment_governance import (
    ExperimentAttemptStatus,
    ExperimentGovernanceSnapshot,
    GovernedSegmentEvaluationReceipt,
    NonExecutableTerminalEvidence,
)
from packages.domain.experiment_registry import EvaluationSegmentKind
from packages.domain.feature import CertifiedFeatureReplay
from packages.domain.fixture_segment_worker import (
    FIXTURE_SEGMENT_FAILURE_CODE,
    FIXTURE_SEGMENT_FAILURE_DETAIL,
    FIXTURE_SEGMENT_FAILURE_SHA256,
    FixtureSegmentJob,
    FixtureSegmentJobProjection,
    FixtureSegmentWorkerConflict,
    FixtureSegmentWorkerError,
    FixtureTranscriptArtifact,
    FixtureTranscriptKind,
    claim_fixture_segment_job,
    complete_fixture_segment_job,
    fail_fixture_segment_job,
    fixture_segment_failure_evidence,
    queue_fixture_segment_job,
    renew_fixture_segment_claim,
)
from tests.unit.test_experiment_governance import (
    FIRST_ATTEMPT_AT,
    GovernanceFixture,
    _configuration,
    _fixture,
    _request,
    _revealed_snapshot,
    _scoped_certification,
    _target_certification,
)


def _queued(
    kind: EvaluationSegmentKind = EvaluationSegmentKind.VALIDATION,
) -> tuple[
    GovernanceFixture,
    ExperimentGovernanceSnapshot,
    CertifiedFeatureReplay,
    FixtureSegmentJob,
    FixtureTranscriptArtifact,
]:
    fixture = _fixture()
    snapshot = _request(
        ExperimentGovernanceSnapshot.empty(fixture.family),
        fixture,
        kind=kind,
        requested_at=FIRST_ATTEMPT_AT,
    )
    certification = {
        EvaluationSegmentKind.TRAIN: fixture.train_certification,
        EvaluationSegmentKind.VALIDATION: fixture.validation_certification,
        EvaluationSegmentKind.TEST: fixture.test_certification,
    }[kind]
    job, artifact = FixtureSegmentJob.from_queued_attempt(
        snapshot,
        snapshot.attempts[-1].attempt_id,
        certification,
        requested_at=FIRST_ATTEMPT_AT + timedelta(seconds=1),
        requested_by="phase3f-scheduler",
    )
    return fixture, snapshot, certification, job, artifact


def _running() -> tuple[
    GovernanceFixture,
    ExperimentGovernanceSnapshot,
    CertifiedFeatureReplay,
    FixtureSegmentJobProjection,
]:
    fixture, queued, certification, job, artifact = _queued()
    governed = queued.transition_attempt(
        job.attempt_id,
        status=ExperimentAttemptStatus.RUNNING,
        occurred_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        actor_id=job.governed_actor_id,
    )
    projection = claim_fixture_segment_job(
        queue_fixture_segment_job(job, artifact),
        worker_id="phase3f-process-a",
        claimed_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        claim_expires_at=FIRST_ATTEMPT_AT + timedelta(minutes=6),
        governance_running_event_sha256=governed.latest_event(job.attempt_id).semantic_sha256,
    )
    return fixture, governed, certification, projection


def test_job_binds_exact_queued_attempt_and_content_addressed_feature_transcript() -> None:
    _fixture_value, _snapshot, certification, job, artifact = _queued()

    assert artifact.kind is FixtureTranscriptKind.FEATURE
    assert artifact.certification_sha256 == certification.semantic_sha256
    assert artifact.transcript_payload_sha256 != artifact.transcript_sha256
    assert job.feature_transcript_artifact_sha256 == artifact.artifact_sha256
    assert job.governed_actor_id == f"phase3f-governed-{job.job_id}"
    assert job.configuration_sha256 not in artifact.transcript_payload


def test_enqueue_rejects_a_request_before_the_governed_attempt() -> None:
    fixture = _fixture()
    snapshot = _request(
        ExperimentGovernanceSnapshot.empty(fixture.family),
        fixture,
        kind=EvaluationSegmentKind.VALIDATION,
        requested_at=FIRST_ATTEMPT_AT,
    )

    with pytest.raises(FixtureSegmentWorkerError, match="cannot precede"):
        FixtureSegmentJob.from_queued_attempt(
            snapshot,
            snapshot.attempts[-1].attempt_id,
            fixture.validation_certification,
            requested_at=FIRST_ATTEMPT_AT - timedelta(seconds=1),
            requested_by="phase3f-scheduler",
        )


def test_enqueue_rejects_substituted_feature_certification() -> None:
    _fixture_value, snapshot, _certification, _job, _artifact = _queued()

    with pytest.raises(FixtureSegmentWorkerError, match="changed the governed segment"):
        FixtureSegmentJob.from_queued_attempt(
            snapshot,
            snapshot.attempts[-1].attempt_id,
            _scoped_certification(40),
            requested_at=FIRST_ATTEMPT_AT + timedelta(seconds=1),
            requested_by="phase3f-scheduler",
        )


def test_enqueue_rejects_unrevealed_holdout_bytes() -> None:
    fixture = _fixture()
    # A domain-created test attempt is impossible before reveal. A train attempt
    # substituted with test evidence must also fail before anything is retained.
    snapshot = _request(
        ExperimentGovernanceSnapshot.empty(fixture.family),
        fixture,
        kind=EvaluationSegmentKind.TRAIN,
        requested_at=FIRST_ATTEMPT_AT,
    )
    with pytest.raises(FixtureSegmentWorkerError, match="changed the governed segment"):
        FixtureSegmentJob.from_queued_attempt(
            snapshot,
            snapshot.attempts[-1].attempt_id,
            fixture.test_certification,
            requested_at=FIRST_ATTEMPT_AT + timedelta(seconds=1),
            requested_by="phase3f-scheduler",
        )


def test_enqueue_accepts_only_the_exact_post_reveal_test_evidence() -> None:
    fixture = _fixture()
    revealed = _revealed_snapshot(fixture)
    queued = _request(
        revealed,
        fixture,
        kind=EvaluationSegmentKind.TEST,
        requested_at=FIRST_ATTEMPT_AT + timedelta(minutes=4),
    )

    job, artifact = FixtureSegmentJob.from_queued_attempt(
        queued,
        queued.attempts[-1].attempt_id,
        fixture.test_certification,
        requested_at=FIRST_ATTEMPT_AT + timedelta(minutes=4, seconds=1),
        requested_by="phase3f-scheduler",
    )

    assert queued.holdout_reveal is not None
    assert job.segment_kind is EvaluationSegmentKind.TEST
    assert job.source_evidence_sha256 == queued.holdout_reveal.test_evidence.semantic_sha256
    assert artifact.certification_sha256 == fixture.test_certification.semantic_sha256


def test_claim_token_rotates_on_renewal_and_rejects_stale_token() -> None:
    _fixture_value, _governed, _certification, projection = _running()
    stale = projection.claim_token
    assert stale is not None
    renewed = renew_fixture_segment_claim(
        projection,
        stale,
        renewed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
        claim_expires_at=FIRST_ATTEMPT_AT + timedelta(minutes=8),
    )

    assert renewed.claim_token is not None
    assert renewed.claim_token != stale
    with pytest.raises(FixtureSegmentWorkerConflict, match="must follow"):
        renew_fixture_segment_claim(
            projection,
            stale,
            renewed_at=projection.latest.occurred_at,
            claim_expires_at=FIRST_ATTEMPT_AT + timedelta(minutes=9),
        )
    with pytest.raises(FixtureSegmentWorkerConflict, match="stale or substituted"):
        renew_fixture_segment_claim(
            renewed,
            stale,
            renewed_at=FIRST_ATTEMPT_AT + timedelta(minutes=3),
            claim_expires_at=FIRST_ATTEMPT_AT + timedelta(minutes=9),
        )


def test_expired_claim_can_be_taken_over_but_old_worker_cannot_publish() -> None:
    fixture, governed, certification, projection = _running()
    stale = projection.claim_token
    assert stale is not None
    takeover = claim_fixture_segment_job(
        projection,
        worker_id="phase3f-process-b",
        claimed_at=FIRST_ATTEMPT_AT + timedelta(minutes=7),
        claim_expires_at=FIRST_ATTEMPT_AT + timedelta(minutes=12),
        governance_running_event_sha256=governed.latest_event(
            projection.job.attempt_id
        ).semantic_sha256,
    )
    target_certification = _target_certification(certification, fixture.configuration)
    target_artifact = FixtureTranscriptArtifact.from_target_certification(
        family=fixture.family,
        attempt=governed.attempts[-1],
        source_evidence=fixture.family.validation_evidence,
        certification=target_certification,
    )
    completed = governed.complete_attempt(
        projection.job.attempt_id,
        target_certification,
        completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=8),
        actor_id=projection.job.governed_actor_id,
    )
    receipt = completed.latest_event(projection.job.attempt_id).terminal_evidence
    assert isinstance(receipt, GovernedSegmentEvaluationReceipt)

    with pytest.raises(FixtureSegmentWorkerConflict, match="stale or substituted"):
        complete_fixture_segment_job(
            takeover,
            stale,
            target_artifact=target_artifact,
            receipt=receipt,
            governance_completed_event=completed.latest_event(projection.job.attempt_id),
            completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=8),
        )


def test_complete_publishes_exact_target_artifact_and_governed_receipt() -> None:
    fixture, governed, certification, projection = _running()
    token = projection.claim_token
    assert token is not None
    target_certification = _target_certification(certification, fixture.configuration)
    completed_governance = governed.complete_attempt(
        projection.job.attempt_id,
        target_certification,
        completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
        actor_id=projection.job.governed_actor_id,
    )
    completed_event = completed_governance.latest_event(projection.job.attempt_id)
    receipt = completed_event.terminal_evidence
    assert isinstance(receipt, GovernedSegmentEvaluationReceipt)
    target_artifact = FixtureTranscriptArtifact.from_target_certification(
        family=fixture.family,
        attempt=governed.attempts[-1],
        source_evidence=fixture.family.validation_evidence,
        certification=target_certification,
    )

    completed = complete_fixture_segment_job(
        projection,
        token,
        target_artifact=target_artifact,
        receipt=receipt,
        governance_completed_event=completed_event,
        completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
    )

    assert completed.target_artifact == target_artifact
    assert completed.latest.completion_receipt_sha256 == receipt.semantic_sha256
    assert completed.latest.governance_event_sha256 == completed_event.semantic_sha256


def test_failure_requires_the_exact_closed_governance_evidence() -> None:
    _fixture_value, governed, _certification, projection = _running()
    token = projection.claim_token
    assert token is not None
    attempt = next(
        item for item in governed.attempts if item.attempt_id == projection.job.attempt_id
    )
    expected = fixture_segment_failure_evidence(attempt)
    assert expected.reason_code == FIXTURE_SEGMENT_FAILURE_CODE
    assert expected.detail == FIXTURE_SEGMENT_FAILURE_DETAIL

    for reason_code, detail in (
        ("different_bounded_reason", FIXTURE_SEGMENT_FAILURE_DETAIL),
        (FIXTURE_SEGMENT_FAILURE_CODE, "A different bounded terminal detail."),
    ):
        substituted = NonExecutableTerminalEvidence.unsuccessful(
            attempt,
            status=ExperimentAttemptStatus.FAILED,
            reason_code=reason_code,
            detail=detail,
        )
        failed_governance = governed.transition_attempt(
            projection.job.attempt_id,
            status=ExperimentAttemptStatus.FAILED,
            occurred_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
            actor_id=projection.job.governed_actor_id,
            terminal_evidence=substituted,
        )
        with pytest.raises(
            FixtureSegmentWorkerConflict,
            match="changed its governed terminal event",
        ):
            fail_fixture_segment_job(
                projection,
                token,
                governance_failed_event=failed_governance.latest_event(projection.job.attempt_id),
                failed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
                reason_code=FIXTURE_SEGMENT_FAILURE_CODE,
                reason_sha256=FIXTURE_SEGMENT_FAILURE_SHA256,
            )


def test_completion_rejects_configuration_substitution() -> None:
    fixture, governed, certification, projection = _running()
    changed_configuration = _configuration(
        fixture.family.strategy_version,
        long_quantity="11",
    )
    changed_target = _target_certification(certification, changed_configuration)
    with pytest.raises(ValueError, match="does not match the exact configuration"):
        governed.complete_attempt(
            projection.job.attempt_id,
            changed_target,
            completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
            actor_id=projection.job.governed_actor_id,
        )


def test_transcript_restore_rejects_payload_corruption() -> None:
    _fixture_value, _snapshot, _certification, _job, artifact = _queued()

    with pytest.raises(FixtureSegmentWorkerError, match="payload is inconsistent"):
        FixtureTranscriptArtifact._restore(
            kind=artifact.kind,
            family_id=artifact.family_id,
            attempt_id=artifact.attempt_id,
            segment_kind=artifact.segment_kind,
            segment_sha256=artifact.segment_sha256,
            source_evidence_sha256=artifact.source_evidence_sha256,
            configuration_sha256=artifact.configuration_sha256,
            certification_sha256=artifact.certification_sha256,
            parity_receipt_sha256=artifact.parity_receipt_sha256,
            transcript_sha256=artifact.transcript_sha256,
            step_sha256s=artifact.step_sha256s,
            output_ids=artifact.output_ids,
            expected_transcript_payload=artifact.transcript_payload + "corrupt",
            expected_transcript_payload_sha256=artifact.transcript_payload_sha256,
            expected_artifact_sha256=artifact.artifact_sha256,
        )
