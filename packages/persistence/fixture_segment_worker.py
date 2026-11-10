"""Transactional persistence for the bounded Phase 3F fixture-segment worker."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast

import sqlalchemy as sa
from sqlalchemy import Connection, Engine
from sqlalchemy.engine import RowMapping

from packages.domain.canonical import canonical_json_bytes
from packages.domain.experiment_governance import (
    ExperimentAttempt,
    ExperimentAttemptStatus,
    ExperimentGovernanceSnapshot,
    ExperimentSegmentEvidence,
    GovernedSegmentEvaluationReceipt,
    NonExecutableTerminalEvidence,
)
from packages.domain.experiment_governance import (
    ExperimentGovernanceError as DomainExperimentGovernanceError,
)
from packages.domain.experiment_registry import EvaluationSegmentKind
from packages.domain.feature import (
    FEATURE_REPLAY_CONTRACT_VERSION,
    CertifiedFeatureReplay,
    FeatureComputationMode,
)
from packages.domain.feature_target import (
    FEATURE_TARGET_CONTRACT_VERSION,
    CertifiedFeatureTargetReplay,
)
from packages.domain.fixture_segment_worker import (
    FIXTURE_SEGMENT_FAILURE_CODE,
    FIXTURE_SEGMENT_FAILURE_SHA256,
    FIXTURE_SEGMENT_WORKER_CONTRACT_VERSION,
    FixtureSegmentClaimToken,
    FixtureSegmentJob,
    FixtureSegmentJobEvent,
    FixtureSegmentJobProjection,
    FixtureSegmentJobStatus,
    FixtureSegmentWorkerError,
    FixtureTranscriptArtifact,
    FixtureTranscriptKind,
    _event,
    claim_fixture_segment_job,
    complete_fixture_segment_job,
    fail_fixture_segment_job,
    fixture_segment_failure_evidence,
    queue_fixture_segment_job,
    renew_fixture_segment_claim,
    segment_evidence_for_attempt,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.experiment_governance import (
    ExperimentGovernanceConflict,
    SqlExperimentGovernance,
    _load_snapshot_history,
    _verify_audits,
    _write_transaction,
)
from packages.persistence.experiment_governance import (
    ExperimentGovernanceError as PersistedExperimentGovernanceError,
)
from packages.persistence.immutable import (
    ImmutableFactConflict,
    as_aware_utc,
    assert_immutable,
    insert_or_verify_atomic,
)
from packages.persistence.schema import (
    phase3_fixture_segment_job_events,
    phase3_fixture_segment_job_heads,
    phase3_fixture_segment_jobs,
    phase3_fixture_segment_transcript_artifacts,
)

_SUPPORTED_DIALECTS = frozenset({"sqlite", "postgresql"})
MAX_FIXTURE_SEGMENT_PROVENANCE_PAGE_SIZE = 100
_SHA256_TEXT = re.compile(r"^[0-9a-f]{64}$")


def _contract_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _feature_transcript_commitments(
    evidence: ExperimentSegmentEvidence,
    artifact: FixtureTranscriptArtifact,
) -> tuple[str, str, str, str]:
    transcript_sha256 = _contract_sha256(
        (
            FEATURE_REPLAY_CONTRACT_VERSION,
            "feature-replay-transcript",
            evidence.feature_artifact_sha256,
            evidence.replay_result_sha256,
            artifact.step_sha256s,
        )
    )
    batch_result_sha256 = _contract_sha256(
        (
            FEATURE_REPLAY_CONTRACT_VERSION,
            "feature-replay-result",
            FeatureComputationMode.BATCH.value,
            transcript_sha256,
        )
    )
    incremental_result_sha256 = _contract_sha256(
        (
            FEATURE_REPLAY_CONTRACT_VERSION,
            "feature-replay-result",
            FeatureComputationMode.INCREMENTAL.value,
            transcript_sha256,
        )
    )
    certification_sha256 = _contract_sha256(
        (
            FEATURE_REPLAY_CONTRACT_VERSION,
            "certified-feature-replay",
            evidence.feature_artifact_sha256,
            batch_result_sha256,
            incremental_result_sha256,
            evidence.feature_parity_receipt_sha256,
        )
    )
    return (
        transcript_sha256,
        batch_result_sha256,
        incremental_result_sha256,
        certification_sha256,
    )


def _target_transcript_commitments(
    source_evidence: ExperimentSegmentEvidence,
    receipt: GovernedSegmentEvaluationReceipt,
    artifact: FixtureTranscriptArtifact,
) -> tuple[str, str, str, str]:
    transcript_sha256 = _contract_sha256(
        (
            FEATURE_TARGET_CONTRACT_VERSION,
            "feature-target-transcript",
            receipt.target_runtime_pin_sha256,
            source_evidence.feature_transcript_sha256,
            source_evidence.feature_parity_receipt_sha256,
            artifact.step_sha256s,
        )
    )
    batch_result_sha256 = _contract_sha256(
        (
            FEATURE_TARGET_CONTRACT_VERSION,
            "feature-target-replay-result",
            FeatureComputationMode.BATCH.value,
            transcript_sha256,
        )
    )
    incremental_result_sha256 = _contract_sha256(
        (
            FEATURE_TARGET_CONTRACT_VERSION,
            "feature-target-replay-result",
            FeatureComputationMode.INCREMENTAL.value,
            transcript_sha256,
        )
    )
    certification_sha256 = _contract_sha256(
        (
            FEATURE_TARGET_CONTRACT_VERSION,
            "certified-feature-target-replay",
            source_evidence.feature_certification_sha256,
            receipt.target_policy_sha256,
            receipt.target_runtime_pin_sha256,
            batch_result_sha256,
            incremental_result_sha256,
            receipt.target_parity_receipt_sha256,
        )
    )
    return (
        transcript_sha256,
        batch_result_sha256,
        incremental_result_sha256,
        certification_sha256,
    )


class FixtureSegmentPersistenceError(RuntimeError):
    """Persisted fixture-segment work is unavailable or malformed."""


class FixtureSegmentPersistenceConflict(FixtureSegmentPersistenceError):
    """A fixture-segment command conflicts with immutable or current state."""


class FixtureSegmentNotFound(FixtureSegmentPersistenceError):
    """A fixture-segment job does not exist."""


@dataclass(frozen=True, slots=True)
class FixtureTranscriptProvenance:
    """Allowlisted identity metadata for one authenticated transcript artifact."""

    artifact_sha256: str
    kind: FixtureTranscriptKind
    family_id: str
    attempt_id: str
    segment_kind: EvaluationSegmentKind
    configuration_sha256: str | None
    certification_sha256: str
    parity_receipt_sha256: str
    transcript_sha256: str
    step_count: int
    output_count: int
    transcript_payload_sha256: str
    semantic_sha256: str


@dataclass(frozen=True, slots=True)
class FixtureSegmentEventProvenance:
    """Allowlisted lifecycle metadata for one authenticated job event."""

    job_id: str
    event_sha256: str
    sequence: int
    status: FixtureSegmentJobStatus
    occurred_at: datetime
    attempt_number: int
    previous_event_sha256: str | None
    claim_expires_at: datetime | None
    governance_event_sha256: str
    feature_artifact_sha256: str
    target_artifact_sha256: str | None
    completion_receipt_sha256: str | None


@dataclass(frozen=True, slots=True)
class FixtureSegmentJobProvenanceSummary:
    """Constant-size allowlisted summary of one authenticated job chain."""

    job_id: str
    family_id: str
    attempt_id: str
    configuration_sha256: str
    segment_kind: EvaluationSegmentKind
    requested_at: datetime
    status: FixtureSegmentJobStatus
    event_count: int
    latest_sequence: int
    latest_event_sha256: str
    latest_occurred_at: datetime
    feature_artifact_sha256: str
    target_artifact_sha256: str | None
    completion_receipt_sha256: str | None


@dataclass(frozen=True, slots=True)
class FixtureSegmentJobProvenance:
    """Safe projection produced only after full Phase 3F chain authentication."""

    job_id: str
    family_id: str
    attempt_id: str
    configuration_sha256: str
    configuration_validation_sha256: str
    segment_kind: EvaluationSegmentKind
    queued_governance_event_sha256: str
    feature_certification_sha256: str
    requested_at: datetime
    feature_artifact: FixtureTranscriptProvenance
    events: tuple[FixtureSegmentEventProvenance, ...]
    target_artifact: FixtureTranscriptProvenance | None

    @property
    def latest(self) -> FixtureSegmentEventProvenance:
        return self.events[-1]

    @property
    def status(self) -> FixtureSegmentJobStatus:
        return self.latest.status


def _artifact_values(artifact: FixtureTranscriptArtifact) -> dict[str, Any]:
    return {
        "artifact_sha256": artifact.artifact_sha256,
        "artifact_kind": artifact.kind.value,
        "family_id": artifact.family_id,
        "attempt_id": artifact.attempt_id,
        "segment_kind": artifact.segment_kind.value,
        "segment_sha256": artifact.segment_sha256,
        "source_evidence_sha256": artifact.source_evidence_sha256,
        "configuration_sha256": artifact.configuration_sha256,
        "certification_sha256": artifact.certification_sha256,
        "parity_receipt_sha256": artifact.parity_receipt_sha256,
        "transcript_sha256": artifact.transcript_sha256,
        "step_count": len(artifact.step_sha256s),
        "output_count": len(artifact.output_ids),
        "transcript_payload": artifact.transcript_payload,
        "transcript_payload_sha256": artifact.transcript_payload_sha256,
        "semantic_sha256": artifact.semantic_sha256,
    }


def _artifact_from_row(row: RowMapping) -> FixtureTranscriptArtifact:
    payload = str(row["transcript_payload"])
    try:
        decoded = json.loads(payload)
        if (
            type(decoded) is not dict
            or decoded.get("type") != "tuple"
            or type(decoded.get("value")) is not list
            or len(decoded["value"]) != 14
        ):
            raise ValueError("unexpected transcript payload shape")
        nodes = cast(list[object], decoded["value"])
        step_node = cast(dict[str, object], nodes[12])
        output_node = cast(dict[str, object], nodes[13])
        if step_node.get("type") != "tuple" or output_node.get("type") != "tuple":
            raise ValueError("unexpected transcript member shape")
        steps = tuple(
            str(cast(dict[str, object], node)["value"])
            for node in cast(list[object], step_node["value"])
        )
        outputs = tuple(
            str(cast(dict[str, object], node)["value"])
            for node in cast(list[object], output_node["value"])
        )
        artifact = FixtureTranscriptArtifact._restore(
            kind=FixtureTranscriptKind(str(row["artifact_kind"])),
            family_id=str(row["family_id"]),
            attempt_id=str(row["attempt_id"]),
            segment_kind=EvaluationSegmentKind(str(row["segment_kind"])),
            segment_sha256=str(row["segment_sha256"]),
            source_evidence_sha256=str(row["source_evidence_sha256"]),
            configuration_sha256=cast(str | None, row["configuration_sha256"]),
            certification_sha256=str(row["certification_sha256"]),
            parity_receipt_sha256=str(row["parity_receipt_sha256"]),
            transcript_sha256=str(row["transcript_sha256"]),
            step_sha256s=steps,
            output_ids=outputs,
            expected_transcript_payload=payload,
            expected_transcript_payload_sha256=str(row["transcript_payload_sha256"]),
            expected_artifact_sha256=str(row["artifact_sha256"]),
        )
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise FixtureSegmentPersistenceError(
            "persisted fixture transcript artifact is malformed"
        ) from error
    try:
        duplicated_fields_match = (
            int(row["step_count"]) == len(artifact.step_sha256s)
            and int(row["output_count"]) == len(artifact.output_ids)
            and row["semantic_sha256"] == artifact.semantic_sha256
        )
    except (TypeError, ValueError) as error:
        raise FixtureSegmentPersistenceError(
            "persisted fixture transcript duplicated fields are malformed"
        ) from error
    if not duplicated_fields_match:
        raise FixtureSegmentPersistenceError(
            "persisted fixture transcript duplicated fields are inconsistent"
        )
    return artifact


def _job_values(job: FixtureSegmentJob) -> dict[str, Any]:
    return {
        "job_id": job.job_id,
        "family_id": job.family_id,
        "attempt_id": job.attempt_id,
        "configuration_sha256": job.configuration_sha256,
        "configuration_validation_sha256": job.configuration_validation_sha256,
        "segment_kind": job.segment_kind.value,
        "segment_sha256": job.segment_sha256,
        "source_evidence_sha256": job.source_evidence_sha256,
        "queued_governance_event_sha256": job.queued_governance_event_sha256,
        "feature_certification_sha256": job.feature_certification_sha256,
        "feature_transcript_artifact_sha256": job.feature_transcript_artifact_sha256,
        "governed_actor_id": job.governed_actor_id,
        "requested_at": job.requested_at,
        "requested_by": job.requested_by,
        "canonical_payload": job.canonical_json,
        "semantic_sha256": job.semantic_sha256,
    }


def _job_from_row(row: RowMapping) -> FixtureSegmentJob:
    try:
        job = FixtureSegmentJob(
            family_id=str(row["family_id"]),
            attempt_id=str(row["attempt_id"]),
            configuration_sha256=str(row["configuration_sha256"]),
            configuration_validation_sha256=str(row["configuration_validation_sha256"]),
            segment_kind=EvaluationSegmentKind(str(row["segment_kind"])),
            segment_sha256=str(row["segment_sha256"]),
            source_evidence_sha256=str(row["source_evidence_sha256"]),
            queued_governance_event_sha256=str(row["queued_governance_event_sha256"]),
            feature_certification_sha256=str(row["feature_certification_sha256"]),
            feature_transcript_artifact_sha256=str(row["feature_transcript_artifact_sha256"]),
            requested_at=as_aware_utc(cast(datetime, row["requested_at"])),
            requested_by=str(row["requested_by"]),
        )
    except (TypeError, ValueError) as error:
        raise FixtureSegmentPersistenceError("persisted fixture job is malformed") from error
    if (
        row["job_id"] != job.job_id
        or row["governed_actor_id"] != job.governed_actor_id
        or row["canonical_payload"] != job.canonical_json
        or row["semantic_sha256"] != job.semantic_sha256
    ):
        raise FixtureSegmentPersistenceError("persisted fixture job digest is inconsistent")
    return job


def _event_values(event: FixtureSegmentJobEvent) -> dict[str, Any]:
    return {
        "event_sha256": event.event_sha256,
        "job_id": event.job_id,
        "sequence_number": event.sequence,
        "status": event.status.value,
        "occurred_at": event.occurred_at,
        "actor_id": event.actor_id,
        "attempt_number": event.attempt_number,
        "previous_event_sha256": event.previous_event_sha256,
        "worker_id": event.worker_id,
        "claim_expires_at": event.claim_expires_at,
        "governance_event_sha256": event.governance_event_sha256,
        "feature_artifact_sha256": event.feature_artifact_sha256,
        "target_artifact_sha256": event.target_artifact_sha256,
        "completion_receipt_sha256": event.completion_receipt_sha256,
        "terminal_reason_code": event.terminal_reason_code,
        "terminal_reason_sha256": event.terminal_reason_sha256,
        "canonical_payload": event.canonical_json,
        "semantic_sha256": event.event_sha256,
    }


def _event_from_row(row: RowMapping) -> FixtureSegmentJobEvent:
    try:
        event = _event(
            job_id=str(row["job_id"]),
            sequence=int(row["sequence_number"]),
            status=FixtureSegmentJobStatus(str(row["status"])),
            occurred_at=as_aware_utc(cast(datetime, row["occurred_at"])),
            actor_id=str(row["actor_id"]),
            attempt_number=int(row["attempt_number"]),
            previous_event_sha256=cast(str | None, row["previous_event_sha256"]),
            worker_id=cast(str | None, row["worker_id"]),
            claim_expires_at=(
                None
                if row["claim_expires_at"] is None
                else as_aware_utc(cast(datetime, row["claim_expires_at"]))
            ),
            governance_event_sha256=str(row["governance_event_sha256"]),
            feature_artifact_sha256=str(row["feature_artifact_sha256"]),
            target_artifact_sha256=cast(str | None, row["target_artifact_sha256"]),
            completion_receipt_sha256=cast(str | None, row["completion_receipt_sha256"]),
            terminal_reason_code=cast(str | None, row["terminal_reason_code"]),
            terminal_reason_sha256=cast(str | None, row["terminal_reason_sha256"]),
        )
    except (TypeError, ValueError) as error:
        raise FixtureSegmentPersistenceError("persisted fixture job event is malformed") from error
    if (
        row["event_sha256"] != event.event_sha256
        or row["canonical_payload"] != event.canonical_json
        or row["semantic_sha256"] != event.event_sha256
    ):
        raise FixtureSegmentPersistenceError("persisted fixture event digest is inconsistent")
    return event


def _head_values(projection: FixtureSegmentJobProjection) -> dict[str, Any]:
    latest = projection.latest
    return {
        "job_id": projection.job.job_id,
        "status": latest.status.value,
        "latest_sequence_number": latest.sequence,
        "latest_event_sha256": latest.event_sha256,
        "attempt_number": latest.attempt_number,
        "worker_id": latest.worker_id if latest.status is FixtureSegmentJobStatus.RUNNING else None,
        "claim_expires_at": (
            latest.claim_expires_at if latest.status is FixtureSegmentJobStatus.RUNNING else None
        ),
    }


def _artifact(
    connection: Connection,
    artifact_sha256: str,
) -> FixtureTranscriptArtifact:
    row = (
        connection.execute(
            sa.select(phase3_fixture_segment_transcript_artifacts).where(
                phase3_fixture_segment_transcript_artifacts.c.artifact_sha256 == artifact_sha256
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise FixtureSegmentPersistenceError("fixture job references a missing transcript artifact")
    return _artifact_from_row(row)


def _projection(
    connection: Connection,
    job: FixtureSegmentJob,
) -> FixtureSegmentJobProjection:
    feature_artifact = _artifact(connection, job.feature_transcript_artifact_sha256)
    rows = tuple(
        connection.execute(
            sa.select(phase3_fixture_segment_job_events)
            .where(phase3_fixture_segment_job_events.c.job_id == job.job_id)
            .order_by(phase3_fixture_segment_job_events.c.sequence_number)
        ).mappings()
    )
    events = tuple(_event_from_row(row) for row in rows)
    target_artifact = (
        None
        if not events or events[-1].target_artifact_sha256 is None
        else _artifact(connection, events[-1].target_artifact_sha256)
    )
    try:
        projection = FixtureSegmentJobProjection(
            job=job,
            feature_artifact=feature_artifact,
            events=events,
            target_artifact=target_artifact,
        )
    except (TypeError, ValueError) as error:
        raise FixtureSegmentPersistenceError(
            "persisted fixture job history is inconsistent"
        ) from error
    head = (
        connection.execute(
            sa.select(phase3_fixture_segment_job_heads).where(
                phase3_fixture_segment_job_heads.c.job_id == job.job_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if head is None:
        raise FixtureSegmentPersistenceError("fixture job lacks its lockable head")
    expected_head = _head_values(projection)
    for key, value in expected_head.items():
        observed = head[key]
        if isinstance(value, datetime) and isinstance(observed, datetime):
            observed = as_aware_utc(observed)
        if observed != value:
            raise FixtureSegmentPersistenceError("fixture job head diverges from event history")
    return projection


def _artifact_provenance(
    artifact: FixtureTranscriptArtifact,
) -> FixtureTranscriptProvenance:
    return FixtureTranscriptProvenance(
        artifact_sha256=artifact.artifact_sha256,
        kind=artifact.kind,
        family_id=artifact.family_id,
        attempt_id=artifact.attempt_id,
        segment_kind=artifact.segment_kind,
        configuration_sha256=artifact.configuration_sha256,
        certification_sha256=artifact.certification_sha256,
        parity_receipt_sha256=artifact.parity_receipt_sha256,
        transcript_sha256=artifact.transcript_sha256,
        step_count=len(artifact.step_sha256s),
        output_count=len(artifact.output_ids),
        transcript_payload_sha256=artifact.transcript_payload_sha256,
        semantic_sha256=artifact.semantic_sha256,
    )


def _provenance(
    projection: FixtureSegmentJobProjection,
) -> FixtureSegmentJobProvenance:
    return FixtureSegmentJobProvenance(
        job_id=projection.job.job_id,
        family_id=projection.job.family_id,
        attempt_id=projection.job.attempt_id,
        configuration_sha256=projection.job.configuration_sha256,
        configuration_validation_sha256=(projection.job.configuration_validation_sha256),
        segment_kind=projection.job.segment_kind,
        queued_governance_event_sha256=projection.job.queued_governance_event_sha256,
        feature_certification_sha256=projection.job.feature_certification_sha256,
        requested_at=projection.job.requested_at,
        feature_artifact=_artifact_provenance(projection.feature_artifact),
        events=tuple(
            FixtureSegmentEventProvenance(
                job_id=event.job_id,
                event_sha256=event.event_sha256,
                sequence=event.sequence,
                status=event.status,
                occurred_at=event.occurred_at,
                attempt_number=event.attempt_number,
                previous_event_sha256=event.previous_event_sha256,
                claim_expires_at=event.claim_expires_at,
                governance_event_sha256=event.governance_event_sha256,
                feature_artifact_sha256=event.feature_artifact_sha256,
                target_artifact_sha256=event.target_artifact_sha256,
                completion_receipt_sha256=event.completion_receipt_sha256,
            )
            for event in projection.events
        ),
        target_artifact=(
            None
            if projection.target_artifact is None
            else _artifact_provenance(projection.target_artifact)
        ),
    )


def _provenance_summary(
    projection: FixtureSegmentJobProjection,
) -> FixtureSegmentJobProvenanceSummary:
    latest = projection.latest
    return FixtureSegmentJobProvenanceSummary(
        job_id=projection.job.job_id,
        family_id=projection.job.family_id,
        attempt_id=projection.job.attempt_id,
        configuration_sha256=projection.job.configuration_sha256,
        segment_kind=projection.job.segment_kind,
        requested_at=projection.job.requested_at,
        status=projection.status,
        event_count=len(projection.events),
        latest_sequence=latest.sequence,
        latest_event_sha256=latest.event_sha256,
        latest_occurred_at=latest.occurred_at,
        feature_artifact_sha256=projection.feature_artifact.artifact_sha256,
        target_artifact_sha256=(
            None
            if projection.target_artifact is None
            else projection.target_artifact.artifact_sha256
        ),
        completion_receipt_sha256=latest.completion_receipt_sha256,
    )


def _job(connection: Connection, job_id: str) -> FixtureSegmentJob:
    row = (
        connection.execute(
            sa.select(phase3_fixture_segment_jobs).where(
                phase3_fixture_segment_jobs.c.job_id == job_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise FixtureSegmentNotFound(f"unknown fixture-segment job {job_id!r}")
    return _job_from_row(row)


def _current_claim_from_terminal(
    projection: FixtureSegmentJobProjection,
) -> FixtureSegmentClaimToken:
    if len(projection.events) < 2:
        raise FixtureSegmentPersistenceError("terminal fixture job lacks its claim predecessor")
    claim_event = projection.events[-2]
    if claim_event.status is not FixtureSegmentJobStatus.RUNNING or claim_event.worker_id is None:
        raise FixtureSegmentPersistenceError("terminal fixture job predecessor is not a claim")
    return FixtureSegmentClaimToken(
        job_id=projection.job.job_id,
        worker_id=claim_event.worker_id,
        attempt_number=claim_event.attempt_number,
        claim_event_sha256=claim_event.event_sha256,
    )


def _job_head_statement(
    job_id: str,
    *,
    lock: bool,
) -> sa.Select[tuple[Any, ...]]:
    statement = sa.select(phase3_fixture_segment_job_heads).where(
        phase3_fixture_segment_job_heads.c.job_id == job_id
    )
    if lock:
        statement = statement.with_for_update(of=phase3_fixture_segment_job_heads)
    return statement


def _load_governance(connection: Connection, family_id: str) -> ExperimentGovernanceSnapshot:
    history = _load_snapshot_history(connection, family_id, lock=True)
    _verify_audits(connection, history)
    return history[-1]


def _load_governance_for_read(
    connection: Connection,
    family_id: str,
) -> ExperimentGovernanceSnapshot:
    history = _load_snapshot_history(connection, family_id)
    _verify_audits(connection, history)
    return history[-1]


def _attempt(snapshot: ExperimentGovernanceSnapshot, attempt_id: str) -> ExperimentAttempt:
    try:
        return next(attempt for attempt in snapshot.attempts if attempt.attempt_id == attempt_id)
    except StopIteration as error:
        raise FixtureSegmentPersistenceConflict(
            "fixture job no longer resolves to its governed attempt"
        ) from error


def _assert_job_context(
    projection: FixtureSegmentJobProjection,
    snapshot: ExperimentGovernanceSnapshot,
) -> tuple[ExperimentAttempt, ExperimentSegmentEvidence]:
    job = projection.job
    attempt = _attempt(snapshot, job.attempt_id)
    try:
        source_evidence = segment_evidence_for_attempt(snapshot, attempt)
    except ValueError as error:
        raise FixtureSegmentPersistenceConflict(
            "fixture job cannot resolve exact opened segment evidence"
        ) from error
    feature_artifact = projection.feature_artifact
    (
        expected_feature_transcript_sha256,
        _expected_feature_batch_result_sha256,
        _expected_feature_incremental_result_sha256,
        expected_feature_certification_sha256,
    ) = _feature_transcript_commitments(source_evidence, feature_artifact)
    if (
        attempt.family_id != job.family_id
        or attempt.configuration.semantic_sha256 != job.configuration_sha256
        or attempt.configuration_validation.semantic_sha256 != job.configuration_validation_sha256
        or attempt.segment_kind is not job.segment_kind
        or attempt.segment_sha256 != job.segment_sha256
        or source_evidence.semantic_sha256 != job.source_evidence_sha256
        or source_evidence.feature_certification_sha256 != job.feature_certification_sha256
        or feature_artifact.kind is not FixtureTranscriptKind.FEATURE
        or feature_artifact.segment_kind is not source_evidence.segment.kind
        or feature_artifact.segment_sha256 != source_evidence.segment.semantic_sha256
        or feature_artifact.source_evidence_sha256 != source_evidence.semantic_sha256
        or feature_artifact.configuration_sha256 is not None
        or feature_artifact.certification_sha256 != source_evidence.feature_certification_sha256
        or feature_artifact.parity_receipt_sha256 != source_evidence.feature_parity_receipt_sha256
        or feature_artifact.transcript_sha256 != source_evidence.feature_transcript_sha256
        or feature_artifact.transcript_sha256 != expected_feature_transcript_sha256
        or feature_artifact.certification_sha256 != expected_feature_certification_sha256
        or len(feature_artifact.step_sha256s) != source_evidence.step_count
        or len(feature_artifact.output_ids) != source_evidence.snapshot_count
    ):
        raise FixtureSegmentPersistenceConflict(
            "fixture job changed attempt, configuration, segment, or feature identity"
        )
    return attempt, source_evidence


def _verify_governance_link(
    projection: FixtureSegmentJobProjection,
    snapshot: ExperimentGovernanceSnapshot,
) -> None:
    attempt, source_evidence = _assert_job_context(projection, snapshot)
    governance_events = tuple(
        event
        for event in snapshot.lifecycle_events
        if event.attempt_id == projection.job.attempt_id
    )
    expected_status = {
        FixtureSegmentJobStatus.QUEUED: ExperimentAttemptStatus.QUEUED,
        FixtureSegmentJobStatus.RUNNING: ExperimentAttemptStatus.RUNNING,
        FixtureSegmentJobStatus.COMPLETED: ExperimentAttemptStatus.COMPLETED,
        FixtureSegmentJobStatus.FAILED: ExperimentAttemptStatus.FAILED,
    }[projection.latest.status]
    expected_governance_statuses = (
        (ExperimentAttemptStatus.QUEUED,)
        if expected_status is ExperimentAttemptStatus.QUEUED
        else (
            ExperimentAttemptStatus.QUEUED,
            ExperimentAttemptStatus.RUNNING,
        )
        if expected_status is ExperimentAttemptStatus.RUNNING
        else (
            ExperimentAttemptStatus.QUEUED,
            ExperimentAttemptStatus.RUNNING,
            expected_status,
        )
    )
    if tuple(event.status for event in governance_events) != expected_governance_statuses or tuple(
        event.attempt_sequence_number for event in governance_events
    ) != tuple(range(len(expected_governance_statuses))):
        raise FixtureSegmentPersistenceError("fixture and governance lifecycle shapes disagree")

    queued_fixture_event = projection.events[0]
    queued_governance_event = governance_events[0]
    if (
        projection.job.queued_governance_event_sha256 != queued_governance_event.semantic_sha256
        or queued_fixture_event.governance_event_sha256 != queued_governance_event.semantic_sha256
    ):
        raise FixtureSegmentPersistenceError(
            "fixture queued event diverges from governed attempt history"
        )

    physical_running_events = tuple(
        event for event in projection.events if event.status is FixtureSegmentJobStatus.RUNNING
    )
    if expected_status is not ExperimentAttemptStatus.QUEUED:
        running_governance_event = governance_events[1]
        if (
            not physical_running_events
            or physical_running_events[0].occurred_at != running_governance_event.occurred_at
            or running_governance_event.actor_id != projection.job.governed_actor_id
            or any(
                event.governance_event_sha256 != running_governance_event.semantic_sha256
                for event in physical_running_events
            )
        ):
            raise FixtureSegmentPersistenceError(
                "fixture claims diverge from the exact governed running event"
            )
    elif physical_running_events:
        raise FixtureSegmentPersistenceError(
            "queued fixture job unexpectedly retained a physical claim"
        )

    terminal_fixture_event = projection.latest
    if expected_status not in {
        ExperimentAttemptStatus.QUEUED,
        ExperimentAttemptStatus.RUNNING,
    }:
        terminal_governance_event = governance_events[2]
        if (
            terminal_fixture_event.governance_event_sha256
            != terminal_governance_event.semantic_sha256
            or terminal_fixture_event.occurred_at != terminal_governance_event.occurred_at
            or terminal_governance_event.actor_id != projection.job.governed_actor_id
        ):
            raise FixtureSegmentPersistenceError(
                "fixture terminal event diverges from governed attempt history"
            )

    if expected_status is ExperimentAttemptStatus.FAILED:
        terminal_governance_event = governance_events[2]
        terminal_evidence = terminal_governance_event.terminal_evidence
        expected_terminal_evidence = fixture_segment_failure_evidence(attempt)
        if (
            terminal_governance_event.family_id != projection.job.family_id
            or type(terminal_evidence) is not NonExecutableTerminalEvidence
            or terminal_evidence.attempt_id != projection.job.attempt_id
            or terminal_evidence.status is not ExperimentAttemptStatus.FAILED
            or terminal_evidence.reason_code != FIXTURE_SEGMENT_FAILURE_CODE
            or terminal_evidence.detail != expected_terminal_evidence.detail
            or terminal_evidence.semantic_sha256 != expected_terminal_evidence.semantic_sha256
            or terminal_evidence != expected_terminal_evidence
            or terminal_fixture_event.terminal_reason_code != FIXTURE_SEGMENT_FAILURE_CODE
            or terminal_fixture_event.terminal_reason_sha256 != FIXTURE_SEGMENT_FAILURE_SHA256
        ):
            raise FixtureSegmentPersistenceError(
                "fixture failure evidence diverges from its closed governance fact"
            )

    if expected_status is ExperimentAttemptStatus.COMPLETED:
        terminal_governance_event = governance_events[2]
        receipt = terminal_governance_event.terminal_evidence
        target_artifact = projection.target_artifact
        if (
            type(receipt) is not GovernedSegmentEvaluationReceipt
            or type(target_artifact) is not FixtureTranscriptArtifact
        ):
            raise FixtureSegmentPersistenceError(
                "fixture completion evidence diverges from its governed receipt"
            )
        (
            expected_target_transcript_sha256,
            expected_target_batch_result_sha256,
            expected_target_incremental_result_sha256,
            expected_target_certification_sha256,
        ) = _target_transcript_commitments(
            source_evidence,
            receipt,
            target_artifact,
        )
        if (
            terminal_fixture_event.completion_receipt_sha256 != receipt.semantic_sha256
            or receipt.family_id != projection.job.family_id
            or receipt.attempt_id != projection.job.attempt_id
            or receipt.configuration_sha256 != projection.job.configuration_sha256
            or receipt.configuration_validation_sha256
            != projection.job.configuration_validation_sha256
            or receipt.segment_kind is not projection.job.segment_kind
            or receipt.segment_sha256 != projection.job.segment_sha256
            or receipt.source_evidence_sha256 != source_evidence.semantic_sha256
            or receipt.feature_certification_sha256 != source_evidence.feature_certification_sha256
            or receipt.running_event_sha256 != governance_events[1].semantic_sha256
            or receipt.started_at != governance_events[1].occurred_at
            or receipt.completed_at != terminal_governance_event.occurred_at
            or receipt.evaluated_by != terminal_governance_event.actor_id
            or target_artifact.kind is not FixtureTranscriptKind.TARGET
            or target_artifact.configuration_sha256 != receipt.configuration_sha256
            or target_artifact.segment_kind is not receipt.segment_kind
            or target_artifact.segment_sha256 != receipt.segment_sha256
            or target_artifact.source_evidence_sha256 != receipt.source_evidence_sha256
            or target_artifact.certification_sha256 != receipt.target_certification_sha256
            or target_artifact.parity_receipt_sha256 != receipt.target_parity_receipt_sha256
            or target_artifact.transcript_sha256 != receipt.target_transcript_sha256
            or target_artifact.transcript_sha256 != expected_target_transcript_sha256
            or receipt.batch_result_sha256 != expected_target_batch_result_sha256
            or receipt.incremental_result_sha256 != expected_target_incremental_result_sha256
            or target_artifact.certification_sha256 != expected_target_certification_sha256
            or receipt.target_certification_sha256 != expected_target_certification_sha256
            or len(target_artifact.step_sha256s) != receipt.step_count
            or len(target_artifact.output_ids) != receipt.target_count
        ):
            raise FixtureSegmentPersistenceError(
                "fixture completion evidence diverges from its governed receipt"
            )
        try:
            receipt.require_context(
                family=snapshot.family,
                attempt=attempt,
                running_event=governance_events[1],
                source_evidence=source_evidence,
            )
        except DomainExperimentGovernanceError as error:
            raise FixtureSegmentPersistenceError(
                "fixture completion receipt changed its governance context"
            ) from error
    elif terminal_fixture_event.completion_receipt_sha256 is not None:
        raise FixtureSegmentPersistenceError(
            "non-completed fixture job retained completion evidence"
        )


def _verify_fixture_segment_integrity(connection: Connection) -> None:
    job_rows = tuple(connection.execute(sa.select(phase3_fixture_segment_jobs)).mappings())
    seen_artifacts: set[str] = set()
    for row in job_rows:
        job = _job_from_row(row)
        projection = _projection(connection, job)
        _verify_governance_link(projection, _load_governance(connection, job.family_id))
        seen_artifacts.add(projection.feature_artifact.artifact_sha256)
        if projection.target_artifact is not None:
            seen_artifacts.add(projection.target_artifact.artifact_sha256)
    artifact_rows = tuple(
        connection.execute(sa.select(phase3_fixture_segment_transcript_artifacts)).mappings()
    )
    for row in artifact_rows:
        artifact = _artifact_from_row(row)
        if artifact.artifact_sha256 not in seen_artifacts:
            raise FixtureSegmentPersistenceError("fixture transcript artifact is orphaned")


class SqlFixtureSegmentProvenanceQuery:
    """Read-only authenticated Phase 3F job and transcript provenance queries."""

    __slots__ = ("_engine",)

    def __init__(self, engine: Engine) -> None:
        if not isinstance(engine, Engine):
            raise FixtureSegmentPersistenceError(
                "fixture-segment provenance requires a SQLAlchemy engine"
            )
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise FixtureSegmentPersistenceError(
                f"fixture-segment provenance does not support {engine.dialect.name!r}"
            )
        self._engine = engine

    def get(self, job_id: str) -> FixtureSegmentJobProvenance:
        """Authenticate and return one complete stored provenance chain."""

        if type(job_id) is not str or _SHA256_TEXT.fullmatch(job_id) is None:
            raise FixtureSegmentPersistenceError("fixture provenance job ID must be a SHA-256")
        try:
            with _repeatable_read_transaction(self._engine) as connection:
                projection = _projection(connection, _job(connection, job_id))
                _verify_governance_link(
                    projection,
                    _load_governance_for_read(connection, projection.job.family_id),
                )
                return _provenance(projection)
        except (
            DomainExperimentGovernanceError,
            PersistedExperimentGovernanceError,
        ) as error:
            raise FixtureSegmentPersistenceError(
                "persisted fixture governance is unavailable or malformed"
            ) from error

    def jobs(
        self,
        *,
        limit: int = 50,
        before_job_id: str | None = None,
    ) -> tuple[tuple[FixtureSegmentJobProvenanceSummary, ...], str | None]:
        """Return a deterministic keyset page after authenticating every job."""

        if type(limit) is not int or not 1 <= limit <= MAX_FIXTURE_SEGMENT_PROVENANCE_PAGE_SIZE:
            raise FixtureSegmentPersistenceError(
                "fixture provenance query limit must be between 1 and 100"
            )
        if before_job_id is not None and (
            type(before_job_id) is not str or _SHA256_TEXT.fullmatch(before_job_id) is None
        ):
            raise FixtureSegmentPersistenceError(
                "fixture provenance cursor must be a SHA-256 job ID"
            )
        try:
            with _repeatable_read_transaction(self._engine) as connection:
                anchor: FixtureSegmentJobProjection | None = None
                if before_job_id is not None:
                    anchor = _projection(connection, _job(connection, before_job_id))
                    _verify_governance_link(
                        anchor,
                        _load_governance_for_read(connection, anchor.job.family_id),
                    )

                statement = sa.select(phase3_fixture_segment_jobs.c.job_id).order_by(
                    phase3_fixture_segment_jobs.c.requested_at.desc(),
                    phase3_fixture_segment_jobs.c.job_id,
                )
                if anchor is not None:
                    statement = statement.where(
                        sa.or_(
                            phase3_fixture_segment_jobs.c.requested_at < anchor.job.requested_at,
                            sa.and_(
                                phase3_fixture_segment_jobs.c.requested_at
                                == anchor.job.requested_at,
                                phase3_fixture_segment_jobs.c.job_id > anchor.job.job_id,
                            ),
                        )
                    )
                job_ids = tuple(connection.scalars(statement.limit(limit + 1)))
                governance_by_family: dict[str, ExperimentGovernanceSnapshot] = {}
                summaries: list[FixtureSegmentJobProvenanceSummary] = []
                for index, job_id in enumerate(job_ids):
                    projection = _projection(connection, _job(connection, str(job_id)))
                    governance = governance_by_family.get(projection.job.family_id)
                    if governance is None:
                        governance = _load_governance_for_read(
                            connection,
                            projection.job.family_id,
                        )
                        governance_by_family[projection.job.family_id] = governance
                    _verify_governance_link(projection, governance)
                    if index < limit:
                        summaries.append(_provenance_summary(projection))
                next_before_job_id = (
                    summaries[-1].job_id if len(job_ids) > limit and summaries else None
                )
                return tuple(summaries), next_before_job_id
        except (
            DomainExperimentGovernanceError,
            PersistedExperimentGovernanceError,
        ) as error:
            raise FixtureSegmentPersistenceError(
                "persisted fixture governance is unavailable or malformed"
            ) from error


class SqlFixtureSegmentWorkflow:
    """Own durable fixture-segment scheduling, claims, and atomic publication."""

    __slots__ = ("_engine", "_governance")

    def __init__(self, engine: Engine) -> None:
        if not isinstance(engine, Engine):
            raise FixtureSegmentPersistenceError(
                "fixture-segment persistence requires a SQLAlchemy engine"
            )
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise FixtureSegmentPersistenceError(
                f"fixture-segment persistence does not support {engine.dialect.name!r}"
            )
        self._engine = engine
        self._governance = SqlExperimentGovernance(engine)

    def enqueue(
        self,
        snapshot: ExperimentGovernanceSnapshot,
        attempt_id: str,
        certification: CertifiedFeatureReplay,
        *,
        requested_at: datetime,
        requested_by: str,
    ) -> FixtureSegmentJobProjection:
        try:
            if type(snapshot) is not ExperimentGovernanceSnapshot:
                raise FixtureSegmentPersistenceConflict(
                    "fixture enqueue requires an exact governance snapshot"
                )
            supplied_attempt = _attempt(snapshot, attempt_id)
            family_id = supplied_attempt.family_id
            with _write_transaction(self._engine) as connection:
                existing_job_id = connection.scalar(
                    sa.select(phase3_fixture_segment_jobs.c.job_id).where(
                        phase3_fixture_segment_jobs.c.family_id == family_id,
                        phase3_fixture_segment_jobs.c.attempt_id == attempt_id,
                    )
                )
                if existing_job_id is not None:
                    # Claim/renew/terminal commands take the job head before
                    # governance. Preserve that order so a PostgreSQL retry
                    # cannot observe a pre-claim projection and post-claim
                    # governance snapshot or deadlock with the claimer.
                    existing = self._locked_projection(connection, str(existing_job_id))
                    current = _load_governance(connection, family_id)
                    expected_job, expected_artifact = FixtureSegmentJob._from_original_enqueue(
                        current,
                        attempt_id,
                        certification,
                        requested_at=requested_at,
                        requested_by=requested_by,
                        require_current_queued=False,
                    )
                    if (
                        existing.job != expected_job
                        or existing.feature_artifact != expected_artifact
                    ):
                        raise FixtureSegmentPersistenceConflict(
                            "fixture enqueue retry changed its exact input"
                        )
                    _verify_governance_link(existing, current)
                    return existing

                current = _load_governance(connection, family_id)
                job, artifact = FixtureSegmentJob.from_queued_attempt(
                    current,
                    attempt_id,
                    certification,
                    requested_at=requested_at,
                    requested_by=requested_by,
                )
                proposed = queue_fixture_segment_job(job, artifact)
                insert_or_verify_atomic(
                    connection,
                    phase3_fixture_segment_transcript_artifacts,
                    _artifact_values(artifact),
                )
                insert_or_verify_atomic(
                    connection,
                    phase3_fixture_segment_jobs,
                    _job_values(job),
                )
                insert_or_verify_atomic(
                    connection,
                    phase3_fixture_segment_job_events,
                    _event_values(proposed.latest),
                )
                head = (
                    connection.execute(
                        sa.select(phase3_fixture_segment_job_heads).where(
                            phase3_fixture_segment_job_heads.c.job_id == job.job_id
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if head is None:
                    connection.execute(
                        sa.insert(phase3_fixture_segment_job_heads).values(**_head_values(proposed))
                    )
                else:
                    assert_immutable(
                        phase3_fixture_segment_job_heads,
                        job.job_id,
                        head,
                        _head_values(proposed),
                    )
                persisted = _projection(connection, job)
                _verify_governance_link(persisted, current)
                return persisted
        except (
            ExperimentGovernanceConflict,
            FixtureSegmentWorkerError,
            ImmutableFactConflict,
        ) as error:
            if isinstance(error, FixtureSegmentPersistenceConflict):
                raise
            raise FixtureSegmentPersistenceConflict(str(error)) from error

    def get(self, job_id: str) -> FixtureSegmentJobProjection:
        with _repeatable_read_transaction(self._engine) as connection:
            projection = _projection(connection, _job(connection, job_id))
            _verify_governance_link(
                projection,
                _load_governance(connection, projection.job.family_id),
            )
            return projection

    def claim_next(
        self,
        *,
        worker_id: str,
        claimed_at: datetime,
        claim_expires_at: datetime,
    ) -> FixtureSegmentJobProjection | None:
        try:
            with _write_transaction(self._engine) as connection:
                statement = (
                    sa.select(phase3_fixture_segment_jobs)
                    .join(
                        phase3_fixture_segment_job_heads,
                        phase3_fixture_segment_job_heads.c.job_id
                        == phase3_fixture_segment_jobs.c.job_id,
                    )
                    .where(
                        sa.or_(
                            phase3_fixture_segment_job_heads.c.status
                            == FixtureSegmentJobStatus.QUEUED.value,
                            sa.and_(
                                phase3_fixture_segment_job_heads.c.status
                                == FixtureSegmentJobStatus.RUNNING.value,
                                phase3_fixture_segment_job_heads.c.claim_expires_at < claimed_at,
                            ),
                        )
                    )
                    .order_by(
                        phase3_fixture_segment_jobs.c.requested_at,
                        phase3_fixture_segment_jobs.c.job_id,
                    )
                    .limit(1)
                )
                if connection.dialect.name == "postgresql":
                    statement = statement.with_for_update(
                        of=phase3_fixture_segment_job_heads,
                        skip_locked=True,
                    )
                row = connection.execute(statement).mappings().one_or_none()
                if row is None:
                    return None
                job = _job_from_row(row)
                prior = _projection(connection, job)
                current = _load_governance(connection, job.family_id)
                _assert_job_context(prior, current)
                governance_event = current.latest_event(job.attempt_id)
                if governance_event.status is ExperimentAttemptStatus.QUEUED:
                    running = current.transition_attempt(
                        job.attempt_id,
                        status=ExperimentAttemptStatus.RUNNING,
                        occurred_at=claimed_at,
                        actor_id=job.governed_actor_id,
                    )
                    current = self._governance._persist_in_transaction(
                        connection,
                        running,
                        expected_action="transition_attempt",
                        expected_registry_sha256=current.semantic_sha256,
                        actor_id=job.governed_actor_id,
                        idempotency_key=f"phase3f-running-{job.job_id}",
                        occurred_at=claimed_at,
                    )
                    governance_event = current.latest_event(job.attempt_id)
                elif (
                    governance_event.status is not ExperimentAttemptStatus.RUNNING
                    or governance_event.actor_id != job.governed_actor_id
                    or prior.latest.status is not FixtureSegmentJobStatus.RUNNING
                    or governance_event.semantic_sha256 != prior.latest.governance_event_sha256
                ):
                    raise FixtureSegmentPersistenceConflict(
                        "claim cannot recover a foreign or terminal governed attempt"
                    )
                updated = claim_fixture_segment_job(
                    prior,
                    worker_id=worker_id,
                    claimed_at=claimed_at,
                    claim_expires_at=claim_expires_at,
                    governance_running_event_sha256=governance_event.semantic_sha256,
                )
                self._append_and_advance(connection, prior, updated)
                return updated
        except (
            ExperimentGovernanceConflict,
            FixtureSegmentWorkerError,
            ImmutableFactConflict,
        ) as error:
            if isinstance(error, FixtureSegmentPersistenceConflict):
                raise
            raise FixtureSegmentPersistenceConflict(str(error)) from error

    def renew_claim(
        self,
        job_id: str,
        token: FixtureSegmentClaimToken,
        *,
        renewed_at: datetime,
        claim_expires_at: datetime,
    ) -> FixtureSegmentJobProjection:
        try:
            with _write_transaction(self._engine) as connection:
                prior = self._locked_projection(connection, job_id)
                current = _load_governance(connection, prior.job.family_id)
                _verify_governance_link(prior, current)
                updated = renew_fixture_segment_claim(
                    prior,
                    token,
                    renewed_at=renewed_at,
                    claim_expires_at=claim_expires_at,
                )
                self._append_and_advance(connection, prior, updated)
                return updated
        except (FixtureSegmentWorkerError, ImmutableFactConflict) as error:
            raise FixtureSegmentPersistenceConflict(str(error)) from error

    def complete(
        self,
        job_id: str,
        token: FixtureSegmentClaimToken,
        certification: CertifiedFeatureTargetReplay,
        *,
        completed_at: datetime,
    ) -> FixtureSegmentJobProjection:
        if type(certification) is not CertifiedFeatureTargetReplay:
            raise FixtureSegmentPersistenceError(
                "fixture completion requires exact certified target evidence"
            )
        try:
            with _write_transaction(self._engine) as connection:
                prior = self._locked_projection(connection, job_id)
                current = _load_governance(connection, prior.job.family_id)
                _assert_job_context(prior, current)
                attempt = _attempt(current, prior.job.attempt_id)
                source_evidence = segment_evidence_for_attempt(current, attempt)
                target_artifact = FixtureTranscriptArtifact.from_target_certification(
                    family=current.family,
                    attempt=attempt,
                    source_evidence=source_evidence,
                    certification=certification,
                )
                if prior.status is FixtureSegmentJobStatus.COMPLETED:
                    existing_token = _current_claim_from_terminal(prior)
                    latest = current.latest_event(prior.job.attempt_id)
                    if (
                        token != existing_token
                        or prior.target_artifact != target_artifact
                        or latest.status is not ExperimentAttemptStatus.COMPLETED
                        or latest.occurred_at != completed_at
                        or latest.semantic_sha256 != prior.latest.governance_event_sha256
                    ):
                        raise FixtureSegmentPersistenceConflict(
                            "completed fixture retry changed its exact input"
                        )
                    return prior
                _verify_governance_link(prior, current)
                proposed = current.complete_attempt(
                    prior.job.attempt_id,
                    certification,
                    completed_at=completed_at,
                    actor_id=prior.job.governed_actor_id,
                )
                completed_event = proposed.latest_event(prior.job.attempt_id)
                receipt = completed_event.terminal_evidence
                if type(receipt) is not GovernedSegmentEvaluationReceipt:
                    raise FixtureSegmentPersistenceConflict(
                        "governed completion did not produce an exact receipt"
                    )
                updated = complete_fixture_segment_job(
                    prior,
                    token,
                    target_artifact=target_artifact,
                    receipt=receipt,
                    governance_completed_event=completed_event,
                    completed_at=completed_at,
                )
                insert_or_verify_atomic(
                    connection,
                    phase3_fixture_segment_transcript_artifacts,
                    _artifact_values(target_artifact),
                )
                self._governance._persist_in_transaction(
                    connection,
                    proposed,
                    expected_action="transition_attempt",
                    expected_registry_sha256=current.semantic_sha256,
                    actor_id=prior.job.governed_actor_id,
                    idempotency_key=f"phase3f-complete-{prior.job.job_id}",
                    occurred_at=completed_at,
                    certification=certification,
                )
                self._append_and_advance(connection, prior, updated)
                return updated
        except (
            ExperimentGovernanceConflict,
            FixtureSegmentWorkerError,
            ImmutableFactConflict,
        ) as error:
            if isinstance(error, FixtureSegmentPersistenceConflict):
                raise
            raise FixtureSegmentPersistenceConflict(str(error)) from error

    def fail(
        self,
        job_id: str,
        token: FixtureSegmentClaimToken,
        *,
        failed_at: datetime,
        reason_code: str,
        reason_sha256: str,
    ) -> FixtureSegmentJobProjection:
        try:
            with _write_transaction(self._engine) as connection:
                prior = self._locked_projection(connection, job_id)
                current = _load_governance(connection, prior.job.family_id)
                if prior.status is FixtureSegmentJobStatus.FAILED:
                    _verify_governance_link(prior, current)
                    if (
                        token != _current_claim_from_terminal(prior)
                        or prior.latest.occurred_at != failed_at
                        or prior.latest.terminal_reason_code != reason_code
                        or prior.latest.terminal_reason_sha256 != reason_sha256
                    ):
                        raise FixtureSegmentPersistenceConflict(
                            "failed fixture retry changed its exact classification"
                        )
                    return prior
                _verify_governance_link(prior, current)
                attempt = _attempt(current, prior.job.attempt_id)
                terminal_evidence = fixture_segment_failure_evidence(attempt)
                proposed = current.transition_attempt(
                    prior.job.attempt_id,
                    status=ExperimentAttemptStatus.FAILED,
                    occurred_at=failed_at,
                    actor_id=prior.job.governed_actor_id,
                    terminal_evidence=terminal_evidence,
                )
                failed_event = proposed.latest_event(prior.job.attempt_id)
                updated = fail_fixture_segment_job(
                    prior,
                    token,
                    governance_failed_event=failed_event,
                    failed_at=failed_at,
                    reason_code=reason_code,
                    reason_sha256=reason_sha256,
                )
                self._governance._persist_in_transaction(
                    connection,
                    proposed,
                    expected_action="transition_attempt",
                    expected_registry_sha256=current.semantic_sha256,
                    actor_id=prior.job.governed_actor_id,
                    idempotency_key=f"phase3f-failed-{prior.job.job_id}",
                    occurred_at=failed_at,
                )
                self._append_and_advance(connection, prior, updated)
                return updated
        except (
            ExperimentGovernanceConflict,
            FixtureSegmentWorkerError,
            ImmutableFactConflict,
        ) as error:
            if isinstance(error, FixtureSegmentPersistenceConflict):
                raise
            raise FixtureSegmentPersistenceConflict(str(error)) from error

    def governance_snapshot(self, family_id: str) -> ExperimentGovernanceSnapshot:
        return self._governance.get(family_id)

    def _locked_projection(
        self,
        connection: Connection,
        job_id: str,
    ) -> FixtureSegmentJobProjection:
        statement = _job_head_statement(
            job_id,
            lock=connection.dialect.name == "postgresql",
        )
        connection.execute(statement).mappings().one_or_none()
        return _projection(connection, _job(connection, job_id))

    def _append_and_advance(
        self,
        connection: Connection,
        prior: FixtureSegmentJobProjection,
        updated: FixtureSegmentJobProjection,
    ) -> None:
        if updated.events[:-1] != prior.events:
            raise FixtureSegmentPersistenceConflict(
                "fixture job transition does not extend its persisted chain"
            )
        event = updated.latest
        insert_or_verify_atomic(
            connection,
            phase3_fixture_segment_job_events,
            _event_values(event),
        )
        values = _head_values(updated)
        result = connection.execute(
            sa.update(phase3_fixture_segment_job_heads)
            .where(
                phase3_fixture_segment_job_heads.c.job_id == prior.job.job_id,
                phase3_fixture_segment_job_heads.c.latest_sequence_number == prior.latest.sequence,
                phase3_fixture_segment_job_heads.c.latest_event_sha256 == prior.latest.event_sha256,
            )
            .values(**{key: value for key, value in values.items() if key != "job_id"})
        )
        if result.rowcount != 1:
            raise FixtureSegmentPersistenceConflict("fixture job head changed concurrently")
        persisted = (
            connection.execute(
                sa.select(phase3_fixture_segment_job_heads).where(
                    phase3_fixture_segment_job_heads.c.job_id == prior.job.job_id
                )
            )
            .mappings()
            .one()
        )
        assert_immutable(
            phase3_fixture_segment_job_heads,
            prior.job.job_id,
            persisted,
            values,
        )


__all__ = [
    "FIXTURE_SEGMENT_WORKER_CONTRACT_VERSION",
    "MAX_FIXTURE_SEGMENT_PROVENANCE_PAGE_SIZE",
    "FixtureSegmentEventProvenance",
    "FixtureSegmentJobProvenance",
    "FixtureSegmentJobProvenanceSummary",
    "FixtureSegmentNotFound",
    "FixtureSegmentPersistenceConflict",
    "FixtureSegmentPersistenceError",
    "FixtureTranscriptProvenance",
    "SqlFixtureSegmentProvenanceQuery",
    "SqlFixtureSegmentWorkflow",
]
