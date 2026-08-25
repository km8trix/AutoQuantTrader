"""Transactional persistence for the bounded Phase 3F fixture-segment worker."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, cast

import sqlalchemy as sa
from sqlalchemy import Connection, Engine
from sqlalchemy.engine import RowMapping

from packages.domain.experiment_governance import (
    ExperimentAttempt,
    ExperimentAttemptStatus,
    ExperimentGovernanceSnapshot,
    GovernedSegmentEvaluationReceipt,
    NonExecutableTerminalEvidence,
)
from packages.domain.experiment_registry import EvaluationSegmentKind
from packages.domain.feature import CertifiedFeatureReplay
from packages.domain.feature_target import CertifiedFeatureTargetReplay
from packages.domain.fixture_segment_worker import (
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


class FixtureSegmentPersistenceError(RuntimeError):
    """Persisted fixture-segment work is unavailable or malformed."""


class FixtureSegmentPersistenceConflict(FixtureSegmentPersistenceError):
    """A fixture-segment command conflicts with immutable or current state."""


class FixtureSegmentNotFound(FixtureSegmentPersistenceError):
    """A fixture-segment job does not exist."""


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


def _load_governance(connection: Connection, family_id: str) -> ExperimentGovernanceSnapshot:
    history = _load_snapshot_history(connection, family_id, lock=True)
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
) -> None:
    job = projection.job
    attempt = _attempt(snapshot, job.attempt_id)
    try:
        source_evidence = segment_evidence_for_attempt(snapshot, attempt)
    except ValueError as error:
        raise FixtureSegmentPersistenceConflict(
            "fixture job cannot resolve exact opened segment evidence"
        ) from error
    if (
        attempt.family_id != job.family_id
        or attempt.configuration.semantic_sha256 != job.configuration_sha256
        or attempt.configuration_validation.semantic_sha256 != job.configuration_validation_sha256
        or attempt.segment_kind is not job.segment_kind
        or attempt.segment_sha256 != job.segment_sha256
        or source_evidence.semantic_sha256 != job.source_evidence_sha256
        or source_evidence.feature_certification_sha256 != job.feature_certification_sha256
        or projection.feature_artifact.certification_sha256 != job.feature_certification_sha256
    ):
        raise FixtureSegmentPersistenceConflict(
            "fixture job changed attempt, configuration, segment, or feature identity"
        )


def _verify_governance_link(
    projection: FixtureSegmentJobProjection,
    snapshot: ExperimentGovernanceSnapshot,
) -> None:
    _assert_job_context(projection, snapshot)
    latest = snapshot.latest_event(projection.job.attempt_id)
    job_event = projection.latest
    if latest.semantic_sha256 != job_event.governance_event_sha256:
        raise FixtureSegmentPersistenceError(
            "fixture job head diverges from governed attempt history"
        )
    expected_status = {
        FixtureSegmentJobStatus.QUEUED: ExperimentAttemptStatus.QUEUED,
        FixtureSegmentJobStatus.RUNNING: ExperimentAttemptStatus.RUNNING,
        FixtureSegmentJobStatus.COMPLETED: ExperimentAttemptStatus.COMPLETED,
        FixtureSegmentJobStatus.FAILED: ExperimentAttemptStatus.FAILED,
    }[job_event.status]
    if latest.status is not expected_status:
        raise FixtureSegmentPersistenceError("fixture and governance terminal states disagree")
    if latest.status is ExperimentAttemptStatus.RUNNING and (
        latest.actor_id != projection.job.governed_actor_id
    ):
        raise FixtureSegmentPersistenceError("governed running actor changed fixture authority")
    if latest.status is ExperimentAttemptStatus.COMPLETED and (
        type(latest.terminal_evidence) is not GovernedSegmentEvaluationReceipt
        or latest.terminal_evidence.semantic_sha256 != job_event.completion_receipt_sha256
    ):
        raise FixtureSegmentPersistenceError("fixture completion receipt is inconsistent")


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
            job, artifact = FixtureSegmentJob.from_queued_attempt(
                snapshot,
                attempt_id,
                certification,
                requested_at=requested_at,
                requested_by=requested_by,
            )
            proposed = queue_fixture_segment_job(job, artifact)
            with _write_transaction(self._engine) as connection:
                existing_row = (
                    connection.execute(
                        sa.select(phase3_fixture_segment_jobs).where(
                            phase3_fixture_segment_jobs.c.job_id == job.job_id
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if existing_row is not None:
                    existing_job = _job_from_row(existing_row)
                    existing = _projection(connection, existing_job)
                    if existing_job != job or existing.feature_artifact != artifact:
                        raise FixtureSegmentPersistenceConflict(
                            "fixture enqueue retry changed its exact input"
                        )
                    _verify_governance_link(
                        existing,
                        _load_governance(connection, job.family_id),
                    )
                    return existing
                current = _load_governance(connection, job.family_id)
                exact_job, exact_artifact = FixtureSegmentJob.from_queued_attempt(
                    current,
                    attempt_id,
                    certification,
                    requested_at=requested_at,
                    requested_by=requested_by,
                )
                if exact_job != job or exact_artifact != artifact:
                    raise FixtureSegmentPersistenceConflict(
                        "enqueue changed the exact governed fixture input"
                    )
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
                terminal_evidence = NonExecutableTerminalEvidence.unsuccessful(
                    attempt,
                    status=ExperimentAttemptStatus.FAILED,
                    reason_code=reason_code,
                    detail=(
                        "Bounded fixture-segment evaluation failed; raw exception text was not "
                        "retained."
                    ),
                )
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
        statement = sa.select(phase3_fixture_segment_job_heads).where(
            phase3_fixture_segment_job_heads.c.job_id == job_id
        )
        if connection.dialect.name == "postgresql":
            statement = statement.with_for_update()
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
    "FixtureSegmentNotFound",
    "FixtureSegmentPersistenceConflict",
    "FixtureSegmentPersistenceError",
    "SqlFixtureSegmentWorkflow",
]
