"""Read-only HTTP projections for authenticated Phase 3F provenance."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from datetime import UTC, datetime
from itertools import islice, pairwise
from typing import Annotated, Protocol

from fastapi import APIRouter, HTTPException, Path, Query, status
from sqlalchemy.exc import SQLAlchemyError

from apps.api.contracts import (
    ApiErrorResponse,
    FixtureSegmentEventProvenanceView,
    FixtureSegmentJobListResponse,
    FixtureSegmentJobProvenanceView,
    FixtureSegmentJobResponse,
    FixtureSegmentJobSummaryView,
    FixtureTranscriptProvenanceView,
)
from packages.domain.experiment_registry import EvaluationSegmentKind
from packages.domain.fixture_segment_worker import (
    FixtureSegmentJobStatus,
    FixtureTranscriptKind,
)
from packages.persistence.experiment_governance import ExperimentGovernanceError
from packages.persistence.fixture_segment_worker import (
    FixtureSegmentEventProvenance,
    FixtureSegmentJobProvenance,
    FixtureSegmentJobProvenanceSummary,
    FixtureSegmentNotFound,
    FixtureSegmentPersistenceError,
    FixtureTranscriptProvenance,
)

logger = logging.getLogger(__name__)
_SHA256_TEXT = re.compile(r"^[0-9a-f]{64}$")
_MAX_STORED_EVENTS = 10_000


class FixtureSegmentProvenanceQuery(Protocol):
    """Minimal query-only boundary exposed to the API composition root."""

    def get(self, job_id: str) -> FixtureSegmentJobProvenance: ...

    def jobs(
        self,
        *,
        limit: int = 50,
        before_job_id: str | None = None,
    ) -> tuple[tuple[FixtureSegmentJobProvenanceSummary, ...], str | None]: ...


class _FixtureSegmentEventCursorNotFound(ValueError):
    """An event cursor does not belong to the authenticated job chain."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_TEXT.fullmatch(value) is not None


def _is_optional_sha256(value: object) -> bool:
    return value is None or _is_sha256(value)


def _is_utc(value: object) -> bool:
    return (
        type(value) is datetime
        and value.tzinfo is not None
        and value.utcoffset() is not None
        and value.utcoffset() == UTC.utcoffset(value)
    )


def _require_artifact_projection(
    artifact: FixtureTranscriptProvenance,
    *,
    kind: FixtureTranscriptKind,
    family_id: str,
    attempt_id: str,
    segment_kind: EvaluationSegmentKind,
    configuration_sha256: str | None,
) -> None:
    if (
        type(artifact) is not FixtureTranscriptProvenance
        or artifact.kind is not kind
        or artifact.family_id != family_id
        or artifact.attempt_id != attempt_id
        or artifact.segment_kind is not segment_kind
        or artifact.configuration_sha256 != configuration_sha256
        or not all(
            _is_sha256(value)
            for value in (
                artifact.artifact_sha256,
                artifact.family_id,
                artifact.attempt_id,
                artifact.certification_sha256,
                artifact.parity_receipt_sha256,
                artifact.transcript_sha256,
                artifact.transcript_payload_sha256,
                artifact.semantic_sha256,
            )
        )
        or artifact.semantic_sha256 != artifact.artifact_sha256
        or type(artifact.step_count) is not int
        or not 1 <= artifact.step_count <= 100_000
        or type(artifact.output_count) is not int
        or not 0 <= artifact.output_count <= 5_000_000
    ):
        raise TypeError("fixture provenance returned malformed artifact proof metadata")


def _require_summary_projection(
    summary: FixtureSegmentJobProvenanceSummary,
) -> None:
    if (
        type(summary) is not FixtureSegmentJobProvenanceSummary
        or not all(
            _is_sha256(value)
            for value in (
                summary.job_id,
                summary.family_id,
                summary.attempt_id,
                summary.configuration_sha256,
                summary.latest_event_sha256,
                summary.feature_artifact_sha256,
            )
        )
        or not _is_optional_sha256(summary.target_artifact_sha256)
        or not _is_optional_sha256(summary.completion_receipt_sha256)
        or type(summary.segment_kind) is not EvaluationSegmentKind
        or type(summary.status) is not FixtureSegmentJobStatus
        or not _is_utc(summary.requested_at)
        or not _is_utc(summary.latest_occurred_at)
        or type(summary.event_count) is not int
        or not 1 <= summary.event_count <= _MAX_STORED_EVENTS
        or type(summary.latest_sequence) is not int
        or summary.latest_sequence != summary.event_count - 1
        or (
            summary.status is FixtureSegmentJobStatus.QUEUED
            and (summary.event_count != 1 or summary.latest_occurred_at != summary.requested_at)
        )
        or (
            summary.status is not FixtureSegmentJobStatus.QUEUED
            and summary.latest_occurred_at <= summary.requested_at
        )
        or (summary.status is FixtureSegmentJobStatus.RUNNING and summary.event_count < 2)
        or (
            summary.status in {FixtureSegmentJobStatus.COMPLETED, FixtureSegmentJobStatus.FAILED}
            and summary.event_count < 3
        )
        or (
            summary.status is FixtureSegmentJobStatus.COMPLETED
            and (
                summary.target_artifact_sha256 is None or summary.completion_receipt_sha256 is None
            )
        )
        or (
            summary.status is not FixtureSegmentJobStatus.COMPLETED
            and (
                summary.target_artifact_sha256 is not None
                or summary.completion_receipt_sha256 is not None
            )
        )
    ):
        raise TypeError("fixture provenance query returned malformed immutable summary")


def _require_summary_page(
    jobs: tuple[FixtureSegmentJobProvenanceSummary, ...],
    *,
    limit: int,
    before_job_id: str | None,
    next_before_job_id: str | None,
) -> None:
    if (
        type(jobs) is not tuple
        or len(jobs) > limit
        or any(type(job) is not FixtureSegmentJobProvenanceSummary for job in jobs)
        or not _is_optional_sha256(before_job_id)
        or (
            next_before_job_id is not None
            and (
                not _is_sha256(next_before_job_id)
                or len(jobs) != limit
                or not jobs
                or jobs[-1].job_id != next_before_job_id
            )
        )
    ):
        raise TypeError("fixture provenance query must return immutable jobs")
    for job in jobs:
        _require_summary_projection(job)
    job_ids = tuple(job.job_id for job in jobs)
    if len(set(job_ids)) != len(job_ids) or (
        before_job_id is not None and before_job_id in job_ids
    ):
        raise TypeError("fixture provenance summary identities are inconsistent")
    for previous, current in pairwise(jobs):
        if current.requested_at > previous.requested_at or (
            current.requested_at == previous.requested_at and current.job_id <= previous.job_id
        ):
            raise TypeError("fixture provenance summary order is inconsistent")


def _require_detail_projection(provenance: FixtureSegmentJobProvenance) -> None:
    if (
        type(provenance) is not FixtureSegmentJobProvenance
        or not all(
            _is_sha256(value)
            for value in (
                provenance.job_id,
                provenance.family_id,
                provenance.attempt_id,
                provenance.configuration_sha256,
                provenance.configuration_validation_sha256,
                provenance.queued_governance_event_sha256,
                provenance.feature_certification_sha256,
            )
        )
        or type(provenance.segment_kind) is not EvaluationSegmentKind
        or not _is_utc(provenance.requested_at)
        or type(provenance.events) is not tuple
        or not 1 <= len(provenance.events) <= _MAX_STORED_EVENTS
        or any(type(event) is not FixtureSegmentEventProvenance for event in provenance.events)
        or (
            provenance.target_artifact is not None
            and type(provenance.target_artifact) is not FixtureTranscriptProvenance
        )
    ):
        raise TypeError("fixture provenance query returned malformed immutable detail")
    _require_artifact_projection(
        provenance.feature_artifact,
        kind=FixtureTranscriptKind.FEATURE,
        family_id=provenance.family_id,
        attempt_id=provenance.attempt_id,
        segment_kind=provenance.segment_kind,
        configuration_sha256=None,
    )
    if provenance.feature_artifact.certification_sha256 != provenance.feature_certification_sha256:
        raise TypeError("fixture provenance feature certification changed")
    event_sha256s = tuple(event.event_sha256 for event in provenance.events)
    if any(not _is_sha256(event_sha256) for event_sha256 in event_sha256s) or len(
        set(event_sha256s)
    ) != len(event_sha256s):
        raise TypeError("fixture provenance event identities are inconsistent")

    previous: FixtureSegmentEventProvenance | None = None
    running_governance_sha256: str | None = None
    for sequence, event in enumerate(provenance.events):
        if (
            event.sequence != sequence
            or type(event.sequence) is not int
            or not _is_sha256(event.job_id)
            or event.job_id != provenance.job_id
            or not _is_sha256(event.event_sha256)
            or not _is_optional_sha256(event.previous_event_sha256)
            or not _is_sha256(event.governance_event_sha256)
            or not _is_sha256(event.feature_artifact_sha256)
            or not _is_optional_sha256(event.target_artifact_sha256)
            or not _is_optional_sha256(event.completion_receipt_sha256)
            or type(event.status) is not FixtureSegmentJobStatus
            or not _is_utc(event.occurred_at)
            or type(event.attempt_number) is not int
            or not 0 <= event.attempt_number <= 9_999
            or event.feature_artifact_sha256 != provenance.feature_artifact.artifact_sha256
            or (event.claim_expires_at is not None and not _is_utc(event.claim_expires_at))
        ):
            raise TypeError("fixture provenance event proof metadata is malformed")
        if previous is None:
            if (
                event.status is not FixtureSegmentJobStatus.QUEUED
                or event.occurred_at != provenance.requested_at
                or event.attempt_number != 0
                or event.previous_event_sha256 is not None
                or event.claim_expires_at is not None
                or event.governance_event_sha256 != provenance.queued_governance_event_sha256
                or event.target_artifact_sha256 is not None
                or event.completion_receipt_sha256 is not None
            ):
                raise TypeError("fixture provenance queued event is inconsistent")
            previous = event
            continue
        if (
            event.previous_event_sha256 != previous.event_sha256
            or event.occurred_at <= previous.occurred_at
        ):
            raise TypeError("fixture provenance event order is inconsistent")
        if event.status is FixtureSegmentJobStatus.RUNNING:
            if (
                previous.status
                not in {FixtureSegmentJobStatus.QUEUED, FixtureSegmentJobStatus.RUNNING}
                or event.claim_expires_at is None
                or event.claim_expires_at <= event.occurred_at
                or event.target_artifact_sha256 is not None
                or event.completion_receipt_sha256 is not None
            ):
                raise TypeError("fixture provenance running event is inconsistent")
            if previous.status is FixtureSegmentJobStatus.QUEUED:
                if (
                    event.attempt_number != 1
                    or event.governance_event_sha256 == provenance.queued_governance_event_sha256
                ):
                    raise TypeError("fixture provenance first claim is inconsistent")
                running_governance_sha256 = event.governance_event_sha256
            else:
                assert previous.claim_expires_at is not None
                if event.attempt_number == previous.attempt_number:
                    if (
                        event.occurred_at > previous.claim_expires_at
                        or event.claim_expires_at <= previous.claim_expires_at
                    ):
                        raise TypeError("fixture provenance renewal is inconsistent")
                elif (
                    event.attempt_number != previous.attempt_number + 1
                    or event.occurred_at <= previous.claim_expires_at
                ):
                    raise TypeError("fixture provenance takeover is inconsistent")
            if event.governance_event_sha256 != running_governance_sha256:
                raise TypeError("fixture provenance running governance link changed")
        else:
            if (
                sequence != len(provenance.events) - 1
                or event.status
                not in {FixtureSegmentJobStatus.COMPLETED, FixtureSegmentJobStatus.FAILED}
                or previous.status is not FixtureSegmentJobStatus.RUNNING
                or previous.claim_expires_at is None
                or event.occurred_at > previous.claim_expires_at
                or event.attempt_number != previous.attempt_number
                or event.claim_expires_at is not None
                or event.governance_event_sha256
                in {
                    provenance.queued_governance_event_sha256,
                    running_governance_sha256,
                }
            ):
                raise TypeError("fixture provenance terminal event is inconsistent")
            if event.status is FixtureSegmentJobStatus.COMPLETED:
                if (
                    provenance.target_artifact is None
                    or event.target_artifact_sha256 != provenance.target_artifact.artifact_sha256
                    or event.completion_receipt_sha256 is None
                ):
                    raise TypeError("fixture provenance completion is inconsistent")
            elif (
                event.target_artifact_sha256 is not None
                or event.completion_receipt_sha256 is not None
            ):
                raise TypeError("fixture provenance failure is inconsistent")
        previous = event

    latest = provenance.events[-1]
    if latest.status is FixtureSegmentJobStatus.COMPLETED:
        assert provenance.target_artifact is not None
        _require_artifact_projection(
            provenance.target_artifact,
            kind=FixtureTranscriptKind.TARGET,
            family_id=provenance.family_id,
            attempt_id=provenance.attempt_id,
            segment_kind=provenance.segment_kind,
            configuration_sha256=provenance.configuration_sha256,
        )
    elif provenance.target_artifact is not None:
        raise TypeError("non-completed fixture provenance retained a target artifact")


def _artifact_view(
    artifact: FixtureTranscriptProvenance,
) -> FixtureTranscriptProvenanceView:
    if type(artifact) is not FixtureTranscriptProvenance:
        raise TypeError("fixture provenance returned an unexpected artifact type")
    return FixtureTranscriptProvenanceView(
        kind=artifact.kind,
        family_id=artifact.family_id,
        attempt_id=artifact.attempt_id,
        segment_kind=artifact.segment_kind,
        configuration_sha256=artifact.configuration_sha256,
        certification_sha256=artifact.certification_sha256,
        parity_receipt_sha256=artifact.parity_receipt_sha256,
        transcript_sha256=artifact.transcript_sha256,
        step_count=artifact.step_count,
        output_count=artifact.output_count,
    )


def fixture_segment_summary_view(
    provenance: FixtureSegmentJobProvenance | FixtureSegmentJobProvenanceSummary,
) -> FixtureSegmentJobSummaryView:
    """Project the fixed allowlist used by bounded job listings."""

    if type(provenance) is FixtureSegmentJobProvenanceSummary:
        _require_summary_projection(provenance)
        return FixtureSegmentJobSummaryView(
            job_id=provenance.job_id,
            family_id=provenance.family_id,
            attempt_id=provenance.attempt_id,
            configuration_sha256=provenance.configuration_sha256,
            segment_kind=provenance.segment_kind,
            requested_at=provenance.requested_at,
            status=provenance.status,
            event_count=provenance.event_count,
            latest_sequence=provenance.latest_sequence,
            latest_occurred_at=provenance.latest_occurred_at,
            completion_receipt_sha256=provenance.completion_receipt_sha256,
        )
    if type(provenance) is not FixtureSegmentJobProvenance:
        raise TypeError("fixture provenance query returned an unexpected job type")
    _require_detail_projection(provenance)
    latest = provenance.latest
    return FixtureSegmentJobSummaryView(
        job_id=provenance.job_id,
        family_id=provenance.family_id,
        attempt_id=provenance.attempt_id,
        configuration_sha256=provenance.configuration_sha256,
        segment_kind=provenance.segment_kind,
        requested_at=provenance.requested_at,
        status=provenance.status,
        event_count=len(provenance.events),
        latest_sequence=latest.sequence,
        latest_occurred_at=latest.occurred_at,
        completion_receipt_sha256=latest.completion_receipt_sha256,
    )


def _event_view(
    event: FixtureSegmentEventProvenance,
) -> FixtureSegmentEventProvenanceView:
    if type(event) is not FixtureSegmentEventProvenance:
        raise TypeError("fixture provenance returned an unexpected event type")
    return FixtureSegmentEventProvenanceView(
        sequence=event.sequence,
        status=event.status,
        occurred_at=event.occurred_at,
        attempt_number=event.attempt_number,
        claim_expires_at=event.claim_expires_at,
        governance_event_sha256=event.governance_event_sha256,
        completion_receipt_sha256=event.completion_receipt_sha256,
    )


def fixture_segment_provenance_view(
    provenance: FixtureSegmentJobProvenance,
    *,
    event_limit: int,
    before_sequence: int | None,
) -> FixtureSegmentJobProvenanceView:
    """Project one bounded reverse-chronological event page from a verified chain."""

    if type(provenance) is not FixtureSegmentJobProvenance:
        raise TypeError("fixture provenance query returned an unexpected job type")
    _require_detail_projection(provenance)
    if type(event_limit) is not int or not 1 <= event_limit <= 100:
        raise ValueError("fixture provenance event limit must be between 1 and 100")
    if before_sequence is not None and (
        type(before_sequence) is not int
        or before_sequence <= 0
        or not any(event.sequence == before_sequence for event in provenance.events)
    ):
        raise _FixtureSegmentEventCursorNotFound

    candidates = (
        event
        for event in reversed(provenance.events)
        if before_sequence is None or event.sequence < before_sequence
    )
    window = tuple(islice(candidates, event_limit + 1))
    page = window[:event_limit]
    next_before_sequence = page[-1].sequence if len(window) > event_limit and page else None
    return FixtureSegmentJobProvenanceView(
        summary=fixture_segment_summary_view(provenance),
        configuration_validation_sha256=provenance.configuration_validation_sha256,
        queued_governance_event_sha256=provenance.queued_governance_event_sha256,
        feature_certification_sha256=provenance.feature_certification_sha256,
        feature_artifact=_artifact_view(provenance.feature_artifact),
        target_artifact=(
            None
            if provenance.target_artifact is None
            else _artifact_view(provenance.target_artifact)
        ),
        total_event_count=len(provenance.events),
        events=[_event_view(event) for event in page],
        next_before_sequence=next_before_sequence,
    )


def _unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="durable fixture-segment provenance is unavailable or malformed",
    )


def _not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="fixture-segment provenance was not found",
    )


def _require_repository(
    repository: FixtureSegmentProvenanceQuery | None,
    persistence_ready: Callable[[], bool],
) -> FixtureSegmentProvenanceQuery:
    if repository is None or not persistence_ready():
        raise _unavailable()
    return repository


def create_fixture_segment_router(
    *,
    repository: FixtureSegmentProvenanceQuery | None,
    persistence_ready: Callable[[], bool],
) -> APIRouter:
    """Build GET-only, bounded fixture provenance routes."""

    router = APIRouter(prefix="/research/fixture-segment-jobs")

    @router.get(
        "",
        response_model=FixtureSegmentJobListResponse,
        responses={
            status.HTTP_404_NOT_FOUND: {
                "model": ApiErrorResponse,
                "description": "Fixture provenance cursor not found.",
            },
            status.HTTP_503_SERVICE_UNAVAILABLE: {
                "model": ApiErrorResponse,
                "description": "Durable fixture provenance is unavailable.",
            },
        },
        tags=["research"],
    )
    def fixture_segment_jobs(
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        before_job_id: Annotated[
            str | None,
            Query(pattern=r"^[0-9a-f]{64}$"),
        ] = None,
    ) -> FixtureSegmentJobListResponse:
        resolved = _require_repository(repository, persistence_ready)
        queried_at = datetime.now(UTC)
        try:
            jobs, next_before_job_id = resolved.jobs(
                limit=limit,
                before_job_id=before_job_id,
            )
            _require_summary_page(
                jobs,
                limit=limit,
                before_job_id=before_job_id,
                next_before_job_id=next_before_job_id,
            )
            return FixtureSegmentJobListResponse(
                as_of=queried_at,
                jobs=[fixture_segment_summary_view(job) for job in jobs],
                next_before_job_id=next_before_job_id,
            )
        except FixtureSegmentNotFound as error:
            raise _not_found() from error
        except (
            SQLAlchemyError,
            ExperimentGovernanceError,
            FixtureSegmentPersistenceError,
            ValueError,
            TypeError,
            AttributeError,
            IndexError,
        ) as error:
            logger.exception("fixture-segment provenance list read failed")
            raise _unavailable() from error

    @router.get(
        "/{job_id}",
        response_model=FixtureSegmentJobResponse,
        responses={
            status.HTTP_404_NOT_FOUND: {
                "model": ApiErrorResponse,
                "description": "Fixture provenance or event cursor not found.",
            },
            status.HTTP_503_SERVICE_UNAVAILABLE: {
                "model": ApiErrorResponse,
                "description": "Durable fixture provenance is unavailable.",
            },
        },
        tags=["research"],
    )
    def fixture_segment_job(
        job_id: Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")],
        event_limit: Annotated[int, Query(ge=1, le=100)] = 100,
        before_sequence: Annotated[int | None, Query(ge=1, le=9_999)] = None,
    ) -> FixtureSegmentJobResponse:
        resolved = _require_repository(repository, persistence_ready)
        queried_at = datetime.now(UTC)
        try:
            provenance = resolved.get(job_id)
            if provenance.job_id != job_id:
                raise TypeError("fixture provenance query returned a different job")
            return FixtureSegmentJobResponse(
                as_of=queried_at,
                job=fixture_segment_provenance_view(
                    provenance,
                    event_limit=event_limit,
                    before_sequence=before_sequence,
                ),
            )
        except (FixtureSegmentNotFound, _FixtureSegmentEventCursorNotFound) as error:
            raise _not_found() from error
        except (
            SQLAlchemyError,
            ExperimentGovernanceError,
            FixtureSegmentPersistenceError,
            ValueError,
            TypeError,
            AttributeError,
            IndexError,
        ) as error:
            logger.exception("fixture-segment provenance detail read failed")
            raise _unavailable() from error

    return router


__all__ = [
    "FixtureSegmentProvenanceQuery",
    "create_fixture_segment_router",
    "fixture_segment_provenance_view",
    "fixture_segment_summary_view",
]
