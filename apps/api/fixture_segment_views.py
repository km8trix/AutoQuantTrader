"""Read-only HTTP projections for authenticated Phase 3F provenance."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from itertools import islice
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
from packages.persistence.fixture_segment_worker import (
    FixtureSegmentEventProvenance,
    FixtureSegmentJobProvenance,
    FixtureSegmentJobProvenanceSummary,
    FixtureSegmentNotFound,
    FixtureSegmentPersistenceError,
    FixtureTranscriptProvenance,
)

logger = logging.getLogger(__name__)


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


def _artifact_view(
    artifact: FixtureTranscriptProvenance,
) -> FixtureTranscriptProvenanceView:
    if type(artifact) is not FixtureTranscriptProvenance:
        raise TypeError("fixture provenance returned an unexpected artifact type")
    return FixtureTranscriptProvenanceView(
        artifact_sha256=artifact.artifact_sha256,
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
        transcript_payload_sha256=artifact.transcript_payload_sha256,
        semantic_sha256=artifact.semantic_sha256,
    )


def fixture_segment_summary_view(
    provenance: FixtureSegmentJobProvenance | FixtureSegmentJobProvenanceSummary,
) -> FixtureSegmentJobSummaryView:
    """Project the fixed allowlist used by bounded job listings."""

    if type(provenance) is FixtureSegmentJobProvenanceSummary:
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
            latest_event_sha256=provenance.latest_event_sha256,
            latest_occurred_at=provenance.latest_occurred_at,
            feature_artifact_sha256=provenance.feature_artifact_sha256,
            target_artifact_sha256=provenance.target_artifact_sha256,
            completion_receipt_sha256=provenance.completion_receipt_sha256,
        )
    if type(provenance) is not FixtureSegmentJobProvenance:
        raise TypeError("fixture provenance query returned an unexpected job type")
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
        latest_event_sha256=latest.event_sha256,
        latest_occurred_at=latest.occurred_at,
        feature_artifact_sha256=provenance.feature_artifact.artifact_sha256,
        target_artifact_sha256=(
            None
            if provenance.target_artifact is None
            else provenance.target_artifact.artifact_sha256
        ),
        completion_receipt_sha256=latest.completion_receipt_sha256,
    )


def _event_view(
    event: FixtureSegmentEventProvenance,
) -> FixtureSegmentEventProvenanceView:
    if type(event) is not FixtureSegmentEventProvenance:
        raise TypeError("fixture provenance returned an unexpected event type")
    return FixtureSegmentEventProvenanceView(
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


def fixture_segment_provenance_view(
    provenance: FixtureSegmentJobProvenance,
    *,
    event_limit: int,
    before_sequence: int | None,
) -> FixtureSegmentJobProvenanceView:
    """Project one bounded reverse-chronological event page from a verified chain."""

    if type(provenance) is not FixtureSegmentJobProvenance:
        raise TypeError("fixture provenance query returned an unexpected job type")
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
            if type(jobs) is not tuple or any(
                type(job) is not FixtureSegmentJobProvenanceSummary for job in jobs
            ):
                raise TypeError("fixture provenance query must return immutable jobs")
            return FixtureSegmentJobListResponse(
                as_of=queried_at,
                jobs=[fixture_segment_summary_view(job) for job in jobs],
                next_before_job_id=next_before_job_id,
            )
        except FixtureSegmentNotFound as error:
            raise _not_found() from error
        except (
            SQLAlchemyError,
            FixtureSegmentPersistenceError,
            ValueError,
            TypeError,
            AttributeError,
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
            FixtureSegmentPersistenceError,
            ValueError,
            TypeError,
            AttributeError,
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
