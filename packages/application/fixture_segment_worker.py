"""Bounded orchestration for the repository-owned Phase 3F fixture worker."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from packages.domain.experiment_governance import governed_target_policy
from packages.domain.feature import CertifiedFeatureReplay
from packages.domain.feature_target_replay import certify_rolling_close_mean_target_parity
from packages.domain.fixture_segment_worker import (
    FIXTURE_SEGMENT_FAILURE_CODE,
    FIXTURE_SEGMENT_FAILURE_SHA256,
    FixtureSegmentJob,
    FixtureSegmentJobProjection,
)
from packages.persistence.fixture_segment_worker import SqlFixtureSegmentWorkflow

FIXTURE_SEGMENT_CLAIM_TTL = timedelta(minutes=5)

Clock = Callable[[], datetime]
FixtureCertificationResolver = Callable[[FixtureSegmentJob], CertifiedFeatureReplay]


class FixtureSegmentApplicationError(RuntimeError):
    """The bounded fixture worker received invalid local authority or evidence."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _trusted_utc(clock: Clock, field_name: str) -> datetime:
    value = clock()
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise FixtureSegmentApplicationError(f"{field_name} must be an aware UTC datetime")
    return value


def process_one_fixture_segment(
    workflow: SqlFixtureSegmentWorkflow,
    *,
    worker_id: str,
    resolve_certification: FixtureCertificationResolver,
    clock: Clock = _utc_now,
) -> FixtureSegmentJobProjection | None:
    """Claim and close at most one already-governed repository fixture segment."""

    if not isinstance(workflow, SqlFixtureSegmentWorkflow):
        raise FixtureSegmentApplicationError("fixture worker requires its exact SQL workflow")
    if type(worker_id) is not str or not worker_id or worker_id != worker_id.strip():
        raise FixtureSegmentApplicationError("fixture worker ID must be non-empty and trimmed")
    if not callable(resolve_certification):
        raise FixtureSegmentApplicationError("fixture certification resolver must be callable")

    claimed_at = _trusted_utc(clock, "fixture claim time")
    claimed = workflow.claim_next(
        worker_id=worker_id,
        claimed_at=claimed_at,
        claim_expires_at=claimed_at + FIXTURE_SEGMENT_CLAIM_TTL,
    )
    if claimed is None:
        return None
    token = claimed.claim_token
    if token is None:
        raise FixtureSegmentApplicationError("claimed fixture job lacks exact worker authority")

    try:
        certification = resolve_certification(claimed.job)
        if (
            type(certification) is not CertifiedFeatureReplay
            or certification.semantic_sha256 != claimed.job.feature_certification_sha256
        ):
            raise FixtureSegmentApplicationError(
                "fixture resolver substituted the certified feature transcript"
            )
        snapshot = workflow.governance_snapshot(claimed.job.family_id)
        attempt = next(
            attempt for attempt in snapshot.attempts if attempt.attempt_id == claimed.job.attempt_id
        )
        target_certification = certify_rolling_close_mean_target_parity(
            certification,
            governed_target_policy(attempt.configuration),
        )
    except Exception:
        failed_at = _trusted_utc(clock, "fixture failure time")
        return workflow.fail(
            claimed.job.job_id,
            token,
            failed_at=failed_at,
            reason_code=FIXTURE_SEGMENT_FAILURE_CODE,
            reason_sha256=FIXTURE_SEGMENT_FAILURE_SHA256,
        )

    completed_at = _trusted_utc(clock, "fixture completion time")
    return workflow.complete(
        claimed.job.job_id,
        token,
        target_certification,
        completed_at=completed_at,
    )


__all__ = [
    "FIXTURE_SEGMENT_CLAIM_TTL",
    "FIXTURE_SEGMENT_FAILURE_CODE",
    "FIXTURE_SEGMENT_FAILURE_SHA256",
    "FixtureCertificationResolver",
    "FixtureSegmentApplicationError",
    "process_one_fixture_segment",
]
