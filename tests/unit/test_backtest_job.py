from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta

import pytest

from packages.domain.backtest_job import (
    BacktestJob,
    BacktestJobConflict,
    BacktestJobEvent,
    BacktestJobInput,
    BacktestJobNotClaimable,
    BacktestJobProjection,
    BacktestJobStatus,
    cancel_queued_backtest_job,
    claim_backtest_job,
    complete_backtest_job,
    create_backtest_job,
    fail_backtest_job,
    reduce_backtest_job_events,
)

REQUESTED_AT = datetime(2026, 7, 20, 14, 0, tzinfo=UTC)


def job_input() -> BacktestJobInput:
    return BacktestJobInput(
        fixture_id="golden-buy-hold-split-dividend-sell",
        fixture_version="1.0.0",
        dataset_manifest_id="1" * 64,
        dataset_manifest_sha256="1" * 64,
        replay_run_id="2" * 64,
        strategy_id="fixture-buy-hold-sell",
        strategy_version="1.0.0",
        strategy_configuration_sha256="3" * 64,
        benchmark_sha256="4" * 64,
        cost_model_sha256="5" * 64,
        fill_model_sha256="6" * 64,
        metric_conventions_sha256="7" * 64,
    )


def queued() -> tuple[BacktestJob, BacktestJobProjection]:
    return create_backtest_job(
        input=job_input(),
        requested_by="local-operator",
        idempotency_key="launch-fixture-0001",
        requested_at=REQUESTED_AT,
    )


def running() -> tuple[BacktestJob, BacktestJobProjection]:
    job, projection = queued()
    return job, claim_backtest_job(
        projection,
        worker_id="fixture-worker-1",
        claimed_at=REQUESTED_AT + timedelta(seconds=1),
        claim_expires_at=REQUESTED_AT + timedelta(minutes=1),
    )


def test_job_input_and_launch_are_immutable_scale_free_content_evidence() -> None:
    job, projection = queued()
    retried, retried_projection = queued()

    assert job == retried
    assert job.input.input_sha256 == job_input().input_sha256
    assert job.job_id == retried.job_id
    assert job.semantic_sha256 == retried.semantic_sha256
    assert projection == retried_projection
    assert projection.status is BacktestJobStatus.QUEUED
    assert projection.latest.sequence == 0
    assert len(job.canonical_json) > 0
    with pytest.raises(FrozenInstanceError):
        job.requested_by = "other"  # type: ignore[misc]


def test_idempotency_identity_is_scoped_to_operator_and_key() -> None:
    first, _ = queued()
    changed_input = replace(job_input(), fixture_version="1.0.1")
    same_identity = BacktestJob(
        input=changed_input,
        requested_by=first.requested_by,
        idempotency_key=first.idempotency_key,
        requested_at=first.requested_at,
    )
    other_key = replace(first, idempotency_key="launch-fixture-0002")
    other_operator = replace(first, requested_by="another-operator")

    assert same_identity.job_id == first.job_id
    assert same_identity.semantic_sha256 != first.semantic_sha256
    assert other_key.job_id != first.job_id
    assert other_operator.job_id != first.job_id


def test_worker_claim_renewal_recovery_and_terminal_success_are_proven() -> None:
    job, projection = running()
    renewed = claim_backtest_job(
        projection,
        worker_id="fixture-worker-1",
        claimed_at=REQUESTED_AT + timedelta(seconds=30),
        claim_expires_at=REQUESTED_AT + timedelta(minutes=2),
    )

    assert renewed.latest.attempt_number == 1
    assert renewed.latest.previous_event_sha256 == projection.latest.event_sha256
    with pytest.raises(BacktestJobNotClaimable, match="active worker claim"):
        claim_backtest_job(
            renewed,
            worker_id="fixture-worker-2",
            claimed_at=REQUESTED_AT + timedelta(minutes=1),
            claim_expires_at=REQUESTED_AT + timedelta(minutes=3),
        )

    recovered = claim_backtest_job(
        renewed,
        worker_id="fixture-worker-2",
        claimed_at=REQUESTED_AT + timedelta(minutes=2, microseconds=1),
        claim_expires_at=REQUESTED_AT + timedelta(minutes=3),
    )
    assert recovered.latest.attempt_number == 2
    completed = complete_backtest_job(
        recovered,
        worker_id="fixture-worker-2",
        completed_at=REQUESTED_AT + timedelta(minutes=2, seconds=30),
        run_manifest_sha256="8" * 64,
        report_sha256="9" * 64,
        report_artifact_sha256="a" * 64,
    )

    assert completed.terminal
    assert completed.status is BacktestJobStatus.COMPLETED
    assert completed.latest.run_manifest_sha256 == "8" * 64
    assert len(completed.projection_sha256) == 64
    assert completed.job_id == job.job_id
    with pytest.raises(BacktestJobNotClaimable, match="terminal"):
        claim_backtest_job(
            completed,
            worker_id="fixture-worker-3",
            claimed_at=REQUESTED_AT + timedelta(minutes=4),
            claim_expires_at=REQUESTED_AT + timedelta(minutes=5),
        )


def test_worker_must_close_current_unexpired_claim() -> None:
    _, projection = running()

    with pytest.raises(BacktestJobNotClaimable, match="active worker"):
        complete_backtest_job(
            projection,
            worker_id="fixture-worker-2",
            completed_at=REQUESTED_AT + timedelta(seconds=20),
            run_manifest_sha256="8" * 64,
            report_sha256="9" * 64,
            report_artifact_sha256="a" * 64,
        )
    with pytest.raises(BacktestJobNotClaimable, match="expired"):
        complete_backtest_job(
            projection,
            worker_id="fixture-worker-1",
            completed_at=REQUESTED_AT + timedelta(minutes=1, microseconds=1),
            run_manifest_sha256="8" * 64,
            report_sha256="9" * 64,
            report_artifact_sha256="a" * 64,
        )


def test_failure_retains_bounded_reason_without_result_claims() -> None:
    _, projection = running()
    failed = fail_backtest_job(
        projection,
        worker_id="fixture-worker-1",
        failed_at=REQUESTED_AT + timedelta(seconds=20),
        terminal_reason_code="fixture_execution_failed",
        terminal_reason_sha256="b" * 64,
    )

    assert failed.status is BacktestJobStatus.FAILED
    assert failed.latest.report_sha256 is None
    assert failed.latest.terminal_reason_code == "fixture_execution_failed"


def test_operator_can_cancel_only_before_claim() -> None:
    _, projection = queued()
    canceled = cancel_queued_backtest_job(
        projection,
        operator_id="local-operator",
        canceled_at=REQUESTED_AT + timedelta(seconds=1),
        terminal_reason_sha256="c" * 64,
    )
    assert canceled.status is BacktestJobStatus.CANCELED

    _, active = running()
    with pytest.raises(BacktestJobConflict, match="only a queued job"):
        cancel_queued_backtest_job(
            active,
            operator_id="local-operator",
            canceled_at=REQUESTED_AT + timedelta(seconds=2),
            terminal_reason_sha256="c" * 64,
        )


def test_event_chain_rejects_reordering_forgery_and_direct_construction() -> None:
    _, projection = running()
    events = projection.events

    with pytest.raises(BacktestJobConflict, match="contiguous"):
        reduce_backtest_job_events(projection.job_id, tuple(reversed(events)))
    forged = object.__new__(BacktestJobEvent)
    for name, value in ((field, getattr(events[1], field)) for field in events[1].__slots__):
        object.__setattr__(forged, name, value)
    object.__setattr__(forged, "previous_event_sha256", "f" * 64)
    with pytest.raises(BacktestJobConflict, match="predecessor"):
        reduce_backtest_job_events(projection.job_id, (events[0], forged))
    with pytest.raises(TypeError, match="_construction_proof"):
        BacktestJobEvent(  # type: ignore[call-arg]
            job_id=projection.job_id,
            sequence=0,
            status=BacktestJobStatus.QUEUED,
            occurred_at=REQUESTED_AT,
            actor_id="local-operator",
            attempt_number=0,
            previous_event_sha256=None,
            worker_id=None,
            claim_expires_at=None,
            run_manifest_sha256=None,
            report_sha256=None,
            report_artifact_sha256=None,
            terminal_reason_code=None,
            terminal_reason_sha256=None,
        )


def test_job_contract_rejects_ambiguous_or_non_fixture_evidence() -> None:
    with pytest.raises(ValueError, match="content-addressed"):
        replace(job_input(), dataset_manifest_id="f" * 64)
    with pytest.raises(ValueError, match="idempotency key"):
        create_backtest_job(
            input=job_input(),
            requested_by="local-operator",
            idempotency_key="short",
            requested_at=REQUESTED_AT,
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        create_backtest_job(
            input=job_input(),
            requested_by="local-operator",
            idempotency_key="launch-fixture-0001",
            requested_at=REQUESTED_AT.replace(tzinfo=None),
        )
