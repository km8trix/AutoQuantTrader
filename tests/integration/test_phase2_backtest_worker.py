from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from packages.application.backtest_worker import (
    GOLDEN_WORKER_CLAIM_TTL,
    GOLDEN_WORKER_FAILURE_CODE,
    ensure_golden_research_catalog,
    process_one_golden_backtest,
)
from packages.backtest.golden_runner import GoldenBacktestRun, run_golden_backtest
from packages.domain.backtest_job import BacktestJobNotClaimable, BacktestJobStatus
from packages.persistence.backtest_workflow import SqlBacktestWorkflow
from packages.persistence.database import create_database_engine
from packages.persistence.schema import phase2_backtest_job_events

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 20, 16, 0, tzinfo=UTC)


def _workflow(tmp_path: Path) -> SqlBacktestWorkflow:
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/worker.sqlite")
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option(
        "sqlalchemy.url",
        engine.url.render_as_string(hide_password=False).replace("%", "%%"),
    )
    command.upgrade(config, "head")
    return SqlBacktestWorkflow(engine)


def test_worker_catalog_is_idempotent_and_idle_without_a_launch(tmp_path: Path) -> None:
    workflow = _workflow(tmp_path)

    first = ensure_golden_research_catalog(workflow)
    second = ensure_golden_research_catalog(workflow)

    assert second == first
    assert len(workflow.strategies()) == 1
    assert (
        process_one_golden_backtest(
            workflow,
            worker_id="worker-a",
            clock=lambda: NOW,
        )
        is None
    )


def test_worker_claims_and_publishes_the_golden_result(tmp_path: Path) -> None:
    workflow = _workflow(tmp_path)
    job_input = ensure_golden_research_catalog(workflow)
    queued = workflow.launch(
        input=job_input,
        requested_by="local-operator",
        idempotency_key="worker-completion",
        requested_at=NOW,
    )

    completed = process_one_golden_backtest(
        workflow,
        worker_id="worker-a",
        clock=lambda: NOW,
    )

    assert completed is not None
    assert completed.job_id == queued.job_id
    assert completed.status is BacktestJobStatus.COMPLETED
    assert completed.report_artifact_sha256 is not None
    report = workflow.report(completed.report_artifact_sha256)
    assert report.ending_equity.as_tuple() == (0, (1, 0, 4, 4, 0, 4), -2)


def test_worker_records_only_a_bounded_failure_classification(tmp_path: Path) -> None:
    workflow = _workflow(tmp_path)
    job_input = ensure_golden_research_catalog(workflow)
    queued = workflow.launch(
        input=job_input,
        requested_by="local-operator",
        idempotency_key="worker-failure",
        requested_at=NOW,
    )

    def fail_runner(**_: object) -> object:
        raise RuntimeError("sensitive raw exception detail")

    failed = process_one_golden_backtest(
        workflow,
        worker_id="worker-a",
        clock=lambda: NOW,
        runner=fail_runner,  # type: ignore[arg-type]
    )

    assert failed is not None
    assert failed.job_id == queued.job_id
    assert failed.status is BacktestJobStatus.FAILED
    assert failed.terminal_reason_code == GOLDEN_WORKER_FAILURE_CODE
    engine = workflow._engine
    with engine.connect() as connection:
        payloads = tuple(
            connection.scalars(sa.select(phase2_backtest_job_events.c.canonical_payload))
        )
    assert all("sensitive raw exception detail" not in payload for payload in payloads)


def test_worker_cannot_publish_after_execution_outlives_its_claim(tmp_path: Path) -> None:
    workflow = _workflow(tmp_path)
    job_input = ensure_golden_research_catalog(workflow)
    queued = workflow.launch(
        input=job_input,
        requested_by="local-operator",
        idempotency_key="worker-expired-completion",
        requested_at=NOW,
    )
    current_time = NOW

    def clock() -> datetime:
        return current_time

    def slow_runner(**arguments: object) -> GoldenBacktestRun:
        nonlocal current_time
        run = run_golden_backtest(**arguments)  # type: ignore[arg-type]
        current_time = NOW + GOLDEN_WORKER_CLAIM_TTL + timedelta(seconds=1)
        return run

    with pytest.raises(BacktestJobNotClaimable, match="expired worker claim"):
        process_one_golden_backtest(
            workflow,
            worker_id="worker-a",
            clock=clock,
            runner=slow_runner,
        )

    stale = workflow.get(queued.job_id)
    assert stale.status is BacktestJobStatus.RUNNING
    assert stale.worker_id == "worker-a"
    recovered = workflow.claim_next(
        worker_id="worker-b",
        claimed_at=current_time,
        claim_expires_at=current_time + GOLDEN_WORKER_CLAIM_TTL,
    )
    assert recovered is not None
    assert recovered.job_id == queued.job_id
    assert recovered.worker_id == "worker-b"
    assert recovered.attempt_number == 2
