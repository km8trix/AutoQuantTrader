"""Fixture-only Phase 2 research catalog and bounded worker orchestration."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from packages.backtest.golden_runner import (
    GOLDEN_FIXTURE_ID,
    GOLDEN_FIXTURE_VERSION,
    GoldenBacktestRun,
    golden_strategy_registration,
    run_golden_backtest,
)
from packages.domain.backtest_job import BacktestJobInput
from packages.domain.backtest_report import BacktestRunManifest
from packages.domain.canonical import canonical_json_bytes
from packages.persistence.backtest_workflow import (
    BacktestJobSnapshot,
    SqlBacktestWorkflow,
)

BACKTEST_WORKER_CONTRACT_VERSION = "phase2-fixture-backtest-worker-v1"
GOLDEN_WORKER_CLAIM_TTL = timedelta(minutes=5)
GOLDEN_WORKER_FAILURE_CODE = "fixture_execution_failed"

Clock = Callable[[], datetime]
GoldenRunner = Callable[..., GoldenBacktestRun]


class BacktestWorkerError(RuntimeError):
    """The worker received unsupported work or an invalid authority instant."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _trusted_utc(clock: Clock, field_name: str) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise BacktestWorkerError(f"{field_name} must be an aware UTC datetime")
    resolved = value.astimezone(UTC)
    if resolved.utcoffset() != timedelta(0):
        raise BacktestWorkerError(f"{field_name} must resolve to UTC")
    return resolved


def _failure_sha256(error: Exception) -> str:
    """Hash a bounded classification, never raw exception text or arguments."""

    return hashlib.sha256(
        canonical_json_bytes(
            (
                BACKTEST_WORKER_CONTRACT_VERSION,
                GOLDEN_WORKER_FAILURE_CODE,
                type(error).__module__,
                type(error).__qualname__,
            )
        )
    ).hexdigest()


def ensure_golden_research_catalog(workflow: SqlBacktestWorkflow) -> BacktestJobInput:
    """Idempotently publish the one immutable strategy/configuration/fixture tuple."""

    version, configuration, display_name, parameter_schema = golden_strategy_registration()
    workflow.register_strategy(
        version=version,
        configuration=configuration,
        display_name=display_name,
        parameter_schema_payload=parameter_schema,
    )
    reference = run_golden_backtest()
    return workflow.register_fixture(
        fixture_id=GOLDEN_FIXTURE_ID,
        fixture_version=GOLDEN_FIXTURE_VERSION,
        reference_manifest=reference.manifest,
        registered_at=configuration.registered_at,
    )


def _terminal_manifest(
    run: GoldenBacktestRun,
    *,
    completed_at: datetime,
) -> BacktestRunManifest:
    """Rebind pure run evidence to the trusted post-execution completion time."""

    manifest = run.manifest
    execution_evidence = manifest.execution_evidence_sha256
    risk_evidence = manifest.risk_evidence_sha256
    coordinator_evidence = manifest.coordinator_evidence_sha256
    if execution_evidence is None or risk_evidence is None or coordinator_evidence is None:
        raise BacktestWorkerError("completed fixture run is missing terminal evidence")
    return BacktestRunManifest.completed(
        report=run.report,
        dataset_replay=manifest.dataset_replay,
        strategy=manifest.strategy,
        contracts=manifest.contracts,
        runtime=manifest.runtime,
        benchmark=manifest.benchmark,
        cost_model=manifest.cost_model,
        fill_model=manifest.fill_model,
        started_at=manifest.result.started_at,
        completed_at=completed_at,
        execution_evidence_sha256=execution_evidence,
        risk_evidence_sha256=risk_evidence,
        coordinator_evidence_sha256=coordinator_evidence,
    )


def process_one_golden_backtest(
    workflow: SqlBacktestWorkflow,
    *,
    worker_id: str,
    catalog_input: BacktestJobInput | None = None,
    clock: Clock = _utc_now,
    runner: GoldenRunner = run_golden_backtest,
) -> BacktestJobSnapshot | None:
    """Claim and close at most one fixture job under a bounded durable lease."""

    if type(worker_id) is not str or not worker_id or worker_id != worker_id.strip():
        raise BacktestWorkerError("worker ID must be non-empty and trimmed")
    if catalog_input is not None and type(catalog_input) is not BacktestJobInput:
        raise BacktestWorkerError("catalog input must be an exact BacktestJobInput")
    expected_input = catalog_input or ensure_golden_research_catalog(workflow)
    claimed_at = _trusted_utc(clock, "claim time")
    claimed = workflow.claim_next(
        worker_id=worker_id,
        claimed_at=claimed_at,
        claim_expires_at=claimed_at + GOLDEN_WORKER_CLAIM_TTL,
    )
    if claimed is None:
        return None

    try:
        if claimed.input_sha256 != expected_input.input_sha256:
            raise BacktestWorkerError("claimed job is outside the fixture worker catalog")
        # The pure runner receives an explicit deterministic generation instant.
        # Authority is checked against a separate trusted instant sampled only
        # after the work has actually finished.
        run = runner(generated_at=claimed_at, completed_at=claimed_at)
    except Exception as error:
        failed_at = _trusted_utc(clock, "failure time")
        if failed_at < claimed_at:
            failed_at = claimed_at
        return workflow.fail(
            claimed.job_id,
            worker_id=worker_id,
            failed_at=failed_at,
            terminal_reason_code=GOLDEN_WORKER_FAILURE_CODE,
            terminal_reason_sha256=_failure_sha256(error),
        )

    completed_at = _trusted_utc(clock, "completion time")
    if completed_at < claimed_at:
        raise BacktestWorkerError("completion time cannot precede the claim")
    terminal_manifest = _terminal_manifest(run, completed_at=completed_at)
    return workflow.complete(
        claimed.job_id,
        worker_id=worker_id,
        completed_at=completed_at,
        report=run.report,
        manifest=terminal_manifest,
    )


__all__ = [
    "BACKTEST_WORKER_CONTRACT_VERSION",
    "GOLDEN_WORKER_CLAIM_TTL",
    "GOLDEN_WORKER_FAILURE_CODE",
    "BacktestWorkerError",
    "ensure_golden_research_catalog",
    "process_one_golden_backtest",
]
