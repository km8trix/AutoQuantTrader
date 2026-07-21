from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import cast

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine

from packages.backtest.golden_runner import (
    GOLDEN_FIXTURE_ID,
    GOLDEN_FIXTURE_VERSION,
    golden_strategy_registration,
    run_golden_backtest,
)
from packages.domain.backtest_job import BacktestJobInput, BacktestJobStatus
from packages.domain.backtest_report import BacktestRunManifest
from packages.domain.experiment_registry import (
    StrategyConfigurationRecord,
    StrategyVersionRecord,
)
from packages.persistence.backtest_workflow import (
    BacktestJobSnapshot,
    BacktestWorkflowConflict,
    BacktestWorkflowError,
    SqlBacktestWorkflow,
)
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.schema import (
    phase2_backtest_audit_events,
    phase2_backtest_fixtures,
    phase2_backtest_job_events,
    phase2_backtest_jobs,
    phase2_backtest_reports,
    phase2_backtest_run_manifests,
    phase2_strategy_configurations,
    phase2_strategy_versions,
)

ROOT = Path(__file__).resolve().parents[2]
REQUESTED_AT = datetime(2026, 7, 20, 14, 0, tzinfo=UTC)


def migrated_engine(tmp_path: Path) -> Engine:
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/research.sqlite")
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option(
        "sqlalchemy.url",
        engine.url.render_as_string(hide_password=False).replace("%", "%%"),
    )
    command.upgrade(config, "head")
    return engine


def configured_workflow(
    tmp_path: Path,
) -> tuple[Engine, SqlBacktestWorkflow, BacktestJobInput]:
    engine = migrated_engine(tmp_path)
    workflow = SqlBacktestWorkflow(engine)
    version, configuration, display_name, parameter_schema = golden_strategy_registration()
    workflow.register_strategy(
        version=version,
        configuration=configuration,
        display_name=display_name,
        parameter_schema_payload=parameter_schema,
    )
    reference = run_golden_backtest()
    job_input = workflow.register_fixture(
        fixture_id=GOLDEN_FIXTURE_ID,
        fixture_version=GOLDEN_FIXTURE_VERSION,
        reference_manifest=reference.manifest,
        registered_at=REQUESTED_AT - timedelta(minutes=1),
    )
    return engine, workflow, job_input


def _registration_for_schema(
    schema_payload: str,
    parameters: Mapping[str, object],
) -> tuple[StrategyVersionRecord, StrategyConfigurationRecord, str]:
    version, original_configuration, display_name, _ = golden_strategy_registration()
    version = replace(
        version,
        parameter_schema_sha256=hashlib.sha256(schema_payload.encode("utf-8")).hexdigest(),
    )
    configuration = StrategyConfigurationRecord(
        strategy_version_sha256=version.strategy_version_id,
        configuration_name=original_configuration.configuration_name,
        parameters=parameters,
        registered_at=original_configuration.registered_at,
        registered_by=original_configuration.registered_by,
    )
    return version, configuration, display_name


def test_catalog_launch_and_idempotent_retry_are_durable_and_audited(tmp_path: Path) -> None:
    engine, workflow, raw_input = configured_workflow(tmp_path)
    job_input = raw_input
    strategies = workflow.strategies()

    assert len(strategies) == 1
    assert strategies[0].fixture_id == GOLDEN_FIXTURE_ID
    assert strategies[0].configuration_sha256 == (job_input.strategy_configuration_sha256)
    first = workflow.launch(
        input=job_input,
        requested_by="local-operator",
        idempotency_key="phase2-launch-0001",
        requested_at=REQUESTED_AT,
    )
    retry = workflow.launch(
        input=job_input,
        requested_by="local-operator",
        idempotency_key="phase2-launch-0001",
        requested_at=REQUESTED_AT + timedelta(minutes=5),
    )

    assert retry == first
    assert first.status is BacktestJobStatus.QUEUED
    assert workflow.get(first.job_id) == first
    assert workflow.jobs() == (first,)
    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_backtest_audit_events))
            == 1
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_backtest_job_events))
            == 1
        )


def test_strategy_registration_accepts_canonical_decimal_schema_value(tmp_path: Path) -> None:
    engine = migrated_engine(tmp_path)
    workflow = SqlBacktestWorkflow(engine)
    _, _, _, schema_payload = golden_strategy_registration()
    version, configuration, display_name = _registration_for_schema(
        schema_payload,
        {"instrument_id": "US-ETF-SPY", "quantity": Decimal("4.00")},
    )

    workflow.register_strategy(
        version=version,
        configuration=configuration,
        display_name=display_name,
        parameter_schema_payload=schema_payload,
    )

    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_strategy_versions)) == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase2_strategy_configurations)
            )
            == 1
        )


def test_strategy_registration_rejects_invalid_schema_without_writes(tmp_path: Path) -> None:
    engine = migrated_engine(tmp_path)
    workflow = SqlBacktestWorkflow(engine)
    parameters = {"instrument_id": "US-ETF-SPY", "quantity": Decimal("4")}
    invalid_schemas = (
        ("{]", "strict JSON"),
        (
            '{"additionalProperties":false,"properties":{},"required":[],'
            '"type":"object","type":"object"}',
            "strict JSON",
        ),
        (
            json.dumps(
                {
                    "additionalProperties": False,
                    "properties": {},
                    "required": [],
                    "title": "unsupported",
                    "type": "object",
                }
            ),
            "unsupported root fields",
        ),
        (
            json.dumps(
                {
                    "additionalProperties": False,
                    "properties": {"quantity": {"minimum": 1, "type": "integer"}},
                    "required": ["quantity"],
                    "type": "object",
                }
            ),
            "unsupported fields",
        ),
        (
            json.dumps(
                {
                    "additionalProperties": False,
                    "properties": {"quantity": {"type": "number"}},
                    "required": ["quantity"],
                    "type": "object",
                }
            ),
            "unsupported type",
        ),
    )

    for schema_payload, message in invalid_schemas:
        version, configuration, display_name = _registration_for_schema(
            schema_payload,
            parameters,
        )
        with pytest.raises(BacktestWorkflowError, match=message):
            workflow.register_strategy(
                version=version,
                configuration=configuration,
                display_name=display_name,
                parameter_schema_payload=schema_payload,
            )

    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_strategy_versions)) == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase2_strategy_configurations)
            )
            == 0
        )


def test_strategy_registration_rejects_schema_incompatible_parameters_without_writes(
    tmp_path: Path,
) -> None:
    engine = migrated_engine(tmp_path)
    workflow = SqlBacktestWorkflow(engine)
    _, _, _, golden_schema = golden_strategy_registration()
    integer_schema = json.dumps(
        {
            "additionalProperties": False,
            "properties": {"quantity": {"type": "integer"}},
            "required": ["quantity"],
            "type": "object",
        }
    )
    invalid_configurations = (
        (golden_schema, {"instrument_id": "US-ETF-SPY"}, "missing required"),
        (
            golden_schema,
            {
                "extra": True,
                "instrument_id": "US-ETF-SPY",
                "quantity": Decimal("4"),
            },
            "undeclared parameters",
        ),
        (
            golden_schema,
            {"instrument_id": "US-ETF-SPY", "quantity": 4},
            "must have type 'string'",
        ),
        (
            golden_schema,
            {"instrument_id": "US-ETF-SPY", "quantity": Decimal("5")},
            "conflicts with schema const",
        ),
        (integer_schema, {"quantity": True}, "must have type 'integer'"),
    )

    for schema_payload, parameters, message in invalid_configurations:
        version, configuration, display_name = _registration_for_schema(
            schema_payload,
            parameters,
        )
        with pytest.raises(BacktestWorkflowConflict, match=message):
            workflow.register_strategy(
                version=version,
                configuration=configuration,
                display_name=display_name,
                parameter_schema_payload=schema_payload,
            )

    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_strategy_versions)) == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase2_strategy_configurations)
            )
            == 0
        )


def test_idempotency_key_rejects_changed_immutable_input(tmp_path: Path) -> None:
    _, workflow, raw_input = configured_workflow(tmp_path)
    workflow.launch(
        input=raw_input,
        requested_by="local-operator",
        idempotency_key="phase2-launch-0002",
        requested_at=REQUESTED_AT,
    )

    with pytest.raises(BacktestWorkflowConflict):
        workflow.launch(
            input=replace(raw_input, benchmark_sha256="f" * 64),
            requested_by="local-operator",
            idempotency_key="phase2-launch-0002",
            requested_at=REQUESTED_AT + timedelta(seconds=1),
        )


def test_parallel_exact_launch_retries_return_one_durable_winner(tmp_path: Path) -> None:
    engine, workflow, job_input = configured_workflow(tmp_path)

    def launch(offset_seconds: int) -> BacktestJobSnapshot:
        return workflow.launch(
            input=job_input,
            requested_by="parallel-local-operator",
            idempotency_key="phase2-parallel-launch",
            requested_at=REQUESTED_AT + timedelta(seconds=offset_seconds),
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(launch, (0, 1)))

    assert results[0] == results[1]
    assert results[0].requested_at in {
        REQUESTED_AT,
        REQUESTED_AT + timedelta(seconds=1),
    }
    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_backtest_audit_events))
            == 1
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_backtest_job_events))
            == 1
        )


def test_parallel_workers_cannot_claim_the_same_job(tmp_path: Path) -> None:
    _, workflow, raw_input = configured_workflow(tmp_path)
    queued = workflow.launch(
        input=raw_input,
        requested_by="local-operator",
        idempotency_key="phase2-launch-0003",
        requested_at=REQUESTED_AT,
    )
    claim_at = REQUESTED_AT + timedelta(seconds=1)

    def claim(worker_id: str) -> BacktestJobSnapshot | None:
        return workflow.claim_next(
            worker_id=worker_id,
            claimed_at=claim_at,
            claim_expires_at=claim_at + timedelta(minutes=5),
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(claim, ("worker-a", "worker-b")))

    claimed = tuple(result for result in results if result is not None)
    assert len(claimed) == 1
    assert claimed[0].job_id == queued.job_id
    assert claimed[0].status is BacktestJobStatus.RUNNING
    assert workflow.get(queued.job_id).worker_id == claimed[0].worker_id


def test_expired_claim_is_recovered_with_a_new_attempt(tmp_path: Path) -> None:
    _, workflow, raw_input = configured_workflow(tmp_path)
    queued = workflow.launch(
        input=raw_input,
        requested_by="local-operator",
        idempotency_key="phase2-launch-0004",
        requested_at=REQUESTED_AT,
    )
    first = workflow.claim_next(
        worker_id="worker-a",
        claimed_at=REQUESTED_AT + timedelta(seconds=1),
        claim_expires_at=REQUESTED_AT + timedelta(seconds=10),
    )
    recovered = workflow.claim_next(
        worker_id="worker-b",
        claimed_at=REQUESTED_AT + timedelta(seconds=11),
        claim_expires_at=REQUESTED_AT + timedelta(minutes=1),
    )

    assert first is not None and first.attempt_number == 1
    assert recovered is not None
    assert recovered.job_id == queued.job_id
    assert recovered.worker_id == "worker-b"
    assert recovered.attempt_number == 2


def test_worker_publishes_exact_golden_report_manifest_and_query_rows(tmp_path: Path) -> None:
    engine, workflow, raw_input = configured_workflow(tmp_path)
    queued = workflow.launch(
        input=raw_input,
        requested_by="local-operator",
        idempotency_key="phase2-launch-0005",
        requested_at=REQUESTED_AT,
    )
    claim = workflow.claim_next(
        worker_id="worker-a",
        claimed_at=REQUESTED_AT + timedelta(seconds=1),
        claim_expires_at=REQUESTED_AT + timedelta(minutes=5),
    )
    assert claim is not None
    run = run_golden_backtest(generated_at=REQUESTED_AT + timedelta(minutes=1))
    completed = workflow.complete(
        queued.job_id,
        worker_id="worker-a",
        completed_at=run.manifest.result.completed_at,
        report=run.report,
        manifest=run.manifest,
    )
    report = workflow.report(run.report.artifact_sha256)

    assert completed.status is BacktestJobStatus.COMPLETED
    assert completed.run_manifest_sha256 == run.manifest.manifest_sha256
    assert tuple(event.status for event in completed.history) == (
        BacktestJobStatus.QUEUED,
        BacktestJobStatus.RUNNING,
        BacktestJobStatus.COMPLETED,
    )
    assert tuple(event.sequence for event in completed.history) == (0, 1, 2)
    assert report.ending_equity == run.report.metrics.ending_equity
    metrics = cast(dict[str, object], report.query_payload["metrics"])
    equity_curve = cast(list[dict[str, object]], report.query_payload["equity_curve"])
    trades = cast(list[dict[str, object]], report.query_payload["trades"])
    ledger_trace = cast(list[dict[str, object]], report.query_payload["ledger_trace"])
    assert metrics["ending_equity"] == "1044.04"
    assert equity_curve[-1]["equity"] == "1044.04"
    assert len(trades) == 1
    assert len(ledger_trace) >= 5
    verify_operational_schema(engine, require_phase_zero_facts=False)


def test_report_corruption_fails_closed(tmp_path: Path) -> None:
    engine, workflow, raw_input = configured_workflow(tmp_path)
    queued = workflow.launch(
        input=raw_input,
        requested_by="local-operator",
        idempotency_key="phase2-launch-0006",
        requested_at=REQUESTED_AT,
    )
    workflow.claim_next(
        worker_id="worker-a",
        claimed_at=REQUESTED_AT + timedelta(seconds=1),
        claim_expires_at=REQUESTED_AT + timedelta(minutes=5),
    )
    run = run_golden_backtest(generated_at=REQUESTED_AT + timedelta(minutes=1))
    workflow.complete(
        queued.job_id,
        worker_id="worker-a",
        completed_at=run.manifest.result.completed_at,
        report=run.report,
        manifest=run.manifest,
    )
    with engine.begin() as connection:
        connection.execute(
            sa.update(phase2_backtest_reports).values(query_payload='{"corrupt":true}')
        )

    with pytest.raises(BacktestWorkflowError, match="query payload digest"):
        workflow.report(run.report.artifact_sha256)


def _tamper_report_query(payload_text: str, section: str) -> str:
    payload = cast(dict[str, object], json.loads(payload_text))
    if section == "conventions":
        conventions = cast(dict[str, object], payload["conventions"])
        conventions["convention_id"] = "tampered-convention"
    elif section == "metrics":
        metrics = cast(dict[str, object], payload["metrics"])
        metrics["capacity_proxy"] = "0"
    elif section == "equity_curve":
        equity = cast(list[dict[str, object]], payload["equity_curve"])
        equity[0]["gross_exposure"] = "1"
    elif section == "trades":
        trades = cast(list[dict[str, object]], payload["trades"])
        trades[0]["opening_execution_sha256"] = "f" * 64
    elif section == "positions":
        positions = cast(list[dict[str, object]], payload["positions"])
        positions[0]["source_projection_sha256"] = "f" * 64
    elif section == "ledger_trace":
        ledger = cast(list[dict[str, object]], payload["ledger_trace"])
        ledger[0]["entry_sha256"] = "f" * 64
    elif section == "provenance":
        provenance = cast(dict[str, object], payload["provenance"])
        provenance["execution_ledger_sha256"] = "f" * 64
    else:  # pragma: no cover - the parametrization is closed below
        raise AssertionError(f"unsupported report section {section!r}")
    return json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


@pytest.mark.parametrize(
    "section",
    (
        "conventions",
        "metrics",
        "equity_curve",
        "trades",
        "positions",
        "ledger_trace",
        "provenance",
    ),
)
def test_rehashed_nested_report_corruption_cannot_disguise_tampering(
    tmp_path: Path,
    section: str,
) -> None:
    engine, workflow, raw_input = configured_workflow(tmp_path)
    queued = workflow.launch(
        input=raw_input,
        requested_by="local-operator",
        idempotency_key=f"phase2-rehashed-report-{section}",
        requested_at=REQUESTED_AT,
    )
    workflow.claim_next(
        worker_id="worker-a",
        claimed_at=REQUESTED_AT + timedelta(seconds=1),
        claim_expires_at=REQUESTED_AT + timedelta(minutes=5),
    )
    run = run_golden_backtest(generated_at=REQUESTED_AT + timedelta(minutes=1))
    workflow.complete(
        queued.job_id,
        worker_id="worker-a",
        completed_at=run.manifest.result.completed_at,
        report=run.report,
        manifest=run.manifest,
    )
    with engine.begin() as connection:
        query_payload = connection.scalar(sa.select(phase2_backtest_reports.c.query_payload))
        assert type(query_payload) is str
        tampered_payload = _tamper_report_query(query_payload, section)
        connection.execute(
            sa.update(phase2_backtest_reports).values(
                query_payload=tampered_payload,
                query_payload_sha256=hashlib.sha256(tampered_payload.encode("utf-8")).hexdigest(),
            )
        )

    with pytest.raises(BacktestWorkflowError, match="immutable report evidence"):
        workflow.report(run.report.artifact_sha256)
    with pytest.raises(DatabaseSchemaNotReady, match="auxiliary evidence"):
        verify_operational_schema(engine, require_phase_zero_facts=False)


def test_parameter_schema_corruption_fails_catalog_reads_and_readiness(tmp_path: Path) -> None:
    engine, workflow, _ = configured_workflow(tmp_path)
    with engine.begin() as connection:
        connection.execute(
            sa.update(phase2_strategy_versions).values(parameter_schema_payload="{}")
        )

    with pytest.raises(BacktestWorkflowError, match="parameter schema"):
        workflow.strategies()
    with pytest.raises(DatabaseSchemaNotReady, match="research evidence digest"):
        verify_operational_schema(engine, require_phase_zero_facts=False)


def test_strategy_display_name_corruption_fails_catalog_reads_and_readiness(
    tmp_path: Path,
) -> None:
    engine, workflow, _ = configured_workflow(tmp_path)
    with engine.begin() as connection:
        connection.execute(
            sa.update(phase2_strategy_versions).values(display_name="Tampered strategy")
        )

    with pytest.raises(BacktestWorkflowError, match="display name"):
        workflow.strategies()
    with pytest.raises(DatabaseSchemaNotReady, match="auxiliary evidence"):
        verify_operational_schema(engine, require_phase_zero_facts=False)


def test_parameters_payload_corruption_fails_catalog_reads_and_readiness(
    tmp_path: Path,
) -> None:
    engine, workflow, _ = configured_workflow(tmp_path)
    with engine.begin() as connection:
        parameters_payload = connection.scalar(
            sa.select(phase2_strategy_configurations.c.parameters_payload)
        )
        assert type(parameters_payload) is str
        tampered_payload = parameters_payload.replace("US-ETF-SPY", "US-ETF-QQQ")
        assert tampered_payload != parameters_payload
        connection.execute(
            sa.update(phase2_strategy_configurations).values(parameters_payload=tampered_payload)
        )

    with pytest.raises(BacktestWorkflowError, match="parameters payload"):
        workflow.strategies()
    with pytest.raises(DatabaseSchemaNotReady, match="auxiliary evidence"):
        verify_operational_schema(engine, require_phase_zero_facts=False)


def test_fixture_pin_corruption_fails_catalog_reads_and_readiness(tmp_path: Path) -> None:
    engine, workflow, _ = configured_workflow(tmp_path)
    with engine.begin() as connection:
        connection.execute(sa.update(phase2_backtest_fixtures).values(benchmark_sha256="f" * 64))

    with pytest.raises(BacktestWorkflowError, match=r"fixture.*canonical identity"):
        workflow.strategies()
    with pytest.raises(DatabaseSchemaNotReady, match="auxiliary evidence"):
        verify_operational_schema(engine, require_phase_zero_facts=False)


def test_job_requested_at_corruption_fails_reads_and_readiness(tmp_path: Path) -> None:
    engine, workflow, job_input = configured_workflow(tmp_path)
    queued = workflow.launch(
        input=job_input,
        requested_by="local-operator",
        idempotency_key="phase2-job-time-corruption",
        requested_at=REQUESTED_AT,
    )
    with engine.begin() as connection:
        connection.execute(
            sa.update(phase2_backtest_jobs)
            .where(phase2_backtest_jobs.c.job_id == queued.job_id)
            .values(requested_at=REQUESTED_AT + timedelta(seconds=1))
        )

    with pytest.raises(BacktestWorkflowError, match="canonical evidence"):
        workflow.get(queued.job_id)
    with pytest.raises(DatabaseSchemaNotReady, match="auxiliary evidence"):
        verify_operational_schema(engine, require_phase_zero_facts=False)


def test_launch_audit_column_corruption_fails_readiness(tmp_path: Path) -> None:
    engine, workflow, job_input = configured_workflow(tmp_path)
    workflow.launch(
        input=job_input,
        requested_by="local-operator",
        idempotency_key="phase2-audit-time-corruption",
        requested_at=REQUESTED_AT,
    )
    with engine.begin() as connection:
        connection.execute(
            sa.update(phase2_backtest_audit_events).values(
                occurred_at=REQUESTED_AT + timedelta(seconds=1)
            )
        )

    with pytest.raises(DatabaseSchemaNotReady, match="auxiliary evidence"):
        verify_operational_schema(engine, require_phase_zero_facts=False)


def test_run_manifest_column_corruption_fails_readiness(tmp_path: Path) -> None:
    engine, workflow, job_input = configured_workflow(tmp_path)
    queued = workflow.launch(
        input=job_input,
        requested_by="local-operator",
        idempotency_key="phase2-manifest-time-corruption",
        requested_at=REQUESTED_AT,
    )
    workflow.claim_next(
        worker_id="worker-a",
        claimed_at=REQUESTED_AT + timedelta(seconds=1),
        claim_expires_at=REQUESTED_AT + timedelta(minutes=5),
    )
    run = run_golden_backtest(generated_at=REQUESTED_AT + timedelta(minutes=1))
    workflow.complete(
        queued.job_id,
        worker_id="worker-a",
        completed_at=run.manifest.result.completed_at,
        report=run.report,
        manifest=run.manifest,
    )
    with engine.begin() as connection:
        started_at = connection.scalar(sa.select(phase2_backtest_run_manifests.c.started_at))
        assert isinstance(started_at, datetime)
        connection.execute(
            sa.update(phase2_backtest_run_manifests).values(
                started_at=started_at + timedelta(microseconds=1)
            )
        )

    with pytest.raises(DatabaseSchemaNotReady, match="auxiliary evidence"):
        verify_operational_schema(engine, require_phase_zero_facts=False)


def test_completion_rejects_replay_evidence_outside_the_registered_fixture(
    tmp_path: Path,
) -> None:
    _, workflow, job_input = configured_workflow(tmp_path)
    queued = workflow.launch(
        input=job_input,
        requested_by="local-operator",
        idempotency_key="phase2-fixture-pin-conflict",
        requested_at=REQUESTED_AT,
    )
    workflow.claim_next(
        worker_id="worker-a",
        claimed_at=REQUESTED_AT + timedelta(seconds=1),
        claim_expires_at=REQUESTED_AT + timedelta(minutes=5),
    )
    run = run_golden_backtest(generated_at=REQUESTED_AT + timedelta(minutes=1))
    manifest = run.manifest
    execution_evidence = manifest.execution_evidence_sha256
    risk_evidence = manifest.risk_evidence_sha256
    coordinator_evidence = manifest.coordinator_evidence_sha256
    assert execution_evidence is not None
    assert risk_evidence is not None
    assert coordinator_evidence is not None
    conflicting_manifest = BacktestRunManifest.completed(
        report=run.report,
        dataset_replay=replace(manifest.dataset_replay, source_tape_sha256="f" * 64),
        strategy=manifest.strategy,
        contracts=manifest.contracts,
        runtime=manifest.runtime,
        benchmark=manifest.benchmark,
        cost_model=manifest.cost_model,
        fill_model=manifest.fill_model,
        started_at=manifest.result.started_at,
        completed_at=manifest.result.completed_at,
        execution_evidence_sha256=execution_evidence,
        risk_evidence_sha256=risk_evidence,
        coordinator_evidence_sha256=coordinator_evidence,
    )

    with pytest.raises(BacktestWorkflowConflict, match="registered fixture replay evidence"):
        workflow.complete(
            queued.job_id,
            worker_id="worker-a",
            completed_at=conflicting_manifest.result.completed_at,
            report=run.report,
            manifest=conflicting_manifest,
        )

    assert workflow.get(queued.job_id).status is BacktestJobStatus.RUNNING
