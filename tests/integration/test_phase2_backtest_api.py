from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from apps.api.config import LocalCredentials, Settings
from apps.api.main import create_app
from packages.application.backtest_worker import (
    ensure_golden_research_catalog,
    process_one_golden_backtest,
)
from packages.backtest.golden_runner import GOLDEN_FIXTURE_ID, run_golden_backtest
from packages.domain.backtest_job import BacktestJobInput
from packages.persistence.backtest_workflow import SqlBacktestWorkflow
from packages.persistence.database import create_database_engine
from packages.persistence.schema import (
    phase2_backtest_audit_events,
    phase2_backtest_job_events,
    phase2_backtest_reports,
)

ROOT = Path(__file__).resolve().parents[2]


def _configured_engine(
    tmp_path: Path,
) -> tuple[Engine, SqlBacktestWorkflow, BacktestJobInput]:
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/backtest-api.sqlite")
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option(
        "sqlalchemy.url",
        engine.url.render_as_string(hide_password=False).replace("%", "%%"),
    )
    command.upgrade(config, "head")
    workflow = SqlBacktestWorkflow(engine)
    job_input = ensure_golden_research_catalog(workflow)
    return engine, workflow, job_input


def _launch_body(job_input: BacktestJobInput) -> dict[str, str]:
    return {
        "fixture_id": job_input.fixture_id,
        "fixture_version": job_input.fixture_version,
        "dataset_manifest_id": job_input.dataset_manifest_id,
        "dataset_manifest_sha256": job_input.dataset_manifest_sha256,
        "replay_run_id": job_input.replay_run_id,
        "strategy_id": job_input.strategy_id,
        "strategy_version": job_input.strategy_version,
        "strategy_configuration_sha256": job_input.strategy_configuration_sha256,
        "benchmark_sha256": job_input.benchmark_sha256,
        "cost_model_sha256": job_input.cost_model_sha256,
        "fill_model_sha256": job_input.fill_model_sha256,
        "metric_conventions_sha256": job_input.metric_conventions_sha256,
    }


def _authorized_client(
    engine: Engine,
    *,
    operator_id: str = "phase2-local-operator",
) -> tuple[TestClient, str]:
    settings = Settings(credentials=LocalCredentials(operator_id=operator_id))
    client = TestClient(create_app(settings, engine=engine))
    bootstrap = client.get("/api/v1/ui/bootstrap")
    capability = bootstrap.json()["backtest_launch"]
    assert capability["enabled"] is True
    assert capability["operator_id"] == operator_id
    csrf_token = capability["csrf_token"]
    assert isinstance(csrf_token, str)
    return client, csrf_token


def test_bootstrap_issues_strict_local_session_and_catalog_launch_pins(tmp_path: Path) -> None:
    engine, _, job_input = _configured_engine(tmp_path)
    client = TestClient(create_app(Settings(), engine=engine))

    bootstrap = client.get("/api/v1/ui/bootstrap")
    cookie = bootstrap.headers["set-cookie"]
    assert bootstrap.headers["cache-control"] == "no-store"
    assert "aqt_local_session=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert "Path=/api/v1" in cookie
    assert "fixture-backtest-query" in bootstrap.json()["capabilities"]
    assert "fixture-backtest-launch" in bootstrap.json()["capabilities"]

    repeated = client.get("/api/v1/ui/bootstrap")
    assert "set-cookie" not in repeated.headers
    assert (
        repeated.json()["backtest_launch"]["csrf_token"]
        == bootstrap.json()["backtest_launch"]["csrf_token"]
    )

    response = client.get("/api/v1/research/strategies")
    assert response.status_code == 200
    payload = response.json()
    assert datetime.fromisoformat(payload["as_of"]).tzinfo is not None
    assert len(payload["strategies"]) == 1
    strategy = payload["strategies"][0]
    assert strategy["fixture_id"] == GOLDEN_FIXTURE_ID
    assert strategy["dataset_manifest_sha256"] == job_input.dataset_manifest_sha256
    assert strategy["replay_run_id"] == job_input.replay_run_id
    assert strategy["configuration_sha256"] == job_input.strategy_configuration_sha256


def test_launch_requires_session_csrf_and_durable_idempotency(tmp_path: Path) -> None:
    engine, _, job_input = _configured_engine(tmp_path)
    body = _launch_body(job_input)
    app = create_app(
        Settings(credentials=LocalCredentials(operator_id="authenticated-operator")),
        engine=engine,
    )

    unauthenticated = TestClient(app)
    missing_session = unauthenticated.post(
        "/api/v1/research/backtests",
        json=body,
        headers={
            "X-CSRF-Token": "x" * 43,
            "Idempotency-Key": "phase2-browser-launch-001",
        },
    )
    assert missing_session.status_code == 401

    client, csrf_token = _authorized_client(engine, operator_id="authenticated-operator")
    bad_csrf = client.post(
        "/api/v1/research/backtests",
        json=body,
        headers={
            "X-CSRF-Token": "x" * 43,
            "Idempotency-Key": "phase2-browser-launch-001",
        },
    )
    assert bad_csrf.status_code == 403

    headers = {
        "X-CSRF-Token": csrf_token,
        "Idempotency-Key": "phase2-browser-launch-001",
    }
    launched = client.post("/api/v1/research/backtests", json=body, headers=headers)
    retry = client.post("/api/v1/research/backtests", json=body, headers=headers)

    assert launched.status_code == 202
    assert retry.status_code == 202
    assert retry.json() == launched.json()
    assert launched.json()["requested_by"] == "authenticated-operator"
    assert launched.json()["history"] == [
        {
            "sequence": 0,
            "status": "queued",
            "occurred_at": launched.json()["requested_at"],
            "actor_id": "authenticated-operator",
            "attempt_number": 0,
            "terminal_reason_code": None,
        }
    ]
    assert launched.headers["location"].endswith(launched.json()["job_id"])
    assert client.get(launched.headers["location"]).json() == launched.json()
    jobs = client.get("/api/v1/research/backtests").json()["jobs"]
    assert jobs == [launched.json()]
    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_backtest_audit_events))
            == 1
        )

    conflict_body = _launch_body(replace(job_input, benchmark_sha256="f" * 64))
    conflict = client.post(
        "/api/v1/research/backtests",
        json=conflict_body,
        headers=headers,
    )
    assert conflict.status_code == 409
    unexpected = client.post(
        "/api/v1/research/backtests",
        json={**body, "unexpected": "field"},
        headers={
            "X-CSRF-Token": csrf_token,
            "Idempotency-Key": "phase2-browser-launch-002",
        },
    )
    assert unexpected.status_code == 422


def test_completed_job_exposes_verified_rich_report(tmp_path: Path) -> None:
    engine, workflow, job_input = _configured_engine(tmp_path)
    client, csrf_token = _authorized_client(engine)
    launched = client.post(
        "/api/v1/research/backtests",
        json=_launch_body(job_input),
        headers={
            "X-CSRF-Token": csrf_token,
            "Idempotency-Key": "phase2-browser-report-001",
        },
    ).json()

    claim_time = datetime.now(UTC) + timedelta(seconds=1)
    claim = workflow.claim_next(
        worker_id="phase2-api-test-worker",
        claimed_at=claim_time,
        claim_expires_at=claim_time + timedelta(minutes=5),
    )
    assert claim is not None
    assert claim.claim_token is not None
    run = run_golden_backtest(generated_at=claim_time + timedelta(minutes=1))
    workflow.complete(
        launched["job_id"],
        worker_id="phase2-api-test-worker",
        claim_token=claim.claim_token,
        completed_at=run.manifest.result.completed_at,
        report=run.report,
        manifest=run.manifest,
    )

    response = client.get(f"/api/v1/research/backtests/{launched['job_id']}/report")
    assert response.status_code == 200
    report = response.json()
    assert report["report_sha256"] == run.report.report_sha256
    assert report["metrics"]["ending_equity"] == "1044.04"
    assert report["equity_curve"][-1]["equity"] == "1044.04"
    assert len(report["trades"]) == 1
    assert report["trades"][0]["symbol"] == "SPY"
    assert report["positions"][-1]["quantity"] == "0"
    assert len(report["ledger_trace"]) >= 5
    assert len(report["provenance"]["accounting_evidence_sha256"]) == 64

    with engine.begin() as connection:
        connection.execute(
            sa.update(phase2_backtest_reports).values(query_payload='{"corrupt":true}')
        )
    assert client.get(f"/api/v1/research/backtests/{launched['job_id']}/report").status_code == 503


def test_authenticated_launch_runs_in_worker_and_returns_the_report(tmp_path: Path) -> None:
    engine, workflow, job_input = _configured_engine(tmp_path)
    client, csrf_token = _authorized_client(engine)
    launched = client.post(
        "/api/v1/research/backtests",
        json=_launch_body(job_input),
        headers={
            "X-CSRF-Token": csrf_token,
            "Idempotency-Key": "phase2-end-to-end-001",
        },
    )
    assert launched.status_code == 202
    job_id = launched.json()["job_id"]
    worker_time = datetime.now(UTC) + timedelta(seconds=1)

    completed = process_one_golden_backtest(
        workflow,
        worker_id="phase2-end-to-end-worker",
        catalog_input=job_input,
        clock=lambda: worker_time,
    )

    assert completed is not None
    assert completed.job_id == job_id
    assert completed.status.value == "completed"
    job = client.get(f"/api/v1/research/backtests/{job_id}")
    assert job.status_code == 200
    assert [event["status"] for event in job.json()["history"]] == [
        "queued",
        "running",
        "completed",
    ]
    assert [event["sequence"] for event in job.json()["history"]] == [0, 1, 2]
    report = client.get(f"/api/v1/research/backtests/{job_id}/report")
    assert report.status_code == 200
    assert report.json()["metrics"]["ending_equity"] == "1044.04"
    with engine.connect() as connection:
        statuses = tuple(
            connection.scalars(
                sa.select(phase2_backtest_job_events.c.status)
                .where(phase2_backtest_job_events.c.job_id == job_id)
                .order_by(phase2_backtest_job_events.c.sequence_number)
            )
        )
    assert statuses == ("queued", "running", "completed")


def test_backtest_routes_fail_closed_without_durable_persistence() -> None:
    client = TestClient(create_app(Settings()))
    bootstrap = client.get("/api/v1/ui/bootstrap").json()

    assert bootstrap["backtest_launch"]["enabled"] is False
    assert bootstrap["backtest_launch"]["csrf_token"] is None
    assert client.get("/api/v1/research/strategies").status_code == 503
    assert client.get("/api/v1/research/backtests").status_code == 503


def test_durable_launch_remains_disabled_without_local_authentication(tmp_path: Path) -> None:
    engine, _, job_input = _configured_engine(tmp_path)
    client = TestClient(create_app(Settings(local_auth_enabled=False), engine=engine))
    capability = client.get("/api/v1/ui/bootstrap").json()["backtest_launch"]

    assert capability["enabled"] is False
    assert capability["csrf_token"] is None
    response = client.post(
        "/api/v1/research/backtests",
        json=_launch_body(job_input),
        headers={
            "X-CSRF-Token": "x" * 43,
            "Idempotency-Key": "phase2-disabled-auth-001",
        },
    )
    assert response.status_code == 403


def test_openapi_declares_local_cookie_security_and_bounded_launch_contract() -> None:
    client = TestClient(create_app(Settings()))
    document = client.get("/openapi.json").json()
    paths = document["paths"]
    launch = paths["/api/v1/research/backtests"]["post"]

    assert "/api/v1/research/strategies" in paths
    assert "/api/v1/research/backtests/{job_id}" in paths
    assert "/api/v1/research/backtests/{job_id}/report" in paths
    assert launch["security"] == [{"LocalOperatorSession": []}]
    assert document["components"]["securitySchemes"]["LocalOperatorSession"] == {
        "type": "apiKey",
        "description": "URL-safe, server-issued local session value",
        "in": "cookie",
        "name": "aqt_local_session",
    }
    parameters = {parameter["name"]: parameter for parameter in launch["parameters"]}
    assert parameters["X-CSRF-Token"]["required"] is True
    assert parameters["Idempotency-Key"]["required"] is True
    launch_schema = document["components"]["schemas"]["BacktestLaunchRequest"]
    assert launch_schema["additionalProperties"] is False
    job_schema = document["components"]["schemas"]["BacktestJobView"]
    assert "history" in job_schema["required"]
    assert job_schema["properties"]["history"]["items"] == {
        "$ref": "#/components/schemas/BacktestJobEventView"
    }

    preflight = client.options(
        "/api/v1/research/backtests",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-csrf-token,idempotency-key",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-methods"] == "GET, POST"
    allowed_headers = preflight.headers["access-control-allow-headers"].lower()
    assert "x-csrf-token" in allowed_headers
    assert "idempotency-key" in allowed_headers
