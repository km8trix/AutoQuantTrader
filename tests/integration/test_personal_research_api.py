"""Actual W2 economics behind local API/SQL fixtures; no process or browser claim."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from threading import Barrier, Lock

import pytest
import sqlalchemy as sa
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient

from apps.api import personal_research_service as service_module
from apps.api.backtest_views import (
    CSRF_HEADER,
    IDEMPOTENCY_HEADER,
    LOCAL_SESSION_COOKIE,
    LocalOperatorSecurity,
)
from apps.api.personal_research_service import PersonalResearchService
from apps.api.personal_research_views import create_personal_research_router
from packages.adapters.personal_build import current_build_pins
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.application.causal_engine import run_causal_engine
from packages.application.personal_inputs import synthetic_engine_inputs
from packages.application.reference_strategy import ReferenceStrategy
from packages.application.research_catalog import StoredResearchInputResolver, create_catalog_entry
from packages.application.research_dataset import research_dataset_to_json_bytes
from packages.application.research_worker_v2 import process_one_research_job
from packages.application.run_report import build_report_artifact, build_run_report
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.engine_contracts import DailyPrice
from packages.domain.personal_evaluation import PriorAccessDeclaration
from packages.domain.report_contracts import ReportArtifact
from packages.domain.research_job_contracts import MAX_INPUT_BYTES, ResearchExecutionOutcome
from packages.persistence.research_catalog import ResearchCatalogConflict, SqlResearchCatalog
from packages.persistence.research_catalog_schema import RESEARCH_CATALOG_TABLES
from packages.persistence.research_schema_v2 import RESEARCH_TABLES_V2, research_jobs_v2
from packages.persistence.research_workflow_v2 import SqlResearchWorkflow
from packages.persistence.schema import metadata
from tests.unit.test_research_catalog import real_class_fixture

PREFIX = "/api/v1/research/personal"


class ActualEngineRunner:
    """Only the process boundary is replaced; accounting, strategy and report are real."""

    def run(self, execution, *, control):
        inputs = execution.inputs
        result = run_causal_engine(
            inputs,
            accounting=PersonalAccounting(),
            strategy=ReferenceStrategy(
                reserve_fraction=inputs.spec.risk_policy.adverse_reserve_fraction,
                fee_per_share=inputs.spec.execution_policy.fee_per_share,
            ),
        )
        report = build_run_report(result, execution.request.conventions)
        return ResearchExecutionOutcome(
            report.status,
            build_report_artifact(
                report, attempt_id=execution.claim.attempt_id, generated_at=datetime.now(UTC)
            ),
        )


@pytest.fixture
def api(tmp_path):
    database = tmp_path / "private.sqlite"
    database.touch(mode=0o600)
    engine = sa.create_engine(f"sqlite+pysqlite:///{database}")

    @sa.event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")

    metadata.create_all(engine, tables=(*RESEARCH_TABLES_V2, *RESEARCH_CATALOG_TABLES))
    workflow = SqlResearchWorkflow(engine, codec=personal_codec)
    catalog = SqlResearchCatalog(engine, codec=personal_codec, workflow=workflow)
    artifacts = LocalResearchArtifactStore(tmp_path / "objects")
    source = synthetic_engine_inputs(
        fixture="flat",
        pins=current_build_pins(),
        session_count=18,
        warmup_count=2,
        configuration=ReferenceConfiguration("buy_hold", 2),
    )
    entry = create_catalog_entry(
        display_name="generated flat acceptance fixture",
        prior_access=PriorAccessDeclaration(
            "known_accessed",
            datetime.now(UTC),
            "local-owner",
            "Synthetic engineering formula, already inspected",
        ),
        source=source,
        source_inputs=artifacts.put(
            personal_codec.encode_record(source), max_bytes=MAX_INPUT_BYTES
        ),
        archive=None,
        settlement_calendar=artifacts.put(
            personal_codec.encode_record(source.spec.execution_policy.settlement_calendar)
        ),
    )
    catalog.register(entry, owner_id="local-owner")
    service = PersonalResearchService(workflow, catalog, artifacts, owner_id="local-owner")
    security = LocalOperatorSecurity(
        enabled=True,
        transport_is_loopback_scoped=True,
        operator_id="local-owner",
        configured_secret="public-test-fixture-not-a-provider-secret",
    )
    app = FastAPI()
    app.include_router(
        create_personal_research_router(service=service, security=security), prefix="/api/v1"
    )

    @app.get("/api/v1/test-session")
    def session(request: Request, response: Response):
        return security.bootstrap_capability(
            response,
            persistence_ready=True,
            issued_at=datetime.now(UTC),
            session_cookie=request.cookies.get(LOCAL_SESSION_COOKIE),
        )

    with TestClient(app) as client:
        token = client.get("/api/v1/test-session").json()["csrf_token"]
        yield {
            "client": client,
            "headers": {CSRF_HEADER: token},
            "service": service,
            "workflow": workflow,
            "catalog": catalog,
            "artifacts": artifacts,
            "source": source,
            "entry": entry,
            "engine": engine,
            "security": security,
        }
    engine.dispose()


def run_request(api, *, cost="base_1x"):
    days = api["source"].spec.calendar.sessions
    return {
        "dataset_id": api["entry"].catalog_id,
        "dataset_manifest_sha256": api["entry"].dataset_sha256,
        "strategy_id": "buy_hold",
        "strategy_version": "personal-daily-reference/1",
        "configuration": {
            "kind": "buy_hold",
            "lookback": 3,
            "allocation": "0.25",
            "rebalance_sessions": None,
        },
        "initial_cash": "10000",
        "warmup_sessions": 3,
        "scored_start": days[3].session_label.isoformat(),
        "scored_end": days[11].session_label.isoformat(),
        "cost_scenario_id": cost,
    }


def post(api, path, body, key):
    return api["client"].post(
        PREFIX + path, json=body, headers={**api["headers"], IDEMPOTENCY_HEADER: key}
    )


def work_one(api):
    return process_one_research_job(
        api["workflow"],
        worker_id="api-test-worker",
        worker_instance_id="api-test-process-boundary",
        resolver=StoredResearchInputResolver(api["artifacts"]),
        runner=ActualEngineRunner(),
        artifacts=api["artifacts"],
        codec=personal_codec,
    )


def test_authenticated_launch_actual_engine_report_rows_export_and_idempotent_retry(
    api, monkeypatch
):
    client = api["client"]
    catalog = client.get(PREFIX + "/catalog")
    assert (
        catalog.status_code == 200
        and catalog.json()["datasets"][0]["dataset_id"] == api["entry"].catalog_id
    )
    assert [c["scenario_id"] for c in catalog.json()["cost_scenarios"]] == [
        "base_1x",
        "base_2x",
        "base_3x",
        "adverse",
    ]
    request = run_request(api)
    accepted = post(api, "/runs", request, "launch-0001")
    assert accepted.status_code == 202, accepted.text
    job_id = accepted.json()["job_id"]
    assert accepted.json()["dataset_id"] == api["source"].spec.dataset_id
    assert client.get(PREFIX + f"/runs/{job_id}/report").status_code == 409
    completed = work_one(api)
    assert completed is not None and completed.status == "completed", completed
    report = client.get(PREFIX + f"/runs/{job_id}/report")
    assert report.status_code == 200, report.text
    assert (
        next(m["value"] for m in report.json()["metrics"] if m["name"] == "ending_equity")
        == "9998.56"
    )
    digest = report.json()["report_sha256"]
    page = client.get(
        PREFIX + f"/runs/{job_id}/rows",
        params={"kind": "equity", "report_sha256": digest, "offset": 1, "limit": 2},
    )
    assert page.status_code == 200 and len(page.json()["rows"]) == 2
    assert (
        client.get(
            PREFIX + f"/runs/{job_id}/rows", params={"kind": "equity", "report_sha256": "b" * 64}
        ).status_code
        == 409
    )
    exported = client.get(report.json()["export_url"])
    assert exported.status_code == 200 and exported.headers["cache-control"] == "no-store"
    artifact = personal_codec.decode_record(exported.content, ReportArtifact)
    assert artifact.report.semantic_sha256 == digest
    monkeypatch.setattr(
        service_module,
        "current_build_pins",
        lambda: pytest.fail("idempotent retry rebuilt the source"),
    )
    monkeypatch.setattr(
        service_module,
        "resolve_catalog_inputs",
        lambda *a, **k: pytest.fail("idempotent retry reloaded source"),
    )
    retried = post(api, "/runs", request, "launch-0001")
    assert (
        retried.status_code == 202
        and retried.json()["job_id"] == job_id
        and retried.json()["status"] == "completed"
    )
    changed = {**request, "initial_cash": "20000"}
    assert post(api, "/runs", changed, "launch-0001").status_code == 409


def test_unauthenticated_mutations_owner_scope_and_disabled_service_fail_closed(api):
    client = api["client"]
    assert client.post(PREFIX + "/runs", json=run_request(api)).status_code == 422
    assert (
        client.post(
            PREFIX + "/runs",
            json=run_request(api),
            headers={CSRF_HEADER: "wrong", IDEMPOTENCY_HEADER: "wrong-csrf-1"},
        ).status_code
        == 403
    )
    accepted = post(api, "/runs", run_request(api), "owner-scope-1")
    assert accepted.status_code == 202
    job = accepted.json()["job_id"]
    foreign = PersonalResearchService(
        api["workflow"], api["catalog"], api["artifacts"], owner_id="other-owner"
    )
    foreign_app = FastAPI()
    foreign_app.include_router(
        create_personal_research_router(service=foreign, security=api["security"]), prefix="/api/v1"
    )
    with TestClient(foreign_app) as other:
        assert other.get(PREFIX + f"/runs/{job}").status_code == 404
        assert other.get(PREFIX + f"/runs/{job}/report").status_code == 404
        assert other.get(PREFIX + "/runs").json()["jobs"] == []
    assert client.get(PREFIX + "/runs/" + "f" * 64).status_code == 404
    cancelled = post(api, f"/runs/{job}/cancel", None, "cancel-0001")
    assert cancelled.status_code == 202 and cancelled.json()["status"] == "cancelled"
    disabled = PersonalResearchService(
        api["workflow"],
        api["catalog"],
        api["artifacts"],
        owner_id="local-owner",
        mutations_enabled=False,
    )
    assert not disabled.catalog().launch.enabled
    from apps.api.personal_research_contracts import PersonalRunRequest

    with pytest.raises(ValueError):
        disabled.launch(
            PersonalRunRequest.model_validate(run_request(api)),
            owner_id="local-owner",
            key="disabled-1",
        )


def test_actual_cost_comparison_route_preserves_each_report_and_basis(api):
    first = post(api, "/runs", run_request(api), "compare-base-1")
    second = post(api, "/runs", run_request(api, cost="adverse"), "compare-adverse-1")
    assert first.status_code == second.status_code == 202
    identities = [first.json()["job_id"], second.json()["job_id"]]
    for _ in range(2):
        assert work_one(api).status == "completed"
    result = api["client"].post(PREFIX + "/comparison", json={"job_ids": identities})
    assert result.status_code == 200, result.text
    body = result.json()
    assert body["comparable"] and not body["reasons"]
    assert [run["cost_scenario_id"] for run in body["runs"]] == ["base_1x", "adverse"]
    assert [
        next(m["value"] for m in run["metrics"] if m["name"] == "ending_equity")
        for run in body["runs"]
    ] == ["9998.56", "9994.72"]


@pytest.mark.parametrize("change", ("manifest", "strategy", "gap", "warmup", "cost"))
def test_invalid_launch_does_not_create_jobs(api, change):
    body = run_request(api)
    if change == "manifest":
        body["dataset_manifest_sha256"] = "b" * 64
    elif change == "strategy":
        body["strategy_id"] = "trend_sma"
    elif change == "gap":
        body["scored_start"] = "2023-01-07"
    elif change == "warmup":
        body["warmup_sessions"] = 252
    else:
        body["cost_scenario_id"] = "zero-cost"
    result = post(api, "/runs", body, "invalid-" + change)
    assert result.status_code in (400, 409), result.text
    assert api["workflow"].jobs(owner_id="local-owner") == ()


@pytest.mark.parametrize("boundary", ("defaults", "explicit_final_day", "warmup_exhausts"))
def test_archive_default_scoring_reserves_the_final_retained_calendar_session(
    api, tmp_path, boundary
):
    # Generated owner-export bytes exercise archive provenance, not real market accuracy.
    dataset, source = real_class_fixture(tmp_path)
    days = tuple(session.session_label for session in source.spec.calendar.sessions)
    assert (
        max(
            event.payload.session
            for event in source.events
            if isinstance(event.payload, DailyPrice)
        )
        == days[-1]
    )
    entry = create_catalog_entry(
        display_name="generated five-session archive boundary",
        prior_access=api["entry"].prior_access,
        source=source,
        source_inputs=api["artifacts"].put(
            personal_codec.encode_record(source), max_bytes=MAX_INPUT_BYTES
        ),
        archive=api["artifacts"].put(
            research_dataset_to_json_bytes(dataset), codec_version="personal-research-dataset-v1"
        ),
        settlement_calendar=api["artifacts"].put(
            personal_codec.encode_record(source.spec.execution_policy.settlement_calendar)
        ),
    )
    api["catalog"].register(entry, owner_id="local-owner")
    body = {
        **run_request(api),
        "dataset_id": entry.catalog_id,
        "dataset_manifest_sha256": entry.dataset_sha256,
        "warmup_sessions": 1,
        "scored_start": None,
        "scored_end": None,
    }
    if boundary == "explicit_final_day":
        body["scored_end"] = days[-1].isoformat()
    elif boundary == "warmup_exhausts":
        body["warmup_sessions"] = len(days) - 1
    response = post(api, "/runs", body, "archive-window-boundary-1")
    if boundary != "defaults":
        assert response.status_code == 400, response.text
        assert api["workflow"].jobs(owner_id="local-owner") == ()
        return
    assert response.status_code == 202, response.text
    retained = api["workflow"].get_request(response.json()["job_id"])
    assert retained.spec.evaluation.warmup_sessions == days[:1]
    assert retained.spec.evaluation.scored_sessions == days[1:-1]
    assert retained.dataset_archive == entry.archive
    assert retained.spec.calendar == source.spec.calendar
    completed = work_one(api)
    assert completed is not None and completed.status == "completed", completed


def experiment_request(api):
    days = api["source"].spec.calendar.sessions
    return {
        "name": "transparent reference acceptance",
        "hypothesis": "Compare every frozen cost scenario",
        "dataset_id": api["entry"].catalog_id,
        "candidates": [
            {
                "candidate_id": "buy_hold",
                "configuration": {
                    "kind": "buy_hold",
                    "lookback": 2,
                    "allocation": "0.25",
                    "rebalance_sessions": None,
                },
            }
        ],
        "folds": [
            {
                "fold_id": "fold-1",
                "train_start": days[2].session_label.isoformat(),
                "train_end": days[5].session_label.isoformat(),
                "validation_start": days[6].session_label.isoformat(),
                "validation_end": days[9].session_label.isoformat(),
                "test_start": days[10].session_label.isoformat(),
                "test_end": days[13].session_label.isoformat(),
            }
        ],
        "warmup_sessions": 2,
        "prior_access": {
            "status": "known_accessed",
            "description": "Synthetic fixture already inspected; no untouched claim",
        },
    }


def test_experiment_preregisters_every_trial_then_publishes_actual_cost_matrix(api, monkeypatch):
    body = experiment_request(api)
    response = post(api, "/experiments", body, "experiment-0001")
    assert response.status_code == 202, response.text
    payload = response.json()
    identity = payload["experiment_id"]
    assert payload["planned_trial_count"] == 12 and len(payload["trials"]) == 12
    assert {t["window"] for t in payload["trials"]} == {"train", "validation", "test"}
    assert {t["status"] for t in payload["trials"]} == {"queued"}
    assert (
        payload["evaluation_mode"] == "descriptive_only"
        and payload["suitability"] == "not_assessed"
    )
    assert len(api["workflow"].jobs(owner_id="local-owner")) == 12
    for _ in range(12):
        completed = work_one(api)
        assert completed is not None and completed.status == "completed", completed
    result = api["client"].get(PREFIX + f"/experiments/{identity}")
    assert result.status_code == 200, result.text
    expected = {
        "base_1x": "9998.56",
        "base_2x": "9997.12",
        "base_3x": "9995.68",
        "adverse": "9994.72",
    }
    for trial in result.json()["trials"]:
        assert trial["status"] == "completed" and trial["report_sha256"]
        assert (
            next(m["value"] for m in trial["metrics"] if m["name"] == "ending_equity")
            == expected[trial["cost_scenario_id"]]
        )
        assert trial["benchmark_metrics"]
    monkeypatch.setattr(
        service_module, "current_build_pins", lambda: pytest.fail("experiment retry rebuilt pins")
    )
    monkeypatch.setattr(
        service_module,
        "resolve_catalog_inputs",
        lambda *a, **k: pytest.fail("experiment retry reloaded source"),
    )
    assert post(api, "/experiments", body, "experiment-0001").json()["experiment_id"] == identity
    assert (
        post(api, "/experiments", {**body, "hypothesis": "changed"}, "experiment-0001").status_code
        == 409
    )
    # List pages preserve trial states but do not read report blobs.
    monkeypatch.setattr(
        api["service"], "_artifact", lambda *a: pytest.fail("list loaded a report blob")
    )
    listed = api["client"].get(PREFIX + "/experiments")
    assert listed.status_code == 200 and listed.json()["experiments"][0]["status"] == "completed"
    assert all(t["metrics"] == [] for t in listed.json()["experiments"][0]["trials"])


def test_experiment_access_downgrade_and_partial_registration_fail_without_jobs(api, monkeypatch):
    body = experiment_request(api)
    downgraded = {
        **body,
        "prior_access": {"status": "unknown", "description": "Do not hide prior inspection"},
    }
    assert post(api, "/experiments", downgraded, "downgrade-1").status_code == 400
    original = api["workflow"].launch_in_transaction
    calls = []

    def fail_second(connection, request):
        calls.append(request.job_id)
        if len(calls) == 2:
            raise ValueError("deliberate transaction rollback boundary")
        return original(connection, request)

    monkeypatch.setattr(api["workflow"], "launch_in_transaction", fail_second)
    assert post(api, "/experiments", body, "rollback-1").status_code == 400
    with api["engine"].connect() as connection:
        assert (
            connection.execute(
                sa.select(sa.func.count()).select_from(research_jobs_v2)
            ).scalar_one()
            == 0
        )
    assert api["catalog"].experiments(owner_id="local-owner") == ()


@pytest.mark.parametrize("path", ("/runs", "/experiments"))
@pytest.mark.parametrize("same_intent", (True, False))
def test_concurrent_first_submissions_recover_only_the_exact_wire_intent(
    api, monkeypatch, path, same_intent
):
    """Synchronize only the initial reads; real SQL serializes both registrations."""
    experiment = path == "/experiments"
    body = experiment_request(api) if experiment else run_request(api)
    other = dict(body)
    if not same_intent:
        other.update(
            {"hypothesis": "different intent"} if experiment else {"initial_cash": "20000"}
        )
    name = "existing_experiment" if experiment else "existing_launch"
    original = getattr(api["catalog"], name)
    barrier = Barrier(2)
    if not experiment and same_intent:
        # Model two accepted build versions racing for the same browser intent.
        # Their immutable SQL requests must still conflict, then recover the winner.
        pins = api["source"].spec.pins
        versions = iter(
            (
                pins,
                tuple(
                    replace(pin, sha256="b" * 64) if pin.name == "source" else pin for pin in pins
                ),
            )
        )
        version_lock = Lock()

        def observed_build():
            with version_lock:
                return next(versions)

        monkeypatch.setattr(service_module, "current_build_pins", observed_build)

    def simultaneous_first_read(**kwargs):
        retained = original(**kwargs)
        if retained is None:
            barrier.wait(timeout=10)
        return retained

    monkeypatch.setattr(api["catalog"], name, simultaneous_first_read)
    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [
            workers.submit(post, api, path, value, "concurrent-first-1") for value in (body, other)
        ]
        responses = [future.result(timeout=30) for future in futures]
    assert sorted(r.status_code for r in responses) == ([202, 202] if same_intent else [202, 409])
    field = "experiment_id" if experiment else "job_id"
    accepted = next(r.json() for r in responses if r.status_code == 202)
    if same_intent:
        assert {r.json()[field] for r in responses} == {accepted[field]}
    assert len(api["workflow"].jobs(owner_id="local-owner")) == (12 if experiment else 1)
    # Recovery returns the accepted declaration and job inventory on later retries too.
    retry_body = body if responses[0].status_code == 202 else other
    retry = post(api, path, retry_body, "concurrent-first-1")
    assert retry.status_code == 202 and retry.json()[field] == accepted[field]


@pytest.mark.parametrize("path", ("/runs", "/experiments"))
def test_catalog_conflict_without_matching_accepted_intent_is_not_recovered(api, monkeypatch, path):
    def conflict(*args, **kwargs):
        raise ResearchCatalogConflict("deliberate immutable boundary conflict")

    method = "register_experiment" if path == "/experiments" else "launch"
    monkeypatch.setattr(api["catalog"], method, conflict)
    body = experiment_request(api) if path == "/experiments" else run_request(api)
    assert post(api, path, body, "unrecoverable-conflict-1").status_code == 409
    assert api["workflow"].jobs(owner_id="local-owner") == ()
