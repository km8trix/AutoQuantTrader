from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from apps.api.config import Settings
from apps.api.experiment_views import create_experiment_router
from apps.api.main import create_app
from packages.domain.experiment_governance import (
    ExperimentAttemptStatus,
    ExperimentGovernanceSnapshot,
    GovernedSegmentEvaluationReceipt,
)
from packages.domain.experiment_registry import EvaluationSegmentKind
from packages.persistence.backtest_workflow import SqlBacktestWorkflow
from packages.persistence.database import create_database_engine
from packages.persistence.experiment_governance import (
    ExperimentGovernanceNotFound,
    SqlExperimentGovernance,
)
from packages.persistence.schema import phase3_experiment_families
from tests.unit.test_experiment_governance import (
    FIRST_ATTEMPT_AT,
    GovernanceFixture,
    _complete_latest,
    _fixture,
    _request,
    _revealed_snapshot,
    _target_certification,
    _terminate_latest,
)

ROOT = Path(__file__).resolve().parents[2]

EVALUATION_RECEIPT_FIELDS = {
    "evidence_kind",
    "family_id",
    "attempt_id",
    "receipt_sha256",
    "strategy_version_sha256",
    "configuration_sha256",
    "configuration_validation_sha256",
    "segment_kind",
    "segment_sha256",
    "source_evidence_sha256",
    "holdout_reveal_sha256",
    "feature_certification_sha256",
    "target_policy_sha256",
    "target_runtime_pin_sha256",
    "target_certification_sha256",
    "batch_result_sha256",
    "incremental_result_sha256",
    "target_parity_receipt_sha256",
    "target_transcript_sha256",
    "step_count",
    "target_count",
    "running_event_sha256",
    "started_at",
    "completed_at",
    "evaluated_by",
}


@dataclass(slots=True)
class _QueryStub:
    snapshots: tuple[ExperimentGovernanceSnapshot, ...]
    last_limit: int | None = None

    def families(self, *, limit: int = 100) -> tuple[ExperimentGovernanceSnapshot, ...]:
        self.last_limit = limit
        return self.snapshots[:limit]

    def get(self, family_id: str) -> ExperimentGovernanceSnapshot:
        for snapshot in self.snapshots:
            if snapshot.family_id == family_id:
                return snapshot
        raise ExperimentGovernanceNotFound("unknown experiment family")


def _query_client(
    *snapshots: ExperimentGovernanceSnapshot,
) -> tuple[TestClient, _QueryStub]:
    repository = _QueryStub(tuple(snapshots))
    app = FastAPI()
    router = APIRouter(prefix="/api/v1")
    router.include_router(
        create_experiment_router(
            repository=repository,
            persistence_ready=lambda: True,
        )
    )
    app.include_router(router)
    return TestClient(app), repository


def _all_statuses_snapshot(
    fixture: GovernanceFixture,
) -> ExperimentGovernanceSnapshot:
    snapshot = ExperimentGovernanceSnapshot.empty(fixture.family)
    current_time = FIRST_ATTEMPT_AT

    snapshot = _request(
        snapshot,
        fixture,
        kind=EvaluationSegmentKind.TRAIN,
        requested_at=current_time,
    )

    current_time += timedelta(minutes=1)
    snapshot = _request(
        snapshot,
        fixture,
        kind=EvaluationSegmentKind.TRAIN,
        requested_at=current_time,
    )
    current_time += timedelta(minutes=1)
    snapshot = snapshot.transition_attempt(
        snapshot.attempts[-1].attempt_id,
        status=ExperimentAttemptStatus.RUNNING,
        occurred_at=current_time,
        actor_id="phase3c-worker",
    )

    current_time += timedelta(minutes=1)
    snapshot = _request(
        snapshot,
        fixture,
        kind=EvaluationSegmentKind.VALIDATION,
        requested_at=current_time,
    )
    snapshot = _complete_latest(
        snapshot,
        fixture,
        started_at=current_time + timedelta(minutes=1),
        completed_at=current_time + timedelta(minutes=2),
    )
    current_time += timedelta(minutes=3)

    for terminal_status in (
        ExperimentAttemptStatus.FAILED,
        ExperimentAttemptStatus.CANCELED,
        ExperimentAttemptStatus.ABANDONED,
    ):
        snapshot = _request(
            snapshot,
            fixture,
            kind=EvaluationSegmentKind.TRAIN,
            requested_at=current_time,
        )
        current_time += timedelta(minutes=1)
        snapshot = _terminate_latest(
            snapshot,
            status=terminal_status,
            occurred_at=current_time,
        )
        current_time += timedelta(minutes=1)
    return snapshot


def _migrated_engine(tmp_path: Path) -> Engine:
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/phase3-api.sqlite")
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option(
        "sqlalchemy.url",
        engine.url.render_as_string(hide_password=False).replace("%", "%%"),
    )
    command.upgrade(config, "head")
    return engine


def _register_fixture(
    engine: Engine,
    fixture: GovernanceFixture,
) -> ExperimentGovernanceSnapshot:
    SqlBacktestWorkflow(engine).register_strategy(
        version=fixture.family.strategy_version,
        configuration=fixture.configuration,
        display_name=fixture.family.family_name,
        parameter_schema_payload=fixture.schema_payload,
    )
    registered = SqlExperimentGovernance(engine).register_family(
        fixture.family,
        actor_id="phase3c-owner",
        idempotency_key="register-phase3c-family",
        registered_at=fixture.family.created_at,
    )
    assert type(registered) is ExperimentGovernanceSnapshot
    return registered


def test_query_routes_are_bounded_get_only_and_preserve_repository_order() -> None:
    fixture = _fixture()
    first = ExperimentGovernanceSnapshot.empty(fixture.family)
    second = ExperimentGovernanceSnapshot.empty(
        replace(fixture.family, family_name="phase3c-second-family")
    )
    client, repository = _query_client(second, first)

    response = client.get("/api/v1/research/experiments?limit=1")
    assert response.status_code == 200
    assert repository.last_limit == 1
    assert [item["family_id"] for item in response.json()["experiments"]] == [second.family_id]
    assert client.get("/api/v1/research/experiments?limit=0").status_code == 422
    assert client.get("/api/v1/research/experiments?limit=501").status_code == 422

    detail = client.get(f"/api/v1/research/experiments/{first.family_id}")
    assert detail.status_code == 200
    assert detail.json()["experiment"]["summary"]["family_id"] == first.family_id
    assert detail.json()["experiment"]["summary"]["remaining_pre_holdout_attempts"] == (
        fixture.family.promotion_criteria.maximum_pre_holdout_trials
    )
    assert client.get("/api/v1/research/experiments/not-a-digest").status_code == 422
    assert client.get(f"/api/v1/research/experiments/{'f' * 64}").status_code == 404
    assert client.post("/api/v1/research/experiments", json={}).status_code == 405

    paths = client.app.openapi()["paths"]
    assert set(paths["/api/v1/research/experiments"]) == {"get"}
    assert set(paths["/api/v1/research/experiments/{family_id}"]) == {"get"}


def test_detail_projects_safe_evaluation_receipt_without_disclosing_payload() -> None:
    fixture = _fixture(maximum_trials=6)
    snapshot = _all_statuses_snapshot(fixture)
    client, _ = _query_client(snapshot)

    response = client.get(f"/api/v1/research/experiments/{snapshot.family_id}")
    assert response.status_code == 200
    experiment = response.json()["experiment"]
    summary = experiment["summary"]
    assert summary["pre_holdout_attempt_count"] == 6
    assert summary["remaining_pre_holdout_attempts"] == 0
    assert summary["attempt_count"] == 6
    assert summary["holdout_state"] == "sealed"
    assert [attempt["status"] for attempt in experiment["attempts"]] == [
        status.value for status in ExperimentAttemptStatus
    ]
    assert [
        event["status"] for attempt in experiment["attempts"] for event in attempt["history"]
    ] == [
        "queued",
        "queued",
        "running",
        "queued",
        "running",
        "completed",
        "queued",
        "failed",
        "queued",
        "canceled",
        "queued",
        "abandoned",
    ]
    completed_event = next(
        event
        for event in snapshot.lifecycle_events
        if event.status is ExperimentAttemptStatus.COMPLETED
    )
    receipt = completed_event.terminal_evidence
    assert type(receipt) is GovernedSegmentEvaluationReceipt
    completed_event_view = next(
        event
        for attempt in experiment["attempts"]
        for event in attempt["history"]
        if event["status"] == "completed"
    )
    evaluation = completed_event_view["evaluation"]
    assert set(evaluation) == EVALUATION_RECEIPT_FIELDS
    assert evaluation == {
        "evidence_kind": receipt.evidence_kind,
        "family_id": receipt.family_id,
        "attempt_id": receipt.attempt_id,
        "receipt_sha256": receipt.semantic_sha256,
        "strategy_version_sha256": receipt.strategy_version_sha256,
        "configuration_sha256": receipt.configuration_sha256,
        "configuration_validation_sha256": receipt.configuration_validation_sha256,
        "segment_kind": receipt.segment_kind.value,
        "segment_sha256": receipt.segment_sha256,
        "source_evidence_sha256": receipt.source_evidence_sha256,
        "holdout_reveal_sha256": receipt.holdout_reveal_sha256,
        "feature_certification_sha256": receipt.feature_certification_sha256,
        "target_policy_sha256": receipt.target_policy_sha256,
        "target_runtime_pin_sha256": receipt.target_runtime_pin_sha256,
        "target_certification_sha256": receipt.target_certification_sha256,
        "batch_result_sha256": receipt.batch_result_sha256,
        "incremental_result_sha256": receipt.incremental_result_sha256,
        "target_parity_receipt_sha256": receipt.target_parity_receipt_sha256,
        "target_transcript_sha256": receipt.target_transcript_sha256,
        "step_count": receipt.step_count,
        "target_count": receipt.target_count,
        "running_event_sha256": receipt.running_event_sha256,
        "started_at": receipt.started_at.isoformat().replace("+00:00", "Z"),
        "completed_at": receipt.completed_at.isoformat().replace("+00:00", "Z"),
        "evaluated_by": receipt.evaluated_by,
    }
    assert all(
        event["evaluation"] is None
        for attempt in experiment["attempts"]
        for event in attempt["history"]
        if event["status"] != "completed"
    )

    test_segment = next(segment for segment in experiment["segments"] if segment["kind"] == "test")
    declared_test = fixture.family.segment(EvaluationSegmentKind.TEST)
    assert test_segment["segment_sha256"] is None
    assert test_segment["dataset_replay_sha256"] is None
    assert test_segment["coverage_start"] == (
        declared_test.coverage_start.isoformat().replace("+00:00", "Z")
    )
    assert test_segment["coverage_end"] == (
        declared_test.coverage_end.isoformat().replace("+00:00", "Z")
    )
    assert test_segment["purge_before"] == "PT0S"
    assert test_segment["embargo_after"] == "PT0S"
    assert experiment["holdout"] == {
        "state": "sealed",
        "commitment_sha256": fixture.family.test_commitment.semantic_sha256,
        "authorization_sha256": None,
        "reveal_sha256": None,
        "selected_configuration_sha256": None,
        "pre_reveal_snapshot_sha256": None,
        "pre_reveal_registry_head_sha256": None,
        "pre_reveal_attempts_sha256": None,
        "pre_reveal_attempt_count": None,
        "revealed_at": None,
        "revealed_by": None,
        "access_reason": None,
    }
    encoded = response.text
    test_evidence = fixture.family.test_commitment.require_certification(
        fixture.family.segment(EvaluationSegmentKind.TEST),
        fixture.test_certification,
    )
    assert test_evidence.semantic_sha256 not in encoded
    assert declared_test.semantic_sha256 not in encoded
    assert declared_test.dataset_replay_sha256 not in encoded
    assert fixture.family.test_commitment.feature_certification_commitment_sha256 not in encoded
    for forbidden_name in (
        "test_evidence",
        "canonical_payload",
        "evidence_payload",
        "transcript_contents",
        "target_steps",
        "target_values",
        "positions",
        "returns",
        "pnl",
        "promotion_decision",
    ):
        assert forbidden_name not in encoded


def test_revealed_detail_exposes_receipts_but_never_test_payload() -> None:
    fixture = _fixture()
    snapshot = _revealed_snapshot(fixture)
    reveal = snapshot.holdout_reveal
    assert reveal is not None
    snapshot = _request(
        snapshot,
        fixture,
        kind=EvaluationSegmentKind.TEST,
        requested_at=FIRST_ATTEMPT_AT + timedelta(minutes=4),
    )
    test_attempt = snapshot.attempts[-1]
    snapshot = snapshot.transition_attempt(
        test_attempt.attempt_id,
        status=ExperimentAttemptStatus.RUNNING,
        occurred_at=FIRST_ATTEMPT_AT + timedelta(minutes=5),
        actor_id="phase3c-worker",
    )
    snapshot = snapshot.complete_attempt(
        test_attempt.attempt_id,
        _target_certification(fixture.test_certification, fixture.configuration),
        completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=6),
        actor_id="phase3c-worker",
    )
    receipt = snapshot.latest_event(test_attempt.attempt_id).terminal_evidence
    assert type(receipt) is GovernedSegmentEvaluationReceipt
    client, _ = _query_client(snapshot)

    response = client.get(f"/api/v1/research/experiments/{snapshot.family_id}")
    assert response.status_code == 200
    experiment = response.json()["experiment"]
    holdout = experiment["holdout"]
    assert holdout["state"] == "revealed"
    assert experiment["summary"]["remaining_pre_holdout_attempts"] == 0
    assert holdout["commitment_sha256"] == fixture.family.test_commitment.semantic_sha256
    assert holdout["authorization_sha256"] == reveal.authorization.semantic_sha256
    assert holdout["reveal_sha256"] == reveal.semantic_sha256
    assert holdout["selected_configuration_sha256"] == (fixture.configuration.semantic_sha256)
    test_segment = next(segment for segment in experiment["segments"] if segment["kind"] == "test")
    declared_test = fixture.family.segment(EvaluationSegmentKind.TEST)
    assert test_segment["segment_sha256"] == declared_test.semantic_sha256
    assert test_segment["dataset_replay_sha256"] == declared_test.dataset_replay_sha256
    test_attempt_view = next(
        attempt
        for attempt in experiment["attempts"]
        if attempt["attempt_id"] == test_attempt.attempt_id
    )
    evaluation = test_attempt_view["history"][-1]["evaluation"]
    assert set(evaluation) == EVALUATION_RECEIPT_FIELDS
    assert evaluation["segment_kind"] == "test"
    assert evaluation["holdout_reveal_sha256"] == reveal.semantic_sha256
    assert evaluation["source_evidence_sha256"] == reveal.test_evidence.semantic_sha256
    for digest_field in (field for field in EVALUATION_RECEIPT_FIELDS if field.endswith("_sha256")):
        assert evaluation[digest_field] == getattr(receipt, digest_field)
    assert evaluation["step_count"] == receipt.step_count
    assert evaluation["target_count"] == receipt.target_count

    encoded = response.text
    for forbidden_name in (
        "test_evidence",
        "feature_certification_commitment_sha256",
        "canonical_payload",
        "evidence_payload",
        "transcript_contents",
        "target_steps",
        "target_values",
        "positions",
        "returns",
        "pnl",
        "promotion_decision",
    ):
        assert forbidden_name not in encoded


def test_durable_app_reads_registered_family_and_fails_closed_on_corruption(
    tmp_path: Path,
) -> None:
    engine = _migrated_engine(tmp_path)
    fixture = _fixture()
    snapshot = _register_fixture(engine, fixture)
    client = TestClient(create_app(Settings(), engine=engine))

    bootstrap = client.get("/api/v1/ui/bootstrap")
    assert "experiment-governance-query" in bootstrap.json()["capabilities"]
    assert bootstrap.json()["feature_flags"]["experiment_query"] is True
    listing = client.get("/api/v1/research/experiments")
    assert listing.status_code == 200
    assert [item["family_id"] for item in listing.json()["experiments"]] == [snapshot.family_id]
    assert client.get(f"/api/v1/research/experiments/{snapshot.family_id}").status_code == 200

    with engine.begin() as connection:
        connection.execute(
            sa.update(phase3_experiment_families)
            .where(phase3_experiment_families.c.family_id == snapshot.family_id)
            .values(evidence_payload="{}")
        )
    corrupted = client.get(f"/api/v1/research/experiments/{snapshot.family_id}")
    assert corrupted.status_code == 503
    assert corrupted.json() == {
        "detail": "durable experiment-governance persistence is unavailable"
    }


def test_ephemeral_and_malformed_queries_fail_closed() -> None:
    ephemeral = create_database_engine("sqlite+pysqlite:///:memory:")
    client = TestClient(create_app(Settings(), engine=ephemeral))
    response = client.get("/api/v1/research/experiments")
    assert response.status_code == 503
    assert response.json() == {"detail": "durable experiment-governance persistence is unavailable"}

    class _MalformedQuery(_QueryStub):
        def families(  # type: ignore[override]
            self,
            *,
            limit: int = 100,
        ) -> tuple[ExperimentGovernanceSnapshot, ...]:
            del limit
            return ("not-a-snapshot",)  # type: ignore[return-value]

    malformed = _MalformedQuery(())
    app = FastAPI()
    app.include_router(
        create_experiment_router(
            repository=malformed,
            persistence_ready=lambda: True,
        ),
        prefix="/api/v1",
    )
    malformed_response = TestClient(app).get("/api/v1/research/experiments")
    assert malformed_response.status_code == 503
    assert malformed_response.json() == {
        "detail": "experiment families are unavailable or malformed"
    }


def test_openapi_contract_has_no_experiment_mutation_or_holdout_evidence() -> None:
    client, _ = _query_client(ExperimentGovernanceSnapshot.empty(_fixture().family))
    schema = client.app.openapi()
    schemas = schema["components"]["schemas"]
    paths = schema["paths"]

    assert set(paths["/api/v1/research/experiments"]) == {"get"}
    assert set(paths["/api/v1/research/experiments/{family_id}"]) == {"get"}
    assert set(schemas["ExperimentHoldoutView"]["properties"]) == {
        "state",
        "commitment_sha256",
        "authorization_sha256",
        "reveal_sha256",
        "selected_configuration_sha256",
        "pre_reveal_snapshot_sha256",
        "pre_reveal_registry_head_sha256",
        "pre_reveal_attempts_sha256",
        "pre_reveal_attempt_count",
        "revealed_at",
        "revealed_by",
        "access_reason",
    }
    assert set(schemas["ExperimentEvaluationReceiptView"]["properties"]) == (
        EVALUATION_RECEIPT_FIELDS
    )
    segment_properties = schemas["ExperimentSegmentView"]["properties"]
    assert {"type": "null"} in segment_properties["segment_sha256"]["anyOf"]
    assert {"type": "null"} in segment_properties["dataset_replay_sha256"]["anyOf"]
    evaluation_properties = schemas["ExperimentEvaluationReceiptView"]["properties"]
    assert evaluation_properties["step_count"]["minimum"] == 1
    assert evaluation_properties["step_count"]["maximum"] == 100_000
    assert evaluation_properties["target_count"]["minimum"] == 0
    assert evaluation_properties["target_count"]["maximum"] == 100_000
    assert evaluation_properties["evaluated_by"]["maxLength"] == 128
    assert set(schemas["ExperimentAttemptEventView"]["properties"]) == {
        "event_sha256",
        "global_sequence_number",
        "attempt_sequence_number",
        "status",
        "occurred_at",
        "actor_id",
        "terminal_evidence_sha256",
        "terminal_reason_code",
        "evaluation",
    }
    for forbidden_field in (
        "canonical_payload",
        "transcript",
        "transcript_contents",
        "steps",
        "targets",
        "positions",
        "returns",
        "pnl",
        "promotion",
        "promotion_decision",
        "strategy_code_sha256",
    ):
        assert forbidden_field not in EVALUATION_RECEIPT_FIELDS
    encoded_schema = str(
        {name: value for name, value in schemas.items() if name.startswith("Experiment")}
    )
    assert "test_evidence" not in encoded_schema
    assert "certification_commitment" not in encoded_schema
