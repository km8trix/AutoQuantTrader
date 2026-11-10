"""Purpose-scoped metadata access against fresh, genuinely migrated SQL facts.

The account is already selected before main starts or any HTTP session is issued.
Operational readiness remains unavailable; metadata credentials must fail in the
original security decoder at every retained authenticated consumer.
"""

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from apps.api.backtest_views import LOCAL_SESSION_COOKIE
from apps.api.config import Settings
from apps.api.contracts import OperationalControlAction
from apps.api.main import create_app
from apps.api.metadata_access import METADATA_CSRF_HEADER, METADATA_SESSION_COOKIE
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.persistence.account_coordinator import SqlAccountCoordinator
from packages.persistence.continuous_account import SqlContinuousAccount
from packages.persistence.continuous_selection_read_model import SqlContinuousSelectionReadModel
from packages.persistence.daily_runtime_risk_schema import daily_runtime_assignments
from packages.persistence.database import EXPECTED_SCHEMA_REVISION, create_database_engine
from packages.persistence.durable_journal_schema import JOURNAL_TABLES
from packages.persistence.immutable import as_aware_utc
from packages.persistence.schema import metadata
from tests.integration.test_continuous_synthetic_offline_configuration import (
    _exclusive_file,
    _release_setup,
    _rows,
    _study,
)

ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = "/api/v1/ui/metadata-bootstrap"
UNAVAILABLE = {"detail": "continuous selection metadata is unavailable or malformed"}


class NoWriterCalls:
    available_actions = frozenset(action.command_kind for action in OperationalControlAction)

    def execute(self, **_kwargs):
        pytest.fail("metadata credential reached an operational writer")

    def assign(self, **_kwargs):
        pytest.fail("metadata credential reached an advanced-risk writer")

    def launch(self, *_args, **_kwargs):
        pytest.fail("metadata credential reached a personal-run writer")

    def cancel(self, *_args, **_kwargs):
        pytest.fail("metadata credential reached a personal cancellation writer")

    def create_experiment(self, *_args, **_kwargs):
        pytest.fail("metadata credential reached an experiment writer")


def _path(account):
    return f"/api/v1/operations/accounts/{account}/continuous-selection"


def _database_facts(engine):
    with engine.connect() as connection:
        revision = tuple(connection.scalars(sa.text("SELECT version_num FROM alembic_version")))
    return revision, _rows(engine, tuple(metadata.sorted_tables))


def _facts(study):
    return (
        _database_facts(study.ports["account_engine"]),
        _rows(study.ports["venue_engine"], JOURNAL_TABLES),
        tuple(
            tuple(sorted((path.name, path.read_bytes()) for path in study.paths[key].iterdir()))
            for key in ("artifact_root", "venue_artifact_root")
        ),
    )


def _cookie(client, name, value):
    client.cookies.set(name, value, domain="testserver.local", path="/api/v1")


def _read_capability(client):
    before = datetime.now(UTC)
    response = client.get(BOOTSTRAP)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    capability = response.json()
    assert set(capability) == {
        "enabled",
        "operator_id",
        "csrf_token",
        "csrf_header",
        "expires_at",
        "disabled_reason",
        "scope",
        "verification",
    }
    assert capability["enabled"] is True
    assert capability["operator_id"] == "local-operator"
    assert capability["csrf_header"] == METADATA_CSRF_HEADER
    assert capability["scope"] == "continuous-selection-read/1"
    assert capability["verification"] == "row_integrity_only"
    assert capability["disabled_reason"] is None
    assert type(capability["csrf_token"]) is str
    assert 32 <= len(capability["csrf_token"]) <= 128
    assert (
        before
        < datetime.fromisoformat(capability["expires_at"])
        <= (datetime.now(UTC) + timedelta(hours=8))
    )
    assert client.cookies.get(METADATA_SESSION_COOKIE)
    return {METADATA_CSRF_HEADER: capability["csrf_token"]}


@contextmanager
def _selected_api(parent, *, install=True, writer_probes=False):
    with _study(parent, install=install) as study:
        _release_setup(study)
        assert study.genesis.account.coordinator.current() is None
        before = _facts(study)
        if writer_probes:
            writers = NoWriterCalls()
            app = create_app(
                Settings(),
                engine=study.ports["account_engine"],
                operations_control=writers,
                operations_assignment=writers,
                personal_research=writers,
            )
        else:
            app = create_app(Settings(), engine=study.ports["account_engine"])
        assert _facts(study) == before
        assert app.state.persistence_ready is False
        assert app.state.persistence_error == "operational persistence unavailable"
        assert type(app.state.continuous_selection) is SqlContinuousSelectionReadModel
        assert app.state.continuous_selection.engine is study.ports["account_engine"]
        with TestClient(app) as client:
            yield SimpleNamespace(study=study, app=app, client=client)


@pytest.fixture
def selected(tmp_path):
    with _selected_api(tmp_path) as api:
        yield api


@contextmanager
def _empty_api(parent):
    root = parent.resolve() / "empty-metadata-api"
    root.mkdir(mode=0o700)
    path = root / "account.sqlite"
    _exclusive_file(path)
    url = f"sqlite+pysqlite:///{path}"
    migration = Config()
    migration.set_main_option("script_location", str(ROOT / "migrations"))
    migration.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    migration.attributes["aqt_explicit_database_url"] = url
    command.upgrade(migration, EXPECTED_SCHEMA_REVISION)
    engine = create_database_engine(url)
    try:
        app = create_app(Settings(), engine=engine)
        assert app.state.persistence_ready is True
        with TestClient(app) as client:
            yield SimpleNamespace(app=app, client=client, engine=engine)
    finally:
        engine.dispose()


def test_already_selected_main_issues_only_read_capability_and_returns_exact_metadata(selected):
    api, study = selected, selected.study
    before = _facts(study)
    headers = _read_capability(api.client)
    token = api.client.cookies.get(METADATA_SESSION_COOKIE)
    assert api.client.cookies.get(LOCAL_SESSION_COOKIE) is None
    assert api.client.get("/health/ready").status_code == 503
    original = api.client.get("/api/v1/ui/bootstrap")
    assert original.status_code == 200
    original_body = original.json()
    assert original_body["backtest_launch"]["enabled"] is False
    assert original_body["backtest_launch"]["csrf_token"] is None
    for feature in (
        "operations_query",
        "operations_control",
        "controls",
        "control_pause",
        "control_drain",
        "control_flatten",
        "control_halt",
        "control_rearm",
    ):
        assert original_body["feature_flags"][feature] is False
    assert api.client.cookies.get(LOCAL_SESSION_COOKIE) is None
    assert api.client.cookies.get(METADATA_SESSION_COOKIE) == token
    response = api.client.get(_path(study.genesis.scope.account_id), headers=headers)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    payload = response.json()
    assert set(payload) == {"account_id", "state", "checkpoint", "selection", "verification"}
    assert payload["account_id"] == study.genesis.scope.account_id
    assert payload["state"] == "selected" and payload["verification"] == "row_integrity_only"
    assert payload["checkpoint"] == {
        "stream_id": study.genesis.scope.stream_id,
        "sequence": "1",
        "recorded_at": study.genesis.restored.receipt.recorded_at.isoformat().replace(
            "+00:00", "Z"
        ),
    }
    assignment = study.assignment
    with study.ports["account_engine"].connect() as connection:
        recorded = as_aware_utc(
            connection.scalar(sa.select(daily_runtime_assignments.c.recorded_at))
        )
    assert payload["selection"] == {
        "generation": str(assignment.generation),
        "strategy_name": assignment.strategy.name,
        "strategy_version": assignment.strategy.version,
        "configuration_sha256": assignment.configuration_sha256,
        "instruments": [
            {"instrument_id": identifier, "symbol": symbol}
            for identifier, symbol in assignment.instrument_symbols
        ],
        "policy_id": assignment.policy.policy_id,
        "enabled_for_new_exposure": False,
        "live_authorized": False,
        "recorded_at": recorded.isoformat().replace("+00:00", "Z"),
        "effective_at": assignment.effective_at.isoformat().replace("+00:00", "Z"),
    }
    assert (
        api.client.get(_path(study.genesis.scope.account_id), headers=headers).content
        == response.content
    )
    assert api.client.get("/health/ready").status_code == 503
    assert _facts(study) == before
    assert study.genesis.account.coordinator.current() is None


def test_metadata_capability_preserves_absent_and_unselected_shapes(tmp_path):
    with _selected_api(tmp_path, install=False) as api:
        before = _facts(api.study)
        headers = _read_capability(api.client)
        unselected = api.client.get(_path(api.study.genesis.scope.account_id), headers=headers)
        assert unselected.status_code == 200
        payload = unselected.json()
        assert payload["state"] == "unselected" and payload["selection"] is None
        assert payload["checkpoint"]["sequence"] == "1"
        absent = api.client.get(_path("never-created-account"), headers=headers)
        assert absent.status_code == 200
        assert absent.json() == {
            "account_id": "never-created-account",
            "state": "absent",
            "checkpoint": None,
            "selection": None,
            "verification": "row_integrity_only",
        }
        assert api.client.get("/health/ready").status_code == 503
        assert _facts(api.study) == before


@pytest.mark.parametrize("failure", ["missing-cookie", "tampered", "wrong-csrf", "missing-header"])
def test_metadata_auth_denials_precede_any_query(selected, monkeypatch, failure):
    headers = _read_capability(selected.client)
    if failure == "missing-cookie":
        selected.client.cookies.clear()
    elif failure == "tampered":
        token = selected.client.cookies.get(METADATA_SESSION_COOKIE)
        _cookie(selected.client, METADATA_SESSION_COOKIE, token + "0")
    elif failure == "wrong-csrf":
        headers = {METADATA_CSRF_HEADER: "x" * 43}
    elif failure == "missing-header":
        headers = {}
    before = _facts(selected.study)

    def forbidden(*_args, **_kwargs):
        pytest.fail("metadata authentication denial did not precede SQL")

    monkeypatch.setattr(SqlContinuousSelectionReadModel, "read", forbidden)
    response = selected.client.get(_path(selected.study.genesis.scope.account_id), headers=headers)
    expected = 403 if failure == "wrong-csrf" else 422 if failure == "missing-header" else 401
    assert response.status_code == expected
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert _facts(selected.study) == before


def test_foreign_process_nonce_rejects_metadata_credential_before_query(selected, monkeypatch):
    with TestClient(create_app(Settings(), engine=selected.study.ports["account_engine"])) as other:
        headers = _read_capability(other)
        _cookie(
            selected.client, METADATA_SESSION_COOKIE, other.cookies.get(METADATA_SESSION_COOKIE)
        )
    before = _facts(selected.study)

    def forbidden(*_args, **_kwargs):
        pytest.fail("a foreign metadata signature reached SQL")

    monkeypatch.setattr(SqlContinuousSelectionReadModel, "read", forbidden)
    response = selected.client.get(_path(selected.study.genesis.scope.account_id), headers=headers)
    assert response.status_code == 401
    assert _facts(selected.study) == before


@pytest.mark.parametrize("first", ["metadata", "operational"])
def test_bootstraps_and_mixed_cookies_preserve_independent_capabilities(tmp_path, first):
    with _empty_api(tmp_path) as api:
        before = _database_facts(api.engine)
        if first == "metadata":
            metadata_headers = _read_capability(api.client)
            metadata_cookie = api.client.cookies.get(METADATA_SESSION_COOKIE)
        original = api.client.get("/api/v1/ui/bootstrap")
        assert original.status_code == 200
        capability = original.json()["backtest_launch"]
        assert capability["enabled"] is True
        original_cookie = api.client.cookies.get(LOCAL_SESSION_COOKIE)
        assert original_cookie
        if first == "operational":
            metadata_headers = _read_capability(api.client)
            metadata_cookie = api.client.cookies.get(METADATA_SESSION_COOKIE)
        assert api.client.cookies.get(LOCAL_SESSION_COOKIE) == original_cookie
        assert api.client.cookies.get(METADATA_SESSION_COOKIE) == metadata_cookie
        assert api.client.get(_path("absent-account"), headers=metadata_headers).status_code == 200
        operational_headers = {"X-CSRF-Token": capability["csrf_token"]}
        overview = "/api/v1/operations/accounts/absent-account"
        assert api.client.get(overview, headers=operational_headers).status_code == 200
        _cookie(api.client, METADATA_SESSION_COOKIE, "invalid-metadata-token")
        assert api.client.get(_path("absent-account"), headers=metadata_headers).status_code == 401
        assert api.client.get(overview, headers=operational_headers).status_code == 200
        _cookie(api.client, METADATA_SESSION_COOKIE, metadata_cookie)
        _cookie(api.client, LOCAL_SESSION_COOKIE, "invalid-operational-token")
        assert api.client.get(_path("absent-account"), headers=metadata_headers).status_code == 200
        assert api.client.get(overview, headers=operational_headers).status_code == 401
        assert _database_facts(api.engine) == before


def test_actual_shared_session_is_not_accepted_as_metadata_session(tmp_path):
    with _empty_api(tmp_path) as api:
        response = api.client.get("/api/v1/ui/bootstrap")
        capability = response.json()["backtest_launch"]
        assert capability["enabled"] is True
        token = api.client.cookies.get(LOCAL_SESSION_COOKIE)
        before = _database_facts(api.engine)
        _cookie(api.client, METADATA_SESSION_COOKIE, token)
        denied = api.client.get(
            _path("absent-account"), headers={METADATA_CSRF_HEADER: capability["csrf_token"]}
        )
        assert denied.status_code == 401
        assert _database_facts(api.engine) == before


def _writer_requests(account):
    configuration = {
        "kind": "buy_hold",
        "lookback": 1,
        "allocation": "1",
        "rebalance_sessions": None,
    }
    backtest = {
        "fixture_id": "fixed-fixture",
        "fixture_version": "1",
        "dataset_manifest_id": "a" * 64,
        "dataset_manifest_sha256": "a" * 64,
        "replay_run_id": "a" * 64,
        "strategy_id": "reference",
        "strategy_version": "1",
        "strategy_configuration_sha256": "a" * 64,
        "benchmark_sha256": "a" * 64,
        "cost_model_sha256": "a" * 64,
        "fill_model_sha256": "a" * 64,
        "metric_conventions_sha256": "a" * 64,
    }
    run = {
        "dataset_id": "synthetic",
        "dataset_manifest_sha256": "a" * 64,
        "strategy_id": "reference",
        "strategy_version": "1",
        "configuration": configuration,
        "initial_cash": "10000",
        "warmup_sessions": 1,
        "scored_start": None,
        "scored_end": None,
        "cost_scenario_id": "base",
    }
    experiment = {
        "name": "metadata-boundary",
        "hypothesis": "credential isolation",
        "dataset_id": "synthetic",
        "candidates": [{"candidate_id": "reference", "configuration": configuration}],
        "folds": [
            {
                "fold_id": "one",
                "train_start": "2020-01-01",
                "train_end": "2020-01-02",
                "validation_start": "2020-01-03",
                "validation_end": "2020-01-04",
                "test_start": "2020-01-05",
                "test_end": "2020-01-06",
            }
        ],
        "warmup_sessions": 1,
        "prior_access": {"status": "unknown", "description": "synthetic only"},
    }
    return (
        ("POST", "/api/v1/research/backtests", backtest),
        *(
            (
                "POST",
                f"/api/v1/operations/accounts/{account}/control/{kind.value}",
                {"reason_code": "metadata-is-read-only"},
            )
            for kind in OperationalControlAction
        ),
        ("POST", f"/api/v1/operations/accounts/{account}/advanced-risk-assignment", None),
        ("POST", "/api/v1/research/personal/runs", run),
        ("POST", f"/api/v1/research/personal/runs/{'a' * 64}/cancel", None),
        ("POST", "/api/v1/research/personal/experiments", experiment),
        ("GET", f"/api/v1/operations/accounts/{account}", None),
        ("GET", "/api/v1/operations/dashboard", None),
    )


def test_metadata_token_copied_into_shared_cookie_is_rejected_by_every_http_consumer(tmp_path):
    with _selected_api(tmp_path, writer_probes=True) as selected:
        metadata_headers = _read_capability(selected.client)
        metadata_token = selected.client.cookies.get(METADATA_SESSION_COOKIE)
        _cookie(selected.client, LOCAL_SESSION_COOKIE, metadata_token)
        headers = {
            "X-CSRF-Token": metadata_headers[METADATA_CSRF_HEADER],
            "Idempotency-Key": "metadata-denial-2026",
        }
        before = _facts(selected.study)
        for method, path, body in _writer_requests(selected.study.genesis.scope.account_id):
            response = selected.client.request(method, path, headers=headers, json=body)
            # A 503 from readiness or a 422 from a bad fixture does not establish
            # rejection by the actual original authentication decoder.
            assert response.status_code == 401, (method, path, response.text)
            assert _facts(selected.study) == before
        assert (
            selected.client.get(
                _path(selected.study.genesis.scope.account_id), headers=metadata_headers
            ).status_code
            == 200
        )


def test_metadata_query_never_uses_private_owner_clock_or_writer_apis(selected, monkeypatch):
    before = _facts(selected.study)

    def forbidden(*_args, **_kwargs):
        pytest.fail("metadata access crossed its retained-row boundary")

    with monkeypatch.context() as patch:
        patch.setattr(SqlContinuousAccount, "restore", forbidden)
        patch.setattr(LocalResearchArtifactStore, "read", forbidden)
        patch.setattr(type(selected.study.ports["clock"]), "now", forbidden)
        for name in (
            "acquire",
            "renew",
            "release",
            "revalidate",
            "revalidate_in_transaction",
            "revalidate_for_commit_in_transaction",
        ):
            patch.setattr(SqlAccountCoordinator, name, forbidden)
        headers = _read_capability(selected.client)
        response = selected.client.get(
            _path(selected.study.genesis.scope.account_id), headers=headers
        )
        assert response.status_code == 200 and response.json()["state"] == "selected"
    assert _facts(selected.study) == before


@pytest.mark.parametrize("damage", ["revision", "head", "payload"])
def test_incompatible_or_corrupt_storage_returns_only_static_503(selected, damage):
    from packages.persistence.continuous_account_schema import continuous_account_commits as commits
    from packages.persistence.continuous_account_schema import continuous_account_heads as heads

    headers = _read_capability(selected.client)
    with selected.study.ports["account_engine"].begin() as connection:
        if damage == "revision":
            connection.execute(sa.text("UPDATE alembic_version SET version_num = 'not-ready'"))
        elif damage == "head":
            connection.execute(heads.update().values(commit_sha256="0" * 64))
        else:
            connection.execute(commits.update().values(canonical_payload=b"{}"))
    before = _facts(selected.study)
    response = selected.client.get(_path(selected.study.genesis.scope.account_id), headers=headers)
    assert response.status_code == 503 and response.json() == UNAVAILABLE
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert _facts(selected.study) == before


def test_disabled_metadata_authentication_does_not_issue_or_query(selected, monkeypatch):
    app = create_app(
        Settings(local_auth_enabled=False), engine=selected.study.ports["account_engine"]
    )
    before = _facts(selected.study)

    def forbidden(*_args, **_kwargs):
        pytest.fail("disabled metadata capability queried SQL")

    monkeypatch.setattr(SqlContinuousSelectionReadModel, "read", forbidden)
    with TestClient(app) as client:
        response = client.get(BOOTSTRAP)
        assert response.status_code == 200
        capability = response.json()
        assert capability["enabled"] is False
        for name in ("operator_id", "csrf_token", "expires_at"):
            assert capability[name] is None
        assert capability["disabled_reason"]
        assert client.cookies.get(METADATA_SESSION_COOKIE) is None
        denied = client.get(
            _path(selected.study.genesis.scope.account_id), headers={METADATA_CSRF_HEADER: "x" * 43}
        )
        assert denied.status_code == 403
    assert _facts(selected.study) == before


def test_invalid_transport_does_not_mutate_selected_storage(selected):
    before = _facts(selected.study)
    with pytest.raises(ValueError, match="loopback"):
        create_app(
            Settings(api_host="0.0.0.0"),
            engine=selected.study.ports["account_engine"],
        )
    assert _facts(selected.study) == before


def test_foreign_metadata_engine_is_rejected_before_its_store_is_read(selected):
    foreign = create_database_engine("sqlite+pysqlite:///:memory:")
    try:
        before = _facts(selected.study)
        with pytest.raises(RuntimeError, match="exact durable SQL engine"):
            create_app(
                Settings(),
                engine=selected.study.ports["account_engine"],
                continuous_selection=SqlContinuousSelectionReadModel(foreign),
            )
        assert _facts(selected.study) == before
    finally:
        foreign.dispose()
