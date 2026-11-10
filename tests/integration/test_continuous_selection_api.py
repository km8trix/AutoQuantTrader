"""Authenticated retained metadata boundaries on fresh migrated SQLite.

Default operational readiness still rejects nonempty W4 history. Metadata uses
its separately selected read-only capability and bounded storage checks; no
replay/lease authority or fake operational-readiness callback is supplied.
"""

import subprocess
import sys
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from textwrap import dedent
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

from apps.api.backtest_views import LOCAL_SESSION_COOKIE
from apps.api.config import Settings
from apps.api.contracts import (
    ContinuousSelectionCheckpointView,
    ContinuousSelectionResponse,
    RetainedContinuousSelectionView,
)
from apps.api.main import create_app
from apps.api.metadata_access import METADATA_CSRF_HEADER, METADATA_SESSION_COOKIE
from apps.trader.synthetic_session_capture import capture_synthetic_bootstrap
from apps.trader.synthetic_session_genesis import initialize_synthetic_session
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec as codec
from packages.application.synthetic_continuous_inputs import synthetic_continuous_inputs
from packages.domain.clock import SimulatedClock
from packages.domain.forward_capture_contracts import CAPTURE_SCHEMA, ForwardCaptureRecord
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.persistence.continuous_selection_read_model import (
    ContinuousSelectionReadError,
    SqlContinuousSelectionReadModel,
)
from packages.persistence.database import EXPECTED_SCHEMA_REVISION, create_database_engine
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import JOURNAL_TABLES
from packages.persistence.forward_capture_publication import SqlForwardCapturePublication
from packages.persistence.schema import metadata
from tests.integration.test_continuous_synthetic_offline_configuration import (
    _exclusive_file,
    _rows,
)
from tests.integration.test_continuous_synthetic_session_genesis import PINS

ROOT = Path(__file__).resolve().parents[2]
ACCOUNT = "absent-continuous-api-account"
UNAVAILABLE = {"detail": "continuous selection metadata is unavailable or malformed"}


def test_clean_process_preserves_actual_ephemeral_api_bootstrap():
    """Collection must not conceal incomplete shared-schema registration."""
    script = dedent(
        """
        import sys
        sys.path.insert(0, sys.argv[1])
        import sqlalchemy as sa
        from apps.api import main
        from apps.api.config import Settings
        from apps.api.contracts import PersistenceMode
        from packages.persistence.schema import fills, ledger_entries, orders

        applications = [main.app]
        try:
            applications.append(main.create_app(Settings()))
            for application in applications:
                assert application.state.persistence_status is PersistenceMode.EPHEMERAL
                assert application.state.persistence_error is None
                assert application.state.persistence_ready is False
                assert application.state.continuous_selection is None
                result = application.state.walking_thread
                with application.state.database_engine.connect() as connection:
                    assert connection.scalar(sa.select(orders.c.order_id)) == result.order.order_id
                    assert connection.scalar(sa.select(fills.c.fill_id)) == result.fill.fill_id
                    assert set(connection.scalars(sa.select(ledger_entries.c.entry_id))) == {
                        entry.entry_id for entry in result.ledger_entries
                    }
                assert (
                    '/api/v1/operations/accounts/{account_id}/continuous-selection'
                    in application.openapi()['paths']
                )
        finally:
            for application in applications:
                application.state.database_engine.dispose()
        """
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script, str(ROOT)],
        cwd=ROOT,
        env={
            "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "TZ": "UTC",
            "AQT_ENVIRONMENT": "local",
            "AQT_DATABASE_URL": "sqlite+pysqlite:///:memory:",
            "AQT_LOCAL_AUTH_ENABLED": "true",
            "AQT_SESSION_SECRET": "synthetic-startup-regression-only-secret-2026",
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "bootstrap failed" not in result.stdout + result.stderr
    assert "NoReferencedTableError" not in result.stdout + result.stderr


def _path(account_id=ACCOUNT):
    return f"/api/v1/operations/accounts/{account_id}/continuous-selection"


def _authorize_legacy(client):
    response = client.get("/api/v1/ui/bootstrap")
    assert response.status_code == 200
    token = response.json()["backtest_launch"]["csrf_token"]
    assert type(token) is str and client.cookies.get(LOCAL_SESSION_COOKIE)
    return {"X-CSRF-Token": token}


def _authorize(client):
    response = client.get("/api/v1/ui/metadata-bootstrap")
    assert response.status_code == 200
    capability = response.json()
    token = capability["csrf_token"]
    assert capability["enabled"] is True
    assert type(token) is str and client.cookies.get(METADATA_SESSION_COOKIE)
    assert capability["csrf_header"] == METADATA_CSRF_HEADER
    return {METADATA_CSRF_HEADER: token}


def _all_rows(engine):
    with engine.connect() as connection:
        revision = tuple(connection.scalars(sa.text("SELECT version_num FROM alembic_version")))
    return revision, _rows(engine, tuple(metadata.sorted_tables))


@pytest.fixture
def api(tmp_path):
    root = tmp_path.resolve() / "continuous-selection-api"
    root.mkdir(mode=0o700)
    path = root / "account.sqlite"
    _exclusive_file(path)
    url = f"sqlite+pysqlite:///{path}"
    config = Config()
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    config.attributes["aqt_explicit_database_url"] = url
    command.upgrade(config, EXPECTED_SCHEMA_REVISION)
    engine = create_database_engine(url)
    try:
        app = create_app(Settings(), engine=engine)
        assert app.state.persistence_ready is True
        assert type(app.state.continuous_selection) is SqlContinuousSelectionReadModel
        with TestClient(app) as client:
            yield SimpleNamespace(
                root=root,
                engine=engine,
                app=app,
                client=client,
                legacy_headers=_authorize_legacy(client),
                headers=_authorize(client),
            )
    finally:
        engine.dispose()


def _forbid_query(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("authentication/readiness denial must precede metadata SQL")

    monkeypatch.setattr(SqlContinuousSelectionReadModel, "read", forbidden)


def _initialize_after_bootstrap(api, cleanup):
    """Publish genuine C1 after a real session was issued against the empty DB."""
    venue_path = api.root / "venue.sqlite"
    _exclusive_file(venue_path)
    venue_engine = create_database_engine(f"sqlite+pysqlite:///{venue_path}")
    cleanup.callback(venue_engine.dispose)
    metadata.create_all(venue_engine, tables=JOURNAL_TABLES)
    artifacts = LocalResearchArtifactStore(api.root / "account-objects")
    venue_artifacts = LocalResearchArtifactStore(api.root / "venue-objects")
    synthetic = synthetic_continuous_inputs(
        fixture="regime", pins=PINS, session_count=4, warmup_count=1
    )
    producer = VersionPin("synthetic-capture", "api-test-1", content_digest("api-capture"))
    journal = SqlDurableJournal(
        api.engine, codec=codec, record_types={CAPTURE_SCHEMA: ForwardCaptureRecord}
    )
    bootstrap = capture_synthetic_bootstrap(
        synthetic,
        calendar_pin=VersionPin(
            "synthetic-calendar", "api-test-1", content_digest(synthetic.inputs.spec.calendar)
        ),
        producer_pin=producer,
        journal=journal,
        publisher=SqlForwardCapturePublication(api.engine, journal=journal),
        artifacts=artifacts,
        codec=codec,
    )
    genesis = initialize_synthetic_session(
        bootstrap,
        account_engine=api.engine,
        venue_engine=venue_engine,
        account_artifacts=artifacts,
        venue_artifacts=venue_artifacts,
        clock=SimulatedClock(bootstrap.inputs.spec.initialized_at),
        monotonic_now_ns=lambda: 1_000_000_000,
        epoch_id="synthetic-api-model-1",
        owner_id="synthetic-api-startup",
        venue_pin=VersionPin("synthetic-venue", "api-test-1", content_digest("api-venue")),
        quote_producer=producer,
    )
    assert genesis.account.coordinator.current() is None
    return genesis, venue_engine


def _object_rows(root):
    return tuple(
        tuple(sorted((p.name, p.read_bytes()) for p in (root / name).iterdir()))
        for name in ("account-objects", "venue-objects")
    )


def test_default_main_reads_actual_absent_sql_without_mutating_any_retained_rows(api):
    before = _all_rows(api.engine)
    response = api.client.get(_path(), headers=api.headers)
    assert response.status_code == 200
    assert response.json() == {
        "account_id": ACCOUNT,
        "state": "absent",
        "checkpoint": None,
        "selection": None,
        "verification": "row_integrity_only",
    }
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert api.client.get(_path(), headers=api.headers).content == response.content
    assert _all_rows(api.engine) == before
    overview = api.client.get(f"/api/v1/operations/accounts/{ACCOUNT}", headers=api.legacy_headers)
    assert overview.status_code == 200
    assert overview.json()["current_risk_assignment"] is None
    assert overview.json()["current_risk_assessment"] is None
    assert "selection" not in overview.json()
    assert _all_rows(api.engine) == before


def test_main_rejects_actual_sql_reader_bound_to_a_foreign_engine(api):
    path = api.root / "foreign.sqlite"
    _exclusive_file(path)
    foreign = create_database_engine(f"sqlite+pysqlite:///{path}")
    try:
        before = _all_rows(api.engine)
        reader = SqlContinuousSelectionReadModel(foreign)
        with pytest.raises(
            RuntimeError,
            match=r"^continuous selection query requires the exact durable SQL engine$",
        ):
            create_app(Settings(), engine=api.engine, continuous_selection=reader)
        assert _all_rows(api.engine) == before
        # Reject composition before opening or querying the independent store.
        assert path.read_bytes() == b""
    finally:
        foreign.dispose()


def test_missing_session_rejects_before_metadata_read(api, monkeypatch):
    _forbid_query(monkeypatch)
    with TestClient(api.app) as client:
        response = client.get(_path(), headers=api.headers)
    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "headers,expected", [({}, 422), ({"X-Metadata-CSRF-Token": "x" * 43}, 403)]
)
def test_missing_or_wrong_csrf_rejects_before_metadata_read(api, monkeypatch, headers, expected):
    _forbid_query(monkeypatch)
    response = api.client.get(_path(), headers=headers)
    assert response.status_code == expected
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("account_id", ["bad!account", "a" * 65, ":account"])
def test_account_path_validation_precedes_query(api, monkeypatch, account_id):
    _forbid_query(monkeypatch)
    assert api.client.get(_path(account_id), headers=api.headers).status_code == 422


@pytest.mark.parametrize("failure", ["sql", "private-http", "type"])
def test_backend_failures_never_expose_private_detail_or_partial_metadata(api, failure):
    class BrokenQuery:
        def read(self, account_id):
            assert account_id == ACCOUNT
            if failure == "private-http":
                raise HTTPException(418, "private-provider-payload")
            if failure == "type":
                return object()
            raise ContinuousSelectionReadError("private-provider-payload")

    app = create_app(Settings(), engine=api.engine, continuous_selection=BrokenQuery())
    with TestClient(app) as client:
        headers = _authorize(client)
        before = _all_rows(api.engine)
        response = client.get(_path(), headers=headers)
        assert response.status_code == 503
        assert response.json() == UNAVAILABLE
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["pragma"] == "no-cache"
        assert _all_rows(api.engine) == before


def test_real_sql_snapshot_for_another_account_cannot_replace_requested_account(api):
    reader = SqlContinuousSelectionReadModel(api.engine)

    class WrongAccountQuery:
        def read(self, account_id):
            assert account_id == ACCOUNT
            return reader.read("different-absent-account")

    app = create_app(Settings(), engine=api.engine, continuous_selection=WrongAccountQuery())
    with TestClient(app) as client:
        headers = _authorize(client)
        before = _all_rows(api.engine)
        response = client.get(_path(), headers=headers)
        assert response.status_code == 503 and response.json() == UNAVAILABLE
        assert _all_rows(api.engine) == before


def test_disabled_auth_never_composes_or_calls_selection_reader(api, monkeypatch):
    app = create_app(Settings(local_auth_enabled=False), engine=api.engine)
    assert app.state.continuous_selection is None
    _forbid_query(monkeypatch)
    with TestClient(app) as client:
        bootstrap = client.get("/api/v1/ui/bootstrap")
        assert bootstrap.json()["backtest_launch"]["enabled"] is False
        metadata = client.get("/api/v1/ui/metadata-bootstrap")
        assert metadata.json()["enabled"] is False
        assert client.get(_path(), headers={METADATA_CSRF_HEADER: "x" * 43}).status_code == 403


def test_changed_schema_denies_without_reading_metadata(api):
    with api.engine.begin() as connection:
        connection.execute(sa.text("UPDATE alembic_version SET version_num = 'not-ready'"))
    before = _all_rows(api.engine)
    observed = []

    def forbid_row_query(_connection, _cursor, statement, _parameters, _context, _executemany):
        observed.append(statement)

    sa.event.listen(api.engine, "before_cursor_execute", forbid_row_query)
    try:
        response = api.client.get(_path(), headers=api.headers)
    finally:
        sa.event.remove(api.engine, "before_cursor_execute", forbid_row_query)
    assert response.status_code == 503
    assert response.json() == UNAVAILABLE
    assert any("alembic_version" in statement for statement in observed)
    assert all("personal_continuous_account" not in statement.lower() for statement in observed)
    assert all("daily_runtime_assignment" not in statement.lower() for statement in observed)
    assert response.headers["cache-control"] == "no-store"
    assert _all_rows(api.engine) == before


def test_real_nonempty_history_preserves_default_full_integrity_readiness_gate(api, monkeypatch):
    with ExitStack() as cleanup:
        genesis, venue = _initialize_after_bootstrap(api, cleanup)
        snapshot = SqlContinuousSelectionReadModel(api.engine).read(genesis.scope.account_id)
        assert snapshot.state == "unselected" and snapshot.checkpoint.sequence == 1
        before = _all_rows(api.engine), _rows(venue, JOURNAL_TABLES), _object_rows(api.root)
        with monkeypatch.context() as guarded:
            _forbid_query(guarded)
            response = api.client.get(
                f"/api/v1/operations/accounts/{genesis.scope.account_id}",
                headers=api.legacy_headers,
            )
            assert response.status_code == 503
            assert response.json() == {
                "detail": "durable local operations persistence is unavailable"
            }
            assert "checkpoint" not in response.text and "selection" not in response.text
            assert api.client.get("/health/ready").status_code == 503
        metadata_response = api.client.get(_path(genesis.scope.account_id), headers=api.headers)
        assert metadata_response.status_code == 200
        assert metadata_response.json()["state"] == "unselected"
        assert metadata_response.json()["verification"] == "row_integrity_only"
        assert (
            _all_rows(api.engine),
            _rows(venue, JOURNAL_TABLES),
            _object_rows(api.root),
        ) == before
        assert genesis.account.coordinator.current() is None


@pytest.mark.parametrize("counter", [1, 2**53 + 1, 2**63 - 1])
def test_response_counters_are_exact_decimal_strings_and_schema_has_no_authority(counter):
    now = datetime(2026, 10, 21, tzinfo=UTC)
    value = ContinuousSelectionResponse(
        account_id=ACCOUNT,
        state="selected",
        checkpoint=ContinuousSelectionCheckpointView(
            stream_id="stream", sequence=counter, recorded_at=now
        ),
        selection=RetainedContinuousSelectionView(
            generation=counter,
            strategy_name="reference",
            strategy_version="1",
            configuration_sha256="a" * 64,
            instruments=({"instrument_id": "instrument-spy", "symbol": "SPY"},),
            policy_id="product-daily-risk/1",
            enabled_for_new_exposure=False,
            live_authorized=False,
            recorded_at=now,
            effective_at=now,
        ),
    )
    serialized = value.model_dump(mode="json")
    assert serialized["checkpoint"]["sequence"] == str(counter)
    assert serialized["selection"]["generation"] == str(counter)
    assert serialized["verification"] == "row_integrity_only"
    schema = ContinuousSelectionResponse.model_json_schema(mode="serialization")
    assert (
        schema["$defs"]["ContinuousSelectionCheckpointView"]["properties"]["sequence"]["type"]
        == "string"
    )
    assert (
        schema["$defs"]["RetainedContinuousSelectionView"]["properties"]["generation"]["type"]
        == "string"
    )
    description = schema["properties"]["verification"]["description"]
    for excluded in (
        "owner history",
        "readiness",
        "current financial state",
        "execution permission",
    ):
        assert excluded in description


@pytest.mark.parametrize("counter", [True, 0, -1, 2**63, "1"])
def test_response_counter_native_bounds_cannot_be_coerced(counter):
    with pytest.raises(ValidationError):
        ContinuousSelectionCheckpointView(
            stream_id="stream", sequence=counter, recorded_at=datetime(2026, 10, 21, tzinfo=UTC)
        )
