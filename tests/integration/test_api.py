from datetime import UTC, datetime
from decimal import Decimal, localcontext
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import Engine, event, text
from sqlalchemy.exc import OperationalError

from apps.api.config import (
    Environment,
    LiveCredentialRefs,
    PaperCredentialRefs,
    Settings,
)
from apps.api.contracts import AccountSummary
from apps.api.main import create_app
from packages.persistence.database import create_database_engine
from packages.persistence.schema import (
    fills,
    ledger_entries,
    ledger_postings,
    risk_reservations,
)

ROOT = Path(__file__).resolve().parents[2]


def durable_engine(tmp_path: Path) -> Engine:
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/autoquant.sqlite")
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option(
        "sqlalchemy.url",
        engine.url.render_as_string(hide_password=False).replace("%", "%%"),
    )
    command.upgrade(config, "head")
    return engine


def test_decimal_api_serialization_is_independent_of_ambient_context() -> None:
    summary = AccountSummary(
        equity=Decimal("1E+5"),
        cash=Decimal("98989.00"),
        currency="USD",
        realized_pnl=Decimal("-1.00"),
        unrealized_pnl=Decimal("0.00"),
        gross_exposure=Decimal("1010.00"),
        net_exposure=Decimal("1010.00"),
    )

    with localcontext() as context:
        context.capitals = 0
        lowercase_context = summary.model_dump_json()
    with localcontext() as context:
        context.capitals = 1
        uppercase_context = summary.model_dump_json()
    rescaled = summary.model_copy(
        update={"equity": Decimal("100000.00"), "cash": Decimal("98989")}
    ).model_dump_json()

    assert lowercase_context == uppercase_context
    assert lowercase_context == rescaled
    assert '"equity":"100000"' in lowercase_context
    assert '"cash":"98989"' in lowercase_context


def test_health_and_browser_contracts(tmp_path: Path) -> None:
    client = TestClient(create_app(Settings(), engine=durable_engine(tmp_path)))

    assert client.get("/health/live").json() == {"service": "api", "status": "ok"}
    assert client.get("/health/ready").json() == {"service": "api", "status": "ready"}

    bootstrap_requested_at = datetime.now(UTC)
    bootstrap = client.get("/api/v1/ui/bootstrap")
    assert bootstrap.status_code == 200
    assert bootstrap.json()["environment"] == {
        "name": "Local simulation",
        "mode": "local",
        "account_id": "simulation-account-001",
    }
    readiness = bootstrap.json()["readiness"]
    assert readiness["status"] == "ready"
    assert readiness["reasons"] == []
    assert datetime.fromisoformat(readiness["as_of"]) >= bootstrap_requested_at
    assert bootstrap.json()["market_clock"]["as_of"] == "2026-07-15T13:32:00Z"
    assert "backtest" not in bootstrap.json()["capabilities"]

    summary = client.get("/api/v1/dashboard/summary")
    assert summary.status_code == 200
    payload = summary.json()
    assert payload["account"]["cash"] == "98989"
    assert payload["account"]["equity"] == "99999"
    assert payload["deployment"]["state"] == "shadow"
    assert payload["deployment"]["mode"] == "local"
    assert payload["alerts"] == {"critical": 0, "warning": 0}
    assert [step["stage"] for step in payload["trace"]] == [
        "market",
        "target",
        "risk",
        "order",
        "fill",
        "ledger",
        "position",
    ]
    assert all(step["status"] == "completed" for step in payload["trace"])


def test_detailed_trace_proves_risk_and_ledger_invariants(tmp_path: Path) -> None:
    client = TestClient(create_app(Settings(), engine=durable_engine(tmp_path)))

    response = client.get("/api/v1/walking-thread/trace")

    assert response.status_code == 200
    payload = response.json()
    assert payload["risk_decision"]["persisted"] is True
    assert payload["risk_decision"]["persistence_mode"] == "durable"
    assert payload["risk_decision"]["status"] == "approved"
    assert all(rule["passed"] for rule in payload["risk_decision"]["rules"])
    assert payload["order"]["risk_decision_id"] == payload["risk_decision"]["decision_id"]
    assert payload["fill"]["executed_at"] > payload["order"]["submitted_at"]
    assert all(entry["balanced"] for entry in payload["ledger_entries"])
    assert payload["position"]["quantity"] == "10"


def test_openapi_exposes_versioned_browser_routes() -> None:
    client = TestClient(create_app(Settings()))

    document = client.get("/openapi.json").json()
    paths = document["paths"]

    assert "/api/v1/ui/bootstrap" in paths
    assert "/api/v1/dashboard/summary" in paths
    assert "/api/v1/walking-thread/trace" in paths
    assert paths["/health/ready"]["get"]["responses"]["503"]["content"]["application/json"][
        "schema"
    ] == {"$ref": "#/components/schemas/HealthResponse"}

    schemas = document["components"]["schemas"]
    assert schemas["EnvironmentMode"]["enum"] == ["local", "paper", "live"]
    assert schemas["MarketStatus"]["enum"] == [
        "open",
        "closed",
        "pre_market",
        "after_hours",
        "unknown",
    ]
    assert schemas["ReadinessStatus"]["enum"] == [
        "ready",
        "not_ready",
        "reconciling",
        "halted",
        "unknown",
    ]
    assert schemas["HealthStatus"]["enum"] == [
        "healthy",
        "warning",
        "critical",
        "unknown",
    ]
    assert schemas["TraceStatus"]["enum"] == ["completed", "pending", "failed"]
    assert schemas["AccountSummary"]["properties"]["equity"]["type"] == "string"
    assert schemas["MarketClock"]["properties"]["as_of"] == {
        "type": "string",
        "format": "date-time",
        "title": "As Of",
    }


def test_ephemeral_database_never_claims_durable_readiness() -> None:
    client = TestClient(create_app(Settings()))

    ready = client.get("/health/ready")
    trace = client.get("/api/v1/walking-thread/trace").json()
    bootstrap_requested_at = datetime.now(UTC)
    bootstrap = client.get("/api/v1/ui/bootstrap").json()

    assert ready.status_code == 503
    assert ready.json()["status"] == "not_ready"
    assert bootstrap["readiness"]["reasons"] == ["operational persistence is ephemeral"]
    assert datetime.fromisoformat(bootstrap["readiness"]["as_of"]) >= bootstrap_requested_at
    assert bootstrap["market_clock"]["as_of"] == "2026-07-15T13:32:00Z"
    assert trace["risk_decision"]["persisted"] is False
    assert trace["risk_decision"]["persistence_mode"] == "ephemeral"


def test_database_loss_downgrades_every_readiness_contract(tmp_path: Path) -> None:
    engine = durable_engine(tmp_path)
    app = create_app(Settings(), engine=engine)

    def fail_probe(*_: object) -> None:
        raise OperationalError("SELECT 1", {}, ConnectionError("database unavailable"))

    event.listen(engine, "before_cursor_execute", fail_probe)
    client = TestClient(app)

    ready = client.get("/health/ready")
    bootstrap_requested_at = datetime.now(UTC)
    bootstrap = client.get("/api/v1/ui/bootstrap").json()
    summary = client.get("/api/v1/dashboard/summary").json()
    trace = client.get("/api/v1/walking-thread/trace").json()

    assert ready.status_code == 503
    assert ready.json()["status"] == "not_ready"
    assert bootstrap["readiness"]["status"] == "not_ready"
    assert bootstrap["readiness"]["reasons"] == ["operational persistence unavailable"]
    assert datetime.fromisoformat(bootstrap["readiness"]["as_of"]) >= bootstrap_requested_at
    assert bootstrap["market_clock"]["as_of"] == "2026-07-15T13:32:00Z"
    assert (
        next(check for check in summary["health"] if check["id"] == "risk")["status"] == "critical"
    )
    assert trace["risk_decision"]["persisted"] is False
    assert trace["risk_decision"]["persistence_mode"] == "unavailable"


def test_missing_migrations_fail_closed_even_when_database_is_reachable(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/unmigrated.sqlite")
    app = create_app(Settings(), engine=engine)

    assert app.state.persistence_status == "unavailable"
    assert TestClient(app).get("/health/ready").status_code == 503


def test_runtime_schema_loss_downgrades_readiness(tmp_path: Path) -> None:
    engine = durable_engine(tmp_path)
    app = create_app(Settings(), engine=engine)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE risk_reservations"))

    response = TestClient(app).get("/health/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"


def test_runtime_authorization_integrity_loss_downgrades_readiness(
    tmp_path: Path,
) -> None:
    engine = durable_engine(tmp_path)
    app = create_app(Settings(), engine=engine)
    with engine.begin() as connection:
        connection.execute(sa.update(risk_reservations).values(state="approved"))

    response = TestClient(app).get("/health/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"


@pytest.mark.parametrize(
    ("missing_table", "health_id"),
    [(fills, "execution"), (ledger_entries, "ledger")],
)
def test_missing_execution_chain_facts_downgrade_readiness_and_dashboard_health(
    tmp_path: Path,
    missing_table: sa.Table,
    health_id: str,
) -> None:
    engine = durable_engine(tmp_path)
    app = create_app(Settings(), engine=engine)
    with engine.begin() as connection:
        if missing_table is ledger_entries:
            connection.execute(sa.delete(ledger_postings))
        connection.execute(sa.delete(missing_table))
    client = TestClient(app)

    assert client.get("/health/ready").status_code == 503
    health = client.get("/api/v1/dashboard/summary").json()["health"]
    assert next(check for check in health if check["id"] == health_id)["status"] == "critical"


@pytest.mark.parametrize("environment", [Environment.PAPER, Environment.LIVE])
def test_fixed_tape_api_cannot_masquerade_as_trading_environment(
    environment: Environment,
) -> None:
    settings = Settings(
        environment=environment,
        local_auth_enabled=False,
        session_secret="non-placeholder-secret",
        credentials=(
            PaperCredentialRefs(
                account_id="paper-account",
                expected_provider_account_id="11111111-1111-4111-8111-111111111111",
                broker_secret_ref="secret://paper/broker",
                broker_secret_version="version-1",
                market_data_secret_ref="secret://paper/data",
            )
            if environment is Environment.PAPER
            else LiveCredentialRefs(
                account_id="live-account",
                broker_secret_ref="secret://live/broker",
                market_data_secret_ref="secret://live/data",
                promotion_record_id="promotion-001",
            )
        ),
    )

    with pytest.raises(RuntimeError, match="local-only"):
        create_app(settings)
