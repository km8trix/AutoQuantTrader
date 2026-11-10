from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient

from apps.api.backtest_views import LOCAL_SESSION_COOKIE, LocalOperatorSecurity
from apps.api.operations_dashboard_views import (
    OPERATIONS_DASHBOARD_SCHEMA_VERSION,
    OperationsDashboardQuery,
    OperationsDashboardSnapshot,
    OperationsDashboardUnavailable,
    WalkingThreadOperationsDashboardQuery,
    create_operations_dashboard_router,
)
from packages.domain.clock import FixedClock
from packages.domain.walking_thread import WalkingThread

NOW = datetime(2026, 7, 15, 13, 32, tzinfo=UTC)


def _app(
    query: OperationsDashboardQuery | None,
    *,
    persistence_ready: bool = True,
) -> FastAPI:
    security = LocalOperatorSecurity(
        enabled=True,
        transport_is_loopback_scoped=True,
        operator_id="local-operator",
        configured_secret="test-only-dashboard-secret",
    )
    app = FastAPI()

    @app.get("/api/v1/test/bootstrap")
    def bootstrap(request: Request, response: Response) -> dict[str, object]:
        capability = security.bootstrap_capability(
            response,
            persistence_ready=True,
            issued_at=NOW,
            session_cookie=request.cookies.get(LOCAL_SESSION_COOKIE),
        )
        return capability.model_dump(mode="json")

    app.include_router(
        create_operations_dashboard_router(
            query=query,
            security=security,
            persistence_ready=lambda: persistence_ready,
            clock=lambda: NOW,
        ),
        prefix="/api/v1",
    )
    return app


def _client(
    query: OperationsDashboardQuery | None,
    *,
    persistence_ready: bool = True,
) -> TestClient:
    app = _app(query, persistence_ready=persistence_ready)
    client = TestClient(app)
    bootstrap = client.get("/api/v1/test/bootstrap")
    assert bootstrap.status_code == 200
    csrf_token = bootstrap.json()["csrf_token"]
    assert isinstance(csrf_token, str)
    client.headers["X-CSRF-Token"] = csrf_token
    return client


def test_walking_thread_dashboard_is_complete_honest_and_read_only() -> None:
    result = WalkingThread.run()
    query = WalkingThreadOperationsDashboardQuery(
        result=result,
        clock=FixedClock(result.completed_at),
    )

    snapshot = query.snapshot()

    assert snapshot.schema_version == OPERATIONS_DASHBOARD_SCHEMA_VERSION
    assert snapshot.read_only is True
    assert snapshot.coordinator.status == "unavailable"
    assert snapshot.deployment.strategy_id == result.target.strategy_id
    assert snapshot.deployment.state == "shadow"
    assert {item.source_id: item.status for item in snapshot.freshness} == {
        "market-data": "current",
        "risk": "stale",
        "ledger": "current",
        "reconciliation": "unavailable",
    }
    assert snapshot.orders[0].order_id == result.order.order_id
    assert snapshot.fills[0].fill_id == result.fill.fill_id
    assert snapshot.positions[0].market_value == result.position.market_value
    assert snapshot.ledger.status == "balanced"
    assert snapshot.reservations[0].state == "consumed"
    assert snapshot.risk_decisions[0].rules
    assert snapshot.reconciliation.status == "unavailable"
    assert snapshot.reconciliation.differences == []
    assert snapshot.alerts == []
    assert snapshot.control.actions_available is False
    assert snapshot.control.history == []


def test_dashboard_route_is_get_only_and_disables_caching() -> None:
    result = WalkingThread.run()
    client = _client(
        WalkingThreadOperationsDashboardQuery(
            result=result,
            clock=FixedClock(result.completed_at),
        )
    )

    response = client.get("/api/v1/operations/dashboard")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert response.json()["read_only"] is True
    assert response.json()["account"]["equity"] == "99999"
    assert client.post("/api/v1/operations/dashboard", json={}).status_code == 405
    operations = cast(FastAPI, client.app).openapi()["paths"]["/api/v1/operations/dashboard"]
    assert set(operations) == {"get"}


def test_dashboard_route_requires_local_session_csrf_and_durable_readiness() -> None:
    result = WalkingThread.run()
    query = WalkingThreadOperationsDashboardQuery(
        result=result,
        clock=FixedClock(result.completed_at),
    )
    app = _app(query)
    unauthenticated = TestClient(app)
    missing_session = unauthenticated.get(
        "/api/v1/operations/dashboard",
        headers={"X-CSRF-Token": "x" * 43},
    )
    assert missing_session.status_code == 401

    client = TestClient(app)
    bootstrap = client.get("/api/v1/test/bootstrap")
    csrf_token = bootstrap.json()["csrf_token"]
    assert isinstance(csrf_token, str)
    bad_csrf = client.get(
        "/api/v1/operations/dashboard",
        headers={"X-CSRF-Token": "x" * 43},
    )
    assert bad_csrf.status_code == 403
    unavailable = _client(query, persistence_ready=False).get("/api/v1/operations/dashboard")
    assert unavailable.status_code == 503
    assert unavailable.json() == {"detail": "operations dashboard persistence is unavailable"}


def test_dashboard_route_fails_closed_when_projection_is_absent() -> None:
    response = _client(None).get("/api/v1/operations/dashboard")

    assert response.status_code == 503
    assert response.json() == {"detail": "operations dashboard projection is unavailable"}
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


def test_dashboard_route_sanitizes_projection_failures() -> None:
    class UnavailableQuery:
        def snapshot(self) -> OperationsDashboardSnapshot:
            raise OperationsDashboardUnavailable("sensitive persistence detail")

    response = _client(UnavailableQuery()).get("/api/v1/operations/dashboard")

    assert response.status_code == 503
    assert response.json() == {"detail": "operations dashboard projection is unavailable"}
    assert "sensitive" not in response.text
