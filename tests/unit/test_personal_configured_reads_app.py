"""Modeled transport admission; genuine ownership is qualified separately.

The context observer below owns no resource. It returns an uninitialized exact
port solely for routes that must not call that port, so no proof is simulated.
"""

import threading

import anyio
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from apps.api import configured_reads_app as app_module
from apps.api.continuous_read_access import (
    CONTINUOUS_READ_CSRF_HEADER,
    CONTINUOUS_READ_SESSION_COOKIE,
    ContinuousReadAccessConfiguration,
    ContinuousReadAccessSecurity,
)
from apps.api.readiness_read_store import ReadinessReadStore


class _Lifetime:
    def __init__(self):
        self.port = object.__new__(ReadinessReadStore)
        self.entries = []
        self.exits = []
        self.failure = None
        self.exit_error = None

    def __enter__(self):
        self.entries.append(threading.current_thread())
        if self.failure is not None:
            raise self.failure
        return self.port

    def __exit__(self, *primary):
        self.exits.append((threading.current_thread(), primary))
        if self.exit_error is not None:
            raise self.exit_error
        return False


def _app(monkeypatch, lifetime, *, enabled=True):
    constructions = []

    def construct(**kwargs):
        constructions.append((threading.current_thread(), kwargs))
        return lifetime

    monkeypatch.setattr(app_module, "configured_readiness_reads", construct)
    app = app_module.create_configured_readiness_reads_app(
        configuration_path="/unopened/unit/configuration.json",
        account_id="unit-read-account",
        instance_lock="/unopened/unit/instance.lock",
        read_access=ContinuousReadAccessConfiguration(
            enabled=enabled,
            transport_is_loopback_scoped=True,
            operator_id="unit-operator",
            configured_secret="disposable-unit-only",
        ),
    )
    assert len(constructions) == 1
    assert constructions[0][0] is threading.current_thread()
    assert constructions[0][1]["account_id"] == "unit-read-account"
    assert lifetime.entries == lifetime.exits == []
    return app


def _uncached(response):
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


def test_data_only_three_routes_and_permission_unavailable_without_actual_lifespan(monkeypatch):
    lifetime = _Lifetime()
    app = _app(monkeypatch, lifetime)
    assert {(route.path, tuple(sorted(route.methods))) for route in app.routes} == {
        ("/health/live", ("GET",)),
        ("/api/v1/ui/continuous-read-bootstrap", ("GET",)),
        ("/api/v1/continuous-selection", ("GET",)),
    }
    with TestClient(app) as entered:
        assert len(lifetime.entries) == 1 and lifetime.exits == []
        response = entered.get("/api/v1/ui/continuous-read-bootstrap")
        assert response.status_code == 200 and response.json()["enabled"] is True
        _uncached(response)
    assert len(lifetime.exits) == 1
    assert lifetime.exits[0][1] == (None, None, None)
    assert lifetime.entries[0] is not threading.current_thread()
    assert lifetime.exits[0][0] is not threading.current_thread()
    client = TestClient(app)
    try:
        response = client.get("/health/live")
        assert response.status_code == 200
        _uncached(response)
        response = client.get("/api/v1/ui/continuous-read-bootstrap")
        assert response.status_code == 200 and response.json()["enabled"] is False
        assert not client.cookies.get(CONTINUOUS_READ_SESSION_COOKIE)
        _uncached(response)
    finally:
        client.close()
    assert len(lifetime.entries) == len(lifetime.exits) == 1


@pytest.mark.parametrize("path", ["/health/ready", "/openapi.json", "/docs", "/redoc"])
def test_unexposed_routes_are_static_and_uncached_without_entry(monkeypatch, path):
    lifetime = _Lifetime()
    app = _app(monkeypatch, lifetime)
    client = TestClient(app)
    try:
        response = client.get(path)
        assert response.status_code == 404
        _uncached(response)
        assert lifetime.entries == lifetime.exits == []
    finally:
        client.close()


def test_auth_validation_errors_never_echo_inputs_or_touch_uninitialized_port(monkeypatch):
    lifetime = _Lifetime()
    app = _app(monkeypatch, lifetime)
    marker = "PRIVATE-DO-NOT-ECHO-" + "z" * 200
    with TestClient(app) as client:
        for headers in ({}, {CONTINUOUS_READ_CSRF_HEADER: marker}):
            response = client.get("/api/v1/continuous-selection", headers=headers)
            assert response.status_code == 422
            assert response.json() == {"detail": "continuous read request is invalid"}
            assert marker not in response.text
            assert "/unopened/" not in response.text
            _uncached(response)
        response = client.get(
            "/api/v1/continuous-selection", headers={CONTINUOUS_READ_CSRF_HEADER: "x" * 43}
        )
        assert response.status_code == 401
        _uncached(response)
        response = client.post("/api/v1/continuous-selection", json={"secret": marker})
        assert response.status_code == 405 and marker not in response.text
        _uncached(response)
    assert len(lifetime.entries) == len(lifetime.exits) == 1


def test_disabled_permission_does_not_mint_a_session_despite_entered_lifecycle(monkeypatch):
    lifetime = _Lifetime()
    app = _app(monkeypatch, lifetime, enabled=False)
    with TestClient(app) as client:
        response = client.get("/api/v1/ui/continuous-read-bootstrap")
        assert response.status_code == 200 and response.json()["enabled"] is False
        assert client.cookies.get(CONTINUOUS_READ_SESSION_COOKIE) is None
        _uncached(response)
        response = client.get(
            "/api/v1/continuous-selection", headers={CONTINUOUS_READ_CSRF_HEADER: "x" * 43}
        )
        assert response.status_code == 403
        _uncached(response)


def test_failed_entry_propagates_identical_failure_and_never_calls_exit(monkeypatch):
    lifetime = _Lifetime()
    primary = BaseException("private modeled entry failure")
    lifetime.failure = primary
    app = _app(monkeypatch, lifetime)
    with pytest.raises(BaseException) as raised, TestClient(app):
        pytest.fail("failed entry yielded a lifespan")
    assert raised.value is primary
    assert len(lifetime.entries) == 1 and lifetime.exits == []


def test_original_primary_type_value_traceback_reaches_sole_worker_exit(monkeypatch):
    lifetime = _Lifetime()
    primary = BaseException("private modeled body failure")
    app = _app(monkeypatch, lifetime)
    original_tracebacks = []

    async def exercise():
        async with app.router.lifespan_context(app):
            try:
                raise primary
            except BaseException as observed:
                original_tracebacks.append(observed.__traceback__)
                raise

    with pytest.raises(BaseException) as raised:
        anyio.run(exercise)
    assert raised.value is primary
    assert len(lifetime.entries) == len(lifetime.exits) == 1
    kind, value, traceback = lifetime.exits[0][1]
    assert kind is BaseException and value is primary
    # asynccontextmanager adds its throw boundary ahead of the original body;
    # the supplied traceback must still contain the exact original body object.
    chain = []
    while traceback is not None:
        chain.append(traceback)
        traceback = traceback.tb_next
    assert original_tracebacks[0] in chain


def test_scope_close_failure_keeps_original_primary_order_and_does_not_skip_exit(monkeypatch):
    lifetime = _Lifetime()
    primary = BaseException("private modeled primary")
    scope_error = BaseException("private modeled scope-close failure")
    original_close = ContinuousReadAccessSecurity.close

    def close_then_fail(security):
        original_close(security)
        raise scope_error

    monkeypatch.setattr(ContinuousReadAccessSecurity, "close", close_then_fail)
    app = _app(monkeypatch, lifetime)

    async def exercise():
        async with app.router.lifespan_context(app):
            raise primary

    with pytest.raises(BaseExceptionGroup) as raised:
        anyio.run(exercise)
    assert raised.value.message == "CONTINUOUS_READ_SCOPE_AND_OPERATION_FAILED"
    assert raised.value.exceptions == (primary, scope_error)
    assert len(lifetime.entries) == len(lifetime.exits) == 1
    assert lifetime.exits[0][1] == (BaseExceptionGroup, raised.value, None)
    client = TestClient(app)
    try:
        response = client.get("/api/v1/ui/continuous-read-bootstrap")
        assert response.status_code == 200 and response.json()["enabled"] is False
        _uncached(response)
    finally:
        client.close()


def test_existing_l_cleanup_group_propagates_by_identity_without_another_primary(monkeypatch):
    lifetime = _Lifetime()
    primary = BaseException("private modeled body primary")
    cleanup = BaseException("private modeled read cleanup")
    original_group = BaseExceptionGroup("modeled original L group", [primary, cleanup])
    lifetime.exit_error = original_group
    app = _app(monkeypatch, lifetime)

    async def exercise():
        async with app.router.lifespan_context(app):
            raise primary

    with pytest.raises(BaseExceptionGroup) as raised:
        anyio.run(exercise)
    assert raised.value is original_group
    assert raised.value.exceptions == (primary, cleanup)
    assert len(lifetime.entries) == len(lifetime.exits) == 1
    assert lifetime.exits[0][1][0] is BaseException
    assert lifetime.exits[0][1][1] is primary


@pytest.mark.parametrize("source", ["clock", "bootstrap", "authentication"])
@pytest.mark.parametrize("status", [401, 403, 503, 500])
def test_unexpected_lower_http_errors_never_forward_private_details_or_headers(
    monkeypatch, caplog, source, status
):
    marker = "PRIVATE-path-sql-token-cause"
    lifetime = _Lifetime()
    app = _app(monkeypatch, lifetime)

    def fail(*args, **kwargs):
        raise HTTPException(status, marker, headers={"X-Private-Token": marker})

    if source == "clock":
        monkeypatch.setattr(app_module, "_utc_now", fail)
    elif source == "bootstrap":
        monkeypatch.setattr(ContinuousReadAccessSecurity, "bootstrap_capability", fail)
    else:
        monkeypatch.setattr(ContinuousReadAccessSecurity, "authenticate", fail)
    with TestClient(app) as client:
        path = (
            "/api/v1/continuous-selection"
            if source == "authentication"
            else "/api/v1/ui/continuous-read-bootstrap"
        )
        response = client.get(path, headers={CONTINUOUS_READ_CSRF_HEADER: "x" * 43})
        expected = status if source == "authentication" and status in {401, 403} else 503
        assert response.status_code == expected
        assert marker not in response.text
        assert marker not in caplog.text
        assert "x-private-token" not in response.headers
        if expected == 503:
            assert response.json() == {"detail": "continuous operational read is unavailable"}
        if expected == 401:
            assert response.headers["www-authenticate"] == "ContinuousReadSession"
        _uncached(response)
