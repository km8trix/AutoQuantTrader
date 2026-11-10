"""Account-scoped ASGI reads over fresh original L/K/G owners only.

No socket or provider is used. Transparent lifecycle observers retain the actual
context/port, and original SQL/verifier barriers never substitute a proof. All
new stores retain the inherited native financial, lease and cleanup oracles.
"""

import sqlite3
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie

import pytest
import sqlalchemy as sa
from fastapi import Response
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.pool import NullPool

from apps.api import configured_readiness_reads as lifecycle_module
from apps.api import configured_reads_app as app_module
from apps.api import readiness_read_store as read_module
from apps.api.backtest_views import LOCAL_SESSION_COOKIE, LocalOperatorSecurity
from apps.api.continuous_read_access import (
    CONTINUOUS_READ_CSRF_HEADER,
    CONTINUOUS_READ_SESSION_COOKIE,
    ContinuousReadAccessConfiguration,
    ContinuousReadAccessSecurity,
)
from apps.api.metadata_access import METADATA_SESSION_COOKIE, MetadataAccessSecurity
from apps.trader import continuous_readiness_owner as owner_module
from packages.persistence.daily_runtime_risk_schema import daily_runtime_assignments
from packages.persistence.immutable import as_aware_utc
from tests.integration.test_continuous_synthetic_configured_readiness import _case
from tests.integration.test_continuous_synthetic_factory_partial_cleanup import _snapshot
from tests.integration.test_continuous_synthetic_readiness_read_store import _read_case
from tests.integration.test_continuous_synthetic_readiness_store_binding import _no_caller_effects

BOOTSTRAP = "/api/v1/ui/continuous-read-bootstrap"
SELECTION = "/api/v1/continuous-selection"
ACCESS = ContinuousReadAccessConfiguration(
    enabled=True,
    transport_is_loopback_scoped=True,
    operator_id="operational-read-test-operator",
    configured_secret="explicit-offline-test-only-secret",
)
UNAVAILABLE = {"detail": "continuous operational read is unavailable"}


@contextmanager
def _app_case(tmp_path, monkeypatch, *, seed=True, changes=None):
    fixture = (
        _read_case(tmp_path, monkeypatch, seed=seed)
        if changes is None
        else _case(tmp_path, monkeypatch, seed=seed, changes=changes)
    )
    with fixture as case:
        unused = case.owner
        build = lifecycle_module.create_configured_readiness_owner
        open_store = lifecycle_module.open_readiness_read_store
        make_context = app_module.configured_readiness_reads
        make_security = app_module.ContinuousReadAccessSecurity
        create_engine = sa.create_engine
        case.app_builds, case.app_contexts, case.app_security = [], [], []
        case.entries, case.entry_returns, case.entry_errors = [], [], []
        case.exits, case.exit_returns, case.exit_errors = [], [], []
        case.opening_thread = None
        case.entry_barrier = None
        if changes is not None:
            case.read_engines, case.read_stores, case.read_disposals = [], [], []
            case.query_count = 0

        def construct(**kwargs):
            assert not case.app_builds and threading.current_thread() is case.caller_thread
            assert kwargs == {
                "configuration_path": str(case.configuration_path),
                "account_id": case.study.genesis.scope.account_id,
                "instance_lock": str(case.lock_path),
                "limits": owner_module.ReadinessOwnerLimits(),
            }
            actual = build(**kwargs)
            assert type(actual) is owner_module.ContinuousReadinessOwner
            assert actual is not unused and actual._thread is None
            case.app_builds.append(actual)
            case.owner = actual
            return actual

        def before_sql(connection, cursor, statement, parameters, context, executemany):
            if "FROM alembic_version" not in statement:
                return
            case.query_count += 1
            case.query_connections.append(connection)
            case.query_threads.append(threading.current_thread())
            if case.query_hook is not None:
                case.query_hook(connection, cursor)

        def engine_created(*args, **kwargs):
            engine = create_engine(*args, **kwargs)
            if threading.current_thread() is case.opening_thread:
                assert changes is None
                assert kwargs["poolclass"] is NullPool
                assert kwargs["connect_args"] == {"timeout": 0.1}
                assert type(args[0]) is sa.URL
                assert args[0].database == case.study.paths["database_path"].as_uri()
                assert dict(args[0].query) == {"mode": "ro", "uri": "true"}
                case.read_engines.append(engine)
                event.listen(engine, "before_cursor_execute", before_sql)
                if case.connect_hook is not None:
                    event.listen(engine, "connect", case.connect_hook)
            return engine

        def opened(owner):
            assert owner is case.owner
            case.opening_thread = threading.current_thread()
            assert case.opening_thread is not case.caller_thread
            assert case.opening_thread is not owner._thread
            try:
                port = open_store(owner)
            finally:
                case.opening_thread = None
            assert type(port) is read_module.ReadinessReadStore
            case.read_stores.append(port)
            return port

        def security(**kwargs):
            actual = make_security(**kwargs)
            assert type(actual) is ContinuousReadAccessSecurity
            assert kwargs == {
                "configuration": ACCESS,
                "account_id": case.study.genesis.scope.account_id,
            }
            case.app_security.append(actual)
            return actual

        def context(**kwargs):
            original = make_context(**kwargs)
            case.app_contexts.append(original)

            class ObservedContext:
                def __enter__(self):
                    case.entries.append(threading.current_thread())
                    try:
                        actual = original.__enter__()
                    except BaseException as error:
                        case.entry_errors.append(error)
                        raise
                    assert actual is case.read_stores[0]
                    case.entry_returns.append(actual)
                    barrier = case.entry_barrier
                    if barrier is not None:
                        barrier.reached.set()
                        # Do not raise between actual entry and delivery: the
                        # app must receive that exact completion and own exit.
                        barrier.released_in_time = barrier.release.wait(12)
                    return actual

                def __exit__(self, kind, error, traceback):
                    case.exits.append((threading.current_thread(), kind, error))
                    try:
                        result = original.__exit__(kind, error, traceback)
                    except BaseException as failure:
                        case.exit_errors.append(failure)
                        raise
                    case.exit_returns.append(result)
                    return result

            return ObservedContext()

        monkeypatch.setattr(lifecycle_module, "create_configured_readiness_owner", construct)
        monkeypatch.setattr(lifecycle_module, "open_readiness_read_store", opened)
        monkeypatch.setattr(app_module, "configured_readiness_reads", context)
        monkeypatch.setattr(app_module, "ContinuousReadAccessSecurity", security)
        monkeypatch.setattr(sa, "create_engine", engine_created)
        with _no_caller_effects(monkeypatch, case.caller_thread):
            case.app = app_module.create_configured_readiness_reads_app(
                configuration_path=str(case.configuration_path),
                account_id=case.study.genesis.scope.account_id,
                instance_lock=str(case.lock_path),
                read_access=ACCESS,
            )
        assert len(case.app_contexts) == len(case.app_builds) == len(case.app_security) == 1
        assert case.owner._thread is unused._thread is None
        assert case.entries == case.exits == case.trace == []
        assert not case.lock_path.exists()
        assert _snapshot(case.study).__dict__ == case.before.__dict__
        assert [(route.path, route.methods) for route in case.app.routes] == [
            ("/health/live", {"GET"}),
            (BOOTSTRAP, {"GET"}),
            (SELECTION, {"GET"}),
        ]
        yield case
        assert unused._thread is None and unused.store_binding() is None
        assert len(case.entries) == 1
        for thread in case.entries + [row[0] for row in case.exits]:
            assert thread is not case.caller_thread and thread is not case.owner._thread
        assert not case.app_security[0].is_open()
        # Original K/G finally retains its native rows/objects/R1/release/head,
        # actual disposal return, guard and joined Thread checks unchanged.


def _uncached(response, expected):
    assert response.status_code == expected
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


def _disabled(response):
    _uncached(response, 200)
    assert response.json() == {
        "enabled": False,
        "operator_id": None,
        "account_id": None,
        "csrf_token": None,
        "csrf_header": CONTINUOUS_READ_CSRF_HEADER,
        "expires_at": None,
        "disabled_reason": "continuous read permission is unavailable",
        "scope": "continuous-operational-read/1",
    }


def _authorize(case, client):
    before = datetime.now(UTC)
    response = client.get(BOOTSTRAP)
    _uncached(response, 200)
    value = response.json()
    assert set(value) == {
        "enabled",
        "operator_id",
        "account_id",
        "csrf_token",
        "csrf_header",
        "expires_at",
        "disabled_reason",
        "scope",
    }
    assert value["enabled"] is True and value["operator_id"] == ACCESS.operator_id
    assert value["account_id"] == case.study.genesis.scope.account_id
    assert value["csrf_header"] == CONTINUOUS_READ_CSRF_HEADER
    assert value["scope"] == "continuous-operational-read/1" and value["disabled_reason"] is None
    assert (
        before
        < datetime.fromisoformat(value["expires_at"])
        <= datetime.now(UTC) + timedelta(hours=8)
    )
    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    assert set(cookies) == {CONTINUOUS_READ_SESSION_COOKIE}
    cookie = cookies[CONTINUOUS_READ_SESSION_COOKIE]
    assert cookie["httponly"] and cookie["samesite"] == "strict"
    assert cookie["path"] == "/api/v1" and cookie["max-age"] == "28800"
    assert not cookie["secure"]  # This fixture qualifies explicit local HTTP only.
    assert client.cookies.get(CONTINUOUS_READ_SESSION_COOKIE) == cookie.value
    return {CONTINUOUS_READ_CSRF_HEADER: value["csrf_token"]}


def _set_cookie(client, value):
    client.cookies.clear()
    if value is not None:
        client.cookies.set(
            CONTINUOUS_READ_SESSION_COOKIE, value, domain="testserver.local", path="/api/v1"
        )


def _selection(case, response):
    _uncached(response, 200)
    assignment = case.study.assignment
    rows = dict(case.before.financial[0])[daily_runtime_assignments.name]
    assert len(rows) == 1
    recorded = as_aware_utc(
        dict(zip(daily_runtime_assignments.c.keys(), rows[0], strict=True))["recorded_at"]
    )
    assert response.json() == {
        "account_id": case.study.genesis.scope.account_id,
        "state": "selected",
        "checkpoint": {
            "stream_id": case.study.genesis.scope.stream_id,
            "sequence": "1",
            "recorded_at": case.study.genesis.restored.receipt.recorded_at.isoformat().replace(
                "+00:00", "Z"
            ),
        },
        "selection": {
            "generation": str(assignment.generation),
            "strategy_name": assignment.strategy.name,
            "strategy_version": assignment.strategy.version,
            "configuration_sha256": assignment.configuration_sha256,
            "instruments": [
                {"instrument_id": key, "symbol": symbol}
                for key, symbol in assignment.instrument_symbols
            ],
            "policy_id": assignment.policy.policy_id,
            "enabled_for_new_exposure": False,
            "live_authorized": False,
            "recorded_at": recorded.isoformat().replace("+00:00", "Z"),
            "effective_at": assignment.effective_at.isoformat().replace("+00:00", "Z"),
        },
        "verification": "row_integrity_only",
    }


def _closed(case):
    assert len(case.entries) == len(case.entry_returns) == len(case.exits) == 1
    assert case.entry_errors == case.exit_errors == []
    assert case.exit_returns == [False]
    assert case.read_stores[0].status() == read_module.ReadinessReadStoreStatus(
        "closed", False, True, None
    )
    assert case.read_disposals == case.read_engines
    status = case.owner.status()
    assert status.phase == "stopped" and status.cleanup_complete is True
    assert not case.owner._thread.is_alive()
    assert len(case.acquires) == len(case.releases) == case.close_calls == case.guard_exits == 1


def _request(client, headers, pause):
    def run():
        try:
            pause.responses.append(client.get(SELECTION, headers=headers))
        except BaseException as error:
            pause.errors.append(error)

    caller = threading.Thread(target=run)
    pause.callers.append(caller)
    caller.start()
    return caller


def test_operational_app_two_fresh_reads_exact_projection_and_closed_permission(
    tmp_path, monkeypatch
):
    with _app_case(tmp_path, monkeypatch) as case:
        client = TestClient(case.app)
        try:
            _disabled(client.get(BOOTSTRAP))
            live = client.get("/health/live")
            _uncached(live, 200)
            assert live.json() == {"service": "continuous-operational-read", "status": "ok"}
            assert case.entries == [] and case.owner._thread is None
            assert case.proofs == case.query_count == 0
            with client:
                assert len(case.entries) == 1 and case.exits == []
                assert case.proofs == case.query_count == 0
                headers = _authorize(case, client)
                cookie = client.cookies.get(CONTINUOUS_READ_SESSION_COOKIE)
                repeated = client.get(BOOTSTRAP)
                _uncached(repeated, 200)
                assert repeated.json()["csrf_token"] == headers[CONTINUOUS_READ_CSRF_HEADER]
                assert "set-cookie" not in repeated.headers
                first = client.get(SELECTION, headers=headers)
                second = client.get(SELECTION, headers=headers)
                _selection(case, first)
                _selection(case, second)
                assert first.content == second.content
                assert case.proofs == case.query_count == 2
                assert len(case.read_ids) == len(set(case.read_ids)) == 2
                assert all(connection.closed for connection in case.query_connections)
                assert _snapshot(case.study).financial == case.before.financial
                with case.read_engines[0].connect() as connection:
                    with pytest.raises(sa.exc.OperationalError) as raised:
                        connection.exec_driver_sql(
                            "INSERT INTO personal_continuous_account_heads "
                            "SELECT * FROM personal_continuous_account_heads"
                        )
                    assert type(raised.value.orig) is sqlite3.OperationalError
                    assert raised.value.orig.sqlite_errorcode == sqlite3.SQLITE_READONLY
                    connection.rollback()
                for path in (
                    "/health/ready",
                    "/docs",
                    "/openapi.json",
                    "/api/v1/ui/bootstrap",
                    "/api/v1/ui/metadata-bootstrap",
                ):
                    _uncached(client.get(path), 404)
                assert client.cookies.get(CONTINUOUS_READ_SESSION_COOKIE) == cookie
            _closed(case)
            _disabled(client.get(BOOTSTRAP))
            _set_cookie(client, cookie)
            denied = client.get(SELECTION, headers=headers)
            _uncached(denied, 503)
            assert case.proofs == case.query_count == 2 and len(case.entries) == 1
        finally:
            client.close()


def test_operational_app_failed_profile_entry_has_no_active_scope_or_k_engine(
    tmp_path, monkeypatch
):
    with _app_case(tmp_path, monkeypatch, changes={"operation": "integrity"}) as case:
        with pytest.raises(RuntimeError) as raised, TestClient(case.app):
            pytest.fail("unsupported actual configuration entered")
        assert len(case.entry_errors) == 1 and raised.value is case.entry_errors[0]
        assert str(raised.value) == "CONFIGURED_READINESS_READS_STARTUP_UNAVAILABLE"
        assert case.exits == case.read_engines == case.acquires == []
        assert case.factory is None and case.proofs == case.query_count == 0
        client = TestClient(case.app)
        try:
            _disabled(client.get(BOOTSTRAP))
        finally:
            client.close()
        assert case.owner.status().cleanup_complete is True


def test_operational_app_failed_k_entry_keeps_original_partial_cleanup(tmp_path, monkeypatch):
    with _app_case(tmp_path, monkeypatch) as case:
        connected = []

        def temp_namespace(connection, record):
            connection.execute("CREATE TEMP TABLE controlled_m_entry (value INTEGER)")
            connected.append(connection)

        case.connect_hook = temp_namespace
        with pytest.raises(RuntimeError) as raised, TestClient(case.app):
            pytest.fail("invalid original K namespace entered")
        assert len(case.entry_errors) == 1 and raised.value is case.entry_errors[0]
        assert str(raised.value) == "READINESS_READ_STORE_BINDING_CHANGED"
        assert case.exits == case.entry_returns == case.read_stores == []
        assert len(connected) == len(case.read_engines) == len(case.read_disposals) == 1
        with pytest.raises(sqlite3.ProgrammingError):
            connected[0].execute("SELECT 1")
        assert case.proofs == case.query_count == 0
        assert case.owner.status().cleanup_complete is True


def test_operational_permission_does_not_claim_missing_phase_zero_proof(
    tmp_path, monkeypatch, caplog
):
    with _app_case(tmp_path, monkeypatch, seed=False) as case:
        with TestClient(case.app) as client:
            headers = _authorize(case, client)
            for _ in range(2):
                response = client.get(SELECTION, headers=headers)
                _uncached(response, 503)
                assert response.json() == UNAVAILABLE
            assert case.proofs == 1 and len(case.proof_errors) == 1 and case.query_count == 0
            assert client.get(BOOTSTRAP).json()["enabled"] is True
            assert str(case.configuration_path) not in caplog.text
        _closed(case)
        assert case.owner.status().primary_failure == "runtime_failed"


def _old_tokens():
    # Actual original decoders, explicit auth-only fixture admission. This is
    # not an old HTTP readiness claim or a grant made by the new application.
    now = datetime.now(UTC)
    values = dict(
        enabled=True,
        transport_is_loopback_scoped=True,
        operator_id=ACCESS.operator_id,
        configured_secret=ACCESS.configured_secret,
    )
    tokens = []
    for security, name in (
        (MetadataAccessSecurity(**values), METADATA_SESSION_COOKIE),
        (LocalOperatorSecurity(**values), LOCAL_SESSION_COOKIE),
    ):
        response = Response()
        kwargs = {} if name == METADATA_SESSION_COOKIE else {"persistence_ready": True}
        capability = security.bootstrap_capability(
            response, issued_at=now, session_cookie=None, **kwargs
        )
        cookies = SimpleCookie()
        cookies.load(response.headers["set-cookie"])
        token = cookies[name].value
        assert security.authenticate(token, capability.csrf_token, now=now) == ACCESS.operator_id
        tokens.append((name, token, capability.csrf_token))
    return tokens


def test_operational_http_auth_denials_precede_every_private_proof_and_query(
    tmp_path, monkeypatch, caplog
):
    with _app_case(tmp_path, monkeypatch) as case:
        with TestClient(case.app) as client:
            headers = _authorize(case, client)
            token = client.cookies.get(CONTINUOUS_READ_SESSION_COOKIE)
            csrf = headers[CONTINUOUS_READ_CSRF_HEADER]
            old = _old_tokens()
            now = datetime.now(UTC)
            response = Response()
            expired = case.app_security[0].bootstrap_capability(
                response, issued_at=now - timedelta(hours=8, seconds=1), session_cookie=None
            )
            cookies = SimpleCookie()
            cookies.load(response.headers["set-cookie"])
            expired_token = cookies[CONTINUOUS_READ_SESSION_COOKIE].value
            matrix = [
                (None, headers, 401),
                (token[:-1] + ("0" if token[-1] != "0" else "1"), headers, 401),
                ("x" * 2049, headers, 401),
                (expired_token, {CONTINUOUS_READ_CSRF_HEADER: expired.csrf_token}, 401),
                (token, {}, 422),
                (token, {CONTINUOUS_READ_CSRF_HEADER: "invalid secret header !"}, 422),
                (token, {CONTINUOUS_READ_CSRF_HEADER: "x" * 129}, 422),
                (token, {CONTINUOUS_READ_CSRF_HEADER: "x" * 43}, 403),
                *(
                    (value, {CONTINUOUS_READ_CSRF_HEADER: old_csrf}, 401)
                    for _, value, old_csrf in old
                ),
            ]
            before = _snapshot(case.study)
            for cookie, request_headers, code in matrix:
                _set_cookie(client, cookie)
                denied = client.get(SELECTION, headers=request_headers)
                _uncached(denied, code)
                assert set(denied.json()) == {"detail"}
                if code == 422:
                    assert denied.json() == {"detail": "continuous read request is invalid"}
                assert case.proofs == case.query_count == 0
                assert case.read_ids == []
            assert _snapshot(case.study).__dict__ == before.__dict__
            assert token not in caplog.text and csrf not in caplog.text
            assert ACCESS.configured_secret not in caplog.text
        _closed(case)


def test_new_fresh_same_account_composition_denies_prior_token_and_keeps_cookie_purposes(
    tmp_path, monkeypatch
):
    first_root, second_root = tmp_path / "first", tmp_path / "second"
    first_root.mkdir(mode=0o700)
    second_root.mkdir(mode=0o700)
    with monkeypatch.context() as first_patch, _app_case(first_root, first_patch) as first:
        with TestClient(first.app) as client:
            headers = _authorize(first, client)
            token = client.cookies.get(CONTINUOUS_READ_SESSION_COOKIE)
            account = first.study.genesis.scope.account_id
        _closed(first)
    with monkeypatch.context() as second_patch, _app_case(second_root, second_patch) as second:
        assert second.study.genesis.scope.account_id == account
        with TestClient(second.app) as client:
            current_headers = _authorize(second, client)
            current = client.cookies.get(CONTINUOUS_READ_SESSION_COOKIE)
            _set_cookie(client, token)
            _uncached(client.get(SELECTION, headers=headers), 401)
            assert second.proofs == second.query_count == 0
            _set_cookie(client, current)
            old = _old_tokens()
            for name, value, _ in old:
                client.cookies.set(name, value, domain="testserver.local", path="/api/v1")
            _selection(second, client.get(SELECTION, headers=current_headers))
            assert second.proofs == second.query_count == 1
            assert client.get(BOOTSTRAP).json()["enabled"] is True
            assert all(client.cookies.get(name) == value for name, value, _ in old)
        _closed(second)
