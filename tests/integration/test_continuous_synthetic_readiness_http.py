"""Fresh ASGI health transport over the real configured readiness owner.

TestClient qualifies application/lifespan behavior only, with no listening socket
or host claim. Every admitted proof and financial check is original. Barriers
pause only after the original full verifier returns, and are always released.
"""

import os
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from apps.api import continuous_readiness as http_module
from apps.trader import continuous_readiness_owner as owner_module
from packages.application.personal_runtime import LocalInstanceGuard
from packages.persistence.database import DatabaseSchemaNotReady
from tests.integration.test_continuous_synthetic_configured_readiness import _case
from tests.integration.test_continuous_synthetic_factory_partial_cleanup import _snapshot


def _reply(response, status_code, state):
    assert response.status_code == status_code
    assert response.json() == {"service": "continuous-readiness", "status": state}
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert "set-cookie" not in response.headers


@contextmanager
def _http_case(tmp_path, monkeypatch, *, seed=True, limits=None):
    with _case(tmp_path, monkeypatch, seed=seed) as case:
        # G's first owner is data only: it has no thread, lease or resources.
        # The app must call the genuine builder again, never receive that owner.
        unused_owner = case.owner
        original_build = http_module.create_configured_readiness_owner
        original_start = owner_module.ContinuousReadinessOwner.start
        original_stop = owner_module.ContinuousReadinessOwner.stop
        original_check = owner_module.ContinuousReadinessOwner.check
        case.http_builds = []
        case.http_starts = []
        case.http_stops = []
        case.http_checks = []

        def build(**kwargs):
            assert case.http_builds == []
            assert threading.current_thread() is case.caller_thread
            assert kwargs["configuration_path"] == str(case.configuration_path)
            assert kwargs["account_id"] == case.study.genesis.scope.account_id
            assert kwargs["instance_lock"] == str(case.lock_path)
            actual = original_build(**kwargs)
            assert type(actual) is owner_module.ContinuousReadinessOwner
            assert actual is not unused_owner and actual._thread is None
            case.http_builds.append(actual)
            case.owner = actual
            return actual

        def start(owner):
            assert owner is case.owner
            case.http_starts.append(threading.current_thread())
            return original_start(owner)

        def stop(owner):
            assert owner is case.owner
            caller = threading.current_thread()
            result = original_stop(owner)
            case.http_stops.append((caller, result))
            return result

        def check(owner, request_id, *, cancel_event=None):
            assert owner is case.owner
            assert type(request_id) is str and len(request_id) == 32
            assert all(character in "0123456789abcdef" for character in request_id)
            assert cancel_event is None
            caller = threading.current_thread()
            assert caller is not owner._thread
            result = original_check(owner, request_id, cancel_event=cancel_event)
            case.http_checks.append((request_id, caller, result))
            return result

        monkeypatch.setattr(http_module, "create_configured_readiness_owner", build)
        monkeypatch.setattr(owner_module.ContinuousReadinessOwner, "start", start)
        monkeypatch.setattr(owner_module.ContinuousReadinessOwner, "stop", stop)
        monkeypatch.setattr(owner_module.ContinuousReadinessOwner, "check", check)
        arguments = dict(
            configuration_path=str(case.configuration_path),
            account_id=case.study.genesis.scope.account_id,
            instance_lock=str(case.lock_path),
        )
        if limits is not None:
            arguments["limits"] = limits
        case.app = http_module.create_continuous_readiness_app(**arguments)
        assert case.http_builds == [case.owner]
        assert unused_owner.status().phase == "new" and unused_owner._thread is None
        assert case.owner.status().phase == "new" and case.owner._thread is None
        assert case.trace == [] and case.http_starts == case.http_stops == []
        assert not case.lock_path.exists()
        assert _snapshot(case.study).__dict__ == case.before.__dict__
        assert [(route.path, route.methods) for route in case.app.routes] == [
            ("/health/live", {"GET"}),
            ("/health/ready", {"GET"}),
        ]
        yield case
        assert unused_owner.status().phase == "new" and unused_owner._thread is None


def _lifespan_closed(case):
    assert len(case.http_starts) == len(case.http_stops) == 1
    for thread in (case.http_starts[0], case.http_stops[0][0]):
        assert thread is not case.caller_thread and thread is not case.owner._thread
    stopped = case.http_stops[0][1]
    assert stopped.phase == "stopped" and stopped.cleanup_complete is True
    assert not case.owner._thread.is_alive()


@contextmanager
def _paused_original_proof(case, monkeypatch):
    original = owner_module.verify_operational_schema
    pause = SimpleNamespace(
        reached=threading.Event(),
        deliver=threading.Event(),
        callers=[],
        responses=[],
        errors=[],
    )

    def verify(*args, **kwargs):
        result = original(*args, **kwargs)
        if case.proofs == 1:
            pause.reached.set()
            assert pause.deliver.wait(12), "test did not release its post-proof barrier"
        return result

    monkeypatch.setattr(owner_module, "verify_operational_schema", verify)
    primary = None
    try:
        yield pause
    except BaseException as error:
        primary = error
        raise
    finally:
        errors = []
        pause.deliver.set()
        for caller in pause.callers:
            try:
                caller.join(8)
                assert not caller.is_alive(), "HTTP caller did not finish"
            except BaseException as error:
                errors.append(error)
        try:
            with case.owner._condition:
                assert case.owner._condition.wait_for(lambda: not case.owner._busy, timeout=8), (
                    "original proof did not actually exit"
                )
        except BaseException as error:
            errors.append(error)
        if errors:
            if primary is not None:
                errors.insert(0, primary)
            raise BaseExceptionGroup("HTTP proof and controlled cleanup failed", errors)


def _request_in_thread(client, pause):
    def request():
        try:
            pause.responses.append(client.get("/health/ready"))
        except BaseException as error:
            pause.errors.append(error)

    caller = threading.Thread(target=request)
    pause.callers.append(caller)
    caller.start()
    return caller


def test_readiness_http_lifespan_runs_fresh_full_proof_for_each_ready_request(
    tmp_path, monkeypatch
):
    with _http_case(tmp_path, monkeypatch) as case:
        with TestClient(case.app) as client:
            assert case.owner.status().phase == "idle"
            assert case.owner.status().cleanup_complete is False
            _reply(client.get("/health/live"), 200, "ok")
            assert case.proofs == 0 and case.http_checks == []
            _reply(client.get("/health/ready"), 200, "ready")
            _reply(client.get("/health/ready"), 200, "ready")
            assert case.proofs == 2 and case.proof_errors == []
            assert len(case.http_checks) == 2
            assert case.http_checks[0][0] != case.http_checks[1][0]
            assert all(result.status == "ready" for _, _, result in case.http_checks)
            assert case.release_attempts == [] and case.http_stops == []
            assert _snapshot(case.study).financial == case.before.financial
            for path in ("/openapi.json", "/docs", "/api/v1/ui/bootstrap"):
                response = client.get(path)
                assert response.status_code == 404 and "set-cookie" not in response.headers
        _lifespan_closed(case)
    with LocalInstanceGuard(case.lock_path) as guard:
        info = os.fstat(guard.fileno())
        assert (info.st_dev, info.st_ino) == case.lock_identity


def test_readiness_http_missing_genuine_phase_zero_stays_unavailable(tmp_path, monkeypatch):
    with _http_case(tmp_path, monkeypatch, seed=False) as case:
        with TestClient(case.app) as client:
            _reply(client.get("/health/live"), 200, "ok")
            _reply(client.get("/health/ready"), 503, "not_ready")
            assert case.proofs == 1 and len(case.proof_errors) == 1
            assert type(case.proof_errors[0]) is DatabaseSchemaNotReady
            _reply(client.get("/health/ready"), 503, "not_ready")
            assert case.proofs == 1 and len(case.acquires) == 1
        _lifespan_closed(case)
        assert case.owner.status().primary_failure == "runtime_failed"


def test_readiness_http_held_instance_guard_does_not_acquire_or_retry(tmp_path, monkeypatch):
    with _http_case(tmp_path, monkeypatch) as case, LocalInstanceGuard(case.lock_path) as held:
        identity = os.fstat(held.fileno())
        with TestClient(case.app) as client:
            _reply(client.get("/health/live"), 200, "ok")
            _reply(client.get("/health/ready"), 503, "not_ready")
            _reply(client.get("/health/ready"), 503, "not_ready")
            assert case.factory is None and case.acquires == [] and case.proofs == 0
            assert os.fstat(held.fileno()).st_ino == identity.st_ino
        _lifespan_closed(case)


def test_readiness_http_without_lifespan_never_implicitly_starts_owner(tmp_path, monkeypatch):
    with _http_case(tmp_path, monkeypatch) as case:
        client = TestClient(case.app)
        try:
            _reply(client.get("/health/live"), 200, "ok")
            _reply(client.get("/health/ready"), 503, "not_ready")
            _reply(client.get("/health/ready"), 503, "not_ready")
        finally:
            client.close()
        assert case.owner.status().phase == "new" and case.owner._thread is None
        assert case.http_starts == case.http_stops == []
        assert case.trace == [] and case.factory is None and case.acquires == []
        assert case.proofs == 0 and not case.lock_path.exists()
        assert _snapshot(case.study).__dict__ == case.before.__dict__
    assert case.owner._thread is None
    assert _snapshot(case.study).__dict__ == case.before.__dict__


def test_readiness_http_busy_and_late_original_proof_cannot_return_stale_ready(
    tmp_path, monkeypatch
):
    with _http_case(tmp_path, monkeypatch) as case:
        with TestClient(case.app) as client:
            with _paused_original_proof(case, monkeypatch) as pause:
                caller = _request_in_thread(client, pause)
                assert pause.reached.wait(5), "real full proof did not reach the barrier"
                assert case.proofs == 1 and case.owner.status().busy is True
                busy_before = sum(result.reason == "busy" for _, _, result in case.http_checks)
                _reply(client.get("/health/ready"), 503, "not_ready")
                assert sum(result.reason == "busy" for _, _, result in case.http_checks) == (
                    busy_before + 1
                )
                _reply(client.get("/health/live"), 200, "ok")
                caller.join(6)
                assert not caller.is_alive() and pause.errors == []
                assert len(pause.responses) == 1
                _reply(pause.responses[0], 503, "not_ready")
                assert any(result.reason == "deadline" for _, _, result in case.http_checks)
                assert case.owner.status().busy is True and case.release_attempts == []
                busy_before = sum(result.reason == "busy" for _, _, result in case.http_checks)
                _reply(client.get("/health/ready"), 503, "not_ready")
                assert sum(result.reason == "busy" for _, _, result in case.http_checks) == (
                    busy_before + 1
                )
                assert case.proofs == 1
            assert case.owner.status().phase == "idle"
            _reply(client.get("/health/ready"), 200, "ready")
            assert case.proofs == 2
            ids = [request_id for request_id, _, _ in case.http_checks]
            assert len(ids) == len(set(ids))
        _lifespan_closed(case)


def test_readiness_http_incomplete_shutdown_is_not_reported_as_success(tmp_path, monkeypatch):
    # Shorten only the ASGI caller's observation budget, never the original
    # 60/5/10 financial lease policy or complete-proof request deadline.
    limits = owner_module.ReadinessOwnerLimits(shutdown_ns=100_000_000)
    with _http_case(tmp_path, monkeypatch, limits=limits) as case:
        with _paused_original_proof(case, monkeypatch) as pause:
            client = TestClient(case.app)
            client.__enter__()
            exit_attempted = False
            primary = None
            try:
                caller = _request_in_thread(client, pause)
                assert pause.reached.wait(5), "real full proof did not reach the barrier"
                caller.join(6)
                assert not caller.is_alive() and pause.errors == []
                assert len(pause.responses) == 1
                _reply(pause.responses[0], 503, "not_ready")
                assert case.owner.status().busy is True
                with pytest.raises(
                    RuntimeError, match=r"^CONTINUOUS_READINESS_CLEANUP_INCOMPLETE$"
                ):
                    exit_attempted = True
                    client.__exit__(None, None, None)
                assert len(case.http_stops) == 1
                stopped = case.http_stops[0][1]
                assert stopped.phase == "stopping" and stopped.cleanup_complete is False
                assert case.owner._thread.is_alive() and case.guard._descriptor is not None
                assert case.release_attempts == [] and case.disposals == []
                assert case.proofs == 1
            except BaseException as error:
                primary = error
                raise
            finally:
                # A failed shutdown never gives the test caller lease/engine
                # cleanup authority. Only release the artificial proof barrier.
                pause.deliver.set()
                if not exit_attempted:
                    try:
                        client.__exit__(None, None, None)
                    except BaseException as cleanup:
                        if primary is not None:
                            raise BaseExceptionGroup(
                                "HTTP assertion and lifespan cleanup failed", [primary, cleanup]
                            ) from None
                        raise
        assert len(case.http_starts) == len(case.http_stops) == 1
        # G's original test finalizer joins actual owner cleanup and verifies
        # exact release/head, both disposals, guard, all SQL and artifact facts.
