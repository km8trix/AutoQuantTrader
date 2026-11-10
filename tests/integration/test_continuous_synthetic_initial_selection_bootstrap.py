"""Fresh original owner proof joined to the original private shared issuer.

The fixture owns separate cumulative observations; it does not reuse or reset
the fixed F/H/L proof counters. Local original-code events observe actual work.
No success verifier, issuer, authentication method or clock is replaced.
"""

import os
import sys
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from hmac import compare_digest
from http.cookies import SimpleCookie
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import HTTPException, Response
from sqlalchemy import Engine

from apps.api import initial_selection_bootstrap as bootstrap
from apps.api.backtest_views import LOCAL_SESSION_COOKIE, LocalOperatorSecurity
from apps.api.continuous_read_access import (
    CONTINUOUS_READ_SESSION_COOKIE,
    ContinuousReadAccessConfiguration,
    ContinuousReadAccessSecurity,
)
from apps.api.contracts import BacktestLaunchCapability
from apps.api.metadata_access import METADATA_SESSION_COOKIE, MetadataAccessSecurity
from apps.trader import initial_selection_preparation_owner as host
from apps.trader.continuous_readiness_owner import _ReadinessRuntime
from apps.trader.continuous_simulation_factory import ContinuousSimulationFactory
from apps.trader.initial_selection_preparation_owner import (
    InitialSelectionPreparationOwner,
    InitialSelectionReadinessResult,
)
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.application.personal_runtime import LocalInstanceGuard
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    account_lease_from_row,
    account_lease_release_from_row,
)
from packages.persistence.continuous_integrity import SqlContinuousIntegrityReader
from packages.persistence.database import DatabaseSchemaNotReady, verify_operational_schema
from packages.persistence.runtime_assignment_publication import SqlRuntimeAssignmentPublication
from packages.persistence.runtime_owner_commands import SqlRuntimeOwnerCommands
from tests.integration import test_continuous_synthetic_offline_configuration as study_module
from tests.integration.test_continuous_synthetic_factory_partial_cleanup import _snapshot
from tests.integration.test_continuous_synthetic_full_readiness import (
    _assert_initial_state,
    _assert_scopes_closed,
    _seed_phase_zero,
)
from tests.integration.test_continuous_synthetic_initial_selection_preparation import _configuration

_INVALID = r"^INITIAL_SELECTION_BOOTSTRAP_INVALID$"
_CHANGED = r"^INITIAL_SELECTION_BOOTSTRAP_BINDING_CHANGED$"


def _security(*, enabled=True):
    return LocalOperatorSecurity(
        enabled=enabled,
        transport_is_loopback_scoped=True,
        operator_id="bootstrap opérateur",
        configured_secret="fresh-private-N-shared-session-configuration",
    )


def _cookie(response, name=LOCAL_SESSION_COOKIE):
    jar = SimpleCookie()
    jar.load(response.headers["set-cookie"])
    return jar[name].value


def _same_secret(left, right):
    # Fail with a fixed diagnostic instead of asking pytest to render credentials.
    if type(left) is not str or type(right) is not str or not compare_digest(left, right):
        raise AssertionError("original credential identity differs")


@contextmanager
def _observe(case):
    labels = {
        ContinuousSimulationFactory.__init__.__code__: "factory",
        ContinuousSimulationFactory.close.__code__: "close",
        ContinuousSimulationFactory.execute.__code__: "execute",
        _ReadinessRuntime.__init__.__code__: "runtime",
        _ReadinessRuntime.verify.__code__: "verify",
        verify_operational_schema.__code__: "schema",
        SqlContinuousIntegrityReader.original_factory_read.__code__: "factory-read",
        SqlAccountCoordinator.acquire.__code__: "acquire",
        SqlAccountCoordinator.release.__code__: "release",
        SqlAccountCoordinator._observe.__code__: "watermark",
        LocalInstanceGuard.__enter__.__code__: "guard-enter",
        LocalInstanceGuard.__exit__.__code__: "guard-exit",
        Engine.connect.__code__: "connect",
        Engine.dispose.__code__: "dispose",
        LocalResearchArtifactStore.put.__code__: "put",
        SqlRuntimeAssignmentPublication.publish.__code__: "publish",
        SqlRuntimeOwnerCommands.prepare.__code__: "request",
        InitialSelectionPreparationOwner.prepare_initial_selection.__code__: "prepare",
        InitialSelectionPreparationOwner.install_initial_selection.__code__: "install",
        InitialSelectionPreparationOwner.check_initial_selection_readiness.__code__: "proof",
        LocalOperatorSecurity.bootstrap_capability.__code__: "issuer",
        LocalOperatorSecurity.authenticate_with_expiry.__code__: "auth",
        host._NOW.__code__: "owner-clock",
    }
    monitor, tool = sys.monitoring, 3
    prior_profile = sys.getprofile()
    enabled, registered, sql_engines = [], [], []
    owned, primary = False, None

    def sql(connection, cursor, statement, parameters, context, executemany):
        assert connection.engine in (case.account_engine, case.venue_engine)
        case.sql.append((connection.engine, threading.current_thread()))

    def worker():
        actual = threading.current_thread()
        assert actual is case.owner._thread and actual is not case.caller_thread
        if case.thread is None:
            case.thread = actual
        assert actual is case.thread
        return actual

    def observe(frame, event, returned):
        label = labels[frame.f_code]
        actual = frame.f_locals.get("self")
        if label in ("issuer", "auth", "proof", "owner-clock"):
            if not case.in_join or threading.current_thread() is not case.caller_thread:
                return None
            if label in ("issuer", "auth"):
                assert actual is case.security
            else:
                assert actual is case.owner
            if event == "call":
                case.join_events.append(label + "-call")
                if label == "issuer":
                    response = frame.f_locals["response"]
                    assert type(response) is Response
                    case.issuer_calls.append(
                        (response, frame.f_locals["persistence_ready"], frame.f_locals["issued_at"])
                    )
                elif label == "proof":
                    case.proof_calls.append(frame.f_locals["call_id"])
                elif label == "owner-clock":
                    case.owner_clock_calls += 1
            else:
                case.join_events.append(label + "-return")
                if label == "issuer":
                    case.issuer_returns.append(returned)
                elif label == "auth":
                    case.auth_returns.append((returned, frame.f_locals["now"]))
                elif label == "proof":
                    case.proof_returns.append(returned)
            return label
        if event == "call":
            if label == "factory":
                assert case.factory is None
                case.factory = actual
                case.trace.append(("factory-call", worker()))
            elif label == "acquire":
                assert actual is case.factory.coordinator
                case.account_engine = case.factory.engine
            elif label == "runtime":
                assert frame.f_locals["reader"] is case.factory.integrity
                assert frame.f_locals["lease"] is case.acquires[0]
            elif label == "verify":
                assert actual is case.runtime and actual.lease is case.acquires[0]
                case.verify_calls.append((frame.f_locals["deadline_ns"], worker()))
            elif label == "schema" and frame.f_locals["continuous_integrity"] is not None:
                assert frame.f_locals["engine"] is case.account_engine
                assert frame.f_locals["continuous_integrity"] is case.runtime.reader
                assert frame.f_locals["research_codec"] is personal_codec
                assert frame.f_locals["require_phase_zero_facts"] is True
                case.schema_calls.append(worker())
            elif label in (
                "execute",
                "factory-read",
                "put",
                "publish",
                "request",
                "prepare",
                "install",
            ):
                case.forbidden.append(label)
            elif label == "release":
                case.release_attempts.append((actual, frame.f_locals["fence"], worker()))
            elif label == "close":
                assert actual is case.factory
                case.close_calls += 1
                case.trace.append(("close-call", worker()))
            elif label == "guard-exit" and actual is case.guard:
                case.guard_primaries.append(frame.f_locals["_"][1])
        else:
            if label == "acquire":
                case.acquires.append(returned)
                case.trace.append(("acquire-return", worker()))
            elif label == "factory":
                case.venue_engine = actual.venue_engine
            elif label == "runtime":
                assert case.runtime is None
                case.runtime, case.stop_event = actual, actual.stop_event
                assert actual.reader.engine is case.account_engine
                assert actual.venue_engine is case.venue_engine
                assert len(actual.reader.journals) == 8
                for engine in (case.account_engine, case.venue_engine):
                    sa.event.listen(engine, "before_cursor_execute", sql)
                    sql_engines.append(engine)
                case.trace.append(("runtime-return", worker()))
            elif label == "verify":
                assert type(returned) is int
                case.verify_returns.append((returned, worker()))
                _assert_scopes_closed(case.runtime.reader)
            elif label == "schema" and frame.f_locals["continuous_integrity"] is not None:
                case.schema_returns += 1
            elif label == "watermark" and actual is case.factory.coordinator:
                at = frame.f_locals["checked_at"]
                assert type(at) is datetime and at.tzinfo is UTC and returned.updated_at == at
                case.watermarks.append(at)
            elif label == "release":
                case.releases.append(returned)
                case.trace.append(("release-return", worker()))
            elif label == "close":
                case.close_returns.append(returned)
                case.trace.append(("close-return", worker()))
            elif label == "guard-enter" and threading.current_thread() is not case.caller_thread:
                case.guard = actual
                info = os.fstat(actual.fileno())
                case.lock_identity = info.st_dev, info.st_ino
            elif label == "guard-exit" and actual is case.guard:
                case.guard_returns += 1
                case.trace.append(("guard-return", worker()))
            elif label == "dispose":
                for engine, name in (
                    (case.venue_engine, "venue"),
                    (case.account_engine, "account"),
                ):
                    if actual is engine and engine is not None:
                        case.disposals.append(name)
                        case.trace.append((name + "-dispose-return", worker()))
            elif label == "connect" and actual in (case.account_engine, case.venue_engine):
                case.connections.append(returned)
        return None

    def event(code, kind, returned):
        frame = sys._getframe(2)
        try:
            assert frame.f_code is code
            try:
                label = observe(frame, kind, returned)
            except BaseException as error:
                case.observer_errors.append(error)
                raise
            # Intentional return-boundary faults are outside the observation
            # assertions. They do not claim the original algorithm raised them.
            if label is not None and case.action is not None:
                case.action(label, kind, frame, returned)
        finally:
            del frame

    def on_start(code, offset):
        event(code, "call", None)

    def on_return(code, offset, returned):
        event(code, "return", returned)

    try:
        assert monitor.get_tool(tool) is None and monitor.get_events(tool) == 0
        monitor.use_tool_id(tool, "aqt-private-shared-bootstrap")
        owned = True
        for kind, callback in (
            (monitor.events.PY_START, on_start),
            (monitor.events.PY_RETURN, on_return),
        ):
            registered.append(kind)
            assert monitor.register_callback(tool, kind, callback) is None
        for code in labels:
            assert monitor.get_local_events(tool, code) == 0
            enabled.append(code)
            monitor.set_local_events(tool, code, monitor.events.PY_START | monitor.events.PY_RETURN)
        yield
    except BaseException as error:
        primary = error
        raise
    finally:
        errors = []
        for engine in sql_engines:
            try:
                sa.event.remove(engine, "before_cursor_execute", sql)
            except BaseException as error:
                errors.append(error)
        if owned:
            for code in enabled:
                try:
                    monitor.set_local_events(tool, code, 0)
                    assert monitor.get_local_events(tool, code) == 0
                except BaseException as error:
                    errors.append(error)
            for kind in registered:
                try:
                    monitor.register_callback(tool, kind, None)
                except BaseException as error:
                    errors.append(error)
            try:
                assert monitor.get_events(tool) == 0
                assert monitor.get_tool(tool) == "aqt-private-shared-bootstrap"
                monitor.free_tool_id(tool)
                assert monitor.get_tool(tool) is None
            except BaseException as error:
                errors.append(error)
        if sys.getprofile() is not prior_profile:
            errors.append(AssertionError("original profiling state changed"))
        errors.extend(case.observer_errors)
        if errors:
            raise BaseExceptionGroup(
                "private bootstrap observation cleanup failed",
                ([primary] if primary else []) + errors,
            )


def _closed(case):
    status = case.owner.status()
    assert status.phase == "stopped" and not status.busy and not status.attempted
    assert status.cleanup_complete and status.cleanup_failure is None
    assert case.thread is case.owner._thread and not case.thread.is_alive()
    assert case.close_calls == case.guard_returns == len(case.acquires) == len(case.releases) == 1
    assert case.forbidden == [] and case.guard._descriptor is None
    assert case.configuration_path.read_bytes() == case.configuration_bytes
    assert all(connection.closed for connection in case.connections)
    _assert_scopes_closed(case.runtime.reader)
    after, before, first = _snapshot(case.study), case.before, case.acquires[0]
    assert after.financial == before.financial == case.admitted.financial
    assert all(row in after.leases for row in before.leases)
    added = [row for row in after.leases if row not in before.leases]
    assert len(after.leases) == len(before.leases) + 1 and len(added) == 1
    assert account_lease_from_row(added[0]) == first
    assert first.fencing_generation == before.heads[0]["last_fencing_generation"] + 1
    assert first.account_id == case.study.genesis.scope.account_id
    assert first.revision_number == 1 and first.previous_lease_sha256 is None
    policy = case.configuration.lease_policy()
    assert first.policy_sha256 == policy.semantic_sha256
    assert first.expires_at - first.acquired_at == policy.lease_ttl == timedelta(seconds=60)
    assert policy.maximum_in_flight_duration == timedelta(seconds=5)
    assert policy.takeover_safety_interval == timedelta(seconds=10)
    assert all(row in after.releases for row in before.releases)
    added = [row for row in after.releases if row not in before.releases]
    assert len(after.releases) == len(before.releases) + 1 and len(added) == 1
    release = account_lease_release_from_row(added[0])
    assert case.releases == case.close_returns == [release]
    assert case.release_attempts == [(case.factory.coordinator, first.fence, case.thread)]
    assert release.lease_sha256 == first.semantic_sha256 and release.fence == first.fence
    assert release.policy_sha256 == first.policy_sha256
    assert first.acquired_at <= release.released_at < first.expires_at
    assert after.heads == (
        dict(
            account_id=first.account_id,
            last_fencing_generation=first.fencing_generation,
            current_fencing_generation=None,
            current_lease_sha256=None,
            updated_at=added[0]["released_at"],
        ),
    )
    assert case.disposals == ["venue", "account"]
    assert case.owner._context_error is None
    assert case.guard_primaries == [case.owner._primary_error]
    assert all(thread is case.thread for _, thread in case.trace)
    labels = [name for name, _ in case.trace]
    assert labels.index("close-call") < labels.index("release-return")
    assert labels.index("release-return") < labels.index("venue-dispose-return")
    assert labels.index("account-dispose-return") < labels.index("close-return")
    assert labels[-1] == "guard-return"
    with LocalInstanceGuard(case.lock_path) as guard:
        info = os.fstat(guard.fileno())
        assert (info.st_dev, info.st_ino) == case.lock_identity


@contextmanager
def _case(tmp_path, *, seed=True):
    with study_module._study(tmp_path, install=False) as study:
        _assert_initial_state(study, installed=False)
        configuration = _configuration(study)
        if seed:
            _seed_phase_zero(study)
        path = study.root / "private-shared-bootstrap.json"
        payload = personal_codec.encode_record(configuration)
        study_module._exclusive_file(path, payload)
        study_module._release_setup(study)
        before = _snapshot(study)
        study.ports["venue_engine"].dispose()
        study.ports["account_engine"].dispose()
        case = SimpleNamespace(
            study=study,
            configuration=configuration,
            configuration_path=path,
            configuration_bytes=payload,
            lock_path=study.root / "private-bootstrap.lock",
            before=before,
            admitted=None,
            caller_thread=threading.current_thread(),
            owner=None,
            thread=None,
            factory=None,
            runtime=None,
            account_engine=None,
            venue_engine=None,
            stop_event=None,
            guard=None,
            lock_identity=None,
            acquires=[],
            release_attempts=[],
            releases=[],
            close_calls=0,
            close_returns=[],
            disposals=[],
            guard_returns=0,
            guard_primaries=[],
            trace=[],
            connections=[],
            verify_calls=[],
            verify_returns=[],
            schema_calls=[],
            schema_returns=0,
            watermarks=[],
            sql=[],
            forbidden=[],
            observer_errors=[],
            security=None,
            in_join=False,
            action=None,
            join_events=[],
            proof_calls=[],
            proof_returns=[],
            issuer_calls=[],
            issuer_returns=[],
            auth_returns=[],
            owner_clock_calls=0,
        )
        with _observe(case):
            case.owner = InitialSelectionPreparationOwner(
                configuration_path=str(path),
                account_id=study.genesis.scope.account_id,
                instance_lock=str(case.lock_path),
            )
            assert case.owner._thread is None and not case.lock_path.exists()
            assert _snapshot(study).__dict__ == before.__dict__
            primary = None
            try:
                status = case.owner.start()
                assert status.phase == "idle" and not status.busy and not status.attempted
                assert status.cleanup_complete is False
                assert case.thread is case.owner._thread and case.thread.is_alive()
                assert case.runtime.lease is case.acquires[0]
                assert case.verify_calls == case.schema_calls == []
                case.admitted = _snapshot(study)
                assert case.admitted.financial == before.financial
                case.admitted_sql_count = len(case.sql)
                yield case
            except BaseException as error:
                primary = error
                raise
            finally:
                # No fixture barrier retains a financial worker; the one real
                # owner stop and actual Thread join remain authoritative.
                errors = []
                try:
                    case.owner.stop()
                except BaseException as error:
                    errors.append(error)
                thread = case.owner._thread
                if thread is not None:
                    thread.join(20)
                    if thread.is_alive():
                        errors.append(AssertionError("original bootstrap worker did not exit"))
                    else:
                        try:
                            _closed(case)
                        except BaseException as error:
                            errors.append(error)
                if errors:
                    raise BaseExceptionGroup(
                        "private bootstrap fixture and cleanup failed",
                        ([primary] if primary else []) + errors,
                    )


def _invoke(case, *, cookie=None, call_id="private-bootstrap", cancel_event=None):
    assert case.in_join is False
    case.in_join = True
    try:
        return bootstrap._bootstrap_initial_selection_operator(
            security=case.security,
            owner=case.owner,
            account_id=case.study.genesis.scope.account_id,
            call_id=call_id,
            session_cookie=cookie,
            cancel_event=cancel_event,
        )
    finally:
        case.in_join = False


def _no_financial_effect(case, *, proofs):
    assert (
        len(case.verify_calls)
        == len(case.verify_returns)
        == len(case.schema_calls)
        == case.schema_returns
        == proofs
    )
    assert all(thread is case.thread for _, thread in case.verify_calls)
    assert all(thread is case.thread for _, thread in case.verify_returns)
    assert case.forbidden == [] and not case.owner._attempted
    assert case.owner._preparation_return_admitted is False
    assert case.owner._prepared_proposal_sha256 is None and not case.owner._install_dispatched
    current = _snapshot(case.study)
    assert current.financial == case.admitted.financial
    if proofs:
        assert len(case.sql) > case.admitted_sql_count
        assert all(thread is case.thread for _, thread in case.sql)
    # Original _NOW may relatch raw phase after completed stop. Public status
    # normalizes the finalized/dead Thread before choosing lease expectations.
    status = case.owner.status()
    if status.phase == "stopped":
        assert status.cleanup_complete and case.owner._finalized
        assert case.thread is case.owner._thread and not case.thread.is_alive()
    else:
        assert current.leases == case.admitted.leases and current.releases == case.admitted.releases
        expected = dict(case.admitted.heads[0])
        if proofs:
            assert case.watermarks
            expected["updated_at"] = case.watermarks[-1].replace(tzinfo=None)
        assert current.heads == (expected,)
    _assert_scopes_closed(case.runtime.reader)


def _enabled(pair, case, *, reused=False):
    assert type(pair) is tuple and len(pair) == 2
    capability, response = pair
    assert type(capability) is BacktestLaunchCapability and type(response) is Response
    assert capability.enabled is True and capability.operator_id == "bootstrap opérateur"
    assert type(capability.csrf_token) is str and 32 <= len(capability.csrf_token) <= 128
    assert capability.csrf_header == "X-CSRF-Token"
    assert capability.idempotency_header == "Idempotency-Key" and capability.disabled_reason is None
    assert response.body == b"" and response.status_code == 200 and response.background is None
    expected = [
        (b"cache-control", b"no-store"),
        (b"pragma", b"no-cache"),
        (b"content-length", b"0"),
    ]
    assert [header for header in response.raw_headers if header[0] != b"set-cookie"] == expected
    headers = [value for name, value in response.raw_headers if name == b"set-cookie"]
    assert len(headers) == (0 if reused else 1)
    if not reused:
        jar = SimpleCookie()
        jar.load(headers[0].decode("latin-1"))
        assert set(jar) == {LOCAL_SESSION_COOKIE}
        morsel = jar[LOCAL_SESSION_COOKIE]
        assert 0 < len(morsel.value) <= 2048
        assert morsel["max-age"] == "28800" and morsel["path"] == "/api/v1"
        assert morsel["httponly"] is True and morsel["samesite"] == "strict"
        assert morsel["domain"] == morsel["secure"] == morsel["expires"] == ""
    assert case.issuer_calls[-1][0] is response
    assert case.issuer_returns[-1] is not capability
    assert case.issuer_calls[-1][1] is True
    return capability, response


def _unavailable(error):
    assert type(error) is HTTPException and error.status_code == 503
    assert error.detail == "initial selection bootstrap is unavailable"
    assert error.headers == {"Cache-Control": "no-store", "Pragma": "no-cache"}


def test_fresh_shared_issue_and_reuse_require_two_original_same_owner_proofs(tmp_path):
    with _case(tmp_path) as case:
        case.security = _security()
        capability, response = _enabled(_invoke(case), case)
        cookie = _cookie(response)
        first_expiry = case.auth_returns[0][0][1]
        assert first_expiry == datetime.fromtimestamp(
            int(case.issuer_calls[0][2].timestamp()) + 28800, UTC
        )
        assert (
            case.security.authenticate(cookie, capability.csrf_token, now=datetime.now(UTC))
            == "bootstrap opérateur"
        )
        second, reused = _enabled(_invoke(case, cookie=cookie), case, reused=True)
        _same_secret(second.csrf_token, capability.csrf_token)
        assert reused is not response
        assert (
            len(case.proof_calls)
            == len(case.proof_returns)
            == len(case.issuer_calls)
            == len(case.auth_returns)
            == 2
        )
        assert all(
            type(result) is InitialSelectionReadinessResult and result.status == "ready"
            for result in case.proof_returns
        )
        assert case.proof_calls == ["private-bootstrap", "private-bootstrap"]
        assert case.auth_returns[1][0][1] == first_expiry
        _no_financial_effect(case, proofs=2)
        assert case.owner.status().phase == "idle" and case.thread.is_alive()
        # Closing H is availability closure, not shared-session revocation.
        case.owner.stop()
        assert (
            case.security.authenticate(cookie, capability.csrf_token, now=datetime.now(UTC))
            == "bootstrap opérateur"
        )
        restarted = _security()
        with pytest.raises(HTTPException) as caught:
            restarted.authenticate(cookie, capability.csrf_token, now=datetime.now(UTC))
        assert caught.value.status_code == 401


def test_disabled_original_issuer_preserves_delete_cookie_without_proof_sql_or_owner_clock(
    tmp_path,
):
    with _case(tmp_path) as case:
        case.security = _security(enabled=False)
        before, sql_count = _snapshot(case.study), len(case.sql)
        capability, response = _invoke(case, cookie="bounded-old-cookie")
        assert type(capability) is BacktestLaunchCapability and type(response) is Response
        assert (
            capability.enabled is False and capability.operator_id is capability.csrf_token is None
        )
        assert capability.disabled_reason == "local operator authentication is disabled"
        assert (
            capability.csrf_header == "X-CSRF-Token"
            and capability.idempotency_header == "Idempotency-Key"
        )
        jar = SimpleCookie()
        jar.load(response.headers["set-cookie"])
        assert set(jar) == {LOCAL_SESSION_COOKIE}
        deleted = jar[LOCAL_SESSION_COOKIE]
        assert deleted.value == "" and deleted["max-age"] == "0"
        assert deleted["path"] == "/api/v1" and deleted["samesite"] == "lax"
        assert deleted["httponly"] == deleted["domain"] == deleted["secure"] == ""
        assert deleted["expires"] and response.headers["cache-control"] == "no-store"
        assert response.headers["pragma"] == "no-cache"
        assert case.proof_calls == case.proof_returns == case.auth_returns == []
        assert len(case.issuer_calls) == len(case.issuer_returns) == 1
        assert case.issuer_calls[0][1] is False and case.owner_clock_calls == 0
        assert len(case.sql) == sql_count and _snapshot(case.study).__dict__ == before.__dict__
        _no_financial_effect(case, proofs=0)


def test_original_full_schema_failure_denies_issuance_and_preserves_owner_primary(tmp_path):
    with _case(tmp_path, seed=False) as case:
        case.security = _security()
        with pytest.raises(HTTPException) as caught:
            _invoke(case)
        _unavailable(caught.value)
        assert len(case.proof_calls) == len(case.proof_returns) == 1
        assert case.proof_returns[0].status == "unavailable"
        assert len(case.verify_calls) == len(case.schema_calls) == 1
        assert case.verify_returns == [] and case.schema_returns == 0
        assert case.issuer_calls == case.issuer_returns == case.auth_returns == []
        primary = case.owner._primary_error
        assert type(primary) is DatabaseSchemaNotReady
        frames = []
        traceback = primary.__traceback__
        while traceback is not None:
            frames.append(traceback.tb_frame.f_code)
            traceback = traceback.tb_next
        assert _ReadinessRuntime.verify.__code__ in frames
        assert verify_operational_schema.__code__ in frames
        status = case.owner.stop()
        assert status.phase == "stopped" and status.cleanup_complete
        assert status.primary_failure == "verification_failed"
        assert case.owner._primary_error is primary
        assert _snapshot(case.study).financial == case.before.financial
        assert case.forbidden == [] and len(case.sql) > case.admitted_sql_count


@pytest.mark.parametrize("incoming", ["malformed", "metadata", "operational"])
def test_bounded_foreign_cookie_fallback_is_new_issuance_not_crosspurpose_authentication(
    tmp_path, incoming
):
    with _case(tmp_path) as case:
        case.security = _security()
        foreign, cookie, csrf = None, "not-a-session", "x" * 32
        if incoming == "metadata":
            foreign = MetadataAccessSecurity(
                enabled=True,
                transport_is_loopback_scoped=True,
                operator_id="read operator",
                configured_secret="fresh-N-metadata",
            )
            response = Response()
            capability = foreign.bootstrap_capability(
                response, issued_at=datetime.now(UTC), session_cookie=None
            )
            cookie, csrf = _cookie(response, METADATA_SESSION_COOKIE), capability.csrf_token
        elif incoming == "operational":
            foreign = ContinuousReadAccessSecurity(
                configuration=ContinuousReadAccessConfiguration(
                    True, True, "read operator", "fresh-N-read"
                ),
                account_id=case.study.genesis.scope.account_id,
            )
            foreign.open()
            response = Response()
            capability = foreign.bootstrap_capability(
                response, issued_at=datetime.now(UTC), session_cookie=None
            )
            cookie, csrf = _cookie(response, CONTINUOUS_READ_SESSION_COOKIE), capability.csrf_token
        try:
            with pytest.raises(HTTPException) as denied:
                case.security.authenticate(cookie, csrf, now=datetime.now(UTC))
            assert denied.value.status_code == 401
            capability, response = _enabled(_invoke(case, cookie=cookie), case)
            fresh = _cookie(response)
            if compare_digest(fresh, cookie):
                raise AssertionError("invalid incoming cookie was not replaced")
            assert (
                case.security.authenticate(fresh, capability.csrf_token, now=datetime.now(UTC))
                == "bootstrap opérateur"
            )
            if foreign is not None:
                with pytest.raises(HTTPException) as other:
                    foreign.authenticate(fresh, capability.csrf_token, now=datetime.now(UTC))
                assert other.value.status_code == 401
            assert len(case.issuer_calls) == len(case.auth_returns) == 1
            _no_financial_effect(case, proofs=1)
        finally:
            if type(foreign) is ContinuousReadAccessSecurity:
                foreign.close()


@pytest.mark.parametrize("denial", ["cancelled", "stopped"])
def test_original_predispatch_unavailability_never_issues_a_shared_cookie(tmp_path, denial):
    with _case(tmp_path) as case:
        case.security, cancel = _security(), threading.Event()
        if denial == "cancelled":
            cancel.set()
        else:
            case.owner.stop()
        before, sql_count = _snapshot(case.study), len(case.sql)
        with pytest.raises(HTTPException) as caught:
            _invoke(case, cancel_event=cancel)
        _unavailable(caught.value)
        assert case.issuer_calls == case.issuer_returns == case.auth_returns == []
        assert len(case.sql) == sql_count and _snapshot(case.study).__dict__ == before.__dict__
        _no_financial_effect(case, proofs=0)


def test_actual_stop_after_proof_before_issuer_prevents_staged_delivery(tmp_path):
    with _case(tmp_path) as case:
        case.security = _security()

        def stop(label, event, frame, returned):
            if label == "proof" and event == "return":
                assert returned.status == "ready"
                # M has exited its Condition before this actual return event.
                result = case.owner.stop()
                assert result.phase == "stopped" and result.cleanup_complete

        case.action = stop
        with pytest.raises(HTTPException) as caught:
            _invoke(case)
        _unavailable(caught.value)
        assert len(case.proof_returns) == 1 and case.issuer_calls == case.auth_returns == []
        _no_financial_effect(case, proofs=1)


@pytest.mark.parametrize("fault", ["external-stop", "cancelled"])
def test_postauthentication_stop_or_cancel_discards_private_staged_cookie(tmp_path, fault):
    with _case(tmp_path) as case:
        case.security, cancel = _security(), threading.Event()

        def interrupt(label, event, frame, returned):
            if label == "auth" and event == "return":
                assert case.owner._condition._is_owned()
                (case.stop_event if fault == "external-stop" else cancel).set()

        case.action = interrupt
        with pytest.raises(HTTPException) as caught:
            _invoke(case, cancel_event=cancel)
        _unavailable(caught.value)
        assert len(case.issuer_calls) == len(case.issuer_returns) == len(case.auth_returns) == 1
        assert "set-cookie" in case.issuer_calls[0][0].headers
        assert case.owner._preparation_return_admitted is False
        if fault == "external-stop":
            # Wait through the actual original stop after the join has released
            # its Condition; do not race lease-head observations with cleanup.
            status = case.owner.stop()
            assert status.phase == "stopped" and status.cleanup_complete
        _no_financial_effect(case, proofs=1)


def test_reused_session_expiring_after_real_authentication_denies_final_admission(tmp_path):
    with _case(tmp_path) as case:
        case.security = _security()
        # Explicit fixture issuance, not a bootstrap-readiness qualification.
        expiry = datetime.fromtimestamp(int(datetime.now(UTC).timestamp()) + 4, UTC)
        response = Response()
        existing = case.security.bootstrap_capability(
            response,
            persistence_ready=True,
            issued_at=expiry - timedelta(hours=8),
            session_cookie=None,
        )
        cookie = _cookie(response)
        started = time.monotonic_ns()
        observed = []

        def expire(label, event, frame, returned):
            if label == "auth" and event == "return":
                assert returned[1] == expiry and frame.f_locals["now"] < expiry
                assert case.owner._condition._is_owned()
                remaining = max(0, (expiry - datetime.now(UTC)).total_seconds())
                assert remaining <= 4
                threading.Event().wait(remaining)
                assert datetime.now(UTC) >= expiry
                elapsed = time.monotonic_ns() - started
                assert elapsed < 5_000_000_000
                observed.append(elapsed)

        case.action = expire
        with pytest.raises(HTTPException) as caught:
            _invoke(case, cookie=cookie)
        _unavailable(caught.value)
        assert len(observed) == len(case.auth_returns) == len(case.issuer_returns) == 1
        assert "set-cookie" not in case.issuer_calls[0][0].headers
        _same_secret(case.issuer_returns[0].csrf_token, existing.csrf_token)
        _no_financial_effect(case, proofs=1)


def test_actual_postissue_elapsed_deadline_denies_without_an_extra_proof_or_issuer_call(tmp_path):
    with _case(tmp_path) as case:
        case.security = _security()
        held = []

        def delay(label, event, frame, returned):
            if label == "issuer" and event == "return":
                assert case.owner._condition._is_owned()
                began = time.monotonic_ns()
                threading.Event().wait(5.01)
                held.append(time.monotonic_ns() - began)

        case.action = delay
        with pytest.raises(HTTPException) as caught:
            _invoke(case)
        _unavailable(caught.value)
        assert len(held) == 1 and held[0] >= 5_000_000_000
        assert len(case.proof_returns) == len(case.issuer_calls) == len(case.issuer_returns) == 1
        assert "set-cookie" in case.issuer_calls[0][0].headers
        _no_financial_effect(case, proofs=1)


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
def test_original_issuer_return_boundary_error_keeps_identity_and_traceback(tmp_path, kind):
    primary = kind("test original issuer return boundary fault")
    with _case(tmp_path) as case:
        case.security = _security()

        def fail(label, event, frame, returned):
            if label == "issuer" and event == "return":
                raise primary

        case.action = fail
        with pytest.raises(kind) as caught:
            _invoke(case)
        assert caught.value is primary and primary.__traceback__ is not None
        traceback = primary.__traceback__
        assert len(case.issuer_calls) == len(case.issuer_returns) == 1
        assert case.auth_returns == [] and case.owner._primary_error is None
        assert "set-cookie" in case.issuer_calls[0][0].headers
        _no_financial_effect(case, proofs=1)
    assert primary.__traceback__ is traceback


@pytest.mark.parametrize("fault", ["header", "capability", "configuration"])
def test_postissuer_native_or_captured_configuration_change_denies_private_delivery(
    tmp_path, fault
):
    with _case(tmp_path) as case:
        case.security = _security()

        def mutate(label, event, frame, returned):
            if label == "issuer" and event == "return":
                if fault == "header":
                    frame.f_locals["response"].raw_headers.append((b"x-unexpected", b"denied"))
                elif fault == "capability":
                    object.__setattr__(returned, "operator_id", "different operator")
                else:
                    case.security._operator_id = "different operator"

        case.action = mutate
        with pytest.raises(ValueError, match=_CHANGED if fault == "configuration" else _INVALID):
            _invoke(case)
        assert len(case.issuer_calls) == len(case.issuer_returns) == 1
        assert case.auth_returns == [] and case.owner._primary_error is None
        _no_financial_effect(case, proofs=1)
