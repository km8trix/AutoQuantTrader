"""Current shared authentication before the actual original H/E preparation.

The unchanged F fixture constructs today's real H owner and has the correct
object-only/no-REQUEST teardown. Fixture-owned issuance deliberately supplies
persistence_ready=True; it does not qualify shared bootstrap or any HTTP gate.
Only two original caller-side code objects are locally observed. No global
profiler runs during the worker's two original financial proof bookends.
"""

import sys
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response

from apps.api.authenticated_initial_selection_preparation import (
    _prepare_authenticated_initial_selection,
)
from apps.api.backtest_views import LOCAL_SESSION_COOKIE, LocalOperatorSecurity
from apps.api.continuous_read_access import (
    CONTINUOUS_READ_SESSION_COOKIE,
    ContinuousReadAccessConfiguration,
    ContinuousReadAccessSecurity,
)
from apps.api.metadata_access import METADATA_SESSION_COOKIE, MetadataAccessSecurity
from apps.trader.initial_selection_descriptor import (
    InitialSelectionDescriptor,
    copy_initial_selection_descriptor,
    initial_selection_request_data,
)
from apps.trader.initial_selection_preparation_owner import (
    InitialSelectionPreparationOwner,
    InitialSelectionPreparationResult,
)
from tests.integration import (
    test_continuous_synthetic_initial_selection_preparation_owner as original,
)
from tests.integration.test_continuous_synthetic_factory_partial_cleanup import _snapshot
from tests.integration.test_continuous_synthetic_initial_selection_preparation import (
    _retained_record,
    _same_application_facts,
)

_INVALID = r"^INITIAL_SELECTION_PREPARATION_ACCESS_INVALID$"
_CHANGED = r"^INITIAL_SELECTION_PREPARATION_ACCESS_BINDING_CHANGED$"


def _cookie(response, name):
    jar = SimpleCookie()
    jar.load(response.headers["set-cookie"])
    return jar[name].value


def _security(*, enabled=True):
    return LocalOperatorSecurity(
        enabled=enabled,
        transport_is_loopback_scoped=True,
        operator_id="préparation operator",
        configured_secret="fresh-synthetic-L-session-configuration",
    )


def _session(*, issued_at=None):
    security = _security()
    at = datetime.now(UTC) if issued_at is None else issued_at
    response = Response()
    capability = security.bootstrap_capability(
        response, persistence_ready=True, issued_at=at, session_cookie=None
    )
    assert capability.enabled and capability.operator_id == "préparation operator"
    assert type(capability.csrf_token) is str
    # Independent projection of the original eight-hour integer-second expiry.
    expiry = datetime.fromtimestamp(int(at.timestamp()) + 8 * 60 * 60, UTC)
    return SimpleNamespace(
        security=security,
        cookie=_cookie(response, LOCAL_SESSION_COOKIE),
        csrf=capability.csrf_token,
        expiry=expiry,
    )


def _invoke(case, session, *, call_id="authenticated-preparation", cancel_event=None):
    return _prepare_authenticated_initial_selection(
        security=session.security,
        owner=case.owner,
        account_id=case.study.genesis.scope.account_id,
        call_id=call_id,
        session_cookie=session.cookie,
        csrf_token=session.csrf,
        cancel_event=cancel_event,
    )


@contextmanager
def _observe(case, session, *, after_return=None):
    """Observe actual original calls; a return fault is explicitly test-owned."""
    prepare_code = InitialSelectionPreparationOwner.prepare_initial_selection.__code__
    auth_code = LocalOperatorSecurity.authenticate_with_expiry.__code__
    codes = (prepare_code, auth_code)
    monitor, tool = sys.monitoring, 3
    previous_profile = sys.getprofile()
    probe = SimpleNamespace(events=[], auth=[], host_calls=[], backend_returns=[], faults=[])
    enabled, registered = [], []
    owned = False
    primary = None

    def on_start(code, offset):
        frame = sys._getframe(1)
        try:
            assert frame.f_code is code and any(code is original_code for original_code in codes)
            if code is auth_code:
                assert frame.f_locals["self"] is session.security
                probe.events.append("auth-call")
            else:
                assert frame.f_locals["self"] is case.owner
                assert threading.current_thread() is not case.owner._thread
                probe.host_calls.append((frame.f_locals["call_id"], case.proofs, len(case.puts)))
                probe.events.append("host-call")
        finally:
            del frame

    def on_return(code, offset, returned):
        frame = sys._getframe(1)
        try:
            assert frame.f_code is code and any(code is original_code for original_code in codes)
            if code is auth_code:
                probe.auth.append((returned, frame.f_locals["now"]))
                probe.events.append("auth-return")
            else:
                assert type(returned) is InitialSelectionPreparationResult
                probe.backend_returns.append(returned)
                probe.events.append("host-return")
                if after_return is not None:
                    after_return(returned)
        finally:
            del frame

    try:
        assert monitor.get_tool(tool) is None and monitor.get_events(tool) == 0
        monitor.use_tool_id(tool, "aqt-authenticated-preparation")
        owned = True
        for event, callback in (
            (monitor.events.PY_START, on_start),
            (monitor.events.PY_RETURN, on_return),
        ):
            registered.append(event)
            assert monitor.register_callback(tool, event, callback) is None
        for code in codes:
            assert monitor.get_local_events(tool, code) == 0
            enabled.append(code)
            monitor.set_local_events(tool, code, monitor.events.PY_START | monitor.events.PY_RETURN)
        yield probe
    except BaseException as error:
        primary = error
        raise
    finally:
        errors = []
        if owned:
            for code in enabled:
                try:
                    monitor.set_local_events(tool, code, 0)
                    assert monitor.get_local_events(tool, code) == 0
                except BaseException as error:
                    errors.append(error)
            for event in registered:
                try:
                    monitor.register_callback(tool, event, None)
                except BaseException as error:
                    errors.append(error)
            try:
                assert monitor.get_events(tool) == 0
                assert monitor.get_tool(tool) == "aqt-authenticated-preparation"
                monitor.free_tool_id(tool)
                assert monitor.get_tool(tool) is None
            except BaseException as error:
                errors.append(error)
        if sys.getprofile() is not previous_profile:
            errors.append(AssertionError("original caller profiling state changed"))
        if errors:
            if primary is not None:
                errors.insert(0, primary)
            raise BaseExceptionGroup("authenticated preparation observation cleanup failed", errors)


def _prepared(case, session, result, probe, *, call_id="authenticated-preparation"):
    assert type(result) is InitialSelectionPreparationResult
    assert result.status == result.reason == "prepared"
    assert result.call_id == call_id and result.incarnation == case.incarnation
    assert type(result.descriptor) is InitialSelectionDescriptor
    assert probe.events == [
        "auth-call",
        "auth-return",
        "host-call",
        "host-return",
        "auth-call",
        "auth-return",
    ]
    assert probe.host_calls == [(call_id, 0, 0)]
    assert len(probe.backend_returns) == 1
    backend = probe.backend_returns[0]
    assert result == backend and result is not backend
    assert result.descriptor is not backend.descriptor
    assert [value for value, at in probe.auth] == [
        ("préparation operator", session.expiry),
        ("préparation operator", session.expiry),
    ]
    assert probe.auth[0][1] <= probe.auth[1][1] < session.expiry
    assert case.proofs == 2 and case.proof_errors == [] and len(case.puts) == 1
    assert case.owner._preparation_return_admitted is True
    assert case.owner._prepared_proposal_sha256 == result.descriptor.after_assignment_sha256
    assert case.close_calls == 0 and case.release_attempts == case.releases == []
    assert case.owner._thread.is_alive() and not case.stop_event.is_set()
    reference, record = _retained_record(case)
    scope, heads, evidence = initial_selection_request_data(result.descriptor)
    assert scope == record.scope and heads == record.heads
    assert evidence.object_ref == reference and evidence.semantic_sha256 == record.semantic_sha256
    assert result.descriptor.after_assignment_sha256 == record.proposed.semantic_sha256
    assert result.descriptor.original_lease_sha256 == case.acquires[0].semantic_sha256
    assert result.descriptor.checked_at == record.checked_at
    assert result.descriptor.valid_until == record.valid_until
    additions = _same_application_facts(case.admitted, _snapshot(case.study))
    assert additions == {reference.object_sha256 + ".json": case.puts[0][1]}
    return record


def _launch(case, session, *, cancel_event=None):
    case.access_done = threading.Event()
    case.access_results, case.access_errors = [], []

    def call():
        try:
            case.access_results.append(_invoke(case, session, cancel_event=cancel_event))
        except BaseException as error:
            case.access_errors.append(error)
        finally:
            case.access_done.set()

    assert case.waiter is None
    case.waiter = threading.Thread(target=call, name="fresh-authenticated-preparation-caller")
    case.waiter.start()


def _join(case):
    case.waiter.join(10)
    assert not case.waiter.is_alive() and case.access_done.is_set()
    assert len(case.access_results) + len(case.access_errors) == 1
    return case.access_results, case.access_errors


def test_current_shared_session_prepares_original_e_once_and_detaches_result(tmp_path, monkeypatch):
    with original._host_case(tmp_path, monkeypatch) as case:
        original._start(case)
        session = _session()
        with _observe(case, session) as probe:
            result = _invoke(case, session)
        record = _prepared(case, session, result, probe)
        exported = copy_initial_selection_descriptor(result.descriptor)
        object.__setattr__(result.descriptor, "dependency_semantic_sha256", "0" * 64)
        assert (
            probe.backend_returns[0].descriptor.dependency_semantic_sha256 == record.semantic_sha256
        )
        assert exported.dependency_semantic_sha256 == record.semantic_sha256
        assert _retained_record(case)[1] == record
        before = _snapshot(case.study)
        with _observe(case, session) as repeated:
            unavailable = _invoke(case, session)
        original._unavailable(case, unavailable, "authenticated-preparation", "already_attempted")
        assert len(repeated.host_calls) == 1 and len(repeated.auth) == 2
        assert case.proofs == 2 and len(case.puts) == 1
        assert _snapshot(case.study).__dict__ == before.__dict__


@pytest.mark.parametrize(
    "denial", ["missing", "expired", "foreign", "csrf", "disabled", "metadata", "operational"]
)
def test_actual_shared_auth_denials_precede_every_host_call_and_effect(
    tmp_path, monkeypatch, denial
):
    with original._host_case(tmp_path, monkeypatch) as case:
        session = _session()
        if denial == "missing":
            session.cookie = None
        elif denial == "expired":
            session = _session(issued_at=datetime.now(UTC) - timedelta(hours=8, seconds=1))
        elif denial == "foreign":
            session.security = _security()
        elif denial == "csrf":
            session.csrf = "x" * 32
        elif denial == "disabled":
            session.security = _security(enabled=False)
        elif denial == "metadata":
            security = MetadataAccessSecurity(
                enabled=True,
                transport_is_loopback_scoped=True,
                operator_id="metadata operator",
                configured_secret="fresh-L-metadata-fixture",
            )
            response = Response()
            capability = security.bootstrap_capability(
                response, issued_at=datetime.now(UTC), session_cookie=None
            )
            assert capability.enabled
            session.cookie = _cookie(response, METADATA_SESSION_COOKIE)
            session.csrf = capability.csrf_token
        else:
            security = ContinuousReadAccessSecurity(
                configuration=ContinuousReadAccessConfiguration(
                    True, True, "read operator", "fresh-L-operational-fixture"
                ),
                account_id=case.study.genesis.scope.account_id,
            )
            security.open()
            try:
                response = Response()
                capability = security.bootstrap_capability(
                    response, issued_at=datetime.now(UTC), session_cookie=None
                )
                assert capability.enabled
                session.cookie = _cookie(response, CONTINUOUS_READ_SESSION_COOKIE)
                session.csrf = capability.csrf_token
            finally:
                security.close()
        with _observe(case, session) as probe, pytest.raises(HTTPException) as caught:
            _invoke(case, session)
        assert caught.value.status_code == (403 if denial in ("csrf", "disabled") else 401)
        assert probe.events == ["auth-call"]
        assert probe.host_calls == probe.backend_returns == probe.auth == []
        status = case.owner.status()
        assert status.phase == "new" and not status.busy and not status.attempted
        assert case.owner._thread is None
        assert case.owner._preparation_return_admitted is False
        original._require_no_entry(case)


def test_precancelled_authenticated_call_does_not_consume_original_e_attempt(tmp_path, monkeypatch):
    with original._host_case(tmp_path, monkeypatch, mode="pre-cancel") as case:
        original._start(case)
        session, cancel = _session(), threading.Event()
        cancel.set()
        before = _snapshot(case.study)
        with _observe(case, session) as probe:
            result = _invoke(case, session, cancel_event=cancel)
        original._unavailable(case, result, "authenticated-preparation", "cancelled")
        assert len(probe.host_calls) == 1 and len(probe.auth) == 2
        assert case.proofs == 0 and case.puts == []
        assert case.owner.status().attempted is False
        assert _snapshot(case.study).__dict__ == before.__dict__
        with _observe(case, session) as eligible:
            result = _invoke(case, session, call_id="later-eligible")
        _prepared(case, session, result, eligible, call_id="later-eligible")


def test_actual_session_expiry_across_preparation_denies_delivery_and_retains_object(
    tmp_path, monkeypatch
):
    with original._host_case(tmp_path, monkeypatch, mode="cancelled") as case:
        original._start(case)
        session = _session(issued_at=datetime.now(UTC) - timedelta(hours=8) + timedelta(seconds=3))
        with _observe(case, session) as probe:
            try:
                _launch(case, session)
                original._held_work(case)
                assert probe.auth == [(("préparation operator", session.expiry), probe.auth[0][1])]
                assert probe.auth[0][1] < session.expiry
                # Admission is current; expiry may already have occurred in the
                # first proof. Require actual expiry by this barrier release.
                remaining = max(0, (session.expiry - datetime.now(UTC)).total_seconds())
                assert remaining <= 3
                threading.Event().wait(remaining)
                assert datetime.now(UTC) >= session.expiry
            finally:
                case.allow_put.set()
            results, errors = _join(case)
        assert results == [] and len(errors) == 1 and type(errors[0]) is HTTPException
        assert errors[0].status_code == 401
        assert probe.events[-1] == "auth-call" and len(probe.host_calls) == 1
        assert len(probe.backend_returns) == 1 and probe.backend_returns[0].status == "prepared"
        assert case.owner._preparation_return_admitted is True
        assert case.proofs == 2 and case.proof_errors == [] and len(case.puts) == 1
        assert case.owner._thread.is_alive() and case.close_calls == 0
        _retained_record(case)


def test_cancellation_during_owned_put_preserves_partial_effect_and_original_ownership(
    tmp_path, monkeypatch
):
    with original._host_case(tmp_path, monkeypatch, mode="cancelled") as case:
        original._start(case)
        session, cancel = _session(), threading.Event()
        with _observe(case, session) as probe:
            try:
                _launch(case, session, cancel_event=cancel)
                original._held_work(case)
                cancel.set()
                results, errors = _join(case)
                assert errors == [] and len(results) == 1
                original._unavailable(case, results[0], "authenticated-preparation", "cancelled")
                original._held_work(case)
                assert case.owner._preparation_return_admitted is False
                assert probe.backend_returns[0].reason == "cancelled" and len(probe.auth) == 2
            finally:
                case.allow_put.set()
        assert len(case.puts) == 1
        _retained_record(case)


def test_post_host_return_cancellation_hides_prepared_copy_without_resetting_backend_fact(
    tmp_path, monkeypatch
):
    with original._host_case(tmp_path, monkeypatch) as case:
        original._start(case)
        session, cancel = _session(), threading.Event()

        def cancel_after_return(returned):
            assert returned.status == "prepared" and case.owner._preparation_return_admitted
            cancel.set()

        with _observe(case, session, after_return=cancel_after_return) as probe:
            result = _invoke(case, session, cancel_event=cancel)
        original._unavailable(case, result, "authenticated-preparation", "cancelled")
        assert probe.backend_returns[0].status == "prepared" and len(probe.auth) == 2
        assert case.owner._preparation_return_admitted is True
        assert case.proofs == 2 and len(case.puts) == 1 and case.close_calls == 0
        _retained_record(case)


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
def test_original_host_return_boundary_fault_keeps_exact_primary_and_traceback(
    tmp_path, monkeypatch, kind
):
    primary = kind("test original H return boundary fault")
    with original._host_case(tmp_path, monkeypatch) as case:
        original._start(case)
        session = _session()

        def fail_after_return(returned):
            assert returned.status == "prepared" and case.owner._preparation_return_admitted
            raise primary

        with (
            _observe(case, session, after_return=fail_after_return) as probe,
            pytest.raises(kind) as caught,
        ):
            _invoke(case, session)
        assert caught.value is primary and primary.__traceback__ is not None
        traceback = primary.__traceback__
        assert len(probe.auth) == len(probe.host_calls) == len(probe.backend_returns) == 1
        assert probe.backend_returns[0].status == "prepared"
        assert case.proofs == 2 and len(case.puts) == 1
        assert case.owner._primary_error is None and case.close_calls == 0
        _retained_record(case)
    assert primary.__traceback__ is traceback
    assert not case.thread.is_alive() and case.close_calls == len(case.releases) == 1


def test_actual_return_binding_change_denies_before_changed_result_validator(tmp_path, monkeypatch):
    with original._host_case(tmp_path, monkeypatch) as case:
        original._start(case)
        session, calls = _session(), []

        def forbidden_validator(value):
            calls.append(value)
            raise AssertionError("changed result validator must not run")

        with monkeypatch.context() as patch:

            def change_after_return(returned):
                assert returned.status == "prepared" and case.owner._preparation_return_admitted
                patch.setattr(
                    InitialSelectionPreparationResult, "__post_init__", forbidden_validator
                )

            with (
                _observe(case, session, after_return=change_after_return) as probe,
                pytest.raises(ValueError, match=_CHANGED),
            ):
                _invoke(case, session)
        assert calls == [] and len(probe.auth) == len(probe.host_calls) == 1
        assert case.owner._preparation_return_admitted is True
        assert case.proofs == 2 and len(case.puts) == 1 and case.close_calls == 0
        _retained_record(case)


def test_actual_returned_call_identity_mutation_denies_without_preparation_replay(
    tmp_path, monkeypatch
):
    with original._host_case(tmp_path, monkeypatch) as case:
        original._start(case)
        session = _session()

        def change_after_return(returned):
            assert returned.status == "prepared" and case.owner._preparation_return_admitted
            object.__setattr__(returned, "call_id", "different-returned-call")

        with (
            _observe(case, session, after_return=change_after_return) as probe,
            pytest.raises(ValueError, match=_INVALID),
        ):
            _invoke(case, session)
        assert len(probe.auth) == len(probe.host_calls) == 1
        assert case.owner._preparation_return_admitted is True
        assert case.proofs == 2 and len(case.puts) == 1 and case.close_calls == 0
        _retained_record(case)
