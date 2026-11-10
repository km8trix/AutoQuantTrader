"""Original shared issuer and native wrapper boundaries, without financial proof.

Unstarted owners qualify denials. Explicit idle/Condition carriers below run the
original M caller with literal completion data only; neither carrier executes a
Runtime verifier, acquires a lease or establishes actual readiness. Separate fresh
integrations own those claims. Original security signs and decodes every token.
"""

import copy
import hmac
import sys
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta, timezone
from http.cookies import SimpleCookie
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response

from apps.api import initial_selection_bootstrap as bootstrap
from apps.api.backtest_views import LOCAL_SESSION_COOKIE, LocalOperatorSecurity
from apps.api.contracts import BacktestLaunchCapability
from apps.trader import initial_selection_preparation_owner as host
from tests.unit.test_personal_initial_selection_readiness import (
    _delivery_tail,
    _live_transport_thread,
)

_INVALID = r"^INITIAL_SELECTION_BOOTSTRAP_INVALID$"
_CHANGED = r"^INITIAL_SELECTION_BOOTSTRAP_BINDING_CHANGED$"
_H_STATE = r"^INITIAL_SELECTION_PREPARATION_OWNER_STATE_INVALID$"
_MAX_NS = 2**63 - 1


def _security(*, enabled=True, operator="bootstrap unit operator"):
    return LocalOperatorSecurity(
        enabled=enabled,
        transport_is_loopback_scoped=True,
        operator_id=operator,
        configured_secret="synthetic-bootstrap-unit-configuration",
    )


@pytest.fixture
def case(tmp_path):
    configuration, lock = tmp_path / "unopened-bootstrap.json", tmp_path / "bootstrap.lock"
    value = SimpleNamespace(
        security=_security(),
        owner=host.InitialSelectionPreparationOwner(
            configuration_path=str(configuration),
            account_id="bootstrap-unit-account",
            instance_lock=str(lock),
        ),
        configuration=configuration,
        lock=lock,
    )
    yield value
    assert not configuration.exists() and not lock.exists()
    assert not value.owner._attempted and not value.owner._preparation_return_admitted
    assert value.owner._prepared_proposal_sha256 is value.owner._terminal_install is None
    assert not value.owner._install_dispatched and not value.owner._install_return_admitted
    assert value.owner._thread is None or not value.owner._thread.is_alive()


def _call(case, **changes):
    arguments = dict(
        security=case.security,
        owner=case.owner,
        account_id="bootstrap-unit-account",
        call_id="bootstrap-unit-call",
        session_cookie=None,
        cancel_event=None,
    )
    arguments.update(changes)
    return bootstrap._bootstrap_initial_selection_operator(**arguments)


def _unavailable(error):
    assert type(error) is HTTPException
    assert error.status_code == 503
    assert error.detail == "initial selection bootstrap is unavailable"
    assert error.headers == {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _cookie(response):
    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    return cookies[LOCAL_SESSION_COOKIE].value


def _same_credential(actual, expected):
    if type(actual) is not str or type(expected) is not str:
        raise AssertionError("synthetic credential comparison failed")
    try:
        matched = hmac.compare_digest(actual, expected)
    except (TypeError, ValueError):
        raise AssertionError("synthetic credential comparison failed") from None
    if not matched:
        raise AssertionError("synthetic credential comparison failed")


@contextmanager
def _observed(*, on_call=None, on_return=None, extra_codes=None):
    """Caller-thread original-code observations, restored even for BaseException."""
    labels = {
        host.InitialSelectionPreparationOwner.check_initial_selection_readiness.__code__: "proof",
        LocalOperatorSecurity.bootstrap_capability.__code__: "issuer",
        LocalOperatorSecurity.authenticate_with_expiry.__code__: "authenticate",
        host.InitialSelectionPreparationOwner._now.__code__: "owner-clock",
    }
    if extra_codes is not None:
        labels.update(extra_codes)
    calls = {name: 0 for name in labels.values()}
    returned_values = {name: [] for name in labels.values()}
    previous = sys.getprofile()

    def observe(frame, event, returned):
        try:
            label = labels.get(frame.f_code)
            if label is None:
                return
            if event == "call":
                calls[label] += 1
                if on_call is not None:
                    on_call(label, frame)
            elif event == "return":
                returned_values[label].append(returned)
                if on_return is not None:
                    on_return(label, returned, frame)
        finally:
            del frame

    sys.setprofile(observe)
    try:
        yield SimpleNamespace(calls=calls, returns=returned_values)
    finally:
        sys.setprofile(previous)
        assert sys.getprofile() is previous


@contextmanager
def _transport(case, monkeypatch):
    """Only native M delivery transport: there is no owner/financial worker."""
    owner = case.owner
    owner._phase, owner._busy, owner._cleanup_ok = "idle", False, False
    owner._startup_deadline = owner._lifetime_deadline = owner._work_deadline = _MAX_NS
    condition = owner._condition
    with _live_transport_thread(owner) as worker:
        held = _delivery_tail(monkeypatch, owner, worker)
        yield held
        assert condition.acquire(blocking=False), "bootstrap retained the native nonreentrant lock"
        condition.release()
    assert not worker.is_alive()
    assert not owner._attempted and owner._primary_error is None


@pytest.mark.parametrize(
    ("name", "bad"),
    [
        ("account_id", None),
        ("account_id", True),
        ("account_id", "two words"),
        ("call_id", None),
        ("call_id", ""),
        ("call_id", "a" * 129),
        ("session_cookie", True),
        ("session_cookie", b"cookie"),
        ("session_cookie", "x" * 2049),
        ("cancel_event", False),
        ("cancel_event", object()),
    ],
)
def test_native_arguments_deny_before_any_original_proof_or_issuer(case, name, bad):
    with _observed() as events, pytest.raises(ValueError, match=_INVALID):
        _call(case, **{name: bad})
    assert all(count == 0 for count in events.calls.values())
    assert case.owner._slot is case.owner._thread is None


@pytest.mark.parametrize("target", ["owner", "security"])
def test_foreign_receivers_are_denied_before_any_getter(case, target):
    callbacks = []

    class Foreign:
        def __getattribute__(self, name):
            callbacks.append(name)
            raise AssertionError("foreign bootstrap getter ran")

    with _observed() as events, pytest.raises(ValueError, match=_INVALID):
        _call(case, **{target: Foreign()})
    assert callbacks == [] and all(count == 0 for count in events.calls.values())


def test_copied_host_is_not_an_original_owner(case):
    duplicate = copy.copy(case.owner)
    with _observed() as events, pytest.raises(ValueError, match=_H_STATE):
        _call(case, owner=duplicate)
    assert all(count == 0 for count in events.calls.values())


def test_configured_account_must_match_before_any_proof(case):
    with _observed() as events, pytest.raises(ValueError, match=_INVALID):
        _call(case, account_id="other-valid-account")
    assert all(count == 0 for count in events.calls.values())


@pytest.mark.parametrize("field", ["account_id", "call_id", "session_cookie"])
def test_hostile_text_never_supplies_operators(case, field):
    callbacks = []

    def forbidden(*args, **kwargs):
        callbacks.append(True)
        raise AssertionError("hostile bootstrap text operator ran")

    class Hostile(str):
        __eq__ = forbidden
        __hash__ = forbidden
        __len__ = forbidden
        __str__ = forbidden

    with _observed() as events, pytest.raises(ValueError, match=_INVALID):
        _call(case, **{field: Hostile("hostile")})
    assert callbacks == [] and all(count == 0 for count in events.calls.values())


@pytest.mark.parametrize("field", ["_enabled", "_operator_id"])
def test_malformed_native_security_configuration_is_not_readiness(case, field):
    original = getattr(case.security, field)
    setattr(case.security, field, 1)
    try:
        with _observed() as events, pytest.raises(ValueError, match=_INVALID):
            _call(case)
        assert all(count == 0 for count in events.calls.values())
    finally:
        setattr(case.security, field, original)


def test_disabled_original_issuer_skips_proof_owner_clock_and_delivery_auth(case, monkeypatch):
    case.security = _security(enabled=False, operator="单元 operator")
    clock_calls = []

    def forbidden():
        clock_calls.append(True)
        raise AssertionError("disabled bootstrap borrowed the owner clock")

    monkeypatch.setattr(host.time, "monotonic_ns", forbidden)
    with _observed(extra_codes={bootstrap._monotonic.__code__: "join-clock"}) as events:
        capability, response = _call(case, session_cookie="bounded invalid old cookie")
    assert type(capability) is BacktestLaunchCapability and not capability.enabled
    assert capability.operator_id is capability.csrf_token is None
    assert capability.csrf_header == "X-CSRF-Token"
    assert capability.idempotency_header == "Idempotency-Key"
    assert capability.disabled_reason == "local operator authentication is disabled"
    assert type(response) is Response and response.body == b"" and response.background is None
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    deleted = SimpleCookie()
    deleted.load(response.headers["set-cookie"])
    assert deleted[LOCAL_SESSION_COOKIE].value == ""
    assert deleted[LOCAL_SESSION_COOKIE]["max-age"] == "0"
    assert deleted[LOCAL_SESSION_COOKIE]["path"] == "/api/v1"
    assert events.calls == {
        "proof": 0,
        "issuer": 1,
        "authenticate": 0,
        "owner-clock": 0,
        "join-clock": 0,
    }
    assert clock_calls == [] and case.owner._thread is None


def test_unstarted_original_owner_denies_after_one_proof_without_issuing(case):
    with _observed() as events, pytest.raises(HTTPException) as caught:
        _call(case)
    _unavailable(caught.value)
    assert events.calls["proof"] == 1
    assert events.calls["issuer"] == events.calls["authenticate"] == 0
    assert case.owner._slot is case.owner._thread is None


@pytest.mark.parametrize("kind", ["exception", "base_exception"])
def test_actual_original_proof_entry_error_keeps_identity_and_traceback(case, kind):
    primary = (
        RuntimeError("synthetic original proof failure")
        if kind == "exception"
        else KeyboardInterrupt()
    )
    captured = []

    def fail(label, frame):
        if label == "proof":
            try:
                raise primary
            except BaseException as error:
                captured.append(error.__traceback__)
                raise

    with _observed(on_call=fail) as events, pytest.raises(type(primary)) as caught:
        _call(case)
    assert caught.value is primary
    assert any(item is captured[0] for item in _tracebacks(primary.__traceback__))
    assert events.calls["proof"] == 1
    assert events.calls["issuer"] == events.calls["authenticate"] == 0


def _tracebacks(traceback):
    while traceback is not None:
        yield traceback
        traceback = traceback.tb_next


@pytest.mark.parametrize("incoming", [None, "bounded invalid cookie"])
def test_transport_only_staging_uses_original_issuer_and_authentication_once(
    case, monkeypatch, incoming
):
    with _transport(case, monkeypatch) as held, _observed() as events:
        capability, response = _call(case, session_cookie=incoming)
    assert len(held) == 1 and held[0].completed and held[0].result == "verified"
    assert events.calls["proof"] == events.calls["issuer"] == events.calls["authenticate"] == 1
    assert type(capability) is BacktestLaunchCapability and capability.enabled
    assert capability.operator_id == "bootstrap unit operator"
    assert type(response) is Response and response.body == b""
    assert response.background is None and response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert len(_cookie(response)) <= 2048
    operator, expiry = case.security.authenticate_with_expiry(
        _cookie(response),
        capability.csrf_token,
        now=datetime.now(UTC),
    )
    assert operator == capability.operator_id and expiry > datetime.now(UTC)
    assert case.owner._slot is case.owner._active_nonce is None
    assert not case.owner._attempted


def test_transport_only_valid_cookie_reuse_preserves_original_expiry_and_no_set_cookie(
    case, monkeypatch
):
    original_response = Response()
    original_capability = case.security.bootstrap_capability(
        original_response,
        persistence_ready=True,
        issued_at=datetime.now(UTC),
        session_cookie=None,
    )
    cookie = _cookie(original_response)
    _, old_expiry = case.security.authenticate_with_expiry(
        cookie,
        original_capability.csrf_token,
        now=datetime.now(UTC),
    )
    with _transport(case, monkeypatch), _observed() as events:
        capability, response = _call(case, session_cookie=cookie)
    assert events.calls["proof"] == events.calls["issuer"] == events.calls["authenticate"] == 1
    assert "set-cookie" not in response.headers
    _same_credential(capability.csrf_token, original_capability.csrf_token)
    operator, expiry = case.security.authenticate_with_expiry(
        cookie,
        capability.csrf_token,
        now=datetime.now(UTC),
    )
    assert operator == capability.operator_id and expiry == old_expiry


@pytest.mark.parametrize("stage", ["proof", "issuer", "authenticate"])
def test_transport_only_cancellation_discards_staged_delivery_without_retry(
    case, monkeypatch, stage
):
    cancel, observed = threading.Event(), []

    def cancel_after(label, returned, frame):
        if label == stage and not observed:
            observed.append(stage)
            cancel.set()

    with (
        _transport(case, monkeypatch),
        _observed(on_return=cancel_after) as events,
        pytest.raises(HTTPException) as caught,
    ):
        _call(case, cancel_event=cancel)
    _unavailable(caught.value)
    assert observed == [stage] and events.calls["proof"] == 1
    expected = 0 if stage == "proof" else 1
    assert events.calls["issuer"] == expected
    assert events.calls["authenticate"] == (1 if stage == "authenticate" else 0)
    assert not case.owner._attempted and case.owner._primary_error is None


@pytest.mark.parametrize("stage", ["issuer", "authenticate"])
def test_transport_only_original_issuer_and_auth_errors_are_not_replaced(case, monkeypatch, stage):
    primary = HTTPException(401, "synthetic original private dependency error")

    def fail(label, frame):
        if label == stage:
            raise primary

    with (
        _transport(case, monkeypatch),
        _observed(on_call=fail) as events,
        pytest.raises(HTTPException) as caught,
    ):
        _call(case)
    assert caught.value is primary and events.calls[stage] == 1
    assert events.calls["proof"] == 1 and not case.owner._attempted


@pytest.mark.parametrize("field", ["_enabled", "_operator_id"])
def test_transport_only_configuration_drift_after_proof_precedes_issuance(case, monkeypatch, field):
    original = getattr(case.security, field)

    def mutate(label, returned, frame):
        if label == "proof":
            setattr(
                case.security, field, not original if field == "_enabled" else "different operator"
            )

    try:
        with (
            _transport(case, monkeypatch),
            _observed(on_return=mutate) as events,
            pytest.raises(ValueError, match=_CHANGED),
        ):
            _call(case)
        assert events.calls["proof"] == 1 and events.calls["issuer"] == 0
    finally:
        setattr(case.security, field, original)


@pytest.mark.parametrize("kind", ["condition", "thread"])
def test_transport_only_coordinated_owner_alias_drift_after_proof_is_not_current(
    case, monkeypatch, kind
):
    original, old_condition = case.owner._original, case.owner._condition
    old_thread = None

    def mutate(label, returned, frame):
        if label != "proof":
            return
        if kind == "condition":
            replacement = threading.Condition(threading.Lock())
            case.owner._condition = replacement
            case.owner._original = (*original[:4], replacement, *original[5:])
        else:
            case.owner._thread = threading.Thread(target=lambda: None)

    with _transport(case, monkeypatch):
        old_thread = case.owner._thread
        try:
            with _observed(on_return=mutate) as events, pytest.raises(ValueError, match=_CHANGED):
                _call(case)
            assert events.calls["proof"] == 1 and events.calls["issuer"] == 0
        finally:
            case.owner._condition, case.owner._original = old_condition, original
            case.owner._thread = old_thread


def _capability(*, enabled=True):
    return BacktestLaunchCapability(
        enabled=enabled,
        operator_id="单元 operator" if enabled else None,
        csrf_token="a" * 43 if enabled else None,
        csrf_header="X-CSRF-Token",
        idempotency_header="Idempotency-Key",
        disabled_reason=None if enabled else "local operator authentication is disabled",
    )


@pytest.mark.parametrize("enabled", [False, True])
def test_pure_capability_native_projection_has_six_fields_and_fresh_copies(enabled):
    original = _capability(enabled=enabled)
    values = bootstrap._capability_values(original)
    assert type(values) is tuple and len(values) == 6
    assert values == (
        original.enabled,
        original.operator_id,
        original.csrf_token,
        original.csrf_header,
        original.idempotency_header,
        original.disabled_reason,
    )
    first = bootstrap._capability_from_values(values)
    second = bootstrap._capability_from_values(values)
    assert type(first) is type(second) is BacktestLaunchCapability
    assert first is not second and first is not original
    assert first.model_dump() == second.model_dump() == original.model_dump()
    object.__setattr__(original, "csrf_header", "mutated-original")
    object.__setattr__(first, "idempotency_header", "mutated-first-copy")
    assert second.csrf_header == "X-CSRF-Token"
    assert second.idempotency_header == "Idempotency-Key"


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("enabled", 1),
        ("operator_id", None),
        ("operator_id", ""),
        ("operator_id", " padded "),
        ("operator_id", "x" * 129),
        ("operator_id", "line\nbreak"),
        ("csrf_token", None),
        ("csrf_token", "a" * 31),
        ("csrf_token", "a" * 129),
        ("csrf_token", "!" * 43),
        ("csrf_header", "X-Metadata-CSRF-Token"),
        ("idempotency_header", "wrong"),
        ("disabled_reason", "unexpected"),
    ],
)
def test_pure_capability_native_and_combination_faults_do_not_coerce(field, bad):
    value = _capability()
    object.__setattr__(value, field, bad)
    with pytest.raises(ValueError, match=_INVALID):
        bootstrap._capability_values(value)


@pytest.mark.parametrize("field", ["operator_id", "csrf_token", "csrf_header", "disabled_reason"])
def test_pure_late_hostile_capability_leaf_denies_before_operator_or_constructor(field):
    value = _capability()
    operators, constructors = [], []

    def forbidden(*args, **kwargs):
        operators.append(True)
        raise AssertionError("hostile capability leaf operator ran")

    class Hostile(str):
        __eq__ = forbidden
        __hash__ = forbidden
        __len__ = forbidden
        __str__ = forbidden

    object.__setattr__(value, field, Hostile("hostile"))
    previous = sys.getprofile()
    code = BacktestLaunchCapability.__init__.__code__

    def observe(frame, event, returned):
        if (event == "call" and frame.f_code is code) and type(
            frame.f_locals.get("self")
        ) is BacktestLaunchCapability:
            constructors.append(True)

    try:
        sys.setprofile(observe)
        with pytest.raises(ValueError, match=_INVALID):
            bootstrap._capability_values(value)
    finally:
        sys.setprofile(previous)
    assert sys.getprofile() is previous and operators == constructors == []


def test_pure_capability_rejects_foreign_before_getters():
    callbacks = []

    class Foreign:
        def __getattribute__(self, name):
            callbacks.append(name)
            raise AssertionError("foreign capability getter ran")

    with pytest.raises(ValueError, match=_INVALID):
        bootstrap._capability_values(Foreign())
    assert callbacks == []


@pytest.mark.parametrize(
    "bad",
    [None, True, datetime(2026, 1, 1), datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=1)))],
)
def test_pure_native_utc_rejects_other_representations_without_a_clock(bad):
    with pytest.raises(HTTPException) as caught:
        bootstrap._utc(bad)
    _unavailable(caught.value)


def test_pure_native_utc_and_original_unicode_operator_grammar_are_preserved():
    at = datetime(2026, 1, 1, tzinfo=UTC)
    assert bootstrap._utc(at) is at
    assert bootstrap._operator("单元 operator") == "单元 operator"
    assert bootstrap._operator("x" * 128) == "x" * 128


@pytest.mark.parametrize("bad", [True, "", " padded ", "x" * 129, "tab\toperator"])
def test_pure_operator_rejects_only_original_native_bounds(bad):
    with pytest.raises(ValueError, match=_INVALID):
        bootstrap._operator(bad)


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("body", b"unexpected"),
        ("body", ""),
        ("status_code", True),
        ("status_code", 201),
        ("background", object()),
        ("raw_headers", {}),
        ("raw_headers", [("content-length", b"0")]),
        ("raw_headers", [(b"content-length", "0")]),
        ("raw_headers", [(b"content-length", b"0", b"extra")]),
    ],
)
def test_pure_response_native_admission_does_not_borrow_a_response_port(field, bad):
    response = Response(headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
    setattr(response, field, bad)
    with pytest.raises(ValueError, match=_INVALID):
        bootstrap._headers(response)


def test_pure_response_rejects_foreign_before_getters():
    callbacks = []

    class Foreign:
        def __getattribute__(self, name):
            callbacks.append(name)
            raise AssertionError("foreign Response getter ran")

    with pytest.raises(ValueError, match=_INVALID):
        bootstrap._headers(Foreign())
    assert callbacks == []


@pytest.mark.parametrize("enabled", [False, True])
def test_pure_header_candidate_comes_only_from_original_issue_or_delete(enabled):
    response = Response(headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
    security = _security(enabled=enabled)
    capability = security.bootstrap_capability(
        response,
        persistence_ready=enabled,
        issued_at=datetime.now(UTC),
        session_cookie=None,
    )
    headers = bootstrap._headers(response)
    assert type(headers) is tuple and all(type(item) is tuple for item in headers)
    candidate = bootstrap._candidate_cookie(headers, None, enabled=enabled)
    if enabled:
        _same_credential(candidate, _cookie(response))
        assert len(candidate) <= 2048 and capability.enabled
        assert (
            security.authenticate(candidate, capability.csrf_token, now=datetime.now(UTC))
            == security._operator_id
        )
    else:
        assert candidate is None and not capability.enabled


@pytest.mark.parametrize(
    "alteration", ["extra", "duplicate", "cache", "cookie", "secure", "domain", "oversize"]
)
def test_pure_cookie_framing_and_header_allowlist_are_not_relaxed(alteration):
    response = Response(headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
    _security().bootstrap_capability(
        response,
        persistence_ready=True,
        issued_at=datetime.now(UTC),
        session_cookie=None,
    )
    if alteration == "extra":
        response.raw_headers.append((b"x-unselected", b"value"))
    elif alteration == "duplicate":
        response.raw_headers.append(
            next(item for item in response.raw_headers if item[0] == b"set-cookie")
        )
    elif alteration == "cache":
        response.raw_headers = [
            (key, b"public" if key == b"cache-control" else value)
            for key, value in response.raw_headers
        ]
    else:
        for index, (key, value) in enumerate(response.raw_headers):
            if key != b"set-cookie":
                continue
            if alteration == "cookie":
                value = value.replace(b"aqt_local_session=", b"other_session=", 1)
            elif alteration == "secure":
                value += b"; Secure"
            elif alteration == "domain":
                value += b"; Domain=example.invalid"
            else:
                value = (
                    b"aqt_local_session="
                    + b"x" * 2049
                    + b"; HttpOnly; Max-Age=28800; Path=/api/v1; SameSite=strict"
                )
            response.raw_headers[index] = (key, value)
    with pytest.raises(ValueError, match=_INVALID):
        headers = bootstrap._headers(response)
        bootstrap._candidate_cookie(headers, None, enabled=True)


def test_transport_only_reused_session_expiring_after_authentication_is_not_delivered(
    case, monkeypatch
):
    response = Response()
    capability = case.security.bootstrap_capability(
        response,
        persistence_ready=True,
        issued_at=datetime.now(UTC) - timedelta(hours=8) + timedelta(seconds=3),
        session_cookie=None,
    )
    cookie = _cookie(response)
    _, expires_at = case.security.authenticate_with_expiry(
        cookie, capability.csrf_token, now=datetime.now(UTC)
    )
    delayed = []

    def expire_after_auth(label, returned, frame):
        if label == "authenticate" and type(returned) is tuple:
            assert returned[1] == expires_at
            remaining = max(0, (expires_at - datetime.now(UTC)).total_seconds())
            assert remaining <= 3
            threading.Event().wait(remaining + 0.01)
            assert datetime.now(UTC) >= expires_at
            delayed.append(True)

    with (
        _transport(case, monkeypatch),
        _observed(on_return=expire_after_auth) as events,
        pytest.raises(HTTPException) as caught,
    ):
        _call(case, session_cookie=cookie)
    _unavailable(caught.value)
    assert delayed == [True]
    assert events.calls["proof"] == events.calls["issuer"] == events.calls["authenticate"] == 1
    assert not case.owner._attempted and case.owner._primary_error is None


@pytest.mark.parametrize(
    "fault", ["enabled", "csrf", "header", "body", "status", "background", "extra_header"]
)
def test_transport_only_malformed_original_issuer_output_stays_private(case, monkeypatch, fault):
    observed = []

    def corrupt(label, returned, frame):
        if label != "issuer":
            return
        observed.append(fault)
        response = frame.f_locals["response"]
        if fault == "enabled":
            object.__setattr__(returned, "enabled", 1)
        elif fault == "csrf":
            object.__setattr__(returned, "csrf_token", "too-short")
        elif fault == "header":
            object.__setattr__(returned, "csrf_header", "X-Metadata-CSRF-Token")
        elif fault == "body":
            response.body = b"unexpected staged payload"
        elif fault == "status":
            response.status_code = True
        elif fault == "background":
            response.background = lambda: None
        else:
            response.raw_headers.append((b"x-unselected", b"value"))

    with (
        _transport(case, monkeypatch),
        _observed(on_return=corrupt) as events,
        pytest.raises(ValueError, match=_INVALID),
    ):
        _call(case)
    assert observed == [fault]
    assert events.calls["proof"] == events.calls["issuer"] == 1
    assert events.calls["authenticate"] == 0
    assert not case.owner._attempted and case.owner._primary_error is None


@pytest.mark.parametrize("field", ["call_id", "incarnation", "status"])
def test_transport_only_proof_result_native_correlation_is_rechecked_before_issuer(
    case, monkeypatch, field
):
    observed = []

    def corrupt(label, returned, frame):
        if label == "proof":
            observed.append(field)
            object.__setattr__(
                returned, field, True if field == "status" else "other-valid-identity"
            )

    with (
        _transport(case, monkeypatch),
        _observed(on_return=corrupt) as events,
        pytest.raises(ValueError, match=_INVALID),
    ):
        _call(case)
    assert observed == [field] and events.calls["proof"] == 1
    assert events.calls["issuer"] == events.calls["authenticate"] == 0


@pytest.mark.parametrize("stage", ["issuer", "authenticate"])
def test_transport_only_outer_deadline_is_not_restarted_after_proof(case, monkeypatch, stage):
    clock, joined, observed = [None], [], []
    original_monotonic = host.time.monotonic_ns
    monkeypatch.setattr(
        host.time,
        "monotonic_ns",
        lambda: original_monotonic() if clock[0] is None else clock[0],
    )

    def expire(label, returned, frame):
        if label == "join-clock":
            joined.append(returned)
            clock[0] = returned
        elif label == "proof":
            clock[0] = joined[0] + 2_000_000_000
        elif label == stage:
            observed.append(stage)
            clock[0] = joined[0] + case.owner._limits[1]

    with (
        _transport(case, monkeypatch),
        _observed(
            on_return=expire, extra_codes={bootstrap._monotonic.__code__: "join-clock"}
        ) as events,
        pytest.raises(HTTPException) as caught,
    ):
        _call(case)
    _unavailable(caught.value)
    assert observed == [stage] and len(joined) == 1
    assert events.calls["proof"] == events.calls["issuer"] == 1
    assert events.calls["authenticate"] == (1 if stage == "authenticate" else 0)
    assert not case.owner._attempted and case.owner._primary_error is None


def test_transport_only_original_valid_operator_cannot_relax_cookie_delivery_bound(
    case, monkeypatch
):
    # Original operator grammar permits 128 astral characters. JSON escaping
    # can nevertheless make its signed cookie exceed the original 2048 limit.
    case.security = _security(operator="\U0001f680" * 128)
    observed = []

    def inspect_original_issue(label, returned, frame):
        if label == "issuer":
            assert len(_cookie(frame.f_locals["response"])) > 2048
            observed.append(True)

    with (
        _transport(case, monkeypatch),
        _observed(on_return=inspect_original_issue) as events,
        pytest.raises(ValueError, match=_INVALID),
    ):
        _call(case)
    assert observed == [True]
    assert events.calls["proof"] == events.calls["issuer"] == 1
    assert events.calls["authenticate"] == 0


def test_pure_late_hostile_header_bytes_are_rejected_before_operators():
    callbacks = []

    def forbidden(*args, **kwargs):
        callbacks.append(True)
        raise AssertionError("hostile raw-header operator ran")

    class Hostile(bytes):
        __eq__ = forbidden
        __hash__ = forbidden
        __len__ = forbidden
        decode = forbidden

    response = Response(headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
    response.raw_headers.append((b"set-cookie", Hostile(b"hostile")))
    with pytest.raises(ValueError, match=_INVALID):
        bootstrap._headers(response)
    assert callbacks == []


@pytest.mark.parametrize(
    ("owner", "name"),
    [
        (LocalOperatorSecurity, "bootstrap_capability"),
        (LocalOperatorSecurity, "authenticate_with_expiry"),
        (LocalOperatorSecurity, "_decode"),
        (LocalOperatorSecurity, "_issue"),
        (LocalOperatorSecurity, "_disabled"),
        (host.InitialSelectionPreparationOwner, "check_initial_selection_readiness"),
        (host.InitialSelectionPreparationOwner, "_now"),
        (Response, "__init__"),
        (Response, "render"),
        (Response, "init_headers"),
        (Response, "set_cookie"),
        (Response, "delete_cookie"),
        (threading.Event, "is_set"),
    ],
)
def test_selected_original_method_drift_is_rejected_before_substitute(
    case, monkeypatch, owner, name
):
    callbacks = []

    def forbidden(*args, **kwargs):
        callbacks.append(True)
        raise AssertionError("substituted bootstrap dependency ran")

    with monkeypatch.context() as patch:
        patch.setattr(owner, name, forbidden)
        with _observed() as events, pytest.raises(ValueError, match=_CHANGED):
            _call(case)
        assert callbacks == [] and all(count == 0 for count in events.calls.values())


@pytest.mark.parametrize(
    "name",
    [
        "_BINDINGS",
        "_bindings",
        "_PROOF",
        "_BOOTSTRAP",
        "_AUTHENTICATE",
        "_CAPABILITY_VALUES",
        "_capability_from_values",
        "_HEADERS",
        "_CONDITION_ENTER",
        "_CONDITION_EXIT",
        "_CLOCK_NOW",
        "_MONOTONIC_NS",
    ],
)
def test_selected_dispatch_and_helper_alias_drift_cannot_run(case, monkeypatch, name):
    callbacks = []

    def forbidden(*args, **kwargs):
        callbacks.append(True)
        raise AssertionError("substituted bootstrap alias ran")

    with monkeypatch.context() as patch:
        patch.setattr(bootstrap, name, forbidden)
        with _observed() as events, pytest.raises(ValueError, match=_CHANGED):
            _call(case)
        assert callbacks == [] and all(count == 0 for count in events.calls.values())


@pytest.mark.parametrize("name", ["_BOOTSTRAP", "_CAPABILITY_VALUES", "_HEADERS"])
def test_transport_only_postproof_alias_drift_is_checked_before_next_dependency(
    case, monkeypatch, name
):
    callbacks, observed = [], []

    def forbidden(*args, **kwargs):
        callbacks.append(True)
        raise AssertionError("post-proof substituted alias ran")

    with _transport(case, monkeypatch), monkeypatch.context() as patch:

        def mutate(label, returned, frame):
            if label == "proof":
                observed.append(True)
                patch.setattr(bootstrap, name, forbidden)

        with _observed(on_return=mutate) as events, pytest.raises(ValueError, match=_CHANGED):
            _call(case)
        assert observed == [True] and callbacks == []
        assert events.calls["proof"] == 1 and events.calls["issuer"] == 0


def test_cancel_event_instance_shadow_is_not_an_authority_callback(case):
    cancel, callbacks = threading.Event(), []

    def forbidden():
        callbacks.append(True)
        raise AssertionError("bootstrap followed an Event instance shadow")

    cancel.is_set = forbidden
    with _observed() as events, pytest.raises(ValueError, match=_CHANGED):
        _call(case, cancel_event=cancel)
    assert callbacks == [] and all(count == 0 for count in events.calls.values())


def test_transport_only_non_boolean_event_flag_keeps_original_h_error_without_truthiness(
    case, monkeypatch
):
    callbacks = []

    class HostileFlag:
        def __bool__(self):
            callbacks.append(True)
            raise AssertionError("bootstrap coerced an Event flag")

    cancel = threading.Event()
    cancel._flag = HostileFlag()
    with (
        _transport(case, monkeypatch),
        _observed() as events,
        pytest.raises(ValueError, match=_H_STATE) as caught,
    ):
        _call(case, cancel_event=cancel)
    # Initial native/cached admission need not pre-sample this flag. The first
    # actual sample is in saved original M, whose own fixed error stays original.
    assert callbacks == [] and events.calls["proof"] == 1 and events.calls["issuer"] == 0
    assert any(
        item.tb_frame.f_code is host._event_is_set.__code__
        for item in _tracebacks(caught.value.__traceback__)
    )
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("kind", ["condition", "thread"])
def test_independent_graph_is_captured_before_original_entry_callback(case, kind):
    """Pure original-entry admission only, with no proof or worker dispatch."""
    original, condition, worker = case.owner._original, case.owner._condition, case.owner._thread
    replacement = threading.Condition(threading.Lock())
    changed, replacement_calls = [], []

    def after_entry(label, returned, frame):
        if label != "owner-entry" or changed:
            return
        assert frame.f_locals["value"] is case.owner
        changed.append(kind)
        if kind == "condition":
            case.owner._condition = replacement
            case.owner._original = (*original[:4], replacement, *original[5:])
        else:
            case.owner._thread = threading.Thread(target=lambda: None)

    def condition_enter(label, frame):
        if label == "condition-enter" and frame.f_locals.get("self") is replacement:
            replacement_calls.append(True)

    try:
        with (
            _observed(
                on_call=condition_enter,
                on_return=after_entry,
                extra_codes={
                    host._entry.__code__: "owner-entry",
                    threading.Condition.__enter__.__code__: "condition-enter",
                },
            ) as events,
            pytest.raises(ValueError, match=_CHANGED),
        ):
            _call(case)
        assert changed == [kind] and replacement_calls == []
        assert events.calls["proof"] == events.calls["issuer"] == 0
        assert case.owner._slot is case.owner._active_nonce is None
    finally:
        case.owner._condition, case.owner._original, case.owner._thread = (
            condition,
            original,
            worker,
        )


def test_pure_capability_uses_native_snapshot_when_caller_changes_at_validation_entry():
    original = _capability()
    code = bootstrap._native_capability_values.__code__
    previous, observed = sys.getprofile(), []

    def mutate(frame, event, returned):
        if event == "call" and frame.f_code is code and not observed:
            values = frame.f_locals["value"]
            assert type(values) is tuple and values[3] == "X-CSRF-Token"
            observed.append(True)
            object.__setattr__(original, "csrf_header", "changed-after-snapshot")

    try:
        sys.setprofile(mutate)
        values = bootstrap._capability_values(original)
        copied = bootstrap._capability_from_values(values)
    finally:
        sys.setprofile(previous)
    assert sys.getprofile() is previous and observed == [True]
    assert original.csrf_header == "changed-after-snapshot"
    assert values[3] == copied.csrf_header == "X-CSRF-Token"
    assert copied is not original


def test_pure_capability_copy_revalidates_original_constructor_output():
    values = bootstrap._capability_values(_capability())
    code = BacktestLaunchCapability.__init__.__code__
    previous, observed = sys.getprofile(), []

    def corrupt(frame, event, returned):
        if event == "return" and frame.f_code is code:
            value = frame.f_locals.get("self")
            if type(value) is BacktestLaunchCapability:
                observed.append(True)
                object.__setattr__(value, "idempotency_header", "changed-constructor-output")

    try:
        sys.setprofile(corrupt)
        with pytest.raises(ValueError, match=_INVALID):
            bootstrap._capability_from_values(values)
    finally:
        sys.setprofile(previous)
    assert sys.getprofile() is previous and observed == [True]


def test_original_shared_version_policy_drift_is_not_silently_issued(case, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(bootstrap.backtest_views, "_SESSION_VERSION", 2)
        with _observed() as events, pytest.raises(ValueError, match=_CHANGED):
            _call(case)
        assert all(count == 0 for count in events.calls.values())


def test_transport_only_response_constructor_time_counts_in_original_outer_cutoff(
    case, monkeypatch
):
    clock, joined, constructed = [None], [], []
    original_monotonic = host.time.monotonic_ns
    monkeypatch.setattr(
        host.time,
        "monotonic_ns",
        lambda: original_monotonic() if clock[0] is None else clock[0],
    )

    def consume_constructor_interval(label, returned, frame):
        if label == "join-clock":
            joined.append(returned)
            clock[0] = returned
        elif label == "response" and type(frame.f_locals.get("self")) is Response:
            constructed.append(True)
            assert len(joined) == 1
            clock[0] = joined[0] + case.owner._limits[1]

    with (
        _transport(case, monkeypatch),
        _observed(
            on_return=consume_constructor_interval,
            extra_codes={
                bootstrap._monotonic.__code__: "join-clock",
                Response.__init__.__code__: "response",
            },
        ) as events,
        pytest.raises(HTTPException) as caught,
    ):
        _call(case)
    _unavailable(caught.value)
    assert constructed == [True] and len(joined) == 1
    assert events.calls["proof"] == events.calls["issuer"] == events.calls["authenticate"] == 0


@pytest.mark.parametrize("fault", ["body", "header", "copied_capability"])
def test_transport_only_final_clock_callback_cannot_mutate_staged_delivery(
    case, monkeypatch, fault
):
    retained, authenticated, observed = {}, [], []

    def after_original(label, returned, frame):
        if label == "issuer":
            response = frame.f_locals["response"]
            if type(response) is not Response:
                raise AssertionError("unexpected original staging response")
            retained["response"] = response
        elif label == "copied-capability":
            if type(returned) is not BacktestLaunchCapability:
                raise AssertionError("unexpected original capability copy")
            retained["capability"] = returned
        elif label == "authenticate":
            authenticated.append(True)
        elif label == "owner-clock" and authenticated and not observed:
            if "response" not in retained or "capability" not in retained:
                raise AssertionError("staging observation is incomplete")
            observed.append(fault)
            if fault == "body":
                retained["response"].body = b"changed-after-authentication"
            elif fault == "header":
                retained["response"].raw_headers.append((b"x-unselected", b"after-authentication"))
            else:
                object.__setattr__(
                    retained["capability"], "csrf_header", "changed-after-authentication"
                )

    with (
        _transport(case, monkeypatch),
        _observed(
            on_return=after_original,
            extra_codes={bootstrap._capability_from_values.__code__: "copied-capability"},
        ) as events,
        pytest.raises(ValueError, match=_INVALID),
    ):
        _call(case)
    assert observed == [fault] and authenticated == [True]
    assert events.calls["proof"] == events.calls["issuer"] == events.calls["authenticate"] == 1
    assert not case.owner._attempted and case.owner._primary_error is None
