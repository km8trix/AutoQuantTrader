"""Shared-auth and data boundaries, never a fabricated financial preparation.

Public calls use a real unstarted/stopped H host and original shared sessions.
Call-entry error injection and literal prepared-result projection below qualify
wrapper transport/data only. Genuine G/E effects belong to native integration.
"""

import copy
import sys
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from http.cookies import SimpleCookie
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response

from apps.api import authenticated_initial_selection_preparation as access
from apps.api.backtest_views import LocalOperatorSecurity
from apps.api.continuous_read_access import (
    CONTINUOUS_READ_SESSION_COOKIE,
    ContinuousReadAccessConfiguration,
    ContinuousReadAccessSecurity,
)
from apps.api.metadata_access import METADATA_SESSION_COOKIE, MetadataAccessSecurity
from apps.trader import initial_selection_descriptor as descriptors
from apps.trader.initial_selection_preparation_owner import (
    InitialSelectionPreparationOwner,
    InitialSelectionPreparationResult,
)
from tests.unit.test_personal_initial_selection_request_retention import (
    _descriptor,
    _session,
)

_INVALID = r"^INITIAL_SELECTION_PREPARATION_ACCESS_INVALID$"
_CHANGED = r"^INITIAL_SELECTION_PREPARATION_ACCESS_BINDING_CHANGED$"
_D_INVALID = r"^INITIAL_SELECTION_DESCRIPTOR_INVALID$"
_H_STATE = r"^INITIAL_SELECTION_PREPARATION_OWNER_STATE_INVALID$"


def _security(*, operator="preparation-access-operator", enabled=True):
    return LocalOperatorSecurity(
        enabled=enabled,
        transport_is_loopback_scoped=True,
        operator_id=operator,
        configured_secret="unit-synthetic-preparation-configuration",
    )


@pytest.fixture
def case(tmp_path):
    security = _security()
    cookie, csrf = _session(security)
    configuration = tmp_path / "unopened-preparation.json"
    lock = tmp_path / "unopened-preparation.lock"
    owner = InitialSelectionPreparationOwner(
        configuration_path=str(configuration),
        account_id="preparation-access-account",
        instance_lock=str(lock),
    )
    value = SimpleNamespace(
        security=security,
        cookie=cookie,
        csrf=csrf,
        owner=owner,
        configuration=configuration,
        lock=lock,
    )
    yield value
    _no_effects(value)


def _call(case, **changes):
    arguments = dict(
        security=case.security,
        owner=case.owner,
        account_id="preparation-access-account",
        call_id="preparation-access-call",
        session_cookie=case.cookie,
        csrf_token=case.csrf,
    )
    arguments.update(changes)
    return access._prepare_authenticated_initial_selection(**arguments)


def _no_effects(case):
    assert case.owner._thread is None and case.owner._attempted is False
    assert case.owner._preparation_return_admitted is False
    assert not case.configuration.exists() and not case.lock.exists()


@contextmanager
def _observed(*, host_return=None, authenticated_return=None, host_error=None):
    """Original-code observation with no cookie/CSRF/frame retention."""
    events = SimpleNamespace(host_calls=0, host_results=[], sessions=[], auth_calls=0)
    previous = sys.getprofile()
    host_code = InitialSelectionPreparationOwner.prepare_initial_selection.__code__
    auth_code = LocalOperatorSecurity.authenticate_with_expiry.__code__

    def observe(frame, event, returned):
        try:
            if frame.f_code is host_code:
                if event == "call":
                    events.host_calls += 1
                    if host_error is not None:
                        raise host_error
                elif event == "return":
                    events.host_results.append(returned)
                    if host_return is not None:
                        host_return(returned)
            elif frame.f_code is auth_code:
                if event == "call":
                    events.auth_calls += 1
                elif event == "return" and type(returned) is tuple:
                    events.sessions.append(returned)
                    if authenticated_return is not None:
                        authenticated_return(returned)
            if previous is not None:
                previous(frame, event, returned)
        finally:
            del frame

    sys.setprofile(observe)
    try:
        yield events
    finally:
        sys.setprofile(previous)


@pytest.mark.parametrize(
    ("name", "bad"),
    [
        ("account_id", True),
        ("account_id", "非ASCII"),
        ("call_id", "two words"),
        ("call_id", "x" * 129),
        ("session_cookie", True),
        ("session_cookie", "x" * 2049),
        ("csrf_token", None),
        ("csrf_token", b"csrf"),
        ("csrf_token", "x" * 129),
        ("cancel_event", False),
        ("cancel_event", object()),
    ],
)
def test_native_arguments_deny_before_shared_auth_or_host(case, name, bad):
    with _observed() as events, pytest.raises(ValueError, match=_INVALID):
        _call(case, **{name: bad})
    assert events.auth_calls == events.host_calls == 0
    _no_effects(case)


def test_explicit_account_must_match_original_configured_host(case):
    with _observed() as events, pytest.raises(ValueError, match=_INVALID):
        _call(case, account_id="another-valid-account")
    assert events.auth_calls == events.host_calls == 0


@pytest.mark.parametrize("target", ["security", "owner"])
def test_foreign_objects_are_rejected_before_borrowing_getters(case, target):
    callbacks = []

    class Foreign:
        def __getattribute__(self, name):
            callbacks.append(name)
            raise AssertionError("foreign getter was borrowed")

    with _observed() as events, pytest.raises(ValueError, match=_INVALID):
        _call(case, **{target: Foreign()})
    assert callbacks == [] and events.auth_calls == events.host_calls == 0


def test_copied_host_never_supplies_original_self_ownership(case):
    duplicate = copy.copy(case.owner)
    assert type(duplicate) is InitialSelectionPreparationOwner
    assert duplicate._instance is case.owner
    with _observed() as events, pytest.raises(ValueError, match=_H_STATE):
        _call(case, owner=duplicate)
    assert events.auth_calls == events.host_calls == 0


@pytest.mark.parametrize("kind", ["missing", "changed", "expired", "restart", "csrf", "disabled"])
def test_real_original_shared_authentication_denies_before_host(case, kind):
    cookie, csrf = case.cookie, case.csrf
    if kind == "missing":
        cookie = None
    elif kind == "changed":
        cookie += "x"
    elif kind == "expired":
        cookie, csrf = _session(case.security, at=datetime.now(UTC) - timedelta(hours=8, seconds=1))
    elif kind == "restart":
        case.security = _security()
    elif kind == "csrf":
        csrf = "wrong-current-csrf"
    else:
        case.security = _security(enabled=False)
    with _observed() as events, pytest.raises(HTTPException) as caught:
        _call(case, session_cookie=cookie, csrf_token=csrf)
    assert caught.value.status_code == (403 if kind in ("csrf", "disabled") else 401)
    assert events.auth_calls == 1 and events.host_calls == 0
    _no_effects(case)


@pytest.mark.parametrize("purpose", ["metadata", "operational"])
def test_actual_read_only_sessions_do_not_authorize_preparation(case, purpose):
    at, response = datetime.now(UTC), Response()
    if purpose == "metadata":
        security = MetadataAccessSecurity(
            enabled=True,
            transport_is_loopback_scoped=True,
            operator_id="preparation-access-operator",
            configured_secret="test-only-metadata",
        )
        name = METADATA_SESSION_COOKIE
    else:
        security = ContinuousReadAccessSecurity(
            configuration=ContinuousReadAccessConfiguration(
                enabled=True,
                transport_is_loopback_scoped=True,
                operator_id="preparation-access-operator",
                configured_secret="test-only-read",
            ),
            account_id="preparation-access-account",
        )
        security.open()
        name = CONTINUOUS_READ_SESSION_COOKIE
    capability = security.bootstrap_capability(response, issued_at=at, session_cookie=None)
    jar = SimpleCookie()
    jar.load(response.headers["set-cookie"])
    try:
        assert (
            security.authenticate(jar[name].value, capability.csrf_token, now=at)
            == "preparation-access-operator"
        )
        with _observed() as events, pytest.raises(HTTPException) as caught:
            _call(case, session_cookie=jar[name].value, csrf_token=capability.csrf_token)
        assert caught.value.status_code == 401 and events.host_calls == 0
        assert events.auth_calls == 1
    finally:
        if purpose == "operational":
            security.close()


@pytest.mark.parametrize("operator", ["ordinary-reader", "研究利用者", "operator with spaces"])
def test_original_unicode_shared_operator_is_not_narrowed_to_host_ascii_ids(case, operator):
    case.security = _security(operator=operator)
    case.cookie, case.csrf = _session(case.security)
    with _observed() as events:
        result = _call(case)
    assert type(result) is InitialSelectionPreparationResult
    assert (
        result.status,
        result.reason,
        result.call_id,
        result.incarnation,
        result.descriptor,
    ) == (
        "unavailable",
        "not_started",
        "preparation-access-call",
        case.owner._incarnation,
        None,
    )
    assert events.host_calls == 1 and events.auth_calls == 2
    assert len(events.sessions) == 2 and events.sessions[0] == events.sessions[1]
    assert events.sessions[0][0] == operator
    assert len(events.host_results) == 1 and result is not events.host_results[0]
    _no_effects(case)


@pytest.mark.parametrize("stopped", [False, True])
def test_original_unavailable_reason_survives_final_cancel_sample(case, stopped):
    if stopped:
        assert case.owner.stop().phase == "stopped"
    cancelled = threading.Event()
    cancelled.set()
    with _observed() as events:
        result = _call(case, cancel_event=cancelled)
    assert result.status == "unavailable" and result.descriptor is None
    assert result.reason == ("stopped" if stopped else "not_started")
    assert events.host_calls == 1 and events.auth_calls == 2
    _no_effects(case)


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt])
def test_original_host_call_entry_error_is_identical_and_not_masked_by_delivery_auth(
    case, error_type
):
    # Boundary-only injected call-entry failure, not an actual financial attempt.
    primary = error_type("test-only original dispatch boundary failed")
    with _observed(host_error=primary) as events, pytest.raises(error_type) as caught:
        _call(case)
    assert caught.value is primary
    assert events.host_calls == events.auth_calls == 1 and len(events.sessions) == 1
    _no_effects(case)


@pytest.mark.parametrize("drift", ["disabled", "process-key"])
def test_actual_delivery_auth_failure_preserves_original_unavailable_host_facts(case, drift):
    def after_host(returned):
        assert returned.reason == "not_started"
        if drift == "disabled":
            case.security._enabled = False
        else:
            case.security._key = b"synthetic-test-only-key-change!!!"

    with _observed(host_return=after_host) as events, pytest.raises(HTTPException) as caught:
        _call(case)
    assert caught.value.status_code == (403 if drift == "disabled" else 401)
    assert events.host_calls == 1 and events.auth_calls == 2 and len(events.sessions) == 1
    _no_effects(case)


def test_actual_short_session_expiry_at_unstarted_host_return_denies_delivery(case):
    # Real elapsed UTC on a no-resource host; this does not claim a put or lease.
    case.cookie, case.csrf = _session(
        case.security,
        at=datetime.now(UTC) - timedelta(hours=8) + timedelta(seconds=3),
    )
    expiry = None

    def authenticated(value):
        nonlocal expiry
        expiry = value[1]

    def after_host(returned):
        assert returned.reason == "not_started" and expiry is not None
        remaining = max(0, (expiry - datetime.now(UTC)).total_seconds())
        threading.Event().wait(remaining)
        assert datetime.now(UTC) >= expiry

    with (
        _observed(host_return=after_host, authenticated_return=authenticated) as events,
        pytest.raises(HTTPException) as caught,
    ):
        _call(case)
    assert caught.value.status_code == 401
    assert events.host_calls == 1 and events.auth_calls == 2 and len(events.sessions) == 1
    _no_effects(case)


@pytest.mark.parametrize(
    "name",
    [
        "_PREPARE",
        "_ENTRY",
        "_AUTHENTICATE",
        "_D_VALUES",
        "_D_VALIDATE",
        "_D_COPY",
        "_RESULT",
        "_BINDINGS",
        "_bindings",
        "_PROJECT_RESULT",
        "_REQUIRE_GRAPH",
    ],
)
@pytest.mark.parametrize("timing", ["before", "host-return"])
def test_selected_direct_alias_drift_is_denied_before_substitute_call(
    case, monkeypatch, name, timing
):
    substituted = []

    def forbidden(*args, **kwargs):
        substituted.append(name)
        raise AssertionError("changed selected dispatch was invoked")

    with monkeypatch.context() as patch:
        if timing == "before":
            patch.setattr(access, name, forbidden)

        def after_host(returned):
            if timing == "host-return":
                patch.setattr(access, name, forbidden)

        with _observed(host_return=after_host) as events, pytest.raises(ValueError, match=_CHANGED):
            _call(case)
    assert substituted == []
    assert events.host_calls == events.auth_calls == int(timing == "host-return")
    _no_effects(case)


@pytest.mark.parametrize(
    ("owner_type", "name"),
    [
        (LocalOperatorSecurity, "authenticate_with_expiry"),
        (LocalOperatorSecurity, "_decode"),
        (InitialSelectionPreparationOwner, "prepare_initial_selection"),
        (InitialSelectionPreparationResult, "__init__"),
        (InitialSelectionPreparationResult, "__post_init__"),
        (descriptors.InitialSelectionDescriptor, "__init__"),
        (descriptors.InitialSelectionDescriptor, "__post_init__"),
        (threading.Event, "is_set"),
    ],
)
def test_selected_original_class_method_change_denies_without_invocation(
    case, monkeypatch, owner_type, name
):
    substituted = []

    def forbidden(*args, **kwargs):
        substituted.append(name)
        raise AssertionError("substituted class method was invoked")

    with monkeypatch.context() as patch:
        patch.setattr(owner_type, name, forbidden)
        with pytest.raises(ValueError, match=_CHANGED):
            _call(case)
    assert substituted == []
    _no_effects(case)


def test_original_host_instance_shadow_denies_without_invocation(case, monkeypatch):
    substituted = []

    def forbidden(*args, **kwargs):
        substituted.append("prepare_initial_selection")
        raise AssertionError("instance shadow was invoked")

    with monkeypatch.context() as patch:
        patch.setitem(vars(case.owner), "prepare_initial_selection", forbidden)
        with pytest.raises(
            RuntimeError, match=r"^INITIAL_SELECTION_PREPARATION_OWNER_BINDING_CHANGED$"
        ):
            _call(case)
    assert substituted == []
    assert "prepare_initial_selection" not in vars(case.owner)
    _no_effects(case)


@pytest.mark.parametrize("name", ["authenticate_with_expiry", "_decode"])
def test_original_slotted_shared_security_cannot_have_instance_method_shadows(case, name):
    substituted = []

    def forbidden(*args, **kwargs):
        substituted.append(name)
        raise AssertionError("slotted security acquired a method shadow")

    with pytest.raises(AttributeError):
        setattr(case.security, name, forbidden)
    with _observed() as events:
        result = _call(case)
    assert result.reason == "not_started"
    assert substituted == [] and events.auth_calls == 2 and events.host_calls == 1
    _no_effects(case)


def test_native_event_instance_shadow_is_rejected_without_invocation(case, monkeypatch):
    cancelled = threading.Event()
    substituted = []

    def forbidden():
        substituted.append(True)
        raise AssertionError("Event.is_set shadow was invoked")

    with monkeypatch.context() as patch:
        patch.setitem(vars(cancelled), "is_set", forbidden)
        with _observed() as events, pytest.raises(ValueError, match=_CHANGED):
            _call(case, cancel_event=cancelled)
    assert substituted == [] and events.auth_calls == events.host_calls == 0
    assert "is_set" not in vars(cancelled)


def test_non_native_event_flag_is_denied_before_truthiness_after_normal_host_return(case):
    callbacks = []

    class ForeignFlag:
        def __bool__(self):
            callbacks.append(True)
            raise AssertionError("foreign flag truthiness was invoked")

    cancelled = threading.Event()
    cancelled._flag = ForeignFlag()
    with _observed() as events, pytest.raises(ValueError, match=_INVALID):
        _call(case, cancel_event=cancelled)
    assert callbacks == [] and events.host_calls == 1 and events.auth_calls == 2
    _no_effects(case)


@pytest.mark.parametrize("kind", ["tuple-only", "account", "incarnation"])
@pytest.mark.parametrize("timing", ["auth-return", "host-return"])
def test_matching_rebound_host_fields_cannot_replace_independent_admitted_baseline(
    case, kind, timing
):
    original = case.owner._original
    changed = []

    def mutate(value):
        if changed:
            return
        values = list(original)
        if kind == "account":
            values[1] = "retargeted-valid-account"
            case.owner._account_id = values[1]
        elif kind == "incarnation":
            values[6] = "retargeted-valid-incarnation"
            case.owner._incarnation = values[6]
        case.owner._original = tuple(values)
        changed.append(True)

    try:
        with (
            _observed(
                authenticated_return=mutate if timing == "auth-return" else None,
                host_return=mutate if timing == "host-return" else None,
            ) as events,
            pytest.raises(ValueError, match=_CHANGED),
        ):
            _call(case)
    finally:
        # Pure unstarted transport fields only; no work or resource is repaired.
        case.owner._account_id, case.owner._incarnation = original[1], original[6]
        case.owner._original = original
    assert changed == [True]
    assert events.auth_calls == 1
    assert events.host_calls == int(timing == "host-return")
    _no_effects(case)


def _literal_result(case, *, prepared=True):
    descriptor = _descriptor(datetime.now(UTC)) if prepared else None
    if descriptor is not None:
        object.__setattr__(descriptor, "account_id", "preparation-access-account")
    return InitialSelectionPreparationResult(
        "prepared" if prepared else "unavailable",
        "prepared" if prepared else "busy",
        "preparation-access-call",
        case.owner._incarnation,
        descriptor,
    )


def _project(case, value):
    return access._project_result(
        value,
        account_id="preparation-access-account",
        call_id="preparation-access-call",
        incarnation=case.owner._incarnation,
    )


@pytest.mark.parametrize("prepared", [False, True])
def test_unowned_literal_projection_returns_fresh_data_only(case, prepared):
    original = _literal_result(case, prepared=prepared)
    result = _project(case, original)
    assert type(result) is InitialSelectionPreparationResult and result == original
    assert result is not original
    if prepared:
        assert result.descriptor is not original.descriptor
        object.__setattr__(result.descriptor, "after_assignment_sha256", "f" * 64)
        assert original.descriptor.after_assignment_sha256 == "1" * 64
    else:
        assert result.descriptor is None
    _no_effects(case)


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("status", True),
        ("reason", b"prepared"),
        ("call_id", "other-call"),
        ("incarnation", "other-incarnation"),
        ("status", "unavailable"),
        ("reason", "busy"),
    ],
)
def test_literal_result_native_correlation_and_combination_denials(case, field, bad):
    original = _literal_result(case)
    object.__setattr__(original, field, bad)
    with pytest.raises(ValueError, match=_INVALID):
        _project(case, original)
    _no_effects(case)


def test_foreign_result_is_denied_before_any_field_getter(case):
    callbacks = []

    class Foreign:
        def __getattribute__(self, name):
            callbacks.append(name)
            raise AssertionError("foreign result getter was borrowed")

    with pytest.raises(ValueError, match=_INVALID):
        _project(case, Foreign())
    assert callbacks == []


@pytest.mark.parametrize("kind", ["wrong-account", "late-counter", "absent"])
def test_literal_descriptor_admission_retains_original_d_error_and_account_binding(case, kind):
    original = _literal_result(case)
    if kind == "absent":
        object.__setattr__(original, "descriptor", None)
    else:
        field, bad = (
            ("account_id", "foreign-valid-account")
            if kind == "wrong-account"
            else ("dependency_byte_count", True)
        )
        object.__setattr__(original.descriptor, field, bad)
    with pytest.raises(ValueError, match=_INVALID if kind == "wrong-account" else _D_INVALID):
        _project(case, original)


def test_projection_consumes_snapshot_after_original_caller_result_and_d_change(case):
    # Unowned data model only. Observe the actual original copier entry after
    # capture, then mutate the caller objects; no host/financial result is forged.
    original = _literal_result(case)
    descriptor = original.descriptor
    expected_values = descriptors._descriptor_values(descriptor)
    copied = []
    previous = sys.getprofile()
    copy_code = descriptors._from_values.__code__

    def observe(frame, event, returned):
        try:
            if event == "call" and frame.f_code is copy_code and not copied:
                copied.append(frame.f_locals["values"])
                object.__setattr__(original, "status", "unavailable")
                object.__setattr__(original, "reason", "cancelled")
                object.__setattr__(original, "call_id", "mutated-call")
                object.__setattr__(original, "incarnation", "mutated-incarnation")
                object.__setattr__(original, "descriptor", None)
                object.__setattr__(descriptor, "account_id", "mutated-account")
                object.__setattr__(descriptor, "after_assignment_sha256", "e" * 64)
                object.__setattr__(descriptor, "dependency_byte_count", True)
            if previous is not None:
                previous(frame, event, returned)
        finally:
            del frame

    sys.setprofile(observe)
    try:
        result = _project(case, original)
    finally:
        sys.setprofile(previous)
    assert copied == [expected_values]
    assert (result.status, result.reason, result.call_id, result.incarnation) == (
        "prepared",
        "prepared",
        "preparation-access-call",
        case.owner._incarnation,
    )
    assert descriptors._descriptor_values(result.descriptor) == expected_values
    assert result.descriptor is not descriptor and original.descriptor is None
    _no_effects(case)


def test_original_fresh_h_validator_error_is_not_remapped_by_pure_projection(case):
    # The literal result is unowned data. This tests only propagation from the
    # original validator on a newly constructed copy, with no host dispatch.
    original = _literal_result(case)
    primary = ValueError("test-only fresh original H validator failure")
    previous = sys.getprofile()
    validate_code = InitialSelectionPreparationResult.__post_init__.__code__
    validators = []

    def observe(frame, event, returned):
        try:
            if event == "call" and frame.f_code is validate_code:
                validators.append(frame.f_locals["self"] is original)
                raise primary
            if previous is not None:
                previous(frame, event, returned)
        finally:
            del frame

    sys.setprofile(observe)
    try:
        with pytest.raises(ValueError) as caught:
            _project(case, original)
    finally:
        sys.setprofile(previous)
    assert caught.value is primary and validators == [False]
    _no_effects(case)


@pytest.mark.parametrize("operator", ["研究利用者", "operator with spaces", "a" * 128])
def test_pure_operator_guard_preserves_original_shared_text_grammar(operator):
    # Compare with the genuine existing configuration boundary, not H's ASCII ID.
    assert _security(operator=operator)._operator_id == operator
    assert access._operator(operator) == operator


@pytest.mark.parametrize("bad", [True, b"reader", "", " padded ", "a" * 129, "bad\x01reader"])
def test_pure_operator_guard_rejects_native_or_original_shared_grammar_faults(bad):
    with pytest.raises(ValueError, match=_INVALID):
        access._operator(bad)


def test_pure_utc_guard_accepts_the_original_native_utc_value():
    at = datetime(2026, 10, 28, 12, tzinfo=UTC)
    assert access._utc(at) is at


@pytest.mark.parametrize("kind", ["foreign", "naive", "nonzero", "callback-zone"])
def test_pure_utc_guard_does_not_borrow_foreign_timezone_callbacks(kind):
    callbacks = []

    class Foreign:
        def __getattribute__(self, name):
            callbacks.append(name)
            raise AssertionError("foreign clock getter was borrowed")

    class CallbackZone(tzinfo):
        def utcoffset(self, value):
            callbacks.append("offset")
            raise AssertionError("foreign timezone callback was borrowed")

    value = {
        "foreign": Foreign(),
        "naive": datetime(2026, 10, 28),
        "nonzero": datetime(2026, 10, 28, tzinfo=timezone(timedelta(hours=1))),
        "callback-zone": datetime(2026, 10, 28, tzinfo=CallbackZone()),
    }[kind]
    with pytest.raises(ValueError, match=_INVALID):
        access._utc(value)
    assert callbacks == []
