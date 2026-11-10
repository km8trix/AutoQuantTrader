"""Actual transient session provenance, without a journal or resolution authority."""

import builtins
import copy
import gc
import hashlib
import socket
import sqlite3
import subprocess
import sys
import time
import weakref
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, fields, is_dataclass, replace
from datetime import UTC, datetime, timedelta, tzinfo
from http.cookies import SimpleCookie
from pathlib import Path
from types import SimpleNamespace
from weakref import WeakValueDictionary

import pytest
from fastapi import HTTPException, Response

from apps.api import operational_control_operator_authentication as authentication
from apps.api.backtest_views import LOCAL_SESSION_COOKIE, LocalOperatorSecurity
from apps.api.continuous_read_access import (
    CONTINUOUS_READ_SESSION_COOKIE,
    ContinuousReadAccessConfiguration,
    ContinuousReadAccessSecurity,
)
from apps.api.metadata_access import METADATA_SESSION_COOKIE, MetadataAccessSecurity
from packages.application.operational_control_operator_authentication import (
    AuthenticatedOperationalControlOperatorStatement,
)
from packages.domain import operational_control_operator_statement as data
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlBlockingEvent,
    OperationalControlIncidentDisposition,
    OperationalControlState,
)

_NOW = datetime(2026, 10, 28, 14, 0, tzinfo=UTC)
_ACCOUNT = "statement-authentication-account"
_OWNER = "statement-authentication-operator"
_AUTHORITY = "a" * 64
_SECRET = "synthetic-test-only-statement-authentication"
_AUTH_CODE = LocalOperatorSecurity.authenticate_with_expiry.__code__
_ISSUER = authentication.LocalOperationalControlOperatorStatementAuthenticator


def _security():
    return LocalOperatorSecurity(
        enabled=True,
        transport_is_loopback_scoped=True,
        operator_id=_OWNER,
        configured_secret=_SECRET,
    )


def _session(security, *, issued_at=_NOW):
    response = Response()
    capability = security.bootstrap_capability(
        response, persistence_ready=True, issued_at=issued_at, session_cookie=None
    )
    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    return cookies[LOCAL_SESSION_COOKIE].value, capability.csrf_token


def _statement(*, at=_NOW, owner=_OWNER, scope=_ACCOUNT, authority=_AUTHORITY):
    event = OperationalControlBlockingEvent(
        scope_id=scope,
        sequence_number=1,
        command_id="initial-halted-command",
        command_sha256="b" * 64,
        state=OperationalControlState.HALTED,
        occurred_at=at - timedelta(seconds=2),
    )
    return data.OperationalControlOperatorStatement(
        scope_id=scope,
        control_transition_id="declared-control-head",
        control_transition_sha256="c" * 64,
        control_sequence_number=1,
        control_state=OperationalControlState.HALTED,
        control_state_epoch_id="declared-control-epoch",
        blocking_event=event,
        actor=OperationalControlActor(
            actor_id=owner,
            kind=OperationalControlActorKind.HUMAN,
            authority_sha256=authority,
            authenticated_at=at,
        ),
        resolution_claim=OperationalControlIncidentDisposition(
            event_id=event.event_id,
            event_sha256=event.semantic_sha256,
            resolution_code="operator-reviewed",
            resolution_evidence_sha256="d" * 64,
            resolved_at=at - timedelta(seconds=1),
        ),
        authentication_checked_at=at,
        attested_at=at,
        idempotency_key="statement-authentication-0001",
    )


def _case(*, issued_at=_NOW):
    security = _security()
    cookie, csrf = _session(security, issued_at=issued_at)
    issuer = _ISSUER(security, scope_id=_ACCOUNT, actor_authority_sha256=_AUTHORITY)
    return SimpleNamespace(
        security=security, cookie=cookie, csrf=csrf, issuer=issuer, statement=_statement()
    )


def _issue(case, *, statement=None, cookie=None, csrf=None, at=_NOW):
    return case.issuer.authenticate(
        case.statement if statement is None else statement,
        session_cookie=case.cookie if cookie is None else cookie,
        csrf_token=case.csrf if csrf is None else csrf,
        now=at,
    )


def _require(case, token, *, cookie=None, csrf=None, at=_NOW):
    return case.issuer.require_authenticated(
        token,
        session_cookie=case.cookie if cookie is None else cookie,
        csrf_token=case.csrf if csrf is None else csrf,
        now=at,
    )


@contextmanager
def _observe_auth(action=None):
    """Observe original function entry; never substitute a passing authenticator."""
    monitor, tool = sys.monitoring, 3
    entries = []
    owned = registered = enabled = False

    def start(code, offset):
        if code is _AUTH_CODE:
            entries.append("original shared authentication")
            if action is not None:
                action()

    try:
        assert monitor.get_tool(tool) is None
        assert monitor.get_events(tool) == 0
        monitor.use_tool_id(tool, "aqt-statement-authentication-unit")
        owned = True
        assert monitor.register_callback(tool, monitor.events.PY_START, start) is None
        registered = True
        assert monitor.get_local_events(tool, _AUTH_CODE) == 0
        monitor.set_local_events(tool, _AUTH_CODE, monitor.events.PY_START)
        enabled = True
        yield entries
    finally:
        try:
            if enabled:
                monitor.set_local_events(tool, _AUTH_CODE, 0)
                assert monitor.get_local_events(tool, _AUTH_CODE) == 0
        finally:
            try:
                if registered:
                    monitor.register_callback(tool, monitor.events.PY_START, None)
            finally:
                if owned:
                    assert monitor.get_events(tool) == 0
                    monitor.free_tool_id(tool)
                    assert monitor.get_tool(tool) is None


def _retained_leaves(value, *, excluded, seen=None):
    """Inspect data containers without traversing the retained original security."""
    seen = set() if seen is None else seen
    if value is excluded or id(value) in seen:
        return []
    seen.add(id(value))
    if type(value) in (str, bytes):
        return [value]
    if isinstance(value, WeakValueDictionary):
        children = tuple(value.values())
    elif type(value) is dict:
        children = (*value.keys(), *value.values())
    elif type(value) in (tuple, list):
        children = value
    elif is_dataclass(value) and not isinstance(value, type):
        children = tuple(getattr(value, field.name) for field in fields(value))
    elif type(value) is _ISSUER:
        children = tuple(getattr(value, name) for name in _ISSUER.__slots__)
    else:
        return []
    leaves = []
    for child in children:
        leaves.extend(_retained_leaves(child, excluded=excluded, seen=seen))
    return leaves


def test_actual_shared_session_issues_detached_operation_metadata_and_checks_current_use():
    login_at = _NOW - timedelta(hours=2)
    case = _case(issued_at=login_at)
    with _observe_auth() as entries:
        token = _issue(case)
        assert _require(case, token) is None
        assert _require(case, token, at=_NOW + timedelta(seconds=61)) is None
    assert len(entries) == 3
    assert type(token) is AuthenticatedOperationalControlOperatorStatement
    assert not hasattr(token, "__dict__")
    assert token.statement is not case.statement
    for name in ("blocking_event", "actor", "resolution_claim"):
        assert getattr(token.statement, name) is not getattr(case.statement, name)
    assert token.statement.canonical_json == case.statement.canonical_json
    assert token.statement.actor.authenticated_at == _NOW
    assert token.statement.authentication_checked_at == _NOW
    assert token.statement.attested_at == _NOW
    assert token.statement.resolution_claim.resolved_at < _NOW
    assert token.session_expires_at == login_at + timedelta(hours=8)
    assert token.statement.control_state is OperationalControlState.HALTED
    with pytest.raises(FrozenInstanceError):
        token.session_expires_at = _NOW
    retained = _retained_leaves(case.issuer, excluded=case.security)
    retained.extend(_retained_leaves(token, excluded=case.security))
    transient = (case.cookie, case.csrf, _SECRET, case.security._key)
    forbidden = []
    for secret in transient:
        encoded = secret.encode() if type(secret) is str else secret
        forbidden.extend((secret, encoded, hashlib.sha256(encoded).hexdigest()))
    # Boolean-only comparisons keep generated credentials out of failed assertion output.
    assert not any(leaf == secret for leaf in retained for secret in forbidden)


@pytest.mark.parametrize("phase", ["issue", "current"])
@pytest.mark.parametrize("kind", ["missing", "changed-cookie", "csrf", "disabled", "restart"])
def test_actual_shared_session_rejections_preserve_original_http_errors(phase, kind):
    case = _case()
    token = _issue(case) if phase == "current" else None
    cookie, csrf = case.cookie, case.csrf
    if kind == "missing":
        cookie = None
    elif kind == "changed-cookie":
        cookie += "x"
    elif kind == "csrf":
        csrf = "wrong-test-csrf"
    elif kind == "disabled":
        case.security._enabled = False
    elif kind == "restart":
        # The same configuration has a new process nonce; the old cookie fails.
        restarted = _security()
        if phase == "issue":
            case.issuer = _ISSUER(restarted, scope_id=_ACCOUNT, actor_authority_sha256=_AUTHORITY)
        else:
            case.security._key = restarted._key
    with _observe_auth() as entries, pytest.raises(HTTPException) as caught:
        if phase == "issue":
            case.issuer.authenticate(
                case.statement, session_cookie=cookie, csrf_token=csrf, now=_NOW
            )
        else:
            case.issuer.require_authenticated(
                token, session_cookie=cookie, csrf_token=csrf, now=_NOW
            )
    assert len(entries) == 1
    assert caught.value.status_code == (403 if kind in ("csrf", "disabled") else 401)


@pytest.mark.parametrize("phase", ["issue", "current"])
@pytest.mark.parametrize("purpose", ["metadata", "operational-read"])
def test_actual_read_only_sessions_never_authenticate_a_statement(phase, purpose):
    case = _case()
    token = _issue(case) if phase == "current" else None
    response = Response()
    if purpose == "metadata":
        security = MetadataAccessSecurity(
            enabled=True,
            transport_is_loopback_scoped=True,
            operator_id=_OWNER,
            configured_secret=_SECRET,
        )
        cookie_name = METADATA_SESSION_COOKIE
    else:
        security = ContinuousReadAccessSecurity(
            configuration=ContinuousReadAccessConfiguration(
                enabled=True,
                transport_is_loopback_scoped=True,
                operator_id=_OWNER,
                configured_secret=_SECRET,
            ),
            account_id=_ACCOUNT,
        )
        security.open()
        cookie_name = CONTINUOUS_READ_SESSION_COOKIE
    try:
        capability = security.bootstrap_capability(response, issued_at=_NOW, session_cookie=None)
        cookies = SimpleCookie()
        cookies.load(response.headers["set-cookie"])
        cookie, csrf = cookies[cookie_name].value, capability.csrf_token
        assert security.authenticate(cookie, csrf, now=_NOW) == _OWNER
        with _observe_auth() as entries, pytest.raises(HTTPException) as caught:
            if phase == "issue":
                case.issuer.authenticate(
                    case.statement, session_cookie=cookie, csrf_token=csrf, now=_NOW
                )
            else:
                case.issuer.require_authenticated(
                    token, session_cookie=cookie, csrf_token=csrf, now=_NOW
                )
        assert len(entries) == 1
        assert caught.value.status_code == 401
    finally:
        if type(security) is ContinuousReadAccessSecurity:
            security.close()


def test_original_expiry_and_current_time_ordering_are_not_extended_by_new_sessions():
    case = _case()
    token = _issue(case)
    original_expiry = _NOW + timedelta(hours=8)
    with _observe_auth() as entries:
        assert _require(case, token, at=_NOW) is None
        assert _require(case, token, at=original_expiry - timedelta(microseconds=1)) is None
    assert len(entries) == 2
    for at in (_NOW - timedelta(microseconds=1), original_expiry):
        with _observe_auth() as entries, pytest.raises(ValueError):
            _require(case, token, at=at)
        assert entries == []
    later = _NOW + timedelta(seconds=1)
    cookie, csrf = _session(case.security, issued_at=later)
    with _observe_auth() as entries, pytest.raises(ValueError):
        _require(case, token, cookie=cookie, csrf=csrf, at=later)
    assert len(entries) == 1
    assert token.session_expires_at == original_expiry
    # Original shared claims expose operator/expiry, not a unique session identity.
    cookie, csrf = _session(case.security, issued_at=_NOW)
    with _observe_auth() as entries:
        assert _require(case, token, cookie=cookie, csrf=csrf) is None
    assert len(entries) == 1


def test_actual_session_expiry_equality_rejects_issuance_without_a_token():
    case = _case()
    at = _NOW + timedelta(hours=8)
    with _observe_auth() as entries, pytest.raises(HTTPException) as caught:
        _issue(case, statement=_statement(at=at), at=at)
    assert len(entries) == 1
    assert caught.value.status_code == 401
    assert len(case.issuer._owned) == len(case.issuer._original) == 0


@pytest.mark.parametrize("field", ["actor", "check", "attestation", "scope", "authority", "owner"])
def test_declared_statement_bindings_and_operation_times_do_not_substitute_for_auth(field):
    case = _case()
    statement = case.statement
    if field == "actor":
        statement = replace(
            statement, actor=replace(statement.actor, authenticated_at=_NOW - timedelta(seconds=1))
        )
    elif field == "check":
        statement = replace(
            statement,
            actor=replace(statement.actor, authenticated_at=_NOW - timedelta(seconds=1)),
            authentication_checked_at=_NOW - timedelta(microseconds=1),
        )
    elif field == "attestation":
        statement = replace(statement, attested_at=_NOW + timedelta(microseconds=1))
    elif field == "scope":
        statement = _statement(scope="foreign-account")
    elif field == "authority":
        statement = _statement(authority="f" * 64)
    elif field == "owner":
        statement = _statement(owner="foreign-operator")
    with _observe_auth() as entries, pytest.raises(ValueError):
        _issue(case, statement=statement)
    assert len(entries) == (1 if field == "owner" else 0)
    assert len(case.issuer._owned) == len(case.issuer._original) == 0


@pytest.mark.parametrize(
    "kind",
    [
        "copy",
        "replace",
        "constructed",
        "foreign-issuer",
        "copied-issuer",
        "statement",
        "nested",
        "expiry",
        "seal",
    ],
)
def test_only_original_issuer_token_statement_and_content_reach_current_authentication(kind):
    case = _case()
    token = _issue(case)
    if kind == "copy":
        token = copy.copy(token)
    elif kind == "replace":
        token = replace(token)
    elif kind == "constructed":
        token = AuthenticatedOperationalControlOperatorStatement(
            token.statement, token.session_expires_at, token.seal
        )
    elif kind == "foreign-issuer":
        case.issuer = _ISSUER(case.security, scope_id=_ACCOUNT, actor_authority_sha256=_AUTHORITY)
    elif kind == "copied-issuer":
        case.issuer = copy.copy(case.issuer)
    elif kind == "statement":
        object.__setattr__(
            token, "statement", data.copy_operational_control_operator_statement(token.statement)
        )
    elif kind == "nested":
        object.__setattr__(
            token.statement.resolution_claim, "resolution_code", "changed-valid-claim"
        )
    elif kind == "expiry":
        object.__setattr__(
            token, "session_expires_at", token.session_expires_at + timedelta(seconds=1)
        )
    else:
        object.__setattr__(token, "seal", object())
    with _observe_auth() as entries, pytest.raises(ValueError):
        _require(case, token)
    assert entries == []


def _poison(kind, calls):
    def forbidden(*args, **kwargs):
        calls.append(kind)
        raise AssertionError("authentication dispatched a non-native input hook")

    if kind == "str":

        class PoisonString(str):
            __eq__ = __len__ = __str__ = __repr__ = __hash__ = forbidden
            strip = encode = forbidden

        return PoisonString("native-looking")
    if kind == "bytes":

        class PoisonBytes(bytes):
            __eq__ = __len__ = __bytes__ = __repr__ = __hash__ = forbidden

        return PoisonBytes(b"native-looking")
    if kind == "datetime":

        class PoisonDateTime(datetime):
            __eq__ = __lt__ = __le__ = __gt__ = __ge__ = forbidden
            utcoffset = isoformat = forbidden
            tzinfo = property(forbidden)

        return PoisonDateTime(2026, 10, 28, 14, tzinfo=UTC)
    if kind == "timezone":

        class PoisonTimezone(tzinfo):
            utcoffset = dst = tzname = forbidden

        return datetime(2026, 10, 28, 14, tzinfo=PoisonTimezone())
    raise AssertionError("unknown poison kind")


@pytest.mark.parametrize("phase", ["issue", "current"])
@pytest.mark.parametrize(
    "field,kind",
    [
        ("cookie", "str"),
        ("csrf", "str"),
        ("now", "datetime"),
        ("now", "timezone"),
        ("actor", "str"),
        ("claim", "str"),
        ("expiry", "timezone"),
    ],
)
def test_native_call_and_known_nested_data_deny_before_hooks_or_actual_auth(phase, field, kind):
    case = _case()
    token = _issue(case) if phase == "current" else None
    calls = []
    poison = _poison(kind, calls)
    cookie, csrf, at = case.cookie, case.csrf, _NOW
    if field == "cookie":
        cookie = poison
    elif field == "csrf":
        csrf = poison
    elif field == "now":
        at = poison
    elif field == "actor":
        statement = case.statement if phase == "issue" else token.statement
        object.__setattr__(statement.actor, "actor_id", poison)
    elif field == "claim":
        statement = case.statement if phase == "issue" else token.statement
        object.__setattr__(statement.resolution_claim, "resolution_evidence_sha256", poison)
    elif phase == "current":
        object.__setattr__(token, "session_expires_at", poison)
    else:
        # Issuance has no caller-supplied session expiry; use declared operation time.
        object.__setattr__(case.statement, "attested_at", poison)
    with _observe_auth() as entries, pytest.raises(ValueError):
        if phase == "issue":
            case.issuer.authenticate(case.statement, session_cookie=cookie, csrf_token=csrf, now=at)
        else:
            case.issuer.require_authenticated(token, session_cookie=cookie, csrf_token=csrf, now=at)
    assert calls == []
    assert entries == []


@pytest.mark.parametrize("field", ["cookie", "csrf", "scope", "authority"])
def test_original_native_configuration_and_credential_caps_are_not_widened(field):
    case = _case()
    with _observe_auth() as entries, pytest.raises(ValueError):
        if field == "cookie":
            _issue(case, cookie="x" * 2049)
        elif field == "csrf":
            _issue(case, csrf="x" * 129)
        elif field == "scope":
            _ISSUER(case.security, scope_id="x" * 129, actor_authority_sha256=_AUTHORITY)
        else:
            _ISSUER(case.security, scope_id=_ACCOUNT, actor_authority_sha256="A" * 64)
    assert entries == []


@pytest.mark.parametrize("field", ["cookie", "csrf"])
def test_original_credential_cap_boundary_reaches_real_authentication(field):
    case = _case()
    with _observe_auth() as entries, pytest.raises(HTTPException) as caught:
        if field == "cookie":
            _issue(case, cookie="x" * 2048)
        else:
            _issue(case, csrf="x" * 128)
    assert len(entries) == 1
    assert caught.value.status_code == (401 if field == "cookie" else 403)


@pytest.mark.parametrize("target", ["security", "issuer", "statement", "token"])
def test_foreign_outer_classes_are_rejected_before_their_getters_or_authentication(target):
    case = _case()
    original = {
        "security": LocalOperatorSecurity,
        "issuer": _ISSUER,
        "statement": data.OperationalControlOperatorStatement,
        "token": AuthenticatedOperationalControlOperatorStatement,
    }[target]
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("getter")
        raise AssertionError("foreign authentication record getter was dispatched")

    foreign_type = type("ForeignAuthenticationValue", (original,), {"__getattribute__": forbidden})
    foreign = object.__new__(foreign_type)
    with _observe_auth() as entries, pytest.raises(ValueError):
        if target == "security":
            _ISSUER(foreign, scope_id=_ACCOUNT, actor_authority_sha256=_AUTHORITY)
        elif target == "issuer":
            _ISSUER.authenticate(
                foreign, case.statement, session_cookie=case.cookie, csrf_token=case.csrf, now=_NOW
            )
        elif target == "statement":
            _issue(case, statement=foreign)
        else:
            _require(case, foreign)
    assert calls == []
    assert entries == []


@pytest.mark.parametrize("phase", ["issue", "current"])
def test_rogue_exact_enum_member_is_denied_by_original_data_admission_before_auth(phase):
    case = _case()
    token = _issue(case) if phase == "current" else None
    rogue = str.__new__(OperationalControlActorKind, "human")
    object.__setattr__(rogue, "_value_", "human")
    object.__setattr__(rogue, "_name_", "HUMAN")
    assert type(rogue) is OperationalControlActorKind
    assert rogue is not OperationalControlActorKind.HUMAN
    statement = case.statement if phase == "issue" else token.statement
    object.__setattr__(statement.actor, "kind", rogue)
    with _observe_auth() as entries, pytest.raises(ValueError):
        if phase == "issue":
            _issue(case)
        else:
            _require(case, token)
    assert entries == []


@pytest.mark.parametrize("field", ["security", "scope_id", "actor_authority_sha256"])
@pytest.mark.parametrize("phase", ["issue", "current"])
def test_replacing_configured_issuer_bindings_is_not_an_authentication_proof(field, phase):
    case = _case()
    token = _issue(case) if phase == "current" else None
    replacement = (
        _security() if field == "security" else "different" if field == "scope_id" else "f" * 64
    )
    object.__setattr__(case.issuer, field, replacement)
    with _observe_auth() as entries, pytest.raises(ValueError):
        if phase == "issue":
            _issue(case)
        else:
            _require(case, token)
    assert entries == []


@pytest.mark.parametrize("phase", ["issue", "current"])
@pytest.mark.parametrize(
    "field,kind", [("_enabled", "str"), ("_operator_id", "str"), ("_key", "bytes")]
)
def test_original_security_private_state_is_native_before_authentication_hooks(phase, field, kind):
    case = _case()
    token = _issue(case) if phase == "current" else None
    calls = []
    object.__setattr__(case.security, field, _poison(kind, calls))
    with _observe_auth() as entries, pytest.raises(ValueError):
        if phase == "issue":
            _issue(case)
        else:
            _require(case, token)
    assert calls == []
    assert entries == []


@pytest.mark.parametrize("method", ["authenticate_with_expiry", "_decode"])
@pytest.mark.parametrize("phase", ["issue", "current"])
def test_replaced_original_authentication_methods_are_denied_without_calling_substitutes(
    method, phase
):
    case = _case()
    token = _issue(case) if phase == "current" else None
    called = []

    def forbidden(*args, **kwargs):
        called.append("substitute")
        raise AssertionError("substitute authentication method was dispatched")

    with pytest.MonkeyPatch.context() as local:
        local.setattr(LocalOperatorSecurity, method, forbidden)
        with _observe_auth() as entries, pytest.raises(ValueError):
            if phase == "issue":
                _issue(case)
            else:
                _require(case, token)
    assert called == []
    assert entries == []


def test_replaced_original_data_admission_is_denied_without_borrowing_a_substitute():
    case = _case()
    called = []

    def forbidden(*args, **kwargs):
        called.append("substitute")
        raise AssertionError("substitute data admission was dispatched")

    with pytest.MonkeyPatch.context() as local:
        local.setattr(data, "copy_operational_control_operator_statement", forbidden)
        with _observe_auth() as entries, pytest.raises(ValueError):
            _issue(case)
    assert called == []
    assert entries == []


def test_issuance_uses_its_detached_snapshot_despite_mutation_during_original_auth():
    case = _case()
    expected = case.statement.canonical_json

    def mutate_caller():
        object.__setattr__(case.statement, "control_transition_id", "changed-during-auth")
        object.__setattr__(case.statement.actor, "actor_id", "changed-during-auth")
        object.__setattr__(
            case.statement.resolution_claim, "resolution_code", "changed-during-auth"
        )

    with _observe_auth(mutate_caller) as entries:
        token = _issue(case)
    assert len(entries) == 1
    assert token.statement.canonical_json == expected
    assert token.statement.actor.actor_id == _OWNER
    assert token.statement.control_transition_id == "declared-control-head"
    assert token.statement.resolution_claim.resolution_code == "operator-reviewed"
    assert _require(case, token) is None


def test_current_owned_content_is_rechecked_after_actual_authentication():
    case = _case()
    token = _issue(case)

    def mutate_owned():
        object.__setattr__(
            token.statement.resolution_claim, "resolution_code", "changed-during-auth"
        )

    with _observe_auth(mutate_owned) as entries, pytest.raises(ValueError):
        _require(case, token)
    assert len(entries) == 1


def test_issuer_configuration_is_rechecked_after_actual_authentication():
    case = _case()

    def mutate_binding():
        object.__setattr__(case.issuer, "scope_id", "changed-during-auth")

    with _observe_auth(mutate_binding) as entries, pytest.raises(ValueError):
        _issue(case)
    assert len(entries) == 1
    assert len(case.issuer._owned) == len(case.issuer._original) == 0


def test_collected_original_tokens_release_both_weak_registry_and_native_baseline():
    case = _case()
    token = _issue(case)
    identity = id(token)
    assert case.issuer._owned[identity] is token
    assert identity in case.issuer._original
    reference = weakref.ref(token)
    del token
    gc.collect()
    assert reference() is None
    assert identity not in case.issuer._owned
    assert identity not in case.issuer._original


def test_authentication_has_no_store_socket_file_or_ambient_time_effect():
    case = _case()
    effects = []

    def forbidden(*args, **kwargs):
        effects.append("effect")
        raise AssertionError("transient authentication attempted an ambient effect")

    with pytest.MonkeyPatch.context() as local:
        for target, name in (
            (builtins, "open"),
            (Path, "open"),
            (Path, "read_bytes"),
            (Path, "write_bytes"),
            (socket, "socket"),
            (sqlite3, "connect"),
            (subprocess, "Popen"),
            (time, "time"),
            (time, "monotonic"),
            (time, "monotonic_ns"),
        ):
            local.setattr(target, name, forbidden)
        token = _issue(case)
        assert _require(case, token) is None
    assert effects == []
    assert case.statement.control_state is OperationalControlState.HALTED
    assert token.statement.control_state is OperationalControlState.HALTED
