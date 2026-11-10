"""History admission boundaries, never fabricated owned historical results.

These units use original shared security and commands with unopened SQLite
Engines. Original read-entry observations stop before SQL; separate native tests
qualify receipt/missing results, historical bytes and delivery authentication.
"""

import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import HTTPException, Response

from apps.api import initial_selection_request_history as history
from apps.api.backtest_views import LocalOperatorSecurity
from apps.api.continuous_read_access import (
    CONTINUOUS_READ_SESSION_COOKIE,
    ContinuousReadAccessConfiguration,
    ContinuousReadAccessSecurity,
)
from apps.api.metadata_access import METADATA_SESSION_COOKIE, MetadataAccessSecurity
from apps.api.runtime_owner_authentication import LocalRuntimeOwnerAuthenticator
from apps.trader import initial_selection_descriptor as descriptors
from packages.application import personal_codec
from packages.persistence import durable_journal
from packages.persistence.daily_runtime_risk import RuntimeReadBudget
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.runtime_owner_commands import (
    ResolvedRuntimeOwnerCommand,
    SqlRuntimeOwnerCommands,
)
from tests.unit.test_personal_initial_selection_request_retention import (
    _descriptor,
    _security,
    _session,
)

_INVALID = r"^INITIAL_SELECTION_REQUEST_HISTORY_INVALID$"
_CHANGED = r"^INITIAL_SELECTION_REQUEST_HISTORY_BINDING_CHANGED$"
_I_INVALID = r"^INITIAL_SELECTION_REQUEST_INVALID$"
_I_CHANGED = r"^INITIAL_SELECTION_REQUEST_BINDING_CHANGED$"
_D_INVALID = r"^INITIAL_SELECTION_DESCRIPTOR_INVALID$"


@pytest.fixture
def case(tmp_path):
    path = tmp_path / "unopened-history.sqlite3"
    engine = sa.create_engine(sa.URL.create("sqlite+pysqlite", database=str(path)))
    security = _security()
    commands = SqlRuntimeOwnerCommands(
        engine,
        codec=personal_codec,
        authenticator=LocalRuntimeOwnerAuthenticator(security),
    )
    cookie, csrf = _session(security)
    calls = []

    def connected(connection):
        calls.append("connect")

    def executed(connection, cursor, statement, parameters, context, executemany):
        calls.append("sql")

    def disposed(actual):
        assert actual is engine
        calls.append("dispose")

    sa.event.listen(engine, "engine_connect", connected)
    sa.event.listen(engine, "before_cursor_execute", executed)
    sa.event.listen(engine, "engine_disposed", disposed)
    value = SimpleNamespace(
        path=path,
        engine=engine,
        security=security,
        commands=commands,
        cookie=cookie,
        csrf=csrf,
        descriptor=_descriptor(datetime.now(UTC)),
        calls=calls,
    )
    try:
        yield value
    finally:
        sa.event.remove(engine, "engine_connect", connected)
        sa.event.remove(engine, "before_cursor_execute", executed)
        sa.event.remove(engine, "engine_disposed", disposed)
        engine.dispose()  # Only this fixture owns Engine cleanup.


def _call(case, **changes):
    arguments = dict(
        security=case.security,
        commands=case.commands,
        engine=case.engine,
        account_id=case.descriptor.account_id,
        descriptor=case.descriptor,
        command_id="native-historical-command",
        session_cookie=case.cookie,
        csrf_token=case.csrf,
    )
    arguments.update(changes)
    return history._read_initial_selection_request(**arguments)


def _no_sql(case):
    assert case.calls == [] and not case.path.exists()
    assert case.commands.engine is case.commands.journal._engine is case.engine
    assert case.commands.authenticator.security is case.security


@pytest.mark.parametrize(
    ("name", "bad"),
    [
        ("account_id", True),
        ("account_id", " padded "),
        ("command_id", None),
        ("command_id", "x" * 129),
    ],
)
def test_reused_identifier_denials_keep_original_i_error_before_sql(case, name, bad):
    with pytest.raises(ValueError, match=_I_INVALID):
        _call(case, **{name: bad})
    _no_sql(case)


@pytest.mark.parametrize(
    ("name", "bad"),
    [
        ("session_cookie", True),
        ("session_cookie", "x" * 2049),
        ("csrf_token", None),
        ("csrf_token", b"csrf"),
        ("csrf_token", "x" * 129),
    ],
)
def test_native_session_input_denials_precede_authentication_and_sql(case, name, bad):
    with pytest.raises(ValueError, match=_INVALID):
        _call(case, **{name: bad})
    _no_sql(case)


def test_explicit_account_mismatch_is_not_a_missing_result(case):
    with pytest.raises(ValueError, match=_INVALID):
        _call(case, account_id="another-configured-account")
    _no_sql(case)


@pytest.mark.parametrize("name", ["now", "budget", "resolved", "callback"])
def test_no_caller_clock_budget_token_or_callback_is_accepted(case, name):
    callbacks = []

    class Foreign:
        def __getattribute__(self, attribute):
            callbacks.append(attribute)
            raise AssertionError("unsupported argument getter was borrowed")

    with pytest.raises(TypeError, match="unexpected keyword argument"):
        _call(case, **{name: Foreign()})
    assert callbacks == []
    _no_sql(case)


@pytest.mark.parametrize("kind", ["foreign", "counter", "naive-time"])
def test_original_complete_descriptor_admission_precedes_auth_or_read(case, kind):
    callbacks = []

    class Foreign:
        def __getattribute__(self, name):
            callbacks.append(name)
            raise AssertionError("foreign descriptor getter was borrowed")

    descriptor = case.descriptor
    if kind == "foreign":
        descriptor = Foreign()
    else:
        field, value = (
            ("dependency_byte_count", True)
            if kind == "counter"
            else ("valid_until", datetime(2026, 1, 1))
        )
        object.__setattr__(descriptor, field, value)
    with pytest.raises(ValueError, match=_D_INVALID):
        _call(case, descriptor=descriptor)
    assert callbacks == []
    _no_sql(case)


@pytest.mark.parametrize("kind", ["missing", "changed", "restart", "expired", "csrf", "disabled"])
def test_original_current_shared_authentication_denies_before_history_read(case, kind):
    cookie, csrf = case.cookie, case.csrf
    if kind == "missing":
        cookie = None
    elif kind == "changed":
        cookie += "x"
    elif kind == "restart":
        case.security = _security()
        case.commands.authenticator = LocalRuntimeOwnerAuthenticator(case.security)
    elif kind == "expired":
        cookie, csrf = _session(case.security, at=datetime.now(UTC) - timedelta(hours=8, seconds=1))
    elif kind == "csrf":
        csrf = "different-csrf"
    else:
        case.security = _security(enabled=False)
        case.commands.authenticator = LocalRuntimeOwnerAuthenticator(case.security)
    with pytest.raises(HTTPException) as caught:
        _call(case, session_cookie=cookie, csrf_token=csrf)
    assert caught.value.status_code == (403 if kind in ("csrf", "disabled") else 401)
    _no_sql(case)


@pytest.mark.parametrize("purpose", ["metadata", "operational"])
def test_read_only_capabilities_do_not_authorize_shared_history_access(case, purpose):
    at = datetime.now(UTC)
    response = Response()
    if purpose == "metadata":
        security = MetadataAccessSecurity(
            enabled=True,
            transport_is_loopback_scoped=True,
            operator_id="native-request-owner",
            configured_secret="test-only-session",
        )
        cookie_name = METADATA_SESSION_COOKIE
    else:
        security = ContinuousReadAccessSecurity(
            configuration=ContinuousReadAccessConfiguration(
                enabled=True,
                transport_is_loopback_scoped=True,
                operator_id="native-request-owner",
                configured_secret="test-only-session",
            ),
            account_id=case.descriptor.account_id,
        )
        security.open()
        cookie_name = CONTINUOUS_READ_SESSION_COOKIE
    capability = security.bootstrap_capability(response, issued_at=at, session_cookie=None)
    jar = SimpleCookie()
    jar.load(response.headers["set-cookie"])
    try:
        assert (
            security.authenticate(jar[cookie_name].value, capability.csrf_token, now=at)
            == "native-request-owner"
        )
        with pytest.raises(HTTPException) as caught:
            _call(case, session_cookie=jar[cookie_name].value, csrf_token=capability.csrf_token)
        assert caught.value.status_code == 401
        _no_sql(case)
    finally:
        if purpose == "operational":
            security.close()


@pytest.mark.parametrize("name", ["security", "commands", "engine"])
def test_reused_exact_graph_admission_never_loans_foreign_getters(case, name):
    callbacks = []

    class Foreign:
        def __getattribute__(self, attribute):
            callbacks.append(attribute)
            raise AssertionError("foreign graph getter was borrowed")

    with pytest.raises(ValueError, match=_I_INVALID):
        _call(case, **{name: Foreign()})
    assert callbacks == []
    _no_sql(case)


def test_reused_graph_requires_the_supplied_original_shared_security(case):
    with pytest.raises(ValueError, match=_I_CHANGED):
        _call(case, security=_security())
    _no_sql(case)


@pytest.mark.parametrize(
    "kind", ["current", "stale", "future", "alternate-scope", "journal-unicode"]
)
def test_unowned_descriptor_window_does_not_replace_current_auth_or_default_read_budget(case, kind):
    if kind == "stale":
        case.descriptor = _descriptor(datetime(2023, 1, 3, tzinfo=UTC))
    elif kind == "future":
        case.descriptor = _descriptor(datetime(2090, 1, 3, tzinfo=UTC))
    elif kind == "alternate-scope":
        case.descriptor = replace(case.descriptor, stream_id="another-historical-stream")
    entries = []
    sessions = []
    command_authentications = []
    previous_profile = sys.getprofile()
    read_code = SqlRuntimeOwnerCommands.read.__code__
    session_code = LocalOperatorSecurity.authenticate_with_expiry.__code__
    command_authentication_code = LocalRuntimeOwnerAuthenticator.authenticate.__code__

    class BeforeRead(BaseException):
        pass

    primary = BeforeRead("test stops before original history SQL")

    def observe(frame, event, arg):
        if event == "return" and frame.f_code is session_code:
            sessions.append((frame.f_locals["now"], arg))
        if event == "call" and frame.f_code is command_authentication_code:
            command_authentications.append(frame.f_locals["command"])
        if event == "call" and frame.f_code is read_code:
            entries.append(
                (
                    frame.f_locals["self"],
                    frame.f_locals["scope"],
                    frame.f_locals["command_id"],
                    frame.f_locals["budget"],
                )
            )
            raise primary
        if previous_profile is not None:
            previous_profile(frame, event, arg)

    sys.setprofile(observe)
    try:
        with pytest.raises(BeforeRead) as caught:
            # A lookup uses the original journal-ID contract. It must not
            # construct a new command just to apply that constructor's ASCII
            # restriction; this sentinel does not claim such a record exists.
            _call(
                case,
                command_id="請求" if kind == "journal-unicode" else "native-historical-command",
            )
    finally:
        sys.setprofile(previous_profile)
    assert caught.value is primary and len(entries) == len(sessions) == 1
    assert command_authentications == []
    commands, scope, command_id, budget = entries[0]
    assert commands is case.commands
    assert scope.account_id == case.descriptor.account_id
    assert scope.stream_id == case.descriptor.stream_id
    assert scope.account_binding_sha256 == case.descriptor.account_binding_sha256
    assert command_id == ("請求" if kind == "journal-unicode" else "native-historical-command")
    assert type(budget) is RuntimeReadBudget
    assert (budget.rows, budget.payload_bytes, budget.metadata_bytes, budget.captured) == (
        0,
        0,
        0,
        [],
    )
    at, (operator, expiry) = sessions[0]
    assert type(at) is datetime and at.tzinfo is UTC
    assert operator == "native-request-owner" and at < expiry
    if kind == "stale":
        assert case.descriptor.valid_until < at
    elif kind == "future":
        assert at < case.descriptor.checked_at
    _no_sql(case)


def test_original_read_consumes_the_validated_descriptor_snapshot(case):
    original = case.descriptor
    copied = []
    scopes = []
    previous_profile = sys.getprofile()
    copy_code = descriptors._from_values.__code__
    read_code = SqlRuntimeOwnerCommands.read.__code__

    class BeforeRead(BaseException):
        pass

    primary = BeforeRead("test stops after original scope projection")

    def observe(frame, event, arg):
        if event == "call" and frame.f_code is copy_code and not copied:
            copied.append(frame.f_locals["values"])
            object.__setattr__(original, "account_binding_sha256", "f" * 64)
            object.__setattr__(original, "stream_id", "mutated-caller-stream")
            object.__setattr__(original, "after_assignment_sha256", "e" * 64)
        if event == "call" and frame.f_code is read_code:
            scopes.append(frame.f_locals["scope"])
            raise primary
        if previous_profile is not None:
            previous_profile(frame, event, arg)

    sys.setprofile(observe)
    try:
        with pytest.raises(BeforeRead) as caught:
            _call(case)
    finally:
        sys.setprofile(previous_profile)
    assert caught.value is primary and len(copied) == len(scopes) == 1
    scope = scopes[0]
    assert scope.account_id == "native-request-account"
    assert scope.account_binding_sha256 == "0" * 64
    assert scope.stream_id == "native-request-stream"
    assert original.stream_id == "mutated-caller-stream"
    _no_sql(case)


@pytest.mark.parametrize(
    ("owner", "name"),
    [
        (SqlRuntimeOwnerCommands, "read"),
        (SqlRuntimeOwnerCommands, "capture_in_transaction"),
        (SqlRuntimeOwnerCommands, "resolve_snapshot"),
        (SqlRuntimeOwnerCommands, "require_resolved"),
        (SqlDurableJournal, "capture_in_transaction"),
        (SqlDurableJournal, "resolve_snapshot"),
        (RuntimeReadBudget, "__init__"),
        (RuntimeReadBudget, "charge"),
    ],
)
def test_selected_original_read_port_class_replacement_is_not_invoked(
    case, monkeypatch, owner, name
):
    substituted = []

    def forbidden(*args, **kwargs):
        substituted.append(name)
        raise AssertionError("substituted read port was invoked")

    with monkeypatch.context() as patch:
        patch.setattr(owner, name, forbidden)
        with pytest.raises(ValueError, match=_CHANGED):
            _call(case)
    assert substituted == []
    _no_sql(case)


@pytest.mark.parametrize(
    ("target_name", "name"),
    [
        ("commands", "read"),
        ("commands", "capture_in_transaction"),
        ("commands", "resolve_snapshot"),
        ("commands", "require_resolved"),
        ("journal", "capture_in_transaction"),
        ("journal", "resolve_snapshot"),
    ],
)
def test_selected_read_port_instance_shadow_is_not_invoked(case, monkeypatch, target_name, name):
    target = case.commands if target_name == "commands" else case.commands.journal
    substituted = []

    def forbidden(*args, **kwargs):
        substituted.append(name)
        raise AssertionError("instance-shadowed read port was invoked")

    with monkeypatch.context() as patch:
        patch.setattr(target, name, forbidden)
        with pytest.raises(ValueError, match=_CHANGED):
            _call(case)
    assert substituted == []
    _no_sql(case)


@pytest.mark.parametrize(
    "name",
    [
        "_BINDINGS",
        "_bindings",
        "_REQUIRE_GRAPH",
        "_SESSION",
        "_MATCHED_RECEIPT",
        "_READ",
        "_REQUIRE_RESOLVED",
        "_READ_TRANSACTION",
        "_BUDGET",
        "_D_FROM",
    ],
)
def test_selected_actual_dispatch_alias_drift_denies_without_substitute_or_sql(
    case, monkeypatch, name
):
    substituted = []

    def forbidden(*args, **kwargs):
        substituted.append(name)
        raise AssertionError("changed direct dispatch was invoked")

    with monkeypatch.context() as patch:
        patch.setattr(history, name, forbidden)
        with pytest.raises(ValueError, match=_CHANGED):
            _call(case)
    assert substituted == []
    _no_sql(case)


@pytest.mark.parametrize("kind", ["foreign-result", "foreign-nested-record"])
def test_projection_rejects_unowned_foreign_shapes_before_borrowing_getters(case, kind):
    callbacks = []

    class Foreign:
        def __getattribute__(self, name):
            callbacks.append(name)
            raise AssertionError("foreign historical result getter was borrowed")

    # This exact wrapper deliberately has invalid nested shapes. It is not an
    # owned command or a modeled successful read, and cannot reach comparisons.
    value = (
        Foreign()
        if kind == "foreign-result"
        else ResolvedRuntimeOwnerCommand(Foreign(), Foreign(), object())
    )
    with pytest.raises(ValueError, match=_INVALID):
        history._matched_receipt(value, None, None, None, None, None, None)
    assert callbacks == []
    _no_sql(case)


@pytest.mark.parametrize(
    "name",
    [
        "MAX_RECORD_BYTES",
        "MAX_APPEND_RECORDS",
        "MAX_SEQUENCE",
        "_MAX_KEY_BYTES",
    ],
)
@pytest.mark.parametrize("invalid_type", [False, True])
def test_original_journal_transfer_limit_alias_changes_deny_before_sql(
    case,
    monkeypatch,
    name,
    invalid_type,
):
    original = getattr(durable_journal, name)
    assert type(original) is int
    with monkeypatch.context() as patch:
        patch.setattr(durable_journal, name, True if invalid_type else original + 1)
        with pytest.raises(ValueError, match=_CHANGED):
            _call(case)
    _no_sql(case)
