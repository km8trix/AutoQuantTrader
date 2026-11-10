"""Native issuer boundaries with original security/command objects.

The descriptor below is explicitly unowned literal metadata. These units never
fabricate an owned preparation, REQUEST commit, H readiness or installation.
Real signing/decoding is used on pre-SQL denial paths; separate fresh integration
tests qualify actual retention and financial-owner consumption.
"""

import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from types import MappingProxyType, SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import HTTPException, Response

from apps.api import initial_selection_request_retention as retention
from apps.api.backtest_views import LOCAL_SESSION_COOKIE, LocalOperatorSecurity
from apps.api.continuous_read_access import (
    CONTINUOUS_READ_SESSION_COOKIE,
    ContinuousReadAccessConfiguration,
    ContinuousReadAccessSecurity,
)
from apps.api.metadata_access import METADATA_SESSION_COOKIE, MetadataAccessSecurity
from apps.api.runtime_owner_authentication import LocalRuntimeOwnerAuthenticator
from apps.trader import initial_selection_descriptor as descriptor_module
from apps.trader.initial_selection_descriptor import InitialSelectionDescriptor
from packages.application import personal_codec
from packages.domain.durable_journal_contracts import MAX_SEQUENCE, JournalHead, JournalReceipt
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.runtime_owner_commands import (
    OWNER_COMMAND_SCHEMA,
    RuntimeOwnerCommandRecord,
    SqlRuntimeOwnerCommands,
)

_INVALID = "^INITIAL_SELECTION_REQUEST_INVALID$"
_BINDING = "^INITIAL_SELECTION_REQUEST_BINDING_CHANGED$"


def _descriptor(at):
    return InitialSelectionDescriptor(
        account_id="native-request-account",
        account_binding_sha256="0" * 64,
        stream_id="native-request-stream",
        after_assignment_sha256="1" * 64,
        ledger_sha256="2" * 64,
        order_sha256="3" * 64,
        capacity_sha256="4" * 64,
        effect_watermark=7,
        attempt_sha256="5" * 64,
        control_revision=11,
        lease_generation=13,
        dependency_schema_id="runtime-owner-dependencies/1",
        dependency_object_sha256="6" * 64,
        dependency_byte_count=1024,
        dependency_codec_version="personal-record/1",
        dependency_semantic_sha256="7" * 64,
        checked_at=at - timedelta(seconds=1),
        valid_until=at + timedelta(seconds=30),
        c1_receipt_sha256="8" * 64,
        control_sha256="9" * 64,
        original_lease_sha256="a" * 64,
    )


def _security(*, enabled=True):
    return LocalOperatorSecurity(
        enabled=enabled,
        transport_is_loopback_scoped=True,
        operator_id="native-request-owner",
        configured_secret="unit-synthetic-session-secret",
    )


def _session(security, *, at=None):
    # Explicit test-only issuance, never evidence of an actual loopback route or
    # production full-readiness admission. I itself must never bootstrap.
    response = Response()
    capability = security.bootstrap_capability(
        response,
        persistence_ready=True,
        issued_at=datetime.now(UTC) if at is None else at,
        session_cookie=None,
    )
    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    return cookies[LOCAL_SESSION_COOKIE].value, capability.csrf_token


@pytest.fixture
def case(tmp_path):
    path = tmp_path / "unopened-issuer.sqlite"
    engine = sa.create_engine(f"sqlite+pysqlite:///{path}")
    security = _security()
    commands = SqlRuntimeOwnerCommands(
        engine, codec=personal_codec, authenticator=LocalRuntimeOwnerAuthenticator(security)
    )
    cookie, csrf = _session(security)
    calls = []

    def connected(connection):
        calls.append("connect")

    def executed(connection, cursor, statement, parameters, context, executemany):
        calls.append("sql")

    sa.event.listen(engine, "engine_connect", connected)
    sa.event.listen(engine, "before_cursor_execute", executed)
    value = SimpleNamespace(
        path=path,
        engine=engine,
        security=security,
        commands=commands,
        descriptor=_descriptor(datetime.now(UTC)),
        cookie=cookie,
        csrf=csrf,
        calls=calls,
    )
    try:
        yield value
    finally:
        sa.event.remove(engine, "engine_connect", connected)
        sa.event.remove(engine, "before_cursor_execute", executed)
        engine.dispose()  # The fixture alone owns this Engine's lifecycle.


def _call(case, **changes):
    arguments = dict(
        security=case.security,
        commands=case.commands,
        engine=case.engine,
        account_id=case.descriptor.account_id,
        descriptor=case.descriptor,
        command_id="native-request-command",
        session_cookie=case.cookie,
        csrf_token=case.csrf,
    )
    arguments.update(changes)
    return retention._retain_initial_selection_request(**arguments)


def _no_sql(case):
    assert case.calls == []
    assert not case.path.exists()
    assert case.commands.engine is case.commands.journal._engine is case.engine
    assert case.commands.authenticator.security is case.security


@pytest.mark.parametrize(
    ("name", "bad"),
    [
        ("account_id", None),
        ("account_id", True),
        ("account_id", ""),
        ("account_id", "a" * 129),
        ("account_id", " padded "),
        ("command_id", None),
        ("command_id", False),
        ("command_id", ""),
        ("command_id", "a" * 129),
        ("command_id", " padded "),
        ("session_cookie", True),
        ("session_cookie", b"cookie"),
        ("session_cookie", "c" * 2049),
        ("csrf_token", None),
        ("csrf_token", True),
        ("csrf_token", b"csrf"),
        ("csrf_token", "c" * 129),
    ],
)
def test_invalid_native_data_denies_before_authentication_or_sql(case, name, bad):
    with pytest.raises(ValueError, match=_INVALID):
        _call(case, **{name: bad})
    _no_sql(case)


@pytest.mark.parametrize("name", ["account_id", "command_id", "session_cookie", "csrf_token"])
def test_non_native_text_never_runs_operators_or_coercion(case, name):
    operators = []

    def forbidden(*args, **kwargs):
        operators.append("operator")
        raise AssertionError("request admission invoked non-native text")

    class HostileText(str):
        __len__ = forbidden
        __eq__ = forbidden
        __hash__ = forbidden
        strip = forbidden
        split = forbidden
        encode = forbidden

    with pytest.raises(ValueError, match=_INVALID):
        _call(case, **{name: HostileText("native-text")})
    assert operators == []
    _no_sql(case)


def test_independently_supplied_account_must_match_admitted_descriptor(case):
    with pytest.raises(ValueError, match=_INVALID):
        _call(case, account_id="another-native-account")
    _no_sql(case)


@pytest.mark.parametrize("kind", ["foreign", "late-int", "late-tz", "unknown-schema"])
def test_complete_descriptor_native_admission_precedes_auth_or_sql(case, kind):
    callbacks = []

    class Foreign:
        def __getattribute__(self, name):
            callbacks.append(name)
            raise AssertionError("foreign descriptor getter was invoked")

    class HostileInt(int):
        def __lt__(self, other):
            callbacks.append("lt")
            raise AssertionError("non-native descriptor counter was compared")

        def __eq__(self, other):
            callbacks.append("eq")
            raise AssertionError("non-native descriptor counter was compared")

    descriptor = case.descriptor
    if kind == "foreign":
        descriptor = Foreign()
    elif kind == "late-int":
        object.__setattr__(descriptor, "dependency_byte_count", HostileInt(1024))
    elif kind == "late-tz":
        object.__setattr__(descriptor, "valid_until", datetime(2026, 10, 28))
    else:
        object.__setattr__(descriptor, "dependency_schema_id", "unreviewed/1")
    with pytest.raises(ValueError, match=r"^INITIAL_SELECTION_DESCRIPTOR_INVALID$"):
        _call(case, descriptor=descriptor)
    assert callbacks == []
    _no_sql(case)


@pytest.mark.parametrize("kind", ["future-checked", "expired"])
def test_actual_utc_rejects_descriptor_outside_its_original_window(case, kind):
    at = datetime.now(UTC)
    if kind == "future-checked":
        descriptor = replace(
            case.descriptor,
            checked_at=at + timedelta(seconds=20),
            valid_until=at + timedelta(seconds=30),
        )
    else:
        descriptor = replace(
            case.descriptor,
            checked_at=at - timedelta(seconds=30),
            valid_until=at - timedelta(seconds=1),
        )
    with pytest.raises(ValueError, match=_INVALID):
        _call(case, descriptor=descriptor)
    _no_sql(case)


@pytest.mark.parametrize("kind", ["missing", "changed", "restart", "expired", "csrf", "disabled"])
def test_actual_shared_authentication_denies_before_head_or_connection(case, kind):
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
        csrf = "wrong-csrf"
    else:
        case.security = _security(enabled=False)
        case.commands.authenticator = LocalRuntimeOwnerAuthenticator(case.security)
    with pytest.raises(HTTPException) as caught:
        _call(case, session_cookie=cookie, csrf_token=csrf)
    assert caught.value.status_code == (403 if kind in ("csrf", "disabled") else 401)
    _no_sql(case)


@pytest.mark.parametrize("purpose", ["metadata", "operational-read"])
def test_read_only_credentials_cannot_reach_request_retention(case, purpose):
    response = Response()
    if purpose == "metadata":
        security = MetadataAccessSecurity(
            enabled=True,
            transport_is_loopback_scoped=True,
            operator_id="native-request-owner",
            configured_secret="unit-synthetic-session-secret",
        )
        capability = security.bootstrap_capability(
            response, issued_at=datetime.now(UTC), session_cookie=None
        )
        name = METADATA_SESSION_COOKIE
    else:
        security = ContinuousReadAccessSecurity(
            configuration=ContinuousReadAccessConfiguration(
                enabled=True,
                transport_is_loopback_scoped=True,
                operator_id="native-request-owner",
                configured_secret="unit-synthetic-session-secret",
            ),
            account_id=case.descriptor.account_id,
        )
        security.open()
        capability = security.bootstrap_capability(
            response, issued_at=datetime.now(UTC), session_cookie=None
        )
        name = CONTINUOUS_READ_SESSION_COOKIE
    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    try:
        with pytest.raises(HTTPException) as caught:
            _call(case, session_cookie=cookies[name].value, csrf_token=capability.csrf_token)
        assert caught.value.status_code == 401
        _no_sql(case)
    finally:
        if purpose == "operational-read":
            security.close()


@pytest.mark.parametrize("field", ["command_id", "account_id", "owner_id"])
def test_original_command_constructor_keeps_its_stricter_identifier_denial(case, field):
    # Journal IDs admit Unicode, while the existing command constructor has its
    # own narrower identifier contract. I must not rewrite this identifier.
    changes = {}
    if field == "command_id":
        changes[field] = "請求"
    elif field == "account_id":
        case.descriptor = replace(case.descriptor, account_id="請求")
    else:
        case.security = LocalOperatorSecurity(
            enabled=True,
            transport_is_loopback_scoped=True,
            operator_id="請求",
            configured_secret="unit-synthetic-session-secret",
        )
        case.commands.authenticator = LocalRuntimeOwnerAuthenticator(case.security)
        case.cookie, case.csrf = _session(case.security)
    with pytest.raises(ValueError, match=f"^invalid bounded {field}$"):
        _call(case, **changes)
    _no_sql(case)


def _receipt(*, previous=23, command_id="native receipt 請求"):
    return JournalReceipt(
        command_id=command_id,
        command_sha256="b" * 64,
        append_sha256="c" * 64,
        previous_head=JournalHead("d" * 64, previous, "e" * 64),
        committed_head=JournalHead("d" * 64, previous + 1, "f" * 64),
        record_ids=(command_id,),
        record_hashes=("0" * 64,),
    )


def _receipt_values(*, previous=23, command_id="native receipt 請求"):
    # Literal independent mapping: command/append, previous/committed heads,
    # and record payload hash have deliberately distinct roles.
    return (
        command_id,
        "b" * 64,
        "c" * 64,
        "d" * 64,
        previous,
        "e" * 64,
        "d" * 64,
        previous + 1,
        "f" * 64,
        (command_id,),
        ("0" * 64,),
    )


@pytest.mark.parametrize("sequence", [0, MAX_SEQUENCE])
def test_head_native_copy_preserves_exact_original_bounds_without_aliasing(sequence):
    original = JournalHead("1" * 64, sequence, "2" * 64)
    values = retention._head_values(original)
    assert values == ("1" * 64, sequence, "2" * 64)
    copied = retention._head_from_values(values)
    assert type(copied) is JournalHead
    assert copied is not original
    assert copied == original
    object.__setattr__(original, "entry_sha256", "3" * 64)
    assert copied.entry_sha256 == "2" * 64


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("key_sha256", None),
        ("key_sha256", "A" * 64),
        ("sequence", True),
        ("sequence", -1),
        ("sequence", MAX_SEQUENCE + 1),
        ("entry_sha256", b"2" * 64),
        ("entry_sha256", "2" * 63),
    ],
)
def test_bad_head_leaf_is_fixed_native_error(field, bad):
    original = JournalHead("1" * 64, 7, "2" * 64)
    object.__setattr__(original, field, bad)
    with pytest.raises(ValueError, match=_INVALID):
        retention._head_from_values(retention._head_values(original))


@pytest.mark.parametrize("previous", [0, MAX_SEQUENCE - 1])
def test_receipt_copy_preserves_unicode_and_distinct_hash_roles(previous):
    original = _receipt(previous=previous)
    values = retention._receipt_values(original)
    assert values == _receipt_values(previous=previous)
    copied = retention._receipt_from_values(values)
    assert type(copied) is JournalReceipt
    assert copied is not original
    assert copied.previous_head is not original.previous_head
    assert copied.committed_head is not original.committed_head
    assert copied == original
    object.__setattr__(original.previous_head, "entry_sha256", "9" * 64)
    object.__setattr__(original, "command_id", "changed-caller-record")
    object.__setattr__(original, "record_ids", ("changed-caller-record",))
    assert copied.command_id == "native receipt 請求"
    assert copied.previous_head.entry_sha256 == "e" * 64
    assert retention._receipt_values(copied) == values


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("command_id", " padded "),
        ("command_sha256", "x" * 64),
        ("append_sha256", None),
        ("previous_head", object()),
        ("committed_head", object()),
        ("record_ids", ["native receipt 請求"]),
        ("record_ids", ()),
        ("record_ids", ("native receipt 請求", "other-command")),
        ("record_hashes", ("0" * 63,)),
        ("record_hashes", ("0" * 64, "1" * 64)),
    ],
)
def test_receipt_native_or_semantic_denial_is_fixed_before_use(field, bad):
    original = _receipt()
    object.__setattr__(original, field, bad)
    with pytest.raises(ValueError, match=_INVALID):
        retention._receipt_from_values(retention._receipt_values(original))


@pytest.mark.parametrize("kind", ["key", "sequence"])
def test_receipt_rejects_inconsistent_original_heads(kind):
    original = _receipt()
    if kind == "key":
        object.__setattr__(original.committed_head, "key_sha256", "a" * 64)
    else:
        object.__setattr__(original.committed_head, "sequence", 25)
    with pytest.raises(ValueError, match=_INVALID):
        retention._receipt_from_values(retention._receipt_values(original))


@pytest.mark.parametrize("count", [2, 64])
def test_pure_copy_keeps_original_journal_inventory_not_public_issuer_policy(count):
    # I's public operation separately requires one record matching its command.
    # Its pure copy helper must retain the original JournalReceipt contract.
    ids = tuple(f"record-{index}" for index in range(count))
    original = JournalReceipt(
        command_id="different-native-command",
        command_sha256="b" * 64,
        append_sha256="c" * 64,
        previous_head=JournalHead("d" * 64, 23, "e" * 64),
        committed_head=JournalHead("d" * 64, 23 + count, "f" * 64),
        record_ids=ids,
        record_hashes=("0" * 64,) * count,
    )
    copied = retention._receipt_from_values(retention._receipt_values(original))
    assert copied == original
    assert copied is not original
    assert copied.record_ids == ids
    assert copied.committed_head.sequence == 23 + count


@pytest.mark.parametrize("kind", ["foreign", "late-int", "late-hash"])
def test_receipt_leaf_admission_never_loans_callbacks_or_constructs_early(kind):
    callbacks = []
    constructor_calls = []

    class Foreign:
        def __getattribute__(self, name):
            callbacks.append(name)
            raise AssertionError("foreign receipt getter loan")

    class HostileInt(int):
        def __eq__(self, other):
            callbacks.append("eq")
            raise AssertionError("non-native receipt comparison")

        def __add__(self, other):
            callbacks.append("add")
            raise AssertionError("non-native receipt arithmetic")

    original = _receipt()
    if kind == "foreign":
        original = Foreign()
    elif kind == "late-int":
        object.__setattr__(original.committed_head, "sequence", HostileInt(24))
    else:
        object.__setattr__(original, "record_hashes", (b"0" * 64,))
    original_codes = {
        JournalHead.__post_init__.__code__,
        JournalReceipt.__post_init__.__code__,
    }
    previous_profile = sys.getprofile()

    def observe(frame, event, arg):
        if event == "call" and frame.f_code in original_codes:
            constructor_calls.append(frame.f_code.co_name)
        if previous_profile is not None:
            previous_profile(frame, event, arg)

    sys.setprofile(observe)
    try:
        with pytest.raises(ValueError, match=_INVALID):
            retention._receipt_values(original)
    finally:
        sys.setprofile(previous_profile)
    assert callbacks == []
    assert constructor_calls == []


@pytest.mark.parametrize("index", [4, 8, 10])
def test_receipt_from_values_revalidates_native_tuple_before_constructors(index):
    values = list(_receipt_values())
    values[index] = True if index in (4, 8) else (b"0" * 64,)
    calls = []
    original_codes = {
        JournalHead.__post_init__.__code__,
        JournalReceipt.__post_init__.__code__,
    }
    previous_profile = sys.getprofile()

    def observe(frame, event, arg):
        if event == "call" and frame.f_code in original_codes:
            calls.append(frame.f_code.co_name)
        if previous_profile is not None:
            previous_profile(frame, event, arg)

    sys.setprofile(observe)
    try:
        with pytest.raises(ValueError, match=_INVALID):
            retention._receipt_from_values(tuple(values))
    finally:
        sys.setprofile(previous_profile)
    assert calls == []


@pytest.mark.parametrize("name", ["security", "commands", "engine"])
def test_exact_original_graph_classes_deny_foreign_getter_loans(case, name):
    callbacks = []

    class Foreign:
        def __getattribute__(self, attribute):
            callbacks.append(attribute)
            raise AssertionError("foreign graph object was traversed")

    with pytest.raises(ValueError, match=_INVALID):
        _call(case, **{name: Foreign()})
    assert callbacks == []
    _no_sql(case)


@pytest.mark.parametrize(
    "kind",
    [
        "commands-engine",
        "journal-engine",
        "auth-security",
        "auth-class",
        "journal-class",
        "commands-codec",
        "journal-codec",
    ],
)
def test_supplied_graph_associations_must_match_before_auth_or_sql(case, kind):
    original = None
    other_engine = None
    if kind in ("commands-engine", "journal-engine"):
        other_engine = sa.create_engine("sqlite+pysqlite:///:memory:")
        target = case.commands if kind == "commands-engine" else case.commands.journal
        attribute = "engine" if kind == "commands-engine" else "_engine"
        changed = other_engine
    elif kind == "auth-security":
        target, attribute, changed = case.commands.authenticator, "security", _security()
    elif kind == "auth-class":
        target, attribute, changed = case.commands, "authenticator", object()
    elif kind == "journal-class":
        target, attribute, changed = case.commands, "journal", object()
    elif kind == "commands-codec":
        target, attribute, changed = case.commands, "codec", SimpleNamespace()
    else:
        target, attribute, changed = case.commands.journal, "_codec", SimpleNamespace()
    original = getattr(target, attribute)
    setattr(target, attribute, changed)
    try:
        with pytest.raises(ValueError, match=_BINDING):
            _call(case)
        assert case.calls == []
        assert not case.path.exists()
    finally:
        setattr(target, attribute, original)
        if other_engine is not None:
            other_engine.dispose()
    _no_sql(case)


@pytest.mark.parametrize(
    "registry",
    [
        {},
        {OWNER_COMMAND_SCHEMA: RuntimeOwnerCommandRecord},
        MappingProxyType({}),
        MappingProxyType({OWNER_COMMAND_SCHEMA: JournalReceipt}),
        MappingProxyType({OWNER_COMMAND_SCHEMA: RuntimeOwnerCommandRecord, "extra/1": JournalHead}),
    ],
)
def test_journal_registry_is_exact_immutable_original_schema_inventory(case, registry):
    journal = case.commands.journal
    original = journal._types
    journal._types = registry
    try:
        with pytest.raises(ValueError, match=_BINDING):
            _call(case)
        assert case.calls == []
        assert not case.path.exists()
    finally:
        journal._types = original
    _no_sql(case)


@pytest.mark.parametrize("field", ["authenticator", "journal"])
def test_captured_graph_rejects_identity_change_without_inventing_constructor_history(case, field):
    captured = retention._graph(case.security, case.commands, case.engine)
    if field == "authenticator":
        replacement = LocalRuntimeOwnerAuthenticator(case.security)
    else:
        replacement = SqlDurableJournal(
            case.engine,
            codec=personal_codec,
            record_types={OWNER_COMMAND_SCHEMA: RuntimeOwnerCommandRecord},
        )
    original = getattr(case.commands, field)
    setattr(case.commands, field, replacement)
    try:
        with pytest.raises(ValueError, match=_BINDING):
            retention._require_graph(captured)
        # A newly and explicitly supplied actual compatible graph is admissible
        # metadata. The guard cannot attest its unobserved constructor history.
        fresh = retention._graph(case.security, case.commands, case.engine)
        retention._require_graph(fresh)
        assert fresh is not captured
        assert case.calls == []
        assert not case.path.exists()
    finally:
        setattr(case.commands, field, original)
    _no_sql(case)


@pytest.mark.parametrize("kind", ["foreign", "other-engine", "instance-shadow"])
def test_actual_connection_guard_denies_before_any_new_statement(case, monkeypatch, kind):
    # This test explicitly opens a caller-owned Connection, without a schema,
    # authentication/command preparation or REQUEST. It tests only that direct
    # entry guard; it is not a successful public retention transaction.
    graph = retention._graph(case.security, case.commands, case.engine)
    substituted = []
    getters = []

    class Foreign:
        def __getattribute__(self, name):
            getters.append(name)
            raise AssertionError("foreign Connection getter loan")

    def forbidden(*args, **kwargs):
        substituted.append("execute")
        raise AssertionError("instance-shadowed SQL effect was invoked")

    other = sa.create_engine("sqlite+pysqlite:///:memory:")
    try:
        with case.engine.connect() as original, other.connect() as foreign:
            assert retention._connection_bindings(original, graph) is original
            baseline = list(case.calls)
            candidate = Foreign() if kind == "foreign" else foreign
            with monkeypatch.context() as patch:
                if kind == "instance-shadow":
                    candidate = original
                    patch.setattr(original, "exec_driver_sql", forbidden)
                with pytest.raises(ValueError, match=_BINDING):
                    retention._connection_bindings(candidate, graph)
            assert case.calls == baseline
            assert substituted == []
            assert getters == []
            assert not original.in_transaction()
            assert not foreign.in_transaction()
    finally:
        other.dispose()


@pytest.mark.parametrize(
    ("owner_class", "name"),
    [
        (LocalOperatorSecurity, "authenticate_with_expiry"),
        (LocalRuntimeOwnerAuthenticator, "authenticate"),
        (LocalRuntimeOwnerAuthenticator, "require_authenticated"),
        (SqlRuntimeOwnerCommands, "prepare"),
        (SqlRuntimeOwnerCommands, "require_prepared"),
        (SqlRuntimeOwnerCommands, "append_in_transaction"),
        (SqlDurableJournal, "read_head"),
        (sa.engine.Engine, "begin"),
        (sa.engine.Connection, "exec_driver_sql"),
    ],
)
def test_finite_direct_class_replacement_denies_without_calling_substitute(
    case,
    monkeypatch,
    owner_class,
    name,
):
    calls = []

    def substituted(*args, **kwargs):
        calls.append(name)
        raise AssertionError("substituted direct effect was invoked")

    with monkeypatch.context() as patch:
        patch.setattr(owner_class, name, substituted)
        with pytest.raises(ValueError, match=_BINDING):
            _call(case)
    assert calls == []
    _no_sql(case)


@pytest.mark.parametrize(
    ("target_name", "name"),
    [
        ("authenticator", "authenticate"),
        ("authenticator", "require_authenticated"),
        ("commands", "prepare"),
        ("commands", "require_prepared"),
        ("commands", "append_in_transaction"),
        ("journal", "read_head"),
        ("engine", "begin"),
    ],
)
def test_finite_direct_instance_shadow_denies_without_calling_substitute(
    case,
    monkeypatch,
    target_name,
    name,
):
    target = {
        "authenticator": case.commands.authenticator,
        "commands": case.commands,
        "journal": case.commands.journal,
        "engine": case.engine,
    }[target_name]
    calls = []

    def substituted(*args, **kwargs):
        calls.append(name)
        raise AssertionError("instance-shadowed effect was invoked")

    with monkeypatch.context() as patch:
        patch.setattr(target, name, substituted)
        with pytest.raises(ValueError, match=_BINDING):
            _call(case)
    assert calls == []
    _no_sql(case)


@pytest.mark.parametrize("clip_session", [False, True])
def test_original_authentication_uses_one_time_and_copied_descriptor_before_sql(
    case,
    clip_session,
):
    # This is a partial workflow observation, stopped at the original read_head
    # entry before its first SQL effect. It creates no REQUEST or owned H proof.
    if clip_session:
        case.cookie, case.csrf = _session(
            case.security, at=datetime.now(UTC) - timedelta(hours=8) + timedelta(seconds=20)
        )
    original = case.descriptor
    admitted_until = original.valid_until
    session_returns = []
    authentications = []
    head_entries = []
    copied = []

    class BeforeHead(BaseException):
        pass

    sentinel = BeforeHead("test stops before original head I/O")
    previous_profile = sys.getprofile()
    session_code = LocalOperatorSecurity.authenticate_with_expiry.__code__
    authentication_code = LocalRuntimeOwnerAuthenticator.authenticate.__code__
    head_code = SqlDurableJournal.read_head.__code__
    copy_code = descriptor_module._from_values.__code__

    def observe(frame, event, arg):
        if event == "call" and frame.f_code is copy_code and not copied:
            copied.append(frame.f_locals["values"])
            # Mutate only the caller's object after the original snapshot. No
            # validator or pinned method is replaced, and the tuple is untouched.
            object.__setattr__(original, "after_assignment_sha256", "f" * 64)
            object.__setattr__(original, "ledger_sha256", "e" * 64)
            object.__setattr__(original, "valid_until", datetime(2000, 1, 1, tzinfo=UTC))
        if event == "return" and frame.f_code is session_code:
            session_returns.append((frame.f_locals["now"], arg))
        if event == "call" and frame.f_code is authentication_code:
            authentications.append((frame.f_locals["command"], frame.f_locals["now"]))
        if event == "call" and frame.f_code is head_code:
            head_entries.append(frame.f_locals["self"])
            raise sentinel
        if previous_profile is not None:
            previous_profile(frame, event, arg)

    sys.setprofile(observe)
    try:
        with pytest.raises(BeforeHead) as caught:
            _call(case)
    finally:
        sys.setprofile(previous_profile)
    assert caught.value is sentinel
    assert len(copied) == 1
    assert head_entries == [case.commands.journal]
    assert len(authentications) == 1
    command, at = authentications[0]
    assert len(session_returns) == 2
    assert all(sample is at for sample, result in session_returns)
    assert session_returns[0][1] == session_returns[1][1]
    operator_id, session_expires = session_returns[0][1]
    assert command.owner_id == operator_id == "native-request-owner"
    assert command.account_id == "native-request-account"
    assert command.command_id == "native-request-command"
    assert command.before_assignment_sha256 is None
    assert command.after_assignment_sha256 == "1" * 64
    assert command.quiescence_sha256 == "7" * 64
    assert command.requested_at is at
    assert command.expires_at == min(at + timedelta(seconds=60), session_expires, admitted_until)
    assert command.runtime_environment == "stateful_simulation"
    heads = command.expected_heads
    assert (heads.ledger_sha256, heads.order_sha256, heads.capacity_sha256) == (
        "2" * 64,
        "3" * 64,
        "4" * 64,
    )
    assert (
        heads.effect_watermark,
        heads.attempt_sha256,
        heads.control_revision,
        heads.lease_generation,
    ) == (
        7,
        "5" * 64,
        11,
        13,
    )
    if clip_session:
        assert command.expires_at == session_expires < admitted_until
    else:
        assert command.expires_at == admitted_until < session_expires
    assert original.after_assignment_sha256 == "f" * 64
    _no_sql(case)


@pytest.mark.parametrize(
    "name",
    [
        "_BINDINGS",
        "_bindings",
        "_GRAPH",
        "_REQUIRE_GRAPH",
        "_AUTHENTICATE",
        "_AUTH_COMMAND",
        "_AUTH_REQUIRE",
        "_PREPARE",
        "_REQUIRE",
        "_APPEND",
        "_READ_HEAD",
        "_KEY",
        "_BEGIN",
        "_EXECUTE",
        "_ENTER",
        "_EXIT",
        "_D_VALUES",
        "_D_FROM",
        "_D_DATA",
        "_COMMAND",
        "_HEAD",
        "_RECEIPT",
        "_HEAD_VALUES",
        "_HEAD_FROM_VALUES",
        "_RECEIPT_VALUES",
        "_NATIVE_RECEIPT_VALUES",
        "_RECEIPT_FROM_VALUES",
    ],
)
def test_actual_dispatch_alias_replacement_is_denied_before_substitute_or_sql(
    case,
    monkeypatch,
    name,
):
    substituted = []

    def forbidden(*args, **kwargs):
        substituted.append(name)
        raise AssertionError("replacement dispatch alias was invoked")

    with monkeypatch.context() as patch:
        patch.setattr(retention, name, forbidden)
        with pytest.raises(ValueError, match=_BINDING):
            _call(case)
    assert substituted == []
    _no_sql(case)


def _deny_without_original_constructor(operation):
    # Observe the unmodified generated constructors and original validators.
    # This cannot make an invalid input pass or replace a pinned effect port.
    calls = []
    codes = {
        JournalHead.__init__.__code__,
        JournalHead.__post_init__.__code__,
        JournalReceipt.__init__.__code__,
        JournalReceipt.__post_init__.__code__,
    }
    previous_profile = sys.getprofile()

    def observe(frame, event, arg):
        if event == "call" and frame.f_code in codes:
            calls.append(frame.f_code.co_name)
        if previous_profile is not None:
            previous_profile(frame, event, arg)

    sys.setprofile(observe)
    try:
        with pytest.raises(ValueError, match=_INVALID):
            operation()
    finally:
        sys.setprofile(previous_profile)
    assert calls == []


@pytest.mark.parametrize(
    ("index", "bad"),
    [
        (0, "a" * 63),
        (0, "a" * 65),
        (0, "A" * 64),
        (0, "g" * 64),
        (1, -1),
        (1, MAX_SEQUENCE + 1),
        (2, "b" * 63),
        (2, "b" * 65),
        (2, "z" * 64),
    ],
)
def test_all_head_primitive_bounds_precede_original_constructor(index, bad):
    values = ["a" * 64, 23, "b" * 64]
    values[index] = bad
    _deny_without_original_constructor(lambda: retention._head_from_values(tuple(values)))


@pytest.mark.parametrize(
    ("index", "bad"),
    [
        (0, ""),
        (0, "請" * 129),
        (1, "b" * 63),
        (1, "b" * 65),
        (1, "g" * 64),
        (2, "C" * 64),
        (3, "d" * 65),
        (4, -1),
        (4, MAX_SEQUENCE + 1),
        (5, "g" * 64),
        (6, "d" * 63),
        (7, MAX_SEQUENCE + 1),
        (8, "f" * 65),
        (9, ("",)),
        (9, ("請" * 129,)),
        (10, ("0" * 63,)),
        (10, ("z" * 64,)),
        (10, ("0" * 64, "z" * 64)),
    ],
)
def test_complete_receipt_primitive_bounds_precede_either_head_constructor(index, bad):
    values = list(_receipt_values())
    values[index] = bad
    _deny_without_original_constructor(lambda: retention._receipt_from_values(tuple(values)))


def test_original_unicode_identifier_bound_is_characters_in_pure_receipt_copy():
    identifier = "請" * 128
    original = _receipt(command_id=identifier)
    copied = retention._receipt_from_values(retention._receipt_values(original))
    assert copied is not original
    assert copied.command_id == identifier
    assert copied.record_ids == (identifier,)
    assert len(copied.command_id) == 128
    assert len(copied.command_id.encode("utf-8")) == 384
