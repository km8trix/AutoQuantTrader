"""Retain one original authenticated REQUEST; never install or issue a session.

The caller owns every supplied owner and Engine. A failed return can follow
COMMIT; this operation neither retries nor infers rollback from an exception.
"""

from __future__ import annotations

from contextlib import _GeneratorContextManager
from datetime import UTC, datetime, timedelta
from types import MappingProxyType

from sqlalchemy import Connection, Engine
from sqlalchemy.dialects.sqlite.pysqlite import SQLiteDialect_pysqlite

from apps.api import backtest_views, runtime_owner_authentication
from apps.api.backtest_views import LocalOperatorSecurity
from apps.api.runtime_owner_authentication import LocalRuntimeOwnerAuthenticator
from apps.trader import initial_selection_descriptor as descriptors
from apps.trader.initial_selection_descriptor import InitialSelectionDescriptor
from packages.application import personal_codec
from packages.domain import durable_journal_contracts as journal_values
from packages.domain.continuous_persistence_contracts import (
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.personal_contracts import ContractRecord, require_digest
from packages.domain.reconciliation_contracts import ReconciliationHeads
from packages.domain.research_job_contracts import ObjectRef, require_identifier
from packages.persistence import daily_runtime_risk, durable_journal, runtime_owner_commands
from packages.persistence.daily_runtime_risk import RuntimeAssignmentCommand
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.runtime_owner_commands import (
    PreparedRuntimeOwnerCommand,
    RuntimeOwnerCommandRecord,
    SqlRuntimeOwnerCommands,
)

_INVALID = "INITIAL_SELECTION_REQUEST_INVALID"
_CHANGED = "INITIAL_SELECTION_REQUEST_BINDING_CHANGED"
_SECURITY = LocalOperatorSecurity
_AUTHENTICATOR = LocalRuntimeOwnerAuthenticator
_COMMANDS = SqlRuntimeOwnerCommands
_JOURNAL = SqlDurableJournal
_ENGINE = Engine
_CONNECTION = Connection
_DIALECT = SQLiteDialect_pysqlite
_CODEC = personal_codec
_DATETIME = datetime
_HEAD = journal_values.JournalHead
_RECEIPT = journal_values.JournalReceipt
_COMMAND = RuntimeAssignmentCommand
_RECORD = RuntimeOwnerCommandRecord
_DESCRIPTOR = InitialSelectionDescriptor
_D_VALUES = descriptors._descriptor_values
_D_FROM = descriptors._from_values
_D_DATA = descriptors.initial_selection_request_data
_AUTHENTICATE = _SECURITY.authenticate_with_expiry
_AUTH_COMMAND = _AUTHENTICATOR.authenticate
_AUTH_REQUIRE = _AUTHENTICATOR.require_authenticated
_PREPARE = _COMMANDS.prepare
_REQUIRE = _COMMANDS.require_prepared
_APPEND = _COMMANDS.append_in_transaction
_READ_HEAD = _JOURNAL.read_head
_KEY = runtime_owner_commands.journal_key
_BEGIN = _ENGINE.begin
_EXECUTE = _CONNECTION.exec_driver_sql
_CONTEXT = _GeneratorContextManager
_ENTER = _CONTEXT.__enter__
_EXIT = _CONTEXT.__exit__

type _HeadValues = tuple[str, int, str]
type _ReceiptValues = tuple[
    str, str, str, str, int, str, str, int, str, tuple[str, ...], tuple[str, ...]
]
type _Graph = tuple[
    LocalOperatorSecurity,
    SqlRuntimeOwnerCommands,
    Engine,
    LocalRuntimeOwnerAuthenticator,
    SqlDurableJournal,
    MappingProxyType[str, type[RuntimeOwnerCommandRecord]],
    SQLiteDialect_pysqlite,
]

_METHODS = (
    (_SECURITY, ("authenticate_with_expiry", "_decode")),
    (_AUTHENTICATOR, ("authenticate", "require_authenticated")),
    (_COMMANDS, ("prepare", "require_prepared", "append_in_transaction", "_require")),
    (_JOURNAL, ("read_head", "prepare_append", "append_in_transaction")),
    (_ENGINE, ("begin", "connect")),
    (
        _CONNECTION,
        (
            "begin",
            "begin_nested",
            "exec_driver_sql",
            "execute",
            "in_transaction",
            "commit",
            "rollback",
            "close",
            "__enter__",
            "__exit__",
        ),
    ),
)
_METHOD_PINS = tuple(
    (owner, name, vars(owner)[name]) for owner, names in _METHODS for name in names
)
_RECORD_PINS = tuple(
    (record, name, vars(record)[name])
    for record in (
        _DESCRIPTOR,
        _COMMAND,
        _HEAD,
        _RECEIPT,
        _RECORD,
        ContinuousAccountScope,
        ReconciliationHeads,
        ObjectRef,
        ContinuousEvidenceRef,
        journal_values.JournalKey,
    )
    for name in ("__init__", "__post_init__")
)
_REFERENCES = (
    (backtest_views, "LocalOperatorSecurity", _SECURITY),
    (runtime_owner_authentication, "LocalRuntimeOwnerAuthenticator", _AUTHENTICATOR),
    (runtime_owner_authentication, "LocalOperatorSecurity", _SECURITY),
    (runtime_owner_commands, "SqlRuntimeOwnerCommands", _COMMANDS),
    (runtime_owner_commands, "RuntimeOwnerCommandRecord", _RECORD),
    (runtime_owner_commands, "journal_key", _KEY),
    (durable_journal, "SqlDurableJournal", _JOURNAL),
    (daily_runtime_risk, "RuntimeAssignmentCommand", _COMMAND),
    (runtime_owner_authentication, "RuntimeAssignmentCommand", _COMMAND),
    (runtime_owner_commands, "RuntimeAssignmentCommand", _COMMAND),
    (descriptors, "InitialSelectionDescriptor", _DESCRIPTOR),
    (descriptors, "_descriptor_values", _D_VALUES),
    (descriptors, "_from_values", _D_FROM),
    (descriptors, "initial_selection_request_data", _D_DATA),
    (descriptors, "_validated_values", descriptors._validated_values),
    (descriptors, "journal_identifier", journal_values.journal_identifier),
    (descriptors, "require_digest", require_digest),
    (descriptors, "ContinuousAccountScope", ContinuousAccountScope),
    (descriptors, "ReconciliationHeads", ReconciliationHeads),
    (descriptors, "ObjectRef", ObjectRef),
    (descriptors, "ContinuousEvidenceRef", ContinuousEvidenceRef),
    (journal_values, "journal_identifier", journal_values.journal_identifier),
    (journal_values, "JournalHead", _HEAD),
    (journal_values, "JournalReceipt", _RECEIPT),
    (journal_values, "require_digest", require_digest),
    (daily_runtime_risk, "require_identifier", require_identifier),
    (personal_codec, "encode_record", personal_codec.encode_record),
    (personal_codec, "decode_record", personal_codec.decode_record),
)
_SEMANTIC = vars(ContractRecord)["semantic_sha256"]


def _bindings() -> None:
    if (
        datetime is not _DATETIME
        or LocalOperatorSecurity is not _SECURITY
        or LocalRuntimeOwnerAuthenticator is not _AUTHENTICATOR
        or SqlRuntimeOwnerCommands is not _COMMANDS
        or Engine is not _ENGINE
        or Connection is not _CONNECTION
        or personal_codec is not _CODEC
        or vars(ContractRecord).get("semantic_sha256") is not _SEMANTIC
        or vars(_CONTEXT).get("__enter__") is not _ENTER
        or vars(_CONTEXT).get("__exit__") is not _EXIT
    ):
        raise ValueError(_CHANGED)
    for constant_value, constant_expected in (
        (runtime_owner_commands.OWNER_COMMAND_SCHEMA, "runtime-owner-command/1"),
        (personal_codec.CODEC_VERSION, "personal-record/1"),
        (journal_values.MAX_RECORD_BYTES, 256 * 1024),
        (journal_values.MAX_APPEND_BYTES, 1024 * 1024),
        (journal_values.MAX_APPEND_RECORDS, 64),
        (journal_values.MAX_SEQUENCE, 2**63 - 1),
    ):
        if (
            type(constant_value) is not type(constant_expected)
            or constant_value != constant_expected
        ):
            raise ValueError(_CHANGED)
    for owner, name, expected in (*_METHOD_PINS, *_RECORD_PINS):
        if vars(owner).get(name) is not expected:
            raise ValueError(_CHANGED)
    for module, name, expected in _REFERENCES:
        if vars(module).get(name) is not expected:
            raise ValueError(_CHANGED)
    for name, expected in _HELPERS:
        if globals().get(name) is not expected:
            raise ValueError(_CHANGED)
    for name, expected in _DISPATCH_PINS:
        if globals().get(name) is not expected:
            raise ValueError(_CHANGED)


def _instance_bindings(value: object, expected: type[object]) -> None:
    if type(value) is not expected:
        raise ValueError(_CHANGED)
    # Security is slotted; the other admitted original owners have native dicts.
    attributes = {} if expected is _SECURITY else vars(value)
    for owner, name, _ in _METHOD_PINS:
        if owner is expected and name in attributes:
            raise ValueError(_CHANGED)


def _graph(
    security: LocalOperatorSecurity, commands: SqlRuntimeOwnerCommands, engine: Engine
) -> _Graph:
    if _BINDINGS is not _bindings:
        raise ValueError(_CHANGED)
    _BINDINGS()
    if (
        type(security) is not _SECURITY
        or type(commands) is not _COMMANDS
        or type(engine) is not _ENGINE
    ):
        raise ValueError(_INVALID)
    authenticator, journal = commands.authenticator, commands.journal
    if (
        type(authenticator) is not LocalRuntimeOwnerAuthenticator
        or type(journal) is not SqlDurableJournal
    ):
        raise ValueError(_CHANGED)
    registry, dialect = journal._types, engine.dialect
    if type(registry) is not MappingProxyType or type(dialect) is not SQLiteDialect_pysqlite:
        raise ValueError(_CHANGED)
    result = (security, commands, engine, authenticator, journal, registry, dialect)
    _REQUIRE_GRAPH(result)
    return result


def _require_graph(graph: _Graph) -> None:
    if _BINDINGS is not _bindings:
        raise ValueError(_CHANGED)
    _BINDINGS()
    security, commands, engine, authenticator, journal, registry, dialect = graph
    for value, expected in (
        (security, _SECURITY),
        (commands, _COMMANDS),
        (engine, _ENGINE),
        (authenticator, _AUTHENTICATOR),
        (journal, _JOURNAL),
    ):
        _INSTANCE_BINDINGS(value, expected)
    if (
        commands.engine is not engine
        or commands.authenticator is not authenticator
        or commands.journal is not journal
        or commands.codec is not _CODEC
        or authenticator.security is not security
        or journal._engine is not engine
        or journal._codec is not _CODEC
        or journal._types is not registry
        or engine.dialect is not dialect
        or engine._connection_cls is not _CONNECTION
        or type(dialect.name) is not str
        or dialect.name != "sqlite"
        or len(registry) != 1
    ):
        raise ValueError(_CHANGED)
    for schema, record in registry.items():
        if type(schema) is not str or schema != "runtime-owner-command/1" or record is not _RECORD:
            raise ValueError(_CHANGED)


def _connection_bindings(connection: object, graph: _Graph) -> Connection:
    _REQUIRE_GRAPH(graph)
    if type(connection) is not Connection:
        raise ValueError(_CHANGED)
    _INSTANCE_BINDINGS(connection, _CONNECTION)
    if connection.engine is not graph[2] or connection.dialect is not graph[6]:
        raise ValueError(_CHANGED)
    return connection


def _identifier(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= 128:
        raise ValueError(_INVALID)
    try:
        journal_values.journal_identifier(value)
    except ValueError:
        raise ValueError(_INVALID) from None
    return value


def _digest(value: object) -> str:
    if type(value) is not str or len(value) != 64:
        raise ValueError(_INVALID)
    try:
        require_digest(value, "request locator digest")
    except ValueError:
        raise ValueError(_INVALID) from None
    return value


def _utc(value: object) -> datetime:
    if type(value) is not _DATETIME or type(value) is not datetime or value.tzinfo is not UTC:
        raise ValueError(_INVALID)
    return value


def _head_values(value: object) -> _HeadValues:
    if type(value) is not _HEAD or type(value) is not journal_values.JournalHead:
        raise ValueError(_INVALID)
    return _NATIVE_HEAD_VALUES((value.key_sha256, value.sequence, value.entry_sha256))


def _native_head_values(value: object) -> _HeadValues:
    if (
        type(value) is not tuple
        or len(value) != 3
        or type(value[0]) is not str
        or type(value[1]) is not int
        or type(value[2]) is not str
        or not 0 <= value[1] <= 2**63 - 1
    ):
        raise ValueError(_INVALID)
    return _DIGEST(value[0]), value[1], _DIGEST(value[2])


def _head_from_values(values: _HeadValues) -> journal_values.JournalHead:
    if _BINDINGS is not _bindings:
        raise ValueError(_CHANGED)
    _BINDINGS()
    values = _NATIVE_HEAD_VALUES(values)
    try:
        return _HEAD(*values)
    except ValueError:
        raise ValueError(_INVALID) from None


def _receipt_values(value: object) -> _ReceiptValues:
    if type(value) is not _RECEIPT or type(value) is not journal_values.JournalReceipt:
        raise ValueError(_INVALID)
    previous, committed = _HEAD_VALUES(value.previous_head), _HEAD_VALUES(value.committed_head)
    return _NATIVE_RECEIPT_VALUES(
        (
            value.command_id,
            value.command_sha256,
            value.append_sha256,
            *previous,
            *committed,
            value.record_ids,
            value.record_hashes,
        )
    )


def _native_receipt_values(value: object) -> _ReceiptValues:
    if type(value) is not tuple or len(value) != 11:
        raise ValueError(_INVALID)
    if (
        any(type(value[index]) is not str for index in (0, 1, 2, 3, 5, 6, 8))
        or type(value[4]) is not int
        or type(value[7]) is not int
        or type(value[9]) is not tuple
        or type(value[10]) is not tuple
        or not 1 <= len(value[9]) <= 64
        or not 1 <= len(value[10]) <= 64
        or any(type(item) is not str for item in (*value[9], *value[10]))
    ):
        raise ValueError(_INVALID)
    # Admit every bounded native leaf before any constructor or hashing.
    _IDENTIFIER(value[0])
    _DIGEST(value[1])
    _DIGEST(value[2])
    _NATIVE_HEAD_VALUES((value[3], value[4], value[5]))
    _NATIVE_HEAD_VALUES((value[6], value[7], value[8]))
    for identifier in value[9]:
        _IDENTIFIER(identifier)
    for digest in value[10]:
        _DIGEST(digest)
    return (
        value[0],
        value[1],
        value[2],
        value[3],
        value[4],
        value[5],
        value[6],
        value[7],
        value[8],
        tuple(item for item in value[9]),
        tuple(item for item in value[10]),
    )


def _receipt_from_values(values: _ReceiptValues) -> journal_values.JournalReceipt:
    if _BINDINGS is not _bindings:
        raise ValueError(_CHANGED)
    _BINDINGS()
    values = _NATIVE_RECEIPT_VALUES(values)
    previous = _HEAD_FROM_VALUES((values[3], values[4], values[5]))
    committed = _HEAD_FROM_VALUES((values[6], values[7], values[8]))
    try:
        return _RECEIPT(
            values[0],
            values[1],
            values[2],
            previous,
            committed,
            tuple(item for item in values[9]),
            tuple(item for item in values[10]),
        )
    except ValueError:
        raise ValueError(_INVALID) from None


def _retain_initial_selection_request(
    *,
    security: LocalOperatorSecurity,
    commands: SqlRuntimeOwnerCommands,
    engine: Engine,
    account_id: str,
    descriptor: InitialSelectionDescriptor,
    command_id: str,
    session_cookie: str | None,
    csrf_token: str,
) -> journal_values.JournalReceipt:
    if _BINDINGS is not _bindings:
        raise ValueError(_CHANGED)
    bindings = _BINDINGS
    bindings()
    graph_factory = _GRAPH
    require_graph = _REQUIRE_GRAPH
    connection_bindings = _CONNECTION_BINDINGS
    identify = _IDENTIFIER
    utc_value = _UTC
    descriptor_values = _D_VALUES
    descriptor_from_values = _D_FROM
    request_data = _D_DATA
    authenticate = _AUTHENTICATE
    authenticate_command = _AUTH_COMMAND
    require_authenticated = _AUTH_REQUIRE
    journal_key = _KEY
    read_head = _READ_HEAD
    head_from_values = _HEAD_FROM_VALUES
    head_values = _HEAD_VALUES
    prepare = _PREPARE
    require_prepared = _REQUIRE
    append_request = _APPEND
    receipt_values = _RECEIPT_VALUES
    receipt_from_values = _RECEIPT_FROM_VALUES
    command_type = _COMMAND
    begin = _BEGIN
    enter_context = _ENTER
    exit_context = _EXIT
    execute = _EXECUTE
    clock = _DATETIME
    timespan = timedelta
    utc_timezone = UTC
    context_type = _CONTEXT
    prepared_type = PreparedRuntimeOwnerCommand
    bindings()
    account_id, command_id = identify(account_id), identify(command_id)
    if (
        (
            session_cookie is not None
            and (type(session_cookie) is not str or len(session_cookie) > 2048)
        )
        or type(csrf_token) is not str
        or len(csrf_token) > 128
    ):
        raise ValueError(_INVALID)
    graph = graph_factory(security, commands, engine)
    values = descriptor_values(descriptor)
    if values[0] != account_id:
        raise ValueError(_INVALID)
    copied = descriptor_from_values(values)
    scope, heads, reference = request_data(copied)
    require_graph(graph)
    at = utc_value(clock.now(utc_timezone))
    if not values[16] <= at < values[17]:
        raise ValueError(_INVALID)
    session = authenticate(security, session_cookie, csrf_token, now=at)
    require_graph(graph)
    if type(session) is not tuple or len(session) != 2:
        raise ValueError(_INVALID)
    operator_id, session_expires_at = identify(session[0]), utc_value(session[1])
    expires_at = min(at + timespan(seconds=60), session_expires_at, values[17])
    if not at < expires_at:
        raise ValueError(_INVALID)
    command = command_type(
        command_id=command_id,
        owner_id=operator_id,
        account_id=account_id,
        before_assignment_sha256=None,
        after_assignment_sha256=values[3],
        expected_heads=heads,
        quiescence_sha256=values[15],
        requested_at=at,
        expires_at=expires_at,
    )
    require_graph(graph)
    authenticated = authenticate_command(
        graph[3],
        command,
        session_cookie=session_cookie,
        csrf_token=csrf_token,
        now=at,
    )
    require_graph(graph)
    require_authenticated(graph[3], authenticated)
    require_graph(graph)
    key = journal_key(scope)
    head = read_head(graph[4], key)
    require_graph(graph)
    expected_head = head_from_values(head_values(head))
    require_graph(graph)
    prepared = prepare(
        commands,
        scope,
        command=command,
        authenticated=authenticated,
        dependencies=reference,
        expected_head=expected_head,
    )
    require_graph(graph)
    require_prepared(commands, prepared)
    require_graph(graph)
    if (
        type(prepared) is not prepared_type
        or prepared.authenticated is not authenticated
        or prepared.record.command is not command
    ):
        raise ValueError(_INVALID)
    expected = receipt_values(prepared.append.receipt)
    receipt_from_values(expected)
    if (
        expected[0] != command_id
        or expected[1] != command.semantic_sha256
        or expected[9] != (command_id,)
    ):
        raise ValueError(_INVALID)
    before_sql = utc_value(clock.now(utc_timezone))
    if before_sql < at or before_sql >= expires_at:
        raise ValueError(_INVALID)
    require_graph(graph)
    context = begin(engine)
    if type(context) is not context_type:
        raise ValueError(_CHANGED)
    # Retain the original context lifetime. Later guard denial unwinds it once;
    # no manual rollback/close, restoration, disposal or cleanup retry is added.
    # Indirect SQLAlchemy callback mutation is not arbitrary-process attestation.
    require_graph(graph)
    connection = enter_context(context)
    try:
        connection = connection_bindings(connection, graph)
        execute(connection, "BEGIN IMMEDIATE")
        connection_bindings(connection, graph)
        receipt = append_request(commands, connection, prepared)
        connection_bindings(connection, graph)
    except BaseException as error:
        exit_context(context, type(error), error, error.__traceback__)
        raise
    else:
        exit_context(context, None, None, None)
    # No receipt copy/hash/authentication runs inside the write transaction.
    require_graph(graph)
    returned = receipt_values(receipt)
    if returned != expected:
        raise ValueError(_INVALID)
    result = receipt_from_values(returned)
    require_graph(graph)
    return result


_BINDINGS = _bindings
_INSTANCE_BINDINGS = _instance_bindings
_GRAPH = _graph
_REQUIRE_GRAPH = _require_graph
_CONNECTION_BINDINGS = _connection_bindings
_IDENTIFIER = _identifier
_DIGEST = _digest
_UTC = _utc
_HEAD_VALUES = _head_values
_NATIVE_HEAD_VALUES = _native_head_values
_HEAD_FROM_VALUES = _head_from_values
_RECEIPT_VALUES = _receipt_values
_NATIVE_RECEIPT_VALUES = _native_receipt_values
_RECEIPT_FROM_VALUES = _receipt_from_values
_HELPERS = tuple(
    (name, value)
    for name, value in (
        ("_bindings", _BINDINGS),
        ("_instance_bindings", _INSTANCE_BINDINGS),
        ("_graph", _GRAPH),
        ("_require_graph", _REQUIRE_GRAPH),
        ("_connection_bindings", _CONNECTION_BINDINGS),
        ("_identifier", _IDENTIFIER),
        ("_digest", _DIGEST),
        ("_native_head_values", _NATIVE_HEAD_VALUES),
        ("_utc", _UTC),
        ("_head_values", _HEAD_VALUES),
        ("_head_from_values", _HEAD_FROM_VALUES),
        ("_receipt_values", _RECEIPT_VALUES),
        ("_native_receipt_values", _NATIVE_RECEIPT_VALUES),
        ("_receipt_from_values", _RECEIPT_FROM_VALUES),
        ("_retain_initial_selection_request", _retain_initial_selection_request),
    )
)

_DISPATCH_PINS = tuple(
    (name, globals()[name])
    for name in (
        "_BINDINGS",
        "_INSTANCE_BINDINGS",
        "_GRAPH",
        "_REQUIRE_GRAPH",
        "_CONNECTION_BINDINGS",
        "_IDENTIFIER",
        "_DIGEST",
        "_UTC",
        "_HEAD_VALUES",
        "_NATIVE_HEAD_VALUES",
        "_HEAD_FROM_VALUES",
        "_RECEIPT_VALUES",
        "_NATIVE_RECEIPT_VALUES",
        "_RECEIPT_FROM_VALUES",
        "_D_VALUES",
        "_D_FROM",
        "_D_DATA",
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
        "_COMMAND",
        "_HEAD",
        "_RECEIPT",
        "_RECORD",
        "_DESCRIPTOR",
        "SQLiteDialect_pysqlite",
        "PreparedRuntimeOwnerCommand",
        "require_digest",
        "_DATETIME",
        "datetime",
        "UTC",
        "timedelta",
        "_CONTEXT",
    )
)
