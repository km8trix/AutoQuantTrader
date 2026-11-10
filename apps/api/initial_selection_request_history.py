"""Resolve one captured original REQUEST, never renew or consume its authority.

Current shared authentication gates admission and delivery. Historical command
times stay unchanged; missing and returned locators describe only the original
read snapshot. The caller retains all Engine and owner lifecycle responsibility.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Engine

from apps.api import initial_selection_request_retention as retention
from apps.api.backtest_views import LocalOperatorSecurity
from apps.trader.initial_selection_descriptor import InitialSelectionDescriptor
from packages.domain.continuous_persistence_contracts import (
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.durable_journal_contracts import JournalReceipt, empty_head
from packages.domain.personal_contracts import content_digest
from packages.domain.reconciliation_contracts import ReconciliationHeads
from packages.domain.research_job_contracts import ObjectRef
from packages.domain.runtime_owner_contracts import RuntimeOwnerAuthentication
from packages.persistence import (
    daily_runtime_risk,
    database,
    detached_journal_capture,
    durable_journal,
    runtime_owner_commands,
)
from packages.persistence.daily_runtime_risk import RuntimeAssignmentCommand, RuntimeReadBudget
from packages.persistence.detached_journal_capture import DetachedJournalCapture
from packages.persistence.durable_journal import (
    JournalReadSnapshot,
    ResolvedJournalRead,
    SqlDurableJournal,
)
from packages.persistence.runtime_owner_commands import (
    ResolvedRuntimeOwnerCommand,
    RuntimeOwnerCommandRecord,
    RuntimeOwnerCommandSnapshot,
    SqlRuntimeOwnerCommands,
)

_INVALID = "INITIAL_SELECTION_REQUEST_HISTORY_INVALID"
_CHANGED = "INITIAL_SELECTION_REQUEST_HISTORY_BINDING_CHANGED"
_DIFFERS = "INITIAL_SELECTION_REQUEST_HISTORY_DIFFERS"
_DATETIME = datetime
_I_BINDINGS = retention._BINDINGS
_GRAPH = retention._GRAPH
_I_REQUIRE_GRAPH = retention._REQUIRE_GRAPH
_IDENTIFIER = retention._IDENTIFIER
_UTC = retention._UTC
_D_VALUES = retention._D_VALUES
_D_FROM = retention._D_FROM
_D_DATA = retention._D_DATA
_AUTHENTICATE = retention._AUTHENTICATE
_RECEIPT_VALUES = retention._RECEIPT_VALUES
_RECEIPT_FROM_VALUES = retention._RECEIPT_FROM_VALUES
_READ = SqlRuntimeOwnerCommands.read
_REQUIRE_RESOLVED = SqlRuntimeOwnerCommands.require_resolved
_READ_TRANSACTION = database._repeatable_read_transaction
_BUDGET = RuntimeReadBudget
_RESOLVED = ResolvedRuntimeOwnerCommand
_RECORD = RuntimeOwnerCommandRecord
_COMMAND = RuntimeAssignmentCommand
_AUTHENTICATION = RuntimeOwnerAuthentication
_SCOPE_VALIDATE = ContinuousAccountScope.__post_init__
_HEADS_VALIDATE = ReconciliationHeads.__post_init__
_OBJECT_VALIDATE = ObjectRef.__post_init__
_REFERENCE_VALIDATE = ContinuousEvidenceRef.__post_init__
_COMMAND_VALIDATE = RuntimeAssignmentCommand.__post_init__
_AUTHENTICATION_VALIDATE = RuntimeOwnerAuthentication.__post_init__
_RECORD_VALIDATE = RuntimeOwnerCommandRecord.__post_init__

# Extend I's original graph gates, without modifying or invoking its write path.
# The original read owns connection/transaction entry and unwind. These finite
# guards do not attest arbitrary mutation inside indirect SQLAlchemy callbacks.
_METHODS = (
    (
        SqlRuntimeOwnerCommands,
        (
            "read",
            "capture_in_transaction",
            "resolve_snapshot",
            "require_resolved",
            "_own",
            "_require",
            "_fingerprint",
            "_remember",
        ),
    ),
    (
        SqlDurableJournal,
        (
            "capture_in_transaction",
            "resolve_snapshot",
            "_read_connection",
            "_validate_stream",
            "_key_payload",
            "_receipt",
            "_decode_entry",
            "_validate_record",
        ),
    ),
    (RuntimeReadBudget, ("__init__", "charge")),
    (DetachedJournalCapture, ("__init__", "capture", "row")),
)
_METHOD_PINS = tuple(
    (owner, name, vars(owner)[name]) for owner, names in _METHODS for name in names
)
_RECORD_PINS = tuple(
    (owner, name, vars(owner)[name])
    for owner, names in (
        (ResolvedRuntimeOwnerCommand, ("__init__",)),
        (RuntimeOwnerCommandSnapshot, ("__init__",)),
        (ResolvedJournalRead, ("__init__",)),
        (JournalReadSnapshot, ("__init__",)),
        (RuntimeOwnerAuthentication, ("__init__", "__post_init__")),
        (ContinuousAccountScope, ("__eq__",)),
        (ReconciliationHeads, ("__eq__",)),
        (ContinuousEvidenceRef, ("__eq__",)),
        (ObjectRef, ("__eq__",)),
    )
    for name in names
)
_VALIDATORS = (
    (ContinuousAccountScope, _SCOPE_VALIDATE),
    (ReconciliationHeads, _HEADS_VALIDATE),
    (ObjectRef, _OBJECT_VALIDATE),
    (ContinuousEvidenceRef, _REFERENCE_VALIDATE),
    (RuntimeAssignmentCommand, _COMMAND_VALIDATE),
    (RuntimeOwnerAuthentication, _AUTHENTICATION_VALIDATE),
    (RuntimeOwnerCommandRecord, _RECORD_VALIDATE),
)
_REFERENCES = (
    (retention, "_BINDINGS", _I_BINDINGS),
    (retention, "_GRAPH", _GRAPH),
    (retention, "_REQUIRE_GRAPH", _I_REQUIRE_GRAPH),
    (retention, "_IDENTIFIER", _IDENTIFIER),
    (retention, "_UTC", _UTC),
    (retention, "_D_VALUES", _D_VALUES),
    (retention, "_D_FROM", _D_FROM),
    (retention, "_D_DATA", _D_DATA),
    (retention, "_AUTHENTICATE", _AUTHENTICATE),
    (retention, "_RECEIPT_VALUES", _RECEIPT_VALUES),
    (retention, "_RECEIPT_FROM_VALUES", _RECEIPT_FROM_VALUES),
    (runtime_owner_commands, "RuntimeReadBudget", _BUDGET),
    (daily_runtime_risk, "RuntimeReadBudget", _BUDGET),
    (runtime_owner_commands, "ResolvedRuntimeOwnerCommand", _RESOLVED),
    (runtime_owner_commands, "RuntimeOwnerAuthentication", _AUTHENTICATION),
    (runtime_owner_commands, "RuntimeOwnerCommandSnapshot", RuntimeOwnerCommandSnapshot),
    (runtime_owner_commands, "DetachedJournalCapture", DetachedJournalCapture),
    (detached_journal_capture, "DetachedJournalCapture", DetachedJournalCapture),
    (
        runtime_owner_commands,
        "detached_journal_value",
        detached_journal_capture.detached_journal_value,
    ),
    (runtime_owner_commands, "content_digest", content_digest),
    (runtime_owner_commands, "_identity_graph", runtime_owner_commands._identity_graph),
    (runtime_owner_commands, "_repeatable_read_transaction", _READ_TRANSACTION),
    (database, "_repeatable_read_transaction", _READ_TRANSACTION),
    (durable_journal, "JournalReadSnapshot", JournalReadSnapshot),
    (durable_journal, "ResolvedJournalRead", ResolvedJournalRead),
    (detached_journal_capture, "JournalReadSnapshot", JournalReadSnapshot),
    (durable_journal, "_stream_row", durable_journal._stream_row),
    (durable_journal, "_entry_row", durable_journal._entry_row),
    (durable_journal, "_capture_receipt", durable_journal._capture_receipt),
    (durable_journal, "_has_records", durable_journal._has_records),
    (durable_journal, "_validate_row", durable_journal._validate_row),
    (durable_journal, "empty_head", empty_head),
)


def _bindings() -> None:
    if _I_BINDINGS is not retention._BINDINGS:
        raise ValueError(_CHANGED)
    _I_BINDINGS()
    for owner, name, expected in (*_METHOD_PINS, *_RECORD_PINS):
        if vars(owner).get(name) is not expected:
            raise ValueError(_CHANGED)
    for validator_owner, validator_expected in _VALIDATORS:
        if vars(validator_owner).get("__post_init__") is not validator_expected:
            raise ValueError(_CHANGED)
    for module, name, expected in _REFERENCES:
        if vars(module).get(name) is not expected:
            raise ValueError(_CHANGED)
    for actual, expected in (
        (
            runtime_owner_commands.MAX_OWNER_SNAPSHOT_BYTES,
            256 * 1024 + 1024 * 1024 + 2 * 256 * 1024 + 16 * 1024,
        ),
        (runtime_owner_commands.MAX_OWNER_METADATA_BYTES, 2 * 1024 * 1024),
        (vars(runtime_owner_commands).get("MAX_RECORD_BYTES"), 256 * 1024),
        (vars(runtime_owner_commands).get("MAX_APPEND_BYTES"), 1024 * 1024),
        (vars(durable_journal).get("MAX_RECORD_BYTES"), 256 * 1024),
        (vars(durable_journal).get("MAX_APPEND_RECORDS"), 64),
        (vars(durable_journal).get("MAX_SEQUENCE"), 2**63 - 1),
        (durable_journal._MAX_KEY_BYTES, 16 * 1024),
        (daily_runtime_risk.MAX_ROWS, 4096),
        (daily_runtime_risk.MAX_TOTAL_ROWS, 16384),
        (daily_runtime_risk.MAX_TOTAL_BYTES, 32 * 1024 * 1024),
        (daily_runtime_risk.MAX_METADATA_BYTES, 2 * 1024 * 1024),
    ):
        if type(actual) is not int or actual != expected:
            raise ValueError(_CHANGED)
    for name, expected in (*_HELPERS, *_DISPATCH_PINS):
        if globals().get(name) is not expected:
            raise ValueError(_CHANGED)


def _require_graph(graph: retention._Graph) -> None:
    if _BINDINGS is not _bindings:
        raise ValueError(_CHANGED)
    _BINDINGS()
    _I_REQUIRE_GRAPH(graph)
    for value in (graph[1], graph[4]):
        attributes = vars(value)
        for owner, name, _ in _METHOD_PINS:
            if type(value) is owner and name in attributes:
                raise ValueError(_CHANGED)


def _session(
    security: LocalOperatorSecurity,
    session_cookie: str | None,
    csrf_token: str,
    at: datetime,
) -> tuple[str, datetime]:
    value = _AUTHENTICATE(security, session_cookie, csrf_token, now=at)
    if type(value) is not tuple or len(value) != 2:
        raise ValueError(_INVALID)
    operator, expiry = _IDENTIFIER(value[0]), _UTC(value[1])
    if expiry <= at:
        raise ValueError(_INVALID)
    return operator, expiry


def _matched_receipt(
    resolved: ResolvedRuntimeOwnerCommand,
    scope: ContinuousAccountScope,
    heads: ReconciliationHeads,
    reference: ContinuousEvidenceRef,
    account_id: str,
    command_id: str,
    proposal_sha256: str,
) -> JournalReceipt:
    # Admit original nested classes before validators, equality or content hashes.
    if type(resolved) is not _RESOLVED:
        raise ValueError(_INVALID)
    record, read = resolved.record, resolved.read
    if type(record) is not _RECORD or type(read) is not ResolvedJournalRead:
        raise ValueError(_INVALID)
    command, authentication, dependencies = (
        record.command,
        record.authentication,
        record.dependencies,
    )
    if (
        type(record.scope) is not ContinuousAccountScope
        or type(command) is not _COMMAND
        or type(authentication) is not _AUTHENTICATION
        or type(dependencies) is not ContinuousEvidenceRef
    ):
        raise ValueError(_INVALID)
    if (
        type(command.expected_heads) is not ReconciliationHeads
        or type(dependencies.object_ref) is not ObjectRef
    ):
        raise ValueError(_INVALID)
    _SCOPE_VALIDATE(record.scope)
    _HEADS_VALIDATE(command.expected_heads)
    _OBJECT_VALIDATE(dependencies.object_ref)
    _REFERENCE_VALIDATE(dependencies)
    _COMMAND_VALIDATE(command)
    _AUTHENTICATION_VALIDATE(authentication)
    _RECORD_VALIDATE(record)
    if (
        record.scope != scope
        or command.account_id != account_id
        or command.command_id != command_id
        or command.before_assignment_sha256 is not None
        or command.after_assignment_sha256 != proposal_sha256
        or command.expected_heads != heads
        or command.quiescence_sha256 != reference.semantic_sha256
        or dependencies != reference
        or command.runtime_environment != "stateful_simulation"
    ):
        raise ValueError(_DIFFERS)
    values = _RECEIPT_VALUES(read.receipt)
    if (
        values[0] != command_id
        or values[1] != command.semantic_sha256
        or values[9] != (command_id,)
    ):
        raise ValueError(_DIFFERS)
    return _RECEIPT_FROM_VALUES(values)


def _read_initial_selection_request(
    *,
    security: LocalOperatorSecurity,
    commands: SqlRuntimeOwnerCommands,
    engine: Engine,
    account_id: str,
    descriptor: InitialSelectionDescriptor,
    command_id: str,
    session_cookie: str | None,
    csrf_token: str,
) -> JournalReceipt | None:
    if _BINDINGS is not _bindings:
        raise ValueError(_CHANGED)
    _BINDINGS()
    require_graph, graph_factory = _REQUIRE_GRAPH, _GRAPH
    identify, utc_value = _IDENTIFIER, _UTC
    descriptor_values, descriptor_from_values, request_data = _D_VALUES, _D_FROM, _D_DATA
    session, read, require_resolved = _SESSION, _READ, _REQUIRE_RESOLVED
    project, budget_type, resolved_type = _MATCHED_RECEIPT, _BUDGET, _RESOLVED
    clock, utc_timezone = _DATETIME, UTC
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
    require_graph(graph)
    values = descriptor_values(descriptor)
    if values[0] != account_id:
        raise ValueError(_INVALID)
    scope, heads, reference = request_data(descriptor_from_values(values))
    require_graph(graph)
    at = utc_value(clock.now(utc_timezone))
    admitted_session = session(security, session_cookie, csrf_token, at)
    require_graph(graph)
    budget = budget_type()
    require_graph(graph)
    # No custom limit or historical validity/current-readiness gate is added.
    resolved = read(commands, scope, command_id=command_id, budget=budget)
    require_graph(graph)
    result = None
    if resolved is not None:
        if type(resolved) is not resolved_type:
            raise ValueError(_INVALID)
        require_resolved(commands, resolved)
        require_graph(graph)
        result = project(resolved, scope, heads, reference, account_id, command_id, values[3])
        require_graph(graph)
        require_resolved(commands, resolved)
        require_graph(graph)
    delivered_at = utc_value(clock.now(utc_timezone))
    if delivered_at < at:
        raise ValueError(_INVALID)
    delivered_session = session(security, session_cookie, csrf_token, delivered_at)
    require_graph(graph)
    if delivered_session != admitted_session:
        raise ValueError(_INVALID)
    return result


_BINDINGS = _bindings
_REQUIRE_GRAPH = _require_graph
_SESSION = _session
_MATCHED_RECEIPT = _matched_receipt
_HELPERS = (
    ("_bindings", _BINDINGS),
    ("_require_graph", _REQUIRE_GRAPH),
    ("_session", _SESSION),
    ("_matched_receipt", _MATCHED_RECEIPT),
    ("_read_initial_selection_request", _read_initial_selection_request),
)
_DISPATCH_PINS = tuple(
    (name, globals()[name])
    for name in (
        "_BINDINGS",
        "_REQUIRE_GRAPH",
        "_SESSION",
        "_MATCHED_RECEIPT",
        "_I_BINDINGS",
        "_GRAPH",
        "_I_REQUIRE_GRAPH",
        "_IDENTIFIER",
        "_UTC",
        "_D_VALUES",
        "_D_FROM",
        "_D_DATA",
        "_AUTHENTICATE",
        "_RECEIPT_VALUES",
        "_RECEIPT_FROM_VALUES",
        "_READ",
        "_REQUIRE_RESOLVED",
        "_READ_TRANSACTION",
        "_BUDGET",
        "_RESOLVED",
        "_RECORD",
        "_COMMAND",
        "_AUTHENTICATION",
        "_DATETIME",
        "datetime",
        "UTC",
        "LocalOperatorSecurity",
        "SqlRuntimeOwnerCommands",
        "Engine",
        "InitialSelectionDescriptor",
        "JournalReceipt",
        "RuntimeReadBudget",
        "ResolvedRuntimeOwnerCommand",
        "ResolvedJournalRead",
        "ContinuousAccountScope",
        "ReconciliationHeads",
        "ContinuousEvidenceRef",
        "ObjectRef",
        "_VALIDATORS",
        "_SCOPE_VALIDATE",
        "_HEADS_VALIDATE",
        "_OBJECT_VALIDATE",
        "_REFERENCE_VALIDATE",
        "_COMMAND_VALIDATE",
        "_AUTHENTICATION_VALIDATE",
        "_RECORD_VALIDATE",
    )
)
