"""Declared operator-statement journal bindings, never publication authority.

Keys, account fields and nonzero heads are unverified data. Actual ownership,
evidence, account/control currentness and final-write admission stay separate.
"""

from packages.application import personal_codec
from packages.domain.continuous_persistence_contracts import ContinuousAccountScope
from packages.domain.durable_journal_contracts import (
    MAX_SEQUENCE,
    JournalAppend,
    JournalHead,
    JournalKey,
    JournalRecord,
    empty_head,
)
from packages.domain.operational_control_operator_record import (
    OPERATOR_STATEMENT_RECORD_SCHEMA,
    OperationalControlOperatorStatementRecord,
    copy_operational_control_operator_statement_record,
)

_ERROR = "OPERATOR_STATEMENT_JOURNAL_INVALID"
_STREAM_ID = "operational-control-operator-statements/1"
_PROVIDER = "local-operator-statement"


def _scope_fields_native(
    account: object, binding: object, deployment: object, environment: object
) -> bool:
    return (
        all(type(value) is str for value in (account, binding, deployment, environment))
        and environment == "stateful_simulation"
    )


def _append_fields_native(
    account: object,
    binding: object,
    deployment: object,
    environment: object,
    key_sha256: object,
    sequence: object,
    entry_sha256: object,
) -> bool:
    return (
        all(
            type(value) is str
            for value in (account, binding, deployment, environment, key_sha256, entry_sha256)
        )
        and type(sequence) is int
        and environment == "stateful_simulation"
    )


def _declared_key(scope: ContinuousAccountScope) -> JournalKey:
    return JournalKey(
        namespace="coordinator",
        stream_id=_STREAM_ID,
        account_scope=scope.account_id,
        source_provider=_PROVIDER,
        source_environment="synthetic",
        source_scope_sha256=scope.semantic_sha256,
    )


def operator_statement_journal_key(scope: ContinuousAccountScope) -> JournalKey:
    """Copy declared scope into a distinct-purpose key; authenticate no account."""
    if type(scope) is not ContinuousAccountScope:
        raise ValueError(_ERROR)
    values = (scope.account_id, scope.account_binding_sha256, scope.stream_id, scope.environment)
    if not _scope_fields_native(*values):
        raise ValueError(_ERROR)
    copied = ContinuousAccountScope(*values)
    return _declared_key(copied)


def operator_statement_journal_append(
    scope: ContinuousAccountScope,
    record: OperationalControlOperatorStatementRecord,
    *,
    expected_head: JournalHead,
) -> tuple[JournalKey, JournalAppend]:
    """Freeze declared bindings and canonical bytes, without preparing any SQL."""
    if type(scope) is not ContinuousAccountScope or type(expected_head) is not JournalHead:
        raise ValueError(_ERROR)
    scope_values = (
        scope.account_id,
        scope.account_binding_sha256,
        scope.stream_id,
        scope.environment,
    )
    head_values = (expected_head.key_sha256, expected_head.sequence, expected_head.entry_sha256)
    if not _append_fields_native(*scope_values, *head_values):
        raise ValueError(_ERROR)
    # Freeze G before original constructors/canonical helpers can run callbacks.
    copied_record = copy_operational_control_operator_statement_record(record)
    copied_scope = ContinuousAccountScope(*scope_values)
    copied_head = JournalHead(*head_values)
    if copied_record.statement.scope_id != copied_scope.account_id:
        raise ValueError(_ERROR)
    key = _declared_key(copied_scope)
    if copied_head.key_sha256 != key.semantic_sha256:
        raise ValueError(_ERROR)
    if copied_head.sequence == 0 and copied_head != empty_head(key):
        raise ValueError(_ERROR)
    if copied_head.sequence + 1 > MAX_SEQUENCE:
        raise ValueError("append exceeds journal sequence range")
    record_id = copied_record.record_id
    command_sha256 = copied_record.semantic_sha256
    payload = personal_codec.encode_record(copied_record)
    if type(payload) is not bytes:
        raise ValueError(_ERROR)
    journal_record = JournalRecord(record_id, OPERATOR_STATEMENT_RECORD_SCHEMA, payload)
    append = JournalAppend(record_id, command_sha256, copied_head, (journal_record,))
    return key, append
