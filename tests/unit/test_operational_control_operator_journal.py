"""Declared journal data bindings, without a database or publication authority."""

import builtins
import hashlib
import socket
import sqlite3
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path

import pytest

from packages.application import operational_control_operator_journal as binding
from packages.application import personal_codec as codec
from packages.domain.continuous_persistence_contracts import ContinuousAccountScope
from packages.domain.durable_journal_contracts import (
    MAX_RECORD_BYTES,
    MAX_SEQUENCE,
    JournalAppend,
    JournalHead,
    JournalKey,
    JournalRecord,
    empty_head,
)
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlBlockingEvent,
    OperationalControlIncidentDisposition,
    OperationalControlState,
)
from packages.domain.operational_control_operator_record import (
    OPERATOR_STATEMENT_RECORD_SCHEMA,
    OperationalControlOperatorStatementRecord,
    copy_operational_control_operator_statement_record,
)
from packages.domain.operational_control_operator_statement import (
    OperationalControlOperatorStatement,
)
from packages.domain.research_job_contracts import ObjectRef

_ACCOUNT = "journal-binding-account"
_BASE = datetime(2026, 10, 28, 14, tzinfo=UTC)
_SCOPE_SHA = "eeed6d5cc4744cc6b092e956e43eb78a2882965e764f4e150e5a4a2c0fb30d3a"
_KEY_SHA = "160a27aea0b28577e62f51a857c604529dea2c804ae80299a92e3b743e8ed306"
_EMPTY_SHA = "59b6307458cf0973d46b5462af42debc62f4ddf7340a380e460b372decc8495d"
_G_COPY_CODE = copy_operational_control_operator_statement_record.__code__
_ENCODE_CODE = codec.encode_record.__code__
_SCOPE_INIT_CODE = ContinuousAccountScope.__init__.__code__
_SCOPE_POST_CODE = ContinuousAccountScope.__post_init__.__code__
_HEAD_INIT_CODE = JournalHead.__init__.__code__
_HEAD_POST_CODE = JournalHead.__post_init__.__code__


def _scope(**changes):
    values = {
        "account_id": _ACCOUNT,
        "account_binding_sha256": "a" * 64,
        "stream_id": "journal-binding-deployment",
        "environment": "stateful_simulation",
    }
    values.update(changes)
    return ContinuousAccountScope(**values)


def _record(account=_ACCOUNT):
    event = OperationalControlBlockingEvent(
        scope_id=account,
        sequence_number=1,
        command_id="initialize-0001",
        command_sha256="a" * 64,
        state=OperationalControlState.HALTED,
        occurred_at=_BASE,
    )
    statement = OperationalControlOperatorStatement(
        scope_id=account,
        control_transition_id="control-head-1",
        control_transition_sha256="d" * 64,
        control_sequence_number=2,
        control_state=OperationalControlState.HALTED,
        control_state_epoch_id="control-epoch-1",
        blocking_event=event,
        actor=OperationalControlActor(
            actor_id="operator-1",
            kind=OperationalControlActorKind.HUMAN,
            authority_sha256="b" * 64,
            authenticated_at=_BASE + timedelta(seconds=2),
        ),
        resolution_claim=OperationalControlIncidentDisposition(
            event_id=event.event_id,
            event_sha256=event.semantic_sha256,
            resolution_code="reviewed",
            resolution_evidence_sha256="c" * 64,
            resolved_at=_BASE + timedelta(seconds=1),
        ),
        authentication_checked_at=_BASE + timedelta(seconds=2),
        attested_at=_BASE + timedelta(seconds=2),
        idempotency_key="statement-0001",
    )
    return OperationalControlOperatorStatementRecord(
        statement=statement,
        evidence=ObjectRef("c" * 64, 17),
        session_expires_at=_BASE + timedelta(hours=1),
    )


def _expected_key(scope):
    # Original values independently spell out the selected fixed key mapping.
    return JournalKey(
        namespace="coordinator",
        stream_id="operational-control-operator-statements/1",
        account_scope=scope.account_id,
        source_provider="local-operator-statement",
        source_environment="synthetic",
        source_scope_sha256=scope.semantic_sha256,
        runtime_environment="stateful_simulation",
    )


def _projection(value):
    if is_dataclass(value) and not isinstance(value, type):
        return type(value), tuple(
            (field.name, _projection(getattr(value, field.name))) for field in fields(value)
        )
    if type(value) is tuple:
        return tuple(_projection(item) for item in value)
    return value


def _append(scope, record, head):
    return binding.operator_statement_journal_append(scope, record, expected_head=head)


@contextmanager
def _observe(action=None, *, at=_G_COPY_CODE):
    monitor, tool = sys.monitoring, 3
    codes = (
        _G_COPY_CODE,
        _ENCODE_CODE,
        _SCOPE_INIT_CODE,
        _SCOPE_POST_CODE,
        _HEAD_INIT_CODE,
        _HEAD_POST_CODE,
    )
    entries, enabled, acted = [], [], []
    owned = registered = False

    def start(code, offset):
        entries.append(code)
        if action is not None and code is at and not acted:
            acted.append(True)
            action()

    try:
        assert monitor.get_tool(tool) is None and monitor.get_events(tool) == 0
        monitor.use_tool_id(tool, "aqt-operator-journal-unit")
        owned = True
        assert monitor.register_callback(tool, monitor.events.PY_START, start) is None
        registered = True
        for code in codes:
            assert monitor.get_local_events(tool, code) == 0
            monitor.set_local_events(tool, code, monitor.events.PY_START)
            enabled.append(code)
        yield entries
    finally:
        try:
            for code in enabled:
                monitor.set_local_events(tool, code, 0)
                assert monitor.get_local_events(tool, code) == 0
        finally:
            try:
                if registered:
                    monitor.register_callback(tool, monitor.events.PY_START, None)
            finally:
                if owned:
                    assert monitor.get_events(tool) == 0
                    monitor.free_tool_id(tool)
                    assert monitor.get_tool(tool) is None


def test_independent_key_empty_head_and_actual_g_bytes_pin_every_declared_binding():
    scope, record = _scope(), _record()
    expected_key = _expected_key(scope)
    head = empty_head(expected_key)
    assert scope.semantic_sha256 == _SCOPE_SHA
    assert expected_key.semantic_sha256 == _KEY_SHA
    assert head.entry_sha256 == _EMPTY_SHA
    key = binding.operator_statement_journal_key(scope)
    assert type(key) is JournalKey and key == expected_key and key is not expected_key
    assert key.namespace == "coordinator"
    assert key.stream_id == "operational-control-operator-statements/1"
    assert key.account_scope == _ACCOUNT
    assert key.source_provider == "local-operator-statement"
    assert key.source_environment == "synthetic"
    assert key.source_scope_sha256 == _SCOPE_SHA
    assert key.runtime_environment == "stateful_simulation"
    result = _append(scope, record, head)
    assert type(result) is tuple and len(result) == 2
    returned_key, append = result
    assert type(returned_key) is JournalKey and returned_key == expected_key
    assert type(append) is JournalAppend and type(append.expected_head) is JournalHead
    assert append.expected_head is not head and append.expected_head == head
    assert append.expected_head.key_sha256 == _KEY_SHA
    assert append.expected_head.sequence == 0 and append.expected_head.entry_sha256 == _EMPTY_SHA
    assert append.command_id == record.record_id == "24f84014-5e46-56fe-ad7a-974249913aa9"
    assert (
        append.command_sha256
        == record.semantic_sha256
        == ("d25a455f2005cbcdd3fee692c9b0252629817d274eb0587c34a3a30f9b351d7d")
    )
    assert type(append.records) is tuple and len(append.records) == 1
    stored = append.records[0]
    assert type(stored) is JournalRecord and stored.record_id == append.command_id
    assert stored.schema_id == OPERATOR_STATEMENT_RECORD_SCHEMA
    assert type(stored.payload) is bytes and len(stored.payload) == 2307 < MAX_RECORD_BYTES
    assert hashlib.sha256(stored.payload).hexdigest() == (
        "c88090744bb5be8e43d2a5163910598227e66d6b70eaeea143c0218493dd4f22"
    )
    assert stored.payload == codec.encode_record(
        copy_operational_control_operator_statement_record(record)
    )
    decoded = codec.decode_record(stored.payload, OperationalControlOperatorStatementRecord)
    assert _projection(decoded) == _projection(record)
    assert (
        decoded.record_id == append.command_id and decoded.semantic_sha256 == append.command_sha256
    )


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("account_id", "another-account"),
        ("account_binding_sha256", "b" * 64),
        ("stream_id", "another-deployment"),
    ],
)
def test_each_original_scope_dimension_changes_declared_key_without_claiming_membership(
    field, replacement
):
    original = binding.operator_statement_journal_key(_scope())
    scope = _scope(**{field: replacement})
    changed = binding.operator_statement_journal_key(scope)
    assert changed == _expected_key(scope)
    assert changed.semantic_sha256 != original.semantic_sha256
    assert changed.source_scope_sha256 != original.source_scope_sha256
    assert changed.stream_id == original.stream_id
    assert changed.source_provider == original.source_provider
    assert changed.account_scope == (replacement if field == "account_id" else _ACCOUNT)


def test_original_unicode_scope_grammar_and_fixed_simulation_environment_are_preserved():
    scope = _scope(account_id="账" * 128, stream_id="部署 λ")
    record = _record(scope.account_id)
    expected = _expected_key(scope)
    key, append = _append(scope, record, empty_head(expected))
    assert key == expected and key.account_scope == "账" * 128
    assert len(key.account_scope.encode()) > 128
    assert (
        key.source_environment == "synthetic" and key.runtime_environment == "stateful_simulation"
    )
    decoded = codec.decode_record(
        append.records[0].payload, OperationalControlOperatorStatementRecord
    )
    assert _projection(decoded) == _projection(record)


@pytest.mark.parametrize("kind", ["account", "wrong-key", "forged-empty", "overflow"])
def test_declared_binding_failures_are_rejected_before_actual_codec_work(kind):
    scope, record = _scope(), _record()
    key = _expected_key(scope)
    head = empty_head(key)
    if kind == "account":
        record = _record("foreign-account")
    elif kind == "wrong-key":
        head = JournalHead("f" * 64, 7, "e" * 64)
    elif kind == "forged-empty":
        head = JournalHead(key.semantic_sha256, 0, "f" * 64)
    else:
        head = JournalHead(key.semantic_sha256, MAX_SEQUENCE, "f" * 64)
    with _observe() as entries, pytest.raises(ValueError):
        _append(scope, record, head)
    assert not any(code is _ENCODE_CODE for code in entries)


@pytest.mark.parametrize("sequence", [7, MAX_SEQUENCE - 1])
def test_well_formed_nonzero_head_and_last_available_sequence_remain_declared_data(sequence):
    scope, record = _scope(), _record()
    head = JournalHead(_expected_key(scope).semantic_sha256, sequence, "f" * 64)
    key, append = _append(scope, record, head)
    assert key == _expected_key(scope)
    assert append.expected_head is not head and append.expected_head == head
    assert append.expected_head.sequence + len(append.records) <= MAX_SEQUENCE
    assert append.expected_head.entry_sha256 == "f" * 64
    assert len(append.records) == 1


def _poison(kind, calls):
    def forbidden(*args, **kwargs):
        calls.append(kind)
        raise AssertionError("declared binding dispatched a non-native input hook")

    if kind == "str":

        class PoisonString(str):
            __eq__ = __len__ = __str__ = __repr__ = __hash__ = forbidden
            strip = encode = forbidden

        return PoisonString("stateful_simulation")
    if kind == "int":

        class PoisonInteger(int):
            __eq__ = __lt__ = __le__ = __gt__ = __ge__ = forbidden
            __int__ = __index__ = __hash__ = __repr__ = forbidden

        return PoisonInteger(1)
    if kind == "bool":
        return True
    if kind == "timezone":

        class PoisonTimezone(tzinfo):
            utcoffset = dst = tzname = forbidden

        return datetime(2026, 10, 28, 15, tzinfo=PoisonTimezone())
    raise AssertionError("unknown poison kind")


@pytest.mark.parametrize(
    "field", ["account_id", "account_binding_sha256", "stream_id", "environment"]
)
def test_all_scope_native_leaves_precede_constructor_copy_canonical_and_codec_callbacks(field):
    scope, record = _scope(), _record()
    head = empty_head(_expected_key(scope))
    calls = []
    object.__setattr__(scope, field, _poison("str", calls))
    for key_only in (True, False):
        with _observe() as entries, pytest.raises(ValueError):
            binding.operator_statement_journal_key(scope) if key_only else _append(
                scope, record, head
            )
        assert entries == []
    assert calls == []


@pytest.mark.parametrize(
    "field,kind",
    [("key_sha256", "str"), ("sequence", "int"), ("sequence", "bool"), ("entry_sha256", "str")],
)
def test_every_head_native_leaf_precedes_any_original_helper(field, kind):
    scope, record = _scope(), _record()
    head = empty_head(_expected_key(scope))
    calls = []
    object.__setattr__(head, field, _poison(kind, calls))
    with _observe() as entries, pytest.raises(ValueError):
        _append(scope, record, head)
    assert entries == [] and calls == []


@pytest.mark.parametrize("target", ["scope", "head", "record"])
def test_foreign_outer_classes_are_denied_without_getter_or_codec_dispatch(target):
    scope, record = _scope(), _record()
    head = empty_head(_expected_key(scope))
    original = {
        "scope": ContinuousAccountScope,
        "head": JournalHead,
        "record": OperationalControlOperatorStatementRecord,
    }[target]
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("getter")
        raise AssertionError("foreign declared record getter was dispatched")

    foreign = object.__new__(
        type("ForeignDeclaredValue", (original,), {"__getattribute__": forbidden})
    )
    with _observe() as entries, pytest.raises(ValueError):
        _append(
            foreign if target == "scope" else scope,
            foreign if target == "record" else record,
            foreign if target == "head" else head,
        )
    assert calls == []
    assert not any(
        code is _ENCODE_CODE or code is _SCOPE_INIT_CODE or code is _HEAD_INIT_CODE
        for code in entries
    )
    if target == "scope":
        with pytest.raises(ValueError):
            binding.operator_statement_journal_key(foreign)
    assert calls == []


@pytest.mark.parametrize(
    "target,field,replacement",
    [
        ("scope", "environment", "production"),
        ("scope", "account_binding_sha256", "A" * 64),
        ("scope", "stream_id", " padded"),
        ("head", "key_sha256", "invalid"),
        ("head", "sequence", -1),
        ("head", "sequence", MAX_SEQUENCE + 1),
        ("head", "entry_sha256", "A" * 64),
    ],
)
def test_original_scope_head_grammars_and_ranges_are_preserved_precodec(target, field, replacement):
    scope, record = _scope(), _record()
    head = empty_head(_expected_key(scope))
    object.__setattr__(scope if target == "scope" else head, field, replacement)
    with _observe() as entries, pytest.raises(ValueError):
        _append(scope, record, head)
    assert not any(code is _ENCODE_CODE for code in entries)


@pytest.mark.parametrize("kind", ["raw-link", "expiry", "poison-ref", "poison-time"])
def test_original_g_admission_precedes_scope_head_construction_and_encoding(kind):
    scope, record = _scope(), _record()
    head = empty_head(_expected_key(scope))
    calls = []
    if kind == "raw-link":
        object.__setattr__(record.evidence, "object_sha256", "f" * 64)
    elif kind == "expiry":
        object.__setattr__(record, "session_expires_at", _BASE + timedelta(seconds=2))
    elif kind == "poison-ref":
        object.__setattr__(record.evidence, "object_sha256", _poison("str", calls))
    else:
        object.__setattr__(record, "session_expires_at", _poison("timezone", calls))
    with _observe() as entries, pytest.raises(ValueError):
        _append(scope, record, head)
    assert calls == []
    assert any(code is _G_COPY_CODE for code in entries)
    assert not any(
        code is _SCOPE_INIT_CODE or code is _HEAD_INIT_CODE or code is _ENCODE_CODE
        for code in entries
    )


def test_scope_and_head_snapshots_precede_genuine_original_g_copy_callbacks():
    scope, record = _scope(), _record()
    key = _expected_key(scope)
    head = empty_head(key)
    expected_head = (head.key_sha256, head.sequence, head.entry_sha256)

    def mutate_callers():
        object.__setattr__(scope, "account_id", "changed-caller-account")
        object.__setattr__(scope, "account_binding_sha256", "f" * 64)
        object.__setattr__(scope, "stream_id", "changed-caller-deployment")
        object.__setattr__(head, "key_sha256", "f" * 64)
        object.__setattr__(head, "sequence", 7)
        object.__setattr__(head, "entry_sha256", "f" * 64)

    with _observe(mutate_callers) as entries:
        returned_key, append = _append(scope, record, head)
    assert returned_key == key
    assert (
        append.expected_head.key_sha256,
        append.expected_head.sequence,
        append.expected_head.entry_sha256,
    ) == expected_head
    assert append.expected_head is not head
    assert any(code is _G_COPY_CODE for code in entries)


@pytest.mark.parametrize("boundary", ["scope-constructor", "head-constructor", "codec"])
def test_original_constructor_and_codec_callbacks_cannot_change_the_snapshotted_command(boundary):
    scope, record = _scope(), _record()
    key = _expected_key(scope)
    head = empty_head(key)
    expected_id, expected_sha = record.record_id, record.semantic_sha256
    expected_payload = codec.encode_record(
        copy_operational_control_operator_statement_record(record)
    )

    def mutate_callers():
        object.__setattr__(scope, "account_id", "changed-caller-account")
        object.__setattr__(head, "sequence", 7)
        object.__setattr__(record.statement.actor, "actor_id", "changed-caller-actor")
        object.__setattr__(record.evidence, "byte_count", 18)

    code = {
        "scope-constructor": _SCOPE_INIT_CODE,
        "head-constructor": _HEAD_INIT_CODE,
        "codec": _ENCODE_CODE,
    }[boundary]
    with _observe(mutate_callers, at=code) as entries:
        returned_key, append = _append(scope, record, head)
    assert returned_key == key and append.expected_head.sequence == 0
    assert append.command_id == append.records[0].record_id == expected_id
    assert append.command_sha256 == expected_sha and append.records[0].payload == expected_payload
    assert sum(code is _ENCODE_CODE for code in entries) == 1


def test_returned_key_head_and_bytes_do_not_alias_later_input_mutations():
    scope, record = _scope(), _record()
    head = empty_head(_expected_key(scope))
    key, append = _append(scope, record, head)
    retained = _projection(key), _projection(append)
    object.__setattr__(scope, "account_id", "later-account")
    object.__setattr__(head, "entry_sha256", "f" * 64)
    object.__setattr__(record.statement.actor, "actor_id", "later-actor")
    object.__setattr__(record.evidence, "byte_count", 18)
    assert (_projection(key), _projection(append)) == retained


def test_declared_key_and_append_have_no_filesystem_network_sql_or_clock_effect():
    scope, record = _scope(), _record()
    head = empty_head(_expected_key(scope))
    effects = []

    def forbidden(*args, **kwargs):
        effects.append("effect")
        raise AssertionError("declared binding attempted an ambient effect")

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
        key = binding.operator_statement_journal_key(scope)
        returned_key, append = _append(scope, record, head)
        assert key == returned_key
        decoded = codec.decode_record(
            append.records[0].payload, OperationalControlOperatorStatementRecord
        )
        assert (
            decoded.record_id == append.command_id
            and decoded.semantic_sha256 == append.command_sha256
        )
    assert effects == []
