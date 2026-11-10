"""Declared retention metadata and its actual existing-codec representation."""

import builtins
import json
import socket
import sqlite3
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, fields, replace
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path

import pytest

from packages.application import personal_codec as codec
from packages.domain import operational_control_operator_record as records
from packages.domain import operational_control_operator_statement as statements
from packages.domain.durable_journal_contracts import (
    MAX_APPEND_BYTES,
    MAX_APPEND_RECORDS,
    MAX_RECORD_BYTES,
    MAX_SEQUENCE,
    JournalAppend,
    JournalHead,
    JournalRecord,
)
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlBlockingEvent,
    OperationalControlIncidentDisposition,
    OperationalControlState,
)
from packages.domain.personal_contracts import content_digest
from packages.domain.research_job_contracts import MAX_OBJECT_BYTES, ObjectRef

_BASE = datetime(2026, 10, 28, 14, tzinfo=UTC)
_OPERATION = _BASE + timedelta(seconds=2)
_EXPIRY = _BASE + timedelta(hours=1)
_TYPE = records.OperationalControlOperatorStatementRecord
_COPY_CODE = statements.copy_operational_control_operator_statement.__code__
_DIGEST_CODE = content_digest.__code__


def _values(*, evidence_codec="personal-record/1", unicode=False):
    scope, actor_id = ("账戶:λ", "操作者λ") if unicode else ("account-1", "operator-1")
    event = OperationalControlBlockingEvent(
        scope_id=scope,
        sequence_number=1,
        command_id="initialize-0001",
        command_sha256="a" * 64,
        state=OperationalControlState.HALTED,
        occurred_at=_BASE,
    )
    statement = statements.OperationalControlOperatorStatement(
        scope_id=scope,
        control_transition_id="control-head-1",
        control_transition_sha256="d" * 64,
        control_sequence_number=2,
        control_state=OperationalControlState.HALTED,
        control_state_epoch_id="control-epoch-1",
        blocking_event=event,
        actor=OperationalControlActor(
            actor_id=actor_id,
            kind=OperationalControlActorKind.HUMAN,
            authority_sha256="b" * 64,
            authenticated_at=_OPERATION,
        ),
        resolution_claim=OperationalControlIncidentDisposition(
            event_id=event.event_id,
            event_sha256=event.semantic_sha256,
            resolution_code="已核对" if unicode else "reviewed",
            resolution_evidence_sha256="c" * 64,
            resolved_at=_BASE + timedelta(seconds=1),
        ),
        authentication_checked_at=_OPERATION,
        attested_at=_OPERATION,
        idempotency_key="statement-0001",
    )
    return {
        "statement": statement,
        "evidence": ObjectRef("c" * 64, 17, evidence_codec),
        "session_expires_at": _EXPIRY,
    }


def _projection(value):
    statement = value.statement
    event, actor, claim = statement.blocking_event, statement.actor, statement.resolution_claim
    return (
        statement.scope_id,
        statement.control_transition_id,
        statement.control_transition_sha256,
        statement.control_sequence_number,
        statement.control_state,
        statement.control_state_epoch_id,
        (
            event.scope_id,
            event.sequence_number,
            event.command_id,
            event.command_sha256,
            event.state,
            event.occurred_at,
        ),
        (actor.actor_id, actor.kind, actor.authority_sha256, actor.authenticated_at),
        (
            claim.event_id,
            claim.event_sha256,
            claim.resolution_code,
            claim.resolution_evidence_sha256,
            claim.resolved_at,
        ),
        statement.authentication_checked_at,
        statement.attested_at,
        statement.idempotency_key,
        (value.evidence.object_sha256, value.evidence.byte_count, value.evidence.codec_version),
        value.session_expires_at,
    )


def _encode(value):
    # Supported boundary: the unchanged generic encoder does not validate raw mutation.
    return codec.encode_record(records.copy_operational_control_operator_statement_record(value))


def _apply(operation, value):
    if operation == "copy":
        return records.copy_operational_control_operator_statement_record(value)
    return getattr(_TYPE, operation).fget(value)


def _mutate(value, path, replacement):
    parts = path.split(".")
    parent = value
    for name in parts[:-1]:
        parent = getattr(parent, name)
    object.__setattr__(parent, parts[-1], replacement)


@contextmanager
def _observe(action=None):
    monitor, tool = sys.monitoring, 3
    entries, enabled, fired = [], [], []
    owned = registered = False

    def start(code, offset):
        entries.append(code)
        if action is not None and code is _COPY_CODE and not fired:
            fired.append(True)
            action()

    try:
        assert monitor.get_tool(tool) is None and monitor.get_events(tool) == 0
        monitor.use_tool_id(tool, "aqt-operator-record-unit")
        owned = True
        assert monitor.register_callback(tool, monitor.events.PY_START, start) is None
        registered = True
        for code in (_COPY_CODE, _DIGEST_CODE):
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


def test_native_record_has_independently_pinned_material_identity_and_no_extra_fields():
    value = _TYPE(**_values())
    assert tuple(field.name for field in fields(value)) == (
        "statement",
        "evidence",
        "session_expires_at",
    )
    assert all(field.kw_only for field in fields(value))
    assert not hasattr(value, "__dict__")
    assert (
        records.OPERATOR_STATEMENT_RECORD_SCHEMA
        == "operational-control-operator-statement-record/1"
    )
    assert value.contract_version == "personal-operational-control-operator-statement-record/1"
    assert value.statement.semantic_sha256 == (
        "acdcde5d2d9907638211e4c99d7683fa309e4f5eda0a5ff19477eaa10dad4b5d"
    )
    assert value.record_id == "aebe7290-42b6-5ea6-918a-55f310104b5e"
    material = (
        "personal-operational-control-operator-statement-record/1",
        "operator_statement_record",
        "acdcde5d2d9907638211e4c99d7683fa309e4f5eda0a5ff19477eaa10dad4b5d",
        "c" * 64,
        17,
        "personal-record/1",
        _EXPIRY,
    )
    assert content_digest(material) == (
        "03c5b22de772eb0e9a3979dddbc55c0b83030076d3684e9d6f6cf9bf859a9587"
    )
    assert (
        value.semantic_sha256 == "03c5b22de772eb0e9a3979dddbc55c0b83030076d3684e9d6f6cf9bf859a9587"
    )


@pytest.mark.parametrize(
    "evidence_codec",
    ["personal-record/1", "personal-research-dataset-v1", "personal-provider-json/1"],
)
@pytest.mark.parametrize("unicode", [False, True])
def test_actual_codec_reconstructs_exact_graph_and_canonical_bytes_without_dataclass_equality(
    evidence_codec, unicode
):
    values = _values(evidence_codec=evidence_codec, unicode=unicode)
    value = _TYPE(**values)
    payload = _encode(value)
    decoded = codec.decode_record(payload, _TYPE)
    assert type(payload) is bytes and payload.endswith(b"\n")
    assert all(character < 128 for character in payload)
    assert type(decoded) is _TYPE
    assert type(decoded.statement) is statements.OperationalControlOperatorStatement
    assert type(decoded.evidence) is ObjectRef
    assert type(decoded.statement.actor) is OperationalControlActor
    assert type(decoded.statement.blocking_event) is OperationalControlBlockingEvent
    assert type(decoded.statement.resolution_claim) is OperationalControlIncidentDisposition
    assert decoded is not value and decoded.statement is not value.statement
    assert decoded.evidence is not value.evidence
    assert _projection(decoded) == _projection(value)
    assert decoded.record_id == value.record_id
    assert decoded.semantic_sha256 == value.semantic_sha256
    assert _encode(decoded) == payload
    assert decoded.session_expires_at.tzinfo is UTC
    assert decoded.statement.authentication_checked_at.tzinfo is UTC
    assert decoded.statement.control_state is OperationalControlState.HALTED
    assert decoded.evidence.codec_version == evidence_codec
    envelope = json.loads(payload)
    assert envelope["codec"] == "personal-record/1"
    assert envelope["value"]["$record"] == (
        "packages.domain.operational_control_operator_record.OperationalControlOperatorStatementRecord"
    )
    assert set(envelope["value"]["fields"]) == {"statement", "evidence", "session_expires_at"}
    if unicode:
        assert b"\\u" in payload
    with pytest.raises(ValueError):
        codec.decode_record(payload, statements.OperationalControlOperatorStatement)


def test_record_and_nested_copies_remain_independent_after_input_or_source_mutation():
    values = _values()
    value = _TYPE(**values)
    copied = records.copy_operational_control_operator_statement_record(value)
    expected = _projection(copied), copied.record_id, copied.semantic_sha256
    assert copied is not value
    assert copied.statement is not value.statement and value.statement is not values["statement"]
    assert copied.evidence is not value.evidence and value.evidence is not values["evidence"]
    for name in ("blocking_event", "actor", "resolution_claim"):
        assert getattr(copied.statement, name) is not getattr(value.statement, name)
    object.__setattr__(values["evidence"], "byte_count", 18)
    object.__setattr__(values["statement"].actor, "actor_id", "changed-input-actor")
    assert (_projection(value), value.record_id, value.semantic_sha256) == expected
    object.__setattr__(value.evidence, "byte_count", 19)
    object.__setattr__(value.statement.actor, "actor_id", "changed-source-actor")
    assert (_projection(copied), copied.record_id, copied.semantic_sha256) == expected
    assert value.record_id != copied.record_id and value.semantic_sha256 != copied.semantic_sha256
    with pytest.raises(FrozenInstanceError):
        copied.session_expires_at = _OPERATION


def test_constructor_and_public_operations_freeze_all_outer_fields_before_d_callbacks():
    baseline = _TYPE(**_values())
    expected = _projection(baseline), baseline.record_id, baseline.semantic_sha256
    original_post_init = _TYPE.__post_init__
    for operation in ("constructor", "copy", "record_id", "semantic_sha256"):
        active = []
        if operation != "constructor":
            active.append(_TYPE(**_values()))

        def capture(value, *, active=active):
            active.append(value)
            original_post_init(value)

        def mutate(*, active=active):
            value = active[0]
            object.__setattr__(value.evidence, "byte_count", 18)
            object.__setattr__(value, "session_expires_at", _EXPIRY + timedelta(seconds=1))
            changed = replace(
                value.statement, actor=replace(value.statement.actor, actor_id="changed")
            )
            object.__setattr__(value, "statement", changed)

        with pytest.MonkeyPatch.context() as local:
            if operation == "constructor":
                local.setattr(_TYPE, "__post_init__", capture)
            with _observe(mutate) as entries:
                result = (
                    _TYPE(**_values())
                    if operation == "constructor"
                    else _apply(operation, active[0])
                )
        assert any(code is _COPY_CODE for code in entries)
        if operation in ("constructor", "copy"):
            assert (_projection(result), result.record_id, result.semantic_sha256) == expected
        else:
            assert result == expected[1 if operation == "record_id" else 2]


def _poison(kind, calls):
    def forbidden(*args, **kwargs):
        calls.append(kind)
        raise AssertionError("record native admission dispatched a caller hook")

    if kind == "str":

        class PoisonString(str):
            __eq__ = __len__ = __str__ = __repr__ = __hash__ = forbidden
            strip = encode = forbidden

        return PoisonString("native-looking")
    if kind == "int":

        class PoisonInteger(int):
            __eq__ = __lt__ = __le__ = __gt__ = __ge__ = forbidden
            __int__ = __index__ = __hash__ = __repr__ = forbidden

        return PoisonInteger(17)
    if kind == "timezone":

        class PoisonTimezone(tzinfo):
            utcoffset = dst = tzname = forbidden

        return datetime(2026, 10, 28, 15, tzinfo=PoisonTimezone())
    if kind == "datetime":

        class PoisonDateTime(datetime):
            __eq__ = __lt__ = __le__ = __gt__ = __ge__ = forbidden
            utcoffset = isoformat = forbidden
            tzinfo = property(forbidden)

        return PoisonDateTime(2026, 10, 28, 15, tzinfo=UTC)
    if kind == "bool":
        return True
    raise AssertionError("unknown poison kind")


@pytest.mark.parametrize(
    "path,kind",
    [
        ("evidence.object_sha256", "str"),
        ("evidence.byte_count", "int"),
        ("evidence.byte_count", "bool"),
        ("evidence.codec_version", "str"),
        ("session_expires_at", "timezone"),
        ("session_expires_at", "datetime"),
    ],
)
def test_native_reference_and_expiry_precede_d_helpers_and_identity_dispatch(path, kind):
    calls = []
    poison = _poison(kind, calls)
    constructor_input = _TYPE(**_values())
    _mutate(constructor_input, path, poison)
    with _observe() as entries, pytest.raises(ValueError):
        _TYPE(
            statement=constructor_input.statement,
            evidence=constructor_input.evidence,
            session_expires_at=constructor_input.session_expires_at,
        )
    assert entries == []
    for operation in ("copy", "record_id", "semantic_sha256"):
        value = _TYPE(**_values())
        _mutate(value, path, poison)
        with _observe() as entries, pytest.raises(ValueError):
            _apply(operation, value)
        assert entries == []
    assert calls == []


@pytest.mark.parametrize("target", ["record", "statement", "evidence"])
def test_foreign_outer_classes_deny_before_field_getters(target):
    original = {
        "record": _TYPE,
        "statement": statements.OperationalControlOperatorStatement,
        "evidence": ObjectRef,
    }[target]
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("getter")
        raise AssertionError("foreign retention record getter was dispatched")

    foreign = object.__new__(type("ForeignRecord", (original,), {"__getattribute__": forbidden}))
    if target != "record":
        values = _values()
        values[target] = foreign
        with pytest.raises(ValueError):
            _TYPE(**values)
    for operation in ("copy", "record_id", "semantic_sha256"):
        value = _TYPE(**_values())
        if target == "record":
            value = foreign
        else:
            object.__setattr__(value, target, foreign)
        with pytest.raises(ValueError):
            _apply(operation, value)
    assert calls == []


@pytest.mark.parametrize(
    "path,replacement",
    [
        ("evidence.object_sha256", "invalid"),
        ("evidence.object_sha256", "e" * 64),
        ("evidence.byte_count", 0),
        ("evidence.byte_count", MAX_OBJECT_BYTES + 1),
        ("evidence.codec_version", "unsupported"),
        ("statement.actor.authenticated_at", _BASE + timedelta(seconds=1)),
        ("statement.attested_at", _BASE + timedelta(seconds=3)),
        ("session_expires_at", _OPERATION),
        ("session_expires_at", _OPERATION - timedelta(microseconds=1)),
        ("session_expires_at", _EXPIRY.replace(tzinfo=None)),
    ],
)
def test_original_reference_raw_linkage_operation_times_and_expiry_revalidate(path, replacement):
    for operation in ("copy", "record_id", "semantic_sha256"):
        value = _TYPE(**_values())
        _mutate(value, path, replacement)
        with pytest.raises(ValueError):
            _apply(operation, value)
        with pytest.raises(ValueError):
            _encode(value)


def test_original_d_native_graph_and_exact_operation_equality_are_not_replaced_by_record_hashes():
    calls = []
    for kind in ("actor", "rogue-enum", "earlier-check"):
        value = _TYPE(**_values())
        if kind == "actor":
            object.__setattr__(value.statement.actor, "actor_id", _poison("str", calls))
        elif kind == "rogue-enum":
            rogue = str.__new__(OperationalControlState, "halted")
            object.__setattr__(rogue, "_value_", "halted")
            object.__setattr__(rogue, "_name_", "HALTED")
            object.__setattr__(value.statement, "control_state", rogue)
        else:
            object.__setattr__(
                value.statement.actor, "authenticated_at", _BASE + timedelta(seconds=1)
            )
            object.__setattr__(
                value.statement, "authentication_checked_at", _BASE + timedelta(seconds=1)
            )
        for operation in ("copy", "record_id", "semantic_sha256"):
            with pytest.raises(ValueError):
                _apply(operation, value)
    assert calls == []


def test_evidence_reference_semantic_hash_is_not_the_new_profile_raw_digest():
    values = _values()
    reference = values["evidence"]
    assert reference.semantic_sha256 != reference.object_sha256
    values["statement"] = replace(
        values["statement"],
        resolution_claim=replace(
            values["statement"].resolution_claim,
            resolution_evidence_sha256=reference.semantic_sha256,
        ),
    )
    with pytest.raises(ValueError):
        _TYPE(**values)


@pytest.mark.parametrize("kind", ["statement", "raw-digest", "count", "codec", "expiry", "actor"])
def test_each_valid_declared_record_change_binds_content_without_issuing_authority(kind):
    value = _TYPE(**_values())
    values = _values()
    if kind == "statement":
        values["statement"] = replace(values["statement"], control_transition_id="different-head")
    elif kind == "raw-digest":
        values["evidence"] = replace(values["evidence"], object_sha256="e" * 64)
        values["statement"] = replace(
            values["statement"],
            resolution_claim=replace(
                values["statement"].resolution_claim, resolution_evidence_sha256="e" * 64
            ),
        )
    elif kind == "count":
        values["evidence"] = replace(values["evidence"], byte_count=MAX_OBJECT_BYTES)
    elif kind == "codec":
        values["evidence"] = replace(values["evidence"], codec_version="personal-provider-json/1")
    elif kind == "expiry":
        values["session_expires_at"] = _BASE + timedelta(days=500)
    else:
        values["statement"] = replace(
            values["statement"], actor=replace(values["statement"].actor, actor_id="operator-2")
        )
    changed = _TYPE(**values)
    assert changed.semantic_sha256 != value.semantic_sha256
    assert (changed.record_id != value.record_id) is (kind == "actor")
    assert _projection(codec.decode_record(_encode(changed), _TYPE)) == _projection(changed)


def _wire(value):
    return json.loads(_encode(value))


def _wire_bytes(value):
    return (
        json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        ).encode("ascii")
        + b"\n"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "root-tag",
        "statement-tag",
        "evidence-tag",
        "extra",
        "missing",
        "bool-count",
        "enum-tag",
        "running",
        "codec",
        "digest",
        "raw-link",
        "auth-time",
        "expiry",
        "non-utc",
        "naive",
        "envelope",
    ],
)
def test_actual_codec_adverse_wire_cannot_skip_expected_graph_or_record_constructors(mutation):
    wire = _wire(_TYPE(**_values()))
    root = wire["value"]
    values = root["fields"]
    statement = values["statement"]["fields"]
    evidence = values["evidence"]["fields"]
    if mutation == "root-tag":
        root["$record"] = "os.system"
    elif mutation == "statement-tag":
        values["statement"]["$record"] = "os.system"
    elif mutation == "evidence-tag":
        values["evidence"]["$record"] = "os.system"
    elif mutation == "extra":
        values["unexpected"] = "not-selected"
    elif mutation == "missing":
        del values["session_expires_at"]
    elif mutation == "bool-count":
        evidence["byte_count"] = True
    elif mutation == "enum-tag":
        statement["control_state"]["$enum"] = "os.system"
    elif mutation == "running":
        statement["control_state"]["value"] = "running"
    elif mutation == "codec":
        evidence["codec_version"] = "unsupported"
    elif mutation == "digest":
        evidence["object_sha256"] = "invalid"
    elif mutation == "raw-link":
        evidence["object_sha256"] = "e" * 64
    elif mutation == "auth-time":
        statement["actor"]["fields"]["authenticated_at"]["$datetime"] = (
            _BASE + timedelta(seconds=1)
        ).isoformat()
    elif mutation == "expiry":
        values["session_expires_at"]["$datetime"] = _OPERATION.isoformat()
    elif mutation == "non-utc":
        values["session_expires_at"]["$datetime"] = "2026-10-28T15:00:00+01:00"
    elif mutation == "naive":
        values["session_expires_at"]["$datetime"] = "2026-10-28T15:00:00"
    else:
        wire["codec"] = "unsupported"
    with pytest.raises(ValueError):
        codec.decode_record(_wire_bytes(wire), _TYPE)


def test_duplicate_noncanonical_and_malformed_wire_are_rejected_without_dynamic_types():
    payload = _encode(_TYPE(**_values()))
    duplicate = payload.replace(
        b'"codec":"personal-record/1"',
        b'"codec":"personal-record/1","codec":"personal-record/1"',
        1,
    )
    for invalid in (duplicate, payload + b" ", payload[:-2], b'{"codec":"personal-record/1"}'):
        with pytest.raises(ValueError):
            codec.decode_record(invalid, _TYPE)


def test_actual_encoded_record_fits_original_pure_journal_envelope_and_append():
    value = _TYPE(**_values())
    payload = _encode(value)
    retained = JournalRecord(value.record_id, records.OPERATOR_STATEMENT_RECORD_SCHEMA, payload)
    head = JournalHead("e" * 64, 0, "f" * 64)
    append = JournalAppend("statement-retain-0001", value.semantic_sha256, head, (retained,))
    assert 0 < len(payload) < MAX_RECORD_BYTES == 256 * 1024
    assert retained.payload == payload
    assert retained.record_id == value.record_id
    assert append.records == (retained,)
    assert append.expected_head == head


def test_original_journal_payload_count_aggregate_and_sequence_bounds_are_preserved():
    head = JournalHead("e" * 64, 0, "f" * 64)
    maximum = b"x" * MAX_RECORD_BYTES
    full = tuple(
        JournalRecord(f"bounded-fixture-{index}", "fixture/1", maximum) for index in range(5)
    )
    assert MAX_APPEND_BYTES == 4 * MAX_RECORD_BYTES == 1024 * 1024
    assert len(JournalAppend("bounded-append", "a" * 64, head, full[:4]).records) == 4
    with pytest.raises(ValueError):
        JournalRecord("too-large-fixture", "fixture/1", maximum + b"x")
    with pytest.raises(ValueError):
        JournalAppend("bounded-append", "a" * 64, head, full)
    small = tuple(JournalRecord(f"small-fixture-{index}", "fixture/1", b"x") for index in range(65))
    assert MAX_APPEND_RECORDS == 64
    assert len(JournalAppend("bounded-count", "a" * 64, head, small[:64]).records) == 64
    with pytest.raises(ValueError):
        JournalAppend("bounded-count", "a" * 64, head, small)
    with pytest.raises(ValueError):
        JournalAppend("duplicate-fixture", "a" * 64, head, (small[0], small[0]))
    with pytest.raises(ValueError):
        JournalAppend(
            "exhausted-sequence",
            "a" * 64,
            JournalHead("e" * 64, MAX_SEQUENCE, "f" * 64),
            (small[0],),
        )


def test_record_copy_identity_and_actual_codec_have_no_io_auth_or_clock_effect():
    values = _values()
    effects = []

    def forbidden(*args, **kwargs):
        effects.append("effect")
        raise AssertionError("pure record attempted an ambient effect")

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
        value = _TYPE(**values)
        copied = records.copy_operational_control_operator_statement_record(value)
        payload = _encode(copied)
        decoded = codec.decode_record(payload, _TYPE)
        assert decoded.record_id == value.record_id
        assert decoded.semantic_sha256 == value.semantic_sha256
        assert _projection(decoded) == _projection(value)
    assert effects == []
