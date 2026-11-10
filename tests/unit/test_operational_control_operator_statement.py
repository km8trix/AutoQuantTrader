"""Inert control claims: exact native data, detached copies and distinct identities."""

import builtins
import json
import socket
import sqlite3
import subprocess
import time
from dataclasses import FrozenInstanceError, fields, replace
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from pathlib import Path

import pytest

from packages.domain import operational_control_operator_statement as statements
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlBlockingEvent,
    OperationalControlError,
    OperationalControlIncidentDisposition,
    OperationalControlState,
)

_BASE = datetime(2026, 10, 28, 14, tzinfo=UTC)
_POLICY = "2f977287c78f590335b6176e67967d23cb55d22ad88ba6b09a40c4cdcf70759e"
_FIELDS = (
    "scope_id",
    "control_transition_id",
    "control_transition_sha256",
    "control_sequence_number",
    "control_state",
    "control_state_epoch_id",
    "blocking_event",
    "actor",
    "resolution_claim",
    "authentication_checked_at",
    "attested_at",
    "idempotency_key",
)
_OPERATIONS = ("copy", "statement_id", "canonical_json", "semantic_sha256")


def _values():
    event = OperationalControlBlockingEvent(
        scope_id="account-1",
        sequence_number=1,
        command_id="initialize-0001",
        command_sha256="a" * 64,
        state=OperationalControlState.HALTED,
        occurred_at=_BASE,
    )
    actor = OperationalControlActor(
        actor_id="operator-1",
        kind=OperationalControlActorKind.HUMAN,
        authority_sha256="b" * 64,
        authenticated_at=_BASE + timedelta(seconds=2),
    )
    claim = OperationalControlIncidentDisposition(
        event_id=event.event_id,
        event_sha256=event.semantic_sha256,
        resolution_code="reviewed",
        resolution_evidence_sha256="c" * 64,
        resolved_at=_BASE + timedelta(seconds=1),
    )
    return {
        "scope_id": "account-1",
        "control_transition_id": "control-head-1",
        "control_transition_sha256": "d" * 64,
        "control_sequence_number": 2,
        "control_state": OperationalControlState.HALTED,
        "control_state_epoch_id": "control-epoch-1",
        "blocking_event": event,
        "actor": actor,
        "resolution_claim": claim,
        "authentication_checked_at": _BASE + timedelta(seconds=3),
        "attested_at": _BASE + timedelta(seconds=4),
        "idempotency_key": "statement-0001",
    }


def _apply(operation, value):
    if operation == "copy":
        return statements.copy_operational_control_operator_statement(value)
    # Directly enter the declared property, even when the input is a hostile subclass.
    return getattr(statements.OperationalControlOperatorStatement, operation).fget(value)


def _mutate(value, path, replacement):
    parts = path.split(".")
    parent = value
    for name in parts[:-1]:
        parent = getattr(parent, name)
    object.__setattr__(parent, parts[-1], replacement)


def _invalid_values(path, replacement):
    values = _values()
    if "." in path:
        name, leaf = path.split(".")
        object.__setattr__(values[name], leaf, replacement)
    else:
        values[path] = replacement
    return values


def _replace_event(values, **changes):
    event = replace(values["blocking_event"], **changes)
    values["blocking_event"] = event
    values["resolution_claim"] = replace(
        values["resolution_claim"], event_id=event.event_id, event_sha256=event.semantic_sha256
    )


def _string(value):
    return {"type": "string", "value": value}


def test_native_composition_detaches_original_values_without_authenticating_them():
    values = _values()
    value = statements.OperationalControlOperatorStatement(**values)
    copied = statements.copy_operational_control_operator_statement(value)
    assert tuple(field.name for field in fields(value)) == _FIELDS
    assert all(field.kw_only for field in fields(value))
    assert not hasattr(value, "__dict__")
    assert copied is not value
    for name, original in (
        ("blocking_event", OperationalControlBlockingEvent),
        ("actor", OperationalControlActor),
        ("resolution_claim", OperationalControlIncidentDisposition),
    ):
        assert type(getattr(value, name)) is original
        assert getattr(value, name) == values[name] == getattr(copied, name)
        assert getattr(value, name) is not values[name]
        assert getattr(value, name) is not getattr(copied, name)
    assert value.scope_id == value.blocking_event.scope_id == "account-1"
    assert value.control_sequence_number == 2
    assert value.blocking_event.sequence_number == 1
    assert value.resolution_claim.event_id == value.blocking_event.event_id
    assert value.resolution_claim.event_sha256 == value.blocking_event.semantic_sha256
    assert value.resolution_claim.resolved_at < value.actor.authenticated_at
    assert value.canonical_json == copied.canonical_json
    assert value.statement_id == copied.statement_id
    assert value.semantic_sha256 == copied.semantic_sha256
    with pytest.raises(FrozenInstanceError):
        value.scope_id = "changed"
    with pytest.raises(FrozenInstanceError):
        value.actor.actor_id = "changed"


def test_input_and_projection_mutation_cannot_change_an_already_detached_copy():
    values = _values()
    value = statements.OperationalControlOperatorStatement(**values)
    copied = statements.copy_operational_control_operator_statement(value)
    retained = (copied.statement_id, copied.semantic_sha256, copied.canonical_json)
    object.__setattr__(values["blocking_event"], "command_id", "changed-original")
    object.__setattr__(values["actor"], "actor_id", "changed-original")
    object.__setattr__(values["resolution_claim"], "resolution_code", "changed-original")
    assert (value.statement_id, value.semantic_sha256, value.canonical_json) == retained
    object.__setattr__(value, "control_transition_id", "different-declared-head")
    object.__setattr__(value.actor, "actor_id", "different-declared-actor")
    object.__setattr__(value.resolution_claim, "resolution_code", "different-claim")
    assert (copied.statement_id, copied.semantic_sha256, copied.canonical_json) == retained
    assert value.semantic_sha256 != retained[1]
    assert value.statement_id != retained[0]


def test_each_operation_uses_one_snapshot_when_an_original_helper_mutates_the_source():
    baseline = statements.OperationalControlOperatorStatement(**_values())
    expected = {
        "statement_id": baseline.statement_id,
        "canonical_json": baseline.canonical_json,
        "semantic_sha256": baseline.semantic_sha256,
    }
    original_text = statements._require_text
    original_post_init = statements.OperationalControlOperatorStatement.__post_init__
    for operation in ("constructor", *_OPERATIONS):
        observed = []
        active = []
        if operation != "constructor":
            active.append(statements.OperationalControlOperatorStatement(**_values()))

        def capture_constructor(value, *, active=active):
            active.append(value)
            original_post_init(value)

        def mutate_after_snapshot(*args, active=active, observed=observed, **kwargs):
            if not observed:
                observed.append("mutated")
                source = active[0]
                object.__setattr__(source, "control_transition_id", "changed-during-helper")
                object.__setattr__(source.actor, "actor_id", "changed-during-helper")
                object.__setattr__(source.blocking_event, "command_id", "changed-during-helper")
                object.__setattr__(
                    source.resolution_claim, "resolution_code", "changed-during-helper"
                )
            return original_text(*args, **kwargs)

        with pytest.MonkeyPatch.context() as local:
            local.setattr(statements, "_require_text", mutate_after_snapshot)
            if operation == "constructor":
                local.setattr(
                    statements.OperationalControlOperatorStatement,
                    "__post_init__",
                    capture_constructor,
                )
                result = statements.OperationalControlOperatorStatement(**_values())
            else:
                result = _apply(operation, active[0])
        assert observed == ["mutated"]
        if operation in ("constructor", "copy"):
            assert result.statement_id == expected["statement_id"]
            assert result.canonical_json == expected["canonical_json"]
            assert result.semantic_sha256 == expected["semantic_sha256"]
        else:
            assert result == expected[operation]


def test_literal_canonical_structure_and_distinct_data_purpose():
    value = statements.OperationalControlOperatorStatement(**_values())
    assert statements.OPERATOR_STATEMENT_DATA_VERSION == "operational-control-operator-statement/1"
    # Independently derived with a stdlib-only typed encoder; see the frozen fixture review.
    assert value.blocking_event.event_id == "360e44fc-8cc2-5d45-8d51-13a1e60b944e"
    assert value.blocking_event.semantic_sha256 == (
        "0ff651323bde9a3cca0937a2c151cb1daf76ad6a9e0c676978ef0fd7504589ab"
    )
    assert value.actor.semantic_sha256 == (
        "bcf4ce68c9d431b7558038936c3694f657076aa7eb6de951eadd41fa3ca1aad1"
    )
    assert value.resolution_claim.semantic_sha256 == (
        "e0fbdc566d590626ddfb21559f699504db65a1c56eaeced606a4930c9a472cf3"
    )
    assert value.statement_id == "aebe7290-42b6-5ea6-918a-55f310104b5e"
    assert value.semantic_sha256 == (
        "a3d1d9dbf0816a64273a6fc24363b7f6ca36c7baca229cd2967144c026067719"
    )
    expected = {
        "type": "tuple",
        "value": [
            _string("operational-control-operator-statement/1"),
            _string("operator_statement"),
            _string(_POLICY),
            _string("aebe7290-42b6-5ea6-918a-55f310104b5e"),
            _string("account-1"),
            _string("control-head-1"),
            _string("d" * 64),
            {"type": "int", "value": "2"},
            {
                "enum_type": "packages.domain.operational_control.OperationalControlState",
                "type": "enum",
                "value": _string("halted"),
            },
            _string("control-epoch-1"),
            _string("0ff651323bde9a3cca0937a2c151cb1daf76ad6a9e0c676978ef0fd7504589ab"),
            _string("bcf4ce68c9d431b7558038936c3694f657076aa7eb6de951eadd41fa3ca1aad1"),
            _string("e0fbdc566d590626ddfb21559f699504db65a1c56eaeced606a4930c9a472cf3"),
            {"type": "datetime", "value": "2026-10-28T14:00:03.000000Z"},
            {"type": "datetime", "value": "2026-10-28T14:00:04.000000Z"},
            _string("statement-0001"),
        ],
    }
    assert json.loads(value.canonical_json) == expected
    assert value.canonical_json == json.dumps(
        expected, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    )


@pytest.mark.parametrize(
    "path,replacement",
    [
        ("scope_id", ""),
        ("control_transition_id", " padded"),
        ("control_state_epoch_id", "epoch\x00body"),
        ("actor.actor_id", "x" * 129),
        ("resolution_claim.resolution_code", "trailing "),
        ("control_transition_sha256", "D" * 64),
        ("actor.authority_sha256", "b" * 63),
        ("resolution_claim.resolution_evidence_sha256", "g" * 64),
        ("idempotency_key", "short"),
        ("idempotency_key", "key has spaces"),
        ("idempotency_key", "é" * 8),
        ("idempotency_key", "a" * 129),
        ("control_sequence_number", 0),
        ("blocking_event.sequence_number", -1),
    ],
)
def test_original_field_grammars_are_retained_on_construction_and_every_public_read(
    path, replacement
):
    with pytest.raises(OperationalControlError):
        statements.OperationalControlOperatorStatement(**_invalid_values(path, replacement))
    for operation in _OPERATIONS:
        value = statements.OperationalControlOperatorStatement(**_values())
        _mutate(value, path, replacement)
        with pytest.raises(OperationalControlError):
            _apply(operation, value)


def test_native_boundary_values_do_not_invent_caps_normalization_or_expiry():
    values = _values()
    values.update(
        scope_id="账" * 128,
        control_transition_id="头" * 128,
        control_transition_sha256="0" * 64,
        control_sequence_number=2**100,
        control_state_epoch_id="纪" * 128,
        idempotency_key="a" * 128,
        attested_at=datetime(9999, 12, 31, tzinfo=UTC),
    )
    _replace_event(values, scope_id=values["scope_id"])
    values["actor"] = replace(values["actor"], actor_id="人" * 128, authority_sha256="0" * 64)
    values["resolution_claim"] = replace(
        values["resolution_claim"],
        resolution_code="已核对" * 42,
        resolution_evidence_sha256="0" * 64,
    )
    value = statements.OperationalControlOperatorStatement(**values)
    assert value.scope_id == "账" * 128
    assert len(value.scope_id.encode()) > 128
    assert value.control_sequence_number == 2**100
    assert value.control_transition_sha256 == "0" * 64
    assert value.attested_at.year == 9999
    values["idempotency_key"] = "a1234567"
    assert statements.OperationalControlOperatorStatement(**values).idempotency_key == "a1234567"


def _poison(kind, calls):
    def forbidden(*args, **kwargs):
        calls.append(kind)
        raise AssertionError("non-native input hook was dispatched")

    if kind == "str":

        class PoisonString(str):
            __eq__ = __hash__ = __len__ = __str__ = __repr__ = forbidden
            strip = encode = forbidden

        return PoisonString("native-looking")
    if kind == "int":

        class PoisonInteger(int):
            __eq__ = __lt__ = __le__ = __gt__ = __ge__ = forbidden
            __int__ = __index__ = __hash__ = __repr__ = forbidden

        return PoisonInteger(1)
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
    if kind == "bool":
        return True
    if kind == "enum":

        class PoisonEnum:
            __eq__ = __hash__ = __bool__ = __str__ = __repr__ = forbidden

        return PoisonEnum()
    raise AssertionError("unknown poison kind")


_NATIVE_PATHS = (
    ("scope_id", "str"),
    ("control_transition_id", "str"),
    ("control_transition_sha256", "str"),
    ("control_sequence_number", "int"),
    ("control_sequence_number", "bool"),
    ("control_state", "enum"),
    ("control_state_epoch_id", "str"),
    ("blocking_event.scope_id", "str"),
    ("blocking_event.sequence_number", "int"),
    ("blocking_event.command_id", "str"),
    ("blocking_event.command_sha256", "str"),
    ("blocking_event.state", "enum"),
    ("blocking_event.occurred_at", "datetime"),
    ("actor.actor_id", "str"),
    ("actor.kind", "enum"),
    ("actor.authority_sha256", "str"),
    ("actor.authenticated_at", "datetime"),
    ("resolution_claim.event_id", "str"),
    ("resolution_claim.event_sha256", "str"),
    ("resolution_claim.resolution_code", "str"),
    ("resolution_claim.resolution_evidence_sha256", "str"),
    ("resolution_claim.resolved_at", "datetime"),
    ("authentication_checked_at", "datetime"),
    ("attested_at", "datetime"),
    ("idempotency_key", "str"),
    ("blocking_event.occurred_at", "timezone"),
    ("actor.authenticated_at", "timezone"),
    ("resolution_claim.resolved_at", "timezone"),
    ("authentication_checked_at", "timezone"),
    ("attested_at", "timezone"),
)


@pytest.mark.parametrize("path,kind", _NATIVE_PATHS)
def test_all_native_admission_precedes_original_helpers_and_hostile_hooks(path, kind):
    calls = []
    replacement = _poison(kind, calls)
    invalid = _invalid_values(path, replacement)
    prepared = []
    for operation in _OPERATIONS:
        value = statements.OperationalControlOperatorStatement(**_values())
        _mutate(value, path, replacement)
        prepared.append((operation, value))

    def forbidden(*args, **kwargs):
        calls.append("original helper")
        raise AssertionError("helper called before complete native admission")

    with pytest.MonkeyPatch.context() as local:
        for original in (
            OperationalControlActor,
            OperationalControlBlockingEvent,
            OperationalControlIncidentDisposition,
        ):
            local.setattr(original, "__post_init__", forbidden)
        for name in (
            "_require_text",
            "_require_sha256",
            "_require_idempotency_key",
            "_require_utc",
            "canonical_id",
            "canonical_json_text",
            "canonical_json_bytes",
        ):
            local.setattr(statements, name, forbidden)
        with pytest.raises(OperationalControlError):
            statements.OperationalControlOperatorStatement(**invalid)
        for operation, value in prepared:
            with pytest.raises(OperationalControlError):
                _apply(operation, value)
    assert calls == []


@pytest.mark.parametrize(
    "field,original",
    [
        ("blocking_event", OperationalControlBlockingEvent),
        ("actor", OperationalControlActor),
        ("resolution_claim", OperationalControlIncidentDisposition),
        (None, statements.OperationalControlOperatorStatement),
    ],
)
def test_foreign_outer_and_nested_classes_are_denied_before_field_getters(field, original):
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("getter")
        raise AssertionError("foreign record field getter was called")

    foreign_type = type("ForeignRecord", (original,), {"__getattribute__": forbidden})
    foreign = object.__new__(foreign_type)
    if field is not None:
        values = _values()
        values[field] = foreign
        with pytest.raises(OperationalControlError):
            statements.OperationalControlOperatorStatement(**values)
    for operation in _OPERATIONS:
        value = statements.OperationalControlOperatorStatement(**_values())
        if field is None:
            value = foreign
        else:
            object.__setattr__(value, field, foreign)
        with pytest.raises(OperationalControlError):
            _apply(operation, value)
    assert calls == []


@pytest.mark.parametrize(
    "path,enum_type,label",
    [
        ("control_state", OperationalControlState, "halted"),
        ("blocking_event.state", OperationalControlState, "halted"),
        ("actor.kind", OperationalControlActorKind, "human"),
    ],
)
def test_exact_enum_class_without_original_member_identity_is_not_admitted(path, enum_type, label):
    rogue = str.__new__(enum_type, label)
    object.__setattr__(rogue, "_value_", label)
    object.__setattr__(rogue, "_name_", label.upper())
    assert type(rogue) is enum_type
    assert rogue == enum_type(label) and rogue is not enum_type(label)
    with pytest.raises(OperationalControlError):
        statements.OperationalControlOperatorStatement(**_invalid_values(path, rogue))
    for operation in _OPERATIONS:
        value = statements.OperationalControlOperatorStatement(**_values())
        _mutate(value, path, rogue)
        with pytest.raises(OperationalControlError):
            _apply(operation, value)


@pytest.mark.parametrize(
    "path,replacement",
    [
        ("blocking_event.scope_id", "foreign-account"),
        ("blocking_event.sequence_number", 3),
        ("resolution_claim.event_id", "foreign-event"),
        ("resolution_claim.event_sha256", "f" * 64),
        ("actor.kind", OperationalControlActorKind.SYSTEM),
        ("actor.authenticated_at", None),
        ("control_state", OperationalControlState.RUNNING),
        ("blocking_event.state", OperationalControlState.RUNNING),
        ("resolution_claim.resolved_at", _BASE - timedelta(microseconds=1)),
        ("resolution_claim.resolved_at", _BASE + timedelta(seconds=5)),
        ("actor.authenticated_at", _BASE + timedelta(seconds=3, microseconds=1)),
        ("authentication_checked_at", _BASE + timedelta(seconds=4, microseconds=1)),
        ("attested_at", _BASE + timedelta(microseconds=1)),
        ("attested_at", _BASE.replace(tzinfo=None)),
        ("attested_at", _BASE.replace(tzinfo=timezone(timedelta(hours=1)))),
    ],
)
def test_declared_coherence_and_both_time_chains_fail_closed(path, replacement):
    with pytest.raises(OperationalControlError):
        statements.OperationalControlOperatorStatement(**_invalid_values(path, replacement))
    for operation in _OPERATIONS:
        value = statements.OperationalControlOperatorStatement(**_values())
        _mutate(value, path, replacement)
        with pytest.raises(OperationalControlError):
            _apply(operation, value)


def test_equality_chronology_and_earlier_blocker_state_are_valid_data():
    values = _values()
    values["actor"] = replace(values["actor"], authenticated_at=_BASE)
    values["resolution_claim"] = replace(values["resolution_claim"], resolved_at=_BASE)
    values["authentication_checked_at"] = values["attested_at"] = _BASE
    _replace_event(values, state=OperationalControlState.PAUSED)
    value = statements.OperationalControlOperatorStatement(**values)
    assert value.blocking_event.state is OperationalControlState.PAUSED
    assert value.control_state is OperationalControlState.HALTED
    assert (
        value.blocking_event.occurred_at == value.resolution_claim.resolved_at == value.attested_at
    )
    assert value.actor.authenticated_at == value.authentication_checked_at == value.attested_at


@pytest.mark.parametrize(
    "path,replacement,changes_id",
    [
        ("scope_id", "account-2", True),
        ("control_transition_id", "different-declared-head", False),
        ("control_transition_sha256", "e" * 64, False),
        ("control_sequence_number", 3, False),
        ("control_state", OperationalControlState.PAUSED, False),
        ("control_state_epoch_id", "different-declared-epoch", False),
        ("blocking_event.sequence_number", 2, False),
        ("blocking_event.command_id", "manual-halt-0001", False),
        ("blocking_event.command_sha256", "e" * 64, False),
        ("blocking_event.state", OperationalControlState.PAUSED, False),
        ("blocking_event.occurred_at", _BASE - timedelta(seconds=1), False),
        ("actor.actor_id", "operator-2", True),
        ("actor.authority_sha256", "e" * 64, False),
        ("actor.authenticated_at", _BASE + timedelta(seconds=1), False),
        ("resolution_claim.resolution_code", "operator-checked", False),
        ("resolution_claim.resolution_evidence_sha256", "e" * 64, False),
        ("resolution_claim.resolved_at", _BASE, False),
        ("authentication_checked_at", _BASE + timedelta(seconds=2), False),
        ("attested_at", _BASE + timedelta(seconds=5), False),
        ("idempotency_key", "statement-0002", True),
    ],
)
def test_each_coherent_data_binding_changes_digest_with_account_actor_key_identity(
    path, replacement, changes_id
):
    original = statements.OperationalControlOperatorStatement(**_values())
    values = _values()
    if path == "scope_id":
        values[path] = replacement
        _replace_event(values, scope_id=replacement)
    elif path.startswith("blocking_event."):
        _replace_event(values, **{path.split(".")[1]: replacement})
    elif "." in path:
        parent, leaf = path.split(".")
        values[parent] = replace(values[parent], **{leaf: replacement})
    else:
        values[path] = replacement
    changed = statements.OperationalControlOperatorStatement(**values)
    assert changed.semantic_sha256 != original.semantic_sha256
    assert changed.canonical_json != original.canonical_json
    assert (changed.statement_id != original.statement_id) is changes_id
    copied = statements.copy_operational_control_operator_statement(changed)
    assert copied.semantic_sha256 == changed.semantic_sha256
    assert copied.statement_id == changed.statement_id


def test_account_actor_delimiters_cannot_alias_the_data_identity():
    first = _values()
    second = _values()
    first["scope_id"] = "account:operator"
    first["actor"] = replace(first["actor"], actor_id="one")
    second["scope_id"] = "account"
    second["actor"] = replace(second["actor"], actor_id="operator:one")
    _replace_event(first, scope_id=first["scope_id"])
    _replace_event(second, scope_id=second["scope_id"])
    left = statements.OperationalControlOperatorStatement(**first)
    right = statements.OperationalControlOperatorStatement(**second)
    assert left.statement_id != right.statement_id
    assert left.semantic_sha256 != right.semantic_sha256


def test_native_data_paths_have_no_ambient_effect_or_evidence_lookup():
    values = _values()
    effects = []

    def forbidden(*args, **kwargs):
        effects.append("effect")
        raise AssertionError("inert statement attempted ambient effect")

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
        value = statements.OperationalControlOperatorStatement(**values)
        copied = statements.copy_operational_control_operator_statement(value)
        assert copied.statement_id == value.statement_id
        assert copied.canonical_json == value.canonical_json
        assert copied.semantic_sha256 == value.semantic_sha256
    assert effects == []
    assert values["blocking_event"].state is OperationalControlState.HALTED
    assert value.control_state is OperationalControlState.HALTED
    assert copied.control_state is OperationalControlState.HALTED
