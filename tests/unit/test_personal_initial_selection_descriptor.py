"""Pure detached-data admission and conversion; no financial owners or authority."""

import builtins
import socket
import sqlite3
import subprocess
import time
from dataclasses import MISSING, FrozenInstanceError, fields
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from pathlib import Path

import pytest

from apps.trader import initial_selection_descriptor as descriptor
from packages.domain.continuous_persistence_contracts import (
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.personal_contracts import ContractRecord
from packages.domain.reconciliation_contracts import (
    MAX_RECONCILIATION_COUNTER,
    ReconciliationHeads,
)
from packages.domain.research_job_contracts import ObjectRef
from packages.domain.runtime_owner_dependency_contracts import MAX_OWNER_DEPENDENCIES_BYTES

_FIELD_NAMES = (
    "account_id",
    "account_binding_sha256",
    "stream_id",
    "after_assignment_sha256",
    "ledger_sha256",
    "order_sha256",
    "capacity_sha256",
    "effect_watermark",
    "attempt_sha256",
    "control_revision",
    "lease_generation",
    "dependency_schema_id",
    "dependency_object_sha256",
    "dependency_byte_count",
    "dependency_codec_version",
    "dependency_semantic_sha256",
    "checked_at",
    "valid_until",
    "c1_receipt_sha256",
    "control_sha256",
    "original_lease_sha256",
)
_ERROR = "^INITIAL_SELECTION_DESCRIPTOR_INVALID$"


def _values(index=0):
    if index == 0:
        return {
            "account_id": "a",
            "account_binding_sha256": "0" * 64,
            "stream_id": "stream λ body",
            "after_assignment_sha256": "1" * 64,
            "ledger_sha256": "2" * 64,
            "order_sha256": "3" * 64,
            "capacity_sha256": "4" * 64,
            "effect_watermark": 0,
            "attempt_sha256": "5" * 64,
            "control_revision": 17,
            "lease_generation": 9223372036854775807,
            "dependency_schema_id": "runtime-owner-dependencies/1",
            "dependency_object_sha256": "6" * 64,
            "dependency_byte_count": 1,
            "dependency_codec_version": "personal-record/1",
            "dependency_semantic_sha256": "7" * 64,
            "checked_at": datetime(2026, 10, 28, 14, 0, 0, tzinfo=UTC),
            "valid_until": datetime(2026, 10, 28, 14, 0, 0, 1, tzinfo=UTC),
            "c1_receipt_sha256": "8" * 64,
            "control_sha256": None,
            "original_lease_sha256": "9" * 64,
        }
    assert index == 1
    return {
        "account_id": "账户 " + "a" * 125,
        "account_binding_sha256": "a" * 64,
        "stream_id": "z" * 128,
        "after_assignment_sha256": "b" * 64,
        "ledger_sha256": "c" * 64,
        "order_sha256": "d" * 64,
        "capacity_sha256": "e" * 64,
        "effect_watermark": 9223372036854775807,
        "attempt_sha256": "f" * 64,
        "control_revision": 0,
        "lease_generation": 29,
        "dependency_schema_id": "runtime-owner-dependencies/1",
        "dependency_object_sha256": "0123456789abcdef" * 4,
        "dependency_byte_count": 262144,
        "dependency_codec_version": "personal-record/1",
        "dependency_semantic_sha256": "1023456789abcdef" * 4,
        "checked_at": datetime(2026, 11, 2, 13, 0, 0, 234567, tzinfo=UTC),
        "valid_until": datetime(2026, 11, 2, 13, 1, 0, 234567, tzinfo=UTC),
        "c1_receipt_sha256": "2103456789abcdef" * 4,
        "control_sha256": "3210456789abcdef" * 4,
        "original_lease_sha256": "4321056789abcdef" * 4,
    }


def _snapshot(value):
    return tuple(getattr(value, name) for name in _FIELD_NAMES)


def _expected_bridge(values):
    # Independent original data constructors; these are not prepared owners.
    return (
        ContinuousAccountScope(
            values["account_id"], values["account_binding_sha256"], values["stream_id"]
        ),
        ReconciliationHeads(
            values["ledger_sha256"],
            values["order_sha256"],
            values["capacity_sha256"],
            values["effect_watermark"],
            values["attempt_sha256"],
            values["control_revision"],
            values["lease_generation"],
        ),
        ContinuousEvidenceRef(
            values["dependency_schema_id"],
            ObjectRef(
                values["dependency_object_sha256"],
                values["dependency_byte_count"],
                values["dependency_codec_version"],
            ),
            values["dependency_semantic_sha256"],
        ),
    )


def _deny_constructor(values):
    with pytest.raises(ValueError, match=_ERROR) as caught:
        descriptor.InitialSelectionDescriptor(**values)
    assert type(caught.value) is ValueError


@pytest.mark.parametrize("index", [0, 1], ids=["null-control", "digest-control"])
def test_literal_flat_values_original_bridge_and_fresh_copies_have_no_effects(index):
    values = _values(index)
    expected = tuple(values[name] for name in _FIELD_NAMES)
    bridge_expected = _expected_bridge(values)
    effects = []

    def forbidden(*args, **kwargs):
        effects.append("effect")
        raise AssertionError("pure descriptor attempted an effect")

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
        value = descriptor.InitialSelectionDescriptor(**values)
        copied = descriptor.copy_initial_selection_descriptor(value)
        copied_again = descriptor.copy_initial_selection_descriptor(value)
        first = descriptor.initial_selection_request_data(value)
        second = descriptor.initial_selection_request_data(value)
    assert effects == []
    assert (
        type(value) is type(copied) is type(copied_again) is descriptor.InitialSelectionDescriptor
    )
    assert tuple(field.name for field in fields(value)) == _FIELD_NAMES
    assert all(field.kw_only and field.default is MISSING for field in fields(value))
    assert not isinstance(value, ContractRecord)
    assert not hasattr(value, "__dict__")
    with pytest.raises(FrozenInstanceError):
        value.account_id = "different"
    assert _snapshot(value) == _snapshot(copied) == _snapshot(copied_again) == expected
    assert value is not copied and value is not copied_again and copied is not copied_again
    assert all(type(leaf) in (str, int, datetime, type(None)) for leaf in expected)
    assert value.checked_at.tzinfo is UTC and value.valid_until.tzinfo is UTC
    assert MAX_RECONCILIATION_COUNTER == 9223372036854775807
    assert MAX_OWNER_DEPENDENCIES_BYTES == 262144
    if index == 0:
        assert len(value.account_id) == 1 and " " in value.stream_id and "λ" in value.stream_id
    else:
        assert len(value.account_id) == len(value.stream_id) == 128
        assert len(value.account_id.encode("utf-8")) > 128
    digest_values = [
        values[name]
        for name in _FIELD_NAMES
        if name.endswith("sha256") and values[name] is not None
    ]
    assert len(digest_values) == len(set(digest_values))
    assert len({value.effect_watermark, value.control_revision, value.lease_generation}) == 3
    assert type(first) is type(second) is tuple and len(first) == len(second) == 3
    assert first == second == bridge_expected
    for left, right, original_class in zip(
        first,
        second,
        (ContinuousAccountScope, ReconciliationHeads, ContinuousEvidenceRef),
        strict=True,
    ):
        assert type(left) is type(right) is original_class and left is not right
    assert first[2].object_ref is not second[2].object_ref
    assert type(first[2].object_ref) is ObjectRef
    assert first[0].environment == "stateful_simulation"
    assert first[2].schema_id == "runtime-owner-dependencies/1"
    assert first[2].object_ref.codec_version == "personal-record/1"
    assert first[2].object_ref.object_sha256 == values["dependency_object_sha256"]
    assert first[2].semantic_sha256 == values["dependency_semantic_sha256"]
    assert first[2].object_ref.object_sha256 != first[2].semantic_sha256


@pytest.mark.parametrize(
    "field,invalid",
    [
        ("account_id", ""),
        ("stream_id", " padded"),
        ("account_id", "a" * 129),
        ("stream_id", "trailing "),
    ],
)
def test_original_identifier_rules_reject_representative_invalid_values(field, invalid):
    values = _values()
    values[field] = invalid
    _deny_constructor(values)


@pytest.mark.parametrize(
    "field,invalid",
    [
        ("after_assignment_sha256", "AB" * 32),
        ("dependency_semantic_sha256", "7" * 63),
        ("original_lease_sha256", "g" * 64),
    ],
)
def test_digest_roles_keep_original_lowercase_length_and_character_rules(field, invalid):
    values = _values()
    values[field] = invalid
    _deny_constructor(values)


@pytest.mark.parametrize(
    "field,invalid",
    [
        ("effect_watermark", -1),
        ("control_revision", 9223372036854775808),
        ("lease_generation", -1),
        ("dependency_byte_count", 0),
        ("dependency_byte_count", -1),
        ("dependency_byte_count", 262145),
    ],
)
def test_original_counter_and_narrow_dependency_byte_bounds(field, invalid):
    values = _values()
    values[field] = invalid
    _deny_constructor(values)


@pytest.mark.parametrize(
    "field,invalid",
    [
        ("dependency_schema_id", "runtime-owner-dependencies/2"),
        ("dependency_codec_version", "personal-provider-json/1"),
    ],
)
def test_dependency_schema_and_codec_are_exact_required_native_literals(field, invalid):
    values = _values()
    values[field] = invalid
    _deny_constructor(values)


@pytest.mark.parametrize("field", [name for name in _FIELD_NAMES if name != "control_sha256"])
def test_every_required_flat_field_rejects_null(field):
    values = _values()
    values[field] = None
    _deny_constructor(values)


def _hostile(kind, calls):
    def forbidden(*args, **kwargs):
        calls.append(kind)
        raise AssertionError("a non-native leaf callback was invoked")

    if kind == "str":

        class HostileString(str):
            __eq__ = forbidden
            __len__ = forbidden
            __str__ = forbidden
            strip = forbidden
            encode = forbidden

        return HostileString("a" * 64)
    if kind == "int":

        class HostileInt(int):
            __eq__ = forbidden
            __lt__ = forbidden
            __le__ = forbidden
            __gt__ = forbidden
            __ge__ = forbidden
            __int__ = forbidden
            __index__ = forbidden

        return HostileInt(1)
    assert kind == "datetime"

    class HostileDateTime(datetime):
        __eq__ = forbidden
        __lt__ = forbidden
        __sub__ = forbidden
        utcoffset = forbidden
        tzinfo = property(forbidden)

    return HostileDateTime(2026, 10, 28, 14, tzinfo=UTC)


@pytest.mark.parametrize(
    "field,kind",
    [
        ("effect_watermark", "bool"),
        ("control_revision", "bool"),
        ("lease_generation", "bool"),
        ("dependency_byte_count", "bool"),
        ("control_revision", "float"),
        ("dependency_byte_count", "int"),
        ("after_assignment_sha256", "str"),
        ("checked_at", "datetime"),
    ],
)
def test_native_admission_does_not_call_subclass_operators_or_coercions(field, kind):
    calls = []
    values = _values()
    values[field] = True if kind == "bool" else 0.0 if kind == "float" else _hostile(kind, calls)
    _deny_constructor(values)
    assert calls == []


def _custom_utc(calls):
    class CustomUTC(tzinfo):
        def utcoffset(self, value):
            calls.append("utcoffset")
            return timedelta(0)

        def dst(self, value):
            calls.append("dst")
            return timedelta(0)

        def tzname(self, value):
            calls.append("tzname")
            return "custom UTC"

    return CustomUTC()


@pytest.mark.parametrize("field", ["checked_at", "valid_until"])
def test_exact_datetime_with_custom_zero_offset_timezone_denies_without_callbacks(field):
    calls = []
    values = _values()
    values[field] = datetime(2026, 10, 28, 14, tzinfo=_custom_utc(calls))
    _deny_constructor(values)
    assert calls == []


@pytest.mark.parametrize(
    "invalid",
    [
        "naive-checked",
        "naive-until",
        "nonutc-checked",
        "nonutc-until",
        "equal",
        "reversed",
        "over60",
    ],
)
def test_original_interval_and_new_utc_representation_boundaries(invalid):
    values = _values()
    if invalid.startswith("naive"):
        field = "checked_at" if invalid.endswith("checked") else "valid_until"
        values[field] = datetime(2026, 10, 28, 14)
    elif invalid.startswith("nonutc"):
        field = "checked_at" if invalid.endswith("checked") else "valid_until"
        values[field] = datetime(2026, 10, 28, 14, tzinfo=timezone(timedelta(hours=1)))
    elif invalid == "equal":
        values["valid_until"] = values["checked_at"]
    elif invalid == "reversed":
        values["checked_at"], values["valid_until"] = values["valid_until"], values["checked_at"]
    else:
        values["valid_until"] = values["checked_at"] + timedelta(seconds=60, microseconds=1)
    _deny_constructor(values)


@pytest.mark.parametrize("kind", ["foreign", "subclass"])
def test_copy_and_conversion_require_exact_descriptor_before_attribute_access(kind):
    calls = []

    def forbidden(self, name):
        calls.append(name)
        raise AssertionError("foreign descriptor fields were read")

    if kind == "foreign":

        class Foreign:
            __getattribute__ = forbidden

        value = Foreign()
    else:

        class Derived(descriptor.InitialSelectionDescriptor):
            __getattribute__ = forbidden

        value = object.__new__(Derived)
    for operation in (
        descriptor.copy_initial_selection_descriptor,
        descriptor.initial_selection_request_data,
    ):
        with pytest.raises(ValueError, match=_ERROR):
            operation(value)
    assert calls == []


def test_last_field_native_failure_precedes_all_original_validators_and_constructors(monkeypatch):
    values = _values()
    value = descriptor.InitialSelectionDescriptor(**values)
    callbacks = []
    bad = _hostile("str", callbacks)
    values["original_lease_sha256"] = bad
    object.__setattr__(value, "original_lease_sha256", bad)
    domain_calls = []

    def observer(name, original):
        def forward(*args, **kwargs):
            domain_calls.append(name)
            return original(*args, **kwargs)

        return forward

    for name in (
        "journal_identifier",
        "require_digest",
        "ContinuousAccountScope",
        "ReconciliationHeads",
        "ObjectRef",
        "ContinuousEvidenceRef",
    ):
        monkeypatch.setattr(descriptor, name, observer(name, getattr(descriptor, name)))
    _deny_constructor(values)
    for operation in (
        descriptor.copy_initial_selection_descriptor,
        descriptor.initial_selection_request_data,
    ):
        with pytest.raises(ValueError, match=_ERROR):
            operation(value)
    assert callbacks == [] and domain_calls == []


@pytest.mark.parametrize("mutation", ["bytes", "digest", "timezone"])
def test_mutated_descriptor_is_revalidated_by_both_public_operations(mutation):
    value = descriptor.InitialSelectionDescriptor(**_values())
    calls = []
    if mutation == "bytes":
        object.__setattr__(value, "dependency_byte_count", 262145)
    elif mutation == "digest":
        object.__setattr__(value, "control_sha256", "not-a-digest")
    else:
        object.__setattr__(
            value, "checked_at", datetime(2026, 10, 28, 14, tzinfo=_custom_utc(calls))
        )
    for operation in (
        descriptor.copy_initial_selection_descriptor,
        descriptor.initial_selection_request_data,
    ):
        with pytest.raises(ValueError, match=_ERROR):
            operation(value)
    assert calls == []


def test_shape_valid_caller_mutation_and_nested_output_mutation_do_not_change_siblings():
    values = _values(1)
    expected = tuple(values[name] for name in _FIELD_NAMES)
    source = descriptor.InitialSelectionDescriptor(**values)
    left = descriptor.copy_initial_selection_descriptor(source)
    right = descriptor.copy_initial_selection_descriptor(source)
    object.__setattr__(left, "ledger_sha256", "9" * 64)
    object.__setattr__(left, "control_sha256", None)
    assert _snapshot(source) == _snapshot(right) == expected
    assert tuple(values[name] for name in _FIELD_NAMES) == expected
    changed = descriptor.copy_initial_selection_descriptor(left)
    assert changed is not left and _snapshot(changed) == _snapshot(left)
    changed_bridge = descriptor.initial_selection_request_data(left)
    assert changed_bridge[1].ledger_sha256 == "9" * 64
    first = descriptor.initial_selection_request_data(source)
    object.__setattr__(first[0], "stream_id", "caller-changed-stream")
    object.__setattr__(first[1], "effect_watermark", -1)
    object.__setattr__(first[2].object_ref, "object_sha256", "0" * 64)
    object.__setattr__(first[2], "semantic_sha256", "1" * 64)
    second = descriptor.initial_selection_request_data(source)
    assert second == _expected_bridge(values)
    assert _snapshot(source) == _snapshot(right) == expected
    assert all(old is not new for old, new in zip(first, second, strict=True))
    assert first[2].object_ref is not second[2].object_ref


@pytest.mark.parametrize("operation", ["copy", "conversion"])
def test_validated_snapshot_is_consumed_when_caller_changes_before_build(monkeypatch, operation):
    # Pure transport observation: forward the complete real validator, mutate
    # only the caller DTO after success, and return its unchanged native tuple.
    # This models no prepared owner, authentication, or financial publication.
    values = _values(1)
    original_values = tuple(values[name] for name in _FIELD_NAMES)
    source = descriptor.InitialSelectionDescriptor(**values)
    replacements = _values(0)
    replacements["dependency_schema_id"] = "caller-mutated-schema"
    replacements["dependency_codec_version"] = "caller-mutated-codec"
    replacements["dependency_byte_count"] = 0
    saved_validator = descriptor._validated_values
    observed = []

    def forward_and_mutate(native_values):
        validated = saved_validator(native_values)
        observed.append(validated)
        if len(observed) == 1:
            for name in _FIELD_NAMES:
                object.__setattr__(source, name, replacements[name])
        return validated

    monkeypatch.setattr(descriptor, "_validated_values", forward_and_mutate)
    if operation == "copy":
        result = descriptor.copy_initial_selection_descriptor(source)
        assert result is not source
        assert _snapshot(result) == original_values
    else:
        result = descriptor.initial_selection_request_data(source)
        assert result == _expected_bridge(values)
    assert type(observed[0]) is tuple and observed[0] == original_values
    assert _snapshot(source) == tuple(replacements[name] for name in _FIELD_NAMES)
    assert _snapshot(source) != original_values
