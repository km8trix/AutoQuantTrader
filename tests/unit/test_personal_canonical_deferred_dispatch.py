"""Retain the old encoding oracle and observable hooks for finite tuple graphs.

Private recursive helper call counts are implementation details. Interpreter
recursion thresholds are excluded; cycles must still fail instead of encoding.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import UTC, date, datetime
from decimal import Decimal, Inexact, Rounded, localcontext
from enum import Enum, IntEnum, StrEnum
from uuid import UUID

import pytest

from packages.domain import canonical
from tests.unit.test_personal_canonical_tuple_dispatch import (
    _legacy_canonical_json_bytes as _legacy_bytes,
)

_READS = []


class _Word(StrEnum):
    VALUE = "value"


class _Number(IntEnum):
    VALUE = 1


class _ObservedEnum(Enum):
    VALUE = ("wrapped", 1, False)

    def __getattribute__(self, name):
        if name == "value":
            _READS.append("enum.value")
        return super().__getattribute__(name)


class _Text(str):
    pass


class _Integer(int):
    pass


class _Tuple(tuple):
    pass


class _List(list):
    pass


class _ObservedMapping(Mapping):
    def __init__(self, later=None):
        self.later = later

    def __iter__(self):
        return iter(("later",))

    def __len__(self):
        return 1

    def __getitem__(self, key):
        if key != "later":
            raise KeyError(key)
        _READS.append("mapping.value")
        return True

    def items(self):
        _READS.append("mapping.items")
        if self.later is not None:
            self.later()
        return super().items()


class _InvalidDate(date):
    def isoformat(self):
        _READS.append("date.isoformat")
        return b"not-json-serializable"


class _RaisingMapping(_ObservedMapping):
    def items(self):
        _READS.append("mapping.raises")
        try:
            raise KeyError("mapping-root-cause")
        except KeyError as error:
            raise ValueError("mapping-conversion-failed") from error


def _outcome(encode, factory):
    value = factory()
    _READS.clear()
    try:
        actual = encode(value)
        result = ("return", type(actual), actual, hashlib.sha256(actual).hexdigest())
    except Exception as error:
        cause = error.__cause__
        result = (
            "error",
            type(error),
            str(error),
            None if cause is None else (type(cause), str(cause)),
        )
    return result, tuple(_READS)


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
        0,
        -(2**100),
        '"\\\n\x00',
        "éπ中😀",
        "\ud800",
        "\udfff",
        "\ud800\udfff",
        bytes(range(256)),
        Decimal("12345678901234567890123456789.1000"),
        Decimal("-0.000"),
        date(2025, 1, 1),
        datetime(2025, 1, 1, tzinfo=UTC),
        UUID(int=7),
        _Word.VALUE,
        _Number.VALUE,
        _ObservedEnum.VALUE,
        {"z": (Decimal("1.00"),), "a": [True, 7]},
        {"x", 2, (3, False)},
        frozenset({"x", 2}),
        ["list", ("tuple", None)],
    ],
)
def test_mixed_tuple_bytes_hashes_and_external_reads_match_original_chain(value):
    def factory():
        return ("before", (value, True, 1, "1"), "after")

    expected = _outcome(_legacy_bytes, factory)
    actual = _outcome(canonical.canonical_json_bytes, factory)
    assert actual == expected
    assert actual[0][0] == "return"


def test_primitive_tags_and_escapes_keep_literal_wire_contract():
    assert canonical.canonical_json_bytes((None, True, 7, "x", b"\x00")) == (
        b'{"type":"tuple","value":[{"type":"null","value":null},'
        b'{"type":"bool","value":true},{"type":"int","value":"7"},'
        b'{"type":"string","value":"x"},{"type":"bytes","value":"00"}]}'
    )
    assert canonical.canonical_json_text("\ud800") == '{"type":"string","value":"\\ud800"}'
    assert canonical.canonical_json_text("😀") == ('{"type":"string","value":"\\ud83d\\ude00"}')


@pytest.mark.parametrize(
    "value",
    [
        _Text("x"),
        _Integer(1),
        _Tuple((1,)),
        _List([1]),
        1.25,
        bytearray(b"x"),
        Decimal("NaN"),
        Decimal("Infinity"),
        datetime(2025, 1, 1),
    ],
)
def test_invalid_values_preserve_error_type_message_and_read_order(value):
    def factory():
        return (value, _ObservedEnum.VALUE, _ObservedMapping())

    expected = _outcome(_legacy_bytes, factory)
    actual = _outcome(canonical.canonical_json_bytes, factory)
    assert actual == expected
    assert actual[0][0] == "error"


def test_fallback_json_failure_occurs_after_later_conversion_hooks():
    def factory():
        return (_InvalidDate(2025, 1, 1), _ObservedEnum.VALUE, _ObservedMapping())

    expected = _outcome(_legacy_bytes, factory)
    actual = _outcome(canonical.canonical_json_bytes, factory)
    assert actual == expected
    assert actual[0] == ("error", TypeError, "Object of type bytes is not JSON serializable", None)
    assert actual[1] == ("date.isoformat", "enum.value", "mapping.items", "mapping.value")


def test_conversion_failure_preserves_its_cause_and_stops_before_later_hooks():
    def factory():
        return (_RaisingMapping(), _ObservedEnum.VALUE)

    expected = _outcome(_legacy_bytes, factory)
    actual = _outcome(canonical.canonical_json_bytes, factory)
    assert actual == expected
    assert actual[0] == (
        "error",
        ValueError,
        "mapping-conversion-failed",
        (KeyError, "'mapping-root-cause'"),
    )
    assert actual[1] == ("mapping.raises",)


def test_aliases_repeat_hooks_and_mutation_between_calls_changes_bytes():
    shared = [_ObservedEnum.VALUE, "before"]
    value = (shared, shared)

    def factory():
        return value

    before = _outcome(canonical.canonical_json_bytes, factory)
    assert before == _outcome(_legacy_bytes, factory)
    assert before[1] == ("enum.value", "enum.value")
    shared.append("after")
    after = _outcome(canonical.canonical_json_bytes, factory)
    assert after == _outcome(_legacy_bytes, factory)
    assert after[1] == ("enum.value", "enum.value")
    assert before[0][2] != after[0][2]


def test_later_conversion_mutation_is_visible_to_deferred_fallback_serialization():
    def factory():
        shared = ["before"]

        class MutableDate(date):
            def isoformat(self):
                _READS.append("date.isoformat")
                return shared

        def change():
            _READS.append("mutate-earlier-list")
            shared.append("after")

        return (MutableDate(2025, 1, 1), _ObservedMapping(later=change))

    expected = _outcome(_legacy_bytes, factory)
    actual = _outcome(canonical.canonical_json_bytes, factory)
    assert actual == expected
    assert actual[0][0] == "return"
    assert b'"value":["before","after"]' in actual[0][2]
    assert actual[1] == ("date.isoformat", "mapping.items", "mutate-earlier-list", "mapping.value")


@pytest.mark.parametrize("precision", [1, 2, 28, 80])
def test_mixed_decimal_fallback_is_context_free(precision):
    value = ((Decimal("12345678901234567890123456789.1000"), Decimal("-0.000")), True)
    expected = _legacy_bytes(value)
    with localcontext() as context:
        context.prec = precision
        context.traps[Inexact] = True
        context.traps[Rounded] = True
        assert canonical.canonical_json_bytes(value) == expected


def test_finite_nested_tuple_uses_same_original_encoding():
    value = (None, True, "leaf")
    for _ in range(64):
        value = (value,)
    assert canonical.canonical_json_bytes(value) == _legacy_bytes(value)


@pytest.mark.parametrize("wrap_tuple", [False, True])
def test_cycles_still_reject_without_promising_interpreter_recursion_threshold(wrap_tuple):
    cycle = []
    cycle.append(cycle)
    value = (cycle,) if wrap_tuple else cycle
    for encode in (_legacy_bytes, canonical.canonical_json_bytes):
        with pytest.raises(RecursionError):
            encode(value)


@pytest.mark.parametrize(
    "converted_value",
    ["", '"\\\n\x00', "éπ中😀", "\ud800\udfff", _Text("subclass\nπ"), None, 17, True],
)
def test_converted_date_values_keep_original_escaping_types_and_later_hooks(converted_value):
    class ConvertedDate(date):
        def isoformat(self):
            _READS.append("converted-date.isoformat")
            return converted_value

    def factory():
        return (ConvertedDate(2025, 1, 1), _ObservedEnum.VALUE, _ObservedMapping())

    expected = _outcome(_legacy_bytes, factory)
    actual = _outcome(canonical.canonical_json_bytes, factory)
    assert actual == expected
    assert actual[0][0] == "return"
    assert actual[1] == ("converted-date.isoformat", "enum.value", "mapping.items", "mapping.value")
