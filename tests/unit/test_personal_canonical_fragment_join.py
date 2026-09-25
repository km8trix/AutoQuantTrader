"""Check deferred fragment placement against the independent original encoder.

The contract concerns bytes, public conversion/serialization hooks and errors;
private helper calls and exact resource-exhaustion boundaries are not promised.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import date
from decimal import Decimal

import pytest

from packages.domain import canonical
from tests.unit.test_personal_canonical_tuple_dispatch import (
    _legacy_canonical_json_bytes as _legacy_bytes,
)


def _outcome(encode, factory):
    reads = []
    value = factory(reads)
    try:
        encoded = encode(value)
        result = ("return", type(encoded), encoded, hashlib.sha256(encoded).hexdigest())
    except Exception as error:
        cause = error.__cause__
        result = (
            "error",
            type(error),
            str(error),
            None if cause is None else (type(cause), str(cause)),
        )
    return result, reads


@pytest.mark.parametrize(
    "value",
    [
        Decimal("1.00"),
        (Decimal("1.00"), "tail"),
        ("head", Decimal("1.00")),
        ((), (Decimal("1.00"), (), (Decimal("2.00"),)), ()),
        (Decimal("1.00"), "between", Decimal("2.00"), False, Decimal("3.00")),
        (None, True, 7, "\ud800", b"\x00", ()),
    ],
)
def test_root_nested_and_separated_fallbacks_preserve_complete_wire_identity(value):
    expected = _legacy_bytes(value)
    actual = canonical.canonical_json_bytes(value)
    assert actual == expected
    assert hashlib.sha256(actual).digest() == hashlib.sha256(expected).digest()


def test_repeated_aliases_preserve_each_conversion_and_later_nested_mutation():
    def factory(reads):
        shared = ["before"]

        class SharedDate(date):
            def isoformat(self):
                reads.append("shared.isoformat")
                return shared

        class MutatingDate(date):
            def isoformat(self):
                reads.append("mutating.isoformat")
                shared.append("after")
                return "last"

        alias = SharedDate(2026, 9, 24)
        return (alias, ("separator", alias, ()), MutatingDate(2026, 9, 24))

    expected = _outcome(_legacy_bytes, factory)
    actual = _outcome(canonical.canonical_json_bytes, factory)
    assert actual == expected
    assert actual[0][0] == "return"
    assert actual[0][2].count(b'"value":["before","after"]') == 2
    assert actual[1] == ["shared.isoformat", "shared.isoformat", "mutating.isoformat"]


def test_first_fallback_serialization_can_mutate_later_fallback_output():
    def factory(reads):
        shared = ["before"]

        class MutatingList(list):
            def __iter__(self):
                reads.append("first.serialize")
                shared.append("after")
                return super().__iter__()

        class FirstDate(date):
            def isoformat(self):
                reads.append("first.convert")
                return MutatingList(["first"])

        class LaterDate(date):
            def isoformat(self):
                reads.append("later.convert")
                return shared

        return ((FirstDate(2026, 9, 24), "separator"), (), LaterDate(2026, 9, 24))

    expected = _outcome(_legacy_bytes, factory)
    actual = _outcome(canonical.canonical_json_bytes, factory)
    assert actual == expected
    assert actual[0][0] == "return"
    assert b'"value":["before","after"]' in actual[0][2]
    assert actual[1] == ["first.convert", "later.convert", "first.serialize"]


@pytest.mark.parametrize("reverse", [False, True])
def test_first_serialization_error_wins_after_all_conversion_hooks(reverse):
    def factory(reads):
        class InvalidDate(date):
            def isoformat(self):
                reads.append("bytes.convert")
                return b"invalid-json-value"

        class OtherInvalidDate(date):
            def isoformat(self):
                reads.append("object.convert")
                return object()

        values = (InvalidDate(2026, 9, 24), OtherInvalidDate(2026, 9, 24))
        if reverse:
            values = tuple(reversed(values))
        return (values[0], ("separator", values[1]))

    expected = _outcome(_legacy_bytes, factory)
    actual = _outcome(canonical.canonical_json_bytes, factory)
    assert actual == expected
    kind = "object" if reverse else "bytes"
    assert actual[0] == (
        "error",
        TypeError,
        f"Object of type {kind} is not JSON serializable",
        None,
    )
    assert actual[1] == (
        ["object.convert", "bytes.convert"] if reverse else ["bytes.convert", "object.convert"]
    )


def test_later_conversion_error_precedes_earlier_pending_serialization_error():
    def factory(reads):
        class InvalidDate(date):
            def isoformat(self):
                reads.append("date.convert")
                return b"invalid-json-value"

        class FailingMapping(Mapping):
            def __iter__(self):
                raise AssertionError("not reached")

            def __len__(self):
                raise AssertionError("not reached")

            def __getitem__(self, key):
                raise AssertionError("not reached")

            def items(self):
                reads.append("mapping.convert")
                try:
                    raise KeyError("original-cause")
                except KeyError as error:
                    raise ValueError("conversion-failed") from error

        return (InvalidDate(2026, 9, 24), ("separator", FailingMapping()))

    expected = _outcome(_legacy_bytes, factory)
    actual = _outcome(canonical.canonical_json_bytes, factory)
    assert actual == expected
    assert actual[0] == ("error", ValueError, "conversion-failed", (KeyError, "'original-cause'"))
    assert actual[1] == ["date.convert", "mapping.convert"]


def test_failed_call_does_not_leave_pending_output_for_later_calls():
    class ChangeableDate(date):
        output = b"invalid-json-value"

        def isoformat(self):
            return self.output

    value = ("head", ChangeableDate(2026, 9, 24), (Decimal("1.00"),))
    with pytest.raises(TypeError, match="Object of type bytes is not JSON serializable"):
        canonical.canonical_json_bytes(value)
    ChangeableDate.output = "valid"
    assert canonical.canonical_json_bytes(value) == _legacy_bytes(value)
