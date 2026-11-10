"""Primitive dispatch must preserve wire types, bounds and fallback behavior."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import ClassVar, Literal

import pytest

from packages.application.personal_codec import decode_record, encode_record

type _CountAlias = int


class _Text(str):
    pass


class _Count(int):
    pass


class _Word(StrEnum):
    HALTED = "halted"


class _Rank(IntEnum):
    FIRST = 1


@dataclass(frozen=True)
class _Record:
    count: _CountAlias
    enabled: bool
    label: str
    optional: int | None
    kind: Literal["plain"]
    values: tuple[int, bool, str]
    constructions: ClassVar[list[int]] = []

    def __post_init__(self):
        if self.count < 0:
            raise ValueError("count must be nonnegative")
        self.constructions.append(self.count)


def _wire(value):
    return (
        json.dumps(
            {"codec": "personal-record/1", "value": value},
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


@pytest.mark.parametrize(
    ("value", "token"),
    [
        (None, b"null"),
        (False, b"false"),
        (True, b"true"),
        (0, b"0"),
        (-17, b"-17"),
        (9007199254740993, b"9007199254740993"),
        ("", b'""'),
        ("\N{GREEK SMALL LETTER PI}", b'"\\u03c0"'),
    ],
)
def test_exact_primitives_keep_canonical_wire_and_exact_type(value, token):
    payload = b'{"codec":"personal-record/1","value":' + token + b"}\n"
    assert encode_record(value) == payload
    actual = decode_record(payload, type(value))
    assert type(actual) is type(value)
    assert actual == value


@pytest.mark.parametrize(
    ("value", "expected_type"), [(True, int), (1, bool), (None, str), ("", type(None))]
)
def test_primitive_mismatch_cannot_coerce(value, expected_type):
    with pytest.raises(ValueError, match="research scalar type differs"):
        decode_record(encode_record(value), expected_type)


@pytest.mark.parametrize(("value", "subclass"), [("x", _Text), (1, _Count)])
def test_scalar_subclasses_remain_outside_exact_primitive_dispatch(value, subclass):
    with pytest.raises(ValueError, match="unsupported research record value"):
        encode_record(subclass(value))
    with pytest.raises(ValueError, match="research scalar type differs"):
        decode_record(encode_record(value), subclass)


def test_string_enum_keeps_declared_wrapper_and_type():
    payload = encode_record(_Word.HALTED)
    assert json.loads(payload)["value"] == {
        "$enum": f"{_Word.__module__}.{_Word.__qualname__}",
        "value": "halted",
    }
    assert decode_record(payload, _Word) is _Word.HALTED


def test_integer_enum_keeps_wrapper_and_existing_decode_rejection():
    payload = encode_record(_Rank.FIRST)
    assert json.loads(payload)["value"] == {
        "$enum": f"{_Rank.__module__}.{_Rank.__qualname__}",
        "value": 1,
    }
    with pytest.raises(ValueError, match="research enum requires text"):
        decode_record(payload, _Rank)


def test_alias_union_literal_tuple_and_each_constructor_remain_in_force(monkeypatch):
    source = _Record(7, True, "sample", None, "plain", (2, False, "x"))
    payload = encode_record(source)
    monkeypatch.setattr(_Record, "constructions", [])
    first = decode_record(payload, _Record)
    second = decode_record(payload, _Record)
    assert first == second == source
    assert first is not second
    assert _Record.constructions == [7, 7]
    assert type(first.count) is int
    assert type(first.enabled) is bool
    assert tuple(type(item) for item in first.values) == (int, bool, str)


@pytest.mark.parametrize(
    ("field", "replacement", "error"),
    [
        ("count", True, "research scalar type differs"),
        ("count", -1, "count must be nonnegative"),
        ("optional", "x", "research record does not match declared union"),
        ("kind", True, "invalid research literal"),
        ("values", [True, False, "x"], "research scalar type differs"),
    ],
)
def test_nested_primitive_edits_cannot_skip_type_or_constructor_checks(field, replacement, error):
    source = _Record(7, True, "sample", None, "plain", (2, False, "x"))
    record = json.loads(encode_record(source))["value"]
    record["fields"][field] = replacement
    with pytest.raises(ValueError, match=error):
        decode_record(_wire(record), _Record)


def test_dataclass_encoding_preserves_metaclass_equality_and_field_read_order():
    reads = []

    class ObservedType(type):
        def __eq__(cls, other):
            reads.append("class equality")
            return super().__eq__(other)

        __hash__ = type.__hash__

    @dataclass(frozen=True)
    class ObservedRecord(metaclass=ObservedType):
        label: str
        count: int

        def __getattribute__(self, name):
            if name in ("label", "count"):
                reads.append(name)
            return object.__getattribute__(self, name)

    source = ObservedRecord("sample", 3)
    reads.clear()
    payload = encode_record(source)
    assert reads == ["label", "count"]
    assert json.loads(payload)["value"] == {
        "$record": f"{ObservedRecord.__module__}.{ObservedRecord.__qualname__}",
        "fields": {"label": "sample", "count": 3},
    }


@pytest.mark.parametrize(
    ("payload", "expected_type"),
    [
        (b'{"codec":"personal-record/1","value":true}', bool),
        (b'{"codec":"personal-record/1", "value":true}\n', bool),
        (b'{"codec":"personal-record/1","value":"\\u0078"}\n', str),
    ],
)
def test_primitive_success_does_not_skip_canonical_reencoding(payload, expected_type):
    with pytest.raises(ValueError, match="research record is not canonical"):
        decode_record(payload, expected_type)


def test_text_bound_is_preserved_on_encode_and_decode():
    boundary = "x" * 65536
    assert decode_record(encode_record(boundary), str) == boundary
    with pytest.raises(ValueError, match="research text exceeds limit"):
        encode_record(boundary + "x")
    with pytest.raises(ValueError, match="invalid research text"):
        decode_record(_wire(boundary + "x"), str)


@pytest.mark.parametrize("depth", [64, 65])
def test_primitive_leaf_cannot_bypass_nesting_bound(depth):
    value = "leaf"
    annotation = str
    for _ in range(depth):
        value = (value,)
        annotation = tuple[annotation]
    payload = _wire(value)
    if depth == 64:
        assert encode_record(value) == payload
        assert decode_record(payload, annotation) == value
    else:
        with pytest.raises(ValueError, match="research record nesting exceeds limit"):
            encode_record(value)
        with pytest.raises(ValueError, match="research record nesting exceeds limit"):
            decode_record(payload, annotation)
