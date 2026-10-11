"""Independent byte and observable-hook oracles for exact two-string tuples.

These finite ordinary tests make no timing, ownership or financial acceptance
claim. The immediately preceding text chain is separate from the old full-tree
oracle because dynamic encoder lookup hooks are specific to that text chain.
"""

import json
from datetime import date
from enum import StrEnum
from hashlib import sha256

import pytest

from packages.domain import canonical
from tests.unit.test_personal_canonical_fallback_lifetime import (
    MAPPING_BYTES,
    ReplacementMapping,
    private_mapping,
)
from tests.unit.test_personal_canonical_tuple_dispatch import (
    _legacy_canonical_json_bytes as _legacy_bytes,
)
from tests.unit.test_personal_canonical_tuple_dispatch import (
    _legacy_json_text,
    _legacy_typed_node,
)


def _previous_append(value, parts, deferred):
    """Literal preceding tuple/scalar traversal, independent of new helpers."""
    if type(value) is tuple:
        parts.append('{"type":"tuple","value":[')
        items = value
        tuple_node = True
    else:
        items = (value,)
        tuple_node = False
    for index, item in enumerate(items):
        if index:
            parts.append(",")
        if type(item) is str:
            parts.append(
                f'{{"type":"string","value":{json.encoder.encode_basestring_ascii(item)}}}'
            )
        elif type(item) is tuple:
            _previous_append(item, parts, deferred)
        elif item is None:
            parts.append('{"type":"null","value":null}')
        elif type(item) is bool:
            parts.append(
                '{"type":"bool","value":true}' if item else '{"type":"bool","value":false}'
            )
        elif type(item) is int:
            parts.append(
                f'{{"type":"int","value":{json.encoder.encode_basestring_ascii(str(item))}}}'
            )
        elif type(item) is bytes:
            parts.append(
                f'{{"type":"bytes","value":{json.encoder.encode_basestring_ascii(item.hex())}}}'
            )
        else:
            converted = _legacy_typed_node(item)
            deferred.append((len(parts), converted))
            parts.append("")
    if tuple_node:
        parts.append("]}")


def _previous_fragment(part):
    if type(part) is str:
        return part
    if (
        type(part) is dict
        and len(part) == 2
        and "type" in part
        and "value" in part
        and type(part["type"]) is str
        and type(part["value"]) is str
    ):
        return (
            '{"type":'
            + json.encoder.encode_basestring_ascii(part["type"])
            + ',"value":'
            + json.encoder.encode_basestring_ascii(part["value"])
            + "}"
        )
    return _legacy_json_text(part)


def _previous_bytes(value):
    parts, deferred = [], []
    _previous_append(value, parts, deferred)
    for position, converted in deferred:
        parts[position] = _previous_fragment(converted)
    return "".join(parts).encode("utf-8")


def _observed(encode, factory):
    events = []
    value = factory(events)
    try:
        payload = encode(value)
        result = ("return", payload, sha256(payload).hexdigest())
    except Exception as error:
        cause = error.__cause__
        result = (
            "error",
            type(error),
            str(error),
            None if cause is None else (type(cause), str(cause)),
        )
    return result, events


@pytest.mark.parametrize(
    "pair,wire",
    [
        (
            ("left", "right"),
            b'{"type":"tuple","value":[{"type":"string","value":"left"},'
            b'{"type":"string","value":"right"}]}',
        ),
        (
            ("", ""),
            b'{"type":"tuple","value":[{"type":"string","value":""},{"type":"string","value":""}]}',
        ),
        (
            ('"\\\n\x00', "\t\r\b\f"),
            b'{"type":"tuple","value":[{"type":"string","value":"\\"\\\\\\n\\u0000"},'
            b'{"type":"string","value":"\\t\\r\\b\\f"}]}',
        ),
        (
            ("é中", "😀"),
            b'{"type":"tuple","value":[{"type":"string","value":"\\u00e9\\u4e2d"},'
            b'{"type":"string","value":"\\ud83d\\ude00"}]}',
        ),
        (
            ("\ud800", "\udfff"),
            b'{"type":"tuple","value":[{"type":"string","value":"\\ud800"},'
            b'{"type":"string","value":"\\udfff"}]}',
        ),
    ],
)
def test_literal_pair_bytes_hash_at_root_nested_and_repeated_alias(pair, wire):
    nested = b'{"type":"tuple","value":[' + wire + b"]}"
    repeated = b'{"type":"tuple","value":[' + wire + b"," + wire + b"]}"
    for value, expected in ((pair, wire), ((pair,), nested), ((pair, pair), repeated)):
        assert _legacy_bytes(value) == _previous_bytes(value) == expected
        payload = canonical.canonical_json_bytes(value)
        assert payload == expected
        assert sha256(payload).digest() == sha256(expected).digest()


@pytest.mark.parametrize("value", [(), ("only",), ("one", "two", "three")])
def test_other_tuple_lengths_keep_original_wire(value):
    for material in (value, (value,)):
        assert (
            canonical.canonical_json_bytes(material)
            == _previous_bytes(material)
            == _legacy_bytes(material)
        )


class _Text(str):
    def __format__(self, specification):
        raise AssertionError("string subclass formatting was reached")


class _Tuple(tuple):
    def __len__(self):
        raise AssertionError("tuple subclass length was reached")

    def __getitem__(self, key):
        raise AssertionError("tuple subclass indexing was reached")


class _Word(StrEnum):
    VALUE = "enum-word"


@pytest.mark.parametrize(
    "value",
    [
        (_Text("left"), "right"),
        ("left", _Text("right")),
        _Tuple(("left", "right")),
        (_Word.VALUE, "right"),
        ("left", _Word.VALUE),
    ],
)
def test_subclasses_and_string_enums_keep_original_fallback(value):
    for material in (value, (value,)):
        expected = _observed(_legacy_bytes, lambda _events, material=material: material)
        assert _observed(_previous_bytes, lambda _events, material=material: material) == expected
        assert (
            _observed(canonical.canonical_json_bytes, lambda _events, material=material: material)
            == expected
        )
        if any(type(item) is _Word for item in tuple.__iter__(value)):
            assert expected[0][0] == "return" and b'"type":"enum"' in expected[0][1]
        else:
            assert expected[0][0:2] == ("error", TypeError)


@pytest.mark.parametrize("position", [0, 1])
def test_first_invalid_pair_child_precedes_later_conversion_hook(position):
    def factory(events):
        class LaterDate(date):
            def isoformat(self):
                events.append("later.convert")
                return "later"

        invalid = (object(), "right") if position == 0 else ("left", object())
        return (invalid, ("valid", "pair"), LaterDate(2026, 10, 11))

    expected = _observed(_legacy_bytes, factory)
    assert _observed(_previous_bytes, factory) == expected
    assert _observed(canonical.canonical_json_bytes, factory) == expected
    assert expected[0][0:2] == ("error", TypeError) and expected[1] == []


def test_later_conversion_mutates_deferred_value_across_string_pair():
    def factory(events):
        shared = ["before"]

        class FirstDate(date):
            def isoformat(self):
                events.append("first.convert")
                return shared

        class LastDate(date):
            def isoformat(self):
                events.append("last.convert")
                shared.append("after")
                return "last"

        return (FirstDate(2026, 10, 11), ("separator", "pair"), LastDate(2026, 10, 11))

    expected = _observed(_legacy_bytes, factory)
    assert _observed(_previous_bytes, factory) == expected
    assert _observed(canonical.canonical_json_bytes, factory) == expected
    assert b'"value":["before","after"]' in expected[0][1]
    assert expected[1] == ["first.convert", "last.convert"]


def test_first_serialization_mutates_later_fallback_across_string_pair():
    def factory(events):
        shared = ["before"]

        class MutatingList(list):
            def __iter__(self):
                events.append("first.serialize")
                shared.append("after")
                return super().__iter__()

        class FirstDate(date):
            def isoformat(self):
                events.append("first.convert")
                return MutatingList(["first"])

        class LastDate(date):
            def isoformat(self):
                events.append("last.convert")
                return shared

        return (FirstDate(2026, 10, 11), ("separator", "pair"), LastDate(2026, 10, 11))

    expected = _observed(_legacy_bytes, factory)
    assert _observed(_previous_bytes, factory) == expected
    assert _observed(canonical.canonical_json_bytes, factory) == expected
    assert b'"value":["before","after"]' in expected[0][1]
    assert expected[1] == ["first.convert", "last.convert", "first.serialize"]


def test_deferred_serialization_error_follows_all_conversion_hooks_around_pair():
    def factory(events):
        class InvalidDate(date):
            def isoformat(self):
                events.append("invalid.convert")
                return b"invalid-json-value"

        class LastDate(date):
            def isoformat(self):
                events.append("last.convert")
                return "last"

        return (InvalidDate(2026, 10, 11), ("separator", "pair"), LastDate(2026, 10, 11))

    expected = _observed(_legacy_bytes, factory)
    assert _observed(_previous_bytes, factory) == expected
    assert _observed(canonical.canonical_json_bytes, factory) == expected
    assert expected == (
        ("error", TypeError, "Object of type bytes is not JSON serializable", None),
        ["invalid.convert", "last.convert"],
    )


def test_mapping_classes_release_before_and_after_pair_with_literal_bytes():
    events, lifetimes = [], []
    before, before_old, _before_state = private_mapping(
        label="before", events=events, lifetimes=lifetimes
    )
    after, after_old, _after_state = private_mapping(
        label="after", events=events, lifetimes=lifetimes
    )
    pair = ("separator", "pair")
    expected = (
        b'{"type":"tuple","value":['
        + MAPPING_BYTES
        + b","
        + _legacy_bytes(pair)
        + b","
        + MAPPING_BYTES
        + b"]}"
    )
    assert canonical.canonical_json_bytes((before, pair, after)) == expected
    assert events == ["before", "after"]
    assert lifetimes == [("before", False), ("after", False)]
    assert before_old() is None and after_old() is None
    assert before.__class__ is after.__class__ is ReplacementMapping


def test_mapping_failure_after_pair_preserves_exact_error_and_class_lifetime():
    events, lifetimes = [], []
    error = RuntimeError("selected mapping failure after pair")
    cause, context = LookupError("existing cause"), IndexError("existing context")
    error.__cause__, error.__context__ = cause, context
    before, _old_before, _before_state = private_mapping(
        label="before", events=events, lifetimes=lifetimes
    )
    after, old_after, _after_state = private_mapping(
        label="after", events=events, lifetimes=lifetimes, error=error
    )
    output = untouched = object()
    with pytest.raises(RuntimeError) as raised:
        output = canonical.canonical_json_bytes((before, ("separator", "pair"), after))
    assert raised.value is error and raised.value.__cause__ is cause
    assert raised.value.__context__ is context and raised.value.__suppress_context__
    assert output is untouched
    assert events == ["before", "after"]
    assert lifetimes == [("before", False), ("after", False)] and old_after() is None


def _dynamic_pair_outcome(encode, monkeypatch, failure):
    events = []
    error = RuntimeError("original second encoder failure")
    cause, context = LookupError("existing cause"), IndexError("existing context")
    error.__cause__, error.__context__ = cause, context

    class Formatted:
        def __init__(self, label):
            self.label = label

        def __format__(self, specification):
            assert specification == ""
            events.append("format:" + self.label)
            if self.label == "first":
                json.encoder = second
            elif failure == "format":
                raise error
            return '"' + self.label + '"'

    class Encoder:
        def __init__(self, label):
            self.label = label

        def __getattribute__(self, name):
            if name == "encode_basestring_ascii":
                label = object.__getattribute__(self, "label")
                events.append("lookup:" + label)
                if label == "second" and failure == "lookup":
                    raise error
            return object.__getattribute__(self, name)

        def encode_basestring_ascii(self, value):
            events.append("encode:" + self.label)
            assert value == ("left" if self.label == "first" else "right")
            if self.label == "second" and failure == "encode":
                raise error
            return Formatted(self.label)

    first, second = Encoder("first"), Encoder("second")
    with monkeypatch.context() as patch:
        patch.setattr(json, "encoder", first)
        try:
            payload = encode((("left", "right"),))
        except RuntimeError as caught:
            assert caught is error and caught.__cause__ is cause
            assert caught.__context__ is context and caught.__suppress_context__
            return ("error", tuple(events))
        return ("return", payload, tuple(events))


def test_pair_preserves_fresh_second_encoder_lookup_after_first_format(monkeypatch):
    expected = _dynamic_pair_outcome(_previous_bytes, monkeypatch, None)
    assert _dynamic_pair_outcome(canonical.canonical_json_bytes, monkeypatch, None) == expected
    assert expected == (
        "return",
        b'{"type":"tuple","value":[{"type":"tuple","value":['
        b'{"type":"string","value":"first"},{"type":"string","value":"second"}]}]}',
        (
            "lookup:first",
            "encode:first",
            "format:first",
            "lookup:second",
            "encode:second",
            "format:second",
        ),
    )


@pytest.mark.parametrize("failure", ["lookup", "encode", "format"])
def test_pair_second_failure_keeps_identity_cause_context_and_original_first_format(
    monkeypatch, failure
):
    expected = _dynamic_pair_outcome(_previous_bytes, monkeypatch, failure)
    assert _dynamic_pair_outcome(canonical.canonical_json_bytes, monkeypatch, failure) == expected
    all_events = (
        "lookup:first",
        "encode:first",
        "format:first",
        "lookup:second",
        "encode:second",
        "format:second",
    )
    end = {"lookup": 4, "encode": 5, "format": 6}[failure]
    assert expected == ("error", all_events[:end])
