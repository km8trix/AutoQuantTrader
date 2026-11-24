"""Finite native field-pair bytes and public hook regressions.

The independent original tree oracle and literal preceding traversal bind observable
bytes, hook/error order and selected lifetimes. Private fragment/frame layout, changed
builtins, arbitrary instrumentation, resource thresholds and financial fit are excluded.
"""

import json
import sys
import weakref
from datetime import date
from decimal import Decimal
from enum import Enum
from hashlib import sha256

import pytest

from packages.domain import canonical
from tests.unit import test_personal_canonical_string_tuple_pairs as preceding
from tests.unit.test_personal_canonical_tuple_dispatch import (
    _legacy_canonical_json_bytes as _legacy_bytes,
)

_TUPLE = b'{"type":"tuple","value":['
_NULL = b'{"type":"null","value":null}'
_FIELD = b'{"type":"string","value":"field"},'


def _shape(pair, wire, shape):
    if shape == "root":
        return pair, wire
    if shape == "nested":
        return (pair,), _TUPLE + wire + b"]}"
    if shape == "leading-null":
        return (None, pair), _TUPLE + _NULL + b"," + wire + b"]}"
    assert shape == "repeated-alias"
    return (pair, pair), _TUPLE + wire + b"," + wire + b"]}"


@pytest.mark.parametrize("shape", ["root", "nested", "leading-null", "repeated-alias"])
@pytest.mark.parametrize(
    "name,value,first,second",
    [
        ("field", None, _FIELD, _NULL),
        ("field", False, _FIELD, b'{"type":"bool","value":false}'),
        ("field", True, _FIELD, b'{"type":"bool","value":true}'),
        ("field", 0, _FIELD, b'{"type":"int","value":"0"}'),
        ("field", -7, _FIELD, b'{"type":"int","value":"-7"}'),
        ("field", 2**100, _FIELD, b'{"type":"int","value":"1267650600228229401496703205376"}'),
        ("field", -(2**100), _FIELD, b'{"type":"int","value":"-1267650600228229401496703205376"}'),
        ("field", 10**100, _FIELD, b'{"type":"int","value":"1' + b"0" * 100 + b'"}'),
        ("field", -(10**100), _FIELD, b'{"type":"int","value":"-1' + b"0" * 100 + b'"}'),
        ("field", b"", _FIELD, b'{"type":"bytes","value":""}'),
        ("field", b'\x00\xff"\\\n', _FIELD, b'{"type":"bytes","value":"00ff225c0a"}'),
        (
            '"\\\n\x00é\ud800',
            b"\x00",
            b'{"type":"string","value":"\\"\\\\\\n\\u0000\\u00e9\\ud800"},',
            b'{"type":"bytes","value":"00"}',
        ),
    ],
    ids=[
        "none",
        "false",
        "true",
        "zero",
        "negative",
        "large",
        "large-negative",
        "power",
        "power-negative",
        "empty-bytes",
        "bytes",
        "escaping",
    ],
)
def test_literal_native_field_pair_wire_and_hash(name, value, first, second, shape):
    material, wire = _shape((name, value), _TUPLE + first + second + b"]}", shape)
    assert _legacy_bytes(material) == preceding._preceding_bytes(material) == wire
    actual = canonical.canonical_json_bytes(material)
    assert actual == wire and sha256(actual).digest() == sha256(wire).digest()


class _Integer(int):
    def __str__(self):
        raise AssertionError("integer subclass conversion reached")


class _Bytes(bytes):
    def hex(self):
        raise AssertionError("bytes subclass conversion reached")


class _Text(str):
    def __format__(self, specification):
        raise AssertionError("first string subclass formatting reached")


class _Tuple(tuple):
    def __len__(self):
        raise AssertionError("outer tuple subclass length reached")

    def __getitem__(self, index):
        raise AssertionError("outer tuple subclass indexing reached")


class _IntegerEnum(int, Enum):
    ONE = 1


def _plain_outcome(encode, value):
    try:
        return "return", encode(value)
    except (TypeError, ValueError) as error:
        return "error", type(error), str(error)


@pytest.mark.parametrize(
    "value",
    [
        ("field", _Integer(7)),
        ("field", _Bytes(b"raw")),
        (_Text("field"), 7),
        _Tuple(("field", 7)),
        ("field", _IntegerEnum.ONE),
        ("field", Decimal("1.00")),
        ("field", [None, 7, True]),
        ("field", {"later": [7]}),
        ("field", object()),
        ("field",),
        ("field", None, 7),
    ],
    ids=[
        "int-subclass",
        "bytes-subclass",
        "first-subclass",
        "outer-subclass",
        "int-enum",
        "decimal",
        "list",
        "mapping",
        "unsupported",
        "short",
        "long",
    ],
)
def test_original_fallback_return_or_error_for_nonexact_fields(value):
    for material in (value, (None, value, value)):
        expected = _plain_outcome(_legacy_bytes, material)
        assert _plain_outcome(preceding._preceding_bytes, material) == expected
        assert _plain_outcome(canonical.canonical_json_bytes, material) == expected


class _SelectedFailure(RuntimeError):
    pass


def _hook_outcome(previous, monkeypatch, kind, shape, fault=None):
    scalar = {"none": None, "false": False, "true": True, "int": 17, "bytes": b"\x00\xff"}[kind]
    pair = ("field", scalar)
    value, _ = _shape(pair, b"", shape)
    events, state = [], {"reference": None, "released": 0}
    primary, cause, context = (
        _SelectedFailure("selected scalar failure"),
        KeyError("cause"),
        IndexError("context"),
    )
    primary.__cause__, primary.__context__ = cause, context
    suppressed = primary.__suppress_context__
    namespace = vars(preceding) if previous else vars(canonical)
    helper = "_preceding_append" if previous else "_append_typed_text"
    original_append = namespace[helper]
    encode = preceding._preceding_bytes if previous else canonical.canonical_json_bytes
    native = json.encoder.encode_basestring_ascii

    def alive():
        reference = state["reference"]
        return reference is not None and reference() is not None

    class Result(str):
        def __del__(self):
            state["released"] += 1
            events.append(("release", state["released"]))
            json.encoder = Encoder("replacement-" + str(state["released"]))
            namespace[helper] = forbid_scalar_child

    class Formatted:
        def __init__(self, text, label):
            self.text, self.label = text, label

        def __format__(self, specification):
            assert specification == ""
            stage = "first" if self.text == "field" else "second"
            events.append(("format", self.label, self.text, alive()))
            if fault == stage + ".format":
                raise primary
            if stage == "first":
                result = Result(native("field"))
                state["reference"] = weakref.ref(result)
                return result
            assert not alive()
            return native(self.text + "-via-" + str(state["released"]))

    class Encoder:
        def __init__(self, label):
            self.label = label

        @property
        def encode_basestring_ascii(self):
            events.append(("lookup", self.label, alive()))
            stage = "first" if self.label == "initial" else "second"
            if fault == stage + ".lookup":
                raise primary

            def encode_string(text):
                events.append(("encode", self.label, text, alive()))
                current = "first" if text == "field" else "second"
                if fault == current + ".encode":
                    raise primary
                return Formatted(text, self.label)

            return encode_string

    def forbid_scalar_child(item, parts, deferred):
        assert not (item is None or type(item) in (bool, int, bytes))
        return original_append(item, parts, deferred)

    output = untouched = object()
    with monkeypatch.context() as patch:
        patch.setitem(namespace, helper, original_append)
        patch.setattr(json, "encoder", Encoder("initial"))
        try:
            output = encode(value)
        except _SelectedFailure as error:
            assert error is primary and error.__cause__ is cause and error.__context__ is context
            assert error.__suppress_context__ is suppressed and output is untouched
            result = "error", type(error), str(error)
        else:
            assert fault is None and not alive()
            result = "return", output, sha256(output).hexdigest()
    return result, tuple(events)


def _success_events(kind, number):
    prior = "initial" if number == 1 else "replacement-" + str(number - 1)
    replacement = "replacement-" + str(number)
    first = (
        ("lookup", prior, False),
        ("encode", prior, "field", False),
        ("format", prior, "field", False),
        ("release", number),
    )
    if kind in ("none", "false", "true"):
        return first
    text = "17" if kind == "int" else "00ff"
    return (
        *first,
        ("lookup", replacement, False),
        ("encode", replacement, text, False),
        ("format", replacement, text, False),
    )


def _hook_pair_wire(kind, number):
    if kind == "none":
        second = _NULL
    elif kind in ("false", "true"):
        second = b'{"type":"bool","value":' + kind.encode("ascii") + b"}"
    else:
        text = b"17" if kind == "int" else b"00ff"
        leaf = b"int" if kind == "int" else b"bytes"
        second = (
            b'{"type":"'
            + leaf
            + b'","value":"'
            + text
            + b"-via-"
            + str(number).encode("ascii")
            + b'"}'
        )
    return _TUPLE + _FIELD + second + b"]}"


@pytest.mark.parametrize("shape", ["root", "nested", "leading-null", "repeated-alias"])
@pytest.mark.parametrize("kind", ["none", "false", "true", "int", "bytes"])
def test_first_format_result_release_replaces_encoder_before_native_second_leaf(
    monkeypatch, kind, shape
):
    first = _hook_pair_wire(kind, 1)
    _, wire = _shape(None, first, shape)
    events = _success_events(kind, 1)
    if shape == "repeated-alias":
        wire = _TUPLE + first + b"," + _hook_pair_wire(kind, 2) + b"]}"
        events += _success_events(kind, 2)
    expected = (("return", wire, sha256(wire).hexdigest()), events)
    assert _hook_outcome(True, monkeypatch, kind, shape) == expected
    assert _hook_outcome(False, monkeypatch, kind, shape) == expected


@pytest.mark.parametrize("kind", ["none", "false", "true", "int", "bytes"])
@pytest.mark.parametrize("stage", ["first.lookup", "first.encode", "first.format"])
def test_first_native_field_failure_preserves_primary_edges_and_stops(monkeypatch, kind, stage):
    count = {"first.lookup": 1, "first.encode": 2, "first.format": 3}[stage]
    expected = (
        ("error", _SelectedFailure, "selected scalar failure"),
        _success_events(kind, 1)[:count],
    )
    assert _hook_outcome(True, monkeypatch, kind, "leading-null", stage) == expected
    assert _hook_outcome(False, monkeypatch, kind, "leading-null", stage) == expected


@pytest.mark.parametrize("kind", ["int", "bytes"])
@pytest.mark.parametrize("stage", ["second.lookup", "second.encode", "second.format"])
def test_second_native_field_failure_preserves_primary_edges_after_first_release(
    monkeypatch, kind, stage
):
    count = {"second.lookup": 5, "second.encode": 6, "second.format": 7}[stage]
    expected = (
        ("error", _SelectedFailure, "selected scalar failure"),
        _success_events(kind, 1)[:count],
    )
    assert _hook_outcome(True, monkeypatch, kind, "leading-null", stage) == expected
    assert _hook_outcome(False, monkeypatch, kind, "leading-null", stage) == expected


def _integer_conversion_outcome(encode, monkeypatch, material):
    native = json.encoder.encode_basestring_ascii
    events = []

    class Encoder:
        @property
        def encode_basestring_ascii(self):
            events.append("lookup")

            def encode_string(text):
                events.append(("encode", text))
                return native(text)

            return encode_string

    with monkeypatch.context() as patch:
        patch.setattr(json, "encoder", Encoder())
        with pytest.raises(ValueError) as caught:
            encode(material)
    error = caught.value
    assert error.__cause__ is None and error.__context__ is None
    assert error.__suppress_context__ is False
    assert events == ["lookup", ("encode", "field"), "lookup"]
    return type(error), str(error)


def test_native_integer_conversion_fault_follows_second_lookup_without_encoding(monkeypatch):
    previous = sys.get_int_max_str_digits()
    material = (None, ("field", 10**1000))
    try:
        sys.set_int_max_str_digits(640)
        assert _integer_conversion_outcome(
            preceding._preceding_bytes, monkeypatch, material
        ) == _integer_conversion_outcome(canonical.canonical_json_bytes, monkeypatch, material)
    finally:
        sys.set_int_max_str_digits(previous)


@pytest.mark.parametrize("kind", ["int", "bytes"])
def test_second_format_result_releases_before_third_dynamic_encoder_lookup(monkeypatch, kind):
    scalar, text = (17, "17") if kind == "int" else (b"\x00\xff", "00ff")
    expected_pair = (
        _TUPLE
        + _FIELD
        + b'{"type":"'
        + kind.encode("ascii")
        + b'","value":"'
        + text.encode("ascii")
        + b'"}]}'
    )
    wire = _TUPLE + _NULL + b"," + expected_pair + b',{"type":"string","value":"tail-after"}]}'
    expected_events = (
        ("lookup", "first", False, False),
        ("encode", "first", "field", False, False),
        ("format", "first", False, False),
        "first.release",
        ("lookup", "second", False, False),
        ("encode", "second", text, False, False),
        ("format", "second", False, False),
        "second.release",
        ("lookup", "third", False, False),
        ("encode", "third", "tail", False, False),
    )
    expected = wire, sha256(wire).hexdigest(), expected_events
    assert _second_release_outcome(preceding._preceding_bytes, monkeypatch, scalar) == expected
    assert _second_release_outcome(canonical.canonical_json_bytes, monkeypatch, scalar) == expected


def _second_release_outcome(encode, monkeypatch, scalar):
    native = json.encoder.encode_basestring_ascii
    events, state = [], {"first": None, "second": None}

    def alive(stage):
        reference = state[stage]
        return reference is not None and reference() is not None

    class FirstResult(str):
        def __del__(self):
            events.append("first.release")
            json.encoder = Encoder("second")

    class SecondResult(str):
        def __del__(self):
            events.append("second.release")
            json.encoder = Encoder("third")

    class Formatted:
        def __init__(self, label, value):
            self.label, self.value = label, value

        def __format__(self, specification):
            assert specification == ""
            events.append(("format", self.label, alive("first"), alive("second")))
            result_type = FirstResult if self.label == "first" else SecondResult
            result = result_type(native(self.value))
            state[self.label] = weakref.ref(result)
            return result

    class Encoder:
        def __init__(self, label):
            self.label = label

        @property
        def encode_basestring_ascii(self):
            events.append(("lookup", self.label, alive("first"), alive("second")))

            def encode_string(value):
                events.append(("encode", self.label, value, alive("first"), alive("second")))
                if self.label == "third":
                    return native(value + "-after")
                return Formatted(self.label, value)

            return encode_string

    with monkeypatch.context() as patch:
        patch.setattr(json, "encoder", Encoder("first"))
        raw = encode((None, ("field", scalar), "tail"))
    assert not alive("first") and not alive("second")
    return raw, sha256(raw).hexdigest(), tuple(events)


def _converted_outcome(encode, factory):
    events = []
    material = factory(events)
    raw = encode(material)
    return raw, sha256(raw).hexdigest(), tuple(events)


def test_scalar_pair_offsets_preserve_late_conversion_mutating_earlier_deferred_value():
    def factory(events):
        shared = ["before"]

        class First(date):
            def isoformat(self):
                events.append("first.convert")
                return shared

        class Last(date):
            def isoformat(self):
                events.append("last.convert")
                shared.append("after")
                return "last"

        return (
            ("missing", None),
            ("number", 17),
            First(2026, 10, 12),
            ("ready", True),
            ("raw", b"\x00"),
            Last(2026, 10, 12),
        )

    wire = (
        _TUPLE
        + _TUPLE
        + b'{"type":"string","value":"missing"},'
        + _NULL
        + b"]},"
        + _TUPLE
        + b'{"type":"string","value":"number"},{"type":"int","value":"17"}]},'
        + b'{"type":"date","value":["before","after"]},'
        + _TUPLE
        + b'{"type":"string","value":"ready"},{"type":"bool","value":true}]},'
        + _TUPLE
        + b'{"type":"string","value":"raw"},{"type":"bytes","value":"00"}]},'
        + b'{"type":"date","value":"last"}]}'
    )
    expected = wire, sha256(wire).hexdigest(), ("first.convert", "last.convert")
    assert _converted_outcome(_legacy_bytes, factory) == expected
    assert _converted_outcome(preceding._preceding_bytes, factory) == expected
    assert _converted_outcome(canonical.canonical_json_bytes, factory) == expected


def test_all_conversions_finish_before_deferred_serialization_mutates_later_value():
    def factory(events):
        shared = ["before"]

        class MutatingList(list):
            def __iter__(self):
                events.append("first.serialize")
                shared.append("after")
                return super().__iter__()

        class First(date):
            def isoformat(self):
                events.append("first.convert")
                return MutatingList(("first",))

        class Last(date):
            def isoformat(self):
                events.append("last.convert")
                return shared

        return (
            ("missing", None),
            First(2026, 10, 12),
            ("number", 17),
            ("raw", b"\x00"),
            Last(2026, 10, 12),
            ("ready", False),
        )

    wire = (
        _TUPLE
        + _TUPLE
        + b'{"type":"string","value":"missing"},'
        + _NULL
        + b"]},"
        + b'{"type":"date","value":["first"]},'
        + _TUPLE
        + b'{"type":"string","value":"number"},{"type":"int","value":"17"}]},'
        + _TUPLE
        + b'{"type":"string","value":"raw"},{"type":"bytes","value":"00"}]},'
        + b'{"type":"date","value":["before","after"]},'
        + _TUPLE
        + b'{"type":"string","value":"ready"},{"type":"bool","value":false}]}]}'
    )
    expected = wire, sha256(wire).hexdigest(), ("first.convert", "last.convert", "first.serialize")
    assert _converted_outcome(_legacy_bytes, factory) == expected
    assert _converted_outcome(preceding._preceding_bytes, factory) == expected
    assert _converted_outcome(canonical.canonical_json_bytes, factory) == expected
