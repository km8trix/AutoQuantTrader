"""Finite byte/hook regressions for exact (string, tuple) canonical wrappers.

The literal preceding traversal is separate from the independent original full-tree
oracle. Hook comparisons preserve selected observable order/lifetimes, not arbitrary
private-frame/global, resource-exhaustion, timing or financial equivalence.
"""

import json
import weakref
from datetime import date
from decimal import Decimal
from enum import Enum
from hashlib import sha256

import pytest

from packages.domain import canonical
from packages.domain.personal_contracts import VersionPin, semantic_value
from tests.unit.test_personal_canonical_fallback_lifetime import (
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


def _preceding_append(value: object, parts: list[str], deferred: list[tuple[int, object]]) -> None:
    """Visit tuple children in order; recurse only for nested exact tuples."""
    if type(value) is tuple:
        parts.append('{"type":"tuple","value":[')
        items = value
        tuple_node = True
    else:
        items = (value,)
        tuple_node = False
    for index, item in enumerate(items):
        if type(item) is str:
            if index:
                parts.append(
                    f',{{"type":"string","value":{json.encoder.encode_basestring_ascii(item)}}}'
                )
            else:
                parts.append(
                    f'{{"type":"string","value":{json.encoder.encode_basestring_ascii(item)}}}'
                )
            continue
        if type(item) is tuple:
            # Exact string pairs can avoid recursion. Keep each item's formatting
            # result released before the next dynamic encoder lookup.
            if len(item) == 2 and type(item[0]) is str and type(item[1]) is str:
                if index:
                    parts.append(
                        ',{"type":"tuple","value":['
                        f'{{"type":"string","value":{json.encoder.encode_basestring_ascii(item[0])}}}'
                        ","
                    )
                else:
                    parts.append(
                        '{"type":"tuple","value":['
                        f'{{"type":"string","value":{json.encoder.encode_basestring_ascii(item[0])}}}'
                        ","
                    )
                parts.append(
                    f'{{"type":"string","value":{json.encoder.encode_basestring_ascii(item[1])}}}'
                    "]}"
                )
            else:
                if index:
                    parts.append(",")
                _preceding_append(item, parts, deferred)
            continue
        if index:
            parts.append(",")
        if item is None:
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
            # Complete conversion hooks in traversal order before serializing
            # any fallback node, including a fallback reached from a scalar root.
            converted = _legacy_typed_node(item)
            deferred.append((len(parts), converted))
            parts.append("")
    if tuple_node:
        parts.append("]}")


def _preceding_fragment(part):
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


def _preceding_bytes(value):
    parts, deferred = [], []
    _preceding_append(value, parts, deferred)
    for position, converted in deferred:
        parts[position] = _preceding_fragment(converted)
    return "".join(parts).encode("utf-8")


_TUPLE = b'{"type":"tuple","value":['
_NULL = b'{"type":"null","value":null}'


@pytest.mark.parametrize(
    "name,children,wire",
    [
        ("name", (), _TUPLE + b'{"type":"string","value":"name"},' + _TUPLE + b"]}]}"),
        (
            "name",
            (7,),
            _TUPLE
            + b'{"type":"string","value":"name"},'
            + _TUPLE
            + b'{"type":"int","value":"7"}]}]}',
        ),
        (
            "name",
            ("left", "right"),
            _TUPLE
            + b'{"type":"string","value":"name"},'
            + _TUPLE
            + b'{"type":"string","value":"left"},{"type":"string","value":"right"}]}]}',
        ),
        (
            "name",
            (None, False, b"\x00", Decimal("-0.000")),
            _TUPLE
            + b'{"type":"string","value":"name"},'
            + _TUPLE
            + _NULL
            + b',{"type":"bool","value":false},{"type":"bytes","value":"00"},'
            + b'{"type":"decimal","value":"0"}]}]}',
        ),
        (
            "name",
            (("field", "value"), ("count", 3)),
            _TUPLE
            + b'{"type":"string","value":"name"},'
            + _TUPLE
            + _TUPLE
            + b'{"type":"string","value":"field"},{"type":"string","value":"value"}]},'
            + _TUPLE
            + b'{"type":"string","value":"count"},{"type":"int","value":"3"}]}]}]}',
        ),
        (
            '"\\\n\x00é\ud800',
            ("中😀\udfff",),
            _TUPLE
            + b'{"type":"string","value":"\\"\\\\\\n\\u0000\\u00e9\\ud800"},'
            + _TUPLE
            + b'{"type":"string","value":"\\u4e2d\\ud83d\\ude00\\udfff"}]}]}',
        ),
    ],
    ids=["empty", "one", "child-string-pair", "native-and-decimal", "nested-fields", "escaping"],
)
def test_literal_string_tuple_wire_and_hash_at_root_nested_comma_and_alias(name, children, wire):
    pair = (name, children)
    for value, expected in (
        (pair, wire),
        ((pair,), _TUPLE + wire + b"]}"),
        ((None, pair), _TUPLE + _NULL + b"," + wire + b"]}"),
        ((pair, pair), _TUPLE + wire + b"," + wire + b"]}"),
    ):
        assert _legacy_bytes(value) == _preceding_bytes(value) == expected
        payload = canonical.canonical_json_bytes(value)
        assert payload == expected
        assert sha256(payload).digest() == sha256(expected).digest()


class _Text(str):
    def __format__(self, specification):
        raise AssertionError("string subclass was admitted to exact guard")


class _TupleSubclass(tuple):
    def __len__(self):
        raise AssertionError("tuple subclass length hook reached")

    def __getitem__(self, key):
        raise AssertionError("tuple subclass indexing hook reached")


class _TupleEnum(tuple, Enum):
    VALUE = ("field", (7,))


def _plain_outcome(encode, value):
    try:
        return "return", encode(value)
    except (TypeError, ValueError) as error:
        return "error", type(error), str(error)


@pytest.mark.parametrize(
    "value",
    [
        (_Text("name"), ()),
        ("name", _TupleSubclass((7,))),
        _TupleSubclass(("name", ())),
        ("name", _TupleEnum.VALUE),
        ("name",),
        ("name", (), 7),
        ("name", 3),
        ("name", None),
    ],
    ids=[
        "first-subclass",
        "child-subclass",
        "outer-subclass",
        "child-enum",
        "one",
        "three",
        "scalar-int",
        "scalar-null",
    ],
)
def test_exact_guard_boundaries_preserve_original_return_or_error(value):
    for material in (value, (value,)):
        expected = _plain_outcome(_legacy_bytes, material)
        assert _plain_outcome(_preceding_bytes, material) == expected
        assert _plain_outcome(canonical.canonical_json_bytes, material) == expected
    if type(value) is _TupleSubclass or any(
        type(item) in (_Text, _TupleSubclass) for item in value
    ):
        assert expected[0:2] == ("error", TypeError)
    else:
        assert expected[0] == "return"


def test_real_version_pin_has_literal_semantic_field_tuple_and_original_wire():
    pin = VersionPin(name="encoder", version="v1", sha256="0" * 64)
    expected_semantic = (
        "packages.domain.personal_contracts.VersionPin",
        (("name", "encoder"), ("version", "v1"), ("sha256", "0" * 64)),
    )
    actual_semantic = semantic_value(pin)
    assert actual_semantic == expected_semantic
    expected = _legacy_bytes((expected_semantic,))
    assert _preceding_bytes((actual_semantic,)) == expected
    payload = canonical.canonical_json_bytes((actual_semantic,))
    assert payload == expected and sha256(payload).digest() == sha256(expected).digest()


class _SelectedFailure(RuntimeError):
    pass


def _hook_outcome(previous, monkeypatch, shape, stage=None, mapping_raise_on_visit=None):
    events, lifetimes = [], []
    state = {"reference": None, "released": 0}
    primary = _SelectedFailure("selected original failure")
    cause, context = LookupError("original cause"), IndexError("original context")
    primary.__cause__, primary.__context__ = cause, context
    suppressed = primary.__suppress_context__
    mapping, old_class, mapping_state = private_mapping(
        events=events,
        lifetimes=lifetimes,
        error=primary if mapping_raise_on_visit is not None else None,
        raise_on_visit=1 if mapping_raise_on_visit is None else mapping_raise_on_visit,
    )
    child = ("child", mapping, "tail")
    pair = ("first", child)
    value = {
        "root": pair,
        "nested": (pair,),
        "leading-null": (None, pair),
        "repeated-alias": (pair, pair),
    }[shape]
    encode = _preceding_bytes if previous else canonical.canonical_json_bytes
    namespace = globals() if previous else vars(canonical)
    helper = "_preceding_append" if previous else "_append_typed_text"
    original_append = namespace[helper]
    native_encode = json.encoder.encode_basestring_ascii

    def alive():
        reference = state["reference"]
        return reference is not None and reference() is not None

    class Result(str):
        def __del__(self):
            state["released"] += 1
            label = "replacement-" + str(state["released"])
            events.append(("release", state["released"]))
            mapping_state.rows = (("z", 9), ("a", 1))
            json.encoder = Encoder(label)
            namespace[helper] = replacement_append
            events.append(("replace", label))

    class Encoded:
        def __init__(self, label, value):
            self.label, self.value = label, value

        def __format__(self, specification):
            assert specification == ""
            events.append(("format", self.label, self.value, alive()))
            if stage == ("first.format" if self.value == "first" else "child.format"):
                raise primary
            if self.value == "first":
                result = Result(native_encode("first"))
                state["reference"] = weakref.ref(result)
                return result
            return native_encode(self.value + "-via-" + self.label)

    class Encoder:
        def __init__(self, label):
            self.label = label

        @property
        def encode_basestring_ascii(self):
            label = self.label
            events.append(("lookup", label, alive()))
            if stage == ("first.lookup" if label == "initial" else "child.lookup"):
                raise primary

            def encode_string(value):
                events.append(("encode", label, value, alive()))
                if stage == ("first.encode" if value == "first" else "child.encode"):
                    raise primary
                return Encoded(label, value)

            return encode_string

    def replacement_append(item, parts, deferred):
        if item is child:
            label = "replacement-" + str(state["released"])
            events.append(("child", label, alive()))
            assert not alive()
            if stage == "child.callee":
                raise primary
        return original_append(item, parts, deferred)

    output = untouched = object()
    with monkeypatch.context() as patch:
        patch.setitem(namespace, helper, original_append)
        patch.setattr(json, "encoder", Encoder("initial"))
        try:
            output = encode(value)
        except _SelectedFailure as caught:
            assert caught is primary and caught.__cause__ is cause and caught.__context__ is context
            assert caught.__suppress_context__ is suppressed and output is untouched
            outcome = ("error", type(caught), str(caught))
        else:
            assert stage is None and mapping_raise_on_visit is None
            assert not alive() and old_class() is None
            assert mapping.__class__ is ReplacementMapping
            outcome = ("return", output, sha256(output).hexdigest())
    return outcome, tuple(events), tuple(lifetimes)


def _successful_events(number):
    first = "initial" if number == 1 else "replacement-" + str(number - 1)
    replacement = "replacement-" + str(number)
    return (
        ("lookup", first, False),
        ("encode", first, "first", False),
        ("format", first, "first", False),
        ("release", number),
        ("replace", replacement),
        ("child", replacement, False),
        ("lookup", replacement, False),
        ("encode", replacement, "child", False),
        ("format", replacement, "child", False),
        "mapping",
        ("lookup", replacement, False),
        ("encode", replacement, "tail", False),
        ("format", replacement, "tail", False),
    )


_MUTATED_MAPPING_WIRE = (
    b'{"type":"mapping","value":['
    b'{"key":{"type":"string","value":"a"},"value":{"type":"int","value":"1"}},'
    b'{"key":{"type":"string","value":"z"},"value":{"type":"int","value":"9"}}]}'
)


def _released_pair_wire(number):
    # The formatter/destructor output and child mutation have literal expected bytes.
    marker = str(number).encode("ascii")
    return (
        _TUPLE
        + b'{"type":"string","value":"first"},'
        + _TUPLE
        + b'{"type":"string","value":"child-via-replacement-'
        + marker
        + b'"},'
        + _MUTATED_MAPPING_WIRE
        + b',{"type":"string","value":"tail-via-replacement-'
        + marker
        + b'"}]}]}'
    )


@pytest.mark.parametrize("shape", ["root", "nested", "leading-null", "repeated-alias"])
def test_first_formatter_release_rebinds_encoder_and_fresh_child_callee_before_hooks(
    monkeypatch, shape
):
    first = _released_pair_wire(1)
    expected_wire = {
        "root": first,
        "nested": _TUPLE + first + b"]}",
        "leading-null": _TUPLE + _NULL + b"," + first + b"]}",
        "repeated-alias": _TUPLE + first + b"," + _released_pair_wire(2) + b"]}",
    }[shape]
    count = 2 if shape == "repeated-alias" else 1
    events = _successful_events(1) + (_successful_events(2) if count == 2 else ())
    expected = (
        ("return", expected_wire, sha256(expected_wire).hexdigest()),
        events,
        (("mapping", False),) * count,
    )
    assert _hook_outcome(True, monkeypatch, shape) == expected
    assert _hook_outcome(False, monkeypatch, shape) == expected


@pytest.mark.parametrize(
    "stage",
    [
        "first.lookup",
        "first.encode",
        "first.format",
        "child.callee",
        "child.lookup",
        "child.encode",
        "child.format",
    ],
)
def test_selected_first_or_child_failure_preserves_exact_primary_and_stops_later_hooks(
    monkeypatch, stage
):
    end = {
        "first.lookup": 1,
        "first.encode": 2,
        "first.format": 3,
        "child.callee": 6,
        "child.lookup": 7,
        "child.encode": 8,
        "child.format": 9,
    }[stage]
    expected = (
        ("error", _SelectedFailure, "selected original failure"),
        _successful_events(1)[:end],
        (),
    )
    assert _hook_outcome(True, monkeypatch, "leading-null", stage) == expected
    assert _hook_outcome(False, monkeypatch, "leading-null", stage) == expected


@pytest.mark.parametrize("visit", [1, 2])
def test_mapping_first_failure_keeps_original_error_lifetime_and_later_leaf_order(
    monkeypatch, visit
):
    events = (_successful_events(1) if visit == 2 else ()) + _successful_events(visit)[:10]
    expected = (
        ("error", _SelectedFailure, "selected original failure"),
        events,
        (("mapping", False),) * visit,
    )
    assert (
        _hook_outcome(True, monkeypatch, "repeated-alias", mapping_raise_on_visit=visit) == expected
    )
    assert (
        _hook_outcome(False, monkeypatch, "repeated-alias", mapping_raise_on_visit=visit)
        == expected
    )


def _converted_outcome(encode, factory):
    events = []
    value = factory(events)
    try:
        output = encode(value)
    except TypeError as error:
        return ("error", type(error), str(error), error.__cause__, error.__context__), tuple(events)
    return ("return", output, sha256(output).hexdigest()), tuple(events)


def test_later_conversion_mutates_earlier_deferred_value_inside_tuple_child():
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

        return (
            None,
            ("fields", (FirstDate(2026, 10, 11), "middle", LastDate(2026, 10, 11))),
            ("after", ()),
        )

    wire = (
        _TUPLE
        + _NULL
        + b","
        + _TUPLE
        + b'{"type":"string","value":"fields"},'
        + _TUPLE
        + b'{"type":"date","value":["before","after"]},{"type":"string","value":"middle"},'
        + b'{"type":"date","value":"last"}]}]},'
        + _TUPLE
        + b'{"type":"string","value":"after"},'
        + _TUPLE
        + b"]}]}]}"
    )
    expected = (("return", wire, sha256(wire).hexdigest()), ("first.convert", "last.convert"))
    assert _converted_outcome(_legacy_bytes, factory) == expected
    assert _converted_outcome(_preceding_bytes, factory) == expected
    assert _converted_outcome(canonical.canonical_json_bytes, factory) == expected


def test_deferred_serialization_mutation_follows_all_child_conversions():
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

        return (None, ("fields", (FirstDate(2026, 10, 11), "middle", LastDate(2026, 10, 11))))

    wire = (
        _TUPLE
        + _NULL
        + b","
        + _TUPLE
        + b'{"type":"string","value":"fields"},'
        + _TUPLE
        + b'{"type":"date","value":["first"]},{"type":"string","value":"middle"},'
        + b'{"type":"date","value":["before","after"]}]}]}]}'
    )
    expected = (
        ("return", wire, sha256(wire).hexdigest()),
        ("first.convert", "last.convert", "first.serialize"),
    )
    assert _converted_outcome(_legacy_bytes, factory) == expected
    assert _converted_outcome(_preceding_bytes, factory) == expected
    assert _converted_outcome(canonical.canonical_json_bytes, factory) == expected


def test_deferred_serialization_failure_waits_for_later_child_conversion():
    def factory(events):
        class InvalidDate(date):
            def isoformat(self):
                events.append("invalid.convert")
                return b"invalid-json-value"

        class LastDate(date):
            def isoformat(self):
                events.append("last.convert")
                return "last"

        return (None, ("fields", (InvalidDate(2026, 10, 11), "middle", LastDate(2026, 10, 11))))

    expected = (
        ("error", TypeError, "Object of type bytes is not JSON serializable", None, None),
        ("invalid.convert", "last.convert"),
    )
    assert _converted_outcome(_legacy_bytes, factory) == expected
    assert _converted_outcome(_preceding_bytes, factory) == expected
    assert _converted_outcome(canonical.canonical_json_bytes, factory) == expected
