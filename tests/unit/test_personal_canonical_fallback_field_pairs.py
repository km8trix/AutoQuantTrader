"""Finite fallback field-pair regressions against literal preceding69 and original tree.

Supported hooks, errors, bytes and lifetimes stay observable. Changed builtins,
arbitrary private-global/frame instrumentation, resource thresholds and financial
fit are excluded, as in the preceding native field-pair contract.
"""

import json
import weakref
from collections.abc import Mapping
from datetime import UTC, date, datetime
from decimal import Decimal, localcontext
from enum import Enum, StrEnum
from hashlib import sha256
from uuid import UUID

import pytest

from packages.domain import canonical
from tests.unit.test_personal_canonical_fallback_lifetime import MAPPING_BYTES, private_mapping
from tests.unit.test_personal_canonical_tuple_dispatch import (
    _legacy_canonical_json_bytes as _tree_bytes,
)


def _previous_decimal(value: Decimal) -> Decimal:
    """Return an exact, scale-independent Decimal without applying a context.

    ``Decimal.normalize`` applies the active arithmetic context and can round a
    high-precision value. Constructing the canonical coefficient directly from
    ``as_tuple`` preserves every significant digit and keeps large exponents
    compact.
    """

    if not isinstance(value, Decimal):
        raise TypeError("canonical decimal encoding requires a Decimal")
    if not value.is_finite():
        raise ValueError("canonical decimal encoding requires a finite value")
    sign, raw_digits, raw_exponent = value.as_tuple()
    if not any(raw_digits):
        return Decimal(0)
    digits = list(raw_digits)
    exponent = int(raw_exponent)
    while digits[-1] == 0:
        digits.pop()
        exponent += 1
    return Decimal((sign, tuple(digits), exponent))


def _previous_decimal_text(value: Decimal) -> str:
    """Return a compact, exact coefficient/exponent representation."""

    canonical = _previous_decimal(value)
    sign, digits, raw_exponent = canonical.as_tuple()
    if not any(digits):
        return "0"
    coefficient = "".join(str(digit) for digit in digits)
    prefix = "-" if sign else ""
    return f"{prefix}{coefficient}e{int(raw_exponent)}"


def _previous_json_text(node: object) -> str:
    return json.dumps(
        node,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _previous_typed_node(value: object) -> object:
    if type(value) is tuple:
        return {"type": "tuple", "value": [_previous_typed_node(item) for item in value]}
    if value is None:
        return {"type": "null", "value": None}
    if isinstance(value, Enum):
        enum_type = type(value)
        return {
            "enum_type": f"{enum_type.__module__}.{enum_type.__qualname__}",
            "type": "enum",
            "value": _previous_typed_node(value.value),
        }
    if type(value) is bool:
        return {"type": "bool", "value": value}
    if type(value) is int:
        return {"type": "int", "value": str(value)}
    if isinstance(value, Decimal):
        return {"type": "decimal", "value": _previous_decimal_text(value)}
    if type(value) is str:
        return {"type": "string", "value": value}
    if type(value) is bytes:
        return {"type": "bytes", "value": value.hex()}
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("canonical datetime encoding requires a timezone-aware value")
        utc_value = value.astimezone(UTC)
        return {
            "type": "datetime",
            "value": utc_value.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        }
    if isinstance(value, date):
        return {"type": "date", "value": value.isoformat()}
    if isinstance(value, UUID):
        return {"type": "uuid", "value": str(value)}
    if type(value) is list:
        return {"type": "list", "value": [_previous_typed_node(item) for item in value]}
    if isinstance(value, Mapping):
        entries = [
            {"key": _previous_typed_node(key), "value": _previous_typed_node(item)}
            for key, item in value.items()
        ]
        entries.sort(key=lambda entry: _previous_json_text(entry["key"]))
        return {"type": "mapping", "value": entries}
    if type(value) is set or type(value) is frozenset:
        items = [_previous_typed_node(item) for item in value]
        items.sort(key=_previous_json_text)
        collection_type = "set" if type(value) is set else "frozenset"
        return {"type": collection_type, "value": items}
    raise TypeError(f"unsupported canonical JSON value type: {type(value).__qualname__}")


def _previous_append(value: object, parts: list[str], deferred: list[tuple[int, object]]) -> None:
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
            if len(item) == 2 and type(item[0]) is str:
                if type(item[1]) is str:
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
                    continue
                elif type(item[1]) is tuple:
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
                    _previous_append(item[1], parts, deferred)
                    parts.append("]}")
                    continue
                elif item[1] is None:
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
                    parts.append('{"type":"null","value":null}]}')
                    continue
                elif type(item[1]) is bool:
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
                        '{"type":"bool","value":true}]}'
                        if item[1]
                        else '{"type":"bool","value":false}]}'
                    )
                    continue
                elif type(item[1]) is int:
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
                        f'{{"type":"int","value":{json.encoder.encode_basestring_ascii(str(item[1]))}}}'
                        "]}"
                    )
                    continue
                elif type(item[1]) is bytes:
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
                        f'{{"type":"bytes","value":{json.encoder.encode_basestring_ascii(item[1].hex())}}}'
                        "]}"
                    )
                    continue
            if index:
                parts.append(",")
            _previous_append(item, parts, deferred)
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
            converted = _previous_typed_node(item)
            deferred.append((len(parts), converted))
            parts.append("")
    if tuple_node:
        parts.append("]}")


def _previous_fragment(part: object) -> str:
    if type(part) is str:
        return part
    # The original fallback already converted these nodes. Emit only exact
    # two-string nodes directly, after all original conversion hooks finish.
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
    return _previous_json_text(part)


def _previous_bytes(value):
    parts, deferred = [], []
    _previous_append(value, parts, deferred)
    for position, converted in deferred:
        parts[position] = _previous_fragment(converted)
    return "".join(parts).encode("utf-8")


_TUPLE = b'{"type":"tuple","value":['
_NULL = b'{"type":"null","value":null}'
_FIELD = b'{"type":"string","value":"field"}'


def _pair_wire(node, field=_FIELD):
    return _TUPLE + field + b"," + node + b"]}"


def _shape(value, wire, shape):
    pair = ("field", value)
    pair_wire = _pair_wire(wire)
    if shape == "root":
        return pair, pair_wire
    if shape == "nested":
        return (pair,), _TUPLE + pair_wire + b"]}"
    if shape == "comma":
        return (None, pair), _TUPLE + _NULL + b"," + pair_wire + b"]}"
    assert shape == "alias"
    return (pair, pair), _TUPLE + pair_wire + b"," + pair_wire + b"]}"


class _Kind(Enum):
    VALUE = "fixed"


class _StringEnum(StrEnum):
    VALUE = "fixed"


class _First(str):
    pass


class _Pair(tuple):
    pass


class _Date(date):
    pass


class _Decimal(Decimal):
    pass


@pytest.mark.parametrize(
    "value,node",
    [
        (Decimal("2.500"), b'{"type":"decimal","value":"25e-1"}'),
        (Decimal("-0.000"), b'{"type":"decimal","value":"0"}'),
        (date(2026, 10, 12), b'{"type":"date","value":"2026-10-12"}'),
        (_Date(2026, 10, 12), b'{"type":"date","value":"2026-10-12"}'),
        (
            datetime(2026, 10, 12, tzinfo=UTC),
            b'{"type":"datetime","value":"2026-10-12T00:00:00.000000Z"}',
        ),
        (
            UUID("00000000-0000-0000-0000-000000000001"),
            b'{"type":"uuid","value":"00000000-0000-0000-0000-000000000001"}',
        ),
        (
            [None, True],
            b'{"type":"list","value":[{"type":"null","value":null},{"type":"bool","value":true}]}',
        ),
        ({"z": 2, "a": 1}, MAPPING_BYTES),
        ({2, 1}, b'{"type":"set","value":[{"type":"int","value":"1"},{"type":"int","value":"2"}]}'),
        (
            frozenset({2, 1}),
            b'{"type":"frozenset","value":[{"type":"int","value":"1"},{"type":"int","value":"2"}]}',
        ),
    ],
)
@pytest.mark.parametrize("shape", ["root", "nested", "comma", "alias"])
def test_literal_fallback_field_pair_wire_and_hash(value, node, shape):
    material, wire = _shape(value, node, shape)
    with localcontext() as context:
        context.prec = 2
        for encode in (_tree_bytes, _previous_bytes, canonical.canonical_json_bytes):
            output = encode(material)
            assert output == wire and sha256(output).digest() == sha256(wire).digest()


def test_string_and_regular_enum_fallback_have_literal_qualified_type_and_value():
    for value, name in ((_Kind.VALUE, "_Kind"), (_StringEnum.VALUE, "_StringEnum")):
        node = (
            b'{"enum_type":"'
            + (__name__ + "." + name).encode("ascii")
            + b'","type":"enum","value":{"type":"string","value":"fixed"}}'
        )
        material, wire = _shape(value, node, "comma")
        for encode in (_tree_bytes, _previous_bytes, canonical.canonical_json_bytes):
            assert encode(material) == wire


def _outcome(encode, material):
    try:
        output = encode(material)
    except (TypeError, ValueError) as error:
        return "error", type(error), str(error), error.__cause__, error.__context__
    return "return", output, sha256(output).digest()


@pytest.mark.parametrize(
    "material",
    [
        (_First("field"), date(2026, 10, 12)),
        _Pair(("field", date(2026, 10, 12))),
        ("field",),
        ("field", date(2026, 10, 12), "tail"),
        ("field", _First("value")),
        ("field", object()),
        ("field", datetime(2026, 10, 12)),
        ("field", Decimal("NaN")),
        ("field", Decimal("Infinity")),
        ("field", _Decimal("2.500")),
        date(2026, 10, 12),
    ],
)
def test_guard_lengths_subclasses_scalar_roots_and_original_conversion_errors(material):
    for value in (material, (None, material)):
        expected = _outcome(_tree_bytes, value)
        assert _outcome(_previous_bytes, value) == expected
        assert _outcome(canonical.canonical_json_bytes, value) == expected


class _SelectedFailure(RuntimeError):
    pass


def _release_converter_outcome(previous, monkeypatch, shape, fault=None):
    namespace = globals() if previous else vars(canonical)
    name = "_previous_typed_node" if previous else "_typed_node"
    append_name = "_previous_append" if previous else "_append_typed_text"
    encode = _previous_bytes if previous else canonical.canonical_json_bytes
    original_converter, original_append = namespace[name], namespace[append_name]
    native = json.encoder.encode_basestring_ascii
    state, events = {"reference": None, "text": "before", "released": 0}, []
    primary, cause, context = (
        _SelectedFailure("selected fallback stage"),
        KeyError("cause"),
        IndexError("context"),
    )
    primary.__cause__, primary.__context__ = cause, context
    suppressed = primary.__suppress_context__

    def alive():
        reference = state["reference"]
        return reference is not None and reference() is not None

    def later_tuple(value, parts, deferred):
        assert value == () and not alive()
        events.append("later.tuple")
        return original_append(value, parts, deferred)

    def replacement(value):
        assert not alive()
        events.append("converter")
        if fault == "converter":
            raise primary
        return original_converter(value)

    class Result(str):
        def __del__(self):
            state["released"] += 1
            state["text"] = "after"
            events.append("release")
            namespace[name] = replacement
            namespace[append_name] = later_tuple
            json.encoder = Encoder("replacement")

    class Formatted:
        def __format__(self, specification):
            assert specification == ""
            events.append("first.format")
            if fault == "format":
                raise primary
            output = Result(native("field"))
            state["reference"] = weakref.ref(output)
            return output

    class Encoder:
        def __init__(self, label):
            self.label = label

        @property
        def encode_basestring_ascii(self):
            events.append(self.label + ".lookup")
            if self.label == "initial" and fault == "lookup":
                raise primary

            def encode_string(value):
                events.append((self.label + ".encode", value))
                if value == "field":
                    if fault == "encode":
                        raise primary
                    return Formatted()
                return native(value)

            return encode_string

    class ObservedDate(date):
        def isoformat(self):
            events.append("date.convert")
            if fault == "getter":
                raise primary
            return state["text"]

    child = ObservedDate(2026, 10, 12)
    if shape == "root":
        material = ("field", child)
    elif shape == "nested":
        material = (("field", child),)
    else:
        assert shape == "comma"
        material = (None, ("field", child), ())
    output = untouched = object()
    with monkeypatch.context() as patch:
        patch.setitem(namespace, name, original_converter)
        patch.setitem(namespace, append_name, original_append)
        patch.setattr(json, "encoder", Encoder("initial"))
        try:
            output = encode(material)
        except _SelectedFailure as error:
            assert error is primary and error.__cause__ is cause and error.__context__ is context
            assert error.__suppress_context__ is suppressed and output is untouched
            outcome = ("error", type(error), str(error))
        else:
            assert fault is None and not alive()
            outcome = ("return", output, sha256(output).digest())
    return outcome, tuple(events)


@pytest.mark.parametrize("shape", ["root", "nested", "comma"])
def test_first_format_release_precedes_fresh_converter_mutation_and_later_tuple_lookup(
    monkeypatch, shape
):
    pair = _pair_wire(b'{"type":"date","value":"after"}')
    wire = pair if shape == "root" else _TUPLE + pair + b"]}"
    events = (
        "initial.lookup",
        ("initial.encode", "field"),
        "first.format",
        "release",
        "converter",
        "date.convert",
    )
    if shape == "comma":
        wire = _TUPLE + _NULL + b"," + pair + b"," + _TUPLE + b"]}]}"
        events += ("later.tuple",)
    events += (
        "replacement.lookup",
        ("replacement.encode", "date"),
        "replacement.lookup",
        ("replacement.encode", "after"),
    )
    expected = (("return", wire, sha256(wire).digest()), events)
    assert _release_converter_outcome(True, monkeypatch, shape) == expected
    assert _release_converter_outcome(False, monkeypatch, shape) == expected


@pytest.mark.parametrize("stage", ["lookup", "encode", "format", "converter", "getter"])
def test_first_or_conversion_failure_keeps_primary_edges_and_stops_later_hooks(monkeypatch, stage):
    all_events = (
        "initial.lookup",
        ("initial.encode", "field"),
        "first.format",
        "release",
        "converter",
        "date.convert",
    )
    count = {"lookup": 1, "encode": 2, "format": 3, "converter": 5, "getter": 6}[stage]
    expected = (("error", _SelectedFailure, "selected fallback stage"), all_events[:count])
    assert _release_converter_outcome(True, monkeypatch, "comma", stage) == expected
    assert _release_converter_outcome(False, monkeypatch, "comma", stage) == expected


@pytest.mark.parametrize("shape", ["root", "comma", "alias"])
def test_mapping_class_releases_at_fallback_field_pair_and_literal_bytes(shape):
    for encode in (_previous_bytes, canonical.canonical_json_bytes):
        value, old_class, state = private_mapping()
        material, wire = _shape(value, MAPPING_BYTES, shape)
        assert encode(material) == wire
        visits = 2 if shape == "alias" else 1
        assert state.events == ["mapping"] * visits
        assert state.lifetimes == [("mapping", False)] * visits and old_class() is None


@pytest.mark.parametrize("visit", [1, 2])
def test_mapping_first_failure_releases_class_and_preserves_error_with_traceback_alive(visit):
    for encode in (_previous_bytes, canonical.canonical_json_bytes):
        events, lifetimes = [], []
        primary, cause, context = (
            _SelectedFailure("mapping failure"),
            KeyError("cause"),
            IndexError("context"),
        )
        primary.__cause__, primary.__context__ = cause, context
        suppressed = primary.__suppress_context__
        value, old_class, _state = private_mapping(
            events=events, lifetimes=lifetimes, error=primary, raise_on_visit=visit
        )
        after, _after_class, _after_state = private_mapping(
            label="later", events=events, lifetimes=lifetimes
        )
        material = (("field", value), ("field", value), ("later", after))
        output = untouched = object()
        with pytest.raises(_SelectedFailure) as raised:
            output = encode(material)
        assert (
            raised.value is primary
            and primary.__cause__ is cause
            and primary.__context__ is context
        )
        assert primary.__suppress_context__ is suppressed and output is untouched
        assert old_class() is None and events == ["mapping"] * visit
        assert lifetimes == [("mapping", False)] * visit


def test_mapping_generator_stopiteration_keeps_chaining_and_stops_later_conversion():
    def run(encode):
        primary = StopIteration("selected generator stop")
        events = []

        class PartialMapping(Mapping):
            def __len__(self):
                return 2

            def __getitem__(self, key):
                raise AssertionError("unexpected lookup")

            def __iter__(self):
                raise AssertionError("unexpected iteration")

            def items(self):
                events.append("items")
                yield "first", 1
                events.append("stop")
                raise primary

        class Later(date):
            def isoformat(self):
                events.append("later")
                return "later"

        with pytest.raises(RuntimeError, match="generator raised StopIteration") as raised:
            encode((("field", PartialMapping()), ("later", Later(2026, 10, 12))))
        assert raised.value.__cause__ is primary and raised.value.__context__ is primary
        assert raised.value.__suppress_context__ is True
        return tuple(events), str(raised.value)

    assert (
        run(_previous_bytes)
        == run(canonical.canonical_json_bytes)
        == (("items", "stop"), "generator raised StopIteration")
    )


def _staged_outcome(encode, mode):
    events, shared = [], ["before"]

    class MutatingList(list):
        def __iter__(self):
            events.append("first.serialize")
            shared.append("after")
            return super().__iter__()

    class First(date):
        def isoformat(self):
            events.append("first.convert")
            if mode == "conversion":
                return shared
            if mode == "serialization":
                return MutatingList(["first"])
            return b"invalid"

    class Last(date):
        def isoformat(self):
            events.append("last.convert")
            if mode == "conversion":
                shared.append("after")
                return "last"
            return shared

    material = (None, ("a", First(2026, 10, 12)), ("native", 7), ("b", Last(2026, 10, 12)))
    return _outcome(encode, material), tuple(events)


@pytest.mark.parametrize("mode", ["conversion", "serialization", "error"])
def test_complete_two_phase_conversion_offsets_mutations_and_serialization_failure(mode):
    if mode == "error":
        expected = (
            ("error", TypeError, "Object of type bytes is not JSON serializable", None, None),
            ("first.convert", "last.convert"),
        )
    else:
        first = (
            b'{"type":"date","value":["before","after"]}'
            if mode == "conversion"
            else b'{"type":"date","value":["first"]}'
        )
        last = (
            b'{"type":"date","value":"last"}'
            if mode == "conversion"
            else b'{"type":"date","value":["before","after"]}'
        )
        wire = (
            _TUPLE
            + _NULL
            + b","
            + _pair_wire(first, b'{"type":"string","value":"a"}')
            + b","
            + _pair_wire(b'{"type":"int","value":"7"}', b'{"type":"string","value":"native"}')
            + b","
            + _pair_wire(last, b'{"type":"string","value":"b"}')
            + b"]}"
        )
        events = ("first.convert", "last.convert")
        if mode == "serialization":
            events += ("first.serialize",)
        expected = (("return", wire, sha256(wire).digest()), events)
    for encode in (_tree_bytes, _previous_bytes, canonical.canonical_json_bytes):
        assert _staged_outcome(encode, mode) == expected


def test_mapping_key_conversion_and_sorting_remain_before_later_field_conversion():
    def run(encode):
        events = []

        class Key(date):
            def isoformat(self):
                events.append("key.convert")
                return "key"

        class Later(date):
            def isoformat(self):
                events.append("later.convert")
                return "later"

        material = (("field", {Key(2026, 10, 12): 1}), ("later", Later(2026, 10, 12)))
        return encode(material), tuple(events)

    node = (
        b'{"type":"mapping","value":[{"key":{"type":"date","value":"key"},'
        b'"value":{"type":"int","value":"1"}}]}'
    )
    wire = (
        _TUPLE
        + _pair_wire(node)
        + b","
        + _pair_wire(b'{"type":"date","value":"later"}', b'{"type":"string","value":"later"}')
        + b"]}"
    )
    expected = wire, ("key.convert", "later.convert")
    assert (
        run(_tree_bytes) == run(_previous_bytes) == run(canonical.canonical_json_bytes) == expected
    )
