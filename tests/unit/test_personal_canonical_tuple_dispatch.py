"""Pure compatibility with the literal original encoder; no persistence or authority.

The oracle below retains the entire original typed/decimal/JSON/UTF-8 chain.
It never imports the new encoder for an intermediate normalization step.
Finite hook/read examples do not claim arbitrary monkeypatched-global,
concurrent-mutation or recursion/resource-exhaustion equivalence.
"""

import json
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta, timezone
from decimal import Decimal, localcontext
from enum import Enum, IntEnum
from hashlib import sha256
from types import MappingProxyType
from uuid import UUID

import pytest

from packages.domain import canonical
from packages.domain.accounting_contracts import ExecutionPolicy, SettlementCalendar
from packages.domain.personal_contracts import content_digest, semantic_value
from tests.unit.test_personal_contract_semantics import AT, GOLDENS, record_for
from tests.unit.test_personal_engine_contracts import _event


def _legacy_canonical_decimal(value: Decimal) -> Decimal:
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


def _legacy_canonical_decimal_text(value: Decimal) -> str:
    """Return a compact, exact coefficient/exponent representation."""

    canonical = _legacy_canonical_decimal(value)
    sign, digits, raw_exponent = canonical.as_tuple()
    if not any(digits):
        return "0"
    coefficient = "".join(str(digit) for digit in digits)
    prefix = "-" if sign else ""
    return f"{prefix}{coefficient}e{int(raw_exponent)}"


def _legacy_json_text(node: object) -> str:
    return json.dumps(
        node,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _legacy_typed_node(value: object) -> object:
    if value is None:
        return {"type": "null", "value": None}
    if isinstance(value, Enum):
        enum_type = type(value)
        return {
            "enum_type": f"{enum_type.__module__}.{enum_type.__qualname__}",
            "type": "enum",
            "value": _legacy_typed_node(value.value),
        }
    if type(value) is bool:
        return {"type": "bool", "value": value}
    if type(value) is int:
        return {"type": "int", "value": str(value)}
    if isinstance(value, Decimal):
        return {"type": "decimal", "value": _legacy_canonical_decimal_text(value)}
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
    if type(value) is tuple:
        return {"type": "tuple", "value": [_legacy_typed_node(item) for item in value]}
    if type(value) is list:
        return {"type": "list", "value": [_legacy_typed_node(item) for item in value]}
    if isinstance(value, Mapping):
        entries = [
            {"key": _legacy_typed_node(key), "value": _legacy_typed_node(item)}
            for key, item in value.items()
        ]
        entries.sort(key=lambda entry: _legacy_json_text(entry["key"]))
        return {"type": "mapping", "value": entries}
    if type(value) is set or type(value) is frozenset:
        items = [_legacy_typed_node(item) for item in value]
        items.sort(key=_legacy_json_text)
        collection_type = "set" if type(value) is set else "frozenset"
        return {"type": collection_type, "value": items}
    raise TypeError(f"unsupported canonical JSON value type: {type(value).__qualname__}")


def _legacy_canonical_json_text(value: object) -> str:
    """Encode supported values as deterministic, explicitly typed JSON."""

    return _legacy_json_text(_legacy_typed_node(value))


def _legacy_canonical_json_bytes(value: object) -> bytes:
    """Encode supported values as deterministic UTF-8 JSON bytes."""

    return _legacy_canonical_json_text(value).encode("utf-8")


class ValueEnum(Enum):
    TUPLE = ("tuple-enum", 2, (3,))


class TupleEnum(tuple, Enum):
    MEMBERS = ("tuple-subclass-enum", 4)


class IntegerEnum(IntEnum):
    ONE = 1


class TupleSubclass(tuple):
    pass


class StringSubclass(str):
    pass


class BytesSubclass(bytes):
    pass


class DecimalSubclass(Decimal):
    pass


class DateSubclass(date):
    pass


class DatetimeSubclass(datetime):
    pass


_READS = []


class ObservedEnum(Enum):
    ORIGINAL = ("observed", 5)

    def __getattribute__(self, name):
        if name == "value":
            _READS.append(("enum-value",))
        return super().__getattribute__(name)


class ObservedMapping(Mapping):
    def __init__(self, items, *, fail=False):
        self.pairs = tuple(items)
        self.fail = fail

    def __getitem__(self, key):
        return dict(self.pairs)[key]

    def __iter__(self):
        return iter(dict(self.pairs))

    def __len__(self):
        return len(self.pairs)

    def items(self):
        _READS.append(("mapping-items",))
        if self.fail:
            raise LookupError("original mapping failure") from ValueError("original cause")
        return iter(self.pairs)


def _outcome(encoder, value):
    try:
        return ("return", encoder(value))
    except Exception as error:
        cause = error.__cause__
        return (
            "error",
            type(error),
            str(error),
            None if cause is None else (type(cause), str(cause)),
        )


def _observed(encoder, value, *, old, monkeypatch):
    """Record each recursive original delegation with no value substitution."""
    original = _legacy_typed_node if old else canonical._typed_node
    visits = []
    _READS.clear()

    def traced(item):
        assert len(visits) < 65536
        visits.append(id(item))
        return original(item)

    with monkeypatch.context() as patch:
        if old:
            patch.setitem(globals(), "_legacy_typed_node", traced)
        else:
            patch.setattr(canonical, "_typed_node", traced)
        result = _outcome(encoder, value)
    return result, tuple(visits), tuple(_READS)


VALID_VALUES = [
    pytest.param(None, id="none"),
    pytest.param(True, id="true"),
    pytest.param(False, id="false"),
    pytest.param(0, id="zero"),
    pytest.param(-(10**35), id="large-negative-integer"),
    pytest.param("é\n\x00", id="unicode-string"),
    pytest.param(b"\x00raw\xff", id="raw-bytes"),
    pytest.param(Decimal("123.45000"), id="decimal-scale"),
    pytest.param(Decimal("-0E-999"), id="negative-zero"),
    pytest.param(Decimal("1E+999"), id="compact-exponent"),
    pytest.param(DecimalSubclass("7.00"), id="decimal-subclass"),
    pytest.param(AT, id="datetime"),
    pytest.param(AT.astimezone(timezone(-timedelta(hours=4))), id="offset-datetime"),
    pytest.param(date(2025, 3, 4), id="date"),
    pytest.param(DateSubclass(2025, 3, 4), id="date-subclass"),
    pytest.param(DatetimeSubclass(2025, 3, 4, tzinfo=UTC), id="datetime-subclass"),
    pytest.param(UUID(int=8), id="uuid"),
    pytest.param(ValueEnum.TUPLE, id="tuple-valued-enum"),
    pytest.param(TupleEnum.MEMBERS, id="tuple-subclass-enum"),
    pytest.param(IntegerEnum.ONE, id="integer-enum"),
    pytest.param((), id="empty-tuple"),
    pytest.param((1, (2, (3, (4, ())))), id="nested-tuples"),
    pytest.param(
        [None, True, False, 42, "short", b"raw", Decimal("12.00")] * 8, id="scalar-list-control"
    ),
    pytest.param({str(i): i for i in range(16)}, id="scalar-mapping-control"),
    pytest.param(
        (
            {"z": (Decimal("100.00"), True), "a": frozenset({"SPY", "QQQ"})},
            [1, ("x", 2)],
            {4, 2},
            b"raw",
        ),
        id="mixed-containers",
    ),
    pytest.param(
        MappingProxyType({("b", 2): (True, b"raw"), ("a", 1): {"nested": ()}}),
        id="mapping-proxy-tuple-keys",
    ),
]


@pytest.mark.parametrize("value", VALID_VALUES)
def test_exact_original_bytes_hash_and_recursive_order_for_finite_values(value, monkeypatch):
    # Both direct scalar dispatch and nested exact-tuple dispatch stay covered.
    for material in (value, ("outer", value, (value,))):
        expected = _observed(
            _legacy_canonical_json_bytes, material, old=True, monkeypatch=monkeypatch
        )
        actual = _observed(
            canonical.canonical_json_bytes, material, old=False, monkeypatch=monkeypatch
        )
        # Private typed-node recursion changes when native text avoids the tree.
        # Preserve actual output/errors and all observable conversion/read hooks.
        assert (actual[0], actual[2]) == (expected[0], expected[2])
        assert actual[0][0] == "return"
        assert sha256(actual[0][1]).digest() == sha256(expected[0][1]).digest()


INVALID_VALUES = [
    pytest.param(1.5, id="float"),
    pytest.param(float("nan"), id="nan-float"),
    pytest.param(object(), id="object"),
    pytest.param(TupleSubclass((1,)), id="tuple-subclass"),
    pytest.param(StringSubclass("x"), id="string-subclass"),
    pytest.param(BytesSubclass(b"x"), id="bytes-subclass"),
    pytest.param(memoryview(b"x"), id="memoryview"),
    pytest.param(bytearray(b"x"), id="bytearray"),
    pytest.param(Decimal("NaN"), id="decimal-nan"),
    pytest.param(Decimal("sNaN"), id="decimal-signaling-nan"),
    pytest.param(Decimal("Infinity"), id="decimal-infinity"),
    pytest.param(datetime(2025, 3, 4), id="naive-datetime"),
    pytest.param(complex(1, 2), id="complex"),
    pytest.param(int, id="class"),
]


@pytest.mark.parametrize("value", INVALID_VALUES)
def test_ordinary_error_and_first_failure_leaf_order_are_unchanged(value, monkeypatch):
    for material in (value, (1, (value,), ObservedEnum.ORIGINAL)):
        expected = _observed(
            _legacy_canonical_json_bytes, material, old=True, monkeypatch=monkeypatch
        )
        actual = _observed(
            canonical.canonical_json_bytes, material, old=False, monkeypatch=monkeypatch
        )
        # Private typed-node recursion changes when native text avoids the tree.
        # Preserve actual output/errors and all observable conversion/read hooks.
        assert (actual[0], actual[2]) == (expected[0], expected[2])
        assert actual[0][0] == "error"
        assert actual[2] == ()  # The later Enum.value is never read after rejection.


@pytest.mark.parametrize("fault", ["none", "mapping", "earlier-leaf"])
def test_mapping_enum_reads_and_original_exception_cause_remain_in_order(fault, monkeypatch):
    mapping = ObservedMapping(
        (("z", (ObservedEnum.ORIGINAL, 3)), ("a", (2, 1))), fail=fault == "mapping"
    )
    material = ((object(),), mapping) if fault == "earlier-leaf" else (mapping,)
    expected = _observed(_legacy_canonical_json_bytes, material, old=True, monkeypatch=monkeypatch)
    actual = _observed(canonical.canonical_json_bytes, material, old=False, monkeypatch=monkeypatch)
    assert (actual[0], actual[2]) == (expected[0], expected[2])
    if fault == "none":
        assert actual[0][0] == "return"
        assert actual[2] == (("mapping-items",), ("enum-value",))
    elif fault == "mapping":
        assert actual[0] == (
            "error",
            LookupError,
            "original mapping failure",
            (ValueError, "original cause"),
        )
        assert actual[2] == (("mapping-items",),)
    else:
        assert actual[2] == ()


@pytest.mark.parametrize("kind", GOLDENS)
def test_actual_contract_semantic_material_has_exact_original_bytes_and_golden(kind):
    record = record_for(kind)
    material = semantic_value((record.contract_version, record))
    expected = _legacy_canonical_json_bytes(material)
    assert canonical.canonical_json_bytes(material) == expected
    assert record.semantic_sha256 == sha256(expected).hexdigest() == GOLDENS[kind]
    assert (
        content_digest(record)
        == sha256(_legacy_canonical_json_bytes(semantic_value(record))).hexdigest()
    )


def test_actual_engine_event_and_execution_calendar_keep_original_full_material():
    event = _event()
    calendar = SettlementCalendar("tuple-fixture", "1", (date(2025, 1, 3), date(2025, 1, 6)))
    for record in (event, event.payload, event.provenance, calendar, ExecutionPolicy(calendar)):
        material = semantic_value((record.contract_version, record))
        payload = _legacy_canonical_json_bytes(material)
        assert canonical.canonical_json_bytes(material) == payload
        assert record.semantic_sha256 == sha256(payload).hexdigest()


def test_original_canonical_bytes_ignore_aliasing_but_recheck_mutations_between_calls():
    shared = [Decimal("12.340"), {"nested": (b"raw", None)}]
    aliased = (shared, shared)
    equal = (
        [Decimal("12.340"), {"nested": (b"raw", None)}],
        [Decimal("12.340"), {"nested": (b"raw", None)}],
    )
    before = _legacy_canonical_json_bytes(aliased)
    assert canonical.canonical_json_bytes(aliased) == before
    assert canonical.canonical_json_bytes(equal) == _legacy_canonical_json_bytes(equal) == before
    shared[1]["nested"] = (b"changed", False)
    assert (
        canonical.canonical_json_bytes(aliased) == _legacy_canonical_json_bytes(aliased) != before
    )
    assert canonical.canonical_json_bytes(equal) == before
    shared[1]["nested"] = (b"raw", None)
    assert canonical.canonical_json_bytes(aliased) == before


def test_original_real_nested_record_mutation_and_equal_copy_are_rehashed():
    record = record_for("append")
    copied = replace(record)
    before = record.semantic_sha256
    assert copied is not record and copied.semantic_sha256 == before
    original = record.records[0].payload
    try:
        object.__setattr__(record.records[0], "payload", b"changed original retained bytes")
        expected = sha256(
            _legacy_canonical_json_bytes(semantic_value((record.contract_version, record)))
        ).hexdigest()
        assert record.semantic_sha256 == copied.semantic_sha256 == expected != before
    finally:
        object.__setattr__(record.records[0], "payload", original)
    assert record.semantic_sha256 == copied.semantic_sha256 == before


@pytest.mark.parametrize("fault", ["float", "decimal", "naive-time", "record-class"])
def test_corrupted_real_record_semantic_material_keeps_original_errors(fault):
    record = record_for("mark" if fault != "record-class" else "append")
    field, value = {
        "float": ("price", 1.25),
        "decimal": ("price", Decimal("Infinity")),
        "naive-time": ("knowledge_at", AT.replace(tzinfo=None)),
        "record-class": ("records", (type(record),)),
    }[fault]
    original = getattr(record, field)
    try:
        object.__setattr__(record, field, value)
        material = semantic_value((record.contract_version, record))
        expected = _outcome(_legacy_canonical_json_bytes, material)
        actual = _outcome(canonical.canonical_json_bytes, material)
        assert actual == expected and actual[0] == "error"
        with pytest.raises(actual[1], match="canonical"):
            _ = record.semantic_sha256
    finally:
        object.__setattr__(record, field, original)


def test_decimal_context_does_not_change_exact_original_bytes():
    value = (Decimal("12345678901234567890123456789.12345678900"), Decimal("-0E-50"))
    expected = _legacy_canonical_json_bytes(value)
    with localcontext() as context:
        context.prec = 2
        assert (
            canonical.canonical_json_bytes(value) == _legacy_canonical_json_bytes(value) == expected
        )


def test_literal_oracle_is_independent_of_candidate_helpers(monkeypatch):
    value = ((Decimal("1.23400"), "é", b"raw"),)
    expected = _legacy_canonical_json_bytes(value)

    def forbidden(*args, **kwargs):
        raise AssertionError("candidate encoder cannot supply an oracle intermediate")

    for name in (
        "canonical_decimal",
        "canonical_decimal_text",
        "_typed_node",
        "_json_text",
        "canonical_json_text",
        "canonical_json_bytes",
    ):
        monkeypatch.setattr(canonical, name, forbidden)
    assert _legacy_canonical_json_bytes(value) == expected
