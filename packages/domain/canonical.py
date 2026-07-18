"""Context-free canonical encodings for deterministic domain identities."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import Enum
from uuid import UUID

PERSISTED_DECIMAL_PRECISION = 28
PERSISTED_DECIMAL_SCALE = 10
PERSISTED_DECIMAL_INTEGER_DIGITS = PERSISTED_DECIMAL_PRECISION - PERSISTED_DECIMAL_SCALE


def canonical_decimal(value: Decimal) -> Decimal:
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


def canonical_decimal_text(value: Decimal) -> str:
    """Return a compact, exact coefficient/exponent representation."""

    canonical = canonical_decimal(value)
    sign, digits, raw_exponent = canonical.as_tuple()
    if not any(digits):
        return "0"
    coefficient = "".join(str(digit) for digit in digits)
    prefix = "-" if sign else ""
    return f"{prefix}{coefficient}e{int(raw_exponent)}"


def canonical_persisted_decimal(value: Decimal, field_name: str) -> Decimal:
    """Return a canonical value exactly representable by NUMERIC(28, 10)."""

    canonical = canonical_decimal(value)
    _, digits, raw_exponent = canonical.as_tuple()
    if not any(digits):
        return canonical
    exponent = int(raw_exponent)
    adjusted_exponent = len(digits) + exponent - 1
    if exponent < -PERSISTED_DECIMAL_SCALE or adjusted_exponent >= PERSISTED_DECIMAL_INTEGER_DIGITS:
        raise ValueError(f"{field_name} must fit NUMERIC(28, 10) exactly")
    return canonical


def _json_text(node: object) -> str:
    return json.dumps(
        node,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _typed_node(value: object) -> object:
    if value is None:
        return {"type": "null", "value": None}
    if isinstance(value, Enum):
        enum_type = type(value)
        return {
            "enum_type": f"{enum_type.__module__}.{enum_type.__qualname__}",
            "type": "enum",
            "value": _typed_node(value.value),
        }
    if type(value) is bool:
        return {"type": "bool", "value": value}
    if type(value) is int:
        return {"type": "int", "value": str(value)}
    if isinstance(value, Decimal):
        return {"type": "decimal", "value": canonical_decimal_text(value)}
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
        return {"type": "tuple", "value": [_typed_node(item) for item in value]}
    if type(value) is list:
        return {"type": "list", "value": [_typed_node(item) for item in value]}
    if isinstance(value, Mapping):
        entries = [
            {"key": _typed_node(key), "value": _typed_node(item)} for key, item in value.items()
        ]
        entries.sort(key=lambda entry: _json_text(entry["key"]))
        return {"type": "mapping", "value": entries}
    if type(value) is set or type(value) is frozenset:
        items = [_typed_node(item) for item in value]
        items.sort(key=_json_text)
        collection_type = "set" if type(value) is set else "frozenset"
        return {"type": collection_type, "value": items}
    raise TypeError(f"unsupported canonical JSON value type: {type(value).__qualname__}")


def canonical_json_text(value: object) -> str:
    """Encode supported values as deterministic, explicitly typed JSON."""

    return _json_text(_typed_node(value))


def canonical_json_bytes(value: object) -> bytes:
    """Encode supported values as deterministic UTF-8 JSON bytes."""

    return canonical_json_text(value).encode("utf-8")
