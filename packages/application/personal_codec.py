"""Bounded JSON codec for declared immutable research records.

Types come exclusively from the caller's expected annotation graph. Wire names
are compared to that graph; they never select an import or bypass constructors.
This is a storage boundary, not proof that a result was economically computed.
"""

from __future__ import annotations

import json
import types
from dataclasses import fields, is_dataclass
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from functools import lru_cache
from typing import Literal, TypeAliasType, Union, cast, get_args, get_origin, get_type_hints

from packages.domain.personal_contracts import require_utc

CODEC_VERSION = "personal-record/1"
MAX_RECORD_BYTES = 64 * 1024 * 1024
_MAX_DEPTH = 64


def _name(cls: type) -> str:
    return cls.__module__ + "." + cls.__qualname__


@lru_cache(maxsize=512)
def _hints(cls: type) -> dict[str, object]:
    return get_type_hints(cls)


def _pack(value: object, depth: int = 0) -> object:
    if depth > _MAX_DEPTH:
        raise ValueError("research record nesting exceeds limit")
    if isinstance(value, Enum):
        return {"$enum": _name(type(value)), "value": _pack(value.value, depth + 1)}
    if type(value) is Decimal:
        if not value.is_finite() or len(str(value)) > 256:
            raise ValueError("invalid research decimal")
        return {"$decimal": str(value)}
    if type(value) is datetime:
        require_utc(value, "research time")
        return {"$datetime": value.isoformat()}
    if type(value) is date:
        return {"$date": value.isoformat()}
    if type(value) is tuple:
        return [_pack(item, depth + 1) for item in value]
    if is_dataclass(value) and not isinstance(value, type):
        if not vars(type(value))["__dataclass_params__"].frozen:
            raise ValueError("research record must be frozen")
        if any(not field.init for field in fields(value)):
            raise ValueError("derived dataclass fields require a dedicated codec")
        return {
            "$record": _name(type(value)),
            "fields": {
                field.name: _pack(getattr(value, field.name), depth + 1) for field in fields(value)
            },
        }
    if value is None or type(value) in (str, int, bool):
        if isinstance(value, str) and len(value) > 65536:
            raise ValueError("research text exceeds limit")
        return value
    raise ValueError("unsupported research record value")


def encode_record(value: object) -> bytes:
    """Encode exact scalars and frozen dataclasses deterministically, without I/O."""
    payload = (
        json.dumps(
            {"codec": CODEC_VERSION, "value": _pack(value)},
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )
    if len(payload) > MAX_RECORD_BYTES:
        raise ValueError("research record exceeds byte limit")
    return payload


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate research JSON key")
        result[key] = value
    return result


def _reject_number(_value: str) -> object:
    raise ValueError("research JSON requires exact typed numbers")


def _mapping(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise ValueError("research record fields differ")
    return cast(dict[str, object], value)


def _text(value: object) -> str:
    if type(value) is not str or len(value) > 65536:
        raise ValueError("invalid research text")
    return value


def _unpack(value: object, annotation: object, depth: int = 0) -> object:
    if depth > _MAX_DEPTH:
        raise ValueError("research record nesting exceeds limit")
    if isinstance(annotation, TypeAliasType):
        return _unpack(value, annotation.__value__, depth + 1)
    origin, args = get_origin(annotation), get_args(annotation)
    if origin in (types.UnionType, Union):
        for candidate in args:
            try:
                return _unpack(value, candidate, depth + 1)
            except (TypeError, ValueError):
                pass
        raise ValueError("research record does not match declared union")
    if origin is Literal:
        if any(type(value) is type(item) and value == item for item in args):
            return value
        raise ValueError("invalid research literal")
    if origin is tuple:
        if type(value) is not list:
            raise ValueError("research tuple requires array")
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_unpack(item, args[0], depth + 1) for item in value)
        if len(args) != len(value):
            raise ValueError("research tuple length differs")
        return tuple(
            _unpack(item, expected, depth + 1) for item, expected in zip(value, args, strict=True)
        )
    if not isinstance(annotation, type):
        raise ValueError("unsupported research annotation")
    if issubclass(annotation, Enum):
        enum = _mapping(value, {"$enum", "value"})
        if enum["$enum"] != _name(annotation):
            raise ValueError("research enum type differs")
        if type(enum["value"]) is not str:
            raise ValueError("research enum requires text")
        return annotation(enum["value"])
    if annotation in (Decimal, datetime, date):
        key = {Decimal: "$decimal", datetime: "$datetime", date: "$date"}[annotation]
        token = _text(_mapping(value, {key})[key])
        if annotation is Decimal:
            if len(token) > 256:
                raise ValueError("research decimal exceeds limit")
            result = Decimal(token)
            if not result.is_finite():
                raise ValueError("research decimal must be finite")
            return result
        if annotation is datetime:
            instant = datetime.fromisoformat(token)
            require_utc(instant, "research time")
            return instant
        return date.fromisoformat(token)
    if is_dataclass(annotation):
        record = _mapping(value, {"$record", "fields"})
        if record["$record"] != _name(annotation):
            raise ValueError("research dataclass type differs")
        definitions = fields(annotation)
        if not vars(annotation)["__dataclass_params__"].frozen or any(
            not field.init for field in definitions
        ):
            raise ValueError("unsupported research dataclass shape")
        values = _mapping(record["fields"], {field.name for field in definitions})
        hints = _hints(annotation)
        return annotation(
            **{
                field.name: _unpack(values[field.name], hints[field.name], depth + 1)
                for field in definitions
            }
        )
    if annotation in (str, int, bool, type(None)) and type(value) is annotation:
        if annotation is str:
            return _text(value)
        return value
    raise ValueError("research scalar type differs")


def decode_record[T](payload: bytes, expected_type: type[T]) -> T:
    """Reconstruct only the expected record graph, running every constructor."""
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_RECORD_BYTES:
        raise ValueError("research record exceeds byte limit")
    try:
        envelope = _mapping(
            json.loads(
                payload,
                object_pairs_hook=_object,
                parse_float=_reject_number,
                parse_constant=_reject_number,
            ),
            {"codec", "value"},
        )
        if envelope["codec"] != CODEC_VERSION:
            raise ValueError("research codec version differs")
        value = _unpack(envelope["value"], expected_type)
        if encode_record(value) != payload:
            raise ValueError("research record is not canonical")
        return cast(T, value)
    except (RecursionError, UnicodeError, ArithmeticError) as exc:
        raise ValueError("invalid research record encoding") from exc
