"""Shared immutable values for the offline personal economic engine.

These records identify simulation inputs and observations; none is an execution
permit, broker attestation or replacement for the retained canonical reducers.
"""

from __future__ import annotations

import hashlib
import re
import types
from dataclasses import dataclass, fields, is_dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import ClassVar, Literal, TypeAliasType, Union, get_args, get_origin, get_type_hints

from packages.domain.canonical import canonical_json_bytes, canonical_persisted_decimal


def semantic_value(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return (
            type(value).__module__ + "." + type(value).__qualname__,
            tuple((f.name, semantic_value(getattr(value, f.name))) for f in fields(value)),
        )
    if type(value) is tuple:
        return tuple(semantic_value(v) for v in value)
    return value


def content_digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(semantic_value(value))).hexdigest()


def require_text(value: str, name: str) -> None:
    if type(value) is not str or not value or value != value.strip() or len(value) > 2048:
        raise ValueError(f"{name} requires bounded nonempty trimmed text")


def require_digest(value: str, name: str) -> None:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"{name} requires a SHA-256 digest")


def require_utc(value: datetime, name: str) -> None:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise ValueError(f"{name} requires an aware UTC datetime")


def require_amount(
    value: Decimal,
    name: str,
    *,
    nonnegative: bool = False,
    positive: bool = False,
    whole: bool = False,
) -> None:
    if type(value) is not Decimal:
        raise ValueError(f"{name} requires exact Decimal")
    canonical_persisted_decimal(value, name)
    if (nonnegative and value < 0) or (positive and value <= 0):
        raise ValueError(f"{name} is outside its permitted range")
    if whole and value != value.to_integral_value():
        raise ValueError(f"{name} requires whole units")


_TYPE_HINTS: dict[type, dict[str, object]] = {}


def _hints(cls: type) -> dict[str, object]:
    if cls not in _TYPE_HINTS:
        _TYPE_HINTS[cls] = get_type_hints(cls)
    return _TYPE_HINTS[cls]


def _check_type(value: object, annotation: object, name: str) -> None:
    if isinstance(annotation, TypeAliasType):
        _check_type(value, annotation.__value__, name)
        return
    origin, args = get_origin(annotation), get_args(annotation)
    if origin in (types.UnionType, Union):
        for candidate in args:
            try:
                _check_type(value, candidate, name)
                return
            except (TypeError, ValueError):
                pass
        raise ValueError(f"{name} has an unsupported value type")
    if origin is Literal:
        if not any(type(value) is type(v) and value == v for v in args):
            raise ValueError(f"{name} has an unsupported literal")
        return
    if origin is tuple:
        if type(value) is not tuple:
            raise ValueError(f"{name} must be immutable tuple")
        if len(args) == 2 and args[1] is Ellipsis:
            for item in value:
                _check_type(item, args[0], name)
        elif len(value) == len(args):
            for item, expected in zip(value, args, strict=True):
                _check_type(item, expected, name)
        else:
            raise ValueError(f"{name} tuple shape differs")
        return
    if annotation is type(None):
        if value is not None:
            raise ValueError(f"{name} must be null")
        return
    if not isinstance(annotation, type) or type(value) is not annotation:
        raise ValueError(f"{name} has an unsupported value type")
    if type(value) is Decimal and not value.is_finite():
        raise ValueError(f"{name} must be finite")
    if type(value) is datetime:
        require_utc(value, name)
    if type(value) is str and len(value) > 65536:
        raise ValueError(f"{name} exceeds text bound")


class ContractRecord:
    """Type/immutability admission plus canonical, context-free content identity."""

    __slots__ = ()
    contract_version: ClassVar[str] = "personal-engine-values/1"

    def __post_init__(self) -> None:
        hints = _hints(type(self))
        for f in fields(self):  # type: ignore[arg-type]
            _check_type(getattr(self, f.name), hints[f.name], f.name)

    @property
    def semantic_sha256(self) -> str:
        return content_digest((self.contract_version, semantic_value(self)))


@dataclass(frozen=True, slots=True)
class VersionPin(ContractRecord):
    name: str
    version: str
    sha256: str

    def __post_init__(self) -> None:
        super(VersionPin, self).__post_init__()
        require_text(self.name, "pin name")
        require_text(self.version, "pin version")
        require_digest(self.sha256, "pin content")


@dataclass(frozen=True, slots=True)
class ReductionPoint(ContractRecord):
    frontier_sequence: int
    reduction_sequence: int
    knowledge_at: datetime
    stage: int

    def __post_init__(self) -> None:
        super(ReductionPoint, self).__post_init__()
        if self.frontier_sequence < 0 or self.reduction_sequence < 0 or not 0 <= self.stage <= 8:
            raise ValueError("invalid engine reduction point")


@dataclass(frozen=True, slots=True)
class CausalMark(ContractRecord):
    mark_id: str
    instrument_id: str
    symbol: str
    price: Decimal
    session: date
    economic_at: datetime
    knowledge_at: datetime
    source_sha256: str
    quality: Literal["current", "last_known", "unavailable"] = "current"
    basis: Literal["raw_close", "raw_execution", "synthetic_boundary"] = "raw_close"

    def __post_init__(self) -> None:
        super(CausalMark, self).__post_init__()
        for name in ("mark_id", "instrument_id", "symbol"):
            require_text(getattr(self, name), name)
        require_digest(self.source_sha256, "mark source")
        require_amount(self.price, "mark price", positive=True)
        if self.economic_at > self.knowledge_at:
            raise ValueError("mark cannot precede economic time")
