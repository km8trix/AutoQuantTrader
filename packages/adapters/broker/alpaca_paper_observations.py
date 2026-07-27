"""Strict, offline Alpaca paper client-order lookup observations.

This module decodes bounded response bytes for the deterministic
``GET /v2/orders:by_client_order_id`` recovery path.  The resulting values are
immutable evidence only: they cannot perform transport I/O, resolve an UNKNOWN
submission, create canonical execution facts, or authorize a broker effect.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from types import MappingProxyType
from typing import Any, cast
from uuid import UUID

from packages.adapters.broker.alpaca_paper import (
    ALPACA_DOCUMENTED_EQUITY_ORDER_CLASSES,
    ALPACA_DOCUMENTED_EQUITY_ORDER_TYPES,
    ALPACA_DOCUMENTED_EQUITY_TIME_IN_FORCE,
    ALPACA_ORDER_BY_CLIENT_ID_PATH,
    ALPACA_PAPER_CAPABILITIES,
    ALPACA_PAPER_CAPABILITY_CONTRACT_VERSION,
    ALPACA_PAPER_TRADING_BASE_URL,
    AlpacaOrderDisposition,
    AlpacaOrderStatus,
    AlpacaPaperContractError,
    AlpacaPaperSubmissionDescription,
    classify_alpaca_order_status,
)
from packages.domain.canonical import canonical_decimal, canonical_json_bytes
from packages.domain.models import require_utc

ALPACA_PAPER_OBSERVATION_CONTRACT_VERSION = "phase4b-alpaca-paper-client-order-observation-v1"
ALPACA_PAPER_MAX_LOOKUP_RESPONSE_BYTES = 262_144
_ALPACA_PAPER_MAX_ERROR_CODE = 2_147_483_647

_ALPACA_ORDER_REQUIRED_RESPONSE_KEYS = frozenset(
    {
        "asset_class",
        "asset_id",
        "canceled_at",
        "client_order_id",
        "created_at",
        "expired_at",
        "extended_hours",
        "failed_at",
        "filled_at",
        "filled_avg_price",
        "filled_qty",
        "hwm",
        "id",
        "legs",
        "limit_price",
        "notional",
        "order_class",
        "qty",
        "replaced_at",
        "replaced_by",
        "replaces",
        "side",
        "status",
        "stop_price",
        "submitted_at",
        "symbol",
        "time_in_force",
        "trail_percent",
        "trail_price",
        "type",
        "updated_at",
    }
)
_ALPACA_ORDER_OPTIONAL_RESPONSE_KEYS = frozenset(
    {
        "expires_at",
        "order_type",
        "position_intent",
        "ratio_qty",
        "source",
        "subtag",
    }
)
_ALPACA_ORDER_RESPONSE_KEYS = (
    _ALPACA_ORDER_REQUIRED_RESPONSE_KEYS | _ALPACA_ORDER_OPTIONAL_RESPONSE_KEYS
)
_ALPACA_NOT_FOUND_KEYS = frozenset({"code", "message"})
_ALPACA_OBSERVED_ORDER_CLASSES = frozenset((*ALPACA_DOCUMENTED_EQUITY_ORDER_CLASSES, "", "mleg"))
_ALPACA_POSITION_INTENTS = frozenset(
    {"buy_to_close", "buy_to_open", "sell_to_close", "sell_to_open"}
)
_ALPACA_SIDES = frozenset({"buy", "sell"})
_ALPACA_MISMATCH_FIELD_NAMES = frozenset(
    {
        "asset_class",
        "extended_hours",
        "high_water_mark",
        "legs",
        "limit_price",
        "notional",
        "order_class",
        "order_type",
        "position_intent",
        "quantity",
        "ratio_quantity",
        "replacement_chain",
        "side",
        "stop_price",
        "symbol",
        "time_in_force",
        "trail_percent",
        "trail_price",
        "type",
    }
)
_DECIMAL_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,18})?")
_TIMESTAMP_PATTERN = re.compile(
    r"(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})"
    r"T(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?"
    r"(?P<zone>Z|[+-][0-9]{2}:[0-9]{2})"
)
_SYMBOL_PATTERN = re.compile(r"[A-Z][A-Z0-9./-]{0,31}")


class AlpacaPaperObservationError(AlpacaPaperContractError):
    """A lookup description or retained response violates the frozen contract."""


class AlpacaClientOrderLookupOutcome(StrEnum):
    """Closed meanings for one offline client-order lookup response."""

    FOUND_MATCHED = "found_matched"
    FOUND_MISMATCH = "found_mismatch"
    NOT_VISIBLE_INCONCLUSIVE = "not_visible_inconclusive"


def _require_text(
    value: object,
    field_name: str,
    *,
    maximum_length: int,
    allow_empty: bool = False,
) -> str:
    if type(value) is not str:
        raise AlpacaPaperObservationError(f"{field_name} must be an exact string")
    if (
        len(value) > maximum_length
        or (not allow_empty and not value)
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise AlpacaPaperObservationError(
            f"{field_name} must be bounded, trimmed text without control characters"
        )
    return value


def _require_optional_text(
    value: object,
    field_name: str,
    *,
    maximum_length: int,
    allow_empty: bool = False,
) -> str | None:
    if value is None:
        return None
    return _require_text(
        value,
        field_name,
        maximum_length=maximum_length,
        allow_empty=allow_empty,
    )


def _require_sha256(value: object, field_name: str) -> str:
    digest = _require_text(value, field_name, maximum_length=64)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise AlpacaPaperObservationError(f"{field_name} must be a lowercase SHA-256 digest")
    return digest


def _require_uuid(value: object, field_name: str) -> str:
    raw = _require_text(value, field_name, maximum_length=36)
    try:
        parsed = UUID(raw)
    except (TypeError, ValueError, AttributeError) as error:
        raise AlpacaPaperObservationError(f"{field_name} must be a canonical UUID") from error
    if str(parsed) != raw:
        raise AlpacaPaperObservationError(f"{field_name} must be a canonical lowercase UUID")
    return raw


def _require_optional_uuid(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_uuid(value, field_name)


def _require_optional_or_empty_uuid(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    if value == "":
        return _require_text(value, field_name, maximum_length=36, allow_empty=True)
    return _require_uuid(value, field_name)


def _require_decimal_text(
    value: object,
    field_name: str,
    *,
    allow_zero: bool,
) -> Decimal:
    raw = _require_text(value, field_name, maximum_length=64)
    if _DECIMAL_PATTERN.fullmatch(raw) is None:
        raise AlpacaPaperObservationError(
            f"{field_name} must be a bounded non-negative plain decimal string"
        )
    integer, separator, fraction = raw.partition(".")
    if len(integer) > 18 or (separator and len(fraction) > 18):
        raise AlpacaPaperObservationError(f"{field_name} exceeds the frozen decimal bounds")
    try:
        result = canonical_decimal(Decimal(raw))
    except (InvalidOperation, ValueError) as error:
        raise AlpacaPaperObservationError(f"{field_name} is not a finite decimal") from error
    if result < 0 or (not allow_zero and result == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise AlpacaPaperObservationError(f"{field_name} must be {qualifier}")
    return result


def _require_optional_decimal_text(
    value: object,
    field_name: str,
    *,
    allow_zero: bool,
) -> Decimal | None:
    if value is None:
        return None
    return _require_decimal_text(value, field_name, allow_zero=allow_zero)


@dataclass(frozen=True, slots=True)
class AlpacaProviderTimestamp:
    """An exact provider timestamp with nanosecond-preserving UTC identity."""

    raw: str
    utc_second: datetime = field(init=False, repr=False)
    nanosecond: int = field(init=False)

    def __post_init__(self) -> None:
        raw = _require_text(self.raw, "Alpaca timestamp", maximum_length=40)
        matched = _TIMESTAMP_PATTERN.fullmatch(raw)
        if matched is None:
            raise AlpacaPaperObservationError(
                "Alpaca timestamp must be an exact ISO-8601 value with at most 9 fractional digits"
            )
        zone = matched.group("zone")
        if zone == "-00:00":
            raise AlpacaPaperObservationError(
                "Alpaca timestamp must not use the RFC 3339 unknown-offset marker"
            )
        base_text = f"{matched.group('date')}T{matched.group('time')}"
        base_text += "+00:00" if zone == "Z" else zone
        try:
            parsed = datetime.fromisoformat(base_text)
        except ValueError as error:
            raise AlpacaPaperObservationError("Alpaca timestamp is not a valid instant") from error
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise AlpacaPaperObservationError("Alpaca timestamp must include an offset")
        fraction = matched.group("fraction") or ""
        object.__setattr__(self, "utc_second", parsed.astimezone(UTC))
        object.__setattr__(self, "nanosecond", int(fraction.ljust(9, "0")) if fraction else 0)

    @property
    def normalized_utc(self) -> str:
        base = self.utc_second.isoformat(timespec="seconds").replace("+00:00", "Z")
        if self.nanosecond == 0:
            return base
        fraction = f"{self.nanosecond:09d}".rstrip("0")
        return f"{base[:-1]}.{fraction}Z"

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                (
                    ALPACA_PAPER_OBSERVATION_CONTRACT_VERSION,
                    "provider_timestamp",
                    self.raw,
                    self.normalized_utc,
                    self.nanosecond,
                )
            )
        ).hexdigest()


def _require_timestamp(value: object, field_name: str) -> AlpacaProviderTimestamp:
    try:
        return AlpacaProviderTimestamp(_require_text(value, field_name, maximum_length=40))
    except AlpacaPaperObservationError as error:
        raise AlpacaPaperObservationError(f"{field_name} is invalid: {error}") from error


def _require_optional_timestamp(
    value: object,
    field_name: str,
) -> AlpacaProviderTimestamp | None:
    if value is None:
        return None
    return _require_timestamp(value, field_name)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AlpacaPaperObservationError(
                f"Alpaca lookup response contains duplicate JSON key {key!r}"
            )
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise AlpacaPaperObservationError(
        f"Alpaca lookup response contains non-standard JSON constant {value!r}"
    )


def _decode_response_object(response_body: bytes) -> dict[str, Any]:
    if type(response_body) is not bytes:
        raise AlpacaPaperObservationError("Alpaca lookup response must be exact bytes")
    if not 1 <= len(response_body) <= ALPACA_PAPER_MAX_LOOKUP_RESPONSE_BYTES:
        raise AlpacaPaperObservationError("Alpaca lookup response size is outside the bound")
    try:
        text = response_body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AlpacaPaperObservationError("Alpaca lookup response must be UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except AlpacaPaperObservationError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as error:
        raise AlpacaPaperObservationError("Alpaca lookup response is invalid JSON") from error
    if type(value) is not dict:
        raise AlpacaPaperObservationError("Alpaca lookup response must be one JSON object")
    return cast(dict[str, Any], value)


def _require_exact_keys(
    value: Mapping[str, Any],
    expected_keys: frozenset[str],
    field_name: str,
) -> None:
    actual = frozenset(value)
    if actual != expected_keys:
        missing = tuple(sorted(expected_keys - actual))
        extra = tuple(sorted(actual - expected_keys))
        raise AlpacaPaperObservationError(
            f"{field_name} shape drifted; missing={missing!r}, extra={extra!r}"
        )


def _require_order_response_keys(value: Mapping[str, Any]) -> None:
    actual = frozenset(value)
    missing = tuple(sorted(_ALPACA_ORDER_REQUIRED_RESPONSE_KEYS - actual))
    extra = tuple(sorted(actual - _ALPACA_ORDER_RESPONSE_KEYS))
    if missing or extra:
        raise AlpacaPaperObservationError(
            "Alpaca order response is outside the local accepted wire profile; "
            f"missing={missing!r}, extra={extra!r}"
        )


def _plain_json_sha256(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise AlpacaPaperObservationError("Alpaca nested order JSON is unsupported") from error
    return hashlib.sha256(encoded).hexdigest()


def _enum_text(
    value: object,
    field_name: str,
    allowed: frozenset[str],
    *,
    allow_empty: bool = False,
    allow_none: bool = False,
) -> str | None:
    if value is None and allow_none:
        return None
    raw = _require_text(
        value,
        field_name,
        maximum_length=64,
        allow_empty=allow_empty,
    )
    if allow_empty and raw == "":
        return raw
    if raw not in allowed:
        raise AlpacaPaperObservationError(f"{field_name} has unsupported value {raw!r}")
    return raw


@dataclass(frozen=True, slots=True)
class AlpacaOrderObservation:
    """A locally profiled REST order object, never an execution event."""

    provider_order_id: str
    client_order_id: str
    created_at: AlpacaProviderTimestamp
    updated_at: AlpacaProviderTimestamp | None
    submitted_at: AlpacaProviderTimestamp | None
    filled_at: AlpacaProviderTimestamp | None
    expired_at: AlpacaProviderTimestamp | None
    expires_at: AlpacaProviderTimestamp | None
    canceled_at: AlpacaProviderTimestamp | None
    failed_at: AlpacaProviderTimestamp | None
    replaced_at: AlpacaProviderTimestamp | None
    replaced_by: str | None
    replaces: str | None
    asset_id: str | None
    symbol: str | None
    asset_class: str | None
    notional: Decimal | None
    quantity: Decimal | None
    filled_quantity: Decimal
    filled_average_price: Decimal | None
    order_class: str
    order_type: str | None
    type: str | None
    side: str | None
    time_in_force: str
    limit_price: Decimal | None
    stop_price: Decimal | None
    status: AlpacaOrderStatus
    extended_hours: bool
    legs_sha256: str | None
    trail_percent: Decimal | None
    trail_price: Decimal | None
    high_water_mark: Decimal | None
    position_intent: str | None
    ratio_quantity: Decimal | None
    source: str | None
    subtag: str | None

    def __post_init__(self) -> None:
        _require_uuid(self.provider_order_id, "Alpaca provider order ID")
        _require_text(
            self.client_order_id,
            "Alpaca client order ID",
            maximum_length=128,
        )
        if type(self.created_at) is not AlpacaProviderTimestamp:
            raise AlpacaPaperObservationError("created_at must be an exact provider timestamp")
        self.created_at.__post_init__()
        for field_name in (
            "updated_at",
            "submitted_at",
            "filled_at",
            "expired_at",
            "expires_at",
            "canceled_at",
            "failed_at",
            "replaced_at",
        ):
            value = getattr(self, field_name)
            if value is not None and type(value) is not AlpacaProviderTimestamp:
                raise AlpacaPaperObservationError(
                    f"{field_name} must be an exact provider timestamp or null"
                )
            if value is not None:
                value.__post_init__()
        _require_optional_uuid(self.replaced_by, "Alpaca replaced_by")
        _require_optional_uuid(self.replaces, "Alpaca replaces")
        _require_optional_or_empty_uuid(self.asset_id, "Alpaca asset ID")
        if self.symbol is not None:
            symbol = _require_text(
                self.symbol,
                "Alpaca symbol",
                maximum_length=32,
                allow_empty=True,
            )
            if symbol and _SYMBOL_PATTERN.fullmatch(symbol) is None:
                raise AlpacaPaperObservationError("Alpaca symbol is not canonical")
        if self.asset_class is not None:
            _require_text(
                self.asset_class,
                "Alpaca asset class",
                maximum_length=64,
                allow_empty=True,
            )
        for value, field_name, allow_zero in (
            (self.notional, "Alpaca notional", False),
            (self.quantity, "Alpaca quantity", False),
            (self.filled_quantity, "Alpaca filled quantity", True),
            (self.filled_average_price, "Alpaca filled average price", True),
            (self.limit_price, "Alpaca limit price", False),
            (self.stop_price, "Alpaca stop price", False),
            (self.trail_percent, "Alpaca trail percent", False),
            (self.trail_price, "Alpaca trail price", False),
            (self.high_water_mark, "Alpaca high water mark", False),
            (self.ratio_quantity, "Alpaca ratio quantity", False),
        ):
            if value is None:
                if field_name == "Alpaca filled quantity":
                    raise AlpacaPaperObservationError("filled quantity cannot be null")
                continue
            if type(value) is not Decimal or not value.is_finite():
                raise AlpacaPaperObservationError(f"{field_name} must be an exact Decimal")
            if value < 0 or (not allow_zero and value == 0):
                raise AlpacaPaperObservationError(f"{field_name} has an invalid sign")
        if (self.notional is None) == (self.quantity is None):
            raise AlpacaPaperObservationError(
                "Alpaca order must contain exactly one positive qty or notional"
            )
        if self.quantity is not None and self.filled_quantity > self.quantity:
            raise AlpacaPaperObservationError("Alpaca cumulative fill exceeds order quantity")
        _enum_text(
            self.order_class,
            "Alpaca order class",
            _ALPACA_OBSERVED_ORDER_CLASSES,
            allow_empty=True,
        )
        _enum_text(
            self.order_type,
            "Alpaca deprecated order type",
            frozenset(ALPACA_DOCUMENTED_EQUITY_ORDER_TYPES),
            allow_empty=True,
            allow_none=True,
        )
        _enum_text(
            self.type,
            "Alpaca order type",
            frozenset(ALPACA_DOCUMENTED_EQUITY_ORDER_TYPES),
            allow_empty=True,
            allow_none=True,
        )
        _enum_text(
            self.side,
            "Alpaca order side",
            _ALPACA_SIDES,
            allow_empty=True,
            allow_none=True,
        )
        _enum_text(
            self.time_in_force,
            "Alpaca time in force",
            frozenset(ALPACA_DOCUMENTED_EQUITY_TIME_IN_FORCE),
        )
        if type(self.status) is not AlpacaOrderStatus:
            raise AlpacaPaperObservationError("Alpaca order status is unsupported")
        if type(self.extended_hours) is not bool:
            raise AlpacaPaperObservationError("Alpaca extended_hours must be an exact boolean")
        if self.legs_sha256 is not None:
            _require_sha256(self.legs_sha256, "Alpaca legs digest")
        if self.position_intent is not None:
            _enum_text(
                self.position_intent,
                "Alpaca position intent",
                _ALPACA_POSITION_INTENTS,
            )
        _require_optional_text(
            self.source,
            "Alpaca source",
            maximum_length=128,
            allow_empty=True,
        )
        _require_optional_text(
            self.subtag,
            "Alpaca subtag",
            maximum_length=256,
            allow_empty=True,
        )
        if self.status is AlpacaOrderStatus.PARTIALLY_FILLED and (
            self.filled_quantity <= 0
            or (self.quantity is not None and self.filled_quantity >= self.quantity)
        ):
            raise AlpacaPaperObservationError(
                "partially-filled status conflicts with cumulative quantity"
            )
        if self.status is AlpacaOrderStatus.FILLED and (
            self.filled_quantity <= 0
            or (self.quantity is not None and self.filled_quantity != self.quantity)
            or self.filled_at is None
        ):
            raise AlpacaPaperObservationError("filled status conflicts with quantity or filled_at")

    @property
    def disposition(self) -> AlpacaOrderDisposition:
        return classify_alpaca_order_status(self.status.value)

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                (
                    ALPACA_PAPER_OBSERVATION_CONTRACT_VERSION,
                    "order_observation",
                    self.provider_order_id,
                    self.client_order_id,
                    self.created_at.semantic_sha256,
                    None if self.updated_at is None else self.updated_at.semantic_sha256,
                    None if self.submitted_at is None else self.submitted_at.semantic_sha256,
                    None if self.filled_at is None else self.filled_at.semantic_sha256,
                    None if self.expired_at is None else self.expired_at.semantic_sha256,
                    None if self.expires_at is None else self.expires_at.semantic_sha256,
                    None if self.canceled_at is None else self.canceled_at.semantic_sha256,
                    None if self.failed_at is None else self.failed_at.semantic_sha256,
                    None if self.replaced_at is None else self.replaced_at.semantic_sha256,
                    self.replaced_by,
                    self.replaces,
                    self.asset_id,
                    self.symbol,
                    self.asset_class,
                    self.notional,
                    self.quantity,
                    self.filled_quantity,
                    self.filled_average_price,
                    self.order_class,
                    self.order_type,
                    self.type,
                    self.side,
                    self.time_in_force,
                    self.limit_price,
                    self.stop_price,
                    self.status,
                    self.disposition,
                    self.extended_hours,
                    self.legs_sha256,
                    self.trail_percent,
                    self.trail_price,
                    self.high_water_mark,
                    self.position_intent,
                    self.ratio_quantity,
                    self.source,
                    self.subtag,
                )
            )
        ).hexdigest()

    @property
    def trading_effect_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False


def _order_observation(value: Mapping[str, Any]) -> AlpacaOrderObservation:
    _require_order_response_keys(value)
    raw_status = _require_text(value["status"], "Alpaca status", maximum_length=64)
    try:
        status = AlpacaOrderStatus(raw_status)
    except ValueError as error:
        raise AlpacaPaperObservationError(
            f"unsupported Alpaca order status: {raw_status!r}"
        ) from error
    classify_alpaca_order_status(raw_status)
    legs = value["legs"]
    if legs is not None and type(legs) is not list:
        raise AlpacaPaperObservationError("Alpaca legs must be an array or null")
    if isinstance(legs, list) and (not legs or len(legs) > 8):
        raise AlpacaPaperObservationError("Alpaca legs must be a bounded non-empty array")

    symbol = _require_optional_text(
        value["symbol"],
        "Alpaca symbol",
        maximum_length=32,
        allow_empty=True,
    )
    asset_class = _require_optional_text(
        value["asset_class"],
        "Alpaca asset class",
        maximum_length=64,
        allow_empty=True,
    )
    order_class = cast(
        str,
        _enum_text(
            value["order_class"],
            "Alpaca order class",
            _ALPACA_OBSERVED_ORDER_CLASSES,
            allow_empty=True,
        ),
    )
    order_type = _enum_text(
        value.get("order_type"),
        "Alpaca deprecated order type",
        frozenset(ALPACA_DOCUMENTED_EQUITY_ORDER_TYPES),
        allow_empty=True,
        allow_none=True,
    )
    order_kind = _enum_text(
        value["type"],
        "Alpaca order type",
        frozenset(ALPACA_DOCUMENTED_EQUITY_ORDER_TYPES),
        allow_empty=True,
        allow_none=True,
    )
    side = _enum_text(
        value["side"],
        "Alpaca order side",
        _ALPACA_SIDES,
        allow_empty=True,
        allow_none=True,
    )
    time_in_force = cast(
        str,
        _enum_text(
            value["time_in_force"],
            "Alpaca time in force",
            frozenset(ALPACA_DOCUMENTED_EQUITY_TIME_IN_FORCE),
        ),
    )
    position_intent = _enum_text(
        value.get("position_intent"),
        "Alpaca position intent",
        _ALPACA_POSITION_INTENTS,
        allow_none=True,
    )
    extended_hours = value["extended_hours"]
    if type(extended_hours) is not bool:
        raise AlpacaPaperObservationError("Alpaca extended_hours must be an exact boolean")

    return AlpacaOrderObservation(
        provider_order_id=_require_uuid(value["id"], "Alpaca provider order ID"),
        client_order_id=_require_text(
            value["client_order_id"],
            "Alpaca client order ID",
            maximum_length=128,
        ),
        created_at=_require_timestamp(value["created_at"], "Alpaca created_at"),
        updated_at=_require_optional_timestamp(value["updated_at"], "Alpaca updated_at"),
        submitted_at=_require_optional_timestamp(value["submitted_at"], "Alpaca submitted_at"),
        filled_at=_require_optional_timestamp(value["filled_at"], "Alpaca filled_at"),
        expired_at=_require_optional_timestamp(value["expired_at"], "Alpaca expired_at"),
        expires_at=_require_optional_timestamp(value.get("expires_at"), "Alpaca expires_at"),
        canceled_at=_require_optional_timestamp(value["canceled_at"], "Alpaca canceled_at"),
        failed_at=_require_optional_timestamp(value["failed_at"], "Alpaca failed_at"),
        replaced_at=_require_optional_timestamp(value["replaced_at"], "Alpaca replaced_at"),
        replaced_by=_require_optional_uuid(value["replaced_by"], "Alpaca replaced_by"),
        replaces=_require_optional_uuid(value["replaces"], "Alpaca replaces"),
        asset_id=_require_optional_or_empty_uuid(value["asset_id"], "Alpaca asset ID"),
        symbol=symbol,
        asset_class=asset_class,
        notional=_require_optional_decimal_text(
            value["notional"],
            "Alpaca notional",
            allow_zero=False,
        ),
        quantity=_require_optional_decimal_text(
            value["qty"],
            "Alpaca quantity",
            allow_zero=False,
        ),
        filled_quantity=_require_decimal_text(
            value["filled_qty"],
            "Alpaca filled quantity",
            allow_zero=True,
        ),
        filled_average_price=_require_optional_decimal_text(
            value["filled_avg_price"],
            "Alpaca filled average price",
            allow_zero=True,
        ),
        order_class=order_class,
        order_type=order_type,
        type=order_kind,
        side=side,
        time_in_force=time_in_force,
        limit_price=_require_optional_decimal_text(
            value["limit_price"],
            "Alpaca limit price",
            allow_zero=False,
        ),
        stop_price=_require_optional_decimal_text(
            value["stop_price"],
            "Alpaca stop price",
            allow_zero=False,
        ),
        status=status,
        extended_hours=extended_hours,
        legs_sha256=None if legs is None else _plain_json_sha256(legs),
        trail_percent=_require_optional_decimal_text(
            value["trail_percent"],
            "Alpaca trail percent",
            allow_zero=False,
        ),
        trail_price=_require_optional_decimal_text(
            value["trail_price"],
            "Alpaca trail price",
            allow_zero=False,
        ),
        high_water_mark=_require_optional_decimal_text(
            value["hwm"],
            "Alpaca high water mark",
            allow_zero=False,
        ),
        position_intent=position_intent,
        ratio_quantity=_require_optional_decimal_text(
            value.get("ratio_qty"),
            "Alpaca ratio quantity",
            allow_zero=False,
        ),
        source=_require_optional_text(
            value.get("source"),
            "Alpaca source",
            maximum_length=128,
            allow_empty=True,
        ),
        subtag=_require_optional_text(
            value.get("subtag"),
            "Alpaca subtag",
            maximum_length=256,
            allow_empty=True,
        ),
    )


@dataclass(frozen=True, slots=True)
class AlpacaClientOrderLookupDescription:
    """An exact non-I/O lookup bound to one prior submission description."""

    account_id: str
    submission: AlpacaPaperSubmissionDescription

    def __post_init__(self) -> None:
        _require_text(self.account_id, "lookup account ID", maximum_length=64)
        if type(self.submission) is not AlpacaPaperSubmissionDescription:
            raise AlpacaPaperObservationError(
                "lookup requires an exact AlpacaPaperSubmissionDescription"
            )
        self.submission.__post_init__()
        if self.submission.capability_sha256 != ALPACA_PAPER_CAPABILITIES.semantic_sha256:
            raise AlpacaPaperObservationError("lookup capability digest drifted")

    @property
    def method(self) -> str:
        return "GET"

    @property
    def base_url(self) -> str:
        return ALPACA_PAPER_TRADING_BASE_URL

    @property
    def path(self) -> str:
        return ALPACA_ORDER_BY_CLIENT_ID_PATH

    @property
    def query(self) -> Mapping[str, str]:
        return MappingProxyType({"client_order_id": self.submission.request.client_order_id})

    @property
    def request_target(self) -> str:
        return f"{self.path}?client_order_id={self.submission.request.client_order_id}"

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                (
                    ALPACA_PAPER_OBSERVATION_CONTRACT_VERSION,
                    ALPACA_PAPER_CAPABILITY_CONTRACT_VERSION,
                    "client_order_lookup",
                    ALPACA_PAPER_CAPABILITIES.semantic_sha256,
                    self.account_id,
                    self.submission.semantic_sha256,
                    self.submission.request.semantic_sha256,
                    self.method,
                    self.base_url,
                    self.path,
                    tuple(sorted(self.query.items())),
                )
            )
        ).hexdigest()

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def create_alpaca_client_order_lookup_description(
    *,
    account_id: str,
    submission: AlpacaPaperSubmissionDescription,
) -> AlpacaClientOrderLookupDescription:
    """Describe recovery lookup I/O without acquiring transport authority."""

    return AlpacaClientOrderLookupDescription(
        account_id=account_id,
        submission=submission,
    )


def _mismatch_fields(
    description: AlpacaClientOrderLookupDescription,
    order: AlpacaOrderObservation,
) -> tuple[str, ...]:
    expected = description.submission.body
    mismatches: list[str] = []
    checks = (
        ("asset_class", order.asset_class == "us_equity"),
        ("symbol", order.symbol == expected["symbol"]),
        ("quantity", order.quantity == Decimal(cast(str, expected["qty"]))),
        ("notional", order.notional is None),
        ("side", order.side == expected["side"]),
        ("order_type", order.order_type in (None, "", expected["type"])),
        ("type", order.type == expected["type"]),
        ("time_in_force", order.time_in_force == expected["time_in_force"]),
        ("order_class", order.order_class in ("", "simple")),
        ("extended_hours", order.extended_hours is expected["extended_hours"]),
        ("limit_price", order.limit_price is None),
        ("stop_price", order.stop_price is None),
        ("trail_percent", order.trail_percent is None),
        ("trail_price", order.trail_price is None),
        ("high_water_mark", order.high_water_mark is None),
        ("legs", order.legs_sha256 is None),
        ("position_intent", order.position_intent is None),
        ("ratio_quantity", order.ratio_quantity is None),
        (
            "replacement_chain",
            order.replaced_at is None and order.replaced_by is None and order.replaces is None,
        ),
    )
    for field_name, matched in checks:
        if not matched:
            mismatches.append(field_name)
    return tuple(mismatches)


def _not_found_details(value: Mapping[str, Any]) -> tuple[int, str]:
    _require_exact_keys(value, _ALPACA_NOT_FOUND_KEYS, "Alpaca not-found response")
    code = value["code"]
    if type(code) is not int or not 1 <= code <= _ALPACA_PAPER_MAX_ERROR_CODE:
        raise AlpacaPaperObservationError(
            "Alpaca not-found response code must be a bounded positive integer"
        )
    message = _require_text(
        value["message"],
        "Alpaca not-found message",
        maximum_length=512,
    )
    return code, message


@dataclass(frozen=True, slots=True)
class AlpacaClientOrderLookupObservation:
    """Exact retained lookup bytes plus a conservative, non-authorizing meaning."""

    description: AlpacaClientOrderLookupDescription
    outcome: AlpacaClientOrderLookupOutcome
    http_status: int
    provider_request_id: str
    received_at: datetime
    response_body: bytes = field(repr=False)
    order: AlpacaOrderObservation | None = None
    mismatch_fields: tuple[str, ...] = ()
    not_found_code: int | None = None
    not_found_message: str | None = None

    def __post_init__(self) -> None:
        if type(self.description) is not AlpacaClientOrderLookupDescription:
            raise AlpacaPaperObservationError(
                "lookup observation requires an exact lookup description"
            )
        self.description.__post_init__()
        if type(self.outcome) is not AlpacaClientOrderLookupOutcome:
            raise AlpacaPaperObservationError("lookup observation outcome is unsupported")
        if type(self.http_status) is not int or self.http_status not in (200, 404):
            raise AlpacaPaperObservationError("lookup observation supports only HTTP 200 or 404")
        _require_text(
            self.provider_request_id,
            "Alpaca X-Request-ID",
            maximum_length=256,
        )
        if type(self.received_at) is not datetime:
            raise AlpacaPaperObservationError("lookup received_at must be an exact datetime")
        try:
            require_utc(self.received_at, "lookup received_at")
        except ValueError as error:
            raise AlpacaPaperObservationError(str(error)) from error
        if self.order is not None and type(self.order) is not AlpacaOrderObservation:
            raise AlpacaPaperObservationError(
                "lookup observation order must be an exact AlpacaOrderObservation or null"
            )
        if self.order is not None:
            self.order.__post_init__()
        if (
            type(self.mismatch_fields) is not tuple
            or any(type(field_name) is not str for field_name in self.mismatch_fields)
            or len(frozenset(self.mismatch_fields)) != len(self.mismatch_fields)
            or not frozenset(self.mismatch_fields) <= _ALPACA_MISMATCH_FIELD_NAMES
        ):
            raise AlpacaPaperObservationError(
                "lookup mismatch fields must be a unique closed tuple"
            )
        if self.not_found_code is not None and type(self.not_found_code) is not int:
            raise AlpacaPaperObservationError(
                "lookup not-found code must be an exact integer or null"
            )
        if self.not_found_message is not None:
            _require_text(
                self.not_found_message,
                "lookup not-found message",
                maximum_length=512,
            )
        decoded = _decode_response_object(self.response_body)

        if self.http_status == 404:
            code, message = _not_found_details(decoded)
            if (
                self.outcome is not AlpacaClientOrderLookupOutcome.NOT_VISIBLE_INCONCLUSIVE
                or self.order is not None
                or self.mismatch_fields
                or self.not_found_code != code
                or self.not_found_message != message
            ):
                raise AlpacaPaperObservationError(
                    "HTTP 404 must remain an exact inconclusive not-visible observation"
                )
            return

        expected_order = _order_observation(decoded)
        expected_client_order_id = self.description.submission.request.client_order_id
        if expected_order.client_order_id != expected_client_order_id:
            raise AlpacaPaperObservationError(
                "Alpaca lookup returned a different client_order_id than requested"
            )
        expected_mismatches = _mismatch_fields(self.description, expected_order)
        expected_outcome = (
            AlpacaClientOrderLookupOutcome.FOUND_MATCHED
            if not expected_mismatches
            else AlpacaClientOrderLookupOutcome.FOUND_MISMATCH
        )
        if (
            self.outcome is not expected_outcome
            or self.order != expected_order
            or self.mismatch_fields != expected_mismatches
            or self.not_found_code is not None
            or self.not_found_message is not None
        ):
            raise AlpacaPaperObservationError(
                "HTTP 200 lookup observation does not match its exact response bytes"
            )

    @property
    def response_sha256(self) -> str:
        return hashlib.sha256(self.response_body).hexdigest()

    @property
    def response_size_bytes(self) -> int:
        return len(self.response_body)

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                (
                    ALPACA_PAPER_OBSERVATION_CONTRACT_VERSION,
                    "client_order_lookup_observation",
                    self.description.semantic_sha256,
                    self.outcome,
                    self.http_status,
                    self.provider_request_id,
                    self.received_at,
                    self.response_size_bytes,
                    self.response_sha256,
                    None if self.order is None else self.order.semantic_sha256,
                    self.mismatch_fields,
                    self.not_found_code,
                    self.not_found_message,
                )
            )
        ).hexdigest()

    @property
    def inconclusive(self) -> bool:
        return self.outcome is AlpacaClientOrderLookupOutcome.NOT_VISIBLE_INCONCLUSIVE

    @property
    def additional_reconciliation_required(self) -> bool:
        return True

    @property
    def unknown_submission_resolution_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def decode_alpaca_client_order_lookup_response(
    description: AlpacaClientOrderLookupDescription,
    *,
    http_status: int,
    provider_request_id: str,
    response_body: bytes,
    received_at: datetime,
) -> AlpacaClientOrderLookupObservation:
    """Decode retained lookup bytes without resolving or mutating local state."""

    if type(description) is not AlpacaClientOrderLookupDescription:
        raise AlpacaPaperObservationError("lookup decoding requires an exact lookup description")
    decoded = _decode_response_object(response_body)
    if type(http_status) is not int:
        raise AlpacaPaperObservationError("lookup HTTP status must be an exact integer")
    if http_status == 404:
        code, message = _not_found_details(decoded)
        return AlpacaClientOrderLookupObservation(
            description=description,
            outcome=AlpacaClientOrderLookupOutcome.NOT_VISIBLE_INCONCLUSIVE,
            http_status=http_status,
            provider_request_id=provider_request_id,
            received_at=received_at,
            response_body=response_body,
            not_found_code=code,
            not_found_message=message,
        )
    if http_status != 200:
        raise AlpacaPaperObservationError(
            "lookup decoding supports only successful or not-visible responses"
        )
    order = _order_observation(decoded)
    expected_client_order_id = description.submission.request.client_order_id
    if order.client_order_id != expected_client_order_id:
        raise AlpacaPaperObservationError(
            "Alpaca lookup returned a different client_order_id than requested"
        )
    mismatches = _mismatch_fields(description, order)
    outcome = (
        AlpacaClientOrderLookupOutcome.FOUND_MATCHED
        if not mismatches
        else AlpacaClientOrderLookupOutcome.FOUND_MISMATCH
    )
    return AlpacaClientOrderLookupObservation(
        description=description,
        outcome=outcome,
        http_status=http_status,
        provider_request_id=provider_request_id,
        received_at=received_at,
        response_body=response_body,
        order=order,
        mismatch_fields=mismatches,
    )


__all__ = [
    "ALPACA_PAPER_MAX_LOOKUP_RESPONSE_BYTES",
    "ALPACA_PAPER_OBSERVATION_CONTRACT_VERSION",
    "AlpacaClientOrderLookupDescription",
    "AlpacaClientOrderLookupObservation",
    "AlpacaClientOrderLookupOutcome",
    "AlpacaOrderObservation",
    "AlpacaPaperObservationError",
    "AlpacaProviderTimestamp",
    "create_alpaca_client_order_lookup_description",
    "decode_alpaca_client_order_lookup_response",
]
