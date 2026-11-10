"""Bounded, raw-first Alpaca paper account-activity pages.

The Trading API account-activities endpoint is an ascending, cursor-paginated
historical view without snapshot isolation.  This module freezes one strict
legacy ``TradeActivity`` FILL profile, retains every page before decoding, and
validates one bounded page chain.  Provider activity IDs remain opaque cursor
text; neither they nor any other field are promoted to canonical execution,
revision, deduplication, lifecycle, or reconciliation authority.
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
from itertools import pairwise
from types import MappingProxyType
from typing import Any, cast
from uuid import UUID

from packages.adapters.broker.alpaca_paper import (
    ALPACA_ACCOUNT_ACTIVITIES_PATH,
    ALPACA_ACTIVITIES_DEFAULT_PAGE_SIZE,
    ALPACA_ACTIVITIES_MAX_PAGE_SIZE,
    ALPACA_ACTIVITIES_MIN_PAGE_SIZE,
    ALPACA_PAPER_ADAPTER_ID,
    ALPACA_PAPER_ADAPTER_VERSION,
    ALPACA_PAPER_CAPABILITIES,
    ALPACA_PAPER_TRADING_BASE_URL,
    AlpacaPaperContractError,
)
from packages.adapters.broker.alpaca_paper_budget import (
    AlpacaPaperBudgetOperation,
    create_alpaca_paper_request_demand,
)
from packages.domain.broker_ingress import (
    MAX_BROKER_INGRESS_BODY_BYTES,
    BrokerIngressDelivery,
    BrokerIngressError,
    BrokerIngressReceipt,
    BrokerIngressRecorder,
)
from packages.domain.broker_request_budget import (
    BrokerRequestDemand,
    BrokerRequestPurpose,
)
from packages.domain.canonical import canonical_decimal, canonical_json_bytes
from packages.domain.identifiers import canonical_id
from packages.domain.models import require_utc

ALPACA_PAPER_ACCOUNT_ACTIVITY_CONTRACT_VERSION = "phase4ad-bounded-raw-first-account-activity-v1"
ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_PAGES = 8
ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_ITEMS = (
    ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_PAGES * ALPACA_ACTIVITIES_MAX_PAGE_SIZE
)
ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_RESPONSE_BYTES = MAX_BROKER_INGRESS_BODY_BYTES
ALPACA_PAPER_ACCOUNT_ACTIVITY_INGRESS_CHANNEL = "rest_account_activity_response"
ALPACA_PAPER_ACCOUNT_ACTIVITY_INGRESS_OPERATION = "get_account_activities_page"

_TRADE_ACTIVITY_KEYS = frozenset(
    {
        "activity_type",
        "cum_qty",
        "id",
        "leaves_qty",
        "order_id",
        "price",
        "qty",
        "side",
        "symbol",
        "transaction_time",
        "type",
    }
)
_DECIMAL_TEXT = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,18})?")
_PROVIDER_ACTIVITY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
_SAFE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SYMBOL = re.compile(r"[A-Z][A-Z0-9./-]{0,31}")
_TIMESTAMP = re.compile(
    r"(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})"
    r"T(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?"
    r"(?P<zone>Z|[+-][0-9]{2}:[0-9]{2})"
)


class AlpacaPaperAccountActivityError(AlpacaPaperContractError):
    """An account-activity page or chain violates the frozen contract."""


class AlpacaPaperTradeActivitySide(StrEnum):
    """Closed legacy TradeActivity side values."""

    BUY = "buy"
    SELL = "sell"


class AlpacaPaperTradeActivityType(StrEnum):
    """Closed legacy FILL activity subtypes."""

    FILL = "fill"
    PARTIAL_FILL = "partial_fill"


class _NoAccountActivityAuthority:
    __slots__ = ()

    @property
    def request_budget_enforced(self) -> bool:
        return False

    @property
    def authenticated_provider_evidence(self) -> bool:
        return False

    @property
    def runtime_current(self) -> bool:
        return False

    @property
    def snapshot_isolation_qualified(self) -> bool:
        return False

    @property
    def provider_snapshot_complete(self) -> bool:
        return False

    @property
    def snapshot_complete(self) -> bool:
        return False

    @property
    def activity_history_complete(self) -> bool:
        return False

    @property
    def converged(self) -> bool:
        return False

    @property
    def provider_execution_identity_qualified(self) -> bool:
        return False

    @property
    def canonical_execution_identity_qualified(self) -> bool:
        return False

    @property
    def provider_revision_identity_qualified(self) -> bool:
        return False

    @property
    def execution_revision_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_identity_qualified(self) -> bool:
        return False

    @property
    def provider_bust_identity_qualified(self) -> bool:
        return False

    @property
    def provider_correction_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_revision_authorized(self) -> bool:
        return False

    @property
    def canonical_account_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_ledger_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_cash_fact_authorized(self) -> bool:
        return False

    @property
    def execution_application_authorized(self) -> bool:
        return False

    @property
    def bust_application_authorized(self) -> bool:
        return False

    @property
    def correction_application_authorized(self) -> bool:
        return False

    @property
    def manual_activity_application_authorized(self) -> bool:
        return False

    @property
    def normalized_fact_authorized(self) -> bool:
        return False

    @property
    def inbox_application_authorized(self) -> bool:
        return False

    @property
    def lifecycle_application_authorized(self) -> bool:
        return False

    @property
    def reconciliation_application_authorized(self) -> bool:
        return False

    @property
    def reconciliation_completion_authorized(self) -> bool:
        return False

    @property
    def reconciliation_complete(self) -> bool:
        return False

    @property
    def unknown_resolution_authorized(self) -> bool:
        return False

    @property
    def reservation_release_authorized(self) -> bool:
        return False

    @property
    def resubmission_authorized(self) -> bool:
        return False

    @property
    def readiness_transition_authorized(self) -> bool:
        return False

    @property
    def activity_snapshot_pagination_ready(self) -> bool:
        return False

    @property
    def decode_quarantine_ready(self) -> bool:
        return False

    @property
    def reconciliation_ready(self) -> bool:
        return False

    @property
    def dispatch_preflight_ready(self) -> bool:
        return False

    @property
    def paper_startup_ready(self) -> bool:
        return False

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def broker_call_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: object, field_name: str, *, maximum: int) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise AlpacaPaperAccountActivityError(
            f"{field_name} must be bounded, trimmed text without control characters"
        )
    return value


def _require_safe_key(value: object, field_name: str) -> str:
    if type(value) is not str or _SAFE_KEY.fullmatch(value) is None:
        raise AlpacaPaperAccountActivityError(
            f"{field_name} must contain 8-128 safe visible characters"
        )
    return value


def _require_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AlpacaPaperAccountActivityError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_provider_activity_id(value: object, field_name: str) -> str:
    if type(value) is not str or _PROVIDER_ACTIVITY_ID.fullmatch(value) is None:
        raise AlpacaPaperAccountActivityError(
            f"{field_name} must be exact bounded provider cursor text"
        )
    return value


def _require_uuid(value: object, field_name: str) -> str:
    raw = _require_text(value, field_name, maximum=36)
    try:
        parsed = UUID(raw)
    except ValueError as error:
        raise AlpacaPaperAccountActivityError(f"{field_name} must be a canonical UUID") from error
    if str(parsed) != raw:
        raise AlpacaPaperAccountActivityError(f"{field_name} must be a canonical lowercase UUID")
    return raw


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperAccountActivityError(f"{field_name} must be an exact datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperAccountActivityError(str(error)) from error
    return value


def _decimal_parts(value: object, field_name: str) -> tuple[str, Decimal]:
    raw = _require_text(value, field_name, maximum=64)
    if _DECIMAL_TEXT.fullmatch(raw) is None:
        raise AlpacaPaperAccountActivityError(
            f"{field_name} must be a bounded non-negative plain decimal string"
        )
    integer, separator, fraction = raw.partition(".")
    if len(integer) > 18 or (separator and len(fraction) > 18):
        raise AlpacaPaperAccountActivityError(f"{field_name} exceeds the reviewed decimal bounds")
    try:
        parsed = canonical_decimal(Decimal(raw))
    except (InvalidOperation, ValueError) as error:
        raise AlpacaPaperAccountActivityError(f"{field_name} must be a finite decimal") from error
    return raw, parsed


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAccountActivityDecimal:
    """A proof-constructed Decimal paired with its exact provider lexeme."""

    raw: str
    value: Decimal

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperAccountActivityDecimal must be proof-constructed")

    def _validate(self) -> None:
        raw, parsed = _decimal_parts(
            self.raw,
            "Alpaca account activity decimal",
        )
        if raw != self.raw or type(self.value) is not Decimal or self.value != parsed:
            raise AlpacaPaperAccountActivityError(
                "Alpaca account activity decimal conflicts with its provider lexeme"
            )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(
            (
                ALPACA_PAPER_ACCOUNT_ACTIVITY_CONTRACT_VERSION,
                "activity_decimal",
                self.raw,
                self.value,
            )
        )


def _activity_decimal(
    value: object,
    field_name: str,
    *,
    positive: bool,
) -> AlpacaPaperAccountActivityDecimal:
    raw, parsed = _decimal_parts(value, field_name)
    if positive and parsed <= 0:
        raise AlpacaPaperAccountActivityError(f"{field_name} must be positive")
    result = object.__new__(AlpacaPaperAccountActivityDecimal)
    object.__setattr__(result, "raw", raw)
    object.__setattr__(result, "value", parsed)
    result._validate()
    return result


def _require_activity_decimal(
    value: object,
    field_name: str,
    *,
    positive: bool,
) -> AlpacaPaperAccountActivityDecimal:
    if type(value) is not AlpacaPaperAccountActivityDecimal:
        raise AlpacaPaperAccountActivityError(
            f"{field_name} must be an exact proof-constructed activity decimal"
        )
    value._validate()
    if positive and value.value <= 0:
        raise AlpacaPaperAccountActivityError(f"{field_name} must be positive")
    return value


def _timestamp_parts(
    value: object,
    field_name: str,
) -> tuple[str, datetime, int]:
    raw = _require_text(value, field_name, maximum=40)
    matched = _TIMESTAMP.fullmatch(raw)
    if matched is None:
        raise AlpacaPaperAccountActivityError(
            f"{field_name} must be exact ISO-8601 with at most 9 fractional digits"
        )
    zone = matched.group("zone")
    if zone == "-00:00":
        raise AlpacaPaperAccountActivityError(
            f"{field_name} cannot use the RFC 3339 unknown-offset marker"
        )
    base_text = f"{matched.group('date')}T{matched.group('time')}"
    base_text += "+00:00" if zone == "Z" else zone
    try:
        parsed = datetime.fromisoformat(base_text)
    except ValueError as error:
        raise AlpacaPaperAccountActivityError(f"{field_name} is not a valid instant") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AlpacaPaperAccountActivityError(f"{field_name} must include an offset")
    fraction = matched.group("fraction") or ""
    nanosecond = int(fraction.ljust(9, "0")) if fraction else 0
    return raw, parsed.astimezone(UTC), nanosecond


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAccountActivityTimestamp:
    """An exact provider time lexeme with nanosecond-preserving UTC identity."""

    raw: str
    utc_second: datetime = field(repr=False)
    nanosecond: int

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperAccountActivityTimestamp must be proof-constructed")

    def _validate(self) -> None:
        raw, utc_second, nanosecond = _timestamp_parts(
            self.raw,
            "Alpaca account activity transaction_time",
        )
        if (
            raw != self.raw
            or type(self.utc_second) is not datetime
            or self.utc_second != utc_second
            or type(self.nanosecond) is not int
            or self.nanosecond != nanosecond
        ):
            raise AlpacaPaperAccountActivityError(
                "Alpaca account activity timestamp conflicts with its provider lexeme"
            )

    @property
    def normalized_utc(self) -> str:
        self._validate()
        base = self.utc_second.isoformat(timespec="seconds").replace("+00:00", "Z")
        if self.nanosecond == 0:
            return base
        fraction = f"{self.nanosecond:09d}".rstrip("0")
        return f"{base[:-1]}.{fraction}Z"

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(
            (
                ALPACA_PAPER_ACCOUNT_ACTIVITY_CONTRACT_VERSION,
                "activity_timestamp",
                self.raw,
                self.normalized_utc,
                self.nanosecond,
            )
        )


def _activity_timestamp(
    value: object,
    field_name: str,
) -> AlpacaPaperAccountActivityTimestamp:
    raw, utc_second, nanosecond = _timestamp_parts(value, field_name)
    result = object.__new__(AlpacaPaperAccountActivityTimestamp)
    object.__setattr__(result, "raw", raw)
    object.__setattr__(result, "utc_second", utc_second)
    object.__setattr__(result, "nanosecond", nanosecond)
    result._validate()
    return result


def _require_activity_timestamp(
    value: object,
    field_name: str,
) -> AlpacaPaperAccountActivityTimestamp:
    if type(value) is not AlpacaPaperAccountActivityTimestamp:
        raise AlpacaPaperAccountActivityError(
            f"{field_name} must be an exact proof-constructed activity timestamp"
        )
    value._validate()
    return value


def _enum_value[T: StrEnum](
    value: object,
    field_name: str,
    enum_type: type[T],
) -> T:
    raw = _require_text(value, field_name, maximum=32)
    try:
        return enum_type(raw)
    except ValueError as error:
        raise AlpacaPaperAccountActivityError(
            f"{field_name} has unsupported value {raw!r}"
        ) from error


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperTradeActivity(_NoAccountActivityAuthority):
    """One strict legacy TradeActivity FILL object with no canonical meaning."""

    activity_type: str
    cumulative_quantity: AlpacaPaperAccountActivityDecimal
    provider_activity_id: str
    leaves_quantity: AlpacaPaperAccountActivityDecimal
    price: AlpacaPaperAccountActivityDecimal
    quantity: AlpacaPaperAccountActivityDecimal
    side: AlpacaPaperTradeActivitySide
    symbol: str
    transaction_time: AlpacaPaperAccountActivityTimestamp
    provider_order_id: str
    trade_type: AlpacaPaperTradeActivityType

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperTradeActivity must be proof-constructed")

    def _validate(self) -> None:
        activity_type = _require_text(
            self.activity_type,
            "Alpaca account activity activity_type",
            maximum=16,
        )
        if activity_type != "FILL":
            raise AlpacaPaperAccountActivityError(
                "Alpaca account activity must be the requested FILL type"
            )
        cumulative = _require_activity_decimal(
            self.cumulative_quantity,
            "Alpaca account activity cum_qty",
            positive=True,
        )
        _require_provider_activity_id(
            self.provider_activity_id,
            "Alpaca account activity ID",
        )
        leaves = _require_activity_decimal(
            self.leaves_quantity,
            "Alpaca account activity leaves_qty",
            positive=False,
        )
        price = _require_activity_decimal(
            self.price,
            "Alpaca account activity price",
            positive=True,
        )
        quantity = _require_activity_decimal(
            self.quantity,
            "Alpaca account activity qty",
            positive=True,
        )
        if type(self.side) is not AlpacaPaperTradeActivitySide:
            raise AlpacaPaperAccountActivityError(
                "Alpaca account activity side is outside the reviewed profile"
            )
        symbol = _require_text(
            self.symbol,
            "Alpaca account activity symbol",
            maximum=32,
        )
        if _SYMBOL.fullmatch(symbol) is None:
            raise AlpacaPaperAccountActivityError(
                "Alpaca account activity symbol is outside the reviewed profile"
            )
        _require_activity_timestamp(
            self.transaction_time,
            "Alpaca account activity transaction_time",
        )
        _require_uuid(
            self.provider_order_id,
            "Alpaca account activity order_id",
        )
        if type(self.trade_type) is not AlpacaPaperTradeActivityType:
            raise AlpacaPaperAccountActivityError(
                "Alpaca account activity type is outside the reviewed FILL profile"
            )
        if cumulative.value < quantity.value:
            raise AlpacaPaperAccountActivityError(
                "Alpaca account activity cum_qty cannot be below qty"
            )
        if leaves.value < 0:
            raise AlpacaPaperAccountActivityError(
                "Alpaca account activity leaves_qty cannot be negative"
            )
        if price.value <= 0:
            raise AlpacaPaperAccountActivityError("Alpaca account activity price must be positive")

    @property
    def id(self) -> str:
        return self.provider_activity_id

    @property
    def cum_qty(self) -> AlpacaPaperAccountActivityDecimal:
        return self.cumulative_quantity

    @property
    def leaves_qty(self) -> AlpacaPaperAccountActivityDecimal:
        return self.leaves_quantity

    @property
    def qty(self) -> AlpacaPaperAccountActivityDecimal:
        return self.quantity

    @property
    def order_id(self) -> str:
        return self.provider_order_id

    @property
    def type(self) -> AlpacaPaperTradeActivityType:
        return self.trade_type

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(
            (
                ALPACA_PAPER_ACCOUNT_ACTIVITY_CONTRACT_VERSION,
                "trade_activity",
                self.activity_type,
                self.cumulative_quantity.semantic_sha256,
                self.provider_activity_id,
                self.leaves_quantity.semantic_sha256,
                self.price.semantic_sha256,
                self.quantity.semantic_sha256,
                self.side,
                self.symbol,
                self.transaction_time.semantic_sha256,
                self.provider_order_id,
                self.trade_type,
                self.provider_execution_identity_qualified,
                self.provider_revision_identity_qualified,
                self.provider_deduplication_identity_qualified,
                self.canonical_execution_fact_authorized,
            )
        )


def _trade_activity(value: dict[str, Any]) -> AlpacaPaperTradeActivity:
    actual = frozenset(value)
    missing = tuple(sorted(_TRADE_ACTIVITY_KEYS - actual))
    extra = tuple(sorted(actual - _TRADE_ACTIVITY_KEYS))
    if missing or extra:
        raise AlpacaPaperAccountActivityError(
            "Alpaca account activity is outside the strict legacy TradeActivity "
            f"FILL schema; missing={missing!r}, extra={extra!r}"
        )
    activity_type = _require_text(
        value["activity_type"],
        "Alpaca account activity activity_type",
        maximum=16,
    )
    if activity_type != "FILL":
        raise AlpacaPaperAccountActivityError(
            "Alpaca account activity conflicts with activity_types=FILL"
        )
    result = object.__new__(AlpacaPaperTradeActivity)
    object.__setattr__(result, "activity_type", activity_type)
    object.__setattr__(
        result,
        "cumulative_quantity",
        _activity_decimal(
            value["cum_qty"],
            "Alpaca account activity cum_qty",
            positive=True,
        ),
    )
    object.__setattr__(
        result,
        "provider_activity_id",
        _require_provider_activity_id(
            value["id"],
            "Alpaca account activity ID",
        ),
    )
    object.__setattr__(
        result,
        "leaves_quantity",
        _activity_decimal(
            value["leaves_qty"],
            "Alpaca account activity leaves_qty",
            positive=False,
        ),
    )
    object.__setattr__(
        result,
        "price",
        _activity_decimal(
            value["price"],
            "Alpaca account activity price",
            positive=True,
        ),
    )
    object.__setattr__(
        result,
        "quantity",
        _activity_decimal(
            value["qty"],
            "Alpaca account activity qty",
            positive=True,
        ),
    )
    object.__setattr__(
        result,
        "side",
        _enum_value(
            value["side"],
            "Alpaca account activity side",
            AlpacaPaperTradeActivitySide,
        ),
    )
    object.__setattr__(
        result,
        "symbol",
        _require_text(
            value["symbol"],
            "Alpaca account activity symbol",
            maximum=32,
        ),
    )
    object.__setattr__(
        result,
        "transaction_time",
        _activity_timestamp(
            value["transaction_time"],
            "Alpaca account activity transaction_time",
        ),
    )
    object.__setattr__(
        result,
        "provider_order_id",
        _require_uuid(
            value["order_id"],
            "Alpaca account activity order_id",
        ),
    )
    object.__setattr__(
        result,
        "trade_type",
        _enum_value(
            value["type"],
            "Alpaca account activity type",
            AlpacaPaperTradeActivityType,
        ),
    )
    result._validate()
    return result


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AlpacaPaperAccountActivityError(
                f"account activity response contains duplicate JSON key {key!r}"
            )
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise AlpacaPaperAccountActivityError(
        f"account activity response contains non-standard JSON constant {value!r}"
    )


def _decode_activity_array(
    response_body: bytes,
) -> tuple[AlpacaPaperTradeActivity, ...]:
    if type(response_body) is not bytes:
        raise AlpacaPaperAccountActivityError("account activity response must be exact bytes")
    if not 1 <= len(response_body) <= ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_RESPONSE_BYTES:
        raise AlpacaPaperAccountActivityError(
            "account activity response size is outside the durable ingress bound"
        )
    try:
        text = response_body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AlpacaPaperAccountActivityError("account activity response must be UTF-8") from error
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except AlpacaPaperAccountActivityError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as error:
        raise AlpacaPaperAccountActivityError(
            "account activity response is invalid JSON"
        ) from error
    if type(decoded) is not list:
        raise AlpacaPaperAccountActivityError("account activity response must be one JSON array")
    result: list[AlpacaPaperTradeActivity] = []
    for position, value in enumerate(decoded):
        if type(value) is not dict:
            raise AlpacaPaperAccountActivityError(
                f"account activity item {position} must be one flat JSON object"
            )
        try:
            result.append(_trade_activity(cast(dict[str, Any], value)))
        except AlpacaPaperAccountActivityError as error:
            raise AlpacaPaperAccountActivityError(
                f"account activity item {position} is outside the frozen FILL profile"
            ) from error
    return tuple(result)


def _activity_instant(
    activity: AlpacaPaperTradeActivity,
) -> tuple[datetime, int]:
    activity._validate()
    return (
        activity.transaction_time.utc_second,
        activity.transaction_time.nanosecond,
    )


@dataclass(frozen=True, slots=True)
class AlpacaPaperAccountActivityPlan(_NoAccountActivityAuthority):
    """One deterministic bounded ascending FILL traversal."""

    account_id: str
    capture_idempotency_key: str
    page_size: int = ALPACA_ACTIVITIES_DEFAULT_PAGE_SIZE
    maximum_pages: int = ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_PAGES
    maximum_items: int = ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_ITEMS

    def __post_init__(self) -> None:
        _require_text(
            self.account_id,
            "account activity account ID",
            maximum=64,
        )
        _require_safe_key(
            self.capture_idempotency_key,
            "account activity capture idempotency key",
        )
        if (
            type(self.page_size) is not int
            or not ALPACA_ACTIVITIES_MIN_PAGE_SIZE
            <= self.page_size
            <= ALPACA_ACTIVITIES_MAX_PAGE_SIZE
        ):
            raise AlpacaPaperAccountActivityError(
                "account activity page_size is outside the reviewed provider bound"
            )
        if (
            type(self.maximum_pages) is not int
            or not 1 <= self.maximum_pages <= ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_PAGES
        ):
            raise AlpacaPaperAccountActivityError(
                "account activity maximum pages is outside the local safety bound"
            )
        if (
            type(self.maximum_items) is not int
            or not 1 <= self.maximum_items <= ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_ITEMS
        ):
            raise AlpacaPaperAccountActivityError(
                "account activity maximum items is outside the local safety bound"
            )
        ALPACA_PAPER_CAPABILITIES.__post_init__()

    @property
    def capture_id(self) -> str:
        self.__post_init__()
        return canonical_id(
            "alpaca-paper-account-activity-capture",
            self.account_id,
            self.capture_idempotency_key,
        )

    @property
    def budget_purpose(self) -> BrokerRequestPurpose:
        return BrokerRequestPurpose.RECONCILIATION

    @property
    def maximum_request_count(self) -> int:
        return self.maximum_pages

    @property
    def activity_types(self) -> str:
        return "FILL"

    @property
    def direction(self) -> str:
        return "asc"

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_ACCOUNT_ACTIVITY_CONTRACT_VERSION,
            "activity_plan",
            self.capture_id,
            self.account_id,
            self.capture_idempotency_key,
            ALPACA_PAPER_CAPABILITIES.semantic_sha256,
            self.page_size,
            self.maximum_pages,
            self.maximum_items,
            self.activity_types,
            self.direction,
            "last_activity_id",
            self.budget_purpose,
            self.snapshot_isolation_qualified,
            self.provider_revision_identity_qualified,
            self.provider_execution_identity_qualified,
        )

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class AlpacaPaperAccountActivityPageDescription(_NoAccountActivityAuthority):
    """One exact request in a predecessor-bound account-activity traversal."""

    plan: AlpacaPaperAccountActivityPlan
    page_number: int
    page_size: int
    page_token: str | None
    previous_page_sha256: str | None

    def __post_init__(self) -> None:
        if type(self.plan) is not AlpacaPaperAccountActivityPlan:
            raise AlpacaPaperAccountActivityError(
                "account activity page requires an exact traversal plan"
            )
        self.plan.__post_init__()
        if (
            type(self.page_number) is not int
            or not 1 <= self.page_number <= self.plan.maximum_pages
        ):
            raise AlpacaPaperAccountActivityError(
                "account activity page number is outside the plan"
            )
        if (
            type(self.page_size) is not int
            or not ALPACA_ACTIVITIES_MIN_PAGE_SIZE <= self.page_size <= self.plan.page_size
            or self.page_size > self.plan.maximum_items
        ):
            raise AlpacaPaperAccountActivityError("account activity page_size is outside the plan")
        if self.page_number == 1:
            if self.page_token is not None or self.previous_page_sha256 is not None:
                raise AlpacaPaperAccountActivityError(
                    "first account activity page cannot name a token or predecessor"
                )
            if self.page_size != min(
                self.plan.page_size,
                self.plan.maximum_items,
            ):
                raise AlpacaPaperAccountActivityError(
                    "first account activity page_size must match the plan bound"
                )
        else:
            _require_provider_activity_id(
                self.page_token,
                "account activity page_token",
            )
            _require_sha256(
                self.previous_page_sha256,
                "account activity previous page digest",
            )

    @property
    def method(self) -> str:
        return "GET"

    @property
    def base_url(self) -> str:
        return ALPACA_PAPER_TRADING_BASE_URL

    @property
    def path(self) -> str:
        return ALPACA_ACCOUNT_ACTIVITIES_PATH

    @property
    def query(self) -> Mapping[str, str]:
        values = {
            "activity_types": "FILL",
            "direction": "asc",
            "page_size": str(self.page_size),
        }
        if self.page_token is not None:
            values["page_token"] = self.page_token
        return MappingProxyType(values)

    @property
    def request_target(self) -> str:
        pairs = [
            ("activity_types", "FILL"),
            ("direction", "asc"),
            ("page_size", str(self.page_size)),
        ]
        if self.page_token is not None:
            pairs.append(("page_token", self.page_token))
        return f"{self.path}?" + "&".join(f"{key}={value}" for key, value in pairs)

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_ACCOUNT_ACTIVITY_CONTRACT_VERSION,
            "activity_page_description",
            self.plan.semantic_sha256,
            self.page_number,
            self.page_size,
            self.page_token,
            self.previous_page_sha256,
            self.method,
            self.base_url,
            self.path,
            tuple(sorted(self.query.items())),
        )

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(self._semantic_material())


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAccountActivityPageObservation(_NoAccountActivityAuthority):
    """One exact retained FILL page decoded without application authority."""

    description: AlpacaPaperAccountActivityPageDescription
    http_status: int
    provider_request_id: str
    received_at: datetime
    response_body: bytes = field(repr=False)
    activities: tuple[AlpacaPaperTradeActivity, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperAccountActivityPageObservation must be proof-constructed")

    def _validate(self) -> None:
        if type(self.description) is not AlpacaPaperAccountActivityPageDescription:
            raise AlpacaPaperAccountActivityError(
                "account activity observation requires an exact page description"
            )
        self.description.__post_init__()
        if type(self.http_status) is not int or self.http_status != 200:
            raise AlpacaPaperAccountActivityError(
                "account activity decoding supports only HTTP 200"
            )
        _require_text(
            self.provider_request_id,
            "account activity X-Request-ID",
            maximum=256,
        )
        _require_utc(self.received_at, "account activity received_at")
        if type(self.activities) is not tuple or any(
            type(activity) is not AlpacaPaperTradeActivity for activity in self.activities
        ):
            raise AlpacaPaperAccountActivityError(
                "account activity observations must be an exact tuple"
            )
        if len(self.activities) > self.description.page_size:
            raise AlpacaPaperAccountActivityError(
                "account activity page exceeds its explicit page_size"
            )
        decoded = _decode_activity_array(self.response_body)
        if decoded != self.activities:
            raise AlpacaPaperAccountActivityError(
                "account activity observations conflict with exact response bytes"
            )
        provider_ids = tuple(activity.provider_activity_id for activity in self.activities)
        if len(set(provider_ids)) != len(provider_ids):
            raise AlpacaPaperAccountActivityError(
                "account activity page repeats a provider activity ID"
            )
        instants = tuple(_activity_instant(activity) for activity in self.activities)
        if any(later < earlier for earlier, later in pairwise(instants)):
            raise AlpacaPaperAccountActivityError(
                "account activity page is not in ascending transaction order"
            )

    @property
    def activity_count(self) -> int:
        self._validate()
        return len(self.activities)

    @property
    def response_size_bytes(self) -> int:
        self._validate()
        return len(self.response_body)

    @property
    def response_sha256(self) -> str:
        self._validate()
        return hashlib.sha256(self.response_body).hexdigest()

    @property
    def terminal_page(self) -> bool:
        self._validate()
        return len(self.activities) < self.description.page_size

    @property
    def next_page_token(self) -> str | None:
        self._validate()
        if self.terminal_page:
            return None
        return self.activities[-1].provider_activity_id

    @property
    def additional_reconciliation_required(self) -> bool:
        return True

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(
            (
                ALPACA_PAPER_ACCOUNT_ACTIVITY_CONTRACT_VERSION,
                "activity_page_observation",
                self.description.semantic_sha256,
                self.http_status,
                self.provider_request_id,
                self.received_at,
                self.response_size_bytes,
                self.response_sha256,
                tuple(activity.semantic_sha256 for activity in self.activities),
                self.terminal_page,
                self.next_page_token,
                self.canonical_execution_fact_authorized,
                self.provider_revision_identity_qualified,
                self.provider_deduplication_identity_qualified,
            )
        )


def decode_alpaca_paper_account_activity_page(
    description: AlpacaPaperAccountActivityPageDescription,
    *,
    http_status: int,
    provider_request_id: str,
    response_body: bytes,
    received_at: datetime,
) -> AlpacaPaperAccountActivityPageObservation:
    """Decode retained bytes without creating an execution fact."""

    if type(description) is not AlpacaPaperAccountActivityPageDescription:
        raise AlpacaPaperAccountActivityError(
            "account activity decoding requires an exact page description"
        )
    description.__post_init__()
    activities = _decode_activity_array(response_body)
    observation = object.__new__(AlpacaPaperAccountActivityPageObservation)
    object.__setattr__(observation, "description", description)
    object.__setattr__(observation, "http_status", http_status)
    object.__setattr__(
        observation,
        "provider_request_id",
        provider_request_id,
    )
    object.__setattr__(observation, "received_at", received_at)
    object.__setattr__(observation, "response_body", response_body)
    object.__setattr__(observation, "activities", activities)
    observation._validate()
    return observation


@dataclass(frozen=True, slots=True)
class PersistedAlpacaPaperAccountActivityPage(_NoAccountActivityAuthority):
    """A decoded activity page bound to bytes committed before decoding."""

    receipt: BrokerIngressReceipt
    observation: AlpacaPaperAccountActivityPageObservation

    def __post_init__(self) -> None:
        if type(self.receipt) is not BrokerIngressReceipt:
            raise AlpacaPaperAccountActivityError(
                "persisted account activity page requires an exact ingress receipt"
            )
        if type(self.observation) is not AlpacaPaperAccountActivityPageObservation:
            raise AlpacaPaperAccountActivityError(
                "persisted account activity page requires an exact observation"
            )
        self.receipt.__post_init__()
        self.observation._validate()
        delivery = self.receipt.delivery
        observation = self.observation
        expected = (
            (delivery.account_id, observation.description.plan.account_id),
            (delivery.provider_id, ALPACA_PAPER_ADAPTER_ID),
            (delivery.adapter_version, ALPACA_PAPER_ADAPTER_VERSION),
            (delivery.environment, "paper"),
            (
                delivery.channel,
                ALPACA_PAPER_ACCOUNT_ACTIVITY_INGRESS_CHANNEL,
            ),
            (
                delivery.operation,
                ALPACA_PAPER_ACCOUNT_ACTIVITY_INGRESS_OPERATION,
            ),
            (
                delivery.correlation_sha256,
                observation.description.semantic_sha256,
            ),
            (delivery.transport_status, observation.http_status),
            (
                delivery.provider_request_id,
                observation.provider_request_id,
            ),
            (delivery.received_at, observation.received_at),
            (delivery.body, observation.response_body),
            (delivery.body_sha256, observation.response_sha256),
        )
        if any(actual != wanted for actual, wanted in expected):
            raise AlpacaPaperAccountActivityError(
                "decoded account activity page conflicts with its raw receipt"
            )

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(
            (
                ALPACA_PAPER_ACCOUNT_ACTIVITY_CONTRACT_VERSION,
                "persisted_activity_page",
                self.receipt.semantic_sha256,
                self.observation.semantic_sha256,
            )
        )


def persist_then_decode_alpaca_paper_account_activity_page(
    recorder: BrokerIngressRecorder,
    description: AlpacaPaperAccountActivityPageDescription,
    *,
    delivery_idempotency_key: str,
    http_status: int,
    provider_request_id: str | None,
    response_body: bytes,
    received_at: datetime,
    recorded_at: datetime,
    media_type: str | None = "application/json",
) -> PersistedAlpacaPaperAccountActivityPage:
    """Commit exact response bytes before invoking the strict page decoder."""

    if not callable(getattr(recorder, "record", None)):
        raise BrokerIngressError("Alpaca account activity ingress requires a durable recorder")
    if type(description) is not AlpacaPaperAccountActivityPageDescription:
        raise AlpacaPaperAccountActivityError(
            "Alpaca account activity ingress requires an exact page description"
        )
    description.__post_init__()
    delivery = BrokerIngressDelivery(
        account_id=description.plan.account_id,
        delivery_idempotency_key=delivery_idempotency_key,
        provider_id=ALPACA_PAPER_ADAPTER_ID,
        adapter_version=ALPACA_PAPER_ADAPTER_VERSION,
        environment="paper",
        channel=ALPACA_PAPER_ACCOUNT_ACTIVITY_INGRESS_CHANNEL,
        operation=ALPACA_PAPER_ACCOUNT_ACTIVITY_INGRESS_OPERATION,
        correlation_sha256=description.semantic_sha256,
        transport_status=http_status,
        provider_request_id=provider_request_id,
        media_type=media_type,
        received_at=received_at,
        recorded_at=recorded_at,
        body=response_body,
    )
    receipt = recorder.record(delivery)
    if type(receipt) is not BrokerIngressReceipt:
        raise BrokerIngressError(
            "durable recorder returned an invalid account activity ingress receipt"
        )
    receipt.__post_init__()
    if receipt.delivery != delivery:
        raise BrokerIngressError(
            "durable recorder returned a receipt for different account activity bytes"
        )
    if provider_request_id is None:
        raise AlpacaPaperAccountActivityError(
            "account activity response is missing X-Request-ID after raw persistence"
        )
    observation = decode_alpaca_paper_account_activity_page(
        description,
        http_status=http_status,
        provider_request_id=provider_request_id,
        response_body=response_body,
        received_at=received_at,
    )
    return PersistedAlpacaPaperAccountActivityPage(
        receipt=receipt,
        observation=observation,
    )


def _first_page_description(
    plan: AlpacaPaperAccountActivityPlan,
) -> AlpacaPaperAccountActivityPageDescription:
    return AlpacaPaperAccountActivityPageDescription(
        plan=plan,
        page_number=1,
        page_size=min(plan.page_size, plan.maximum_items),
        page_token=None,
        previous_page_sha256=None,
    )


def _next_page_description(
    page: PersistedAlpacaPaperAccountActivityPage,
    *,
    remaining_items: int,
) -> AlpacaPaperAccountActivityPageDescription:
    token = page.observation.next_page_token
    if token is None:
        raise AlpacaPaperAccountActivityError(
            "terminal account activity page has no continuation token"
        )
    if type(remaining_items) is not int or remaining_items <= 0:
        raise AlpacaPaperAccountActivityError(
            "account activity item bound has no continuation capacity"
        )
    return AlpacaPaperAccountActivityPageDescription(
        plan=page.observation.description.plan,
        page_number=page.observation.description.page_number + 1,
        page_size=min(
            page.observation.description.plan.page_size,
            remaining_items,
        ),
        page_token=token,
        previous_page_sha256=page.semantic_sha256,
    )


@dataclass(frozen=True, slots=True)
class AlpacaPaperAccountActivityCapture(_NoAccountActivityAuthority):
    """One bounded raw-first page chain, never canonical execution history."""

    plan: AlpacaPaperAccountActivityPlan
    pages: tuple[PersistedAlpacaPaperAccountActivityPage, ...] = ()

    def __post_init__(self) -> None:
        if type(self.plan) is not AlpacaPaperAccountActivityPlan:
            raise AlpacaPaperAccountActivityError("account activity capture requires an exact plan")
        self.plan.__post_init__()
        if type(self.pages) is not tuple or any(
            type(page) is not PersistedAlpacaPaperAccountActivityPage for page in self.pages
        ):
            raise AlpacaPaperAccountActivityError(
                "account activity capture pages must be an exact tuple"
            )
        if len(self.pages) > self.plan.maximum_pages:
            raise AlpacaPaperAccountActivityError("account activity capture exceeds its page bound")
        seen_provider_ids: set[str] = set()
        observed_items = 0
        previous: PersistedAlpacaPaperAccountActivityPage | None = None
        for page_number, page in enumerate(self.pages, start=1):
            page.__post_init__()
            remaining_before = self.plan.maximum_items - observed_items
            expected = (
                _first_page_description(self.plan)
                if previous is None
                else _next_page_description(
                    previous,
                    remaining_items=remaining_before,
                )
            )
            if page.observation.description != expected:
                raise AlpacaPaperAccountActivityError(
                    "account activity page conflicts with its exact predecessor"
                )
            if page.observation.description.page_number != page_number:
                raise AlpacaPaperAccountActivityError("account activity page chain is not gap-free")
            if previous is not None:
                if previous.observation.terminal_page:
                    raise AlpacaPaperAccountActivityError(
                        "account activity capture continues after a terminal page"
                    )
                if page.receipt.ingress_sequence <= previous.receipt.ingress_sequence:
                    raise AlpacaPaperAccountActivityError(
                        "account activity raw receipt sequence did not advance"
                    )
                if page.observation.received_at < previous.observation.received_at:
                    raise AlpacaPaperAccountActivityError("account activity receive time regressed")
                if page.observation.activities and (
                    _activity_instant(page.observation.activities[0])
                    < _activity_instant(previous.observation.activities[-1])
                ):
                    raise AlpacaPaperAccountActivityError(
                        "account activity page chain is not in ascending transaction order"
                    )
            provider_ids = {
                activity.provider_activity_id for activity in page.observation.activities
            }
            if seen_provider_ids & provider_ids:
                raise AlpacaPaperAccountActivityError(
                    "account activity pages overlap despite the page token"
                )
            observed_items += len(page.observation.activities)
            if observed_items > self.plan.maximum_items:
                raise AlpacaPaperAccountActivityError(
                    "account activity capture exceeds its item bound"
                )
            seen_provider_ids.update(provider_ids)
            previous = page

    @property
    def page_count(self) -> int:
        self.__post_init__()
        return len(self.pages)

    @property
    def activity_count(self) -> int:
        self.__post_init__()
        return sum(len(page.observation.activities) for page in self.pages)

    @property
    def response_size_bytes(self) -> int:
        self.__post_init__()
        return sum(page.observation.response_size_bytes for page in self.pages)

    @property
    def pagination_exhausted(self) -> bool:
        self.__post_init__()
        return bool(self.pages and self.pages[-1].observation.terminal_page)

    @property
    def bounded_truncation(self) -> bool:
        self.__post_init__()
        return bool(
            self.pages
            and not self.pages[-1].observation.terminal_page
            and (
                len(self.pages) == self.plan.maximum_pages
                or self.activity_count == self.plan.maximum_items
            )
        )

    @property
    def next_page_description(
        self,
    ) -> AlpacaPaperAccountActivityPageDescription | None:
        self.__post_init__()
        if not self.pages:
            return _first_page_description(self.plan)
        if self.pagination_exhausted or self.bounded_truncation:
            return None
        return _next_page_description(
            self.pages[-1],
            remaining_items=self.plan.maximum_items - self.activity_count,
        )

    @property
    def additional_reconciliation_required(self) -> bool:
        return True

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(
            (
                ALPACA_PAPER_ACCOUNT_ACTIVITY_CONTRACT_VERSION,
                "activity_capture",
                self.plan.semantic_sha256,
                tuple(page.semantic_sha256 for page in self.pages),
                self.activity_count,
                self.response_size_bytes,
                self.pagination_exhausted,
                self.bounded_truncation,
                self.snapshot_isolation_qualified,
                self.activity_history_complete,
                self.converged,
                self.canonical_execution_fact_authorized,
            )
        )


def create_alpaca_paper_account_activity_plan(
    *,
    account_id: str,
    capture_idempotency_key: str,
    page_size: int = ALPACA_ACTIVITIES_DEFAULT_PAGE_SIZE,
    maximum_pages: int = ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_PAGES,
    maximum_items: int = ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_ITEMS,
) -> AlpacaPaperAccountActivityPlan:
    """Create one bounded ascending FILL traversal without transport authority."""

    return AlpacaPaperAccountActivityPlan(
        account_id=account_id,
        capture_idempotency_key=capture_idempotency_key,
        page_size=page_size,
        maximum_pages=maximum_pages,
        maximum_items=maximum_items,
    )


def start_alpaca_paper_account_activity_capture(
    plan: AlpacaPaperAccountActivityPlan,
) -> AlpacaPaperAccountActivityCapture:
    """Start an empty immutable raw-first account-activity capture."""

    return AlpacaPaperAccountActivityCapture(plan=plan)


def append_alpaca_paper_account_activity_page(
    capture: AlpacaPaperAccountActivityCapture,
    page: PersistedAlpacaPaperAccountActivityPage,
) -> AlpacaPaperAccountActivityCapture:
    """Append only the exact next retained page in the bounded chain."""

    if type(capture) is not AlpacaPaperAccountActivityCapture:
        raise AlpacaPaperAccountActivityError("account activity append requires an exact capture")
    if type(page) is not PersistedAlpacaPaperAccountActivityPage:
        raise AlpacaPaperAccountActivityError(
            "account activity append requires an exact persisted page"
        )
    capture.__post_init__()
    expected = capture.next_page_description
    if expected is None:
        raise AlpacaPaperAccountActivityError(
            "account activity capture has no remaining page authority"
        )
    if page.observation.description != expected:
        raise AlpacaPaperAccountActivityError(
            "account activity append received a different page description"
        )
    return AlpacaPaperAccountActivityCapture(
        plan=capture.plan,
        pages=(*capture.pages, page),
    )


def create_alpaca_paper_account_activity_page_demand(
    description: AlpacaPaperAccountActivityPageDescription,
    *,
    requested_at: datetime,
) -> BrokerRequestDemand:
    """Bind one exact page to a distinct reconciliation-capacity demand."""

    if type(description) is not AlpacaPaperAccountActivityPageDescription:
        raise AlpacaPaperAccountActivityError(
            "account activity demand requires an exact page description"
        )
    description.__post_init__()
    return create_alpaca_paper_request_demand(
        account_id=description.plan.account_id,
        idempotency_key=(
            f"account-activity:{description.plan.capture_id}:{description.page_number:02d}"
        ),
        operation=AlpacaPaperBudgetOperation.RECONCILE_ACCOUNT,
        correlation_sha256=description.semantic_sha256,
        requested_at=requested_at,
    )


__all__ = [
    "ALPACA_PAPER_ACCOUNT_ACTIVITY_CONTRACT_VERSION",
    "ALPACA_PAPER_ACCOUNT_ACTIVITY_INGRESS_CHANNEL",
    "ALPACA_PAPER_ACCOUNT_ACTIVITY_INGRESS_OPERATION",
    "ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_ITEMS",
    "ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_PAGES",
    "ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_RESPONSE_BYTES",
    "AlpacaPaperAccountActivityCapture",
    "AlpacaPaperAccountActivityDecimal",
    "AlpacaPaperAccountActivityError",
    "AlpacaPaperAccountActivityPageDescription",
    "AlpacaPaperAccountActivityPageObservation",
    "AlpacaPaperAccountActivityPlan",
    "AlpacaPaperAccountActivityTimestamp",
    "AlpacaPaperTradeActivity",
    "AlpacaPaperTradeActivitySide",
    "AlpacaPaperTradeActivityType",
    "PersistedAlpacaPaperAccountActivityPage",
    "append_alpaca_paper_account_activity_page",
    "create_alpaca_paper_account_activity_page_demand",
    "create_alpaca_paper_account_activity_plan",
    "decode_alpaca_paper_account_activity_page",
    "persist_then_decode_alpaca_paper_account_activity_page",
    "start_alpaca_paper_account_activity_capture",
]
