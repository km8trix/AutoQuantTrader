"""Bounded, raw-first Alpaca paper open-position observations.

This module describes and decodes one offline ``GET /v2/positions`` capture.
It can append exact response bytes through an injected durable ingress port,
but it has no credential, transport, runtime, lifecycle, reconciliation, or
trading authority.  A decoded array is deliberately not called a complete or
canonical provider snapshot: the endpoint supplies neither snapshot isolation
nor a provider revision identity.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from types import MappingProxyType
from typing import Any, cast
from uuid import UUID

from packages.adapters.broker.alpaca_paper import (
    ALPACA_PAPER_ADAPTER_ID,
    ALPACA_PAPER_ADAPTER_VERSION,
    ALPACA_PAPER_CAPABILITIES,
    ALPACA_PAPER_TRADING_BASE_URL,
    ALPACA_POSITIONS_PATH,
    AlpacaPaperContractError,
)
from packages.adapters.broker.alpaca_paper_account_assets import (
    AlpacaAssetClass,
    AlpacaAssetExchange,
)
from packages.domain.broker_ingress import (
    MAX_BROKER_INGRESS_BODY_BYTES,
    BrokerIngressDelivery,
    BrokerIngressError,
    BrokerIngressReceipt,
    BrokerIngressRecorder,
)
from packages.domain.canonical import canonical_decimal, canonical_json_bytes
from packages.domain.identifiers import canonical_id
from packages.domain.models import require_utc

ALPACA_PAPER_POSITION_SNAPSHOT_CONTRACT_VERSION = "phase4r-bounded-raw-first-position-snapshot-v1"
ALPACA_PAPER_POSITION_SNAPSHOT_REVIEWED_ON = "2026-07-28"
ALPACA_PAPER_POSITION_SNAPSHOT_MAX_RESPONSE_BYTES = MAX_BROKER_INGRESS_BODY_BYTES
ALPACA_PAPER_POSITION_SNAPSHOT_MAX_POSITIONS = 512
ALPACA_PAPER_POSITION_SNAPSHOT_INGRESS_CHANNEL = "rest_position_snapshot_response"
ALPACA_PAPER_POSITION_SNAPSHOT_INGRESS_OPERATION = "get_all_open_positions"

_POSITION_REQUIRED_KEYS = frozenset(
    {
        "asset_class",
        "asset_id",
        "avg_entry_price",
        "change_today",
        "cost_basis",
        "current_price",
        "exchange",
        "lastday_price",
        "market_value",
        "qty",
        "side",
        "symbol",
        "unrealized_intraday_pl",
        "unrealized_intraday_plpc",
        "unrealized_pl",
        "unrealized_plpc",
        "asset_marginable",
    }
)
_POSITION_OPTIONAL_KEYS = frozenset({"qty_available"})
_POSITION_KEYS = _POSITION_REQUIRED_KEYS | _POSITION_OPTIONAL_KEYS
_US_EQUITY_POSITION_EXCHANGES = frozenset(
    {
        AlpacaAssetExchange.AMEX,
        AlpacaAssetExchange.ARCA,
        AlpacaAssetExchange.BATS,
        AlpacaAssetExchange.NYSE,
        AlpacaAssetExchange.NASDAQ,
        AlpacaAssetExchange.NYSEARCA,
        AlpacaAssetExchange.OTC,
    }
)
_DECIMAL_TEXT = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]{1,18})?")
_SAFE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SYMBOL = re.compile(r"[A-Z][A-Z0-9./-]{0,31}")


class AlpacaPaperPositionSnapshotError(AlpacaPaperContractError):
    """A position capture or retained response violates the frozen profile."""


class AlpacaPaperPositionSide(StrEnum):
    """Reviewed Alpaca position-side values."""

    LONG = "long"
    SHORT = "short"


class _NoPositionSnapshotAuthority:
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
    def converged(self) -> bool:
        return False

    @property
    def provider_revision_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_authorized(self) -> bool:
        return False

    @property
    def canonical_position_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
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
        raise AlpacaPaperPositionSnapshotError(
            f"{field_name} must be bounded, trimmed text without control characters"
        )
    return value


def _require_safe_key(value: object, field_name: str) -> str:
    if type(value) is not str or _SAFE_KEY.fullmatch(value) is None:
        raise AlpacaPaperPositionSnapshotError(
            f"{field_name} must contain 8-128 safe visible characters"
        )
    return value


def _require_uuid(value: object, field_name: str) -> str:
    raw = _require_text(value, field_name, maximum=36)
    try:
        parsed = UUID(raw)
    except ValueError as error:
        raise AlpacaPaperPositionSnapshotError(f"{field_name} must be a canonical UUID") from error
    if str(parsed) != raw:
        raise AlpacaPaperPositionSnapshotError(f"{field_name} must be a canonical lowercase UUID")
    return raw


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperPositionSnapshotError(f"{field_name} must be an exact datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperPositionSnapshotError(str(error)) from error
    return value


def _decimal_parts(value: object, field_name: str) -> tuple[str, Decimal]:
    raw = _require_text(value, field_name, maximum=64)
    if _DECIMAL_TEXT.fullmatch(raw) is None:
        raise AlpacaPaperPositionSnapshotError(
            f"{field_name} must be a bounded plain decimal string"
        )
    integer, separator, fraction = raw.removeprefix("-").partition(".")
    if len(integer) > 18 or (separator and len(fraction) > 18):
        raise AlpacaPaperPositionSnapshotError(f"{field_name} exceeds the reviewed decimal bounds")
    try:
        parsed = canonical_decimal(Decimal(raw))
    except (InvalidOperation, ValueError) as error:
        raise AlpacaPaperPositionSnapshotError(f"{field_name} must be a finite decimal") from error
    return raw, parsed


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperPositionDecimal:
    """A proof-constructed Decimal paired with its exact provider lexeme."""

    raw: str
    value: Decimal

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperPositionDecimal must be proof-constructed")

    def _validate(self) -> None:
        raw, parsed = _decimal_parts(self.raw, "Alpaca position decimal")
        if raw != self.raw or type(self.value) is not Decimal or self.value != parsed:
            raise AlpacaPaperPositionSnapshotError(
                "Alpaca position decimal conflicts with its exact provider lexeme"
            )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(
            (
                ALPACA_PAPER_POSITION_SNAPSHOT_CONTRACT_VERSION,
                "position_decimal",
                self.raw,
                self.value,
            )
        )


def _position_decimal(value: object, field_name: str) -> AlpacaPaperPositionDecimal:
    raw, parsed = _decimal_parts(value, field_name)
    result = object.__new__(AlpacaPaperPositionDecimal)
    object.__setattr__(result, "raw", raw)
    object.__setattr__(result, "value", parsed)
    result._validate()
    return result


def _optional_position_decimal(
    value: object,
    field_name: str,
) -> AlpacaPaperPositionDecimal | None:
    if value is None:
        return None
    return _position_decimal(value, field_name)


def _require_position_decimal(
    value: object,
    field_name: str,
) -> AlpacaPaperPositionDecimal:
    if type(value) is not AlpacaPaperPositionDecimal:
        raise AlpacaPaperPositionSnapshotError(
            f"{field_name} must be an exact proof-constructed position decimal"
        )
    value._validate()
    return value


def _require_optional_position_decimal(
    value: object,
    field_name: str,
) -> AlpacaPaperPositionDecimal | None:
    if value is None:
        return None
    return _require_position_decimal(value, field_name)


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperPositionObservation(_NoPositionSnapshotAuthority):
    """One strict, raw-derived position object with no canonical meaning."""

    asset_id: str
    symbol: str
    exchange: AlpacaAssetExchange
    asset_class: AlpacaAssetClass
    asset_marginable: bool
    average_entry_price: AlpacaPaperPositionDecimal
    quantity: AlpacaPaperPositionDecimal
    side: AlpacaPaperPositionSide
    market_value: AlpacaPaperPositionDecimal
    cost_basis: AlpacaPaperPositionDecimal
    unrealized_profit_loss: AlpacaPaperPositionDecimal
    unrealized_profit_loss_percent: AlpacaPaperPositionDecimal
    unrealized_intraday_profit_loss: AlpacaPaperPositionDecimal
    unrealized_intraday_profit_loss_percent: AlpacaPaperPositionDecimal
    current_price: AlpacaPaperPositionDecimal
    last_day_price: AlpacaPaperPositionDecimal
    change_today: AlpacaPaperPositionDecimal
    quantity_available: AlpacaPaperPositionDecimal | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperPositionObservation must be proof-constructed")

    def _validate(self) -> None:
        _require_uuid(self.asset_id, "Alpaca position asset ID")
        symbol = _require_text(self.symbol, "Alpaca position symbol", maximum=32)
        if _SYMBOL.fullmatch(symbol) is None:
            raise AlpacaPaperPositionSnapshotError(
                "Alpaca position symbol is outside the reviewed profile"
            )
        if (
            type(self.exchange) is not AlpacaAssetExchange
            or self.exchange not in _US_EQUITY_POSITION_EXCHANGES
        ):
            raise AlpacaPaperPositionSnapshotError(
                "Alpaca position exchange is outside the reviewed US-equity profile"
            )
        if (
            type(self.asset_class) is not AlpacaAssetClass
            or self.asset_class is not AlpacaAssetClass.US_EQUITY
        ):
            raise AlpacaPaperPositionSnapshotError(
                "Alpaca position asset class must be the reviewed us_equity profile"
            )
        if type(self.asset_marginable) is not bool:
            raise AlpacaPaperPositionSnapshotError(
                "Alpaca US-equity position asset_marginable must be an exact boolean"
            )
        average_entry_price = _require_position_decimal(
            self.average_entry_price,
            "Alpaca position average entry price",
        )
        quantity = _require_position_decimal(self.quantity, "Alpaca position quantity")
        if average_entry_price.value <= 0:
            raise AlpacaPaperPositionSnapshotError(
                "Alpaca open-position average entry price must be positive"
            )
        if type(self.side) is not AlpacaPaperPositionSide:
            raise AlpacaPaperPositionSnapshotError(
                "Alpaca position side is outside the reviewed profile"
            )
        if (self.side is AlpacaPaperPositionSide.LONG and quantity.value <= 0) or (
            self.side is AlpacaPaperPositionSide.SHORT and quantity.value >= 0
        ):
            raise AlpacaPaperPositionSnapshotError(
                "Alpaca open-position quantity sign conflicts with its side"
            )
        for value, field_name in (
            (self.market_value, "Alpaca position market value"),
            (self.unrealized_profit_loss, "Alpaca position unrealized profit/loss"),
            (
                self.unrealized_profit_loss_percent,
                "Alpaca position unrealized profit/loss percent",
            ),
            (
                self.unrealized_intraday_profit_loss,
                "Alpaca position unrealized intraday profit/loss",
            ),
            (
                self.unrealized_intraday_profit_loss_percent,
                "Alpaca position unrealized intraday profit/loss percent",
            ),
            (self.change_today, "Alpaca position change today"),
        ):
            _require_position_decimal(value, field_name)
        _require_optional_position_decimal(
            self.quantity_available,
            "Alpaca position quantity available",
        )
        _require_position_decimal(self.cost_basis, "Alpaca position cost basis")
        for value, field_name in (
            (self.current_price, "Alpaca position current price"),
            (self.last_day_price, "Alpaca position last-day price"),
        ):
            price = _require_position_decimal(value, field_name)
            if price.value < 0:
                raise AlpacaPaperPositionSnapshotError(f"{field_name} cannot be negative")

    @property
    def semantic_sha256(self) -> str:
        self._validate()

        def optional_digest(value: AlpacaPaperPositionDecimal | None) -> str | None:
            return None if value is None else value.semantic_sha256

        return _semantic_sha256(
            (
                ALPACA_PAPER_POSITION_SNAPSHOT_CONTRACT_VERSION,
                "position_observation",
                self.asset_id,
                self.symbol,
                self.exchange,
                self.asset_class,
                self.asset_marginable,
                self.average_entry_price.semantic_sha256,
                self.quantity.semantic_sha256,
                self.side,
                self.market_value.semantic_sha256,
                self.cost_basis.semantic_sha256,
                self.unrealized_profit_loss.semantic_sha256,
                self.unrealized_profit_loss_percent.semantic_sha256,
                self.unrealized_intraday_profit_loss.semantic_sha256,
                self.unrealized_intraday_profit_loss_percent.semantic_sha256,
                self.current_price.semantic_sha256,
                self.last_day_price.semantic_sha256,
                self.change_today.semantic_sha256,
                optional_digest(self.quantity_available),
            )
        )


def _enum_value[T: StrEnum](
    value: object,
    field_name: str,
    enum_type: type[T],
) -> T:
    raw = _require_text(value, field_name, maximum=64)
    try:
        return enum_type(raw)
    except ValueError as error:
        raise AlpacaPaperPositionSnapshotError(
            f"{field_name} has unsupported value {raw!r}"
        ) from error


def _position_observation(value: dict[str, Any]) -> AlpacaPaperPositionObservation:
    actual = frozenset(value)
    missing = tuple(sorted(_POSITION_REQUIRED_KEYS - actual))
    extra = tuple(sorted(actual - _POSITION_KEYS))
    if missing or extra:
        raise AlpacaPaperPositionSnapshotError(
            "Alpaca position object is outside the reviewed wire profile; "
            f"missing={missing!r}, extra={extra!r}"
        )
    asset_marginable = value["asset_marginable"]
    if type(asset_marginable) is not bool:
        raise AlpacaPaperPositionSnapshotError(
            "Alpaca US-equity position asset_marginable must be an exact boolean"
        )
    result = object.__new__(AlpacaPaperPositionObservation)
    object.__setattr__(
        result,
        "asset_id",
        _require_uuid(value["asset_id"], "Alpaca position asset ID"),
    )
    object.__setattr__(
        result,
        "symbol",
        _require_text(value["symbol"], "Alpaca position symbol", maximum=32),
    )
    object.__setattr__(
        result,
        "exchange",
        _enum_value(value["exchange"], "Alpaca position exchange", AlpacaAssetExchange),
    )
    object.__setattr__(
        result,
        "asset_class",
        _enum_value(
            value["asset_class"],
            "Alpaca position asset class",
            AlpacaAssetClass,
        ),
    )
    object.__setattr__(result, "asset_marginable", asset_marginable)
    object.__setattr__(
        result,
        "average_entry_price",
        _position_decimal(
            value["avg_entry_price"],
            "Alpaca position avg_entry_price",
        ),
    )
    object.__setattr__(
        result,
        "quantity",
        _position_decimal(value["qty"], "Alpaca position qty"),
    )
    object.__setattr__(
        result,
        "side",
        _enum_value(value["side"], "Alpaca position side", AlpacaPaperPositionSide),
    )
    object.__setattr__(
        result,
        "market_value",
        _position_decimal(
            value["market_value"],
            "Alpaca position market_value",
        ),
    )
    object.__setattr__(
        result,
        "cost_basis",
        _position_decimal(value["cost_basis"], "Alpaca position cost_basis"),
    )
    for attribute, wire_name, field_name in (
        ("unrealized_profit_loss", "unrealized_pl", "Alpaca position unrealized_pl"),
        (
            "unrealized_profit_loss_percent",
            "unrealized_plpc",
            "Alpaca position unrealized_plpc",
        ),
        (
            "unrealized_intraday_profit_loss",
            "unrealized_intraday_pl",
            "Alpaca position unrealized_intraday_pl",
        ),
        (
            "unrealized_intraday_profit_loss_percent",
            "unrealized_intraday_plpc",
            "Alpaca position unrealized_intraday_plpc",
        ),
        ("current_price", "current_price", "Alpaca position current_price"),
        ("last_day_price", "lastday_price", "Alpaca position lastday_price"),
        ("change_today", "change_today", "Alpaca position change_today"),
    ):
        object.__setattr__(
            result,
            attribute,
            _position_decimal(value[wire_name], field_name),
        )
    object.__setattr__(
        result,
        "quantity_available",
        (
            None
            if "qty_available" not in value
            else _position_decimal(value["qty_available"], "Alpaca position qty_available")
        ),
    )
    result._validate()
    return result


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AlpacaPaperPositionSnapshotError(
                f"position snapshot response contains duplicate JSON key {key!r}"
            )
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise AlpacaPaperPositionSnapshotError(
        f"position snapshot response contains non-standard JSON constant {value!r}"
    )


def _decode_position_array(response_body: bytes) -> tuple[AlpacaPaperPositionObservation, ...]:
    if type(response_body) is not bytes:
        raise AlpacaPaperPositionSnapshotError("position snapshot response must be exact bytes")
    if not 1 <= len(response_body) <= ALPACA_PAPER_POSITION_SNAPSHOT_MAX_RESPONSE_BYTES:
        raise AlpacaPaperPositionSnapshotError(
            "position snapshot response size is outside the durable ingress bound"
        )
    try:
        text = response_body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AlpacaPaperPositionSnapshotError(
            "position snapshot response must be UTF-8"
        ) from error
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except AlpacaPaperPositionSnapshotError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as error:
        raise AlpacaPaperPositionSnapshotError(
            "position snapshot response is invalid JSON"
        ) from error
    if type(decoded) is not list:
        raise AlpacaPaperPositionSnapshotError("position snapshot response must be one JSON array")
    if len(decoded) > ALPACA_PAPER_POSITION_SNAPSHOT_MAX_POSITIONS:
        raise AlpacaPaperPositionSnapshotError(
            "position snapshot response exceeds the local item bound; no items were truncated"
        )
    positions: list[AlpacaPaperPositionObservation] = []
    for index, value in enumerate(decoded):
        if type(value) is not dict:
            raise AlpacaPaperPositionSnapshotError(
                f"position snapshot item {index} must be one JSON object"
            )
        try:
            positions.append(_position_observation(cast(dict[str, Any], value)))
        except AlpacaPaperPositionSnapshotError as error:
            raise AlpacaPaperPositionSnapshotError(
                f"position snapshot item {index} is outside the frozen position profile"
            ) from error
    asset_ids = tuple(position.asset_id for position in positions)
    if len(set(asset_ids)) != len(asset_ids):
        raise AlpacaPaperPositionSnapshotError("position snapshot repeats a provider asset ID")
    provider_identities = tuple((position.asset_class, position.symbol) for position in positions)
    if len(set(provider_identities)) != len(provider_identities):
        raise AlpacaPaperPositionSnapshotError(
            "position snapshot repeats an asset-class/symbol provider identity"
        )
    return tuple(positions)


@dataclass(frozen=True, slots=True)
class AlpacaPaperPositionSnapshotDescription(_NoPositionSnapshotAuthority):
    """One exact, non-I/O GET description and account-local capture identity."""

    account_id: str
    capture_idempotency_key: str

    def __post_init__(self) -> None:
        _require_text(self.account_id, "position snapshot account ID", maximum=64)
        _require_safe_key(
            self.capture_idempotency_key,
            "position snapshot capture idempotency key",
        )
        ALPACA_PAPER_CAPABILITIES.__post_init__()

    @property
    def capture_id(self) -> str:
        self.__post_init__()
        return canonical_id(
            "alpaca-paper-position-snapshot",
            self.account_id,
            self.capture_idempotency_key,
        )

    @property
    def method(self) -> str:
        return "GET"

    @property
    def base_url(self) -> str:
        return ALPACA_PAPER_TRADING_BASE_URL

    @property
    def path(self) -> str:
        return ALPACA_POSITIONS_PATH

    @property
    def query(self) -> Mapping[str, str]:
        return MappingProxyType({})

    @property
    def request_target(self) -> str:
        return self.path

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(
            (
                ALPACA_PAPER_POSITION_SNAPSHOT_CONTRACT_VERSION,
                "position_snapshot_description",
                self.capture_id,
                self.account_id,
                self.capture_idempotency_key,
                ALPACA_PAPER_CAPABILITIES.semantic_sha256,
                self.method,
                self.base_url,
                self.path,
                tuple(self.query.items()),
            )
        )


def create_alpaca_paper_position_snapshot_description(
    *,
    account_id: str,
    capture_idempotency_key: str,
) -> AlpacaPaperPositionSnapshotDescription:
    """Describe one open-position capture without granting broker-call authority."""

    return AlpacaPaperPositionSnapshotDescription(
        account_id=account_id,
        capture_idempotency_key=capture_idempotency_key,
    )


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperPositionSnapshotObservation(_NoPositionSnapshotAuthority):
    """Exact retained response bytes and their strict, non-authorizing decode."""

    description: AlpacaPaperPositionSnapshotDescription
    http_status: int
    provider_request_id: str
    received_at: datetime
    response_body: bytes = field(repr=False)
    positions: tuple[AlpacaPaperPositionObservation, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperPositionSnapshotObservation must be proof-constructed")

    def _validate(self) -> None:
        if type(self.description) is not AlpacaPaperPositionSnapshotDescription:
            raise AlpacaPaperPositionSnapshotError(
                "position snapshot observation requires an exact description"
            )
        self.description.__post_init__()
        if type(self.http_status) is not int or self.http_status != 200:
            raise AlpacaPaperPositionSnapshotError(
                "position snapshot decoding supports only HTTP 200"
            )
        _require_text(
            self.provider_request_id,
            "position snapshot X-Request-ID",
            maximum=256,
        )
        _require_utc(self.received_at, "position snapshot received_at")
        if type(self.positions) is not tuple or any(
            type(position) is not AlpacaPaperPositionObservation for position in self.positions
        ):
            raise AlpacaPaperPositionSnapshotError(
                "position snapshot positions must be an exact tuple"
            )
        decoded = _decode_position_array(self.response_body)
        if decoded != self.positions:
            raise AlpacaPaperPositionSnapshotError(
                "position snapshot observations conflict with exact response bytes"
            )

    @property
    def position_count(self) -> int:
        self._validate()
        return len(self.positions)

    @property
    def response_size_bytes(self) -> int:
        self._validate()
        return len(self.response_body)

    @property
    def response_sha256(self) -> str:
        self._validate()
        return hashlib.sha256(self.response_body).hexdigest()

    @property
    def additional_reconciliation_required(self) -> bool:
        return True

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(
            (
                ALPACA_PAPER_POSITION_SNAPSHOT_CONTRACT_VERSION,
                "position_snapshot_observation",
                self.description.semantic_sha256,
                self.http_status,
                self.provider_request_id,
                self.received_at,
                self.response_size_bytes,
                self.response_sha256,
                tuple(position.semantic_sha256 for position in self.positions),
                self.provider_snapshot_complete,
                self.canonical_position_fact_authorized,
                self.reconciliation_complete,
            )
        )


def decode_alpaca_paper_position_snapshot_response(
    description: AlpacaPaperPositionSnapshotDescription,
    *,
    http_status: int,
    provider_request_id: str,
    response_body: bytes,
    received_at: datetime,
) -> AlpacaPaperPositionSnapshotObservation:
    """Decode retained bytes without applying or reconciling positions."""

    if type(description) is not AlpacaPaperPositionSnapshotDescription:
        raise AlpacaPaperPositionSnapshotError(
            "position snapshot decoding requires an exact description"
        )
    description.__post_init__()
    positions = _decode_position_array(response_body)
    observation = object.__new__(AlpacaPaperPositionSnapshotObservation)
    object.__setattr__(observation, "description", description)
    object.__setattr__(observation, "http_status", http_status)
    object.__setattr__(observation, "provider_request_id", provider_request_id)
    object.__setattr__(observation, "received_at", received_at)
    object.__setattr__(observation, "response_body", response_body)
    object.__setattr__(observation, "positions", positions)
    observation._validate()
    return observation


@dataclass(frozen=True, slots=True)
class PersistedAlpacaPaperPositionSnapshot(_NoPositionSnapshotAuthority):
    """A decoded position response bound to bytes committed before decoding."""

    receipt: BrokerIngressReceipt
    observation: AlpacaPaperPositionSnapshotObservation

    def __post_init__(self) -> None:
        if type(self.receipt) is not BrokerIngressReceipt:
            raise AlpacaPaperPositionSnapshotError(
                "persisted position snapshot requires an exact ingress receipt"
            )
        if type(self.observation) is not AlpacaPaperPositionSnapshotObservation:
            raise AlpacaPaperPositionSnapshotError(
                "persisted position snapshot requires an exact observation"
            )
        self.receipt.__post_init__()
        self.observation._validate()
        delivery = self.receipt.delivery
        observation = self.observation
        expected = (
            (delivery.account_id, observation.description.account_id),
            (delivery.delivery_idempotency_key, observation.description.capture_idempotency_key),
            (delivery.provider_id, ALPACA_PAPER_ADAPTER_ID),
            (delivery.adapter_version, ALPACA_PAPER_ADAPTER_VERSION),
            (delivery.environment, "paper"),
            (delivery.channel, ALPACA_PAPER_POSITION_SNAPSHOT_INGRESS_CHANNEL),
            (delivery.operation, ALPACA_PAPER_POSITION_SNAPSHOT_INGRESS_OPERATION),
            (delivery.correlation_sha256, observation.description.semantic_sha256),
            (delivery.transport_status, observation.http_status),
            (delivery.provider_request_id, observation.provider_request_id),
            (delivery.received_at, observation.received_at),
            (delivery.body, observation.response_body),
            (delivery.body_sha256, observation.response_sha256),
        )
        if any(actual != wanted for actual, wanted in expected):
            raise AlpacaPaperPositionSnapshotError(
                "decoded position snapshot conflicts with its raw receipt"
            )

    @property
    def capture_id(self) -> str:
        self.__post_init__()
        return self.observation.description.capture_id

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(
            (
                ALPACA_PAPER_POSITION_SNAPSHOT_CONTRACT_VERSION,
                "persisted_position_snapshot",
                self.capture_id,
                self.receipt.semantic_sha256,
                self.observation.semantic_sha256,
            )
        )


def persist_then_decode_alpaca_paper_position_snapshot_response(
    recorder: BrokerIngressRecorder,
    description: AlpacaPaperPositionSnapshotDescription,
    *,
    http_status: int,
    provider_request_id: str | None,
    response_body: bytes,
    received_at: datetime,
    recorded_at: datetime,
    media_type: str | None = "application/json",
) -> PersistedAlpacaPaperPositionSnapshot:
    """Commit exact response bytes before invoking the strict offline decoder."""

    if not callable(getattr(recorder, "record", None)):
        raise BrokerIngressError("Alpaca position snapshot ingress requires a durable recorder")
    if type(description) is not AlpacaPaperPositionSnapshotDescription:
        raise AlpacaPaperPositionSnapshotError(
            "Alpaca position snapshot ingress requires an exact description"
        )
    description.__post_init__()
    delivery = BrokerIngressDelivery(
        account_id=description.account_id,
        delivery_idempotency_key=description.capture_idempotency_key,
        provider_id=ALPACA_PAPER_ADAPTER_ID,
        adapter_version=ALPACA_PAPER_ADAPTER_VERSION,
        environment="paper",
        channel=ALPACA_PAPER_POSITION_SNAPSHOT_INGRESS_CHANNEL,
        operation=ALPACA_PAPER_POSITION_SNAPSHOT_INGRESS_OPERATION,
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
            "durable recorder returned an invalid position snapshot ingress receipt"
        )
    receipt.__post_init__()
    if receipt.delivery != delivery:
        raise BrokerIngressError(
            "durable recorder returned a receipt for different position snapshot bytes"
        )
    if provider_request_id is None:
        raise AlpacaPaperPositionSnapshotError(
            "position snapshot response is missing X-Request-ID after raw persistence"
        )
    observation = decode_alpaca_paper_position_snapshot_response(
        description,
        http_status=http_status,
        provider_request_id=provider_request_id,
        response_body=response_body,
        received_at=received_at,
    )
    return PersistedAlpacaPaperPositionSnapshot(
        receipt=receipt,
        observation=observation,
    )


__all__ = [
    "ALPACA_PAPER_POSITION_SNAPSHOT_CONTRACT_VERSION",
    "ALPACA_PAPER_POSITION_SNAPSHOT_INGRESS_CHANNEL",
    "ALPACA_PAPER_POSITION_SNAPSHOT_INGRESS_OPERATION",
    "ALPACA_PAPER_POSITION_SNAPSHOT_MAX_POSITIONS",
    "ALPACA_PAPER_POSITION_SNAPSHOT_MAX_RESPONSE_BYTES",
    "ALPACA_PAPER_POSITION_SNAPSHOT_REVIEWED_ON",
    "AlpacaPaperPositionDecimal",
    "AlpacaPaperPositionObservation",
    "AlpacaPaperPositionSide",
    "AlpacaPaperPositionSnapshotDescription",
    "AlpacaPaperPositionSnapshotError",
    "AlpacaPaperPositionSnapshotObservation",
    "PersistedAlpacaPaperPositionSnapshot",
    "create_alpaca_paper_position_snapshot_description",
    "decode_alpaca_paper_position_snapshot_response",
    "persist_then_decode_alpaca_paper_position_snapshot_response",
]
