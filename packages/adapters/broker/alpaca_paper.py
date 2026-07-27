"""Offline, non-authorizing Alpaca paper capability contract.

This module freezes one reviewed provider surface and translates an exact
canonical intent into immutable request evidence.  It has no credential,
clock, filesystem, transport, persistence, reconciliation, or trading
authority.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import cast

from packages.domain.canonical import canonical_decimal, canonical_json_bytes
from packages.domain.models import OrderIntent
from packages.domain.submission_attempt import (
    BrokerSubmissionRequest,
    create_broker_submission_request,
)

ALPACA_PAPER_CAPABILITY_CONTRACT_VERSION = "phase4a-alpaca-paper-capability-v1"
ALPACA_PAPER_ADAPTER_ID = "alpaca-paper"
ALPACA_PAPER_ADAPTER_VERSION = "1.0.0"
ALPACA_PAPER_CAPABILITY_PROFILE_ID = "alpaca-paper-us-etf-market-day-rth-v1"
ALPACA_PAPER_CAPABILITY_REVIEWED_ON = "2026-07-26"

ALPACA_PAPER_TRADING_BASE_URL = "https://paper-api.alpaca.markets"
ALPACA_PAPER_TRADING_WEBSOCKET_URL = "wss://paper-api.alpaca.markets/stream"
ALPACA_CREATE_ORDER_PATH = "/v2/orders"
ALPACA_ORDER_BY_CLIENT_ID_PATH = "/v2/orders:by_client_order_id"
ALPACA_ACCOUNT_PATH = "/v2/account"
ALPACA_POSITIONS_PATH = "/v2/positions"
ALPACA_ORDERS_PATH = "/v2/orders"
ALPACA_ACCOUNT_ACTIVITIES_PATH = "/v2/account/activities"
ALPACA_AUTH_HEADER_NAMES = ("APCA-API-KEY-ID", "APCA-API-SECRET-KEY")

ALPACA_PAPER_CANDIDATE_INSTRUMENTS = (
    ("US-ETF-DIA", "DIA"),
    ("US-ETF-IWM", "IWM"),
    ("US-ETF-QQQ", "QQQ"),
    ("US-ETF-SPY", "SPY"),
)
ALPACA_DOCUMENTED_EQUITY_ORDER_TYPES = (
    "limit",
    "market",
    "stop",
    "stop_limit",
    "trailing_stop",
)
ALPACA_DOCUMENTED_EQUITY_TIME_IN_FORCE = (
    "cls",
    "day",
    "fok",
    "gtc",
    "ioc",
    "opg",
)
ALPACA_DOCUMENTED_EQUITY_ORDER_CLASSES = ("bracket", "oco", "oto", "simple")

ALPACA_PAPER_MAX_CLIENT_ORDER_ID_LENGTH = 128
ALPACA_ORDERS_DEFAULT_PAGE_LIMIT = 50
ALPACA_ORDERS_MAX_PAGE_LIMIT = 500
ALPACA_ACTIVITIES_MIN_PAGE_SIZE = 1
ALPACA_ACTIVITIES_DEFAULT_PAGE_SIZE = 100
ALPACA_ACTIVITIES_MAX_PAGE_SIZE = 100
ALPACA_DOCUMENTED_TRADING_REQUESTS_PER_MINUTE = 200

_ALPACA_REQUEST_METADATA_KEYS = (
    "capability_sha256",
    "contract_version",
    "instrument_id",
    "required_asset_class",
    "required_dispatch_session",
    "required_order_class",
)
_ALPACA_ORDER_BODY_KEYS = (
    "extended_hours",
    "qty",
    "side",
    "symbol",
    "time_in_force",
    "type",
)
_RUNTIME_READINESS_FIELDS = (
    "credential_resolution_ready",
    "request_budget_enforced",
    "transport_submission_ready",
    "transport_cancellation_ready",
    "client_order_id_lookup_ready",
    "order_snapshot_pagination_ready",
    "activity_snapshot_pagination_ready",
    "trade_update_stream_ready",
    "inbox_deduplication_ready",
    "reconciliation_ready",
    "market_data_feed_ready",
    "exchange_calendar_binding_ready",
    "session_validation_ready",
    "security_mapping_ready",
    "asset_tradability_validation_ready",
    "reduce_only_validation_ready",
    "coordinator_dispatch_ready",
    "paper_startup_ready",
    "live_startup_ready",
)

type AlpacaOrderBodyValue = str | bool


class AlpacaPaperContractError(ValueError):
    """The frozen paper contract or a translated request was violated."""


class AlpacaOrderStatus(StrEnum):
    """Frozen Alpaca equity order statuses reviewed for Phase 4A."""

    ACCEPTED = "accepted"
    PENDING_NEW = "pending_new"
    ACCEPTED_FOR_BIDDING = "accepted_for_bidding"
    NEW = "new"
    HELD = "held"
    STOPPED = "stopped"
    PARTIALLY_FILLED = "partially_filled"
    FILLED = "filled"
    DONE_FOR_DAY = "done_for_day"
    CANCELED = "canceled"
    EXPIRED = "expired"
    REPLACED = "replaced"
    PENDING_CANCEL = "pending_cancel"
    PENDING_REPLACE = "pending_replace"
    PENDING_REVIEW = "pending_review"
    REJECTED = "rejected"
    SUSPENDED = "suspended"
    CALCULATED = "calculated"


class AlpacaOrderDisposition(StrEnum):
    """Conservative non-canonical meaning of a frozen provider state."""

    ACKNOWLEDGED = "acknowledged"
    WORKING = "working"
    PARTIALLY_FILLED = "partially_filled"
    FILLED = "filled"
    PENDING_CANCEL = "pending_cancel"
    CANCELED = "canceled"
    EXPIRED = "expired"
    REJECTED = "rejected"
    RECONCILIATION_REQUIRED = "reconciliation_required"


ALPACA_ORDER_STATUS_DISPOSITIONS: Mapping[AlpacaOrderStatus, AlpacaOrderDisposition] = (
    MappingProxyType(
        {
            AlpacaOrderStatus.ACCEPTED: AlpacaOrderDisposition.ACKNOWLEDGED,
            AlpacaOrderStatus.PENDING_NEW: AlpacaOrderDisposition.ACKNOWLEDGED,
            AlpacaOrderStatus.ACCEPTED_FOR_BIDDING: (
                AlpacaOrderDisposition.RECONCILIATION_REQUIRED
            ),
            AlpacaOrderStatus.NEW: AlpacaOrderDisposition.WORKING,
            AlpacaOrderStatus.HELD: AlpacaOrderDisposition.RECONCILIATION_REQUIRED,
            AlpacaOrderStatus.STOPPED: AlpacaOrderDisposition.RECONCILIATION_REQUIRED,
            AlpacaOrderStatus.PARTIALLY_FILLED: AlpacaOrderDisposition.PARTIALLY_FILLED,
            AlpacaOrderStatus.FILLED: AlpacaOrderDisposition.FILLED,
            AlpacaOrderStatus.DONE_FOR_DAY: AlpacaOrderDisposition.RECONCILIATION_REQUIRED,
            AlpacaOrderStatus.CANCELED: AlpacaOrderDisposition.CANCELED,
            AlpacaOrderStatus.EXPIRED: AlpacaOrderDisposition.EXPIRED,
            AlpacaOrderStatus.REPLACED: AlpacaOrderDisposition.RECONCILIATION_REQUIRED,
            AlpacaOrderStatus.PENDING_CANCEL: AlpacaOrderDisposition.PENDING_CANCEL,
            AlpacaOrderStatus.PENDING_REPLACE: AlpacaOrderDisposition.RECONCILIATION_REQUIRED,
            AlpacaOrderStatus.PENDING_REVIEW: AlpacaOrderDisposition.RECONCILIATION_REQUIRED,
            AlpacaOrderStatus.REJECTED: AlpacaOrderDisposition.REJECTED,
            AlpacaOrderStatus.SUSPENDED: AlpacaOrderDisposition.RECONCILIATION_REQUIRED,
            AlpacaOrderStatus.CALCULATED: AlpacaOrderDisposition.RECONCILIATION_REQUIRED,
        }
    )
)


def _require_exhaustive_dispositions() -> None:
    if frozenset(ALPACA_ORDER_STATUS_DISPOSITIONS) != frozenset(AlpacaOrderStatus):
        raise RuntimeError("Alpaca order-status dispositions must be exhaustive")


_require_exhaustive_dispositions()


def classify_alpaca_order_status(raw_status: str) -> AlpacaOrderDisposition:
    """Classify one exact provider status without normalization or inference."""

    if type(raw_status) is not str or not raw_status or raw_status != raw_status.strip():
        raise AlpacaPaperContractError("Alpaca order status must be a non-empty exact string")
    try:
        status = AlpacaOrderStatus(raw_status)
    except ValueError as error:
        raise AlpacaPaperContractError(
            f"unsupported Alpaca order status: {raw_status!r}"
        ) from error
    return ALPACA_ORDER_STATUS_DISPOSITIONS[status]


@dataclass(frozen=True, slots=True)
class AlpacaPaperCapabilityMatrix:
    """Exact reviewed provider breadth, local subset, and closed runtime gates."""

    contract_version: str = ALPACA_PAPER_CAPABILITY_CONTRACT_VERSION
    profile_id: str = ALPACA_PAPER_CAPABILITY_PROFILE_ID
    reviewed_on: str = ALPACA_PAPER_CAPABILITY_REVIEWED_ON
    environment: str = "paper"
    trading_base_url: str = ALPACA_PAPER_TRADING_BASE_URL
    trading_websocket_url: str = ALPACA_PAPER_TRADING_WEBSOCKET_URL
    create_order_path: str = ALPACA_CREATE_ORDER_PATH
    order_by_client_id_path: str = ALPACA_ORDER_BY_CLIENT_ID_PATH
    account_path: str = ALPACA_ACCOUNT_PATH
    positions_path: str = ALPACA_POSITIONS_PATH
    orders_path: str = ALPACA_ORDERS_PATH
    account_activities_path: str = ALPACA_ACCOUNT_ACTIVITIES_PATH
    auth_header_names: tuple[str, ...] = ALPACA_AUTH_HEADER_NAMES
    asset_class: str = "us_equity"
    candidate_instrument_symbols: tuple[tuple[str, str], ...] = ALPACA_PAPER_CANDIDATE_INSTRUMENTS
    provider_order_types: tuple[str, ...] = ALPACA_DOCUMENTED_EQUITY_ORDER_TYPES
    provider_time_in_force: tuple[str, ...] = ALPACA_DOCUMENTED_EQUITY_TIME_IN_FORCE
    provider_order_classes: tuple[str, ...] = ALPACA_DOCUMENTED_EQUITY_ORDER_CLASSES
    provider_order_statuses: tuple[str, ...] = tuple(status.value for status in AlpacaOrderStatus)
    enabled_order_types: tuple[str, ...] = ("market",)
    enabled_time_in_force: tuple[str, ...] = ("day",)
    enabled_order_classes: tuple[str, ...] = ("simple",)
    required_dispatch_session: str = "exchange_regular_session"
    extended_hours_enabled: bool = False
    whole_share_only: bool = True
    fractional_quantity_enabled: bool = False
    notional_quantity_enabled: bool = False
    buy_shape_enabled: bool = True
    sell_shape_enabled: bool = True
    reduce_only_required_at_dispatch: bool = True
    short_exposure_authorized: bool = False
    price_fields_enabled: bool = False
    replacement_enabled: bool = False
    maximum_client_order_id_length: int = ALPACA_PAPER_MAX_CLIENT_ORDER_ID_LENGTH
    orders_default_page_limit: int = ALPACA_ORDERS_DEFAULT_PAGE_LIMIT
    orders_max_page_limit: int = ALPACA_ORDERS_MAX_PAGE_LIMIT
    orders_status_filters: tuple[str, ...] = ("all", "closed", "open")
    orders_time_cursor_fields: tuple[str, ...] = ("after", "until")
    orders_order_id_cursor_fields: tuple[str, ...] = ("after_order_id", "before_order_id")
    orders_directions: tuple[str, ...] = ("asc", "desc")
    orders_order_id_cursors_mutually_exclusive: bool = True
    orders_cursor_families_mutually_exclusive: bool = True
    activities_min_page_size: int = ALPACA_ACTIVITIES_MIN_PAGE_SIZE
    activities_default_page_size: int = ALPACA_ACTIVITIES_DEFAULT_PAGE_SIZE
    activities_max_page_size: int = ALPACA_ACTIVITIES_MAX_PAGE_SIZE
    activities_page_token_field: str = "page_token"
    activities_page_token_semantics: str = "last_activity_id"
    activities_directions: tuple[str, ...] = ("asc", "desc")
    documented_trading_requests_per_minute: int = ALPACA_DOCUMENTED_TRADING_REQUESTS_PER_MINUTE
    selected_market_data_feed: str | None = None
    offline_contract_only: bool = True
    credential_resolution_ready: bool = False
    request_budget_enforced: bool = False
    transport_submission_ready: bool = False
    transport_cancellation_ready: bool = False
    client_order_id_lookup_ready: bool = False
    order_snapshot_pagination_ready: bool = False
    activity_snapshot_pagination_ready: bool = False
    trade_update_stream_ready: bool = False
    inbox_deduplication_ready: bool = False
    reconciliation_ready: bool = False
    market_data_feed_ready: bool = False
    exchange_calendar_binding_ready: bool = False
    session_validation_ready: bool = False
    security_mapping_ready: bool = False
    asset_tradability_validation_ready: bool = False
    reduce_only_validation_ready: bool = False
    coordinator_dispatch_ready: bool = False
    paper_startup_ready: bool = False
    live_startup_ready: bool = False

    def __post_init__(self) -> None:
        expected_values: tuple[tuple[str, object], ...] = (
            ("contract_version", ALPACA_PAPER_CAPABILITY_CONTRACT_VERSION),
            ("profile_id", ALPACA_PAPER_CAPABILITY_PROFILE_ID),
            ("reviewed_on", ALPACA_PAPER_CAPABILITY_REVIEWED_ON),
            ("environment", "paper"),
            ("trading_base_url", ALPACA_PAPER_TRADING_BASE_URL),
            ("trading_websocket_url", ALPACA_PAPER_TRADING_WEBSOCKET_URL),
            ("create_order_path", ALPACA_CREATE_ORDER_PATH),
            ("order_by_client_id_path", ALPACA_ORDER_BY_CLIENT_ID_PATH),
            ("account_path", ALPACA_ACCOUNT_PATH),
            ("positions_path", ALPACA_POSITIONS_PATH),
            ("orders_path", ALPACA_ORDERS_PATH),
            ("account_activities_path", ALPACA_ACCOUNT_ACTIVITIES_PATH),
            ("auth_header_names", ALPACA_AUTH_HEADER_NAMES),
            ("asset_class", "us_equity"),
            (
                "candidate_instrument_symbols",
                ALPACA_PAPER_CANDIDATE_INSTRUMENTS,
            ),
            ("provider_order_types", ALPACA_DOCUMENTED_EQUITY_ORDER_TYPES),
            ("provider_time_in_force", ALPACA_DOCUMENTED_EQUITY_TIME_IN_FORCE),
            ("provider_order_classes", ALPACA_DOCUMENTED_EQUITY_ORDER_CLASSES),
            (
                "provider_order_statuses",
                tuple(status.value for status in AlpacaOrderStatus),
            ),
            ("enabled_order_types", ("market",)),
            ("enabled_time_in_force", ("day",)),
            ("enabled_order_classes", ("simple",)),
            ("required_dispatch_session", "exchange_regular_session"),
            ("extended_hours_enabled", False),
            ("whole_share_only", True),
            ("fractional_quantity_enabled", False),
            ("notional_quantity_enabled", False),
            ("buy_shape_enabled", True),
            ("sell_shape_enabled", True),
            ("reduce_only_required_at_dispatch", True),
            ("short_exposure_authorized", False),
            ("price_fields_enabled", False),
            ("replacement_enabled", False),
            ("maximum_client_order_id_length", ALPACA_PAPER_MAX_CLIENT_ORDER_ID_LENGTH),
            ("orders_default_page_limit", ALPACA_ORDERS_DEFAULT_PAGE_LIMIT),
            ("orders_max_page_limit", ALPACA_ORDERS_MAX_PAGE_LIMIT),
            ("orders_status_filters", ("all", "closed", "open")),
            ("orders_time_cursor_fields", ("after", "until")),
            (
                "orders_order_id_cursor_fields",
                ("after_order_id", "before_order_id"),
            ),
            ("orders_directions", ("asc", "desc")),
            ("orders_order_id_cursors_mutually_exclusive", True),
            ("orders_cursor_families_mutually_exclusive", True),
            ("activities_min_page_size", ALPACA_ACTIVITIES_MIN_PAGE_SIZE),
            (
                "activities_default_page_size",
                ALPACA_ACTIVITIES_DEFAULT_PAGE_SIZE,
            ),
            ("activities_max_page_size", ALPACA_ACTIVITIES_MAX_PAGE_SIZE),
            ("activities_page_token_field", "page_token"),
            ("activities_page_token_semantics", "last_activity_id"),
            ("activities_directions", ("asc", "desc")),
            (
                "documented_trading_requests_per_minute",
                ALPACA_DOCUMENTED_TRADING_REQUESTS_PER_MINUTE,
            ),
            ("selected_market_data_feed", None),
            ("offline_contract_only", True),
            *(tuple((field_name, False) for field_name in _RUNTIME_READINESS_FIELDS)),
        )
        for field_name, expected in expected_values:
            actual = getattr(self, field_name)
            if type(actual) is not type(expected) or actual != expected:
                raise AlpacaPaperContractError(
                    f"Alpaca paper capability field {field_name!r} was altered"
                )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_CAPABILITY_CONTRACT_VERSION,
            "capability_matrix",
            self.contract_version,
            self.profile_id,
            self.reviewed_on,
            self.environment,
            self.trading_base_url,
            self.trading_websocket_url,
            self.create_order_path,
            self.order_by_client_id_path,
            self.account_path,
            self.positions_path,
            self.orders_path,
            self.account_activities_path,
            self.auth_header_names,
            self.asset_class,
            self.candidate_instrument_symbols,
            self.provider_order_types,
            self.provider_time_in_force,
            self.provider_order_classes,
            self.provider_order_statuses,
            self.enabled_order_types,
            self.enabled_time_in_force,
            self.enabled_order_classes,
            self.required_dispatch_session,
            self.extended_hours_enabled,
            self.whole_share_only,
            self.fractional_quantity_enabled,
            self.notional_quantity_enabled,
            self.buy_shape_enabled,
            self.sell_shape_enabled,
            self.reduce_only_required_at_dispatch,
            self.short_exposure_authorized,
            self.price_fields_enabled,
            self.replacement_enabled,
            self.maximum_client_order_id_length,
            self.orders_default_page_limit,
            self.orders_max_page_limit,
            self.orders_status_filters,
            self.orders_time_cursor_fields,
            self.orders_order_id_cursor_fields,
            self.orders_directions,
            self.orders_order_id_cursors_mutually_exclusive,
            self.orders_cursor_families_mutually_exclusive,
            self.activities_min_page_size,
            self.activities_default_page_size,
            self.activities_max_page_size,
            self.activities_page_token_field,
            self.activities_page_token_semantics,
            self.activities_directions,
            self.documented_trading_requests_per_minute,
            self.selected_market_data_feed,
            self.offline_contract_only,
            tuple(
                (field_name, cast(bool, getattr(self, field_name)))
                for field_name in _RUNTIME_READINESS_FIELDS
            ),
        )

    @property
    def runtime_readiness(self) -> Mapping[str, bool]:
        return MappingProxyType(
            {
                field_name: cast(bool, getattr(self, field_name))
                for field_name in _RUNTIME_READINESS_FIELDS
            }
        )

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self._semantic_material())).hexdigest()

    @property
    def trading_effect_authorized(self) -> bool:
        return False


ALPACA_PAPER_CAPABILITIES = AlpacaPaperCapabilityMatrix()


def _quantity_text(intent: OrderIntent) -> str:
    quantity = canonical_decimal(intent.quantity)
    if quantity <= 0 or quantity != quantity.to_integral_value():
        raise AlpacaPaperContractError("Alpaca paper v1 requires a positive whole-share quantity")
    return format(quantity, "f")


def _validate_instrument(intent: OrderIntent) -> None:
    candidates = dict(ALPACA_PAPER_CANDIDATE_INSTRUMENTS)
    expected_symbol = candidates.get(intent.instrument_id)
    if expected_symbol is None:
        raise AlpacaPaperContractError(
            "instrument is outside the Alpaca paper v1 candidate translation map: "
            f"{intent.instrument_id!r}"
        )
    if intent.symbol != expected_symbol:
        raise AlpacaPaperContractError(
            "Alpaca paper instrument and symbol do not match the candidate translation map"
        )


def create_alpaca_paper_submission_request(intent: OrderIntent) -> BrokerSubmissionRequest:
    """Compile one exact intent into immutable, non-dispatching adapter evidence."""

    if type(intent) is not OrderIntent:
        raise AlpacaPaperContractError("Alpaca paper translation requires an exact OrderIntent")
    intent.__post_init__()
    _validate_instrument(intent)
    return create_broker_submission_request(
        intent=intent,
        adapter_id=ALPACA_PAPER_ADAPTER_ID,
        adapter_version=ALPACA_PAPER_ADAPTER_VERSION,
        operation="submit_order",
        payload={
            "capability_sha256": ALPACA_PAPER_CAPABILITIES.semantic_sha256,
            "contract_version": ALPACA_PAPER_CAPABILITY_CONTRACT_VERSION,
            "extended_hours": False,
            "instrument_id": intent.instrument_id,
            "qty": _quantity_text(intent),
            "required_asset_class": "us_equity",
            "required_dispatch_session": "exchange_regular_session",
            "required_order_class": "simple",
            "side": intent.side.value,
            "symbol": intent.symbol,
            "time_in_force": "day",
            "type": "market",
        },
    )


def _validate_submission_request(request: BrokerSubmissionRequest) -> None:
    if type(request) is not BrokerSubmissionRequest:
        raise AlpacaPaperContractError(
            "Alpaca paper description requires an exact BrokerSubmissionRequest"
        )
    if request.adapter_id != ALPACA_PAPER_ADAPTER_ID:
        raise AlpacaPaperContractError("Alpaca paper request adapter ID was altered")
    if request.adapter_version != ALPACA_PAPER_ADAPTER_VERSION:
        raise AlpacaPaperContractError("Alpaca paper request adapter version was altered")
    if request.operation != "submit_order":
        raise AlpacaPaperContractError("Alpaca paper request operation was altered")
    expected_client_order_id = f"aqt-{request.order_id.replace('-', '')[:24]}"
    if request.client_order_id != expected_client_order_id:
        raise AlpacaPaperContractError("Alpaca paper deterministic client order ID drifted")
    if len(request.client_order_id) > ALPACA_PAPER_MAX_CLIENT_ORDER_ID_LENGTH:
        raise AlpacaPaperContractError("Alpaca paper client order ID exceeds provider limit")
    if any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789-"
        for character in request.client_order_id
    ):
        raise AlpacaPaperContractError("Alpaca paper client order ID contains unsupported text")

    payload = request.payload
    expected_keys = frozenset((*_ALPACA_REQUEST_METADATA_KEYS, *_ALPACA_ORDER_BODY_KEYS))
    if frozenset(payload) != expected_keys:
        raise AlpacaPaperContractError("Alpaca paper request payload shape was altered")
    expected_metadata: Mapping[str, object] = {
        "capability_sha256": ALPACA_PAPER_CAPABILITIES.semantic_sha256,
        "contract_version": ALPACA_PAPER_CAPABILITY_CONTRACT_VERSION,
        "required_asset_class": "us_equity",
        "required_dispatch_session": "exchange_regular_session",
        "required_order_class": "simple",
        "extended_hours": False,
        "time_in_force": "day",
        "type": "market",
    }
    for key, expected in expected_metadata.items():
        value = payload[key]
        if type(value) is not type(expected) or value != expected:
            raise AlpacaPaperContractError(f"Alpaca paper request field {key!r} was altered")
    if payload["side"] not in ("buy", "sell") or type(payload["side"]) is not str:
        raise AlpacaPaperContractError("Alpaca paper request side is unsupported")
    instrument_id = payload["instrument_id"]
    symbol = payload["symbol"]
    if type(instrument_id) is not str or type(symbol) is not str:
        raise AlpacaPaperContractError("Alpaca paper request instrument identity is malformed")
    expected_symbol = dict(ALPACA_PAPER_CANDIDATE_INSTRUMENTS).get(instrument_id)
    if expected_symbol is None or symbol != expected_symbol:
        raise AlpacaPaperContractError("Alpaca paper request symbol is unsupported")
    quantity_text = payload["qty"]
    if (
        type(quantity_text) is not str
        or not quantity_text.isascii()
        or not quantity_text.isdecimal()
        or quantity_text.startswith("0")
    ):
        raise AlpacaPaperContractError(
            "Alpaca paper request quantity must be a canonical positive whole-share string"
        )


@dataclass(frozen=True, slots=True)
class AlpacaPaperSubmissionDescription:
    """Exact endpoint/body evidence that is never sufficient transport authority.

    A future transport must require a durable submission preparation and a fresh
    dispatch fence in addition to revalidating this intent-bound description.
    """

    intent: OrderIntent
    request: BrokerSubmissionRequest
    capability_sha256: str

    def __post_init__(self) -> None:
        if type(self.intent) is not OrderIntent:
            raise AlpacaPaperContractError("Alpaca paper description requires an exact OrderIntent")
        self.intent.__post_init__()
        _validate_submission_request(self.request)
        expected_request = create_alpaca_paper_submission_request(self.intent)
        if self.request != expected_request:
            raise AlpacaPaperContractError(
                "Alpaca paper request is not bound to the exact canonical intent"
            )
        if (
            type(self.capability_sha256) is not str
            or self.capability_sha256 != ALPACA_PAPER_CAPABILITIES.semantic_sha256
        ):
            raise AlpacaPaperContractError("Alpaca paper description capability digest was altered")

    @property
    def method(self) -> str:
        return "POST"

    @property
    def base_url(self) -> str:
        return ALPACA_PAPER_TRADING_BASE_URL

    @property
    def path(self) -> str:
        return ALPACA_CREATE_ORDER_PATH

    @property
    def url(self) -> str:
        return f"{self.base_url}{self.path}"

    @property
    def body(self) -> Mapping[str, AlpacaOrderBodyValue]:
        payload = self.request.payload
        return MappingProxyType(
            {
                "client_order_id": self.request.client_order_id,
                "extended_hours": cast(bool, payload["extended_hours"]),
                "qty": cast(str, payload["qty"]),
                "side": cast(str, payload["side"]),
                "symbol": cast(str, payload["symbol"]),
                "time_in_force": cast(str, payload["time_in_force"]),
                "type": cast(str, payload["type"]),
            }
        )

    def to_json_bytes(self) -> bytes:
        """Return deterministic provider JSON without performing transport I/O."""

        return json.dumps(
            dict(self.body),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @property
    def semantic_sha256(self) -> str:
        material = (
            ALPACA_PAPER_CAPABILITY_CONTRACT_VERSION,
            "submission_description",
            self.capability_sha256,
            self.intent.semantic_sha256,
            self.request.semantic_sha256,
            self.method,
            self.base_url,
            self.path,
            tuple(sorted(self.body.items())),
        )
        return hashlib.sha256(canonical_json_bytes(material)).hexdigest()

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def create_alpaca_paper_submission_description(
    intent: OrderIntent,
) -> AlpacaPaperSubmissionDescription:
    """Describe the exact paper request while granting no dispatch authority."""

    return AlpacaPaperSubmissionDescription(
        intent=intent,
        request=create_alpaca_paper_submission_request(intent),
        capability_sha256=ALPACA_PAPER_CAPABILITIES.semantic_sha256,
    )
