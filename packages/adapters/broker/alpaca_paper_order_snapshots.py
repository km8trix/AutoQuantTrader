"""Bounded, raw-first Alpaca paper order snapshot pages.

The Trading API order list is paginated with an order-ID cursor but does not
offer snapshot isolation.  This module therefore retains each page before
decoding, validates one bounded descending page chain, and deliberately
withholds every lifecycle, execution, reconciliation, and trading authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from itertools import pairwise
from types import MappingProxyType
from typing import Any, cast
from uuid import UUID

from packages.adapters.broker.alpaca_paper import (
    ALPACA_ORDERS_MAX_PAGE_LIMIT,
    ALPACA_ORDERS_PATH,
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
from packages.adapters.broker.alpaca_paper_observations import (
    AlpacaOrderObservation,
    AlpacaPaperObservationError,
    decode_alpaca_order_observation_object,
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
from packages.domain.canonical import canonical_json_bytes
from packages.domain.identifiers import canonical_id
from packages.domain.models import require_utc

ALPACA_PAPER_ORDER_SNAPSHOT_CONTRACT_VERSION = "phase4m-bounded-raw-first-order-snapshot-v1"
ALPACA_PAPER_ORDER_SNAPSHOT_MAX_PAGES = 8
ALPACA_PAPER_ORDER_SNAPSHOT_MAX_RESPONSE_BYTES = MAX_BROKER_INGRESS_BODY_BYTES
ALPACA_PAPER_ORDER_SNAPSHOT_INGRESS_CHANNEL = "rest_order_snapshot_response"
ALPACA_PAPER_ORDER_SNAPSHOT_INGRESS_OPERATION = "get_all_orders_page"

_SAFE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AlpacaPaperOrderSnapshotError(AlpacaPaperContractError):
    """A bounded order snapshot page or chain violates the frozen contract."""


class _NoOrderSnapshotAuthority:
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
    def converged(self) -> bool:
        return False

    @property
    def provider_revision_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_authorized(self) -> bool:
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
    def reconciliation_complete(self) -> bool:
        return False

    @property
    def unknown_resolution_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def reservation_release_authorized(self) -> bool:
        return False

    @property
    def resubmission_authorized(self) -> bool:
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
        raise AlpacaPaperOrderSnapshotError(
            f"{field_name} must be bounded, trimmed text without control characters"
        )
    return value


def _require_safe_key(value: object, field_name: str) -> str:
    if type(value) is not str or _SAFE_KEY.fullmatch(value) is None:
        raise AlpacaPaperOrderSnapshotError(
            f"{field_name} must contain 8-128 safe visible characters"
        )
    return value


def _require_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AlpacaPaperOrderSnapshotError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_uuid(value: object, field_name: str) -> str:
    raw = _require_text(value, field_name, maximum=36)
    try:
        parsed = UUID(raw)
    except ValueError as error:
        raise AlpacaPaperOrderSnapshotError(f"{field_name} must be a canonical UUID") from error
    if str(parsed) != raw:
        raise AlpacaPaperOrderSnapshotError(f"{field_name} must be a canonical lowercase UUID")
    return raw


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperOrderSnapshotError(f"{field_name} must be an exact datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperOrderSnapshotError(str(error)) from error
    return value


@dataclass(frozen=True, slots=True)
class AlpacaPaperOrderSnapshotPlan(_NoOrderSnapshotAuthority):
    """One deterministic, bounded descending traversal description."""

    account_id: str
    capture_idempotency_key: str
    page_limit: int = ALPACA_ORDERS_MAX_PAGE_LIMIT
    maximum_pages: int = ALPACA_PAPER_ORDER_SNAPSHOT_MAX_PAGES

    def __post_init__(self) -> None:
        _require_text(self.account_id, "order snapshot account ID", maximum=64)
        _require_safe_key(
            self.capture_idempotency_key,
            "order snapshot capture idempotency key",
        )
        if (
            type(self.page_limit) is not int
            or not 1 <= self.page_limit <= ALPACA_ORDERS_MAX_PAGE_LIMIT
        ):
            raise AlpacaPaperOrderSnapshotError(
                "order snapshot page limit is outside the reviewed provider bound"
            )
        if (
            type(self.maximum_pages) is not int
            or not 1 <= self.maximum_pages <= ALPACA_PAPER_ORDER_SNAPSHOT_MAX_PAGES
        ):
            raise AlpacaPaperOrderSnapshotError(
                "order snapshot maximum pages is outside the local safety bound"
            )
        ALPACA_PAPER_CAPABILITIES.__post_init__()

    @property
    def snapshot_id(self) -> str:
        return canonical_id(
            "alpaca-paper-order-snapshot",
            self.account_id,
            self.capture_idempotency_key,
        )

    @property
    def budget_purpose(self) -> BrokerRequestPurpose:
        return BrokerRequestPurpose.RECONCILIATION

    @property
    def maximum_request_count(self) -> int:
        return self.maximum_pages

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_ORDER_SNAPSHOT_CONTRACT_VERSION,
            "snapshot_plan",
            self.snapshot_id,
            self.account_id,
            self.capture_idempotency_key,
            ALPACA_PAPER_CAPABILITIES.semantic_sha256,
            self.page_limit,
            self.maximum_pages,
            "all",
            "desc",
            False,
            "us_equity",
            "before_order_id",
            self.budget_purpose,
            self.snapshot_isolation_qualified,
        )

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class AlpacaPaperOrderSnapshotPageDescription(_NoOrderSnapshotAuthority):
    """One exact page request in a predecessor-bound traversal."""

    plan: AlpacaPaperOrderSnapshotPlan
    page_number: int
    before_order_id: str | None
    previous_page_sha256: str | None

    def __post_init__(self) -> None:
        if type(self.plan) is not AlpacaPaperOrderSnapshotPlan:
            raise AlpacaPaperOrderSnapshotError(
                "order snapshot page requires an exact snapshot plan"
            )
        self.plan.__post_init__()
        if (
            type(self.page_number) is not int
            or not 1 <= self.page_number <= self.plan.maximum_pages
        ):
            raise AlpacaPaperOrderSnapshotError("order snapshot page number is outside the plan")
        if self.page_number == 1:
            if self.before_order_id is not None or self.previous_page_sha256 is not None:
                raise AlpacaPaperOrderSnapshotError(
                    "first order snapshot page cannot name a cursor or predecessor"
                )
        else:
            _require_uuid(
                self.before_order_id,
                "order snapshot before_order_id",
            )
            _require_sha256(
                self.previous_page_sha256,
                "order snapshot previous page digest",
            )

    @property
    def method(self) -> str:
        return "GET"

    @property
    def base_url(self) -> str:
        return ALPACA_PAPER_TRADING_BASE_URL

    @property
    def path(self) -> str:
        return ALPACA_ORDERS_PATH

    @property
    def query(self) -> Mapping[str, str]:
        values = {
            "asset_class": "us_equity",
            "direction": "desc",
            "limit": str(self.plan.page_limit),
            "nested": "false",
            "status": "all",
        }
        if self.before_order_id is not None:
            values["before_order_id"] = self.before_order_id
        return MappingProxyType(values)

    @property
    def request_target(self) -> str:
        ordered = (
            ("status", "all"),
            ("limit", str(self.plan.page_limit)),
            ("direction", "desc"),
            ("nested", "false"),
            ("asset_class", "us_equity"),
        )
        pairs = list(ordered)
        if self.before_order_id is not None:
            pairs.append(("before_order_id", self.before_order_id))
        return f"{self.path}?" + "&".join(f"{key}={value}" for key, value in pairs)

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_ORDER_SNAPSHOT_CONTRACT_VERSION,
            "snapshot_page_description",
            self.plan.semantic_sha256,
            self.page_number,
            self.before_order_id,
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


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AlpacaPaperOrderSnapshotError(
                f"order snapshot response contains duplicate JSON key {key!r}"
            )
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise AlpacaPaperOrderSnapshotError(
        f"order snapshot response contains non-standard JSON constant {value!r}"
    )


def _decode_order_array(response_body: bytes) -> tuple[AlpacaOrderObservation, ...]:
    if type(response_body) is not bytes:
        raise AlpacaPaperOrderSnapshotError("order snapshot response must be exact bytes")
    if not 1 <= len(response_body) <= ALPACA_PAPER_ORDER_SNAPSHOT_MAX_RESPONSE_BYTES:
        raise AlpacaPaperOrderSnapshotError(
            "order snapshot response size is outside the durable ingress bound"
        )
    try:
        text = response_body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AlpacaPaperOrderSnapshotError("order snapshot response must be UTF-8") from error
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except AlpacaPaperOrderSnapshotError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as error:
        raise AlpacaPaperOrderSnapshotError("order snapshot response is invalid JSON") from error
    if type(decoded) is not list:
        raise AlpacaPaperOrderSnapshotError("order snapshot response must be one JSON array")
    result: list[AlpacaOrderObservation] = []
    for position, value in enumerate(decoded):
        if type(value) is not dict:
            raise AlpacaPaperOrderSnapshotError(
                f"order snapshot item {position} must be one JSON object"
            )
        try:
            result.append(decode_alpaca_order_observation_object(cast(dict[str, Any], value)))
        except AlpacaPaperObservationError as error:
            raise AlpacaPaperOrderSnapshotError(
                f"order snapshot item {position} is outside the frozen order profile"
            ) from error
    return tuple(result)


def _submitted_instant(order: AlpacaOrderObservation) -> tuple[datetime, int]:
    if order.submitted_at is None:
        raise AlpacaPaperOrderSnapshotError(
            "order snapshot pagination requires a provider submitted_at value"
        )
    return order.submitted_at.utc_second, order.submitted_at.nanosecond


@dataclass(frozen=True, slots=True)
class AlpacaPaperOrderSnapshotPageObservation(_NoOrderSnapshotAuthority):
    """One exact retained order-list page with no application authority."""

    description: AlpacaPaperOrderSnapshotPageDescription
    http_status: int
    provider_request_id: str
    received_at: datetime
    response_body: bytes = field(repr=False)
    orders: tuple[AlpacaOrderObservation, ...]

    def __post_init__(self) -> None:
        if type(self.description) is not AlpacaPaperOrderSnapshotPageDescription:
            raise AlpacaPaperOrderSnapshotError(
                "order snapshot observation requires an exact page description"
            )
        self.description.__post_init__()
        if type(self.http_status) is not int or self.http_status != 200:
            raise AlpacaPaperOrderSnapshotError("order snapshot decoding supports only HTTP 200")
        _require_text(
            self.provider_request_id,
            "order snapshot X-Request-ID",
            maximum=256,
        )
        _require_utc(self.received_at, "order snapshot received_at")
        if type(self.orders) is not tuple or any(
            type(order) is not AlpacaOrderObservation for order in self.orders
        ):
            raise AlpacaPaperOrderSnapshotError("order snapshot orders must be an exact tuple")
        if len(self.orders) > self.description.plan.page_limit:
            raise AlpacaPaperOrderSnapshotError(
                "order snapshot page exceeds its requested item limit"
            )
        decoded = _decode_order_array(self.response_body)
        if decoded != self.orders:
            raise AlpacaPaperOrderSnapshotError(
                "order snapshot observations conflict with exact response bytes"
            )
        if any(order.asset_class != "us_equity" for order in self.orders):
            raise AlpacaPaperOrderSnapshotError(
                "order snapshot item conflicts with the fixed us_equity request"
            )
        provider_ids = tuple(order.provider_order_id for order in self.orders)
        if len(set(provider_ids)) != len(provider_ids):
            raise AlpacaPaperOrderSnapshotError("order snapshot page repeats a provider order ID")
        instants = tuple(_submitted_instant(order) for order in self.orders)
        if any(later > earlier for earlier, later in pairwise(instants)):
            raise AlpacaPaperOrderSnapshotError(
                "order snapshot page is not in descending submission order"
            )

    @property
    def response_size_bytes(self) -> int:
        return len(self.response_body)

    @property
    def response_sha256(self) -> str:
        return hashlib.sha256(self.response_body).hexdigest()

    @property
    def terminal_page(self) -> bool:
        return len(self.orders) < self.description.plan.page_limit

    @property
    def next_before_order_id(self) -> str | None:
        if self.terminal_page:
            return None
        return self.orders[-1].provider_order_id

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_ORDER_SNAPSHOT_CONTRACT_VERSION,
            "snapshot_page_observation",
            self.description.semantic_sha256,
            self.http_status,
            self.provider_request_id,
            self.received_at,
            self.response_size_bytes,
            self.response_sha256,
            tuple(order.semantic_sha256 for order in self.orders),
            self.terminal_page,
            self.next_before_order_id,
        )

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(self._semantic_material())


def decode_alpaca_paper_order_snapshot_page(
    description: AlpacaPaperOrderSnapshotPageDescription,
    *,
    http_status: int,
    provider_request_id: str,
    response_body: bytes,
    received_at: datetime,
) -> AlpacaPaperOrderSnapshotPageObservation:
    """Decode one retained page without granting provider-fact authority."""

    if type(description) is not AlpacaPaperOrderSnapshotPageDescription:
        raise AlpacaPaperOrderSnapshotError(
            "order snapshot decoding requires an exact page description"
        )
    orders = _decode_order_array(response_body)
    return AlpacaPaperOrderSnapshotPageObservation(
        description=description,
        http_status=http_status,
        provider_request_id=provider_request_id,
        received_at=received_at,
        response_body=response_body,
        orders=orders,
    )


@dataclass(frozen=True, slots=True)
class PersistedAlpacaPaperOrderSnapshotPage(_NoOrderSnapshotAuthority):
    """A decoded order page bound to bytes committed before decoding."""

    receipt: BrokerIngressReceipt
    observation: AlpacaPaperOrderSnapshotPageObservation

    def __post_init__(self) -> None:
        if type(self.receipt) is not BrokerIngressReceipt:
            raise AlpacaPaperOrderSnapshotError(
                "persisted order snapshot page requires an exact ingress receipt"
            )
        if type(self.observation) is not AlpacaPaperOrderSnapshotPageObservation:
            raise AlpacaPaperOrderSnapshotError(
                "persisted order snapshot page requires an exact observation"
            )
        self.receipt.__post_init__()
        self.observation.__post_init__()
        delivery = self.receipt.delivery
        observation = self.observation
        expected = (
            (delivery.account_id, observation.description.plan.account_id),
            (delivery.provider_id, ALPACA_PAPER_ADAPTER_ID),
            (delivery.adapter_version, ALPACA_PAPER_ADAPTER_VERSION),
            (delivery.environment, "paper"),
            (delivery.channel, ALPACA_PAPER_ORDER_SNAPSHOT_INGRESS_CHANNEL),
            (delivery.operation, ALPACA_PAPER_ORDER_SNAPSHOT_INGRESS_OPERATION),
            (delivery.correlation_sha256, observation.description.semantic_sha256),
            (delivery.transport_status, observation.http_status),
            (delivery.provider_request_id, observation.provider_request_id),
            (delivery.received_at, observation.received_at),
            (delivery.body, observation.response_body),
        )
        if any(actual != wanted for actual, wanted in expected):
            raise AlpacaPaperOrderSnapshotError(
                "decoded order snapshot page conflicts with its raw receipt"
            )

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(
            (
                ALPACA_PAPER_ORDER_SNAPSHOT_CONTRACT_VERSION,
                "persisted_snapshot_page",
                self.receipt.semantic_sha256,
                self.observation.semantic_sha256,
            )
        )


def persist_then_decode_alpaca_paper_order_snapshot_page(
    recorder: BrokerIngressRecorder,
    description: AlpacaPaperOrderSnapshotPageDescription,
    *,
    delivery_idempotency_key: str,
    http_status: int,
    provider_request_id: str | None,
    response_body: bytes,
    received_at: datetime,
    recorded_at: datetime,
    media_type: str | None = "application/json",
) -> PersistedAlpacaPaperOrderSnapshotPage:
    """Commit one exact page before invoking its strict offline decoder."""

    if not callable(getattr(recorder, "record", None)):
        raise BrokerIngressError("Alpaca order snapshot ingress requires a durable recorder")
    if type(description) is not AlpacaPaperOrderSnapshotPageDescription:
        raise AlpacaPaperOrderSnapshotError(
            "Alpaca order snapshot ingress requires an exact page description"
        )
    description.__post_init__()
    delivery = BrokerIngressDelivery(
        account_id=description.plan.account_id,
        delivery_idempotency_key=delivery_idempotency_key,
        provider_id=ALPACA_PAPER_ADAPTER_ID,
        adapter_version=ALPACA_PAPER_ADAPTER_VERSION,
        environment="paper",
        channel=ALPACA_PAPER_ORDER_SNAPSHOT_INGRESS_CHANNEL,
        operation=ALPACA_PAPER_ORDER_SNAPSHOT_INGRESS_OPERATION,
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
            "durable recorder returned an invalid order snapshot ingress receipt"
        )
    receipt.__post_init__()
    if receipt.delivery != delivery:
        raise BrokerIngressError(
            "durable recorder returned a receipt for different order snapshot bytes"
        )
    if provider_request_id is None:
        raise AlpacaPaperOrderSnapshotError(
            "order snapshot response is missing X-Request-ID after raw persistence"
        )
    observation = decode_alpaca_paper_order_snapshot_page(
        description,
        http_status=http_status,
        provider_request_id=provider_request_id,
        response_body=response_body,
        received_at=received_at,
    )
    return PersistedAlpacaPaperOrderSnapshotPage(
        receipt=receipt,
        observation=observation,
    )


def _first_page_description(
    plan: AlpacaPaperOrderSnapshotPlan,
) -> AlpacaPaperOrderSnapshotPageDescription:
    return AlpacaPaperOrderSnapshotPageDescription(
        plan=plan,
        page_number=1,
        before_order_id=None,
        previous_page_sha256=None,
    )


def _next_page_description(
    page: PersistedAlpacaPaperOrderSnapshotPage,
) -> AlpacaPaperOrderSnapshotPageDescription:
    cursor = page.observation.next_before_order_id
    if cursor is None:
        raise AlpacaPaperOrderSnapshotError("terminal order snapshot page has no continuation")
    return AlpacaPaperOrderSnapshotPageDescription(
        plan=page.observation.description.plan,
        page_number=page.observation.description.page_number + 1,
        before_order_id=cursor,
        previous_page_sha256=page.semantic_sha256,
    )


@dataclass(frozen=True, slots=True)
class AlpacaPaperOrderSnapshotCapture(_NoOrderSnapshotAuthority):
    """One bounded raw-first page chain, never an isolated provider snapshot."""

    plan: AlpacaPaperOrderSnapshotPlan
    pages: tuple[PersistedAlpacaPaperOrderSnapshotPage, ...] = ()

    def __post_init__(self) -> None:
        if type(self.plan) is not AlpacaPaperOrderSnapshotPlan:
            raise AlpacaPaperOrderSnapshotError("order snapshot capture requires an exact plan")
        self.plan.__post_init__()
        if type(self.pages) is not tuple or any(
            type(page) is not PersistedAlpacaPaperOrderSnapshotPage for page in self.pages
        ):
            raise AlpacaPaperOrderSnapshotError(
                "order snapshot capture pages must be an exact tuple"
            )
        if len(self.pages) > self.plan.maximum_pages:
            raise AlpacaPaperOrderSnapshotError("order snapshot capture exceeds its page bound")
        seen_provider_ids: set[str] = set()
        previous: PersistedAlpacaPaperOrderSnapshotPage | None = None
        for page_number, page in enumerate(self.pages, start=1):
            page.__post_init__()
            expected = (
                _first_page_description(self.plan)
                if previous is None
                else _next_page_description(previous)
            )
            if page.observation.description != expected:
                raise AlpacaPaperOrderSnapshotError(
                    "order snapshot page conflicts with its exact predecessor"
                )
            if page.observation.description.page_number != page_number:
                raise AlpacaPaperOrderSnapshotError("order snapshot page chain is not gap-free")
            if previous is not None:
                if previous.observation.terminal_page:
                    raise AlpacaPaperOrderSnapshotError(
                        "order snapshot capture continues after a terminal page"
                    )
                if page.receipt.ingress_sequence <= previous.receipt.ingress_sequence:
                    raise AlpacaPaperOrderSnapshotError(
                        "order snapshot raw receipt sequence did not advance"
                    )
                if page.observation.received_at < previous.observation.received_at:
                    raise AlpacaPaperOrderSnapshotError("order snapshot receive time regressed")
                if page.observation.orders and (
                    _submitted_instant(page.observation.orders[0])
                    > _submitted_instant(previous.observation.orders[-1])
                ):
                    raise AlpacaPaperOrderSnapshotError(
                        "order snapshot page chain is not in descending submission order"
                    )
            provider_ids = {order.provider_order_id for order in page.observation.orders}
            if seen_provider_ids & provider_ids:
                raise AlpacaPaperOrderSnapshotError(
                    "order snapshot pages overlap despite an exclusive cursor"
                )
            seen_provider_ids.update(provider_ids)
            previous = page

    @property
    def page_count(self) -> int:
        return len(self.pages)

    @property
    def order_count(self) -> int:
        return sum(len(page.observation.orders) for page in self.pages)

    @property
    def pagination_exhausted(self) -> bool:
        return bool(self.pages and self.pages[-1].observation.terminal_page)

    @property
    def bounded_truncation(self) -> bool:
        return bool(
            len(self.pages) == self.plan.maximum_pages
            and self.pages
            and not self.pages[-1].observation.terminal_page
        )

    @property
    def next_page_description(
        self,
    ) -> AlpacaPaperOrderSnapshotPageDescription | None:
        self.__post_init__()
        if not self.pages:
            return _first_page_description(self.plan)
        if self.pagination_exhausted or self.bounded_truncation:
            return None
        return _next_page_description(self.pages[-1])

    @property
    def additional_reconciliation_required(self) -> bool:
        return True

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(
            (
                ALPACA_PAPER_ORDER_SNAPSHOT_CONTRACT_VERSION,
                "snapshot_capture",
                self.plan.semantic_sha256,
                tuple(page.semantic_sha256 for page in self.pages),
                self.pagination_exhausted,
                self.bounded_truncation,
                self.snapshot_isolation_qualified,
                self.converged,
            )
        )


def create_alpaca_paper_order_snapshot_plan(
    *,
    account_id: str,
    capture_idempotency_key: str,
    page_limit: int = ALPACA_ORDERS_MAX_PAGE_LIMIT,
    maximum_pages: int = ALPACA_PAPER_ORDER_SNAPSHOT_MAX_PAGES,
) -> AlpacaPaperOrderSnapshotPlan:
    """Create one bounded traversal plan without transport authority."""

    return AlpacaPaperOrderSnapshotPlan(
        account_id=account_id,
        capture_idempotency_key=capture_idempotency_key,
        page_limit=page_limit,
        maximum_pages=maximum_pages,
    )


def start_alpaca_paper_order_snapshot(
    plan: AlpacaPaperOrderSnapshotPlan,
) -> AlpacaPaperOrderSnapshotCapture:
    """Start an empty immutable raw-first capture."""

    return AlpacaPaperOrderSnapshotCapture(plan=plan)


def append_alpaca_paper_order_snapshot_page(
    capture: AlpacaPaperOrderSnapshotCapture,
    page: PersistedAlpacaPaperOrderSnapshotPage,
) -> AlpacaPaperOrderSnapshotCapture:
    """Append only the exact next raw-first page in the bounded chain."""

    if type(capture) is not AlpacaPaperOrderSnapshotCapture:
        raise AlpacaPaperOrderSnapshotError("order snapshot append requires an exact capture")
    if type(page) is not PersistedAlpacaPaperOrderSnapshotPage:
        raise AlpacaPaperOrderSnapshotError(
            "order snapshot append requires an exact persisted page"
        )
    capture.__post_init__()
    expected = capture.next_page_description
    if expected is None:
        raise AlpacaPaperOrderSnapshotError(
            "order snapshot capture has no remaining page authority"
        )
    if page.observation.description != expected:
        raise AlpacaPaperOrderSnapshotError(
            "order snapshot append received a different page description"
        )
    return AlpacaPaperOrderSnapshotCapture(
        plan=capture.plan,
        pages=(*capture.pages, page),
    )


def create_alpaca_paper_order_snapshot_page_demand(
    description: AlpacaPaperOrderSnapshotPageDescription,
    *,
    requested_at: datetime,
) -> BrokerRequestDemand:
    """Bind one page to a distinct reconciliation-capacity demand."""

    if type(description) is not AlpacaPaperOrderSnapshotPageDescription:
        raise AlpacaPaperOrderSnapshotError(
            "order snapshot demand requires an exact page description"
        )
    description.__post_init__()
    return create_alpaca_paper_request_demand(
        account_id=description.plan.account_id,
        idempotency_key=(
            f"order-snapshot:{description.plan.snapshot_id}:{description.page_number:02d}"
        ),
        operation=AlpacaPaperBudgetOperation.RECONCILE_ACCOUNT,
        correlation_sha256=description.semantic_sha256,
        requested_at=requested_at,
    )


__all__ = [
    "ALPACA_PAPER_ORDER_SNAPSHOT_CONTRACT_VERSION",
    "ALPACA_PAPER_ORDER_SNAPSHOT_INGRESS_CHANNEL",
    "ALPACA_PAPER_ORDER_SNAPSHOT_INGRESS_OPERATION",
    "ALPACA_PAPER_ORDER_SNAPSHOT_MAX_PAGES",
    "ALPACA_PAPER_ORDER_SNAPSHOT_MAX_RESPONSE_BYTES",
    "AlpacaPaperOrderSnapshotCapture",
    "AlpacaPaperOrderSnapshotError",
    "AlpacaPaperOrderSnapshotPageDescription",
    "AlpacaPaperOrderSnapshotPageObservation",
    "AlpacaPaperOrderSnapshotPlan",
    "PersistedAlpacaPaperOrderSnapshotPage",
    "append_alpaca_paper_order_snapshot_page",
    "create_alpaca_paper_order_snapshot_page_demand",
    "create_alpaca_paper_order_snapshot_plan",
    "decode_alpaca_paper_order_snapshot_page",
    "persist_then_decode_alpaca_paper_order_snapshot_page",
    "start_alpaca_paper_order_snapshot",
]
