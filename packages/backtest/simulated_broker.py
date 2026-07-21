"""Conservative, deterministic market-order simulation over sealed market facts."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum

from packages.domain.batch_risk import BatchRiskSession, BatchRiskSessionKind
from packages.domain.canonical import canonical_json_bytes, canonical_persisted_decimal
from packages.domain.decimal_math import (
    exact_decimal_add,
    exact_decimal_multiply,
    exact_decimal_subtract,
)
from packages.domain.identifiers import canonical_id
from packages.domain.market_batch import MarketBatch
from packages.domain.models import DecisionStatus, MarketEvent, OrderIntent, Side, require_utc
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    CanonicalOrderState,
    CanonicalOrderStatus,
    OrderSubmission,
    create_order_submission,
    reduce_order_lifecycle,
)
from packages.domain.risk import (
    ExecutableRiskAuthorization,
    RiskAuthorizationConsumer,
    intent_payload_hash,
)
from packages.market_data.calendar import ExchangeSession, SessionKind

SIMULATED_BROKER_CONTRACT_VERSION = "phase2-simulated-broker-v1"
_MISSING_AUTHORIZATION_CAP = object()


class SimulatedBrokerError(ValueError):
    """Raised when a simulated order cannot be evaluated without inventing facts."""


class SimulatedBrokerFactConflict(SimulatedBrokerError):
    """Raised when supposedly immutable simulation facts conflict."""


class SimulatedBrokerOutcome(StrEnum):
    FILLED = "filled"
    WORKING_NO_ELIGIBLE_EVENT = "working_no_eligible_event"
    WORKING_RISK_CAP_BLOCKED = "working_risk_cap_blocked"
    WORKING_DEFERRED_SOURCE_BLOCKED = "working_deferred_source_blocked"


class SimulatedRiskCapViolation(StrEnum):
    BUY_PRICE = "buy_price"
    CASH_REQUIREMENT = "cash_requirement"


class SimulatedDeferredSourceBlockReason(StrEnum):
    INCOMPLETE_BATCH = "incomplete_batch"
    INVALID_EXECUTION_TERMS = "invalid_execution_terms"


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: str, field_name: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise SimulatedBrokerError(f"{field_name} must be a non-empty, trimmed string")


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SimulatedBrokerError(f"{field_name} must be a lowercase SHA-256 digest")


def _persisted_decimal(
    value: Decimal,
    field_name: str,
    *,
    positive: bool = False,
) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise SimulatedBrokerError(f"{field_name} must be a finite exact Decimal")
    if value < 0 or (positive and value == 0):
        qualifier = "positive" if positive else "non-negative"
        raise SimulatedBrokerError(f"{field_name} must be {qualifier}")
    try:
        return canonical_persisted_decimal(value, field_name)
    except ValueError as error:
        raise SimulatedBrokerError(str(error)) from error


def _whole_quantity(value: Decimal, field_name: str) -> Decimal:
    quantity = _persisted_decimal(value, field_name, positive=True)
    if quantity != quantity.to_integral_value():
        raise SimulatedBrokerError(f"{field_name} must be a whole number of shares")
    return quantity


@dataclass(frozen=True, slots=True)
class SimulatedRiskExecutionCaps:
    """Exact child-authorization constraints carried into simulation output."""

    authorization_decision_id: str
    session_sha256: str
    currency: str
    maximum_execution_price: Decimal
    maximum_cash_requirement: Decimal

    def __post_init__(self) -> None:
        _require_text(self.authorization_decision_id, "authorization decision ID")
        _require_sha256(self.session_sha256, "authorization session_sha256")
        _require_text(self.currency, "authorization currency")
        if (
            len(self.currency) != 3
            or not self.currency.isalpha()
            or self.currency != self.currency.upper()
        ):
            raise SimulatedBrokerError("authorization currency must be three-letter uppercase")
        object.__setattr__(
            self,
            "maximum_execution_price",
            _persisted_decimal(
                self.maximum_execution_price,
                "authorization maximum_execution_price",
                positive=True,
            ),
        )
        object.__setattr__(
            self,
            "maximum_cash_requirement",
            _persisted_decimal(
                self.maximum_cash_requirement,
                "authorization maximum_cash_requirement",
            ),
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                SIMULATED_BROKER_CONTRACT_VERSION,
                "risk_execution_caps",
                self.authorization_decision_id,
                self.session_sha256,
                self.currency,
                self.maximum_execution_price,
                self.maximum_cash_requirement,
            )
        )


def _timedelta_microseconds(value: timedelta) -> int:
    return value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds


def _batch_risk_session_evidence(session: SimulatedBrokerSession) -> BatchRiskSession:
    return BatchRiskSession(
        calendar_id=session.calendar_id,
        calendar_version=session.calendar_version,
        calendar_sha256=session.calendar_sha256,
        venue=session.session.venue,
        session_label=session.session.session_label,
        opens_at=session.session.opens_at,
        closes_at=session.session.closes_at,
        kind=BatchRiskSessionKind(session.session.kind.value),
    )


def _authorization_execution_caps(
    authorization: object | None,
    intent: OrderIntent,
    session: SimulatedBrokerSession,
    model: SimulatedMarketOrderModel,
    risk_decision_id: str,
) -> SimulatedRiskExecutionCaps | None:
    """Read optional batch-risk caps without changing the Phase 0 authorization shape."""

    if authorization is None:
        return None
    maximum_execution_price = getattr(
        authorization,
        "maximum_execution_price",
        _MISSING_AUTHORIZATION_CAP,
    )
    maximum_cash_requirement = getattr(
        authorization,
        "maximum_cash_requirement",
        _MISSING_AUTHORIZATION_CAP,
    )
    if (
        maximum_execution_price is _MISSING_AUTHORIZATION_CAP
        and maximum_cash_requirement is _MISSING_AUTHORIZATION_CAP
    ):
        return None
    if (
        maximum_execution_price is _MISSING_AUTHORIZATION_CAP
        or maximum_cash_requirement is _MISSING_AUTHORIZATION_CAP
    ):
        raise SimulatedBrokerError("batch risk authorization execution caps are incomplete")
    if type(maximum_execution_price) is not Decimal:
        raise SimulatedBrokerError(
            "authorization maximum_execution_price must be a finite exact Decimal"
        )
    if type(maximum_cash_requirement) is not Decimal:
        raise SimulatedBrokerError(
            "authorization maximum_cash_requirement must be a finite exact Decimal"
        )

    price_cap = _persisted_decimal(
        maximum_execution_price,
        "authorization maximum_execution_price",
        positive=True,
    )
    cash_cap = _persisted_decimal(
        maximum_cash_requirement,
        "authorization maximum_cash_requirement",
    )
    if price_cap < intent.reference_price:
        raise SimulatedBrokerError(
            "batch risk authorization execution price cap is below the intent reference price"
        )
    if intent.side is Side.BUY:
        minimum_cash_cap = exact_decimal_multiply(intent.quantity, price_cap)
        if cash_cap < minimum_cash_cap:
            raise SimulatedBrokerError(
                "batch risk authorization cash cap does not cover its buy price cap"
            )
    authorization_session_sha256 = getattr(
        authorization,
        "session_sha256",
        _MISSING_AUTHORIZATION_CAP,
    )
    authorization_currency = getattr(
        authorization,
        "currency",
        _MISSING_AUTHORIZATION_CAP,
    )
    if (
        authorization_session_sha256 is _MISSING_AUTHORIZATION_CAP
        or authorization_currency is _MISSING_AUTHORIZATION_CAP
    ):
        raise SimulatedBrokerError("batch risk authorization execution context is incomplete")
    if type(authorization_session_sha256) is not str:
        raise SimulatedBrokerError("authorization session digest must be a string")
    _require_sha256(authorization_session_sha256, "authorization session_sha256")
    if type(authorization_currency) is not str:
        raise SimulatedBrokerError("authorization currency must be a string")
    _require_text(authorization_currency, "authorization currency")
    if (
        len(authorization_currency) != 3
        or not authorization_currency.isalpha()
        or authorization_currency != authorization_currency.upper()
    ):
        raise SimulatedBrokerError("authorization currency must be three-letter uppercase")
    broker_risk_session = _batch_risk_session_evidence(session)
    if authorization_session_sha256 != broker_risk_session.semantic_sha256:
        raise SimulatedBrokerError("broker session does not match the risk authorization")
    if authorization_currency != model.currency:
        raise SimulatedBrokerError("broker currency does not match the risk authorization")
    authorization_decision_id = getattr(authorization, "decision_id", None)
    if authorization_decision_id != risk_decision_id:
        raise SimulatedBrokerError("broker risk decision does not match the authorization")
    return SimulatedRiskExecutionCaps(
        authorization_decision_id=authorization_decision_id,
        session_sha256=authorization_session_sha256,
        currency=authorization_currency,
        maximum_execution_price=price_cap,
        maximum_cash_requirement=cash_cap,
    )


def _execution_cap_violations(
    *,
    intent: OrderIntent,
    terms: SimulatedExecutionTerms,
    caps: SimulatedRiskExecutionCaps,
) -> tuple[SimulatedRiskCapViolation, ...]:
    violations: list[SimulatedRiskCapViolation] = []
    if intent.side is Side.BUY and terms.execution_price > caps.maximum_execution_price:
        violations.append(SimulatedRiskCapViolation.BUY_PRICE)
    cash_requirement = (
        exact_decimal_add(
            exact_decimal_multiply(terms.quantity, terms.execution_price),
            terms.total_fee,
        )
        if intent.side is Side.BUY
        else terms.total_fee
    )
    # This is an ephemeral exact comparison, not a persisted money field. The
    # product of two individually persistable values can exceed the persistence
    # envelope; because the cap itself is persistable, that still proves a
    # breach and must not turn a consumed authorization into an exception.
    if cash_requirement > caps.maximum_cash_requirement:
        violations.append(SimulatedRiskCapViolation.CASH_REQUIREMENT)
    return tuple(violations)


def _validate_execution_caps(
    *,
    intent: OrderIntent,
    terms: SimulatedExecutionTerms,
    caps: SimulatedRiskExecutionCaps,
) -> None:
    violations = _execution_cap_violations(intent=intent, terms=terms, caps=caps)
    if SimulatedRiskCapViolation.BUY_PRICE in violations:
        raise SimulatedBrokerError(
            "simulated buy execution price exceeds its risk authorization cap"
        )
    if SimulatedRiskCapViolation.CASH_REQUIREMENT in violations:
        raise SimulatedBrokerError(
            "simulated execution cash requirement exceeds its risk authorization cap"
        )


@dataclass(frozen=True, slots=True)
class SimulatedBrokerSession:
    """Exact calendar evidence authorizing one regular-hours simulation session."""

    calendar_id: str
    calendar_version: str
    calendar_sha256: str
    session: ExchangeSession

    def __post_init__(self) -> None:
        _require_text(self.calendar_id, "calendar_id")
        _require_text(self.calendar_version, "calendar_version")
        _require_sha256(self.calendar_sha256, "calendar_sha256")
        if type(self.session) is not ExchangeSession:
            raise SimulatedBrokerError("session must be an exact ExchangeSession")
        if not isinstance(self.session.kind, SessionKind):
            raise SimulatedBrokerError("simulated broker session kind is unsupported")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                SIMULATED_BROKER_CONTRACT_VERSION,
                "session",
                self.calendar_id,
                self.calendar_version,
                self.calendar_sha256,
                self.session.venue,
                self.session.session_label,
                self.session.opens_at,
                self.session.closes_at,
                self.session.kind,
            )
        )

    @property
    def session_id(self) -> str:
        return canonical_id("simulated-broker-session", self.semantic_sha256)


@dataclass(frozen=True, slots=True)
class SimulatedExecutionTerms:
    """Auditable price and fee arithmetic for one full simulated fill."""

    side: Side
    quantity: Decimal
    reference_price: Decimal
    half_spread_per_share: Decimal
    slippage_per_share: Decimal
    execution_price: Decimal
    fixed_fee: Decimal
    variable_fee: Decimal
    total_fee: Decimal

    def __post_init__(self) -> None:
        if not isinstance(self.side, Side):
            raise SimulatedBrokerError("execution side is unsupported")
        object.__setattr__(
            self,
            "quantity",
            _whole_quantity(self.quantity, "execution terms quantity"),
        )
        for field_name, positive in (
            ("reference_price", True),
            ("half_spread_per_share", False),
            ("slippage_per_share", False),
            ("execution_price", True),
            ("fixed_fee", False),
            ("variable_fee", False),
            ("total_fee", False),
        ):
            object.__setattr__(
                self,
                field_name,
                _persisted_decimal(
                    getattr(self, field_name),
                    f"execution terms {field_name}",
                    positive=positive,
                ),
            )
        adverse_offset = exact_decimal_add(
            self.half_spread_per_share,
            self.slippage_per_share,
        )
        expected_price = (
            exact_decimal_add(self.reference_price, adverse_offset)
            if self.side is Side.BUY
            else exact_decimal_subtract(self.reference_price, adverse_offset)
        )
        if expected_price <= 0:
            raise SimulatedBrokerError("adverse sell offsets produce a non-positive price")
        try:
            expected_price = canonical_persisted_decimal(
                expected_price,
                "execution terms expected price",
            )
            expected_fee = canonical_persisted_decimal(
                exact_decimal_add(self.fixed_fee, self.variable_fee),
                "execution terms expected fee",
            )
        except ValueError as error:
            raise SimulatedBrokerError(str(error)) from error
        if self.execution_price != expected_price:
            raise SimulatedBrokerError("execution price does not match its adverse offsets")
        if self.total_fee != expected_fee:
            raise SimulatedBrokerError("total fee does not match fixed and variable fees")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                SIMULATED_BROKER_CONTRACT_VERSION,
                "execution_terms",
                self.side,
                self.quantity,
                self.reference_price,
                self.half_spread_per_share,
                self.slippage_per_share,
                self.execution_price,
                self.fixed_fee,
                self.variable_fee,
                self.total_fee,
            )
        )


@dataclass(frozen=True, slots=True)
class SimulatedMarketOrderModel:
    """Versioned full-fill model with explicit adverse price and fee assumptions."""

    model_id: str
    model_version: str
    activation_latency: timedelta
    half_spread_per_share: Decimal
    slippage_per_share: Decimal
    fixed_fee: Decimal
    fee_per_share: Decimal
    currency: str = "USD"

    def __post_init__(self) -> None:
        _require_text(self.model_id, "model_id")
        _require_text(self.model_version, "model_version")
        _require_text(self.currency, "currency")
        if (
            len(self.currency) != 3
            or not self.currency.isalpha()
            or self.currency != self.currency.upper()
        ):
            raise SimulatedBrokerError("currency must be a three-letter uppercase code")
        if type(self.activation_latency) is not timedelta:
            raise SimulatedBrokerError("activation_latency must be an exact timedelta")
        if self.activation_latency < timedelta(0):
            raise SimulatedBrokerError("activation_latency must be non-negative")
        for field_name in (
            "half_spread_per_share",
            "slippage_per_share",
            "fixed_fee",
            "fee_per_share",
        ):
            object.__setattr__(
                self,
                field_name,
                _persisted_decimal(getattr(self, field_name), field_name),
            )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                SIMULATED_BROKER_CONTRACT_VERSION,
                "market_order_model",
                self.model_id,
                self.model_version,
                _timedelta_microseconds(self.activation_latency),
                self.half_spread_per_share,
                self.slippage_per_share,
                self.fixed_fee,
                self.fee_per_share,
                self.currency,
            )
        )

    def execution_terms(
        self,
        *,
        side: Side,
        quantity: Decimal,
        reference_price: Decimal,
    ) -> SimulatedExecutionTerms:
        """Apply the configured assumptions without consulting ambient state."""

        if not isinstance(side, Side):
            raise SimulatedBrokerError("execution side is unsupported")
        quantity = _whole_quantity(quantity, "execution quantity")
        reference_price = _persisted_decimal(
            reference_price,
            "execution reference_price",
            positive=True,
        )
        adverse_offset = exact_decimal_add(
            self.half_spread_per_share,
            self.slippage_per_share,
        )
        execution_price = (
            exact_decimal_add(reference_price, adverse_offset)
            if side is Side.BUY
            else exact_decimal_subtract(reference_price, adverse_offset)
        )
        if execution_price <= 0:
            raise SimulatedBrokerError("adverse sell offsets produce a non-positive price")
        variable_fee = exact_decimal_multiply(self.fee_per_share, quantity)
        total_fee = exact_decimal_add(self.fixed_fee, variable_fee)
        return SimulatedExecutionTerms(
            side=side,
            quantity=quantity,
            reference_price=reference_price,
            half_spread_per_share=self.half_spread_per_share,
            slippage_per_share=self.slippage_per_share,
            execution_price=execution_price,
            fixed_fee=self.fixed_fee,
            variable_fee=variable_fee,
            total_fee=total_fee,
        )


@dataclass(frozen=True, slots=True)
class SimulatedFillEvidence:
    """Source, configuration, and lifecycle facts supporting one simulated fill."""

    working_order_state_sha256: str
    source_batch_id: str
    source_batch_sha256: str
    source_event_id: str
    source_event_sha256: str
    model_sha256: str
    session_sha256: str
    terms: SimulatedExecutionTerms
    occurred_at: datetime
    received_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.source_batch_id, "source_batch_id")
        _require_text(self.source_event_id, "source_event_id")
        for value, field_name in (
            (self.working_order_state_sha256, "working_order_state_sha256"),
            (self.source_batch_sha256, "source_batch_sha256"),
            (self.source_event_sha256, "source_event_sha256"),
            (self.model_sha256, "model_sha256"),
            (self.session_sha256, "session_sha256"),
        ):
            _require_sha256(value, field_name)
        if type(self.terms) is not SimulatedExecutionTerms:
            raise SimulatedBrokerError("fill evidence requires exact execution terms")
        try:
            require_utc(self.occurred_at, "fill occurred_at")
            require_utc(self.received_at, "fill received_at")
        except ValueError as error:
            raise SimulatedBrokerError(str(error)) from error
        if self.received_at < self.occurred_at:
            raise SimulatedBrokerError("fill cannot be received before it occurred")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                SIMULATED_BROKER_CONTRACT_VERSION,
                "fill_evidence",
                self.working_order_state_sha256,
                self.source_batch_id,
                self.source_batch_sha256,
                self.source_event_id,
                self.source_event_sha256,
                self.model_sha256,
                self.session_sha256,
                self.terms.semantic_sha256,
                self.occurred_at,
                self.received_at,
            )
        )


@dataclass(frozen=True, slots=True)
class SimulatedRiskCapBlockEvidence:
    """Future source and terms proving why an accepted order did not execute."""

    working_order_state_sha256: str
    source_batch_id: str
    source_batch_sha256: str
    source_event_id: str
    source_event_sha256: str
    model_sha256: str
    session_sha256: str
    execution_caps_sha256: str
    terms: SimulatedExecutionTerms
    violations: tuple[SimulatedRiskCapViolation, ...]
    occurred_at: datetime
    received_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.source_batch_id, "cap-block source_batch_id")
        _require_text(self.source_event_id, "cap-block source_event_id")
        for value, field_name in (
            (self.working_order_state_sha256, "working_order_state_sha256"),
            (self.source_batch_sha256, "cap-block source_batch_sha256"),
            (self.source_event_sha256, "cap-block source_event_sha256"),
            (self.model_sha256, "cap-block model_sha256"),
            (self.session_sha256, "cap-block session_sha256"),
            (self.execution_caps_sha256, "cap-block execution_caps_sha256"),
        ):
            _require_sha256(value, field_name)
        if type(self.terms) is not SimulatedExecutionTerms:
            raise SimulatedBrokerError("cap-block evidence requires exact execution terms")
        if (
            type(self.violations) is not tuple
            or not self.violations
            or any(
                not isinstance(violation, SimulatedRiskCapViolation)
                for violation in self.violations
            )
            or tuple(sorted(set(self.violations), key=lambda item: item.value)) != self.violations
        ):
            raise SimulatedBrokerError("cap-block evidence requires canonical cap violations")
        try:
            require_utc(self.occurred_at, "cap-block occurred_at")
            require_utc(self.received_at, "cap-block received_at")
        except ValueError as error:
            raise SimulatedBrokerError(str(error)) from error
        if self.received_at < self.occurred_at:
            raise SimulatedBrokerError("cap block cannot be received before it occurred")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                SIMULATED_BROKER_CONTRACT_VERSION,
                "risk_cap_block_evidence",
                self.working_order_state_sha256,
                self.source_batch_id,
                self.source_batch_sha256,
                self.source_event_id,
                self.source_event_sha256,
                self.model_sha256,
                self.session_sha256,
                self.execution_caps_sha256,
                self.terms.semantic_sha256,
                self.violations,
                self.occurred_at,
                self.received_at,
            )
        )


@dataclass(frozen=True, slots=True)
class SimulatedDeferredSourceBlockEvidence:
    """Exact future fact proving why an accepted capped order stayed working."""

    reason: SimulatedDeferredSourceBlockReason
    working_order_state_sha256: str
    source_batch_id: str
    source_batch_sha256: str
    source_event_id: str | None
    source_event_sha256: str | None
    model_sha256: str
    session_sha256: str
    execution_caps_sha256: str
    occurred_at: datetime
    received_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.reason, SimulatedDeferredSourceBlockReason):
            raise SimulatedBrokerError("deferred source-block reason is unsupported")
        _require_text(self.source_batch_id, "deferred-block source_batch_id")
        for value, field_name in (
            (self.working_order_state_sha256, "working_order_state_sha256"),
            (self.source_batch_sha256, "deferred-block source_batch_sha256"),
            (self.model_sha256, "deferred-block model_sha256"),
            (self.session_sha256, "deferred-block session_sha256"),
            (self.execution_caps_sha256, "deferred-block execution_caps_sha256"),
        ):
            _require_sha256(value, field_name)
        if (self.source_event_id is None) != (self.source_event_sha256 is None):
            raise SimulatedBrokerError(
                "deferred source-block event identity and digest must appear together"
            )
        if self.source_event_id is not None:
            _require_text(self.source_event_id, "deferred-block source_event_id")
            assert self.source_event_sha256 is not None
            _require_sha256(
                self.source_event_sha256,
                "deferred-block source_event_sha256",
            )
        if (
            self.reason is SimulatedDeferredSourceBlockReason.INCOMPLETE_BATCH
            and self.source_event_id is not None
        ):
            raise SimulatedBrokerError(
                "incomplete source-block evidence cannot select a source event"
            )
        if (
            self.reason is SimulatedDeferredSourceBlockReason.INVALID_EXECUTION_TERMS
            and self.source_event_id is None
        ):
            raise SimulatedBrokerError("invalid-terms evidence requires the exact source event")
        try:
            require_utc(self.occurred_at, "deferred-block occurred_at")
            require_utc(self.received_at, "deferred-block received_at")
        except ValueError as error:
            raise SimulatedBrokerError(str(error)) from error
        if self.received_at < self.occurred_at:
            raise SimulatedBrokerError(
                "deferred source block cannot be received before it occurred"
            )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                SIMULATED_BROKER_CONTRACT_VERSION,
                "deferred_source_block_evidence",
                self.reason,
                self.working_order_state_sha256,
                self.source_batch_id,
                self.source_batch_sha256,
                self.source_event_id,
                self.source_event_sha256,
                self.model_sha256,
                self.session_sha256,
                self.execution_caps_sha256,
                self.occurred_at,
                self.received_at,
            )
        )


def _canonical_market_batches(
    market_batches: Iterable[MarketBatch],
    session: SimulatedBrokerSession,
) -> tuple[MarketBatch, ...]:
    by_digest: dict[str, MarketBatch] = {}
    by_id: dict[str, MarketBatch] = {}
    watermarks_by_id: dict[str, object] = {}
    events_by_id: dict[str, MarketEvent] = {}
    observation_bindings: dict[tuple[str, str], tuple[str, datetime]] = {}
    for batch in market_batches:
        if type(batch) is not MarketBatch:
            raise SimulatedBrokerError("market tape requires exact MarketBatch values")
        try:
            batch._validate()
        except ValueError as error:
            raise SimulatedBrokerError(f"invalid market batch: {error}") from error
        frontier = batch.watermark.event_time_through
        if not session.session.opens_at <= frontier <= session.session.closes_at:
            raise SimulatedBrokerError("market batch frontier is outside the configured session")
        existing_watermark = watermarks_by_id.get(batch.watermark.watermark_id)
        if existing_watermark is not None and existing_watermark != batch.watermark:
            raise SimulatedBrokerFactConflict("market watermark identity has conflicting semantics")
        watermarks_by_id[batch.watermark.watermark_id] = batch.watermark
        for event in batch.events:
            existing_event = events_by_id.get(event.event_id)
            if existing_event is not None and existing_event != event:
                raise SimulatedBrokerFactConflict("market event identity has conflicting semantics")
            events_by_id[event.event_id] = event
            observation_identity = (event.source, event.observation_key)
            observation_binding = (event.instrument_id, event.event_time)
            existing_binding = observation_bindings.get(observation_identity)
            if existing_binding is not None and existing_binding != observation_binding:
                raise SimulatedBrokerFactConflict(
                    "market observation identity spans multiple event-time chains"
                )
            observation_bindings[observation_identity] = observation_binding
        digest = batch.semantic_sha256
        existing_id = by_id.get(batch.batch_id)
        if existing_id is not None and existing_id.semantic_sha256 != digest:
            raise SimulatedBrokerFactConflict("market batch identity has conflicting semantics")
        by_id[batch.batch_id] = batch
        by_digest.setdefault(digest, batch)

    ordered = tuple(
        sorted(
            by_digest.values(),
            key=lambda batch: (
                batch.as_of,
                batch.watermark.event_time_through,
                batch.batch_id,
            ),
        )
    )
    prior: MarketBatch | None = None
    for batch in ordered:
        if prior is not None:
            prior_frontier = prior.watermark.event_time_through
            frontier = batch.watermark.event_time_through
            if frontier < prior_frontier:
                raise SimulatedBrokerFactConflict(
                    "market event-time frontier regresses in availability order"
                )
            if frontier == prior_frontier:
                raise SimulatedBrokerFactConflict(
                    "market tape contains conflicting slices at one event-time frontier"
                )
        prior = batch
    return ordered


def _source_event(batch: MarketBatch, intent: OrderIntent) -> MarketEvent:
    try:
        event = batch.event_for(intent.instrument_id)
    except KeyError as error:
        raise SimulatedBrokerError(
            "complete market batch lacks the submitted instrument"
        ) from error
    if event.symbol != intent.symbol:
        raise SimulatedBrokerFactConflict(
            "market event symbol conflicts with the submitted instrument"
        )
    return event


def _validate_intent_tape(
    *,
    intent: OrderIntent,
    session: SimulatedBrokerSession,
    market_batches: tuple[MarketBatch, ...],
) -> None:
    if not session.session.contains(intent.created_at):
        raise SimulatedBrokerError("intent creation is outside the configured session")
    if not session.session.contains(intent.decision_event_time):
        raise SimulatedBrokerError("intent decision time is outside the configured session")
    for batch in market_batches:
        if intent.instrument_id not in batch.watermark.expected_instrument_ids:
            raise SimulatedBrokerError(
                "market tape does not expect the submitted instrument in every slice"
            )
        for event in batch.events:
            if event.instrument_id == intent.instrument_id and event.symbol != intent.symbol:
                raise SimulatedBrokerFactConflict(
                    "market event symbol conflicts with the submitted instrument"
                )


def _first_relevant_future_batch(
    *,
    market_batches: tuple[MarketBatch, ...],
    activation_at: datetime,
) -> MarketBatch | None:
    for batch in market_batches:
        if batch.watermark.event_time_through <= activation_at:
            continue
        return batch
    return None


def _first_eligible_source(
    *,
    market_batches: tuple[MarketBatch, ...],
    intent: OrderIntent,
    activation_at: datetime,
) -> tuple[MarketBatch, MarketEvent] | None:
    batch = _first_relevant_future_batch(
        market_batches=market_batches,
        activation_at=activation_at,
    )
    if batch is not None:
        if not batch.complete:
            raise SimulatedBrokerError(
                "first relevant future market batch is incomplete; fill is unknowable"
            )
        return batch, _source_event(batch, intent)
    return None


@dataclass(frozen=True, slots=True)
class SimulatedBrokerResult:
    """Canonical order output plus every source fact used by the simulation."""

    outcome: SimulatedBrokerOutcome
    session: SimulatedBrokerSession
    model: SimulatedMarketOrderModel
    submission: OrderSubmission
    activation_at: datetime
    market_batches: tuple[MarketBatch, ...]
    risk_execution_caps: SimulatedRiskExecutionCaps | None
    cap_block_evidence: SimulatedRiskCapBlockEvidence | None
    deferred_source_block_evidence: SimulatedDeferredSourceBlockEvidence | None
    fill_evidence: SimulatedFillEvidence | None
    broker_events: tuple[BrokerOrderEvent, ...]
    order_state: CanonicalOrderState
    completed_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, SimulatedBrokerOutcome):
            raise SimulatedBrokerError("simulation outcome is unsupported")
        if type(self.session) is not SimulatedBrokerSession:
            raise SimulatedBrokerError("result requires an exact simulated session")
        if type(self.model) is not SimulatedMarketOrderModel:
            raise SimulatedBrokerError("result requires an exact market-order model")
        if type(self.submission) is not OrderSubmission:
            raise SimulatedBrokerError("result requires an exact order submission")
        try:
            require_utc(self.activation_at, "activation_at")
            require_utc(self.completed_at, "completed_at")
        except ValueError as error:
            raise SimulatedBrokerError(str(error)) from error
        if self.activation_at != self.submission.submitted_at + self.model.activation_latency:
            raise SimulatedBrokerError("activation time does not match the configured latency")
        if not self.session.session.contains(self.submission.submitted_at):
            raise SimulatedBrokerError("result submission is outside the configured session")
        if self.activation_at >= self.session.session.closes_at:
            raise SimulatedBrokerError("result activation does not precede session close")
        if type(self.market_batches) is not tuple:
            raise SimulatedBrokerError("result market batches must be an immutable tuple")
        if _canonical_market_batches(self.market_batches, self.session) != self.market_batches:
            raise SimulatedBrokerError("result market batches are not in canonical order")
        _validate_intent_tape(
            intent=self.submission.intent,
            session=self.session,
            market_batches=self.market_batches,
        )
        expected_submission = create_order_submission(
            intent=self.submission.intent,
            risk_decision_id=self.submission.risk_decision_id,
            submission_attempt_id=self.submission.submission_attempt_id,
            submitted_at=self.submission.submitted_at,
        )
        if self.submission != expected_submission:
            raise SimulatedBrokerError("result submission is not canonically identified")
        if type(self.broker_events) is not tuple or any(
            type(event) is not BrokerOrderEvent for event in self.broker_events
        ):
            raise SimulatedBrokerError("result broker events must be immutable canonical facts")
        canonical_state = reduce_order_lifecycle(
            submission=self.submission,
            broker_events=self.broker_events,
        )
        if canonical_state != self.order_state:
            raise SimulatedBrokerError("result order state is not reducer-produced")
        if self.completed_at < self.order_state.as_of:
            raise SimulatedBrokerError("result completion cannot precede its order state")
        expected_completed_at = max(
            (self.activation_at, *(batch.as_of for batch in self.market_batches))
        )
        if self.completed_at != expected_completed_at:
            raise SimulatedBrokerError("result completion does not cover its canonical tape")
        if (
            not self.broker_events
            or self.broker_events[0].kind is not BrokerOrderEventKind.ACCEPTED
        ):
            raise SimulatedBrokerError("simulated broker result requires an acceptance event")

        expected_broker_order_id = canonical_id(
            "simulated-broker-order",
            self.submission.order_id,
            self.model.semantic_sha256,
            self.session.semantic_sha256,
        )
        expected_accepted = BrokerOrderEvent(
            event_id=canonical_id(
                "simulated-broker-event",
                expected_broker_order_id,
                1,
                BrokerOrderEventKind.ACCEPTED,
                self.submission.submitted_at,
            ),
            order_id=self.submission.order_id,
            broker_order_id=expected_broker_order_id,
            broker_sequence=1,
            occurred_at=self.submission.submitted_at,
            received_at=self.submission.submitted_at,
            kind=BrokerOrderEventKind.ACCEPTED,
        )
        if self.broker_events[0] != expected_accepted:
            raise SimulatedBrokerError("acceptance event is not canonically identified")
        working_state = reduce_order_lifecycle(
            submission=self.submission,
            broker_events=(self.broker_events[0],),
        )
        caps = self.risk_execution_caps
        if caps is not None:
            if type(caps) is not SimulatedRiskExecutionCaps:
                raise SimulatedBrokerError("result requires exact risk execution caps")
            if caps.authorization_decision_id != self.submission.risk_decision_id:
                raise SimulatedBrokerError(
                    "result execution caps do not bind the submission authorization"
                )
            if caps.session_sha256 != _batch_risk_session_evidence(self.session).semantic_sha256:
                raise SimulatedBrokerError("result execution caps do not bind the broker session")
            if caps.currency != self.model.currency:
                raise SimulatedBrokerError("result execution caps do not bind the broker currency")
            if caps.maximum_execution_price < self.submission.intent.reference_price:
                raise SimulatedBrokerError(
                    "result execution price cap is below the intent reference price"
                )
            if self.submission.intent.side is Side.BUY and (
                caps.maximum_cash_requirement
                < exact_decimal_multiply(
                    self.submission.intent.quantity,
                    caps.maximum_execution_price,
                )
            ):
                raise SimulatedBrokerError(
                    "result cash cap does not cover its buy execution price cap"
                )
        first_future_batch = _first_relevant_future_batch(
            market_batches=self.market_batches,
            activation_at=self.activation_at,
        )
        selected = (
            None
            if first_future_batch is None or not first_future_batch.complete
            else (
                first_future_batch,
                _source_event(first_future_batch, self.submission.intent),
            )
        )
        if self.outcome is SimulatedBrokerOutcome.WORKING_NO_ELIGIBLE_EVENT:
            if (
                self.fill_evidence is not None
                or self.cap_block_evidence is not None
                or self.deferred_source_block_evidence is not None
                or len(self.broker_events) != 1
            ):
                raise SimulatedBrokerError("working result cannot contain simulated fill evidence")
            if self.order_state.status is not CanonicalOrderStatus.WORKING:
                raise SimulatedBrokerError("no-fill simulation must leave the order working")
            if first_future_batch is not None:
                raise SimulatedBrokerError("working result ignores an eligible market event")
            return

        if self.outcome is SimulatedBrokerOutcome.WORKING_RISK_CAP_BLOCKED:
            if (
                self.fill_evidence is not None
                or self.deferred_source_block_evidence is not None
                or len(self.broker_events) != 1
            ):
                raise SimulatedBrokerError("cap-blocked result cannot contain an execution")
            if self.order_state.status is not CanonicalOrderStatus.WORKING:
                raise SimulatedBrokerError("cap-blocked result must leave the order working")
            if caps is None or type(self.cap_block_evidence) is not SimulatedRiskCapBlockEvidence:
                raise SimulatedBrokerError(
                    "cap-blocked result requires exact cap and source evidence"
                )
            if selected is None:
                raise SimulatedBrokerError("cap-blocked result has no eligible source event")
            block_source_batch, block_source_event = selected
            block_evidence = self.cap_block_evidence
            expected_terms = self.model.execution_terms(
                side=self.submission.intent.side,
                quantity=self.submission.intent.quantity,
                reference_price=block_source_event.close_price,
            )
            expected_violations = _execution_cap_violations(
                intent=self.submission.intent,
                terms=expected_terms,
                caps=caps,
            )
            if not expected_violations:
                raise SimulatedBrokerError("cap-blocked source does not breach its constraints")
            if (
                block_evidence.working_order_state_sha256 != working_state.semantic_sha256
                or block_evidence.source_batch_id != block_source_batch.batch_id
                or block_evidence.source_batch_sha256 != block_source_batch.semantic_sha256
                or block_evidence.source_event_id != block_source_event.event_id
                or block_evidence.source_event_sha256 != block_source_event.semantic_sha256
                or block_evidence.model_sha256 != self.model.semantic_sha256
                or block_evidence.session_sha256 != self.session.semantic_sha256
                or block_evidence.execution_caps_sha256 != caps.semantic_sha256
                or block_evidence.terms != expected_terms
                or block_evidence.violations != expected_violations
                or block_evidence.occurred_at != block_source_event.event_time
                or block_evidence.received_at != block_source_batch.as_of
            ):
                raise SimulatedBrokerError(
                    "cap-block evidence does not match the first eligible source"
                )
            return

        if self.outcome is SimulatedBrokerOutcome.WORKING_DEFERRED_SOURCE_BLOCKED:
            if (
                self.fill_evidence is not None
                or self.cap_block_evidence is not None
                or len(self.broker_events) != 1
            ):
                raise SimulatedBrokerError(
                    "deferred source-blocked result cannot contain an execution"
                )
            if self.order_state.status is not CanonicalOrderStatus.WORKING:
                raise SimulatedBrokerError(
                    "deferred source-blocked result must leave the order working"
                )
            deferred = self.deferred_source_block_evidence
            if (
                caps is None
                or type(deferred) is not SimulatedDeferredSourceBlockEvidence
                or first_future_batch is None
            ):
                raise SimulatedBrokerError(
                    "deferred source-blocked result requires exact cap and source evidence"
                )
            if (
                deferred.working_order_state_sha256 != working_state.semantic_sha256
                or deferred.source_batch_id != first_future_batch.batch_id
                or deferred.source_batch_sha256 != first_future_batch.semantic_sha256
                or deferred.model_sha256 != self.model.semantic_sha256
                or deferred.session_sha256 != self.session.semantic_sha256
                or deferred.execution_caps_sha256 != caps.semantic_sha256
            ):
                raise SimulatedBrokerError(
                    "deferred source-block evidence does not match its causal context"
                )
            if deferred.reason is SimulatedDeferredSourceBlockReason.INCOMPLETE_BATCH:
                if (
                    first_future_batch.complete
                    or deferred.source_event_id is not None
                    or deferred.occurred_at != first_future_batch.watermark.event_time_through
                    or deferred.received_at != first_future_batch.as_of
                ):
                    raise SimulatedBrokerError(
                        "incomplete deferred-block evidence does not match its first batch"
                    )
                return
            if not first_future_batch.complete:
                raise SimulatedBrokerError(
                    "invalid-terms deferred block requires a complete source batch"
                )
            source_event = _source_event(first_future_batch, self.submission.intent)
            if (
                deferred.source_event_id != source_event.event_id
                or deferred.source_event_sha256 != source_event.semantic_sha256
                or deferred.occurred_at != source_event.event_time
                or deferred.received_at != first_future_batch.as_of
            ):
                raise SimulatedBrokerError(
                    "invalid-terms deferred-block evidence does not match its source"
                )
            try:
                self.model.execution_terms(
                    side=self.submission.intent.side,
                    quantity=self.submission.intent.quantity,
                    reference_price=source_event.close_price,
                )
            except SimulatedBrokerError:
                return
            raise SimulatedBrokerError("invalid-terms deferred block has valid execution terms")

        if self.cap_block_evidence is not None or self.deferred_source_block_evidence is not None:
            raise SimulatedBrokerError("filled result cannot contain working-block evidence")
        if type(self.fill_evidence) is not SimulatedFillEvidence:
            raise SimulatedBrokerError("filled result requires exact fill evidence")
        if len(self.broker_events) != 2:
            raise SimulatedBrokerError("full-fill simulation requires two broker events")
        if self.order_state.status is not CanonicalOrderStatus.FILLED:
            raise SimulatedBrokerError("filled simulation must produce a filled order")
        if selected is None:
            raise SimulatedBrokerError("filled result has no eligible source event")
        fill_evidence = self.fill_evidence
        if fill_evidence.working_order_state_sha256 != working_state.semantic_sha256:
            raise SimulatedBrokerError("fill evidence is not bound to the working order state")
        if fill_evidence.model_sha256 != self.model.semantic_sha256:
            raise SimulatedBrokerError("fill evidence is not bound to the configured model")
        if fill_evidence.session_sha256 != self.session.semantic_sha256:
            raise SimulatedBrokerError("fill evidence is not bound to the configured session")
        source_batch = next(
            (
                batch
                for batch in self.market_batches
                if batch.batch_id == fill_evidence.source_batch_id
                and batch.semantic_sha256 == fill_evidence.source_batch_sha256
            ),
            None,
        )
        if source_batch is None:
            raise SimulatedBrokerError("fill evidence source batch is absent from the tape")
        source_event = _source_event(source_batch, self.submission.intent)
        if selected != (source_batch, source_event):
            raise SimulatedBrokerError("fill evidence did not select the first eligible event")
        if (
            source_event.event_id != fill_evidence.source_event_id
            or source_event.semantic_sha256 != fill_evidence.source_event_sha256
        ):
            raise SimulatedBrokerError("fill evidence source event does not match its batch")
        if fill_evidence.occurred_at != source_event.event_time:
            raise SimulatedBrokerError("fill occurrence does not match the source event time")
        if fill_evidence.received_at != source_batch.as_of:
            raise SimulatedBrokerError("fill receipt does not match the sealed batch time")
        if fill_evidence.occurred_at <= self.activation_at:
            raise SimulatedBrokerError("fill source must be strictly later than activation")
        expected_terms = self.model.execution_terms(
            side=self.submission.intent.side,
            quantity=self.submission.intent.quantity,
            reference_price=source_event.close_price,
        )
        if fill_evidence.terms != expected_terms:
            raise SimulatedBrokerError("fill terms do not match source price and model")
        if caps is not None:
            _validate_execution_caps(
                intent=self.submission.intent,
                terms=expected_terms,
                caps=caps,
            )
        execution = self.broker_events[1]
        expected_execution_id = canonical_id(
            "simulated-execution",
            expected_broker_order_id,
            fill_evidence.source_batch_sha256,
            fill_evidence.source_event_sha256,
            fill_evidence.model_sha256,
        )
        expected_execution_event_id = canonical_id(
            "simulated-broker-event",
            expected_broker_order_id,
            2,
            expected_execution_id,
            fill_evidence.semantic_sha256,
        )
        if (
            execution.kind is not BrokerOrderEventKind.EXECUTION
            or execution.broker_order_id != expected_broker_order_id
            or execution.broker_sequence != 2
            or execution.execution_id != expected_execution_id
            or execution.event_id != expected_execution_event_id
            or execution.execution_revision != 1
            or execution.occurred_at != fill_evidence.occurred_at
            or execution.received_at != fill_evidence.received_at
            or execution.quantity != fill_evidence.terms.quantity
            or execution.price != fill_evidence.terms.execution_price
            or execution.fee != fill_evidence.terms.total_fee
        ):
            raise SimulatedBrokerError("canonical execution event conflicts with fill evidence")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                SIMULATED_BROKER_CONTRACT_VERSION,
                "result",
                self.outcome,
                self.session.semantic_sha256,
                self.model.semantic_sha256,
                self.submission.semantic_sha256,
                self.activation_at,
                tuple(batch.semantic_sha256 for batch in self.market_batches),
                (
                    None
                    if self.risk_execution_caps is None
                    else self.risk_execution_caps.semantic_sha256
                ),
                (
                    None
                    if self.cap_block_evidence is None
                    else self.cap_block_evidence.semantic_sha256
                ),
                (
                    None
                    if self.deferred_source_block_evidence is None
                    else self.deferred_source_block_evidence.semantic_sha256
                ),
                None if self.fill_evidence is None else self.fill_evidence.semantic_sha256,
                tuple(event.semantic_sha256 for event in self.broker_events),
                self.order_state.semantic_sha256,
                self.completed_at,
            )
        )

    @property
    def result_id(self) -> str:
        return canonical_id("simulated-broker-result", self.semantic_sha256)


class ConservativeSimulatedBroker:
    """Submit authorized intents to a deterministic next-event full-fill model."""

    __slots__ = ("_market_batches", "_model", "_risk_authorizations", "_session")

    def __init__(
        self,
        *,
        risk_authorizations: RiskAuthorizationConsumer,
        model: SimulatedMarketOrderModel,
        session: SimulatedBrokerSession,
        market_batches: Iterable[MarketBatch],
    ) -> None:
        if type(model) is not SimulatedMarketOrderModel:
            raise SimulatedBrokerError("broker requires an exact market-order model")
        if type(session) is not SimulatedBrokerSession:
            raise SimulatedBrokerError("broker requires an exact simulated session")
        self._risk_authorizations = risk_authorizations
        self._model = model
        self._session = session
        self._market_batches = _canonical_market_batches(market_batches, session)

    @property
    def model(self) -> SimulatedMarketOrderModel:
        return self._model

    @property
    def session(self) -> SimulatedBrokerSession:
        return self._session

    @property
    def market_batches(self) -> tuple[MarketBatch, ...]:
        return self._market_batches

    def _validate_intent_tape(self, intent: OrderIntent) -> None:
        _validate_intent_tape(
            intent=intent,
            session=self._session,
            market_batches=self._market_batches,
        )

    def _preflight_activation_lower_bound(
        self,
        intent: OrderIntent,
        authorization: ExecutableRiskAuthorization | None,
    ) -> datetime:
        earliest_submission = intent.created_at
        if (
            authorization is not None
            and getattr(authorization, "status", None) is DecisionStatus.APPROVED
            and getattr(authorization, "intent_id", None) == intent.intent_id
            and getattr(authorization, "intent_payload_hash", None) == intent_payload_hash(intent)
        ):
            evaluated_at = authorization.evaluated_at.astimezone(UTC)
            expires_at = authorization.expires_at.astimezone(UTC)
            if not self._session.session.contains(evaluated_at):
                raise SimulatedBrokerError(
                    "risk evaluation is outside the configured execution session"
                )
            try:
                latest_activation_bound = expires_at + self._model.activation_latency
            except OverflowError as error:
                raise SimulatedBrokerError(
                    "approval window and activation latency exceed datetime bounds"
                ) from error
            if latest_activation_bound > self._session.session.closes_at:
                raise SimulatedBrokerError(
                    "approval window cannot guarantee activation before session close"
                )
            earliest_submission = max(earliest_submission, evaluated_at)
        try:
            return earliest_submission + self._model.activation_latency
        except OverflowError as error:
            raise SimulatedBrokerError("activation latency exceeds datetime bounds") from error

    def _preflight_submission(
        self,
        intent: OrderIntent,
        risk_decision_id: str,
    ) -> SimulatedRiskExecutionCaps | None:
        self._validate_intent_tape(intent)
        authorization = self._risk_authorizations.get(risk_decision_id)
        activation_lower_bound = self._preflight_activation_lower_bound(
            intent,
            authorization,
        )
        caps = _authorization_execution_caps(
            authorization,
            intent,
            self._session,
            self._model,
            risk_decision_id,
        )
        if caps is not None:
            return caps
        for batch in self._market_batches:
            if not batch.complete:
                if batch.watermark.event_time_through > activation_lower_bound:
                    raise SimulatedBrokerError(
                        "a potentially relevant future market batch is incomplete; "
                        "fill is unknowable"
                    )
                continue
            source_event = _source_event(batch, intent)
            self._model.execution_terms(
                side=intent.side,
                quantity=intent.quantity,
                reference_price=source_event.close_price,
            )
        return None

    def submit(
        self,
        intent: OrderIntent,
        risk_decision_id: str,
        submission_attempt_id: str,
    ) -> SimulatedBrokerResult:
        """Consume one approval, accept immediately, and fill on the first later event."""

        if type(intent) is not OrderIntent:
            raise SimulatedBrokerError("broker submission requires an exact OrderIntent")
        _require_text(risk_decision_id, "risk_decision_id")
        _require_text(submission_attempt_id, "submission_attempt_id")
        caps = self._preflight_submission(intent, risk_decision_id)

        submitted_at = self._risk_authorizations.consume(risk_decision_id, intent)
        submitted_at = submitted_at.astimezone(UTC)
        try:
            require_utc(submitted_at, "risk consumption time")
        except ValueError as error:
            raise SimulatedBrokerError(str(error)) from error
        if not self._session.session.contains(submitted_at):
            raise SimulatedBrokerError("submission time is outside the configured session")
        try:
            activation_at = submitted_at + self._model.activation_latency
        except OverflowError as error:
            raise SimulatedBrokerError("activation latency exceeds datetime bounds") from error
        if activation_at >= self._session.session.closes_at:
            raise SimulatedBrokerError("order cannot activate before the session closes")

        submission = create_order_submission(
            intent=intent,
            risk_decision_id=risk_decision_id,
            submission_attempt_id=submission_attempt_id,
            submitted_at=submitted_at,
        )
        broker_order_id = canonical_id(
            "simulated-broker-order",
            submission.order_id,
            self._model.semantic_sha256,
            self._session.semantic_sha256,
        )
        accepted = BrokerOrderEvent(
            event_id=canonical_id(
                "simulated-broker-event",
                broker_order_id,
                1,
                BrokerOrderEventKind.ACCEPTED,
                submitted_at,
            ),
            order_id=submission.order_id,
            broker_order_id=broker_order_id,
            broker_sequence=1,
            occurred_at=submitted_at,
            received_at=submitted_at,
            kind=BrokerOrderEventKind.ACCEPTED,
        )
        working_state = reduce_order_lifecycle(
            submission=submission,
            broker_events=(accepted,),
        )

        completed_at = max((activation_at, *(batch.as_of for batch in self._market_batches)))
        first_future_batch = _first_relevant_future_batch(
            market_batches=self._market_batches,
            activation_at=activation_at,
        )
        if caps is not None and first_future_batch is not None and not first_future_batch.complete:
            deferred_evidence = SimulatedDeferredSourceBlockEvidence(
                reason=SimulatedDeferredSourceBlockReason.INCOMPLETE_BATCH,
                working_order_state_sha256=working_state.semantic_sha256,
                source_batch_id=first_future_batch.batch_id,
                source_batch_sha256=first_future_batch.semantic_sha256,
                source_event_id=None,
                source_event_sha256=None,
                model_sha256=self._model.semantic_sha256,
                session_sha256=self._session.semantic_sha256,
                execution_caps_sha256=caps.semantic_sha256,
                occurred_at=first_future_batch.watermark.event_time_through,
                received_at=first_future_batch.as_of,
            )
            return SimulatedBrokerResult(
                outcome=SimulatedBrokerOutcome.WORKING_DEFERRED_SOURCE_BLOCKED,
                session=self._session,
                model=self._model,
                submission=submission,
                activation_at=activation_at,
                market_batches=self._market_batches,
                risk_execution_caps=caps,
                cap_block_evidence=None,
                deferred_source_block_evidence=deferred_evidence,
                fill_evidence=None,
                broker_events=(accepted,),
                order_state=working_state,
                completed_at=completed_at,
            )

        selected = _first_eligible_source(
            market_batches=self._market_batches,
            intent=intent,
            activation_at=activation_at,
        )
        if selected is None:
            return SimulatedBrokerResult(
                outcome=SimulatedBrokerOutcome.WORKING_NO_ELIGIBLE_EVENT,
                session=self._session,
                model=self._model,
                submission=submission,
                activation_at=activation_at,
                market_batches=self._market_batches,
                risk_execution_caps=caps,
                cap_block_evidence=None,
                deferred_source_block_evidence=None,
                fill_evidence=None,
                broker_events=(accepted,),
                order_state=working_state,
                completed_at=completed_at,
            )

        source_batch, source_event = selected
        try:
            terms = self._model.execution_terms(
                side=intent.side,
                quantity=intent.quantity,
                reference_price=source_event.close_price,
            )
        except SimulatedBrokerError:
            if caps is None:
                raise
            deferred_evidence = SimulatedDeferredSourceBlockEvidence(
                reason=SimulatedDeferredSourceBlockReason.INVALID_EXECUTION_TERMS,
                working_order_state_sha256=working_state.semantic_sha256,
                source_batch_id=source_batch.batch_id,
                source_batch_sha256=source_batch.semantic_sha256,
                source_event_id=source_event.event_id,
                source_event_sha256=source_event.semantic_sha256,
                model_sha256=self._model.semantic_sha256,
                session_sha256=self._session.semantic_sha256,
                execution_caps_sha256=caps.semantic_sha256,
                occurred_at=source_event.event_time,
                received_at=source_batch.as_of,
            )
            return SimulatedBrokerResult(
                outcome=SimulatedBrokerOutcome.WORKING_DEFERRED_SOURCE_BLOCKED,
                session=self._session,
                model=self._model,
                submission=submission,
                activation_at=activation_at,
                market_batches=self._market_batches,
                risk_execution_caps=caps,
                cap_block_evidence=None,
                deferred_source_block_evidence=deferred_evidence,
                fill_evidence=None,
                broker_events=(accepted,),
                order_state=working_state,
                completed_at=completed_at,
            )
        if caps is not None:
            violations = _execution_cap_violations(
                intent=intent,
                terms=terms,
                caps=caps,
            )
            if violations:
                block_evidence = SimulatedRiskCapBlockEvidence(
                    working_order_state_sha256=working_state.semantic_sha256,
                    source_batch_id=source_batch.batch_id,
                    source_batch_sha256=source_batch.semantic_sha256,
                    source_event_id=source_event.event_id,
                    source_event_sha256=source_event.semantic_sha256,
                    model_sha256=self._model.semantic_sha256,
                    session_sha256=self._session.semantic_sha256,
                    execution_caps_sha256=caps.semantic_sha256,
                    terms=terms,
                    violations=violations,
                    occurred_at=source_event.event_time,
                    received_at=source_batch.as_of,
                )
                return SimulatedBrokerResult(
                    outcome=SimulatedBrokerOutcome.WORKING_RISK_CAP_BLOCKED,
                    session=self._session,
                    model=self._model,
                    submission=submission,
                    activation_at=activation_at,
                    market_batches=self._market_batches,
                    risk_execution_caps=caps,
                    cap_block_evidence=block_evidence,
                    deferred_source_block_evidence=None,
                    fill_evidence=None,
                    broker_events=(accepted,),
                    order_state=working_state,
                    completed_at=completed_at,
                )
        evidence = SimulatedFillEvidence(
            working_order_state_sha256=working_state.semantic_sha256,
            source_batch_id=source_batch.batch_id,
            source_batch_sha256=source_batch.semantic_sha256,
            source_event_id=source_event.event_id,
            source_event_sha256=source_event.semantic_sha256,
            model_sha256=self._model.semantic_sha256,
            session_sha256=self._session.semantic_sha256,
            terms=terms,
            occurred_at=source_event.event_time,
            received_at=source_batch.as_of,
        )
        execution_id = canonical_id(
            "simulated-execution",
            broker_order_id,
            evidence.source_batch_sha256,
            evidence.source_event_sha256,
            evidence.model_sha256,
        )
        execution = BrokerOrderEvent(
            event_id=canonical_id(
                "simulated-broker-event",
                broker_order_id,
                2,
                execution_id,
                evidence.semantic_sha256,
            ),
            order_id=submission.order_id,
            broker_order_id=broker_order_id,
            broker_sequence=2,
            occurred_at=evidence.occurred_at,
            received_at=evidence.received_at,
            kind=BrokerOrderEventKind.EXECUTION,
            execution_id=execution_id,
            execution_revision=1,
            quantity=terms.quantity,
            price=terms.execution_price,
            fee=terms.total_fee,
        )
        broker_events = (accepted, execution)
        order_state = reduce_order_lifecycle(
            submission=submission,
            broker_events=broker_events,
        )
        return SimulatedBrokerResult(
            outcome=SimulatedBrokerOutcome.FILLED,
            session=self._session,
            model=self._model,
            submission=submission,
            activation_at=activation_at,
            market_batches=self._market_batches,
            risk_execution_caps=caps,
            cap_block_evidence=None,
            deferred_source_block_evidence=None,
            fill_evidence=evidence,
            broker_events=broker_events,
            order_state=order_state,
            completed_at=completed_at,
        )
