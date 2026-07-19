"""Immutable domain facts used by the Phase 0 walking thread."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum

from packages.domain.canonical import (
    canonical_decimal,
    canonical_json_bytes,
    canonical_persisted_decimal,
)
from packages.domain.decimal_math import exact_decimal_multiply, exact_decimal_sum
from packages.domain.decision import DecisionTrigger, DecisionTriggerKind


def require_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")


def require_utc(value: datetime, field_name: str) -> None:
    require_aware(value, field_name)
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{field_name} must be UTC")


def require_positive(value: Decimal, field_name: str) -> None:
    if type(value) is not Decimal or not value.is_finite() or value <= 0:
        raise ValueError(f"{field_name} must be a finite positive decimal")


class Side(StrEnum):
    BUY = "buy"
    SELL = "sell"


class DecisionStatus(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class OrderStatus(StrEnum):
    WORKING = "working"
    FILLED = "filled"


PHASE0_RISK_POLICY_VERSION = "phase0-v1"
PHASE0_REQUIRED_RISK_RULES = (
    "instrument_allow_list",
    "long_only",
    "quantity",
    "notional",
    "cash_buffer",
    "intent_freshness",
)


@dataclass(frozen=True, slots=True)
class MarketEvent:
    event_id: str
    instrument_id: str
    symbol: str
    event_time: datetime
    available_at: datetime
    close_price: Decimal
    source: str = "fixed-tape"
    source_sequence: int | None = None
    observation_id: str | None = None
    revision: int = 1
    supersedes_event_revision_id: str | None = None

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.event_id, "event_id"),
            (self.instrument_id, "instrument_id"),
            (self.symbol, "symbol"),
            (self.source, "source"),
        ):
            if not value or value != value.strip():
                raise ValueError(f"{field_name} must be non-empty and trimmed")
        if self.symbol != self.symbol.upper():
            raise ValueError("symbol must use its canonical uppercase form")
        if self.observation_id is not None and (
            not self.observation_id or self.observation_id != self.observation_id.strip()
        ):
            raise ValueError("observation_id must be non-empty and trimmed")
        if self.source_sequence is not None and (
            type(self.source_sequence) is not int or self.source_sequence < 0
        ):
            raise ValueError("source_sequence must be a non-negative integer")
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("revision must be a positive integer")
        if self.revision == 1 and self.supersedes_event_revision_id is not None:
            raise ValueError("an initial event revision cannot supersede another revision")
        if self.revision > 1 and (
            self.observation_id is None or not self.supersedes_event_revision_id
        ):
            raise ValueError(
                "a correction requires an observation_id and superseded event revision"
            )
        if self.supersedes_event_revision_id == self.event_id:
            raise ValueError("an event revision cannot supersede itself")
        require_utc(self.event_time, "event_time")
        require_utc(self.available_at, "available_at")
        require_positive(self.close_price, "close_price")
        object.__setattr__(
            self,
            "close_price",
            canonical_persisted_decimal(self.close_price, "close_price"),
        )
        if self.available_at < self.event_time:
            raise ValueError("available_at cannot precede event_time")

    @property
    def observation_key(self) -> str:
        return self.observation_id or self.event_id


@dataclass(frozen=True, slots=True)
class PositionTarget:
    instrument_id: str
    symbol: str
    quantity: Decimal

    def __post_init__(self) -> None:
        if type(self.quantity) is not Decimal:
            raise ValueError("target quantity must be an exact Decimal")
        if not self.instrument_id or self.instrument_id != self.instrument_id.strip():
            raise ValueError("target instrument_id must be non-empty and trimmed")
        if not self.symbol or self.symbol != self.symbol.strip():
            raise ValueError("target symbol must be non-empty and trimmed")
        if self.symbol != self.symbol.upper():
            raise ValueError("target symbol must use its canonical uppercase form")
        if not self.quantity.is_finite() or self.quantity < 0:
            raise ValueError("target quantity must be finite and non-negative")
        if self.quantity != self.quantity.to_integral_value():
            raise ValueError("target quantity must be a whole number of shares")
        object.__setattr__(
            self,
            "quantity",
            canonical_persisted_decimal(self.quantity, "target quantity"),
        )


@dataclass(frozen=True, slots=True)
class TargetPortfolio:
    target_id: str
    strategy_id: str
    strategy_version: str
    decision_trigger: DecisionTrigger
    as_of: datetime
    expires_at: datetime
    targets: tuple[PositionTarget, ...]
    rebalance_generation: int = 1
    full_snapshot: bool = True

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.target_id, "target_id"),
            (self.strategy_id, "strategy_id"),
            (self.strategy_version, "strategy_version"),
        ):
            if not value or value != value.strip():
                raise ValueError(f"{field_name} must be non-empty and trimmed")
        if type(self.decision_trigger) is not DecisionTrigger:
            raise ValueError("target decision_trigger must be an exact DecisionTrigger")
        require_utc(self.as_of, "as_of")
        require_utc(self.expires_at, "expires_at")
        if self.expires_at <= self.as_of:
            raise ValueError("target must expire after its as_of time")
        if type(self.targets) is not tuple:
            raise ValueError("position targets must be an immutable tuple")
        if not self.targets:
            raise ValueError("target portfolio cannot be empty")
        if any(type(target) is not PositionTarget for target in self.targets):
            raise ValueError("position targets must contain immutable PositionTarget values")
        instrument_ids = tuple(target.instrument_id for target in self.targets)
        if instrument_ids != tuple(sorted(set(instrument_ids))):
            raise ValueError("position targets must be unique and sorted by instrument_id")
        if type(self.rebalance_generation) is not int or self.rebalance_generation < 1:
            raise ValueError("rebalance_generation must be a positive integer")
        if type(self.full_snapshot) is not bool:
            raise ValueError("full_snapshot must be a boolean")
        if self.as_of != self.decision_trigger.as_of:
            raise ValueError("target and decision trigger must share the same as_of")

    @property
    def decision_batch_id(self) -> str:
        """Return the market-batch cause for legacy market-only consumers."""

        if self.decision_trigger.kind is not DecisionTriggerKind.MARKET_BATCH:
            raise ValueError("target was not caused by a market batch")
        return self.decision_trigger.trigger_id

    @property
    def decision_clock_event_id(self) -> str:
        if self.decision_trigger.kind is not DecisionTriggerKind.CLOCK:
            raise ValueError("target was not caused by a clock event")
        return self.decision_trigger.trigger_id

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                (
                    "phase2-target-portfolio-v1",
                    self.target_id,
                    self.strategy_id,
                    self.strategy_version,
                    self.decision_trigger.semantic_sha256,
                    self.as_of,
                    self.expires_at,
                    tuple(
                        (target.instrument_id, target.symbol, target.quantity)
                        for target in self.targets
                    ),
                    self.rebalance_generation,
                    self.full_snapshot,
                )
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class OrderIntent:
    intent_id: str
    target_id: str
    instrument_id: str
    symbol: str
    side: Side
    quantity: Decimal
    reference_price: Decimal
    decision_event_id: str
    decision_event_time: datetime
    created_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        require_aware(self.created_at, "created_at")
        require_aware(self.expires_at, "expires_at")
        require_aware(self.decision_event_time, "decision_event_time")
        require_positive(self.quantity, "quantity")
        if self.quantity != self.quantity.to_integral_value():
            raise ValueError("intent quantity must be a whole number of shares")
        require_positive(self.reference_price, "reference_price")
        object.__setattr__(
            self,
            "quantity",
            canonical_persisted_decimal(self.quantity, "intent quantity"),
        )
        object.__setattr__(
            self,
            "reference_price",
            canonical_persisted_decimal(self.reference_price, "intent reference_price"),
        )
        if self.created_at < self.decision_event_time:
            raise ValueError("intent cannot be created before its decision event")
        if self.expires_at <= self.created_at:
            raise ValueError("intent must expire after it is created")

    @property
    def notional(self) -> Decimal:
        return exact_decimal_multiply(self.quantity, self.reference_price)


@dataclass(frozen=True, slots=True)
class RiskRuleResult:
    rule: str
    passed: bool
    observed: str
    limit: str

    def __post_init__(self) -> None:
        if not all(type(value) is str for value in (self.rule, self.observed, self.limit)):
            raise ValueError("risk rule fields must be strings")
        if not self.rule:
            raise ValueError("risk rule name cannot be empty")
        if type(self.passed) is not bool:
            raise ValueError("risk rule passed must be a boolean")


@dataclass(frozen=True, slots=True)
class RiskDecision:
    decision_id: str
    intent_id: str
    intent_payload_hash: str
    policy_version: str
    status: DecisionStatus
    evaluated_at: datetime
    expires_at: datetime
    rules: tuple[RiskRuleResult, ...]
    reserved_cash: Decimal

    def __post_init__(self) -> None:
        require_aware(self.evaluated_at, "evaluated_at")
        require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.evaluated_at:
            raise ValueError("risk decision must have a positive TTL")
        if (
            type(self.reserved_cash) is not Decimal
            or not self.reserved_cash.is_finite()
            or self.reserved_cash < 0
        ):
            raise ValueError("reserved cash must be finite and non-negative")
        object.__setattr__(
            self,
            "reserved_cash",
            canonical_persisted_decimal(self.reserved_cash, "reserved cash"),
        )
        if len(self.intent_payload_hash) != 64 or any(
            character not in "0123456789abcdef" for character in self.intent_payload_hash
        ):
            raise ValueError("intent payload hash must be a lowercase SHA-256 digest")
        if self.policy_version != PHASE0_RISK_POLICY_VERSION:
            raise ValueError("unsupported risk policy version")
        rule_names = tuple(rule.rule for rule in self.rules)
        if rule_names != PHASE0_REQUIRED_RISK_RULES:
            raise ValueError("risk decision must contain the complete versioned rule set")
        expected = (
            DecisionStatus.APPROVED
            if all(rule.passed for rule in self.rules)
            else DecisionStatus.REJECTED
        )
        if self.status is not expected:
            raise ValueError("risk decision status must agree with its rule results")
        if self.status is DecisionStatus.APPROVED and self.reserved_cash <= 0:
            raise ValueError("approved risk decisions require a positive reservation")
        if self.status is DecisionStatus.REJECTED and self.reserved_cash != 0:
            raise ValueError("rejected risk decisions cannot reserve cash")


@dataclass(frozen=True, slots=True)
class Order:
    order_id: str
    client_order_id: str
    intent_id: str
    risk_decision_id: str
    instrument_id: str
    symbol: str
    side: Side
    quantity: Decimal
    activation_after_event_time: datetime
    submitted_at: datetime
    status: OrderStatus
    filled_quantity: Decimal = Decimal("0")

    def __post_init__(self) -> None:
        require_aware(self.submitted_at, "submitted_at")
        require_aware(self.activation_after_event_time, "activation_after_event_time")
        require_positive(self.quantity, "quantity")
        if self.quantity != self.quantity.to_integral_value():
            raise ValueError("order quantity must be a whole number of shares")
        if self.submitted_at < self.activation_after_event_time:
            raise ValueError("order submission cannot precede its decision event")
        if (
            not self.filled_quantity.is_finite()
            or self.filled_quantity < 0
            or self.filled_quantity > self.quantity
        ):
            raise ValueError("filled quantity must be finite and between zero and order quantity")
        if self.filled_quantity != self.filled_quantity.to_integral_value():
            raise ValueError("filled quantity must be a whole number of shares")
        object.__setattr__(
            self,
            "quantity",
            canonical_persisted_decimal(self.quantity, "order quantity"),
        )
        object.__setattr__(
            self,
            "filled_quantity",
            canonical_persisted_decimal(self.filled_quantity, "order filled_quantity"),
        )


@dataclass(frozen=True, slots=True)
class Fill:
    fill_id: str
    order_id: str
    instrument_id: str
    symbol: str
    side: Side
    quantity: Decimal
    price: Decimal
    fee: Decimal
    executed_at: datetime

    def __post_init__(self) -> None:
        require_aware(self.executed_at, "executed_at")
        require_positive(self.quantity, "quantity")
        if self.quantity != self.quantity.to_integral_value():
            raise ValueError("fill quantity must be a whole number of shares")
        require_positive(self.price, "price")
        if type(self.fee) is not Decimal or not self.fee.is_finite() or self.fee < 0:
            raise ValueError("fill fee must be finite and non-negative")
        object.__setattr__(
            self,
            "quantity",
            canonical_persisted_decimal(self.quantity, "fill quantity"),
        )
        object.__setattr__(
            self,
            "price",
            canonical_persisted_decimal(self.price, "fill price"),
        )
        object.__setattr__(self, "fee", canonical_persisted_decimal(self.fee, "fill fee"))

    @property
    def notional(self) -> Decimal:
        return exact_decimal_multiply(self.quantity, self.price)


@dataclass(frozen=True, slots=True)
class Posting:
    account: str
    currency: str
    debit: Decimal = Decimal("0")
    credit: Decimal = Decimal("0")
    units_delta: Decimal = Decimal("0")
    instrument_id: str | None = None

    def __post_init__(self) -> None:
        if any(type(value) is not Decimal for value in (self.debit, self.credit, self.units_delta)):
            raise ValueError("posting amounts and units must be exact Decimals")
        if not all(value.is_finite() for value in (self.debit, self.credit, self.units_delta)):
            raise ValueError("posting amounts and units must be finite")
        if self.debit < 0 or self.credit < 0:
            raise ValueError("posting amounts cannot be negative")
        if (self.debit > 0) == (self.credit > 0):
            raise ValueError("a posting must have exactly one positive debit or credit")
        if self.units_delta and self.instrument_id is None:
            raise ValueError("unit postings require an instrument ID")
        object.__setattr__(
            self,
            "debit",
            canonical_persisted_decimal(self.debit, "posting debit"),
        )
        object.__setattr__(
            self,
            "credit",
            canonical_persisted_decimal(self.credit, "posting credit"),
        )
        object.__setattr__(
            self,
            "units_delta",
            canonical_persisted_decimal(self.units_delta, "posting units_delta"),
        )


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    entry_id: str
    event_type: str
    reference_id: str
    posted_at: datetime
    postings: tuple[Posting, ...]

    def __post_init__(self) -> None:
        require_aware(self.posted_at, "posted_at")
        if len(self.postings) < 2:
            raise ValueError("ledger entries require at least two postings")
        currencies = {posting.currency for posting in self.postings}
        if len(currencies) != 1:
            raise ValueError("Phase 0 ledger entries must use one currency")
        total_debits = exact_decimal_sum(posting.debit for posting in self.postings)
        total_credits = exact_decimal_sum(posting.credit for posting in self.postings)
        if total_debits != total_credits:
            raise ValueError("ledger entry is not balanced")

    @property
    def currency(self) -> str:
        return self.postings[0].currency

    @property
    def total(self) -> Decimal:
        return exact_decimal_sum(posting.debit for posting in self.postings)


@dataclass(frozen=True, slots=True)
class Position:
    instrument_id: str
    symbol: str
    quantity: Decimal
    average_cost: Decimal
    market_price: Decimal

    def __post_init__(self) -> None:
        if type(self.quantity) is not Decimal or not self.quantity.is_finite() or self.quantity < 0:
            raise ValueError("position quantity must be finite and non-negative")
        if self.quantity != self.quantity.to_integral_value():
            raise ValueError("position quantity must be a whole number of shares")
        if (
            type(self.average_cost) is not Decimal
            or not self.average_cost.is_finite()
            or self.average_cost < 0
        ):
            raise ValueError("average cost must be finite and non-negative")
        require_positive(self.market_price, "market_price")
        object.__setattr__(self, "quantity", canonical_decimal(self.quantity))
        object.__setattr__(self, "average_cost", canonical_decimal(self.average_cost))
        object.__setattr__(self, "market_price", canonical_decimal(self.market_price))

    @property
    def market_value(self) -> Decimal:
        return exact_decimal_multiply(self.quantity, self.market_price)


@dataclass(frozen=True, slots=True)
class AccountProjection:
    currency: str
    cash: Decimal
    equity: Decimal
    realized_pnl: Decimal
    unrealized_pnl: Decimal
    gross_exposure: Decimal
    net_exposure: Decimal

    def __post_init__(self) -> None:
        values = (
            self.cash,
            self.equity,
            self.realized_pnl,
            self.unrealized_pnl,
            self.gross_exposure,
            self.net_exposure,
        )
        if not all(type(value) is Decimal and value.is_finite() for value in values):
            raise ValueError("account projection values must be finite")
        if self.gross_exposure < 0:
            raise ValueError("gross exposure cannot be negative")
        for field_name in (
            "cash",
            "equity",
            "realized_pnl",
            "unrealized_pnl",
            "gross_exposure",
            "net_exposure",
        ):
            object.__setattr__(self, field_name, canonical_decimal(getattr(self, field_name)))


@dataclass(frozen=True, slots=True)
class TraceStep:
    trace_id: str
    stage: str
    status: str
    occurred_at: datetime
    title: str
    detail: str

    def __post_init__(self) -> None:
        require_aware(self.occurred_at, "occurred_at")


FIXED_NOW = datetime(2026, 7, 15, 13, 32, tzinfo=UTC)
