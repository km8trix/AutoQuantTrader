"""Mandatory, persisted, single-use Phase 0 risk approvals."""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Protocol

from packages.domain.canonical import canonical_decimal_text, canonical_persisted_decimal
from packages.domain.clock import Clock
from packages.domain.decimal_math import (
    DECIMAL_ARITHMETIC_VERSION,
    exact_decimal_add,
    exact_decimal_subtract,
)
from packages.domain.identifiers import deterministic_id
from packages.domain.models import (
    PHASE0_RISK_POLICY_VERSION,
    DecisionStatus,
    OrderIntent,
    RiskDecision,
    RiskRuleResult,
    Side,
    require_aware,
)


class RiskAuthorizationError(RuntimeError):
    """Raised when execution lacks a valid persisted approval."""


@dataclass(frozen=True, slots=True)
class RiskAccountSnapshot:
    """Versioned account capacity supplied by the authoritative accounting projection."""

    account_id: str
    version: str
    available_cash: Decimal

    def __post_init__(self) -> None:
        if not self.account_id or not self.version:
            raise ValueError("risk account snapshot requires account and version IDs")
        if (
            type(self.available_cash) is not Decimal
            or not self.available_cash.is_finite()
            or self.available_cash < 0
        ):
            raise ValueError("available cash must be finite and non-negative")
        object.__setattr__(
            self,
            "available_cash",
            canonical_persisted_decimal(self.available_cash, "available cash"),
        )


class RiskDecisionIssuer(Protocol):
    """Narrow authority capability; callers can supply only an immutable intent."""

    def authorize(self, intent: OrderIntent) -> RiskDecision: ...


class ExecutableRiskAuthorization(Protocol):
    """Minimum immutable authorization evidence required at execution."""

    @property
    def decision_id(self) -> str: ...

    @property
    def intent_id(self) -> str: ...

    @property
    def intent_payload_hash(self) -> str: ...

    @property
    def status(self) -> DecisionStatus: ...

    @property
    def evaluated_at(self) -> datetime: ...

    @property
    def expires_at(self) -> datetime: ...


class RiskAuthorizationConsumer(Protocol):
    """Narrow execution capability; it cannot create or persist approvals."""

    def get(self, decision_id: str) -> ExecutableRiskAuthorization | None: ...

    def consume(self, decision_id: str, intent: OrderIntent) -> datetime: ...


class RiskDecisionRepository(RiskDecisionIssuer, RiskAuthorizationConsumer, Protocol):
    """Combined application port; execution receives only its consumer capability."""


def intent_payload_hash(intent: OrderIntent) -> str:
    """Hash every execution-relevant intent field using a canonical representation."""

    payload = {
        "created_at": intent.created_at.astimezone(UTC).isoformat(),
        "decimal_arithmetic_version": DECIMAL_ARITHMETIC_VERSION,
        "decision_event_id": intent.decision_event_id,
        "decision_event_time": intent.decision_event_time.astimezone(UTC).isoformat(),
        "decision_trigger_sha256": intent.decision_trigger.semantic_sha256,
        "expires_at": intent.expires_at.astimezone(UTC).isoformat(),
        "instrument_id": intent.instrument_id,
        "intent_id": intent.intent_id,
        "intent_batch_id": intent.intent_batch_id,
        "portfolio_snapshot_sha256": intent.portfolio_snapshot_sha256,
        "quantity": canonical_decimal_text(intent.quantity),
        "reference_price": canonical_decimal_text(intent.reference_price),
        "reference_event_sha256": intent.reference_event_sha256,
        "side": intent.side.value,
        "symbol": intent.symbol,
        "target_id": intent.target_id,
        "target_sha256": intent.target_sha256,
        "strategy_id": intent.strategy_id,
        "strategy_version": intent.strategy_version,
        "strategy_configuration_sha256": intent.strategy_configuration_sha256,
    }
    canonical = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class RiskLimits:
    allowed_instruments: frozenset[str]
    max_order_quantity: Decimal
    max_order_notional: Decimal
    minimum_cash_buffer: Decimal
    estimated_fee: Decimal = Decimal("1.00")
    approval_ttl: timedelta = timedelta(seconds=30)

    def __post_init__(self) -> None:
        if type(self.allowed_instruments) is not frozenset or not self.allowed_instruments:
            raise ValueError("risk allow-list must be a non-empty immutable frozenset")
        if any(
            type(instrument_id) is not str
            or not instrument_id
            or instrument_id != instrument_id.strip()
            for instrument_id in self.allowed_instruments
        ):
            raise ValueError("risk allow-list IDs must be non-empty trimmed strings")
        for value, name in (
            (self.max_order_quantity, "max order quantity"),
            (self.max_order_notional, "max order notional"),
        ):
            if type(value) is not Decimal or not value.is_finite() or value <= 0:
                raise ValueError(f"{name} must be finite and positive")
        if (
            type(self.minimum_cash_buffer) is not Decimal
            or type(self.estimated_fee) is not Decimal
            or not self.minimum_cash_buffer.is_finite()
            or not self.estimated_fee.is_finite()
            or self.minimum_cash_buffer < 0
            or self.estimated_fee < 0
        ):
            raise ValueError("cash buffer and estimated fee must be finite and non-negative")
        if self.approval_ttl <= timedelta(0):
            raise ValueError("approval TTL must be positive")
        for field_name in (
            "max_order_quantity",
            "max_order_notional",
            "minimum_cash_buffer",
            "estimated_fee",
        ):
            object.__setattr__(
                self,
                field_name,
                canonical_persisted_decimal(getattr(self, field_name), field_name),
            )


class RiskAccountSnapshotProvider(Protocol):
    """Trusted accounting projection used by the authorization service."""

    def current(self) -> RiskAccountSnapshot: ...


@dataclass(frozen=True, slots=True)
class FixedRiskAccountSnapshotProvider:
    snapshot: RiskAccountSnapshot

    def current(self) -> RiskAccountSnapshot:
        return self.snapshot


@dataclass(frozen=True, slots=True)
class RiskAuthority:
    """Immutable dependencies that callers cannot override per authorization."""

    limits: RiskLimits
    account_snapshots: RiskAccountSnapshotProvider
    evaluation_clock: Clock
    consumption_clock: Clock


def evaluate_risk_decision(
    intent: OrderIntent,
    limits: RiskLimits,
    available_cash_after_existing_reservations: Decimal,
    evaluated_at: datetime,
) -> RiskDecision:
    """Apply the one canonical Phase 0 policy to current unreserved capacity."""

    require_aware(evaluated_at, "evaluated_at")
    if evaluated_at < intent.created_at:
        raise RiskAuthorizationError("risk evaluation cannot precede intent creation")
    if (
        type(available_cash_after_existing_reservations) is not Decimal
        or not available_cash_after_existing_reservations.is_finite()
        or available_cash_after_existing_reservations < 0
    ):
        raise ValueError("unreserved cash must be finite and non-negative")
    available_cash_after_existing_reservations = canonical_persisted_decimal(
        available_cash_after_existing_reservations,
        "unreserved cash",
    )

    notional = intent.notional
    required_cash = exact_decimal_add(notional, limits.estimated_fee)
    remaining_cash = exact_decimal_subtract(
        available_cash_after_existing_reservations,
        required_cash,
    )
    rules = (
        RiskRuleResult(
            rule="instrument_allow_list",
            passed=intent.instrument_id in limits.allowed_instruments,
            observed=intent.instrument_id,
            limit=",".join(sorted(limits.allowed_instruments)),
        ),
        RiskRuleResult(
            rule="long_only",
            passed=intent.side is Side.BUY,
            observed=intent.side.value,
            limit=Side.BUY.value,
        ),
        RiskRuleResult(
            rule="quantity",
            passed=intent.quantity <= limits.max_order_quantity,
            observed=canonical_decimal_text(intent.quantity),
            limit=canonical_decimal_text(limits.max_order_quantity),
        ),
        RiskRuleResult(
            rule="notional",
            passed=notional <= limits.max_order_notional,
            observed=canonical_decimal_text(notional),
            limit=canonical_decimal_text(limits.max_order_notional),
        ),
        RiskRuleResult(
            rule="cash_buffer",
            passed=remaining_cash >= limits.minimum_cash_buffer,
            observed=canonical_decimal_text(remaining_cash),
            limit=canonical_decimal_text(limits.minimum_cash_buffer),
        ),
        RiskRuleResult(
            rule="intent_freshness",
            passed=evaluated_at < intent.expires_at,
            observed=evaluated_at.isoformat(),
            limit=intent.expires_at.isoformat(),
        ),
    )
    approved = all(rule.passed for rule in rules)
    return RiskDecision(
        decision_id=deterministic_id("risk-decision", intent.intent_id, evaluated_at.isoformat()),
        intent_id=intent.intent_id,
        intent_payload_hash=intent_payload_hash(intent),
        policy_version=PHASE0_RISK_POLICY_VERSION,
        status=DecisionStatus.APPROVED if approved else DecisionStatus.REJECTED,
        evaluated_at=evaluated_at,
        expires_at=(
            min(intent.expires_at, evaluated_at + limits.approval_ttl)
            if approved
            else evaluated_at + limits.approval_ttl
        ),
        rules=rules,
        reserved_cash=required_cash if approved else Decimal("0"),
    )


def validate_authorization_consumption(
    authorization: ExecutableRiskAuthorization,
    intent: OrderIntent,
    consumed_at: datetime,
) -> None:
    """Validate the common executable-authorization contract."""

    require_aware(consumed_at, "consumed_at")
    if authorization.intent_id != intent.intent_id:
        raise RiskAuthorizationError("risk decision does not authorize this intent")
    if authorization.intent_payload_hash != intent_payload_hash(intent):
        raise RiskAuthorizationError("risk decision payload does not match this intent")
    if authorization.status is not DecisionStatus.APPROVED:
        raise RiskAuthorizationError("rejected risk decisions cannot authorize execution")
    if consumed_at < intent.created_at or consumed_at < authorization.evaluated_at:
        raise RiskAuthorizationError("risk approval cannot be consumed before evaluation")
    if consumed_at >= authorization.expires_at or consumed_at >= intent.expires_at:
        raise RiskAuthorizationError("risk approval has expired")


def validate_consumption(
    decision: RiskDecision,
    intent: OrderIntent,
    consumed_at: datetime,
) -> None:
    """Preserve the Phase 0 validation entry point."""

    validate_authorization_consumption(decision, intent, consumed_at)


class InMemoryRiskDecisionRepository:
    """Thread-safe local adapter that mirrors durable issuance and consumption rules."""

    def __init__(self, authority: RiskAuthority) -> None:
        self._authority = authority
        self._decisions: dict[str, RiskDecision] = {}
        self._intent_decisions: dict[str, str] = {}
        self._intent_snapshots: dict[str, tuple[str, str]] = {}
        self._consumed: set[str] = set()
        self._snapshots: dict[str, tuple[str, Decimal, Decimal]] = {}
        self._lock = threading.Lock()

    def authorize(self, intent: OrderIntent) -> RiskDecision:
        snapshot = self._authority.account_snapshots.current()
        evaluated_at = self._authority.evaluation_clock.now()
        with self._lock:
            state = self._snapshots.get(snapshot.account_id)
            if state is None:
                capacity, reserved = snapshot.available_cash, Decimal("0")
            else:
                version, capacity, reserved = state
                if version != snapshot.version:
                    raise RiskAuthorizationError("risk account snapshot version is stale")
                if capacity != snapshot.available_cash:
                    raise RiskAuthorizationError("risk snapshot version changed its cash capacity")
            prior_decision_id = self._intent_decisions.get(intent.intent_id)
            if prior_decision_id is not None:
                prior = self._decisions[prior_decision_id]
                if prior.intent_payload_hash != intent_payload_hash(intent):
                    raise RiskAuthorizationError("intent IDs are immutable")
                if self._intent_snapshots[intent.intent_id] != (
                    snapshot.account_id,
                    snapshot.version,
                ):
                    raise RiskAuthorizationError(
                        "risk decision belongs to a different account snapshot"
                    )
                return prior
            decision = evaluate_risk_decision(
                intent,
                self._authority.limits,
                exact_decimal_subtract(capacity, reserved),
                evaluated_at,
            )
            existing = self._decisions.get(decision.decision_id)
            if existing is not None:
                if existing != decision:
                    raise RiskAuthorizationError("risk decision IDs are immutable")
                return existing
            self._decisions[decision.decision_id] = decision
            self._intent_decisions[intent.intent_id] = decision.decision_id
            self._intent_snapshots[intent.intent_id] = (
                snapshot.account_id,
                snapshot.version,
            )
            if decision.status is DecisionStatus.APPROVED:
                reserved = exact_decimal_add(reserved, decision.reserved_cash)
            self._snapshots[snapshot.account_id] = (
                snapshot.version,
                capacity,
                reserved,
            )
            return decision

    def get(self, decision_id: str) -> RiskDecision | None:
        with self._lock:
            return self._decisions.get(decision_id)

    def consume(self, decision_id: str, intent: OrderIntent) -> datetime:
        consumed_at = self._authority.consumption_clock.now()
        with self._lock:
            decision = self._decisions.get(decision_id)
            if decision is None:
                raise RiskAuthorizationError("execution requires a persisted risk decision")
            validate_consumption(decision, intent, consumed_at)
            if decision_id in self._consumed:
                raise RiskAuthorizationError("risk approval has already been consumed")
            self._consumed.add(decision_id)
            return consumed_at

    def was_consumed(self, decision_id: str) -> bool:
        with self._lock:
            return decision_id in self._consumed

    def reserved_cash(self, snapshot: RiskAccountSnapshot) -> Decimal:
        with self._lock:
            state = self._snapshots.get(snapshot.account_id)
            if state is None:
                return Decimal("0")
            version, capacity, reserved = state
            if version != snapshot.version or capacity != snapshot.available_cash:
                raise RiskAuthorizationError("risk snapshot does not match reserved capacity")
            return reserved
