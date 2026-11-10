"""Pure all-or-none risk evaluation for immutable order-intent batches."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Protocol, TypeVar

from packages.domain.account_projection import CanonicalAccountProjection
from packages.domain.canonical import (
    canonical_decimal_text,
    canonical_json_bytes,
    canonical_persisted_decimal,
)
from packages.domain.clock import Clock
from packages.domain.decimal_math import (
    exact_decimal_add,
    exact_decimal_multiply,
    exact_decimal_subtract,
    exact_decimal_sum,
)
from packages.domain.identifiers import canonical_id
from packages.domain.models import (
    DecisionStatus,
    OrderIntent,
    OrderIntentBatch,
    PortfolioPosition,
    PortfolioSnapshot,
    RiskRuleResult,
    Side,
    TargetPortfolio,
    require_utc,
)
from packages.domain.portfolio import target_to_intent_batch
from packages.domain.risk import intent_payload_hash
from packages.domain.settlement_ledger import CanonicalSettlementLedgerState

BATCH_RISK_CONTRACT_VERSION = "phase2-atomic-batch-risk-v2"
SnapshotTransactionResultT = TypeVar("SnapshotTransactionResultT")

BATCH_RISK_RULES = (
    "operational_state",
    "active_instrument",
    "instrument_allow_list",
    "instrument_halt",
    "session",
    "snapshot_freshness",
    "reference_price_freshness",
    "intent_freshness",
    "quantity",
    "order_notional",
    "batch_notional",
    "cash_buffer",
    "sell_capacity",
    "instrument_gross_exposure",
    "account_gross_exposure",
    "daily_order_count",
    "open_order_count",
)


class BatchRiskError(ValueError):
    """Raised when a batch cannot be evaluated without inventing risk facts."""


class BatchRiskFactConflict(BatchRiskError):
    """Raised when one supposedly immutable identity has conflicting semantics."""


class BatchRiskOperationalState(StrEnum):
    RUNNING = "running"
    PAUSED = "paused"
    HALTED = "halted"


class BatchRiskSessionKind(StrEnum):
    REGULAR = "regular"
    HALF_DAY = "half_day"


class BatchRiskDecisionStatus(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"
    NO_ACTION = "no_action"


class ActiveCapacityReservationState(StrEnum):
    """Risk-facing state of one durable reservation capacity projection."""

    ACTIVE = "active"
    PARTIALLY_RELEASED = "partially_released"
    FROZEN = "frozen"


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: str, field_name: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise BatchRiskError(f"{field_name} must be a non-empty, trimmed string")


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise BatchRiskError(f"{field_name} must be a lowercase SHA-256 digest")


def _persisted_decimal(
    value: Decimal,
    field_name: str,
    *,
    positive: bool = False,
) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise BatchRiskError(f"{field_name} must be a finite exact Decimal")
    if value < 0 or (positive and value == 0):
        qualifier = "positive" if positive else "non-negative"
        raise BatchRiskError(f"{field_name} must be {qualifier}")
    try:
        return canonical_persisted_decimal(value, field_name)
    except ValueError as error:
        raise BatchRiskError(str(error)) from error


def _signed_persisted_decimal(value: Decimal, field_name: str) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise BatchRiskError(f"{field_name} must be a finite exact Decimal")
    try:
        return canonical_persisted_decimal(value, field_name)
    except ValueError as error:
        raise BatchRiskError(str(error)) from error


def _whole_quantity(value: Decimal, field_name: str) -> Decimal:
    quantity = _persisted_decimal(value, field_name, positive=True)
    if quantity != quantity.to_integral_value():
        raise BatchRiskError(f"{field_name} must be a whole number of shares")
    return quantity


def _require_utc(value: datetime, field_name: str) -> None:
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise BatchRiskError(str(error)) from error


def _timedelta_microseconds(value: timedelta) -> int:
    return value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds


def _duration_text(value: timedelta) -> str:
    return str(_timedelta_microseconds(value))


def _decimal_bindings(values: dict[str, Decimal]) -> str:
    return ",".join(
        f"{key}:{canonical_decimal_text(value)}" for key, value in sorted(values.items())
    )


@dataclass(frozen=True, slots=True)
class BatchRiskSession:
    """Exact calendar evidence used by evaluation and authorization consumption."""

    calendar_id: str
    calendar_version: str
    calendar_sha256: str
    venue: str
    session_label: date
    opens_at: datetime
    closes_at: datetime
    kind: BatchRiskSessionKind = BatchRiskSessionKind.REGULAR

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.calendar_id, "calendar_id"),
            (self.calendar_version, "calendar_version"),
            (self.venue, "venue"),
        ):
            _require_text(value, field_name)
        _require_sha256(self.calendar_sha256, "calendar_sha256")
        if self.venue != self.venue.upper():
            raise BatchRiskError("venue must use its canonical uppercase form")
        if type(self.session_label) is not date:
            raise BatchRiskError("session_label must be an exact date")
        _require_utc(self.opens_at, "opens_at")
        _require_utc(self.closes_at, "closes_at")
        if self.closes_at <= self.opens_at:
            raise BatchRiskError("closes_at must follow opens_at")
        if type(self.kind) is not BatchRiskSessionKind:
            raise BatchRiskError("batch risk session kind is unsupported")

    def contains(self, instant: datetime) -> bool:
        _require_utc(instant, "session instant")
        return self.opens_at <= instant < self.closes_at

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                BATCH_RISK_CONTRACT_VERSION,
                "session",
                self.calendar_id,
                self.calendar_version,
                self.calendar_sha256,
                self.venue,
                self.session_label,
                self.opens_at,
                self.closes_at,
                self.kind,
            )
        )


@dataclass(frozen=True, slots=True)
class BatchRiskLimits:
    """Versioned conservative limits and explicit reservation assumptions."""

    policy_id: str
    policy_version: str
    allowed_instruments: frozenset[str]
    max_order_quantity: Decimal
    max_order_notional: Decimal
    max_batch_notional: Decimal
    max_instrument_gross_exposure: Decimal
    max_account_gross_exposure: Decimal
    minimum_cash_buffer: Decimal
    estimated_fixed_fee: Decimal = Decimal("1.00")
    estimated_fee_per_share: Decimal = Decimal("0")
    market_order_price_buffer_per_share: Decimal = Decimal("0")
    max_snapshot_age: timedelta = timedelta(minutes=5)
    max_price_age: timedelta = timedelta(minutes=5)
    approval_ttl: timedelta = timedelta(seconds=30)
    max_daily_order_count: int = 100
    max_open_order_count: int = 20

    def __post_init__(self) -> None:
        _require_text(self.policy_id, "policy_id")
        _require_text(self.policy_version, "policy_version")
        if type(self.allowed_instruments) is not frozenset or not self.allowed_instruments:
            raise BatchRiskError("allowed_instruments must be a non-empty frozenset")
        for instrument_id in self.allowed_instruments:
            _require_text(instrument_id, "allowed instrument ID")
        for field_name in (
            "max_order_quantity",
            "max_order_notional",
            "max_batch_notional",
            "max_instrument_gross_exposure",
            "max_account_gross_exposure",
        ):
            object.__setattr__(
                self,
                field_name,
                _persisted_decimal(getattr(self, field_name), field_name, positive=True),
            )
        for field_name in (
            "minimum_cash_buffer",
            "estimated_fixed_fee",
            "estimated_fee_per_share",
            "market_order_price_buffer_per_share",
        ):
            object.__setattr__(
                self,
                field_name,
                _persisted_decimal(getattr(self, field_name), field_name),
            )
        for field_name in ("max_snapshot_age", "max_price_age", "approval_ttl"):
            value = getattr(self, field_name)
            if type(value) is not timedelta or value <= timedelta(0):
                raise BatchRiskError(f"{field_name} must be a positive exact timedelta")
        for field_name in ("max_daily_order_count", "max_open_order_count"):
            value = getattr(self, field_name)
            if type(value) is not int or value < 0:
                raise BatchRiskError(f"{field_name} must be a non-negative integer")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                BATCH_RISK_CONTRACT_VERSION,
                "limits",
                self.policy_id,
                self.policy_version,
                self.allowed_instruments,
                self.max_order_quantity,
                self.max_order_notional,
                self.max_batch_notional,
                self.max_instrument_gross_exposure,
                self.max_account_gross_exposure,
                self.minimum_cash_buffer,
                self.estimated_fixed_fee,
                self.estimated_fee_per_share,
                self.market_order_price_buffer_per_share,
                _timedelta_microseconds(self.max_snapshot_age),
                _timedelta_microseconds(self.max_price_age),
                _timedelta_microseconds(self.approval_ttl),
                self.max_daily_order_count,
                self.max_open_order_count,
            )
        )


@dataclass(frozen=True, slots=True)
class _BatchRiskProjectionAttestation:
    account_id: str
    currency: str
    available_cash: Decimal
    current_gross_exposure: Decimal
    account_projection_sha256: str
    settlement_projection_sha256: str
    account_positions: tuple[PortfolioPosition, ...]
    account_projection_as_of: datetime
    settlement_projection_as_of: datetime
    account_execution_ledger_sha256: str
    settlement_execution_ledger_sha256: str


def _attest_batch_risk_projections(
    *,
    portfolio_snapshot: PortfolioSnapshot,
    account_projection: CanonicalAccountProjection,
    settlement_projection: CanonicalSettlementLedgerState,
) -> _BatchRiskProjectionAttestation:
    """Re-prove every economic field retained by a batch-risk snapshot."""

    if type(portfolio_snapshot) is not PortfolioSnapshot:
        raise BatchRiskError("risk snapshot construction requires an exact portfolio")
    try:
        portfolio_snapshot.__post_init__()
        for portfolio_position in portfolio_snapshot.positions:
            portfolio_position.__post_init__()
        for portfolio_price in portfolio_snapshot.prices:
            portfolio_price.__post_init__()
            portfolio_price.event.__post_init__()
    except ValueError as error:
        raise BatchRiskError(f"invalid portfolio snapshot evidence: {error}") from error
    if type(account_projection) is not CanonicalAccountProjection:
        raise BatchRiskError("risk snapshot construction requires an exact account projection")
    try:
        account_projection._validate()
    except ValueError as error:
        raise BatchRiskError(f"invalid account projection evidence: {error}") from error
    if type(settlement_projection) is not CanonicalSettlementLedgerState:
        raise BatchRiskError("risk snapshot construction requires an exact settlement projection")
    try:
        settlement_projection._validate()
    except ValueError as error:
        raise BatchRiskError(f"invalid settlement projection evidence: {error}") from error
    if account_projection.account_id != settlement_projection.account_id:
        raise BatchRiskFactConflict("account and settlement projections disagree on account")
    if account_projection.currency != settlement_projection.currency:
        raise BatchRiskFactConflict("account and settlement currencies disagree")
    if account_projection.ledger != settlement_projection.trade_date_ledger:
        raise BatchRiskFactConflict(
            "account and settlement projections use different execution ledgers"
        )
    if account_projection.as_of != portfolio_snapshot.as_of:
        raise BatchRiskFactConflict("account and portfolio projections have different as_of")
    if settlement_projection.as_of is None:
        raise BatchRiskError("settlement projection requires a causal observation time")
    if settlement_projection.as_of > portfolio_snapshot.as_of:
        raise BatchRiskFactConflict("settlement projection cannot come from the future")

    account_positions = tuple(
        PortfolioPosition(
            instrument_id=account_position.instrument_id,
            symbol=account_position.symbol,
            quantity=account_position.quantity,
        )
        for account_position in account_projection.positions
        if account_position.quantity > 0
    )
    if account_positions != portfolio_snapshot.positions:
        raise BatchRiskFactConflict(
            "portfolio positions do not match post-action account positions"
        )
    prices = {price.instrument_id: price for price in portfolio_snapshot.prices}
    for account_position in account_projection.positions:
        if account_position.quantity <= 0:
            continue
        causal_price = prices.get(account_position.instrument_id)
        if causal_price is None or account_position.mark is None:
            raise BatchRiskError("open account position lacks exact valuation evidence")
        if (
            causal_price.symbol != account_position.symbol
            or causal_price.event_id != account_position.mark.source_event_id
            or causal_price.price != account_position.mark.price
            or causal_price.event_time != account_position.mark.effective_at
            or causal_price.available_at != account_position.mark.recorded_at
        ):
            raise BatchRiskFactConflict(
                "portfolio price does not match the account projection mark"
            )

    payable_balance = settlement_projection.balance("liabilities:trade_payables").amount
    derived_available_cash = exact_decimal_add(
        settlement_projection.balance(f"assets:cash:{settlement_projection.currency}").amount,
        payable_balance,
    )
    if derived_available_cash != settlement_projection.available_cash:
        raise BatchRiskFactConflict(
            "settlement available cash does not match its canonical balances"
        )
    derived_gross_exposure = exact_decimal_sum(
        position.market_value.copy_abs() for position in account_projection.positions
    )
    if derived_gross_exposure != account_projection.gross_exposure:
        raise BatchRiskFactConflict("account gross exposure does not match its canonical positions")

    return _BatchRiskProjectionAttestation(
        account_id=account_projection.account_id,
        currency=account_projection.currency,
        available_cash=derived_available_cash,
        current_gross_exposure=derived_gross_exposure,
        account_projection_sha256=account_projection.semantic_sha256,
        settlement_projection_sha256=settlement_projection.semantic_sha256,
        account_positions=account_positions,
        account_projection_as_of=account_projection.as_of,
        settlement_projection_as_of=settlement_projection.as_of,
        account_execution_ledger_sha256=account_projection.ledger.semantic_sha256,
        settlement_execution_ledger_sha256=(
            settlement_projection.trade_date_ledger.semantic_sha256
        ),
    )


@dataclass(frozen=True, slots=True, init=False)
class VersionedBatchRiskSnapshot:
    """Trusted account, settlement, portfolio, session, and control capacity."""

    account_id: str
    version: str
    portfolio_snapshot: PortfolioSnapshot
    account_projection: CanonicalAccountProjection
    settlement_projection: CanonicalSettlementLedgerState
    available_cash: Decimal
    current_gross_exposure: Decimal
    account_projection_sha256: str
    settlement_projection_sha256: str
    account_positions: tuple[PortfolioPosition, ...]
    account_projection_as_of: datetime
    settlement_projection_as_of: datetime
    account_execution_ledger_sha256: str
    settlement_execution_ledger_sha256: str
    currency: str
    session: BatchRiskSession
    operational_state: BatchRiskOperationalState
    halted_instruments: frozenset[str] = frozenset()
    daily_order_count: int = 0
    open_order_count: int = 0

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("VersionedBatchRiskSnapshot can only be created from attested projections")

    def _validate(self) -> None:
        _require_text(self.account_id, "account_id")
        _require_text(self.version, "snapshot version")
        attestation = _attest_batch_risk_projections(
            portfolio_snapshot=self.portfolio_snapshot,
            account_projection=self.account_projection,
            settlement_projection=self.settlement_projection,
        )
        object.__setattr__(
            self,
            "available_cash",
            _signed_persisted_decimal(self.available_cash, "available_cash"),
        )
        object.__setattr__(
            self,
            "current_gross_exposure",
            _persisted_decimal(self.current_gross_exposure, "current_gross_exposure"),
        )
        _require_sha256(self.account_projection_sha256, "account_projection_sha256")
        _require_sha256(self.settlement_projection_sha256, "settlement_projection_sha256")
        if type(self.account_positions) is not tuple or any(
            type(position) is not PortfolioPosition for position in self.account_positions
        ):
            raise BatchRiskError("account_positions must be immutable exact values")
        _require_utc(self.account_projection_as_of, "account_projection_as_of")
        _require_utc(self.settlement_projection_as_of, "settlement_projection_as_of")
        _require_sha256(
            self.account_execution_ledger_sha256,
            "account_execution_ledger_sha256",
        )
        _require_sha256(
            self.settlement_execution_ledger_sha256,
            "settlement_execution_ledger_sha256",
        )
        _require_text(self.currency, "currency")
        if (
            len(self.currency) != 3
            or not self.currency.isalpha()
            or self.currency != self.currency.upper()
        ):
            raise BatchRiskError("currency must be a three-letter uppercase code")
        for actual, expected, field_name in (
            (self.account_id, attestation.account_id, "account identity"),
            (self.currency, attestation.currency, "currency"),
            (self.available_cash, attestation.available_cash, "available cash"),
            (
                self.current_gross_exposure,
                attestation.current_gross_exposure,
                "current gross exposure",
            ),
            (
                self.account_projection_sha256,
                attestation.account_projection_sha256,
                "account projection digest",
            ),
            (
                self.settlement_projection_sha256,
                attestation.settlement_projection_sha256,
                "settlement projection digest",
            ),
            (self.account_positions, attestation.account_positions, "account positions"),
            (
                self.account_projection_as_of,
                attestation.account_projection_as_of,
                "account projection time",
            ),
            (
                self.settlement_projection_as_of,
                attestation.settlement_projection_as_of,
                "settlement projection time",
            ),
            (
                self.account_execution_ledger_sha256,
                attestation.account_execution_ledger_sha256,
                "account execution-ledger digest",
            ),
            (
                self.settlement_execution_ledger_sha256,
                attestation.settlement_execution_ledger_sha256,
                "settlement execution-ledger digest",
            ),
        ):
            if actual != expected:
                raise BatchRiskFactConflict(
                    f"risk snapshot {field_name} does not match its retained projections"
                )
        if type(self.session) is not BatchRiskSession:
            raise BatchRiskError("risk capacity requires exact session evidence")
        self.session.__post_init__()
        if type(self.operational_state) is not BatchRiskOperationalState:
            raise BatchRiskError("risk operational state is unsupported")
        if type(self.halted_instruments) is not frozenset:
            raise BatchRiskError("halted_instruments must be a frozenset")
        for instrument_id in self.halted_instruments:
            _require_text(instrument_id, "halted instrument ID")
        for field_name in ("daily_order_count", "open_order_count"):
            value = getattr(self, field_name)
            if type(value) is not int or value < 0:
                raise BatchRiskError(f"{field_name} must be a non-negative integer")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                BATCH_RISK_CONTRACT_VERSION,
                "capacity_snapshot",
                self.account_id,
                self.version,
                self.portfolio_snapshot.semantic_sha256,
                self.available_cash,
                self.current_gross_exposure,
                self.account_projection_sha256,
                self.settlement_projection_sha256,
                tuple(
                    (position.instrument_id, position.symbol, position.quantity)
                    for position in self.account_positions
                ),
                self.account_projection_as_of,
                self.settlement_projection_as_of,
                self.account_execution_ledger_sha256,
                self.settlement_execution_ledger_sha256,
                self.currency,
                self.session.semantic_sha256,
                self.operational_state,
                self.halted_instruments,
                self.daily_order_count,
                self.open_order_count,
            )
        )


def _create_versioned_batch_risk_snapshot(
    *,
    version: str,
    portfolio_snapshot: PortfolioSnapshot,
    account_projection: CanonicalAccountProjection,
    settlement_projection: CanonicalSettlementLedgerState,
    session: BatchRiskSession,
    operational_state: BatchRiskOperationalState,
    halted_instruments: frozenset[str],
    daily_order_count: int,
    open_order_count: int,
) -> VersionedBatchRiskSnapshot:
    attestation = _attest_batch_risk_projections(
        portfolio_snapshot=portfolio_snapshot,
        account_projection=account_projection,
        settlement_projection=settlement_projection,
    )
    snapshot = object.__new__(VersionedBatchRiskSnapshot)
    for field_name, value in (
        ("account_id", attestation.account_id),
        ("version", version),
        ("portfolio_snapshot", portfolio_snapshot),
        ("account_projection", account_projection),
        ("settlement_projection", settlement_projection),
        ("available_cash", attestation.available_cash),
        ("current_gross_exposure", attestation.current_gross_exposure),
        ("account_projection_sha256", attestation.account_projection_sha256),
        ("settlement_projection_sha256", attestation.settlement_projection_sha256),
        ("account_positions", attestation.account_positions),
        ("account_projection_as_of", attestation.account_projection_as_of),
        ("settlement_projection_as_of", attestation.settlement_projection_as_of),
        (
            "account_execution_ledger_sha256",
            attestation.account_execution_ledger_sha256,
        ),
        (
            "settlement_execution_ledger_sha256",
            attestation.settlement_execution_ledger_sha256,
        ),
        ("currency", attestation.currency),
        ("session", session),
        ("operational_state", operational_state),
        ("halted_instruments", halted_instruments),
        ("daily_order_count", daily_order_count),
        ("open_order_count", open_order_count),
    ):
        object.__setattr__(snapshot, field_name, value)
    snapshot._validate()
    return snapshot


def batch_risk_snapshot_from_projections(
    *,
    version: str,
    portfolio_snapshot: PortfolioSnapshot,
    account_projection: CanonicalAccountProjection,
    settlement_projection: CanonicalSettlementLedgerState,
    session: BatchRiskSession,
    operational_state: BatchRiskOperationalState,
    halted_instruments: frozenset[str] = frozenset(),
    daily_order_count: int = 0,
    open_order_count: int = 0,
) -> VersionedBatchRiskSnapshot:
    """Seal one reconciled risk snapshot from exact accounting projections."""

    return _create_versioned_batch_risk_snapshot(
        version=version,
        portfolio_snapshot=portfolio_snapshot,
        account_projection=account_projection,
        settlement_projection=settlement_projection,
        session=session,
        operational_state=operational_state,
        halted_instruments=halted_instruments,
        daily_order_count=daily_order_count,
        open_order_count=open_order_count,
    )


def batch_risk_snapshot_with_controls(
    snapshot: VersionedBatchRiskSnapshot,
    *,
    version: str | None = None,
    session: BatchRiskSession | None = None,
    operational_state: BatchRiskOperationalState | None = None,
    halted_instruments: frozenset[str] | None = None,
    daily_order_count: int | None = None,
    open_order_count: int | None = None,
) -> VersionedBatchRiskSnapshot:
    """Create a control-state successor while preserving sealed economic evidence."""

    if type(snapshot) is not VersionedBatchRiskSnapshot:
        raise BatchRiskError("risk control transition requires an attested snapshot")
    snapshot._validate()
    return _create_versioned_batch_risk_snapshot(
        version=snapshot.version if version is None else version,
        portfolio_snapshot=snapshot.portfolio_snapshot,
        account_projection=snapshot.account_projection,
        settlement_projection=snapshot.settlement_projection,
        session=snapshot.session if session is None else session,
        operational_state=(
            snapshot.operational_state if operational_state is None else operational_state
        ),
        halted_instruments=(
            snapshot.halted_instruments if halted_instruments is None else halted_instruments
        ),
        daily_order_count=(
            snapshot.daily_order_count if daily_order_count is None else daily_order_count
        ),
        open_order_count=(
            snapshot.open_order_count if open_order_count is None else open_order_count
        ),
    )


class BatchRiskSnapshotProvider(Protocol):
    def current(self) -> VersionedBatchRiskSnapshot: ...

    def transact(
        self,
        operation: Callable[[VersionedBatchRiskSnapshot], SnapshotTransactionResultT],
    ) -> SnapshotTransactionResultT:
        """Run an operation while blocking process-local snapshot transitions."""
        ...


@dataclass(frozen=True, slots=True)
class FixedBatchRiskSnapshotProvider:
    snapshot: VersionedBatchRiskSnapshot

    def current(self) -> VersionedBatchRiskSnapshot:
        return self.snapshot

    def transact(
        self,
        operation: Callable[[VersionedBatchRiskSnapshot], SnapshotTransactionResultT],
    ) -> SnapshotTransactionResultT:
        return operation(self.snapshot)


@dataclass(frozen=True, slots=True)
class BatchRiskAuthority:
    """Immutable dependencies callers cannot override per batch."""

    limits: BatchRiskLimits
    snapshots: BatchRiskSnapshotProvider
    evaluation_clock: Clock
    consumption_clock: Clock
    _identity: object = field(default_factory=object, init=False, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class BatchRiskAuthorization:
    """One executable child capability bound to its complete parent decision."""

    decision_id: str
    parent_decision_id: str
    reservation_id: str
    intent_batch_id: str
    intent_batch_sha256: str
    snapshot_sha256: str
    policy_sha256: str
    session_sha256: str
    currency: str
    intent_id: str
    intent_payload_hash: str
    status: DecisionStatus
    evaluated_at: datetime
    expires_at: datetime
    instrument_id: str
    symbol: str
    side: Side
    quantity: Decimal
    reference_price: Decimal
    snapshot_as_of: datetime
    reference_event_time: datetime
    maximum_execution_price: Decimal
    maximum_fee: Decimal
    maximum_cash_requirement: Decimal
    reserved_cash: Decimal
    reserved_sell_quantity: Decimal
    reserved_buy_exposure: Decimal

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.decision_id, "authorization ID"),
            (self.parent_decision_id, "parent decision ID"),
            (self.reservation_id, "reservation ID"),
            (self.intent_batch_id, "intent batch ID"),
            (self.intent_id, "intent ID"),
            (self.instrument_id, "instrument ID"),
            (self.symbol, "symbol"),
            (self.currency, "currency"),
        ):
            _require_text(value, field_name)
        for value, field_name in (
            (self.intent_batch_sha256, "intent_batch_sha256"),
            (self.snapshot_sha256, "snapshot_sha256"),
            (self.policy_sha256, "policy_sha256"),
            (self.session_sha256, "session_sha256"),
            (self.intent_payload_hash, "intent_payload_hash"),
        ):
            _require_sha256(value, field_name)
        if self.reservation_id != canonical_id(
            "batch-risk-reservation",
            self.parent_decision_id,
        ):
            raise BatchRiskError("authorization reservation ID is not canonically derived")
        if self.decision_id != canonical_id(
            "batch-risk-authorization",
            self.parent_decision_id,
            self.intent_id,
        ):
            raise BatchRiskError("authorization ID is not canonically derived")
        if self.symbol != self.symbol.upper():
            raise BatchRiskError("authorization symbol must be canonical uppercase")
        if (
            len(self.currency) != 3
            or not self.currency.isalpha()
            or self.currency != self.currency.upper()
        ):
            raise BatchRiskError("authorization currency must be three-letter uppercase")
        if type(self.status) is not DecisionStatus or self.status is not DecisionStatus.APPROVED:
            raise BatchRiskError("child authorizations must be approved")
        if type(self.side) is not Side:
            raise BatchRiskError("authorization side is unsupported")
        _require_utc(self.evaluated_at, "authorization evaluated_at")
        _require_utc(self.expires_at, "authorization expires_at")
        _require_utc(self.snapshot_as_of, "authorization snapshot_as_of")
        _require_utc(self.reference_event_time, "authorization reference_event_time")
        if self.expires_at <= self.evaluated_at:
            raise BatchRiskError("authorization expiry must follow evaluation")
        object.__setattr__(
            self,
            "quantity",
            _whole_quantity(self.quantity, "authorization quantity"),
        )
        for field_name, positive in (
            ("reference_price", True),
            ("maximum_execution_price", True),
            ("maximum_fee", False),
            ("maximum_cash_requirement", False),
            ("reserved_cash", False),
            ("reserved_sell_quantity", False),
            ("reserved_buy_exposure", False),
        ):
            object.__setattr__(
                self,
                field_name,
                _persisted_decimal(
                    getattr(self, field_name),
                    f"authorization {field_name}",
                    positive=positive,
                ),
            )
        expected_buy_exposure = (
            exact_decimal_multiply(self.quantity, self.maximum_execution_price)
            if self.side is Side.BUY
            else Decimal(0)
        )
        expected_sell_quantity = self.quantity if self.side is Side.SELL else Decimal(0)
        expected_cash = exact_decimal_add(expected_buy_exposure, self.maximum_fee)
        if self.maximum_execution_price < self.reference_price:
            raise BatchRiskError("maximum execution price cannot be below reference price")
        if self.reserved_buy_exposure != expected_buy_exposure:
            raise BatchRiskError("buy exposure reservation does not match its authorization")
        if self.reserved_sell_quantity != expected_sell_quantity:
            raise BatchRiskError("sell reservation does not match its authorization")
        if self.maximum_cash_requirement != expected_cash or self.reserved_cash != expected_cash:
            raise BatchRiskError("cash reservation does not match its authorization")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                BATCH_RISK_CONTRACT_VERSION,
                "authorization",
                self.decision_id,
                self.parent_decision_id,
                self.reservation_id,
                self.intent_batch_id,
                self.intent_batch_sha256,
                self.snapshot_sha256,
                self.policy_sha256,
                self.session_sha256,
                self.currency,
                self.intent_id,
                self.intent_payload_hash,
                self.status,
                self.evaluated_at,
                self.expires_at,
                self.instrument_id,
                self.symbol,
                self.side,
                self.quantity,
                self.reference_price,
                self.snapshot_as_of,
                self.reference_event_time,
                self.maximum_execution_price,
                self.maximum_fee,
                self.maximum_cash_requirement,
                self.reserved_cash,
                self.reserved_sell_quantity,
                self.reserved_buy_exposure,
            )
        )


@dataclass(frozen=True, slots=True)
class BatchRiskReservation:
    """The indivisible cash, shares, and buy-exposure hold for one batch."""

    reservation_id: str
    parent_decision_id: str
    intent_batch_id: str
    intent_batch_sha256: str
    snapshot_sha256: str
    policy_sha256: str
    currency: str
    authorizations: tuple[BatchRiskAuthorization, ...]
    reserved_cash: Decimal
    reserved_buy_exposure: Decimal

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.reservation_id, "reservation ID"),
            (self.parent_decision_id, "parent decision ID"),
            (self.intent_batch_id, "intent batch ID"),
            (self.currency, "currency"),
        ):
            _require_text(value, field_name)
        for value, field_name in (
            (self.intent_batch_sha256, "intent_batch_sha256"),
            (self.snapshot_sha256, "snapshot_sha256"),
            (self.policy_sha256, "policy_sha256"),
        ):
            _require_sha256(value, field_name)
        if self.reservation_id != canonical_id(
            "batch-risk-reservation",
            self.parent_decision_id,
        ):
            raise BatchRiskError("reservation ID is not canonically derived")
        if (
            len(self.currency) != 3
            or not self.currency.isalpha()
            or self.currency != self.currency.upper()
        ):
            raise BatchRiskError("reservation currency must be three-letter uppercase")
        if type(self.authorizations) is not tuple or not self.authorizations:
            raise BatchRiskError("an approved reservation requires child authorizations")
        if any(type(item) is not BatchRiskAuthorization for item in self.authorizations):
            raise BatchRiskError("reservation authorizations must be exact immutable values")
        instrument_ids = tuple(item.instrument_id for item in self.authorizations)
        if instrument_ids != tuple(sorted(set(instrument_ids))):
            raise BatchRiskError("reservation authorizations must be unique and sorted")
        if any(
            item.reservation_id != self.reservation_id
            or item.parent_decision_id != self.parent_decision_id
            or item.intent_batch_id != self.intent_batch_id
            or item.intent_batch_sha256 != self.intent_batch_sha256
            or item.snapshot_sha256 != self.snapshot_sha256
            or item.policy_sha256 != self.policy_sha256
            or item.currency != self.currency
            for item in self.authorizations
        ):
            raise BatchRiskError("reservation child bindings disagree with their parent")
        expected_cash = exact_decimal_sum(item.reserved_cash for item in self.authorizations)
        expected_exposure = exact_decimal_sum(
            item.reserved_buy_exposure for item in self.authorizations
        )
        object.__setattr__(
            self,
            "reserved_cash",
            _persisted_decimal(self.reserved_cash, "reservation reserved_cash"),
        )
        object.__setattr__(
            self,
            "reserved_buy_exposure",
            _persisted_decimal(
                self.reserved_buy_exposure,
                "reservation reserved_buy_exposure",
            ),
        )
        if self.reserved_cash != expected_cash or self.reserved_buy_exposure != expected_exposure:
            raise BatchRiskError("reservation totals do not match their child holds")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                BATCH_RISK_CONTRACT_VERSION,
                "reservation",
                self.reservation_id,
                self.parent_decision_id,
                self.intent_batch_id,
                self.intent_batch_sha256,
                self.snapshot_sha256,
                self.policy_sha256,
                self.currency,
                tuple(item.semantic_sha256 for item in self.authorizations),
                self.reserved_cash,
                self.reserved_buy_exposure,
            )
        )

    def reserved_sell_quantity(self, instrument_id: str) -> Decimal:
        return exact_decimal_sum(
            item.reserved_sell_quantity
            for item in self.authorizations
            if item.instrument_id == instrument_id
        )


@dataclass(frozen=True, slots=True)
class ActiveCapacityAuthorization:
    """Exact remaining risk hold for one still-active child authorization."""

    authorization_id: str
    authorization_sha256: str
    intent_id: str
    instrument_id: str
    side: Side
    reserved_cash: Decimal
    reserved_sell_quantity: Decimal
    reserved_buy_exposure: Decimal
    remaining_cash: Decimal
    remaining_sell_quantity: Decimal
    remaining_buy_exposure: Decimal

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.authorization_id, "active authorization ID"),
            (self.intent_id, "active authorization intent ID"),
            (self.instrument_id, "active authorization instrument ID"),
        ):
            _require_text(value, field_name)
        _require_sha256(
            self.authorization_sha256,
            "active authorization digest",
        )
        if type(self.side) is not Side:
            raise BatchRiskError("active authorization side is unsupported")
        for field_name in (
            "reserved_cash",
            "reserved_sell_quantity",
            "reserved_buy_exposure",
            "remaining_cash",
            "remaining_sell_quantity",
            "remaining_buy_exposure",
        ):
            object.__setattr__(
                self,
                field_name,
                _persisted_decimal(
                    getattr(self, field_name),
                    f"active authorization {field_name}",
                ),
            )
        if (
            self.remaining_cash > self.reserved_cash
            or self.remaining_sell_quantity > self.reserved_sell_quantity
            or self.remaining_buy_exposure > self.reserved_buy_exposure
        ):
            raise BatchRiskError("active authorization remaining hold exceeds its reservation")
        if (
            self.reserved_sell_quantity != self.reserved_sell_quantity.to_integral_value()
            or self.remaining_sell_quantity != self.remaining_sell_quantity.to_integral_value()
        ):
            raise BatchRiskError("active authorization sell capacity must use whole shares")
        if self.side is Side.BUY:
            if self.reserved_sell_quantity != 0 or self.remaining_sell_quantity != 0:
                raise BatchRiskError("active buy authorization cannot reserve sell shares")
            if self.reserved_buy_exposure <= 0:
                raise BatchRiskError("active buy authorization requires buy exposure")
            if self.reserved_cash < self.reserved_buy_exposure:
                raise BatchRiskError("active buy reserved cash cannot be below buy exposure")
            if self.remaining_cash < self.remaining_buy_exposure:
                raise BatchRiskError("active buy cash cannot be below its buy exposure")
        else:
            if self.reserved_buy_exposure != 0 or self.remaining_buy_exposure != 0:
                raise BatchRiskError("active sell authorization cannot reserve buy exposure")
            if self.reserved_sell_quantity <= 0:
                raise BatchRiskError("active sell authorization requires reserved sell shares")
        if not any(
            value > 0
            for value in (
                self.remaining_cash,
                self.remaining_sell_quantity,
                self.remaining_buy_exposure,
            )
        ):
            raise BatchRiskError("active authorization must retain positive capacity")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                BATCH_RISK_CONTRACT_VERSION,
                "active_capacity_authorization",
                self.authorization_id,
                self.authorization_sha256,
                self.intent_id,
                self.instrument_id,
                self.side,
                self.reserved_cash,
                self.reserved_sell_quantity,
                self.reserved_buy_exposure,
                self.remaining_cash,
                self.remaining_sell_quantity,
                self.remaining_buy_exposure,
            )
        )


@dataclass(frozen=True, slots=True)
class ActiveCapacityReservation:
    """Authenticated remaining capacity from one nonterminal reservation."""

    reservation_id: str
    reservation_sha256: str
    projection_sha256: str
    provenance_sha256: str
    currency: str
    state: ActiveCapacityReservationState
    authorizations: tuple[ActiveCapacityAuthorization, ...]

    def __post_init__(self) -> None:
        _require_text(self.reservation_id, "active reservation ID")
        _require_sha256(self.reservation_sha256, "active reservation digest")
        _require_sha256(self.projection_sha256, "active capacity projection digest")
        _require_sha256(self.provenance_sha256, "active capacity provenance digest")
        _require_text(self.currency, "active reservation currency")
        if (
            len(self.currency) != 3
            or not self.currency.isalpha()
            or self.currency != self.currency.upper()
        ):
            raise BatchRiskError("active reservation currency must be three-letter uppercase")
        if type(self.state) is not ActiveCapacityReservationState:
            raise BatchRiskError("active reservation state is unsupported")
        if type(self.authorizations) is not tuple or not self.authorizations:
            raise BatchRiskError("active reservation requires remaining child capacity")
        if any(type(item) is not ActiveCapacityAuthorization for item in self.authorizations):
            raise BatchRiskError("active reservation authorizations must be exact immutable values")
        ordering = tuple(
            (item.instrument_id, item.authorization_id) for item in self.authorizations
        )
        if ordering != tuple(sorted(ordering)):
            raise BatchRiskError("active reservation authorizations must be canonically ordered")
        authorization_ids = tuple(item.authorization_id for item in self.authorizations)
        intent_ids = tuple(item.intent_id for item in self.authorizations)
        if len(authorization_ids) != len(set(authorization_ids)):
            raise BatchRiskFactConflict("active authorization IDs are not unique")
        if len(intent_ids) != len(set(intent_ids)):
            raise BatchRiskFactConflict("active intent IDs are not unique")

    @property
    def remaining_cash(self) -> Decimal:
        return exact_decimal_sum(item.remaining_cash for item in self.authorizations)

    @property
    def remaining_buy_exposure(self) -> Decimal:
        return exact_decimal_sum(item.remaining_buy_exposure for item in self.authorizations)

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                BATCH_RISK_CONTRACT_VERSION,
                "active_capacity_reservation",
                self.reservation_id,
                self.reservation_sha256,
                self.projection_sha256,
                self.provenance_sha256,
                self.currency,
                self.state,
                tuple(item.semantic_sha256 for item in self.authorizations),
            )
        )


@dataclass(frozen=True, slots=True)
class ActiveCapacityUniverse:
    """Complete ordered set of remaining holds charged by one risk decision."""

    account_id: str
    reservations: tuple[ActiveCapacityReservation, ...]

    def __post_init__(self) -> None:
        _require_text(self.account_id, "active capacity account ID")
        if type(self.reservations) is not tuple or any(
            type(item) is not ActiveCapacityReservation for item in self.reservations
        ):
            raise BatchRiskError("active capacity reservations must be immutable exact values")
        reservation_ids = tuple(item.reservation_id for item in self.reservations)
        if reservation_ids != tuple(sorted(reservation_ids)):
            raise BatchRiskError("active capacity reservations must be canonically ordered")
        if len(reservation_ids) != len(set(reservation_ids)):
            raise BatchRiskFactConflict("active reservation IDs are not unique")
        authorizations = self.authorizations
        authorization_ids = tuple(item.authorization_id for item in authorizations)
        intent_ids = tuple(item.intent_id for item in authorizations)
        if len(authorization_ids) != len(set(authorization_ids)):
            raise BatchRiskFactConflict("active authorization IDs are not unique")
        if len(intent_ids) != len(set(intent_ids)):
            raise BatchRiskFactConflict("active intent IDs are not unique")

    @property
    def authorizations(self) -> tuple[ActiveCapacityAuthorization, ...]:
        return tuple(
            authorization
            for reservation in self.reservations
            for authorization in reservation.authorizations
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                BATCH_RISK_CONTRACT_VERSION,
                "active_capacity_universe",
                self.account_id,
                tuple(item.semantic_sha256 for item in self.reservations),
            )
        )


def initial_active_capacity_universe(
    account_id: str,
    reservations: tuple[BatchRiskReservation, ...] = (),
) -> ActiveCapacityUniverse:
    """Project immutable, unreleased reservations into their complete initial holds."""

    if type(reservations) is not tuple or any(
        type(item) is not BatchRiskReservation for item in reservations
    ):
        raise BatchRiskError("initial active reservations must be immutable exact values")
    ordered = tuple(sorted(reservations, key=lambda item: item.reservation_id))
    if reservations != ordered:
        raise BatchRiskError("initial active reservations must be canonically ordered")
    projected = tuple(
        ActiveCapacityReservation(
            reservation_id=reservation.reservation_id,
            reservation_sha256=reservation.semantic_sha256,
            projection_sha256=_semantic_sha256(
                (
                    BATCH_RISK_CONTRACT_VERSION,
                    "initial_active_capacity_projection",
                    reservation.semantic_sha256,
                )
            ),
            provenance_sha256=_semantic_sha256(
                (
                    BATCH_RISK_CONTRACT_VERSION,
                    "initial_active_capacity_provenance",
                    reservation.semantic_sha256,
                )
            ),
            currency=reservation.currency,
            state=ActiveCapacityReservationState.ACTIVE,
            authorizations=tuple(
                ActiveCapacityAuthorization(
                    authorization_id=authorization.decision_id,
                    authorization_sha256=authorization.semantic_sha256,
                    intent_id=authorization.intent_id,
                    instrument_id=authorization.instrument_id,
                    side=authorization.side,
                    reserved_cash=authorization.reserved_cash,
                    reserved_sell_quantity=authorization.reserved_sell_quantity,
                    reserved_buy_exposure=authorization.reserved_buy_exposure,
                    remaining_cash=authorization.reserved_cash,
                    remaining_sell_quantity=authorization.reserved_sell_quantity,
                    remaining_buy_exposure=authorization.reserved_buy_exposure,
                )
                for authorization in reservation.authorizations
            ),
        )
        for reservation in ordered
    )
    return ActiveCapacityUniverse(account_id=account_id, reservations=projected)


@dataclass(frozen=True, slots=True)
class BatchRiskDecision:
    """Immutable all-or-none result for one exact intent batch."""

    decision_id: str
    intent_batch_id: str
    intent_batch_sha256: str
    account_id: str
    snapshot_version: str
    snapshot_sha256: str
    active_capacity_sha256: str
    policy_id: str
    policy_version: str
    policy_sha256: str
    currency: str
    status: BatchRiskDecisionStatus
    evaluated_at: datetime
    expires_at: datetime
    intent_count: int
    rules: tuple[RiskRuleResult, ...]
    reservation: BatchRiskReservation | None
    authorizations: tuple[BatchRiskAuthorization, ...]

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.decision_id, "batch risk decision ID"),
            (self.intent_batch_id, "intent batch ID"),
            (self.account_id, "account ID"),
            (self.snapshot_version, "snapshot version"),
            (self.policy_id, "policy ID"),
            (self.policy_version, "policy version"),
            (self.currency, "currency"),
        ):
            _require_text(value, field_name)
        for value, field_name in (
            (self.intent_batch_sha256, "intent_batch_sha256"),
            (self.snapshot_sha256, "snapshot_sha256"),
            (self.active_capacity_sha256, "active_capacity_sha256"),
            (self.policy_sha256, "policy_sha256"),
        ):
            _require_sha256(value, field_name)
        if type(self.status) is not BatchRiskDecisionStatus:
            raise BatchRiskError("batch risk decision status is unsupported")
        if (
            len(self.currency) != 3
            or not self.currency.isalpha()
            or self.currency != self.currency.upper()
        ):
            raise BatchRiskError("batch risk currency must be three-letter uppercase")
        if type(self.intent_count) is not int or self.intent_count < 0:
            raise BatchRiskError("batch risk intent_count must be a non-negative integer")
        _require_utc(self.evaluated_at, "batch risk evaluated_at")
        _require_utc(self.expires_at, "batch risk expires_at")
        if self.expires_at <= self.evaluated_at:
            raise BatchRiskError("batch risk decision must have a positive TTL")
        if type(self.rules) is not tuple or any(
            type(rule) is not RiskRuleResult for rule in self.rules
        ):
            raise BatchRiskError("batch risk rules must be immutable exact values")
        if type(self.authorizations) is not tuple or any(
            type(item) is not BatchRiskAuthorization for item in self.authorizations
        ):
            raise BatchRiskError("batch authorizations must be immutable exact values")
        expected_decision_id = canonical_id(
            "batch-risk-decision",
            self.intent_batch_id,
            self.intent_batch_sha256,
            self.snapshot_sha256,
            self.active_capacity_sha256,
            self.policy_sha256,
            self.evaluated_at,
        )
        if self.decision_id != expected_decision_id:
            raise BatchRiskError("batch risk decision ID is not canonically derived")
        if self.status is BatchRiskDecisionStatus.NO_ACTION:
            if (
                self.intent_count != 0
                or self.rules
                or self.reservation is not None
                or self.authorizations
            ):
                raise BatchRiskError("no-action decisions cannot contain rules or holds")
            return
        if self.intent_count <= 0:
            raise BatchRiskError("nonempty batch decisions require a positive intent count")
        if tuple(rule.rule for rule in self.rules) != BATCH_RISK_RULES:
            raise BatchRiskError("batch decision must contain the complete versioned rule set")
        approved = all(rule.passed for rule in self.rules)
        if self.status is BatchRiskDecisionStatus.APPROVED:
            if (
                not approved
                or self.reservation is None
                or len(self.authorizations) != self.intent_count
            ):
                raise BatchRiskError("approved batch decisions require every rule and hold")
            if self.reservation.authorizations != self.authorizations:
                raise BatchRiskError("batch decision and reservation children disagree")
            if (
                self.reservation.parent_decision_id != self.decision_id
                or self.reservation.intent_batch_id != self.intent_batch_id
                or self.reservation.intent_batch_sha256 != self.intent_batch_sha256
                or self.reservation.snapshot_sha256 != self.snapshot_sha256
                or self.reservation.policy_sha256 != self.policy_sha256
                or self.reservation.currency != self.currency
            ):
                raise BatchRiskError("batch reservation is not bound to its decision")
            if any(
                item.evaluated_at != self.evaluated_at
                or item.expires_at != self.expires_at
                or item.decision_id
                != canonical_id(
                    "batch-risk-authorization",
                    self.decision_id,
                    item.intent_id,
                )
                for item in self.authorizations
            ):
                raise BatchRiskError("batch child authorization binding is not canonical")
        elif approved or self.reservation is not None or self.authorizations:
            raise BatchRiskError("rejected batch decisions cannot contain executable holds")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                BATCH_RISK_CONTRACT_VERSION,
                "decision",
                self.decision_id,
                self.intent_batch_id,
                self.intent_batch_sha256,
                self.account_id,
                self.snapshot_version,
                self.snapshot_sha256,
                self.active_capacity_sha256,
                self.policy_id,
                self.policy_version,
                self.policy_sha256,
                self.currency,
                self.status,
                self.evaluated_at,
                self.expires_at,
                self.intent_count,
                tuple((rule.rule, rule.passed, rule.observed, rule.limit) for rule in self.rules),
                None if self.reservation is None else self.reservation.semantic_sha256,
                tuple(item.semantic_sha256 for item in self.authorizations),
            )
        )


@dataclass(frozen=True, slots=True)
class BatchRiskReservationTerms:
    """Exact Phase 2 reservation economics for one canonical intent."""

    intent: OrderIntent
    maximum_execution_price: Decimal
    maximum_fee: Decimal
    reserved_cash: Decimal
    reserved_sell_quantity: Decimal
    reserved_buy_exposure: Decimal
    gross_notional: Decimal


def validate_batch_risk_evidence(
    batch: OrderIntentBatch,
    target: TargetPortfolio,
    snapshot: VersionedBatchRiskSnapshot,
    evaluated_at: datetime,
) -> tuple[dict[str, Decimal], dict[str, Decimal]]:
    if type(batch) is not OrderIntentBatch:
        raise BatchRiskError("batch risk requires an exact OrderIntentBatch")
    if type(snapshot) is not VersionedBatchRiskSnapshot:
        raise BatchRiskError("batch risk requires an exact versioned capacity snapshot")
    snapshot._validate()
    if type(target) is not TargetPortfolio:
        raise BatchRiskError("batch risk requires exact target-portfolio evidence")
    _require_utc(evaluated_at, "evaluated_at")
    portfolio = snapshot.portfolio_snapshot
    if evaluated_at < portfolio.as_of:
        raise BatchRiskError("risk evaluation cannot precede its portfolio snapshot")
    if batch.portfolio_snapshot_sha256 != portfolio.semantic_sha256:
        raise BatchRiskFactConflict("intent batch does not bind the supplied portfolio snapshot")
    if batch.decision_trigger.as_of != portfolio.as_of:
        raise BatchRiskFactConflict("intent batch trigger and portfolio snapshot disagree")
    if batch.target_id != target.target_id or batch.target_sha256 != target.semantic_sha256:
        raise BatchRiskFactConflict("intent batch does not bind the supplied target portfolio")
    try:
        expected_batch = target_to_intent_batch(target, portfolio)
    except ValueError as error:
        raise BatchRiskFactConflict(f"target-to-intent derivation failed: {error}") from error
    if batch != expected_batch:
        raise BatchRiskFactConflict("intent batch is not the canonical target-position delta")
    expected_batch_id = canonical_id(
        "intent-batch",
        batch.target_id,
        batch.target_sha256,
        portfolio.semantic_sha256,
    )
    if batch.intent_batch_id != expected_batch_id:
        raise BatchRiskFactConflict("intent batch ID is not canonically derived")

    intent_ids = tuple(intent.intent_id for intent in batch.intents)
    if len(intent_ids) != len(set(intent_ids)):
        raise BatchRiskFactConflict("intent IDs must be unique within a batch")
    strategy_bindings = {
        (
            intent.strategy_id,
            intent.strategy_version,
            intent.strategy_configuration_sha256,
            intent.expires_at,
        )
        for intent in batch.intents
    }
    if len(strategy_bindings) > 1:
        raise BatchRiskFactConflict("intent batch members have conflicting strategy evidence")

    prices = {price.instrument_id: price for price in portfolio.prices}
    positions = {position.instrument_id: position for position in portfolio.positions}
    current_values: dict[str, Decimal] = {}
    current_quantities: dict[str, Decimal] = {}
    for instrument_id, position in positions.items():
        price = prices.get(instrument_id)
        if price is None:
            raise BatchRiskError(f"current position {instrument_id!r} lacks an exact price")
        if price.symbol != position.symbol:
            raise BatchRiskFactConflict("portfolio position and price symbols disagree")
        current_quantities[instrument_id] = position.quantity
        current_values[instrument_id] = exact_decimal_multiply(position.quantity, price.price)
    computed_gross = exact_decimal_sum(current_values.values())
    if computed_gross != snapshot.current_gross_exposure:
        raise BatchRiskFactConflict(
            "account gross exposure does not match the supplied positions and prices"
        )

    for intent in batch.intents:
        expected_intent_id = canonical_id(
            "intent",
            batch.intent_batch_id,
            intent.instrument_id,
            intent.side,
            intent.quantity,
        )
        if intent.intent_id != expected_intent_id:
            raise BatchRiskFactConflict("intent ID is not canonically derived")
        price = prices.get(intent.instrument_id)
        if price is None:
            raise BatchRiskError(f"intent {intent.intent_id!r} lacks an exact reference price")
        if (
            intent.decision_event_id != price.event_id
            or intent.reference_event_sha256 != price.source_event_sha256
            or intent.instrument_id != price.instrument_id
            or intent.symbol != price.symbol
            or intent.reference_price != price.price
            or intent.decision_event_time != price.event_time
        ):
            raise BatchRiskFactConflict("intent reference price evidence does not match snapshot")
        if price.available_at > portfolio.as_of or price.available_at > evaluated_at:
            raise BatchRiskError("intent reference price was not causally available")
        if intent.created_at != portfolio.as_of:
            raise BatchRiskFactConflict("intent creation and portfolio snapshot disagree")
    return current_quantities, current_values


def batch_risk_reservation_terms(
    intent: OrderIntent,
    limits: BatchRiskLimits,
) -> BatchRiskReservationTerms:
    """Derive the same conservative terms used by the Phase 2 decision."""

    if type(intent) is not OrderIntent:
        raise BatchRiskError("reservation terms require an exact OrderIntent")
    if type(limits) is not BatchRiskLimits:
        raise BatchRiskError("reservation terms require exact versioned limits")
    variable_fee = exact_decimal_multiply(limits.estimated_fee_per_share, intent.quantity)
    maximum_fee = exact_decimal_add(limits.estimated_fixed_fee, variable_fee)
    maximum_execution_price = (
        exact_decimal_add(
            intent.reference_price,
            limits.market_order_price_buffer_per_share,
        )
        if intent.side is Side.BUY
        else intent.reference_price
    )
    reserved_buy_exposure = (
        exact_decimal_multiply(intent.quantity, maximum_execution_price)
        if intent.side is Side.BUY
        else Decimal(0)
    )
    reserved_sell_quantity = intent.quantity if intent.side is Side.SELL else Decimal(0)
    gross_notional = (
        reserved_buy_exposure
        if intent.side is Side.BUY
        else exact_decimal_multiply(intent.quantity, intent.reference_price)
    )
    return BatchRiskReservationTerms(
        intent=intent,
        maximum_execution_price=_persisted_decimal(
            maximum_execution_price,
            "maximum execution price",
            positive=True,
        ),
        maximum_fee=_persisted_decimal(maximum_fee, "maximum fee"),
        reserved_cash=_persisted_decimal(
            exact_decimal_add(reserved_buy_exposure, maximum_fee),
            "reserved cash",
        ),
        reserved_sell_quantity=_persisted_decimal(
            reserved_sell_quantity,
            "reserved sell quantity",
        ),
        reserved_buy_exposure=_persisted_decimal(
            reserved_buy_exposure,
            "reserved buy exposure",
        ),
        gross_notional=_persisted_decimal(gross_notional, "gross order notional"),
    )


def _make_rule(rule: str, passed: bool, observed: str, limit: str) -> RiskRuleResult:
    return RiskRuleResult(rule=rule, passed=passed, observed=observed, limit=limit)


def _decision_expiry(
    *,
    batch: OrderIntentBatch,
    snapshot: VersionedBatchRiskSnapshot,
    limits: BatchRiskLimits,
    evaluated_at: datetime,
) -> datetime:
    expiries = [
        evaluated_at + limits.approval_ttl,
        snapshot.session.closes_at,
        snapshot.portfolio_snapshot.as_of + limits.max_snapshot_age,
    ]
    expiries.extend(intent.expires_at for intent in batch.intents)
    prices = {price.instrument_id: price for price in snapshot.portfolio_snapshot.prices}
    risk_price_ids = {
        position.instrument_id
        for position in snapshot.portfolio_snapshot.positions
        if position.quantity > 0
    }
    risk_price_ids.update(intent.instrument_id for intent in batch.intents)
    expiries.extend(
        prices[instrument_id].event_time + limits.max_price_age
        for instrument_id in sorted(risk_price_ids)
    )
    return min(expiries)


def evaluate_batch_risk_decision(
    batch: OrderIntentBatch,
    target: TargetPortfolio,
    snapshot: VersionedBatchRiskSnapshot,
    limits: BatchRiskLimits,
    active_capacity: ActiveCapacityUniverse,
    evaluated_at: datetime,
) -> BatchRiskDecision:
    """Evaluate and construct one complete batch result without mutating capacity."""

    if type(limits) is not BatchRiskLimits:
        raise BatchRiskError("batch risk requires exact versioned limits")
    if type(active_capacity) is not ActiveCapacityUniverse:
        raise BatchRiskError("batch risk requires an exact active capacity universe")
    active_capacity.__post_init__()
    if active_capacity.account_id != snapshot.account_id:
        raise BatchRiskFactConflict("active capacity and risk snapshot accounts differ")
    if any(
        reservation.currency != snapshot.currency for reservation in active_capacity.reservations
    ):
        raise BatchRiskFactConflict("active capacity and risk snapshot currencies differ")
    current_quantities, current_values = validate_batch_risk_evidence(
        batch,
        target,
        snapshot,
        evaluated_at,
    )
    decision_id = canonical_id(
        "batch-risk-decision",
        batch.intent_batch_id,
        batch.semantic_sha256,
        snapshot.semantic_sha256,
        active_capacity.semantic_sha256,
        limits.semantic_sha256,
        evaluated_at,
    )
    if not batch.intents:
        return BatchRiskDecision(
            decision_id=decision_id,
            intent_batch_id=batch.intent_batch_id,
            intent_batch_sha256=batch.semantic_sha256,
            account_id=snapshot.account_id,
            snapshot_version=snapshot.version,
            snapshot_sha256=snapshot.semantic_sha256,
            active_capacity_sha256=active_capacity.semantic_sha256,
            policy_id=limits.policy_id,
            policy_version=limits.policy_version,
            policy_sha256=limits.semantic_sha256,
            currency=snapshot.currency,
            status=BatchRiskDecisionStatus.NO_ACTION,
            evaluated_at=evaluated_at,
            expires_at=evaluated_at + limits.approval_ttl,
            intent_count=0,
            rules=(),
            reservation=None,
            authorizations=(),
        )

    terms = tuple(batch_risk_reservation_terms(intent, limits) for intent in batch.intents)
    active_authorizations = active_capacity.authorizations
    new_instruments = {intent.instrument_id for intent in batch.intents}
    active_instruments = {item.instrument_id for item in active_authorizations}
    halted = new_instruments & snapshot.halted_instruments
    disallowed = new_instruments - limits.allowed_instruments

    snapshot_age = evaluated_at - snapshot.portfolio_snapshot.as_of
    prices_by_instrument = {
        price.instrument_id: price for price in snapshot.portfolio_snapshot.prices
    }
    risk_price_ids = {
        position.instrument_id
        for position in snapshot.portfolio_snapshot.positions
        if position.quantity > 0
    }
    risk_price_ids.update(item.intent.instrument_id for item in terms)
    price_ages = {
        instrument_id: evaluated_at - prices_by_instrument[instrument_id].event_time
        for instrument_id in sorted(risk_price_ids)
    }
    stale_price_ids = {
        instrument_id for instrument_id, age in price_ages.items() if age >= limits.max_price_age
    }
    expired_intents = tuple(
        intent.intent_id for intent in batch.intents if evaluated_at >= intent.expires_at
    )
    over_quantity = {
        item.intent.instrument_id: item.intent.quantity
        for item in terms
        if item.intent.quantity > limits.max_order_quantity
    }
    over_notional = {
        item.intent.instrument_id: item.gross_notional
        for item in terms
        if item.gross_notional > limits.max_order_notional
    }
    batch_notional = exact_decimal_sum(item.gross_notional for item in terms)
    active_cash = exact_decimal_sum(
        reservation.remaining_cash for reservation in active_capacity.reservations
    )
    proposed_cash = exact_decimal_sum(item.reserved_cash for item in terms)
    remaining_cash = exact_decimal_subtract(
        exact_decimal_subtract(snapshot.available_cash, active_cash),
        proposed_cash,
    )

    active_sells: dict[str, Decimal] = {}
    for authorization in active_authorizations:
        active_sells[authorization.instrument_id] = exact_decimal_add(
            active_sells.get(authorization.instrument_id, Decimal(0)),
            authorization.remaining_sell_quantity,
        )
    proposed_sells: dict[str, Decimal] = {}
    for item in terms:
        proposed_sells[item.intent.instrument_id] = exact_decimal_add(
            proposed_sells.get(item.intent.instrument_id, Decimal(0)),
            item.reserved_sell_quantity,
        )
    remaining_shares = {
        instrument_id: exact_decimal_subtract(
            exact_decimal_subtract(
                current_quantities.get(instrument_id, Decimal(0)),
                active_sells.get(instrument_id, Decimal(0)),
            ),
            proposed_sells.get(instrument_id, Decimal(0)),
        )
        for instrument_id in sorted(active_sells.keys() | proposed_sells.keys())
    }
    oversold = {key: value for key, value in remaining_shares.items() if value < 0}

    instrument_exposure = dict(current_values)
    for authorization in active_authorizations:
        instrument_exposure[authorization.instrument_id] = exact_decimal_add(
            instrument_exposure.get(authorization.instrument_id, Decimal(0)),
            authorization.remaining_buy_exposure,
        )
    for item in terms:
        instrument_exposure[item.intent.instrument_id] = exact_decimal_add(
            instrument_exposure.get(item.intent.instrument_id, Decimal(0)),
            item.reserved_buy_exposure,
        )
    over_instrument_exposure = {
        key: value
        for key, value in instrument_exposure.items()
        if value > limits.max_instrument_gross_exposure
    }
    account_gross = exact_decimal_add(
        snapshot.current_gross_exposure,
        exact_decimal_add(
            exact_decimal_sum(
                authorization.remaining_buy_exposure for authorization in active_authorizations
            ),
            exact_decimal_sum(item.reserved_buy_exposure for item in terms),
        ),
    )
    projected_daily_count = (
        snapshot.daily_order_count + len(active_authorizations) + len(batch.intents)
    )
    projected_open_count = (
        snapshot.open_order_count + len(active_authorizations) + len(batch.intents)
    )
    session_is_current = (
        snapshot.session.contains(snapshot.portfolio_snapshot.as_of)
        and snapshot.session.contains(evaluated_at)
        and all(
            snapshot.session.contains(prices_by_instrument[instrument_id].event_time)
            and snapshot.session.contains(prices_by_instrument[instrument_id].available_at)
            for instrument_id in risk_price_ids
        )
    )

    rules = (
        _make_rule(
            "operational_state",
            snapshot.operational_state is BatchRiskOperationalState.RUNNING,
            snapshot.operational_state.value,
            BatchRiskOperationalState.RUNNING.value,
        ),
        _make_rule(
            "active_instrument",
            not (new_instruments & active_instruments),
            ",".join(sorted(new_instruments & active_instruments)),
            "none",
        ),
        _make_rule(
            "instrument_allow_list",
            not disallowed,
            ",".join(sorted(disallowed)),
            ",".join(sorted(limits.allowed_instruments)),
        ),
        _make_rule(
            "instrument_halt",
            not halted,
            ",".join(sorted(halted)),
            "none",
        ),
        _make_rule(
            "session",
            session_is_current,
            f"{snapshot.portfolio_snapshot.as_of.isoformat()},{evaluated_at.isoformat()}",
            f"[{snapshot.session.opens_at.isoformat()},{snapshot.session.closes_at.isoformat()})",
        ),
        _make_rule(
            "snapshot_freshness",
            snapshot_age < limits.max_snapshot_age,
            _duration_text(snapshot_age),
            _duration_text(limits.max_snapshot_age),
        ),
        _make_rule(
            "reference_price_freshness",
            not stale_price_ids,
            ",".join(sorted(stale_price_ids)),
            _duration_text(limits.max_price_age),
        ),
        _make_rule(
            "intent_freshness",
            not expired_intents,
            ",".join(expired_intents),
            "evaluated_at < intent.expires_at",
        ),
        _make_rule(
            "quantity",
            not over_quantity,
            _decimal_bindings(over_quantity),
            canonical_decimal_text(limits.max_order_quantity),
        ),
        _make_rule(
            "order_notional",
            not over_notional,
            _decimal_bindings(over_notional),
            canonical_decimal_text(limits.max_order_notional),
        ),
        _make_rule(
            "batch_notional",
            batch_notional <= limits.max_batch_notional,
            canonical_decimal_text(batch_notional),
            canonical_decimal_text(limits.max_batch_notional),
        ),
        _make_rule(
            "cash_buffer",
            remaining_cash >= limits.minimum_cash_buffer,
            canonical_decimal_text(remaining_cash),
            canonical_decimal_text(limits.minimum_cash_buffer),
        ),
        _make_rule(
            "sell_capacity",
            not oversold,
            _decimal_bindings(oversold),
            "remaining shares >= 0",
        ),
        _make_rule(
            "instrument_gross_exposure",
            not over_instrument_exposure,
            _decimal_bindings(over_instrument_exposure),
            canonical_decimal_text(limits.max_instrument_gross_exposure),
        ),
        _make_rule(
            "account_gross_exposure",
            account_gross <= limits.max_account_gross_exposure,
            canonical_decimal_text(account_gross),
            canonical_decimal_text(limits.max_account_gross_exposure),
        ),
        _make_rule(
            "daily_order_count",
            projected_daily_count <= limits.max_daily_order_count,
            str(projected_daily_count),
            str(limits.max_daily_order_count),
        ),
        _make_rule(
            "open_order_count",
            projected_open_count <= limits.max_open_order_count,
            str(projected_open_count),
            str(limits.max_open_order_count),
        ),
    )
    approved = all(rule.passed for rule in rules)
    if not approved:
        return BatchRiskDecision(
            decision_id=decision_id,
            intent_batch_id=batch.intent_batch_id,
            intent_batch_sha256=batch.semantic_sha256,
            account_id=snapshot.account_id,
            snapshot_version=snapshot.version,
            snapshot_sha256=snapshot.semantic_sha256,
            active_capacity_sha256=active_capacity.semantic_sha256,
            policy_id=limits.policy_id,
            policy_version=limits.policy_version,
            policy_sha256=limits.semantic_sha256,
            currency=snapshot.currency,
            status=BatchRiskDecisionStatus.REJECTED,
            evaluated_at=evaluated_at,
            expires_at=evaluated_at + limits.approval_ttl,
            intent_count=len(batch.intents),
            rules=rules,
            reservation=None,
            authorizations=(),
        )

    expires_at = _decision_expiry(
        batch=batch,
        snapshot=snapshot,
        limits=limits,
        evaluated_at=evaluated_at,
    )
    if expires_at <= evaluated_at:
        raise BatchRiskError("approved batch has no positive executable lifetime")
    reservation_id = canonical_id("batch-risk-reservation", decision_id)
    authorizations = tuple(
        BatchRiskAuthorization(
            decision_id=canonical_id(
                "batch-risk-authorization",
                decision_id,
                item.intent.intent_id,
            ),
            parent_decision_id=decision_id,
            reservation_id=reservation_id,
            intent_batch_id=batch.intent_batch_id,
            intent_batch_sha256=batch.semantic_sha256,
            snapshot_sha256=snapshot.semantic_sha256,
            policy_sha256=limits.semantic_sha256,
            session_sha256=snapshot.session.semantic_sha256,
            currency=snapshot.currency,
            intent_id=item.intent.intent_id,
            intent_payload_hash=intent_payload_hash(item.intent),
            status=DecisionStatus.APPROVED,
            evaluated_at=evaluated_at,
            expires_at=expires_at,
            instrument_id=item.intent.instrument_id,
            symbol=item.intent.symbol,
            side=item.intent.side,
            quantity=item.intent.quantity,
            reference_price=item.intent.reference_price,
            snapshot_as_of=snapshot.portfolio_snapshot.as_of,
            reference_event_time=item.intent.decision_event_time,
            maximum_execution_price=item.maximum_execution_price,
            maximum_fee=item.maximum_fee,
            maximum_cash_requirement=item.reserved_cash,
            reserved_cash=item.reserved_cash,
            reserved_sell_quantity=item.reserved_sell_quantity,
            reserved_buy_exposure=item.reserved_buy_exposure,
        )
        for item in terms
    )
    reservation = BatchRiskReservation(
        reservation_id=reservation_id,
        parent_decision_id=decision_id,
        intent_batch_id=batch.intent_batch_id,
        intent_batch_sha256=batch.semantic_sha256,
        snapshot_sha256=snapshot.semantic_sha256,
        policy_sha256=limits.semantic_sha256,
        currency=snapshot.currency,
        authorizations=authorizations,
        reserved_cash=proposed_cash,
        reserved_buy_exposure=exact_decimal_sum(item.reserved_buy_exposure for item in terms),
    )
    return BatchRiskDecision(
        decision_id=decision_id,
        intent_batch_id=batch.intent_batch_id,
        intent_batch_sha256=batch.semantic_sha256,
        account_id=snapshot.account_id,
        snapshot_version=snapshot.version,
        snapshot_sha256=snapshot.semantic_sha256,
        active_capacity_sha256=active_capacity.semantic_sha256,
        policy_id=limits.policy_id,
        policy_version=limits.policy_version,
        policy_sha256=limits.semantic_sha256,
        currency=snapshot.currency,
        status=BatchRiskDecisionStatus.APPROVED,
        evaluated_at=evaluated_at,
        expires_at=expires_at,
        intent_count=len(batch.intents),
        rules=rules,
        reservation=reservation,
        authorizations=authorizations,
    )
