"""One-step simulation accounting port; scheduling belongs to the engine."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Literal, Protocol

from packages.domain.account_projection import OpenTaxLot
from packages.domain.corporate_action_ledger import (
    CashDividendAccrual,
    CashDividendPayment,
    StockSplitAction,
)
from packages.domain.decimal_math import exact_decimal_subtract
from packages.domain.ledger_reducer import CanonicalLedgerEntry, LedgerCashFlow
from packages.domain.models import Side
from packages.domain.order_reducer import BrokerOrderEvent, OrderCancelRequest, OrderSubmission
from packages.domain.personal_contracts import (
    CausalMark,
    ContractRecord,
    ReductionPoint,
    require_amount,
    require_digest,
    require_text,
)
from packages.domain.settlement_ledger import (
    ExecutionSettlementConfirmation,
    ExecutionSettlementInstruction,
)


@dataclass(frozen=True, slots=True)
class SettlementCalendar(ContractRecord):
    calendar_id: str
    version: str
    business_dates: tuple[date, ...]
    timezone: Literal["America/New_York"] = "America/New_York"

    def __post_init__(self) -> None:
        super(SettlementCalendar, self).__post_init__()
        require_text(self.calendar_id, "settlement calendar")
        require_text(self.version, "calendar version")
        if not self.business_dates or self.business_dates != tuple(
            sorted(set(self.business_dates))
        ):
            raise ValueError("settlement dates must be nonempty sorted unique dates")


@dataclass(frozen=True, slots=True)
class ExecutionPolicy(ContractRecord):
    settlement_calendar: SettlementCalendar
    model_id: Literal["next-regular-open-proxy-v1", "synthetic-events-v1"] = (
        "next-regular-open-proxy-v1"
    )
    slippage_bps: Decimal = Decimal("5")
    fee_per_share: Decimal = Decimal("0.01")
    price_quantum: Decimal = Decimal("0.0000000001")
    settlement_model: Literal["dated-us-equity-standard-settlement-v1"] = (
        "dated-us-equity-standard-settlement-v1"
    )
    correction_settlement: Literal["explicit-or-receipt-trade-date-v1"] = (
        "explicit-or-receipt-trade-date-v1"
    )
    terminal_model: Literal["observed-model-day-expiry-v1"] = "observed-model-day-expiry-v1"
    financing_policy: Literal["cash-funded-long-only/1"] = "cash-funded-long-only/1"

    def __post_init__(self) -> None:
        super(ExecutionPolicy, self).__post_init__()
        require_amount(self.slippage_bps, "slippage", nonnegative=True)
        require_amount(self.fee_per_share, "per-share fee", nonnegative=True)
        if self.slippage_bps >= 10000 or self.price_quantum != Decimal("0.0000000001"):
            raise ValueError("unsupported cost model")


@dataclass(frozen=True, slots=True)
class Commitment(ContractRecord):
    commitment_id: str
    intent_id: str
    order_id: str
    instrument_id: str
    symbol: str
    side: Side
    original_quantity: Decimal
    filled_quantity: Decimal
    remaining_quantity: Decimal
    reserved_cash: Decimal
    reserved_sell_quantity: Decimal
    approved_price: Decimal
    remaining_fee_budget: Decimal
    source_session: date
    execution_session: date
    created_sequence: int
    not_before: datetime
    expires_at: datetime
    policy_sha256: str
    snapshot_sha256: str
    state: Literal[
        "approved_unsent", "active", "working", "partial", "unknown", "pending_cancel", "terminal"
    ] = "approved_unsent"
    activated_at: datetime | None = None
    activation_sequence: int | None = None
    activation_frontier: int | None = None
    terminal_reason: str | None = None

    def __post_init__(self) -> None:
        super(Commitment, self).__post_init__()
        for name in ("commitment_id", "intent_id", "order_id", "instrument_id", "symbol"):
            require_text(getattr(self, name), name)
        for name in (
            "original_quantity",
            "filled_quantity",
            "remaining_quantity",
            "reserved_sell_quantity",
        ):
            require_amount(getattr(self, name), name, nonnegative=True, whole=True)
        for name in ("reserved_cash", "approved_price", "remaining_fee_budget"):
            require_amount(getattr(self, name), name, nonnegative=True)
        require_digest(self.policy_sha256, "commitment policy")
        require_digest(self.snapshot_sha256, "commitment snapshot")
        if self.original_quantity <= 0 or self.filled_quantity > self.original_quantity:
            raise ValueError("commitment quantity exceeds original")
        if self.remaining_quantity > exact_decimal_subtract(
            self.original_quantity, self.filled_quantity
        ):
            raise ValueError("commitment remainder exceeds unfilled quantity")
        if self.not_before >= self.expires_at or self.created_sequence < 0:
            raise ValueError("invalid commitment window/sequence")
        if self.state == "terminal" and (
            self.remaining_quantity or self.reserved_cash or self.reserved_sell_quantity
        ):
            raise ValueError("terminal commitment cannot retain capacity")


@dataclass(frozen=True, slots=True)
class PositionState(ContractRecord):
    instrument_id: str
    symbol: str
    quantity: Decimal
    cost_basis: Decimal
    lots: tuple[OpenTaxLot, ...]
    gross_realized_pnl: Decimal = Decimal(0)
    fees: Decimal = Decimal(0)
    dividend_income: Decimal = Decimal(0)
    dividend_receivable: Decimal = Decimal(0)


@dataclass(frozen=True, slots=True)
class FifoMatchRow(ContractRecord):
    match_id: str
    instrument_id: str
    opening_execution_id: str
    opening_revision: int
    closing_execution_id: str
    closing_revision: int
    opening_order_id: str
    closing_order_id: str
    quantity: Decimal
    basis: Decimal
    proceeds: Decimal
    opening_fee: Decimal
    closing_fee: Decimal
    acquired_at: datetime
    disposed_at: datetime
    source_sha256: str
    split_ids: tuple[str, ...] = ()
    group_complete: bool = False


@dataclass(frozen=True, slots=True)
class ExecutionRow(ContractRecord):
    execution_id: str
    revision: int
    fact_id: str
    fact_sha256: str
    order_id: str
    intent_id: str
    instrument_id: str
    symbol: str
    side: Side
    quantity: Decimal
    price: Decimal
    fee: Decimal
    economic_at: datetime
    knowledge_at: datetime
    sequence: int
    model_id: str
    supersedes_fact_id: str | None = None


@dataclass(frozen=True, slots=True)
class AccountSnapshot(ContractRecord):
    account_id: str
    point: ReductionPoint
    state_sha256: str
    positions: tuple[PositionState, ...]
    commitments: tuple[Commitment, ...]
    marks: tuple[CausalMark, ...]
    trade_date_cash: Decimal
    settled_cash: Decimal
    trade_receivable: Decimal
    trade_payable: Decimal
    dividend_receivable: Decimal
    buy_reserve: Decimal
    sell_fee_reserve: Decimal
    available_cash: Decimal
    market_value: Decimal | None
    nav: Decimal | None
    gross_realized_pnl: Decimal
    fees: Decimal
    dividend_income: Decimal
    unrealized_pnl: Decimal | None
    net_external_flow: Decimal
    journal_sha256: str
    order_sha256: str
    valuation_reasons: tuple[str, ...] = ()
    last_known_nav: Decimal | None = None
    halted: bool = False


@dataclass(frozen=True, slots=True)
class InstallCommitment(ContractRecord):
    submission: OrderSubmission
    commitment: Commitment


@dataclass(frozen=True, slots=True)
class ActivateCommitment(ContractRecord):
    commitment_id: str


@dataclass(frozen=True, slots=True)
class ExecutionObservation(ContractRecord):
    observation_id: str
    instrument_id: str
    symbol: str
    session: date
    price: Decimal
    economic_at: datetime
    knowledge_at: datetime
    model_id: str
    source_sha256: str
    quantity_budget: Decimal | None = None
    basis: Literal["raw_open", "synthetic_price"] = "raw_open"

    def __post_init__(self) -> None:
        super(ExecutionObservation, self).__post_init__()
        require_amount(self.price, "execution reference price", positive=True)
        require_digest(self.source_sha256, "execution source")
        if self.quantity_budget is not None:
            require_amount(self.quantity_budget, "quantity budget", nonnegative=True, whole=True)
        if self.economic_at > self.knowledge_at:
            raise ValueError("execution observation cannot arrive before its event")


@dataclass(frozen=True, slots=True)
class ModelDisposition(ContractRecord):
    commitment_id: str
    kind: Literal["day_expired", "unknown", "resolved_no_remaining"]
    evidence_id: str


@dataclass(frozen=True, slots=True)
class ControlCommand(ContractRecord):
    halted: bool
    reason: str


type AccountingPayload = (
    InstallCommitment
    | ActivateCommitment
    | ExecutionObservation
    | BrokerOrderEvent
    | OrderCancelRequest
    | LedgerCashFlow
    | StockSplitAction
    | CashDividendAccrual
    | CashDividendPayment
    | ExecutionSettlementInstruction
    | ExecutionSettlementConfirmation
    | CausalMark
    | ModelDisposition
    | ControlCommand
)


@dataclass(frozen=True, slots=True)
class AccountingCommand(ContractRecord):
    command_id: str
    payload: AccountingPayload


@dataclass(frozen=True, slots=True)
class AccountingState(ContractRecord):
    account_id: str
    execution_policy_sha256: str | None = None
    commands: tuple[tuple[str, str], ...] = ()
    submissions: tuple[OrderSubmission, ...] = ()
    broker_events: tuple[BrokerOrderEvent, ...] = ()
    event_points: tuple[tuple[str, ReductionPoint], ...] = ()
    observations: tuple[ExecutionObservation, ...] = ()
    cancel_requests: tuple[OrderCancelRequest, ...] = ()
    cash_flows: tuple[LedgerCashFlow, ...] = ()
    stock_splits: tuple[StockSplitAction, ...] = ()
    cash_dividends: tuple[CashDividendAccrual, ...] = ()
    dividend_payments: tuple[CashDividendPayment, ...] = ()
    settlement_instructions: tuple[ExecutionSettlementInstruction, ...] = ()
    settlement_confirmations: tuple[ExecutionSettlementConfirmation, ...] = ()
    commitments: tuple[Commitment, ...] = ()
    marks: tuple[CausalMark, ...] = ()
    halted: bool = False
    revision: int = 0


@dataclass(frozen=True, slots=True)
class AccountingContext(ContractRecord):
    run_id: str
    point: ReductionPoint
    economic_at: datetime
    event_id: str
    expected_mark_session: date
    instruments: tuple[tuple[str, str], ...]
    approved_snapshot: AccountSnapshot | None = None
    risk_policy_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class DueAccountingEvent(ContractRecord):
    event_id: str
    parent_event_id: str
    due_at: datetime
    command: AccountingCommand
    policy_sha256: str


@dataclass(frozen=True, slots=True)
class AccountingTransition(ContractRecord):
    disposition: Literal["applied", "duplicate", "rejected"]
    state: AccountingState
    snapshot: AccountSnapshot
    journal_entries: tuple[CanonicalLedgerEntry, ...]
    executions: tuple[ExecutionRow, ...]
    fifo_matches: tuple[FifoMatchRow, ...]
    due_events: tuple[DueAccountingEvent, ...] = ()
    reasons: tuple[str, ...] = ()


class ExecutionAccountingPort(Protocol):
    def advance(
        self,
        *,
        state: AccountingState,
        command: AccountingCommand,
        context: AccountingContext,
        policy: ExecutionPolicy,
    ) -> AccountingTransition: ...

    def project(
        self, *, state: AccountingState, context: AccountingContext, policy: ExecutionPolicy
    ) -> AccountingTransition: ...
