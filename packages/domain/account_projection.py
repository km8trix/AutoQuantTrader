"""Pure FIFO account, lot, and profit-and-loss projection."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum

from packages.domain.canonical import canonical_json_bytes, canonical_persisted_decimal
from packages.domain.corporate_action_ledger import (
    CanonicalCorporateActionLedgerState,
    CashDividendAccrual,
    CashDividendPayment,
    CorporateActionFactConflict,
    CorporateActionLedgerError,
    StockSplitAction,
    reduce_corporate_action_ledger,
)
from packages.domain.decimal_math import (
    deterministic_decimal_divide,
    exact_decimal_add,
    exact_decimal_multiply,
    exact_decimal_subtract,
    exact_decimal_sum,
)
from packages.domain.identifiers import canonical_id
from packages.domain.ledger_reducer import (
    CanonicalLedgerState,
    LedgerCashFlow,
    LedgerFactConflict,
    reduce_execution_ledger,
)
from packages.domain.models import Side, require_utc
from packages.domain.order_reducer import (
    BrokerOrderEventKind,
    CanonicalOrderState,
)

ACCOUNT_PROJECTION_CONTRACT_VERSION = "phase2-fifo-account-projection-v3"


class AccountProjectionError(ValueError):
    """Raised when account facts cannot produce a canonical cash-account projection."""


class AccountFactConflict(AccountProjectionError):
    """Raised when an immutable account fact identity has conflicting semantics."""


class CostBasisPolicy(StrEnum):
    FIFO_TRADE_DATE = "fifo_trade_date_v1"


def _require_text(value: str, field_name: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise AccountProjectionError(f"{field_name} must be a non-empty, trimmed string")


def _require_currency(value: str) -> None:
    if type(value) is not str or len(value) != 3 or not value.isalpha() or value != value.upper():
        raise AccountProjectionError("currency must be a three-letter uppercase code")


def _persisted(value: Decimal, field_name: str) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise AccountProjectionError(f"{field_name} must be a finite exact Decimal")
    try:
        return canonical_persisted_decimal(value, field_name)
    except ValueError as error:
        raise AccountProjectionError(str(error)) from error


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class PositionMark:
    mark_id: str
    source_event_id: str
    instrument_id: str
    symbol: str
    price: Decimal
    effective_at: datetime
    recorded_at: datetime

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.mark_id, "mark_id"),
            (self.source_event_id, "mark source_event_id"),
            (self.instrument_id, "mark instrument_id"),
            (self.symbol, "mark symbol"),
        ):
            _require_text(value, field_name)
        if self.symbol != self.symbol.upper():
            raise AccountProjectionError("mark symbol must use canonical uppercase form")
        price = _persisted(self.price, "mark price")
        if price <= 0:
            raise AccountProjectionError("mark price must be positive")
        object.__setattr__(self, "price", price)
        require_utc(self.effective_at, "mark effective_at")
        require_utc(self.recorded_at, "mark recorded_at")
        if self.recorded_at < self.effective_at:
            raise AccountProjectionError("mark cannot be recorded before it is effective")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ACCOUNT_PROJECTION_CONTRACT_VERSION,
                "mark",
                self.mark_id,
                self.source_event_id,
                self.instrument_id,
                self.symbol,
                self.price,
                self.effective_at,
                self.recorded_at,
            )
        )


def create_position_mark(
    *,
    source_event_id: str,
    instrument_id: str,
    symbol: str,
    price: Decimal,
    effective_at: datetime,
    recorded_at: datetime,
) -> PositionMark:
    """Create a mark whose identity is stable across exact redelivery."""

    return PositionMark(
        mark_id=canonical_id("position-mark", source_event_id),
        source_event_id=source_event_id,
        instrument_id=instrument_id,
        symbol=symbol,
        price=price,
        effective_at=effective_at,
        recorded_at=recorded_at,
    )


@dataclass(frozen=True, slots=True)
class OpenTaxLot:
    execution_id: str
    order_id: str
    quantity: Decimal
    cost_basis: Decimal
    acquired_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.execution_id, "lot execution_id")
        _require_text(self.order_id, "lot order_id")
        quantity = _persisted(self.quantity, "lot quantity")
        cost_basis = _persisted(self.cost_basis, "lot cost_basis")
        if quantity <= 0 or quantity != quantity.to_integral_value():
            raise AccountProjectionError("lot quantity must be positive whole shares")
        if cost_basis <= 0:
            raise AccountProjectionError("lot cost_basis must be positive")
        object.__setattr__(self, "quantity", quantity)
        object.__setattr__(self, "cost_basis", cost_basis)
        require_utc(self.acquired_at, "lot acquired_at")

    @property
    def unit_cost(self) -> Decimal:
        """Return the derived average unit cost without rounding stored basis."""

        return deterministic_decimal_divide(self.cost_basis, self.quantity)

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ACCOUNT_PROJECTION_CONTRACT_VERSION,
                "open_lot",
                self.execution_id,
                self.order_id,
                self.quantity,
                self.cost_basis,
                self.acquired_at,
            )
        )


@dataclass(frozen=True, slots=True)
class InstrumentAccountProjection:
    instrument_id: str
    symbol: str
    quantity: Decimal
    open_lots: tuple[OpenTaxLot, ...]
    cost_basis: Decimal
    mark: PositionMark | None
    market_value: Decimal
    realized_pnl_before_fees: Decimal
    execution_fees: Decimal
    dividend_income: Decimal
    realized_pnl: Decimal
    unrealized_pnl: Decimal

    def __post_init__(self) -> None:
        _require_text(self.instrument_id, "position instrument_id")
        _require_text(self.symbol, "position symbol")
        if self.symbol != self.symbol.upper():
            raise AccountProjectionError("position symbol must use canonical uppercase form")
        quantity = _persisted(self.quantity, "position quantity")
        if quantity < 0 or quantity != quantity.to_integral_value():
            raise AccountProjectionError("position quantity must be non-negative whole shares")
        if type(self.open_lots) is not tuple or any(
            type(lot) is not OpenTaxLot for lot in self.open_lots
        ):
            raise AccountProjectionError("open lots must be immutable OpenTaxLot values")
        if exact_decimal_sum(lot.quantity for lot in self.open_lots) != quantity:
            raise AccountProjectionError("open lot quantity does not match position quantity")
        if self.open_lots != tuple(
            sorted(
                self.open_lots, key=lambda lot: (lot.acquired_at, lot.order_id, lot.execution_id)
            )
        ):
            raise AccountProjectionError("open lots must remain in canonical FIFO order")
        expected_cost = exact_decimal_sum(lot.cost_basis for lot in self.open_lots)
        if _persisted(self.cost_basis, "position cost_basis") != expected_cost:
            raise AccountProjectionError("position cost basis does not match its open lots")
        if quantity > 0 and self.mark is None:
            raise AccountProjectionError("open position requires a causal mark")
        if self.mark is not None and (
            self.mark.instrument_id != self.instrument_id or self.mark.symbol != self.symbol
        ):
            raise AccountProjectionError("position mark belongs to a different instrument")
        expected_market_value = (
            Decimal(0) if self.mark is None else exact_decimal_multiply(quantity, self.mark.price)
        )
        if _persisted(self.market_value, "position market_value") != expected_market_value:
            raise AccountProjectionError("position market value does not match quantity and mark")
        realized_before_fees = _persisted(
            self.realized_pnl_before_fees,
            "position realized_pnl_before_fees",
        )
        fees = _persisted(self.execution_fees, "position execution_fees")
        dividend_income = _persisted(self.dividend_income, "position dividend_income")
        realized = _persisted(self.realized_pnl, "position realized_pnl")
        unrealized = _persisted(self.unrealized_pnl, "position unrealized_pnl")
        if fees < 0:
            raise AccountProjectionError("position execution fees cannot be negative")
        if dividend_income < 0:
            raise AccountProjectionError("position dividend income cannot be negative")
        if realized != exact_decimal_add(
            exact_decimal_subtract(realized_before_fees, fees),
            dividend_income,
        ):
            raise AccountProjectionError(
                "position realized P&L does not include fees and dividends"
            )
        if unrealized != exact_decimal_subtract(expected_market_value, expected_cost):
            raise AccountProjectionError("position unrealized P&L is inconsistent")
        object.__setattr__(self, "quantity", quantity)
        object.__setattr__(self, "cost_basis", expected_cost)
        object.__setattr__(self, "market_value", expected_market_value)
        object.__setattr__(self, "realized_pnl_before_fees", realized_before_fees)
        object.__setattr__(self, "execution_fees", fees)
        object.__setattr__(self, "dividend_income", dividend_income)
        object.__setattr__(self, "realized_pnl", realized)
        object.__setattr__(self, "unrealized_pnl", unrealized)

    @property
    def average_cost(self) -> Decimal:
        if self.quantity == 0:
            return Decimal(0)
        return deterministic_decimal_divide(self.cost_basis, self.quantity)

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ACCOUNT_PROJECTION_CONTRACT_VERSION,
                "instrument_projection",
                self.instrument_id,
                self.symbol,
                self.quantity,
                tuple(lot.semantic_sha256 for lot in self.open_lots),
                self.cost_basis,
                None if self.mark is None else self.mark.semantic_sha256,
                self.market_value,
                self.realized_pnl_before_fees,
                self.execution_fees,
                self.dividend_income,
                self.realized_pnl,
                self.unrealized_pnl,
            )
        )


@dataclass(frozen=True, slots=True, init=False)
class CanonicalAccountProjection:
    """A reducer-produced proof of one account's canonical valuation state."""

    account_id: str
    policy: CostBasisPolicy
    currency: str
    ledger: CanonicalLedgerState
    corporate_action_ledger: CanonicalCorporateActionLedgerState
    observed_marks: tuple[PositionMark, ...]
    positions: tuple[InstrumentAccountProjection, ...]
    cash: Decimal
    market_value: Decimal
    equity: Decimal
    gross_exposure: Decimal
    net_exposure: Decimal
    realized_pnl_before_fees: Decimal
    execution_fees: Decimal
    dividend_income: Decimal
    dividend_receivable: Decimal
    realized_pnl: Decimal
    unrealized_pnl: Decimal
    as_of: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("CanonicalAccountProjection can only be created by the account reducer")

    def _validate(self) -> None:
        """Re-derive all retained proof fields from the embedded canonical evidence."""

        _require_text(self.account_id, "account_id")
        if type(self.policy) is not CostBasisPolicy:
            raise AccountProjectionError("account projection has an unsupported policy")
        _require_currency(self.currency)
        require_utc(self.as_of, "account projection as_of")
        if type(self.ledger) is not CanonicalLedgerState:
            raise AccountProjectionError("account projection requires an exact ledger state")
        if type(self.corporate_action_ledger) is not CanonicalCorporateActionLedgerState:
            raise AccountProjectionError(
                "account projection requires an exact corporate-action ledger state"
            )
        if self.corporate_action_ledger.base_ledger != self.ledger:
            raise AccountProjectionError(
                "account projection corporate-action ledger does not bind its execution ledger"
            )
        if self.corporate_action_ledger.currency != self.currency:
            raise AccountProjectionError(
                "account projection currency differs from its corporate-action ledger"
            )
        try:
            expected_corporate_action_ledger = reduce_corporate_action_ledger(
                base_ledger=self.ledger,
                stock_splits=self.corporate_action_ledger.stock_splits,
                cash_dividends=self.corporate_action_ledger.cash_dividends,
                dividend_payments=self.corporate_action_ledger.dividend_payments,
                currency=self.currency,
            )
        except CorporateActionFactConflict as error:
            raise AccountFactConflict(str(error)) from error
        except CorporateActionLedgerError as error:
            raise AccountProjectionError(str(error)) from error
        if expected_corporate_action_ledger != self.corporate_action_ledger:
            raise AccountProjectionError(
                "account projection requires a canonical corporate-action ledger"
            )

        for evidence_as_of, field_name in (
            (self.ledger.as_of, "execution ledger"),
            (self.corporate_action_ledger.as_of, "corporate-action ledger"),
        ):
            if evidence_as_of is not None and evidence_as_of > self.as_of:
                raise AccountProjectionError(
                    f"account projection as_of precedes its {field_name} evidence"
                )

        if type(self.observed_marks) is not tuple or any(
            type(mark) is not PositionMark for mark in self.observed_marks
        ):
            raise AccountProjectionError(
                "account projection requires immutable exact position marks"
            )
        for observed_mark in self.observed_marks:
            observed_mark.__post_init__()
            if observed_mark.mark_id != canonical_id(
                "position-mark",
                observed_mark.source_event_id,
            ):
                raise AccountProjectionError(
                    "account projection mark does not have its canonical identity"
                )
        canonical_marks, selected_marks = _canonical_marks(self.observed_marks, self.as_of)
        if canonical_marks != self.observed_marks:
            raise AccountProjectionError("account projection marks are not canonical")

        if type(self.positions) is not tuple or any(
            type(position) is not InstrumentAccountProjection for position in self.positions
        ):
            raise AccountProjectionError(
                "account projection requires immutable exact instrument projections"
            )
        if self.positions != tuple(
            sorted(self.positions, key=lambda position: position.instrument_id)
        ):
            raise AccountProjectionError("account positions are not canonically ordered")
        position_ids = tuple(position.instrument_id for position in self.positions)
        if len(position_ids) != len(set(position_ids)):
            raise AccountProjectionError("account projection repeats an instrument")

        for position in self.positions:
            position.__post_init__()
            if position.mark != selected_marks.get(position.instrument_id):
                raise AccountProjectionError(
                    "account position does not bind its selected canonical mark"
                )
            if any(lot.acquired_at > self.as_of for lot in position.open_lots):
                raise AccountProjectionError("account projection as_of precedes open-lot evidence")
            if position.quantity != self.corporate_action_ledger.position_quantity(
                position.instrument_id
            ):
                raise AccountProjectionError(
                    "account units do not reconcile to the corporate-action ledger"
                )

        represented_instruments = set(position_ids)
        ledger_instruments = {
            posting.instrument_id
            for entry in self.ledger.entries
            for posting in entry.postings
            if posting.instrument_id is not None
        }
        if represented_instruments != ledger_instruments:
            raise AccountProjectionError(
                "account positions do not exhaust the execution-ledger instruments"
            )

        expected_cash = self.corporate_action_ledger.cash_balance()
        expected_market_value = exact_decimal_sum(
            position.market_value for position in self.positions
        )
        expected_equity = exact_decimal_add(
            exact_decimal_add(expected_cash, expected_market_value),
            self.corporate_action_ledger.dividend_receivable,
        )
        expected_gross_exposure = exact_decimal_sum(
            position.market_value.copy_abs() for position in self.positions
        )
        expected_net_exposure = exact_decimal_sum(
            position.market_value for position in self.positions
        )
        expected_realized_before_fees = exact_decimal_sum(
            position.realized_pnl_before_fees for position in self.positions
        )
        expected_execution_fees = exact_decimal_sum(
            position.execution_fees for position in self.positions
        )
        ledger_execution_fees = self.ledger.balance(
            "expenses:execution_fees",
            currency=self.currency,
        ).amount
        if expected_execution_fees != ledger_execution_fees:
            raise AccountProjectionError("account fees do not reconcile to the execution ledger")
        expected_dividend_income = exact_decimal_sum(
            position.dividend_income for position in self.positions
        )
        if expected_dividend_income != self.corporate_action_ledger.dividend_income:
            raise AccountProjectionError(
                "account dividend income does not reconcile to the corporate-action ledger"
            )
        expected_realized = exact_decimal_add(
            exact_decimal_subtract(
                expected_realized_before_fees,
                expected_execution_fees,
            ),
            expected_dividend_income,
        )
        if expected_realized != exact_decimal_sum(
            position.realized_pnl for position in self.positions
        ):
            raise AccountProjectionError("account realized P&L does not reconcile to its positions")
        expected_unrealized = exact_decimal_sum(
            position.unrealized_pnl for position in self.positions
        )

        expected_aggregates = (
            ("cash", self.cash, expected_cash),
            ("market_value", self.market_value, expected_market_value),
            ("equity", self.equity, expected_equity),
            ("gross_exposure", self.gross_exposure, expected_gross_exposure),
            ("net_exposure", self.net_exposure, expected_net_exposure),
            (
                "realized_pnl_before_fees",
                self.realized_pnl_before_fees,
                expected_realized_before_fees,
            ),
            ("execution_fees", self.execution_fees, expected_execution_fees),
            ("dividend_income", self.dividend_income, expected_dividend_income),
            (
                "dividend_receivable",
                self.dividend_receivable,
                self.corporate_action_ledger.dividend_receivable,
            ),
            ("realized_pnl", self.realized_pnl, expected_realized),
            ("unrealized_pnl", self.unrealized_pnl, expected_unrealized),
        )
        for field_name, retained, expected in expected_aggregates:
            retained = _persisted(retained, f"account {field_name}")
            if retained != expected:
                raise AccountProjectionError(
                    f"account {field_name} does not match canonical evidence"
                )
            object.__setattr__(self, field_name, expected)

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ACCOUNT_PROJECTION_CONTRACT_VERSION,
                "account_projection",
                self.account_id,
                self.policy,
                self.currency,
                self.ledger.semantic_sha256,
                self.corporate_action_ledger.semantic_sha256,
                tuple(mark.semantic_sha256 for mark in self.observed_marks),
                tuple(position.semantic_sha256 for position in self.positions),
                self.cash,
                self.market_value,
                self.equity,
                self.gross_exposure,
                self.net_exposure,
                self.realized_pnl_before_fees,
                self.execution_fees,
                self.dividend_income,
                self.dividend_receivable,
                self.realized_pnl,
                self.unrealized_pnl,
                self.as_of,
            )
        )


def _create_canonical_account_projection(
    *,
    account_id: str,
    policy: CostBasisPolicy,
    currency: str,
    ledger: CanonicalLedgerState,
    corporate_action_ledger: CanonicalCorporateActionLedgerState,
    observed_marks: tuple[PositionMark, ...],
    positions: tuple[InstrumentAccountProjection, ...],
    cash: Decimal,
    market_value: Decimal,
    equity: Decimal,
    gross_exposure: Decimal,
    net_exposure: Decimal,
    realized_pnl_before_fees: Decimal,
    execution_fees: Decimal,
    dividend_income: Decimal,
    dividend_receivable: Decimal,
    realized_pnl: Decimal,
    unrealized_pnl: Decimal,
    as_of: datetime,
) -> CanonicalAccountProjection:
    """Seal one fully derived account projection for the reducer."""

    projection = object.__new__(CanonicalAccountProjection)
    for field_name, value in (
        ("account_id", account_id),
        ("policy", policy),
        ("currency", currency),
        ("ledger", ledger),
        ("corporate_action_ledger", corporate_action_ledger),
        ("observed_marks", observed_marks),
        ("positions", positions),
        ("cash", cash),
        ("market_value", market_value),
        ("equity", equity),
        ("gross_exposure", gross_exposure),
        ("net_exposure", net_exposure),
        ("realized_pnl_before_fees", realized_pnl_before_fees),
        ("execution_fees", execution_fees),
        ("dividend_income", dividend_income),
        ("dividend_receivable", dividend_receivable),
        ("realized_pnl", realized_pnl),
        ("unrealized_pnl", unrealized_pnl),
        ("as_of", as_of),
    ):
        object.__setattr__(projection, field_name, value)
    projection._validate()
    return projection


@dataclass(slots=True)
class _MutableLot:
    execution_id: str
    order_id: str
    quantity: Decimal
    cost_basis: Decimal
    acquired_at: datetime


@dataclass(frozen=True, slots=True)
class _CurrentExecution:
    instrument_id: str
    symbol: str
    side: Side
    execution_id: str
    order_id: str
    quantity: Decimal
    price: Decimal
    fee: Decimal
    occurred_at: datetime
    received_at: datetime
    broker_sequence: int


def _current_executions(
    states: tuple[CanonicalOrderState, ...],
) -> tuple[_CurrentExecution, ...]:
    executions: list[_CurrentExecution] = []
    execution_owners: dict[str, str] = {}
    for state in states:
        initial_events = {
            event.execution_id: event
            for event in state.broker_events
            if event.kind is BrokerOrderEventKind.EXECUTION
        }
        for current in state.executions:
            existing_order_id = execution_owners.get(current.execution_id)
            if existing_order_id is not None and existing_order_id != state.submission.order_id:
                raise AccountFactConflict("broker execution identity is reused across orders")
            execution_owners[current.execution_id] = state.submission.order_id
            initial = initial_events[current.execution_id]
            executions.append(
                _CurrentExecution(
                    instrument_id=state.submission.intent.instrument_id,
                    symbol=state.submission.intent.symbol,
                    side=state.submission.intent.side,
                    execution_id=current.execution_id,
                    order_id=state.submission.order_id,
                    quantity=current.quantity,
                    price=current.price,
                    fee=current.fee,
                    occurred_at=initial.occurred_at,
                    received_at=initial.received_at,
                    broker_sequence=initial.broker_sequence,
                )
            )
    return tuple(
        sorted(
            executions,
            key=lambda execution: (
                execution.occurred_at,
                execution.received_at,
                execution.order_id,
                execution.broker_sequence,
                execution.execution_id,
            ),
        )
    )


def _canonical_marks(
    marks: tuple[PositionMark, ...],
    valuation_at: datetime,
) -> tuple[tuple[PositionMark, ...], dict[str, PositionMark]]:
    by_id: dict[str, PositionMark] = {}
    by_source: dict[str, PositionMark] = {}
    for mark in marks:
        if type(mark) is not PositionMark:
            raise AccountProjectionError("account projection requires exact PositionMark values")
        existing_id = by_id.get(mark.mark_id)
        if existing_id is not None and existing_id != mark:
            raise AccountFactConflict("mark identity has conflicting semantics")
        existing_source = by_source.get(mark.source_event_id)
        if existing_source is not None and existing_source != mark:
            raise AccountFactConflict("mark source identity has conflicting semantics")
        by_id[mark.mark_id] = mark
        by_source[mark.source_event_id] = mark
    ordered = tuple(
        sorted(
            by_id.values(),
            key=lambda mark: (
                mark.recorded_at,
                mark.effective_at,
                mark.instrument_id,
                mark.mark_id,
            ),
        )
    )
    if any(mark.recorded_at > valuation_at for mark in ordered):
        raise AccountProjectionError("account marks cannot arrive after valuation_at")
    selected: dict[str, PositionMark] = {}
    for mark in ordered:
        previous = selected.get(mark.instrument_id)
        if previous is None or (
            mark.effective_at,
            mark.recorded_at,
            mark.mark_id,
        ) > (
            previous.effective_at,
            previous.recorded_at,
            previous.mark_id,
        ):
            selected[mark.instrument_id] = mark
    return ordered, selected


def project_fifo_account(
    *,
    account_id: str,
    order_states: Iterable[CanonicalOrderState] = (),
    cash_flows: Iterable[LedgerCashFlow] = (),
    marks: Iterable[PositionMark] = (),
    stock_splits: Iterable[StockSplitAction] = (),
    cash_dividends: Iterable[CashDividendAccrual] = (),
    dividend_payments: Iterable[CashDividendPayment] = (),
    valuation_at: datetime,
    currency: str = "USD",
    policy: CostBasisPolicy = CostBasisPolicy.FIFO_TRADE_DATE,
) -> CanonicalAccountProjection:
    """Project a long-only cash account from corrected executions and causal marks."""

    _require_text(account_id, "account_id")
    require_utc(valuation_at, "valuation_at")
    _require_currency(currency)
    if policy is not CostBasisPolicy.FIFO_TRADE_DATE:
        raise AccountProjectionError("unsupported cost-basis policy")
    states = tuple(order_states)
    flows = tuple(cash_flows)
    mark_values = tuple(marks)
    split_values = tuple(stock_splits)
    dividend_values = tuple(cash_dividends)
    payment_values = tuple(dividend_payments)
    try:
        ledger = reduce_execution_ledger(
            order_states=states,
            cash_flows=flows,
            execution_currency=currency,
        )
    except LedgerFactConflict as error:
        raise AccountFactConflict(str(error)) from error
    except ValueError as error:
        raise AccountProjectionError(str(error)) from error
    try:
        corporate_action_ledger = reduce_corporate_action_ledger(
            base_ledger=ledger,
            stock_splits=split_values,
            cash_dividends=dividend_values,
            dividend_payments=payment_values,
            currency=currency,
        )
    except CorporateActionFactConflict as error:
        raise AccountFactConflict(str(error)) from error
    except CorporateActionLedgerError as error:
        raise AccountProjectionError(str(error)) from error
    if corporate_action_ledger.as_of is not None and valuation_at < corporate_action_ledger.as_of:
        raise AccountProjectionError("valuation_at cannot precede the accounting state")
    observed_marks, selected_marks = _canonical_marks(mark_values, valuation_at)
    unique_states = {state.submission.order_id: state for state in states}
    canonical_states = tuple(unique_states[order_id] for order_id in sorted(unique_states))

    lots: dict[str, list[_MutableLot]] = {}
    symbols: dict[str, str] = {}
    realized_by_instrument: dict[str, Decimal] = {}
    fees_by_instrument: dict[str, Decimal] = {}
    dividend_by_instrument: dict[str, Decimal] = {}
    latest_split_by_instrument: dict[str, datetime] = {}
    timeline: list[
        tuple[
            datetime,
            int,
            str,
            StockSplitAction | CashDividendAccrual | _CurrentExecution,
        ]
    ] = []
    timeline.extend(
        (split.effective_at, 0, split.split_id, split)
        for split in corporate_action_ledger.stock_splits
    )
    timeline.extend(
        (dividend.effective_at, 1, dividend.dividend_id, dividend)
        for dividend in corporate_action_ledger.cash_dividends
    )
    timeline.extend(
        (execution.occurred_at, 2, execution.execution_id, execution)
        for execution in _current_executions(canonical_states)
    )
    for _, _, _, account_event in sorted(timeline, key=lambda item: item[:3]):
        if isinstance(account_event, StockSplitAction):
            instrument_lots = lots.get(account_event.instrument_id, [])
            held_quantity = exact_decimal_sum(lot.quantity for lot in instrument_lots)
            if held_quantity != account_event.entitled_quantity:
                raise AccountProjectionError(
                    "stock split entitlement does not match the causal lot book"
                )
            existing_symbol = symbols.get(account_event.instrument_id)
            if existing_symbol != account_event.symbol:
                raise AccountFactConflict("stock split symbol conflicts with lot evidence")
            basis_before = exact_decimal_sum(lot.cost_basis for lot in instrument_lots)
            for lot in instrument_lots:
                new_quantity = deterministic_decimal_divide(
                    exact_decimal_multiply(lot.quantity, account_event.numerator),
                    account_event.denominator,
                )
                if new_quantity != new_quantity.to_integral_value():
                    raise AccountProjectionError(
                        "stock split creates a fractional FIFO lot without cash-in-lieu policy"
                    )
                lot.quantity = _persisted(new_quantity, "split lot quantity")
            basis_after = exact_decimal_sum(lot.cost_basis for lot in instrument_lots)
            if basis_after != basis_before:
                raise AccountProjectionError("stock split does not preserve FIFO cost basis")
            latest_split_by_instrument[account_event.instrument_id] = account_event.effective_at
            continue
        if isinstance(account_event, CashDividendAccrual):
            instrument_lots = lots.get(account_event.instrument_id, [])
            held_quantity = exact_decimal_sum(lot.quantity for lot in instrument_lots)
            if held_quantity != account_event.entitled_quantity:
                raise AccountProjectionError(
                    "cash dividend entitlement does not match the causal lot book"
                )
            existing_symbol = symbols.get(account_event.instrument_id)
            if existing_symbol != account_event.symbol:
                raise AccountFactConflict("dividend symbol conflicts with lot evidence")
            dividend_by_instrument[account_event.instrument_id] = exact_decimal_add(
                dividend_by_instrument.get(account_event.instrument_id, Decimal(0)),
                account_event.amount,
            )
            continue

        if not isinstance(account_event, _CurrentExecution):
            raise AssertionError("account timeline contains an unsupported event")
        execution = account_event
        existing_symbol = symbols.get(execution.instrument_id)
        if existing_symbol is not None and existing_symbol != execution.symbol:
            raise AccountFactConflict("instrument identity has conflicting symbols")
        symbols[execution.instrument_id] = execution.symbol
        fees_by_instrument[execution.instrument_id] = exact_decimal_add(
            fees_by_instrument.get(execution.instrument_id, Decimal(0)),
            execution.fee,
        )
        instrument_lots = lots.setdefault(execution.instrument_id, [])
        if execution.side is Side.BUY:
            if execution.quantity > 0:
                instrument_lots.append(
                    _MutableLot(
                        execution_id=execution.execution_id,
                        order_id=execution.order_id,
                        quantity=execution.quantity,
                        cost_basis=exact_decimal_multiply(
                            execution.quantity,
                            execution.price,
                        ),
                        acquired_at=execution.occurred_at,
                    )
                )
            continue

        remaining = execution.quantity
        cost_basis = Decimal(0)
        while remaining > 0 and instrument_lots:
            lot = instrument_lots[0]
            consumed = min(remaining, lot.quantity)
            if consumed == lot.quantity:
                consumed_basis = lot.cost_basis
            else:
                consumed_basis = _persisted(
                    deterministic_decimal_divide(
                        exact_decimal_multiply(lot.cost_basis, consumed),
                        lot.quantity,
                    ),
                    "partial FIFO basis allocation",
                )
            cost_basis = exact_decimal_add(cost_basis, consumed_basis)
            lot.quantity = exact_decimal_subtract(lot.quantity, consumed)
            lot.cost_basis = exact_decimal_subtract(lot.cost_basis, consumed_basis)
            remaining = exact_decimal_subtract(remaining, consumed)
            if lot.quantity == 0:
                instrument_lots.pop(0)
        if remaining > 0:
            raise AccountProjectionError(
                f"sell execution creates a short position for {execution.instrument_id}"
            )
        proceeds = exact_decimal_multiply(execution.quantity, execution.price)
        realized_by_instrument[execution.instrument_id] = exact_decimal_add(
            realized_by_instrument.get(execution.instrument_id, Decimal(0)),
            exact_decimal_subtract(proceeds, cost_basis),
        )

    projections: list[InstrumentAccountProjection] = []
    for instrument_id in sorted(symbols):
        open_lots = tuple(
            OpenTaxLot(
                execution_id=lot.execution_id,
                order_id=lot.order_id,
                quantity=lot.quantity,
                cost_basis=lot.cost_basis,
                acquired_at=lot.acquired_at,
            )
            for lot in lots.get(instrument_id, ())
        )
        quantity = exact_decimal_sum(lot.quantity for lot in open_lots)
        mark = selected_marks.get(instrument_id)
        if quantity > 0 and mark is None:
            raise AccountProjectionError(f"open position lacks a causal mark for {instrument_id}")
        latest_split_at = latest_split_by_instrument.get(instrument_id)
        if (
            quantity > 0
            and mark is not None
            and latest_split_at is not None
            and mark.effective_at <= latest_split_at
        ):
            raise AccountProjectionError(
                f"open position lacks an unambiguous post-split mark for {instrument_id}"
            )
        symbol = symbols[instrument_id]
        if mark is not None and mark.symbol != symbol:
            raise AccountFactConflict("mark symbol conflicts with execution evidence")
        cost_basis = exact_decimal_sum(lot.cost_basis for lot in open_lots)
        market_value = Decimal(0) if mark is None else exact_decimal_multiply(quantity, mark.price)
        realized_before_fees = realized_by_instrument.get(instrument_id, Decimal(0))
        fees = fees_by_instrument.get(instrument_id, Decimal(0))
        dividend_income = dividend_by_instrument.get(instrument_id, Decimal(0))
        projections.append(
            InstrumentAccountProjection(
                instrument_id=instrument_id,
                symbol=symbol,
                quantity=quantity,
                open_lots=open_lots,
                cost_basis=cost_basis,
                mark=mark,
                market_value=market_value,
                realized_pnl_before_fees=realized_before_fees,
                execution_fees=fees,
                dividend_income=dividend_income,
                realized_pnl=exact_decimal_add(
                    exact_decimal_subtract(realized_before_fees, fees),
                    dividend_income,
                ),
                unrealized_pnl=exact_decimal_subtract(market_value, cost_basis),
            )
        )

    positions = tuple(projections)
    execution_fees = exact_decimal_sum(position.execution_fees for position in positions)
    ledger_fees = ledger.balance("expenses:execution_fees", currency=currency).amount
    if execution_fees != ledger_fees:
        raise AccountProjectionError("account fees do not reconcile to the execution ledger")
    for position in positions:
        if position.quantity != corporate_action_ledger.position_quantity(position.instrument_id):
            raise AccountProjectionError(
                "account units do not reconcile to the corporate-action ledger"
            )
    cash = corporate_action_ledger.cash_balance()
    market_value = exact_decimal_sum(position.market_value for position in positions)
    realized_before_fees = exact_decimal_sum(
        position.realized_pnl_before_fees for position in positions
    )
    dividend_income = exact_decimal_sum(position.dividend_income for position in positions)
    if dividend_income != corporate_action_ledger.dividend_income:
        raise AccountProjectionError(
            "account dividend income does not reconcile to the corporate-action ledger"
        )
    realized = exact_decimal_add(
        exact_decimal_subtract(realized_before_fees, execution_fees),
        dividend_income,
    )
    unrealized = exact_decimal_sum(position.unrealized_pnl for position in positions)
    return _create_canonical_account_projection(
        account_id=account_id,
        policy=policy,
        currency=currency,
        ledger=ledger,
        corporate_action_ledger=corporate_action_ledger,
        observed_marks=observed_marks,
        positions=positions,
        cash=cash,
        market_value=market_value,
        equity=exact_decimal_add(
            exact_decimal_add(cash, market_value),
            corporate_action_ledger.dividend_receivable,
        ),
        gross_exposure=market_value.copy_abs(),
        net_exposure=market_value,
        realized_pnl_before_fees=realized_before_fees,
        execution_fees=execution_fees,
        dividend_income=dividend_income,
        dividend_receivable=corporate_action_ledger.dividend_receivable,
        realized_pnl=realized,
        unrealized_pnl=unrealized,
        as_of=valuation_at,
    )
