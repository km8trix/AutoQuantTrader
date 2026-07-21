"""Pure append-only execution ledger and rebuildable balance projections."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum

from packages.domain.canonical import canonical_json_bytes, canonical_persisted_decimal
from packages.domain.decimal_math import (
    exact_decimal_add,
    exact_decimal_multiply,
    exact_decimal_subtract,
    exact_decimal_sum,
)
from packages.domain.identifiers import canonical_id
from packages.domain.models import Side, require_utc
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    CanonicalOrderState,
    reduce_order_lifecycle,
)

LEDGER_REDUCER_CONTRACT_VERSION = "phase2-execution-ledger-v1"


class LedgerReductionError(ValueError):
    """Raised when financial facts violate the canonical ledger contract."""


class LedgerFactConflict(LedgerReductionError):
    """Raised when one immutable financial identity has conflicting semantics."""


class CashFlowKind(StrEnum):
    CONTRIBUTION = "contribution"
    WITHDRAWAL = "withdrawal"


class LedgerEntryKind(StrEnum):
    CASH_FLOW = "cash_flow"
    EXECUTION = "execution"
    EXECUTION_CORRECTION = "execution_correction"
    SETTLEMENT_RECLASSIFICATION = "settlement_reclassification"
    EXECUTION_SETTLEMENT = "execution_settlement"
    STOCK_SPLIT = "stock_split"
    CASH_DIVIDEND_ACCRUAL = "cash_dividend_accrual"
    CASH_DIVIDEND_PAYMENT = "cash_dividend_payment"


def _require_text(value: str, field_name: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise LedgerReductionError(f"{field_name} must be a non-empty, trimmed string")


def _require_currency(value: str) -> None:
    if type(value) is not str or len(value) != 3 or not value.isalpha() or value != value.upper():
        raise LedgerReductionError("currency must be a three-letter uppercase code")


def _persisted(value: Decimal, field_name: str) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise LedgerReductionError(f"{field_name} must be a finite exact Decimal")
    try:
        return canonical_persisted_decimal(value, field_name)
    except ValueError as error:
        raise LedgerReductionError(str(error)) from error


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class LedgerCashFlow:
    cash_flow_id: str
    kind: CashFlowKind
    currency: str
    amount: Decimal
    effective_at: datetime
    recorded_at: datetime
    external_reference: str

    def __post_init__(self) -> None:
        _require_text(self.cash_flow_id, "cash_flow_id")
        _require_text(self.external_reference, "cash flow external_reference")
        if not isinstance(self.kind, CashFlowKind):
            raise LedgerReductionError("cash flow kind is unsupported")
        _require_currency(self.currency)
        amount = _persisted(self.amount, "cash flow amount")
        if amount <= 0:
            raise LedgerReductionError("cash flow amount must be positive")
        object.__setattr__(self, "amount", amount)
        require_utc(self.effective_at, "cash flow effective_at")
        require_utc(self.recorded_at, "cash flow recorded_at")
        if self.recorded_at < self.effective_at:
            raise LedgerReductionError("cash flow cannot be recorded before it is effective")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                LEDGER_REDUCER_CONTRACT_VERSION,
                "cash_flow",
                self.cash_flow_id,
                self.kind,
                self.currency,
                self.amount,
                self.effective_at,
                self.recorded_at,
                self.external_reference,
            )
        )


def create_cash_flow(
    *,
    kind: CashFlowKind,
    currency: str,
    amount: Decimal,
    effective_at: datetime,
    recorded_at: datetime,
    external_reference: str,
) -> LedgerCashFlow:
    """Create a deterministic external cash-flow fact."""

    return LedgerCashFlow(
        cash_flow_id=canonical_id(
            "ledger-cash-flow",
            external_reference,
        ),
        kind=kind,
        currency=currency,
        amount=amount,
        effective_at=effective_at,
        recorded_at=recorded_at,
        external_reference=external_reference,
    )


@dataclass(frozen=True, slots=True)
class CanonicalLedgerPosting:
    account: str
    currency: str
    debit: Decimal = Decimal(0)
    credit: Decimal = Decimal(0)
    units_delta: Decimal = Decimal(0)
    instrument_id: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.account, "ledger account")
        _require_currency(self.currency)
        debit = _persisted(self.debit, "posting debit")
        credit = _persisted(self.credit, "posting credit")
        units_delta = _persisted(self.units_delta, "posting units_delta")
        if debit < 0 or credit < 0:
            raise LedgerReductionError("posting debit and credit cannot be negative")
        if debit > 0 and credit > 0:
            raise LedgerReductionError("posting cannot contain both a debit and credit")
        if debit == 0 and credit == 0 and units_delta == 0:
            raise LedgerReductionError("posting must contain money or security units")
        if units_delta != 0:
            if self.instrument_id is None:
                raise LedgerReductionError("unit posting requires an instrument_id")
            if units_delta != units_delta.to_integral_value():
                raise LedgerReductionError("security units must be whole shares")
        if self.instrument_id is not None:
            _require_text(self.instrument_id, "posting instrument_id")
        object.__setattr__(self, "debit", debit)
        object.__setattr__(self, "credit", credit)
        object.__setattr__(self, "units_delta", units_delta)

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                LEDGER_REDUCER_CONTRACT_VERSION,
                "posting",
                self.account,
                self.currency,
                self.debit,
                self.credit,
                self.units_delta,
                self.instrument_id,
            )
        )


@dataclass(frozen=True, slots=True)
class CanonicalLedgerEntry:
    entry_id: str
    kind: LedgerEntryKind
    reference_id: str
    source_sha256: str
    effective_at: datetime
    recorded_at: datetime
    postings: tuple[CanonicalLedgerPosting, ...]

    def __post_init__(self) -> None:
        _require_text(self.entry_id, "ledger entry_id")
        _require_text(self.reference_id, "ledger reference_id")
        if not isinstance(self.kind, LedgerEntryKind):
            raise LedgerReductionError("ledger entry kind is unsupported")
        if (
            type(self.source_sha256) is not str
            or len(self.source_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.source_sha256)
        ):
            raise LedgerReductionError("ledger source_sha256 must be a lowercase SHA-256 digest")
        require_utc(self.effective_at, "ledger effective_at")
        require_utc(self.recorded_at, "ledger recorded_at")
        if self.recorded_at < self.effective_at:
            raise LedgerReductionError("ledger entry cannot be recorded before it is effective")
        if type(self.postings) is not tuple or not self.postings:
            raise LedgerReductionError("ledger entry requires immutable postings")
        if any(type(posting) is not CanonicalLedgerPosting for posting in self.postings):
            raise LedgerReductionError("ledger entry requires exact CanonicalLedgerPosting values")
        posting_keys = tuple(
            (posting.account, posting.currency, posting.instrument_id) for posting in self.postings
        )
        if posting_keys != tuple(
            sorted(posting_keys, key=lambda key: (key[0], key[1], key[2] or ""))
        ):
            raise LedgerReductionError("ledger postings must use canonical account order")
        if len(posting_keys) != len(set(posting_keys)):
            raise LedgerReductionError("ledger entry cannot repeat one account balance key")
        total_debits = exact_decimal_sum(posting.debit for posting in self.postings)
        total_credits = exact_decimal_sum(posting.credit for posting in self.postings)
        if total_debits != total_credits:
            raise LedgerReductionError("ledger entry is not balanced")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                LEDGER_REDUCER_CONTRACT_VERSION,
                "entry",
                self.entry_id,
                self.kind,
                self.reference_id,
                self.source_sha256,
                self.effective_at,
                self.recorded_at,
                tuple(posting.semantic_sha256 for posting in self.postings),
            )
        )


@dataclass(frozen=True, slots=True)
class LedgerBalance:
    account: str
    currency: str
    instrument_id: str | None
    amount: Decimal
    units: Decimal

    def __post_init__(self) -> None:
        _require_text(self.account, "balance account")
        _require_currency(self.currency)
        if self.instrument_id is not None:
            _require_text(self.instrument_id, "balance instrument_id")
        object.__setattr__(self, "amount", _persisted(self.amount, "balance amount"))
        units = _persisted(self.units, "balance units")
        if units != units.to_integral_value():
            raise LedgerReductionError("balance units must be whole shares")
        object.__setattr__(self, "units", units)

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                LEDGER_REDUCER_CONTRACT_VERSION,
                "balance",
                self.account,
                self.currency,
                self.instrument_id,
                self.amount,
                self.units,
            )
        )


@dataclass(frozen=True, slots=True)
class CanonicalLedgerState:
    entries: tuple[CanonicalLedgerEntry, ...]
    balances: tuple[LedgerBalance, ...]
    as_of: datetime | None

    def balance(
        self,
        account: str,
        *,
        currency: str = "USD",
        instrument_id: str | None = None,
    ) -> LedgerBalance:
        for balance in self.balances:
            if (
                balance.account == account
                and balance.currency == currency
                and balance.instrument_id == instrument_id
            ):
                return balance
        return LedgerBalance(
            account=account,
            currency=currency,
            instrument_id=instrument_id,
            amount=Decimal(0),
            units=Decimal(0),
        )

    def cash_balance(self, currency: str = "USD") -> Decimal:
        return self.balance(f"assets:cash:{currency}", currency=currency).amount

    def position_quantity(self, instrument_id: str, currency: str = "USD") -> Decimal:
        return self.balance(
            f"clearing:executions:{instrument_id}",
            currency=currency,
            instrument_id=instrument_id,
        ).units

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                LEDGER_REDUCER_CONTRACT_VERSION,
                "state",
                tuple(entry.semantic_sha256 for entry in self.entries),
                tuple(balance.semantic_sha256 for balance in self.balances),
                self.as_of,
            )
        )


def _posting_from_delta(
    *,
    account: str,
    currency: str,
    amount_delta: Decimal,
    units_delta: Decimal = Decimal(0),
    instrument_id: str | None = None,
) -> CanonicalLedgerPosting | None:
    amount_delta = _persisted(amount_delta, f"{account} amount delta")
    units_delta = _persisted(units_delta, f"{account} units delta")
    if amount_delta == 0 and units_delta == 0:
        return None
    return CanonicalLedgerPosting(
        account=account,
        currency=currency,
        debit=amount_delta if amount_delta > 0 else Decimal(0),
        credit=amount_delta.copy_negate() if amount_delta < 0 else Decimal(0),
        units_delta=units_delta,
        instrument_id=instrument_id,
    )


def _entry(
    *,
    kind: LedgerEntryKind,
    reference_id: str,
    source_sha256: str,
    effective_at: datetime,
    recorded_at: datetime,
    postings: Iterable[CanonicalLedgerPosting | None],
) -> CanonicalLedgerEntry:
    canonical_postings = tuple(
        sorted(
            (posting for posting in postings if posting is not None),
            key=lambda posting: (posting.account, posting.currency, posting.instrument_id or ""),
        )
    )
    return CanonicalLedgerEntry(
        entry_id=canonical_id(
            "ledger-entry",
            kind,
            reference_id,
            source_sha256,
        ),
        kind=kind,
        reference_id=reference_id,
        source_sha256=source_sha256,
        effective_at=effective_at,
        recorded_at=recorded_at,
        postings=canonical_postings,
    )


def _cash_flow_entry(cash_flow: LedgerCashFlow) -> CanonicalLedgerEntry:
    direction = Decimal(1) if cash_flow.kind is CashFlowKind.CONTRIBUTION else Decimal(-1)
    cash_delta = exact_decimal_multiply(cash_flow.amount, direction)
    equity_account = (
        "equity:contributions"
        if cash_flow.kind is CashFlowKind.CONTRIBUTION
        else "equity:distributions"
    )
    return _entry(
        kind=LedgerEntryKind.CASH_FLOW,
        reference_id=cash_flow.cash_flow_id,
        source_sha256=cash_flow.semantic_sha256,
        effective_at=cash_flow.effective_at,
        recorded_at=cash_flow.recorded_at,
        postings=(
            _posting_from_delta(
                account=f"assets:cash:{cash_flow.currency}",
                currency=cash_flow.currency,
                amount_delta=cash_delta,
            ),
            _posting_from_delta(
                account=equity_account,
                currency=cash_flow.currency,
                amount_delta=cash_delta.copy_negate(),
            ),
        ),
    )


def _execution_economics(
    event: BrokerOrderEvent,
    side: Side,
) -> tuple[Decimal, Decimal, Decimal, Decimal]:
    assert event.quantity is not None
    assert event.price is not None
    assert event.fee is not None
    notional = exact_decimal_multiply(event.quantity, event.price)
    if side is Side.BUY:
        clearing_delta = notional
        cash_delta = exact_decimal_add(notional, event.fee).copy_negate()
        units_delta = event.quantity
    else:
        clearing_delta = notional.copy_negate()
        cash_delta = exact_decimal_subtract(notional, event.fee)
        units_delta = event.quantity.copy_negate()
    return cash_delta, clearing_delta, event.fee, units_delta


def _execution_entries(
    state: CanonicalOrderState,
    currency: str,
) -> tuple[CanonicalLedgerEntry, ...]:
    predecessors: dict[str, BrokerOrderEvent] = {}
    entries: list[CanonicalLedgerEntry] = []
    intent = state.submission.intent
    for event in state.broker_events:
        if event.kind not in (
            BrokerOrderEventKind.EXECUTION,
            BrokerOrderEventKind.EXECUTION_CORRECTION,
        ):
            continue
        assert event.execution_id is not None
        current = _execution_economics(event, intent.side)
        if event.kind is BrokerOrderEventKind.EXECUTION:
            previous = (Decimal(0), Decimal(0), Decimal(0), Decimal(0))
            kind = LedgerEntryKind.EXECUTION
        else:
            predecessor = predecessors[event.execution_id]
            previous = _execution_economics(predecessor, intent.side)
            kind = LedgerEntryKind.EXECUTION_CORRECTION
        cash_delta, clearing_delta, fee_delta, units_delta = (
            exact_decimal_subtract(current_value, previous_value)
            for current_value, previous_value in zip(current, previous, strict=True)
        )
        entries.append(
            _entry(
                kind=kind,
                reference_id=event.event_id,
                source_sha256=event.semantic_sha256,
                effective_at=event.occurred_at,
                recorded_at=event.received_at,
                postings=(
                    _posting_from_delta(
                        account=f"assets:cash:{currency}",
                        currency=currency,
                        amount_delta=cash_delta,
                    ),
                    _posting_from_delta(
                        account=f"clearing:executions:{intent.instrument_id}",
                        currency=currency,
                        amount_delta=clearing_delta,
                        units_delta=units_delta,
                        instrument_id=intent.instrument_id,
                    ),
                    _posting_from_delta(
                        account="expenses:execution_fees",
                        currency=currency,
                        amount_delta=fee_delta,
                    ),
                ),
            )
        )
        predecessors[event.execution_id] = event
    return tuple(entries)


def reduce_execution_ledger(
    *,
    order_states: Iterable[CanonicalOrderState] = (),
    cash_flows: Iterable[LedgerCashFlow] = (),
    execution_currency: str = "USD",
) -> CanonicalLedgerState:
    """Rebuild append-only entries and balances from exact financial facts."""

    _require_currency(execution_currency)
    unique_orders: dict[str, CanonicalOrderState] = {}
    for state in order_states:
        if type(state) is not CanonicalOrderState:
            raise LedgerReductionError("ledger requires exact CanonicalOrderState values")
        canonical_state = reduce_order_lifecycle(
            submission=state.submission,
            broker_events=state.broker_events,
            cancel_request=state.cancel_request,
        )
        if canonical_state != state:
            raise LedgerReductionError("ledger requires reducer-produced canonical order states")
        order_id = state.submission.order_id
        existing_order = unique_orders.get(order_id)
        if existing_order is not None and existing_order != state:
            raise LedgerFactConflict("order identity has conflicting canonical states")
        unique_orders[order_id] = state

    unique_cash_flows: dict[str, LedgerCashFlow] = {}
    cash_flows_by_external_reference: dict[str, LedgerCashFlow] = {}
    for cash_flow in cash_flows:
        if type(cash_flow) is not LedgerCashFlow:
            raise LedgerReductionError("ledger requires exact LedgerCashFlow values")
        existing_cash_flow = unique_cash_flows.get(cash_flow.cash_flow_id)
        if existing_cash_flow is not None and existing_cash_flow != cash_flow:
            raise LedgerFactConflict("cash flow identity has conflicting semantics")
        existing_external_reference = cash_flows_by_external_reference.get(
            cash_flow.external_reference
        )
        if existing_external_reference is not None and existing_external_reference != cash_flow:
            raise LedgerFactConflict("cash flow external reference has conflicting semantics")
        unique_cash_flows[cash_flow.cash_flow_id] = cash_flow
        cash_flows_by_external_reference[cash_flow.external_reference] = cash_flow

    source_events: dict[str, BrokerOrderEvent] = {}
    entries = [_cash_flow_entry(flow) for flow in unique_cash_flows.values()]
    for order_id in sorted(unique_orders):
        state = unique_orders[order_id]
        for event in state.broker_events:
            if event.kind not in (
                BrokerOrderEventKind.EXECUTION,
                BrokerOrderEventKind.EXECUTION_CORRECTION,
            ):
                continue
            existing_source_event = source_events.get(event.event_id)
            if existing_source_event is not None and existing_source_event != event:
                raise LedgerFactConflict("broker event identity has conflicting ledger semantics")
            source_events[event.event_id] = event
        entries.extend(_execution_entries(state, execution_currency))

    entries.sort(key=lambda entry: (entry.recorded_at, entry.effective_at, entry.entry_id))
    entry_ids: dict[str, CanonicalLedgerEntry] = {}
    for entry in entries:
        existing_entry = entry_ids.get(entry.entry_id)
        if existing_entry is not None and existing_entry != entry:
            raise LedgerFactConflict("ledger entry identity has conflicting semantics")
        entry_ids[entry.entry_id] = entry
    canonical_entries = tuple(entry_ids.values())

    projected: dict[tuple[str, str, str | None], tuple[Decimal, Decimal]] = {}
    for entry in canonical_entries:
        for posting in entry.postings:
            key = (posting.account, posting.currency, posting.instrument_id)
            amount, units = projected.get(key, (Decimal(0), Decimal(0)))
            projected[key] = (
                exact_decimal_add(
                    amount,
                    exact_decimal_subtract(posting.debit, posting.credit),
                ),
                exact_decimal_add(units, posting.units_delta),
            )
    balances = tuple(
        LedgerBalance(
            account=account,
            currency=currency,
            instrument_id=instrument_id,
            amount=amount,
            units=units,
        )
        for (account, currency, instrument_id), (amount, units) in sorted(
            projected.items(),
            key=lambda item: (item[0][0], item[0][1], item[0][2] or ""),
        )
        if amount != 0 or units != 0
    )
    return CanonicalLedgerState(
        entries=canonical_entries,
        balances=balances,
        as_of=None
        if not canonical_entries
        else max(entry.recorded_at for entry in canonical_entries),
    )
