"""Balanced double-entry ledger and rebuildable account projections."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from packages.domain.canonical import canonical_persisted_decimal
from packages.domain.decimal_math import (
    deterministic_decimal_divide,
    exact_decimal_add,
    exact_decimal_multiply,
    exact_decimal_subtract,
    exact_decimal_sum,
)
from packages.domain.identifiers import canonical_id, deterministic_id
from packages.domain.models import (
    AccountProjection,
    Fill,
    LedgerEntry,
    Position,
    Posting,
    Side,
)


class Ledger:
    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []

    @property
    def entries(self) -> tuple[LedgerEntry, ...]:
        return tuple(self._entries)

    def post(self, entry: LedgerEntry) -> None:
        if any(existing.entry_id == entry.entry_id for existing in self._entries):
            raise ValueError("ledger entry IDs are immutable and unique")
        self._entries.append(entry)

    def open_account(self, amount: Decimal, posted_at: datetime) -> LedgerEntry:
        if type(amount) is not Decimal or not amount.is_finite() or amount <= 0:
            raise ValueError("opening balance must be finite and positive")
        amount = canonical_persisted_decimal(amount, "opening balance")
        entry = LedgerEntry(
            entry_id=canonical_id("ledger", "opening", amount, posted_at),
            event_type="opening_balance",
            reference_id="account-opening",
            posted_at=posted_at,
            postings=(
                Posting(account="assets:cash:USD", currency="USD", debit=amount),
                Posting(account="equity:opening", currency="USD", credit=amount),
            ),
        )
        self.post(entry)
        return entry

    def post_fill(self, fill: Fill) -> LedgerEntry:
        if fill.side is not Side.BUY:
            raise ValueError("Phase 0 accounting supports long-only buy fills")
        cash_outflow = exact_decimal_add(fill.notional, fill.fee)
        postings = [
            Posting(
                account=f"assets:securities:{fill.instrument_id}",
                currency="USD",
                debit=fill.notional,
                units_delta=fill.quantity,
                instrument_id=fill.instrument_id,
            ),
            Posting(account="assets:cash:USD", currency="USD", credit=cash_outflow),
        ]
        if fill.fee > 0:
            postings.append(
                Posting(account="expenses:execution_fees", currency="USD", debit=fill.fee)
            )
        entry = LedgerEntry(
            entry_id=deterministic_id("ledger", "fill", fill.fill_id),
            event_type="fill",
            reference_id=fill.fill_id,
            posted_at=fill.executed_at,
            postings=tuple(postings),
        )
        self.post(entry)
        return entry

    def cash_balance(self, currency: str = "USD") -> Decimal:
        account = f"assets:cash:{currency}"
        return exact_decimal_sum(
            exact_decimal_subtract(posting.debit, posting.credit)
            for entry in self._entries
            for posting in entry.postings
            if posting.account == account
        )

    def project_position(
        self,
        instrument_id: str,
        symbol: str,
        market_price: Decimal,
    ) -> Position:
        relevant = [
            posting
            for entry in self._entries
            for posting in entry.postings
            if posting.instrument_id == instrument_id
        ]
        quantity = exact_decimal_sum(posting.units_delta for posting in relevant)
        cost = exact_decimal_sum(
            exact_decimal_subtract(posting.debit, posting.credit) for posting in relevant
        )
        average_cost = deterministic_decimal_divide(cost, quantity) if quantity else Decimal("0")
        return Position(
            instrument_id=instrument_id,
            symbol=symbol,
            quantity=quantity,
            average_cost=average_cost,
            market_price=market_price,
        )

    def project_account(self, position: Position) -> AccountProjection:
        cash = self.cash_balance()
        inventory_cost = exact_decimal_multiply(position.quantity, position.average_cost)
        unrealized_pnl = exact_decimal_subtract(position.market_value, inventory_cost)
        fee_expense = exact_decimal_sum(
            exact_decimal_subtract(posting.debit, posting.credit)
            for entry in self._entries
            for posting in entry.postings
            if posting.account == "expenses:execution_fees"
        )
        realized_pnl = fee_expense.copy_negate()
        equity = exact_decimal_add(cash, position.market_value)
        return AccountProjection(
            currency="USD",
            cash=cash,
            equity=equity,
            realized_pnl=realized_pnl,
            unrealized_pnl=unrealized_pnl,
            gross_exposure=position.market_value.copy_abs(),
            net_exposure=position.market_value,
        )
