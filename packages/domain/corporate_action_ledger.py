"""Pure stock-split and cash-dividend accounting overlay."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

from packages.domain.canonical import canonical_json_bytes, canonical_persisted_decimal
from packages.domain.decimal_math import (
    deterministic_decimal_divide,
    exact_decimal_add,
    exact_decimal_multiply,
    exact_decimal_subtract,
)
from packages.domain.identifiers import canonical_id
from packages.domain.ledger_reducer import (
    CanonicalLedgerEntry,
    CanonicalLedgerPosting,
    CanonicalLedgerState,
    LedgerBalance,
    LedgerEntryKind,
)
from packages.domain.models import require_utc

CORPORATE_ACTION_LEDGER_CONTRACT_VERSION = "phase2-corporate-action-ledger-v1"


class CorporateActionLedgerError(ValueError):
    """Raised when corporate-action evidence violates the accounting contract."""


class CorporateActionFactConflict(CorporateActionLedgerError):
    """Raised when one immutable corporate-action identity conflicts."""


def _require_text(value: str, field_name: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise CorporateActionLedgerError(f"{field_name} must be a non-empty, trimmed string")


def _require_currency(value: str) -> None:
    if type(value) is not str or len(value) != 3 or not value.isalpha() or value != value.upper():
        raise CorporateActionLedgerError("currency must be a three-letter uppercase code")


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CorporateActionLedgerError(f"{field_name} must be a lowercase SHA-256 digest")


def _persisted(value: Decimal, field_name: str) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise CorporateActionLedgerError(f"{field_name} must be a finite exact Decimal")
    try:
        return canonical_persisted_decimal(value, field_name)
    except ValueError as error:
        raise CorporateActionLedgerError(str(error)) from error


def _whole_quantity(value: Decimal, field_name: str) -> Decimal:
    value = _persisted(value, field_name)
    if value <= 0 or value != value.to_integral_value():
        raise CorporateActionLedgerError(f"{field_name} must be positive whole shares")
    return value


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class StockSplitAction:
    split_id: str
    source_action_id: str
    source_revision_id: str
    source_sha256: str
    instrument_id: str
    symbol: str
    numerator: Decimal
    denominator: Decimal
    entitled_quantity: Decimal
    effective_at: datetime
    recorded_at: datetime

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.split_id, "split_id"),
            (self.source_action_id, "split source_action_id"),
            (self.source_revision_id, "split source_revision_id"),
            (self.instrument_id, "split instrument_id"),
            (self.symbol, "split symbol"),
        ):
            _require_text(value, field_name)
        _require_sha256(self.source_sha256, "split source_sha256")
        if self.symbol != self.symbol.upper():
            raise CorporateActionLedgerError("split symbol must use canonical uppercase form")
        numerator = _whole_quantity(self.numerator, "split numerator")
        denominator = _whole_quantity(self.denominator, "split denominator")
        if numerator == denominator:
            raise CorporateActionLedgerError("stock split ratio cannot be neutral")
        entitled_quantity = _whole_quantity(
            self.entitled_quantity,
            "split entitled_quantity",
        )
        post_split_quantity = deterministic_decimal_divide(
            exact_decimal_multiply(entitled_quantity, numerator),
            denominator,
        )
        if post_split_quantity != post_split_quantity.to_integral_value():
            raise CorporateActionLedgerError(
                "stock split requires unsupported fractional shares or cash-in-lieu"
            )
        object.__setattr__(self, "numerator", numerator)
        object.__setattr__(self, "denominator", denominator)
        object.__setattr__(self, "entitled_quantity", entitled_quantity)
        require_utc(self.effective_at, "split effective_at")
        require_utc(self.recorded_at, "split recorded_at")
        if self.recorded_at < self.effective_at:
            raise CorporateActionLedgerError("split cannot be recorded before it is effective")

    @property
    def post_split_quantity(self) -> Decimal:
        return deterministic_decimal_divide(
            exact_decimal_multiply(self.entitled_quantity, self.numerator),
            self.denominator,
        )

    @property
    def units_delta(self) -> Decimal:
        return exact_decimal_subtract(self.post_split_quantity, self.entitled_quantity)

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                CORPORATE_ACTION_LEDGER_CONTRACT_VERSION,
                "stock_split",
                self.split_id,
                self.source_action_id,
                self.source_revision_id,
                self.source_sha256,
                self.instrument_id,
                self.symbol,
                self.numerator,
                self.denominator,
                self.entitled_quantity,
                self.effective_at,
                self.recorded_at,
            )
        )


def create_stock_split(
    *,
    source_action_id: str,
    source_revision_id: str,
    source_sha256: str,
    instrument_id: str,
    symbol: str,
    numerator: Decimal,
    denominator: Decimal,
    entitled_quantity: Decimal,
    effective_at: datetime,
    recorded_at: datetime,
) -> StockSplitAction:
    """Create an admitted split-accounting fact from explicit entitlement evidence."""

    return StockSplitAction(
        split_id=canonical_id("stock-split", source_action_id),
        source_action_id=source_action_id,
        source_revision_id=source_revision_id,
        source_sha256=source_sha256,
        instrument_id=instrument_id,
        symbol=symbol,
        numerator=numerator,
        denominator=denominator,
        entitled_quantity=entitled_quantity,
        effective_at=effective_at,
        recorded_at=recorded_at,
    )


@dataclass(frozen=True, slots=True)
class CashDividendAccrual:
    dividend_id: str
    source_action_id: str
    source_revision_id: str
    source_sha256: str
    instrument_id: str
    symbol: str
    currency: str
    amount_per_share: Decimal
    entitled_quantity: Decimal
    effective_at: datetime
    payable_at: datetime
    recorded_at: datetime

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.dividend_id, "dividend_id"),
            (self.source_action_id, "dividend source_action_id"),
            (self.source_revision_id, "dividend source_revision_id"),
            (self.instrument_id, "dividend instrument_id"),
            (self.symbol, "dividend symbol"),
        ):
            _require_text(value, field_name)
        _require_sha256(self.source_sha256, "dividend source_sha256")
        if self.symbol != self.symbol.upper():
            raise CorporateActionLedgerError("dividend symbol must use canonical uppercase form")
        _require_currency(self.currency)
        amount = _persisted(self.amount_per_share, "dividend amount_per_share")
        if amount <= 0:
            raise CorporateActionLedgerError("dividend amount_per_share must be positive")
        entitled_quantity = _whole_quantity(
            self.entitled_quantity,
            "dividend entitled_quantity",
        )
        object.__setattr__(self, "amount_per_share", amount)
        object.__setattr__(self, "entitled_quantity", entitled_quantity)
        require_utc(self.effective_at, "dividend effective_at")
        require_utc(self.payable_at, "dividend payable_at")
        require_utc(self.recorded_at, "dividend recorded_at")
        if self.payable_at < self.effective_at:
            raise CorporateActionLedgerError("dividend payable time cannot precede entitlement")
        if self.recorded_at < self.effective_at:
            raise CorporateActionLedgerError("dividend cannot be recorded before entitlement")

    @property
    def amount(self) -> Decimal:
        return exact_decimal_multiply(self.entitled_quantity, self.amount_per_share)

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                CORPORATE_ACTION_LEDGER_CONTRACT_VERSION,
                "cash_dividend_accrual",
                self.dividend_id,
                self.source_action_id,
                self.source_revision_id,
                self.source_sha256,
                self.instrument_id,
                self.symbol,
                self.currency,
                self.amount_per_share,
                self.entitled_quantity,
                self.effective_at,
                self.payable_at,
                self.recorded_at,
            )
        )


def create_cash_dividend(
    *,
    source_action_id: str,
    source_revision_id: str,
    source_sha256: str,
    instrument_id: str,
    symbol: str,
    currency: str,
    amount_per_share: Decimal,
    entitled_quantity: Decimal,
    effective_at: datetime,
    payable_at: datetime,
    recorded_at: datetime,
) -> CashDividendAccrual:
    """Create an admitted cash-dividend accrual with explicit entitlement."""

    return CashDividendAccrual(
        dividend_id=canonical_id("cash-dividend", source_action_id),
        source_action_id=source_action_id,
        source_revision_id=source_revision_id,
        source_sha256=source_sha256,
        instrument_id=instrument_id,
        symbol=symbol,
        currency=currency,
        amount_per_share=amount_per_share,
        entitled_quantity=entitled_quantity,
        effective_at=effective_at,
        payable_at=payable_at,
        recorded_at=recorded_at,
    )


@dataclass(frozen=True, slots=True)
class CashDividendPayment:
    payment_id: str
    dividend_id: str
    dividend_sha256: str
    paid_at: datetime
    recorded_at: datetime
    external_reference: str

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.payment_id, "dividend payment_id"),
            (self.dividend_id, "payment dividend_id"),
            (self.external_reference, "dividend payment external_reference"),
        ):
            _require_text(value, field_name)
        _require_sha256(self.dividend_sha256, "payment dividend_sha256")
        require_utc(self.paid_at, "dividend paid_at")
        require_utc(self.recorded_at, "dividend payment recorded_at")
        if self.recorded_at < self.paid_at:
            raise CorporateActionLedgerError("dividend payment cannot be recorded before payment")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                CORPORATE_ACTION_LEDGER_CONTRACT_VERSION,
                "cash_dividend_payment",
                self.payment_id,
                self.dividend_id,
                self.dividend_sha256,
                self.paid_at,
                self.recorded_at,
                self.external_reference,
            )
        )


def create_dividend_payment(
    dividend: CashDividendAccrual,
    *,
    paid_at: datetime,
    recorded_at: datetime,
    external_reference: str,
) -> CashDividendPayment:
    """Confirm cash receipt for one exact dividend accrual."""

    if type(dividend) is not CashDividendAccrual:
        raise CorporateActionLedgerError("payment requires an exact dividend accrual")
    require_utc(paid_at, "dividend paid_at")
    require_utc(recorded_at, "dividend payment recorded_at")
    if paid_at < dividend.payable_at:
        raise CorporateActionLedgerError("dividend payment cannot precede payable_at")
    if recorded_at < dividend.recorded_at:
        raise CorporateActionLedgerError("dividend payment cannot be recorded before its accrual")
    return CashDividendPayment(
        payment_id=canonical_id("cash-dividend-payment", external_reference),
        dividend_id=dividend.dividend_id,
        dividend_sha256=dividend.semantic_sha256,
        paid_at=paid_at,
        recorded_at=recorded_at,
        external_reference=external_reference,
    )


@dataclass(frozen=True, slots=True)
class CanonicalCorporateActionLedgerState:
    base_ledger: CanonicalLedgerState
    corporate_action_entries: tuple[CanonicalLedgerEntry, ...]
    balances: tuple[LedgerBalance, ...]
    stock_splits: tuple[StockSplitAction, ...]
    cash_dividends: tuple[CashDividendAccrual, ...]
    dividend_payments: tuple[CashDividendPayment, ...]
    currency: str
    dividend_income: Decimal
    dividend_receivable: Decimal
    as_of: datetime | None

    def balance(
        self,
        account: str,
        *,
        instrument_id: str | None = None,
    ) -> LedgerBalance:
        for balance in self.balances:
            if (
                balance.account == account
                and balance.currency == self.currency
                and balance.instrument_id == instrument_id
            ):
                return balance
        return LedgerBalance(
            account=account,
            currency=self.currency,
            instrument_id=instrument_id,
            amount=Decimal(0),
            units=Decimal(0),
        )

    def cash_balance(self) -> Decimal:
        return self.balance(f"assets:cash:{self.currency}").amount

    def position_quantity(self, instrument_id: str) -> Decimal:
        execution_units = self.balance(
            f"clearing:executions:{instrument_id}",
            instrument_id=instrument_id,
        ).units
        split_units = self.balance(
            f"corporate-actions:splits:{instrument_id}",
            instrument_id=instrument_id,
        ).units
        return exact_decimal_add(execution_units, split_units)

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                CORPORATE_ACTION_LEDGER_CONTRACT_VERSION,
                "state",
                self.base_ledger.semantic_sha256,
                tuple(entry.semantic_sha256 for entry in self.corporate_action_entries),
                tuple(balance.semantic_sha256 for balance in self.balances),
                tuple(split.semantic_sha256 for split in self.stock_splits),
                tuple(dividend.semantic_sha256 for dividend in self.cash_dividends),
                tuple(payment.semantic_sha256 for payment in self.dividend_payments),
                self.currency,
                self.dividend_income,
                self.dividend_receivable,
                self.as_of,
            )
        )


def _posting(
    *,
    account: str,
    currency: str,
    amount_delta: Decimal = Decimal(0),
    units_delta: Decimal = Decimal(0),
    instrument_id: str | None = None,
) -> CanonicalLedgerPosting:
    amount_delta = _persisted(amount_delta, f"{account} corporate-action amount")
    units_delta = _persisted(units_delta, f"{account} corporate-action units")
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
    postings: tuple[CanonicalLedgerPosting, ...],
) -> CanonicalLedgerEntry:
    return CanonicalLedgerEntry(
        entry_id=canonical_id("corporate-action-entry", kind, reference_id, source_sha256),
        kind=kind,
        reference_id=reference_id,
        source_sha256=source_sha256,
        effective_at=effective_at,
        recorded_at=recorded_at,
        postings=tuple(
            sorted(
                postings,
                key=lambda posting: (
                    posting.account,
                    posting.currency,
                    posting.instrument_id or "",
                ),
            )
        ),
    )


def _validate_base_ledger(base_ledger: CanonicalLedgerState) -> None:
    if type(base_ledger) is not CanonicalLedgerState:
        raise CorporateActionLedgerError("corporate actions require an exact ledger state")
    if type(base_ledger.entries) is not tuple or any(
        type(entry) is not CanonicalLedgerEntry for entry in base_ledger.entries
    ):
        raise CorporateActionLedgerError("corporate actions require exact ledger entries")
    if type(base_ledger.balances) is not tuple or any(
        type(balance) is not LedgerBalance for balance in base_ledger.balances
    ):
        raise CorporateActionLedgerError("corporate actions require exact ledger balances")
    canonical_entries = tuple(
        sorted(
            base_ledger.entries,
            key=lambda entry: (entry.recorded_at, entry.effective_at, entry.entry_id),
        )
    )
    if base_ledger.entries != canonical_entries:
        raise CorporateActionLedgerError("base ledger entries are not canonically ordered")
    if len({entry.entry_id for entry in base_ledger.entries}) != len(base_ledger.entries):
        raise CorporateActionLedgerError("base ledger repeats an entry identity")
    allowed_kinds = {
        LedgerEntryKind.CASH_FLOW,
        LedgerEntryKind.EXECUTION,
        LedgerEntryKind.EXECUTION_CORRECTION,
    }
    if any(entry.kind not in allowed_kinds for entry in base_ledger.entries):
        raise CorporateActionLedgerError("corporate actions require an execution-ledger base")
    for entry in base_ledger.entries:
        for posting in entry.postings:
            if posting.units_delta != 0 and posting.account != (
                f"clearing:executions:{posting.instrument_id}"
            ):
                raise CorporateActionLedgerError(
                    "base ledger contains unsupported security-unit postings"
                )
    balances = _project_balances(base_ledger.entries)
    expected_as_of = (
        None if not base_ledger.entries else max(entry.recorded_at for entry in base_ledger.entries)
    )
    if balances != base_ledger.balances or expected_as_of != base_ledger.as_of:
        raise CorporateActionLedgerError("corporate actions require a canonical ledger state")


@dataclass(frozen=True, slots=True)
class _BaseUnitDelta:
    entry_id: str
    instrument_id: str
    units_delta: Decimal
    effective_at: datetime


def _validate_causal_entitlements(
    base_ledger: CanonicalLedgerState,
    splits: tuple[StockSplitAction, ...],
    dividends: tuple[CashDividendAccrual, ...],
) -> None:
    unit_deltas: list[_BaseUnitDelta] = []
    position_change_keys: set[tuple[datetime, str]] = set()
    for entry in base_ledger.entries:
        for posting in entry.postings:
            if posting.units_delta == 0:
                continue
            assert posting.instrument_id is not None
            key = (entry.effective_at, posting.instrument_id)
            position_change_keys.add(key)
            unit_deltas.append(
                _BaseUnitDelta(
                    entry_id=entry.entry_id,
                    instrument_id=posting.instrument_id,
                    units_delta=posting.units_delta,
                    effective_at=entry.effective_at,
                )
            )

    split_keys: set[tuple[datetime, str]] = set()
    for split in splits:
        key = (split.effective_at, split.instrument_id)
        if key in position_change_keys:
            raise CorporateActionLedgerError(
                "corporate-action entitlement is ambiguous at a position-change time"
            )
        if key in split_keys:
            raise CorporateActionLedgerError(
                "multiple stock splits share an ambiguous effective time"
            )
        split_keys.add(key)
    for dividend in dividends:
        key = (dividend.effective_at, dividend.instrument_id)
        if key in position_change_keys:
            raise CorporateActionLedgerError(
                "corporate-action entitlement is ambiguous at a position-change time"
            )
        if key in split_keys:
            raise CorporateActionLedgerError(
                "split and dividend entitlements share an ambiguous effective time"
            )

    timeline: list[
        tuple[
            datetime,
            int,
            str,
            _BaseUnitDelta | StockSplitAction | CashDividendAccrual,
        ]
    ] = []
    timeline.extend((delta.effective_at, 0, delta.entry_id, delta) for delta in unit_deltas)
    timeline.extend((split.effective_at, 1, split.split_id, split) for split in splits)
    timeline.extend(
        (dividend.effective_at, 2, dividend.dividend_id, dividend) for dividend in dividends
    )
    quantities: dict[str, Decimal] = {}
    for _, _, _, event in sorted(timeline, key=lambda item: item[:3]):
        if isinstance(event, _BaseUnitDelta):
            quantities[event.instrument_id] = exact_decimal_add(
                quantities.get(event.instrument_id, Decimal(0)),
                event.units_delta,
            )
            continue
        held_quantity = quantities.get(event.instrument_id, Decimal(0))
        if held_quantity != event.entitled_quantity:
            action = "stock split" if isinstance(event, StockSplitAction) else "cash dividend"
            raise CorporateActionLedgerError(
                f"{action} entitlement does not match causal ledger units"
            )
        if isinstance(event, StockSplitAction):
            quantities[event.instrument_id] = exact_decimal_add(
                held_quantity,
                event.units_delta,
            )


def _project_balances(
    entries: tuple[CanonicalLedgerEntry, ...],
) -> tuple[LedgerBalance, ...]:
    projected: dict[tuple[str, str, str | None], tuple[Decimal, Decimal]] = {}
    for entry in entries:
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
    return tuple(
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


def _unique_facts[T](
    values: tuple[T, ...],
    *,
    expected_type: type[T],
    identity: Callable[[T], str],
    source_identity: Callable[[T], str],
    label: str,
) -> tuple[T, ...]:
    by_id: dict[str, T] = {}
    by_source: dict[str, T] = {}
    for value in values:
        if type(value) is not expected_type:
            raise CorporateActionLedgerError(f"{label} requires exact immutable facts")
        value_id = identity(value)
        source_id = source_identity(value)
        existing_id = by_id.get(value_id)
        if existing_id is not None and existing_id != value:
            raise CorporateActionFactConflict(f"{label} identity has conflicting semantics")
        existing_source = by_source.get(source_id)
        if existing_source is not None and existing_source != value:
            raise CorporateActionFactConflict(f"{label} source identity has conflicting semantics")
        by_id[value_id] = value
        by_source[source_id] = value
    return tuple(by_id.values())


def reduce_corporate_action_ledger(
    *,
    base_ledger: CanonicalLedgerState,
    stock_splits: Iterable[StockSplitAction] = (),
    cash_dividends: Iterable[CashDividendAccrual] = (),
    dividend_payments: Iterable[CashDividendPayment] = (),
    currency: str = "USD",
) -> CanonicalCorporateActionLedgerState:
    """Overlay admitted split and dividend facts on a canonical ledger."""

    _require_currency(currency)
    _validate_base_ledger(base_ledger)
    splits = _unique_facts(
        tuple(stock_splits),
        expected_type=StockSplitAction,
        identity=lambda split: split.split_id,
        source_identity=lambda split: split.source_action_id,
        label="stock split",
    )
    dividends = _unique_facts(
        tuple(cash_dividends),
        expected_type=CashDividendAccrual,
        identity=lambda dividend: dividend.dividend_id,
        source_identity=lambda dividend: dividend.source_action_id,
        label="cash dividend",
    )
    payments = _unique_facts(
        tuple(dividend_payments),
        expected_type=CashDividendPayment,
        identity=lambda payment: payment.payment_id,
        source_identity=lambda payment: payment.external_reference,
        label="dividend payment",
    )
    source_actions = [split.source_action_id for split in splits]
    source_actions.extend(dividend.source_action_id for dividend in dividends)
    if len(source_actions) != len(set(source_actions)):
        raise CorporateActionFactConflict("corporate-action source identity is reused")
    source_revisions = [split.source_revision_id for split in splits]
    source_revisions.extend(dividend.source_revision_id for dividend in dividends)
    if len(source_revisions) != len(set(source_revisions)):
        raise CorporateActionFactConflict("corporate-action source revision is reused")
    _validate_causal_entitlements(base_ledger, splits, dividends)
    dividends_by_id = {dividend.dividend_id: dividend for dividend in dividends}
    payments_by_dividend: dict[str, CashDividendPayment] = {}
    for payment in payments:
        dividend = dividends_by_id.get(payment.dividend_id)
        if dividend is None:
            raise CorporateActionLedgerError("dividend payment has no known accrual")
        if payment.dividend_sha256 != dividend.semantic_sha256:
            raise CorporateActionLedgerError("dividend payment does not bind its accrual")
        if payment.paid_at < dividend.payable_at:
            raise CorporateActionLedgerError("dividend payment precedes payable_at")
        if payment.recorded_at < dividend.recorded_at:
            raise CorporateActionLedgerError("dividend payment predates its accrual")
        existing = payments_by_dividend.get(payment.dividend_id)
        if existing is not None and existing != payment:
            raise CorporateActionFactConflict("dividend has conflicting payments")
        payments_by_dividend[payment.dividend_id] = payment

    entries: list[CanonicalLedgerEntry] = []
    for split in splits:
        if split.units_delta == 0:
            raise CorporateActionLedgerError("stock split cannot have zero unit effect")
        entries.append(
            _entry(
                kind=LedgerEntryKind.STOCK_SPLIT,
                reference_id=split.split_id,
                source_sha256=split.semantic_sha256,
                effective_at=split.effective_at,
                recorded_at=split.recorded_at,
                postings=(
                    _posting(
                        account=f"corporate-actions:splits:{split.instrument_id}",
                        currency=currency,
                        units_delta=split.units_delta,
                        instrument_id=split.instrument_id,
                    ),
                ),
            )
        )
    for dividend in dividends:
        if dividend.currency != currency:
            raise CorporateActionLedgerError("dividend currency differs from account currency")
        entries.append(
            _entry(
                kind=LedgerEntryKind.CASH_DIVIDEND_ACCRUAL,
                reference_id=dividend.dividend_id,
                source_sha256=dividend.semantic_sha256,
                effective_at=dividend.effective_at,
                recorded_at=dividend.recorded_at,
                postings=(
                    _posting(
                        account="assets:dividend_receivable",
                        currency=currency,
                        amount_delta=dividend.amount,
                    ),
                    _posting(
                        account="income:cash_dividends",
                        currency=currency,
                        amount_delta=dividend.amount.copy_negate(),
                    ),
                ),
            )
        )
        matching_payment = payments_by_dividend.get(dividend.dividend_id)
        if matching_payment is not None:
            entries.append(
                _entry(
                    kind=LedgerEntryKind.CASH_DIVIDEND_PAYMENT,
                    reference_id=matching_payment.payment_id,
                    source_sha256=matching_payment.semantic_sha256,
                    effective_at=matching_payment.paid_at,
                    recorded_at=matching_payment.recorded_at,
                    postings=(
                        _posting(
                            account=f"assets:cash:{currency}",
                            currency=currency,
                            amount_delta=dividend.amount,
                        ),
                        _posting(
                            account="assets:dividend_receivable",
                            currency=currency,
                            amount_delta=dividend.amount.copy_negate(),
                        ),
                    ),
                )
            )

    corporate_entries = tuple(
        sorted(entries, key=lambda entry: (entry.recorded_at, entry.effective_at, entry.entry_id))
    )
    all_entries = tuple(
        sorted(
            (*base_ledger.entries, *corporate_entries),
            key=lambda entry: (entry.recorded_at, entry.effective_at, entry.entry_id),
        )
    )
    balances = _project_balances(all_entries)

    def amount(account: str) -> Decimal:
        for balance in balances:
            if balance.account == account and balance.currency == currency:
                return balance.amount
        return Decimal(0)

    dividend_income_balance = amount("income:cash_dividends")
    receivable = amount("assets:dividend_receivable")
    if dividend_income_balance > 0 or receivable < 0:
        raise CorporateActionLedgerError("dividend accounts have invalid orientation")
    return CanonicalCorporateActionLedgerState(
        base_ledger=base_ledger,
        corporate_action_entries=corporate_entries,
        balances=balances,
        stock_splits=tuple(
            sorted(
                splits, key=lambda split: (split.effective_at, split.recorded_at, split.split_id)
            )
        ),
        cash_dividends=tuple(
            sorted(
                dividends,
                key=lambda dividend: (
                    dividend.effective_at,
                    dividend.recorded_at,
                    dividend.dividend_id,
                ),
            )
        ),
        dividend_payments=tuple(
            sorted(payments, key=lambda payment: (payment.paid_at, payment.payment_id))
        ),
        currency=currency,
        dividend_income=dividend_income_balance.copy_negate(),
        dividend_receivable=receivable,
        as_of=None if not all_entries else max(entry.recorded_at for entry in all_entries),
    )
