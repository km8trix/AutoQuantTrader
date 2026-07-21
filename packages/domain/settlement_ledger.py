"""Pure execution-settlement ledger layered over trade-date postings."""

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
)
from packages.domain.identifiers import canonical_id
from packages.domain.ledger_reducer import (
    CanonicalLedgerEntry,
    CanonicalLedgerPosting,
    CanonicalLedgerState,
    LedgerBalance,
    LedgerCashFlow,
    LedgerEntryKind,
    LedgerFactConflict,
    reduce_execution_ledger,
)
from packages.domain.models import Side, require_utc
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    CanonicalOrderState,
)

SETTLEMENT_LEDGER_CONTRACT_VERSION = "phase2-execution-settlement-v2"


class SettlementLedgerError(ValueError):
    """Raised when settlement evidence violates the canonical contract."""


class SettlementFactConflict(SettlementLedgerError):
    """Raised when one immutable settlement identity has conflicting semantics."""


class SettlementDirection(StrEnum):
    RECEIVABLE = "receivable"
    PAYABLE = "payable"


class SettlementStatus(StrEnum):
    UNSETTLED = "unsettled"
    SETTLED = "settled"


def _require_text(value: str, field_name: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise SettlementLedgerError(f"{field_name} must be a non-empty, trimmed string")


def _require_currency(value: str) -> None:
    if type(value) is not str or len(value) != 3 or not value.isalpha() or value != value.upper():
        raise SettlementLedgerError("currency must be a three-letter uppercase code")


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SettlementLedgerError(f"{field_name} must be a lowercase SHA-256 digest")


def _persisted(value: Decimal, field_name: str) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise SettlementLedgerError(f"{field_name} must be a finite exact Decimal")
    try:
        return canonical_persisted_decimal(value, field_name)
    except ValueError as error:
        raise SettlementLedgerError(str(error)) from error


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class ExecutionSettlementInstruction:
    instruction_id: str
    execution_event_id: str
    execution_event_sha256: str
    contractual_settlement_at: datetime
    recorded_at: datetime
    external_reference: str

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.instruction_id, "settlement instruction_id"),
            (self.execution_event_id, "settlement execution_event_id"),
            (self.external_reference, "settlement external_reference"),
        ):
            _require_text(value, field_name)
        _require_sha256(self.execution_event_sha256, "settlement execution_event_sha256")
        require_utc(self.contractual_settlement_at, "contractual_settlement_at")
        require_utc(self.recorded_at, "settlement instruction recorded_at")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                SETTLEMENT_LEDGER_CONTRACT_VERSION,
                "instruction",
                self.instruction_id,
                self.execution_event_id,
                self.execution_event_sha256,
                self.contractual_settlement_at,
                self.recorded_at,
                self.external_reference,
            )
        )


def create_settlement_instruction(
    event: BrokerOrderEvent,
    *,
    contractual_settlement_at: datetime,
    recorded_at: datetime,
    external_reference: str,
) -> ExecutionSettlementInstruction:
    """Bind one contractual settlement instruction to an exact execution revision."""

    if type(event) is not BrokerOrderEvent or event.kind not in (
        BrokerOrderEventKind.EXECUTION,
        BrokerOrderEventKind.EXECUTION_CORRECTION,
    ):
        raise SettlementLedgerError("settlement instruction requires an execution event")
    if contractual_settlement_at < event.occurred_at:
        raise SettlementLedgerError("contractual settlement cannot precede execution")
    if recorded_at < event.received_at:
        raise SettlementLedgerError("settlement instruction cannot predate execution receipt")
    return ExecutionSettlementInstruction(
        instruction_id=canonical_id("settlement-instruction", external_reference),
        execution_event_id=event.event_id,
        execution_event_sha256=event.semantic_sha256,
        contractual_settlement_at=contractual_settlement_at,
        recorded_at=recorded_at,
        external_reference=external_reference,
    )


@dataclass(frozen=True, slots=True)
class ExecutionSettlementConfirmation:
    confirmation_id: str
    instruction_id: str
    instruction_sha256: str
    settled_at: datetime
    recorded_at: datetime
    external_reference: str

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.confirmation_id, "settlement confirmation_id"),
            (self.instruction_id, "settlement confirmation instruction_id"),
            (self.external_reference, "settlement confirmation external_reference"),
        ):
            _require_text(value, field_name)
        _require_sha256(self.instruction_sha256, "settlement instruction_sha256")
        require_utc(self.settled_at, "settled_at")
        require_utc(self.recorded_at, "settlement confirmation recorded_at")
        if self.recorded_at < self.settled_at:
            raise SettlementLedgerError("settlement cannot be recorded before it occurred")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                SETTLEMENT_LEDGER_CONTRACT_VERSION,
                "confirmation",
                self.confirmation_id,
                self.instruction_id,
                self.instruction_sha256,
                self.settled_at,
                self.recorded_at,
                self.external_reference,
            )
        )


def create_settlement_confirmation(
    instruction: ExecutionSettlementInstruction,
    *,
    settled_at: datetime,
    recorded_at: datetime,
    external_reference: str,
) -> ExecutionSettlementConfirmation:
    """Confirm the actual settlement of one exact instruction."""

    if type(instruction) is not ExecutionSettlementInstruction:
        raise SettlementLedgerError("settlement confirmation requires an exact instruction")
    if settled_at < instruction.recorded_at:
        raise SettlementLedgerError("actual settlement cannot predate its instruction")
    return ExecutionSettlementConfirmation(
        confirmation_id=canonical_id("settlement-confirmation", external_reference),
        instruction_id=instruction.instruction_id,
        instruction_sha256=instruction.semantic_sha256,
        settled_at=settled_at,
        recorded_at=recorded_at,
        external_reference=external_reference,
    )


@dataclass(frozen=True, slots=True)
class SettlementObligation:
    instruction: ExecutionSettlementInstruction
    confirmation: ExecutionSettlementConfirmation | None
    order_id: str
    execution_id: str
    execution_event_id: str
    direction: SettlementDirection
    amount: Decimal
    status: SettlementStatus

    def __post_init__(self) -> None:
        if type(self.instruction) is not ExecutionSettlementInstruction:
            raise SettlementLedgerError("obligation requires an exact settlement instruction")
        if (
            self.confirmation is not None
            and type(self.confirmation) is not ExecutionSettlementConfirmation
        ):
            raise SettlementLedgerError("obligation confirmation has an unsupported type")
        for value, field_name in (
            (self.order_id, "obligation order_id"),
            (self.execution_id, "obligation execution_id"),
            (self.execution_event_id, "obligation execution_event_id"),
        ):
            _require_text(value, field_name)
        if not isinstance(self.direction, SettlementDirection):
            raise SettlementLedgerError("obligation direction is unsupported")
        amount = _persisted(self.amount, "settlement obligation amount")
        if amount <= 0:
            raise SettlementLedgerError("settlement obligation amount must be positive")
        object.__setattr__(self, "amount", amount)
        expected_status = (
            SettlementStatus.SETTLED
            if self.confirmation is not None
            else SettlementStatus.UNSETTLED
        )
        if self.status is not expected_status:
            raise SettlementLedgerError("obligation status disagrees with confirmation evidence")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                SETTLEMENT_LEDGER_CONTRACT_VERSION,
                "obligation",
                self.instruction.semantic_sha256,
                None if self.confirmation is None else self.confirmation.semantic_sha256,
                self.order_id,
                self.execution_id,
                self.execution_event_id,
                self.direction,
                self.amount,
                self.status,
            )
        )


@dataclass(frozen=True, slots=True, init=False)
class CanonicalSettlementLedgerState:
    """A canonical settlement aggregate sealed by the trusted reducer."""

    account_id: str
    trade_date_ledger: CanonicalLedgerState
    settlement_entries: tuple[CanonicalLedgerEntry, ...]
    balances: tuple[LedgerBalance, ...]
    obligations: tuple[SettlementObligation, ...]
    currency: str
    trade_date_cash: Decimal
    settled_cash: Decimal
    available_cash: Decimal
    receivables: Decimal
    payables: Decimal
    as_of: datetime | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "CanonicalSettlementLedgerState can only be created by the settlement reducer"
        )

    def _validate(self) -> None:
        _require_text(self.account_id, "settlement account_id")
        _require_currency(self.currency)
        _validate_trade_date_ledger(self.trade_date_ledger)
        if type(self.settlement_entries) is not tuple or any(
            type(entry) is not CanonicalLedgerEntry for entry in self.settlement_entries
        ):
            raise SettlementLedgerError(
                "settlement entries must be immutable exact CanonicalLedgerEntry values"
            )
        if type(self.obligations) is not tuple or any(
            type(obligation) is not SettlementObligation for obligation in self.obligations
        ):
            raise SettlementLedgerError(
                "settlement obligations must be immutable exact SettlementObligation values"
            )
        canonical_obligations = tuple(sorted(self.obligations, key=_obligation_key))
        if self.obligations != canonical_obligations:
            raise SettlementLedgerError("settlement obligations must use canonical order")
        event_ids = tuple(obligation.execution_event_id for obligation in self.obligations)
        if len(event_ids) != len(set(event_ids)):
            raise SettlementLedgerError("settlement obligations cannot repeat an execution event")
        expected_entries = _entries_for_obligations(
            trade_date_ledger=self.trade_date_ledger,
            obligations=self.obligations,
            currency=self.currency,
        )
        if self.settlement_entries != expected_entries:
            raise SettlementLedgerError(
                "settlement entries do not match their canonical obligations"
            )
        derived = _derive_settlement_aggregate(
            trade_date_ledger=self.trade_date_ledger,
            settlement_entries=self.settlement_entries,
            currency=self.currency,
        )
        if self.balances != derived.balances:
            raise SettlementLedgerError(
                "settlement balances do not match the canonical ledger entries"
            )
        for actual, expected, field_name in (
            (self.trade_date_cash, derived.trade_date_cash, "trade-date cash"),
            (self.settled_cash, derived.settled_cash, "settled cash"),
            (self.available_cash, derived.available_cash, "available cash"),
            (self.receivables, derived.receivables, "receivables"),
            (self.payables, derived.payables, "payables"),
        ):
            if _persisted(actual, f"settlement {field_name}") != expected:
                raise SettlementLedgerError(
                    f"settlement {field_name} does not match canonical balances"
                )
        if self.as_of != derived.as_of:
            raise SettlementLedgerError(
                "settlement as_of does not match the canonical ledger entries"
            )

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

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                SETTLEMENT_LEDGER_CONTRACT_VERSION,
                "state",
                self.account_id,
                self.trade_date_ledger.semantic_sha256,
                tuple(entry.semantic_sha256 for entry in self.settlement_entries),
                tuple(balance.semantic_sha256 for balance in self.balances),
                tuple(obligation.semantic_sha256 for obligation in self.obligations),
                self.currency,
                self.trade_date_cash,
                self.settled_cash,
                self.available_cash,
                self.receivables,
                self.payables,
                self.as_of,
            )
        )


@dataclass(frozen=True, slots=True)
class _ExecutionCashDelta:
    order_id: str
    execution_id: str
    event: BrokerOrderEvent
    cash_delta: Decimal


def _event_cash(event: BrokerOrderEvent, side: Side) -> Decimal:
    assert event.quantity is not None
    assert event.price is not None
    assert event.fee is not None
    notional = exact_decimal_multiply(event.quantity, event.price)
    if side is Side.BUY:
        return exact_decimal_add(notional, event.fee).copy_negate()
    return exact_decimal_subtract(notional, event.fee)


def _execution_cash_deltas(
    states: tuple[CanonicalOrderState, ...],
) -> tuple[_ExecutionCashDelta, ...]:
    unique_states: dict[str, CanonicalOrderState] = {}
    for state in states:
        order_id = state.submission.order_id
        existing = unique_states.get(order_id)
        if existing is not None and existing != state:
            raise SettlementFactConflict("order identity has conflicting settlement states")
        unique_states[order_id] = state
    deltas: list[_ExecutionCashDelta] = []
    source_event_ids: dict[str, BrokerOrderEvent] = {}
    execution_owners: dict[str, str] = {}
    for order_id in sorted(unique_states):
        state = unique_states[order_id]
        predecessors: dict[str, BrokerOrderEvent] = {}
        for event in state.broker_events:
            if event.kind not in (
                BrokerOrderEventKind.EXECUTION,
                BrokerOrderEventKind.EXECUTION_CORRECTION,
            ):
                continue
            assert event.execution_id is not None
            existing_event = source_event_ids.get(event.event_id)
            if existing_event is not None and existing_event != event:
                raise SettlementFactConflict("execution event identity has conflicting semantics")
            source_event_ids[event.event_id] = event
            owner = execution_owners.get(event.execution_id)
            if owner is not None and owner != order_id:
                raise SettlementFactConflict("execution identity is reused across orders")
            execution_owners[event.execution_id] = order_id
            current_cash = _event_cash(event, state.submission.intent.side)
            previous_cash = Decimal(0)
            if event.kind is BrokerOrderEventKind.EXECUTION_CORRECTION:
                previous = predecessors[event.execution_id]
                previous_cash = _event_cash(previous, state.submission.intent.side)
            cash_delta = exact_decimal_subtract(current_cash, previous_cash)
            if cash_delta != 0:
                deltas.append(
                    _ExecutionCashDelta(
                        order_id=order_id,
                        execution_id=event.execution_id,
                        event=event,
                        cash_delta=cash_delta,
                    )
                )
            predecessors[event.execution_id] = event
    return tuple(
        sorted(
            deltas,
            key=lambda delta: (
                delta.event.received_at,
                delta.event.occurred_at,
                delta.order_id,
                delta.event.broker_sequence,
            ),
        )
    )


def _posting(
    *,
    account: str,
    currency: str,
    amount_delta: Decimal,
) -> CanonicalLedgerPosting:
    amount_delta = _persisted(amount_delta, f"{account} settlement delta")
    if amount_delta == 0:
        raise SettlementLedgerError("settlement posting cannot be empty")
    return CanonicalLedgerPosting(
        account=account,
        currency=currency,
        debit=amount_delta if amount_delta > 0 else Decimal(0),
        credit=amount_delta.copy_negate() if amount_delta < 0 else Decimal(0),
    )


def _entry(
    *,
    kind: LedgerEntryKind,
    reference_id: str,
    source_sha256: str,
    effective_at: datetime,
    recorded_at: datetime,
    postings: tuple[CanonicalLedgerPosting, CanonicalLedgerPosting],
) -> CanonicalLedgerEntry:
    ordered = tuple(sorted(postings, key=lambda posting: posting.account))
    return CanonicalLedgerEntry(
        entry_id=canonical_id("settlement-ledger-entry", kind, reference_id, source_sha256),
        kind=kind,
        reference_id=reference_id,
        source_sha256=source_sha256,
        effective_at=effective_at,
        recorded_at=recorded_at,
        postings=ordered,
    )


def _settlement_account(cash_delta: Decimal) -> str:
    return "assets:trade_receivables" if cash_delta > 0 else "liabilities:trade_payables"


def _canonical_instructions(
    instructions: tuple[ExecutionSettlementInstruction, ...],
) -> tuple[
    dict[str, ExecutionSettlementInstruction],
    dict[str, ExecutionSettlementInstruction],
]:
    by_id: dict[str, ExecutionSettlementInstruction] = {}
    by_event: dict[str, ExecutionSettlementInstruction] = {}
    by_external_reference: dict[str, ExecutionSettlementInstruction] = {}
    for instruction in instructions:
        if type(instruction) is not ExecutionSettlementInstruction:
            raise SettlementLedgerError("settlement requires exact instruction values")
        existing_id = by_id.get(instruction.instruction_id)
        if existing_id is not None and existing_id != instruction:
            raise SettlementFactConflict("settlement instruction identity conflicts")
        existing_event = by_event.get(instruction.execution_event_id)
        if existing_event is not None and existing_event != instruction:
            raise SettlementFactConflict("execution event has conflicting instructions")
        existing_reference = by_external_reference.get(instruction.external_reference)
        if existing_reference is not None and existing_reference != instruction:
            raise SettlementFactConflict("instruction external reference conflicts")
        by_id[instruction.instruction_id] = instruction
        by_event[instruction.execution_event_id] = instruction
        by_external_reference[instruction.external_reference] = instruction
    return by_id, by_event


def _canonical_confirmations(
    confirmations: tuple[ExecutionSettlementConfirmation, ...],
) -> dict[str, ExecutionSettlementConfirmation]:
    by_instruction: dict[str, ExecutionSettlementConfirmation] = {}
    by_id: dict[str, ExecutionSettlementConfirmation] = {}
    by_external_reference: dict[str, ExecutionSettlementConfirmation] = {}
    for confirmation in confirmations:
        if type(confirmation) is not ExecutionSettlementConfirmation:
            raise SettlementLedgerError("settlement requires exact confirmation values")
        existing_id = by_id.get(confirmation.confirmation_id)
        if existing_id is not None and existing_id != confirmation:
            raise SettlementFactConflict("settlement confirmation identity conflicts")
        existing_instruction = by_instruction.get(confirmation.instruction_id)
        if existing_instruction is not None and existing_instruction != confirmation:
            raise SettlementFactConflict("instruction has conflicting confirmations")
        existing_reference = by_external_reference.get(confirmation.external_reference)
        if existing_reference is not None and existing_reference != confirmation:
            raise SettlementFactConflict("confirmation external reference conflicts")
        by_id[confirmation.confirmation_id] = confirmation
        by_instruction[confirmation.instruction_id] = confirmation
        by_external_reference[confirmation.external_reference] = confirmation
    return by_instruction


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


def _entry_key(entry: CanonicalLedgerEntry) -> tuple[datetime, datetime, str]:
    return (entry.recorded_at, entry.effective_at, entry.entry_id)


def _obligation_key(
    obligation: SettlementObligation,
) -> tuple[datetime, str, str]:
    return (
        obligation.instruction.recorded_at,
        obligation.order_id,
        obligation.execution_event_id,
    )


def _validate_trade_date_ledger(ledger: CanonicalLedgerState) -> None:
    if type(ledger) is not CanonicalLedgerState:
        raise SettlementLedgerError(
            "settlement requires an exact CanonicalLedgerState trade-date ledger"
        )
    if type(ledger.entries) is not tuple or any(
        type(entry) is not CanonicalLedgerEntry for entry in ledger.entries
    ):
        raise SettlementLedgerError(
            "trade-date entries must be immutable exact CanonicalLedgerEntry values"
        )
    if ledger.entries != tuple(sorted(ledger.entries, key=_entry_key)):
        raise SettlementLedgerError("trade-date entries must use canonical order")
    entry_ids = tuple(entry.entry_id for entry in ledger.entries)
    if len(entry_ids) != len(set(entry_ids)):
        raise SettlementLedgerError("trade-date ledger cannot repeat an entry identity")
    for entry in ledger.entries:
        if entry.kind not in (
            LedgerEntryKind.CASH_FLOW,
            LedgerEntryKind.EXECUTION,
            LedgerEntryKind.EXECUTION_CORRECTION,
        ):
            raise SettlementLedgerError("trade-date ledger contains a non-trade-date entry")
        if entry.entry_id != canonical_id(
            "ledger-entry",
            entry.kind,
            entry.reference_id,
            entry.source_sha256,
        ):
            raise SettlementLedgerError("trade-date ledger entry identity is not canonical")
    expected_balances = _project_balances(ledger.entries)
    if ledger.balances != expected_balances:
        raise SettlementLedgerError("trade-date balances do not match the canonical entries")
    expected_as_of = (
        None if not ledger.entries else max(entry.recorded_at for entry in ledger.entries)
    )
    if ledger.as_of != expected_as_of:
        raise SettlementLedgerError("trade-date as_of does not match the canonical entries")


def _execution_cash_entries(
    trade_date_ledger: CanonicalLedgerState,
    currency: str,
) -> dict[str, tuple[CanonicalLedgerEntry, Decimal]]:
    entries: dict[str, tuple[CanonicalLedgerEntry, Decimal]] = {}
    for entry in trade_date_ledger.entries:
        if entry.kind not in (
            LedgerEntryKind.EXECUTION,
            LedgerEntryKind.EXECUTION_CORRECTION,
        ):
            continue
        cash_delta = Decimal(0)
        for posting in entry.postings:
            if (
                posting.account == f"assets:cash:{currency}"
                and posting.currency == currency
                and posting.instrument_id is None
            ):
                cash_delta = exact_decimal_subtract(posting.debit, posting.credit)
                break
        if cash_delta == 0:
            continue
        if entry.reference_id in entries:
            raise SettlementLedgerError("trade-date ledger repeats an execution event identity")
        entries[entry.reference_id] = (entry, cash_delta)
    return entries


def _entries_for_obligations(
    *,
    trade_date_ledger: CanonicalLedgerState,
    obligations: tuple[SettlementObligation, ...],
    currency: str,
) -> tuple[CanonicalLedgerEntry, ...]:
    executions = _execution_cash_entries(trade_date_ledger, currency)
    obligations_by_event = {obligation.execution_event_id: obligation for obligation in obligations}
    if set(obligations_by_event) != set(executions):
        raise SettlementLedgerError(
            "settlement obligations do not cover the trade-date execution cash deltas"
        )
    instruction_ids: set[str] = set()
    confirmation_ids: set[str] = set()
    entries: list[CanonicalLedgerEntry] = []
    for event_id, (trade_entry, cash_delta) in executions.items():
        obligation = obligations_by_event[event_id]
        instruction = obligation.instruction
        if type(instruction) is not ExecutionSettlementInstruction:
            raise SettlementLedgerError("settlement obligation requires an exact instruction")
        if instruction.instruction_id in instruction_ids:
            raise SettlementLedgerError(
                "settlement obligations cannot reuse an instruction identity"
            )
        instruction_ids.add(instruction.instruction_id)
        if instruction.execution_event_id != event_id:
            raise SettlementLedgerError(
                "settlement instruction belongs to a different execution event"
            )
        if instruction.execution_event_sha256 != trade_entry.source_sha256:
            raise SettlementLedgerError("settlement instruction does not bind its trade-date entry")
        if instruction.contractual_settlement_at < trade_entry.effective_at:
            raise SettlementLedgerError("contractual settlement cannot precede execution")
        if instruction.recorded_at < trade_entry.recorded_at:
            raise SettlementLedgerError("settlement instruction predates execution receipt")
        expected_direction = (
            SettlementDirection.RECEIVABLE if cash_delta > 0 else SettlementDirection.PAYABLE
        )
        if obligation.direction is not expected_direction:
            raise SettlementLedgerError(
                "settlement obligation direction disagrees with trade-date cash"
            )
        if obligation.amount != cash_delta.copy_abs():
            raise SettlementLedgerError(
                "settlement obligation amount disagrees with trade-date cash"
            )
        settlement_account = _settlement_account(cash_delta)
        entries.append(
            _entry(
                kind=LedgerEntryKind.SETTLEMENT_RECLASSIFICATION,
                reference_id=instruction.instruction_id,
                source_sha256=instruction.semantic_sha256,
                effective_at=trade_entry.effective_at,
                recorded_at=instruction.recorded_at,
                postings=(
                    _posting(
                        account=f"assets:cash:{currency}",
                        currency=currency,
                        amount_delta=cash_delta.copy_negate(),
                    ),
                    _posting(
                        account=settlement_account,
                        currency=currency,
                        amount_delta=cash_delta,
                    ),
                ),
            )
        )
        confirmation = obligation.confirmation
        if confirmation is None:
            if obligation.status is not SettlementStatus.UNSETTLED:
                raise SettlementLedgerError(
                    "settlement obligation status disagrees with confirmation evidence"
                )
            continue
        if type(confirmation) is not ExecutionSettlementConfirmation:
            raise SettlementLedgerError("settlement obligation has an unsupported confirmation")
        if confirmation.confirmation_id in confirmation_ids:
            raise SettlementLedgerError(
                "settlement obligations cannot reuse a confirmation identity"
            )
        confirmation_ids.add(confirmation.confirmation_id)
        if confirmation.instruction_id != instruction.instruction_id:
            raise SettlementLedgerError(
                "settlement confirmation belongs to a different instruction"
            )
        if confirmation.instruction_sha256 != instruction.semantic_sha256:
            raise SettlementLedgerError(
                "settlement confirmation does not bind its exact instruction"
            )
        if confirmation.settled_at < instruction.recorded_at:
            raise SettlementLedgerError("actual settlement predates its instruction")
        if obligation.status is not SettlementStatus.SETTLED:
            raise SettlementLedgerError(
                "settlement obligation status disagrees with confirmation evidence"
            )
        entries.append(
            _entry(
                kind=LedgerEntryKind.EXECUTION_SETTLEMENT,
                reference_id=confirmation.confirmation_id,
                source_sha256=confirmation.semantic_sha256,
                effective_at=confirmation.settled_at,
                recorded_at=confirmation.recorded_at,
                postings=(
                    _posting(
                        account=f"assets:cash:{currency}",
                        currency=currency,
                        amount_delta=cash_delta,
                    ),
                    _posting(
                        account=settlement_account,
                        currency=currency,
                        amount_delta=cash_delta.copy_negate(),
                    ),
                ),
            )
        )
    return tuple(sorted(entries, key=_entry_key))


@dataclass(frozen=True, slots=True)
class _DerivedSettlementAggregate:
    balances: tuple[LedgerBalance, ...]
    trade_date_cash: Decimal
    settled_cash: Decimal
    available_cash: Decimal
    receivables: Decimal
    payables: Decimal
    as_of: datetime | None


def _derive_settlement_aggregate(
    *,
    trade_date_ledger: CanonicalLedgerState,
    settlement_entries: tuple[CanonicalLedgerEntry, ...],
    currency: str,
) -> _DerivedSettlementAggregate:
    all_entries = tuple(
        sorted(
            (*trade_date_ledger.entries, *settlement_entries),
            key=_entry_key,
        )
    )
    entry_ids = tuple(entry.entry_id for entry in all_entries)
    if len(entry_ids) != len(set(entry_ids)):
        raise SettlementLedgerError("settlement aggregate cannot repeat a ledger entry identity")
    balances = _project_balances(all_entries)

    def balance_amount(account: str) -> Decimal:
        for balance in balances:
            if (
                balance.account == account
                and balance.currency == currency
                and balance.instrument_id is None
            ):
                return balance.amount
        return Decimal(0)

    settled_cash = balance_amount(f"assets:cash:{currency}")
    receivables = balance_amount("assets:trade_receivables")
    payable_balance = balance_amount("liabilities:trade_payables")
    if receivables < 0 or payable_balance > 0:
        raise SettlementLedgerError("settlement balances have invalid account orientation")
    return _DerivedSettlementAggregate(
        balances=balances,
        trade_date_cash=trade_date_ledger.cash_balance(currency),
        settled_cash=settled_cash,
        available_cash=exact_decimal_add(settled_cash, payable_balance),
        receivables=receivables,
        payables=payable_balance.copy_negate(),
        as_of=(None if not all_entries else max(entry.recorded_at for entry in all_entries)),
    )


def _create_settlement_ledger_state(
    *,
    account_id: str,
    trade_date_ledger: CanonicalLedgerState,
    settlement_entries: tuple[CanonicalLedgerEntry, ...],
    obligations: tuple[SettlementObligation, ...],
    currency: str,
) -> CanonicalSettlementLedgerState:
    """Seal one aggregate after rederiving every aggregate projection."""

    derived = _derive_settlement_aggregate(
        trade_date_ledger=trade_date_ledger,
        settlement_entries=settlement_entries,
        currency=currency,
    )
    state = object.__new__(CanonicalSettlementLedgerState)
    object.__setattr__(state, "account_id", account_id)
    object.__setattr__(state, "trade_date_ledger", trade_date_ledger)
    object.__setattr__(state, "settlement_entries", settlement_entries)
    object.__setattr__(state, "balances", derived.balances)
    object.__setattr__(state, "obligations", obligations)
    object.__setattr__(state, "currency", currency)
    object.__setattr__(state, "trade_date_cash", derived.trade_date_cash)
    object.__setattr__(state, "settled_cash", derived.settled_cash)
    object.__setattr__(state, "available_cash", derived.available_cash)
    object.__setattr__(state, "receivables", derived.receivables)
    object.__setattr__(state, "payables", derived.payables)
    object.__setattr__(state, "as_of", derived.as_of)
    state._validate()
    return state


def reduce_settlement_ledger(
    *,
    account_id: str,
    order_states: Iterable[CanonicalOrderState] = (),
    cash_flows: Iterable[LedgerCashFlow] = (),
    instructions: Iterable[ExecutionSettlementInstruction] = (),
    confirmations: Iterable[ExecutionSettlementConfirmation] = (),
    currency: str = "USD",
) -> CanonicalSettlementLedgerState:
    """Reclassify trade-date cash and apply explicit execution settlements."""

    _require_text(account_id, "settlement account_id")
    _require_currency(currency)
    states = tuple(order_states)
    flows = tuple(cash_flows)
    instruction_values = tuple(instructions)
    confirmation_values = tuple(confirmations)
    try:
        trade_date_ledger = reduce_execution_ledger(
            order_states=states,
            cash_flows=flows,
            execution_currency=currency,
        )
    except LedgerFactConflict as error:
        raise SettlementFactConflict(str(error)) from error
    except ValueError as error:
        raise SettlementLedgerError(str(error)) from error
    deltas = _execution_cash_deltas(states)
    instructions_by_id, instructions_by_event = _canonical_instructions(instruction_values)
    confirmations_by_instruction = _canonical_confirmations(confirmation_values)

    expected_event_ids = {delta.event.event_id for delta in deltas}
    if set(instructions_by_event) != expected_event_ids:
        missing = expected_event_ids - set(instructions_by_event)
        detail = "missing" if missing else "unexpected"
        raise SettlementLedgerError(f"settlement instructions have {detail} execution events")
    if set(confirmations_by_instruction) - set(instructions_by_id):
        raise SettlementLedgerError("settlement confirmation has no known instruction")

    settlement_entries: list[CanonicalLedgerEntry] = []
    obligations: list[SettlementObligation] = []
    for delta in deltas:
        instruction = instructions_by_event[delta.event.event_id]
        if instruction.execution_event_sha256 != delta.event.semantic_sha256:
            raise SettlementLedgerError("settlement instruction does not bind its execution event")
        if instruction.contractual_settlement_at < delta.event.occurred_at:
            raise SettlementLedgerError("contractual settlement cannot precede execution")
        if instruction.recorded_at < delta.event.received_at:
            raise SettlementLedgerError("settlement instruction predates execution receipt")
        settlement_account = _settlement_account(delta.cash_delta)
        settlement_entries.append(
            _entry(
                kind=LedgerEntryKind.SETTLEMENT_RECLASSIFICATION,
                reference_id=instruction.instruction_id,
                source_sha256=instruction.semantic_sha256,
                effective_at=delta.event.occurred_at,
                recorded_at=instruction.recorded_at,
                postings=(
                    _posting(
                        account=f"assets:cash:{currency}",
                        currency=currency,
                        amount_delta=delta.cash_delta.copy_negate(),
                    ),
                    _posting(
                        account=settlement_account,
                        currency=currency,
                        amount_delta=delta.cash_delta,
                    ),
                ),
            )
        )
        confirmation = confirmations_by_instruction.get(instruction.instruction_id)
        if confirmation is not None:
            if confirmation.instruction_sha256 != instruction.semantic_sha256:
                raise SettlementLedgerError("confirmation does not bind its exact instruction")
            if confirmation.settled_at < instruction.recorded_at:
                raise SettlementLedgerError("actual settlement predates its instruction")
            settlement_entries.append(
                _entry(
                    kind=LedgerEntryKind.EXECUTION_SETTLEMENT,
                    reference_id=confirmation.confirmation_id,
                    source_sha256=confirmation.semantic_sha256,
                    effective_at=confirmation.settled_at,
                    recorded_at=confirmation.recorded_at,
                    postings=(
                        _posting(
                            account=f"assets:cash:{currency}",
                            currency=currency,
                            amount_delta=delta.cash_delta,
                        ),
                        _posting(
                            account=settlement_account,
                            currency=currency,
                            amount_delta=delta.cash_delta.copy_negate(),
                        ),
                    ),
                )
            )
        obligations.append(
            SettlementObligation(
                instruction=instruction,
                confirmation=confirmation,
                order_id=delta.order_id,
                execution_id=delta.execution_id,
                execution_event_id=delta.event.event_id,
                direction=(
                    SettlementDirection.RECEIVABLE
                    if delta.cash_delta > 0
                    else SettlementDirection.PAYABLE
                ),
                amount=delta.cash_delta.copy_abs(),
                status=(
                    SettlementStatus.SETTLED
                    if confirmation is not None
                    else SettlementStatus.UNSETTLED
                ),
            )
        )

    canonical_settlement_entries = tuple(
        sorted(
            settlement_entries,
            key=_entry_key,
        )
    )
    canonical_obligations = tuple(sorted(obligations, key=_obligation_key))
    return _create_settlement_ledger_state(
        account_id=account_id,
        trade_date_ledger=trade_date_ledger,
        settlement_entries=canonical_settlement_entries,
        obligations=canonical_obligations,
        currency=currency,
    )
