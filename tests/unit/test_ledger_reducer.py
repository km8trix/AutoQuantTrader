from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext
from itertools import permutations

import pytest

from packages.domain.ledger_reducer import (
    CanonicalLedgerEntry,
    CanonicalLedgerPosting,
    CashFlowKind,
    LedgerEntryKind,
    LedgerFactConflict,
    LedgerReductionError,
    create_cash_flow,
    reduce_execution_ledger,
)
from packages.domain.models import Side
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    CanonicalOrderStatus,
    create_order_submission,
    reduce_order_lifecycle,
)
from packages.domain.walking_thread import WalkingThread

BASE_TIME = datetime(2026, 7, 15, 13, 31, 5, tzinfo=UTC)


def cash_flow(amount: str = "100000"):
    return create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=Decimal(amount),
        effective_at=BASE_TIME - timedelta(seconds=2),
        recorded_at=BASE_TIME - timedelta(seconds=1),
        external_reference="simulation-funding",
    )


def submission(side: Side = Side.BUY, suffix: str = "buy"):
    base_intent = WalkingThread.run().intent
    intent = replace(
        base_intent,
        intent_id=f"intent-{suffix}",
        intent_batch_id=f"intent-batch-{suffix}",
        side=side,
    )
    return create_order_submission(
        intent=intent,
        risk_decision_id=f"risk-decision-{suffix}",
        submission_attempt_id=f"submission-attempt-{suffix}",
        submitted_at=BASE_TIME,
    )


def broker_event(
    submitted,
    sequence: int,
    kind: BrokerOrderEventKind,
    *,
    event_id: str | None = None,
    execution_id: str | None = None,
    revision: int | None = None,
    supersedes: str | None = None,
    quantity: str | None = None,
    price: str | None = None,
    fee: str | None = None,
) -> BrokerOrderEvent:
    occurred_at = BASE_TIME + timedelta(seconds=sequence)
    return BrokerOrderEvent(
        event_id=event_id or f"{submitted.order_id}-event-{sequence}",
        order_id=submitted.order_id,
        broker_order_id=f"broker-{submitted.order_id}",
        broker_sequence=sequence,
        occurred_at=occurred_at,
        received_at=occurred_at + timedelta(milliseconds=100),
        kind=kind,
        execution_id=execution_id,
        execution_revision=revision,
        supersedes_event_id=supersedes,
        quantity=None if quantity is None else Decimal(quantity),
        price=None if price is None else Decimal(price),
        fee=None if fee is None else Decimal(fee),
    )


def execution_state(
    *,
    side: Side = Side.BUY,
    suffix: str = "buy",
    quantity: str = "4",
    price: str = "101",
    fee: str = "1",
):
    submitted = submission(side, suffix)
    accepted = broker_event(submitted, 1, BrokerOrderEventKind.ACCEPTED)
    execution = broker_event(
        submitted,
        2,
        BrokerOrderEventKind.EXECUTION,
        execution_id=f"execution-{suffix}",
        revision=1,
        quantity=quantity,
        price=price,
        fee=fee,
    )
    return reduce_order_lifecycle(
        submission=submitted,
        broker_events=(accepted, execution),
    )


def corrected_state(
    *,
    corrected_quantity: str,
    corrected_price: str,
    corrected_fee: str,
):
    initial_state = execution_state(quantity="4", price="100", fee="2")
    submitted = initial_state.submission
    initial = initial_state.broker_events[1]
    correction = broker_event(
        submitted,
        3,
        BrokerOrderEventKind.EXECUTION_CORRECTION,
        execution_id=initial.execution_id,
        revision=2,
        supersedes=initial.event_id,
        quantity=corrected_quantity,
        price=corrected_price,
        fee=corrected_fee,
    )
    return reduce_order_lifecycle(
        submission=submitted,
        broker_events=(*initial_state.broker_events, correction),
    )


def test_contribution_and_buy_execution_produce_balanced_append_only_entries() -> None:
    order = execution_state()
    ledger = reduce_execution_ledger(order_states=(order,), cash_flows=(cash_flow(),))

    assert len(ledger.entries) == 2
    assert ledger.cash_balance() == Decimal("99595")
    assert ledger.position_quantity(WalkingThread.instrument_id) == Decimal("4")
    assert ledger.balance("expenses:execution_fees", currency="USD").amount == Decimal("1")
    clearing = ledger.balance(
        f"clearing:executions:{WalkingThread.instrument_id}",
        currency="USD",
        instrument_id=WalkingThread.instrument_id,
    )
    assert clearing.amount == Decimal("404")
    assert clearing.units == Decimal("4")
    for entry in ledger.entries:
        assert sum((posting.debit for posting in entry.postings), Decimal(0)) == sum(
            (posting.credit for posting in entry.postings), Decimal(0)
        )


def test_execution_correction_posts_only_the_economic_delta() -> None:
    order = corrected_state(
        corrected_quantity="3",
        corrected_price="110",
        corrected_fee="1",
    )
    ledger = reduce_execution_ledger(order_states=(order,), cash_flows=(cash_flow(),))

    assert ledger.cash_balance() == Decimal("99669")
    assert ledger.position_quantity(WalkingThread.instrument_id) == Decimal("3")
    assert ledger.balance("expenses:execution_fees").amount == Decimal("1")
    correction = ledger.entries[-1]
    assert correction.kind is LedgerEntryKind.EXECUTION_CORRECTION
    by_account = {posting.account: posting for posting in correction.postings}
    assert by_account["assets:cash:USD"].debit == Decimal("71")
    assert by_account[f"clearing:executions:{WalkingThread.instrument_id}"].credit == Decimal("70")
    assert by_account[f"clearing:executions:{WalkingThread.instrument_id}"].units_delta == -1
    assert by_account["expenses:execution_fees"].credit == Decimal("1")


def test_economically_identical_correction_advances_revision_without_ledger_entry() -> None:
    initial_state = execution_state(quantity="4", price="100", fee="2")
    submitted = initial_state.submission
    initial = initial_state.broker_events[1]
    identical = broker_event(
        submitted,
        3,
        BrokerOrderEventKind.EXECUTION_CORRECTION,
        execution_id=initial.execution_id,
        revision=2,
        supersedes=initial.event_id,
        quantity="4",
        price="100",
        fee="2",
    )
    later = broker_event(
        submitted,
        4,
        BrokerOrderEventKind.EXECUTION_CORRECTION,
        execution_id=initial.execution_id,
        revision=3,
        supersedes=identical.event_id,
        quantity="5",
        price="100",
        fee="2",
    )
    order = reduce_order_lifecycle(
        submission=submitted,
        broker_events=(*initial_state.broker_events, identical, later),
    )

    ledger = reduce_execution_ledger(order_states=(order,))

    assert [entry.reference_id for entry in ledger.entries] == [initial.event_id, later.event_id]
    assert ledger.position_quantity(WalkingThread.instrument_id) == Decimal("5")


def test_execution_bust_reverses_cash_units_trade_value_and_fee() -> None:
    order = corrected_state(
        corrected_quantity="0",
        corrected_price="100",
        corrected_fee="0",
    )
    ledger = reduce_execution_ledger(order_states=(order,), cash_flows=(cash_flow(),))

    assert ledger.cash_balance() == Decimal("100000")
    assert ledger.position_quantity(WalkingThread.instrument_id) == 0
    assert ledger.balance("expenses:execution_fees").amount == 0
    assert len(ledger.entries) == 3


def test_sell_execution_conserves_cash_units_fees_and_trade_value() -> None:
    buy = execution_state(quantity="10", price="100", fee="0")
    sell = execution_state(
        side=Side.SELL,
        suffix="sell",
        quantity="4",
        price="110",
        fee="1",
    )
    ledger = reduce_execution_ledger(
        order_states=(sell, buy),
        cash_flows=(cash_flow(),),
    )

    assert ledger.cash_balance() == Decimal("99439")
    assert ledger.position_quantity(WalkingThread.instrument_id) == Decimal("6")
    assert ledger.balance("expenses:execution_fees").amount == Decimal("1")
    clearing = ledger.balance(
        f"clearing:executions:{WalkingThread.instrument_id}",
        instrument_id=WalkingThread.instrument_id,
    )
    assert clearing.amount == Decimal("560")
    assert clearing.units == Decimal("6")


def test_input_permutations_and_exact_duplicate_facts_are_invariant() -> None:
    buy = execution_state(quantity="2", suffix="buy-a")
    second_buy = execution_state(quantity="3", suffix="buy-b")
    funding = cash_flow()
    expected = None

    for order_values in permutations((buy, second_buy)):
        ledger = reduce_execution_ledger(
            order_states=(*order_values, order_values[0]),
            cash_flows=(funding, funding),
        )
        if expected is None:
            expected = ledger
        else:
            assert ledger == expected
            assert ledger.semantic_sha256 == expected.semantic_sha256


def test_conflicting_order_snapshots_and_cash_flow_identities_fail_closed() -> None:
    partial = execution_state(quantity="2")
    submitted_only = reduce_order_lifecycle(
        submission=partial.submission,
        broker_events=(),
    )
    with pytest.raises(LedgerFactConflict, match="order identity"):
        reduce_execution_ledger(order_states=(partial, submitted_only))

    funding = cash_flow()
    conflicting = replace(funding, amount=Decimal("99999"))
    with pytest.raises(LedgerFactConflict, match="cash flow identity"):
        reduce_execution_ledger(cash_flows=(funding, conflicting))

    recorded_later = create_cash_flow(
        kind=funding.kind,
        currency=funding.currency,
        amount=funding.amount,
        effective_at=funding.effective_at,
        recorded_at=funding.recorded_at + timedelta(seconds=1),
        external_reference=funding.external_reference,
    )
    assert recorded_later.cash_flow_id == funding.cash_flow_id
    with pytest.raises(LedgerFactConflict, match="cash flow identity"):
        reduce_execution_ledger(cash_flows=(funding, recorded_later))

    forged_identity = replace(funding, cash_flow_id="different-id")
    with pytest.raises(LedgerFactConflict, match="external reference"):
        reduce_execution_ledger(cash_flows=(funding, forged_identity))


def test_forged_order_projection_is_rejected_before_posting() -> None:
    order = execution_state()
    forged = replace(order, status=CanonicalOrderStatus.CANCELED)

    with pytest.raises(LedgerReductionError, match="reducer-produced"):
        reduce_execution_ledger(order_states=(forged,), cash_flows=(cash_flow(),))


def test_posting_and_entry_validation_reject_unbalanced_or_empty_facts() -> None:
    posting = CanonicalLedgerPosting(
        account="assets:cash:USD",
        currency="USD",
        debit=Decimal("1"),
    )
    with pytest.raises(LedgerReductionError, match="not balanced"):
        CanonicalLedgerEntry(
            entry_id="entry-1",
            kind=LedgerEntryKind.CASH_FLOW,
            reference_id="reference-1",
            source_sha256="0" * 64,
            effective_at=BASE_TIME,
            recorded_at=BASE_TIME,
            postings=(posting,),
        )
    with pytest.raises(LedgerReductionError, match="money or security units"):
        CanonicalLedgerPosting(account="empty", currency="USD")


def test_reduction_is_independent_of_ambient_decimal_context() -> None:
    order = corrected_state(
        corrected_quantity="3",
        corrected_price="100.123456789",
        corrected_fee="1.123456789",
    )
    funding = cash_flow()

    with localcontext() as context:
        context.prec = 4
        low_precision = reduce_execution_ledger(
            order_states=(order,),
            cash_flows=(funding,),
        )
    with localcontext() as context:
        context.prec = 40
        high_precision = reduce_execution_ledger(
            order_states=(order,),
            cash_flows=(funding,),
        )

    assert low_precision == high_precision
    assert low_precision.semantic_sha256 == high_precision.semantic_sha256
