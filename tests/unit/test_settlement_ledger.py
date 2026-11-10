from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext
from itertools import permutations

import pytest

from packages.domain.ledger_reducer import CashFlowKind, LedgerEntryKind, create_cash_flow
from packages.domain.models import Side
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    create_order_submission,
    reduce_order_lifecycle,
)
from packages.domain.settlement_ledger import (
    CanonicalSettlementLedgerState,
    SettlementDirection,
    SettlementFactConflict,
    SettlementLedgerError,
    SettlementStatus,
    create_settlement_confirmation,
    create_settlement_instruction,
    reduce_settlement_ledger,
)
from packages.domain.walking_thread import WalkingThread

BASE_TIME = datetime(2026, 7, 15, 13, 31, 5, tzinfo=UTC)
ACCOUNT_ID = "account-settlement-test"


def funding():
    return create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=Decimal("10000"),
        effective_at=BASE_TIME - timedelta(seconds=2),
        recorded_at=BASE_TIME - timedelta(seconds=1),
        external_reference="settlement-funding",
    )


def order_state(
    *,
    side: Side = Side.BUY,
    suffix: str = "buy",
    quantity: str = "4",
    price: str = "100",
    fee: str = "1",
):
    intent = replace(
        WalkingThread.run().intent,
        intent_id=f"intent-{suffix}",
        intent_batch_id=f"batch-{suffix}",
        side=side,
        quantity=Decimal(quantity),
    )
    submitted = create_order_submission(
        intent=intent,
        risk_decision_id=f"risk-{suffix}",
        submission_attempt_id=f"attempt-{suffix}",
        submitted_at=BASE_TIME,
    )
    accepted_at = BASE_TIME + timedelta(milliseconds=100)
    accepted = BrokerOrderEvent(
        event_id=f"accepted-{suffix}",
        order_id=submitted.order_id,
        broker_order_id=f"broker-{suffix}",
        broker_sequence=1,
        occurred_at=accepted_at,
        received_at=accepted_at + timedelta(milliseconds=10),
        kind=BrokerOrderEventKind.ACCEPTED,
    )
    executed_at = BASE_TIME + timedelta(milliseconds=200)
    execution = BrokerOrderEvent(
        event_id=f"execution-event-{suffix}",
        order_id=submitted.order_id,
        broker_order_id=f"broker-{suffix}",
        broker_sequence=2,
        occurred_at=executed_at,
        received_at=executed_at + timedelta(milliseconds=10),
        kind=BrokerOrderEventKind.EXECUTION,
        execution_id=f"execution-{suffix}",
        execution_revision=1,
        quantity=Decimal(quantity),
        price=Decimal(price),
        fee=Decimal(fee),
    )
    return reduce_order_lifecycle(
        submission=submitted,
        broker_events=(accepted, execution),
    )


def corrected(state, *, quantity: str, price: str, fee: str):
    initial = state.broker_events[-1]
    correction_time = initial.occurred_at + timedelta(milliseconds=100)
    correction = BrokerOrderEvent(
        event_id=f"correction-{initial.execution_id}",
        order_id=state.submission.order_id,
        broker_order_id=initial.broker_order_id,
        broker_sequence=3,
        occurred_at=correction_time,
        received_at=correction_time + timedelta(milliseconds=10),
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        execution_id=initial.execution_id,
        execution_revision=2,
        supersedes_event_id=initial.event_id,
        quantity=Decimal(quantity),
        price=Decimal(price),
        fee=Decimal(fee),
    )
    return reduce_order_lifecycle(
        submission=state.submission,
        broker_events=(*state.broker_events, correction),
    )


def instruction(event, *, suffix: str):
    return create_settlement_instruction(
        event,
        contractual_settlement_at=BASE_TIME + timedelta(days=1),
        recorded_at=event.received_at + timedelta(milliseconds=10),
        external_reference=f"instruction-{suffix}",
    )


def confirmation(settlement_instruction, *, suffix: str):
    return create_settlement_confirmation(
        settlement_instruction,
        settled_at=BASE_TIME + timedelta(days=1),
        recorded_at=BASE_TIME + timedelta(days=1, seconds=1),
        external_reference=f"confirmation-{suffix}",
    )


def test_unsettled_buy_reclassifies_trade_date_cash_to_payable() -> None:
    order = order_state()
    settlement_instruction = instruction(order.broker_events[-1], suffix="buy")
    state = reduce_settlement_ledger(
        account_id=ACCOUNT_ID,
        order_states=(order,),
        cash_flows=(funding(),),
        instructions=(settlement_instruction,),
    )

    assert state.trade_date_cash == Decimal("9599")
    assert state.settled_cash == Decimal("10000")
    assert state.available_cash == Decimal("9599")
    assert state.payables == Decimal("401")
    assert state.receivables == 0
    assert state.obligations[0].direction is SettlementDirection.PAYABLE
    assert state.obligations[0].status is SettlementStatus.UNSETTLED
    assert state.obligations[0].amount == Decimal("401")
    assert state.settlement_entries[0].kind is LedgerEntryKind.SETTLEMENT_RECLASSIFICATION


def test_buy_confirmation_clears_payable_and_moves_settled_cash() -> None:
    order = order_state()
    settlement_instruction = instruction(order.broker_events[-1], suffix="buy")
    settlement_confirmation = confirmation(settlement_instruction, suffix="buy")
    state = reduce_settlement_ledger(
        account_id=ACCOUNT_ID,
        order_states=(order,),
        cash_flows=(funding(),),
        instructions=(settlement_instruction,),
        confirmations=(settlement_confirmation,),
    )

    assert state.trade_date_cash == Decimal("9599")
    assert state.settled_cash == Decimal("9599")
    assert state.available_cash == Decimal("9599")
    assert state.payables == 0
    assert state.receivables == 0
    assert state.obligations[0].status is SettlementStatus.SETTLED
    assert len(state.settlement_entries) == 2


def test_unsettled_sale_proceeds_are_receivable_and_not_available_cash() -> None:
    order = order_state(side=Side.SELL, suffix="sell", price="110")
    settlement_instruction = instruction(order.broker_events[-1], suffix="sell")
    unsettled = reduce_settlement_ledger(
        account_id=ACCOUNT_ID,
        order_states=(order,),
        cash_flows=(funding(),),
        instructions=(settlement_instruction,),
    )

    assert unsettled.trade_date_cash == Decimal("10439")
    assert unsettled.settled_cash == Decimal("10000")
    assert unsettled.available_cash == Decimal("10000")
    assert unsettled.receivables == Decimal("439")
    assert unsettled.payables == 0
    assert unsettled.obligations[0].direction is SettlementDirection.RECEIVABLE

    settled = reduce_settlement_ledger(
        account_id=ACCOUNT_ID,
        order_states=(order,),
        cash_flows=(funding(),),
        instructions=(settlement_instruction,),
        confirmations=(confirmation(settlement_instruction, suffix="sell"),),
    )
    assert settled.settled_cash == Decimal("10439")
    assert settled.available_cash == Decimal("10439")
    assert settled.receivables == 0


def test_correction_has_its_own_delta_obligation_and_settlement() -> None:
    initial_state = order_state(quantity="4", price="100", fee="2")
    order = corrected(initial_state, quantity="3", price="110", fee="1")
    initial_instruction = instruction(order.broker_events[-2], suffix="initial")
    correction_instruction = instruction(order.broker_events[-1], suffix="correction")

    unsettled = reduce_settlement_ledger(
        account_id=ACCOUNT_ID,
        order_states=(order,),
        cash_flows=(funding(),),
        instructions=(correction_instruction, initial_instruction),
    )
    assert unsettled.trade_date_cash == Decimal("9669")
    assert unsettled.settled_cash == Decimal("10000")
    assert unsettled.payables == Decimal("402")
    assert unsettled.receivables == Decimal("71")
    assert unsettled.available_cash == Decimal("9598")
    assert tuple(obligation.amount for obligation in unsettled.obligations) == (
        Decimal("402"),
        Decimal("71"),
    )

    settled = reduce_settlement_ledger(
        account_id=ACCOUNT_ID,
        order_states=(order,),
        cash_flows=(funding(),),
        instructions=(initial_instruction, correction_instruction),
        confirmations=(
            confirmation(correction_instruction, suffix="correction"),
            confirmation(initial_instruction, suffix="initial"),
        ),
    )
    assert settled.trade_date_cash == settled.settled_cash == Decimal("9669")
    assert settled.available_cash == Decimal("9669")
    assert settled.payables == settled.receivables == 0


def test_exact_duplicates_and_caller_permutations_are_invariant() -> None:
    initial_state = order_state(quantity="4", price="100", fee="2")
    order = corrected(initial_state, quantity="3", price="110", fee="1")
    instructions = (
        instruction(order.broker_events[-2], suffix="initial"),
        instruction(order.broker_events[-1], suffix="correction"),
    )
    confirmations = tuple(
        confirmation(value, suffix=str(index)) for index, value in enumerate(instructions)
    )
    expected = None

    for instruction_order in permutations(instructions):
        for confirmation_order in permutations(confirmations):
            state = reduce_settlement_ledger(
                account_id=ACCOUNT_ID,
                order_states=(order, order),
                cash_flows=(funding(), funding()),
                instructions=(*instruction_order, instruction_order[0]),
                confirmations=(*confirmation_order, confirmation_order[0]),
            )
            if expected is None:
                expected = state
            else:
                assert state == expected
                assert state.semantic_sha256 == expected.semantic_sha256


def test_missing_unexpected_or_forged_settlement_evidence_fails_closed() -> None:
    order = order_state()
    settlement_instruction = instruction(order.broker_events[-1], suffix="buy")
    with pytest.raises(SettlementLedgerError, match="missing execution events"):
        reduce_settlement_ledger(
            account_id=ACCOUNT_ID,
            order_states=(order,),
            cash_flows=(funding(),),
        )

    forged_instruction = replace(
        settlement_instruction,
        execution_event_sha256="0" * 64,
    )
    with pytest.raises(SettlementLedgerError, match="does not bind"):
        reduce_settlement_ledger(
            account_id=ACCOUNT_ID,
            order_states=(order,),
            cash_flows=(funding(),),
            instructions=(forged_instruction,),
        )

    unknown_confirmation = confirmation(settlement_instruction, suffix="buy")
    with pytest.raises(SettlementLedgerError, match="no known instruction"):
        reduce_settlement_ledger(
            account_id=ACCOUNT_ID,
            confirmations=(unknown_confirmation,),
        )


def test_instruction_and_confirmation_identity_conflicts_fail_closed() -> None:
    order = order_state()
    settlement_instruction = instruction(order.broker_events[-1], suffix="buy")
    conflicting_instruction = replace(
        settlement_instruction,
        contractual_settlement_at=settlement_instruction.contractual_settlement_at
        + timedelta(days=1),
    )
    with pytest.raises(SettlementFactConflict, match="instruction identity"):
        reduce_settlement_ledger(
            account_id=ACCOUNT_ID,
            order_states=(order,),
            instructions=(settlement_instruction, conflicting_instruction),
        )

    settlement_confirmation = confirmation(settlement_instruction, suffix="buy")
    conflicting_confirmation = replace(
        settlement_confirmation,
        settled_at=settlement_confirmation.settled_at + timedelta(seconds=1),
    )
    with pytest.raises(SettlementFactConflict, match="confirmation identity"):
        reduce_settlement_ledger(
            account_id=ACCOUNT_ID,
            order_states=(order,),
            instructions=(settlement_instruction,),
            confirmations=(settlement_confirmation, conflicting_confirmation),
        )


def test_zero_cash_delta_requires_no_settlement_instruction() -> None:
    order = order_state(
        side=Side.SELL,
        suffix="zero-cash",
        quantity="1",
        price="1",
        fee="1",
    )
    state = reduce_settlement_ledger(
        account_id=ACCOUNT_ID,
        order_states=(order,),
        cash_flows=(funding(),),
    )

    assert state.trade_date_cash == state.settled_cash == Decimal("10000")
    assert state.obligations == ()
    assert state.settlement_entries == ()


def test_settlement_arithmetic_is_independent_of_ambient_decimal_context() -> None:
    order = order_state(quantity="3", price="100.123456789", fee="1.123456789")
    settlement_instruction = instruction(order.broker_events[-1], suffix="precise")
    settlement_confirmation = confirmation(settlement_instruction, suffix="precise")

    with localcontext() as context:
        context.prec = 4
        low_precision = reduce_settlement_ledger(
            account_id=ACCOUNT_ID,
            order_states=(order,),
            cash_flows=(funding(),),
            instructions=(settlement_instruction,),
            confirmations=(settlement_confirmation,),
        )
    with localcontext() as context:
        context.prec = 40
        high_precision = reduce_settlement_ledger(
            account_id=ACCOUNT_ID,
            order_states=(order,),
            cash_flows=(funding(),),
            instructions=(settlement_instruction,),
            confirmations=(settlement_confirmation,),
        )

    assert low_precision == high_precision
    assert low_precision.semantic_sha256 == high_precision.semantic_sha256


def test_settlement_state_is_bound_to_its_required_account_identity() -> None:
    first = reduce_settlement_ledger(
        account_id=ACCOUNT_ID,
        cash_flows=(funding(),),
    )
    second = reduce_settlement_ledger(
        account_id="account-settlement-other",
        cash_flows=(funding(),),
    )

    assert first.account_id == ACCOUNT_ID
    assert first.trade_date_ledger == second.trade_date_ledger
    assert first.balances == second.balances
    assert first.semantic_sha256 != second.semantic_sha256
    with pytest.raises(SettlementLedgerError, match="account_id"):
        reduce_settlement_ledger(account_id=" account-settlement-test ")


def test_settlement_state_can_only_be_proof_constructed_by_reducer() -> None:
    state = reduce_settlement_ledger(
        account_id=ACCOUNT_ID,
        cash_flows=(funding(),),
    )

    with pytest.raises(TypeError, match="only be created by the settlement reducer"):
        CanonicalSettlementLedgerState()
    with pytest.raises(TypeError, match="only be created by the settlement reducer"):
        replace(state, available_cash=Decimal("999999"))
