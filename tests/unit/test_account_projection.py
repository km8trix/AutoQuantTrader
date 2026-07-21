from __future__ import annotations

from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext
from itertools import permutations

import pytest

from packages.domain.account_projection import (
    AccountFactConflict,
    AccountProjectionError,
    CanonicalAccountProjection,
    CostBasisPolicy,
    create_position_mark,
    project_fifo_account,
)
from packages.domain.ledger_reducer import CashFlowKind, create_cash_flow
from packages.domain.models import Side
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    create_order_submission,
    reduce_order_lifecycle,
)
from packages.domain.walking_thread import WalkingThread

BASE_TIME = datetime(2026, 7, 15, 13, 31, 5, tzinfo=UTC)
VALUATION_AT = BASE_TIME + timedelta(minutes=1)
ACCOUNT_ID = "account-primary"


def funding():
    return create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=Decimal("10000"),
        effective_at=BASE_TIME - timedelta(seconds=2),
        recorded_at=BASE_TIME - timedelta(seconds=1),
        external_reference="account-funding",
    )


def order_state(
    *,
    side: Side,
    suffix: str,
    quantity: str,
    price: str,
    fee: str,
    offset: int,
):
    intent = replace(
        WalkingThread.run().intent,
        intent_id=f"intent-{suffix}",
        intent_batch_id=f"batch-{suffix}",
        side=side,
        quantity=Decimal(quantity),
    )
    submitted_at = BASE_TIME + timedelta(seconds=offset)
    submitted = create_order_submission(
        intent=intent,
        risk_decision_id=f"risk-{suffix}",
        submission_attempt_id=f"attempt-{suffix}",
        submitted_at=submitted_at,
    )
    accepted_at = submitted_at + timedelta(milliseconds=100)
    accepted = BrokerOrderEvent(
        event_id=f"accepted-{suffix}",
        order_id=submitted.order_id,
        broker_order_id=f"broker-{suffix}",
        broker_sequence=1,
        occurred_at=accepted_at,
        received_at=accepted_at + timedelta(milliseconds=10),
        kind=BrokerOrderEventKind.ACCEPTED,
    )
    executed_at = submitted_at + timedelta(milliseconds=200)
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


def mark(price: str = "125", *, source: str = "mark-spy"):
    return create_position_mark(
        source_event_id=source,
        instrument_id=WalkingThread.instrument_id,
        symbol=WalkingThread.symbol,
        price=Decimal(price),
        effective_at=VALUATION_AT - timedelta(seconds=2),
        recorded_at=VALUATION_AT - timedelta(seconds=1),
    )


def fifo_history():
    return (
        order_state(
            side=Side.BUY,
            suffix="buy-a",
            quantity="4",
            price="100",
            fee="1",
            offset=0,
        ),
        order_state(
            side=Side.BUY,
            suffix="buy-b",
            quantity="6",
            price="110",
            fee="2",
            offset=1,
        ),
        order_state(
            side=Side.SELL,
            suffix="sell-a",
            quantity="5",
            price="120",
            fee="1",
            offset=2,
        ),
    )


def forged_projection(
    projection: CanonicalAccountProjection,
    **overrides: object,
) -> CanonicalAccountProjection:
    forged = object.__new__(CanonicalAccountProjection)
    for projection_field in fields(CanonicalAccountProjection):
        object.__setattr__(
            forged,
            projection_field.name,
            overrides.get(projection_field.name, getattr(projection, projection_field.name)),
        )
    return forged


def test_fifo_lots_realized_unrealized_fees_cash_and_equity() -> None:
    account = project_fifo_account(
        account_id=ACCOUNT_ID,
        order_states=fifo_history(),
        cash_flows=(funding(),),
        marks=(mark(),),
        valuation_at=VALUATION_AT,
    )

    assert account.policy is CostBasisPolicy.FIFO_TRADE_DATE
    assert account.cash == Decimal("9536")
    assert account.market_value == Decimal("625")
    assert account.equity == Decimal("10161")
    assert account.realized_pnl_before_fees == Decimal("90")
    assert account.execution_fees == Decimal("4")
    assert account.realized_pnl == Decimal("86")
    assert account.unrealized_pnl == Decimal("75")
    position = account.positions[0]
    assert position.quantity == Decimal("5")
    assert position.cost_basis == Decimal("550")
    assert position.average_cost == Decimal("110")
    assert len(position.open_lots) == 1
    assert position.open_lots[0].execution_id == "execution-buy-b"
    assert position.open_lots[0].quantity == Decimal("5")


def test_correction_rebuilds_fifo_book_from_current_execution_heads() -> None:
    buy_a, buy_b, sell = fifo_history()
    corrected_buy = corrected(buy_a, quantity="2", price="100", fee="0.5")
    account = project_fifo_account(
        account_id=ACCOUNT_ID,
        order_states=(corrected_buy, buy_b, sell),
        cash_flows=(funding(),),
        marks=(mark(),),
        valuation_at=VALUATION_AT,
    )

    position = account.positions[0]
    assert position.quantity == Decimal("3")
    assert position.cost_basis == Decimal("330")
    assert account.realized_pnl_before_fees == Decimal("70")
    assert account.execution_fees == Decimal("3.5")
    assert account.realized_pnl == Decimal("66.5")
    assert account.unrealized_pnl == Decimal("45")
    assert account.cash == Decimal("9736.5")
    assert account.equity == Decimal("10111.5")


def test_corrected_history_that_would_create_short_position_fails_closed() -> None:
    buy_a, _, sell = fifo_history()
    busted_buy = corrected(buy_a, quantity="0", price="100", fee="0")
    small_buy = order_state(
        side=Side.BUY,
        suffix="small-buy",
        quantity="2",
        price="110",
        fee="0",
        offset=1,
    )

    with pytest.raises(AccountProjectionError, match="short position"):
        project_fifo_account(
            account_id=ACCOUNT_ID,
            order_states=(busted_buy, small_buy, sell),
            cash_flows=(funding(),),
            marks=(mark(),),
            valuation_at=VALUATION_AT,
        )


def test_open_position_requires_causal_mark_and_matching_symbol() -> None:
    buy = fifo_history()[0]
    with pytest.raises(AccountProjectionError, match="lacks a causal mark"):
        project_fifo_account(
            account_id=ACCOUNT_ID,
            order_states=(buy,),
            cash_flows=(funding(),),
            valuation_at=VALUATION_AT,
        )

    future_mark = replace(mark(), recorded_at=VALUATION_AT + timedelta(seconds=1))
    with pytest.raises(AccountProjectionError, match="after valuation_at"):
        project_fifo_account(
            account_id=ACCOUNT_ID,
            order_states=(buy,),
            cash_flows=(funding(),),
            marks=(future_mark,),
            valuation_at=VALUATION_AT,
        )

    wrong_symbol = replace(mark(), symbol="QQQ")
    with pytest.raises(AccountFactConflict, match="symbol conflicts"):
        project_fifo_account(
            account_id=ACCOUNT_ID,
            order_states=(buy,),
            cash_flows=(funding(),),
            marks=(wrong_symbol,),
            valuation_at=VALUATION_AT,
        )


def test_closed_position_needs_no_mark_and_retains_realized_trace() -> None:
    buy = order_state(
        side=Side.BUY,
        suffix="roundtrip-buy",
        quantity="4",
        price="100",
        fee="1",
        offset=0,
    )
    sell = order_state(
        side=Side.SELL,
        suffix="roundtrip-sell",
        quantity="4",
        price="110",
        fee="1",
        offset=1,
    )
    account = project_fifo_account(
        account_id=ACCOUNT_ID,
        order_states=(buy, sell),
        cash_flows=(funding(),),
        valuation_at=VALUATION_AT,
    )

    assert account.positions[0].quantity == 0
    assert account.positions[0].mark is None
    assert account.realized_pnl_before_fees == Decimal("40")
    assert account.execution_fees == Decimal("2")
    assert account.realized_pnl == Decimal("38")
    assert account.unrealized_pnl == 0
    assert account.cash == Decimal("10038")
    assert account.equity == Decimal("10038")


def test_fact_permutations_and_exact_duplicates_are_semantically_invariant() -> None:
    history = fifo_history()
    observed_mark = mark()
    older_mark = create_position_mark(
        source_event_id="older-mark",
        instrument_id=WalkingThread.instrument_id,
        symbol=WalkingThread.symbol,
        price=Decimal("115"),
        effective_at=VALUATION_AT - timedelta(seconds=4),
        recorded_at=VALUATION_AT - timedelta(seconds=3),
    )
    expected = None

    for order_values in permutations(history):
        account = project_fifo_account(
            account_id=ACCOUNT_ID,
            order_states=(*order_values, order_values[0]),
            cash_flows=(funding(), funding()),
            marks=(observed_mark, older_mark, observed_mark),
            valuation_at=VALUATION_AT,
        )
        assert account.positions[0].mark == observed_mark
        if expected is None:
            expected = account
        else:
            assert account == expected
            assert account.semantic_sha256 == expected.semantic_sha256


def test_conflicting_mark_identity_or_source_fails_closed() -> None:
    observed_mark = mark()
    conflicting = replace(observed_mark, price=Decimal("126"))
    with pytest.raises(AccountFactConflict, match="mark identity"):
        project_fifo_account(
            account_id=ACCOUNT_ID,
            marks=(observed_mark, conflicting),
            valuation_at=VALUATION_AT,
        )

    forged_id = replace(observed_mark, mark_id="different-mark-id")
    with pytest.raises(AccountFactConflict, match="source identity"):
        project_fifo_account(
            account_id=ACCOUNT_ID,
            marks=(observed_mark, forged_id),
            valuation_at=VALUATION_AT,
        )
    with pytest.raises(AccountProjectionError, match="canonical identity"):
        project_fifo_account(
            account_id=ACCOUNT_ID,
            marks=(forged_id,),
            valuation_at=VALUATION_AT,
        )


def test_broker_execution_identity_cannot_be_reused_across_orders() -> None:
    first = fifo_history()[0]
    second = order_state(
        side=Side.BUY,
        suffix="duplicate-execution-id",
        quantity="2",
        price="100",
        fee="0",
        offset=1,
    )
    duplicate_execution = replace(
        second.broker_events[-1],
        execution_id=first.executions[0].execution_id,
    )
    second_with_duplicate = reduce_order_lifecycle(
        submission=second.submission,
        broker_events=(second.broker_events[0], duplicate_execution),
    )

    with pytest.raises(AccountFactConflict, match="reused across orders"):
        project_fifo_account(
            account_id=ACCOUNT_ID,
            order_states=(first, second_with_duplicate),
            cash_flows=(funding(),),
            marks=(mark(),),
            valuation_at=VALUATION_AT,
        )


def test_valuation_cannot_precede_accounting_state() -> None:
    buy = fifo_history()[0]
    with pytest.raises(AccountProjectionError, match="precede the accounting state"):
        project_fifo_account(
            account_id=ACCOUNT_ID,
            order_states=(buy,),
            cash_flows=(funding(),),
            marks=(mark(),),
            valuation_at=BASE_TIME,
        )


def test_account_arithmetic_is_independent_of_ambient_decimal_context() -> None:
    buy = order_state(
        side=Side.BUY,
        suffix="precise-buy",
        quantity="3",
        price="100.123456789",
        fee="1.123456789",
        offset=0,
    )
    precise_mark = mark("101.987654321")

    with localcontext() as context:
        context.prec = 4
        low_precision = project_fifo_account(
            account_id=ACCOUNT_ID,
            order_states=(buy,),
            cash_flows=(funding(),),
            marks=(precise_mark,),
            valuation_at=VALUATION_AT,
        )
    with localcontext() as context:
        context.prec = 40
        high_precision = project_fifo_account(
            account_id=ACCOUNT_ID,
            order_states=(buy,),
            cash_flows=(funding(),),
            marks=(precise_mark,),
            valuation_at=VALUATION_AT,
        )

    assert low_precision == high_precision
    assert low_precision.semantic_sha256 == high_precision.semantic_sha256


def test_account_projection_is_reducer_produced_and_account_bound() -> None:
    first = project_fifo_account(
        account_id=ACCOUNT_ID,
        order_states=fifo_history(),
        cash_flows=(funding(),),
        marks=(mark(),),
        valuation_at=VALUATION_AT,
    )
    second = project_fifo_account(
        account_id="account-secondary",
        order_states=fifo_history(),
        cash_flows=(funding(),),
        marks=(mark(),),
        valuation_at=VALUATION_AT,
    )

    assert first.account_id == ACCOUNT_ID
    assert first != second
    assert first.semantic_sha256 != second.semantic_sha256
    with pytest.raises(TypeError, match="only be created by the account reducer"):
        CanonicalAccountProjection()
    with pytest.raises(TypeError, match="only be created by the account reducer"):
        replace(first, account_id="forged-account")


@pytest.mark.parametrize(
    "field_name",
    (
        "cash",
        "market_value",
        "equity",
        "gross_exposure",
        "net_exposure",
        "realized_pnl_before_fees",
        "execution_fees",
        "dividend_income",
        "dividend_receivable",
        "realized_pnl",
        "unrealized_pnl",
    ),
)
def test_account_projection_rederives_every_retained_aggregate(field_name: str) -> None:
    account = project_fifo_account(
        account_id=ACCOUNT_ID,
        order_states=fifo_history(),
        cash_flows=(funding(),),
        marks=(mark(),),
        valuation_at=VALUATION_AT,
    )
    retained = getattr(account, field_name)
    assert type(retained) is Decimal
    forged = forged_projection(
        account,
        **{field_name: retained + Decimal("1")},
    )

    with pytest.raises(AccountProjectionError, match=field_name):
        forged._validate()


def test_account_projection_revalidates_ledger_marks_positions_and_as_of() -> None:
    account = project_fifo_account(
        account_id=ACCOUNT_ID,
        order_states=fifo_history(),
        cash_flows=(funding(),),
        marks=(mark(),),
        valuation_at=VALUATION_AT,
    )
    unrelated = project_fifo_account(
        account_id=ACCOUNT_ID,
        valuation_at=VALUATION_AT,
    )

    with pytest.raises(AccountProjectionError, match="does not bind its execution ledger"):
        forged_projection(account, ledger=unrelated.ledger)._validate()
    with pytest.raises(AccountProjectionError, match="marks are not canonical"):
        forged_projection(
            account,
            observed_marks=(*account.observed_marks, account.observed_marks[0]),
        )._validate()
    with pytest.raises(AccountProjectionError, match="repeats an instrument"):
        forged_projection(
            account,
            positions=(*account.positions, account.positions[0]),
        )._validate()
    with pytest.raises(AccountProjectionError, match="execution-ledger instruments"):
        forged_projection(account, positions=())._validate()
    with pytest.raises(AccountProjectionError, match="as_of precedes"):
        forged_projection(account, as_of=BASE_TIME)._validate()
