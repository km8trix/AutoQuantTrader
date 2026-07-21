from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext
from itertools import permutations

import pytest

from packages.domain.account_projection import (
    AccountProjectionError,
    create_position_mark,
    project_fifo_account,
)
from packages.domain.corporate_action_ledger import (
    CorporateActionFactConflict,
    CorporateActionLedgerError,
    create_cash_dividend,
    create_dividend_payment,
    create_stock_split,
    reduce_corporate_action_ledger,
)
from packages.domain.ledger_reducer import (
    CashFlowKind,
    LedgerEntryKind,
    create_cash_flow,
    reduce_execution_ledger,
)
from packages.domain.models import Side
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    create_order_submission,
    reduce_order_lifecycle,
)
from packages.domain.walking_thread import WalkingThread

BASE_TIME = datetime(2026, 7, 15, 13, 31, 5, tzinfo=UTC)
ACTION_AT = BASE_TIME + timedelta(seconds=10)
VALUATION_AT = BASE_TIME + timedelta(minutes=1)
ACCOUNT_ID = "account-primary"


def source_sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def funding():
    return create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=Decimal("10000"),
        effective_at=BASE_TIME - timedelta(seconds=2),
        recorded_at=BASE_TIME - timedelta(seconds=1),
        external_reference="corporate-action-funding",
    )


def order_state(
    *,
    side: Side = Side.BUY,
    suffix: str = "buy",
    quantity: str = "4",
    price: str = "100",
    fee: str = "1",
    offset: int = 0,
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


def account_mark(
    price: str,
    *,
    effective_at: datetime = VALUATION_AT - timedelta(seconds=2),
    source: str = "corporate-action-mark",
):
    return create_position_mark(
        source_event_id=source,
        instrument_id=WalkingThread.instrument_id,
        symbol=WalkingThread.symbol,
        price=Decimal(price),
        effective_at=effective_at,
        recorded_at=effective_at + timedelta(milliseconds=100),
    )


def stock_split(
    *,
    numerator: str = "2",
    denominator: str = "1",
    entitled_quantity: str = "4",
    action_id: str = "split-action-a",
    revision_id: str = "split-revision-a",
    effective_at: datetime = ACTION_AT,
):
    return create_stock_split(
        source_action_id=action_id,
        source_revision_id=revision_id,
        source_sha256=source_sha256(revision_id),
        instrument_id=WalkingThread.instrument_id,
        symbol=WalkingThread.symbol,
        numerator=Decimal(numerator),
        denominator=Decimal(denominator),
        entitled_quantity=Decimal(entitled_quantity),
        effective_at=effective_at,
        recorded_at=effective_at + timedelta(milliseconds=100),
    )


def cash_dividend(
    *,
    amount_per_share: str = "1.25",
    entitled_quantity: str = "4",
    action_id: str = "dividend-action-a",
    revision_id: str = "dividend-revision-a",
    effective_at: datetime = ACTION_AT,
):
    return create_cash_dividend(
        source_action_id=action_id,
        source_revision_id=revision_id,
        source_sha256=source_sha256(revision_id),
        instrument_id=WalkingThread.instrument_id,
        symbol=WalkingThread.symbol,
        currency="USD",
        amount_per_share=Decimal(amount_per_share),
        entitled_quantity=Decimal(entitled_quantity),
        effective_at=effective_at,
        payable_at=effective_at + timedelta(seconds=10),
        recorded_at=effective_at + timedelta(milliseconds=100),
    )


def dividend_payment(dividend, *, suffix: str = "a"):
    paid_at = dividend.payable_at + timedelta(seconds=1)
    return create_dividend_payment(
        dividend,
        paid_at=paid_at,
        recorded_at=paid_at + timedelta(milliseconds=100),
        external_reference=f"dividend-payment-{suffix}",
    )


def execution_ledger(*orders):
    return reduce_execution_ledger(
        order_states=orders,
        cash_flows=(funding(),),
    )


def test_forward_split_preserves_fifo_basis_and_updates_account_units() -> None:
    split = stock_split()
    account = project_fifo_account(
        account_id=ACCOUNT_ID,
        order_states=(order_state(),),
        cash_flows=(funding(),),
        marks=(account_mark("60"),),
        stock_splits=(split,),
        valuation_at=VALUATION_AT,
    )

    position = account.positions[0]
    assert position.quantity == Decimal("8")
    assert position.cost_basis == Decimal("400")
    assert position.average_cost == Decimal("50")
    assert position.open_lots[0].quantity == Decimal("8")
    assert position.open_lots[0].cost_basis == Decimal("400")
    assert position.open_lots[0].unit_cost == Decimal("50")
    assert account.cash == Decimal("9599")
    assert account.market_value == Decimal("480")
    assert account.equity == Decimal("10079")
    assert account.realized_pnl == Decimal("-1")
    assert account.unrealized_pnl == Decimal("80")

    state = account.corporate_action_ledger
    assert state.position_quantity(WalkingThread.instrument_id) == Decimal("8")
    assert len(state.corporate_action_entries) == 1
    entry = state.corporate_action_entries[0]
    assert entry.kind is LedgerEntryKind.STOCK_SPLIT
    assert entry.postings[0].units_delta == Decimal("4")
    assert entry.postings[0].debit == entry.postings[0].credit == 0


def test_reverse_split_preserves_fifo_basis() -> None:
    split = stock_split(
        numerator="1",
        denominator="2",
        action_id="reverse-split-action",
        revision_id="reverse-split-revision",
    )
    account = project_fifo_account(
        account_id=ACCOUNT_ID,
        order_states=(order_state(),),
        cash_flows=(funding(),),
        marks=(account_mark("210"),),
        stock_splits=(split,),
        valuation_at=VALUATION_AT,
    )

    position = account.positions[0]
    assert position.quantity == Decimal("2")
    assert position.cost_basis == Decimal("400")
    assert position.average_cost == Decimal("200")
    assert position.open_lots[0].quantity == Decimal("2")
    assert position.open_lots[0].cost_basis == Decimal("400")
    assert account.market_value == Decimal("420")
    assert account.equity == Decimal("10019")
    assert account.unrealized_pnl == Decimal("20")
    assert account.corporate_action_ledger.corporate_action_entries[0].postings[
        0
    ].units_delta == Decimal("-2")


def test_three_for_two_split_preserves_total_basis_without_rounding_unit_cost() -> None:
    split = stock_split(
        numerator="3",
        denominator="2",
        action_id="three-for-two-action",
        revision_id="three-for-two-revision",
    )
    account = project_fifo_account(
        account_id=ACCOUNT_ID,
        order_states=(order_state(),),
        cash_flows=(funding(),),
        marks=(account_mark("70"),),
        stock_splits=(split,),
        valuation_at=VALUATION_AT,
    )

    position = account.positions[0]
    assert position.quantity == Decimal("6")
    assert position.cost_basis == Decimal("400")
    assert position.open_lots[0].quantity == Decimal("6")
    assert position.open_lots[0].cost_basis == Decimal("400")
    assert position.open_lots[0].unit_cost == position.average_cost
    assert account.market_value == Decimal("420")
    assert account.equity == Decimal("10019")
    assert account.unrealized_pnl == Decimal("20")


def test_sale_after_split_consumes_adjusted_fifo_units_and_basis() -> None:
    buy = order_state(fee="0")
    sell = order_state(
        side=Side.SELL,
        suffix="sell-after-split",
        quantity="3",
        price="60",
        fee="0",
        offset=20,
    )
    account = project_fifo_account(
        account_id=ACCOUNT_ID,
        order_states=(sell, buy),
        cash_flows=(funding(),),
        marks=(account_mark("60"),),
        stock_splits=(stock_split(),),
        valuation_at=VALUATION_AT,
    )

    position = account.positions[0]
    assert position.quantity == Decimal("5")
    assert position.cost_basis == Decimal("250")
    assert position.average_cost == Decimal("50")
    assert account.cash == Decimal("9780")
    assert account.market_value == Decimal("300")
    assert account.equity == Decimal("10080")
    assert account.realized_pnl_before_fees == Decimal("30")
    assert account.realized_pnl == Decimal("30")
    assert account.unrealized_pnl == Decimal("50")


def test_partial_sale_after_nonterminating_split_basis_fails_closed() -> None:
    split = stock_split(
        numerator="3",
        denominator="2",
        action_id="nonterminating-basis-action",
        revision_id="nonterminating-basis-revision",
    )
    sell = order_state(
        side=Side.SELL,
        suffix="nonterminating-basis-sale",
        quantity="1",
        price="70",
        fee="0",
        offset=20,
    )

    with pytest.raises(AccountProjectionError, match="partial FIFO basis allocation"):
        project_fifo_account(
            account_id=ACCOUNT_ID,
            order_states=(order_state(fee="0"), sell),
            cash_flows=(funding(),),
            marks=(account_mark("70"),),
            stock_splits=(split,),
            valuation_at=VALUATION_AT,
        )


def test_cash_dividend_accrues_income_and_receivable_without_moving_cash() -> None:
    dividend = cash_dividend()
    account = project_fifo_account(
        account_id=ACCOUNT_ID,
        order_states=(order_state(),),
        cash_flows=(funding(),),
        marks=(account_mark("100"),),
        cash_dividends=(dividend,),
        valuation_at=VALUATION_AT,
    )

    assert account.cash == Decimal("9599")
    assert account.market_value == Decimal("400")
    assert account.dividend_income == Decimal("5")
    assert account.dividend_receivable == Decimal("5")
    assert account.realized_pnl_before_fees == 0
    assert account.execution_fees == Decimal("1")
    assert account.realized_pnl == Decimal("4")
    assert account.equity == Decimal("10004")

    state = account.corporate_action_ledger
    assert state.dividend_income == Decimal("5")
    assert state.dividend_receivable == Decimal("5")
    assert state.cash_balance() == Decimal("9599")
    assert len(state.corporate_action_entries) == 1
    entry = state.corporate_action_entries[0]
    assert entry.kind is LedgerEntryKind.CASH_DIVIDEND_ACCRUAL
    assert tuple(posting.account for posting in entry.postings) == (
        "assets:dividend_receivable",
        "income:cash_dividends",
    )
    assert entry.postings[0].debit == Decimal("5")
    assert entry.postings[1].credit == Decimal("5")


def test_dividend_payment_clears_receivable_without_recognizing_income_twice() -> None:
    dividend = cash_dividend()
    payment = dividend_payment(dividend)
    account = project_fifo_account(
        account_id=ACCOUNT_ID,
        order_states=(order_state(),),
        cash_flows=(funding(),),
        marks=(account_mark("100"),),
        cash_dividends=(dividend,),
        dividend_payments=(payment,),
        valuation_at=VALUATION_AT,
    )

    assert account.cash == Decimal("9604")
    assert account.dividend_income == Decimal("5")
    assert account.dividend_receivable == 0
    assert account.realized_pnl == Decimal("4")
    assert account.equity == Decimal("10004")
    assert tuple(
        entry.kind for entry in account.corporate_action_ledger.corporate_action_entries
    ) == (
        LedgerEntryKind.CASH_DIVIDEND_ACCRUAL,
        LedgerEntryKind.CASH_DIVIDEND_PAYMENT,
    )
    payment_entry = account.corporate_action_ledger.corporate_action_entries[1]
    assert tuple(posting.account for posting in payment_entry.postings) == (
        "assets:cash:USD",
        "assets:dividend_receivable",
    )
    assert payment_entry.postings[0].debit == Decimal("5")
    assert payment_entry.postings[1].credit == Decimal("5")


def test_dividend_payment_cannot_be_recorded_before_its_accrual() -> None:
    dividend = replace(
        cash_dividend(),
        recorded_at=ACTION_AT + timedelta(seconds=30),
    )
    paid_at = dividend.payable_at + timedelta(seconds=1)

    with pytest.raises(CorporateActionLedgerError, match="before its accrual"):
        create_dividend_payment(
            dividend,
            paid_at=paid_at,
            recorded_at=ACTION_AT + timedelta(seconds=20),
            external_reference="premature-payment-record",
        )


def test_reducer_rejects_split_and_dividend_entitlements_that_disagree_with_units() -> None:
    base_ledger = execution_ledger(order_state())

    with pytest.raises(CorporateActionLedgerError, match="stock split entitlement"):
        reduce_corporate_action_ledger(
            base_ledger=base_ledger,
            stock_splits=(stock_split(entitled_quantity="3"),),
        )

    with pytest.raises(CorporateActionLedgerError, match="cash dividend entitlement"):
        reduce_corporate_action_ledger(
            base_ledger=base_ledger,
            cash_dividends=(cash_dividend(entitled_quantity="3"),),
        )


def test_fractional_aggregate_or_fifo_lot_split_fails_closed() -> None:
    with pytest.raises(CorporateActionLedgerError, match="fractional shares"):
        stock_split(
            numerator="1",
            denominator="2",
            entitled_quantity="3",
            action_id="fractional-total-action",
            revision_id="fractional-total-revision",
        )

    first = order_state(
        suffix="one-share-a",
        quantity="1",
        price="100",
        fee="0",
    )
    second = order_state(
        suffix="one-share-b",
        quantity="1",
        price="110",
        fee="0",
        offset=1,
    )
    aggregate_whole = stock_split(
        numerator="1",
        denominator="2",
        entitled_quantity="2",
        action_id="fractional-lots-action",
        revision_id="fractional-lots-revision",
    )
    with pytest.raises(AccountProjectionError, match="fractional FIFO lot"):
        project_fifo_account(
            account_id=ACCOUNT_ID,
            order_states=(first, second),
            cash_flows=(funding(),),
            marks=(account_mark("210"),),
            stock_splits=(aggregate_whole,),
            valuation_at=VALUATION_AT,
        )


def test_same_time_position_changes_and_corporate_entitlements_are_ambiguous() -> None:
    order = order_state()
    execution_at = order.broker_events[-1].occurred_at
    colliding_split = stock_split(
        action_id="execution-collision-action",
        revision_id="execution-collision-revision",
        effective_at=execution_at,
    )
    with pytest.raises(CorporateActionLedgerError, match="position-change time"):
        reduce_corporate_action_ledger(
            base_ledger=execution_ledger(order),
            stock_splits=(colliding_split,),
        )

    split = stock_split()
    dividend = cash_dividend(effective_at=split.effective_at)
    with pytest.raises(CorporateActionLedgerError, match="split and dividend"):
        reduce_corporate_action_ledger(
            base_ledger=execution_ledger(order),
            stock_splits=(split,),
            cash_dividends=(dividend,),
        )


def test_open_position_requires_a_mark_strictly_after_the_latest_split() -> None:
    split = stock_split()
    stale_mark = account_mark(
        "60",
        effective_at=split.effective_at,
        source="same-time-split-mark",
    )

    with pytest.raises(AccountProjectionError, match="post-split mark"):
        project_fifo_account(
            account_id=ACCOUNT_ID,
            order_states=(order_state(),),
            cash_flows=(funding(),),
            marks=(stale_mark,),
            stock_splits=(split,),
            valuation_at=VALUATION_AT,
        )


def test_exact_duplicates_and_caller_permutations_are_invariant() -> None:
    order = order_state()
    first_split = stock_split()
    second_split = stock_split(
        numerator="1",
        denominator="2",
        entitled_quantity="8",
        action_id="split-action-b",
        revision_id="split-revision-b",
        effective_at=ACTION_AT + timedelta(seconds=1),
    )
    first_dividend = cash_dividend(
        action_id="dividend-action-a",
        revision_id="dividend-revision-a",
        effective_at=ACTION_AT + timedelta(seconds=2),
    )
    second_dividend = cash_dividend(
        amount_per_share="0.75",
        action_id="dividend-action-b",
        revision_id="dividend-revision-b",
        effective_at=ACTION_AT + timedelta(seconds=3),
    )
    payments = (
        dividend_payment(first_dividend, suffix="a"),
        dividend_payment(second_dividend, suffix="b"),
    )
    expected = None

    for split_order in permutations((first_split, second_split)):
        for dividend_order in permutations((first_dividend, second_dividend)):
            for payment_order in permutations(payments):
                state = reduce_corporate_action_ledger(
                    base_ledger=execution_ledger(order),
                    stock_splits=(*split_order, split_order[0]),
                    cash_dividends=(*dividend_order, dividend_order[0]),
                    dividend_payments=(*payment_order, payment_order[0]),
                )
                if expected is None:
                    expected = state
                else:
                    assert state == expected
                    assert state.semantic_sha256 == expected.semantic_sha256


def test_action_revisions_source_reuse_and_payment_binding_fail_closed() -> None:
    base_ledger = execution_ledger(order_state())
    first_split = stock_split()
    revised_split = replace(
        first_split,
        source_revision_id="split-revision-a-v2",
        source_sha256=source_sha256("split-revision-a-v2"),
    )
    with pytest.raises(CorporateActionFactConflict, match="identity"):
        reduce_corporate_action_ledger(
            base_ledger=base_ledger,
            stock_splits=(first_split, revised_split),
        )

    reused_revision = cash_dividend(
        action_id="different-action",
        revision_id=first_split.source_revision_id,
        effective_at=ACTION_AT + timedelta(seconds=1),
    )
    with pytest.raises(CorporateActionFactConflict, match="source revision is reused"):
        reduce_corporate_action_ledger(
            base_ledger=base_ledger,
            stock_splits=(first_split,),
            cash_dividends=(reused_revision,),
        )

    dividend = cash_dividend()
    payment = dividend_payment(dividend)
    forged_payment = replace(payment, dividend_sha256="0" * 64)
    with pytest.raises(CorporateActionLedgerError, match="does not bind"):
        reduce_corporate_action_ledger(
            base_ledger=base_ledger,
            cash_dividends=(dividend,),
            dividend_payments=(forged_payment,),
        )
    with pytest.raises(CorporateActionLedgerError, match="no known accrual"):
        reduce_corporate_action_ledger(
            base_ledger=base_ledger,
            dividend_payments=(payment,),
        )

    second_payment = dividend_payment(dividend, suffix="second")
    with pytest.raises(CorporateActionFactConflict, match="conflicting payments"):
        reduce_corporate_action_ledger(
            base_ledger=base_ledger,
            cash_dividends=(dividend,),
            dividend_payments=(payment, second_payment),
        )


def test_corporate_action_arithmetic_is_independent_of_ambient_decimal_context() -> None:
    order = order_state(
        suffix="precise-buy",
        quantity="6",
        price="100.123456789",
        fee="1.123456789",
    )
    split = stock_split(
        numerator="3",
        denominator="2",
        entitled_quantity="6",
        action_id="precise-split-action",
        revision_id="precise-split-revision",
    )
    dividend = cash_dividend(
        amount_per_share="0.123456789",
        entitled_quantity="9",
        action_id="precise-dividend-action",
        revision_id="precise-dividend-revision",
        effective_at=ACTION_AT + timedelta(seconds=1),
    )
    payment = dividend_payment(dividend, suffix="precise")
    precise_mark = account_mark("101.987654321", source="precise-corporate-mark")

    with localcontext() as context:
        context.prec = 4
        low_precision = project_fifo_account(
            account_id=ACCOUNT_ID,
            order_states=(order,),
            cash_flows=(funding(),),
            marks=(precise_mark,),
            stock_splits=(split,),
            cash_dividends=(dividend,),
            dividend_payments=(payment,),
            valuation_at=VALUATION_AT,
        )
    with localcontext() as context:
        context.prec = 40
        high_precision = project_fifo_account(
            account_id=ACCOUNT_ID,
            order_states=(order,),
            cash_flows=(funding(),),
            marks=(precise_mark,),
            stock_splits=(split,),
            cash_dividends=(dividend,),
            dividend_payments=(payment,),
            valuation_at=VALUATION_AT,
        )

    assert low_precision == high_precision
    assert low_precision.semantic_sha256 == high_precision.semantic_sha256
