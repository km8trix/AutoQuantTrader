from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext
from fractions import Fraction
from itertools import permutations
from typing import TypedDict

import pytest

from packages.domain.account_projection import (
    AccountFactConflict,
    AccountProjectionError,
    UnvaluedFifoAccountProjection,
    create_position_mark,
    project_fifo_account,
    project_unvalued_fifo_account,
)
from packages.domain.corporate_action_ledger import (
    StockSplitAction,
    create_cash_dividend,
    create_dividend_payment,
    create_stock_split,
)
from packages.domain.decision import DecisionTrigger, DecisionTriggerKind
from packages.domain.ledger_reducer import CashFlowKind, LedgerCashFlow, create_cash_flow
from packages.domain.models import OrderIntent, Side
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    CanonicalOrderState,
    create_order_submission,
    reduce_order_lifecycle,
)
from tests.unit import test_account_projection as historical

BASE = datetime(2024, 6, 3, 13, 0, tzinfo=UTC)
AS_OF = BASE + timedelta(hours=1)


class _Scope(TypedDict):
    account_id: str
    as_of: datetime


SCOPE: _Scope = {"account_id": "synthetic-fifo", "as_of": AS_OF}


def order(
    name: str, side: Side, quantity: str, price: str, fee: str, minute: int
) -> CanonicalOrderState:
    at = BASE + timedelta(minutes=minute)
    intent = OrderIntent(
        intent_id=f"intent-{name}",
        intent_batch_id=f"batch-{name}",
        target_id=f"target-{name}",
        target_sha256="1" * 64,
        portfolio_snapshot_sha256="2" * 64,
        strategy_id="synthetic-fifo-oracle",
        strategy_version="1",
        strategy_configuration_sha256="3" * 64,
        decision_trigger=DecisionTrigger(DecisionTriggerKind.CLOCK, f"clock-{name}", "4" * 64, at),
        instrument_id="synthetic-spy",
        symbol="SPY",
        side=side,
        quantity=Decimal(quantity),
        reference_price=Decimal(price),
        decision_event_id=f"reference-{name}",
        reference_event_sha256="5" * 64,
        decision_event_time=at,
        created_at=at,
        expires_at=AS_OF,
    )
    submission = create_order_submission(
        intent=intent,
        risk_decision_id=f"risk-{name}",
        submission_attempt_id=f"attempt-{name}",
        submitted_at=at,
    )
    accepted = BrokerOrderEvent(
        event_id=f"accepted-{name}",
        order_id=submission.order_id,
        broker_order_id=f"broker-{name}",
        broker_sequence=1,
        occurred_at=at + timedelta(seconds=1),
        received_at=at + timedelta(seconds=1),
        kind=BrokerOrderEventKind.ACCEPTED,
    )
    executed = BrokerOrderEvent(
        event_id=f"fill-{name}",
        order_id=submission.order_id,
        broker_order_id=f"broker-{name}",
        broker_sequence=2,
        occurred_at=at + timedelta(seconds=2),
        received_at=at + timedelta(seconds=2),
        kind=BrokerOrderEventKind.EXECUTION,
        execution_id=f"execution-{name}",
        execution_revision=1,
        quantity=Decimal(quantity),
        price=Decimal(price),
        fee=Decimal(fee),
    )
    return reduce_order_lifecycle(submission=submission, broker_events=(accepted, executed))


def correct(
    state: CanonicalOrderState, quantity: str, price: str, fee: str, minute: int
) -> CanonicalOrderState:
    current = state.executions[0]
    assert state.broker_order_id is not None
    at = BASE + timedelta(minutes=minute)
    event = BrokerOrderEvent(
        event_id=f"revision-{current.revision + 1}-{current.execution_id}",
        order_id=state.submission.order_id,
        broker_order_id=state.broker_order_id,
        broker_sequence=state.last_broker_sequence + 1,
        occurred_at=at,
        received_at=at,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        execution_id=current.execution_id,
        execution_revision=current.revision + 1,
        supersedes_event_id=current.event_id,
        quantity=Decimal(quantity),
        price=Decimal(price),
        fee=Decimal(fee),
    )
    return reduce_order_lifecycle(
        submission=state.submission, broker_events=(*state.broker_events, event)
    )


def funding() -> LedgerCashFlow:
    return create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=Decimal(1000),
        effective_at=BASE,
        recorded_at=BASE,
        external_reference="synthetic-funding",
    )


def split(
    name: str, numerator: int, denominator: int, entitled: int, minute: int
) -> StockSplitAction:
    at = BASE + timedelta(minutes=minute)
    return create_stock_split(
        source_action_id=name,
        source_revision_id=f"{name}-r1",
        source_sha256="6" * 64,
        instrument_id="synthetic-spy",
        symbol="SPY",
        numerator=Decimal(numerator),
        denominator=Decimal(denominator),
        entitled_quantity=Decimal(entitled),
        effective_at=at,
        recorded_at=at,
    )


def test_strict_historical_outputs_and_hashes_are_unchanged() -> None:
    strict = project_fifo_account(
        account_id=historical.ACCOUNT_ID,
        order_states=historical.fifo_history(),
        cash_flows=(historical.funding(),),
        marks=(historical.mark(),),
        valuation_at=historical.VALUATION_AT,
    )
    # Captured from ec63ca79 before the extraction, using its existing fixture.
    assert (
        strict.semantic_sha256 == "3654526898db23839b8209257aeec61870c5addba8d709abbb68b8c7591bcf80"
    )
    assert strict.positions[0].semantic_sha256 == (
        "56db4aec41c41e2d41b30eccae534a1f265080feb84be1184a9abfa1d8543d7d"
    )
    facts = project_unvalued_fifo_account(
        account_id=historical.ACCOUNT_ID,
        order_states=historical.fifo_history(),
        cash_flows=(historical.funding(),),
        as_of=historical.VALUATION_AT,
    )
    for name in (
        "ledger",
        "corporate_action_ledger",
        "cash",
        "realized_pnl_before_fees",
        "execution_fees",
        "dividend_income",
        "dividend_receivable",
        "realized_pnl",
        "as_of",
    ):
        assert getattr(facts, name) == getattr(strict, name)
    assert facts.positions[0].open_lots == strict.positions[0].open_lots


def test_missing_marks_retains_cash_lots_and_fees_but_strict_still_rejects() -> None:
    buy = order("buy", Side.BUY, "4", "100", "1", 1)
    facts = project_unvalued_fifo_account(**SCOPE, order_states=(buy,), cash_flows=(funding(),))
    assert type(facts) is UnvaluedFifoAccountProjection
    assert facts.cash == 599
    assert facts.execution_fees == 1
    assert facts.positions[0].quantity == 4
    assert facts.positions[0].cost_basis == 400
    assert facts.positions[0].open_lot_lineage[0].fee_weight == (1, 1)
    assert not hasattr(facts, "equity")
    assert not hasattr(facts, "market_value")
    assert facts.realized_matches == ()
    with pytest.raises(AccountProjectionError, match="open position lacks a causal mark"):
        project_fifo_account(
            account_id=SCOPE["account_id"], valuation_at=AS_OF, order_states=(buy,)
        )
    with pytest.raises(FrozenInstanceError):
        facts.as_of = BASE  # type: ignore[misc]
    with pytest.raises(TypeError, match="only be created by the account reducer"):
        replace(facts, account_id="forged")


def test_fifo_matches_and_residual_fee_weights_are_exact_without_reexpensing() -> None:
    history = (
        order("first", Side.BUY, "2", "100", "2", 1),
        order("second", Side.BUY, "3", "110", "3", 2),
        order("sale", Side.SELL, "4", "120", "4", 3),
    )
    facts = project_unvalued_fifo_account(**SCOPE, order_states=history, cash_flows=(funding(),))
    first, second = facts.realized_matches
    assert [(match.quantity, match.cost_basis, match.proceeds) for match in (first, second)] == [
        (2, 200, 240),
        (2, 220, 240),
    ]
    assert first.buy.execution_id == "execution-first"
    assert second.buy.execution_id == "execution-second"
    assert first.buy_fee_weight == (1, 1)
    assert second.buy_fee_weight == (2, 3)
    assert first.sell_fee_weight == second.sell_fee_weight == (1, 2)
    residual = facts.positions[0].open_lot_lineage[0]
    assert residual.fee_weight == (1, 3)
    assert residual.lot.quantity == 1
    assert facts.cash == 941
    assert facts.realized_pnl_before_fees == 60
    assert facts.execution_fees == 9
    assert facts.realized_pnl == 51
    assert facts.ledger.balance("expenses:execution_fees", currency="USD").amount == 9
    allocated = sum(
        Fraction(match.buy.fee) * Fraction(*match.buy_fee_weight)
        + Fraction(match.sell.fee) * Fraction(*match.sell_fee_weight)
        for match in facts.realized_matches
    )
    assert allocated == 8
    assert allocated + Fraction(residual.execution.fee) * Fraction(*residual.fee_weight) == 9


def test_splits_preserve_fee_entitlement_through_sales_before_and_after_actions() -> None:
    history = (
        order("buy", Side.BUY, "4", "100", "1", 1),
        order("before", Side.SELL, "1", "110", "0.25", 2),
        order("after", Side.SELL, "2", "60", "0.5", 4),
        order("reverse", Side.SELL, "1", "120", "0.25", 6),
    )
    forward, reverse = split("forward", 2, 1, 3, 3), split("reverse", 1, 2, 4, 5)
    facts = project_unvalued_fifo_account(
        **SCOPE, order_states=history, cash_flows=(funding(),), stock_splits=(reverse, forward)
    )
    before, after, reversed_match = facts.realized_matches
    assert [match.buy_fee_weight for match in facts.realized_matches] == [(1, 4)] * 3
    assert before.split_ids == ()
    assert after.split_ids == (forward.split_id,)
    assert after.split_sha256s == (forward.semantic_sha256,)
    assert reversed_match.split_ids == (forward.split_id, reverse.split_id)
    assert reversed_match.split_sha256s == (forward.semantic_sha256, reverse.semantic_sha256)
    residual = facts.positions[0].open_lot_lineage[0]
    assert residual.fee_weight == (1, 4)
    assert residual.lot.quantity == 1
    assert residual.lot.cost_basis == 100
    assert residual.split_sha256s == (forward.semantic_sha256, reverse.semantic_sha256)
    assert residual.lot.acquired_at == history[0].executions[0].occurred_at
    assert facts.cash == 948
    assert facts.realized_pnl_before_fees == 50
    assert facts.execution_fees == 2
    assert facts.positions[0].latest_split_at == reverse.effective_at


def test_correction_changes_match_revision_not_original_acquisition_order() -> None:
    first = order("first", Side.BUY, "2", "100", "1", 1)
    second = order("second", Side.BUY, "2", "105", "1", 2)
    sale = order("sale", Side.SELL, "1", "110", "1", 3)
    initial = project_unvalued_fifo_account(**SCOPE, order_states=(first, second, sale))
    revised = correct(first, "2", "101", "2", 4)
    current = project_unvalued_fifo_account(**SCOPE, order_states=(revised, second, sale))
    old_match, new_match = initial.realized_matches[0], current.realized_matches[0]
    assert old_match.match_id == new_match.match_id
    assert old_match.semantic_sha256 != new_match.semantic_sha256
    assert new_match.buy.execution_id == first.executions[0].execution_id
    assert new_match.buy.revision == 2
    assert new_match.buy.event_sha256 == revised.broker_events[-1].semantic_sha256
    assert new_match.buy.occurred_at == first.executions[0].occurred_at
    assert new_match.buy.current_occurred_at == revised.executions[0].occurred_at
    assert new_match.cost_basis == 101
    assert new_match.realized_pnl_before_fees == 9
    assert current.positions[0].open_lots[0].acquired_at == first.executions[0].occurred_at
    assert current.realized_pnl_before_fees == 9
    assert current.execution_fees == 4
    assert old_match.cost_basis == 100  # The previously returned snapshot remains immutable.
    duplicate = project_unvalued_fifo_account(
        **SCOPE, order_states=(sale, revised, second, revised)
    )
    assert duplicate == current
    assert duplicate.semantic_sha256 == current.semantic_sha256


@pytest.mark.parametrize("fee", ("0", "1"))
def test_bust_removes_lot_and_matches_but_retains_explicit_current_fee(fee: str) -> None:
    bought = order("buy", Side.BUY, "4", "100", "1", 1)
    revised = correct(bought, "4", "101", "2", 2)
    busted = correct(revised, "0", "101", fee, 3)
    facts = project_unvalued_fifo_account(**SCOPE, order_states=(busted,), cash_flows=(funding(),))
    assert facts.cash == 1000 - Decimal(fee)
    assert facts.positions[0].quantity == facts.positions[0].cost_basis == 0
    assert facts.execution_fees == Decimal(fee)
    assert facts.realized_matches == ()
    assert facts.executions[0].revision == 3
    assert facts.executions[0].quantity == 0
    assert facts.executions[0].occurred_at == bought.executions[0].occurred_at


def test_sale_bust_releases_prior_match_and_restores_buy_fee_weight() -> None:
    buy = order("buy", Side.BUY, "3", "100", "1", 1)
    sale = order("sale", Side.SELL, "1", "110", "1", 2)
    before = project_unvalued_fifo_account(**SCOPE, order_states=(buy, sale))
    assert before.realized_matches[0].buy_fee_weight == (1, 3)
    busted = correct(sale, "0", "110", "0", 3)
    after = project_unvalued_fifo_account(**SCOPE, order_states=(buy, busted))
    assert after.realized_matches == ()
    assert after.positions[0].quantity == 3
    assert after.positions[0].open_lot_lineage[0].fee_weight == (1, 1)
    assert after.execution_fees == 1


def test_dividend_accrual_and_payment_remain_visible_without_marks() -> None:
    buy = order("buy", Side.BUY, "4", "100", "0", 1)
    accrual_at, payable_at = BASE + timedelta(minutes=2), BASE + timedelta(minutes=3)
    dividend = create_cash_dividend(
        source_action_id="dividend",
        source_revision_id="dividend-r1",
        source_sha256="7" * 64,
        instrument_id="synthetic-spy",
        symbol="SPY",
        currency="USD",
        amount_per_share=Decimal(2),
        entitled_quantity=Decimal(4),
        effective_at=accrual_at,
        payable_at=payable_at,
        recorded_at=accrual_at,
    )
    payment = create_dividend_payment(
        dividend=dividend,
        paid_at=payable_at,
        recorded_at=payable_at,
        external_reference="synthetic-payment",
    )
    accrued = project_unvalued_fifo_account(
        **SCOPE, order_states=(buy,), cash_flows=(funding(),), cash_dividends=(dividend,)
    )
    paid = project_unvalued_fifo_account(
        **SCOPE,
        order_states=(buy,),
        cash_flows=(funding(),),
        cash_dividends=(dividend,),
        dividend_payments=(payment,),
    )
    assert accrued.cash == 600
    assert accrued.dividend_receivable == 8
    assert paid.cash == 608
    assert paid.dividend_receivable == 0
    assert accrued.dividend_income == paid.dividend_income == 8
    assert accrued.realized_pnl == paid.realized_pnl == 8


def test_permutation_duplicates_and_decimal_context_do_not_change_lineage() -> None:
    history = (
        order("first", Side.BUY, "3", "100", "1", 1),
        order("second", Side.BUY, "3", "110", "1", 2),
        order("sale", Side.SELL, "4", "120", "1", 3),
    )
    expected = project_unvalued_fifo_account(**SCOPE, order_states=history)
    for precision, ordered in zip((4, 40, 4, 40, 4, 40), permutations(history), strict=True):
        with localcontext() as context:
            context.prec = precision
            result = project_unvalued_fifo_account(**SCOPE, order_states=(*ordered, ordered[0]))
            assert result == expected
            assert result.semantic_sha256 == expected.semantic_sha256
    other = project_unvalued_fifo_account(account_id="other", as_of=AS_OF, order_states=history)
    assert other.semantic_sha256 != expected.semantic_sha256
    assert other.realized_matches[0].match_id != expected.realized_matches[0].match_id


def test_unvalued_still_rejects_short_fractional_ambiguous_and_future_facts() -> None:
    buy = order("buy", Side.BUY, "1", "100", "0", 1)
    sale = order("sell", Side.SELL, "2", "110", "0", 2)
    with pytest.raises(AccountProjectionError, match="short position"):
        project_unvalued_fifo_account(**SCOPE, order_states=(buy, sale))
    with pytest.raises(AccountProjectionError, match="precede the accounting state"):
        project_unvalued_fifo_account(account_id="synthetic-fifo", as_of=BASE, order_states=(buy,))
    # Aggregate split quantity is whole, but an individual FIFO lot would be fractional.
    other = order("other", Side.BUY, "1", "100", "0", 2)
    action = split("fractional-lots", 3, 2, 2, 3)
    with pytest.raises(AccountProjectionError, match="fractional FIFO lot"):
        project_unvalued_fifo_account(**SCOPE, order_states=(buy, other), stock_splits=(action,))
    dividend = create_cash_dividend(
        source_action_id="ambiguous",
        source_revision_id="ambiguous-r1",
        source_sha256="8" * 64,
        instrument_id="synthetic-spy",
        symbol="SPY",
        currency="USD",
        amount_per_share=Decimal(1),
        entitled_quantity=Decimal(2),
        effective_at=action.effective_at,
        payable_at=AS_OF,
        recorded_at=action.recorded_at,
    )
    with pytest.raises(AccountProjectionError, match="ambiguous effective time"):
        project_unvalued_fifo_account(
            **SCOPE, order_states=(buy, other), stock_splits=(action,), cash_dividends=(dividend,)
        )


def test_strict_post_split_and_symbol_errors_remain_unchanged() -> None:
    buy = order("buy", Side.BUY, "4", "100", "0", 1)
    action = split("split", 2, 1, 4, 2)
    mark = create_position_mark(
        source_event_id="mark",
        instrument_id="synthetic-spy",
        symbol="SPY",
        price=Decimal(50),
        effective_at=action.effective_at,
        recorded_at=action.recorded_at,
    )
    with pytest.raises(AccountProjectionError, match="unambiguous post-split mark"):
        project_fifo_account(
            account_id="synthetic-fifo",
            valuation_at=AS_OF,
            order_states=(buy,),
            stock_splits=(action,),
            marks=(mark,),
        )
    wrong_symbol = replace(mark, symbol="QQQ", effective_at=AS_OF, recorded_at=AS_OF)
    with pytest.raises(AccountFactConflict, match="symbol conflicts"):
        project_fifo_account(
            account_id="synthetic-fifo",
            valuation_at=AS_OF,
            order_states=(buy,),
            stock_splits=(action,),
            marks=(wrong_symbol,),
        )


def test_nonrepresentable_partial_basis_still_fails_without_rounding() -> None:
    buy = order("buy", Side.BUY, "2", "100", "1", 1)
    action = split("thirds", 3, 2, 2, 2)
    sale = order("sale", Side.SELL, "1", "70", "1", 3)
    with pytest.raises(AccountProjectionError, match="partial FIFO basis allocation"):
        project_unvalued_fifo_account(**SCOPE, order_states=(buy, sale), stock_splits=(action,))
    with pytest.raises(AccountProjectionError, match="partial FIFO basis allocation"):
        project_fifo_account(
            account_id="synthetic-fifo",
            valuation_at=AS_OF,
            order_states=(buy, sale),
            stock_splits=(action,),
        )
