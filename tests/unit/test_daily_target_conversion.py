from dataclasses import replace
from datetime import UTC, date, datetime
from decimal import Decimal, Inexact, localcontext

import pytest

from packages.domain.accounting_contracts import AccountSnapshot, Commitment, PositionState
from packages.domain.engine_contracts import DailyTarget, DailyTrigger
from packages.domain.models import PositionTarget, Side
from packages.domain.personal_contracts import CausalMark, ReductionPoint, VersionPin
from packages.domain.portfolio import daily_target_to_intents

D = Decimal
SHA = "a" * 64
NOW = datetime(2025, 2, 4, 1, tzinfo=UTC)
OPEN = datetime(2025, 2, 4, 14, 30, tzinfo=UTC)
CLOSE = datetime(2025, 2, 4, 21, tzinfo=UTC)
SOURCE = date(2025, 2, 3)
EXECUTION = date(2025, 2, 4)
PIN = VersionPin("strategy", "fixture/1", SHA)


def account(*, quantity: str = "0", commitments: tuple[Commitment, ...] = ()) -> AccountSnapshot:
    zero = D(0)
    return AccountSnapshot(
        account_id="account",
        point=ReductionPoint(1, 1, NOW, 5),
        state_sha256=SHA,
        positions=() if quantity == "0" else (PositionState("spy", "SPY", D(quantity), D(0), ()),),
        commitments=commitments,
        marks=(
            CausalMark(
                "close",
                "spy",
                "SPY",
                D(100),
                SOURCE,
                datetime(2025, 2, 3, 21, tzinfo=UTC),
                NOW,
                SHA,
            ),
        ),
        trade_date_cash=D(10000),
        settled_cash=D(10000),
        trade_receivable=zero,
        trade_payable=zero,
        dividend_receivable=zero,
        buy_reserve=zero,
        sell_fee_reserve=zero,
        available_cash=D(10000),
        market_value=zero,
        nav=D(10000),
        gross_realized_pnl=zero,
        fees=zero,
        dividend_income=zero,
        unrealized_pnl=zero,
        net_external_flow=D(10000),
        journal_sha256=SHA,
        order_sha256=SHA,
    )


def target(quantity: str = "10") -> DailyTarget:
    return DailyTarget(
        "target",
        DailyTrigger("clock", SOURCE, EXECUTION, NOW, "complete_market", SHA, 0),
        SHA,
        (PositionTarget("spy", "SPY", D(quantity)),),
        OPEN,
        CLOSE,
    )


def commitment(*, quantity: str = "10", filled: str = "0", side: Side = Side.BUY) -> Commitment:
    return Commitment(
        "commitment",
        "intent",
        "order",
        "spy",
        "SPY",
        side,
        D(quantity),
        D(filled),
        D(quantity) - D(filled),
        D(1010),
        D(0) if side is Side.BUY else D(quantity) - D(filled),
        D(101),
        D(0),
        SOURCE,
        EXECUTION,
        0,
        OPEN,
        CLOSE,
        SHA,
        SHA,
    )


def test_initial_target_and_filled_target_have_literal_whole_share_deltas() -> None:
    batch = daily_target_to_intents(target(), account(), strategy_pin=PIN)
    assert [(i.side, i.quantity, i.reference_price) for i in batch.intents] == [
        (Side.BUY, D(10), D(100))
    ]
    sell = daily_target_to_intents(target("4"), account(quantity="10"), strategy_pin=PIN)
    assert [(i.side, i.quantity) for i in sell.intents] == [(Side.SELL, D(6))]
    assert daily_target_to_intents(target(), account(quantity="10"), strategy_pin=PIN).intents == ()


@pytest.mark.parametrize(
    "state", ["approved_unsent", "active", "working", "partial", "unknown", "pending_cancel"]
)
def test_every_live_commitment_counts_before_another_callback(state: str) -> None:
    pending = replace(commitment(filled="4"), state=state)
    batch = daily_target_to_intents(
        target(), account(quantity="4", commitments=(pending,)), strategy_pin=PIN
    )
    assert batch.intents == () and batch.reasons == ()
    changed = daily_target_to_intents(
        target("9"), account(quantity="4", commitments=(pending,)), strategy_pin=PIN
    )
    assert changed.intents == ()
    assert changed.reasons == ("PENDING_COMMITMENT_REQUIRES_EXPLICIT_RESOLUTION",)


def test_pending_sell_is_counted_but_never_replaced_by_opposing_buy() -> None:
    pending = commitment(quantity="6", side=Side.SELL)
    assert (
        daily_target_to_intents(
            target("4"), account(quantity="10", commitments=(pending,)), strategy_pin=PIN
        ).intents
        == ()
    )
    result = daily_target_to_intents(
        target("8"), account(quantity="10", commitments=(pending,)), strategy_pin=PIN
    )
    assert result.reasons and not result.intents


def test_batch_rejects_missing_price_and_mismatched_symbol() -> None:
    missing = daily_target_to_intents(target(), replace(account(), marks=()), strategy_pin=PIN)
    assert missing.reasons == ("MISSING_CURRENT_REFERENCE_PRICE",)
    with pytest.raises(ValueError, match="symbol"):
        daily_target_to_intents(
            replace(target(), targets=(PositionTarget("spy", "QQQ", D(10)),)),
            account(),
            strategy_pin=PIN,
        )


def test_reduction_uses_ambient_independent_exact_quantity_arithmetic() -> None:
    with localcontext() as context:
        context.prec = 1
        context.traps[Inexact] = True
        result = daily_target_to_intents(target("4"), account(quantity="123"), strategy_pin=PIN)
    assert result.intents[0].quantity == D(119)


def test_stale_and_duplicate_target_keys_reject() -> None:
    with pytest.raises(ValueError, match="knowledge"):
        daily_target_to_intents(
            target(), replace(account(), point=ReductionPoint(2, 2, OPEN, 5)), strategy_pin=PIN
        )
    with pytest.raises(ValueError, match="duplicate"):
        daily_target_to_intents(
            replace(target(), targets=target().targets * 2), account(), strategy_pin=PIN
        )
