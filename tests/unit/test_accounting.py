from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal, localcontext

import pytest

from packages.domain.accounting import Ledger
from packages.domain.decision import DecisionTrigger
from packages.domain.models import OrderIntent, Posting
from packages.domain.portfolio import target_to_order_intent
from packages.domain.risk import RiskAccountSnapshot
from packages.domain.strategy import (
    FixedQuantityStrategy,
    ReadOnlyStrategyContext,
    StrategyInitializationContext,
)
from packages.domain.walking_thread import WalkingThread


@pytest.mark.parametrize("amount", [Decimal("NaN"), Decimal("Infinity"), Decimal("0")])
def test_opening_balance_must_be_finite_and_positive(amount: Decimal) -> None:
    with pytest.raises(ValueError, match="finite and positive"):
        Ledger().open_account(amount, datetime(2026, 7, 15, tzinfo=UTC))


@pytest.mark.parametrize("non_finite", [Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")])
def test_non_finite_values_are_rejected_at_accounting_and_risk_boundaries(
    non_finite: Decimal,
) -> None:
    result = WalkingThread.run()
    with pytest.raises(ValueError, match="fill fee"):
        replace(result.fill, fee=non_finite)
    with pytest.raises(ValueError, match="finite"):
        Posting(account="assets:cash:USD", currency="USD", debit=non_finite)
    with pytest.raises(ValueError, match="available cash"):
        RiskAccountSnapshot(
            account_id=WalkingThread.account_id,
            version=WalkingThread.risk_snapshot_version,
            available_cash=non_finite,
        )


@pytest.mark.parametrize("quantity", [Decimal("0.5"), Decimal("10.25")])
def test_fractional_share_facts_are_rejected(quantity: Decimal) -> None:
    result = WalkingThread.run()

    with pytest.raises(ValueError, match="whole number"):
        replace(result.target.targets[0], quantity=quantity)
    with pytest.raises(ValueError, match="whole number"):
        replace(result.intent, quantity=quantity)
    with pytest.raises(ValueError, match="whole number"):
        replace(result.order, quantity=quantity, filled_quantity=Decimal("0"))
    with pytest.raises(ValueError, match="whole number"):
        replace(result.fill, quantity=quantity)


def test_target_symbol_must_match_its_decision_batch_event() -> None:
    result = WalkingThread.run()
    mislabeled_target = replace(
        result.target,
        targets=(replace(result.target.targets[0], symbol="QQQ"),),
    )

    with pytest.raises(ValueError, match="target symbol"):
        target_to_order_intent(
            mislabeled_target,
            Decimal("0"),
            result.decision_batch,
        )


def test_target_position_collection_must_be_an_immutable_tuple() -> None:
    result = WalkingThread.run()
    caller_owned_targets = list(result.target.targets)

    with pytest.raises(ValueError, match="immutable tuple"):
        replace(result.target, targets=caller_owned_targets)  # type: ignore[arg-type]

    caller_owned_targets.clear()
    assert result.target.targets


def test_target_position_elements_cannot_be_mutable_duck_types() -> None:
    class MutablePositionTarget:
        def __init__(self) -> None:
            self.instrument_id = "US-ETF-SPY"
            self.symbol = "SPY"
            self.quantity = Decimal("10")

    result = WalkingThread.run()
    mutable_target = MutablePositionTarget()

    with pytest.raises(ValueError, match="immutable PositionTarget"):
        replace(result.target, targets=(mutable_target,))  # type: ignore[arg-type]

    mutable_target.quantity = Decimal("99")
    assert result.target.targets[0].quantity == Decimal("10")


def test_strategy_and_target_quantities_reject_mutable_numeric_duck_types() -> None:
    class MutableQuantity:
        def __init__(self) -> None:
            self.value = Decimal("10")

        def is_finite(self) -> bool:
            return self.value.is_finite()

        def __lt__(self, other: object) -> bool:
            return self.value < other  # type: ignore[operator]

        def to_integral_value(self) -> "MutableQuantity":
            return self

    result = WalkingThread.run()
    mutable_quantity = MutableQuantity()
    strategy = FixedQuantityStrategy(target_quantity=Decimal("10"))

    with pytest.raises(ValueError, match="exact Decimal"):
        replace(result.target.targets[0], quantity=mutable_quantity)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="exact Decimal"):
        ReadOnlyStrategyContext(
            decision_trigger=DecisionTrigger.from_market_batch(result.decision_batch),
            state=strategy.initialize(
                StrategyInitializationContext(
                    started_at=result.decision_batch.as_of,
                    current_positions={},
                )
            ),
            current_positions={"US-ETF-SPY": mutable_quantity},  # type: ignore[dict-item]
        )
    with pytest.raises(ValueError, match="exact Decimal"):
        FixedQuantityStrategy(target_quantity=mutable_quantity)  # type: ignore[arg-type]

    mutable_quantity.value = Decimal("99")
    assert result.target.targets[0].quantity == Decimal("10")


def test_target_to_intent_arithmetic_is_independent_of_ambient_context() -> None:
    result = WalkingThread.run()
    desired_quantity = Decimal("123456789012345678")
    target = replace(
        result.target,
        targets=(replace(result.target.targets[0], quantity=desired_quantity),),
    )

    def build_intent(precision: int) -> OrderIntent | None:
        with localcontext() as context:
            context.prec = precision
            return target_to_order_intent(
                target,
                Decimal("1"),
                result.decision_batch,
            )

    low_precision = build_intent(6)
    high_precision = build_intent(40)

    assert low_precision == high_precision
    assert low_precision is not None
    assert low_precision.quantity == Decimal("123456789012345677")
