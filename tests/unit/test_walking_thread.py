from decimal import ROUND_DOWN, ROUND_UP, Decimal, localcontext

from packages.domain.models import DecisionStatus, OrderStatus
from packages.domain.walking_thread import WalkingThread


def test_walking_thread_is_deterministic_and_complete() -> None:
    first = WalkingThread.run()
    second = WalkingThread.run()

    assert first == second
    assert first.decision_batch.complete
    assert first.decision_batch.events == (first.decision_event,)
    assert first.target.decision_batch_id == first.decision_batch.batch_id
    assert first.target.targets[0].quantity == Decimal("10")
    assert first.risk_decision.status is DecisionStatus.APPROVED
    assert all(rule.passed for rule in first.risk_decision.rules)
    assert first.order.status is OrderStatus.FILLED
    assert first.fill.executed_at > first.order.submitted_at
    assert first.fill.price == Decimal("101.00")
    assert first.position.quantity == Decimal("10")
    assert first.account.cash == Decimal("98989.00")
    assert first.account.equity == Decimal("99999.00")
    assert [step.stage for step in first.trace] == [
        "market",
        "target",
        "risk",
        "order",
        "fill",
        "ledger",
        "position",
    ]


def test_walking_thread_is_independent_of_ambient_decimal_context() -> None:
    with localcontext() as context:
        context.prec = 4
        context.capitals = 0
        context.rounding = ROUND_DOWN
        low_precision = WalkingThread.run()
    with localcontext() as context:
        context.prec = 40
        context.capitals = 1
        context.rounding = ROUND_UP
        high_precision = WalkingThread.run()

    assert low_precision == high_precision


def test_every_ledger_entry_balances_exactly() -> None:
    result = WalkingThread.run()

    for entry in result.ledger_entries:
        debits = sum((posting.debit for posting in entry.postings), Decimal("0"))
        credits = sum((posting.credit for posting in entry.postings), Decimal("0"))
        assert debits == credits
