from dataclasses import replace
from decimal import Inexact, localcontext

import pytest

from packages.domain.daily_risk import evaluate_daily_risk
from packages.domain.engine_contracts import DailyRiskEvidence, DailyRiskPolicy
from packages.domain.models import Side
from packages.domain.personal_contracts import ReductionPoint, VersionPin
from packages.domain.portfolio import daily_target_to_intents
from tests.unit.test_daily_target_conversion import (
    CLOSE,
    EXECUTION,
    NOW,
    OPEN,
    PIN,
    SHA,
    SOURCE,
    D,
    account,
    commitment,
    target,
)


def evidence(snapshot_sha256: str) -> DailyRiskEvidence:
    return DailyRiskEvidence(
        snapshot_sha256,
        "decision",
        NOW,
        SOURCE,
        EXECUTION,
        VersionPin("engine", "fixture/1", SHA),
        D(0),
        D(0),
        (),
        True,
        True,
        True,
        True,
        True,
        True,
        True,
    )


def test_literal_cash_reserve_includes_adverse_price_and_fee_once() -> None:
    snapshot = account()
    batch = daily_target_to_intents(target("24"), snapshot, strategy_pin=PIN)
    decision = evaluate_daily_risk(
        DailyRiskPolicy(), snapshot, batch, evidence(snapshot.semantic_sha256), NOW
    )
    assert decision.approved
    assert decision.reserved_cash_by_intent == ((batch.intents[0].intent_id, D("2424.24")),)
    assert decision.reserved_shares_by_intent == ()


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("daily_return", D("-.03"), "LOSS_CONTROL_BLOCKS_NEW_EXPOSURE"),
        ("drawdown", D(".15"), "LOSS_CONTROL_BLOCKS_NEW_EXPOSURE"),
        ("daily_return", None, "FLOW_NEUTRAL_LOSS_EVIDENCE_REQUIRED"),
        ("controls_healthy", False, "CONTROLS_HEALTHY_REQUIRED"),
        ("cash_semantics_known", False, "CASH_SEMANTICS_KNOWN_REQUIRED"),
        ("simulation_reconciled", False, "SIMULATION_RECONCILED_REQUIRED"),
        ("complete_daily_inputs", False, "COMPLETE_DAILY_INPUTS_REQUIRED"),
        ("snapshot_sha256", "b" * 64, "STALE_OR_UNBOUND_ACCOUNT_EVIDENCE"),
    ],
)
def test_mandatory_evidence_and_inclusive_loss_boundaries(
    field: str, value: object, reason: str
) -> None:
    snapshot = account()
    batch = daily_target_to_intents(target(), snapshot, strategy_pin=PIN)
    decision = evaluate_daily_risk(
        DailyRiskPolicy(),
        snapshot,
        batch,
        replace(evidence(snapshot.semantic_sha256), **{field: value}),
        NOW,
    )
    assert not decision.approved and reason in decision.reasons
    assert decision.reserved_cash_by_intent == ()


def test_ninth_intent_rejected_and_eighth_permitted() -> None:
    snapshot = account()
    batch = daily_target_to_intents(target(), snapshot, strategy_pin=PIN)
    for previous, expected in [(7, True), (8, False)]:
        fact = replace(
            evidence(snapshot.semantic_sha256),
            accepted_intent_ids=tuple(str(i) for i in range(previous)),
        )
        result = evaluate_daily_risk(DailyRiskPolicy(), snapshot, batch, fact, NOW)
        assert result.approved is expected
        if not expected:
            assert "SESSION_INTENT_LIMIT" in result.reasons


def test_activation_replaces_own_hold_once_without_recounting_intent() -> None:
    initial = account()
    original = daily_target_to_intents(target("24"), initial, strategy_pin=PIN)
    pending = replace(
        commitment(quantity="24"),
        intent_id=original.intents[0].intent_id,
        reserved_cash=D("2424.24"),
        remaining_fee_budget=D(".24"),
        policy_sha256=DailyRiskPolicy().semantic_sha256,
    )
    snapshot = replace(
        initial,
        commitments=(pending,),
        available_cash=D("7575.76"),
        buy_reserve=D("2424.24"),
        point=ReductionPoint(2, 10, OPEN, 3),
        marks=(
            replace(
                initial.marks[0],
                session=EXECUTION,
                economic_at=OPEN,
                knowledge_at=OPEN,
                basis="raw_execution",
            ),
        ),
    )
    batch = replace(original, snapshot_sha256=snapshot.semantic_sha256)
    fact = replace(
        evidence(snapshot.semantic_sha256),
        phase="activation",
        produced_at=OPEN,
        accepted_intent_ids=(pending.intent_id,),
    )
    result = evaluate_daily_risk(DailyRiskPolicy(), snapshot, batch, fact, OPEN)
    assert result.approved and result.reserved_cash_by_intent[0][1] == D("2424.24")
    tight = replace(snapshot, available_cash=D(0))
    result = evaluate_daily_risk(
        DailyRiskPolicy(),
        tight,
        replace(batch, snapshot_sha256=tight.semantic_sha256),
        replace(fact, snapshot_sha256=tight.semantic_sha256),
        OPEN,
    )
    assert result.approved  # held cash alone still covers the exact approved remainder


def test_unsettled_or_pending_sales_never_fund_buys() -> None:
    snapshot = replace(account(), available_cash=D(0), trade_receivable=D(10000))
    batch = daily_target_to_intents(target(), snapshot, strategy_pin=PIN)
    result = evaluate_daily_risk(
        DailyRiskPolicy(), snapshot, batch, evidence(snapshot.semantic_sha256), NOW
    )
    assert "INSUFFICIENT_SETTLED_UNCOMMITTED_CASH" in result.reasons


def test_reduce_only_loss_exception_still_requires_cash_for_sell_fee() -> None:
    snapshot = replace(account(quantity="10"), available_cash=D(0))
    batch = daily_target_to_intents(
        replace(target("0"), reduce_only_scope=True), snapshot, strategy_pin=PIN
    )
    result = evaluate_daily_risk(
        DailyRiskPolicy(),
        snapshot,
        batch,
        replace(evidence(snapshot.semantic_sha256), daily_return=D("-.04")),
        NOW,
    )
    assert "LOSS_CONTROL_BLOCKS_NEW_EXPOSURE" not in result.reasons
    assert "INSUFFICIENT_SETTLED_UNCOMMITTED_CASH" in result.reasons
    assert batch.intents[0].side is Side.SELL


@pytest.mark.parametrize(
    "quantity,reason", [("26", "ORDER_NAV_LIMIT"), ("1001", "ORDER_QUANTITY_LIMIT")]
)
def test_quantity_and_nav_caps(quantity: str, reason: str) -> None:
    snapshot = account()
    batch = daily_target_to_intents(target(quantity), snapshot, strategy_pin=PIN)
    assert (
        reason
        in evaluate_daily_risk(
            DailyRiskPolicy(), snapshot, batch, evidence(snapshot.semantic_sha256), NOW
        ).reasons
    )


def test_reservation_arithmetic_ignores_ambient_decimal_traps() -> None:
    snapshot = account()
    batch = daily_target_to_intents(target("24"), snapshot, strategy_pin=PIN)
    with localcontext() as context:
        context.prec = 1
        context.traps[Inexact] = True
        result = evaluate_daily_risk(
            DailyRiskPolicy(), snapshot, batch, evidence(snapshot.semantic_sha256), NOW
        )
    assert result.approved


def test_expiry_equal_boundary_rejects() -> None:
    snapshot = replace(account(), point=ReductionPoint(2, 10, CLOSE, 3))
    batch = daily_target_to_intents(
        replace(
            target(),
            trigger=replace(target().trigger, as_of=CLOSE),
            not_before=CLOSE,
            expires_at=CLOSE.replace(hour=22),
        ),
        snapshot,
        strategy_pin=PIN,
    )
    batch = replace(batch, target=replace(batch.target, expires_at=CLOSE))
    result = evaluate_daily_risk(
        DailyRiskPolicy(),
        snapshot,
        batch,
        replace(evidence(snapshot.semantic_sha256), produced_at=CLOSE),
        CLOSE,
    )
    assert "TARGET_EXPIRED" in result.reasons


@pytest.mark.parametrize("quantity,reason", [("30", "SYMBOL_NAV_LIMIT"), ("96", "GROSS_NAV_LIMIT")])
def test_existing_breach_needs_explicit_reduce_only_recovery(quantity: str, reason: str) -> None:
    snapshot = account(quantity=quantity)
    normal = daily_target_to_intents(target(str(D(quantity) - 1)), snapshot, strategy_pin=PIN)
    blocked = evaluate_daily_risk(
        DailyRiskPolicy(), snapshot, normal, evidence(snapshot.semantic_sha256), NOW
    )
    assert reason in blocked.reasons
    recovery = daily_target_to_intents(
        replace(normal.target, reduce_only_scope=True), snapshot, strategy_pin=PIN
    )
    accepted = evaluate_daily_risk(
        DailyRiskPolicy(), snapshot, recovery, evidence(snapshot.semantic_sha256), NOW
    )
    assert accepted.approved
    assert accepted.reserved_cash_by_intent[0][1] == D(".01")
