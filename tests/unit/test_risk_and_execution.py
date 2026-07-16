from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from decimal import Decimal
from inspect import signature

import pytest

from packages.domain.clock import FixedClock
from packages.domain.execution import SimulatedBroker
from packages.domain.models import DecisionStatus, Side
from packages.domain.risk import (
    InMemoryRiskDecisionRepository,
    RiskAccountSnapshot,
    RiskAuthority,
    RiskAuthorizationError,
    RiskLimits,
)
from packages.domain.walking_thread import WalkingThread, WalkingThreadResult


@dataclass
class MutableSnapshotProvider:
    snapshot: RiskAccountSnapshot

    def current(self) -> RiskAccountSnapshot:
        return self.snapshot


def make_limits(
    *,
    max_order_quantity: Decimal = Decimal("100"),
    minimum_cash_buffer: Decimal = Decimal("1000"),
) -> RiskLimits:
    return RiskLimits(
        allowed_instruments=frozenset({WalkingThread.instrument_id}),
        max_order_quantity=max_order_quantity,
        max_order_notional=Decimal("25000"),
        minimum_cash_buffer=minimum_cash_buffer,
    )


def repository_for(
    result: WalkingThreadResult,
    *,
    evaluated_at: datetime | None = None,
    submitted_at: datetime | None = None,
    available_cash: Decimal = WalkingThread.starting_cash,
    limits: RiskLimits | None = None,
    version: str = WalkingThread.risk_snapshot_version,
) -> tuple[
    InMemoryRiskDecisionRepository,
    RiskAccountSnapshot,
    MutableSnapshotProvider,
]:
    snapshot = RiskAccountSnapshot(
        account_id=WalkingThread.account_id,
        version=version,
        available_cash=available_cash,
    )
    provider = MutableSnapshotProvider(snapshot)
    authority = RiskAuthority(
        limits=limits or make_limits(),
        account_snapshots=provider,
        evaluation_clock=FixedClock(evaluated_at or result.risk_decision.evaluated_at),
        consumption_clock=FixedClock(submitted_at or result.order.submitted_at),
    )
    return InMemoryRiskDecisionRepository(authority), snapshot, provider


def test_execution_rejects_missing_or_reused_persisted_approval() -> None:
    result = WalkingThread.run()
    repository, _, _ = repository_for(result)
    broker = SimulatedBroker(repository)

    with pytest.raises(RiskAuthorizationError, match="persisted"):
        broker.submit(result.intent, "missing")

    decision = repository.authorize(result.intent)
    broker.submit(result.intent, decision.decision_id)
    with pytest.raises(RiskAuthorizationError, match="already been consumed"):
        broker.submit(result.intent, decision.decision_id)


def test_expired_intent_persists_a_rejection_instead_of_raising() -> None:
    result = WalkingThread.run()
    stale_intent = replace(
        result.intent,
        expires_at=result.intent.created_at + timedelta(seconds=1),
    )
    evaluated_at = stale_intent.expires_at + timedelta(seconds=1)
    repository, _, _ = repository_for(
        result,
        evaluated_at=evaluated_at,
        submitted_at=evaluated_at,
    )

    decision = repository.authorize(stale_intent)

    assert decision.status is DecisionStatus.REJECTED
    assert decision.expires_at > decision.evaluated_at
    assert repository.get(decision.decision_id) == decision
    with pytest.raises(RiskAuthorizationError, match="rejected"):
        SimulatedBroker(repository).submit(stale_intent, decision.decision_id)


def test_same_event_fill_is_forbidden() -> None:
    result = WalkingThread.run()
    repository, _, _ = repository_for(result)
    decision = repository.authorize(result.intent)
    broker = SimulatedBroker(repository)
    order = broker.submit(result.intent, decision.decision_id)

    with pytest.raises(ValueError, match="later available"):
        broker.fill_at_next_event(order, result.decision_event, Decimal("1.00"))


@pytest.mark.parametrize(
    "changes",
    [
        {"quantity": Decimal("11")},
        {"side": Side.SELL},
        {"instrument_id": "US-ETF-QQQ"},
        {"symbol": "QQQ"},
        {"target_id": "forged-target"},
        {"reference_price": Decimal("99.00")},
        {"created_at": WalkingThread.run().intent.created_at + timedelta(seconds=1)},
        {"expires_at": WalkingThread.run().intent.expires_at + timedelta(seconds=1)},
    ],
)
def test_risk_approval_is_bound_to_the_complete_intent_payload(
    changes: dict[str, object],
) -> None:
    result = WalkingThread.run()
    repository, _, _ = repository_for(result)
    decision = repository.authorize(result.intent)

    with pytest.raises(RiskAuthorizationError, match="payload"):
        SimulatedBroker(repository).submit(
            replace(result.intent, **changes),  # type: ignore[arg-type]
            decision.decision_id,
        )


def test_approval_expiry_is_exclusive() -> None:
    result = WalkingThread.run()
    repository, _, _ = repository_for(
        result,
        submitted_at=result.risk_decision.expires_at,
    )
    decision = repository.authorize(result.intent)

    with pytest.raises(RiskAuthorizationError, match="expired"):
        SimulatedBroker(repository).submit(result.intent, decision.decision_id)


def test_risk_decision_rejects_empty_or_incomplete_rule_sets() -> None:
    decision = WalkingThread.run().risk_decision
    with pytest.raises(ValueError, match="complete versioned rule set"):
        replace(decision, rules=())
    forged = replace(decision.rules[0], rule="forged")
    with pytest.raises(ValueError, match="complete versioned rule set"):
        replace(decision, rules=(forged, *decision.rules[1:]))


def test_delayed_older_correction_cannot_fill_order() -> None:
    result = WalkingThread.run()
    repository, _, _ = repository_for(result)
    decision = repository.authorize(result.intent)
    broker = SimulatedBroker(repository)
    order = broker.submit(result.intent, decision.decision_id)
    delayed_correction = replace(
        result.fill_event,
        event_id="delayed-old-correction",
        event_time=result.decision_event.event_time - timedelta(minutes=1),
        available_at=result.fill_event.available_at + timedelta(minutes=1),
    )

    with pytest.raises(ValueError, match="causally later"):
        broker.fill_at_next_event(order, delayed_correction, Decimal("1.00"))


def test_authority_owns_policy_capacity_and_clocks() -> None:
    result = WalkingThread.run()
    repository, _, _ = repository_for(result)
    oversized = replace(
        result.intent,
        intent_id="oversized-intent",
        target_id="oversized-target",
        quantity=Decimal("1000000"),
    )

    assert list(signature(repository.authorize).parameters) == ["intent"]
    assert list(signature(repository.consume).parameters) == ["decision_id", "intent"]
    assert not hasattr(repository, "save")
    decision = repository.authorize(oversized)
    assert decision.status is DecisionStatus.REJECTED
    with pytest.raises(RiskAuthorizationError, match="rejected"):
        SimulatedBroker(repository).submit(oversized, decision.decision_id)


def test_reservations_prevent_double_spending_and_retries_are_idempotent() -> None:
    result = WalkingThread.run()
    limits = make_limits(minimum_cash_buffer=Decimal("0"))
    repository, snapshot, _ = repository_for(
        result,
        available_cash=Decimal("1500"),
        limits=limits,
        version="constrained-snapshot-v1",
    )
    first = repository.authorize(result.intent)
    retry = repository.authorize(result.intent)
    competing_intent = replace(
        result.intent,
        intent_id="competing-intent",
        target_id="competing-target",
    )
    second = repository.authorize(competing_intent)

    assert first.status is DecisionStatus.APPROVED
    assert retry == first
    assert second.status is DecisionStatus.REJECTED
    assert repository.reserved_cash(snapshot) == Decimal("1001.00")


def test_snapshot_provider_cannot_change_version_or_cash_capacity() -> None:
    result = WalkingThread.run()
    repository, snapshot, provider = repository_for(result)
    repository.authorize(result.intent)
    second = replace(result.intent, intent_id="second-intent", target_id="second-target")

    provider.snapshot = replace(
        snapshot,
        available_cash=WalkingThread.starting_cash + Decimal("1"),
    )
    with pytest.raises(RiskAuthorizationError, match="cash capacity"):
        repository.authorize(second)

    provider.snapshot = replace(snapshot, version="untrusted-roll-forward-v2")
    with pytest.raises(RiskAuthorizationError, match="snapshot version is stale"):
        repository.authorize(second)


def test_trusted_clocks_enforce_causal_evaluation_and_submission() -> None:
    result = WalkingThread.run()
    early_repository, _, _ = repository_for(
        result,
        evaluated_at=result.intent.created_at - timedelta(microseconds=1),
    )

    with pytest.raises(RiskAuthorizationError, match="precede intent creation"):
        early_repository.authorize(result.intent)
    with pytest.raises(ValueError, match="decision event"):
        replace(
            result.intent,
            decision_event_time=result.intent.created_at + timedelta(microseconds=1),
        )

    repository, _, _ = repository_for(
        result,
        submitted_at=result.risk_decision.evaluated_at - timedelta(microseconds=1),
    )
    decision = repository.authorize(result.intent)
    with pytest.raises(RiskAuthorizationError, match="before evaluation"):
        SimulatedBroker(repository).submit(result.intent, decision.decision_id)
