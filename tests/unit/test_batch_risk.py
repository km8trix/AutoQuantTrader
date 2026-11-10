from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, fields, replace
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal, localcontext
from itertools import permutations

import pytest

from packages.domain.account_projection import (
    CanonicalAccountProjection,
    create_position_mark,
    project_fifo_account,
)
from packages.domain.batch_risk import (
    BATCH_RISK_RULES,
    ActiveCapacityReservationState,
    BatchRiskAuthority,
    BatchRiskDecision,
    BatchRiskDecisionStatus,
    BatchRiskError,
    BatchRiskFactConflict,
    BatchRiskLimits,
    BatchRiskOperationalState,
    BatchRiskSession,
    VersionedBatchRiskSnapshot,
    batch_risk_snapshot_from_projections,
    batch_risk_snapshot_with_controls,
    evaluate_batch_risk_decision,
    initial_active_capacity_universe,
)
from packages.domain.clock import ClockEvent, FixedClock
from packages.domain.decimal_math import (
    exact_decimal_add,
    exact_decimal_multiply,
    exact_decimal_sum,
)
from packages.domain.decision import DecisionTrigger
from packages.domain.ledger_reducer import CashFlowKind, LedgerCashFlow, create_cash_flow
from packages.domain.models import (
    MarketEvent,
    OrderIntentBatch,
    PortfolioSnapshot,
    PositionTarget,
    RiskRuleResult,
    Side,
    TargetPortfolio,
)
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    CanonicalOrderState,
    create_order_submission,
    reduce_order_lifecycle,
)
from packages.domain.portfolio import portfolio_snapshot, target_to_intent_batch
from packages.domain.risk import RiskAuthorizationError
from packages.domain.settlement_ledger import (
    CanonicalSettlementLedgerState,
    ExecutionSettlementInstruction,
    create_settlement_instruction,
    reduce_settlement_ledger,
)
from packages.domain.walking_thread import WalkingThread
from packages.risk.batch_repository import (
    InMemoryBatchRiskRepository,
    InMemoryBatchRiskSnapshotProvider,
)

AS_OF = datetime(2026, 7, 15, 14, 0, tzinfo=UTC)
EVALUATED_AT = AS_OF + timedelta(seconds=10)
CONSUMED_AT = EVALUATED_AT + timedelta(seconds=1)

INSTRUMENTS = {
    "US-ETF-IWM": "IWM",
    "US-ETF-QQQ": "QQQ",
    "US-ETF-SPY": "SPY",
}
PRICES = {
    "US-ETF-IWM": Decimal("50"),
    "US-ETF-QQQ": Decimal("100"),
    "US-ETF-SPY": Decimal("100"),
}


@dataclass
class MutableClock:
    instant: datetime

    def now(self) -> datetime:
        return self.instant


@dataclass
class BlockingClock:
    instant: datetime
    entered: threading.Event
    release: threading.Event

    def now(self) -> datetime:
        self.entered.set()
        if not self.release.wait(timeout=10):
            raise TimeoutError("test clock was not released")
        return self.instant


@dataclass(frozen=True)
class ReconciledProjectionCase:
    account: CanonicalAccountProjection
    settlement: CanonicalSettlementLedgerState
    portfolio: PortfolioSnapshot
    order: CanonicalOrderState
    funding: LedgerCashFlow
    instruction: ExecutionSettlementInstruction
    market: MarketEvent


def price_event(
    instrument_id: str,
    *,
    event_time: datetime | None = None,
    price: Decimal | None = None,
) -> MarketEvent:
    symbol = INSTRUMENTS[instrument_id]
    resolved_event_time = event_time or AS_OF - timedelta(minutes=1)
    return MarketEvent(
        event_id=f"risk-price-{symbol}-{resolved_event_time.isoformat()}",
        instrument_id=instrument_id,
        symbol=symbol,
        event_time=resolved_event_time,
        available_at=AS_OF,
        close_price=price or PRICES[instrument_id],
        source="batch-risk-test-tape-v1",
        source_sequence=tuple(sorted(INSTRUMENTS)).index(instrument_id) + 1,
        observation_id=f"risk-price-{symbol}",
    )


def make_portfolio(
    *,
    current: dict[str, Decimal],
    instruments: tuple[str, ...],
    events: tuple[MarketEvent, ...] | None = None,
) -> PortfolioSnapshot:
    selected_events = events or tuple(price_event(instrument_id) for instrument_id in instruments)
    return portfolio_snapshot(
        as_of=AS_OF,
        current_positions={
            instrument_id: (INSTRUMENTS[instrument_id], quantity)
            for instrument_id, quantity in current.items()
        },
        price_events=selected_events,
    )


def make_batch(
    portfolio: PortfolioSnapshot,
    *,
    desired: dict[str, Decimal],
    target_id: str = "batch-risk-target",
    expires_at: datetime = AS_OF + timedelta(minutes=10),
) -> tuple[TargetPortfolio, OrderIntentBatch]:
    clock_event = ClockEvent(
        clock_event_id=f"clock-{target_id}",
        schedule_id="regular-session-v1",
        scheduled_at=AS_OF,
        sequence=0,
    )
    target = TargetPortfolio(
        target_id=target_id,
        strategy_id="batch-risk-strategy",
        strategy_version="1.0.0",
        strategy_configuration_sha256="a" * 64,
        decision_trigger=DecisionTrigger.from_clock_event(clock_event),
        as_of=AS_OF,
        expires_at=expires_at,
        targets=tuple(
            PositionTarget(
                instrument_id=instrument_id,
                symbol=INSTRUMENTS[instrument_id],
                quantity=quantity,
            )
            for instrument_id, quantity in sorted(desired.items())
        ),
        full_snapshot=False,
    )
    return target, target_to_intent_batch(target, portfolio)


def session(
    *,
    closes_at: datetime = datetime(2026, 7, 15, 20, 0, tzinfo=UTC),
) -> BatchRiskSession:
    return BatchRiskSession(
        calendar_id="xnys-batch-risk-test",
        calendar_version="2026.07.15",
        calendar_sha256="b" * 64,
        venue="XNYS",
        session_label=date(2026, 7, 15),
        opens_at=datetime(2026, 7, 15, 13, 30, tzinfo=UTC),
        closes_at=closes_at,
    )


def limits(**changes: object) -> BatchRiskLimits:
    values: dict[str, object] = {
        "policy_id": "minimum-cash-account-risk",
        "policy_version": "1.0.0",
        "allowed_instruments": frozenset(INSTRUMENTS),
        "max_order_quantity": Decimal("100"),
        "max_order_notional": Decimal("100000"),
        "max_batch_notional": Decimal("200000"),
        "max_instrument_gross_exposure": Decimal("100000"),
        "max_account_gross_exposure": Decimal("200000"),
        "minimum_cash_buffer": Decimal("0"),
        "estimated_fixed_fee": Decimal("1"),
        "estimated_fee_per_share": Decimal("0.1"),
        "market_order_price_buffer_per_share": Decimal("0.5"),
        "max_snapshot_age": timedelta(minutes=5),
        "max_price_age": timedelta(minutes=5),
        "approval_ttl": timedelta(seconds=30),
        "max_daily_order_count": 100,
        "max_open_order_count": 20,
    }
    values.update(changes)
    return BatchRiskLimits(**values)  # type: ignore[arg-type]


def snapshot(
    portfolio: PortfolioSnapshot,
    *,
    account_id: str = "batch-risk-account",
    available_cash: Decimal = Decimal("1000"),
    operational_state: BatchRiskOperationalState = BatchRiskOperationalState.RUNNING,
    halted_instruments: frozenset[str] = frozenset(),
    session_evidence: BatchRiskSession | None = None,
    daily_order_count: int = 0,
    open_order_count: int = 0,
) -> VersionedBatchRiskSnapshot:
    prices = {price.instrument_id: price.price for price in portfolio.prices}
    gross = exact_decimal_sum(
        exact_decimal_multiply(position.quantity, prices[position.instrument_id])
        for position in portfolio.positions
    )
    base_intent = WalkingThread.run().intent
    order_states: list[CanonicalOrderState] = []
    instructions: list[ExecutionSettlementInstruction] = []
    for index, position in enumerate(portfolio.positions, start=1):
        if position.quantity == 0:
            continue
        intent = replace(
            base_intent,
            intent_id=f"account-proof-intent-{position.instrument_id}",
            intent_batch_id=f"account-proof-batch-{position.instrument_id}",
            instrument_id=position.instrument_id,
            symbol=position.symbol,
            side=Side.BUY,
            quantity=position.quantity,
        )
        submitted_at = datetime(2026, 7, 15, 13, 32, index, tzinfo=UTC)
        submission = create_order_submission(
            intent=intent,
            risk_decision_id=f"account-proof-risk-{position.instrument_id}",
            submission_attempt_id=f"account-proof-attempt-{position.instrument_id}",
            submitted_at=submitted_at,
        )
        accepted = BrokerOrderEvent(
            event_id=f"account-proof-accepted-{position.instrument_id}",
            order_id=submission.order_id,
            broker_order_id=f"account-proof-broker-{position.instrument_id}",
            broker_sequence=1,
            occurred_at=submitted_at,
            received_at=submitted_at,
            kind=BrokerOrderEventKind.ACCEPTED,
        )
        execution = BrokerOrderEvent(
            event_id=f"account-proof-execution-event-{position.instrument_id}",
            order_id=submission.order_id,
            broker_order_id=f"account-proof-broker-{position.instrument_id}",
            broker_sequence=2,
            occurred_at=submitted_at + timedelta(milliseconds=100),
            received_at=submitted_at + timedelta(milliseconds=110),
            kind=BrokerOrderEventKind.EXECUTION,
            execution_id=f"account-proof-execution-{position.instrument_id}",
            execution_revision=1,
            quantity=position.quantity,
            price=prices[position.instrument_id],
            fee=Decimal(0),
        )
        order_states.append(
            reduce_order_lifecycle(
                submission=submission,
                broker_events=(accepted, execution),
            )
        )
        instructions.append(
            create_settlement_instruction(
                execution,
                contractual_settlement_at=AS_OF + timedelta(days=1),
                recorded_at=execution.received_at + timedelta(milliseconds=10),
                external_reference=f"account-proof-instruction-{position.instrument_id}",
            )
        )
    funding_amount = exact_decimal_add(available_cash, gross)
    cash_flows = (
        (
            create_cash_flow(
                kind=CashFlowKind.CONTRIBUTION,
                currency="USD",
                amount=funding_amount,
                effective_at=datetime(2026, 7, 15, 13, 30, tzinfo=UTC),
                recorded_at=datetime(2026, 7, 15, 13, 30, 1, tzinfo=UTC),
                external_reference=(
                    f"batch-risk-capacity-{portfolio.semantic_sha256}-{available_cash}"
                ),
            ),
        )
        if funding_amount > 0
        else ()
    )
    marks = tuple(
        create_position_mark(
            source_event_id=price.event_id,
            instrument_id=price.instrument_id,
            symbol=price.symbol,
            price=price.price,
            effective_at=price.event_time,
            recorded_at=price.available_at,
        )
        for price in portfolio.prices
    )
    account_projection = project_fifo_account(
        account_id=account_id,
        order_states=tuple(order_states),
        cash_flows=cash_flows,
        marks=marks,
        valuation_at=portfolio.as_of,
        currency="USD",
    )
    settlement_projection = reduce_settlement_ledger(
        account_id=account_id,
        order_states=tuple(order_states),
        cash_flows=cash_flows,
        instructions=tuple(instructions),
        currency="USD",
    )
    return batch_risk_snapshot_from_projections(
        version="account-snapshot-v1",
        portfolio_snapshot=portfolio,
        account_projection=account_projection,
        settlement_projection=settlement_projection,
        session=session_evidence or session(),
        operational_state=operational_state,
        halted_instruments=halted_instruments,
        daily_order_count=daily_order_count,
        open_order_count=open_order_count,
    )


def reconciled_projection_case() -> ReconciledProjectionCase:
    base = datetime(2026, 7, 15, 13, 31, 5, tzinfo=UTC)
    funding = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=Decimal("10000"),
        effective_at=base - timedelta(seconds=2),
        recorded_at=base - timedelta(seconds=1),
        external_reference="batch-risk-projection-funding",
    )
    intent = replace(
        WalkingThread.run().intent,
        intent_id="intent-batch-risk-projection",
        intent_batch_id="batch-risk-projection",
        side=Side.BUY,
        quantity=Decimal("4"),
    )
    submission = create_order_submission(
        intent=intent,
        risk_decision_id="risk-batch-risk-projection",
        submission_attempt_id="attempt-batch-risk-projection",
        submitted_at=base,
    )
    accepted = BrokerOrderEvent(
        event_id="accepted-batch-risk-projection",
        order_id=submission.order_id,
        broker_order_id="broker-batch-risk-projection",
        broker_sequence=1,
        occurred_at=base + timedelta(milliseconds=100),
        received_at=base + timedelta(milliseconds=110),
        kind=BrokerOrderEventKind.ACCEPTED,
    )
    execution = BrokerOrderEvent(
        event_id="execution-event-batch-risk-projection",
        order_id=submission.order_id,
        broker_order_id="broker-batch-risk-projection",
        broker_sequence=2,
        occurred_at=base + timedelta(milliseconds=200),
        received_at=base + timedelta(milliseconds=210),
        kind=BrokerOrderEventKind.EXECUTION,
        execution_id="execution-batch-risk-projection",
        execution_revision=1,
        quantity=Decimal("4"),
        price=Decimal("100"),
        fee=Decimal("1"),
    )
    order = reduce_order_lifecycle(
        submission=submission,
        broker_events=(accepted, execution),
    )
    market = price_event("US-ETF-SPY", price=Decimal("100"))
    mark = create_position_mark(
        source_event_id=market.event_id,
        instrument_id=market.instrument_id,
        symbol=market.symbol,
        price=market.close_price,
        effective_at=market.event_time,
        recorded_at=market.available_at,
    )
    account = project_fifo_account(
        account_id="batch-risk-account",
        order_states=(order,),
        cash_flows=(funding,),
        marks=(mark,),
        valuation_at=AS_OF,
        currency="USD",
    )
    instruction = create_settlement_instruction(
        execution,
        contractual_settlement_at=base + timedelta(days=1),
        recorded_at=execution.received_at + timedelta(milliseconds=10),
        external_reference="instruction-batch-risk-projection",
    )
    settlement = reduce_settlement_ledger(
        account_id="batch-risk-account",
        order_states=(order,),
        cash_flows=(funding,),
        instructions=(instruction,),
        currency="USD",
    )
    portfolio = make_portfolio(
        current={"US-ETF-SPY": Decimal("4")},
        instruments=("US-ETF-SPY",),
        events=(market,),
    )
    return ReconciledProjectionCase(
        account=account,
        settlement=settlement,
        portfolio=portfolio,
        order=order,
        funding=funding,
        instruction=instruction,
        market=market,
    )


def repository(
    capacity: VersionedBatchRiskSnapshot,
    *,
    configured_limits: BatchRiskLimits | None = None,
    evaluation_clock: MutableClock | None = None,
    consumption_clock: MutableClock | None = None,
) -> tuple[InMemoryBatchRiskRepository, MutableClock, MutableClock]:
    evaluated = evaluation_clock or MutableClock(EVALUATED_AT)
    consumed = consumption_clock or MutableClock(CONSUMED_AT)
    provider = InMemoryBatchRiskSnapshotProvider(capacity)
    authority = BatchRiskAuthority(
        limits=configured_limits or limits(),
        snapshots=provider,
        evaluation_clock=evaluated,
        consumption_clock=consumed,
    )
    return InMemoryBatchRiskRepository(authority), evaluated, consumed


def mixed_case() -> tuple[
    PortfolioSnapshot,
    TargetPortfolio,
    OrderIntentBatch,
    VersionedBatchRiskSnapshot,
]:
    portfolio = make_portfolio(
        current={"US-ETF-IWM": Decimal("10"), "US-ETF-SPY": Decimal("2")},
        instruments=("US-ETF-IWM", "US-ETF-SPY"),
    )
    target, batch = make_batch(
        portfolio,
        desired={"US-ETF-IWM": Decimal("6"), "US-ETF-SPY": Decimal("5")},
    )
    return portfolio, target, batch, snapshot(portfolio)


def rule(decision: BatchRiskDecision, name: str) -> RiskRuleResult:
    return next(item for item in decision.rules if item.rule == name)


@pytest.mark.parametrize(
    ("field_name", "forged_value", "message"),
    [
        ("available_cash", Decimal("1000000000"), "available cash"),
        ("current_gross_exposure", Decimal("0"), "current gross exposure"),
    ],
)
def test_risk_snapshot_revalidates_capacity_from_retained_projection_proofs(
    field_name: str,
    forged_value: object,
    message: str,
) -> None:
    _, target, batch, capacity = mixed_case()
    forged = object.__new__(VersionedBatchRiskSnapshot)
    for definition in fields(VersionedBatchRiskSnapshot):
        object.__setattr__(forged, definition.name, getattr(capacity, definition.name))
    object.__setattr__(forged, field_name, forged_value)

    with pytest.raises(BatchRiskFactConflict, match=message):
        InMemoryBatchRiskSnapshotProvider(forged)
    with pytest.raises(BatchRiskFactConflict, match=message):
        evaluate_batch_risk_decision(
            batch=batch,
            target=target,
            snapshot=forged,
            limits=limits(),
            active_capacity=initial_active_capacity_universe(forged.account_id),
            evaluated_at=EVALUATED_AT,
        )


def test_repository_revalidates_retained_projection_proofs_before_each_use() -> None:
    _, target, batch, capacity = mixed_case()
    risk, _, _ = repository(capacity)
    genuine_available_cash = capacity.available_cash
    object.__setattr__(capacity, "available_cash", Decimal("1000000000"))
    try:
        with pytest.raises(BatchRiskFactConflict, match="available cash"):
            risk.authorize(batch, target)
    finally:
        object.__setattr__(capacity, "available_cash", genuine_available_cash)


def test_mixed_buy_sell_batch_is_approved_with_exact_indivisible_holds() -> None:
    _, target, batch, capacity = mixed_case()
    risk, _, _ = repository(capacity)

    decision = risk.authorize(batch, target)

    assert decision.status is BatchRiskDecisionStatus.APPROVED
    assert tuple(item.rule for item in decision.rules) == BATCH_RISK_RULES
    assert all(item.passed for item in decision.rules)
    assert tuple(
        (item.instrument_id, item.side, item.quantity) for item in decision.authorizations
    ) == (
        ("US-ETF-IWM", Side.SELL, Decimal("4")),
        ("US-ETF-SPY", Side.BUY, Decimal("3")),
    )
    sell, buy = decision.authorizations
    assert sell.maximum_execution_price == Decimal("50")
    assert sell.maximum_fee == Decimal("1.4")
    assert sell.reserved_cash == Decimal("1.4")
    assert sell.reserved_sell_quantity == Decimal("4")
    assert sell.reserved_buy_exposure == 0
    assert buy.maximum_execution_price == Decimal("100.5")
    assert buy.maximum_fee == Decimal("1.3")
    assert buy.reserved_cash == Decimal("302.8")
    assert buy.reserved_sell_quantity == 0
    assert buy.reserved_buy_exposure == Decimal("301.5")
    assert decision.reservation is not None
    assert decision.reservation.authorizations == decision.authorizations
    assert decision.reservation.reserved_cash == Decimal("304.2")
    assert decision.reservation.reserved_buy_exposure == Decimal("301.5")
    assert risk.total_reserved_resources(capacity) == (
        Decimal("304.2"),
        Decimal("301.5"),
    )


def test_decision_identity_binds_the_exact_active_capacity_universe() -> None:
    _, target, batch, capacity = mixed_case()
    risk, _, _ = repository(capacity)
    prior = risk.authorize(batch, target)
    assert prior.reservation is not None
    active = initial_active_capacity_universe(
        capacity.account_id,
        (prior.reservation,),
    )
    frozen = replace(
        active,
        reservations=(
            replace(
                active.reservations[0],
                state=ActiveCapacityReservationState.FROZEN,
            ),
        ),
    )

    active_decision = evaluate_batch_risk_decision(
        batch=batch,
        target=target,
        snapshot=capacity,
        limits=limits(),
        active_capacity=active,
        evaluated_at=EVALUATED_AT,
    )
    frozen_decision = evaluate_batch_risk_decision(
        batch=batch,
        target=target,
        snapshot=capacity,
        limits=limits(),
        active_capacity=frozen,
        evaluated_at=EVALUATED_AT,
    )

    assert active.authorizations == frozen.authorizations
    assert active.semantic_sha256 != frozen.semantic_sha256
    assert active_decision.active_capacity_sha256 == active.semantic_sha256
    assert frozen_decision.active_capacity_sha256 == frozen.semantic_sha256
    assert active_decision.decision_id != frozen_decision.decision_id
    assert active_decision.semantic_sha256 != frozen_decision.semantic_sha256


def test_active_capacity_authorization_rejects_impossible_side_shapes() -> None:
    _, target, batch, capacity = mixed_case()
    risk, _, _ = repository(capacity)
    decision = risk.authorize(batch, target)
    assert decision.reservation is not None
    universe = initial_active_capacity_universe(
        capacity.account_id,
        (decision.reservation,),
    )
    buy = next(item for item in universe.authorizations if item.side is Side.BUY)
    sell = next(item for item in universe.authorizations if item.side is Side.SELL)

    with pytest.raises(BatchRiskError, match="reserved cash cannot be below buy exposure"):
        replace(
            buy,
            reserved_cash=buy.reserved_buy_exposure - Decimal("0.1"),
            remaining_cash=buy.remaining_buy_exposure - Decimal("0.1"),
        )
    with pytest.raises(BatchRiskError, match="requires buy exposure"):
        replace(buy, reserved_buy_exposure=Decimal(0), remaining_buy_exposure=Decimal(0))
    with pytest.raises(BatchRiskError, match="whole shares"):
        replace(
            sell,
            reserved_sell_quantity=sell.reserved_sell_quantity + Decimal("0.5"),
            remaining_sell_quantity=sell.remaining_sell_quantity + Decimal("0.5"),
        )
    with pytest.raises(BatchRiskError, match="cannot reserve buy exposure"):
        replace(
            sell,
            reserved_buy_exposure=Decimal("1"),
            remaining_buy_exposure=Decimal("1"),
        )


def test_one_member_failure_rejects_the_whole_batch_without_partial_holds() -> None:
    _, target, batch, capacity = mixed_case()
    risk, _, _ = repository(
        capacity,
        configured_limits=limits(max_order_quantity=Decimal("3")),
    )

    decision = risk.authorize(batch, target)

    assert decision.status is BatchRiskDecisionStatus.REJECTED
    assert not rule(decision, "quantity").passed
    assert decision.reservation is None
    assert decision.authorizations == ()
    assert risk.active_reservations() == ()


def test_evidence_bearing_empty_batch_is_no_action_without_rules_or_holds() -> None:
    portfolio = make_portfolio(
        current={"US-ETF-SPY": Decimal("2")},
        instruments=("US-ETF-SPY",),
    )
    target, batch = make_batch(portfolio, desired={"US-ETF-SPY": Decimal("2")})
    risk, _, _ = repository(snapshot(portfolio))

    decision = risk.authorize(batch, target)

    assert decision.status is BatchRiskDecisionStatus.NO_ACTION
    assert decision.intent_batch_sha256 == batch.semantic_sha256
    assert decision.rules == ()
    assert decision.reservation is None
    assert decision.authorizations == ()
    assert risk.active_reservations() == ()


def test_batch_and_each_intent_are_rebound_to_exact_portfolio_price_evidence() -> None:
    portfolio, target, batch, capacity = mixed_case()
    changed_event = replace(
        portfolio.prices[-1].event,
        close_price=Decimal("100.01"),
    )
    changed_portfolio = make_portfolio(
        current={"US-ETF-IWM": Decimal("10"), "US-ETF-SPY": Decimal("2")},
        instruments=("US-ETF-IWM", "US-ETF-SPY"),
        events=(portfolio.prices[0].event, changed_event),
    )

    with pytest.raises(BatchRiskFactConflict, match="portfolio snapshot"):
        evaluate_batch_risk_decision(
            batch=batch,
            target=target,
            snapshot=snapshot(changed_portfolio),
            limits=limits(),
            active_capacity=initial_active_capacity_universe(
                snapshot(changed_portfolio).account_id
            ),
            evaluated_at=EVALUATED_AT,
        )

    changed_intent = replace(batch.intents[-1], reference_price=Decimal("100.01"))
    forged_batch = replace(batch, intents=(*batch.intents[:-1], changed_intent))
    with pytest.raises(BatchRiskFactConflict, match="canonical target-position delta"):
        evaluate_batch_risk_decision(
            batch=forged_batch,
            target=target,
            snapshot=capacity,
            limits=limits(),
            active_capacity=initial_active_capacity_universe(capacity.account_id),
            evaluated_at=EVALUATED_AT,
        )

    changed_quantity = replace(
        batch.intents[-1],
        quantity=batch.intents[-1].quantity + Decimal("1"),
    )
    forged_quantity_batch = replace(
        batch,
        intents=(*batch.intents[:-1], changed_quantity),
    )
    with pytest.raises(BatchRiskFactConflict, match="canonical target-position delta"):
        evaluate_batch_risk_decision(
            batch=forged_quantity_batch,
            target=target,
            snapshot=capacity,
            limits=limits(),
            active_capacity=initial_active_capacity_universe(capacity.account_id),
            evaluated_at=EVALUATED_AT,
        )


def test_snapshot_factory_seals_exact_reconciled_account_and_settlement_evidence() -> None:
    case = reconciled_projection_case()

    sealed = batch_risk_snapshot_from_projections(
        version="projection-snapshot-v1",
        portfolio_snapshot=case.portfolio,
        account_projection=case.account,
        settlement_projection=case.settlement,
        session=session(),
        operational_state=BatchRiskOperationalState.RUNNING,
    )

    assert sealed.available_cash == case.settlement.available_cash
    assert sealed.current_gross_exposure == case.account.gross_exposure
    assert sealed.account_projection_sha256 == case.account.semantic_sha256
    assert sealed.settlement_projection_sha256 == case.settlement.semantic_sha256
    assert sealed.account_positions == case.portfolio.positions
    assert (
        sealed.account_execution_ledger_sha256
        == sealed.settlement_execution_ledger_sha256
        == case.account.ledger.semantic_sha256
    )
    with pytest.raises(TypeError, match="attested projections"):
        replace(sealed, available_cash=Decimal("1000000"))


def test_snapshot_factory_rejects_currency_and_execution_ledger_divergence() -> None:
    case = reconciled_projection_case()
    other_account_settlement = reduce_settlement_ledger(
        account_id="other-batch-risk-account",
        order_states=(case.order,),
        cash_flows=(case.funding,),
        instructions=(case.instruction,),
        currency="USD",
    )
    with pytest.raises(BatchRiskFactConflict, match="disagree on account"):
        batch_risk_snapshot_from_projections(
            version="projection-snapshot-v1",
            portfolio_snapshot=case.portfolio,
            account_projection=case.account,
            settlement_projection=other_account_settlement,
            session=session(),
            operational_state=BatchRiskOperationalState.RUNNING,
        )

    eur_funding = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="EUR",
        amount=case.funding.amount,
        effective_at=case.funding.effective_at,
        recorded_at=case.funding.recorded_at,
        external_reference="batch-risk-projection-eur-funding",
    )
    eur_settlement = reduce_settlement_ledger(
        account_id="batch-risk-account",
        order_states=(case.order,),
        cash_flows=(eur_funding,),
        instructions=(case.instruction,),
        currency="EUR",
    )
    with pytest.raises(BatchRiskFactConflict, match="currencies disagree"):
        batch_risk_snapshot_from_projections(
            version="projection-snapshot-v1",
            portfolio_snapshot=case.portfolio,
            account_projection=case.account,
            settlement_projection=eur_settlement,
            session=session(),
            operational_state=BatchRiskOperationalState.RUNNING,
        )

    conflicting_funding = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=case.funding.amount,
        effective_at=case.funding.effective_at,
        recorded_at=case.funding.recorded_at,
        external_reference="batch-risk-projection-conflicting-funding",
    )
    conflicting_settlement = reduce_settlement_ledger(
        account_id="batch-risk-account",
        order_states=(case.order,),
        cash_flows=(conflicting_funding,),
        instructions=(case.instruction,),
        currency="USD",
    )
    with pytest.raises(BatchRiskFactConflict, match="different execution ledgers"):
        batch_risk_snapshot_from_projections(
            version="projection-snapshot-v1",
            portfolio_snapshot=case.portfolio,
            account_projection=case.account,
            settlement_projection=conflicting_settlement,
            session=session(),
            operational_state=BatchRiskOperationalState.RUNNING,
        )


def test_snapshot_factory_rejects_position_mark_and_future_settlement_conflicts() -> None:
    case = reconciled_projection_case()
    changed_quantity = make_portfolio(
        current={"US-ETF-SPY": Decimal("3")},
        instruments=("US-ETF-SPY",),
        events=(case.market,),
    )
    with pytest.raises(BatchRiskFactConflict, match="portfolio positions do not match"):
        batch_risk_snapshot_from_projections(
            version="projection-snapshot-v1",
            portfolio_snapshot=changed_quantity,
            account_projection=case.account,
            settlement_projection=case.settlement,
            session=session(),
            operational_state=BatchRiskOperationalState.RUNNING,
        )

    changed_market = replace(case.market, close_price=Decimal("126"))
    changed_mark = make_portfolio(
        current={"US-ETF-SPY": Decimal("4")},
        instruments=("US-ETF-SPY",),
        events=(changed_market,),
    )
    with pytest.raises(BatchRiskFactConflict, match="portfolio price does not match"):
        batch_risk_snapshot_from_projections(
            version="projection-snapshot-v1",
            portfolio_snapshot=changed_mark,
            account_projection=case.account,
            settlement_projection=case.settlement,
            session=session(),
            operational_state=BatchRiskOperationalState.RUNNING,
        )

    future_instruction = create_settlement_instruction(
        case.order.broker_events[-1],
        contractual_settlement_at=AS_OF + timedelta(days=1),
        recorded_at=AS_OF + timedelta(seconds=1),
        external_reference="instruction-batch-risk-projection-future",
    )
    future_settlement = reduce_settlement_ledger(
        account_id="batch-risk-account",
        order_states=(case.order,),
        cash_flows=(case.funding,),
        instructions=(future_instruction,),
        currency="USD",
    )
    with pytest.raises(BatchRiskFactConflict, match="cannot come from the future"):
        batch_risk_snapshot_from_projections(
            version="projection-snapshot-v1",
            portfolio_snapshot=case.portfolio,
            account_projection=case.account,
            settlement_projection=future_settlement,
            session=session(),
            operational_state=BatchRiskOperationalState.RUNNING,
        )


@pytest.mark.parametrize(
    ("capacity_change", "limit_change", "failed_rule"),
    [
        (
            {"operational_state": BatchRiskOperationalState.PAUSED},
            {},
            "operational_state",
        ),
        (
            {"operational_state": BatchRiskOperationalState.HALTED},
            {},
            "operational_state",
        ),
        (
            {"halted_instruments": frozenset({"US-ETF-SPY"})},
            {},
            "instrument_halt",
        ),
        (
            {"session": session(closes_at=AS_OF)},
            {},
            "session",
        ),
        ({}, {"max_account_gross_exposure": Decimal("1000")}, "account_gross_exposure"),
        ({"daily_order_count": 99}, {"max_daily_order_count": 100}, "daily_order_count"),
        ({"open_order_count": 19}, {"max_open_order_count": 20}, "open_order_count"),
    ],
)
def test_control_session_and_account_limits_fail_closed(
    capacity_change: dict[str, object],
    limit_change: dict[str, object],
    failed_rule: str,
) -> None:
    _, target, batch, baseline = mixed_case()
    capacity = batch_risk_snapshot_with_controls(
        baseline,
        **capacity_change,  # type: ignore[arg-type]
    )
    risk, _, _ = repository(capacity, configured_limits=limits(**limit_change))

    decision = risk.authorize(batch, target)

    assert decision.status is BatchRiskDecisionStatus.REJECTED
    assert not rule(decision, failed_rule).passed
    assert decision.reservation is None


def test_stale_snapshot_and_stale_price_are_distinct_fail_closed_rules() -> None:
    portfolio, target, batch, capacity = mixed_case()
    stale_snapshot = evaluate_batch_risk_decision(
        batch=batch,
        target=target,
        snapshot=capacity,
        limits=limits(max_snapshot_age=timedelta(seconds=5)),
        active_capacity=initial_active_capacity_universe(capacity.account_id),
        evaluated_at=EVALUATED_AT,
    )
    assert stale_snapshot.status is BatchRiskDecisionStatus.REJECTED
    assert not rule(stale_snapshot, "snapshot_freshness").passed

    old_events = tuple(
        price_event(price.instrument_id, event_time=AS_OF - timedelta(minutes=6))
        for price in portfolio.prices
    )
    old_portfolio = make_portfolio(
        current={"US-ETF-IWM": Decimal("10"), "US-ETF-SPY": Decimal("2")},
        instruments=("US-ETF-IWM", "US-ETF-SPY"),
        events=old_events,
    )
    old_target, old_batch = make_batch(
        old_portfolio,
        desired={"US-ETF-IWM": Decimal("6"), "US-ETF-SPY": Decimal("5")},
    )
    stale_price = evaluate_batch_risk_decision(
        batch=old_batch,
        target=old_target,
        snapshot=snapshot(old_portfolio),
        limits=limits(),
        active_capacity=initial_active_capacity_universe(snapshot(old_portfolio).account_id),
        evaluated_at=EVALUATED_AT,
    )
    assert stale_price.status is BatchRiskDecisionStatus.REJECTED
    assert not rule(stale_price, "reference_price_freshness").passed


def test_stale_price_on_an_untouched_holding_fails_closed() -> None:
    portfolio = make_portfolio(
        current={"US-ETF-IWM": Decimal("4")},
        instruments=("US-ETF-IWM", "US-ETF-SPY"),
        events=(
            price_event(
                "US-ETF-IWM",
                event_time=AS_OF - timedelta(minutes=6),
            ),
            price_event("US-ETF-SPY"),
        ),
    )
    target, batch = make_batch(
        portfolio,
        desired={"US-ETF-SPY": Decimal("1")},
        target_id="buy-with-stale-untouched-holding",
    )

    decision = evaluate_batch_risk_decision(
        batch=batch,
        target=target,
        snapshot=snapshot(portfolio),
        limits=limits(),
        active_capacity=initial_active_capacity_universe(snapshot(portfolio).account_id),
        evaluated_at=EVALUATED_AT,
    )

    assert decision.status is BatchRiskDecisionStatus.REJECTED
    assert not rule(decision, "reference_price_freshness").passed


def test_sell_proceeds_are_never_netted_into_buying_capacity() -> None:
    portfolio, target, batch, _ = mixed_case()
    capacity = snapshot(portfolio, available_cash=Decimal("303"))
    risk, _, _ = repository(capacity)

    decision = risk.authorize(batch, target)

    assert decision.status is BatchRiskDecisionStatus.REJECTED
    assert not rule(decision, "cash_buffer").passed
    assert rule(decision, "cash_buffer").observed == "-12e-1"
    assert decision.reservation is None


def test_existing_sell_hold_prevents_a_parallel_batch_from_overselling() -> None:
    portfolio = make_portfolio(
        current={"US-ETF-IWM": Decimal("10")},
        instruments=("US-ETF-IWM",),
    )
    first_target, first = make_batch(
        portfolio,
        desired={"US-ETF-IWM": Decimal("4")},
        target_id="sell-six-a",
    )
    second_target, second = make_batch(
        portfolio,
        desired={"US-ETF-IWM": Decimal("4")},
        target_id="sell-six-b",
    )
    capacity = snapshot(portfolio)
    risk, _, _ = repository(capacity)

    approved = risk.authorize(first, first_target)
    rejected = risk.authorize(second, second_target)

    assert approved.status is BatchRiskDecisionStatus.APPROVED
    assert risk.reserved_sell_quantity(capacity, "US-ETF-IWM") == Decimal("6")
    assert rejected.status is BatchRiskDecisionStatus.REJECTED
    assert not rule(rejected, "sell_capacity").passed
    assert rejected.reservation is None


def test_exact_retry_is_idempotent_but_batch_identity_conflict_fails() -> None:
    portfolio, target, batch, capacity = mixed_case()
    risk, evaluation_clock, _ = repository(capacity)

    first = risk.authorize(batch, target)
    evaluation_clock.instant = first.expires_at + timedelta(minutes=1)
    retry = risk.authorize(batch, target)

    assert retry is first
    assert retry.expires_at == first.expires_at
    changed_target = replace(
        target,
        rebalance_generation=target.rebalance_generation + 1,
    )
    canonical_conflict = target_to_intent_batch(changed_target, portfolio)
    changed_intents = tuple(
        replace(intent, intent_batch_id=batch.intent_batch_id)
        for intent in canonical_conflict.intents
    )
    conflicting = replace(
        canonical_conflict,
        intent_batch_id=batch.intent_batch_id,
        intents=changed_intents,
    )
    with pytest.raises(BatchRiskFactConflict, match="batch IDs are immutable"):
        risk.authorize(conflicting, changed_target)


def test_child_authorizations_are_independently_single_use_and_expire_exclusively() -> None:
    _, target, batch, capacity = mixed_case()
    risk, _, consumption_clock = repository(capacity)
    decision = risk.authorize(batch, target)
    first_authorization = decision.authorizations[0]
    first_intent = next(
        intent for intent in batch.intents if intent.intent_id == first_authorization.intent_id
    )

    assert risk.consume(first_authorization.decision_id, first_intent) == CONSUMED_AT
    assert risk.was_consumed(first_authorization.decision_id)
    with pytest.raises(RiskAuthorizationError, match="already been consumed"):
        risk.consume(first_authorization.decision_id, first_intent)

    second_authorization = decision.authorizations[1]
    second_intent = next(
        intent for intent in batch.intents if intent.intent_id == second_authorization.intent_id
    )
    consumption_clock.instant = second_authorization.expires_at
    with pytest.raises(RiskAuthorizationError, match="expired"):
        risk.consume(second_authorization.decision_id, second_intent)
    assert not risk.was_consumed(second_authorization.decision_id)


def test_batch_hold_survives_partial_consumption_and_authorization_expiry() -> None:
    _, target, batch, capacity = mixed_case()
    risk, _, consumption_clock = repository(capacity)
    decision = risk.authorize(batch, target)
    assert decision.reservation is not None
    authorization = decision.authorizations[0]
    intent = next(item for item in batch.intents if item.intent_id == authorization.intent_id)

    risk.consume(authorization.decision_id, intent)
    consumption_clock.instant = decision.expires_at + timedelta(seconds=1)

    assert risk.active_reservations() == (decision.reservation,)
    assert risk.total_reserved_resources(capacity) == (
        Decimal("304.2"),
        Decimal("301.5"),
    )


def test_parallel_batches_cannot_overreserve_cash() -> None:
    portfolio = make_portfolio(
        current={},
        instruments=("US-ETF-QQQ", "US-ETF-SPY"),
    )
    batches = (
        make_batch(portfolio, desired={"US-ETF-QQQ": Decimal("5")}, target_id="buy-qqq"),
        make_batch(portfolio, desired={"US-ETF-SPY": Decimal("5")}, target_id="buy-spy"),
    )
    capacity = snapshot(portfolio, available_cash=Decimal("700"))
    risk, _, _ = repository(capacity)
    start = threading.Barrier(3)

    def authorize(case: tuple[TargetPortfolio, OrderIntentBatch]) -> BatchRiskDecisionStatus:
        target, batch = case
        start.wait(timeout=10)
        return risk.authorize(batch, target).status

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(authorize, case) for case in batches]
        start.wait(timeout=10)
        statuses = [future.result(timeout=10) for future in futures]

    assert sorted(status.value for status in statuses) == ["approved", "rejected"]
    reserved_cash, reserved_exposure = risk.total_reserved_resources(capacity)
    assert reserved_cash == Decimal("504")
    assert reserved_exposure == Decimal("502.5")
    assert reserved_cash <= capacity.available_cash


def test_repositories_for_one_authority_share_the_same_capacity_store() -> None:
    portfolio = make_portfolio(
        current={},
        instruments=("US-ETF-QQQ", "US-ETF-SPY"),
    )
    cases = (
        make_batch(portfolio, desired={"US-ETF-QQQ": Decimal("5")}, target_id="repo-a"),
        make_batch(portfolio, desired={"US-ETF-SPY": Decimal("5")}, target_id="repo-b"),
    )
    capacity = snapshot(portfolio, available_cash=Decimal("700"))
    provider = InMemoryBatchRiskSnapshotProvider(capacity)
    authority = BatchRiskAuthority(
        limits=limits(),
        snapshots=provider,
        evaluation_clock=MutableClock(EVALUATED_AT),
        consumption_clock=MutableClock(CONSUMED_AT),
    )
    repositories = (
        InMemoryBatchRiskRepository(authority),
        InMemoryBatchRiskRepository(authority),
    )
    start = threading.Barrier(3)

    def authorize(
        risk: InMemoryBatchRiskRepository,
        case: tuple[TargetPortfolio, OrderIntentBatch],
    ) -> BatchRiskDecisionStatus:
        target, batch = case
        start.wait(timeout=10)
        return risk.authorize(batch, target).status

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(authorize, risk, case)
            for risk, case in zip(repositories, cases, strict=True)
        ]
        start.wait(timeout=10)
        statuses = [future.result(timeout=10) for future in futures]

    assert sorted(status.value for status in statuses) == ["approved", "rejected"]
    assert repositories[0].active_reservations() == repositories[1].active_reservations()
    assert repositories[0].reserved_cash(capacity) == Decimal("504")


def test_duplicate_account_providers_cannot_create_independent_authorities() -> None:
    portfolio = make_portfolio(
        current={},
        instruments=("US-ETF-SPY",),
    )
    capacity = snapshot(portfolio)
    first_provider = InMemoryBatchRiskSnapshotProvider(capacity)
    duplicate_provider = InMemoryBatchRiskSnapshotProvider(capacity)
    first_authority = BatchRiskAuthority(
        limits=limits(),
        snapshots=first_provider,
        evaluation_clock=MutableClock(EVALUATED_AT),
        consumption_clock=MutableClock(CONSUMED_AT),
    )
    duplicate_authority = BatchRiskAuthority(
        limits=limits(),
        snapshots=duplicate_provider,
        evaluation_clock=MutableClock(EVALUATED_AT),
        consumption_clock=MutableClock(CONSUMED_AT),
    )

    InMemoryBatchRiskRepository(first_authority)

    with pytest.raises(BatchRiskFactConflict, match="multiple authorities"):
        InMemoryBatchRiskRepository(duplicate_authority)


def test_snapshot_transition_cannot_interleave_with_reservation_publication() -> None:
    portfolio = make_portfolio(
        current={},
        instruments=("US-ETF-SPY",),
    )
    target, batch = make_batch(
        portfolio,
        desired={"US-ETF-SPY": Decimal("1")},
        target_id="snapshot-transition-race",
    )
    capacity = snapshot(portfolio)
    entered = threading.Event()
    release = threading.Event()
    transition_started = threading.Event()
    transition_completed = threading.Event()
    provider = InMemoryBatchRiskSnapshotProvider(capacity)
    authority = BatchRiskAuthority(
        limits=limits(),
        snapshots=provider,
        evaluation_clock=BlockingClock(EVALUATED_AT, entered, release),
        consumption_clock=MutableClock(CONSUMED_AT),
    )
    risk = InMemoryBatchRiskRepository(authority)
    halted = batch_risk_snapshot_with_controls(
        capacity,
        operational_state=BatchRiskOperationalState.HALTED,
    )

    def transition() -> None:
        transition_started.set()
        provider.transition_to(halted)
        transition_completed.set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        decision_future = executor.submit(risk.authorize, batch, target)
        assert entered.wait(timeout=10)
        transition_future = executor.submit(transition)
        assert transition_started.wait(timeout=10)
        assert not transition_completed.wait(timeout=0.05)
        release.set()
        decision = decision_future.result(timeout=10)
        transition_future.result(timeout=10)

    assert decision.status is BatchRiskDecisionStatus.APPROVED
    assert transition_completed.is_set()
    assert provider.current() == halted


def test_parallel_sell_batches_cannot_overreserve_shares() -> None:
    portfolio = make_portfolio(
        current={"US-ETF-IWM": Decimal("10")},
        instruments=("US-ETF-IWM",),
    )
    batches = (
        make_batch(portfolio, desired={"US-ETF-IWM": Decimal("4")}, target_id="sell-race-a"),
        make_batch(portfolio, desired={"US-ETF-IWM": Decimal("4")}, target_id="sell-race-b"),
    )
    capacity = snapshot(portfolio)
    risk, _, _ = repository(capacity)
    start = threading.Barrier(3)

    def authorize(case: tuple[TargetPortfolio, OrderIntentBatch]) -> BatchRiskDecisionStatus:
        target, batch = case
        start.wait(timeout=10)
        return risk.authorize(batch, target).status

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(authorize, case) for case in batches]
        start.wait(timeout=10)
        statuses = [future.result(timeout=10) for future in futures]

    assert sorted(status.value for status in statuses) == ["approved", "rejected"]
    assert risk.reserved_sell_quantity(capacity, "US-ETF-IWM") == Decimal("6")
    assert risk.reserved_sell_quantity(capacity, "US-ETF-IWM") <= Decimal("10")


def test_caller_order_and_ambient_decimal_context_cannot_change_decision() -> None:
    current_items = (
        ("US-ETF-IWM", Decimal("10")),
        ("US-ETF-SPY", Decimal("2")),
    )
    events = tuple(price_event(instrument_id) for instrument_id, _ in current_items)
    expected: BatchRiskDecision | None = None

    for event_order in permutations(events):
        for current_order in permutations(current_items):
            portfolio = make_portfolio(
                current=dict(current_order),
                instruments=("US-ETF-IWM", "US-ETF-SPY"),
                events=event_order,
            )
            target, batch = make_batch(
                portfolio,
                desired={"US-ETF-SPY": Decimal("5"), "US-ETF-IWM": Decimal("6")},
            )
            for precision in (4, 40):
                with localcontext() as context:
                    context.prec = precision
                    decision = evaluate_batch_risk_decision(
                        batch=batch,
                        target=target,
                        snapshot=snapshot(portfolio),
                        limits=limits(),
                        active_capacity=initial_active_capacity_universe(
                            snapshot(portfolio).account_id
                        ),
                        evaluated_at=FixedClock(EVALUATED_AT).now(),
                    )
                if expected is None:
                    expected = decision
                else:
                    assert decision == expected
                    assert decision.semantic_sha256 == expected.semantic_sha256
