"""The Phase 0 executable architecture proof."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from packages.domain.accounting import Ledger
from packages.domain.clock import FixedClock
from packages.domain.execution import SimulatedBroker
from packages.domain.identifiers import deterministic_id
from packages.domain.models import (
    AccountProjection,
    Fill,
    LedgerEntry,
    MarketEvent,
    Order,
    OrderIntent,
    Position,
    RiskDecision,
    TargetPortfolio,
    TraceStep,
)
from packages.domain.portfolio import target_to_order_intent
from packages.domain.risk import (
    FixedRiskAccountSnapshotProvider,
    InMemoryRiskDecisionRepository,
    RiskAccountSnapshot,
    RiskAuthority,
    RiskDecisionRepository,
    RiskLimits,
)
from packages.domain.strategy import FixedQuantityStrategy, ReadOnlyStrategyContext


@dataclass(frozen=True, slots=True)
class WalkingThreadResult:
    run_id: str
    started_at: datetime
    completed_at: datetime
    decision_event: MarketEvent
    fill_event: MarketEvent
    target: TargetPortfolio
    intent: OrderIntent
    risk_account_snapshot: RiskAccountSnapshot
    risk_decision: RiskDecision
    order: Order
    fill: Fill
    ledger_entries: tuple[LedgerEntry, ...]
    position: Position
    account: AccountProjection
    trace: tuple[TraceStep, ...]


class WalkingThread:
    """Runs one deterministic ETF buy through every mandatory Phase 0 boundary."""

    instrument_id = "US-ETF-SPY"
    symbol = "SPY"
    starting_cash = Decimal("100000.00")
    target_quantity = Decimal("10")
    execution_fee = Decimal("1.00")
    account_id = "simulation-account-001"
    risk_snapshot_version = "opening-balance-v1"

    @classmethod
    def risk_authority(cls) -> RiskAuthority:
        """Build the immutable authority used by this deterministic local fixture."""

        evaluated_at = datetime(2026, 7, 15, 13, 31, 1, tzinfo=UTC)
        submitted_at = evaluated_at + timedelta(seconds=1)
        return RiskAuthority(
            limits=RiskLimits(
                allowed_instruments=frozenset({cls.instrument_id}),
                max_order_quantity=Decimal("100"),
                max_order_notional=Decimal("25000.00"),
                minimum_cash_buffer=Decimal("1000.00"),
                estimated_fee=cls.execution_fee,
                approval_ttl=timedelta(seconds=30),
            ),
            account_snapshots=FixedRiskAccountSnapshotProvider(
                RiskAccountSnapshot(
                    account_id=cls.account_id,
                    version=cls.risk_snapshot_version,
                    available_cash=cls.starting_cash,
                )
            ),
            evaluation_clock=FixedClock(evaluated_at),
            consumption_clock=FixedClock(submitted_at),
        )

    @classmethod
    def run(
        cls,
        risk_repository: RiskDecisionRepository | None = None,
    ) -> WalkingThreadResult:
        started_at = datetime(2026, 7, 15, 13, 30, tzinfo=UTC)
        decision_event = MarketEvent(
            event_id="fixed-tape-SPY-20260715T133100Z",
            instrument_id=cls.instrument_id,
            symbol=cls.symbol,
            event_time=datetime(2026, 7, 15, 13, 31, tzinfo=UTC),
            available_at=datetime(2026, 7, 15, 13, 31, tzinfo=UTC),
            close_price=Decimal("100.00"),
        )
        fill_event = MarketEvent(
            event_id="fixed-tape-SPY-20260715T133200Z",
            instrument_id=cls.instrument_id,
            symbol=cls.symbol,
            event_time=datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
            available_at=datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
            close_price=Decimal("101.00"),
        )

        ledger = Ledger()
        ledger.open_account(cls.starting_cash, started_at)

        context = ReadOnlyStrategyContext(current_positions={})
        strategy = FixedQuantityStrategy(target_quantity=cls.target_quantity)
        strategy.initialize(context)
        target = strategy.on_market(context, decision_event)
        if target is None:
            raise RuntimeError("walking-thread strategy unexpectedly emitted no target")
        intent = target_to_order_intent(target, Decimal("0"), decision_event)
        if intent is None:
            raise RuntimeError("walking-thread target unexpectedly emitted no order intent")

        authority = cls.risk_authority()
        risk_snapshot = authority.account_snapshots.current()
        if risk_snapshot.available_cash != ledger.cash_balance():
            raise RuntimeError("walking-thread risk authority is not bound to ledger cash")
        resolved_risk_repository = risk_repository or InMemoryRiskDecisionRepository(authority)
        risk_decision = resolved_risk_repository.authorize(intent)

        broker = SimulatedBroker(resolved_risk_repository)
        working_order = broker.submit(intent, risk_decision.decision_id)
        order, fill = broker.fill_at_next_event(working_order, fill_event, cls.execution_fee)
        ledger.post_fill(fill)
        position = ledger.project_position(cls.instrument_id, cls.symbol, fill.price)
        account = ledger.project_account(position)

        run_id = deterministic_id("walking-thread", decision_event.event_id)
        trace = (
            TraceStep(
                trace_id=deterministic_id("trace", run_id, "market"),
                stage="market",
                status="completed",
                occurred_at=decision_event.available_at,
                title="Market event became available",
                detail="SPY close 100.00 entered the causal strategy context.",
            ),
            TraceStep(
                trace_id=deterministic_id("trace", run_id, "target"),
                stage="target",
                status="completed",
                occurred_at=target.as_of,
                title="Strategy emitted target",
                detail="fixed-quantity@1.0.0 targeted 10 whole shares of SPY.",
            ),
            TraceStep(
                trace_id=deterministic_id("trace", run_id, "risk"),
                stage="risk",
                status="completed",
                occurred_at=risk_decision.evaluated_at,
                title="Risk decision persisted",
                detail="All six rules passed; 1001.00 USD was reserved for one use.",
            ),
            TraceStep(
                trace_id=deterministic_id("trace", run_id, "order"),
                stage="order",
                status="completed",
                occurred_at=working_order.submitted_at,
                title="Simulated order submitted",
                detail="Execution consumed the persisted risk approval before submission.",
            ),
            TraceStep(
                trace_id=deterministic_id("trace", run_id, "fill"),
                stage="fill",
                status="completed",
                occurred_at=fill.executed_at,
                title="Order filled on next event",
                detail="Bought 10 SPY at 101.00 with a 1.00 USD fee.",
            ),
            TraceStep(
                trace_id=deterministic_id("trace", run_id, "ledger"),
                stage="ledger",
                status="completed",
                occurred_at=fill.executed_at,
                title="Balanced ledger entry posted",
                detail="1011.00 USD of debits and credits balance exactly.",
            ),
            TraceStep(
                trace_id=deterministic_id("trace", run_id, "position"),
                stage="position",
                status="completed",
                occurred_at=fill.executed_at,
                title="Position projection rebuilt",
                detail="The ledger projects 10 SPY, 98989.00 cash, and 99999.00 equity.",
            ),
        )
        return WalkingThreadResult(
            run_id=run_id,
            started_at=started_at,
            completed_at=fill_event.available_at,
            decision_event=decision_event,
            fill_event=fill_event,
            target=target,
            intent=intent,
            risk_account_snapshot=risk_snapshot,
            risk_decision=risk_decision,
            order=order,
            fill=fill,
            ledger_entries=ledger.entries,
            position=position,
            account=account,
            trace=trace,
        )
