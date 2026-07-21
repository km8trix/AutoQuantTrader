"""Pure fixture-only golden backtest composed from the Phase 2 contracts.

The production strategy replay currently snapshots positions once for an entire
replay, while a round trip needs fills and corporate actions to become visible
before later callbacks.  This module therefore owns a deliberately narrow
causal step runner: it invokes the public strategy context/state contracts one
sealed batch at a time and rebuilds every economic projection between steps.

Likewise, the fixture authorization store below is only a single-use broker
capability.  It does not pretend to provide durable risk-hold lifecycle or
cross-process coordination.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

from packages.backtest.simulated_broker import (
    SIMULATED_BROKER_CONTRACT_VERSION,
    ConservativeSimulatedBroker,
    SimulatedBrokerOutcome,
    SimulatedBrokerResult,
    SimulatedBrokerSession,
    SimulatedMarketOrderModel,
)
from packages.domain.account_projection import (
    ACCOUNT_PROJECTION_CONTRACT_VERSION,
    CanonicalAccountProjection,
    PositionMark,
    create_position_mark,
    project_fifo_account,
)
from packages.domain.backtest_report import (
    NOT_APPLICABLE,
    BacktestContractPins,
    BacktestEquityPoint,
    BacktestLedgerTraceEntry,
    BacktestMetricConventions,
    BacktestMetrics,
    BacktestPosition,
    BacktestReport,
    BacktestReturnFrequency,
    BacktestReturnType,
    BacktestRunManifest,
    BacktestRunResult,
    BacktestRuntimePin,
    BacktestTrade,
    BenchmarkPin,
    DatasetReplayPin,
    ExternalCashFlowTreatment,
    SimulationModelKind,
    SimulationModelPin,
    StrategyRunPin,
    UncertaintyMethod,
)
from packages.domain.batch_risk import (
    BATCH_RISK_CONTRACT_VERSION,
    BatchRiskAuthorization,
    BatchRiskDecision,
    BatchRiskDecisionStatus,
    BatchRiskLimits,
    BatchRiskOperationalState,
    BatchRiskSession,
    BatchRiskSessionKind,
    VersionedBatchRiskSnapshot,
    batch_risk_snapshot_from_projections,
    evaluate_batch_risk_decision,
    initial_active_capacity_universe,
)
from packages.domain.canonical import canonical_json_bytes
from packages.domain.clock import ClockEvent
from packages.domain.corporate_action_ledger import (
    CORPORATE_ACTION_LEDGER_CONTRACT_VERSION,
    CanonicalCorporateActionLedgerState,
    CashDividendAccrual,
    CashDividendPayment,
    StockSplitAction,
    create_cash_dividend,
    create_dividend_payment,
    create_stock_split,
)
from packages.domain.decimal_math import DECIMAL_ARITHMETIC_VERSION
from packages.domain.decision import DecisionTrigger
from packages.domain.experiment_registry import (
    StrategyConfigurationRecord,
    StrategyVersionRecord,
)
from packages.domain.identifiers import canonical_id
from packages.domain.ledger_reducer import (
    LEDGER_REDUCER_CONTRACT_VERSION,
    CanonicalLedgerEntry,
    CanonicalLedgerState,
    CashFlowKind,
    LedgerCashFlow,
    create_cash_flow,
)
from packages.domain.market_batch import MarketBatch, MarketWatermark
from packages.domain.models import (
    MarketEvent,
    OrderIntent,
    OrderIntentBatch,
    PortfolioSnapshot,
    PositionTarget,
    TargetPortfolio,
)
from packages.domain.order_reducer import (
    ORDER_REDUCER_CONTRACT_VERSION,
    BrokerOrderEvent,
    BrokerOrderEventKind,
    CanonicalOrderState,
)
from packages.domain.portfolio import portfolio_snapshot, target_to_intent_batch
from packages.domain.replay import ReplayResult, replay_market_events
from packages.domain.risk import (
    RiskAuthorizationError,
    validate_authorization_consumption,
)
from packages.domain.settlement_ledger import (
    SETTLEMENT_LEDGER_CONTRACT_VERSION,
    CanonicalSettlementLedgerState,
    ExecutionSettlementConfirmation,
    ExecutionSettlementInstruction,
    create_settlement_confirmation,
    create_settlement_instruction,
    reduce_settlement_ledger,
)
from packages.domain.strategy import (
    ReadOnlyStrategyContext,
    StrategyInitializationContext,
    StrategyTransition,
)
from packages.domain.strategy_state import VersionedStrategyState
from packages.market_data.calendar import ExchangeSession, SessionKind

GOLDEN_BACKTEST_RUNNER_VERSION = "phase2-golden-backtest-runner-v1"
GOLDEN_CAUSAL_STRATEGY_RUNNER_VERSION = "phase2-golden-causal-strategy-runner-v1"
GOLDEN_FIXTURE_ID = "golden-buy-hold-split-dividend-sell"
GOLDEN_FIXTURE_VERSION = "1.0.0"

_ACCOUNT_ID = "fixture-golden-account"
_INSTRUMENT_ID = "US-ETF-SPY"
_SYMBOL = "SPY"
_CURRENCY = "USD"
_SOURCE = "golden-raw-fixture-v1"

_SESSION_OPEN = datetime(2026, 7, 15, 13, 30, tzinfo=UTC)
_SESSION_CLOSE = datetime(2026, 7, 15, 14, 0, tzinfo=UTC)
_ENTRY_DECISION_TIME = datetime(2026, 7, 15, 13, 31, tzinfo=UTC)
_ENTRY_FILL_TIME = datetime(2026, 7, 15, 13, 32, tzinfo=UTC)
_EXIT_DECISION_TIME = datetime(2026, 7, 15, 13, 34, tzinfo=UTC)
_EXIT_FILL_TIME = datetime(2026, 7, 15, 13, 36, tzinfo=UTC)
_WATERMARK_DELAY = timedelta(seconds=5)
_INITIAL_CORRECTION_AVAILABILITY = timedelta(seconds=1)


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _golden_parameter_schema_payload() -> str:
    return json.dumps(
        {
            "additionalProperties": False,
            "properties": {
                "instrument_id": {"const": _INSTRUMENT_ID, "type": "string"},
                "quantity": {"const": "4", "type": "string"},
            },
            "required": ["instrument_id", "quantity"],
            "type": "object",
        },
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def golden_strategy_version() -> StrategyVersionRecord:
    """Return the immutable catalog identity used by the golden strategy."""

    schema_payload = _golden_parameter_schema_payload()
    return StrategyVersionRecord(
        strategy_id="fixture-raw-buy-hold-exit",
        strategy_version="1.0.0",
        code_sha256=_sha256("fixture-raw-buy-hold-exit-code-v1"),
        parameter_schema_sha256=hashlib.sha256(schema_payload.encode("utf-8")).hexdigest(),
        state_schema_version="fixture-raw-buy-hold-exit-state-v1",
        source_revision="0" * 40,
        registered_at=_SESSION_OPEN,
        registered_by="phase2-golden-fixture",
    )


def golden_strategy_configuration() -> StrategyConfigurationRecord:
    """Return the only schema-validated configuration for the fixture."""

    version = golden_strategy_version()
    return StrategyConfigurationRecord(
        strategy_version_sha256=version.strategy_version_id,
        configuration_name="SPY four-share round trip",
        parameters={
            "instrument_id": _INSTRUMENT_ID,
            "quantity": Decimal("4"),
        },
        registered_at=_SESSION_OPEN + timedelta(microseconds=1),
        registered_by="phase2-golden-fixture",
    )


def golden_strategy_registration() -> tuple[
    StrategyVersionRecord, StrategyConfigurationRecord, str, str
]:
    """Return version, configuration, display name, and exact JSON schema."""

    return (
        golden_strategy_version(),
        golden_strategy_configuration(),
        "Golden raw-price buy, split, dividend, and exit",
        _golden_parameter_schema_payload(),
    )


def _canonical_positions(
    positions: Mapping[str, Decimal],
) -> tuple[tuple[str, Decimal], ...]:
    return tuple(sorted(positions.items()))


@dataclass(frozen=True, slots=True)
class GoldenStrategyStep:
    """One public strategy transition with its exact causal position snapshot."""

    batch: MarketBatch
    positions_before: tuple[tuple[str, Decimal], ...]
    context_sha256: str
    previous_state_sha256: str
    transition: StrategyTransition

    @property
    def target(self) -> TargetPortfolio | None:
        return self.transition.target

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                GOLDEN_CAUSAL_STRATEGY_RUNNER_VERSION,
                self.batch.semantic_sha256,
                self.positions_before,
                self.context_sha256,
                self.previous_state_sha256,
                self.transition.semantic_sha256,
            )
        )


@dataclass(frozen=True, slots=True)
class GoldenBacktestTrace:
    """Reducer-produced evidence retained by the fixture run."""

    market_events: tuple[MarketEvent, ...]
    replay: ReplayResult
    strategy_initial_state: VersionedStrategyState
    strategy_steps: tuple[GoldenStrategyStep, ...]
    portfolio_snapshots: tuple[PortfolioSnapshot, ...]
    intent_batches: tuple[OrderIntentBatch, ...]
    risk_snapshots: tuple[VersionedBatchRiskSnapshot, ...]
    risk_decisions: tuple[BatchRiskDecision, ...]
    broker_results: tuple[SimulatedBrokerResult, ...]
    funding: LedgerCashFlow
    stock_split: StockSplitAction
    cash_dividend: CashDividendAccrual
    dividend_payment: CashDividendPayment
    settlement_instructions: tuple[ExecutionSettlementInstruction, ...]
    settlement_confirmations: tuple[ExecutionSettlementConfirmation, ...]
    account_projections: tuple[CanonicalAccountProjection, ...]
    settlement_projections: tuple[CanonicalSettlementLedgerState, ...]

    @property
    def targets(self) -> tuple[TargetPortfolio, ...]:
        return tuple(step.target for step in self.strategy_steps if step.target is not None)

    @property
    def intents(self) -> tuple[OrderIntent, ...]:
        return tuple(intent for batch in self.intent_batches for intent in batch.intents)

    @property
    def order_states(self) -> tuple[CanonicalOrderState, ...]:
        return tuple(result.order_state for result in self.broker_results)

    @property
    def execution_events(self) -> tuple[BrokerOrderEvent, ...]:
        return tuple(
            event
            for result in self.broker_results
            for event in result.broker_events
            if event.kind is BrokerOrderEventKind.EXECUTION
        )

    @property
    def execution_ledger(self) -> CanonicalLedgerState:
        return self.account_projections[-1].ledger

    @property
    def corporate_action_ledger(self) -> CanonicalCorporateActionLedgerState:
        return self.account_projections[-1].corporate_action_ledger

    @property
    def settlement_ledger(self) -> CanonicalSettlementLedgerState:
        return self.settlement_projections[-1]

    @property
    def final_account(self) -> CanonicalAccountProjection:
        return self.account_projections[-1]

    @property
    def strategy_semantic_sha256(self) -> str:
        return _sha256(
            (
                GOLDEN_CAUSAL_STRATEGY_RUNNER_VERSION,
                self.replay.semantic_sha256,
                self.strategy_initial_state.semantic_sha256,
                tuple(step.semantic_sha256 for step in self.strategy_steps),
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                GOLDEN_BACKTEST_RUNNER_VERSION,
                tuple(event.semantic_sha256 for event in self.market_events),
                self.replay.semantic_sha256,
                self.strategy_semantic_sha256,
                tuple(snapshot.semantic_sha256 for snapshot in self.portfolio_snapshots),
                tuple(batch.semantic_sha256 for batch in self.intent_batches),
                tuple(snapshot.semantic_sha256 for snapshot in self.risk_snapshots),
                tuple(decision.semantic_sha256 for decision in self.risk_decisions),
                tuple(result.semantic_sha256 for result in self.broker_results),
                self.funding.semantic_sha256,
                self.stock_split.semantic_sha256,
                self.cash_dividend.semantic_sha256,
                self.dividend_payment.semantic_sha256,
                tuple(item.semantic_sha256 for item in self.settlement_instructions),
                tuple(item.semantic_sha256 for item in self.settlement_confirmations),
                tuple(item.semantic_sha256 for item in self.account_projections),
                tuple(item.semantic_sha256 for item in self.settlement_projections),
            )
        )


@dataclass(frozen=True, slots=True)
class GoldenBacktestRun:
    """Completed report, terminal proof objects, and their supporting trace."""

    report: BacktestReport
    result: BacktestRunResult
    manifest: BacktestRunManifest
    trace: GoldenBacktestTrace

    def __post_init__(self) -> None:
        if self.result != self.manifest.result:
            raise ValueError("golden run result must be bound to its manifest")
        if self.result.report_sha256 != self.report.report_sha256:
            raise ValueError("golden run result does not bind its economic report")
        if self.result.report_artifact_sha256 != self.report.artifact_sha256:
            raise ValueError("golden run result does not bind its report artifact")
        if self.manifest.execution_evidence_sha256 != _sha256(
            tuple(result.semantic_sha256 for result in self.trace.broker_results)
        ):
            raise ValueError("golden manifest execution evidence does not bind the trace")
        if self.manifest.risk_evidence_sha256 != _sha256(
            tuple(decision.semantic_sha256 for decision in self.trace.risk_decisions)
        ):
            raise ValueError("golden manifest risk evidence does not bind the trace")

    @property
    def economic_identity(self) -> str:
        return self.report.report_sha256

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                GOLDEN_BACKTEST_RUNNER_VERSION,
                self.report.report_sha256,
                self.report.artifact_sha256,
                self.result.semantic_sha256,
                self.manifest.manifest_sha256,
                self.trace.semantic_sha256,
            )
        )


@dataclass(frozen=True, slots=True)
class _GoldenBuyHoldStrategy:
    strategy_id: str = "fixture-raw-buy-hold-exit"
    version: str = "1.0.0"
    state_schema_version: str = "fixture-raw-buy-hold-exit-state-v1"

    @property
    def configuration_sha256(self) -> str:
        return golden_strategy_configuration().configuration_sha256

    def initialize(
        self,
        context: StrategyInitializationContext,
    ) -> VersionedStrategyState:
        if context.quantity_for(_INSTRUMENT_ID) != 0:
            raise ValueError("golden strategy requires an initially flat account")
        return VersionedStrategyState.initial(
            strategy_id=self.strategy_id,
            strategy_version=self.version,
            strategy_configuration_sha256=self.configuration_sha256,
            schema_version=self.state_schema_version,
            as_of=context.started_at,
            values={
                "clock_callbacks": 0,
                "market_callbacks": 0,
                "phase": "await_entry",
            },
        )

    def _next_state(
        self,
        context: ReadOnlyStrategyContext,
        *,
        phase: str,
        callback_key: str,
    ) -> VersionedStrategyState:
        context.require_strategy(
            strategy_id=self.strategy_id,
            strategy_version=self.version,
            strategy_configuration_sha256=self.configuration_sha256,
            state_schema_version=self.state_schema_version,
        )
        values = dict(context.state.values)
        callback_count = values.get(callback_key)
        if type(callback_count) is not int:
            raise ValueError("golden strategy callback state is invalid")
        values[callback_key] = callback_count + 1
        values["phase"] = phase
        return context.state.advance(trigger=context.decision_trigger, values=values)

    def _target(
        self,
        context: ReadOnlyStrategyContext,
        batch: MarketBatch,
        *,
        quantity: Decimal,
        generation: int,
    ) -> TargetPortfolio:
        return TargetPortfolio(
            target_id=canonical_id(
                "golden-target",
                self.strategy_id,
                self.version,
                batch.batch_id,
                quantity,
                generation,
            ),
            strategy_id=self.strategy_id,
            strategy_version=self.version,
            strategy_configuration_sha256=self.configuration_sha256,
            decision_trigger=context.decision_trigger,
            as_of=context.as_of,
            expires_at=context.as_of + timedelta(minutes=5),
            targets=(
                PositionTarget(
                    instrument_id=_INSTRUMENT_ID,
                    symbol=_SYMBOL,
                    quantity=quantity,
                ),
            ),
            rebalance_generation=generation,
        )

    def on_market(
        self,
        context: ReadOnlyStrategyContext,
        batch: MarketBatch,
    ) -> StrategyTransition:
        context.require_batch(batch)
        if len(batch.events) != 1 or batch.events[0].instrument_id != _INSTRUMENT_ID:
            raise ValueError("golden strategy requires one SPY raw-price event per batch")
        phase = context.state.values.get("phase")
        quantity = context.quantity_for(_INSTRUMENT_ID)
        target: TargetPortfolio | None = None
        next_phase: str
        if phase == "await_entry":
            if quantity != 0:
                raise ValueError("golden entry decision requires a flat account")
            target = self._target(
                context,
                batch,
                quantity=Decimal("4"),
                generation=1,
            )
            next_phase = "holding_pre_split"
        elif phase == "holding_pre_split" and quantity == Decimal("8"):
            target = self._target(
                context,
                batch,
                quantity=Decimal("0"),
                generation=2,
            )
            next_phase = "await_exit_fill"
        elif phase == "await_exit_fill" and quantity == 0:
            next_phase = "complete"
        elif type(phase) is str:
            next_phase = phase
        else:
            raise ValueError("golden strategy phase state is invalid")
        return StrategyTransition(
            state=self._next_state(
                context,
                phase=next_phase,
                callback_key="market_callbacks",
            ),
            target=target,
        )

    def on_clock(
        self,
        context: ReadOnlyStrategyContext,
        event: ClockEvent,
    ) -> StrategyTransition:
        context.require_clock_event(event)
        phase = context.state.values.get("phase")
        if type(phase) is not str:
            raise ValueError("golden strategy phase state is invalid")
        return StrategyTransition(
            state=self._next_state(
                context,
                phase=phase,
                callback_key="clock_callbacks",
            )
        )


class _SingleUseAuthorizationStore:
    """Fixture-scoped execution capability for approved child authorizations."""

    def __init__(self, authorizations: tuple[BatchRiskAuthorization, ...]) -> None:
        self._authorizations = {item.decision_id: item for item in authorizations}
        self._consumed: set[str] = set()

    def get(self, decision_id: str) -> BatchRiskAuthorization | None:
        return self._authorizations.get(decision_id)

    def consume(self, decision_id: str, intent: OrderIntent) -> datetime:
        authorization = self.get(decision_id)
        if authorization is None:
            raise RiskAuthorizationError(
                "execution requires a fixture-persisted risk authorization"
            )
        validate_authorization_consumption(
            authorization,
            intent,
            authorization.evaluated_at,
        )
        if decision_id in self._consumed:
            raise RiskAuthorizationError("risk authorization has already been consumed")
        self._consumed.add(decision_id)
        return authorization.evaluated_at


def _market_event(
    *,
    event_id: str,
    observation_id: str,
    event_time: datetime,
    available_at: datetime,
    close_price: Decimal,
    source_sequence: int,
    revision: int = 1,
    supersedes_event_revision_id: str | None = None,
) -> MarketEvent:
    return MarketEvent(
        event_id=event_id,
        instrument_id=_INSTRUMENT_ID,
        symbol=_SYMBOL,
        event_time=event_time,
        available_at=available_at,
        close_price=close_price,
        source=_SOURCE,
        source_sequence=source_sequence,
        observation_id=observation_id,
        revision=revision,
        supersedes_event_revision_id=supersedes_event_revision_id,
    )


def _market_tape(
    future_correction_delay: timedelta,
) -> tuple[tuple[MarketEvent, ...], tuple[MarketWatermark, ...]]:
    if type(future_correction_delay) is not timedelta:
        raise ValueError("future_correction_delay must be an exact timedelta")
    if not (_INITIAL_CORRECTION_AVAILABILITY <= future_correction_delay <= _WATERMARK_DELAY):
        raise ValueError(
            "future_correction_delay must keep the revision inside its pinned watermark"
        )
    exit_initial_id = "golden-exit-fill-revision-1"
    events = (
        _market_event(
            event_id="golden-entry-decision-raw",
            observation_id="golden-entry-decision-observation",
            event_time=_ENTRY_DECISION_TIME,
            available_at=_ENTRY_DECISION_TIME + timedelta(seconds=1),
            close_price=Decimal("100"),
            source_sequence=1,
        ),
        _market_event(
            event_id="golden-entry-fill-raw",
            observation_id="golden-entry-fill-observation",
            event_time=_ENTRY_FILL_TIME,
            available_at=_ENTRY_FILL_TIME + timedelta(seconds=1),
            close_price=Decimal("101"),
            source_sequence=2,
        ),
        _market_event(
            event_id="golden-exit-decision-raw",
            observation_id="golden-exit-decision-observation",
            event_time=_EXIT_DECISION_TIME,
            available_at=_EXIT_DECISION_TIME + timedelta(seconds=1),
            close_price=Decimal("53"),
            source_sequence=3,
        ),
        _market_event(
            event_id=exit_initial_id,
            observation_id="golden-exit-fill-observation",
            event_time=_EXIT_FILL_TIME,
            available_at=_EXIT_FILL_TIME + _INITIAL_CORRECTION_AVAILABILITY,
            close_price=Decimal("54.50"),
            source_sequence=4,
        ),
        _market_event(
            event_id="golden-exit-fill-revision-2",
            observation_id="golden-exit-fill-observation",
            event_time=_EXIT_FILL_TIME,
            available_at=_EXIT_FILL_TIME + future_correction_delay,
            close_price=Decimal("55"),
            source_sequence=5,
            revision=2,
            supersedes_event_revision_id=exit_initial_id,
        ),
    )
    watermarks = tuple(
        MarketWatermark(
            watermark_id=f"golden-watermark-{sequence}",
            event_time_through=event_time,
            closed_at=event_time + _WATERMARK_DELAY,
            expected_instrument_ids=(_INSTRUMENT_ID,),
        )
        for sequence, event_time in enumerate(
            (
                _ENTRY_DECISION_TIME,
                _ENTRY_FILL_TIME,
                _EXIT_DECISION_TIME,
                _EXIT_FILL_TIME,
            ),
            start=1,
        )
    )
    return events, watermarks


def _strategy_step(
    *,
    strategy: _GoldenBuyHoldStrategy,
    state: VersionedStrategyState,
    batch: MarketBatch,
    positions: Mapping[str, Decimal],
) -> GoldenStrategyStep:
    trigger = DecisionTrigger.from_market_batch(batch)
    context = ReadOnlyStrategyContext(
        decision_trigger=trigger,
        state=state,
        current_positions=positions,
    )
    transition = strategy.on_market(context, batch)
    state.require_successor(transition.state, trigger)
    if transition.target is not None:
        target = transition.target
        if (
            target.strategy_id != strategy.strategy_id
            or target.strategy_version != strategy.version
            or target.strategy_configuration_sha256 != strategy.configuration_sha256
            or target.decision_trigger != trigger
            or target.as_of != batch.as_of
        ):
            raise ValueError("golden strategy target is not bound to its callback")
    return GoldenStrategyStep(
        batch=batch,
        positions_before=_canonical_positions(positions),
        context_sha256=context.semantic_sha256,
        previous_state_sha256=state.semantic_sha256,
        transition=transition,
    )


def _mark(event: MarketEvent) -> PositionMark:
    return create_position_mark(
        source_event_id=event.event_id,
        instrument_id=event.instrument_id,
        symbol=event.symbol,
        price=event.close_price,
        effective_at=event.event_time,
        recorded_at=event.available_at,
    )


def _account_projection(
    *,
    order_states: tuple[CanonicalOrderState, ...],
    funding: LedgerCashFlow,
    marks: tuple[PositionMark, ...],
    stock_splits: tuple[StockSplitAction, ...] = (),
    cash_dividends: tuple[CashDividendAccrual, ...] = (),
    dividend_payments: tuple[CashDividendPayment, ...] = (),
    valuation_at: datetime,
) -> CanonicalAccountProjection:
    return project_fifo_account(
        account_id=_ACCOUNT_ID,
        order_states=order_states,
        cash_flows=(funding,),
        marks=marks,
        stock_splits=stock_splits,
        cash_dividends=cash_dividends,
        dividend_payments=dividend_payments,
        valuation_at=valuation_at,
        currency=_CURRENCY,
    )


def _settlement_projection(
    *,
    order_states: tuple[CanonicalOrderState, ...],
    funding: LedgerCashFlow,
    instructions: tuple[ExecutionSettlementInstruction, ...] = (),
    confirmations: tuple[ExecutionSettlementConfirmation, ...] = (),
) -> CanonicalSettlementLedgerState:
    return reduce_settlement_ledger(
        account_id=_ACCOUNT_ID,
        order_states=order_states,
        cash_flows=(funding,),
        instructions=instructions,
        confirmations=confirmations,
        currency=_CURRENCY,
    )


def _batch_risk_session(session: SimulatedBrokerSession) -> BatchRiskSession:
    return BatchRiskSession(
        calendar_id=session.calendar_id,
        calendar_version=session.calendar_version,
        calendar_sha256=session.calendar_sha256,
        venue=session.session.venue,
        session_label=session.session.session_label,
        opens_at=session.session.opens_at,
        closes_at=session.session.closes_at,
        kind=BatchRiskSessionKind(session.session.kind.value),
    )


def _risk_limits() -> BatchRiskLimits:
    return BatchRiskLimits(
        policy_id="golden-cash-account-risk",
        policy_version="1.0.0",
        allowed_instruments=frozenset({_INSTRUMENT_ID}),
        max_order_quantity=Decimal("100"),
        max_order_notional=Decimal("100000"),
        max_batch_notional=Decimal("100000"),
        max_instrument_gross_exposure=Decimal("100000"),
        max_account_gross_exposure=Decimal("100000"),
        minimum_cash_buffer=Decimal("0"),
        estimated_fixed_fee=Decimal("0.50"),
        estimated_fee_per_share=Decimal("0.01"),
        market_order_price_buffer_per_share=Decimal("1.07"),
        max_snapshot_age=timedelta(minutes=10),
        max_price_age=timedelta(minutes=10),
        approval_ttl=timedelta(seconds=30),
    )


def _authorize(
    *,
    target: TargetPortfolio,
    portfolio: PortfolioSnapshot,
    account: CanonicalAccountProjection,
    settlement: CanonicalSettlementLedgerState,
    session: BatchRiskSession,
    version: str,
    daily_order_count: int,
) -> tuple[
    OrderIntentBatch,
    VersionedBatchRiskSnapshot,
    BatchRiskDecision,
]:
    intent_batch = target_to_intent_batch(target, portfolio)
    snapshot = batch_risk_snapshot_from_projections(
        version=version,
        portfolio_snapshot=portfolio,
        account_projection=account,
        settlement_projection=settlement,
        session=session,
        operational_state=BatchRiskOperationalState.RUNNING,
        daily_order_count=daily_order_count,
    )
    decision = evaluate_batch_risk_decision(
        intent_batch,
        target,
        snapshot,
        _risk_limits(),
        initial_active_capacity_universe(snapshot.account_id),
        portfolio.as_of,
    )
    if (
        decision.status is not BatchRiskDecisionStatus.APPROVED
        or len(decision.authorizations) != 1
        or len(intent_batch.intents) != 1
    ):
        raise RuntimeError("golden fixture risk decision was not exactly one approval")
    return intent_batch, snapshot, decision


def _submit(
    *,
    intent_batch: OrderIntentBatch,
    decision: BatchRiskDecision,
    model: SimulatedMarketOrderModel,
    session: SimulatedBrokerSession,
    replay: ReplayResult,
    attempt: str,
) -> SimulatedBrokerResult:
    authorization = decision.authorizations[0]
    store = _SingleUseAuthorizationStore((authorization,))
    broker = ConservativeSimulatedBroker(
        risk_authorizations=store,
        model=model,
        session=session,
        market_batches=replay.batches,
    )
    result = broker.submit(
        intent_batch.intents[0],
        authorization.decision_id,
        f"golden-{attempt}-submission-attempt",
    )
    if result.outcome is not SimulatedBrokerOutcome.FILLED:
        raise RuntimeError("golden fixture order did not fill")
    return result


def _execution_event(result: SimulatedBrokerResult) -> BrokerOrderEvent:
    event = result.broker_events[-1]
    if event.kind is not BrokerOrderEventKind.EXECUTION:
        raise RuntimeError("golden broker result lacks its terminal execution")
    return event


def _settlement_instruction(
    event: BrokerOrderEvent,
    *,
    suffix: str,
) -> ExecutionSettlementInstruction:
    return create_settlement_instruction(
        event,
        contractual_settlement_at=event.occurred_at + timedelta(days=1),
        recorded_at=event.received_at + timedelta(seconds=1),
        external_reference=f"golden-{suffix}-t-plus-one-instruction",
    )


def _settlement_confirmation(
    instruction: ExecutionSettlementInstruction,
    *,
    suffix: str,
) -> ExecutionSettlementConfirmation:
    return create_settlement_confirmation(
        instruction,
        settled_at=instruction.contractual_settlement_at,
        recorded_at=instruction.contractual_settlement_at + timedelta(seconds=1),
        external_reference=f"golden-{suffix}-t-plus-one-confirmation",
    )


def _ledger_trace(
    *,
    execution_ledger: CanonicalLedgerState,
    corporate_action_ledger: CanonicalCorporateActionLedgerState,
    settlement_ledger: CanonicalSettlementLedgerState,
) -> tuple[BacktestLedgerTraceEntry, ...]:
    entries: tuple[CanonicalLedgerEntry, ...] = (
        *execution_ledger.entries,
        *corporate_action_ledger.corporate_action_entries,
        *settlement_ledger.settlement_entries,
    )
    ordered = tuple(
        sorted(entries, key=lambda item: (item.recorded_at, item.effective_at, item.entry_id))
    )
    return tuple(
        BacktestLedgerTraceEntry(
            sequence=sequence,
            entry_id=entry.entry_id,
            entry_kind=entry.kind.value,
            source_fact_id=entry.reference_id,
            effective_at=entry.effective_at,
            recorded_at=entry.recorded_at,
            entry_sha256=entry.semantic_sha256,
        )
        for sequence, entry in enumerate(ordered)
    )


def _position_row(
    projection: CanonicalAccountProjection,
    *,
    sequence: int,
) -> BacktestPosition:
    position = projection.positions[0]
    if position.mark is None:
        raise RuntimeError("golden account position lacks its raw mark")
    return BacktestPosition(
        sequence=sequence,
        as_of=projection.as_of,
        instrument_id=position.instrument_id,
        symbol=position.symbol,
        quantity=position.quantity,
        cost_basis=position.cost_basis,
        mark_price=position.mark.price,
        market_value=position.market_value,
        realized_pnl=position.realized_pnl,
        unrealized_pnl=position.unrealized_pnl,
        execution_costs=position.execution_fees,
        dividend_income=position.dividend_income,
        source_projection_sha256=projection.semantic_sha256,
    )


def _report(
    *,
    funding_at: datetime,
    buy_account: CanonicalAccountProjection,
    action_account: CanonicalAccountProjection,
    final_account: CanonicalAccountProjection,
    final_settlement: CanonicalSettlementLedgerState,
    buy_execution: BrokerOrderEvent,
    sell_execution: BrokerOrderEvent,
    generated_at: datetime,
) -> BacktestReport:
    conventions = BacktestMetricConventions(
        convention_id="golden-event-metrics",
        convention_version="1.0.0",
        currency=_CURRENCY,
        return_type=BacktestReturnType.SIMPLE,
        return_frequency=BacktestReturnFrequency.EVENT,
        annualization_periods=252,
        annual_risk_free_rate=Decimal("0"),
        risk_free_rate_version="fixture-zero-v1",
        external_cash_flow_treatment=ExternalCashFlowTreatment.EXCLUDED_FROM_RETURN,
        uncertainty_method=UncertaintyMethod.NONE,
        absolute_tolerance=Decimal("0.0000000001"),
        relative_tolerance=Decimal("0"),
    )
    equity_curve = (
        BacktestEquityPoint(
            sequence=0,
            as_of=funding_at,
            cash=Decimal("1000"),
            market_value=Decimal("0"),
            equity=Decimal("1000"),
            gross_exposure=Decimal("0"),
            net_exposure=Decimal("0"),
            cumulative_external_cash_flow=Decimal("1000"),
            period_return=Decimal("0"),
            cumulative_return=Decimal("0"),
            drawdown=Decimal("0"),
        ),
        BacktestEquityPoint(
            sequence=1,
            as_of=buy_account.as_of,
            cash=buy_account.cash,
            market_value=buy_account.market_value,
            equity=buy_account.equity,
            gross_exposure=buy_account.gross_exposure,
            net_exposure=buy_account.net_exposure,
            cumulative_external_cash_flow=Decimal("1000"),
            period_return=Decimal("-0.00082"),
            cumulative_return=Decimal("-0.00082"),
            drawdown=Decimal("0.00082"),
        ),
        BacktestEquityPoint(
            sequence=2,
            as_of=action_account.as_of,
            cash=action_account.cash,
            market_value=action_account.market_value,
            equity=action_account.equity,
            gross_exposure=action_account.gross_exposure,
            net_exposure=action_account.net_exposure,
            cumulative_external_cash_flow=Decimal("1000"),
            period_return=Decimal("0.0300246202"),
            cumulative_return=Decimal("0.02918"),
            drawdown=Decimal("0"),
        ),
        BacktestEquityPoint(
            sequence=3,
            as_of=final_account.as_of,
            cash=final_account.cash,
            market_value=final_account.market_value,
            equity=final_account.equity,
            gross_exposure=final_account.gross_exposure,
            net_exposure=final_account.net_exposure,
            cumulative_external_cash_flow=Decimal("1000"),
            period_return=Decimal("0.0144386793"),
            cumulative_return=Decimal("0.04404"),
            drawdown=Decimal("0"),
        ),
    )
    trade = BacktestTrade(
        sequence=0,
        trade_id=canonical_id(
            "golden-round-trip",
            buy_execution.execution_id,
            sell_execution.execution_id,
        ),
        instrument_id=_INSTRUMENT_ID,
        symbol=_SYMBOL,
        opened_at=buy_execution.occurred_at,
        closed_at=sell_execution.occurred_at,
        quantity=Decimal("8"),
        cost_basis=Decimal("404.28"),
        proceeds=Decimal("439.44"),
        gross_pnl=Decimal("35.16"),
        execution_costs=Decimal("1.12"),
        net_pnl=Decimal("34.04"),
        opening_execution_sha256=buy_execution.semantic_sha256,
        closing_execution_sha256=sell_execution.semantic_sha256,
    )
    positions = (
        _position_row(buy_account, sequence=0),
        _position_row(action_account, sequence=1),
        _position_row(final_account, sequence=2),
    )
    metrics = BacktestMetrics(
        starting_equity=Decimal("1000"),
        ending_equity=Decimal("1044.04"),
        total_return=Decimal("0.04404"),
        annualized_return=None,
        annualized_volatility=None,
        sharpe_ratio=None,
        sortino_ratio=None,
        maximum_drawdown=Decimal("0.00082"),
        turnover=Decimal("0.84372"),
        average_gross_exposure=Decimal("207"),
        average_net_exposure=Decimal("207"),
        trade_count=1,
        winning_trade_count=1,
        losing_trade_count=0,
        breakeven_trade_count=0,
        hit_rate=Decimal("1"),
        profit_factor=None,
        total_execution_costs=Decimal("1.12"),
        capacity_proxy=None,
        realized_pnl=Decimal("44.04"),
        unrealized_pnl=Decimal("0"),
        dividend_income=Decimal("10"),
    )
    return BacktestReport(
        account_id=_ACCOUNT_ID,
        currency=_CURRENCY,
        period_start=funding_at,
        period_end=final_account.as_of,
        generated_at=generated_at,
        conventions=conventions,
        equity_curve=equity_curve,
        trades=(trade,),
        positions=positions,
        ledger_trace=_ledger_trace(
            execution_ledger=final_account.ledger,
            corporate_action_ledger=final_account.corporate_action_ledger,
            settlement_ledger=final_settlement,
        ),
        metrics=metrics,
        execution_ledger_sha256=final_account.ledger.semantic_sha256,
        corporate_action_ledger_sha256=(final_account.corporate_action_ledger.semantic_sha256),
        settlement_ledger_sha256=final_settlement.semantic_sha256,
        account_projection_sha256=final_account.semantic_sha256,
    )


def _manifest(
    *,
    report: BacktestReport,
    trace: GoldenBacktestTrace,
    strategy: _GoldenBuyHoldStrategy,
    model: SimulatedMarketOrderModel,
    started_at: datetime,
    completed_at: datetime,
) -> BacktestRunManifest:
    replay_manifest_sha256 = _sha256(("golden-replay-manifest-v1", trace.replay.semantic_sha256))
    dataset_replay = DatasetReplayPin(
        dataset_manifest_sha256=_sha256(
            (
                "golden-raw-dataset-manifest-v1",
                tuple(event.semantic_sha256 for event in trace.market_events),
            )
        ),
        source_tape_sha256=trace.replay.tape_sha256,
        replay_run_id=replay_manifest_sha256,
        replay_manifest_sha256=replay_manifest_sha256,
        replay_input_sha256=_sha256(("golden-replay-input-v1", trace.replay.tape_sha256)),
        replay_semantic_sha256=trace.replay.semantic_sha256,
    )
    strategy_pin = StrategyRunPin(
        strategy_id=strategy.strategy_id,
        strategy_version=strategy.version,
        strategy_configuration_sha256=strategy.configuration_sha256,
        initial_state_sha256=trace.strategy_initial_state.semantic_sha256,
        strategy_replay_sha256=trace.strategy_semantic_sha256,
        final_state_sha256=trace.strategy_steps[-1].transition.state.semantic_sha256,
    )
    contracts = BacktestContractPins(
        strategy_replay_version=GOLDEN_CAUSAL_STRATEGY_RUNNER_VERSION,
        order_reducer_version=ORDER_REDUCER_CONTRACT_VERSION,
        simulated_broker_version=SIMULATED_BROKER_CONTRACT_VERSION,
        execution_ledger_version=LEDGER_REDUCER_CONTRACT_VERSION,
        account_projection_version=ACCOUNT_PROJECTION_CONTRACT_VERSION,
        corporate_action_ledger_version=CORPORATE_ACTION_LEDGER_CONTRACT_VERSION,
        settlement_ledger_version=SETTLEMENT_LEDGER_CONTRACT_VERSION,
        batch_risk_version=BATCH_RISK_CONTRACT_VERSION,
        account_coordinator_version="fixture-single-process-causal-orchestrator-v1",
        decimal_arithmetic_version=DECIMAL_ARITHMETIC_VERSION,
    )
    runtime = BacktestRuntimePin(
        source_revision="0" * 40,
        dirty_patch_sha256=_sha256("golden-runner-fixture-source-v1"),
        dependency_lock_sha256=_sha256("golden-runner-fixture-lock-v1"),
        container_image_sha256=NOT_APPLICABLE,
        schema_revision="fixture-only",
        python_version="3.12-fixture",
        numerical_runtime_version=DECIMAL_ARITHMETIC_VERSION,
        tzdata_version="2026a-fixture",
    )
    benchmark = BenchmarkPin(
        benchmark_id="SPY-total-return-golden-fixture",
        benchmark_version="2026-07-15-v1",
        content_sha256=_sha256(
            (
                "golden-total-return-benchmark-v1",
                trace.stock_split.semantic_sha256,
                trace.cash_dividend.semantic_sha256,
            )
        ),
        currency=_CURRENCY,
        total_return=True,
    )
    cost_model = SimulationModelPin(
        kind=SimulationModelKind.COST,
        model_id="golden-fixed-cost-model",
        model_version=model.model_version,
        configuration_sha256=_sha256(
            (
                "golden-cost-model-v1",
                model.fixed_fee,
                model.fee_per_share,
                model.currency,
            )
        ),
        currency=model.currency,
    )
    fill_model = SimulationModelPin(
        kind=SimulationModelKind.FILL,
        model_id=model.model_id,
        model_version=model.model_version,
        configuration_sha256=model.semantic_sha256,
        currency=model.currency,
    )
    execution_evidence_sha256 = _sha256(
        tuple(result.semantic_sha256 for result in trace.broker_results)
    )
    risk_evidence_sha256 = _sha256(
        tuple(decision.semantic_sha256 for decision in trace.risk_decisions)
    )
    return BacktestRunManifest.completed(
        report=report,
        dataset_replay=dataset_replay,
        strategy=strategy_pin,
        contracts=contracts,
        runtime=runtime,
        benchmark=benchmark,
        cost_model=cost_model,
        fill_model=fill_model,
        started_at=started_at,
        completed_at=completed_at,
        execution_evidence_sha256=execution_evidence_sha256,
        risk_evidence_sha256=risk_evidence_sha256,
        coordinator_evidence_sha256=_sha256(
            ("golden-causal-orchestration-v1", trace.semantic_sha256)
        ),
    )


def run_golden_backtest(
    *,
    future_correction_delay: timedelta = timedelta(seconds=2),
    generated_at: datetime | None = None,
    completed_at: datetime | None = None,
) -> GoldenBacktestRun:
    """Run the canonical raw-price buy/split/dividend/exit fixture.

    Economics are intentionally hand-checkable: contribute 1000; buy four at
    101.07 plus 0.54; split to eight; receive a 10 dividend; sell eight at
    54.93 less 0.58; finish with 1044.04 account cash.  Execution settlement is
    explicit T+1, while corporate-action cash remains in the account overlay.
    """

    market_events, watermarks = _market_tape(future_correction_delay)
    replay = replay_market_events(events=market_events, watermarks=watermarks)
    if len(replay.batches) != 4 or not all(batch.complete for batch in replay.batches):
        raise RuntimeError("golden replay did not seal four complete market batches")

    funding = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency=_CURRENCY,
        amount=Decimal("1000"),
        effective_at=_SESSION_OPEN,
        recorded_at=_SESSION_OPEN,
        external_reference="golden-initial-funding",
    )
    initial_settlement = _settlement_projection(
        order_states=(),
        funding=funding,
    )
    start_account = _account_projection(
        order_states=(),
        funding=funding,
        marks=(),
        valuation_at=_SESSION_OPEN,
    )

    broker_session = SimulatedBrokerSession(
        calendar_id="xnys-golden-fixture-calendar",
        calendar_version="2026.07.15-v1",
        calendar_sha256=_sha256("xnys-golden-fixture-calendar-2026-07-15"),
        session=ExchangeSession(
            venue="XNYS",
            session_label=date(2026, 7, 15),
            opens_at=_SESSION_OPEN,
            closes_at=_SESSION_CLOSE,
            kind=SessionKind.REGULAR,
        ),
    )
    risk_session = _batch_risk_session(broker_session)
    model = SimulatedMarketOrderModel(
        model_id="golden-next-raw-event-full-fill",
        model_version="1.0.0",
        activation_latency=timedelta(microseconds=1),
        half_spread_per_share=Decimal("0.05"),
        slippage_per_share=Decimal("0.02"),
        fixed_fee=Decimal("0.50"),
        fee_per_share=Decimal("0.01"),
        currency=_CURRENCY,
    )

    strategy = _GoldenBuyHoldStrategy()
    initialization = StrategyInitializationContext(
        started_at=replay.started_at,
        current_positions={},
    )
    initial_state = strategy.initialize(initialization)
    strategy_steps: list[GoldenStrategyStep] = []

    entry_decision_batch, entry_fill_batch, exit_decision_batch, exit_fill_batch = replay.batches
    entry_step = _strategy_step(
        strategy=strategy,
        state=initial_state,
        batch=entry_decision_batch,
        positions={},
    )
    strategy_steps.append(entry_step)
    if entry_step.target is None:
        raise RuntimeError("golden strategy omitted its entry target")
    entry_decision_mark = _mark(entry_decision_batch.events[0])
    entry_decision_account = _account_projection(
        order_states=(),
        funding=funding,
        marks=(entry_decision_mark,),
        valuation_at=entry_decision_batch.as_of,
    )
    entry_portfolio = portfolio_snapshot(
        as_of=entry_decision_batch.as_of,
        current_positions={},
        price_events=entry_decision_batch.events,
    )
    entry_intents, entry_risk_snapshot, entry_risk_decision = _authorize(
        target=entry_step.target,
        portfolio=entry_portfolio,
        account=entry_decision_account,
        settlement=initial_settlement,
        session=risk_session,
        version="golden-pre-entry-v1",
        daily_order_count=0,
    )
    entry_result = _submit(
        intent_batch=entry_intents,
        decision=entry_risk_decision,
        model=model,
        session=broker_session,
        replay=replay,
        attempt="entry",
    )
    buy_execution = _execution_event(entry_result)
    buy_instruction = _settlement_instruction(buy_execution, suffix="buy")
    buy_settlement = _settlement_projection(
        order_states=(entry_result.order_state,),
        funding=funding,
        instructions=(buy_instruction,),
    )
    buy_mark = _mark(entry_fill_batch.events[0])
    buy_account = _account_projection(
        order_states=(entry_result.order_state,),
        funding=funding,
        marks=(buy_mark,),
        valuation_at=entry_fill_batch.as_of,
    )

    fill_step = _strategy_step(
        strategy=strategy,
        state=entry_step.transition.state,
        batch=entry_fill_batch,
        positions={_INSTRUMENT_ID: Decimal("4")},
    )
    strategy_steps.append(fill_step)
    if fill_step.target is not None:
        raise RuntimeError("golden strategy emitted an unexpected fill-batch target")

    stock_split = create_stock_split(
        source_action_id="golden-spy-split",
        source_revision_id="golden-spy-split-r1",
        source_sha256=_sha256("golden-spy-split-2-for-1"),
        instrument_id=_INSTRUMENT_ID,
        symbol=_SYMBOL,
        numerator=Decimal("2"),
        denominator=Decimal("1"),
        entitled_quantity=Decimal("4"),
        effective_at=_ENTRY_FILL_TIME + timedelta(seconds=30),
        recorded_at=_ENTRY_FILL_TIME + timedelta(seconds=31),
    )
    cash_dividend = create_cash_dividend(
        source_action_id="golden-spy-dividend",
        source_revision_id="golden-spy-dividend-r1",
        source_sha256=_sha256("golden-spy-dividend-1.25"),
        instrument_id=_INSTRUMENT_ID,
        symbol=_SYMBOL,
        currency=_CURRENCY,
        amount_per_share=Decimal("1.25"),
        entitled_quantity=Decimal("8"),
        effective_at=_ENTRY_FILL_TIME + timedelta(minutes=1),
        payable_at=_ENTRY_FILL_TIME + timedelta(minutes=1, seconds=20),
        recorded_at=_ENTRY_FILL_TIME + timedelta(minutes=1, seconds=1),
    )
    dividend_payment = create_dividend_payment(
        cash_dividend,
        paid_at=cash_dividend.payable_at,
        recorded_at=cash_dividend.payable_at + timedelta(seconds=1),
        external_reference="golden-spy-dividend-payment",
    )
    action_mark = _mark(exit_decision_batch.events[0])
    action_account = _account_projection(
        order_states=(entry_result.order_state,),
        funding=funding,
        marks=(action_mark,),
        stock_splits=(stock_split,),
        cash_dividends=(cash_dividend,),
        dividend_payments=(dividend_payment,),
        valuation_at=exit_decision_batch.as_of,
    )

    exit_step = _strategy_step(
        strategy=strategy,
        state=fill_step.transition.state,
        batch=exit_decision_batch,
        positions={_INSTRUMENT_ID: Decimal("8")},
    )
    strategy_steps.append(exit_step)
    if exit_step.target is None:
        raise RuntimeError("golden strategy omitted its exit target")
    exit_portfolio = portfolio_snapshot(
        as_of=exit_decision_batch.as_of,
        current_positions={_INSTRUMENT_ID: (_SYMBOL, Decimal("8"))},
        price_events=exit_decision_batch.events,
    )
    exit_intents, exit_risk_snapshot, exit_risk_decision = _authorize(
        target=exit_step.target,
        portfolio=exit_portfolio,
        account=action_account,
        settlement=buy_settlement,
        session=risk_session,
        version="golden-pre-exit-v1",
        daily_order_count=1,
    )
    exit_result = _submit(
        intent_batch=exit_intents,
        decision=exit_risk_decision,
        model=model,
        session=broker_session,
        replay=replay,
        attempt="exit",
    )
    sell_execution = _execution_event(exit_result)
    sell_instruction = _settlement_instruction(sell_execution, suffix="sell")
    buy_confirmation = _settlement_confirmation(buy_instruction, suffix="buy")
    sell_confirmation = _settlement_confirmation(sell_instruction, suffix="sell")
    final_settlement = _settlement_projection(
        order_states=(entry_result.order_state, exit_result.order_state),
        funding=funding,
        instructions=(buy_instruction, sell_instruction),
        confirmations=(buy_confirmation, sell_confirmation),
    )
    if final_settlement.as_of is None:
        raise RuntimeError("golden final settlement lacks a causal as_of")
    final_mark = _mark(exit_fill_batch.events[0])
    final_account = _account_projection(
        order_states=(entry_result.order_state, exit_result.order_state),
        funding=funding,
        marks=(final_mark,),
        stock_splits=(stock_split,),
        cash_dividends=(cash_dividend,),
        dividend_payments=(dividend_payment,),
        valuation_at=final_settlement.as_of,
    )

    terminal_step = _strategy_step(
        strategy=strategy,
        state=exit_step.transition.state,
        batch=exit_fill_batch,
        positions={},
    )
    strategy_steps.append(terminal_step)
    if terminal_step.target is not None:
        raise RuntimeError("golden strategy emitted a post-exit target")

    trace = GoldenBacktestTrace(
        market_events=market_events,
        replay=replay,
        strategy_initial_state=initial_state,
        strategy_steps=tuple(strategy_steps),
        portfolio_snapshots=(entry_portfolio, exit_portfolio),
        intent_batches=(entry_intents, exit_intents),
        risk_snapshots=(entry_risk_snapshot, exit_risk_snapshot),
        risk_decisions=(entry_risk_decision, exit_risk_decision),
        broker_results=(entry_result, exit_result),
        funding=funding,
        stock_split=stock_split,
        cash_dividend=cash_dividend,
        dividend_payment=dividend_payment,
        settlement_instructions=(buy_instruction, sell_instruction),
        settlement_confirmations=(buy_confirmation, sell_confirmation),
        account_projections=(
            start_account,
            entry_decision_account,
            buy_account,
            action_account,
            final_account,
        ),
        settlement_projections=(initial_settlement, buy_settlement, final_settlement),
    )
    resolved_generated_at = generated_at or (final_settlement.as_of + timedelta(minutes=1))
    report = _report(
        funding_at=funding.recorded_at,
        buy_account=buy_account,
        action_account=action_account,
        final_account=final_account,
        final_settlement=final_settlement,
        buy_execution=buy_execution,
        sell_execution=sell_execution,
        generated_at=resolved_generated_at,
    )
    started_at = funding.recorded_at - timedelta(seconds=1)
    resolved_completed_at = completed_at or (resolved_generated_at + timedelta(minutes=1))
    manifest = _manifest(
        report=report,
        trace=trace,
        strategy=strategy,
        model=model,
        started_at=started_at,
        completed_at=resolved_completed_at,
    )
    return GoldenBacktestRun(
        report=report,
        result=manifest.result,
        manifest=manifest,
        trace=trace,
    )
