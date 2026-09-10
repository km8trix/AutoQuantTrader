"""Hand-specified E4/E5 input facts; no alternate event engine or report math."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

from packages.application.personal_inputs import canonical_events
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.accounting_contracts import (
    AccountingCommand,
    AccountingContext,
    AccountingState,
    ActivateCommitment,
    Commitment,
    ExecutionPolicy,
    InstallCommitment,
    SettlementCalendar,
)
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.decision import DecisionTrigger, DecisionTriggerKind
from packages.domain.engine_contracts import (
    BenchmarkPrice,
    DailyPrice,
    DailyRiskPolicy,
    DailyStrategyContext,
    DailyStrategyState,
    DailyStrategyTransition,
    EngineEvent,
    EngineInputs,
    EvaluationSpec,
    ObservationProvenance,
    RunSpec,
)
from packages.domain.ledger_reducer import CashFlowKind, create_cash_flow
from packages.domain.models import OrderIntent, Side
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    create_order_submission,
)
from packages.domain.personal_contracts import (
    CausalMark,
    ReductionPoint,
    VersionPin,
    content_digest,
)
from packages.domain.research_dataset import (
    ResearchCalendar,
    ResearchDataClass,
    ResearchSession,
    modeled_daily_availability,
)
from packages.domain.settlement_ledger import create_settlement_instruction

D = Decimal
SCOPE = (("US-ETF-SPY", "SPY"),)
CLASS = ResearchDataClass.SYNTHETIC_FIXTURE
DATES = tuple(date(2024, 6, day) for day in (3, 4, 5, 6, 7, 10, 11, 12))
POLICY = ExecutionPolicy(
    SettlementCalendar("explicit-synthetic-settlement", "1", DATES),
    model_id="synthetic-events-v1",
    slippage_bps=D(0),
    fee_per_share=D(0),
)


class NoTarget:
    """The financial oracle does not express any new strategy allocation."""

    def initialize(self, *, configuration, initial_snapshot):
        return DailyStrategyState()

    def on_decision(self, context: DailyStrategyContext) -> DailyStrategyTransition:
        state = DailyStrategyState(context.state.generation + 1, context.state.semantic_sha256)
        return DailyStrategyTransition(state, None, ("financial-oracle-no-new-target",))


def _opening() -> AccountingState:
    """Actually post funding, an eight-share buy and its explicit settlement."""
    port = PersonalAccounting()
    state = AccountingState("flow-oracle-account")
    at = datetime(2024, 6, 3, 13, 0, tzinfo=UTC)
    sequence = 0

    def context(approved=None):
        return AccountingContext(
            "opening-oracle",
            ReductionPoint(sequence, sequence, at, 2),
            at,
            f"opening-command-{sequence}",
            DATES[0],
            SCOPE,
            approved,
            "a" * 64 if approved else None,
        )

    def apply(payload, approved=None):
        nonlocal state, at, sequence
        at += timedelta(seconds=1)
        sequence += 1
        transition = port.advance(
            state=state,
            command=AccountingCommand(f"opening-command-{sequence}", payload),
            context=context(approved),
            policy=POLICY,
        )
        assert transition.disposition == "applied", transition.reasons
        state = transition.state
        return transition

    apply(
        create_cash_flow(
            kind=CashFlowKind.CONTRIBUTION,
            currency="USD",
            amount=D(1000),
            effective_at=at,
            recorded_at=at,
            external_reference="independent-opening-capital",
        )
    )
    source = port.project(state=state, context=context(), policy=POLICY).snapshot
    intent = OrderIntent(
        intent_id="opening-buy",
        intent_batch_id="opening-batch",
        target_id="opening-target",
        target_sha256="1" * 64,
        portfolio_snapshot_sha256="2" * 64,
        strategy_id="opening-oracle",
        strategy_version="1",
        strategy_configuration_sha256="3" * 64,
        decision_trigger=DecisionTrigger(DecisionTriggerKind.CLOCK, "opening-clock", "4" * 64, at),
        instrument_id="US-ETF-SPY",
        symbol="SPY",
        side=Side.BUY,
        quantity=D(8),
        reference_price=D(100),
        decision_event_time=at,
        expires_at=datetime(2024, 6, 3, 20, tzinfo=UTC),
        decision_event_id="opening-reference",
        reference_event_sha256="5" * 64,
        created_at=at,
    )
    submission = create_order_submission(
        intent=intent,
        risk_decision_id="opening-risk",
        submission_attempt_id="opening-attempt",
        submitted_at=at,
    )
    commitment = Commitment(
        "opening-commitment",
        intent.intent_id,
        submission.order_id,
        "US-ETF-SPY",
        "SPY",
        Side.BUY,
        D(8),
        D(0),
        D(8),
        D(800),
        D(0),
        D(100),
        D(0),
        DATES[0],
        DATES[0],
        sequence,
        at,
        datetime(2024, 6, 3, 20, tzinfo=UTC),
        "a" * 64,
        source.semantic_sha256,
    )
    apply(InstallCommitment(submission, commitment), source)
    apply(ActivateCommitment(commitment.commitment_id))
    accepted = state.broker_events[0]
    execution = BrokerOrderEvent(
        "opening-fill",
        submission.order_id,
        accepted.broker_order_id,
        2,
        at + timedelta(seconds=1),
        at + timedelta(seconds=1),
        BrokerOrderEventKind.EXECUTION,
        execution_id="opening-fill",
        execution_revision=1,
        quantity=D(8),
        price=D(100),
        fee=D(0),
    )
    instruction = create_settlement_instruction(
        execution,
        contractual_settlement_at=at + timedelta(seconds=3),
        recorded_at=at + timedelta(seconds=1),
        external_reference="explicit-oracle-same-day-opening-settlement",
    )
    apply(instruction)
    filled = apply(execution)
    apply(filled.due_events[0].command.payload)
    marked = apply(
        CausalMark("opening-mark", "US-ETF-SPY", "SPY", D(100), DATES[0], at, at, "b" * 64)
    )
    assert marked.snapshot.trade_date_cash == marked.snapshot.settled_cash == D(200)
    assert marked.snapshot.nav == D(1000)
    return state


def _event(identifier, economic, available, payload):
    return EngineEvent(
        identifier,
        economic,
        available,
        payload,
        ObservationProvenance(
            CLASS,
            "independent-flow-oracle/1",
            content_digest(payload),
            simulated_available_at=available,
            assumption_id="explicit-synthetic-event-clock/1",
        ),
    )


def flow_inputs(kind: str, pins: tuple[VersionPin, ...]) -> EngineInputs:
    if kind not in ("contribution", "withdrawal", "missing-mark"):
        raise ValueError("unknown flow oracle")
    contribution = kind != "withdrawal"
    amount = D(500) if contribution else D(200)
    terminal = D("132.5") if contribution else D("123.75")
    state = _opening()
    days = DATES[1:5]
    sessions = tuple(
        ResearchSession(
            "SYNTHETIC",
            day,
            datetime(day.year, day.month, day.day, 13, 30, tzinfo=UTC),
            datetime(day.year, day.month, day.day, 20, tzinfo=UTC),
            "regular",
        )
        for day in days
    )
    calendar = ResearchCalendar(
        "independent-flow-oracle-calendar", "1", "SYNTHETIC", "America/New_York", sessions
    )
    events = []
    baseline = sessions[0].opens_at
    baseline_mark = CausalMark(
        "baseline-mark",
        "US-ETF-SPY",
        "SPY",
        D(100),
        days[0],
        baseline,
        baseline,
        "c" * 64,
        basis="synthetic_boundary",
    )
    events.append(
        _event(
            "baseline-account-mark",
            baseline,
            baseline,
            AccountingCommand("baseline-mark", baseline_mark),
        )
    )
    events.append(
        _event(
            "baseline-benchmark",
            baseline,
            baseline,
            BenchmarkPrice("oracle-SPY-TR", D(100), "synthetic_total_return_units"),
        )
    )
    for index, session in enumerate(sessions[:3]):
        close = D(100) if index == 0 else terminal
        benchmark = D(100) if index == 0 else D(121)
        available = modeled_daily_availability(session.session_label)
        price = DailyPrice("US-ETF-SPY", "SPY", session.session_label, D(100), close, benchmark)
        events.append(_event(f"daily-{index}", session.closes_at, available, price))
        events.append(
            _event(
                f"benchmark-close-{index}",
                session.closes_at,
                available,
                BenchmarkPrice("oracle-SPY-TR", benchmark, "synthetic_total_return_units"),
            )
        )
    flow_at = sessions[1].opens_at + timedelta(minutes=30)
    mark_at = flow_at if kind != "missing-mark" else flow_at - timedelta(minutes=10)
    mark = CausalMark(
        "flow-mark",
        "US-ETF-SPY",
        "SPY",
        D("112.5"),
        days[1],
        mark_at,
        mark_at,
        "d" * 64,
        basis="synthetic_boundary",
    )
    events.append(
        _event("flow-account-mark", mark_at, mark_at, AccountingCommand("flow-mark", mark))
    )
    events.append(
        _event(
            "flow-benchmark",
            flow_at,
            flow_at,
            BenchmarkPrice("oracle-SPY-TR", D(110), "synthetic_total_return_units"),
        )
    )
    flow = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION if contribution else CashFlowKind.WITHDRAWAL,
        currency="USD",
        amount=amount,
        effective_at=flow_at,
        recorded_at=flow_at,
        external_reference="independent-event-flow",
    )
    events.append(
        _event("external-flow", flow_at, flow_at, AccountingCommand("external-flow", flow))
    )
    events[-1] = replace(events[-1], predecessor_ids=("flow-account-mark", "flow-benchmark"))
    frozen = canonical_events(tuple(events))
    digest = content_digest(("E4-E5-hand-specification", kind, frozen, state))
    spec = RunSpec(
        account_id=state.account_id,
        dataset_id="oracle-" + digest,
        dataset_sha256=digest,
        events_sha256=content_digest(frozen),
        data_class=CLASS,
        availability_mode="modeled",
        instruments=SCOPE,
        calendar=calendar,
        strategy=VersionPin(
            "strategy", "no-target-financial-oracle/1", content_digest("NoTarget/1")
        ),
        strategy_configuration=ReferenceConfiguration(),
        evaluation=EvaluationSpec("E4-E5", (), days[:3], "hand-calculated-synthetic-no-holdout"),
        execution_policy=POLICY,
        risk_policy=replace(
            DailyRiskPolicy(),
            policy_id="independent-economic-oracle/1",
            policy_scope="synthetic_oracle",
            fee_per_share=D(0),
        ),
        pins=pins,
        initial_state_sha256=state.semantic_sha256,
        initial_cash=D(0),
        limitations=(
            "independent-economic-oracle-not-strategy-qualification",
            "explicit-synthetic-opening-settlement",
        ),
    )
    return EngineInputs(spec, frozen, state)
