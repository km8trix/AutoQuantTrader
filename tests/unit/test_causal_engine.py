from __future__ import annotations

from dataclasses import replace
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from zoneinfo import ZoneInfo

import pytest

from packages.application.causal_engine import _SimulatedRequests, _Stop, run_causal_engine
from packages.application.personal_inputs import canonical_events, synthetic_engine_inputs
from packages.application.reference_strategy import ReferenceStrategy
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.accounting_contracts import (
    AccountingCommand,
    AccountingContext,
    AccountingState,
    AccountingTransition,
    ControlCommand,
    DueAccountingEvent,
    ExecutionObservation,
    ExecutionPolicy,
    InstallCommitment,
    SettlementCalendar,
)
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.engine_contracts import (
    BenchmarkPrice,
    DailyPrice,
    DailyStrategyContext,
    DailyStrategyTransition,
    EngineEvent,
    EngineInputs,
    EnginePayload,
    EvaluationSpec,
    ObservationProvenance,
    ScheduleSignal,
)
from packages.domain.ledger_reducer import CashFlowKind, create_cash_flow
from packages.domain.personal_contracts import CausalMark, VersionPin, content_digest
from packages.domain.report_contracts import EngineResult
from packages.domain.research_dataset import (
    ResearchCalendar,
    ResearchSession,
    modeled_daily_availability,
)

D = Decimal
PINS = tuple(
    VersionPin(name, "test/1", "a" * 64)
    for name in sorted(
        (
            "engine",
            "source",
            "dependency_lock",
            "tzdata",
            "availability",
            "actions",
            "numeric",
            "benchmark",
            "report",
            "dirty_patch",
        )
    )
)


def small_inputs(*, count: int = 6, warmup: int = 1, kind: str = "buy_hold") -> EngineInputs:
    return synthetic_engine_inputs(
        fixture="flat",
        pins=PINS,
        session_count=count,
        warmup_count=warmup,
        configuration=ReferenceConfiguration(kind=kind, lookback=2),
    )


def with_events(inputs: EngineInputs, events: tuple[EngineEvent, ...]) -> EngineInputs:
    canonical = canonical_events(events)
    return replace(
        inputs, events=events, spec=replace(inputs.spec, events_sha256=content_digest(canonical))
    )


def event(
    inputs: EngineInputs,
    identity: str,
    payload: EnginePayload,
    economic: datetime,
    knowledge: datetime,
    predecessors: tuple[str, ...] = (),
) -> EngineEvent:
    return EngineEvent(
        identity,
        economic,
        knowledge,
        payload,
        ObservationProvenance(
            inputs.spec.data_class,
            "independent-unit-fixture",
            content_digest(payload),
            simulated_available_at=knowledge,
            assumption_id="synthetic-unit-timing/1",
        ),
        predecessors,
    )


def run(inputs: EngineInputs, strategy: ReferenceStrategy | None = None) -> EngineResult:
    return run_causal_engine(
        inputs, accounting=PersonalAccounting(), strategy=strategy or ReferenceStrategy()
    )


class RecordingStrategy(ReferenceStrategy):
    def __init__(self) -> None:
        super().__init__()
        self.contexts: list[DailyStrategyContext] = []

    def on_decision(self, context: DailyStrategyContext) -> DailyStrategyTransition:
        self.contexts.append(context)
        return super().on_decision(context)


def test_actual_account_feedback_funding_fill_and_final_effective_heads() -> None:
    inputs = small_inputs()
    strategy = RecordingStrategy()
    result = run(inputs, strategy)
    assert result.status == "completed", result.reasons
    assert result.final_snapshot.trade_date_cash == D("7598.56")
    assert result.final_snapshot.nav == D("9998.56")
    assert result.final_snapshot.positions[0].quantity == D(24)
    assert len(result.executions) == len(result.final_state.submissions) == 1
    assert result.executions[0].price == D("100.05")
    assert result.executions[0].fee == D(".24")
    assert len(result.flows) == 1 and result.flows[0].origin == "initial_capital"
    assert result.valuations[0].snapshot.nav == 0 and not result.valuations[0].scored
    assert result.valuations[1].snapshot.nav == 10000 and "baseline" in result.valuations[1].roles
    assert result.valuations[-1].roles == ("daily_close", "terminal")
    assert result.final_snapshot == result.valuations[-1].snapshot
    assert len(strategy.contexts) == len(inputs.spec.evaluation.scored_sessions)
    assert not strategy.contexts[0].account.positions
    assert strategy.contexts[1].account.positions[0].quantity == D(24)
    assert strategy.contexts[1].account.available_cash < D(10000)
    assert result.executions[0].economic_at > result.final_state.commitments[0].activated_at
    sequences = [item.snapshot.point.reduction_sequence for item in result.valuations]
    assert sequences == sorted(set(sequences))


def test_flat_sma_equality_keeps_cash_and_never_creates_a_commitment() -> None:
    result = run(small_inputs(kind="trend_sma"))
    assert result.status == "completed"
    assert result.final_snapshot.nav == D(10000)
    assert result.final_state.submissions == () and result.executions == ()


def test_permutations_and_exact_duplicates_have_identical_results() -> None:
    inputs = small_inputs()
    baseline = run(inputs)
    shuffled = replace(inputs, events=(*reversed(inputs.events), inputs.events[0]))
    assert run(shuffled) == baseline


def test_future_price_and_raw_aggregate_perturbation_preserves_prefix_after_settlement() -> None:
    inputs = small_inputs(count=8)
    original = run(inputs)
    last = inputs.spec.evaluation.scored_sessions[-1]
    changed: list[EngineEvent] = []
    for row in inputs.events:
        payload = row.payload
        if isinstance(payload, DailyPrice) and payload.session == last:
            payload = replace(payload, close_price=D(150), adjusted_close=D(150))
        changed.append(
            replace(
                row,
                payload=payload,
                provenance=replace(
                    row.provenance, normalized_sha256=content_digest(payload), raw_sha256="f" * 64
                ),
            )
        )
    modified = with_events(inputs, tuple(changed))
    modified = replace(
        modified,
        spec=replace(modified.spec, dataset_sha256="e" * 64, dataset_id="perturbed-future-dataset"),
    )
    replay = run(modified)
    assert replay.status == "completed"
    frontier = modeled_daily_availability(last)

    def prefix(result: EngineResult) -> list[tuple[object, ...]]:
        return [
            (row.kind, row.point, row.causal_content_sha256)
            for row in result.trace
            if row.point.knowledge_at < frontier
        ]

    assert any(
        row.kind == "ExecutionSettlementConfirmation"
        for row in original.trace
        if row.point.knowledge_at < frontier
    )
    assert original.run_id != replay.run_id
    assert prefix(original) == prefix(replay)


@pytest.mark.parametrize("offset,decides", [(-1, True), (0, False), (1, False)])
def test_delayed_publication_strictly_before_cutoff(offset: int, decides: bool) -> None:
    inputs = small_inputs()
    source = inputs.spec.evaluation.scored_sessions[0]
    next_day = inputs.spec.evaluation.scored_sessions[1]
    cutoff = datetime.combine(next_day, time(9), ZoneInfo("America/New_York")).astimezone(UTC)
    altered: list[EngineEvent] = []
    for row in inputs.events:
        if isinstance(row.payload, DailyPrice) and row.payload.session == source:
            at = cutoff + timedelta(microseconds=offset)
            row = replace(
                row, knowledge_at=at, provenance=replace(row.provenance, simulated_available_at=at)
            )
        altered.append(row)
    strategy = RecordingStrategy()
    result = run(with_events(inputs, tuple(altered)), strategy)
    assert result.status == "completed"
    assert any(c.trigger.source_session == source for c in strategy.contexts) is decides
    if not decides:
        assert result.final_state.halted


def test_warmup_baseline_not_available_before_first_open_rejects_without_funding() -> None:
    inputs = small_inputs()
    warm = inputs.spec.evaluation.warmup_sessions[-1]
    first_open = inputs.spec.calendar.sessions[1].opens_at
    rows = tuple(
        replace(
            row,
            knowledge_at=first_open,
            provenance=replace(row.provenance, simulated_available_at=first_open),
        )
        if isinstance(row.payload, DailyPrice) and row.payload.session == warm
        else row
        for row in inputs.events
    )
    result = run(with_events(inputs, rows))
    assert result.status == "rejected"
    assert result.reasons == ("WARMUP_BASELINE_NOT_KNOWN_BEFORE_SCORED_OPEN",)
    assert not result.final_state.cash_flows


def test_missing_close_preserves_estimate_but_does_not_reuse_open_as_close() -> None:
    inputs = small_inputs()
    missing = inputs.spec.evaluation.scored_sessions[2]
    rows = tuple(
        row
        for row in inputs.events
        if not (isinstance(row.payload, DailyPrice) and row.payload.session == missing)
    )
    result = run(with_events(inputs, rows))
    valuation = next(
        row for row in result.valuations if row.session == missing and "daily_close" in row.roles
    )
    assert valuation.snapshot.nav is None
    assert valuation.snapshot.last_known_nav == D("9998.56")
    assert valuation.snapshot.valuation_reasons
    assert result.final_state.halted


def test_missing_execution_open_halts_and_retains_approved_capacity() -> None:
    inputs = small_inputs()
    missing = inputs.spec.evaluation.scored_sessions[1]
    rows = tuple(
        row
        for row in inputs.events
        if not (isinstance(row.payload, ExecutionObservation) and row.payload.session == missing)
    )
    result = run(with_events(inputs, rows))
    assert result.status == "completed" and result.final_state.halted
    assert not result.executions
    assert result.final_snapshot.buy_reserve == D("2424.24")
    assert result.final_state.commitments[0].state != "terminal"


def test_partial_model_fill_transfers_only_filled_reserve_then_day_expiry_releases_remainder() -> (
    None
):
    inputs = small_inputs()
    fill_day = inputs.spec.evaluation.scored_sessions[1]
    rows = []
    for row in inputs.events:
        if isinstance(row.payload, ExecutionObservation) and row.payload.session == fill_day:
            payload = replace(row.payload, quantity_budget=D(4))
            row = replace(
                row,
                payload=payload,
                provenance=replace(row.provenance, normalized_sha256=content_digest(payload)),
            )
        rows.append(row)
    result = run(with_events(inputs, tuple(rows)))
    assert result.status == "completed"
    assert result.final_snapshot.positions[0].quantity == 4
    assert result.final_snapshot.trade_date_cash == D("9599.76")
    assert result.final_snapshot.nav == D("9999.76")
    assert result.final_snapshot.buy_reserve == 0
    reason = result.final_state.commitments[0].terminal_reason
    assert reason is not None and reason.startswith("day_expired:")


def test_model_gap_beyond_hold_never_spends_excess_capacity() -> None:
    inputs = small_inputs()
    fill_day = inputs.spec.evaluation.scored_sessions[1]
    rows = []
    for row in inputs.events:
        if isinstance(row.payload, ExecutionObservation) and row.payload.session == fill_day:
            payload = replace(row.payload, price=D(102))
            row = replace(
                row,
                payload=payload,
                provenance=replace(row.provenance, normalized_sha256=content_digest(payload)),
            )
        rows.append(row)
    result = run(with_events(inputs, tuple(rows)))
    assert result.status == "completed" and result.final_state.halted
    assert result.executions == ()
    assert result.final_snapshot.available_cash == D("7575.76")
    assert result.final_snapshot.buy_reserve == D("2424.24")


def test_timer_does_not_reopen_consumed_daily_session() -> None:
    inputs = small_inputs()
    source = inputs.spec.evaluation.scored_sessions[0]
    at = modeled_daily_availability(source)
    timer = event(inputs, "timer", ScheduleSignal("fixture", source, "timer"), at, at)
    strategy = RecordingStrategy()
    result = run(with_events(inputs, (*inputs.events, timer)), strategy)
    assert result.status == "completed"
    assert sum(context.trigger.source_session == source for context in strategy.contexts) == 1
    assert len(result.final_state.submissions) == 1


def test_revision_admitted_after_predecessor_changes_only_later_callbacks() -> None:
    inputs = small_inputs()
    source = inputs.spec.evaluation.scored_sessions[0]
    original = next(
        row
        for row in inputs.events
        if isinstance(row.payload, DailyPrice) and row.payload.session == source
    )
    assert isinstance(original.payload, DailyPrice)
    at = original.knowledge_at + timedelta(seconds=1)
    revised = event(
        inputs,
        "revision-2",
        replace(
            original.payload,
            close_price=D(101),
            adjusted_close=D(101),
            revision=2,
            predecessor_revision_id=original.event_id,
        ),
        original.economic_at,
        at,
        (original.event_id,),
    )
    strategy = RecordingStrategy()
    result = run(with_events(inputs, (*inputs.events, revised)), strategy)
    assert result.status == "completed"
    first = dict(strategy.contexts[0].history)[source]
    later = dict(strategy.contexts[1].history)[source]
    assert first[0][1] == 100 and later[0][1] == 101
    assert sum(c.trigger.source_session == source for c in strategy.contexts) == 1


def test_conflicting_identity_and_cycle_fail_closed() -> None:
    inputs = small_inputs()
    first = inputs.events[0]
    conflict = replace(first, provenance=replace(first.provenance, raw_sha256="e" * 64))
    assert run(replace(inputs, events=(*inputs.events, conflict))).reasons == (
        "CONFLICTING_EVENT_ID",
    )
    source = inputs.spec.evaluation.scored_sessions[0]
    at = modeled_daily_availability(source)
    one = event(inputs, "cycle1", ScheduleSignal("fixture", source, "timer"), at, at, ("cycle2",))
    two = event(inputs, "cycle2", ScheduleSignal("fixture", source, "timer"), at, at, ("cycle1",))
    assert run(with_events(inputs, (*inputs.events, one, two))).reasons == (
        "CYCLIC_OR_UNAVAILABLE_PREDECESSOR",
    )


def test_close_or_same_frontier_observation_cannot_impersonate_next_open() -> None:
    inputs = small_inputs()
    original = next(row for row in inputs.events if isinstance(row.payload, ExecutionObservation))
    assert isinstance(original.payload, ExecutionObservation)
    at = modeled_daily_availability(original.payload.session)
    payload = replace(original.payload, economic_at=at, knowledge_at=at)
    bad = replace(
        original,
        economic_at=at,
        knowledge_at=at,
        payload=payload,
        provenance=replace(original.provenance, normalized_sha256=content_digest(payload)),
    )
    result = run(
        with_events(inputs, tuple(bad if row == original else row for row in inputs.events))
    )
    assert result.reasons == ("EXECUTION_REQUIRES_EXACT_REGULAR_OPEN",)


def test_cancellation_and_event_output_time_budgets_return_bounded_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = small_inputs()
    assert (
        run_causal_engine(
            inputs,
            accounting=PersonalAccounting(),
            strategy=ReferenceStrategy(),
            stop_requested=lambda: True,
        ).status
        == "cancelled"
    )
    assert run(replace(inputs, spec=replace(inputs.spec, max_events=1))).reasons == (
        "EVENT_BUDGET_EXCEEDED",
    )
    assert run(replace(inputs, spec=replace(inputs.spec, max_output_bytes=1))).reasons == (
        "OUTPUT_BUDGET_EXCEEDED",
    )
    clock = iter((0.0, 99999.0))
    monkeypatch.setattr("packages.application.causal_engine.monotonic", lambda: next(clock))
    assert run(inputs).reasons == ("WALL_TIME_BUDGET_EXCEEDED",)


def test_request_budget_20_21_and_10_11_with_exact_60_second_release() -> None:
    requests = _SimulatedRequests()
    at = datetime(2025, 2, 3, tzinfo=UTC)
    for _ in range(10):
        requests.record(at, low_priority=True)
    assert not requests.permits(at, 1, low_priority=True)
    for _ in range(10):
        requests.record(at, low_priority=False)
    assert not requests.permits(at, 1, low_priority=False)
    with pytest.raises(_Stop):
        requests.record(at, low_priority=False)
    assert not requests.permits(at + timedelta(seconds=59), 1, low_priority=True)
    assert requests.permits(at + timedelta(seconds=60), 10, low_priority=True)


def calendar_inputs(days: tuple[date, ...], *, half_day: date | None = None) -> EngineInputs:
    base = small_inputs(count=len(days) - 1, warmup=0)
    zone = ZoneInfo("America/New_York")
    sessions = tuple(
        ResearchSession(
            "XNYS",
            day,
            datetime.combine(day, time(9, 30), zone).astimezone(UTC),
            datetime.combine(day, time(13 if day == half_day else 16), zone).astimezone(UTC),
            "half_day" if day == half_day else "regular",
        )
        for day in days
    )
    calendar = ResearchCalendar(
        "explicit-calendar-fixture", "1", "XNYS", "America/New_York", sessions
    )
    rows: list[EngineEvent] = []
    instrument, symbol = base.spec.instruments[0]
    for session in sessions[:-1]:
        daily = DailyPrice(instrument, symbol, session.session_label, D(100), D(100), D(100))
        rows.append(
            event(
                base,
                f"close-{session.session_label}",
                daily,
                session.closes_at,
                modeled_daily_availability(session.session_label),
            )
        )
        observation = ExecutionObservation(
            f"open-{session.session_label}",
            instrument,
            symbol,
            session.session_label,
            D(100),
            session.opens_at,
            session.opens_at,
            "next-regular-open-proxy-v1",
            "c" * 64,
        )
        rows.append(
            EngineEvent(
                observation.observation_id,
                session.opens_at,
                session.opens_at,
                observation,
                ObservationProvenance(
                    base.spec.data_class,
                    "calendar-fixture",
                    content_digest(observation),
                    simulated_available_at=session.opens_at,
                    assumption_id="explicit-open-proxy",
                ),
            )
        )
    spec = replace(
        base.spec,
        calendar=calendar,
        evaluation=EvaluationSpec("calendar", (), days[:-1], "synthetic-calendar"),
        execution_policy=replace(
            base.spec.execution_policy,
            settlement_calendar=SettlementCalendar("settlement-fixture", "1", days),
        ),
    )
    return with_events(replace(base, spec=spec), tuple(rows))


@pytest.mark.parametrize(
    "days,half_day,utc_hour",
    [
        ((date(2025, 3, 7), date(2025, 3, 10), date(2025, 3, 11), date(2025, 3, 12)), None, 13),
        (
            (date(2025, 11, 26), date(2025, 11, 28), date(2025, 12, 1), date(2025, 12, 2)),
            date(2025, 11, 28),
            14,
        ),
    ],
)
def test_explicit_calendar_controls_dst_half_days_and_holiday_gap(
    days: tuple[date, ...], half_day: date | None, utc_hour: int
) -> None:
    inputs = calendar_inputs(days, half_day=half_day)
    result = run(inputs)
    assert result.status == "completed", result.reasons
    assert result.executions[0].economic_at == datetime.combine(days[1], time(utc_hour, 30), UTC)
    if half_day:
        close = next(row for row in result.valuations if row.session == half_day)
        assert close.economic_at.hour == 18
        assert close.snapshot.point.knowledge_at.hour == 1


class RejectSecondInstall(PersonalAccounting):
    def advance(
        self,
        *,
        state: AccountingState,
        command: AccountingCommand,
        context: AccountingContext,
        policy: ExecutionPolicy,
    ) -> AccountingTransition:
        if isinstance(command.payload, InstallCommitment) and state.submissions:
            return replace(
                self.project(state=state, context=context, policy=policy),
                disposition="rejected",
                reasons=("injected-second-install-rejection",),
            )
        return super().advance(state=state, command=command, context=context, policy=policy)


def test_whole_batch_install_rolls_back_when_second_member_rejects() -> None:
    inputs = small_inputs()
    rows = list(inputs.events)
    for row in inputs.events:
        if isinstance(row.payload, (DailyPrice, ExecutionObservation)):
            payload = replace(row.payload, instrument_id="US-ETF-QQQ", symbol="QQQ")
            if isinstance(payload, ExecutionObservation):
                payload = replace(payload, observation_id=row.event_id + "-qqq")
            rows.append(
                replace(
                    row,
                    event_id=row.event_id + "-qqq",
                    payload=payload,
                    provenance=replace(row.provenance, normalized_sha256=content_digest(payload)),
                )
            )
    spec = replace(
        inputs.spec,
        instruments=tuple(sorted((*inputs.spec.instruments, ("US-ETF-QQQ", "QQQ")))),
        strategy_configuration=ReferenceConfiguration(allocation=D(".2375")),
    )
    inputs = with_events(replace(inputs, spec=spec), tuple(rows))
    result = run_causal_engine(
        inputs, accounting=RejectSecondInstall(), strategy=ReferenceStrategy()
    )
    assert result.status == "completed"
    assert any(row.kind == "batch_install_rolled_back" for row in result.trace)
    assert result.final_state.submissions == () and result.final_state.commitments == ()
    assert result.final_snapshot.available_cash == D(10000)


@pytest.mark.parametrize("exact", [True, False])
def test_flow_boundaries_require_exact_causal_marks_and_adjacent_pair(exact: bool) -> None:
    inputs = small_inputs()
    session = inputs.spec.evaluation.scored_sessions[2]
    at = next(
        s.opens_at for s in inputs.spec.calendar.sessions if s.session_label == session
    ) + timedelta(minutes=30)
    instrument, symbol = inputs.spec.instruments[0]
    mark_at = at if exact else at - timedelta(minutes=10)
    mark = CausalMark(
        "flow-mark",
        instrument,
        symbol,
        D(100),
        session,
        mark_at,
        mark_at,
        "d" * 64,
        basis="synthetic_boundary",
    )
    mark_event = event(
        inputs, "flow-mark-event", AccountingCommand("flow-mark", mark), mark_at, mark_at
    )
    benchmark = event(
        inputs,
        "flow-benchmark",
        BenchmarkPrice("SPY-total-return-units/1", D(100), "synthetic_total_return_units"),
        at,
        at,
    )
    flow = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=D(500),
        effective_at=at,
        recorded_at=at,
        external_reference="unit-flow",
    )
    flow_event = event(
        inputs,
        "external-flow",
        AccountingCommand("external-flow", flow),
        at,
        at,
        (mark_event.event_id, benchmark.event_id),
    )
    result = run(with_events(inputs, (*inputs.events, mark_event, benchmark, flow_event)))
    assert result.status == "completed"
    rows = [row for row in result.valuations if row.flow_id == flow.cash_flow_id]
    assert len(rows) == 2
    assert rows[0].paired_row_id == rows[1].row_id and rows[1].paired_row_id == rows[0].row_id
    assert rows[0].snapshot.point.frontier_sequence == rows[1].snapshot.point.frontier_sequence
    assert rows[0].snapshot.marks == rows[1].snapshot.marks
    if exact:
        assert [row.snapshot.nav for row in rows] == [D("9998.56"), D("10498.56")]
    else:
        assert all(row.snapshot.nav is None and row.snapshot.valuation_reasons for row in rows)
        assert [row.snapshot.last_known_nav for row in rows] == [D("9998.56"), D("10498.56")]


class ImmediateDueControl(PersonalAccounting):
    def advance(
        self,
        *,
        state: AccountingState,
        command: AccountingCommand,
        context: AccountingContext,
        policy: ExecutionPolicy,
    ) -> AccountingTransition:
        result = super().advance(state=state, command=command, context=context, policy=policy)
        if (
            isinstance(command.payload, ExecutionObservation)
            and result.executions
            and not state.halted
        ):
            due_id = "same-frontier-control"
            due = DueAccountingEvent(
                due_id,
                command.command_id,
                context.point.knowledge_at,
                AccountingCommand(due_id, ControlCommand(True, "unit-due-control")),
                policy.semantic_sha256,
            )
            return replace(result, due_events=(*result.due_events, due))
        return result


def test_due_commands_share_frontier_and_post_before_next_callback() -> None:
    strategy = RecordingStrategy()
    result = run_causal_engine(small_inputs(), accounting=ImmediateDueControl(), strategy=strategy)
    assert result.status == "completed", result.reasons
    due = next(row for row in result.trace if row.event_id == "same-frontier-control")
    prior = next(
        row
        for row in result.trace
        if row.kind == "ExecutionObservation" and row.point.knowledge_at == due.point.knowledge_at
    )
    assert prior.point.frontier_sequence == due.point.frontier_sequence
    assert prior.point.reduction_sequence < due.point.reduction_sequence
    assert strategy.contexts[1].account.halted


def test_declared_source_sequence_overrides_lexical_and_economic_tie_breaks() -> None:
    inputs = small_inputs()
    source = inputs.spec.evaluation.scored_sessions[0]
    at = modeled_daily_availability(source) + timedelta(minutes=1)
    first = event(
        inputs, "zzz-first", AccountingCommand("zzz-first", ControlCommand(True, "first")), at, at
    )
    second = event(
        inputs,
        "aaa-second",
        AccountingCommand("aaa-second", ControlCommand(False, "second")),
        at - timedelta(seconds=1),
        at,
    )
    first = replace(first, sequence_scope="control-fixture", source_sequence=1)
    second = replace(second, sequence_scope="control-fixture", source_sequence=2)
    result = run(with_events(inputs, (*inputs.events, second, first)))
    assert result.status == "completed"
    assert not result.final_state.halted
    assert [
        row.event_id for row in result.trace if row.event_id in (first.event_id, second.event_id)
    ] == [first.event_id, second.event_id]
