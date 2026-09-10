"""Actual W2 engine boundaries for preregistered descriptive synthetic trials.

This fixture exercises the same engine once per prepared input. It does not own
a durable scheduler, certify data access history or qualify a strategy.
"""

from dataclasses import replace
from decimal import Decimal

import pytest

from packages.application.causal_engine import run_causal_engine
from packages.application.evaluation_inputs import prepare_trial_inputs
from packages.application.reference_strategy import ReferenceStrategy
from packages.application.run_report import build_run_report
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.accounting_contracts import AccountingState
from packages.domain.engine_contracts import DailyPrice, ScheduleSignal
from packages.domain.personal_contracts import content_digest
from packages.domain.personal_evaluation import (
    EvaluationError,
    TrialOutcome,
    compare_trials,
    expand_trials,
)
from packages.domain.report_contracts import ReportConventions
from packages.domain.research_dataset import modeled_daily_availability
from tests.unit.test_causal_engine import event
from tests.unit.test_personal_evaluation import fits_for, protocol_for, revise_source, source_inputs

D = Decimal


def prepare(source, *, segment="validation", candidate="buy_hold", cost="base_1x"):
    protocol = protocol_for(source)
    fits = fits_for(protocol, source)
    trials = expand_trials(protocol, fits=fits)
    trial = next(
        t
        for t in trials
        if (t.segment, t.candidate_id, t.cost.scenario_id) == (segment, candidate, cost)
    )
    fit = next(f for f in fits if f.semantic_sha256 == trial.fit_sha256)
    return (
        protocol,
        trials,
        fit,
        prepare_trial_inputs(protocol=protocol, trial=trial, fit=fit, source=source),
    )


def run(inputs):
    return run_causal_engine(
        inputs,
        accounting=PersonalAccounting(),
        strategy=ReferenceStrategy(
            reserve_fraction=inputs.spec.risk_policy.adverse_reserve_fraction,
            fee_per_share=inputs.spec.execution_policy.fee_per_share,
        ),
    )


def causal_prefix(result, before):
    return tuple(
        (row.kind, row.point, row.causal_content_sha256)
        for row in result.trace
        if row.point.knowledge_at < before
    )


def test_all_declared_trials_use_actual_engine_costs_and_independent_resets():
    source = source_inputs()
    protocol = protocol_for(source)
    fits = fits_for(protocol, source)
    trials = expand_trials(protocol, fits=fits)  # Complete inventory exists before the first run.
    outcomes = []
    expected = {
        "base_1x": D("9998.56"),
        "base_2x": D("9997.12"),
        "base_3x": D("9995.68"),
        "adverse": D("9994.72"),
    }
    for trial in trials:
        fit = next(f for f in fits if f.semantic_sha256 == trial.fit_sha256)
        prepared = prepare_trial_inputs(protocol=protocol, trial=trial, fit=fit, source=source)
        assert prepared.initial_state == AccountingState(source.spec.account_id)
        assert prepared.spec.calendar is source.spec.calendar
        assert (
            prepared.spec.execution_policy.settlement_calendar
            is source.spec.execution_policy.settlement_calendar
        )
        assert all(row in source.events for row in prepared.events)
        assert prepared.spec.risk_policy.fee_per_share == trial.cost.fee_per_share
        assert (
            dict((p.name, p.sha256) for p in prepared.spec.pins)["evaluation_trial"]
            == trial.semantic_sha256
        )
        result = run(prepared)
        assert result.status == "completed", result.reasons
        baseline = next(v for v in result.valuations if "baseline" in v.roles)
        assert baseline.snapshot.nav == 10000 and baseline.snapshot.positions == ()
        assert baseline.snapshot.fees == 0
        assert all(
            e.economic_at.date() >= prepared.spec.evaluation.scored_sessions[0]
            for e in result.executions
        )
        if trial.candidate_id == "buy_hold":
            assert result.final_snapshot.nav == expected[trial.cost.scenario_id]
            assert len(result.executions) == 1
            fill = result.executions[0]
            assert fill.price == D(100) * (1 + trial.cost.slippage_bps / 10000)
            assert fill.fee == fill.quantity * trial.cost.fee_per_share
        else:
            assert result.executions == () and result.final_snapshot.nav == 10000
        report = build_run_report(result, ReportConventions())
        assert report.status == "completed", report.reasons
        outcomes.append(
            TrialOutcome(trial.trial_id, f"attempt-{trial.ordinal}", "completed", report)
        )
    comparison = compare_trials(protocol, trials=trials, outcomes=tuple(outcomes))
    assert len(comparison.rows) == 24 and all(row.metrics for row in comparison.rows)
    assert comparison.selected_candidate_id is None and comparison.eligibility == "not_assessed"
    assert source.initial_state == AccountingState(source.spec.account_id)


@pytest.mark.parametrize(
    "segment,future_segment", (("train", "validation"), ("validation", "test"))
)
def test_future_partition_changes_cannot_change_fit_or_earlier_causal_execution(
    segment, future_segment
):
    source = source_inputs("regime")
    protocol, _, fit, prepared = prepare(source, segment=segment, candidate="trend_sma")
    future = protocol.folds[0].window(future_segment).scored_sessions[0]

    def mutate(row):
        if isinstance(row.payload, DailyPrice) and row.payload.session >= future:
            payload = replace(row.payload, close_price=D(900), adjusted_close=D(900))
            return replace(
                row,
                payload=payload,
                provenance=replace(row.provenance, normalized_sha256=content_digest(payload)),
            )
        return row

    changed = revise_source(source, mutate)
    _, _, changed_fit, changed_prepared = prepare(changed, segment=segment, candidate="trend_sma")
    assert fit == changed_fit and fit.fitted_parameters == ()
    assert prepared.events == changed_prepared.events
    original, replay = run(prepared), run(changed_prepared)
    assert original.status == replay.status == "completed"
    assert original.run_id != replay.run_id  # Whole-dataset identity is intentionally honest.
    assert causal_prefix(original, modeled_daily_availability(future)) == causal_prefix(
        replay, modeled_daily_availability(future)
    )
    assert original.final_snapshot.nav == replay.final_snapshot.nav
    assert original.final_strategy_state.values == replay.final_strategy_state.values


def test_later_observation_inside_scored_window_preserves_actual_engine_prefix():
    source = source_inputs("regime")
    protocol, _, fit, prepared = prepare(source, candidate="trend_sma")
    last = protocol.folds[0].window("validation").scored_sessions[-1]

    def mutate(row):
        if isinstance(row.payload, DailyPrice) and row.payload.session == last:
            payload = replace(row.payload, close_price=D(200), adjusted_close=D(200))
            return replace(
                row,
                payload=payload,
                provenance=replace(row.provenance, normalized_sha256=content_digest(payload)),
            )
        return row

    changed = revise_source(source, mutate)
    _, _, changed_fit, changed_prepared = prepare(changed, candidate="trend_sma")
    assert changed_fit == fit
    original, replay = run(prepared), run(changed_prepared)
    assert original.status == replay.status == "completed"
    assert original.final_snapshot.nav != replay.final_snapshot.nav
    assert causal_prefix(original, modeled_daily_availability(last)) == causal_prefix(
        replay, modeled_daily_availability(last)
    )


@pytest.mark.parametrize(
    "change", ("manifest", "source", "fit", "trial", "carry", "schedule", "predecessor")
)
def test_preparation_rejects_unregistered_or_unsupported_boundaries(change):
    source = source_inputs()
    protocol, trials, fit, _ = prepare(source)
    trial = next(
        t for t in trials if t.fit_sha256 == fit.semantic_sha256 and t.segment == "validation"
    )
    if change == "manifest":
        source = replace(source, events=source.events[1:])
    elif change == "source":
        source = replace(source, spec=replace(source.spec, initial_cash=D(20000)))
    elif change == "fit":
        fit = fits_for(protocol, source)[1]
    elif change == "trial":
        trial = replace(trial, ordinal=trial.ordinal + 1)
    elif change == "carry":
        carried = run(prepare(source)[3]).final_state
        source = replace(
            source,
            initial_state=carried,
            spec=replace(source.spec, initial_state_sha256=carried.semantic_sha256),
        )
        protocol = protocol_for(source)
        trials = expand_trials(protocol, fits=fits_for(protocol, source))
        trial = next(t for t in trials if t.segment == "validation")
    elif change == "schedule":
        at = source.spec.calendar.sessions[0].opens_at
        row = event(
            source,
            "unsupported-schedule",
            ScheduleSignal(
                "test-decision", source.spec.calendar.sessions[0].session_label, "decision_due"
            ),
            at,
            at,
        )
        source = replace(source, events=(*source.events, row))
        from packages.application.personal_inputs import canonical_events

        source = replace(
            source,
            events=canonical_events(source.events),
            spec=replace(
                source.spec, events_sha256=content_digest(canonical_events(source.events))
            ),
        )
        protocol = protocol_for(source)
        trial = next(
            t
            for t in expand_trials(protocol, fits=fits_for(protocol, source))
            if t.segment == "validation"
        )
    else:
        included = next(
            e
            for e in source.events
            if isinstance(e.payload, DailyPrice)
            and e.payload.session == protocol.folds[0].window("validation").scored_sessions[0]
        )
        excluded = next(
            e
            for e in source.events
            if isinstance(e.payload, DailyPrice)
            and e.payload.session == protocol.folds[0].window("train").warmup_sessions[0]
        )
        source = revise_source(
            source,
            lambda e: replace(e, predecessor_ids=(excluded.event_id,)) if e == included else e,
        )
        protocol = protocol_for(source)
        trial = next(
            t
            for t in expand_trials(protocol, fits=fits_for(protocol, source))
            if t.segment == "validation"
        )
    with pytest.raises(EvaluationError):
        prepare_trial_inputs(protocol=protocol, trial=trial, fit=fit, source=source)


def test_comparison_rejects_report_from_wrong_cost_or_window():
    source = source_inputs()
    protocol, trials, _, prepared = prepare(source)
    trial = next(
        t
        for t in trials
        if t.segment == "validation"
        and t.candidate_id == "buy_hold"
        and t.cost.scenario_id == "base_1x"
    )
    report = build_run_report(run(prepared), ReportConventions())
    for wrong in (
        next(t for t in trials if t.segment == "test"),
        replace(trial, configuration_sha256="f" * 64),
    ):
        with pytest.raises(EvaluationError):
            compare_trials(
                protocol,
                trials=trials
                if wrong in trials
                else tuple(wrong if t == trial else t for t in trials),
                outcomes=(TrialOutcome(wrong.trial_id, "wrong-scope", "completed", report),),
            )


def test_cancelled_attempt_is_retained_beside_later_actual_completion():
    source = source_inputs()
    protocol, trials, _, prepared = prepare(source)
    trial = next(
        t
        for t in trials
        if t.segment == "validation"
        and t.candidate_id == "buy_hold"
        and t.cost.scenario_id == "base_1x"
    )
    cancelled = run_causal_engine(
        prepared,
        accounting=PersonalAccounting(),
        strategy=ReferenceStrategy(),
        stop_requested=lambda: True,
    )
    assert cancelled.status == "cancelled"
    report = build_run_report(run(prepared), ReportConventions())
    outcomes = (
        TrialOutcome(trial.trial_id, "cancelled-attempt", "cancelled", reasons=cancelled.reasons),
        TrialOutcome(trial.trial_id, "completed-retry", "completed", report),
    )
    comparison = compare_trials(protocol, trials=trials, outcomes=outcomes)
    row = comparison.rows[trial.ordinal]
    assert row.outcomes == outcomes and row.metrics == report.metrics
    assert comparison.selected_candidate_id is None
