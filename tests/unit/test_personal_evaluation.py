from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from packages.application.personal_inputs import canonical_events, synthetic_engine_inputs
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.engine_contracts import DailyPrice
from packages.domain.personal_contracts import content_digest
from packages.domain.personal_evaluation import (
    COST_SCENARIOS,
    CostScenario,
    EvaluationCandidate,
    EvaluationComparison,
    EvaluationError,
    EvaluationFold,
    EvaluationProtocol,
    EvaluationWindow,
    PriorAccessDeclaration,
    TrialOutcome,
    compare_trials,
    expand_trials,
    freeze_reference_fit,
    training_slice,
    validate_protocol,
)
from packages.domain.report_contracts import ReportConventions
from packages.domain.research_dataset import modeled_daily_availability
from tests.unit.test_causal_engine import PINS

D = Decimal


def source_inputs(fixture="flat"):
    pins = tuple(
        replace(p, version=ReportConventions().version) if p.name == "report" else p for p in PINS
    )
    return synthetic_engine_inputs(
        fixture=fixture,
        pins=pins,
        session_count=18,
        warmup_count=2,
        configuration=ReferenceConfiguration("buy_hold", 2),
    )


def protocol_for(source, *, candidates=None):
    days = tuple(s.session_label for s in source.spec.calendar.sessions)
    fold = EvaluationFold(
        "fold-1",
        (
            EvaluationWindow("train", days[:2], days[2:6]),
            EvaluationWindow("validation", days[4:6], days[6:10]),
            EvaluationWindow("test", days[8:10], days[10:14]),
        ),
        modeled_daily_availability(days[5]),
    )
    at = datetime(2026, 9, 9, tzinfo=UTC)
    return EvaluationProtocol(
        name="explicit engineering evaluation",
        hypothesis="Compare fixed W2 references",
        registered_at=at,
        registered_by="test-owner",
        dataset_id=source.spec.dataset_id,
        dataset_sha256=source.spec.dataset_sha256,
        source_spec_sha256=source.spec.semantic_sha256,
        data_class=source.spec.data_class,
        availability_mode=source.spec.availability_mode,
        calendar_sha256=content_digest(source.spec.calendar),
        instruments=source.spec.instruments,
        candidates=candidates
        or (
            EvaluationCandidate("buy_hold", ReferenceConfiguration("buy_hold", 2)),
            EvaluationCandidate("trend_sma", ReferenceConfiguration("trend_sma", 2)),
        ),
        folds=(fold,),
        prior_access=PriorAccessDeclaration(
            "known_accessed",
            at,
            "test-owner",
            "Transparent synthetic formula; no untouched or empirical claim",
        ),
        implementation_pins=source.spec.pins,
        warmup_sessions=2,
    )


def fits_for(protocol, source):
    return tuple(
        freeze_reference_fit(
            training_slice(protocol, f.fold_id, daily_events=source.events), c.configuration
        )
        for f in protocol.folds
        for c in protocol.candidates
    )


def revise_source(source, transform):
    events = canonical_events(tuple(transform(e) for e in source.events))
    return replace(
        source,
        events=events,
        spec=replace(
            source.spec,
            events_sha256=content_digest(events),
            dataset_sha256=content_digest(("mutated-test-source", events)),
        ),
    )


def test_four_exact_costs_and_all_registered_trial_identities():
    source = source_inputs()
    protocol = protocol_for(source)
    validate_protocol(protocol, calendar=source.spec.calendar)
    trials = expand_trials(protocol, fits=fits_for(protocol, source))
    assert len(trials) == protocol.planned_trial_count == 24
    assert len({t.trial_id for t in trials}) == 24
    assert [(c.slippage_bps, c.fee_per_share) for c in COST_SCENARIOS] == [
        (5, D(".01")),
        (10, D(".02")),
        (15, D(".03")),
        (20, D(".02")),
    ]
    assert trials == expand_trials(protocol, fits=fits_for(protocol, source))
    with pytest.raises(EvaluationError, match="frozen"):
        CostScenario("base_1x", D(0), D(0))
    with pytest.raises(EvaluationError, match="all four"):
        replace(protocol, costs=COST_SCENARIOS[:1])
    with pytest.raises(EvaluationError, match="budget"):
        replace(protocol, maximum_trials=23)


@pytest.mark.parametrize("change", ("order", "overlap", "carry", "purge", "embargo", "warmup"))
def test_invalid_fold_declarations_fail_closed(change):
    protocol = protocol_for(source_inputs())
    fold = protocol.folds[0]
    with pytest.raises(ValueError):
        if change == "order":
            replace(fold, windows=tuple(reversed(fold.windows)))
        elif change == "overlap":
            replace(
                fold,
                windows=(
                    fold.windows[0],
                    replace(fold.windows[1], scored_sessions=fold.windows[0].scored_sessions),
                    fold.windows[2],
                ),
            )
        elif change in ("carry", "purge", "embargo"):
            kwargs = {"reset_mode": "carry"} if change == "carry" else {change + "_sessions": 1}
            replace(fold, **kwargs)
        else:
            replace(protocol, warmup_sessions=3)


def test_exact_calendar_warmup_horizon_and_fit_time():
    source = source_inputs()
    protocol = protocol_for(source)
    fold = protocol.folds[0]
    for cutoff in (
        fold.fit_knowledge_cutoff - timedelta(days=10),
        fold.fit_knowledge_cutoff + timedelta(days=10),
    ):
        with pytest.raises(EvaluationError, match="cutoff"):
            validate_protocol(
                replace(protocol, folds=(replace(fold, fit_knowledge_cutoff=cutoff),)),
                calendar=source.spec.calendar,
            )
    shortened = replace(source.spec.calendar, sessions=source.spec.calendar.sessions[:14])
    with pytest.raises(EvaluationError, match="horizon"):
        validate_protocol(
            replace(protocol, calendar_sha256=content_digest(shortened)), calendar=shortened
        )
    with pytest.raises(EvaluationError, match="calendar identity"):
        validate_protocol(protocol, calendar=replace(source.spec.calendar, version="different"))


@pytest.mark.parametrize(
    "change", ("scored_gap", "wrong_warmup", "early_availability", "fit_scope")
)
def test_training_and_window_boundaries_require_exact_declared_inputs(change):
    source = source_inputs()
    protocol = protocol_for(source)
    fold = protocol.folds[0]
    train = fold.windows[0]
    with pytest.raises(EvaluationError):
        if change in ("scored_gap", "wrong_warmup"):
            window = (
                replace(train, scored_sessions=train.scored_sessions[::2])
                if change == "scored_gap"
                else replace(fold.windows[1], warmup_sessions=train.warmup_sessions)
            )
            windows = (
                (window, *fold.windows[1:])
                if change == "scored_gap"
                else (train, window, fold.windows[2])
            )
            validate_protocol(
                replace(protocol, folds=(replace(fold, windows=windows),)),
                calendar=source.spec.calendar,
            )
        elif change == "early_availability":
            fit = fits_for(protocol, source)[0]
            row = fit.training.events[0]
            revised = replace(
                row,
                provenance=replace(
                    row.provenance, simulated_available_at=row.knowledge_at + timedelta(seconds=1)
                ),
            )
            training_slice(
                protocol,
                fold.fold_id,
                daily_events=tuple(revised if e == row else e for e in source.events),
            )
        else:
            fit = fits_for(protocol, source)[0]
            expand_trials(
                protocol,
                fits=(
                    replace(
                        fit,
                        training=replace(
                            fit.training,
                            knowledge_cutoff=fit.training.knowledge_cutoff + timedelta(seconds=1),
                        ),
                    ),
                    *fits_for(protocol, source)[1:],
                ),
            )


def test_cross_fold_scoring_cannot_be_double_counted():
    protocol = protocol_for(source_inputs())
    with pytest.raises(EvaluationError, match="overlap across folds"):
        replace(protocol, folds=(protocol.folds[0], replace(protocol.folds[0], fold_id="fold-2")))


def test_no_fit_is_empty_immutable_and_train_only():
    source = source_inputs()
    protocol = protocol_for(source)
    fit = fits_for(protocol, source)[0]
    assert fit.transform_version == "identity-no-fit/1"
    assert fit.fitted_parameters == () and fit.learned_transform_supported is False
    future = protocol.folds[0].windows[1].scored_sessions[0]

    def mutate(event):
        if isinstance(event.payload, DailyPrice) and event.payload.session >= future:
            payload = replace(event.payload, close_price=D(900), adjusted_close=D(900))
            return replace(
                event,
                payload=payload,
                provenance=replace(event.provenance, normalized_sha256=content_digest(payload)),
            )
        return event

    changed = revise_source(source, mutate)
    changed_fit = fits_for(protocol_for(changed), changed)[0]
    assert changed_fit == fit
    assert changed_fit.parameters_sha256 == fit.parameters_sha256
    with pytest.raises(EvaluationError, match="learned"):
        replace(fit, fitted_parameters=(("invented", D(1)),))
    with pytest.raises(ValueError):
        replace(fit, transform_version="learned-scaler/1")
    with pytest.raises(EvaluationError, match="scope"):
        replace(fit.training, sessions=protocol.folds[0].windows[2].scored_sessions)


def test_late_training_rows_are_excluded_and_missing_training_rejects():
    source = source_inputs()
    protocol = protocol_for(source)
    fit = fits_for(protocol, source)[0]
    first = fit.training.events[0]
    late = replace(
        first,
        event_id=first.event_id + ":late",
        knowledge_at=fit.training.knowledge_cutoff + timedelta(seconds=1),
    )
    assert training_slice(protocol, "fold-1", daily_events=(*source.events, late)) == fit.training
    missing = tuple(e for e in source.events if e.event_id != first.event_id)
    with pytest.raises(EvaluationError, match="incomplete"):
        training_slice(protocol, "fold-1", daily_events=missing)
    with pytest.raises(EvaluationError, match="cutoff"):
        replace(fit.training, events=(late,))


def test_access_never_becomes_untouched_and_comparison_keeps_all_attempts():
    source = source_inputs()
    protocol = protocol_for(source)
    trials = expand_trials(protocol, fits=fits_for(protocol, source))
    outcomes = tuple(
        TrialOutcome(
            trials[0].trial_id,
            status,
            status,
            reasons=("explicit-test-outcome",)
            if status in ("incomplete", "failed", "cancelled", "abandoned")
            else (),
        )
        for status in ("queued", "running", "incomplete", "failed", "cancelled", "abandoned")
    )
    comparison = compare_trials(protocol, trials=trials, outcomes=outcomes)
    assert type(comparison) is EvaluationComparison and len(comparison.rows) == 24
    assert comparison.rows[0].outcomes == outcomes
    assert comparison.rows[-1].reasons == ("not_attempted",)
    assert comparison.eligibility == "not_assessed" and comparison.selected_candidate_id is None
    with pytest.raises(ValueError):
        replace(protocol.prior_access, status="untouched")
    with pytest.raises(EvaluationError, match="unique"):
        compare_trials(protocol, trials=trials, outcomes=(*outcomes, outcomes[0]))
    with pytest.raises(EvaluationError, match="full declared"):
        compare_trials(protocol, trials=trials[:-1], outcomes=())
    with pytest.raises(EvaluationError, match="completed economic"):
        TrialOutcome(trials[0].trial_id, "bad-completion", "completed")
    with pytest.raises(ValueError):
        TrialOutcome(trials[0].trial_id, "wrong-spelling", "canceled", reasons=("cancelled",))
    with pytest.raises(EvaluationError, match="reason"):
        TrialOutcome(trials[0].trial_id, "missing-status-evidence", "incomplete")
    unknown = replace(protocol, prior_access=replace(protocol.prior_access, status="unknown"))
    assert unknown.semantic_sha256 != protocol.semantic_sha256
    assert unknown.mode == "descriptive_only"
