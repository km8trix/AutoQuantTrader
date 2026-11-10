"""Input provenance and reference callback contracts, without a simulator oracle."""

from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from decimal import ROUND_DOWN, Decimal, localcontext

import pytest

from packages.adapters.personal_build import current_build_pins
from packages.application.personal_inputs import (
    OPEN_PROXY_ASSUMPTION,
    canonical_events,
    synthetic_engine_inputs,
)
from packages.application.reference_strategy import ReferenceStrategy
from packages.domain.accounting_contracts import AccountSnapshot, ExecutionObservation
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.engine_contracts import (
    BenchmarkPrice,
    DailyPrice,
    DailyStrategyContext,
    DailyStrategyState,
    DailyTrigger,
)
from packages.domain.personal_contracts import (
    CausalMark,
    ReductionPoint,
    VersionPin,
    content_digest,
)
from packages.domain.research_dataset import ResearchDataClass

D = Decimal
AT = datetime(2025, 1, 3, 1, tzinfo=UTC)
SESSION = date(2025, 1, 2)


def _pins():
    names = (
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
    return tuple(
        VersionPin(name, "unit-test-only/1", content_digest(name)) for name in sorted(names)
    )


def _input(**kwargs):
    return synthetic_engine_inputs(pins=_pins(), session_count=8, warmup_count=3, **kwargs)


def _snapshot():
    mark = CausalMark(
        "mark", "US-ETF-SPY", "SPY", D(100), SESSION, AT - timedelta(hours=4), AT, "a" * 64
    )
    return AccountSnapshot(
        account_id="account",
        point=ReductionPoint(1, 2, AT, 6),
        state_sha256="b" * 64,
        positions=(),
        commitments=(),
        marks=(mark,),
        trade_date_cash=D(10000),
        settled_cash=D(10000),
        trade_receivable=D(0),
        trade_payable=D(0),
        dividend_receivable=D(0),
        buy_reserve=D(0),
        sell_fee_reserve=D(0),
        available_cash=D(10000),
        market_value=D(0),
        nav=D(10000),
        gross_realized_pnl=D(0),
        fees=D(0),
        dividend_income=D(0),
        unrealized_pnl=D(0),
        net_external_flow=D(10000),
        journal_sha256="c" * 64,
        order_sha256="d" * 64,
    )


def _context():
    trigger = DailyTrigger("trigger", SESSION, date(2025, 1, 3), AT, "complete_market", "e" * 64, 2)
    return DailyStrategyContext(
        trigger,
        _snapshot(),
        DailyStrategyState(),
        ReferenceConfiguration(),
        (("US-ETF-SPY", "SPY"),),
        ((SESSION, (("US-ETF-SPY", D(100)),)),),
        (SESSION,),
        0,
        datetime(2025, 1, 3, 14, 30, tzinfo=UTC),
        datetime(2025, 1, 3, 21, tzinfo=UTC),
    )


def test_default_has_full_warmup_scored_coverage_and_labelled_synthetic_calendars():
    inputs = synthetic_engine_inputs(fixture="flat", pins=_pins())
    assert len(inputs.spec.evaluation.warmup_sessions) == 252
    assert len(inputs.spec.evaluation.scored_sessions) == 268
    assert len(inputs.spec.calendar.sessions) == 521
    assert len(inputs.spec.execution_policy.settlement_calendar.business_dates) == 526
    assert inputs.spec.data_class is ResearchDataClass.SYNTHETIC_FIXTURE
    assert "synthetic" in inputs.spec.calendar.calendar_id
    assert inputs.spec.events_sha256 == content_digest(inputs.events)
    assert inputs.spec.initial_state_sha256 == inputs.initial_state.semantic_sha256


def test_fixture_configuration_costs_and_actual_data_each_change_run_identity():
    first = _input(fixture="flat")
    variants = (
        _input(fixture="regime"),
        _input(fixture="flat", configuration=ReferenceConfiguration("trend_sma", lookback=3)),
        _input(fixture="flat", configuration=ReferenceConfiguration(allocation=D("0.2"))),
        _input(fixture="flat", slippage_bps=D(10)),
        _input(fixture="flat", fee_per_share=D("0.02")),
    )
    assert len({first.spec.run_id, *(item.spec.run_id for item in variants)}) == 6
    assert first.spec.events_sha256 == variants[1].spec.events_sha256
    assert first.spec.events_sha256 != variants[0].spec.events_sha256


def test_open_proxy_never_contains_close_or_adjusted_data():
    inputs = _input(fixture="regime")
    opens = [e for e in inputs.events if isinstance(e.payload, ExecutionObservation)]
    closes = [e for e in inputs.events if isinstance(e.payload, DailyPrice)]
    benchmarks = [e for e in inputs.events if isinstance(e.payload, BenchmarkPrice)]
    assert len(opens) == len(closes) == len(benchmarks) == 8
    assert all(e.knowledge_at == e.economic_at for e in opens)
    assert all(e.provenance.assumption_id == OPEN_PROXY_ASSUMPTION for e in opens)
    assert all(e.provenance.observed_at is None for e in inputs.events)
    assert all(e.knowledge_at > e.economic_at for e in closes)
    assert all(not hasattr(e.payload, "close_price") for e in opens)
    assert all(e.payload.representation == "synthetic_total_return_units" for e in benchmarks)


def test_event_normalization_is_permutation_and_exact_duplicate_invariant():
    inputs = _input(fixture="flat")
    assert canonical_events(tuple(reversed(inputs.events)) + inputs.events) == inputs.events
    event = inputs.events[0]
    conflict = replace(event, provenance=replace(event.provenance, raw_sha256="e" * 64))
    with pytest.raises(ValueError, match="conflicting"):
        canonical_events((event, conflict))


def test_input_identity_and_prices_ignore_ambient_decimal_arithmetic():
    first = _input(fixture="regime")
    with localcontext() as context:
        context.prec = 2
        context.rounding = ROUND_DOWN
        other = _input(fixture="regime")
    assert first == other
    assert first.spec.run_id == other.spec.run_id


@pytest.mark.parametrize(
    "overrides",
    [
        {"session_count": 1},
        {"session_count": 5001},
        {"warmup_count": -1},
        {"warmup_count": 8},
        {"warmup_count": True},
    ],
)
def test_fixture_bounds_reject(overrides):
    kwargs = {"fixture": "flat", "pins": _pins(), "session_count": 8, "warmup_count": 3}
    kwargs.update(overrides)
    with pytest.raises(ValueError):
        synthetic_engine_inputs(**kwargs)


def test_reference_target_matches_hand_calculated_whole_share_cash_budget():
    transition = ReferenceStrategy().on_decision(_context())
    assert transition.target is not None
    assert transition.target.targets[0].quantity == 24  # floor(2500 / (100*1.01 + .01))
    assert transition.state.previously_allocated is False
    assert transition.state.predecessor_sha256 == _context().state.semantic_sha256
    assert transition.target.not_before > transition.target.trigger.as_of


def test_rejected_buyhold_target_does_not_suppress_retry_next_callback():
    strategy = ReferenceStrategy()
    context = _context()
    first = strategy.on_decision(context)
    second = strategy.on_decision(replace(context, state=first.state, scored_session_index=1))
    assert first.target is not None and second.target is not None
    assert second.state.previously_allocated is False


def test_missing_authoritative_mark_is_no_target_not_fake_zero_position():
    context = _context()
    bad = replace(context, account=replace(context.account, marks=()))
    transition = ReferenceStrategy().on_decision(bad)
    assert transition.target is None
    assert "REFERENCE_PRICE_UNAVAILABLE:US-ETF-SPY" in transition.reasons


def test_cost_sizing_is_injected_and_remains_below_cash_budget():
    target = ReferenceStrategy(fee_per_share=D(10)).on_decision(_context()).target
    assert target is not None and target.targets[0].quantity == 22
    with pytest.raises(ValueError):
        ReferenceStrategy(reserve_fraction=D(-1))


def test_zero_initial_cash_only_accepts_explicit_synthetic_oracle():
    inputs = _input(fixture="flat")
    with pytest.raises(ValueError, match="synthetic oracle"):
        replace(inputs.spec, initial_cash=D(0))
    oracle = replace(inputs.spec.risk_policy, policy_scope="synthetic_oracle")
    assert replace(inputs.spec, initial_cash=D(0), risk_policy=oracle).initial_cash == 0


def test_actual_build_pins_are_repeatable_and_complete():
    first = current_build_pins()
    assert first == current_build_pins()
    assert {p.name for p in _pins()} <= {p.name for p in first}
    assert next(p for p in first if p.name == "source").version == "actual-python-source-content/1"
