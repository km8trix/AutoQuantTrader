"""Synthetic input labels, causal partitions and unchanged product risk defaults."""

from dataclasses import replace
from datetime import timedelta
from decimal import ROUND_DOWN, Decimal, localcontext

import pytest

from packages.application.personal_inputs import synthetic_engine_inputs
from packages.application.synthetic_continuous_inputs import synthetic_continuous_inputs
from packages.domain.accounting_contracts import AccountingState, ExecutionObservation
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.engine_contracts import DailyPrice
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.domain.research_dataset import ResearchDataClass, modeled_daily_availability


def _pins():
    return tuple(
        VersionPin(name, "synthetic-input-unit-only/1", content_digest(("unit-only", name)))
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


@pytest.mark.parametrize("fixture", ["flat", "regime"])
def test_inputs_are_explicit_synthetic_data_without_execution_authority(fixture):
    pins = _pins()
    result = synthetic_continuous_inputs(fixture=fixture, pins=pins)
    inputs, spec = result.inputs, result.inputs.spec
    assert spec.environment == "stateful_simulation"
    assert spec.source_mode == "synthetic_observed"
    assert spec.data_class is ResearchDataClass.SYNTHETIC_FIXTURE
    assert spec.availability_mode == "modeled"
    assert spec.live_authorized is False
    assert spec.account_privileges == "CASH"
    assert spec.financing_policy == "cash-funded-long-only/1"
    assert spec.pins == pins
    assert spec.deployment_id == "synthetic-stream"
    assert spec.account_binding_sha256 == content_digest(
        (
            "synthetic-continuous-account-binding/1",
            spec.account_id,
            "synthetic-stream",
            (("US-ETF-SPY", "SPY"),),
        )
    )
    assert inputs.initial_state == AccountingState(spec.account_id)
    assert spec.initial_state_sha256 == inputs.initial_state.semantic_sha256
    assert spec.bootstrap_events_sha256 == content_digest(inputs.bootstrap_events)
    events = inputs.bootstrap_events + result.daily_events
    assert len(events) == 8 and all(type(event.payload) is DailyPrice for event in events)
    assert not any(isinstance(event.payload, ExecutionObservation) for event in events)
    assert all(
        event.provenance.data_class is ResearchDataClass.SYNTHETIC_FIXTURE for event in events
    )
    assert all(event.provenance.observed_at is None for event in events)


def test_conversion_keeps_product_risk_sizing_costs_and_continuous_bounds():
    pins = _pins()
    finite = synthetic_engine_inputs(
        fixture="flat",
        pins=pins,
        session_count=8,
        warmup_count=2,
        configuration=ReferenceConfiguration(lookback=2),
    )
    spec = synthetic_continuous_inputs(fixture="flat", pins=pins).inputs.spec
    assert spec.risk_policy == replace(
        finite.spec.risk_policy, policy_id="personal-daily-stateful-simulation/1"
    )
    assert spec.risk_policy.policy_scope == "product"
    assert spec.risk_policy.max_order_quantity == Decimal(1000)
    assert spec.risk_policy.max_order_nav_fraction == Decimal("0.25")
    assert spec.risk_policy.max_batch_nav_fraction == Decimal("0.95")
    assert spec.risk_policy.max_symbol_nav_fraction == Decimal("0.25")
    assert spec.risk_policy.max_gross_nav_fraction == Decimal("0.95")
    assert spec.risk_policy.adverse_reserve_fraction == Decimal("0.01")
    assert spec.risk_policy.daily_loss_boundary == Decimal("-0.03")
    assert spec.risk_policy.drawdown_boundary == Decimal("0.15")
    assert (
        spec.risk_policy.max_open_intents,
        spec.risk_policy.max_per_symbol_intents,
        spec.risk_policy.max_new_intents_per_session,
    ) == (4, 1, 8)
    assert spec.execution_policy == replace(
        finite.spec.execution_policy,
        model_id="observed-facts-v1",
        settlement_model="observed-only-v1",
        correction_settlement="explicit-only-v1",
        terminal_model="observed-only-v1",
    )
    assert spec.initial_cash == Decimal(10000)
    assert spec.execution_policy.slippage_bps == Decimal(5)
    assert spec.execution_policy.fee_per_share == spec.risk_policy.fee_per_share == Decimal("0.01")
    assert spec.strategy == finite.spec.strategy
    assert spec.strategy_configuration == ReferenceConfiguration(kind="buy_hold", lookback=2)
    assert spec.strategy_configuration.allocation == Decimal("0.25")
    assert spec.max_events == 100000
    assert spec.max_output_bytes == 33554432
    assert spec.max_wall_seconds == 30
    assert spec.max_memory_bytes == 4294967296


@pytest.mark.parametrize("warmup", [0, 2, 7])
def test_bootstrap_and_scored_prices_keep_original_causal_times(warmup):
    result = synthetic_continuous_inputs(fixture="regime", pins=_pins(), warmup_count=warmup)
    inputs, spec = result.inputs, result.inputs.spec
    calendar = {session.session_label: session for session in spec.calendar.sessions}
    assert len(inputs.bootstrap_events) == warmup
    assert len(result.daily_events) == 8 - warmup
    assert (
        tuple(event.payload.session for event in inputs.bootstrap_events)
        == spec.window.warmup_sessions
    )
    assert (
        tuple(event.payload.session for event in result.daily_events) == spec.window.scored_sessions
    )
    first = calendar[spec.window.scored_sessions[0]]
    assert spec.initialized_at == first.opens_at - timedelta(minutes=30)
    assert spec.calendar.sessions[-1].session_label > spec.window.scored_sessions[-1]
    assert tuple(event.event_id for event in inputs.bootstrap_events) == tuple(
        sorted({event.event_id for event in inputs.bootstrap_events})
    )
    assert result.daily_events == tuple(
        sorted(result.daily_events, key=lambda event: (event.knowledge_at, event.event_id))
    )
    for event in inputs.bootstrap_events + result.daily_events:
        session = calendar[event.payload.session]
        assert event.economic_at == session.closes_at
        assert event.knowledge_at == modeled_daily_availability(session.session_label)
        assert event.knowledge_at > event.economic_at
        assert event.provenance.simulated_available_at == event.knowledge_at
        assert event.provenance.normalized_sha256 == content_digest(event.payload)
    assert all(event.knowledge_at <= spec.initialized_at for event in inputs.bootstrap_events)
    assert all(event.knowledge_at > spec.initialized_at for event in result.daily_events)


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("flat", ("100",) * 8),
        ("regime", ("100", "100.1", "100.2", "100.3", "100.4", "100.3", "100.2", "100.1")),
    ],
)
def test_flat_and_regime_are_deterministic_engineering_prices(fixture, expected):
    first = synthetic_continuous_inputs(fixture=fixture, pins=_pins())
    with localcontext() as context:
        context.prec = 2
        context.rounding = ROUND_DOWN
        repeated = synthetic_continuous_inputs(fixture=fixture, pins=_pins())
    assert repeated == first
    assert repeated.inputs.spec.run_id == first.inputs.spec.run_id
    events = first.inputs.bootstrap_events + first.daily_events
    closes = tuple(Decimal(value) for value in expected)
    assert tuple(event.payload.close_price for event in events) == closes
    assert tuple(event.payload.adjusted_close for event in events) == closes
    assert tuple(event.payload.open_price for event in events) == (Decimal(100), *closes[:-1])


def test_synthetic_binding_identifies_the_account_not_future_price_rows():
    flat = synthetic_continuous_inputs(fixture="flat", pins=_pins())
    regime = synthetic_continuous_inputs(fixture="regime", pins=_pins())
    assert flat.inputs.spec.account_binding_sha256 == regime.inputs.spec.account_binding_sha256
    assert flat.daily_events != regime.daily_events


@pytest.mark.parametrize(
    "overrides",
    [
        {"fixture": "market"},
        {"fixture": None},
        {"session_count": 1},
        {"session_count": 5001},
        {"session_count": True},
        {"session_count": 8.0},
        {"warmup_count": -1},
        {"warmup_count": 8},
        {"warmup_count": True},
        {"warmup_count": 2.0},
    ],
)
def test_invalid_fixture_session_and_warmup_bounds_are_rejected(overrides):
    values = {"fixture": "flat", "pins": _pins(), "session_count": 8, "warmup_count": 2}
    values.update(overrides)
    with pytest.raises(ValueError):
        synthetic_continuous_inputs(**values)


@pytest.mark.parametrize("warmup", [0, 1])
def test_minimum_session_window_retains_a_following_execution_horizon(warmup):
    result = synthetic_continuous_inputs(
        fixture="flat", pins=_pins(), session_count=2, warmup_count=warmup
    )
    assert len(result.inputs.bootstrap_events) + len(result.daily_events) == 2
    assert (
        result.inputs.spec.calendar.sessions[-1].session_label
        > result.inputs.spec.window.scored_sessions[-1]
    )


def test_missing_build_pins_are_rejected_without_discovery():
    with pytest.raises(ValueError):
        synthetic_continuous_inputs(fixture="flat", pins=())
