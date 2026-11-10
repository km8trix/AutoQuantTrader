"""Prospective fixture data, causal UTC bounds and original byte preservation."""

from dataclasses import replace
from datetime import UTC, date, datetime, timedelta, timezone
from decimal import ROUND_DOWN, Decimal, localcontext
from hashlib import sha256

import pytest

from packages.application.personal_codec import encode_record
from packages.application.personal_inputs import synthetic_engine_inputs
from packages.application.prospective_synthetic_inputs import prospective_synthetic_inputs
from packages.application.synthetic_continuous_inputs import synthetic_continuous_inputs
from packages.domain.accounting_contracts import AccountingState, ExecutionObservation
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.engine_contracts import DailyPrice
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.domain.research_dataset import ResearchDataClass


def _pins():
    # Exact pins used for the independent, pre-extraction original-byte capture.
    return tuple(
        VersionPin(name, "synthetic-input-unit-only/1", content_digest(("unit-only", name)))
        for name in (
            "actions",
            "availability",
            "benchmark",
            "dependency_lock",
            "dirty_patch",
            "engine",
            "numeric",
            "report",
            "source",
            "tzdata",
        )
    )


def _values():
    return {
        "fixture": "flat",
        "pins": _pins(),
        "start": date(2026, 10, 19),
        "initialized_at": datetime(2026, 10, 21, 13, tzinfo=UTC),
    }


@pytest.mark.parametrize("fixture", ["flat", "regime"])
def test_explicit_candidate_is_data_for_a_fixed_synthetic_profile(fixture):
    values = _values() | {"fixture": fixture}
    result = prospective_synthetic_inputs(**values)
    inputs, spec = result.inputs, result.inputs.spec
    assert spec.initialized_at == values["initialized_at"]
    assert spec.instruments == (("US-ETF-SPY", "SPY"),)
    assert spec.strategy_configuration == ReferenceConfiguration(kind="buy_hold", lookback=2)
    assert spec.pins == values["pins"]
    assert spec.environment == "stateful_simulation"
    assert spec.source_mode == "synthetic_observed"
    assert spec.data_class is ResearchDataClass.SYNTHETIC_FIXTURE
    assert spec.availability_mode == "modeled"
    assert spec.live_authorized is False
    assert spec.account_privileges == "CASH"
    assert spec.financing_policy == "cash-funded-long-only/1"
    assert inputs.initial_state == AccountingState(spec.account_id)
    assert spec.initial_state_sha256 == inputs.initial_state.semantic_sha256
    assert spec.bootstrap_events_sha256 == content_digest(inputs.bootstrap_events)
    assert spec.account_binding_sha256 == content_digest(
        (
            "synthetic-continuous-account-binding/1",
            spec.account_id,
            "synthetic-stream",
            (("US-ETF-SPY", "SPY"),),
        )
    )
    assert spec.window.warmup_sessions == (date(2026, 10, 19), date(2026, 10, 20))
    assert spec.window.scored_sessions == (
        date(2026, 10, 21),
        date(2026, 10, 22),
        date(2026, 10, 23),
        date(2026, 10, 26),
        date(2026, 10, 27),
        date(2026, 10, 28),
    )
    assert len(inputs.bootstrap_events) == 2
    assert len(result.daily_events) == 6
    assert len(spec.calendar.sessions) == 9
    assert spec.calendar.sessions[-1].session_label == date(2026, 10, 29)
    events = inputs.bootstrap_events + result.daily_events
    assert all(type(event.payload) is DailyPrice for event in events)
    assert not any(isinstance(event.payload, ExecutionObservation) for event in events)
    assert all(event.provenance.observed_at is None for event in events)
    assert all(
        event.provenance.data_class is ResearchDataClass.SYNTHETIC_FIXTURE for event in events
    )
    assert all(event.knowledge_at <= spec.initialized_at for event in inputs.bootstrap_events)
    assert all(event.knowledge_at > spec.initialized_at for event in result.daily_events)
    assert result.daily_events == tuple(
        sorted(result.daily_events, key=lambda event: (event.knowledge_at, event.event_id))
    )


def test_financial_and_resource_defaults_equal_the_existing_product_envelope():
    values = _values()
    finite = synthetic_engine_inputs(
        fixture="flat",
        pins=values["pins"],
        start=values["start"],
        session_count=8,
        warmup_count=2,
        configuration=ReferenceConfiguration(lookback=2),
    )
    spec = prospective_synthetic_inputs(**values).inputs.spec
    assert spec.risk_policy == replace(
        finite.spec.risk_policy, policy_id="personal-daily-stateful-simulation/1"
    )
    assert spec.risk_policy.policy_scope == "product"
    assert spec.risk_policy.max_order_quantity == Decimal("1000")
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
    assert spec.initial_cash == Decimal("10000")
    assert spec.execution_policy.slippage_bps == Decimal("5")
    assert spec.execution_policy.fee_per_share == Decimal("0.01")
    assert spec.risk_policy.fee_per_share == Decimal("0.01")
    assert spec.strategy == finite.spec.strategy
    assert spec.strategy_configuration.allocation == Decimal("0.25")
    assert (
        spec.max_events,
        spec.max_output_bytes,
        spec.max_wall_seconds,
        spec.max_memory_bytes,
    ) == (100000, 33554432, 30, 4294967296)


@pytest.mark.parametrize(
    ("start", "candidate", "last_warmup_known", "first_open", "first_close", "daily_known"),
    [
        (
            date(2026, 3, 5),
            datetime(2026, 3, 9, 13, tzinfo=UTC),
            datetime(2026, 3, 7, 1, tzinfo=UTC),
            datetime(2026, 3, 9, 13, 30, tzinfo=UTC),
            datetime(2026, 3, 9, 20, tzinfo=UTC),
            datetime(2026, 3, 10, 0, tzinfo=UTC),
        ),
        (
            date(2026, 10, 29),
            datetime(2026, 11, 2, 14, tzinfo=UTC),
            datetime(2026, 10, 31, 0, tzinfo=UTC),
            datetime(2026, 11, 2, 14, 30, tzinfo=UTC),
            datetime(2026, 11, 2, 21, tzinfo=UTC),
            datetime(2026, 11, 3, 1, tzinfo=UTC),
        ),
    ],
)
def test_dst_and_weekend_times_use_known_new_york_utc_values(
    start, candidate, last_warmup_known, first_open, first_close, daily_known
):
    result = prospective_synthetic_inputs(
        fixture="flat", pins=_pins(), start=start, initialized_at=candidate, session_count=3
    )
    spec = result.inputs.spec
    assert max(event.knowledge_at for event in result.inputs.bootstrap_events) == last_warmup_known
    assert len(result.daily_events) == 1
    daily = result.daily_events[0]
    assert daily.payload.session == first_open.date()
    first = next(
        session
        for session in spec.calendar.sessions
        if session.session_label == daily.payload.session
    )
    assert first.opens_at == first_open
    assert first.closes_at == daily.economic_at == first_close
    assert daily.knowledge_at == daily.provenance.simulated_available_at == daily_known
    assert spec.calendar.sessions[-1].session_label == first_open.date() + timedelta(days=1)


@pytest.mark.parametrize(
    "candidate",
    [
        datetime(2026, 10, 21, 0, tzinfo=UTC),
        datetime(2026, 10, 21, 19, 59, 59, 999999, tzinfo=UTC),
    ],
)
def test_warmup_equality_and_candidate_after_open_preserve_original_boundary(candidate):
    result = prospective_synthetic_inputs(**(_values() | {"initialized_at": candidate}))
    assert result.inputs.spec.initialized_at == candidate
    assert max(event.knowledge_at for event in result.inputs.bootstrap_events) == datetime(
        2026, 10, 21, 0, tzinfo=UTC
    )
    assert result.daily_events[0].economic_at == datetime(2026, 10, 21, 20, tzinfo=UTC)
    assert result.daily_events[0].knowledge_at == datetime(2026, 10, 22, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "candidate",
    [
        datetime(2026, 10, 20, 23, 59, 59, 999999, tzinfo=UTC),
        datetime(2026, 10, 21, 20, tzinfo=UTC),
        datetime(2026, 10, 21, 20, 0, 0, 1, tzinfo=UTC),
        datetime(2026, 10, 22, 0, tzinfo=UTC),
    ],
)
def test_incomplete_warmup_and_elapsed_first_close_fail_without_rolling(candidate):
    with pytest.raises(ValueError, match=r"^PROSPECTIVE_SYNTHETIC_INPUTS_INVALID$"):
        prospective_synthetic_inputs(**(_values() | {"initialized_at": candidate}))


@pytest.mark.parametrize(
    ("fixture", "expected_closes"),
    [
        ("flat", ("100",) * 8),
        ("regime", ("100", "100.1", "100.2", "100.3", "100.4", "100.3", "100.2", "100.1")),
    ],
)
def test_canonical_prices_are_exact_under_a_hostile_decimal_context(fixture, expected_closes):
    values = _values() | {"fixture": fixture}
    result = prospective_synthetic_inputs(**values)
    encoded = encode_record((result.inputs, result.daily_events))
    with localcontext() as context:
        context.prec = 2
        context.rounding = ROUND_DOWN
        context.capitals = 0
        repeated = prospective_synthetic_inputs(**values)
    # Compare returned representations under the same serialization context.
    # The separate legacy codec uses str(Decimal); its ambient exponent casing
    # is not controlled by this pure builder and needs compatibility review.
    repeated_encoded = encode_record((repeated.inputs, repeated.daily_events))
    assert repeated == result
    assert repeated_encoded == encoded
    assert repeated.inputs.spec.run_id == result.inputs.spec.run_id
    prices = tuple(
        event.payload
        for event in sorted(
            result.inputs.bootstrap_events + result.daily_events,
            key=lambda event: event.payload.session,
        )
    )
    closes = tuple(Decimal(value) for value in expected_closes)
    assert tuple(price.close_price for price in prices) == closes
    assert tuple(price.adjusted_close for price in prices) == closes
    assert tuple(price.open_price for price in prices) == (Decimal("100"), *closes[:-1])


def test_candidate_and_build_pins_bind_identity_without_changing_price_rows():
    first = prospective_synthetic_inputs(**_values())
    later = prospective_synthetic_inputs(
        **(_values() | {"initialized_at": datetime(2026, 10, 21, 14, tzinfo=UTC)})
    )
    pins = _pins()
    changed = prospective_synthetic_inputs(
        **(_values() | {"pins": (replace(pins[0], sha256="a" * 64), *pins[1:])})
    )
    assert first.inputs.spec.run_id != later.inputs.spec.run_id
    assert first.inputs.spec.run_id != changed.inputs.spec.run_id
    assert first.daily_events == later.daily_events == changed.daily_events
    assert (
        first.inputs.bootstrap_events
        == later.inputs.bootstrap_events
        == changed.inputs.bootstrap_events
    )
    assert first.inputs.spec.account_binding_sha256 == later.inputs.spec.account_binding_sha256
    assert changed.inputs.spec.live_authorized is False


@pytest.mark.parametrize("session_count", [3, 5000])
def test_original_session_cap_and_following_horizon_are_preserved(session_count):
    result = prospective_synthetic_inputs(**(_values() | {"session_count": session_count}))
    spec = result.inputs.spec
    assert len(result.inputs.bootstrap_events) == 2
    assert len(result.daily_events) == session_count - 2
    assert len(spec.calendar.sessions) == session_count + 1
    assert spec.calendar.sessions[-1].session_label > spec.window.scored_sessions[-1]
    assert result.daily_events[-1].payload.close_price == Decimal("100")


@pytest.mark.parametrize(
    "overrides",
    [
        {"fixture": "market"},
        {"fixture": None},
        {"fixture": True},
        {"start": "2026-10-19"},
        {"start": datetime(2026, 10, 19, tzinfo=UTC)},
        {"start": None},
        {"start": date(2026, 10, 17)},
        {"start": date(2026, 10, 18)},
        {"start": date(9999, 12, 30)},
        {"initialized_at": datetime(2026, 10, 21, 13)},
        {"initialized_at": datetime(2026, 10, 21, 9, tzinfo=timezone(timedelta(hours=-4)))},
        {"initialized_at": date(2026, 10, 21)},
        {"initialized_at": "2026-10-21T13:00:00Z"},
        {"initialized_at": None},
        {"session_count": 0},
        {"session_count": 2},
        {"session_count": 5001},
        {"session_count": True},
        {"session_count": 8.0},
        {"pins": ()},
        {"pins": list(_pins())},
        {"pins": tuple(reversed(_pins()))},
        {"pins": _pins()[:-1]},
        {"pins": (_pins()[0], *_pins())},
        {"pins": (None, *_pins()[1:])},
    ],
)
def test_malformed_profiles_native_values_and_overflow_have_one_static_denial(overrides):
    with pytest.raises(ValueError, match=r"^PROSPECTIVE_SYNTHETIC_INPUTS_INVALID$"):
        prospective_synthetic_inputs(**(_values() | overrides))


def test_mutated_pin_is_revalidated_instead_of_trusting_a_frozen_object_label():
    pins = _pins()
    object.__setattr__(pins[0], "sha256", "not-a-digest")
    with pytest.raises(ValueError, match=r"^PROSPECTIVE_SYNTHETIC_INPUTS_INVALID$"):
        prospective_synthetic_inputs(**(_values() | {"pins": pins}))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("warmup_count", 0),
        ("configuration", ReferenceConfiguration(lookback=3)),
        ("initial_cash", Decimal("10001")),
        ("slippage_bps", Decimal("0")),
        ("fee_per_share", Decimal("0")),
        ("live_authorized", True),
        ("source_mode", "recorded_as_observed"),
    ],
)
def test_fixed_profile_does_not_offer_capital_source_or_warmup_knobs(field, value):
    with pytest.raises(TypeError):
        prospective_synthetic_inputs(**(_values() | {field: value}))


# Captured by Root before the converter extraction at aab585df, old Source
# SHA256 96d4295277c21b0220e3f42b939fb61c0f36c73259d99eaaed9e9d5d9930fa57.
# These literals do not derive their expectation from either refactored entrypoint.
@pytest.mark.parametrize(
    ("fixture", "warmup", "byte_count", "digest"),
    [
        ("flat", 0, 19442, "5c0ebce58d93b5e689e18d272cc3d464ee632a9a9ead886ce93807c9ef43a28a"),
        ("flat", 2, 19440, "b1f788d87495f4c265ba090c6331bec8b0a5b9b5fcb000d085a531b6a6c642df"),
        ("flat", 7, 19440, "23e733d17dc2a323c6db93e64ddb0bfa2359e7f57fd2b7008d59a3f552634027"),
        ("regime", 0, 19462, "521bbd61857518c2801d985e1af6cb18e535a393ddb8cc85306be0e59f22c662"),
        ("regime", 2, 19460, "b01fcf6697c66d22a748a023d118ddfad8cd9c5f0dd9e23f9d76e2dd0a46ab7c"),
        ("regime", 7, 19460, "53a9495d52cd81301aa3c0f66876e74b428957874a2a7c556c1d4bedbcc31771"),
    ],
)
def test_original_accelerated_builder_preserves_all_six_full_byte_baselines(
    fixture, warmup, byte_count, digest
):
    result = synthetic_continuous_inputs(
        fixture=fixture, pins=_pins(), session_count=8, warmup_count=warmup
    )
    encoded = encode_record((result.inputs, result.daily_events))
    assert len(encoded) == byte_count
    assert sha256(encoded).hexdigest() == digest
    assert result.inputs.spec.calendar.sessions[0].session_label == date(2023, 1, 2)
    assert len(result.inputs.bootstrap_events) == warmup
    assert len(result.daily_events) == 8 - warmup
    if warmup == 2:
        # A past candidate remains explicit data: this pure path must not read
        # host time or silently replace the caller's 2023 plan with today's dates.
        prospective = prospective_synthetic_inputs(
            fixture=fixture,
            pins=_pins(),
            start=date(2023, 1, 2),
            initialized_at=datetime(2023, 1, 4, 14, tzinfo=UTC),
        )
        prospective_encoded = encode_record((prospective.inputs, prospective.daily_events))
        assert len(prospective_encoded) == byte_count
        assert sha256(prospective_encoded).hexdigest() == digest


def test_original_2023_default_initialization_and_lower_generator_defaults_are_unchanged():
    old = synthetic_continuous_inputs(fixture="flat", pins=_pins())
    assert old.inputs.spec.initialized_at == datetime(2023, 1, 4, 14, tzinfo=UTC)
    assert old.inputs.spec.window.warmup_sessions == (date(2023, 1, 2), date(2023, 1, 3))
    assert old.inputs.spec.calendar.sessions[-1].session_label == date(2023, 1, 12)
    assert old.daily_events[0].economic_at == datetime(2023, 1, 4, 21, tzinfo=UTC)
    assert old.daily_events[0].knowledge_at == datetime(2023, 1, 5, 1, tzinfo=UTC)
    finite = synthetic_engine_inputs(fixture="flat", pins=_pins())
    assert len(finite.spec.evaluation.warmup_sessions) == 252
    assert len(finite.spec.evaluation.scored_sessions) == 268
    assert len(finite.spec.calendar.sessions) == 521
    assert finite.spec.calendar.sessions[0].session_label == date(2023, 1, 2)
    assert finite.spec.initial_cash == Decimal("10000")
    assert finite.spec.execution_policy.slippage_bps == Decimal("5")
    assert finite.spec.execution_policy.fee_per_share == Decimal("0.01")
