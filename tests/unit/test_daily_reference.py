from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import date, datetime, timedelta
from decimal import ROUND_UP, Decimal, Inexact, Rounded, localcontext
from typing import Any

import pytest

from packages.domain.daily_reference import (
    ReferenceConfiguration,
    ReferenceDecision,
    reference_targets,
)
from packages.domain.models import PositionTarget

SPY = "fixture-instrument-spy"
IWM = "fixture-instrument-iwm"
START = date(2025, 2, 3)


def _inputs(count: int = 1) -> dict[str, Any]:
    sessions = tuple(START + timedelta(days=index) for index in range(count))
    return {
        "instrument_symbols": ((SPY, "SPY"),),
        "history": tuple((session, ((SPY, Decimal("100")),)) for session in sessions),
        "expected_sessions": sessions,
        "current_quantities": (),
        "nav": Decimal("10000"),
        "reference_prices": ((SPY, Decimal("100")),),
        "scored_session_index": 0,
        "previously_allocated": False,
    }


def test_literal_buy_hold_sizes_24_whole_shares_and_preserves_explicit_identity() -> None:
    inputs = _inputs()
    result = reference_targets(ReferenceConfiguration(), **inputs)
    assert result == ReferenceDecision((PositionTarget(SPY, "SPY", Decimal("24")),), True, ())
    assert inputs == _inputs()


@pytest.mark.parametrize(
    "updates",
    [
        {"kind": "trend"},
        {"kind": "BUY_HOLD"},
        {"kind": None},
        {"lookback": 0},
        {"lookback": -1},
        {"lookback": True},
        {"lookback": Decimal("200")},
        {"lookback": 200.0},
        {"allocation": Decimal("-0.01")},
        {"allocation": Decimal("0.2500000001")},
        {"allocation": Decimal("NaN")},
        {"allocation": Decimal("sNaN")},
        {"allocation": Decimal("Infinity")},
        {"allocation": Decimal("0.00000000001")},
        {"allocation": 0.25},
        {"rebalance_sessions": 0},
        {"rebalance_sessions": -1},
        {"rebalance_sessions": True},
    ],
)
def test_configuration_rejects_invalid_or_inexact_values(updates: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        ReferenceConfiguration(**updates)


def test_configuration_and_decision_are_immutable_and_allocation_is_canonical() -> None:
    configuration = ReferenceConfiguration(allocation=Decimal("0.2500"))
    assert configuration.allocation.as_tuple() == Decimal("0.25").as_tuple()
    result = reference_targets(configuration, **_inputs())
    with pytest.raises(FrozenInstanceError):
        configuration.lookback = 1  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        result.should_emit = False  # type: ignore[misc]


@pytest.mark.parametrize("current", [Decimal("0"), Decimal("7")])
@pytest.mark.parametrize("last_close", [Decimal("99"), Decimal("100")])
def test_trend_equality_or_below_mean_is_explicit_flat_target(
    current: Decimal, last_close: Decimal
) -> None:
    inputs = _inputs(200)
    inputs["history"] = (
        *inputs["history"][:-1],
        (inputs["expected_sessions"][-1], ((SPY, last_close),)),
    )
    inputs["current_quantities"] = ((SPY, current),)
    result = reference_targets(ReferenceConfiguration(kind="trend_sma"), **inputs)
    assert result == ReferenceDecision((PositionTarget(SPY, "SPY", Decimal("0")),), True, ())


def test_trend_uses_adjusted_close_for_signal_and_distinct_raw_price_for_sizing() -> None:
    inputs = _inputs(200)
    inputs["history"] = (
        *inputs["history"][:-1],
        (inputs["expected_sessions"][-1], ((SPY, Decimal("201")),)),
    )
    inputs["current_quantities"] = ((SPY, Decimal("24")),)
    inputs["previously_allocated"] = True
    inputs["scored_session_index"] = 1
    result = reference_targets(
        ReferenceConfiguration(kind="trend_sma", rebalance_sessions=21), **inputs
    )
    # 201 > (199 * 100 + 201) / 200, but raw reference price remains 100.
    assert result.targets == (PositionTarget(SPY, "SPY", Decimal("24")),)
    assert result.should_emit


@pytest.mark.parametrize("count,emit", [(199, False), (200, True)])
def test_default_trend_requires_200_consecutive_expected_sessions(count: int, emit: bool) -> None:
    result = reference_targets(ReferenceConfiguration(kind="trend_sma"), **_inputs(count))
    assert result.should_emit is emit
    if not emit:
        assert result.targets == ()
        assert result.reasons == (f"INSUFFICIENT_CONTIGUOUS_HISTORY:{SPY}",)


@pytest.mark.parametrize("gap_kind", ["missing_session", "missing_symbol", "none"])
@pytest.mark.parametrize("after_gap,emit", [(199, False), (200, True)])
def test_gap_resets_window_and_only_200_following_sessions_restore_eligibility(
    gap_kind: str, after_gap: int, emit: bool
) -> None:
    inputs = _inputs(after_gap + 2)
    history = list(inputs["history"])
    if gap_kind == "missing_session":
        del history[1]
    elif gap_kind == "missing_symbol":
        history[1] = (inputs["expected_sessions"][1], ())
    else:
        history[1] = (inputs["expected_sessions"][1], ((SPY, None),))
    history[-1] = (inputs["expected_sessions"][-1], ((SPY, Decimal("101")),))
    inputs["history"] = tuple(history)
    inputs["current_quantities"] = ((SPY, Decimal("7")),)
    result = reference_targets(ReferenceConfiguration(kind="trend_sma"), **inputs)
    assert result.should_emit is emit
    assert result.targets == ((PositionTarget(SPY, "SPY", Decimal("24")),) if emit else ())
    if not emit:
        assert result.reasons == (f"INSUFFICIENT_CONTIGUOUS_HISTORY:{SPY}",)


def test_calendar_days_absent_from_expected_sessions_are_not_feature_gaps() -> None:
    sessions = (date(2025, 2, 14), date(2025, 2, 18), date(2025, 2, 19))
    inputs = _inputs()
    inputs["expected_sessions"] = sessions
    inputs["history"] = tuple(
        (session, ((SPY, value),))
        for session, value in zip(
            sessions, (Decimal("100"), Decimal("101"), Decimal("102")), strict=True
        )
    )
    result = reference_targets(ReferenceConfiguration(kind="trend_sma", lookback=3), **inputs)
    assert result.targets == (PositionTarget(SPY, "SPY", Decimal("24")),)


@pytest.mark.parametrize("index,emit", [(0, False), (1, False), (2, False), (3, True), (6, True)])
def test_buy_hold_rebalances_only_at_positive_scored_interval_boundaries(
    index: int, emit: bool
) -> None:
    inputs = _inputs()
    inputs.update(scored_session_index=index, previously_allocated=True)
    result = reference_targets(ReferenceConfiguration(rebalance_sessions=3), **inputs)
    assert result.should_emit is emit
    assert result.reasons == (() if emit else ("REBALANCE_NOT_DUE",))


def test_acknowledged_buy_hold_does_not_reallocate_when_filled_quantity_is_still_zero() -> None:
    inputs = _inputs()
    inputs.update(scored_session_index=100, previously_allocated=True)
    assert reference_targets(ReferenceConfiguration(), **inputs) == ReferenceDecision(
        (), False, ("REBALANCE_NOT_DUE",)
    )


def test_first_allocation_is_not_suppressed_by_rebalance_schedule_or_filled_equality() -> None:
    inputs = _inputs()
    inputs.update(scored_session_index=7, current_quantities=((SPY, Decimal("24")),))
    result = reference_targets(ReferenceConfiguration(rebalance_sessions=3), **inputs)
    assert result.should_emit and result.targets[0].quantity == Decimal("24")


@pytest.mark.parametrize(
    "nav,reason", [(None, "NAV_UNAVAILABLE"), (Decimal("0"), "NAV_NOT_POSITIVE")]
)
def test_unavailable_or_zero_nav_never_becomes_a_liquidation_target(
    nav: Decimal | None, reason: str
) -> None:
    inputs = _inputs()
    inputs.update(nav=nav, current_quantities=((SPY, Decimal("7")),))
    assert reference_targets(ReferenceConfiguration(), **inputs) == ReferenceDecision(
        (), False, (reason,)
    )


@pytest.mark.parametrize("missing", ["price", "close", "session"])
def test_one_configured_instrument_missing_input_blocks_the_entire_target(missing: str) -> None:
    inputs = _inputs()
    inputs["instrument_symbols"] = ((SPY, "SPY"), (IWM, "IWM"))
    inputs["current_quantities"] = ((IWM, Decimal("7")),)
    inputs["reference_prices"] = ((SPY, Decimal("100")), (IWM, Decimal("100")))
    inputs["history"] = ((START, ((SPY, Decimal("100")), (IWM, Decimal("100")))),)
    if missing == "price":
        inputs["reference_prices"] = ((SPY, Decimal("100")),)
        reason = f"REFERENCE_PRICE_UNAVAILABLE:{IWM}"
    elif missing == "close":
        inputs["history"] = ((START, ((SPY, Decimal("100")), (IWM, None))),)
        reason = f"CURRENT_CLOSE_UNAVAILABLE:{IWM}"
    else:
        inputs["expected_sessions"] = (START, START + timedelta(days=1))
        reason = f"CURRENT_CLOSE_UNAVAILABLE:{IWM}"
    result = reference_targets(ReferenceConfiguration(), **inputs)
    assert not result.should_emit and result.targets == ()
    assert reason in result.reasons


def test_empty_calendar_view_is_no_target_not_an_empty_full_portfolio() -> None:
    inputs = _inputs()
    inputs.update(history=(), expected_sessions=(), current_quantities=((SPY, Decimal("7")),))
    assert reference_targets(ReferenceConfiguration(), **inputs) == ReferenceDecision(
        (), False, (f"CURRENT_CLOSE_UNAVAILABLE:{SPY}",)
    )


def test_equal_basket_allocations_return_sorted_full_universe_targets() -> None:
    inputs = _inputs()
    inputs["instrument_symbols"] = ((SPY, "SPY"), (IWM, "IWM"))
    inputs["reference_prices"] = ((SPY, Decimal("100")), (IWM, Decimal("250")))
    inputs["history"] = ((START, ((SPY, Decimal("100")), (IWM, Decimal("250")))),)
    result = reference_targets(ReferenceConfiguration(allocation=Decimal("0.2375")), **inputs)
    assert result.targets == (
        PositionTarget(IWM, "IWM", Decimal("9")),
        PositionTarget(SPY, "SPY", Decimal("23")),
    )
    inputs["instrument_symbols"] = tuple(reversed(inputs["instrument_symbols"]))
    inputs["reference_prices"] = tuple(reversed(inputs["reference_prices"]))
    assert (
        reference_targets(ReferenceConfiguration(allocation=Decimal("0.2375")), **inputs) == result
    )


@pytest.mark.parametrize(
    "allocation,quantity", [(Decimal("0"), Decimal("0")), (Decimal("0.25"), Decimal("25"))]
)
def test_explicit_zero_allocation_and_zero_cost_sizing(
    allocation: Decimal, quantity: Decimal
) -> None:
    inputs = _inputs()
    inputs.update(reserve_fraction=Decimal("0"), fee_per_share=Decimal("0"))
    result = reference_targets(ReferenceConfiguration(allocation=allocation), **inputs)
    assert result.should_emit and result.targets[0].quantity == quantity


def test_sizing_floors_a_near_integer_large_quantity_without_ambient_rounding() -> None:
    inputs = _inputs()
    inputs.update(
        nav=Decimal("999999999999999999.9999999999"),
        reference_prices=((SPY, Decimal("2.5")),),
        reserve_fraction=Decimal("0"),
        fee_per_share=Decimal("0"),
    )
    result = reference_targets(ReferenceConfiguration(), **inputs)
    assert result.targets[0].quantity == Decimal("99999999999999999")


def test_signal_and_sizing_ignore_ambient_decimal_precision_rounding_exponents_and_traps() -> None:
    inputs = _inputs(200)
    inputs["history"] = (
        *inputs["history"][:-1],
        (inputs["expected_sessions"][-1], ((SPY, Decimal("100.0000000001")),)),
    )
    configuration = ReferenceConfiguration(kind="trend_sma")
    expected = reference_targets(configuration, **inputs)
    with localcontext() as context:
        context.prec = 2
        context.rounding = ROUND_UP
        context.Emin = -2
        context.Emax = 2
        context.traps[Inexact] = True
        context.traps[Rounded] = True
        assert reference_targets(configuration, **inputs) == expected
    assert expected.targets[0].quantity == Decimal("24")


@pytest.mark.parametrize(
    "key,value",
    [
        ("nav", Decimal("-1")),
        ("nav", Decimal("NaN")),
        ("nav", Decimal("Infinity")),
        ("nav", 10000),
        ("reserve_fraction", Decimal("-0.01")),
        ("reserve_fraction", Decimal("sNaN")),
        ("fee_per_share", Decimal("-0.01")),
        ("fee_per_share", 0.01),
        ("scored_session_index", -1),
        ("scored_session_index", True),
        ("previously_allocated", 1),
        ("reference_prices", ((SPY, Decimal("0")),)),
        ("reference_prices", ((SPY, Decimal("-1")),)),
        ("reference_prices", ((SPY, Decimal("NaN")),)),
        ("reference_prices", ((SPY, None),)),
        ("reference_prices", ((SPY, Decimal("100")), (SPY, Decimal("101")))),
        ("current_quantities", ((SPY, Decimal("-1")),)),
        ("current_quantities", ((SPY, Decimal("0.5")),)),
        ("current_quantities", ((SPY, 1),)),
        ("current_quantities", (("unconfigured", Decimal("1")),)),
        ("instrument_symbols", ()),
        ("instrument_symbols", ((SPY, "spy"),)),
        ("instrument_symbols", ((SPY, "AAPL"),)),
        ("instrument_symbols", ((SPY, "SPY"), (SPY, "IWM"))),
        ("instrument_symbols", ((SPY, "SPY"), (IWM, "SPY"))),
        ("expected_sessions", (START, START)),
        ("expected_sessions", (START + timedelta(days=1), START)),
        ("expected_sessions", (datetime(2025, 2, 3),)),
        ("history", ((START, ((SPY, Decimal("0")),)),)),
        ("history", ((START, ((SPY, Decimal("NaN")),)),)),
        ("history", ((START, (("unconfigured", Decimal("100")),)),)),
        ("history", ((START, ((SPY, Decimal("100")), (SPY, Decimal("100")))),)),
        ("history", ((START, ()), (START, ()))),
        ("history", ((START + timedelta(days=1), ((SPY, Decimal("100")),)),)),
        ("history", [(START, ((SPY, Decimal("100")),))]),
    ],
)
def test_invalid_or_out_of_scope_inputs_reject_without_targets(key: str, value: Any) -> None:
    inputs = _inputs()
    inputs[key] = value
    with pytest.raises(ValueError):
        reference_targets(ReferenceConfiguration(), **inputs)


def test_reference_decision_cannot_disguise_missing_data_as_a_liquidation() -> None:
    with pytest.raises(ValueError):
        ReferenceDecision((PositionTarget(SPY, "SPY", Decimal("0")),), False, ("MISSING",))
    with pytest.raises(ValueError):
        ReferenceDecision((), True, ())
    with pytest.raises(ValueError):
        ReferenceDecision((), False, ())
