"""Pure prospective synthetic planning; supplied UTC is data, not clock evidence.

The explicit weekday start is the first of two warmup sessions. The existing
synthetic calendar models weekdays, not exchange holidays or bank settlement.
No current time is sampled and no account, capture, lease or authority is created.
Actual initialization must construct its own spec/closure from retained captures
and recompile at its independently observed initialization boundary.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from packages.application.personal_inputs import synthetic_engine_inputs
from packages.application.synthetic_continuous_inputs import (
    SyntheticContinuousInputs,
    _continuous_from_finite,
)
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.personal_contracts import VersionPin, require_utc


def _require_fixture(value: object) -> None:
    if type(value) is not str or value not in ("flat", "regime"):
        raise ValueError("invalid prospective fixture")


def prospective_synthetic_inputs(
    *,
    fixture: Literal["flat", "regime"],
    pins: tuple[VersionPin, ...],
    start: date,
    initialized_at: datetime,
    session_count: int = 8,
) -> SyntheticContinuousInputs:
    """Plan the existing one-SPY, lookback2, two-warmup engineering profile.

    ``initialized_at`` is an explicit candidate, never authenticated actual time.
    Complete warmup may be known at that candidate; the first scored close must
    still follow it. Rejection never rolls dates or truncates the requested plan.
    Financial defaults and the generator's 5000-session bound remain unchanged.
    """
    try:
        _require_fixture(fixture)
        if (
            type(start) is not date
            or start.weekday() >= 5
            or type(session_count) is not int
            or not 3 <= session_count <= 5000
            or type(pins) is not tuple
            or any(type(pin) is not VersionPin for pin in pins)
        ):
            raise ValueError("invalid prospective input values")
        require_utc(initialized_at, "initialization candidate")
        for pin in pins:
            pin.__post_init__()
        finite = synthetic_engine_inputs(
            fixture=fixture,
            pins=pins,
            start=start,
            session_count=session_count,
            warmup_count=2,
            configuration=ReferenceConfiguration(lookback=2),
        )
        # The original contracts enforce complete warmup <= initialization,
        # initialization < first scored close, and a following execution horizon.
        # The shared conversion removes retrospective execution proxies exactly
        # as in the existing modeled builder; no financial engine is duplicated.
        return _continuous_from_finite(finite, initialized_at=initialized_at)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("PROSPECTIVE_SYNTHETIC_INPUTS_INVALID") from None
