from datetime import UTC, datetime, timedelta
from typing import NoReturn

import pytest

from packages.adapters.standard_clock import (
    StandardClock,
    TimeSourceMeasurement,
)
from packages.application.personal_runtime import ClockHealthStatus


class ManualTime:
    def __init__(self) -> None:
        self.utc = datetime(2026, 9, 8, 12, tzinfo=UTC)
        self.mono = 100_000_000_000
        self.epoch = "test-process-one"
        self.offset = 0
        self.uncertainty = 0

    def advance(self, seconds: int) -> None:
        self.utc += timedelta(seconds=seconds)
        self.mono += seconds * 1_000_000_000

    def source(self, utc: datetime, mono: int) -> TimeSourceMeasurement:
        return TimeSourceMeasurement("test-source", utc, mono, self.offset, self.uncertainty)

    def clock(self, *, simulated: bool = False) -> StandardClock:
        return StandardClock(
            utc_now=lambda: self.utc,
            monotonic_now_ns=lambda: self.mono,
            epoch_provider=lambda: self.epoch,
            source=None if simulated else self.source,
            simulated_health=simulated,
        )


def test_standard_clock_has_utc_and_monotonic_but_does_not_invent_host_drift() -> None:
    clock = StandardClock()
    assert clock.now().utcoffset() == timedelta(0)
    assert clock.monotonic_ns() >= 0
    snapshot = clock.health_snapshot()
    assert snapshot.status is ClockHealthStatus.BLOCKED
    assert "source_unavailable" in snapshot.reasons
    assert snapshot.offset_ns is None
    assert snapshot.uncertainty_ns is None
    assert snapshot.evidence_class == "unavailable"
    assert snapshot.rearm_required


def test_simulated_time_requires_explicit_label_and_sixty_healthy_seconds() -> None:
    manual = ManualTime()
    clock = manual.clock(simulated=True)
    first = clock.health_snapshot()
    assert first.status is ClockHealthStatus.BLOCKED
    assert first.reasons == ("startup_qualifying",)
    assert first.evidence_class == "simulated"
    assert first.offset_ns == first.uncertainty_ns == 0
    for _ in range(5):
        manual.advance(10)
        assert not clock.health_snapshot().recovery_ready
    manual.advance(10)
    recovered = clock.health_snapshot()
    assert recovered.status is ClockHealthStatus.HEALTHY
    assert recovered.recovery_ready
    assert recovered.rearm_required
    assert recovered.sequence == 7
    assert recovered.sampling_duration_ns == recovered.sample_age_ns == 0


@pytest.mark.parametrize(
    ("offset", "uncertainty", "expected"),
    [
        (249_999_999, 0, "startup_qualifying"),
        (250_000_000, 0, "offset_warning"),
        (-249_000_000, 1_000_000, "offset_warning"),
        (999_999_999, 0, "offset_warning"),
        (999_000_000, 1_000_000, "offset_blocked"),
        (-1_000_000_000, 0, "offset_blocked"),
    ],
)
def test_offset_plus_uncertainty_equality_boundaries(
    offset: int, uncertainty: int, expected: str
) -> None:
    manual = ManualTime()
    manual.offset = offset
    manual.uncertainty = uncertainty
    snapshot = manual.clock().health_snapshot()
    assert expected in snapshot.reasons
    if expected == "offset_blocked":
        assert snapshot.status is ClockHealthStatus.BLOCKED


@pytest.mark.parametrize(
    ("wall_delta", "mono_delta", "reason"),
    [
        (-1, 1, "utc_regression"),
        (1, -1, "monotonic_regression"),
        (60, 1, "suspend_or_cadence_gap"),
        (60, 60, "suspend_or_cadence_gap"),
        (30, 30, "suspend_or_cadence_gap"),
        (1, 2, "utc_monotonic_disagreement"),
    ],
)
def test_regression_and_both_suspend_clock_behaviors_latch(
    wall_delta: int, mono_delta: int, reason: str
) -> None:
    manual = ManualTime()
    clock = manual.clock()
    clock.health_snapshot()
    manual.utc += timedelta(seconds=wall_delta)
    manual.mono += mono_delta * 1_000_000_000
    failed = clock.health_snapshot()
    assert failed.status is ClockHealthStatus.BLOCKED
    assert reason in failed.reasons
    for _ in range(7):
        manual.advance(10)
        recovered = clock.health_snapshot()
    assert recovered.recovery_ready
    assert recovered.status is ClockHealthStatus.BLOCKED
    assert reason in recovered.reasons
    assert recovered.rearm_required


def test_epoch_change_and_source_change_are_blocked() -> None:
    manual = ManualTime()
    clock = manual.clock()
    clock.health_snapshot()
    manual.epoch = "test-process-two"
    manual.advance(1)
    assert "epoch_changed" in clock.health_snapshot().reasons
    source_id = "one"
    clock = StandardClock(
        utc_now=lambda: manual.utc,
        monotonic_now_ns=lambda: manual.mono,
        source=lambda utc, mono: TimeSourceMeasurement(source_id, utc, mono, 0, 0),
    )
    clock.health_snapshot()
    source_id = "two"
    assert "source_changed" in clock.health_snapshot().reasons


@pytest.mark.parametrize("seconds", [29, 30])
def test_source_observation_age_is_not_rewritten_to_poll_time(seconds: int) -> None:
    manual = ManualTime()
    measurement = manual.source(manual.utc, manual.mono)
    clock = StandardClock(
        utc_now=lambda: manual.utc,
        monotonic_now_ns=lambda: manual.mono,
        source=lambda utc, mono: measurement,
    )
    clock.health_snapshot()
    manual.advance(20)
    clock.health_snapshot()
    manual.advance(seconds - 20)
    snapshot = clock.health_snapshot()
    assert snapshot.sample_age_ns == seconds * 1_000_000_000
    assert snapshot.source_observed_at_utc == measurement.observed_at_utc
    assert snapshot.source_observed_monotonic_ns == measurement.observed_monotonic_ns
    assert snapshot.observed_at_utc == manual.utc
    assert ("sample_stale" in snapshot.reasons) == (seconds == 30)


def test_future_source_observation_is_blocked() -> None:
    manual = ManualTime()
    clock = StandardClock(
        utc_now=lambda: manual.utc,
        monotonic_now_ns=lambda: manual.mono,
        source=lambda utc, mono: TimeSourceMeasurement(
            "future", utc + timedelta(microseconds=1), mono + 1000, 0, 0
        ),
    )
    assert "future_sample" in clock.health_snapshot().reasons


def test_slow_sample_at_timeout_equality_is_blocked() -> None:
    manual = ManualTime()

    def slow(utc: datetime, mono: int) -> TimeSourceMeasurement:
        manual.advance(1)
        return manual.source(utc, mono)

    clock = StandardClock(
        utc_now=lambda: manual.utc, monotonic_now_ns=lambda: manual.mono, source=slow
    )
    snapshot = clock.health_snapshot()
    assert snapshot.sampling_duration_ns == 1_000_000_000
    assert "sampling_timeout" in snapshot.reasons


@pytest.mark.parametrize("failure", ["utc", "monotonic", "source"])
def test_unavailable_clocks_and_sources_fail_closed_without_exception_text(failure: str) -> None:
    manual = ManualTime()

    def broken() -> NoReturn:
        raise RuntimeError("private sentinel must never appear")

    clock = StandardClock(
        utc_now=(lambda: datetime(2026, 9, 8)) if failure == "utc" else lambda: manual.utc,
        monotonic_now_ns=broken if failure == "monotonic" else lambda: manual.mono,
        source=(lambda utc, mono: broken()) if failure == "source" else manual.source,
    )
    snapshot = clock.health_snapshot()
    assert snapshot.status is ClockHealthStatus.BLOCKED
    assert "clock_or_source_unavailable" in snapshot.reasons
    assert "private sentinel" not in str(snapshot.as_dict())


def test_simulation_flag_cannot_relabel_a_real_measurement_source() -> None:
    with pytest.raises(ValueError, match="cannot relabel"):
        StandardClock(simulated_health=True, source=ManualTime().source)
