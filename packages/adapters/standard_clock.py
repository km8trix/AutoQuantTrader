"""Standard UTC/monotonic health with explicit simulated or unavailable evidence.

Host UTC-vs-monotonic agreement detects steps and pauses; it cannot measure UTC
synchronization. A qualified host offset/uncertainty producer is injected. Its
absence is blocked, never fabricated as zero drift. No native enrollment or
network/time-service request occurs here.

The personal-v1 equality policy differs from the historical trusted-time
reducer: warning >=250ms, block >=1s, freshness/cadence >=30s. The old reducer
and its authenticated historical evidence remain unchanged.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from packages.application.personal_runtime import ClockHealthSnapshot, ClockHealthStatus
from packages.domain.clock import SystemClock

STANDARD_CLOCK_POLICY_VERSION = "personal-v1-clock-1"
WARNING_NS = 250_000_000
BLOCK_NS = 1_000_000_000
MAX_SAMPLE_AGE_NS = 30_000_000_000
MAX_SAMPLING_DURATION_NS = 1_000_000_000
HEALTHY_RECOVERY_NS = 60_000_000_000


def _utc(instant: datetime) -> datetime:
    if (
        type(instant) is not datetime
        or instant.tzinfo is None
        or instant.utcoffset() != timedelta(0)
    ):
        raise ValueError("clock must return aware UTC")
    return instant.astimezone(UTC)


def _nanoseconds(value: int) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("monotonic clock must return nonnegative integer nanoseconds")
    return value


def _elapsed_ns(start: datetime, end: datetime) -> int:
    delta = end - start
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


@dataclass(frozen=True, slots=True)
class TimeSourceMeasurement:
    """An already measured source offset bound, with its actual observation time."""

    source_id: str
    observed_at_utc: datetime
    observed_monotonic_ns: int
    offset_ns: int
    uncertainty_ns: int

    def __post_init__(self) -> None:
        if (
            type(self.source_id) is not str
            or not self.source_id
            or len(self.source_id) > 128
            or any(not char.isprintable() for char in self.source_id)
        ):
            raise ValueError("time source requires a bounded printable identity")
        _utc(self.observed_at_utc)
        _nanoseconds(self.observed_monotonic_ns)
        if type(self.offset_ns) is not int:
            raise ValueError("source offset must be integer nanoseconds")
        _nanoseconds(self.uncertainty_ns)


TimeSource = Callable[[datetime, int], TimeSourceMeasurement | None]


class StandardClock:
    def __init__(
        self,
        *,
        utc_now: Callable[[], datetime] | None = None,
        monotonic_now_ns: Callable[[], int] | None = None,
        epoch_provider: Callable[[], str] | None = None,
        source: TimeSource | None = None,
        simulated_health: bool = False,
    ) -> None:
        if simulated_health and source is not None:
            raise ValueError("simulated health cannot relabel a supplied host time source")
        self._utc_now = utc_now if utc_now is not None else SystemClock().now
        self._monotonic_now_ns = monotonic_now_ns or time.monotonic_ns
        process_id = uuid4().hex
        self._epoch_provider = epoch_provider or (lambda: f"{process_id}:{os.getpid()}")
        self._source = source
        self._simulated_health = simulated_health
        self._previous: tuple[datetime, int, str] | None = None
        self._source_id: str | None = None
        self._healthy_since: int | None = None
        self._latched_reasons: set[str] = set()
        self._sequence = 0

    def now(self) -> datetime:
        return _utc(self._utc_now())

    def monotonic_ns(self) -> int:
        return _nanoseconds(self._monotonic_now_ns())

    def health_snapshot(self) -> ClockHealthSnapshot:
        """Sample and classify; no result clears a fault latch or authorizes re-arm."""
        self._sequence += 1
        reasons: set[str] = set()
        instant: datetime | None = None
        mono: int | None = None
        epoch: str | None = None
        measurement: TimeSourceMeasurement | None = None
        duration: int | None = None
        age: int | None = None
        try:
            started = self.monotonic_ns()
            started_utc = self.now()
            epoch = self._epoch_provider()
            if type(epoch) is not str or not epoch or len(epoch) > 128:
                raise ValueError("clock epoch is unavailable")
            if self._simulated_health:
                measurement = TimeSourceMeasurement(
                    "explicit-simulation-time-model", started_utc, started, 0, 0
                )
            elif self._source is not None:
                measurement = self._source(started_utc, started)
            instant = self.now()
            mono = self.monotonic_ns()
            duration = mono - started
            if duration < 0:
                reasons.add("monotonic_regression")
            elif duration >= MAX_SAMPLING_DURATION_NS:
                reasons.add("sampling_timeout")
            wall_duration = _elapsed_ns(started_utc, instant)
            if wall_duration < 0:
                reasons.add("utc_regression")
            if abs(wall_duration - duration) >= WARNING_NS:
                reasons.add("utc_monotonic_disagreement")
            if self._previous is not None:
                previous_utc, previous_mono, previous_epoch = self._previous
                wall_elapsed = _elapsed_ns(previous_utc, instant)
                elapsed = mono - previous_mono
                if previous_epoch != epoch:
                    reasons.add("epoch_changed")
                if wall_elapsed < 0:
                    reasons.add("utc_regression")
                if elapsed < 0:
                    reasons.add("monotonic_regression")
                if max(wall_elapsed, elapsed) >= MAX_SAMPLE_AGE_NS:
                    reasons.add("suspend_or_cadence_gap")
                if abs(wall_elapsed - elapsed) >= WARNING_NS:
                    reasons.add("utc_monotonic_disagreement")
            self._previous = (instant, mono, epoch)
            if measurement is None:
                reasons.add("source_unavailable")
            else:
                if type(measurement) is not TimeSourceMeasurement:
                    raise ValueError("invalid time source measurement")
                measurement.__post_init__()
                monotonic_age = mono - measurement.observed_monotonic_ns
                utc_age = _elapsed_ns(measurement.observed_at_utc, instant)
                age = max(monotonic_age, utc_age)
                if min(monotonic_age, utc_age) < 0:
                    reasons.add("future_sample")
                if age >= MAX_SAMPLE_AGE_NS:
                    reasons.add("sample_stale")
                if abs(monotonic_age - utc_age) >= WARNING_NS:
                    reasons.add("source_clock_disagreement")
                if self._source_id is not None and self._source_id != measurement.source_id:
                    reasons.add("source_changed")
                self._source_id = measurement.source_id
                magnitude = abs(measurement.offset_ns) + measurement.uncertainty_ns
                if magnitude >= BLOCK_NS:
                    reasons.add("offset_blocked")
                elif magnitude >= WARNING_NS:
                    reasons.add("offset_warning")
        except Exception:
            reasons.add("clock_or_source_unavailable")
            measurement = None

        blocking = reasons - {"offset_warning"}
        self._latched_reasons.update(blocking)
        if reasons or mono is None:
            self._healthy_since = None
        elif self._healthy_since is None:
            self._healthy_since = mono
        recovery_ready = (
            mono is not None
            and self._healthy_since is not None
            and mono - self._healthy_since >= HEALTHY_RECOVERY_NS
        )
        if self._latched_reasons:
            status = ClockHealthStatus.BLOCKED
            reasons.update(self._latched_reasons)
            reasons.add("fault_latched_rearm_required")
        elif "offset_warning" in reasons:
            status = ClockHealthStatus.WARNING
        elif not recovery_ready:
            status = ClockHealthStatus.BLOCKED
            reasons.add("startup_qualifying")
        else:
            status = ClockHealthStatus.HEALTHY
            reasons.add("within_limit")
        return ClockHealthSnapshot(
            status=status,
            reasons=tuple(sorted(reasons)),
            evidence_class=(
                "simulated"
                if self._simulated_health
                else "unavailable"
                if measurement is None
                else "host-measurement"
            ),
            source_id=measurement.source_id if measurement is not None else None,
            observed_at_utc=instant,
            observed_monotonic_ns=mono,
            source_observed_at_utc=(
                measurement.observed_at_utc if measurement is not None else None
            ),
            source_observed_monotonic_ns=(
                measurement.observed_monotonic_ns if measurement is not None else None
            ),
            epoch=epoch,
            sequence=self._sequence,
            offset_ns=measurement.offset_ns if measurement is not None else None,
            uncertainty_ns=measurement.uncertainty_ns if measurement is not None else None,
            sampling_duration_ns=duration,
            sample_age_ns=age,
            recovery_ready=recovery_ready,
        )
