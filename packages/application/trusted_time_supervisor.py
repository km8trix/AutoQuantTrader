"""Pure fixed-grid supervision for durable trusted-time probes.

The core owns only monotonic scheduling.  Process sleep, stop signaling, clocks,
and the already durable one-shot probe are injected.  A returned result means
the injected stop predicate ended supervision cleanly; dependency, clock, or
durable-probe failures raise a sanitized fatal error and are never retried.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from packages.application.durable_trusted_time_monitor import PersistedTrustedTimeProbe

TRUSTED_TIME_SUPERVISOR_CONTRACT_VERSION = "phase6c-fixed-grid-trusted-time-supervision-v1"
TRUSTED_TIME_SUPERVISOR_INTERVAL_NS = 20_000_000_000


class TrustedTimeSupervisorError(RuntimeError):
    """Fixed-grid supervision failed closed and grants no authority."""


class DurableTrustedTimeProbe(Protocol):
    def __call__(self) -> PersistedTrustedTimeProbe: ...


class SupervisorMonotonicClock(Protocol):
    def __call__(self) -> int: ...


class SupervisorDeadlineWaiter(Protocol):
    def __call__(self, *, deadline_monotonic_ns: int) -> object: ...


class SupervisorStopPredicate(Protocol):
    def __call__(self) -> bool: ...


def _authority_is_never_granted(_: object) -> bool:
    return False


@dataclass(frozen=True, slots=True)
class TrustedTimeSupervisorEvent:
    """Bounded process-local projection of one completed durable tick."""

    probe_sequence: int
    scheduled_monotonic_ns: int
    observed_monotonic_ns: int
    persisted_probe: PersistedTrustedTimeProbe

    def __post_init__(self) -> None:
        if type(self.probe_sequence) is not int or self.probe_sequence <= 0:
            raise TrustedTimeSupervisorError(
                "trusted-time supervisor probe sequence must be positive"
            )
        for value, field_name in (
            (self.scheduled_monotonic_ns, "scheduled monotonic instant"),
            (self.observed_monotonic_ns, "observed monotonic instant"),
        ):
            if type(value) is not int or value < 0:
                raise TrustedTimeSupervisorError(
                    f"trusted-time supervisor {field_name} must be a non-negative integer"
                )
        if self.observed_monotonic_ns < self.scheduled_monotonic_ns:
            raise TrustedTimeSupervisorError(
                "trusted-time supervisor event predates its scheduled tick"
            )
        if type(self.persisted_probe) is not PersistedTrustedTimeProbe:
            raise TrustedTimeSupervisorError("trusted-time supervisor durable result must be exact")
        try:
            self.persisted_probe.__post_init__()
        except Exception:
            raise TrustedTimeSupervisorError(
                "trusted-time supervisor durable result is invalid"
            ) from None

    @property
    def overdue_by_ns(self) -> int:
        return self.observed_monotonic_ns - self.scheduled_monotonic_ns

    operational_control_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)


@dataclass(frozen=True, slots=True)
class TrustedTimeSupervisorResult:
    """Graceful-stop result retaining only the latest completed event."""

    probe_count: int
    last_event: TrustedTimeSupervisorEvent | None

    def __post_init__(self) -> None:
        if type(self.probe_count) is not int or self.probe_count < 0:
            raise TrustedTimeSupervisorError(
                "trusted-time supervisor probe count must be a non-negative integer"
            )
        if self.last_event is None:
            if self.probe_count != 0:
                raise TrustedTimeSupervisorError(
                    "trusted-time supervisor result lost its latest event"
                )
        elif type(self.last_event) is not TrustedTimeSupervisorEvent:
            raise TrustedTimeSupervisorError("trusted-time supervisor latest event must be exact")
        else:
            try:
                self.last_event.__post_init__()
            except Exception:
                raise TrustedTimeSupervisorError(
                    "trusted-time supervisor latest event is invalid"
                ) from None
            if self.last_event.probe_sequence != self.probe_count:
                raise TrustedTimeSupervisorError(
                    "trusted-time supervisor latest event conflicts with probe count"
                )

    operational_control_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)


def _require_callable(value: object, field_name: str) -> object:
    if not callable(value):
        raise TrustedTimeSupervisorError(f"trusted-time supervisor {field_name} is unavailable")
    return value


def _read_monotonic_ns(clock: SupervisorMonotonicClock) -> int:
    try:
        value = clock()
    except Exception:
        raise TrustedTimeSupervisorError("trusted-time supervisor monotonic clock failed") from None
    if type(value) is not int or value < 0:
        raise TrustedTimeSupervisorError(
            "trusted-time supervisor monotonic clock returned an invalid instant"
        )
    return value


def _stop_requested(predicate: SupervisorStopPredicate) -> bool:
    try:
        value = predicate()
    except Exception:
        raise TrustedTimeSupervisorError("trusted-time supervisor stop predicate failed") from None
    if type(value) is not bool:
        raise TrustedTimeSupervisorError(
            "trusted-time supervisor stop predicate returned an invalid value"
        )
    return value


def _wait_until(
    waiter: SupervisorDeadlineWaiter,
    *,
    deadline_monotonic_ns: int,
) -> None:
    try:
        waiter(deadline_monotonic_ns=deadline_monotonic_ns)
    except Exception:
        raise TrustedTimeSupervisorError("trusted-time supervisor wait failed") from None


def _run_durable_probe(probe: DurableTrustedTimeProbe) -> PersistedTrustedTimeProbe:
    try:
        result = probe()
    except Exception:
        raise TrustedTimeSupervisorError("trusted-time supervisor durable probe failed") from None
    if type(result) is not PersistedTrustedTimeProbe:
        raise TrustedTimeSupervisorError(
            "trusted-time supervisor durable probe returned a noncanonical result"
        )
    try:
        result.__post_init__()
    except Exception:
        raise TrustedTimeSupervisorError(
            "trusted-time supervisor durable probe returned an invalid result"
        ) from None
    return result


def _stopped_result(
    *,
    probe_count: int,
    last_event: TrustedTimeSupervisorEvent | None,
) -> TrustedTimeSupervisorResult:
    return TrustedTimeSupervisorResult(
        probe_count=probe_count,
        last_event=last_event,
    )


def run_trusted_time_supervisor(
    *,
    durable_probe: DurableTrustedTimeProbe,
    monotonic_clock: SupervisorMonotonicClock,
    waiter: SupervisorDeadlineWaiter,
    stop_requested: SupervisorStopPredicate,
) -> TrustedTimeSupervisorResult:
    """Run immediate and fixed-grid durable probes until cleanly stopped.

    The first probe is scheduled at the initial monotonic instant.  Later
    deadlines stay on that absolute 20-second grid.  An early waiter return is
    observed but never probes.  After every successful probe, its completion is
    observed and the next deadline advances directly to the first grid boundary
    after completion, skipping catch-up work even when the probe spans a
    boundary or the host suspends while it runs.
    """

    exact_probe = cast(
        DurableTrustedTimeProbe,
        _require_callable(durable_probe, "durable probe"),
    )
    exact_clock = cast(
        SupervisorMonotonicClock,
        _require_callable(monotonic_clock, "monotonic clock"),
    )
    exact_waiter = cast(
        SupervisorDeadlineWaiter,
        _require_callable(waiter, "deadline waiter"),
    )
    exact_stop = cast(
        SupervisorStopPredicate,
        _require_callable(stop_requested, "stop predicate"),
    )

    anchor_monotonic_ns = _read_monotonic_ns(exact_clock)
    last_observed_monotonic_ns = anchor_monotonic_ns
    probe_count = 0
    last_event: TrustedTimeSupervisorEvent | None = None

    if _stop_requested(exact_stop):
        return _stopped_result(probe_count=probe_count, last_event=last_event)

    persisted = _run_durable_probe(exact_probe)
    completed_monotonic_ns = _read_monotonic_ns(exact_clock)
    if completed_monotonic_ns < last_observed_monotonic_ns:
        raise TrustedTimeSupervisorError("trusted-time supervisor monotonic clock regressed")
    last_observed_monotonic_ns = completed_monotonic_ns
    probe_count += 1
    last_event = TrustedTimeSupervisorEvent(
        probe_sequence=probe_count,
        scheduled_monotonic_ns=anchor_monotonic_ns,
        observed_monotonic_ns=anchor_monotonic_ns,
        persisted_probe=persisted,
    )
    completed_intervals = (
        completed_monotonic_ns - anchor_monotonic_ns
    ) // TRUSTED_TIME_SUPERVISOR_INTERVAL_NS
    next_tick_monotonic_ns = (
        anchor_monotonic_ns + (completed_intervals + 1) * TRUSTED_TIME_SUPERVISOR_INTERVAL_NS
    )

    while True:
        if _stop_requested(exact_stop):
            return _stopped_result(probe_count=probe_count, last_event=last_event)

        _wait_until(
            exact_waiter,
            deadline_monotonic_ns=next_tick_monotonic_ns,
        )

        # A stop raised while waiting wins before another clock read or probe.
        if _stop_requested(exact_stop):
            return _stopped_result(probe_count=probe_count, last_event=last_event)

        observed_monotonic_ns = _read_monotonic_ns(exact_clock)
        if observed_monotonic_ns < last_observed_monotonic_ns:
            raise TrustedTimeSupervisorError("trusted-time supervisor monotonic clock regressed")
        last_observed_monotonic_ns = observed_monotonic_ns

        if observed_monotonic_ns < next_tick_monotonic_ns:
            continue

        persisted = _run_durable_probe(exact_probe)
        completed_monotonic_ns = _read_monotonic_ns(exact_clock)
        if completed_monotonic_ns < last_observed_monotonic_ns:
            raise TrustedTimeSupervisorError("trusted-time supervisor monotonic clock regressed")
        last_observed_monotonic_ns = completed_monotonic_ns
        probe_count += 1
        last_event = TrustedTimeSupervisorEvent(
            probe_sequence=probe_count,
            scheduled_monotonic_ns=next_tick_monotonic_ns,
            observed_monotonic_ns=observed_monotonic_ns,
            persisted_probe=persisted,
        )

        elapsed_intervals = (
            completed_monotonic_ns - next_tick_monotonic_ns
        ) // TRUSTED_TIME_SUPERVISOR_INTERVAL_NS
        next_tick_monotonic_ns += (elapsed_intervals + 1) * TRUSTED_TIME_SUPERVISOR_INTERVAL_NS


__all__ = [
    "TRUSTED_TIME_SUPERVISOR_CONTRACT_VERSION",
    "TRUSTED_TIME_SUPERVISOR_INTERVAL_NS",
    "DurableTrustedTimeProbe",
    "SupervisorDeadlineWaiter",
    "SupervisorMonotonicClock",
    "SupervisorStopPredicate",
    "TrustedTimeSupervisorError",
    "TrustedTimeSupervisorEvent",
    "TrustedTimeSupervisorResult",
    "run_trusted_time_supervisor",
]
