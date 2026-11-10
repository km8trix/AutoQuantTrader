from __future__ import annotations

from dataclasses import fields
from datetime import UTC, datetime

import pytest

from packages.application.durable_trusted_time_monitor import PersistedTrustedTimeProbe
from packages.application.trusted_time_monitor import (
    TrustedTimeMonitorResult,
    TrustedTimeProbeStatus,
)
from packages.application.trusted_time_supervisor import (
    TRUSTED_TIME_SUPERVISOR_CONTRACT_VERSION,
    TRUSTED_TIME_SUPERVISOR_INTERVAL_NS,
    TrustedTimeSupervisorError,
    TrustedTimeSupervisorEvent,
    TrustedTimeSupervisorResult,
    run_trusted_time_supervisor,
)
from packages.domain.trusted_time import evaluate_trusted_time

BASE = datetime(2026, 7, 31, 18, 0, tzinfo=UTC)


def _persisted(sequence: int) -> PersistedTrustedTimeProbe:
    result = TrustedTimeMonitorResult(
        status=TrustedTimeProbeStatus.SOURCE_UNAVAILABLE,
        evaluation=evaluate_trusted_time(
            None,
            None,
            evaluated_at_utc=BASE,
            evaluated_at_monotonic_ns=sequence,
        ),
    )
    return PersistedTrustedTimeProbe(
        result=result,
        evaluation_sequence=sequence,
        record_sha256=f"{sequence:064x}",
        host_head_sha256=f"{sequence + 100:064x}",
    )


class SequenceClock:
    def __init__(self, *values: object) -> None:
        self.values = list(values)
        self.calls = 0

    def __call__(self) -> object:
        self.calls += 1
        if not self.values:
            raise RuntimeError("secret exhausted clock")
        return self.values.pop(0)


class Probe:
    def __init__(
        self,
        *,
        failure_on_call: int | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.calls = 0
        self.failure_on_call = failure_on_call
        self.failure = failure

    def __call__(self) -> PersistedTrustedTimeProbe:
        self.calls += 1
        if self.calls == self.failure_on_call:
            raise self.failure or RuntimeError("secret durable failure")
        return _persisted(self.calls)


class Waiter:
    def __init__(self, *actions: object) -> None:
        self.actions = list(actions)
        self.deadlines: list[int] = []

    def __call__(self, *, deadline_monotonic_ns: int) -> None:
        self.deadlines.append(deadline_monotonic_ns)
        if self.actions:
            action = self.actions.pop(0)
            if isinstance(action, Exception):
                raise action
            if callable(action):
                action()


def _stop_after_probe(probe: Probe, target: int) -> object:
    return lambda: probe.calls >= target


def _run(
    probe: object,
    clock: object,
    waiter: object,
    stop: object,
) -> TrustedTimeSupervisorResult:
    return run_trusted_time_supervisor(
        durable_probe=probe,  # type: ignore[arg-type]
        monotonic_clock=clock,  # type: ignore[arg-type]
        waiter=waiter,  # type: ignore[arg-type]
        stop_requested=stop,  # type: ignore[arg-type]
    )


def test_startup_probe_is_immediate_and_uses_initial_grid_anchor() -> None:
    anchor = 137
    probe = Probe()
    clock = SequenceClock(anchor, anchor)
    waiter = Waiter()

    result = _run(probe, clock, waiter, _stop_after_probe(probe, 1))

    assert probe.calls == 1
    assert clock.calls == 2
    assert waiter.deadlines == []
    assert result.probe_count == 1
    assert result.last_event is not None
    assert result.last_event.scheduled_monotonic_ns == anchor
    assert result.last_event.observed_monotonic_ns == anchor
    assert result.last_event.overdue_by_ns == 0


def test_long_startup_probe_skips_boundaries_crossed_before_completion() -> None:
    anchor = 137
    completed = anchor + TRUSTED_TIME_SUPERVISOR_INTERVAL_NS
    stopped = False

    def stop_during_first_wait() -> None:
        nonlocal stopped
        stopped = True

    probe = Probe()
    clock = SequenceClock(anchor, completed)
    waiter = Waiter(stop_during_first_wait)

    result = _run(probe, clock, waiter, lambda: stopped)

    assert probe.calls == 1
    assert waiter.deadlines == [
        anchor + 2 * TRUSTED_TIME_SUPERVISOR_INTERVAL_NS,
    ]
    assert result.last_event is not None
    assert result.last_event.scheduled_monotonic_ns == anchor
    assert result.last_event.observed_monotonic_ns == anchor
    assert result.last_event.overdue_by_ns == 0


def test_spurious_early_waiter_returns_repeat_deadline_without_probe() -> None:
    anchor = 1_000
    first_deadline = anchor + TRUSTED_TIME_SUPERVISOR_INTERVAL_NS
    probe = Probe()
    clock = SequenceClock(
        anchor,
        anchor,
        first_deadline - 2,
        first_deadline - 1,
        first_deadline,
        first_deadline,
    )
    waiter = Waiter()

    result = _run(probe, clock, waiter, _stop_after_probe(probe, 2))

    assert probe.calls == 2
    assert waiter.deadlines == [first_deadline, first_deadline, first_deadline]
    assert result.probe_count == 2
    assert result.last_event is not None
    assert result.last_event.scheduled_monotonic_ns == first_deadline
    assert result.last_event.observed_monotonic_ns == first_deadline


def test_late_return_runs_once_and_skips_missed_grid_ticks_without_burst() -> None:
    anchor = 5
    first_deadline = anchor + TRUSTED_TIME_SUPERVISOR_INTERVAL_NS
    observed = anchor + 65_000_000_000
    stopped = False

    def stop_during_second_wait() -> None:
        nonlocal stopped
        stopped = True

    probe = Probe()
    clock = SequenceClock(anchor, anchor, observed, observed)
    waiter = Waiter(None, stop_during_second_wait)

    result = _run(probe, clock, waiter, lambda: stopped)

    assert probe.calls == 2
    assert waiter.deadlines == [
        first_deadline,
        anchor + 80_000_000_000,
    ]
    assert result.probe_count == 2
    assert result.last_event is not None
    assert result.last_event.scheduled_monotonic_ns == first_deadline
    assert result.last_event.observed_monotonic_ns == observed
    assert result.last_event.overdue_by_ns == 45_000_000_000


def test_long_due_probe_skips_boundaries_crossed_before_completion() -> None:
    anchor = 5
    first_deadline = anchor + TRUSTED_TIME_SUPERVISOR_INTERVAL_NS
    completed = first_deadline + TRUSTED_TIME_SUPERVISOR_INTERVAL_NS
    stopped = False

    def stop_during_second_wait() -> None:
        nonlocal stopped
        stopped = True

    probe = Probe()
    clock = SequenceClock(anchor, anchor, first_deadline, completed)
    waiter = Waiter(None, stop_during_second_wait)

    result = _run(probe, clock, waiter, lambda: stopped)

    assert probe.calls == 2
    assert waiter.deadlines == [
        first_deadline,
        anchor + 3 * TRUSTED_TIME_SUPERVISOR_INTERVAL_NS,
    ]
    assert result.last_event is not None
    assert result.last_event.scheduled_monotonic_ns == first_deadline
    assert result.last_event.observed_monotonic_ns == first_deadline
    assert result.last_event.overdue_by_ns == 0


def test_stop_during_wait_exits_before_clock_read_or_extra_probe() -> None:
    stopped = False

    def request_stop() -> None:
        nonlocal stopped
        stopped = True

    probe = Probe()
    clock = SequenceClock(10, 10)
    waiter = Waiter(request_stop)

    result = _run(probe, clock, waiter, lambda: stopped)

    assert result.probe_count == 1
    assert probe.calls == 1
    assert clock.calls == 2
    assert waiter.deadlines == [10 + TRUSTED_TIME_SUPERVISOR_INTERVAL_NS]


def test_initial_stop_performs_no_probe_or_wait() -> None:
    probe = Probe()
    clock = SequenceClock(10)
    waiter = Waiter()

    result = _run(probe, clock, waiter, lambda: True)

    assert result == TrustedTimeSupervisorResult(probe_count=0, last_event=None)
    assert probe.calls == 0
    assert waiter.deadlines == []


def test_persisted_source_failures_continue_on_the_next_grid_tick() -> None:
    anchor = 0
    probe = Probe()
    clock = SequenceClock(
        anchor,
        anchor,
        TRUSTED_TIME_SUPERVISOR_INTERVAL_NS,
        TRUSTED_TIME_SUPERVISOR_INTERVAL_NS,
    )
    waiter = Waiter()

    result = _run(probe, clock, waiter, _stop_after_probe(probe, 2))

    assert probe.calls == 2
    assert result.last_event is not None
    assert result.last_event.persisted_probe.result.status is (
        TrustedTimeProbeStatus.SOURCE_UNAVAILABLE
    )
    assert result.last_event.persisted_probe.result.evaluation.sample is None


@pytest.mark.parametrize(
    "failure",
    [
        RuntimeError("secret preparation connection"),
        RuntimeError("secret CAS winner"),
        ValueError("secret durable configuration"),
    ],
)
def test_durable_failures_are_sanitized_fatal_and_never_retry(
    failure: Exception,
) -> None:
    probe = Probe(failure_on_call=2, failure=failure)
    clock = SequenceClock(0, 0, TRUSTED_TIME_SUPERVISOR_INTERVAL_NS)
    waiter = Waiter()

    with pytest.raises(
        TrustedTimeSupervisorError,
        match="durable probe failed",
    ) as captured:
        _run(probe, clock, waiter, lambda: False)

    assert "secret" not in str(captured.value)
    assert probe.calls == 2
    assert waiter.deadlines == [TRUSTED_TIME_SUPERVISOR_INTERVAL_NS]


@pytest.mark.parametrize("value", [-1, True, 1.5, "0", None])
def test_invalid_initial_monotonic_clock_fails_before_probe(value: object) -> None:
    probe = Probe()

    with pytest.raises(TrustedTimeSupervisorError, match="invalid instant"):
        _run(probe, SequenceClock(value), Waiter(), lambda: False)

    assert probe.calls == 0


def test_backward_monotonic_clock_fails_closed_after_startup_probe() -> None:
    probe = Probe()
    waiter = Waiter()

    with pytest.raises(TrustedTimeSupervisorError, match="regressed"):
        _run(probe, SequenceClock(100, 99), waiter, lambda: False)

    assert probe.calls == 1
    assert waiter.deadlines == []


def test_backward_monotonic_clock_fails_closed_after_due_probe() -> None:
    first_deadline = TRUSTED_TIME_SUPERVISOR_INTERVAL_NS
    probe = Probe()
    waiter = Waiter()

    with pytest.raises(TrustedTimeSupervisorError, match="regressed"):
        _run(
            probe,
            SequenceClock(0, 0, first_deadline, first_deadline - 1),
            waiter,
            lambda: False,
        )

    assert probe.calls == 2
    assert waiter.deadlines == [first_deadline]


def test_clock_wait_and_stop_failures_are_sanitized_and_never_probe_again() -> None:
    clock_probe = Probe()
    with pytest.raises(TrustedTimeSupervisorError, match="monotonic clock failed") as clock_error:
        _run(clock_probe, SequenceClock(), Waiter(), lambda: False)
    assert "secret" not in str(clock_error.value)
    assert clock_probe.calls == 0

    wait_probe = Probe()
    with pytest.raises(TrustedTimeSupervisorError, match="wait failed") as wait_error:
        _run(
            wait_probe,
            SequenceClock(0, 0),
            Waiter(RuntimeError("secret wait primitive")),
            lambda: False,
        )
    assert "secret" not in str(wait_error.value)
    assert wait_probe.calls == 1

    stop_probe = Probe()

    def broken_stop() -> bool:
        raise RuntimeError("secret stop transport")

    with pytest.raises(TrustedTimeSupervisorError, match="stop predicate failed") as stop_error:
        _run(stop_probe, SequenceClock(0), Waiter(), broken_stop)
    assert "secret" not in str(stop_error.value)
    assert stop_probe.calls == 0


@pytest.mark.parametrize(
    ("dependency_name", "kwargs"),
    [
        ("durable probe", {"probe": None}),
        ("monotonic clock", {"clock": None}),
        ("deadline waiter", {"waiter": None}),
        ("stop predicate", {"stop": None}),
    ],
)
def test_invalid_configuration_fails_before_any_effect(
    dependency_name: str,
    kwargs: dict[str, object],
) -> None:
    probe = Probe()
    arguments: dict[str, object] = {
        "probe": probe,
        "clock": SequenceClock(0),
        "waiter": Waiter(),
        "stop": lambda: True,
    }
    arguments.update(kwargs)

    with pytest.raises(TrustedTimeSupervisorError, match=dependency_name):
        _run(**arguments)

    assert probe.calls == 0


def test_noncanonical_durable_result_is_fatal_without_retry() -> None:
    class BadProbe:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self) -> object:
            self.calls += 1
            return {"status": "recorded"}

    probe = BadProbe()

    with pytest.raises(TrustedTimeSupervisorError, match="noncanonical"):
        _run(probe, SequenceClock(0), Waiter(), lambda: False)

    assert probe.calls == 1


def test_result_and_event_are_bounded_immutable_and_never_authorize() -> None:
    probe = Probe()
    result = _run(
        probe,
        SequenceClock(0, 0),
        Waiter(),
        _stop_after_probe(probe, 1),
    )
    event = result.last_event
    assert event is not None

    assert TRUSTED_TIME_SUPERVISOR_CONTRACT_VERSION == (
        "phase6c-fixed-grid-trusted-time-supervision-v1"
    )
    assert TRUSTED_TIME_SUPERVISOR_INTERVAL_NS == 20_000_000_000
    assert tuple(field.name for field in fields(TrustedTimeSupervisorEvent)) == (
        "probe_sequence",
        "scheduled_monotonic_ns",
        "observed_monotonic_ns",
        "persisted_probe",
    )
    assert tuple(field.name for field in fields(TrustedTimeSupervisorResult)) == (
        "probe_count",
        "last_event",
    )
    for projection in (event, result):
        assert projection.operational_control_authorized is False
        assert projection.readiness_authorized is False
        assert projection.arming_authorized is False
        assert projection.new_exposure_authorized is False
        assert projection.broker_action_authorized is False
        assert projection.automatic_rearm_authorized is False
        assert projection.automatic_resume_authorized is False

    with pytest.raises(AttributeError):
        result.probe_count = 2  # type: ignore[misc]
