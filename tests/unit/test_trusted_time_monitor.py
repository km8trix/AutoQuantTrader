from __future__ import annotations

from dataclasses import fields
from datetime import UTC, datetime, timedelta, timezone

import pytest

from packages.application.trusted_time_monitor import (
    TrustedTimeMonitorBinding,
    TrustedTimeMonitorError,
    TrustedTimeMonitorResult,
    TrustedTimeProbeStatus,
    TrustedTimeSourceReading,
    run_trusted_time_probe,
)
from packages.domain.trusted_time import (
    TrustedTimeHealth,
    TrustedTimeReason,
    TrustedTimeState,
)

BASE = datetime(2026, 7, 28, 14, 0, tzinfo=UTC)
AUTHORITY = "a" * 64


class SequenceClock:
    def __init__(self, *values: object) -> None:
        self.values = list(values)
        self.calls = 0

    def __call__(self) -> object:
        self.calls += 1
        if not self.values:
            raise RuntimeError("clock exhausted")
        return self.values.pop(0)


class Source:
    def __init__(self, reading: object = None, *, failure: Exception | None = None) -> None:
        self.reading = reading
        self.failure = failure
        self.calls = 0
        self.deadlines: list[int] = []

    def read_trusted_time(self, *, deadline_monotonic_ns: int) -> object:
        self.calls += 1
        self.deadlines.append(deadline_monotonic_ns)
        if self.failure is not None:
            raise self.failure
        return self.reading


class ExplodingSourcePort:
    def __getattribute__(self, name: str) -> object:
        if name == "read_trusted_time":
            raise RuntimeError("secret source port detail")
        return super().__getattribute__(name)


def _binding(
    *,
    source_id: str = "trusted-source-1",
    authority: str = AUTHORITY,
    host_id: str = "paper-trader-1",
    epoch_id: str = "monitor-epoch-1",
) -> TrustedTimeMonitorBinding:
    return TrustedTimeMonitorBinding(
        source_id=source_id,
        source_authority_sha256=authority,
        host_id=host_id,
        monitor_epoch_id=epoch_id,
    )


def _reading(
    *,
    trusted_at: datetime = BASE,
    source_id: str = "trusted-source-1",
    authority: str = AUTHORITY,
) -> TrustedTimeSourceReading:
    return TrustedTimeSourceReading(
        source_id=source_id,
        source_authority_sha256=authority,
        trusted_at_utc=trusted_at,
        source_evidence_sha256="b" * 64,
    )


def _probe(
    source: Source,
    *,
    prior: TrustedTimeState | None = None,
    binding: TrustedTimeMonitorBinding | None = None,
    utc_values: tuple[object, object] = (BASE, BASE),
    monotonic_values: tuple[object, object] = (0, 0),
) -> TrustedTimeMonitorResult:
    return run_trusted_time_probe(
        prior,
        binding=_binding() if binding is None else binding,
        source=source,  # type: ignore[arg-type]
        utc_clock=SequenceClock(*utc_values),  # type: ignore[arg-type]
        monotonic_clock=SequenceClock(*monotonic_values),  # type: ignore[arg-type]
    )


def test_monitor_records_one_authenticated_midpoint_sample() -> None:
    source = Source(_reading(trusted_at=BASE + timedelta(milliseconds=100)))

    result = _probe(
        source,
        utc_values=(BASE, BASE + timedelta(milliseconds=20)),
        monotonic_values=(1_000, 20_001_000),
    )

    assert source.calls == 1
    assert source.deadlines == [1_000_001_000]
    assert result.status is TrustedTimeProbeStatus.RECORDED
    assert result.state.latest_sample is not None
    assert result.state.latest_sample.offset_milliseconds == 90
    assert result.state.latest_sample.sequence == 1
    assert result.state.health is TrustedTimeHealth.HEALTHY
    assert result.state.reason is TrustedTimeReason.STARTUP_QUALIFYING


def test_monitor_derives_the_next_sequence_from_retained_state() -> None:
    first = _probe(Source(_reading())).state
    next_base = BASE + timedelta(seconds=1)

    second = _probe(
        Source(_reading(trusted_at=next_base)),
        prior=first,
        utc_values=(next_base, next_base),
        monotonic_values=(1_000_000_000, 1_000_000_000),
    )

    assert second.status is TrustedTimeProbeStatus.RECORDED
    assert second.state.latest_sample is not None
    assert second.state.latest_sample.sequence == 2
    assert second.state.previous_state_sha256 == first.semantic_sha256


@pytest.mark.parametrize(
    "binding",
    [
        _binding(source_id="trusted-source-2"),
        _binding(authority="c" * 64),
        _binding(host_id="paper-trader-2"),
        _binding(epoch_id="monitor-epoch-2"),
    ],
)
def test_monitor_rejects_identity_rotation_before_source_effect(
    binding: TrustedTimeMonitorBinding,
) -> None:
    prior = _probe(Source(_reading())).state
    source = Source(_reading())

    with pytest.raises(TrustedTimeMonitorError, match="binding conflicts"):
        _probe(source, prior=prior, binding=binding)

    assert source.calls == 0


def test_source_exception_is_sanitized_and_fails_closed() -> None:
    source = Source(failure=RuntimeError("secret endpoint and credential"))

    result = _probe(source)

    assert source.calls == 1
    assert result.status is TrustedTimeProbeStatus.SOURCE_UNAVAILABLE
    assert result.state.health is TrustedTimeHealth.BLOCKED
    assert result.state.reason is TrustedTimeReason.STARTUP_NO_SAMPLE
    assert "secret" not in repr(result)
    assert "credential" not in repr(result)


@pytest.mark.parametrize(
    "reading",
    [
        _reading(source_id="other-source"),
        _reading(authority="c" * 64),
    ],
)
def test_source_identity_mismatch_never_becomes_a_sample(
    reading: TrustedTimeSourceReading,
) -> None:
    result = _probe(Source(reading))

    assert result.status is TrustedTimeProbeStatus.SOURCE_IDENTITY_MISMATCH
    assert result.evaluation.sample is None
    assert result.state.health is TrustedTimeHealth.BLOCKED


def test_wrong_reading_type_is_invalid_and_fails_closed() -> None:
    result = _probe(Source({"trusted_at": BASE.isoformat()}))

    assert result.status is TrustedTimeProbeStatus.INVALID_READING
    assert result.evaluation.sample is None
    assert result.state.health is TrustedTimeHealth.BLOCKED


def test_source_port_attribute_failure_is_sanitized_before_clock_or_source_effect() -> None:
    utc_clock = SequenceClock(BASE, BASE)
    monotonic_clock = SequenceClock(0, 0)

    with pytest.raises(TrustedTimeMonitorError, match="source port is unavailable") as captured:
        run_trusted_time_probe(
            None,
            binding=_binding(),
            source=ExplodingSourcePort(),  # type: ignore[arg-type]
            utc_clock=utc_clock,  # type: ignore[arg-type]
            monotonic_clock=monotonic_clock,  # type: ignore[arg-type]
        )

    assert "secret" not in str(captured.value)
    assert utc_clock.calls == 0
    assert monotonic_clock.calls == 0


@pytest.mark.parametrize(
    ("utc_values", "monotonic_values"),
    [
        ((BASE + timedelta(seconds=1), BASE), (0, 1)),
        ((BASE, BASE), (2, 1)),
    ],
)
def test_regressing_local_probe_interval_is_invalid(
    utc_values: tuple[object, object],
    monotonic_values: tuple[object, object],
) -> None:
    result = _probe(
        Source(_reading()),
        utc_values=utc_values,
        monotonic_values=monotonic_values,
    )

    assert result.status is TrustedTimeProbeStatus.INVALID_READING
    assert result.state.health is TrustedTimeHealth.BLOCKED


def test_exact_probe_duration_is_accepted_but_overrun_fails_closed() -> None:
    exact = _probe(
        Source(_reading(trusted_at=BASE + timedelta(milliseconds=500))),
        utc_values=(BASE, BASE + timedelta(seconds=1)),
        monotonic_values=(0, 1_000_000_000),
    )
    overrun_source = Source(_reading(trusted_at=BASE + timedelta(milliseconds=500)))
    overrun = _probe(
        overrun_source,
        utc_values=(BASE, BASE + timedelta(seconds=1)),
        monotonic_values=(0, 1_000_000_001),
    )

    assert exact.status is TrustedTimeProbeStatus.RECORDED
    assert exact.state.health is TrustedTimeHealth.HEALTHY
    assert overrun_source.deadlines == [1_000_000_000]
    assert overrun.status is TrustedTimeProbeStatus.INVALID_READING
    assert overrun.evaluation.sample is None
    assert overrun.state.health is TrustedTimeHealth.BLOCKED


def test_divergent_utc_and_monotonic_probe_intervals_fail_closed() -> None:
    result = _probe(
        Source(_reading()),
        utc_values=(BASE, BASE),
        monotonic_values=(0, 250_000_001),
    )

    assert result.status is TrustedTimeProbeStatus.INVALID_READING
    assert result.evaluation.sample is None
    assert result.state.health is TrustedTimeHealth.BLOCKED


def test_invalid_starting_clock_fails_before_source_effect() -> None:
    source = Source(_reading())

    with pytest.raises(TrustedTimeMonitorError, match="starting UTC clock"):
        _probe(
            source,
            utc_values=(
                BASE.astimezone(timezone(timedelta(hours=-4))),
                BASE,
            ),
        )

    assert source.calls == 0


def test_monitor_result_exposes_no_control_broker_or_rearm_effect() -> None:
    result = _probe(Source(_reading()))

    assert tuple(field.name for field in fields(TrustedTimeMonitorResult)) == (
        "status",
        "evaluation",
    )
    assert not hasattr(result, "control_command")
    assert not hasattr(result, "broker_action")
    assert not hasattr(result, "rearm")
    assert not hasattr(result.state, "rearm_eligible")
