"""Offline personal bridge tests; original Chrony parser fixtures remain synthetic."""

from dataclasses import replace
from datetime import datetime, timedelta, tzinfo
from decimal import Decimal, Inexact, localcontext

import pytest

from packages.adapters.standard_clock import StandardClock
from packages.adapters.standard_clock_chrony import (
    ChronyStandardTimeError,
    ChronyStandardTimeSource,
)
from packages.adapters.trusted_time import chrony_nts
from packages.adapters.trusted_time.chrony_nts import ChronyNtsTrustedTimeSource
from packages.application.personal_runtime import ClockHealthStatus
from packages.application.trusted_time_monitor import TrustedTimeSourceReading
from tests.unit.test_chrony_nts import BASE, _authority, _source


@pytest.fixture(autouse=True)
def forbid_real_process(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("real process forbidden in bridge qualification")

    monkeypatch.setattr(chrony_nts.subprocess, "Popen", forbidden)


def reading(**overrides: object) -> TrustedTimeSourceReading:
    values: dict[str, object] = {
        "source_id": _authority().source_id,
        "source_authority_sha256": _authority().source_authority_sha256,
        "local_observed_at_utc": BASE,
        "trusted_at_utc": BASE + timedelta(microseconds=2_001),
        "observed_at_monotonic_ns": 10_000_000_000,
        "source_uncertainty_milliseconds": Decimal("0.0000011"),
        "source_evidence_sha256": "b" * 64,
    }
    values.update(overrides)
    return TrustedTimeSourceReading(**values)  # type: ignore[arg-type]


def stub_read(
    monkeypatch: pytest.MonkeyPatch, value: object
) -> tuple[ChronyStandardTimeSource, list[int]]:
    source, _ = _source()
    calls: list[int] = []

    def read(self: ChronyNtsTrustedTimeSource, *, deadline_monotonic_ns: int) -> object:
        assert self is source
        calls.append(deadline_monotonic_ns)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(ChronyNtsTrustedTimeSource, "read_trusted_time", read)
    return ChronyStandardTimeSource(source), calls


@pytest.mark.parametrize("microseconds", [2_001, -2_001, 0])
def test_signed_offset_and_original_timestamps(
    monkeypatch: pytest.MonkeyPatch, microseconds: int
) -> None:
    original = reading(trusted_at_utc=BASE + timedelta(microseconds=microseconds))
    bridge, calls = stub_read(monkeypatch, original)
    measurement = bridge(BASE + timedelta(milliseconds=5), 10_005_000_000)
    assert measurement.observed_at_utc is original.local_observed_at_utc
    assert measurement.observed_monotonic_ns == original.observed_at_monotonic_ns
    assert measurement.offset_ns == microseconds * 1_000
    assert calls == [11_005_000_000]


@pytest.mark.parametrize(
    ("milliseconds", "expected_ns"),
    [("0", 0), ("0.000001", 1), ("0.0000011", 2), ("99.9999999", 100_000_000)],
)
def test_uncertainty_rounds_up_without_decimal_context_rounding(
    monkeypatch: pytest.MonkeyPatch, milliseconds: str, expected_ns: int
) -> None:
    bridge, _ = stub_read(
        monkeypatch, reading(source_uncertainty_milliseconds=Decimal(milliseconds))
    )
    with localcontext() as context:
        context.prec = 2
        context.traps[Inexact] = True
        assert bridge(BASE, 10_000_000_000).uncertainty_ns == expected_ns


def test_source_identity_binds_authority_configuration_not_per_reading_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = reading()
    bridge, _ = stub_read(monkeypatch, original)
    identity = bridge(BASE, 10_000_000_000).source_id
    object.__setattr__(original, "source_evidence_sha256", "c" * 64)
    assert bridge(BASE, 10_000_000_000).source_id == identity
    assert len(identity) <= 128
    altered = replace(bridge.source, authority=_authority(socket_path="/run/chrony/other.sock"))
    other = ChronyStandardTimeSource(altered)
    assert other._measurement_source_id != identity


@pytest.mark.parametrize("field", ["source_id", "source_authority_sha256"])
def test_reading_authority_mismatch_rejected(monkeypatch: pytest.MonkeyPatch, field: str) -> None:
    value = "other-source" if field == "source_id" else "d" * 64
    bridge, calls = stub_read(monkeypatch, reading(**{field: value}))
    with pytest.raises(ChronyStandardTimeError, match=r"^CHRONY_STANDARD_READING_INVALID$"):
        bridge(BASE, 10_000_000_000)
    assert calls == [11_000_000_000]


def test_changed_authority_rejected_before_read(monkeypatch: pytest.MonkeyPatch) -> None:
    bridge, calls = stub_read(monkeypatch, reading())
    object.__setattr__(bridge.source, "authority", _authority(socket_path="/run/changed.sock"))
    with pytest.raises(ChronyStandardTimeError, match=r"^CHRONY_STANDARD_AUTHORITY_CHANGED$"):
        bridge(BASE, 10_000_000_000)
    assert calls == []


def test_changed_authority_during_read_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    source, _ = _source()
    bridge = ChronyStandardTimeSource(source)
    calls = []

    def read(self: ChronyNtsTrustedTimeSource, *, deadline_monotonic_ns: int) -> object:
        calls.append(deadline_monotonic_ns)
        object.__setattr__(self, "authority", _authority(socket_path="/run/changed.sock"))
        return reading()

    monkeypatch.setattr(ChronyNtsTrustedTimeSource, "read_trusted_time", read)
    with pytest.raises(ChronyStandardTimeError, match=r"^CHRONY_STANDARD_READING_INVALID$"):
        bridge(BASE, 10_000_000_000)
    assert calls == [11_000_000_000]


@pytest.mark.parametrize("value", [None, object(), {"source_id": "fake"}])
def test_nonexact_reading_rejected(monkeypatch: pytest.MonkeyPatch, value: object) -> None:
    bridge, _ = stub_read(monkeypatch, value)
    with pytest.raises(ChronyStandardTimeError, match=r"^CHRONY_STANDARD_READING_INVALID$"):
        bridge(BASE, 10_000_000_000)


@pytest.mark.parametrize("value", [None, object()])
def test_nonexact_source_rejected(value: object) -> None:
    with pytest.raises(ChronyStandardTimeError, match=r"^CHRONY_STANDARD_SOURCE_INVALID$"):
        ChronyStandardTimeSource(value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("at", "mono"),
    [(datetime(2026, 7, 31), 0), (BASE, -1), (BASE, True), ("private-clock-value", 0)],
)
def test_invalid_call_has_static_diagnostic_and_no_read(
    monkeypatch: pytest.MonkeyPatch, at: object, mono: object
) -> None:
    bridge, calls = stub_read(monkeypatch, reading())
    with pytest.raises(ChronyStandardTimeError, match=r"^CHRONY_STANDARD_CALL_INVALID$"):
        bridge(at, mono)  # type: ignore[arg-type]
    assert calls == []


def test_raising_timezone_is_sanitized_before_source_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenTimezone(tzinfo):
        def utcoffset(self, dt: datetime | None) -> timedelta | None:
            raise RuntimeError("private timezone diagnostic")

    bridge, calls = stub_read(monkeypatch, reading())
    at = datetime(2026, 7, 31, tzinfo=BrokenTimezone())
    with pytest.raises(ChronyStandardTimeError) as error:
        bridge(at, 10_000_000_000)
    assert str(error.value) == "CHRONY_STANDARD_CALL_INVALID"
    assert error.value.__suppress_context__
    assert calls == []


def test_source_failure_is_static_unavailable_without_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge, calls = stub_read(monkeypatch, RuntimeError("private provider diagnostic"))
    with pytest.raises(ChronyStandardTimeError) as error:
        bridge(BASE, 10_000_000_000)
    assert str(error.value) == "CHRONY_STANDARD_READ_UNAVAILABLE"
    assert error.value.__suppress_context__
    assert calls == [11_000_000_000]
    snapshot = StandardClock(
        utc_now=lambda: BASE,
        monotonic_now_ns=lambda: 10_000_000_000,
        source=bridge,
    ).health_snapshot()
    assert snapshot.status is ClockHealthStatus.BLOCKED
    assert snapshot.evidence_class == "unavailable"
    assert snapshot.offset_ns is snapshot.uncertainty_ns is None
    assert "clock_or_source_unavailable" in snapshot.reasons
    assert calls == [11_000_000_000, 11_000_000_000]


@pytest.mark.parametrize(
    ("age_ns", "reason"), [(30_000_000_000, "sample_stale"), (-1_000, "future_sample")]
)
def test_original_observation_age_is_not_refreshed(
    monkeypatch: pytest.MonkeyPatch, age_ns: int, reason: str
) -> None:
    bridge, _ = stub_read(
        monkeypatch,
        reading(
            local_observed_at_utc=BASE - timedelta(microseconds=age_ns // 1_000),
            observed_at_monotonic_ns=100_000_000_000 - age_ns,
        ),
    )
    snapshot = StandardClock(
        utc_now=lambda: BASE, monotonic_now_ns=lambda: 100_000_000_000, source=bridge
    ).health_snapshot()
    assert snapshot.status is ClockHealthStatus.BLOCKED
    assert reason in snapshot.reasons


def test_real_chrony_parser_fixture_through_bridge_to_standard_clock() -> None:
    source, runner = _source()
    clock = StandardClock(
        utc_now=iter((BASE, BASE + timedelta(milliseconds=20))).__next__,
        monotonic_now_ns=iter((1_000, 20_001_000)).__next__,
        epoch_provider=lambda: "synthetic-process-epoch",
        source=ChronyStandardTimeSource(source),
    )
    snapshot = clock.health_snapshot()
    assert runner.calls == 1
    assert runner.deadline_monotonic_ns == 1_000_001_000
    assert snapshot.status is ClockHealthStatus.BLOCKED
    assert snapshot.reasons == ("startup_qualifying",)
    assert snapshot.offset_ns == 2_000_000
    assert snapshot.uncertainty_ns == 30_000_000
    assert snapshot.source_observed_at_utc == BASE + timedelta(milliseconds=10)
    assert snapshot.source_observed_monotonic_ns == 10_001_000
    assert snapshot.sample_age_ns == 10_000_000
    assert not snapshot.recovery_ready
    assert snapshot.rearm_required


def test_expired_original_deadline_never_runs_chronyc() -> None:
    source, runner = _source(monotonic_values=(1_000_000_000,))
    bridge = ChronyStandardTimeSource(source)
    with pytest.raises(ChronyStandardTimeError, match=r"^CHRONY_STANDARD_READ_UNAVAILABLE$"):
        bridge(BASE, 0)
    assert runner.calls == 0


@pytest.mark.parametrize("elapsed_ns", [999_999_000, 1_000_000_000])
def test_complete_callback_sampling_duration_keeps_strict_original_limit(
    monkeypatch: pytest.MonkeyPatch, elapsed_ns: int
) -> None:
    bridge, calls = stub_read(monkeypatch, reading())
    clock = StandardClock(
        utc_now=iter((BASE, BASE + timedelta(microseconds=elapsed_ns // 1_000))).__next__,
        monotonic_now_ns=iter((10_000_000_000, 10_000_000_000 + elapsed_ns)).__next__,
        source=bridge,
    )
    snapshot = clock.health_snapshot()
    assert calls == [11_000_000_000]
    assert snapshot.sampling_duration_ns == elapsed_ns
    assert ("sampling_timeout" in snapshot.reasons) == (elapsed_ns == 1_000_000_000)
    assert snapshot.status is ClockHealthStatus.BLOCKED


def test_bridge_does_not_skip_startup_or_clear_a_latched_fault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, _ = _source()
    elapsed = 0
    offset = 0
    calls: list[int] = []

    def read(self: ChronyNtsTrustedTimeSource, *, deadline_monotonic_ns: int) -> object:
        assert self is source
        calls.append(deadline_monotonic_ns)
        return reading(
            local_observed_at_utc=BASE + timedelta(seconds=elapsed),
            trusted_at_utc=BASE + timedelta(seconds=elapsed, microseconds=offset),
            observed_at_monotonic_ns=10_000_000_000 + elapsed * 1_000_000_000,
            source_uncertainty_milliseconds=Decimal(0),
        )

    monkeypatch.setattr(ChronyNtsTrustedTimeSource, "read_trusted_time", read)
    clock = StandardClock(
        utc_now=lambda: BASE + timedelta(seconds=elapsed),
        monotonic_now_ns=lambda: 10_000_000_000 + elapsed * 1_000_000_000,
        epoch_provider=lambda: "synthetic-process-epoch",
        source=ChronyStandardTimeSource(source),
    )
    for sample_elapsed in (0, 10, 20, 30, 40, 50):
        elapsed = sample_elapsed
        snapshot = clock.health_snapshot()
        assert snapshot.reasons == ("startup_qualifying",)
        assert not snapshot.recovery_ready
    elapsed = 60
    assert clock.health_snapshot().status is ClockHealthStatus.HEALTHY
    elapsed, offset = 61, 1_000_000
    assert "offset_blocked" in clock.health_snapshot().reasons
    elapsed, offset = 62, 0
    recovered = clock.health_snapshot()
    assert recovered.status is ClockHealthStatus.BLOCKED
    assert "fault_latched_rearm_required" in recovered.reasons
    assert recovered.rearm_required
    assert calls == [
        (11 + second) * 1_000_000_000 for second in (0, 10, 20, 30, 40, 50, 60, 61, 62)
    ]
