"""One provider-neutral, non-authorizing trusted-time probe step.

The application seam owns only injected source and clock calls.  It does not
choose a source, schedule itself, persist evidence, mutate operational control,
call a broker, or authorize arming/re-arm.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from packages.domain.trusted_time import (
    TRUSTED_TIME_POLICY,
    TrustedTimeError,
    TrustedTimeEvaluation,
    TrustedTimeSample,
    TrustedTimeState,
    evaluate_trusted_time,
)


class TrustedTimeMonitorError(RuntimeError):
    """The monitor boundary itself is malformed and grants no authority."""


class TrustedTimeProbeStatus(StrEnum):
    RECORDED = "recorded"
    SOURCE_UNAVAILABLE = "source_unavailable"
    SOURCE_IDENTITY_MISMATCH = "source_identity_mismatch"
    INVALID_READING = "invalid_reading"


def _require_text(value: str, field_name: str, *, maximum: int = 128) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise TrustedTimeMonitorError(f"{field_name} must be non-empty trimmed text")
    if len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise TrustedTimeMonitorError(f"{field_name} contains unsupported text")


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise TrustedTimeMonitorError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise TrustedTimeMonitorError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise TrustedTimeMonitorError(f"{field_name} must be UTC")


@dataclass(frozen=True, slots=True)
class TrustedTimeMonitorBinding:
    """Operator/deployment supplied nonsecret identity pins."""

    source_id: str
    source_authority_sha256: str
    host_id: str
    monitor_epoch_id: str

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.source_id, "trusted-time source ID"),
            (self.host_id, "trusted-time host ID"),
            (self.monitor_epoch_id, "trusted-time monitor epoch ID"),
        ):
            _require_text(value, field_name)
        _require_sha256(
            self.source_authority_sha256,
            "trusted-time source authority_sha256",
        )


@dataclass(frozen=True, slots=True)
class TrustedTimeSourceReading:
    """Authenticated source output for the local probe midpoint."""

    source_id: str
    source_authority_sha256: str
    trusted_at_utc: datetime
    source_evidence_sha256: str

    def __post_init__(self) -> None:
        _require_text(self.source_id, "trusted-time reading source ID")
        _require_sha256(
            self.source_authority_sha256,
            "trusted-time reading source authority_sha256",
        )
        _require_utc(self.trusted_at_utc, "trusted-time reading source instant")
        _require_sha256(
            self.source_evidence_sha256,
            "trusted-time reading evidence_sha256",
        )


class TrustedTimeSource(Protocol):
    def read_trusted_time(
        self,
        *,
        deadline_monotonic_ns: int,
    ) -> TrustedTimeSourceReading: ...


class UtcClock(Protocol):
    def __call__(self) -> datetime: ...


class MonotonicNanosecondClock(Protocol):
    def __call__(self) -> int: ...


@dataclass(frozen=True, slots=True)
class TrustedTimeMonitorResult:
    """One sanitized probe outcome and its fail-closed domain evaluation."""

    status: TrustedTimeProbeStatus
    evaluation: TrustedTimeEvaluation

    def __post_init__(self) -> None:
        if type(self.status) is not TrustedTimeProbeStatus:
            raise TrustedTimeMonitorError("trusted-time probe status is unsupported")
        if type(self.evaluation) is not TrustedTimeEvaluation:
            raise TrustedTimeMonitorError("trusted-time monitor evaluation must be exact")
        has_sample = self.evaluation.sample is not None
        if has_sample != (self.status is TrustedTimeProbeStatus.RECORDED):
            raise TrustedTimeMonitorError(
                "trusted-time probe status conflicts with retained sample"
            )

    @property
    def state(self) -> TrustedTimeState:
        return self.evaluation.state


def _read_utc(clock: UtcClock, field_name: str) -> datetime:
    if not callable(clock):
        raise TrustedTimeMonitorError(f"{field_name} is unavailable")
    try:
        instant = clock()
    except Exception as error:
        raise TrustedTimeMonitorError(f"{field_name} is unavailable") from error
    _require_utc(instant, field_name)
    return instant


def _read_monotonic_ns(
    clock: MonotonicNanosecondClock,
    field_name: str,
) -> int:
    if not callable(clock):
        raise TrustedTimeMonitorError(f"{field_name} is unavailable")
    try:
        value = clock()
    except Exception as error:
        raise TrustedTimeMonitorError(f"{field_name} is unavailable") from error
    if type(value) is not int or value < 0:
        raise TrustedTimeMonitorError(f"{field_name} must return a non-negative integer")
    return value


def _unavailable(
    *,
    prior: TrustedTimeState | None,
    status: TrustedTimeProbeStatus,
    evaluated_at_utc: datetime,
    evaluated_at_monotonic_ns: int,
) -> TrustedTimeMonitorResult:
    return TrustedTimeMonitorResult(
        status=status,
        evaluation=evaluate_trusted_time(
            prior,
            None,
            evaluated_at_utc=evaluated_at_utc,
            evaluated_at_monotonic_ns=evaluated_at_monotonic_ns,
        ),
    )


def _require_binding_continuity(
    prior: TrustedTimeState | None,
    binding: TrustedTimeMonitorBinding,
) -> None:
    latest = None if prior is None else prior.latest_sample
    if latest is None:
        return
    if (
        binding.source_id != latest.source_id
        or binding.source_authority_sha256 != latest.source_authority_sha256
        or binding.host_id != latest.host_id
        or binding.monitor_epoch_id != latest.monitor_epoch_id
    ):
        raise TrustedTimeMonitorError(
            "trusted-time monitor binding conflicts with retained identity"
        )


def run_trusted_time_probe(
    prior: TrustedTimeState | None,
    *,
    binding: TrustedTimeMonitorBinding,
    source: TrustedTimeSource,
    utc_clock: UtcClock,
    monotonic_clock: MonotonicNanosecondClock,
) -> TrustedTimeMonitorResult:
    """Issue one deadline-bound source request and reduce its evidence."""

    if prior is not None and type(prior) is not TrustedTimeState:
        raise TrustedTimeMonitorError("trusted-time prior state must be exact")
    if type(binding) is not TrustedTimeMonitorBinding:
        raise TrustedTimeMonitorError("trusted-time monitor binding must be exact")
    _require_binding_continuity(prior, binding)
    read_source = getattr(source, "read_trusted_time", None)
    if not callable(read_source):
        raise TrustedTimeMonitorError("trusted-time source port is unavailable")

    started_monotonic_ns = _read_monotonic_ns(
        monotonic_clock,
        "trusted-time starting monotonic clock",
    )
    started_at_utc = _read_utc(utc_clock, "trusted-time starting UTC clock")
    deadline_monotonic_ns = started_monotonic_ns + TRUSTED_TIME_POLICY.maximum_probe_duration_ns
    try:
        reading = read_source(deadline_monotonic_ns=deadline_monotonic_ns)
    except Exception:
        completed_at_utc = _read_utc(
            utc_clock,
            "trusted-time completion UTC clock",
        )
        completed_monotonic_ns = _read_monotonic_ns(
            monotonic_clock,
            "trusted-time completion monotonic clock",
        )
        return _unavailable(
            prior=prior,
            status=TrustedTimeProbeStatus.SOURCE_UNAVAILABLE,
            evaluated_at_utc=completed_at_utc,
            evaluated_at_monotonic_ns=completed_monotonic_ns,
        )

    completed_at_utc = _read_utc(utc_clock, "trusted-time completion UTC clock")
    completed_monotonic_ns = _read_monotonic_ns(
        monotonic_clock,
        "trusted-time completion monotonic clock",
    )
    if type(reading) is not TrustedTimeSourceReading:
        return _unavailable(
            prior=prior,
            status=TrustedTimeProbeStatus.INVALID_READING,
            evaluated_at_utc=completed_at_utc,
            evaluated_at_monotonic_ns=completed_monotonic_ns,
        )
    if (
        reading.source_id != binding.source_id
        or reading.source_authority_sha256 != binding.source_authority_sha256
    ):
        return _unavailable(
            prior=prior,
            status=TrustedTimeProbeStatus.SOURCE_IDENTITY_MISMATCH,
            evaluated_at_utc=completed_at_utc,
            evaluated_at_monotonic_ns=completed_monotonic_ns,
        )

    latest = None if prior is None else prior.latest_sample
    sequence = 1 if latest is None else latest.sequence + 1
    try:
        sample = TrustedTimeSample(
            source_id=reading.source_id,
            source_authority_sha256=reading.source_authority_sha256,
            host_id=binding.host_id,
            monitor_epoch_id=binding.monitor_epoch_id,
            sequence=sequence,
            source_evidence_sha256=reading.source_evidence_sha256,
            probe_started_at_utc=started_at_utc,
            probe_completed_at_utc=completed_at_utc,
            trusted_at_utc=reading.trusted_at_utc,
            probe_started_monotonic_ns=started_monotonic_ns,
            probe_completed_monotonic_ns=completed_monotonic_ns,
        )
        evaluation = evaluate_trusted_time(
            prior,
            sample,
            evaluated_at_utc=completed_at_utc,
            evaluated_at_monotonic_ns=completed_monotonic_ns,
        )
    except TrustedTimeError:
        return _unavailable(
            prior=prior,
            status=TrustedTimeProbeStatus.INVALID_READING,
            evaluated_at_utc=completed_at_utc,
            evaluated_at_monotonic_ns=completed_monotonic_ns,
        )
    return TrustedTimeMonitorResult(
        status=TrustedTimeProbeStatus.RECORDED,
        evaluation=evaluation,
    )


__all__ = [
    "MonotonicNanosecondClock",
    "TrustedTimeMonitorBinding",
    "TrustedTimeMonitorError",
    "TrustedTimeMonitorResult",
    "TrustedTimeProbeStatus",
    "TrustedTimeSource",
    "TrustedTimeSourceReading",
    "UtcClock",
    "run_trusted_time_probe",
]
