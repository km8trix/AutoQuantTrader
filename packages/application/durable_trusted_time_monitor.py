"""Durable, non-authorizing composition for one trusted-time probe.

The repository prepares one exact epoch head before source I/O and atomically
compares-and-swaps that head after the existing provider-neutral probe returns.
This module owns no database, ambient process identity, scheduler, source
selection, control transition, broker action, or re-arm authority.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, cast

from packages.application.trusted_time_monitor import (
    MonotonicNanosecondClock,
    TrustedTimeMonitorBinding,
    TrustedTimeMonitorResult,
    TrustedTimeSource,
    UtcClock,
    run_trusted_time_probe,
)
from packages.domain.trusted_time import TrustedTimeState

DURABLE_TRUSTED_TIME_MONITOR_CONTRACT_VERSION = "phase6a-durable-trusted-time-persistence-v2"


class DurableTrustedTimeMonitorError(RuntimeError):
    """One durable probe could not be authenticated and grants no authority."""


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DurableTrustedTimeMonitorError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_binding(value: object) -> TrustedTimeMonitorBinding:
    if type(value) is not TrustedTimeMonitorBinding:
        raise DurableTrustedTimeMonitorError("durable trusted-time binding must be exact")
    try:
        value.__post_init__()
    except Exception:
        raise DurableTrustedTimeMonitorError("durable trusted-time binding is invalid") from None
    return value


@dataclass(frozen=True, slots=True, init=False)
class DurableTrustedTimeEpochSession:
    """Opaque process-local epoch handle issued and authenticated by a repository."""

    binding: TrustedTimeMonitorBinding
    epoch_registration_sha256: str

    def __init__(self) -> None:
        raise TypeError("DurableTrustedTimeEpochSession is issued by a trusted-time repository")

    def __post_init__(self) -> None:
        _require_binding(self.binding)
        _require_sha256(
            self.epoch_registration_sha256,
            "durable trusted-time epoch registration SHA-256",
        )


def _new_durable_trusted_time_epoch_session(
    *,
    binding: TrustedTimeMonitorBinding,
    epoch_registration_sha256: str,
) -> DurableTrustedTimeEpochSession:
    """Issue an opaque handle for persistence implementations.

    A repository must separately retain and verify the exact object identity,
    repository instance, and process identity. Merely constructing an object
    with matching visible fields is never durable authority.
    """

    value = object.__new__(DurableTrustedTimeEpochSession)
    object.__setattr__(value, "binding", binding)
    object.__setattr__(
        value,
        "epoch_registration_sha256",
        epoch_registration_sha256,
    )
    value.__post_init__()
    return value


@dataclass(frozen=True, slots=True)
class PreparedTrustedTimeProbe:
    """Authenticated current head captured before one source request."""

    binding: TrustedTimeMonitorBinding
    prior: TrustedTimeState | None
    expected_host_head_sha256: str
    epoch_registration_sha256: str
    next_evaluation_sequence: int

    def __post_init__(self) -> None:
        binding = _require_binding(self.binding)
        if self.prior is not None:
            if type(self.prior) is not TrustedTimeState:
                raise DurableTrustedTimeMonitorError(
                    "prepared trusted-time prior state must be exact"
                )
            try:
                self.prior.__post_init__()
            except Exception:
                raise DurableTrustedTimeMonitorError(
                    "prepared trusted-time prior state is invalid"
                ) from None
        _require_sha256(
            self.expected_host_head_sha256,
            "prepared trusted-time expected host-head SHA-256",
        )
        _require_sha256(
            self.epoch_registration_sha256,
            "prepared trusted-time epoch registration SHA-256",
        )
        if type(self.next_evaluation_sequence) is not int or self.next_evaluation_sequence <= 0:
            raise DurableTrustedTimeMonitorError(
                "prepared trusted-time evaluation sequence must be positive"
            )
        if (self.next_evaluation_sequence == 1) != (self.prior is None):
            raise DurableTrustedTimeMonitorError(
                "prepared trusted-time sequence conflicts with prior state"
            )
        latest = None if self.prior is None else self.prior.latest_sample
        if latest is not None and (
            latest.source_id != binding.source_id
            or latest.source_authority_sha256 != binding.source_authority_sha256
            or latest.host_id != binding.host_id
            or latest.monitor_epoch_id != binding.monitor_epoch_id
        ):
            raise DurableTrustedTimeMonitorError(
                "prepared trusted-time binding conflicts with prior state"
            )


@dataclass(frozen=True, slots=True)
class PersistedTrustedTimeProbe:
    """Exact durable record returned after the repository wins its head CAS."""

    result: TrustedTimeMonitorResult
    evaluation_sequence: int
    record_sha256: str
    host_head_sha256: str

    def __post_init__(self) -> None:
        if type(self.result) is not TrustedTimeMonitorResult:
            raise DurableTrustedTimeMonitorError("persisted trusted-time result must be exact")
        try:
            self.result.__post_init__()
            self.result.evaluation.__post_init__()
        except Exception:
            raise DurableTrustedTimeMonitorError(
                "persisted trusted-time result is invalid"
            ) from None
        if type(self.evaluation_sequence) is not int or self.evaluation_sequence <= 0:
            raise DurableTrustedTimeMonitorError(
                "persisted trusted-time evaluation sequence must be positive"
            )
        _require_sha256(
            self.record_sha256,
            "persisted trusted-time record SHA-256",
        )
        _require_sha256(
            self.host_head_sha256,
            "persisted trusted-time host-head SHA-256",
        )

    @property
    def operational_control_authorized(self) -> bool:
        return False

    @property
    def readiness_authorized(self) -> bool:
        return False

    @property
    def arming_authorized(self) -> bool:
        return False

    @property
    def new_exposure_authorized(self) -> bool:
        return False

    @property
    def broker_action_authorized(self) -> bool:
        return False

    @property
    def automatic_rearm_authorized(self) -> bool:
        return False

    @property
    def automatic_resume_authorized(self) -> bool:
        return False


class DurableTrustedTimeMonitorRepository(Protocol):
    """Injected prepare/CAS-append boundary for one active monitor epoch."""

    def prepare_probe(
        self,
        session: DurableTrustedTimeEpochSession,
    ) -> PreparedTrustedTimeProbe: ...

    def append_probe(
        self,
        session: DurableTrustedTimeEpochSession,
        *,
        prepared: PreparedTrustedTimeProbe,
        result: TrustedTimeMonitorResult,
    ) -> PersistedTrustedTimeProbe: ...


def _port_method(
    dependency: object,
    method_name: str,
) -> Callable[..., object]:
    try:
        method = getattr(dependency, method_name, None)
    except Exception:
        raise DurableTrustedTimeMonitorError(
            "durable trusted-time repository port is unavailable"
        ) from None
    if not callable(method):
        raise DurableTrustedTimeMonitorError("durable trusted-time repository port is unavailable")
    return cast(Callable[..., object], method)


def _require_session(value: object) -> DurableTrustedTimeEpochSession:
    if type(value) is not DurableTrustedTimeEpochSession:
        raise DurableTrustedTimeMonitorError(
            "durable trusted-time epoch session must be repository-issued"
        )
    try:
        value.__post_init__()
    except Exception:
        raise DurableTrustedTimeMonitorError(
            "durable trusted-time epoch session is invalid"
        ) from None
    return value


def _require_prepared(
    value: object,
    *,
    session: DurableTrustedTimeEpochSession,
) -> PreparedTrustedTimeProbe:
    if type(value) is not PreparedTrustedTimeProbe:
        raise DurableTrustedTimeMonitorError(
            "trusted-time repository returned a noncanonical preparation"
        )
    try:
        value.__post_init__()
    except Exception:
        raise DurableTrustedTimeMonitorError(
            "trusted-time repository returned an invalid preparation"
        ) from None
    if (
        value.binding != session.binding
        or value.epoch_registration_sha256 != session.epoch_registration_sha256
    ):
        raise DurableTrustedTimeMonitorError("trusted-time preparation crossed epoch identity")
    return value


def _require_persisted(
    value: object,
    *,
    prepared: PreparedTrustedTimeProbe,
    result: TrustedTimeMonitorResult,
) -> PersistedTrustedTimeProbe:
    if type(value) is not PersistedTrustedTimeProbe:
        raise DurableTrustedTimeMonitorError(
            "trusted-time repository returned a noncanonical persisted result"
        )
    try:
        value.__post_init__()
    except Exception:
        raise DurableTrustedTimeMonitorError(
            "trusted-time repository returned an invalid persisted result"
        ) from None
    if value.result != result or value.evaluation_sequence != prepared.next_evaluation_sequence:
        raise DurableTrustedTimeMonitorError("trusted-time repository substituted the probe result")
    return value


def run_durable_trusted_time_probe_once(
    session: DurableTrustedTimeEpochSession,
    *,
    repository: DurableTrustedTimeMonitorRepository,
    source: TrustedTimeSource,
    utc_clock: UtcClock,
    monotonic_clock: MonotonicNanosecondClock,
) -> PersistedTrustedTimeProbe:
    """Prepare, issue exactly one probe, and attempt exactly one durable append."""

    exact_session = _require_session(session)
    prepare_probe = _port_method(repository, "prepare_probe")
    append_probe = _port_method(repository, "append_probe")

    try:
        raw_prepared = prepare_probe(exact_session)
    except Exception:
        raise DurableTrustedTimeMonitorError("durable trusted-time preparation failed") from None
    prepared = _require_prepared(raw_prepared, session=exact_session)

    try:
        result = run_trusted_time_probe(
            prepared.prior,
            binding=prepared.binding,
            source=source,
            utc_clock=utc_clock,
            monotonic_clock=monotonic_clock,
        )
    except Exception:
        raise DurableTrustedTimeMonitorError("durable trusted-time probe failed") from None

    try:
        raw_persisted = append_probe(
            exact_session,
            prepared=prepared,
            result=result,
        )
    except Exception:
        raise DurableTrustedTimeMonitorError("durable trusted-time append failed") from None
    return _require_persisted(
        raw_persisted,
        prepared=prepared,
        result=result,
    )


__all__ = [
    "DURABLE_TRUSTED_TIME_MONITOR_CONTRACT_VERSION",
    "DurableTrustedTimeEpochSession",
    "DurableTrustedTimeMonitorError",
    "DurableTrustedTimeMonitorRepository",
    "PersistedTrustedTimeProbe",
    "PreparedTrustedTimeProbe",
    "run_durable_trusted_time_probe_once",
]
