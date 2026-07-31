"""Pure provider-neutral trusted-time health evidence.

The reducer in this module owns no clock, network, scheduler, persistence,
operational-control, or re-arm authority.  It classifies already authenticated
samples and exposes the continuous-health proof required by the operational
budget without changing trading state.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum

from packages.domain.canonical import (
    canonical_json_bytes,
    canonical_json_text,
    canonical_persisted_decimal,
)

TRUSTED_TIME_CONTRACT_VERSION = "phase6a-provider-neutral-trusted-time-v1"


class TrustedTimeError(ValueError):
    """Trusted-time evidence is malformed or cannot extend the prior state."""


class TrustedTimeHealth(StrEnum):
    HEALTHY = "healthy"
    WARNING = "warning"
    BLOCKED = "blocked"


class TrustedTimeReason(StrEnum):
    WITHIN_LIMIT = "within_limit"
    STARTUP_NO_SAMPLE = "startup_no_sample"
    STARTUP_QUALIFYING = "startup_qualifying"
    SOURCE_UNAVAILABLE = "source_unavailable"
    WARNING_OFFSET = "warning_offset"
    HARD_OFFSET = "hard_offset"
    HARD_OFFSET_LATCHED = "hard_offset_latched"
    SAMPLE_STALE = "sample_stale"
    IDENTITY_CHANGED = "identity_changed"
    SEQUENCE_DISCONTINUITY = "sequence_discontinuity"
    CADENCE_GAP = "cadence_gap"
    UTC_REGRESSION = "utc_regression"
    MONOTONIC_REGRESSION = "monotonic_regression"


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: str, field_name: str, *, maximum: int = 128) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise TrustedTimeError(f"{field_name} must be non-empty trimmed text")
    if len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise TrustedTimeError(f"{field_name} contains unsupported text")


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise TrustedTimeError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise TrustedTimeError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise TrustedTimeError(f"{field_name} must be UTC")


def _require_monotonic_ns(value: int, field_name: str) -> None:
    if type(value) is not int or value < 0:
        raise TrustedTimeError(f"{field_name} must be a non-negative integer")


def _timedelta_milliseconds(value: timedelta) -> Decimal:
    microseconds = (value.days * 86_400 + value.seconds) * 1_000_000 + value.microseconds
    return canonical_persisted_decimal(
        Decimal(microseconds) / Decimal(1_000),
        "trusted-time offset milliseconds",
    )


def _timedelta_nanoseconds(value: timedelta) -> int:
    return (value.days * 86_400 + value.seconds) * 1_000_000_000 + value.microseconds * 1_000


@dataclass(frozen=True, slots=True)
class TrustedTimePolicy:
    """Versioned clock-drift, cadence, and recovery thresholds."""

    warning_offset_milliseconds: Decimal
    hard_offset_milliseconds: Decimal
    maximum_probe_duration_ns: int
    maximum_sample_age_ns: int
    maximum_cadence_gap_ns: int
    healthy_recovery_window_ns: int

    def __post_init__(self) -> None:
        try:
            warning = canonical_persisted_decimal(
                self.warning_offset_milliseconds,
                "trusted-time warning offset",
            )
            hard = canonical_persisted_decimal(
                self.hard_offset_milliseconds,
                "trusted-time hard offset",
            )
        except (TypeError, ValueError) as error:
            raise TrustedTimeError(str(error)) from error
        if warning != self.warning_offset_milliseconds:
            object.__setattr__(self, "warning_offset_milliseconds", warning)
        if hard != self.hard_offset_milliseconds:
            object.__setattr__(self, "hard_offset_milliseconds", hard)
        if warning <= 0 or hard <= warning:
            raise TrustedTimeError("trusted-time offsets require 0 < warning < hard")
        for value, field_name in (
            (self.maximum_probe_duration_ns, "maximum probe duration"),
            (self.maximum_sample_age_ns, "maximum sample age"),
            (self.maximum_cadence_gap_ns, "maximum cadence gap"),
            (self.healthy_recovery_window_ns, "healthy recovery window"),
        ):
            if type(value) is not int or value <= 0:
                raise TrustedTimeError(f"{field_name} must be a positive integer")
        if self.maximum_sample_age_ns != self.maximum_cadence_gap_ns:
            raise TrustedTimeError(
                "trusted-time freshness and replacement cadence must share one limit"
            )
        if self.maximum_probe_duration_ns > self.maximum_sample_age_ns:
            raise TrustedTimeError("trusted-time probe duration cannot exceed sample freshness")
        if self.healthy_recovery_window_ns < self.maximum_cadence_gap_ns:
            raise TrustedTimeError("trusted-time recovery cannot be shorter than the cadence limit")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            TRUSTED_TIME_CONTRACT_VERSION,
            "policy",
            self.warning_offset_milliseconds,
            self.hard_offset_milliseconds,
            self.maximum_probe_duration_ns,
            self.maximum_sample_age_ns,
            self.maximum_cadence_gap_ns,
            self.healthy_recovery_window_ns,
            "offset_lt_warning_is_healthy",
            "offset_equality_is_within_magnitude_limit",
            "probe_duration_equality_is_within_limit",
            "utc_monotonic_elapsed_delta_within_warning_offset",
            "sample_age_equality_is_stale",
            "replacement_gap_equality_preserves_cadence",
            "hard_offset_latches_until_external_manual_rearm",
            "recovery_never_changes_operational_control",
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


TRUSTED_TIME_POLICY = TrustedTimePolicy(
    warning_offset_milliseconds=Decimal("250"),
    hard_offset_milliseconds=Decimal("1000"),
    maximum_probe_duration_ns=1_000_000_000,
    maximum_sample_age_ns=30_000_000_000,
    maximum_cadence_gap_ns=30_000_000_000,
    healthy_recovery_window_ns=60_000_000_000,
)


@dataclass(frozen=True, slots=True)
class TrustedTimeSample:
    """One authenticated source reading correlated to host UTC and monotonic time.

    ``trusted_at_utc`` is the source adapter's authenticated estimate for the
    midpoint of the bounded local probe interval.  The signed offset is derived
    rather than accepted as a caller-supplied scalar.
    """

    source_id: str
    source_authority_sha256: str
    host_id: str
    monitor_epoch_id: str
    sequence: int
    source_evidence_sha256: str
    probe_started_at_utc: datetime
    probe_completed_at_utc: datetime
    trusted_at_utc: datetime
    probe_started_monotonic_ns: int
    probe_completed_monotonic_ns: int

    def __post_init__(self) -> None:
        for text_value, field_name in (
            (self.source_id, "trusted-time source ID"),
            (self.host_id, "trusted-time host ID"),
            (self.monitor_epoch_id, "trusted-time monitor epoch ID"),
        ):
            _require_text(text_value, field_name)
        _require_sha256(
            self.source_authority_sha256,
            "trusted-time source authority_sha256",
        )
        _require_sha256(
            self.source_evidence_sha256,
            "trusted-time source evidence_sha256",
        )
        if type(self.sequence) is not int or self.sequence <= 0:
            raise TrustedTimeError("trusted-time sample sequence must be a positive integer")
        for instant, field_name in (
            (self.probe_started_at_utc, "trusted-time probe started_at"),
            (self.probe_completed_at_utc, "trusted-time probe completed_at"),
            (self.trusted_at_utc, "trusted-time source instant"),
        ):
            _require_utc(instant, field_name)
        if self.probe_completed_at_utc < self.probe_started_at_utc:
            raise TrustedTimeError("trusted-time probe UTC interval regressed")
        _require_monotonic_ns(
            self.probe_started_monotonic_ns,
            "trusted-time probe started monotonic_ns",
        )
        _require_monotonic_ns(
            self.probe_completed_monotonic_ns,
            "trusted-time probe completed monotonic_ns",
        )
        if self.probe_completed_monotonic_ns < self.probe_started_monotonic_ns:
            raise TrustedTimeError("trusted-time probe monotonic interval regressed")
        monotonic_duration_ns = self.probe_completed_monotonic_ns - self.probe_started_monotonic_ns
        utc_duration_ns = _timedelta_nanoseconds(
            self.probe_completed_at_utc - self.probe_started_at_utc
        )
        if (
            monotonic_duration_ns > TRUSTED_TIME_POLICY.maximum_probe_duration_ns
            or utc_duration_ns > TRUSTED_TIME_POLICY.maximum_probe_duration_ns
        ):
            raise TrustedTimeError("trusted-time probe duration exceeded its limit")
        maximum_elapsed_delta_ns = int(
            TRUSTED_TIME_POLICY.warning_offset_milliseconds * Decimal(1_000_000)
        )
        if abs(utc_duration_ns - monotonic_duration_ns) > maximum_elapsed_delta_ns:
            raise TrustedTimeError("trusted-time UTC and monotonic probe intervals diverged")
        # Force exact persisted-range validation during construction.
        _ = self.offset_milliseconds

    @property
    def local_midpoint_at_utc(self) -> datetime:
        return (
            self.probe_started_at_utc
            + (self.probe_completed_at_utc - self.probe_started_at_utc) / 2
        )

    @property
    def offset_milliseconds(self) -> Decimal:
        return _timedelta_milliseconds(self.trusted_at_utc - self.local_midpoint_at_utc)

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            TRUSTED_TIME_CONTRACT_VERSION,
            "sample",
            self.source_id,
            self.source_authority_sha256,
            self.host_id,
            self.monitor_epoch_id,
            self.sequence,
            self.source_evidence_sha256,
            self.probe_started_at_utc,
            self.probe_completed_at_utc,
            self.local_midpoint_at_utc,
            self.trusted_at_utc,
            self.offset_milliseconds,
            self.probe_started_monotonic_ns,
            self.probe_completed_monotonic_ns,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


@dataclass(frozen=True, slots=True)
class _TrustedTimeStateSeal:
    payload_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(self.payload_sha256, "trusted-time state seal")


def _trusted_time_state_material(
    *,
    previous_state_sha256: str | None,
    policy_sha256: str,
    latest_sample: TrustedTimeSample | None,
    sample_health: TrustedTimeHealth,
    health: TrustedTimeHealth,
    reason: TrustedTimeReason,
    hard_failure_latched: bool,
    healthy_since_monotonic_ns: int | None,
    clock_recovery_qualified: bool,
    evaluated_at_utc: datetime,
    evaluated_at_monotonic_ns: int,
) -> tuple[object, ...]:
    return (
        TRUSTED_TIME_CONTRACT_VERSION,
        "state",
        policy_sha256,
        previous_state_sha256,
        None if latest_sample is None else latest_sample.semantic_sha256,
        sample_health,
        health,
        reason,
        hard_failure_latched,
        healthy_since_monotonic_ns,
        clock_recovery_qualified,
        evaluated_at_utc,
        evaluated_at_monotonic_ns,
    )


@dataclass(frozen=True, slots=True)
class TrustedTimeState:
    """One immutable, reducer-sealed monitor result."""

    previous_state_sha256: str | None
    policy_sha256: str
    latest_sample: TrustedTimeSample | None
    sample_health: TrustedTimeHealth
    health: TrustedTimeHealth
    reason: TrustedTimeReason
    hard_failure_latched: bool
    healthy_since_monotonic_ns: int | None
    clock_recovery_qualified: bool
    evaluated_at_utc: datetime
    evaluated_at_monotonic_ns: int
    _seal: _TrustedTimeStateSeal = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.previous_state_sha256 is not None:
            _require_sha256(
                self.previous_state_sha256,
                "trusted-time previous state_sha256",
            )
        _require_sha256(self.policy_sha256, "trusted-time policy_sha256")
        if self.policy_sha256 != TRUSTED_TIME_POLICY.semantic_sha256:
            raise TrustedTimeError("trusted-time state policy is not approved")
        if self.latest_sample is not None and type(self.latest_sample) is not TrustedTimeSample:
            raise TrustedTimeError("trusted-time latest sample must be exact")
        if type(self.sample_health) is not TrustedTimeHealth:
            raise TrustedTimeError("trusted-time sample health is unsupported")
        if type(self.health) is not TrustedTimeHealth:
            raise TrustedTimeError("trusted-time effective health is unsupported")
        if type(self.reason) is not TrustedTimeReason:
            raise TrustedTimeError("trusted-time state reason is unsupported")
        if type(self.hard_failure_latched) is not bool:
            raise TrustedTimeError("trusted-time hard-failure latch must be exact")
        if self.healthy_since_monotonic_ns is not None:
            _require_monotonic_ns(
                self.healthy_since_monotonic_ns,
                "trusted-time healthy-since monotonic_ns",
            )
            if self.healthy_since_monotonic_ns > self.evaluated_at_monotonic_ns:
                raise TrustedTimeError("trusted-time healthy-since cannot follow evaluation")
        if type(self.clock_recovery_qualified) is not bool:
            raise TrustedTimeError("trusted-time clock recovery result must be exact")
        if self.clock_recovery_qualified and self.healthy_since_monotonic_ns is None:
            raise TrustedTimeError("trusted-time clock recovery requires a healthy-chain origin")
        _require_utc(self.evaluated_at_utc, "trusted-time evaluated_at")
        _require_monotonic_ns(
            self.evaluated_at_monotonic_ns,
            "trusted-time evaluated monotonic_ns",
        )
        if type(self._seal) is not _TrustedTimeStateSeal:
            raise TrustedTimeError("trusted-time state must be reducer-produced")
        self._verify_seal()

    def _semantic_material(self) -> tuple[object, ...]:
        return _trusted_time_state_material(
            previous_state_sha256=self.previous_state_sha256,
            policy_sha256=self.policy_sha256,
            latest_sample=self.latest_sample,
            sample_health=self.sample_health,
            health=self.health,
            reason=self.reason,
            hard_failure_latched=self.hard_failure_latched,
            healthy_since_monotonic_ns=self.healthy_since_monotonic_ns,
            clock_recovery_qualified=self.clock_recovery_qualified,
            evaluated_at_utc=self.evaluated_at_utc,
            evaluated_at_monotonic_ns=self.evaluated_at_monotonic_ns,
        )

    def _verify_seal(self) -> str:
        payload_sha256 = _sha256(self._semantic_material())
        if self._seal.payload_sha256 != payload_sha256:
            raise TrustedTimeError("trusted-time state seal conflicts with its payload")
        return payload_sha256

    @property
    def semantic_sha256(self) -> str:
        return self._verify_seal()

    @property
    def canonical_json(self) -> str:
        self._verify_seal()
        return canonical_json_text(self._semantic_material())


def _new_trusted_time_state(
    *,
    previous_state_sha256: str | None,
    latest_sample: TrustedTimeSample | None,
    sample_health: TrustedTimeHealth,
    health: TrustedTimeHealth,
    reason: TrustedTimeReason,
    hard_failure_latched: bool,
    healthy_since_monotonic_ns: int | None,
    clock_recovery_qualified: bool,
    evaluated_at_utc: datetime,
    evaluated_at_monotonic_ns: int,
) -> TrustedTimeState:
    policy_sha256 = TRUSTED_TIME_POLICY.semantic_sha256
    material = _trusted_time_state_material(
        previous_state_sha256=previous_state_sha256,
        policy_sha256=policy_sha256,
        latest_sample=latest_sample,
        sample_health=sample_health,
        health=health,
        reason=reason,
        hard_failure_latched=hard_failure_latched,
        healthy_since_monotonic_ns=healthy_since_monotonic_ns,
        clock_recovery_qualified=clock_recovery_qualified,
        evaluated_at_utc=evaluated_at_utc,
        evaluated_at_monotonic_ns=evaluated_at_monotonic_ns,
    )
    return TrustedTimeState(
        previous_state_sha256=previous_state_sha256,
        policy_sha256=policy_sha256,
        latest_sample=latest_sample,
        sample_health=sample_health,
        health=health,
        reason=reason,
        hard_failure_latched=hard_failure_latched,
        healthy_since_monotonic_ns=healthy_since_monotonic_ns,
        clock_recovery_qualified=clock_recovery_qualified,
        evaluated_at_utc=evaluated_at_utc,
        evaluated_at_monotonic_ns=evaluated_at_monotonic_ns,
        _seal=_TrustedTimeStateSeal(payload_sha256=_sha256(material)),
    )


@dataclass(frozen=True, slots=True)
class TrustedTimeEvaluation:
    """Reducer-validated link from one prior state and optional sample to a state."""

    prior: TrustedTimeState | None
    sample: TrustedTimeSample | None
    state: TrustedTimeState

    def __post_init__(self) -> None:
        if self.prior is not None and type(self.prior) is not TrustedTimeState:
            raise TrustedTimeError("trusted-time prior state must be exact")
        if self.sample is not None and type(self.sample) is not TrustedTimeSample:
            raise TrustedTimeError("trusted-time evaluation sample must be exact")
        if type(self.state) is not TrustedTimeState:
            raise TrustedTimeError("trusted-time evaluated state must be exact")
        expected_previous = None if self.prior is None else self.prior.semantic_sha256
        if self.state.previous_state_sha256 != expected_previous:
            raise TrustedTimeError("trusted-time state predecessor conflicts")
        if (
            self.sample is None
            and self.prior is not None
            and self.state.latest_sample != self.prior.latest_sample
        ):
            raise TrustedTimeError("trusted-time unavailable evaluation changed retained sample")
        expected_state = _reduce_trusted_time_state(
            self.prior,
            self.sample,
            evaluated_at_utc=self.state.evaluated_at_utc,
            evaluated_at_monotonic_ns=self.state.evaluated_at_monotonic_ns,
        )
        if self.state != expected_state:
            raise TrustedTimeError("trusted-time evaluation conflicts with reducer semantics")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            TRUSTED_TIME_CONTRACT_VERSION,
            "evaluation",
            None if self.prior is None else self.prior.semantic_sha256,
            None if self.sample is None else self.sample.semantic_sha256,
            self.state.semantic_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


def _sample_health(sample: TrustedTimeSample) -> TrustedTimeHealth:
    magnitude = abs(sample.offset_milliseconds)
    if magnitude < TRUSTED_TIME_POLICY.warning_offset_milliseconds:
        return TrustedTimeHealth.HEALTHY
    if magnitude <= TRUSTED_TIME_POLICY.hard_offset_milliseconds:
        return TrustedTimeHealth.WARNING
    return TrustedTimeHealth.BLOCKED


def _evaluation_regression_reason(
    prior: TrustedTimeState | None,
    *,
    evaluated_at_utc: datetime,
    evaluated_at_monotonic_ns: int,
) -> TrustedTimeReason | None:
    if prior is None:
        return None
    if evaluated_at_monotonic_ns < prior.evaluated_at_monotonic_ns:
        return TrustedTimeReason.MONOTONIC_REGRESSION
    if evaluated_at_utc < prior.evaluated_at_utc:
        return TrustedTimeReason.UTC_REGRESSION
    return None


def _continuity_reason(
    prior: TrustedTimeState | None,
    sample: TrustedTimeSample,
    *,
    evaluated_at_utc: datetime,
    evaluated_at_monotonic_ns: int,
) -> TrustedTimeReason | None:
    evaluation_regression = _evaluation_regression_reason(
        prior,
        evaluated_at_utc=evaluated_at_utc,
        evaluated_at_monotonic_ns=evaluated_at_monotonic_ns,
    )
    if evaluation_regression is not None:
        return evaluation_regression
    if sample.probe_completed_monotonic_ns > evaluated_at_monotonic_ns:
        return TrustedTimeReason.MONOTONIC_REGRESSION
    if sample.probe_completed_at_utc > evaluated_at_utc:
        return TrustedTimeReason.UTC_REGRESSION
    age = evaluated_at_monotonic_ns - sample.probe_completed_monotonic_ns
    if age >= TRUSTED_TIME_POLICY.maximum_sample_age_ns:
        return TrustedTimeReason.SAMPLE_STALE
    if prior is None:
        return None if sample.sequence == 1 else TrustedTimeReason.SEQUENCE_DISCONTINUITY
    previous_sample = prior.latest_sample
    if previous_sample is None:
        return None if sample.sequence == 1 else TrustedTimeReason.SEQUENCE_DISCONTINUITY
    if (
        sample.source_id != previous_sample.source_id
        or sample.source_authority_sha256 != previous_sample.source_authority_sha256
        or sample.host_id != previous_sample.host_id
        or sample.monitor_epoch_id != previous_sample.monitor_epoch_id
    ):
        return TrustedTimeReason.IDENTITY_CHANGED
    if sample.sequence != previous_sample.sequence + 1:
        return TrustedTimeReason.SEQUENCE_DISCONTINUITY
    if sample.probe_started_monotonic_ns < previous_sample.probe_completed_monotonic_ns:
        return TrustedTimeReason.MONOTONIC_REGRESSION
    if sample.probe_started_at_utc < previous_sample.probe_completed_at_utc:
        return TrustedTimeReason.UTC_REGRESSION
    gap = sample.probe_completed_monotonic_ns - previous_sample.probe_completed_monotonic_ns
    if gap > TRUSTED_TIME_POLICY.maximum_cadence_gap_ns:
        return TrustedTimeReason.CADENCE_GAP
    return None


def _reduce_trusted_time_state(
    prior: TrustedTimeState | None,
    sample: TrustedTimeSample | None,
    *,
    evaluated_at_utc: datetime,
    evaluated_at_monotonic_ns: int,
) -> TrustedTimeState:
    previous_sha256 = None if prior is None else prior.semantic_sha256
    previous_latch = False if prior is None else prior.hard_failure_latched

    if sample is None:
        regression_reason = _evaluation_regression_reason(
            prior,
            evaluated_at_utc=evaluated_at_utc,
            evaluated_at_monotonic_ns=evaluated_at_monotonic_ns,
        )
        return _new_trusted_time_state(
            previous_state_sha256=previous_sha256,
            latest_sample=None if prior is None else prior.latest_sample,
            sample_health=TrustedTimeHealth.BLOCKED,
            health=TrustedTimeHealth.BLOCKED,
            reason=(
                regression_reason
                if regression_reason is not None
                else (
                    TrustedTimeReason.STARTUP_NO_SAMPLE
                    if prior is None
                    else TrustedTimeReason.SOURCE_UNAVAILABLE
                )
            ),
            hard_failure_latched=previous_latch,
            healthy_since_monotonic_ns=None,
            clock_recovery_qualified=False,
            evaluated_at_utc=evaluated_at_utc,
            evaluated_at_monotonic_ns=evaluated_at_monotonic_ns,
        )

    sample_health = _sample_health(sample)
    continuity_reason = _continuity_reason(
        prior,
        sample,
        evaluated_at_utc=evaluated_at_utc,
        evaluated_at_monotonic_ns=evaluated_at_monotonic_ns,
    )
    hard_failure_latched = previous_latch or sample_health is TrustedTimeHealth.BLOCKED

    healthy_since: int | None = None
    recovery_satisfied = False
    if sample_health is TrustedTimeHealth.HEALTHY:
        continuous_prior = (
            prior is not None
            and continuity_reason is None
            and prior.sample_health is TrustedTimeHealth.HEALTHY
            and prior.healthy_since_monotonic_ns is not None
        )
        if continuous_prior and prior is not None:
            healthy_since = prior.healthy_since_monotonic_ns
        else:
            healthy_since = sample.probe_completed_monotonic_ns
        if healthy_since is None:
            raise TrustedTimeError("trusted-time healthy-chain origin is unavailable")
        recovery_satisfied = (
            sample.probe_completed_monotonic_ns - healthy_since
            >= TRUSTED_TIME_POLICY.healthy_recovery_window_ns
        )

    if continuity_reason is not None:
        health = TrustedTimeHealth.BLOCKED
        reason = continuity_reason
    elif sample_health is TrustedTimeHealth.BLOCKED:
        health = TrustedTimeHealth.BLOCKED
        reason = TrustedTimeReason.HARD_OFFSET
    elif hard_failure_latched:
        health = TrustedTimeHealth.BLOCKED
        reason = TrustedTimeReason.HARD_OFFSET_LATCHED
    elif sample_health is TrustedTimeHealth.WARNING:
        health = TrustedTimeHealth.WARNING
        reason = TrustedTimeReason.WARNING_OFFSET
    else:
        health = TrustedTimeHealth.HEALTHY
        reason = (
            TrustedTimeReason.WITHIN_LIMIT
            if recovery_satisfied
            else TrustedTimeReason.STARTUP_QUALIFYING
        )

    latest_sample = (
        prior.latest_sample
        if (continuity_reason is TrustedTimeReason.IDENTITY_CHANGED and prior is not None)
        else sample
    )
    return _new_trusted_time_state(
        previous_state_sha256=previous_sha256,
        latest_sample=latest_sample,
        sample_health=sample_health,
        health=health,
        reason=reason,
        hard_failure_latched=hard_failure_latched,
        healthy_since_monotonic_ns=healthy_since,
        clock_recovery_qualified=recovery_satisfied,
        evaluated_at_utc=evaluated_at_utc,
        evaluated_at_monotonic_ns=evaluated_at_monotonic_ns,
    )


def evaluate_trusted_time(
    prior: TrustedTimeState | None,
    sample: TrustedTimeSample | None,
    *,
    evaluated_at_utc: datetime,
    evaluated_at_monotonic_ns: int,
) -> TrustedTimeEvaluation:
    """Reduce one optional authenticated sample under the approved fixed policy."""

    if prior is not None and type(prior) is not TrustedTimeState:
        raise TrustedTimeError("trusted-time prior state must be exact")
    if sample is not None and type(sample) is not TrustedTimeSample:
        raise TrustedTimeError("trusted-time sample must be exact")
    _require_utc(evaluated_at_utc, "trusted-time evaluated_at")
    _require_monotonic_ns(
        evaluated_at_monotonic_ns,
        "trusted-time evaluated monotonic_ns",
    )
    state = _reduce_trusted_time_state(
        prior,
        sample,
        evaluated_at_utc=evaluated_at_utc,
        evaluated_at_monotonic_ns=evaluated_at_monotonic_ns,
    )
    return TrustedTimeEvaluation(prior=prior, sample=sample, state=state)


__all__ = [
    "TRUSTED_TIME_CONTRACT_VERSION",
    "TRUSTED_TIME_POLICY",
    "TrustedTimeError",
    "TrustedTimeEvaluation",
    "TrustedTimeHealth",
    "TrustedTimePolicy",
    "TrustedTimeReason",
    "TrustedTimeSample",
    "TrustedTimeState",
    "evaluate_trusted_time",
]
