"""Pure scheduling and evidence state for sparse trusted-head anchoring.

The core in this module performs no database, network, signing, sleeping, or
thread operations.  A runtime may notify it about completed durable probes and
execute the returned work requests on one background worker.  Consequently,
external anchoring can never delay the twenty-second local trusted-time probe
grid.

External checkpoints are evidence only.  No state or result in this module
grants readiness, operational control, exposure, arming, resume, re-arm,
paper/live trading, or broker authority.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from packages.application.durable_trusted_time_monitor import PersistedTrustedTimeProbe
from packages.application.trusted_time_head_anchor import (
    TrustedTimeHeadAnchorCheckpointReason,
)
from packages.domain.trusted_time import TrustedTimeHealth

TRUSTED_TIME_HEAD_ANCHOR_WORKER_CONTRACT_VERSION = (
    "phase6d-single-flight-trusted-head-anchor-worker-v1"
)
TRUSTED_TIME_HEAD_ANCHOR_WORKER_INTERVAL_NS = 300_000_000_000
TRUSTED_TIME_HEAD_ANCHOR_WORKER_STALE_AFTER_NS = 360_000_000_000
TRUSTED_TIME_HEAD_ANCHOR_WORKER_RETRY_INTERVAL_NS = 20_000_000_000

_MAX_MONOTONIC_NS = 9_223_372_036_854_775_807
_MAX_PENDING_REASONS = len(TrustedTimeHeadAnchorCheckpointReason)


class TrustedTimeHeadAnchorWorkerError(RuntimeError):
    """The background anchor worker contract was violated."""


class TrustedTimeHeadAnchorTransientFailure(RuntimeError):
    """A bounded external outage may be retried without stopping local probes."""


class TrustedTimeHeadAnchorFatalFailure(RuntimeError):
    """Configuration, integrity, fork, or durable-state failure is terminal."""


class TrustedTimeHeadAnchorEnrollmentNotApprovedFailure(TrustedTimeHeadAnchorFatalFailure):
    """Remote history is absent and first enrollment remains owner-blocked."""


class TrustedTimeHeadAnchorFatalReason(StrEnum):
    """Fixed nonsecret classifications retained across the background boundary."""

    REMOTE_HISTORY_ABSENT_ENROLLMENT_NOT_APPROVED = (
        "head_anchor_remote_history_absent_enrollment_not_approved"
    )


class TrustedTimeHeadAnchorWorkerStatus(StrEnum):
    STARTING = "starting"
    CURRENT = "current"
    UNAVAILABLE = "unavailable"
    FATAL = "fatal"
    STOPPED = "stopped"


def _authority_is_never_granted(_: object) -> bool:
    return False


def _require_monotonic_ns(value: object, field_name: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_MONOTONIC_NS:
        raise TrustedTimeHeadAnchorWorkerError(
            f"trusted-time anchor worker {field_name} is invalid"
        )
    return value


def _require_positive_integer(value: object, field_name: str) -> int:
    if type(value) is not int or not 0 < value <= _MAX_MONOTONIC_NS:
        raise TrustedTimeHeadAnchorWorkerError(
            f"trusted-time anchor worker {field_name} is invalid"
        )
    return value


def _require_sha256(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise TrustedTimeHeadAnchorWorkerError(
            f"trusted-time anchor worker {field_name} is invalid"
        )
    return value


def _require_optional_sha256(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, field_name)


def _require_utc(value: object, field_name: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise TrustedTimeHeadAnchorWorkerError(
            f"trusted-time anchor worker {field_name} must be UTC"
        )
    return value


@dataclass(frozen=True, slots=True)
class TrustedTimeHeadAnchorWorkRequest:
    """One single-flight checkpoint request selected by the pure scheduler."""

    request_sequence: int
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason
    full_audit: bool
    allow_enrollment: bool
    scheduled_monotonic_ns: int

    def __post_init__(self) -> None:
        _require_positive_integer(self.request_sequence, "request sequence")
        if type(self.checkpoint_reason) is not TrustedTimeHeadAnchorCheckpointReason:
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker checkpoint reason is invalid"
            )
        if type(self.full_audit) is not bool or type(self.allow_enrollment) is not bool:
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker audit or enrollment flag is invalid"
            )
        if self.allow_enrollment and not self.full_audit:
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor enrollment requires a full startup audit"
            )
        _require_monotonic_ns(
            self.scheduled_monotonic_ns,
            "scheduled monotonic instant",
        )

    operational_control_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)
    alert_delivery_authorized = property(_authority_is_never_granted)
    exposure_authorized = property(_authority_is_never_granted)
    paper_trading_authorized = property(_authority_is_never_granted)
    live_trading_authorized = property(_authority_is_never_granted)


@dataclass(frozen=True, slots=True)
class TrustedTimeHeadAnchorAttemptResult:
    """Sanitized result returned only after remote and local confirmation.

    ``receipt_semantic_sha256`` is required when a new candidate was remotely
    observed.  A terminal-object verification that needed no new candidate has
    no new receipt and leaves it null.
    """

    request_sequence: int
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason
    current_host_head_sha256: str
    current_anchor_sha256: str
    current_anchor_semantic_sha256: str
    completed_at_utc: datetime
    full_audit_completed: bool
    pending_intent_recovered: bool
    candidate_remote_readback_sha256: str | None
    receipt_semantic_sha256: str | None

    def __post_init__(self) -> None:
        _require_positive_integer(self.request_sequence, "result request sequence")
        if type(self.checkpoint_reason) is not TrustedTimeHeadAnchorCheckpointReason:
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker result reason is invalid"
            )
        _require_sha256(self.current_host_head_sha256, "result host-head SHA-256")
        _require_sha256(self.current_anchor_sha256, "result anchor SHA-256")
        _require_sha256(
            self.current_anchor_semantic_sha256,
            "result anchor semantic SHA-256",
        )
        _require_utc(self.completed_at_utc, "result completion instant")
        if (
            type(self.full_audit_completed) is not bool
            or type(self.pending_intent_recovered) is not bool
        ):
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker result audit or recovery flag is invalid"
            )
        readback = _require_optional_sha256(
            self.candidate_remote_readback_sha256,
            "candidate remote-readback SHA-256",
        )
        receipt = _require_optional_sha256(
            self.receipt_semantic_sha256,
            "durable receipt semantic SHA-256",
        )
        if (readback is None) != (receipt is None):
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor remote readback and durable receipt must be paired"
            )

    operational_control_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)
    alert_delivery_authorized = property(_authority_is_never_granted)
    exposure_authorized = property(_authority_is_never_granted)
    paper_trading_authorized = property(_authority_is_never_granted)
    live_trading_authorized = property(_authority_is_never_granted)


class TrustedTimeHeadAnchorAttempt(Protocol):
    """One complete prepare/intent/upload/readback/receipt composition.

    Implementations must raise ``TrustedTimeHeadAnchorTransientFailure`` only
    for a positively classified bounded provider outage.  Every unclassified,
    configuration, persistence, signature, rollback, or fork failure is fatal.
    """

    def __call__(
        self,
        request: TrustedTimeHeadAnchorWorkRequest,
    ) -> TrustedTimeHeadAnchorAttemptResult: ...


@dataclass(frozen=True, slots=True)
class TrustedTimeHeadAnchorWorkerEvidence:
    """Point-in-time external evidence projection; never an authority grant."""

    status: TrustedTimeHeadAnchorWorkerStatus
    observed_at_monotonic_ns: int
    last_successful_anchor_monotonic_ns: int | None
    last_successful_anchor_at_utc: datetime | None
    current_host_head_sha256: str | None
    current_anchor_sha256: str | None
    current_anchor_semantic_sha256: str | None
    last_checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason | None
    request_in_flight: bool
    pending_reason_count: int
    startup_full_audit_completed: bool
    external_head_anchor_evidence: bool
    fatal_error_latched: bool
    clean_shutdown_completed: bool

    def __post_init__(self) -> None:
        if type(self.status) is not TrustedTimeHeadAnchorWorkerStatus:
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker evidence status is invalid"
            )
        observed = _require_monotonic_ns(
            self.observed_at_monotonic_ns,
            "evidence observation instant",
        )
        success_monotonic = self.last_successful_anchor_monotonic_ns
        success_utc = self.last_successful_anchor_at_utc
        digests = (
            self.current_host_head_sha256,
            self.current_anchor_sha256,
            self.current_anchor_semantic_sha256,
        )
        if success_monotonic is None:
            if success_utc is not None or any(value is not None for value in digests):
                raise TrustedTimeHeadAnchorWorkerError(
                    "trusted-time anchor worker evidence has a partial successful result"
                )
        else:
            exact_success = _require_monotonic_ns(
                success_monotonic,
                "last successful anchor instant",
            )
            if exact_success > observed or success_utc is None:
                raise TrustedTimeHeadAnchorWorkerError(
                    "trusted-time anchor worker evidence success instant is invalid"
                )
            _require_utc(success_utc, "last successful anchor UTC instant")
            for digest, field_name in zip(
                digests,
                ("host-head SHA-256", "anchor SHA-256", "anchor semantic SHA-256"),
                strict=True,
            ):
                _require_sha256(digest, field_name)
        if (
            self.last_checkpoint_reason is not None
            and type(self.last_checkpoint_reason) is not TrustedTimeHeadAnchorCheckpointReason
        ):
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker evidence reason is invalid"
            )
        if type(self.pending_reason_count) is not int or not (
            0 <= self.pending_reason_count <= _MAX_PENDING_REASONS + 1
        ):
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker pending-reason count is invalid"
            )
        for flag in (
            self.request_in_flight,
            self.startup_full_audit_completed,
            self.external_head_anchor_evidence,
            self.fatal_error_latched,
            self.clean_shutdown_completed,
        ):
            if type(flag) is not bool:
                raise TrustedTimeHeadAnchorWorkerError(
                    "trusted-time anchor worker evidence flag is invalid"
                )
        if self.external_head_anchor_evidence and success_monotonic is None:
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker evidence lacks a successful checkpoint"
            )
        if self.fatal_error_latched != (self.status is TrustedTimeHeadAnchorWorkerStatus.FATAL):
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker fatal status conflicts with its latch"
            )
        if self.clean_shutdown_completed and (
            self.status is not TrustedTimeHeadAnchorWorkerStatus.STOPPED
        ):
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker stop status conflicts with completion"
            )

    operational_control_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)
    alert_delivery_authorized = property(_authority_is_never_granted)
    exposure_authorized = property(_authority_is_never_granted)
    paper_trading_authorized = property(_authority_is_never_granted)
    live_trading_authorized = property(_authority_is_never_granted)


@dataclass(frozen=True, slots=True)
class _QueuedReason:
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason
    enqueued_monotonic_ns: int
    full_audit: bool = False


class TrustedTimeHeadAnchorWorkerCore:
    """Deterministic single-flight scheduling, retry, and freshness state."""

    __slots__ = (
        "_allow_enrollment",
        "_clean_shutdown_completed",
        "_clean_stop_requested",
        "_failure_latched",
        "_fatal",
        "_in_flight",
        "_last_anchor_monotonic_ns",
        "_last_attempt_result",
        "_last_hard_failure_latched",
        "_last_health",
        "_last_monotonic_ns",
        "_last_recovery_qualified",
        "_next_periodic_monotonic_ns",
        "_next_request_sequence",
        "_pending_reasons",
        "_retry_due_monotonic_ns",
        "_retry_request",
        "_started_at_monotonic_ns",
        "_startup_full_audit_completed",
        "_stopped",
    )

    def __init__(
        self,
        *,
        started_at_monotonic_ns: int,
        allow_enrollment: bool = False,
    ) -> None:
        started = _require_monotonic_ns(
            started_at_monotonic_ns,
            "start monotonic instant",
        )
        if type(allow_enrollment) is not bool:
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker enrollment flag is invalid"
            )
        if started > _MAX_MONOTONIC_NS - TRUSTED_TIME_HEAD_ANCHOR_WORKER_INTERVAL_NS:
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker periodic grid would overflow"
            )
        self._started_at_monotonic_ns = started
        self._last_monotonic_ns = started
        self._allow_enrollment = allow_enrollment
        self._next_periodic_monotonic_ns = started + TRUSTED_TIME_HEAD_ANCHOR_WORKER_INTERVAL_NS
        self._next_request_sequence = 1
        self._pending_reasons: deque[_QueuedReason] = deque(
            (
                _QueuedReason(
                    (
                        TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT
                        if allow_enrollment
                        else TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION
                    ),
                    started,
                    True,
                ),
            )
        )
        self._in_flight: TrustedTimeHeadAnchorWorkRequest | None = None
        self._retry_request: TrustedTimeHeadAnchorWorkRequest | None = None
        self._retry_due_monotonic_ns: int | None = None
        self._startup_full_audit_completed = False
        self._failure_latched = False
        self._fatal = False
        self._stopped = False
        self._clean_stop_requested = False
        self._clean_shutdown_completed = False
        self._last_anchor_monotonic_ns: int | None = None
        self._last_attempt_result: TrustedTimeHeadAnchorAttemptResult | None = None
        self._last_health: TrustedTimeHealth | None = None
        self._last_hard_failure_latched = False
        self._last_recovery_qualified = False

    def _observe_monotonic(self, value: object, field_name: str) -> int:
        observed = _require_monotonic_ns(value, field_name)
        if observed < self._last_monotonic_ns:
            self._fatal = True
            self._failure_latched = True
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker monotonic clock regressed"
            )
        self._last_monotonic_ns = observed
        return observed

    def _enqueue_reason(
        self,
        reason: TrustedTimeHeadAnchorCheckpointReason,
        *,
        observed_at_monotonic_ns: int,
        full_audit: bool = False,
    ) -> None:
        if self._fatal or self._stopped or self._clean_stop_requested:
            return
        if any(item.checkpoint_reason is reason for item in self._pending_reasons):
            return
        if self._retry_request is not None and self._retry_request.checkpoint_reason is reason:
            return
        if self._in_flight is not None and self._in_flight.checkpoint_reason is reason:
            return
        if len(self._pending_reasons) >= _MAX_PENDING_REASONS:
            self._fatal = True
            self._failure_latched = True
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker pending reasons exceeded their bound"
            )
        self._pending_reasons.append(
            _QueuedReason(
                checkpoint_reason=reason,
                enqueued_monotonic_ns=observed_at_monotonic_ns,
                full_audit=full_audit,
            )
        )

    def request_epoch_rotation(self, *, observed_at_monotonic_ns: int) -> None:
        observed = self._observe_monotonic(
            observed_at_monotonic_ns,
            "epoch-rotation observation instant",
        )
        self._enqueue_reason(
            TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION,
            observed_at_monotonic_ns=observed,
        )

    def request_on_demand(self, *, observed_at_monotonic_ns: int) -> None:
        observed = self._observe_monotonic(
            observed_at_monotonic_ns,
            "on-demand observation instant",
        )
        self._enqueue_reason(
            TrustedTimeHeadAnchorCheckpointReason.ON_DEMAND,
            observed_at_monotonic_ns=observed,
            full_audit=True,
        )

    def observe_persisted_probe(
        self,
        persisted_probe: PersistedTrustedTimeProbe,
        *,
        observed_at_monotonic_ns: int,
    ) -> None:
        """Queue transition reasons without invoking any external dependency."""

        observed = self._observe_monotonic(
            observed_at_monotonic_ns,
            "durable-probe observation instant",
        )
        if type(persisted_probe) is not PersistedTrustedTimeProbe:
            self._fatal = True
            self._failure_latched = True
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker durable probe is invalid"
            )
        try:
            persisted_probe.__post_init__()
        except Exception:
            self._fatal = True
            self._failure_latched = True
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker durable probe is invalid"
            ) from None
        state = persisted_probe.result.evaluation.state
        reason: TrustedTimeHeadAnchorCheckpointReason | None = None
        if state.hard_failure_latched and not self._last_hard_failure_latched:
            reason = TrustedTimeHeadAnchorCheckpointReason.HARD_FAILURE
        elif state.clock_recovery_qualified and not self._last_recovery_qualified:
            reason = TrustedTimeHeadAnchorCheckpointReason.RECOVERY_TRANSITION
        elif self._last_health is not None and state.health is not self._last_health:
            reason = TrustedTimeHeadAnchorCheckpointReason.HEALTH_TRANSITION
        self._last_health = state.health
        self._last_hard_failure_latched = state.hard_failure_latched
        self._last_recovery_qualified = state.clock_recovery_qualified
        if reason is not None:
            self._enqueue_reason(reason, observed_at_monotonic_ns=observed)

    def request_clean_stop(self, *, observed_at_monotonic_ns: int) -> None:
        observed = self._observe_monotonic(
            observed_at_monotonic_ns,
            "clean-stop observation instant",
        )
        if self._fatal or self._stopped:
            return
        self._clean_stop_requested = True
        if self._startup_full_audit_completed:
            self._pending_reasons.clear()
            self._retry_request = None
            self._retry_due_monotonic_ns = None
        elif self._in_flight is not None and self._in_flight.full_audit:
            self._pending_reasons.clear()
        else:
            # Preserve only the one startup full-audit request.  Later reasons
            # are superseded by a clean-stop checkpoint of the latest head.
            self._pending_reasons = deque(tuple(self._pending_reasons)[:1])
            if self._retry_request is not None:
                self._pending_reasons.clear()
                self._retry_due_monotonic_ns = observed
        if not any(
            item.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP
            for item in self._pending_reasons
        ):
            self._pending_reasons.append(
                _QueuedReason(
                    TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP,
                    observed,
                    False,
                )
            )

    def _new_request(
        self,
        *,
        reason: TrustedTimeHeadAnchorCheckpointReason,
        scheduled_monotonic_ns: int,
        full_audit: bool,
    ) -> TrustedTimeHeadAnchorWorkRequest:
        request = TrustedTimeHeadAnchorWorkRequest(
            request_sequence=self._next_request_sequence,
            checkpoint_reason=reason,
            full_audit=full_audit,
            allow_enrollment=(
                full_audit and not self._startup_full_audit_completed and self._allow_enrollment
            ),
            scheduled_monotonic_ns=scheduled_monotonic_ns,
        )
        self._next_request_sequence += 1
        self._in_flight = request
        return request

    def take_work(
        self,
        *,
        observed_at_monotonic_ns: int,
    ) -> TrustedTimeHeadAnchorWorkRequest | None:
        observed = self._observe_monotonic(
            observed_at_monotonic_ns,
            "work-selection observation instant",
        )
        if self._fatal or self._stopped or self._in_flight is not None:
            return None

        retry = self._retry_request
        retry_due = self._retry_due_monotonic_ns
        if not self._startup_full_audit_completed and retry is not None:
            if retry_due is None or observed < retry_due:
                return None
            self._retry_request = None
            self._retry_due_monotonic_ns = None
            return self._new_request(
                reason=retry.checkpoint_reason,
                scheduled_monotonic_ns=retry_due,
                full_audit=True,
            )

        if self._pending_reasons:
            queued = self._pending_reasons.popleft()
            return self._new_request(
                reason=queued.checkpoint_reason,
                scheduled_monotonic_ns=queued.enqueued_monotonic_ns,
                full_audit=(not self._startup_full_audit_completed or queued.full_audit),
            )

        if retry is not None and retry_due is not None and observed >= retry_due:
            self._retry_request = None
            self._retry_due_monotonic_ns = None
            return self._new_request(
                reason=retry.checkpoint_reason,
                scheduled_monotonic_ns=retry_due,
                full_audit=retry.full_audit,
            )

        if observed >= self._next_periodic_monotonic_ns:
            scheduled = self._next_periodic_monotonic_ns
            intervals = ((observed - scheduled) // TRUSTED_TIME_HEAD_ANCHOR_WORKER_INTERVAL_NS) + 1
            advance = intervals * TRUSTED_TIME_HEAD_ANCHOR_WORKER_INTERVAL_NS
            if scheduled > _MAX_MONOTONIC_NS - advance:
                self._fatal = True
                self._failure_latched = True
                raise TrustedTimeHeadAnchorWorkerError(
                    "trusted-time anchor worker periodic grid overflowed"
                )
            self._next_periodic_monotonic_ns = scheduled + advance
            return self._new_request(
                reason=TrustedTimeHeadAnchorCheckpointReason.PERIODIC,
                scheduled_monotonic_ns=scheduled,
                full_audit=False,
            )
        return None

    def next_wake_monotonic_ns(self) -> int | None:
        if self._fatal or self._stopped or self._in_flight is not None:
            return None
        if self._pending_reasons:
            return self._last_monotonic_ns
        deadlines = [self._next_periodic_monotonic_ns]
        if self._retry_due_monotonic_ns is not None:
            deadlines.append(self._retry_due_monotonic_ns)
        return min(deadlines)

    def record_success(
        self,
        request: TrustedTimeHeadAnchorWorkRequest,
        result: TrustedTimeHeadAnchorAttemptResult,
        *,
        observed_at_monotonic_ns: int,
    ) -> None:
        observed = self._observe_monotonic(
            observed_at_monotonic_ns,
            "successful-attempt observation instant",
        )
        if request is not self._in_flight:
            self._fatal = True
            self._failure_latched = True
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker completed a foreign request"
            )
        if type(result) is not TrustedTimeHeadAnchorAttemptResult:
            self._fatal = True
            self._failure_latched = True
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker attempt result is invalid"
            )
        try:
            result.__post_init__()
        except Exception:
            self._fatal = True
            self._failure_latched = True
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker attempt result is invalid"
            ) from None
        if (
            result.request_sequence != request.request_sequence
            or result.checkpoint_reason is not request.checkpoint_reason
            or (request.full_audit and not result.full_audit_completed)
        ):
            self._fatal = True
            self._failure_latched = True
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker attempt result conflicts with its request"
            )
        self._in_flight = None
        self._retry_request = None
        self._retry_due_monotonic_ns = None
        self._failure_latched = False
        self._last_anchor_monotonic_ns = observed
        self._last_attempt_result = result
        if request.full_audit:
            self._startup_full_audit_completed = True
        if request.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP:
            self._stopped = True
            self._clean_shutdown_completed = True

    def record_transient_failure(
        self,
        request: TrustedTimeHeadAnchorWorkRequest,
        *,
        observed_at_monotonic_ns: int,
    ) -> None:
        observed = self._observe_monotonic(
            observed_at_monotonic_ns,
            "transient-failure observation instant",
        )
        if request is not self._in_flight:
            self._fatal = True
            self._failure_latched = True
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker failed a foreign request"
            )
        self._in_flight = None
        self._failure_latched = True
        if request.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP:
            self._stopped = True
            return
        if observed > _MAX_MONOTONIC_NS - TRUSTED_TIME_HEAD_ANCHOR_WORKER_RETRY_INTERVAL_NS:
            self._fatal = True
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker retry deadline overflowed"
            )
        self._retry_request = request
        self._retry_due_monotonic_ns = observed + TRUSTED_TIME_HEAD_ANCHOR_WORKER_RETRY_INTERVAL_NS

    def record_fatal_failure(
        self,
        request: TrustedTimeHeadAnchorWorkRequest | None,
        *,
        observed_at_monotonic_ns: int,
    ) -> None:
        self._observe_monotonic(
            observed_at_monotonic_ns,
            "fatal-failure observation instant",
        )
        if request is not None and request is not self._in_flight:
            raise TrustedTimeHeadAnchorWorkerError(
                "trusted-time anchor worker rejected a foreign fatal request"
            )
        self._in_flight = None
        self._retry_request = None
        self._retry_due_monotonic_ns = None
        self._failure_latched = True
        self._fatal = True

    def evidence(
        self,
        *,
        observed_at_monotonic_ns: int,
    ) -> TrustedTimeHeadAnchorWorkerEvidence:
        observed = self._observe_monotonic(
            observed_at_monotonic_ns,
            "evidence observation instant",
        )
        result = self._last_attempt_result
        last_success = self._last_anchor_monotonic_ns
        fresh = (
            not self._failure_latched
            and not self._fatal
            and last_success is not None
            and observed - last_success < TRUSTED_TIME_HEAD_ANCHOR_WORKER_STALE_AFTER_NS
        )
        if self._fatal:
            status = TrustedTimeHeadAnchorWorkerStatus.FATAL
        elif self._stopped:
            status = TrustedTimeHeadAnchorWorkerStatus.STOPPED
        elif fresh:
            status = TrustedTimeHeadAnchorWorkerStatus.CURRENT
        elif self._startup_full_audit_completed or self._failure_latched:
            status = TrustedTimeHeadAnchorWorkerStatus.UNAVAILABLE
        else:
            status = TrustedTimeHeadAnchorWorkerStatus.STARTING
        pending_count = len(self._pending_reasons) + int(self._retry_request is not None)
        return TrustedTimeHeadAnchorWorkerEvidence(
            status=status,
            observed_at_monotonic_ns=observed,
            last_successful_anchor_monotonic_ns=last_success,
            last_successful_anchor_at_utc=(None if result is None else result.completed_at_utc),
            current_host_head_sha256=(None if result is None else result.current_host_head_sha256),
            current_anchor_sha256=None if result is None else result.current_anchor_sha256,
            current_anchor_semantic_sha256=(
                None if result is None else result.current_anchor_semantic_sha256
            ),
            last_checkpoint_reason=None if result is None else result.checkpoint_reason,
            request_in_flight=self._in_flight is not None,
            pending_reason_count=pending_count,
            startup_full_audit_completed=self._startup_full_audit_completed,
            external_head_anchor_evidence=fresh,
            fatal_error_latched=self._fatal,
            clean_shutdown_completed=self._clean_shutdown_completed,
        )

    @property
    def fatal_error_latched(self) -> bool:
        return self._fatal

    @property
    def clean_shutdown_completed(self) -> bool:
        return self._clean_shutdown_completed

    @property
    def stopped(self) -> bool:
        return self._stopped


__all__ = [
    "TRUSTED_TIME_HEAD_ANCHOR_WORKER_CONTRACT_VERSION",
    "TRUSTED_TIME_HEAD_ANCHOR_WORKER_INTERVAL_NS",
    "TRUSTED_TIME_HEAD_ANCHOR_WORKER_RETRY_INTERVAL_NS",
    "TRUSTED_TIME_HEAD_ANCHOR_WORKER_STALE_AFTER_NS",
    "TrustedTimeHeadAnchorAttempt",
    "TrustedTimeHeadAnchorAttemptResult",
    "TrustedTimeHeadAnchorEnrollmentNotApprovedFailure",
    "TrustedTimeHeadAnchorFatalFailure",
    "TrustedTimeHeadAnchorFatalReason",
    "TrustedTimeHeadAnchorTransientFailure",
    "TrustedTimeHeadAnchorWorkRequest",
    "TrustedTimeHeadAnchorWorkerCore",
    "TrustedTimeHeadAnchorWorkerError",
    "TrustedTimeHeadAnchorWorkerEvidence",
    "TrustedTimeHeadAnchorWorkerStatus",
]
