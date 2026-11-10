"""Provider-neutral, single-use delivery of durable critical alerts."""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from packages.domain.canonical import canonical_json_bytes
from packages.domain.critical_alert import (
    CriticalAlertConflict,
    CriticalAlertDeliveryAttempt,
    CriticalAlertDeliveryCommand,
    CriticalAlertDeliveryOutcome,
    CriticalAlertDeliveryResult,
    CriticalAlertDeliveryState,
    CriticalAlertError,
    CriticalAlertIncident,
    CriticalAlertRoute,
    critical_alert_delivery_deadline,
    critical_alert_delivery_milestone_met,
    record_critical_alert_delivery_result,
)
from packages.domain.identifiers import canonical_id

MonotonicClock = Callable[[], float]
UtcClock = Callable[[], datetime]


class CriticalAlertDeliveryError(CriticalAlertError):
    """The alert delivery boundary or one of its trusted clocks is invalid."""


class CriticalAlertDeliveryUnavailable(CriticalAlertDeliveryError):
    """A selected provider adapter is unavailable before provider I/O."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class CriticalAlertDeliveryPort(Protocol):
    """Injected provider adapter; credentials remain private to the adapter."""

    @property
    def provider_id(self) -> str: ...

    def deliver(
        self,
        request: CriticalAlertProviderRequest,
        *,
        timeout_seconds: float,
    ) -> CriticalAlertProviderReceipt: ...


class CriticalAlertDeliveryRepository(Protocol):
    """Minimum durable boundary required around a provider effect."""

    def find_delivery_attempt(
        self,
        *,
        incident_id: str,
        provider_id: str,
        idempotency_key: str,
    ) -> CriticalAlertDeliveryAttempt | None: ...

    def claim_delivery_attempt(
        self,
        command: CriticalAlertDeliveryCommand,
    ) -> tuple[CriticalAlertDeliveryAttempt, bool]: ...

    def load_delivery_result(
        self,
        attempt_id: str,
    ) -> CriticalAlertDeliveryResult | None: ...

    def load_delivery_history(
        self,
        incident_id: str,
    ) -> tuple[
        tuple[CriticalAlertDeliveryAttempt, ...],
        tuple[CriticalAlertDeliveryResult, ...],
    ]: ...

    def record_delivery_result(
        self,
        result: CriticalAlertDeliveryResult,
    ) -> CriticalAlertDeliveryResult: ...


@dataclass(frozen=True, slots=True)
class CriticalAlertProviderRequest:
    """Bounded provider input containing identifiers and digests, never secrets."""

    incident_id: str
    incident_sha256: str
    scope_id: str
    source_id: str
    alert_code: str
    evidence_sha256: str
    correlation_sha256: str
    route: CriticalAlertRoute
    provider_id: str
    idempotency_key: str

    @classmethod
    def bind(
        cls,
        *,
        incident: CriticalAlertIncident,
        route: CriticalAlertRoute,
        provider_id: str,
        idempotency_key: str,
    ) -> CriticalAlertProviderRequest:
        command_probe = CriticalAlertDeliveryCommand(
            incident_id=incident.incident_id,
            incident_sha256=incident.semantic_sha256,
            route=route,
            provider_id=provider_id,
            idempotency_key=idempotency_key,
            request_sha256="0" * 64,
            requested_at=incident.recorded_at,
        )
        # Command construction supplies strict route/provider/key validation.
        _ = command_probe
        return cls(
            incident_id=incident.incident_id,
            incident_sha256=incident.semantic_sha256,
            scope_id=incident.scope_id,
            source_id=incident.source_id,
            alert_code=incident.alert_code,
            evidence_sha256=incident.evidence_sha256,
            correlation_sha256=incident.correlation_sha256,
            route=route,
            provider_id=provider_id,
            idempotency_key=idempotency_key,
        )

    @property
    def attempt_id(self) -> str:
        return canonical_id(
            "critical-alert-delivery-attempt",
            self.incident_id,
            self.provider_id,
            self.idempotency_key,
        )

    @property
    def semantic_sha256(self) -> str:
        import hashlib

        return hashlib.sha256(
            canonical_json_bytes(
                (
                    "phase5d-critical-alert-provider-request-v1",
                    self.incident_id,
                    self.incident_sha256,
                    self.scope_id,
                    self.source_id,
                    self.alert_code,
                    self.evidence_sha256,
                    self.correlation_sha256,
                    self.route,
                    self.provider_id,
                    self.idempotency_key,
                )
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class CriticalAlertProviderReceipt:
    """Sanitized provider acknowledgement; no message or raw response is accepted."""

    provider_receipt_sha256: str

    def __post_init__(self) -> None:
        probe = CriticalAlertDeliveryResult(
            incident_id="receipt-validation",
            incident_sha256="0" * 64,
            attempt_id="receipt-validation",
            attempt_sha256="0" * 64,
            outcome=CriticalAlertDeliveryOutcome.CONFIRMED,
            completed_at=datetime(2000, 1, 1, tzinfo=UTC),
            elapsed_microseconds=0,
            provider_receipt_sha256=self.provider_receipt_sha256,
            failure_code=None,
        )
        _ = probe


@dataclass(frozen=True, slots=True)
class CriticalAlertDeliveryRun:
    """Process-local projection of a claimed attempt and optional terminal result."""

    incident: CriticalAlertIncident
    attempt: CriticalAlertDeliveryAttempt
    result: CriticalAlertDeliveryResult | None
    provider_called: bool
    exact_retry: bool

    @property
    def unresolved(self) -> bool:
        return self.result is None

    @property
    def delivery_state(self) -> CriticalAlertDeliveryState:
        if self.result is None:
            return CriticalAlertDeliveryState.UNKNOWN
        return CriticalAlertDeliveryState(self.result.outcome.value)

    @property
    def delivery_milestone_met(self) -> bool | None:
        if self.result is None:
            return None
        return critical_alert_delivery_milestone_met(
            incident=self.incident,
            attempt=self.attempt,
            result=self.result,
        )

    @property
    def requested_control_state(self) -> None:
        return None

    @property
    def broker_action_authorized(self) -> bool:
        return False


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _read_utc(clock: UtcClock) -> datetime:
    value = clock()
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise CriticalAlertDeliveryError("critical-alert UTC clock must return an aware datetime")
    if value.utcoffset() != UTC.utcoffset(value):
        raise CriticalAlertDeliveryError("critical-alert UTC clock must return UTC")
    return value


def _read_monotonic(clock: MonotonicClock, previous: float | None = None) -> float:
    raw = clock()
    if type(raw) not in {int, float}:
        raise CriticalAlertDeliveryError(
            "critical-alert monotonic clock must return a finite number"
        )
    value = float(raw)
    if not math.isfinite(value):
        raise CriticalAlertDeliveryError(
            "critical-alert monotonic clock must return a finite number"
        )
    if previous is not None and value < previous:
        raise CriticalAlertDeliveryError("critical-alert monotonic clock moved backwards")
    return value


def _elapsed_microseconds(started: float, completed: float) -> int:
    return max(0, int((completed - started) * 1_000_000))


def _result_for_failure(
    *,
    incident: CriticalAlertIncident,
    attempt: CriticalAlertDeliveryAttempt,
    outcome: CriticalAlertDeliveryOutcome,
    completed_at: datetime,
    elapsed_microseconds: int,
    failure_code: str,
) -> CriticalAlertDeliveryResult:
    return record_critical_alert_delivery_result(
        incident=incident,
        attempt=attempt,
        outcome=outcome,
        completed_at=completed_at,
        elapsed_microseconds=elapsed_microseconds,
        failure_code=failure_code,
    )


def _already_delivered(
    *,
    incident: CriticalAlertIncident,
    attempts: tuple[CriticalAlertDeliveryAttempt, ...],
    results: tuple[CriticalAlertDeliveryResult, ...],
) -> bool:
    result_by_attempt = {result.attempt_id: result for result in results}
    return any(
        result is not None
        and critical_alert_delivery_milestone_met(
            incident=incident,
            attempt=attempt,
            result=result,
        )
        for attempt in attempts
        if (result := result_by_attempt.get(attempt.attempt_id)) is not None
    )


def _escalation_is_eligible(
    *,
    incident: CriticalAlertIncident,
    attempts: tuple[CriticalAlertDeliveryAttempt, ...],
    results: tuple[CriticalAlertDeliveryResult, ...],
    requested_at: datetime,
) -> bool:
    result_by_attempt = {result.attempt_id: result for result in results}
    primary_attempts = tuple(
        attempt for attempt in attempts if attempt.route is CriticalAlertRoute.PRIMARY
    )
    primary_failed = any(
        result_by_attempt.get(attempt.attempt_id) is not None
        and not critical_alert_delivery_milestone_met(
            incident=incident,
            attempt=attempt,
            result=result_by_attempt[attempt.attempt_id],
        )
        for attempt in primary_attempts
    )
    return primary_failed or requested_at >= incident.primary_deadline


def deliver_critical_alert(
    *,
    incident: CriticalAlertIncident,
    route: CriticalAlertRoute,
    idempotency_key: str,
    repository: CriticalAlertDeliveryRepository,
    delivery_port: CriticalAlertDeliveryPort,
    utc_clock: UtcClock = _utc_now,
    monotonic_clock: MonotonicClock = time.monotonic,
) -> CriticalAlertDeliveryRun:
    """Claim once, perform at most one provider call, and durably record its result.

    An exact retry returns retained evidence. A crash after claim but before a
    terminal result remains unresolved and is never resent under the same key.
    """

    if type(incident) is not CriticalAlertIncident:
        raise CriticalAlertDeliveryError("critical-alert delivery requires an exact incident")
    if type(route) is not CriticalAlertRoute:
        raise CriticalAlertDeliveryError("critical-alert delivery requires an exact route")
    provider_id = delivery_port.provider_id
    provider_request = CriticalAlertProviderRequest.bind(
        incident=incident,
        route=route,
        provider_id=provider_id,
        idempotency_key=idempotency_key,
    )
    started_monotonic = _read_monotonic(monotonic_clock)
    requested_at = _read_utc(utc_clock)
    command = CriticalAlertDeliveryCommand(
        incident_id=incident.incident_id,
        incident_sha256=incident.semantic_sha256,
        route=route,
        provider_id=provider_id,
        idempotency_key=idempotency_key,
        request_sha256=provider_request.semantic_sha256,
        requested_at=requested_at,
    )

    existing = repository.find_delivery_attempt(
        incident_id=incident.incident_id,
        provider_id=provider_id,
        idempotency_key=idempotency_key,
    )
    if existing is not None:
        if (
            existing.route is not route
            or existing.request_sha256 != provider_request.semantic_sha256
        ):
            raise CriticalAlertConflict("critical-alert delivery idempotency key conflicts")
        return CriticalAlertDeliveryRun(
            incident=incident,
            attempt=existing,
            result=repository.load_delivery_result(existing.attempt_id),
            provider_called=False,
            exact_retry=True,
        )

    attempts, results = repository.load_delivery_history(incident.incident_id)
    if _already_delivered(
        incident=incident,
        attempts=attempts,
        results=results,
    ):
        raise CriticalAlertConflict("critical-alert already has an in-budget confirmed delivery")
    if route is CriticalAlertRoute.ESCALATION and not _escalation_is_eligible(
        incident=incident,
        attempts=attempts,
        results=results,
        requested_at=requested_at,
    ):
        raise CriticalAlertConflict("critical-alert escalation is not yet eligible")

    attempt, created = repository.claim_delivery_attempt(command)
    if not created:
        return CriticalAlertDeliveryRun(
            incident=incident,
            attempt=attempt,
            result=repository.load_delivery_result(attempt.attempt_id),
            provider_called=False,
            exact_retry=True,
        )

    last_monotonic = _read_monotonic(monotonic_clock, started_monotonic)
    elapsed_before_send = last_monotonic - started_monotonic
    deadline = critical_alert_delivery_deadline(incident, route)
    deadline_seconds = (deadline - requested_at).total_seconds()
    remaining_seconds = deadline_seconds - elapsed_before_send
    if requested_at >= deadline or remaining_seconds <= 0:
        completed_at = _read_utc(utc_clock)
        result = _result_for_failure(
            incident=incident,
            attempt=attempt,
            outcome=CriticalAlertDeliveryOutcome.TIMEOUT,
            completed_at=completed_at,
            elapsed_microseconds=_elapsed_microseconds(
                started_monotonic,
                last_monotonic,
            ),
            failure_code="delivery_deadline_missed",
        )
        return CriticalAlertDeliveryRun(
            incident=incident,
            attempt=attempt,
            result=repository.record_delivery_result(result),
            provider_called=False,
            exact_retry=False,
        )

    receipt: CriticalAlertProviderReceipt | None = None
    outcome = CriticalAlertDeliveryOutcome.CONFIRMED
    failure_code: str | None = None
    try:
        delivered = delivery_port.deliver(
            provider_request,
            timeout_seconds=remaining_seconds,
        )
        if type(delivered) is not CriticalAlertProviderReceipt:
            outcome = CriticalAlertDeliveryOutcome.ERROR
            failure_code = "invalid_provider_receipt"
        else:
            receipt = delivered
    except CriticalAlertDeliveryUnavailable:
        # Configuration discovery is not a provider outcome. The durable claim
        # remains unresolved so a restart cannot turn uncertainty into a resend.
        raise
    except TimeoutError:
        outcome = CriticalAlertDeliveryOutcome.TIMEOUT
        failure_code = "provider_timeout"
    except Exception:
        outcome = CriticalAlertDeliveryOutcome.ERROR
        failure_code = "provider_error"

    completed_monotonic = _read_monotonic(monotonic_clock, last_monotonic)
    completed_at = _read_utc(utc_clock)
    elapsed_microseconds = _elapsed_microseconds(
        started_monotonic,
        completed_monotonic,
    )
    if completed_at >= deadline or elapsed_microseconds >= int(deadline_seconds * 1_000_000):
        outcome = CriticalAlertDeliveryOutcome.TIMEOUT
        failure_code = "delivery_deadline_missed"
        receipt = None

    if outcome is CriticalAlertDeliveryOutcome.CONFIRMED:
        if receipt is None:
            raise CriticalAlertDeliveryError("critical-alert confirmed delivery lost its receipt")
        result = record_critical_alert_delivery_result(
            incident=incident,
            attempt=attempt,
            outcome=outcome,
            completed_at=completed_at,
            elapsed_microseconds=elapsed_microseconds,
            provider_receipt_sha256=receipt.provider_receipt_sha256,
        )
    else:
        if failure_code is None:
            raise CriticalAlertDeliveryError("critical-alert failed delivery lost its failure code")
        result = _result_for_failure(
            incident=incident,
            attempt=attempt,
            outcome=outcome,
            completed_at=completed_at,
            elapsed_microseconds=elapsed_microseconds,
            failure_code=failure_code,
        )
    return CriticalAlertDeliveryRun(
        incident=incident,
        attempt=attempt,
        result=repository.record_delivery_result(result),
        provider_called=True,
        exact_retry=False,
    )
