from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from packages.application.critical_alert_delivery import (
    CriticalAlertDeliveryPort,
    CriticalAlertDeliveryRun,
    CriticalAlertProviderReceipt,
    CriticalAlertProviderRequest,
    deliver_critical_alert,
)
from packages.domain.critical_alert import (
    CriticalAlertConflict,
    CriticalAlertDeliveryAttempt,
    CriticalAlertDeliveryCommand,
    CriticalAlertDeliveryOutcome,
    CriticalAlertDeliveryResult,
    CriticalAlertDeliveryState,
    CriticalAlertIncident,
    CriticalAlertRoute,
    append_critical_alert_delivery_attempt,
    validate_critical_alert_delivery_history,
)

BASE = datetime(2026, 7, 28, 14, 0, tzinfo=UTC)


def _incident() -> CriticalAlertIncident:
    return CriticalAlertIncident(
        scope_id="paper-account-1",
        source_id="strategy-supervisor",
        idempotency_key="incident-0001",
        alert_code="strategy_deadline_exceeded",
        evidence_sha256="a" * 64,
        detected_at=BASE - timedelta(milliseconds=100),
        recorded_at=BASE,
        correlation_sha256="b" * 64,
    )


def _sequence_float(values: tuple[float, ...]) -> Callable[[], float]:
    remaining = iter(values)

    def read() -> float:
        return next(remaining)

    return read


def _sequence_utc(values: tuple[datetime, ...]) -> Callable[[], datetime]:
    remaining = iter(values)

    def read() -> datetime:
        return next(remaining)

    return read


@dataclass(slots=True)
class MemoryCriticalAlertRepository:
    incident: CriticalAlertIncident
    attempts: list[CriticalAlertDeliveryAttempt] = field(default_factory=list)
    results: dict[str, CriticalAlertDeliveryResult] = field(default_factory=dict)

    def find_delivery_attempt(
        self,
        *,
        incident_id: str,
        provider_id: str,
        idempotency_key: str,
    ) -> CriticalAlertDeliveryAttempt | None:
        assert incident_id == self.incident.incident_id
        return next(
            (
                attempt
                for attempt in self.attempts
                if attempt.provider_id == provider_id and attempt.idempotency_key == idempotency_key
            ),
            None,
        )

    def claim_delivery_attempt(
        self,
        command: CriticalAlertDeliveryCommand,
    ) -> tuple[CriticalAlertDeliveryAttempt, bool]:
        existing = self.find_delivery_attempt(
            incident_id=command.incident_id,
            provider_id=command.provider_id,
            idempotency_key=command.idempotency_key,
        )
        if existing is not None:
            if existing.command_sha256 != command.semantic_sha256:
                raise CriticalAlertConflict("delivery command conflicts")
            return existing, False
        attempt = append_critical_alert_delivery_attempt(
            incident=self.incident,
            command=command,
            claimed_at=command.requested_at,
            previous=self.attempts[-1] if self.attempts else None,
        )
        self.attempts.append(attempt)
        return attempt, True

    def load_delivery_result(
        self,
        attempt_id: str,
    ) -> CriticalAlertDeliveryResult | None:
        return self.results.get(attempt_id)

    def load_delivery_history(
        self,
        incident_id: str,
    ) -> tuple[
        tuple[CriticalAlertDeliveryAttempt, ...],
        tuple[CriticalAlertDeliveryResult, ...],
    ]:
        assert incident_id == self.incident.incident_id
        attempts = tuple(self.attempts)
        results = tuple(
            self.results[attempt.attempt_id]
            for attempt in attempts
            if attempt.attempt_id in self.results
        )
        validate_critical_alert_delivery_history(
            incident=self.incident,
            attempts=attempts,
            results=results,
        )
        return attempts, results

    def record_delivery_result(
        self,
        result: CriticalAlertDeliveryResult,
    ) -> CriticalAlertDeliveryResult:
        existing = self.results.get(result.attempt_id)
        if existing is not None:
            if existing != result:
                raise CriticalAlertConflict("delivery result conflicts")
            return existing
        self.results[result.attempt_id] = result
        return result


@dataclass(slots=True)
class StubDeliveryPort:
    provider_id: str
    behavior: str = "confirmed"
    calls: list[tuple[CriticalAlertProviderRequest, float]] = field(default_factory=list)

    def deliver(
        self,
        request: CriticalAlertProviderRequest,
        *,
        timeout_seconds: float,
    ) -> CriticalAlertProviderReceipt:
        self.calls.append((request, timeout_seconds))
        if self.behavior == "timeout":
            raise TimeoutError("raw timeout response must not be retained")
        if self.behavior == "error":
            raise RuntimeError("raw provider secret must not be retained")
        return CriticalAlertProviderReceipt(provider_receipt_sha256="c" * 64)


def _run(
    *,
    incident: CriticalAlertIncident,
    repository: MemoryCriticalAlertRepository,
    port: CriticalAlertDeliveryPort,
    route: CriticalAlertRoute = CriticalAlertRoute.PRIMARY,
    key: str = "delivery-0001",
    requested_at: datetime,
    completed_at: datetime | None = None,
) -> CriticalAlertDeliveryRun:
    return deliver_critical_alert(
        incident=incident,
        route=route,
        idempotency_key=key,
        repository=repository,
        delivery_port=port,
        utc_clock=_sequence_utc(
            (requested_at,) if completed_at is None else (requested_at, completed_at)
        ),
        monotonic_clock=_sequence_float((0.0,) if completed_at is None else (0.0, 0.01, 0.1)),
    )


def test_primary_confirmation_is_single_use_and_exact_retry_does_not_resend() -> None:
    incident = _incident()
    repository = MemoryCriticalAlertRepository(incident)
    port = StubDeliveryPort("primary-pager")
    first = _run(
        incident=incident,
        repository=repository,
        port=port,
        requested_at=BASE + timedelta(seconds=1),
        completed_at=BASE + timedelta(seconds=2),
    )
    assert first.result is not None
    assert first.result.outcome is CriticalAlertDeliveryOutcome.CONFIRMED
    assert first.delivery_milestone_met is True
    assert first.provider_called is True
    assert first.requested_control_state is None
    assert first.broker_action_authorized is False
    assert len(port.calls) == 1
    assert port.calls[0][1] < 15

    retry = _run(
        incident=incident,
        repository=repository,
        port=port,
        requested_at=BASE + timedelta(seconds=3),
    )

    assert retry.exact_retry is True
    assert retry.provider_called is False
    assert retry.result == first.result
    assert len(port.calls) == 1


@pytest.mark.parametrize(
    ("behavior", "outcome", "failure_code"),
    (
        ("timeout", CriticalAlertDeliveryOutcome.TIMEOUT, "provider_timeout"),
        ("error", CriticalAlertDeliveryOutcome.ERROR, "provider_error"),
    ),
)
def test_provider_timeout_and_error_are_sanitized_explicit_failures(
    behavior: str,
    outcome: CriticalAlertDeliveryOutcome,
    failure_code: str,
) -> None:
    incident = _incident()
    repository = MemoryCriticalAlertRepository(incident)
    port = StubDeliveryPort("primary-pager", behavior=behavior)

    run = _run(
        incident=incident,
        repository=repository,
        port=port,
        requested_at=BASE + timedelta(seconds=1),
        completed_at=BASE + timedelta(seconds=2),
    )
    assert run.result is not None
    assert run.result.outcome is outcome
    assert run.result.failure_code == failure_code
    assert run.result.provider_receipt_sha256 is None
    assert "raw" not in run.result.canonical_json
    assert run.requested_control_state is None
    assert run.broker_action_authorized is False


def test_primary_deadline_equality_is_missed_without_provider_call() -> None:
    incident = _incident()
    repository = MemoryCriticalAlertRepository(incident)
    port = StubDeliveryPort("primary-pager")
    deadline = incident.primary_deadline

    run = deliver_critical_alert(
        incident=incident,
        route=CriticalAlertRoute.PRIMARY,
        idempotency_key="delivery-0001",
        repository=repository,
        delivery_port=port,
        utc_clock=_sequence_utc((deadline, deadline)),
        monotonic_clock=_sequence_float((0.0, 0.0)),
    )

    assert run.result is not None
    assert run.result.outcome is CriticalAlertDeliveryOutcome.TIMEOUT
    assert run.result.failure_code == "delivery_deadline_missed"
    assert run.delivery_milestone_met is False
    assert run.provider_called is False
    assert port.calls == []


def test_failed_primary_allows_early_escalation_and_escalation_can_confirm() -> None:
    incident = _incident()
    repository = MemoryCriticalAlertRepository(incident)
    primary = StubDeliveryPort("primary-pager", behavior="error")
    fallback = StubDeliveryPort("fallback-pager")
    primary_run = _run(
        incident=incident,
        repository=repository,
        port=primary,
        requested_at=BASE + timedelta(seconds=1),
        completed_at=BASE + timedelta(seconds=2),
    )
    assert primary_run.delivery_milestone_met is False

    escalation = _run(
        incident=incident,
        repository=repository,
        port=fallback,
        route=CriticalAlertRoute.ESCALATION,
        key="delivery-0002",
        requested_at=BASE + timedelta(seconds=3),
        completed_at=BASE + timedelta(seconds=4),
    )
    assert escalation.result is not None
    assert escalation.result.outcome is CriticalAlertDeliveryOutcome.CONFIRMED
    assert escalation.delivery_milestone_met is True
    assert len(fallback.calls) == 1


def test_escalation_before_primary_failure_or_deadline_is_rejected() -> None:
    incident = _incident()
    repository = MemoryCriticalAlertRepository(incident)
    fallback = StubDeliveryPort("fallback-pager")

    with pytest.raises(CriticalAlertConflict, match="not yet eligible"):
        _run(
            incident=incident,
            repository=repository,
            port=fallback,
            route=CriticalAlertRoute.ESCALATION,
            key="delivery-0002",
            requested_at=BASE + timedelta(seconds=1),
        )

    assert repository.attempts == []
    assert fallback.calls == []


def test_escalation_deadline_equality_is_missed_without_provider_call() -> None:
    incident = _incident()
    repository = MemoryCriticalAlertRepository(incident)
    fallback = StubDeliveryPort("fallback-pager")
    deadline = incident.escalation_deadline

    run = deliver_critical_alert(
        incident=incident,
        route=CriticalAlertRoute.ESCALATION,
        idempotency_key="delivery-0002",
        repository=repository,
        delivery_port=fallback,
        utc_clock=_sequence_utc((deadline, deadline)),
        monotonic_clock=_sequence_float((0.0, 0.0)),
    )

    assert run.result is not None
    assert run.result.outcome is CriticalAlertDeliveryOutcome.TIMEOUT
    assert run.delivery_milestone_met is False
    assert run.provider_called is False
    assert fallback.calls == []


def test_restart_with_claim_but_no_result_never_resends_same_attempt() -> None:
    incident = _incident()
    repository = MemoryCriticalAlertRepository(incident)
    port = StubDeliveryPort("primary-pager")
    provider_request = CriticalAlertProviderRequest.bind(
        incident=incident,
        route=CriticalAlertRoute.PRIMARY,
        provider_id=port.provider_id,
        idempotency_key="delivery-0001",
    )
    command = CriticalAlertDeliveryCommand(
        incident_id=incident.incident_id,
        incident_sha256=incident.semantic_sha256,
        route=CriticalAlertRoute.PRIMARY,
        provider_id=port.provider_id,
        idempotency_key="delivery-0001",
        request_sha256=provider_request.semantic_sha256,
        requested_at=BASE + timedelta(seconds=1),
    )
    attempt, created = repository.claim_delivery_attempt(command)
    assert created is True

    run = _run(
        incident=incident,
        repository=repository,
        port=port,
        requested_at=BASE + timedelta(seconds=2),
    )

    assert run.attempt == attempt
    assert run.unresolved is True
    assert run.delivery_state is CriticalAlertDeliveryState.UNKNOWN
    assert run.provider_called is False
    assert run.exact_retry is True
    assert port.calls == []


def test_reusing_provider_key_for_another_route_is_a_conflict() -> None:
    incident = _incident()
    repository = MemoryCriticalAlertRepository(incident)
    port = StubDeliveryPort("shared-pager", behavior="error")
    _run(
        incident=incident,
        repository=repository,
        port=port,
        requested_at=BASE + timedelta(seconds=1),
        completed_at=BASE + timedelta(seconds=2),
    )

    with pytest.raises(CriticalAlertConflict, match="idempotency key conflicts"):
        _run(
            incident=incident,
            repository=repository,
            port=port,
            route=CriticalAlertRoute.ESCALATION,
            requested_at=BASE + timedelta(seconds=3),
        )

    assert len(port.calls) == 1
