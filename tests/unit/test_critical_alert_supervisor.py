from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from packages.application.critical_alert_delivery import (
    CriticalAlertDeliveryPort,
    CriticalAlertProviderReceipt,
    CriticalAlertProviderRequest,
)
from packages.application.critical_alert_supervisor import (
    CriticalAlertDeliverySupervisor,
    CriticalAlertRouteBinding,
    CriticalAlertRoutePlan,
    CriticalAlertSupervisorDisposition,
    CriticalAlertSupervisorError,
    CriticalAlertSupervisorReason,
    critical_alert_route_idempotency_key,
)
from packages.domain.critical_alert import (
    CriticalAlertConflict,
    CriticalAlertDeliveryAttempt,
    CriticalAlertDeliveryCommand,
    CriticalAlertDeliveryOutcome,
    CriticalAlertDeliveryResult,
    CriticalAlertIncident,
    CriticalAlertRoute,
    append_critical_alert_delivery_attempt,
    record_critical_alert_delivery_result,
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


def _route_plan(
    *,
    primary_provider: str = "primary-pager",
    escalation_provider: str = "fallback-sms",
    primary_destination_sha256: str = "c" * 64,
) -> CriticalAlertRoutePlan:
    return CriticalAlertRoutePlan(
        plan_id="paper-critical-alerts",
        plan_version="2026-07-28.1",
        primary=CriticalAlertRouteBinding(
            route=CriticalAlertRoute.PRIMARY,
            provider_id=primary_provider,
            destination_sha256=primary_destination_sha256,
            recipient_set_sha256="d" * 64,
        ),
        escalation=CriticalAlertRouteBinding(
            route=CriticalAlertRoute.ESCALATION,
            provider_id=escalation_provider,
            destination_sha256="e" * 64,
            recipient_set_sha256="f" * 64,
        ),
    )


def _sequence(values: tuple[datetime, ...]) -> Callable[[], datetime]:
    remaining = iter(values)

    def read() -> datetime:
        return next(remaining)

    return read


def _sequence_float(values: tuple[float, ...]) -> Callable[[], float]:
    remaining = iter(values)

    def read() -> float:
        return next(remaining)

    return read


@dataclass(slots=True)
class MemoryCriticalAlertRepository:
    incident: CriticalAlertIncident
    attempts: list[CriticalAlertDeliveryAttempt] = field(default_factory=list)
    results: dict[str, CriticalAlertDeliveryResult] = field(default_factory=dict)
    operations: list[str] = field(default_factory=list)

    def load_incident(self, incident_id: str) -> CriticalAlertIncident:
        self.operations.append("load_incident")
        if incident_id != self.incident.incident_id:
            raise ValueError("unknown incident")
        return self.incident

    def find_delivery_attempt(
        self,
        *,
        incident_id: str,
        provider_id: str,
        idempotency_key: str,
    ) -> CriticalAlertDeliveryAttempt | None:
        self.operations.append("find_attempt")
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
        self.operations.append("claim_attempt")
        existing = next(
            (
                attempt
                for attempt in self.attempts
                if attempt.provider_id == command.provider_id
                and attempt.idempotency_key == command.idempotency_key
            ),
            None,
        )
        if existing is not None:
            if (
                existing.route is not command.route
                or existing.request_sha256 != command.request_sha256
            ):
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
        self.operations.append("load_result")
        return self.results.get(attempt_id)

    def load_delivery_history(
        self,
        incident_id: str,
    ) -> tuple[
        tuple[CriticalAlertDeliveryAttempt, ...],
        tuple[CriticalAlertDeliveryResult, ...],
    ]:
        self.operations.append("load_history")
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
        self.operations.append("record_result")
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
    raw_error: str = "raw provider secret token for alice@example.test"
    calls: list[tuple[CriticalAlertProviderRequest, float]] = field(default_factory=list)

    def deliver(
        self,
        request: CriticalAlertProviderRequest,
        *,
        timeout_seconds: float,
    ) -> CriticalAlertProviderReceipt:
        self.calls.append((request, timeout_seconds))
        if self.behavior == "timeout":
            raise TimeoutError(self.raw_error)
        if self.behavior == "error":
            raise RuntimeError(self.raw_error)
        return CriticalAlertProviderReceipt(provider_receipt_sha256="9" * 64)


def _supervisor(
    *,
    repository: MemoryCriticalAlertRepository,
    route_plan: CriticalAlertRoutePlan,
    primary: CriticalAlertDeliveryPort,
    escalation: CriticalAlertDeliveryPort,
    utc_values: tuple[datetime, ...],
    monotonic_values: tuple[float, ...] = (0.0, 0.01, 0.1),
) -> CriticalAlertDeliverySupervisor:
    return CriticalAlertDeliverySupervisor(
        repository=repository,
        route_plan=route_plan,
        primary_port=primary,
        escalation_port=escalation,
        utc_clock=_sequence(utc_values),
        monotonic_clock=_sequence_float(monotonic_values),
    )


def _claim(
    *,
    repository: MemoryCriticalAlertRepository,
    route_plan: CriticalAlertRoutePlan,
    route: CriticalAlertRoute,
    requested_at: datetime,
) -> CriticalAlertDeliveryAttempt:
    request = CriticalAlertProviderRequest.bind(
        incident=repository.incident,
        route=route,
        provider_id=route_plan.binding_for(route).provider_id,
        idempotency_key=critical_alert_route_idempotency_key(
            incident=repository.incident,
            route_plan=route_plan,
            route=route,
        ),
    )
    command = CriticalAlertDeliveryCommand(
        incident_id=repository.incident.incident_id,
        incident_sha256=repository.incident.semantic_sha256,
        route=route,
        provider_id=request.provider_id,
        idempotency_key=request.idempotency_key,
        request_sha256=request.semantic_sha256,
        requested_at=requested_at,
    )
    return repository.claim_delivery_attempt(command)[0]


def test_primary_confirmation_reloads_history_first_and_restart_does_not_resend() -> None:
    incident = _incident()
    repository = MemoryCriticalAlertRepository(incident)
    plan = _route_plan()
    primary = StubDeliveryPort(plan.primary.provider_id)
    escalation = StubDeliveryPort(plan.escalation.provider_id)

    first = _supervisor(
        repository=repository,
        route_plan=plan,
        primary=primary,
        escalation=escalation,
        utc_values=(BASE + timedelta(seconds=1), BASE + timedelta(seconds=2)),
    ).run_once(incident.incident_id)

    assert first.disposition is CriticalAlertSupervisorDisposition.CONFIRMED
    assert first.reason is CriticalAlertSupervisorReason.PRIMARY_CONFIRMED
    assert first.provider_called is True
    assert first.requested_control_state is None
    assert first.broker_action_authorized is False
    assert first.automatic_rearm_authorized is False
    assert first.operational_independence_verified is False
    assert repository.operations[:2] == ["load_incident", "load_history"]
    assert len(primary.calls) == 1
    assert primary.calls[0][0].idempotency_key == critical_alert_route_idempotency_key(
        incident=incident,
        route_plan=plan,
        route=CriticalAlertRoute.PRIMARY,
    )

    restarted = _supervisor(
        repository=repository,
        route_plan=plan,
        primary=primary,
        escalation=escalation,
        utc_values=(BASE + timedelta(seconds=3),),
        monotonic_values=(0.0,),
    ).run_once(incident.incident_id)

    assert restarted.disposition is CriticalAlertSupervisorDisposition.CONFIRMED
    assert restarted.provider_called is False
    assert restarted.result_sha256 == first.result_sha256
    assert len(primary.calls) == 1
    assert escalation.calls == []


def test_primary_failure_waits_without_io_then_selects_escalation_at_equality() -> None:
    incident = _incident()
    repository = MemoryCriticalAlertRepository(incident)
    plan = _route_plan()
    primary = StubDeliveryPort(plan.primary.provider_id, behavior="error")
    escalation = StubDeliveryPort(plan.escalation.provider_id)

    failed = _supervisor(
        repository=repository,
        route_plan=plan,
        primary=primary,
        escalation=escalation,
        utc_values=(BASE + timedelta(seconds=1), BASE + timedelta(seconds=2)),
    ).run_once(incident.incident_id)
    assert failed.disposition is CriticalAlertSupervisorDisposition.PRIMARY_FAILED
    assert failed.reason is CriticalAlertSupervisorReason.PRIMARY_ATTEMPT_FAILED

    waiting = _supervisor(
        repository=repository,
        route_plan=plan,
        primary=primary,
        escalation=escalation,
        utc_values=(BASE + timedelta(seconds=14, milliseconds=999),),
        monotonic_values=(0.0,),
    ).run_once(incident.incident_id)
    assert waiting.disposition is CriticalAlertSupervisorDisposition.WAIT
    assert waiting.wait_until == incident.primary_deadline
    assert len(primary.calls) == 1
    assert escalation.calls == []

    confirmed = _supervisor(
        repository=repository,
        route_plan=plan,
        primary=primary,
        escalation=escalation,
        utc_values=(incident.primary_deadline, BASE + timedelta(seconds=16)),
    ).run_once(incident.incident_id)
    assert confirmed.disposition is CriticalAlertSupervisorDisposition.CONFIRMED
    assert confirmed.selected_route is CriticalAlertRoute.ESCALATION
    assert len(primary.calls) == 1
    assert len(escalation.calls) == 1


def test_unresolved_primary_claim_is_not_resent_and_escalates_at_primary_deadline() -> None:
    incident = _incident()
    repository = MemoryCriticalAlertRepository(incident)
    plan = _route_plan()
    primary = StubDeliveryPort(plan.primary.provider_id)
    escalation = StubDeliveryPort(plan.escalation.provider_id)
    primary_attempt = _claim(
        repository=repository,
        route_plan=plan,
        route=CriticalAlertRoute.PRIMARY,
        requested_at=BASE + timedelta(seconds=1),
    )

    waiting = _supervisor(
        repository=repository,
        route_plan=plan,
        primary=primary,
        escalation=escalation,
        utc_values=(BASE + timedelta(seconds=10),),
        monotonic_values=(0.0,),
    ).run_once(incident.incident_id)
    assert waiting.disposition is CriticalAlertSupervisorDisposition.WAIT
    assert waiting.reason is CriticalAlertSupervisorReason.PRIMARY_CLAIM_UNRESOLVED
    assert waiting.attempt_id == primary_attempt.attempt_id
    assert waiting.unresolved_claim is True
    assert primary.calls == []
    assert escalation.calls == []

    escalated = _supervisor(
        repository=repository,
        route_plan=plan,
        primary=primary,
        escalation=escalation,
        utc_values=(incident.primary_deadline, BASE + timedelta(seconds=16)),
    ).run_once(incident.incident_id)
    assert escalated.disposition is CriticalAlertSupervisorDisposition.CONFIRMED
    assert primary.calls == []
    assert len(escalation.calls) == 1


def test_unresolved_escalation_waits_then_becomes_total_failure_at_equality() -> None:
    incident = _incident()
    repository = MemoryCriticalAlertRepository(incident)
    plan = _route_plan()
    primary = StubDeliveryPort(plan.primary.provider_id)
    escalation = StubDeliveryPort(plan.escalation.provider_id)
    escalation_attempt = _claim(
        repository=repository,
        route_plan=plan,
        route=CriticalAlertRoute.ESCALATION,
        requested_at=incident.primary_deadline,
    )

    waiting = _supervisor(
        repository=repository,
        route_plan=plan,
        primary=primary,
        escalation=escalation,
        utc_values=(incident.escalation_deadline - timedelta(microseconds=1),),
        monotonic_values=(0.0,),
    ).run_once(incident.incident_id)
    assert waiting.disposition is CriticalAlertSupervisorDisposition.WAIT
    assert waiting.reason is CriticalAlertSupervisorReason.ESCALATION_CLAIM_UNRESOLVED
    assert waiting.unresolved_claim is True
    assert waiting.wait_until == incident.escalation_deadline

    total = _supervisor(
        repository=repository,
        route_plan=plan,
        primary=primary,
        escalation=escalation,
        utc_values=(incident.escalation_deadline,),
        monotonic_values=(0.0,),
    ).run_once(incident.incident_id)
    assert total.disposition is CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE
    assert total.reason is CriticalAlertSupervisorReason.ESCALATION_DEADLINE_UNRESOLVED
    assert total.attempt_id == escalation_attempt.attempt_id
    assert total.unresolved_claim is True
    assert total.requested_control_state is None
    assert total.broker_action_authorized is False
    assert primary.calls == []
    assert escalation.calls == []


@pytest.mark.parametrize(
    ("behavior", "failure_code"),
    (("error", "provider_error"), ("timeout", "provider_timeout")),
)
def test_terminal_escalation_failure_is_total_and_provider_errors_are_sanitized(
    behavior: str,
    failure_code: str,
) -> None:
    incident = _incident()
    repository = MemoryCriticalAlertRepository(incident)
    plan = _route_plan()
    primary = StubDeliveryPort(plan.primary.provider_id)
    escalation = StubDeliveryPort(plan.escalation.provider_id, behavior=behavior)

    total = _supervisor(
        repository=repository,
        route_plan=plan,
        primary=primary,
        escalation=escalation,
        utc_values=(incident.primary_deadline, BASE + timedelta(seconds=16)),
    ).run_once(incident.incident_id)

    assert total.disposition is CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE
    assert total.reason is CriticalAlertSupervisorReason.ESCALATION_ATTEMPT_FAILED
    assert total.provider_called is True
    result = next(iter(repository.results.values()))
    assert result.failure_code == failure_code
    assert escalation.raw_error not in result.canonical_json
    assert escalation.raw_error not in total.canonical_json
    assert "alice@example.test" not in total.canonical_json
    assert len(escalation.calls) == 1

    restarted = _supervisor(
        repository=repository,
        route_plan=plan,
        primary=primary,
        escalation=escalation,
        utc_values=(BASE + timedelta(seconds=17),),
        monotonic_values=(0.0,),
    ).run_once(incident.incident_id)
    assert restarted.disposition is CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE
    assert restarted.provider_called is False
    assert len(escalation.calls) == 1


def test_escalation_deadline_equality_claims_timeout_without_provider_io() -> None:
    incident = _incident()
    repository = MemoryCriticalAlertRepository(incident)
    plan = _route_plan()
    primary = StubDeliveryPort(plan.primary.provider_id)
    escalation = StubDeliveryPort(plan.escalation.provider_id)

    total = _supervisor(
        repository=repository,
        route_plan=plan,
        primary=primary,
        escalation=escalation,
        utc_values=(incident.escalation_deadline, incident.escalation_deadline),
        monotonic_values=(0.0, 0.0),
    ).run_once(incident.incident_id)

    assert total.disposition is CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE
    assert total.provider_called is False
    assert escalation.calls == []
    result = next(iter(repository.results.values()))
    assert result.outcome is CriticalAlertDeliveryOutcome.TIMEOUT
    assert result.failure_code == "delivery_deadline_missed"


def test_provider_collision_and_changed_port_identity_fail_closed() -> None:
    with pytest.raises(CriticalAlertSupervisorError, match="must be distinct"):
        _route_plan(
            primary_provider="same-provider",
            escalation_provider="same-provider",
        )

    incident = _incident()
    repository = MemoryCriticalAlertRepository(incident)
    plan = _route_plan()
    primary = StubDeliveryPort(plan.primary.provider_id)
    escalation = StubDeliveryPort(plan.escalation.provider_id)
    supervisor = _supervisor(
        repository=repository,
        route_plan=plan,
        primary=primary,
        escalation=escalation,
        utc_values=(BASE + timedelta(seconds=1),),
        monotonic_values=(0.0,),
    )
    primary.provider_id = "changed-provider"

    with pytest.raises(CriticalAlertSupervisorError, match="changed provider"):
        supervisor.run_once(incident.incident_id)
    assert repository.operations[:2] == ["load_incident", "load_history"]
    assert primary.calls == []
    assert escalation.calls == []


def test_foreign_route_plan_history_and_corrupt_result_prefix_fail_before_io() -> None:
    incident = _incident()
    plan = _route_plan()
    foreign_plan = _route_plan(primary_destination_sha256="0" * 64)
    repository = MemoryCriticalAlertRepository(incident)
    _claim(
        repository=repository,
        route_plan=foreign_plan,
        route=CriticalAlertRoute.PRIMARY,
        requested_at=BASE + timedelta(seconds=1),
    )
    primary = StubDeliveryPort(plan.primary.provider_id)
    escalation = StubDeliveryPort(plan.escalation.provider_id)

    with pytest.raises(CriticalAlertConflict, match="route plan"):
        _supervisor(
            repository=repository,
            route_plan=plan,
            primary=primary,
            escalation=escalation,
            utc_values=(BASE + timedelta(seconds=2),),
            monotonic_values=(0.0,),
        ).run_once(incident.incident_id)
    assert primary.calls == []
    assert escalation.calls == []

    valid_repository = MemoryCriticalAlertRepository(incident)
    attempt = _claim(
        repository=valid_repository,
        route_plan=plan,
        route=CriticalAlertRoute.PRIMARY,
        requested_at=BASE + timedelta(seconds=1),
    )
    result = record_critical_alert_delivery_result(
        incident=incident,
        attempt=attempt,
        outcome=CriticalAlertDeliveryOutcome.ERROR,
        completed_at=BASE + timedelta(seconds=2),
        elapsed_microseconds=1_000_000,
        failure_code="provider_error",
    )

    class CorruptHistoryRepository(MemoryCriticalAlertRepository):
        def load_delivery_history(
            self,
            incident_id: str,
        ) -> tuple[
            tuple[CriticalAlertDeliveryAttempt, ...],
            tuple[CriticalAlertDeliveryResult, ...],
        ]:
            self.operations.append("load_history")
            return (), (result,)

    corrupt_repository = CorruptHistoryRepository(incident)
    with pytest.raises(CriticalAlertConflict, match="has no attempt"):
        _supervisor(
            repository=corrupt_repository,
            route_plan=plan,
            primary=primary,
            escalation=escalation,
            utc_values=(BASE + timedelta(seconds=3),),
            monotonic_values=(0.0,),
        ).run_once(incident.incident_id)
    assert corrupt_repository.operations == ["load_incident", "load_history"]
    assert primary.calls == []
    assert escalation.calls == []
