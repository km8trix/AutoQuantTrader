from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import Engine

from packages.application.critical_alert_delivery import (
    CriticalAlertProviderReceipt,
    CriticalAlertProviderRequest,
)
from packages.application.critical_alert_supervisor import (
    CriticalAlertDeliverySupervisor,
    CriticalAlertRouteBinding,
    CriticalAlertRoutePlan,
    CriticalAlertSupervisorDisposition,
    CriticalAlertSupervisorReason,
    critical_alert_route_idempotency_key,
)
from packages.domain.critical_alert import (
    CriticalAlertDeliveryCommand,
    CriticalAlertIncident,
    CriticalAlertRoute,
)
from packages.persistence.critical_alert import SqlCriticalAlertRepository
from packages.persistence.database import create_database_engine
from packages.persistence.schema import metadata

BASE = datetime(2026, 7, 28, 18, 0, tzinfo=UTC)


@dataclass(slots=True)
class MutableClock:
    instant: datetime

    def now(self) -> datetime:
        return self.instant


@dataclass(slots=True)
class StubDeliveryPort:
    provider_id: str
    calls: list[CriticalAlertProviderRequest] = field(default_factory=list)

    def deliver(
        self,
        request: CriticalAlertProviderRequest,
        *,
        timeout_seconds: float,
    ) -> CriticalAlertProviderReceipt:
        assert timeout_seconds > 0
        self.calls.append(request)
        return CriticalAlertProviderReceipt(provider_receipt_sha256="9" * 64)


def _engine(path: Path) -> Engine:
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    metadata.create_all(engine)
    return engine


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


def _plan() -> CriticalAlertRoutePlan:
    return CriticalAlertRoutePlan(
        plan_id="paper-critical-alerts",
        plan_version="2026-07-28.1",
        primary=CriticalAlertRouteBinding(
            route=CriticalAlertRoute.PRIMARY,
            provider_id="primary-pager",
            destination_sha256="c" * 64,
            recipient_set_sha256="d" * 64,
        ),
        escalation=CriticalAlertRouteBinding(
            route=CriticalAlertRoute.ESCALATION,
            provider_id="fallback-sms",
            destination_sha256="e" * 64,
            recipient_set_sha256="f" * 64,
        ),
    )


def _sequence_utc(values: tuple[datetime, ...]) -> Callable[[], datetime]:
    remaining = iter(values)

    def read() -> datetime:
        return next(remaining)

    return read


def _sequence_float(values: tuple[float, ...]) -> Callable[[], float]:
    remaining = iter(values)

    def read() -> float:
        return next(remaining)

    return read


def test_sql_supervisor_restarts_from_confirmed_primary_without_resending(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "supervisor-restart.sqlite")
    clock = MutableClock(BASE)
    repository = SqlCriticalAlertRepository(engine=engine, clock=clock)
    incident = _incident()
    repository.record_incident(incident)
    plan = _plan()
    primary = StubDeliveryPort(plan.primary.provider_id)
    escalation = StubDeliveryPort(plan.escalation.provider_id)
    clock.instant = BASE + timedelta(seconds=2)

    first = CriticalAlertDeliverySupervisor(
        repository=repository,
        route_plan=plan,
        primary_port=primary,
        escalation_port=escalation,
        utc_clock=_sequence_utc((BASE + timedelta(seconds=1), BASE + timedelta(seconds=2))),
        monotonic_clock=_sequence_float((0.0, 0.01, 0.1)),
    ).run_once(incident.incident_id)
    assert first.disposition is CriticalAlertSupervisorDisposition.CONFIRMED
    assert len(primary.calls) == 1

    restarted = CriticalAlertDeliverySupervisor(
        repository=repository,
        route_plan=plan,
        primary_port=primary,
        escalation_port=escalation,
        utc_clock=_sequence_utc((BASE + timedelta(seconds=3),)),
        monotonic_clock=_sequence_float((0.0,)),
    ).run_once(incident.incident_id)
    assert restarted.disposition is CriticalAlertSupervisorDisposition.CONFIRMED
    assert restarted.provider_called is False
    assert restarted.result_sha256 == first.result_sha256
    assert len(primary.calls) == 1
    assert escalation.calls == []


def test_sql_unresolved_escalation_becomes_total_failure_at_deadline_without_io(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "supervisor-unresolved.sqlite")
    clock = MutableClock(BASE)
    repository = SqlCriticalAlertRepository(engine=engine, clock=clock)
    incident = _incident()
    repository.record_incident(incident)
    plan = _plan()
    request = CriticalAlertProviderRequest.bind(
        incident=incident,
        route=CriticalAlertRoute.ESCALATION,
        provider_id=plan.escalation.provider_id,
        idempotency_key=critical_alert_route_idempotency_key(
            incident=incident,
            route_plan=plan,
            route=CriticalAlertRoute.ESCALATION,
        ),
    )
    clock.instant = incident.primary_deadline
    attempt, created = repository.claim_delivery_attempt(
        CriticalAlertDeliveryCommand(
            incident_id=incident.incident_id,
            incident_sha256=incident.semantic_sha256,
            route=CriticalAlertRoute.ESCALATION,
            provider_id=request.provider_id,
            idempotency_key=request.idempotency_key,
            request_sha256=request.semantic_sha256,
            requested_at=incident.primary_deadline,
        )
    )
    assert created is True
    primary = StubDeliveryPort(plan.primary.provider_id)
    escalation = StubDeliveryPort(plan.escalation.provider_id)

    evidence = CriticalAlertDeliverySupervisor(
        repository=repository,
        route_plan=plan,
        primary_port=primary,
        escalation_port=escalation,
        utc_clock=_sequence_utc((incident.escalation_deadline,)),
        monotonic_clock=_sequence_float((0.0,)),
    ).run_once(incident.incident_id)

    assert evidence.disposition is CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE
    assert evidence.reason is CriticalAlertSupervisorReason.ESCALATION_DEADLINE_UNRESOLVED
    assert evidence.attempt_id == attempt.attempt_id
    assert evidence.unresolved_claim is True
    assert evidence.provider_called is False
    assert evidence.requested_control_state is None
    assert evidence.broker_action_authorized is False
    assert primary.calls == []
    assert escalation.calls == []
