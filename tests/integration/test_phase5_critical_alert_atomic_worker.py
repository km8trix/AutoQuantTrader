from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine

from packages.application.critical_alert_atomic_worker import (
    CriticalAlertAtomicWorkerConflict,
    CriticalAlertAtomicWorkerIncidentState,
    run_critical_alert_atomic_worker_once,
)
from packages.application.critical_alert_delivery import CriticalAlertProviderRequest
from packages.application.critical_alert_supervisor import (
    CriticalAlertRouteBinding,
    CriticalAlertRoutePlan,
    critical_alert_route_idempotency_key,
)
from packages.application.critical_alert_supervisor_failure_control import (
    CRITICAL_ALERT_FAILURE_CONTROL_POLICY_SHA256,
    CriticalAlertFailureControlReceipt,
)
from packages.domain.critical_alert import (
    CriticalAlertDeliveryAttempt,
    CriticalAlertDeliveryCommand,
    CriticalAlertDeliveryOutcome,
    CriticalAlertIncident,
    CriticalAlertRoute,
    record_critical_alert_delivery_result,
)
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlState,
)
from packages.persistence.critical_alert import SqlCriticalAlertRepository
from packages.persistence.critical_alert_failure_control import (
    SqlCriticalAlertFailureControlRepository,
    verify_critical_alert_failure_control_integrity,
)
from packages.persistence.database import create_database_engine
from packages.persistence.operational_control import SqlOperationalControlRepository
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase5_critical_alert_failure_control_receipts,
    phase5_operational_control_transitions,
)

ACCOUNT_ID = "phase5-atomic-worker-account"
BASE = datetime(2026, 7, 28, 14, 0, tzinfo=UTC)


@dataclass(slots=True)
class MutableClock:
    instant: datetime

    def now(self) -> datetime:
        return self.instant


@dataclass(slots=True)
class SpyUtcClock:
    instant: datetime
    calls: int = 0

    def __call__(self) -> datetime:
        self.calls += 1
        return self.instant


@dataclass(slots=True)
class NoResolutionExpected:
    calls: list[CriticalAlertRoute] = field(default_factory=list)

    def resolve(
        self,
        _incident: CriticalAlertIncident,
        binding: CriticalAlertRouteBinding,
    ) -> None:
        self.calls.append(binding.route)
        raise AssertionError("replay-derived terminal history must not resolve an adapter")


def _engine(path: Path) -> Engine:
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    metadata.create_all(engine)
    return engine


def _plan() -> CriticalAlertRoutePlan:
    return CriticalAlertRoutePlan(
        plan_id="paper-critical-alerts",
        plan_version="1",
        primary=CriticalAlertRouteBinding(
            route=CriticalAlertRoute.PRIMARY,
            provider_id="primary-pager",
            destination_sha256="1" * 64,
            recipient_set_sha256="2" * 64,
        ),
        escalation=CriticalAlertRouteBinding(
            route=CriticalAlertRoute.ESCALATION,
            provider_id="fallback-sms",
            destination_sha256="3" * 64,
            recipient_set_sha256="4" * 64,
        ),
    )


def _incident() -> CriticalAlertIncident:
    return CriticalAlertIncident(
        scope_id=ACCOUNT_ID,
        source_id="strategy-supervisor",
        idempotency_key="atomic-worker-incident-0001",
        alert_code="strategy_deadline_exceeded",
        evidence_sha256="a" * 64,
        detected_at=BASE - timedelta(milliseconds=100),
        recorded_at=BASE,
        correlation_sha256="b" * 64,
    )


def _account_and_control(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_account_lease_heads).values(
                account_id=ACCOUNT_ID,
                last_fencing_generation=0,
                current_fencing_generation=None,
                current_lease_sha256=None,
                updated_at=BASE - timedelta(minutes=2),
            )
        )
    initial_at = BASE - timedelta(minutes=1)
    SqlOperationalControlRepository(
        engine=engine,
        clock=MutableClock(initial_at),
    ).apply(
        OperationalControlCommand(
            scope_id=ACCOUNT_ID,
            idempotency_key="initialize-halted",
            kind=OperationalControlCommandKind.INITIALIZE_HALTED,
            target_state=OperationalControlState.HALTED,
            actor=OperationalControlActor(
                actor_id="bootstrap",
                kind=OperationalControlActorKind.SYSTEM,
                authority_sha256="5" * 64,
                authenticated_at=None,
            ),
            reason_code="bootstrap",
            reason_evidence_sha256="6" * 64,
            requested_at=initial_at,
        )
    )


def _claim(
    repository: SqlCriticalAlertRepository,
    clock: MutableClock,
    incident: CriticalAlertIncident,
    plan: CriticalAlertRoutePlan,
    route: CriticalAlertRoute,
    requested_at: datetime,
) -> CriticalAlertDeliveryAttempt:
    clock.instant = requested_at
    request = CriticalAlertProviderRequest.bind(
        incident=incident,
        route=route,
        provider_id=plan.binding_for(route).provider_id,
        idempotency_key=critical_alert_route_idempotency_key(
            incident=incident,
            route_plan=plan,
            route=route,
        ),
    )
    attempt, created = repository.claim_delivery_attempt(
        CriticalAlertDeliveryCommand(
            incident_id=incident.incident_id,
            incident_sha256=incident.semantic_sha256,
            route=route,
            provider_id=request.provider_id,
            idempotency_key=request.idempotency_key,
            request_sha256=request.semantic_sha256,
            requested_at=requested_at,
        )
    )
    assert created is True
    return attempt


def _seed_terminal_equality(
    engine: Engine,
) -> tuple[
    SqlCriticalAlertRepository,
    SqlCriticalAlertFailureControlRepository,
    CriticalAlertIncident,
    CriticalAlertRoutePlan,
]:
    _account_and_control(engine)
    clock = MutableClock(BASE)
    repository = SqlCriticalAlertRepository(engine=engine, clock=clock)
    incident = _incident()
    plan = _plan()
    repository.record_incident(incident)
    primary = _claim(
        repository,
        clock,
        incident,
        plan,
        CriticalAlertRoute.PRIMARY,
        BASE + timedelta(seconds=1),
    )
    clock.instant = BASE + timedelta(seconds=2)
    repository.record_delivery_result(
        record_critical_alert_delivery_result(
            incident=incident,
            attempt=primary,
            outcome=CriticalAlertDeliveryOutcome.ERROR,
            completed_at=clock.instant,
            elapsed_microseconds=1_000_000,
            failure_code="provider_error",
        )
    )
    escalation = _claim(
        repository,
        clock,
        incident,
        plan,
        CriticalAlertRoute.ESCALATION,
        incident.primary_deadline,
    )
    clock.instant = incident.escalation_deadline
    repository.record_delivery_result(
        record_critical_alert_delivery_result(
            incident=incident,
            attempt=escalation,
            outcome=CriticalAlertDeliveryOutcome.CONFIRMED,
            completed_at=clock.instant,
            elapsed_microseconds=1_000_000,
            provider_receipt_sha256="7" * 64,
        )
    )
    control_clock = MutableClock(incident.escalation_deadline + timedelta(seconds=1))
    failure_control = SqlCriticalAlertFailureControlRepository(
        engine=engine,
        clock=control_clock,
        route_plan=plan,
        actor_authority_sha256="8" * 64,
    )
    return repository, failure_control, incident, plan


def _counts(engine: Engine) -> tuple[int, int]:
    with engine.connect() as connection:
        return (
            int(
                connection.scalar(
                    sa.select(sa.func.count()).select_from(phase5_operational_control_transitions)
                )
                or 0
            ),
            int(
                connection.scalar(
                    sa.select(sa.func.count()).select_from(
                        phase5_critical_alert_failure_control_receipts
                    )
                )
                or 0
            ),
        )


def test_sql_atomic_worker_concurrent_and_restart_retries_converge(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "atomic-worker.sqlite")
    repository, failure_control, incident, plan = _seed_terminal_equality(engine)
    assert repository.runtime_store_identity == failure_control.runtime_store_identity
    assert failure_control.route_plan_sha256 == plan.semantic_sha256
    assert (
        failure_control.failure_control_policy_sha256
        == CRITICAL_ALERT_FAILURE_CONTROL_POLICY_SHA256
    )
    resolver = NoResolutionExpected()
    barrier = Barrier(2)

    def run(_: int) -> CriticalAlertFailureControlReceipt:
        barrier.wait(timeout=10)
        result = run_critical_alert_atomic_worker_once(
            repository=repository,
            route_plan=plan,
            route_resolver=resolver,
            failure_control=failure_control,
            utc_clock=SpyUtcClock(incident.escalation_deadline + timedelta(seconds=10)),
        )
        incident_run = result.incident_runs[0]
        assert incident_run.state is CriticalAlertAtomicWorkerIncidentState.CONTROL_BOUND
        assert incident_run.supervision.observed_at == incident.escalation_deadline
        assert incident_run.failure_control_receipt is not None
        return incident_run.failure_control_receipt

    with ThreadPoolExecutor(max_workers=2) as executor:
        receipts = tuple(executor.map(run, range(2)))

    assert receipts[0] == receipts[1]
    assert resolver.calls == []
    assert _counts(engine) == (2, 1)

    restarted = run_critical_alert_atomic_worker_once(
        repository=repository,
        route_plan=plan,
        route_resolver=resolver,
        failure_control=failure_control,
        utc_clock=SpyUtcClock(incident.escalation_deadline + timedelta(days=1)),
    )
    assert restarted.incident_runs[0].failure_control_receipt == receipts[0]
    assert _counts(engine) == (2, 1)
    verify_critical_alert_failure_control_integrity(engine)


def test_sql_split_store_rejects_before_clock_or_scan(tmp_path: Path) -> None:
    alert_engine = _engine(tmp_path / "alerts.sqlite")
    control_engine = _engine(tmp_path / "control.sqlite")
    plan = _plan()
    repository = SqlCriticalAlertRepository(
        engine=alert_engine,
        clock=MutableClock(BASE),
    )
    failure_control = SqlCriticalAlertFailureControlRepository(
        engine=control_engine,
        clock=MutableClock(BASE),
        route_plan=plan,
        actor_authority_sha256="8" * 64,
    )
    clock = SpyUtcClock(BASE)
    with pytest.raises(CriticalAlertAtomicWorkerConflict, match="one process-local store"):
        run_critical_alert_atomic_worker_once(
            repository=repository,
            route_plan=plan,
            route_resolver=NoResolutionExpected(),
            failure_control=failure_control,
            utc_clock=clock,
        )
    assert clock.calls == 0
