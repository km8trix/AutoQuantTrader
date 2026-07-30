from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from typing import Any, cast

import pytest
import sqlalchemy as sa
from alembic import command as alembic_command
from alembic.config import Config
from sqlalchemy import Engine, event

from packages.application.critical_alert_delivery import CriticalAlertProviderRequest
from packages.application.critical_alert_supervisor import (
    CriticalAlertRouteBinding,
    CriticalAlertRoutePlan,
    CriticalAlertSupervisorDisposition,
    CriticalAlertSupervisorEvidence,
    CriticalAlertSupervisorReason,
    critical_alert_route_idempotency_key,
)
from packages.application.critical_alert_supervisor_failure_control import (
    CRITICAL_ALERT_FAILURE_CONTROL_POLICY_SHA256,
    CRITICAL_ALERT_FAILURE_CONTROL_REASON_CODE,
    CRITICAL_ALERT_FAILURE_CONTROL_RULE_ID,
    CRITICAL_ALERT_FAILURE_CONTROL_SYSTEM_ACTOR_ID,
    CriticalAlertFailureControlReceipt,
    bind_critical_alert_failure_control_receipt,
)
from packages.domain.account_coordinator import AccountLeasePolicy
from packages.domain.clock import Clock
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
    OperationalControlConflict,
    OperationalControlIncidentDisposition,
    OperationalControlState,
    OperationalControlTransition,
    _operational_control_rearm_evidence,
)
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.critical_alert import SqlCriticalAlertRepository
from packages.persistence.critical_alert_failure_control import (
    CriticalAlertFailureControlPersistenceConflict,
    CriticalAlertFailureControlPersistenceError,
    SqlCriticalAlertFailureControlRepository,
    verify_critical_alert_failure_control_integrity,
)
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.operational_control import (
    SqlOperationalControlRepository,
    _critical_alert_failure_control_append_authority,
    apply_authenticated_operational_control_rearm_in_transaction,
    apply_operational_control_command_in_transaction,
)
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase5_critical_alert_failure_control_receipts,
    phase5_operational_control_heads,
    phase5_operational_control_transitions,
)

ROOT = Path(__file__).resolve().parents[2]
ACCOUNT_ID = "phase5-paper-account"
BASE = datetime(2026, 7, 28, 14, 0, tzinfo=UTC)
AUTHORITY_SHA256 = "9" * 64


@dataclass(slots=True)
class MutableClock:
    instant: datetime

    def now(self) -> datetime:
        return self.instant


@dataclass(frozen=True, slots=True)
class Seed:
    repository: SqlCriticalAlertFailureControlRepository
    clock: MutableClock
    incident: CriticalAlertIncident
    plan: CriticalAlertRoutePlan
    evidence: CriticalAlertSupervisorEvidence
    pre_control: OperationalControlTransition


def _engine(path: Path) -> Engine:
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    metadata.create_all(engine)
    _account_head(engine)
    return engine


def _config(url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", url)
    return config


def _account_head(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_account_lease_heads).values(
                account_id=ACCOUNT_ID,
                last_fencing_generation=0,
                current_fencing_generation=None,
                current_lease_sha256=None,
                updated_at=BASE - timedelta(minutes=3),
            )
        )


def _account_lease(engine: Engine) -> None:
    clock = MutableClock(BASE - timedelta(minutes=3))
    coordinator = SqlAccountCoordinator(
        account_id=ACCOUNT_ID,
        authority=SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=AccountLeasePolicy(
                policy_id="failure-control-tests",
                policy_version="1",
                lease_ttl=timedelta(minutes=10),
                maximum_in_flight_duration=timedelta(seconds=5),
                takeover_safety_interval=timedelta(seconds=10),
            ),
            clock=clock,
        ),
    )
    coordinator.acquire("failure-control-worker")


def _actor(
    actor_id: str,
    kind: OperationalControlActorKind,
    authority: str,
    authenticated_at: datetime | None = None,
) -> OperationalControlActor:
    return OperationalControlActor(
        actor_id=actor_id,
        kind=kind,
        authority_sha256=authority,
        authenticated_at=authenticated_at,
    )


def _seed_control(engine: Engine, *, running: bool) -> OperationalControlTransition:
    initial_at = BASE - timedelta(minutes=2)
    clock = MutableClock(initial_at)
    repository = SqlOperationalControlRepository(engine=engine, clock=clock)
    initial = repository.apply(
        OperationalControlCommand(
            scope_id=ACCOUNT_ID,
            idempotency_key="initialize-halted",
            kind=OperationalControlCommandKind.INITIALIZE_HALTED,
            target_state=OperationalControlState.HALTED,
            actor=_actor(
                "bootstrap",
                OperationalControlActorKind.SYSTEM,
                "1" * 64,
            ),
            reason_code="bootstrap",
            reason_evidence_sha256="2" * 64,
            requested_at=initial_at,
        )
    )
    if not running:
        return initial
    checked_at = BASE - timedelta(minutes=1)
    human = _actor(
        "operator",
        OperationalControlActorKind.HUMAN,
        "3" * 64,
        checked_at,
    )
    dispositions = tuple(
        sorted(
            (
                OperationalControlIncidentDisposition(
                    event_id=item.event_id,
                    event_sha256=item.semantic_sha256,
                    resolution_code="reviewed",
                    resolution_evidence_sha256="4" * 64,
                    resolved_at=checked_at,
                )
                for item in initial.blocking_events
            ),
            key=lambda value: value.event_id,
        )
    )
    rearm_evidence = _operational_control_rearm_evidence(
        scope_id=ACCOUNT_ID,
        current_transition_id=initial.transition_id,
        current_transition_sha256=initial.semantic_sha256,
        current_state=initial.effective_state,
        current_state_epoch_id=initial.state_epoch_id,
        actor=human,
        checked_at=checked_at,
        expires_at=checked_at + timedelta(seconds=30),
        readiness_sha256="5" * 64,
        reconciliation_sha256="6" * 64,
        incident_register_sha256="7" * 64,
        reconciliation_clean=True,
        data_healthy=True,
        clock_healthy=True,
        working_order_ids=(),
        unknown_order_ids=(),
        pending_cancel_order_ids=(),
        incident_dispositions=dispositions,
    )
    command = OperationalControlCommand(
        scope_id=ACCOUNT_ID,
        idempotency_key="authenticated-rearm",
        kind=OperationalControlCommandKind.REARM,
        target_state=OperationalControlState.RUNNING,
        actor=human,
        reason_code="operator-rearm",
        reason_evidence_sha256="8" * 64,
        requested_at=checked_at,
        rearm_evidence_sha256=rearm_evidence.semantic_sha256,
    )
    with engine.begin() as connection:
        return apply_authenticated_operational_control_rearm_in_transaction(
            connection,
            command,
            rearm_evidence,
            decided_at=checked_at,
        )


def _incident() -> CriticalAlertIncident:
    return CriticalAlertIncident(
        scope_id=ACCOUNT_ID,
        source_id="strategy-supervisor",
        idempotency_key="critical-incident-0001",
        alert_code="strategy_deadline_exceeded",
        evidence_sha256="a" * 64,
        detected_at=BASE - timedelta(milliseconds=100),
        recorded_at=BASE,
        correlation_sha256="b" * 64,
    )


def _plan(version: str = "1") -> CriticalAlertRoutePlan:
    return CriticalAlertRoutePlan(
        plan_id="paper-critical-alerts",
        plan_version=version,
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


def _result(
    repository: SqlCriticalAlertRepository,
    clock: MutableClock,
    incident: CriticalAlertIncident,
    attempt: CriticalAlertDeliveryAttempt,
    outcome: CriticalAlertDeliveryOutcome,
    completed_at: datetime,
) -> None:
    clock.instant = completed_at
    repository.record_delivery_result(
        record_critical_alert_delivery_result(
            incident=incident,
            attempt=attempt,
            outcome=outcome,
            completed_at=completed_at,
            elapsed_microseconds=1_000_000,
            provider_receipt_sha256=(
                "0" * 64 if outcome is CriticalAlertDeliveryOutcome.CONFIRMED else None
            ),
            failure_code=(
                None if outcome is CriticalAlertDeliveryOutcome.CONFIRMED else "provider_failure"
            ),
        )
    )


def _seed_alert(
    engine: Engine,
    terminal: CriticalAlertDeliveryOutcome | None,
    *,
    observed_at: datetime | None = None,
    terminal_at: datetime | None = None,
) -> tuple[
    MutableClock,
    CriticalAlertIncident,
    CriticalAlertRoutePlan,
    CriticalAlertSupervisorEvidence,
]:
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
    _result(
        repository,
        clock,
        incident,
        primary,
        CriticalAlertDeliveryOutcome.ERROR,
        BASE + timedelta(seconds=2),
    )
    escalation = _claim(
        repository,
        clock,
        incident,
        plan,
        CriticalAlertRoute.ESCALATION,
        incident.primary_deadline,
    )
    terminal_result = None
    if terminal is not None:
        completion = terminal_at or (
            incident.escalation_deadline
            if terminal is CriticalAlertDeliveryOutcome.CONFIRMED
            else incident.primary_deadline + timedelta(seconds=1)
        )
        _result(repository, clock, incident, escalation, terminal, completion)
        terminal_result = repository.load_delivery_result(escalation.attempt_id)
        assert terminal_result is not None
    evidence = CriticalAlertSupervisorEvidence(
        incident_id=incident.incident_id,
        incident_sha256=incident.semantic_sha256,
        route_plan_sha256=plan.semantic_sha256,
        disposition=CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE,
        reason=(
            CriticalAlertSupervisorReason.ESCALATION_DEADLINE_UNRESOLVED
            if terminal_result is None
            else CriticalAlertSupervisorReason.ESCALATION_ATTEMPT_FAILED
        ),
        observed_at=observed_at or incident.escalation_deadline,
        selected_route=CriticalAlertRoute.ESCALATION,
        attempt_id=escalation.attempt_id,
        attempt_sha256=escalation.semantic_sha256,
        result_id=None if terminal_result is None else terminal_result.result_id,
        result_sha256=(None if terminal_result is None else terminal_result.semantic_sha256),
        wait_until=None,
        provider_called=False,
        unresolved_claim=terminal_result is None,
    )
    clock.instant = incident.escalation_deadline + timedelta(seconds=1)
    return clock, incident, plan, evidence


def _seed(
    engine: Engine,
    terminal: CriticalAlertDeliveryOutcome | None = None,
    *,
    running: bool = True,
) -> Seed:
    pre_control = _seed_control(engine, running=running)
    clock, incident, plan, evidence = _seed_alert(engine, terminal)
    return Seed(
        repository=SqlCriticalAlertFailureControlRepository(
            engine=engine,
            clock=clock,
            route_plan=plan,
            actor_authority_sha256=AUTHORITY_SHA256,
        ),
        clock=clock,
        incident=incident,
        plan=plan,
        evidence=evidence,
        pre_control=pre_control,
    )


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


def _uncommitted_receipt(
    engine: Engine,
    seed: Seed,
) -> CriticalAlertFailureControlReceipt:
    attempts, results = SqlCriticalAlertRepository(
        engine=engine,
        clock=seed.clock,
    ).load_delivery_history(seed.incident.incident_id)
    return bind_critical_alert_failure_control_receipt(
        incident=seed.incident,
        route_plan=seed.plan,
        attempts=attempts,
        results=results,
        evidence=seed.evidence,
        pre_control=seed.pre_control,
        actor_authority_sha256=AUTHORITY_SHA256,
        bound_at=seed.clock.instant,
    )


@pytest.mark.parametrize(
    "terminal",
    [
        None,
        CriticalAlertDeliveryOutcome.ERROR,
        CriticalAlertDeliveryOutcome.TIMEOUT,
        CriticalAlertDeliveryOutcome.CONFIRMED,
    ],
)
def test_failure_binds_paused_and_exact_history(
    tmp_path: Path,
    terminal: CriticalAlertDeliveryOutcome | None,
) -> None:
    engine = _engine(tmp_path / f"bind-{terminal}.sqlite")
    seed = _seed(engine, terminal)
    receipt = seed.repository.bind(
        account_id=ACCOUNT_ID,
        evidence=seed.evidence,
    )
    assert receipt.pre_control == seed.pre_control
    assert receipt.final_control.effective_state is OperationalControlState.PAUSED
    assert receipt.command.kind is OperationalControlCommandKind.TRIP
    assert receipt.broker_action_authorized is False
    assert receipt.fence_authority_granted is False
    if terminal is None:
        seed.clock.instant += timedelta(hours=1)
        assert (
            seed.repository.bind(
                account_id=ACCOUNT_ID,
                evidence=seed.evidence,
            )
            == receipt
        )
        assert seed.repository.load(seed.incident.incident_id) == receipt
        assert seed.repository.history(ACCOUNT_ID) == (receipt,)
    assert _counts(engine) == (seed.pre_control.sequence_number + 1, 1)
    verify_critical_alert_failure_control_integrity(engine)


def test_terminal_failure_binds_on_first_replay_before_deadline(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "terminal-first-replay.sqlite")
    pre_control = _seed_control(engine, running=True)
    completed_at = BASE + timedelta(seconds=16)
    clock, _, plan, evidence = _seed_alert(
        engine,
        CriticalAlertDeliveryOutcome.ERROR,
        observed_at=completed_at,
        terminal_at=completed_at,
    )
    clock.instant = completed_at
    repository = SqlCriticalAlertFailureControlRepository(
        engine=engine,
        clock=clock,
        route_plan=plan,
        actor_authority_sha256=AUTHORITY_SHA256,
    )
    receipt = repository.bind(account_id=ACCOUNT_ID, evidence=evidence)
    assert receipt.pre_control == pre_control
    assert receipt.evidence.observed_at == completed_at
    assert receipt.command.requested_at == completed_at
    assert receipt.final_control.effective_state is OperationalControlState.PAUSED
    assert _counts(engine) == (pre_control.sequence_number + 1, 1)


def test_predeadline_and_in_budget_confirmation_roll_back(
    tmp_path: Path,
) -> None:
    early_engine = _engine(tmp_path / "early.sqlite")
    _seed_control(early_engine, running=True)
    clock, _, plan, evidence = _seed_alert(
        early_engine,
        None,
        observed_at=BASE + timedelta(seconds=29, microseconds=999_999),
    )
    repository = SqlCriticalAlertFailureControlRepository(
        engine=early_engine,
        clock=clock,
        route_plan=plan,
        actor_authority_sha256=AUTHORITY_SHA256,
    )
    before = _counts(early_engine)
    with pytest.raises(
        CriticalAlertFailureControlPersistenceError,
        match="predates",
    ):
        repository.bind(account_id=ACCOUNT_ID, evidence=evidence)
    assert _counts(early_engine) == before

    confirmed_engine = _engine(tmp_path / "confirmed.sqlite")
    _seed_control(confirmed_engine, running=True)
    clock, incident, plan, evidence = _seed_alert(
        confirmed_engine,
        CriticalAlertDeliveryOutcome.CONFIRMED,
        terminal_at=BASE + timedelta(seconds=29, microseconds=999_999),
    )
    repository = SqlCriticalAlertFailureControlRepository(
        engine=confirmed_engine,
        clock=clock,
        route_plan=plan,
        actor_authority_sha256=AUTHORITY_SHA256,
    )
    assert evidence.observed_at == incident.escalation_deadline
    before = _counts(confirmed_engine)
    with pytest.raises(
        CriticalAlertFailureControlPersistenceError,
        match="confirmed",
    ):
        repository.bind(account_id=ACCOUNT_ID, evidence=evidence)
    assert _counts(confirmed_engine) == before


def test_stronger_halted_state_is_preserved(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "halted.sqlite")
    seed = _seed(engine, running=False)
    receipt = seed.repository.bind(
        account_id=ACCOUNT_ID,
        evidence=seed.evidence,
    )
    assert receipt.pre_control.effective_state is OperationalControlState.HALTED
    assert receipt.final_control.effective_state is OperationalControlState.HALTED
    assert receipt.final_control.state_changed is False


def test_concurrent_retry_converges_on_one_receipt(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "concurrent.sqlite")
    seed = _seed(engine)
    barrier = Barrier(2)

    def bind(_: int) -> CriticalAlertFailureControlReceipt:
        barrier.wait(timeout=10)
        return seed.repository.bind(
            account_id=ACCOUNT_ID,
            evidence=seed.evidence,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        receipts = tuple(executor.map(bind, range(2)))
    assert receipts[0] == receipts[1]
    assert _counts(engine) == (seed.pre_control.sequence_number + 1, 1)


@pytest.mark.parametrize(
    "table_name",
    [
        "phase5_operational_control_transitions",
        "phase5_critical_alert_failure_control_receipts",
    ],
)
def test_insert_fault_rolls_back_transition_and_receipt(
    tmp_path: Path,
    table_name: str,
) -> None:
    engine = _engine(tmp_path / f"fault-{table_name}.sqlite")
    seed = _seed(engine)
    before = _counts(engine)

    def fail(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        if statement.lstrip().upper().startswith("INSERT") and table_name in statement:
            raise RuntimeError("injected failure-control fault")

    event.listen(engine, "before_cursor_execute", fail)
    try:
        with pytest.raises(RuntimeError, match="injected"):
            seed.repository.bind(account_id=ACCOUNT_ID, evidence=seed.evidence)
    finally:
        event.remove(engine, "before_cursor_execute", fail)
    assert _counts(engine) == before
    with engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(phase5_operational_control_heads.c.sequence_number).where(
                    phase5_operational_control_heads.c.account_id == ACCOUNT_ID
                )
            )
            == seed.pre_control.sequence_number
        )


def test_conflicting_source_and_missing_injected_configuration_reject(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "conflict.sqlite")
    seed = _seed(engine)
    receipt = seed.repository.bind(account_id=ACCOUNT_ID, evidence=seed.evidence)
    variants = (
        SqlCriticalAlertFailureControlRepository(
            engine=engine,
            clock=seed.clock,
            route_plan=_plan("2"),
            actor_authority_sha256=AUTHORITY_SHA256,
        ),
        SqlCriticalAlertFailureControlRepository(
            engine=engine,
            clock=seed.clock,
            route_plan=seed.plan,
            actor_authority_sha256="8" * 64,
        ),
    )
    for repository in variants:
        with pytest.raises(
            CriticalAlertFailureControlPersistenceConflict,
            match="source identity",
        ):
            repository.bind(account_id=ACCOUNT_ID, evidence=seed.evidence)
    with pytest.raises(
        CriticalAlertFailureControlPersistenceConflict,
        match="source identity",
    ):
        seed.repository.bind(
            account_id=ACCOUNT_ID,
            evidence=replace(
                seed.evidence,
                observed_at=seed.evidence.observed_at + timedelta(seconds=1),
            ),
        )
    assert seed.repository.load(seed.incident.incident_id) == receipt
    with pytest.raises(
        CriticalAlertFailureControlPersistenceError,
        match="injected exact route plan",
    ):
        SqlCriticalAlertFailureControlRepository(
            engine=engine,
            clock=cast(Clock, seed.clock),
            route_plan=cast(CriticalAlertRoutePlan, None),
            actor_authority_sha256=AUTHORITY_SHA256,
        )


def test_public_operational_control_repository_rejects_reserved_namespace(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "reserved-public-namespace.sqlite")
    seed = _seed(engine)
    receipt = _uncommitted_receipt(engine, seed)
    neutral = replace(
        receipt.command,
        idempotency_key="alternate-trip",
        actor=replace(receipt.command.actor, actor_id="alternate-system"),
        reason_code="alternate-trip",
        trip_rule_id="alternate-trip-rule",
        trip_policy_sha256="0" * 64,
    )
    variants = (
        receipt.command,
        replace(neutral, actor=receipt.command.actor),
        replace(
            neutral,
            reason_code=CRITICAL_ALERT_FAILURE_CONTROL_REASON_CODE,
        ),
        replace(neutral, trip_rule_id=CRITICAL_ALERT_FAILURE_CONTROL_RULE_ID),
        replace(
            neutral,
            trip_policy_sha256=CRITICAL_ALERT_FAILURE_CONTROL_POLICY_SHA256,
        ),
        replace(
            neutral,
            idempotency_key="critical-alert-failure:alternate-incident",
        ),
    )
    assert receipt.command.actor.actor_id == CRITICAL_ALERT_FAILURE_CONTROL_SYSTEM_ACTOR_ID
    before = _counts(engine)
    repository = SqlOperationalControlRepository(engine=engine, clock=seed.clock)
    for command in variants:
        with pytest.raises(
            OperationalControlConflict,
            match="atomic receipt binder",
        ):
            repository.apply(command)
        assert _counts(engine) == before


def test_atomic_append_authority_rejects_missing_fake_stale_and_changed_use(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "reserved-append-authority.sqlite")
    seed = _seed(engine)
    receipt = _uncommitted_receipt(engine, seed)
    before = _counts(engine)

    with engine.begin() as connection:
        with pytest.raises(
            OperationalControlConflict,
            match="atomic receipt binder",
        ):
            apply_operational_control_command_in_transaction(
                connection,
                receipt.command,
                decided_at=receipt.bound_at,
            )
        with pytest.raises(
            OperationalControlConflict,
            match="atomic receipt binder",
        ):
            apply_operational_control_command_in_transaction(
                connection,
                receipt.command,
                decided_at=receipt.bound_at,
                _critical_alert_failure_control_authority=cast(Any, object()),
            )

    with engine.begin() as connection:
        stale_authority = _critical_alert_failure_control_append_authority(
            connection,
            receipt,
        )
    with (
        engine.begin() as connection,
        pytest.raises(
            OperationalControlConflict,
            match="atomic receipt binder",
        ),
    ):
        apply_operational_control_command_in_transaction(
            connection,
            receipt.command,
            decided_at=receipt.bound_at,
            _critical_alert_failure_control_authority=stale_authority,
        )

    changed_command = replace(
        receipt.command,
        reason_evidence_sha256="f" * 64,
        trip_observation_sha256="f" * 64,
    )
    with engine.begin() as connection:
        command_authority = _critical_alert_failure_control_append_authority(
            connection,
            receipt,
        )
        with pytest.raises(
            OperationalControlConflict,
            match="atomic receipt binder",
        ):
            apply_operational_control_command_in_transaction(
                connection,
                changed_command,
                decided_at=receipt.bound_at,
                _critical_alert_failure_control_authority=command_authority,
            )

    assert _counts(engine) == before
    persisted = seed.repository.bind(
        account_id=ACCOUNT_ID,
        evidence=seed.evidence,
    )
    assert persisted == receipt
    assert _counts(engine) == (seed.pre_control.sequence_number + 1, 1)


def test_authenticated_rearm_rejects_reserved_failure_control_collisions(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "reserved-rearm-namespace.sqlite")
    initial = _seed_control(engine, running=False)
    checked_at = BASE - timedelta(minutes=1)
    human = _actor(
        "namespace-test-operator",
        OperationalControlActorKind.HUMAN,
        "3" * 64,
        checked_at,
    )
    dispositions = tuple(
        sorted(
            (
                OperationalControlIncidentDisposition(
                    event_id=item.event_id,
                    event_sha256=item.semantic_sha256,
                    resolution_code="reviewed",
                    resolution_evidence_sha256="4" * 64,
                    resolved_at=checked_at,
                )
                for item in initial.blocking_events
            ),
            key=lambda value: value.event_id,
        )
    )
    evidence = _operational_control_rearm_evidence(
        scope_id=ACCOUNT_ID,
        current_transition_id=initial.transition_id,
        current_transition_sha256=initial.semantic_sha256,
        current_state=initial.effective_state,
        current_state_epoch_id=initial.state_epoch_id,
        actor=human,
        checked_at=checked_at,
        expires_at=checked_at + timedelta(seconds=30),
        readiness_sha256="5" * 64,
        reconciliation_sha256="6" * 64,
        incident_register_sha256="7" * 64,
        reconciliation_clean=True,
        data_healthy=True,
        clock_healthy=True,
        working_order_ids=(),
        unknown_order_ids=(),
        pending_cancel_order_ids=(),
        incident_dispositions=dispositions,
    )
    base_command = OperationalControlCommand(
        scope_id=ACCOUNT_ID,
        idempotency_key="namespace-test-rearm",
        kind=OperationalControlCommandKind.REARM,
        target_state=OperationalControlState.RUNNING,
        actor=human,
        reason_code="namespace-test-rearm",
        reason_evidence_sha256="8" * 64,
        requested_at=checked_at,
        rearm_evidence_sha256=evidence.semantic_sha256,
    )
    variants = (
        replace(
            base_command,
            reason_code=CRITICAL_ALERT_FAILURE_CONTROL_REASON_CODE,
        ),
        replace(
            base_command,
            idempotency_key="critical-alert-failure:rearm-collision",
        ),
    )
    before = _counts(engine)
    repository = SqlOperationalControlRepository(
        engine=engine,
        clock=MutableClock(checked_at),
    )
    for command in variants:
        with pytest.raises(
            OperationalControlConflict,
            match="atomic receipt binder",
        ):
            repository.apply_authenticated_rearm(command, evidence)
        assert _counts(engine) == before


def test_corruption_fails_load_integrity_and_startup(tmp_path: Path) -> None:
    database_path = tmp_path / "corruption.sqlite"
    url = f"sqlite+pysqlite:///{database_path}"
    alembic_command.upgrade(_config(url), "head")
    engine = create_database_engine(url)
    _account_lease(engine)
    seed = _seed(engine)
    receipt = seed.repository.bind(account_id=ACCOUNT_ID, evidence=seed.evidence)
    verify_operational_schema(engine, require_phase_zero_facts=False)
    with engine.begin() as connection:
        connection.execute(
            sa.update(phase5_critical_alert_failure_control_receipts)
            .where(
                phase5_critical_alert_failure_control_receipts.c.receipt_id == receipt.receipt_id
            )
            .values(canonical_payload="[]")
        )
    with pytest.raises(
        CriticalAlertFailureControlPersistenceConflict,
        match="receipt conflicts",
    ):
        seed.repository.load(seed.incident.incident_id)
    with pytest.raises(DatabaseSchemaNotReady, match="failure-control integrity"):
        verify_operational_schema(engine, require_phase_zero_facts=False)


def test_0032_downgrade_refuses_nonempty_history(tmp_path: Path) -> None:
    database_path = tmp_path / "downgrade.sqlite"
    url = f"sqlite+pysqlite:///{database_path}"
    config = _config(url)
    alembic_command.upgrade(config, "0032_phase5_alert_fail_control")
    engine = create_database_engine(url)
    _account_head(engine)
    seed = _seed(engine)
    seed.repository.bind(account_id=ACCOUNT_ID, evidence=seed.evidence)
    engine.dispose()
    with pytest.raises(RuntimeError, match="nonempty critical-alert"):
        alembic_command.downgrade(config, "0031_phase5_strategy_claims")
