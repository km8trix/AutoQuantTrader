from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine

from packages.domain.account_coordinator import AccountLeasePolicy
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlState,
)
from packages.domain.strategy_supervision import (
    STRATEGY_DECISION_DEADLINE_MICROSECONDS,
    STRATEGY_SUBPROCESS_PROTOCOL_VERSION,
    StrategyInvocation,
    StrategyProtocolResponse,
    StrategySupervisionOutcome,
    StrategySupervisionResult,
)
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.database import create_database_engine
from packages.persistence.operational_control import (
    SqlOperationalControlRepository,
)
from packages.persistence.schema import (
    metadata,
    phase5_critical_alert_incidents,
    phase5_strategy_invocation_claims,
    phase5_strategy_invocation_finalizations,
    phase5_strategy_supervision_results,
)
from packages.persistence.strategy_supervision import (
    SqlStrategySupervisionRepository,
    StrategySupervisionPersistenceConflict,
    verify_strategy_supervision_integrity,
)
from tests.unit.test_strategy_supervision import _invocation

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


@dataclass(slots=True)
class MutableClock:
    instant: datetime

    def now(self) -> datetime:
        return self.instant


@dataclass(frozen=True, slots=True)
class _System:
    engine: Engine
    clock: MutableClock
    coordinator: SqlAccountCoordinator
    repository: SqlStrategySupervisionRepository
    invocation: StrategyInvocation
    initial_control_id: str


def _system(
    path: Path,
    *,
    lifecycle_schema_active: bool = False,
) -> _System:
    _, invocation_object = _invocation()
    assert type(invocation_object) is StrategyInvocation
    invocation = invocation_object
    initial_at = invocation.market_batch_as_of - timedelta(seconds=1)
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    metadata.create_all(engine)
    if not lifecycle_schema_active:
        # These ADR 0077 compatibility tests exercise the repository contract
        # as it existed before migration 0031 activated the claim-owned write
        # path. Post-0031 rejection is covered explicitly below.
        phase5_strategy_invocation_finalizations.drop(engine)
        phase5_strategy_invocation_claims.drop(engine)
    clock = MutableClock(initial_at)
    coordinator = SqlAccountCoordinator(
        account_id=invocation.control_scope_id,
        authority=SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=AccountLeasePolicy(
                policy_id="phase5c-strategy-supervision-tests",
                policy_version="1",
                lease_ttl=timedelta(minutes=5),
                maximum_in_flight_duration=timedelta(seconds=5),
                takeover_safety_interval=timedelta(seconds=10),
            ),
            clock=clock,
        ),
    )
    coordinator.acquire("phase5c-worker")
    control = SqlOperationalControlRepository(engine=engine, clock=clock)
    initial = control.apply(
        OperationalControlCommand(
            scope_id=invocation.control_scope_id,
            idempotency_key="initialize-halted",
            kind=OperationalControlCommandKind.INITIALIZE_HALTED,
            target_state=OperationalControlState.HALTED,
            actor=OperationalControlActor(
                actor_id="startup",
                kind=OperationalControlActorKind.SYSTEM,
                authority_sha256="a" * 64,
                authenticated_at=None,
            ),
            reason_code="startup",
            reason_evidence_sha256="b" * 64,
            requested_at=initial_at,
        )
    )
    return _System(
        engine=engine,
        clock=clock,
        coordinator=coordinator,
        repository=SqlStrategySupervisionRepository(
            engine=engine,
            coordinator=coordinator,
            clock=clock,
        ),
        invocation=invocation,
        initial_control_id=initial.transition_id,
    )


def _success(invocation: StrategyInvocation) -> StrategySupervisionResult:
    result_json = '{"targets":["DIA","IWM","QQQ","SPY"]}'
    response = StrategyProtocolResponse(
        invocation_id=invocation.invocation_id,
        invocation_sha256=invocation.semantic_sha256,
        protocol_version=STRATEGY_SUBPROCESS_PROTOCOL_VERSION,
        result_json=result_json,
        result_sha256=hashlib.sha256(result_json.encode()).hexdigest(),
    )
    completed_at = invocation.requested_at + timedelta(milliseconds=10)
    return StrategySupervisionResult(
        invocation_id=invocation.invocation_id,
        invocation_sha256=invocation.semantic_sha256,
        outcome=StrategySupervisionOutcome.COMPLETED,
        started_at=invocation.requested_at,
        completed_at=completed_at,
        elapsed_microseconds=10_000,
        process_started=True,
        exit_code=0,
        stdout_bytes=len(result_json),
        stdout_sha256=hashlib.sha256(result_json.encode()).hexdigest(),
        stderr_bytes=0,
        stderr_sha256=EMPTY_SHA256,
        detail_code="completed",
        response=response,
    )


def _timeout(invocation: StrategyInvocation) -> StrategySupervisionResult:
    completed_at = invocation.requested_at + timedelta(
        microseconds=STRATEGY_DECISION_DEADLINE_MICROSECONDS
    )
    return StrategySupervisionResult(
        invocation_id=invocation.invocation_id,
        invocation_sha256=invocation.semantic_sha256,
        outcome=StrategySupervisionOutcome.TIMEOUT,
        started_at=invocation.requested_at,
        completed_at=completed_at,
        elapsed_microseconds=STRATEGY_DECISION_DEADLINE_MICROSECONDS,
        process_started=True,
        exit_code=None,
        stdout_bytes=0,
        stdout_sha256=EMPTY_SHA256,
        stderr_bytes=0,
        stderr_sha256=EMPTY_SHA256,
        detail_code="hard_deadline_exceeded",
    )


def test_completed_result_is_durable_idempotent_and_does_not_rearm(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "strategy-success.sqlite")
    result = _success(system.invocation)
    system.clock.instant = result.completed_at + timedelta(seconds=1)
    fence = system.coordinator.current()
    assert fence is not None

    first = system.repository.record(system.invocation, result, fence.fence)
    second = system.repository.record(system.invocation, result, fence.fence)

    assert first == second
    assert first.pre_control == first.final_control
    assert first.critical_alert_incident is None
    assert first.final_control.transition_id == system.initial_control_id
    assert first.final_control.effective_state is OperationalControlState.HALTED
    assert system.repository.load(system.invocation.invocation_id) == first
    assert system.repository.history(system.invocation.control_scope_id) == (first,)
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_strategy_supervision_results)
            )
            == 1
        )
    verify_strategy_supervision_integrity(system.engine)


def test_timeout_and_paused_trip_commit_atomically_and_survive_restart(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "strategy-timeout.sqlite")
    result = _timeout(system.invocation)
    system.clock.instant = result.completed_at + timedelta(seconds=1)
    lease = system.coordinator.current()
    assert lease is not None

    record = system.repository.record(system.invocation, result, lease.fence)

    assert record.pre_control.transition_id == system.initial_control_id
    assert record.final_control.sequence_number == record.pre_control.sequence_number + 1
    assert record.final_control.previous_transition_sha256 == record.pre_control.semantic_sha256
    assert record.final_control.effective_state is OperationalControlState.HALTED
    assert record.final_control.blocking_events[-1].command_id == record.final_control.command_id
    assert record.critical_alert_incident is not None
    assert record.critical_alert_incident.alert_code == "strategy_timeout"
    assert record.critical_alert_incident.local_durability_milestone_met is True

    restarted = SqlStrategySupervisionRepository(
        engine=system.engine,
        coordinator=system.coordinator,
        clock=system.clock,
    )
    assert restarted.load(system.invocation.invocation_id) == record
    assert (
        SqlOperationalControlRepository(
            engine=system.engine,
            clock=system.clock,
        ).load(system.invocation.control_scope_id)
        == record.final_control
    )


def test_same_invocation_with_different_result_is_rejected(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "strategy-conflict.sqlite")
    result = _success(system.invocation)
    system.clock.instant = result.completed_at + timedelta(seconds=1)
    lease = system.coordinator.current()
    assert lease is not None
    system.repository.record(system.invocation, result, lease.fence)

    with pytest.raises(
        StrategySupervisionPersistenceConflict,
        match="identity conflicts",
    ):
        system.repository.record(
            system.invocation,
            replace(result, detail_code="different_completed_detail"),
            lease.fence,
        )


def test_tampered_normalized_or_payload_fact_fails_closed(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "strategy-tamper.sqlite")
    result = _success(system.invocation)
    system.clock.instant = result.completed_at + timedelta(seconds=1)
    lease = system.coordinator.current()
    assert lease is not None
    system.repository.record(system.invocation, result, lease.fence)
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase5_strategy_supervision_results)
            .where(
                phase5_strategy_supervision_results.c.invocation_id
                == system.invocation.invocation_id
            )
            .values(detail_code="tampered")
        )

    with pytest.raises(
        StrategySupervisionPersistenceConflict,
        match="detail_code conflicts",
    ):
        system.repository.load(system.invocation.invocation_id)


def test_failed_insert_rolls_back_breaker_transition(tmp_path: Path) -> None:
    system = _system(tmp_path / "strategy-rollback.sqlite")
    result = _timeout(system.invocation)
    system.clock.instant = result.completed_at + timedelta(seconds=1)
    lease = system.coordinator.current()
    assert lease is not None
    before = SqlOperationalControlRepository(
        engine=system.engine,
        clock=system.clock,
    ).load(system.invocation.control_scope_id)
    assert before is not None
    with system.engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TRIGGER reject_strategy_supervision_insert "
            "BEFORE INSERT ON phase5_strategy_supervision_results "
            "BEGIN SELECT RAISE(ABORT, 'forced append failure'); END"
        )

    with pytest.raises(StrategySupervisionPersistenceConflict):
        system.repository.record(system.invocation, result, lease.fence)

    after = SqlOperationalControlRepository(
        engine=system.engine,
        clock=system.clock,
    ).load(system.invocation.control_scope_id)
    assert after == before
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_critical_alert_incidents)
            )
            == 0
        )


def test_public_repository_is_disabled_after_lifecycle_activation_without_side_effects(
    tmp_path: Path,
) -> None:
    system = _system(
        tmp_path / "strategy-post-lifecycle-direct-write.sqlite",
        lifecycle_schema_active=True,
    )
    result = _timeout(system.invocation)
    system.clock.instant = result.completed_at + timedelta(seconds=1)
    lease = system.coordinator.current()
    assert lease is not None
    before = SqlOperationalControlRepository(
        engine=system.engine,
        clock=system.clock,
    ).load(system.invocation.control_scope_id)
    assert before is not None

    with pytest.raises(
        StrategySupervisionPersistenceConflict,
        match="direct strategy-supervision writes are disabled",
    ):
        system.repository.record(system.invocation, result, lease.fence)

    after = SqlOperationalControlRepository(
        engine=system.engine,
        clock=system.clock,
    ).load(system.invocation.control_scope_id)
    assert after == before
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_strategy_supervision_results)
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_critical_alert_incidents)
            )
            == 0
        )
