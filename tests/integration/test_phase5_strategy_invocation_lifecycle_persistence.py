from __future__ import annotations

import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine

from packages.application.durable_supervised_strategy import (
    run_durable_supervised_strategy_once,
)
from packages.domain.account_coordinator import AccountFence, AccountLeasePolicy
from packages.domain.market_batch import MarketBatch
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlIncidentDisposition,
    OperationalControlState,
    _operational_control_rearm_evidence,
)
from packages.domain.strategy_invocation_lifecycle import (
    STRATEGY_INVOCATION_INTERRUPTED_DETAIL_CODE,
    STRATEGY_INVOCATION_RECOVERY_INTERVAL,
    StrategyInvocationClaim,
    StrategyInvocationDisposition,
    StrategyInvocationLifecycleConflict,
    StrategyInvocationLifecycleDecision,
    StrategyInvocationNewClaim,
    StrategyInvocationStartAuthorization,
    interrupted_strategy_supervision_result,
)
from packages.domain.strategy_supervision import (
    STRATEGY_SUBPROCESS_PROTOCOL_VERSION,
    StrategyInvocation,
    StrategyProtocolResponse,
    StrategySupervisionOutcome,
    StrategySupervisionResult,
)
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
    lock_account_capacity_serialization,
)
from packages.persistence.database import create_database_engine
from packages.persistence.operational_control import (
    SqlOperationalControlRepository,
)
from packages.persistence.schema import (
    metadata,
    phase5_critical_alert_incidents,
    phase5_operational_control_transitions,
    phase5_strategy_invocation_claims,
    phase5_strategy_invocation_finalizations,
    phase5_strategy_supervision_results,
)
from packages.persistence.strategy_invocation_lifecycle import (
    SqlStrategyInvocationLifecycleRepository,
    StrategyInvocationLifecyclePersistenceConflict,
    StrategyInvocationLifecyclePersistenceError,
    StrategyInvocationRecoveryCursor,
    verify_strategy_invocation_lifecycle_integrity,
)
from packages.persistence.strategy_supervision import (
    SqlStrategySupervisionRepository,
    StrategySupervisionPersistenceConflict,
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
    repository: SqlStrategyInvocationLifecycleRepository
    invocation: StrategyInvocation
    fence: AccountFence
    initial_control_id: str | None


def _system(
    path: Path,
    *,
    lease_ttl: timedelta = timedelta(minutes=5),
    initialize_control: bool = True,
    rearm_control: bool = True,
) -> _System:
    _, invocation_value = _invocation()
    assert type(invocation_value) is StrategyInvocation
    invocation = invocation_value
    claim_at = invocation.requested_at + timedelta(milliseconds=1)
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    metadata.create_all(engine)
    clock = MutableClock(claim_at)
    coordinator = SqlAccountCoordinator(
        account_id=invocation.control_scope_id,
        authority=SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=AccountLeasePolicy(
                policy_id="phase5c-invocation-lifecycle-tests",
                policy_version="1",
                lease_ttl=lease_ttl,
                maximum_in_flight_duration=timedelta(seconds=5),
                takeover_safety_interval=timedelta(seconds=10),
            ),
            clock=clock,
        ),
    )
    lease = coordinator.acquire("phase5c-lifecycle-worker")
    initial_control_id: str | None = None
    if initialize_control:
        control_repository = SqlOperationalControlRepository(engine=engine, clock=clock)
        initial = control_repository.apply(
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
                requested_at=invocation.market_batch_as_of - timedelta(seconds=1),
            )
        )
        initial_control_id = initial.transition_id
        if rearm_control:
            human = OperationalControlActor(
                actor_id="phase5c-rearm-operator",
                kind=OperationalControlActorKind.HUMAN,
                authority_sha256="c" * 64,
                authenticated_at=claim_at,
            )
            dispositions = tuple(
                OperationalControlIncidentDisposition(
                    event_id=event.event_id,
                    event_sha256=event.semantic_sha256,
                    resolution_code="startup_verified",
                    resolution_evidence_sha256="d" * 64,
                    resolved_at=claim_at,
                )
                for event in initial.blocking_events
            )
            evidence = _operational_control_rearm_evidence(
                scope_id=invocation.control_scope_id,
                current_transition_id=initial.transition_id,
                current_transition_sha256=initial.semantic_sha256,
                current_state=initial.effective_state,
                current_state_epoch_id=initial.state_epoch_id,
                actor=human,
                checked_at=claim_at,
                expires_at=claim_at + timedelta(seconds=30),
                readiness_sha256="e" * 64,
                reconciliation_sha256="f" * 64,
                incident_register_sha256="1" * 64,
                reconciliation_clean=True,
                data_healthy=True,
                clock_healthy=True,
                working_order_ids=(),
                unknown_order_ids=(),
                pending_cancel_order_ids=(),
                incident_dispositions=dispositions,
            )
            rearmed = control_repository.apply_authenticated_rearm(
                OperationalControlCommand(
                    scope_id=invocation.control_scope_id,
                    idempotency_key="verified-rearm-0001",
                    kind=OperationalControlCommandKind.REARM,
                    target_state=OperationalControlState.RUNNING,
                    actor=human,
                    reason_code="startup_verified",
                    reason_evidence_sha256="2" * 64,
                    requested_at=claim_at,
                    rearm_evidence_sha256=evidence.semantic_sha256,
                ),
                evidence,
            )
            initial_control_id = rearmed.transition_id
    return _System(
        engine=engine,
        clock=clock,
        coordinator=coordinator,
        repository=SqlStrategyInvocationLifecycleRepository(
            engine=engine,
            coordinator=coordinator,
            clock=clock,
        ),
        invocation=invocation,
        fence=lease.fence,
        initial_control_id=initial_control_id,
    )


def _apply_control(
    system: _System,
    kind: OperationalControlCommandKind,
) -> None:
    target = {
        OperationalControlCommandKind.PAUSE: OperationalControlState.PAUSED,
        OperationalControlCommandKind.HALT: OperationalControlState.HALTED,
    }[kind]
    SqlOperationalControlRepository(
        engine=system.engine,
        clock=system.clock,
    ).apply(
        OperationalControlCommand(
            scope_id=system.invocation.control_scope_id,
            idempotency_key=f"phase5c-{kind.value}-0001",
            kind=kind,
            target_state=target,
            actor=OperationalControlActor(
                actor_id="phase5c-operator",
                kind=OperationalControlActorKind.HUMAN,
                authority_sha256="3" * 64,
                authenticated_at=system.clock.instant,
            ),
            reason_code=f"phase5c_{kind.value}",
            reason_evidence_sha256="4" * 64,
            requested_at=system.clock.instant,
        )
    )


def _completed(
    invocation: StrategyInvocation,
    *,
    started_at: datetime,
) -> StrategySupervisionResult:
    result_json = '{"targets":["DIA","IWM","QQQ","SPY"]}'
    response = StrategyProtocolResponse(
        invocation_id=invocation.invocation_id,
        invocation_sha256=invocation.semantic_sha256,
        protocol_version=STRATEGY_SUBPROCESS_PROTOCOL_VERSION,
        result_json=result_json,
        result_sha256=hashlib.sha256(result_json.encode()).hexdigest(),
    )
    completed_at = started_at + timedelta(milliseconds=10)
    return StrategySupervisionResult(
        invocation_id=invocation.invocation_id,
        invocation_sha256=invocation.semantic_sha256,
        outcome=StrategySupervisionOutcome.COMPLETED,
        started_at=started_at,
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


def _failure(
    invocation: StrategyInvocation,
    *,
    started_at: datetime,
) -> StrategySupervisionResult:
    return StrategySupervisionResult(
        invocation_id=invocation.invocation_id,
        invocation_sha256=invocation.semantic_sha256,
        outcome=StrategySupervisionOutcome.RESOURCE_EXCEEDED,
        started_at=started_at,
        completed_at=started_at + timedelta(milliseconds=1),
        elapsed_microseconds=1_000,
        process_started=False,
        exit_code=None,
        stdout_bytes=0,
        stdout_sha256=EMPTY_SHA256,
        stderr_bytes=0,
        stderr_sha256=EMPTY_SHA256,
        detail_code="request_too_large",
    )


@dataclass(slots=True)
class InspectingRunner:
    repository: SqlStrategyInvocationLifecycleRepository
    clock: MutableClock
    calls: int = 0

    def run(
        self,
        *,
        invocation: StrategyInvocation,
        market_batch: MarketBatch,
        start_authorization: StrategyInvocationStartAuthorization,
    ) -> StrategySupervisionResult:
        del market_batch
        self.calls += 1
        state = self.repository.load(invocation.invocation_id)
        assert state is not None
        assert state.disposition is StrategyInvocationDisposition.PENDING
        assert start_authorization.claim == state.claim
        assert start_authorization.authorized_at == self.clock.instant
        result = _completed(
            invocation,
            started_at=start_authorization.authorized_at + timedelta(microseconds=1),
        )
        self.clock.instant = result.completed_at + timedelta(microseconds=1)
        return result


@dataclass(slots=True)
class NeverRunner:
    calls: int = 0

    def run(
        self,
        *,
        invocation: StrategyInvocation,
        market_batch: MarketBatch,
        start_authorization: StrategyInvocationStartAuthorization,
    ) -> StrategySupervisionResult:
        del invocation, market_batch, start_authorization
        self.calls += 1
        raise AssertionError("an existing claim must never rerun")


@dataclass(slots=True)
class TransitionBeforeStartRepository:
    system: _System
    kind: OperationalControlCommandKind
    transitioned: bool = False

    def claim(
        self,
        invocation: StrategyInvocation,
        fence: AccountFence,
    ) -> StrategyInvocationNewClaim | StrategyInvocationLifecycleDecision:
        return self.system.repository.claim(invocation, fence)

    def authorize_start(
        self,
        start_capability: object,
        fence: AccountFence,
    ) -> StrategyInvocationStartAuthorization | StrategyInvocationLifecycleDecision:
        if not self.transitioned:
            _apply_control(self.system, self.kind)
            self.transitioned = True
        return self.system.repository.authorize_start(start_capability, fence)

    def finalize(
        self,
        claim: StrategyInvocationClaim,
        result: StrategySupervisionResult,
        fence: AccountFence,
    ) -> StrategyInvocationLifecycleDecision:
        return self.system.repository.finalize(claim, result, fence)

    def recover(
        self,
        claim: StrategyInvocationClaim,
        fence: AccountFence,
    ) -> StrategyInvocationLifecycleDecision:
        return self.system.repository.recover(claim, fence)


def test_application_commits_claim_before_runner_and_exact_retry_is_retained(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "strategy-lifecycle-success.sqlite")
    batch, _ = _invocation()
    runner = InspectingRunner(system.repository, system.clock)

    first = run_durable_supervised_strategy_once(
        invocation=system.invocation,
        market_batch=batch,
        fence=system.fence,
        repository=system.repository,
        runner=runner,
    )
    _apply_control(system, OperationalControlCommandKind.PAUSE)
    second = run_durable_supervised_strategy_once(
        invocation=system.invocation,
        market_batch=batch,
        fence=system.fence,
        repository=system.repository,
        runner=runner,
    )

    assert first == second
    assert first.disposition is StrategyInvocationDisposition.FINAL
    assert first.result is not None
    assert first.result.outcome is StrategySupervisionOutcome.COMPLETED
    assert runner.calls == 1
    control = SqlOperationalControlRepository(
        engine=system.engine,
        clock=system.clock,
    ).load(system.invocation.control_scope_id)
    assert control is not None
    assert control.effective_state is OperationalControlState.PAUSED
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_strategy_invocation_claims)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_strategy_invocation_finalizations)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_strategy_supervision_results)
            )
            == 1
        )
    verify_strategy_invocation_lifecycle_integrity(system.engine)


def test_restart_never_reruns_orphan_and_equality_recovers_fail_closed(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "strategy-lifecycle-recovery.sqlite")
    batch, _ = _invocation()
    claimed = system.repository.claim(system.invocation, system.fence)
    assert claimed.disposition is StrategyInvocationDisposition.NEW
    _apply_control(system, OperationalControlCommandKind.HALT)
    restarted = SqlStrategyInvocationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
        clock=system.clock,
    )
    runner = NeverRunner()

    pending = run_durable_supervised_strategy_once(
        invocation=system.invocation,
        market_batch=batch,
        fence=system.fence,
        repository=restarted,
        runner=runner,
    )
    assert pending.disposition is StrategyInvocationDisposition.PENDING
    assert runner.calls == 0

    system.clock.instant = claimed.claim.recoverable_at
    recovered = run_durable_supervised_strategy_once(
        invocation=system.invocation,
        market_batch=batch,
        fence=system.fence,
        repository=restarted,
        runner=runner,
    )
    retry = run_durable_supervised_strategy_once(
        invocation=system.invocation,
        market_batch=batch,
        fence=system.fence,
        repository=restarted,
        runner=runner,
    )

    assert recovered == retry
    assert recovered.result is not None
    assert recovered.result.outcome is StrategySupervisionOutcome.CRASH
    assert recovered.result.detail_code == STRATEGY_INVOCATION_INTERRUPTED_DETAIL_CODE
    assert recovered.result.process_started is False
    assert runner.calls == 0
    control = SqlOperationalControlRepository(
        engine=system.engine,
        clock=system.clock,
    ).load(system.invocation.control_scope_id)
    assert control is not None
    assert control.effective_state is OperationalControlState.HALTED
    assert control.sequence_number == 4
    with system.engine.connect() as connection:
        incidents = connection.execute(sa.select(phase5_critical_alert_incidents)).mappings().all()
    assert len(incidents) == 1
    assert incidents[0]["source_id"] == "strategy-supervisor"
    assert incidents[0]["alert_code"] == "strategy_crash"
    verify_strategy_invocation_lifecycle_integrity(system.engine)


def test_claimed_timely_result_finalizes_after_control_becomes_paused(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "strategy-lifecycle-paused-finalization.sqlite")
    claimed = system.repository.claim(system.invocation, system.fence)
    assert claimed.disposition is StrategyInvocationDisposition.NEW
    _apply_control(system, OperationalControlCommandKind.PAUSE)
    result = _completed(
        system.invocation,
        started_at=claimed.claim.claimed_at + timedelta(microseconds=1),
    )
    system.clock.instant = result.completed_at + timedelta(microseconds=1)

    finalized = system.repository.finalize(
        claimed.claim,
        result,
        system.fence,
    )

    assert finalized.disposition is StrategyInvocationDisposition.FINAL
    assert finalized.result == result
    retained = system.repository.load(system.invocation.invocation_id)
    assert retained == finalized
    control = SqlOperationalControlRepository(
        engine=system.engine,
        clock=system.clock,
    ).load(system.invocation.control_scope_id)
    assert control is not None
    assert control.effective_state is OperationalControlState.PAUSED
    verify_strategy_invocation_lifecycle_integrity(system.engine)


def test_orphan_recovery_uses_the_new_current_fence_after_clean_handoff(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "strategy-lifecycle-current-fence-recovery.sqlite")
    batch, _ = _invocation()
    claimed = system.repository.claim(system.invocation, system.fence)
    assert claimed.disposition is StrategyInvocationDisposition.NEW

    system.clock.instant += timedelta(seconds=1)
    system.coordinator.release(system.fence)
    recovery_lease = system.coordinator.acquire("phase5c-recovery-worker")
    assert recovery_lease.fencing_generation == system.fence.fencing_generation + 1

    system.clock.instant = claimed.claim.recoverable_at
    restarted = SqlStrategyInvocationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
        clock=system.clock,
    )
    runner = NeverRunner()
    recovered = run_durable_supervised_strategy_once(
        invocation=system.invocation,
        market_batch=batch,
        fence=recovery_lease.fence,
        repository=restarted,
        runner=runner,
    )

    assert recovered.disposition is StrategyInvocationDisposition.FINAL
    assert recovered.result is not None
    assert recovered.result.outcome is StrategySupervisionOutcome.CRASH
    assert recovered.result.detail_code == STRATEGY_INVOCATION_INTERRUPTED_DETAIL_CODE
    assert recovered.result.process_started is False
    assert runner.calls == 0
    assert system.coordinator.revalidate(recovery_lease.fence).fence == recovery_lease.fence
    verify_strategy_invocation_lifecycle_integrity(system.engine)


def test_claim_readiness_requires_current_fence_and_full_execution_window(
    tmp_path: Path,
) -> None:
    short = _system(
        tmp_path / "strategy-lifecycle-short-lease.sqlite",
        lease_ttl=STRATEGY_INVOCATION_RECOVERY_INTERVAL,
    )
    with pytest.raises(
        StrategyInvocationLifecyclePersistenceError,
        match="full supervised execution window",
    ):
        short.repository.claim(short.invocation, short.fence)

    system = _system(tmp_path / "strategy-lifecycle-stale-fence.sqlite")
    stale = replace(
        system.fence,
        fencing_generation=system.fence.fencing_generation + 1,
    )
    with pytest.raises(
        StrategyInvocationLifecyclePersistenceError,
        match=r"no longer current|does not match",
    ):
        system.repository.claim(system.invocation, stale)

    unready = _system(
        tmp_path / "strategy-lifecycle-missing-control.sqlite",
        initialize_control=False,
    )
    with pytest.raises(
        StrategyInvocationLifecyclePersistenceError,
        match="operational-control readiness",
    ):
        unready.repository.claim(unready.invocation, unready.fence)


@pytest.mark.parametrize(
    "control_state",
    (
        OperationalControlState.PAUSED,
        OperationalControlState.HALTED,
    ),
)
def test_new_claim_requires_running_control_before_runner_effect(
    tmp_path: Path,
    control_state: OperationalControlState,
) -> None:
    system = _system(
        tmp_path / f"strategy-lifecycle-{control_state.value}-gate.sqlite",
        rearm_control=control_state is not OperationalControlState.HALTED,
    )
    if control_state is OperationalControlState.PAUSED:
        _apply_control(system, OperationalControlCommandKind.PAUSE)
    batch, _ = _invocation()
    runner = NeverRunner()

    with pytest.raises(
        StrategyInvocationLifecyclePersistenceError,
        match="requires RUNNING operational control",
    ):
        run_durable_supervised_strategy_once(
            invocation=system.invocation,
            market_batch=batch,
            fence=system.fence,
            repository=system.repository,
            runner=runner,
        )

    assert runner.calls == 0
    assert system.repository.load(system.invocation.invocation_id) is None
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_strategy_invocation_claims)
            )
            == 0
        )


@pytest.mark.parametrize(
    "kind",
    (
        OperationalControlCommandKind.PAUSE,
        OperationalControlCommandKind.HALT,
    ),
)
def test_nonrunning_transition_between_claim_and_start_blocks_runner_but_allows_recovery(
    tmp_path: Path,
    kind: OperationalControlCommandKind,
) -> None:
    system = _system(tmp_path / f"strategy-lifecycle-prestart-{kind.value}.sqlite")
    repository = TransitionBeforeStartRepository(system=system, kind=kind)
    batch, _ = _invocation()
    runner = NeverRunner()

    with pytest.raises(
        StrategyInvocationLifecyclePersistenceError,
        match="start authorization requires RUNNING operational control",
    ):
        run_durable_supervised_strategy_once(
            invocation=system.invocation,
            market_batch=batch,
            fence=system.fence,
            repository=repository,
            runner=runner,
        )

    pending = system.repository.load(system.invocation.invocation_id)
    assert pending is not None
    assert pending.disposition is StrategyInvocationDisposition.PENDING
    assert runner.calls == 0

    system.clock.instant = pending.claim.recoverable_at
    recovered = run_durable_supervised_strategy_once(
        invocation=system.invocation,
        market_batch=batch,
        fence=system.fence,
        repository=repository,
        runner=runner,
    )

    assert recovered.disposition is StrategyInvocationDisposition.FINAL
    assert recovered.result is not None
    assert recovered.result.outcome is StrategySupervisionOutcome.CRASH
    assert recovered.result.detail_code == STRATEGY_INVOCATION_INTERRUPTED_DETAIL_CODE
    assert runner.calls == 0


def test_tampered_claim_and_finalization_block_load_and_readiness(
    tmp_path: Path,
) -> None:
    claim_system = _system(tmp_path / "strategy-lifecycle-claim-tamper.sqlite")
    claim_system.repository.claim(claim_system.invocation, claim_system.fence)
    with claim_system.engine.begin() as connection:
        connection.execute(
            sa.update(phase5_strategy_invocation_claims)
            .where(
                phase5_strategy_invocation_claims.c.invocation_id
                == claim_system.invocation.invocation_id
            )
            .values(semantic_sha256="f" * 64)
        )
    with pytest.raises(
        StrategyInvocationLifecyclePersistenceConflict,
        match="semantic_sha256 conflicts",
    ):
        claim_system.repository.load(claim_system.invocation.invocation_id)

    final_system = _system(tmp_path / "strategy-lifecycle-finalization-tamper.sqlite")
    claimed = final_system.repository.claim(
        final_system.invocation,
        final_system.fence,
    )
    result = _completed(
        final_system.invocation,
        started_at=claimed.claim.claimed_at + timedelta(microseconds=1),
    )
    final_system.clock.instant = result.completed_at + timedelta(microseconds=1)
    final_system.repository.finalize(claimed.claim, result, final_system.fence)
    with final_system.engine.begin() as connection:
        connection.execute(
            sa.update(phase5_strategy_invocation_finalizations).values(semantic_sha256="e" * 64)
        )
    with pytest.raises(
        StrategyInvocationLifecyclePersistenceConflict,
        match="semantic_sha256 conflicts",
    ):
        verify_strategy_invocation_lifecycle_integrity(final_system.engine)


def test_finalization_insert_failure_rolls_back_result_control_and_incident(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "strategy-lifecycle-rollback.sqlite")
    claimed = system.repository.claim(system.invocation, system.fence)
    result = _failure(
        system.invocation,
        started_at=claimed.claim.claimed_at + timedelta(microseconds=1),
    )
    system.clock.instant = result.completed_at + timedelta(microseconds=1)
    before = SqlOperationalControlRepository(
        engine=system.engine,
        clock=system.clock,
    ).load(system.invocation.control_scope_id)
    assert before is not None
    with system.engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TRIGGER reject_strategy_lifecycle_finalization "
            "BEFORE INSERT ON phase5_strategy_invocation_finalizations "
            "BEGIN SELECT RAISE(ABORT, 'forced finalization failure'); END"
        )

    with pytest.raises(StrategyInvocationLifecyclePersistenceConflict):
        system.repository.finalize(claimed.claim, result, system.fence)

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
    verify_strategy_invocation_lifecycle_integrity(system.engine)


def test_claim_time_is_sampled_after_account_serialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    system = _system(tmp_path / "strategy-lifecycle-lock-time.sqlite")
    import packages.persistence.strategy_invocation_lifecycle as lifecycle_persistence

    original_lock = lock_account_capacity_serialization
    entered_at = system.clock.instant

    def delayed_lock(connection: sa.Connection, account_id: str) -> None:
        original_lock(connection, account_id)
        system.clock.instant += STRATEGY_INVOCATION_RECOVERY_INTERVAL

    monkeypatch.setattr(
        lifecycle_persistence,
        "lock_account_capacity_serialization",
        delayed_lock,
    )

    claimed = system.repository.claim(system.invocation, system.fence)

    assert claimed.disposition is StrategyInvocationDisposition.NEW
    assert claimed.claim.claimed_at == entered_at + STRATEGY_INVOCATION_RECOVERY_INTERVAL
    assert claimed.claim.recoverable_at == (
        entered_at + (2 * STRATEGY_INVOCATION_RECOVERY_INTERVAL)
    )


def test_new_start_permit_is_repository_bound_and_single_use(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "strategy-lifecycle-one-shot-start.sqlite")
    claimed = system.repository.claim(system.invocation, system.fence)
    assert type(claimed) is StrategyInvocationNewClaim
    competing_repository = SqlStrategyInvocationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
        clock=system.clock,
    )

    with pytest.raises(
        StrategyInvocationLifecyclePersistenceConflict,
        match="another repository process",
    ):
        competing_repository.authorize_start(
            claimed.start_capability,
            system.fence,
        )

    authorization = system.repository.authorize_start(
        claimed.start_capability,
        system.fence,
    )
    assert type(authorization) is StrategyInvocationStartAuthorization
    assert authorization.claim == claimed.claim
    with pytest.raises(
        StrategyInvocationLifecyclePersistenceConflict,
        match="already consumed",
    ):
        system.repository.authorize_start(
            claimed.start_capability,
            system.fence,
        )

    retained = system.repository.load(system.invocation.invocation_id)
    assert retained is not None
    assert retained.disposition is StrategyInvocationDisposition.PENDING
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_strategy_supervision_results)
            )
            == 0
        )


def test_retained_same_repository_claim_never_reissues_start_authority(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "strategy-lifecycle-same-repository-retry.sqlite")
    winner = system.repository.claim(system.invocation, system.fence)
    assert type(winner) is StrategyInvocationNewClaim

    retained = system.repository.claim(system.invocation, system.fence)
    assert type(retained) is StrategyInvocationLifecycleDecision
    assert retained.disposition is StrategyInvocationDisposition.PENDING
    assert retained.claim == winner.claim
    assert not hasattr(retained, "start_capability")
    with pytest.raises(
        StrategyInvocationLifecyclePersistenceError,
        match="winning NEW permit",
    ):
        system.repository.authorize_start(retained.claim, system.fence)

    authorization = system.repository.authorize_start(
        winner.start_capability,
        system.fence,
    )
    assert type(authorization) is StrategyInvocationStartAuthorization
    assert authorization.claim == winner.claim


def test_start_permit_is_pid_bound_without_consumption_on_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    system = _system(tmp_path / "strategy-lifecycle-pid-bound-start.sqlite")
    winner = system.repository.claim(system.invocation, system.fence)
    assert type(winner) is StrategyInvocationNewClaim
    import packages.persistence.strategy_invocation_lifecycle as lifecycle_persistence

    issued_pid = lifecycle_persistence.os.getpid()
    monkeypatch.setattr(lifecycle_persistence.os, "getpid", lambda: issued_pid + 1)
    with pytest.raises(
        StrategyInvocationLifecyclePersistenceConflict,
        match="another repository process",
    ):
        system.repository.authorize_start(
            winner.start_capability,
            system.fence,
        )

    monkeypatch.setattr(lifecycle_persistence.os, "getpid", lambda: issued_pid)
    authorization = system.repository.authorize_start(
        winner.start_capability,
        system.fence,
    )
    assert type(authorization) is StrategyInvocationStartAuthorization
    assert authorization.claim == winner.claim


def test_start_authorization_runtime_use_is_pid_bound_without_consumption_on_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    system = _system(tmp_path / "strategy-lifecycle-runtime-pid-bound-start.sqlite")
    winner = system.repository.claim(system.invocation, system.fence)
    assert type(winner) is StrategyInvocationNewClaim
    authorization = system.repository.authorize_start(
        winner.start_capability,
        system.fence,
    )
    assert type(authorization) is StrategyInvocationStartAuthorization
    import packages.persistence.strategy_invocation_lifecycle as lifecycle_persistence

    issued_pid = lifecycle_persistence.os.getpid()
    monkeypatch.setattr(lifecycle_persistence.os, "getpid", lambda: issued_pid + 1)
    with pytest.raises(
        StrategyInvocationLifecycleConflict,
        match="another repository process",
    ):
        authorization.consume_for_runner_start()

    monkeypatch.setattr(lifecycle_persistence.os, "getpid", lambda: issued_pid)
    authorization.consume_for_runner_start()
    with pytest.raises(
        StrategyInvocationLifecycleConflict,
        match="already consumed",
    ):
        authorization.consume_for_runner_start()


def test_start_authorization_runtime_use_is_atomic_across_threads(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "strategy-lifecycle-runtime-thread-race.sqlite")
    winner = system.repository.claim(system.invocation, system.fence)
    assert type(winner) is StrategyInvocationNewClaim
    authorization = system.repository.authorize_start(
        winner.start_capability,
        system.fence,
    )
    assert type(authorization) is StrategyInvocationStartAuthorization
    barrier = threading.Barrier(2)

    def consume_once() -> str:
        barrier.wait()
        try:
            authorization.consume_for_runner_start()
        except StrategyInvocationLifecycleConflict as error:
            return str(error)
        return "consumed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = tuple(executor.submit(consume_once) for _ in range(2))
        outcomes = tuple(future.result(timeout=10) for future in futures)

    assert outcomes.count("consumed") == 1
    assert outcomes.count("strategy start authorization was already consumed") == 1


def test_latest_strict_start_authorization_is_valid_but_equality_is_not(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "strategy-lifecycle-latest-start.sqlite")
    winner = system.repository.claim(system.invocation, system.fence)
    assert type(winner) is StrategyInvocationNewClaim
    latest_start = winner.claim.start_deadline_at - timedelta(microseconds=1)
    system.clock.instant = latest_start

    authorization = system.repository.authorize_start(
        winner.start_capability,
        system.fence,
    )

    assert type(authorization) is StrategyInvocationStartAuthorization
    assert authorization.authorized_at == latest_start
    authorization.require_start_at(latest_start)
    with pytest.raises(
        StrategyInvocationLifecycleConflict,
        match="fresh authorization window",
    ):
        authorization.require_start_at(winner.claim.start_deadline_at)


def test_consumed_start_permit_cannot_cross_the_strict_start_deadline(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "strategy-lifecycle-start-deadline.sqlite")
    claimed = system.repository.claim(system.invocation, system.fence)
    assert type(claimed) is StrategyInvocationNewClaim
    system.clock.instant = claimed.claim.start_deadline_at

    with pytest.raises(
        StrategyInvocationLifecyclePersistenceError,
        match="strict start deadline",
    ):
        system.repository.authorize_start(
            claimed.start_capability,
            system.fence,
        )
    with pytest.raises(
        StrategyInvocationLifecyclePersistenceConflict,
        match="already consumed",
    ):
        system.repository.authorize_start(
            claimed.start_capability,
            system.fence,
        )

    retained = system.repository.load(system.invocation.invocation_id)
    assert retained is not None
    assert retained.disposition is StrategyInvocationDisposition.PENDING
    system.clock.instant = claimed.claim.recoverable_at
    recovered = system.repository.recover(claimed.claim, system.fence)
    assert recovered.disposition is StrategyInvocationDisposition.FINAL
    assert recovered.result == interrupted_strategy_supervision_result(claimed.claim)


def test_unused_winning_permit_at_recovery_equality_finalizes_without_start(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "strategy-lifecycle-unused-start-recovery.sqlite")
    winner = system.repository.claim(system.invocation, system.fence)
    assert type(winner) is StrategyInvocationNewClaim
    system.clock.instant = winner.claim.recoverable_at

    recovered = system.repository.authorize_start(
        winner.start_capability,
        system.fence,
    )

    assert type(recovered) is StrategyInvocationLifecycleDecision
    assert recovered.disposition is StrategyInvocationDisposition.FINAL
    assert recovered.result == interrupted_strategy_supervision_result(winner.claim)
    with pytest.raises(
        StrategyInvocationLifecyclePersistenceConflict,
        match="already consumed",
    ):
        system.repository.authorize_start(
            winner.start_capability,
            system.fence,
        )


def test_due_claim_scan_is_bounded_cursor_exact_and_never_runs_strategy(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "strategy-lifecycle-due-scan.sqlite")
    first = system.repository.claim(system.invocation, system.fence)
    assert first.disposition is StrategyInvocationDisposition.NEW

    system.clock.instant += timedelta(microseconds=1)
    second_invocation = replace(
        system.invocation,
        input_state_sha256="9" * 64,
    )
    second = system.repository.claim(second_invocation, system.fence)
    assert second.disposition is StrategyInvocationDisposition.NEW
    due_at = second.claim.recoverable_at

    first_page = system.repository.scan_due_claims(
        due_at=due_at,
        page_size=1,
    )
    assert first_page.claims == (first.claim,)
    assert type(first_page.resume_after) is StrategyInvocationRecoveryCursor
    second_page = system.repository.scan_due_claims(
        due_at=due_at,
        page_size=1,
        resume_after=first_page.resume_after,
    )
    assert second_page.claims == (second.claim,)
    assert second_page.resume_after is None

    batch, _ = _invocation()
    runner = NeverRunner()
    system.clock.instant = due_at
    recovered = run_durable_supervised_strategy_once(
        invocation=first.claim.invocation,
        market_batch=batch,
        fence=system.fence,
        repository=system.repository,
        runner=runner,
    )
    assert recovered.disposition is StrategyInvocationDisposition.FINAL
    assert recovered.result == interrupted_strategy_supervision_result(first.claim)
    assert runner.calls == 0

    remaining = system.repository.scan_due_claims(due_at=due_at)
    assert remaining.claims == (second.claim,)
    assert remaining.resume_after is None


def test_concurrent_exact_claims_converge_to_one_new_and_one_pending(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "strategy-lifecycle-concurrent-claim.sqlite")
    before = SqlOperationalControlRepository(
        engine=system.engine,
        clock=system.clock,
    ).load(system.invocation.control_scope_id)
    assert before is not None
    barrier = threading.Barrier(2)

    def claim_once() -> StrategyInvocationNewClaim | StrategyInvocationLifecycleDecision:
        barrier.wait()
        return system.repository.claim(
            system.invocation,
            system.fence,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = tuple(executor.submit(claim_once) for _ in range(2))
        results = tuple(future.result(timeout=10) for future in futures)

    dispositions = tuple(result.disposition for result in results)
    assert dispositions.count(StrategyInvocationDisposition.NEW) == 1
    assert dispositions.count(StrategyInvocationDisposition.PENDING) == 1
    winner = next(result for result in results if type(result) is StrategyInvocationNewClaim)
    loser = next(
        result for result in results if type(result) is StrategyInvocationLifecycleDecision
    )
    assert loser.claim == winner.claim
    assert not hasattr(loser, "start_capability")
    with pytest.raises(
        StrategyInvocationLifecyclePersistenceError,
        match="winning NEW permit",
    ):
        system.repository.authorize_start(loser.claim, system.fence)
    authorization = system.repository.authorize_start(
        winner.start_capability,
        system.fence,
    )
    assert type(authorization) is StrategyInvocationStartAuthorization
    assert authorization.claim == winner.claim
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_strategy_invocation_claims)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_critical_alert_incidents)
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_operational_control_transitions)
            )
            == before.sequence_number
        )


def test_direct_legacy_result_write_is_rejected_after_lifecycle_activation(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "strategy-lifecycle-orphan-result.sqlite")
    before = SqlOperationalControlRepository(
        engine=system.engine,
        clock=system.clock,
    ).load(system.invocation.control_scope_id)
    assert before is not None
    started_at = system.clock.instant + timedelta(microseconds=1)
    result = _completed(system.invocation, started_at=started_at)
    system.clock.instant = result.completed_at + timedelta(microseconds=1)
    with pytest.raises(
        StrategySupervisionPersistenceConflict,
        match="direct strategy-supervision writes are disabled",
    ):
        SqlStrategySupervisionRepository(
            engine=system.engine,
            coordinator=system.coordinator,
            clock=system.clock,
        ).record(system.invocation, result, system.fence)

    assert system.repository.load(system.invocation.invocation_id) is None
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
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_operational_control_transitions)
            )
            == before.sequence_number
        )
    verify_strategy_invocation_lifecycle_integrity(system.engine)
