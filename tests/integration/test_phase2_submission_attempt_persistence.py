from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from threading import Barrier
from typing import TypeVar

import pytest
import sqlalchemy as sa

from packages.domain.account_coordinator import AccountLease, AccountLeasePolicy
from packages.domain.batch_risk import (
    BatchRiskAuthority,
    BatchRiskDecision,
    BatchRiskFactConflict,
    VersionedBatchRiskSnapshot,
)
from packages.domain.models import OrderIntent
from packages.domain.submission_attempt import (
    BrokerSubmissionRequest,
    CanonicalSubmissionAttempt,
    SubmissionAttemptError,
    SubmissionAttemptState,
    UnknownSubmissionBarrier,
    UnknownSubmissionResolution,
    create_broker_submission_request,
)
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.batch_risk import (
    LEGACY_CAPACITY_OBSERVATION_CONTRACT,
    SqlBatchRiskRepository,
    _attempts_at,
    _decode_active_capacity,
)
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    _verify_phase2_durability_integrity,
    create_database_engine,
)
from packages.persistence.reservation_lifecycle import SqlReservationLifecycleRepository
from packages.persistence.schema import (
    metadata,
    phase2_account_leases,
    phase2_authorization_consumptions,
    phase2_batch_authorizations,
    phase2_batch_decisions,
    phase2_batch_reservations,
    phase2_logical_orders,
    phase2_submission_attempt_events,
    phase2_submission_attempts,
)
from packages.persistence.submission_attempt import (
    PENDING_RECOVERY_ERROR_CLASS,
    RECOVERY_ERROR_CLASS,
    SqlSubmissionAttemptRepository,
    SubmissionAttemptPersistenceError,
)
from tests.unit.test_batch_risk import (
    EVALUATED_AT,
    MutableClock,
    limits,
    make_batch,
    mixed_case,
)

ResultT = TypeVar("ResultT")


@dataclass(frozen=True)
class SnapshotTransactions:
    snapshot: VersionedBatchRiskSnapshot

    def current(self) -> VersionedBatchRiskSnapshot:
        return self.snapshot

    def transact(
        self,
        operation: Callable[[VersionedBatchRiskSnapshot], ResultT],
    ) -> ResultT:
        return operation(self.snapshot)


@dataclass(frozen=True)
class SubmissionSystem:
    engine: sa.Engine
    coordinator: SqlAccountCoordinator
    coordinator_clock: MutableClock
    lease: AccountLease
    decision: BatchRiskDecision
    intents: tuple[OrderIntent, ...]
    repository: SqlSubmissionAttemptRepository


def _request(intent: OrderIntent) -> BrokerSubmissionRequest:
    return create_broker_submission_request(
        intent=intent,
        adapter_id="integration-broker",
        adapter_version="1.0.0",
        operation="submit_order",
        payload={
            "client_tag": "phase2",
            "quantity": intent.quantity,
            "side": intent.side.value,
            "symbol": intent.symbol,
            "test_only": True,
        },
    )


def _system(
    path: Path,
    *,
    lease_ttl: timedelta = timedelta(minutes=10),
    risk_limit_overrides: dict[str, object] | None = None,
) -> SubmissionSystem:
    _, target, batch, capacity = mixed_case()
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    metadata.create_all(engine)
    coordinator_clock = MutableClock(EVALUATED_AT)
    authority = SqlAccountCoordinatorAuthority(
        engine=engine,
        policy=AccountLeasePolicy(
            policy_id="phase2-submission-integration",
            policy_version="1.0.0",
            lease_ttl=lease_ttl,
            maximum_in_flight_duration=timedelta(seconds=5),
            takeover_safety_interval=timedelta(seconds=10),
        ),
        clock=coordinator_clock,
    )
    coordinator = SqlAccountCoordinator(
        account_id=capacity.account_id,
        authority=authority,
    )
    lease = coordinator.acquire("worker-a")
    risk_authority = BatchRiskAuthority(
        limits=limits(**(risk_limit_overrides or {})),
        snapshots=SnapshotTransactions(capacity),
        evaluation_clock=MutableClock(EVALUATED_AT),
        consumption_clock=MutableClock(EVALUATED_AT + timedelta(seconds=1)),
    )
    risk = SqlBatchRiskRepository(
        engine=engine,
        authority=risk_authority,
        coordinator=coordinator,
    )
    decision = risk.authorize(batch, target, lease.fence)
    assert decision.reservation is not None
    return SubmissionSystem(
        engine=engine,
        coordinator=coordinator,
        coordinator_clock=coordinator_clock,
        lease=lease,
        decision=decision,
        intents=batch.intents,
        repository=SqlSubmissionAttemptRepository(
            engine=engine,
            coordinator=coordinator,
        ),
    )


def _prepare(
    system: SubmissionSystem,
    intent: OrderIntent,
    *,
    at: datetime,
) -> CanonicalSubmissionAttempt:
    return system.repository.prepare(
        intent=intent,
        risk_decision=system.decision,
        fence=system.lease.fence,
        request=_request(intent),
        prepared_at=at,
        recorded_at=at,
    )


def _count(connection: sa.Connection, table: sa.Table) -> int:
    value = connection.scalar(sa.select(sa.func.count()).select_from(table))
    assert isinstance(value, int)
    return value


def test_legacy_attempt_cutoff_includes_equal_timestamp_pending_fact(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase2-legacy-attempt-equal-time.sqlite")
    observed_at = EVALUATED_AT + timedelta(seconds=1)
    attempt = _prepare(system, system.intents[0], at=observed_at)
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase2_submission_attempt_events)
            .where(phase2_submission_attempt_events.c.attempt_id == attempt.attempt_id)
            .values(
                visible_after_observation_sequence=0,
                capacity_visibility_sha256=None,
            )
        )
    with system.engine.connect() as connection:
        observed = _attempts_at(
            connection,
            system.decision.decision_id,
            as_of=observed_at,
            observation_contract=LEGACY_CAPACITY_OBSERVATION_CONTRACT,
        )

    assert observed == (attempt,)


def test_legacy_attempt_cutoff_rejects_preparation_without_visible_pending_fact(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase2-legacy-attempt-missing-pending.sqlite")
    prepared_at = EVALUATED_AT + timedelta(seconds=1)
    attempt = system.repository.prepare(
        intent=system.intents[0],
        risk_decision=system.decision,
        fence=system.lease.fence,
        request=_request(system.intents[0]),
        prepared_at=prepared_at,
        recorded_at=prepared_at + timedelta(seconds=1),
    )
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase2_submission_attempt_events)
            .where(phase2_submission_attempt_events.c.attempt_id == attempt.attempt_id)
            .values(
                visible_after_observation_sequence=0,
                capacity_visibility_sha256=None,
            )
        )
    with (
        system.engine.connect() as connection,
        pytest.raises(
            BatchRiskFactConflict,
            match="attempt preparation lacks its pending fact",
        ),
    ):
        _attempts_at(
            connection,
            system.decision.decision_id,
            as_of=prepared_at + timedelta(milliseconds=500),
            observation_contract=LEGACY_CAPACITY_OBSERVATION_CONTRACT,
        )


def test_legacy_attempt_cutoff_excludes_post_migration_backdated_attempt(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase2-legacy-attempt-post-migration.sqlite")
    attempt = _prepare(
        system,
        system.intents[0],
        at=EVALUATED_AT + timedelta(seconds=1),
    )
    with system.engine.connect() as connection:
        observed = _attempts_at(
            connection,
            system.decision.decision_id,
            as_of=attempt.preparation.prepared_at + timedelta(seconds=1),
            observation_contract=LEGACY_CAPACITY_OBSERVATION_CONTRACT,
        )

    assert observed == ()


def test_preparation_atomically_persists_order_consumption_attempt_and_pending(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase2-submission.sqlite")
    intent = system.intents[0]
    prepared_at = EVALUATED_AT + timedelta(seconds=1)

    attempt = system.repository.prepare(
        intent=intent,
        risk_decision=system.decision,
        fence=system.lease.fence,
        request=_request(intent),
        prepared_at=prepared_at,
        recorded_at=prepared_at + timedelta(milliseconds=1),
    )

    assert attempt.state is SubmissionAttemptState.PENDING
    assert attempt.attempt_number == 1
    assert system.repository.get(attempt.attempt_id) == attempt
    assert system.repository.for_parent(system.decision.decision_id) == (attempt,)
    with system.engine.connect() as connection:
        assert _count(connection, phase2_logical_orders) == 1
        assert _count(connection, phase2_authorization_consumptions) == 1
        assert _count(connection, phase2_submission_attempts) == 1
        assert _count(connection, phase2_submission_attempt_events) == 1
        _verify_phase2_durability_integrity(connection)


def test_initial_preparation_accepts_current_renewal_of_authorized_stable_fence(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase2-submission-renewed-initial.sqlite")
    system.coordinator_clock.instant = EVALUATED_AT + timedelta(seconds=1)
    renewed = system.coordinator.renew(system.lease.fence)

    assert renewed.fence == system.lease.fence
    assert renewed.semantic_sha256 != system.lease.semantic_sha256
    prepared_at = EVALUATED_AT + timedelta(seconds=2)
    attempt = system.repository.prepare(
        intent=system.intents[0],
        risk_decision=system.decision,
        fence=renewed.fence,
        request=_request(system.intents[0]),
        prepared_at=prepared_at,
        recorded_at=prepared_at,
    )

    assert attempt.preparation.fence_receipt.lease_sha256 == renewed.semantic_sha256
    assert system.repository.get(attempt.attempt_id) == attempt
    with system.engine.connect() as connection:
        authorization_lease = connection.scalar(
            sa.select(phase2_batch_authorizations.c.lease_sha256).where(
                phase2_batch_authorizations.c.authorization_id
                == attempt.preparation.authorization_id
            )
        )
        logical_order_lease = connection.scalar(
            sa.select(phase2_logical_orders.c.lease_sha256).where(
                phase2_logical_orders.c.order_id == attempt.order_id
            )
        )
        consumption_lease = connection.scalar(
            sa.select(phase2_authorization_consumptions.c.lease_sha256).where(
                phase2_authorization_consumptions.c.order_id == attempt.order_id
            )
        )
        assert authorization_lease == system.lease.semantic_sha256
        assert logical_order_lease == renewed.semantic_sha256
        assert consumption_lease == renewed.semantic_sha256
        _verify_phase2_durability_integrity(connection)


def test_dispatch_persists_renewed_receipt_after_preparation_receipt_expires(
    tmp_path: Path,
) -> None:
    system = _system(
        tmp_path / "phase2-submission-renewed-dispatch.sqlite",
        lease_ttl=timedelta(seconds=3),
    )
    pending = _prepare(
        system,
        system.intents[0],
        at=EVALUATED_AT + timedelta(seconds=1),
    )
    preparation_receipt = pending.preparation.fence_receipt
    system.coordinator_clock.instant = EVALUATED_AT + timedelta(seconds=2)
    renewed = system.coordinator.renew(system.lease.fence)
    dispatch_at = EVALUATED_AT + timedelta(seconds=4)

    assert dispatch_at > preparation_receipt.valid_until
    assert renewed.expires_at > dispatch_at
    in_flight = system.repository.mark_in_flight(
        pending.attempt_id,
        fence=renewed.fence,
        occurred_at=dispatch_at,
        recorded_at=dispatch_at,
    )

    dispatch_receipt = in_flight.events[-1].dispatch_fence_receipt
    assert dispatch_receipt is not None
    assert dispatch_receipt.fence == preparation_receipt.fence
    assert dispatch_receipt.lease_sha256 == renewed.semantic_sha256
    assert dispatch_receipt.validated_at == dispatch_at
    assert dispatch_receipt.valid_until == renewed.expires_at
    assert system.repository.get(in_flight.attempt_id) == in_flight
    with system.engine.connect() as connection:
        row = (
            connection.execute(
                sa.select(phase2_submission_attempt_events).where(
                    phase2_submission_attempt_events.c.event_id == in_flight.events[-1].event_id
                )
            )
            .mappings()
            .one()
        )
        assert row["dispatch_lease_sha256"] == renewed.semantic_sha256
        assert row["dispatch_fence_receipt_sha256"] == dispatch_receipt.semantic_sha256
        _verify_phase2_durability_integrity(connection)


def test_pending_insert_failure_rolls_back_every_preparation_fact(tmp_path: Path) -> None:
    system = _system(tmp_path / "phase2-submission-rollback.sqlite")
    with system.engine.begin() as connection:
        connection.exec_driver_sql(
            """
            CREATE TRIGGER fail_phase2_pending
            BEFORE INSERT ON phase2_submission_attempt_events
            BEGIN
              SELECT RAISE(ABORT, 'injected pending failure');
            END
            """
        )

    with pytest.raises(SubmissionAttemptPersistenceError, match="conflicts"):
        _prepare(
            system,
            system.intents[0],
            at=EVALUATED_AT + timedelta(seconds=1),
        )

    with system.engine.connect() as connection:
        assert _count(connection, phase2_logical_orders) == 0
        assert _count(connection, phase2_authorization_consumptions) == 0
        assert _count(connection, phase2_submission_attempts) == 0
        assert _count(connection, phase2_submission_attempt_events) == 0


def test_outcome_recording_does_not_require_a_still_current_fence(tmp_path: Path) -> None:
    system = _system(tmp_path / "phase2-submission-old-fence.sqlite")
    pending = _prepare(
        system,
        system.intents[0],
        at=EVALUATED_AT + timedelta(seconds=1),
    )
    assert hasattr(pending, "attempt_id")
    in_flight = system.repository.mark_in_flight(
        pending.attempt_id,
        fence=system.lease.fence,
        occurred_at=EVALUATED_AT + timedelta(seconds=2),
        recorded_at=EVALUATED_AT + timedelta(seconds=2),
    )

    after_lease_expiry = system.lease.expires_at + timedelta(seconds=1)
    confirmed = system.repository.confirm(
        in_flight.attempt_id,
        occurred_at=after_lease_expiry,
        recorded_at=after_lease_expiry,
        response_sha256="a" * 64,
        broker_order_id="broker-order-old-fence",
    )

    assert confirmed.state is SubmissionAttemptState.CONFIRMED
    assert system.repository.get(confirmed.attempt_id) == confirmed


def test_unknown_cannot_be_resolved_or_retried_without_authenticated_reconciliation(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase2-submission-unknown.sqlite")
    first = _prepare(
        system,
        system.intents[0],
        at=EVALUATED_AT + timedelta(seconds=1),
    )
    first = system.repository.mark_in_flight(
        first.attempt_id,
        fence=system.lease.fence,
        occurred_at=EVALUATED_AT + timedelta(seconds=2),
        recorded_at=EVALUATED_AT + timedelta(seconds=2),
    )
    first = system.repository.mark_unknown(
        first.attempt_id,
        occurred_at=EVALUATED_AT + timedelta(seconds=3),
        recorded_at=EVALUATED_AT + timedelta(seconds=3),
        error_class="FirstTimeout",
    )
    with system.engine.connect() as connection:
        assert connection.scalar(sa.select(phase2_batch_reservations.c.state)) == "frozen"
        event_count = _count(connection, phase2_submission_attempt_events)
    _, _, _, capacity = mixed_case()
    frozen_capacity = SqlBatchRiskRepository(
        engine=system.engine,
        authority=BatchRiskAuthority(
            limits=limits(),
            snapshots=SnapshotTransactions(capacity),
            evaluation_clock=MutableClock(EVALUATED_AT + timedelta(seconds=3)),
            consumption_clock=MutableClock(EVALUATED_AT + timedelta(seconds=3)),
        ),
        coordinator=system.coordinator,
    ).active_capacity(capacity.account_id)
    assert frozen_capacity.reservations[0].state.value == "frozen"
    assert len(frozen_capacity.reservations[0].provenance_sha256) == 64

    with pytest.raises(
        SubmissionAttemptPersistenceError,
        match="durable authenticated broker reconciliation evidence producer",
    ):
        system.repository.resolve_unknown(
            first.attempt_id,
            occurred_at=EVALUATED_AT + timedelta(seconds=4),
            recorded_at=EVALUATED_AT + timedelta(seconds=4),
            resolution=UnknownSubmissionResolution.NOT_SUBMITTED,
            reconciliation_sha256="b" * 64,
        )

    assert system.repository.get(first.attempt_id) == first
    with system.engine.connect() as connection:
        assert connection.scalar(sa.select(phase2_batch_reservations.c.state)) == "frozen"
        assert _count(connection, phase2_submission_attempt_events) == event_count
        _verify_phase2_durability_integrity(connection)
    with pytest.raises(UnknownSubmissionBarrier):
        system.repository.prepare(
            intent=system.intents[0],
            risk_decision=system.decision,
            fence=system.lease.fence,
            request=_request(system.intents[0]),
            prepared_at=EVALUATED_AT + timedelta(seconds=5),
            recorded_at=EVALUATED_AT + timedelta(seconds=5),
        )


def test_same_timestamp_unknown_is_visible_only_after_its_serialized_decision(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase2-submission-unknown-ordering.sqlite")
    pending = _prepare(
        system,
        system.intents[0],
        at=EVALUATED_AT + timedelta(seconds=1),
    )
    in_flight = system.repository.mark_in_flight(
        pending.attempt_id,
        fence=system.lease.fence,
        occurred_at=EVALUATED_AT + timedelta(seconds=2),
        recorded_at=EVALUATED_AT + timedelta(seconds=2),
    )
    portfolio, _, _, capacity = mixed_case()
    observation_at = EVALUATED_AT + timedelta(seconds=3)

    before_target, before_batch = make_batch(
        portfolio,
        desired={"US-ETF-IWM": Decimal("7"), "US-ETF-SPY": Decimal("5")},
        target_id="unknown-ordering-before",
    )
    before_risk = SqlBatchRiskRepository(
        engine=system.engine,
        authority=BatchRiskAuthority(
            limits=limits(),
            snapshots=SnapshotTransactions(capacity),
            evaluation_clock=MutableClock(observation_at),
            consumption_clock=MutableClock(observation_at),
        ),
        coordinator=system.coordinator,
    )
    before = before_risk.authorize(before_batch, before_target, system.lease.fence)

    system.repository.mark_unknown(
        in_flight.attempt_id,
        occurred_at=observation_at,
        recorded_at=observation_at,
        error_class="SameTimestampTimeout",
    )
    assert before_risk.get_batch(before.decision_id) == before

    after_target, after_batch = make_batch(
        portfolio,
        desired={"US-ETF-IWM": Decimal("8"), "US-ETF-SPY": Decimal("5")},
        target_id="unknown-ordering-after",
    )
    after_risk = SqlBatchRiskRepository(
        engine=system.engine,
        authority=BatchRiskAuthority(
            limits=limits(),
            snapshots=SnapshotTransactions(capacity),
            evaluation_clock=MutableClock(observation_at),
            consumption_clock=MutableClock(observation_at),
        ),
        coordinator=system.coordinator,
    )
    after = after_risk.authorize(after_batch, after_target, system.lease.fence)
    with system.engine.connect() as connection:
        before_capacity = _decode_active_capacity(
            connection.scalar(
                sa.select(phase2_batch_decisions.c.active_capacity_payload).where(
                    phase2_batch_decisions.c.decision_id == before.decision_id
                )
            )
        )
        after_capacity = _decode_active_capacity(
            connection.scalar(
                sa.select(phase2_batch_decisions.c.active_capacity_payload).where(
                    phase2_batch_decisions.c.decision_id == after.decision_id
                )
            )
        )
    assert before_capacity.reservations[0].state.value != "frozen"
    assert after_capacity.reservations[0].state.value == "frozen"
    assert after_risk.get_batch(after.decision_id) == after


@pytest.mark.parametrize("clean_handoff", [False, True], ids=("renewal", "new-generation"))
def test_stale_pending_is_abandoned_and_retried_across_current_fences(
    tmp_path: Path,
    clean_handoff: bool,
) -> None:
    system = _system(tmp_path / f"phase2-pending-recovery-{clean_handoff}.sqlite")
    pending = _prepare(
        system,
        system.intents[0],
        at=EVALUATED_AT + timedelta(seconds=1),
    )
    system.coordinator_clock.instant = EVALUATED_AT + timedelta(seconds=2)
    if clean_handoff:
        system.coordinator.release(system.lease.fence)
        system.coordinator_clock.instant = EVALUATED_AT + timedelta(seconds=3)
        current_lease = system.coordinator.acquire("worker-b")
        with pytest.raises(
            SubmissionAttemptPersistenceError,
            match="prepared stable fence",
        ):
            system.repository.mark_in_flight(
                pending.attempt_id,
                fence=current_lease.fence,
                occurred_at=EVALUATED_AT + timedelta(seconds=3),
                recorded_at=EVALUATED_AT + timedelta(seconds=3),
            )
    else:
        current_lease = system.coordinator.renew(system.lease.fence)

    recovered = system.repository.recover_stale_pending(
        stale_before=EVALUATED_AT + timedelta(seconds=2),
        recovered_at=EVALUATED_AT + timedelta(seconds=4),
        recorded_at=EVALUATED_AT + timedelta(seconds=4),
    )

    assert len(recovered) == 1
    abandoned = recovered[0]
    assert abandoned.attempt_id == pending.attempt_id
    assert abandoned.state is SubmissionAttemptState.ABANDONED
    assert abandoned.events[-1].error_class == PENDING_RECOVERY_ERROR_CLASS
    assert abandoned.events[-1].dispatch_fence_receipt is None
    assert abandoned.events[-1].reconciliation_sha256 is None
    assert abandoned.may_resubmit is True
    assert (
        system.repository.recover_stale_pending(
            stale_before=EVALUATED_AT + timedelta(seconds=5),
            recovered_at=EVALUATED_AT + timedelta(seconds=5),
            recorded_at=EVALUATED_AT + timedelta(seconds=5),
        )
        == ()
    )

    retry_at = EVALUATED_AT + timedelta(seconds=6)
    retry = system.repository.prepare(
        intent=system.intents[0],
        risk_decision=system.decision,
        fence=current_lease.fence,
        request=_request(system.intents[0]),
        prepared_at=retry_at,
        recorded_at=retry_at,
    )

    assert retry.attempt_number == 2
    assert retry.order_id == abandoned.order_id
    assert retry.preparation.client_order_id == abandoned.preparation.client_order_id
    assert retry.preparation.fence_receipt.fence == current_lease.fence
    with system.engine.connect() as connection:
        assert _count(connection, phase2_logical_orders) == 1
        assert _count(connection, phase2_authorization_consumptions) == 1
        assert _count(connection, phase2_submission_attempts) == 2
        assert _count(connection, phase2_submission_attempt_events) == 3
        _verify_phase2_durability_integrity(connection)


def test_pending_recovery_rejects_impossible_evidence_before_mutation(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase2-pending-recovery-invalid-evidence.sqlite")
    pending = _prepare(
        system,
        system.intents[0],
        at=EVALUATED_AT + timedelta(seconds=1),
    )

    with pytest.raises(SubmissionAttemptError, match="before its stale cutoff"):
        system.repository.recover_stale_pending(
            stale_before=EVALUATED_AT + timedelta(seconds=4),
            recovered_at=EVALUATED_AT + timedelta(seconds=3),
            recorded_at=EVALUATED_AT + timedelta(seconds=3),
        )
    with pytest.raises(SubmissionAttemptError, match="recorded before"):
        system.repository.recover_stale_pending(
            stale_before=EVALUATED_AT + timedelta(seconds=2),
            recovered_at=EVALUATED_AT + timedelta(seconds=4),
            recorded_at=EVALUATED_AT + timedelta(seconds=3),
        )
    with pytest.raises(SubmissionAttemptError, match="non-empty, trimmed"):
        system.repository.recover_stale_pending(
            stale_before=EVALUATED_AT + timedelta(seconds=2),
            recovered_at=EVALUATED_AT + timedelta(seconds=3),
            recorded_at=EVALUATED_AT + timedelta(seconds=3),
            error_class=" ",
        )

    assert system.repository.get(pending.attempt_id) == pending


def test_abandoned_pending_can_release_at_expiry_and_released_capacity_blocks_retry(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase2-pending-abandoned-release.sqlite")
    intent = system.intents[0]
    pending = _prepare(
        system,
        intent,
        at=EVALUATED_AT + timedelta(seconds=1),
    )
    abandoned = system.repository.recover_stale_pending(
        stale_before=EVALUATED_AT + timedelta(seconds=2),
        recovered_at=EVALUATED_AT + timedelta(seconds=3),
        recorded_at=EVALUATED_AT + timedelta(seconds=3),
    )[0]
    authorization = next(
        item for item in system.decision.authorizations if item.intent_id == intent.intent_id
    )
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    released = lifecycle.expire_unsent(
        reservation_id=abandoned.preparation.reservation_id,
        authorization_id=abandoned.preparation.authorization_id,
        fence=system.lease.fence,
        finality_reference="abandoned-pending-expiry",
        observed_at=authorization.expires_at,
        recorded_at=authorization.expires_at,
    )

    released_authorization = next(
        item
        for item in released.snapshot.projection.authorizations
        if item.authorization_id == authorization.decision_id
    )
    assert released_authorization.fully_released is True
    with pytest.raises(SubmissionAttemptPersistenceError, match="fully released"):
        system.repository.prepare(
            intent=intent,
            risk_decision=system.decision,
            fence=system.lease.fence,
            request=_request(intent),
            prepared_at=authorization.expires_at + timedelta(seconds=1),
            recorded_at=authorization.expires_at + timedelta(seconds=1),
        )
    assert system.repository.get(pending.attempt_id) == abandoned


def test_pending_recovery_and_dispatch_race_produces_one_legal_successor(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase2-pending-recovery-race.sqlite")
    pending = _prepare(
        system,
        system.intents[0],
        at=EVALUATED_AT + timedelta(seconds=1),
    )
    start = Barrier(2)

    def dispatch() -> CanonicalSubmissionAttempt | SubmissionAttemptError:
        start.wait()
        try:
            return system.repository.mark_in_flight(
                pending.attempt_id,
                fence=system.lease.fence,
                occurred_at=EVALUATED_AT + timedelta(seconds=4),
                recorded_at=EVALUATED_AT + timedelta(seconds=4),
            )
        except SubmissionAttemptError as error:
            return error

    def recover() -> tuple[CanonicalSubmissionAttempt, ...]:
        start.wait()
        return system.repository.recover_stale_pending(
            stale_before=EVALUATED_AT + timedelta(seconds=2),
            recovered_at=EVALUATED_AT + timedelta(seconds=4),
            recorded_at=EVALUATED_AT + timedelta(seconds=4),
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        dispatch_future = executor.submit(dispatch)
        recovery_future = executor.submit(recover)
        dispatch_result = dispatch_future.result()
        recovery_result = recovery_future.result()

    persisted = system.repository.get(pending.attempt_id)
    assert persisted is not None
    assert tuple(event.state for event in persisted.events) in {
        (SubmissionAttemptState.PENDING, SubmissionAttemptState.IN_FLIGHT),
        (SubmissionAttemptState.PENDING, SubmissionAttemptState.ABANDONED),
    }
    if persisted.state is SubmissionAttemptState.IN_FLIGHT:
        assert isinstance(dispatch_result, CanonicalSubmissionAttempt)
        assert recovery_result == ()
    else:
        assert isinstance(dispatch_result, SubmissionAttemptError)
        assert len(recovery_result) == 1
        assert recovery_result[0] == persisted
    with system.engine.connect() as connection:
        assert _count(connection, phase2_submission_attempt_events) == 2
        _verify_phase2_durability_integrity(connection)


def test_recovery_promotes_stale_in_flight_to_unknown_and_freezes_parent(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase2-submission-recovery.sqlite")
    pending = _prepare(
        system,
        system.intents[0],
        at=EVALUATED_AT + timedelta(seconds=1),
    )
    in_flight = system.repository.mark_in_flight(
        pending.attempt_id,
        fence=system.lease.fence,
        occurred_at=EVALUATED_AT + timedelta(seconds=2),
        recorded_at=EVALUATED_AT + timedelta(seconds=2),
    )

    recovered = system.repository.recover_stale_in_flight(
        stale_before=EVALUATED_AT + timedelta(seconds=3),
        recovered_at=EVALUATED_AT + timedelta(seconds=4),
        recorded_at=EVALUATED_AT + timedelta(seconds=4),
    )

    assert len(recovered) == 1
    assert recovered[0].attempt_id == in_flight.attempt_id
    assert recovered[0].state is SubmissionAttemptState.UNKNOWN
    assert recovered[0].unknown_error_class == RECOVERY_ERROR_CLASS
    with system.engine.connect() as connection:
        assert connection.scalar(sa.select(phase2_batch_reservations.c.state)) == "frozen"


def test_readiness_rejects_dispatch_receipt_not_bound_to_prepared_fence(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase2-dispatch-receipt-readiness.sqlite")
    pending = _prepare(
        system,
        system.intents[0],
        at=EVALUATED_AT + timedelta(seconds=1),
    )
    in_flight = system.repository.mark_in_flight(
        pending.attempt_id,
        fence=system.lease.fence,
        occurred_at=EVALUATED_AT + timedelta(seconds=2),
        recorded_at=EVALUATED_AT + timedelta(seconds=2),
    )
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase2_submission_attempt_events)
            .where(phase2_submission_attempt_events.c.event_id == in_flight.events[-1].event_id)
            .values(dispatch_fence_sha256="f" * 64)
        )

    with (
        system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="durable execution integrity"),
    ):
        _verify_phase2_durability_integrity(connection)
    with pytest.raises(SubmissionAttemptPersistenceError, match="immutable lease"):
        system.repository.get(in_flight.attempt_id)


@pytest.mark.parametrize(
    ("column", "value", "message"),
    [
        ("request_payload", " []", "not canonical JSON"),
        ("fence_receipt_sha256", "f" * 64, "receipt digest"),
        ("semantic_sha256", "e" * 64, "exact evidence"),
    ],
)
def test_strict_read_rejects_corrupt_or_counterfeit_attempt_rows(
    tmp_path: Path,
    column: str,
    value: str,
    message: str,
) -> None:
    system = _system(tmp_path / f"phase2-submission-corrupt-{column}.sqlite")
    attempt = _prepare(
        system,
        system.intents[0],
        at=EVALUATED_AT + timedelta(seconds=1),
    )
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase2_submission_attempts)
            .where(phase2_submission_attempts.c.attempt_id == attempt.attempt_id)
            .values({column: value})
        )

    with pytest.raises(SubmissionAttemptPersistenceError, match=message):
        system.repository.get(attempt.attempt_id)
    with (
        system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="canonical execution evidence"),
    ):
        _verify_phase2_durability_integrity(connection)


def test_readiness_strictly_authenticates_account_lease_history(tmp_path: Path) -> None:
    system = _system(tmp_path / "phase2-coordinator-readiness.sqlite")
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase2_account_leases).values(owner_id="counterfeit-coordinator-owner")
        )

    with (
        system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="canonical execution evidence"),
    ):
        _verify_phase2_durability_integrity(connection)


@pytest.mark.parametrize(
    ("fact", "message"),
    [
        ("intent_payload", "not canonical JSON"),
        ("logical_client", "logical order conflicts"),
        ("consumption_time", "consumption time conflicts"),
        ("event_digest", "event digest"),
        ("authorization_digest", "risk decision is malformed"),
    ],
)
def test_strict_read_authenticates_every_normalized_source_fact(
    tmp_path: Path,
    fact: str,
    message: str,
) -> None:
    system = _system(tmp_path / f"phase2-submission-source-{fact}.sqlite")
    attempt = _prepare(
        system,
        system.intents[0],
        at=EVALUATED_AT + timedelta(seconds=1),
    )
    with system.engine.begin() as connection:
        if fact == "intent_payload":
            payload = connection.scalar(sa.select(phase2_logical_orders.c.intent_payload))
            assert isinstance(payload, str)
            connection.execute(
                sa.update(phase2_logical_orders).values(intent_payload=f" {payload}")
            )
        elif fact == "logical_client":
            connection.execute(
                sa.update(phase2_logical_orders).values(client_order_id="tampered-client-order-id")
            )
        elif fact == "consumption_time":
            connection.execute(
                sa.update(phase2_authorization_consumptions).values(
                    consumed_at=EVALUATED_AT + timedelta(seconds=2)
                )
            )
        elif fact == "event_digest":
            connection.execute(
                sa.update(phase2_submission_attempt_events).values(semantic_sha256="f" * 64)
            )
        else:
            connection.execute(
                sa.update(phase2_batch_authorizations)
                .where(
                    phase2_batch_authorizations.c.authorization_id
                    == attempt.preparation.authorization_id
                )
                .values(semantic_sha256="e" * 64)
            )

    with pytest.raises(SubmissionAttemptPersistenceError, match=message):
        system.repository.get(attempt.attempt_id)
