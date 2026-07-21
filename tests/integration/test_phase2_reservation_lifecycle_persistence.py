from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
import sqlalchemy as sa

from packages.domain.batch_risk import (
    BatchRiskAuthority,
    BatchRiskAuthorization,
    BatchRiskReservation,
)
from packages.domain.ledger_reducer import (
    CanonicalLedgerEntry,
    CanonicalLedgerPosting,
    LedgerEntryKind,
    reduce_execution_ledger,
)
from packages.domain.models import OrderIntent, Side
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    CanonicalOrderState,
    create_order_submission,
    reduce_order_lifecycle,
)
from packages.domain.reservation_lifecycle import (
    ReservationCapacityState,
    ReservationReleaseReason,
)
from packages.domain.submission_attempt import (
    CanonicalSubmissionAttempt,
    UnknownSubmissionBarrier,
    UnknownSubmissionResolution,
    resolve_unknown_submission,
)
from packages.persistence.batch_risk import SqlBatchRiskRepository
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    _verify_phase2_durability_integrity,
)
from packages.persistence.phase2_ledger import (
    Phase2LedgerPersistenceError,
    persist_phase2_ledger_entry,
)
from packages.persistence.reservation_lifecycle import (
    ReservationLifecycleFrozen,
    ReservationLifecyclePersistenceError,
    SqlReservationLifecycleRepository,
)
from packages.persistence.schema import (
    phase2_batch_reservations,
    phase2_ledger_entries,
    phase2_ledger_postings,
    phase2_order_events,
    phase2_reservation_release_events,
    phase2_submission_attempt_events,
)
from packages.persistence.submission_attempt import (
    SubmissionAttemptPersistenceError,
    _event_values,
)
from tests.integration.test_phase2_submission_attempt_persistence import (
    SnapshotTransactions,
    SubmissionSystem,
    _prepare,
    _system,
)
from tests.unit.test_batch_risk import EVALUATED_AT, MutableClock, limits, mixed_case

BROKER_ORDER_ID = "reservation-sql-broker-order"


def _reservation(system: SubmissionSystem) -> BatchRiskReservation:
    reservation = system.decision.reservation
    assert reservation is not None
    return reservation


def _authorization(
    system: SubmissionSystem,
    intent: OrderIntent,
) -> BatchRiskAuthorization:
    return next(
        authorization
        for authorization in system.decision.authorizations
        if authorization.intent_id == intent.intent_id
    )


def _confirmed(
    system: SubmissionSystem,
    intent: OrderIntent,
    *,
    prepared_at: datetime,
) -> CanonicalSubmissionAttempt:
    pending = _prepare(system, intent, at=prepared_at)
    in_flight = system.repository.mark_in_flight(
        pending.attempt_id,
        fence=system.lease.fence,
        occurred_at=prepared_at + timedelta(seconds=1),
        recorded_at=prepared_at + timedelta(seconds=1),
    )
    return system.repository.confirm(
        in_flight.attempt_id,
        occurred_at=prepared_at + timedelta(seconds=2),
        recorded_at=prepared_at + timedelta(seconds=2),
        response_sha256="a" * 64,
        broker_order_id=BROKER_ORDER_ID,
    )


def _install_unsupported_resolution_fact(
    system: SubmissionSystem,
    attempt: CanonicalSubmissionAttempt,
    *,
    occurred_at: datetime,
    reconciliation_sha256: str,
) -> CanonicalSubmissionAttempt:
    """Seed a legacy resolution fact that no current authenticated producer can write."""

    resolved = resolve_unknown_submission(
        attempt,
        occurred_at=occurred_at,
        recorded_at=occurred_at,
        resolution=UnknownSubmissionResolution.NOT_SUBMITTED,
        reconciliation_sha256=reconciliation_sha256,
    )
    with system.engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_submission_attempt_events).values(**_event_values(resolved.events[-1]))
        )
    return resolved


def _order_state(
    attempt: CanonicalSubmissionAttempt,
    authorization: BatchRiskAuthorization,
    events: tuple[BrokerOrderEvent, ...],
) -> CanonicalOrderState:
    submission = create_order_submission(
        intent=attempt.preparation.intent,
        risk_decision_id=authorization.decision_id,
        submission_attempt_id=attempt.attempt_id,
        submitted_at=attempt.preparation.prepared_at,
    )
    return reduce_order_lifecycle(submission=submission, broker_events=events)


def _event(
    *,
    order_id: str,
    sequence: int,
    kind: BrokerOrderEventKind,
    occurred_at: datetime,
    execution_id: str | None = None,
    revision: int | None = None,
    supersedes: str | None = None,
    quantity: Decimal | None = None,
    reason: str | None = None,
) -> BrokerOrderEvent:
    return BrokerOrderEvent(
        event_id=f"sql-reservation-event-{sequence}-{kind.value}",
        order_id=order_id,
        broker_order_id=BROKER_ORDER_ID,
        broker_sequence=sequence,
        occurred_at=occurred_at,
        received_at=occurred_at + timedelta(milliseconds=100),
        kind=kind,
        reason=reason,
        execution_id=execution_id,
        execution_revision=revision,
        supersedes_event_id=supersedes,
        quantity=quantity,
        price=Decimal("100") if quantity is not None else None,
        fee=Decimal("0.25") if quantity is not None else None,
    )


def _ledger_source(
    system: SubmissionSystem,
    state: CanonicalOrderState,
    event: BrokerOrderEvent,
) -> CanonicalLedgerEntry:
    entries = tuple(
        entry
        for entry in reduce_execution_ledger(
            order_states=(state,),
            execution_currency=system.decision.currency,
        ).entries
        if entry.reference_id == event.event_id
    )
    assert len(entries) == 1
    return entries[0]


def _count(connection: sa.Connection, table: sa.Table) -> int:
    value = connection.scalar(sa.select(sa.func.count()).select_from(table))
    assert isinstance(value, int)
    return value


def test_unsent_expiry_updates_head_atomically_and_exact_retry_is_idempotent(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-expiry.sqlite")
    reservation = _reservation(system)
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    first, second = reservation.authorizations
    first_result = lifecycle.expire_unsent(
        reservation_id=reservation.reservation_id,
        authorization_id=first.decision_id,
        fence=system.lease.fence,
        finality_reference="complete-parent-attempt-snapshot",
        observed_at=first.expires_at,
        recorded_at=first.expires_at,
    )

    assert first_result.inserted is True
    assert first_result.fact.reason is ReservationReleaseReason.APPROVAL_EXPIRED_UNSENT
    assert first_result.snapshot.persisted_state is ReservationCapacityState.PARTIALLY_RELEASED
    assert first_result.snapshot.state_version == 2
    assert first_result.snapshot.projection.remaining_authorization_count == 1

    retry = lifecycle.expire_unsent(
        reservation_id=reservation.reservation_id,
        authorization_id=first.decision_id,
        fence=system.lease.fence,
        finality_reference="complete-parent-attempt-snapshot",
        observed_at=first.expires_at,
        recorded_at=first.expires_at,
    )
    assert retry.fact == first_result.fact
    assert retry.inserted is False
    assert retry.snapshot.state_version == 2

    final_result = lifecycle.expire_unsent(
        reservation_id=reservation.reservation_id,
        authorization_id=second.decision_id,
        fence=system.lease.fence,
        finality_reference="complete-parent-attempt-snapshot",
        observed_at=second.expires_at,
        recorded_at=second.expires_at + timedelta(seconds=1),
    )
    assert final_result.snapshot.persisted_state is ReservationCapacityState.RELEASED
    assert final_result.snapshot.projection.remaining_cash == 0
    assert final_result.snapshot.state_version == 3
    assert lifecycle.history(reservation.reservation_id) == (
        first_result.fact,
        final_result.fact,
    )


def test_unknown_attempt_maps_to_child_and_freezes_every_sibling_release(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-unknown.sqlite")
    reservation = _reservation(system)
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    unknown_intent = system.intents[0]
    sibling = system.intents[1]
    unknown_authorization = _authorization(system, unknown_intent)
    sibling_authorization = _authorization(system, sibling)
    pending = _prepare(
        system,
        unknown_intent,
        at=EVALUATED_AT + timedelta(seconds=1),
    )
    in_flight = system.repository.mark_in_flight(
        pending.attempt_id,
        fence=system.lease.fence,
        occurred_at=EVALUATED_AT + timedelta(seconds=2),
        recorded_at=EVALUATED_AT + timedelta(seconds=2),
    )
    unknown = system.repository.mark_unknown(
        in_flight.attempt_id,
        occurred_at=EVALUATED_AT + timedelta(seconds=3),
        recorded_at=EVALUATED_AT + timedelta(seconds=3),
        error_class="TransportTimeout",
    )

    frozen = lifecycle.get(reservation.reservation_id)
    assert frozen is not None
    assert frozen.persisted_state is ReservationCapacityState.FROZEN
    assert frozen.projection.unknown_authorization_ids == (unknown_authorization.decision_id,)
    with pytest.raises(ReservationLifecycleFrozen, match="complete parent"):
        lifecycle.expire_unsent(
            reservation_id=reservation.reservation_id,
            authorization_id=sibling_authorization.decision_id,
            fence=system.lease.fence,
            finality_reference="blocked-expiry-snapshot",
            observed_at=sibling_authorization.expires_at,
            recorded_at=sibling_authorization.expires_at,
        )

    resolved_at = EVALUATED_AT + timedelta(seconds=4)
    with pytest.raises(
        SubmissionAttemptPersistenceError,
        match="durable authenticated broker reconciliation evidence producer",
    ):
        system.repository.resolve_unknown(
            unknown.attempt_id,
            occurred_at=resolved_at,
            recorded_at=resolved_at,
            resolution=UnknownSubmissionResolution.NOT_SUBMITTED,
            reconciliation_sha256="b" * 64,
        )

    remains_frozen = lifecycle.get(reservation.reservation_id)
    assert remains_frozen is not None
    assert remains_frozen.persisted_state is ReservationCapacityState.FROZEN
    assert remains_frozen.projection.unknown_authorization_ids == (
        unknown_authorization.decision_id,
    )
    assert lifecycle.history(reservation.reservation_id) == ()


def test_released_child_cannot_prepare_a_retry_without_capacity(tmp_path: Path) -> None:
    system = _system(tmp_path / "reservation-released-retry.sqlite")
    reservation = _reservation(system)
    intent = system.intents[0]
    authorization = _authorization(system, intent)
    attempt = _confirmed(
        system,
        intent,
        prepared_at=EVALUATED_AT + timedelta(seconds=1),
    )
    submitted = _order_state(attempt, authorization, ())
    rejection = _event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=BrokerOrderEventKind.REJECTED,
        occurred_at=EVALUATED_AT + timedelta(seconds=5),
        reason="capacity released before retry",
    )
    rejected = _order_state(attempt, authorization, (rejection,))
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    released = lifecycle.broker_rejected(
        reservation_id=reservation.reservation_id,
        authorization_id=authorization.decision_id,
        attempt_id=attempt.attempt_id,
        order_state=rejected,
        rejection_event=rejection,
        fence=system.lease.fence,
        recorded_at=rejection.received_at,
    )
    assert released.snapshot.persisted_state is ReservationCapacityState.PARTIALLY_RELEASED

    with pytest.raises(SubmissionAttemptPersistenceError, match="fully released"):
        _prepare(system, intent, at=EVALUATED_AT + timedelta(seconds=6))


def test_sent_terminal_release_requires_durable_external_reconciliation(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-sent-reconciliation.sqlite")
    reservation = _reservation(system)
    intent = system.intents[0]
    authorization = _authorization(system, intent)
    attempt = _confirmed(
        system,
        intent,
        prepared_at=EVALUATED_AT + timedelta(seconds=1),
    )
    submitted = _order_state(attempt, authorization, ())
    rejected = _event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=BrokerOrderEventKind.REJECTED,
        occurred_at=EVALUATED_AT + timedelta(seconds=5),
        reason="test broker rejection",
    )
    terminal = _order_state(attempt, authorization, (rejected,))
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )

    with pytest.raises(
        ReservationLifecyclePersistenceError,
        match="durable external reconciliation evidence producer",
    ):
        lifecycle.reconciled_terminal(
            reservation_id=reservation.reservation_id,
            authorization_id=authorization.decision_id,
            attempt_id=attempt.attempt_id,
            order_state=terminal,
            terminal_event=rejected,
            reconciliation_reference="unverified-terminal-snapshot",
            reconciliation_source_sha256="9" * 64,
            fence=system.lease.fence,
            reconciled_at=EVALUATED_AT + timedelta(seconds=6),
            recorded_at=EVALUATED_AT + timedelta(seconds=6),
        )

    assert lifecycle.history(reservation.reservation_id) == ()
    assert lifecycle.order_state(attempt.attempt_id) == submitted


def test_unverified_reconciliation_cannot_enable_retry_or_finality(tmp_path: Path) -> None:
    system = _system(tmp_path / "reservation-retry-lifecycle.sqlite")
    reservation = _reservation(system)
    intent = system.intents[0]
    pending = _prepare(system, intent, at=EVALUATED_AT + timedelta(seconds=1))
    in_flight = system.repository.mark_in_flight(
        pending.attempt_id,
        fence=system.lease.fence,
        occurred_at=EVALUATED_AT + timedelta(seconds=2),
        recorded_at=EVALUATED_AT + timedelta(seconds=2),
    )
    unknown = system.repository.mark_unknown(
        in_flight.attempt_id,
        occurred_at=EVALUATED_AT + timedelta(seconds=3),
        recorded_at=EVALUATED_AT + timedelta(seconds=3),
        error_class="RetryBeforeReleaseTimeout",
    )
    with pytest.raises(
        SubmissionAttemptPersistenceError,
        match="durable authenticated broker reconciliation evidence producer",
    ):
        system.repository.resolve_unknown(
            unknown.attempt_id,
            occurred_at=EVALUATED_AT + timedelta(seconds=4),
            recorded_at=EVALUATED_AT + timedelta(seconds=4),
            resolution=UnknownSubmissionResolution.NOT_SUBMITTED,
            reconciliation_sha256="4" * 64,
        )
    with pytest.raises(UnknownSubmissionBarrier):
        _prepare(system, intent, at=EVALUATED_AT + timedelta(seconds=5))

    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    with pytest.raises(
        ReservationLifecyclePersistenceError,
        match="durable external reconciliation evidence producer",
    ):
        lifecycle.reconciled_terminal(
            reservation_id=reservation.reservation_id,
            authorization_id=unknown.preparation.authorization_id,
            attempt_id=unknown.attempt_id,
            order_state=None,
            terminal_event=None,
            reconciliation_reference="unverified-attempt-finality",
            reconciliation_source_sha256="4" * 64,
            fence=system.lease.fence,
            reconciled_at=EVALUATED_AT + timedelta(seconds=6),
            recorded_at=EVALUATED_AT + timedelta(seconds=6),
        )
    frozen = lifecycle.get(reservation.reservation_id)
    assert frozen is not None
    assert frozen.persisted_state is ReservationCapacityState.FROZEN
    assert lifecycle.history(reservation.reservation_id) == ()
    with system.engine.connect() as connection:
        _verify_phase2_durability_integrity(connection)


def test_order_event_and_release_head_roll_back_together_on_insert_failure(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-rollback.sqlite")
    reservation = _reservation(system)
    intent = system.intents[0]
    authorization = _authorization(system, intent)
    attempt = _confirmed(
        system,
        intent,
        prepared_at=EVALUATED_AT + timedelta(seconds=1),
    )
    submitted = _order_state(attempt, authorization, ())
    rejection = _event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=BrokerOrderEventKind.REJECTED,
        occurred_at=EVALUATED_AT + timedelta(seconds=4),
        reason="broker rejected test order",
    )
    rejected = _order_state(attempt, authorization, (rejection,))
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    with system.engine.begin() as connection:
        connection.exec_driver_sql(
            """
            CREATE TRIGGER fail_reservation_release
            BEFORE INSERT ON phase2_reservation_release_events
            BEGIN
              SELECT RAISE(ABORT, 'injected release failure');
            END
            """
        )

    with pytest.raises(ReservationLifecyclePersistenceError, match="immutable SQL"):
        lifecycle.broker_rejected(
            reservation_id=reservation.reservation_id,
            authorization_id=authorization.decision_id,
            attempt_id=attempt.attempt_id,
            order_state=rejected,
            rejection_event=rejection,
            fence=system.lease.fence,
            recorded_at=rejection.received_at,
        )
    with system.engine.connect() as connection:
        assert _count(connection, phase2_order_events) == 0
        assert _count(connection, phase2_reservation_release_events) == 0
        head = connection.execute(sa.select(phase2_batch_reservations)).mappings().one()
        assert head["state"] == "active"
        assert head["state_version"] == 1

    with system.engine.begin() as connection:
        connection.exec_driver_sql("DROP TRIGGER fail_reservation_release")
    result = lifecycle.broker_rejected(
        reservation_id=reservation.reservation_id,
        authorization_id=authorization.decision_id,
        attempt_id=attempt.attempt_id,
        order_state=rejected,
        rejection_event=rejection,
        fence=system.lease.fence,
        recorded_at=rejection.received_at,
    )
    assert result.inserted is True
    assert lifecycle.order_state(attempt.attempt_id) == rejected


def test_execution_order_ledger_and_release_roll_back_in_one_transaction(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-accounting-rollback.sqlite")
    reservation = _reservation(system)
    intent = system.intents[0]
    authorization = _authorization(system, intent)
    attempt = _confirmed(
        system,
        intent,
        prepared_at=EVALUATED_AT + timedelta(seconds=1),
    )
    submitted = _order_state(attempt, authorization, ())
    execution = _event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=BrokerOrderEventKind.EXECUTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=4),
        execution_id="atomic-ledger-execution",
        revision=1,
        quantity=Decimal("1"),
    )
    state = _order_state(attempt, authorization, (execution,))
    ledger_entry = _ledger_source(system, state, execution)
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    with system.engine.begin() as connection:
        connection.exec_driver_sql(
            """
            CREATE TRIGGER fail_reservation_release
            BEFORE INSERT ON phase2_reservation_release_events
            BEGIN
              SELECT RAISE(ABORT, 'injected release failure');
            END
            """
        )

    with pytest.raises(ReservationLifecyclePersistenceError, match="immutable SQL"):
        lifecycle.execution_accounted(
            reservation_id=reservation.reservation_id,
            authorization_id=authorization.decision_id,
            attempt_id=attempt.attempt_id,
            order_state=state,
            execution_event=execution,
            accounting_reference=ledger_entry.entry_id,
            accounting_source_sha256=ledger_entry.semantic_sha256,
            fence=system.lease.fence,
            accounted_at=execution.received_at,
            recorded_at=execution.received_at,
        )
    with system.engine.connect() as connection:
        assert _count(connection, phase2_order_events) == 0
        assert _count(connection, phase2_ledger_entries) == 0
        assert _count(connection, phase2_ledger_postings) == 0
        assert _count(connection, phase2_reservation_release_events) == 0

    with system.engine.begin() as connection:
        connection.exec_driver_sql("DROP TRIGGER fail_reservation_release")
    result = lifecycle.execution_accounted(
        reservation_id=reservation.reservation_id,
        authorization_id=authorization.decision_id,
        attempt_id=attempt.attempt_id,
        order_state=state,
        execution_event=execution,
        accounting_reference=ledger_entry.entry_id,
        accounting_source_sha256=ledger_entry.semantic_sha256,
        fence=system.lease.fence,
        accounted_at=execution.received_at,
        recorded_at=execution.received_at,
    )
    assert result.inserted is True
    retry = lifecycle.execution_accounted(
        reservation_id=reservation.reservation_id,
        authorization_id=authorization.decision_id,
        attempt_id=attempt.attempt_id,
        order_state=state,
        execution_event=execution,
        accounting_reference=ledger_entry.entry_id,
        accounting_source_sha256=ledger_entry.semantic_sha256,
        fence=system.lease.fence,
        accounted_at=execution.received_at,
        recorded_at=execution.received_at,
    )
    assert retry.inserted is False
    assert retry.fact == result.fact
    with system.engine.connect() as connection:
        assert _count(connection, phase2_order_events) == 1
        assert _count(connection, phase2_ledger_entries) == 1
        assert _count(connection, phase2_ledger_postings) == len(ledger_entry.postings)
        assert _count(connection, phase2_reservation_release_events) == 1


def test_unknown_sibling_keeps_prior_sell_release_frozen_without_reconciliation(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-sell-restore.sqlite")
    reservation = _reservation(system)
    sell_intent = next(item for item in system.intents if item.side is Side.SELL)
    sell_authorization = _authorization(system, sell_intent)
    sell_attempt = _confirmed(
        system,
        sell_intent,
        prepared_at=EVALUATED_AT + timedelta(seconds=1),
    )
    submitted = _order_state(sell_attempt, sell_authorization, ())
    accepted = _event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=BrokerOrderEventKind.ACCEPTED,
        occurred_at=EVALUATED_AT + timedelta(seconds=4),
    )
    execution = _event(
        order_id=submitted.submission.order_id,
        sequence=2,
        kind=BrokerOrderEventKind.EXECUTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=5),
        execution_id="sell-restore-execution",
        revision=1,
        quantity=Decimal("1"),
    )
    sell_state = _order_state(
        sell_attempt,
        sell_authorization,
        (accepted, execution),
    )
    ledger_entry = _ledger_source(
        system,
        sell_state,
        execution,
    )
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    released = lifecycle.execution_accounted(
        reservation_id=reservation.reservation_id,
        authorization_id=sell_authorization.decision_id,
        attempt_id=sell_attempt.attempt_id,
        order_state=sell_state,
        execution_event=execution,
        accounting_reference=ledger_entry.entry_id,
        accounting_source_sha256=ledger_entry.semantic_sha256,
        fence=system.lease.fence,
        accounted_at=execution.received_at,
        recorded_at=execution.received_at,
    )
    assert released.fact.released_sell_quantity == Decimal("1")
    with system.engine.connect() as connection:
        head = connection.execute(sa.select(phase2_batch_reservations)).mappings().one()
        assert head["remaining_authorization_count"] == head["authorization_count"]
        assert head["remaining_cash"] == head["initial_cash"]
        assert head["remaining_buy_exposure"] == head["initial_buy_exposure"]

    buy_intent = next(item for item in system.intents if item.side is Side.BUY)
    pending = _prepare(
        system,
        buy_intent,
        at=EVALUATED_AT + timedelta(seconds=6),
    )
    in_flight = system.repository.mark_in_flight(
        pending.attempt_id,
        fence=system.lease.fence,
        occurred_at=EVALUATED_AT + timedelta(seconds=7),
        recorded_at=EVALUATED_AT + timedelta(seconds=7),
    )
    unknown = system.repository.mark_unknown(
        in_flight.attempt_id,
        occurred_at=EVALUATED_AT + timedelta(seconds=8),
        recorded_at=EVALUATED_AT + timedelta(seconds=8),
        error_class="SellRestoreSiblingTimeout",
    )
    with pytest.raises(
        SubmissionAttemptPersistenceError,
        match="durable authenticated broker reconciliation evidence producer",
    ):
        system.repository.resolve_unknown(
            unknown.attempt_id,
            occurred_at=EVALUATED_AT + timedelta(seconds=9),
            recorded_at=EVALUATED_AT + timedelta(seconds=9),
            resolution=UnknownSubmissionResolution.NOT_SUBMITTED,
            reconciliation_sha256="8" * 64,
        )

    snapshot = lifecycle.get(reservation.reservation_id)
    assert snapshot is not None
    assert snapshot.persisted_state is ReservationCapacityState.FROZEN
    sell_capacity = next(
        item
        for item in snapshot.projection.sell_capacity
        if item.instrument_id == sell_authorization.instrument_id
    )
    assert sell_capacity.released_quantity == Decimal("1")


def test_accounted_execution_releases_monotone_delta_and_downward_correction_freezes(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-correction.sqlite")
    reservation = _reservation(system)
    intent = next(item for item in system.intents if item.side is Side.BUY)
    authorization = _authorization(system, intent)
    attempt = _confirmed(
        system,
        intent,
        prepared_at=EVALUATED_AT + timedelta(seconds=1),
    )
    sibling_intent = next(item for item in system.intents if item.side is Side.SELL)
    sibling_pending = _prepare(
        system,
        sibling_intent,
        at=EVALUATED_AT + timedelta(seconds=3, milliseconds=200),
    )
    sibling_in_flight = system.repository.mark_in_flight(
        sibling_pending.attempt_id,
        fence=system.lease.fence,
        occurred_at=EVALUATED_AT + timedelta(seconds=3, milliseconds=400),
        recorded_at=EVALUATED_AT + timedelta(seconds=3, milliseconds=400),
    )
    submitted = _order_state(attempt, authorization, ())
    accepted = _event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=BrokerOrderEventKind.ACCEPTED,
        occurred_at=EVALUATED_AT + timedelta(seconds=4),
    )
    execution = _event(
        order_id=submitted.submission.order_id,
        sequence=2,
        kind=BrokerOrderEventKind.EXECUTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=5),
        execution_id="sql-execution-1",
        revision=1,
        quantity=Decimal("2"),
    )
    first_state = _order_state(attempt, authorization, (accepted, execution))
    first_entry = _ledger_source(
        system,
        first_state,
        execution,
    )
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    first = lifecycle.execution_accounted(
        reservation_id=reservation.reservation_id,
        authorization_id=authorization.decision_id,
        attempt_id=attempt.attempt_id,
        order_state=first_state,
        execution_event=execution,
        accounting_reference=first_entry.entry_id,
        accounting_source_sha256=first_entry.semantic_sha256,
        fence=system.lease.fence,
        accounted_at=execution.received_at,
        recorded_at=execution.received_at,
    )
    assert first.fact.accounted_quantity == Decimal("2")
    assert first.snapshot.persisted_state is ReservationCapacityState.PARTIALLY_RELEASED

    upward_correction = _event(
        order_id=submitted.submission.order_id,
        sequence=3,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=6),
        execution_id="sql-execution-1",
        revision=2,
        supersedes=execution.event_id,
        quantity=Decimal("3"),
    )
    upward_state = _order_state(
        attempt,
        authorization,
        (accepted, execution, upward_correction),
    )
    upward_entry = _ledger_source(
        system,
        upward_state,
        upward_correction,
    )
    upward = lifecycle.execution_accounted(
        reservation_id=reservation.reservation_id,
        authorization_id=authorization.decision_id,
        attempt_id=attempt.attempt_id,
        order_state=upward_state,
        execution_event=upward_correction,
        accounting_reference=upward_entry.entry_id,
        accounting_source_sha256=upward_entry.semantic_sha256,
        fence=system.lease.fence,
        accounted_at=upward_correction.received_at,
        recorded_at=upward_correction.received_at,
    )
    assert upward.fact.accounted_quantity == Decimal("1")
    assert upward.fact.execution_head_quantity == Decimal("3")

    correction = _event(
        order_id=submitted.submission.order_id,
        sequence=4,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=7),
        execution_id="sql-execution-1",
        revision=3,
        supersedes=upward_correction.event_id,
        quantity=Decimal("1"),
    )
    corrected_state = _order_state(
        attempt,
        authorization,
        (accepted, execution, upward_correction, correction),
    )
    correction_entry = _ledger_source(
        system,
        corrected_state,
        correction,
    )
    with pytest.raises(ReservationLifecycleFrozen, match="downward"):
        lifecycle.execution_accounted(
            reservation_id=reservation.reservation_id,
            authorization_id=authorization.decision_id,
            attempt_id=attempt.attempt_id,
            order_state=corrected_state,
            execution_event=correction,
            accounting_reference=correction_entry.entry_id,
            accounting_source_sha256=correction_entry.semantic_sha256,
            fence=system.lease.fence,
            accounted_at=correction.received_at,
            recorded_at=correction.received_at,
        )

    frozen = lifecycle.get(reservation.reservation_id)
    assert frozen is not None
    assert frozen.persisted_state is ReservationCapacityState.FROZEN
    assert frozen.correction_frozen is True
    assert len(lifecycle.history(reservation.reservation_id)) == 2
    assert lifecycle.order_state(attempt.attempt_id) == corrected_state
    assert system.repository.get(attempt.attempt_id) == attempt
    _, _, _, capacity = mixed_case()
    frozen_capacity = SqlBatchRiskRepository(
        engine=system.engine,
        authority=BatchRiskAuthority(
            limits=limits(),
            snapshots=SnapshotTransactions(capacity),
            evaluation_clock=MutableClock(EVALUATED_AT + timedelta(seconds=7)),
            consumption_clock=MutableClock(EVALUATED_AT + timedelta(seconds=7)),
        ),
        coordinator=system.coordinator,
    ).active_capacity(capacity.account_id)
    assert frozen_capacity.reservations[0].state.value == "frozen"
    assert len(frozen_capacity.reservations[0].provenance_sha256) == 64
    with system.engine.connect() as connection:
        _verify_phase2_durability_integrity(connection)

    with pytest.raises(SubmissionAttemptPersistenceError, match="correction freezes"):
        system.repository.prepare(
            intent=intent,
            risk_decision=system.decision,
            fence=system.lease.fence,
            request=attempt.preparation.request,
            prepared_at=EVALUATED_AT + timedelta(seconds=8),
            recorded_at=EVALUATED_AT + timedelta(seconds=8),
        )
    sibling_unknown = system.repository.mark_unknown(
        sibling_in_flight.attempt_id,
        occurred_at=EVALUATED_AT + timedelta(seconds=8),
        recorded_at=EVALUATED_AT + timedelta(seconds=8),
        error_class="CorrectionFreezeSiblingTimeout",
    )
    with pytest.raises(
        SubmissionAttemptPersistenceError,
        match="durable authenticated broker reconciliation evidence producer",
    ):
        system.repository.resolve_unknown(
            sibling_unknown.attempt_id,
            occurred_at=EVALUATED_AT + timedelta(seconds=9),
            recorded_at=EVALUATED_AT + timedelta(seconds=9),
            resolution=UnknownSubmissionResolution.NOT_SUBMITTED,
            reconciliation_sha256="7" * 64,
        )
    still_frozen = lifecycle.get(reservation.reservation_id)
    assert still_frozen is not None
    assert still_frozen.persisted_state is ReservationCapacityState.FROZEN
    # The unresolved UNKNOWN is now the visible projection-level freeze cause;
    # the independent non-monotone correction evidence remains durable.
    assert still_frozen.correction_frozen is False
    with system.engine.connect() as connection:
        _verify_phase2_durability_integrity(connection)


def test_execution_release_rejects_self_consistent_counterfeit_ledger_economics(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-counterfeit-ledger.sqlite")
    reservation = _reservation(system)
    intent = system.intents[0]
    authorization = _authorization(system, intent)
    attempt = _confirmed(
        system,
        intent,
        prepared_at=EVALUATED_AT + timedelta(seconds=1),
    )
    submitted = _order_state(attempt, authorization, ())
    execution = _event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=BrokerOrderEventKind.EXECUTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=5),
        execution_id="counterfeit-ledger-execution",
        revision=1,
        quantity=Decimal("2"),
    )
    state = _order_state(attempt, authorization, (execution,))
    expected = next(
        entry
        for entry in reduce_execution_ledger(
            order_states=(state,),
            execution_currency=system.decision.currency,
        ).entries
        if entry.reference_id == execution.event_id
    )
    counterfeit = CanonicalLedgerEntry(
        entry_id=expected.entry_id,
        kind=expected.kind,
        reference_id=expected.reference_id,
        source_sha256=expected.source_sha256,
        effective_at=expected.effective_at,
        recorded_at=expected.recorded_at,
        postings=(
            CanonicalLedgerPosting(
                account="assets:cash:USD",
                currency="USD",
                debit=Decimal("0.01"),
            ),
            CanonicalLedgerPosting(
                account="liabilities:counterfeit",
                currency="USD",
                credit=Decimal("0.01"),
            ),
        ),
    )
    with system.engine.begin() as connection:
        persist_phase2_ledger_entry(
            connection,
            account_id=system.decision.account_id,
            entry=counterfeit,
        )
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )

    with pytest.raises(
        ReservationLifecyclePersistenceError,
        match="reducer-derived execution economics",
    ):
        lifecycle.execution_accounted(
            reservation_id=reservation.reservation_id,
            authorization_id=authorization.decision_id,
            attempt_id=attempt.attempt_id,
            order_state=state,
            execution_event=execution,
            accounting_reference=counterfeit.entry_id,
            accounting_source_sha256=counterfeit.semantic_sha256,
            fence=system.lease.fence,
            accounted_at=execution.received_at,
            recorded_at=execution.received_at,
        )
    with (
        system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="canonical execution evidence"),
    ):
        _verify_phase2_durability_integrity(connection)


def test_readiness_rejects_tampered_canonical_ledger_posting(tmp_path: Path) -> None:
    system = _system(tmp_path / "reservation-ledger-readiness.sqlite")
    reservation = _reservation(system)
    intent = system.intents[0]
    authorization = _authorization(system, intent)
    attempt = _confirmed(
        system,
        intent,
        prepared_at=EVALUATED_AT + timedelta(seconds=1),
    )
    submitted = _order_state(attempt, authorization, ())
    execution = _event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=BrokerOrderEventKind.EXECUTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=5),
        execution_id="readiness-ledger-execution",
        revision=1,
        quantity=Decimal("1"),
    )
    state = _order_state(attempt, authorization, (execution,))
    ledger_entry = _ledger_source(system, state, execution)
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    lifecycle.execution_accounted(
        reservation_id=reservation.reservation_id,
        authorization_id=authorization.decision_id,
        attempt_id=attempt.attempt_id,
        order_state=state,
        execution_event=execution,
        accounting_reference=ledger_entry.entry_id,
        accounting_source_sha256=ledger_entry.semantic_sha256,
        fence=system.lease.fence,
        accounted_at=execution.received_at,
        recorded_at=execution.received_at,
    )
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase2_ledger_postings)
            .where(
                phase2_ledger_postings.c.entry_id == ledger_entry.entry_id,
                phase2_ledger_postings.c.line_number == 1,
            )
            .values(semantic_sha256="f" * 64)
        )

    with (
        system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="canonical execution evidence"),
    ):
        _verify_phase2_durability_integrity(connection)


def test_readiness_rejects_accounted_release_without_referenced_ledger(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-missing-ledger-readiness.sqlite")
    reservation = _reservation(system)
    intent = system.intents[0]
    authorization = _authorization(system, intent)
    attempt = _confirmed(
        system,
        intent,
        prepared_at=EVALUATED_AT + timedelta(seconds=1),
    )
    submitted = _order_state(attempt, authorization, ())
    execution = _event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=BrokerOrderEventKind.EXECUTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=5),
        execution_id="missing-ledger-execution",
        revision=1,
        quantity=Decimal("1"),
    )
    state = _order_state(attempt, authorization, (execution,))
    ledger_entry = _ledger_source(system, state, execution)
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    lifecycle.execution_accounted(
        reservation_id=reservation.reservation_id,
        authorization_id=authorization.decision_id,
        attempt_id=attempt.attempt_id,
        order_state=state,
        execution_event=execution,
        accounting_reference=ledger_entry.entry_id,
        accounting_source_sha256=ledger_entry.semantic_sha256,
        fence=system.lease.fence,
        accounted_at=execution.received_at,
        recorded_at=execution.received_at,
    )
    with system.engine.begin() as connection:
        connection.execute(
            sa.delete(phase2_ledger_postings).where(
                phase2_ledger_postings.c.entry_id == ledger_entry.entry_id
            )
        )
        connection.execute(
            sa.delete(phase2_ledger_entries).where(
                phase2_ledger_entries.c.entry_id == ledger_entry.entry_id
            )
        )

    with (
        system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="canonical execution evidence"),
    ):
        _verify_phase2_durability_integrity(connection)


def test_phase2_ledger_rejects_decimal_that_sqlite_cannot_round_trip(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-ledger-portability.sqlite")
    non_portable = Decimal("99999999999999.1234567890")
    entry = CanonicalLedgerEntry(
        entry_id="non-portable-ledger-entry",
        kind=LedgerEntryKind.CASH_FLOW,
        reference_id="non-portable-ledger-source",
        source_sha256="a" * 64,
        effective_at=EVALUATED_AT,
        recorded_at=EVALUATED_AT,
        postings=(
            CanonicalLedgerPosting(
                account="assets:cash:USD",
                currency="USD",
                debit=non_portable,
            ),
            CanonicalLedgerPosting(
                account="equity:external_cash_flow:USD",
                currency="USD",
                credit=non_portable,
            ),
        ),
    )

    with (
        pytest.raises(Phase2LedgerPersistenceError, match="round-trip exactly"),
        system.engine.begin() as connection,
    ):
        persist_phase2_ledger_entry(
            connection,
            account_id=system.decision.account_id,
            entry=entry,
        )
    with system.engine.connect() as connection:
        assert _count(connection, phase2_ledger_entries) == 0
        assert _count(connection, phase2_ledger_postings) == 0


def test_strict_read_rejects_tampered_release_payload(tmp_path: Path) -> None:
    system = _system(tmp_path / "reservation-tamper.sqlite")
    reservation = _reservation(system)
    authorization = reservation.authorizations[0]
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    lifecycle.expire_unsent(
        reservation_id=reservation.reservation_id,
        authorization_id=authorization.decision_id,
        fence=system.lease.fence,
        finality_reference="tamper-source-snapshot",
        observed_at=authorization.expires_at,
        recorded_at=authorization.expires_at,
    )
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase2_reservation_release_events).values(canonical_payload="{}")
        )

    with pytest.raises(ReservationLifecyclePersistenceError, match="object shape"):
        lifecycle.get(reservation.reservation_id)


def test_readiness_rejects_an_unexplained_frozen_reservation(tmp_path: Path) -> None:
    system = _system(tmp_path / "reservation-unexplained-freeze.sqlite")
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase2_batch_reservations).values(
                state=ReservationCapacityState.FROZEN.value,
                state_version=phase2_batch_reservations.c.state_version + 1,
            )
        )
    with (
        system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady),
    ):
        _verify_phase2_durability_integrity(connection)


def test_readiness_rejects_release_head_without_release_facts(tmp_path: Path) -> None:
    system = _system(tmp_path / "reservation-false-release.sqlite")
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase2_batch_reservations).values(
                state=ReservationCapacityState.RELEASED.value,
                state_version=phase2_batch_reservations.c.state_version + 1,
                remaining_authorization_count=0,
                remaining_cash=Decimal(0),
                remaining_buy_exposure=Decimal(0),
                released_at=EVALUATED_AT + timedelta(seconds=1),
            )
        )

    with (
        system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="reservation head"),
    ):
        _verify_phase2_durability_integrity(connection)


def test_readiness_rejects_every_persisted_resolved_submission_fact(tmp_path: Path) -> None:
    system = _system(tmp_path / "reservation-resolved-readiness.sqlite")
    intent = system.intents[0]
    pending = _prepare(system, intent, at=EVALUATED_AT + timedelta(seconds=1))
    in_flight = system.repository.mark_in_flight(
        pending.attempt_id,
        fence=system.lease.fence,
        occurred_at=EVALUATED_AT + timedelta(seconds=2),
        recorded_at=EVALUATED_AT + timedelta(seconds=2),
    )
    unknown = system.repository.mark_unknown(
        in_flight.attempt_id,
        occurred_at=EVALUATED_AT + timedelta(seconds=3),
        recorded_at=EVALUATED_AT + timedelta(seconds=3),
        error_class="ReadinessReconciliationTimeout",
    )
    # Stand in for a future authenticated producer so readiness proves that
    # unsupported legacy RESOLVED facts remain fail-closed in Phase 2.
    _install_unsupported_resolution_fact(
        system,
        unknown,
        occurred_at=EVALUATED_AT + timedelta(seconds=4),
        reconciliation_sha256="8" * 64,
    )

    with (
        system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady),
    ):
        _verify_phase2_durability_integrity(connection)


@pytest.mark.parametrize(
    "reason",
    (
        ReservationReleaseReason.RECONCILED_TERMINAL,
        ReservationReleaseReason.SIMULATION_HORIZON_FINAL,
    ),
)
def test_readiness_rejects_every_unsupported_terminal_release(
    tmp_path: Path,
    reason: ReservationReleaseReason,
) -> None:
    system = _system(tmp_path / f"reservation-{reason.value}-readiness.sqlite")
    reservation = _reservation(system)
    authorization = reservation.authorizations[0]
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    lifecycle.expire_unsent(
        reservation_id=reservation.reservation_id,
        authorization_id=authorization.decision_id,
        fence=system.lease.fence,
        finality_reference="readiness-expiry-source",
        observed_at=authorization.expires_at,
        recorded_at=authorization.expires_at,
    )
    with system.engine.begin() as connection:
        # Stand in for an unsupported legacy producer without reopening the
        # production release gates, which intentionally fail closed in Phase 2.
        connection.execute(sa.update(phase2_reservation_release_events).values(reason=reason.value))

    with (
        system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady),
    ):
        _verify_phase2_durability_integrity(connection)
