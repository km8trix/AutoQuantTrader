from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
import sqlalchemy as sa

from packages.domain.batch_risk import (
    BatchRiskAuthority,
    BatchRiskAuthorization,
    BatchRiskFactConflict,
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
    ReservationLifecycleError,
    ReservationReleaseFact,
    ReservationReleaseReason,
    _new_release_fact,
    project_reservation_capacity,
    record_approval_expired_unsent_release,
)
from packages.domain.submission_attempt import (
    CanonicalSubmissionAttempt,
    SubmissionAttemptError,
    SubmissionAttemptState,
    UnknownSubmissionBarrier,
    UnknownSubmissionResolution,
    resolve_unknown_submission,
)
from packages.persistence import batch_risk as batch_risk_persistence
from packages.persistence.batch_risk import (
    LEGACY_CAPACITY_OBSERVATION_CONTRACT,
    SqlBatchRiskRepository,
    _decode_active_capacity,
    _legacy_freeze_provenance_material,
    _order_state_at,
)
from packages.persistence.capacity_ordering import (
    ORDER_EVENT_VISIBILITY_KIND,
    RESERVATION_RELEASE_VISIBILITY_KIND,
    capacity_visibility_values,
)
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
    _parent_attempt_snapshot_sha256,
    immutable_order_event_values,
    immutable_reservation_release_values,
)
from packages.persistence.schema import (
    phase2_batch_decisions,
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
from tests.unit.test_batch_risk import EVALUATED_AT, MutableClock, limits, make_batch, mixed_case

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
    broker_order_id: str = BROKER_ORDER_ID,
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
        broker_order_id=broker_order_id,
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
            sa.insert(phase2_submission_attempt_events).values(
                **_event_values(
                    resolved.events[-1],
                    account_id=system.decision.account_id,
                    visible_after_observation_sequence=1,
                )
            )
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
    price: Decimal = Decimal("100"),
    fee: Decimal = Decimal("0.25"),
    broker_order_id: str = BROKER_ORDER_ID,
) -> BrokerOrderEvent:
    return BrokerOrderEvent(
        event_id=f"sql-reservation-event-{sequence}-{kind.value}",
        order_id=order_id,
        broker_order_id=broker_order_id,
        broker_sequence=sequence,
        occurred_at=occurred_at,
        received_at=occurred_at + timedelta(milliseconds=100),
        kind=kind,
        reason=reason,
        execution_id=execution_id,
        execution_revision=revision,
        supersedes_event_id=supersedes,
        quantity=quantity,
        price=price if quantity is not None else None,
        fee=fee if quantity is not None else None,
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


def test_legacy_order_cutoff_includes_equal_timestamp_event(tmp_path: Path) -> None:
    system = _system(tmp_path / "reservation-legacy-order-equal-time.sqlite")
    intent = system.intents[0]
    authorization = _authorization(system, intent)
    attempt = _confirmed(
        system,
        intent,
        prepared_at=EVALUATED_AT + timedelta(seconds=1),
    )
    submitted = _order_state(attempt, authorization, ())
    accepted = _event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=BrokerOrderEventKind.ACCEPTED,
        occurred_at=EVALUATED_AT + timedelta(seconds=4),
    )
    accepted_state = _order_state(attempt, authorization, (accepted,))
    with system.engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_order_events).values(
                **immutable_order_event_values(accepted),
                visible_after_observation_sequence=0,
                capacity_visibility_sha256=None,
            )
        )
    with system.engine.connect() as connection:
        observed = _order_state_at(
            connection,
            attempt,
            as_of=accepted.received_at,
            observation_contract=LEGACY_CAPACITY_OBSERVATION_CONTRACT,
        )

    assert observed == accepted_state


def test_legacy_freeze_provenance_uses_original_execution_projection_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    system = _system(tmp_path / "reservation-legacy-freeze-provenance.sqlite")
    reservation = _reservation(system)
    intent = next(item for item in system.intents if item.side is Side.BUY)
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
        execution_id="legacy-freeze-execution",
        revision=1,
        quantity=Decimal("2"),
    )
    initial_state = _order_state(attempt, authorization, (execution,))
    initial_entry = _ledger_source(system, initial_state, execution)
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    lifecycle.execution_accounted(
        reservation_id=reservation.reservation_id,
        authorization_id=authorization.decision_id,
        attempt_id=attempt.attempt_id,
        order_state=initial_state,
        execution_event=execution,
        accounting_reference=initial_entry.entry_id,
        accounting_source_sha256=initial_entry.semantic_sha256,
        fence=system.lease.fence,
        accounted_at=execution.received_at,
        recorded_at=execution.received_at,
    )
    correction = _event(
        order_id=submitted.submission.order_id,
        sequence=2,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=5),
        execution_id=execution.execution_id,
        revision=2,
        supersedes=execution.event_id,
        quantity=Decimal("1"),
    )
    corrected_state = _order_state(attempt, authorization, (execution, correction))
    correction_entry = _ledger_source(system, corrected_state, correction)
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
    with system.engine.begin() as connection:
        for table in (
            phase2_submission_attempt_events,
            phase2_order_events,
            phase2_reservation_release_events,
        ):
            connection.execute(
                sa.update(table).values(
                    visible_after_observation_sequence=0,
                    capacity_visibility_sha256=None,
                )
            )
        parent_row = (
            connection.execute(
                sa.select(phase2_batch_decisions).where(
                    phase2_batch_decisions.c.decision_id == system.decision.decision_id
                )
            )
            .mappings()
            .one()
        )
        parent_capacity = _decode_active_capacity(parent_row["active_capacity_payload"])
        connection.execute(
            sa.update(phase2_batch_decisions)
            .where(phase2_batch_decisions.c.decision_id == system.decision.decision_id)
            .values(
                capacity_observation_contract=LEGACY_CAPACITY_OBSERVATION_CONTRACT,
                canonical_payload=batch_risk_persistence._decision_fact_payload(
                    system.decision,
                    parent_capacity,
                    parent_row["account_observation_sequence"],
                    capacity_observation_contract=LEGACY_CAPACITY_OBSERVATION_CONTRACT,
                    fencing_generation=parent_row["fencing_generation"],
                    lease_sha256=parent_row["lease_sha256"],
                    fence_sha256=parent_row["fence_sha256"],
                ),
            )
        )
    history = lifecycle.history(reservation.reservation_id)
    with system.engine.connect() as connection:
        unknown, corrections = _legacy_freeze_provenance_material(
            connection,
            reservation,
            history,
            as_of=correction.received_at,
            observation_sequence=None,
        )

    correction_projection = next(
        item for item in corrected_state.executions if item.event_id == correction.event_id
    )
    assert unknown == ()
    assert len(corrections) == 1
    assert corrections[0][5] == correction_projection.semantic_sha256
    assert corrections[0][5] != initial_state.executions[0].semantic_sha256

    original_active_capacity_universe = batch_risk_persistence._active_capacity_universe
    original_decision_values = batch_risk_persistence._decision_values

    def legacy_active_capacity_universe(
        connection: sa.Connection,
        account_id: str,
        *,
        as_of: datetime | None = None,
        observation_contract: str | None = None,
        observation_sequence: int | None = None,
        reject_unresolved_corrections: bool = False,
    ) -> object:
        del observation_contract, reject_unresolved_corrections
        return original_active_capacity_universe(
            connection,
            account_id,
            as_of=as_of,
            observation_contract=LEGACY_CAPACITY_OBSERVATION_CONTRACT,
            observation_sequence=observation_sequence,
        )

    def legacy_decision_values(
        decision: object,
        receipt: object,
        active_capacity: object,
        account_observation_sequence: int,
    ) -> dict[str, object]:
        values = original_decision_values(
            decision,  # type: ignore[arg-type]
            receipt,  # type: ignore[arg-type]
            active_capacity,  # type: ignore[arg-type]
            account_observation_sequence,
        )
        values["capacity_observation_contract"] = LEGACY_CAPACITY_OBSERVATION_CONTRACT
        values["canonical_payload"] = batch_risk_persistence._decision_fact_payload(
            decision,  # type: ignore[arg-type]
            active_capacity,  # type: ignore[arg-type]
            account_observation_sequence,
            capacity_observation_contract=LEGACY_CAPACITY_OBSERVATION_CONTRACT,
            fencing_generation=receipt.fence.fencing_generation,  # type: ignore[attr-defined]
            lease_sha256=receipt.lease_sha256,  # type: ignore[attr-defined]
            fence_sha256=receipt.fence.semantic_sha256,  # type: ignore[attr-defined]
        )
        return values

    monkeypatch.setattr(
        batch_risk_persistence,
        "_active_capacity_universe",
        legacy_active_capacity_universe,
    )
    monkeypatch.setattr(
        batch_risk_persistence,
        "_decision_values",
        legacy_decision_values,
    )
    portfolio, _, _, capacity = mixed_case()
    observed_at = correction.received_at + timedelta(seconds=1)
    legacy_risk = SqlBatchRiskRepository(
        engine=system.engine,
        authority=BatchRiskAuthority(
            limits=limits(max_order_quantity=Decimal("0.5")),
            snapshots=SnapshotTransactions(capacity),
            evaluation_clock=MutableClock(observed_at),
            consumption_clock=MutableClock(observed_at),
        ),
        coordinator=system.coordinator,
    )
    target, batch = make_batch(
        portfolio,
        desired={"US-ETF-IWM": Decimal("5"), "US-ETF-SPY": Decimal("6")},
        target_id="legacy-frozen-correction-observation",
    )
    legacy_decision = legacy_risk.authorize(batch, target, system.lease.fence)

    assert legacy_risk.get_batch(legacy_decision.decision_id) == legacy_decision


def _persist_counterfeit_correction_release(
    system: SubmissionSystem,
    *,
    attempt: CanonicalSubmissionAttempt,
    authorization: BatchRiskAuthorization,
    order_state: CanonicalOrderState,
    correction: BrokerOrderEvent,
    inserted_events: tuple[BrokerOrderEvent, ...],
    prior_releases: tuple[ReservationReleaseFact, ...],
    execution_head_quantity: Decimal,
    accounted_quantity: Decimal,
) -> None:
    assert authorization.side is Side.SELL
    reservation = _reservation(system)
    ledger_entry = _ledger_source(system, order_state, correction)
    history = tuple(prior_releases)
    fact = _new_release_fact(
        reservation=reservation,
        authorization=authorization,
        prior_releases=history,
        reason=ReservationReleaseReason.EXECUTION_ACCOUNTED,
        finality_reference=ledger_entry.entry_id,
        source_sha256=ledger_entry.semantic_sha256,
        occurred_at=correction.received_at,
        recorded_at=correction.received_at,
        released_cash=Decimal(0),
        released_buy_exposure=Decimal(0),
        released_sell_quantity=accounted_quantity,
        attempt=attempt,
        order_state=order_state,
        order_event=correction,
        execution_id=correction.execution_id,
        execution_revision=correction.execution_revision,
        execution_head_quantity=execution_head_quantity,
        accounted_quantity=accounted_quantity,
    )
    projection = project_reservation_capacity(reservation, (*history, fact))
    with system.engine.begin() as connection:
        for event in inserted_events:
            connection.execute(
                sa.insert(phase2_order_events).values(
                    **immutable_order_event_values(event),
                    **capacity_visibility_values(
                        account_id=system.decision.account_id,
                        fact_kind=ORDER_EVENT_VISIBILITY_KIND,
                        fact_sha256=event.semantic_sha256,
                        visible_after_observation_sequence=1,
                    ),
                )
            )
        persist_phase2_ledger_entry(
            connection,
            account_id=system.decision.account_id,
            entry=ledger_entry,
        )
        connection.execute(
            sa.insert(phase2_reservation_release_events).values(
                **immutable_reservation_release_values(fact),
                **capacity_visibility_values(
                    account_id=system.decision.account_id,
                    fact_kind=RESERVATION_RELEASE_VISIBILITY_KIND,
                    fact_sha256=fact.semantic_sha256,
                    visible_after_observation_sequence=1,
                ),
            )
        )
        connection.execute(
            sa.update(phase2_batch_reservations)
            .where(phase2_batch_reservations.c.reservation_id == reservation.reservation_id)
            .values(
                state=projection.state.value,
                state_version=phase2_batch_reservations.c.state_version + 1,
                remaining_authorization_count=projection.remaining_authorization_count,
                remaining_cash=projection.remaining_cash,
                remaining_buy_exposure=projection.remaining_buy_exposure,
                released_at=projection.released_at,
            )
        )


def _persist_legacy_abandoned_broker_effect_release(
    system: SubmissionSystem,
    *,
    attempt: CanonicalSubmissionAttempt,
    authorization: BatchRiskAuthorization,
    order_state: CanonicalOrderState,
    event: BrokerOrderEvent,
    reason: ReservationReleaseReason,
) -> ReservationReleaseFact:
    """Seed an unsafe pre-hardening release without using the guarded factories."""

    reservation = _reservation(system)
    ledger_entry = (
        _ledger_source(system, order_state, event)
        if reason is ReservationReleaseReason.EXECUTION_ACCOUNTED
        else None
    )
    accounted_quantity = event.quantity if ledger_entry is not None else None
    released_buy_exposure = (
        authorization.maximum_execution_price * event.quantity
        if ledger_entry is not None
        and authorization.side is Side.BUY
        and event.quantity is not None
        else Decimal(0)
    )
    released_sell_quantity = (
        event.quantity
        if ledger_entry is not None
        and authorization.side is Side.SELL
        and event.quantity is not None
        else Decimal(0)
    )
    fact = _new_release_fact(
        reservation=reservation,
        authorization=authorization,
        prior_releases=(),
        reason=reason,
        finality_reference=(event.event_id if ledger_entry is None else ledger_entry.entry_id),
        source_sha256=(
            event.semantic_sha256 if ledger_entry is None else ledger_entry.semantic_sha256
        ),
        occurred_at=event.received_at,
        recorded_at=event.received_at,
        released_cash=(
            authorization.reserved_cash if ledger_entry is None else released_buy_exposure
        ),
        released_buy_exposure=(
            authorization.reserved_buy_exposure if ledger_entry is None else released_buy_exposure
        ),
        released_sell_quantity=(
            authorization.reserved_sell_quantity if ledger_entry is None else released_sell_quantity
        ),
        attempt=attempt,
        order_state=order_state,
        order_event=event,
        execution_id=event.execution_id,
        execution_revision=event.execution_revision,
        execution_head_quantity=event.quantity,
        accounted_quantity=accounted_quantity,
    )
    projection = project_reservation_capacity(reservation, (fact,))
    with system.engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_order_events).values(
                **immutable_order_event_values(event),
                visible_after_observation_sequence=0,
                capacity_visibility_sha256=None,
            )
        )
        if ledger_entry is not None:
            persist_phase2_ledger_entry(
                connection,
                account_id=system.decision.account_id,
                entry=ledger_entry,
            )
        connection.execute(
            sa.insert(phase2_reservation_release_events).values(
                **immutable_reservation_release_values(fact),
                visible_after_observation_sequence=0,
                capacity_visibility_sha256=None,
            )
        )
        connection.execute(
            sa.update(phase2_batch_reservations)
            .where(phase2_batch_reservations.c.reservation_id == reservation.reservation_id)
            .values(
                state=projection.state.value,
                state_version=phase2_batch_reservations.c.state_version + 1,
                remaining_authorization_count=projection.remaining_authorization_count,
                remaining_cash=projection.remaining_cash,
                remaining_buy_exposure=projection.remaining_buy_exposure,
                released_at=projection.released_at,
            )
        )
    return fact


def _persist_counterfeit_expiry_release(
    system: SubmissionSystem,
    *,
    attempt: CanonicalSubmissionAttempt,
    authorization: BatchRiskAuthorization,
) -> ReservationReleaseFact:
    """Seed a reason-shaped expiry that names an unsafe target snapshot."""

    reservation = _reservation(system)
    fact = _new_release_fact(
        reservation=reservation,
        authorization=authorization,
        prior_releases=(),
        reason=ReservationReleaseReason.APPROVAL_EXPIRED_UNSENT,
        finality_reference=f"counterfeit-expiry-{attempt.state.value}",
        source_sha256=_parent_attempt_snapshot_sha256(
            reservation.parent_decision_id,
            (attempt,),
        ),
        occurred_at=authorization.expires_at,
        recorded_at=authorization.expires_at,
        released_cash=authorization.reserved_cash,
        released_buy_exposure=authorization.reserved_buy_exposure,
        released_sell_quantity=authorization.reserved_sell_quantity,
    )
    projection = project_reservation_capacity(reservation, (fact,))
    with system.engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_reservation_release_events).values(
                **immutable_reservation_release_values(fact),
                **capacity_visibility_values(
                    account_id=system.decision.account_id,
                    fact_kind=RESERVATION_RELEASE_VISIBILITY_KIND,
                    fact_sha256=fact.semantic_sha256,
                    visible_after_observation_sequence=1,
                ),
            )
        )
        connection.execute(
            sa.update(phase2_batch_reservations)
            .where(phase2_batch_reservations.c.reservation_id == reservation.reservation_id)
            .values(
                state=projection.state.value,
                state_version=phase2_batch_reservations.c.state_version + 1,
                remaining_authorization_count=projection.remaining_authorization_count,
                remaining_cash=projection.remaining_cash,
                remaining_buy_exposure=projection.remaining_buy_exposure,
                released_at=projection.released_at,
            )
        )
    return fact


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


def test_expiry_replay_ignores_later_backdated_same_watermark_sibling_outcome(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-expiry-later-sibling.sqlite")
    reservation = _reservation(system)
    target_intent, sibling_intent = system.intents
    target_authorization = _authorization(system, target_intent)
    dispatch_at = target_authorization.expires_at - timedelta(seconds=2)
    sibling = _prepare(
        system,
        sibling_intent,
        at=dispatch_at - timedelta(seconds=1),
    )
    system.coordinator_clock.instant = dispatch_at
    sibling = system.repository.mark_in_flight(
        sibling.attempt_id,
        fence=system.lease.fence,
        occurred_at=dispatch_at,
        recorded_at=dispatch_at,
    )
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    system.coordinator_clock.instant = target_authorization.expires_at
    released = lifecycle.expire_unsent(
        reservation_id=reservation.reservation_id,
        authorization_id=target_authorization.decision_id,
        fence=system.lease.fence,
        finality_reference="causal-sibling-snapshot",
        observed_at=target_authorization.expires_at,
        recorded_at=target_authorization.expires_at,
    )

    # This immutable outcome is appended later in SQL while carrying a valid,
    # backdated business timestamp and the same account observation watermark.
    confirmed = system.repository.confirm(
        sibling.attempt_id,
        occurred_at=target_authorization.expires_at - timedelta(seconds=1),
        recorded_at=target_authorization.expires_at - timedelta(seconds=1),
        response_sha256="b" * 64,
        broker_order_id="later-backdated-sibling",
    )

    assert confirmed.state is SubmissionAttemptState.CONFIRMED
    assert lifecycle.history(reservation.reservation_id) == (released.fact,)
    with system.engine.connect() as connection:
        _verify_phase2_durability_integrity(connection)


@pytest.mark.parametrize(
    "attempt_state",
    (
        SubmissionAttemptState.PENDING,
        SubmissionAttemptState.IN_FLIGHT,
        SubmissionAttemptState.CONFIRMED,
    ),
)
def test_counterfeit_expiry_cannot_release_a_target_with_unsafe_attempt_state(
    tmp_path: Path,
    attempt_state: SubmissionAttemptState,
) -> None:
    system = _system(tmp_path / f"reservation-counterfeit-expiry-{attempt_state.value}.sqlite")
    reservation = _reservation(system)
    intent = system.intents[0]
    authorization = _authorization(system, intent)
    attempt = _prepare(system, intent, at=EVALUATED_AT + timedelta(seconds=1))
    if attempt_state is not SubmissionAttemptState.PENDING:
        system.coordinator_clock.instant = EVALUATED_AT + timedelta(seconds=2)
        attempt = system.repository.mark_in_flight(
            attempt.attempt_id,
            fence=system.lease.fence,
            occurred_at=EVALUATED_AT + timedelta(seconds=2),
            recorded_at=EVALUATED_AT + timedelta(seconds=2),
        )
    if attempt_state is SubmissionAttemptState.CONFIRMED:
        attempt = system.repository.confirm(
            attempt.attempt_id,
            occurred_at=EVALUATED_AT + timedelta(seconds=3),
            recorded_at=EVALUATED_AT + timedelta(seconds=3),
            response_sha256="c" * 64,
            broker_order_id="counterfeit-expiry-target",
        )
    assert attempt.state is attempt_state
    _persist_counterfeit_expiry_release(
        system,
        attempt=attempt,
        authorization=authorization,
    )
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )

    with pytest.raises(
        ReservationLifecyclePersistenceError,
        match="exact causal unsent snapshot",
    ):
        lifecycle.history(reservation.reservation_id)
    with (
        system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="canonical execution evidence"),
    ):
        _verify_phase2_durability_integrity(connection)


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


def test_abandoned_attempt_cannot_persist_rejection_or_execution_release(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-abandoned-broker-effects.sqlite")
    reservation = _reservation(system)
    intent = system.intents[0]
    authorization = _authorization(system, intent)
    _prepare(
        system,
        intent,
        at=EVALUATED_AT + timedelta(seconds=1),
    )
    recovered_at = EVALUATED_AT + timedelta(seconds=3)
    recovered = system.repository.recover_stale_pending(
        stale_before=EVALUATED_AT + timedelta(seconds=2),
        recovered_at=recovered_at,
        recorded_at=recovered_at,
    )
    assert len(recovered) == 1
    abandoned = recovered[0]
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    submitted = _order_state(abandoned, authorization, ())
    rejection = _event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=BrokerOrderEventKind.REJECTED,
        occurred_at=EVALUATED_AT + timedelta(seconds=4),
        reason="counterfeit abandoned rejection",
    )
    rejected = _order_state(abandoned, authorization, (rejection,))
    system.coordinator_clock.instant = rejection.received_at
    with pytest.raises(ReservationLifecycleError, match="never-dispatched ABANDONED"):
        lifecycle.broker_rejected(
            reservation_id=reservation.reservation_id,
            authorization_id=authorization.decision_id,
            attempt_id=abandoned.attempt_id,
            order_state=rejected,
            rejection_event=rejection,
            fence=system.lease.fence,
            recorded_at=rejection.received_at,
        )

    execution = _event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=BrokerOrderEventKind.EXECUTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=5),
        execution_id="counterfeit-abandoned-execution",
        revision=1,
        quantity=Decimal("1"),
    )
    executed = _order_state(abandoned, authorization, (execution,))
    ledger_entry = _ledger_source(system, executed, execution)
    system.coordinator_clock.instant = execution.received_at
    with pytest.raises(ReservationLifecycleError, match="never-dispatched ABANDONED"):
        lifecycle.execution_accounted(
            reservation_id=reservation.reservation_id,
            authorization_id=authorization.decision_id,
            attempt_id=abandoned.attempt_id,
            order_state=executed,
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
        _verify_phase2_durability_integrity(connection)


@pytest.mark.parametrize(
    "reason",
    (
        ReservationReleaseReason.BROKER_REJECTED,
        ReservationReleaseReason.EXECUTION_ACCOUNTED,
    ),
)
def test_strict_readiness_rejects_legacy_abandoned_broker_effect_release(
    tmp_path: Path,
    reason: ReservationReleaseReason,
) -> None:
    system = _system(tmp_path / f"reservation-legacy-abandoned-{reason.value}.sqlite")
    reservation = _reservation(system)
    intent = system.intents[0]
    authorization = _authorization(system, intent)
    pending = _prepare(system, intent, at=EVALUATED_AT + timedelta(seconds=1))
    recovered_at = EVALUATED_AT + timedelta(seconds=3)
    recovered = system.repository.recover_stale_pending(
        stale_before=EVALUATED_AT + timedelta(seconds=2),
        recovered_at=recovered_at,
        recorded_at=recovered_at,
    )
    assert len(recovered) == 1
    attempt = recovered[0]
    assert attempt.attempt_id == pending.attempt_id
    submitted = _order_state(attempt, authorization, ())
    event = _event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=(
            BrokerOrderEventKind.REJECTED
            if reason is ReservationReleaseReason.BROKER_REJECTED
            else BrokerOrderEventKind.EXECUTION
        ),
        occurred_at=EVALUATED_AT + timedelta(seconds=4),
        execution_id=(
            None
            if reason is ReservationReleaseReason.BROKER_REJECTED
            else "legacy-abandoned-execution"
        ),
        revision=(None if reason is ReservationReleaseReason.BROKER_REJECTED else 1),
        quantity=(None if reason is ReservationReleaseReason.BROKER_REJECTED else Decimal("1")),
        reason=(
            "legacy abandoned rejection"
            if reason is ReservationReleaseReason.BROKER_REJECTED
            else None
        ),
    )
    order_state = _order_state(attempt, authorization, (event,))
    _persist_legacy_abandoned_broker_effect_release(
        system,
        attempt=attempt,
        authorization=authorization,
        order_state=order_state,
        event=event,
        reason=reason,
    )
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )

    with pytest.raises(
        ReservationLifecyclePersistenceError,
        match="unresolved or never-dispatched",
    ):
        lifecycle.history(reservation.reservation_id)
    with (
        system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="canonical execution evidence"),
    ):
        _verify_phase2_durability_integrity(connection)


@pytest.mark.parametrize(
    "reason",
    (
        ReservationReleaseReason.BROKER_REJECTED,
        ReservationReleaseReason.EXECUTION_ACCOUNTED,
    ),
)
def test_strict_readiness_preserves_confirmed_broker_effect_release(
    tmp_path: Path,
    reason: ReservationReleaseReason,
) -> None:
    system = _system(tmp_path / f"reservation-confirmed-{reason.value}.sqlite")
    reservation = _reservation(system)
    intent = system.intents[0]
    authorization = _authorization(system, intent)
    attempt = _confirmed(
        system,
        intent,
        prepared_at=EVALUATED_AT + timedelta(seconds=1),
    )
    submitted = _order_state(attempt, authorization, ())
    event = _event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=(
            BrokerOrderEventKind.REJECTED
            if reason is ReservationReleaseReason.BROKER_REJECTED
            else BrokerOrderEventKind.EXECUTION
        ),
        occurred_at=EVALUATED_AT + timedelta(seconds=5),
        execution_id=(
            None if reason is ReservationReleaseReason.BROKER_REJECTED else "confirmed-execution"
        ),
        revision=(None if reason is ReservationReleaseReason.BROKER_REJECTED else 1),
        quantity=(None if reason is ReservationReleaseReason.BROKER_REJECTED else Decimal("1")),
        reason=(
            "confirmed broker rejection"
            if reason is ReservationReleaseReason.BROKER_REJECTED
            else None
        ),
    )
    order_state = _order_state(attempt, authorization, (event,))
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    system.coordinator_clock.instant = event.received_at
    if reason is ReservationReleaseReason.BROKER_REJECTED:
        result = lifecycle.broker_rejected(
            reservation_id=reservation.reservation_id,
            authorization_id=authorization.decision_id,
            attempt_id=attempt.attempt_id,
            order_state=order_state,
            rejection_event=event,
            fence=system.lease.fence,
            recorded_at=event.received_at,
        )
    else:
        ledger_entry = _ledger_source(system, order_state, event)
        result = lifecycle.execution_accounted(
            reservation_id=reservation.reservation_id,
            authorization_id=authorization.decision_id,
            attempt_id=attempt.attempt_id,
            order_state=order_state,
            execution_event=event,
            accounting_reference=ledger_entry.entry_id,
            accounting_source_sha256=ledger_entry.semantic_sha256,
            fence=system.lease.fence,
            accounted_at=event.received_at,
            recorded_at=event.received_at,
        )

    assert lifecycle.history(reservation.reservation_id) == (result.fact,)
    with system.engine.connect() as connection:
        _verify_phase2_durability_integrity(connection)


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
    portfolio, _, _, capacity = mixed_case()
    risk = SqlBatchRiskRepository(
        engine=system.engine,
        authority=BatchRiskAuthority(
            limits=limits(),
            snapshots=SnapshotTransactions(capacity),
            evaluation_clock=MutableClock(EVALUATED_AT + timedelta(seconds=7)),
            consumption_clock=MutableClock(EVALUATED_AT + timedelta(seconds=7)),
        ),
        coordinator=system.coordinator,
    )
    frozen_capacity = risk.active_capacity(capacity.account_id)
    assert frozen_capacity.reservations[0].state.value == "frozen"
    assert len(frozen_capacity.reservations[0].provenance_sha256) == 64
    blocked_target, blocked_batch = make_batch(
        portfolio,
        desired={"US-ETF-IWM": Decimal("4"), "US-ETF-SPY": Decimal("5")},
        target_id="correction-freeze-blocked-risk",
    )
    with pytest.raises(BatchRiskFactConflict, match="quarantines account capacity"):
        risk.authorize(blocked_batch, blocked_target, system.lease.fence)
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
    # UNKNOWN and historical correction causes remain independently visible.
    assert still_frozen.correction_frozen is True
    with system.engine.connect() as connection:
        _verify_phase2_durability_integrity(connection)


def test_correction_after_full_release_preserves_terminal_projection_and_quarantines(
    tmp_path: Path,
) -> None:
    system = _system(
        tmp_path / "reservation-terminal-correction.sqlite",
        risk_limit_overrides={
            "estimated_fixed_fee": Decimal(0),
            "estimated_fee_per_share": Decimal(0),
        },
    )
    reservation = _reservation(system)
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    accounted: list[
        tuple[
            OrderIntent,
            BatchRiskAuthorization,
            CanonicalSubmissionAttempt,
            BrokerOrderEvent,
            CanonicalOrderState,
        ]
    ] = []
    for index, intent in enumerate(system.intents):
        authorization = _authorization(system, intent)
        broker_order_id = f"{BROKER_ORDER_ID}-{index}"
        attempt = _confirmed(
            system,
            intent,
            prepared_at=EVALUATED_AT + timedelta(seconds=1 if index == 0 else 9),
            broker_order_id=broker_order_id,
        )
        submitted = _order_state(attempt, authorization, ())
        prefix = ()
        execution_sequence = 1
        if index:
            accepted = _event(
                order_id=submitted.submission.order_id,
                sequence=1,
                kind=BrokerOrderEventKind.ACCEPTED,
                occurred_at=EVALUATED_AT + timedelta(seconds=12),
                broker_order_id=broker_order_id,
            )
            prefix = (accepted,)
            execution_sequence = 2
        execution = _event(
            order_id=submitted.submission.order_id,
            sequence=execution_sequence,
            kind=BrokerOrderEventKind.EXECUTION,
            occurred_at=EVALUATED_AT + timedelta(seconds=8 + index * 5),
            execution_id=f"terminal-correction-{index}",
            revision=1,
            quantity=intent.quantity,
            price=authorization.maximum_execution_price,
            fee=Decimal(0),
            broker_order_id=broker_order_id,
        )
        state = _order_state(attempt, authorization, (*prefix, execution))
        entry = _ledger_source(system, state, execution)
        system.coordinator_clock.instant = execution.received_at
        lifecycle.execution_accounted(
            reservation_id=reservation.reservation_id,
            authorization_id=authorization.decision_id,
            attempt_id=attempt.attempt_id,
            order_state=state,
            execution_event=execution,
            accounting_reference=entry.entry_id,
            accounting_source_sha256=entry.semantic_sha256,
            fence=system.lease.fence,
            accounted_at=execution.received_at,
            recorded_at=execution.received_at,
        )
        accounted.append((intent, authorization, attempt, execution, state))

    terminal = lifecycle.get(reservation.reservation_id)
    assert terminal is not None
    assert terminal.persisted_state is ReservationCapacityState.RELEASED
    assert terminal.projection.state is ReservationCapacityState.RELEASED
    assert terminal.projection.remaining_authorization_count == 0
    assert terminal.projection.released_at is not None

    portfolio, _, _, capacity = mixed_case()
    terminal_observed_at = terminal.projection.released_at + timedelta(milliseconds=100)
    system.coordinator_clock.instant = terminal_observed_at
    terminal_observation_risk = SqlBatchRiskRepository(
        engine=system.engine,
        authority=BatchRiskAuthority(
            limits=limits(
                max_order_quantity=Decimal("0.5"),
                estimated_fixed_fee=Decimal(0),
                estimated_fee_per_share=Decimal(0),
            ),
            snapshots=SnapshotTransactions(capacity),
            evaluation_clock=MutableClock(terminal_observed_at),
            consumption_clock=MutableClock(terminal_observed_at),
        ),
        coordinator=system.coordinator,
    )
    observed_target, observed_batch = make_batch(
        portfolio,
        desired={"US-ETF-IWM": Decimal("5"), "US-ETF-SPY": Decimal("6")},
        target_id="terminal-before-correction-observation",
    )
    terminal_observation = terminal_observation_risk.authorize(
        observed_batch,
        observed_target,
        system.lease.fence,
    )
    assert terminal_observation.reservation is None

    intent, authorization, attempt, execution, _state = accounted[0]
    correction = _event(
        order_id=attempt.order_id,
        sequence=2,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=15),
        execution_id=execution.execution_id,
        revision=2,
        supersedes=execution.event_id,
        quantity=intent.quantity - Decimal(1),
        price=authorization.maximum_execution_price,
        fee=Decimal(0),
        broker_order_id=execution.broker_order_id,
    )
    corrected_state = _order_state(attempt, authorization, (execution, correction))
    correction_entry = _ledger_source(system, corrected_state, correction)
    system.coordinator_clock.instant = correction.received_at
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

    quarantined = lifecycle.get(reservation.reservation_id)
    assert quarantined is not None
    assert quarantined.persisted_state is ReservationCapacityState.RELEASED
    assert quarantined.projection.state is ReservationCapacityState.RELEASED
    assert quarantined.correction_frozen is True
    assert quarantined.projection.released_at == terminal.projection.released_at
    risk = SqlBatchRiskRepository(
        engine=system.engine,
        authority=BatchRiskAuthority(
            limits=limits(
                estimated_fixed_fee=Decimal(0),
                estimated_fee_per_share=Decimal(0),
            ),
            snapshots=SnapshotTransactions(capacity),
            evaluation_clock=MutableClock(correction.received_at),
            consumption_clock=MutableClock(correction.received_at),
        ),
        coordinator=system.coordinator,
    )
    with pytest.raises(BatchRiskFactConflict, match="quarantines account capacity"):
        risk.active_capacity(capacity.account_id)
    blocked_target, blocked_batch = make_batch(
        portfolio,
        desired={"US-ETF-IWM": Decimal("4"), "US-ETF-SPY": Decimal("5")},
        target_id="terminal-correction-blocked-risk",
    )
    with pytest.raises(BatchRiskFactConflict, match="quarantines account capacity"):
        risk.authorize(blocked_batch, blocked_target, system.lease.fence)
    with system.engine.connect() as connection:
        assert _count(connection, phase2_ledger_entries) == 3
        assert _count(connection, phase2_reservation_release_events) == 2
        _verify_phase2_durability_integrity(connection)

    with pytest.raises(SubmissionAttemptError, match="already released"):
        system.repository.prepare(
            intent=intent,
            risk_decision=system.decision,
            fence=system.lease.fence,
            request=attempt.preparation.request,
            prepared_at=correction.received_at + timedelta(seconds=1),
            recorded_at=correction.received_at + timedelta(seconds=1),
        )
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase2_order_events)
            .where(phase2_order_events.c.event_id == correction.event_id)
            .values(
                **capacity_visibility_values(
                    account_id=system.decision.account_id,
                    fact_kind=ORDER_EVENT_VISIBILITY_KIND,
                    fact_sha256=correction.semantic_sha256,
                    visible_after_observation_sequence=1,
                )
            )
        )
    with pytest.raises(
        BatchRiskFactConflict,
        match="omits a reservation with unresolved execution correction evidence",
    ):
        risk.get_batch(terminal_observation.decision_id)


def test_backdated_correction_persisted_after_decision_advances_only_later_capacity(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-backdated-correction-ordering.sqlite")
    reservation = _reservation(system)
    intent = next(item for item in system.intents if item.side is Side.BUY)
    authorization = _authorization(system, intent)
    attempt = _confirmed(
        system,
        intent,
        prepared_at=EVALUATED_AT + timedelta(seconds=1),
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
        execution_id="backdated-correction-execution",
        revision=1,
        quantity=Decimal("1"),
    )
    initial_state = _order_state(attempt, authorization, (accepted, execution))
    initial_entry = _ledger_source(system, initial_state, execution)
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    lifecycle.execution_accounted(
        reservation_id=reservation.reservation_id,
        authorization_id=authorization.decision_id,
        attempt_id=attempt.attempt_id,
        order_state=initial_state,
        execution_event=execution,
        accounting_reference=initial_entry.entry_id,
        accounting_source_sha256=initial_entry.semantic_sha256,
        fence=system.lease.fence,
        accounted_at=execution.received_at,
        recorded_at=execution.received_at,
    )

    portfolio, _, _, capacity = mixed_case()
    observation_at = EVALUATED_AT + timedelta(seconds=10)
    before_target, before_batch = make_batch(
        portfolio,
        desired={"US-ETF-IWM": Decimal("5"), "US-ETF-SPY": Decimal("5")},
        target_id="backdated-correction-before",
    )
    risk = SqlBatchRiskRepository(
        engine=system.engine,
        authority=BatchRiskAuthority(
            limits=limits(),
            snapshots=SnapshotTransactions(capacity),
            evaluation_clock=MutableClock(observation_at),
            consumption_clock=MutableClock(observation_at),
        ),
        coordinator=system.coordinator,
    )
    before = risk.authorize(before_batch, before_target, system.lease.fence)

    correction = _event(
        order_id=submitted.submission.order_id,
        sequence=3,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=6),
        execution_id=execution.execution_id,
        revision=2,
        supersedes=execution.event_id,
        quantity=Decimal("2"),
    )
    corrected_state = _order_state(
        attempt,
        authorization,
        (accepted, execution, correction),
    )
    correction_entry = _ledger_source(system, corrected_state, correction)
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
    assert risk.get_batch(before.decision_id) == before

    after_target, after_batch = make_batch(
        portfolio,
        desired={"US-ETF-IWM": Decimal("4"), "US-ETF-SPY": Decimal("5")},
        target_id="backdated-correction-after",
    )
    after = risk.authorize(after_batch, after_target, system.lease.fence)
    with system.engine.connect() as connection:
        capacity_payloads = {
            row["decision_id"]: _decode_active_capacity(row["active_capacity_payload"])
            for row in connection.execute(
                sa.select(
                    phase2_batch_decisions.c.decision_id,
                    phase2_batch_decisions.c.active_capacity_payload,
                ).where(
                    phase2_batch_decisions.c.decision_id.in_(
                        (before.decision_id, after.decision_id)
                    )
                )
            ).mappings()
        }
        _verify_phase2_durability_integrity(connection)
    before_parent = next(
        item
        for item in capacity_payloads[before.decision_id].reservations
        if item.reservation_id == reservation.reservation_id
    )
    after_parent = next(
        item
        for item in capacity_payloads[after.decision_id].reservations
        if item.reservation_id == reservation.reservation_id
    )
    assert correction.received_at < before.evaluated_at
    assert before_parent.remaining_cash > after_parent.remaining_cash
    assert risk.get_batch(after.decision_id) == after


def test_legacy_correction_and_nonmonotone_release_times_remain_readable_only_as_legacy(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-legacy-correction-history.sqlite")
    reservation = _reservation(system)
    sell_intent = next(item for item in system.intents if item.side is Side.SELL)
    sell_authorization = _authorization(system, sell_intent)
    sibling_authorization = next(
        item
        for item in reservation.authorizations
        if item.decision_id != sell_authorization.decision_id
    )
    attempt = _confirmed(
        system,
        sell_intent,
        prepared_at=EVALUATED_AT + timedelta(seconds=1),
    )
    submitted = _order_state(attempt, sell_authorization, ())
    execution = _event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=BrokerOrderEventKind.EXECUTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=5),
        execution_id="legacy-predecessorless-correction",
        revision=1,
        quantity=Decimal("1"),
    )
    correction = _event(
        order_id=submitted.submission.order_id,
        sequence=2,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=6),
        execution_id=execution.execution_id,
        revision=2,
        supersedes=execution.event_id,
        quantity=Decimal("2"),
    )
    corrected_state = _order_state(
        attempt,
        sell_authorization,
        (execution, correction),
    )
    correction_entry = _ledger_source(system, corrected_state, correction)
    late_recorded_expiry = record_approval_expired_unsent_release(
        reservation=reservation,
        authorization=sibling_authorization,
        parent_attempts=(attempt,),
        finality_reference="legacy-late-recorded-sibling-expiry",
        observed_at=sibling_authorization.expires_at,
        recorded_at=sibling_authorization.expires_at + timedelta(seconds=30),
    )
    predecessorless_correction = _new_release_fact(
        reservation=reservation,
        authorization=sell_authorization,
        prior_releases=(late_recorded_expiry,),
        reason=ReservationReleaseReason.EXECUTION_ACCOUNTED,
        finality_reference=correction_entry.entry_id,
        source_sha256=correction_entry.semantic_sha256,
        occurred_at=correction.received_at,
        recorded_at=correction.received_at,
        released_cash=Decimal(0),
        released_buy_exposure=Decimal(0),
        released_sell_quantity=correction.quantity or Decimal(0),
        attempt=attempt,
        order_state=corrected_state,
        order_event=correction,
        execution_id=correction.execution_id,
        execution_revision=correction.execution_revision,
        execution_head_quantity=correction.quantity,
        accounted_quantity=correction.quantity,
    )
    history = (late_recorded_expiry, predecessorless_correction)
    projection = project_reservation_capacity(reservation, history)
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase2_submission_attempt_events)
            .where(phase2_submission_attempt_events.c.attempt_id == attempt.attempt_id)
            .values(
                visible_after_observation_sequence=0,
                capacity_visibility_sha256=None,
            )
        )
        for event in corrected_state.broker_events:
            connection.execute(
                sa.insert(phase2_order_events).values(
                    **immutable_order_event_values(event),
                    visible_after_observation_sequence=0,
                    capacity_visibility_sha256=None,
                )
            )
        persist_phase2_ledger_entry(
            connection,
            account_id=system.decision.account_id,
            entry=correction_entry,
        )
        for fact in history:
            connection.execute(
                sa.insert(phase2_reservation_release_events).values(
                    **immutable_reservation_release_values(fact),
                    visible_after_observation_sequence=0,
                    capacity_visibility_sha256=None,
                )
            )
        connection.execute(
            sa.update(phase2_batch_reservations)
            .where(phase2_batch_reservations.c.reservation_id == reservation.reservation_id)
            .values(
                state=projection.state.value,
                state_version=phase2_batch_reservations.c.state_version + len(history),
                remaining_authorization_count=projection.remaining_authorization_count,
                remaining_cash=projection.remaining_cash,
                remaining_buy_exposure=projection.remaining_buy_exposure,
                released_at=projection.released_at,
            )
        )

    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    assert predecessorless_correction.recorded_at < late_recorded_expiry.recorded_at
    assert lifecycle.history(reservation.reservation_id) == history
    snapshot = lifecycle.get(reservation.reservation_id)
    assert snapshot is not None
    assert snapshot.projection == projection
    with system.engine.connect() as connection:
        _verify_phase2_durability_integrity(connection)

    current_visibility = capacity_visibility_values(
        account_id=system.decision.account_id,
        fact_kind=RESERVATION_RELEASE_VISIBILITY_KIND,
        fact_sha256=predecessorless_correction.semantic_sha256,
        visible_after_observation_sequence=1,
    )
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase2_reservation_release_events)
            .where(
                phase2_reservation_release_events.c.release_event_id
                == predecessorless_correction.release_event_id
            )
            .values(**current_visibility)
        )
    with pytest.raises(
        ReservationLifecyclePersistenceError,
        match="regresses its recorded time",
    ):
        lifecycle.get(reservation.reservation_id)


def test_independent_execution_cannot_release_state_hiding_downward_correction(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-hidden-correction.sqlite")
    reservation = _reservation(system)
    intent = next(item for item in system.intents if item.side is Side.SELL)
    authorization = _authorization(system, intent)
    attempt = _confirmed(
        system,
        intent,
        prepared_at=EVALUATED_AT + timedelta(seconds=1),
    )
    submitted = _order_state(attempt, authorization, ())
    accepted = _event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=BrokerOrderEventKind.ACCEPTED,
        occurred_at=EVALUATED_AT + timedelta(seconds=4),
    )
    execution_a = _event(
        order_id=submitted.submission.order_id,
        sequence=2,
        kind=BrokerOrderEventKind.EXECUTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=5),
        execution_id="hidden-correction-a",
        revision=1,
        quantity=Decimal("3"),
    )
    downward_a = _event(
        order_id=submitted.submission.order_id,
        sequence=3,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=6),
        execution_id="hidden-correction-a",
        revision=2,
        supersedes=execution_a.event_id,
        quantity=Decimal("2"),
    )
    execution_b = _event(
        order_id=submitted.submission.order_id,
        sequence=4,
        kind=BrokerOrderEventKind.EXECUTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=7),
        execution_id="independent-monotone-b",
        revision=1,
        quantity=Decimal("2"),
    )
    state = _order_state(
        attempt,
        authorization,
        (accepted, execution_a, downward_a, execution_b),
    )
    execution_b_entry = _ledger_source(system, state, execution_b)
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    system.coordinator_clock.instant = execution_b.received_at

    with pytest.raises(ReservationLifecycleFrozen, match="downward"):
        lifecycle.execution_accounted(
            reservation_id=reservation.reservation_id,
            authorization_id=authorization.decision_id,
            attempt_id=attempt.attempt_id,
            order_state=state,
            execution_event=execution_b,
            accounting_reference=execution_b_entry.entry_id,
            accounting_source_sha256=execution_b_entry.semantic_sha256,
            fence=system.lease.fence,
            accounted_at=execution_b.received_at,
            recorded_at=execution_b.received_at,
        )

    snapshot = lifecycle.get(reservation.reservation_id)
    assert snapshot is not None
    assert snapshot.persisted_state is ReservationCapacityState.FROZEN
    assert snapshot.correction_frozen is True
    assert lifecycle.order_state(attempt.attempt_id) == state
    assert lifecycle.history(reservation.reservation_id) == ()
    with system.engine.connect() as connection:
        assert _count(connection, phase2_order_events) == 4
        assert _count(connection, phase2_ledger_entries) == 1
        assert _count(connection, phase2_ledger_postings) == len(execution_b_entry.postings)
        _verify_phase2_durability_integrity(connection)


def test_later_execution_revision_cannot_erase_historical_correction_freeze(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-sticky-correction.sqlite")
    reservation = _reservation(system)
    intent = next(item for item in system.intents if item.side is Side.SELL)
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
        execution_id="sticky-correction",
        revision=1,
        quantity=Decimal("3"),
    )
    downward = _event(
        order_id=submitted.submission.order_id,
        sequence=2,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=6),
        execution_id="sticky-correction",
        revision=2,
        supersedes=execution.event_id,
        quantity=Decimal("2"),
    )
    downward_state = _order_state(
        attempt,
        authorization,
        (execution, downward),
    )
    downward_entry = _ledger_source(system, downward_state, downward)
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    system.coordinator_clock.instant = downward.received_at
    with pytest.raises(ReservationLifecycleFrozen, match="downward"):
        lifecycle.execution_accounted(
            reservation_id=reservation.reservation_id,
            authorization_id=authorization.decision_id,
            attempt_id=attempt.attempt_id,
            order_state=downward_state,
            execution_event=downward,
            accounting_reference=downward_entry.entry_id,
            accounting_source_sha256=downward_entry.semantic_sha256,
            fence=system.lease.fence,
            accounted_at=downward.received_at,
            recorded_at=downward.received_at,
        )

    later = _event(
        order_id=submitted.submission.order_id,
        sequence=3,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=7),
        execution_id="sticky-correction",
        revision=3,
        supersedes=downward.event_id,
        quantity=Decimal("4"),
    )
    with system.engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_order_events).values(
                **immutable_order_event_values(later),
                **capacity_visibility_values(
                    account_id=system.decision.account_id,
                    fact_kind=ORDER_EVENT_VISIBILITY_KIND,
                    fact_sha256=later.semantic_sha256,
                    visible_after_observation_sequence=1,
                ),
            )
        )

    sticky = lifecycle.get(reservation.reservation_id)
    assert sticky is not None
    assert sticky.persisted_state is ReservationCapacityState.FROZEN
    assert sticky.correction_frozen is True
    with system.engine.connect() as connection:
        _verify_phase2_durability_integrity(connection)

    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase2_batch_reservations)
            .where(phase2_batch_reservations.c.reservation_id == reservation.reservation_id)
            .values(state=ReservationCapacityState.ACTIVE.value)
        )

    with pytest.raises(ReservationLifecyclePersistenceError, match="durable correction history"):
        lifecycle.get(reservation.reservation_id)
    with (
        system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="durable execution integrity"),
    ):
        _verify_phase2_durability_integrity(connection)


def test_later_upward_revision_completes_ledger_chain_without_unfreezing(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-frozen-upward-ledger-chain.sqlite")
    reservation = _reservation(system)
    intent = next(item for item in system.intents if item.side is Side.SELL)
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
        execution_id="frozen-upward-ledger-chain",
        revision=1,
        quantity=Decimal("2"),
    )
    initial_state = _order_state(attempt, authorization, (execution,))
    initial_entry = _ledger_source(system, initial_state, execution)
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    system.coordinator_clock.instant = execution.received_at
    initial = lifecycle.execution_accounted(
        reservation_id=reservation.reservation_id,
        authorization_id=authorization.decision_id,
        attempt_id=attempt.attempt_id,
        order_state=initial_state,
        execution_event=execution,
        accounting_reference=initial_entry.entry_id,
        accounting_source_sha256=initial_entry.semantic_sha256,
        fence=system.lease.fence,
        accounted_at=execution.received_at,
        recorded_at=execution.received_at,
    )

    downward = _event(
        order_id=submitted.submission.order_id,
        sequence=2,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=6),
        execution_id=execution.execution_id,
        revision=2,
        supersedes=execution.event_id,
        quantity=Decimal("1"),
    )
    downward_state = _order_state(attempt, authorization, (execution, downward))
    downward_entry = _ledger_source(system, downward_state, downward)
    system.coordinator_clock.instant = downward.received_at
    with pytest.raises(ReservationLifecycleFrozen, match="downward"):
        lifecycle.execution_accounted(
            reservation_id=reservation.reservation_id,
            authorization_id=authorization.decision_id,
            attempt_id=attempt.attempt_id,
            order_state=downward_state,
            execution_event=downward,
            accounting_reference=downward_entry.entry_id,
            accounting_source_sha256=downward_entry.semantic_sha256,
            fence=system.lease.fence,
            accounted_at=downward.received_at,
            recorded_at=downward.received_at,
        )

    upward = _event(
        order_id=submitted.submission.order_id,
        sequence=3,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=7),
        execution_id=execution.execution_id,
        revision=3,
        supersedes=downward.event_id,
        quantity=Decimal("3"),
    )
    upward_state = _order_state(
        attempt,
        authorization,
        (execution, downward, upward),
    )
    upward_entry = _ledger_source(system, upward_state, upward)
    system.coordinator_clock.instant = upward.received_at
    with pytest.raises(ReservationLifecycleFrozen, match="downward"):
        lifecycle.execution_accounted(
            reservation_id=reservation.reservation_id,
            authorization_id=authorization.decision_id,
            attempt_id=attempt.attempt_id,
            order_state=upward_state,
            execution_event=upward,
            accounting_reference=upward_entry.entry_id,
            accounting_source_sha256=upward_entry.semantic_sha256,
            fence=system.lease.fence,
            accounted_at=upward.received_at,
            recorded_at=upward.received_at,
        )

    frozen = lifecycle.get(reservation.reservation_id)
    assert frozen is not None
    assert frozen.persisted_state is ReservationCapacityState.FROZEN
    assert frozen.correction_frozen is True
    assert lifecycle.history(reservation.reservation_id) == (initial.fact,)
    assert lifecycle.order_state(attempt.attempt_id) == upward_state
    with system.engine.connect() as connection:
        assert _count(connection, phase2_ledger_entries) == 3
        assert _count(connection, phase2_ledger_postings) == sum(
            len(entry.postings) for entry in (initial_entry, downward_entry, upward_entry)
        )
        assert _count(connection, phase2_reservation_release_events) == 1
        _verify_phase2_durability_integrity(connection)


def test_multi_revision_catchup_rolls_back_before_partial_ledger_chain(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-multi-revision-catchup.sqlite")
    reservation = _reservation(system)
    intent = next(item for item in system.intents if item.side is Side.SELL)
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
        execution_id="multi-revision-catchup",
        revision=1,
        quantity=Decimal("2"),
    )
    initial_state = _order_state(attempt, authorization, (execution,))
    initial_entry = _ledger_source(system, initial_state, execution)
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    system.coordinator_clock.instant = execution.received_at
    initial = lifecycle.execution_accounted(
        reservation_id=reservation.reservation_id,
        authorization_id=authorization.decision_id,
        attempt_id=attempt.attempt_id,
        order_state=initial_state,
        execution_event=execution,
        accounting_reference=initial_entry.entry_id,
        accounting_source_sha256=initial_entry.semantic_sha256,
        fence=system.lease.fence,
        accounted_at=execution.received_at,
        recorded_at=execution.received_at,
    )

    downward = _event(
        order_id=submitted.submission.order_id,
        sequence=2,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=6),
        execution_id=execution.execution_id,
        revision=2,
        supersedes=execution.event_id,
        quantity=Decimal("1"),
    )
    upward = _event(
        order_id=submitted.submission.order_id,
        sequence=3,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=7),
        execution_id=execution.execution_id,
        revision=3,
        supersedes=downward.event_id,
        quantity=Decimal("3"),
    )
    catchup_state = _order_state(
        attempt,
        authorization,
        (execution, downward, upward),
    )
    upward_entry = _ledger_source(system, catchup_state, upward)
    system.coordinator_clock.instant = upward.received_at

    with pytest.raises(
        ReservationLifecyclePersistenceError,
        match="partial execution revision ledger chain",
    ):
        lifecycle.execution_accounted(
            reservation_id=reservation.reservation_id,
            authorization_id=authorization.decision_id,
            attempt_id=attempt.attempt_id,
            order_state=catchup_state,
            execution_event=upward,
            accounting_reference=upward_entry.entry_id,
            accounting_source_sha256=upward_entry.semantic_sha256,
            fence=system.lease.fence,
            accounted_at=upward.received_at,
            recorded_at=upward.received_at,
        )

    assert lifecycle.order_state(attempt.attempt_id) == initial_state
    assert lifecycle.history(reservation.reservation_id) == (initial.fact,)
    with system.engine.connect() as connection:
        assert _count(connection, phase2_order_events) == 1
        assert _count(connection, phase2_ledger_entries) == 1
        assert _count(connection, phase2_ledger_postings) == len(initial_entry.postings)
        assert _count(connection, phase2_reservation_release_events) == 1
        _verify_phase2_durability_integrity(connection)


def test_upward_correction_cannot_account_before_its_predecessor(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-unaccounted-upward-correction.sqlite")
    reservation = _reservation(system)
    intent = system.intents[0]
    authorization = _authorization(system, intent)
    attempt = _confirmed(
        system,
        intent,
        prepared_at=EVALUATED_AT + timedelta(seconds=1),
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
        execution_id="unaccounted-upward",
        revision=1,
        quantity=Decimal("2"),
    )
    correction = _event(
        order_id=submitted.submission.order_id,
        sequence=3,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=6),
        execution_id="unaccounted-upward",
        revision=2,
        supersedes=execution.event_id,
        quantity=Decimal("3"),
    )
    corrected_state = _order_state(
        attempt,
        authorization,
        (accepted, execution, correction),
    )
    correction_entry = _ledger_source(system, corrected_state, correction)
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    system.coordinator_clock.instant = correction.received_at

    with pytest.raises(ReservationLifecycleError, match="exact accounting coverage first"):
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

    with system.engine.connect() as connection:
        assert _count(connection, phase2_order_events) == 0
        assert _count(connection, phase2_ledger_entries) == 0
        assert _count(connection, phase2_ledger_postings) == 0
        assert _count(connection, phase2_reservation_release_events) == 0
        assert connection.scalar(sa.select(phase2_batch_reservations.c.state)) == "active"
        _verify_phase2_durability_integrity(connection)


def test_load_and_readiness_reject_upward_correction_with_wrong_delta(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-upward-wrong-delta.sqlite")
    reservation = _reservation(system)
    intent = next(item for item in system.intents if item.side is Side.SELL)
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
        execution_id="wrong-upward-delta",
        revision=1,
        quantity=Decimal("2"),
    )
    first_state = _order_state(attempt, authorization, (execution,))
    first_entry = _ledger_source(system, first_state, execution)
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
    correction = _event(
        order_id=submitted.submission.order_id,
        sequence=2,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=6),
        execution_id="wrong-upward-delta",
        revision=2,
        supersedes=execution.event_id,
        quantity=Decimal("3"),
    )
    corrected_state = _order_state(attempt, authorization, (execution, correction))
    _persist_counterfeit_correction_release(
        system,
        attempt=attempt,
        authorization=authorization,
        order_state=corrected_state,
        correction=correction,
        inserted_events=(correction,),
        prior_releases=(first.fact,),
        execution_head_quantity=Decimal("4"),
        accounted_quantity=Decimal("2"),
    )

    with pytest.raises(ReservationLifecyclePersistenceError, match="exact durable revision"):
        lifecycle.get(reservation.reservation_id)
    with (
        system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="canonical execution evidence"),
    ):
        _verify_phase2_durability_integrity(connection)


def test_load_and_readiness_reject_upward_correction_without_predecessor_release(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-upward-missing-predecessor.sqlite")
    reservation = _reservation(system)
    intent = next(item for item in system.intents if item.side is Side.SELL)
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
        execution_id="missing-upward-predecessor",
        revision=1,
        quantity=Decimal("2"),
    )
    correction = _event(
        order_id=submitted.submission.order_id,
        sequence=2,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=6),
        execution_id="missing-upward-predecessor",
        revision=2,
        supersedes=execution.event_id,
        quantity=Decimal("3"),
    )
    corrected_state = _order_state(attempt, authorization, (execution, correction))
    _persist_counterfeit_correction_release(
        system,
        attempt=attempt,
        authorization=authorization,
        order_state=corrected_state,
        correction=correction,
        inserted_events=(execution, correction),
        prior_releases=(),
        execution_head_quantity=Decimal("3"),
        accounted_quantity=Decimal("3"),
    )
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )

    with pytest.raises(ReservationLifecyclePersistenceError, match="predecessor release"):
        lifecycle.get(reservation.reservation_id)
    with (
        system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="canonical execution evidence"),
    ):
        _verify_phase2_durability_integrity(connection)


def test_downward_correction_freezes_even_before_predecessor_accounting(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-unaccounted-downward-correction.sqlite")
    reservation = _reservation(system)
    intent = system.intents[0]
    authorization = _authorization(system, intent)
    attempt = _confirmed(
        system,
        intent,
        prepared_at=EVALUATED_AT + timedelta(seconds=1),
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
        execution_id="unaccounted-downward",
        revision=1,
        quantity=Decimal("4"),
    )
    correction = _event(
        order_id=submitted.submission.order_id,
        sequence=3,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=6),
        execution_id="unaccounted-downward",
        revision=2,
        supersedes=execution.event_id,
        quantity=Decimal("3"),
    )
    corrected_state = _order_state(
        attempt,
        authorization,
        (accepted, execution, correction),
    )
    correction_entry = _ledger_source(system, corrected_state, correction)
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    system.coordinator_clock.instant = correction.received_at

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
    with system.engine.connect() as connection:
        assert _count(connection, phase2_order_events) == 3
        assert _count(connection, phase2_ledger_entries) == 0
        assert _count(connection, phase2_ledger_postings) == 0
        assert _count(connection, phase2_reservation_release_events) == 0
        _verify_phase2_durability_integrity(connection)

    initial_entry = _ledger_source(system, corrected_state, execution)
    later = correction.received_at + timedelta(seconds=1)
    system.coordinator_clock.instant = later
    with pytest.raises(ReservationLifecycleFrozen, match="downward"):
        lifecycle.execution_accounted(
            reservation_id=reservation.reservation_id,
            authorization_id=authorization.decision_id,
            attempt_id=attempt.attempt_id,
            order_state=corrected_state,
            execution_event=execution,
            accounting_reference=initial_entry.entry_id,
            accounting_source_sha256=initial_entry.semantic_sha256,
            fence=system.lease.fence,
            accounted_at=later,
            recorded_at=later,
        )

    with system.engine.connect() as connection:
        assert _count(connection, phase2_ledger_entries) == 0
        assert _count(connection, phase2_ledger_postings) == 0
        assert _count(connection, phase2_reservation_release_events) == 0
        _verify_phase2_durability_integrity(connection)

    with system.engine.begin() as connection:
        persist_phase2_ledger_entry(
            connection,
            account_id=system.decision.account_id,
            entry=initial_entry,
        )
    with (
        system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="canonical execution evidence"),
    ):
        _verify_phase2_durability_integrity(connection)


def test_equal_correction_freezes_without_requiring_a_zero_posting_ledger_entry(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "reservation-equal-correction.sqlite")
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
        execution_id="equal-correction",
        revision=1,
        quantity=Decimal("4"),
    )
    correction = _event(
        order_id=submitted.submission.order_id,
        sequence=2,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        occurred_at=EVALUATED_AT + timedelta(seconds=6),
        execution_id="equal-correction",
        revision=2,
        supersedes=execution.event_id,
        quantity=Decimal("4"),
    )
    corrected_state = _order_state(attempt, authorization, (execution, correction))
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    system.coordinator_clock.instant = correction.received_at

    with pytest.raises(ReservationLifecycleFrozen, match="non-monotone"):
        lifecycle.execution_accounted(
            reservation_id=reservation.reservation_id,
            authorization_id=authorization.decision_id,
            attempt_id=attempt.attempt_id,
            order_state=corrected_state,
            execution_event=correction,
            accounting_reference="equal-correction-has-no-ledger-entry",
            accounting_source_sha256="0" * 64,
            fence=system.lease.fence,
            accounted_at=correction.received_at,
            recorded_at=correction.received_at,
        )

    frozen = lifecycle.get(reservation.reservation_id)
    assert frozen is not None
    assert frozen.persisted_state is ReservationCapacityState.FROZEN
    assert frozen.correction_frozen is True
    with system.engine.connect() as connection:
        assert _count(connection, phase2_order_events) == 2
        assert _count(connection, phase2_ledger_entries) == 0
        assert _count(connection, phase2_ledger_postings) == 0
        assert _count(connection, phase2_reservation_release_events) == 0
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


def test_strict_read_rejects_authenticated_future_release_visibility(tmp_path: Path) -> None:
    system = _system(tmp_path / "reservation-future-visibility.sqlite")
    reservation = _reservation(system)
    authorization = reservation.authorizations[0]
    lifecycle = SqlReservationLifecycleRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    result = lifecycle.expire_unsent(
        reservation_id=reservation.reservation_id,
        authorization_id=authorization.decision_id,
        fence=system.lease.fence,
        finality_reference="future-visibility-source",
        observed_at=authorization.expires_at,
        recorded_at=authorization.expires_at,
    )
    future_visibility = capacity_visibility_values(
        account_id=system.decision.account_id,
        fact_kind=RESERVATION_RELEASE_VISIBILITY_KIND,
        fact_sha256=result.fact.semantic_sha256,
        visible_after_observation_sequence=2,
    )
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase2_reservation_release_events)
            .where(
                phase2_reservation_release_events.c.release_event_id == result.fact.release_event_id
            )
            .values(**future_visibility)
        )

    with pytest.raises(
        ReservationLifecyclePersistenceError,
        match="exceeds the durable account observation watermark",
    ):
        lifecycle.get(reservation.reservation_id)
    with (
        system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="canonical execution evidence"),
    ):
        _verify_phase2_durability_integrity(connection)


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
