from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from decimal import Decimal

import pytest

from packages.domain.batch_risk import (
    BatchRiskAuthorization,
    BatchRiskDecision,
    BatchRiskReservation,
)
from packages.domain.models import OrderIntent, Side
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    CanonicalOrderState,
    create_cancel_request,
    create_order_submission,
    reduce_order_lifecycle,
)
from packages.domain.reservation_lifecycle import (
    ReservationCapacityState,
    ReservationLifecycleError,
    ReservationReleaseConflict,
    ReservationReleaseFact,
    ReservationReleaseReason,
    project_reservation_capacity,
    record_approval_expired_unsent_release,
    record_broker_rejected_release,
    record_execution_accounted_release,
    record_reconciled_terminal_release,
    record_simulation_horizon_final_release,
)
from packages.domain.submission_attempt import (
    CanonicalSubmissionAttempt,
    UnknownSubmissionResolution,
    _abandon_pending_submission,
    confirm_submission,
    resolve_unknown_submission,
)
from tests.unit.test_submission_attempt import (
    PREPARED_AT,
    RISK_EXPIRES_AT,
    in_flight_attempt,
    intent,
    pending_attempt,
    risk_decision,
    sibling_intent,
    unknown_attempt,
)

BROKER_ORDER_ID = "reservation-lifecycle-broker-order"
SUBMITTED_AT = PREPARED_AT + timedelta(seconds=1)
CONFIRMED_AT = PREPARED_AT + timedelta(seconds=2)


def approved_case(
    order_intent: OrderIntent | None = None,
    decision: BatchRiskDecision | None = None,
) -> tuple[BatchRiskDecision, BatchRiskReservation, BatchRiskAuthorization]:
    order_intent = order_intent or intent()
    decision = decision or risk_decision((order_intent,))
    assert decision.reservation is not None
    authorization = next(
        item for item in decision.authorizations if item.intent_id == order_intent.intent_id
    )
    return decision, decision.reservation, authorization


def confirmed_attempt(
    *,
    order_intent: OrderIntent | None = None,
    decision: BatchRiskDecision | None = None,
) -> CanonicalSubmissionAttempt:
    return confirm_submission(
        in_flight_attempt(order_intent=order_intent, decision=decision),
        occurred_at=CONFIRMED_AT,
        recorded_at=CONFIRMED_AT,
        response_sha256="a" * 64,
        broker_order_id=BROKER_ORDER_ID,
    )


def order_state(
    attempt: CanonicalSubmissionAttempt,
    authorization: BatchRiskAuthorization,
    events: tuple[BrokerOrderEvent, ...],
) -> CanonicalOrderState:
    submission = create_order_submission(
        intent=attempt.preparation.intent,
        risk_decision_id=authorization.decision_id,
        submission_attempt_id=attempt.attempt_id,
        submitted_at=SUBMITTED_AT,
    )
    return reduce_order_lifecycle(submission=submission, broker_events=events)


def broker_event(
    *,
    order_id: str,
    sequence: int,
    kind: BrokerOrderEventKind,
    execution_id: str | None = None,
    revision: int | None = None,
    supersedes: str | None = None,
    quantity: Decimal | None = None,
    reason: str | None = None,
    occurred_at: datetime | None = None,
) -> BrokerOrderEvent:
    occurred_at = occurred_at or CONFIRMED_AT + timedelta(seconds=sequence)
    return BrokerOrderEvent(
        event_id=f"reservation-event-{sequence}-{kind.value}",
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


def test_release_reason_vocabulary_and_projection_construction_are_closed() -> None:
    assert {reason.value for reason in ReservationReleaseReason} == {
        "approval_expired_unsent",
        "broker_rejected",
        "execution_accounted",
        "reconciled_terminal",
        "simulation_horizon_final",
    }
    with pytest.raises(TypeError, match="finality reducer"):
        ReservationReleaseFact()


def test_expired_approval_releases_only_with_complete_unsent_evidence() -> None:
    decision, reservation, authorization = approved_case()
    active = project_reservation_capacity(reservation)

    assert active.state is ReservationCapacityState.ACTIVE
    assert active.remaining_cash == authorization.reserved_cash
    with pytest.raises(ReservationLifecycleError, match="before its exact expiry"):
        record_approval_expired_unsent_release(
            reservation=reservation,
            authorization=authorization,
            parent_attempts=(),
            finality_reference="complete-attempt-snapshot-early",
            observed_at=RISK_EXPIRES_AT - timedelta(microseconds=1),
            recorded_at=RISK_EXPIRES_AT,
        )

    prepared = pending_attempt(decision=decision)
    for unretired in (
        prepared,
        in_flight_attempt(decision=decision),
        unknown_attempt(decision=decision),
        confirmed_attempt(decision=decision),
    ):
        with pytest.raises(ReservationLifecycleError, match="unretired prepared or sent order"):
            record_approval_expired_unsent_release(
                reservation=reservation,
                authorization=authorization,
                parent_attempts=(unretired,),
                finality_reference="complete-attempt-snapshot-sent",
                observed_at=RISK_EXPIRES_AT,
                recorded_at=RISK_EXPIRES_AT,
            )

    abandoned = _abandon_pending_submission(
        prepared,
        occurred_at=prepared.as_of + timedelta(seconds=1),
        recorded_at=prepared.as_of + timedelta(seconds=1),
        error_class="RecoveredPreparedWithoutDispatch",
    )

    release = record_approval_expired_unsent_release(
        reservation=reservation,
        authorization=authorization,
        parent_attempts=(abandoned,),
        finality_reference="complete-attempt-snapshot-unsent",
        observed_at=RISK_EXPIRES_AT,
        recorded_at=RISK_EXPIRES_AT + timedelta(seconds=1),
    )
    projection = project_reservation_capacity(reservation, (release,))

    assert release.reason is ReservationReleaseReason.APPROVAL_EXPIRED_UNSENT
    assert release.order_id is release.attempt_id is release.order_event_id is None
    assert projection.state is ReservationCapacityState.RELEASED
    assert projection.remaining_authorization_count == 0
    assert projection.remaining_cash == projection.remaining_buy_exposure == 0


def test_broker_rejection_is_bound_to_exact_attempt_order_and_event() -> None:
    decision, reservation, authorization = approved_case()
    attempt = confirmed_attempt(decision=decision)
    submitted = order_state(attempt, authorization, ())
    rejected = broker_event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=BrokerOrderEventKind.REJECTED,
        reason="broker rejected order",
    )
    rejected_state = order_state(attempt, authorization, (rejected,))
    release = record_broker_rejected_release(
        reservation=reservation,
        authorization=authorization,
        attempt=attempt,
        order_state=rejected_state,
        rejection_event=rejected,
        recorded_at=rejected.received_at,
    )

    assert release.reason is ReservationReleaseReason.BROKER_REJECTED
    assert release.order_id == rejected_state.submission.order_id
    assert release.attempt_id == attempt.attempt_id
    assert release.order_event_id == rejected.event_id
    assert release.source_sha256 == rejected.semantic_sha256
    assert project_reservation_capacity(reservation, (release,)).state is (
        ReservationCapacityState.RELEASED
    )

    mismatched_submission = replace(
        rejected_state.submission,
        risk_decision_id="another-authorization",
    )
    mismatched_state = reduce_order_lifecycle(
        submission=mismatched_submission,
        broker_events=(rejected,),
    )
    with pytest.raises(ReservationReleaseConflict, match="exact attempt and authorization"):
        record_broker_rejected_release(
            reservation=reservation,
            authorization=authorization,
            attempt=attempt,
            order_state=mismatched_state,
            rejection_event=rejected,
            recorded_at=rejected.received_at,
        )


def test_accounted_execution_and_upward_correction_release_only_monotone_capacity() -> None:
    decision, reservation, authorization = approved_case()
    attempt = confirmed_attempt(decision=decision)
    submitted = order_state(attempt, authorization, ())
    accepted = broker_event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=BrokerOrderEventKind.ACCEPTED,
    )
    execution = broker_event(
        order_id=submitted.submission.order_id,
        sequence=2,
        kind=BrokerOrderEventKind.EXECUTION,
        execution_id="execution-1",
        revision=1,
        quantity=Decimal("4"),
    )
    first_state = order_state(attempt, authorization, (accepted, execution))
    first_release = record_execution_accounted_release(
        reservation=reservation,
        authorization=authorization,
        attempt=attempt,
        order_state=first_state,
        execution_event=execution,
        accounting_reference="ledger-entry-execution-1-r1",
        accounting_source_sha256="b" * 64,
        accounted_at=execution.received_at + timedelta(milliseconds=1),
        recorded_at=execution.received_at + timedelta(milliseconds=1),
    )
    correction = broker_event(
        order_id=submitted.submission.order_id,
        sequence=3,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        execution_id="execution-1",
        revision=2,
        supersedes=execution.event_id,
        quantity=Decimal("6"),
    )
    corrected_state = order_state(
        attempt,
        authorization,
        (accepted, execution, correction),
    )
    correction_release = record_execution_accounted_release(
        reservation=reservation,
        authorization=authorization,
        attempt=attempt,
        order_state=corrected_state,
        execution_event=correction,
        accounting_reference="ledger-entry-execution-1-r2",
        accounting_source_sha256="c" * 64,
        accounted_at=correction.received_at + timedelta(milliseconds=1),
        recorded_at=correction.received_at + timedelta(milliseconds=1),
        prior_releases=(first_release,),
    )
    projection = project_reservation_capacity(
        reservation,
        (first_release, correction_release),
    )

    assert first_release.accounted_quantity == Decimal("4")
    assert correction_release.accounted_quantity == Decimal("2")
    assert correction_release.execution_head_quantity == Decimal("6")
    assert projection.state is ReservationCapacityState.PARTIALLY_RELEASED
    assert projection.released_cash == Decimal("606")
    assert projection.released_buy_exposure == Decimal("606")
    assert projection.remaining_cash == Decimal("405")
    assert projection.remaining_buy_exposure == Decimal("404")

    downward = broker_event(
        order_id=submitted.submission.order_id,
        sequence=4,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        execution_id="execution-1",
        revision=3,
        supersedes=correction.event_id,
        quantity=Decimal("3"),
    )
    downward_state = order_state(
        attempt,
        authorization,
        (accepted, execution, correction, downward),
    )
    with pytest.raises(ReservationLifecycleError, match="additional monotone capacity"):
        record_execution_accounted_release(
            reservation=reservation,
            authorization=authorization,
            attempt=attempt,
            order_state=downward_state,
            execution_event=downward,
            accounting_reference="ledger-entry-execution-1-r3",
            accounting_source_sha256="d" * 64,
            accounted_at=downward.received_at + timedelta(milliseconds=1),
            recorded_at=downward.received_at + timedelta(milliseconds=1),
            prior_releases=(first_release, correction_release),
        )


def test_sell_shares_and_fee_cash_are_conserved_until_final_simulation_horizon() -> None:
    sell_intent = replace(intent(), side=Side.SELL)
    decision, reservation, authorization = approved_case(sell_intent)
    attempt = confirmed_attempt(order_intent=sell_intent, decision=decision)
    submitted = order_state(attempt, authorization, ())
    accepted = broker_event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=BrokerOrderEventKind.ACCEPTED,
    )
    execution = broker_event(
        order_id=submitted.submission.order_id,
        sequence=2,
        kind=BrokerOrderEventKind.EXECUTION,
        execution_id="sell-execution-1",
        revision=1,
        quantity=Decimal("4"),
    )
    partial_state = order_state(attempt, authorization, (accepted, execution))
    partial_release = record_execution_accounted_release(
        reservation=reservation,
        authorization=authorization,
        attempt=attempt,
        order_state=partial_state,
        execution_event=execution,
        accounting_reference="sell-ledger-entry",
        accounting_source_sha256="e" * 64,
        accounted_at=execution.received_at,
        recorded_at=execution.received_at,
    )
    partial = project_reservation_capacity(reservation, (partial_release,))

    assert partial.released_cash == 0
    assert partial.sell_capacity[0].released_quantity == Decimal("4")
    assert partial.sell_capacity[0].remaining_quantity == Decimal("6")
    assert partial.remaining_cash == Decimal("1")

    horizon_at = partial_state.as_of + timedelta(seconds=1)
    final_release = record_simulation_horizon_final_release(
        reservation=reservation,
        authorization=authorization,
        attempt=attempt,
        order_state=partial_state,
        last_order_event=execution,
        horizon_reference="sealed-backtest-horizon",
        horizon_source_sha256="f" * 64,
        horizon_at=horizon_at,
        recorded_at=horizon_at,
        prior_releases=(partial_release,),
    )
    final = project_reservation_capacity(
        reservation,
        (partial_release, final_release),
    )

    assert final_release.released_cash == Decimal("1")
    assert final_release.released_sell_quantity == Decimal("6")
    assert final.state is ReservationCapacityState.RELEASED
    assert final.sell_capacity[0].remaining_quantity == 0


def test_cancel_and_local_terminal_state_do_not_authorize_release() -> None:
    decision, reservation, authorization = approved_case()
    attempt = confirmed_attempt(decision=decision)
    submitted = order_state(attempt, authorization, ())
    accepted = broker_event(
        order_id=submitted.submission.order_id,
        sequence=1,
        kind=BrokerOrderEventKind.ACCEPTED,
    )
    working = order_state(attempt, authorization, (accepted,))
    cancel = create_cancel_request(
        working,
        requested_at=working.as_of + timedelta(seconds=1),
        reason="user requested cancellation",
    )
    canceled_event = broker_event(
        order_id=submitted.submission.order_id,
        sequence=2,
        kind=BrokerOrderEventKind.CANCELED,
        occurred_at=cancel.requested_at + timedelta(seconds=1),
    )
    canceled = reduce_order_lifecycle(
        submission=working.submission,
        broker_events=(accepted, canceled_event),
        cancel_request=cancel,
    )

    reconciled_at = canceled.as_of + timedelta(seconds=1)
    with pytest.raises(ReservationLifecycleError, match="local terminal state alone"):
        record_reconciled_terminal_release(
            reservation=reservation,
            authorization=authorization,
            attempt=attempt,
            order_state=canceled,
            terminal_event=canceled_event,
            reconciliation_reference="local-cancel-view",
            reconciliation_source_sha256=canceled.semantic_sha256,
            reconciled_at=reconciled_at,
            recorded_at=reconciled_at,
        )

    release = record_reconciled_terminal_release(
        reservation=reservation,
        authorization=authorization,
        attempt=attempt,
        order_state=canceled,
        terminal_event=canceled_event,
        reconciliation_reference="broker-reconciliation-snapshot-7",
        reconciliation_source_sha256="1" * 64,
        reconciled_at=reconciled_at,
        recorded_at=reconciled_at,
    )
    assert release.reason is ReservationReleaseReason.RECONCILED_TERMINAL
    assert project_reservation_capacity(reservation, (release,)).state is (
        ReservationCapacityState.RELEASED
    )


def test_reconciled_not_submitted_uses_exact_unknown_resolution_source() -> None:
    decision, reservation, authorization = approved_case()
    unknown = unknown_attempt(decision=decision)
    resolved_at = unknown.as_of + timedelta(seconds=1)
    resolved = resolve_unknown_submission(
        unknown,
        occurred_at=resolved_at,
        recorded_at=resolved_at,
        resolution=UnknownSubmissionResolution.NOT_SUBMITTED,
        reconciliation_sha256="2" * 64,
    )

    with pytest.raises(ReservationReleaseConflict, match="attempt reconciliation source"):
        record_reconciled_terminal_release(
            reservation=reservation,
            authorization=authorization,
            attempt=resolved,
            order_state=None,
            terminal_event=None,
            reconciliation_reference="absence-reconciliation",
            reconciliation_source_sha256="3" * 64,
            reconciled_at=resolved_at,
            recorded_at=resolved_at,
        )

    release = record_reconciled_terminal_release(
        reservation=reservation,
        authorization=authorization,
        attempt=resolved,
        order_state=None,
        terminal_event=None,
        reconciliation_reference="absence-reconciliation",
        reconciliation_source_sha256="2" * 64,
        reconciled_at=resolved_at,
        recorded_at=resolved_at,
    )
    assert release.order_id is release.order_event_id is None
    assert release.attempt_id == resolved.attempt_id
    assert project_reservation_capacity(reservation, (release,)).state is (
        ReservationCapacityState.RELEASED
    )


def test_unknown_child_freezes_parent_without_releasing_its_capacity() -> None:
    intents = (sibling_intent(), intent())
    decision = risk_decision(intents)
    assert decision.reservation is not None
    reservation = decision.reservation
    released_child, unknown_child = reservation.authorizations
    release = record_approval_expired_unsent_release(
        reservation=reservation,
        authorization=released_child,
        parent_attempts=(),
        finality_reference="complete-parent-attempt-snapshot",
        observed_at=RISK_EXPIRES_AT,
        recorded_at=RISK_EXPIRES_AT,
    )
    frozen = project_reservation_capacity(
        reservation,
        (release,),
        unknown_authorization_ids=frozenset({unknown_child.decision_id}),
    )

    assert frozen.state is ReservationCapacityState.FROZEN
    assert frozen.unknown_authorization_ids == (unknown_child.decision_id,)
    unknown_projection = next(
        child
        for child in frozen.authorizations
        if child.authorization_id == unknown_child.decision_id
    )
    assert unknown_projection.released_cash == 0
    assert unknown_projection.remaining_cash == unknown_child.reserved_cash

    unknown_release = record_approval_expired_unsent_release(
        reservation=reservation,
        authorization=unknown_child,
        parent_attempts=(),
        finality_reference="complete-parent-attempt-snapshot",
        observed_at=RISK_EXPIRES_AT,
        recorded_at=RISK_EXPIRES_AT + timedelta(seconds=1),
        prior_releases=(release,),
    )
    with pytest.raises(ReservationReleaseConflict, match="UNKNOWN authorization"):
        project_reservation_capacity(
            reservation,
            (release, unknown_release),
            unknown_authorization_ids=frozenset({unknown_child.decision_id}),
        )
