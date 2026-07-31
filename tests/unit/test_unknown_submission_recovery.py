from __future__ import annotations

from copy import copy
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone

import pytest

from packages.domain.account_coordinator import (
    AccountFence,
    AccountFenceReceipt,
    AccountLease,
    _account_fence_receipt,
)
from packages.domain.broker_ingress import BrokerIngressDelivery
from packages.domain.broker_request_budget import BrokerRequestPurpose
from packages.domain.submission_attempt import (
    SubmissionAttemptEvent,
    SubmissionAttemptState,
    _create_event,
)
from packages.domain.unknown_submission_recovery import (
    UNKNOWN_SUBMISSION_LOOKUP_OPERATION,
    UNKNOWN_SUBMISSION_RECOVERY_CONTRACT_VERSION,
    UNKNOWN_SUBMISSION_RECOVERY_HORIZON,
    UNKNOWN_SUBMISSION_RECOVERY_OFFSETS_SECONDS,
    RecoveryScheduleOutcome,
    UnknownSubmissionRecoveryConflict,
    UnknownSubmissionRecoveryError,
    UnknownSubmissionRecoveryEvaluation,
    UnknownSubmissionRecoveryPlan,
    UnknownSubmissionRecoverySlot,
    UnknownSubmissionRecoveryTicket,
    create_unknown_submission_recovery_demand,
    create_unknown_submission_recovery_plan,
    evaluate_unknown_submission_recovery,
)

ACCOUNT_ID = "alpaca-paper-account"
ATTEMPT_ID = "phase4j-attempt-001"
ATTEMPT_SHA256 = "a" * 64
LOOKUP_CORRELATION_SHA256 = "b" * 64
CLIENT_ORDER_ID = "aqt-phase4j-client-order"
DISPATCH_AT = datetime(2026, 7, 27, 14, 30, tzinfo=UTC)
UNKNOWN_COMMITTED_AT = DISPATCH_AT + timedelta(seconds=5)


def dispatch_receipt() -> AccountFenceReceipt:
    lease = AccountLease(
        account_id=ACCOUNT_ID,
        owner_id="phase4j-worker",
        lease_id="phase4j-dispatch-lease",
        fencing_generation=1,
        revision_number=1,
        previous_lease_sha256=None,
        acquired_at=DISPATCH_AT,
        heartbeat_at=DISPATCH_AT,
        expires_at=DISPATCH_AT + timedelta(minutes=3),
        policy_sha256="c" * 64,
    )
    return _account_fence_receipt(
        fence=AccountFence(
            account_id=lease.account_id,
            owner_id=lease.owner_id,
            lease_id=lease.lease_id,
            fencing_generation=lease.fencing_generation,
        ),
        validated_at=DISPATCH_AT,
        valid_until=lease.expires_at,
        policy_sha256=lease.policy_sha256,
        lease_sha256=lease.semantic_sha256,
    )


def source_events(
    *,
    attempt_id: str = ATTEMPT_ID,
    unknown_recorded_at: datetime = UNKNOWN_COMMITTED_AT,
) -> tuple[SubmissionAttemptEvent, SubmissionAttemptEvent]:
    in_flight = _create_event(
        attempt_id=attempt_id,
        sequence_number=2,
        state=SubmissionAttemptState.IN_FLIGHT,
        occurred_at=DISPATCH_AT,
        recorded_at=DISPATCH_AT,
        previous_event_sha256="d" * 64,
        dispatch_fence_receipt=dispatch_receipt(),
    )
    unknown = _create_event(
        attempt_id=attempt_id,
        sequence_number=3,
        state=SubmissionAttemptState.UNKNOWN,
        occurred_at=unknown_recorded_at,
        recorded_at=unknown_recorded_at,
        previous_event_sha256=in_flight.semantic_sha256,
        error_class="TransportTimeout",
    )
    return in_flight, unknown


def plan(
    *,
    attempt_sha256: str = ATTEMPT_SHA256,
    lookup_correlation_sha256: str = LOOKUP_CORRELATION_SHA256,
    client_order_id: str = CLIENT_ORDER_ID,
    unknown_recorded_at: datetime = UNKNOWN_COMMITTED_AT,
) -> UnknownSubmissionRecoveryPlan:
    in_flight, unknown = source_events(unknown_recorded_at=unknown_recorded_at)
    return create_unknown_submission_recovery_plan(
        account_id=ACCOUNT_ID,
        client_order_id=client_order_id,
        attempt_sha256=attempt_sha256,
        in_flight_event=in_flight,
        unknown_event=unknown,
        lookup_correlation_sha256=lookup_correlation_sha256,
    )


def test_v1_plan_binds_exact_sources_and_freezes_reviewed_bounded_offsets() -> None:
    first = plan()
    replay = plan()
    in_flight, unknown = source_events()

    assert UNKNOWN_SUBMISSION_RECOVERY_CONTRACT_VERSION in first.canonical_json
    assert timedelta(seconds=60) == UNKNOWN_SUBMISSION_RECOVERY_HORIZON
    assert UNKNOWN_SUBMISSION_RECOVERY_OFFSETS_SECONDS == (1, 2, 4, 8, 16, 32)
    assert first == replay
    assert first.plan_id == replay.plan_id
    assert first.semantic_sha256 == replay.semantic_sha256
    assert len(first.plan_id) == 64
    assert len(first.semantic_sha256) == 64
    assert first.account_id == ACCOUNT_ID
    assert first.attempt_id == ATTEMPT_ID
    assert first.attempt_sha256 == ATTEMPT_SHA256
    assert first.client_order_id == CLIENT_ORDER_ID
    assert first.lookup_correlation_sha256 == LOOKUP_CORRELATION_SHA256
    assert first.in_flight_event_id == in_flight.event_id
    assert first.in_flight_event_sha256 == in_flight.semantic_sha256
    assert first.in_flight_sequence_number == 2
    assert first.in_flight_occurred_at == DISPATCH_AT
    assert first.in_flight_recorded_at == DISPATCH_AT
    assert first.unknown_event_id == unknown.event_id
    assert first.unknown_event_sha256 == unknown.semantic_sha256
    assert first.unknown_sequence_number == 3
    assert first.unknown_occurred_at == UNKNOWN_COMMITTED_AT
    assert first.unknown_recorded_at == UNKNOWN_COMMITTED_AT
    assert first.recovery_deadline_at == DISPATCH_AT + timedelta(seconds=60)
    assert first.slot_count == 6
    assert tuple(slot.ordinal for slot in first.slots) == (1, 2, 3, 4, 5, 6)
    assert tuple(slot.offset_seconds for slot in first.slots) == (1, 2, 4, 8, 16, 32)
    assert tuple(slot.scheduled_at for slot in first.slots) == tuple(
        UNKNOWN_COMMITTED_AT + timedelta(seconds=offset)
        for offset in UNKNOWN_SUBMISSION_RECOVERY_OFFSETS_SECONDS
    )
    assert len({slot.slot_id for slot in first.slots}) == 6
    assert all(len(slot.slot_id) == 64 for slot in first.slots)
    assert all(slot.plan_id == first.plan_id for slot in first.slots)
    assert all(slot.scheduled_at < first.recovery_deadline_at for slot in first.slots)
    with pytest.raises(FrozenInstanceError):
        first.account_id = "other"  # type: ignore[misc]
    with pytest.raises(TypeError, match="recovery planner"):
        UnknownSubmissionRecoveryPlan()
    with pytest.raises(TypeError, match="recovery planner"):
        UnknownSubmissionRecoverySlot()
    with pytest.raises(TypeError, match="scheduler evaluation"):
        UnknownSubmissionRecoveryTicket()
    with pytest.raises(TypeError, match="scheduler"):
        UnknownSubmissionRecoveryEvaluation()


@pytest.mark.parametrize(
    ("unknown_offset_seconds", "expected_offsets"),
    [
        (5, (1, 2, 4, 8, 16, 32)),
        (44, (1, 2, 4, 8)),
        (58, (1,)),
        (59, ()),
        (60, ()),
        (61, ()),
    ],
)
def test_slots_are_clipped_strictly_before_dispatch_plus_sixty_seconds(
    unknown_offset_seconds: int,
    expected_offsets: tuple[int, ...],
) -> None:
    recovery_plan = plan(
        unknown_recorded_at=DISPATCH_AT + timedelta(seconds=unknown_offset_seconds)
    )

    assert tuple(slot.offset_seconds for slot in recovery_plan.slots) == expected_offsets
    assert all(
        slot.scheduled_at < DISPATCH_AT + timedelta(seconds=60) for slot in recovery_plan.slots
    )
    if expected_offsets:
        assert recovery_plan.slots[0].scheduled_at == (
            recovery_plan.unknown_recorded_at + timedelta(seconds=1)
        )


@pytest.mark.parametrize(
    ("evaluated_at", "expected_outcome"),
    [
        (
            DISPATCH_AT + timedelta(seconds=59),
            RecoveryScheduleOutcome.WAITING,
        ),
        (
            DISPATCH_AT + timedelta(seconds=60),
            RecoveryScheduleOutcome.EXHAUSTED,
        ),
        (
            DISPATCH_AT + timedelta(seconds=61),
            RecoveryScheduleOutcome.EXHAUSTED,
        ),
    ],
)
def test_zero_slot_plan_waits_before_and_exhausts_at_or_after_deadline(
    evaluated_at: datetime,
    expected_outcome: RecoveryScheduleOutcome,
) -> None:
    recovery_plan = plan(unknown_recorded_at=DISPATCH_AT + timedelta(seconds=59))
    assert recovery_plan.slots == ()

    evaluation = evaluate_unknown_submission_recovery(
        plan=recovery_plan,
        evaluated_at=evaluated_at,
    )

    assert evaluation.outcome is expected_outcome
    assert evaluation.selected_ticket is None
    assert evaluation.latest_due_slot_id is None
    assert evaluation.coalesced_slot_ids == ()
    assert evaluation.remaining_slot_ids == ()
    assert evaluation.next_slot_id is None
    assert evaluation.next_scheduled_at is None


def test_missed_slots_coalesce_to_latest_due_without_a_catch_up_burst() -> None:
    recovery_plan = plan()

    waiting = evaluate_unknown_submission_recovery(
        plan=recovery_plan,
        evaluated_at=UNKNOWN_COMMITTED_AT,
    )
    first_due = evaluate_unknown_submission_recovery(
        plan=recovery_plan,
        evaluated_at=UNKNOWN_COMMITTED_AT + timedelta(seconds=1),
    )
    delayed = evaluate_unknown_submission_recovery(
        plan=recovery_plan,
        evaluated_at=UNKNOWN_COMMITTED_AT + timedelta(seconds=7),
    )

    assert waiting.outcome is RecoveryScheduleOutcome.WAITING
    assert waiting.selected_ticket is None
    assert waiting.latest_due_slot_id is None
    assert waiting.next_slot_id == recovery_plan.slots[0].slot_id
    assert waiting.next_scheduled_at == recovery_plan.slots[0].scheduled_at
    assert first_due.outcome is RecoveryScheduleOutcome.DUE
    assert first_due.selected_ticket is not None
    assert first_due.selected_ticket.slot_id == recovery_plan.slots[0].slot_id
    assert first_due.coalesced_slot_ids == ()
    assert delayed.outcome is RecoveryScheduleOutcome.DUE
    assert delayed.selected_ticket is not None
    assert delayed.selected_ticket.slot_id == recovery_plan.slots[2].slot_id
    assert delayed.coalesced_slot_ordinals == (1, 2)
    assert delayed.coalesced_slot_ids == tuple(slot.slot_id for slot in recovery_plan.slots[:2])
    assert delayed.coalesced_slot_sha256s == tuple(
        slot.semantic_sha256 for slot in recovery_plan.slots[:2]
    )

    after_latest_consumed = evaluate_unknown_submission_recovery(
        plan=recovery_plan,
        evaluated_at=UNKNOWN_COMMITTED_AT + timedelta(seconds=7),
        consumed_slot_ids=(recovery_plan.slots[2].slot_id,),
    )

    assert after_latest_consumed.outcome is RecoveryScheduleOutcome.WAITING
    assert after_latest_consumed.selected_ticket is None
    assert after_latest_consumed.coalesced_slot_ordinals == (1, 2)
    assert after_latest_consumed.next_slot_id == recovery_plan.slots[3].slot_id
    assert after_latest_consumed.next_scheduled_at == recovery_plan.slots[3].scheduled_at


def test_consumed_latest_slot_never_reopens_an_earlier_missed_slot() -> None:
    recovery_plan = plan()
    third = recovery_plan.slots[2]
    fourth = recovery_plan.slots[3]

    before_fourth = evaluate_unknown_submission_recovery(
        plan=recovery_plan,
        evaluated_at=fourth.scheduled_at - timedelta(microseconds=1),
        consumed_slot_ids=(third.slot_id,),
    )
    at_fourth = evaluate_unknown_submission_recovery(
        plan=recovery_plan,
        evaluated_at=fourth.scheduled_at,
        consumed_slot_ids=(third.slot_id,),
    )

    assert before_fourth.outcome is RecoveryScheduleOutcome.WAITING
    assert before_fourth.selected_ticket is None
    assert before_fourth.latest_due_slot_id == third.slot_id
    assert before_fourth.coalesced_slot_ordinals == (1, 2)
    assert at_fourth.outcome is RecoveryScheduleOutcome.DUE
    assert at_fourth.selected_ticket is not None
    assert at_fourth.selected_ticket.slot_id == fourth.slot_id
    assert at_fourth.coalesced_slot_ordinals == (1, 2)


def test_attempting_every_slot_stays_waiting_until_strict_horizon_exhaustion() -> None:
    recovery_plan = plan()
    all_slot_ids = tuple(slot.slot_id for slot in recovery_plan.slots)
    before_deadline = recovery_plan.recovery_deadline_at - timedelta(microseconds=1)

    waiting = evaluate_unknown_submission_recovery(
        plan=recovery_plan,
        evaluated_at=before_deadline,
        consumed_slot_ids=tuple(reversed(all_slot_ids)),
    )
    exhausted = evaluate_unknown_submission_recovery(
        plan=recovery_plan,
        evaluated_at=recovery_plan.recovery_deadline_at,
        consumed_slot_ids=all_slot_ids,
    )

    assert waiting.outcome is RecoveryScheduleOutcome.WAITING
    assert waiting.consumed_slot_ids == all_slot_ids
    assert waiting.selected_ticket is None
    assert waiting.next_slot_id is None
    assert waiting.terminal is False
    assert exhausted.outcome is RecoveryScheduleOutcome.EXHAUSTED
    assert exhausted.selected_ticket is None
    assert exhausted.coalesced_slot_ids == ()
    assert exhausted.remaining_slot_ids == ()
    assert exhausted.terminal is True


def test_horizon_exhaustion_surfaces_every_unconsumed_slot_without_dispatch() -> None:
    recovery_plan = plan()
    consumed = (recovery_plan.slots[1].slot_id, recovery_plan.slots[3].slot_id)

    exhausted = evaluate_unknown_submission_recovery(
        plan=recovery_plan,
        evaluated_at=recovery_plan.recovery_deadline_at,
        consumed_slot_ids=consumed,
    )
    expected_remaining = tuple(
        slot for slot in recovery_plan.slots if slot.slot_id not in set(consumed)
    )

    assert exhausted.outcome is RecoveryScheduleOutcome.EXHAUSTED
    assert exhausted.latest_due_slot_id == recovery_plan.slots[-1].slot_id
    assert exhausted.selected_ticket is None
    assert exhausted.next_slot_id is None
    assert exhausted.next_scheduled_at is None
    assert exhausted.coalesced_slot_ordinals == tuple(slot.ordinal for slot in expected_remaining)
    assert exhausted.coalesced_slot_ids == tuple(slot.slot_id for slot in expected_remaining)
    assert exhausted.remaining_slot_ids == exhausted.coalesced_slot_ids


def test_ticket_reconstructs_stable_phase4i_demand_and_raw_delivery_identity() -> None:
    recovery_plan = plan()
    evaluated_at = UNKNOWN_COMMITTED_AT + timedelta(seconds=7)
    first = evaluate_unknown_submission_recovery(
        plan=recovery_plan,
        evaluated_at=evaluated_at,
    )
    replay = evaluate_unknown_submission_recovery(
        plan=recovery_plan,
        evaluated_at=evaluated_at,
    )
    assert first.selected_ticket is not None
    assert replay.selected_ticket is not None
    ticket = first.selected_ticket

    assert ticket == replay.selected_ticket
    assert ticket.ticket_id == replay.selected_ticket.ticket_id
    assert ticket.semantic_sha256 == replay.selected_ticket.semantic_sha256
    assert len(ticket.ticket_id) == 64
    assert len(ticket.demand_id) == 64
    assert len(ticket.delivery_id) == 64
    assert ticket.scheduled_at == recovery_plan.slots[2].scheduled_at
    assert ticket.recovery_deadline_at == recovery_plan.recovery_deadline_at
    assert ticket.demand_idempotency_key.startswith("phase4j-demand-")
    assert ticket.delivery_idempotency_key.startswith("phase4j-delivery-")
    assert len(ticket.demand_idempotency_key) <= 128
    assert len(ticket.delivery_idempotency_key) <= 128

    scheduled_demand = create_unknown_submission_recovery_demand(
        ticket=ticket,
        requested_at=ticket.scheduled_at,
    )
    delayed_demand = create_unknown_submission_recovery_demand(
        ticket=ticket,
        requested_at=evaluated_at,
    )
    assert scheduled_demand.demand_id == ticket.demand_id
    assert delayed_demand.demand_id == ticket.demand_id
    assert delayed_demand.semantic_sha256 != scheduled_demand.semantic_sha256
    assert delayed_demand.account_id == ACCOUNT_ID
    assert delayed_demand.idempotency_key == ticket.demand_idempotency_key
    assert delayed_demand.operation == UNKNOWN_SUBMISSION_LOOKUP_OPERATION
    assert delayed_demand.purpose is BrokerRequestPurpose.UNKNOWN_LOOKUP
    assert delayed_demand.correlation_sha256 == LOOKUP_CORRELATION_SHA256
    ingress = BrokerIngressDelivery(
        account_id=ACCOUNT_ID,
        delivery_idempotency_key=ticket.delivery_idempotency_key,
        provider_id="alpaca",
        adapter_version="phase4a-alpaca-paper-v1",
        environment="paper",
        channel="trading_api",
        operation="lookup_order_by_client_order_id",
        correlation_sha256=LOOKUP_CORRELATION_SHA256,
        transport_status=404,
        provider_request_id="request-phase4j",
        media_type="application/json",
        received_at=evaluated_at,
        recorded_at=evaluated_at,
        body=b"{}",
    )
    assert ingress.receipt_id == ticket.delivery_id

    with pytest.raises(UnknownSubmissionRecoveryError, match="precede"):
        create_unknown_submission_recovery_demand(
            ticket=ticket,
            requested_at=ticket.scheduled_at - timedelta(microseconds=1),
        )
    with pytest.raises(UnknownSubmissionRecoveryError, match="at or after"):
        create_unknown_submission_recovery_demand(
            ticket=ticket,
            requested_at=ticket.recovery_deadline_at,
        )


def test_all_scheduler_evidence_and_terminal_outcomes_are_non_authorizing() -> None:
    recovery_plan = plan()
    due = evaluate_unknown_submission_recovery(
        plan=recovery_plan,
        evaluated_at=recovery_plan.slots[0].scheduled_at,
    )
    exhausted = evaluate_unknown_submission_recovery(
        plan=recovery_plan,
        evaluated_at=recovery_plan.recovery_deadline_at,
    )
    assert due.selected_ticket is not None

    assert recovery_plan.transport_authorized is False
    assert recovery_plan.attempt_resolution_authorized is False
    assert recovery_plan.resubmission_authorized is False
    assert all(slot.transport_authorized is False for slot in recovery_plan.slots)
    assert due.selected_ticket.transport_authorized is False
    assert due.selected_ticket.lookup_authorized is False
    assert due.selected_ticket.attempt_resolution_authorized is False
    assert due.selected_ticket.resubmission_authorized is False
    for evaluation in (due, exhausted):
        assert evaluation.transport_authorized is False
        assert evaluation.lookup_authorized is False
        assert evaluation.attempt_resolution_authorized is False
        assert evaluation.resubmission_authorized is False
        assert evaluation.lifecycle_mutation_authorized is False
    assert exhausted.terminal is True
    assert not hasattr(exhausted, "resolve")
    assert not hasattr(exhausted, "resubmit")


def test_plan_and_ticket_identities_change_with_immutable_source_semantics() -> None:
    baseline = plan()
    changed_attempt = plan(attempt_sha256="e" * 64)
    changed_correlation = plan(lookup_correlation_sha256="f" * 64)
    changed_client_order = plan(client_order_id="aqt-different-client-order")
    delayed_unknown = plan(unknown_recorded_at=UNKNOWN_COMMITTED_AT + timedelta(seconds=1))

    assert (
        len(
            {
                baseline.plan_id,
                changed_attempt.plan_id,
                changed_correlation.plan_id,
                changed_client_order.plan_id,
                delayed_unknown.plan_id,
            }
        )
        == 5
    )
    baseline_due = evaluate_unknown_submission_recovery(
        plan=baseline,
        evaluated_at=baseline.slots[0].scheduled_at,
    )
    changed_due = evaluate_unknown_submission_recovery(
        plan=changed_correlation,
        evaluated_at=changed_correlation.slots[0].scheduled_at,
    )
    assert baseline_due.selected_ticket is not None
    assert changed_due.selected_ticket is not None
    assert baseline_due.selected_ticket.ticket_id != changed_due.selected_ticket.ticket_id
    assert baseline_due.selected_ticket.demand_id != changed_due.selected_ticket.demand_id
    assert baseline_due.selected_ticket.delivery_id != changed_due.selected_ticket.delivery_id


def test_plan_rejects_noncanonical_or_cross_attempt_source_events() -> None:
    in_flight, unknown = source_events()
    cross_attempt_unknown = _create_event(
        attempt_id="other-attempt",
        sequence_number=3,
        state=SubmissionAttemptState.UNKNOWN,
        occurred_at=UNKNOWN_COMMITTED_AT,
        recorded_at=UNKNOWN_COMMITTED_AT,
        previous_event_sha256=in_flight.semantic_sha256,
        error_class="TransportTimeout",
    )
    wrong_predecessor_unknown = _create_event(
        attempt_id=ATTEMPT_ID,
        sequence_number=3,
        state=SubmissionAttemptState.UNKNOWN,
        occurred_at=UNKNOWN_COMMITTED_AT,
        recorded_at=UNKNOWN_COMMITTED_AT,
        previous_event_sha256="9" * 64,
        error_class="TransportTimeout",
    )
    confirmed = _create_event(
        attempt_id=ATTEMPT_ID,
        sequence_number=3,
        state=SubmissionAttemptState.CONFIRMED,
        occurred_at=UNKNOWN_COMMITTED_AT,
        recorded_at=UNKNOWN_COMMITTED_AT,
        previous_event_sha256=in_flight.semantic_sha256,
        response_sha256="8" * 64,
        broker_order_id="provider-order",
    )

    for candidate, message in (
        (cross_attempt_unknown, "does not chain"),
        (wrong_predecessor_unknown, "does not chain"),
        (confirmed, "IN_FLIGHT followed by UNKNOWN"),
    ):
        with pytest.raises(UnknownSubmissionRecoveryError, match=message):
            create_unknown_submission_recovery_plan(
                account_id=ACCOUNT_ID,
                client_order_id=CLIENT_ORDER_ID,
                attempt_sha256=ATTEMPT_SHA256,
                in_flight_event=in_flight,
                unknown_event=candidate,
                lookup_correlation_sha256=LOOKUP_CORRELATION_SHA256,
            )

    tampered = copy(unknown)
    object.__setattr__(tampered, "event_id", "tampered-event-id")
    with pytest.raises(UnknownSubmissionRecoveryConflict, match="not canonical"):
        create_unknown_submission_recovery_plan(
            account_id=ACCOUNT_ID,
            client_order_id=CLIENT_ORDER_ID,
            attempt_sha256=ATTEMPT_SHA256,
            in_flight_event=in_flight,
            unknown_event=tampered,
            lookup_correlation_sha256=LOOKUP_CORRELATION_SHA256,
        )
    with pytest.raises(UnknownSubmissionRecoveryConflict, match="dispatch fence"):
        create_unknown_submission_recovery_plan(
            account_id="different-account",
            client_order_id=CLIENT_ORDER_ID,
            attempt_sha256=ATTEMPT_SHA256,
            in_flight_event=in_flight,
            unknown_event=unknown,
            lookup_correlation_sha256=LOOKUP_CORRELATION_SHA256,
        )
    with pytest.raises(UnknownSubmissionRecoveryError, match="exact submission"):
        create_unknown_submission_recovery_plan(
            account_id=ACCOUNT_ID,
            client_order_id=CLIENT_ORDER_ID,
            attempt_sha256=ATTEMPT_SHA256,
            in_flight_event="in-flight",  # type: ignore[arg-type]
            unknown_event=unknown,
            lookup_correlation_sha256=LOOKUP_CORRELATION_SHA256,
        )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"account_id": " account"}, "trimmed"),
        ({"client_order_id": "x" * 129}, "unsupported"),
        ({"attempt_sha256": "A" * 64}, "lowercase SHA-256"),
        ({"lookup_correlation_sha256": "short"}, "lowercase SHA-256"),
    ],
)
def test_plan_inputs_are_strict_bounded_and_canonical(
    changes: dict[str, object],
    message: str,
) -> None:
    in_flight, unknown = source_events()
    values: dict[str, object] = {
        "account_id": ACCOUNT_ID,
        "client_order_id": CLIENT_ORDER_ID,
        "attempt_sha256": ATTEMPT_SHA256,
        "in_flight_event": in_flight,
        "unknown_event": unknown,
        "lookup_correlation_sha256": LOOKUP_CORRELATION_SHA256,
    }
    values.update(changes)

    with pytest.raises(UnknownSubmissionRecoveryError, match=message):
        create_unknown_submission_recovery_plan(**values)  # type: ignore[arg-type]


def test_evaluation_rejects_regressed_time_and_invalid_consumed_snapshot() -> None:
    recovery_plan = plan()
    first, second = recovery_plan.slots[:2]

    with pytest.raises(UnknownSubmissionRecoveryError, match="precede"):
        evaluate_unknown_submission_recovery(
            plan=recovery_plan,
            evaluated_at=recovery_plan.unknown_recorded_at - timedelta(microseconds=1),
        )
    with pytest.raises(UnknownSubmissionRecoveryError, match="immutable tuple"):
        evaluate_unknown_submission_recovery(
            plan=recovery_plan,
            evaluated_at=second.scheduled_at,
            consumed_slot_ids=[first.slot_id],  # type: ignore[arg-type]
        )
    with pytest.raises(UnknownSubmissionRecoveryConflict, match="unique"):
        evaluate_unknown_submission_recovery(
            plan=recovery_plan,
            evaluated_at=second.scheduled_at,
            consumed_slot_ids=(first.slot_id, first.slot_id),
        )
    with pytest.raises(UnknownSubmissionRecoveryConflict, match="exact plan"):
        evaluate_unknown_submission_recovery(
            plan=recovery_plan,
            evaluated_at=second.scheduled_at,
            consumed_slot_ids=("0" * 64,),
        )
    with pytest.raises(UnknownSubmissionRecoveryConflict, match="before it becomes"):
        evaluate_unknown_submission_recovery(
            plan=recovery_plan,
            evaluated_at=first.scheduled_at,
            consumed_slot_ids=(second.slot_id,),
        )
    with pytest.raises(UnknownSubmissionRecoveryError, match="exact recovery plan"):
        evaluate_unknown_submission_recovery(
            plan="plan",  # type: ignore[arg-type]
            evaluated_at=first.scheduled_at,
        )


def test_utc_is_exact_and_plan_tampering_fails_closed() -> None:
    recovery_plan = plan()
    non_utc = recovery_plan.unknown_recorded_at.astimezone(timezone(timedelta(hours=-4)))
    with pytest.raises(UnknownSubmissionRecoveryError, match="must be UTC"):
        evaluate_unknown_submission_recovery(
            plan=recovery_plan,
            evaluated_at=non_utc,
        )
    with pytest.raises(UnknownSubmissionRecoveryError, match="timezone-aware"):
        evaluate_unknown_submission_recovery(
            plan=recovery_plan,
            evaluated_at=recovery_plan.unknown_recorded_at.replace(tzinfo=None),
        )

    tampered = copy(recovery_plan)
    object.__setattr__(tampered, "plan_id", "0" * 64)
    with pytest.raises(UnknownSubmissionRecoveryConflict, match="canonically derived"):
        evaluate_unknown_submission_recovery(
            plan=tampered,
            evaluated_at=recovery_plan.unknown_recorded_at,
        )
