from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext
from itertools import permutations

import pytest

from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    CanonicalOrderStatus,
    OrderCancelRequest,
    OrderEventConflict,
    OrderLifecycleError,
    create_cancel_request,
    create_order_submission,
    reduce_order_lifecycle,
)
from packages.domain.walking_thread import WalkingThread

SUBMITTED_AT = datetime(2026, 7, 15, 13, 31, 5, tzinfo=UTC)
BROKER_ORDER_ID = "broker-order-1"


def submission():
    return create_order_submission(
        intent=WalkingThread.run().intent,
        risk_decision_id="risk-decision-1",
        submission_attempt_id="submission-attempt-1",
        submitted_at=SUBMITTED_AT,
    )


def broker_event(
    sequence: int,
    kind: BrokerOrderEventKind,
    *,
    event_id: str | None = None,
    execution_id: str | None = None,
    revision: int | None = None,
    supersedes: str | None = None,
    quantity: Decimal | None = None,
    price: Decimal | None = None,
    fee: Decimal | None = None,
    reason: str | None = None,
) -> BrokerOrderEvent:
    occurred_at = SUBMITTED_AT + timedelta(seconds=sequence)
    return BrokerOrderEvent(
        event_id=event_id or f"broker-event-{sequence}",
        order_id=submission().order_id,
        broker_order_id=BROKER_ORDER_ID,
        broker_sequence=sequence,
        occurred_at=occurred_at,
        received_at=occurred_at + timedelta(milliseconds=100),
        kind=kind,
        execution_id=execution_id,
        execution_revision=revision,
        supersedes_event_id=supersedes,
        quantity=quantity,
        price=price,
        fee=fee,
        reason=reason,
    )


def accepted() -> BrokerOrderEvent:
    return broker_event(1, BrokerOrderEventKind.ACCEPTED)


def execution(
    sequence: int,
    execution_id: str,
    quantity: str,
    *,
    price: str = "101",
    fee: str = "1",
) -> BrokerOrderEvent:
    return broker_event(
        sequence,
        BrokerOrderEventKind.EXECUTION,
        execution_id=execution_id,
        revision=1,
        quantity=Decimal(quantity),
        price=Decimal(price),
        fee=Decimal(fee),
    )


def correction(
    sequence: int,
    previous: BrokerOrderEvent,
    quantity: str,
    *,
    price: str = "101",
    fee: str = "1",
) -> BrokerOrderEvent:
    assert previous.execution_id is not None
    assert previous.execution_revision is not None
    return broker_event(
        sequence,
        BrokerOrderEventKind.EXECUTION_CORRECTION,
        execution_id=previous.execution_id,
        revision=previous.execution_revision + 1,
        supersedes=previous.event_id,
        quantity=Decimal(quantity),
        price=Decimal(price),
        fee=Decimal(fee),
    )


def test_submission_and_acceptance_are_deterministic_and_evidence_bound() -> None:
    submitted = reduce_order_lifecycle(submission=submission(), broker_events=())
    working = reduce_order_lifecycle(submission=submission(), broker_events=(accepted(),))

    assert submitted.status is CanonicalOrderStatus.SUBMITTED
    assert submitted.broker_order_id is None
    assert submitted.filled_quantity == 0
    assert working.status is CanonicalOrderStatus.WORKING
    assert working.broker_order_id == BROKER_ORDER_ID
    assert (
        working.submission.intent_payload_sha256
        == WalkingThread.run().risk_decision.intent_payload_hash
    )
    assert working.semantic_sha256 == replace(working).semantic_sha256


def test_partial_and_complete_fills_are_cumulative_and_permutation_invariant() -> None:
    events = (accepted(), execution(2, "execution-a", "4"), execution(3, "execution-b", "6"))
    expected = None

    for ordering in permutations(events):
        result = reduce_order_lifecycle(submission=submission(), broker_events=ordering)
        assert result.status is CanonicalOrderStatus.FILLED
        assert result.filled_quantity == Decimal("10")
        assert result.remaining_quantity == 0
        assert result.total_fees == Decimal("2")
        assert tuple(execution.execution_id for execution in result.executions) == (
            "execution-a",
            "execution-b",
        )
        if expected is None:
            expected = result
        else:
            assert result == expected
            assert result.semantic_sha256 == expected.semantic_sha256

    partial = reduce_order_lifecycle(
        submission=submission(),
        broker_events=(accepted(), execution(2, "execution-a", "4")),
    )
    assert partial.status is CanonicalOrderStatus.PARTIALLY_FILLED
    assert partial.remaining_quantity == Decimal("6")


def test_exact_duplicate_delivery_collapses_but_identity_and_sequence_conflicts_fail() -> None:
    event = accepted()
    deduplicated = reduce_order_lifecycle(
        submission=submission(),
        broker_events=(event, event),
    )
    assert deduplicated.broker_events == (event,)

    with pytest.raises(OrderEventConflict, match="identity"):
        reduce_order_lifecycle(
            submission=submission(),
            broker_events=(event, replace(event, broker_order_id="other")),
        )
    with pytest.raises(OrderEventConflict, match="sequence slot"):
        reduce_order_lifecycle(
            submission=submission(),
            broker_events=(event, replace(event, event_id="other-event")),
        )


def test_sequence_gaps_and_time_regressions_fail_closed() -> None:
    with pytest.raises(OrderLifecycleError, match="contiguous"):
        reduce_order_lifecycle(
            submission=submission(),
            broker_events=(accepted(), execution(3, "execution-a", "1")),
        )
    with pytest.raises(OrderLifecycleError, match="time cannot move backwards"):
        reduce_order_lifecycle(
            submission=submission(),
            broker_events=(
                accepted(),
                replace(
                    execution(2, "execution-a", "1"),
                    occurred_at=SUBMITTED_AT + timedelta(milliseconds=1),
                ),
            ),
        )


def test_cancel_requires_exact_local_request_and_late_fill_is_conserved() -> None:
    submitted = submission()
    working = reduce_order_lifecycle(submission=submitted, broker_events=(accepted(),))
    requested = create_cancel_request(
        working,
        requested_at=SUBMITTED_AT + timedelta(seconds=1, milliseconds=500),
        reason="target expired",
    )
    canceled = broker_event(2, BrokerOrderEventKind.CANCELED, reason="canceled")
    late_fill = execution(3, "execution-late", "3")

    with pytest.raises(OrderLifecycleError, match="local request"):
        reduce_order_lifecycle(
            submission=submitted,
            broker_events=(accepted(), canceled),
        )

    state = reduce_order_lifecycle(
        submission=submitted,
        cancel_request=requested,
        broker_events=(late_fill, canceled, accepted()),
    )
    assert state.status is CanonicalOrderStatus.CANCELED
    assert state.filled_quantity == Decimal("3")
    assert state.remaining_quantity == Decimal("7")
    assert state.executions[0].execution_id == "execution-late"


def test_execution_correction_replaces_exact_head_and_can_reopen_filled_order() -> None:
    initial = execution(2, "execution-a", "10", price="101", fee="2")
    corrected = correction(3, initial, "4", price="100", fee="1")
    state = reduce_order_lifecycle(
        submission=submission(),
        broker_events=(accepted(), corrected, initial),
    )

    assert state.status is CanonicalOrderStatus.PARTIALLY_FILLED
    assert state.filled_quantity == Decimal("4")
    assert state.total_fees == Decimal("1")
    assert state.executions[0].revision == 2
    assert state.executions[0].event_id == corrected.event_id
    assert state.executions[0].price == Decimal("100")

    wrong_predecessor = replace(corrected, supersedes_event_id="not-the-head")
    with pytest.raises(OrderLifecycleError, match="current head"):
        reduce_order_lifecycle(
            submission=submission(),
            broker_events=(accepted(), initial, wrong_predecessor),
        )


def test_execution_bust_after_cancel_preserves_canceled_terminal_state() -> None:
    submitted = submission()
    initial = execution(2, "execution-a", "4")
    partial = reduce_order_lifecycle(
        submission=submitted,
        broker_events=(accepted(), initial),
    )
    requested = create_cancel_request(
        partial,
        requested_at=SUBMITTED_AT + timedelta(seconds=2, milliseconds=500),
        reason="operator cancel",
    )
    canceled = broker_event(3, BrokerOrderEventKind.CANCELED, reason="canceled")
    busted = correction(4, initial, "0", fee="0")

    state = reduce_order_lifecycle(
        submission=submitted,
        cancel_request=requested,
        broker_events=(accepted(), initial, canceled, busted),
    )
    assert state.status is CanonicalOrderStatus.CANCELED
    assert state.filled_quantity == 0
    assert state.total_fees == 0


def test_cancel_request_rejects_terminal_or_stale_order_state() -> None:
    filled = reduce_order_lifecycle(
        submission=submission(),
        broker_events=(accepted(), execution(2, "execution-a", "10")),
    )
    with pytest.raises(OrderLifecycleError, match="terminal"):
        create_cancel_request(
            filled,
            requested_at=filled.as_of + timedelta(seconds=1),
            reason="too late",
        )
    direct_terminal_cancel = OrderCancelRequest(
        cancel_request_id="direct-terminal-cancel",
        order_id=filled.submission.order_id,
        prior_order_state_sha256=filled.semantic_sha256,
        requested_at=filled.as_of + timedelta(seconds=1),
        reason="too late",
    )
    with pytest.raises(OrderLifecycleError, match="terminal order state"):
        reduce_order_lifecycle(
            submission=filled.submission,
            cancel_request=direct_terminal_cancel,
            broker_events=filled.broker_events,
        )

    forged_state = replace(filled, status=CanonicalOrderStatus.WORKING)
    with pytest.raises(OrderLifecycleError, match="reducer-produced"):
        create_cancel_request(
            forged_state,
            requested_at=forged_state.as_of + timedelta(seconds=1),
            reason="forged",
        )

    working = reduce_order_lifecycle(submission=submission(), broker_events=(accepted(),))
    requested = create_cancel_request(
        working,
        requested_at=working.as_of + timedelta(seconds=1),
        reason="cancel",
    )
    forged = replace(requested, prior_order_state_sha256="0" * 64)
    with pytest.raises(OrderLifecycleError, match="exact prior"):
        reduce_order_lifecycle(
            submission=submission(),
            cancel_request=forged,
            broker_events=(accepted(),),
        )


def test_overfills_rejections_and_broker_identity_changes_fail_closed() -> None:
    with pytest.raises(OrderLifecycleError, match="exceeds"):
        reduce_order_lifecycle(
            submission=submission(),
            broker_events=(accepted(), execution(2, "execution-a", "11")),
        )
    with pytest.raises(OrderLifecycleError, match="rejection"):
        reduce_order_lifecycle(
            submission=submission(),
            broker_events=(
                accepted(),
                broker_event(2, BrokerOrderEventKind.REJECTED, reason="rejected"),
            ),
        )
    with pytest.raises(OrderEventConflict, match="identity changed"):
        reduce_order_lifecycle(
            submission=submission(),
            broker_events=(
                accepted(),
                replace(execution(2, "execution-a", "1"), broker_order_id="other"),
            ),
        )


def test_rejected_order_is_terminal_without_execution() -> None:
    rejected = broker_event(1, BrokerOrderEventKind.REJECTED, reason="venue rejected")
    state = reduce_order_lifecycle(submission=submission(), broker_events=(rejected,))
    assert state.status is CanonicalOrderStatus.REJECTED
    assert state.executions == ()

    with pytest.raises(OrderLifecycleError, match="rejected order"):
        reduce_order_lifecycle(
            submission=submission(),
            broker_events=(rejected, execution(2, "execution-a", "1")),
        )


def test_execution_arithmetic_is_independent_of_ambient_decimal_context() -> None:
    events = (
        accepted(),
        execution(2, "execution-a", "4", fee="1.123456789"),
        execution(3, "execution-b", "6", fee="2.876543211"),
    )

    with localcontext() as context:
        context.prec = 4
        low_precision = reduce_order_lifecycle(submission=submission(), broker_events=events)
    with localcontext() as context:
        context.prec = 40
        high_precision = reduce_order_lifecycle(submission=submission(), broker_events=events)

    assert low_precision == high_precision
    assert low_precision.total_fees == Decimal("4")
    assert low_precision.semantic_sha256 == high_precision.semantic_sha256
