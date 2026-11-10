from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext

import pytest

from packages.adapters.broker.alpaca_paper import (
    create_alpaca_paper_submission_description,
)
from packages.domain.account_coordinator import (
    AccountFence,
    AccountFenceReceipt,
    AccountLease,
    _account_fence_receipt,
)
from packages.domain.batch_risk import (
    BATCH_RISK_RULES,
    BatchRiskAuthorization,
    BatchRiskDecision,
    BatchRiskDecisionStatus,
    BatchRiskReservation,
    initial_active_capacity_universe,
)
from packages.domain.identifiers import canonical_id
from packages.domain.models import DecisionStatus, OrderIntent, RiskRuleResult, Side
from packages.domain.risk import intent_payload_hash
from packages.domain.submission_attempt import (
    BlindResubmissionError,
    BrokerSubmissionRequest,
    CanonicalSubmissionAttempt,
    ParentBatchSubmissionBarrier,
    SubmissionAttemptError,
    SubmissionAttemptEvent,
    SubmissionAttemptPreparation,
    SubmissionAttemptState,
    UnknownSubmissionBarrier,
    UnknownSubmissionResolution,
    _abandon_pending_submission,
    confirm_submission,
    create_broker_submission_request,
    mark_submission_in_flight,
    mark_submission_unknown,
    prepare_submission_attempt,
    reduce_submission_attempt,
    require_parent_batch_submission_clear,
    resolve_unknown_submission,
    submission_barrier_for_parent,
)
from packages.domain.walking_thread import WalkingThread

EVALUATED_AT = datetime(2026, 7, 15, 13, 31, 5, tzinfo=UTC)
RECEIPT_AT = EVALUATED_AT + timedelta(seconds=1)
PREPARED_AT = EVALUATED_AT + timedelta(seconds=2)
RISK_EXPIRES_AT = EVALUATED_AT + timedelta(minutes=3)
FENCE_VALID_UNTIL = EVALUATED_AT + timedelta(minutes=2)
ACCOUNT_ID = "fixture-submission-account"


def intent() -> OrderIntent:
    return WalkingThread.run().intent


def sibling_intent() -> OrderIntent:
    source = intent()
    return replace(
        source,
        intent_id="sibling-intent-qqq",
        instrument_id="US-ETF-QQQ",
        symbol="QQQ",
        quantity=Decimal("2"),
        reference_price=Decimal("50"),
        decision_event_id="fixture-qqq-decision-event",
        reference_event_sha256="f" * 64,
    )


def fence_receipt(
    *,
    account_id: str = ACCOUNT_ID,
    validated_at: datetime = RECEIPT_AT,
    valid_until: datetime = FENCE_VALID_UNTIL,
    fencing_generation: int = 1,
) -> AccountFenceReceipt:
    lease = AccountLease(
        account_id=account_id,
        owner_id="worker-a",
        lease_id=f"lease-{account_id}",
        fencing_generation=fencing_generation,
        revision_number=1,
        previous_lease_sha256=None,
        acquired_at=EVALUATED_AT,
        heartbeat_at=EVALUATED_AT,
        expires_at=valid_until,
        policy_sha256="1" * 64,
    )
    return _account_fence_receipt(
        fence=AccountFence(
            account_id=lease.account_id,
            owner_id=lease.owner_id,
            lease_id=lease.lease_id,
            fencing_generation=lease.fencing_generation,
        ),
        validated_at=validated_at,
        valid_until=lease.expires_at,
        policy_sha256=lease.policy_sha256,
        lease_sha256=lease.semantic_sha256,
    )


def risk_decision(
    intents: tuple[OrderIntent, ...] | None = None,
    *,
    approved: bool = True,
) -> BatchRiskDecision:
    intents = intents or (intent(),)
    intent_batch_id = intents[0].intent_batch_id
    assert all(item.intent_batch_id == intent_batch_id for item in intents)
    intent_batch_sha256 = "2" * 64
    snapshot_sha256 = "3" * 64
    policy_sha256 = "4" * 64
    active_capacity_sha256 = initial_active_capacity_universe(ACCOUNT_ID).semantic_sha256
    decision_id = canonical_id(
        "batch-risk-decision",
        intent_batch_id,
        intent_batch_sha256,
        snapshot_sha256,
        active_capacity_sha256,
        policy_sha256,
        EVALUATED_AT,
    )
    reservation_id = canonical_id("batch-risk-reservation", decision_id)
    authorizations: list[BatchRiskAuthorization] = []
    if approved:
        for order_intent in sorted(intents, key=lambda item: item.instrument_id):
            maximum_execution_price = order_intent.reference_price + Decimal("1")
            maximum_fee = Decimal("1")
            buy_exposure = (
                order_intent.quantity * maximum_execution_price
                if order_intent.side is Side.BUY
                else Decimal(0)
            )
            sell_quantity = order_intent.quantity if order_intent.side is Side.SELL else Decimal(0)
            maximum_cash = buy_exposure + maximum_fee
            authorizations.append(
                BatchRiskAuthorization(
                    decision_id=canonical_id(
                        "batch-risk-authorization",
                        decision_id,
                        order_intent.intent_id,
                    ),
                    parent_decision_id=decision_id,
                    reservation_id=reservation_id,
                    intent_batch_id=intent_batch_id,
                    intent_batch_sha256=intent_batch_sha256,
                    snapshot_sha256=snapshot_sha256,
                    policy_sha256=policy_sha256,
                    session_sha256="5" * 64,
                    currency="USD",
                    intent_id=order_intent.intent_id,
                    intent_payload_hash=intent_payload_hash(order_intent),
                    status=DecisionStatus.APPROVED,
                    evaluated_at=EVALUATED_AT,
                    expires_at=RISK_EXPIRES_AT,
                    instrument_id=order_intent.instrument_id,
                    symbol=order_intent.symbol,
                    side=order_intent.side,
                    quantity=order_intent.quantity,
                    reference_price=order_intent.reference_price,
                    snapshot_as_of=order_intent.created_at,
                    reference_event_time=order_intent.decision_event_time,
                    maximum_execution_price=maximum_execution_price,
                    maximum_fee=maximum_fee,
                    maximum_cash_requirement=maximum_cash,
                    reserved_cash=maximum_cash,
                    reserved_sell_quantity=sell_quantity,
                    reserved_buy_exposure=buy_exposure,
                )
            )
    rules = tuple(
        RiskRuleResult(
            rule=rule,
            passed=approved or index > 0,
            observed="fixture",
            limit="fixture",
        )
        for index, rule in enumerate(BATCH_RISK_RULES)
    )
    authorization_tuple = tuple(authorizations)
    reservation = (
        BatchRiskReservation(
            reservation_id=reservation_id,
            parent_decision_id=decision_id,
            intent_batch_id=intent_batch_id,
            intent_batch_sha256=intent_batch_sha256,
            snapshot_sha256=snapshot_sha256,
            policy_sha256=policy_sha256,
            currency="USD",
            authorizations=authorization_tuple,
            reserved_cash=sum(
                (item.reserved_cash for item in authorization_tuple),
                start=Decimal(0),
            ),
            reserved_buy_exposure=sum(
                (item.reserved_buy_exposure for item in authorization_tuple),
                start=Decimal(0),
            ),
        )
        if approved
        else None
    )
    return BatchRiskDecision(
        decision_id=decision_id,
        intent_batch_id=intent_batch_id,
        intent_batch_sha256=intent_batch_sha256,
        account_id=ACCOUNT_ID,
        snapshot_version="fixture-snapshot-v1",
        snapshot_sha256=snapshot_sha256,
        active_capacity_sha256=active_capacity_sha256,
        policy_id="fixture-risk-policy",
        policy_version="1.0.0",
        policy_sha256=policy_sha256,
        currency="USD",
        status=(BatchRiskDecisionStatus.APPROVED if approved else BatchRiskDecisionStatus.REJECTED),
        evaluated_at=EVALUATED_AT,
        expires_at=RISK_EXPIRES_AT,
        intent_count=len(intents),
        rules=rules,
        reservation=reservation,
        authorizations=authorization_tuple,
    )


def broker_request(
    order_intent: OrderIntent | None = None,
    *,
    scale_quantity: bool = False,
    reverse_payload: bool = False,
) -> BrokerSubmissionRequest:
    order_intent = order_intent or intent()
    quantity = Decimal("10.0") if scale_quantity else order_intent.quantity
    items: list[tuple[str, object]] = [
        ("symbol", order_intent.symbol),
        ("side", order_intent.side.value),
        ("quantity", quantity),
        ("order_type", "market"),
        ("time_in_force", "day"),
    ]
    if reverse_payload:
        items.reverse()
    return create_broker_submission_request(
        intent=order_intent,
        adapter_id="fixture-broker",
        adapter_version="1.0.0",
        operation="submit_order",
        payload=dict(items),
    )


def pending_attempt(
    *,
    order_intent: OrderIntent | None = None,
    decision: BatchRiskDecision | None = None,
    receipt: AccountFenceReceipt | None = None,
    request: BrokerSubmissionRequest | None = None,
    parent_attempts: tuple[CanonicalSubmissionAttempt, ...] = (),
    prepared_at: datetime = PREPARED_AT,
) -> CanonicalSubmissionAttempt:
    order_intent = order_intent or intent()
    return prepare_submission_attempt(
        intent=order_intent,
        risk_decision=decision or risk_decision((order_intent,)),
        fence_receipt=receipt or fence_receipt(),
        request=request or broker_request(order_intent),
        prepared_at=prepared_at,
        recorded_at=prepared_at,
        parent_attempts=parent_attempts,
    )


def in_flight_attempt(
    *,
    order_intent: OrderIntent | None = None,
    decision: BatchRiskDecision | None = None,
) -> CanonicalSubmissionAttempt:
    return mark_submission_in_flight(
        pending_attempt(order_intent=order_intent, decision=decision),
        dispatch_fence_receipt=fence_receipt(validated_at=PREPARED_AT + timedelta(seconds=1)),
        occurred_at=PREPARED_AT + timedelta(seconds=1),
        recorded_at=PREPARED_AT + timedelta(seconds=1),
    )


def unknown_attempt(
    *,
    order_intent: OrderIntent | None = None,
    decision: BatchRiskDecision | None = None,
) -> CanonicalSubmissionAttempt:
    return mark_submission_unknown(
        in_flight_attempt(order_intent=order_intent, decision=decision),
        occurred_at=PREPARED_AT + timedelta(seconds=2),
        recorded_at=PREPARED_AT + timedelta(seconds=2),
        error_class="TransportTimeout",
    )


def test_preparation_is_deterministic_canonical_and_proof_constructed() -> None:
    first_request = broker_request(scale_quantity=True)
    second_request = broker_request(reverse_payload=True)
    first = pending_attempt(request=first_request)
    second = pending_attempt(request=second_request)

    assert first_request == second_request
    assert first == second
    assert first.state is SubmissionAttemptState.PENDING
    assert first.attempt_number == 1
    assert first.preparation.request.request_sha256 == first_request.semantic_sha256
    assert first.preparation.risk_decision_sha256 == risk_decision().semantic_sha256
    assert first.preparation.fence_receipt_sha256 == fence_receipt().semantic_sha256
    assert first.events[0].occurred_at == PREPARED_AT
    assert len(first.semantic_sha256) == 64
    with pytest.raises(TypeError, match="proof-constructed"):
        SubmissionAttemptPreparation()
    with pytest.raises(TypeError, match="lifecycle reducers"):
        SubmissionAttemptEvent()
    with pytest.raises(TypeError, match="reducer"):
        CanonicalSubmissionAttempt()
    with pytest.raises(TypeError, match="reducer-produced"):
        ParentBatchSubmissionBarrier()


def test_preparation_requires_exact_matching_intent_risk_fence_and_request() -> None:
    approved = risk_decision()
    changed_intent = replace(intent(), quantity=Decimal("11"))
    with pytest.raises(SubmissionAttemptError, match=r"authorization .* does not match"):
        pending_attempt(
            order_intent=changed_intent,
            decision=approved,
            request=broker_request(changed_intent),
        )
    with pytest.raises(SubmissionAttemptError, match="different account"):
        pending_attempt(receipt=fence_receipt(account_id="other-account"))

    request = broker_request()
    mismatched_request = BrokerSubmissionRequest(
        adapter_id=request.adapter_id,
        adapter_version=request.adapter_version,
        operation=request.operation,
        order_id="different-order",
        client_order_id=request.client_order_id,
        intent_payload_sha256=request.intent_payload_sha256,
        payload=request.payload,
    )
    with pytest.raises(SubmissionAttemptError, match="different order"):
        pending_attempt(request=mismatched_request)
    with pytest.raises(SubmissionAttemptError, match="approved batch risk"):
        pending_attempt(decision=risk_decision(approved=False))
    with pytest.raises(SubmissionAttemptError, match="current risk approval"):
        pending_attempt(
            receipt=fence_receipt(valid_until=RISK_EXPIRES_AT + timedelta(minutes=1)),
            prepared_at=RISK_EXPIRES_AT,
        )
    with pytest.raises(SubmissionAttemptError, match="timezone-aware"):
        pending_attempt(prepared_at=PREPARED_AT.replace(tzinfo=None))


def test_confirmed_lifecycle_is_strictly_pending_in_flight_confirmed() -> None:
    pending = pending_attempt()
    with pytest.raises(BlindResubmissionError, match="durable proof"):
        pending_attempt(
            prepared_at=PREPARED_AT + timedelta(seconds=1),
            parent_attempts=(pending,),
        )
    in_flight = mark_submission_in_flight(
        pending,
        dispatch_fence_receipt=fence_receipt(validated_at=PREPARED_AT + timedelta(seconds=1)),
        occurred_at=PREPARED_AT + timedelta(seconds=1),
        recorded_at=PREPARED_AT + timedelta(seconds=1),
    )
    confirmed = confirm_submission(
        in_flight,
        occurred_at=PREPARED_AT + timedelta(seconds=2),
        recorded_at=PREPARED_AT + timedelta(seconds=3),
        response_sha256="6" * 64,
        broker_order_id="broker-order-1",
    )

    assert tuple(event.state for event in confirmed.events) == (
        SubmissionAttemptState.PENDING,
        SubmissionAttemptState.IN_FLIGHT,
        SubmissionAttemptState.CONFIRMED,
    )
    assert confirmed.response_sha256 == "6" * 64
    assert confirmed.broker_order_id == "broker-order-1"
    assert confirmed.resolution is None
    assert confirmed.may_resubmit is False
    with pytest.raises(BlindResubmissionError, match="durable proof"):
        pending_attempt(
            prepared_at=PREPARED_AT + timedelta(seconds=4),
            parent_attempts=(confirmed,),
        )
    with pytest.raises(SubmissionAttemptError, match="invalid submission transition"):
        confirm_submission(
            pending,
            occurred_at=PREPARED_AT + timedelta(seconds=1),
            recorded_at=PREPARED_AT + timedelta(seconds=1),
            response_sha256="6" * 64,
            broker_order_id="broker-order-1",
        )
    with pytest.raises(SubmissionAttemptError, match="invalid submission transition"):
        mark_submission_unknown(
            confirmed,
            occurred_at=PREPARED_AT + timedelta(seconds=4),
            recorded_at=PREPARED_AT + timedelta(seconds=4),
            error_class="ImpossibleTimeout",
        )


def test_dispatch_uses_a_current_receipt_for_the_prepared_stable_fence() -> None:
    old_valid_until = PREPARED_AT + timedelta(seconds=1)
    pending = pending_attempt(receipt=fence_receipt(valid_until=old_valid_until))
    dispatch_at = old_valid_until + timedelta(seconds=1)
    renewed_receipt = fence_receipt(
        validated_at=dispatch_at,
        valid_until=FENCE_VALID_UNTIL,
    )
    in_flight = mark_submission_in_flight(
        pending,
        dispatch_fence_receipt=renewed_receipt,
        occurred_at=dispatch_at,
        recorded_at=dispatch_at,
    )

    assert in_flight.events[-1].dispatch_fence_receipt == renewed_receipt
    with pytest.raises(SubmissionAttemptError, match="prepared stable fence"):
        mark_submission_in_flight(
            pending,
            dispatch_fence_receipt=fence_receipt(
                validated_at=dispatch_at,
                fencing_generation=2,
            ),
            occurred_at=dispatch_at,
            recorded_at=dispatch_at,
        )
    with pytest.raises(SubmissionAttemptError, match="recorded before"):
        mark_submission_in_flight(
            pending,
            dispatch_fence_receipt=fence_receipt(validated_at=PREPARED_AT + timedelta(seconds=2)),
            occurred_at=PREPARED_AT + timedelta(seconds=2),
            recorded_at=PREPARED_AT + timedelta(seconds=1),
        )
    with pytest.raises(SubmissionAttemptError, match="lowercase SHA-256"):
        confirm_submission(
            in_flight_attempt(),
            occurred_at=PREPARED_AT + timedelta(seconds=2),
            recorded_at=PREPARED_AT + timedelta(seconds=2),
            response_sha256="NOT-A-DIGEST",
            broker_order_id="broker-order-1",
        )


def test_abandoned_pending_is_append_only_proven_unsent_and_retryable() -> None:
    pending = pending_attempt()
    abandoned_at = PREPARED_AT + timedelta(seconds=1)
    abandoned = _abandon_pending_submission(
        pending,
        occurred_at=abandoned_at,
        recorded_at=abandoned_at,
        error_class="RecoveredPreparedWithoutDispatch",
    )
    retry = pending_attempt(
        prepared_at=abandoned_at + timedelta(seconds=1),
        parent_attempts=(abandoned,),
    )

    assert abandoned.state is SubmissionAttemptState.ABANDONED
    assert abandoned.events[-1].dispatch_fence_receipt is None
    assert abandoned.events[-1].reconciliation_sha256 is None
    assert abandoned.may_resubmit is True
    assert retry.attempt_number == 2
    assert retry.order_id == abandoned.order_id
    with pytest.raises(SubmissionAttemptError, match="invalid submission transition"):
        mark_submission_in_flight(
            abandoned,
            dispatch_fence_receipt=fence_receipt(validated_at=abandoned_at + timedelta(seconds=2)),
            occurred_at=abandoned_at + timedelta(seconds=2),
            recorded_at=abandoned_at + timedelta(seconds=2),
        )


def test_unknown_blocks_parent_batch_until_reconciliation_proves_absence() -> None:
    unknown = unknown_attempt()
    barrier = submission_barrier_for_parent(
        parent_decision_id=unknown.parent_decision_id,
        attempts=(unknown,),
    )

    assert barrier.blocked is True
    assert barrier.unknown_attempt_ids == (unknown.attempt_id,)
    with pytest.raises(UnknownSubmissionBarrier, match="dispatch is fenced"):
        require_parent_batch_submission_clear(
            parent_decision_id=unknown.parent_decision_id,
            attempts=(unknown,),
        )
    with pytest.raises(UnknownSubmissionBarrier, match="dispatch is fenced"):
        pending_attempt(
            prepared_at=PREPARED_AT + timedelta(seconds=4),
            parent_attempts=(unknown,),
        )

    resolved = resolve_unknown_submission(
        unknown,
        occurred_at=PREPARED_AT + timedelta(seconds=3),
        recorded_at=PREPARED_AT + timedelta(seconds=3),
        resolution=UnknownSubmissionResolution.NOT_SUBMITTED,
        reconciliation_sha256="7" * 64,
    )
    clear = require_parent_batch_submission_clear(
        parent_decision_id=resolved.parent_decision_id,
        attempts=(resolved,),
    )
    retry = pending_attempt(
        prepared_at=PREPARED_AT + timedelta(seconds=4),
        parent_attempts=(resolved,),
    )

    assert clear.blocked is False
    assert resolved.may_resubmit is True
    assert resolved.unknown_error_class == "TransportTimeout"
    assert retry.attempt_number == 2
    assert retry.order_id == resolved.order_id
    assert retry.preparation.client_order_id == resolved.preparation.client_order_id
    assert retry.attempt_id != resolved.attempt_id


def test_unknown_in_one_member_blocks_sibling_dispatch_across_parent_batch() -> None:
    first_intent = intent()
    second_intent = sibling_intent()
    decision = risk_decision((first_intent, second_intent))
    unknown = unknown_attempt(order_intent=first_intent, decision=decision)

    with pytest.raises(UnknownSubmissionBarrier, match="parent batch"):
        pending_attempt(
            order_intent=second_intent,
            decision=decision,
            request=broker_request(second_intent),
            prepared_at=PREPARED_AT + timedelta(seconds=3),
            parent_attempts=(unknown,),
        )


@pytest.mark.parametrize(
    ("resolution", "response_sha256", "broker_order_id", "may_resubmit"),
    [
        (UnknownSubmissionResolution.NOT_SUBMITTED, None, None, True),
        (UnknownSubmissionResolution.BROKER_ACCEPTED, "8" * 64, "broker-order-2", False),
        (UnknownSubmissionResolution.BROKER_REJECTED, "9" * 64, None, False),
    ],
)
def test_unknown_resolution_shapes_are_explicit_and_only_absence_allows_retry(
    resolution: UnknownSubmissionResolution,
    response_sha256: str | None,
    broker_order_id: str | None,
    may_resubmit: bool,
) -> None:
    resolved = resolve_unknown_submission(
        unknown_attempt(),
        occurred_at=PREPARED_AT + timedelta(seconds=3),
        recorded_at=PREPARED_AT + timedelta(seconds=3),
        resolution=resolution,
        reconciliation_sha256="a" * 64,
        response_sha256=response_sha256,
        broker_order_id=broker_order_id,
    )

    assert resolved.state is SubmissionAttemptState.RESOLVED
    assert resolved.resolution is resolution
    assert resolved.may_resubmit is may_resubmit
    if not may_resubmit:
        with pytest.raises(BlindResubmissionError, match="durable proof"):
            pending_attempt(
                prepared_at=PREPARED_AT + timedelta(seconds=4),
                parent_attempts=(resolved,),
            )


def test_resolution_cannot_invent_or_omit_broker_evidence() -> None:
    unknown = unknown_attempt()

    with pytest.raises(SubmissionAttemptError, match="accepted unknown"):
        resolve_unknown_submission(
            unknown,
            occurred_at=PREPARED_AT + timedelta(seconds=3),
            recorded_at=PREPARED_AT + timedelta(seconds=3),
            resolution=UnknownSubmissionResolution.BROKER_ACCEPTED,
            reconciliation_sha256="a" * 64,
        )
    with pytest.raises(SubmissionAttemptError, match="confirmed absence"):
        resolve_unknown_submission(
            unknown,
            occurred_at=PREPARED_AT + timedelta(seconds=3),
            recorded_at=PREPARED_AT + timedelta(seconds=3),
            resolution=UnknownSubmissionResolution.NOT_SUBMITTED,
            reconciliation_sha256="a" * 64,
            response_sha256="b" * 64,
        )
    with pytest.raises(SubmissionAttemptError, match="rejected unknown"):
        resolve_unknown_submission(
            unknown,
            occurred_at=PREPARED_AT + timedelta(seconds=3),
            recorded_at=PREPARED_AT + timedelta(seconds=3),
            resolution=UnknownSubmissionResolution.BROKER_REJECTED,
            reconciliation_sha256="a" * 64,
        )


def test_reducer_rejects_reordered_or_cross_attempt_event_history() -> None:
    first = in_flight_attempt()

    with pytest.raises(SubmissionAttemptError, match="sequence must be contiguous"):
        reduce_submission_attempt(first.preparation, tuple(reversed(first.events)))
    source_request = broker_request()
    other_request = BrokerSubmissionRequest(
        adapter_id=source_request.adapter_id,
        adapter_version=source_request.adapter_version,
        operation=source_request.operation,
        order_id=source_request.order_id,
        client_order_id=source_request.client_order_id,
        intent_payload_sha256=source_request.intent_payload_sha256,
        payload={**source_request.payload, "route": "alternate"},
    )
    other = pending_attempt(request=other_request)
    with pytest.raises(SubmissionAttemptError, match="another attempt"):
        reduce_submission_attempt(first.preparation, (other.events[0],))
    with pytest.raises(SubmissionAttemptError, match="immutable exact events"):
        reduce_submission_attempt(first.preparation, [*first.events])  # type: ignore[arg-type]


def test_request_is_bounded_immutable_and_strictly_typed() -> None:
    request = broker_request()

    assert request.payload["quantity"] == Decimal("10")
    with pytest.raises(TypeError):
        request.payload["quantity"] = Decimal("11")  # type: ignore[index]
    with pytest.raises(SubmissionAttemptError, match="exact Decimal"):
        create_broker_submission_request(
            intent=intent(),
            adapter_id="fixture-broker",
            adapter_version="1",
            operation="submit_order",
            payload={"quantity": 10.0},
        )
    with pytest.raises(SubmissionAttemptError, match="field count"):
        create_broker_submission_request(
            intent=intent(),
            adapter_id="fixture-broker",
            adapter_version="1",
            operation="submit_order",
            payload={},
        )


def test_alpaca_description_composes_only_as_pending_submission_evidence() -> None:
    order_intent = intent()
    description = create_alpaca_paper_submission_description(order_intent)

    pending = pending_attempt(
        order_intent=order_intent,
        request=description.request,
    )

    assert pending.preparation.intent == description.intent
    assert pending.preparation.request == description.request
    assert pending.state is SubmissionAttemptState.PENDING
    assert tuple(event.state for event in pending.events) == (SubmissionAttemptState.PENDING,)
    assert pending.events[0].dispatch_fence_receipt is None
    assert description.trading_effect_authorized is False


def test_digests_ignore_ambient_decimal_context() -> None:
    decision = risk_decision()
    receipt = fence_receipt()
    with localcontext() as decimal_context:
        decimal_context.prec = 3
        low_precision = pending_attempt(
            decision=decision,
            receipt=receipt,
            request=broker_request(scale_quantity=True),
        )
    with localcontext() as decimal_context:
        decimal_context.prec = 40
        high_precision = pending_attempt(
            decision=decision,
            receipt=receipt,
            request=broker_request(scale_quantity=False),
        )

    assert low_precision == high_precision
    assert low_precision.semantic_sha256 == high_precision.semantic_sha256
