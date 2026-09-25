"""Pure daily attempt validation; no persistence, delivery token or provider effects."""

from __future__ import annotations

from datetime import datetime, timedelta

from packages.domain.account_coordinator import AccountFenceReceipt
from packages.domain.accounting_contracts import AccountSnapshot
from packages.domain.daily_attempt_contracts import (
    MAX_DAILY_ATTEMPT_EVENTS,
    CanonicalDailyAttempt,
    DailyActivationRecord,
    DailyAttemptEvent,
    DailyAttemptPreparation,
    DailyAttemptTransition,
    DailyDispatchRecord,
    DailyFenceReference,
    DailyVenueSubmissionRequest,
)
from packages.domain.daily_risk import evaluate_daily_risk
from packages.domain.daily_runtime_contracts import (
    DailyRuntimeRiskEvidence,
    RuntimeCommitmentBinding,
    RuntimeRiskAdmission,
)
from packages.domain.engine_contracts import DailyRiskDecision
from packages.domain.models import Side
from packages.domain.personal_contracts import require_utc
from packages.domain.reconciliation_contracts import ReconciliationHeads
from packages.domain.stateful_venue_contracts import VenueSourceReference
from packages.domain.submission_attempt import SubmissionAttemptState


def daily_fence_reference(receipt: AccountFenceReceipt) -> DailyFenceReference:
    """Extract wire provenance from an actual receipt without reconstructing that proof."""
    if type(receipt) is not AccountFenceReceipt:
        raise ValueError("actual coordinator receipt required")
    receipt._validate()
    return DailyFenceReference(
        fence=receipt.fence,
        validated_at=receipt.validated_at,
        valid_until=receipt.valid_until,
        policy_sha256=receipt.policy_sha256,
        lease_sha256=receipt.lease_sha256,
        original_receipt_sha256=receipt.semantic_sha256,
    )


def require_daily_fence_match(reference: DailyFenceReference, receipt: AccountFenceReceipt) -> None:
    """Compare provenance to a coordinator-supplied proof; this comparison samples no clock."""
    if type(reference) is not DailyFenceReference or reference != daily_fence_reference(receipt):
        raise ValueError("daily fence provenance differs from the actual receipt")


def prepare_daily_attempt(
    *,
    request: DailyVenueSubmissionRequest,
    original_admission: RuntimeRiskAdmission,
    admission_source: VenueSourceReference,
    original_hold: RuntimeCommitmentBinding,
    prepared_at: datetime,
) -> DailyAttemptPreparation:
    return DailyAttemptPreparation(
        request=request,
        original_admission=original_admission,
        admission_source=admission_source,
        original_hold=original_hold,
        prepared_at=prepared_at,
    )


def prepare_daily_activation(
    *,
    preparation: DailyAttemptPreparation,
    current_hold: RuntimeCommitmentBinding,
    snapshot: AccountSnapshot,
    evidence: DailyRuntimeRiskEvidence,
    decision: DailyRiskDecision,
    heads: ReconciliationHeads,
    fence: DailyFenceReference,
    checked_at: datetime,
) -> DailyActivationRecord:
    """Recompute activation risk; replacing its reserve remains a separate atomic obligation."""
    for value, cls in (
        (preparation, DailyAttemptPreparation),
        (current_hold, RuntimeCommitmentBinding),
        (snapshot, AccountSnapshot),
        (evidence, DailyRuntimeRiskEvidence),
        (decision, DailyRiskDecision),
        (heads, ReconciliationHeads),
        (fence, DailyFenceReference),
    ):
        if type(value) is not cls:
            raise ValueError("daily activation requires exact immutable records")
    require_utc(checked_at, "activation check")
    preparation.__post_init__()
    original, current = preparation.original_hold.commitment, current_hold.commitment
    if (
        current_hold.account_id != preparation.request.source_account_id
        or current_hold.origin != "daily_runtime"
        or current_hold.original_policy_sha256 != preparation.original_hold.original_policy_sha256
        or current.commitment_id != original.commitment_id
        or current.intent_id != original.intent_id
        or current.order_id != original.order_id
        or current.instrument_id != original.instrument_id
        or current.symbol != original.symbol
        or current.side is not original.side
        or current.original_quantity != original.original_quantity
        or current.remaining_quantity != original.remaining_quantity
        or current.filled_quantity != 0
        or current.policy_sha256 != original.policy_sha256
        or current.snapshot_sha256 != original.snapshot_sha256
        or current.created_sequence != original.created_sequence
        or current.source_session != original.source_session
        or current.execution_session != original.execution_session
        or current.not_before != original.not_before
        or current.expires_at != original.expires_at
        or current.state != "approved_unsent"
        or current.activated_at is not None
        or current.activation_sequence is not None
        or current.activation_frontier is not None
        or current.terminal_reason is not None
        or snapshot.commitments.count(current) != 1
        or evidence.inputs.obligations.bindings.count(current_hold) != 1
    ):
        raise ValueError("activation changed original unsent hold identity or current inventory")
    original_batch = preparation.original_admission.decision.batch
    if (
        evidence.phase != "activation"
        or evidence.assignment.account_binding_sha256
        != preparation.request.source_account_binding_sha256
        or evidence.assignment.account_id != preparation.request.source_account_id
        or evidence.inputs.heads != heads
        or decision.batch.target != original_batch.target
        or preparation.request.submission.intent not in decision.batch.intents
        or any(intent not in original_batch.intents for intent in decision.batch.intents)
        or not preparation.prepared_at <= fence.validated_at <= checked_at
    ):
        raise ValueError("activation changed admission, intent, account, heads or time scope")
    recomputed = evaluate_daily_risk(
        evidence.assignment.policy, snapshot, decision.batch, evidence, checked_at
    )
    if decision != recomputed or not decision.approved:
        raise ValueError("daily activation risk did not independently approve")
    required_ids = (
        {intent.instrument_id for intent in decision.batch.intents}
        | {item.instrument_id for item in snapshot.positions if item.quantity != 0}
        | {
            item.instrument_id
            for item in snapshot.commitments
            if item.side is Side.BUY and item.remaining_quantity > 0
        }
    )
    expiry = min(
        fence.valid_until,
        current.expires_at,
        decision.batch.target.expires_at,
        snapshot.point.knowledge_at + timedelta(seconds=5),
        *(source.valid_until for source in evidence.inputs.sources),
        *(
            mark.economic_at + timedelta(seconds=5)
            for mark in snapshot.marks
            if mark.instrument_id in required_ids
        ),
    )
    for source in evidence.inputs.sources:
        if source.spec.role == "clock":
            expiry = min(expiry, source.source_at + timedelta(seconds=30))
        elif source.spec.role == "quotes":
            expiry = min(
                expiry,
                source.source_at + timedelta(seconds=5),
                source.received_at + timedelta(seconds=1),
            )
    reconciliation = evidence.inputs.reconciliation
    if reconciliation is not None:
        expiry = min(
            expiry,
            reconciliation.observation_started_at + timedelta(seconds=60),
            reconciliation.completed_at + timedelta(seconds=60),
            reconciliation.observation_received_through + timedelta(seconds=60),
        )
    return DailyActivationRecord(
        preparation_sha256=preparation.semantic_sha256,
        request_sha256=preparation.request.semantic_sha256,
        current_hold=current_hold,
        snapshot=snapshot,
        evidence=evidence,
        decision=decision,
        heads=heads,
        fence=fence,
        checked_at=checked_at,
        expires_at=expiry,
    )


def prepare_daily_dispatch(
    *,
    attempt: CanonicalDailyAttempt,
    activation: DailyActivationRecord,
    command_id: str,
    dispatched_at: datetime,
) -> DailyDispatchRecord:
    if type(attempt) is not CanonicalDailyAttempt or type(activation) is not DailyActivationRecord:
        raise ValueError("dispatch requires exact attempt and activation records")
    attempt.__post_init__()
    if attempt.state is not SubmissionAttemptState.PENDING:
        raise ValueError("one first send is allowed only from pending")
    recomputed = prepare_daily_activation(
        preparation=attempt.preparation,
        current_hold=activation.current_hold,
        snapshot=activation.snapshot,
        evidence=activation.evidence,
        decision=activation.decision,
        heads=activation.heads,
        fence=activation.fence,
        checked_at=activation.checked_at,
    )
    if activation != recomputed:
        raise ValueError("dispatch activation is not the exact recomputed record")
    return DailyDispatchRecord(
        command_id=command_id,
        preparation=attempt.preparation,
        activation=activation,
        previous_attempt_sha256=attempt.semantic_sha256,
        dispatched_at=dispatched_at,
    )


def _validate_daily_history(
    preparation: DailyAttemptPreparation, events: tuple[DailyAttemptEvent, ...]
) -> None:
    if type(preparation) is not DailyAttemptPreparation or type(events) is not tuple:
        raise ValueError("daily attempt requires exact immutable history")
    preparation.__post_init__()
    if not 1 <= len(events) <= MAX_DAILY_ATTEMPT_EVENTS:
        raise ValueError("daily attempt history exceeds its bound")
    transitions = {
        SubmissionAttemptState.PENDING: (
            SubmissionAttemptState.IN_FLIGHT,
            SubmissionAttemptState.ABANDONED,
        ),
        SubmissionAttemptState.IN_FLIGHT: (
            SubmissionAttemptState.CONFIRMED,
            SubmissionAttemptState.UNKNOWN,
        ),
        SubmissionAttemptState.UNKNOWN: (SubmissionAttemptState.RESOLVED,),
    }
    dispatched = None
    for index, event in enumerate(events):
        if type(event) is not DailyAttemptEvent:
            raise ValueError("daily history contains an unsupported event")
        event.__post_init__()
        previous = None if index == 0 else events[index - 1]
        if (
            event.attempt_id != preparation.attempt_id
            or event.sequence != index + 1
            or event.previous_event_sha256
            != (None if previous is None else previous.semantic_sha256)
            or event.recorded_at
            < (preparation.prepared_at if previous is None else previous.recorded_at)
        ):
            raise ValueError("daily event identity, predecessor or recording time differs")
        if previous is None:
            if event.state is not SubmissionAttemptState.PENDING:
                raise ValueError("daily history must begin pending")
        elif event.state not in transitions.get(previous.state, ()):
            raise ValueError("daily attempt cannot retry, reopen or skip lifecycle states")
        if event.dispatch is not None:
            prefix = CanonicalDailyAttempt(preparation=preparation, events=events[:index])
            record = event.dispatch.record
            expected = prepare_daily_dispatch(
                attempt=prefix,
                activation=record.activation,
                command_id=record.command_id,
                dispatched_at=record.dispatched_at,
            )
            if (
                record != expected
                or record.dispatched_at > event.recorded_at
                or event.recorded_at >= record.activation.expires_at
            ):
                raise ValueError("in-flight event differs from its exact first-send claim")
            dispatched = record
        if event.outcome is not None:
            outcome, request = event.outcome, preparation.request
            intent = request.submission.intent
            if (
                dispatched is None
                or not dispatched.dispatched_at <= outcome.observed_at <= event.recorded_at
                or outcome.scope.account_id != request.venue_account_id
                or outcome.scope.binding_sha256 != request.venue_model.semantic_sha256_ref
                or outcome.order.order_id != request.submission.order_id
                or outcome.order.instrument_id != intent.instrument_id
                or outcome.order.symbol != intent.symbol
                or outcome.order.side is not intent.side
                or outcome.order.quantity != intent.quantity
            ):
                raise ValueError("observed outcome is not bound to this dispatched venue order")
        if event.unsent_proof is not None:
            proof = event.unsent_proof
            prefix = CanonicalDailyAttempt(preparation=preparation, events=events[:index])
            if (
                dispatched is not None
                or proof.account_id != preparation.request.source_account_id
                or proof.attempt_id != preparation.attempt_id
                or proof.request_sha256 != preparation.request.semantic_sha256
                or proof.attempt_history_sha256 != prefix.semantic_sha256
                or proof.commitment_sha256 != preparation.original_hold.commitment.semantic_sha256
                or not prefix.events[-1].recorded_at
                <= proof.checked_at
                <= event.recorded_at
                < proof.fence.valid_until
                or (
                    proof.reason == "expired"
                    and proof.checked_at < preparation.original_hold.commitment.expires_at
                )
            ):
                raise ValueError("abandonment is not the exact unsent history proof")


def reduce_daily_attempt(
    preparation: DailyAttemptPreparation, events: tuple[DailyAttemptEvent, ...]
) -> CanonicalDailyAttempt:
    if type(events) is not tuple or len(events) > MAX_DAILY_ATTEMPT_EVENTS:
        raise ValueError("daily attempt replay requires bounded immutable events")
    by_sequence: dict[int, DailyAttemptEvent] = {}
    for event in events:
        if type(event) is not DailyAttemptEvent:
            raise ValueError("daily attempt event type differs")
        if event.sequence in by_sequence and by_sequence[event.sequence] != event:
            raise ValueError("daily attempt event sequence conflicts")
        by_sequence[event.sequence] = event
    return CanonicalDailyAttempt(
        preparation=preparation, events=tuple(by_sequence[key] for key in sorted(by_sequence))
    )


def advance_daily_attempt(
    attempt: CanonicalDailyAttempt, event: DailyAttemptEvent
) -> DailyAttemptTransition:
    if type(attempt) is not CanonicalDailyAttempt or type(event) is not DailyAttemptEvent:
        raise ValueError("daily advance requires exact immutable records")
    attempt.__post_init__()
    if event.sequence <= len(attempt.events):
        if attempt.events[event.sequence - 1] != event:
            raise ValueError("immutable daily attempt event retry conflicts")
        return DailyAttemptTransition(attempt=attempt, disposition="idempotent")
    return DailyAttemptTransition(
        attempt=reduce_daily_attempt(attempt.preparation, (*attempt.events, event)),
        disposition="applied",
    )
