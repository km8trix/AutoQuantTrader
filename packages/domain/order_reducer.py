"""Pure canonical order and execution lifecycle reduction."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from itertools import pairwise

from packages.domain.canonical import canonical_json_bytes, canonical_persisted_decimal
from packages.domain.decimal_math import exact_decimal_subtract, exact_decimal_sum
from packages.domain.identifiers import canonical_id
from packages.domain.models import OrderIntent, require_utc
from packages.domain.risk import intent_payload_hash

ORDER_REDUCER_CONTRACT_VERSION = "phase2-order-reducer-v1"


class OrderLifecycleError(ValueError):
    """Raised when order history violates the canonical lifecycle contract."""


class OrderEventConflict(OrderLifecycleError):
    """Raised when an event identity or broker sequence is reused inconsistently."""


class CanonicalOrderStatus(StrEnum):
    SUBMITTED = "submitted"
    WORKING = "working"
    PARTIALLY_FILLED = "partially_filled"
    FILLED = "filled"
    CANCELED = "canceled"
    REJECTED = "rejected"


class BrokerOrderEventKind(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    CANCELED = "canceled"
    EXECUTION = "execution"
    EXECUTION_CORRECTION = "execution_correction"


def _require_text(value: str, field_name: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise OrderLifecycleError(f"{field_name} must be a non-empty, trimmed string")


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise OrderLifecycleError(f"{field_name} must be a lowercase SHA-256 digest")


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _whole_quantity(value: Decimal, field_name: str, *, allow_zero: bool = False) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise OrderLifecycleError(f"{field_name} must be a finite exact Decimal")
    if value < 0 or (not allow_zero and value == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise OrderLifecycleError(f"{field_name} must be {qualifier}")
    if value != value.to_integral_value():
        raise OrderLifecycleError(f"{field_name} must be a whole number of shares")
    return canonical_persisted_decimal(value, field_name)


def _money(value: Decimal, field_name: str, *, allow_zero: bool = False) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise OrderLifecycleError(f"{field_name} must be a finite exact Decimal")
    if value < 0 or (not allow_zero and value == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise OrderLifecycleError(f"{field_name} must be {qualifier}")
    return canonical_persisted_decimal(value, field_name)


@dataclass(frozen=True, slots=True)
class OrderSubmission:
    order_id: str
    submission_attempt_id: str
    client_order_id: str
    risk_decision_id: str
    intent: OrderIntent
    intent_payload_sha256: str
    submitted_at: datetime

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.order_id, "order_id"),
            (self.submission_attempt_id, "submission_attempt_id"),
            (self.client_order_id, "client_order_id"),
            (self.risk_decision_id, "risk_decision_id"),
        ):
            _require_text(value, field_name)
        if type(self.intent) is not OrderIntent:
            raise OrderLifecycleError("submission intent must be an exact OrderIntent")
        _require_sha256(self.intent_payload_sha256, "intent_payload_sha256")
        if self.intent_payload_sha256 != intent_payload_hash(self.intent):
            raise OrderLifecycleError("submission intent payload digest does not match its intent")
        require_utc(self.submitted_at, "submitted_at")
        if self.submitted_at < self.intent.created_at:
            raise OrderLifecycleError("submission cannot precede intent creation")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ORDER_REDUCER_CONTRACT_VERSION,
                "submission",
                self.order_id,
                self.submission_attempt_id,
                self.client_order_id,
                self.risk_decision_id,
                self.intent.semantic_sha256,
                self.intent_payload_sha256,
                self.submitted_at,
            )
        )


def create_order_submission(
    *,
    intent: OrderIntent,
    risk_decision_id: str,
    submission_attempt_id: str,
    submitted_at: datetime,
) -> OrderSubmission:
    """Create immutable submission evidence from an authorized intent."""

    if type(intent) is not OrderIntent:
        raise OrderLifecycleError("submission requires an exact OrderIntent")
    order_id = canonical_id("order", intent.intent_id, intent_payload_hash(intent))
    return OrderSubmission(
        order_id=order_id,
        submission_attempt_id=submission_attempt_id,
        client_order_id=f"aqt-{order_id.replace('-', '')[:24]}",
        risk_decision_id=risk_decision_id,
        intent=intent,
        intent_payload_sha256=intent_payload_hash(intent),
        submitted_at=submitted_at,
    )


@dataclass(frozen=True, slots=True)
class OrderCancelRequest:
    cancel_request_id: str
    order_id: str
    prior_order_state_sha256: str
    requested_at: datetime
    reason: str

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.cancel_request_id, "cancel_request_id"),
            (self.order_id, "cancel order_id"),
            (self.reason, "cancel reason"),
        ):
            _require_text(value, field_name)
        _require_sha256(self.prior_order_state_sha256, "cancel prior_order_state_sha256")
        require_utc(self.requested_at, "cancel requested_at")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ORDER_REDUCER_CONTRACT_VERSION,
                "cancel_request",
                self.cancel_request_id,
                self.order_id,
                self.prior_order_state_sha256,
                self.requested_at,
                self.reason,
            )
        )


@dataclass(frozen=True, slots=True)
class BrokerOrderEvent:
    event_id: str
    order_id: str
    broker_order_id: str
    broker_sequence: int
    occurred_at: datetime
    received_at: datetime
    kind: BrokerOrderEventKind
    reason: str | None = None
    execution_id: str | None = None
    execution_revision: int | None = None
    supersedes_event_id: str | None = None
    quantity: Decimal | None = None
    price: Decimal | None = None
    fee: Decimal | None = None

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.event_id, "broker event_id"),
            (self.order_id, "broker event order_id"),
            (self.broker_order_id, "broker_order_id"),
        ):
            _require_text(value, field_name)
        if type(self.broker_sequence) is not int or self.broker_sequence < 1:
            raise OrderLifecycleError("broker_sequence must be a positive integer")
        require_utc(self.occurred_at, "broker event occurred_at")
        require_utc(self.received_at, "broker event received_at")
        if self.received_at < self.occurred_at:
            raise OrderLifecycleError("broker event cannot be received before it occurred")
        if not isinstance(self.kind, BrokerOrderEventKind):
            raise OrderLifecycleError("broker event kind is unsupported")
        if self.reason is not None:
            _require_text(self.reason, "broker event reason")
        if self.kind is BrokerOrderEventKind.REJECTED and self.reason is None:
            raise OrderLifecycleError("broker rejection requires a reason")

        execution_kind = self.kind in (
            BrokerOrderEventKind.EXECUTION,
            BrokerOrderEventKind.EXECUTION_CORRECTION,
        )
        execution_values = (
            self.execution_id,
            self.execution_revision,
            self.quantity,
            self.price,
            self.fee,
        )
        if not execution_kind:
            if any(value is not None for value in (*execution_values, self.supersedes_event_id)):
                raise OrderLifecycleError("non-execution broker event contains execution fields")
            return

        if self.execution_id is None:
            raise OrderLifecycleError("execution event requires execution_id")
        _require_text(self.execution_id, "execution_id")
        if type(self.execution_revision) is not int or self.execution_revision < 1:
            raise OrderLifecycleError("execution_revision must be a positive integer")
        if self.quantity is None or self.price is None or self.fee is None:
            raise OrderLifecycleError("execution event requires quantity, price, and fee")
        object.__setattr__(
            self,
            "quantity",
            _whole_quantity(
                self.quantity,
                "execution quantity",
                allow_zero=self.kind is BrokerOrderEventKind.EXECUTION_CORRECTION,
            ),
        )
        object.__setattr__(self, "price", _money(self.price, "execution price"))
        object.__setattr__(self, "fee", _money(self.fee, "execution fee", allow_zero=True))
        if self.kind is BrokerOrderEventKind.EXECUTION:
            if self.execution_revision != 1 or self.supersedes_event_id is not None:
                raise OrderLifecycleError(
                    "initial execution must be revision one without predecessor"
                )
        elif self.execution_revision == 1 or self.supersedes_event_id is None:
            raise OrderLifecycleError("execution correction requires a revision and predecessor")
        else:
            _require_text(self.supersedes_event_id, "superseded execution event_id")
        if self.supersedes_event_id == self.event_id:
            raise OrderLifecycleError("execution event cannot supersede itself")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ORDER_REDUCER_CONTRACT_VERSION,
                "broker_event",
                self.event_id,
                self.order_id,
                self.broker_order_id,
                self.broker_sequence,
                self.occurred_at,
                self.received_at,
                self.kind,
                self.reason,
                self.execution_id,
                self.execution_revision,
                self.supersedes_event_id,
                self.quantity,
                self.price,
                self.fee,
            )
        )


@dataclass(frozen=True, slots=True)
class ExecutionProjection:
    execution_id: str
    revision: int
    event_id: str
    quantity: Decimal
    price: Decimal
    fee: Decimal
    occurred_at: datetime
    received_at: datetime

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ORDER_REDUCER_CONTRACT_VERSION,
                "execution_projection",
                self.execution_id,
                self.revision,
                self.event_id,
                self.quantity,
                self.price,
                self.fee,
                self.occurred_at,
                self.received_at,
            )
        )


@dataclass(frozen=True, slots=True)
class CanonicalOrderState:
    submission: OrderSubmission
    cancel_request: OrderCancelRequest | None
    broker_order_id: str | None
    status: CanonicalOrderStatus
    broker_events: tuple[BrokerOrderEvent, ...]
    executions: tuple[ExecutionProjection, ...]
    filled_quantity: Decimal
    total_fees: Decimal
    last_broker_sequence: int
    as_of: datetime

    @property
    def remaining_quantity(self) -> Decimal:
        return exact_decimal_subtract(
            self.submission.intent.quantity,
            self.filled_quantity,
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ORDER_REDUCER_CONTRACT_VERSION,
                "order_state",
                self.submission.semantic_sha256,
                None if self.cancel_request is None else self.cancel_request.semantic_sha256,
                self.broker_order_id,
                self.status,
                tuple(event.semantic_sha256 for event in self.broker_events),
                tuple(execution.semantic_sha256 for execution in self.executions),
                self.filled_quantity,
                self.total_fees,
                self.last_broker_sequence,
                self.as_of,
            )
        )


def create_cancel_request(
    state: CanonicalOrderState,
    *,
    requested_at: datetime,
    reason: str,
) -> OrderCancelRequest:
    """Bind a cancel command to the exact non-terminal order projection observed."""

    if type(state) is not CanonicalOrderState:
        raise OrderLifecycleError("cancel requires an exact CanonicalOrderState")
    canonical_state = reduce_order_lifecycle(
        submission=state.submission,
        broker_events=state.broker_events,
        cancel_request=state.cancel_request,
    )
    if canonical_state != state:
        raise OrderLifecycleError("cancel requires a canonical reducer-produced order state")
    if state.cancel_request is not None:
        raise OrderLifecycleError("order already has a cancel request")
    if state.status in (
        CanonicalOrderStatus.FILLED,
        CanonicalOrderStatus.CANCELED,
        CanonicalOrderStatus.REJECTED,
    ):
        raise OrderLifecycleError("terminal order cannot be canceled")
    require_utc(requested_at, "cancel requested_at")
    if requested_at <= state.as_of:
        raise OrderLifecycleError("cancel request must follow the observed order state")
    return OrderCancelRequest(
        cancel_request_id=canonical_id(
            "cancel-request",
            state.submission.order_id,
            state.semantic_sha256,
            requested_at,
            reason,
        ),
        order_id=state.submission.order_id,
        prior_order_state_sha256=state.semantic_sha256,
        requested_at=requested_at,
        reason=reason,
    )


def _unique_broker_events(events: Iterable[BrokerOrderEvent]) -> tuple[BrokerOrderEvent, ...]:
    by_id: dict[str, BrokerOrderEvent] = {}
    by_sequence: dict[int, BrokerOrderEvent] = {}
    for event in events:
        if type(event) is not BrokerOrderEvent:
            raise OrderLifecycleError("broker history requires exact BrokerOrderEvent values")
        existing_id = by_id.get(event.event_id)
        if existing_id is not None:
            if existing_id != event:
                raise OrderEventConflict("broker event identity has conflicting semantics")
            continue
        existing_sequence = by_sequence.get(event.broker_sequence)
        if existing_sequence is not None:
            raise OrderEventConflict("broker sequence slot has conflicting events")
        by_id[event.event_id] = event
        by_sequence[event.broker_sequence] = event
    ordered = tuple(sorted(by_id.values(), key=lambda event: event.broker_sequence))
    if tuple(event.broker_sequence for event in ordered) != tuple(range(1, len(ordered) + 1)):
        raise OrderLifecycleError("broker event sequence must be contiguous from one")
    for previous, current in pairwise(ordered):
        if current.occurred_at < previous.occurred_at:
            raise OrderLifecycleError("broker event time cannot move backwards with sequence")
        if current.received_at < previous.received_at:
            raise OrderLifecycleError("broker receipt time cannot move backwards with sequence")
    return ordered


def reduce_order_lifecycle(
    *,
    submission: OrderSubmission,
    broker_events: Iterable[BrokerOrderEvent],
    cancel_request: OrderCancelRequest | None = None,
) -> CanonicalOrderState:
    """Rebuild one order from immutable submission, cancel, and broker facts."""

    if type(submission) is not OrderSubmission:
        raise OrderLifecycleError("order reduction requires an exact OrderSubmission")
    if cancel_request is not None:
        if type(cancel_request) is not OrderCancelRequest:
            raise OrderLifecycleError("order reduction requires an exact OrderCancelRequest")
        if cancel_request.order_id != submission.order_id:
            raise OrderLifecycleError("cancel request belongs to a different order")
        if cancel_request.requested_at < submission.submitted_at:
            raise OrderLifecycleError("cancel request cannot precede submission")

    ordered = _unique_broker_events(broker_events)
    if cancel_request is not None:
        prior_events = tuple(
            event for event in ordered if event.received_at < cancel_request.requested_at
        )
        prior_state = reduce_order_lifecycle(
            submission=submission,
            broker_events=prior_events,
        )
        if prior_state.semantic_sha256 != cancel_request.prior_order_state_sha256:
            raise OrderLifecycleError("cancel request is not bound to the exact prior order state")
        if cancel_request.requested_at <= prior_state.as_of:
            raise OrderLifecycleError("cancel request must follow the observed order state")
        if prior_state.status in (
            CanonicalOrderStatus.FILLED,
            CanonicalOrderStatus.CANCELED,
            CanonicalOrderStatus.REJECTED,
        ):
            raise OrderLifecycleError("cancel request cannot bind a terminal order state")
    broker_order_id: str | None = None
    accepted = False
    rejected = False
    canceled = False
    execution_heads: dict[str, BrokerOrderEvent] = {}

    for event in ordered:
        if event.order_id != submission.order_id:
            raise OrderLifecycleError("broker event belongs to a different order")
        if event.occurred_at < submission.submitted_at:
            raise OrderLifecycleError("broker event cannot precede submission")
        if broker_order_id is None:
            broker_order_id = event.broker_order_id
        elif broker_order_id != event.broker_order_id:
            raise OrderEventConflict("broker order identity changed within one order")

        if event.kind is BrokerOrderEventKind.ACCEPTED:
            if accepted or rejected or canceled:
                raise OrderLifecycleError("broker acceptance is invalid in the current lifecycle")
            accepted = True
        elif event.kind is BrokerOrderEventKind.REJECTED:
            if accepted or rejected or canceled or execution_heads:
                raise OrderLifecycleError("broker rejection cannot follow acceptance or execution")
            rejected = True
        elif event.kind is BrokerOrderEventKind.CANCELED:
            if rejected or canceled:
                raise OrderLifecycleError("broker cancellation is invalid in the current lifecycle")
            if cancel_request is None:
                raise OrderLifecycleError("broker cancellation requires an exact local request")
            if event.occurred_at < cancel_request.requested_at:
                raise OrderLifecycleError("broker cancellation cannot precede its local request")
            canceled = True
        elif event.kind is BrokerOrderEventKind.EXECUTION:
            assert event.execution_id is not None
            if rejected:
                raise OrderLifecycleError("rejected order cannot receive an execution")
            if event.execution_id in execution_heads:
                raise OrderEventConflict("execution identity already exists")
            execution_heads[event.execution_id] = event
        else:
            assert event.kind is BrokerOrderEventKind.EXECUTION_CORRECTION
            assert event.execution_id is not None
            previous = execution_heads.get(event.execution_id)
            if previous is None:
                raise OrderLifecycleError("execution correction has no known predecessor")
            assert previous.execution_revision is not None
            if event.execution_revision != previous.execution_revision + 1:
                raise OrderLifecycleError("execution correction revision is not contiguous")
            if event.supersedes_event_id != previous.event_id:
                raise OrderLifecycleError(
                    "execution correction does not supersede the current head"
                )
            execution_heads[event.execution_id] = event

        filled = exact_decimal_sum(
            head.quantity for head in execution_heads.values() if head.quantity is not None
        )
        if filled > submission.intent.quantity:
            raise OrderLifecycleError("cumulative execution quantity exceeds the order quantity")

    executions = tuple(
        ExecutionProjection(
            execution_id=execution_id,
            revision=event.execution_revision,
            event_id=event.event_id,
            quantity=event.quantity,
            price=event.price,
            fee=event.fee,
            occurred_at=event.occurred_at,
            received_at=event.received_at,
        )
        for execution_id, event in sorted(execution_heads.items())
        if event.execution_revision is not None
        and event.quantity is not None
        and event.price is not None
        and event.fee is not None
    )
    filled_quantity = exact_decimal_sum(execution.quantity for execution in executions)
    total_fees = exact_decimal_sum(execution.fee for execution in executions)
    if rejected:
        status = CanonicalOrderStatus.REJECTED
    elif filled_quantity == submission.intent.quantity:
        status = CanonicalOrderStatus.FILLED
    elif canceled:
        status = CanonicalOrderStatus.CANCELED
    elif filled_quantity > 0:
        status = CanonicalOrderStatus.PARTIALLY_FILLED
    elif accepted:
        status = CanonicalOrderStatus.WORKING
    else:
        status = CanonicalOrderStatus.SUBMITTED
    as_of_candidates = (
        submission.submitted_at,
        *(event.received_at for event in ordered),
        *(() if cancel_request is None else (cancel_request.requested_at,)),
    )
    as_of = max(as_of_candidates)
    return CanonicalOrderState(
        submission=submission,
        cancel_request=cancel_request,
        broker_order_id=broker_order_id,
        status=status,
        broker_events=ordered,
        executions=executions,
        filled_quantity=filled_quantity,
        total_fees=total_fees,
        last_broker_sequence=0 if not ordered else ordered[-1].broker_sequence,
        as_of=as_of,
    )
