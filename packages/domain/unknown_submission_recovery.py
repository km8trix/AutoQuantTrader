"""Pure, bounded scheduling contracts for UNKNOWN submission recovery.

The scheduler binds one immutable recovery plan to the exact durable
``IN_FLIGHT`` and terminal ``UNKNOWN`` submission events.  It performs no I/O,
does not claim that either event is currently authoritative in a database, and
cannot authorize a broker request or any submission lifecycle transition.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from packages.domain.broker_ingress import BROKER_INGRESS_CONTRACT_VERSION
from packages.domain.broker_request_budget import (
    BrokerRequestDemand,
    BrokerRequestPurpose,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.submission_attempt import (
    SubmissionAttemptEvent,
    SubmissionAttemptState,
)

UNKNOWN_SUBMISSION_RECOVERY_CONTRACT_VERSION = "phase4j-unknown-submission-recovery-v1"
UNKNOWN_SUBMISSION_RECOVERY_OFFSETS_SECONDS = (1, 2, 4, 8, 16, 32)
UNKNOWN_SUBMISSION_RECOVERY_HORIZON = timedelta(seconds=60)
UNKNOWN_SUBMISSION_LOOKUP_OPERATION = "lookup_unknown_by_client_order_id"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class UnknownSubmissionRecoveryError(ValueError):
    """UNKNOWN recovery scheduling evidence is malformed or inconsistent."""


class UnknownSubmissionRecoveryConflict(UnknownSubmissionRecoveryError):
    """Immutable recovery provenance or identity conflicts."""


class RecoveryScheduleOutcome(StrEnum):
    """Closed, non-authorizing outcomes from one trusted-time evaluation."""

    WAITING = "waiting"
    DUE = "due"
    EXHAUSTED = "exhausted"


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(
    value: str,
    field_name: str,
    *,
    maximum: int = 128,
) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise UnknownSubmissionRecoveryError(f"{field_name} must be a non-empty, trimmed string")
    if len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise UnknownSubmissionRecoveryError(f"{field_name} contains unsupported text")


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise UnknownSubmissionRecoveryError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_optional_sha256(value: str | None, field_name: str) -> None:
    if value is not None:
        _require_sha256(value, field_name)


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise UnknownSubmissionRecoveryError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise UnknownSubmissionRecoveryError(f"{field_name} must be UTC")


def _add_seconds(value: datetime, seconds: int, field_name: str) -> datetime:
    try:
        return value + timedelta(seconds=seconds)
    except OverflowError as error:
        raise UnknownSubmissionRecoveryError(
            f"{field_name} exceeds the supported datetime range"
        ) from error


def _delivery_receipt_id(account_id: str, delivery_idempotency_key: str) -> str:
    """Mirror the durable raw-ingress receipt identity without making a delivery."""

    return _sha256(
        (
            BROKER_INGRESS_CONTRACT_VERSION,
            "receipt_identity",
            account_id,
            delivery_idempotency_key,
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class UnknownSubmissionRecoverySlot:
    """One immutable eligibility instant in a bounded recovery plan."""

    plan_id: str
    slot_id: str
    ordinal: int
    offset_seconds: int
    scheduled_at: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("UnknownSubmissionRecoverySlot must be created by the recovery planner")

    def _validate(self) -> None:
        _require_sha256(self.plan_id, "recovery slot plan_id")
        _require_sha256(self.slot_id, "recovery slot ID")
        if type(self.ordinal) is not int or not 1 <= self.ordinal <= len(
            UNKNOWN_SUBMISSION_RECOVERY_OFFSETS_SECONDS
        ):
            raise UnknownSubmissionRecoveryError("recovery slot ordinal is outside the v1 schedule")
        expected_offset = UNKNOWN_SUBMISSION_RECOVERY_OFFSETS_SECONDS[self.ordinal - 1]
        if type(self.offset_seconds) is not int or self.offset_seconds != expected_offset:
            raise UnknownSubmissionRecoveryConflict(
                "recovery slot offset conflicts with the v1 schedule"
            )
        _require_utc(self.scheduled_at, "recovery slot scheduled_at")
        expected_id = _sha256(
            (
                UNKNOWN_SUBMISSION_RECOVERY_CONTRACT_VERSION,
                "slot_identity",
                self.plan_id,
                self.ordinal,
            )
        )
        if self.slot_id != expected_id:
            raise UnknownSubmissionRecoveryConflict("recovery slot ID is not canonically derived")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            UNKNOWN_SUBMISSION_RECOVERY_CONTRACT_VERSION,
            "slot",
            self.plan_id,
            self.slot_id,
            self.ordinal,
            self.offset_seconds,
            self.scheduled_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def transport_authorized(self) -> bool:
        return False


def _recovery_slot(
    *,
    plan_id: str,
    ordinal: int,
    scheduled_at: datetime,
) -> UnknownSubmissionRecoverySlot:
    slot = object.__new__(UnknownSubmissionRecoverySlot)
    for field_name, value in (
        ("plan_id", plan_id),
        (
            "slot_id",
            _sha256(
                (
                    UNKNOWN_SUBMISSION_RECOVERY_CONTRACT_VERSION,
                    "slot_identity",
                    plan_id,
                    ordinal,
                )
            ),
        ),
        ("ordinal", ordinal),
        (
            "offset_seconds",
            UNKNOWN_SUBMISSION_RECOVERY_OFFSETS_SECONDS[ordinal - 1],
        ),
        ("scheduled_at", scheduled_at),
    ):
        object.__setattr__(slot, field_name, value)
    slot._validate()
    return slot


@dataclass(frozen=True, slots=True, init=False)
class UnknownSubmissionRecoveryPlan:
    """Source-bound schedule for one exact durable UNKNOWN attempt."""

    plan_id: str
    account_id: str
    attempt_id: str
    attempt_sha256: str
    client_order_id: str
    lookup_correlation_sha256: str
    in_flight_event_id: str
    in_flight_event_sha256: str
    in_flight_sequence_number: int
    in_flight_occurred_at: datetime
    in_flight_recorded_at: datetime
    unknown_event_id: str
    unknown_event_sha256: str
    unknown_sequence_number: int
    unknown_occurred_at: datetime
    unknown_recorded_at: datetime
    recovery_deadline_at: datetime
    slots: tuple[UnknownSubmissionRecoverySlot, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("UnknownSubmissionRecoveryPlan must be created by the recovery planner")

    def _identity_material(self) -> tuple[object, ...]:
        return (
            UNKNOWN_SUBMISSION_RECOVERY_CONTRACT_VERSION,
            "plan_identity",
            self.account_id,
            self.attempt_id,
            self.attempt_sha256,
            self.client_order_id,
            self.lookup_correlation_sha256,
            self.in_flight_event_id,
            self.in_flight_event_sha256,
            self.in_flight_sequence_number,
            self.in_flight_occurred_at,
            self.in_flight_recorded_at,
            self.unknown_event_id,
            self.unknown_event_sha256,
            self.unknown_sequence_number,
            self.unknown_occurred_at,
            self.unknown_recorded_at,
            self.recovery_deadline_at,
        )

    def _validate(self) -> None:
        _require_sha256(self.plan_id, "recovery plan ID")
        _require_text(self.account_id, "recovery plan account ID", maximum=64)
        _require_text(self.attempt_id, "recovery plan attempt ID")
        _require_sha256(self.attempt_sha256, "recovery plan attempt digest")
        _require_text(
            self.client_order_id,
            "recovery plan client order ID",
            maximum=128,
        )
        _require_sha256(
            self.lookup_correlation_sha256,
            "recovery plan lookup correlation digest",
        )
        for value, field_name in (
            (self.in_flight_event_id, "recovery plan IN_FLIGHT event ID"),
            (self.unknown_event_id, "recovery plan UNKNOWN event ID"),
        ):
            _require_text(value, field_name)
        for value, field_name in (
            (
                self.in_flight_event_sha256,
                "recovery plan IN_FLIGHT event digest",
            ),
            (self.unknown_event_sha256, "recovery plan UNKNOWN event digest"),
        ):
            _require_sha256(value, field_name)
        if (
            type(self.in_flight_sequence_number) is not int
            or self.in_flight_sequence_number != 2
            or type(self.unknown_sequence_number) is not int
            or self.unknown_sequence_number != 3
        ):
            raise UnknownSubmissionRecoveryConflict(
                "recovery sources must be the exact IN_FLIGHT and UNKNOWN lifecycle positions"
            )
        for timestamp, field_name in (
            (self.in_flight_occurred_at, "recovery IN_FLIGHT occurred_at"),
            (self.in_flight_recorded_at, "recovery IN_FLIGHT recorded_at"),
            (self.unknown_occurred_at, "recovery UNKNOWN occurred_at"),
            (self.unknown_recorded_at, "recovery UNKNOWN recorded_at"),
            (self.recovery_deadline_at, "recovery deadline"),
        ):
            _require_utc(timestamp, field_name)
        if (
            self.in_flight_recorded_at < self.in_flight_occurred_at
            or self.unknown_occurred_at < self.in_flight_occurred_at
            or self.unknown_recorded_at < self.in_flight_recorded_at
            or self.unknown_recorded_at < self.unknown_occurred_at
        ):
            raise UnknownSubmissionRecoveryConflict(
                "recovery source chronology conflicts with the durable lifecycle"
            )
        expected_deadline = _add_seconds(
            self.in_flight_occurred_at,
            60,
            "recovery deadline",
        )
        if self.recovery_deadline_at != expected_deadline:
            raise UnknownSubmissionRecoveryConflict(
                "recovery deadline must be exactly 60 seconds after dispatch"
            )
        expected_plan_id = _sha256(self._identity_material())
        if self.plan_id != expected_plan_id:
            raise UnknownSubmissionRecoveryConflict("recovery plan ID is not canonically derived")
        if type(self.slots) is not tuple or any(
            type(slot) is not UnknownSubmissionRecoverySlot for slot in self.slots
        ):
            raise UnknownSubmissionRecoveryError(
                "recovery plan slots must be an immutable exact tuple"
            )
        expected_slots: list[UnknownSubmissionRecoverySlot] = []
        for ordinal, offset_seconds in enumerate(
            UNKNOWN_SUBMISSION_RECOVERY_OFFSETS_SECONDS,
            start=1,
        ):
            scheduled_at = _add_seconds(
                self.unknown_recorded_at,
                offset_seconds,
                "recovery slot",
            )
            if scheduled_at >= self.recovery_deadline_at:
                continue
            expected_slots.append(
                _recovery_slot(
                    plan_id=self.plan_id,
                    ordinal=ordinal,
                    scheduled_at=scheduled_at,
                )
            )
        if self.slots != tuple(expected_slots):
            raise UnknownSubmissionRecoveryConflict(
                "recovery slots do not match the bounded v1 schedule"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            UNKNOWN_SUBMISSION_RECOVERY_CONTRACT_VERSION,
            "plan",
            *self._identity_material()[2:],
            self.plan_id,
            tuple(slot.semantic_sha256 for slot in self.slots),
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def slot_count(self) -> int:
        return len(self.slots)

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def attempt_resolution_authorized(self) -> bool:
        return False

    @property
    def resubmission_authorized(self) -> bool:
        return False


def _validate_recovery_sources(
    *,
    account_id: str,
    in_flight_event: SubmissionAttemptEvent,
    unknown_event: SubmissionAttemptEvent,
) -> None:
    if (
        type(in_flight_event) is not SubmissionAttemptEvent
        or type(unknown_event) is not SubmissionAttemptEvent
    ):
        raise UnknownSubmissionRecoveryError(
            "recovery planning requires exact submission lifecycle events"
        )
    try:
        in_flight_event._validate()
        unknown_event._validate()
    except ValueError as error:
        raise UnknownSubmissionRecoveryConflict(
            "recovery planning source event is not canonical"
        ) from error
    if (
        in_flight_event.state is not SubmissionAttemptState.IN_FLIGHT
        or unknown_event.state is not SubmissionAttemptState.UNKNOWN
    ):
        raise UnknownSubmissionRecoveryError(
            "recovery planning requires IN_FLIGHT followed by UNKNOWN"
        )
    if (
        in_flight_event.sequence_number != 2
        or unknown_event.sequence_number != 3
        or unknown_event.attempt_id != in_flight_event.attempt_id
        or unknown_event.previous_event_sha256 != in_flight_event.semantic_sha256
    ):
        raise UnknownSubmissionRecoveryConflict(
            "UNKNOWN does not chain to the exact durable IN_FLIGHT dispatch"
        )
    dispatch_receipt = in_flight_event.dispatch_fence_receipt
    if dispatch_receipt is None:
        raise UnknownSubmissionRecoveryConflict("IN_FLIGHT source lacks dispatch fence evidence")
    if (
        dispatch_receipt.fence.account_id != account_id
        or dispatch_receipt.validated_at != in_flight_event.occurred_at
        or in_flight_event.occurred_at >= dispatch_receipt.valid_until
    ):
        raise UnknownSubmissionRecoveryConflict(
            "IN_FLIGHT source does not bind a current dispatch fence for the account"
        )
    if (
        unknown_event.occurred_at < in_flight_event.occurred_at
        or unknown_event.recorded_at < in_flight_event.recorded_at
    ):
        raise UnknownSubmissionRecoveryConflict(
            "UNKNOWN commit cannot precede the exact IN_FLIGHT dispatch"
        )


def create_unknown_submission_recovery_plan(
    *,
    account_id: str,
    client_order_id: str,
    attempt_sha256: str,
    in_flight_event: SubmissionAttemptEvent,
    unknown_event: SubmissionAttemptEvent,
    lookup_correlation_sha256: str,
) -> UnknownSubmissionRecoveryPlan:
    """Freeze the reviewed local v1 schedule for one UNKNOWN attempt.

    Eligible instants are one, two, four, eight, sixteen, and thirty-two
    seconds after the durable UNKNOWN ``recorded_at`` value.  Any instant at or
    after sixty seconds from the exact IN_FLIGHT dispatch is omitted.
    """

    _require_text(account_id, "recovery plan account ID", maximum=64)
    _require_text(client_order_id, "recovery plan client order ID", maximum=128)
    _require_sha256(attempt_sha256, "recovery plan attempt digest")
    _require_sha256(
        lookup_correlation_sha256,
        "recovery plan lookup correlation digest",
    )
    _validate_recovery_sources(
        account_id=account_id,
        in_flight_event=in_flight_event,
        unknown_event=unknown_event,
    )
    recovery_deadline_at = _add_seconds(
        in_flight_event.occurred_at,
        60,
        "recovery deadline",
    )
    identity_material = (
        UNKNOWN_SUBMISSION_RECOVERY_CONTRACT_VERSION,
        "plan_identity",
        account_id,
        in_flight_event.attempt_id,
        attempt_sha256,
        client_order_id,
        lookup_correlation_sha256,
        in_flight_event.event_id,
        in_flight_event.semantic_sha256,
        in_flight_event.sequence_number,
        in_flight_event.occurred_at,
        in_flight_event.recorded_at,
        unknown_event.event_id,
        unknown_event.semantic_sha256,
        unknown_event.sequence_number,
        unknown_event.occurred_at,
        unknown_event.recorded_at,
        recovery_deadline_at,
    )
    plan_id = _sha256(identity_material)
    slots: list[UnknownSubmissionRecoverySlot] = []
    for ordinal, offset_seconds in enumerate(
        UNKNOWN_SUBMISSION_RECOVERY_OFFSETS_SECONDS,
        start=1,
    ):
        scheduled_at = _add_seconds(
            unknown_event.recorded_at,
            offset_seconds,
            "recovery slot",
        )
        if scheduled_at >= recovery_deadline_at:
            continue
        slots.append(
            _recovery_slot(
                plan_id=plan_id,
                ordinal=ordinal,
                scheduled_at=scheduled_at,
            )
        )
    plan = object.__new__(UnknownSubmissionRecoveryPlan)
    for field_name, value in (
        ("plan_id", plan_id),
        ("account_id", account_id),
        ("attempt_id", in_flight_event.attempt_id),
        ("attempt_sha256", attempt_sha256),
        ("client_order_id", client_order_id),
        ("lookup_correlation_sha256", lookup_correlation_sha256),
        ("in_flight_event_id", in_flight_event.event_id),
        ("in_flight_event_sha256", in_flight_event.semantic_sha256),
        ("in_flight_sequence_number", in_flight_event.sequence_number),
        ("in_flight_occurred_at", in_flight_event.occurred_at),
        ("in_flight_recorded_at", in_flight_event.recorded_at),
        ("unknown_event_id", unknown_event.event_id),
        ("unknown_event_sha256", unknown_event.semantic_sha256),
        ("unknown_sequence_number", unknown_event.sequence_number),
        ("unknown_occurred_at", unknown_event.occurred_at),
        ("unknown_recorded_at", unknown_event.recorded_at),
        ("recovery_deadline_at", recovery_deadline_at),
        ("slots", tuple(slots)),
    ):
        object.__setattr__(plan, field_name, value)
    plan._validate()
    return plan


@dataclass(frozen=True, slots=True, init=False)
class UnknownSubmissionRecoveryTicket:
    """Stable identities for one due slot; never broker-call authority."""

    ticket_id: str
    plan_id: str
    plan_sha256: str
    slot_id: str
    slot_sha256: str
    account_id: str
    attempt_id: str
    lookup_correlation_sha256: str
    scheduled_at: datetime
    recovery_deadline_at: datetime
    demand_id: str
    demand_idempotency_key: str
    delivery_id: str
    delivery_idempotency_key: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("UnknownSubmissionRecoveryTicket must be created by scheduler evaluation")

    def _validate(self) -> None:
        for value, field_name in (
            (self.ticket_id, "recovery ticket ID"),
            (self.plan_id, "recovery ticket plan ID"),
            (self.plan_sha256, "recovery ticket plan digest"),
            (self.slot_id, "recovery ticket slot ID"),
            (self.slot_sha256, "recovery ticket slot digest"),
            (
                self.lookup_correlation_sha256,
                "recovery ticket lookup correlation digest",
            ),
            (self.demand_id, "recovery ticket demand ID"),
            (self.delivery_id, "recovery ticket delivery ID"),
        ):
            _require_sha256(value, field_name)
        _require_text(self.account_id, "recovery ticket account ID", maximum=64)
        _require_text(self.attempt_id, "recovery ticket attempt ID")
        for value, field_name in (
            (
                self.demand_idempotency_key,
                "recovery ticket demand idempotency key",
            ),
            (
                self.delivery_idempotency_key,
                "recovery ticket delivery idempotency key",
            ),
        ):
            _require_text(value, field_name)
        _require_utc(self.scheduled_at, "recovery ticket scheduled_at")
        _require_utc(self.recovery_deadline_at, "recovery ticket deadline")
        if self.scheduled_at >= self.recovery_deadline_at:
            raise UnknownSubmissionRecoveryConflict(
                "recovery ticket must precede the dispatch horizon"
            )
        expected_ticket_id = _sha256(
            (
                UNKNOWN_SUBMISSION_RECOVERY_CONTRACT_VERSION,
                "ticket_identity",
                self.plan_sha256,
                self.slot_sha256,
            )
        )
        if self.ticket_id != expected_ticket_id:
            raise UnknownSubmissionRecoveryConflict("recovery ticket ID is not canonically derived")
        if self.demand_idempotency_key != f"phase4j-demand-{self.ticket_id}":
            raise UnknownSubmissionRecoveryConflict(
                "recovery demand idempotency key is not canonically derived"
            )
        if self.delivery_idempotency_key != f"phase4j-delivery-{self.ticket_id}":
            raise UnknownSubmissionRecoveryConflict(
                "recovery delivery idempotency key is not canonically derived"
            )
        expected_demand = BrokerRequestDemand(
            account_id=self.account_id,
            idempotency_key=self.demand_idempotency_key,
            operation=UNKNOWN_SUBMISSION_LOOKUP_OPERATION,
            purpose=BrokerRequestPurpose.UNKNOWN_LOOKUP,
            correlation_sha256=self.lookup_correlation_sha256,
            requested_at=self.scheduled_at,
        )
        if self.demand_id != expected_demand.demand_id:
            raise UnknownSubmissionRecoveryConflict("recovery demand ID is not canonically derived")
        if self.delivery_id != _delivery_receipt_id(
            self.account_id,
            self.delivery_idempotency_key,
        ):
            raise UnknownSubmissionRecoveryConflict(
                "recovery delivery ID is not canonically derived"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            UNKNOWN_SUBMISSION_RECOVERY_CONTRACT_VERSION,
            "ticket",
            self.ticket_id,
            self.plan_id,
            self.plan_sha256,
            self.slot_id,
            self.slot_sha256,
            self.account_id,
            self.attempt_id,
            self.lookup_correlation_sha256,
            self.scheduled_at,
            self.recovery_deadline_at,
            self.demand_id,
            self.demand_idempotency_key,
            self.delivery_id,
            self.delivery_idempotency_key,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def lookup_authorized(self) -> bool:
        return False

    @property
    def attempt_resolution_authorized(self) -> bool:
        return False

    @property
    def resubmission_authorized(self) -> bool:
        return False


def _recovery_ticket(
    *,
    plan: UnknownSubmissionRecoveryPlan,
    slot: UnknownSubmissionRecoverySlot,
) -> UnknownSubmissionRecoveryTicket:
    plan._validate()
    slot._validate()
    if slot.plan_id != plan.plan_id or slot not in plan.slots:
        raise UnknownSubmissionRecoveryConflict(
            "recovery ticket slot does not belong to the exact plan"
        )
    plan_sha256 = plan.semantic_sha256
    slot_sha256 = slot.semantic_sha256
    ticket_id = _sha256(
        (
            UNKNOWN_SUBMISSION_RECOVERY_CONTRACT_VERSION,
            "ticket_identity",
            plan_sha256,
            slot_sha256,
        )
    )
    demand_idempotency_key = f"phase4j-demand-{ticket_id}"
    delivery_idempotency_key = f"phase4j-delivery-{ticket_id}"
    demand = BrokerRequestDemand(
        account_id=plan.account_id,
        idempotency_key=demand_idempotency_key,
        operation=UNKNOWN_SUBMISSION_LOOKUP_OPERATION,
        purpose=BrokerRequestPurpose.UNKNOWN_LOOKUP,
        correlation_sha256=plan.lookup_correlation_sha256,
        requested_at=slot.scheduled_at,
    )
    ticket = object.__new__(UnknownSubmissionRecoveryTicket)
    for field_name, value in (
        ("ticket_id", ticket_id),
        ("plan_id", plan.plan_id),
        ("plan_sha256", plan_sha256),
        ("slot_id", slot.slot_id),
        ("slot_sha256", slot_sha256),
        ("account_id", plan.account_id),
        ("attempt_id", plan.attempt_id),
        ("lookup_correlation_sha256", plan.lookup_correlation_sha256),
        ("scheduled_at", slot.scheduled_at),
        ("recovery_deadline_at", plan.recovery_deadline_at),
        ("demand_id", demand.demand_id),
        ("demand_idempotency_key", demand_idempotency_key),
        (
            "delivery_id",
            _delivery_receipt_id(plan.account_id, delivery_idempotency_key),
        ),
        ("delivery_idempotency_key", delivery_idempotency_key),
    ):
        object.__setattr__(ticket, field_name, value)
    ticket._validate()
    return ticket


def create_unknown_submission_recovery_demand(
    *,
    ticket: UnknownSubmissionRecoveryTicket,
    requested_at: datetime,
) -> BrokerRequestDemand:
    """Reconstruct the exact fixed-purpose demand for a due recovery ticket."""

    if type(ticket) is not UnknownSubmissionRecoveryTicket:
        raise UnknownSubmissionRecoveryError("recovery demand requires an exact scheduler ticket")
    ticket._validate()
    _require_utc(requested_at, "recovery demand requested_at")
    if requested_at < ticket.scheduled_at:
        raise UnknownSubmissionRecoveryError("recovery demand cannot precede its scheduled slot")
    if requested_at >= ticket.recovery_deadline_at:
        raise UnknownSubmissionRecoveryError(
            "recovery demand cannot begin at or after the dispatch horizon"
        )
    demand = BrokerRequestDemand(
        account_id=ticket.account_id,
        idempotency_key=ticket.demand_idempotency_key,
        operation=UNKNOWN_SUBMISSION_LOOKUP_OPERATION,
        purpose=BrokerRequestPurpose.UNKNOWN_LOOKUP,
        correlation_sha256=ticket.lookup_correlation_sha256,
        requested_at=requested_at,
    )
    if demand.demand_id != ticket.demand_id:
        raise UnknownSubmissionRecoveryConflict(
            "reconstructed recovery demand changed its stable identity"
        )
    return demand


@dataclass(frozen=True, slots=True, init=False)
class UnknownSubmissionRecoveryEvaluation:
    """One deterministic poll result over a caller-supplied consumed-slot set."""

    evaluation_id: str
    plan_id: str
    plan_sha256: str
    evaluated_at: datetime
    outcome: RecoveryScheduleOutcome
    consumed_slot_ids: tuple[str, ...]
    latest_due_slot_id: str | None
    selected_ticket: UnknownSubmissionRecoveryTicket | None
    coalesced_slot_ordinals: tuple[int, ...]
    coalesced_slot_ids: tuple[str, ...]
    coalesced_slot_sha256s: tuple[str, ...]
    remaining_slot_ordinals: tuple[int, ...]
    remaining_slot_ids: tuple[str, ...]
    remaining_slot_sha256s: tuple[str, ...]
    next_slot_id: str | None
    next_scheduled_at: datetime | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("UnknownSubmissionRecoveryEvaluation must be produced by the scheduler")

    def _validate(self) -> None:
        for value, field_name in (
            (self.evaluation_id, "recovery evaluation ID"),
            (self.plan_id, "recovery evaluation plan ID"),
            (self.plan_sha256, "recovery evaluation plan digest"),
        ):
            _require_sha256(value, field_name)
        _require_utc(self.evaluated_at, "recovery evaluated_at")
        if type(self.outcome) is not RecoveryScheduleOutcome:
            raise UnknownSubmissionRecoveryError("recovery evaluation outcome must be exact")
        for values, field_name in (
            (self.consumed_slot_ids, "consumed recovery slot IDs"),
            (self.coalesced_slot_ids, "coalesced recovery slot IDs"),
            (self.coalesced_slot_sha256s, "coalesced recovery slot digests"),
            (self.remaining_slot_ids, "remaining recovery slot IDs"),
            (self.remaining_slot_sha256s, "remaining recovery slot digests"),
        ):
            if type(values) is not tuple:
                raise UnknownSubmissionRecoveryError(f"{field_name} must be an immutable tuple")
            for value in values:
                _require_sha256(value, field_name)
        for ordinals, field_name in (
            (self.coalesced_slot_ordinals, "coalesced recovery slot ordinals"),
            (self.remaining_slot_ordinals, "remaining recovery slot ordinals"),
        ):
            if type(ordinals) is not tuple or any(
                type(ordinal) is not int or ordinal <= 0 for ordinal in ordinals
            ):
                raise UnknownSubmissionRecoveryError(
                    f"{field_name} must be positive exact integers"
                )
        _require_optional_sha256(
            self.latest_due_slot_id,
            "latest due recovery slot ID",
        )
        _require_optional_sha256(self.next_slot_id, "next recovery slot ID")
        if self.next_scheduled_at is not None:
            _require_utc(self.next_scheduled_at, "next recovery scheduled_at")
        if self.selected_ticket is not None:
            if type(self.selected_ticket) is not UnknownSubmissionRecoveryTicket:
                raise UnknownSubmissionRecoveryError("selected recovery ticket must be exact")
            self.selected_ticket._validate()
        if (self.outcome is RecoveryScheduleOutcome.DUE) != (self.selected_ticket is not None):
            raise UnknownSubmissionRecoveryConflict(
                "only a due evaluation may carry a recovery ticket"
            )
        expected_id = _sha256(
            (
                UNKNOWN_SUBMISSION_RECOVERY_CONTRACT_VERSION,
                "evaluation_identity",
                self.plan_sha256,
                self.evaluated_at,
                self.consumed_slot_ids,
            )
        )
        if self.evaluation_id != expected_id:
            raise UnknownSubmissionRecoveryConflict(
                "recovery evaluation ID is not canonically derived"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            UNKNOWN_SUBMISSION_RECOVERY_CONTRACT_VERSION,
            "evaluation",
            self.evaluation_id,
            self.plan_id,
            self.plan_sha256,
            self.evaluated_at,
            self.outcome.value,
            self.consumed_slot_ids,
            self.latest_due_slot_id,
            (None if self.selected_ticket is None else self.selected_ticket.semantic_sha256),
            self.coalesced_slot_ordinals,
            self.coalesced_slot_ids,
            self.coalesced_slot_sha256s,
            self.remaining_slot_ordinals,
            self.remaining_slot_ids,
            self.remaining_slot_sha256s,
            self.next_slot_id,
            self.next_scheduled_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def terminal(self) -> bool:
        return self.outcome is RecoveryScheduleOutcome.EXHAUSTED

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def lookup_authorized(self) -> bool:
        return False

    @property
    def attempt_resolution_authorized(self) -> bool:
        return False

    @property
    def resubmission_authorized(self) -> bool:
        return False

    @property
    def lifecycle_mutation_authorized(self) -> bool:
        return False


def evaluate_unknown_submission_recovery(
    *,
    plan: UnknownSubmissionRecoveryPlan,
    evaluated_at: datetime,
    consumed_slot_ids: tuple[str, ...] = (),
) -> UnknownSubmissionRecoveryEvaluation:
    """Select at most the latest due slot and coalesce every earlier miss.

    The caller supplies the exact set of slots already durably consumed.  Older
    due slots are never selected after a newer slot becomes due, so delayed
    polling cannot create a catch-up burst.
    """

    if type(plan) is not UnknownSubmissionRecoveryPlan:
        raise UnknownSubmissionRecoveryError("recovery evaluation requires an exact recovery plan")
    plan._validate()
    _require_utc(evaluated_at, "recovery evaluated_at")
    if evaluated_at < plan.unknown_recorded_at:
        raise UnknownSubmissionRecoveryError(
            "recovery evaluation cannot precede the durable UNKNOWN commit"
        )
    if type(consumed_slot_ids) is not tuple:
        raise UnknownSubmissionRecoveryError(
            "consumed recovery slot IDs must be an immutable tuple"
        )
    if len(set(consumed_slot_ids)) != len(consumed_slot_ids):
        raise UnknownSubmissionRecoveryConflict("consumed recovery slot IDs must be unique")
    slot_by_id = {slot.slot_id: slot for slot in plan.slots}
    if any(slot_id not in slot_by_id for slot_id in consumed_slot_ids):
        raise UnknownSubmissionRecoveryConflict(
            "consumed recovery slot does not belong to the exact plan"
        )
    canonical_consumed = tuple(
        slot.slot_id for slot in plan.slots if slot.slot_id in consumed_slot_ids
    )
    if any(slot_by_id[slot_id].scheduled_at > evaluated_at for slot_id in canonical_consumed):
        raise UnknownSubmissionRecoveryConflict(
            "a recovery slot cannot be consumed before it becomes eligible"
        )
    due_slots = tuple(slot for slot in plan.slots if slot.scheduled_at <= evaluated_at)
    latest_due = due_slots[-1] if due_slots else None
    future_slots = tuple(slot for slot in plan.slots if slot.scheduled_at > evaluated_at)
    consumed = set(canonical_consumed)
    remaining = tuple(slot for slot in plan.slots if slot.slot_id not in consumed)
    selected_ticket: UnknownSubmissionRecoveryTicket | None = None
    coalesced: tuple[UnknownSubmissionRecoverySlot, ...] = ()
    next_slot = future_slots[0] if future_slots else None

    if evaluated_at >= plan.recovery_deadline_at:
        outcome = RecoveryScheduleOutcome.EXHAUSTED
        latest_due = plan.slots[-1] if plan.slots else None
        coalesced = remaining
        next_slot = None
    elif latest_due is None:
        outcome = RecoveryScheduleOutcome.WAITING
    else:
        coalesced = tuple(
            slot
            for slot in due_slots
            if slot.ordinal < latest_due.ordinal and slot.slot_id not in consumed
        )
        if latest_due.slot_id not in consumed:
            outcome = RecoveryScheduleOutcome.DUE
            selected_ticket = _recovery_ticket(
                plan=plan,
                slot=latest_due,
            )
        else:
            outcome = RecoveryScheduleOutcome.WAITING

    evaluation_id = _sha256(
        (
            UNKNOWN_SUBMISSION_RECOVERY_CONTRACT_VERSION,
            "evaluation_identity",
            plan.semantic_sha256,
            evaluated_at,
            canonical_consumed,
        )
    )
    evaluation = object.__new__(UnknownSubmissionRecoveryEvaluation)
    for field_name, value in (
        ("evaluation_id", evaluation_id),
        ("plan_id", plan.plan_id),
        ("plan_sha256", plan.semantic_sha256),
        ("evaluated_at", evaluated_at),
        ("outcome", outcome),
        ("consumed_slot_ids", canonical_consumed),
        (
            "latest_due_slot_id",
            None if latest_due is None else latest_due.slot_id,
        ),
        ("selected_ticket", selected_ticket),
        (
            "coalesced_slot_ordinals",
            tuple(slot.ordinal for slot in coalesced),
        ),
        ("coalesced_slot_ids", tuple(slot.slot_id for slot in coalesced)),
        (
            "coalesced_slot_sha256s",
            tuple(slot.semantic_sha256 for slot in coalesced),
        ),
        (
            "remaining_slot_ordinals",
            tuple(slot.ordinal for slot in remaining),
        ),
        ("remaining_slot_ids", tuple(slot.slot_id for slot in remaining)),
        (
            "remaining_slot_sha256s",
            tuple(slot.semantic_sha256 for slot in remaining),
        ),
        ("next_slot_id", None if next_slot is None else next_slot.slot_id),
        (
            "next_scheduled_at",
            None if next_slot is None else next_slot.scheduled_at,
        ),
    ):
        object.__setattr__(evaluation, field_name, value)
    evaluation._validate()
    return evaluation


__all__ = [
    "UNKNOWN_SUBMISSION_LOOKUP_OPERATION",
    "UNKNOWN_SUBMISSION_RECOVERY_CONTRACT_VERSION",
    "UNKNOWN_SUBMISSION_RECOVERY_HORIZON",
    "UNKNOWN_SUBMISSION_RECOVERY_OFFSETS_SECONDS",
    "RecoveryScheduleOutcome",
    "UnknownSubmissionRecoveryConflict",
    "UnknownSubmissionRecoveryError",
    "UnknownSubmissionRecoveryEvaluation",
    "UnknownSubmissionRecoveryPlan",
    "UnknownSubmissionRecoverySlot",
    "UnknownSubmissionRecoveryTicket",
    "create_unknown_submission_recovery_demand",
    "create_unknown_submission_recovery_plan",
    "evaluate_unknown_submission_recovery",
]
