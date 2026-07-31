"""Durable one-shot scheduling for bounded UNKNOWN client-order lookups."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from packages.adapters.broker.alpaca_paper_lookup_runtime import (
    AlpacaPaperAuthenticatedLookupOutcome,
    AlpacaPaperAuthenticatedLookupReceipt,
    AlpacaPaperLookupRuntimeError,
)
from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountFence,
    AccountFenceReceipt,
    _account_fence_receipt,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.submission_attempt import (
    CanonicalSubmissionAttempt,
    SubmissionAttemptError,
    SubmissionAttemptState,
    reduce_submission_attempt,
)
from packages.domain.unknown_submission_recovery import (
    RecoveryScheduleOutcome,
    UnknownSubmissionRecoveryConflict,
    UnknownSubmissionRecoveryError,
    UnknownSubmissionRecoveryEvaluation,
    UnknownSubmissionRecoveryPlan,
    UnknownSubmissionRecoveryTicket,
    create_unknown_submission_recovery_demand,
    create_unknown_submission_recovery_plan,
    evaluate_unknown_submission_recovery,
)
from packages.persistence.account_coordinator import (
    _write_transaction,
    account_lease_from_row,
    lock_account_capacity_serialization,
)
from packages.persistence.alpaca_paper_lookup_observation import (
    _authenticate_durable_sources as _authenticate_lookup_sources,
)
from packages.persistence.alpaca_paper_lookup_observation import (
    _authenticate_fence_position_at,
    _authenticate_ingress_source,
)
from packages.persistence.alpaca_paper_lookup_observation import (
    _history as _lookup_history,
)
from packages.persistence.alpaca_paper_lookup_observation import (
    _receipt_by_id as _lookup_receipt_by_id,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import as_aware_utc, assert_immutable
from packages.persistence.schema import (
    phase2_account_leases,
    phase4_unknown_lookup_recovery_events,
    phase4_unknown_lookup_recovery_heads,
    phase4_unknown_lookup_recovery_plans,
)
from packages.persistence.submission_attempt import (
    SubmissionAttemptPersistenceError,
    _authenticate_terminal_unknown,
    load_submission_attempt,
)

UNKNOWN_SUBMISSION_RECOVERY_PERSISTENCE_CONTRACT_VERSION = (
    "phase4j-unknown-submission-recovery-persistence-v1"
)
UNKNOWN_SUBMISSION_RECOVERY_CLAIM_TTL = timedelta(seconds=3)
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})
_EMPTY_IDS_PAYLOAD = "[]"


class UnknownSubmissionRecoveryPersistenceError(UnknownSubmissionRecoveryError):
    """Durable recovery schedule is malformed or unavailable."""


class UnknownSubmissionRecoveryPersistenceConflict(
    UnknownSubmissionRecoveryConflict,
    UnknownSubmissionRecoveryPersistenceError,
):
    """Durable recovery schedule conflicts with immutable evidence."""


class RecoveryClaimOutcome(StrEnum):
    """Persistence-owned claim projection over a pure schedule evaluation."""

    WAITING = "waiting"
    DUE = "due"
    ACTIVE = "active"
    EXHAUSTED = "exhausted"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    BLOCKED_MISMATCH = "blocked_mismatch"


class RecoveryScheduleEventKind(StrEnum):
    DISPATCH = "dispatch"
    OBSERVATION = "observation"
    EXHAUSTED = "exhausted"


class SqlAccountFenceValidator(Protocol):
    def revalidate_for_commit_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt: ...


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_utc(value: datetime, field_name: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise UnknownSubmissionRecoveryPersistenceError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise UnknownSubmissionRecoveryPersistenceError(f"{field_name} must be UTC")
    return value


def _required_text(row: RowMapping, field_name: str) -> str:
    value = row[field_name]
    if type(value) is not str or not value:
        raise UnknownSubmissionRecoveryPersistenceError(
            f"recovery schedule {field_name} is malformed"
        )
    return value


def _optional_text(row: RowMapping, field_name: str) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str or not value:
        raise UnknownSubmissionRecoveryPersistenceError(
            f"recovery schedule {field_name} is malformed"
        )
    return value


def _required_int(row: RowMapping, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise UnknownSubmissionRecoveryPersistenceError(
            f"recovery schedule {field_name} is malformed"
        )
    return value


def _optional_int(row: RowMapping, field_name: str) -> int | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not int:
        raise UnknownSubmissionRecoveryPersistenceError(
            f"recovery schedule {field_name} is malformed"
        )
    return value


def _required_datetime(row: RowMapping, field_name: str) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise UnknownSubmissionRecoveryPersistenceError(
            f"recovery schedule {field_name} is malformed"
        )
    return _require_utc(as_aware_utc(value), field_name)


def _optional_datetime(row: RowMapping, field_name: str) -> datetime | None:
    value = row[field_name]
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise UnknownSubmissionRecoveryPersistenceError(
            f"recovery schedule {field_name} is malformed"
        )
    return _require_utc(as_aware_utc(value), field_name)


def _ids_payload(values: tuple[str, ...]) -> str:
    if type(values) is not tuple or any(
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
        for value in values
    ):
        raise UnknownSubmissionRecoveryPersistenceError(
            "recovery slot IDs must be an exact digest tuple"
        )
    return json.dumps(values, ensure_ascii=True, separators=(",", ":"))


def _ids_from_payload(value: object, field_name: str) -> tuple[str, ...]:
    if type(value) is not str:
        raise UnknownSubmissionRecoveryPersistenceError(
            f"recovery schedule {field_name} is malformed"
        )
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError) as error:
        raise UnknownSubmissionRecoveryPersistenceError(
            f"recovery schedule {field_name} is malformed"
        ) from error
    if type(decoded) is not list:
        raise UnknownSubmissionRecoveryPersistenceError(
            f"recovery schedule {field_name} is malformed"
        )
    result = tuple(decoded)
    if _ids_payload(result) != value or len(set(result)) != len(result):
        raise UnknownSubmissionRecoveryPersistenceError(
            f"recovery schedule {field_name} is not canonical"
        )
    return result


def _slots_payload(plan: UnknownSubmissionRecoveryPlan) -> str:
    return canonical_json_text(
        tuple(
            (
                slot.slot_id,
                slot.semantic_sha256,
                slot.ordinal,
                slot.offset_seconds,
                slot.scheduled_at,
            )
            for slot in plan.slots
        )
    )


def immutable_unknown_submission_recovery_plan_values(
    plan: UnknownSubmissionRecoveryPlan,
) -> dict[str, object]:
    if type(plan) is not UnknownSubmissionRecoveryPlan:
        raise UnknownSubmissionRecoveryPersistenceError(
            "recovery plan persistence requires an exact plan"
        )
    plan._validate()
    slots_payload = _slots_payload(plan)
    return {
        "plan_id": plan.plan_id,
        "account_id": plan.account_id,
        "attempt_id": plan.attempt_id,
        "attempt_sha256": plan.attempt_sha256,
        "client_order_id": plan.client_order_id,
        "lookup_correlation_sha256": plan.lookup_correlation_sha256,
        "in_flight_event_id": plan.in_flight_event_id,
        "in_flight_event_sha256": plan.in_flight_event_sha256,
        "in_flight_sequence_number": plan.in_flight_sequence_number,
        "in_flight_occurred_at": plan.in_flight_occurred_at,
        "in_flight_recorded_at": plan.in_flight_recorded_at,
        "unknown_event_id": plan.unknown_event_id,
        "unknown_event_sha256": plan.unknown_event_sha256,
        "unknown_sequence_number": plan.unknown_sequence_number,
        "unknown_occurred_at": plan.unknown_occurred_at,
        "unknown_recorded_at": plan.unknown_recorded_at,
        "recovery_deadline_at": plan.recovery_deadline_at,
        "slot_count": plan.slot_count,
        "slots_payload": slots_payload,
        "slots_sha256": hashlib.sha256(slots_payload.encode("utf-8")).hexdigest(),
        "canonical_payload": plan.canonical_json,
        "semantic_sha256": plan.semantic_sha256,
    }


def _plan_from_row(
    connection: Connection,
    row: RowMapping,
) -> UnknownSubmissionRecoveryPlan:
    attempt_id = _required_text(row, "attempt_id")
    attempt = load_submission_attempt(connection, attempt_id)
    if attempt is None or len(attempt.events) < 3:
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery plan references a missing submission history"
        )
    try:
        historical = reduce_submission_attempt(
            attempt.preparation,
            attempt.events[:3],
        )
    except SubmissionAttemptError as error:
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery plan UNKNOWN attempt prefix is not canonical"
        ) from error
    in_flight_event = historical.events[1]
    unknown_event = historical.events[2]
    if (
        historical.state is not SubmissionAttemptState.UNKNOWN
        or historical.preparation.account_id != _required_text(row, "account_id")
        or historical.preparation.client_order_id != _required_text(row, "client_order_id")
        or historical.semantic_sha256 != _required_text(row, "attempt_sha256")
        or in_flight_event.state is not SubmissionAttemptState.IN_FLIGHT
        or unknown_event.state is not SubmissionAttemptState.UNKNOWN
        or in_flight_event.event_id != _required_text(row, "in_flight_event_id")
        or in_flight_event.semantic_sha256 != _required_text(row, "in_flight_event_sha256")
        or unknown_event.event_id != _required_text(row, "unknown_event_id")
        or unknown_event.semantic_sha256 != _required_text(row, "unknown_event_sha256")
    ):
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery plan conflicts with its exact historical UNKNOWN source"
        )
    plan = create_unknown_submission_recovery_plan(
        account_id=historical.preparation.account_id,
        client_order_id=historical.preparation.client_order_id,
        attempt_sha256=historical.semantic_sha256,
        in_flight_event=in_flight_event,
        unknown_event=unknown_event,
        lookup_correlation_sha256=_required_text(
            row,
            "lookup_correlation_sha256",
        ),
    )
    values = immutable_unknown_submission_recovery_plan_values(plan)
    for field_name, expected in values.items():
        actual: object = row[field_name]
        if isinstance(expected, datetime):
            if not isinstance(actual, datetime):
                raise UnknownSubmissionRecoveryPersistenceConflict(
                    "recovery plan SQL datetime is malformed"
                )
            actual = as_aware_utc(actual)
        if actual != expected:
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "recovery plan conflicts with its canonical durable sources"
            )
    return plan


def _plan_row(
    connection: Connection,
    plan_id: str,
) -> RowMapping | None:
    return (
        connection.execute(
            sa.select(phase4_unknown_lookup_recovery_plans).where(
                phase4_unknown_lookup_recovery_plans.c.plan_id == plan_id
            )
        )
        .mappings()
        .one_or_none()
    )


@dataclass(frozen=True, slots=True)
class UnknownSubmissionRecoveryClaim:
    """One persisted, one-shot three-second claim for a deterministic ticket."""

    ticket: UnknownSubmissionRecoveryTicket
    dispatch_event_id: str
    dispatch_event_sha256: str
    issued_at: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        if type(self.ticket) is not UnknownSubmissionRecoveryTicket:
            raise UnknownSubmissionRecoveryPersistenceError(
                "recovery claim requires an exact ticket"
            )
        self.ticket._validate()
        for value, field_name in (
            (self.dispatch_event_id, "claim dispatch event ID"),
            (self.dispatch_event_sha256, "claim dispatch event digest"),
        ):
            if (
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise UnknownSubmissionRecoveryPersistenceError(
                    f"{field_name} must be a lowercase SHA-256 digest"
                )
        _require_utc(self.issued_at, "recovery claim issued_at")
        _require_utc(self.valid_until, "recovery claim valid_until")
        expected_valid_until = min(
            self.issued_at + UNKNOWN_SUBMISSION_RECOVERY_CLAIM_TTL,
            self.ticket.recovery_deadline_at,
        )
        if (
            self.ticket.scheduled_at > self.issued_at
            or self.issued_at >= self.valid_until
            or self.valid_until != expected_valid_until
        ):
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "recovery claim does not use the exact bounded claim window"
            )

    def is_active_at(self, checked_at: datetime) -> bool:
        _require_utc(checked_at, "recovery claim checked_at")
        return self.issued_at <= checked_at < self.valid_until

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def lookup_authorized(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class UnknownSubmissionRecoveryScheduleDecision:
    """Repository result that distinguishes a new claim from an active one."""

    outcome: RecoveryClaimOutcome
    evaluation: UnknownSubmissionRecoveryEvaluation
    claim: UnknownSubmissionRecoveryClaim | None

    def __post_init__(self) -> None:
        if type(self.outcome) is not RecoveryClaimOutcome:
            raise UnknownSubmissionRecoveryPersistenceError(
                "recovery decision outcome must be exact"
            )
        if type(self.evaluation) is not UnknownSubmissionRecoveryEvaluation:
            raise UnknownSubmissionRecoveryPersistenceError(
                "recovery decision requires an exact pure evaluation"
            )
        self.evaluation._validate()
        if (self.outcome in {RecoveryClaimOutcome.DUE, RecoveryClaimOutcome.ACTIVE}) != (
            self.claim is not None
        ):
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "only due or active recovery decisions carry a claim"
            )
        if self.claim is not None:
            self.claim.__post_init__()

    @property
    def newly_issued(self) -> bool:
        return self.outcome is RecoveryClaimOutcome.DUE

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


@dataclass(frozen=True, slots=True, init=False)
class UnknownSubmissionRecoveryDispatchProgress:
    """One authenticated durable claim and its optional attached lookup."""

    claim: UnknownSubmissionRecoveryClaim
    lookup_receipt: AlpacaPaperAuthenticatedLookupReceipt | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "UnknownSubmissionRecoveryDispatchProgress must be loaded from durable history"
        )

    def __post_init__(self) -> None:
        if type(self.claim) is not UnknownSubmissionRecoveryClaim:
            raise UnknownSubmissionRecoveryPersistenceError(
                "recovery dispatch progress requires an exact durable claim"
            )
        self.claim.__post_init__()
        if self.lookup_receipt is None:
            return
        if type(self.lookup_receipt) is not AlpacaPaperAuthenticatedLookupReceipt:
            raise UnknownSubmissionRecoveryPersistenceError(
                "recovery dispatch progress requires an exact lookup receipt"
            )
        self.lookup_receipt._validate()
        ticket = self.claim.ticket
        if (
            self.lookup_receipt.account_id != ticket.account_id
            or self.lookup_receipt.attempt_id != ticket.attempt_id
            or self.lookup_receipt.demand_id != ticket.demand_id
            or self.lookup_receipt.ingress_receipt_id != ticket.delivery_id
            or not self.claim.issued_at <= self.lookup_receipt.requested_at < self.claim.valid_until
        ):
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "recovery dispatch progress lookup conflicts with its exact claim"
            )

    @property
    def lookup_receipt_id(self) -> str | None:
        return None if self.lookup_receipt is None else self.lookup_receipt.receipt_id

    @property
    def lookup_receipt_sha256(self) -> str | None:
        return None if self.lookup_receipt is None else self.lookup_receipt.semantic_sha256

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


@dataclass(frozen=True, slots=True, init=False)
class UnknownSubmissionRecoveryProgress:
    """Authenticated immutable dispatch progress for restart-safe composition."""

    plan: UnknownSubmissionRecoveryPlan
    dispatches: tuple[UnknownSubmissionRecoveryDispatchProgress, ...]
    consumed_slot_ids: tuple[str, ...]
    issuance_status: RecoveryClaimOutcome

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("UnknownSubmissionRecoveryProgress must be loaded from durable history")

    def __post_init__(self) -> None:
        if type(self.plan) is not UnknownSubmissionRecoveryPlan:
            raise UnknownSubmissionRecoveryPersistenceError(
                "recovery progress requires an exact durable plan"
            )
        self.plan._validate()
        if type(self.dispatches) is not tuple or any(
            type(dispatch) is not UnknownSubmissionRecoveryDispatchProgress
            for dispatch in self.dispatches
        ):
            raise UnknownSubmissionRecoveryPersistenceError(
                "recovery progress dispatches must be an immutable exact tuple"
            )
        if (
            type(self.consumed_slot_ids) is not tuple
            or any(type(slot_id) is not str for slot_id in self.consumed_slot_ids)
            or _canonical_consumed(self.plan, self.consumed_slot_ids) != self.consumed_slot_ids
        ):
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "recovery progress consumed slots conflict with its plan"
            )
        if type(self.issuance_status) is not RecoveryClaimOutcome:
            raise UnknownSubmissionRecoveryPersistenceError(
                "recovery progress issuance status must be exact"
            )
        slot_positions = {slot.slot_id: position for position, slot in enumerate(self.plan.slots)}
        prior_position = -1
        dispatch_event_ids: set[str] = set()
        for dispatch in self.dispatches:
            dispatch.__post_init__()
            claim = dispatch.claim
            ticket = claim.ticket
            position = slot_positions.get(ticket.slot_id)
            if (
                ticket.plan_id != self.plan.plan_id
                or ticket.plan_sha256 != self.plan.semantic_sha256
                or ticket.account_id != self.plan.account_id
                or ticket.attempt_id != self.plan.attempt_id
                or ticket.lookup_correlation_sha256 != self.plan.lookup_correlation_sha256
                or ticket.recovery_deadline_at != self.plan.recovery_deadline_at
                or position is None
                or position <= prior_position
                or claim.dispatch_event_id in dispatch_event_ids
                or ticket.slot_id not in self.consumed_slot_ids
            ):
                raise UnknownSubmissionRecoveryPersistenceConflict(
                    "recovery progress dispatch chain conflicts with its plan"
                )
            slot = self.plan.slots[position]
            if (
                ticket.slot_sha256 != slot.semantic_sha256
                or ticket.scheduled_at != slot.scheduled_at
            ):
                raise UnknownSubmissionRecoveryPersistenceConflict(
                    "recovery progress dispatch conflicts with its exact slot"
                )
            prior_position = position
            dispatch_event_ids.add(claim.dispatch_event_id)

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


def _recovery_dispatch_progress(
    *,
    claim: UnknownSubmissionRecoveryClaim,
    lookup_receipt: AlpacaPaperAuthenticatedLookupReceipt | None,
) -> UnknownSubmissionRecoveryDispatchProgress:
    progress = object.__new__(UnknownSubmissionRecoveryDispatchProgress)
    object.__setattr__(progress, "claim", claim)
    object.__setattr__(progress, "lookup_receipt", lookup_receipt)
    progress.__post_init__()
    return progress


def _recovery_progress(
    *,
    plan: UnknownSubmissionRecoveryPlan,
    dispatches: tuple[UnknownSubmissionRecoveryDispatchProgress, ...],
    consumed_slot_ids: tuple[str, ...],
    issuance_status: RecoveryClaimOutcome,
) -> UnknownSubmissionRecoveryProgress:
    progress = object.__new__(UnknownSubmissionRecoveryProgress)
    object.__setattr__(progress, "plan", plan)
    object.__setattr__(progress, "dispatches", dispatches)
    object.__setattr__(progress, "consumed_slot_ids", consumed_slot_ids)
    object.__setattr__(progress, "issuance_status", issuance_status)
    progress.__post_init__()
    return progress


@dataclass(frozen=True, slots=True)
class _RecoveryScheduleEvent:
    plan_id: str
    plan_sha256: str
    account_id: str
    attempt_id: str
    sequence_number: int
    kind: RecoveryScheduleEventKind
    previous_event_sha256: str | None
    committed_at: datetime
    evaluation_id: str | None
    evaluation_sha256: str | None
    evaluation_payload: str | None
    consumed_slot_ids: tuple[str, ...]
    coalesced_slot_ids: tuple[str, ...]
    selected_slot_ordinal: int | None
    selected_slot_id: str | None
    selected_slot_sha256: str | None
    selected_scheduled_at: datetime | None
    ticket_id: str | None
    ticket_sha256: str | None
    claim_issued_at: datetime | None
    claim_valid_until: datetime | None
    source_dispatch_event_id: str | None
    source_dispatch_event_sha256: str | None
    lookup_receipt_id: str | None
    lookup_receipt_sha256: str | None
    fence_receipt: AccountFenceReceipt

    def _material(self) -> tuple[object, ...]:
        return (
            UNKNOWN_SUBMISSION_RECOVERY_PERSISTENCE_CONTRACT_VERSION,
            "schedule_event",
            self.plan_id,
            self.plan_sha256,
            self.account_id,
            self.attempt_id,
            self.sequence_number,
            self.kind.value,
            self.previous_event_sha256,
            self.committed_at,
            self.evaluation_id,
            self.evaluation_sha256,
            self.evaluation_payload,
            self.consumed_slot_ids,
            self.coalesced_slot_ids,
            self.selected_slot_ordinal,
            self.selected_slot_id,
            self.selected_slot_sha256,
            self.selected_scheduled_at,
            self.ticket_id,
            self.ticket_sha256,
            self.claim_issued_at,
            self.claim_valid_until,
            self.source_dispatch_event_id,
            self.source_dispatch_event_sha256,
            self.lookup_receipt_id,
            self.lookup_receipt_sha256,
            self.fence_receipt.semantic_sha256,
        )

    @property
    def event_id(self) -> str:
        return _sha256(
            (
                UNKNOWN_SUBMISSION_RECOVERY_PERSISTENCE_CONTRACT_VERSION,
                "schedule_event_identity",
                self.plan_id,
                self.sequence_number,
                self.kind.value,
                self.previous_event_sha256,
                self.committed_at,
                self.ticket_id,
                self.lookup_receipt_id,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._material())


def _event_values(event: _RecoveryScheduleEvent) -> dict[str, object]:
    fence = event.fence_receipt
    return {
        "event_id": event.event_id,
        "plan_id": event.plan_id,
        "plan_sha256": event.plan_sha256,
        "account_id": event.account_id,
        "attempt_id": event.attempt_id,
        "sequence_number": event.sequence_number,
        "kind": event.kind.value,
        "previous_event_sha256": event.previous_event_sha256,
        "committed_at": event.committed_at,
        "evaluation_id": event.evaluation_id,
        "evaluation_sha256": event.evaluation_sha256,
        "evaluation_payload": event.evaluation_payload,
        "consumed_slot_ids_payload": _ids_payload(event.consumed_slot_ids),
        "coalesced_slot_ids_payload": _ids_payload(event.coalesced_slot_ids),
        "selected_slot_ordinal": event.selected_slot_ordinal,
        "selected_slot_id": event.selected_slot_id,
        "selected_slot_sha256": event.selected_slot_sha256,
        "selected_scheduled_at": event.selected_scheduled_at,
        "ticket_id": event.ticket_id,
        "ticket_sha256": event.ticket_sha256,
        "claim_issued_at": event.claim_issued_at,
        "claim_valid_until": event.claim_valid_until,
        "source_dispatch_event_id": event.source_dispatch_event_id,
        "source_dispatch_event_sha256": event.source_dispatch_event_sha256,
        "lookup_receipt_id": event.lookup_receipt_id,
        "lookup_receipt_sha256": event.lookup_receipt_sha256,
        "fence_owner_id": fence.fence.owner_id,
        "fence_lease_id": fence.fence.lease_id,
        "fence_fencing_generation": fence.fence.fencing_generation,
        "fence_sha256": fence.fence.semantic_sha256,
        "fence_policy_sha256": fence.policy_sha256,
        "fence_lease_sha256": fence.lease_sha256,
        "fence_receipt_sha256": fence.semantic_sha256,
        "fence_valid_until": fence.valid_until,
        "canonical_payload": event.canonical_json,
        "semantic_sha256": event.semantic_sha256,
    }


def _fence_from_row(
    connection: Connection,
    row: RowMapping,
) -> AccountFenceReceipt:
    lease_row = (
        connection.execute(
            sa.select(phase2_account_leases).where(
                phase2_account_leases.c.account_id == row["account_id"],
                phase2_account_leases.c.fencing_generation == row["fence_fencing_generation"],
                phase2_account_leases.c.lease_sha256 == row["fence_lease_sha256"],
            )
        )
        .mappings()
        .one_or_none()
    )
    if lease_row is None:
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery event references a missing fence lease"
        )
    try:
        lease = account_lease_from_row(lease_row)
        committed_at = _required_datetime(row, "committed_at")
        valid_until = _required_datetime(row, "fence_valid_until")
        receipt = _account_fence_receipt(
            fence=lease.fence,
            validated_at=committed_at,
            valid_until=valid_until,
            policy_sha256=lease.policy_sha256,
            lease_sha256=lease.semantic_sha256,
        )
        if (
            lease.owner_id != row["fence_owner_id"]
            or lease.lease_id != row["fence_lease_id"]
            or lease.fence.semantic_sha256 != row["fence_sha256"]
            or lease.policy_sha256 != row["fence_policy_sha256"]
            or lease.expires_at != valid_until
            or receipt.semantic_sha256 != row["fence_receipt_sha256"]
        ):
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "recovery event fence conflicts with its exact lease"
            )
        _authenticate_fence_position_at(
            connection,
            receipt,
            checked_at=committed_at,
        )
        return receipt
    except (AccountCoordinatorError, AlpacaPaperLookupRuntimeError, ValueError) as error:
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery event fence source is malformed"
        ) from error


def _event_from_row(
    connection: Connection,
    row: RowMapping,
) -> _RecoveryScheduleEvent:
    try:
        kind = RecoveryScheduleEventKind(_required_text(row, "kind"))
    except ValueError as error:
        raise UnknownSubmissionRecoveryPersistenceError(
            "recovery event kind is malformed"
        ) from error
    event = _RecoveryScheduleEvent(
        plan_id=_required_text(row, "plan_id"),
        plan_sha256=_required_text(row, "plan_sha256"),
        account_id=_required_text(row, "account_id"),
        attempt_id=_required_text(row, "attempt_id"),
        sequence_number=_required_int(row, "sequence_number"),
        kind=kind,
        previous_event_sha256=_optional_text(row, "previous_event_sha256"),
        committed_at=_required_datetime(row, "committed_at"),
        evaluation_id=_optional_text(row, "evaluation_id"),
        evaluation_sha256=_optional_text(row, "evaluation_sha256"),
        evaluation_payload=_optional_text(row, "evaluation_payload"),
        consumed_slot_ids=_ids_from_payload(
            row["consumed_slot_ids_payload"],
            "consumed slot payload",
        ),
        coalesced_slot_ids=_ids_from_payload(
            row["coalesced_slot_ids_payload"],
            "coalesced slot payload",
        ),
        selected_slot_ordinal=_optional_int(row, "selected_slot_ordinal"),
        selected_slot_id=_optional_text(row, "selected_slot_id"),
        selected_slot_sha256=_optional_text(row, "selected_slot_sha256"),
        selected_scheduled_at=_optional_datetime(row, "selected_scheduled_at"),
        ticket_id=_optional_text(row, "ticket_id"),
        ticket_sha256=_optional_text(row, "ticket_sha256"),
        claim_issued_at=_optional_datetime(row, "claim_issued_at"),
        claim_valid_until=_optional_datetime(row, "claim_valid_until"),
        source_dispatch_event_id=_optional_text(row, "source_dispatch_event_id"),
        source_dispatch_event_sha256=_optional_text(
            row,
            "source_dispatch_event_sha256",
        ),
        lookup_receipt_id=_optional_text(row, "lookup_receipt_id"),
        lookup_receipt_sha256=_optional_text(row, "lookup_receipt_sha256"),
        fence_receipt=_fence_from_row(connection, row),
    )
    values = _event_values(event)
    for field_name, expected in values.items():
        actual: object = row[field_name]
        if isinstance(expected, datetime):
            if not isinstance(actual, datetime):
                raise UnknownSubmissionRecoveryPersistenceConflict(
                    "recovery event SQL datetime is malformed"
                )
            actual = as_aware_utc(actual)
        if actual != expected:
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "recovery event conflicts with its canonical SQL content"
            )
    return event


def _canonical_consumed(
    plan: UnknownSubmissionRecoveryPlan,
    slot_ids: tuple[str, ...],
) -> tuple[str, ...]:
    selected = set(slot_ids)
    if len(selected) != len(slot_ids):
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery history consumes a slot more than once"
        )
    canonical = tuple(slot.slot_id for slot in plan.slots if slot.slot_id in selected)
    if len(canonical) != len(slot_ids):
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery history consumes a foreign slot"
        )
    return canonical


def _claim_from_dispatch(
    event: _RecoveryScheduleEvent,
    ticket: UnknownSubmissionRecoveryTicket,
) -> UnknownSubmissionRecoveryClaim:
    if (
        event.claim_issued_at is None
        or event.claim_valid_until is None
        or event.ticket_id != ticket.ticket_id
        or event.ticket_sha256 != ticket.semantic_sha256
    ):
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery dispatch lacks its exact ticket claim"
        )
    return UnknownSubmissionRecoveryClaim(
        ticket=ticket,
        dispatch_event_id=event.event_id,
        dispatch_event_sha256=event.semantic_sha256,
        issued_at=event.claim_issued_at,
        valid_until=event.claim_valid_until,
    )


def _authenticate_observation(
    connection: Connection,
    *,
    plan: UnknownSubmissionRecoveryPlan,
    event: _RecoveryScheduleEvent,
    dispatch_event: _RecoveryScheduleEvent,
    claim: UnknownSubmissionRecoveryClaim,
) -> AlpacaPaperAuthenticatedLookupReceipt:
    if (
        event.lookup_receipt_id is None
        or event.lookup_receipt_sha256 is None
        or event.source_dispatch_event_id != dispatch_event.event_id
        or event.source_dispatch_event_sha256 != dispatch_event.semantic_sha256
    ):
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery observation lacks its exact dispatch source"
        )
    receipt = _lookup_receipt_by_id(connection, event.lookup_receipt_id)
    if receipt is None or receipt.semantic_sha256 != event.lookup_receipt_sha256:
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery observation references a missing lookup receipt"
        )
    history = _lookup_history(
        connection,
        account_id=receipt.account_id,
        attempt_id=receipt.attempt_id,
    )
    if receipt not in history:
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery observation receipt is outside authenticated lookup history"
        )
    _authenticate_lookup_sources(connection, receipt)
    demand = create_unknown_submission_recovery_demand(
        ticket=claim.ticket,
        requested_at=receipt.requested_at,
    )
    ingress = _authenticate_ingress_source(connection, receipt)
    dispatch_fence = dispatch_event.fence_receipt
    if (
        receipt.account_id != plan.account_id
        or receipt.attempt_id != plan.attempt_id
        or receipt.attempt_sha256 != plan.attempt_sha256
        or receipt.client_order_id != plan.client_order_id
        or receipt.terminal_event_id != plan.unknown_event_id
        or receipt.terminal_event_sha256 != plan.unknown_event_sha256
        or receipt.demand_id != demand.demand_id
        or receipt.demand_sha256 != demand.semantic_sha256
        or receipt.requested_at < claim.issued_at
        or receipt.requested_at >= claim.valid_until
        or receipt.ingress_receipt_id != claim.ticket.delivery_id
        or ingress.delivery.delivery_idempotency_key != claim.ticket.delivery_idempotency_key
        or receipt.fence_owner_id != dispatch_fence.fence.owner_id
        or receipt.fence_lease_id != dispatch_fence.fence.lease_id
        or receipt.fence_fencing_generation != dispatch_fence.fence.fencing_generation
        or receipt.fence_sha256 != dispatch_fence.fence.semantic_sha256
        or receipt.fence_policy_sha256 != dispatch_fence.policy_sha256
        or receipt.pre_fence_lease_sha256 != dispatch_fence.lease_sha256
        or receipt.post_fence_lease_sha256 != dispatch_fence.lease_sha256
    ):
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery observation conflicts with its plan or one-shot claim"
        )
    return receipt


@dataclass(frozen=True, slots=True)
class _VerifiedHistory:
    events: tuple[_RecoveryScheduleEvent, ...]
    consumed_slot_ids: tuple[str, ...]
    dispatch_claims: dict[str, UnknownSubmissionRecoveryClaim]
    observation_receipts: dict[str, AlpacaPaperAuthenticatedLookupReceipt]
    observed_dispatch_ids: frozenset[str]
    issuance_status: RecoveryClaimOutcome

    @property
    def exhausted(self) -> bool:
        return self.issuance_status is RecoveryClaimOutcome.EXHAUSTED

    @property
    def terminal(self) -> bool:
        return self.issuance_status in {
            RecoveryClaimOutcome.EXHAUSTED,
            RecoveryClaimOutcome.RECONCILIATION_REQUIRED,
            RecoveryClaimOutcome.BLOCKED_MISMATCH,
        }

    def active_claim_at(
        self,
        checked_at: datetime,
    ) -> UnknownSubmissionRecoveryClaim | None:
        active = tuple(
            claim
            for event_id, claim in self.dispatch_claims.items()
            if event_id not in self.observed_dispatch_ids and claim.is_active_at(checked_at)
        )
        if len(active) > 1:
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "recovery history contains overlapping active claims"
            )
        return None if not active else active[0]


def _issuance_status_after_observation(
    current: RecoveryClaimOutcome,
    receipt: AlpacaPaperAuthenticatedLookupReceipt,
) -> RecoveryClaimOutcome:
    if current is RecoveryClaimOutcome.EXHAUSTED:
        return current
    if receipt.outcome in {
        AlpacaPaperAuthenticatedLookupOutcome.FOUND_MISMATCH,
        AlpacaPaperAuthenticatedLookupOutcome.SECURITY_IDENTITY_MISMATCH,
    }:
        return RecoveryClaimOutcome.BLOCKED_MISMATCH
    if (
        receipt.outcome is AlpacaPaperAuthenticatedLookupOutcome.FOUND_MATCHED
        and current is not RecoveryClaimOutcome.BLOCKED_MISMATCH
    ):
        return RecoveryClaimOutcome.RECONCILIATION_REQUIRED
    return current


def _history(
    connection: Connection,
    plan: UnknownSubmissionRecoveryPlan,
) -> _VerifiedHistory:
    rows = tuple(
        connection.execute(
            sa.select(phase4_unknown_lookup_recovery_events)
            .where(phase4_unknown_lookup_recovery_events.c.plan_id == plan.plan_id)
            .order_by(phase4_unknown_lookup_recovery_events.c.sequence_number)
        ).mappings()
    )
    events: list[_RecoveryScheduleEvent] = []
    consumed: tuple[str, ...] = ()
    dispatches: dict[str, tuple[_RecoveryScheduleEvent, UnknownSubmissionRecoveryClaim]] = {}
    observations: dict[str, AlpacaPaperAuthenticatedLookupReceipt] = {}
    observed: set[str] = set()
    issuance_status = RecoveryClaimOutcome.ACTIVE
    previous: _RecoveryScheduleEvent | None = None
    for row in rows:
        event = _event_from_row(connection, row)
        if (
            event.plan_id != plan.plan_id
            or event.plan_sha256 != plan.semantic_sha256
            or event.account_id != plan.account_id
            or event.attempt_id != plan.attempt_id
            or event.sequence_number != len(events) + 1
            or event.previous_event_sha256
            != (None if previous is None else previous.semantic_sha256)
            or (previous is not None and event.committed_at < previous.committed_at)
        ):
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "recovery event chain is discontinuous or regressing"
            )
        if event.kind is RecoveryScheduleEventKind.DISPATCH:
            if issuance_status is not RecoveryClaimOutcome.ACTIVE:
                raise UnknownSubmissionRecoveryPersistenceConflict(
                    "recovery dispatch appears after terminal schedule evidence"
                )
            evaluation = evaluate_unknown_submission_recovery(
                plan=plan,
                evaluated_at=event.committed_at,
                consumed_slot_ids=consumed,
            )
            ticket = evaluation.selected_ticket
            if (
                evaluation.outcome is not RecoveryScheduleOutcome.DUE
                or ticket is None
                or event.evaluation_id != evaluation.evaluation_id
                or event.evaluation_sha256 != evaluation.semantic_sha256
                or event.evaluation_payload != evaluation.canonical_json
                or event.coalesced_slot_ids != evaluation.coalesced_slot_ids
                or event.selected_slot_id != ticket.slot_id
                or event.selected_slot_sha256 != ticket.slot_sha256
                or event.selected_scheduled_at != ticket.scheduled_at
                or event.ticket_id != ticket.ticket_id
                or event.ticket_sha256 != ticket.semantic_sha256
            ):
                raise UnknownSubmissionRecoveryPersistenceConflict(
                    "recovery dispatch does not reproduce its pure due evaluation"
                )
            slot = next(slot for slot in plan.slots if slot.slot_id == ticket.slot_id)
            if event.selected_slot_ordinal != slot.ordinal:
                raise UnknownSubmissionRecoveryPersistenceConflict(
                    "recovery dispatch selected slot ordinal conflicts"
                )
            consumed = _canonical_consumed(
                plan,
                (*consumed, *evaluation.coalesced_slot_ids, ticket.slot_id),
            )
            if event.consumed_slot_ids != consumed:
                raise UnknownSubmissionRecoveryPersistenceConflict(
                    "recovery dispatch consumed-slot projection conflicts"
                )
            claim = _claim_from_dispatch(event, ticket)
            if any(
                existing.is_active_at(event.committed_at)
                and existing.dispatch_event_id not in observed
                for _, existing in dispatches.values()
            ):
                raise UnknownSubmissionRecoveryPersistenceConflict(
                    "recovery dispatch overlaps an active one-shot claim"
                )
            dispatches[event.event_id] = (event, claim)
        elif event.kind is RecoveryScheduleEventKind.EXHAUSTED:
            if issuance_status is not RecoveryClaimOutcome.ACTIVE:
                raise UnknownSubmissionRecoveryPersistenceConflict(
                    "recovery exhaustion appears after terminal schedule evidence"
                )
            evaluation = evaluate_unknown_submission_recovery(
                plan=plan,
                evaluated_at=event.committed_at,
                consumed_slot_ids=consumed,
            )
            if (
                evaluation.outcome is not RecoveryScheduleOutcome.EXHAUSTED
                or event.evaluation_id != evaluation.evaluation_id
                or event.evaluation_sha256 != evaluation.semantic_sha256
                or event.evaluation_payload != evaluation.canonical_json
                or event.coalesced_slot_ids != evaluation.coalesced_slot_ids
            ):
                raise UnknownSubmissionRecoveryPersistenceConflict(
                    "recovery exhaustion does not reproduce its pure evaluation"
                )
            consumed = _canonical_consumed(
                plan,
                (*consumed, *evaluation.coalesced_slot_ids),
            )
            if event.consumed_slot_ids != consumed:
                raise UnknownSubmissionRecoveryPersistenceConflict(
                    "recovery exhaustion consumed-slot projection conflicts"
                )
            issuance_status = RecoveryClaimOutcome.EXHAUSTED
        else:
            if event.consumed_slot_ids != consumed or event.coalesced_slot_ids:
                raise UnknownSubmissionRecoveryPersistenceConflict(
                    "recovery observation changed the slot projection"
                )
            source_id = event.source_dispatch_event_id
            if source_id is None or source_id not in dispatches or source_id in observed:
                raise UnknownSubmissionRecoveryPersistenceConflict(
                    "recovery observation dispatch source is missing or reused"
                )
            dispatch_event, claim = dispatches[source_id]
            receipt = _authenticate_observation(
                connection,
                plan=plan,
                event=event,
                dispatch_event=dispatch_event,
                claim=claim,
            )
            observations[source_id] = receipt
            observed.add(source_id)
            issuance_status = _issuance_status_after_observation(
                issuance_status,
                receipt,
            )
        events.append(event)
        previous = event
    claims = {event_id: claim for event_id, (_, claim) in dispatches.items()}
    verified = _VerifiedHistory(
        events=tuple(events),
        consumed_slot_ids=consumed,
        dispatch_claims=claims,
        observation_receipts=observations,
        observed_dispatch_ids=frozenset(observed),
        issuance_status=issuance_status,
    )
    _verify_head(connection, plan, verified)
    return verified


def _head_row(
    connection: Connection,
    plan_id: str,
) -> RowMapping | None:
    return (
        connection.execute(
            sa.select(phase4_unknown_lookup_recovery_heads).where(
                phase4_unknown_lookup_recovery_heads.c.plan_id == plan_id
            )
        )
        .mappings()
        .one_or_none()
    )


def _verify_head(
    connection: Connection,
    plan: UnknownSubmissionRecoveryPlan,
    history: _VerifiedHistory,
) -> None:
    row = _head_row(connection, plan.plan_id)
    if not history.events:
        if row is not None:
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "recovery head exists without schedule events"
            )
        return
    terminal = history.events[-1]
    if row is None:
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery events exist without a durable head"
        )
    expected = {
        "plan_id": plan.plan_id,
        "plan_sha256": plan.semantic_sha256,
        "account_id": plan.account_id,
        "attempt_id": plan.attempt_id,
        "last_sequence_number": terminal.sequence_number,
        "last_event_id": terminal.event_id,
        "last_event_sha256": terminal.semantic_sha256,
        "last_committed_at": terminal.committed_at,
        "consumed_slot_ids_payload": _ids_payload(history.consumed_slot_ids),
        "consumed_slot_count": len(history.consumed_slot_ids),
        "issuance_status": history.issuance_status.value,
    }
    for field_name, expected_value in expected.items():
        actual: object = row[field_name]
        if isinstance(expected_value, datetime):
            if not isinstance(actual, datetime):
                raise UnknownSubmissionRecoveryPersistenceConflict(
                    "recovery head timestamp is malformed"
                )
            actual = as_aware_utc(actual)
        if actual != expected_value:
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "recovery head conflicts with authenticated event history"
            )


def _append_event(
    connection: Connection,
    *,
    plan: UnknownSubmissionRecoveryPlan,
    history: _VerifiedHistory,
    event: _RecoveryScheduleEvent,
    observation_receipt: AlpacaPaperAuthenticatedLookupReceipt | None = None,
) -> None:
    previous = None if not history.events else history.events[-1]
    if event.sequence_number != (
        1 if previous is None else previous.sequence_number + 1
    ) or event.previous_event_sha256 != (None if previous is None else previous.semantic_sha256):
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery append does not extend the exact durable head"
        )
    if previous is not None and event.committed_at < previous.committed_at:
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery append commit time regresses behind its durable predecessor"
        )
    values = _event_values(event)
    try:
        connection.execute(sa.insert(phase4_unknown_lookup_recovery_events).values(**values))
    except IntegrityError as error:
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery event conflicts with durable history"
        ) from error
    consumed_payload = _ids_payload(event.consumed_slot_ids)
    if event.kind is RecoveryScheduleEventKind.OBSERVATION:
        if observation_receipt is None:
            raise UnknownSubmissionRecoveryPersistenceError(
                "recovery observation append requires its authenticated receipt"
            )
        status = _issuance_status_after_observation(
            history.issuance_status,
            observation_receipt,
        )
    else:
        if observation_receipt is not None:
            raise UnknownSubmissionRecoveryPersistenceError(
                "non-observation recovery append cannot carry a lookup receipt"
            )
        if history.issuance_status is not RecoveryClaimOutcome.ACTIVE:
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "terminal recovery schedule cannot append issuance events"
            )
        status = (
            RecoveryClaimOutcome.EXHAUSTED
            if event.kind is RecoveryScheduleEventKind.EXHAUSTED
            else RecoveryClaimOutcome.ACTIVE
        )
    if previous is None:
        try:
            connection.execute(
                sa.insert(phase4_unknown_lookup_recovery_heads).values(
                    plan_id=plan.plan_id,
                    plan_sha256=plan.semantic_sha256,
                    account_id=plan.account_id,
                    attempt_id=plan.attempt_id,
                    last_sequence_number=event.sequence_number,
                    last_event_id=event.event_id,
                    last_event_sha256=event.semantic_sha256,
                    last_committed_at=event.committed_at,
                    consumed_slot_ids_payload=consumed_payload,
                    consumed_slot_count=len(event.consumed_slot_ids),
                    issuance_status=status.value,
                )
            )
        except IntegrityError as error:
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "recovery head conflicts with first event"
            ) from error
    else:
        updated = connection.execute(
            sa.update(phase4_unknown_lookup_recovery_heads)
            .where(
                phase4_unknown_lookup_recovery_heads.c.plan_id == plan.plan_id,
                phase4_unknown_lookup_recovery_heads.c.last_sequence_number
                == previous.sequence_number,
                phase4_unknown_lookup_recovery_heads.c.last_event_id == previous.event_id,
                phase4_unknown_lookup_recovery_heads.c.last_event_sha256
                == previous.semantic_sha256,
                phase4_unknown_lookup_recovery_heads.c.last_committed_at == previous.committed_at,
                phase4_unknown_lookup_recovery_heads.c.consumed_slot_ids_payload
                == _ids_payload(history.consumed_slot_ids),
                phase4_unknown_lookup_recovery_heads.c.issuance_status
                == history.issuance_status.value,
            )
            .values(
                last_sequence_number=event.sequence_number,
                last_event_id=event.event_id,
                last_event_sha256=event.semantic_sha256,
                last_committed_at=event.committed_at,
                consumed_slot_ids_payload=consumed_payload,
                consumed_slot_count=len(event.consumed_slot_ids),
                issuance_status=status.value,
            )
        )
        if updated.rowcount != 1:
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "recovery head changed during compare-and-swap append"
            )
    row = (
        connection.execute(
            sa.select(phase4_unknown_lookup_recovery_events).where(
                phase4_unknown_lookup_recovery_events.c.event_id == event.event_id
            )
        )
        .mappings()
        .one()
    )
    persisted = _event_from_row(connection, row)
    if persisted != event:
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery event failed exact SQL readback"
        )
    assert_immutable(
        phase4_unknown_lookup_recovery_events,
        event.event_id,
        row,
        values,
    )


def _require_non_regressing_schedule_time(
    history: _VerifiedHistory,
    checked_at: datetime,
) -> None:
    _require_utc(checked_at, "recovery schedule checked_at")
    if history.events and checked_at < history.events[-1].committed_at:
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "trusted recovery schedule time regresses behind durable history"
        )


def _ensure_plan(
    connection: Connection,
    plan: UnknownSubmissionRecoveryPlan,
) -> None:
    row = _plan_row(connection, plan.plan_id)
    values = immutable_unknown_submission_recovery_plan_values(plan)
    if row is not None:
        persisted = _plan_from_row(connection, row)
        if persisted != plan:
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "recovery plan identity conflicts with durable content"
            )
        assert_immutable(
            phase4_unknown_lookup_recovery_plans,
            plan.plan_id,
            row,
            values,
        )
        return
    conflicting = (
        connection.execute(
            sa.select(phase4_unknown_lookup_recovery_plans).where(
                phase4_unknown_lookup_recovery_plans.c.account_id == plan.account_id,
                phase4_unknown_lookup_recovery_plans.c.attempt_id == plan.attempt_id,
                phase4_unknown_lookup_recovery_plans.c.unknown_event_id == plan.unknown_event_id,
            )
        )
        .mappings()
        .one_or_none()
    )
    if conflicting is not None:
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "UNKNOWN attempt already has a different durable recovery plan"
        )
    try:
        connection.execute(sa.insert(phase4_unknown_lookup_recovery_plans).values(**values))
    except IntegrityError as error:
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery plan conflicts with durable sources"
        ) from error
    persisted_row = _plan_row(connection, plan.plan_id)
    if persisted_row is None or _plan_from_row(connection, persisted_row) != plan:
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery plan failed exact SQL readback"
        )
    assert_immutable(
        phase4_unknown_lookup_recovery_plans,
        plan.plan_id,
        persisted_row,
        values,
    )


def _current_attempt_for_plan(
    connection: Connection,
    plan: UnknownSubmissionRecoveryPlan,
    *,
    checked_at: datetime,
) -> CanonicalSubmissionAttempt:
    attempt = load_submission_attempt(connection, plan.attempt_id)
    if attempt is None:
        raise UnknownSubmissionRecoveryPersistenceConflict("recovery plan attempt does not exist")
    freshness = _authenticate_terminal_unknown(
        connection,
        attempt,
        checked_at=checked_at,
    )
    expected = create_unknown_submission_recovery_plan(
        account_id=attempt.preparation.account_id,
        client_order_id=attempt.preparation.client_order_id,
        attempt_sha256=attempt.semantic_sha256,
        in_flight_event=attempt.events[1],
        unknown_event=attempt.events[2],
        lookup_correlation_sha256=plan.lookup_correlation_sha256,
    )
    if (
        expected != plan
        or freshness.attempt_sha256 != plan.attempt_sha256
        or freshness.terminal_event_id != plan.unknown_event_id
        or freshness.terminal_event_sha256 != plan.unknown_event_sha256
    ):
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery plan conflicts with the exact current UNKNOWN head"
        )
    return attempt


def _dispatch_event(
    *,
    plan: UnknownSubmissionRecoveryPlan,
    history: _VerifiedHistory,
    evaluation: UnknownSubmissionRecoveryEvaluation,
    fence_receipt: AccountFenceReceipt,
) -> tuple[_RecoveryScheduleEvent, UnknownSubmissionRecoveryClaim]:
    ticket = evaluation.selected_ticket
    if evaluation.outcome is not RecoveryScheduleOutcome.DUE or ticket is None:
        raise UnknownSubmissionRecoveryPersistenceError(
            "dispatch construction requires a due evaluation"
        )
    valid_until = min(
        evaluation.evaluated_at + UNKNOWN_SUBMISSION_RECOVERY_CLAIM_TTL,
        plan.recovery_deadline_at,
    )
    consumed = _canonical_consumed(
        plan,
        (
            *history.consumed_slot_ids,
            *evaluation.coalesced_slot_ids,
            ticket.slot_id,
        ),
    )
    slot = next(slot for slot in plan.slots if slot.slot_id == ticket.slot_id)
    event = _RecoveryScheduleEvent(
        plan_id=plan.plan_id,
        plan_sha256=plan.semantic_sha256,
        account_id=plan.account_id,
        attempt_id=plan.attempt_id,
        sequence_number=len(history.events) + 1,
        kind=RecoveryScheduleEventKind.DISPATCH,
        previous_event_sha256=(None if not history.events else history.events[-1].semantic_sha256),
        committed_at=evaluation.evaluated_at,
        evaluation_id=evaluation.evaluation_id,
        evaluation_sha256=evaluation.semantic_sha256,
        evaluation_payload=evaluation.canonical_json,
        consumed_slot_ids=consumed,
        coalesced_slot_ids=evaluation.coalesced_slot_ids,
        selected_slot_ordinal=slot.ordinal,
        selected_slot_id=slot.slot_id,
        selected_slot_sha256=slot.semantic_sha256,
        selected_scheduled_at=slot.scheduled_at,
        ticket_id=ticket.ticket_id,
        ticket_sha256=ticket.semantic_sha256,
        claim_issued_at=evaluation.evaluated_at,
        claim_valid_until=valid_until,
        source_dispatch_event_id=None,
        source_dispatch_event_sha256=None,
        lookup_receipt_id=None,
        lookup_receipt_sha256=None,
        fence_receipt=fence_receipt,
    )
    claim = UnknownSubmissionRecoveryClaim(
        ticket=ticket,
        dispatch_event_id=event.event_id,
        dispatch_event_sha256=event.semantic_sha256,
        issued_at=evaluation.evaluated_at,
        valid_until=valid_until,
    )
    return event, claim


def _exhausted_event(
    *,
    plan: UnknownSubmissionRecoveryPlan,
    history: _VerifiedHistory,
    evaluation: UnknownSubmissionRecoveryEvaluation,
    fence_receipt: AccountFenceReceipt,
) -> _RecoveryScheduleEvent:
    if evaluation.outcome is not RecoveryScheduleOutcome.EXHAUSTED:
        raise UnknownSubmissionRecoveryPersistenceError(
            "exhaustion construction requires an exhausted evaluation"
        )
    consumed = _canonical_consumed(
        plan,
        (*history.consumed_slot_ids, *evaluation.coalesced_slot_ids),
    )
    return _RecoveryScheduleEvent(
        plan_id=plan.plan_id,
        plan_sha256=plan.semantic_sha256,
        account_id=plan.account_id,
        attempt_id=plan.attempt_id,
        sequence_number=len(history.events) + 1,
        kind=RecoveryScheduleEventKind.EXHAUSTED,
        previous_event_sha256=(None if not history.events else history.events[-1].semantic_sha256),
        committed_at=evaluation.evaluated_at,
        evaluation_id=evaluation.evaluation_id,
        evaluation_sha256=evaluation.semantic_sha256,
        evaluation_payload=evaluation.canonical_json,
        consumed_slot_ids=consumed,
        coalesced_slot_ids=evaluation.coalesced_slot_ids,
        selected_slot_ordinal=None,
        selected_slot_id=None,
        selected_slot_sha256=None,
        selected_scheduled_at=None,
        ticket_id=None,
        ticket_sha256=None,
        claim_issued_at=None,
        claim_valid_until=None,
        source_dispatch_event_id=None,
        source_dispatch_event_sha256=None,
        lookup_receipt_id=None,
        lookup_receipt_sha256=None,
        fence_receipt=fence_receipt,
    )


def _observation_event(
    *,
    plan: UnknownSubmissionRecoveryPlan,
    history: _VerifiedHistory,
    claim: UnknownSubmissionRecoveryClaim,
    receipt: AlpacaPaperAuthenticatedLookupReceipt,
    fence_receipt: AccountFenceReceipt,
) -> _RecoveryScheduleEvent:
    return _RecoveryScheduleEvent(
        plan_id=plan.plan_id,
        plan_sha256=plan.semantic_sha256,
        account_id=plan.account_id,
        attempt_id=plan.attempt_id,
        sequence_number=len(history.events) + 1,
        kind=RecoveryScheduleEventKind.OBSERVATION,
        previous_event_sha256=(None if not history.events else history.events[-1].semantic_sha256),
        committed_at=fence_receipt.validated_at,
        evaluation_id=None,
        evaluation_sha256=None,
        evaluation_payload=None,
        consumed_slot_ids=history.consumed_slot_ids,
        coalesced_slot_ids=(),
        selected_slot_ordinal=None,
        selected_slot_id=None,
        selected_slot_sha256=None,
        selected_scheduled_at=None,
        ticket_id=None,
        ticket_sha256=None,
        claim_issued_at=None,
        claim_valid_until=None,
        source_dispatch_event_id=claim.dispatch_event_id,
        source_dispatch_event_sha256=claim.dispatch_event_sha256,
        lookup_receipt_id=receipt.receipt_id,
        lookup_receipt_sha256=receipt.semantic_sha256,
        fence_receipt=fence_receipt,
    )


def _verify_unknown_submission_recovery_integrity(
    connection: Connection,
) -> None:
    plan_rows = tuple(
        connection.execute(
            sa.select(phase4_unknown_lookup_recovery_plans).order_by(
                phase4_unknown_lookup_recovery_plans.c.account_id,
                phase4_unknown_lookup_recovery_plans.c.attempt_id,
            )
        ).mappings()
    )
    known_plan_ids: set[str] = set()
    for row in plan_rows:
        plan = _plan_from_row(connection, row)
        known_plan_ids.add(plan.plan_id)
        _history(connection, plan)
    orphan_event = connection.scalar(
        sa.select(phase4_unknown_lookup_recovery_events.c.event_id)
        .outerjoin(
            phase4_unknown_lookup_recovery_plans,
            phase4_unknown_lookup_recovery_plans.c.plan_id
            == phase4_unknown_lookup_recovery_events.c.plan_id,
        )
        .where(phase4_unknown_lookup_recovery_plans.c.plan_id.is_(None))
        .limit(1)
    )
    orphan_head = connection.scalar(
        sa.select(phase4_unknown_lookup_recovery_heads.c.plan_id)
        .outerjoin(
            phase4_unknown_lookup_recovery_plans,
            phase4_unknown_lookup_recovery_plans.c.plan_id
            == phase4_unknown_lookup_recovery_heads.c.plan_id,
        )
        .where(phase4_unknown_lookup_recovery_plans.c.plan_id.is_(None))
        .limit(1)
    )
    if orphan_event is not None or orphan_head is not None:
        raise UnknownSubmissionRecoveryPersistenceConflict(
            "recovery schedule contains orphan durable state"
        )


def verify_unknown_submission_recovery_integrity(engine: Engine) -> None:
    """Verify all durable plans, event chains, claims, observations, and heads."""

    if not isinstance(engine, Engine) or engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise UnknownSubmissionRecoveryPersistenceError(
            "recovery schedule verification requires a supported SQL engine"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_unknown_submission_recovery_integrity(connection)


class SqlUnknownSubmissionRecoveryRepository:
    """Issue one-shot due tickets and append historical lookup observations."""

    __slots__ = ("_coordinator", "_engine")

    def __init__(
        self,
        *,
        engine: Engine,
        coordinator: SqlAccountFenceValidator,
    ) -> None:
        if not isinstance(engine, Engine) or engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise UnknownSubmissionRecoveryPersistenceError(
                "recovery schedule repository requires a supported Engine"
            )
        if not callable(getattr(coordinator, "revalidate_for_commit_in_transaction", None)):
            raise UnknownSubmissionRecoveryPersistenceError(
                "recovery schedule repository requires a SQL fence validator"
            )
        self._engine = engine
        self._coordinator = coordinator

    @property
    def runtime_store_identity(self) -> int:
        """Identify the shared SQL engine for process-local composition checks."""

        return id(self._engine)

    def _commit_fence(
        self,
        connection: Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt:
        try:
            receipt = self._coordinator.revalidate_for_commit_in_transaction(
                connection,
                fence,
            )
            if type(receipt) is not AccountFenceReceipt:
                raise TypeError("non-canonical fence receipt")
            receipt._validate()
            return receipt
        except Exception:
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "recovery schedule fence validation failed with sanitized diagnostics"
            ) from None

    def evaluate(
        self,
        plan: UnknownSubmissionRecoveryPlan,
        *,
        fence: AccountFence,
    ) -> UnknownSubmissionRecoveryScheduleDecision:
        """Evaluate trusted time and durably issue at most one new slot claim."""

        if type(plan) is not UnknownSubmissionRecoveryPlan:
            raise UnknownSubmissionRecoveryPersistenceError(
                "recovery evaluation requires an exact plan"
            )
        plan._validate()
        if type(fence) is not AccountFence or fence.account_id != plan.account_id:
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "recovery evaluation fence belongs to a different account"
            )
        try:
            with _write_transaction(self._engine) as connection:
                lock_account_capacity_serialization(connection, plan.account_id)
                commit_fence = self._commit_fence(connection, fence)
                checked_at = commit_fence.validated_at
                _current_attempt_for_plan(
                    connection,
                    plan,
                    checked_at=checked_at,
                )
                _ensure_plan(connection, plan)
                history = _history(connection, plan)
                _require_non_regressing_schedule_time(history, checked_at)
                evaluation = evaluate_unknown_submission_recovery(
                    plan=plan,
                    evaluated_at=checked_at,
                    consumed_slot_ids=history.consumed_slot_ids,
                )
                active_claim = history.active_claim_at(checked_at)
                if history.issuance_status in {
                    RecoveryClaimOutcome.RECONCILIATION_REQUIRED,
                    RecoveryClaimOutcome.BLOCKED_MISMATCH,
                }:
                    decision = UnknownSubmissionRecoveryScheduleDecision(
                        outcome=history.issuance_status,
                        evaluation=evaluation,
                        claim=None,
                    )
                elif active_claim is not None:
                    decision = UnknownSubmissionRecoveryScheduleDecision(
                        outcome=RecoveryClaimOutcome.ACTIVE,
                        evaluation=evaluation,
                        claim=active_claim,
                    )
                elif history.exhausted:
                    if evaluation.outcome is not RecoveryScheduleOutcome.EXHAUSTED:
                        raise UnknownSubmissionRecoveryPersistenceConflict(
                            "exhausted recovery head predates its immutable deadline"
                        )
                    decision = UnknownSubmissionRecoveryScheduleDecision(
                        outcome=RecoveryClaimOutcome.EXHAUSTED,
                        evaluation=evaluation,
                        claim=None,
                    )
                elif evaluation.outcome is RecoveryScheduleOutcome.DUE:
                    event, claim = _dispatch_event(
                        plan=plan,
                        history=history,
                        evaluation=evaluation,
                        fence_receipt=commit_fence,
                    )
                    _append_event(
                        connection,
                        plan=plan,
                        history=history,
                        event=event,
                    )
                    decision = UnknownSubmissionRecoveryScheduleDecision(
                        outcome=RecoveryClaimOutcome.DUE,
                        evaluation=evaluation,
                        claim=claim,
                    )
                elif evaluation.outcome is RecoveryScheduleOutcome.EXHAUSTED:
                    event = _exhausted_event(
                        plan=plan,
                        history=history,
                        evaluation=evaluation,
                        fence_receipt=commit_fence,
                    )
                    _append_event(
                        connection,
                        plan=plan,
                        history=history,
                        event=event,
                    )
                    decision = UnknownSubmissionRecoveryScheduleDecision(
                        outcome=RecoveryClaimOutcome.EXHAUSTED,
                        evaluation=evaluation,
                        claim=None,
                    )
                else:
                    decision = UnknownSubmissionRecoveryScheduleDecision(
                        outcome=RecoveryClaimOutcome.WAITING,
                        evaluation=evaluation,
                        claim=None,
                    )
                final_fence = self._commit_fence(connection, fence)
                if (
                    final_fence.fence != commit_fence.fence
                    or final_fence.policy_sha256 != commit_fence.policy_sha256
                    or final_fence.lease_sha256 != commit_fence.lease_sha256
                    or final_fence.valid_until != commit_fence.valid_until
                    or final_fence.validated_at < commit_fence.validated_at
                ):
                    raise UnknownSubmissionRecoveryPersistenceConflict(
                        "recovery fence changed before durable commit"
                    )
                return decision
        except UnknownSubmissionRecoveryError:
            raise
        except (
            AccountCoordinatorError,
            AlpacaPaperLookupRuntimeError,
            SubmissionAttemptPersistenceError,
        ):
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "durable recovery schedule authentication failed"
            ) from None

    def record_observation(
        self,
        *,
        plan_id: str,
        claim: object,
        receipt: AlpacaPaperAuthenticatedLookupReceipt,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedLookupReceipt:
        """Bind one typed Phase 4I receipt to its exact one-shot dispatch claim."""

        if (
            type(claim) is not UnknownSubmissionRecoveryClaim
            or type(receipt) is not AlpacaPaperAuthenticatedLookupReceipt
        ):
            raise UnknownSubmissionRecoveryPersistenceError(
                "recovery observation requires exact claim and receipt evidence"
            )
        claim.__post_init__()
        receipt._validate()
        ticket = claim.ticket
        if (
            type(plan_id) is not str
            or plan_id != ticket.plan_id
            or len(plan_id) != 64
            or any(character not in "0123456789abcdef" for character in plan_id)
        ):
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "recovery observation plan identity conflicts with its claim"
            )
        try:
            with _write_transaction(self._engine) as connection:
                plan_row = _plan_row(connection, plan_id)
                if plan_row is None:
                    raise UnknownSubmissionRecoveryPersistenceConflict(
                        "recovery observation plan does not exist"
                    )
                plan = _plan_from_row(connection, plan_row)
                lock_account_capacity_serialization(connection, plan.account_id)
                commit_fence = self._commit_fence(connection, fence)
                history = _history(connection, plan)
                _require_non_regressing_schedule_time(
                    history,
                    commit_fence.validated_at,
                )
                durable_claim = history.dispatch_claims.get(claim.dispatch_event_id)
                if durable_claim != claim:
                    raise UnknownSubmissionRecoveryPersistenceConflict(
                        "recovery observation ticket is not one exact durable claim"
                    )
                existing = next(
                    (
                        event
                        for event in history.events
                        if event.source_dispatch_event_id == claim.dispatch_event_id
                    ),
                    None,
                )
                if existing is not None:
                    exact_replay = (
                        existing.lookup_receipt_id == receipt.receipt_id
                        and existing.lookup_receipt_sha256 == receipt.semantic_sha256
                    )
                    if not exact_replay:
                        raise UnknownSubmissionRecoveryPersistenceConflict(
                            "recovery dispatch already has a different observation"
                        )
                else:
                    provisional = _observation_event(
                        plan=plan,
                        history=history,
                        claim=claim,
                        receipt=receipt,
                        fence_receipt=commit_fence,
                    )
                    dispatch_event = next(
                        event
                        for event in history.events
                        if event.event_id == claim.dispatch_event_id
                    )
                    authenticated_receipt = _authenticate_observation(
                        connection,
                        plan=plan,
                        event=provisional,
                        dispatch_event=dispatch_event,
                        claim=claim,
                    )
                    _append_event(
                        connection,
                        plan=plan,
                        history=history,
                        event=provisional,
                        observation_receipt=authenticated_receipt,
                    )
                final_fence = self._commit_fence(connection, fence)
                if (
                    final_fence.fence != commit_fence.fence
                    or final_fence.policy_sha256 != commit_fence.policy_sha256
                    or final_fence.lease_sha256 != commit_fence.lease_sha256
                    or final_fence.valid_until != commit_fence.valid_until
                    or final_fence.validated_at < commit_fence.validated_at
                ):
                    raise UnknownSubmissionRecoveryPersistenceConflict(
                        "recovery observation fence changed before durable commit"
                    )
                return receipt
        except UnknownSubmissionRecoveryError:
            raise
        except (
            AccountCoordinatorError,
            AlpacaPaperLookupRuntimeError,
            SubmissionAttemptPersistenceError,
        ):
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "durable recovery observation authentication failed"
            ) from None

    def load_plan(
        self,
        plan_id: str,
    ) -> UnknownSubmissionRecoveryPlan | None:
        if (
            type(plan_id) is not str
            or len(plan_id) != 64
            or any(character not in "0123456789abcdef" for character in plan_id)
        ):
            raise UnknownSubmissionRecoveryPersistenceError(
                "recovery plan ID must be a lowercase SHA-256 digest"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            row = _plan_row(connection, plan_id)
            if row is None:
                return None
            plan = _plan_from_row(connection, row)
            _history(connection, plan)
            return plan

    def load_progress(
        self,
        plan_id: str,
    ) -> UnknownSubmissionRecoveryProgress | None:
        """Load authenticated claims and attached lookup receipts in dispatch order."""

        if (
            type(plan_id) is not str
            or len(plan_id) != 64
            or any(character not in "0123456789abcdef" for character in plan_id)
        ):
            raise UnknownSubmissionRecoveryPersistenceError(
                "recovery plan ID must be a lowercase SHA-256 digest"
            )
        try:
            with _repeatable_read_transaction(self._engine) as connection:
                row = _plan_row(connection, plan_id)
                if row is None:
                    return None
                plan = _plan_from_row(connection, row)
                history = _history(connection, plan)
                return _recovery_progress(
                    plan=plan,
                    dispatches=tuple(
                        _recovery_dispatch_progress(
                            claim=history.dispatch_claims[event.event_id],
                            lookup_receipt=history.observation_receipts.get(event.event_id),
                        )
                        for event in history.events
                        if event.kind is RecoveryScheduleEventKind.DISPATCH
                    ),
                    consumed_slot_ids=history.consumed_slot_ids,
                    issuance_status=history.issuance_status,
                )
        except UnknownSubmissionRecoveryError:
            raise
        except (
            AccountCoordinatorError,
            AlpacaPaperLookupRuntimeError,
            SubmissionAttemptPersistenceError,
        ):
            raise UnknownSubmissionRecoveryPersistenceConflict(
                "durable recovery progress authentication failed"
            ) from None

    def history(
        self,
        plan_id: str,
    ) -> tuple[str, ...]:
        """Return authenticated event digests without exposing mutable authority."""

        plan = self.load_plan(plan_id)
        if plan is None:
            return ()
        with _repeatable_read_transaction(self._engine) as connection:
            row = _plan_row(connection, plan_id)
            if row is None:
                raise UnknownSubmissionRecoveryPersistenceConflict(
                    "recovery plan disappeared during authenticated read"
                )
            durable_plan = _plan_from_row(connection, row)
            return tuple(
                event.semantic_sha256 for event in _history(connection, durable_plan).events
            )


__all__ = [
    "UNKNOWN_SUBMISSION_RECOVERY_CLAIM_TTL",
    "UNKNOWN_SUBMISSION_RECOVERY_PERSISTENCE_CONTRACT_VERSION",
    "RecoveryClaimOutcome",
    "RecoveryScheduleEventKind",
    "SqlUnknownSubmissionRecoveryRepository",
    "UnknownSubmissionRecoveryClaim",
    "UnknownSubmissionRecoveryDispatchProgress",
    "UnknownSubmissionRecoveryPersistenceConflict",
    "UnknownSubmissionRecoveryPersistenceError",
    "UnknownSubmissionRecoveryProgress",
    "UnknownSubmissionRecoveryScheduleDecision",
    "immutable_unknown_submission_recovery_plan_values",
    "verify_unknown_submission_recovery_integrity",
]
