"""Pure durable operational-control contracts.

This module models the fail-closed state machine used by operators and circuit
breakers.  It performs no persistence, authentication, clock, broker, or other
I/O.  Callers must authenticate source facts and commit returned facts
atomically.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum

from packages.domain.batch_risk import BatchRiskOperationalState
from packages.domain.canonical import (
    canonical_json_bytes,
    canonical_json_text,
    canonical_persisted_decimal,
)
from packages.domain.decimal_math import DECIMAL_ARITHMETIC_VERSION, exact_decimal_sum
from packages.domain.identifiers import canonical_id

OPERATIONAL_CONTROL_CONTRACT_VERSION = "phase5a-operational-control-v1"
OPERATIONAL_CONTROL_POLICY_ID = "phase5a-severity-join-manual-rearm-policy-v1"
MAX_OPERATIONAL_CONTROL_BLOCKERS = 2_048
MAX_OPERATIONAL_CONTROL_RESIDUAL_POSITIONS = 1_024

_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class OperationalControlError(ValueError):
    """Operational-control evidence is malformed or cannot be applied."""


class OperationalControlConflict(OperationalControlError):
    """Immutable operational-control identity or history conflicts."""


class OperationalControlAbsent(OperationalControlError):
    """A command other than initialization was attempted without durable state."""


class OperationalControlRearmRejected(OperationalControlError):
    """Manual re-arm evidence is absent, stale, incomplete, or incorrectly bound."""


class OperationalControlOperationConflict(OperationalControlError):
    """A drain/flatten completion or retry conflicts with its operation attempt."""


class OperationalControlState(StrEnum):
    """Closed states ordered by increasing safety severity."""

    RUNNING = "running"
    PAUSED = "paused"
    DRAINING = "draining"
    FLATTENING = "flattening"
    HALTED = "halted"


_STATE_SEVERITY = {
    OperationalControlState.RUNNING: 0,
    OperationalControlState.PAUSED: 1,
    OperationalControlState.DRAINING: 2,
    OperationalControlState.FLATTENING: 3,
    OperationalControlState.HALTED: 4,
}


class OperationalControlActorKind(StrEnum):
    HUMAN = "human"
    SYSTEM = "system"
    CIRCUIT_BREAKER = "circuit_breaker"


class OperationalControlCommandKind(StrEnum):
    INITIALIZE_HALTED = "initialize_halted"
    PAUSE = "pause"
    DRAIN = "drain"
    FLATTEN = "flatten"
    HALT = "halt"
    TRIP = "trip"
    REARM = "rearm"


class OperationalControlOperationKind(StrEnum):
    DRAIN = "drain"
    FLATTEN = "flatten"


class OperationalControlCompletionOutcome(StrEnum):
    COMPLETED = "completed"
    INCOMPLETE = "incomplete"
    DEADLINE_EXCEEDED = "deadline_exceeded"


OPERATIONAL_CONTROL_POLICY_SHA256 = hashlib.sha256(
    canonical_json_bytes(
        (
            OPERATIONAL_CONTROL_CONTRACT_VERSION,
            "operational_control_policy",
            OPERATIONAL_CONTROL_POLICY_ID,
            tuple((state, _STATE_SEVERITY[state]) for state in OperationalControlState),
            "absence_is_distinct_and_maps_fail_closed_to_halted",
            "initialize_halted_is_the_only_absent_transition",
            "non_rearm_commands_apply_the_severity_join",
            "commands_are_account_actor_and_idempotency_bound",
            "no_op_commands_remain_audited_blockers",
            "breaker_recovery_never_lowers_state",
            "only_exact_head_bound_authenticated_human_rearm_to_running_lowers_state",
            "rearm_requires_fresh_health_clean_reconciliation_and_all_dispositions",
            "operation_completion_never_auto_resumes",
            "incomplete_operations_retry_with_distinct_attempts_at_unchanged_severity",
            "unrelated_noops_preserve_the_active_operation_attempt",
            "bounded_blocker_projection_overflow_is_sticky_and_blocks_rearm",
            "batch_risk_v2_semantics_remain_unchanged",
            DECIMAL_ARITHMETIC_VERSION,
            MAX_OPERATIONAL_CONTROL_BLOCKERS,
            MAX_OPERATIONAL_CONTROL_RESIDUAL_POSITIONS,
        )
    )
).hexdigest()


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: str, field_name: str, *, maximum: int = 128) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise OperationalControlError(f"{field_name} must be a non-empty, trimmed string")
    if len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise OperationalControlError(f"{field_name} contains unsupported text")


def _require_idempotency_key(value: str, field_name: str) -> None:
    if type(value) is not str or _IDEMPOTENCY_KEY.fullmatch(value) is None:
        raise OperationalControlError(f"{field_name} must contain 8-128 safe visible characters")


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise OperationalControlError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_optional_sha256(value: str | None, field_name: str) -> None:
    if value is not None:
        _require_sha256(value, field_name)


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise OperationalControlError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise OperationalControlError(f"{field_name} must be UTC")


def _require_sorted_unique(
    values: tuple[str, ...],
    field_name: str,
    *,
    maximum: int = MAX_OPERATIONAL_CONTROL_BLOCKERS,
) -> None:
    if type(values) is not tuple:
        raise OperationalControlError(f"{field_name} must be an exact tuple")
    if len(values) > maximum:
        raise OperationalControlError(f"{field_name} exceeds its bounded member count")
    for value in values:
        _require_text(value, field_name)
    if values != tuple(sorted(values)) or len(values) != len(set(values)):
        raise OperationalControlError(f"{field_name} must be sorted and unique")


def _state_join(
    left: OperationalControlState,
    right: OperationalControlState,
) -> OperationalControlState:
    return left if _STATE_SEVERITY[left] >= _STATE_SEVERITY[right] else right


@dataclass(frozen=True, slots=True)
class OperationalControlActor:
    """Immutable principal and authority proof bound into one command."""

    actor_id: str
    kind: OperationalControlActorKind
    authority_sha256: str
    authenticated_at: datetime | None

    def __post_init__(self) -> None:
        _require_text(self.actor_id, "control actor ID")
        if type(self.kind) is not OperationalControlActorKind:
            raise OperationalControlError("control actor kind is unsupported")
        _require_sha256(self.authority_sha256, "control actor authority_sha256")
        if self.kind is OperationalControlActorKind.HUMAN:
            if self.authenticated_at is None:
                raise OperationalControlError(
                    "human control actor requires an authentication instant"
                )
            _require_utc(self.authenticated_at, "control actor authenticated_at")
        elif self.authenticated_at is not None:
            raise OperationalControlError(
                "non-human control actor cannot claim a human authentication instant"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            OPERATIONAL_CONTROL_CONTRACT_VERSION,
            "actor",
            self.actor_id,
            self.kind,
            self.authority_sha256,
            self.authenticated_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


_FIXED_COMMAND_TARGETS = {
    OperationalControlCommandKind.INITIALIZE_HALTED: OperationalControlState.HALTED,
    OperationalControlCommandKind.PAUSE: OperationalControlState.PAUSED,
    OperationalControlCommandKind.DRAIN: OperationalControlState.DRAINING,
    OperationalControlCommandKind.FLATTEN: OperationalControlState.FLATTENING,
    OperationalControlCommandKind.HALT: OperationalControlState.HALTED,
}


@dataclass(frozen=True, slots=True)
class OperationalControlCommand:
    """One actor-bound, idempotent request to update an exact control scope."""

    scope_id: str
    idempotency_key: str
    kind: OperationalControlCommandKind
    target_state: OperationalControlState
    actor: OperationalControlActor
    reason_code: str
    reason_evidence_sha256: str
    requested_at: datetime
    rearm_evidence_sha256: str | None = None
    trip_rule_id: str | None = None
    trip_policy_sha256: str | None = None
    trip_observation_sha256: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.scope_id, "control scope ID")
        _require_idempotency_key(self.idempotency_key, "control command idempotency key")
        if type(self.kind) is not OperationalControlCommandKind:
            raise OperationalControlError("control command kind is unsupported")
        if type(self.target_state) is not OperationalControlState:
            raise OperationalControlError("control command target state is unsupported")
        if type(self.actor) is not OperationalControlActor:
            raise OperationalControlError("control command actor must be exact")
        _require_text(self.reason_code, "control command reason code")
        _require_sha256(
            self.reason_evidence_sha256,
            "control command reason_evidence_sha256",
        )
        _require_utc(self.requested_at, "control command requested_at")
        if (
            self.actor.authenticated_at is not None
            and self.actor.authenticated_at > self.requested_at
        ):
            raise OperationalControlError("control command cannot predate actor authentication")
        fixed_target = _FIXED_COMMAND_TARGETS.get(self.kind)
        if fixed_target is not None and self.target_state is not fixed_target:
            raise OperationalControlError(
                f"{self.kind.value} command requires target {fixed_target.value}"
            )
        if (
            self.kind is OperationalControlCommandKind.INITIALIZE_HALTED
            and self.actor.kind is not OperationalControlActorKind.SYSTEM
        ):
            raise OperationalControlError(
                "INITIALIZE_HALTED requires an authenticated system actor"
            )
        if self.kind is OperationalControlCommandKind.TRIP:
            if self.actor.kind not in {
                OperationalControlActorKind.SYSTEM,
                OperationalControlActorKind.CIRCUIT_BREAKER,
            }:
                raise OperationalControlError("trip command requires a system or breaker actor")
            if self.target_state not in {
                OperationalControlState.PAUSED,
                OperationalControlState.HALTED,
            }:
                raise OperationalControlError("trip command may target only PAUSED or HALTED")
            _require_text(self.trip_rule_id or "", "trip command rule ID")
            _require_sha256(
                self.trip_policy_sha256 or "",
                "trip command policy_sha256",
            )
            _require_sha256(
                self.trip_observation_sha256 or "",
                "trip command observation_sha256",
            )
        elif any(
            value is not None
            for value in (
                self.trip_rule_id,
                self.trip_policy_sha256,
                self.trip_observation_sha256,
            )
        ):
            raise OperationalControlError("only a trip command may carry breaker rule evidence")
        if self.kind is OperationalControlCommandKind.REARM:
            if self.actor.kind is not OperationalControlActorKind.HUMAN:
                raise OperationalControlError("rearm command requires an authenticated human")
            _require_sha256(
                self.rearm_evidence_sha256 or "",
                "rearm command rearm_evidence_sha256",
            )
            if self.target_state is not OperationalControlState.RUNNING:
                raise OperationalControlError("rearm command must target RUNNING")
        elif self.rearm_evidence_sha256 is not None:
            raise OperationalControlError("only a rearm command may bind rearm evidence")

    @property
    def command_id(self) -> str:
        return canonical_id(
            "operational-control-command",
            OPERATIONAL_CONTROL_POLICY_SHA256,
            self.scope_id,
            self.actor.kind,
            self.actor.actor_id,
            self.idempotency_key,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            OPERATIONAL_CONTROL_CONTRACT_VERSION,
            "command",
            self.command_id,
            OPERATIONAL_CONTROL_POLICY_SHA256,
            self.scope_id,
            self.idempotency_key,
            self.kind,
            self.target_state,
            self.actor.semantic_sha256,
            self.reason_code,
            self.reason_evidence_sha256,
            self.requested_at,
            self.rearm_evidence_sha256,
            self.trip_rule_id,
            self.trip_policy_sha256,
            self.trip_observation_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


@dataclass(frozen=True, slots=True)
class OperationalControlBlockingEvent:
    """One non-running command that must be explicitly disposed before RUNNING."""

    scope_id: str
    sequence_number: int
    command_id: str
    command_sha256: str
    state: OperationalControlState
    occurred_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.scope_id, "blocking event scope ID")
        if type(self.sequence_number) is not int or self.sequence_number <= 0:
            raise OperationalControlError(
                "blocking event sequence_number must be a positive integer"
            )
        _require_text(self.command_id, "blocking event command ID")
        _require_sha256(self.command_sha256, "blocking event command_sha256")
        if (
            type(self.state) is not OperationalControlState
            or self.state is OperationalControlState.RUNNING
        ):
            raise OperationalControlError("blocking event requires a non-running state")
        _require_utc(self.occurred_at, "blocking event occurred_at")

    @property
    def event_id(self) -> str:
        return canonical_id(
            "operational-control-blocking-event",
            OPERATIONAL_CONTROL_POLICY_SHA256,
            self.scope_id,
            self.sequence_number,
            self.command_id,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            OPERATIONAL_CONTROL_CONTRACT_VERSION,
            "blocking_event",
            self.event_id,
            self.scope_id,
            self.sequence_number,
            self.command_id,
            self.command_sha256,
            self.state,
            self.occurred_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class OperationalControlOperationAttempt:
    """Distinct retryable DRAIN or FLATTEN operation within a state epoch."""

    attempt_id: str
    scope_id: str
    operation: OperationalControlOperationKind
    state_epoch_id: str
    opened_by_command_id: str
    opened_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.scope_id, "operation attempt scope ID")
        if type(self.operation) is not OperationalControlOperationKind:
            raise OperationalControlError("operation attempt kind is unsupported")
        _require_text(self.state_epoch_id, "operation attempt state epoch ID")
        _require_text(self.opened_by_command_id, "operation attempt command ID")
        expected_id = canonical_id(
            "operational-control-operation-attempt",
            OPERATIONAL_CONTROL_POLICY_SHA256,
            self.scope_id,
            self.opened_by_command_id,
        )
        if self.attempt_id != expected_id:
            raise OperationalControlConflict("operation attempt ID is not canonically derived")
        _require_utc(self.opened_at, "operation attempt opened_at")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            OPERATIONAL_CONTROL_CONTRACT_VERSION,
            "operation_attempt",
            self.attempt_id,
            self.scope_id,
            self.operation,
            self.state_epoch_id,
            self.opened_by_command_id,
            self.opened_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class OperationalControlTransition:
    """One gap-free durable audit-head revision."""

    transition_id: str
    scope_id: str
    sequence_number: int
    previous_transition_sha256: str | None
    command_id: str
    command_sha256: str
    prior_state: OperationalControlState | None
    effective_state: OperationalControlState
    state_changed: bool
    state_epoch_id: str
    blocking_events: tuple[OperationalControlBlockingEvent, ...]
    blocker_overflowed: bool
    active_operation: OperationalControlOperationAttempt | None
    decided_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.scope_id, "control transition scope ID")
        if type(self.sequence_number) is not int or self.sequence_number <= 0:
            raise OperationalControlError(
                "control transition sequence_number must be a positive integer"
            )
        expected_id = canonical_id(
            "operational-control-transition",
            OPERATIONAL_CONTROL_POLICY_SHA256,
            self.scope_id,
            self.sequence_number,
            self.command_id,
        )
        if self.transition_id != expected_id:
            raise OperationalControlConflict("control transition ID is not canonically derived")
        if self.sequence_number == 1:
            if self.previous_transition_sha256 is not None:
                raise OperationalControlConflict(
                    "initial control transition cannot have a predecessor"
                )
        else:
            _require_sha256(
                self.previous_transition_sha256 or "",
                "control transition previous_transition_sha256",
            )
        _require_text(self.command_id, "control transition command ID")
        _require_sha256(self.command_sha256, "control transition command_sha256")
        if self.sequence_number == 1:
            if self.prior_state is not None:
                raise OperationalControlConflict(
                    "initial control transition must retain absent prior state"
                )
        elif type(self.prior_state) is not OperationalControlState:
            raise OperationalControlError("control transition prior state is unsupported")
        if type(self.effective_state) is not OperationalControlState:
            raise OperationalControlError("control transition effective state is unsupported")
        if type(self.state_changed) is not bool:
            raise OperationalControlError("control transition state_changed must be exact")
        if self.state_changed != (self.prior_state is not self.effective_state):
            raise OperationalControlConflict(
                "control transition state_changed conflicts with its states"
            )
        _require_text(self.state_epoch_id, "control transition state epoch ID")
        if (self.sequence_number == 1 or self.state_changed) and (
            self.state_epoch_id != self.transition_id
        ):
            raise OperationalControlConflict(
                "new control state epoch must equal its opening transition ID"
            )
        if (
            type(self.blocking_events) is not tuple
            or len(self.blocking_events) > MAX_OPERATIONAL_CONTROL_BLOCKERS
        ):
            raise OperationalControlError("control blocking events must be an exact tuple")
        if type(self.blocker_overflowed) is not bool:
            raise OperationalControlError("blocker_overflowed must be an exact bool")
        previous_event_sequence = 0
        seen_event_ids: set[str] = set()
        for event in self.blocking_events:
            if type(event) is not OperationalControlBlockingEvent:
                raise OperationalControlError("control blocking event must be exact")
            if event.scope_id != self.scope_id:
                raise OperationalControlConflict("blocking event scope conflicts")
            if event.sequence_number <= previous_event_sequence:
                raise OperationalControlConflict(
                    "blocking events must have strictly increasing sequence numbers"
                )
            if event.sequence_number > self.sequence_number:
                raise OperationalControlConflict("blocking event follows transition head")
            if event.event_id in seen_event_ids:
                raise OperationalControlConflict("blocking event identity is duplicated")
            previous_event_sequence = event.sequence_number
            seen_event_ids.add(event.event_id)
        if self.effective_state is OperationalControlState.RUNNING:
            if self.blocking_events or self.blocker_overflowed:
                raise OperationalControlConflict("RUNNING transition cannot retain blocking events")
        elif (
            not self.blocking_events
            or self.blocking_events[-1].sequence_number != self.sequence_number
            or self.blocking_events[-1].command_id != self.command_id
        ):
            raise OperationalControlConflict(
                "non-running transition must append its command as a blocking event"
            )
        expected_operation: OperationalControlOperationKind | None = None
        if self.effective_state is OperationalControlState.DRAINING:
            expected_operation = OperationalControlOperationKind.DRAIN
        elif self.effective_state is OperationalControlState.FLATTENING:
            expected_operation = OperationalControlOperationKind.FLATTEN
        if expected_operation is None:
            if self.active_operation is not None:
                raise OperationalControlConflict("state cannot retain a drain/flatten operation")
        else:
            if (
                self.active_operation is None
                or self.active_operation.operation is not expected_operation
                or self.active_operation.scope_id != self.scope_id
                or self.active_operation.state_epoch_id != self.state_epoch_id
            ):
                raise OperationalControlConflict(
                    "control state requires an exact state-epoch-bound operation"
                )
        _require_utc(self.decided_at, "control transition decided_at")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            OPERATIONAL_CONTROL_CONTRACT_VERSION,
            "transition",
            self.transition_id,
            self.scope_id,
            self.sequence_number,
            self.previous_transition_sha256,
            self.command_id,
            self.command_sha256,
            self.prior_state,
            self.effective_state,
            self.state_changed,
            self.state_epoch_id,
            tuple(event.semantic_sha256 for event in self.blocking_events),
            self.blocker_overflowed,
            None if self.active_operation is None else self.active_operation.semantic_sha256,
            self.decided_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


@dataclass(frozen=True, slots=True)
class OperationalControlIncidentDisposition:
    """Immutable resolution proof for one exact blocking event."""

    event_id: str
    event_sha256: str
    resolution_code: str
    resolution_evidence_sha256: str
    resolved_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.event_id, "incident disposition event ID")
        _require_sha256(self.event_sha256, "incident disposition event_sha256")
        _require_text(self.resolution_code, "incident disposition resolution code")
        _require_sha256(
            self.resolution_evidence_sha256,
            "incident disposition resolution_evidence_sha256",
        )
        _require_utc(self.resolved_at, "incident disposition resolved_at")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            OPERATIONAL_CONTROL_CONTRACT_VERSION,
            "incident_disposition",
            self.event_id,
            self.event_sha256,
            self.resolution_code,
            self.resolution_evidence_sha256,
            self.resolved_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True, init=False)
class OperationalControlRearmEvidence:
    """Fresh human-bound evidence for lowering one exact non-running head."""

    scope_id: str
    current_transition_id: str
    current_transition_sha256: str
    current_state: OperationalControlState
    current_state_epoch_id: str
    target_state: OperationalControlState
    actor: OperationalControlActor
    checked_at: datetime
    expires_at: datetime
    readiness_sha256: str
    reconciliation_sha256: str
    incident_register_sha256: str
    reconciliation_clean: bool
    data_healthy: bool
    clock_healthy: bool
    working_order_ids: tuple[str, ...]
    unknown_order_ids: tuple[str, ...]
    pending_cancel_order_ids: tuple[str, ...]
    incident_dispositions: tuple[OperationalControlIncidentDisposition, ...]
    operation_completion: OperationalControlCompletion | None

    def __init__(self) -> None:
        raise TypeError(
            "OperationalControlRearmEvidence is proof-constructed by an authoritative verifier"
        )

    def __post_init__(self) -> None:
        _require_text(self.scope_id, "rearm evidence scope ID")
        _require_text(self.current_transition_id, "rearm current transition ID")
        _require_sha256(
            self.current_transition_sha256,
            "rearm current_transition_sha256",
        )
        if (
            type(self.current_state) is not OperationalControlState
            or self.current_state is OperationalControlState.RUNNING
        ):
            raise OperationalControlError("rearm evidence requires a non-running current state")
        _require_text(self.current_state_epoch_id, "rearm current state epoch ID")
        if self.target_state is not OperationalControlState.RUNNING:
            raise OperationalControlError("rearm evidence target must be RUNNING")
        if (
            type(self.actor) is not OperationalControlActor
            or self.actor.kind is not OperationalControlActorKind.HUMAN
        ):
            raise OperationalControlError("rearm evidence requires an authenticated human actor")
        _require_utc(self.checked_at, "rearm evidence checked_at")
        _require_utc(self.expires_at, "rearm evidence expires_at")
        if self.expires_at <= self.checked_at:
            raise OperationalControlError("rearm evidence expiry must follow its check")
        if self.actor.authenticated_at is None or self.actor.authenticated_at > self.checked_at:
            raise OperationalControlError("rearm evidence cannot predate human authentication")
        for digest, field_name in (
            (self.readiness_sha256, "rearm readiness_sha256"),
            (self.reconciliation_sha256, "rearm reconciliation_sha256"),
            (self.incident_register_sha256, "rearm incident_register_sha256"),
        ):
            _require_sha256(digest, field_name)
        for healthy, field_name in (
            (self.reconciliation_clean, "rearm reconciliation_clean"),
            (self.data_healthy, "rearm data_healthy"),
            (self.clock_healthy, "rearm clock_healthy"),
        ):
            if type(healthy) is not bool:
                raise OperationalControlError(f"{field_name} must be exact")
        _require_sorted_unique(self.working_order_ids, "rearm working order IDs")
        _require_sorted_unique(self.unknown_order_ids, "rearm unknown order IDs")
        _require_sorted_unique(
            self.pending_cancel_order_ids,
            "rearm pending-cancel order IDs",
        )
        if type(self.incident_dispositions) is not tuple:
            raise OperationalControlError("rearm incident dispositions must be an exact tuple")
        disposition_ids: list[str] = []
        for disposition in self.incident_dispositions:
            if type(disposition) is not OperationalControlIncidentDisposition:
                raise OperationalControlError("rearm incident disposition must be exact")
            if disposition.resolved_at > self.checked_at:
                raise OperationalControlError(
                    "incident disposition cannot follow the evidence check"
                )
            disposition_ids.append(disposition.event_id)
        if disposition_ids != sorted(disposition_ids) or len(disposition_ids) != len(
            set(disposition_ids)
        ):
            raise OperationalControlError(
                "rearm incident dispositions must be sorted and unique by event ID"
            )
        if (
            self.operation_completion is not None
            and type(self.operation_completion) is not OperationalControlCompletion
        ):
            raise OperationalControlError("rearm operation completion must be an exact completion")

    @property
    def evidence_id(self) -> str:
        return canonical_id(
            "operational-control-rearm-evidence",
            OPERATIONAL_CONTROL_POLICY_SHA256,
            self.scope_id,
            self.current_transition_id,
            self.target_state,
            self.checked_at,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            OPERATIONAL_CONTROL_CONTRACT_VERSION,
            "rearm_evidence",
            self.evidence_id,
            self.scope_id,
            self.current_transition_id,
            self.current_transition_sha256,
            self.current_state,
            self.current_state_epoch_id,
            self.target_state,
            self.actor.semantic_sha256,
            self.checked_at,
            self.expires_at,
            self.readiness_sha256,
            self.reconciliation_sha256,
            self.incident_register_sha256,
            self.reconciliation_clean,
            self.data_healthy,
            self.clock_healthy,
            self.working_order_ids,
            self.unknown_order_ids,
            self.pending_cancel_order_ids,
            tuple(item.semantic_sha256 for item in self.incident_dispositions),
            (
                None
                if self.operation_completion is None
                else self.operation_completion.semantic_sha256
            ),
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


@dataclass(frozen=True, slots=True)
class OperationalControlResidualPosition:
    instrument_id: str
    quantity: Decimal
    gross_exposure: Decimal

    def __post_init__(self) -> None:
        _require_text(self.instrument_id, "residual position instrument ID")
        if type(self.quantity) is not Decimal or not self.quantity.is_finite():
            raise OperationalControlError(
                "residual position quantity must be a finite exact Decimal"
            )
        try:
            canonical_quantity = canonical_persisted_decimal(
                self.quantity,
                "residual position quantity",
            )
        except ValueError as error:
            raise OperationalControlError(str(error)) from error
        if canonical_quantity == 0:
            raise OperationalControlError("residual position quantity cannot be zero")
        object.__setattr__(self, "quantity", canonical_quantity)
        if type(self.gross_exposure) is not Decimal or not self.gross_exposure.is_finite():
            raise OperationalControlError(
                "residual position gross_exposure must be a finite exact Decimal"
            )
        try:
            canonical_exposure = canonical_persisted_decimal(
                self.gross_exposure,
                "residual position gross_exposure",
            )
        except ValueError as error:
            raise OperationalControlError(str(error)) from error
        if canonical_exposure <= 0:
            raise OperationalControlError("residual position gross_exposure must be positive")
        object.__setattr__(self, "gross_exposure", canonical_exposure)

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            OPERATIONAL_CONTROL_CONTRACT_VERSION,
            "residual_position",
            self.instrument_id,
            self.quantity,
            self.gross_exposure,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class OperationalControlResidualFacts:
    terminal_order_count: int
    working_order_ids: tuple[str, ...]
    unknown_order_ids: tuple[str, ...]
    pending_cancel_order_ids: tuple[str, ...]
    positions: tuple[OperationalControlResidualPosition, ...]
    reconciliation_clean: bool
    source_evidence_sha256: str

    def __post_init__(self) -> None:
        if type(self.terminal_order_count) is not int or self.terminal_order_count < 0:
            raise OperationalControlError("residual terminal_order_count must be non-negative")
        _require_sorted_unique(self.working_order_ids, "residual working order IDs")
        _require_sorted_unique(self.unknown_order_ids, "residual unknown order IDs")
        _require_sorted_unique(
            self.pending_cancel_order_ids,
            "residual pending-cancel order IDs",
        )
        if (
            type(self.positions) is not tuple
            or len(self.positions) > MAX_OPERATIONAL_CONTROL_RESIDUAL_POSITIONS
        ):
            raise OperationalControlError("residual positions must be an exact tuple")
        instrument_ids: list[str] = []
        for position in self.positions:
            if type(position) is not OperationalControlResidualPosition:
                raise OperationalControlError("residual position must be exact")
            instrument_ids.append(position.instrument_id)
        if instrument_ids != sorted(instrument_ids) or len(instrument_ids) != len(
            set(instrument_ids)
        ):
            raise OperationalControlError(
                "residual positions must be sorted and unique by instrument ID"
            )
        if type(self.reconciliation_clean) is not bool:
            raise OperationalControlError("residual reconciliation_clean must be exact")
        _require_sha256(
            self.source_evidence_sha256,
            "residual source_evidence_sha256",
        )

    @property
    def is_empty(self) -> bool:
        return (
            not self.working_order_ids
            and not self.unknown_order_ids
            and not self.pending_cancel_order_ids
            and not self.positions
        )

    @property
    def residual_gross_exposure(self) -> Decimal:
        return exact_decimal_sum(position.gross_exposure for position in self.positions)

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            OPERATIONAL_CONTROL_CONTRACT_VERSION,
            "residual_facts",
            self.terminal_order_count,
            self.working_order_ids,
            self.unknown_order_ids,
            self.pending_cancel_order_ids,
            tuple(position.semantic_sha256 for position in self.positions),
            self.residual_gross_exposure,
            self.reconciliation_clean,
            self.source_evidence_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class OperationalControlCompletion:
    """Explicit terminal outcome for one exact drain/flatten operation attempt."""

    completion_id: str
    scope_id: str
    idempotency_key: str
    operation_attempt_id: str
    operation: OperationalControlOperationKind
    state_epoch_id: str
    head_transition_id: str
    head_transition_sha256: str
    head_sequence_number: int
    outcome: OperationalControlCompletionOutcome
    observed_at: datetime
    evidence_sha256: str
    residual_facts: OperationalControlResidualFacts
    incomplete_reason: str | None
    deadline_at: datetime | None

    def __post_init__(self) -> None:
        _require_text(self.scope_id, "operation completion scope ID")
        _require_idempotency_key(
            self.idempotency_key,
            "operation completion idempotency key",
        )
        expected_id = canonical_id(
            "operational-control-operation-completion",
            OPERATIONAL_CONTROL_POLICY_SHA256,
            self.scope_id,
            self.idempotency_key,
        )
        if self.completion_id != expected_id:
            raise OperationalControlConflict("operation completion ID is not canonically derived")
        _require_text(self.operation_attempt_id, "completion operation attempt ID")
        if type(self.operation) is not OperationalControlOperationKind:
            raise OperationalControlError("completion operation is unsupported")
        _require_text(self.state_epoch_id, "completion state epoch ID")
        _require_text(self.head_transition_id, "completion head transition ID")
        _require_sha256(
            self.head_transition_sha256,
            "completion head_transition_sha256",
        )
        if type(self.head_sequence_number) is not int or self.head_sequence_number <= 0:
            raise OperationalControlError(
                "completion head_sequence_number must be a positive integer"
            )
        if type(self.outcome) is not OperationalControlCompletionOutcome:
            raise OperationalControlError("completion outcome is unsupported")
        _require_utc(self.observed_at, "operation completion observed_at")
        _require_sha256(self.evidence_sha256, "operation completion evidence_sha256")
        if type(self.residual_facts) is not OperationalControlResidualFacts:
            raise OperationalControlError("operation completion residual facts must be exact")
        if self.deadline_at is not None:
            _require_utc(self.deadline_at, "operation completion deadline_at")
        if self.outcome is OperationalControlCompletionOutcome.COMPLETED:
            if self.incomplete_reason is not None:
                raise OperationalControlConflict(
                    "completed operation cannot carry an incomplete reason"
                )
            if (
                self.residual_facts.working_order_ids
                or self.residual_facts.unknown_order_ids
                or self.residual_facts.pending_cancel_order_ids
                or not self.residual_facts.reconciliation_clean
            ):
                raise OperationalControlConflict(
                    "completed operation requires terminal known orders and clean reconciliation"
                )
            if (
                self.operation is OperationalControlOperationKind.FLATTEN
                and self.residual_facts.positions
            ):
                raise OperationalControlConflict(
                    "completed flatten operation requires zero residual positions"
                )
        else:
            _require_text(
                self.incomplete_reason or "",
                "incomplete operation reason",
                maximum=256,
            )
            if self.residual_facts.is_empty and self.residual_facts.reconciliation_clean:
                raise OperationalControlConflict(
                    "incomplete operation must retain unresolved or residual facts"
                )
            if self.outcome is OperationalControlCompletionOutcome.DEADLINE_EXCEEDED and (
                self.deadline_at is None or self.deadline_at > self.observed_at
            ):
                raise OperationalControlConflict(
                    "deadline-exceeded completion requires an elapsed deadline"
                )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            OPERATIONAL_CONTROL_CONTRACT_VERSION,
            "operation_completion",
            self.completion_id,
            self.scope_id,
            self.idempotency_key,
            self.operation_attempt_id,
            self.operation,
            self.state_epoch_id,
            self.head_transition_id,
            self.head_transition_sha256,
            self.head_sequence_number,
            self.outcome,
            self.observed_at,
            self.evidence_sha256,
            self.residual_facts.semantic_sha256,
            self.incomplete_reason,
            self.deadline_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


def _operational_control_rearm_evidence(
    *,
    scope_id: str,
    current_transition_id: str,
    current_transition_sha256: str,
    current_state: OperationalControlState,
    current_state_epoch_id: str,
    actor: OperationalControlActor,
    checked_at: datetime,
    expires_at: datetime,
    readiness_sha256: str,
    reconciliation_sha256: str,
    incident_register_sha256: str,
    reconciliation_clean: bool,
    data_healthy: bool,
    clock_healthy: bool,
    working_order_ids: tuple[str, ...],
    unknown_order_ids: tuple[str, ...],
    pending_cancel_order_ids: tuple[str, ...],
    incident_dispositions: tuple[OperationalControlIncidentDisposition, ...],
    operation_completion: OperationalControlCompletion | None = None,
) -> OperationalControlRearmEvidence:
    """Construct evidence only after an authoritative verifier checks its sources."""

    value = object.__new__(OperationalControlRearmEvidence)
    for field_name, field_value in (
        ("scope_id", scope_id),
        ("current_transition_id", current_transition_id),
        ("current_transition_sha256", current_transition_sha256),
        ("current_state", current_state),
        ("current_state_epoch_id", current_state_epoch_id),
        ("target_state", OperationalControlState.RUNNING),
        ("actor", actor),
        ("checked_at", checked_at),
        ("expires_at", expires_at),
        ("readiness_sha256", readiness_sha256),
        ("reconciliation_sha256", reconciliation_sha256),
        ("incident_register_sha256", incident_register_sha256),
        ("reconciliation_clean", reconciliation_clean),
        ("data_healthy", data_healthy),
        ("clock_healthy", clock_healthy),
        ("working_order_ids", working_order_ids),
        ("unknown_order_ids", unknown_order_ids),
        ("pending_cancel_order_ids", pending_cancel_order_ids),
        ("incident_dispositions", incident_dispositions),
        ("operation_completion", operation_completion),
    ):
        object.__setattr__(value, field_name, field_value)
    value.__post_init__()
    return value


def _operation_kind(command: OperationalControlCommand) -> OperationalControlOperationKind | None:
    if command.kind is OperationalControlCommandKind.DRAIN:
        return OperationalControlOperationKind.DRAIN
    if command.kind is OperationalControlCommandKind.FLATTEN:
        return OperationalControlOperationKind.FLATTEN
    return None


def _validate_rearm(
    current: OperationalControlTransition,
    command: OperationalControlCommand,
    evidence: OperationalControlRearmEvidence | None,
    decided_at: datetime,
) -> None:
    if evidence is None:
        raise OperationalControlRearmRejected("rearm requires explicit prerequisite evidence")
    if command.rearm_evidence_sha256 != evidence.semantic_sha256:
        raise OperationalControlRearmRejected(
            "rearm command does not bind the exact prerequisite evidence"
        )
    if command.actor != evidence.actor:
        raise OperationalControlRearmRejected(
            "rearm evidence does not bind the exact authenticated human actor"
        )
    if (
        evidence.scope_id != current.scope_id
        or evidence.current_transition_id != current.transition_id
        or evidence.current_transition_sha256 != current.semantic_sha256
        or evidence.current_state is not current.effective_state
        or evidence.current_state_epoch_id != current.state_epoch_id
        or evidence.target_state is not command.target_state
    ):
        raise OperationalControlRearmRejected(
            "rearm evidence does not bind the exact current non-running head"
        )
    if not (evidence.checked_at <= command.requested_at <= decided_at < evidence.expires_at):
        raise OperationalControlRearmRejected("rearm prerequisite evidence is not fresh")
    if (
        not evidence.reconciliation_clean
        or not evidence.data_healthy
        or not evidence.clock_healthy
        or evidence.working_order_ids
        or evidence.unknown_order_ids
        or evidence.pending_cancel_order_ids
    ):
        raise OperationalControlRearmRejected(
            "rearm prerequisite evidence is not healthy and clean"
        )
    expected = sorted((event.event_id, event.semantic_sha256) for event in current.blocking_events)
    supplied = [
        (disposition.event_id, disposition.event_sha256)
        for disposition in evidence.incident_dispositions
    ]
    if supplied != expected:
        raise OperationalControlRearmRejected(
            "rearm evidence does not dispose every exact blocking event"
        )
    events_by_id = {event.event_id: event for event in current.blocking_events}
    if any(
        disposition.resolved_at < events_by_id[disposition.event_id].occurred_at
        for disposition in evidence.incident_dispositions
    ):
        raise OperationalControlRearmRejected(
            "incident disposition predates its exact blocking event"
        )
    if current.blocker_overflowed:
        raise OperationalControlRearmRejected(
            "rearm requires authoritative disposition of overflowed blocker history"
        )
    if current.effective_state in {
        OperationalControlState.DRAINING,
        OperationalControlState.FLATTENING,
    }:
        active = current.active_operation
        completion = evidence.operation_completion
        if (
            active is None
            or completion is None
            or completion.scope_id != current.scope_id
            or completion.operation_attempt_id != active.attempt_id
            or completion.operation is not active.operation
            or completion.state_epoch_id != current.state_epoch_id
            or completion.outcome is not OperationalControlCompletionOutcome.COMPLETED
            or completion.observed_at > evidence.checked_at
        ):
            raise OperationalControlRearmRejected(
                "operation state rearm requires its exact completed attempt"
            )
    elif evidence.operation_completion is not None:
        raise OperationalControlRearmRejected(
            "non-operation state rearm cannot substitute operation completion"
        )


def _validate_operation_completion_for_retry(
    current: OperationalControlTransition,
    command: OperationalControlCommand,
    completion: OperationalControlCompletion,
) -> None:
    active = current.active_operation
    if active is None:
        raise OperationalControlOperationConflict("operation retry has no active operation attempt")
    if (
        completion.scope_id != current.scope_id
        or completion.operation_attempt_id != active.attempt_id
        or completion.operation is not active.operation
        or completion.state_epoch_id != current.state_epoch_id
        or completion.head_sequence_number > current.sequence_number
        or completion.observed_at > command.requested_at
    ):
        raise OperationalControlOperationConflict(
            "operation retry completion does not bind the active attempt"
        )
    if completion.outcome not in {
        OperationalControlCompletionOutcome.INCOMPLETE,
        OperationalControlCompletionOutcome.DEADLINE_EXCEEDED,
    }:
        raise OperationalControlOperationConflict(
            "only an incomplete or deadline operation may be retried"
        )
    if completion.head_sequence_number == current.sequence_number and (
        completion.head_transition_id != current.transition_id
        or completion.head_transition_sha256 != current.semantic_sha256
    ):
        raise OperationalControlOperationConflict(
            "operation retry completion conflicts with the current head"
        )


def apply_operational_control_command(
    current: OperationalControlTransition | None,
    command: OperationalControlCommand,
    *,
    decided_at: datetime,
    rearm_evidence: OperationalControlRearmEvidence | None = None,
    active_operation_completion: OperationalControlCompletion | None = None,
) -> OperationalControlTransition:
    """Apply one command to an authenticated head without performing I/O."""

    if type(command) is not OperationalControlCommand:
        raise OperationalControlError("control command must be exact")
    _require_utc(decided_at, "control decision decided_at")
    if command.requested_at > decided_at:
        raise OperationalControlError("control decision cannot predate its command")

    if current is None:
        if command.kind is not OperationalControlCommandKind.INITIALIZE_HALTED:
            raise OperationalControlAbsent(
                "absent operational control only accepts INITIALIZE_HALTED"
            )
        sequence_number = 1
        prior_state: OperationalControlState | None = None
        effective_state = OperationalControlState.HALTED
        previous_transition_sha256 = None
        prior_blocking_events: tuple[OperationalControlBlockingEvent, ...] = ()
        prior_blocker_overflowed = False
        prior_state_epoch_id = ""
        prior_active_operation = None
    else:
        if type(current) is not OperationalControlTransition:
            raise OperationalControlError("current control transition must be exact")
        if current.scope_id != command.scope_id:
            raise OperationalControlConflict("control command scope conflicts with head")
        if current.command_id == command.command_id:
            if current.command_sha256 != command.semantic_sha256:
                raise OperationalControlConflict("control command idempotency identity conflicts")
            return current
        if command.kind is OperationalControlCommandKind.INITIALIZE_HALTED:
            raise OperationalControlConflict(
                "INITIALIZE_HALTED is valid only for absent control state"
            )
        if command.requested_at < current.decided_at:
            raise OperationalControlConflict("control command predates the current head")
        sequence_number = current.sequence_number + 1
        prior_state = current.effective_state
        previous_transition_sha256 = current.semantic_sha256
        prior_blocking_events = current.blocking_events
        prior_blocker_overflowed = current.blocker_overflowed
        prior_state_epoch_id = current.state_epoch_id
        prior_active_operation = current.active_operation
        if command.kind is OperationalControlCommandKind.REARM:
            if _STATE_SEVERITY[command.target_state] >= _STATE_SEVERITY[prior_state]:
                raise OperationalControlRearmRejected(
                    "rearm must strictly lower a non-running state"
                )
            _validate_rearm(current, command, rearm_evidence, decided_at)
            effective_state = command.target_state
        else:
            effective_state = _state_join(prior_state, command.target_state)

    state_changed = prior_state is not effective_state
    transition_id = canonical_id(
        "operational-control-transition",
        OPERATIONAL_CONTROL_POLICY_SHA256,
        command.scope_id,
        sequence_number,
        command.command_id,
    )
    state_epoch_id = transition_id if current is None or state_changed else prior_state_epoch_id
    if effective_state is OperationalControlState.RUNNING:
        blocking_events: tuple[OperationalControlBlockingEvent, ...] = ()
        blocker_overflowed = False
    else:
        blocking_event = OperationalControlBlockingEvent(
            scope_id=command.scope_id,
            sequence_number=sequence_number,
            command_id=command.command_id,
            command_sha256=command.semantic_sha256,
            state=effective_state,
            occurred_at=decided_at,
        )
        pending_blocking_events = (*prior_blocking_events, blocking_event)
        blocker_overflowed = (
            prior_blocker_overflowed
            or len(pending_blocking_events) > MAX_OPERATIONAL_CONTROL_BLOCKERS
        )
        blocking_events = pending_blocking_events[-MAX_OPERATIONAL_CONTROL_BLOCKERS:]

    expected_operation: OperationalControlOperationKind | None = None
    if effective_state is OperationalControlState.DRAINING:
        expected_operation = OperationalControlOperationKind.DRAIN
    elif effective_state is OperationalControlState.FLATTENING:
        expected_operation = OperationalControlOperationKind.FLATTEN
    requested_operation = _operation_kind(command)
    active_operation: OperationalControlOperationAttempt | None
    open_new_attempt = False
    if expected_operation is None:
        active_operation = None
    else:
        if state_changed:
            open_new_attempt = True
        elif requested_operation is expected_operation and active_operation_completion is not None:
            if current is None:
                raise OperationalControlOperationConflict("initial state cannot retry an operation")
            _validate_operation_completion_for_retry(
                current,
                command,
                active_operation_completion,
            )
            open_new_attempt = True
        if open_new_attempt:
            active_operation = OperationalControlOperationAttempt(
                attempt_id=canonical_id(
                    "operational-control-operation-attempt",
                    OPERATIONAL_CONTROL_POLICY_SHA256,
                    command.scope_id,
                    command.command_id,
                ),
                scope_id=command.scope_id,
                operation=expected_operation,
                state_epoch_id=state_epoch_id,
                opened_by_command_id=command.command_id,
                opened_at=decided_at,
            )
        else:
            active_operation = prior_active_operation
            if active_operation is None or active_operation.operation is not expected_operation:
                raise OperationalControlOperationConflict(
                    "control head lacks the required active operation"
                )

    return OperationalControlTransition(
        transition_id=transition_id,
        scope_id=command.scope_id,
        sequence_number=sequence_number,
        previous_transition_sha256=previous_transition_sha256,
        command_id=command.command_id,
        command_sha256=command.semantic_sha256,
        prior_state=prior_state,
        effective_state=effective_state,
        state_changed=state_changed,
        state_epoch_id=state_epoch_id,
        blocking_events=blocking_events,
        blocker_overflowed=blocker_overflowed,
        active_operation=active_operation,
        decided_at=decided_at,
    )


def record_operational_control_completion(
    current: OperationalControlTransition,
    *,
    idempotency_key: str,
    outcome: OperationalControlCompletionOutcome,
    observed_at: datetime,
    evidence_sha256: str,
    residual_facts: OperationalControlResidualFacts,
    incomplete_reason: str | None = None,
    deadline_at: datetime | None = None,
) -> OperationalControlCompletion:
    """Create a terminal result bound to the exact active operation and audit head."""

    if type(current) is not OperationalControlTransition:
        raise OperationalControlError("completion current transition must be exact")
    if current.active_operation is None:
        raise OperationalControlOperationConflict(
            "control state has no active drain/flatten operation"
        )
    _require_idempotency_key(idempotency_key, "operation completion idempotency key")
    if type(outcome) is not OperationalControlCompletionOutcome:
        raise OperationalControlError("completion outcome is unsupported")
    _require_utc(observed_at, "operation completion observed_at")
    if observed_at < current.decided_at:
        raise OperationalControlOperationConflict(
            "operation completion cannot predate its current head"
        )
    if deadline_at is not None and deadline_at < current.active_operation.opened_at:
        raise OperationalControlOperationConflict(
            "operation completion deadline cannot predate its active attempt"
        )
    return OperationalControlCompletion(
        completion_id=canonical_id(
            "operational-control-operation-completion",
            OPERATIONAL_CONTROL_POLICY_SHA256,
            current.scope_id,
            idempotency_key,
        ),
        scope_id=current.scope_id,
        idempotency_key=idempotency_key,
        operation_attempt_id=current.active_operation.attempt_id,
        operation=current.active_operation.operation,
        state_epoch_id=current.state_epoch_id,
        head_transition_id=current.transition_id,
        head_transition_sha256=current.semantic_sha256,
        head_sequence_number=current.sequence_number,
        outcome=outcome,
        observed_at=observed_at,
        evidence_sha256=evidence_sha256,
        residual_facts=residual_facts,
        incomplete_reason=incomplete_reason,
        deadline_at=deadline_at,
    )


def fail_closed_operational_control_state(
    current: OperationalControlTransition | None,
) -> OperationalControlState:
    """Return HALTED for absence without pretending a durable row exists."""

    if current is None:
        return OperationalControlState.HALTED
    if type(current) is not OperationalControlTransition:
        raise OperationalControlError("current control transition must be exact")
    return current.effective_state


def batch_risk_operational_state(
    current: OperationalControlTransition | OperationalControlState | None,
) -> BatchRiskOperationalState:
    """Conservatively adapt Phase 5A controls to the existing Phase 2 contract."""

    if current is None:
        state = OperationalControlState.HALTED
    elif type(current) is OperationalControlTransition:
        state = current.effective_state
    elif type(current) is OperationalControlState:
        state = current
    else:
        raise OperationalControlError("batch-risk control source is unsupported")
    if state is OperationalControlState.RUNNING:
        return BatchRiskOperationalState.RUNNING
    if state in {
        OperationalControlState.PAUSED,
        OperationalControlState.DRAINING,
        OperationalControlState.FLATTENING,
    }:
        return BatchRiskOperationalState.PAUSED
    return BatchRiskOperationalState.HALTED
