"""Durable, account-serialized Phase 5A operational-control repository."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from packages.application.critical_alert_supervisor_failure_control import (
    CRITICAL_ALERT_FAILURE_CONTROL_POLICY_SHA256,
    CRITICAL_ALERT_FAILURE_CONTROL_REASON_CODE,
    CRITICAL_ALERT_FAILURE_CONTROL_RULE_ID,
    CRITICAL_ALERT_FAILURE_CONTROL_SYSTEM_ACTOR_ID,
    CriticalAlertFailureControlError,
    CriticalAlertFailureControlReceipt,
)
from packages.domain.account_coordinator import AccountCoordinatorError
from packages.domain.canonical import (
    canonical_decimal_text,
    canonical_json_bytes,
    canonical_json_text,
)
from packages.domain.clock import Clock
from packages.domain.operational_control import (
    OPERATIONAL_CONTROL_CONTRACT_VERSION,
    OPERATIONAL_CONTROL_POLICY_SHA256,
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlCompletion,
    OperationalControlCompletionOutcome,
    OperationalControlConflict,
    OperationalControlError,
    OperationalControlOperationConflict,
    OperationalControlOperationKind,
    OperationalControlRearmEvidence,
    OperationalControlRearmRejected,
    OperationalControlResidualFacts,
    OperationalControlResidualPosition,
    OperationalControlState,
    OperationalControlTransition,
    apply_operational_control_command,
    record_operational_control_completion,
)
from packages.persistence.account_coordinator import (
    _write_transaction,
    lock_account_capacity_serialization,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import ImmutableFactConflict, as_aware_utc, assert_immutable
from packages.persistence.schema import (
    phase5_operational_control_completions,
    phase5_operational_control_heads,
    phase5_operational_control_transitions,
)

OperationalControlRow = Mapping[str, object] | RowMapping
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})
_CRITICAL_ALERT_FAILURE_CONTROL_IDEMPOTENCY_PREFIX = "critical-alert-failure:"
_CRITICAL_ALERT_FAILURE_CONTROL_NAMESPACE_ERROR = (
    "critical-alert failure-control namespace requires the atomic receipt binder"
)
_CRITICAL_ALERT_FAILURE_CONTROL_AUTHORITY_SEAL = object()


@dataclass(frozen=True, slots=True)
class _PersistedTransition:
    command: OperationalControlCommand
    transition: OperationalControlTransition


@dataclass(frozen=True, slots=True)
class _CriticalAlertFailureControlAppendAuthority:
    connection: Connection
    transaction: object
    receipt: CriticalAlertFailureControlReceipt
    command_sha256: str
    receipt_sha256: str
    seal: object


def _claims_critical_alert_failure_control_namespace(
    command: OperationalControlCommand,
) -> bool:
    return (
        command.actor.actor_id == CRITICAL_ALERT_FAILURE_CONTROL_SYSTEM_ACTOR_ID
        or command.reason_code == CRITICAL_ALERT_FAILURE_CONTROL_REASON_CODE
        or command.trip_rule_id == CRITICAL_ALERT_FAILURE_CONTROL_RULE_ID
        or command.trip_policy_sha256 == CRITICAL_ALERT_FAILURE_CONTROL_POLICY_SHA256
        or command.idempotency_key.startswith(_CRITICAL_ALERT_FAILURE_CONTROL_IDEMPOTENCY_PREFIX)
    )


def _is_exact_critical_alert_failure_control_command(
    command: OperationalControlCommand,
) -> bool:
    return (
        command.kind is OperationalControlCommandKind.TRIP
        and command.target_state is OperationalControlState.PAUSED
        and command.actor.kind is OperationalControlActorKind.SYSTEM
        and command.actor.actor_id == CRITICAL_ALERT_FAILURE_CONTROL_SYSTEM_ACTOR_ID
        and command.reason_code == CRITICAL_ALERT_FAILURE_CONTROL_REASON_CODE
        and command.reason_evidence_sha256 == command.trip_observation_sha256
        and command.trip_rule_id == CRITICAL_ALERT_FAILURE_CONTROL_RULE_ID
        and command.trip_policy_sha256 == CRITICAL_ALERT_FAILURE_CONTROL_POLICY_SHA256
        and command.idempotency_key.startswith(_CRITICAL_ALERT_FAILURE_CONTROL_IDEMPOTENCY_PREFIX)
    )


def _critical_alert_failure_control_append_authority(
    connection: Connection,
    receipt: CriticalAlertFailureControlReceipt,
) -> _CriticalAlertFailureControlAppendAuthority:
    """Issue transaction-local append authority to the atomic receipt binder."""

    if not isinstance(connection, Connection):
        raise OperationalControlConflict(_CRITICAL_ALERT_FAILURE_CONTROL_NAMESPACE_ERROR)
    transaction = connection.get_transaction()
    if (
        transaction is None
        or not connection.in_transaction()
        or not transaction.is_active
        or type(receipt) is not CriticalAlertFailureControlReceipt
    ):
        raise OperationalControlConflict(_CRITICAL_ALERT_FAILURE_CONTROL_NAMESPACE_ERROR)
    try:
        receipt.__post_init__()
        command_sha256 = receipt.command.semantic_sha256
        receipt_sha256 = receipt.semantic_sha256
    except (CriticalAlertFailureControlError, OperationalControlError) as error:
        raise OperationalControlConflict(_CRITICAL_ALERT_FAILURE_CONTROL_NAMESPACE_ERROR) from error
    if not _is_exact_critical_alert_failure_control_command(receipt.command):
        raise OperationalControlConflict(_CRITICAL_ALERT_FAILURE_CONTROL_NAMESPACE_ERROR)
    return _CriticalAlertFailureControlAppendAuthority(
        connection=connection,
        transaction=transaction,
        receipt=receipt,
        command_sha256=command_sha256,
        receipt_sha256=receipt_sha256,
        seal=_CRITICAL_ALERT_FAILURE_CONTROL_AUTHORITY_SEAL,
    )


def _has_critical_alert_failure_control_append_authority(
    *,
    connection: Connection,
    command: OperationalControlCommand,
    decided_at: datetime,
    authority: object,
) -> bool:
    if (
        type(authority) is not _CriticalAlertFailureControlAppendAuthority
        or authority.seal is not _CRITICAL_ALERT_FAILURE_CONTROL_AUTHORITY_SEAL
        or authority.connection is not connection
        or not connection.in_transaction()
    ):
        return False
    transaction = connection.get_transaction()
    if (
        transaction is None
        or not transaction.is_active
        or authority.transaction is not transaction
        or authority.receipt.command != command
        or authority.receipt.bound_at != decided_at
        or authority.command_sha256 != command.semantic_sha256
    ):
        return False
    try:
        authority.receipt.__post_init__()
        return authority.receipt_sha256 == authority.receipt.semantic_sha256
    except (CriticalAlertFailureControlError, OperationalControlError):
        return False


def _guard_critical_alert_failure_control_namespace(
    *,
    connection: Connection,
    command: OperationalControlCommand,
    decided_at: datetime,
    authority: object | None,
) -> None:
    claims_namespace = _claims_critical_alert_failure_control_namespace(command)
    if claims_namespace:
        if not _has_critical_alert_failure_control_append_authority(
            connection=connection,
            command=command,
            decided_at=decided_at,
            authority=authority,
        ):
            raise OperationalControlConflict(_CRITICAL_ALERT_FAILURE_CONTROL_NAMESPACE_ERROR)
        return
    if authority is not None:
        raise OperationalControlConflict(_CRITICAL_ALERT_FAILURE_CONTROL_NAMESPACE_ERROR)


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _assert_operational_control_immutable(
    table: sa.Table,
    identifier: str,
    row: OperationalControlRow,
    expected: Mapping[str, object],
) -> None:
    try:
        assert_immutable(table, identifier, row, expected)
    except ImmutableFactConflict as error:
        raise OperationalControlConflict(
            f"persisted operational control fact {identifier!r} conflicts"
        ) from error


def _required_text(row: OperationalControlRow, field_name: str) -> str:
    value = row[field_name]
    if type(value) is not str:
        raise OperationalControlError(
            f"persisted operational control {field_name} must be a string"
        )
    return value


def _optional_text(row: OperationalControlRow, field_name: str) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str:
        raise OperationalControlError(
            f"persisted operational control {field_name} must be a string or null"
        )
    return value


def _required_integer(row: OperationalControlRow, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise OperationalControlError(
            f"persisted operational control {field_name} must be an integer"
        )
    return value


def _optional_integer(row: OperationalControlRow, field_name: str) -> int | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not int:
        raise OperationalControlError(
            f"persisted operational control {field_name} must be an integer or null"
        )
    return value


def _required_bool(row: OperationalControlRow, field_name: str) -> bool:
    value = row[field_name]
    if type(value) is not bool:
        raise OperationalControlError(
            f"persisted operational control {field_name} must be a boolean"
        )
    return value


def _required_datetime(row: OperationalControlRow, field_name: str) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise OperationalControlError(
            f"persisted operational control {field_name} must be a datetime"
        )
    return as_aware_utc(value)


def _optional_datetime(row: OperationalControlRow, field_name: str) -> datetime | None:
    value = row[field_name]
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise OperationalControlError(
            f"persisted operational control {field_name} must be a datetime or null"
        )
    return as_aware_utc(value)


def _required_decimal(row: OperationalControlRow, field_name: str) -> Decimal:
    value = row[field_name]
    if not isinstance(value, Decimal):
        raise OperationalControlError(
            f"persisted operational control {field_name} must be a Decimal"
        )
    return value


def _json_list(value: tuple[str, ...]) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def _decode_text_list(payload: str, field_name: str) -> tuple[str, ...]:
    try:
        decoded = json.loads(payload)
    except (TypeError, json.JSONDecodeError) as error:
        raise OperationalControlError(
            f"persisted operational control {field_name} is not valid JSON"
        ) from error
    if type(decoded) is not list or any(type(item) is not str for item in decoded):
        raise OperationalControlError(
            f"persisted operational control {field_name} must encode a string list"
        )
    values = tuple(decoded)
    if payload != _json_list(values):
        raise OperationalControlError(
            f"persisted operational control {field_name} is not canonical"
        )
    return values


def _position_payload(
    positions: tuple[OperationalControlResidualPosition, ...],
) -> str:
    value = tuple(
        (
            position.instrument_id,
            canonical_decimal_text(position.quantity),
            canonical_decimal_text(position.gross_exposure),
        )
        for position in positions
    )
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def _decode_positions(payload: str) -> tuple[OperationalControlResidualPosition, ...]:
    try:
        decoded = json.loads(payload)
    except (TypeError, json.JSONDecodeError) as error:
        raise OperationalControlError(
            "persisted operational control residual positions are not valid JSON"
        ) from error
    if type(decoded) is not list:
        raise OperationalControlError(
            "persisted operational control residual positions must encode a list"
        )
    positions: list[OperationalControlResidualPosition] = []
    try:
        for item in decoded:
            if (
                type(item) is not list
                or len(item) != 3
                or any(type(value) is not str for value in item)
            ):
                raise OperationalControlError(
                    "persisted operational control residual position is malformed"
                )
            positions.append(
                OperationalControlResidualPosition(
                    instrument_id=item[0],
                    quantity=Decimal(item[1]),
                    gross_exposure=Decimal(item[2]),
                )
            )
    except Exception as error:
        if isinstance(error, OperationalControlError):
            raise
        raise OperationalControlError(
            "persisted operational control residual position is malformed"
        ) from error
    result = tuple(positions)
    if payload != _position_payload(result):
        raise OperationalControlError(
            "persisted operational control residual positions are not canonical"
        )
    return result


def _canonical_tuple_text_item(payload: str, index: int, field_name: str) -> str:
    """Read one string from this project's typed canonical tuple encoding."""

    try:
        root = json.loads(payload)
        if (
            type(root) is not dict
            or root.get("type") != "tuple"
            or type(root.get("value")) is not list
        ):
            raise KeyError(index)
        item = root["value"][index]
        if type(item) is not dict or item.get("type") != "string":
            raise KeyError(index)
        value = item["value"]
        if type(value) is not str:
            raise KeyError(index)
        return value
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise OperationalControlError(
            f"persisted operational control {field_name} canonical payload is malformed"
        ) from error


def _command_kind_from_row(row: OperationalControlRow) -> OperationalControlCommandKind:
    raw = _required_text(row, "command_kind")
    try:
        return OperationalControlCommandKind(raw)
    except ValueError as error:
        raise OperationalControlError(
            "persisted operational control command kind is unsupported"
        ) from error


def _command_kind_value(kind: OperationalControlCommandKind) -> str:
    return kind.value


def _state_from_text(value: str, field_name: str) -> OperationalControlState:
    try:
        return OperationalControlState(value)
    except ValueError as error:
        raise OperationalControlError(
            f"persisted operational control {field_name} is unsupported"
        ) from error


def _command_from_row(row: OperationalControlRow) -> OperationalControlCommand:
    kind = _command_kind_from_row(row)
    try:
        actor_kind = OperationalControlActorKind(_required_text(row, "actor_kind"))
    except ValueError as error:
        raise OperationalControlError(
            "persisted operational control actor kind is unsupported"
        ) from error
    requested_at = _required_datetime(row, "requested_at")
    persisted_actor_at = _optional_datetime(row, "actor_authenticated_at")
    actor = OperationalControlActor(
        actor_id=_required_text(row, "actor_id"),
        kind=actor_kind,
        authority_sha256=_required_text(row, "actor_authority_sha256"),
        authenticated_at=persisted_actor_at,
    )
    target = _state_from_text(_required_text(row, "target_state"), "target state")
    command = OperationalControlCommand(
        scope_id=_required_text(row, "account_id"),
        idempotency_key=_required_text(row, "idempotency_key"),
        kind=kind,
        target_state=target,
        actor=actor,
        reason_code=_required_text(row, "reason_code"),
        reason_evidence_sha256=_required_text(row, "reason_evidence_sha256"),
        requested_at=requested_at,
        rearm_evidence_sha256=_optional_text(row, "rearm_evidence_sha256"),
        trip_rule_id=_optional_text(row, "trip_rule_id"),
        trip_policy_sha256=_optional_text(row, "trip_policy_sha256"),
        trip_observation_sha256=_optional_text(row, "trip_observation_sha256"),
    )
    if _required_text(row, "command_id") != command.command_id:
        raise OperationalControlConflict("persisted operational control command ID conflicts")
    if _required_text(row, "command_sha256") != command.semantic_sha256:
        raise OperationalControlConflict("persisted operational control command digest conflicts")
    if _required_text(row, "command_canonical_payload") != command.canonical_json:
        raise OperationalControlConflict("persisted operational control command payload conflicts")
    return command


def _operation_kind_from_state(state: OperationalControlState) -> OperationalControlOperationKind:
    if state is OperationalControlState.DRAINING:
        return OperationalControlOperationKind.DRAIN
    if state is OperationalControlState.FLATTENING:
        return OperationalControlOperationKind.FLATTEN
    raise OperationalControlError("persisted operational control operation state is unsupported")


def _completion_from_row(
    row: OperationalControlRow,
    transitions_by_id: Mapping[str, _PersistedTransition],
) -> OperationalControlCompletion:
    initiating = transitions_by_id.get(_required_text(row, "opener_transition_id"))
    bound_head = transitions_by_id.get(_required_text(row, "head_transition_id"))
    if initiating is None or bound_head is None:
        raise OperationalControlConflict(
            "persisted operation completion references a missing transition"
        )
    try:
        operation = OperationalControlOperationKind(_required_text(row, "operation_kind"))
    except ValueError as error:
        raise OperationalControlError(
            "persisted operation completion kind is unsupported"
        ) from error
    residuals = OperationalControlResidualFacts(
        terminal_order_count=_required_integer(row, "terminal_order_count"),
        working_order_ids=_decode_text_list(
            _required_text(row, "working_order_ids_payload"),
            "working order IDs",
        ),
        unknown_order_ids=_decode_text_list(
            _required_text(row, "unknown_order_ids_payload"),
            "unknown order IDs",
        ),
        pending_cancel_order_ids=_decode_text_list(
            _required_text(row, "pending_cancel_order_ids_payload"),
            "pending-cancel order IDs",
        ),
        positions=_decode_positions(_required_text(row, "residual_positions_payload")),
        reconciliation_clean=_required_bool(row, "reconciliation_clean"),
        source_evidence_sha256=_required_text(row, "source_evidence_sha256"),
    )
    try:
        outcome = OperationalControlCompletionOutcome(_required_text(row, "outcome"))
    except ValueError as error:
        raise OperationalControlError(
            "persisted operation completion outcome is unsupported"
        ) from error
    completion = OperationalControlCompletion(
        completion_id=_required_text(row, "completion_id"),
        scope_id=_required_text(row, "account_id"),
        idempotency_key=_required_text(row, "idempotency_key"),
        operation_attempt_id=_required_text(row, "operation_attempt_id"),
        operation=operation,
        state_epoch_id=_required_text(row, "state_epoch_id"),
        head_transition_id=_required_text(row, "head_transition_id"),
        head_transition_sha256=_required_text(row, "head_transition_sha256"),
        head_sequence_number=_required_integer(row, "head_sequence_number"),
        outcome=outcome,
        observed_at=_required_datetime(row, "observed_at"),
        evidence_sha256=_required_text(row, "evidence_sha256"),
        residual_facts=residuals,
        incomplete_reason=_optional_text(row, "incomplete_reason"),
        deadline_at=_optional_datetime(row, "deadline_at"),
    )
    active = initiating.transition.active_operation
    bound_active = bound_head.transition.active_operation
    if (
        active is None
        or bound_active is None
        or initiating.transition.scope_id != _required_text(row, "account_id")
        or bound_head.transition.scope_id != initiating.transition.scope_id
        or bound_head.transition.sequence_number < initiating.transition.sequence_number
        or bound_active != active
        or completion.operation is not active.operation
        or initiating.transition.command_id != active.opened_by_command_id
        or completion.operation_attempt_id != active.attempt_id
        or completion.state_epoch_id != initiating.transition.state_epoch_id
        or completion.observed_at < bound_head.transition.decided_at
        or (completion.deadline_at is not None and completion.deadline_at < active.opened_at)
        or _required_text(row, "operation_state_epoch_id") != active.state_epoch_id
        or _required_integer(row, "opener_sequence_number") != initiating.transition.sequence_number
        or _required_text(row, "opener_transition_sha256") != initiating.transition.semantic_sha256
        or not _required_bool(row, "opener_operation_started")
        or _required_integer(row, "head_sequence_number") != bound_head.transition.sequence_number
        or _required_text(row, "head_transition_sha256") != bound_head.transition.semantic_sha256
        or _required_text(row, "operation_attempt_sha256") != active.semantic_sha256
        or _required_text(row, "operation_opened_by_command_id") != active.opened_by_command_id
        or _required_datetime(row, "operation_opened_at") != active.opened_at
        or _required_integer(row, "working_order_count") != len(residuals.working_order_ids)
        or _required_text(row, "working_order_ids_sha256") != _sha256(residuals.working_order_ids)
        or _required_integer(row, "unknown_order_count") != len(residuals.unknown_order_ids)
        or _required_text(row, "unknown_order_ids_sha256") != _sha256(residuals.unknown_order_ids)
        or _required_integer(row, "pending_cancel_order_count")
        != len(residuals.pending_cancel_order_ids)
        or _required_text(row, "pending_cancel_order_ids_sha256")
        != _sha256(residuals.pending_cancel_order_ids)
        or _required_integer(row, "residual_position_count") != len(residuals.positions)
        or _required_decimal(row, "residual_gross_exposure") != residuals.residual_gross_exposure
        or _required_text(row, "residual_positions_sha256")
        != _sha256(tuple(position.semantic_sha256 for position in residuals.positions))
        or _required_text(row, "residual_facts_sha256") != residuals.semantic_sha256
        or _required_text(row, "canonical_payload") != completion.canonical_json
        or _required_text(row, "semantic_sha256") != completion.semantic_sha256
    ):
        raise OperationalControlConflict(
            "persisted operation completion duplicated fields conflict"
        )
    return completion


def _transition_values(
    *,
    command: OperationalControlCommand,
    transition: OperationalControlTransition,
    previous: _PersistedTransition | None,
) -> dict[str, object]:
    active = transition.active_operation
    operation_started = active is not None and active.opened_by_command_id == command.command_id
    blocking_ids = tuple(event.event_id for event in transition.blocking_events)
    return {
        "transition_id": transition.transition_id,
        "account_id": transition.scope_id,
        "sequence_number": transition.sequence_number,
        "previous_transition_id": (None if previous is None else previous.transition.transition_id),
        "previous_transition_sha256": transition.previous_transition_sha256,
        "command_id": command.command_id,
        "actor_kind": command.actor.kind.value,
        "actor_id": command.actor.actor_id,
        "actor_authority_sha256": command.actor.authority_sha256,
        "actor_authenticated_at": command.actor.authenticated_at,
        "idempotency_key": command.idempotency_key,
        "command_kind": _command_kind_value(command.kind),
        "target_state": command.target_state.value,
        "requested_at": command.requested_at,
        "reason_code": command.reason_code,
        "reason_evidence_sha256": command.reason_evidence_sha256,
        "rearm_evidence_sha256": command.rearm_evidence_sha256,
        "trip_rule_id": command.trip_rule_id,
        "trip_policy_sha256": command.trip_policy_sha256,
        "trip_observation_sha256": command.trip_observation_sha256,
        "command_canonical_payload": command.canonical_json,
        "command_sha256": command.semantic_sha256,
        "prior_state": None if transition.prior_state is None else transition.prior_state.value,
        "effective_state": transition.effective_state.value,
        "state_changed": transition.state_changed,
        "state_epoch_id": transition.state_epoch_id,
        "blocking_event_count": len(blocking_ids),
        "blocking_event_ids_payload": _json_list(blocking_ids),
        "blocking_event_ids_sha256": _sha256(blocking_ids),
        "blocker_overflowed": transition.blocker_overflowed,
        "active_operation_attempt_id": None if active is None else active.attempt_id,
        "active_operation_kind": None if active is None else active.operation.value,
        "active_operation_state_epoch_id": (None if active is None else active.state_epoch_id),
        "active_operation_opened_by_command_id": (
            None if active is None else active.opened_by_command_id
        ),
        "active_operation_opened_at": None if active is None else active.opened_at,
        "active_operation_sha256": None if active is None else active.semantic_sha256,
        "operation_started": operation_started,
        "decided_at": transition.decided_at,
        "canonical_payload": transition.canonical_json,
        "semantic_sha256": transition.semantic_sha256,
    }


def _completion_values(
    *,
    completion: OperationalControlCompletion,
    initiating: _PersistedTransition,
    bound_head: _PersistedTransition,
) -> dict[str, object]:
    active = initiating.transition.active_operation
    if active is None:
        raise OperationalControlOperationConflict(
            "operation completion initiating transition has no operation"
        )
    residuals = completion.residual_facts
    return {
        "completion_id": completion.completion_id,
        "account_id": completion.scope_id,
        "idempotency_key": completion.idempotency_key,
        "operation_attempt_id": active.attempt_id,
        "operation_kind": active.operation.value,
        "state_epoch_id": initiating.transition.state_epoch_id,
        "operation_state_epoch_id": active.state_epoch_id,
        "operation_attempt_sha256": active.semantic_sha256,
        "operation_opened_by_command_id": active.opened_by_command_id,
        "operation_opened_at": active.opened_at,
        "opener_transition_id": initiating.transition.transition_id,
        "opener_sequence_number": initiating.transition.sequence_number,
        "opener_transition_sha256": initiating.transition.semantic_sha256,
        "opener_operation_started": True,
        "head_transition_id": bound_head.transition.transition_id,
        "head_sequence_number": bound_head.transition.sequence_number,
        "head_transition_sha256": bound_head.transition.semantic_sha256,
        "outcome": completion.outcome.value,
        "observed_at": completion.observed_at,
        "evidence_sha256": completion.evidence_sha256,
        "terminal_order_count": residuals.terminal_order_count,
        "working_order_count": len(residuals.working_order_ids),
        "working_order_ids_payload": _json_list(residuals.working_order_ids),
        "working_order_ids_sha256": _sha256(residuals.working_order_ids),
        "unknown_order_count": len(residuals.unknown_order_ids),
        "unknown_order_ids_payload": _json_list(residuals.unknown_order_ids),
        "unknown_order_ids_sha256": _sha256(residuals.unknown_order_ids),
        "pending_cancel_order_count": len(residuals.pending_cancel_order_ids),
        "pending_cancel_order_ids_payload": _json_list(residuals.pending_cancel_order_ids),
        "pending_cancel_order_ids_sha256": _sha256(residuals.pending_cancel_order_ids),
        "reconciliation_clean": residuals.reconciliation_clean,
        "source_evidence_sha256": residuals.source_evidence_sha256,
        "incomplete_reason": completion.incomplete_reason,
        "deadline_at": completion.deadline_at,
        "residual_position_count": len(residuals.positions),
        "residual_gross_exposure": residuals.residual_gross_exposure,
        "residual_positions_payload": _position_payload(residuals.positions),
        "residual_positions_sha256": _sha256(
            tuple(position.semantic_sha256 for position in residuals.positions)
        ),
        "residual_facts_sha256": residuals.semantic_sha256,
        "canonical_payload": completion.canonical_json,
        "semantic_sha256": completion.semantic_sha256,
    }


def _head_values(record: _PersistedTransition) -> dict[str, object]:
    transition = record.transition
    active = transition.active_operation
    blocker_ids = tuple(event.event_id for event in transition.blocking_events)
    material = (
        OPERATIONAL_CONTROL_CONTRACT_VERSION,
        "sql_head",
        OPERATIONAL_CONTROL_POLICY_SHA256,
        transition.scope_id,
        transition.sequence_number,
        transition.transition_id,
        transition.semantic_sha256,
        transition.effective_state,
        transition.state_epoch_id,
        None if active is None else active.semantic_sha256,
        len(blocker_ids),
        _sha256(blocker_ids),
        transition.blocker_overflowed,
        transition.decided_at,
    )
    return {
        "account_id": transition.scope_id,
        "sequence_number": transition.sequence_number,
        "transition_id": transition.transition_id,
        "transition_sha256": transition.semantic_sha256,
        "effective_state": transition.effective_state.value,
        "state_epoch_id": transition.state_epoch_id,
        "blocking_event_count": len(blocker_ids),
        "blocking_event_ids_payload": _json_list(blocker_ids),
        "blocking_event_ids_sha256": _sha256(blocker_ids),
        "blocker_overflowed": transition.blocker_overflowed,
        "active_operation_attempt_id": None if active is None else active.attempt_id,
        "active_operation_kind": None if active is None else active.operation.value,
        "active_operation_state_epoch_id": (None if active is None else active.state_epoch_id),
        "active_operation_opened_by_command_id": (
            None if active is None else active.opened_by_command_id
        ),
        "active_operation_opened_at": None if active is None else active.opened_at,
        "active_operation_sha256": None if active is None else active.semantic_sha256,
        "decided_at": transition.decided_at,
        "canonical_payload": canonical_json_text(material),
        "semantic_sha256": _sha256(material),
    }


def _completion_rows_by_operation(
    connection: Connection,
    account_id: str,
) -> dict[str, RowMapping]:
    rows = tuple(
        connection.execute(
            sa.select(phase5_operational_control_completions).where(
                phase5_operational_control_completions.c.account_id == account_id
            )
        ).mappings()
    )
    result: dict[str, RowMapping] = {}
    for row in rows:
        operation_id = _required_text(row, "operation_attempt_id")
        if operation_id in result:
            raise OperationalControlConflict(
                "persisted operation attempt has duplicate completions"
            )
        result[operation_id] = row
    return result


def _verified_history_records(
    connection: Connection,
    account_id: str,
) -> tuple[_PersistedTransition, ...]:
    transition_rows = tuple(
        connection.execute(
            sa.select(phase5_operational_control_transitions)
            .where(phase5_operational_control_transitions.c.account_id == account_id)
            .order_by(phase5_operational_control_transitions.c.sequence_number)
        ).mappings()
    )
    completion_rows = _completion_rows_by_operation(connection, account_id)
    records: list[_PersistedTransition] = []
    records_by_id: dict[str, _PersistedTransition] = {}
    current: OperationalControlTransition | None = None
    for row in transition_rows:
        command = _command_from_row(row)
        expected_sequence = len(records) + 1
        if _required_integer(row, "sequence_number") != expected_sequence:
            raise OperationalControlConflict(
                "persisted operational control sequence is not gap-free"
            )
        previous = None if not records else records[-1]
        expected_previous_id = None if previous is None else previous.transition.transition_id
        if _optional_text(row, "previous_transition_id") != expected_previous_id:
            raise OperationalControlConflict(
                "persisted operational control predecessor identity conflicts"
            )
        active_completion: OperationalControlCompletion | None = None
        same_operation_retry = current is not None and (
            (
                current.effective_state is OperationalControlState.DRAINING
                and command.kind is OperationalControlCommandKind.DRAIN
            )
            or (
                current.effective_state is OperationalControlState.FLATTENING
                and command.kind is OperationalControlCommandKind.FLATTEN
            )
        )
        if (
            current is not None
            and current.active_operation is not None
            and same_operation_retry
            and _required_bool(row, "operation_started")
            and _optional_text(row, "active_operation_attempt_id")
            != current.active_operation.attempt_id
        ):
            completion_row = completion_rows.get(current.active_operation.attempt_id)
            if completion_row is None:
                raise OperationalControlOperationConflict(
                    "operation retry lacks its durable terminal completion"
                )
            active_completion = _completion_from_row(completion_row, records_by_id)
        decided_at = _required_datetime(row, "decided_at")
        if command.kind is OperationalControlCommandKind.REARM:
            if (
                current is None
                or current.effective_state is OperationalControlState.RUNNING
                or command.actor.kind is not OperationalControlActorKind.HUMAN
                or command.target_state is not OperationalControlState.RUNNING
                or command.rearm_evidence_sha256 is None
                or command.requested_at < current.decided_at
                or command.requested_at > decided_at
            ):
                raise OperationalControlRearmRejected(
                    "persisted REARM receipt has an unsafe immutable shape"
                )
            transition = OperationalControlTransition(
                transition_id=_required_text(row, "transition_id"),
                scope_id=command.scope_id,
                sequence_number=expected_sequence,
                previous_transition_sha256=current.semantic_sha256,
                command_id=command.command_id,
                command_sha256=command.semantic_sha256,
                prior_state=current.effective_state,
                effective_state=OperationalControlState.RUNNING,
                state_changed=True,
                state_epoch_id=_required_text(row, "transition_id"),
                blocking_events=(),
                blocker_overflowed=False,
                active_operation=None,
                decided_at=decided_at,
            )
        else:
            transition = apply_operational_control_command(
                current,
                command,
                decided_at=decided_at,
                active_operation_completion=active_completion,
            )
        record = _PersistedTransition(
            command=command,
            transition=transition,
        )
        expected_values = _transition_values(
            command=command,
            transition=transition,
            previous=previous,
        )
        _assert_operational_control_immutable(
            phase5_operational_control_transitions,
            transition.transition_id,
            row,
            expected_values,
        )
        records.append(record)
        records_by_id[transition.transition_id] = record
        current = transition

    completions: dict[str, OperationalControlCompletion] = {}
    for operation_id, row in completion_rows.items():
        completion = _completion_from_row(row, records_by_id)
        if completion.operation_attempt_id != operation_id:
            raise OperationalControlConflict(
                "operation completion index conflicts with reconstructed identity"
            )
        completions[operation_id] = completion

    head_row = (
        connection.execute(
            sa.select(phase5_operational_control_heads).where(
                phase5_operational_control_heads.c.account_id == account_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if not records:
        if head_row is not None or completions:
            raise OperationalControlConflict(
                "operational control head/completion exists without transition history"
            )
        return ()
    if head_row is None:
        raise OperationalControlConflict("operational control history has no durable head")
    expected_head = _head_values(records[-1])
    _assert_operational_control_immutable(
        phase5_operational_control_heads,
        account_id,
        head_row,
        expected_head,
    )
    return tuple(records)


def _verify_operational_control_integrity(connection: Connection) -> None:
    """Authenticate every account-local control chain on the caller's snapshot."""

    if not isinstance(connection, Connection):
        raise OperationalControlError("operational control verification requires a Connection")
    if connection.dialect.name not in _SUPPORTED_DIALECTS:
        raise OperationalControlError(
            f"operational control verification does not support dialect {connection.dialect.name!r}"
        )
    account_ids = {
        str(value)
        for value in connection.scalars(
            sa.select(phase5_operational_control_transitions.c.account_id)
        )
    }
    account_ids.update(
        str(value)
        for value in connection.scalars(sa.select(phase5_operational_control_heads.c.account_id))
    )
    account_ids.update(
        str(value)
        for value in connection.scalars(
            sa.select(phase5_operational_control_completions.c.account_id)
        )
    )
    try:
        for account_id in sorted(account_ids):
            _verified_history_records(connection, account_id)
    except ImmutableFactConflict as error:
        raise OperationalControlConflict(
            "persisted operational control immutable values conflict"
        ) from error


def verify_operational_control_integrity(engine: Engine) -> None:
    """Authenticate every account-local control chain in one stable snapshot."""

    if not isinstance(engine, Engine):
        raise OperationalControlError("operational control verification requires an Engine")
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise OperationalControlError(
            f"operational control verification does not support dialect {engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_operational_control_integrity(connection)


def _require_trusted_time(value: datetime) -> None:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise OperationalControlError("operational control trusted time must be UTC")


def _record_by_actor_key(
    records: tuple[_PersistedTransition, ...],
    command: OperationalControlCommand,
) -> _PersistedTransition | None:
    for record in records:
        persisted = record.command
        if (
            persisted.actor.kind is command.actor.kind
            and persisted.actor.actor_id == command.actor.actor_id
            and persisted.idempotency_key == command.idempotency_key
        ):
            return record
    return None


def load_operational_control_head_in_transaction(
    connection: Connection,
    account_id: str,
) -> OperationalControlTransition | None:
    """Authenticate and return the current control head on the caller's transaction.

    Callers that compose risk admission with a breaker transition use this
    helper while holding the shared account lease-head lock.  Absence remains a
    distinct fail-closed result; corrupt history raises.
    """

    if not isinstance(connection, Connection):
        raise OperationalControlError(
            "transactional operational control load requires a Connection"
        )
    if type(account_id) is not str or not account_id or account_id != account_id.strip():
        raise OperationalControlError(
            "operational control account ID must be non-empty and trimmed"
        )
    records = _verified_history_records(connection, account_id)
    return None if not records else records[-1].transition


def load_operational_control_transition_in_transaction(
    connection: Connection,
    account_id: str,
    transition_id: str,
) -> OperationalControlTransition | None:
    """Authenticate the complete chain and return one exact historical transition."""

    if not isinstance(connection, Connection):
        raise OperationalControlError(
            "transactional operational control load requires a Connection"
        )
    for value, field_name in (
        (account_id, "operational control account ID"),
        (transition_id, "operational control transition ID"),
    ):
        if type(value) is not str or not value or value != value.strip():
            raise OperationalControlError(f"{field_name} must be non-empty and trimmed")
    records = _verified_history_records(connection, account_id)
    return next(
        (
            record.transition
            for record in records
            if record.transition.transition_id == transition_id
        ),
        None,
    )


def apply_operational_control_command_in_transaction(
    connection: Connection,
    command: OperationalControlCommand,
    *,
    decided_at: datetime,
    _critical_alert_failure_control_authority: (
        _CriticalAlertFailureControlAppendAuthority | None
    ) = None,
) -> OperationalControlTransition:
    """Append one non-rearm command inside an existing account transaction.

    The helper deliberately owns no clock and opens no nested transaction.  It
    reacquires the shared lease-head lock so every caller uses the same lock
    order: account lease head, then operational-control history/head.
    """

    if not isinstance(connection, Connection):
        raise OperationalControlError(
            "transactional operational control append requires a Connection"
        )
    if type(command) is not OperationalControlCommand:
        raise OperationalControlError(
            "transactional operational control append requires an exact command"
        )
    command.__post_init__()
    if command.kind is OperationalControlCommandKind.REARM:
        raise OperationalControlRearmRejected(
            "Phase 5A SQL repository rejects REARM until an authoritative verifier exists"
        )
    _require_trusted_time(decided_at)
    _guard_critical_alert_failure_control_namespace(
        connection=connection,
        command=command,
        decided_at=decided_at,
        authority=_critical_alert_failure_control_authority,
    )
    lock_account_capacity_serialization(connection, command.scope_id)
    records = _verified_history_records(connection, command.scope_id)
    if _critical_alert_failure_control_authority is not None and (
        not records
        or records[-1].transition != _critical_alert_failure_control_authority.receipt.pre_control
    ):
        raise OperationalControlConflict(_CRITICAL_ALERT_FAILURE_CONTROL_NAMESPACE_ERROR)
    existing = _record_by_actor_key(records, command)
    if existing is not None:
        if existing.command != command:
            raise OperationalControlConflict(
                "operational control actor-scoped idempotency conflicts"
            )
        return existing.transition
    previous = None if not records else records[-1]
    current = None if previous is None else previous.transition
    active_completion = None
    if current is not None and current.active_operation is not None:
        completion_row = (
            connection.execute(
                sa.select(phase5_operational_control_completions).where(
                    phase5_operational_control_completions.c.account_id == command.scope_id,
                    phase5_operational_control_completions.c.operation_attempt_id
                    == current.active_operation.attempt_id,
                )
            )
            .mappings()
            .one_or_none()
        )
        if completion_row is not None:
            active_completion = _completion_from_row(
                completion_row,
                {record.transition.transition_id: record for record in records},
            )
    transition = apply_operational_control_command(
        current,
        command,
        decided_at=decided_at,
        active_operation_completion=active_completion,
    )
    record = _PersistedTransition(command=command, transition=transition)
    transition_values = _transition_values(
        command=command,
        transition=transition,
        previous=previous,
    )
    try:
        connection.execute(
            sa.insert(phase5_operational_control_transitions).values(**transition_values)
        )
    except IntegrityError as error:
        raise OperationalControlConflict(
            "operational control transition conflicts with durable history"
        ) from error
    expected_head = _head_values(record)
    if previous is None:
        try:
            connection.execute(sa.insert(phase5_operational_control_heads).values(**expected_head))
        except IntegrityError as error:
            raise OperationalControlConflict(
                "operational control initial head conflicts"
            ) from error
    else:
        updated = connection.execute(
            sa.update(phase5_operational_control_heads)
            .where(
                phase5_operational_control_heads.c.account_id == command.scope_id,
                phase5_operational_control_heads.c.sequence_number
                == previous.transition.sequence_number,
                phase5_operational_control_heads.c.transition_id
                == previous.transition.transition_id,
                phase5_operational_control_heads.c.transition_sha256
                == previous.transition.semantic_sha256,
            )
            .values(**expected_head)
        )
        if updated.rowcount != 1:
            raise OperationalControlConflict("operational control head changed during append")
    persisted_records = _verified_history_records(connection, command.scope_id)
    persisted = persisted_records[-1]
    if persisted.command != command or persisted.transition != transition:
        raise OperationalControlError("operational control transition failed exact SQL readback")
    return persisted.transition


def apply_authenticated_operational_control_rearm_in_transaction(
    connection: Connection,
    command: OperationalControlCommand,
    evidence: OperationalControlRearmEvidence,
    *,
    decided_at: datetime,
) -> OperationalControlTransition:
    """Append one verifier-constructed REARM under the shared account lock.

    This is deliberately separate from
    :func:`apply_operational_control_command_in_transaction`: callers cannot
    turn the public fail-closed raw-command path into a downgrade by attaching
    an untrusted digest. The exact proof object is required here and is
    re-bound to the authenticated head inside this transaction.
    """

    if not isinstance(connection, Connection):
        raise OperationalControlError("transactional authenticated rearm requires a Connection")
    if type(command) is not OperationalControlCommand:
        raise OperationalControlError("transactional authenticated rearm requires an exact command")
    command.__post_init__()
    if command.kind is not OperationalControlCommandKind.REARM:
        raise OperationalControlRearmRejected("authenticated rearm accepts only a REARM command")
    if type(evidence) is not OperationalControlRearmEvidence:
        raise OperationalControlRearmRejected(
            "authenticated rearm requires verifier-constructed evidence"
        )
    evidence.__post_init__()
    if command.rearm_evidence_sha256 != evidence.semantic_sha256:
        raise OperationalControlRearmRejected(
            "authenticated rearm command does not bind the exact evidence"
        )
    _require_trusted_time(decided_at)
    _guard_critical_alert_failure_control_namespace(
        connection=connection,
        command=command,
        decided_at=decided_at,
        authority=None,
    )

    lock_account_capacity_serialization(connection, command.scope_id)
    records = _verified_history_records(connection, command.scope_id)
    existing = _record_by_actor_key(records, command)
    if existing is not None:
        if existing.command != command:
            raise OperationalControlConflict(
                "operational control actor-scoped idempotency conflicts"
            )
        return existing.transition
    if not records:
        raise OperationalControlRearmRejected(
            "authenticated rearm requires durable non-running control state"
        )

    previous = records[-1]
    current = previous.transition
    if evidence.operation_completion is not None:
        completion_row = (
            connection.execute(
                sa.select(phase5_operational_control_completions).where(
                    phase5_operational_control_completions.c.account_id == command.scope_id,
                    phase5_operational_control_completions.c.completion_id
                    == evidence.operation_completion.completion_id,
                )
            )
            .mappings()
            .one_or_none()
        )
        if completion_row is None:
            raise OperationalControlRearmRejected(
                "authenticated rearm operation completion is not durable"
            )
        durable_completion = _completion_from_row(
            completion_row,
            {record.transition.transition_id: record for record in records},
        )
        if durable_completion != evidence.operation_completion:
            raise OperationalControlConflict("authenticated rearm operation completion conflicts")

    transition = apply_operational_control_command(
        current,
        command,
        decided_at=decided_at,
        rearm_evidence=evidence,
    )
    record = _PersistedTransition(command=command, transition=transition)
    transition_values = _transition_values(
        command=command,
        transition=transition,
        previous=previous,
    )
    try:
        connection.execute(
            sa.insert(phase5_operational_control_transitions).values(**transition_values)
        )
    except IntegrityError as error:
        raise OperationalControlConflict(
            "authenticated rearm conflicts with durable history"
        ) from error

    expected_head = _head_values(record)
    updated = connection.execute(
        sa.update(phase5_operational_control_heads)
        .where(
            phase5_operational_control_heads.c.account_id == command.scope_id,
            phase5_operational_control_heads.c.sequence_number
            == previous.transition.sequence_number,
            phase5_operational_control_heads.c.transition_id == previous.transition.transition_id,
            phase5_operational_control_heads.c.transition_sha256
            == previous.transition.semantic_sha256,
        )
        .values(**expected_head)
    )
    if updated.rowcount != 1:
        raise OperationalControlConflict(
            "operational control head changed during authenticated rearm"
        )

    persisted_records = _verified_history_records(connection, command.scope_id)
    persisted = persisted_records[-1]
    if persisted.command != command or persisted.transition != transition:
        raise OperationalControlError("authenticated rearm failed exact SQL readback")
    return persisted.transition


def _find_operation_opener(
    records: tuple[_PersistedTransition, ...],
    attempt_id: str,
) -> _PersistedTransition:
    for record in records:
        active = record.transition.active_operation
        if (
            active is not None
            and active.attempt_id == attempt_id
            and active.opened_by_command_id == record.transition.command_id
        ):
            return record
    raise OperationalControlOperationConflict(
        "active operation opener is absent from authenticated history"
    )


class SqlOperationalControlRepository:
    """Append operational commands under the shared durable account lock."""

    __slots__ = ("_clock", "_engine")

    def __init__(self, *, engine: Engine, clock: Clock) -> None:
        if not isinstance(engine, Engine):
            raise OperationalControlError("SQL operational control repository requires an Engine")
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise OperationalControlError(
                "SQL operational control repository does not support "
                f"dialect {engine.dialect.name!r}"
            )
        if not callable(getattr(clock, "now", None)):
            raise OperationalControlError(
                "SQL operational control repository requires a trusted clock"
            )
        self._engine = engine
        self._clock = clock

    @property
    def runtime_store_identity(self) -> int:
        """Identify the exact SQL engine for process-local safe composition."""

        return id(self._engine)

    def load(self, account_id: str) -> OperationalControlTransition | None:
        """Load and authenticate the exact current head; absence remains None."""

        if type(account_id) is not str or not account_id or account_id != account_id.strip():
            raise OperationalControlError(
                "operational control account ID must be non-empty and trimmed"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            records = _verified_history_records(connection, account_id)
            return None if not records else records[-1].transition

    def history(self, account_id: str) -> tuple[OperationalControlTransition, ...]:
        """Load the authenticated gap-free transition history."""

        if type(account_id) is not str or not account_id or account_id != account_id.strip():
            raise OperationalControlError(
                "operational control account ID must be non-empty and trimmed"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            return tuple(
                record.transition for record in _verified_history_records(connection, account_id)
            )

    def load_actor_command(
        self,
        *,
        account_id: str,
        actor_kind: OperationalControlActorKind,
        actor_id: str,
        idempotency_key: str,
    ) -> tuple[OperationalControlCommand, OperationalControlTransition] | None:
        """Load one authenticated actor-scoped command receipt.

        Exact HTTP retries use this before consulting changing readiness or
        head state. The complete chain is authenticated before a receipt is
        returned.
        """

        for value, field_name in (
            (account_id, "operational control account ID"),
            (actor_id, "operational control actor ID"),
            (idempotency_key, "operational control idempotency key"),
        ):
            if type(value) is not str or not value or value != value.strip():
                raise OperationalControlError(f"{field_name} must be non-empty and trimmed")
        if type(actor_kind) is not OperationalControlActorKind:
            raise OperationalControlError("operational control actor kind is unsupported")
        with _repeatable_read_transaction(self._engine) as connection:
            records = _verified_history_records(connection, account_id)
            record = next(
                (
                    candidate
                    for candidate in records
                    if candidate.command.actor.kind is actor_kind
                    and candidate.command.actor.actor_id == actor_id
                    and candidate.command.idempotency_key == idempotency_key
                ),
                None,
            )
            if record is None:
                return None
            return record.command, record.transition

    def load_completion(
        self,
        completion_id: str,
    ) -> OperationalControlCompletion | None:
        """Load a completion through its fully authenticated account history."""

        if (
            type(completion_id) is not str
            or not completion_id
            or completion_id != completion_id.strip()
        ):
            raise OperationalControlError("operation completion ID must be non-empty and trimmed")
        with _repeatable_read_transaction(self._engine) as connection:
            row = (
                connection.execute(
                    sa.select(phase5_operational_control_completions).where(
                        phase5_operational_control_completions.c.completion_id == completion_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return None
            records = _verified_history_records(
                connection,
                _required_text(row, "account_id"),
            )
            return _completion_from_row(
                row,
                {record.transition.transition_id: record for record in records},
            )

    def apply(self, command: OperationalControlCommand) -> OperationalControlTransition:
        """Append exactly one non-rearm command or replay its historical result."""

        try:
            with _write_transaction(self._engine) as connection:
                decided_at = self._clock.now()
                return apply_operational_control_command_in_transaction(
                    connection,
                    command,
                    decided_at=decided_at,
                )
        except OperationalControlError:
            raise
        except (AccountCoordinatorError, ImmutableFactConflict) as error:
            raise OperationalControlError(str(error)) from error

    def apply_authenticated_rearm(
        self,
        command: OperationalControlCommand,
        evidence: OperationalControlRearmEvidence,
    ) -> OperationalControlTransition:
        """Commit one exact server-verified REARM proof.

        ``apply`` intentionally continues to reject every raw REARM command.
        """

        try:
            with _write_transaction(self._engine) as connection:
                decided_at = self._clock.now()
                return apply_authenticated_operational_control_rearm_in_transaction(
                    connection,
                    command,
                    evidence,
                    decided_at=decided_at,
                )
        except OperationalControlError:
            raise
        except (AccountCoordinatorError, ImmutableFactConflict) as error:
            raise OperationalControlError(str(error)) from error

    def record_completion(
        self,
        *,
        account_id: str,
        idempotency_key: str,
        outcome: OperationalControlCompletionOutcome,
        evidence_sha256: str,
        residual_facts: OperationalControlResidualFacts,
        incomplete_reason: str | None = None,
        deadline_at: datetime | None = None,
    ) -> OperationalControlCompletion:
        """Record one terminal fact for the exact active operation attempt."""

        try:
            with _write_transaction(self._engine) as connection:
                lock_account_capacity_serialization(connection, account_id)
                records = _verified_history_records(connection, account_id)
                if not records:
                    raise OperationalControlOperationConflict(
                        "operation completion requires durable control state"
                    )
                completions = tuple(
                    _completion_from_row(
                        row,
                        {record.transition.transition_id: record for record in records},
                    )
                    for row in connection.execute(
                        sa.select(phase5_operational_control_completions).where(
                            phase5_operational_control_completions.c.account_id == account_id
                        )
                    ).mappings()
                )
                existing_key = next(
                    (
                        completion
                        for completion in completions
                        if completion.idempotency_key == idempotency_key
                    ),
                    None,
                )
                if existing_key is not None:
                    if (
                        existing_key.outcome is not outcome
                        or existing_key.evidence_sha256 != evidence_sha256
                        or existing_key.residual_facts != residual_facts
                        or existing_key.incomplete_reason != incomplete_reason
                        or existing_key.deadline_at != deadline_at
                    ):
                        raise OperationalControlConflict(
                            "operation completion idempotency conflicts"
                        )
                    return existing_key
                current = records[-1]
                active = current.transition.active_operation
                if active is None:
                    raise OperationalControlOperationConflict(
                        "control head has no active operation"
                    )
                existing_operation = next(
                    (
                        completion
                        for completion in completions
                        if completion.operation_attempt_id == active.attempt_id
                    ),
                    None,
                )
                if existing_operation is not None:
                    raise OperationalControlConflict(
                        "active operation already has a terminal completion"
                    )
                observed_at = self._clock.now()
                _require_trusted_time(observed_at)
                completion = record_operational_control_completion(
                    current.transition,
                    idempotency_key=idempotency_key,
                    outcome=outcome,
                    observed_at=observed_at,
                    evidence_sha256=evidence_sha256,
                    residual_facts=residual_facts,
                    incomplete_reason=incomplete_reason,
                    deadline_at=deadline_at,
                )
                initiating = _find_operation_opener(records, active.attempt_id)
                values = _completion_values(
                    completion=completion,
                    initiating=initiating,
                    bound_head=current,
                )
                try:
                    connection.execute(
                        sa.insert(phase5_operational_control_completions).values(**values)
                    )
                except IntegrityError as error:
                    raise OperationalControlConflict(
                        "operation completion conflicts with durable history"
                    ) from error
                row = (
                    connection.execute(
                        sa.select(phase5_operational_control_completions).where(
                            phase5_operational_control_completions.c.completion_id
                            == completion.completion_id
                        )
                    )
                    .mappings()
                    .one()
                )
                persisted = _completion_from_row(
                    row,
                    {record.transition.transition_id: record for record in records},
                )
                if persisted != completion:
                    raise OperationalControlError("operation completion failed exact SQL readback")
                return persisted
        except OperationalControlError:
            raise
        except (AccountCoordinatorError, ImmutableFactConflict) as error:
            raise OperationalControlError(str(error)) from error


__all__ = [
    "SqlOperationalControlRepository",
    "_verify_operational_control_integrity",
    "verify_operational_control_integrity",
]
