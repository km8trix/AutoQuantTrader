"""Durable, provider-neutral trusted-time epoch and evaluation journal.

The SQL repository persists evidence only.  It grants no readiness, control,
broker, exposure, arming, resume, or re-arm authority.  An epoch session is
valid only in the process and exact repository instance that registered it;
durable rows cannot be used to resume a session after restart.
"""

from __future__ import annotations

import hashlib
import os
import threading
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from packages.application.durable_trusted_time_monitor import (
    DURABLE_TRUSTED_TIME_MONITOR_CONTRACT_VERSION,
    DurableTrustedTimeEpochSession,
    PersistedTrustedTimeProbe,
    PreparedTrustedTimeProbe,
    _new_durable_trusted_time_epoch_session,
)
from packages.application.trusted_time_head_anchor import (
    TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
    AuthenticatedTrustedTimeHeadTransition,
    TrustedTimeHeadAnchorError,
)
from packages.application.trusted_time_monitor import (
    TrustedTimeMonitorBinding,
    TrustedTimeMonitorError,
    TrustedTimeMonitorResult,
    TrustedTimeProbeStatus,
)
from packages.domain.canonical import (
    canonical_json_bytes,
    canonical_json_text,
    canonical_persisted_decimal,
)
from packages.domain.trusted_time import (
    TRUSTED_TIME_POLICY,
    TrustedTimeError,
    TrustedTimeSample,
    TrustedTimeState,
    evaluate_trusted_time,
)
from packages.persistence.account_coordinator import _write_transaction
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import as_aware_utc, same_value
from packages.persistence.schema import (
    phase6_trusted_time_epoch_registrations,
    phase6_trusted_time_host_heads,
    phase6_trusted_time_probe_evaluations,
)

TRUSTED_TIME_PERSISTENCE_CONTRACT_VERSION = DURABLE_TRUSTED_TIME_MONITOR_CONTRACT_VERSION
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})
_TRUSTED_TIME_FULL_REPLAY_PAGE_SIZE = 256
TrustedTimeRow = Mapping[str, object] | RowMapping


class TrustedTimePersistenceError(RuntimeError):
    """Durable trusted-time evidence is malformed or unavailable."""


class TrustedTimePersistenceConflict(TrustedTimePersistenceError):
    """A session, immutable fact, or expected host head conflicts."""


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedTrustedTimeHeadReplayProof:
    """Opaque compact proof issued only after one complete stable replay."""

    first_transition: AuthenticatedTrustedTimeHeadTransition
    current_transition: AuthenticatedTrustedTimeHeadTransition
    transition_count: int
    current_host_head_sha256: str

    def __init__(self) -> None:
        raise TypeError(
            "AuthenticatedTrustedTimeHeadReplayProof is issued by a trusted-time repository"
        )

    @property
    def operational_control_authorized(self) -> bool:
        return False

    @property
    def readiness_authorized(self) -> bool:
        return False

    @property
    def broker_action_authorized(self) -> bool:
        return False


def _new_authenticated_trusted_time_head_replay_proof(
    *,
    first_transition: AuthenticatedTrustedTimeHeadTransition,
    current_transition: AuthenticatedTrustedTimeHeadTransition,
    transition_count: int,
) -> AuthenticatedTrustedTimeHeadReplayProof:
    proof = object.__new__(AuthenticatedTrustedTimeHeadReplayProof)
    object.__setattr__(proof, "first_transition", first_transition)
    object.__setattr__(proof, "current_transition", current_transition)
    object.__setattr__(proof, "transition_count", transition_count)
    object.__setattr__(
        proof,
        "current_host_head_sha256",
        current_transition.current_host_head_sha256,
    )
    return proof


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedTrustedTimeHeadSnapshot:
    """Opaque process-local cursor plus one authenticated transition batch.

    Startup snapshots retain only a compact complete-replay proof. Refreshed
    snapshots contain the newly authenticated suffix. Consumers should compact
    each consumed suffix so the long-running cursor retains constant memory.
    """

    local_transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...]
    transition_count: int
    current_host_head_sha256: str
    complete_replay: bool
    full_replay_proof: AuthenticatedTrustedTimeHeadReplayProof | None

    def __init__(self) -> None:
        raise TypeError(
            "AuthenticatedTrustedTimeHeadSnapshot is issued by a trusted-time repository"
        )

    @property
    def operational_control_authorized(self) -> bool:
        return False

    @property
    def readiness_authorized(self) -> bool:
        return False

    @property
    def broker_action_authorized(self) -> bool:
        return False


def _new_authenticated_trusted_time_head_snapshot(
    *,
    local_transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    transition_count: int,
    current_host_head_sha256: str,
    complete_replay: bool,
    full_replay_proof: AuthenticatedTrustedTimeHeadReplayProof | None,
) -> AuthenticatedTrustedTimeHeadSnapshot:
    snapshot = object.__new__(AuthenticatedTrustedTimeHeadSnapshot)
    object.__setattr__(snapshot, "local_transitions", local_transitions)
    object.__setattr__(snapshot, "transition_count", transition_count)
    object.__setattr__(
        snapshot,
        "current_host_head_sha256",
        current_host_head_sha256,
    )
    object.__setattr__(snapshot, "complete_replay", complete_replay)
    object.__setattr__(snapshot, "full_replay_proof", full_replay_proof)
    return snapshot


@dataclass(frozen=True, slots=True)
class _EpochRegistration:
    monitor_epoch_id: str
    host_id: str
    epoch_sequence: int
    previous_monitor_epoch_id: str | None
    previous_epoch_sha256: str | None
    previous_host_head_sha256: str | None
    source_id: str
    source_authority_sha256: str
    registered_at_utc: datetime
    semantic_sha256: str

    @property
    def binding(self) -> TrustedTimeMonitorBinding:
        return TrustedTimeMonitorBinding(
            source_id=self.source_id,
            source_authority_sha256=self.source_authority_sha256,
            host_id=self.host_id,
            monitor_epoch_id=self.monitor_epoch_id,
        )


@dataclass(frozen=True, slots=True)
class _EvaluationRecord:
    evaluation_id: str
    evaluation_sequence: int
    previous_evaluation_id: str | None
    previous_evaluation_sha256: str | None
    semantic_sha256: str
    result: TrustedTimeMonitorResult


@dataclass(frozen=True, slots=True)
class _HostHead:
    host_id: str
    epoch_sequence: int
    monitor_epoch_id: str
    epoch_sha256: str
    evaluation_sequence: int
    evaluation_id: str | None
    evaluation_record_sha256: str | None
    state_sha256: str | None
    health: str | None
    reason: str | None
    hard_failure_latched: bool | None
    clock_recovery_qualified: bool | None
    evaluated_at_utc: datetime | None
    evaluated_at_monotonic_ns: int | None
    semantic_sha256: str


@dataclass(frozen=True, slots=True)
class _VerifiedHeadTransition:
    epoch: _EpochRegistration
    head: _HostHead
    evaluation: _EvaluationRecord | None


@dataclass(frozen=True, slots=True)
class _VerifiedHost:
    epoch: _EpochRegistration
    head: _HostHead
    prior: TrustedTimeState | None
    terminal_evaluation: _EvaluationRecord | None
    head_transitions: tuple[_VerifiedHeadTransition, ...]


@dataclass(frozen=True, slots=True)
class _AuthenticatedHeadFullReplayResult:
    """Compact terminal result of a callback-consumed authenticated replay."""

    verified: _VerifiedHost
    first_transition: AuthenticatedTrustedTimeHeadTransition
    current_transition: AuthenticatedTrustedTimeHeadTransition
    transition_count: int


@dataclass(frozen=True, slots=True)
class _ActiveSession:
    session: DurableTrustedTimeEpochSession
    process_id: int
    repository_token: object
    source_id: str
    source_authority_sha256: str
    host_id: str
    monitor_epoch_id: str
    epoch_registration_sha256: str
    epoch: _EpochRegistration
    head: _HostHead
    prior: TrustedTimeState | None
    terminal_evaluation: _EvaluationRecord | None

    @property
    def binding(self) -> TrustedTimeMonitorBinding:
        return TrustedTimeMonitorBinding(
            source_id=self.source_id,
            source_authority_sha256=self.source_authority_sha256,
            host_id=self.host_id,
            monitor_epoch_id=self.monitor_epoch_id,
        )


@dataclass(frozen=True, slots=True)
class _AuthenticatedHeadSnapshotState:
    snapshot: AuthenticatedTrustedTimeHeadSnapshot
    process_id: int
    repository_token: object
    host_id: str
    deployment_identity_sha256: str
    runtime_database_identity_sha256: str
    anchor_project_identity_sha256: str
    anchor_project_ref: str
    bucket_name: str
    principal_id: str
    epoch: _EpochRegistration
    head: _HostHead
    prior: TrustedTimeState | None
    terminal_evaluation: _EvaluationRecord | None
    transition_count: int
    full_replay_proof: AuthenticatedTrustedTimeHeadReplayProof | None


@dataclass(frozen=True, slots=True)
class _AuthenticatedHeadReplayProofState:
    proof: AuthenticatedTrustedTimeHeadReplayProof
    process_id: int
    repository_token: object
    first_transition: AuthenticatedTrustedTimeHeadTransition
    current_transition: AuthenticatedTrustedTimeHeadTransition
    host_id: str
    deployment_identity_sha256: str
    runtime_database_identity_sha256: str
    anchor_project_identity_sha256: str
    anchor_project_ref: str
    bucket_name: str
    principal_id: str
    epoch: _EpochRegistration
    head: _HostHead
    prior: TrustedTimeState | None
    terminal_evaluation: _EvaluationRecord | None
    transition_count: int


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_utc(value: datetime, field_name: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise TrustedTimePersistenceError(f"{field_name} must be UTC")
    return value


def _required_text(row: TrustedTimeRow, field_name: str) -> str:
    value = row[field_name]
    if type(value) is not str:
        raise TrustedTimePersistenceError(f"persisted trusted-time {field_name} must be text")
    return value


def _optional_text(row: TrustedTimeRow, field_name: str) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str:
        raise TrustedTimePersistenceError(
            f"persisted trusted-time {field_name} must be text or null"
        )
    return value


def _required_integer(row: TrustedTimeRow, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise TrustedTimePersistenceError(f"persisted trusted-time {field_name} must be an integer")
    return value


def _optional_integer(row: TrustedTimeRow, field_name: str) -> int | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not int:
        raise TrustedTimePersistenceError(
            f"persisted trusted-time {field_name} must be an integer or null"
        )
    return value


def _required_boolean(row: TrustedTimeRow, field_name: str) -> bool:
    value = row[field_name]
    if type(value) is not bool:
        raise TrustedTimePersistenceError(f"persisted trusted-time {field_name} must be a boolean")
    return value


def _optional_boolean(row: TrustedTimeRow, field_name: str) -> bool | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not bool:
        raise TrustedTimePersistenceError(
            f"persisted trusted-time {field_name} must be a boolean or null"
        )
    return value


def _required_datetime(row: TrustedTimeRow, field_name: str) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise TrustedTimePersistenceError(f"persisted trusted-time {field_name} must be a datetime")
    return as_aware_utc(value)


def _required_decimal(row: TrustedTimeRow, field_name: str) -> Decimal:
    value = row[field_name]
    if type(value) is not Decimal:
        raise TrustedTimePersistenceError(
            f"persisted trusted-time {field_name} must be an exact Decimal"
        )
    try:
        return canonical_persisted_decimal(value, f"persisted trusted-time {field_name}")
    except ValueError as error:
        raise TrustedTimePersistenceError(str(error)) from error


def _optional_datetime(row: TrustedTimeRow, field_name: str) -> datetime | None:
    value = row[field_name]
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise TrustedTimePersistenceError(
            f"persisted trusted-time {field_name} must be a datetime or null"
        )
    return as_aware_utc(value)


def _assert_exact_row(
    row: TrustedTimeRow,
    expected: Mapping[str, object],
    subject: str,
) -> None:
    for field_name, expected_value in expected.items():
        if not same_value(row[field_name], expected_value):
            raise TrustedTimePersistenceConflict(
                f"persisted trusted-time {subject} conflicts in {field_name}"
            )


def _epoch_material(
    *,
    monitor_epoch_id: str,
    host_id: str,
    epoch_sequence: int,
    previous_monitor_epoch_id: str | None,
    previous_epoch_sha256: str | None,
    previous_host_head_sha256: str | None,
    source_id: str,
    source_authority_sha256: str,
    registered_at_utc: datetime,
) -> tuple[object, ...]:
    return (
        TRUSTED_TIME_PERSISTENCE_CONTRACT_VERSION,
        "epoch_registration",
        monitor_epoch_id,
        host_id,
        epoch_sequence,
        previous_monitor_epoch_id,
        previous_epoch_sha256,
        previous_host_head_sha256,
        source_id,
        source_authority_sha256,
        TRUSTED_TIME_POLICY.semantic_sha256,
        registered_at_utc,
    )


def _new_epoch(
    *,
    binding: TrustedTimeMonitorBinding,
    epoch_sequence: int,
    previous_monitor_epoch_id: str | None,
    previous_epoch_sha256: str | None,
    previous_host_head_sha256: str | None,
    registered_at_utc: datetime,
) -> _EpochRegistration:
    material = _epoch_material(
        monitor_epoch_id=binding.monitor_epoch_id,
        host_id=binding.host_id,
        epoch_sequence=epoch_sequence,
        previous_monitor_epoch_id=previous_monitor_epoch_id,
        previous_epoch_sha256=previous_epoch_sha256,
        previous_host_head_sha256=previous_host_head_sha256,
        source_id=binding.source_id,
        source_authority_sha256=binding.source_authority_sha256,
        registered_at_utc=registered_at_utc,
    )
    return _EpochRegistration(
        monitor_epoch_id=binding.monitor_epoch_id,
        host_id=binding.host_id,
        epoch_sequence=epoch_sequence,
        previous_monitor_epoch_id=previous_monitor_epoch_id,
        previous_epoch_sha256=previous_epoch_sha256,
        previous_host_head_sha256=previous_host_head_sha256,
        source_id=binding.source_id,
        source_authority_sha256=binding.source_authority_sha256,
        registered_at_utc=registered_at_utc,
        semantic_sha256=_sha256(material),
    )


def _epoch_values(epoch: _EpochRegistration) -> dict[str, Any]:
    material = _epoch_material(
        monitor_epoch_id=epoch.monitor_epoch_id,
        host_id=epoch.host_id,
        epoch_sequence=epoch.epoch_sequence,
        previous_monitor_epoch_id=epoch.previous_monitor_epoch_id,
        previous_epoch_sha256=epoch.previous_epoch_sha256,
        previous_host_head_sha256=epoch.previous_host_head_sha256,
        source_id=epoch.source_id,
        source_authority_sha256=epoch.source_authority_sha256,
        registered_at_utc=epoch.registered_at_utc,
    )
    return {
        "monitor_epoch_id": epoch.monitor_epoch_id,
        "host_id": epoch.host_id,
        "epoch_sequence": epoch.epoch_sequence,
        "previous_monitor_epoch_id": epoch.previous_monitor_epoch_id,
        "previous_epoch_sha256": epoch.previous_epoch_sha256,
        "previous_host_head_sha256": epoch.previous_host_head_sha256,
        "source_id": epoch.source_id,
        "source_authority_sha256": epoch.source_authority_sha256,
        "policy_sha256": TRUSTED_TIME_POLICY.semantic_sha256,
        "registered_at_utc": epoch.registered_at_utc,
        "canonical_payload": canonical_json_text(material),
        "semantic_sha256": epoch.semantic_sha256,
    }


def _epoch_from_row(row: TrustedTimeRow) -> _EpochRegistration:
    try:
        binding = TrustedTimeMonitorBinding(
            source_id=_required_text(row, "source_id"),
            source_authority_sha256=_required_text(row, "source_authority_sha256"),
            host_id=_required_text(row, "host_id"),
            monitor_epoch_id=_required_text(row, "monitor_epoch_id"),
        )
        epoch = _new_epoch(
            binding=binding,
            epoch_sequence=_required_integer(row, "epoch_sequence"),
            previous_monitor_epoch_id=_optional_text(row, "previous_monitor_epoch_id"),
            previous_epoch_sha256=_optional_text(row, "previous_epoch_sha256"),
            previous_host_head_sha256=_optional_text(row, "previous_host_head_sha256"),
            registered_at_utc=_required_datetime(row, "registered_at_utc"),
        )
        _assert_exact_row(row, _epoch_values(epoch), "epoch registration")
        return epoch
    except TrustedTimePersistenceError:
        raise
    except (KeyError, TrustedTimeMonitorError, TypeError, ValueError) as error:
        raise TrustedTimePersistenceError(
            "persisted trusted-time epoch registration is malformed"
        ) from error


def _evaluation_material(
    *,
    evaluation_id: str,
    epoch: _EpochRegistration,
    evaluation_sequence: int,
    previous_evaluation_id: str | None,
    previous_evaluation_sha256: str | None,
    result: TrustedTimeMonitorResult,
) -> tuple[object, ...]:
    return (
        TRUSTED_TIME_PERSISTENCE_CONTRACT_VERSION,
        "probe_evaluation",
        evaluation_id,
        epoch.host_id,
        epoch.monitor_epoch_id,
        epoch.semantic_sha256,
        evaluation_sequence,
        previous_evaluation_id,
        previous_evaluation_sha256,
        result.status.value,
        None if result.evaluation.sample is None else result.evaluation.sample.semantic_sha256,
        result.state.semantic_sha256,
        result.evaluation.semantic_sha256,
    )


def _evaluation_values(
    *,
    evaluation_id: str,
    epoch: _EpochRegistration,
    evaluation_sequence: int,
    previous_evaluation_id: str | None,
    previous_evaluation_sha256: str | None,
    result: TrustedTimeMonitorResult,
) -> dict[str, Any]:
    sample = result.evaluation.sample
    state = result.state
    material = _evaluation_material(
        evaluation_id=evaluation_id,
        epoch=epoch,
        evaluation_sequence=evaluation_sequence,
        previous_evaluation_id=previous_evaluation_id,
        previous_evaluation_sha256=previous_evaluation_sha256,
        result=result,
    )
    return {
        "evaluation_id": evaluation_id,
        "host_id": epoch.host_id,
        "monitor_epoch_id": epoch.monitor_epoch_id,
        "epoch_sha256": epoch.semantic_sha256,
        "evaluation_sequence": evaluation_sequence,
        "previous_evaluation_id": previous_evaluation_id,
        "previous_evaluation_sha256": previous_evaluation_sha256,
        "probe_status": result.status.value,
        "sample_sequence": None if sample is None else sample.sequence,
        "source_evidence_sha256": (None if sample is None else sample.source_evidence_sha256),
        "probe_started_at_utc": (None if sample is None else sample.probe_started_at_utc),
        "probe_completed_at_utc": (None if sample is None else sample.probe_completed_at_utc),
        "trusted_at_utc": None if sample is None else sample.trusted_at_utc,
        "source_uncertainty_milliseconds": (
            None if sample is None else sample.source_uncertainty_milliseconds
        ),
        "probe_started_monotonic_ns": (
            None if sample is None else sample.probe_started_monotonic_ns
        ),
        "probe_completed_monotonic_ns": (
            None if sample is None else sample.probe_completed_monotonic_ns
        ),
        "sample_canonical_payload": (None if sample is None else sample.canonical_json),
        "sample_sha256": None if sample is None else sample.semantic_sha256,
        "previous_state_sha256": state.previous_state_sha256,
        "policy_sha256": state.policy_sha256,
        "latest_sample_sha256": (
            None if state.latest_sample is None else state.latest_sample.semantic_sha256
        ),
        "sample_health": state.sample_health.value,
        "health": state.health.value,
        "reason": state.reason.value,
        "hard_failure_latched": state.hard_failure_latched,
        "healthy_since_monotonic_ns": state.healthy_since_monotonic_ns,
        "clock_recovery_qualified": state.clock_recovery_qualified,
        "evaluated_at_utc": state.evaluated_at_utc,
        "evaluated_at_monotonic_ns": state.evaluated_at_monotonic_ns,
        "state_canonical_payload": state.canonical_json,
        "state_sha256": state.semantic_sha256,
        "evaluation_sha256": result.evaluation.semantic_sha256,
        "canonical_payload": canonical_json_text(material),
        "semantic_sha256": _sha256(material),
    }


def _evaluation_from_row(
    row: TrustedTimeRow,
    *,
    epoch: _EpochRegistration,
    prior: TrustedTimeState | None,
    previous: _EvaluationRecord | None,
    expected_sequence: int,
) -> _EvaluationRecord:
    try:
        status = TrustedTimeProbeStatus(_required_text(row, "probe_status"))
        sample: TrustedTimeSample | None = None
        if status is TrustedTimeProbeStatus.RECORDED:
            sample = TrustedTimeSample(
                source_id=epoch.source_id,
                source_authority_sha256=epoch.source_authority_sha256,
                host_id=epoch.host_id,
                monitor_epoch_id=epoch.monitor_epoch_id,
                sequence=_required_integer(row, "sample_sequence"),
                source_evidence_sha256=_required_text(row, "source_evidence_sha256"),
                probe_started_at_utc=_required_datetime(row, "probe_started_at_utc"),
                probe_completed_at_utc=_required_datetime(row, "probe_completed_at_utc"),
                trusted_at_utc=_required_datetime(row, "trusted_at_utc"),
                source_uncertainty_milliseconds=_required_decimal(
                    row,
                    "source_uncertainty_milliseconds",
                ),
                probe_started_monotonic_ns=_required_integer(row, "probe_started_monotonic_ns"),
                probe_completed_monotonic_ns=_required_integer(row, "probe_completed_monotonic_ns"),
            )
        evaluation = evaluate_trusted_time(
            prior,
            sample,
            evaluated_at_utc=_required_datetime(row, "evaluated_at_utc"),
            evaluated_at_monotonic_ns=_required_integer(row, "evaluated_at_monotonic_ns"),
        )
        result = TrustedTimeMonitorResult(status=status, evaluation=evaluation)
        evaluation_id = _required_text(row, "evaluation_id")
        values = _evaluation_values(
            evaluation_id=evaluation_id,
            epoch=epoch,
            evaluation_sequence=expected_sequence,
            previous_evaluation_id=(None if previous is None else previous.evaluation_id),
            previous_evaluation_sha256=(None if previous is None else previous.semantic_sha256),
            result=result,
        )
        _assert_exact_row(row, values, "probe evaluation")
        return _EvaluationRecord(
            evaluation_id=evaluation_id,
            evaluation_sequence=expected_sequence,
            previous_evaluation_id=(None if previous is None else previous.evaluation_id),
            previous_evaluation_sha256=(None if previous is None else previous.semantic_sha256),
            semantic_sha256=str(values["semantic_sha256"]),
            result=result,
        )
    except TrustedTimePersistenceError:
        raise
    except (
        KeyError,
        TrustedTimeError,
        TrustedTimeMonitorError,
        TypeError,
        ValueError,
    ) as error:
        raise TrustedTimePersistenceError(
            "persisted trusted-time probe evaluation is malformed"
        ) from error


def _head_material(head: _HostHead) -> tuple[object, ...]:
    return (
        TRUSTED_TIME_PERSISTENCE_CONTRACT_VERSION,
        "host_head",
        head.host_id,
        head.epoch_sequence,
        head.monitor_epoch_id,
        head.epoch_sha256,
        head.evaluation_sequence,
        head.evaluation_id,
        head.evaluation_record_sha256,
        head.state_sha256,
        head.health,
        head.reason,
        head.hard_failure_latched,
        head.clock_recovery_qualified,
        head.evaluated_at_utc,
        head.evaluated_at_monotonic_ns,
    )


def _new_head(
    epoch: _EpochRegistration,
    terminal: _EvaluationRecord | None,
) -> _HostHead:
    result = None if terminal is None else terminal.result
    state = None if result is None else result.state
    provisional = _HostHead(
        host_id=epoch.host_id,
        epoch_sequence=epoch.epoch_sequence,
        monitor_epoch_id=epoch.monitor_epoch_id,
        epoch_sha256=epoch.semantic_sha256,
        evaluation_sequence=(0 if terminal is None else terminal.evaluation_sequence),
        evaluation_id=None if terminal is None else terminal.evaluation_id,
        evaluation_record_sha256=(None if terminal is None else terminal.semantic_sha256),
        state_sha256=None if state is None else state.semantic_sha256,
        health=None if state is None else state.health.value,
        reason=None if state is None else state.reason.value,
        hard_failure_latched=(None if state is None else state.hard_failure_latched),
        clock_recovery_qualified=(None if state is None else state.clock_recovery_qualified),
        evaluated_at_utc=None if state is None else state.evaluated_at_utc,
        evaluated_at_monotonic_ns=(None if state is None else state.evaluated_at_monotonic_ns),
        semantic_sha256="",
    )
    return _HostHead(
        **{
            **{
                field_name: getattr(provisional, field_name)
                for field_name in provisional.__dataclass_fields__
                if field_name != "semantic_sha256"
            },
            "semantic_sha256": _sha256(_head_material(provisional)),
        }
    )


def _head_values(head: _HostHead) -> dict[str, Any]:
    return {
        "host_id": head.host_id,
        "epoch_sequence": head.epoch_sequence,
        "monitor_epoch_id": head.monitor_epoch_id,
        "epoch_sha256": head.epoch_sha256,
        "evaluation_sequence": head.evaluation_sequence,
        "evaluation_id": head.evaluation_id,
        "evaluation_record_sha256": head.evaluation_record_sha256,
        "state_sha256": head.state_sha256,
        "health": head.health,
        "reason": head.reason,
        "hard_failure_latched": head.hard_failure_latched,
        "clock_recovery_qualified": head.clock_recovery_qualified,
        "evaluated_at_utc": head.evaluated_at_utc,
        "evaluated_at_monotonic_ns": head.evaluated_at_monotonic_ns,
        "canonical_payload": canonical_json_text(_head_material(head)),
        "semantic_sha256": head.semantic_sha256,
    }


def _head_from_row(row: TrustedTimeRow) -> _HostHead:
    try:
        head = _HostHead(
            host_id=_required_text(row, "host_id"),
            epoch_sequence=_required_integer(row, "epoch_sequence"),
            monitor_epoch_id=_required_text(row, "monitor_epoch_id"),
            epoch_sha256=_required_text(row, "epoch_sha256"),
            evaluation_sequence=_required_integer(row, "evaluation_sequence"),
            evaluation_id=_optional_text(row, "evaluation_id"),
            evaluation_record_sha256=_optional_text(row, "evaluation_record_sha256"),
            state_sha256=_optional_text(row, "state_sha256"),
            health=_optional_text(row, "health"),
            reason=_optional_text(row, "reason"),
            hard_failure_latched=_optional_boolean(row, "hard_failure_latched"),
            clock_recovery_qualified=_optional_boolean(row, "clock_recovery_qualified"),
            evaluated_at_utc=_optional_datetime(row, "evaluated_at_utc"),
            evaluated_at_monotonic_ns=_optional_integer(row, "evaluated_at_monotonic_ns"),
            semantic_sha256=_required_text(row, "semantic_sha256"),
        )
        if _sha256(_head_material(head)) != head.semantic_sha256:
            raise TrustedTimePersistenceConflict(
                "persisted trusted-time host head digest conflicts"
            )
        _assert_exact_row(row, _head_values(head), "host head")
        return head
    except TrustedTimePersistenceError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise TrustedTimePersistenceError(
            "persisted trusted-time host head is malformed"
        ) from error


def _select_head(
    connection: Connection,
    host_id: str,
    *,
    for_update: bool,
) -> _HostHead | None:
    statement = sa.select(phase6_trusted_time_host_heads).where(
        phase6_trusted_time_host_heads.c.host_id == host_id
    )
    if for_update and connection.dialect.name == "postgresql":
        statement = statement.with_for_update()
    row = connection.execute(statement).mappings().one_or_none()
    return None if row is None else _head_from_row(row)


def _require_full_replay_page_size(value: object) -> int:
    if type(value) is not int or value < 1 or value > _TRUSTED_TIME_FULL_REPLAY_PAGE_SIZE:
        raise TrustedTimePersistenceError(
            "trusted-time full replay page size is outside the admitted bound"
        )
    return value


def _trusted_time_epoch_replay_page(
    connection: Connection,
    *,
    host_id: str,
    after_epoch_sequence: int | None,
    page_size: int,
) -> tuple[RowMapping, ...]:
    statement = sa.select(phase6_trusted_time_epoch_registrations).where(
        phase6_trusted_time_epoch_registrations.c.host_id == host_id
    )
    if after_epoch_sequence is not None:
        statement = statement.where(
            phase6_trusted_time_epoch_registrations.c.epoch_sequence > after_epoch_sequence
        )
    rows = (
        connection.execute(
            statement.order_by(phase6_trusted_time_epoch_registrations.c.epoch_sequence).limit(
                page_size
            )
        )
        .mappings()
        .all()
    )
    if len(rows) > page_size:
        raise TrustedTimePersistenceConflict(
            "trusted-time epoch replay page exceeded its authenticated bound"
        )
    return tuple(rows)


def _trusted_time_evaluation_replay_page(
    connection: Connection,
    *,
    host_id: str,
    monitor_epoch_id: str,
    after_evaluation_sequence: int | None,
    page_size: int,
) -> tuple[RowMapping, ...]:
    statement = sa.select(phase6_trusted_time_probe_evaluations).where(
        phase6_trusted_time_probe_evaluations.c.host_id == host_id,
        phase6_trusted_time_probe_evaluations.c.monitor_epoch_id == monitor_epoch_id,
    )
    if after_evaluation_sequence is not None:
        statement = statement.where(
            phase6_trusted_time_probe_evaluations.c.evaluation_sequence > after_evaluation_sequence
        )
    rows = (
        connection.execute(
            statement.order_by(phase6_trusted_time_probe_evaluations.c.evaluation_sequence).limit(
                page_size
            )
        )
        .mappings()
        .all()
    )
    if len(rows) > page_size:
        raise TrustedTimePersistenceConflict(
            "trusted-time evaluation replay page exceeded its authenticated bound"
        )
    return tuple(rows)


def _verified_host(
    connection: Connection,
    host_id: str,
    *,
    for_update: bool,
    transition_consumer: Callable[[_VerifiedHeadTransition], None] | None = None,
    replay_page_size: int = _TRUSTED_TIME_FULL_REPLAY_PAGE_SIZE,
    collect_transitions: bool = False,
) -> _VerifiedHost | None:
    """Replay one complete host journal with a page-bounded working set."""

    page_size = _require_full_replay_page_size(replay_page_size)
    head = _select_head(connection, host_id, for_update=for_update)
    first_epoch_page = _trusted_time_epoch_replay_page(
        connection,
        host_id=host_id,
        after_epoch_sequence=None,
        page_size=page_size,
    )
    if not first_epoch_page:
        if head is not None:
            raise TrustedTimePersistenceError("trusted-time host head exists without epoch history")
        orphan = connection.scalar(
            sa.select(phase6_trusted_time_probe_evaluations.c.evaluation_id)
            .where(phase6_trusted_time_probe_evaluations.c.host_id == host_id)
            .limit(1)
        )
        if orphan is not None:
            raise TrustedTimePersistenceError(
                "trusted-time evaluations exist without epoch history"
            )
        return None

    previous_epoch: _EpochRegistration | None = None
    previous_terminal_head: _HostHead | None = None
    current_prior: TrustedTimeState | None = None
    current_terminal: _EvaluationRecord | None = None
    current_epoch: _EpochRegistration | None = None
    head_transitions: list[_VerifiedHeadTransition] = []
    expected_epoch_sequence = 1
    epoch_page = first_epoch_page
    while epoch_page:
        for row in epoch_page:
            epoch = _epoch_from_row(row)
            if epoch.epoch_sequence != expected_epoch_sequence:
                raise TrustedTimePersistenceError("trusted-time epoch history is not contiguous")
            if (
                epoch.previous_monitor_epoch_id
                != (None if previous_epoch is None else previous_epoch.monitor_epoch_id)
                or epoch.previous_epoch_sha256
                != (None if previous_epoch is None else previous_epoch.semantic_sha256)
                or epoch.previous_host_head_sha256
                != (
                    None
                    if previous_terminal_head is None
                    else previous_terminal_head.semantic_sha256
                )
            ):
                raise TrustedTimePersistenceError("trusted-time epoch predecessor chain conflicts")

            zero_transition = _VerifiedHeadTransition(
                epoch=epoch,
                head=_new_head(epoch, None),
                evaluation=None,
            )
            if collect_transitions:
                head_transitions.append(zero_transition)
            if transition_consumer is not None:
                transition_consumer(zero_transition)

            prior: TrustedTimeState | None = None
            terminal: _EvaluationRecord | None = None
            expected_evaluation_sequence = 1
            evaluation_page = _trusted_time_evaluation_replay_page(
                connection,
                host_id=host_id,
                monitor_epoch_id=epoch.monitor_epoch_id,
                after_evaluation_sequence=None,
                page_size=page_size,
            )
            while evaluation_page:
                for evaluation_row in evaluation_page:
                    terminal = _evaluation_from_row(
                        evaluation_row,
                        epoch=epoch,
                        prior=prior,
                        previous=terminal,
                        expected_sequence=expected_evaluation_sequence,
                    )
                    prior = terminal.result.state
                    evaluated_transition = _VerifiedHeadTransition(
                        epoch=epoch,
                        head=_new_head(epoch, terminal),
                        evaluation=terminal,
                    )
                    if collect_transitions:
                        head_transitions.append(evaluated_transition)
                    if transition_consumer is not None:
                        transition_consumer(evaluated_transition)
                    expected_evaluation_sequence += 1
                evaluation_page = _trusted_time_evaluation_replay_page(
                    connection,
                    host_id=host_id,
                    monitor_epoch_id=epoch.monitor_epoch_id,
                    after_evaluation_sequence=expected_evaluation_sequence - 1,
                    page_size=page_size,
                )

            previous_terminal_head = _new_head(epoch, terminal)
            previous_epoch = epoch
            current_epoch = epoch
            current_prior = prior
            current_terminal = terminal
            expected_epoch_sequence += 1
        epoch_page = _trusted_time_epoch_replay_page(
            connection,
            host_id=host_id,
            after_epoch_sequence=expected_epoch_sequence - 1,
            page_size=page_size,
        )

    evaluation = phase6_trusted_time_probe_evaluations.alias("trusted_time_evaluation_integrity")
    known_epoch = phase6_trusted_time_epoch_registrations.alias("trusted_time_known_epoch")
    foreign_evaluation = connection.scalar(
        sa.select(evaluation.c.evaluation_id)
        .where(
            evaluation.c.host_id == host_id,
            ~sa.exists(
                sa.select(sa.literal(1)).where(
                    known_epoch.c.host_id == evaluation.c.host_id,
                    known_epoch.c.monitor_epoch_id == evaluation.c.monitor_epoch_id,
                )
            ),
        )
        .limit(1)
    )
    if foreign_evaluation is not None:
        raise TrustedTimePersistenceError(
            "trusted-time evaluation references an unknown host epoch"
        )

    assert current_epoch is not None
    expected_head = _new_head(current_epoch, current_terminal)
    if head is None:
        raise TrustedTimePersistenceError("trusted-time epoch history exists without a host head")
    if head != expected_head:
        raise TrustedTimePersistenceConflict(
            "trusted-time host head conflicts with authenticated history"
        )
    return _VerifiedHost(
        epoch=current_epoch,
        head=head,
        prior=current_prior,
        terminal_evaluation=current_terminal,
        head_transitions=tuple(head_transitions),
    )


def _verify_cached_host_tip(
    connection: Connection,
    active: _ActiveSession,
    *,
    for_update: bool,
) -> _VerifiedHost:
    """Authenticate the exact durable tip against a startup-authenticated prefix.

    The active-session state is issued only after a complete replay. Every
    repository append replaces it only after an exact insert/head readback and
    successful commit. This fixed-query path therefore authenticates the
    current epoch row, host-head CAS token, and terminal evaluation without
    replaying the immutable prefix on every probe.
    """

    head = _select_head(connection, active.host_id, for_update=for_update)
    if head is None or head != active.head:
        raise TrustedTimePersistenceConflict(
            "trusted-time durable tip conflicts with the authenticated session"
        )

    epoch_row = (
        connection.execute(
            sa.select(phase6_trusted_time_epoch_registrations).where(
                phase6_trusted_time_epoch_registrations.c.monitor_epoch_id
                == active.monitor_epoch_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if epoch_row is None or _epoch_from_row(epoch_row) != active.epoch:
        raise TrustedTimePersistenceConflict(
            "trusted-time current epoch conflicts with the authenticated session"
        )

    terminal = active.terminal_evaluation
    if terminal is not None:
        evaluation_row = (
            connection.execute(
                sa.select(phase6_trusted_time_probe_evaluations).where(
                    phase6_trusted_time_probe_evaluations.c.evaluation_id == terminal.evaluation_id
                )
            )
            .mappings()
            .one_or_none()
        )
        if evaluation_row is None:
            raise TrustedTimePersistenceConflict("trusted-time terminal evaluation is missing")
        expected_values = _evaluation_values(
            evaluation_id=terminal.evaluation_id,
            epoch=active.epoch,
            evaluation_sequence=terminal.evaluation_sequence,
            previous_evaluation_id=terminal.previous_evaluation_id,
            previous_evaluation_sha256=terminal.previous_evaluation_sha256,
            result=terminal.result,
        )
        _assert_exact_row(
            evaluation_row,
            expected_values,
            "authenticated terminal probe evaluation",
        )

    return _VerifiedHost(
        epoch=active.epoch,
        head=head,
        prior=active.prior,
        terminal_evaluation=terminal,
        head_transitions=(),
    )


def _verified_host_suffix_from_boundary(
    connection: Connection,
    *,
    host_id: str,
    epoch: _EpochRegistration,
    head_boundary: _HostHead,
    prior: TrustedTimeState | None,
    terminal_evaluation: _EvaluationRecord | None,
) -> _VerifiedHost:
    """Authenticate only rows strictly after one sealed full-replay cursor."""

    head = _select_head(connection, host_id, for_update=False)
    if head is None:
        raise TrustedTimePersistenceConflict(
            "trusted-time host head disappeared after authenticated startup"
        )

    epoch_rows = (
        connection.execute(
            sa.select(phase6_trusted_time_epoch_registrations)
            .where(
                phase6_trusted_time_epoch_registrations.c.host_id == host_id,
                phase6_trusted_time_epoch_registrations.c.epoch_sequence >= epoch.epoch_sequence,
            )
            .order_by(phase6_trusted_time_epoch_registrations.c.epoch_sequence)
        )
        .mappings()
        .all()
    )
    if not epoch_rows:
        raise TrustedTimePersistenceConflict("trusted-time authenticated cursor epoch disappeared")
    boundary_epoch = _epoch_from_row(epoch_rows[0])
    if boundary_epoch != epoch or head_boundary != _new_head(
        epoch,
        terminal_evaluation,
    ):
        raise TrustedTimePersistenceConflict("trusted-time authenticated cursor boundary conflicts")

    if terminal_evaluation is not None:
        terminal = terminal_evaluation
        boundary_row = (
            connection.execute(
                sa.select(phase6_trusted_time_probe_evaluations).where(
                    phase6_trusted_time_probe_evaluations.c.evaluation_id == terminal.evaluation_id
                )
            )
            .mappings()
            .one_or_none()
        )
        if boundary_row is None:
            raise TrustedTimePersistenceConflict(
                "trusted-time authenticated cursor terminal disappeared"
            )
        _assert_exact_row(
            boundary_row,
            _evaluation_values(
                evaluation_id=terminal.evaluation_id,
                epoch=epoch,
                evaluation_sequence=terminal.evaluation_sequence,
                previous_evaluation_id=terminal.previous_evaluation_id,
                previous_evaluation_sha256=terminal.previous_evaluation_sha256,
                result=terminal.result,
            ),
            "authenticated cursor terminal evaluation",
        )

    current_epoch = epoch
    current_prior = prior
    current_terminal = terminal_evaluation
    previous_terminal_head = head_boundary
    transitions: list[_VerifiedHeadTransition] = []
    for row_index, epoch_row in enumerate(epoch_rows):
        epoch = _epoch_from_row(epoch_row)
        if row_index == 0:
            evaluation_sequence = previous_terminal_head.evaluation_sequence + 1
        else:
            if (
                epoch.epoch_sequence != current_epoch.epoch_sequence + 1
                or epoch.previous_monitor_epoch_id != current_epoch.monitor_epoch_id
                or epoch.previous_epoch_sha256 != current_epoch.semantic_sha256
                or epoch.previous_host_head_sha256 != previous_terminal_head.semantic_sha256
            ):
                raise TrustedTimePersistenceConflict(
                    "trusted-time suffix epoch predecessor chain conflicts"
                )
            current_epoch = epoch
            current_prior = None
            current_terminal = None
            evaluation_sequence = 1
            zero_head = _new_head(epoch, None)
            transitions.append(
                _VerifiedHeadTransition(
                    epoch=epoch,
                    head=zero_head,
                    evaluation=None,
                )
            )

        evaluation_rows = (
            connection.execute(
                sa.select(phase6_trusted_time_probe_evaluations)
                .where(
                    phase6_trusted_time_probe_evaluations.c.host_id == host_id,
                    phase6_trusted_time_probe_evaluations.c.monitor_epoch_id
                    == epoch.monitor_epoch_id,
                    phase6_trusted_time_probe_evaluations.c.evaluation_sequence
                    >= evaluation_sequence,
                )
                .order_by(phase6_trusted_time_probe_evaluations.c.evaluation_sequence)
            )
            .mappings()
            .all()
        )
        for evaluation_row in evaluation_rows:
            current_terminal = _evaluation_from_row(
                evaluation_row,
                epoch=epoch,
                prior=current_prior,
                previous=current_terminal,
                expected_sequence=evaluation_sequence,
            )
            current_prior = current_terminal.result.state
            transition_head = _new_head(epoch, current_terminal)
            transitions.append(
                _VerifiedHeadTransition(
                    epoch=epoch,
                    head=transition_head,
                    evaluation=current_terminal,
                )
            )
            evaluation_sequence += 1
        previous_terminal_head = _new_head(epoch, current_terminal)
        current_epoch = epoch

    if previous_terminal_head != head:
        raise TrustedTimePersistenceConflict(
            "trusted-time suffix does not terminate at the durable host head"
        )
    return _VerifiedHost(
        epoch=current_epoch,
        head=head,
        prior=current_prior,
        terminal_evaluation=current_terminal,
        head_transitions=tuple(transitions),
    )


def _verified_host_suffix(
    connection: Connection,
    state: _AuthenticatedHeadSnapshotState,
) -> _VerifiedHost:
    return _verified_host_suffix_from_boundary(
        connection,
        host_id=state.host_id,
        epoch=state.epoch,
        head_boundary=state.head,
        prior=state.prior,
        terminal_evaluation=state.terminal_evaluation,
    )


def _require_head_transition_export_text(value: object, field_name: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise TrustedTimePersistenceError(f"{field_name} must be non-empty trimmed text")
    if len(value) > 128 or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise TrustedTimePersistenceError(f"{field_name} contains unsupported text")
    return value


def _require_head_transition_export_sha256(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise TrustedTimePersistenceError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_head_transition_export_principal(value: object) -> str:
    principal_id = _require_head_transition_export_text(
        value,
        "trusted-time anchor principal ID",
    )
    try:
        parsed = UUID(principal_id)
    except (AttributeError, ValueError):
        raise TrustedTimePersistenceError(
            "trusted-time anchor principal ID must be a canonical UUID"
        ) from None
    if parsed.int == 0 or str(parsed) != principal_id:
        raise TrustedTimePersistenceError(
            "trusted-time anchor principal ID must be a non-nil canonical UUID"
        )
    return principal_id


def _require_head_transition_export_project_ref(value: object) -> str:
    project_ref = _require_head_transition_export_text(
        value,
        "trusted-time anchor project ref",
    )
    if len(project_ref) != 20 or any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789" for character in project_ref
    ):
        raise TrustedTimePersistenceError(
            "trusted-time anchor project ref must be 20 lowercase alphanumeric characters"
        )
    return project_ref


@dataclass(frozen=True, slots=True)
class _AuthenticatedHeadTransitionExportScope:
    deployment_identity_sha256: str
    runtime_database_identity_sha256: str
    anchor_project_identity_sha256: str
    anchor_project_ref: str
    bucket_name: str
    principal_id: str


def _authenticated_head_transition_export_scope(
    *,
    deployment_identity_sha256: object,
    runtime_database_identity_sha256: object,
    anchor_project_identity_sha256: object,
    anchor_project_ref: object,
    bucket_name: object,
    principal_id: object,
) -> _AuthenticatedHeadTransitionExportScope:
    bucket = _require_head_transition_export_text(
        bucket_name,
        "trusted-time anchor bucket",
    )
    if bucket != TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME:
        raise TrustedTimePersistenceError(
            "trusted-time anchor bucket must match the exact admitted bucket"
        )
    return _AuthenticatedHeadTransitionExportScope(
        deployment_identity_sha256=_require_head_transition_export_sha256(
            deployment_identity_sha256,
            "trusted-time anchor deployment identity SHA-256",
        ),
        runtime_database_identity_sha256=_require_head_transition_export_sha256(
            runtime_database_identity_sha256,
            "trusted-time anchor runtime-database identity SHA-256",
        ),
        anchor_project_identity_sha256=_require_head_transition_export_sha256(
            anchor_project_identity_sha256,
            "trusted-time anchor project identity SHA-256",
        ),
        anchor_project_ref=_require_head_transition_export_project_ref(anchor_project_ref),
        bucket_name=bucket,
        principal_id=_require_head_transition_export_principal(principal_id),
    )


def _authenticated_head_transition(
    verified_transition: _VerifiedHeadTransition,
    *,
    scope: _AuthenticatedHeadTransitionExportScope,
    previous_host_head_sha256: str | None,
) -> AuthenticatedTrustedTimeHeadTransition:
    epoch = verified_transition.epoch
    evaluation = verified_transition.evaluation
    head = verified_transition.head
    state = None if evaluation is None else evaluation.result.state
    if evaluation is None and epoch.previous_host_head_sha256 != previous_host_head_sha256:
        raise TrustedTimePersistenceConflict(
            "trusted-time authenticated head transition predecessor conflicts"
        )
    try:
        return AuthenticatedTrustedTimeHeadTransition(
            deployment_identity_sha256=scope.deployment_identity_sha256,
            runtime_database_identity_sha256=scope.runtime_database_identity_sha256,
            anchor_project_identity_sha256=scope.anchor_project_identity_sha256,
            anchor_project_ref=scope.anchor_project_ref,
            bucket_name=scope.bucket_name,
            principal_id=scope.principal_id,
            head_authenticated_at_utc=(
                epoch.registered_at_utc if state is None else state.evaluated_at_utc
            ),
            host_id=epoch.host_id,
            source_id=epoch.source_id,
            source_authority_sha256=epoch.source_authority_sha256,
            policy_sha256=TRUSTED_TIME_POLICY.semantic_sha256,
            persistence_contract_version=TRUSTED_TIME_PERSISTENCE_CONTRACT_VERSION,
            epoch_sequence=epoch.epoch_sequence,
            monitor_epoch_id=epoch.monitor_epoch_id,
            epoch_sha256=epoch.semantic_sha256,
            evaluation_sequence=head.evaluation_sequence,
            evaluation_id=None if evaluation is None else evaluation.evaluation_id,
            evaluation_record_sha256=(None if evaluation is None else evaluation.semantic_sha256),
            state_sha256=None if state is None else state.semantic_sha256,
            probe_status=None if evaluation is None else evaluation.result.status,
            health=None if state is None else state.health,
            reason=None if state is None else state.reason,
            hard_failure_latched=None if state is None else state.hard_failure_latched,
            clock_recovery_qualified=(None if state is None else state.clock_recovery_qualified),
            evaluated_at_utc=None if state is None else state.evaluated_at_utc,
            evaluated_at_monotonic_ns=(None if state is None else state.evaluated_at_monotonic_ns),
            previous_host_head_sha256=previous_host_head_sha256,
            current_host_head_sha256=head.semantic_sha256,
        )
    except TrustedTimeHeadAnchorError as error:
        raise TrustedTimePersistenceConflict(
            "trusted-time authenticated head transition projection conflicts"
        ) from error


def _authenticated_head_transitions(
    verified: _VerifiedHost | None,
    *,
    deployment_identity_sha256: object,
    runtime_database_identity_sha256: object,
    anchor_project_identity_sha256: object,
    anchor_project_ref: object,
    bucket_name: object,
    principal_id: object,
    initial_previous_host_head_sha256: str | None = None,
) -> tuple[AuthenticatedTrustedTimeHeadTransition, ...]:
    scope = _authenticated_head_transition_export_scope(
        deployment_identity_sha256=deployment_identity_sha256,
        runtime_database_identity_sha256=runtime_database_identity_sha256,
        anchor_project_identity_sha256=anchor_project_identity_sha256,
        anchor_project_ref=anchor_project_ref,
        bucket_name=bucket_name,
        principal_id=principal_id,
    )
    if verified is None:
        return ()

    exported: list[AuthenticatedTrustedTimeHeadTransition] = []
    previous_head_sha256 = initial_previous_host_head_sha256
    for verified_transition in verified.head_transitions:
        transition = _authenticated_head_transition(
            verified_transition,
            scope=scope,
            previous_host_head_sha256=previous_head_sha256,
        )
        exported.append(transition)
        previous_head_sha256 = transition.current_host_head_sha256

    if not exported or exported[-1].current_host_head_sha256 != verified.head.semantic_sha256:
        raise TrustedTimePersistenceConflict(
            "trusted-time authenticated head transition export is incomplete"
        )
    return tuple(exported)


def _consume_authenticated_head_full_replay(
    connection: Connection,
    *,
    host_id: str,
    deployment_identity_sha256: object,
    runtime_database_identity_sha256: object,
    anchor_project_identity_sha256: object,
    anchor_project_ref: object,
    bucket_name: object,
    principal_id: object,
    page_consumer: Callable[
        [tuple[AuthenticatedTrustedTimeHeadTransition, ...]],
        None,
    ],
    page_size: int = _TRUSTED_TIME_FULL_REPLAY_PAGE_SIZE,
) -> _AuthenticatedHeadFullReplayResult | None:
    """Authenticate and synchronously consume one host replay in bounded pages.

    Pages are provisional until this function returns successfully. Callers
    must not treat a page callback as proof of a complete replay. The caller
    owns ``connection`` and must keep one repeatable-read transaction open for
    the entire call.
    """

    exact_host_id = _require_head_transition_export_text(
        host_id,
        "trusted-time anchor host ID",
    )
    exact_page_size = _require_full_replay_page_size(page_size)
    if not callable(page_consumer):
        raise TrustedTimePersistenceError("trusted-time full replay page consumer must be callable")
    scope = _authenticated_head_transition_export_scope(
        deployment_identity_sha256=deployment_identity_sha256,
        runtime_database_identity_sha256=runtime_database_identity_sha256,
        anchor_project_identity_sha256=anchor_project_identity_sha256,
        anchor_project_ref=anchor_project_ref,
        bucket_name=bucket_name,
        principal_id=principal_id,
    )

    pending_page: list[AuthenticatedTrustedTimeHeadTransition] = []
    first_transition: AuthenticatedTrustedTimeHeadTransition | None = None
    current_transition: AuthenticatedTrustedTimeHeadTransition | None = None
    transition_count = 0
    previous_host_head_sha256: str | None = None

    def consume_verified_transition(verified_transition: _VerifiedHeadTransition) -> None:
        nonlocal first_transition
        nonlocal current_transition
        nonlocal transition_count
        nonlocal previous_host_head_sha256
        transition = _authenticated_head_transition(
            verified_transition,
            scope=scope,
            previous_host_head_sha256=previous_host_head_sha256,
        )
        if first_transition is None:
            first_transition = transition
        current_transition = transition
        transition_count += 1
        previous_host_head_sha256 = transition.current_host_head_sha256
        pending_page.append(transition)
        if len(pending_page) == exact_page_size:
            page_consumer(tuple(pending_page))
            pending_page.clear()

    verified = _verified_host(
        connection,
        exact_host_id,
        for_update=False,
        transition_consumer=consume_verified_transition,
        replay_page_size=exact_page_size,
        collect_transitions=False,
    )
    if verified is None:
        return None
    if (
        first_transition is None
        or current_transition is None
        or transition_count < 1
        or current_transition.current_host_head_sha256 != verified.head.semantic_sha256
    ):
        raise TrustedTimePersistenceConflict(
            "trusted-time authenticated head transition export is incomplete"
        )
    if pending_page:
        page_consumer(tuple(pending_page))
        pending_page.clear()
    return _AuthenticatedHeadFullReplayResult(
        verified=verified,
        first_transition=first_transition,
        current_transition=current_transition,
        transition_count=transition_count,
    )


def _verify_global_integrity(connection: Connection) -> None:
    raw_host_ids = connection.scalars(
        sa.union(
            sa.select(phase6_trusted_time_epoch_registrations.c.host_id),
            sa.select(phase6_trusted_time_host_heads.c.host_id),
            sa.select(phase6_trusted_time_probe_evaluations.c.host_id),
        )
    )
    host_ids: set[str] = set()
    for value in raw_host_ids:
        if type(value) is not str:
            raise TrustedTimePersistenceError("persisted trusted-time host ID must be text")
        host_ids.add(value)
    for host_id in sorted(host_ids):
        _verified_host(connection, host_id, for_update=False)


def verify_trusted_time_integrity(engine: Engine) -> None:
    """Authenticate every epoch, evaluation, reducer replay, and current head."""

    if not isinstance(engine, Engine):
        raise TrustedTimePersistenceError("trusted-time verification requires an Engine")
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise TrustedTimePersistenceError(
            f"trusted-time verification does not support dialect {engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_global_integrity(connection)


class SqlTrustedTimeRepository:
    """Register non-resumable epochs and CAS-append reducer-authenticated probes."""

    __slots__ = (
        "_active_sessions",
        "_authenticated_head_replay_proofs",
        "_authenticated_head_snapshots",
        "_engine",
        "_lock",
        "_owner_process_id",
        "_repository_token",
    )

    def __init__(self, engine: Engine) -> None:
        if not isinstance(engine, Engine):
            raise TrustedTimePersistenceError("SQL trusted-time repository requires an Engine")
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise TrustedTimePersistenceError(
                f"SQL trusted-time repository does not support dialect {engine.dialect.name!r}"
            )
        self._engine = engine
        self._owner_process_id = os.getpid()
        self._repository_token = object()
        self._active_sessions: dict[int, _ActiveSession] = {}
        self._authenticated_head_replay_proofs: dict[
            int,
            _AuthenticatedHeadReplayProofState,
        ] = {}
        self._authenticated_head_snapshots: dict[
            int,
            _AuthenticatedHeadSnapshotState,
        ] = {}
        self._lock = threading.RLock()

    def _require_owner_process(self) -> int:
        process_id = os.getpid()
        if process_id != self._owner_process_id:
            raise TrustedTimePersistenceConflict(
                "trusted-time repository cannot cross process identity"
            )
        return process_id

    def _require_active_session(self, session: DurableTrustedTimeEpochSession) -> _ActiveSession:
        if type(session) is not DurableTrustedTimeEpochSession:
            raise TrustedTimePersistenceConflict(
                "trusted-time epoch session must be repository-issued"
            )
        process_id = self._require_owner_process()
        with self._lock:
            active = self._active_sessions.get(id(session))
            if (
                active is None
                or active.session is not session
                or active.process_id != process_id
                or active.repository_token is not self._repository_token
            ):
                raise TrustedTimePersistenceConflict(
                    "trusted-time epoch session is not active in this repository"
                )
            try:
                session.__post_init__()
            except Exception:
                raise TrustedTimePersistenceConflict(
                    "trusted-time epoch session is malformed"
                ) from None
            if (
                session.binding.source_id != active.source_id
                or session.binding.source_authority_sha256 != active.source_authority_sha256
                or session.binding.host_id != active.host_id
                or session.binding.monitor_epoch_id != active.monitor_epoch_id
                or session.epoch_registration_sha256 != active.epoch_registration_sha256
            ):
                raise TrustedTimePersistenceConflict(
                    "trusted-time epoch session identity was modified"
                )
            return active

    def _require_authenticated_head_snapshot(
        self,
        snapshot: AuthenticatedTrustedTimeHeadSnapshot,
    ) -> _AuthenticatedHeadSnapshotState:
        if type(snapshot) is not AuthenticatedTrustedTimeHeadSnapshot:
            raise TrustedTimePersistenceConflict(
                "trusted-time authenticated head snapshot must be repository-issued"
            )
        process_id = self._require_owner_process()
        state = self._authenticated_head_snapshots.get(id(snapshot))
        if (
            state is None
            or state.snapshot is not snapshot
            or state.process_id != process_id
            or state.repository_token is not self._repository_token
            or snapshot.transition_count != state.transition_count
            or snapshot.current_host_head_sha256 != state.head.semantic_sha256
            or snapshot.full_replay_proof is not state.full_replay_proof
        ):
            raise TrustedTimePersistenceConflict(
                "trusted-time authenticated head snapshot is stale or foreign"
            )
        if state.full_replay_proof is not None:
            self._require_authenticated_head_replay_proof(state.full_replay_proof)
        return state

    def _issue_authenticated_head_replay_proof(
        self,
        result: _AuthenticatedHeadFullReplayResult,
        *,
        host_id: str,
        deployment_identity_sha256: str,
        runtime_database_identity_sha256: str,
        anchor_project_identity_sha256: str,
        anchor_project_ref: str,
        bucket_name: str,
        principal_id: str,
    ) -> AuthenticatedTrustedTimeHeadReplayProof:
        proof = _new_authenticated_trusted_time_head_replay_proof(
            first_transition=result.first_transition,
            current_transition=result.current_transition,
            transition_count=result.transition_count,
        )
        verified = result.verified
        self._authenticated_head_replay_proofs[id(proof)] = _AuthenticatedHeadReplayProofState(
            proof=proof,
            process_id=self._owner_process_id,
            repository_token=self._repository_token,
            first_transition=result.first_transition,
            current_transition=result.current_transition,
            host_id=host_id,
            deployment_identity_sha256=deployment_identity_sha256,
            runtime_database_identity_sha256=runtime_database_identity_sha256,
            anchor_project_identity_sha256=anchor_project_identity_sha256,
            anchor_project_ref=anchor_project_ref,
            bucket_name=bucket_name,
            principal_id=principal_id,
            epoch=verified.epoch,
            head=verified.head,
            prior=verified.prior,
            terminal_evaluation=verified.terminal_evaluation,
            transition_count=result.transition_count,
        )
        return proof

    def _require_authenticated_head_replay_proof(
        self,
        proof: AuthenticatedTrustedTimeHeadReplayProof,
    ) -> _AuthenticatedHeadReplayProofState:
        if type(proof) is not AuthenticatedTrustedTimeHeadReplayProof:
            raise TrustedTimePersistenceConflict(
                "trusted-time authenticated replay proof must be repository-issued"
            )
        process_id = self._require_owner_process()
        state = self._authenticated_head_replay_proofs.get(id(proof))
        if (
            state is None
            or state.proof is not proof
            or state.process_id != process_id
            or state.repository_token is not self._repository_token
            or proof.first_transition != state.first_transition
            or proof.current_transition != state.current_transition
            or proof.first_transition.host_id != state.host_id
            or proof.current_transition.current_host_head_sha256 != state.head.semantic_sha256
            or proof.current_host_head_sha256 != state.head.semantic_sha256
            or proof.transition_count != state.transition_count
        ):
            raise TrustedTimePersistenceConflict(
                "trusted-time authenticated replay proof is stale or foreign"
            )
        return state

    def _replace_authenticated_head_snapshot(
        self,
        *,
        previous: AuthenticatedTrustedTimeHeadSnapshot | None,
        local_transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
        complete_replay: bool,
        full_replay_proof: AuthenticatedTrustedTimeHeadReplayProof | None,
        verified: _VerifiedHost,
        transition_count: int,
        host_id: str,
        deployment_identity_sha256: str,
        runtime_database_identity_sha256: str,
        anchor_project_identity_sha256: str,
        anchor_project_ref: str,
        bucket_name: str,
        principal_id: str,
    ) -> AuthenticatedTrustedTimeHeadSnapshot:
        snapshot = _new_authenticated_trusted_time_head_snapshot(
            local_transitions=local_transitions,
            transition_count=transition_count,
            current_host_head_sha256=verified.head.semantic_sha256,
            complete_replay=complete_replay,
            full_replay_proof=full_replay_proof,
        )
        self._authenticated_head_snapshots[id(snapshot)] = _AuthenticatedHeadSnapshotState(
            snapshot=snapshot,
            process_id=self._owner_process_id,
            repository_token=self._repository_token,
            host_id=host_id,
            deployment_identity_sha256=deployment_identity_sha256,
            runtime_database_identity_sha256=runtime_database_identity_sha256,
            anchor_project_identity_sha256=anchor_project_identity_sha256,
            anchor_project_ref=anchor_project_ref,
            bucket_name=bucket_name,
            principal_id=principal_id,
            epoch=verified.epoch,
            head=verified.head,
            prior=verified.prior,
            terminal_evaluation=verified.terminal_evaluation,
            transition_count=transition_count,
            full_replay_proof=full_replay_proof,
        )
        if previous is not None:
            previous_state = self._authenticated_head_snapshots.pop(id(previous), None)
            if previous_state is not None and previous_state.full_replay_proof is not None:
                self._authenticated_head_replay_proofs.pop(
                    id(previous_state.full_replay_proof),
                    None,
                )
        return snapshot

    def register_new_epoch(
        self,
        *,
        source_id: str,
        source_authority_sha256: str,
        host_id: str,
        recorded_at: datetime,
    ) -> DurableTrustedTimeEpochSession:
        """Create a fresh epoch and sequence-zero head; never resume durable state."""

        self._require_owner_process()
        with self._lock:
            return self._register_new_epoch_locked(
                source_id=source_id,
                source_authority_sha256=source_authority_sha256,
                host_id=host_id,
                recorded_at=recorded_at,
            )

    def _register_new_epoch_locked(
        self,
        *,
        source_id: str,
        source_authority_sha256: str,
        host_id: str,
        recorded_at: datetime,
    ) -> DurableTrustedTimeEpochSession:
        self._require_owner_process()
        recorded_at = _require_utc(recorded_at, "trusted-time epoch recorded_at")
        try:
            binding = TrustedTimeMonitorBinding(
                source_id=source_id,
                source_authority_sha256=source_authority_sha256,
                host_id=host_id,
                monitor_epoch_id=str(uuid.uuid4()),
            )
            with _write_transaction(self._engine) as connection:
                current = _verified_host(connection, binding.host_id, for_update=True)
                epoch = _new_epoch(
                    binding=binding,
                    epoch_sequence=(1 if current is None else current.epoch.epoch_sequence + 1),
                    previous_monitor_epoch_id=(
                        None if current is None else current.epoch.monitor_epoch_id
                    ),
                    previous_epoch_sha256=(
                        None if current is None else current.epoch.semantic_sha256
                    ),
                    previous_host_head_sha256=(
                        None if current is None else current.head.semantic_sha256
                    ),
                    registered_at_utc=recorded_at,
                )
                connection.execute(
                    sa.insert(phase6_trusted_time_epoch_registrations).values(
                        **_epoch_values(epoch)
                    )
                )
                head = _new_head(epoch, None)
                if current is None:
                    connection.execute(
                        sa.insert(phase6_trusted_time_host_heads).values(**_head_values(head))
                    )
                else:
                    updated = connection.execute(
                        sa.update(phase6_trusted_time_host_heads)
                        .where(
                            phase6_trusted_time_host_heads.c.host_id == binding.host_id,
                            phase6_trusted_time_host_heads.c.semantic_sha256
                            == current.head.semantic_sha256,
                        )
                        .values(**_head_values(head))
                    )
                    if updated.rowcount != 1:
                        raise TrustedTimePersistenceConflict(
                            "trusted-time host head changed during epoch registration"
                        )
                readback = _verified_host(connection, binding.host_id, for_update=False)
                if (
                    readback is None
                    or readback.epoch != epoch
                    or readback.head != head
                    or readback.prior is not None
                ):
                    raise TrustedTimePersistenceError(
                        "trusted-time epoch failed exact SQL readback"
                    )
        except TrustedTimePersistenceError:
            raise
        except IntegrityError as error:
            raise TrustedTimePersistenceConflict(
                "trusted-time epoch registration conflicts"
            ) from error
        except (SQLAlchemyError, TrustedTimeMonitorError) as error:
            raise TrustedTimePersistenceError("trusted-time epoch registration failed") from error

        session = _new_durable_trusted_time_epoch_session(
            binding=binding,
            epoch_registration_sha256=epoch.semantic_sha256,
        )
        with self._lock:
            for key, active in tuple(self._active_sessions.items()):
                if active.host_id == binding.host_id:
                    del self._active_sessions[key]
            self._active_sessions[id(session)] = _ActiveSession(
                session=session,
                process_id=self._owner_process_id,
                repository_token=self._repository_token,
                source_id=binding.source_id,
                source_authority_sha256=binding.source_authority_sha256,
                host_id=binding.host_id,
                monitor_epoch_id=binding.monitor_epoch_id,
                epoch_registration_sha256=epoch.semantic_sha256,
                epoch=readback.epoch,
                head=readback.head,
                prior=readback.prior,
                terminal_evaluation=readback.terminal_evaluation,
            )
        return session

    def prepare_probe(self, session: DurableTrustedTimeEpochSession) -> PreparedTrustedTimeProbe:
        """Authenticate the exact current epoch head before external source I/O."""

        with self._lock:
            active = self._require_active_session(session)
            binding = active.binding
            with _repeatable_read_transaction(self._engine) as connection:
                current = _verify_cached_host_tip(connection, active, for_update=False)
                return PreparedTrustedTimeProbe(
                    binding=binding,
                    prior=current.prior,
                    expected_host_head_sha256=current.head.semantic_sha256,
                    epoch_registration_sha256=current.epoch.semantic_sha256,
                    next_evaluation_sequence=current.head.evaluation_sequence + 1,
                )

    def append_probe(
        self,
        session: DurableTrustedTimeEpochSession,
        *,
        prepared: PreparedTrustedTimeProbe,
        result: TrustedTimeMonitorResult,
    ) -> PersistedTrustedTimeProbe:
        """Append once under an exact head CAS; stale preparations never retry."""

        with self._lock:
            active = self._require_active_session(session)
            binding = active.binding
            if type(prepared) is not PreparedTrustedTimeProbe:
                raise TrustedTimePersistenceConflict(
                    "trusted-time append requires an exact preparation"
                )
            if type(result) is not TrustedTimeMonitorResult:
                raise TrustedTimePersistenceConflict(
                    "trusted-time append requires an exact monitor result"
                )
            try:
                prepared.__post_init__()
                result.__post_init__()
                result.evaluation.__post_init__()
            except Exception as error:
                raise TrustedTimePersistenceConflict(
                    "trusted-time append inputs are invalid"
                ) from error
            if (
                prepared.binding != binding
                or prepared.epoch_registration_sha256 != active.epoch_registration_sha256
            ):
                raise TrustedTimePersistenceConflict(
                    "trusted-time preparation crosses epoch identity"
                )

            try:
                with _write_transaction(self._engine) as connection:
                    current = _verify_cached_host_tip(connection, active, for_update=True)
                    expected_prepared = PreparedTrustedTimeProbe(
                        binding=current.epoch.binding,
                        prior=current.prior,
                        expected_host_head_sha256=current.head.semantic_sha256,
                        epoch_registration_sha256=current.epoch.semantic_sha256,
                        next_evaluation_sequence=(current.head.evaluation_sequence + 1),
                    )
                    if expected_prepared != prepared:
                        raise TrustedTimePersistenceConflict(
                            "trusted-time host head changed after preparation"
                        )
                    if (
                        result.evaluation.prior != prepared.prior
                        or result.evaluation.state.previous_state_sha256
                        != (None if prepared.prior is None else prepared.prior.semantic_sha256)
                    ):
                        raise TrustedTimePersistenceConflict(
                            "trusted-time result does not extend the prepared state"
                        )
                    sample = result.evaluation.sample
                    if sample is not None and (
                        sample.source_id != binding.source_id
                        or sample.source_authority_sha256 != binding.source_authority_sha256
                        or sample.host_id != binding.host_id
                        or sample.monitor_epoch_id != binding.monitor_epoch_id
                    ):
                        raise TrustedTimePersistenceConflict(
                            "trusted-time sample crosses epoch binding"
                        )

                    previous = current.terminal_evaluation
                    evaluation_id = str(uuid.uuid4())
                    values = _evaluation_values(
                        evaluation_id=evaluation_id,
                        epoch=current.epoch,
                        evaluation_sequence=prepared.next_evaluation_sequence,
                        previous_evaluation_id=(
                            None if previous is None else previous.evaluation_id
                        ),
                        previous_evaluation_sha256=(
                            None if previous is None else previous.semantic_sha256
                        ),
                        result=result,
                    )
                    connection.execute(
                        sa.insert(phase6_trusted_time_probe_evaluations).values(**values)
                    )
                    terminal = _EvaluationRecord(
                        evaluation_id=evaluation_id,
                        evaluation_sequence=prepared.next_evaluation_sequence,
                        previous_evaluation_id=(
                            None if previous is None else previous.evaluation_id
                        ),
                        previous_evaluation_sha256=(
                            None if previous is None else previous.semantic_sha256
                        ),
                        semantic_sha256=str(values["semantic_sha256"]),
                        result=result,
                    )
                    head = _new_head(current.epoch, terminal)
                    updated = connection.execute(
                        sa.update(phase6_trusted_time_host_heads)
                        .where(
                            phase6_trusted_time_host_heads.c.host_id == binding.host_id,
                            phase6_trusted_time_host_heads.c.semantic_sha256
                            == prepared.expected_host_head_sha256,
                        )
                        .values(**_head_values(head))
                    )
                    if updated.rowcount != 1:
                        raise TrustedTimePersistenceConflict(
                            "trusted-time host head compare-and-swap lost"
                        )
                    evaluation_row = (
                        connection.execute(
                            sa.select(phase6_trusted_time_probe_evaluations).where(
                                phase6_trusted_time_probe_evaluations.c.evaluation_id
                                == evaluation_id
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if evaluation_row is None:
                        raise TrustedTimePersistenceError(
                            "trusted-time probe append lost its inserted evaluation"
                        )
                    _assert_exact_row(evaluation_row, values, "appended probe evaluation")
                    readback_head = _select_head(
                        connection,
                        binding.host_id,
                        for_update=False,
                    )
                    if readback_head != head:
                        raise TrustedTimePersistenceError(
                            "trusted-time probe append failed exact SQL readback"
                        )
            except TrustedTimePersistenceError:
                raise
            except IntegrityError as error:
                raise TrustedTimePersistenceConflict(
                    "trusted-time probe append conflicts"
                ) from error
            except (SQLAlchemyError, TrustedTimeError) as error:
                raise TrustedTimePersistenceError("trusted-time probe append failed") from error

            self._active_sessions[id(session)] = _ActiveSession(
                session=active.session,
                process_id=active.process_id,
                repository_token=active.repository_token,
                source_id=active.source_id,
                source_authority_sha256=active.source_authority_sha256,
                host_id=active.host_id,
                monitor_epoch_id=active.monitor_epoch_id,
                epoch_registration_sha256=active.epoch_registration_sha256,
                epoch=current.epoch,
                head=head,
                prior=result.state,
                terminal_evaluation=terminal,
            )
            return PersistedTrustedTimeProbe(
                result=result,
                evaluation_sequence=terminal.evaluation_sequence,
                record_sha256=terminal.semantic_sha256,
                host_head_sha256=head.semantic_sha256,
            )

    def verify_active_session_tip(
        self,
        session: DurableTrustedTimeEpochSession,
    ) -> None:
        """Run the constant-size rolling audit used by the active probe path."""

        with self._lock:
            active = self._require_active_session(session)
            with _repeatable_read_transaction(self._engine) as connection:
                _verify_cached_host_tip(connection, active, for_update=False)

    def consume_authenticated_head_full_replay(
        self,
        *,
        host_id: str,
        deployment_identity_sha256: str,
        runtime_database_identity_sha256: str,
        anchor_project_identity_sha256: str,
        anchor_project_ref: str,
        bucket_name: str,
        principal_id: str,
        page_consumer: Callable[
            [tuple[AuthenticatedTrustedTimeHeadTransition, ...]],
            None,
        ],
        page_size: int = _TRUSTED_TIME_FULL_REPLAY_PAGE_SIZE,
    ) -> AuthenticatedTrustedTimeHeadReplayProof:
        """Consume a full replay in bounded pages and issue its compact proof.

        Every callback runs synchronously inside the same stable SQL snapshot.
        Pages are provisional until this method returns. A callback failure or
        any incomplete/tampered replay prevents proof issuance.
        """

        exact_host_id = _require_head_transition_export_text(
            host_id,
            "trusted-time anchor host ID",
        )
        scope = _authenticated_head_transition_export_scope(
            deployment_identity_sha256=deployment_identity_sha256,
            runtime_database_identity_sha256=runtime_database_identity_sha256,
            anchor_project_identity_sha256=anchor_project_identity_sha256,
            anchor_project_ref=anchor_project_ref,
            bucket_name=bucket_name,
            principal_id=principal_id,
        )
        exact_page_size = _require_full_replay_page_size(page_size)
        with self._lock:
            self._require_owner_process()
            with _repeatable_read_transaction(self._engine) as connection:
                result = _consume_authenticated_head_full_replay(
                    connection,
                    host_id=exact_host_id,
                    deployment_identity_sha256=scope.deployment_identity_sha256,
                    runtime_database_identity_sha256=(scope.runtime_database_identity_sha256),
                    anchor_project_identity_sha256=(scope.anchor_project_identity_sha256),
                    anchor_project_ref=scope.anchor_project_ref,
                    bucket_name=scope.bucket_name,
                    principal_id=scope.principal_id,
                    page_consumer=page_consumer,
                    page_size=exact_page_size,
                )
            if result is None:
                raise TrustedTimePersistenceConflict(
                    "trusted-time full replay proof requires an existing host history"
                )
            return self._issue_authenticated_head_replay_proof(
                result,
                host_id=exact_host_id,
                deployment_identity_sha256=scope.deployment_identity_sha256,
                runtime_database_identity_sha256=scope.runtime_database_identity_sha256,
                anchor_project_identity_sha256=scope.anchor_project_identity_sha256,
                anchor_project_ref=scope.anchor_project_ref,
                bucket_name=scope.bucket_name,
                principal_id=scope.principal_id,
            )

    def discard_authenticated_head_full_replay_proof(
        self,
        proof: AuthenticatedTrustedTimeHeadReplayProof,
    ) -> None:
        """Release one process-local full-replay proof explicitly."""

        with self._lock:
            self._require_authenticated_head_replay_proof(proof)
            if any(
                state.full_replay_proof is proof
                for state in self._authenticated_head_snapshots.values()
            ):
                raise TrustedTimePersistenceConflict(
                    "trusted-time replay proof is retained by an active startup snapshot"
                )
            self._authenticated_head_replay_proofs.pop(id(proof), None)

    def load_authenticated_head_startup_snapshot(
        self,
        *,
        host_id: str,
        deployment_identity_sha256: str,
        runtime_database_identity_sha256: str,
        anchor_project_identity_sha256: str,
        anchor_project_ref: str,
        bucket_name: str,
        principal_id: str,
    ) -> AuthenticatedTrustedTimeHeadSnapshot:
        """Bounded-full-replay one host and issue a compact sealed cursor."""

        exact_host_id = _require_head_transition_export_text(
            host_id,
            "trusted-time anchor host ID",
        )
        exact_deployment = _require_head_transition_export_sha256(
            deployment_identity_sha256,
            "trusted-time anchor deployment identity SHA-256",
        )
        exact_database = _require_head_transition_export_sha256(
            runtime_database_identity_sha256,
            "trusted-time anchor runtime-database identity SHA-256",
        )
        exact_project_identity = _require_head_transition_export_sha256(
            anchor_project_identity_sha256,
            "trusted-time anchor project identity SHA-256",
        )
        exact_project_ref = _require_head_transition_export_project_ref(anchor_project_ref)
        exact_bucket = _require_head_transition_export_text(
            bucket_name,
            "trusted-time anchor bucket",
        )
        if exact_bucket != TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME:
            raise TrustedTimePersistenceError(
                "trusted-time anchor bucket must match the exact admitted bucket"
            )
        exact_principal = _require_head_transition_export_principal(principal_id)

        with self._lock:
            self._require_owner_process()
            with _repeatable_read_transaction(self._engine) as connection:
                replay = _consume_authenticated_head_full_replay(
                    connection,
                    host_id=exact_host_id,
                    deployment_identity_sha256=exact_deployment,
                    runtime_database_identity_sha256=exact_database,
                    anchor_project_identity_sha256=exact_project_identity,
                    anchor_project_ref=exact_project_ref,
                    bucket_name=exact_bucket,
                    principal_id=exact_principal,
                    page_consumer=lambda _page: None,
                )
                if replay is None:
                    raise TrustedTimePersistenceConflict(
                        "trusted-time startup snapshot requires an existing host history"
                    )
            proof = self._issue_authenticated_head_replay_proof(
                replay,
                host_id=exact_host_id,
                deployment_identity_sha256=exact_deployment,
                runtime_database_identity_sha256=exact_database,
                anchor_project_identity_sha256=exact_project_identity,
                anchor_project_ref=exact_project_ref,
                bucket_name=exact_bucket,
                principal_id=exact_principal,
            )
            return self._replace_authenticated_head_snapshot(
                previous=None,
                local_transitions=(),
                complete_replay=True,
                full_replay_proof=proof,
                verified=replay.verified,
                transition_count=replay.transition_count,
                host_id=exact_host_id,
                deployment_identity_sha256=exact_deployment,
                runtime_database_identity_sha256=exact_database,
                anchor_project_identity_sha256=exact_project_identity,
                anchor_project_ref=exact_project_ref,
                bucket_name=exact_bucket,
                principal_id=exact_principal,
            )

    def compact_authenticated_head_snapshot(
        self,
        snapshot: AuthenticatedTrustedTimeHeadSnapshot,
    ) -> AuthenticatedTrustedTimeHeadSnapshot:
        """Release a consumed replay/suffix while retaining its sealed tip."""

        with self._lock:
            state = self._require_authenticated_head_snapshot(snapshot)
            if not snapshot.local_transitions and not snapshot.complete_replay:
                return snapshot
            verified = _VerifiedHost(
                epoch=state.epoch,
                head=state.head,
                prior=state.prior,
                terminal_evaluation=state.terminal_evaluation,
                head_transitions=(),
            )
            return self._replace_authenticated_head_snapshot(
                previous=snapshot,
                local_transitions=(),
                complete_replay=False,
                full_replay_proof=None,
                verified=verified,
                transition_count=state.transition_count,
                host_id=state.host_id,
                deployment_identity_sha256=state.deployment_identity_sha256,
                runtime_database_identity_sha256=state.runtime_database_identity_sha256,
                anchor_project_identity_sha256=state.anchor_project_identity_sha256,
                anchor_project_ref=state.anchor_project_ref,
                bucket_name=state.bucket_name,
                principal_id=state.principal_id,
            )

    def discard_authenticated_head_snapshot(
        self,
        snapshot: AuthenticatedTrustedTimeHeadSnapshot,
    ) -> None:
        """Release one no-longer-used startup/on-demand cursor explicitly."""

        with self._lock:
            state = self._require_authenticated_head_snapshot(snapshot)
            self._authenticated_head_snapshots.pop(id(snapshot), None)
            if state.full_replay_proof is not None:
                self._authenticated_head_replay_proofs.pop(
                    id(state.full_replay_proof),
                    None,
                )

    def refresh_authenticated_head_snapshot(
        self,
        snapshot: AuthenticatedTrustedTimeHeadSnapshot,
    ) -> AuthenticatedTrustedTimeHeadSnapshot:
        """Authenticate only the suffix appended after a sealed cursor."""

        with self._lock:
            state = self._require_authenticated_head_snapshot(snapshot)
            with _repeatable_read_transaction(self._engine) as connection:
                verified = _verified_host_suffix(connection, state)
                if not verified.head_transitions:
                    return snapshot
                transitions = _authenticated_head_transitions(
                    verified,
                    deployment_identity_sha256=state.deployment_identity_sha256,
                    runtime_database_identity_sha256=state.runtime_database_identity_sha256,
                    anchor_project_identity_sha256=(state.anchor_project_identity_sha256),
                    anchor_project_ref=state.anchor_project_ref,
                    bucket_name=state.bucket_name,
                    principal_id=state.principal_id,
                    initial_previous_host_head_sha256=state.head.semantic_sha256,
                )
            return self._replace_authenticated_head_snapshot(
                previous=snapshot,
                local_transitions=transitions,
                complete_replay=False,
                full_replay_proof=None,
                verified=verified,
                transition_count=state.transition_count + len(transitions),
                host_id=state.host_id,
                deployment_identity_sha256=state.deployment_identity_sha256,
                runtime_database_identity_sha256=state.runtime_database_identity_sha256,
                anchor_project_identity_sha256=state.anchor_project_identity_sha256,
                anchor_project_ref=state.anchor_project_ref,
                bucket_name=state.bucket_name,
                principal_id=state.principal_id,
            )

    def read_authenticated_head_transitions(
        self,
        *,
        host_id: str,
        deployment_identity_sha256: str,
        runtime_database_identity_sha256: str,
        anchor_project_identity_sha256: str,
        anchor_project_ref: str,
        bucket_name: str,
        principal_id: str,
    ) -> tuple[AuthenticatedTrustedTimeHeadTransition, ...]:
        """Diagnostic compatibility export of the complete transition tuple.

        Production consumers must use the bounded callback/proof API. This
        diagnostic adapter necessarily allocates its returned tuple, but raw
        SQL rows and intermediate replay transitions remain page bounded. The
        returned evidence grants no readiness, control, or broker authority.
        """

        transitions: list[AuthenticatedTrustedTimeHeadTransition] = []
        with _repeatable_read_transaction(self._engine) as connection:
            _consume_authenticated_head_full_replay(
                connection,
                host_id=host_id,
                deployment_identity_sha256=deployment_identity_sha256,
                runtime_database_identity_sha256=runtime_database_identity_sha256,
                anchor_project_identity_sha256=anchor_project_identity_sha256,
                anchor_project_ref=anchor_project_ref,
                bucket_name=bucket_name,
                principal_id=principal_id,
                page_consumer=transitions.extend,
            )
        return tuple(transitions)

    def verify_integrity(self) -> None:
        """Authenticate all durable trusted-time histories."""

        verify_trusted_time_integrity(self._engine)


__all__ = [
    "TRUSTED_TIME_PERSISTENCE_CONTRACT_VERSION",
    "AuthenticatedTrustedTimeHeadReplayProof",
    "AuthenticatedTrustedTimeHeadSnapshot",
    "SqlTrustedTimeRepository",
    "TrustedTimePersistenceConflict",
    "TrustedTimePersistenceError",
    "verify_trusted_time_integrity",
]
