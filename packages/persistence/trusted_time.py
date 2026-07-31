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
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

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
from packages.application.trusted_time_monitor import (
    TrustedTimeMonitorBinding,
    TrustedTimeMonitorError,
    TrustedTimeMonitorResult,
    TrustedTimeProbeStatus,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
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
TrustedTimeRow = Mapping[str, object] | RowMapping


class TrustedTimePersistenceError(RuntimeError):
    """Durable trusted-time evidence is malformed or unavailable."""


class TrustedTimePersistenceConflict(TrustedTimePersistenceError):
    """A session, immutable fact, or expected host head conflicts."""


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
class _VerifiedHost:
    epoch: _EpochRegistration
    head: _HostHead
    prior: TrustedTimeState | None
    terminal_evaluation: _EvaluationRecord | None


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

    @property
    def binding(self) -> TrustedTimeMonitorBinding:
        return TrustedTimeMonitorBinding(
            source_id=self.source_id,
            source_authority_sha256=self.source_authority_sha256,
            host_id=self.host_id,
            monitor_epoch_id=self.monitor_epoch_id,
        )


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
    previous: _EvaluationRecord | None,
    result: TrustedTimeMonitorResult,
) -> dict[str, Any]:
    sample = result.evaluation.sample
    state = result.state
    material = _evaluation_material(
        evaluation_id=evaluation_id,
        epoch=epoch,
        evaluation_sequence=evaluation_sequence,
        previous_evaluation_id=None if previous is None else previous.evaluation_id,
        previous_evaluation_sha256=(None if previous is None else previous.semantic_sha256),
        result=result,
    )
    return {
        "evaluation_id": evaluation_id,
        "host_id": epoch.host_id,
        "monitor_epoch_id": epoch.monitor_epoch_id,
        "epoch_sha256": epoch.semantic_sha256,
        "evaluation_sequence": evaluation_sequence,
        "previous_evaluation_id": (None if previous is None else previous.evaluation_id),
        "previous_evaluation_sha256": (None if previous is None else previous.semantic_sha256),
        "probe_status": result.status.value,
        "sample_sequence": None if sample is None else sample.sequence,
        "source_evidence_sha256": (None if sample is None else sample.source_evidence_sha256),
        "probe_started_at_utc": (None if sample is None else sample.probe_started_at_utc),
        "probe_completed_at_utc": (None if sample is None else sample.probe_completed_at_utc),
        "trusted_at_utc": None if sample is None else sample.trusted_at_utc,
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
            previous=previous,
            result=result,
        )
        _assert_exact_row(row, values, "probe evaluation")
        return _EvaluationRecord(
            evaluation_id=evaluation_id,
            evaluation_sequence=expected_sequence,
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


def _verified_host(
    connection: Connection,
    host_id: str,
    *,
    for_update: bool,
) -> _VerifiedHost | None:
    head = _select_head(connection, host_id, for_update=for_update)
    epoch_rows = (
        connection.execute(
            sa.select(phase6_trusted_time_epoch_registrations)
            .where(phase6_trusted_time_epoch_registrations.c.host_id == host_id)
            .order_by(phase6_trusted_time_epoch_registrations.c.epoch_sequence)
        )
        .mappings()
        .all()
    )
    if not epoch_rows:
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
    for expected_epoch_sequence, row in enumerate(epoch_rows, start=1):
        epoch = _epoch_from_row(row)
        if epoch.epoch_sequence != expected_epoch_sequence:
            raise TrustedTimePersistenceError("trusted-time epoch history is not contiguous")
        if (
            epoch.previous_monitor_epoch_id
            != (None if previous_epoch is None else previous_epoch.monitor_epoch_id)
            or epoch.previous_epoch_sha256
            != (None if previous_epoch is None else previous_epoch.semantic_sha256)
            or epoch.previous_host_head_sha256
            != (None if previous_terminal_head is None else previous_terminal_head.semantic_sha256)
        ):
            raise TrustedTimePersistenceError("trusted-time epoch predecessor chain conflicts")

        evaluation_rows = (
            connection.execute(
                sa.select(phase6_trusted_time_probe_evaluations)
                .where(
                    phase6_trusted_time_probe_evaluations.c.host_id == host_id,
                    phase6_trusted_time_probe_evaluations.c.monitor_epoch_id
                    == epoch.monitor_epoch_id,
                )
                .order_by(phase6_trusted_time_probe_evaluations.c.evaluation_sequence)
            )
            .mappings()
            .all()
        )
        prior: TrustedTimeState | None = None
        terminal: _EvaluationRecord | None = None
        for expected_evaluation_sequence, evaluation_row in enumerate(evaluation_rows, start=1):
            terminal = _evaluation_from_row(
                evaluation_row,
                epoch=epoch,
                prior=prior,
                previous=terminal,
                expected_sequence=expected_evaluation_sequence,
            )
            prior = terminal.result.state
        previous_terminal_head = _new_head(epoch, terminal)
        previous_epoch = epoch
        current_epoch = epoch
        current_prior = prior
        current_terminal = terminal

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
            )
        return session

    def prepare_probe(self, session: DurableTrustedTimeEpochSession) -> PreparedTrustedTimeProbe:
        """Authenticate the exact current epoch head before external source I/O."""

        active = self._require_active_session(session)
        binding = active.binding
        with _repeatable_read_transaction(self._engine) as connection:
            current = _verified_host(connection, binding.host_id, for_update=False)
            if (
                current is None
                or current.epoch.binding != binding
                or current.epoch.semantic_sha256 != active.epoch_registration_sha256
            ):
                raise TrustedTimePersistenceConflict(
                    "trusted-time session is not the current durable epoch"
                )
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
            raise TrustedTimePersistenceConflict("trusted-time preparation crosses epoch identity")

        try:
            with _write_transaction(self._engine) as connection:
                current = _verified_host(connection, binding.host_id, for_update=True)
                expected_prepared = (
                    None
                    if current is None
                    else PreparedTrustedTimeProbe(
                        binding=current.epoch.binding,
                        prior=current.prior,
                        expected_host_head_sha256=current.head.semantic_sha256,
                        epoch_registration_sha256=current.epoch.semantic_sha256,
                        next_evaluation_sequence=(current.head.evaluation_sequence + 1),
                    )
                )
                if expected_prepared != prepared:
                    raise TrustedTimePersistenceConflict(
                        "trusted-time host head changed after preparation"
                    )
                assert current is not None
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

                evaluation_id = str(uuid.uuid4())
                values = _evaluation_values(
                    evaluation_id=evaluation_id,
                    epoch=current.epoch,
                    evaluation_sequence=prepared.next_evaluation_sequence,
                    previous=current.terminal_evaluation,
                    result=result,
                )
                connection.execute(
                    sa.insert(phase6_trusted_time_probe_evaluations).values(**values)
                )
                terminal = _EvaluationRecord(
                    evaluation_id=evaluation_id,
                    evaluation_sequence=prepared.next_evaluation_sequence,
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
                readback = _verified_host(connection, binding.host_id, for_update=False)
                if (
                    readback is None
                    or readback.head != head
                    or readback.terminal_evaluation != terminal
                ):
                    raise TrustedTimePersistenceError(
                        "trusted-time probe append failed exact SQL readback"
                    )
                return PersistedTrustedTimeProbe(
                    result=result,
                    evaluation_sequence=terminal.evaluation_sequence,
                    record_sha256=terminal.semantic_sha256,
                    host_head_sha256=head.semantic_sha256,
                )
        except TrustedTimePersistenceError:
            raise
        except IntegrityError as error:
            raise TrustedTimePersistenceConflict("trusted-time probe append conflicts") from error
        except (SQLAlchemyError, TrustedTimeError) as error:
            raise TrustedTimePersistenceError("trusted-time probe append failed") from error

    def verify_integrity(self) -> None:
        """Authenticate all durable trusted-time histories."""

        verify_trusted_time_integrity(self._engine)


__all__ = [
    "TRUSTED_TIME_PERSISTENCE_CONTRACT_VERSION",
    "SqlTrustedTimeRepository",
    "TrustedTimePersistenceConflict",
    "TrustedTimePersistenceError",
    "verify_trusted_time_integrity",
]
