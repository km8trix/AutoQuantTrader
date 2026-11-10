"""Stable-snapshot SQL reader for the allowlisted local operations view."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping

from packages.application.local_operations import (
    ActiveCriticalAlertSummary,
    LocalCoordinatorStatus,
    LocalOperationsSnapshot,
    LocalOperationsSnapshotError,
)
from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountLease,
)
from packages.domain.advanced_risk_admission import AdvancedRiskAssessmentReference
from packages.domain.advanced_risk_assignment import AdvancedRiskPolicyAssignment
from packages.domain.critical_alert import (
    CriticalAlertDeliveryAttempt,
    CriticalAlertDeliveryResult,
    CriticalAlertDeliveryState,
    CriticalAlertRoute,
    critical_alert_delivery_milestone_met,
)
from packages.domain.operational_control import OperationalControlTransition
from packages.persistence.account_coordinator import (
    account_lease_from_row,
    account_lease_release_from_row,
    verify_account_lease_history,
)
from packages.persistence.advanced_risk import (
    load_advanced_risk_assessment_reference_in_transaction,
    load_current_advanced_risk_assignment_in_transaction,
)
from packages.persistence.critical_alert import (
    CriticalAlertHistory,
    load_critical_alert_history_in_transaction,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import as_aware_utc
from packages.persistence.operational_control import (
    load_operational_control_head_in_transaction,
    load_operational_control_transition_in_transaction,
)
from packages.persistence.schema import (
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
    phase5_advanced_risk_assessments,
    phase5_advanced_risk_assignments,
    phase5_advanced_risk_evidence,
    phase5_advanced_risk_evidence_sources,
    phase5_critical_alert_delivery_attempts,
    phase5_critical_alert_delivery_results,
    phase5_critical_alert_incidents,
    phase5_operational_control_completions,
    phase5_operational_control_transitions,
)

_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})
_MAX_SOURCE_FACTS = 2_048
_MAX_CONTROL_HISTORY = 512
_MAX_ACTIVE_ALERTS = 512


@dataclass(frozen=True, slots=True)
class _CoordinatorHead:
    account_id: str
    last_fencing_generation: int
    current_fencing_generation: int | None
    current_lease_sha256: str | None
    updated_at: datetime


def _require_utc(value: datetime, field_name: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise LocalOperationsSnapshotError(f"{field_name} must be UTC")
    return value


def _require_account_id(account_id: str) -> None:
    if (
        type(account_id) is not str
        or not account_id
        or account_id != account_id.strip()
        or len(account_id) > 64
    ):
        raise LocalOperationsSnapshotError(
            "local operations account ID must be 1-64 characters of trimmed text"
        )


def _bounded_rows(
    connection: Connection,
    statement: sa.Select[tuple[Any, ...]],
    *,
    maximum: int,
    fact_name: str,
) -> tuple[RowMapping, ...]:
    rows = tuple(connection.execute(statement.limit(maximum + 1)).mappings())
    if len(rows) > maximum:
        raise LocalOperationsSnapshotError(
            f"{fact_name} exceeds the local operations verification bound"
        )
    return rows


def _coordinator_head_from_row(row: RowMapping) -> _CoordinatorHead:
    try:
        account_id = row["account_id"]
        last_generation = row["last_fencing_generation"]
        current_generation = row["current_fencing_generation"]
        current_digest = row["current_lease_sha256"]
        updated_at = row["updated_at"]
        if type(account_id) is not str or not account_id:
            raise TypeError("account_id")
        if type(last_generation) is not int or last_generation < 0:
            raise TypeError("last_fencing_generation")
        if current_generation is not None and (
            type(current_generation) is not int or current_generation <= 0
        ):
            raise TypeError("current_fencing_generation")
        if current_digest is not None and (
            type(current_digest) is not str
            or len(current_digest) != 64
            or any(character not in "0123456789abcdef" for character in current_digest)
        ):
            raise TypeError("current_lease_sha256")
        if (current_generation is None) != (current_digest is None):
            raise TypeError("current lease identity")
        if current_generation is not None and current_generation != last_generation:
            raise TypeError("current generation")
        if not isinstance(updated_at, datetime):
            raise TypeError("updated_at")
        return _CoordinatorHead(
            account_id=account_id,
            last_fencing_generation=last_generation,
            current_fencing_generation=current_generation,
            current_lease_sha256=current_digest,
            updated_at=as_aware_utc(updated_at),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise LocalOperationsSnapshotError("persisted coordinator head is malformed") from error


def _coordinator(
    connection: Connection,
    account_id: str,
    *,
    as_of: datetime,
) -> tuple[LocalCoordinatorStatus, AccountLease | None]:
    head_row = (
        connection.execute(
            sa.select(phase2_account_lease_heads).where(
                phase2_account_lease_heads.c.account_id == account_id
            )
        )
        .mappings()
        .one_or_none()
    )
    lease_rows = _bounded_rows(
        connection,
        sa.select(phase2_account_leases)
        .where(phase2_account_leases.c.account_id == account_id)
        .order_by(
            phase2_account_leases.c.fencing_generation,
            phase2_account_leases.c.revision_number,
        ),
        maximum=_MAX_SOURCE_FACTS,
        fact_name="account lease history",
    )
    release_rows = _bounded_rows(
        connection,
        sa.select(phase2_account_lease_releases)
        .where(phase2_account_lease_releases.c.account_id == account_id)
        .order_by(phase2_account_lease_releases.c.fencing_generation),
        maximum=_MAX_SOURCE_FACTS,
        fact_name="account lease release history",
    )
    if head_row is None:
        if lease_rows or release_rows:
            raise LocalOperationsSnapshotError(
                "account coordinator history exists without its head"
            )
        return LocalCoordinatorStatus.ABSENT, None
    head = _coordinator_head_from_row(head_row)
    if head.account_id != account_id:
        raise LocalOperationsSnapshotError("account coordinator head crosses account scope")
    leases = tuple(account_lease_from_row(row) for row in lease_rows)
    releases = tuple(account_lease_release_from_row(row) for row in release_rows)
    try:
        latest = verify_account_lease_history(
            account_id=account_id,
            head=cast(Any, head),
            leases=leases,
            releases=releases,
        )
    except AccountCoordinatorError as error:
        raise LocalOperationsSnapshotError(
            "account coordinator history failed authentication"
        ) from error
    if head.updated_at > as_of:
        raise LocalOperationsSnapshotError(
            "account coordinator current facts are later than the snapshot"
        )
    if head.current_lease_sha256 is None:
        return LocalCoordinatorStatus.ABSENT, None
    if latest is None or latest.semantic_sha256 != head.current_lease_sha256:
        raise LocalOperationsSnapshotError(
            "account coordinator current lease conflicts with its head"
        )
    if latest.acquired_at > as_of or latest.heartbeat_at > as_of:
        raise LocalOperationsSnapshotError(
            "account coordinator current facts are later than the snapshot"
        )
    return (
        LocalCoordinatorStatus.EXPIRED
        if as_of >= latest.expires_at
        else LocalCoordinatorStatus.ACTIVE,
        latest,
    )


def _control_history(
    connection: Connection,
    account_id: str,
    *,
    as_of: datetime,
) -> tuple[OperationalControlTransition, ...]:
    identity_rows = _bounded_rows(
        connection,
        sa.select(
            phase5_operational_control_transitions.c.transition_id,
            phase5_operational_control_transitions.c.sequence_number,
        )
        .where(phase5_operational_control_transitions.c.account_id == account_id)
        .order_by(phase5_operational_control_transitions.c.sequence_number),
        maximum=_MAX_SOURCE_FACTS,
        fact_name="operational control history",
    )
    _bounded_rows(
        connection,
        sa.select(phase5_operational_control_completions.c.completion_id).where(
            phase5_operational_control_completions.c.account_id == account_id
        ),
        maximum=_MAX_SOURCE_FACTS,
        fact_name="operational control completion history",
    )
    head = load_operational_control_head_in_transaction(connection, account_id)
    if not identity_rows:
        if head is not None:
            raise LocalOperationsSnapshotError("operational control head exists without history")
        return ()
    retained_rows = identity_rows[-_MAX_CONTROL_HISTORY:]
    transitions = []
    for row in retained_rows:
        transition_id = row["transition_id"]
        if type(transition_id) is not str:
            raise LocalOperationsSnapshotError(
                "operational control transition identity is malformed"
            )
        transition = load_operational_control_transition_in_transaction(
            connection,
            account_id,
            transition_id,
        )
        if transition is None:
            raise LocalOperationsSnapshotError(
                "operational control transition disappeared from stable snapshot"
            )
        transitions.append(transition)
    if head is None or transitions[-1] != head:
        raise LocalOperationsSnapshotError(
            "operational control retained history conflicts with its head"
        )
    if head.decided_at > as_of:
        raise LocalOperationsSnapshotError("operational control head is later than the snapshot")
    return tuple(transitions)


def _risk_facts(
    connection: Connection,
    account_id: str,
    *,
    as_of: datetime,
) -> tuple[
    AdvancedRiskPolicyAssignment | None,
    AdvancedRiskAssessmentReference | None,
]:
    for table, label in (
        (phase5_advanced_risk_assignments, "advanced-risk assignment history"),
        (phase5_advanced_risk_evidence, "advanced-risk evidence history"),
        (phase5_advanced_risk_assessments, "advanced-risk assessment history"),
    ):
        _bounded_rows(
            connection,
            sa.select(table.c.account_id).where(table.c.account_id == account_id),
            maximum=_MAX_SOURCE_FACTS,
            fact_name=label,
        )
    _bounded_rows(
        connection,
        sa.select(phase5_advanced_risk_evidence_sources.c.evidence_id).where(
            phase5_advanced_risk_evidence_sources.c.account_id == account_id
        ),
        maximum=_MAX_SOURCE_FACTS,
        fact_name="advanced-risk retained source history",
    )
    authenticated = load_current_advanced_risk_assignment_in_transaction(
        connection,
        account_id,
    )
    assignment = None if authenticated is None else authenticated.assignment
    if assignment is not None and assignment.assigned_at > as_of:
        raise LocalOperationsSnapshotError(
            "current advanced-risk assignment is later than the snapshot"
        )
    assessment_id = connection.scalar(
        sa.select(phase5_advanced_risk_assessments.c.assessment_id)
        .where(phase5_advanced_risk_assessments.c.account_id == account_id)
        .order_by(
            phase5_advanced_risk_assessments.c.sequence_number.desc(),
            phase5_advanced_risk_assessments.c.assessment_id.desc(),
        )
        .limit(1)
    )
    if assessment_id is None:
        return assignment, None
    if type(assessment_id) is not str:
        raise LocalOperationsSnapshotError("latest advanced-risk assessment identity is malformed")
    assessment = load_advanced_risk_assessment_reference_in_transaction(
        connection,
        assessment_id,
    )
    if assessment is None:
        raise LocalOperationsSnapshotError(
            "latest advanced-risk assessment disappeared from stable snapshot"
        )
    if assessment.assessed_at > as_of:
        raise LocalOperationsSnapshotError(
            "latest advanced-risk assessment is later than the snapshot"
        )
    return assignment, assessment


def _delivery_state(
    history: CriticalAlertHistory,
    route: CriticalAlertRoute,
) -> CriticalAlertDeliveryState:
    attempts = tuple(item for item in history.attempts if item.route is route)
    if not attempts:
        return CriticalAlertDeliveryState.UNKNOWN
    attempt: CriticalAlertDeliveryAttempt = attempts[-1]
    result: CriticalAlertDeliveryResult | None = next(
        (item for item in history.results if item.attempt_id == attempt.attempt_id),
        None,
    )
    if result is None:
        return CriticalAlertDeliveryState.UNKNOWN
    return CriticalAlertDeliveryState(result.outcome.value)


def _is_active(history: CriticalAlertHistory) -> bool:
    results = {item.attempt_id: item for item in history.results}
    return not any(
        critical_alert_delivery_milestone_met(
            incident=history.incident,
            attempt=attempt,
            result=result,
        )
        for attempt in history.attempts
        if (result := results.get(attempt.attempt_id)) is not None
    )


def _active_alerts(
    connection: Connection,
    account_id: str,
    *,
    as_of: datetime,
) -> tuple[ActiveCriticalAlertSummary, ...]:
    incident_rows = _bounded_rows(
        connection,
        sa.select(
            phase5_critical_alert_incidents.c.incident_id,
            phase5_critical_alert_incidents.c.recorded_at,
        )
        .where(phase5_critical_alert_incidents.c.scope_id == account_id)
        .order_by(
            phase5_critical_alert_incidents.c.recorded_at,
            phase5_critical_alert_incidents.c.incident_id,
        ),
        maximum=_MAX_SOURCE_FACTS,
        fact_name="critical-alert incident history",
    )
    for table, label in (
        (
            phase5_critical_alert_delivery_attempts,
            "critical-alert attempt history",
        ),
        (
            phase5_critical_alert_delivery_results,
            "critical-alert result history",
        ),
    ):
        _bounded_rows(
            connection,
            sa.select(table.c.incident_id)
            .join(
                phase5_critical_alert_incidents,
                phase5_critical_alert_incidents.c.incident_id == table.c.incident_id,
            )
            .where(phase5_critical_alert_incidents.c.scope_id == account_id),
            maximum=_MAX_SOURCE_FACTS,
            fact_name=label,
        )
    active: list[ActiveCriticalAlertSummary] = []
    for row in incident_rows:
        incident_id = row["incident_id"]
        if type(incident_id) is not str:
            raise LocalOperationsSnapshotError("critical-alert incident identity is malformed")
        history = load_critical_alert_history_in_transaction(
            connection,
            incident_id,
        )
        if history.incident.scope_id != account_id:
            raise LocalOperationsSnapshotError("critical-alert history crosses account scope")
        if (
            history.incident.recorded_at > as_of
            or any(
                attempt.claimed_at > as_of or attempt.requested_at > as_of
                for attempt in history.attempts
            )
            or any(result.completed_at > as_of for result in history.results)
        ):
            raise LocalOperationsSnapshotError(
                "critical-alert retained facts are later than the snapshot"
            )
        if not _is_active(history):
            continue
        active.append(
            ActiveCriticalAlertSummary(
                incident=history.incident,
                primary_delivery_state=_delivery_state(
                    history,
                    CriticalAlertRoute.PRIMARY,
                ),
                escalation_delivery_state=_delivery_state(
                    history,
                    CriticalAlertRoute.ESCALATION,
                ),
            )
        )
        if len(active) > _MAX_ACTIVE_ALERTS:
            raise LocalOperationsSnapshotError("active critical alerts exceed the response bound")
    return tuple(active)


class SqlLocalOperationsSnapshotReader:
    """Authenticate all view facts inside one repeatable-read transaction."""

    __slots__ = ("_engine",)

    def __init__(self, engine: Engine) -> None:
        if not isinstance(engine, Engine):
            raise LocalOperationsSnapshotError("SQL local operations reader requires an Engine")
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise LocalOperationsSnapshotError(
                f"SQL local operations reader does not support dialect {engine.dialect.name!r}"
            )
        self._engine = engine

    @property
    def runtime_store_identity(self) -> int:
        return id(self._engine)

    def read(
        self,
        account_id: str,
        *,
        as_of: datetime,
    ) -> LocalOperationsSnapshot:
        _require_account_id(account_id)
        observed_at = _require_utc(as_of, "local operations as_of")
        with _repeatable_read_transaction(self._engine) as connection:
            coordinator_status, current_lease = _coordinator(
                connection,
                account_id,
                as_of=observed_at,
            )
            controls = _control_history(
                connection,
                account_id,
                as_of=observed_at,
            )
            assignment, assessment = _risk_facts(
                connection,
                account_id,
                as_of=observed_at,
            )
            alerts = _active_alerts(
                connection,
                account_id,
                as_of=observed_at,
            )
            return LocalOperationsSnapshot(
                account_id=account_id,
                as_of=observed_at,
                coordinator_status=coordinator_status,
                current_lease=current_lease,
                control_history=controls,
                current_risk_assignment=assignment,
                current_risk_assessment=assessment,
                active_alerts=alerts,
            )


__all__ = ["SqlLocalOperationsSnapshotReader"]
