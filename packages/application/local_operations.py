"""Non-authorizing snapshots and bounded local operational commands."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from packages.application.operational_rearm import (
    AuthenticatedOperationalControlService,
    OperationalControlRepository,
    UtcClock,
)
from packages.domain.account_coordinator import AccountLease
from packages.domain.advanced_risk_admission import AdvancedRiskAssessmentReference
from packages.domain.advanced_risk_assignment import AdvancedRiskPolicyAssignment
from packages.domain.critical_alert import (
    CriticalAlertDeliveryState,
    CriticalAlertIncident,
)
from packages.domain.operational_control import (
    OperationalControlAbsent,
    OperationalControlCommandKind,
    OperationalControlError,
    OperationalControlTransition,
)


class LocalOperationsSnapshotError(RuntimeError):
    """A durable local-operations projection is malformed or exceeds its bounds."""


class LocalCoordinatorStatus(StrEnum):
    ACTIVE = "active"
    ABSENT = "absent"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class ActiveCriticalAlertSummary:
    """Allowlisted delivery state for one still-active critical incident."""

    incident: CriticalAlertIncident
    primary_delivery_state: CriticalAlertDeliveryState
    escalation_delivery_state: CriticalAlertDeliveryState

    def __post_init__(self) -> None:
        if type(self.incident) is not CriticalAlertIncident:
            raise LocalOperationsSnapshotError("active alert summary requires an exact incident")
        if type(self.primary_delivery_state) is not CriticalAlertDeliveryState:
            raise LocalOperationsSnapshotError("active alert primary delivery state is unsupported")
        if type(self.escalation_delivery_state) is not CriticalAlertDeliveryState:
            raise LocalOperationsSnapshotError(
                "active alert escalation delivery state is unsupported"
            )


@dataclass(frozen=True, slots=True)
class LocalOperationsSnapshot:
    """One stable, authenticated SQL snapshot with no mutation authority."""

    account_id: str
    as_of: datetime
    coordinator_status: LocalCoordinatorStatus
    current_lease: AccountLease | None
    control_history: tuple[OperationalControlTransition, ...]
    current_risk_assignment: AdvancedRiskPolicyAssignment | None
    current_risk_assessment: AdvancedRiskAssessmentReference | None
    active_alerts: tuple[ActiveCriticalAlertSummary, ...]

    def __post_init__(self) -> None:
        if (
            type(self.account_id) is not str
            or not self.account_id
            or self.account_id != self.account_id.strip()
        ):
            raise LocalOperationsSnapshotError(
                "local operations account ID must be non-empty trimmed text"
            )
        if (
            type(self.as_of) is not datetime
            or self.as_of.tzinfo is None
            or self.as_of.utcoffset() is None
            or self.as_of.utcoffset() != UTC.utcoffset(self.as_of)
        ):
            raise LocalOperationsSnapshotError("local operations snapshot time must be UTC")
        if type(self.coordinator_status) is not LocalCoordinatorStatus:
            raise LocalOperationsSnapshotError("local operations coordinator status is unsupported")
        if self.current_lease is not None and (
            type(self.current_lease) is not AccountLease
            or self.current_lease.account_id != self.account_id
        ):
            raise LocalOperationsSnapshotError(
                "local operations current lease crosses account scope"
            )
        if (self.coordinator_status is LocalCoordinatorStatus.ABSENT) != (
            self.current_lease is None
        ):
            raise LocalOperationsSnapshotError(
                "local operations coordinator status conflicts with its lease"
            )
        if type(self.control_history) is not tuple or len(self.control_history) > 512:
            raise LocalOperationsSnapshotError(
                "local operations control history exceeds its response bound"
            )
        if any(
            type(item) is not OperationalControlTransition or item.scope_id != self.account_id
            for item in self.control_history
        ):
            raise LocalOperationsSnapshotError(
                "local operations control history crosses account scope"
            )
        if self.control_history and tuple(
            item.sequence_number for item in self.control_history
        ) != tuple(
            range(
                self.control_history[0].sequence_number,
                self.control_history[-1].sequence_number + 1,
            )
        ):
            raise LocalOperationsSnapshotError(
                "local operations retained control history is not contiguous"
            )
        if self.current_risk_assignment is not None and (
            type(self.current_risk_assignment) is not AdvancedRiskPolicyAssignment
            or self.current_risk_assignment.account_id != self.account_id
        ):
            raise LocalOperationsSnapshotError(
                "local operations risk assignment crosses account scope"
            )
        if self.current_risk_assessment is not None and (
            type(self.current_risk_assessment) is not AdvancedRiskAssessmentReference
            or self.current_risk_assessment.account_id != self.account_id
        ):
            raise LocalOperationsSnapshotError(
                "local operations risk assessment crosses account scope"
            )
        if type(self.active_alerts) is not tuple or len(self.active_alerts) > 512:
            raise LocalOperationsSnapshotError(
                "local operations active alerts exceed their response bound"
            )
        if any(
            type(item) is not ActiveCriticalAlertSummary
            or item.incident.scope_id != self.account_id
            for item in self.active_alerts
        ):
            raise LocalOperationsSnapshotError("local operations active alerts cross account scope")

    @property
    def control(self) -> OperationalControlTransition | None:
        return None if not self.control_history else self.control_history[-1]


class LocalOperationsSnapshotReader(Protocol):
    def read(
        self,
        account_id: str,
        *,
        as_of: datetime,
    ) -> LocalOperationsSnapshot: ...


class DatabaseOnlyOperationalControlService:
    """Expose only durable PAUSE and HALT; no executor or re-arm proof is implied."""

    __slots__ = ("_delegate", "_repository", "_runtime_store_identity")

    available_actions = frozenset(
        {
            OperationalControlCommandKind.PAUSE,
            OperationalControlCommandKind.HALT,
        }
    )

    def __init__(
        self,
        *,
        repository: OperationalControlRepository,
        actor_authority_sha256: str,
        clock: UtcClock,
    ) -> None:
        self._delegate = AuthenticatedOperationalControlService(
            repository=repository,
            actor_authority_sha256=actor_authority_sha256,
            rearm_verifier=None,
            clock=clock,
        )
        self._repository = repository
        identity = getattr(repository, "runtime_store_identity", None)
        self._runtime_store_identity = identity if type(identity) is int else None

    @property
    def runtime_store_identity(self) -> int | None:
        return self._runtime_store_identity

    def execute(
        self,
        *,
        account_id: str,
        operator_id: str,
        idempotency_key: str,
        kind: OperationalControlCommandKind,
        reason_code: str,
    ) -> OperationalControlTransition:
        if type(kind) is not OperationalControlCommandKind:
            raise OperationalControlError("database-only local control command kind is unsupported")
        if kind not in self.available_actions:
            raise OperationalControlError("database-only local controls expose only PAUSE and HALT")
        if self._repository.load(account_id) is None:
            raise OperationalControlAbsent(
                "database-only local controls do not initialize account control"
            )
        return self._delegate.execute(
            account_id=account_id,
            operator_id=operator_id,
            idempotency_key=idempotency_key,
            kind=kind,
            reason_code=reason_code,
        )


__all__ = [
    "ActiveCriticalAlertSummary",
    "DatabaseOnlyOperationalControlService",
    "LocalCoordinatorStatus",
    "LocalOperationsSnapshot",
    "LocalOperationsSnapshotError",
    "LocalOperationsSnapshotReader",
]
