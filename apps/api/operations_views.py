"""Authenticated, loopback-only HTTP projections for local operations."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Protocol

from fastapi import APIRouter, Header, HTTPException, Path, Response, Security, status
from fastapi.security import APIKeyCookie
from sqlalchemy.exc import SQLAlchemyError

from apps.api.backtest_views import (
    CSRF_HEADER,
    IDEMPOTENCY_HEADER,
    LOCAL_SESSION_COOKIE,
    LocalOperatorSecurity,
)
from apps.api.contracts import (
    ActiveCriticalAlertView,
    AdvancedRiskAssessmentView,
    AdvancedRiskAssignmentMutationResponse,
    AdvancedRiskAssignmentView,
    ApiErrorResponse,
    EnvironmentMode,
    OperationalControlAction,
    OperationalControlCommandRequest,
    OperationalControlMutationResponse,
    OperationalControlOperationView,
    OperationalControlTransitionView,
    OperationsCoordinatorStatus,
    OperationsCoordinatorView,
    OperationsEnvironmentView,
    OperationsOverviewResponse,
    OperationsReadinessView,
    ReadinessStatus,
)
from packages.application.local_operations import (
    LocalCoordinatorStatus,
    LocalOperationsSnapshot,
    LocalOperationsSnapshotReader,
)
from packages.domain.account_coordinator import AccountCoordinatorError
from packages.domain.advanced_risk_assignment import (
    AdvancedRiskAssignmentConflict,
    AdvancedRiskAssignmentError,
    AdvancedRiskPolicyAssignment,
)
from packages.domain.advanced_risk_policy import AdvancedRiskDisposition
from packages.domain.operational_control import (
    OperationalControlAbsent,
    OperationalControlCommandKind,
    OperationalControlConflict,
    OperationalControlError,
    OperationalControlRearmRejected,
    OperationalControlState,
    OperationalControlTransition,
)
from packages.persistence.advanced_risk import (
    AdvancedRiskPersistenceConflict,
    AdvancedRiskPersistenceError,
)

logger = logging.getLogger(__name__)

_LOCAL_OPERATIONS_SESSION = APIKeyCookie(
    name=LOCAL_SESSION_COOKIE,
    scheme_name="LocalOperatorSession",
    description="URL-safe, server-issued local session value",
    auto_error=False,
)

_AccountId = Annotated[
    str,
    Path(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$",
    ),
]
_CsrfToken = Annotated[
    str,
    Header(
        alias=CSRF_HEADER,
        min_length=32,
        max_length=128,
        pattern=r"^[A-Za-z0-9_-]+$",
    ),
]
_IdempotencyKey = Annotated[
    str,
    Header(
        alias=IDEMPOTENCY_HEADER,
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$",
    ),
]


class LocalOperationsQuery(Protocol):
    """Allowlisted, authenticated read-model boundary."""

    def overview(
        self,
        account_id: str,
        *,
        as_of: datetime,
    ) -> OperationsOverviewResponse: ...


class OperationalControlCommandService(Protocol):
    def execute(
        self,
        *,
        account_id: str,
        operator_id: str,
        idempotency_key: str,
        kind: OperationalControlCommandKind,
        reason_code: str,
    ) -> OperationalControlTransition: ...


class AdvancedRiskAssignmentCommandService(Protocol):
    @property
    def approved_policy_id(self) -> str: ...

    def assign(
        self,
        *,
        account_id: str,
        operator_id: str,
        idempotency_key: str,
    ) -> AdvancedRiskPolicyAssignment: ...


class DurableLocalOperationsQuery:
    """Project one authenticated durable snapshot into the public allowlist."""

    __slots__ = ("_environment_mode", "_environment_name", "_loopback_only", "_reader")

    def __init__(
        self,
        *,
        reader: LocalOperationsSnapshotReader,
        environment_name: str,
        environment_mode: EnvironmentMode,
        loopback_only: bool,
    ) -> None:
        if not callable(getattr(reader, "read", None)):
            raise TypeError("durable local operations query requires a snapshot reader")
        if (
            type(environment_name) is not str
            or not environment_name
            or environment_name != environment_name.strip()
            or len(environment_name) > 64
        ):
            raise ValueError(
                "durable local operations environment name must be bounded trimmed text"
            )
        if type(environment_mode) is not EnvironmentMode:
            raise TypeError("durable local operations environment mode is unsupported")
        if type(loopback_only) is not bool:
            raise TypeError("durable local operations loopback flag must be exact")
        self._reader = reader
        self._environment_name = environment_name
        self._environment_mode = environment_mode
        self._loopback_only = loopback_only

    def overview(
        self,
        account_id: str,
        *,
        as_of: datetime,
    ) -> OperationsOverviewResponse:
        snapshot = self._reader.read(account_id, as_of=as_of)
        if (
            type(snapshot) is not LocalOperationsSnapshot
            or snapshot.account_id != account_id
            or snapshot.as_of != as_of
        ):
            raise TypeError("durable local operations reader returned a conflicting snapshot")
        control = snapshot.control
        reasons = self._readiness_reasons(snapshot)
        return OperationsOverviewResponse(
            as_of=snapshot.as_of,
            environment=OperationsEnvironmentView(
                name=self._environment_name,
                mode=self._environment_mode,
                account_id=account_id,
                loopback_only=self._loopback_only,
            ),
            readiness=OperationsReadinessView(
                status=(
                    ReadinessStatus.HALTED
                    if control is not None
                    and control.effective_state is OperationalControlState.HALTED
                    else ReadinessStatus.NOT_READY
                ),
                reasons=reasons,
                as_of=snapshot.as_of,
            ),
            coordinator=self._coordinator_view(snapshot),
            control=(None if control is None else operational_control_transition_view(control)),
            control_history=[
                operational_control_transition_view(item) for item in snapshot.control_history
            ],
            current_risk_assignment=(
                None
                if snapshot.current_risk_assignment is None
                else advanced_risk_assignment_view(snapshot.current_risk_assignment)
            ),
            current_risk_assessment=(
                None
                if snapshot.current_risk_assessment is None
                else AdvancedRiskAssessmentView(
                    assessment_id=snapshot.current_risk_assessment.assessment_id,
                    disposition=snapshot.current_risk_assessment.disposition,
                    assessed_at=snapshot.current_risk_assessment.assessed_at,
                    valid_through=snapshot.current_risk_assessment.valid_through,
                )
            ),
            active_alerts=[
                ActiveCriticalAlertView(
                    incident_id=item.incident.incident_id,
                    alert_code=item.incident.alert_code,
                    recorded_at=item.incident.recorded_at,
                    primary_delivery_state=item.primary_delivery_state,
                    escalation_delivery_state=item.escalation_delivery_state,
                    primary_deadline_at=item.incident.primary_deadline,
                    escalation_deadline_at=item.incident.escalation_deadline,
                )
                for item in snapshot.active_alerts
            ],
        )

    @property
    def runtime_store_identity(self) -> int | None:
        identity = getattr(self._reader, "runtime_store_identity", None)
        return identity if type(identity) is int else None

    @staticmethod
    def _coordinator_view(
        snapshot: LocalOperationsSnapshot,
    ) -> OperationsCoordinatorView:
        lease = snapshot.current_lease
        status_by_domain = {
            LocalCoordinatorStatus.ACTIVE: OperationsCoordinatorStatus.ACTIVE,
            LocalCoordinatorStatus.ABSENT: OperationsCoordinatorStatus.ABSENT,
            LocalCoordinatorStatus.EXPIRED: OperationsCoordinatorStatus.EXPIRED,
        }
        return OperationsCoordinatorView(
            status=status_by_domain[snapshot.coordinator_status],
            owner_id=None if lease is None else lease.owner_id,
            fencing_generation=(None if lease is None else lease.fencing_generation),
            lease_expires_at=None if lease is None else lease.expires_at,
        )

    @staticmethod
    def _readiness_reasons(snapshot: LocalOperationsSnapshot) -> list[str]:
        reasons = ["authoritative reconciliation readiness is unavailable"]
        if snapshot.coordinator_status is LocalCoordinatorStatus.ABSENT:
            reasons.append("account coordinator owner is absent")
        elif snapshot.coordinator_status is LocalCoordinatorStatus.EXPIRED:
            reasons.append("account coordinator lease is expired")
        control = snapshot.control
        if control is None:
            reasons.append("operational control is uninitialized")
        elif control.effective_state is not OperationalControlState.RUNNING:
            reasons.append(f"operational control state is {control.effective_state.value}")
        assignment = snapshot.current_risk_assignment
        if assignment is None:
            reasons.append("advanced-risk policy assignment is absent")
        assessment = snapshot.current_risk_assessment
        if assessment is None:
            reasons.append("advanced-risk assessment is absent")
        else:
            if assessment.valid_through <= snapshot.as_of:
                reasons.append("advanced-risk assessment is expired")
            if assessment.disposition is not AdvancedRiskDisposition.NONE:
                reasons.append(f"advanced-risk disposition is {assessment.disposition.value}")
        if snapshot.active_alerts:
            reasons.append("active critical alerts require attention")
        return reasons


def operational_control_transition_view(
    transition: OperationalControlTransition,
) -> OperationalControlTransitionView:
    """Project state and bounded counts, never command/evidence payloads."""

    if type(transition) is not OperationalControlTransition:
        raise TypeError("operations query returned an invalid control transition")
    operation = transition.active_operation
    return OperationalControlTransitionView(
        transition_id=transition.transition_id,
        sequence_number=transition.sequence_number,
        prior_state=transition.prior_state,
        effective_state=transition.effective_state,
        state_changed=transition.state_changed,
        state_epoch_id=transition.state_epoch_id,
        blocker_count=len(transition.blocking_events),
        blocker_overflowed=transition.blocker_overflowed,
        active_operation=(
            None
            if operation is None
            else OperationalControlOperationView(
                attempt_id=operation.attempt_id,
                operation=operation.operation,
                opened_at=operation.opened_at,
            )
        ),
        decided_at=transition.decided_at,
    )


def advanced_risk_assignment_view(
    assignment: AdvancedRiskPolicyAssignment,
) -> AdvancedRiskAssignmentView:
    if type(assignment) is not AdvancedRiskPolicyAssignment:
        raise TypeError("operations assignment returned an invalid receipt")
    return AdvancedRiskAssignmentView(
        assignment_id=assignment.assignment_id,
        sequence_number=assignment.sequence_number,
        policy_id=assignment.policy_id,
        policy_sha256=assignment.policy_sha256,
        environment=assignment.environment,
        assigned_at=assignment.assigned_at,
    )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _trusted_now(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="local operations trusted time is unavailable",
        )
    return value


def _require_ready(persistence_ready: Callable[[], bool]) -> None:
    try:
        ready = persistence_ready()
    except Exception as error:
        logger.exception("local operations persistence readiness check failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="durable local operations persistence is unavailable",
        ) from error
    if ready is not True:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="durable local operations persistence is unavailable",
        )


def _authenticate(
    *,
    security: LocalOperatorSecurity,
    session_cookie: str | None,
    csrf_token: str,
    now: datetime,
) -> str:
    return security.authenticate(session_cookie, csrf_token, now=now)


def create_operations_router(
    *,
    query: LocalOperationsQuery | None,
    control: OperationalControlCommandService | None,
    security: LocalOperatorSecurity,
    persistence_ready: Callable[[], bool],
    assignment: AdvancedRiskAssignmentCommandService | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> APIRouter:
    """Create local operations routes without acquiring broker authority."""

    router = APIRouter(prefix="/operations")

    @router.get(
        "/accounts/{account_id}",
        response_model=OperationsOverviewResponse,
        responses={
            status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse},
            status.HTTP_403_FORBIDDEN: {"model": ApiErrorResponse},
            status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ApiErrorResponse},
        },
        tags=["operations"],
    )
    def operations_overview(
        response: Response,
        account_id: _AccountId,
        session_cookie: Annotated[str | None, Security(_LOCAL_OPERATIONS_SESSION)],
        csrf_token: _CsrfToken,
    ) -> OperationsOverviewResponse:
        now = _trusted_now(clock)
        _authenticate(
            security=security,
            session_cookie=session_cookie,
            csrf_token=csrf_token,
            now=now,
        )
        _require_ready(persistence_ready)
        if query is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="local operations read models are unavailable",
            )
        try:
            result = query.overview(account_id, as_of=now)
            if type(result) is not OperationsOverviewResponse:
                raise TypeError("operations query returned an invalid response")
        except HTTPException:
            raise
        except Exception as error:
            logger.exception("local operations overview failed")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="local operations read models are unavailable or malformed",
            ) from error
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return result

    @router.post(
        "/accounts/{account_id}/control/{action}",
        response_model=OperationalControlMutationResponse,
        responses={
            status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse},
            status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse},
            status.HTTP_403_FORBIDDEN: {"model": ApiErrorResponse},
            status.HTTP_409_CONFLICT: {"model": ApiErrorResponse},
            status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ApiErrorResponse},
        },
        tags=["operations"],
    )
    def mutate_control(
        request: OperationalControlCommandRequest,
        response: Response,
        account_id: _AccountId,
        action: OperationalControlAction,
        session_cookie: Annotated[str | None, Security(_LOCAL_OPERATIONS_SESSION)],
        csrf_token: _CsrfToken,
        idempotency_key: _IdempotencyKey,
    ) -> OperationalControlMutationResponse:
        now = _trusted_now(clock)
        operator_id = _authenticate(
            security=security,
            session_cookie=session_cookie,
            csrf_token=csrf_token,
            now=now,
        )
        _require_ready(persistence_ready)
        if control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="durable operational controls are unavailable",
            )
        try:
            transition = control.execute(
                account_id=account_id,
                operator_id=operator_id,
                idempotency_key=idempotency_key,
                kind=action.command_kind,
                reason_code=request.reason_code,
            )
            result = OperationalControlMutationResponse(
                action=action,
                control=operational_control_transition_view(transition),
            )
        except OperationalControlConflict as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="idempotency or operational-control head conflicts",
            ) from error
        except (OperationalControlAbsent, OperationalControlRearmRejected) as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="operational command is not allowed by current durable prerequisites",
            ) from error
        except OperationalControlError as error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="operational command is invalid",
            ) from error
        except (SQLAlchemyError, RuntimeError, TypeError) as error:
            logger.exception("local operational command failed")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="durable operational controls are unavailable",
            ) from error
        response.headers["Cache-Control"] = "no-store"
        return result

    if assignment is not None:

        @router.post(
            "/accounts/{account_id}/advanced-risk-assignment",
            response_model=AdvancedRiskAssignmentMutationResponse,
            responses={
                status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse},
                status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse},
                status.HTTP_403_FORBIDDEN: {"model": ApiErrorResponse},
                status.HTTP_409_CONFLICT: {"model": ApiErrorResponse},
                status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ApiErrorResponse},
            },
            tags=["operations"],
        )
        def assign_advanced_risk(
            response: Response,
            account_id: _AccountId,
            session_cookie: Annotated[
                str | None,
                Security(_LOCAL_OPERATIONS_SESSION),
            ],
            csrf_token: _CsrfToken,
            idempotency_key: _IdempotencyKey,
        ) -> AdvancedRiskAssignmentMutationResponse:
            now = _trusted_now(clock)
            operator_id = _authenticate(
                security=security,
                session_cookie=session_cookie,
                csrf_token=csrf_token,
                now=now,
            )
            _require_ready(persistence_ready)
            try:
                assigned = assignment.assign(
                    account_id=account_id,
                    operator_id=operator_id,
                    idempotency_key=idempotency_key,
                )
                result = AdvancedRiskAssignmentMutationResponse(
                    assignment=advanced_risk_assignment_view(assigned),
                )
            except (
                OperationalControlConflict,
                AdvancedRiskAssignmentConflict,
                AdvancedRiskPersistenceConflict,
            ) as error:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="advanced-risk assignment idempotency or head conflicts",
                ) from error
            except (
                OperationalControlError,
                AccountCoordinatorError,
                AdvancedRiskAssignmentError,
            ) as error:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="advanced-risk assignment is invalid or lacks a current fence",
                ) from error
            except (
                SQLAlchemyError,
                AdvancedRiskPersistenceError,
                RuntimeError,
                TypeError,
            ) as error:
                logger.exception("advanced-risk assignment command failed")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="advanced-risk assignment persistence is unavailable",
                ) from error
            response.headers["Cache-Control"] = "no-store"
            return result

    return router


__all__ = [
    "AdvancedRiskAssignmentCommandService",
    "DurableLocalOperationsQuery",
    "LocalOperationsQuery",
    "OperationalControlCommandService",
    "advanced_risk_assignment_view",
    "create_operations_router",
    "operational_control_transition_view",
]
