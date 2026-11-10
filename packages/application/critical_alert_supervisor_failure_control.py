"""Pure supervisor-evidence binding from total alert failure to PAUSED.

This module is deliberately local and unwired. It owns no worker, route
defaults, persistence, fence, broker, rearm, or resume authority.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from packages.application.critical_alert_supervisor import (
    CRITICAL_ALERT_SUPERVISOR_CONTRACT_VERSION,
    CriticalAlertRoutePlan,
    CriticalAlertSupervisorDisposition,
    CriticalAlertSupervisorEvidence,
    CriticalAlertSupervisorReason,
    validate_critical_alert_route_plan_history,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.critical_alert import (
    CriticalAlertDeliveryAttempt,
    CriticalAlertDeliveryResult,
    CriticalAlertError,
    CriticalAlertIncident,
    CriticalAlertRoute,
    critical_alert_delivery_milestone_met,
    validate_critical_alert_delivery_history,
)
from packages.domain.identifiers import canonical_id
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlError,
    OperationalControlState,
    OperationalControlTransition,
    apply_operational_control_command,
)

CRITICAL_ALERT_FAILURE_CONTROL_CONTRACT_VERSION = "phase5d-critical-alert-failure-control-v1"
CRITICAL_ALERT_FAILURE_CONTROL_POLICY_ID = "phase5d-total-delivery-failure-pauses-v1"
CRITICAL_ALERT_FAILURE_CONTROL_SYSTEM_ACTOR_ID = "phase5d-critical-alert-failure-control"
CRITICAL_ALERT_FAILURE_CONTROL_RULE_ID = "critical_alert_total_delivery_failure"
CRITICAL_ALERT_FAILURE_CONTROL_REASON_CODE = "critical_alert_total_delivery_failure"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

CRITICAL_ALERT_FAILURE_CONTROL_POLICY_SHA256 = hashlib.sha256(
    canonical_json_bytes(
        (
            CRITICAL_ALERT_FAILURE_CONTROL_CONTRACT_VERSION,
            "failure_control_policy",
            CRITICAL_ALERT_FAILURE_CONTROL_POLICY_ID,
            CRITICAL_ALERT_SUPERVISOR_CONTRACT_VERSION,
            CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE,
            CriticalAlertRoute.ESCALATION,
            CriticalAlertSupervisorReason.ESCALATION_DEADLINE_UNRESOLVED,
            CriticalAlertSupervisorReason.ESCALATION_ATTEMPT_FAILED,
            OperationalControlCommandKind.TRIP,
            OperationalControlState.PAUSED,
            OperationalControlActorKind.SYSTEM,
            CRITICAL_ALERT_FAILURE_CONTROL_SYSTEM_ACTOR_ID,
            CRITICAL_ALERT_FAILURE_CONTROL_RULE_ID,
            "exact_incident_route_plan_attempt_and_result_history",
            "no_in_budget_confirmed_delivery_result",
            "terminal_failure_on_first_replay_at_or_after_latest_history",
            "unresolved_claim_at_or_after_escalation_deadline",
            "severity_join_preserves_stronger_control_states",
            "actor_authority_is_authenticated_and_injected",
            "no_fence_broker_rearm_or_automatic_resume_authority",
        )
    )
).hexdigest()


class CriticalAlertFailureControlError(CriticalAlertError):
    """Total-delivery-failure evidence cannot safely control the account."""


class CriticalAlertFailureControlConflict(CriticalAlertFailureControlError):
    """Immutable alert, history, command, or control identities conflict."""


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise CriticalAlertFailureControlError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> None:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise CriticalAlertFailureControlError(f"{field_name} must be UTC")


def _canonical_results(
    attempts: tuple[CriticalAlertDeliveryAttempt, ...],
    results: tuple[CriticalAlertDeliveryResult, ...],
) -> tuple[CriticalAlertDeliveryResult, ...]:
    by_attempt = {result.attempt_id: result for result in results}
    return tuple(
        by_attempt[attempt.attempt_id] for attempt in attempts if attempt.attempt_id in by_attempt
    )


def authenticate_total_delivery_failure_evidence(
    *,
    incident: CriticalAlertIncident,
    route_plan: CriticalAlertRoutePlan,
    attempts: tuple[CriticalAlertDeliveryAttempt, ...],
    results: tuple[CriticalAlertDeliveryResult, ...],
    evidence: CriticalAlertSupervisorEvidence,
) -> CriticalAlertSupervisorEvidence:
    """Reauthenticate one total-failure result against its complete history."""

    if type(incident) is not CriticalAlertIncident:
        raise CriticalAlertFailureControlError(
            "critical-alert failure control requires an exact incident"
        )
    if type(route_plan) is not CriticalAlertRoutePlan:
        raise CriticalAlertFailureControlError(
            "critical-alert failure control requires an exact route plan"
        )
    if type(attempts) is not tuple or type(results) is not tuple:
        raise CriticalAlertFailureControlError(
            "critical-alert failure-control history must use exact tuples"
        )
    if type(evidence) is not CriticalAlertSupervisorEvidence:
        raise CriticalAlertFailureControlError(
            "critical-alert failure control requires exact supervisor evidence"
        )
    try:
        incident.__post_init__()
        route_plan.__post_init__()
        evidence.__post_init__()
        validate_critical_alert_delivery_history(
            incident=incident,
            attempts=attempts,
            results=results,
        )
        validate_critical_alert_route_plan_history(
            incident=incident,
            route_plan=route_plan,
            attempts=attempts,
        )
    except (CriticalAlertError, ValueError, TypeError) as error:
        raise CriticalAlertFailureControlConflict(
            "critical-alert failure-control source history is not authentic"
        ) from error

    if results != _canonical_results(attempts, results):
        raise CriticalAlertFailureControlConflict(
            "critical-alert failure-control results do not follow attempt history"
        )
    if (
        evidence.incident_id != incident.incident_id
        or evidence.incident_sha256 != incident.semantic_sha256
    ):
        raise CriticalAlertFailureControlConflict(
            "critical-alert failure-control evidence crosses incident identity"
        )
    if evidence.route_plan_sha256 != route_plan.semantic_sha256:
        raise CriticalAlertFailureControlConflict(
            "critical-alert failure-control evidence crosses route-plan identity"
        )
    if evidence.disposition is not CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE:
        raise CriticalAlertFailureControlConflict(
            "only total delivery failure may request alert failure control"
        )
    if evidence.selected_route is not CriticalAlertRoute.ESCALATION:
        raise CriticalAlertFailureControlConflict(
            "total delivery failure must select the escalation route"
        )
    if evidence.provider_called:
        raise CriticalAlertFailureControlConflict(
            "failure control accepts only replay-derived supervisor evidence"
        )
    latest_history_time = max(
        (
            incident.recorded_at,
            *(attempt.claimed_at for attempt in attempts),
            *(result.completed_at for result in results),
        )
    )
    if evidence.observed_at < latest_history_time:
        raise CriticalAlertFailureControlConflict(
            "total-delivery-failure observation predates durable history"
        )
    attempts_by_id = {attempt.attempt_id: attempt for attempt in attempts}
    if any(
        critical_alert_delivery_milestone_met(
            incident=incident,
            attempt=attempts_by_id[result.attempt_id],
            result=result,
        )
        for result in results
    ):
        raise CriticalAlertFailureControlConflict(
            "a confirmed delivery result cannot authorize failure control"
        )

    escalation_attempt = next(
        (attempt for attempt in attempts if attempt.route is CriticalAlertRoute.ESCALATION),
        None,
    )
    if escalation_attempt is None:
        raise CriticalAlertFailureControlConflict(
            "total delivery failure lacks an escalation attempt"
        )
    if (
        evidence.attempt_id != escalation_attempt.attempt_id
        or evidence.attempt_sha256 != escalation_attempt.semantic_sha256
    ):
        raise CriticalAlertFailureControlConflict(
            "total-delivery-failure evidence does not bind the escalation attempt"
        )
    escalation_result = next(
        (result for result in results if result.attempt_id == escalation_attempt.attempt_id),
        None,
    )
    if evidence.reason is CriticalAlertSupervisorReason.ESCALATION_DEADLINE_UNRESOLVED:
        if evidence.observed_at < incident.escalation_deadline:
            raise CriticalAlertFailureControlConflict(
                "unresolved total delivery failure predates the escalation deadline"
            )
        if (
            escalation_result is not None
            or evidence.result_id is not None
            or evidence.result_sha256 is not None
            or not evidence.unresolved_claim
        ):
            raise CriticalAlertFailureControlConflict(
                "unresolved escalation evidence conflicts with terminal history"
            )
    elif evidence.reason is CriticalAlertSupervisorReason.ESCALATION_ATTEMPT_FAILED:
        if (
            escalation_result is None
            or evidence.result_id != escalation_result.result_id
            or evidence.result_sha256 != escalation_result.semantic_sha256
            or evidence.unresolved_claim
        ):
            raise CriticalAlertFailureControlConflict(
                "terminal escalation failure does not bind its exact result"
            )
    else:
        raise CriticalAlertFailureControlConflict(
            "total delivery failure uses an unsupported reason"
        )
    return evidence


def _critical_alert_total_delivery_failure_trip_command(
    incident: CriticalAlertIncident,
    evidence: CriticalAlertSupervisorEvidence,
    *,
    actor_authority_sha256: str,
) -> OperationalControlCommand:
    """Return the exact source-idempotent SYSTEM trip to at least PAUSED."""

    if type(incident) is not CriticalAlertIncident:
        raise CriticalAlertFailureControlError(
            "critical-alert failure trip requires an exact incident"
        )
    if type(evidence) is not CriticalAlertSupervisorEvidence:
        raise CriticalAlertFailureControlError(
            "critical-alert failure trip requires exact supervisor evidence"
        )
    try:
        incident.__post_init__()
        evidence.__post_init__()
    except (CriticalAlertError, ValueError, TypeError) as error:
        raise CriticalAlertFailureControlConflict(
            "critical-alert failure trip source is not authentic"
        ) from error
    _require_sha256(
        actor_authority_sha256,
        "critical-alert failure-control actor authority_sha256",
    )
    if (
        evidence.incident_id != incident.incident_id
        or evidence.incident_sha256 != incident.semantic_sha256
        or evidence.disposition is not CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE
        or evidence.selected_route is not CriticalAlertRoute.ESCALATION
        or evidence.provider_called
        or (
            evidence.reason is CriticalAlertSupervisorReason.ESCALATION_DEADLINE_UNRESOLVED
            and evidence.observed_at < incident.escalation_deadline
        )
        or (
            evidence.reason is CriticalAlertSupervisorReason.ESCALATION_ATTEMPT_FAILED
            and evidence.observed_at < incident.primary_deadline
        )
        or evidence.reason
        not in {
            CriticalAlertSupervisorReason.ESCALATION_DEADLINE_UNRESOLVED,
            CriticalAlertSupervisorReason.ESCALATION_ATTEMPT_FAILED,
        }
    ):
        raise CriticalAlertFailureControlConflict(
            "critical-alert failure trip does not bind an eligible incident"
        )
    return OperationalControlCommand(
        scope_id=incident.scope_id,
        idempotency_key=f"critical-alert-failure:{incident.incident_id}",
        kind=OperationalControlCommandKind.TRIP,
        target_state=OperationalControlState.PAUSED,
        actor=OperationalControlActor(
            actor_id=CRITICAL_ALERT_FAILURE_CONTROL_SYSTEM_ACTOR_ID,
            kind=OperationalControlActorKind.SYSTEM,
            authority_sha256=actor_authority_sha256,
            authenticated_at=None,
        ),
        reason_code=CRITICAL_ALERT_FAILURE_CONTROL_REASON_CODE,
        reason_evidence_sha256=evidence.semantic_sha256,
        requested_at=evidence.observed_at,
        trip_rule_id=CRITICAL_ALERT_FAILURE_CONTROL_RULE_ID,
        trip_policy_sha256=CRITICAL_ALERT_FAILURE_CONTROL_POLICY_SHA256,
        trip_observation_sha256=evidence.semantic_sha256,
    )


@dataclass(frozen=True, slots=True)
class CriticalAlertFailureControlReceipt:
    """Immutable proof of one authenticated failure-control severity join."""

    incident: CriticalAlertIncident
    route_plan: CriticalAlertRoutePlan
    evidence: CriticalAlertSupervisorEvidence
    pre_control: OperationalControlTransition
    command: OperationalControlCommand
    final_control: OperationalControlTransition
    bound_at: datetime

    def __post_init__(self) -> None:
        for value, expected, label in (
            (self.incident, CriticalAlertIncident, "incident"),
            (self.route_plan, CriticalAlertRoutePlan, "route plan"),
            (
                self.evidence,
                CriticalAlertSupervisorEvidence,
                "supervisor evidence",
            ),
            (
                self.pre_control,
                OperationalControlTransition,
                "pre-control transition",
            ),
            (self.command, OperationalControlCommand, "command"),
            (
                self.final_control,
                OperationalControlTransition,
                "final-control transition",
            ),
        ):
            if type(value) is not expected:
                raise CriticalAlertFailureControlError(
                    f"failure-control receipt {label} must be exact"
                )
        _require_utc(self.bound_at, "failure-control receipt bound_at")
        try:
            self.incident.__post_init__()
            self.route_plan.__post_init__()
            self.evidence.__post_init__()
            self.pre_control.__post_init__()
            self.command.__post_init__()
            self.final_control.__post_init__()
        except (
            CriticalAlertError,
            OperationalControlError,
            ValueError,
            TypeError,
        ) as error:
            raise CriticalAlertFailureControlConflict(
                "failure-control receipt contains an inauthentic source"
            ) from error
        if (
            self.evidence.incident_id != self.incident.incident_id
            or self.evidence.incident_sha256 != self.incident.semantic_sha256
            or self.evidence.route_plan_sha256 != self.route_plan.semantic_sha256
        ):
            raise CriticalAlertFailureControlConflict(
                "failure-control receipt crosses alert source identities"
            )
        expected_command = _critical_alert_total_delivery_failure_trip_command(
            self.incident,
            self.evidence,
            actor_authority_sha256=self.command.actor.authority_sha256,
        )
        if self.command != expected_command:
            raise CriticalAlertFailureControlConflict(
                "failure-control receipt command is not the exact policy command"
            )
        if self.pre_control.scope_id != self.incident.scope_id:
            raise CriticalAlertFailureControlConflict(
                "failure-control receipt pre-control scope crosses the incident"
            )
        if self.pre_control.command_id == self.command.command_id:
            raise CriticalAlertFailureControlConflict(
                "failure-control receipt pre-control already contains its source command"
            )
        if self.bound_at < max(self.evidence.observed_at, self.pre_control.decided_at):
            raise CriticalAlertFailureControlConflict(
                "failure-control binding predates its authenticated sources"
            )
        try:
            expected_final = apply_operational_control_command(
                self.pre_control,
                self.command,
                decided_at=self.bound_at,
            )
        except OperationalControlError as error:
            raise CriticalAlertFailureControlConflict(
                "failure-control receipt cannot apply its exact control command"
            ) from error
        if self.final_control != expected_final:
            raise CriticalAlertFailureControlConflict(
                "failure-control receipt final transition conflicts with the severity join"
            )

    @property
    def receipt_id(self) -> str:
        return canonical_id(
            "critical-alert-failure-control-receipt",
            self.incident.incident_id,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        self.__post_init__()
        return (
            CRITICAL_ALERT_FAILURE_CONTROL_CONTRACT_VERSION,
            "failure_control_receipt",
            self.receipt_id,
            CRITICAL_ALERT_FAILURE_CONTROL_POLICY_ID,
            CRITICAL_ALERT_FAILURE_CONTROL_POLICY_SHA256,
            self.incident.incident_id,
            self.incident.semantic_sha256,
            self.route_plan.plan_id,
            self.route_plan.plan_version,
            self.route_plan.semantic_sha256,
            self.evidence.semantic_sha256,
            self.pre_control.transition_id,
            self.pre_control.semantic_sha256,
            self.command.command_id,
            self.command.semantic_sha256,
            self.final_control.transition_id,
            self.final_control.semantic_sha256,
            self.bound_at,
            self.requested_control_state,
            self.broker_action_authorized,
            self.fence_authority_granted,
            self.automatic_rearm_authorized,
            self.automatic_resume_authorized,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json.encode()).hexdigest()

    @property
    def requested_control_state(self) -> OperationalControlState:
        return OperationalControlState.PAUSED

    @property
    def broker_action_authorized(self) -> bool:
        return False

    @property
    def fence_authority_granted(self) -> bool:
        return False

    @property
    def automatic_rearm_authorized(self) -> bool:
        return False

    @property
    def automatic_resume_authorized(self) -> bool:
        return False


def bind_critical_alert_failure_control_receipt(
    *,
    incident: CriticalAlertIncident,
    route_plan: CriticalAlertRoutePlan,
    attempts: tuple[CriticalAlertDeliveryAttempt, ...],
    results: tuple[CriticalAlertDeliveryResult, ...],
    evidence: CriticalAlertSupervisorEvidence,
    pre_control: OperationalControlTransition,
    actor_authority_sha256: str,
    bound_at: datetime,
) -> CriticalAlertFailureControlReceipt:
    """Authenticate and reduce one failure to an immutable receipt without I/O."""

    authenticated = authenticate_total_delivery_failure_evidence(
        incident=incident,
        route_plan=route_plan,
        attempts=attempts,
        results=results,
        evidence=evidence,
    )
    if type(pre_control) is not OperationalControlTransition:
        raise CriticalAlertFailureControlError(
            "failure-control binding requires an exact pre-control transition"
        )
    _require_utc(bound_at, "failure-control bound_at")
    command = _critical_alert_total_delivery_failure_trip_command(
        incident,
        authenticated,
        actor_authority_sha256=actor_authority_sha256,
    )
    if pre_control.command_id == command.command_id:
        raise CriticalAlertFailureControlConflict(
            "failure-control source command is already present in the pre-control head"
        )
    try:
        final_control = apply_operational_control_command(
            pre_control,
            command,
            decided_at=bound_at,
        )
    except OperationalControlError as error:
        raise CriticalAlertFailureControlConflict(
            "failure-control trip cannot apply to the exact pre-control head"
        ) from error
    return CriticalAlertFailureControlReceipt(
        incident=incident,
        route_plan=route_plan,
        evidence=authenticated,
        pre_control=pre_control,
        command=command,
        final_control=final_control,
        bound_at=bound_at,
    )


__all__ = [
    "CRITICAL_ALERT_FAILURE_CONTROL_CONTRACT_VERSION",
    "CRITICAL_ALERT_FAILURE_CONTROL_POLICY_ID",
    "CRITICAL_ALERT_FAILURE_CONTROL_POLICY_SHA256",
    "CRITICAL_ALERT_FAILURE_CONTROL_REASON_CODE",
    "CRITICAL_ALERT_FAILURE_CONTROL_RULE_ID",
    "CRITICAL_ALERT_FAILURE_CONTROL_SYSTEM_ACTOR_ID",
    "CriticalAlertFailureControlConflict",
    "CriticalAlertFailureControlError",
    "CriticalAlertFailureControlReceipt",
    "authenticate_total_delivery_failure_evidence",
    "bind_critical_alert_failure_control_receipt",
]
