from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from packages.application.critical_alert_delivery import CriticalAlertProviderRequest
from packages.application.critical_alert_supervisor import (
    CriticalAlertRouteBinding,
    CriticalAlertRoutePlan,
    CriticalAlertSupervisorDisposition,
    CriticalAlertSupervisorEvidence,
    CriticalAlertSupervisorReason,
    critical_alert_route_idempotency_key,
)
from packages.application.critical_alert_supervisor_failure_control import (
    CRITICAL_ALERT_FAILURE_CONTROL_SYSTEM_ACTOR_ID,
    CriticalAlertFailureControlConflict,
    authenticate_total_delivery_failure_evidence,
    bind_critical_alert_failure_control_receipt,
)
from packages.domain.critical_alert import (
    CriticalAlertDeliveryAttempt,
    CriticalAlertDeliveryCommand,
    CriticalAlertDeliveryOutcome,
    CriticalAlertDeliveryResult,
    CriticalAlertIncident,
    CriticalAlertRoute,
    append_critical_alert_delivery_attempt,
    record_critical_alert_delivery_result,
)
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlState,
    OperationalControlTransition,
    apply_operational_control_command,
)

BASE = datetime(2026, 7, 28, 14, 0, tzinfo=UTC)
AUTHORITY_SHA256 = "9" * 64


def _incident() -> CriticalAlertIncident:
    return CriticalAlertIncident(
        scope_id="paper-account-1",
        source_id="strategy-supervisor",
        idempotency_key="incident-0001",
        alert_code="strategy_deadline_exceeded",
        evidence_sha256="a" * 64,
        detected_at=BASE - timedelta(milliseconds=100),
        recorded_at=BASE,
        correlation_sha256="b" * 64,
    )


def _plan(version: str = "1") -> CriticalAlertRoutePlan:
    return CriticalAlertRoutePlan(
        plan_id="paper-critical-alerts",
        plan_version=version,
        primary=CriticalAlertRouteBinding(
            route=CriticalAlertRoute.PRIMARY,
            provider_id="primary-pager",
            destination_sha256="c" * 64,
            recipient_set_sha256="d" * 64,
        ),
        escalation=CriticalAlertRouteBinding(
            route=CriticalAlertRoute.ESCALATION,
            provider_id="fallback-sms",
            destination_sha256="e" * 64,
            recipient_set_sha256="f" * 64,
        ),
    )


def _attempt(
    incident: CriticalAlertIncident,
    plan: CriticalAlertRoutePlan,
    route: CriticalAlertRoute,
    requested_at: datetime,
    previous: CriticalAlertDeliveryAttempt | None,
) -> CriticalAlertDeliveryAttempt:
    request = CriticalAlertProviderRequest.bind(
        incident=incident,
        route=route,
        provider_id=plan.binding_for(route).provider_id,
        idempotency_key=critical_alert_route_idempotency_key(
            incident=incident,
            route_plan=plan,
            route=route,
        ),
    )
    return append_critical_alert_delivery_attempt(
        incident=incident,
        command=CriticalAlertDeliveryCommand(
            incident_id=incident.incident_id,
            incident_sha256=incident.semantic_sha256,
            route=route,
            provider_id=request.provider_id,
            idempotency_key=request.idempotency_key,
            request_sha256=request.semantic_sha256,
            requested_at=requested_at,
        ),
        claimed_at=requested_at,
        previous=previous,
    )


def _result(
    incident: CriticalAlertIncident,
    attempt: CriticalAlertDeliveryAttempt,
    outcome: CriticalAlertDeliveryOutcome,
    completed_at: datetime,
) -> CriticalAlertDeliveryResult:
    return record_critical_alert_delivery_result(
        incident=incident,
        attempt=attempt,
        outcome=outcome,
        completed_at=completed_at,
        elapsed_microseconds=1_000_000,
        provider_receipt_sha256=(
            "0" * 64 if outcome is CriticalAlertDeliveryOutcome.CONFIRMED else None
        ),
        failure_code=(None if outcome is CriticalAlertDeliveryOutcome.CONFIRMED else "failure"),
    )


def _history(
    terminal: CriticalAlertDeliveryOutcome | None = None,
    *,
    completed_at: datetime | None = None,
) -> tuple[
    CriticalAlertIncident,
    CriticalAlertRoutePlan,
    tuple[CriticalAlertDeliveryAttempt, ...],
    tuple[CriticalAlertDeliveryResult, ...],
    CriticalAlertSupervisorEvidence,
]:
    incident = _incident()
    plan = _plan()
    primary = _attempt(
        incident,
        plan,
        CriticalAlertRoute.PRIMARY,
        BASE + timedelta(seconds=1),
        None,
    )
    primary_result = _result(
        incident,
        primary,
        CriticalAlertDeliveryOutcome.ERROR,
        BASE + timedelta(seconds=2),
    )
    escalation = _attempt(
        incident,
        plan,
        CriticalAlertRoute.ESCALATION,
        incident.primary_deadline,
        primary,
    )
    terminal_result = (
        None
        if terminal is None
        else _result(
            incident,
            escalation,
            terminal,
            completed_at or incident.primary_deadline + timedelta(seconds=1),
        )
    )
    results = (primary_result,) if terminal_result is None else (primary_result, terminal_result)
    evidence = CriticalAlertSupervisorEvidence(
        incident_id=incident.incident_id,
        incident_sha256=incident.semantic_sha256,
        route_plan_sha256=plan.semantic_sha256,
        disposition=CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE,
        reason=(
            CriticalAlertSupervisorReason.ESCALATION_DEADLINE_UNRESOLVED
            if terminal_result is None
            else CriticalAlertSupervisorReason.ESCALATION_ATTEMPT_FAILED
        ),
        observed_at=incident.escalation_deadline,
        selected_route=CriticalAlertRoute.ESCALATION,
        attempt_id=escalation.attempt_id,
        attempt_sha256=escalation.semantic_sha256,
        result_id=None if terminal_result is None else terminal_result.result_id,
        result_sha256=(None if terminal_result is None else terminal_result.semantic_sha256),
        wait_until=None,
        provider_called=False,
        unresolved_claim=terminal_result is None,
    )
    return incident, plan, (primary, escalation), results, evidence


def _halted(scope_id: str) -> OperationalControlTransition:
    instant = BASE - timedelta(minutes=1)
    command = OperationalControlCommand(
        scope_id=scope_id,
        idempotency_key="initialize-halted",
        kind=OperationalControlCommandKind.INITIALIZE_HALTED,
        target_state=OperationalControlState.HALTED,
        actor=OperationalControlActor(
            actor_id="bootstrap",
            kind=OperationalControlActorKind.SYSTEM,
            authority_sha256="1" * 64,
            authenticated_at=None,
        ),
        reason_code="bootstrap",
        reason_evidence_sha256="2" * 64,
        requested_at=instant,
    )
    return apply_operational_control_command(None, command, decided_at=instant)


@pytest.mark.parametrize(
    "outcome",
    [
        None,
        CriticalAlertDeliveryOutcome.ERROR,
        CriticalAlertDeliveryOutcome.TIMEOUT,
    ],
)
def test_exact_unresolved_or_terminal_failure_authenticates(
    outcome: CriticalAlertDeliveryOutcome | None,
) -> None:
    incident, plan, attempts, results, evidence = _history(outcome)
    assert (
        authenticate_total_delivery_failure_evidence(
            incident=incident,
            route_plan=plan,
            attempts=attempts,
            results=results,
            evidence=evidence,
        )
        == evidence
    )


def test_terminal_failure_authenticates_on_first_replay_before_deadline() -> None:
    incident = _incident()
    completed_at = incident.primary_deadline + timedelta(seconds=1)
    incident, plan, attempts, results, evidence = _history(
        CriticalAlertDeliveryOutcome.ERROR,
        completed_at=completed_at,
    )
    replay = replace(evidence, observed_at=completed_at)
    assert (
        authenticate_total_delivery_failure_evidence(
            incident=incident,
            route_plan=plan,
            attempts=attempts,
            results=results,
            evidence=replay,
        )
        == replay
    )
    receipt = bind_critical_alert_failure_control_receipt(
        incident=incident,
        route_plan=plan,
        attempts=attempts,
        results=results,
        evidence=replay,
        pre_control=_halted(incident.scope_id),
        actor_authority_sha256=AUTHORITY_SHA256,
        bound_at=completed_at,
    )
    assert receipt.evidence.observed_at == completed_at
    assert receipt.command.requested_at == completed_at


def test_late_confirmation_is_failure_but_in_budget_confirmation_rejects() -> None:
    incident = _incident()
    late = _history(
        CriticalAlertDeliveryOutcome.CONFIRMED,
        completed_at=incident.escalation_deadline,
    )
    authenticate_total_delivery_failure_evidence(
        incident=late[0],
        route_plan=late[1],
        attempts=late[2],
        results=late[3],
        evidence=late[4],
    )
    timely = _history(
        CriticalAlertDeliveryOutcome.CONFIRMED,
        completed_at=incident.escalation_deadline - timedelta(microseconds=1),
    )
    with pytest.raises(CriticalAlertFailureControlConflict, match="confirmed"):
        authenticate_total_delivery_failure_evidence(
            incident=timely[0],
            route_plan=timely[1],
            attempts=timely[2],
            results=timely[3],
            evidence=timely[4],
        )


def test_predeadline_provider_called_and_route_drift_reject() -> None:
    incident, plan, attempts, results, evidence = _history()
    cases = (
        (
            plan,
            replace(
                evidence,
                observed_at=incident.escalation_deadline - timedelta(microseconds=1),
            ),
            "predates",
        ),
        (plan, replace(evidence, provider_called=True), "replay-derived"),
        (_plan("2"), evidence, "source history"),
    )
    for selected_plan, selected_evidence, message in cases:
        with pytest.raises(CriticalAlertFailureControlConflict, match=message):
            authenticate_total_delivery_failure_evidence(
                incident=incident,
                route_plan=selected_plan,
                attempts=attempts,
                results=results,
                evidence=selected_evidence,
            )


def test_command_and_receipt_are_system_paused_without_adjacent_authority() -> None:
    incident, plan, attempts, results, evidence = _history()
    receipt = bind_critical_alert_failure_control_receipt(
        incident=incident,
        route_plan=plan,
        attempts=attempts,
        results=results,
        evidence=evidence,
        pre_control=_halted(incident.scope_id),
        actor_authority_sha256=AUTHORITY_SHA256,
        bound_at=incident.escalation_deadline,
    )
    command = receipt.command
    assert command.kind is OperationalControlCommandKind.TRIP
    assert command.target_state is OperationalControlState.PAUSED
    assert command.actor.kind is OperationalControlActorKind.SYSTEM
    assert command.actor.actor_id == CRITICAL_ALERT_FAILURE_CONTROL_SYSTEM_ACTOR_ID
    assert receipt.final_control.effective_state is OperationalControlState.HALTED
    assert receipt.final_control.state_changed is False
    assert receipt.requested_control_state is OperationalControlState.PAUSED
    assert receipt.broker_action_authorized is False
    assert receipt.fence_authority_granted is False
    assert receipt.automatic_rearm_authorized is False
    assert receipt.automatic_resume_authorized is False


def test_public_receipt_binder_rejects_forged_terminal_evidence() -> None:
    incident, plan, attempts, results, evidence = _history()
    forged = replace(
        evidence,
        reason=CriticalAlertSupervisorReason.ESCALATION_ATTEMPT_FAILED,
        observed_at=incident.primary_deadline,
        result_id="forged-result",
        result_sha256="0" * 64,
        unresolved_claim=False,
    )
    with pytest.raises(CriticalAlertFailureControlConflict, match="terminal"):
        bind_critical_alert_failure_control_receipt(
            incident=incident,
            route_plan=plan,
            attempts=attempts,
            results=results,
            evidence=forged,
            pre_control=_halted(incident.scope_id),
            actor_authority_sha256=AUTHORITY_SHA256,
            bound_at=incident.primary_deadline,
        )
