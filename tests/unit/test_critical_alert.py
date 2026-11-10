from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta

import pytest

from packages.domain.critical_alert import (
    CRITICAL_ALERT_ESCALATION_DEADLINE_MICROSECONDS,
    CRITICAL_ALERT_LOCAL_DURABILITY_MICROSECONDS,
    CRITICAL_ALERT_PRIMARY_DEADLINE_MICROSECONDS,
    CriticalAlertConflict,
    CriticalAlertDeliveryCommand,
    CriticalAlertDeliveryOutcome,
    CriticalAlertError,
    CriticalAlertIncident,
    CriticalAlertRoute,
    append_critical_alert_delivery_attempt,
    critical_alert_delivery_milestone_met,
    record_critical_alert_delivery_result,
    validate_critical_alert_delivery_history,
)

BASE = datetime(2026, 7, 28, 14, 0, tzinfo=UTC)


def _incident(
    *,
    recorded_at: datetime = BASE + timedelta(milliseconds=500),
) -> CriticalAlertIncident:
    return CriticalAlertIncident(
        scope_id="paper-account-1",
        source_id="strategy-supervisor",
        idempotency_key="incident-0001",
        alert_code="strategy_deadline_exceeded",
        evidence_sha256="a" * 64,
        detected_at=BASE,
        recorded_at=recorded_at,
        correlation_sha256="b" * 64,
    )


def _command(
    incident: CriticalAlertIncident,
    *,
    route: CriticalAlertRoute = CriticalAlertRoute.PRIMARY,
    key: str = "delivery-0001",
    requested_at: datetime | None = None,
) -> CriticalAlertDeliveryCommand:
    return CriticalAlertDeliveryCommand(
        incident_id=incident.incident_id,
        incident_sha256=incident.semantic_sha256,
        route=route,
        provider_id="pager-provider",
        idempotency_key=key,
        request_sha256="c" * 64,
        requested_at=requested_at or incident.recorded_at,
    )


def _attempt(
    incident: CriticalAlertIncident,
    *,
    route: CriticalAlertRoute = CriticalAlertRoute.PRIMARY,
    key: str = "delivery-0001",
    requested_at: datetime | None = None,
    previous: object = None,
) -> object:
    from packages.domain.critical_alert import CriticalAlertDeliveryAttempt

    assert previous is None or type(previous) is CriticalAlertDeliveryAttempt
    command = _command(
        incident,
        route=route,
        key=key,
        requested_at=requested_at,
    )
    return append_critical_alert_delivery_attempt(
        incident=incident,
        command=command,
        claimed_at=command.requested_at,
        previous=previous,
    )


def test_incident_identity_and_local_durability_boundary_are_deterministic() -> None:
    at_budget = _incident(
        recorded_at=BASE + timedelta(microseconds=CRITICAL_ALERT_LOCAL_DURABILITY_MICROSECONDS)
    )
    late = replace(at_budget, recorded_at=at_budget.recorded_at + timedelta(microseconds=1))

    assert replace(at_budget).incident_id == at_budget.incident_id
    assert replace(at_budget).semantic_sha256 == at_budget.semantic_sha256
    assert at_budget.local_durability_milestone_met is True
    assert late.local_durability_milestone_met is False
    assert at_budget.primary_deadline - at_budget.recorded_at == timedelta(
        microseconds=CRITICAL_ALERT_PRIMARY_DEADLINE_MICROSECONDS
    )
    assert at_budget.escalation_deadline - at_budget.recorded_at == timedelta(
        microseconds=CRITICAL_ALERT_ESCALATION_DEADLINE_MICROSECONDS
    )
    assert at_budget.requested_control_state is None
    assert at_budget.broker_action_authorized is False

    with pytest.raises(FrozenInstanceError):
        at_budget.alert_code = "mutated"  # type: ignore[misc]


def test_source_idempotency_identity_does_not_hide_content_conflicts() -> None:
    incident = _incident()
    conflicting = replace(incident, evidence_sha256="f" * 64)

    assert conflicting.incident_id == incident.incident_id
    assert conflicting.semantic_sha256 != incident.semantic_sha256


def test_attempts_form_a_gap_free_predecessor_authenticated_chain() -> None:
    incident = _incident()
    first_object = _attempt(incident)
    from packages.domain.critical_alert import CriticalAlertDeliveryAttempt

    assert type(first_object) is CriticalAlertDeliveryAttempt
    first = first_object
    second_object = _attempt(
        incident,
        route=CriticalAlertRoute.ESCALATION,
        key="delivery-0002",
        requested_at=incident.recorded_at + timedelta(seconds=15),
        previous=first,
    )
    assert type(second_object) is CriticalAlertDeliveryAttempt
    second = second_object

    assert first.sequence_number == 1
    assert first.previous_attempt_id is None
    assert second.sequence_number == 2
    assert second.previous_attempt_id == first.attempt_id
    assert second.previous_attempt_sha256 == first.semantic_sha256

    validate_critical_alert_delivery_history(
        incident=incident,
        attempts=(first, second),
        results=(),
    )
    with pytest.raises(CriticalAlertConflict, match="gap-free"):
        validate_critical_alert_delivery_history(
            incident=incident,
            attempts=(second,),
            results=(),
        )


def test_primary_and_escalation_confirmation_equality_misses_deadline() -> None:
    incident = _incident()
    primary_object = _attempt(incident)
    escalation_object = _attempt(
        incident,
        route=CriticalAlertRoute.ESCALATION,
        key="delivery-0002",
        requested_at=incident.recorded_at + timedelta(seconds=15),
        previous=primary_object,
    )
    from packages.domain.critical_alert import CriticalAlertDeliveryAttempt

    assert type(primary_object) is CriticalAlertDeliveryAttempt
    assert type(escalation_object) is CriticalAlertDeliveryAttempt
    primary_at_equality = record_critical_alert_delivery_result(
        incident=incident,
        attempt=primary_object,
        outcome=CriticalAlertDeliveryOutcome.CONFIRMED,
        completed_at=incident.primary_deadline,
        elapsed_microseconds=CRITICAL_ALERT_PRIMARY_DEADLINE_MICROSECONDS,
        provider_receipt_sha256="d" * 64,
    )
    primary_before = replace(
        primary_at_equality,
        completed_at=incident.primary_deadline - timedelta(microseconds=1),
        elapsed_microseconds=CRITICAL_ALERT_PRIMARY_DEADLINE_MICROSECONDS - 1,
    )
    monotonic_at_equality = replace(
        primary_before,
        elapsed_microseconds=CRITICAL_ALERT_PRIMARY_DEADLINE_MICROSECONDS,
    )
    escalation_at_equality = record_critical_alert_delivery_result(
        incident=incident,
        attempt=escalation_object,
        outcome=CriticalAlertDeliveryOutcome.CONFIRMED,
        completed_at=incident.escalation_deadline,
        elapsed_microseconds=CRITICAL_ALERT_ESCALATION_DEADLINE_MICROSECONDS,
        provider_receipt_sha256="e" * 64,
    )

    assert (
        critical_alert_delivery_milestone_met(
            incident=incident,
            attempt=primary_object,
            result=primary_at_equality,
        )
        is False
    )
    assert (
        critical_alert_delivery_milestone_met(
            incident=incident,
            attempt=primary_object,
            result=primary_before,
        )
        is True
    )
    assert (
        critical_alert_delivery_milestone_met(
            incident=incident,
            attempt=primary_object,
            result=monotonic_at_equality,
        )
        is False
    )
    assert (
        critical_alert_delivery_milestone_met(
            incident=incident,
            attempt=escalation_object,
            result=escalation_at_equality,
        )
        is False
    )


def test_terminal_outcomes_retain_only_receipt_digest_or_failure_code() -> None:
    incident = _incident()
    attempt = _attempt(incident)
    from packages.domain.critical_alert import CriticalAlertDeliveryAttempt

    assert type(attempt) is CriticalAlertDeliveryAttempt
    confirmed = record_critical_alert_delivery_result(
        incident=incident,
        attempt=attempt,
        outcome=CriticalAlertDeliveryOutcome.CONFIRMED,
        completed_at=incident.recorded_at + timedelta(seconds=1),
        elapsed_microseconds=1_000_000,
        provider_receipt_sha256="d" * 64,
    )
    timeout = record_critical_alert_delivery_result(
        incident=incident,
        attempt=attempt,
        outcome=CriticalAlertDeliveryOutcome.TIMEOUT,
        completed_at=incident.recorded_at + timedelta(seconds=2),
        elapsed_microseconds=2_000_000,
        failure_code="provider_timeout",
    )

    assert confirmed.failure_code is None
    assert timeout.provider_receipt_sha256 is None
    assert confirmed.requested_control_state is None
    assert timeout.broker_action_authorized is False

    with pytest.raises(CriticalAlertError, match="receipt digest"):
        replace(confirmed, provider_receipt_sha256=None)
    with pytest.raises(CriticalAlertError, match="failure code"):
        replace(timeout, failure_code=None)


def test_result_cannot_cross_attempt_or_incident_identity() -> None:
    incident = _incident()
    attempt = _attempt(incident)
    other = replace(incident, idempotency_key="incident-0002")
    from packages.domain.critical_alert import CriticalAlertDeliveryAttempt

    assert type(attempt) is CriticalAlertDeliveryAttempt
    with pytest.raises(CriticalAlertConflict, match="crosses"):
        record_critical_alert_delivery_result(
            incident=other,
            attempt=attempt,
            outcome=CriticalAlertDeliveryOutcome.ERROR,
            completed_at=incident.recorded_at + timedelta(seconds=1),
            elapsed_microseconds=1,
            failure_code="provider_error",
        )


def test_delivery_milestone_authenticates_incident_content_not_only_its_id() -> None:
    incident = _incident()
    attempt_object = _attempt(incident)
    from packages.domain.critical_alert import CriticalAlertDeliveryAttempt

    assert type(attempt_object) is CriticalAlertDeliveryAttempt
    forged_attempt = replace(attempt_object, incident_sha256="f" * 64)
    result = record_critical_alert_delivery_result(
        incident=incident,
        attempt=attempt_object,
        outcome=CriticalAlertDeliveryOutcome.CONFIRMED,
        completed_at=incident.recorded_at + timedelta(seconds=1),
        elapsed_microseconds=1_000_000,
        provider_receipt_sha256="d" * 64,
    )
    forged_result = replace(
        result,
        attempt_sha256=forged_attempt.semantic_sha256,
    )

    with pytest.raises(CriticalAlertConflict, match="cross"):
        critical_alert_delivery_milestone_met(
            incident=incident,
            attempt=forged_attempt,
            result=forged_result,
        )
