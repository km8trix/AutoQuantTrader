"""Bounded, restart-derived supervision for critical-alert delivery."""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from packages.application.critical_alert_delivery import (
    CriticalAlertDeliveryPort,
    CriticalAlertDeliveryRepository,
    CriticalAlertDeliveryRun,
    CriticalAlertProviderRequest,
    MonotonicClock,
    UtcClock,
    deliver_critical_alert,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.critical_alert import (
    CriticalAlertConflict,
    CriticalAlertDeliveryAttempt,
    CriticalAlertDeliveryResult,
    CriticalAlertError,
    CriticalAlertIncident,
    CriticalAlertRoute,
    critical_alert_delivery_milestone_met,
    validate_critical_alert_delivery_history,
)

CRITICAL_ALERT_SUPERVISOR_CONTRACT_VERSION = "phase5d-critical-alert-supervisor-v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CriticalAlertSupervisorError(CriticalAlertError):
    """The supervisor plan, durable history, or trusted clock is invalid."""


class CriticalAlertSupervisorDisposition(StrEnum):
    """One bounded outcome derived from the current durable prefix."""

    CONFIRMED = "confirmed"
    PRIMARY_FAILED = "primary_failed"
    WAIT = "wait"
    TOTAL_DELIVERY_FAILURE = "total_delivery_failure"


class CriticalAlertSupervisorReason(StrEnum):
    """Allowlisted diagnostics that cannot contain provider exception text."""

    PRIMARY_CONFIRMED = "primary_confirmed"
    ESCALATION_CONFIRMED = "escalation_confirmed"
    PRIMARY_ATTEMPT_FAILED = "primary_attempt_failed"
    PRIMARY_CLAIM_UNRESOLVED = "primary_claim_unresolved"
    PRIMARY_DEADLINE_WAIT = "primary_deadline_wait"
    ESCALATION_CONFIRMED_AFTER_PRIMARY_DEADLINE = "escalation_confirmed_after_primary_deadline"
    ESCALATION_CLAIM_UNRESOLVED = "escalation_claim_unresolved"
    ESCALATION_ATTEMPT_FAILED = "escalation_attempt_failed"
    ESCALATION_DEADLINE_UNRESOLVED = "escalation_deadline_unresolved"


class CriticalAlertSupervisorRepository(
    CriticalAlertDeliveryRepository,
    Protocol,
):
    """Durable boundary used to reconstruct each supervisor decision."""

    def load_incident(self, incident_id: str) -> CriticalAlertIncident: ...


def _require_text(value: str, field_name: str, *, maximum: int = 128) -> None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise CriticalAlertSupervisorError(f"{field_name} must be bounded, non-empty, trimmed text")


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise CriticalAlertSupervisorError(f"{field_name} must be a lowercase SHA-256 digest")


def _read_utc(clock: UtcClock) -> datetime:
    value = clock()
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise CriticalAlertSupervisorError("critical-alert supervisor UTC clock must return UTC")
    return value


@dataclass(frozen=True, slots=True)
class CriticalAlertRouteBinding:
    """Injected opaque route identity; it carries no credentials or raw recipients."""

    route: CriticalAlertRoute
    provider_id: str
    destination_sha256: str
    recipient_set_sha256: str

    def __post_init__(self) -> None:
        if type(self.route) is not CriticalAlertRoute:
            raise CriticalAlertSupervisorError("critical-alert route binding is unsupported")
        _require_text(self.provider_id, "critical-alert route provider ID")
        _require_sha256(
            self.destination_sha256,
            "critical-alert route destination_sha256",
        )
        _require_sha256(
            self.recipient_set_sha256,
            "critical-alert route recipient_set_sha256",
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                CRITICAL_ALERT_SUPERVISOR_CONTRACT_VERSION,
                "route_binding",
                self.route,
                self.provider_id,
                self.destination_sha256,
                self.recipient_set_sha256,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class CriticalAlertRoutePlan:
    """Exact injected primary/escalation identities without an independence claim."""

    plan_id: str
    plan_version: str
    primary: CriticalAlertRouteBinding
    escalation: CriticalAlertRouteBinding

    def __post_init__(self) -> None:
        _require_text(self.plan_id, "critical-alert route-plan ID")
        _require_text(self.plan_version, "critical-alert route-plan version")
        if type(self.primary) is not CriticalAlertRouteBinding:
            raise CriticalAlertSupervisorError(
                "critical-alert route plan requires an exact primary binding"
            )
        if type(self.escalation) is not CriticalAlertRouteBinding:
            raise CriticalAlertSupervisorError(
                "critical-alert route plan requires an exact escalation binding"
            )
        if self.primary.route is not CriticalAlertRoute.PRIMARY:
            raise CriticalAlertSupervisorError("critical-alert primary binding has the wrong route")
        if self.escalation.route is not CriticalAlertRoute.ESCALATION:
            raise CriticalAlertSupervisorError(
                "critical-alert escalation binding has the wrong route"
            )
        if self.primary.provider_id == self.escalation.provider_id:
            raise CriticalAlertSupervisorError(
                "critical-alert primary and escalation providers must be distinct"
            )

    def binding_for(self, route: CriticalAlertRoute) -> CriticalAlertRouteBinding:
        if route is CriticalAlertRoute.PRIMARY:
            return self.primary
        if route is CriticalAlertRoute.ESCALATION:
            return self.escalation
        raise CriticalAlertSupervisorError("critical-alert route plan lookup is unsupported")

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                CRITICAL_ALERT_SUPERVISOR_CONTRACT_VERSION,
                "route_plan",
                self.plan_id,
                self.plan_version,
                self.primary.semantic_sha256,
                self.escalation.semantic_sha256,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json.encode()).hexdigest()

    @property
    def operational_independence_verified(self) -> bool:
        """Distinct provider IDs do not prove operational independence."""

        return False


def critical_alert_route_idempotency_key(
    *,
    incident: CriticalAlertIncident,
    route_plan: CriticalAlertRoutePlan,
    route: CriticalAlertRoute,
) -> str:
    """Bind one deterministic provider key to the incident and exact route plan."""

    if type(incident) is not CriticalAlertIncident:
        raise CriticalAlertSupervisorError("critical-alert route key requires an exact incident")
    if type(route_plan) is not CriticalAlertRoutePlan:
        raise CriticalAlertSupervisorError("critical-alert route key requires an exact route plan")
    binding = route_plan.binding_for(route)
    digest = hashlib.sha256(
        canonical_json_bytes(
            (
                CRITICAL_ALERT_SUPERVISOR_CONTRACT_VERSION,
                "route_idempotency",
                incident.incident_id,
                incident.semantic_sha256,
                route_plan.semantic_sha256,
                binding.semantic_sha256,
            )
        )
    ).hexdigest()
    return f"critical-alert-{route.value}-{digest}"


@dataclass(frozen=True, slots=True)
class CriticalAlertSupervisorEvidence:
    """Sanitized process-local proof of one bounded supervisor invocation."""

    incident_id: str
    incident_sha256: str
    route_plan_sha256: str
    disposition: CriticalAlertSupervisorDisposition
    reason: CriticalAlertSupervisorReason
    observed_at: datetime
    selected_route: CriticalAlertRoute
    attempt_id: str | None
    attempt_sha256: str | None
    result_id: str | None
    result_sha256: str | None
    wait_until: datetime | None
    provider_called: bool
    unresolved_claim: bool

    def __post_init__(self) -> None:
        _require_text(self.incident_id, "critical-alert supervisor incident ID")
        _require_sha256(
            self.incident_sha256,
            "critical-alert supervisor incident_sha256",
        )
        _require_sha256(
            self.route_plan_sha256,
            "critical-alert supervisor route_plan_sha256",
        )
        if type(self.disposition) is not CriticalAlertSupervisorDisposition:
            raise CriticalAlertSupervisorError(
                "critical-alert supervisor disposition is unsupported"
            )
        if type(self.reason) is not CriticalAlertSupervisorReason:
            raise CriticalAlertSupervisorError("critical-alert supervisor reason is unsupported")
        _ = _read_utc(lambda: self.observed_at)
        if type(self.selected_route) is not CriticalAlertRoute:
            raise CriticalAlertSupervisorError(
                "critical-alert supervisor selected route is unsupported"
            )
        if (self.attempt_id is None) != (self.attempt_sha256 is None):
            raise CriticalAlertSupervisorError(
                "critical-alert supervisor attempt identity is incomplete"
            )
        if self.attempt_id is not None:
            _require_text(self.attempt_id, "critical-alert supervisor attempt ID")
            if self.attempt_sha256 is None:
                raise CriticalAlertSupervisorError(
                    "critical-alert supervisor attempt digest is absent"
                )
            _require_sha256(
                self.attempt_sha256,
                "critical-alert supervisor attempt_sha256",
            )
        if (self.result_id is None) != (self.result_sha256 is None):
            raise CriticalAlertSupervisorError(
                "critical-alert supervisor result identity is incomplete"
            )
        if self.result_id is not None:
            if self.attempt_id is None:
                raise CriticalAlertSupervisorError(
                    "critical-alert supervisor result requires an attempt"
                )
            _require_text(self.result_id, "critical-alert supervisor result ID")
            if self.result_sha256 is None:
                raise CriticalAlertSupervisorError(
                    "critical-alert supervisor result digest is absent"
                )
            _require_sha256(
                self.result_sha256,
                "critical-alert supervisor result_sha256",
            )
        wait_until = self.wait_until
        if wait_until is not None:
            _ = _read_utc(lambda: wait_until)
        if type(self.provider_called) is not bool:
            raise CriticalAlertSupervisorError(
                "critical-alert supervisor provider_called must be boolean"
            )
        if type(self.unresolved_claim) is not bool:
            raise CriticalAlertSupervisorError(
                "critical-alert supervisor unresolved_claim must be boolean"
            )
        if self.unresolved_claim != (self.attempt_id is not None and self.result_id is None):
            raise CriticalAlertSupervisorError(
                "critical-alert supervisor unresolved-claim evidence conflicts"
            )
        expected_reasons = {
            CriticalAlertSupervisorDisposition.CONFIRMED: frozenset(
                {
                    CriticalAlertSupervisorReason.PRIMARY_CONFIRMED,
                    CriticalAlertSupervisorReason.ESCALATION_CONFIRMED,
                    CriticalAlertSupervisorReason.ESCALATION_CONFIRMED_AFTER_PRIMARY_DEADLINE,
                }
            ),
            CriticalAlertSupervisorDisposition.PRIMARY_FAILED: frozenset(
                {CriticalAlertSupervisorReason.PRIMARY_ATTEMPT_FAILED}
            ),
            CriticalAlertSupervisorDisposition.WAIT: frozenset(
                {
                    CriticalAlertSupervisorReason.PRIMARY_CLAIM_UNRESOLVED,
                    CriticalAlertSupervisorReason.PRIMARY_DEADLINE_WAIT,
                    CriticalAlertSupervisorReason.ESCALATION_CLAIM_UNRESOLVED,
                }
            ),
            CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE: frozenset(
                {
                    CriticalAlertSupervisorReason.ESCALATION_ATTEMPT_FAILED,
                    CriticalAlertSupervisorReason.ESCALATION_DEADLINE_UNRESOLVED,
                }
            ),
        }
        if self.reason not in expected_reasons[self.disposition]:
            raise CriticalAlertSupervisorError(
                "critical-alert supervisor reason conflicts with its disposition"
            )
        if self.disposition in {
            CriticalAlertSupervisorDisposition.WAIT,
            CriticalAlertSupervisorDisposition.PRIMARY_FAILED,
        }:
            if self.wait_until is None:
                raise CriticalAlertSupervisorError(
                    "critical-alert supervisor pending evidence requires wait_until"
                )
        elif self.wait_until is not None:
            raise CriticalAlertSupervisorError(
                "terminal critical-alert supervisor evidence cannot wait"
            )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                CRITICAL_ALERT_SUPERVISOR_CONTRACT_VERSION,
                "supervisor_evidence",
                self.incident_id,
                self.incident_sha256,
                self.route_plan_sha256,
                self.disposition,
                self.reason,
                self.observed_at,
                self.selected_route,
                self.attempt_id,
                self.attempt_sha256,
                self.result_id,
                self.result_sha256,
                self.wait_until,
                self.provider_called,
                self.unresolved_claim,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json.encode()).hexdigest()

    @property
    def requested_control_state(self) -> None:
        return None

    @property
    def broker_action_authorized(self) -> bool:
        return False

    @property
    def automatic_rearm_authorized(self) -> bool:
        return False

    @property
    def operational_independence_verified(self) -> bool:
        return False


def _expected_request(
    *,
    incident: CriticalAlertIncident,
    route_plan: CriticalAlertRoutePlan,
    route: CriticalAlertRoute,
) -> CriticalAlertProviderRequest:
    binding = route_plan.binding_for(route)
    return CriticalAlertProviderRequest.bind(
        incident=incident,
        route=route,
        provider_id=binding.provider_id,
        idempotency_key=critical_alert_route_idempotency_key(
            incident=incident,
            route_plan=route_plan,
            route=route,
        ),
    )


def validate_critical_alert_route_plan_history(
    *,
    incident: CriticalAlertIncident,
    route_plan: CriticalAlertRoutePlan,
    attempts: tuple[CriticalAlertDeliveryAttempt, ...],
) -> None:
    seen_routes: set[CriticalAlertRoute] = set()
    for attempt in attempts:
        if attempt.route in seen_routes:
            raise CriticalAlertConflict("critical-alert supervisor history repeats a fixed route")
        seen_routes.add(attempt.route)
        expected = _expected_request(
            incident=incident,
            route_plan=route_plan,
            route=attempt.route,
        )
        if (
            attempt.provider_id != expected.provider_id
            or attempt.idempotency_key != expected.idempotency_key
            or attempt.request_sha256 != expected.semantic_sha256
        ):
            raise CriticalAlertConflict(
                "critical-alert supervisor history conflicts with the route plan"
            )
        if (
            attempt.route is CriticalAlertRoute.PRIMARY
            and attempt.requested_at >= incident.primary_deadline
        ):
            raise CriticalAlertConflict(
                "critical-alert supervisor primary claim missed its selection window"
            )
        if (
            attempt.route is CriticalAlertRoute.ESCALATION
            and attempt.requested_at < incident.primary_deadline
        ):
            raise CriticalAlertConflict(
                "critical-alert supervisor escalation claim predates its selection window"
            )
    if len(attempts) == 2 and attempts[0].route is not CriticalAlertRoute.PRIMARY:
        raise CriticalAlertConflict("critical-alert supervisor route history is not primary-first")


def _result_by_attempt(
    results: tuple[CriticalAlertDeliveryResult, ...],
) -> dict[str, CriticalAlertDeliveryResult]:
    return {result.attempt_id: result for result in results}


def _attempt_for_route(
    attempts: tuple[CriticalAlertDeliveryAttempt, ...],
    route: CriticalAlertRoute,
) -> CriticalAlertDeliveryAttempt | None:
    return next((attempt for attempt in attempts if attempt.route is route), None)


def _confirmed_attempt(
    *,
    incident: CriticalAlertIncident,
    attempts: tuple[CriticalAlertDeliveryAttempt, ...],
    results: tuple[CriticalAlertDeliveryResult, ...],
) -> tuple[CriticalAlertDeliveryAttempt, CriticalAlertDeliveryResult] | None:
    by_attempt = _result_by_attempt(results)
    for attempt in attempts:
        result = by_attempt.get(attempt.attempt_id)
        if result is not None and critical_alert_delivery_milestone_met(
            incident=incident,
            attempt=attempt,
            result=result,
        ):
            return attempt, result
    return None


def _history_latest_time(
    *,
    incident: CriticalAlertIncident,
    attempts: tuple[CriticalAlertDeliveryAttempt, ...],
    results: tuple[CriticalAlertDeliveryResult, ...],
) -> datetime:
    times = [incident.recorded_at]
    times.extend(attempt.claimed_at for attempt in attempts)
    times.extend(result.completed_at for result in results)
    return max(times)


def _evidence(
    *,
    incident: CriticalAlertIncident,
    route_plan: CriticalAlertRoutePlan,
    disposition: CriticalAlertSupervisorDisposition,
    reason: CriticalAlertSupervisorReason,
    observed_at: datetime,
    route: CriticalAlertRoute,
    attempt: CriticalAlertDeliveryAttempt | None,
    result: CriticalAlertDeliveryResult | None,
    wait_until: datetime | None = None,
    provider_called: bool = False,
) -> CriticalAlertSupervisorEvidence:
    return CriticalAlertSupervisorEvidence(
        incident_id=incident.incident_id,
        incident_sha256=incident.semantic_sha256,
        route_plan_sha256=route_plan.semantic_sha256,
        disposition=disposition,
        reason=reason,
        observed_at=observed_at,
        selected_route=route,
        attempt_id=None if attempt is None else attempt.attempt_id,
        attempt_sha256=None if attempt is None else attempt.semantic_sha256,
        result_id=None if result is None else result.result_id,
        result_sha256=None if result is None else result.semantic_sha256,
        wait_until=wait_until,
        provider_called=provider_called,
        unresolved_claim=attempt is not None and result is None,
    )


def _from_delivery_run(
    *,
    incident: CriticalAlertIncident,
    route_plan: CriticalAlertRoutePlan,
    run: CriticalAlertDeliveryRun,
    decision_at: datetime,
) -> CriticalAlertSupervisorEvidence:
    result = run.result
    observed_at = (
        max(decision_at, run.attempt.claimed_at)
        if result is None
        else max(decision_at, result.completed_at)
    )
    if result is not None and run.delivery_milestone_met is True:
        reason = (
            CriticalAlertSupervisorReason.PRIMARY_CONFIRMED
            if run.attempt.route is CriticalAlertRoute.PRIMARY
            else CriticalAlertSupervisorReason.ESCALATION_CONFIRMED_AFTER_PRIMARY_DEADLINE
        )
        return _evidence(
            incident=incident,
            route_plan=route_plan,
            disposition=CriticalAlertSupervisorDisposition.CONFIRMED,
            reason=reason,
            observed_at=observed_at,
            route=run.attempt.route,
            attempt=run.attempt,
            result=result,
            provider_called=run.provider_called,
        )
    if run.attempt.route is CriticalAlertRoute.PRIMARY:
        if result is None:
            return _evidence(
                incident=incident,
                route_plan=route_plan,
                disposition=CriticalAlertSupervisorDisposition.WAIT,
                reason=CriticalAlertSupervisorReason.PRIMARY_CLAIM_UNRESOLVED,
                observed_at=observed_at,
                route=run.attempt.route,
                attempt=run.attempt,
                result=None,
                wait_until=incident.primary_deadline,
                provider_called=run.provider_called,
            )
        return _evidence(
            incident=incident,
            route_plan=route_plan,
            disposition=CriticalAlertSupervisorDisposition.PRIMARY_FAILED,
            reason=CriticalAlertSupervisorReason.PRIMARY_ATTEMPT_FAILED,
            observed_at=observed_at,
            route=run.attempt.route,
            attempt=run.attempt,
            result=result,
            wait_until=incident.primary_deadline,
            provider_called=run.provider_called,
        )
    if result is None:
        disposition = (
            CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE
            if observed_at >= incident.escalation_deadline
            else CriticalAlertSupervisorDisposition.WAIT
        )
        reason = (
            CriticalAlertSupervisorReason.ESCALATION_DEADLINE_UNRESOLVED
            if disposition is CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE
            else CriticalAlertSupervisorReason.ESCALATION_CLAIM_UNRESOLVED
        )
        return _evidence(
            incident=incident,
            route_plan=route_plan,
            disposition=disposition,
            reason=reason,
            observed_at=observed_at,
            route=run.attempt.route,
            attempt=run.attempt,
            result=None,
            wait_until=(
                incident.escalation_deadline
                if disposition is CriticalAlertSupervisorDisposition.WAIT
                else None
            ),
            provider_called=run.provider_called,
        )
    return _evidence(
        incident=incident,
        route_plan=route_plan,
        disposition=CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE,
        reason=CriticalAlertSupervisorReason.ESCALATION_ATTEMPT_FAILED,
        observed_at=observed_at,
        route=run.attempt.route,
        attempt=run.attempt,
        result=result,
        provider_called=run.provider_called,
    )


@dataclass(slots=True)
class _AnchoredUtcClock:
    first_value: datetime
    delegate: UtcClock
    first_read: bool = True

    def __call__(self) -> datetime:
        if self.first_read:
            self.first_read = False
            return self.first_value
        return _read_utc(self.delegate)


class CriticalAlertDeliverySupervisor:
    """Derive and execute at most one route action from exact durable history."""

    __slots__ = (
        "_escalation_port",
        "_monotonic_clock",
        "_primary_port",
        "_repository",
        "_route_plan",
        "_utc_clock",
    )

    def __init__(
        self,
        *,
        repository: CriticalAlertSupervisorRepository,
        route_plan: CriticalAlertRoutePlan,
        primary_port: CriticalAlertDeliveryPort,
        escalation_port: CriticalAlertDeliveryPort,
        utc_clock: UtcClock,
        monotonic_clock: MonotonicClock = time.monotonic,
    ) -> None:
        if type(route_plan) is not CriticalAlertRoutePlan:
            raise CriticalAlertSupervisorError(
                "critical-alert supervisor requires an exact route plan"
            )
        if primary_port.provider_id != route_plan.primary.provider_id:
            raise CriticalAlertSupervisorError(
                "critical-alert primary port conflicts with the route plan"
            )
        if escalation_port.provider_id != route_plan.escalation.provider_id:
            raise CriticalAlertSupervisorError(
                "critical-alert escalation port conflicts with the route plan"
            )
        self._repository = repository
        self._route_plan = route_plan
        self._primary_port = primary_port
        self._escalation_port = escalation_port
        self._utc_clock = utc_clock
        self._monotonic_clock = monotonic_clock

    def run_once(self, incident_id: str) -> CriticalAlertSupervisorEvidence:
        """Reload, validate, derive, and perform no more than one provider call."""

        _require_text(incident_id, "critical-alert supervisor incident ID")

        # Durable history is always reconstructed and authenticated before time
        # or provider state can influence a decision.
        incident = self._repository.load_incident(incident_id)
        if incident.incident_id != incident_id:
            raise CriticalAlertConflict(
                "critical-alert repository returned the wrong incident identity"
            )
        attempts, results = self._repository.load_delivery_history(incident_id)
        validate_critical_alert_delivery_history(
            incident=incident,
            attempts=attempts,
            results=results,
        )
        validate_critical_alert_route_plan_history(
            incident=incident,
            route_plan=self._route_plan,
            attempts=attempts,
        )

        if self._primary_port.provider_id != self._route_plan.primary.provider_id:
            raise CriticalAlertSupervisorError(
                "critical-alert primary port changed provider identity"
            )
        if self._escalation_port.provider_id != self._route_plan.escalation.provider_id:
            raise CriticalAlertSupervisorError(
                "critical-alert escalation port changed provider identity"
            )

        observed_at = _read_utc(self._utc_clock)
        if observed_at < _history_latest_time(
            incident=incident,
            attempts=attempts,
            results=results,
        ):
            raise CriticalAlertSupervisorError(
                "critical-alert supervisor clock predates durable history"
            )
        by_attempt = _result_by_attempt(results)
        confirmed = _confirmed_attempt(
            incident=incident,
            attempts=attempts,
            results=results,
        )
        if confirmed is not None:
            attempt, result = confirmed
            reason = (
                CriticalAlertSupervisorReason.PRIMARY_CONFIRMED
                if attempt.route is CriticalAlertRoute.PRIMARY
                else CriticalAlertSupervisorReason.ESCALATION_CONFIRMED
            )
            return _evidence(
                incident=incident,
                route_plan=self._route_plan,
                disposition=CriticalAlertSupervisorDisposition.CONFIRMED,
                reason=reason,
                observed_at=observed_at,
                route=attempt.route,
                attempt=attempt,
                result=result,
            )

        primary = _attempt_for_route(attempts, CriticalAlertRoute.PRIMARY)
        escalation = _attempt_for_route(attempts, CriticalAlertRoute.ESCALATION)
        primary_result = None if primary is None else by_attempt.get(primary.attempt_id)
        escalation_result = None if escalation is None else by_attempt.get(escalation.attempt_id)

        if observed_at < incident.primary_deadline:
            if primary is None:
                return self._deliver(
                    incident=incident,
                    route=CriticalAlertRoute.PRIMARY,
                    delivery_port=self._primary_port,
                    observed_at=observed_at,
                )
            reason = (
                CriticalAlertSupervisorReason.PRIMARY_CLAIM_UNRESOLVED
                if primary_result is None
                else CriticalAlertSupervisorReason.PRIMARY_DEADLINE_WAIT
            )
            return _evidence(
                incident=incident,
                route_plan=self._route_plan,
                disposition=CriticalAlertSupervisorDisposition.WAIT,
                reason=reason,
                observed_at=observed_at,
                route=CriticalAlertRoute.PRIMARY,
                attempt=primary,
                result=primary_result,
                wait_until=incident.primary_deadline,
            )

        if escalation is None:
            return self._deliver(
                incident=incident,
                route=CriticalAlertRoute.ESCALATION,
                delivery_port=self._escalation_port,
                observed_at=observed_at,
            )
        if escalation_result is None:
            total_failure = observed_at >= incident.escalation_deadline
            return _evidence(
                incident=incident,
                route_plan=self._route_plan,
                disposition=(
                    CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE
                    if total_failure
                    else CriticalAlertSupervisorDisposition.WAIT
                ),
                reason=(
                    CriticalAlertSupervisorReason.ESCALATION_DEADLINE_UNRESOLVED
                    if total_failure
                    else CriticalAlertSupervisorReason.ESCALATION_CLAIM_UNRESOLVED
                ),
                observed_at=observed_at,
                route=CriticalAlertRoute.ESCALATION,
                attempt=escalation,
                result=None,
                wait_until=None if total_failure else incident.escalation_deadline,
            )
        return _evidence(
            incident=incident,
            route_plan=self._route_plan,
            disposition=CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE,
            reason=CriticalAlertSupervisorReason.ESCALATION_ATTEMPT_FAILED,
            observed_at=observed_at,
            route=CriticalAlertRoute.ESCALATION,
            attempt=escalation,
            result=escalation_result,
        )

    def _deliver(
        self,
        *,
        incident: CriticalAlertIncident,
        route: CriticalAlertRoute,
        delivery_port: CriticalAlertDeliveryPort,
        observed_at: datetime,
    ) -> CriticalAlertSupervisorEvidence:
        run = deliver_critical_alert(
            incident=incident,
            route=route,
            idempotency_key=critical_alert_route_idempotency_key(
                incident=incident,
                route_plan=self._route_plan,
                route=route,
            ),
            repository=self._repository,
            delivery_port=delivery_port,
            utc_clock=_AnchoredUtcClock(observed_at, self._utc_clock),
            monotonic_clock=self._monotonic_clock,
        )
        return _from_delivery_run(
            incident=incident,
            route_plan=self._route_plan,
            run=run,
            decision_at=observed_at,
        )
