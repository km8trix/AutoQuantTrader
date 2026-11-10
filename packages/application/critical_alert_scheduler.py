"""Bounded durable scheduling around the strict critical-alert supervisor."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from packages.application.critical_alert_delivery import (
    CriticalAlertDeliveryPort,
    CriticalAlertDeliveryUnavailable,
    CriticalAlertProviderReceipt,
    CriticalAlertProviderRequest,
    MonotonicClock,
)
from packages.application.critical_alert_supervisor import (
    CriticalAlertDeliverySupervisor,
    CriticalAlertRouteBinding,
    CriticalAlertRoutePlan,
    CriticalAlertSupervisorDisposition,
    CriticalAlertSupervisorEvidence,
    CriticalAlertSupervisorReason,
    CriticalAlertSupervisorRepository,
    validate_critical_alert_route_plan_history,
)
from packages.domain.canonical import canonical_json_text
from packages.domain.critical_alert import (
    MAX_CRITICAL_ALERT_SCAN_PAGE,
    CriticalAlertConflict,
    CriticalAlertDeliveryAttempt,
    CriticalAlertDeliveryResult,
    CriticalAlertError,
    CriticalAlertIncident,
    CriticalAlertIncidentScanCursor,
    CriticalAlertIncidentScanPage,
    CriticalAlertRoute,
    critical_alert_delivery_deadline,
    critical_alert_delivery_milestone_met,
    validate_critical_alert_delivery_history,
)
from packages.domain.identifiers import canonical_id
from packages.domain.operational_control import (
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlState,
    OperationalControlTransition,
)

CRITICAL_ALERT_WORKER_CONTRACT_VERSION = "phase5d-critical-alert-worker-v1"
CRITICAL_ALERT_TOTAL_FAILURE_RULE_ID = "critical_alert_total_delivery_failure"
CRITICAL_ALERT_TOTAL_FAILURE_REASON_CODE = "critical_alert_total_delivery_failure"
CRITICAL_ALERT_ATOMIC_FAILURE_CONTROL_REQUIRED = "atomic_failure_control_required"
DEFAULT_CRITICAL_ALERT_WORKER_PAGE_LIMIT = 64

UtcClock = Callable[[], datetime]


class CriticalAlertWorkerError(CriticalAlertError):
    """The durable worker cannot safely interpret or execute its next action."""


class CriticalAlertWorkerUnavailable(CriticalAlertWorkerError):
    """Required deployment configuration or an injected boundary is unavailable."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class CriticalAlertWorkerRepository(CriticalAlertSupervisorRepository, Protocol):
    """Bounded incident scan plus the existing strict supervisor repository."""

    def scan_active_incidents(
        self,
        *,
        as_of: datetime,
        after: CriticalAlertIncidentScanCursor | None,
        limit: int,
    ) -> CriticalAlertIncidentScanPage: ...


class CriticalAlertRouteResolver(Protocol):
    """Resolve one approved opaque binding to its credential-owning adapter."""

    def resolve(
        self,
        incident: CriticalAlertIncident,
        binding: CriticalAlertRouteBinding,
    ) -> CriticalAlertDeliveryPort | None: ...


class CriticalAlertTotalFailureControlPolicy(Protocol):
    """Explicit deployment policy that chooses and binds a control trip."""

    @property
    def policy_id(self) -> str: ...

    @property
    def policy_sha256(self) -> str: ...

    def bind(
        self,
        failure: CriticalAlertTotalDeliveryFailure,
        *,
        idempotency_key: str,
    ) -> OperationalControlCommand: ...


class CriticalAlertOperationalControlWriter(Protocol):
    """Existing durable operational-control write boundary."""

    def apply(self, command: OperationalControlCommand) -> OperationalControlTransition: ...


class CriticalAlertWorkerIncidentState(StrEnum):
    ALREADY_CONFIRMED = "already_confirmed"
    DELIVERY_CONFIRMED = "delivery_confirmed"
    DELIVERY_FAILED = "delivery_failed"
    DELIVERY_UNRESOLVED = "delivery_unresolved"
    CONTROL_BOUND = "control_bound"


def _require_text(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 128
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise CriticalAlertWorkerError(f"{field_name} must be safe non-empty text")


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CriticalAlertWorkerError(f"{field_name} must be a lowercase SHA-256 digest")


def _read_utc(clock: UtcClock) -> datetime:
    value = clock()
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise CriticalAlertWorkerError(
            "critical-alert worker clock must return a timezone-aware UTC instant"
        )
    return value


def _nondecreasing_utc_clock(
    clock: UtcClock,
    *,
    initial: datetime,
) -> UtcClock:
    last = initial

    def read() -> datetime:
        nonlocal last
        value = _read_utc(clock)
        if value < last:
            raise CriticalAlertWorkerError("critical-alert worker clock moved backwards")
        last = value
        return value

    return read


def _result_by_attempt(
    results: tuple[CriticalAlertDeliveryResult, ...],
) -> dict[str, CriticalAlertDeliveryResult]:
    return {result.attempt_id: result for result in results}


def _has_in_budget_confirmation(
    *,
    incident: CriticalAlertIncident,
    attempts: tuple[CriticalAlertDeliveryAttempt, ...],
    results: tuple[CriticalAlertDeliveryResult, ...],
) -> bool:
    results_by_attempt = _result_by_attempt(results)
    return any(
        critical_alert_delivery_milestone_met(
            incident=incident,
            attempt=attempt,
            result=result,
        )
        for attempt in attempts
        if (result := results_by_attempt.get(attempt.attempt_id)) is not None
    )


def _route_exhausted_at(
    *,
    incident: CriticalAlertIncident,
    route: CriticalAlertRoute,
    attempts: tuple[CriticalAlertDeliveryAttempt, ...],
    results: tuple[CriticalAlertDeliveryResult, ...],
    as_of: datetime,
) -> datetime | None:
    route_attempts = tuple(attempt for attempt in attempts if attempt.route is route)
    results_by_attempt = _result_by_attempt(results)
    unresolved = tuple(
        attempt for attempt in route_attempts if attempt.attempt_id not in results_by_attempt
    )
    deadline = critical_alert_delivery_deadline(incident, route)
    if unresolved:
        return deadline if as_of >= deadline else None
    terminal_results = tuple(
        results_by_attempt[attempt.attempt_id]
        for attempt in route_attempts
        if attempt.attempt_id in results_by_attempt
    )
    if terminal_results:
        return min(result.completed_at for result in terminal_results)
    return deadline if as_of >= deadline else None


@dataclass(frozen=True, slots=True)
class CriticalAlertTotalDeliveryFailure:
    """Exact immutable evidence that the supervised route plan is exhausted."""

    incident: CriticalAlertIncident
    route_plan: CriticalAlertRoutePlan
    supervision: CriticalAlertSupervisorEvidence
    attempts: tuple[CriticalAlertDeliveryAttempt, ...]
    results: tuple[CriticalAlertDeliveryResult, ...]
    determined_at: datetime

    def __post_init__(self) -> None:
        if (
            type(self.incident) is not CriticalAlertIncident
            or type(self.route_plan) is not CriticalAlertRoutePlan
            or type(self.supervision) is not CriticalAlertSupervisorEvidence
        ):
            raise CriticalAlertWorkerError(
                "critical-alert total failure requires exact supervised facts"
            )
        validate_critical_alert_delivery_history(
            incident=self.incident,
            attempts=self.attempts,
            results=self.results,
        )
        validate_critical_alert_route_plan_history(
            incident=self.incident,
            route_plan=self.route_plan,
            attempts=self.attempts,
        )
        results_by_attempt = _result_by_attempt(self.results)
        canonical_results = tuple(
            results_by_attempt[attempt.attempt_id]
            for attempt in self.attempts
            if attempt.attempt_id in results_by_attempt
        )
        if self.results != canonical_results:
            raise CriticalAlertConflict(
                "critical-alert total-failure results must follow attempt order"
            )
        if self.supervision.disposition is not (
            CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE
        ):
            raise CriticalAlertConflict(
                "critical-alert total failure requires terminal supervisor evidence"
            )
        if (
            self.supervision.incident_id != self.incident.incident_id
            or self.supervision.incident_sha256 != self.incident.semantic_sha256
            or self.supervision.route_plan_sha256 != self.route_plan.semantic_sha256
        ):
            raise CriticalAlertConflict(
                "critical-alert total failure crosses supervised identities"
            )
        attempt = next(
            (item for item in self.attempts if item.attempt_id == self.supervision.attempt_id),
            None,
        )
        if attempt is None or attempt.semantic_sha256 != self.supervision.attempt_sha256:
            raise CriticalAlertConflict("critical-alert total failure lacks its supervised attempt")
        result = results_by_attempt.get(attempt.attempt_id)
        if self.supervision.result_id is None:
            if result is not None:
                raise CriticalAlertConflict(
                    "critical-alert unresolved supervision has a terminal result"
                )
        elif (
            result is None
            or result.result_id != self.supervision.result_id
            or result.semantic_sha256 != self.supervision.result_sha256
        ):
            raise CriticalAlertConflict("critical-alert total failure lacks its supervised result")
        if (
            type(self.determined_at) is not datetime
            or self.determined_at.tzinfo is None
            or self.determined_at.utcoffset() is None
            or self.determined_at.utcoffset() != UTC.utcoffset(self.determined_at)
        ):
            raise CriticalAlertWorkerError("critical-alert total-failure time must be UTC")
        if _has_in_budget_confirmation(
            incident=self.incident,
            attempts=self.attempts,
            results=self.results,
        ):
            raise CriticalAlertConflict("confirmed critical-alert delivery cannot be total failure")
        exhausted_at = tuple(
            _route_exhausted_at(
                incident=self.incident,
                route=route,
                attempts=self.attempts,
                results=self.results,
                as_of=self.supervision.observed_at,
            )
            for route in CriticalAlertRoute
        )
        if any(value is None for value in exhausted_at):
            raise CriticalAlertConflict(
                "critical-alert total failure requires both exhausted routes"
            )
        expected_determined_at = max(value for value in exhausted_at if value is not None)
        if (
            self.determined_at != expected_determined_at
            or self.supervision.observed_at < self.determined_at
        ):
            raise CriticalAlertConflict(
                "critical-alert total failure time is not canonically derived"
            )

    @property
    def failure_id(self) -> str:
        return canonical_id(
            "critical-alert-total-delivery-failure",
            self.incident.incident_id,
            self.route_plan.semantic_sha256,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                CRITICAL_ALERT_WORKER_CONTRACT_VERSION,
                "total_delivery_failure",
                CRITICAL_ALERT_TOTAL_FAILURE_RULE_ID,
                self.failure_id,
                self.incident.incident_id,
                self.incident.semantic_sha256,
                self.route_plan.semantic_sha256,
                self.supervision.disposition,
                self.supervision.reason,
                self.supervision.selected_route,
                self.supervision.attempt_id,
                self.supervision.attempt_sha256,
                self.supervision.result_id,
                self.supervision.result_sha256,
                self.supervision.unresolved_claim,
                tuple(attempt.semantic_sha256 for attempt in self.attempts),
                tuple(result.semantic_sha256 for result in self.results),
                self.incident.primary_deadline,
                self.incident.escalation_deadline,
                self.determined_at,
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


def critical_alert_total_delivery_failure(
    *,
    incident: CriticalAlertIncident,
    route_plan: CriticalAlertRoutePlan,
    supervision: CriticalAlertSupervisorEvidence,
    attempts: tuple[CriticalAlertDeliveryAttempt, ...],
    results: tuple[CriticalAlertDeliveryResult, ...],
) -> CriticalAlertTotalDeliveryFailure:
    """Bind retained route-plan history to terminal supervisor evidence."""

    validate_critical_alert_delivery_history(
        incident=incident,
        attempts=attempts,
        results=results,
    )
    exhausted_at = tuple(
        _route_exhausted_at(
            incident=incident,
            route=route,
            attempts=attempts,
            results=results,
            as_of=supervision.observed_at,
        )
        for route in CriticalAlertRoute
    )
    if any(value is None for value in exhausted_at):
        raise CriticalAlertConflict("critical-alert total failure requires both exhausted routes")
    results_by_attempt = _result_by_attempt(results)
    canonical_results = tuple(
        results_by_attempt[attempt.attempt_id]
        for attempt in attempts
        if attempt.attempt_id in results_by_attempt
    )
    return CriticalAlertTotalDeliveryFailure(
        incident=incident,
        route_plan=route_plan,
        supervision=supervision,
        attempts=attempts,
        results=canonical_results,
        determined_at=max(value for value in exhausted_at if value is not None),
    )


def critical_alert_control_idempotency_key(
    failure: CriticalAlertTotalDeliveryFailure,
) -> str:
    if type(failure) is not CriticalAlertTotalDeliveryFailure:
        raise CriticalAlertWorkerError(
            "critical-alert control key requires exact total-failure evidence"
        )
    return f"alert-failure:{failure.failure_id}"


@dataclass(frozen=True, slots=True)
class CriticalAlertControlBinding:
    """Validated result of one explicitly injected control policy and write."""

    failure: CriticalAlertTotalDeliveryFailure
    policy_id: str
    policy_sha256: str
    command: OperationalControlCommand
    transition: OperationalControlTransition

    def __post_init__(self) -> None:
        if type(self.failure) is not CriticalAlertTotalDeliveryFailure:
            raise CriticalAlertWorkerError(
                "critical-alert control binding requires exact failure evidence"
            )
        _require_text(self.policy_id, "critical-alert control policy ID")
        _require_sha256(self.policy_sha256, "critical-alert control policy_sha256")
        if (
            type(self.command) is not OperationalControlCommand
            or type(self.transition) is not OperationalControlTransition
        ):
            raise CriticalAlertWorkerError(
                "critical-alert control binding requires exact control facts"
            )
        self.command.__post_init__()
        self.transition.__post_init__()
        if (
            self.command.scope_id != self.failure.incident.scope_id
            or self.command.idempotency_key != critical_alert_control_idempotency_key(self.failure)
            or self.command.kind is not OperationalControlCommandKind.TRIP
            or self.command.target_state
            not in {
                OperationalControlState.PAUSED,
                OperationalControlState.HALTED,
            }
            or self.command.reason_code != CRITICAL_ALERT_TOTAL_FAILURE_REASON_CODE
            or self.command.reason_evidence_sha256 != self.failure.semantic_sha256
            or self.command.requested_at != self.failure.determined_at
            or self.command.trip_rule_id != CRITICAL_ALERT_TOTAL_FAILURE_RULE_ID
            or self.command.trip_policy_sha256 != self.policy_sha256
            or self.command.trip_observation_sha256 != self.failure.semantic_sha256
        ):
            raise CriticalAlertConflict(
                "critical-alert control command is not exactly failure-bound"
            )
        if (
            self.transition.scope_id != self.failure.incident.scope_id
            or self.transition.command_id != self.command.command_id
            or self.transition.command_sha256 != self.command.semantic_sha256
            or self.transition.effective_state is OperationalControlState.RUNNING
            or self.transition.decided_at < self.command.requested_at
        ):
            raise CriticalAlertConflict(
                "critical-alert control transition is not exactly command-bound"
            )


@dataclass(frozen=True, slots=True)
class CriticalAlertWorkerIncidentRun:
    incident: CriticalAlertIncident
    state: CriticalAlertWorkerIncidentState
    supervision: CriticalAlertSupervisorEvidence
    total_failure: CriticalAlertTotalDeliveryFailure | None
    control_binding: CriticalAlertControlBinding | None

    @property
    def broker_action_authorized(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class CriticalAlertWorkerRun:
    scanned_as_of: datetime
    scanned_count: int
    incident_runs: tuple[CriticalAlertWorkerIncidentRun, ...]
    resume_after: CriticalAlertIncidentScanCursor | None

    @property
    def broker_action_authorized(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class _LazyResolvedDeliveryPort:
    """Provider-ID-bound port that resolves only when its route is selected."""

    incident: CriticalAlertIncident
    binding: CriticalAlertRouteBinding
    resolver: CriticalAlertRouteResolver | None

    @property
    def provider_id(self) -> str:
        return self.binding.provider_id

    def deliver(
        self,
        request: CriticalAlertProviderRequest,
        *,
        timeout_seconds: float,
    ) -> CriticalAlertProviderReceipt:
        resolver = self.resolver
        if resolver is None or not callable(getattr(resolver, "resolve", None)):
            raise CriticalAlertDeliveryUnavailable("route_adapter_unavailable")
        try:
            raw_port = resolver.resolve(self.incident, self.binding)
        except Exception:
            raise CriticalAlertDeliveryUnavailable("route_adapter_resolution_failed") from None
        if raw_port is None or not callable(getattr(raw_port, "deliver", None)):
            raise CriticalAlertDeliveryUnavailable("route_adapter_unavailable")
        try:
            provider_id = raw_port.provider_id
        except Exception:
            raise CriticalAlertDeliveryUnavailable("route_adapter_invalid") from None
        if provider_id != self.binding.provider_id:
            raise CriticalAlertDeliveryUnavailable("route_adapter_invalid")
        return raw_port.deliver(request, timeout_seconds=timeout_seconds)


def _lazy_port(
    *,
    resolver: CriticalAlertRouteResolver | None,
    incident: CriticalAlertIncident,
    binding: CriticalAlertRouteBinding,
) -> _LazyResolvedDeliveryPort:
    return _LazyResolvedDeliveryPort(
        incident=incident,
        binding=binding,
        resolver=resolver,
    )


def _bind_total_failure_control(
    *,
    failure: CriticalAlertTotalDeliveryFailure,
    policy: CriticalAlertTotalFailureControlPolicy | None,
    writer: CriticalAlertOperationalControlWriter | None,
) -> CriticalAlertControlBinding:
    """Reject the retired split policy/writer authority before either is read."""

    _ = failure, policy, writer
    raise CriticalAlertWorkerUnavailable(CRITICAL_ALERT_ATOMIC_FAILURE_CONTROL_REQUIRED)


def _load_and_validate_history(
    *,
    repository: CriticalAlertWorkerRepository,
    incident: CriticalAlertIncident,
    route_plan: CriticalAlertRoutePlan,
) -> tuple[
    tuple[CriticalAlertDeliveryAttempt, ...],
    tuple[CriticalAlertDeliveryResult, ...],
]:
    retained_incident = repository.load_incident(incident.incident_id)
    if retained_incident != incident:
        raise CriticalAlertConflict("critical-alert scan incident conflicts with durable readback")
    attempts, results = repository.load_delivery_history(incident.incident_id)
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
    return attempts, results


def _run_incident(
    *,
    incident: CriticalAlertIncident,
    repository: CriticalAlertWorkerRepository,
    route_plan: CriticalAlertRoutePlan | None,
    route_resolver: CriticalAlertRouteResolver | None,
    control_policy: CriticalAlertTotalFailureControlPolicy | None,
    control_writer: CriticalAlertOperationalControlWriter | None,
    utc_clock: UtcClock,
    monotonic_clock: MonotonicClock,
) -> CriticalAlertWorkerIncidentRun:
    if type(route_plan) is not CriticalAlertRoutePlan:
        raise CriticalAlertWorkerUnavailable("route_plan_unavailable")
    attempts, results = _load_and_validate_history(
        repository=repository,
        incident=incident,
        route_plan=route_plan,
    )
    if _has_in_budget_confirmation(
        incident=incident,
        attempts=attempts,
        results=results,
    ):
        # A concurrent worker may have closed the incident after the scan.
        confirmed_attempt = next(
            attempt
            for attempt in attempts
            if (
                (result := _result_by_attempt(results).get(attempt.attempt_id)) is not None
                and critical_alert_delivery_milestone_met(
                    incident=incident,
                    attempt=attempt,
                    result=result,
                )
            )
        )
        confirmed_result = _result_by_attempt(results)[confirmed_attempt.attempt_id]
        supervision = CriticalAlertSupervisorEvidence(
            incident_id=incident.incident_id,
            incident_sha256=incident.semantic_sha256,
            route_plan_sha256=route_plan.semantic_sha256,
            disposition=CriticalAlertSupervisorDisposition.CONFIRMED,
            reason=(
                CriticalAlertSupervisorReason.PRIMARY_CONFIRMED
                if confirmed_attempt.route is CriticalAlertRoute.PRIMARY
                else CriticalAlertSupervisorReason.ESCALATION_CONFIRMED
            ),
            observed_at=max(incident.recorded_at, confirmed_result.completed_at),
            selected_route=confirmed_attempt.route,
            attempt_id=confirmed_attempt.attempt_id,
            attempt_sha256=confirmed_attempt.semantic_sha256,
            result_id=confirmed_result.result_id,
            result_sha256=confirmed_result.semantic_sha256,
            wait_until=None,
            provider_called=False,
            unresolved_claim=False,
        )
        return CriticalAlertWorkerIncidentRun(
            incident=incident,
            state=CriticalAlertWorkerIncidentState.ALREADY_CONFIRMED,
            supervision=supervision,
            total_failure=None,
            control_binding=None,
        )

    # The route-plan history is authenticated before either adapter is resolved.
    primary_port = _lazy_port(
        resolver=route_resolver,
        incident=incident,
        binding=route_plan.primary,
    )
    escalation_port = _lazy_port(
        resolver=route_resolver,
        incident=incident,
        binding=route_plan.escalation,
    )
    try:
        supervision = CriticalAlertDeliverySupervisor(
            repository=repository,
            route_plan=route_plan,
            primary_port=primary_port,
            escalation_port=escalation_port,
            utc_clock=utc_clock,
            monotonic_clock=monotonic_clock,
        ).run_once(incident.incident_id)
    except CriticalAlertDeliveryUnavailable as error:
        raise CriticalAlertWorkerUnavailable(error.reason_code) from None
    if supervision.disposition is CriticalAlertSupervisorDisposition.CONFIRMED:
        state = (
            CriticalAlertWorkerIncidentState.DELIVERY_CONFIRMED
            if supervision.provider_called
            else CriticalAlertWorkerIncidentState.ALREADY_CONFIRMED
        )
        return CriticalAlertWorkerIncidentRun(
            incident=incident,
            state=state,
            supervision=supervision,
            total_failure=None,
            control_binding=None,
        )
    if supervision.disposition is CriticalAlertSupervisorDisposition.WAIT:
        return CriticalAlertWorkerIncidentRun(
            incident=incident,
            state=(
                CriticalAlertWorkerIncidentState.DELIVERY_UNRESOLVED
                if supervision.unresolved_claim
                else CriticalAlertWorkerIncidentState.DELIVERY_FAILED
            ),
            supervision=supervision,
            total_failure=None,
            control_binding=None,
        )
    if supervision.disposition is CriticalAlertSupervisorDisposition.PRIMARY_FAILED:
        return CriticalAlertWorkerIncidentRun(
            incident=incident,
            state=CriticalAlertWorkerIncidentState.DELIVERY_FAILED,
            supervision=supervision,
            total_failure=None,
            control_binding=None,
        )

    attempts, results = _load_and_validate_history(
        repository=repository,
        incident=incident,
        route_plan=route_plan,
    )
    failure = critical_alert_total_delivery_failure(
        incident=incident,
        route_plan=route_plan,
        supervision=supervision,
        attempts=attempts,
        results=results,
    )
    binding = _bind_total_failure_control(
        failure=failure,
        policy=control_policy,
        writer=control_writer,
    )
    return CriticalAlertWorkerIncidentRun(
        incident=incident,
        state=CriticalAlertWorkerIncidentState.CONTROL_BOUND,
        supervision=supervision,
        total_failure=failure,
        control_binding=binding,
    )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def run_critical_alert_worker_once(
    *,
    repository: CriticalAlertWorkerRepository,
    route_plan: CriticalAlertRoutePlan | None,
    route_resolver: CriticalAlertRouteResolver | None,
    control_policy: CriticalAlertTotalFailureControlPolicy | None,
    control_writer: CriticalAlertOperationalControlWriter | None,
    after: CriticalAlertIncidentScanCursor | None = None,
    limit: int = DEFAULT_CRITICAL_ALERT_WORKER_PAGE_LIMIT,
    utc_clock: UtcClock = _utc_now,
    monotonic_clock: MonotonicClock = time.monotonic,
) -> CriticalAlertWorkerRun:
    """Process one bounded scan page through the strict single-step supervisor."""

    required_methods = (
        "scan_active_incidents",
        "load_incident",
        "find_delivery_attempt",
        "claim_delivery_attempt",
        "load_delivery_result",
        "load_delivery_history",
        "record_delivery_result",
    )
    if not all(callable(getattr(repository, method, None)) for method in required_methods):
        raise CriticalAlertWorkerError(
            "critical-alert worker requires a complete durable repository"
        )
    if after is not None and type(after) is not CriticalAlertIncidentScanCursor:
        raise CriticalAlertWorkerError("critical-alert worker scan cursor must be exact")
    if type(limit) is not int or not 1 <= limit <= MAX_CRITICAL_ALERT_SCAN_PAGE:
        raise CriticalAlertWorkerError("critical-alert worker page limit exceeds its bounded range")
    if not callable(utc_clock) or not callable(monotonic_clock):
        raise CriticalAlertWorkerError("critical-alert worker requires trusted clocks")

    scanned_as_of = _read_utc(utc_clock)
    page = repository.scan_active_incidents(
        as_of=scanned_as_of,
        after=after,
        limit=limit,
    )
    if type(page) is not CriticalAlertIncidentScanPage:
        raise CriticalAlertWorkerError(
            "critical-alert worker repository returned a noncanonical scan page"
        )
    if page.scanned_count > limit:
        raise CriticalAlertWorkerError(
            "critical-alert worker repository exceeded the requested scan bound"
        )
    if any(
        incident.recorded_at > scanned_as_of
        or (after is not None and (incident.recorded_at, incident.incident_id) <= after.sort_key)
        for incident in page.incidents
    ):
        raise CriticalAlertWorkerError(
            "critical-alert worker repository returned an out-of-window incident"
        )
    if page.resume_after is not None and (
        page.resume_after.recorded_at > scanned_as_of
        or (after is not None and page.resume_after.sort_key <= after.sort_key)
    ):
        raise CriticalAlertWorkerError(
            "critical-alert worker repository returned a nonadvancing cursor"
        )

    supervisor_utc_clock = _nondecreasing_utc_clock(
        utc_clock,
        initial=scanned_as_of,
    )
    incident_runs = tuple(
        _run_incident(
            incident=incident,
            repository=repository,
            route_plan=route_plan,
            route_resolver=route_resolver,
            control_policy=control_policy,
            control_writer=control_writer,
            utc_clock=supervisor_utc_clock,
            monotonic_clock=monotonic_clock,
        )
        for incident in page.incidents
    )
    return CriticalAlertWorkerRun(
        scanned_as_of=scanned_as_of,
        scanned_count=page.scanned_count,
        incident_runs=incident_runs,
        resume_after=page.resume_after,
    )


__all__ = [
    "CRITICAL_ALERT_ATOMIC_FAILURE_CONTROL_REQUIRED",
    "CRITICAL_ALERT_TOTAL_FAILURE_REASON_CODE",
    "CRITICAL_ALERT_TOTAL_FAILURE_RULE_ID",
    "CRITICAL_ALERT_WORKER_CONTRACT_VERSION",
    "CriticalAlertControlBinding",
    "CriticalAlertOperationalControlWriter",
    "CriticalAlertRouteResolver",
    "CriticalAlertTotalDeliveryFailure",
    "CriticalAlertTotalFailureControlPolicy",
    "CriticalAlertWorkerError",
    "CriticalAlertWorkerIncidentRun",
    "CriticalAlertWorkerIncidentState",
    "CriticalAlertWorkerRepository",
    "CriticalAlertWorkerRun",
    "CriticalAlertWorkerUnavailable",
    "critical_alert_control_idempotency_key",
    "critical_alert_total_delivery_failure",
    "run_critical_alert_worker_once",
]
