"""Bounded critical-alert supervision with atomic local failure control.

This composition is deliberately local and unwired. It requires one exact
injected route plan, credential-owning route adapters, and the authority-owning
Phase 5D atomic failure-control binder. It owns no provider defaults, recipient
configuration, broker, fence, re-arm, or resume authority.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from packages.application.critical_alert_delivery import (
    CriticalAlertDeliveryPort,
    CriticalAlertDeliveryUnavailable,
    CriticalAlertProviderReceipt,
    CriticalAlertProviderRequest,
    MonotonicClock,
    UtcClock,
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
from packages.application.critical_alert_supervisor_failure_control import (
    CRITICAL_ALERT_FAILURE_CONTROL_POLICY_SHA256,
    CriticalAlertFailureControlError,
    CriticalAlertFailureControlReceipt,
    authenticate_total_delivery_failure_evidence,
)
from packages.domain.critical_alert import (
    MAX_CRITICAL_ALERT_SCAN_PAGE,
    CriticalAlertDeliveryAttempt,
    CriticalAlertDeliveryResult,
    CriticalAlertError,
    CriticalAlertIncident,
    CriticalAlertIncidentScanCursor,
    CriticalAlertIncidentScanPage,
    validate_critical_alert_delivery_history,
)
from packages.domain.operational_control import OperationalControlState

CRITICAL_ALERT_ATOMIC_WORKER_CONTRACT_VERSION = "phase5d-atomic-critical-alert-worker-v1"
DEFAULT_CRITICAL_ALERT_ATOMIC_WORKER_PAGE_LIMIT = 64


class CriticalAlertAtomicWorkerError(RuntimeError):
    """The local atomic worker cannot safely interpret its injected boundary."""


class CriticalAlertAtomicWorkerConflict(CriticalAlertAtomicWorkerError):
    """Injected identities or returned canonical facts conflict."""


class CriticalAlertAtomicWorkerUnavailableReason(StrEnum):
    """Allowlisted failure states that never expose boundary exception text."""

    TRUSTED_CLOCK_INVALID = "trusted_clock_invalid"
    DURABLE_SCAN_FAILED = "durable_scan_failed"
    DURABLE_SUPERVISION_FAILED = "durable_supervision_failed"
    ROUTE_ADAPTER_UNAVAILABLE = "route_adapter_unavailable"
    ROUTE_ADAPTER_RESOLUTION_FAILED = "route_adapter_resolution_failed"
    ROUTE_ADAPTER_INVALID = "route_adapter_invalid"
    FAILURE_CONTROL_BIND_FAILED = "failure_control_bind_failed"


class CriticalAlertAtomicWorkerUnavailable(CriticalAlertAtomicWorkerError):
    """One required local or provider boundary is unavailable."""

    def __init__(self, reason: CriticalAlertAtomicWorkerUnavailableReason) -> None:
        super().__init__(reason.value)
        self.reason_code = reason.value


class CriticalAlertAtomicWorkerRepository(
    CriticalAlertSupervisorRepository,
    Protocol,
):
    """One durable alert store used by both the scan and supervisor."""

    @property
    def runtime_store_identity(self) -> int: ...

    def scan_active_incidents(
        self,
        *,
        as_of: datetime,
        after: CriticalAlertIncidentScanCursor | None,
        limit: int,
    ) -> CriticalAlertIncidentScanPage: ...


class CriticalAlertAtomicRouteResolver(Protocol):
    """Resolve one approved opaque route binding without exposing credentials."""

    def resolve(
        self,
        incident: CriticalAlertIncident,
        binding: CriticalAlertRouteBinding,
    ) -> CriticalAlertDeliveryPort | None: ...


class CriticalAlertAtomicFailureControlBinder(Protocol):
    """Authority-owning atomic Phase 5D trip-and-receipt boundary."""

    @property
    def runtime_store_identity(self) -> int: ...

    @property
    def route_plan_sha256(self) -> str: ...

    @property
    def failure_control_policy_sha256(self) -> str: ...

    def bind(
        self,
        *,
        account_id: str,
        evidence: CriticalAlertSupervisorEvidence,
    ) -> CriticalAlertFailureControlReceipt: ...


class CriticalAlertAtomicWorkerIncidentState(StrEnum):
    """One bounded incident outcome from a single supervisor step."""

    CONFIRMED = "confirmed"
    PRIMARY_FAILED = "primary_failed"
    WAIT = "wait"
    TOTAL_FAILURE_AWAITING_REPLAY = "total_failure_awaiting_replay"
    CONTROL_BOUND = "control_bound"


@dataclass(frozen=True, slots=True)
class CriticalAlertAtomicWorkerIncidentRun:
    """Sanitized result for one active incident in the bounded scan page."""

    incident: CriticalAlertIncident
    state: CriticalAlertAtomicWorkerIncidentState
    supervision: CriticalAlertSupervisorEvidence
    failure_control_receipt: CriticalAlertFailureControlReceipt | None

    def __post_init__(self) -> None:
        if type(self.incident) is not CriticalAlertIncident:
            raise CriticalAlertAtomicWorkerError(
                "atomic critical-alert incident run requires an exact incident"
            )
        if type(self.state) is not CriticalAlertAtomicWorkerIncidentState:
            raise CriticalAlertAtomicWorkerError(
                "atomic critical-alert incident run requires an exact state"
            )
        if type(self.supervision) is not CriticalAlertSupervisorEvidence:
            raise CriticalAlertAtomicWorkerError(
                "atomic critical-alert incident run requires exact supervisor evidence"
            )
        try:
            self.incident.__post_init__()
            self.supervision.__post_init__()
        except Exception:
            raise CriticalAlertAtomicWorkerConflict(
                "atomic critical-alert incident run contains inauthentic source facts"
            ) from None
        if (
            self.supervision.incident_id != self.incident.incident_id
            or self.supervision.incident_sha256 != self.incident.semantic_sha256
        ):
            raise CriticalAlertAtomicWorkerConflict(
                "atomic critical-alert incident run crosses incident identity"
            )
        expected_disposition = {
            CriticalAlertAtomicWorkerIncidentState.CONFIRMED: (
                CriticalAlertSupervisorDisposition.CONFIRMED
            ),
            CriticalAlertAtomicWorkerIncidentState.PRIMARY_FAILED: (
                CriticalAlertSupervisorDisposition.PRIMARY_FAILED
            ),
            CriticalAlertAtomicWorkerIncidentState.WAIT: (CriticalAlertSupervisorDisposition.WAIT),
            CriticalAlertAtomicWorkerIncidentState.TOTAL_FAILURE_AWAITING_REPLAY: (
                CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE
            ),
            CriticalAlertAtomicWorkerIncidentState.CONTROL_BOUND: (
                CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE
            ),
        }[self.state]
        if self.supervision.disposition is not expected_disposition:
            raise CriticalAlertAtomicWorkerConflict(
                "atomic critical-alert incident state conflicts with supervision"
            )
        if self.state is CriticalAlertAtomicWorkerIncidentState.CONTROL_BOUND:
            if type(self.failure_control_receipt) is not CriticalAlertFailureControlReceipt:
                raise CriticalAlertAtomicWorkerConflict(
                    "bound atomic critical-alert run requires an exact receipt"
                )
            try:
                self.failure_control_receipt.__post_init__()
            except Exception:
                raise CriticalAlertAtomicWorkerConflict(
                    "atomic critical-alert failure-control receipt is inauthentic"
                ) from None
            if (
                self.supervision.disposition
                is not CriticalAlertSupervisorDisposition.TOTAL_DELIVERY_FAILURE
                or self.supervision.provider_called
                or self.failure_control_receipt.incident != self.incident
                or self.failure_control_receipt.evidence != self.supervision
            ):
                raise CriticalAlertAtomicWorkerConflict(
                    "atomic critical-alert receipt is not exactly replay-bound"
                )
        elif self.failure_control_receipt is not None:
            raise CriticalAlertAtomicWorkerConflict(
                "non-bound atomic critical-alert run cannot retain a control receipt"
            )

    @property
    def requested_control_state(self) -> OperationalControlState | None:
        if self.failure_control_receipt is None:
            return None
        return self.failure_control_receipt.requested_control_state

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


@dataclass(frozen=True, slots=True)
class CriticalAlertAtomicWorkerRun:
    """One bounded active-incident page and its single-step outcomes."""

    scanned_as_of: datetime
    scanned_count: int
    incident_runs: tuple[CriticalAlertAtomicWorkerIncidentRun, ...]
    resume_after: CriticalAlertIncidentScanCursor | None

    def __post_init__(self) -> None:
        _require_utc(self.scanned_as_of, "atomic critical-alert scan instant")
        if (
            type(self.scanned_count) is not int
            or not 0 <= self.scanned_count <= MAX_CRITICAL_ALERT_SCAN_PAGE
        ):
            raise CriticalAlertAtomicWorkerError(
                "atomic critical-alert scanned count exceeds its bound"
            )
        if type(self.incident_runs) is not tuple or len(self.incident_runs) > self.scanned_count:
            raise CriticalAlertAtomicWorkerError(
                "atomic critical-alert incident runs exceed the scanned count"
            )
        if any(
            type(value) is not CriticalAlertAtomicWorkerIncidentRun for value in self.incident_runs
        ):
            raise CriticalAlertAtomicWorkerError(
                "atomic critical-alert run contains a noncanonical incident result"
            )
        if (
            self.resume_after is not None
            and type(self.resume_after) is not CriticalAlertIncidentScanCursor
        ):
            raise CriticalAlertAtomicWorkerError(
                "atomic critical-alert run contains a noncanonical resume cursor"
            )

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


def _require_utc(value: datetime, field_name: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise CriticalAlertAtomicWorkerError(f"{field_name} must be UTC")
    return value


def _read_utc(clock: UtcClock) -> datetime:
    try:
        value = clock()
    except Exception:
        raise CriticalAlertAtomicWorkerUnavailable(
            CriticalAlertAtomicWorkerUnavailableReason.TRUSTED_CLOCK_INVALID
        ) from None
    try:
        return _require_utc(value, "atomic critical-alert trusted clock instant")
    except CriticalAlertAtomicWorkerError:
        raise CriticalAlertAtomicWorkerUnavailable(
            CriticalAlertAtomicWorkerUnavailableReason.TRUSTED_CLOCK_INVALID
        ) from None


@dataclass(slots=True)
class _NondecreasingUtcClock:
    delegate: UtcClock
    last: datetime

    def __call__(self) -> datetime:
        value = _read_utc(self.delegate)
        if value < self.last:
            raise CriticalAlertAtomicWorkerUnavailable(
                CriticalAlertAtomicWorkerUnavailableReason.TRUSTED_CLOCK_INVALID
            )
        self.last = value
        return value


def _runtime_store_identity(value: object, field_name: str) -> int:
    try:
        identity = value.runtime_store_identity  # type: ignore[attr-defined]
    except Exception:
        raise CriticalAlertAtomicWorkerConflict(
            f"{field_name} runtime-store identity is unavailable"
        ) from None
    if type(identity) is not int or identity <= 0:
        raise CriticalAlertAtomicWorkerConflict(
            f"{field_name} runtime-store identity must be a positive exact integer"
        )
    return identity


def _require_callable(value: object, method_name: str, field_name: str) -> None:
    try:
        capability = getattr(value, method_name, None)
    except Exception:
        raise CriticalAlertAtomicWorkerConflict(f"{field_name} capability is unavailable") from None
    if not callable(capability):
        raise CriticalAlertAtomicWorkerConflict(f"{field_name} capability is unavailable")


def _preflight(
    *,
    repository: object,
    route_plan: CriticalAlertRoutePlan,
    route_resolver: object,
    failure_control: object,
    utc_clock: object,
    monotonic_clock: object,
) -> None:
    repository_identity = _runtime_store_identity(
        repository,
        "critical-alert repository",
    )
    control_identity = _runtime_store_identity(
        failure_control,
        "critical-alert atomic failure control",
    )
    if repository_identity != control_identity:
        raise CriticalAlertAtomicWorkerConflict(
            "critical-alert scan and failure control do not share one process-local store"
        )
    try:
        binder_route_plan_sha256 = failure_control.route_plan_sha256  # type: ignore[attr-defined]
        binder_policy_sha256 = failure_control.failure_control_policy_sha256  # type: ignore[attr-defined]
    except Exception:
        raise CriticalAlertAtomicWorkerConflict(
            "critical-alert atomic failure-control identity is unavailable"
        ) from None
    if binder_route_plan_sha256 != route_plan.semantic_sha256:
        raise CriticalAlertAtomicWorkerConflict(
            "critical-alert atomic failure control uses another route plan"
        )
    if binder_policy_sha256 != CRITICAL_ALERT_FAILURE_CONTROL_POLICY_SHA256:
        raise CriticalAlertAtomicWorkerConflict(
            "critical-alert atomic failure control uses another control policy"
        )
    for value, method_name, field_name in (
        (repository, "scan_active_incidents", "critical-alert active scan"),
        (repository, "load_incident", "critical-alert incident loader"),
        (repository, "find_delivery_attempt", "critical-alert attempt lookup"),
        (repository, "claim_delivery_attempt", "critical-alert attempt claim"),
        (repository, "load_delivery_result", "critical-alert result loader"),
        (repository, "load_delivery_history", "critical-alert history loader"),
        (repository, "record_delivery_result", "critical-alert result recorder"),
        (route_resolver, "resolve", "critical-alert route resolver"),
        (failure_control, "bind", "critical-alert atomic failure control"),
    ):
        _require_callable(value, method_name, field_name)
    if not callable(utc_clock):
        raise CriticalAlertAtomicWorkerConflict(
            "atomic critical-alert worker requires an injected trusted UTC clock"
        )
    if not callable(monotonic_clock):
        raise CriticalAlertAtomicWorkerConflict(
            "atomic critical-alert worker requires an injected monotonic clock"
        )


@dataclass(frozen=True, slots=True)
class _LazyResolvedDeliveryPort:
    incident: CriticalAlertIncident
    binding: CriticalAlertRouteBinding
    resolver: CriticalAlertAtomicRouteResolver

    @property
    def provider_id(self) -> str:
        return self.binding.provider_id

    def deliver(
        self,
        request: CriticalAlertProviderRequest,
        *,
        timeout_seconds: float,
    ) -> CriticalAlertProviderReceipt:
        try:
            raw_port = self.resolver.resolve(self.incident, self.binding)
        except Exception:
            raise CriticalAlertDeliveryUnavailable(
                CriticalAlertAtomicWorkerUnavailableReason.ROUTE_ADAPTER_RESOLUTION_FAILED.value
            ) from None
        if raw_port is None:
            raise CriticalAlertDeliveryUnavailable(
                CriticalAlertAtomicWorkerUnavailableReason.ROUTE_ADAPTER_UNAVAILABLE.value
            )
        try:
            provider_id = raw_port.provider_id
            deliver = raw_port.deliver
        except Exception:
            raise CriticalAlertDeliveryUnavailable(
                CriticalAlertAtomicWorkerUnavailableReason.ROUTE_ADAPTER_INVALID.value
            ) from None
        if provider_id != self.binding.provider_id or not callable(deliver):
            raise CriticalAlertDeliveryUnavailable(
                CriticalAlertAtomicWorkerUnavailableReason.ROUTE_ADAPTER_INVALID.value
            )
        return deliver(request, timeout_seconds=timeout_seconds)


def _authenticated_history(
    *,
    repository: CriticalAlertAtomicWorkerRepository,
    incident: CriticalAlertIncident,
    route_plan: CriticalAlertRoutePlan,
) -> tuple[
    tuple[CriticalAlertDeliveryAttempt, ...],
    tuple[CriticalAlertDeliveryResult, ...],
]:
    try:
        retained = repository.load_incident(incident.incident_id)
        if retained != incident:
            raise CriticalAlertAtomicWorkerConflict(
                "critical-alert scan incident conflicts with durable readback"
            )
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
    except CriticalAlertAtomicWorkerConflict:
        raise
    except CriticalAlertError:
        raise CriticalAlertAtomicWorkerConflict(
            "critical-alert durable history is inauthentic"
        ) from None
    return attempts, results


def _unavailable_from_delivery(
    error: CriticalAlertDeliveryUnavailable,
) -> CriticalAlertAtomicWorkerUnavailable:
    allowed = {
        reason.value: reason
        for reason in (
            CriticalAlertAtomicWorkerUnavailableReason.ROUTE_ADAPTER_UNAVAILABLE,
            CriticalAlertAtomicWorkerUnavailableReason.ROUTE_ADAPTER_RESOLUTION_FAILED,
            CriticalAlertAtomicWorkerUnavailableReason.ROUTE_ADAPTER_INVALID,
        )
    }
    reason = allowed.get(
        error.reason_code,
        CriticalAlertAtomicWorkerUnavailableReason.DURABLE_SUPERVISION_FAILED,
    )
    return CriticalAlertAtomicWorkerUnavailable(reason)


def _canonical_total_failure_evidence(
    *,
    incident: CriticalAlertIncident,
    route_plan: CriticalAlertRoutePlan,
    attempts: tuple[CriticalAlertDeliveryAttempt, ...],
    results: tuple[CriticalAlertDeliveryResult, ...],
    supervision: CriticalAlertSupervisorEvidence,
) -> CriticalAlertSupervisorEvidence | None:
    latest_history_time = max(
        (
            incident.recorded_at,
            *(attempt.claimed_at for attempt in attempts),
            *(result.completed_at for result in results),
        )
    )
    eligible_at = (
        max(incident.escalation_deadline, latest_history_time)
        if supervision.reason is CriticalAlertSupervisorReason.ESCALATION_DEADLINE_UNRESOLVED
        else latest_history_time
    )
    if supervision.provider_called or supervision.observed_at < eligible_at:
        return None
    canonical = replace(
        supervision,
        observed_at=eligible_at,
        wait_until=None,
        provider_called=False,
    )
    authenticate_total_delivery_failure_evidence(
        incident=incident,
        route_plan=route_plan,
        attempts=attempts,
        results=results,
        evidence=canonical,
    )
    return canonical


def _run_incident(
    *,
    incident: CriticalAlertIncident,
    repository: CriticalAlertAtomicWorkerRepository,
    route_plan: CriticalAlertRoutePlan,
    route_resolver: CriticalAlertAtomicRouteResolver,
    failure_control: CriticalAlertAtomicFailureControlBinder,
    utc_clock: _NondecreasingUtcClock,
    monotonic_clock: MonotonicClock,
) -> CriticalAlertAtomicWorkerIncidentRun:
    try:
        _authenticated_history(
            repository=repository,
            incident=incident,
            route_plan=route_plan,
        )
        supervision = CriticalAlertDeliverySupervisor(
            repository=repository,
            route_plan=route_plan,
            primary_port=_LazyResolvedDeliveryPort(
                incident=incident,
                binding=route_plan.primary,
                resolver=route_resolver,
            ),
            escalation_port=_LazyResolvedDeliveryPort(
                incident=incident,
                binding=route_plan.escalation,
                resolver=route_resolver,
            ),
            utc_clock=utc_clock,
            monotonic_clock=monotonic_clock,
        ).run_once(incident.incident_id)
    except CriticalAlertAtomicWorkerUnavailable:
        raise
    except CriticalAlertAtomicWorkerConflict:
        raise
    except CriticalAlertDeliveryUnavailable as error:
        raise _unavailable_from_delivery(error) from None
    except (CriticalAlertError, CriticalAlertFailureControlError):
        raise CriticalAlertAtomicWorkerConflict(
            "critical-alert durable history conflicts with supervision"
        ) from None
    except Exception:
        raise CriticalAlertAtomicWorkerUnavailable(
            CriticalAlertAtomicWorkerUnavailableReason.DURABLE_SUPERVISION_FAILED
        ) from None

    if supervision.disposition is CriticalAlertSupervisorDisposition.CONFIRMED:
        return CriticalAlertAtomicWorkerIncidentRun(
            incident=incident,
            state=CriticalAlertAtomicWorkerIncidentState.CONFIRMED,
            supervision=supervision,
            failure_control_receipt=None,
        )
    if supervision.disposition is CriticalAlertSupervisorDisposition.PRIMARY_FAILED:
        return CriticalAlertAtomicWorkerIncidentRun(
            incident=incident,
            state=CriticalAlertAtomicWorkerIncidentState.PRIMARY_FAILED,
            supervision=supervision,
            failure_control_receipt=None,
        )
    if supervision.disposition is CriticalAlertSupervisorDisposition.WAIT:
        return CriticalAlertAtomicWorkerIncidentRun(
            incident=incident,
            state=CriticalAlertAtomicWorkerIncidentState.WAIT,
            supervision=supervision,
            failure_control_receipt=None,
        )

    try:
        attempts, results = _authenticated_history(
            repository=repository,
            incident=incident,
            route_plan=route_plan,
        )
        canonical = _canonical_total_failure_evidence(
            incident=incident,
            route_plan=route_plan,
            attempts=attempts,
            results=results,
            supervision=supervision,
        )
    except CriticalAlertAtomicWorkerConflict:
        raise
    except (CriticalAlertError, CriticalAlertFailureControlError):
        raise CriticalAlertAtomicWorkerConflict(
            "critical-alert total-failure history conflicts with supervision"
        ) from None
    except Exception:
        raise CriticalAlertAtomicWorkerUnavailable(
            CriticalAlertAtomicWorkerUnavailableReason.DURABLE_SUPERVISION_FAILED
        ) from None
    if canonical is None:
        return CriticalAlertAtomicWorkerIncidentRun(
            incident=incident,
            state=CriticalAlertAtomicWorkerIncidentState.TOTAL_FAILURE_AWAITING_REPLAY,
            supervision=supervision,
            failure_control_receipt=None,
        )
    try:
        receipt = failure_control.bind(
            account_id=incident.scope_id,
            evidence=canonical,
        )
    except Exception:
        raise CriticalAlertAtomicWorkerUnavailable(
            CriticalAlertAtomicWorkerUnavailableReason.FAILURE_CONTROL_BIND_FAILED
        ) from None
    if type(receipt) is not CriticalAlertFailureControlReceipt:
        raise CriticalAlertAtomicWorkerConflict(
            "critical-alert atomic failure control returned a noncanonical receipt"
        )
    try:
        receipt.__post_init__()
    except Exception:
        raise CriticalAlertAtomicWorkerConflict(
            "critical-alert atomic failure control returned an inauthentic receipt"
        ) from None
    if (
        receipt.incident != incident
        or receipt.route_plan != route_plan
        or receipt.evidence != canonical
    ):
        raise CriticalAlertAtomicWorkerConflict(
            "critical-alert atomic failure-control receipt crosses source identity"
        )
    return CriticalAlertAtomicWorkerIncidentRun(
        incident=incident,
        state=CriticalAlertAtomicWorkerIncidentState.CONTROL_BOUND,
        supervision=canonical,
        failure_control_receipt=receipt,
    )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def run_critical_alert_atomic_worker_once(
    *,
    repository: CriticalAlertAtomicWorkerRepository,
    route_plan: CriticalAlertRoutePlan,
    route_resolver: CriticalAlertAtomicRouteResolver,
    failure_control: CriticalAlertAtomicFailureControlBinder,
    after: CriticalAlertIncidentScanCursor | None = None,
    limit: int = DEFAULT_CRITICAL_ALERT_ATOMIC_WORKER_PAGE_LIMIT,
    utc_clock: UtcClock = _utc_now,
    monotonic_clock: MonotonicClock = time.monotonic,
) -> CriticalAlertAtomicWorkerRun:
    """Process one bounded page and atomically bind replay-derived total failures."""

    if type(route_plan) is not CriticalAlertRoutePlan:
        raise CriticalAlertAtomicWorkerError(
            "atomic critical-alert worker requires an exact injected route plan"
        )
    try:
        route_plan.__post_init__()
    except Exception:
        raise CriticalAlertAtomicWorkerConflict(
            "atomic critical-alert worker route plan is invalid"
        ) from None
    if after is not None and type(after) is not CriticalAlertIncidentScanCursor:
        raise CriticalAlertAtomicWorkerError(
            "atomic critical-alert worker scan cursor must be exact"
        )
    if type(limit) is not int or not 1 <= limit <= MAX_CRITICAL_ALERT_SCAN_PAGE:
        raise CriticalAlertAtomicWorkerError(
            "atomic critical-alert worker page limit exceeds its bounded range"
        )
    _preflight(
        repository=repository,
        route_plan=route_plan,
        route_resolver=route_resolver,
        failure_control=failure_control,
        utc_clock=utc_clock,
        monotonic_clock=monotonic_clock,
    )

    scanned_as_of = _read_utc(utc_clock)
    try:
        page = repository.scan_active_incidents(
            as_of=scanned_as_of,
            after=after,
            limit=limit,
        )
    except Exception:
        raise CriticalAlertAtomicWorkerUnavailable(
            CriticalAlertAtomicWorkerUnavailableReason.DURABLE_SCAN_FAILED
        ) from None
    if type(page) is not CriticalAlertIncidentScanPage:
        raise CriticalAlertAtomicWorkerConflict(
            "critical-alert repository returned a noncanonical active scan page"
        )
    try:
        page.__post_init__()
    except Exception:
        raise CriticalAlertAtomicWorkerConflict(
            "critical-alert repository returned an invalid active scan page"
        ) from None
    if page.scanned_count > limit:
        raise CriticalAlertAtomicWorkerConflict(
            "critical-alert repository exceeded the requested scan bound"
        )
    if any(
        incident.recorded_at > scanned_as_of
        or (after is not None and (incident.recorded_at, incident.incident_id) <= after.sort_key)
        for incident in page.incidents
    ):
        raise CriticalAlertAtomicWorkerConflict(
            "critical-alert repository returned an out-of-window active incident"
        )
    if page.resume_after is not None and (
        page.resume_after.recorded_at > scanned_as_of
        or (after is not None and page.resume_after.sort_key <= after.sort_key)
    ):
        raise CriticalAlertAtomicWorkerConflict(
            "critical-alert repository returned a nonadvancing scan cursor"
        )

    supervisor_clock = _NondecreasingUtcClock(
        delegate=utc_clock,
        last=scanned_as_of,
    )
    incident_runs = tuple(
        _run_incident(
            incident=incident,
            repository=repository,
            route_plan=route_plan,
            route_resolver=route_resolver,
            failure_control=failure_control,
            utc_clock=supervisor_clock,
            monotonic_clock=monotonic_clock,
        )
        for incident in page.incidents
    )
    return CriticalAlertAtomicWorkerRun(
        scanned_as_of=scanned_as_of,
        scanned_count=page.scanned_count,
        incident_runs=incident_runs,
        resume_after=page.resume_after,
    )


__all__ = [
    "CRITICAL_ALERT_ATOMIC_WORKER_CONTRACT_VERSION",
    "DEFAULT_CRITICAL_ALERT_ATOMIC_WORKER_PAGE_LIMIT",
    "CriticalAlertAtomicFailureControlBinder",
    "CriticalAlertAtomicRouteResolver",
    "CriticalAlertAtomicWorkerConflict",
    "CriticalAlertAtomicWorkerError",
    "CriticalAlertAtomicWorkerIncidentRun",
    "CriticalAlertAtomicWorkerIncidentState",
    "CriticalAlertAtomicWorkerRepository",
    "CriticalAlertAtomicWorkerRun",
    "CriticalAlertAtomicWorkerUnavailable",
    "CriticalAlertAtomicWorkerUnavailableReason",
    "run_critical_alert_atomic_worker_once",
]
