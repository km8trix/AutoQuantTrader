from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from packages.application.critical_alert_atomic_worker import (
    CriticalAlertAtomicWorkerConflict,
    CriticalAlertAtomicWorkerIncidentState,
    CriticalAlertAtomicWorkerUnavailable,
    run_critical_alert_atomic_worker_once,
)
from packages.application.critical_alert_delivery import (
    CriticalAlertProviderReceipt,
    CriticalAlertProviderRequest,
)
from packages.application.critical_alert_supervisor import (
    CriticalAlertRouteBinding,
    CriticalAlertRoutePlan,
    CriticalAlertSupervisorEvidence,
    critical_alert_route_idempotency_key,
)
from packages.application.critical_alert_supervisor_failure_control import (
    CRITICAL_ALERT_FAILURE_CONTROL_POLICY_SHA256,
    CriticalAlertFailureControlConflict,
    CriticalAlertFailureControlReceipt,
    bind_critical_alert_failure_control_receipt,
)
from packages.domain.critical_alert import (
    CriticalAlertConflict,
    CriticalAlertDeliveryAttempt,
    CriticalAlertDeliveryCommand,
    CriticalAlertDeliveryOutcome,
    CriticalAlertDeliveryResult,
    CriticalAlertIncident,
    CriticalAlertIncidentScanCursor,
    CriticalAlertIncidentScanPage,
    CriticalAlertRoute,
    append_critical_alert_delivery_attempt,
    critical_alert_delivery_milestone_met,
    record_critical_alert_delivery_result,
    validate_critical_alert_delivery_history,
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


def _plan(version: str = "1") -> CriticalAlertRoutePlan:
    return CriticalAlertRoutePlan(
        plan_id="paper-critical-alerts",
        plan_version=version,
        primary=CriticalAlertRouteBinding(
            route=CriticalAlertRoute.PRIMARY,
            provider_id="primary-pager",
            destination_sha256="1" * 64,
            recipient_set_sha256="2" * 64,
        ),
        escalation=CriticalAlertRouteBinding(
            route=CriticalAlertRoute.ESCALATION,
            provider_id="fallback-sms",
            destination_sha256="3" * 64,
            recipient_set_sha256="4" * 64,
        ),
    )


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
        failure_code=None if outcome is CriticalAlertDeliveryOutcome.CONFIRMED else "failure",
    )


def _halted(scope_id: str) -> OperationalControlTransition:
    decided_at = BASE - timedelta(minutes=1)
    return apply_operational_control_command(
        None,
        OperationalControlCommand(
            scope_id=scope_id,
            idempotency_key="initialize-control",
            kind=OperationalControlCommandKind.INITIALIZE_HALTED,
            target_state=OperationalControlState.HALTED,
            actor=OperationalControlActor(
                actor_id="bootstrap",
                kind=OperationalControlActorKind.SYSTEM,
                authority_sha256="5" * 64,
                authenticated_at=None,
            ),
            reason_code="bootstrap",
            reason_evidence_sha256="6" * 64,
            requested_at=decided_at,
        ),
        decided_at=decided_at,
    )


@dataclass(slots=True)
class MemoryAlertRepository:
    incidents: tuple[CriticalAlertIncident, ...]
    identity: object = 1
    events: list[str] = field(default_factory=list)
    attempts: dict[str, list[CriticalAlertDeliveryAttempt]] = field(default_factory=dict)
    results: dict[str, CriticalAlertDeliveryResult] = field(default_factory=dict)
    scan_failure: bool = False
    force_active: bool = False

    def __post_init__(self) -> None:
        self.attempts = {
            incident.incident_id: list(self.attempts.get(incident.incident_id, ()))
            for incident in self.incidents
        }

    @property
    def runtime_store_identity(self) -> Any:
        self.events.append("repository.identity")
        return self.identity

    def load_incident(self, incident_id: str) -> CriticalAlertIncident:
        self.events.append("repository.load_incident")
        return next(incident for incident in self.incidents if incident.incident_id == incident_id)

    def scan_active_incidents(
        self,
        *,
        as_of: datetime,
        after: CriticalAlertIncidentScanCursor | None,
        limit: int,
    ) -> CriticalAlertIncidentScanPage:
        self.events.append("repository.scan")
        if self.scan_failure:
            raise RuntimeError("secret scan failure")
        candidates = tuple(
            incident
            for incident in sorted(
                self.incidents,
                key=lambda item: (item.recorded_at, item.incident_id),
            )
            if incident.recorded_at <= as_of
            and (after is None or (incident.recorded_at, incident.incident_id) > after.sort_key)
        )
        segment = candidates[:limit]
        active: list[CriticalAlertIncident] = []
        for incident in segment:
            attempts, results = self.load_delivery_history(incident.incident_id)
            results_by_attempt = {result.attempt_id: result for result in results}
            delivered = any(
                critical_alert_delivery_milestone_met(
                    incident=incident,
                    attempt=attempt,
                    result=result,
                )
                for attempt in attempts
                if (result := results_by_attempt.get(attempt.attempt_id)) is not None
            )
            if self.force_active or not delivered:
                active.append(incident)
        resume_after = None
        if len(candidates) > limit:
            last = segment[-1]
            resume_after = CriticalAlertIncidentScanCursor(
                recorded_at=last.recorded_at,
                incident_id=last.incident_id,
            )
        return CriticalAlertIncidentScanPage(
            incidents=tuple(active),
            scanned_count=len(segment),
            resume_after=resume_after,
        )

    def find_delivery_attempt(
        self,
        *,
        incident_id: str,
        provider_id: str,
        idempotency_key: str,
    ) -> CriticalAlertDeliveryAttempt | None:
        self.events.append("repository.find_attempt")
        return next(
            (
                attempt
                for attempt in self.attempts[incident_id]
                if attempt.provider_id == provider_id and attempt.idempotency_key == idempotency_key
            ),
            None,
        )

    def claim_delivery_attempt(
        self,
        command: CriticalAlertDeliveryCommand,
    ) -> tuple[CriticalAlertDeliveryAttempt, bool]:
        self.events.append("repository.claim_attempt")
        existing = self.find_delivery_attempt(
            incident_id=command.incident_id,
            provider_id=command.provider_id,
            idempotency_key=command.idempotency_key,
        )
        if existing is not None:
            return existing, False
        incident = next(item for item in self.incidents if item.incident_id == command.incident_id)
        previous = (
            self.attempts[command.incident_id][-1] if self.attempts[command.incident_id] else None
        )
        attempt = append_critical_alert_delivery_attempt(
            incident=incident,
            command=command,
            claimed_at=command.requested_at,
            previous=previous,
        )
        self.attempts[command.incident_id].append(attempt)
        return attempt, True

    def load_delivery_result(
        self,
        attempt_id: str,
    ) -> CriticalAlertDeliveryResult | None:
        self.events.append("repository.load_result")
        return self.results.get(attempt_id)

    def load_delivery_history(
        self,
        incident_id: str,
    ) -> tuple[
        tuple[CriticalAlertDeliveryAttempt, ...],
        tuple[CriticalAlertDeliveryResult, ...],
    ]:
        self.events.append("repository.load_history")
        incident = next(item for item in self.incidents if item.incident_id == incident_id)
        attempts = tuple(self.attempts[incident_id])
        results = tuple(
            self.results[attempt.attempt_id]
            for attempt in attempts
            if attempt.attempt_id in self.results
        )
        validate_critical_alert_delivery_history(
            incident=incident,
            attempts=attempts,
            results=results,
        )
        return attempts, results

    def record_delivery_result(
        self,
        result: CriticalAlertDeliveryResult,
    ) -> CriticalAlertDeliveryResult:
        self.events.append("repository.record_result")
        existing = self.results.get(result.attempt_id)
        if existing is not None and existing != result:
            raise CriticalAlertConflict("delivery result conflicts")
        self.results[result.attempt_id] = result
        return result


@dataclass(slots=True)
class MemoryFailureControl:
    repository: MemoryAlertRepository
    plan: CriticalAlertRoutePlan
    identity: object = 1
    events: list[str] = field(default_factory=list)
    fail: bool = False
    route_plan_override: str | None = None
    policy_override: str | None = None
    calls: list[tuple[str, CriticalAlertSupervisorEvidence]] = field(default_factory=list)
    receipt: CriticalAlertFailureControlReceipt | None = None

    @property
    def runtime_store_identity(self) -> Any:
        self.events.append("control.identity")
        return self.identity

    @property
    def route_plan_sha256(self) -> str:
        self.events.append("control.route_plan")
        return self.route_plan_override or self.plan.semantic_sha256

    @property
    def failure_control_policy_sha256(self) -> str:
        self.events.append("control.policy")
        return self.policy_override or CRITICAL_ALERT_FAILURE_CONTROL_POLICY_SHA256

    def bind(
        self,
        *,
        account_id: str,
        evidence: CriticalAlertSupervisorEvidence,
    ) -> CriticalAlertFailureControlReceipt:
        self.events.append("control.bind")
        self.calls.append((account_id, evidence))
        if self.fail:
            raise RuntimeError("secret authority detail")
        if self.receipt is not None:
            if self.receipt.evidence != evidence:
                raise CriticalAlertFailureControlConflict("retry evidence conflicts")
            return self.receipt
        incident = next(
            value
            for value in self.repository.incidents
            if value.incident_id == evidence.incident_id
        )
        attempts, results = self.repository.load_delivery_history(incident.incident_id)
        self.receipt = bind_critical_alert_failure_control_receipt(
            incident=incident,
            route_plan=self.plan,
            attempts=attempts,
            results=results,
            evidence=evidence,
            pre_control=_halted(incident.scope_id),
            actor_authority_sha256=AUTHORITY_SHA256,
            bound_at=evidence.observed_at,
        )
        return self.receipt


@dataclass(slots=True)
class FakePort:
    provider_id: str
    behavior: str = "confirmed"
    calls: list[CriticalAlertProviderRequest] = field(default_factory=list)

    def deliver(
        self,
        request: CriticalAlertProviderRequest,
        *,
        timeout_seconds: float,
    ) -> CriticalAlertProviderReceipt:
        assert timeout_seconds > 0
        self.calls.append(request)
        if self.behavior == "error":
            raise RuntimeError("secret provider detail")
        if self.behavior == "timeout":
            raise TimeoutError("secret provider detail")
        return CriticalAlertProviderReceipt(provider_receipt_sha256="7" * 64)


@dataclass(slots=True)
class FakeResolver:
    ports: dict[CriticalAlertRoute, FakePort]
    events: list[str] = field(default_factory=list)
    fail: bool = False

    def resolve(
        self,
        incident: CriticalAlertIncident,
        binding: CriticalAlertRouteBinding,
    ) -> FakePort | None:
        self.events.append(f"resolver.{binding.route.value}")
        assert incident.scope_id == "paper-account-1"
        if self.fail:
            raise RuntimeError("secret resolver detail")
        return self.ports.get(binding.route)


@dataclass(slots=True)
class SequenceClock:
    values: list[datetime]
    events: list[str] = field(default_factory=list)
    index: int = 0

    def __call__(self) -> datetime:
        self.events.append("clock")
        value = self.values[min(self.index, len(self.values) - 1)]
        self.index += 1
        return value


@dataclass(slots=True)
class StepMonotonic:
    value: float = 0.0

    def __call__(self) -> float:
        current = self.value
        self.value += 0.01
        return current


def _terminal_repository(
    outcome: CriticalAlertDeliveryOutcome | None,
    *,
    completed_at: datetime | None = None,
) -> tuple[
    MemoryAlertRepository,
    CriticalAlertIncident,
    CriticalAlertRoutePlan,
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
    attempts = {incident.incident_id: [primary, escalation]}
    results = {primary.attempt_id: primary_result}
    if outcome is not None:
        terminal = _result(
            incident,
            escalation,
            outcome,
            completed_at or incident.primary_deadline + timedelta(seconds=1),
        )
        results[escalation.attempt_id] = terminal
    return (
        MemoryAlertRepository(
            incidents=(incident,),
            attempts=attempts,
            results=results,
        ),
        incident,
        plan,
    )


def _run(
    repository: MemoryAlertRepository,
    plan: CriticalAlertRoutePlan,
    control: MemoryFailureControl,
    *,
    instant: datetime,
    resolver: FakeResolver | None = None,
) -> Any:
    return run_critical_alert_atomic_worker_once(
        repository=repository,
        route_plan=plan,
        route_resolver=resolver or FakeResolver({}),
        failure_control=control,
        utc_clock=SequenceClock([instant]),
        monotonic_clock=StepMonotonic(),
    )


def test_split_store_fails_before_clock_scan_resolution_or_control_effect() -> None:
    repository, _, plan = _terminal_repository(None)
    repository.identity = 1
    control = MemoryFailureControl(repository, plan, identity=2)
    resolver = FakeResolver({})
    clock = SequenceClock([BASE])

    with pytest.raises(CriticalAlertAtomicWorkerConflict, match="one process-local store"):
        run_critical_alert_atomic_worker_once(
            repository=repository,
            route_plan=plan,
            route_resolver=resolver,
            failure_control=control,
            utc_clock=clock,
            monotonic_clock=StepMonotonic(),
        )

    assert repository.events == ["repository.identity"]
    assert control.events == ["control.identity"]
    assert clock.events == []
    assert resolver.events == []
    assert control.calls == []


@pytest.mark.parametrize("invalid", [0, -1, True, "1", None])
def test_invalid_store_identity_fails_before_clock_scan_or_effect(invalid: object) -> None:
    repository, _, plan = _terminal_repository(None)
    repository.identity = invalid
    control = MemoryFailureControl(repository, plan)
    clock = SequenceClock([BASE])

    with pytest.raises(CriticalAlertAtomicWorkerConflict, match="positive exact integer"):
        run_critical_alert_atomic_worker_once(
            repository=repository,
            route_plan=plan,
            route_resolver=FakeResolver({}),
            failure_control=control,
            utc_clock=clock,
            monotonic_clock=StepMonotonic(),
        )

    assert repository.events == ["repository.identity"]
    assert control.events == []
    assert clock.events == []


def test_absent_store_identity_fails_before_clock_scan_or_effect() -> None:
    repository, _, plan = _terminal_repository(None)
    control = MemoryFailureControl(repository, plan)
    clock = SequenceClock([BASE])

    class MissingIdentity:
        def __getattr__(self, name: str) -> Any:
            if name == "runtime_store_identity":
                raise AttributeError(name)
            return getattr(repository, name)

    with pytest.raises(CriticalAlertAtomicWorkerConflict, match="identity is unavailable"):
        run_critical_alert_atomic_worker_once(
            repository=MissingIdentity(),  # type: ignore[arg-type]
            route_plan=plan,
            route_resolver=FakeResolver({}),
            failure_control=control,
            utc_clock=clock,
            monotonic_clock=StepMonotonic(),
        )
    assert clock.events == []
    assert "repository.scan" not in repository.events


@pytest.mark.parametrize(
    ("route_override", "policy_override", "message"),
    [
        ("8" * 64, None, "another route plan"),
        (None, "8" * 64, "another control policy"),
    ],
)
def test_atomic_binder_identity_must_match_before_clock_or_scan(
    route_override: str | None,
    policy_override: str | None,
    message: str,
) -> None:
    repository, _, plan = _terminal_repository(None)
    control = MemoryFailureControl(
        repository,
        plan,
        route_plan_override=route_override,
        policy_override=policy_override,
    )
    clock = SequenceClock([BASE])
    with pytest.raises(CriticalAlertAtomicWorkerConflict, match=message):
        run_critical_alert_atomic_worker_once(
            repository=repository,
            route_plan=plan,
            route_resolver=FakeResolver({}),
            failure_control=control,
            utc_clock=clock,
            monotonic_clock=StepMonotonic(),
        )
    assert clock.events == []
    assert "repository.scan" not in repository.events
    assert control.calls == []


def test_unresolved_total_failure_binds_canonical_evidence_and_exact_retry() -> None:
    repository, incident, plan = _terminal_repository(None)
    control = MemoryFailureControl(repository, plan)
    first = _run(
        repository,
        plan,
        control,
        instant=incident.escalation_deadline + timedelta(seconds=10),
    )
    first_incident = first.incident_runs[0]
    assert first_incident.state is CriticalAlertAtomicWorkerIncidentState.CONTROL_BOUND
    assert first_incident.supervision.observed_at == incident.escalation_deadline
    assert first_incident.supervision.provider_called is False
    assert first_incident.requested_control_state is OperationalControlState.PAUSED
    assert first_incident.broker_action_authorized is False
    assert len(control.calls) == 1

    second = _run(
        repository,
        plan,
        control,
        instant=incident.escalation_deadline + timedelta(hours=1),
    )
    assert second.incident_runs[0].failure_control_receipt == (
        first_incident.failure_control_receipt
    )
    assert control.calls[0] == control.calls[1]
    assert len(control.calls) == 2


def test_replayed_terminal_failure_binds_at_latest_history_before_deadline() -> None:
    incident = _incident()
    completed_at = incident.primary_deadline + timedelta(seconds=1)
    repository, incident, plan = _terminal_repository(
        CriticalAlertDeliveryOutcome.ERROR,
        completed_at=completed_at,
    )
    control = MemoryFailureControl(repository, plan)
    run = _run(
        repository,
        plan,
        control,
        instant=completed_at,
    )
    result = run.incident_runs[0]
    assert result.state is CriticalAlertAtomicWorkerIncidentState.CONTROL_BOUND
    assert result.supervision.observed_at == completed_at
    assert result.failure_control_receipt is not None
    assert result.failure_control_receipt.command.requested_at == completed_at


@pytest.mark.parametrize("late_by", [timedelta(0), timedelta(seconds=1)])
def test_deadline_equality_and_late_confirmation_do_not_suppress_total_failure(
    late_by: timedelta,
) -> None:
    incident = _incident()
    repository, incident, plan = _terminal_repository(
        CriticalAlertDeliveryOutcome.CONFIRMED,
        completed_at=incident.escalation_deadline + late_by,
    )
    control = MemoryFailureControl(repository, plan)
    run = _run(
        repository,
        plan,
        control,
        instant=incident.escalation_deadline + late_by + timedelta(seconds=5),
    )
    result = run.incident_runs[0]
    assert result.state is CriticalAlertAtomicWorkerIncidentState.CONTROL_BOUND
    assert result.supervision.observed_at == incident.escalation_deadline + late_by
    assert len(control.calls) == 1


def test_confirmed_wait_and_primary_failed_paths_never_bind() -> None:
    incident = _incident()
    plan = _plan()

    confirmed_repository = MemoryAlertRepository((incident,))
    confirmed_control = MemoryFailureControl(confirmed_repository, plan)
    confirmed_port = FakePort(plan.primary.provider_id)
    confirmed_run = run_critical_alert_atomic_worker_once(
        repository=confirmed_repository,
        route_plan=plan,
        route_resolver=FakeResolver({CriticalAlertRoute.PRIMARY: confirmed_port}),
        failure_control=confirmed_control,
        utc_clock=SequenceClock([BASE + timedelta(seconds=1)]),
        monotonic_clock=StepMonotonic(),
    )
    assert confirmed_run.incident_runs[0].state is CriticalAlertAtomicWorkerIncidentState.CONFIRMED
    assert confirmed_control.calls == []

    primary = _attempt(
        incident,
        plan,
        CriticalAlertRoute.PRIMARY,
        BASE + timedelta(seconds=1),
        None,
    )
    waiting_repository = MemoryAlertRepository(
        (incident,),
        attempts={incident.incident_id: [primary]},
    )
    waiting_control = MemoryFailureControl(waiting_repository, plan)
    waiting = _run(
        waiting_repository,
        plan,
        waiting_control,
        instant=BASE + timedelta(seconds=5),
    )
    assert waiting.incident_runs[0].state is CriticalAlertAtomicWorkerIncidentState.WAIT
    assert waiting_control.calls == []

    failed_repository = MemoryAlertRepository((incident,))
    failed_control = MemoryFailureControl(failed_repository, plan)
    failed_port = FakePort(plan.primary.provider_id, behavior="error")
    failed_run = run_critical_alert_atomic_worker_once(
        repository=failed_repository,
        route_plan=plan,
        route_resolver=FakeResolver({CriticalAlertRoute.PRIMARY: failed_port}),
        failure_control=failed_control,
        utc_clock=SequenceClock([BASE + timedelta(seconds=1)]),
        monotonic_clock=StepMonotonic(),
    )
    assert (
        failed_run.incident_runs[0].state is CriticalAlertAtomicWorkerIncidentState.PRIMARY_FAILED
    )
    assert failed_control.calls == []


def test_terminal_provider_call_waits_for_replay_before_atomic_bind() -> None:
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
    repository = MemoryAlertRepository(
        (incident,),
        attempts={incident.incident_id: [primary]},
        results={primary.attempt_id: primary_result},
    )
    control = MemoryFailureControl(repository, plan)
    escalation_port = FakePort(plan.escalation.provider_id, behavior="error")
    resolver = FakeResolver({CriticalAlertRoute.ESCALATION: escalation_port})
    first_instant = incident.primary_deadline + timedelta(seconds=1)
    first = run_critical_alert_atomic_worker_once(
        repository=repository,
        route_plan=plan,
        route_resolver=resolver,
        failure_control=control,
        utc_clock=SequenceClock([first_instant]),
        monotonic_clock=StepMonotonic(),
    )
    first_result = first.incident_runs[0]
    assert (
        first_result.state is CriticalAlertAtomicWorkerIncidentState.TOTAL_FAILURE_AWAITING_REPLAY
    )
    assert first_result.supervision.provider_called is True
    assert len(escalation_port.calls) == 1
    assert control.calls == []

    second = _run(
        repository,
        plan,
        control,
        instant=first_instant,
        resolver=resolver,
    )
    assert second.incident_runs[0].state is CriticalAlertAtomicWorkerIncidentState.CONTROL_BOUND
    assert second.incident_runs[0].supervision.provider_called is False
    assert second.incident_runs[0].supervision.observed_at == first_instant
    assert len(escalation_port.calls) == 1
    assert len(control.calls) == 1


def test_binder_failure_is_sanitized_and_never_exposes_authority_detail() -> None:
    repository, incident, plan = _terminal_repository(None)
    control = MemoryFailureControl(repository, plan, fail=True)
    with pytest.raises(CriticalAlertAtomicWorkerUnavailable) as raised:
        _run(
            repository,
            plan,
            control,
            instant=incident.escalation_deadline,
        )
    assert raised.value.reason_code == "failure_control_bind_failed"
    assert "secret" not in str(raised.value)
    assert len(control.calls) == 1


def test_adapter_resolution_and_scan_failures_are_sanitized() -> None:
    incident = _incident()
    plan = _plan()
    repository = MemoryAlertRepository((incident,))
    control = MemoryFailureControl(repository, plan)
    with pytest.raises(CriticalAlertAtomicWorkerUnavailable) as resolution:
        run_critical_alert_atomic_worker_once(
            repository=repository,
            route_plan=plan,
            route_resolver=FakeResolver({}, fail=True),
            failure_control=control,
            utc_clock=SequenceClock([BASE + timedelta(seconds=1)]),
            monotonic_clock=StepMonotonic(),
        )
    assert resolution.value.reason_code == "route_adapter_resolution_failed"
    assert "secret" not in str(resolution.value)
    assert control.calls == []

    scan_repository = MemoryAlertRepository((incident,), scan_failure=True)
    scan_control = MemoryFailureControl(scan_repository, plan)
    with pytest.raises(CriticalAlertAtomicWorkerUnavailable) as scan:
        _run(
            scan_repository,
            plan,
            scan_control,
            instant=BASE + timedelta(seconds=1),
        )
    assert scan.value.reason_code == "durable_scan_failed"
    assert "secret" not in str(scan.value)
    assert scan_control.calls == []
