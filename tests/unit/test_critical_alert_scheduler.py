from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta

import pytest

from packages.application.critical_alert_delivery import (
    CriticalAlertProviderReceipt,
    CriticalAlertProviderRequest,
)
from packages.application.critical_alert_scheduler import (
    CRITICAL_ALERT_TOTAL_FAILURE_REASON_CODE,
    CRITICAL_ALERT_TOTAL_FAILURE_RULE_ID,
    CriticalAlertTotalDeliveryFailure,
    CriticalAlertTotalFailureControlPolicy,
    CriticalAlertWorkerIncidentState,
    CriticalAlertWorkerRun,
    CriticalAlertWorkerUnavailable,
    run_critical_alert_worker_once,
)
from packages.application.critical_alert_supervisor import (
    CriticalAlertRouteBinding,
    CriticalAlertRoutePlan,
    critical_alert_route_idempotency_key,
)
from packages.domain.critical_alert import (
    CriticalAlertConflict,
    CriticalAlertDeliveryAttempt,
    CriticalAlertDeliveryCommand,
    CriticalAlertDeliveryResult,
    CriticalAlertIncident,
    CriticalAlertIncidentScanCursor,
    CriticalAlertIncidentScanPage,
    CriticalAlertRoute,
    append_critical_alert_delivery_attempt,
    critical_alert_delivery_milestone_met,
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


def _route_plan() -> CriticalAlertRoutePlan:
    return CriticalAlertRoutePlan(
        plan_id="test-approved-route-plan",
        plan_version="1",
        primary=CriticalAlertRouteBinding(
            route=CriticalAlertRoute.PRIMARY,
            provider_id="primary-provider",
            destination_sha256="1" * 64,
            recipient_set_sha256="2" * 64,
        ),
        escalation=CriticalAlertRouteBinding(
            route=CriticalAlertRoute.ESCALATION,
            provider_id="escalation-provider",
            destination_sha256="3" * 64,
            recipient_set_sha256="4" * 64,
        ),
    )


def _incident(
    *,
    suffix: str = "0001",
    recorded_at: datetime = BASE,
) -> CriticalAlertIncident:
    return CriticalAlertIncident(
        scope_id="paper-account-1",
        source_id="strategy-supervisor",
        idempotency_key=f"incident-{suffix}",
        alert_code="strategy_deadline_exceeded",
        evidence_sha256="a" * 64,
        detected_at=recorded_at - timedelta(milliseconds=100),
        recorded_at=recorded_at,
        correlation_sha256="b" * 64,
    )


@dataclass(slots=True)
class MemoryWorkerRepository:
    incidents: tuple[CriticalAlertIncident, ...]
    attempts: dict[str, list[CriticalAlertDeliveryAttempt]] = field(default_factory=dict)
    results: dict[str, CriticalAlertDeliveryResult] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.attempts = {
            incident.incident_id: list(self.attempts.get(incident.incident_id, ()))
            for incident in self.incidents
        }

    def load_incident(self, incident_id: str) -> CriticalAlertIncident:
        return next(incident for incident in self.incidents if incident.incident_id == incident_id)

    def scan_active_incidents(
        self,
        *,
        as_of: datetime,
        after: CriticalAlertIncidentScanCursor | None,
        limit: int,
    ) -> CriticalAlertIncidentScanPage:
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
            result_by_attempt = {result.attempt_id: result for result in results}
            if not any(
                critical_alert_delivery_milestone_met(
                    incident=incident,
                    attempt=attempt,
                    result=result,
                )
                for attempt in attempts
                if (result := result_by_attempt.get(attempt.attempt_id)) is not None
            ):
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
        existing = self.find_delivery_attempt(
            incident_id=command.incident_id,
            provider_id=command.provider_id,
            idempotency_key=command.idempotency_key,
        )
        if existing is not None:
            if (
                existing.route is not command.route
                or existing.request_sha256 != command.request_sha256
            ):
                raise CriticalAlertConflict("delivery command conflicts")
            return existing, False
        incident = self.load_incident(command.incident_id)
        history = self.attempts[command.incident_id]
        attempt = append_critical_alert_delivery_attempt(
            incident=incident,
            command=command,
            claimed_at=command.requested_at,
            previous=history[-1] if history else None,
        )
        history.append(attempt)
        return attempt, True

    def load_delivery_result(
        self,
        attempt_id: str,
    ) -> CriticalAlertDeliveryResult | None:
        return self.results.get(attempt_id)

    def load_delivery_history(
        self,
        incident_id: str,
    ) -> tuple[
        tuple[CriticalAlertDeliveryAttempt, ...],
        tuple[CriticalAlertDeliveryResult, ...],
    ]:
        incident = self.load_incident(incident_id)
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
        existing = self.results.get(result.attempt_id)
        if existing is not None and existing != result:
            raise CriticalAlertConflict("delivery result conflicts")
        self.results[result.attempt_id] = result
        return result


@dataclass(slots=True)
class FakeDeliveryPort:
    provider_id: str
    behavior: str = "confirmed"
    calls: list[tuple[CriticalAlertProviderRequest, float]] = field(default_factory=list)

    def deliver(
        self,
        request: CriticalAlertProviderRequest,
        *,
        timeout_seconds: float,
    ) -> CriticalAlertProviderReceipt:
        self.calls.append((request, timeout_seconds))
        if self.behavior == "error":
            raise RuntimeError("raw provider detail")
        if self.behavior == "timeout":
            raise TimeoutError("raw provider detail")
        return CriticalAlertProviderReceipt(provider_receipt_sha256="c" * 64)


@dataclass(slots=True)
class FakeRouteResolver:
    ports: dict[CriticalAlertRoute, FakeDeliveryPort]
    resolutions: list[CriticalAlertRoute] = field(default_factory=list)

    def resolve(
        self,
        incident: CriticalAlertIncident,
        binding: CriticalAlertRouteBinding,
    ) -> FakeDeliveryPort | None:
        assert incident.scope_id == "paper-account-1"
        self.resolutions.append(binding.route)
        return self.ports.get(binding.route)


def _initialize_control() -> OperationalControlTransition:
    command = OperationalControlCommand(
        scope_id="paper-account-1",
        idempotency_key="initialize-control-0001",
        kind=OperationalControlCommandKind.INITIALIZE_HALTED,
        target_state=OperationalControlState.HALTED,
        actor=OperationalControlActor(
            actor_id="test-system",
            kind=OperationalControlActorKind.SYSTEM,
            authority_sha256="d" * 64,
            authenticated_at=None,
        ),
        reason_code="test_initialization",
        reason_evidence_sha256="e" * 64,
        requested_at=BASE,
    )
    return apply_operational_control_command(None, command, decided_at=BASE)


@dataclass(slots=True)
class ExplicitTestControlPolicy:
    """A test-only policy; production intentionally has no default."""

    target_state: OperationalControlState = OperationalControlState.HALTED
    policy_id: str = "test-approved-alert-failure-policy"
    policy_sha256: str = "f" * 64
    calls: list[CriticalAlertTotalDeliveryFailure] = field(default_factory=list)

    def bind(
        self,
        failure: CriticalAlertTotalDeliveryFailure,
        *,
        idempotency_key: str,
    ) -> OperationalControlCommand:
        self.calls.append(failure)
        return OperationalControlCommand(
            scope_id=failure.incident.scope_id,
            idempotency_key=idempotency_key,
            kind=OperationalControlCommandKind.TRIP,
            target_state=self.target_state,
            actor=OperationalControlActor(
                actor_id="test-alert-breaker",
                kind=OperationalControlActorKind.CIRCUIT_BREAKER,
                authority_sha256="1" * 64,
                authenticated_at=None,
            ),
            reason_code=CRITICAL_ALERT_TOTAL_FAILURE_REASON_CODE,
            reason_evidence_sha256=failure.semantic_sha256,
            requested_at=failure.determined_at,
            trip_rule_id=CRITICAL_ALERT_TOTAL_FAILURE_RULE_ID,
            trip_policy_sha256=self.policy_sha256,
            trip_observation_sha256=failure.semantic_sha256,
        )


@dataclass(slots=True)
class FakeControlWriter:
    current: OperationalControlTransition = field(default_factory=_initialize_control)
    calls: list[OperationalControlCommand] = field(default_factory=list)
    retained: dict[
        tuple[OperationalControlActorKind, str, str],
        tuple[OperationalControlCommand, OperationalControlTransition],
    ] = field(default_factory=dict)

    def apply(self, command: OperationalControlCommand) -> OperationalControlTransition:
        self.calls.append(command)
        key = (
            command.actor.kind,
            command.actor.actor_id,
            command.idempotency_key,
        )
        existing = self.retained.get(key)
        if existing is not None:
            retained_command, transition = existing
            if retained_command != command:
                raise CriticalAlertConflict("control command idempotency conflicts")
            return transition
        self.current = apply_operational_control_command(
            self.current,
            command,
            decided_at=max(self.current.decided_at, command.requested_at),
        )
        self.retained[key] = (command, self.current)
        return self.current


def _worker(
    *,
    repository: MemoryWorkerRepository,
    resolver: FakeRouteResolver | None,
    at: datetime,
    policy: CriticalAlertTotalFailureControlPolicy | None = None,
    writer: FakeControlWriter | None = None,
    after: CriticalAlertIncidentScanCursor | None = None,
    limit: int = 64,
) -> CriticalAlertWorkerRun:
    return run_critical_alert_worker_once(
        repository=repository,
        route_plan=_route_plan(),
        route_resolver=resolver,
        control_policy=policy,
        control_writer=writer,
        after=after,
        limit=limit,
        utc_clock=lambda: at,
        monotonic_clock=lambda: 0.0,
    )


def test_primary_confirmation_is_bounded_and_never_resolves_absent_escalation() -> None:
    incidents = (
        _incident(suffix="0001", recorded_at=BASE),
        _incident(suffix="0002", recorded_at=BASE + timedelta(microseconds=1)),
    )
    repository = MemoryWorkerRepository(incidents)
    primary = FakeDeliveryPort("primary-provider")
    resolver = FakeRouteResolver({CriticalAlertRoute.PRIMARY: primary})

    first = _worker(
        repository=repository,
        resolver=resolver,
        at=BASE + timedelta(seconds=1),
        limit=1,
    )
    second = _worker(
        repository=repository,
        resolver=resolver,
        at=BASE + timedelta(seconds=1),
        after=first.resume_after,
        limit=1,
    )
    closed = _worker(
        repository=repository,
        resolver=resolver,
        at=BASE + timedelta(seconds=2),
    )

    assert first.scanned_count == second.scanned_count == 1
    assert first.resume_after is not None
    assert first.incident_runs[0].state is (CriticalAlertWorkerIncidentState.DELIVERY_CONFIRMED)
    assert second.incident_runs[0].state is (CriticalAlertWorkerIncidentState.DELIVERY_CONFIRMED)
    assert closed.scanned_count == 2
    assert closed.incident_runs == ()
    assert len(primary.calls) == 2
    assert resolver.resolutions == [
        CriticalAlertRoute.PRIMARY,
        CriticalAlertRoute.PRIMARY,
    ]


def test_missing_selected_adapter_leaves_one_unresolved_claim_and_never_resends() -> None:
    incident = _incident()
    repository = MemoryWorkerRepository((incident,))
    resolver = FakeRouteResolver({})

    with pytest.raises(CriticalAlertWorkerUnavailable, match="route_adapter_unavailable"):
        _worker(
            repository=repository,
            resolver=resolver,
            at=BASE + timedelta(seconds=1),
        )

    attempts, results = repository.load_delivery_history(incident.incident_id)
    assert len(attempts) == 1
    assert results == ()
    assert resolver.resolutions == [CriticalAlertRoute.PRIMARY]

    restarted = _worker(
        repository=repository,
        resolver=resolver,
        at=BASE + timedelta(seconds=2),
    )
    assert restarted.incident_runs[0].state is (
        CriticalAlertWorkerIncidentState.DELIVERY_UNRESOLVED
    )
    assert resolver.resolutions == [CriticalAlertRoute.PRIMARY]
    assert len(repository.attempts[incident.incident_id]) == 1


def test_preexisting_unresolved_claim_is_authenticated_before_adapter_resolution() -> None:
    incident = _incident()
    plan = _route_plan()
    repository = MemoryWorkerRepository((incident,))
    key = critical_alert_route_idempotency_key(
        incident=incident,
        route_plan=plan,
        route=CriticalAlertRoute.PRIMARY,
    )
    request = CriticalAlertProviderRequest.bind(
        incident=incident,
        route=CriticalAlertRoute.PRIMARY,
        provider_id=plan.primary.provider_id,
        idempotency_key=key,
    )
    repository.claim_delivery_attempt(
        CriticalAlertDeliveryCommand(
            incident_id=incident.incident_id,
            incident_sha256=incident.semantic_sha256,
            route=CriticalAlertRoute.PRIMARY,
            provider_id=plan.primary.provider_id,
            idempotency_key=key,
            request_sha256=request.semantic_sha256,
            requested_at=BASE + timedelta(seconds=1),
        )
    )
    resolver = FakeRouteResolver(
        {CriticalAlertRoute.PRIMARY: FakeDeliveryPort(plan.primary.provider_id)}
    )

    run = _worker(
        repository=repository,
        resolver=resolver,
        at=BASE + timedelta(seconds=2),
    )

    assert run.incident_runs[0].state is (CriticalAlertWorkerIncidentState.DELIVERY_UNRESOLVED)
    assert resolver.resolutions == []


def test_terminal_primary_failure_waits_until_fixed_escalation_boundary() -> None:
    incident = _incident()
    repository = MemoryWorkerRepository((incident,))
    primary = FakeDeliveryPort("primary-provider", behavior="error")
    escalation = FakeDeliveryPort("escalation-provider")
    resolver = FakeRouteResolver(
        {
            CriticalAlertRoute.PRIMARY: primary,
            CriticalAlertRoute.ESCALATION: escalation,
        }
    )

    primary_run = _worker(
        repository=repository,
        resolver=resolver,
        at=BASE + timedelta(seconds=1),
    )
    waiting_run = _worker(
        repository=repository,
        resolver=resolver,
        at=BASE + timedelta(seconds=2),
    )
    escalation_run = _worker(
        repository=repository,
        resolver=resolver,
        at=incident.primary_deadline,
    )

    assert primary_run.incident_runs[0].state is (CriticalAlertWorkerIncidentState.DELIVERY_FAILED)
    assert waiting_run.incident_runs[0].state is (CriticalAlertWorkerIncidentState.DELIVERY_FAILED)
    assert escalation_run.incident_runs[0].state is (
        CriticalAlertWorkerIncidentState.DELIVERY_CONFIRMED
    )
    assert waiting_run.incident_runs[0].supervision.wait_until == (incident.primary_deadline)
    assert resolver.resolutions == [
        CriticalAlertRoute.PRIMARY,
        CriticalAlertRoute.ESCALATION,
    ]


def test_primary_deadline_equality_selects_only_escalation() -> None:
    incident = _incident()
    repository = MemoryWorkerRepository((incident,))
    primary = FakeDeliveryPort("primary-provider")
    escalation = FakeDeliveryPort("escalation-provider")
    resolver = FakeRouteResolver(
        {
            CriticalAlertRoute.PRIMARY: primary,
            CriticalAlertRoute.ESCALATION: escalation,
        }
    )

    run = _worker(
        repository=repository,
        resolver=resolver,
        at=incident.primary_deadline,
    )

    assert run.incident_runs[0].supervision.selected_route is (CriticalAlertRoute.ESCALATION)
    assert run.incident_runs[0].state is (CriticalAlertWorkerIncidentState.DELIVERY_CONFIRMED)
    assert primary.calls == []
    assert len(escalation.calls) == 1
    assert resolver.resolutions == [CriticalAlertRoute.ESCALATION]


@pytest.mark.parametrize(
    "target_state",
    [OperationalControlState.PAUSED, OperationalControlState.HALTED],
)
def test_escalation_deadline_rejects_legacy_split_policy_and_writer(
    target_state: OperationalControlState,
) -> None:
    incident = _incident()
    repository = MemoryWorkerRepository((incident,))
    resolver = FakeRouteResolver({})
    writer = FakeControlWriter()

    with pytest.raises(
        CriticalAlertWorkerUnavailable,
        match="atomic_failure_control_required",
    ):
        _worker(
            repository=repository,
            resolver=resolver,
            at=incident.escalation_deadline,
            writer=writer,
        )
    assert resolver.resolutions == []
    assert writer.calls == []
    attempts, results = repository.load_delivery_history(incident.incident_id)
    assert len(attempts) == len(results) == 1

    policy = ExplicitTestControlPolicy(target_state=target_state)
    with pytest.raises(
        CriticalAlertWorkerUnavailable,
        match="atomic_failure_control_required",
    ):
        _worker(
            repository=repository,
            resolver=resolver,
            at=incident.escalation_deadline,
            policy=policy,
            writer=writer,
        )
    assert policy.calls == []
    assert writer.calls == []
    assert resolver.resolutions == []


def test_failed_escalation_is_durable_and_never_resent_without_policy() -> None:
    incident = _incident()
    repository = MemoryWorkerRepository((incident,))
    primary = FakeDeliveryPort("primary-provider", behavior="error")
    escalation = FakeDeliveryPort("escalation-provider", behavior="error")
    resolver = FakeRouteResolver(
        {
            CriticalAlertRoute.PRIMARY: primary,
            CriticalAlertRoute.ESCALATION: escalation,
        }
    )
    _worker(
        repository=repository,
        resolver=resolver,
        at=BASE + timedelta(seconds=1),
    )

    with pytest.raises(
        CriticalAlertWorkerUnavailable,
        match="atomic_failure_control_required",
    ):
        _worker(
            repository=repository,
            resolver=resolver,
            at=incident.primary_deadline,
        )
    attempts, results = repository.load_delivery_history(incident.incident_id)
    assert len(attempts) == len(results) == 2
    calls_before_restart = (len(primary.calls), len(escalation.calls))
    resolutions_before_restart = tuple(resolver.resolutions)

    with pytest.raises(
        CriticalAlertWorkerUnavailable,
        match="atomic_failure_control_required",
    ):
        _worker(
            repository=repository,
            resolver=resolver,
            at=BASE + timedelta(seconds=20),
        )

    assert (len(primary.calls), len(escalation.calls)) == calls_before_restart
    assert tuple(resolver.resolutions) == resolutions_before_restart
    assert len(repository.attempts[incident.incident_id]) == 2


def test_legacy_split_policy_and_writer_never_run_across_restart() -> None:
    incident = _incident()
    repository = MemoryWorkerRepository((incident,))
    resolver = FakeRouteResolver(
        {
            CriticalAlertRoute.PRIMARY: FakeDeliveryPort(
                "primary-provider",
                behavior="error",
            ),
            CriticalAlertRoute.ESCALATION: FakeDeliveryPort(
                "escalation-provider",
                behavior="error",
            ),
        }
    )
    policy = ExplicitTestControlPolicy()
    writer = FakeControlWriter()
    _worker(
        repository=repository,
        resolver=resolver,
        at=BASE + timedelta(seconds=1),
    )
    for instant in (
        incident.primary_deadline,
        BASE + timedelta(seconds=20),
    ):
        with pytest.raises(
            CriticalAlertWorkerUnavailable,
            match="atomic_failure_control_required",
        ):
            _worker(
                repository=repository,
                resolver=resolver,
                at=instant,
                policy=policy,
                writer=writer,
            )
    assert policy.calls == []
    assert writer.calls == []


def test_unbound_control_policy_is_rejected_before_writer_authority() -> None:
    incident = _incident()
    repository = MemoryWorkerRepository((incident,))
    writer = FakeControlWriter()
    valid_policy = ExplicitTestControlPolicy()

    @dataclass(slots=True)
    class UnboundPolicy:
        policy_id: str = valid_policy.policy_id
        policy_sha256: str = valid_policy.policy_sha256

        def bind(
            self,
            failure: CriticalAlertTotalDeliveryFailure,
            *,
            idempotency_key: str,
        ) -> OperationalControlCommand:
            return replace(
                valid_policy.bind(
                    failure,
                    idempotency_key=idempotency_key,
                ),
                reason_evidence_sha256="0" * 64,
            )

    with pytest.raises(
        CriticalAlertWorkerUnavailable,
        match="atomic_failure_control_required",
    ):
        _worker(
            repository=repository,
            resolver=FakeRouteResolver({}),
            at=incident.escalation_deadline,
            policy=UnboundPolicy(),
            writer=writer,
        )

    assert valid_policy.calls == []
    assert writer.calls == []
