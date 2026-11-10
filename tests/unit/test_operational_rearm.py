from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

import pytest

from packages.application.operational_rearm import (
    ApprovedAdvancedRiskAssignment,
    AuthenticatedOperationalControlService,
    AuthoritativeOperationalRearmFacts,
    FencedAdvancedRiskAssignmentService,
)
from packages.domain.account_coordinator import AccountFence
from packages.domain.advanced_risk_assignment import (
    AdvancedRiskAssignmentCommand,
    AdvancedRiskPolicyAssignment,
    assign_advanced_risk_policy,
)
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlCompletion,
    OperationalControlCompletionOutcome,
    OperationalControlConflict,
    OperationalControlIncidentDisposition,
    OperationalControlRearmEvidence,
    OperationalControlRearmRejected,
    OperationalControlResidualFacts,
    OperationalControlState,
    OperationalControlTransition,
    apply_operational_control_command,
    record_operational_control_completion,
)

BASE = datetime(2026, 7, 28, 15, 0, tzinfo=UTC)
ACCOUNT = "phase5f-paper-account"


@dataclass(slots=True)
class MutableClock:
    instant: datetime

    def __call__(self) -> datetime:
        return self.instant


class FakeControlRepository:
    def __init__(
        self,
        current: OperationalControlTransition,
        *,
        clock: MutableClock,
    ) -> None:
        self.current = current
        self.clock = clock
        self.receipts: dict[
            tuple[str, OperationalControlActorKind, str, str],
            tuple[OperationalControlCommand, OperationalControlTransition],
        ] = {}
        self.raw_commands: list[OperationalControlCommand] = []
        self.rearm_commands: list[
            tuple[OperationalControlCommand, OperationalControlRearmEvidence]
        ] = []
        self.before_rearm: Callable[[], None] | None = None

    def load(self, account_id: str) -> OperationalControlTransition | None:
        assert account_id == ACCOUNT
        return self.current

    def load_actor_command(
        self,
        *,
        account_id: str,
        actor_kind: OperationalControlActorKind,
        actor_id: str,
        idempotency_key: str,
    ) -> tuple[OperationalControlCommand, OperationalControlTransition] | None:
        return self.receipts.get((account_id, actor_kind, actor_id, idempotency_key))

    def _remember(
        self,
        command: OperationalControlCommand,
        transition: OperationalControlTransition,
    ) -> None:
        self.receipts[
            (
                command.scope_id,
                command.actor.kind,
                command.actor.actor_id,
                command.idempotency_key,
            )
        ] = command, transition

    def apply(
        self,
        command: OperationalControlCommand,
    ) -> OperationalControlTransition:
        self.raw_commands.append(command)
        transition = apply_operational_control_command(
            self.current,
            command,
            decided_at=self.clock(),
        )
        self.current = transition
        self._remember(command, transition)
        return transition

    def apply_authenticated_rearm(
        self,
        command: OperationalControlCommand,
        evidence: OperationalControlRearmEvidence,
    ) -> OperationalControlTransition:
        callback = self.before_rearm
        if callback is not None:
            callback()
        transition = apply_operational_control_command(
            self.current,
            command,
            decided_at=self.clock(),
            rearm_evidence=evidence,
        )
        self.rearm_commands.append((command, evidence))
        self.current = transition
        self._remember(command, transition)
        return transition


class FakeVerifier:
    def __init__(self) -> None:
        self.calls = 0
        self.transform: (
            Callable[
                [AuthoritativeOperationalRearmFacts],
                AuthoritativeOperationalRearmFacts | None,
            ]
            | None
        ) = None
        self.operation_completion: OperationalControlCompletion | None = None

    def verify(
        self,
        current: OperationalControlTransition,
        *,
        checked_at: datetime,
    ) -> AuthoritativeOperationalRearmFacts | None:
        self.calls += 1
        dispositions = tuple(
            sorted(
                (
                    OperationalControlIncidentDisposition(
                        event_id=event.event_id,
                        event_sha256=event.semantic_sha256,
                        resolution_code="operator-reviewed",
                        resolution_evidence_sha256="e" * 64,
                        resolved_at=checked_at,
                    )
                    for event in current.blocking_events
                ),
                key=lambda item: item.event_id,
            )
        )
        facts = AuthoritativeOperationalRearmFacts(
            scope_id=current.scope_id,
            current_transition_id=current.transition_id,
            current_transition_sha256=current.semantic_sha256,
            current_state=current.effective_state,
            current_state_epoch_id=current.state_epoch_id,
            checked_at=checked_at,
            expires_at=checked_at + timedelta(seconds=30),
            readiness_sha256="f" * 64,
            reconciliation_sha256="1" * 64,
            incident_register_sha256="2" * 64,
            reconciliation_clean=True,
            data_healthy=True,
            clock_healthy=True,
            working_order_ids=(),
            unknown_order_ids=(),
            pending_cancel_order_ids=(),
            incident_dispositions=dispositions,
            operation_completion=self.operation_completion,
        )
        transform = self.transform
        if transform is not None:
            return transform(facts)
        return facts


def _initial_halted() -> OperationalControlTransition:
    actor = OperationalControlActor(
        actor_id="bootstrap",
        kind=OperationalControlActorKind.SYSTEM,
        authority_sha256="a" * 64,
        authenticated_at=None,
    )
    command = OperationalControlCommand(
        scope_id=ACCOUNT,
        idempotency_key="initialize-phase5f-0001",
        kind=OperationalControlCommandKind.INITIALIZE_HALTED,
        target_state=OperationalControlState.HALTED,
        actor=actor,
        reason_code="startup-fail-closed",
        reason_evidence_sha256="b" * 64,
        requested_at=BASE,
    )
    return apply_operational_control_command(None, command, decided_at=BASE)


def _service(
    *,
    clock: MutableClock | None = None,
    verifier: FakeVerifier | None = None,
) -> tuple[
    AuthenticatedOperationalControlService,
    FakeControlRepository,
    MutableClock,
    FakeVerifier,
]:
    selected_clock = clock or MutableClock(BASE + timedelta(seconds=1))
    selected_verifier = verifier or FakeVerifier()
    repository = FakeControlRepository(_initial_halted(), clock=selected_clock)
    service = AuthenticatedOperationalControlService(
        repository=repository,
        actor_authority_sha256="9" * 64,
        rearm_verifier=selected_verifier,
        clock=selected_clock,
    )
    return service, repository, selected_clock, selected_verifier


def _execute(
    service: AuthenticatedOperationalControlService,
    kind: OperationalControlCommandKind,
    *,
    key: str,
    reason: str | None = None,
) -> OperationalControlTransition:
    return service.execute(
        account_id=ACCOUNT,
        operator_id="local-operator",
        idempotency_key=key,
        kind=kind,
        reason_code=reason or f"operator-{kind.value}",
    )


def test_rearm_is_proof_constructed_server_side_and_exactly_replayed() -> None:
    service, repository, _, verifier = _service()

    first = _execute(
        service,
        OperationalControlCommandKind.REARM,
        key="phase5f-rearm-0001",
    )
    retry = _execute(
        service,
        OperationalControlCommandKind.REARM,
        key="phase5f-rearm-0001",
    )

    assert first == retry
    assert first.effective_state is OperationalControlState.RUNNING
    assert verifier.calls == 1
    assert not repository.raw_commands
    command, evidence = repository.rearm_commands[0]
    assert command.rearm_evidence_sha256 == evidence.semantic_sha256
    assert evidence.current_transition_id != first.transition_id
    assert evidence.working_order_ids == ()


def test_same_actor_key_with_different_intent_conflicts_before_mutation() -> None:
    service, repository, _, _ = _service()
    _execute(
        service,
        OperationalControlCommandKind.REARM,
        key="phase5f-conflict-0001",
    )

    with pytest.raises(OperationalControlConflict, match="idempotency"):
        _execute(
            service,
            OperationalControlCommandKind.PAUSE,
            key="phase5f-conflict-0001",
        )

    assert len(repository.rearm_commands) == 1
    assert not repository.raw_commands


@pytest.mark.parametrize(
    ("transform", "message"),
    [
        (
            lambda facts: None,
            "prerequisites are unavailable",
        ),
        (
            lambda facts: replace(facts, working_order_ids=("working-order-1",)),
            "healthy and clean",
        ),
        (
            lambda facts: replace(facts, incident_dispositions=()),
            "dispose every exact blocking event",
        ),
        (
            lambda facts: replace(facts, expires_at=facts.checked_at),
            "expiry must follow",
        ),
        (
            lambda facts: replace(facts, current_transition_sha256="0" * 64),
            "exact current head",
        ),
    ],
)
def test_rearm_rejects_incomplete_expired_or_wrong_head_facts(
    transform: Callable[
        [AuthoritativeOperationalRearmFacts],
        AuthoritativeOperationalRearmFacts | None,
    ],
    message: str,
) -> None:
    service, repository, _, verifier = _service()
    verifier.transform = transform

    with pytest.raises(ValueError, match=message):
        _execute(
            service,
            OperationalControlCommandKind.REARM,
            key="phase5f-rearm-invalid-0001",
        )

    assert not repository.rearm_commands


def test_rearm_expiry_equality_is_rejected_at_commit_time() -> None:
    service, repository, clock, verifier = _service()
    verifier.transform = lambda facts: replace(
        facts,
        expires_at=facts.checked_at + timedelta(seconds=1),
    )

    def reach_exclusive_expiry() -> None:
        clock.instant += timedelta(seconds=1)

    repository.before_rearm = reach_exclusive_expiry
    with pytest.raises(OperationalControlRearmRejected, match="not fresh"):
        _execute(
            service,
            OperationalControlCommandKind.REARM,
            key="phase5f-rearm-expiry-equality-0001",
        )


def test_rearm_is_unavailable_without_an_authoritative_verifier() -> None:
    clock = MutableClock(BASE + timedelta(seconds=1))
    repository = FakeControlRepository(_initial_halted(), clock=clock)
    service = AuthenticatedOperationalControlService(
        repository=repository,
        actor_authority_sha256="9" * 64,
        rearm_verifier=None,
        clock=clock,
    )

    with pytest.raises(OperationalControlRearmRejected, match="unavailable"):
        _execute(
            service,
            OperationalControlCommandKind.REARM,
            key="phase5f-no-verifier-0001",
        )


def test_concurrent_head_change_invalidates_verified_rearm() -> None:
    service, repository, clock, _ = _service()

    def advance_head() -> None:
        actor = OperationalControlActor(
            actor_id="circuit-breaker",
            kind=OperationalControlActorKind.CIRCUIT_BREAKER,
            authority_sha256="7" * 64,
            authenticated_at=None,
        )
        command = OperationalControlCommand(
            scope_id=ACCOUNT,
            idempotency_key="concurrent-trip-0001",
            kind=OperationalControlCommandKind.TRIP,
            target_state=OperationalControlState.HALTED,
            actor=actor,
            reason_code="concurrent-risk-trip",
            reason_evidence_sha256="6" * 64,
            requested_at=clock(),
            trip_rule_id="session-loss",
            trip_policy_sha256="5" * 64,
            trip_observation_sha256="4" * 64,
        )
        repository.current = apply_operational_control_command(
            repository.current,
            command,
            decided_at=clock(),
        )

    repository.before_rearm = advance_head
    with pytest.raises(OperationalControlRearmRejected, match="exact current"):
        _execute(
            service,
            OperationalControlCommandKind.REARM,
            key="phase5f-stale-head-0001",
        )


def test_drain_rearm_requires_the_exact_completed_attempt() -> None:
    service, repository, clock, verifier = _service()
    _execute(
        service,
        OperationalControlCommandKind.REARM,
        key="phase5f-running-0001",
    )
    clock.instant += timedelta(seconds=1)
    draining = _execute(
        service,
        OperationalControlCommandKind.DRAIN,
        key="phase5f-drain-0001",
    )
    clock.instant += timedelta(seconds=1)

    with pytest.raises(OperationalControlRearmRejected, match="completed attempt"):
        _execute(
            service,
            OperationalControlCommandKind.REARM,
            key="phase5f-drain-rearm-missing-0001",
        )

    verifier.operation_completion = record_operational_control_completion(
        draining,
        idempotency_key="phase5f-drain-complete-0001",
        outcome=OperationalControlCompletionOutcome.COMPLETED,
        observed_at=clock(),
        evidence_sha256="3" * 64,
        residual_facts=OperationalControlResidualFacts(
            terminal_order_count=4,
            working_order_ids=(),
            unknown_order_ids=(),
            pending_cancel_order_ids=(),
            positions=(),
            reconciliation_clean=True,
            source_evidence_sha256="8" * 64,
        ),
    )
    rearmed = _execute(
        service,
        OperationalControlCommandKind.REARM,
        key="phase5f-drain-rearm-complete-0001",
    )
    assert rearmed.effective_state is OperationalControlState.RUNNING
    assert repository.rearm_commands[-1][1].operation_completion is not None


def test_non_rearm_commands_use_durable_severity_join_and_never_a_broker() -> None:
    service, repository, clock, _ = _service()
    _execute(
        service,
        OperationalControlCommandKind.REARM,
        key="phase5f-start-running-0001",
    )
    clock.instant += timedelta(seconds=1)
    halted = _execute(
        service,
        OperationalControlCommandKind.HALT,
        key="phase5f-halt-0001",
    )
    clock.instant += timedelta(seconds=1)
    lower_severity = _execute(
        service,
        OperationalControlCommandKind.PAUSE,
        key="phase5f-pause-after-halt-0001",
    )

    assert halted.effective_state is OperationalControlState.HALTED
    assert lower_severity.effective_state is OperationalControlState.HALTED
    assert [command.kind for command in repository.raw_commands] == [
        OperationalControlCommandKind.HALT,
        OperationalControlCommandKind.PAUSE,
    ]


class FakeAssignmentRepository:
    def __init__(self) -> None:
        self.current: AdvancedRiskPolicyAssignment | None = None
        self.calls: list[tuple[AdvancedRiskAssignmentCommand, AccountFence]] = []

    def current_assignment(
        self,
        account_id: str,
    ) -> AdvancedRiskPolicyAssignment | None:
        assert account_id == ACCOUNT
        return self.current

    def assign(
        self,
        command: AdvancedRiskAssignmentCommand,
        fence: AccountFence,
    ) -> AdvancedRiskPolicyAssignment:
        self.calls.append((command, fence))
        assignment = assign_advanced_risk_policy(
            self.current,
            command,
            assigned_at=BASE + timedelta(seconds=1),
        )
        self.current = assignment
        return assignment


class FakeFenceAuthority:
    def __init__(self, fence: AccountFence | None) -> None:
        self.fence = fence
        self.calls: list[tuple[str, datetime]] = []

    def current_fence(
        self,
        account_id: str,
        *,
        checked_at: datetime,
    ) -> AccountFence | None:
        self.calls.append((account_id, checked_at))
        return self.fence


def test_risk_assignment_uses_only_server_policy_and_current_exact_fence() -> None:
    repository = FakeAssignmentRepository()
    authority = FakeFenceAuthority(
        AccountFence(
            account_id=ACCOUNT,
            owner_id="trader-process-1",
            lease_id="lease-1",
            fencing_generation=9,
        )
    )
    service = FencedAdvancedRiskAssignmentService(
        repository=repository,
        current_fence_authority=authority,
        approved=ApprovedAdvancedRiskAssignment(
            policy_id="moderate-paper-policy",
            policy_sha256="c" * 64,
            environment="paper",
            approval_evidence_sha256="d" * 64,
        ),
        actor_authority_sha256="9" * 64,
        clock=MutableClock(BASE + timedelta(seconds=1)),
    )

    first = service.assign(
        account_id=ACCOUNT,
        operator_id="local-operator",
        idempotency_key="phase5f-risk-assign-0001",
    )
    retry = service.assign(
        account_id=ACCOUNT,
        operator_id="local-operator",
        idempotency_key="phase5f-risk-assign-0001",
    )

    assert retry == first
    assert len(repository.calls) == 1
    command, fence = repository.calls[0]
    assert command.policy_id == "moderate-paper-policy"
    assert command.expected_assignment_sequence_number == 0
    assert command.expected_assignment_sha256 is None
    assert fence == authority.fence
    assert authority.calls == [
        (ACCOUNT, BASE + timedelta(seconds=1)),
        (ACCOUNT, BASE + timedelta(seconds=1)),
    ]


def test_risk_assignment_refuses_to_fabricate_a_missing_account_fence() -> None:
    repository = FakeAssignmentRepository()
    service = FencedAdvancedRiskAssignmentService(
        repository=repository,
        current_fence_authority=FakeFenceAuthority(None),
        approved=ApprovedAdvancedRiskAssignment(
            policy_id="moderate-paper-policy",
            policy_sha256="c" * 64,
            environment="paper",
            approval_evidence_sha256="d" * 64,
        ),
        actor_authority_sha256="9" * 64,
        clock=MutableClock(BASE + timedelta(seconds=1)),
    )

    with pytest.raises(ValueError, match="no current exact account fence"):
        service.assign(
            account_id=ACCOUNT,
            operator_id="local-operator",
            idempotency_key="phase5f-risk-assign-0002",
        )

    assert repository.calls == []
