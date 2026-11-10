"""Authenticated local operational commands and authoritative manual re-arm."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from packages.domain.account_coordinator import AccountFence
from packages.domain.advanced_risk_assignment import (
    ADVANCED_RISK_ASSIGNMENT_CONTRACT_VERSION,
    AdvancedRiskAssignmentCommand,
    AdvancedRiskPolicyAssignment,
)
from packages.domain.canonical import canonical_json_bytes
from packages.domain.identifiers import canonical_id
from packages.domain.operational_control import (
    OperationalControlAbsent,
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlCompletion,
    OperationalControlConflict,
    OperationalControlError,
    OperationalControlIncidentDisposition,
    OperationalControlRearmEvidence,
    OperationalControlRearmRejected,
    OperationalControlState,
    OperationalControlTransition,
    _operational_control_rearm_evidence,
)

LOCAL_OPERATIONS_CONTRACT_VERSION = "phase5f-authenticated-local-operations-v1"

UtcClock = Callable[[], datetime]


class OperationalControlRepository(Protocol):
    """Minimum durable command boundary used by the local operations service."""

    def load(self, account_id: str) -> OperationalControlTransition | None: ...

    def load_actor_command(
        self,
        *,
        account_id: str,
        actor_kind: OperationalControlActorKind,
        actor_id: str,
        idempotency_key: str,
    ) -> tuple[OperationalControlCommand, OperationalControlTransition] | None: ...

    def apply(self, command: OperationalControlCommand) -> OperationalControlTransition: ...

    def apply_authenticated_rearm(
        self,
        command: OperationalControlCommand,
        evidence: OperationalControlRearmEvidence,
    ) -> OperationalControlTransition: ...


@dataclass(frozen=True, slots=True)
class AuthoritativeOperationalRearmFacts:
    """Exact source facts returned by a trusted, server-side verifier."""

    scope_id: str
    current_transition_id: str
    current_transition_sha256: str
    current_state: OperationalControlState
    current_state_epoch_id: str
    checked_at: datetime
    expires_at: datetime
    readiness_sha256: str
    reconciliation_sha256: str
    incident_register_sha256: str
    reconciliation_clean: bool
    data_healthy: bool
    clock_healthy: bool
    working_order_ids: tuple[str, ...]
    unknown_order_ids: tuple[str, ...]
    pending_cancel_order_ids: tuple[str, ...]
    incident_dispositions: tuple[OperationalControlIncidentDisposition, ...]
    operation_completion: OperationalControlCompletion | None = None


class OperationalRearmVerifier(Protocol):
    """Authoritative source adapter; browser input never crosses this boundary."""

    def verify(
        self,
        current: OperationalControlTransition,
        *,
        checked_at: datetime,
    ) -> AuthoritativeOperationalRearmFacts | None: ...


_ACTION_TARGETS = {
    OperationalControlCommandKind.PAUSE: OperationalControlState.PAUSED,
    OperationalControlCommandKind.DRAIN: OperationalControlState.DRAINING,
    OperationalControlCommandKind.FLATTEN: OperationalControlState.FLATTENING,
    OperationalControlCommandKind.HALT: OperationalControlState.HALTED,
    OperationalControlCommandKind.REARM: OperationalControlState.RUNNING,
}


def _read_utc(clock: UtcClock) -> datetime:
    value = clock()
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise OperationalControlError(
            "local operations clock must return a timezone-aware UTC instant"
        )
    return value


def _reason_evidence_sha256(
    *,
    account_id: str,
    operator_id: str,
    idempotency_key: str,
    kind: OperationalControlCommandKind,
    reason_code: str,
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            (
                LOCAL_OPERATIONS_CONTRACT_VERSION,
                "authenticated_operator_reason",
                account_id,
                operator_id,
                idempotency_key,
                kind,
                reason_code,
            )
        )
    ).hexdigest()


class AuthenticatedOperationalControlService:
    """Turn a local authenticated intent into one durable control command."""

    __slots__ = ("_actor_authority_sha256", "_clock", "_rearm_verifier", "_repository")

    def __init__(
        self,
        *,
        repository: OperationalControlRepository,
        actor_authority_sha256: str,
        rearm_verifier: OperationalRearmVerifier | None,
        clock: UtcClock,
    ) -> None:
        if not all(
            callable(getattr(repository, method, None))
            for method in (
                "load",
                "load_actor_command",
                "apply",
                "apply_authenticated_rearm",
            )
        ):
            raise OperationalControlError(
                "local operations requires a complete durable control repository"
            )
        if rearm_verifier is not None and not callable(getattr(rearm_verifier, "verify", None)):
            raise OperationalControlError("local operations rearm verifier is unsupported")
        if not callable(clock):
            raise OperationalControlError("local operations requires a trusted clock")
        # Validate the configured digest without retaining a synthetic command.
        OperationalControlActor(
            actor_id="local-operations-authority-validation",
            kind=OperationalControlActorKind.SYSTEM,
            authority_sha256=actor_authority_sha256,
            authenticated_at=None,
        )
        self._repository = repository
        self._actor_authority_sha256 = actor_authority_sha256
        self._rearm_verifier = rearm_verifier
        self._clock = clock

    def execute(
        self,
        *,
        account_id: str,
        operator_id: str,
        idempotency_key: str,
        kind: OperationalControlCommandKind,
        reason_code: str,
    ) -> OperationalControlTransition:
        """Apply or exactly replay one authenticated browser control intent."""

        if type(kind) is not OperationalControlCommandKind or kind not in _ACTION_TARGETS:
            raise OperationalControlError(
                "local operations supports PAUSE, DRAIN, FLATTEN, HALT, or REARM"
            )
        reason_sha256 = _reason_evidence_sha256(
            account_id=account_id,
            operator_id=operator_id,
            idempotency_key=idempotency_key,
            kind=kind,
            reason_code=reason_code,
        )
        existing = self._repository.load_actor_command(
            account_id=account_id,
            actor_kind=OperationalControlActorKind.HUMAN,
            actor_id=operator_id,
            idempotency_key=idempotency_key,
        )
        if existing is not None:
            command, transition = existing
            if not self._is_exact_retry(
                command,
                kind=kind,
                target_state=_ACTION_TARGETS[kind],
                reason_code=reason_code,
                reason_evidence_sha256=reason_sha256,
            ):
                raise OperationalControlConflict(
                    "local operations idempotency key conflicts with its durable command"
                )
            return transition

        requested_at = _read_utc(self._clock)
        actor = OperationalControlActor(
            actor_id=operator_id,
            kind=OperationalControlActorKind.HUMAN,
            authority_sha256=self._actor_authority_sha256,
            authenticated_at=requested_at,
        )
        if kind is OperationalControlCommandKind.REARM:
            return self._rearm(
                account_id=account_id,
                idempotency_key=idempotency_key,
                reason_code=reason_code,
                reason_evidence_sha256=reason_sha256,
                requested_at=requested_at,
                actor=actor,
            )

        command = OperationalControlCommand(
            scope_id=account_id,
            idempotency_key=idempotency_key,
            kind=kind,
            target_state=_ACTION_TARGETS[kind],
            actor=actor,
            reason_code=reason_code,
            reason_evidence_sha256=reason_sha256,
            requested_at=requested_at,
        )
        return self._repository.apply(command)

    def _is_exact_retry(
        self,
        command: OperationalControlCommand,
        *,
        kind: OperationalControlCommandKind,
        target_state: OperationalControlState,
        reason_code: str,
        reason_evidence_sha256: str,
    ) -> bool:
        return (
            command.kind is kind
            and command.target_state is target_state
            and command.actor.kind is OperationalControlActorKind.HUMAN
            and command.actor.authority_sha256 == self._actor_authority_sha256
            and command.reason_code == reason_code
            and command.reason_evidence_sha256 == reason_evidence_sha256
            and (command.rearm_evidence_sha256 is not None)
            == (kind is OperationalControlCommandKind.REARM)
            and command.trip_rule_id is None
            and command.trip_policy_sha256 is None
            and command.trip_observation_sha256 is None
        )

    def _rearm(
        self,
        *,
        account_id: str,
        idempotency_key: str,
        reason_code: str,
        reason_evidence_sha256: str,
        requested_at: datetime,
        actor: OperationalControlActor,
    ) -> OperationalControlTransition:
        verifier = self._rearm_verifier
        if verifier is None:
            raise OperationalControlRearmRejected(
                "manual rearm is unavailable without an authoritative verifier"
            )
        current = self._repository.load(account_id)
        if current is None:
            raise OperationalControlAbsent(
                "manual rearm requires durable operational control state"
            )
        if current.effective_state is OperationalControlState.RUNNING:
            raise OperationalControlRearmRejected(
                "manual rearm requires a non-running control head"
            )
        facts = verifier.verify(current, checked_at=requested_at)
        if type(facts) is not AuthoritativeOperationalRearmFacts:
            raise OperationalControlRearmRejected(
                "authoritative rearm prerequisites are unavailable"
            )
        if (
            facts.scope_id != current.scope_id
            or facts.current_transition_id != current.transition_id
            or facts.current_transition_sha256 != current.semantic_sha256
            or facts.current_state is not current.effective_state
            or facts.current_state_epoch_id != current.state_epoch_id
            or facts.checked_at != requested_at
        ):
            raise OperationalControlRearmRejected(
                "authoritative rearm prerequisites do not bind the exact current head and check"
            )
        evidence = _operational_control_rearm_evidence(
            scope_id=facts.scope_id,
            current_transition_id=facts.current_transition_id,
            current_transition_sha256=facts.current_transition_sha256,
            current_state=facts.current_state,
            current_state_epoch_id=facts.current_state_epoch_id,
            actor=actor,
            checked_at=facts.checked_at,
            expires_at=facts.expires_at,
            readiness_sha256=facts.readiness_sha256,
            reconciliation_sha256=facts.reconciliation_sha256,
            incident_register_sha256=facts.incident_register_sha256,
            reconciliation_clean=facts.reconciliation_clean,
            data_healthy=facts.data_healthy,
            clock_healthy=facts.clock_healthy,
            working_order_ids=facts.working_order_ids,
            unknown_order_ids=facts.unknown_order_ids,
            pending_cancel_order_ids=facts.pending_cancel_order_ids,
            incident_dispositions=facts.incident_dispositions,
            operation_completion=facts.operation_completion,
        )
        command = OperationalControlCommand(
            scope_id=account_id,
            idempotency_key=idempotency_key,
            kind=OperationalControlCommandKind.REARM,
            target_state=OperationalControlState.RUNNING,
            actor=actor,
            reason_code=reason_code,
            reason_evidence_sha256=reason_evidence_sha256,
            requested_at=requested_at,
            rearm_evidence_sha256=evidence.semantic_sha256,
        )
        return self._repository.apply_authenticated_rearm(command, evidence)


@dataclass(frozen=True, slots=True)
class ApprovedAdvancedRiskAssignment:
    """Server configuration for the one policy an operator may assign."""

    policy_id: str
    policy_sha256: str
    environment: str
    approval_evidence_sha256: str


class CurrentAccountFenceAuthority(Protocol):
    """Return the process's current exact account authority, or fail closed."""

    def current_fence(
        self,
        account_id: str,
        *,
        checked_at: datetime,
    ) -> AccountFence | None: ...


class AdvancedRiskAssignmentRepository(Protocol):
    def current_assignment(
        self,
        account_id: str,
    ) -> AdvancedRiskPolicyAssignment | None: ...

    def assign(
        self,
        command: AdvancedRiskAssignmentCommand,
        fence: AccountFence,
    ) -> AdvancedRiskPolicyAssignment: ...


class FencedAdvancedRiskAssignmentService:
    """Assign only the server-approved policy through a current account fence."""

    __slots__ = ("_approved", "_authority_sha256", "_clock", "_fences", "_repository")

    def __init__(
        self,
        *,
        repository: AdvancedRiskAssignmentRepository,
        current_fence_authority: CurrentAccountFenceAuthority,
        approved: ApprovedAdvancedRiskAssignment,
        actor_authority_sha256: str,
        clock: UtcClock,
    ) -> None:
        if not all(
            callable(getattr(repository, method, None))
            for method in ("current_assignment", "assign")
        ):
            raise OperationalControlError("advanced-risk assignment requires a fenced repository")
        if not callable(getattr(current_fence_authority, "current_fence", None)):
            raise OperationalControlError(
                "advanced-risk assignment requires current-fence authority"
            )
        if type(approved) is not ApprovedAdvancedRiskAssignment:
            raise OperationalControlError(
                "advanced-risk assignment requires an approved server binding"
            )
        if not callable(clock):
            raise OperationalControlError("advanced-risk assignment requires a trusted clock")
        # The command validates every binding, including paper-only scope.
        AdvancedRiskAssignmentCommand(
            account_id="advanced-risk-assignment-validation",
            environment=approved.environment,
            idempotency_key="validation-key-0001",
            policy_id=approved.policy_id,
            policy_sha256=approved.policy_sha256,
            actor_id="local-operations-authority-validation",
            actor_authority_sha256=actor_authority_sha256,
            actor_authenticated_at=datetime(2000, 1, 1, tzinfo=UTC),
            requested_at=datetime(2000, 1, 1, tzinfo=UTC),
            approval_evidence_sha256=approved.approval_evidence_sha256,
            expected_assignment_sequence_number=0,
            expected_assignment_sha256=None,
        )
        self._repository = repository
        self._fences = current_fence_authority
        self._approved = approved
        self._authority_sha256 = actor_authority_sha256
        self._clock = clock

    @property
    def approved_policy_id(self) -> str:
        return self._approved.policy_id

    def assign(
        self,
        *,
        account_id: str,
        operator_id: str,
        idempotency_key: str,
    ) -> AdvancedRiskPolicyAssignment:
        requested_at = _read_utc(self._clock)
        fence = self._fences.current_fence(account_id, checked_at=requested_at)
        if type(fence) is not AccountFence or fence.account_id != account_id:
            raise OperationalControlError(
                "advanced-risk assignment has no current exact account fence"
            )
        current = self._repository.current_assignment(account_id)
        command_id = canonical_id(
            "advanced-risk-assignment-command",
            ADVANCED_RISK_ASSIGNMENT_CONTRACT_VERSION,
            account_id,
            operator_id,
            idempotency_key,
        )
        if current is not None and current.command_id == command_id:
            if (
                current.policy_id != self._approved.policy_id
                or current.policy_sha256 != self._approved.policy_sha256
                or current.actor_id != operator_id
                or current.actor_authority_sha256 != self._authority_sha256
                or current.environment != self._approved.environment
            ):
                raise OperationalControlConflict("advanced-risk assignment idempotency conflicts")
            return current
        command = AdvancedRiskAssignmentCommand(
            account_id=account_id,
            environment=self._approved.environment,
            idempotency_key=idempotency_key,
            policy_id=self._approved.policy_id,
            policy_sha256=self._approved.policy_sha256,
            actor_id=operator_id,
            actor_authority_sha256=self._authority_sha256,
            actor_authenticated_at=requested_at,
            requested_at=requested_at,
            approval_evidence_sha256=self._approved.approval_evidence_sha256,
            expected_assignment_sequence_number=(0 if current is None else current.sequence_number),
            expected_assignment_sha256=(None if current is None else current.semantic_sha256),
        )
        return self._repository.assign(command, fence)
