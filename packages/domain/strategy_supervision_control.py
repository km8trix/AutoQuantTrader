"""Pure binding from supervised strategy failures to Phase 5A PAUSED trips."""

from __future__ import annotations

import hashlib

from packages.domain.canonical import canonical_json_bytes
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlState,
)
from packages.domain.strategy_supervision import (
    STRATEGY_DECISION_DEADLINE_MICROSECONDS,
    STRATEGY_DECISION_WARNING_MICROSECONDS,
    STRATEGY_SUPERVISION_CONTRACT_VERSION,
    StrategyInvocation,
    StrategySupervisionConflict,
    StrategySupervisionOutcome,
    StrategySupervisionResult,
)

STRATEGY_SUPERVISION_BREAKER_ACTOR_ID = "phase5c-strategy-supervisor"
STRATEGY_SUPERVISION_CONTROL_POLICY_SHA256 = hashlib.sha256(
    canonical_json_bytes(
        (
            STRATEGY_SUPERVISION_CONTRACT_VERSION,
            "strategy_supervision_control_policy",
            STRATEGY_DECISION_WARNING_MICROSECONDS,
            STRATEGY_DECISION_DEADLINE_MICROSECONDS,
            tuple(StrategySupervisionOutcome),
            "every_noncompleted_outcome_requests_paused",
            "completed_never_requests_running",
            "no_automatic_rearm",
        )
    )
).hexdigest()
STRATEGY_SUPERVISION_BREAKER_AUTHORITY_SHA256 = hashlib.sha256(
    canonical_json_bytes(
        (
            STRATEGY_SUPERVISION_CONTROL_POLICY_SHA256,
            "strategy_supervision_breaker_authority",
            STRATEGY_SUPERVISION_BREAKER_ACTOR_ID,
            "pause_only",
        )
    )
).hexdigest()


def strategy_supervision_trip_command(
    invocation: StrategyInvocation,
    result: StrategySupervisionResult,
) -> OperationalControlCommand | None:
    """Return the exact PAUSED trip for a failed invocation, or none on success."""

    if type(invocation) is not StrategyInvocation:
        raise StrategySupervisionConflict("strategy control binding requires an exact invocation")
    if type(result) is not StrategySupervisionResult:
        raise StrategySupervisionConflict("strategy control binding requires an exact result")
    invocation.__post_init__()
    result.__post_init__()
    if (
        result.invocation_id != invocation.invocation_id
        or result.invocation_sha256 != invocation.semantic_sha256
    ):
        raise StrategySupervisionConflict("strategy control result crosses invocation identity")
    if result.outcome is StrategySupervisionOutcome.COMPLETED:
        return None
    return OperationalControlCommand(
        scope_id=invocation.control_scope_id,
        idempotency_key=f"strategy-failure:{invocation.invocation_id}",
        kind=OperationalControlCommandKind.TRIP,
        target_state=OperationalControlState.PAUSED,
        actor=OperationalControlActor(
            actor_id=STRATEGY_SUPERVISION_BREAKER_ACTOR_ID,
            kind=OperationalControlActorKind.CIRCUIT_BREAKER,
            authority_sha256=STRATEGY_SUPERVISION_BREAKER_AUTHORITY_SHA256,
            authenticated_at=None,
        ),
        reason_code=f"strategy_{result.outcome.value}",
        reason_evidence_sha256=result.semantic_sha256,
        requested_at=result.completed_at,
        trip_rule_id="strategy_subprocess_failure",
        trip_policy_sha256=STRATEGY_SUPERVISION_CONTROL_POLICY_SHA256,
        trip_observation_sha256=result.semantic_sha256,
    )
