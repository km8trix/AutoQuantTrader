"""Pure binding from supervised strategy failures to critical-alert incidents."""

from __future__ import annotations

import hashlib
from datetime import datetime

from packages.domain.canonical import canonical_json_bytes
from packages.domain.critical_alert import CriticalAlertIncident
from packages.domain.operational_control import OperationalControlTransition
from packages.domain.strategy_supervision import (
    STRATEGY_SUPERVISION_CONTRACT_VERSION,
    StrategyInvocation,
    StrategySupervisionConflict,
    StrategySupervisionOutcome,
    StrategySupervisionResult,
)

STRATEGY_SUPERVISION_ALERT_CONTRACT_VERSION = "phase5c-strategy-supervision-alert-v1"
STRATEGY_SUPERVISION_ALERT_SOURCE_ID = "strategy-supervisor"


def strategy_supervision_critical_alert(
    *,
    invocation: StrategyInvocation,
    result: StrategySupervisionResult,
    control_transition: OperationalControlTransition,
    recorded_at: datetime,
) -> CriticalAlertIncident | None:
    """Bind a failed child and its durable breaker transition to one incident."""

    if type(invocation) is not StrategyInvocation:
        raise StrategySupervisionConflict("strategy alert binding requires an exact invocation")
    if type(result) is not StrategySupervisionResult:
        raise StrategySupervisionConflict("strategy alert binding requires an exact result")
    if type(control_transition) is not OperationalControlTransition:
        raise StrategySupervisionConflict(
            "strategy alert binding requires an exact control transition"
        )
    invocation.__post_init__()
    result.__post_init__()
    control_transition.__post_init__()
    if (
        result.invocation_id != invocation.invocation_id
        or result.invocation_sha256 != invocation.semantic_sha256
        or control_transition.scope_id != invocation.control_scope_id
    ):
        raise StrategySupervisionConflict("strategy alert binding crosses source identities")
    if result.outcome is StrategySupervisionOutcome.COMPLETED:
        return None
    correlation_sha256 = hashlib.sha256(
        canonical_json_bytes(
            (
                STRATEGY_SUPERVISION_ALERT_CONTRACT_VERSION,
                STRATEGY_SUPERVISION_CONTRACT_VERSION,
                invocation.semantic_sha256,
                result.semantic_sha256,
                control_transition.semantic_sha256,
            )
        )
    ).hexdigest()
    return CriticalAlertIncident(
        scope_id=invocation.control_scope_id,
        source_id=STRATEGY_SUPERVISION_ALERT_SOURCE_ID,
        idempotency_key=f"strategy:{invocation.invocation_id}",
        alert_code=f"strategy_{result.outcome.value}",
        evidence_sha256=result.semantic_sha256,
        detected_at=result.completed_at,
        recorded_at=recorded_at,
        correlation_sha256=correlation_sha256,
    )
