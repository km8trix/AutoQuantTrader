from __future__ import annotations

import hashlib
from datetime import timedelta

import pytest

from packages.domain.operational_control import (
    OperationalControlActorKind,
    OperationalControlCommandKind,
    OperationalControlState,
)
from packages.domain.strategy_supervision import (
    STRATEGY_SUBPROCESS_PROTOCOL_VERSION,
    StrategyProtocolResponse,
    StrategySupervisionOutcome,
    StrategySupervisionResult,
)
from packages.domain.strategy_supervision_control import (
    STRATEGY_SUPERVISION_BREAKER_ACTOR_ID,
    STRATEGY_SUPERVISION_BREAKER_AUTHORITY_SHA256,
    STRATEGY_SUPERVISION_CONTROL_POLICY_SHA256,
    strategy_supervision_trip_command,
)
from tests.unit.test_strategy_supervision import _failed_result, _invocation


@pytest.mark.parametrize(
    "outcome",
    (
        StrategySupervisionOutcome.TIMEOUT,
        StrategySupervisionOutcome.CRASH,
        StrategySupervisionOutcome.PROTOCOL_ERROR,
        StrategySupervisionOutcome.RESOURCE_EXCEEDED,
    ),
)
def test_every_failure_maps_to_the_same_idempotent_pause_only_authority(
    outcome: StrategySupervisionOutcome,
) -> None:
    _, invocation = _invocation()
    result = _failed_result(outcome)

    first = strategy_supervision_trip_command(invocation, result)
    second = strategy_supervision_trip_command(invocation, result)

    assert first == second
    assert first is not None
    assert first.kind is OperationalControlCommandKind.TRIP
    assert first.target_state is OperationalControlState.PAUSED
    assert first.actor.kind is OperationalControlActorKind.CIRCUIT_BREAKER
    assert first.actor.actor_id == STRATEGY_SUPERVISION_BREAKER_ACTOR_ID
    assert first.actor.authority_sha256 == STRATEGY_SUPERVISION_BREAKER_AUTHORITY_SHA256
    assert first.reason_evidence_sha256 == result.semantic_sha256
    assert first.trip_policy_sha256 == STRATEGY_SUPERVISION_CONTROL_POLICY_SHA256
    assert first.trip_observation_sha256 == result.semantic_sha256


def test_completed_child_never_requests_running_or_any_control_command() -> None:
    _, invocation = _invocation()
    result_json = "{}"
    response = StrategyProtocolResponse(
        invocation_id=invocation.invocation_id,
        invocation_sha256=invocation.semantic_sha256,
        protocol_version=STRATEGY_SUBPROCESS_PROTOCOL_VERSION,
        result_json=result_json,
        result_sha256=hashlib.sha256(result_json.encode()).hexdigest(),
    )
    result = StrategySupervisionResult(
        invocation_id=invocation.invocation_id,
        invocation_sha256=invocation.semantic_sha256,
        outcome=StrategySupervisionOutcome.COMPLETED,
        started_at=invocation.requested_at,
        completed_at=invocation.requested_at + timedelta(milliseconds=10),
        elapsed_microseconds=10_000,
        process_started=True,
        exit_code=0,
        stdout_bytes=2,
        stdout_sha256=hashlib.sha256(b"{}").hexdigest(),
        stderr_bytes=0,
        stderr_sha256=hashlib.sha256(b"").hexdigest(),
        detail_code="completed",
        response=response,
    )

    assert strategy_supervision_trip_command(invocation, result) is None
