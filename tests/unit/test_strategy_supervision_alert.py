from __future__ import annotations

from datetime import timedelta

from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlState,
    apply_operational_control_command,
)
from packages.domain.strategy_supervision import (
    StrategyInvocation,
    StrategySupervisionOutcome,
)
from packages.domain.strategy_supervision_alert import (
    STRATEGY_SUPERVISION_ALERT_SOURCE_ID,
    strategy_supervision_critical_alert,
)
from packages.domain.strategy_supervision_control import (
    strategy_supervision_trip_command,
)
from tests.unit.test_strategy_supervision import _failed_result, _invocation


def _failed_sources() -> tuple[object, object, object]:
    _, invocation_object = _invocation()
    assert type(invocation_object) is StrategyInvocation
    invocation = invocation_object
    initial_command = OperationalControlCommand(
        scope_id=invocation.control_scope_id,
        idempotency_key="alert-initialize",
        kind=OperationalControlCommandKind.INITIALIZE_HALTED,
        target_state=OperationalControlState.HALTED,
        actor=OperationalControlActor(
            actor_id="startup",
            kind=OperationalControlActorKind.SYSTEM,
            authority_sha256="a" * 64,
            authenticated_at=None,
        ),
        reason_code="startup",
        reason_evidence_sha256="b" * 64,
        requested_at=invocation.market_batch_as_of,
    )
    initial = apply_operational_control_command(
        None,
        initial_command,
        decided_at=invocation.market_batch_as_of,
    )
    result = _failed_result(StrategySupervisionOutcome.TIMEOUT)
    trip = strategy_supervision_trip_command(invocation, result)
    assert trip is not None
    final = apply_operational_control_command(
        initial,
        trip,
        decided_at=result.completed_at + timedelta(milliseconds=100),
    )
    return invocation, result, final


def test_failed_strategy_binds_one_source_idempotent_critical_incident() -> None:
    invocation_object, result_object, final_object = _failed_sources()
    from packages.domain.operational_control import OperationalControlTransition
    from packages.domain.strategy_supervision import StrategySupervisionResult

    assert type(invocation_object) is StrategyInvocation
    assert type(result_object) is StrategySupervisionResult
    assert type(final_object) is OperationalControlTransition
    recorded_at = result_object.completed_at + timedelta(milliseconds=200)

    first = strategy_supervision_critical_alert(
        invocation=invocation_object,
        result=result_object,
        control_transition=final_object,
        recorded_at=recorded_at,
    )
    second = strategy_supervision_critical_alert(
        invocation=invocation_object,
        result=result_object,
        control_transition=final_object,
        recorded_at=recorded_at,
    )

    assert first == second
    assert first is not None
    assert first.source_id == STRATEGY_SUPERVISION_ALERT_SOURCE_ID
    assert first.alert_code == "strategy_timeout"
    assert first.evidence_sha256 == result_object.semantic_sha256
    assert first.local_durability_milestone_met is True
    assert first.requested_control_state is None
    assert first.broker_action_authorized is False


def test_completed_strategy_does_not_create_a_critical_incident() -> None:
    invocation_object, _, final_object = _failed_sources()
    from packages.domain.operational_control import OperationalControlTransition
    from packages.domain.strategy_supervision import (
        StrategyProtocolResponse,
        StrategySupervisionResult,
    )

    assert type(invocation_object) is StrategyInvocation
    assert type(final_object) is OperationalControlTransition
    response = StrategyProtocolResponse(
        invocation_id=invocation_object.invocation_id,
        invocation_sha256=invocation_object.semantic_sha256,
        protocol_version=invocation_object.protocol_version,
        result_json="{}",
        result_sha256=("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"),
    )
    result = StrategySupervisionResult(
        invocation_id=invocation_object.invocation_id,
        invocation_sha256=invocation_object.semantic_sha256,
        outcome=StrategySupervisionOutcome.COMPLETED,
        started_at=invocation_object.requested_at,
        completed_at=invocation_object.requested_at + timedelta(milliseconds=1),
        elapsed_microseconds=1_000,
        process_started=True,
        exit_code=0,
        stdout_bytes=2,
        stdout_sha256=response.result_sha256,
        stderr_bytes=0,
        stderr_sha256=("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        detail_code="completed",
        response=response,
    )

    assert (
        strategy_supervision_critical_alert(
            invocation=invocation_object,
            result=result,
            control_transition=final_object,
            recorded_at=result.completed_at,
        )
        is None
    )
