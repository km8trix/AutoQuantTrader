from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext

import pytest

import packages.domain.operational_control as operational_control
from packages.domain.batch_risk import BatchRiskOperationalState
from packages.domain.operational_control import (
    OPERATIONAL_CONTROL_CONTRACT_VERSION,
    OPERATIONAL_CONTROL_POLICY_SHA256,
    OperationalControlAbsent,
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlCompletion,
    OperationalControlCompletionOutcome,
    OperationalControlConflict,
    OperationalControlError,
    OperationalControlIncidentDisposition,
    OperationalControlOperationConflict,
    OperationalControlRearmEvidence,
    OperationalControlRearmRejected,
    OperationalControlResidualFacts,
    OperationalControlResidualPosition,
    OperationalControlState,
    OperationalControlTransition,
    _operational_control_rearm_evidence,
    apply_operational_control_command,
    batch_risk_operational_state,
    fail_closed_operational_control_state,
    record_operational_control_completion,
)

BASE = datetime(2026, 7, 28, 14, 30, tzinfo=UTC)


def _sha(character: str) -> str:
    return character * 64


def _actor(
    kind: OperationalControlActorKind = OperationalControlActorKind.HUMAN,
    *,
    actor_id: str = "operator-1",
) -> OperationalControlActor:
    return OperationalControlActor(
        actor_id=actor_id,
        kind=kind,
        authority_sha256=_sha("a"),
        authenticated_at=BASE if kind is OperationalControlActorKind.HUMAN else None,
    )


_TARGETS = {
    OperationalControlCommandKind.INITIALIZE_HALTED: OperationalControlState.HALTED,
    OperationalControlCommandKind.PAUSE: OperationalControlState.PAUSED,
    OperationalControlCommandKind.DRAIN: OperationalControlState.DRAINING,
    OperationalControlCommandKind.FLATTEN: OperationalControlState.FLATTENING,
    OperationalControlCommandKind.HALT: OperationalControlState.HALTED,
}


def _command(
    kind: OperationalControlCommandKind,
    *,
    key: str,
    requested_at: datetime = BASE,
    actor: OperationalControlActor | None = None,
    target: OperationalControlState | None = None,
    rearm_evidence: OperationalControlRearmEvidence | None = None,
) -> OperationalControlCommand:
    selected_actor = actor
    if selected_actor is None:
        selected_actor = (
            _actor(OperationalControlActorKind.SYSTEM, actor_id="bootstrap")
            if kind is OperationalControlCommandKind.INITIALIZE_HALTED
            else _actor()
        )
    selected_target = target
    if selected_target is None:
        selected_target = (
            OperationalControlState.RUNNING
            if kind is OperationalControlCommandKind.REARM
            else _TARGETS[kind]
        )
    trip = kind is OperationalControlCommandKind.TRIP
    return OperationalControlCommand(
        scope_id="account-1",
        idempotency_key=key,
        kind=kind,
        target_state=selected_target,
        actor=selected_actor,
        reason_code=f"reason-{kind.value}",
        reason_evidence_sha256=_sha("b"),
        requested_at=requested_at,
        rearm_evidence_sha256=(None if rearm_evidence is None else rearm_evidence.semantic_sha256),
        trip_rule_id="rule-1" if trip else None,
        trip_policy_sha256=_sha("c") if trip else None,
        trip_observation_sha256=_sha("d") if trip else None,
    )


def _initialize() -> OperationalControlTransition:
    return apply_operational_control_command(
        None,
        _command(
            OperationalControlCommandKind.INITIALIZE_HALTED,
            key="initialize-0001",
        ),
        decided_at=BASE,
    )


def _dispositions(
    current: OperationalControlTransition,
    *,
    resolved_at: datetime,
) -> tuple[OperationalControlIncidentDisposition, ...]:
    return tuple(
        sorted(
            (
                OperationalControlIncidentDisposition(
                    event_id=event.event_id,
                    event_sha256=event.semantic_sha256,
                    resolution_code="operator-reviewed",
                    resolution_evidence_sha256=_sha("e"),
                    resolved_at=resolved_at,
                )
                for event in current.blocking_events
            ),
            key=lambda item: item.event_id,
        )
    )


def _rearm_evidence(
    current: OperationalControlTransition,
    *,
    actor: OperationalControlActor,
    checked_at: datetime,
    expires_at: datetime | None = None,
    reconciliation_clean: bool = True,
    data_healthy: bool = True,
    clock_healthy: bool = True,
    working_order_ids: tuple[str, ...] = (),
    unknown_order_ids: tuple[str, ...] = (),
    pending_cancel_order_ids: tuple[str, ...] = (),
    dispositions: tuple[OperationalControlIncidentDisposition, ...] | None = None,
    completion: OperationalControlCompletion | None = None,
) -> OperationalControlRearmEvidence:
    return _operational_control_rearm_evidence(
        scope_id=current.scope_id,
        current_transition_id=current.transition_id,
        current_transition_sha256=current.semantic_sha256,
        current_state=current.effective_state,
        current_state_epoch_id=current.state_epoch_id,
        actor=actor,
        checked_at=checked_at,
        expires_at=(checked_at + timedelta(seconds=30) if expires_at is None else expires_at),
        readiness_sha256=_sha("f"),
        reconciliation_sha256=_sha("1"),
        incident_register_sha256=_sha("2"),
        reconciliation_clean=reconciliation_clean,
        data_healthy=data_healthy,
        clock_healthy=clock_healthy,
        working_order_ids=working_order_ids,
        unknown_order_ids=unknown_order_ids,
        pending_cancel_order_ids=pending_cancel_order_ids,
        incident_dispositions=(
            _dispositions(current, resolved_at=checked_at) if dispositions is None else dispositions
        ),
        operation_completion=completion,
    )


def _to_running() -> OperationalControlTransition:
    initial = _initialize()
    human = _actor()
    checked_at = BASE + timedelta(seconds=1)
    evidence = _rearm_evidence(initial, actor=human, checked_at=checked_at)
    return apply_operational_control_command(
        initial,
        _command(
            OperationalControlCommandKind.REARM,
            key="rearm-0001",
            requested_at=checked_at,
            actor=human,
            rearm_evidence=evidence,
        ),
        decided_at=checked_at,
        rearm_evidence=evidence,
    )


def _advance(
    current: OperationalControlTransition,
    kind: OperationalControlCommandKind,
    *,
    key: str,
    second: int,
    active_operation_completion: OperationalControlCompletion | None = None,
) -> OperationalControlTransition:
    instant = BASE + timedelta(seconds=second)
    return apply_operational_control_command(
        current,
        _command(kind, key=key, requested_at=instant),
        decided_at=instant,
        active_operation_completion=active_operation_completion,
    )


def _residual(
    *,
    terminal_order_count: int = 3,
    working: tuple[str, ...] = (),
    unknown: tuple[str, ...] = (),
    pending_cancel: tuple[str, ...] = (),
    positions: tuple[OperationalControlResidualPosition, ...] = (),
    clean: bool = True,
) -> OperationalControlResidualFacts:
    return OperationalControlResidualFacts(
        terminal_order_count=terminal_order_count,
        working_order_ids=working,
        unknown_order_ids=unknown,
        pending_cancel_order_ids=pending_cancel,
        positions=positions,
        reconciliation_clean=clean,
        source_evidence_sha256=_sha("3"),
    )


def test_contract_and_actor_scoped_command_identity_are_pinned() -> None:
    first = _command(OperationalControlCommandKind.PAUSE, key="pause-key-01")
    same = _command(OperationalControlCommandKind.PAUSE, key="pause-key-01")
    other_actor = _command(
        OperationalControlCommandKind.PAUSE,
        key="pause-key-01",
        actor=_actor(actor_id="operator-2"),
    )
    changed = replace(first, reason_code="changed")

    assert OPERATIONAL_CONTROL_CONTRACT_VERSION == "phase5a-operational-control-v1"
    assert OPERATIONAL_CONTROL_POLICY_SHA256 == (
        "2f977287c78f590335b6176e67967d23cb55d22ad88ba6b09a40c4cdcf70759e"
    )
    assert first.command_id == same.command_id
    assert first.semantic_sha256 == same.semantic_sha256
    assert other_actor.command_id != first.command_id
    assert changed.command_id == first.command_id
    assert changed.semantic_sha256 != first.semantic_sha256


def test_absence_only_initializes_audited_halted_state() -> None:
    with pytest.raises(OperationalControlAbsent, match="INITIALIZE_HALTED"):
        apply_operational_control_command(
            None,
            _command(OperationalControlCommandKind.PAUSE, key="pause-absent"),
            decided_at=BASE,
        )

    initial = _initialize()
    assert initial.prior_state is None
    assert initial.effective_state is OperationalControlState.HALTED
    assert initial.state_changed
    assert initial.state_epoch_id == initial.transition_id
    assert len(initial.blocking_events) == 1
    assert fail_closed_operational_control_state(None) is OperationalControlState.HALTED
    assert batch_risk_operational_state(None) is BatchRiskOperationalState.HALTED


@pytest.mark.parametrize(
    ("current_kind", "requested_kind", "expected"),
    (
        (None, OperationalControlCommandKind.PAUSE, OperationalControlState.PAUSED),
        (None, OperationalControlCommandKind.DRAIN, OperationalControlState.DRAINING),
        (None, OperationalControlCommandKind.FLATTEN, OperationalControlState.FLATTENING),
        (None, OperationalControlCommandKind.HALT, OperationalControlState.HALTED),
        (
            OperationalControlCommandKind.PAUSE,
            OperationalControlCommandKind.DRAIN,
            OperationalControlState.DRAINING,
        ),
        (
            OperationalControlCommandKind.DRAIN,
            OperationalControlCommandKind.PAUSE,
            OperationalControlState.DRAINING,
        ),
        (
            OperationalControlCommandKind.DRAIN,
            OperationalControlCommandKind.FLATTEN,
            OperationalControlState.FLATTENING,
        ),
        (
            OperationalControlCommandKind.FLATTEN,
            OperationalControlCommandKind.DRAIN,
            OperationalControlState.FLATTENING,
        ),
        (
            OperationalControlCommandKind.FLATTEN,
            OperationalControlCommandKind.HALT,
            OperationalControlState.HALTED,
        ),
        (
            OperationalControlCommandKind.HALT,
            OperationalControlCommandKind.PAUSE,
            OperationalControlState.HALTED,
        ),
    ),
)
def test_non_rearm_commands_apply_severity_join_and_audit_noops(
    current_kind: OperationalControlCommandKind | None,
    requested_kind: OperationalControlCommandKind,
    expected: OperationalControlState,
) -> None:
    current = _to_running()
    second = 2
    if current_kind is not None:
        current = _advance(
            current,
            current_kind,
            key=f"current-{current_kind.value}",
            second=second,
        )
        second += 1
    prior_sequence = current.sequence_number
    prior_blocker_count = len(current.blocking_events)

    result = _advance(
        current,
        requested_kind,
        key=f"requested-{requested_kind.value}",
        second=second,
    )

    assert result.effective_state is expected
    assert result.sequence_number == prior_sequence + 1
    assert len(result.blocking_events) == prior_blocker_count + 1
    if result.effective_state is current.effective_state:
        assert not result.state_changed


def test_breaker_requires_exact_rule_policy_and_observation_and_never_resumes() -> None:
    running = _to_running()
    instant = BASE + timedelta(seconds=2)
    breaker = _actor(
        OperationalControlActorKind.CIRCUIT_BREAKER,
        actor_id="drawdown-breaker",
    )
    trip = _command(
        OperationalControlCommandKind.TRIP,
        key="breaker-trip-01",
        actor=breaker,
        requested_at=instant,
        target=OperationalControlState.PAUSED,
    )
    paused = apply_operational_control_command(
        running,
        trip,
        decided_at=instant,
    )

    assert paused.effective_state is OperationalControlState.PAUSED
    with pytest.raises(OperationalControlError, match="observation_sha256"):
        replace(trip, trip_observation_sha256=None)
    with pytest.raises(OperationalControlError, match="PAUSED or HALTED"):
        replace(trip, target_state=OperationalControlState.RUNNING)


def test_exact_current_command_retry_returns_original_and_changed_payload_conflicts() -> None:
    running = _to_running()
    instant = BASE + timedelta(seconds=2)
    command = _command(
        OperationalControlCommandKind.PAUSE,
        key="pause-exact-retry",
        requested_at=instant,
    )
    first = apply_operational_control_command(running, command, decided_at=instant)
    assert (
        apply_operational_control_command(
            first,
            command,
            decided_at=instant + timedelta(seconds=1),
        )
        == first
    )
    with pytest.raises(OperationalControlConflict, match="idempotency"):
        apply_operational_control_command(
            first,
            replace(command, reason_code="changed"),
            decided_at=instant + timedelta(seconds=1),
        )


def test_drain_complete_allows_positions_but_requires_terminal_orders_and_clean_recon() -> None:
    drain = _advance(
        _to_running(),
        OperationalControlCommandKind.DRAIN,
        key="drain-start-01",
        second=2,
    )
    position = OperationalControlResidualPosition(
        instrument_id="SPY",
        quantity=Decimal("5"),
        gross_exposure=Decimal("2500"),
    )
    completion = record_operational_control_completion(
        drain,
        idempotency_key="drain-complete-01",
        outcome=OperationalControlCompletionOutcome.COMPLETED,
        observed_at=BASE + timedelta(seconds=3),
        evidence_sha256=_sha("4"),
        residual_facts=_residual(positions=(position,)),
    )

    assert completion.residual_facts.positions == (position,)
    with pytest.raises(OperationalControlConflict, match="terminal known orders"):
        record_operational_control_completion(
            drain,
            idempotency_key="drain-invalid-02",
            outcome=OperationalControlCompletionOutcome.COMPLETED,
            observed_at=BASE + timedelta(seconds=3),
            evidence_sha256=_sha("4"),
            residual_facts=_residual(pending_cancel=("order-1",)),
        )


def test_incomplete_flatten_retry_survives_intervening_lower_noop() -> None:
    flatten = _advance(
        _to_running(),
        OperationalControlCommandKind.FLATTEN,
        key="flatten-start-01",
        second=2,
    )
    position = OperationalControlResidualPosition(
        instrument_id="SPY",
        quantity=Decimal("2"),
        gross_exposure=Decimal("1000"),
    )
    incomplete = record_operational_control_completion(
        flatten,
        idempotency_key="flatten-incomplete-01",
        outcome=OperationalControlCompletionOutcome.INCOMPLETE,
        observed_at=BASE + timedelta(seconds=3),
        evidence_sha256=_sha("5"),
        residual_facts=_residual(
            pending_cancel=("order-pending",),
            positions=(position,),
            clean=False,
        ),
        incomplete_reason="market closed",
    )
    noop = _advance(
        flatten,
        OperationalControlCommandKind.PAUSE,
        key="pause-during-flatten",
        second=4,
    )
    assert noop.active_operation == flatten.active_operation

    retried = _advance(
        noop,
        OperationalControlCommandKind.FLATTEN,
        key="flatten-retry-02",
        second=5,
        active_operation_completion=incomplete,
    )

    assert retried.effective_state is OperationalControlState.FLATTENING
    assert not retried.state_changed
    assert retried.active_operation != flatten.active_operation


def test_complete_operation_cannot_be_used_to_open_another_attempt() -> None:
    drain = _advance(
        _to_running(),
        OperationalControlCommandKind.DRAIN,
        key="drain-start-03",
        second=2,
    )
    complete = record_operational_control_completion(
        drain,
        idempotency_key="drain-complete-03",
        outcome=OperationalControlCompletionOutcome.COMPLETED,
        observed_at=BASE + timedelta(seconds=3),
        evidence_sha256=_sha("6"),
        residual_facts=_residual(),
    )
    with pytest.raises(OperationalControlOperationConflict, match="incomplete or deadline"):
        _advance(
            drain,
            OperationalControlCommandKind.DRAIN,
            key="drain-retry-complete",
            second=4,
            active_operation_completion=complete,
        )


def test_incomplete_or_deadline_requires_reason_and_explicit_residual() -> None:
    drain = _advance(
        _to_running(),
        OperationalControlCommandKind.DRAIN,
        key="drain-start-04",
        second=2,
    )
    with pytest.raises(OperationalControlError, match="reason"):
        record_operational_control_completion(
            drain,
            idempotency_key="drain-incomplete-empty",
            outcome=OperationalControlCompletionOutcome.INCOMPLETE,
            observed_at=BASE + timedelta(seconds=3),
            evidence_sha256=_sha("7"),
            residual_facts=_residual(),
        )
    with pytest.raises(OperationalControlConflict, match="elapsed deadline"):
        record_operational_control_completion(
            drain,
            idempotency_key="drain-deadline-future",
            outcome=OperationalControlCompletionOutcome.DEADLINE_EXCEEDED,
            observed_at=BASE + timedelta(seconds=3),
            evidence_sha256=_sha("7"),
            residual_facts=_residual(working=("order-1",), clean=False),
            incomplete_reason="deadline",
            deadline_at=BASE + timedelta(seconds=4),
        )


def test_residual_exposure_sum_is_context_independent_and_fits_bounded_aggregate() -> None:
    positions = (
        OperationalControlResidualPosition(
            instrument_id="QQQ",
            quantity=Decimal("1"),
            gross_exposure=Decimal("999999999999999999.9999999999"),
        ),
        OperationalControlResidualPosition(
            instrument_id="SPY",
            quantity=Decimal("1"),
            gross_exposure=Decimal("999999999999999999.9999999999"),
        ),
    )
    residuals = _residual(positions=positions)

    with localcontext() as context:
        context.prec = 28
        low_precision_sum = residuals.residual_gross_exposure
        low_precision_sha256 = residuals.semantic_sha256
    with localcontext() as context:
        context.prec = 50
        high_precision_sum = residuals.residual_gross_exposure
        high_precision_sha256 = residuals.semantic_sha256

    assert low_precision_sum == Decimal("1999999999999999999.9999999998")
    assert high_precision_sum == low_precision_sum
    assert high_precision_sha256 == low_precision_sha256


def test_complete_flatten_and_all_exact_dispositions_enable_manual_rearm() -> None:
    flatten = _advance(
        _to_running(),
        OperationalControlCommandKind.FLATTEN,
        key="flatten-start-05",
        second=2,
    )
    complete = record_operational_control_completion(
        flatten,
        idempotency_key="flatten-complete-05",
        outcome=OperationalControlCompletionOutcome.COMPLETED,
        observed_at=BASE + timedelta(seconds=3),
        evidence_sha256=_sha("8"),
        residual_facts=_residual(),
    )
    human = _actor()
    checked_at = BASE + timedelta(seconds=4)
    evidence = _rearm_evidence(
        flatten,
        actor=human,
        checked_at=checked_at,
        completion=complete,
    )
    rearmed = apply_operational_control_command(
        flatten,
        _command(
            OperationalControlCommandKind.REARM,
            key="rearm-flatten-05",
            requested_at=checked_at,
            actor=human,
            rearm_evidence=evidence,
        ),
        decided_at=checked_at,
        rearm_evidence=evidence,
    )

    assert rearmed.effective_state is OperationalControlState.RUNNING
    assert rearmed.blocking_events == ()
    assert rearmed.active_operation is None


@pytest.mark.parametrize(
    ("missing", "message"),
    (
        ("reconciliation_clean", "healthy and clean"),
        ("data_healthy", "healthy and clean"),
        ("clock_healthy", "healthy and clean"),
        ("working_order_ids", "healthy and clean"),
        ("unknown_order_ids", "healthy and clean"),
        ("pending_cancel_order_ids", "healthy and clean"),
        ("dispositions", "dispose every"),
    ),
)
def test_rearm_rejects_each_missing_prerequisite(
    missing: str,
    message: str,
) -> None:
    initial = _initialize()
    human = _actor()
    checked_at = BASE + timedelta(seconds=1)
    evidence = _rearm_evidence(
        initial,
        actor=human,
        checked_at=checked_at,
        reconciliation_clean=missing != "reconciliation_clean",
        data_healthy=missing != "data_healthy",
        clock_healthy=missing != "clock_healthy",
        working_order_ids=("order-1",) if missing == "working_order_ids" else (),
        unknown_order_ids=("order-1",) if missing == "unknown_order_ids" else (),
        pending_cancel_order_ids=(("order-1",) if missing == "pending_cancel_order_ids" else ()),
        dispositions=() if missing == "dispositions" else None,
    )
    with pytest.raises(OperationalControlRearmRejected, match=message):
        apply_operational_control_command(
            initial,
            _command(
                OperationalControlCommandKind.REARM,
                key=f"rearm-invalid-{missing}",
                requested_at=checked_at,
                actor=human,
                rearm_evidence=evidence,
            ),
            decided_at=checked_at,
            rearm_evidence=evidence,
        )


def test_rearm_expiry_equality_and_stale_head_fail_closed() -> None:
    initial = _initialize()
    human = _actor()
    checked_at = BASE + timedelta(seconds=1)
    with pytest.raises(OperationalControlError, match="expiry"):
        _rearm_evidence(
            initial,
            actor=human,
            checked_at=checked_at,
            expires_at=checked_at,
        )
    boundary = _rearm_evidence(
        initial,
        actor=human,
        checked_at=checked_at,
        expires_at=checked_at + timedelta(seconds=2),
    )
    with pytest.raises(OperationalControlRearmRejected, match="fresh"):
        apply_operational_control_command(
            initial,
            _command(
                OperationalControlCommandKind.REARM,
                key="rearm-expiry-boundary",
                requested_at=checked_at + timedelta(seconds=2),
                actor=human,
                rearm_evidence=boundary,
            ),
            decided_at=checked_at + timedelta(seconds=2),
            rearm_evidence=boundary,
        )

    stale = _rearm_evidence(initial, actor=human, checked_at=checked_at)
    later = _advance(
        initial,
        OperationalControlCommandKind.HALT,
        key="halt-after-rearm-proof",
        second=2,
    )
    with pytest.raises(OperationalControlRearmRejected, match="exact current"):
        apply_operational_control_command(
            later,
            _command(
                OperationalControlCommandKind.REARM,
                key="rearm-stale-head",
                requested_at=BASE + timedelta(seconds=3),
                actor=human,
                rearm_evidence=stale,
            ),
            decided_at=BASE + timedelta(seconds=3),
            rearm_evidence=stale,
        )


def test_rearm_proof_cannot_be_caller_constructed() -> None:
    with pytest.raises(TypeError):
        OperationalControlRearmEvidence()


def test_blocker_projection_overflow_remains_escalatable_but_cannot_rearm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(operational_control, "MAX_OPERATIONAL_CONTROL_BLOCKERS", 2)
    paused = _advance(
        _to_running(),
        OperationalControlCommandKind.PAUSE,
        key="overflow-pause",
        second=2,
    )
    halted = _advance(
        paused,
        OperationalControlCommandKind.HALT,
        key="overflow-halt",
        second=3,
    )
    audited = _advance(
        halted,
        OperationalControlCommandKind.HALT,
        key="overflow-halt-noop",
        second=4,
    )
    assert audited.effective_state is OperationalControlState.HALTED
    assert audited.blocker_overflowed
    assert len(audited.blocking_events) == 2

    human = _actor()
    checked_at = BASE + timedelta(seconds=5)
    evidence = _rearm_evidence(audited, actor=human, checked_at=checked_at)
    with pytest.raises(OperationalControlRearmRejected, match="overflowed"):
        apply_operational_control_command(
            audited,
            _command(
                OperationalControlCommandKind.REARM,
                key="overflow-rearm",
                requested_at=checked_at,
                actor=human,
                rearm_evidence=evidence,
            ),
            decided_at=checked_at,
            rearm_evidence=evidence,
        )


def test_batch_risk_projection_preserves_existing_three_state_contract() -> None:
    assert (
        batch_risk_operational_state(OperationalControlState.RUNNING)
        is BatchRiskOperationalState.RUNNING
    )
    assert (
        batch_risk_operational_state(OperationalControlState.PAUSED)
        is BatchRiskOperationalState.PAUSED
    )
    assert (
        batch_risk_operational_state(OperationalControlState.DRAINING)
        is BatchRiskOperationalState.PAUSED
    )
    assert (
        batch_risk_operational_state(OperationalControlState.FLATTENING)
        is BatchRiskOperationalState.PAUSED
    )
    assert (
        batch_risk_operational_state(OperationalControlState.HALTED)
        is BatchRiskOperationalState.HALTED
    )
    with pytest.raises(OperationalControlError, match="unsupported"):
        batch_risk_operational_state("running")  # type: ignore[arg-type]
