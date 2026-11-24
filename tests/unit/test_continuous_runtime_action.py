"""Internal action engine values only; SQL attempt/source proof remains separate."""

from dataclasses import replace
from datetime import timedelta

import pytest

from packages.application.causal_engine import (
    apply_continuous_runtime_action,
    continuous_runtime_action_context,
)
from packages.application.continuous_account_transition import ContinuousAccountTransitionPreparer
from packages.application.personal_codec import decode_record, encode_record
from packages.application.reference_strategy import ReferenceStrategy
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.accounting_contracts import (
    AccountingCommand,
    ActivateRuntimeCommitments,
    ControlCommand,
    ReleaseRuntimeUnsent,
    RuntimeActivationTerms,
)
from packages.domain.continuous_engine_contracts import ClosedEngineFrontier
from packages.domain.continuous_runtime_action import ContinuousRuntimeAction
from packages.domain.engine_contracts import EngineEvent
from packages.domain.personal_contracts import content_digest
from tests.unit.test_continuous_engine import FixtureEvidence, step
from tests.unit.test_continuous_source_events import advance, project, setup


def case():
    checkpoint, sources = setup(False)
    checkpoint = advance(checkpoint, project(checkpoint, sources))
    hold = checkpoint.state.commitments[0]
    assert hold.state == "approved_unsent"
    boundary = ClosedEngineFrontier(
        frontier_id="after-send-window",
        stream_id=checkpoint.inputs.spec.run_id,
        previous_checkpoint_sha256=checkpoint.semantic_sha256,
        source_frontier_sha256="b" * 64,
        knowledge_at=hold.expires_at + timedelta(seconds=1),
        events=(),
    )
    checkpoint = advance(checkpoint, boundary)
    command = AccountingCommand(
        "release-observed-unsent",
        ReleaseRuntimeUnsent(
            account_id=checkpoint.state.account_id,
            commitment_id=hold.commitment_id,
            expected_commitment_sha256=hold.semantic_sha256,
            source_state_sha256=checkpoint.state.semantic_sha256,
            attempt_history_sha256="c" * 64,
            locked_unsent_proof_sha256="d" * 64,
            proof_at=checkpoint.now,
            reason="expired",
        ),
    )
    action = ContinuousRuntimeAction(
        action_id="unsent-expiry",
        stream_id=checkpoint.inputs.spec.run_id,
        previous_checkpoint_sha256=checkpoint.semantic_sha256,
        source_closure_sha256="e" * 64,
        checked_at=checkpoint.now,
        command=command,
    )
    return checkpoint, action


def apply(checkpoint, action):
    return apply_continuous_runtime_action(
        checkpoint,
        action,
        expected_sha256=checkpoint.semantic_sha256,
        accounting=PersonalAccounting(),
        strategy=ReferenceStrategy(),
        runtime_evidence=FixtureEvidence(checkpoint.inputs.spec),
    )


def activation_case():
    """Actual engine history/mark; explicitly synthetic activation provenance only."""
    checkpoint, sources = setup(False)
    checkpoint = advance(checkpoint, project(checkpoint, sources))
    hold = checkpoint.state.commitments[0]
    at = hold.not_before
    old_mark = next(m for m in checkpoint.state.marks if m.instrument_id == hold.instrument_id)
    mark = replace(
        old_mark,
        mark_id="fresh-fixture-quote",
        session=hold.execution_session,
        economic_at=at,
        knowledge_at=at,
        source_sha256="c" * 64,
        basis="runtime_quote_ask_v1",
    )
    command = AccountingCommand(mark.mark_id, mark)
    provenance = replace(
        checkpoint.inputs.bootstrap_events[0].provenance,
        normalized_sha256=content_digest(command),
        simulated_available_at=at,
    )
    checkpoint, _ = step(
        checkpoint,
        (EngineEvent(mark.mark_id, at, at, command, provenance),),
    )
    payload = ActivateRuntimeCommitments(
        account_id=checkpoint.state.account_id,
        source_state_sha256=checkpoint.state.semantic_sha256,
        source_snapshot_sha256=checkpoint.current.snapshot.semantic_sha256,
        original_policy_sha256=hold.policy_sha256,
        decision_sha256="d" * 64,
        evidence_sha256="e" * 64,
        checked_at=checkpoint.now,
        expires_at=checkpoint.now + timedelta(seconds=1),
        terms=(
            RuntimeActivationTerms(
                commitment_id=hold.commitment_id,
                expected_commitment_sha256=hold.semantic_sha256,
                reserved_cash=hold.reserved_cash,
                reserved_sell_quantity=hold.reserved_sell_quantity,
                approved_price=hold.approved_price,
                remaining_fee_budget=hold.remaining_fee_budget,
                activation_sha256="f" * 64,
                dispatch_sha256="a" * 64,
            ),
        ),
    )
    action = ContinuousRuntimeAction(
        action_id="first-send",
        stream_id=checkpoint.inputs.spec.run_id,
        previous_checkpoint_sha256=checkpoint.semantic_sha256,
        source_closure_sha256="b" * 64,
        checked_at=checkpoint.now,
        command=AccountingCommand("fixture-first-send", payload),
    )
    return checkpoint, action


def test_exact_internal_release_preserves_engine_history_and_does_not_advance_source_time():
    checkpoint, action = case()
    result = apply(checkpoint, action)
    hold = result.state.commitments[0]
    assert hold.state == "terminal" and hold.reserved_cash == 0
    assert result.now == checkpoint.now and result.frontier == checkpoint.frontier
    assert result.sequence == checkpoint.sequence + 1
    for name in (
        "events",
        "pending_ids",
        "strategy_state",
        "targets",
        "runtime_decisions",
        "valuations",
        "wealth",
        "request_rows",
        "flows",
    ):
        assert getattr(result, name) == getattr(checkpoint, name)
    for name in ("submissions", "broker_events", "cash_flows", "cancel_requests"):
        assert getattr(result.state, name) == getattr(checkpoint.state, name)
    assert result.current.snapshot.available_cash == (
        checkpoint.current.snapshot.available_cash + checkpoint.state.commitments[0].reserved_cash
    )
    context = continuous_runtime_action_context(
        checkpoint, command_id=action.command.command_id, activation=False
    )
    assert result.current.snapshot.point == context.point and context.approved_snapshot is None
    assert apply(result, action) is result
    restored = decode_record(encode_record(result), type(result))
    assert apply(restored, action) is restored
    next_boundary = ClosedEngineFrontier(
        frontier_id="later-source-clock",
        stream_id=result.inputs.spec.run_id,
        previous_checkpoint_sha256=result.semantic_sha256,
        source_frontier_sha256="f" * 64,
        knowledge_at=result.now + timedelta(seconds=1),
        events=(),
    )
    later = advance(result, next_boundary)
    assert apply(later, action) is later


@pytest.mark.parametrize("change", ["predecessor", "time", "identity", "command"])
def test_action_cannot_refresh_its_source_or_replace_an_existing_identity(change):
    checkpoint, action = case()
    if change == "predecessor":
        action = replace(action, previous_checkpoint_sha256="f" * 64)
    elif change == "time":
        at = checkpoint.now - timedelta(seconds=1)
        action = replace(
            action,
            checked_at=at,
            command=replace(action.command, payload=replace(action.command.payload, proof_at=at)),
        )
    elif change == "identity":
        checkpoint = apply(checkpoint, action)
        action = replace(action, source_closure_sha256="f" * 64)
    else:
        with pytest.raises(ValueError, match="canonical activation"):
            replace(
                action, command=AccountingCommand("rearm", ControlCommand(False, "not-authorized"))
            )
        return
    with pytest.raises(ValueError):
        apply(checkpoint, action)


def test_preparer_runs_internal_action_and_authenticates_its_original_request():
    checkpoint, action = case()
    preparer = ContinuousAccountTransitionPreparer(
        accounting=PersonalAccounting(),
        strategy=ReferenceStrategy(),
        runtime_evidence=FixtureEvidence(checkpoint.inputs.spec),
    )
    result = preparer.prepare_runtime_action(
        command_id="account-release", checkpoint=checkpoint, action=action
    )
    preparer.require_prepared(result)
    assert result.disposition == "runtime_action" and result.request == action
    assert not result.new_decisions and not result.application_batches
    with pytest.raises(ValueError, match="OWNED"):
        preparer.require_prepared(replace(result))


@pytest.mark.parametrize("activation", [False, True])
def test_new_action_identity_cannot_relabel_an_original_consumed_accounting_command(activation):
    checkpoint, action = activation_case() if activation else case()
    result = apply(checkpoint, action)
    original = result.semantic_sha256
    changed = replace(
        action,
        action_id="relabeled-action",
        previous_checkpoint_sha256=original,
        source_closure_sha256="9" * 64,
    )
    with pytest.raises(ValueError, match="relabel a previously consumed command"):
        apply(result, changed)
    assert result.semantic_sha256 == original
    assert dict(result.causal_sources)[action.command.command_id] == action.source_closure_sha256


def test_activation_records_each_dispatch_once_with_original_time_and_no_broker_ack():
    checkpoint, action = activation_case()
    rows = ((checkpoint.now - timedelta(seconds=1), True),) * 9
    checkpoint = replace(checkpoint, request_rows=rows)
    action = replace(action, previous_checkpoint_sha256=checkpoint.semantic_sha256)
    result = apply(checkpoint, action)
    assert result.state.commitments[0].state == "active"
    assert result.request_rows == (*rows, (checkpoint.now, True))
    assert result.state.broker_events == checkpoint.state.broker_events == ()
    assert result.state.cash_flows == checkpoint.state.cash_flows
    assert result.now == checkpoint.now
    restored = decode_record(encode_record(result), type(result))
    assert apply(restored, action) is restored
    assert restored.request_rows == result.request_rows


def test_exhausted_modeled_budget_rejects_activation_and_keeps_exact_old_hold():
    checkpoint, action = activation_case()
    checkpoint = replace(checkpoint, request_rows=((checkpoint.now, True),) * 10)
    action = replace(action, previous_checkpoint_sha256=checkpoint.semantic_sha256)
    original = checkpoint.semantic_sha256
    with pytest.raises(ValueError, match="modeled low-priority request budget"):
        apply(checkpoint, action)
    assert checkpoint.semantic_sha256 == original
    assert checkpoint.state.commitments[0].state == "approved_unsent"


def test_later_activation_uses_original_snapshot_and_actual_check_without_refresh():
    checkpoint, action = activation_case()
    later, _ = step(checkpoint, (), at=checkpoint.now + timedelta(milliseconds=100))
    assert later.current.snapshot.point.knowledge_at < later.now
    action = replace(
        action,
        previous_checkpoint_sha256=later.semantic_sha256,
        checked_at=later.now,
        command=replace(
            action.command, payload=replace(action.command.payload, checked_at=later.now)
        ),
    )
    result = apply(later, action)
    assert result.now == later.now
    assert result.state.marks == checkpoint.state.marks
    assert result.state.commitments[0].activated_at == later.now
    assert result.request_rows[-1][0] == later.now
    assert (
        action.command.payload.source_snapshot_sha256 == checkpoint.current.snapshot.semantic_sha256
    )
    assert result.runtime_decisions == checkpoint.runtime_decisions
