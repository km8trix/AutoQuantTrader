"""Attempt metadata never manufactures accounting or delivery authority."""

from dataclasses import replace
from datetime import timedelta

import pytest

from packages.application.causal_engine import _Engine, _Stop
from packages.application.personal_codec import decode_record, encode_record
from packages.application.reference_strategy import ReferenceStrategy
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.continuous_runtime_action import ContinuousRuntimeAction
from packages.domain.daily_attempt_contracts import DailyAttemptEvent
from packages.domain.submission_attempt import SubmissionAttemptState
from tests.unit.test_continuous_engine import FixtureEvidence, inputs_and_prices, step
from tests.unit.test_continuous_runtime_action import apply, case


@pytest.mark.parametrize("unknown", [False, True])
def test_attempt_metadata_retains_all_economics_and_reserves_and_retry_is_inert(unknown):
    checkpoint, _ = case()
    event = DailyAttemptEvent(
        attempt_id="modeled-attempt",
        sequence=2 if unknown else 1,
        previous_event_sha256="a" * 64 if unknown else None,
        state=SubmissionAttemptState.UNKNOWN if unknown else SubmissionAttemptState.PENDING,
        recorded_at=checkpoint.now,
        reason="TIMEOUT" if unknown else None,
    )
    action = ContinuousRuntimeAction(
        action_id="attempt-metadata",
        stream_id=checkpoint.inputs.spec.run_id,
        previous_checkpoint_sha256=checkpoint.semantic_sha256,
        source_closure_sha256="b" * 64,
        checked_at=checkpoint.now,
        attempt_events=(event,),
    )
    assert decode_record(encode_record(action), ContinuousRuntimeAction) == action
    result = apply(checkpoint, action)
    assert result.state == checkpoint.state
    assert result.current == checkpoint.current
    assert result.request_rows == checkpoint.request_rows
    assert result.trace == checkpoint.trace
    assert result.runtime_decisions == checkpoint.runtime_decisions
    assert result.strategy_state == checkpoint.strategy_state
    assert result.processed == checkpoint.processed + 1
    assert dict(result.closed_source_frontiers)[action.retained_id] == action.semantic_sha256
    assert apply(result, action) is result
    with pytest.raises(ValueError, match="conflicts"):
        apply(result, replace(action, source_closure_sha256="c" * 64))
    with pytest.raises(ValueError, match="original closed-boundary"):
        apply(
            checkpoint,
            replace(
                action,
                checked_at=checkpoint.now - timedelta(seconds=1),
                attempt_events=(replace(event, recorded_at=checkpoint.now - timedelta(seconds=1)),),
            ),
        )

    later = checkpoint.now + timedelta(seconds=1)
    delayed = apply(
        checkpoint,
        replace(action, checked_at=later, attempt_events=(replace(event, recorded_at=later),)),
    )
    assert delayed.now == later
    assert delayed.state == checkpoint.state
    assert delayed.current == checkpoint.current
    assert delayed.pending_ids == checkpoint.pending_ids
    assert delayed.runtime_decisions == checkpoint.runtime_decisions
    assert delayed.request_rows == checkpoint.request_rows
    assert delayed.trace == checkpoint.trace


def test_metadata_action_requires_original_bounded_group_and_cannot_mix_release():
    checkpoint, release = case()
    with pytest.raises(ValueError, match="complete bounded"):
        replace(release, command=None)
    event = DailyAttemptEvent(
        attempt_id="pending",
        sequence=1,
        previous_event_sha256=None,
        state=SubmissionAttemptState.PENDING,
        recorded_at=checkpoint.now,
    )
    with pytest.raises(ValueError, match="cannot mix"):
        replace(release, attempt_events=(event,))
    with pytest.raises(ValueError, match="complete bounded"):
        replace(release, command=None, attempt_events=(event, event))
    with pytest.raises(ValueError, match="complete bounded"):
        replace(
            release,
            command=None,
            attempt_events=tuple(replace(event, attempt_id=str(i)) for i in range(5)),
        )


def test_continuous_step_gets_own_budget_but_same_step_cannot_overrun(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("packages.application.causal_engine.monotonic", lambda: now[0])
    inputs, _ = inputs_and_prices()
    engine = _Engine(
        inputs,
        PersonalAccounting(),
        ReferenceStrategy(),
        None,
        runtime_evidence=FixtureEvidence(inputs.spec),
    )
    engine._admit()
    while engine.queue and engine.queue[0][0] <= inputs.spec.initialized_at:
        engine.advance_next_frontier()
    now[0] += inputs.spec.max_wall_seconds - 1
    previous = engine.checkpoint()
    assert previous.remaining_wall_nanoseconds == 10**9
    now[0] += 3600
    result, _ = step(previous, (), at=previous.now + timedelta(seconds=1), identity="new-step")
    assert result.remaining_wall_nanoseconds == inputs.spec.max_wall_seconds * 10**9
    original = _Engine._frontier

    def slow(self, events):
        now[0] += inputs.spec.max_wall_seconds + 1
        return original(self, events)

    monkeypatch.setattr(_Engine, "_frontier", slow)
    with pytest.raises(_Stop) as stopped:
        step(result, (), at=result.now + timedelta(seconds=1), identity="too-slow")
    assert stopped.value.reason == "WALL_TIME_BUDGET_EXCEEDED"
    assert "too-slow" not in dict(result.closed_source_frontiers)
