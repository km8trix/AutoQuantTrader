"""The fixed factory emits bytes only after the fresh capture and final guards.

These cases use the actual signed bootstrap, factory stores and original
delegated reads. They do not qualify retained-session startup time.
"""

import json
from contextlib import contextmanager

import pytest

from apps.trader.continuous_simulation_factory import ContinuousSimulationFactoryError
from tests.integration.test_continuous_factory_integrity_result import (
    assert_closed,
)
from tests.integration.test_continuous_factory_integrity_result import (
    original_factory as original_factory,
)
from tests.integration.test_continuous_simulation_factory import configured as configured


def observe_final_capture(monkeypatch, factory):
    observed = []
    original = factory.daily.require_same_complete_capture

    def compare(previous, fresh):
        original(previous, fresh)
        observed.append((previous, fresh))

    monkeypatch.setattr(factory.daily, "require_same_complete_capture", compare)
    return observed


def test_factory_keeps_fresh_capture_and_uses_original_daily_without_final_resolver(
    original_factory, monkeypatch
):
    fixture, factory = original_factory
    counts = fixture[0].counts()
    reader = factory.integrity
    reads = []
    final_rows = []
    original_read = factory.daily.read_snapshot
    original_resolve = factory.daily.resolve_snapshot
    original_rows = reader._recheck_original_rows
    observed = observe_final_capture(monkeypatch, factory)

    def read(*args, **kwargs):
        state = reader._factory_read
        final = state is not None and state.completed
        raw = original_read(*args, **kwargs)
        if final:
            assert args == ()
            assert kwargs == {"account_id": reader.scope.account_id, "fence": reader.fence}
            assert reader._daily_episode is None
            assert reader.composer._integrity_daily is None
            reads.append(raw)
        return raw

    def resolve(raw):
        state = reader._factory_read
        if state is not None and state.completed:
            pytest.fail("the factory's final fresh capture must not repeat full B replay")
        return original_resolve(raw)

    def rows(*args, **kwargs):
        result = original_rows(*args, **kwargs)
        if observed:
            final_rows.append("original coherent rows returned")
        return result

    monkeypatch.setattr(factory.daily, "read_snapshot", read)
    monkeypatch.setattr(factory.daily, "resolve_snapshot", resolve)
    monkeypatch.setattr(reader, "_recheck_original_rows", rows)
    payload = factory.execute(operation_id="fresh-complete-daily-handoff")
    assert len(observed) == len(reads) == 1
    previous, fresh = observed[0]
    assert fresh is reads[0] and fresh is not previous.raw
    assert fresh.receipt.validated_at >= previous.raw.receipt.validated_at
    assert fresh.receipt.valid_until == previous.raw.receipt.valid_until
    assert final_rows == ["original coherent rows returned"]
    result = json.loads(payload)
    assert result["sequence"] == 1
    assert result["assignment_generation"] == previous.assignment.generation == 1
    assert result["assignment_sha256"] == previous.assignment.semantic_sha256
    assert fixture[0].counts() == counts
    assert_closed(reader)


@pytest.mark.parametrize("boundary", ["terminal_sql", "observation_cleanup"])
def test_stop_during_final_validation_or_cleanup_prevents_factory_bytes(
    original_factory, monkeypatch, boundary
):
    fixture, factory = original_factory
    counts = fixture[0].counts()
    reader = factory.integrity
    observed = observe_final_capture(monkeypatch, factory)
    reached = []

    def stop_after_original():
        assert len(observed) == 1
        reached.append(boundary)
        factory.stop_requested = lambda: True

    if boundary == "terminal_sql":
        original = reader._recheck_original_rows

        def rows(*args, **kwargs):
            result = original(*args, **kwargs)
            if observed:
                stop_after_original()
            return result

        monkeypatch.setattr(reader, "_recheck_original_rows", rows)
    else:
        owner = factory.coordinator
        original = type(owner).inspect_committed_observations

        @contextmanager
        def observations(coordinator, *args, **kwargs):
            with original(coordinator, *args, **kwargs) as value:
                yield value
            if coordinator is owner:
                stop_after_original()

        monkeypatch.setattr(type(owner), "inspect_committed_observations", observations)

    with pytest.raises(ContinuousSimulationFactoryError, match="OFFLINE_OPERATION_FAILED"):
        factory.execute(operation_id="stop-after-provisional-payload")
    assert reached == [boundary]
    assert fixture[0].counts() == counts
    assert_closed(reader)


@pytest.mark.parametrize("boundary", ["terminal_sql", "observation_cleanup"])
def test_final_guard_or_cleanup_error_discards_provisional_factory_bytes(
    original_factory, monkeypatch, boundary
):
    fixture, factory = original_factory
    counts = fixture[0].counts()
    reader = factory.integrity
    observed = observe_final_capture(monkeypatch, factory)
    reached = []

    def deny_after_original():
        assert len(observed) == 1
        reached.append(boundary)
        raise ValueError("reached-original-final-boundary")

    if boundary == "terminal_sql":
        original = reader._recheck_original_rows

        def rows(*args, **kwargs):
            result = original(*args, **kwargs)
            if observed:
                deny_after_original()
            return result

        monkeypatch.setattr(reader, "_recheck_original_rows", rows)
    else:
        owner = factory.coordinator
        original = type(owner).inspect_committed_observations

        @contextmanager
        def observations(coordinator, *args, **kwargs):
            with original(coordinator, *args, **kwargs) as value:
                yield value
            if coordinator is owner:
                deny_after_original()

        monkeypatch.setattr(type(owner), "inspect_committed_observations", observations)

    with pytest.raises(ContinuousSimulationFactoryError, match="OFFLINE_OPERATION_FAILED"):
        factory.execute(operation_id="deny-after-provisional-payload")
    assert reached == [boundary]
    assert fixture[0].counts() == counts
    assert_closed(reader)


def test_failed_complete_capture_comparison_cannot_return_factory_bytes(
    original_factory, monkeypatch
):
    fixture, factory = original_factory
    counts = fixture[0].counts()
    original = factory.daily.require_same_complete_capture
    reached = []

    def deny(previous, fresh):
        original(previous, fresh)
        reached.append("complete original comparison returned")
        raise ValueError("comparison-boundary-denial")

    monkeypatch.setattr(factory.daily, "require_same_complete_capture", deny)
    with pytest.raises(ContinuousSimulationFactoryError, match="OFFLINE_OPERATION_FAILED"):
        factory.execute(operation_id="deny-at-complete-capture-comparison")
    assert reached == ["complete original comparison returned"]
    assert fixture[0].counts() == counts
    assert_closed(factory.integrity)
