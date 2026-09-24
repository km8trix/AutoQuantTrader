"""Modeled request history retains its original times and protected capacity."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from packages.application.causal_engine import continuous_request_budget_available
from tests.unit.test_continuous_engine import FixtureEvidence, inputs_and_prices, start, step

AT = datetime(2025, 2, 4, 14, 0, tzinfo=UTC)


def test_low_priority_ceiling_preserves_ten_requests_for_recovery():
    rows = ((AT - timedelta(seconds=1), True),) * 10
    assert not continuous_request_budget_available(rows, at=AT, count=1, low_priority=True)
    assert continuous_request_budget_available(rows, at=AT, count=10, low_priority=False)
    assert not continuous_request_budget_available(rows, at=AT, count=11, low_priority=False)
    mixed = rows + ((AT, False),) * 10
    assert not continuous_request_budget_available(mixed, at=AT, count=1, low_priority=False)
    assert not continuous_request_budget_available(mixed, at=AT, count=1, low_priority=True)


def test_exact_sixty_second_cutoff_expires_without_rewriting_original_history():
    expired = AT - timedelta(seconds=60)
    retained = expired + timedelta(microseconds=1)
    rows = ((expired, True),) * 5 + ((retained, True),) * 5
    original = tuple(rows)
    assert continuous_request_budget_available(rows, at=AT, count=5, low_priority=True)
    assert not continuous_request_budget_available(rows, at=AT, count=6, low_priority=True)
    assert continuous_request_budget_available(
        rows, at=AT + timedelta(microseconds=1), count=10, low_priority=True
    )
    assert rows == original
    assert all(instant < AT for instant, _ in rows)


@pytest.mark.parametrize(
    "rows,count,priority",
    [
        ([], 1, True),
        (((AT, True),) * 21, 0, False),
        (((AT, 1),), 1, True),
        (((AT + timedelta(microseconds=1), True),), 1, True),
        (((AT, True), (AT - timedelta(seconds=1), False)), 1, False),
        (((AT.replace(tzinfo=None), True),), 1, False),
        ((), True, True),
        ((), -1, True),
        ((), 21, False),
        ((), 1, 1),
    ],
)
def test_invalid_or_future_request_inventory_cannot_be_used(rows, count, priority):
    with pytest.raises(ValueError):
        continuous_request_budget_available(rows, at=AT, count=count, low_priority=priority)


def test_actual_engine_evidence_callback_receives_original_checkpoint_request_rows():
    inputs, prices = inputs_and_prices()
    checkpoint = start(inputs)
    rows = ((checkpoint.now - timedelta(seconds=1), False),)
    checkpoint = replace(checkpoint, request_rows=rows)

    class RecordingEvidence(FixtureEvidence):
        def __init__(self, spec):
            super().__init__(spec)
            self.received = []

        def build(self, **kwargs):
            self.received.append(kwargs["request_rows"])
            return super().build(**kwargs)

    evidence = RecordingEvidence(inputs.spec)
    first_session = inputs.spec.window.scored_sessions[0]
    events = tuple(event for event in prices if event.payload.session == first_session)
    result, _ = step(checkpoint, events, evidence=evidence)
    assert evidence.received and all(received == rows for received in evidence.received)
    assert result.request_rows == rows
    assert evidence.received[0][0][0] < checkpoint.now
