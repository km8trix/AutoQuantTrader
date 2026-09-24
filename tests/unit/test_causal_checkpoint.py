"""Restart through real economic frontiers; finite-manifest seam only."""

from dataclasses import replace
from decimal import Decimal

import pytest

from packages.application.causal_engine import _Engine, _Stop, run_causal_engine
from packages.application.personal_codec import decode_record, encode_record
from packages.application.personal_inputs import synthetic_engine_inputs
from packages.application.reference_strategy import ReferenceStrategy
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.personal_contracts import VersionPin

PINS = tuple(
    VersionPin(name, "checkpoint-fixture/1", "a" * 64)
    for name in sorted(
        (
            "engine",
            "source",
            "dependency_lock",
            "tzdata",
            "availability",
            "actions",
            "numeric",
            "benchmark",
            "report",
            "dirty_patch",
        )
    )
)


def admitted(fixture: str = "flat", kind: str = "buy_hold") -> _Engine:
    inputs = synthetic_engine_inputs(
        fixture=fixture,
        pins=PINS,
        session_count=8,
        warmup_count=2,
        configuration=ReferenceConfiguration(kind=kind, lookback=2),
    )
    engine = _Engine(inputs, PersonalAccounting(), ReferenceStrategy(), None)
    engine._admit()
    return engine


@pytest.mark.parametrize("fixture,kind", [("flat", "buy_hold"), ("regime", "trend_sma")])
def test_restart_after_every_closed_frontier_matches_uninterrupted_economics(
    fixture: str,
    kind: str,
) -> None:
    original = admitted(fixture, kind)
    expected_frontiers = []
    while original.advance_next_frontier():
        expected_frontiers.append(original.checkpoint())
    restarted = admitted(fixture, kind)
    saw_commitment = saw_funding = saw_request = False
    for expected in expected_frontiers:
        assert restarted.advance_next_frontier()
        checkpoint = restarted.checkpoint()
        # Active wall time is retained resource metadata, not financial state.
        assert replace(checkpoint, remaining_wall_nanoseconds=0) == replace(
            expected, remaining_wall_nanoseconds=0
        )
        saw_commitment |= bool(checkpoint.state.commitments)
        saw_funding |= bool(checkpoint.state.cash_flows)
        saw_request |= bool(checkpoint.request_rows)
        payload = encode_record(checkpoint)
        decoded = decode_record(payload, CausalEngineCheckpoint)
        restarted = _Engine.restore(
            decoded,
            expected_sha256=checkpoint.semantic_sha256,
            accounting=PersonalAccounting(),
            strategy=ReferenceStrategy(),
        )
    assert not restarted.advance_next_frontier()
    assert replace(restarted.checkpoint(), remaining_wall_nanoseconds=0) == replace(
        original.checkpoint(), remaining_wall_nanoseconds=0
    )
    assert saw_funding and saw_commitment and saw_request
    report = run_causal_engine(
        original.inputs,
        accounting=PersonalAccounting(),
        strategy=ReferenceStrategy(),
    )
    assert report.status == "completed"
    assert restarted.state == report.final_state
    assert tuple(restarted.trace) == report.trace
    if fixture == "flat":
        # One 24-share buy at 100.05 with a 0.24 fee. Restart must not refund,
        # reapply funding, or submit the same decision again.
        assert len(restarted.current.executions) == 1
        assert restarted.current.snapshot.trade_date_cash == Decimal("7598.56")
        assert restarted.current.snapshot.nav == Decimal("9998.56")
        assert len(restarted.state.cash_flows) == 1


def test_restore_requires_exact_retained_digest_and_closed_frontier() -> None:
    engine = admitted()
    assert engine.advance_next_frontier()
    checkpoint = engine.checkpoint()
    with pytest.raises(ValueError, match="retained digest"):
        _Engine.restore(
            replace(checkpoint, processed=checkpoint.processed + 1),
            expected_sha256=checkpoint.semantic_sha256,
            accounting=PersonalAccounting(),
            strategy=ReferenceStrategy(),
        )
    past = next(event for event in checkpoint.events if event.knowledge_at <= checkpoint.now)
    with pytest.raises(ValueError, match="unclosed earlier frontier"):
        replace(checkpoint, pending_ids=(*checkpoint.pending_ids, past.event_id))
    with pytest.raises(ValueError, match="account projection and state"):
        replace(checkpoint, state=replace(checkpoint.state, halted=not checkpoint.state.halted))
    with pytest.raises(ValueError, match="no retained event"):
        replace(checkpoint, heads=(((checkpoint.mark_session, "instrument"), "missing"),))
    with pytest.raises(ValueError, match="outside consumed or pending"):
        replace(checkpoint, pending_ids=checkpoint.pending_ids[1:])


def test_unadmitted_or_failed_frontier_cannot_be_checkpointed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = admitted()
    new = _Engine(engine.inputs, PersonalAccounting(), ReferenceStrategy(), None)
    with pytest.raises(ValueError, match="successful admission"):
        new.checkpoint()
    with pytest.raises(ValueError, match="successful admission"):
        new.advance_next_frontier()

    def failed(_events: object) -> None:
        # The real queue was already popped; no checkpoint may hide this loss.
        assert not engine.seen
        raise OSError("fixture accounting interruption")

    monkeypatch.setattr(engine, "_frontier", failed)
    with pytest.raises(OSError, match="interruption"):
        engine.advance_next_frontier()
    with pytest.raises(ValueError, match="closed frontier"):
        engine.checkpoint()
    with pytest.raises(ValueError, match="closed frontier"):
        engine.advance_next_frontier()


def test_failed_admission_and_stop_cannot_be_checkpointed() -> None:
    source = admitted()
    new = _Engine(
        replace(source.inputs, events=()), PersonalAccounting(), ReferenceStrategy(), None
    )
    with pytest.raises(_Stop) as rejected:
        new._admit()
    assert rejected.value.reason == "EVENT_MANIFEST_MISMATCH"
    with pytest.raises(ValueError, match="successful admission"):
        new.checkpoint()
    source.stop_requested = lambda: True
    with pytest.raises(_Stop) as cancelled:
        source.advance_next_frontier()
    assert cancelled.value.reason == "OWNER_CANCELLED"
    with pytest.raises(ValueError, match="closed frontier"):
        source.checkpoint()


def test_repeated_restore_preserves_consumed_wall_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [100.0]
    monkeypatch.setattr("packages.application.causal_engine.monotonic", lambda: now[0])
    engine = admitted()
    assert engine.advance_next_frontier()
    initial = engine.spec.max_wall_seconds * 10**9
    for count in range(1, 4):
        now[0] += 1
        checkpoint = engine.checkpoint()
        assert checkpoint.remaining_wall_nanoseconds == initial - count * 10**9
        # Process downtime does not create more active execution budget.
        now[0] += 100
        engine = _Engine.restore(
            checkpoint,
            expected_sha256=checkpoint.semantic_sha256,
            accounting=PersonalAccounting(),
            strategy=ReferenceStrategy(),
        )
        assert (
            engine.checkpoint().remaining_wall_nanoseconds == checkpoint.remaining_wall_nanoseconds
        )
    now[0] += engine.spec.max_wall_seconds
    with pytest.raises(_Stop) as expired:
        engine.advance_next_frontier()
    assert expired.value.reason == "WALL_TIME_BUDGET_EXCEEDED"
    with pytest.raises(ValueError, match="closed frontier"):
        engine.checkpoint()
