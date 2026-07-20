from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from itertools import permutations

import pytest

from packages.domain.clock import ClockEvent
from packages.domain.decision import DecisionTrigger
from packages.domain.models import MarketEvent, PositionTarget, Side, TargetPortfolio
from packages.domain.portfolio import portfolio_snapshot, target_to_intent_batch
from packages.domain.risk import intent_payload_hash

AS_OF = datetime(2026, 7, 15, 14, 0, tzinfo=UTC)
CONFIGURATION_SHA256 = "a" * 64


def price_event(instrument_id: str, symbol: str, price: str, sequence: int) -> MarketEvent:
    return MarketEvent(
        event_id=f"price-{symbol}-{sequence}",
        instrument_id=instrument_id,
        symbol=symbol,
        event_time=AS_OF - timedelta(minutes=sequence + 1),
        available_at=AS_OF - timedelta(minutes=sequence),
        close_price=Decimal(price),
        source_sequence=sequence,
    )


def clock_target(*, full_snapshot: bool = True) -> TargetPortfolio:
    event = ClockEvent(
        clock_event_id="regular-close",
        schedule_id="regular-session-v1",
        scheduled_at=AS_OF,
        sequence=0,
    )
    return TargetPortfolio(
        target_id="target-1",
        strategy_id="allocation",
        strategy_version="1.0.0",
        strategy_configuration_sha256=CONFIGURATION_SHA256,
        decision_trigger=DecisionTrigger.from_clock_event(event),
        as_of=AS_OF,
        expires_at=AS_OF + timedelta(minutes=5),
        targets=(
            PositionTarget("US-ETF-IWM", "IWM", Decimal("2")),
            PositionTarget("US-ETF-SPY", "SPY", Decimal("5")),
        ),
        full_snapshot=full_snapshot,
    )


def test_clock_target_converts_to_canonical_multi_instrument_intent_batch() -> None:
    events = (
        price_event("US-ETF-SPY", "SPY", "100", 1),
        price_event("US-ETF-IWM", "IWM", "200", 2),
        price_event("US-ETF-QQQ", "QQQ", "300", 3),
    )
    positions = {
        "US-ETF-SPY": ("SPY", Decimal("10")),
        "US-ETF-QQQ": ("QQQ", Decimal("5")),
    }
    expected = None

    for ordering in permutations(events):
        snapshot = portfolio_snapshot(
            as_of=AS_OF,
            current_positions=positions,
            price_events=ordering,
        )
        batch = target_to_intent_batch(clock_target(), snapshot)

        assert tuple(intent.instrument_id for intent in batch.intents) == (
            "US-ETF-IWM",
            "US-ETF-QQQ",
            "US-ETF-SPY",
        )
        assert tuple((intent.side, intent.quantity) for intent in batch.intents) == (
            (Side.BUY, Decimal("2")),
            (Side.SELL, Decimal("5")),
            (Side.SELL, Decimal("5")),
        )
        assert all(intent.intent_batch_id == batch.intent_batch_id for intent in batch.intents)
        assert all(
            intent.target_sha256 == clock_target().semantic_sha256 for intent in batch.intents
        )
        assert all(
            intent.portfolio_snapshot_sha256 == batch.portfolio_snapshot_sha256
            for intent in batch.intents
        )
        assert all(
            intent.strategy_configuration_sha256 == CONFIGURATION_SHA256 for intent in batch.intents
        )
        if expected is None:
            expected = batch
        else:
            assert batch == expected
            assert batch.semantic_sha256 == expected.semantic_sha256


def test_partial_target_does_not_liquidate_omitted_position() -> None:
    snapshot = portfolio_snapshot(
        as_of=AS_OF,
        current_positions={
            "US-ETF-SPY": ("SPY", Decimal("10")),
            "US-ETF-QQQ": ("QQQ", Decimal("5")),
        },
        price_events=(
            price_event("US-ETF-SPY", "SPY", "100", 1),
            price_event("US-ETF-IWM", "IWM", "200", 2),
        ),
    )

    batch = target_to_intent_batch(clock_target(full_snapshot=False), snapshot)

    assert tuple(intent.instrument_id for intent in batch.intents) == (
        "US-ETF-IWM",
        "US-ETF-SPY",
    )


def test_conversion_fails_closed_without_causal_price_or_with_future_price() -> None:
    target = clock_target()
    missing = portfolio_snapshot(
        as_of=AS_OF,
        current_positions={"US-ETF-SPY": ("SPY", Decimal("10"))},
        price_events=(price_event("US-ETF-SPY", "SPY", "100", 1),),
    )

    with pytest.raises(ValueError, match="no causal reference price"):
        target_to_intent_batch(target, missing)

    future = replace(
        price_event("US-ETF-SPY", "SPY", "100", 1),
        available_at=AS_OF + timedelta(microseconds=1),
    )
    with pytest.raises(ValueError, match="future-available"):
        portfolio_snapshot(
            as_of=AS_OF,
            current_positions={},
            price_events=(future,),
        )


def test_strategy_configuration_and_target_evidence_reach_risk_payload() -> None:
    snapshot = portfolio_snapshot(
        as_of=AS_OF,
        current_positions={"US-ETF-SPY": ("SPY", Decimal("5"))},
        price_events=(
            price_event("US-ETF-IWM", "IWM", "200", 2),
            price_event("US-ETF-SPY", "SPY", "100", 1),
        ),
    )
    target = clock_target(full_snapshot=False)
    intent = target_to_intent_batch(target, snapshot).intents[0]
    changed_target = replace(target, strategy_configuration_sha256="b" * 64)
    changed_intent = target_to_intent_batch(changed_target, snapshot).intents[0]

    assert intent.target_sha256 == target.semantic_sha256
    assert intent_payload_hash(intent) != intent_payload_hash(changed_intent)


def test_snapshot_binds_complete_source_event_semantics_and_copies_inputs() -> None:
    event = price_event("US-ETF-SPY", "SPY", "100", 1)
    positions = {"US-ETF-SPY": ("SPY", Decimal("5"))}
    baseline = portfolio_snapshot(
        as_of=AS_OF,
        current_positions=positions,
        price_events=(event,),
    )
    different_source = portfolio_snapshot(
        as_of=AS_OF,
        current_positions=positions,
        price_events=(replace(event, source="other-source"),),
    )
    positions["US-ETF-SPY"] = ("SPY", Decimal("99"))

    assert baseline.positions[0].quantity == Decimal("5")
    assert baseline.semantic_sha256 != different_source.semantic_sha256
    target = replace(
        clock_target(full_snapshot=False),
        targets=(PositionTarget("US-ETF-SPY", "SPY", Decimal("10")),),
    )
    baseline_intent = target_to_intent_batch(target, baseline).intents[0]
    different_source_intent = target_to_intent_batch(target, different_source).intents[0]
    assert baseline_intent.reference_event_sha256 != (
        different_source_intent.reference_event_sha256
    )
    assert intent_payload_hash(baseline_intent) != intent_payload_hash(different_source_intent)


def test_unchanged_target_produces_an_evidence_bearing_empty_batch() -> None:
    target = replace(
        clock_target(full_snapshot=False),
        targets=(PositionTarget("US-ETF-SPY", "SPY", Decimal("5")),),
    )
    snapshot = portfolio_snapshot(
        as_of=AS_OF,
        current_positions={"US-ETF-SPY": ("SPY", Decimal("5"))},
        price_events=(),
    )

    batch = target_to_intent_batch(target, snapshot)

    assert batch.intents == ()
    assert batch.target_sha256 == target.semantic_sha256
