from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from itertools import permutations

import pytest

from packages.domain.clock import Clock, SimulatedClock
from packages.domain.market_batch import (
    MarketBatch,
    MarketBatchStatus,
    MarketWatermark,
    ReplayRevisionPolicy,
)
from packages.domain.models import MarketEvent
from packages.domain.portfolio import target_to_order_intent
from packages.domain.replay import (
    LateMarketEvent,
    MarketEventConflict,
    ReplayContractError,
    ReplayIdentityConflict,
    ReplayResult,
    UnexpectedMarketEvent,
    replay_market_events,
)
from packages.domain.risk import intent_payload_hash
from packages.domain.strategy import FixedQuantityStrategy, ReadOnlyStrategyContext

SLICE = datetime(2026, 7, 15, 13, 31, tzinfo=UTC)
CLOSED_AT = SLICE + timedelta(seconds=5)


def market_event(
    symbol: str = "SPY",
    *,
    event_time: datetime = SLICE,
    available_at: datetime = CLOSED_AT,
    revision: int = 1,
    source_sequence: int | None = 1,
    supersedes_event_revision_id: str | None = None,
    close_price: Decimal = Decimal("100.00"),
    event_id: str | None = None,
    observation_id: str | None = None,
) -> MarketEvent:
    resolved_event_id = event_id or f"synthetic-{symbol}-{event_time.isoformat()}-r{revision}"
    return MarketEvent(
        event_id=resolved_event_id,
        instrument_id=f"US-ETF-{symbol}",
        symbol=symbol,
        event_time=event_time,
        available_at=available_at,
        close_price=close_price,
        source="synthetic-replay-v1",
        source_sequence=source_sequence,
        observation_id=observation_id or f"synthetic-{symbol}-{event_time.isoformat()}",
        revision=revision,
        supersedes_event_revision_id=supersedes_event_revision_id,
    )


def watermark(
    *symbols: str,
    event_time: datetime = SLICE,
    closed_at: datetime = CLOSED_AT,
    revision_policy: ReplayRevisionPolicy = ReplayRevisionPolicy.REVISED_AS_OF,
) -> MarketWatermark:
    return MarketWatermark(
        watermark_id=f"watermark-{event_time.isoformat()}-{revision_policy.value}",
        event_time_through=event_time,
        closed_at=closed_at,
        expected_instrument_ids=tuple(sorted(f"US-ETF-{symbol}" for symbol in symbols)),
        revision_policy=revision_policy,
    )


def test_simulated_clock_is_utc_monotonic_and_equality_is_idempotent() -> None:
    clock = SimulatedClock(SLICE)

    assert clock.advance_to(SLICE) == SLICE
    assert clock.advance_to(CLOSED_AT) == CLOSED_AT
    with pytest.raises(ValueError, match="backwards"):
        clock.advance_to(SLICE)
    with pytest.raises(ValueError, match="must be UTC"):
        SimulatedClock(SLICE.astimezone(timezone(timedelta(hours=-4))))
    with pytest.raises(ValueError, match="timezone-aware"):
        SimulatedClock(SLICE.replace(tzinfo=None))


def test_equal_time_facts_precede_watermark_and_input_permutations_are_identical() -> None:
    symbols = ("DIA", "IWM", "QQQ", "SPY")
    events = tuple(
        market_event(symbol, source_sequence=index) for index, symbol in enumerate(symbols, start=1)
    )
    expected_result = None

    for ordering in permutations(events):
        callbacks: list[tuple[str, datetime, tuple[str, ...]]] = []

        def capture(
            batch: MarketBatch,
            clock: Clock,
            sink: list[tuple[str, datetime, tuple[str, ...]]] = callbacks,
        ) -> None:
            sink.append((batch.batch_id, clock.now(), batch.received_instrument_ids))

        result = replay_market_events(
            events=ordering,
            watermarks=(watermark(*symbols),),
            on_complete_batch=capture,
        )

        assert callbacks == [
            (
                result.batches[0].batch_id,
                CLOSED_AT,
                tuple(f"US-ETF-{symbol}" for symbol in symbols),
            )
        ]
        assert result.batches[0].complete
        if expected_result is None:
            expected_result = result
        else:
            assert result == expected_result
            assert result.semantic_sha256 == expected_result.semantic_sha256


def test_availability_time_not_event_time_controls_replay_order() -> None:
    earlier_slice = SLICE
    later_slice = SLICE + timedelta(minutes=1)
    later_fact = market_event(
        "SPY",
        event_time=later_slice,
        available_at=later_slice + timedelta(seconds=1),
        event_id="later-event-time-earlier-availability",
    )
    earlier_fact = market_event(
        "SPY",
        event_time=earlier_slice,
        available_at=later_slice + timedelta(seconds=2),
        event_id="earlier-event-time-later-availability",
    )
    later_watermark = watermark(
        "SPY",
        event_time=later_slice,
        closed_at=later_slice + timedelta(seconds=3),
    )
    earlier_watermark = watermark(
        "SPY",
        event_time=earlier_slice,
        closed_at=later_slice + timedelta(seconds=2),
    )

    result = replay_market_events(
        events=(earlier_fact, later_fact),
        watermarks=(earlier_watermark, later_watermark),
    )

    assert result.processed_event_ids == (
        "later-event-time-earlier-availability",
        "earlier-event-time-later-availability",
    )
    assert [batch.watermark.event_time_through for batch in result.batches] == [
        earlier_slice,
        later_slice,
    ]


def test_watermark_event_time_frontier_cannot_regress_in_closed_order() -> None:
    later_slice = SLICE + timedelta(minutes=1)

    with pytest.raises(ReplayContractError, match="strictly increase"):
        replay_market_events(
            events=(),
            watermarks=(
                watermark(
                    "SPY",
                    event_time=later_slice,
                    closed_at=later_slice + timedelta(seconds=1),
                ),
                watermark(
                    "SPY",
                    event_time=SLICE,
                    closed_at=later_slice + timedelta(seconds=2),
                ),
            ),
        )


def test_exact_duplicate_delivery_collapses_and_conflicting_identity_fails() -> None:
    event = market_event()

    result = replay_market_events(
        events=(event, event),
        watermarks=(watermark("SPY"),),
    )

    assert result.processed_event_ids == (event.event_id,)
    with pytest.raises(ReplayIdentityConflict, match="conflicting semantics"):
        replay_market_events(
            events=(event, replace(event, close_price=Decimal("999.00"))),
            watermarks=(watermark("SPY"),),
        )


def test_equivalent_decimal_scales_have_input_order_independent_digests() -> None:
    one_decimal_place = market_event(close_price=Decimal("100.0"))
    two_decimal_places = replace(
        one_decimal_place,
        close_price=Decimal("100.00"),
    )

    forward = replay_market_events(
        events=(one_decimal_place, two_decimal_places),
        watermarks=(watermark("SPY"),),
    )
    reversed_result = replay_market_events(
        events=(two_decimal_places, one_decimal_place),
        watermarks=(watermark("SPY"),),
    )

    assert forward == reversed_result
    assert forward.tape_sha256 == reversed_result.tape_sha256
    assert forward.semantic_sha256 == reversed_result.semantic_sha256
    assert forward.batches[0].events[0].close_price.as_tuple() == Decimal("1E+2").as_tuple()

    def downstream_risk_hash(result: ReplayResult) -> str:
        batch = result.batches[0]
        context = ReadOnlyStrategyContext(
            decision_batch_id=batch.batch_id,
            decision_batch_sha256=batch.semantic_sha256,
            as_of=batch.as_of,
            current_positions={},
        )
        target = FixedQuantityStrategy(target_quantity=Decimal("10")).on_market(
            context,
            batch,
        )
        assert target is not None
        intent = target_to_order_intent(target, Decimal("0"), batch)
        assert intent is not None
        return intent_payload_hash(intent)

    assert downstream_risk_hash(forward) == downstream_risk_hash(reversed_result)


def test_observation_identity_is_bound_globally_to_one_instrument_and_slice() -> None:
    future_slice = SLICE + timedelta(minutes=1)
    shared_observation_id = "provider-observation-1"
    first = market_event("SPY", observation_id=shared_observation_id)
    reused = market_event(
        "QQQ",
        event_time=future_slice,
        available_at=future_slice + timedelta(seconds=1),
        event_id="reused-provider-observation",
        observation_id=shared_observation_id,
    )

    with pytest.raises(ReplayIdentityConflict, match="multiple instrument/event-time"):
        replay_market_events(
            events=(first, reused),
            watermarks=(
                watermark("SPY"),
                watermark(
                    "QQQ",
                    event_time=future_slice,
                    closed_at=future_slice + timedelta(seconds=1),
                ),
            ),
        )


def test_distinct_high_precision_decimals_cannot_collide_in_digests() -> None:
    first = market_event(
        close_price=Decimal("123456789012345678.1234567891"),
    )
    second = replace(
        first,
        close_price=Decimal("123456789012345678.1234567892"),
    )

    first_result = replay_market_events(
        events=(first,),
        watermarks=(watermark("SPY"),),
    )
    second_result = replay_market_events(
        events=(second,),
        watermarks=(watermark("SPY"),),
    )

    assert first_result.batches[0].semantic_sha256 != second_result.batches[0].semantic_sha256
    assert first_result.tape_sha256 != second_result.tape_sha256
    assert first_result.semantic_sha256 != second_result.semantic_sha256


def test_revision_policy_selects_only_visible_contiguous_revision() -> None:
    first = market_event(available_at=CLOSED_AT - timedelta(seconds=1))
    correction = market_event(
        available_at=CLOSED_AT,
        revision=2,
        source_sequence=2,
        supersedes_event_revision_id=first.event_id,
        close_price=Decimal("101.00"),
    )

    revised = replay_market_events(
        events=(correction, first),
        watermarks=(watermark("SPY"),),
    )
    first_seen = replay_market_events(
        events=(correction, first),
        watermarks=(
            watermark(
                "SPY",
                revision_policy=ReplayRevisionPolicy.FIRST_SEEN,
            ),
        ),
    )

    assert revised.batches[0].events == (correction,)
    assert first_seen.batches[0].events == (first,)
    assert revised.processed_event_ids == (first.event_id, correction.event_id)
    assert revised.semantic_sha256 != first_seen.semantic_sha256


def test_tape_digest_covers_unselected_revision_semantics() -> None:
    first = market_event(available_at=CLOSED_AT - timedelta(seconds=1))
    correction = market_event(
        available_at=CLOSED_AT,
        revision=2,
        source_sequence=2,
        supersedes_event_revision_id=first.event_id,
        close_price=Decimal("101.00"),
    )
    first_seen_watermark = watermark(
        "SPY",
        revision_policy=ReplayRevisionPolicy.FIRST_SEEN,
    )

    baseline = replay_market_events(
        events=(first, correction),
        watermarks=(first_seen_watermark,),
    )
    changed_unselected_revision = replay_market_events(
        events=(first, replace(correction, close_price=Decimal("999.00"))),
        watermarks=(first_seen_watermark,),
    )

    assert baseline.batches == changed_unselected_revision.batches
    assert baseline.tape_sha256 != changed_unselected_revision.tape_sha256
    assert baseline.semantic_sha256 != changed_unselected_revision.semantic_sha256


@pytest.mark.parametrize(
    ("correction_changes", "message"),
    [
        ({"revision": 3}, "noncontiguous"),
        ({"revision": 10**12}, "noncontiguous"),
        ({"supersedes_event_revision_id": "wrong"}, "broken revision"),
        ({"available_at": SLICE}, "revision availability"),
        ({"source_sequence": None}, "source-sequence presence"),
        ({"source_sequence": 1}, "nonmonotonic"),
    ],
)
def test_invalid_revision_lineage_fails_closed(
    correction_changes: dict[str, object],
    message: str,
) -> None:
    first = market_event(available_at=CLOSED_AT - timedelta(seconds=1))
    correction = market_event(
        available_at=CLOSED_AT,
        revision=2,
        source_sequence=2,
        supersedes_event_revision_id=first.event_id,
        close_price=Decimal("101.00"),
    )
    correction = replace(correction, **correction_changes)  # type: ignore[arg-type]

    with pytest.raises(MarketEventConflict, match=message):
        replay_market_events(
            events=(correction, first),
            watermarks=(watermark("SPY"),),
        )


def test_incomplete_watermark_is_sealed_and_skipped_without_callback() -> None:
    callbacks: list[str] = []

    result = replay_market_events(
        events=(market_event("SPY"),),
        watermarks=(watermark("QQQ", "SPY"),),
        on_complete_batch=lambda batch, _: callbacks.append(batch.batch_id),
    )

    batch = result.batches[0]
    assert batch.status is MarketBatchStatus.INCOMPLETE
    assert batch.received_instrument_ids == ("US-ETF-SPY",)
    assert batch.missing_instrument_ids == ("US-ETF-QQQ",)
    assert callbacks == []
    assert result.complete_batch_ids == ()
    assert result.skipped_batch_ids == (batch.batch_id,)


def test_late_correction_halts_and_never_reopens_a_sealed_batch() -> None:
    first = market_event(available_at=CLOSED_AT - timedelta(seconds=1))
    late_correction = market_event(
        available_at=CLOSED_AT + timedelta(microseconds=1),
        revision=2,
        source_sequence=2,
        supersedes_event_revision_id=first.event_id,
        close_price=Decimal("101.00"),
    )

    with pytest.raises(LateMarketEvent, match="after its watermark"):
        replay_market_events(
            events=(first, late_correction),
            watermarks=(watermark("SPY"),),
        )


def test_unexpected_instrument_or_unpinned_slice_fails_closed() -> None:
    with pytest.raises(UnexpectedMarketEvent, match="unexpected instrument"):
        replay_market_events(
            events=(market_event("QQQ"),),
            watermarks=(watermark("SPY"),),
        )

    with pytest.raises(UnexpectedMarketEvent, match="no pinned"):
        replay_market_events(
            events=(
                market_event(
                    "SPY",
                    event_time=SLICE + timedelta(minutes=1),
                    available_at=SLICE + timedelta(minutes=1, seconds=1),
                ),
            ),
            watermarks=(watermark("SPY"),),
        )


def test_future_tape_extension_cannot_change_an_earlier_batch() -> None:
    first_fact = market_event("SPY")
    first_watermark = watermark("SPY")
    baseline = replay_market_events(
        events=(first_fact,),
        watermarks=(first_watermark,),
    )
    future_slice = SLICE + timedelta(minutes=1)
    future_fact = market_event(
        "SPY",
        event_time=future_slice,
        available_at=future_slice + timedelta(seconds=5),
    )
    extended = replay_market_events(
        events=(future_fact, first_fact),
        watermarks=(
            watermark(
                "SPY",
                event_time=future_slice,
                closed_at=future_slice + timedelta(seconds=5),
            ),
            first_watermark,
        ),
    )

    assert extended.batches[0] == baseline.batches[0]
    assert extended.complete_batch_ids[0] == baseline.complete_batch_ids[0]

    def target_for(batch: MarketBatch) -> object:
        context = ReadOnlyStrategyContext(
            decision_batch_id=batch.batch_id,
            decision_batch_sha256=batch.semantic_sha256,
            as_of=batch.as_of,
            current_positions={},
        )
        return FixedQuantityStrategy(target_quantity=Decimal("10")).on_market(
            context,
            batch,
        )

    assert target_for(extended.batches[0]) == target_for(baseline.batches[0])


def test_strategy_context_copies_positions_and_rejects_noncausal_batch() -> None:
    positions = {"US-ETF-SPY": Decimal("7")}
    complete_batch = replay_market_events(
        events=(market_event(),),
        watermarks=(watermark("SPY"),),
    ).batches[0]
    context = ReadOnlyStrategyContext(
        decision_batch_id=complete_batch.batch_id,
        decision_batch_sha256=complete_batch.semantic_sha256,
        as_of=CLOSED_AT,
        current_positions=positions,
    )
    positions["US-ETF-SPY"] = Decimal("99")

    assert context.quantity_for("US-ETF-SPY") == Decimal("7")
    with pytest.raises(TypeError):
        context.current_positions["US-ETF-SPY"] = Decimal("8")  # type: ignore[index]
    context.require_batch(complete_batch)

    future_context = ReadOnlyStrategyContext(
        decision_batch_id=complete_batch.batch_id,
        decision_batch_sha256=complete_batch.semantic_sha256,
        as_of=CLOSED_AT + timedelta(seconds=1),
        current_positions={},
    )
    with pytest.raises(ValueError, match="same as_of"):
        future_context.require_batch(complete_batch)

    substitute_batch = replay_market_events(
        events=(replace(market_event(), close_price=Decimal("101"), event_id="substitute"),),
        watermarks=(watermark("SPY"),),
    ).batches[0]
    with pytest.raises(ValueError, match="batch ID"):
        context.require_batch(substitute_batch)


def test_market_batch_cannot_be_constructed_outside_the_replay_reducer() -> None:
    first = market_event("SPY", available_at=CLOSED_AT - timedelta(seconds=1))
    second = market_event("QQQ", available_at=CLOSED_AT - timedelta(seconds=1))
    batch_watermark = watermark("QQQ", "SPY")

    with pytest.raises(TypeError, match="only be created by the replay reducer"):
        MarketBatch(watermark=batch_watermark, events=(first, second))
    with pytest.raises(TypeError, match="only be created by the replay reducer"):
        MarketBatch(
            watermark=watermark("SPY"),
            events=(replace(first, available_at=CLOSED_AT + timedelta(microseconds=1)),),
        )
