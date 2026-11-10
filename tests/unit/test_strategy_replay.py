from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta, timezone
from decimal import ROUND_DOWN, ROUND_UP, Decimal, localcontext
from itertools import permutations

import pytest

from packages.domain.clock import ClockEvent, FixedClock
from packages.domain.decision import DecisionTrigger, DecisionTriggerKind
from packages.domain.identifiers import canonical_id
from packages.domain.market_batch import MarketBatch, MarketWatermark
from packages.domain.models import MarketEvent, PositionTarget, TargetPortfolio
from packages.domain.portfolio import target_to_order_intent
from packages.domain.replay import ReplayResult, replay_market_events
from packages.domain.strategy import (
    FixedQuantityStrategy,
    ReadOnlyStrategyContext,
    StrategyInitializationContext,
    StrategyTransition,
)
from packages.domain.strategy_replay import (
    ClockEventConflict,
    StrategyReplayContractError,
    StrategyTransitionError,
    replay_strategy_callbacks,
)
from packages.domain.strategy_state import (
    MAX_STATE_FIELDS,
    VersionedStrategyState,
)

SLICE = datetime(2026, 7, 15, 13, 31, tzinfo=UTC)
AVAILABLE_AT = SLICE + timedelta(seconds=10)
CLOSED_AT = SLICE + timedelta(seconds=30)
CONFIGURATION_SHA256 = "a" * 64


def market_event(
    *,
    event_time: datetime = SLICE,
    available_at: datetime = AVAILABLE_AT,
    event_id: str = "strategy-replay-SPY-1",
) -> MarketEvent:
    return MarketEvent(
        event_id=event_id,
        instrument_id="US-ETF-SPY",
        symbol="SPY",
        event_time=event_time,
        available_at=available_at,
        close_price=Decimal("100.00"),
        source="strategy-replay-fixture-v1",
        source_sequence=1,
        observation_id=f"observation-{event_id}",
    )


def watermark(
    *,
    event_time: datetime = SLICE,
    closed_at: datetime = CLOSED_AT,
    complete: bool = True,
) -> MarketWatermark:
    expected = ("US-ETF-SPY",) if complete else ("US-ETF-QQQ", "US-ETF-SPY")
    return MarketWatermark(
        watermark_id=f"strategy-watermark-{event_time.isoformat()}",
        event_time_through=event_time,
        closed_at=closed_at,
        expected_instrument_ids=expected,
    )


def market_replay(*, complete: bool = True) -> ReplayResult:
    return replay_market_events(
        events=(market_event(),),
        watermarks=(watermark(complete=complete),),
    )


def clock_event(
    clock_event_id: str,
    *,
    scheduled_at: datetime = CLOSED_AT,
    schedule_id: str = "regular-session-v1",
    sequence: int = 0,
) -> ClockEvent:
    return ClockEvent(
        clock_event_id=clock_event_id,
        schedule_id=schedule_id,
        scheduled_at=scheduled_at,
        sequence=sequence,
    )


def run_fixed(
    replay: ReplayResult,
    *,
    clocks: tuple[ClockEvent, ...] = (),
    positions: dict[str, Decimal] | None = None,
) -> object:
    return replay_strategy_callbacks(
        market_replay=replay,
        clock_events=clocks,
        strategy=FixedQuantityStrategy(target_quantity=Decimal("10")),
        current_positions=positions or {},
    )


def test_clock_event_and_fixed_clock_are_utc_only_and_semantically_complete() -> None:
    event = clock_event("rebalance-close", sequence=7)

    assert event.semantic_sha256 == replace(event).semantic_sha256
    assert event.semantic_sha256 != replace(event, sequence=8).semantic_sha256
    assert FixedClock(CLOSED_AT).now() == CLOSED_AT
    with pytest.raises(ValueError, match="must be UTC"):
        replace(event, scheduled_at=CLOSED_AT.astimezone(timezone(timedelta(hours=-4))))
    with pytest.raises(ValueError, match="timezone-aware"):
        replace(event, scheduled_at=CLOSED_AT.replace(tzinfo=None))
    with pytest.raises(ValueError, match="must be UTC"):
        FixedClock(CLOSED_AT.astimezone(timezone(timedelta(hours=-4))))
    with pytest.raises(ValueError, match="non-negative"):
        replace(event, sequence=-1)
    with pytest.raises(ValueError, match="trimmed"):
        replace(event, clock_event_id=" bad ")


def test_equal_time_market_then_canonical_clocks_are_permutation_invariant() -> None:
    replay = market_replay()
    clocks = (
        clock_event("close-z", schedule_id="z-schedule", sequence=0),
        clock_event("close-a-1", schedule_id="a-schedule", sequence=1),
        clock_event("close-a-0", schedule_id="a-schedule", sequence=0),
    )
    expected = None

    for ordering in permutations(clocks):
        result = run_fixed(replay, clocks=(*ordering, ordering[0]))
        assert [decision.trigger.kind for decision in result.decisions] == [
            DecisionTriggerKind.MARKET_BATCH,
            DecisionTriggerKind.CLOCK,
            DecisionTriggerKind.CLOCK,
            DecisionTriggerKind.CLOCK,
        ]
        assert [decision.trigger.trigger_id for decision in result.decisions[1:]] == [
            "close-a-0",
            "close-a-1",
            "close-z",
        ]
        assert result.market_callback_count == 1
        assert result.clock_callback_count == 3
        assert result.final_state.values == {
            "clock_callbacks": 3,
            "market_callbacks": 1,
        }
        if expected is None:
            expected = result
        else:
            assert result == expected
            assert result.semantic_sha256 == expected.semantic_sha256


def test_clock_identity_slot_order_and_coverage_conflicts_fail_closed() -> None:
    replay = market_replay()
    event = clock_event("event-1")

    with pytest.raises(ClockEventConflict, match="conflicting semantics"):
        run_fixed(replay, clocks=(event, replace(event, schedule_id="other")))
    with pytest.raises(ClockEventConflict, match="slot"):
        run_fixed(replay, clocks=(event, replace(event, clock_event_id="event-2")))
    with pytest.raises(ClockEventConflict, match="outside"):
        run_fixed(
            replay,
            clocks=(replace(event, scheduled_at=replay.completed_at + timedelta(microseconds=1)),),
        )
    with pytest.raises(ClockEventConflict, match="moves backwards"):
        run_fixed(
            replay,
            clocks=(
                replace(event, sequence=0, scheduled_at=CLOSED_AT),
                clock_event(
                    "event-2",
                    sequence=1,
                    scheduled_at=CLOSED_AT - timedelta(seconds=1),
                ),
            ),
        )


def test_incomplete_batch_skips_market_callback_but_explicit_clock_still_runs() -> None:
    replay = market_replay(complete=False)

    result = run_fixed(replay, clocks=(clock_event("incomplete-close"),))

    assert replay.complete_batch_ids == ()
    assert len(replay.skipped_batch_ids) == 1
    assert result.market_callback_count == 0
    assert result.clock_callback_count == 1
    assert result.targets == ()
    assert result.final_state.values == {
        "clock_callbacks": 1,
        "market_callbacks": 0,
    }


def test_state_payload_is_canonical_bounded_copied_and_immutable() -> None:
    values: dict[str, object] = {"z": Decimal("1.00"), "a": 1}
    first = VersionedStrategyState.initial(
        strategy_id="example",
        strategy_version="1.0.0",
        strategy_configuration_sha256=CONFIGURATION_SHA256,
        schema_version="example-state-v1",
        as_of=AVAILABLE_AT,
        values=values,
    )
    second = VersionedStrategyState.initial(
        strategy_id="example",
        strategy_version="1.0.0",
        strategy_configuration_sha256=CONFIGURATION_SHA256,
        schema_version="example-state-v1",
        as_of=AVAILABLE_AT,
        values={"a": 1, "z": Decimal("1")},
    )
    values["a"] = 99

    assert first == second
    assert first.semantic_sha256 == second.semantic_sha256
    assert first.values == {"a": 1, "z": Decimal("1")}
    with pytest.raises(TypeError):
        first.values["a"] = 2  # type: ignore[index]
    with pytest.raises(ValueError, match="must be null"):
        VersionedStrategyState.initial(
            strategy_id="example",
            strategy_version="1.0.0",
            strategy_configuration_sha256=CONFIGURATION_SHA256,
            schema_version="example-state-v1",
            as_of=AVAILABLE_AT,
            values={"float": 1.5},
        )
    with pytest.raises(ValueError, match="field-count"):
        VersionedStrategyState.initial(
            strategy_id="example",
            strategy_version="1.0.0",
            strategy_configuration_sha256=CONFIGURATION_SHA256,
            schema_version="example-state-v1",
            as_of=AVAILABLE_AT,
            values={str(index): index for index in range(MAX_STATE_FIELDS + 1)},
        )


@dataclass(frozen=True, slots=True)
class StaleStateStrategy:
    strategy_id: str = "stale-state"
    version: str = "1.0.0"
    state_schema_version: str = "stale-state-v1"
    configuration_sha256: str = CONFIGURATION_SHA256

    def initialize(self, context: StrategyInitializationContext) -> VersionedStrategyState:
        return VersionedStrategyState.initial(
            strategy_id=self.strategy_id,
            strategy_version=self.version,
            strategy_configuration_sha256=self.configuration_sha256,
            schema_version=self.state_schema_version,
            as_of=context.started_at,
            values={},
        )

    def on_market(
        self,
        context: ReadOnlyStrategyContext,
        batch: MarketBatch,
    ) -> StrategyTransition:
        context.require_batch(batch)
        return StrategyTransition(state=context.state)

    def on_clock(
        self,
        context: ReadOnlyStrategyContext,
        event: ClockEvent,
    ) -> StrategyTransition:
        context.require_clock_event(event)
        return StrategyTransition(state=context.state)


def test_stale_or_forked_callback_state_is_rejected() -> None:
    with pytest.raises(StrategyTransitionError, match="generation"):
        replay_strategy_callbacks(
            market_replay=market_replay(),
            clock_events=(),
            strategy=StaleStateStrategy(),
            current_positions={},
        )

    state = VersionedStrategyState.initial(
        strategy_id="example",
        strategy_version="1.0.0",
        strategy_configuration_sha256=CONFIGURATION_SHA256,
        schema_version="example-state-v1",
        as_of=AVAILABLE_AT,
        values={},
    )
    trigger = DecisionTrigger.from_clock_event(clock_event("advance", scheduled_at=AVAILABLE_AT))
    successor = state.advance(trigger=trigger, values={})
    fork = VersionedStrategyState(
        strategy_id=successor.strategy_id,
        strategy_version=successor.strategy_version,
        strategy_configuration_sha256=successor.strategy_configuration_sha256,
        schema_version=successor.schema_version,
        generation=successor.generation,
        as_of=successor.as_of,
        values={},
        previous_state_sha256="0" * 64,
        trigger=trigger,
    )
    with pytest.raises(ValueError, match="exact predecessor"):
        state.require_successor(fork, trigger)


@dataclass(frozen=True, slots=True)
class ClockTargetStrategy:
    delegate: FixedQuantityStrategy = field(
        default_factory=lambda: FixedQuantityStrategy(target_quantity=Decimal("10"))
    )

    @property
    def strategy_id(self) -> str:
        return self.delegate.strategy_id

    @property
    def version(self) -> str:
        return self.delegate.version

    @property
    def state_schema_version(self) -> str:
        return self.delegate.state_schema_version

    @property
    def configuration_sha256(self) -> str:
        return self.delegate.configuration_sha256

    def initialize(self, context: StrategyInitializationContext) -> VersionedStrategyState:
        return self.delegate.initialize(context)

    def on_market(
        self,
        context: ReadOnlyStrategyContext,
        batch: MarketBatch,
    ) -> StrategyTransition:
        return self.delegate.on_market(context, batch)

    def on_clock(
        self,
        context: ReadOnlyStrategyContext,
        event: ClockEvent,
    ) -> StrategyTransition:
        state_only = self.delegate.on_clock(context, event)
        target = TargetPortfolio(
            target_id=canonical_id("clock-target", context.decision_trigger.semantic_sha256),
            strategy_id=self.strategy_id,
            strategy_version=self.version,
            strategy_configuration_sha256=self.configuration_sha256,
            decision_trigger=context.decision_trigger,
            as_of=context.as_of,
            expires_at=context.as_of + timedelta(minutes=5),
            targets=(
                PositionTarget(
                    instrument_id="US-ETF-SPY",
                    symbol="SPY",
                    quantity=Decimal("5"),
                ),
            ),
        )
        return StrategyTransition(state=state_only.state, target=target)


@dataclass(slots=True)
class MutatingCallerPositionsStrategy:
    caller_positions: dict[str, Decimal]
    delegate: FixedQuantityStrategy = field(
        default_factory=lambda: FixedQuantityStrategy(target_quantity=Decimal("10"))
    )

    @property
    def strategy_id(self) -> str:
        return self.delegate.strategy_id

    @property
    def version(self) -> str:
        return self.delegate.version

    @property
    def state_schema_version(self) -> str:
        return self.delegate.state_schema_version

    @property
    def configuration_sha256(self) -> str:
        return self.delegate.configuration_sha256

    def initialize(self, context: StrategyInitializationContext) -> VersionedStrategyState:
        return self.delegate.initialize(context)

    def on_market(
        self,
        context: ReadOnlyStrategyContext,
        batch: MarketBatch,
    ) -> StrategyTransition:
        if context.quantity_for("US-ETF-SPY") != Decimal("7"):
            raise AssertionError("market callback did not receive the entry snapshot")
        transition = self.delegate.on_market(context, batch)
        self.caller_positions["US-ETF-SPY"] = Decimal("99")
        return transition

    def on_clock(
        self,
        context: ReadOnlyStrategyContext,
        event: ClockEvent,
    ) -> StrategyTransition:
        if context.quantity_for("US-ETF-SPY") != Decimal("7"):
            raise AssertionError("clock callback observed caller mutation")
        return self.delegate.on_clock(context, event)


@dataclass(slots=True)
class DriftingRuntimePinStrategy:
    delegate: FixedQuantityStrategy = field(
        default_factory=lambda: FixedQuantityStrategy(target_quantity=Decimal("10"))
    )
    configuration_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        self.configuration_sha256 = self.delegate.configuration_sha256

    @property
    def strategy_id(self) -> str:
        return self.delegate.strategy_id

    @property
    def version(self) -> str:
        return self.delegate.version

    @property
    def state_schema_version(self) -> str:
        return self.delegate.state_schema_version

    def initialize(self, context: StrategyInitializationContext) -> VersionedStrategyState:
        return self.delegate.initialize(context)

    def on_market(
        self,
        context: ReadOnlyStrategyContext,
        batch: MarketBatch,
    ) -> StrategyTransition:
        transition = self.delegate.on_market(context, batch)
        self.configuration_sha256 = "b" * 64
        return transition

    def on_clock(
        self,
        context: ReadOnlyStrategyContext,
        event: ClockEvent,
    ) -> StrategyTransition:
        return self.delegate.on_clock(context, event)


def test_clock_target_is_causal_but_current_market_intent_converter_rejects_it() -> None:
    replay = market_replay()
    result = replay_strategy_callbacks(
        market_replay=replay,
        clock_events=(clock_event("clock-target"),),
        strategy=ClockTargetStrategy(),
        current_positions={"US-ETF-SPY": Decimal("10")},
    )

    assert len(result.targets) == 1
    target = result.targets[0]
    assert target.decision_clock_event_id == "clock-target"
    with pytest.raises(ValueError, match="not a market batch"):
        target_to_order_intent(target, Decimal("10"), replay.batches[0])


def test_one_position_snapshot_is_used_even_if_caller_mapping_mutates() -> None:
    positions = {"US-ETF-SPY": Decimal("7")}

    result = replay_strategy_callbacks(
        market_replay=market_replay(),
        clock_events=(clock_event("after-market"),),
        strategy=MutatingCallerPositionsStrategy(positions),
        current_positions=positions,
    )

    assert positions == {"US-ETF-SPY": Decimal("99")}
    assert result.market_callback_count == 1
    assert result.clock_callback_count == 1


def test_strategy_runtime_pin_drift_fails_closed() -> None:
    with pytest.raises(StrategyTransitionError, match="runtime pins changed"):
        replay_strategy_callbacks(
            market_replay=market_replay(),
            clock_events=(),
            strategy=DriftingRuntimePinStrategy(),
            current_positions={},
        )


@dataclass(frozen=True, slots=True)
class ExplodingClockStrategy(ClockTargetStrategy):
    def on_clock(
        self,
        context: ReadOnlyStrategyContext,
        event: ClockEvent,
    ) -> StrategyTransition:
        del context, event
        raise RuntimeError("callback failed")


class WrongTargetConfigurationStrategy(FixedQuantityStrategy):
    def on_market(
        self,
        context: ReadOnlyStrategyContext,
        batch: MarketBatch,
    ) -> StrategyTransition:
        transition = super().on_market(context, batch)
        assert transition.target is not None
        return replace(
            transition,
            target=replace(transition.target, strategy_configuration_sha256="b" * 64),
        )


def test_target_configuration_must_match_captured_runtime_pin() -> None:
    with pytest.raises(
        StrategyTransitionError, match="target has the wrong strategy configuration"
    ):
        replay_strategy_callbacks(
            market_replay=market_replay(),
            clock_events=(),
            strategy=WrongTargetConfigurationStrategy(target_quantity=Decimal("10")),
            current_positions={},
        )


def test_callback_failure_returns_no_partial_transcript() -> None:
    with pytest.raises(RuntimeError, match="callback failed"):
        replay_strategy_callbacks(
            market_replay=market_replay(),
            clock_events=(clock_event("explode"),),
            strategy=ExplodingClockStrategy(),
            current_positions={},
        )


def test_future_tape_and_schedule_extension_preserve_prior_decision_prefix() -> None:
    baseline_replay = market_replay()
    baseline_clock = clock_event(
        "mid-slice",
        scheduled_at=AVAILABLE_AT + timedelta(seconds=5),
    )
    baseline = run_fixed(baseline_replay, clocks=(baseline_clock,))
    future_slice = SLICE + timedelta(minutes=1)
    future_available = future_slice + timedelta(seconds=10)
    future_closed = future_slice + timedelta(seconds=30)
    extended_replay = replay_market_events(
        events=(
            market_event(),
            market_event(
                event_time=future_slice,
                available_at=future_available,
                event_id="strategy-replay-SPY-2",
            ),
        ),
        watermarks=(
            watermark(),
            watermark(event_time=future_slice, closed_at=future_closed),
        ),
    )
    extended = run_fixed(
        extended_replay,
        clocks=(
            clock_event(
                "future-clock",
                scheduled_at=future_available + timedelta(seconds=5),
                sequence=1,
            ),
            baseline_clock,
        ),
    )

    assert extended.decisions[: len(baseline.decisions)] == baseline.decisions
    assert extended.final_state.generation == baseline.final_state.generation + 2


def test_transcript_is_decimal_context_independent_and_binds_positions_and_targets() -> None:
    replay = market_replay()

    with localcontext() as context:
        context.prec = 4
        context.rounding = ROUND_DOWN
        low_precision = replay_strategy_callbacks(
            market_replay=replay,
            clock_events=(clock_event("close"),),
            strategy=FixedQuantityStrategy(target_quantity=Decimal("10.00")),
            current_positions={"US-ETF-QQQ": Decimal("0.00"), "US-ETF-SPY": Decimal("0")},
        )
    with localcontext() as context:
        context.prec = 40
        context.rounding = ROUND_UP
        high_precision = replay_strategy_callbacks(
            market_replay=replay,
            clock_events=(clock_event("close"),),
            strategy=FixedQuantityStrategy(target_quantity=Decimal("10")),
            current_positions={"US-ETF-SPY": Decimal("0.0"), "US-ETF-QQQ": Decimal("0")},
        )

    assert low_precision == high_precision
    assert low_precision.semantic_sha256 == high_precision.semantic_sha256
    assert len(low_precision.targets) == 1
    target = low_precision.targets[0]
    assert target.strategy_configuration_sha256 == low_precision.strategy_configuration_sha256
    assert (
        target.semantic_sha256
        != replace(
            target,
            expires_at=target.expires_at + timedelta(seconds=1),
        ).semantic_sha256
    )

    already_positioned = run_fixed(
        replay,
        positions={"US-ETF-SPY": Decimal("10")},
    )
    assert already_positioned.targets == ()
    assert already_positioned.initialization_context_sha256 != (
        low_precision.initialization_context_sha256
    )
    assert already_positioned.semantic_sha256 != low_precision.semantic_sha256

    different_configuration = replay_strategy_callbacks(
        market_replay=replay,
        clock_events=(clock_event("close"),),
        strategy=FixedQuantityStrategy(target_quantity=Decimal("11")),
        current_positions={"US-ETF-SPY": Decimal("0"), "US-ETF-QQQ": Decimal("0")},
    )
    assert different_configuration.strategy_configuration_sha256 != (
        low_precision.strategy_configuration_sha256
    )
    assert different_configuration.initial_state.semantic_sha256 != (
        low_precision.initial_state.semantic_sha256
    )
    assert different_configuration.semantic_sha256 != low_precision.semantic_sha256


def test_replay_result_indexes_are_revalidated_before_any_callback() -> None:
    replay = market_replay()
    malformed = replace(replay, complete_batch_ids=())

    with pytest.raises(StrategyReplayContractError, match="complete-batch index"):
        run_fixed(malformed)

    batch = replay.batches[0]
    duplicated = replace(
        replay,
        batches=(batch, batch),
        complete_batch_ids=(batch.batch_id, batch.batch_id),
    )
    with pytest.raises(StrategyReplayContractError, match="repeats a batch identity"):
        run_fixed(duplicated, positions={"US-ETF-SPY": Decimal("10")})

    truncated_interval = replace(
        replay,
        completed_at=AVAILABLE_AT + timedelta(seconds=1),
    )
    with pytest.raises(StrategyReplayContractError, match="outside the completed"):
        run_fixed(truncated_interval)
