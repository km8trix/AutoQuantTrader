"""Deterministic strategy callbacks layered over completed market replay output."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from itertools import pairwise

from packages.domain.canonical import canonical_json_bytes
from packages.domain.clock import ClockEvent, SimulatedClock
from packages.domain.decision import DecisionTrigger, DecisionTriggerKind
from packages.domain.market_batch import MarketBatch
from packages.domain.models import TargetPortfolio
from packages.domain.replay import ReplayResult
from packages.domain.strategy import (
    ReadOnlyStrategyContext,
    Strategy,
    StrategyInitializationContext,
    StrategyTransition,
)
from packages.domain.strategy_state import VersionedStrategyState

STRATEGY_REPLAY_CONTRACT_VERSION = "phase2-strategy-replay-v1"
CLOCK_SCHEDULE_CONTRACT_VERSION = "phase2-clock-schedule-v1"


class StrategyReplayContractError(ValueError):
    """The strategy schedule or callback transcript is causally ambiguous."""


class ClockEventConflict(StrategyReplayContractError):
    """One clock identity or schedule slot was reused inconsistently."""


class StrategyTransitionError(StrategyReplayContractError):
    """A strategy callback returned an invalid state transition or target."""


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: str, field_name: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise StrategyReplayContractError(f"{field_name} must be a non-empty, trimmed string")


@dataclass(frozen=True, slots=True)
class StrategyRuntimePin:
    strategy_id: str
    strategy_version: str
    strategy_configuration_sha256: str
    state_schema_version: str

    @classmethod
    def capture(cls, strategy: Strategy) -> StrategyRuntimePin:
        pin = cls(
            strategy_id=strategy.strategy_id,
            strategy_version=strategy.version,
            strategy_configuration_sha256=strategy.configuration_sha256,
            state_schema_version=strategy.state_schema_version,
        )
        for value, field_name in (
            (pin.strategy_id, "strategy ID"),
            (pin.strategy_version, "strategy version"),
            (pin.state_schema_version, "strategy state schema version"),
        ):
            _require_text(value, field_name)
        if (
            type(pin.strategy_configuration_sha256) is not str
            or len(pin.strategy_configuration_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in pin.strategy_configuration_sha256
            )
        ):
            raise StrategyReplayContractError(
                "strategy configuration digest must be lowercase SHA-256"
            )
        return pin

    def require_unchanged(self, strategy: Strategy) -> None:
        current = (
            strategy.strategy_id,
            strategy.version,
            strategy.configuration_sha256,
            strategy.state_schema_version,
        )
        expected = (
            self.strategy_id,
            self.strategy_version,
            self.strategy_configuration_sha256,
            self.state_schema_version,
        )
        if current != expected:
            raise StrategyTransitionError("strategy runtime pins changed during replay")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                STRATEGY_REPLAY_CONTRACT_VERSION,
                "strategy-runtime-pin",
                self.strategy_id,
                self.strategy_version,
                self.strategy_configuration_sha256,
                self.state_schema_version,
            )
        )


def _unique_clock_events(
    events: Iterable[ClockEvent],
    *,
    started_at: datetime,
    completed_at: datetime,
) -> tuple[ClockEvent, ...]:
    by_id: dict[str, ClockEvent] = {}
    by_slot: dict[tuple[str, int], ClockEvent] = {}
    for event in events:
        if type(event) is not ClockEvent:
            raise ClockEventConflict("clock schedule must contain exact ClockEvent values")
        existing = by_id.get(event.clock_event_id)
        if existing is not None:
            if existing != event:
                raise ClockEventConflict(
                    f"clock event identity {event.clock_event_id!r} has conflicting semantics"
                )
            continue
        slot = (event.schedule_id, event.sequence)
        same_slot = by_slot.get(slot)
        if same_slot is not None:
            raise ClockEventConflict(f"clock schedule slot {slot!r} is assigned more than once")
        if not started_at <= event.scheduled_at <= completed_at:
            raise ClockEventConflict("clock event is outside the sealed market-replay interval")
        by_id[event.clock_event_id] = event
        by_slot[slot] = event

    by_schedule: dict[str, list[ClockEvent]] = {}
    for event in by_id.values():
        by_schedule.setdefault(event.schedule_id, []).append(event)
    for schedule_id, schedule_events in by_schedule.items():
        ordered_schedule = sorted(schedule_events, key=lambda item: item.sequence)
        for previous, current in pairwise(ordered_schedule):
            if current.scheduled_at < previous.scheduled_at:
                raise ClockEventConflict(
                    f"clock schedule {schedule_id!r} moves backwards by sequence"
                )
    return tuple(
        sorted(
            by_id.values(),
            key=lambda event: (
                event.scheduled_at,
                event.schedule_id,
                event.sequence,
                event.clock_event_id,
            ),
        )
    )


def _strategy_item_key(item: MarketBatch | ClockEvent) -> tuple[object, ...]:
    if isinstance(item, MarketBatch):
        return (
            item.as_of,
            0,
            item.watermark.event_time_through,
            item.watermark.watermark_id,
            item.batch_id,
        )
    return (
        item.scheduled_at,
        1,
        item.schedule_id,
        item.sequence,
        item.clock_event_id,
    )


def _validate_market_replay(replay: ReplayResult) -> None:
    if type(replay) is not ReplayResult:
        raise StrategyReplayContractError("strategy replay requires an exact ReplayResult")
    if replay.started_at > replay.completed_at:
        raise StrategyReplayContractError("market replay completion cannot precede its start")
    if type(replay.batches) is not tuple:
        raise StrategyReplayContractError("market replay batches must be an immutable tuple")
    batch_ids: set[str] = set()
    for batch in replay.batches:
        if type(batch) is not MarketBatch:
            raise StrategyReplayContractError(
                "market replay batches must contain exact MarketBatch values"
            )
        if batch.batch_id in batch_ids:
            raise StrategyReplayContractError("market replay repeats a batch identity")
        if not replay.started_at <= batch.as_of <= replay.completed_at:
            raise StrategyReplayContractError(
                "market replay batch is outside the completed replay interval"
            )
        batch_ids.add(batch.batch_id)
    if replay.batches != tuple(sorted(replay.batches, key=_strategy_item_key)):
        raise StrategyReplayContractError("market replay batches are not canonically ordered")
    complete_ids = tuple(batch.batch_id for batch in replay.batches if batch.complete)
    skipped_ids = tuple(batch.batch_id for batch in replay.batches if not batch.complete)
    if replay.complete_batch_ids != complete_ids:
        raise StrategyReplayContractError("market replay complete-batch index is inconsistent")
    if replay.skipped_batch_ids != skipped_ids:
        raise StrategyReplayContractError("market replay skipped-batch index is inconsistent")


def _validate_initial_state(
    state: VersionedStrategyState,
    *,
    strategy_pin: StrategyRuntimePin,
    started_at: datetime,
) -> None:
    if type(state) is not VersionedStrategyState:
        raise StrategyTransitionError("strategy initialize must return exact versioned state")
    if state.strategy_id != strategy_pin.strategy_id:
        raise StrategyTransitionError("initial state has the wrong strategy identity")
    if state.strategy_version != strategy_pin.strategy_version:
        raise StrategyTransitionError("initial state has the wrong strategy version")
    if state.strategy_configuration_sha256 != strategy_pin.strategy_configuration_sha256:
        raise StrategyTransitionError("initial state has the wrong strategy configuration")
    if state.schema_version != strategy_pin.state_schema_version:
        raise StrategyTransitionError("initial state has the wrong schema version")
    if state.generation != 0:
        raise StrategyTransitionError("initial state generation must be zero")
    if state.as_of != started_at:
        raise StrategyTransitionError("initial state must be bound to replay start")
    if state.previous_state_sha256 is not None or state.trigger is not None:
        raise StrategyTransitionError("initial state cannot have a predecessor or trigger")


def _validate_target(
    target: TargetPortfolio,
    *,
    trigger: DecisionTrigger,
    strategy_pin: StrategyRuntimePin,
) -> None:
    if type(target) is not TargetPortfolio:
        raise StrategyTransitionError("strategy callback target must be exact TargetPortfolio")
    if target.strategy_id != strategy_pin.strategy_id:
        raise StrategyTransitionError("strategy target has the wrong strategy identity")
    if target.strategy_version != strategy_pin.strategy_version:
        raise StrategyTransitionError("strategy target has the wrong strategy version")
    if target.decision_trigger != trigger:
        raise StrategyTransitionError("strategy target is not bound to the exact callback trigger")
    if target.as_of != trigger.as_of:
        raise StrategyTransitionError("strategy target is not bound to the callback time")


@dataclass(frozen=True, slots=True)
class StrategyDecisionRecord:
    sequence: int
    trigger: DecisionTrigger
    context_sha256: str
    input_state_sha256: str
    transition: StrategyTransition

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError("strategy decision sequence must be positive")
        if type(self.trigger) is not DecisionTrigger:
            raise ValueError("strategy decision record requires an exact trigger")
        for value, field_name in (
            (self.context_sha256, "strategy context digest"),
            (self.input_state_sha256, "strategy input-state digest"),
        ):
            if (
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError(f"{field_name} must be lowercase SHA-256")
        if type(self.transition) is not StrategyTransition:
            raise ValueError("strategy decision record requires an exact transition")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                STRATEGY_REPLAY_CONTRACT_VERSION,
                "decision",
                self.sequence,
                self.trigger.semantic_sha256,
                self.context_sha256,
                self.input_state_sha256,
                self.transition.semantic_sha256,
            )
        )


@dataclass(frozen=True, slots=True)
class StrategyReplayResult:
    started_at: datetime
    completed_at: datetime
    market_replay_sha256: str
    clock_schedule_sha256: str
    strategy_pin: StrategyRuntimePin
    initialization_context_sha256: str
    initial_state: VersionedStrategyState
    decisions: tuple[StrategyDecisionRecord, ...]
    final_state: VersionedStrategyState

    @property
    def strategy_id(self) -> str:
        return self.strategy_pin.strategy_id

    @property
    def strategy_version(self) -> str:
        return self.strategy_pin.strategy_version

    @property
    def strategy_configuration_sha256(self) -> str:
        return self.strategy_pin.strategy_configuration_sha256

    @property
    def state_schema_version(self) -> str:
        return self.strategy_pin.state_schema_version

    @property
    def targets(self) -> tuple[TargetPortfolio, ...]:
        return tuple(
            decision.transition.target
            for decision in self.decisions
            if decision.transition.target is not None
        )

    @property
    def market_callback_count(self) -> int:
        return sum(
            decision.trigger.kind is DecisionTriggerKind.MARKET_BATCH for decision in self.decisions
        )

    @property
    def clock_callback_count(self) -> int:
        return sum(
            decision.trigger.kind is DecisionTriggerKind.CLOCK for decision in self.decisions
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                STRATEGY_REPLAY_CONTRACT_VERSION,
                self.started_at,
                self.completed_at,
                self.market_replay_sha256,
                self.clock_schedule_sha256,
                self.strategy_pin.semantic_sha256,
                self.initialization_context_sha256,
                self.initial_state.semantic_sha256,
                tuple(decision.semantic_sha256 for decision in self.decisions),
                self.final_state.semantic_sha256,
            )
        )


def replay_strategy_callbacks(
    *,
    market_replay: ReplayResult,
    clock_events: Iterable[ClockEvent],
    strategy: Strategy,
    current_positions: Mapping[str, Decimal],
) -> StrategyReplayResult:
    """Run a pure strategy reducer over complete batches and explicit clocks.

    The sealed market reducer remains unchanged. At an equal instant, every
    watermark-complete market batch is reduced before canonically ordered clock
    events. Callback failure raises and no result is returned or persisted.
    """

    _validate_market_replay(market_replay)
    strategy_pin = StrategyRuntimePin.capture(strategy)

    clocks = _unique_clock_events(
        clock_events,
        started_at=market_replay.started_at,
        completed_at=market_replay.completed_at,
    )
    clock_schedule_sha256 = _semantic_sha256(
        (
            CLOCK_SCHEDULE_CONTRACT_VERSION,
            tuple(
                (
                    event.clock_event_id,
                    event.schedule_id,
                    event.scheduled_at,
                    event.sequence,
                    event.semantic_sha256,
                )
                for event in clocks
            ),
        )
    )
    initialization_context = StrategyInitializationContext(
        started_at=market_replay.started_at,
        current_positions=current_positions,
    )
    position_snapshot = initialization_context.current_positions
    initial_state = strategy.initialize(initialization_context)
    strategy_pin.require_unchanged(strategy)
    _validate_initial_state(
        initial_state,
        strategy_pin=strategy_pin,
        started_at=market_replay.started_at,
    )

    callback_items: tuple[MarketBatch | ClockEvent, ...] = tuple(
        sorted(
            (
                *(batch for batch in market_replay.batches if batch.complete),
                *clocks,
            ),
            key=_strategy_item_key,
        )
    )
    clock = SimulatedClock(market_replay.started_at)
    state = initial_state
    decisions: list[StrategyDecisionRecord] = []
    target_ids: set[str] = set()

    for sequence, item in enumerate(callback_items, start=1):
        if isinstance(item, MarketBatch):
            trigger = DecisionTrigger.from_market_batch(item)
        else:
            trigger = DecisionTrigger.from_clock_event(item)
        clock.advance_to(trigger.as_of)
        context = ReadOnlyStrategyContext(
            decision_trigger=trigger,
            state=state,
            current_positions=position_snapshot,
        )
        if context.clock.now() != clock.now():
            raise StrategyReplayContractError("strategy callback clock snapshot is inconsistent")

        transition = (
            strategy.on_market(context, item)
            if isinstance(item, MarketBatch)
            else strategy.on_clock(context, item)
        )
        strategy_pin.require_unchanged(strategy)
        if type(transition) is not StrategyTransition:
            raise StrategyTransitionError("strategy callback must return exact StrategyTransition")
        try:
            state.require_successor(transition.state, trigger)
        except ValueError as error:
            raise StrategyTransitionError(str(error)) from error
        if transition.target is not None:
            _validate_target(
                transition.target,
                trigger=trigger,
                strategy_pin=strategy_pin,
            )
            if transition.target.target_id in target_ids:
                raise StrategyTransitionError("strategy reused a target identity")
            target_ids.add(transition.target.target_id)

        decisions.append(
            StrategyDecisionRecord(
                sequence=sequence,
                trigger=trigger,
                context_sha256=context.semantic_sha256,
                input_state_sha256=state.semantic_sha256,
                transition=transition,
            )
        )
        state = transition.state

    return StrategyReplayResult(
        started_at=market_replay.started_at,
        completed_at=market_replay.completed_at,
        market_replay_sha256=market_replay.semantic_sha256,
        clock_schedule_sha256=clock_schedule_sha256,
        strategy_pin=strategy_pin,
        initialization_context_sha256=initialization_context.semantic_sha256,
        initial_state=initial_state,
        decisions=tuple(decisions),
        final_state=state,
    )
