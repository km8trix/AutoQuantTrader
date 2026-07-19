"""Pure strategy reducer boundary with explicit, versioned callback state."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import MappingProxyType
from typing import Protocol

from packages.domain.canonical import canonical_json_bytes, canonical_persisted_decimal
from packages.domain.clock import ClockEvent, FixedClock
from packages.domain.decision import DecisionTrigger, DecisionTriggerKind
from packages.domain.identifiers import canonical_id
from packages.domain.market_batch import MarketBatch
from packages.domain.models import PositionTarget, TargetPortfolio
from packages.domain.strategy_state import VersionedStrategyState

STRATEGY_CONTEXT_CONTRACT_VERSION = "phase2-strategy-context-v1"
STRATEGY_TRANSITION_CONTRACT_VERSION = "phase2-strategy-transition-v1"


def _require_utc(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{field_name} must be UTC")


def _position_snapshot(
    current_positions: Mapping[str, Decimal],
) -> tuple[tuple[str, Decimal], ...]:
    snapshot: list[tuple[str, Decimal]] = []
    for instrument_id, quantity in current_positions.items():
        if (
            type(instrument_id) is not str
            or not instrument_id
            or instrument_id != instrument_id.strip()
        ):
            raise ValueError("context instrument_id must be non-empty and trimmed")
        if type(quantity) is not Decimal:
            raise ValueError("context position quantity must be an exact Decimal")
        if not quantity.is_finite() or quantity < 0:
            raise ValueError("context position quantity must be finite and non-negative")
        snapshot.append(
            (
                instrument_id,
                canonical_persisted_decimal(quantity, "context position quantity"),
            )
        )
    return tuple(sorted(snapshot))


@dataclass(frozen=True, slots=True, init=False)
class StrategyInitializationContext:
    """The causal starting snapshot, deliberately unaware of future replay input."""

    started_at: datetime
    _positions: tuple[tuple[str, Decimal], ...]

    def __init__(
        self,
        *,
        started_at: datetime,
        current_positions: Mapping[str, Decimal],
    ) -> None:
        _require_utc(started_at, "strategy initialization started_at")
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "_positions", _position_snapshot(current_positions))

    @property
    def current_positions(self) -> Mapping[str, Decimal]:
        return MappingProxyType(dict(self._positions))

    def quantity_for(self, instrument_id: str) -> Decimal:
        for current_instrument_id, quantity in self._positions:
            if current_instrument_id == instrument_id:
                return quantity
        return Decimal("0")

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                (
                    STRATEGY_CONTEXT_CONTRACT_VERSION,
                    "initialization",
                    self.started_at,
                    self._positions,
                )
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True, init=False)
class ReadOnlyStrategyContext:
    """An immutable position and state snapshot bound to one exact callback cause."""

    decision_trigger: DecisionTrigger
    state: VersionedStrategyState
    _positions: tuple[tuple[str, Decimal], ...]

    def __init__(
        self,
        *,
        decision_trigger: DecisionTrigger,
        state: VersionedStrategyState,
        current_positions: Mapping[str, Decimal],
    ) -> None:
        if type(decision_trigger) is not DecisionTrigger:
            raise ValueError("strategy context requires an exact decision trigger")
        if type(state) is not VersionedStrategyState:
            raise ValueError("strategy context requires exact versioned strategy state")
        if state.as_of > decision_trigger.as_of:
            raise ValueError("strategy context state cannot come from the future")
        object.__setattr__(self, "decision_trigger", decision_trigger)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "_positions", _position_snapshot(current_positions))

    @property
    def as_of(self) -> datetime:
        return self.decision_trigger.as_of

    @property
    def decision_batch_id(self) -> str:
        if self.decision_trigger.kind is not DecisionTriggerKind.MARKET_BATCH:
            raise ValueError("strategy context is not bound to a market batch")
        return self.decision_trigger.trigger_id

    @property
    def decision_batch_sha256(self) -> str:
        if self.decision_trigger.kind is not DecisionTriggerKind.MARKET_BATCH:
            raise ValueError("strategy context is not bound to a market batch")
        return self.decision_trigger.trigger_sha256

    @property
    def current_positions(self) -> Mapping[str, Decimal]:
        return MappingProxyType(dict(self._positions))

    @property
    def clock(self) -> FixedClock:
        return FixedClock(self.as_of)

    def quantity_for(self, instrument_id: str) -> Decimal:
        for current_instrument_id, quantity in self._positions:
            if current_instrument_id == instrument_id:
                return quantity
        return Decimal("0")

    def require_batch(self, batch: MarketBatch) -> None:
        self.decision_trigger.require_market_batch(batch)

    def require_clock_event(self, event: ClockEvent) -> None:
        self.decision_trigger.require_clock_event(event)

    def require_strategy(
        self,
        *,
        strategy_id: str,
        strategy_version: str,
        strategy_configuration_sha256: str,
        state_schema_version: str,
    ) -> None:
        if self.state.strategy_id != strategy_id:
            raise ValueError("strategy context state has the wrong strategy identity")
        if self.state.strategy_version != strategy_version:
            raise ValueError("strategy context state has the wrong strategy version")
        if self.state.strategy_configuration_sha256 != strategy_configuration_sha256:
            raise ValueError("strategy context state has the wrong configuration digest")
        if self.state.schema_version != state_schema_version:
            raise ValueError("strategy context state has the wrong schema version")

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                (
                    STRATEGY_CONTEXT_CONTRACT_VERSION,
                    "callback",
                    self.decision_trigger.semantic_sha256,
                    self.state.semantic_sha256,
                    self._positions,
                )
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class StrategyTransition:
    state: VersionedStrategyState
    target: TargetPortfolio | None = None

    def __post_init__(self) -> None:
        if type(self.state) is not VersionedStrategyState:
            raise ValueError("strategy transition requires exact versioned state")
        if self.target is not None and type(self.target) is not TargetPortfolio:
            raise ValueError("strategy transition target must be an exact TargetPortfolio")

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                (
                    STRATEGY_TRANSITION_CONTRACT_VERSION,
                    self.state.semantic_sha256,
                    None if self.target is None else self.target.semantic_sha256,
                )
            )
        ).hexdigest()


class Strategy(Protocol):
    @property
    def strategy_id(self) -> str: ...

    @property
    def version(self) -> str: ...

    @property
    def state_schema_version(self) -> str: ...

    @property
    def configuration_sha256(self) -> str: ...

    def initialize(
        self,
        context: StrategyInitializationContext,
    ) -> VersionedStrategyState: ...

    def on_market(
        self,
        context: ReadOnlyStrategyContext,
        batch: MarketBatch,
    ) -> StrategyTransition: ...

    def on_clock(
        self,
        context: ReadOnlyStrategyContext,
        event: ClockEvent,
    ) -> StrategyTransition: ...


@dataclass(frozen=True, slots=True)
class FixedQuantityStrategy:
    """A deterministic reference reducer with no authoritative hidden state."""

    target_quantity: Decimal
    strategy_id: str = "fixed-quantity"
    version: str = "1.0.0"
    state_schema_version: str = "fixed-quantity-state-v1"

    def __post_init__(self) -> None:
        if type(self.target_quantity) is not Decimal:
            raise ValueError("target quantity must be an exact Decimal")
        if not self.target_quantity.is_finite() or self.target_quantity < 0:
            raise ValueError("target quantity must be finite and non-negative")
        object.__setattr__(
            self,
            "target_quantity",
            canonical_persisted_decimal(self.target_quantity, "strategy target quantity"),
        )

    @property
    def configuration_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                (
                    "fixed-quantity-configuration-v1",
                    self.strategy_id,
                    self.version,
                    self.target_quantity,
                )
            )
        ).hexdigest()

    def initialize(
        self,
        context: StrategyInitializationContext,
    ) -> VersionedStrategyState:
        return VersionedStrategyState.initial(
            strategy_id=self.strategy_id,
            strategy_version=self.version,
            strategy_configuration_sha256=self.configuration_sha256,
            schema_version=self.state_schema_version,
            as_of=context.started_at,
            values={"clock_callbacks": 0, "market_callbacks": 0},
        )

    def _next_state(
        self,
        context: ReadOnlyStrategyContext,
        *,
        callback_key: str,
    ) -> VersionedStrategyState:
        context.require_strategy(
            strategy_id=self.strategy_id,
            strategy_version=self.version,
            strategy_configuration_sha256=self.configuration_sha256,
            state_schema_version=self.state_schema_version,
        )
        values = dict(context.state.values)
        callback_count = values.get(callback_key)
        if type(callback_count) is not int:
            raise ValueError("fixed-quantity callback counter state is invalid")
        values[callback_key] = callback_count + 1
        return context.state.advance(trigger=context.decision_trigger, values=values)

    def on_market(
        self,
        context: ReadOnlyStrategyContext,
        batch: MarketBatch,
    ) -> StrategyTransition:
        context.require_batch(batch)
        next_state = self._next_state(context, callback_key="market_callbacks")
        if len(batch.events) != 1:
            raise ValueError("fixed-quantity reference strategy requires one market event")
        event = batch.events[0]
        if context.quantity_for(event.instrument_id) == self.target_quantity:
            return StrategyTransition(state=next_state)
        target = TargetPortfolio(
            target_id=canonical_id(
                "target",
                self.strategy_id,
                self.version,
                batch.batch_id,
                self.target_quantity,
            ),
            strategy_id=self.strategy_id,
            strategy_version=self.version,
            decision_trigger=context.decision_trigger,
            as_of=context.as_of,
            expires_at=context.as_of + timedelta(minutes=5),
            targets=(
                PositionTarget(
                    instrument_id=event.instrument_id,
                    symbol=event.symbol,
                    quantity=self.target_quantity,
                ),
            ),
        )
        return StrategyTransition(state=next_state, target=target)

    def on_clock(
        self,
        context: ReadOnlyStrategyContext,
        event: ClockEvent,
    ) -> StrategyTransition:
        context.require_clock_event(event)
        return StrategyTransition(state=self._next_state(context, callback_key="clock_callbacks"))
