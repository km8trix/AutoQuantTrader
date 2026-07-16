"""Strategy boundary and a deterministic Phase 0 reference strategy."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from typing import Protocol

from packages.domain.identifiers import deterministic_id
from packages.domain.models import MarketEvent, PositionTarget, TargetPortfolio


@dataclass(frozen=True, slots=True)
class ReadOnlyStrategyContext:
    current_positions: dict[str, Decimal]

    def quantity_for(self, instrument_id: str) -> Decimal:
        return self.current_positions.get(instrument_id, Decimal("0"))


class Strategy(Protocol):
    strategy_id: str
    version: str

    def initialize(self, context: ReadOnlyStrategyContext) -> None: ...

    def on_market(
        self,
        context: ReadOnlyStrategyContext,
        event: MarketEvent,
    ) -> TargetPortfolio | None: ...


@dataclass(frozen=True, slots=True)
class FixedQuantityStrategy:
    """Targets one fixed long position without retaining hidden mutable state."""

    target_quantity: Decimal
    strategy_id: str = "fixed-quantity"
    version: str = "1.0.0"

    def __post_init__(self) -> None:
        if not self.target_quantity.is_finite() or self.target_quantity < 0:
            raise ValueError("target quantity must be finite and non-negative")

    def initialize(self, context: ReadOnlyStrategyContext) -> None:
        del context

    def on_market(
        self,
        context: ReadOnlyStrategyContext,
        event: MarketEvent,
    ) -> TargetPortfolio | None:
        if context.quantity_for(event.instrument_id) == self.target_quantity:
            return None
        return TargetPortfolio(
            target_id=deterministic_id(
                "target", self.strategy_id, self.version, event.event_id, self.target_quantity
            ),
            strategy_id=self.strategy_id,
            strategy_version=self.version,
            as_of=event.available_at,
            expires_at=event.available_at + timedelta(minutes=5),
            targets=(
                PositionTarget(
                    instrument_id=event.instrument_id,
                    symbol=event.symbol,
                    quantity=self.target_quantity,
                ),
            ),
        )
