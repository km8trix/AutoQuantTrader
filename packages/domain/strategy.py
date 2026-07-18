"""Strategy boundary and a deterministic Phase 0 reference strategy."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import MappingProxyType
from typing import Protocol

from packages.domain.canonical import canonical_persisted_decimal
from packages.domain.identifiers import canonical_id
from packages.domain.market_batch import MarketBatch
from packages.domain.models import PositionTarget, TargetPortfolio


@dataclass(frozen=True, slots=True, init=False)
class ReadOnlyStrategyContext:
    """An immutable causal position snapshot with no repository escape hatch."""

    as_of: datetime
    decision_batch_id: str
    decision_batch_sha256: str
    _positions: tuple[tuple[str, Decimal], ...]

    def __init__(
        self,
        *,
        as_of: datetime,
        decision_batch_id: str,
        decision_batch_sha256: str,
        current_positions: Mapping[str, Decimal],
    ) -> None:
        if as_of.tzinfo is None or as_of.utcoffset() is None:
            raise ValueError("strategy context as_of must be timezone-aware")
        if as_of.utcoffset() != UTC.utcoffset(as_of):
            raise ValueError("strategy context as_of must be UTC")
        if (
            type(decision_batch_id) is not str
            or not decision_batch_id
            or decision_batch_id != decision_batch_id.strip()
        ):
            raise ValueError("strategy context decision_batch_id must be non-empty and trimmed")
        if (
            type(decision_batch_sha256) is not str
            or len(decision_batch_sha256) != 64
            or any(character not in "0123456789abcdef" for character in decision_batch_sha256)
        ):
            raise ValueError("strategy context decision_batch_sha256 must be lowercase SHA-256")
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
        object.__setattr__(self, "as_of", as_of)
        object.__setattr__(self, "decision_batch_id", decision_batch_id)
        object.__setattr__(self, "decision_batch_sha256", decision_batch_sha256)
        object.__setattr__(self, "_positions", tuple(sorted(snapshot)))

    @property
    def current_positions(self) -> Mapping[str, Decimal]:
        return MappingProxyType(dict(self._positions))

    def quantity_for(self, instrument_id: str) -> Decimal:
        for current_instrument_id, quantity in self._positions:
            if current_instrument_id == instrument_id:
                return quantity
        return Decimal("0")

    def require_batch(self, batch: MarketBatch) -> None:
        if self.decision_batch_id != batch.batch_id:
            raise ValueError("strategy context is not bound to the supplied market batch ID")
        if self.decision_batch_sha256 != batch.semantic_sha256:
            raise ValueError("strategy context is not bound to the supplied market batch digest")
        if self.as_of != batch.as_of:
            raise ValueError("strategy context and market batch must share the same as_of")
        if not batch.complete:
            raise ValueError("strategy cannot receive an incomplete market batch")


class Strategy(Protocol):
    strategy_id: str
    version: str

    def initialize(self, context: ReadOnlyStrategyContext) -> None: ...

    def on_market(
        self,
        context: ReadOnlyStrategyContext,
        batch: MarketBatch,
    ) -> TargetPortfolio | None: ...


@dataclass(frozen=True, slots=True)
class FixedQuantityStrategy:
    """Targets one fixed long position without retaining hidden mutable state."""

    target_quantity: Decimal
    strategy_id: str = "fixed-quantity"
    version: str = "1.0.0"

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

    def initialize(self, context: ReadOnlyStrategyContext) -> None:
        del context

    def on_market(
        self,
        context: ReadOnlyStrategyContext,
        batch: MarketBatch,
    ) -> TargetPortfolio | None:
        context.require_batch(batch)
        if len(batch.events) != 1:
            raise ValueError("fixed-quantity reference strategy requires one market event")
        event = batch.events[0]
        if context.quantity_for(event.instrument_id) == self.target_quantity:
            return None
        return TargetPortfolio(
            target_id=canonical_id(
                "target",
                self.strategy_id,
                self.version,
                batch.batch_id,
                self.target_quantity,
            ),
            strategy_id=self.strategy_id,
            strategy_version=self.version,
            decision_batch_id=batch.batch_id,
            as_of=batch.as_of,
            expires_at=batch.as_of + timedelta(minutes=5),
            targets=(
                PositionTarget(
                    instrument_id=event.instrument_id,
                    symbol=event.symbol,
                    quantity=self.target_quantity,
                ),
            ),
        )
