"""Causal portfolio snapshots and canonical target-to-intent conversion."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from decimal import Decimal

from packages.domain.decimal_math import exact_decimal_subtract
from packages.domain.identifiers import canonical_id
from packages.domain.market_batch import MarketBatch
from packages.domain.models import (
    CausalPrice,
    MarketEvent,
    OrderIntent,
    OrderIntentBatch,
    PortfolioPosition,
    PortfolioSnapshot,
    Side,
    TargetPortfolio,
)


def portfolio_snapshot(
    *,
    as_of: datetime,
    current_positions: Mapping[str, tuple[str, Decimal]],
    price_events: Iterable[MarketEvent],
) -> PortfolioSnapshot:
    """Copy caller-owned state into one exact, causally visible valuation snapshot."""

    events = tuple(price_events)
    if any(type(event) is not MarketEvent for event in events):
        raise ValueError("portfolio prices require exact MarketEvent values")
    positions = tuple(
        sorted(
            (
                PortfolioPosition(
                    instrument_id=instrument_id,
                    symbol=symbol_quantity[0],
                    quantity=symbol_quantity[1],
                )
                for instrument_id, symbol_quantity in current_positions.items()
            ),
            key=lambda position: position.instrument_id,
        )
    )
    prices = tuple(
        sorted(
            (CausalPrice(event=event) for event in events),
            key=lambda price: price.instrument_id,
        )
    )
    return PortfolioSnapshot(as_of=as_of, positions=positions, prices=prices)


def target_to_intent_batch(
    target: TargetPortfolio,
    snapshot: PortfolioSnapshot,
) -> OrderIntentBatch:
    """Convert a complete desired portfolio against one immutable causal snapshot."""

    if type(target) is not TargetPortfolio:
        raise ValueError("conversion requires an exact TargetPortfolio")
    if type(snapshot) is not PortfolioSnapshot:
        raise ValueError("conversion requires an exact PortfolioSnapshot")
    if target.as_of != snapshot.as_of:
        raise ValueError("target and portfolio snapshot must share the same as_of")

    current_by_id = {position.instrument_id: position for position in snapshot.positions}
    price_by_id = {price.instrument_id: price for price in snapshot.prices}
    desired_by_id = {position.instrument_id: position for position in target.targets}
    conversion_ids = set(desired_by_id)
    if target.full_snapshot:
        conversion_ids.update(current_by_id)

    batch_id = canonical_id(
        "intent-batch",
        target.target_id,
        target.semantic_sha256,
        snapshot.semantic_sha256,
    )
    intents: list[OrderIntent] = []
    for instrument_id in sorted(conversion_ids):
        current = current_by_id.get(instrument_id)
        desired = desired_by_id.get(instrument_id)
        current_quantity = Decimal("0") if current is None else current.quantity
        desired_quantity = Decimal("0") if desired is None else desired.quantity
        quantity_delta = exact_decimal_subtract(desired_quantity, current_quantity)
        if quantity_delta == 0:
            continue
        price = price_by_id.get(instrument_id)
        if price is None:
            raise ValueError(f"changed target {instrument_id!r} has no causal reference price")
        if desired is not None:
            expected_symbol = desired.symbol
        elif current is not None:
            expected_symbol = current.symbol
        else:
            raise RuntimeError("conversion instrument has no current or desired position")
        if expected_symbol != price.symbol:
            raise ValueError(f"target symbol for {instrument_id!r} does not match its price")
        if current is not None and current.symbol != expected_symbol:
            raise ValueError(f"current symbol for {instrument_id!r} differs from its target")
        side = Side.BUY if quantity_delta > 0 else Side.SELL
        intents.append(
            OrderIntent(
                intent_id=canonical_id(
                    "intent",
                    batch_id,
                    instrument_id,
                    side,
                    quantity_delta.copy_abs(),
                ),
                intent_batch_id=batch_id,
                target_id=target.target_id,
                target_sha256=target.semantic_sha256,
                portfolio_snapshot_sha256=snapshot.semantic_sha256,
                strategy_id=target.strategy_id,
                strategy_version=target.strategy_version,
                strategy_configuration_sha256=target.strategy_configuration_sha256,
                decision_trigger=target.decision_trigger,
                instrument_id=instrument_id,
                symbol=expected_symbol,
                side=side,
                quantity=quantity_delta.copy_abs(),
                reference_price=price.price,
                decision_event_id=price.event_id,
                reference_event_sha256=price.source_event_sha256,
                decision_event_time=price.event_time,
                created_at=target.as_of,
                expires_at=target.expires_at,
            )
        )
    return OrderIntentBatch(
        intent_batch_id=batch_id,
        target_id=target.target_id,
        target_sha256=target.semantic_sha256,
        portfolio_snapshot_sha256=snapshot.semantic_sha256,
        decision_trigger=target.decision_trigger,
        intents=tuple(intents),
    )


def target_to_order_intent(
    target: TargetPortfolio,
    current_quantity: Decimal,
    decision_batch: MarketBatch,
) -> OrderIntent | None:
    if not decision_batch.complete:
        raise ValueError("an incomplete market batch cannot create an order intent")
    target.decision_trigger.require_market_batch(decision_batch)
    if target.as_of != decision_batch.as_of:
        raise ValueError("target and market batch must share the same as_of")
    if len(target.targets) != 1:
        raise ValueError("Phase 0 supports exactly one position target")
    desired = target.targets[0]
    batch = target_to_intent_batch(
        target,
        portfolio_snapshot(
            as_of=target.as_of,
            current_positions={desired.instrument_id: (desired.symbol, current_quantity)},
            price_events=decision_batch.events,
        ),
    )
    if len(batch.intents) > 1:
        raise RuntimeError("single-position compatibility conversion emitted multiple intents")
    return batch.intents[0] if batch.intents else None
