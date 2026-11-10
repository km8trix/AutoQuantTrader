"""Causal portfolio snapshots and canonical target-to-intent conversion."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from decimal import Decimal

from packages.domain.accounting_contracts import AccountSnapshot
from packages.domain.clock import ClockEvent
from packages.domain.decimal_math import (
    exact_decimal_add,
    exact_decimal_subtract,
    exact_decimal_sum,
)
from packages.domain.decision import DecisionTrigger
from packages.domain.engine_contracts import DailyIntentBatch, DailyTarget
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
from packages.domain.personal_contracts import VersionPin


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


def daily_target_to_intents(
    target: DailyTarget, snapshot: AccountSnapshot, *, strategy_pin: VersionPin
) -> DailyIntentBatch:
    """Convert a desired daily portfolio against fills and every live commitment.

    A changed target with a live commitment requires an explicit cancellation
    workflow. This converter never nets two independently executable orders.
    """
    if type(target) is not DailyTarget or type(snapshot) is not AccountSnapshot:
        raise ValueError("daily conversion requires immutable daily contracts")
    if target.trigger.as_of != snapshot.point.knowledge_at:
        raise ValueError("daily target and account must share a knowledge frontier")
    if target.not_before < target.trigger.as_of or target.expires_at <= target.not_before:
        raise ValueError("daily target has an invalid execution window")
    desired = {item.instrument_id: item for item in target.targets}
    if len(desired) != len(target.targets):
        raise ValueError("daily targets contain duplicate instruments")
    positions = {item.instrument_id: item for item in snapshot.positions}
    marks = {item.instrument_id: item for item in snapshot.marks}
    pending = tuple(item for item in snapshot.commitments if item.state != "terminal")
    instruments = set(desired)
    if target.full_snapshot:
        instruments.update(positions)
        instruments.update(item.instrument_id for item in pending)
    batch_id = canonical_id("daily-intent-batch", target.semantic_sha256, snapshot.semantic_sha256)
    intents: list[OrderIntent] = []
    reasons: list[str] = []
    trigger = DecisionTrigger.from_clock_event(
        ClockEvent(
            target.trigger.trigger_id,
            "personal-daily-decision/1",
            target.trigger.as_of,
            target.trigger.sequence,
        )
    )
    for instrument_id in sorted(instruments):
        position = positions.get(instrument_id)
        wanted = desired.get(instrument_id)
        live = tuple(item for item in pending if item.instrument_id == instrument_id)
        filled = Decimal(0) if position is None else position.quantity
        committed = exact_decimal_sum(
            item.remaining_quantity
            if item.side is Side.BUY
            else item.remaining_quantity.copy_negate()
            for item in live
        )
        effective = exact_decimal_add(filled, committed)
        quantity = Decimal(0) if wanted is None else wanted.quantity
        delta = exact_decimal_subtract(quantity, effective)
        if delta == 0:
            continue
        if live:
            reasons.append("PENDING_COMMITMENT_REQUIRES_EXPLICIT_RESOLUTION")
            continue
        mark = marks.get(instrument_id)
        if mark is None or mark.quality != "current" or mark.knowledge_at > target.trigger.as_of:
            reasons.append("MISSING_CURRENT_REFERENCE_PRICE")
            continue
        symbol = wanted.symbol if wanted is not None else position.symbol if position else None
        if symbol != mark.symbol or (position is not None and position.symbol != symbol):
            raise ValueError("daily instrument symbol differs from account mark")
        if target.reduce_only_scope and delta > 0:
            reasons.append("REDUCE_ONLY_TARGET_INCREASES_EXPOSURE")
            continue
        side = Side.BUY if delta > 0 else Side.SELL
        intents.append(
            OrderIntent(
                intent_id=canonical_id(
                    "daily-intent", batch_id, instrument_id, side, delta.copy_abs()
                ),
                intent_batch_id=batch_id,
                target_id=target.target_id,
                target_sha256=target.semantic_sha256,
                portfolio_snapshot_sha256=snapshot.semantic_sha256,
                strategy_id=strategy_pin.name,
                strategy_version=strategy_pin.version,
                strategy_configuration_sha256=target.configuration_sha256,
                decision_trigger=trigger,
                instrument_id=instrument_id,
                symbol=mark.symbol,
                side=side,
                quantity=delta.copy_abs(),
                reference_price=mark.price,
                decision_event_id=mark.mark_id,
                reference_event_sha256=mark.source_sha256,
                decision_event_time=mark.economic_at,
                created_at=target.trigger.as_of,
                expires_at=target.expires_at,
            )
        )
    return DailyIntentBatch(
        batch_id,
        target,
        snapshot.semantic_sha256,
        () if reasons else tuple(intents),
        tuple(sorted(set(reasons))),
    )
