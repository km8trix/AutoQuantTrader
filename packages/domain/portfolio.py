"""Portfolio target interpretation."""

from __future__ import annotations

from decimal import Decimal

from packages.domain.identifiers import deterministic_id
from packages.domain.models import MarketEvent, OrderIntent, Side, TargetPortfolio


def target_to_order_intent(
    target: TargetPortfolio,
    current_quantity: Decimal,
    reference_event: MarketEvent,
) -> OrderIntent | None:
    if len(target.targets) != 1:
        raise ValueError("Phase 0 supports exactly one position target")
    desired = target.targets[0]
    if desired.instrument_id != reference_event.instrument_id:
        raise ValueError("target and reference event instruments do not match")
    quantity_delta = desired.quantity - current_quantity
    if quantity_delta == 0:
        return None
    side = Side.BUY if quantity_delta > 0 else Side.SELL
    return OrderIntent(
        intent_id=deterministic_id("intent", target.target_id, side, abs(quantity_delta)),
        target_id=target.target_id,
        instrument_id=desired.instrument_id,
        symbol=desired.symbol,
        side=side,
        quantity=abs(quantity_delta),
        reference_price=reference_event.close_price,
        decision_event_id=reference_event.event_id,
        decision_event_time=reference_event.event_time,
        created_at=target.as_of,
        expires_at=target.expires_at,
    )
