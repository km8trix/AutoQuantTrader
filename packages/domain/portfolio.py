"""Portfolio target interpretation."""

from __future__ import annotations

from decimal import Decimal

from packages.domain.canonical import canonical_persisted_decimal
from packages.domain.decimal_math import exact_decimal_subtract
from packages.domain.identifiers import canonical_id
from packages.domain.market_batch import MarketBatch
from packages.domain.models import OrderIntent, Side, TargetPortfolio


def target_to_order_intent(
    target: TargetPortfolio,
    current_quantity: Decimal,
    decision_batch: MarketBatch,
) -> OrderIntent | None:
    if type(current_quantity) is not Decimal:
        raise ValueError("current quantity must be an exact Decimal")
    if (
        not current_quantity.is_finite()
        or current_quantity < 0
        or current_quantity != current_quantity.to_integral_value()
    ):
        raise ValueError("current quantity must be finite, non-negative, and whole")
    current_quantity = canonical_persisted_decimal(current_quantity, "current quantity")
    if not decision_batch.complete:
        raise ValueError("an incomplete market batch cannot create an order intent")
    if target.decision_batch_id != decision_batch.batch_id:
        raise ValueError("target is not bound to the supplied market batch")
    if target.as_of != decision_batch.as_of:
        raise ValueError("target and market batch must share the same as_of")
    if len(target.targets) != 1:
        raise ValueError("Phase 0 supports exactly one position target")
    desired = target.targets[0]
    try:
        reference_event = decision_batch.event_for(desired.instrument_id)
    except KeyError as error:
        raise ValueError("target has no reference event in its decision batch") from error
    if desired.symbol != reference_event.symbol:
        raise ValueError("target symbol does not match its decision-batch event")
    quantity_delta = exact_decimal_subtract(desired.quantity, current_quantity)
    if quantity_delta == 0:
        return None
    side = Side.BUY if quantity_delta > 0 else Side.SELL
    return OrderIntent(
        intent_id=canonical_id("intent", target.target_id, side, quantity_delta.copy_abs()),
        target_id=target.target_id,
        instrument_id=desired.instrument_id,
        symbol=desired.symbol,
        side=side,
        quantity=quantity_delta.copy_abs(),
        reference_price=reference_event.close_price,
        decision_event_id=reference_event.event_id,
        decision_event_time=reference_event.event_time,
        created_at=target.as_of,
        expires_at=target.expires_at,
    )
