"""Deterministic simulated execution behind a mandatory authorization port."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

from packages.domain.identifiers import deterministic_id
from packages.domain.models import Fill, MarketEvent, Order, OrderIntent, OrderStatus
from packages.domain.risk import RiskAuthorizationConsumer


class SimulatedBroker:
    def __init__(self, authorizations: RiskAuthorizationConsumer) -> None:
        self._authorizations = authorizations

    def submit(
        self,
        intent: OrderIntent,
        risk_decision_id: str,
    ) -> Order:
        submitted_at = self._authorizations.consume(risk_decision_id, intent)
        return Order(
            order_id=deterministic_id("order", intent.intent_id),
            client_order_id=f"aqt-{deterministic_id('client-order', intent.intent_id)[:24]}",
            intent_id=intent.intent_id,
            risk_decision_id=risk_decision_id,
            instrument_id=intent.instrument_id,
            symbol=intent.symbol,
            side=intent.side,
            quantity=intent.quantity,
            activation_after_event_time=intent.decision_event_time,
            submitted_at=submitted_at,
            status=OrderStatus.WORKING,
        )

    def fill_at_next_event(
        self,
        order: Order,
        event: MarketEvent,
        fee: Decimal,
    ) -> tuple[Order, Fill]:
        if order.status is not OrderStatus.WORKING:
            raise ValueError("only working orders can fill")
        if event.instrument_id != order.instrument_id:
            raise ValueError("fill event instrument does not match the order")
        if event.available_at <= order.submitted_at:
            raise ValueError("orders may only fill on a later available market event")
        if event.event_time <= order.activation_after_event_time:
            raise ValueError("orders may only fill from a causally later market event")
        fill = Fill(
            fill_id=deterministic_id("fill", order.order_id, event.event_id),
            order_id=order.order_id,
            instrument_id=order.instrument_id,
            symbol=order.symbol,
            side=order.side,
            quantity=order.quantity,
            price=event.close_price,
            fee=fee,
            executed_at=event.available_at,
        )
        return replace(order, status=OrderStatus.FILLED, filled_quantity=order.quantity), fill
