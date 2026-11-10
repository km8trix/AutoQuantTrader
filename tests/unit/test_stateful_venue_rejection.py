"""Independent explicit modeled order rejection, never a command ACK inference."""

from datetime import timedelta

import pytest

from packages.application import personal_codec
from packages.application.stateful_venue import advance_stateful_venue
from packages.domain.order_reducer import (
    BrokerOrderEventKind,
    CanonicalOrderStatus,
    reduce_order_lifecycle,
)
from packages.domain.stateful_venue_contracts import VenueAccept, VenueCommand, VenueReject
from tests.unit.test_stateful_venue import VenueHarness, packet, quote


def test_registered_order_rejection_has_original_fact_and_releases_only_venue_reserve():
    h = VenueHarness()
    outgoing = packet(h.model)
    h.command(outgoing, at=outgoing.registration.submission.submitted_at)
    before = h.project()
    original, ack = h.command(
        VenueReject(outgoing.registration.submission.order_id, "modeled-venue-declined")
    )
    assert ack.disposition == "applied"
    after = h.project()
    order = reduce_order_lifecycle(
        submission=outgoing.registration.submission, broker_events=h.state.accounting.broker_events
    )
    assert order.status is CanonicalOrderStatus.REJECTED
    assert after.snapshot.buy_reserve == 0 < before.snapshot.buy_reserve
    assert after.snapshot.trade_date_cash == before.snapshot.trade_date_cash
    assert after.snapshot.positions == before.snapshot.positions
    assert h.state.accounting.cash_flows == (h.model.initial_cash_flow,)
    assert not after.executions
    assert h.state.facts[-1].payload.kind is BrokerOrderEventKind.REJECTED
    assert h.state.facts[-1].payload.reason == "modeled-venue-declined"
    raw = personal_codec.encode_record(original)
    assert personal_codec.decode_record(raw, VenueCommand) == original
    state = h.state
    retry = advance_stateful_venue(h.model, state, original)
    assert retry.state == state and retry.acknowledgment == ack
    at = state.as_of + timedelta(seconds=1)
    _, quote_ack = h.command(quote(at), at=at)
    assert quote_ack.disposition == "no_effect"
    assert not h.project().executions


@pytest.mark.parametrize("stage", ["missing", "accepted", "partial", "filled", "rejected"])
def test_rejection_cannot_erase_unknown_or_accepted_order_effects(stage):
    h = VenueHarness()
    order_id = "missing"
    if stage != "missing":
        outgoing = packet(h.model)
        h.command(outgoing, at=outgoing.registration.submission.submitted_at)
        order_id = outgoing.registration.submission.order_id
        if stage == "rejected":
            h.command(VenueReject(order_id, "first-rejection"))
        else:
            h.command(VenueAccept(order_id))
            if stage in ("partial", "filled"):
                h.filled(budget="2" if stage == "partial" else "4")
    before = h.state
    _, ack = h.command(VenueReject(order_id, "late-rejection"))
    assert ack.disposition == "rejected"
    assert ack.reasons == (
        "VENUE_ORDER_UNKNOWN" if stage == "missing" else "VENUE_REJECT_REQUIRES_REGISTERED_ORDER",
    )
    assert h.state.accounting == before.accounting
    assert h.state.facts == before.facts
