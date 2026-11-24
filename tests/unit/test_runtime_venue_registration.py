"""An activated coordinator hold remains exact provenance at the independent venue."""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest

from packages.domain.accounting_contracts import RegisterVenueSubmission
from tests.unit.test_daily_runtime_activation import case, prepare_daily_runtime_activation
from tests.unit.test_daily_runtime_activation import fence as fence
from tests.unit.test_personal_accounting import Harness
from tests.unit.test_venue_accounting import VENUE


def activated_packet(fence):
    values = case(fence, price="120")
    active = prepare_daily_runtime_activation(**values)
    return RegisterVenueSubmission(
        account_id="synthetic-account",
        submission=active.transition.state.submissions[0],
        source_commitment=active.commitments[0],
        source_risk_admission_sha256="a" * 64,
        source_dispatch_sha256="b" * 64,
        venue_model_sha256=VENUE.semantic_sha256,
    )


def test_active_registration_preserves_all_reserve_terms_with_venue_own_activation(fence):
    packet = activated_packet(fence)
    original = packet.source_commitment
    venue = Harness(VENUE, funding="2000")
    at = original.activated_at + timedelta(seconds=2)
    outcome = venue.apply(packet, at=at)
    assert outcome.disposition == "applied", outcome.reasons
    local = outcome.state.commitments[0]
    assert local == replace(
        original,
        created_sequence=venue.sequence,
        activated_at=at,
        activation_sequence=venue.sequence,
        activation_frontier=venue.frontier,
    )
    assert local.reserved_cash == Decimal("1212.10")
    assert local.approved_price == Decimal("121.20")
    assert local.remaining_fee_budget == Decimal(".10")
    assert outcome.snapshot.trade_date_cash == 2000
    assert outcome.snapshot.available_cash == Decimal("787.90")
    assert not outcome.state.broker_events and not outcome.due_events


def test_active_registration_cannot_use_earlier_smaller_reservation_capacity(fence):
    packet = activated_packet(fence)
    venue = Harness(VENUE, funding="1100")
    before = venue.state
    outcome = venue.apply(packet, at=packet.source_commitment.activated_at)
    assert outcome.disposition == "rejected"
    assert outcome.reasons == ("commitment exceeds current available cash",)
    assert venue.state == before


@pytest.mark.parametrize("change", ["reduced_reserve", "future_activation", "partial_fill"])
def test_active_registration_rejects_changed_or_already_partly_consumed_source(fence, change):
    packet = activated_packet(fence)
    original = packet.source_commitment
    at = original.activated_at + timedelta(seconds=1)
    changed = (
        replace(original, reserved_cash=Decimal("1010.10"))
        if change == "reduced_reserve"
        else replace(original, activated_at=at + timedelta(seconds=1))
        if change == "future_activation"
        else replace(
            original,
            filled_quantity=Decimal(1),
            remaining_quantity=Decimal(9),
            reserved_cash=Decimal("1090.90"),
        )
    )
    venue = Harness(VENUE, funding="2000")
    before = venue.state
    outcome = venue.apply(replace(packet, source_commitment=changed), at=at)
    assert outcome.disposition == "rejected"
    assert venue.state == before and not venue.state.submissions
