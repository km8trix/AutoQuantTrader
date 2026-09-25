"""Independent venue capacity and exact shared model terms; no provider effects."""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal, Inexact, localcontext

import pytest

from packages.application.personal_codec import decode_record, encode_record
from packages.backtest.personal_accounting import model_execution_terms, model_settlement_at
from packages.domain.accounting_contracts import RegisterVenueSubmission
from packages.domain.models import Side
from packages.domain.order_reducer import BrokerOrderEvent, BrokerOrderEventKind
from tests.unit.test_observed_accounting import OBSERVED
from tests.unit.test_personal_accounting import Harness

VENUE = replace(OBSERVED, model_id="stateful-venue-facts-v1")


def packet():
    source = Harness(OBSERVED)
    c = source.install("sent", "4", "100", "1", activate=False)
    return RegisterVenueSubmission(
        account_id=source.state.account_id,
        submission=source.state.submissions[0],
        source_commitment=c,
        source_risk_admission_sha256="a" * 64,
        source_dispatch_sha256="b" * 64,
        venue_model_sha256=VENUE.semantic_sha256,
    )


def test_registration_uses_independent_cash_and_never_synthesizes_acceptance():
    command = packet()
    venue = Harness(VENUE, funding="700")
    before = venue.project().snapshot
    assert before.semantic_sha256 != command.source_commitment.snapshot_sha256
    result = venue.apply(command, at=command.submission.submitted_at + timedelta(seconds=2))
    assert result.disposition == "applied", result.reasons
    assert result.snapshot.trade_date_cash == 700
    assert result.snapshot.available_cash == 299
    assert result.state.broker_events == () and result.due_events == ()
    local = result.state.commitments[0]
    assert local.snapshot_sha256 == command.source_commitment.snapshot_sha256
    assert local.policy_sha256 == command.source_commitment.policy_sha256
    assert local.created_sequence == local.activation_sequence == venue.sequence
    assert command.source_commitment.state == "approved_unsent"
    assert decode_record(encode_record(command), RegisterVenueSubmission) == command
    identity = "command-" + str(venue.sequence)
    state = venue.state
    assert venue.apply(command, command_id=identity).disposition == "duplicate"
    assert venue.state == state
    at = venue.at + timedelta(seconds=1)
    accepted = BrokerOrderEvent(
        event_id="venue-acceptance",
        order_id=local.order_id,
        broker_order_id="venue-order",
        broker_sequence=1,
        occurred_at=at,
        received_at=at,
        kind=BrokerOrderEventKind.ACCEPTED,
    )
    assert venue.apply(accepted, at=at).disposition == "applied"
    fill = venue.fill(local, "4", "100", "1")
    assert fill.snapshot.trade_date_cash == 299 and fill.snapshot.trade_payable == 401
    assert fill.snapshot.settled_cash == 700 and fill.due_events == ()


def test_same_valid_outbound_is_rejected_when_venue_has_insufficient_own_funds():
    command = packet()
    venue = Harness(VENUE, funding="100")
    before = venue.state
    result = venue.apply(command, at=command.submission.submitted_at + timedelta(seconds=1))
    assert result.disposition == "rejected"
    assert result.reasons == ("commitment exceeds current available cash",)
    assert venue.state == before and venue.state.submissions == ()


@pytest.mark.parametrize(
    "field,value", [("account_id", "foreign"), ("venue_model_sha256", "c" * 64)]
)
def test_registration_rejects_foreign_account_or_model(field, value):
    command = replace(packet(), **{field: value})
    venue = Harness(VENUE)
    assert venue.apply(command, at=command.submission.submitted_at).disposition == "rejected"
    assert venue.state.submissions == ()


def test_registration_is_unavailable_to_coordinator_or_approved_snapshot_context():
    command = packet()
    coordinator = Harness(OBSERVED)
    assert coordinator.apply(command, at=command.submission.submitted_at).disposition == "rejected"
    venue = Harness(VENUE)
    assert (
        venue.apply(
            command, at=command.submission.submitted_at, approved=venue.project().snapshot
        ).disposition
        == "rejected"
    )
    assert venue.state.submissions == coordinator.state.submissions == ()


def test_registration_checks_exact_outbound_terms_and_expiry_without_rebinding_risk():
    original = packet()
    venue = Harness(VENUE)
    bad = replace(
        original, source_commitment=replace(original.source_commitment, reserved_cash=Decimal(1))
    )
    assert venue.apply(bad, at=bad.submission.submitted_at).disposition == "rejected"
    assert venue.apply(original, at=original.source_commitment.expires_at).disposition == "rejected"
    assert venue.state.submissions == ()


def test_shared_model_terms_use_frozen_w2_adverse_rounding_and_exact_fees():
    policy = replace(VENUE, slippage_bps=Decimal(5), fee_per_share=Decimal(".01"))
    for side, expected in (
        (Side.BUY, Decimal("100.0500000000")),
        (Side.SELL, Decimal("99.9500000000")),
    ):
        with localcontext() as ambient:
            ambient.prec = 1
            ambient.traps[Inexact] = True
            actual = model_execution_terms(
                quantity=Decimal(4), reference_price=Decimal(100), side=side, policy=policy
            )
        assert actual == (expected, Decimal(".04"))
    source = packet()
    at = source.submission.submitted_at + timedelta(seconds=1)
    event = BrokerOrderEvent(
        event_id="fixture-execution",
        order_id=source.submission.order_id,
        broker_order_id="venue",
        broker_sequence=2,
        occurred_at=at,
        received_at=at,
        kind=BrokerOrderEventKind.EXECUTION,
        execution_id="fixture-fill",
        execution_revision=1,
        quantity=Decimal(4),
        price=Decimal(100),
        fee=Decimal(".04"),
    )
    assert model_settlement_at(event=event, policy=policy) == at.replace(
        day=4, hour=13, minute=30, second=0
    )
