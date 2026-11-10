"""Canonical local release is distinct from a broker cancel or an expiry guess."""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest

from packages.application.personal_codec import decode_record, encode_record
from packages.domain.accounting_contracts import ReleaseRuntimeUnsent
from packages.domain.order_reducer import BrokerOrderEvent, BrokerOrderEventKind
from tests.unit.test_observed_accounting import OBSERVED
from tests.unit.test_personal_accounting import Harness
from tests.unit.test_venue_accounting import VENUE


def case(reason="expired"):
    harness = Harness(OBSERVED)
    commitment = harness.install("unsent", "4", "100", "1", activate=False)
    at = commitment.expires_at if reason == "expired" else harness.at + timedelta(seconds=1)
    command = ReleaseRuntimeUnsent(
        account_id=harness.state.account_id,
        commitment_id=commitment.commitment_id,
        expected_commitment_sha256=commitment.semantic_sha256,
        source_state_sha256=harness.state.semantic_sha256,
        attempt_history_sha256="a" * 64,
        locked_unsent_proof_sha256="b" * 64,
        proof_at=at,
        reason=reason,
        owner_command_sha256=None if reason == "expired" else "c" * 64,
    )
    return harness, commitment, command, at


@pytest.mark.parametrize("reason", ["expired", "revoked", "policy_cutover"])
def test_exact_local_release_removes_only_unsent_capacity_and_retry_is_inert(reason):
    harness, commitment, command, at = case(reason)
    before = harness.project().snapshot
    result = harness.apply(command, at=at, command_id="release-original")
    assert result.disposition == "applied", result.reasons
    assert result.snapshot.trade_date_cash == before.trade_date_cash == Decimal(1000)
    assert result.snapshot.available_cash == before.available_cash + commitment.reserved_cash
    assert (
        result.state.broker_events == ()
        and result.journal_entries == ()
        and result.due_events == ()
    )
    assert result.state.commitments[0] == replace(
        commitment,
        state="terminal",
        remaining_quantity=Decimal(0),
        reserved_cash=Decimal(0),
        reserved_sell_quantity=Decimal(0),
        remaining_fee_budget=Decimal(0),
        terminal_reason="runtime_unsent_" + reason,
    )
    state = harness.state
    retry = harness.apply(command, at=at + timedelta(seconds=1), command_id="release-original")
    assert retry.disposition == "duplicate" and harness.state == state
    assert decode_record(encode_record(command), ReleaseRuntimeUnsent) == command


@pytest.mark.parametrize(
    "field,value",
    [
        ("account_id", "other-account"),
        ("expected_commitment_sha256", "d" * 64),
        ("source_state_sha256", "e" * 64),
    ],
)
def test_release_rejects_changed_account_state_or_commitment(field, value):
    harness, _, command, at = case()
    before = harness.state
    result = harness.apply(replace(command, **{field: value}), at=at)
    assert result.disposition == "rejected" and harness.state == before


def test_expiry_and_proof_time_are_exact_and_never_refresh_on_use():
    harness, _, command, at = case()
    before = harness.state
    early = at - timedelta(seconds=1)
    assert harness.apply(replace(command, proof_at=early), at=early).disposition == "rejected"
    assert harness.apply(command, at=at + timedelta(seconds=1)).disposition == "rejected"
    assert harness.state == before


@pytest.mark.parametrize("state", ["unknown", "pending_cancel", "working", "active"])
def test_claimed_or_unresolved_order_never_expires_by_this_command(state):
    harness, commitment, command, at = case()
    changed = replace(commitment, state=state)
    harness.state = replace(harness.state, commitments=(changed,))
    command = replace(
        command,
        expected_commitment_sha256=changed.semantic_sha256,
        source_state_sha256=harness.state.semantic_sha256,
    )
    before = harness.state
    assert harness.apply(command, at=at).disposition == "rejected"
    assert harness.state == before


def test_release_cannot_ignore_an_observed_order_even_if_status_were_reset():
    harness, commitment, command, at = case()
    accepted_at = harness.at + timedelta(seconds=1)
    event = BrokerOrderEvent(
        event_id="actual-ack",
        order_id=commitment.order_id,
        broker_order_id="venue-order",
        broker_sequence=1,
        occurred_at=accepted_at,
        received_at=accepted_at,
        kind=BrokerOrderEventKind.ACCEPTED,
    )
    assert harness.apply(event, at=accepted_at).disposition == "applied"
    # Deliberately inconsistent status cannot erase the canonical broker history.
    harness.state = replace(harness.state, commitments=(commitment,))
    command = replace(command, source_state_sha256=harness.state.semantic_sha256)
    before = harness.state
    assert harness.apply(command, at=at).disposition == "rejected" and harness.state == before


def test_late_fill_contradicting_unsent_proof_is_booked_and_halts_account():
    harness, commitment, command, at = case()
    assert harness.apply(command, at=at).disposition == "applied"
    accepted_at = at + timedelta(seconds=1)
    accepted = BrokerOrderEvent(
        event_id="contradicting-ack",
        order_id=commitment.order_id,
        broker_order_id="venue-order",
        broker_sequence=1,
        occurred_at=accepted_at,
        received_at=accepted_at,
        kind=BrokerOrderEventKind.ACCEPTED,
    )
    acknowledgment = harness.apply(accepted, at=accepted_at)
    assert acknowledgment.disposition == "applied" and acknowledgment.state.halted
    fill = harness.fill(commitment, "4", "100", "1")
    assert fill.disposition == "applied" and fill.state.halted
    assert fill.snapshot.trade_date_cash == Decimal(599)
    assert fill.snapshot.trade_payable == Decimal(401)
    assert fill.snapshot.positions[0].quantity == Decimal(4)
    assert fill.state.commitments[0].state == "terminal"


def test_unrevoked_venue_or_historical_model_cannot_interpret_local_release():
    for policy in (VENUE, Harness().policy):
        harness = Harness(policy)
        commitment = harness.install("not-runtime", "4", "100", "1", activate=False)
        _, _, command, _ = case()
        at = commitment.expires_at
        command = replace(
            command,
            commitment_id=commitment.commitment_id,
            expected_commitment_sha256=commitment.semantic_sha256,
            source_state_sha256=harness.state.semantic_sha256,
            proof_at=at,
        )
        before = harness.state
        assert harness.apply(command, at=at).disposition == "rejected" and harness.state == before
