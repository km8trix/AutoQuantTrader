"""Observed fills book economics without synthesizing settlement or acceptance."""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest

from packages.domain.accounting_contracts import ActivateCommitment, ModelDisposition
from packages.domain.order_reducer import BrokerOrderEvent, BrokerOrderEventKind
from packages.domain.settlement_ledger import (
    create_settlement_confirmation,
    create_settlement_instruction,
    reduce_observed_settlement_ledger,
)
from tests.unit.test_personal_accounting import POLICY, Harness

OBSERVED = replace(
    POLICY,
    model_id="observed-facts-v1",
    settlement_model="observed-only-v1",
    correction_settlement="explicit-only-v1",
    terminal_model="observed-only-v1",
)


def observed_order(*, quantity="4", funding="1000", fee_budget="1"):
    h = Harness(OBSERVED, funding=funding)
    commitment = h.install("observed", quantity, "100", fee_budget, activate=False)
    at = h.at + timedelta(seconds=1)
    accepted = BrokerOrderEvent(
        event_id="venue-accepted",
        order_id=commitment.order_id,
        broker_order_id="venue-order-1",
        broker_sequence=1,
        occurred_at=at,
        received_at=at,
        kind=BrokerOrderEventKind.ACCEPTED,
    )
    assert h.apply(accepted, at=at).disposition == "applied"
    return h, commitment


def test_fill_without_instruction_books_trade_and_waits_for_explicit_confirmation():
    h, c = observed_order()
    filled = h.fill(c, "4", "100", "1")
    assert filled.due_events == ()
    assert h.state.settlement_instructions == h.state.settlement_confirmations == ()
    assert filled.snapshot.positions[0].quantity == 4
    assert (
        filled.snapshot.trade_date_cash,
        filled.snapshot.settled_cash,
        filled.snapshot.trade_payable,
        filled.snapshot.available_cash,
    ) == (599, 1000, 401, 599)
    fill = next(e for e in h.state.broker_events if e.kind is BrokerOrderEventKind.EXECUTION)
    state = reduce_observed_settlement_ledger(
        account_id=h.state.account_id,
        order_states=(h.order(c),),
        cash_flows=h.state.cash_flows,
    )
    assert state.missing_instruction_event_ids == (fill.event_id,)
    before = h.project().journal_entries
    recorded = h.at + timedelta(hours=1)
    instruction = create_settlement_instruction(
        fill,
        contractual_settlement_at=recorded + timedelta(days=1),
        recorded_at=recorded,
        external_reference="venue-instruction-1",
    )
    instructed = h.apply(instruction, at=recorded)
    assert instructed.disposition == "applied"
    assert instructed.due_events == instructed.journal_entries == ()
    assert h.project().journal_entries == before
    # Merely advancing beyond the contractual date does not settle the fill.
    h.at += timedelta(days=2)
    assert h.project().snapshot.settled_cash == 1000
    assert h.project().snapshot.trade_payable == 401
    confirmation = create_settlement_confirmation(
        instruction,
        settled_at=h.at,
        recorded_at=h.at,
        external_reference="venue-confirmation-1",
    )
    settled = h.apply(confirmation, at=h.at)
    assert settled.disposition == "applied"
    assert len(settled.journal_entries) == 1
    assert settled.snapshot.settled_cash == 599 and settled.snapshot.trade_payable == 0
    assert settled.due_events == ()
    journal = h.project().journal_entries
    duplicate = h.apply(confirmation)
    assert duplicate.disposition == "duplicate" and duplicate.journal_entries == ()
    assert h.project().journal_entries == journal


def test_explicit_correction_keeps_original_postings_and_new_unsettled_delta():
    h, c = observed_order()
    h.fill(c, "4", "100", "1")
    original = h.project().journal_entries
    corrected = h.fill(c, "3", "101", "2", correction=True)
    # The source now says 3 shares costing 305. The 96 difference is an
    # unsettled receivable, not cash that can fund another purchase.
    assert corrected.snapshot.positions[0].quantity == 3
    assert corrected.snapshot.trade_date_cash == 695
    assert corrected.snapshot.settled_cash == 1000
    assert corrected.snapshot.trade_payable == 401
    assert corrected.snapshot.trade_receivable == 96
    assert corrected.snapshot.available_cash == 599
    assert corrected.due_events == ()
    assert set(original) <= set(h.project().journal_entries)
    assert h.state.settlement_instructions == ()


def test_actual_fee_overshoot_is_booked_and_halts_account():
    h, c = observed_order(quantity="9", funding="1000", fee_budget="0")
    filled = h.fill(c, "9", "120", "5")
    assert filled.disposition == "applied"
    assert filled.snapshot.positions[0].quantity == 9
    assert filled.snapshot.trade_date_cash == Decimal("-85")
    assert filled.snapshot.trade_payable == 1085
    assert filled.state.halted and "NEGATIVE_CASH_CAPACITY" in filled.reasons
    assert filled.due_events == ()


def test_observed_mode_rejects_all_modeled_lifecycle_effects():
    h = Harness(OBSERVED)
    c = h.install("observed", "4", "100", activate=False)
    original = h.state
    for payload in (
        ActivateCommitment(c.commitment_id),
        ModelDisposition(c.commitment_id, "unknown", "fixture"),
    ):
        result = h.apply(payload)
        assert result.disposition == "rejected"
        assert result.state == original
    result = h.observe()
    assert result.disposition == "rejected" and result.state == original
    assert h.state.broker_events == ()


@pytest.mark.parametrize(
    "field,value",
    [
        ("settlement_model", POLICY.settlement_model),
        ("correction_settlement", POLICY.correction_settlement),
        ("terminal_model", POLICY.terminal_model),
        ("model_id", POLICY.model_id),
    ],
)
def test_observed_policy_cannot_mix_in_modeled_assumptions(field, value):
    with pytest.raises(ValueError, match="explicit observation policies"):
        replace(OBSERVED, **{field: value})
