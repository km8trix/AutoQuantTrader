"""Finite session economics and restart over independent temporary databases.

Market time, operational re-arm and initial assignment are explicitly modeled
by the existing fixture. Captures, admissions, dispatch, venue records and all
financial publications use concrete owners. This is not provider qualification.
"""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
from time import perf_counter

import pytest

from packages.application.stateful_venue import project_stateful_venue
from packages.domain.stateful_venue_contracts import VenueAccept, VenueCommand
from tests.integration import test_continuous_runtime_attempt_sources as attempt_fixture
from tests.integration.test_continuous_runtime_sources import fresh_reader
from tests.integration.test_continuous_session import canonical_accounting, session_for
from tests.unit.test_stateful_venue import quote


def compare_economics(session):
    """Compare separately reduced venue records with the committed account."""
    retained = session.account.restore(session.scope)
    independent = session.delivery.venue.read()
    venue = project_stateful_venue(
        session.delivery.model,
        independent.state,
        accounting=session.delivery.runtime.accounting,
    ).snapshot
    actual = retained.checkpoint.current.snapshot
    for field in (
        "positions",
        "trade_date_cash",
        "settled_cash",
        "trade_receivable",
        "trade_payable",
        "dividend_receivable",
        "buy_reserve",
        "sell_fee_reserve",
        "available_cash",
        "fees",
        "net_external_flow",
    ):
        assert getattr(actual, field) == getattr(venue, field), field
    return retained, actual


def test_session_partial_fill_completion_restart_and_overlap(tmp_path, monkeypatch):
    measured_at = perf_counter()

    def mark(label):
        nonlocal measured_at
        finished = perf_counter()
        print(f"session step {label}: {finished - measured_at:.3f}s", flush=True)
        measured_at = finished

    canonical_accounting(monkeypatch)
    fixture = attempt_fixture.attempt_case.__wrapped__(tmp_path, monkeypatch)
    try:
        initial = next(fixture)
        case, runtime, reader, _previous, current, _admission, _prepared, descriptor = (
            attempt_fixture.activation_preparation(initial)
        )
        pair = case.paired_fixture
        mark("original admission and activation dependencies")
        session = session_for(pair, runtime, reader)
        ids = tuple(sorted(item.attempt_id for item in current.attempts))
        assert len(ids) == 1
        original_clock = descriptor.plan.operating.clock_reference
        quote_clock = descriptor.plan.quote_clock.reference
        receipts = session.activate_and_send(
            operation_id="session-accepted-send",
            attempt_ids=ids,
            clock_reference=original_clock,
            quote_clock_reference=quote_clock,
        )
        assert len(receipts) == 1
        mark("application activation and send")
        assert receipts[0].acknowledgment.disposition == "registered"
        assert session.last_delivery_failure is None
        before = pair.account.restore(case.scope)
        obligations = case.h.resolved().obligations
        assert (
            session.observe_attempt(
                operation_id="registration-is-not-acceptance",
                capture_id="registered-session-order",
                attempt_id=ids[0],
            )
            is None
        )
        assert pair.account.restore(case.scope).receipt == before.receipt
        assert case.h.resolved().obligations == obligations

        order = before.checkpoint.state.commitments[0]
        mark("registered observation remains uncertain")
        venue = session.delivery.venue
        case.h.clock.instant += timedelta(milliseconds=20)
        accepted = venue.execute(
            VenueCommand(
                "session-independent-accept", case.h.clock.instant, VenueAccept(order.order_id)
            )
        )
        assert accepted.acknowledgment.disposition == "applied"
        case.h.clock.instant += timedelta(milliseconds=20)
        modeled = quote(case.h.clock.instant, name="session-modeled-partial", budget="1")
        modeled = replace(
            modeled,
            observation=replace(
                modeled.observation,
                payload=replace(modeled.observation.payload, instrument_id=order.instrument_id),
            ),
        )
        filled = venue.execute(
            VenueCommand("session-independent-partial", case.h.clock.instant, modeled)
        )
        assert filled.acknowledgment.disposition == "applied"
        outcome = session.observe_attempt(
            operation_id="session-observed-acceptance",
            capture_id="session-definitive-capture",
            attempt_id=ids[0],
        )
        assert outcome is not None
        assert case.h.resolved().attempts[0].state.value == "confirmed"
        assert pair.account.restore(case.scope).checkpoint.state == before.checkpoint.state
        assert case.h.resolved().obligations == obligations

        partial_receipt = session.reconcile(
            operation_id="session-apply-partial", capture_id="session-partial-financial-capture"
        )
        mark("partial fill outcome and financial reconciliation")
        partial, snapshot = compare_economics(session)
        assert partial.receipt == partial_receipt.continuous
        assert snapshot.positions[0].quantity == Decimal(1)
        policy = runtime.venue_model.execution_policy
        expected_price = Decimal(100) * (1 + policy.slippage_bps / Decimal(10000))
        assert snapshot.fees == policy.fee_per_share
        assert (
            snapshot.trade_date_cash
            == (policy_initial_cash := runtime.venue_model.initial_cash_flow.amount)
            - expected_price
            - policy.fee_per_share
        )
        assert snapshot.settled_cash == policy_initial_cash
        hold = case.h.resolved().obligations.bindings[0].commitment
        assert hold.remaining_quantity == order.original_quantity - 1
        assert hold.reserved_cash > 0
        mark("independent partial economics comparison")

        # A later independent quote fills only the original remaining quantity.
        # External cancellation without a canonical local request is a separate
        # negative reconciliation case; it cannot imply financial convergence.
        case.h.clock.instant += timedelta(milliseconds=20)
        remaining_quote = quote(
            case.h.clock.instant,
            name="session-modeled-remainder",
            budget=str(hold.remaining_quantity),
        )
        remaining_quote = replace(
            remaining_quote,
            observation=replace(
                remaining_quote.observation,
                payload=replace(
                    remaining_quote.observation.payload, instrument_id=order.instrument_id
                ),
            ),
        )
        completed = venue.execute(
            VenueCommand(
                "session-independent-completion",
                case.h.clock.instant,
                remaining_quote,
            )
        )
        assert completed.acknowledgment.disposition == "applied"
        session.reconcile(
            operation_id="session-apply-completion", capture_id="session-complete-financial-capture"
        )
        final, snapshot = compare_economics(session)
        mark("completion reconciliation and independent comparison")
        hold = case.h.resolved().obligations.bindings[0].commitment
        assert hold.state == "terminal"
        assert hold.remaining_quantity == hold.reserved_cash == 0
        assert snapshot.positions[0].quantity == order.original_quantity
        assert snapshot.fees == order.original_quantity * policy.fee_per_share
        assert snapshot.trade_date_cash == policy_initial_cash - order.original_quantity * (
            expected_price + policy.fee_per_share
        )

        # Reconstruct the application, account, source, capture and independent
        # venue owners from their retained stores, without issuing another send.
        previous_heads = venue.read().head
        restarted_runtime = fresh_reader(case, runtime)
        case.h.store.producers = restarted_runtime
        case.reader = restarted_runtime
        case.owner.runtime_evidence = restarted_runtime
        pair.restart()
        case.store = pair.account
        restarted_runtime.bind_stores(accounts=pair.account, daily=case.h.store)
        restarted_runtime.bind_reconciliation(pair.publisher)
        restarted = session_for(pair, restarted_runtime)
        restored = pair.account.restore(case.scope)
        assert restored.receipt == final.receipt
        assert restored.checkpoint == final.checkpoint
        assert not restarted_runtime._active
        mark("reconstructed owners and retained restore")
        assert restarted.delivery.venue.read().head == previous_heads
        with pytest.raises(ValueError):
            restarted.activate_and_send(
                operation_id="session-restart-cannot-resend",
                attempt_ids=ids,
                clock_reference=original_clock,
                quote_clock_reference=quote_clock,
            )
        assert restarted.delivery.venue.read().head == previous_heads
        restarted.reconcile(
            operation_id="session-repeat-financial-view", capture_id="session-overlap-capture"
        )
        mark("restart denial and overlapping reconciliation")
        repeated, _ = compare_economics(restarted)
        assert repeated.checkpoint.state.cash_flows == final.checkpoint.state.cash_flows
        assert repeated.checkpoint.state.broker_events == final.checkpoint.state.broker_events
        assert repeated.checkpoint.state.commitments == final.checkpoint.state.commitments
        assert case.h.resolved().obligations.bindings[0].commitment == hold
        mark("overlap economic equality")
        assert restarted.delivery.venue.read().head == previous_heads
    finally:
        fixture.close()
