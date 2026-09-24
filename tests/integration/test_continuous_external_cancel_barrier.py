"""Independent cancellation cannot supply the canonical owner's cancel request.

Initial risk approval, controls and venue delivery use CoupledCase's labelled
synthetic fixtures. Captures, sole accounting, C/B/A publication and restoration
use their actual owners. This test grants no owner readiness or provider authority.
"""

from decimal import Decimal

from packages.application.stateful_venue import project_stateful_venue
from packages.domain.order_reducer import BrokerOrderEventKind
from packages.domain.stateful_venue_contracts import VenueCancel
from tests.integration.test_continuous_observed_publication import CoupledCase


def test_external_cancel_keeps_original_partial_hold_and_repeated_owner_barrier(tmp_path):
    case = CoupledCase(tmp_path)
    try:
        case.venue_case.fill("1")
        _, partial_holds, partial_prepared = case.prepare("before-external-cancel")
        partial_receipt = case.publisher.publish(partial_prepared, fence=case.h.lease.fence)
        partial = case.restore()
        assert partial.continuous.receipt == partial_receipt.continuous
        original = partial.continuous.checkpoint
        original_daily = case.h.resolved()
        original_hold = original_daily.obligations.bindings[0].commitment
        assert original_daily.obligations == partial_holds.result.after
        assert original_hold.state == "partial"
        assert original_hold.filled_quantity == Decimal(1)
        assert original_hold.remaining_quantity > 0 and original_hold.reserved_cash > 0
        assert original.state.cancel_requests == ()

        case.venue_case.execute(
            VenueCancel(original_hold.order_id, "explicit-independent-owner-cancel")
        )
        independent = case.venue_case.venue.read()
        independent_projection = project_stateful_venue(
            case.venue_case.model,
            independent.state,
            accounting=case.venue_case.accounting,
        )
        canceled = tuple(
            event
            for event in independent.state.accounting.broker_events
            if event.kind is BrokerOrderEventKind.CANCELED
        )
        assert len(canceled) == 1
        assert len(independent.state.accounting.cancel_requests) == 1
        assert independent_projection.snapshot.buy_reserve == 0

        original_applications = partial.reconciliation.resolved.applications.applications
        expected_reasons = (
            "APPLIED_WATERMARK_INCOMPLETE",
            "CANONICAL_FACT_NOT_APPLIED",
            "TERMINAL_ORDER_REQUIRES_APPLIED_TRANSITION",
        )
        economic_fields = (
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
        )
        previous_round = None
        for identity in ("external-cancel", "external-cancel-overlap"):
            token, holds, prepared = case.prepare(identity)
            assert holds.result.group is None
            assert holds.result.changed_bindings == ()
            assert holds.result.before == holds.result.after == original_daily.obligations
            assert token.inputs.application_batches[-1].reasons == (
                "CANONICAL_ACCOUNTING_REJECTED_FACT",
            )
            assert token.inputs.application_batches[-1].unresolved_fact_ids == (
                canceled[0].event_id,
            )
            receipt = case.publisher.publish(prepared, fence=case.h.lease.fence)
            case.restart()
            restored = case.restore()
            assert restored.continuous.receipt == receipt.continuous
            assert restored.reconciliation.receipt == receipt.reconciliation
            checkpoint = restored.continuous.checkpoint
            result = restored.reconciliation.resolved.result
            applications = restored.reconciliation.resolved.applications
            assert result.status == "blocked"
            assert result.blocking_reasons == expected_reasons
            assert result.unresolved_fact_ids == (canceled[0].event_id,)
            assert result.quarantined_fact_ids == ()
            assert result.applied_through is None and applications.applied_through is None
            assert result.round_sha256 != previous_round
            previous_round = result.round_sha256
            assert applications.applications == original_applications
            assert checkpoint.state.halted and checkpoint.current.snapshot.halted
            assert checkpoint.state.cancel_requests == ()
            assert checkpoint.state.broker_events == original.state.broker_events
            assert checkpoint.state.commitments == original.state.commitments
            for name in economic_fields:
                assert getattr(checkpoint.current.snapshot, name) == getattr(
                    original.current.snapshot, name
                ), name
            current = case.h.resolved()
            assert current.obligations == original_daily.obligations
            assert current.control == original_daily.control
            assert current.attempts == original_daily.attempts == ()
            assert current.observed_groups == original_daily.observed_groups
            assert (
                receipt.continuous.commit.transition.resulting_heads.effect_watermark
                == partial_receipt.continuous.commit.transition.resulting_heads.effect_watermark
            )
            assert case.venue_case.venue.read() == independent
    finally:
        case.venue_case.close()
