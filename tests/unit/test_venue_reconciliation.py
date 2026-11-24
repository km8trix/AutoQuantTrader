"""Independent modeled observations, never coordinator-derived expected balances."""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest

from packages.application.account_reconciliation import apply_reconciliation_facts
from packages.application.stateful_venue import venue_fact_page, venue_order_id
from packages.application.venue_reconciliation import (
    VenueCaptureError,
    build_venue_financial_pages,
    resolve_venue_capture,
)
from packages.domain.accounting_contracts import AccountingState
from packages.domain.applied_reconciliation import assess_reconciliation_coverage
from packages.domain.durable_journal_contracts import JournalHead
from packages.domain.ledger_reducer import CashFlowKind, create_cash_flow
from packages.domain.personal_contracts import content_digest
from packages.domain.reconciliation_contracts import FactApplication, ReconciliationScope
from packages.domain.stateful_venue_contracts import (
    VenueCorrect,
    VenueRead,
    VenueRunDue,
    VenueSubmit,
)
from packages.domain.venue_reconciliation_contracts import (
    VenueAccountBinding,
    VenueCapturePage,
    VenueCaptureRequest,
    VenueSubmissionBinding,
)
from tests.unit.test_observed_accounting import OBSERVED
from tests.unit.test_personal_accounting import BASE, Harness
from tests.unit.test_stateful_venue import VenueHarness

D = Decimal


def request_for(model, state, *, name="capture-one", mapped=True):
    mappings = (
        tuple(
            sorted(
                (
                    VenueSubmissionBinding(
                        c.payload.registration.submission,
                        c.payload.registration.semantic_sha256,
                        venue_order_id(model, c.payload.registration.submission.order_id),
                    )
                    for c, ack in zip(state.commands, state.acknowledgments, strict=True)
                    if isinstance(c.payload, VenueSubmit) and ack.disposition == "registered"
                ),
                key=lambda m: m.submission.order_id,
            )
        )
        if mapped
        else ()
    )
    scope = ReconciliationScope(
        "coordinator-account",
        model.venue_id,
        "stateful_simulation",
        "a" * 64,
        "stateful_simulation",
    )
    return VenueCaptureRequest(
        name, VenueAccountBinding(scope, model, "b" * 64, mappings), BASE, state.as_of
    )


def capture_pages(h, *, mapped=True, page_size=200):
    request = request_for(h.model, h.state, mapped=mapped)
    head = JournalHead(
        content_digest("explicit-synthetic-key"),
        h.state.sequence + 1,
        content_digest("explicit-synthetic-head"),
    )
    read = VenueRead(head, h.state)
    original = tuple(
        venue_fact_page(
            h.model, h.state, through_sequence=h.state.sequence, offset=offset, limit=page_size
        )
        for offset in range(0, len(h.state.facts), page_size)
    )
    bodies = build_venue_financial_pages(request, read, original)
    at = h.state.as_of + timedelta(seconds=1)
    pages = tuple(
        VenueCapturePage(
            request,
            head,
            h.state.semantic_sha256,
            h.state.as_of,
            at + timedelta(microseconds=body.ordinal * 2),
            at + timedelta(microseconds=body.ordinal * 2 + 1),
            body,
            index,
            len(bodies),
        )
        for index, body in enumerate(bodies)
    )
    return pages, resolve_venue_capture(pages)


def cash(observed):
    return {value.field: value.value for value in observed.cash}


@pytest.mark.parametrize(
    "quantity,expected_cash,expected_fee", [("2", "799.50", ".50"), ("4", "599", "1")]
)
def test_independent_partial_and_full_literal_economics(quantity, expected_cash, expected_fee):
    h = VenueHarness()
    h.accepted()
    h.filled(budget=quantity)
    pages, (observed, facts) = capture_pages(h, page_size=2)
    assert cash(observed)["trade_date_cash"] == D(expected_cash)
    assert cash(observed)["fees"] == D(expected_fee)
    assert observed.positions[0].quantity == D(quantity)
    assert observed.scope.account_id != h.state.accounting.account_id
    assert {f.command.payload for f in facts} == {f.payload for f in h.state.facts}
    activity = [p for p in pages if p.body.fact_page is not None]
    assert tuple(f for p in activity for f in p.body.fact_page.facts) == h.state.facts
    assert all(p.provider_sequence is None for p in observed.pages)
    assert not assess_reconciliation_coverage(
        observed, required_from=BASE, required_through=h.state.as_of, now=observed.completed_at
    ).reasons
    assert (
        "STALE_PAGE_RECEIPT"
        in assess_reconciliation_coverage(
            observed,
            required_from=BASE,
            required_through=h.state.as_of,
            now=observed.completed_at + timedelta(seconds=60),
        ).reasons
    )


def test_correction_and_explicit_settlement_are_original_facts():
    h = VenueHarness()
    h.accepted()
    h.filled()
    execution = next(e for e in h.state.accounting.broker_events if e.execution_id is not None)
    h.command(VenueCorrect(execution.execution_id, D(3), D(101), D(2), "fixture-correction"))
    _, (observed, commands) = capture_pages(h)
    assert (
        cash(observed)["trade_date_cash"],
        cash(observed)["trade_receivable"],
        cash(observed)["trade_payable"],
    ) == (695, 96, 401)
    correction = next(c for c in commands if c.observation.kind == "correction")
    assert correction.predecessor_fact_ids == (execution.event_id,)
    h.command(VenueRunDue(), at=max(d.due_at for d in h.state.due_settlements))
    _, (settled, _) = capture_pages(h)
    assert (
        cash(settled)["settled_cash"],
        cash(settled)["trade_payable"],
        cash(settled)["trade_receivable"],
    ) == (695, 0, 0)


def test_cashflow_exact_identity_not_amount_matching():
    h = VenueHarness()
    flow = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=D(1000),
        effective_at=h.state.as_of + timedelta(seconds=1),
        recorded_at=h.state.as_of + timedelta(seconds=1),
        external_reference="independent-venue-deposit",
    )
    h.command(flow)
    _, (observed, commands) = capture_pages(h)
    assert cash(observed)["trade_date_cash"] == 2000
    assert (
        next(c.command.payload for c in commands if c.observation.fact_id == flow.cash_flow_id)
        == flow
    )
    assert len({c.observation.fact_id for c in commands}) == 2
    assert (
        next(c.observation.origin for c in commands if c.observation.fact_id == flow.cash_flow_id)
        == "external"
    )
    assert (
        next(
            c.observation.origin
            for c in commands
            if c.observation.fact_id == h.model.initial_cash_flow.cash_flow_id
        )
        == "application"
    )


def test_no_auto_adoption_and_mapping_conflict():
    h = VenueHarness()
    h.accepted()
    h.filled()
    pages, (observed, commands) = capture_pages(h, mapped=False)
    assert observed.orders[0].order_id is None
    broker = [c for c in commands if c.observation.kind in ("order", "execution")]
    assert all(c.mapping is None and c.observation.origin == "external" for c in broker)
    valid, _ = capture_pages(h)
    bad_mapping = replace(valid[0].request.binding.orders[0], registration_sha256="c" * 64)
    request = replace(
        valid[0].request, binding=replace(valid[0].request.binding, orders=(bad_mapping,))
    )
    with pytest.raises(VenueCaptureError, match="SUBMISSION_MAPPING"):
        build_venue_financial_pages(
            request,
            VenueRead(valid[0].venue_head, h.state),
            tuple(p.body.fact_page for p in valid if p.body.fact_page is not None),
        )
    assert pages[0].request.binding.model.source_mode == "synthetic_fixture"


def test_page_gap_duplicate_and_mixed_head_reject():
    h = VenueHarness()
    h.accepted()
    h.filled()
    pages, _ = capture_pages(h, page_size=2)
    for corrupt in (pages[:-1], (*pages, pages[-1]), (*pages[:-1], replace(pages[-1], index=0))):
        with pytest.raises(VenueCaptureError, match="PAGE_GAP"):
            resolve_venue_capture(corrupt)
    with pytest.raises(VenueCaptureError, match="COMMON_BINDING"):
        resolve_venue_capture((replace(pages[0], venue_state_sha256="d" * 64), *pages[1:]))
    fact_pages = tuple(p.body.fact_page for p in pages if p.body.fact_page is not None)
    with pytest.raises(VenueCaptureError, match="PAGE_CLOSURE"):
        build_venue_financial_pages(
            pages[0].request, VenueRead(pages[0].venue_head, h.state), fact_pages[1:]
        )


@pytest.mark.parametrize("scenario", ["partial", "correction", "split"])
def test_separate_coordinator_applies_exact_facts_once_with_existing_submission(scenario):
    venue = VenueHarness()
    venue.accepted()
    venue.filled(budget="4" if scenario == "split" else "2")
    expected_cash, expected_quantity = D("799.5"), 2
    if scenario == "correction":
        execution = next(
            e for e in venue.state.accounting.broker_events if e.execution_id is not None
        )
        assert (
            venue.command(VenueCorrect(execution.execution_id, D(1), D(101), D(2), "correction"))[
                1
            ].disposition
            == "applied"
        )
        expected_cash, expected_quantity = D(897), 1
    elif scenario == "split":
        from packages.domain.corporate_action_ledger import create_stock_split

        at = venue.state.as_of + timedelta(seconds=1)
        split = create_stock_split(
            source_action_id="split",
            source_revision_id="1",
            source_sha256="a" * 64,
            instrument_id="spy",
            symbol="SPY",
            numerator=D(2),
            denominator=D(1),
            entitled_quantity=D(4),
            effective_at=at,
            recorded_at=at,
        )
        assert venue.command(split, at=at)[1].disposition == "applied"
        expected_cash, expected_quantity = D(599), 8
    _, (observed, commands) = capture_pages(venue, page_size=2 if scenario == "split" else 200)
    coordinator = Harness(OBSERVED, funding=None)
    coordinator.state = AccountingState("coordinator-account")
    # Composition explicitly shares the original canonical opening cash-flow.
    opening = venue.model.initial_cash_flow
    funded = coordinator.apply(opening)
    opening_application = FactApplication(
        opening.cash_flow_id,
        opening.semantic_sha256,
        coordinator.at,
        tuple(sorted(e.entry_id for e in funded.journal_entries)),
    )
    coordinator.install("one", "4", "110", "1", activate=False)
    assert coordinator.state.submissions == venue.state.accounting.submissions
    context = coordinator.context(at=observed.completed_at)
    context = replace(context, point=replace(context.point, stage=1, frontier_sequence=100))
    result = apply_reconciliation_facts(
        scope=observed.scope,
        state=coordinator.state,
        facts=commands,
        source_receipts=observed.pages,
        prior_applications=(opening_application,),
        context=context,
        accounting=coordinator.port,
        policy=OBSERVED,
        source_order=tuple(f.fact_id for f in venue.state.facts),
    )
    assert not result.unresolved_fact_ids and not result.quarantined_fact_ids, result.reasons
    assert result.current.snapshot.trade_date_cash == expected_cash
    assert result.current.snapshot.positions[0].quantity == expected_quantity
    retry = apply_reconciliation_facts(
        scope=observed.scope,
        state=result.state,
        facts=commands,
        source_receipts=observed.pages,
        prior_applications=result.applications,
        context=replace(context, point=result.current.snapshot.point),
        accounting=coordinator.port,
        policy=OBSERVED,
        source_order=tuple(f.fact_id for f in venue.state.facts),
    )
    assert retry.state == result.state and retry.applications == result.applications
    assert set(retry.duplicate_fact_ids) == {c.observation.fact_id for c in commands}


def test_supported_split_dividend_and_payment_remain_independent_exact_actions():
    from packages.domain.corporate_action_ledger import (
        create_cash_dividend,
        create_dividend_payment,
        create_stock_split,
    )

    h = VenueHarness()
    h.accepted()
    h.filled()
    at = h.state.as_of + timedelta(seconds=1)
    split = create_stock_split(
        source_action_id="split",
        source_revision_id="1",
        source_sha256="a" * 64,
        instrument_id="spy",
        symbol="SPY",
        numerator=D(2),
        denominator=D(1),
        entitled_quantity=D(4),
        effective_at=at,
        recorded_at=at,
    )
    assert h.command(split, at=at)[1].disposition == "applied"
    at += timedelta(seconds=1)
    dividend = create_cash_dividend(
        source_action_id="dividend",
        source_revision_id="dividend-1",
        source_sha256="b" * 64,
        instrument_id="spy",
        symbol="SPY",
        currency="USD",
        amount_per_share=D(1),
        entitled_quantity=D(8),
        effective_at=at,
        payable_at=at + timedelta(days=1),
        recorded_at=at,
    )
    assert h.command(dividend, at=at)[1].disposition == "applied"
    _, (observed, _) = capture_pages(h)
    assert observed.positions[0].quantity == 8 and cash(observed)["dividend_receivable"] == 8
    payment = create_dividend_payment(
        dividend,
        paid_at=at + timedelta(days=1),
        recorded_at=at + timedelta(days=1),
        external_reference="explicit-payment",
    )
    assert h.command(payment, at=payment.paid_at)[1].disposition == "applied"
    _, (observed, commands) = capture_pages(h)
    assert cash(observed)["trade_date_cash"] == 607 and cash(observed)["dividend_receivable"] == 0
    assert {split, dividend, payment} <= {c.command.payload for c in commands}
    assert next(
        c.predecessor_fact_ids for c in commands if c.observation.fact_id == payment.payment_id
    ) == (dividend.dividend_id,)


def test_fact_canonical_links_and_financial_page_bound_are_checked():
    h = VenueHarness()
    h.accepted()
    h.filled()
    pages, _ = capture_pages(h)
    fact_pages = tuple(p.body.fact_page for p in pages if p.body.fact_page is not None)
    changed = replace(h.state.facts[0], journal_entry_ids=("unrelated-entry",))
    state = replace(h.state, facts=(changed, *h.state.facts[1:]))
    original = tuple(
        venue_fact_page(h.model, state, through_sequence=state.sequence, offset=0, limit=200)
        for _ in range(1)
    )
    with pytest.raises(VenueCaptureError, match="CANONICAL_LINKS"):
        build_venue_financial_pages(
            pages[0].request, VenueRead(pages[0].venue_head, state), original
        )
    with pytest.raises(ValueError, match="PAGE_ITEMS"):
        replace(
            pages[0].body, cash=pages[0].body.cash * 26, next_offset=len(pages[0].body.cash) * 26
        )
    assert fact_pages


def test_cash_flow_chronology_preserves_funded_withdrawal_with_one_receipt():
    venue = VenueHarness()
    deposit_at = venue.state.as_of + timedelta(seconds=1)
    deposit = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=D(500),
        effective_at=deposit_at,
        recorded_at=deposit_at,
        external_reference="source-deposit",
    )
    withdrawal_at = deposit_at + timedelta(seconds=1)
    # Fix a deterministic fixture whose receipt-tied lexicographic ordering is
    # opposite the source's actual economically funded command chronology.
    withdrawals = tuple(
        create_cash_flow(
            kind=CashFlowKind.WITHDRAWAL,
            currency="USD",
            amount=D(1200),
            effective_at=withdrawal_at,
            recorded_at=withdrawal_at,
            external_reference=f"source-withdrawal-{n}",
        )
        for n in range(16)
    )
    withdrawal = next(w for w in withdrawals if w.cash_flow_id < deposit.cash_flow_id)
    assert venue.command(deposit, at=deposit_at)[1].disposition == "applied"
    assert venue.command(withdrawal, at=withdrawal_at)[1].disposition == "applied"
    _, (observed, commands) = capture_pages(venue)
    assert cash(observed)["trade_date_cash"] == 300
    coordinator = Harness(OBSERVED, funding=None)
    coordinator.state = AccountingState("coordinator-account")
    opening = venue.model.initial_cash_flow
    seeded = coordinator.apply(opening)
    prior = FactApplication(
        opening.cash_flow_id,
        opening.semantic_sha256,
        coordinator.at,
        tuple(sorted(e.entry_id for e in seeded.journal_entries)),
    )
    context = coordinator.context(at=observed.completed_at)
    context = replace(context, point=replace(context.point, stage=1, frontier_sequence=100))
    result = apply_reconciliation_facts(
        scope=observed.scope,
        state=coordinator.state,
        facts=commands,
        source_receipts=observed.pages,
        prior_applications=(prior,),
        context=context,
        accounting=coordinator.port,
        policy=OBSERVED,
        source_order=tuple(f.fact_id for f in venue.state.facts),
    )
    assert not result.unresolved_fact_ids, result.reasons
    assert result.current.snapshot.trade_date_cash == 300 and not result.state.halted
    assert "EXTERNAL_ACTIVITY_REQUIRES_OWNER_DISPOSITION" in result.reasons


def test_action_dependency_mapping_is_recomputed_across_pages():
    from packages.domain.corporate_action_ledger import create_stock_split

    h = VenueHarness()
    h.accepted()
    h.filled()
    at = h.state.as_of + timedelta(seconds=1)
    split = create_stock_split(
        source_action_id="split",
        source_revision_id="1",
        source_sha256="a" * 64,
        instrument_id="spy",
        symbol="SPY",
        numerator=D(2),
        denominator=D(1),
        entitled_quantity=D(4),
        effective_at=at,
        recorded_at=at,
    )
    assert h.command(split, at=at)[1].disposition == "applied"
    pages, (_, commands) = capture_pages(h, page_size=2)
    action = next(c for c in commands if c.observation.fact_id == split.split_id)
    fill = next(c for c in commands if c.observation.kind == "execution")
    assert fill.observation.fact_id in action.predecessor_fact_ids
    assert fill.observation.source_receipt_id != action.observation.source_receipt_id
    changed = tuple(
        replace(p, body=replace(p.body, action_predecessors=()))
        if p.body.action_predecessors
        else p
        for p in pages
    )
    with pytest.raises(VenueCaptureError, match="ACTION_PREDECESSOR_CLOSURE"):
        resolve_venue_capture(changed)


def test_altered_original_within_command_fact_order_is_rejected():
    h = VenueHarness()
    h.accepted()
    h.filled()
    pages, _ = capture_pages(h)
    activity = next(p for p in pages if p.body.fact_page is not None)
    original = activity.body.fact_page
    # The actual same-command fill precedes its explicit instruction. Moving
    # instruction ahead cannot masquerade as the original retained C order.
    changed_facts = (*original.facts[:2], original.facts[3], original.facts[2])
    changed = replace(
        activity, body=replace(activity.body, fact_page=replace(original, facts=changed_facts))
    )
    with pytest.raises(VenueCaptureError, match="SOURCE_FACT_ORDER"):
        resolve_venue_capture(tuple(changed if p is activity else p for p in pages))


def test_action_dependency_inventory_above_sixteen_is_explicitly_bounded():
    from packages.domain.corporate_action_ledger import create_stock_split
    from tests.unit.test_stateful_venue import model

    h = VenueHarness(model(funding="10000"))
    for index in range(17):
        h.accepted(name=f"bounded-{index}", quantity="1")
        h.filled(name=f"bounded-quote-{index}", budget="1")
    at = h.state.as_of + timedelta(seconds=1)
    split = create_stock_split(
        source_action_id="split",
        source_revision_id="1",
        source_sha256="a" * 64,
        instrument_id="spy",
        symbol="SPY",
        numerator=D(2),
        denominator=D(1),
        entitled_quantity=D(17),
        effective_at=at,
        recorded_at=at,
    )
    assert h.command(split, at=at)[1].disposition == "applied"
    with pytest.raises(VenueCaptureError, match="ACTION_PREDECESSOR_LIMIT"):
        capture_pages(h)
