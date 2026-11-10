"""Financial cutover oracles, using explicit B commands rather than A's engine.

All accounting/report inputs are actual canonical reducer outputs. The preserved
golden execution admission is delayed one second to admit its original explicit
settlement instruction first; there is no intervening strategy decision. This is
an economics oracle, not qualification of the old intraday execution chronology.
"""

from dataclasses import replace
from datetime import date, timedelta
from decimal import Decimal

import pytest

from packages.backtest.golden_runner import run_golden_backtest
from packages.domain.accounting_contracts import SettlementCalendar
from packages.domain.corporate_action_ledger import (
    create_cash_dividend,
    create_dividend_payment,
    create_stock_split,
)
from packages.domain.ledger_reducer import CashFlowKind, create_cash_flow
from packages.domain.models import Side
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    create_cancel_request,
)
from packages.domain.report_contracts import ReportConventions
from tests.helpers.personal_economics import LABEL, OracleDriver
from tests.unit.test_personal_accounting import POLICY

D = Decimal


def _funded():
    h = OracleDriver()
    h.fund(
        create_cash_flow(
            kind=CashFlowKind.CONTRIBUTION,
            currency="USD",
            amount=D(1000),
            effective_at=h.at,
            recorded_at=h.at,
            external_reference="oracle-initial-funding",
        )
    )
    return h


def _report(h, case, **expected):
    # C's frozen builder is imported here so driver-only checks can run before
    # integration. Missing builder is a failure, never a skipped report oracle.
    from packages.application.run_report import build_run_report

    result = h.result(case)
    report = build_run_report(result, ReportConventions())
    assert report.source == result
    assert LABEL in result.spec.limitations
    assert result.spec.strategy.version == "unused-in-command-driver/1"
    assert result.final_strategy_state.values == (("driver", LABEL),)
    assert all(row.kind.startswith("oracle:") for row in result.trace)
    metrics = {metric.name: metric for metric in report.metrics}
    for name, value in expected.items():
        assert metrics[name].value == D(str(value)), (name, metrics[name])
    assert metrics["annualized_return"].value is None
    assert metrics["annualized_return"].reasons
    # The funded baseline precedes every execution: fees remain inside P&L.
    baseline = result.valuations[1]
    assert baseline.snapshot.nav == 1000
    assert baseline.snapshot.fees == 0
    assert all(
        row.sequence > baseline.snapshot.point.reduction_sequence for row in result.executions
    )
    assert result.executions == h.project().executions
    assert result.fifo_matches == h.project().fifo_matches
    assert result.journal_entries == h.project().journal_entries
    return report


def _split(h, *, numerator=2, denominator=1, entitled=4):
    at = h.at + timedelta(seconds=1)
    return create_stock_split(
        source_action_id="oracle-split",
        source_revision_id="oracle-split-r1",
        source_sha256="9" * 64,
        instrument_id="spy",
        symbol="SPY",
        numerator=D(numerator),
        denominator=D(denominator),
        entitled_quantity=D(entitled),
        effective_at=at,
        recorded_at=at,
    )


def test_e1_open_lot_fee_attribution_and_settlement_feed_report():
    h = _funded()
    buy = h.install("buy", "4", "100", "1")
    filled = h.fill(buy, "4", "100", "1")
    due = filled.due_events[0]
    h.apply(due.command.payload, at=due.due_at)
    sell = h.install("sell", "2", "110", "1", Side.SELL)
    sold = h.fill(sell, "2", "110", "1")
    due = sold.due_events[0]
    h.apply(due.command.payload, at=due.due_at)
    h.mark("110")
    report = _report(
        h,
        "E1",
        starting_equity=1000,
        ending_equity=1038,
        ending_trade_date_cash=818,
        ending_settled_cash=818,
        ending_available_cash=818,
        gross_realized_pnl=20,
        realized_pnl=18,
        unrealized_pnl=20,
        net_pnl=38,
        total_execution_costs=2,
        closed_trade_net_pnl="18.5",
        trade_count=1,
    )
    match = report.source.fifo_matches[0]
    assert (match.opening_fee, match.closing_fee) == (D("0.5"), 1)
    # All fees reduce portfolio economics, but only matched fees reduce this trade.
    assert report.source.final_snapshot.positions[0].cost_basis == 200
    assert report.source.final_snapshot.positions[0].quantity == 2


def test_e2_dividend_accrual_and_payment_are_one_income_in_report():
    h = _funded()
    buy = h.install("buy", "4", "100")
    due = h.fill(buy, "4", "100").due_events[0]
    h.apply(due.command.payload, at=due.due_at)
    at = h.at + timedelta(seconds=1)
    dividend = create_cash_dividend(
        source_action_id="oracle-dividend",
        source_revision_id="oracle-dividend-r1",
        source_sha256="8" * 64,
        instrument_id="spy",
        symbol="SPY",
        currency="USD",
        amount_per_share=D(2),
        entitled_quantity=D(4),
        effective_at=at,
        recorded_at=at,
        payable_at=at + timedelta(minutes=1),
    )
    h.apply(dividend, at=at)
    h.mark("98")
    accrued = _report(
        h,
        "E2-accrued",
        ending_equity=1000,
        dividend_income=8,
        ending_trade_date_cash=600,
        ending_dividend_receivable=8,
        net_pnl=0,
        realized_pnl=8,
        unrealized_pnl=-8,
        total_execution_costs=0,
    )
    payment = create_dividend_payment(
        dividend,
        paid_at=dividend.payable_at,
        recorded_at=dividend.payable_at,
        external_reference="oracle-payment",
    )
    h.apply(payment, at=payment.recorded_at)
    assert h.apply(payment).disposition == "duplicate"
    paid = _report(
        h,
        "E2-paid",
        ending_equity=1000,
        dividend_income=8,
        ending_trade_date_cash=608,
        ending_settled_cash=608,
        ending_dividend_receivable=0,
        net_pnl=0,
        realized_pnl=8,
        unrealized_pnl=-8,
    )
    assert accrued.source.final_snapshot.dividend_receivable == 8
    assert paid.source.final_snapshot.dividend_receivable == 0


def test_e3_split_basis_and_effective_fifo_lineage_feed_report():
    h = _funded()
    buy = h.install("buy", "4", "100")
    h.fill(buy, "4", "100")
    action = _split(h)
    h.apply(action, at=action.recorded_at)
    h.mark("50")
    sell = h.install("sell", "3", "55", "1", Side.SELL)
    h.fill(sell, "3", "55", "1")
    h.mark("55")
    report = _report(
        h,
        "E3",
        ending_equity=1039,
        ending_trade_date_cash=764,
        gross_realized_pnl=15,
        realized_pnl=14,
        unrealized_pnl=25,
        total_execution_costs=1,
        net_pnl=39,
        closed_trade_net_pnl=14,
    )
    match = report.source.fifo_matches[0]
    assert (match.quantity, match.basis, match.proceeds, match.split_ids) == (
        3,
        150,
        165,
        (action.split_id,),
    )
    assert report.source.final_snapshot.positions[0].cost_basis == 250


def test_e6_correction_duplicate_and_bust_report_only_effective_heads():
    h = _funded()
    buy = h.install("buy", "4", "100", "2")
    original = h.fill(buy, "4", "100", "1")
    revised = h.fill(buy, "4", "101", "2", correction=True)
    h.mark("101")
    event = next(e for e in h.state.broker_events if e.event_id == revised.executions[0].fact_id)
    assert h.apply(event).disposition == "duplicate"
    report = _report(
        h,
        "E6-corrected",
        ending_equity=998,
        ending_trade_date_cash=594,
        total_execution_costs=2,
        net_pnl=-2,
        trade_count=0,
    )
    assert len(report.source.executions) == 1 and report.source.executions[0].revision == 2
    h.fill(buy, "0", "101", "0", correction=True)
    busted = _report(
        h,
        "E6-busted",
        ending_equity=1000,
        ending_trade_date_cash=1000,
        ending_available_cash=594,
        total_execution_costs=0,
        net_pnl=0,
        trade_count=0,
    )
    assert len(busted.source.executions) == 1
    head = busted.source.executions[0]
    assert (head.revision, head.quantity, head.economic_at) == (
        3,
        0,
        original.executions[0].economic_at,
    )
    assert not busted.source.fifo_matches
    assert report.source.final_snapshot.nav == 998  # Retained snapshot is immutable.


def test_correction_rebuilds_closed_fifo_matches_from_current_execution_heads():
    h = _funded()
    buy = h.install("buy", "4", "100", "2")
    original = h.fill(buy, "4", "100", "1")
    sell = h.install("sell", "2", "110", "1", Side.SELL)
    h.fill(sell, "2", "110", "1")
    revised = h.fill(buy, "4", "101", "2", correction=True)
    h.mark("110")
    report = _report(
        h,
        "corrected-closed-match",
        ending_equity=1033,
        gross_realized_pnl=18,
        realized_pnl=15,
        unrealized_pnl=18,
        total_execution_costs=3,
        net_pnl=33,
        closed_trade_net_pnl=16,
        trade_count=1,
    )
    assert len(report.source.executions) == 2 and len(report.source.fifo_matches) == 1
    match = report.source.fifo_matches[0]
    assert match.opening_revision == 2 and match.closing_revision == 1
    assert (match.basis, match.opening_fee, match.closing_fee) == (202, 1, 1)
    assert match.acquired_at == original.executions[0].economic_at
    current = {row.execution_id: row for row in revised.executions}
    assert current[match.opening_execution_id].revision == match.opening_revision
    assert current[match.closing_execution_id].revision == match.closing_revision


def test_missing_mark_keeps_valid_financial_facts_in_report():
    h = _funded()
    buy = h.install("buy", "4", "100", "1")
    h.fill(buy, "4", "100", "1")
    report = _report(
        h,
        "missing-current-mark",
        ending_trade_date_cash=599,
        total_execution_costs=1,
        gross_realized_pnl=0,
        realized_pnl=-1,
    )
    metrics = {metric.name: metric for metric in report.metrics}
    for name in ("ending_equity", "net_pnl", "unrealized_pnl"):
        assert metrics[name].status == "undefined" and metrics[name].value is None
        assert metrics[name].reasons
    assert report.source.final_snapshot.positions[0].cost_basis == 400
    assert report.source.final_snapshot.positions[0].quantity == 4
    assert report.source.executions[0].fee == 1


def test_e7_partial_cancel_late_fill_capacity_and_costs_feed_report():
    h = _funded()
    buy = h.install("buy", "5", "102", "3")
    h.fill(buy, "2", "100", "1")
    cancel = create_cancel_request(
        h.order(buy), requested_at=h.at + timedelta(seconds=1), reason="oracle-cancel"
    )
    h.apply(cancel, at=cancel.requested_at)
    late = h.fill(buy, "1", "102", "1")
    assert (
        late.snapshot.trade_payable,
        late.snapshot.buy_reserve,
        late.snapshot.available_cash,
    ) == (304, 205, 491)
    h.mark("102")
    order = h.order(buy)
    at = h.at + timedelta(seconds=1)
    h.apply(
        BrokerOrderEvent(
            event_id="oracle-cancel-confirmed",
            order_id=buy.order_id,
            broker_order_id=order.broker_order_id,
            broker_sequence=order.last_broker_sequence + 1,
            occurred_at=at,
            received_at=at,
            kind=BrokerOrderEventKind.CANCELED,
        ),
        at=at,
    )
    report = _report(
        h,
        "E7",
        ending_equity=1002,
        ending_trade_date_cash=696,
        ending_available_cash=696,
        total_execution_costs=2,
        gross_realized_pnl=0,
        realized_pnl=-2,
        unrealized_pnl=4,
        net_pnl=2,
        trade_count=0,
    )
    assert len(report.source.executions) == 2
    assert report.source.final_snapshot.buy_reserve == 0
    assert report.source.final_snapshot.positions[0].cost_basis == 302


@pytest.mark.parametrize("scope", ("fractional-lots", "pending-buy", "pending-sell"))
def test_unsupported_split_scope_retains_accounting_and_incomplete_report(scope):
    h = _funded()
    if scope == "fractional-lots":
        for name in ("first", "second"):
            buy = h.install(name, "1", "100")
            h.fill(buy, "1", "100")
        action = _split(h, numerator=3, denominator=2, entitled=2)
    else:
        buy = h.install("opening", "2", "100")
        h.fill(buy, "2", "100")
        h.install("pending", "1", "100", side=Side.BUY if scope == "pending-buy" else Side.SELL)
        action = _split(h, entitled=2)
    prior = h.state
    rejected = h.apply(action, at=action.recorded_at)
    assert rejected.disposition == "rejected" and rejected.state == prior
    report = _report(h, scope, ending_trade_date_cash=800, total_execution_costs=0)
    assert report.status == "incomplete" and report.source.status == "rejected"
    assert report.source.final_snapshot.nav is None
    assert report.source.final_snapshot.positions[0].quantity == 2
    assert report.source.final_state.stock_splits == ()


def _golden_driver():
    legacy = run_golden_backtest()
    trace = legacy.trace
    h = OracleDriver(
        base=trace.funding.recorded_at,
        account_id=trace.final_account.account_id,
        instruments=(("US-ETF-SPY", "SPY"),),
        limitations=(
            "preserved-golden-execution-admission-delayed-one-second-"
            "instruction-first-no-intervening-decisions",
        ),
        policy=replace(
            POLICY,
            settlement_calendar=SettlementCalendar(
                "synthetic-golden-oracle",
                "1",
                (date(2026, 7, 15), date(2026, 7, 16), date(2026, 7, 17)),
            ),
        ),
    )
    h.fund(trace.funding)
    # A finite test fixture plan, not a second runtime scheduling engine. Preserve
    # source timestamps; one-second execution admission delay has no decisions.
    plan = []
    instructions = {item.execution_event_id: item for item in trace.settlement_instructions}
    for order in trace.order_states:
        plan.append((order.submission.submitted_at, 0, order.submission))
    for event in (event for result in trace.broker_results for event in result.broker_events):
        instruction = instructions.get(event.event_id)
        admission = (
            max(event.received_at, instruction.recorded_at) if instruction else event.received_at
        )
        plan.append((admission, 2, event))
    for fact in (
        *trace.settlement_instructions,
        trace.stock_split,
        trace.cash_dividend,
        trace.dividend_payment,
        *trace.settlement_confirmations,
    ):
        plan.append((fact.recorded_at, 1, fact))
    for at, priority, fact in sorted(plan, key=lambda row: (row[0], row[1])):
        if priority == 0:
            h.install_exact_submission(
                fact,
                approved_price=D(105) if fact.intent.side is Side.BUY else D(53),
                fee_budget=D(1),
            )
        else:
            result = h.apply(fact, at=at)
            assert result.disposition == "applied", (type(fact), result.reasons)
    return legacy, h


def test_preserved_golden_exact_journal_through_accounting_command_driver():
    legacy, h = _golden_driver()
    trace = legacy.trace
    final = h.project()
    expected = (
        *trace.execution_ledger.entries,
        *trace.corporate_action_ledger.corporate_action_entries,
        *trace.settlement_ledger.settlement_entries,
    )
    assert {entry.entry_id: entry for entry in final.journal_entries} == {
        entry.entry_id: entry for entry in expected
    }
    assert len(final.journal_entries) == len(expected)
    assert h.state.cash_flows == (trace.funding,)
    assert set(h.state.submissions) == {order.submission for order in trace.order_states}
    assert set(h.state.broker_events) == {
        event for result in trace.broker_results for event in result.broker_events
    }
    assert set(h.state.settlement_instructions) == set(trace.settlement_instructions)
    assert set(h.state.settlement_confirmations) == set(trace.settlement_confirmations)
    assert h.state.stock_splits == (trace.stock_split,)
    assert h.state.cash_dividends == (trace.cash_dividend,)
    assert h.state.dividend_payments == (trace.dividend_payment,)
    assert (
        final.snapshot.trade_date_cash,
        final.snapshot.settled_cash,
        final.snapshot.available_cash,
        final.snapshot.nav,
    ) == (D("1044.04"),) * 4
    assert final.snapshot.nav == trace.final_account.equity
    assert len(final.executions) == 2 and len(final.fifo_matches) == 1
    assert final.snapshot.fees == legacy.report.metrics.total_execution_costs == D("1.12")
    assert final.snapshot.dividend_income == legacy.report.metrics.dividend_income == 10
    assert final.snapshot.gross_realized_pnl == legacy.report.trades[0].gross_pnl == D("35.16")
    match = final.fifo_matches[0]
    assert (
        match.proceeds - match.basis - match.opening_fee - match.closing_fee
        == (legacy.report.trades[0].net_pnl)
        == D("34.04")
    )
    source = h.result("preserved-golden-driver")
    assert any("admission-delayed-one-second" in item for item in source.spec.limitations)
    assert all(
        c.policy_sha256 == source.spec.risk_policy.semantic_sha256
        for c in source.final_state.commitments
    )


def test_preserved_golden_derived_report_matches_legacy_financial_oracle():
    legacy, h = _golden_driver()
    report = _report(
        h,
        "preserved-golden-financial-cutover",
        starting_equity=1000,
        ending_equity="1044.04",
        ending_trade_date_cash="1044.04",
        ending_settled_cash="1044.04",
        ending_available_cash="1044.04",
        total_execution_costs="1.12",
        gross_realized_pnl="35.16",
        realized_pnl="44.04",
        unrealized_pnl=0,
        dividend_income=10,
        closed_trade_net_pnl="34.04",
        net_pnl="44.04",
        trade_count=1,
    )
    metrics = {metric.name: metric.value for metric in report.metrics}
    assert metrics["ending_equity"] == legacy.report.metrics.ending_equity
    assert metrics["total_execution_costs"] == legacy.report.metrics.total_execution_costs
    assert metrics["dividend_income"] == legacy.report.metrics.dividend_income
    old_trade = legacy.report.trades[0]
    assert (metrics["gross_realized_pnl"], metrics["closed_trade_net_pnl"]) == (
        old_trade.gross_pnl,
        old_trade.net_pnl,
    )
    match = report.source.fifo_matches[0]
    assert (match.basis, match.proceeds, match.opening_fee + match.closing_fee) == (
        old_trade.cost_basis,
        old_trade.proceeds,
        old_trade.execution_costs,
    )
