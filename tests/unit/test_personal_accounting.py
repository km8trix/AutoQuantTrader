from __future__ import annotations

from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal, Inexact, Rounded, localcontext
from zoneinfo import ZoneInfo

import pytest

from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.accounting_contracts import (
    AccountingCommand,
    AccountingContext,
    AccountingState,
    ActivateCommitment,
    Commitment,
    ExecutionObservation,
    ExecutionPolicy,
    InstallCommitment,
    ModelDisposition,
    SettlementCalendar,
)
from packages.domain.corporate_action_ledger import (
    create_cash_dividend,
    create_dividend_payment,
    create_stock_split,
)
from packages.domain.decision import DecisionTrigger, DecisionTriggerKind
from packages.domain.ledger_reducer import CashFlowKind, create_cash_flow
from packages.domain.models import OrderIntent, Side
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    create_cancel_request,
    create_order_submission,
    reduce_order_lifecycle,
)
from packages.domain.personal_contracts import CausalMark, ReductionPoint
from packages.domain.settlement_ledger import create_settlement_instruction

D = Decimal
ET = ZoneInfo("America/New_York")
BASE = datetime(2024, 6, 3, 13, 0, tzinfo=UTC)
DATES = tuple(date(2024, 6, day) for day in (3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 17, 18, 19, 20))
POLICY = ExecutionPolicy(
    SettlementCalendar("synthetic-settlement", "1", DATES),
    model_id="synthetic-events-v1",
    slippage_bps=D(0),
    fee_per_share=D(0),
)


class Harness:
    """Explicit command driver; tests choose every instant and due confirmation."""

    def __init__(self, policy=POLICY, base=BASE, funding="1000"):
        self.port = PersonalAccounting()
        self.policy = policy
        self.state = AccountingState("synthetic-account")
        self.at = base
        self.sequence = 0
        self.frontier = 0
        self.last = self.project()
        if funding is not None:
            self.apply(
                create_cash_flow(
                    kind=CashFlowKind.CONTRIBUTION,
                    currency="USD",
                    amount=D(funding),
                    effective_at=base,
                    recorded_at=base,
                    external_reference="initial-funding",
                )
            )

    def context(self, *, at=None, approved=None, frontier=None):
        instant = self.at if at is None else at
        return AccountingContext(
            run_id="synthetic-run",
            point=ReductionPoint(
                self.frontier if frontier is None else frontier, self.sequence, instant, 2
            ),
            economic_at=instant,
            event_id=f"engine-{self.sequence}",
            expected_mark_session=instant.astimezone(ET).date(),
            instruments=(("spy", "SPY"),),
            approved_snapshot=approved,
            risk_policy_sha256=None if approved is None else "a" * 64,
        )

    def project(self):
        return self.port.project(state=self.state, context=self.context(), policy=self.policy)

    def apply(self, payload, *, at=None, frontier=None, command_id=None, approved=None):
        self.sequence += 1
        self.frontier = self.frontier + 1 if frontier is None else frontier
        self.at = self.at + timedelta(seconds=1) if at is None else at
        command = AccountingCommand(command_id or f"command-{self.sequence}", payload)
        self.last = self.port.advance(
            state=self.state,
            command=command,
            context=self.context(approved=approved),
            policy=self.policy,
        )
        self.state = self.last.state
        return self.last

    def install(self, name, quantity, price, fee_budget="0", side=Side.BUY):
        source = self.project().snapshot
        at = self.at + timedelta(seconds=1)
        expiry = at.replace(hour=21, minute=0, second=0, microsecond=0)
        intent = OrderIntent(
            intent_id=f"intent-{name}",
            intent_batch_id=f"batch-{name}",
            target_id=f"target-{name}",
            target_sha256="1" * 64,
            portfolio_snapshot_sha256="2" * 64,
            strategy_id="independent-oracle",
            strategy_version="1",
            strategy_configuration_sha256="3" * 64,
            decision_trigger=DecisionTrigger(
                DecisionTriggerKind.CLOCK, f"clock-{name}", "4" * 64, at
            ),
            instrument_id="spy",
            symbol="SPY",
            side=side,
            quantity=D(quantity),
            reference_price=D(price),
            decision_event_id=f"reference-{name}",
            reference_event_sha256="5" * 64,
            decision_event_time=at,
            created_at=at,
            expires_at=expiry,
        )
        submission = create_order_submission(
            intent=intent,
            risk_decision_id=f"risk-{name}",
            submission_attempt_id=f"attempt-{name}",
            submitted_at=at,
        )
        c = Commitment(
            commitment_id=f"commitment-{name}",
            intent_id=intent.intent_id,
            order_id=submission.order_id,
            instrument_id="spy",
            symbol="SPY",
            side=side,
            original_quantity=D(quantity),
            filled_quantity=D(0),
            remaining_quantity=D(quantity),
            reserved_cash=D(quantity) * D(price) + D(fee_budget)
            if side is Side.BUY
            else D(fee_budget),
            reserved_sell_quantity=D(quantity) if side is Side.SELL else D(0),
            approved_price=D(price),
            remaining_fee_budget=D(fee_budget),
            source_session=at.astimezone(ET).date(),
            execution_session=at.astimezone(ET).date(),
            created_sequence=self.sequence,
            not_before=at,
            expires_at=expiry,
            policy_sha256="a" * 64,
            snapshot_sha256=source.semantic_sha256,
        )
        result = self.apply(InstallCommitment(submission, c), at=at, approved=source)
        assert result.disposition == "applied", result.reasons
        result = self.apply(ActivateCommitment(c.commitment_id))
        assert result.disposition == "applied", result.reasons
        return c

    def order(self, c):
        return reduce_order_lifecycle(
            submission=next(s for s in self.state.submissions if s.order_id == c.order_id),
            broker_events=tuple(e for e in self.state.broker_events if e.order_id == c.order_id),
            cancel_request=next(
                (r for r in self.state.cancel_requests if r.order_id == c.order_id), None
            ),
        )

    def fill_event(self, c, quantity, price, fee, *, correction=False, at=None, received=None):
        order = self.order(c)
        instant = at or self.at + timedelta(seconds=1)
        previous = order.executions[0] if correction else None
        return BrokerOrderEvent(
            event_id=f"fill-{self.sequence + 1}",
            order_id=c.order_id,
            broker_order_id=order.broker_order_id,
            broker_sequence=order.last_broker_sequence + 1,
            occurred_at=instant,
            received_at=received or instant,
            kind=BrokerOrderEventKind.EXECUTION_CORRECTION
            if correction
            else BrokerOrderEventKind.EXECUTION,
            execution_id=previous.execution_id if previous else f"execution-{self.sequence + 1}",
            execution_revision=previous.revision + 1 if previous else 1,
            supersedes_event_id=previous.event_id if previous else None,
            quantity=D(quantity),
            price=D(price),
            fee=D(fee),
        )

    def fill(self, c, quantity, price, fee="0", *, correction=False, at=None, received=None):
        event = self.fill_event(
            c, quantity, price, fee, correction=correction, at=at, received=received
        )
        result = self.apply(event, at=event.received_at)
        assert result.disposition == "applied", result.reasons
        return result

    def mark(self, price, *, quality="current", session=None, at=None):
        instant = at or self.at + timedelta(seconds=1)
        return self.apply(
            CausalMark(
                mark_id=f"mark-{self.sequence + 1}",
                instrument_id="spy",
                symbol="SPY",
                price=D(price),
                session=session or instant.astimezone(ET).date(),
                economic_at=instant,
                knowledge_at=instant,
                source_sha256="6" * 64,
                quality=quality,
                basis="synthetic_boundary",
            ),
            at=instant,
        )

    def observe(self, price="100", budget=None, **kwargs):
        at = kwargs.pop("at", self.at + timedelta(seconds=1))
        observation = ExecutionObservation(
            observation_id=kwargs.pop("observation_id", f"observation-{self.sequence + 1}"),
            instrument_id="spy",
            symbol="SPY",
            session=at.astimezone(ET).date(),
            price=D(price),
            economic_at=kwargs.pop("economic_at", at),
            knowledge_at=at,
            model_id=self.policy.model_id,
            source_sha256="7" * 64,
            quantity_budget=None if budget is None else D(budget),
            basis="synthetic_price"
            if self.policy.model_id == "synthetic-events-v1"
            else "raw_open",
        )
        return self.apply(observation, at=at, **kwargs)


def test_e1_buy_sell_fees_settlement_and_unavailable_nav():
    h = Harness()
    buy = h.install("buy", "4", "100", "1")
    filled = h.fill(buy, "4", "100", "1")
    assert filled.snapshot.nav is None and filled.snapshot.positions[0].quantity == 4
    assert (
        filled.snapshot.trade_date_cash,
        filled.snapshot.settled_cash,
        filled.snapshot.trade_payable,
        filled.snapshot.available_cash,
    ) == (599, 1000, 401, 599)
    assert h.mark("100").snapshot.nav == 999
    due = filled.due_events[0]
    h.apply(due.command.payload, at=due.due_at)
    assert h.last.snapshot.settled_cash == 599
    assert h.last.snapshot.trade_payable == 0
    sell = h.install("sell", "2", "110", "1", Side.SELL)
    sold = h.fill(sell, "2", "110", "1")
    assert (
        sold.snapshot.trade_date_cash,
        sold.snapshot.settled_cash,
        sold.snapshot.trade_receivable,
        sold.snapshot.available_cash,
    ) == (818, 599, 219, 599)
    marked = h.mark("110")
    assert (
        marked.snapshot.nav,
        marked.snapshot.gross_realized_pnl,
        marked.snapshot.fees,
        marked.snapshot.unrealized_pnl,
    ) == (1038, 20, 2, 20)
    assert marked.snapshot.positions[0].cost_basis == 200
    due = sold.due_events[0]
    settled = h.apply(due.command.payload, at=due.due_at)
    assert settled.snapshot.settled_cash == settled.snapshot.available_cash == 818
    assert settled.snapshot.trade_receivable == 0
    assert h.mark("110").snapshot.nav == 1038


def test_e2_dividend_payment_is_one_income_and_combined_settled_cash():
    h = Harness()
    buy = h.install("buy", "4", "100")
    due = h.fill(buy, "4", "100").due_events[0]
    h.apply(due.command.payload, at=due.due_at)
    at = h.at + timedelta(seconds=1)
    dividend = create_cash_dividend(
        source_action_id="dividend",
        source_revision_id="r1",
        source_sha256="8" * 64,
        instrument_id="spy",
        symbol="SPY",
        currency="USD",
        amount_per_share=D(2),
        entitled_quantity=D(4),
        effective_at=at,
        payable_at=at + timedelta(minutes=1),
        recorded_at=at,
    )
    assert h.apply(dividend, at=at).disposition == "applied"
    accrued = h.mark("98")
    assert (
        accrued.snapshot.settled_cash,
        accrued.snapshot.dividend_receivable,
        accrued.snapshot.dividend_income,
        accrued.snapshot.nav,
    ) == (600, 8, 8, 1000)
    payment = create_dividend_payment(
        dividend,
        paid_at=dividend.payable_at,
        recorded_at=dividend.payable_at,
        external_reference="synthetic-payment",
    )
    paid = h.apply(payment, at=payment.paid_at)
    assert (
        paid.snapshot.trade_date_cash,
        paid.snapshot.settled_cash,
        paid.snapshot.dividend_receivable,
        paid.snapshot.dividend_income,
        paid.snapshot.nav,
    ) == (608, 608, 0, 8, 1000)
    duplicate = h.apply(payment)
    assert duplicate.disposition == "duplicate" and not duplicate.journal_entries


def test_e3_split_fifo_sale_and_match_fee_lineage():
    h = Harness()
    buy = h.install("buy", "4", "100")
    h.fill(buy, "4", "100")
    h.mark("100")
    at = h.at + timedelta(seconds=1)
    split = create_stock_split(
        source_action_id="split",
        source_revision_id="r1",
        source_sha256="9" * 64,
        instrument_id="spy",
        symbol="SPY",
        numerator=D(2),
        denominator=D(1),
        entitled_quantity=D(4),
        effective_at=at,
        recorded_at=at,
    )
    changed = h.apply(split, at=at)
    assert changed.snapshot.nav is None and changed.snapshot.last_known_nav is None
    assert changed.snapshot.positions[0].quantity == 8
    assert h.mark("50").snapshot.nav == 1000
    sell = h.install("sell", "3", "55", "1", Side.SELL)
    h.fill(sell, "3", "55", "1")
    final = h.mark("55")
    assert (
        final.snapshot.trade_date_cash,
        final.snapshot.positions[0].quantity,
        final.snapshot.positions[0].cost_basis,
        final.snapshot.nav,
    ) == (764, 5, 250, 1039)
    match = final.fifo_matches[0]
    assert (match.quantity, match.basis, match.proceeds, match.closing_fee) == (3, 150, 165, 1)
    assert match.split_ids == (split.split_id,) and match.group_complete


def test_e6_correction_duplicate_bust_preserves_effective_heads_and_points():
    h = Harness()
    c = h.install("buy", "4", "100", "2")
    original = h.fill(c, "4", "100", "1")
    original_time = original.executions[0].economic_at
    revised = h.fill(c, "4", "101", "2", correction=True)
    assert (revised.snapshot.trade_date_cash, revised.snapshot.fees) == (594, 2)
    assert h.mark("101").snapshot.nav == 998
    event = next(e for e in h.state.broker_events if e.event_id == revised.executions[0].fact_id)
    duplicate = h.apply(event)
    assert duplicate.disposition == "duplicate" and not duplicate.journal_entries
    busted = h.fill(c, "0", "101", "0", correction=True)
    assert (busted.snapshot.trade_date_cash, busted.snapshot.fees, busted.snapshot.nav) == (
        1000,
        0,
        1000,
    )
    assert busted.snapshot.available_cash == 594  # Opposing obligations are not settled cash.
    assert len(busted.executions) == 1 and busted.executions[0].revision == 3
    assert busted.executions[0].quantity == 0 and busted.executions[0].economic_at == original_time
    assert busted.executions[0].sequence == h.sequence
    assert busted.snapshot.commitments[0].state == "terminal"
    assert busted.snapshot.commitments[0].remaining_quantity == 0


def test_e7_partial_cancel_pending_late_fill_and_exact_reserve_overlap():
    h = Harness()
    c = h.install("buy", "5", "102", "3")
    first = h.fill(c, "2", "100", "1")
    assert (
        first.snapshot.trade_payable,
        first.snapshot.buy_reserve,
        first.snapshot.available_cash,
    ) == (201, 308, 491)
    cancel = create_cancel_request(
        h.order(c), requested_at=h.at + timedelta(seconds=1), reason="synthetic-owner-cancel"
    )
    pending = h.apply(cancel, at=cancel.requested_at)
    assert pending.snapshot.buy_reserve == 308
    assert not h.observe(budget="3").journal_entries
    late = h.fill(c, "1", "102", "1")
    assert (
        late.snapshot.trade_date_cash,
        late.snapshot.trade_payable,
        late.snapshot.buy_reserve,
        late.snapshot.available_cash,
    ) == (696, 304, 205, 491)
    assert h.mark("102").snapshot.nav == 1002
    order = h.order(c)
    at = h.at + timedelta(seconds=1)
    terminal = h.apply(
        BrokerOrderEvent(
            event_id="cancel-confirmed",
            order_id=c.order_id,
            broker_order_id=order.broker_order_id,
            broker_sequence=order.last_broker_sequence + 1,
            occurred_at=at,
            received_at=at,
            kind=BrokerOrderEventKind.CANCELED,
        ),
        at=at,
    )
    assert terminal.snapshot.commitments[0].remaining_quantity == 0
    assert terminal.snapshot.available_cash == 696
    assert h.order(c).remaining_quantity == 2  # Canonical arithmetic remains unchanged.


def test_shared_observation_budget_consumed_once_across_orders_and_commands():
    h = Harness()
    first = h.install("first", "2", "101")
    second = h.install("second", "2", "101")
    observed = h.observe(budget="3")
    assert observed.disposition == "applied" and len(observed.executions) == 2
    by_order = {e.order_id: e.quantity for e in observed.executions}
    assert by_order == {first.order_id: D(2), second.order_id: D(1)}
    source = h.state.observations[0]
    repeated = h.apply(source)
    assert repeated.disposition == "duplicate" and repeated.state == observed.state
    conflict = h.apply(replace(source, quantity_budget=D(4)))
    assert conflict.disposition == "rejected"
    assert h.project().executions == observed.executions


@pytest.mark.parametrize("same_frontier", (True, False))
def test_preexisting_activation_time_and_frontier_are_both_required(same_frontier):
    h = Harness()
    h.install("buy", "2", "101")
    activation = h.state.commitments[0]
    kwargs = (
        {"frontier": activation.activation_frontier}
        if same_frontier
        else {"economic_at": activation.activated_at}
    )
    rejected_source = h.observe(budget="2", **kwargs)
    assert rejected_source.disposition == "applied" and not rejected_source.executions
    assert len(h.state.observations) == 1
    assert h.apply(h.state.observations[0]).disposition == "duplicate"
    assert h.observe(budget="2").snapshot.positions[0].quantity == 2


@pytest.mark.parametrize("unresolved", ("unknown", "pending_cancel"))
def test_day_expiry_retains_unknown_and_cancel_pending_holds(unresolved):
    h = Harness()
    c = h.install("buy", "2", "101")
    if unresolved == "unknown":
        h.apply(ModelDisposition(c.commitment_id, "unknown", "synthetic-uncertain-response"))
    else:
        cancel = create_cancel_request(
            h.order(c), requested_at=h.at + timedelta(seconds=1), reason="synthetic-cancel"
        )
        h.apply(cancel, at=cancel.requested_at)
    rejected = h.apply(
        ModelDisposition(c.commitment_id, "day_expired", "model-close"), at=c.expires_at
    )
    assert rejected.disposition == "rejected" and rejected.snapshot.buy_reserve == 202
    terminal = h.apply(
        ModelDisposition(c.commitment_id, "resolved_no_remaining", "explicit-synthetic-resolution")
    )
    assert terminal.disposition == "applied" and terminal.snapshot.buy_reserve == 0


def test_supported_expiry_releases_hold_but_late_execution_truth_still_posts():
    h = Harness()
    c = h.install("buy", "5", "102")
    expired = h.apply(
        ModelDisposition(c.commitment_id, "day_expired", "synthetic-close"), at=c.expires_at
    )
    assert expired.snapshot.buy_reserve == 0
    late = h.fill(c, "5", "300")
    assert late.disposition == "applied"
    assert late.snapshot.trade_date_cash == late.snapshot.available_cash == -500
    assert late.snapshot.halted and late.state.halted
    assert late.snapshot.positions[0].quantity == 5
    assert late.snapshot.commitments[0].remaining_quantity == 0


def test_gap_model_halts_without_erasing_hold_or_filling():
    h = Harness()
    h.install("buy", "2", "101")
    blocked = h.observe(price="200", budget="2")
    assert blocked.snapshot.halted and blocked.snapshot.buy_reserve == 202
    assert not blocked.executions and not blocked.journal_entries


def test_cashflow_sign_withdrawal_capacity_and_command_identity():
    h = Harness()
    h.install("buy", "2", "100")
    at = h.at + timedelta(seconds=1)
    withdrawal = create_cash_flow(
        kind=CashFlowKind.WITHDRAWAL,
        currency="USD",
        amount=D(801),
        effective_at=at,
        recorded_at=at,
        external_reference="withdrawal",
    )
    refused = h.apply(withdrawal, at=at)
    assert refused.disposition == "rejected" and refused.snapshot.trade_date_cash == 1000
    allowed = replace(withdrawal, amount=D(800))
    taken = h.apply(allowed, command_id="withdraw-once")
    assert (
        taken.snapshot.trade_date_cash,
        taken.snapshot.available_cash,
        taken.snapshot.net_external_flow,
    ) == (200, 0, 200)
    assert h.apply(allowed, command_id="withdraw-once").disposition == "duplicate"
    assert h.apply(withdrawal, command_id="withdraw-once").reasons == ("COMMAND_ID_CONFLICT",)


def test_current_session_quality_and_last_known_estimate_are_separate():
    h = Harness()
    c = h.install("buy", "4", "100")
    h.fill(c, "4", "100")
    current = h.mark("100")
    assert current.snapshot.nav == 1000 and current.snapshot.last_known_nav is None
    stale = h.mark("101", session=date(2024, 5, 31))
    assert stale.snapshot.nav is None and stale.snapshot.market_value is None
    assert stale.snapshot.last_known_nav == 1004 and stale.snapshot.positions[0].quantity == 4
    unknown = h.mark("102", quality="unavailable")
    assert unknown.snapshot.nav is None and unknown.snapshot.last_known_nav == 1004
    assert h.mark("103").snapshot.nav == 1012


@pytest.mark.parametrize(
    ("trade", "dates", "expected"),
    (
        (
            date(2017, 9, 1),
            (date(2017, 9, 1), date(2017, 9, 5), date(2017, 9, 6), date(2017, 9, 7)),
            date(2017, 9, 7),
        ),
        (
            date(2017, 9, 5),
            (date(2017, 9, 5), date(2017, 9, 6), date(2017, 9, 7)),
            date(2017, 9, 7),
        ),
        (
            date(2024, 5, 24),
            (date(2024, 5, 24), date(2024, 5, 28), date(2024, 5, 29)),
            date(2024, 5, 29),
        ),
        (date(2024, 5, 28), (date(2024, 5, 28), date(2024, 5, 29)), date(2024, 5, 29)),
    ),
)
def test_dated_settlement_uses_explicit_business_dates(trade, dates, expected):
    policy = replace(
        POLICY, settlement_calendar=SettlementCalendar("synthetic-boundary", "1", dates)
    )
    base = datetime.combine(trade, datetime.min.time(), UTC).replace(hour=13)
    h = Harness(policy, base=base)
    c = h.install("buy", "1", "100")
    result = h.fill(c, "1", "100")
    due = result.due_events[0]
    assert due.due_at.astimezone(ET).date() == expected
    assert (due.due_at.astimezone(ET).hour, due.due_at.astimezone(ET).minute) == (9, 30)
    assert result.snapshot.settled_cash == 1000 and result.snapshot.trade_payable == 100


def test_correction_schedule_uses_receipt_date_and_explicit_instruction_precedence():
    h = Harness()
    c = h.install("buy", "2", "100")
    h.fill(c, "2", "100")
    received = datetime(2024, 6, 5, 15, tzinfo=UTC)
    correction = h.fill_event(
        c, "2", "101", "0", correction=True, at=h.at + timedelta(seconds=1), received=received
    )
    result = h.apply(correction, at=received)
    assert result.disposition == "applied"
    assert result.due_events[0].due_at == datetime(2024, 6, 6, 13, 30, tzinfo=UTC)
    event = h.fill_event(c, "2", "102", "0", correction=True)
    explicit = create_settlement_instruction(
        event,
        contractual_settlement_at=datetime(2024, 6, 7, 13, 30, tzinfo=UTC),
        recorded_at=event.received_at,
        external_reference="explicit-oracle-instruction",
    )
    pending = h.apply(explicit, at=event.received_at)
    assert pending.disposition == "applied" and not pending.journal_entries
    bound = h.apply(event, at=event.received_at)
    assert (
        bound.disposition == "applied"
        and bound.due_events[0].due_at == explicit.contractual_settlement_at
    )
    assert explicit in bound.state.settlement_instructions
    conflict = h.apply(
        replace(explicit, contractual_settlement_at=datetime(2024, 6, 10, 13, 30, tzinfo=UTC))
    )
    assert conflict.disposition == "rejected"


def test_calendar_exhaustion_rejects_fill_without_publishing_partial_economics():
    policy = replace(
        POLICY, settlement_calendar=SettlementCalendar("short", "1", (date(2024, 6, 3),))
    )
    h = Harness(policy)
    c = h.install("buy", "1", "100")
    event = h.fill_event(c, "1", "100", "0")
    before = h.state
    result = h.apply(event, at=event.received_at)
    assert result.disposition == "rejected" and "coverage exhausted" in result.reasons[0]
    assert result.state == before and not result.executions and not result.journal_entries
    assert result.snapshot.buy_reserve == 100
    # The incoming immutable event is not yet admitted. A retains it with this
    # rejected scope in its input/trace; no previously admitted raw fact is removed.
    assert all(event in result.state.broker_events for event in before.broker_events)


def test_policy_binding_and_ambient_decimal_precision():
    policy = replace(POLICY, slippage_bps=D(5), fee_per_share=D("0.01"))
    outputs = []
    for precision in (4, 40, 2):
        h = Harness(policy)
        h.install("buy", "1", "101", "0.01")
        with localcontext() as context:
            context.prec = precision
            if precision == 2:
                context.Emin, context.Emax = -1, 1
                context.traps[Inexact] = context.traps[Rounded] = True
            outputs.append(h.observe("100.0000000001", "1"))
    assert outputs[0] == outputs[1] == outputs[2]
    assert outputs[0].executions[0].price == D("100.0500000002")
    assert outputs[0].executions[0].fee == D("0.01")
    with pytest.raises(ValueError, match="policy binding differs"):
        h.port.project(
            state=h.state, context=h.context(), policy=replace(policy, fee_per_share=D("0.02"))
        )


def test_install_requires_exact_source_snapshot_and_combined_current_capacity():
    h = Harness()
    c = h.install("first", "6", "100")
    source = h.project().snapshot
    original = next(s for s in h.state.submissions if s.order_id == c.order_id)
    bad = InstallCommitment(original, replace(c, snapshot_sha256="b" * 64))
    assert h.apply(bad, approved=source).disposition == "rejected"
    with pytest.raises(AssertionError, match="current available cash"):
        h.install("second", "5", "100")


def test_nonterminal_quantity_correction_retains_unknown_hold_without_reopening():
    h = Harness()
    c = h.install("buy", "5", "102", "3")
    h.fill(c, "2", "100", "1")
    corrected = h.fill(c, "1", "100", "0.5", correction=True)
    commitment = corrected.snapshot.commitments[0]
    assert commitment.state == "unknown" and commitment.remaining_quantity == 4
    assert corrected.snapshot.halted
    assert len(h.observe(budget="5").executions) == 1


def test_e8_fractional_split_and_ambiguous_entitlement_reject_affected_command():
    h = Harness()
    c = h.install("first", "1", "100")
    h.fill(c, "1", "100")
    other = h.install("second", "1", "100")
    h.fill(other, "1", "100")
    at = h.at + timedelta(seconds=1)
    action = create_stock_split(
        source_action_id="fractional",
        source_revision_id="r1",
        source_sha256="9" * 64,
        instrument_id="spy",
        symbol="SPY",
        numerator=D(3),
        denominator=D(2),
        entitled_quantity=D(2),
        effective_at=at,
        recorded_at=at,
    )
    rejected = h.apply(action, at=at)
    assert rejected.disposition == "rejected" and "fractional FIFO lot" in rejected.reasons[0]
    action = replace(action, numerator=D(2), denominator=D(1))
    assert h.apply(action).disposition == "applied"
    dividend = create_cash_dividend(
        source_action_id="ambiguous-dividend",
        source_revision_id="ambiguous-dividend-r1",
        source_sha256="8" * 64,
        instrument_id="spy",
        symbol="SPY",
        currency="USD",
        amount_per_share=D(1),
        entitled_quantity=D(2),
        effective_at=at,
        payable_at=h.at + timedelta(minutes=1),
        recorded_at=at,
    )
    ambiguous = h.apply(dividend)
    assert ambiguous.disposition == "rejected" and "ambiguous" in ambiguous.reasons[0]


@pytest.mark.parametrize("side", (Side.BUY, Side.SELL))
def test_split_with_unresolved_order_rejects_without_adjusting_orders(side):
    h = Harness()
    opening = h.install("opening", "2", "100")
    h.fill(opening, "2", "100")
    h.install("pending", "1", "100", side=side)
    at = h.at + timedelta(seconds=1)
    action = create_stock_split(
        source_action_id="split-with-pending",
        source_revision_id="split-with-pending-r1",
        source_sha256="9" * 64,
        instrument_id="spy",
        symbol="SPY",
        numerator=D(2),
        denominator=D(1),
        entitled_quantity=D(2),
        effective_at=at,
        recorded_at=at,
    )
    before = h.state
    result = h.apply(action, at=at)
    assert result.disposition == "rejected"
    assert "unresolved order commitment" in result.reasons[0]
    assert result.state == before and result.snapshot.positions[0].quantity == 2


def test_initial_oracle_state_requires_coverage_and_causal_observations():
    h = Harness()
    h.install("buy", "2", "100")
    for changes in ({"commitments": ()}, {"submissions": ()}, {"event_points": ()}):
        with pytest.raises(ValueError):
            h.port.project(state=replace(h.state, **changes), context=h.context(), policy=h.policy)
    future = h.at + timedelta(days=1)
    observation = ExecutionObservation(
        "future",
        "spy",
        "SPY",
        future.astimezone(ET).date(),
        D(100),
        future,
        future,
        h.policy.model_id,
        "7" * 64,
        basis="synthetic_price",
    )
    with pytest.raises(ValueError, match="outside causal scope"):
        h.port.project(
            state=replace(h.state, observations=(observation,)),
            context=h.context(),
            policy=h.policy,
        )
    unscoped = replace(observation, instrument_id="unscoped", economic_at=h.at, knowledge_at=h.at)
    with pytest.raises(ValueError, match="outside causal scope"):
        h.port.project(
            state=replace(h.state, observations=(unscoped,)), context=h.context(), policy=h.policy
        )


def test_independent_same_time_flow_permutation_has_identical_final_state():
    flows = tuple(
        create_cash_flow(
            kind=CashFlowKind.CONTRIBUTION,
            currency="USD",
            amount=D(amount),
            effective_at=BASE,
            recorded_at=BASE,
            external_reference=f"synthetic-flow-{amount}",
        )
        for amount in ("100", "200")
    )
    results = []
    for sequence in (flows, tuple(reversed(flows))):
        h = Harness(funding=None)
        for flow in sequence:
            h.apply(flow, at=BASE, command_id=flow.cash_flow_id)
        results.append(h.project())
    assert results[0] == results[1]
    assert results[0].snapshot.nav == 300


def test_sell_slippage_rounds_adversely_down_to_price_quantum():
    policy = replace(POLICY, slippage_bps=D(5), fee_per_share=D("0.01"))
    h = Harness(policy)
    opening = h.install("opening", "1", "100", "0.01")
    h.fill(opening, "1", "100", "0.01")
    h.install("closing", "1", "100", "0.01", Side.SELL)
    sold = h.observe("100.0000000001", "1")
    assert sold.disposition == "applied"
    sell = next(e for e in sold.executions if e.side is Side.SELL)
    assert sell.price == D("99.9500000000") and sell.fee == D("0.01")


def test_receipt_points_stay_original_after_duplicate_under_later_context():
    h = Harness()
    c = h.install("buy", "2", "100")
    filled = h.fill(c, "2", "100")
    event = next(e for e in h.state.broker_events if e.event_id == filled.executions[0].fact_id)
    point = dict(h.state.event_points)[event.event_id]
    later = h.apply(event, at=h.at + timedelta(hours=1))
    assert later.disposition == "duplicate"
    assert dict(later.state.event_points)[event.event_id] == point
    assert later.executions[0].sequence == point.reduction_sequence
    assert later.executions == filled.executions


def test_settlement_timezone_release_tracks_dst_from_pinned_business_dates():
    dates = (date(2024, 11, 1), date(2024, 11, 4))
    policy = replace(POLICY, settlement_calendar=SettlementCalendar("synthetic-dst", "1", dates))
    h = Harness(policy, base=datetime(2024, 11, 1, 13, tzinfo=UTC))
    c = h.install("buy", "1", "100")
    filled = h.fill(c, "1", "100")
    assert filled.due_events[0].due_at == datetime(2024, 11, 4, 14, 30, tzinfo=UTC)
