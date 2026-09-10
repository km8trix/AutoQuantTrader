"""One-command offline accounting; the application engine owns all scheduling."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, date, datetime, time
from decimal import (
    ROUND_CEILING,
    ROUND_FLOOR,
    Context,
    Decimal,
    DivisionByZero,
    InvalidOperation,
    Overflow,
    localcontext,
)
from zoneinfo import ZoneInfo

from packages.domain.account_projection import project_unvalued_fifo_account
from packages.domain.accounting_contracts import (
    AccountingCommand,
    AccountingContext,
    AccountingState,
    AccountingTransition,
    AccountSnapshot,
    ActivateCommitment,
    Commitment,
    ControlCommand,
    DueAccountingEvent,
    ExecutionObservation,
    ExecutionPolicy,
    ExecutionRow,
    FifoMatchRow,
    InstallCommitment,
    ModelDisposition,
    PositionState,
)
from packages.domain.corporate_action_ledger import (
    CashDividendAccrual,
    CashDividendPayment,
    StockSplitAction,
)
from packages.domain.decimal_math import (
    deterministic_decimal_divide as divide,
)
from packages.domain.decimal_math import (
    exact_decimal_add as add,
)
from packages.domain.decimal_math import (
    exact_decimal_multiply as multiply,
)
from packages.domain.decimal_math import (
    exact_decimal_subtract as subtract,
)
from packages.domain.decimal_math import (
    exact_decimal_sum as total,
)
from packages.domain.identifiers import canonical_id
from packages.domain.ledger_reducer import CashFlowKind, LedgerCashFlow
from packages.domain.models import Side
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    CanonicalOrderState,
    CanonicalOrderStatus,
    OrderCancelRequest,
    reduce_order_lifecycle,
)
from packages.domain.personal_contracts import CausalMark, content_digest, require_text
from packages.domain.settlement_ledger import (
    ExecutionSettlementConfirmation,
    ExecutionSettlementInstruction,
    create_settlement_confirmation,
    create_settlement_instruction,
    reduce_settlement_ledger,
)

_ZERO = Decimal(0)
_EASTERN = ZoneInfo("America/New_York")
_PRICE_CONTEXT = Context(
    prec=64, Emin=-63, Emax=63, traps=[InvalidOperation, DivisionByZero, Overflow]
)


def _append[T](values: tuple[T, ...], value: T, identity: str) -> tuple[T, ...]:
    key = getattr(value, identity)
    for previous in values:
        if getattr(previous, identity) == key:
            if previous != value:
                raise ValueError(f"conflicting {identity}")
            return values
    return tuple(sorted((*values, value), key=lambda item: getattr(item, identity)))


def _orders(state: AccountingState) -> tuple[CanonicalOrderState, ...]:
    by_order = {submission.order_id: submission for submission in state.submissions}
    if len(by_order) != len(state.submissions):
        raise ValueError("duplicate submission identity")
    if any(event.order_id not in by_order for event in state.broker_events):
        raise ValueError("broker fact has no installed submission")
    cancels = {request.order_id: request for request in state.cancel_requests}
    if len(cancels) != len(state.cancel_requests) or set(cancels) - set(by_order):
        raise ValueError("unsupported cancel request coverage")
    return tuple(
        reduce_order_lifecycle(
            submission=submission,
            broker_events=tuple(e for e in state.broker_events if e.order_id == order_id),
            cancel_request=cancels.get(order_id),
        )
        for order_id, submission in sorted(by_order.items())
    )


def _commitment(state: AccountingState, commitment_id: str) -> Commitment:
    for value in state.commitments:
        if value.commitment_id == commitment_id:
            return value
    raise ValueError("unknown commitment")


def _replace_commitment(state: AccountingState, value: Commitment) -> AccountingState:
    return replace(
        state,
        commitments=tuple(
            value if item.commitment_id == value.commitment_id else item
            for item in state.commitments
        ),
    )


def _cash(event: BrokerOrderEvent, side: Side) -> Decimal:
    assert event.quantity is not None and event.price is not None and event.fee is not None
    notional = multiply(event.quantity, event.price)
    return (
        add(notional, event.fee).copy_negate()
        if side is Side.BUY
        else subtract(notional, event.fee)
    )


def _settlement_at(event: BrokerOrderEvent, policy: ExecutionPolicy) -> datetime:
    instant = (
        event.received_at
        if event.kind is BrokerOrderEventKind.EXECUTION_CORRECTION
        else event.occurred_at
    )
    trade_date = instant.astimezone(_EASTERN).date()
    dates = policy.settlement_calendar.business_dates
    if trade_date < dates[0] or trade_date > dates[-1]:
        raise ValueError("settlement calendar lacks trade-date coverage")
    lag = 3 if trade_date < date(2017, 9, 5) else 2 if trade_date < date(2024, 5, 28) else 1
    following = tuple(day for day in dates if day > trade_date)
    if len(following) < lag:
        raise ValueError("settlement calendar coverage exhausted")
    return datetime.combine(following[lag - 1], time(9, 30), _EASTERN).astimezone(UTC)


def _price(reference: Decimal, side: Side, policy: ExecutionPolicy) -> Decimal:
    adverse = divide(multiply(reference, policy.slippage_bps), Decimal(10000))
    value = add(reference, adverse) if side is Side.BUY else subtract(reference, adverse)
    with localcontext(_PRICE_CONTEXT) as context:
        context.rounding = ROUND_CEILING if side is Side.BUY else ROUND_FLOOR
        value = value.quantize(policy.price_quantum)
    if value <= 0:
        raise ValueError("modeled execution price is not positive")
    return value


def _validate_context(state: AccountingState, context: AccountingContext) -> None:
    require_text(state.account_id, "account ID")
    require_text(context.run_id, "run ID")
    require_text(context.event_id, "event ID")
    if context.economic_at > context.point.knowledge_at:
        raise ValueError("context contains future economic time")
    allowed = dict(context.instruments)
    if len(allowed) != len(context.instruments) or len(set(allowed.values())) != len(allowed):
        raise ValueError("instrument scope is not unique")
    scoped: tuple[Commitment | CausalMark | StockSplitAction | CashDividendAccrual, ...] = (
        *state.commitments,
        *state.marks,
        *state.stock_splits,
        *state.cash_dividends,
    )
    for value in scoped:
        if allowed.get(value.instrument_id) != value.symbol:
            raise ValueError("account fact falls outside instrument scope")
    ids = tuple(c.commitment_id for c in state.commitments)
    order_ids = tuple(c.order_id for c in state.commitments)
    if len(ids) != len(set(ids)) or len(order_ids) != len(set(order_ids)):
        raise ValueError("commitments repeat one reservation identity")
    receipts: tuple[BrokerOrderEvent | CausalMark, ...] = (*state.broker_events, *state.marks)
    for receipt in receipts:
        recorded = (
            receipt.received_at if isinstance(receipt, BrokerOrderEvent) else receipt.knowledge_at
        )
        if recorded > context.point.knowledge_at:
            raise ValueError("account contains future receipt evidence")
    event_points = dict(state.event_points)
    if len(event_points) != len(state.event_points) or set(event_points) != {
        event.event_id for event in state.broker_events
    }:
        raise ValueError("broker fact reduction-point coverage differs")
    for event in state.broker_events:
        point = event_points[event.event_id]
        if point.knowledge_at < event.received_at or (
            point.knowledge_at > context.point.knowledge_at
            or point.reduction_sequence > context.point.reduction_sequence
            or point.frontier_sequence > context.point.frontier_sequence
        ):
            raise ValueError("broker fact reduction point is not causal")
    if len({o.observation_id for o in state.observations}) != len(state.observations):
        raise ValueError("execution observations repeat a source identity")
    for observation in state.observations:
        if (
            observation.knowledge_at > context.point.knowledge_at
            or allowed.get(observation.instrument_id) != observation.symbol
        ):
            raise ValueError("execution observation is outside causal scope")
    for instruction in state.settlement_instructions:
        if instruction.recorded_at > context.point.knowledge_at:
            raise ValueError("future settlement instruction receipt")


class PersonalAccounting:
    """Pure historical simulation adapter; no provider or order authority."""

    def project(
        self, *, state: AccountingState, context: AccountingContext, policy: ExecutionPolicy
    ) -> AccountingTransition:
        _validate_context(state, context)
        if state.execution_policy_sha256 not in (None, policy.semantic_sha256):
            raise ValueError("account execution policy binding differs")
        orders = _orders(state)
        by_order = {order.submission.order_id: order for order in orders}
        if set(by_order) != {c.order_id for c in state.commitments}:
            raise ValueError("submission/commitment coverage differs")
        for c in state.commitments:
            canonical_order = by_order[c.order_id]
            intent = canonical_order.submission.intent
            if (
                c.intent_id,
                c.instrument_id,
                c.symbol,
                c.side,
                c.original_quantity,
                c.filled_quantity,
            ) != (
                intent.intent_id,
                intent.instrument_id,
                intent.symbol,
                intent.side,
                intent.quantity,
                canonical_order.filled_quantity,
            ):
                raise ValueError("commitment differs from canonical order facts")
            remainder = (
                _ZERO if c.state == "terminal" else subtract(c.original_quantity, c.filled_quantity)
            )
            reserve = (
                add(multiply(remainder, c.approved_price), c.remaining_fee_budget)
                if c.side is Side.BUY
                else c.remaining_fee_budget
            )
            if (
                c.remaining_quantity != remainder
                or c.reserved_cash != reserve
                or c.reserved_sell_quantity != (remainder if c.side is Side.SELL else _ZERO)
            ):
                raise ValueError("commitment capacity differs from its remaining quantity")
            if c.state == "terminal" and c.remaining_fee_budget:
                raise ValueError("terminal commitment retains a fee budget")
        facts = project_unvalued_fifo_account(
            account_id=state.account_id,
            order_states=orders,
            cash_flows=state.cash_flows,
            stock_splits=state.stock_splits,
            cash_dividends=state.cash_dividends,
            dividend_payments=state.dividend_payments,
            as_of=context.point.knowledge_at,
        )
        event_ids = {event.event_id for event in state.broker_events}
        instructions = tuple(
            item for item in state.settlement_instructions if item.execution_event_id in event_ids
        )
        settlement = reduce_settlement_ledger(
            account_id=state.account_id,
            order_states=orders,
            cash_flows=state.cash_flows,
            instructions=instructions,
            confirmations=state.settlement_confirmations,
        )
        if settlement.as_of is not None and settlement.as_of > context.point.knowledge_at:
            raise ValueError("future settlement evidence")
        entries = tuple(
            sorted(
                (
                    *facts.ledger.entries,
                    *facts.corporate_action_ledger.corporate_action_entries,
                    *settlement.settlement_entries,
                ),
                key=lambda entry: (entry.recorded_at, entry.effective_at, entry.entry_id),
            )
        )
        if len({entry.entry_id for entry in entries}) != len(entries):
            raise ValueError("economic journal repeats an entry")
        paid = {payment.dividend_id for payment in state.dividend_payments}
        positions = tuple(
            PositionState(
                instrument_id=p.instrument_id,
                symbol=p.symbol,
                quantity=p.quantity,
                cost_basis=p.cost_basis,
                lots=p.open_lots,
                gross_realized_pnl=p.realized_pnl_before_fees,
                fees=p.execution_fees,
                dividend_income=p.dividend_income,
                dividend_receivable=total(
                    d.amount
                    for d in state.cash_dividends
                    if d.instrument_id == p.instrument_id and d.dividend_id not in paid
                ),
            )
            for p in facts.positions
        )
        settled = add(settlement.settled_cash, subtract(facts.cash, settlement.trade_date_cash))
        buy_reserve = total(c.reserved_cash for c in state.commitments if c.side is Side.BUY)
        sell_reserve = total(c.reserved_cash for c in state.commitments if c.side is Side.SELL)
        available = subtract(
            subtract(subtract(settled, settlement.payables), buy_reserve), sell_reserve
        )
        selected: dict[str, CausalMark] = {}
        estimates: dict[str, CausalMark] = {}
        for mark in sorted(state.marks, key=lambda m: (m.economic_at, m.knowledge_at, m.mark_id)):
            selected[mark.instrument_id] = mark
            if mark.quality != "unavailable":
                estimates[mark.instrument_id] = mark
        reasons: list[str] = []
        market = _ZERO
        estimated_market = _ZERO
        estimate_complete = True
        for position in facts.positions:
            if not position.quantity:
                continue
            current_mark = selected.get(position.instrument_id)
            if current_mark is None:
                reasons.append(f"MISSING_MARK:{position.instrument_id}")
            elif (
                current_mark.quality != "current"
                or current_mark.session != context.expected_mark_session
            ):
                reasons.append(f"NONCURRENT_MARK:{position.instrument_id}")
            elif (
                position.latest_split_at is not None
                and current_mark.economic_at <= position.latest_split_at
            ):
                reasons.append(f"POST_SPLIT_MARK_REQUIRED:{position.instrument_id}")
            else:
                market = add(market, multiply(position.quantity, current_mark.price))
            estimate = estimates.get(position.instrument_id)
            if estimate is None or (
                position.latest_split_at is not None
                and estimate.economic_at <= position.latest_split_at
            ):
                estimate_complete = False
            else:
                estimated_market = add(
                    estimated_market, multiply(position.quantity, estimate.price)
                )
        nav = None if reasons else add(add(facts.cash, facts.dividend_receivable), market)
        last_known = (
            add(add(facts.cash, facts.dividend_receivable), estimated_market)
            if reasons and estimate_complete
            else None
        )
        unknown = any(c.state == "unknown" for c in state.commitments)
        snapshot = AccountSnapshot(
            account_id=state.account_id,
            point=context.point,
            state_sha256=state.semantic_sha256,
            positions=positions,
            commitments=state.commitments,
            marks=tuple(selected[key] for key in sorted(selected)),
            trade_date_cash=facts.cash,
            settled_cash=settled,
            trade_receivable=settlement.receivables,
            trade_payable=settlement.payables,
            dividend_receivable=facts.dividend_receivable,
            buy_reserve=buy_reserve,
            sell_fee_reserve=sell_reserve,
            available_cash=available,
            market_value=None if reasons else market,
            nav=nav,
            gross_realized_pnl=facts.realized_pnl_before_fees,
            fees=facts.execution_fees,
            dividend_income=facts.dividend_income,
            unrealized_pnl=None
            if reasons
            else subtract(market, total(p.cost_basis for p in positions)),
            net_external_flow=total(
                flow.amount if flow.kind is CashFlowKind.CONTRIBUTION else flow.amount.copy_negate()
                for flow in state.cash_flows
            ),
            journal_sha256=content_digest(tuple(entry.semantic_sha256 for entry in entries)),
            order_sha256=content_digest(tuple(order.semantic_sha256 for order in orders)),
            valuation_reasons=tuple(reasons),
            last_known_nav=last_known,
            halted=state.halted or available < 0 or settled < 0 or unknown,
        )
        by_commitment = {c.order_id: c for c in state.commitments}
        by_event = {event.event_id: event for event in state.broker_events}
        event_points = dict(state.event_points)
        executions = tuple(
            ExecutionRow(
                execution_id=e.execution_id,
                revision=e.revision,
                fact_id=e.event_id,
                fact_sha256=e.event_sha256,
                order_id=e.order_id,
                intent_id=by_order[e.order_id].submission.intent.intent_id,
                instrument_id=e.instrument_id,
                symbol=e.symbol,
                side=e.side,
                quantity=e.quantity,
                price=e.price,
                fee=e.fee,
                economic_at=e.occurred_at,
                knowledge_at=e.current_received_at,
                sequence=event_points[e.event_id].reduction_sequence,
                model_id=policy.model_id
                if by_event[e.event_id].reason == "modeled-execution"
                else "synthetic-authoritative-fact-v1",
                supersedes_fact_id=by_event[e.event_id].supersedes_event_id,
            )
            for e in facts.executions
        )
        matches = tuple(
            FifoMatchRow(
                match_id=m.match_id,
                instrument_id=m.buy.instrument_id,
                opening_execution_id=m.buy.execution_id,
                opening_revision=m.buy.revision,
                closing_execution_id=m.sell.execution_id,
                closing_revision=m.sell.revision,
                opening_order_id=m.buy.order_id,
                closing_order_id=m.sell.order_id,
                quantity=m.quantity,
                basis=m.cost_basis,
                proceeds=m.proceeds,
                opening_fee=divide(
                    multiply(m.buy.fee, Decimal(m.buy_fee_weight[0])), Decimal(m.buy_fee_weight[1])
                ),
                closing_fee=divide(
                    multiply(m.sell.fee, Decimal(m.sell_fee_weight[0])),
                    Decimal(m.sell_fee_weight[1]),
                ),
                acquired_at=m.buy.occurred_at,
                disposed_at=m.sell.occurred_at,
                source_sha256=m.semantic_sha256,
                split_ids=m.split_ids,
                group_complete=by_commitment[m.sell.order_id].state == "terminal",
            )
            for m in facts.realized_matches
        )
        return AccountingTransition(
            disposition="applied",
            state=state,
            snapshot=snapshot,
            journal_entries=entries,
            executions=executions,
            fifo_matches=matches,
        )

    def advance(
        self,
        *,
        state: AccountingState,
        command: AccountingCommand,
        context: AccountingContext,
        policy: ExecutionPolicy,
    ) -> AccountingTransition:
        before = self.project(state=state, context=context, policy=policy)
        require_text(command.command_id, "command ID")
        known = dict(state.commands).get(command.command_id)
        if known is not None:
            if known != command.semantic_sha256:
                return replace(
                    before,
                    disposition="rejected",
                    journal_entries=(),
                    reasons=("COMMAND_ID_CONFLICT",),
                )
            return replace(before, disposition="duplicate", journal_entries=())
        try:
            updated, due, reasons = self._apply(state, command, context, policy, before)
            if updated == state:
                return replace(before, disposition="duplicate", journal_entries=(), reasons=reasons)
            updated = replace(
                updated,
                execution_policy_sha256=policy.semantic_sha256,
                commands=tuple(
                    sorted((*state.commands, (command.command_id, command.semantic_sha256)))
                ),
                revision=state.revision + 1,
            )
            after = self.project(state=updated, context=context, policy=policy)
            if after.snapshot.available_cash < 0 or after.snapshot.settled_cash < 0:
                updated = replace(updated, halted=True)
                after = self.project(state=updated, context=context, policy=policy)
                reasons = (*reasons, "NEGATIVE_CASH_CAPACITY")
            previous_ids = {entry.entry_id for entry in before.journal_entries}
            return replace(
                after,
                journal_entries=tuple(
                    e for e in after.journal_entries if e.entry_id not in previous_ids
                ),
                due_events=due,
                reasons=reasons,
            )
        except ValueError as error:
            return replace(
                before, disposition="rejected", journal_entries=(), reasons=(str(error),)
            )

    def _apply(
        self,
        state: AccountingState,
        command: AccountingCommand,
        context: AccountingContext,
        policy: ExecutionPolicy,
        before: AccountingTransition,
    ) -> tuple[AccountingState, tuple[DueAccountingEvent, ...], tuple[str, ...]]:
        payload = command.payload
        now = context.point.knowledge_at
        due: tuple[DueAccountingEvent, ...] = ()
        if isinstance(payload, InstallCommitment):
            c, submission = payload.commitment, payload.submission
            existing = next(
                (s for s in state.submissions if s.order_id == submission.order_id), None
            )
            if existing is not None:
                if existing == submission and _commitment(state, c.commitment_id) == c:
                    return state, (), ()
                raise ValueError("installed submission/commitment conflict")
            source = context.approved_snapshot
            if source is None or context.risk_policy_sha256 is None:
                raise ValueError("install requires exact risk source snapshot and policy")
            if (
                source.account_id != state.account_id
                or source.semantic_sha256 != c.snapshot_sha256
                or context.risk_policy_sha256 != c.policy_sha256
                or source.point.knowledge_at > now
                or source.point.reduction_sequence > context.point.reduction_sequence
                or source.point.frontier_sequence > context.point.frontier_sequence
            ):
                raise ValueError("install source snapshot/policy binding differs")
            intent = submission.intent
            if (
                (c.order_id, c.intent_id, c.instrument_id, c.symbol, c.side, c.original_quantity)
                != (
                    submission.order_id,
                    intent.intent_id,
                    intent.instrument_id,
                    intent.symbol,
                    intent.side,
                    intent.quantity,
                )
                or c.state != "approved_unsent"
                or c.filled_quantity != 0
                or c.remaining_quantity != c.original_quantity
                or c.approved_price <= 0
                or c.activated_at is not None
                or c.activation_sequence is not None
                or c.activation_frontier is not None
                or c.terminal_reason is not None
                or c.created_sequence > context.point.reduction_sequence
                or c.created_sequence < source.point.reduction_sequence
                or submission.submitted_at > now
                or c.expires_at <= now
            ):
                raise ValueError("submission and initial commitment do not bind")
            if before.snapshot.halted:
                raise ValueError("account is halted")
            expected_reserve = (
                add(multiply(c.remaining_quantity, c.approved_price), c.remaining_fee_budget)
                if c.side is Side.BUY
                else c.remaining_fee_budget
            )
            if c.reserved_cash != expected_reserve or c.reserved_sell_quantity != (
                c.remaining_quantity if c.side is Side.SELL else _ZERO
            ):
                raise ValueError("commitment reserve formula differs")
            if c.remaining_fee_budget < multiply(c.remaining_quantity, policy.fee_per_share):
                raise ValueError("commitment fee budget is below modeled fees")
            if c.reserved_cash > before.snapshot.available_cash:
                raise ValueError("commitment exceeds current available cash")
            if c.side is Side.SELL:
                held = total(
                    p.quantity
                    for p in before.snapshot.positions
                    if p.instrument_id == c.instrument_id
                )
                reserved = total(
                    p.reserved_sell_quantity
                    for p in state.commitments
                    if p.instrument_id == c.instrument_id
                )
                if c.remaining_quantity > subtract(held, reserved):
                    raise ValueError("commitment exceeds unreserved long shares")
            if any(
                p.intent_id == c.intent_id or p.commitment_id == c.commitment_id
                for p in state.commitments
            ):
                raise ValueError("commitment repeats an intent or reservation")
            state = replace(
                state,
                submissions=_append(state.submissions, submission, "order_id"),
                commitments=_append(state.commitments, c, "commitment_id"),
            )
        elif isinstance(payload, ActivateCommitment):
            c = _commitment(state, payload.commitment_id)
            if c.state != "approved_unsent" or before.snapshot.halted or now >= c.expires_at:
                raise ValueError("commitment cannot activate in current state")
            if context.point.reduction_sequence <= c.created_sequence:
                raise ValueError("activation must follow creation sequence")
            state = _replace_commitment(
                state,
                replace(
                    c,
                    state="active",
                    activated_at=now,
                    activation_sequence=context.point.reduction_sequence,
                    activation_frontier=context.point.frontier_sequence,
                ),
            )
            accepted = BrokerOrderEvent(
                event_id=canonical_id("model-accepted", c.order_id),
                order_id=c.order_id,
                broker_order_id=canonical_id("model-order", c.order_id),
                broker_sequence=1,
                occurred_at=now,
                received_at=now,
                kind=BrokerOrderEventKind.ACCEPTED,
            )
            state, due = self._event(state, accepted, context, policy)
        elif isinstance(payload, ExecutionObservation):
            return self._observe(state, payload, context, policy)
        elif isinstance(payload, BrokerOrderEvent):
            state, due = self._event(state, payload, context, policy)
        elif isinstance(payload, OrderCancelRequest):
            if payload.requested_at > now:
                raise ValueError("future cancel request")
            requests = _append(state.cancel_requests, payload, "cancel_request_id")
            if requests == state.cancel_requests:
                return state, (), ()
            cancel_commitment = next(
                (c for c in state.commitments if c.order_id == payload.order_id), None
            )
            if cancel_commitment is None or cancel_commitment.state == "terminal":
                raise ValueError("cancel requires an unresolved installed commitment")
            state = _replace_commitment(
                replace(state, cancel_requests=requests),
                replace(cancel_commitment, state="pending_cancel"),
            )
        elif isinstance(payload, LedgerCashFlow):
            if payload.recorded_at > now or payload.effective_at > context.economic_at:
                raise ValueError("future cash flow")
            flows = _append(state.cash_flows, payload, "cash_flow_id")
            if flows == state.cash_flows:
                return state, (), ()
            if payload.currency != "USD":
                raise ValueError("unsupported cash-flow currency")
            if (
                payload.kind is CashFlowKind.WITHDRAWAL
                and payload.amount > before.snapshot.available_cash
            ):
                raise ValueError("withdrawal exceeds available cash after commitments")
            state = replace(state, cash_flows=flows)
        elif isinstance(payload, (StockSplitAction, CashDividendAccrual, CashDividendPayment)):
            if payload.recorded_at > now:
                raise ValueError("future corporate-action receipt")
            if isinstance(payload, StockSplitAction):
                if any(
                    c.instrument_id == payload.instrument_id and c.state != "terminal"
                    for c in state.commitments
                ):
                    raise ValueError("unsupported stock split with unresolved order commitment")
                state = replace(
                    state, stock_splits=_append(state.stock_splits, payload, "split_id")
                )
            elif isinstance(payload, CashDividendAccrual):
                state = replace(
                    state, cash_dividends=_append(state.cash_dividends, payload, "dividend_id")
                )
            else:
                state = replace(
                    state, dividend_payments=_append(state.dividend_payments, payload, "payment_id")
                )
        elif isinstance(payload, ExecutionSettlementInstruction):
            if payload.recorded_at > now:
                raise ValueError("future settlement instruction receipt")
            for prior_instruction in state.settlement_instructions:
                if prior_instruction.execution_event_id == payload.execution_event_id:
                    if prior_instruction != payload:
                        raise ValueError("settlement instruction conflicts with prior binding")
                    return state, (), ()
            state = replace(
                state,
                settlement_instructions=_append(
                    state.settlement_instructions, payload, "instruction_id"
                ),
            )
        elif isinstance(payload, ExecutionSettlementConfirmation):
            if payload.recorded_at > now or payload.settled_at > context.economic_at:
                raise ValueError("future settlement confirmation")
            state = replace(
                state,
                settlement_confirmations=_append(
                    state.settlement_confirmations, payload, "confirmation_id"
                ),
            )
        elif isinstance(payload, CausalMark):
            if payload.knowledge_at > now or payload.economic_at > context.economic_at:
                raise ValueError("future mark")
            state = replace(state, marks=_append(state.marks, payload, "mark_id"))
        elif isinstance(payload, ModelDisposition):
            require_text(payload.evidence_id, "modeled disposition evidence")
            c = _commitment(state, payload.commitment_id)
            if payload.kind == "unknown":
                if c.state == "terminal":
                    raise ValueError("terminal commitment cannot become unknown by model")
                state = _replace_commitment(state, replace(c, state="unknown"))
            else:
                if payload.kind == "day_expired" and (
                    now < c.expires_at or c.state in ("unknown", "pending_cancel")
                ):
                    raise ValueError("DAY expiry cannot release this remainder")
                if c.state == "terminal":
                    return state, (), ()
                state = _replace_commitment(
                    state,
                    replace(
                        c,
                        state="terminal",
                        remaining_quantity=_ZERO,
                        reserved_cash=_ZERO,
                        reserved_sell_quantity=_ZERO,
                        remaining_fee_budget=_ZERO,
                        terminal_reason=f"{payload.kind}:{payload.evidence_id}",
                    ),
                )
        elif isinstance(payload, ControlCommand):
            require_text(payload.reason, "control reason")
            state = replace(state, halted=payload.halted)
        else:
            raise ValueError("unsupported accounting command")
        return state, due, ()

    def _event(
        self,
        state: AccountingState,
        event: BrokerOrderEvent,
        context: AccountingContext,
        policy: ExecutionPolicy,
    ) -> tuple[AccountingState, tuple[DueAccountingEvent, ...]]:
        if (
            event.received_at > context.point.knowledge_at
            or event.occurred_at > context.economic_at
        ):
            raise ValueError("future broker fact")
        events = _append(state.broker_events, event, "event_id")
        if events == state.broker_events:
            return state, ()
        before = next(
            (order for order in _orders(state) if order.submission.order_id == event.order_id), None
        )
        if before is None:
            raise ValueError("execution has no installed order")
        c = next(c for c in state.commitments if c.order_id == event.order_id)
        state = replace(
            state,
            broker_events=events,
            event_points=tuple(sorted((*state.event_points, (event.event_id, context.point)))),
        )
        after = next(
            order for order in _orders(state) if order.submission.order_id == event.order_id
        )
        terminal = c.state == "terminal" or after.status in (
            CanonicalOrderStatus.FILLED,
            CanonicalOrderStatus.CANCELED,
            CanonicalOrderStatus.REJECTED,
        )
        remaining = _ZERO if terminal else subtract(c.original_quantity, after.filled_quantity)
        fee_budget = (
            _ZERO
            if terminal
            else max(
                _ZERO,
                subtract(c.remaining_fee_budget, subtract(after.total_fees, before.total_fees)),
            )
        )
        status = (
            "terminal"
            if terminal
            else c.state
            if c.state in ("unknown", "pending_cancel")
            else "partial"
            if after.filled_quantity
            else "working"
        )
        if (
            event.kind is BrokerOrderEventKind.EXECUTION_CORRECTION
            and after.filled_quantity < before.filled_quantity
            and not terminal
        ):
            status = "unknown"
            fee_budget = max(fee_budget, multiply(remaining, policy.fee_per_share))
        reserved = (
            _ZERO
            if terminal
            else add(multiply(remaining, c.approved_price), fee_budget)
            if c.side is Side.BUY
            else fee_budget
        )
        state = _replace_commitment(
            state,
            replace(
                c,
                filled_quantity=after.filled_quantity,
                remaining_quantity=remaining,
                remaining_fee_budget=fee_budget,
                reserved_cash=reserved,
                reserved_sell_quantity=remaining if c.side is Side.SELL else _ZERO,
                state=status,
                terminal_reason=(c.terminal_reason or after.status.value) if terminal else None,
            ),
        )
        due: tuple[DueAccountingEvent, ...] = ()
        if event.kind in (
            BrokerOrderEventKind.EXECUTION,
            BrokerOrderEventKind.EXECUTION_CORRECTION,
        ):
            delta = _cash(event, c.side)
            if event.supersedes_event_id is not None:
                previous = next(e for e in events if e.event_id == event.supersedes_event_id)
                delta = subtract(delta, _cash(previous, c.side))
            if delta:
                instruction = next(
                    (
                        i
                        for i in state.settlement_instructions
                        if i.execution_event_id == event.event_id
                    ),
                    None,
                )
                if instruction is None:
                    reference = canonical_id(
                        "modeled-settlement",
                        state.account_id,
                        event.event_id,
                        policy.semantic_sha256,
                    )
                    instruction = create_settlement_instruction(
                        event,
                        contractual_settlement_at=_settlement_at(event, policy),
                        recorded_at=event.received_at,
                        external_reference=reference,
                    )
                    state = replace(
                        state,
                        settlement_instructions=_append(
                            state.settlement_instructions, instruction, "instruction_id"
                        ),
                    )
                if instruction.execution_event_sha256 != event.semantic_sha256:
                    raise ValueError("explicit instruction does not bind exact execution")
                due_at = max(
                    instruction.contractual_settlement_at,
                    instruction.recorded_at,
                    context.point.knowledge_at,
                )
                confirmation = create_settlement_confirmation(
                    instruction,
                    settled_at=due_at,
                    recorded_at=due_at,
                    external_reference=canonical_id(
                        "modeled-confirmation", instruction.instruction_id
                    ),
                )
                event_id = canonical_id("due-settlement", confirmation.confirmation_id)
                due = (
                    DueAccountingEvent(
                        event_id=event_id,
                        parent_event_id=context.event_id,
                        due_at=due_at,
                        command=AccountingCommand(event_id, confirmation),
                        policy_sha256=policy.semantic_sha256,
                    ),
                )
        return state, due

    def _observe(
        self,
        state: AccountingState,
        observation: ExecutionObservation,
        context: AccountingContext,
        policy: ExecutionPolicy,
    ) -> tuple[AccountingState, tuple[DueAccountingEvent, ...], tuple[str, ...]]:
        if (
            observation.knowledge_at > context.point.knowledge_at
            or observation.economic_at > context.economic_at
            or dict(context.instruments).get(observation.instrument_id) != observation.symbol
            or observation.model_id != policy.model_id
            or observation.basis
            != (
                "raw_open" if policy.model_id == "next-regular-open-proxy-v1" else "synthetic_price"
            )
        ):
            raise ValueError("execution observation scope, model or causal boundary differs")
        observations = _append(state.observations, observation, "observation_id")
        if observations == state.observations:
            return state, (), ()
        state = replace(state, observations=observations)
        due: list[DueAccountingEvent] = []
        reasons: list[str] = []
        budget = observation.quantity_budget
        for c in sorted(state.commitments, key=lambda c: (c.activation_sequence or -1, c.order_id)):
            if (
                c.instrument_id != observation.instrument_id
                or c.symbol != observation.symbol
                or c.state not in ("active", "working", "partial")
                or c.execution_session != observation.session
                or c.activated_at is None
                or c.activation_sequence is None
                or c.activation_frontier is None
                or c.activation_sequence >= context.point.reduction_sequence
                or c.activation_frontier >= context.point.frontier_sequence
                or c.activated_at >= observation.economic_at
                or not c.not_before <= observation.economic_at < c.expires_at
                or not c.remaining_quantity
                or budget == 0
            ):
                continue
            current = self.project(state=state, context=context, policy=policy)
            if current.snapshot.halted:
                reasons.append("EXECUTION_HALTED")
                break
            quantity = c.remaining_quantity if budget is None else min(c.remaining_quantity, budget)
            price = _price(observation.price, c.side, policy)
            fee = multiply(quantity, policy.fee_per_share)
            released_fee = min(c.remaining_fee_budget, fee)
            released = (
                add(multiply(quantity, c.approved_price), released_fee)
                if c.side is Side.BUY
                else released_fee
            )
            required = add(multiply(quantity, price), fee) if c.side is Side.BUY else fee
            if (
                fee > c.remaining_fee_budget
                or (c.side is Side.BUY and price > c.approved_price)
                or required > add(current.snapshot.available_cash, released)
            ):
                reasons.append("EXECUTION_PRICE_OR_CASH_CAPACITY_BLOCKED")
                state = replace(state, halted=True)
                break
            if c.side is Side.SELL:
                held = total(
                    p.quantity
                    for p in current.snapshot.positions
                    if p.instrument_id == c.instrument_id
                )
                other = total(
                    p.reserved_sell_quantity
                    for p in state.commitments
                    if p.instrument_id == c.instrument_id and p.commitment_id != c.commitment_id
                )
                if quantity > subtract(held, other):
                    reasons.append("EXECUTION_LONG_SHARE_CAPACITY_BLOCKED")
                    state = replace(state, halted=True)
                    break
            order = next(o for o in _orders(state) if o.submission.order_id == c.order_id)
            assert order.broker_order_id is not None
            event = BrokerOrderEvent(
                event_id=canonical_id("modeled-fill", observation.observation_id, c.order_id),
                order_id=c.order_id,
                broker_order_id=order.broker_order_id,
                broker_sequence=order.last_broker_sequence + 1,
                occurred_at=observation.economic_at,
                received_at=observation.knowledge_at,
                kind=BrokerOrderEventKind.EXECUTION,
                reason="modeled-execution",
                execution_id=canonical_id(
                    "modeled-execution", observation.observation_id, c.order_id
                ),
                execution_revision=1,
                quantity=quantity,
                price=price,
                fee=fee,
            )
            state, event_due = self._event(state, event, context, policy)
            due.extend(event_due)
            if budget is not None:
                budget = subtract(budget, quantity)
        return state, tuple(due), tuple(reasons)
