"""Explicit venue commands over independent canonical accounting, without an engine loop."""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from typing import Literal
from zoneinfo import ZoneInfo

from packages.application.personal_forward_data import admit_observation, quote_admission
from packages.backtest.personal_accounting import (
    PersonalAccounting,
    model_execution_terms,
    model_settlement_at,
)
from packages.domain.accounting_contracts import (
    AccountingCommand,
    AccountingContext,
    AccountingPayload,
    AccountingState,
    AccountingTransition,
    ExecutionAccountingPort,
)
from packages.domain.corporate_action_ledger import (
    CashDividendAccrual,
    CashDividendPayment,
    StockSplitAction,
)
from packages.domain.decimal_math import exact_decimal_add as add
from packages.domain.decimal_math import exact_decimal_multiply as multiply
from packages.domain.decimal_math import exact_decimal_subtract as subtract
from packages.domain.decimal_math import exact_decimal_sum as total
from packages.domain.forward_contracts import (
    ForwardDataState,
    ForwardQuote,
    ForwardRequirement,
    ModeledAvailability,
)
from packages.domain.identifiers import canonical_id
from packages.domain.ledger_reducer import LedgerCashFlow
from packages.domain.models import Side
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    CanonicalOrderState,
    CanonicalOrderStatus,
    create_cancel_request,
    reduce_order_lifecycle,
)
from packages.domain.personal_contracts import ReductionPoint
from packages.domain.settlement_ledger import (
    ExecutionSettlementConfirmation,
    ExecutionSettlementInstruction,
    create_settlement_confirmation,
    create_settlement_instruction,
    reduce_observed_settlement_ledger,
)
from packages.domain.stateful_venue_contracts import (
    MAX_VENUE_COMMANDS,
    MAX_VENUE_EFFECTS,
    VenueAccept,
    VenueAck,
    VenueCancel,
    VenueCommand,
    VenueCorrect,
    VenueDue,
    VenueFact,
    VenueFactPage,
    VenueFactPayload,
    VenueModel,
    VenueQuote,
    VenueReject,
    VenueRunDue,
    VenueState,
    VenueSubmit,
    VenueTransition,
    VerifiedVenueSources,
)

_ET = ZoneInfo("America/New_York")
_ZERO = Decimal(0)


_REJECTION_CODES = frozenset(
    {
        "VENUE_ORDER_UNKNOWN",
        "VENUE_VERIFIED_OUTBOUND_PORT_REQUIRED",
        "VENUE_ACCEPT_REQUIRES_REGISTERED_ORDER",
        "VENUE_ACCEPT_OUTSIDE_ORDER_WINDOW",
        "VENUE_REJECT_REQUIRES_REGISTERED_ORDER",
        "VENUE_CORRECTION_EXECUTION_UNKNOWN",
        "VENUE_ACCOUNTING_CREATED_MODELED_DUE_EVENT",
        "VENUE_EFFECT_BOUND_EXCEEDED",
        "VENUE_QUOTE_ADMISSION_REJECTED",
        "VENUE_ACCOUNTING_REJECTED",
        "VENUE_CASH_CAPACITY_BLOCKED",
        "VENUE_LONG_SHARE_CAPACITY_BLOCKED",
        "VENUE_SOURCE_VERIFICATION_FAILED",
    }
)
_ACCOUNTING_REASONS = frozenset(
    {
        "COMMAND_ID_CONFLICT",
        "NEGATIVE_CASH_CAPACITY",
        "EXECUTION_HALTED",
        "EXECUTION_PRICE_OR_CASH_CAPACITY_BLOCKED",
        "EXECUTION_LONG_SHARE_CAPACITY_BLOCKED",
    }
)


class VenueInputError(ValueError):
    """Malformed or conflicting immutable venue input; no durable effect."""


def venue_order_id(model: VenueModel, order_id: str) -> str:
    return canonical_id("stateful-venue-order/1", model.venue_id, model.account_id, order_id)


def venue_fact_id(payload: VenueFactPayload) -> str:
    if isinstance(payload, BrokerOrderEvent):
        return payload.event_id
    if isinstance(payload, LedgerCashFlow):
        return payload.cash_flow_id
    if isinstance(payload, StockSplitAction):
        return payload.split_id
    if isinstance(payload, CashDividendAccrual):
        return payload.dividend_id
    if isinstance(payload, CashDividendPayment):
        return payload.payment_id
    if isinstance(payload, ExecutionSettlementInstruction):
        return payload.instruction_id
    return payload.confirmation_id


def _context(
    model: VenueModel, state: AccountingState, *, sequence: int, at: datetime, event_id: str
) -> AccountingContext:
    return AccountingContext(
        run_id=canonical_id("stateful-venue-run/1", model.semantic_sha256),
        point=ReductionPoint(sequence, state.revision + 1, at, 1),
        economic_at=at,
        event_id=event_id,
        expected_mark_session=at.astimezone(_ET).date(),
        instruments=model.instruments,
    )


def _orders(state: AccountingState) -> tuple[CanonicalOrderState, ...]:
    return tuple(
        reduce_order_lifecycle(
            submission=submission,
            broker_events=tuple(
                e for e in state.broker_events if e.order_id == submission.order_id
            ),
            cancel_request=next(
                (c for c in state.cancel_requests if c.order_id == submission.order_id), None
            ),
        )
        for submission in state.submissions
    )


def _order(state: AccountingState, order_id: str) -> CanonicalOrderState:
    found = next((o for o in _orders(state) if o.submission.order_id == order_id), None)
    if found is None:
        raise VenueInputError("VENUE_ORDER_UNKNOWN")
    return found


def _due(state: AccountingState) -> tuple[VenueDue, ...]:
    confirmed = {c.instruction_id for c in state.settlement_confirmations}
    return tuple(
        sorted(
            (
                VenueDue(i.instruction_id, i.contractual_settlement_at)
                for i in state.settlement_instructions
                if i.instruction_id not in confirmed
            ),
            key=lambda d: (d.due_at, d.instruction_id),
        )
    )


def project_stateful_venue(
    model: VenueModel, state: VenueState, *, accounting: ExecutionAccountingPort | None = None
) -> AccountingTransition:
    validate_venue_state(model, state)
    return (accounting or PersonalAccounting()).project(
        state=state.accounting,
        policy=model.execution_policy,
        context=_context(
            model,
            state.accounting,
            sequence=state.sequence,
            at=state.as_of,
            event_id="venue-projection",
        ),
    )


def validate_venue_state(model: VenueModel, state: VenueState) -> None:
    model.__post_init__()
    state.__post_init__()
    if (
        state.model_sha256 != model.semantic_sha256
        or state.accounting.account_id != model.account_id
        or state.as_of < model.initial_cash_flow.recorded_at
    ):
        raise VenueInputError("VENUE_STATE_SCOPE_DIFFERS")
    if (
        state.forward_data.sources != model.sources
        or state.forward_data.mode
        != ("modeled" if model.source_mode == "synthetic_fixture" else "recorded")
        or state.forward_data.frontiers
    ):
        raise VenueInputError("VENUE_FORWARD_STATE_DIFFERS")
    if state.due_settlements != _due(state.accounting):
        raise VenueInputError("VENUE_DUE_INVENTORY_DIFFERS")
    retained: tuple[VenueFactPayload, ...] = (
        *state.accounting.broker_events,
        *state.accounting.cash_flows,
        *state.accounting.stock_splits,
        *state.accounting.cash_dividends,
        *state.accounting.dividend_payments,
        *state.accounting.settlement_instructions,
        *state.accounting.settlement_confirmations,
    )
    if {venue_fact_id(p): p for p in retained} != {f.fact_id: f.payload for f in state.facts}:
        raise VenueInputError("VENUE_FACT_INVENTORY_DIFFERS")
    if (
        not state.facts
        or state.facts[0].payload != model.initial_cash_flow
        or state.facts[0].sequence != 0
    ):
        raise VenueInputError("VENUE_GENESIS_DIFFERS")
    for f in state.facts:
        if f.fact_id != venue_fact_id(f.payload) or f.sequence > state.sequence:
            raise VenueInputError("VENUE_FACT_BINDING_DIFFERS")
        if f.sequence and (
            f.command_id != state.commands[f.sequence - 1].command_id
            or f.fact_id not in state.acknowledgments[f.sequence - 1].canonical_fact_ids
        ):
            raise VenueInputError("VENUE_FACT_ACK_DIFFERS")
    for ack in state.acknowledgments:
        if ack.canonical_fact_ids != tuple(
            f.fact_id for f in state.facts if f.sequence == ack.sequence
        ):
            raise VenueInputError("VENUE_ACK_FACT_INVENTORY_DIFFERS")


def initialize_stateful_venue(
    model: VenueModel, *, accounting: ExecutionAccountingPort | None = None
) -> VenueState:
    model.__post_init__()
    port = accounting or PersonalAccounting()
    empty = AccountingState(model.account_id)
    command_id = canonical_id("venue-genesis/1", model.semantic_sha256)
    transition = port.advance(
        state=empty,
        command=AccountingCommand(command_id, model.initial_cash_flow),
        context=_context(
            model, empty, sequence=0, at=model.initial_cash_flow.recorded_at, event_id=command_id
        ),
        policy=model.execution_policy,
    )
    if transition.disposition != "applied" or transition.due_events:
        raise VenueInputError("VENUE_GENESIS_REJECTED")
    return VenueState(
        model.semantic_sha256,
        transition.state,
        0,
        model.initial_cash_flow.recorded_at,
        (),
        (),
        (
            VenueFact(
                venue_fact_id(model.initial_cash_flow),
                command_id,
                0,
                model.initial_cash_flow,
                tuple(e.entry_id for e in transition.journal_entries),
            ),
        ),
        (),
        ForwardDataState(
            model.sources, "modeled" if model.source_mode == "synthetic_fixture" else "recorded"
        ),
    )


class _Advance:
    def __init__(
        self,
        model: VenueModel,
        state: VenueState,
        command: VenueCommand,
        port: ExecutionAccountingPort,
    ) -> None:
        self.model, self.original, self.command, self.port = model, state, command, port
        self.state = state.accounting
        self.facts: list[VenueFact] = []
        self.reasons: list[str] = []
        self.forward = state.forward_data
        self.sequence = state.sequence + 1

    def project(self) -> AccountingTransition:
        return self.port.project(
            state=self.state,
            policy=self.model.execution_policy,
            context=_context(
                self.model,
                self.state,
                sequence=self.sequence,
                at=self.command.received_at,
                event_id=self.command.command_id,
            ),
        )

    def apply(self, payload: AccountingPayload, *, fact: bool = False) -> None:
        command_id = canonical_id(
            "venue-accounting-command/1",
            self.command.command_id,
            self.state.revision,
            payload.semantic_sha256,
        )
        result = self.port.advance(
            state=self.state,
            command=AccountingCommand(command_id, payload),
            context=_context(
                self.model,
                self.state,
                sequence=self.sequence,
                at=self.command.received_at,
                event_id=command_id,
            ),
            policy=self.model.execution_policy,
        )
        if result.disposition == "rejected":
            rejected: dict[tuple[str, ...], str] = {
                ("commitment exceeds current available cash",): "VENUE_CASH_CAPACITY_BLOCKED",
                ("commitment exceeds unreserved long shares",): "VENUE_LONG_SHARE_CAPACITY_BLOCKED",
            }
            raise VenueInputError(rejected.get(result.reasons, "VENUE_ACCOUNTING_REJECTED"))
        if result.due_events:
            raise VenueInputError("VENUE_ACCOUNTING_CREATED_MODELED_DUE_EVENT")
        self.state = result.state
        self.reasons.extend(
            reason if reason in _ACCOUNTING_REASONS else "VENUE_ACCOUNTING_DIAGNOSTIC_UNAVAILABLE"
            for reason in result.reasons
        )
        if fact and result.disposition == "applied":
            assert isinstance(
                payload,
                (
                    BrokerOrderEvent,
                    LedgerCashFlow,
                    StockSplitAction,
                    CashDividendAccrual,
                    CashDividendPayment,
                    ExecutionSettlementInstruction,
                    ExecutionSettlementConfirmation,
                ),
            )
            self.facts.append(
                VenueFact(
                    venue_fact_id(payload),
                    self.command.command_id,
                    self.sequence,
                    payload,
                    tuple(e.entry_id for e in result.journal_entries),
                )
            )
            if len(self.facts) > MAX_VENUE_EFFECTS:
                raise VenueInputError("VENUE_EFFECT_BOUND_EXCEEDED")

    def event(
        self,
        order: CanonicalOrderState,
        kind: BrokerOrderEventKind,
        *,
        reason: str | None = None,
        execution_id: str | None = None,
        execution_revision: int | None = None,
        supersedes_event_id: str | None = None,
        quantity: Decimal | None = None,
        price: Decimal | None = None,
        fee: Decimal | None = None,
    ) -> BrokerOrderEvent:
        # Explicitly assigned true per-order venue sequence, never a quote sequence.
        return BrokerOrderEvent(
            event_id=canonical_id(
                "venue-source-fact/1",
                self.model.semantic_sha256,
                self.command.command_id,
                order.submission.order_id,
                kind.value,
            ),
            order_id=order.submission.order_id,
            broker_order_id=venue_order_id(self.model, order.submission.order_id),
            broker_sequence=order.last_broker_sequence + 1,
            occurred_at=self.command.received_at,
            received_at=self.command.received_at,
            kind=kind,
            reason=reason,
            execution_id=execution_id,
            execution_revision=execution_revision,
            supersedes_event_id=supersedes_event_id,
            quantity=quantity,
            price=price,
            fee=fee,
        )

    def execution(self, event: BrokerOrderEvent) -> None:
        self.apply(event, fact=True)
        # Ask the same canonical observed settlement reducer whether this exact
        # revision has a nonzero obligation; do not reproduce cash-delta logic.
        ledger = reduce_observed_settlement_ledger(
            account_id=self.model.account_id,
            order_states=_orders(self.state),
            cash_flows=self.state.cash_flows,
            instructions=self.state.settlement_instructions,
            confirmations=self.state.settlement_confirmations,
        )
        if event.event_id in ledger.missing_instruction_event_ids:
            instruction = create_settlement_instruction(
                event,
                contractual_settlement_at=model_settlement_at(
                    event=event, policy=self.model.execution_policy
                ),
                recorded_at=self.command.received_at,
                external_reference=canonical_id(
                    "venue-model-settlement/1", self.model.semantic_sha256, event.event_id
                ),
            )
            self.apply(instruction, fact=True)


def _quote_reasons(
    work: _Advance, payload: VenueQuote, sources: VerifiedVenueSources | None
) -> tuple[str, ...]:
    observation = payload.observation
    source = next((s for s in work.model.sources if s.source_id == observation.source_id), None)
    q = observation.payload
    if (
        source is None
        or not isinstance(q, ForwardQuote)
        or dict(work.model.instruments).get(q.instrument_id) != q.symbol
    ):
        return ("VENUE_QUOTE_SCOPE_DIFFERS",)
    at = work.command.received_at
    if q.session != at.astimezone(_ET).date():
        return ("VENUE_QUOTE_SESSION_DIFFERS",)
    if work.model.source_mode == "recorded_as_observed":
        if sources is None:
            return ("VENUE_VERIFIED_SOURCE_PORT_REQUIRED",)
        if source.account_scope is None:
            return ("VENUE_SOURCE_ACCOUNT_SCOPE_UNKNOWN",)
        try:
            sources.verify_quote(work.model, source, observation)
        except Exception:
            raise VenueInputError("VENUE_SOURCE_VERIFICATION_FAILED") from None
        admission = quote_admission(
            observation,
            source,
            expected=ForwardRequirement(
                source.source_id, q.instrument_id, q.symbol, q.session, "quote"
            ),
            environment=source.environment,
            account_scope=source.account_scope,
            evaluated_at=at,
            boot_id=payload.boot_id,
            evaluated_monotonic_ns=payload.evaluated_monotonic_ns,
        )
        return admission.reasons
    # This is an explicit fixture model, never provider quote qualification.
    if (
        source.provider != "fixture"
        or source.environment != "synthetic"
        or not isinstance(observation.availability, ModeledAvailability)
    ):
        return ("VENUE_SYNTHETIC_QUOTE_REQUIRED",)
    reasons = []
    if q.bid is None or q.ask is None or q.currency != "USD":
        reasons.append("VENUE_FIXTURE_PRICE_UNAVAILABLE")
    if not timedelta(0) <= at - observation.known_at < timedelta(seconds=1):
        reasons.append("VENUE_FIXTURE_RECEIPT_STALE_OR_FUTURE")
    for value in (q.bid_at, q.ask_at):
        if value is None or not timedelta(0) <= at - value < timedelta(seconds=5):
            reasons.append("VENUE_FIXTURE_SIDE_STALE_OR_FUTURE")
    return tuple(sorted(set(reasons)))


def _fill(work: _Advance, payload: VenueQuote, sources: VerifiedVenueSources | None) -> None:
    admitted = admit_observation(
        work.forward, payload.observation, admitted_at=work.command.received_at
    )
    if admitted.disposition == "rejected":
        raise VenueInputError("VENUE_QUOTE_ADMISSION_REJECTED")
    work.forward = admitted.state
    if admitted.disposition == "duplicate":
        work.reasons.append("VENUE_QUOTE_ALREADY_CONSUMED")
        return
    if admitted.disposition == "pending":
        work.reasons.extend(admitted.reasons)
        return
    if any(
        o.source_id == payload.observation.source_id
        and o.revision_key == payload.observation.revision_key
        and o.revision > payload.observation.revision
        for o in work.forward.observations
    ):
        work.reasons.append("VENUE_QUOTE_SUPERSEDED")
        return
    reasons = _quote_reasons(work, payload, sources)
    if reasons:
        work.reasons.extend(reasons)
        return
    q = payload.observation.payload
    assert (
        isinstance(q, ForwardQuote)
        and q.bid is not None
        and q.ask is not None
        and q.bid_at is not None
        and q.ask_at is not None
    )
    budget = payload.quantity_budget
    # Stable account-wide admission order, independent of coordinator projections.
    commitments = sorted(work.state.commitments, key=lambda c: (c.created_sequence, c.order_id))
    for c in commitments:
        if budget == 0:
            break
        if len(work.facts) >= MAX_VENUE_EFFECTS - 2:
            work.reasons.append("VENUE_EFFECT_BATCH_BOUND_REACHED")
            break
        if (
            c.instrument_id != q.instrument_id
            or c.state not in ("working", "partial")
            or c.execution_session != q.session
            or not c.not_before <= work.command.received_at < c.expires_at
        ):
            continue
        order = _order(work.state, c.order_id)
        accepted = next(
            (e for e in order.broker_events if e.kind is BrokerOrderEventKind.ACCEPTED), None
        )
        if (
            accepted is None
            or accepted.received_at >= payload.observation.known_at
            or min(q.bid_at, q.ask_at) <= accepted.occurred_at
        ):
            continue
        current = work.project()
        if current.snapshot.halted:
            work.reasons.append("VENUE_EXECUTION_HALTED")
            break
        quantity = min(c.remaining_quantity, budget)
        price, fee = model_execution_terms(
            quantity=quantity,
            reference_price=q.ask if c.side is Side.BUY else q.bid,
            side=c.side,
            policy=work.model.execution_policy,
        )
        released = (
            add(multiply(quantity, c.approved_price), min(fee, c.remaining_fee_budget))
            if c.side is Side.BUY
            else min(fee, c.remaining_fee_budget)
        )
        required = add(multiply(quantity, price), fee) if c.side is Side.BUY else fee
        if (
            fee > c.remaining_fee_budget
            or (c.side is Side.BUY and price > c.approved_price)
            or required > add(current.snapshot.available_cash, released)
        ):
            work.reasons.append("VENUE_EXECUTION_CASH_OR_PRICE_BLOCKED")
            continue
        if c.side is Side.SELL:
            held = total(
                p.quantity for p in current.snapshot.positions if p.instrument_id == c.instrument_id
            )
            other = total(
                item.reserved_sell_quantity
                for item in work.state.commitments
                if item.instrument_id == c.instrument_id and item.commitment_id != c.commitment_id
            )
            if quantity > subtract(held, other):
                work.reasons.append("VENUE_EXECUTION_LONG_SHARES_BLOCKED")
                continue
        event = work.event(
            order,
            BrokerOrderEventKind.EXECUTION,
            execution_id=canonical_id(
                "venue-execution/1",
                work.model.semantic_sha256,
                payload.observation.observation_id,
                c.order_id,
            ),
            execution_revision=1,
            quantity=quantity,
            price=price,
            fee=fee,
            reason="stateful-venue-modeled-bid-ask-fill",
        )
        work.execution(event)
        budget = subtract(budget, quantity)


def advance_stateful_venue(
    model: VenueModel,
    state: VenueState,
    command: VenueCommand,
    *,
    accounting: ExecutionAccountingPort | None = None,
    verified_sources: VerifiedVenueSources | None = None,
) -> VenueTransition:
    """Derive one explicit effect; exact command retries are inert even after later work."""
    validate_venue_state(model, state)
    command.__post_init__()
    prior = next((a for a in state.acknowledgments if a.command_id == command.command_id), None)
    if prior is not None:
        if prior.command_sha256 != command.semantic_sha256:
            raise VenueInputError("VENUE_COMMAND_ID_CONFLICT")
        return VenueTransition(state, prior)
    if state.sequence >= MAX_VENUE_COMMANDS or command.received_at < state.as_of:
        raise VenueInputError("VENUE_COMMAND_BOUND_OR_TIME_REGRESSION")
    port = accounting or PersonalAccounting()
    work = _Advance(model, state, command, port)
    disposition: LiteralDisposition = "applied"
    venue_id = None
    try:
        payload = command.payload
        if isinstance(payload, VenueSubmit):
            if verified_sources is None:
                raise VenueInputError("VENUE_VERIFIED_OUTBOUND_PORT_REQUIRED")
            try:
                verified_sources.verify_submission(model, payload, received_at=command.received_at)
            except Exception:
                raise VenueInputError("VENUE_SOURCE_VERIFICATION_FAILED") from None
            work.apply(payload.registration)
            venue_id = venue_order_id(model, payload.registration.submission.order_id)
            disposition = "registered"
        elif isinstance(payload, VenueAccept):
            order = _order(work.state, payload.order_id)
            if order.status is not CanonicalOrderStatus.SUBMITTED:
                raise VenueInputError("VENUE_ACCEPT_REQUIRES_REGISTERED_ORDER")
            c = next(c for c in work.state.commitments if c.order_id == payload.order_id)
            if not c.not_before <= command.received_at < c.expires_at:
                raise VenueInputError("VENUE_ACCEPT_OUTSIDE_ORDER_WINDOW")
            work.apply(work.event(order, BrokerOrderEventKind.ACCEPTED), fact=True)
            venue_id = venue_order_id(model, payload.order_id)
        elif isinstance(payload, VenueReject):
            order = _order(work.state, payload.order_id)
            if order.status is not CanonicalOrderStatus.SUBMITTED:
                raise VenueInputError("VENUE_REJECT_REQUIRES_REGISTERED_ORDER")
            work.apply(
                work.event(order, BrokerOrderEventKind.REJECTED, reason=payload.reason), fact=True
            )
            venue_id = venue_order_id(model, payload.order_id)
        elif isinstance(payload, VenueCancel):
            order = _order(work.state, payload.order_id)
            work.apply(
                create_cancel_request(
                    order, requested_at=command.received_at, reason=payload.reason
                )
            )
            work.apply(
                work.event(order, BrokerOrderEventKind.CANCELED, reason=payload.reason), fact=True
            )
            venue_id = venue_order_id(model, payload.order_id)
        elif isinstance(payload, VenueQuote):
            _fill(work, payload, verified_sources)
        elif isinstance(payload, VenueCorrect):
            originals = [
                e for e in work.state.broker_events if e.execution_id == payload.execution_id
            ]
            if not originals:
                raise VenueInputError("VENUE_CORRECTION_EXECUTION_UNKNOWN")
            previous = max(originals, key=lambda e: e.execution_revision or 0)
            order = _order(work.state, previous.order_id)
            work.execution(
                work.event(
                    order,
                    BrokerOrderEventKind.EXECUTION_CORRECTION,
                    execution_id=payload.execution_id,
                    execution_revision=(previous.execution_revision or 0) + 1,
                    supersedes_event_id=previous.event_id,
                    quantity=payload.quantity,
                    price=payload.price,
                    fee=payload.fee,
                    reason=payload.reason,
                )
            )
            venue_id = venue_order_id(model, order.submission.order_id)
        elif isinstance(payload, VenueRunDue):
            available = [d for d in _due(work.state) if d.due_at <= command.received_at][
                : payload.limit
            ]
            for due in available:
                instruction = next(
                    i
                    for i in work.state.settlement_instructions
                    if i.instruction_id == due.instruction_id
                )
                # The due command executes now. Sleeping past due time never
                # invents an earlier actual settlement/confirmation receipt.
                confirmation = create_settlement_confirmation(
                    instruction,
                    settled_at=command.received_at,
                    recorded_at=command.received_at,
                    external_reference=canonical_id(
                        "venue-settlement-confirmation/1",
                        model.semantic_sha256,
                        instruction.instruction_id,
                    ),
                )
                work.apply(confirmation, fact=True)
        else:
            work.apply(payload, fact=True)
        if disposition == "applied" and not work.facts and work.state == state.accounting:
            disposition = "no_effect"
    except Exception as error:
        # A rejected command is retained, but a partially prepared transition
        # cannot expose half a fill/instruction or half a cancel receipt.
        work.state, work.facts, work.forward = state.accounting, [], state.forward_data
        # Only locally reviewed literals can be persisted. Neither an injected
        # port's exception text nor arbitrary returned diagnostics are evidence.
        reason = error.args[0] if type(error) is VenueInputError and len(error.args) == 1 else None
        work.reasons = [
            reason
            if type(reason) is str and reason in _REJECTION_CODES
            else "VENUE_COMMAND_REJECTED"
        ]
        disposition, venue_id = "rejected", None
    acknowledgment = VenueAck(
        command.command_id,
        command.semantic_sha256,
        state.sequence + 1,
        disposition,
        venue_id,
        tuple(f.fact_id for f in work.facts),
        tuple(sorted(set(work.reasons))),
    )
    updated = VenueState(
        model.semantic_sha256,
        work.state,
        state.sequence + 1,
        command.received_at,
        (*state.commands, command),
        (*state.acknowledgments, acknowledgment),
        (*state.facts, *work.facts),
        _due(work.state),
        work.forward,
    )
    project_stateful_venue(model, updated, accounting=port)
    return VenueTransition(updated, acknowledgment)


# Keep the acknowledgment literals tied to the public record, without a second DTO.
type LiteralDisposition = Literal["registered", "applied", "rejected", "no_effect"]


def venue_fact_page(
    model: VenueModel,
    state: VenueState,
    *,
    through_sequence: int,
    offset: int = 0,
    limit: int = 200,
) -> VenueFactPage:
    validate_venue_state(model, state)
    if (
        type(through_sequence) is not int
        or not 0 <= through_sequence <= state.sequence
        or type(offset) is not int
        or offset < 0
        or type(limit) is not int
        or not 1 <= limit <= 200
    ):
        raise VenueInputError("VENUE_PAGE_BOUND_INVALID")
    retained = tuple(f for f in state.facts if f.sequence <= through_sequence)
    if offset > len(retained):
        raise VenueInputError("VENUE_PAGE_OFFSET_INVALID")
    page = retained[offset : offset + limit]
    return VenueFactPage(
        model.semantic_sha256,
        state.semantic_sha256,
        through_sequence,
        offset,
        page,
        offset + len(page),
        offset + len(page) == len(retained),
    )
