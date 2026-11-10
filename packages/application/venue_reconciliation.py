"""Interpret retained independent venue observations without account-state substitution.

The capture producer and caller's durable metadata reader authenticate sources.
These detached functions check structure and reuse canonical reducers. They do
not authenticate a caller-created record or clear UNKNOWN/terminal holds.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Literal, Protocol

from packages.application.stateful_venue import (
    project_stateful_venue,
    venue_fact_id,
    venue_order_id,
)
from packages.domain.accounting_contracts import AccountingCommand
from packages.domain.canonical import canonical_json_bytes
from packages.domain.continuous_account_contracts import CanonicalAccountTransitionRef
from packages.domain.corporate_action_ledger import (
    CashDividendAccrual,
    CashDividendPayment,
    StockSplitAction,
)
from packages.domain.identifiers import canonical_id
from packages.domain.ledger_reducer import LedgerCashFlow
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    reduce_order_lifecycle,
)
from packages.domain.personal_contracts import ContractRecord, content_digest, semantic_value
from packages.domain.reconciliation_application_contracts import (
    ReconciliationFactCommand,
    reconciliation_command_id,
)
from packages.domain.reconciliation_contracts import (
    MAX_RECONCILIATION_ITEMS,
    REQUIRED_CASH_FIELDS,
    REQUIRED_RECONCILIATION_OPERATIONS,
    CashObservation,
    FactObservation,
    ObservationRound,
    OrderObservation,
    PositionObservation,
    ReconciliationOrderBinding,
    ReconciliationPage,
)
from packages.domain.reconciliation_persistence_contracts import (
    ReconciliationSourceContent,
    ReconciliationSourceManifest,
    ReconciliationSourceRef,
    ResolvedReconciliationTransition,
)
from packages.domain.settlement_ledger import (
    ExecutionSettlementConfirmation,
    ExecutionSettlementInstruction,
)
from packages.domain.stateful_venue_contracts import (
    VenueFact,
    VenueFactPage,
    VenueModel,
    VenueRead,
    VenueSubmit,
)
from packages.domain.venue_reconciliation_contracts import (
    VENUE_CAPTURE_SCHEMA,
    VenueCapturePage,
    VenueCaptureRequest,
    VenueFinancialPage,
)


class VenueCaptureError(ValueError):
    """Static source/closure failure, without private data or exception text."""


def _action_dependencies(
    model: VenueModel,
    facts: tuple[VenueFact, ...],
    orders: tuple[OrderObservation, ...],
) -> dict[str, tuple[str, ...]]:
    """Economic action prerequisites from the independent venue's actual history.

    These are causal dependencies, not substituted provider sequence numbers.
    Unrelated orders/cash remain independent when another source fact blocks.
    """
    order_instruments = {order.provider_order_id: order.instrument_id for order in orders}
    executions: dict[str, dict[str, str]] = {}
    previous_actions: dict[str, str] = {}
    result: dict[str, tuple[str, ...]] = {}
    previous_sequence = -1
    seen: set[str] = set()
    broker_sequences: dict[str, int] = {}
    for fact in facts:
        if fact.sequence < previous_sequence:
            raise VenueCaptureError("VENUE_SOURCE_COMMAND_SEQUENCE_REGRESSED")
        previous_sequence = fact.sequence
        payload = fact.payload
        parents: tuple[str, ...] = ()
        if isinstance(payload, BrokerOrderEvent):
            expected_sequence = broker_sequences.get(payload.order_id, 0) + 1
            if payload.broker_sequence != expected_sequence:
                raise VenueCaptureError("VENUE_SOURCE_ORDER_SEQUENCE_GAP")
            broker_sequences[payload.order_id] = payload.broker_sequence
            parents = () if payload.supersedes_event_id is None else (payload.supersedes_event_id,)
        elif isinstance(payload, CashDividendPayment):
            parents = (payload.dividend_id,)
        elif isinstance(payload, ExecutionSettlementInstruction):
            parents = (payload.execution_event_id,)
        elif isinstance(payload, ExecutionSettlementConfirmation):
            parents = (payload.instruction_id,)
        if fact.fact_id in seen or not set(parents) <= seen:
            raise VenueCaptureError("VENUE_SOURCE_FACT_ORDER_INVALID")
        seen.add(fact.fact_id)
        if isinstance(payload, BrokerOrderEvent) and payload.execution_id is not None:
            instrument = order_instruments.get(venue_order_id(model, payload.order_id))
            if instrument is None:
                raise VenueCaptureError("VENUE_ACTION_ORDER_INSTRUMENT_MISSING")
            executions.setdefault(instrument, {})[payload.order_id] = fact.fact_id
        elif isinstance(payload, (StockSplitAction, CashDividendAccrual)):
            instrument = payload.instrument_id
            action_parents = set(executions.get(instrument, {}).values())
            if instrument in previous_actions:
                action_parents.add(previous_actions[instrument])
            if len(action_parents) > 16:
                raise VenueCaptureError("VENUE_ACTION_PREDECESSOR_LIMIT")
            result[fact.fact_id] = tuple(sorted(action_parents))
            previous_actions[instrument] = fact.fact_id
    return result


def build_venue_financial_pages(
    request: VenueCaptureRequest, read: VenueRead, fact_pages: tuple[VenueFactPage, ...]
) -> tuple[VenueFinancialPage, ...]:
    """Build only from C's independent state and its complete fixed-through pages."""
    model, state = request.binding.model, read.state
    if request.through_head is not None and request.through_head != read.head:
        raise VenueCaptureError("VENUE_REQUEST_HEAD_DIFFERS")
    if len(state.facts) > MAX_RECONCILIATION_ITEMS or len(state.accounting.submissions) > 200:
        raise VenueCaptureError("VENUE_CAPTURE_ITEM_LIMIT")
    if not fact_pages or len(fact_pages) > 256:
        raise VenueCaptureError("VENUE_FACT_PAGES_REQUIRED")
    offset = 0
    for index, page in enumerate(fact_pages):
        if (
            page.model_sha256 != model.semantic_sha256
            or page.state_sha256 != state.semantic_sha256
            or page.through_sequence != state.sequence
            or page.offset != offset
            or page.complete != (index == len(fact_pages) - 1)
            or (not page.complete and not page.facts)
        ):
            raise VenueCaptureError("VENUE_FACT_PAGE_CLOSURE_DIFFERS")
        offset = page.next_offset
    if tuple(fact for page in fact_pages for fact in page.facts) != state.facts:
        raise VenueCaptureError("VENUE_FACT_INVENTORY_DIFFERS")
    projected = project_stateful_venue(model, state)
    entries = projected.journal_entries
    for fact in state.facts:
        if fact.fact_id != venue_fact_id(fact.payload) or fact.journal_entry_ids != tuple(
            sorted(
                entry.entry_id
                for entry in entries
                if entry.source_sha256 == fact.payload.semantic_sha256
            )
        ):
            raise VenueCaptureError("VENUE_FACT_CANONICAL_LINKS_DIFFER")
    registrations = {
        command.payload.registration.submission.order_id: command.payload.registration
        for command, acknowledgment in zip(state.commands, state.acknowledgments, strict=True)
        if isinstance(command.payload, VenueSubmit) and acknowledgment.disposition == "registered"
    }
    mappings = {value.submission.order_id: value for value in request.binding.orders}
    for order_id, mapping in mappings.items():
        registration = registrations.get(order_id)
        if (
            registration is None
            or registration.account_id != model.account_id
            or registration.submission != mapping.submission
            or registration.semantic_sha256 != mapping.registration_sha256
            or mapping.provider_order_id != venue_order_id(model, order_id)
        ):
            raise VenueCaptureError("VENUE_SUBMISSION_MAPPING_DIFFERS")
    snapshot = projected.snapshot
    # These are explicit properties of this modeled cash-only venue, not defaults
    # for missing provider liability/restriction fields. Negative cash halts below.
    cash = tuple(
        CashObservation(
            field,
            Decimal(0)
            if field in ("margin_liability", "restricted_cash")
            else getattr(snapshot, field),
            "USD",
            content_digest(("venue-cash-semantics/1", model.semantic_sha256, field)),
        )
        for field in REQUIRED_CASH_FIELDS
    )
    positions = tuple(
        PositionObservation(p.instrument_id, p.symbol, p.quantity) for p in snapshot.positions
    )
    orders: list[OrderObservation] = []
    for submission in sorted(state.accounting.submissions, key=lambda value: value.order_id):
        order = reduce_order_lifecycle(
            submission=submission,
            broker_events=tuple(
                e for e in state.accounting.broker_events if e.order_id == submission.order_id
            ),
            cancel_request=next(
                (c for c in state.accounting.cancel_requests if c.order_id == submission.order_id),
                None,
            ),
        )
        status = order.status.value
        observed_status: Literal[
            "working", "partial", "pending_cancel", "filled", "canceled", "rejected", "unknown"
        ]
        status_map: dict[
            str,
            Literal[
                "working", "partial", "pending_cancel", "filled", "canceled", "rejected", "unknown"
            ],
        ] = {
            "submitted": "unknown",
            "partially_filled": "partial",
            "working": "working",
            "filled": "filled",
            "canceled": "canceled",
            "rejected": "rejected",
        }
        observed_status = status_map[status]
        if order.cancel_request is not None and status in ("working", "partially_filled"):
            observed_status = "pending_cancel"
        orders.append(
            OrderObservation(
                venue_order_id(model, submission.order_id),
                submission.order_id if submission.order_id in mappings else None,
                submission.intent.instrument_id,
                submission.intent.symbol,
                submission.intent.side,
                submission.intent.quantity,
                order.filled_quantity,
                observed_status,  # validated closed canonical status mapping
                order.last_broker_sequence or None,
            )
        )
    pages = [
        VenueFinancialPage("balances", 0, 0, len(cash), True, cash=cash),
        VenueFinancialPage("positions", 0, 0, len(positions), True, positions=positions),
    ]
    for operation in ("orders_current", "orders_history"):
        values = tuple(
            o
            for o in orders
            if operation == "orders_history" or o.status not in ("filled", "canceled", "rejected")
        )
        for offset in range(0, max(1, len(values)), 200):
            selected = values[offset : offset + 200]
            pages.append(
                VenueFinancialPage(
                    operation,
                    offset // 200,
                    offset,
                    offset + len(selected),
                    offset + len(selected) == len(values),
                    orders=selected,
                )
            )
    dependencies = _action_dependencies(model, state.facts, tuple(orders))
    pages.extend(
        VenueFinancialPage(
            "activity",
            index,
            p.offset,
            p.next_offset,
            p.complete,
            fact_page=p,
            action_predecessors=tuple(
                sorted(
                    (f.fact_id, dependencies[f.fact_id])
                    for f in p.facts
                    if f.fact_id in dependencies
                )
            ),
        )
        for index, p in enumerate(fact_pages)
    )
    return tuple(pages)


def reconciliation_page(value: VenueCapturePage) -> ReconciliationPage:
    body, request = value.body, value.request
    raw = canonical_json_bytes(semantic_value(body))
    query = content_digest(
        (
            "venue-capture-query/1",
            request,
            value.venue_head,
            value.venue_state_sha256,
            body.operation,
        )
    )
    return ReconciliationPage(
        operation=body.operation,
        receipt_id=canonical_id(
            "venue-capture-page/1",
            request.capture_id,
            request.binding.scope.semantic_sha256,
            value.index,
        ),
        scope_sha256=request.binding.scope.semantic_sha256,
        query_sha256=query,
        request_sha256=content_digest((query, body.offset)),
        body_sha256=content_digest(body),
        body_bytes=len(raw),
        ordinal=body.ordinal,
        requested_at=value.requested_at,
        received_at=value.received_at,
        requested_from=request.requested_from
        if body.operation in ("activity", "orders_history")
        else None,
        requested_through=request.requested_through
        if body.operation in ("activity", "orders_history")
        else None,
        cursor=None if body.ordinal == 0 else str(body.offset),
        next_cursor=None if body.complete else str(body.next_offset),
        termination="documented_end" if body.complete else "more",
        terminal_evidence_sha256=content_digest(("venue-fixed-page-end/1", value.venue_head, body))
        if body.complete
        else None,
        selection="all_account",
        provider_sequence=None,  # venue command sequence is a separate pinned namespace
    )


def _fact_command(value: VenueCapturePage, fact: VenueFact) -> ReconciliationFactCommand:
    payload, page, binding = fact.payload, reconciliation_page(value), value.request.binding
    kind: Literal["execution", "correction", "order", "cash_flow", "settlement", "corporate_action"]
    mapping = None
    parents: tuple[str, ...] = ()
    if isinstance(payload, BrokerOrderEvent):
        known = next((m for m in binding.orders if m.submission.order_id == payload.order_id), None)
        if known is not None:
            mapping = ReconciliationOrderBinding(
                payload.order_id, known.provider_order_id, known.semantic_sha256
            )
        kind = (
            "execution"
            if payload.kind is BrokerOrderEventKind.EXECUTION
            else "correction"
            if payload.kind is BrokerOrderEventKind.EXECUTION_CORRECTION
            else "order"
        )
        effective = payload.occurred_at
        provider_id = payload.execution_id or payload.event_id
        revision = (
            str(payload.execution_revision) if payload.execution_revision is not None else None
        )
        sequence = payload.broker_sequence
        predecessor = payload.supersedes_event_id
        if predecessor is not None:
            parents = (predecessor,)
    else:
        kind = (
            "cash_flow"
            if isinstance(payload, LedgerCashFlow)
            else "settlement"
            if isinstance(
                payload, (ExecutionSettlementInstruction, ExecutionSettlementConfirmation)
            )
            else "corporate_action"
        )
        provider_id, revision, sequence, predecessor = fact.fact_id, None, None, None
        if isinstance(payload, CashDividendPayment):
            effective, parents = payload.paid_at, (payload.dividend_id,)
        elif isinstance(payload, ExecutionSettlementInstruction):
            effective, parents = payload.recorded_at, (payload.execution_event_id,)
        elif isinstance(payload, ExecutionSettlementConfirmation):
            effective, parents = payload.settled_at, (payload.instruction_id,)
        else:
            effective = payload.effective_at
    parents = tuple(
        sorted(set(parents) | set(dict(value.body.action_predecessors).get(fact.fact_id, ())))
    )
    observation = FactObservation(
        fact.fact_id,
        payload.semantic_sha256,
        kind,
        provider_id,
        revision,
        sequence,
        page.receipt_id,
        effective,
        page.received_at,
        "external"
        if (
            (isinstance(payload, BrokerOrderEvent) and mapping is None)
            or (isinstance(payload, LedgerCashFlow) and payload != binding.model.initial_cash_flow)
        )
        else "application",
        predecessor,
    )
    return ReconciliationFactCommand(
        binding.scope,
        observation,
        AccountingCommand(reconciliation_command_id(binding.scope, observation), payload),
        page.semantic_sha256,
        mapping,
        parents,
    )


def source_commands(value: VenueCapturePage) -> tuple[ReconciliationFactCommand, ...]:
    if value.body.fact_page is None:
        return ()
    return tuple(
        sorted(
            (_fact_command(value, f) for f in value.body.fact_page.facts),
            key=lambda f: f.observation.fact_id,
        )
    )


def resolve_venue_capture(
    pages: tuple[VenueCapturePage, ...],
) -> tuple[ObservationRound, tuple[ReconciliationFactCommand, ...]]:
    """Reject partial/mixed captures; freshness is never refreshed during replay."""
    if not pages or len(pages) > 256:
        raise VenueCaptureError("VENUE_CAPTURE_PAGES_REQUIRED")
    ordered = tuple(sorted(pages, key=lambda p: p.index))
    first = ordered[0]
    common = (
        first.request,
        first.venue_head,
        first.venue_state_sha256,
        first.venue_as_of,
        first.page_count,
        first.source_blockers,
    )
    if len(ordered) != first.page_count or tuple(p.index for p in ordered) != tuple(
        range(len(ordered))
    ):
        raise VenueCaptureError("VENUE_CAPTURE_PAGE_GAP")
    for p in ordered:
        p.__post_init__()
        if (
            p.request,
            p.venue_head,
            p.venue_state_sha256,
            p.venue_as_of,
            p.page_count,
            p.source_blockers,
        ) != common:
            raise VenueCaptureError("VENUE_CAPTURE_COMMON_BINDING_DIFFERS")
    for operation in REQUIRED_RECONCILIATION_OPERATIONS:
        selected = tuple(p for p in ordered if p.body.operation == operation)
        if not selected:
            raise VenueCaptureError("VENUE_CAPTURE_OPERATION_MISSING")
        if operation != "activity" and len(selected) != 1:
            raise VenueCaptureError("VENUE_FINANCIAL_RESPONSE_REQUIRES_ONE_PAGE")
        offset = 0
        for index, p in enumerate(selected):
            if (
                p.body.ordinal != index
                or p.body.offset != offset
                or p.body.complete != (index == len(selected) - 1)
            ):
                raise VenueCaptureError("VENUE_CAPTURE_OPERATION_PAGE_GAP")
            if index and selected[index - 1].received_at > p.requested_at:
                raise VenueCaptureError("VENUE_CAPTURE_PAGE_TIMES_OVERLAP")
            offset = p.body.next_offset
    facts = tuple(
        sorted(
            (f for p in ordered for f in source_commands(p)), key=lambda f: f.observation.fact_id
        )
    )
    if len(facts) > MAX_RECONCILIATION_ITEMS or len({f.observation.fact_id for f in facts}) != len(
        facts
    ):
        raise VenueCaptureError("VENUE_CAPTURE_FACT_DUPLICATE_OR_LIMIT")
    orders = tuple(o for p in ordered for o in p.body.orders)
    unique_orders = {o.provider_order_id: o for o in orders}
    if any(unique_orders[o.provider_order_id] != o for o in orders):
        raise VenueCaptureError("VENUE_CAPTURE_ORDER_OVERLAP_DIFFERS")
    raw_facts = tuple(
        f for p in ordered if p.body.fact_page is not None for f in p.body.fact_page.facts
    )
    expected_dependencies = _action_dependencies(
        first.request.binding.model, raw_facts, tuple(unique_orders.values())
    )
    retained_dependencies = tuple(pair for p in ordered for pair in p.body.action_predecessors)
    if (
        len(dict(retained_dependencies)) != len(retained_dependencies)
        or dict(retained_dependencies) != expected_dependencies
    ):
        raise VenueCaptureError("VENUE_ACTION_PREDECESSOR_CLOSURE_DIFFERS")
    observed = ObservationRound(
        scope=first.request.binding.scope,
        round_id=first.request.capture_id,
        started_at=min(p.requested_at for p in ordered),
        completed_at=max(p.received_at for p in ordered),
        requested_from=first.request.requested_from,
        requested_through=first.request.requested_through,
        pages=tuple(reconciliation_page(p) for p in ordered),
        cash=tuple(v for p in ordered for v in p.body.cash),
        positions=tuple(v for p in ordered for v in p.body.positions),
        orders=tuple(unique_orders[k] for k in sorted(unique_orders)),
        facts=tuple(f.observation for f in facts),
        currency="USD",
        account_modes=(("stateful-venue-model", "CASH"),),
        source_blockers=first.source_blockers,
    )
    return observed, facts


class ReconciliationTransitionResolver(Protocol):
    def resolve_transition(
        self, reference: CanonicalAccountTransitionRef, value: ContractRecord
    ) -> ResolvedReconciliationTransition: ...


class VenueReconciliationResolver:
    """Exact source interpretation plus required root-owned transition delegation."""

    def __init__(self, *, transition_resolver: ReconciliationTransitionResolver) -> None:
        self.transition_resolver = transition_resolver

    def resolve_source(
        self, reference: ReconciliationSourceRef, value: ContractRecord
    ) -> ReconciliationSourceContent:
        if (
            type(value) is not VenueCapturePage
            or reference.evidence.schema_id != VENUE_CAPTURE_SCHEMA
            or reference.evidence.semantic_sha256 != value.semantic_sha256
        ):
            raise VenueCaptureError("VENUE_CAPTURE_SOURCE_TYPE_OR_HASH_DIFFERS")
        return ReconciliationSourceContent(
            reference, reconciliation_page(value), source_commands(value)
        )

    def resolve_observation(
        self, manifest: ReconciliationSourceManifest, values: tuple[ContractRecord, ...]
    ) -> ObservationRound:
        if any(type(value) is not VenueCapturePage for value in values) or len(values) != len(
            manifest.sources
        ):
            raise VenueCaptureError("VENUE_CAPTURE_SOURCE_INVENTORY_DIFFERS")
        pages = tuple(value for value in values if isinstance(value, VenueCapturePage))
        observed, _ = resolve_venue_capture(pages)
        for source, value in zip(manifest.sources, pages, strict=True):
            self.resolve_source(source, value)
        if observed.scope != manifest.scope:
            raise VenueCaptureError("VENUE_CAPTURE_SOURCE_SCOPE_DIFFERS")
        return observed

    def resolve_source_order(
        self, manifest: ReconciliationSourceManifest, values: tuple[ContractRecord, ...]
    ) -> tuple[str, ...]:
        """Rebuild ordering from the authenticated caller's exact retained pages.

        This never accepts a caller's claimed ordering as source evidence.
        """
        self.resolve_observation(manifest, values)
        pages = sorted(
            (v for v in values if isinstance(v, VenueCapturePage)), key=lambda p: p.index
        )
        return tuple(
            f.fact_id for p in pages if p.body.fact_page is not None for f in p.body.fact_page.facts
        )

    def resolve_transition(
        self, reference: CanonicalAccountTransitionRef, value: ContractRecord
    ) -> ResolvedReconciliationTransition:
        return self.transition_resolver.resolve_transition(reference, value)
