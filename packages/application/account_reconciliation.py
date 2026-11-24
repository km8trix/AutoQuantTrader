"""Apply structurally bound observed facts through the canonical accounting port.

No transport, SQL, source authentication, risk authorization, hold release or
UNKNOWN disposition occurs here. The caller supplies an authenticated current
account context and retains the returned canonical history in its transaction.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime

from packages.domain.accounting_contracts import (
    AccountingContext,
    AccountingState,
    AccountingTransition,
    ExecutionAccountingPort,
    ExecutionPolicy,
)
from packages.domain.corporate_action_ledger import (
    CashDividendAccrual,
    CashDividendPayment,
    StockSplitAction,
)
from packages.domain.ledger_reducer import LedgerCashFlow
from packages.domain.order_reducer import BrokerOrderEvent, BrokerOrderEventKind
from packages.domain.reconciliation_application_contracts import (
    AppliedReconciliationBatch,
    ReconciliationCandidateCheck,
    ReconciliationFactCommand,
    ReconciliationFactPlan,
    reconciliation_command_id,
)
from packages.domain.reconciliation_contracts import (
    MAX_RECONCILIATION_ITEMS,
    MAX_RECONCILIATION_PAGES,
    FactApplication,
    ReconciliationPage,
    ReconciliationScope,
)
from packages.domain.settlement_ledger import (
    ExecutionSettlementConfirmation,
    ExecutionSettlementInstruction,
)

type _Fact = (
    BrokerOrderEvent
    | LedgerCashFlow
    | StockSplitAction
    | CashDividendAccrual
    | CashDividendPayment
    | ExecutionSettlementInstruction
    | ExecutionSettlementConfirmation
)
_FACT_TYPES = (
    BrokerOrderEvent,
    LedgerCashFlow,
    StockSplitAction,
    CashDividendAccrual,
    CashDividendPayment,
    ExecutionSettlementInstruction,
    ExecutionSettlementConfirmation,
)


def _identity(fact: _Fact) -> str:
    if isinstance(fact, BrokerOrderEvent):
        return fact.event_id
    if isinstance(fact, LedgerCashFlow):
        return fact.cash_flow_id
    if isinstance(fact, StockSplitAction):
        return fact.split_id
    if isinstance(fact, CashDividendAccrual):
        return fact.dividend_id
    if isinstance(fact, CashDividendPayment):
        return fact.payment_id
    if isinstance(fact, ExecutionSettlementInstruction):
        return fact.instruction_id
    return fact.confirmation_id


def _effective(fact: _Fact) -> datetime:
    if isinstance(fact, BrokerOrderEvent):
        return fact.occurred_at
    if isinstance(fact, CashDividendPayment):
        return fact.paid_at
    if isinstance(fact, ExecutionSettlementInstruction):
        # Contractual settlement is a declared future due date, not receipt-time cash.
        return fact.recorded_at
    if isinstance(fact, ExecutionSettlementConfirmation):
        return fact.settled_at
    return fact.effective_at


def _recorded(fact: _Fact) -> datetime:
    return fact.received_at if isinstance(fact, BrokerOrderEvent) else fact.recorded_at


def _parents(fact: _Fact) -> dict[str, str | None]:
    if isinstance(fact, BrokerOrderEvent) and fact.supersedes_event_id is not None:
        return {fact.supersedes_event_id: None}
    if isinstance(fact, CashDividendPayment):
        return {fact.dividend_id: fact.dividend_sha256}
    if isinstance(fact, ExecutionSettlementInstruction):
        return {fact.execution_event_id: fact.execution_event_sha256}
    if isinstance(fact, ExecutionSettlementConfirmation):
        return {fact.instruction_id: fact.instruction_sha256}
    return {}


def _inventory(state: AccountingState) -> dict[str, _Fact]:
    result: dict[str, _Fact] = {}
    values: tuple[_Fact, ...] = (
        *state.broker_events,
        *state.cash_flows,
        *state.stock_splits,
        *state.cash_dividends,
        *state.dividend_payments,
        *state.settlement_instructions,
        *state.settlement_confirmations,
    )
    for value in values:
        identity = _identity(value)
        if identity in result and result[identity] != value:
            raise ValueError("current canonical fact identities conflict")
        result[identity] = value
    return result


def _links(current: AccountingTransition, fact: _Fact) -> tuple[tuple[str, ...], tuple[str, ...]]:
    journal = tuple(
        sorted(
            entry.entry_id
            for entry in current.journal_entries
            # One source can produce both its trade-date entry and a separately
            # identified observed receivable/payable recognition entry.
            if entry.source_sha256 == fact.semantic_sha256
        )
    )
    orders = (
        (fact.event_id,)
        if isinstance(fact, BrokerOrderEvent) and fact in current.state.broker_events
        else ()
    )
    return journal, orders


def _application_valid(
    application: FactApplication,
    inventory: dict[str, _Fact],
    current: AccountingTransition,
    now: datetime,
) -> bool:
    """Recompute canonical links and broker application time, without SQL trust.

    Nonbroker facts do not retain an intrinsic application point in AccountingState.
    Their timestamp bounds are checked here; an immutable durable receipt must
    authenticate the exact originally recorded nonbroker application timestamp.
    """
    fact = inventory.get(application.fact_id)
    if (
        fact is None
        or fact.semantic_sha256 != application.fact_sha256
        or application.applied_at > now
    ):
        return False
    if isinstance(fact, BrokerOrderEvent):
        point = dict(current.state.event_points).get(fact.event_id)
        if point is None or point.knowledge_at != application.applied_at:
            return False
    journal, orders = _links(current, fact)
    return (
        application.journal_entry_ids == journal
        and application.order_event_ids == orders
        and application.canonical_fact_ids in ((), (application.fact_id,))
        and application.applied_at >= _recorded(fact)
    )


def _binding_reason(
    item: ReconciliationFactCommand,
    *,
    scope: ReconciliationScope,
    receipts: dict[str, ReconciliationPage],
    context: AccountingContext,
) -> str | None:
    observed, payload = item.observation, item.command.payload
    if item.scope != scope:
        return "FACT_SCOPE_MISMATCH"
    if scope.source_class != "stateful_simulation":
        return "PROVIDER_QUALIFICATION_REQUIRED"
    if type(payload) not in _FACT_TYPES:
        return "SOURCE_COMMAND_NOT_AN_OBSERVED_FACT"
    assert isinstance(payload, _FACT_TYPES)
    page = receipts.get(observed.source_receipt_id)
    if (
        page is None
        or page.semantic_sha256 != item.source_sha256
        or page.scope_sha256 != scope.semantic_sha256
        or observed.received_at != page.received_at
        or page.received_at > context.point.knowledge_at
        or page.body_bytes == 0
    ):
        return "FACT_RECEIPT_BINDING_MISMATCH"
    if page.operation not in (
        ("activity", "orders_current", "orders_history")
        if isinstance(payload, BrokerOrderEvent)
        else ("activity",)
    ):
        return "FACT_RECEIPT_OPERATION_MISMATCH"
    if (
        observed.fact_id != _identity(payload)
        or observed.fact_sha256 != payload.semantic_sha256
        or item.command.command_id != reconciliation_command_id(scope, observed)
        or observed.effective_at != _effective(payload)
        or not _recorded(payload) <= observed.received_at <= context.point.knowledge_at
        or _effective(payload) > context.economic_at
    ):
        return "CANONICAL_FACT_ENVELOPE_MISMATCH"
    if not set(_parents(payload)) <= set(item.predecessor_fact_ids):
        return "CANONICAL_PREDECESSOR_DECLARATION_REQUIRED"
    if isinstance(payload, BrokerOrderEvent):
        kind = (
            "execution"
            if payload.kind is BrokerOrderEventKind.EXECUTION
            else "correction"
            if payload.kind is BrokerOrderEventKind.EXECUTION_CORRECTION
            else "order"
        )
        if (
            item.mapping is None
            or item.mapping.order_id != payload.order_id
            or item.mapping.provider_order_id != payload.broker_order_id
            or observed.provider_sequence != payload.broker_sequence
            or observed.provider_fact_id != (payload.execution_id or payload.event_id)
            or observed.provider_revision
            != (str(payload.execution_revision) if payload.execution_revision is not None else None)
            or observed.predecessor_fact_id != payload.supersedes_event_id
            or observed.kind != kind
        ):
            return "ORDER_FACT_IDENTITY_OR_SEQUENCE_MISMATCH"
    else:
        kind = (
            "cash_flow"
            if isinstance(payload, LedgerCashFlow)
            else (
                "settlement"
                if isinstance(
                    payload, (ExecutionSettlementInstruction, ExecutionSettlementConfirmation)
                )
                else "corporate_action"
            )
        )
        if item.mapping is not None or observed.kind != kind or observed.provider_fact_id is None:
            return "NONORDER_FACT_IDENTITY_MISMATCH"
    return None


def _content(item: ReconciliationFactCommand) -> tuple[object, ...]:
    observed = item.observation
    return (
        item.scope,
        item.command,
        item.mapping,
        item.predecessor_fact_ids,
        observed.fact_id,
        observed.fact_sha256,
        observed.kind,
        observed.provider_fact_id,
        observed.provider_revision,
        observed.provider_sequence,
        observed.effective_at,
        observed.origin,
        observed.predecessor_fact_id,
    )


def _require_observed_context(
    scope: ReconciliationScope,
    state: AccountingState,
    context: AccountingContext,
    policy: ExecutionPolicy,
) -> None:
    if (
        policy.model_id != "observed-facts-v1"
        or policy.settlement_model != "observed-only-v1"
        or policy.correction_settlement != "explicit-only-v1"
        or policy.terminal_model != "observed-only-v1"
    ):
        raise ValueError("observed-only accounting policy is required")
    if (
        state.account_id != scope.account_id
        or context.approved_snapshot is not None
        or context.risk_policy_sha256 is not None
    ):
        raise ValueError("application requires the exact account and an unapproved fact context")
    if context.point.stage != 1:
        raise ValueError("observed application requires the coordinator fact stage")


def plan_reconciliation_facts(
    *,
    scope: ReconciliationScope,
    current: AccountingTransition,
    facts: tuple[ReconciliationFactCommand, ...],
    source_receipts: tuple[ReconciliationPage, ...],
    prior_applications: tuple[FactApplication, ...],
    context: AccountingContext,
    policy: ExecutionPolicy,
    source_order: tuple[str, ...] = (),
) -> ReconciliationFactPlan:
    """Validate source bindings without posting, invoking a port or authorizing risk.

    Consumers must use actual canonical accounting outcomes to resolve dependencies.
    This plan is an immutable structural value, not retained-source authentication.
    """
    state = current.state
    if (
        current.snapshot.point != context.point
        or current.snapshot.state_sha256 != state.semantic_sha256
    ):
        raise ValueError("planning requires the exact current fact-stage projection")
    _require_observed_context(scope, state, context, policy)
    for values, maximum in (
        (facts, MAX_RECONCILIATION_ITEMS),
        (source_receipts, MAX_RECONCILIATION_PAGES),
        (prior_applications, MAX_RECONCILIATION_ITEMS),
    ):
        if type(values) is not tuple or len(values) > maximum:
            raise ValueError("application input exceeds immutable bound")
    if (
        any(type(item) is not ReconciliationFactCommand for item in facts)
        or any(type(page) is not ReconciliationPage for page in source_receipts)
        or any(type(item) is not FactApplication for item in prior_applications)
    ):
        raise ValueError("application requires exact immutable input records")
    # Optional order is supplied only by an authenticated stateful source closure.
    # It is not a dependency edge, provider sequence, or authority assertion.
    if type(source_order) is not tuple or len(source_order) > MAX_RECONCILIATION_ITEMS:
        raise ValueError("source order exceeds immutable bound")
    if source_order:
        if scope.source_class != "stateful_simulation" or any(
            type(identity) is not str for identity in source_order
        ):
            raise ValueError("source order requires stateful simulation identities")
        if len(set(source_order)) != len(source_order) or set(source_order) != {
            item.observation.fact_id for item in facts
        }:
            raise ValueError("source order must exactly cover distinct supplied facts")
    if context.point.stage != 1:
        raise ValueError("observed application requires the coordinator fact stage")
    inventory = _inventory(state)
    prior: dict[str, FactApplication] = {}
    for application in prior_applications:
        if (
            application.fact_id in prior and prior[application.fact_id] != application
        ) or not _application_valid(application, inventory, current, context.point.knowledge_at):
            raise ValueError("retained application does not bind actual canonical history")
        prior[application.fact_id] = application
    receipts: dict[str, ReconciliationPage] = {}
    for page in source_receipts:
        if page.receipt_id in receipts and receipts[page.receipt_id] != page:
            raise ValueError("retained page identity has conflicting content")
        receipts[page.receipt_id] = page
    candidates: dict[str, ReconciliationFactCommand] = {}
    quarantine: set[str] = set()
    reasons: set[str] = set()
    provider_ids: dict[tuple[str, str, str | None], str] = {}
    for item in facts:
        identity = item.observation.fact_id
        reason = _binding_reason(item, scope=scope, receipts=receipts, context=context)
        if reason is not None:
            quarantine.add(identity)
            reasons.add(reason)
        if item.observation.origin == "external":
            reasons.add("EXTERNAL_ACTIVITY_REQUIRES_OWNER_DISPOSITION")
        if identity in candidates and _content(candidates[identity]) != _content(item):
            quarantine.add(identity)
            reasons.add("CANONICAL_FACT_ID_CONFLICT")
        observed = item.observation
        if observed.provider_fact_id is not None:
            category = "execution" if observed.kind == "correction" else observed.kind
            key = (category, observed.provider_fact_id, observed.provider_revision)
            if key in provider_ids and provider_ids[key] != identity:
                quarantine.update((identity, provider_ids[key]))
                reasons.add("PROVIDER_FACT_IDENTITY_ALIAS")
            provider_ids[key] = identity
        # Pick a deterministic receipt for identical overlap deliveries.
        existing = candidates.get(identity)
        if existing is None or item.semantic_sha256 < existing.semantic_sha256:
            candidates[identity] = item

    return ReconciliationFactPlan(
        scope=scope,
        initial_state_sha256=state.semantic_sha256,
        context=context,
        candidates=tuple(candidates[key] for key in sorted(candidates)),
        prior_applications=tuple(prior[key] for key in sorted(prior)),
        quarantined_fact_ids=tuple(sorted(quarantine)),
        reasons=tuple(sorted(reasons)),
        source_order=source_order,
    )


def reconciliation_ready_facts(
    plan: ReconciliationFactPlan, *, pending_fact_ids: tuple[str, ...]
) -> tuple[ReconciliationFactCommand, ...]:
    """Return one original ready round, or one source-ordered ready fact.

    An empty result with nonempty pending IDs denotes a dependency cycle. Process
    the returned round in order and check each candidate against actual outcomes.
    This preserves the legacy default round ordering; explicit source_order instead
    recomputes readiness after every step so newly ready early facts are not delayed.
    """
    candidates = {item.observation.fact_id: item for item in plan.candidates}
    if (
        type(pending_fact_ids) is not tuple
        or pending_fact_ids != tuple(sorted(set(pending_fact_ids)))
        or not set(pending_fact_ids) <= set(candidates) - set(plan.quarantined_fact_ids)
    ):
        raise ValueError("pending facts differ from the exact admitted plan")
    pending = set(pending_fact_ids)
    ready = [
        candidates[identity]
        for identity in pending
        if not set(candidates[identity].predecessor_fact_ids) & pending
    ]
    if plan.source_order:
        positions = {identity: index for index, identity in enumerate(plan.source_order)}
        ready.sort(key=lambda item: positions[item.observation.fact_id])
        return tuple(ready[:1])
    ready.sort(
        key=lambda item: (
            item.observation.received_at,
            item.observation.provider_sequence or 0,
            item.observation.fact_id,
        )
    )
    return tuple(ready)


def check_reconciliation_candidate(
    plan: ReconciliationFactPlan,
    item: ReconciliationFactCommand,
    *,
    current: AccountingTransition,
    blocked_fact_ids: tuple[str, ...],
) -> ReconciliationCandidateCheck:
    """Check dependency results from actual current history, never planned success."""
    candidates = {value.observation.fact_id: value for value in plan.candidates}
    identity = item.observation.fact_id
    if candidates.get(identity) != item or identity in plan.quarantined_fact_ids:
        raise ValueError("candidate is outside the admitted plan")
    if (
        current.state.account_id != plan.scope.account_id
        or current.snapshot.point.knowledge_at > plan.context.point.knowledge_at
        or type(blocked_fact_ids) is not tuple
        or blocked_fact_ids != tuple(sorted(set(blocked_fact_ids)))
        or not set(blocked_fact_ids) <= set(candidates)
    ):
        raise ValueError("candidate outcomes differ from the exact planning scope")
    inventory = _inventory(current.state)
    dependencies = set(item.predecessor_fact_ids)
    if not dependencies <= set(inventory) or dependencies & (
        set(plan.quarantined_fact_ids) | set(blocked_fact_ids)
    ):
        return ReconciliationCandidateCheck("unresolved", reason="FACT_DEPENDENCY_NOT_APPLIED")
    payload = item.command.payload
    if not isinstance(payload, _FACT_TYPES):
        raise ValueError("planned candidate has no supported observed payload")
    if any(
        digest is not None and inventory[parent].semantic_sha256 != digest
        for parent, digest in _parents(payload).items()
    ):
        return ReconciliationCandidateCheck(
            "quarantined", reason="CANONICAL_PREDECESSOR_CONTENT_MISMATCH"
        )
    retained = inventory.get(identity)
    if retained is None:
        return ReconciliationCandidateCheck("apply")
    if retained != payload:
        return ReconciliationCandidateCheck(
            "quarantined", reason="RETAINED_CANONICAL_FACT_CONFLICT"
        )
    prior = {value.fact_id: value for value in plan.prior_applications}.get(identity)
    if prior is None:
        return ReconciliationCandidateCheck(
            "unresolved", reason="RETAINED_APPLICATION_RECEIPT_REQUIRED"
        )
    if not _application_valid(prior, inventory, current, plan.context.point.knowledge_at):
        raise ValueError("retained application no longer binds actual canonical history")
    return ReconciliationCandidateCheck("duplicate", application=prior)


def reconciliation_fact_effective_at(item: ReconciliationFactCommand) -> datetime:
    """Canonical economic boundary, preserving instruction-receipt semantics."""
    if not isinstance(item.command.payload, _FACT_TYPES):
        raise ValueError("source command is not an observed fact")
    return _effective(item.command.payload)


def derive_reconciliation_application(
    item: ReconciliationFactCommand,
    *,
    current: AccountingTransition,
    applied_context: AccountingContext,
) -> FactApplication | None:
    """Link an actual successful fact-stage transition, without reapplying it.

    The caller retains the transition returned by its canonical engine/port before
    any later valuation projection. In particular, nonbroker original application
    time comes from that exact engine-issued context; this helper cannot authenticate
    arbitrary caller-constructed transitions or establish durable source authority.
    """
    payload = item.command.payload
    if (
        not isinstance(payload, _FACT_TYPES)
        or item.observation.fact_id != _identity(payload)
        or item.observation.fact_sha256 != payload.semantic_sha256
        or item.observation.effective_at != _effective(payload)
        or item.command.command_id != reconciliation_command_id(item.scope, item.observation)
        or applied_context.point.stage != 1
        or current.snapshot.point != applied_context.point
        or applied_context.event_id
        not in (
            (item.command.command_id, payload.cash_flow_id)
            if isinstance(payload, LedgerCashFlow)
            else (item.command.command_id,)
        )
        or applied_context.approved_snapshot is not None
        or applied_context.risk_policy_sha256 is not None
        or current.state.account_id != item.scope.account_id
        or current.snapshot.state_sha256 != current.state.semantic_sha256
        or current.disposition == "rejected"
        or _inventory(current.state).get(item.observation.fact_id) != payload
    ):
        raise ValueError("application requires the exact actual canonical fact-stage transition")
    journal, orders = _links(current, payload)
    if isinstance(payload, ExecutionSettlementConfirmation) and not journal:
        return None
    if not journal and not orders and not isinstance(payload, ExecutionSettlementInstruction):
        return None
    application = FactApplication(
        item.observation.fact_id,
        payload.semantic_sha256,
        applied_context.point.knowledge_at,
        journal,
        orders,
        (item.observation.fact_id,),
    )
    if not _application_valid(
        application, _inventory(current.state), current, applied_context.point.knowledge_at
    ):
        raise ValueError("actual application time or canonical links differ")
    return application


def apply_reconciliation_facts(
    *,
    scope: ReconciliationScope,
    state: AccountingState,
    facts: tuple[ReconciliationFactCommand, ...],
    source_receipts: tuple[ReconciliationPage, ...],
    prior_applications: tuple[FactApplication, ...],
    context: AccountingContext,
    accounting: ExecutionAccountingPort,
    policy: ExecutionPolicy,
    source_order: tuple[str, ...] = (),
) -> AppliedReconciliationBatch:
    """Consume exact facts once, retaining independent postings and all blockers.

    Caller-owned context has no risk approval. Source hashes bind retained pages
    structurally; they are not authenticated here. No supplied source fact may
    clear a control or trigger modeled venue settlement/acceptance. Optional
    source_order comes from a separately authenticated complete source inventory;
    constructors and this pure function cannot establish that authentication.
    """
    _require_observed_context(scope, state, context, policy)
    current = accounting.project(state=state, context=context, policy=policy)
    plan = plan_reconciliation_facts(
        scope=scope,
        current=current,
        facts=facts,
        source_receipts=source_receipts,
        prior_applications=prior_applications,
        context=context,
        policy=policy,
        source_order=source_order,
    )
    inventory = _inventory(state)
    quarantine = set(plan.quarantined_fact_ids)
    unresolved: set[str] = set()
    reasons = set(plan.reasons)
    applications: dict[str, FactApplication] = {}
    duplicate: set[str] = set()
    pending = {item.observation.fact_id for item in plan.candidates} - quarantine
    sequence = context.point.reduction_sequence
    while pending:
        ready = reconciliation_ready_facts(plan, pending_fact_ids=tuple(sorted(pending)))
        if not ready:
            unresolved.update(pending)
            reasons.add("CYCLIC_FACT_DEPENDENCY")
            break
        for item in ready:
            identity = item.observation.fact_id
            pending.remove(identity)
            checked = check_reconciliation_candidate(
                plan,
                item,
                current=current,
                blocked_fact_ids=tuple(sorted(quarantine | unresolved)),
            )
            if checked.disposition != "apply":
                if checked.disposition == "duplicate":
                    assert checked.application is not None
                    applications[identity] = checked.application
                    duplicate.add(identity)
                else:
                    (quarantine if checked.disposition == "quarantined" else unresolved).add(
                        identity
                    )
                    assert checked.reason is not None
                    reasons.add(checked.reason)
                continue
            payload = item.command.payload
            assert isinstance(payload, _FACT_TYPES)
            sequence += 1
            step_context = replace(
                context,
                event_id=item.command.command_id,
                point=replace(context.point, reduction_sequence=sequence),
            )
            transition = accounting.advance(
                state=state, command=item.command, context=step_context, policy=policy
            )
            if transition.disposition == "rejected":
                unresolved.add(identity)
                reasons.add("CANONICAL_ACCOUNTING_REJECTED_FACT")
                continue
            if transition.due_events:
                raise ValueError("observed accounting emitted a modeled due event")
            updated = _inventory(transition.state)
            if (
                transition.state.account_id != scope.account_id
                or any(updated.get(key) != value for key, value in inventory.items())
                or (state.halted and not transition.state.halted)
            ):
                raise ValueError("accounting result replaced history or cleared a retained halt")
            if updated.get(identity) != payload:
                raise ValueError("accounting result omitted the exact observed canonical fact")
            state = transition.state
            inventory = updated
            current = accounting.project(state=state, context=step_context, policy=policy)
            application = derive_reconciliation_application(
                item, current=current, applied_context=step_context
            )
            if application is None:
                unresolved.add(identity)
                reasons.add(
                    "SETTLEMENT_CONFIRMATION_POSTING_UNAVAILABLE"
                    if isinstance(payload, ExecutionSettlementConfirmation)
                    else "CANONICAL_ECONOMIC_APPLICATION_UNAVAILABLE"
                )
                continue
            applications[identity] = application
            reasons.update(transition.reasons)
            if item.observation.origin == "external":
                reasons.add("EXTERNAL_ACTIVITY_REQUIRES_OWNER_DISPOSITION")
    final_context = replace(context, point=replace(context.point, reduction_sequence=sequence))
    current = accounting.project(state=state, context=final_context, policy=policy)
    return AppliedReconciliationBatch(
        state,
        current,
        tuple(applications[key] for key in sorted(applications)),
        tuple(sorted(duplicate)),
        tuple(sorted(unresolved - quarantine)),
        tuple(sorted(quarantine)),
        tuple(sorted(reasons)),
    )
