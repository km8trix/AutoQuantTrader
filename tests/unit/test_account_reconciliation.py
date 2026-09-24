from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest

from packages.application.account_reconciliation import apply_reconciliation_facts
from packages.domain.accounting_contracts import (
    AccountingCommand,
    AccountingState,
    ControlCommand,
    ModelDisposition,
)
from packages.domain.ledger_reducer import CashFlowKind, LedgerEntryKind, create_cash_flow
from packages.domain.order_reducer import BrokerOrderEventKind
from packages.domain.reconciliation_application_contracts import (
    ReconciliationFactCommand,
    reconciliation_command_id,
)
from packages.domain.reconciliation_contracts import (
    FactObservation,
    ReconciliationOrderBinding,
    ReconciliationPage,
    ReconciliationScope,
)
from packages.domain.settlement_ledger import (
    create_settlement_confirmation,
    create_settlement_instruction,
)
from tests.unit.test_observed_accounting import OBSERVED, observed_order
from tests.unit.test_personal_accounting import POLICY, Harness

D = Decimal
SHA = "a" * 64


def scope(h):
    return ReconciliationScope(
        h.state.account_id, "independent-venue", "stateful_simulation", SHA, "stateful_simulation"
    )


def fill(h, commitment, *, quantity="4", price="100", fee="1"):
    return h.fill_event(commitment, quantity, price, fee)


def wrap(h, payload, *, parents=(), receipt_id=None, origin="application"):
    """Literal synthetic source page; no provider capture/authentication claim."""
    mapping = None
    revision = sequence = predecessor = None
    if hasattr(payload, "event_id"):
        identity, effective, received = payload.event_id, payload.occurred_at, payload.received_at
        kind = (
            "execution"
            if payload.kind is BrokerOrderEventKind.EXECUTION
            else (
                "correction"
                if payload.kind is BrokerOrderEventKind.EXECUTION_CORRECTION
                else "order"
            )
        )
        provider_id = payload.execution_id or payload.event_id
        revision = (
            str(payload.execution_revision) if payload.execution_revision is not None else None
        )
        sequence, predecessor = payload.broker_sequence, payload.supersedes_event_id
        mapping = ReconciliationOrderBinding(payload.order_id, payload.broker_order_id, SHA)
    elif hasattr(payload, "cash_flow_id"):
        identity, effective, received = (
            payload.cash_flow_id,
            payload.effective_at,
            payload.recorded_at,
        )
        kind, provider_id = "cash_flow", payload.external_reference
    elif hasattr(payload, "confirmation_id"):
        identity, effective, received = (
            payload.confirmation_id,
            payload.settled_at,
            payload.recorded_at,
        )
        kind, provider_id = "settlement", payload.external_reference
    else:
        identity, effective, received = (
            payload.instruction_id,
            payload.recorded_at,
            payload.recorded_at,
        )
        kind, provider_id = "settlement", payload.external_reference
    page = ReconciliationPage(
        operation="activity",
        receipt_id=receipt_id or "receipt-" + identity,
        scope_sha256=scope(h).semantic_sha256,
        query_sha256=SHA,
        request_sha256=SHA,
        body_sha256=payload.semantic_sha256,
        body_bytes=200,
        ordinal=0,
        requested_at=received,
        received_at=received,
        requested_from=effective,
        requested_through=received,
        cursor=None,
        next_cursor=None,
        termination="documented_end",
        terminal_evidence_sha256=SHA,
        selection="all_account",
    )
    observation = FactObservation(
        identity,
        payload.semantic_sha256,
        kind,
        provider_id,
        revision,
        sequence,
        page.receipt_id,
        effective,
        received,
        origin,
        predecessor,
    )
    return ReconciliationFactCommand(
        scope(h),
        observation,
        AccountingCommand(reconciliation_command_id(scope(h), observation), payload),
        page.semantic_sha256,
        mapping,
        tuple(sorted(parents)),
    ), page


def apply(
    h,
    pairs,
    *,
    prior=(),
    state=None,
    context=None,
    expected_scope=None,
    policy=OBSERVED,
    source_order=(),
):
    latest = max((page.received_at for _, page in pairs), default=h.at)
    context = context or replace(
        h.context(at=latest),
        point=replace(h.context(at=latest).point, stage=1),
    )
    return apply_reconciliation_facts(
        scope=expected_scope or scope(h),
        state=h.state if state is None else state,
        facts=tuple(item for item, _ in pairs),
        source_receipts=tuple(page for _, page in pairs),
        prior_applications=prior,
        context=context,
        accounting=h.port,
        policy=policy,
        source_order=source_order,
    )


def test_actual_fill_applies_once_with_real_ledger_order_links_and_no_modeled_settlement():
    h, c = observed_order()
    original = h.state
    pair = wrap(h, fill(h, c))
    result = apply(h, (pair,))
    assert result.current.snapshot.trade_date_cash == D(599)
    assert result.current.snapshot.settled_cash == D(1000)
    assert result.current.snapshot.trade_payable == D(401)
    assert result.current.snapshot.positions[0].quantity == D(4)
    assert result.state.settlement_instructions == result.state.settlement_confirmations == ()
    assert result.current.due_events == ()
    assert len(result.applications) == 1
    application = result.applications[0]
    entries = tuple(
        entry
        for entry in result.current.journal_entries
        if entry.source_sha256 == pair[0].observation.fact_sha256
    )
    assert {entry.kind for entry in entries} == {
        LedgerEntryKind.EXECUTION,
        LedgerEntryKind.SETTLEMENT_RECLASSIFICATION,
    }
    assert len(entries) == 2
    assert application.journal_entry_ids == tuple(sorted(entry.entry_id for entry in entries))
    assert application.order_event_ids == (pair[0].observation.fact_id,)
    assert application.canonical_fact_ids == (pair[0].observation.fact_id,)
    assert h.state == original
    duplicate = apply(
        h,
        (pair,),
        state=result.state,
        prior=result.applications,
        context=replace(
            h.context(at=pair[1].received_at), point=replace(result.current.snapshot.point, stage=1)
        ),
    )
    assert duplicate.state == result.state
    assert duplicate.duplicate_fact_ids == (pair[0].observation.fact_id,)
    assert duplicate.applications == result.applications


def test_overlap_receipt_does_not_change_canonical_command_identity():
    h, c = observed_order()
    event = fill(h, c)
    first = wrap(h, event)
    second = wrap(h, event, receipt_id="overlap-reread")
    assert first[0].command == second[0].command
    result = apply(h, (second, first))
    assert len(result.applications) == 1 and len(result.current.executions) == 1


def test_conflicting_revision_quarantines_both_while_independent_flow_posts():
    h, c = observed_order()
    event = fill(h, c)
    other = replace(event, price=D(101))
    flow = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=D(50),
        effective_at=event.received_at,
        recorded_at=event.received_at,
        external_reference="independent-deposit",
    )
    pairs = (wrap(h, event), wrap(h, other, receipt_id="conflict-receipt"), wrap(h, flow))
    result = apply(h, pairs)
    assert result.quarantined_fact_ids == (event.event_id,)
    assert result.current.snapshot.trade_date_cash == D(1050)
    assert result.current.snapshot.positions == ()
    assert tuple(a.fact_id for a in result.applications) == (flow.cash_flow_id,)
    assert apply(h, tuple(reversed(pairs))).state == result.state


@pytest.mark.parametrize(
    "field", ["source", "receipt", "scope", "sequence", "mapping", "payload_hash", "command"]
)
def test_exact_source_scope_mapping_sequence_and_payload_bindings_are_required(field):
    h, c = observed_order()
    item, page = wrap(h, fill(h, c))
    if field == "source":
        item = replace(item, source_sha256="b" * 64)
    elif field == "receipt":
        item = replace(item, observation=replace(item.observation, source_receipt_id="missing"))
    elif field == "scope":
        item = replace(item, scope=replace(item.scope, binding_sha256="b" * 64))
    elif field == "sequence":
        item = replace(item, observation=replace(item.observation, provider_sequence=None))
    elif field == "mapping":
        item = replace(item, mapping=replace(item.mapping, provider_order_id="other"))
    elif field == "payload_hash":
        item = replace(item, observation=replace(item.observation, fact_sha256="b" * 64))
    else:
        item = replace(item, command=replace(item.command, command_id="arbitrary"))
    result = apply(h, ((item, page),))
    assert result.state == h.state and result.quarantined_fact_ids == (item.observation.fact_id,)


def test_provider_scope_cannot_promote_observed_payload_to_qualified_application():
    h, c = observed_order()
    item, page = wrap(h, fill(h, c))
    provider = replace(
        item.scope,
        provider_id="etrade",
        source_class="provider_observation",
        environment="production",
    )
    page = replace(page, scope_sha256=provider.semantic_sha256)
    item = replace(
        item,
        scope=provider,
        source_sha256=page.semantic_sha256,
        command=replace(
            item.command, command_id=reconciliation_command_id(provider, item.observation)
        ),
    )
    result = apply(h, ((item, page),), expected_scope=provider)
    assert "PROVIDER_QUALIFICATION_REQUIRED" in result.reasons and result.state == h.state


def test_source_controls_and_model_dispositions_are_not_canonical_observed_facts():
    h, c = observed_order()
    item, page = wrap(h, fill(h, c))
    for payload in (
        ControlCommand(False, "attempt-clear"),
        ModelDisposition(c.commitment_id, "resolved_no_remaining", "fixture"),
    ):
        changed = replace(item, command=AccountingCommand(item.command.command_id, payload))
        result = apply(h, ((changed, page),))
        assert result.state == h.state
        assert "SOURCE_COMMAND_NOT_AN_OBSERVED_FACT" in result.reasons


def test_simulation_policy_cannot_be_used_as_observed_fact_consumption():
    h, c = observed_order()
    with pytest.raises(ValueError, match="observed-only"):
        apply(h, (wrap(h, fill(h, c)),), policy=POLICY)


def test_correction_uses_explicit_predecessor_and_preserves_original_postings():
    h, c = observed_order()
    original = fill(h, c)
    correction = replace(
        original,
        event_id="corrected",
        broker_sequence=3,
        occurred_at=original.occurred_at + timedelta(seconds=1),
        received_at=original.received_at + timedelta(seconds=1),
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        execution_revision=2,
        supersedes_event_id=original.event_id,
        quantity=D(3),
        price=D(101),
        fee=D(2),
    )
    first = wrap(h, original)
    corrected = wrap(h, correction, parents=(original.event_id,))
    result = apply(h, (corrected, first))
    assert result.current.snapshot.trade_date_cash == D(695)
    assert result.current.snapshot.trade_payable == D(401)
    assert result.current.snapshot.trade_receivable == D(96)
    assert result.current.snapshot.settled_cash == D(1000)
    assert result.current.snapshot.positions[0].quantity == D(3)
    assert {entry.reference_id for entry in result.current.journal_entries} >= {
        original.event_id,
        correction.event_id,
    }
    assert result.unresolved_fact_ids == result.quarantined_fact_ids == ()
    result = apply(h, (corrected,))
    assert result.unresolved_fact_ids == (correction.event_id,)
    no_parent = (replace(corrected[0], predecessor_fact_ids=()), corrected[1])
    assert apply(h, (no_parent, first)).quarantined_fact_ids == (correction.event_id,)


def test_explicit_instruction_is_nonposting_and_confirmation_settles_only_actual_fact():
    h, c = observed_order()
    event = fill(h, c)
    instruction = create_settlement_instruction(
        event,
        contractual_settlement_at=event.received_at + timedelta(days=1),
        recorded_at=event.received_at + timedelta(seconds=1),
        external_reference="instruction",
    )
    confirmation = create_settlement_confirmation(
        instruction,
        settled_at=event.received_at + timedelta(days=1),
        recorded_at=event.received_at + timedelta(days=1),
        external_reference="confirmation",
    )
    pairs = (wrap(h, event), wrap(h, instruction, parents=(event.event_id,)))
    pending = apply(h, pairs)
    instruction_application = next(
        a for a in pending.applications if a.fact_id == instruction.instruction_id
    )
    assert (
        instruction_application.journal_entry_ids == instruction_application.order_event_ids == ()
    )
    assert instruction_application.canonical_fact_ids == (instruction.instruction_id,)
    assert pending.current.snapshot.settled_cash == D(1000)
    assert pending.current.snapshot.trade_payable == D(401)
    settled = apply(
        h,
        (wrap(h, confirmation, parents=(instruction.instruction_id,)),),
        prior=pending.applications,
        state=pending.state,
        context=replace(
            h.context(at=confirmation.recorded_at),
            point=replace(
                pending.current.snapshot.point, knowledge_at=confirmation.recorded_at, stage=1
            ),
        ),
    )
    assert settled.current.snapshot.settled_cash == D(599)
    assert settled.current.snapshot.trade_payable == 0
    assert len(settled.applications[0].journal_entry_ids) == 1
    assert settled.current.due_events == ()


def test_neutral_correction_retains_real_order_fact_without_inventing_a_journal_entry():
    h, c = observed_order()
    original = fill(h, c)
    correction = replace(
        original,
        event_id="neutral-correction",
        broker_sequence=3,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        execution_revision=2,
        supersedes_event_id=original.event_id,
    )
    result = apply(h, (wrap(h, original), wrap(h, correction, parents=(original.event_id,))))
    corrected = next(a for a in result.applications if a.fact_id == correction.event_id)
    assert corrected.journal_entry_ids == ()
    assert corrected.order_event_ids == corrected.canonical_fact_ids == (correction.event_id,)
    assert result.current.snapshot.trade_date_cash == D(599)


def test_known_fact_overshoot_is_booked_and_halted_not_rejected_as_new_risk():
    h, c = observed_order(quantity="9", fee_budget="0")
    result = apply(h, (wrap(h, fill(h, c, quantity="9", price="120", fee="5")),))
    assert result.current.snapshot.trade_date_cash == D(-85)
    assert result.current.snapshot.trade_payable == D(1085)
    assert result.state.halted and "NEGATIVE_CASH_CAPACITY" in result.reasons
    assert len(result.applications) == 1


def test_pending_unknown_holds_are_not_an_application_input_or_release_output():
    h, c = observed_order(quantity="8")
    state = replace(
        h.state, commitments=(replace(h.state.commitments[0], state="unknown"),), halted=True
    )
    result = apply(h, (wrap(h, fill(h, c)),), state=state)
    assert result.state.halted and result.state.commitments[0].state == "unknown"
    assert result.state.commitments[0].remaining_quantity == 4
    assert result.current.snapshot.positions[0].quantity == 4
    assert not hasattr(result, "released_hold_ids")


def test_external_flow_is_booked_but_disposition_barrier_survives_retry():
    h = Harness(OBSERVED)
    at = h.at + timedelta(seconds=1)
    flow = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=D(50),
        effective_at=at,
        recorded_at=at,
        external_reference="external-deposit",
    )
    pair = wrap(h, flow, origin="external")
    result = apply(h, (pair,))
    assert result.current.snapshot.trade_date_cash == 1050
    assert "EXTERNAL_ACTIVITY_REQUIRES_OWNER_DISPOSITION" in result.reasons
    context = replace(h.context(at=at), point=replace(result.current.snapshot.point, stage=1))
    retry = apply(h, (pair,), state=result.state, prior=result.applications, context=context)
    assert "EXTERNAL_ACTIVITY_REQUIRES_OWNER_DISPOSITION" in retry.reasons


def test_retained_application_links_and_original_application_time_are_verified():
    h, c = observed_order()
    pair = wrap(h, fill(h, c))
    result = apply(h, (pair,))
    context = replace(
        h.context(at=pair[1].received_at), point=replace(result.current.snapshot.point, stage=1)
    )
    missing = apply(h, (pair,), state=result.state, context=context)
    assert "RETAINED_APPLICATION_RECEIPT_REQUIRED" in missing.reasons
    assert missing.applications == ()
    for bad in (
        replace(result.applications[0], journal_entry_ids=("fabricated",)),
        replace(
            result.applications[0], journal_entry_ids=result.applications[0].journal_entry_ids[:1]
        ),
        replace(result.applications[0], canonical_fact_ids=("fabricated",)),
        replace(result.applications[0], applied_at=pair[1].received_at + timedelta(days=1)),
    ):
        with pytest.raises(ValueError, match="actual canonical history"):
            apply(h, (pair,), state=result.state, prior=(bad,), context=context)


def test_broker_application_time_equals_retained_point_not_just_timestamp_bounds():
    h, c = observed_order()
    pair = wrap(h, fill(h, c))
    received = pair[1].received_at
    applied_at = received + timedelta(seconds=10)
    context = replace(
        h.context(at=applied_at), point=replace(h.context(at=applied_at).point, stage=1)
    )
    result = apply(h, (pair,), context=context)
    recorded = result.applications[0]
    assert (
        recorded.applied_at
        == dict(result.state.event_points)[recorded.fact_id].knowledge_at
        == applied_at
    )
    retry_at = applied_at + timedelta(seconds=10)
    retry_context = replace(
        h.context(at=retry_at),
        point=replace(result.current.snapshot.point, knowledge_at=retry_at, stage=1),
    )
    assert apply(
        h, (pair,), state=result.state, prior=result.applications, context=retry_context
    ).duplicate_fact_ids == (recorded.fact_id,)
    inside_old_bounds = replace(recorded, applied_at=received + timedelta(seconds=5))
    with pytest.raises(ValueError, match="actual canonical history"):
        apply(h, (pair,), state=result.state, prior=(inside_old_bounds,), context=retry_context)


def test_future_fact_and_missing_dependency_do_not_block_independent_funding():
    h, c = observed_order()
    event = fill(h, c)
    pair = wrap(h, event)
    missing = replace(pair[0], predecessor_fact_ids=("missing-parent",))
    result = apply(h, ((missing, pair[1]),))
    assert result.unresolved_fact_ids == (event.event_id,)
    context = replace(h.context(), point=replace(h.context().point, stage=1))
    result = apply(h, (pair,), context=context)
    assert result.quarantined_fact_ids == (event.event_id,) and result.state == h.state


def test_wrong_account_and_risk_approval_context_reject_before_accounting():
    h, c = observed_order()
    pair = wrap(h, fill(h, c))
    with pytest.raises(ValueError, match="exact account"):
        apply(h, (pair,), state=AccountingState("another-account"))
    approved = replace(h.context(), approved_snapshot=h.project().snapshot, risk_policy_sha256=SHA)
    with pytest.raises(ValueError, match="unapproved"):
        apply(h, (pair,), context=approved)


@pytest.mark.parametrize("case", ["missing", "extra", "duplicate", "list", "provider"])
def test_explicit_source_order_requires_exact_unique_stateful_fact_inventory(case):
    h = Harness(OBSERVED)
    at = h.at + timedelta(seconds=1)
    flows = tuple(
        create_cash_flow(
            kind=CashFlowKind.CONTRIBUTION,
            currency="USD",
            amount=D(1),
            effective_at=at,
            recorded_at=at,
            external_reference=f"source-order-{n}",
        )
        for n in range(2)
    )
    pairs = tuple(wrap(h, f) for f in flows)
    source_order = tuple(f.cash_flow_id for f in flows)
    selected_scope = scope(h)
    if case == "missing":
        source_order = source_order[:1]
    elif case == "extra":
        source_order = (*source_order, "absent-fact")
    elif case == "duplicate":
        source_order = (*source_order, source_order[0])
    elif case == "list":
        source_order = list(source_order)
    elif case == "provider":
        selected_scope = replace(
            selected_scope, environment="production", source_class="provider_observation"
        )
    with pytest.raises(ValueError, match="source order"):
        apply(h, pairs, source_order=source_order, expected_scope=selected_scope)


def test_explicit_source_order_is_not_a_dependency_on_quarantined_unrelated_fact():
    h = Harness(OBSERVED)
    at = h.at + timedelta(seconds=1)
    flows = tuple(
        create_cash_flow(
            kind=CashFlowKind.CONTRIBUTION,
            currency="USD",
            amount=D(7),
            effective_at=at,
            recorded_at=at,
            external_reference=f"ordered-independent-{n}",
        )
        for n in range(2)
    )
    bad, good = (wrap(h, flow) for flow in flows)
    bad = (replace(bad[0], source_sha256="0" * 64), bad[1])
    result = apply(h, (good, bad, good), source_order=tuple(f.cash_flow_id for f in flows))
    assert result.quarantined_fact_ids == (flows[0].cash_flow_id,)
    assert result.current.snapshot.trade_date_cash == 1007
    assert tuple(a.fact_id for a in result.applications) == (flows[1].cash_flow_id,)


def planned(h, pairs, *, source_order=(), prior=(), current=None):
    from packages.application.account_reconciliation import plan_reconciliation_facts

    at = max(page.received_at for _, page in pairs)
    context = replace(h.context(at=at), point=replace(h.context(at=at).point, stage=1))
    current = current or h.port.project(state=h.state, context=context, policy=OBSERVED)
    plan = plan_reconciliation_facts(
        scope=scope(h),
        current=current,
        facts=tuple(item for item, _ in pairs),
        source_receipts=tuple(page for _, page in pairs),
        prior_applications=prior,
        context=context,
        policy=OBSERVED,
        source_order=source_order,
    )
    return plan, current, context


def test_plan_is_pure_and_preserves_original_default_ready_round():
    from packages.application.account_reconciliation import reconciliation_ready_facts

    h, c = observed_order()
    event = fill(h, c)
    instruction = create_settlement_instruction(
        event,
        contractual_settlement_at=event.received_at + timedelta(days=1),
        recorded_at=event.received_at,
        external_reference="planned-instruction",
    )
    flow = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=D(7),
        effective_at=event.received_at,
        recorded_at=event.received_at,
        external_reference="independent-plan-flow",
    )
    pairs = (wrap(h, instruction, parents=(event.event_id,)), wrap(h, event), wrap(h, flow))
    before = h.state
    plan, current, _ = planned(h, pairs)
    ready = reconciliation_ready_facts(
        plan, pending_fact_ids=tuple(sorted(i.observation.fact_id for i in plan.candidates))
    )
    assert tuple(i.observation.fact_id for i in ready) == tuple(
        i.observation.fact_id
        for i in sorted(
            (pairs[1][0], pairs[2][0]),
            key=lambda i: (
                i.observation.received_at,
                i.observation.provider_sequence or 0,
                i.observation.fact_id,
            ),
        )
    )
    assert h.state == before and current.state == before
    assert plan.initial_state_sha256 == before.semantic_sha256
    assert not plan.quarantined_fact_ids


def test_dynamic_selector_uses_actual_rejected_parent_and_keeps_unrelated_flow():
    from packages.application.account_reconciliation import (
        check_reconciliation_candidate,
        reconciliation_ready_facts,
    )

    h, c = observed_order()
    event = replace(fill(h, c), order_id="absent-canonical-order")
    instruction = create_settlement_instruction(
        event,
        contractual_settlement_at=event.received_at + timedelta(days=1),
        recorded_at=event.received_at,
        external_reference="dependent-instruction",
    )
    flow = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=D(7),
        effective_at=event.received_at,
        recorded_at=event.received_at,
        external_reference="unrelated-funding",
    )
    pairs = (wrap(h, event), wrap(h, instruction, parents=(event.event_id,)), wrap(h, flow))
    plan, current, context = planned(
        h, pairs, source_order=(event.event_id, instruction.instruction_id, flow.cash_flow_id)
    )
    pending = tuple(sorted(i.observation.fact_id for i in plan.candidates))
    first = reconciliation_ready_facts(plan, pending_fact_ids=pending)
    assert first == (pairs[0][0],)
    assert (
        check_reconciliation_candidate(
            plan, first[0], current=current, blocked_fact_ids=()
        ).disposition
        == "apply"
    )
    actual = h.port.advance(
        state=current.state,
        command=first[0].command,
        context=replace(
            context,
            event_id=first[0].command.command_id,
            point=replace(context.point, reduction_sequence=context.point.reduction_sequence + 1),
        ),
        policy=OBSERVED,
    )
    assert actual.disposition == "rejected" and actual.state == current.state
    pending = tuple(i for i in pending if i != event.event_id)
    child = reconciliation_ready_facts(plan, pending_fact_ids=pending)[0]
    checked = check_reconciliation_candidate(
        plan, child, current=actual, blocked_fact_ids=(event.event_id,)
    )
    assert checked.disposition == "unresolved" and checked.reason == "FACT_DEPENDENCY_NOT_APPLIED"
    pending = tuple(i for i in pending if i != instruction.instruction_id)
    independent = reconciliation_ready_facts(plan, pending_fact_ids=pending)[0]
    assert independent == pairs[2][0]
    assert (
        check_reconciliation_candidate(
            plan,
            independent,
            current=actual,
            blocked_fact_ids=tuple(sorted((event.event_id, instruction.instruction_id))),
        ).disposition
        == "apply"
    )
    result = apply(h, pairs, source_order=plan.source_order)
    assert result.current.snapshot.trade_date_cash == 1007
    assert set(result.unresolved_fact_ids) == {event.event_id, instruction.instruction_id}
    assert tuple(a.fact_id for a in result.applications) == (flow.cash_flow_id,)


@pytest.mark.parametrize("invalid", ["unknown", "duplicate", "quarantine"])
def test_ready_selector_rejects_nonplan_or_quarantined_pending_inventory(invalid):
    from packages.application.account_reconciliation import reconciliation_ready_facts

    h, c = observed_order()
    pair = wrap(h, fill(h, c))
    if invalid == "quarantine":
        pair = (replace(pair[0], source_sha256="0" * 64), pair[1])
    plan, _, _ = planned(h, (pair,))
    identity = pair[0].observation.fact_id
    pending = (
        ("not-in-plan",)
        if invalid == "unknown"
        else (identity, identity)
        if invalid == "duplicate"
        else (identity,)
    )
    with pytest.raises(ValueError, match="exact admitted plan"):
        reconciliation_ready_facts(plan, pending_fact_ids=pending)


def test_application_helper_requires_actual_point_and_derives_all_canonical_effects():
    from packages.application.account_reconciliation import derive_reconciliation_application

    h, c = observed_order()
    item, page = wrap(h, fill(h, c))
    context = replace(
        h.context(at=page.received_at),
        event_id=item.command.command_id,
        point=replace(
            h.context(at=page.received_at).point, stage=1, reduction_sequence=h.sequence + 1
        ),
    )
    current = h.port.advance(state=h.state, command=item.command, context=context, policy=OBSERVED)
    receipt = derive_reconciliation_application(item, current=current, applied_context=context)
    assert receipt is not None and len(receipt.journal_entry_ids) == 2
    assert receipt.order_event_ids == (item.observation.fact_id,)
    assert (
        receipt.applied_at
        == dict(current.state.event_points)[item.observation.fact_id].knowledge_at
    )
    wrong = replace(
        context,
        point=replace(
            context.point, knowledge_at=context.point.knowledge_at + timedelta(seconds=1)
        ),
    )
    with pytest.raises(ValueError, match="exact actual"):
        derive_reconciliation_application(item, current=current, applied_context=wrong)
    reprojected = h.port.project(state=current.state, context=wrong, policy=OBSERVED)
    with pytest.raises(ValueError, match="actual application time"):
        derive_reconciliation_application(item, current=reprojected, applied_context=wrong)


def test_canonical_initial_cash_flow_point_is_supported_without_reapplication():
    from packages.application.account_reconciliation import derive_reconciliation_application

    h = Harness(OBSERVED)
    fact = h.state.cash_flows[0]
    item, _ = wrap(h, fact)
    context = replace(
        h.context(at=fact.recorded_at),
        event_id=fact.cash_flow_id,
        point=replace(h.context(at=fact.recorded_at).point, stage=1),
    )
    actual = h.port.advance(
        state=AccountingState(h.state.account_id),
        command=AccountingCommand(fact.cash_flow_id, fact),
        context=context,
        policy=OBSERVED,
    )
    receipt = derive_reconciliation_application(item, current=actual, applied_context=context)
    assert receipt is not None and receipt.canonical_fact_ids == (fact.cash_flow_id,)
    assert actual.snapshot.trade_date_cash == 1000
    with pytest.raises(ValueError, match="exact actual"):
        derive_reconciliation_application(
            item, current=actual, applied_context=replace(context, event_id="invented-command")
        )


def test_effective_boundary_preserves_instruction_receipt_instead_of_future_due():
    from packages.application.account_reconciliation import reconciliation_fact_effective_at

    h, c = observed_order()
    event = fill(h, c)
    instruction = create_settlement_instruction(
        event,
        contractual_settlement_at=event.received_at + timedelta(days=1),
        recorded_at=event.received_at,
        external_reference="dated-source-instruction",
    )
    assert reconciliation_fact_effective_at(wrap(h, event)[0]) == event.occurred_at
    assert (
        reconciliation_fact_effective_at(wrap(h, instruction, parents=(event.event_id,))[0])
        == instruction.recorded_at
    )
