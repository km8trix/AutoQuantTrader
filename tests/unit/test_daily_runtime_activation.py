"""Actual canonical accounting with explicitly synthetic runtime provenance."""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal, Inexact, Rounded, localcontext
from uuid import uuid4

import pytest

from packages.application.daily_commitment_install import prepare_daily_commitments
from packages.application.daily_runtime_activation import prepare_daily_runtime_activation
from packages.application.personal_codec import decode_record, encode_record
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.accounting_contracts import (
    AccountingCommand,
    AccountingState,
    ActivateRuntimeCommitments,
)
from packages.domain.daily_attempt import (
    daily_fence_reference,
    prepare_daily_activation,
    prepare_daily_attempt,
    prepare_daily_dispatch,
    reduce_daily_attempt,
)
from packages.domain.daily_attempt_contracts import DailyAttemptEvent, DailyVenueSubmissionRequest
from packages.domain.daily_risk import evaluate_daily_risk
from packages.domain.daily_runtime_contracts import RuntimeCommitmentBinding, RuntimeRiskAdmission
from packages.domain.models import Side
from packages.domain.personal_contracts import VersionPin
from packages.domain.portfolio import daily_target_to_intents
from packages.domain.submission_attempt import SubmissionAttemptState
from tests.unit.test_account_coordinator import coordinator
from tests.unit.test_daily_attempt import rebind_case, reference
from tests.unit.test_daily_commitment_install import install_case
from tests.unit.test_daily_risk_snapshot import END, START, build, runtime_case
from tests.unit.test_daily_target_conversion import EXECUTION, NOW, PIN
from tests.unit.test_stateful_venue import model

D = Decimal


@pytest.fixture(scope="module")
def fence():
    owner, clock, _ = coordinator(f"runtime-activation-canonical-account-{uuid4().hex}")
    clock.instant = START
    return daily_fence_reference(
        owner.revalidate(owner.acquire("explicit-runtime-test-owner").fence)
    )


def scoped(case, instruments, *, fence):
    case = (replace(case[0], instrument_symbols=instruments), *case[1:])
    return rebind_case(case, account_id=fence.fence.account_id)


def case(fence, *, two=False, price="100", sell=False):
    raw = install_case(two=two)
    policy = replace(
        raw["execution_policy"],
        model_id="observed-facts-v1",
        settlement_model="observed-only-v1",
        correction_settlement="explicit-only-v1",
        terminal_model="observed-only-v1",
    )
    port = PersonalAccounting()
    state = AccountingState(fence.fence.account_id)
    context = raw["context"]
    start_sequence = 1
    payloads = (*raw["state"].cash_flows, *raw["state"].marks)
    if sell:
        from packages.domain.order_reducer import BrokerOrderEvent, BrokerOrderEventKind
        from tests.unit.test_personal_accounting import Harness

        h = Harness(policy, base=NOW - timedelta(minutes=1), funding="10000")
        opening = h.install("retained-opening", "10", "100", ".10", activate=False)
        at = h.at + timedelta(seconds=1)
        ack = BrokerOrderEvent(
            event_id="opening-ack",
            order_id=opening.order_id,
            broker_order_id="opening-venue-order",
            broker_sequence=1,
            occurred_at=at,
            received_at=at,
            kind=BrokerOrderEventKind.ACCEPTED,
        )
        assert h.apply(ack, at=at).disposition == "applied"
        assert h.fill(opening, "10", "100", ".10").disposition == "applied"
        state = replace(h.state, account_id=state.account_id)
        payloads = raw["state"].marks
        start_sequence = h.sequence + 1
        context = replace(context, point=replace(context.point, frontier_sequence=h.frontier + 1))
    # Replay canonical facts; the SELL fixture retains an actual observed opening fill/payable.
    for index, payload in enumerate(payloads, start_sequence):
        context = replace(context, point=replace(context.point, reduction_sequence=index, stage=2))
        result = port.advance(
            state=state,
            command=AccountingCommand("bootstrap-" + str(index), payload),
            context=context,
            policy=policy,
        )
        assert result.disposition == "applied", result.reasons
        state = result.state
    context = replace(
        context,
        point=replace(
            context.point, reduction_sequence=context.point.reduction_sequence + 1, stage=5
        ),
    )
    snapshot = port.project(state=state, context=context, policy=policy).snapshot
    target = replace(raw["batch"].target, not_before=START, expires_at=END)
    if sell:
        from packages.domain.models import PositionTarget

        target = replace(target, targets=(PositionTarget("spy", "SPY", D(0)),))
    batch = daily_target_to_intents(target, snapshot, strategy_pin=PIN)
    initial = scoped(runtime_case(snapshot=snapshot, batch=batch), context.instruments, fence=fence)
    evidence = build(initial)
    decision = evaluate_daily_risk(initial[0].policy, snapshot, batch, evidence, NOW)
    assert decision.approved, decision.reasons
    installed = prepare_daily_commitments(
        state=state,
        snapshot=snapshot,
        batch=batch,
        decision=decision,
        context=context,
        execution_policy=policy,
        risk_policy=initial[0].policy,
        accounting=port,
        attempt_namespace="daily-runtime-attempt",
    )
    assert installed.disposition == "installed", installed.reasons
    admission = RuntimeRiskAdmission(
        evidence=evidence, decision=decision, recorded_at=NOW, expires_at=NOW + timedelta(seconds=5)
    )
    holds = tuple(
        RuntimeCommitmentBinding(
            account_id=state.account_id,
            commitment=c,
            origin="daily_runtime",
            source_id=c.intent_id,
            source_sha256=admission.semantic_sha256,
            original_policy_sha256=c.policy_sha256,
            projection=VersionPin("fixture-hold", "1", "a" * 64),
        )
        for c in installed.commitments
    )
    venue = model()
    attempts = []
    for hold in holds:
        submission = next(
            s for s in installed.state.submissions if s.order_id == hold.commitment.order_id
        )
        request = DailyVenueSubmissionRequest(
            submission=submission,
            original_commitment=hold.commitment,
            source_account_id=state.account_id,
            source_account_binding_sha256=initial[0].account_binding_sha256,
            venue_account_id=venue.account_id,
            venue_model=reference(venue),
            original_admission_sha256=admission.semantic_sha256,
        )
        prep = prepare_daily_attempt(
            request=request,
            original_admission=admission,
            admission_source=reference(admission),
            original_hold=hold,
            prepared_at=NOW,
        )
        event = DailyAttemptEvent(
            attempt_id=prep.attempt_id,
            sequence=1,
            previous_event_sha256=None,
            state=SubmissionAttemptState.PENDING,
            recorded_at=NOW,
        )
        attempts.append(reduce_daily_attempt(prep, (event,)))
    state = installed.state
    context = replace(
        context,
        economic_at=START,
        expected_mark_session=EXECUTION,
        point=replace(
            context.point,
            knowledge_at=START,
            reduction_sequence=installed.last_reduction_sequence + 1,
            frontier_sequence=context.point.frontier_sequence + 1,
            stage=2,
        ),
    )
    for mark in raw["state"].marks:
        fresh = replace(
            mark,
            mark_id="quote-" + mark.instrument_id,
            price=D(price),
            session=EXECUTION,
            economic_at=START,
            knowledge_at=START,
            basis="runtime_quote_bid_v1" if sell else "runtime_quote_ask_v1",
        )
        result = port.advance(
            state=state,
            command=AccountingCommand(fresh.mark_id, fresh),
            context=context,
            policy=policy,
        )
        assert result.disposition == "applied", result.reasons
        state = result.state
        context = replace(
            context,
            point=replace(context.point, reduction_sequence=context.point.reduction_sequence + 1),
        )
    context = replace(context, point=replace(context.point, stage=5))
    snapshot = port.project(state=state, context=context, policy=policy).snapshot
    fresh_batch = replace(batch, snapshot_sha256=snapshot.semantic_sha256)
    current = scoped(
        runtime_case(
            snapshot=snapshot,
            batch=fresh_batch,
            phase="activation",
            now=START,
            bindings=tuple(
                sorted(
                    (*initial[3].obligations.bindings, *holds),
                    key=lambda item: item.commitment.commitment_id,
                )
            ),
        ),
        context.instruments,
        fence=fence,
    )
    current = (
        *current[:3],
        replace(current[3], accepted_intent_ids=tuple(sorted(i.intent_id for i in batch.intents))),
        *current[4:],
    )
    current = scoped(current, context.instruments, fence=fence)
    evidence = build(current)
    decision = evaluate_daily_risk(current[0].policy, snapshot, fresh_batch, evidence, START)
    assert decision.approved, decision.reasons
    dispatches = []
    for attempt, hold in zip(attempts, holds, strict=True):
        activation = prepare_daily_activation(
            preparation=attempt.preparation,
            current_hold=hold,
            snapshot=snapshot,
            evidence=evidence,
            decision=decision,
            heads=current[3].heads,
            fence=fence,
            checked_at=START,
        )
        dispatches.append(
            prepare_daily_dispatch(
                attempt=attempt,
                activation=activation,
                command_id="send-" + attempt.attempt_id,
                dispatched_at=START,
            )
        )
    context = replace(
        context,
        point=replace(
            context.point, stage=7, reduction_sequence=context.point.reduction_sequence + 1
        ),
        approved_snapshot=snapshot,
        risk_policy_sha256=current[0].policy.semantic_sha256,
    )
    return dict(
        state=state,
        context=context,
        execution_policy=policy,
        attempts=tuple(attempts),
        dispatches=tuple(dispatches),
        accounting=port,
    )


@pytest.mark.parametrize("price", ["80", "100", "120"])
@pytest.mark.parametrize("two", [False, True])
def test_real_helper_replaces_entire_reserve_once_without_acknowledgement(fence, price, two):
    values = case(fence, two=two, price=price)
    before = values["context"].approved_snapshot
    result = prepare_daily_runtime_activation(**values)
    expected = (D(price) * D("1.01") * D(10) + D(".10")) * (2 if two else 1)
    assert result.transition.snapshot.available_cash == D(10000) - expected
    assert result.transition.snapshot.buy_reserve == expected
    assert result.transition.snapshot.trade_date_cash == before.trade_date_cash == D(10000)
    assert result.transition.snapshot.trade_payable == before.trade_payable == 0
    assert result.transition.state.broker_events == values["state"].broker_events == ()
    assert result.transition.state.submissions == values["state"].submissions
    assert result.transition.journal_entries == result.transition.due_events == ()
    assert result.transition.state.settlement_instructions == ()
    assert result.transition.state.revision == values["state"].revision + 1
    for new in result.commitments:
        old = next(c for c in values["state"].commitments if c.commitment_id == new.commitment_id)
        assert new == replace(
            old,
            reserved_cash=D(price) * D("1.01") * D(10) + D(".10"),
            approved_price=D(price) * D("1.01"),
            state="active",
            activated_at=START,
            activation_sequence=values["context"].point.reduction_sequence,
            activation_frontier=values["context"].point.frontier_sequence,
        )
    assert (
        decode_record(encode_record(result.command.payload), ActivateRuntimeCommitments)
        == result.command.payload
    )
    retry = values["accounting"].advance(
        state=result.transition.state,
        command=result.command,
        context=replace(
            values["context"], point=replace(values["context"].point, knowledge_at=END)
        ),
        policy=values["execution_policy"],
    )
    assert retry.disposition == "duplicate" and retry.state == result.transition.state


def test_batch_permutation_is_identical_and_subset_or_duplicate_cannot_reuse_approval(fence):
    values = case(fence, two=True, price="120")
    normal = prepare_daily_runtime_activation(**values)
    reverse = prepare_daily_runtime_activation(
        **{
            **values,
            "attempts": tuple(reversed(values["attempts"])),
            "dispatches": tuple(reversed(values["dispatches"])),
        }
    )
    assert normal == reverse
    for changed in (
        {"attempts": values["attempts"][:1], "dispatches": values["dispatches"][:1]},
        {"attempts": (values["attempts"][0],) * 2},
    ):
        with pytest.raises(ValueError):
            prepare_daily_runtime_activation(**{**values, **changed})


def test_atomic_capacity_check_cannot_spend_same_replaced_cash_twice(fence):
    values = case(fence, two=True)
    result = prepare_daily_runtime_activation(**values)
    # Each individual reserve fits the released capacity; their sum does not.
    terms = tuple(
        replace(t, approved_price=D(600), remaining_fee_budget=D(".10"), reserved_cash=D("6000.10"))
        for t in result.command.payload.terms
    )
    command = replace(result.command, payload=replace(result.command.payload, terms=terms))
    rejected = values["accounting"].advance(
        state=values["state"],
        command=command,
        context=values["context"],
        policy=values["execution_policy"],
    )
    assert rejected.disposition == "rejected"
    assert (
        rejected.state == values["state"] and rejected.journal_entries == rejected.due_events == ()
    )
    assert "available cash" in rejected.reasons[0]


@pytest.mark.parametrize(
    "change",
    [
        "account",
        "state",
        "snapshot",
        "policy",
        "old_digest",
        "reserve",
        "shares",
        "fee",
        "expired",
        "future",
        "halted",
        "no_snapshot",
        "sequence",
    ],
)
def test_reducer_rejects_altered_bindings_or_terms_atomically(fence, change):
    values = case(fence)
    result = prepare_daily_runtime_activation(**values)
    payload, state, context = result.command.payload, values["state"], values["context"]
    if change in ("account", "state", "snapshot", "policy"):
        field = {
            "account": "account_id",
            "state": "source_state_sha256",
            "snapshot": "source_snapshot_sha256",
            "policy": "original_policy_sha256",
        }[change]
        payload = replace(payload, **{field: "other" if change == "account" else "d" * 64})
    elif change in ("old_digest", "reserve", "shares", "fee"):
        term = payload.terms[0]
        fields = {
            "old_digest": {"expected_commitment_sha256": "d" * 64},
            "reserve": {"reserved_cash": term.reserved_cash + D(1)},
            "shares": {"reserved_sell_quantity": D(1)},
            "fee": {
                "remaining_fee_budget": D(0),
                "reserved_cash": term.reserved_cash - term.remaining_fee_budget,
            },
        }[change]
        payload = replace(payload, terms=(replace(term, **fields),))
    elif change == "expired":
        context = replace(context, point=replace(context.point, knowledge_at=payload.expires_at))
    elif change == "future":
        payload = replace(payload, checked_at=payload.checked_at + timedelta(microseconds=1))
    elif change == "halted":
        state = replace(state, halted=True)
    elif change == "no_snapshot":
        context = replace(context, approved_snapshot=None)
    else:
        context = replace(
            context,
            point=replace(
                context.point, reduction_sequence=context.approved_snapshot.point.reduction_sequence
            ),
        )
    rejected = values["accounting"].advance(
        state=state,
        command=replace(result.command, payload=payload),
        context=context,
        policy=values["execution_policy"],
    )
    assert rejected.disposition == "rejected" and rejected.state == state
    assert rejected.journal_entries == rejected.due_events == ()


@pytest.mark.parametrize("state", ["active", "working", "unknown", "pending_cancel"])
def test_non_unsent_commitment_cannot_activate_again(fence, state):
    values = case(fence)
    result = prepare_daily_runtime_activation(**values)
    old = replace(values["state"].commitments[0], state=state)
    changed = replace(values["state"], commitments=(old,))
    source = (
        values["accounting"]
        .project(state=changed, context=values["context"], policy=values["execution_policy"])
        .snapshot
    )
    source = replace(source, point=values["context"].approved_snapshot.point)
    payload = replace(
        result.command.payload,
        source_state_sha256=changed.semantic_sha256,
        source_snapshot_sha256=source.semantic_sha256,
        terms=(
            replace(
                result.command.payload.terms[0], expected_commitment_sha256=old.semantic_sha256
            ),
        ),
    )
    rejected = values["accounting"].advance(
        state=changed,
        command=replace(result.command, payload=payload),
        context=replace(values["context"], approved_snapshot=source),
        policy=values["execution_policy"],
    )
    assert rejected.disposition == "rejected" and rejected.state == changed


def test_helper_is_independent_of_ambient_decimal_precision(fence):
    values = case(fence, two=True, price="101.23")
    expected = prepare_daily_runtime_activation(**values)
    with localcontext() as ctx:
        ctx.prec = 2
        ctx.traps[Inexact] = ctx.traps[Rounded] = True
        assert prepare_daily_runtime_activation(**values) == expected


def test_sell_uses_bid_preserves_payable_and_never_credits_projected_proceeds(fence):
    values = case(fence, sell=True, price="120")
    before = values["context"].approved_snapshot
    result = prepare_daily_runtime_activation(**values)
    new = result.commitments[0]
    assert new.side is Side.SELL
    assert new.approved_price == D(120)
    assert new.reserved_cash == new.remaining_fee_budget == D(".10")
    assert new.reserved_sell_quantity == D(10)
    assert result.transition.snapshot.available_cash == before.available_cash
    assert result.transition.snapshot.trade_date_cash == before.trade_date_cash == D("8999.90")
    assert result.transition.snapshot.trade_payable == before.trade_payable == D("1000.10")
    assert result.transition.snapshot.positions == before.positions
    assert result.transition.state.broker_events == values["state"].broker_events
    assert result.transition.journal_entries == result.transition.due_events == ()


@pytest.mark.parametrize("kind", ["broker", "cancel"])
def test_existing_order_evidence_cannot_be_erased_by_resetting_unsent_status(fence, kind):
    from packages.domain.order_reducer import (
        BrokerOrderEvent,
        BrokerOrderEventKind,
        create_cancel_request,
        reduce_order_lifecycle,
    )

    values = case(fence)
    prepared = prepare_daily_runtime_activation(**values)
    old = values["state"].commitments[0]
    at = START
    if kind == "broker":
        evidence = BrokerOrderEvent(
            event_id="actual-venue-ack",
            order_id=old.order_id,
            broker_order_id="actual-venue-order",
            broker_sequence=1,
            occurred_at=at,
            received_at=at,
            kind=BrokerOrderEventKind.ACCEPTED,
        )
    else:
        evidence = create_cancel_request(
            reduce_order_lifecycle(submission=values["state"].submissions[0], broker_events=()),
            requested_at=at,
            reason="explicit-fixture-cancel",
        )
    applied = values["accounting"].advance(
        state=values["state"],
        command=AccountingCommand("actual-order-evidence", evidence),
        context=values["context"],
        policy=values["execution_policy"],
    )
    assert applied.disposition == "applied", applied.reasons
    state = replace(applied.state, commitments=(old,))
    snapshot = (
        values["accounting"]
        .project(state=state, context=values["context"], policy=values["execution_policy"])
        .snapshot
    )
    snapshot = replace(snapshot, point=values["context"].approved_snapshot.point)
    payload = replace(
        prepared.command.payload,
        source_state_sha256=state.semantic_sha256,
        source_snapshot_sha256=snapshot.semantic_sha256,
    )
    rejected = values["accounting"].advance(
        state=state,
        command=replace(prepared.command, payload=payload),
        context=replace(values["context"], approved_snapshot=snapshot),
        policy=values["execution_policy"],
    )
    assert rejected.disposition == "rejected" and rejected.state == state
    assert "broker or cancel" in rejected.reasons[0]


@pytest.mark.parametrize("model", ["next-regular-open-proxy-v1", "stateful-venue-facts-v1"])
def test_command_is_exclusive_to_coordinator_observed_accounting(fence, model):
    values = case(fence)
    prepared = prepare_daily_runtime_activation(**values)
    policy = replace(
        values["execution_policy"],
        model_id=model,
        **(
            {
                "settlement_model": "dated-us-equity-standard-settlement-v1",
                "correction_settlement": "explicit-or-receipt-trade-date-v1",
                "terminal_model": "observed-model-day-expiry-v1",
            }
            if model == "next-regular-open-proxy-v1"
            else {}
        ),
    )
    # Explicit negative fixture with a different admitted policy; no policy migration performed.
    state = replace(values["state"], execution_policy_sha256=policy.semantic_sha256)
    source = (
        values["accounting"].project(state=state, context=values["context"], policy=policy).snapshot
    )
    source = replace(source, point=values["context"].approved_snapshot.point)
    payload = replace(
        prepared.command.payload,
        source_state_sha256=state.semantic_sha256,
        source_snapshot_sha256=source.semantic_sha256,
    )
    rejected = values["accounting"].advance(
        state=state,
        command=replace(prepared.command, payload=payload),
        context=replace(values["context"], approved_snapshot=source),
        policy=policy,
    )
    assert rejected.disposition == "rejected" and rejected.state == state
