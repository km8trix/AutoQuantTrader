"""Pure stateful provenance fixtures; no delivery, provider or SQL authority."""

from dataclasses import replace
from datetime import timedelta

import pytest

from packages.application.personal_codec import decode_record, encode_record
from packages.domain.account_coordinator import AccountFenceReceipt
from packages.domain.daily_attempt import daily_fence_reference, require_daily_fence_match
from packages.domain.daily_attempt_contracts import DailyFenceReference
from tests.unit.test_account_coordinator import coordinator


def test_fence_wire_round_trip_preserves_actual_receipt_without_reconstructing_proof():
    authority, _, _ = coordinator("daily-attempt-roundtrip")
    lease = authority.acquire("explicit-fixture-owner")
    receipt = authority.revalidate(lease.fence)
    wire = daily_fence_reference(receipt)
    restored = decode_record(encode_record(wire), DailyFenceReference)
    assert restored == wire
    assert restored.original_receipt_sha256 == receipt.semantic_sha256
    require_daily_fence_match(restored, receipt)
    with pytest.raises(TypeError, match="coordinator"):
        AccountFenceReceipt()
    with pytest.raises(ValueError, match="actual coordinator receipt"):
        daily_fence_reference(restored)


@pytest.mark.parametrize(
    "change", ["account", "owner", "generation", "receipt", "policy", "lease", "time"]
)
def test_fence_wire_cannot_match_a_different_actual_receipt(change):
    authority, _, _ = coordinator("daily-attempt-wire-" + change)
    receipt = authority.revalidate(authority.acquire("explicit-fixture-owner").fence)
    wire = daily_fence_reference(receipt)
    if change in ("account", "owner", "generation"):
        field = {"account": "account_id", "owner": "owner_id", "generation": "fencing_generation"}[
            change
        ]
        value = 2 if change == "generation" else "different"
        wire = replace(wire, fence=replace(wire.fence, **{field: value}))
    elif change == "time":
        wire = replace(wire, validated_at=wire.validated_at + timedelta(microseconds=1))
    else:
        field = {
            "receipt": "original_receipt_sha256",
            "policy": "policy_sha256",
            "lease": "lease_sha256",
        }[change]
        wire = replace(wire, **{field: "b" * 64})
    with pytest.raises(ValueError, match="provenance differs"):
        require_daily_fence_match(wire, receipt)


def reference(record):
    from hashlib import sha256

    from packages.domain.personal_contracts import VersionPin
    from packages.domain.research_job_contracts import ObjectRef
    from packages.domain.stateful_venue_contracts import VenueSourceReference

    payload = encode_record(record)
    return VenueSourceReference(
        VersionPin("pure-attempt-fixture", "1", "a" * 64),
        record.semantic_sha256,
        ObjectRef(sha256(payload).hexdigest(), len(payload)),
    )


def rebind_case(case, *, account_id):
    from packages.domain.daily_runtime_contracts import RuntimeProducerMap
    from packages.domain.daily_runtime_risk import runtime_source_value_sha256

    assignment, snapshot, batch, inputs, producers, now = case
    producers = RuntimeProducerMap(
        producers=tuple(replace(item, account_scope=account_id) for item in producers.producers)
    )
    assignment = replace(
        assignment, account_id=account_id, producer_map_sha256=producers.semantic_sha256
    )
    inputs = replace(
        inputs,
        assignment_sha256=assignment.semantic_sha256,
        reconciliation=replace(
            inputs.reconciliation, scope=replace(inputs.reconciliation.scope, account_id=account_id)
        ),
    )
    by_role = {item.role: item for item in producers.producers}
    inputs = replace(
        inputs,
        sources=tuple(
            replace(
                item,
                account_id=account_id,
                spec=by_role[item.spec.role],
                value_sha256=runtime_source_value_sha256(item.spec.role, snapshot, batch, inputs),
            )
            for item in inputs.sources
        ),
    )
    return assignment, snapshot, batch, inputs, producers, now


def pending_case(*, account_id="daily-pure-canonical-account"):
    from packages.application.daily_commitment_install import prepare_daily_commitments
    from packages.backtest.personal_accounting import PersonalAccounting
    from packages.domain.daily_attempt import prepare_daily_attempt, reduce_daily_attempt
    from packages.domain.daily_attempt_contracts import (
        DailyAttemptEvent,
        DailyVenueSubmissionRequest,
    )
    from packages.domain.daily_risk import evaluate_daily_risk
    from packages.domain.daily_runtime_contracts import (
        RuntimeCommitmentBinding,
        RuntimeRiskAdmission,
    )
    from packages.domain.personal_contracts import VersionPin
    from packages.domain.portfolio import daily_target_to_intents
    from packages.domain.submission_attempt import SubmissionAttemptState
    from tests.unit.test_daily_commitment_install import install_case
    from tests.unit.test_daily_risk_snapshot import END, START, build, runtime_case
    from tests.unit.test_daily_target_conversion import NOW, PIN
    from tests.unit.test_stateful_venue import model

    raw = install_case()
    state = replace(raw["state"], account_id=account_id)
    snapshot = (
        PersonalAccounting()
        .project(state=state, context=raw["context"], policy=raw["execution_policy"])
        .snapshot
    )
    batch = daily_target_to_intents(
        replace(raw["batch"].target, not_before=START, expires_at=END), snapshot, strategy_pin=PIN
    )
    case = rebind_case(runtime_case(snapshot=snapshot, batch=batch), account_id=state.account_id)
    evidence = build(case)
    decision = evaluate_daily_risk(case[0].policy, snapshot, batch, evidence, NOW)
    assert decision.approved, decision.reasons
    installed = prepare_daily_commitments(
        state=state,
        snapshot=snapshot,
        batch=batch,
        decision=decision,
        context=raw["context"],
        execution_policy=raw["execution_policy"],
        risk_policy=case[0].policy,
        accounting=PersonalAccounting(),
        attempt_namespace="daily-runtime-attempt",
    )
    assert installed.disposition == "installed"
    admission = RuntimeRiskAdmission(
        evidence=evidence, decision=decision, recorded_at=NOW, expires_at=NOW + timedelta(seconds=5)
    )
    hold = RuntimeCommitmentBinding(
        account_id=state.account_id,
        commitment=installed.commitments[0],
        origin="daily_runtime",
        source_id="retained-fixture-admission",
        source_sha256=admission.semantic_sha256,
        original_policy_sha256=decision.policy_sha256,
        projection=VersionPin("daily_runtime_hold", "fixture/1", "a" * 64),
    )
    venue = model()
    request = DailyVenueSubmissionRequest(
        submission=installed.state.submissions[0],
        original_commitment=hold.commitment,
        source_account_id=state.account_id,
        source_account_binding_sha256=case[0].account_binding_sha256,
        venue_account_id=venue.account_id,
        venue_model=reference(venue),
        original_admission_sha256=admission.semantic_sha256,
    )
    preparation = prepare_daily_attempt(
        request=request,
        original_admission=admission,
        admission_source=reference(admission),
        original_hold=hold,
        prepared_at=NOW,
    )
    event = DailyAttemptEvent(
        attempt_id=preparation.attempt_id,
        sequence=1,
        previous_event_sha256=None,
        state=SubmissionAttemptState.PENDING,
        recorded_at=NOW,
    )
    return reduce_daily_attempt(preparation, (event,)), raw, installed.state


def activation_case(activation_receipt):
    from packages.backtest.personal_accounting import PersonalAccounting
    from packages.domain.daily_attempt import prepare_daily_activation
    from packages.domain.daily_risk import evaluate_daily_risk
    from tests.unit.test_daily_risk_snapshot import START, build, runtime_case
    from tests.unit.test_daily_target_conversion import EXECUTION

    attempt, raw, state = pending_case()
    hold = attempt.preparation.original_hold
    context = replace(
        raw["context"],
        point=replace(
            raw["context"].point,
            knowledge_at=START,
            reduction_sequence=raw["context"].point.reduction_sequence + 2,
        ),
    )
    snapshot = (
        PersonalAccounting()
        .project(state=state, context=context, policy=raw["execution_policy"])
        .snapshot
    )
    snapshot = replace(
        snapshot,
        marks=tuple(
            replace(
                mark,
                economic_at=START,
                knowledge_at=START,
                session=EXECUTION,
                basis="runtime_quote_ask_v1",
            )
            for mark in snapshot.marks
        ),
    )
    batch = replace(
        attempt.preparation.original_admission.decision.batch,
        snapshot_sha256=snapshot.semantic_sha256,
    )
    case = rebind_case(
        runtime_case(
            snapshot=snapshot, batch=batch, phase="activation", now=START, bindings=(hold,)
        ),
        account_id=state.account_id,
    )
    case = (
        *case[:3],
        replace(case[3], accepted_intent_ids=(hold.commitment.intent_id,)),
        *case[4:],
    )
    case = rebind_case(case, account_id=state.account_id)
    evidence = build(case)
    decision = evaluate_daily_risk(case[0].policy, snapshot, batch, evidence, START)
    assert decision.approved, decision.reasons
    activation = prepare_daily_activation(
        preparation=attempt.preparation,
        current_hold=hold,
        snapshot=snapshot,
        evidence=evidence,
        decision=decision,
        heads=case[3].heads,
        fence=daily_fence_reference(activation_receipt),
        checked_at=START,
    )
    return attempt, activation


def test_pending_request_is_canonical_and_round_trips_without_old_risk_coercion():
    from packages.domain.daily_attempt_contracts import CanonicalDailyAttempt
    from packages.domain.identifiers import canonical_id

    attempt, _, _ = pending_case()
    request = attempt.preparation.request
    assert attempt.attempt_id == canonical_id(
        "daily-runtime-attempt", request.submission.intent.intent_id
    )
    assert decode_record(encode_record(attempt), CanonicalDailyAttempt) == attempt
    assert request.live_authorized is False and request.operation == "submit"
    with pytest.raises(ValueError):
        replace(request, operation="place_order")
    with pytest.raises(ValueError):
        replace(request, live_authorized=True)
    with pytest.raises(ValueError, match="canonical order"):
        replace(request, submission=replace(request.submission, client_order_id="changed"))


def test_morning_activation_has_fresh_lifetime_and_preserves_original_expired_admission(
    activation_receipt,
):
    from tests.unit.test_daily_risk_snapshot import START

    attempt, activation = activation_case(activation_receipt)
    assert attempt.preparation.original_admission.expires_at < START
    assert activation.checked_at == START < activation.expires_at
    assert activation.preparation_sha256 == attempt.preparation.semantic_sha256
    assert not hasattr(activation, "delivery_token")


def dispatch_case(activation_receipt):
    from hashlib import sha256

    from packages.domain.daily_attempt import advance_daily_attempt, prepare_daily_dispatch
    from packages.domain.daily_attempt_contracts import DailyAttemptEvent, DailyDispatchClaim
    from packages.domain.durable_journal_contracts import (
        JournalAppend,
        JournalEntry,
        JournalKey,
        JournalReceipt,
        JournalRecord,
        empty_head,
    )
    from packages.domain.research_job_contracts import ObjectRef
    from packages.domain.submission_attempt import SubmissionAttemptState

    attempt, activation = activation_case(activation_receipt)
    record = prepare_daily_dispatch(
        attempt=attempt,
        activation=activation,
        command_id="retained-fixture-send",
        dispatched_at=activation.checked_at,
    )
    payload = encode_record(record)
    key = JournalKey(
        "coordinator",
        "attempt-fixture",
        attempt.preparation.request.source_account_id,
        "fixture",
        "synthetic",
        "d" * 64,
    )
    item = JournalRecord(record.record_id, "personal-daily-attempt/1", payload)
    append = JournalAppend(record.command_id, record.semantic_sha256, empty_head(key), (item,))
    entry = JournalEntry(
        key.semantic_sha256, 1, record.command_id, item, empty_head(key).entry_sha256
    )
    receipt = JournalReceipt(
        record.command_id,
        record.semantic_sha256,
        append.semantic_sha256,
        empty_head(key),
        entry.head,
        (item.record_id,),
        (item.payload_sha256,),
    )
    claim = DailyDispatchClaim(
        record=record,
        receipt=receipt,
        record_ref=ObjectRef(sha256(payload).hexdigest(), len(payload)),
    )
    event = DailyAttemptEvent(
        attempt_id=attempt.attempt_id,
        sequence=2,
        previous_event_sha256=attempt.events[-1].semantic_sha256,
        state=SubmissionAttemptState.IN_FLIGHT,
        recorded_at=activation.checked_at,
        dispatch=claim,
    )
    return attempt, advance_daily_attempt(attempt, event).attempt, event


def observed_outcome(attempt, at, *, resolution="accepted"):
    from decimal import Decimal

    from packages.domain.daily_attempt_contracts import DailyObservedOutcome
    from packages.domain.reconciliation_contracts import OrderObservation, ReconciliationScope

    request = attempt.preparation.request
    intent = request.submission.intent
    order = OrderObservation(
        "fixture-venue-order",
        request.submission.order_id,
        intent.instrument_id,
        intent.symbol,
        intent.side,
        intent.quantity,
        Decimal(0),
        "working" if resolution == "accepted" else "rejected",
    )
    return DailyObservedOutcome(
        scope=ReconciliationScope(
            request.venue_account_id,
            "fixture-venue",
            "stateful_simulation",
            request.venue_model.semantic_sha256_ref,
            "stateful_simulation",
        ),
        order=order,
        source=reference(order),
        observed_at=at,
        resolution=resolution,
    )


def event_after(attempt, state, at, **payload):
    from packages.domain.daily_attempt_contracts import DailyAttemptEvent

    return DailyAttemptEvent(
        attempt_id=attempt.attempt_id,
        sequence=len(attempt.events) + 1,
        previous_event_sha256=attempt.events[-1].semantic_sha256,
        state=state,
        recorded_at=at,
        **payload,
    )


def test_exact_first_send_claim_roundtrip_and_inert_retry(activation_receipt):
    from packages.domain.daily_attempt import (
        advance_daily_attempt,
        prepare_daily_dispatch,
        reduce_daily_attempt,
    )
    from packages.domain.daily_attempt_contracts import CanonicalDailyAttempt

    pending, sent, event = dispatch_case(activation_receipt)
    assert decode_record(encode_record(sent), CanonicalDailyAttempt) == sent
    assert advance_daily_attempt(sent, event).disposition == "idempotent"
    assert reduce_daily_attempt(sent.preparation, (*reversed(sent.events), event)) == sent
    with pytest.raises(ValueError, match="first send"):
        prepare_daily_dispatch(
            attempt=sent,
            activation=event.dispatch.record.activation,
            command_id="retry",
            dispatched_at=event.recorded_at,
        )
    changed = replace(event, recorded_at=event.recorded_at + timedelta(microseconds=1))
    with pytest.raises(ValueError, match="retry conflicts"):
        advance_daily_attempt(sent, changed)
    assert pending.events == sent.events[:1]


@pytest.mark.parametrize("resolution", ["accepted", "rejected"])
def test_positive_observed_outcome_confirms_without_posting_or_releasing_economics(
    activation_receipt, resolution
):
    from packages.domain.daily_attempt import advance_daily_attempt
    from packages.domain.submission_attempt import SubmissionAttemptState

    _, sent, event = dispatch_case(activation_receipt)
    at = event.recorded_at + timedelta(seconds=1)
    outcome = observed_outcome(sent, at, resolution=resolution)
    confirmed = advance_daily_attempt(
        sent, event_after(sent, SubmissionAttemptState.CONFIRMED, at, outcome=outcome)
    ).attempt
    assert confirmed.state is SubmissionAttemptState.CONFIRMED
    assert confirmed.preparation == sent.preparation
    assert confirmed.preparation.original_hold.commitment.reserved_cash > 0
    assert not hasattr(confirmed, "accounting_transition")


@pytest.mark.parametrize("resolution", ["accepted", "rejected"])
def test_unknown_retains_hold_until_positive_observed_resolution_and_never_retries(
    activation_receipt, resolution
):
    from packages.domain.daily_attempt import advance_daily_attempt, prepare_daily_dispatch
    from packages.domain.submission_attempt import SubmissionAttemptState

    _, sent, first = dispatch_case(activation_receipt)
    at = first.recorded_at + timedelta(seconds=2)
    unknown = advance_daily_attempt(
        sent,
        event_after(sent, SubmissionAttemptState.UNKNOWN, at, reason="bounded_transport_timeout"),
    ).attempt
    assert unknown.preparation.original_hold == sent.preparation.original_hold
    outcome = observed_outcome(
        unknown, first.recorded_at + timedelta(seconds=1), resolution=resolution
    )
    resolved = advance_daily_attempt(
        unknown, event_after(unknown, SubmissionAttemptState.RESOLVED, at, outcome=outcome)
    ).attempt
    assert resolved.state is SubmissionAttemptState.RESOLVED
    for current in (unknown, resolved):
        with pytest.raises(ValueError, match="first send"):
            prepare_daily_dispatch(
                attempt=current,
                activation=first.dispatch.record.activation,
                command_id="no-retry",
                dispatched_at=at,
            )


@pytest.mark.parametrize(
    "change", ["account", "model", "order", "instrument", "symbol", "quantity", "old_time"]
)
def test_wrong_observed_order_identity_or_source_time_cannot_resolve_unknown(
    activation_receipt, change
):
    from decimal import Decimal

    from packages.domain.daily_attempt import advance_daily_attempt
    from packages.domain.submission_attempt import SubmissionAttemptState

    _, sent, first = dispatch_case(activation_receipt)
    at = first.recorded_at + timedelta(seconds=2)
    unknown = advance_daily_attempt(
        sent, event_after(sent, SubmissionAttemptState.UNKNOWN, at, reason="unknown_transport")
    ).attempt
    outcome = observed_outcome(unknown, at)
    if change == "account":
        outcome = replace(outcome, scope=replace(outcome.scope, account_id="other"))
    elif change == "model":
        outcome = replace(outcome, scope=replace(outcome.scope, binding_sha256="b" * 64))
    elif change == "old_time":
        outcome = replace(outcome, observed_at=first.recorded_at - timedelta(microseconds=1))
    else:
        field = {
            "order": "order_id",
            "instrument": "instrument_id",
            "symbol": "symbol",
            "quantity": "quantity",
        }[change]
        outcome = replace(
            outcome,
            order=replace(
                outcome.order, **{field: Decimal(999) if change == "quantity" else "other"}
            ),
        )
    with pytest.raises(ValueError, match="observed outcome"):
        advance_daily_attempt(
            unknown, event_after(unknown, SubmissionAttemptState.RESOLVED, at, outcome=outcome)
        )


def test_absence_or_unknown_order_does_not_prove_non_submission(activation_receipt):
    _, sent, event = dispatch_case(activation_receipt)
    outcome = observed_outcome(sent, event.recorded_at)
    for changes in (
        {"order_id": None},
        {"instrument_id": None},
        {"quantity": None},
        {"status": "unknown"},
    ):
        with pytest.raises(ValueError):
            replace(outcome, order=replace(outcome.order, **changes))
    with pytest.raises(ValueError):
        replace(outcome, resolution="not_submitted")
    with pytest.raises(ValueError):
        replace(outcome, resolution="rejected")


@pytest.mark.parametrize(
    "change", ["record_id", "byte_hash", "command", "activation", "predecessor"]
)
def test_dispatch_receipt_or_record_substitution_cannot_enter_first_send(
    activation_receipt, change
):
    from packages.domain.daily_attempt import advance_daily_attempt

    pending, _, event = dispatch_case(activation_receipt)
    claim = event.dispatch
    with pytest.raises(ValueError):
        if change == "record_id":
            claim = replace(claim, receipt=replace(claim.receipt, record_ids=("unrelated-record",)))
        elif change == "byte_hash":
            claim = replace(claim, record_ref=replace(claim.record_ref, object_sha256="b" * 64))
        elif change == "command":
            claim = replace(claim, receipt=replace(claim.receipt, command_id="unrelated-command"))
        elif change == "activation":
            claim = replace(
                claim,
                record=replace(
                    claim.record,
                    activation=replace(
                        claim.record.activation,
                        expires_at=claim.record.activation.expires_at + timedelta(milliseconds=1),
                    ),
                ),
            )
        else:
            claim = replace(claim, record=replace(claim.record, previous_attempt_sha256="b" * 64))
        advance_daily_attempt(pending, replace(event, dispatch=claim))


def test_dispatch_at_exact_activation_deadline_fails_without_refresh(activation_receipt):
    from packages.domain.daily_attempt import prepare_daily_dispatch

    pending, activation = activation_case(activation_receipt)
    with pytest.raises(ValueError, match="fresh activation"):
        prepare_daily_dispatch(
            attempt=pending,
            activation=activation,
            command_id="expired",
            dispatched_at=activation.expires_at,
        )


def unsent_case(reason, *, suffix=""):
    from packages.domain.daily_attempt_contracts import DailyUnsentProof
    from tests.unit.test_daily_risk_snapshot import END, START

    pending, _, _ = pending_case(account_id="pure-unsent-" + reason + suffix)
    authority, clock, _ = coordinator(pending.preparation.request.source_account_id)
    clock.instant = END if reason == "expired" else START
    receipt = authority.revalidate(authority.acquire("explicit-unsent-owner").fence)
    proof = DailyUnsentProof(
        account_id=pending.preparation.request.source_account_id,
        attempt_id=pending.attempt_id,
        request_sha256=pending.preparation.request.semantic_sha256,
        attempt_history_sha256=pending.semantic_sha256,
        commitment_sha256=pending.preparation.original_hold.commitment.semantic_sha256,
        heads=pending.preparation.original_admission.evidence.inputs.heads,
        fence=daily_fence_reference(receipt),
        checked_at=receipt.validated_at,
        reason=reason,
        # Explicit typed fixture reference; actual owner-command authentication is a SQL obligation.
        owner_command=None if reason == "expired" else reference(pending.preparation),
    )
    return pending, proof


@pytest.mark.parametrize("reason", ["expired", "revoked", "policy_cutover"])
def test_matching_unsent_proof_abandons_without_itself_releasing_cash(reason):
    from packages.domain.daily_attempt import advance_daily_attempt
    from packages.domain.daily_attempt_contracts import CanonicalDailyAttempt
    from packages.domain.submission_attempt import SubmissionAttemptState

    pending, proof = unsent_case(reason)
    event = event_after(
        pending, SubmissionAttemptState.ABANDONED, proof.checked_at, unsent_proof=proof
    )
    result = advance_daily_attempt(pending, event)
    assert result.disposition == "applied"
    assert result.attempt.state is SubmissionAttemptState.ABANDONED
    assert result.attempt.preparation.original_hold == pending.preparation.original_hold
    assert result.attempt.preparation.original_hold.commitment.reserved_cash > 0
    assert decode_record(encode_record(result.attempt), CanonicalDailyAttempt) == result.attempt
    assert advance_daily_attempt(result.attempt, event).disposition == "idempotent"
    assert not hasattr(result, "release_authorization")
    if reason != "expired":
        with pytest.raises(ValueError, match="owner provenance"):
            replace(proof, owner_command=None)


@pytest.mark.parametrize(
    "change", ["attempt", "request", "history", "commitment", "expired_early", "fence_expired"]
)
def test_wrong_or_stale_unsent_proof_cannot_abandon(change):
    from packages.domain.daily_attempt import advance_daily_attempt
    from packages.domain.submission_attempt import SubmissionAttemptState

    pending, proof = unsent_case("revoked", suffix="-" + change)
    at = proof.checked_at
    if change == "expired_early":
        proof = replace(proof, reason="expired", owner_command=None)
    elif change == "fence_expired":
        at = proof.fence.valid_until
    else:
        field = {
            "attempt": "attempt_id",
            "request": "request_sha256",
            "history": "attempt_history_sha256",
            "commitment": "commitment_sha256",
        }[change]
        proof = replace(proof, **{field: "other" if change == "attempt" else "e" * 64})
    with pytest.raises(ValueError, match="unsent history proof"):
        advance_daily_attempt(
            pending, event_after(pending, SubmissionAttemptState.ABANDONED, at, unsent_proof=proof)
        )


@pytest.mark.parametrize("change", ["gap", "predecessor", "time", "pending_again", "skip_send"])
def test_history_cannot_skip_or_reopen_lifecycle(activation_receipt, change):
    from packages.domain.daily_attempt import advance_daily_attempt
    from packages.domain.submission_attempt import SubmissionAttemptState

    pending, _, first = dispatch_case(activation_receipt)
    if change == "gap":
        event = replace(first, sequence=3)
    elif change == "predecessor":
        event = replace(first, previous_event_sha256="e" * 64)
    elif change == "time":
        event = replace(first, recorded_at=pending.events[0].recorded_at - timedelta(seconds=1))
    elif change == "pending_again":
        event = event_after(pending, SubmissionAttemptState.PENDING, first.recorded_at)
    else:
        event = event_after(
            pending,
            SubmissionAttemptState.CONFIRMED,
            first.recorded_at,
            outcome=observed_outcome(pending, first.recorded_at),
        )
    with pytest.raises(ValueError):
        advance_daily_attempt(pending, event)


@pytest.mark.parametrize("state", ["in_flight", "unknown"])
def test_sent_or_unknown_attempt_cannot_use_unsent_proof(activation_receipt, state):
    from packages.domain.daily_attempt import advance_daily_attempt
    from packages.domain.daily_attempt_contracts import DailyUnsentProof
    from packages.domain.submission_attempt import SubmissionAttemptState

    _, current, first = dispatch_case(activation_receipt)
    at = first.recorded_at + timedelta(microseconds=1)
    if state == "unknown":
        current = advance_daily_attempt(
            current, event_after(current, SubmissionAttemptState.UNKNOWN, at, reason="timeout")
        ).attempt
    proof = DailyUnsentProof(
        account_id=current.preparation.request.source_account_id,
        attempt_id=current.attempt_id,
        request_sha256=current.preparation.request.semantic_sha256,
        attempt_history_sha256=current.semantic_sha256,
        commitment_sha256=current.preparation.original_hold.commitment.semantic_sha256,
        heads=first.dispatch.record.activation.heads,
        fence=first.dispatch.record.activation.fence,
        checked_at=at,
        reason="policy_cutover",
        owner_command=reference(current.preparation),
    )
    with pytest.raises(ValueError, match="lifecycle states"):
        advance_daily_attempt(
            current, event_after(current, SubmissionAttemptState.ABANDONED, at, unsent_proof=proof)
        )


@pytest.mark.parametrize("change", ["hold", "heads", "fence", "decision", "time", "expiry"])
def test_activation_or_dispatch_recomputes_exact_current_bindings(activation_receipt, change):
    from packages.domain.daily_attempt import prepare_daily_activation, prepare_daily_dispatch

    attempt, activation = activation_case(activation_receipt)
    if change == "expiry":
        altered = replace(activation, expires_at=activation.expires_at + timedelta(microseconds=1))
        with pytest.raises(ValueError, match="recomputed record"):
            prepare_daily_dispatch(
                attempt=attempt,
                activation=altered,
                command_id="changed-expiry",
                dispatched_at=activation.checked_at,
            )
        return
    values = dict(
        preparation=attempt.preparation,
        current_hold=activation.current_hold,
        snapshot=activation.snapshot,
        evidence=activation.evidence,
        decision=activation.decision,
        heads=activation.heads,
        fence=activation.fence,
        checked_at=activation.checked_at,
    )
    if change == "hold":
        values["current_hold"] = replace(
            activation.current_hold,
            commitment=replace(activation.current_hold.commitment, created_sequence=999),
        )
    elif change == "heads":
        values["heads"] = replace(activation.heads, effect_watermark=999)
    elif change == "fence":
        values["fence"] = replace(
            activation.fence, fence=replace(activation.fence.fence, fencing_generation=999)
        )
    elif change == "decision":
        values["decision"] = replace(activation.decision, approved=False, reasons=("REJECTED",))
    else:
        values["checked_at"] = activation.checked_at + timedelta(microseconds=1)
    with pytest.raises(ValueError):
        prepare_daily_activation(**values)


@pytest.mark.parametrize(
    "change", ["origin", "source", "session", "submitted_time", "expired", "price", "fee"]
)
def test_original_pending_binding_cannot_be_relabelled(change):
    attempt, _, _ = pending_case()
    original = attempt.preparation
    with pytest.raises(ValueError):
        if change in ("origin", "source"):
            altered = replace(
                original.original_hold,
                **(
                    {"origin": "legacy_phase2"}
                    if change == "origin"
                    else {"source_sha256": "e" * 64}
                ),
            )
            replace(original, original_hold=altered)
        elif change == "session":
            commitment = replace(
                original.original_hold.commitment,
                execution_session=original.original_hold.commitment.execution_session
                + timedelta(days=1),
            )
            replace(
                original,
                original_hold=replace(original.original_hold, commitment=commitment),
                request=replace(original.request, original_commitment=commitment),
            )
        elif change in ("price", "fee"):
            from decimal import Decimal

            field = "approved_price" if change == "price" else "remaining_fee_budget"
            commitment = replace(original.original_hold.commitment, **{field: Decimal("999")})
            replace(
                original,
                original_hold=replace(original.original_hold, commitment=commitment),
                request=replace(original.request, original_commitment=commitment),
            )
        elif change == "submitted_time":
            replace(
                original,
                request=replace(
                    original.request,
                    submission=replace(
                        original.request.submission,
                        submitted_at=original.request.submission.submitted_at
                        + timedelta(microseconds=1),
                    ),
                ),
            )
        else:
            replace(original, prepared_at=original.original_admission.expires_at)


def test_actual_sql_admission_envelope_retains_its_distinct_hold_source(tmp_path):
    from packages.domain.daily_attempt import prepare_daily_attempt
    from packages.domain.daily_attempt_contracts import (
        DailyAttemptPreparation,
        DailyVenueSubmissionRequest,
    )
    from packages.persistence.database import create_database_engine
    from tests.integration.test_sql_daily_runtime_risk import Harness
    from tests.unit.test_stateful_venue import model

    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path / 'attempt-admission.sqlite'}")
    try:
        harness = Harness(engine)
        harness.enable()
        admission = harness.admit(harness.request())
        resolved = harness.resolved()
        envelope = resolved.admissions[0]
        hold = resolved.obligations.bindings[0]
        assert hold.source_sha256 == envelope.semantic_sha256 != admission.semantic_sha256
        from packages.application.daily_commitment_install import prepare_daily_commitments
        from packages.backtest.personal_accounting import PersonalAccounting

        canonical = prepare_daily_commitments(
            state=envelope.resolved.state,
            snapshot=envelope.resolved.snapshot,
            batch=admission.decision.batch,
            decision=admission.decision,
            context=envelope.resolved.context,
            execution_policy=envelope.resolved.execution_policy,
            risk_policy=admission.evidence.assignment.policy,
            accounting=PersonalAccounting(),
            attempt_namespace="daily-runtime-attempt",
        )
        venue = model()
        request = DailyVenueSubmissionRequest(
            submission=canonical.state.submissions[0],
            original_commitment=hold.commitment,
            source_account_id=hold.account_id,
            source_account_binding_sha256=admission.evidence.assignment.account_binding_sha256,
            venue_account_id=venue.account_id,
            venue_model=reference(venue),
            original_admission_sha256=admission.semantic_sha256,
        )
        prepared = prepare_daily_attempt(
            request=request,
            original_admission=admission,
            admission_source=reference(envelope),
            original_hold=hold,
            prepared_at=admission.recorded_at,
        )
        assert decode_record(encode_record(prepared), DailyAttemptPreparation) == prepared
        assert prepared.original_hold == hold
        with pytest.raises(ValueError, match="pending daily attempt sources"):
            replace(prepared, admission_source=reference(admission))
        with pytest.raises(ValueError, match="pending daily attempt sources"):
            replace(
                prepared,
                request=replace(request, original_admission_sha256=envelope.semantic_sha256),
            )
    finally:
        engine.dispose()


def test_activation_deadline_uses_earliest_reconciliation_observation(activation_receipt):
    from packages.domain.daily_attempt import prepare_daily_activation, prepare_daily_dispatch
    from packages.domain.daily_risk import evaluate_daily_risk
    from tests.unit.test_daily_risk_snapshot import START, build

    attempt, original = activation_case(activation_receipt)
    inputs = replace(
        original.evidence.inputs,
        reconciliation=replace(
            original.evidence.inputs.reconciliation,
            observation_started_at=START - timedelta(seconds=59, microseconds=500000),
            observation_received_through=START,
            completed_at=START,
        ),
    )
    case = rebind_case(
        (
            original.evidence.assignment,
            original.snapshot,
            original.decision.batch,
            inputs,
            original.evidence.producer_map,
            START,
        ),
        account_id=original.snapshot.account_id,
    )
    evidence = build(case)
    decision = evaluate_daily_risk(case[0].policy, case[1], case[2], evidence, START)
    assert decision.approved
    activation = prepare_daily_activation(
        preparation=attempt.preparation,
        current_hold=original.current_hold,
        snapshot=original.snapshot,
        evidence=evidence,
        decision=decision,
        heads=inputs.heads,
        fence=original.fence,
        checked_at=START,
    )
    assert activation.expires_at == START + timedelta(microseconds=500000)
    assert activation.expires_at < original.expires_at
    at = activation.expires_at - timedelta(microseconds=1)
    record = prepare_daily_dispatch(
        attempt=attempt,
        activation=activation,
        command_id="oldest-reconciliation-source",
        dispatched_at=at,
    )
    assert record.activation.decision == decision
    assert record.preparation.original_admission == attempt.preparation.original_admission
    with pytest.raises(ValueError, match="fresh activation"):
        prepare_daily_dispatch(
            attempt=attempt,
            activation=activation,
            command_id="expired-reconciliation-source",
            dispatched_at=activation.expires_at,
        )
