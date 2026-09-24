from dataclasses import FrozenInstanceError, replace
from datetime import timedelta

import pytest

from packages.domain.daily_runtime_contracts import (
    DailyRuntimeRiskEvidence,
    RuntimeCommitmentBinding,
    RuntimeProducerMap,
    RuntimeRiskAdmission,
    RuntimeRiskAssignment,
    RuntimeRiskCheck,
)
from packages.domain.engine_contracts import DailyRiskDecision, DailyRiskPolicy
from packages.domain.models import Side
from packages.domain.personal_contracts import VersionPin
from tests.unit.test_daily_risk_snapshot import END, build, inventory, runtime_case
from tests.unit.test_daily_target_conversion import NOW, SHA, D, commitment


def test_runtime_assignment_has_distinct_policy_version_and_disabled_live_scope() -> None:
    assignment = runtime_case()[0]
    assert assignment.policy.policy_id == "personal-daily-stateful-simulation/1"
    assert assignment.policy.semantic_sha256 != DailyRiskPolicy().semantic_sha256
    assert assignment.financing_policy == "cash-funded-long-only/1"
    assert assignment.live_authorized is False
    assert RuntimeRiskAssignment.contract_version == "personal-daily-runtime-risk/1"
    disabled = replace(assignment, enabled_for_new_exposure=False)
    assert disabled.semantic_sha256 != assignment.semantic_sha256
    with pytest.raises(FrozenInstanceError):
        assignment.generation = 2  # type: ignore[misc]


@pytest.mark.parametrize(
    "changes",
    [
        {"environment": "production"},
        {"environment": "sandbox"},
        {"live_authorized": True},
        {"enabled_for_new_exposure": 1},
        {"generation": True},
        {"generation": 0},
        {"generation": 2},
        {"previous_assignment_sha256": SHA},
        {"policy": DailyRiskPolicy()},
        {"configuration_sha256": "not-a-digest"},
        {"instrument_symbols": (("spy", "OTHER"),)},
        {"instrument_symbols": (("spy", "SPY"), ("spy", "QQQ"))},
        {"instrument_symbols": ()},
    ],
)
def test_assignment_rejects_foreign_scope_loose_types_or_unbound_generations(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        replace(runtime_case()[0], **changes)


def test_policy_transition_retains_predecessor_and_tightening_changes_identity() -> None:
    original = runtime_case()[0]
    next_assignment = replace(
        original,
        generation=2,
        previous_assignment_sha256=original.semantic_sha256,
        policy=replace(original.policy, max_order_quantity=D(100)),
    )
    assert next_assignment.previous_assignment_sha256 == original.semantic_sha256
    assert next_assignment.policy.semantic_sha256 != original.policy.semantic_sha256
    for policy in (
        replace(original.policy, daily_loss_boundary=D("-.04")),
        replace(original.policy, drawdown_boundary=D(".2")),
        replace(original.policy, policy_scope="synthetic_oracle"),
    ):
        with pytest.raises(ValueError):
            replace(original, policy=policy)


def test_producer_roles_are_exact_complete_ordered_and_versioned() -> None:
    producer_map = runtime_case()[4]
    with pytest.raises(ValueError):
        RuntimeProducerMap(producers=producer_map.producers[:-1])
    with pytest.raises(ValueError):
        RuntimeProducerMap(producers=tuple(reversed(producer_map.producers)))
    with pytest.raises(ValueError):
        replace(producer_map.producers[0], role="engine")
    changed = RuntimeProducerMap(
        producers=(
            replace(producer_map.producers[0], producer=VersionPin("account", "changed/2", SHA)),
            *producer_map.producers[1:],
        )
    )
    assert changed.semantic_sha256 != producer_map.semantic_sha256


def test_original_hold_policy_and_source_identity_cannot_be_rewritten_or_duplicated() -> None:
    value = RuntimeCommitmentBinding(
        account_id="account",
        commitment=commitment(),
        origin="legacy_phase2",
        source_id="retained",
        source_sha256=SHA,
        original_policy_sha256=SHA,
        projection=VersionPin("legacy_projection", "fixture/1", SHA),
    )
    with pytest.raises(ValueError, match="original policy"):
        replace(value, original_policy_sha256="b" * 64)
    with pytest.raises(ValueError, match="sorted and unique"):
        inventory((value, value))
    with pytest.raises(ValueError, match="source identities"):
        inventory(
            (value, replace(value, commitment=replace(value.commitment, commitment_id="second")))
        )
    record = inventory((value,))
    with pytest.raises(ValueError, match="universe"):
        replace(record, legacy_universe_sha256="b" * 64)
    assert record.bindings[0].commitment is value.commitment


def test_blocked_input_and_check_must_retain_reasons_without_integer_boolean_coercion() -> None:
    source = runtime_case()[3].sources[0]
    for changes in (
        {"status": "blocked"},
        {"status": "available", "reasons": ("BLOCK",)},
        {"revision": True},
    ):
        with pytest.raises(ValueError):
            replace(source, **changes)
    with pytest.raises(ValueError):
        RuntimeRiskCheck(rule="cash", status="pass", sources=(), reasons=("MISSING",))
    with pytest.raises(ValueError):
        RuntimeRiskCheck(rule="cash", status="unavailable", sources=())


def decision(fact: DailyRuntimeRiskEvidence, *, approved: bool = True) -> DailyRiskDecision:
    return DailyRiskDecision(
        approved=approved,
        batch=runtime_case()[2],
        policy_sha256=fact.assignment.policy.semantic_sha256,
        evidence_sha256=fact.semantic_sha256,
        reserved_cash_by_intent=(),
        reserved_shares_by_intent=(),
        reasons=() if approved else ("EXPIRED",),
    )


def test_admission_binds_exact_policy_evidence_batch_and_never_live_authority() -> None:
    fact = build(runtime_case())
    result = RuntimeRiskAdmission(
        evidence=fact, decision=decision(fact), recorded_at=NOW, expires_at=END
    )
    assert result.live_authorized is False
    for changes in (
        {"decision": replace(result.decision, evidence_sha256="b" * 64)},
        {"decision": replace(result.decision, policy_sha256=DailyRiskPolicy().semantic_sha256)},
        {"recorded_at": NOW - timedelta(microseconds=1)},
        {"expires_at": END + timedelta(microseconds=1)},
        {"expires_at": NOW},
        {"live_authorized": True},
    ):
        with pytest.raises(ValueError):
            replace(result, **changes)


def test_rejected_expired_decision_can_be_retained_without_active_admission() -> None:
    fact = build(runtime_case())
    record = RuntimeRiskAdmission(
        evidence=fact, decision=decision(fact, approved=False), recorded_at=END, expires_at=END
    )
    assert not record.decision.approved and not record.live_authorized


def test_canonical_entry_point_uses_runtime_producers_and_same_reservation_arithmetic() -> None:
    from packages.domain.daily_risk import evaluate_daily_risk

    case = runtime_case()
    fact = build(case)
    result = evaluate_daily_risk(case[0].policy, case[1], case[2], fact, case[5])
    assert result.approved and result.reasons == ()
    assert result.reserved_cash_by_intent == ((case[2].intents[0].intent_id, D("2424.24")),)
    assert result.evidence_sha256 == fact.semantic_sha256
    assert result.policy_sha256 == case[0].policy.semantic_sha256
    admission = RuntimeRiskAdmission(
        evidence=fact, decision=result, recorded_at=NOW, expires_at=END
    )
    assert admission.live_authorized is False


def test_forged_pass_checks_cannot_hide_missing_runtime_producer() -> None:
    from packages.domain.daily_risk import evaluate_daily_risk

    case = runtime_case()
    inputs = replace(case[3], sources=tuple(s for s in case[3].sources if s.spec.role != "cash"))
    actual = build(case, inputs=inputs)
    forged = replace(actual, checks=(RuntimeRiskCheck(rule="cash", status="pass", sources=()),))
    result = evaluate_daily_risk(case[0].policy, case[1], case[2], forged, NOW)
    assert not result.approved and result.reserved_cash_by_intent == ()
    assert "RUNTIME_SOURCE_MISSING:cash" in result.reasons
    assert "RUNTIME_EVIDENCE_RECOMPUTATION_MISMATCH" in result.reasons


def test_runtime_policy_and_account_snapshot_cannot_be_substituted_after_validation() -> None:
    from packages.domain.daily_risk import evaluate_daily_risk

    case = runtime_case()
    fact = build(case)
    policy = replace(case[0].policy, max_order_quantity=D(100))
    result = evaluate_daily_risk(policy, case[1], case[2], fact, NOW)
    assert not result.approved and "RUNTIME_POLICY_ASSIGNMENT_MISMATCH" in result.reasons
    changed = replace(case[1], available_cash=D(0))
    result = evaluate_daily_risk(case[0].policy, changed, case[2], fact, NOW)
    assert not result.approved
    assert "RUNTIME_EVIDENCE_RECOMPUTATION_MISMATCH" in result.reasons
    assert "RUNTIME_SNAPSHOT_BINDING_MISMATCH" in result.reasons


def test_historical_policy_evidence_and_decision_hashes_remain_literal() -> None:
    from packages.domain.daily_risk import evaluate_daily_risk
    from packages.domain.portfolio import daily_target_to_intents
    from tests.unit.test_daily_risk import evidence
    from tests.unit.test_daily_target_conversion import PIN, account, target

    snapshot = account()
    batch = daily_target_to_intents(target("24"), snapshot, strategy_pin=PIN)
    fact = evidence(snapshot.semantic_sha256)
    policy = DailyRiskPolicy()
    result = evaluate_daily_risk(policy, snapshot, batch, fact, NOW)
    assert (
        policy.semantic_sha256 == "ccbc97f330a817678a1902027edf299ed7e2bb98e13a21c12a643b1584a63360"
    )
    assert (
        fact.semantic_sha256 == "99ae858b2241bc202475b6c79fe5f4f084d3e63feec84d16ee8d5bd0192494a5"
    )
    assert (
        result.semantic_sha256 == "f988d02122e9836f673eed2042a28b6c593fdd3151e7aebd14492b367709b062"
    )
    wrong = replace(fact, producer=replace(fact.producer, name="runtime"))
    assert (
        "UNRECOGNIZED_EVIDENCE_PRODUCER"
        in evaluate_daily_risk(policy, snapshot, batch, wrong, NOW).reasons
    )


def test_runtime_loss_boundaries_and_new_intent_count_use_shared_arithmetic() -> None:
    from packages.domain.daily_risk import evaluate_daily_risk
    from packages.domain.daily_runtime_risk import runtime_source_value_sha256

    case = runtime_case()
    for changes, reason in (
        ({"daily_return": D("-.03")}, "LOSS_CONTROL_BLOCKS_NEW_EXPOSURE"),
        ({"drawdown": D(".15")}, "LOSS_CONTROL_BLOCKS_NEW_EXPOSURE"),
        ({"daily_return": None}, "FLOW_NEUTRAL_LOSS_EVIDENCE_REQUIRED"),
        ({"accepted_intent_ids": tuple(str(i) for i in range(8))}, "SESSION_INTENT_LIMIT"),
    ):
        inputs = replace(case[3], **changes)
        inputs = replace(
            inputs,
            sources=tuple(
                replace(
                    s,
                    value_sha256=runtime_source_value_sha256(s.spec.role, case[1], case[2], inputs),
                )
                for s in inputs.sources
            ),
        )
        result = evaluate_daily_risk(
            case[0].policy, case[1], case[2], build(case, inputs=inputs), NOW
        )
        assert not result.approved and reason in result.reasons
        assert result.reserved_cash_by_intent == ()


@pytest.mark.parametrize(
    "side,basis,approved",
    [
        (Side.BUY, "runtime_quote_ask_v1", True),
        (Side.BUY, "runtime_quote_bid_v1", False),
        (Side.BUY, "raw_execution", False),
        (Side.SELL, "runtime_quote_bid_v1", True),
        (Side.SELL, "runtime_quote_ask_v1", False),
        (Side.SELL, "raw_execution", False),
    ],
)
def test_runtime_activation_replaces_only_its_own_current_policy_hold_once(
    side: Side, basis: str, approved: bool
) -> None:
    from packages.domain.daily_risk import evaluate_daily_risk
    from packages.domain.daily_runtime_risk import runtime_source_value_sha256
    from packages.domain.personal_contracts import ReductionPoint
    from tests.unit.test_daily_risk_snapshot import START
    from tests.unit.test_daily_target_conversion import EXECUTION, account

    initial = runtime_case(snapshot=account(quantity="0" if side is Side.BUY else "48"))
    if side is Side.SELL:
        initial = (
            initial[0],
            initial[1],
            replace(initial[2], target=replace(initial[2].target, reduce_only_scope=True)),
            *initial[3:],
        )
    reserve = D("2424.24") if side is Side.BUY else D(".24")
    pending = replace(
        commitment(quantity="24", side=side),
        intent_id=initial[2].intents[0].intent_id,
        reserved_cash=reserve,
        remaining_fee_budget=D(".24"),
        policy_sha256=initial[0].policy.semantic_sha256,
        not_before=START,
        expires_at=END,
    )
    snapshot = replace(
        initial[1],
        commitments=(pending,),
        available_cash=D("7575.76") if side is Side.BUY else D("9999.76"),
        buy_reserve=reserve if side is Side.BUY else D(0),
        sell_fee_reserve=reserve if side is Side.SELL else D(0),
        point=ReductionPoint(2, 10, START, 3),
        marks=(
            replace(
                initial[1].marks[0],
                session=EXECUTION,
                economic_at=START,
                knowledge_at=START,
                basis=basis,
            ),
        ),
    )
    case = runtime_case(
        snapshot=snapshot,
        batch=replace(initial[2], snapshot_sha256=snapshot.semantic_sha256),
        phase="activation",
        now=START,
    )
    inputs = replace(case[3], accepted_intent_ids=(pending.intent_id,))
    inputs = replace(
        inputs,
        sources=tuple(
            replace(
                s, value_sha256=runtime_source_value_sha256(s.spec.role, snapshot, case[2], inputs)
            )
            for s in inputs.sources
        ),
    )
    fact = build(case, inputs=inputs)
    result = evaluate_daily_risk(case[0].policy, snapshot, case[2], fact, START)
    assert result.approved is approved
    if approved:
        assert result.reserved_cash_by_intent[0][1] == reserve
        if side is Side.SELL:
            assert result.reserved_shares_by_intent == ((pending.intent_id, D(24)),)
    else:
        assert result.reserved_cash_by_intent == ()
        assert "RUNTIME_ACTIVATION_REQUIRES_SIDE_QUOTE" in result.reasons
    assert "UNRECOGNIZED_EVIDENCE_PRODUCER" not in result.reasons


def test_runtime_activation_duplicate_marks_cannot_be_hidden_by_dictionary_projection() -> None:
    from tests.unit.test_daily_risk_snapshot import START

    initial = runtime_case()
    snapshot = replace(initial[1], marks=initial[1].marks * 2)
    case = runtime_case(
        snapshot=snapshot,
        batch=replace(initial[2], snapshot_sha256=snapshot.semantic_sha256),
        phase="activation",
        now=START,
    )
    assert "RUNTIME_DUPLICATE_INSTRUMENT_MARK" in build(case).reasons


def test_runtime_reservation_ignores_ambient_precision_and_traps() -> None:
    from decimal import Inexact, localcontext

    from packages.domain.daily_risk import evaluate_daily_risk

    case = runtime_case()
    fact = build(case)
    with localcontext() as context:
        context.prec = 1
        context.traps[Inexact] = True
        result = evaluate_daily_risk(case[0].policy, case[1], case[2], fact, NOW)
    assert result.approved and result.reserved_cash_by_intent[0][1] == D("2424.24")


def exposure_activation_case(*, kind="held", mark_changes=None, missing=False, state="working"):
    """Self-consistent synthetic source pins isolate non-batch exposure valuation."""
    from packages.domain.accounting_contracts import PositionState
    from packages.domain.daily_runtime_risk import runtime_source_value_sha256
    from packages.domain.personal_contracts import ReductionPoint
    from tests.unit.test_daily_risk_snapshot import START
    from tests.unit.test_daily_target_conversion import EXECUTION

    initial = runtime_case()
    own = replace(
        commitment(quantity="24"),
        intent_id=initial[2].intents[0].intent_id,
        reserved_cash=D("2424.24"),
        remaining_fee_budget=D(".24"),
        policy_sha256=initial[0].policy.semantic_sha256,
        not_before=START,
        expires_at=END,
    )
    other = replace(
        commitment(quantity="1"),
        commitment_id="qqq-existing",
        intent_id="qqq-existing",
        order_id="qqq-existing",
        instrument_id="qqq",
        symbol="QQQ",
        reserved_cash=D("101.01"),
        remaining_fee_budget=D(".01"),
        state=state,
    )
    fresh = replace(
        initial[1].marks[0],
        session=EXECUTION,
        economic_at=START,
        knowledge_at=START,
        basis="runtime_quote_ask_v1",
    )
    qqq = replace(
        fresh, mark_id="qqq-mark", instrument_id="qqq", symbol="QQQ", basis="runtime_quote_bid_v1"
    )
    qqq = replace(qqq, **(mark_changes or {}))
    pending = (own,) if kind == "held" else (own, other)
    snapshot = replace(
        initial[1],
        positions=(PositionState("qqq", "QQQ", D(1), D(100), ()),) if kind == "held" else (),
        commitments=pending,
        available_cash=D("7575.76") if kind == "held" else D("7474.75"),
        buy_reserve=D("2424.24") if kind == "held" else D("2525.25"),
        point=ReductionPoint(2, 10, START, 3),
        marks=(fresh,) if missing else (qqq, fresh),
        market_value=D(100) if kind == "held" else D(0),
        nav=D(10100) if kind == "held" else D(10000),
    )
    case = runtime_case(
        snapshot=snapshot,
        batch=replace(initial[2], snapshot_sha256=snapshot.semantic_sha256),
        phase="activation",
        now=START,
    )
    assignment = replace(case[0], instrument_symbols=(("qqq", "QQQ"), ("spy", "SPY")))
    inputs = replace(
        case[3],
        assignment_sha256=assignment.semantic_sha256,
        accepted_intent_ids=tuple(sorted(item.intent_id for item in pending)),
    )
    inputs = replace(
        inputs,
        sources=tuple(
            replace(
                source,
                value_sha256=runtime_source_value_sha256(
                    source.spec.role, snapshot, case[2], inputs
                ),
            )
            for source in inputs.sources
        ),
    )
    return assignment, snapshot, case[2], inputs, case[4], START


@pytest.mark.parametrize("kind", ["held", "remaining_buy"])
@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "prior_session",
        "expired",
        "economic_future",
        "knowledge_future",
        "symbol",
        "last_known",
        "raw_close",
    ],
)
def test_activation_requires_current_quoted_nonbatch_exposure_even_with_matching_hashes(
    kind, change
):
    from packages.domain.daily_risk import evaluate_daily_risk
    from tests.unit.test_daily_risk_snapshot import START
    from tests.unit.test_daily_target_conversion import SOURCE

    changes = {
        "missing": {},
        "prior_session": {"session": SOURCE},
        "expired": {"economic_at": START - timedelta(seconds=5)},
        "economic_future": {
            "economic_at": START + timedelta(microseconds=1),
            "knowledge_at": START + timedelta(microseconds=1),
        },
        "knowledge_future": {"knowledge_at": START + timedelta(microseconds=1)},
        "symbol": {"symbol": "OTHER"},
        "last_known": {"quality": "last_known"},
        "raw_close": {"basis": "raw_close"},
    }[change]
    case = exposure_activation_case(kind=kind, mark_changes=changes, missing=change == "missing")
    fact = build(case)
    expected = (
        "RUNTIME_EXPOSURE_QUOTE_MARK_REQUIRED"
        if change == "missing"
        else (
            "RUNTIME_EXPOSURE_REQUIRES_QUOTE_MARK"
            if change == "raw_close"
            else "RUNTIME_EXPOSURE_QUOTE_MARK_NOT_CURRENT"
        )
    )
    result = evaluate_daily_risk(case[0].policy, case[1], case[2], fact, START)
    assert not result.approved and expected in result.reasons
    assert result.reserved_cash_by_intent == ()
    assert not any("SOURCE_VALUE_MISMATCH" in reason for reason in result.reasons)


@pytest.mark.parametrize("kind", ["held", "remaining_buy"])
def test_current_quoted_nonbatch_exposure_keeps_runtime_arithmetic_available(kind):
    from packages.domain.daily_risk import evaluate_daily_risk

    case = exposure_activation_case(kind=kind)
    result = evaluate_daily_risk(case[0].policy, case[1], case[2], build(case), case[5])
    assert result.approved, result.reasons
    assert result.reserved_cash_by_intent == ((case[2].intents[0].intent_id, D("2424.24")),)


@pytest.mark.parametrize(
    "state", ["approved_unsent", "active", "working", "partial", "unknown", "pending_cancel"]
)
def test_every_remaining_buy_state_requires_its_own_current_exposure_mark(state):
    from tests.unit.test_daily_risk_snapshot import START

    case = exposure_activation_case(
        kind="remaining_buy",
        state=state,
        mark_changes={"economic_at": START - timedelta(seconds=5)},
    )
    assert "RUNTIME_EXPOSURE_QUOTE_MARK_NOT_CURRENT" in build(case).reasons


@pytest.mark.parametrize("kind", ["held", "remaining_buy"])
def test_normalized_synthetic_quote_records_cover_nonbatch_exposure_without_refresh(kind):
    from packages.application.runtime_quote_marks import (
        RuntimeQuoteMarkRequest,
        build_runtime_quote_marks,
    )
    from packages.domain.daily_risk import evaluate_daily_risk
    from packages.domain.daily_runtime_risk import runtime_source_value_sha256
    from tests.unit.test_daily_risk_snapshot import START
    from tests.unit.test_daily_target_conversion import EXECUTION
    from tests.unit.test_personal_forward_data import observation, requirement, source

    case = exposure_activation_case(kind=kind)
    src = source(account_scope="account")
    requests = []
    for instrument_id, symbol, side in (("qqq", "QQQ", Side.SELL), ("spy", "SPY", Side.BUY)):
        obs = observation(
            "fixture-" + instrument_id,
            src=src,
            at=START - timedelta(milliseconds=100),
            revision_key="quote-" + instrument_id,
        )
        obs = replace(
            obs,
            payload=replace(
                obs.payload,
                instrument_id=instrument_id,
                symbol=symbol,
                session=EXECUTION,
                bid=D(100),
                ask=D(100),
            ),
        )
        requests.append(
            RuntimeQuoteMarkRequest(
                obs,
                src,
                replace(requirement(instrument=instrument_id, symbol=symbol), session=EXECUTION),
                side,
                VersionPin("quote_normalization", "synthetic-fixture/1", SHA),
            )
        )
    marks = build_runtime_quote_marks(
        tuple(requests),
        environment="production",
        account_scope="account",
        evaluated_at=START,
        boot_id="boot-1",
        evaluated_monotonic_ns=1100000000,
    )
    snapshot = replace(case[1], marks=marks)
    batch = replace(case[2], snapshot_sha256=snapshot.semantic_sha256)
    inputs = replace(case[3], snapshot_sha256=snapshot.semantic_sha256)
    inputs = replace(
        inputs,
        sources=tuple(
            replace(
                item,
                value_sha256=runtime_source_value_sha256(item.spec.role, snapshot, batch, inputs),
            )
            for item in inputs.sources
        ),
    )
    updated = (case[0], snapshot, batch, inputs, case[4], START)
    result = evaluate_daily_risk(case[0].policy, snapshot, batch, build(updated), START)
    assert result.approved, result.reasons
    assert tuple(mark.source_sha256 for mark in marks) == tuple(
        item.semantic_sha256 for item in requests
    )
    assert all(mark.knowledge_at == START - timedelta(milliseconds=80) for mark in marks)
    assert all(mark.economic_at == START - timedelta(milliseconds=1100) for mark in marks)


@pytest.mark.parametrize(
    "age",
    [timedelta(seconds=59, microseconds=999999), timedelta(seconds=60), timedelta(seconds=61)],
)
def test_latest_reconciliation_receipt_cannot_refresh_earlier_financial_observation(age):
    from packages.domain.daily_risk import evaluate_daily_risk
    from packages.domain.daily_runtime_risk import runtime_source_value_sha256

    case = runtime_case()
    inputs = replace(
        case[3],
        reconciliation=replace(
            case[3].reconciliation,
            observation_started_at=NOW - age,
            observation_received_through=NOW,
            completed_at=NOW,
        ),
    )
    inputs = replace(
        inputs,
        sources=tuple(
            replace(
                source,
                value_sha256=runtime_source_value_sha256(
                    source.spec.role, case[1], case[2], inputs
                ),
            )
            for source in inputs.sources
        ),
    )
    changed = (*case[:3], inputs, *case[4:])
    evidence = build(changed)
    decision = evaluate_daily_risk(case[0].policy, case[1], case[2], evidence, NOW)
    assert decision.approved is (age < timedelta(seconds=60))
    assert ("RUNTIME_RECONCILIATION_OBSERVATION_STALE" in decision.reasons) is (
        age >= timedelta(seconds=60)
    )
    assert "RUNTIME_RECONCILIATION_STALE" not in decision.reasons
    assert "RUNTIME_RECONCILIATION_RECEIPT_STALE" not in decision.reasons
