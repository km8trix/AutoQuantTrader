from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Inexact, localcontext
from typing import Literal

import pytest

from packages.application.daily_risk_snapshot import (
    build_daily_runtime_evidence,
    runtime_source_value_sha256,
)
from packages.domain.accounting_contracts import AccountSnapshot
from packages.domain.daily_runtime_contracts import (
    RUNTIME_POLICY_ID,
    RUNTIME_ROLES,
    DailyRuntimeRiskEvidence,
    RuntimeCommitmentBinding,
    RuntimeObligationInventory,
    RuntimeProducerMap,
    RuntimeProducerSpec,
    RuntimeRiskAssignment,
    RuntimeRiskInputRefs,
    RuntimeRiskSource,
)
from packages.domain.engine_contracts import DailyIntentBatch, DailyRiskPolicy
from packages.domain.models import Side
from packages.domain.personal_contracts import ReductionPoint, VersionPin, content_digest
from packages.domain.portfolio import daily_target_to_intents
from packages.domain.reconciliation_contracts import (
    ReconciliationHeads,
    ReconciliationResult,
    ReconciliationScope,
)
from tests.unit.test_daily_target_conversion import (
    EXECUTION,
    NOW,
    PIN,
    SHA,
    SOURCE,
    D,
    account,
    commitment,
    target,
)

START = datetime(2025, 2, 4, 14, 35, tzinfo=UTC)
END = datetime(2025, 2, 4, 14, 40, tzinfo=UTC)
Case = tuple[
    RuntimeRiskAssignment,
    AccountSnapshot,
    DailyIntentBatch,
    RuntimeRiskInputRefs,
    RuntimeProducerMap,
    datetime,
]


def inventory(bindings: tuple[RuntimeCommitmentBinding, ...]) -> RuntimeObligationInventory:
    return RuntimeObligationInventory(
        bindings=tuple(sorted(bindings, key=lambda item: item.commitment.commitment_id)),
        legacy_universe_sha256=content_digest(
            tuple(item for item in bindings if item.origin == "legacy_phase2")
        ),
        daily_universe_sha256=content_digest(
            tuple(item for item in bindings if item.origin == "daily_runtime")
        ),
    )


def runtime_case(
    *,
    snapshot: AccountSnapshot | None = None,
    batch: DailyIntentBatch | None = None,
    phase: Literal["decision", "activation"] = "decision",
    now: datetime = NOW,
    bindings: tuple[RuntimeCommitmentBinding, ...] | None = None,
) -> Case:
    snapshot = account() if snapshot is None else snapshot
    batch = (
        daily_target_to_intents(
            replace(target("24"), not_before=START, expires_at=END), snapshot, strategy_pin=PIN
        )
        if batch is None
        else batch
    )
    producer_map = RuntimeProducerMap(
        producers=tuple(
            RuntimeProducerSpec(
                role=role,
                producer=VersionPin(role, "explicit-fixture/1", SHA),
                provider_id="simulator",
                source_environment="stateful_simulation",
                account_scope="account",
            )
            for role in RUNTIME_ROLES
        )
    )
    assignment = RuntimeRiskAssignment(
        account_id="account",
        account_binding_sha256=SHA,
        generation=1,
        policy=DailyRiskPolicy(policy_id=RUNTIME_POLICY_ID),
        strategy=PIN,
        configuration_sha256=SHA,
        instrument_symbols=(("spy", "SPY"),),
        producer_map_sha256=producer_map.semantic_sha256,
        effective_at=NOW - timedelta(hours=1),
        enabled_for_new_exposure=True,
    )
    if bindings is None:
        bindings = tuple(
            RuntimeCommitmentBinding(
                account_id=snapshot.account_id,
                commitment=item,
                origin="legacy_phase2",
                source_id=item.commitment_id,
                source_sha256=SHA,
                original_policy_sha256=item.policy_sha256,
                projection=VersionPin("legacy_projection", "fixture-authenticated/1", SHA),
            )
            for item in snapshot.commitments
        )
    obligations = inventory(bindings)
    heads = ReconciliationHeads(
        snapshot.journal_sha256, snapshot.order_sha256, obligations.semantic_sha256, 0, SHA, 0, 1
    )
    observed = now - timedelta(milliseconds=500)
    reconciliation = ReconciliationResult(
        scope=ReconciliationScope(
            "account", "simulator", "stateful_simulation", SHA, "stateful_simulation"
        ),
        heads=heads,
        round_sha256=SHA,
        previous_result_sha256=SHA,
        observation_started_at=now - timedelta(seconds=2),
        observation_received_through=observed,
        coverage_from=now - timedelta(days=1),
        coverage_through=observed,
        applied_through=observed,
        completed_at=now - timedelta(milliseconds=100),
        status="converged",
        blocking_reasons=(),
        discrepancies=(),
        source_receipt_ids=("receipt",),
    )
    inputs = RuntimeRiskInputRefs(
        snapshot_sha256=snapshot.semantic_sha256,
        assignment_sha256=assignment.semantic_sha256,
        heads=heads,
        phase=phase,
        source_session=SOURCE,
        execution_session=EXECUTION,
        sources=(),
        obligations=obligations,
        reconciliation=reconciliation,
        accepted_intent_ids=(),
        daily_return=D(0),
        drawdown=D(0),
        cash_restrictions=D(0),
    )
    inputs = replace(
        inputs,
        sources=tuple(
            RuntimeRiskSource(
                spec=spec,
                account_id="account",
                account_binding_sha256=SHA,
                source_id="source." + spec.role,
                source_sha256=content_digest(("retained-source", spec.role)),
                value_sha256=runtime_source_value_sha256(spec.role, snapshot, batch, inputs),
                revision=0,
                source_at=now - timedelta(milliseconds=250),
                received_at=now - timedelta(milliseconds=200),
                valid_until=now + timedelta(seconds=30),
                status="available",
            )
            for spec in producer_map.producers
            if spec.role != "quotes" or phase == "activation"
        ),
    )
    return assignment, snapshot, batch, inputs, producer_map, now


def build(case: Case, *, inputs: RuntimeRiskInputRefs | None = None) -> DailyRuntimeRiskEvidence:
    assignment, snapshot, batch, original, producer_map, now = case
    return build_daily_runtime_evidence(
        assignment,
        snapshot,
        batch,
        original if inputs is None else inputs,
        producer_map=producer_map,
        evaluated_at=now,
    )


def changed_source(case: Case, role: str, **changes: object) -> RuntimeRiskInputRefs:
    inputs = case[3]
    return replace(
        inputs,
        sources=tuple(
            replace(source, **changes) if source.spec.role == role else source
            for source in inputs.sources
        ),
    )


def test_explicit_runtime_sources_build_without_fabricated_engine_producer() -> None:
    case = runtime_case()
    fact = build(case)
    assert fact.reasons == ()
    assert all(item.status == "pass" for item in fact.checks)
    assert {source.spec.producer.name for source in fact.inputs.sources} == set(RUNTIME_ROLES) - {
        "quotes"
    }
    assert fact.assignment.environment == "stateful_simulation"
    assert fact.assignment.live_authorized is False
    assert build(case).semantic_sha256 == fact.semantic_sha256


@pytest.mark.parametrize("role", tuple(role for role in RUNTIME_ROLES if role != "quotes"))
def test_missing_mandatory_producer_is_unavailable(role: str) -> None:
    case = runtime_case()
    inputs = replace(case[3], sources=tuple(s for s in case[3].sources if s.spec.role != role))
    fact = build(case, inputs=inputs)
    assert "RUNTIME_SOURCE_MISSING:" + role in fact.reasons
    assert next(c for c in fact.checks if c.rule == "source:" + role).status == "unavailable"


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"account_id": "foreign"}, "RUNTIME_SOURCE_ACCOUNT_MISMATCH:cash"),
        ({"account_binding_sha256": "b" * 64}, "RUNTIME_SOURCE_ACCOUNT_MISMATCH:cash"),
        ({"value_sha256": "b" * 64}, "RUNTIME_SOURCE_VALUE_MISMATCH:cash"),
        ({"valid_until": NOW}, "RUNTIME_SOURCE_EXPIRED:cash"),
        (
            {"source_at": NOW, "received_at": NOW + timedelta(microseconds=1)},
            "RUNTIME_SOURCE_FUTURE:cash",
        ),
        ({"status": "unavailable", "reasons": ("UNQUALIFIED_CASH",)}, "UNQUALIFIED_CASH"),
    ],
)
def test_source_binding_status_and_inclusive_expiry_fail_closed(
    change: dict[str, object], reason: str
) -> None:
    case = runtime_case()
    assert reason in build(case, inputs=changed_source(case, "cash", **change)).reasons


def test_same_source_hash_cannot_substitute_foreign_version_environment_or_scope() -> None:
    case = runtime_case()
    cash = next(s for s in case[3].sources if s.spec.role == "cash")
    for spec in (
        replace(cash.spec, source_environment="production"),
        replace(cash.spec, account_scope="foreign"),
        replace(cash.spec, producer=replace(cash.spec.producer, sha256="b" * 64)),
    ):
        assert (
            "RUNTIME_SOURCE_PRODUCER_MISMATCH:cash"
            in build(case, inputs=changed_source(case, "cash", spec=spec)).reasons
        )


def test_clock_observation_cannot_be_refreshed_by_new_receipt() -> None:
    case = runtime_case()
    inputs = changed_source(case, "clock", source_at=NOW - timedelta(seconds=30))
    assert "RUNTIME_CLOCK_STALE" in build(case, inputs=inputs).reasons


@pytest.mark.parametrize(
    "head",
    [
        "ledger_sha256",
        "order_sha256",
        "capacity_sha256",
        "attempt_sha256",
        "effect_watermark",
        "control_revision",
        "lease_generation",
    ],
)
def test_any_new_durable_head_invalidates_reconciliation_without_refreshing_completion(
    head: str,
) -> None:
    case = runtime_case()
    old = case[3].heads
    value: object = "b" * 64 if head.endswith("sha256") else getattr(old, head) + 1
    inputs = replace(case[3], heads=replace(old, **{head: value}))
    assert "RUNTIME_RECONCILIATION_HEADS_CHANGED" in build(case, inputs=inputs).reasons


def test_recent_comparison_does_not_refresh_old_observation() -> None:
    case = runtime_case()
    old = case[3].reconciliation
    assert old is not None
    observed = NOW - timedelta(seconds=60)
    result = replace(
        old,
        observation_started_at=observed,
        observation_received_through=observed,
        coverage_through=observed,
        applied_through=observed,
    )
    assert (
        "RUNTIME_RECONCILIATION_RECEIPT_STALE"
        in build(case, inputs=replace(case[3], reconciliation=result)).reasons
    )
    result = replace(old, scope=replace(old.scope, provider_id="foreign"))
    assert (
        "RUNTIME_RECONCILIATION_SCOPE_MISMATCH"
        in build(case, inputs=replace(case[3], reconciliation=result)).reasons
    )


def test_missing_reconciliation_is_not_a_simulator_pass() -> None:
    case = runtime_case()
    assert (
        "RUNTIME_RECONCILIATION_UNAVAILABLE"
        in build(case, inputs=replace(case[3], reconciliation=None)).reasons
    )


def test_full_old_and_new_inventory_preserves_original_policy_and_payable_overlap() -> None:
    old = replace(commitment(filled="4"), reserved_cash=D("606.06"), remaining_fee_budget=D(".06"))
    new = replace(
        commitment(side=Side.SELL, quantity="2"),
        commitment_id="new",
        intent_id="new-intent",
        order_id="new-order",
        instrument_id="qqq",
        symbol="QQQ",
        reserved_cash=D(".02"),
        policy_sha256="b" * 64,
    )
    snapshot = replace(
        account(commitments=(old, new)),
        trade_payable=D("400.04"),
        buy_reserve=D("606.06"),
        sell_fee_reserve=D(".02"),
        available_cash=D("8993.88"),
    )
    base = daily_target_to_intents(
        replace(target("24"), not_before=START, expires_at=END), account(), strategy_pin=PIN
    )
    bindings = tuple(
        RuntimeCommitmentBinding(
            account_id="account",
            commitment=item,
            origin=origin,
            source_id=item.commitment_id,
            source_sha256=content_digest((origin, item)),
            original_policy_sha256=item.policy_sha256,
            projection=VersionPin("projection", "fixture/1", SHA),
        )
        for item, origin in ((old, "legacy_phase2"), (new, "daily_runtime"))
    )
    case = runtime_case(
        snapshot=snapshot,
        batch=replace(base, snapshot_sha256=snapshot.semantic_sha256),
        bindings=bindings,
    )
    assignment = replace(case[0], instrument_symbols=(("qqq", "QQQ"), ("spy", "SPY")))
    inputs = replace(case[3], assignment_sha256=assignment.semantic_sha256)
    # Economic check is independent from deliberately unchanged source-value bindings.
    fact = build((assignment, *case[1:3], inputs, *case[4:]))
    assert next(c for c in fact.checks if c.rule == "obligations").reasons == ()
    assert tuple(b.original_policy_sha256 for b in inputs.obligations.bindings) == (SHA, "b" * 64)
    assert snapshot.available_cash == D(
        "8993.88"
    )  # Filled 400.04 is payable; only 606.06 remains held.
    with localcontext() as context:
        context.prec = 1
        context.traps[Inexact] = True
        assert next(c for c in build(case).checks if c.rule == "obligations").reasons == ()
    missing = replace(inputs, obligations=inventory((bindings[1],)))
    assert "RUNTIME_FULL_COMMITMENT_INVENTORY_MISMATCH" in build(case, inputs=missing).reasons


def test_unknown_hold_cannot_disappear_or_be_reclassified_by_a_new_policy() -> None:
    pending = replace(commitment(), state="unknown")
    snapshot = replace(account(commitments=(pending,)), buy_reserve=D(1010), available_cash=D(8990))
    base = runtime_case()[2]
    case = runtime_case(
        snapshot=snapshot, batch=replace(base, snapshot_sha256=snapshot.semantic_sha256)
    )
    assert "RUNTIME_UNKNOWN_OBLIGATION" in build(case).reasons
    empty = replace(case[3], obligations=inventory(()))
    assert "RUNTIME_FULL_COMMITMENT_INVENTORY_MISMATCH" in build(case, inputs=empty).reasons
    assert build(case).inputs.obligations.bindings[0].original_policy_sha256 == SHA


def test_missing_cash_restrictions_is_not_zero_and_double_subtraction_rejects() -> None:
    case = runtime_case()
    assert (
        "RUNTIME_CASH_RESTRICTIONS_UNAVAILABLE"
        in build(case, inputs=replace(case[3], cash_restrictions=None)).reasons
    )
    assert (
        "RUNTIME_AVAILABLE_CASH_MISMATCH"
        in build(case, inputs=replace(case[3], cash_restrictions=D(1))).reasons
    )


@pytest.mark.parametrize(
    "source_age,receipt_age,reason",
    [
        (5, 0.2, "RUNTIME_QUOTE_SOURCE_STALE"),
        (2, 1, "RUNTIME_QUOTE_RECEIPT_STALE"),
    ],
)
def test_activation_requires_quote_source_and_receipt_strict_boundaries(
    source_age: float, receipt_age: float, reason: str
) -> None:
    snapshot = replace(account(), point=ReductionPoint(2, 2, START, 5))
    base = runtime_case()[2]
    case = runtime_case(
        snapshot=snapshot,
        batch=replace(base, snapshot_sha256=snapshot.semantic_sha256),
        phase="activation",
        now=START,
    )
    inputs = changed_source(
        case,
        "quotes",
        source_at=START - timedelta(seconds=source_age),
        received_at=START - timedelta(seconds=receipt_age),
    )
    assert reason in build(case, inputs=inputs).reasons
    missing = replace(case[3], sources=tuple(s for s in case[3].sources if s.spec.role != "quotes"))
    assert "RUNTIME_SOURCE_MISSING:quotes" in build(case, inputs=missing).reasons


def test_historical_next_open_proxy_is_not_the_forward_window() -> None:
    case = runtime_case()
    batch = replace(case[2], target=target())
    assert "RUNTIME_FORWARD_WINDOW_REQUIRED" in build((*case[:2], batch, *case[3:])).reasons


@pytest.mark.parametrize(
    "phase,now,reason",
    [
        ("decision", datetime(2025, 2, 4, 14, tzinfo=UTC), "RUNTIME_DECISION_OUTSIDE_WINDOW"),
        ("activation", START - timedelta(microseconds=1), "RUNTIME_EXECUTION_OUTSIDE_WINDOW"),
        ("activation", END, "RUNTIME_EXECUTION_OUTSIDE_WINDOW"),
    ],
)
def test_daily_cutoff_and_forward_execution_equality_boundaries(
    phase: Literal["decision", "activation"], now: datetime, reason: str
) -> None:
    case = runtime_case(phase=phase, now=now)
    assert reason in build(case).reasons


def test_reconciliation_policy_must_be_exact_frozen_profile() -> None:
    case = runtime_case()
    result = case[3].reconciliation
    assert result is not None
    changed = replace(case[3], reconciliation=replace(result, policy_sha256="b" * 64))
    assert "RUNTIME_RECONCILIATION_POLICY_MISMATCH" in build(case, inputs=changed).reasons


@pytest.mark.parametrize("age", [timedelta(seconds=5), timedelta(microseconds=-1)])
def test_snapshot_age_equality_and_future_frontier_reject(age: timedelta) -> None:
    case = runtime_case()
    snapshot = replace(case[1], point=replace(case[1].point, knowledge_at=NOW - age))
    changed = (case[0], snapshot, *case[2:])
    assert "RUNTIME_SNAPSHOT_NOT_CURRENT" in build(changed).reasons


def test_assignment_checks_actual_configuration_and_instrument_identity() -> None:
    case = runtime_case()
    assigned = replace(case[0], configuration_sha256="b" * 64)
    assert "RUNTIME_STRATEGY_BINDING_MISMATCH" in build((assigned, *case[1:])).reasons
    assigned = replace(case[0], strategy=replace(case[0].strategy, name="unassigned"))
    assert "RUNTIME_STRATEGY_BINDING_MISMATCH" in build((assigned, *case[1:])).reasons
    assigned = replace(case[0], instrument_symbols=(("other-spy-id", "SPY"),))
    assert "RUNTIME_INSTRUMENT_BINDING_MISMATCH" in build((assigned, *case[1:])).reasons
