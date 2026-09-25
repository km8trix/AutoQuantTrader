"""Pure runtime producer validation; durable source authentication is caller-owned.

No SQL, provider call, clock sampling, legacy capacity inference or re-arm occurs
here. The account transaction resolves each reference to its exact retained
producer record before invoking this projection.
"""

from __future__ import annotations

from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

from packages.domain.accounting_contracts import AccountSnapshot
from packages.domain.daily_runtime_contracts import (
    RUNTIME_ROLES,
    DailyRuntimeRiskEvidence,
    RuntimeProducerMap,
    RuntimeRiskAssignment,
    RuntimeRiskCheck,
    RuntimeRiskInputRefs,
    RuntimeRole,
)
from packages.domain.decimal_math import exact_decimal_subtract, exact_decimal_sum
from packages.domain.engine_contracts import DailyIntentBatch
from packages.domain.models import Side
from packages.domain.personal_contracts import content_digest, require_utc
from packages.domain.reconciliation_contracts import ReconciliationPolicy


def runtime_source_value_sha256(
    role: RuntimeRole,
    snapshot: AccountSnapshot,
    batch: DailyIntentBatch,
    inputs: RuntimeRiskInputRefs,
) -> str:
    """Pin each normalized producer view; this digest is not authentication."""
    trigger = batch.target.trigger
    values: dict[RuntimeRole, object] = {
        "account": (snapshot.account_id, inputs.assignment_sha256),
        "cash": (
            snapshot.settled_cash,
            snapshot.trade_payable,
            snapshot.buy_reserve,
            snapshot.sell_fee_reserve,
            snapshot.available_cash,
            inputs.cash_restrictions,
        ),
        "clock": (inputs.heads.lease_generation, inputs.phase),
        "commitments": (inputs.obligations.semantic_sha256, inputs.heads),
        "controls": (inputs.heads.control_revision, inputs.assignment_sha256),
        "daily_inputs": (trigger.source_sha256, inputs.source_session, inputs.execution_session),
        "intent_registry": (inputs.execution_session, inputs.accepted_intent_ids),
        "ledger": (snapshot.state_sha256, snapshot.journal_sha256, snapshot.order_sha256),
        "loss": (snapshot.nav, snapshot.net_external_flow, inputs.daily_return, inputs.drawdown),
        "quotes": (inputs.phase, snapshot.marks),
        "reconciliation": None
        if inputs.reconciliation is None
        else inputs.reconciliation.semantic_sha256,
        "request_budget": (inputs.phase, batch.semantic_sha256),
        "session": (
            inputs.source_session,
            inputs.execution_session,
            batch.target.not_before,
            batch.target.expires_at,
        ),
    }
    if role not in values:
        raise ValueError("unrecognized runtime source role")
    return content_digest(("personal-daily-runtime-source-values/1", role, values[role]))


def build_daily_runtime_evidence(
    assignment: RuntimeRiskAssignment,
    snapshot: AccountSnapshot,
    batch: DailyIntentBatch,
    inputs: RuntimeRiskInputRefs,
    *,
    producer_map: RuntimeProducerMap,
    evaluated_at: datetime,
) -> DailyRuntimeRiskEvidence:
    """Return complete deterministic reasons; no missing producer becomes PASS."""
    for input_record, expected_type in (
        (assignment, RuntimeRiskAssignment),
        (snapshot, AccountSnapshot),
        (batch, DailyIntentBatch),
        (inputs, RuntimeRiskInputRefs),
        (producer_map, RuntimeProducerMap),
    ):
        if type(input_record) is not expected_type:
            raise ValueError("runtime risk requires exact immutable input records")
    require_utc(evaluated_at, "runtime risk evaluation")
    checks: list[RuntimeRiskCheck] = []

    def check(
        rule: str, reasons: list[str], sources: tuple[str, ...] = (), *, missing: bool = False
    ) -> None:
        checks.append(
            RuntimeRiskCheck(
                rule=rule,
                status="unavailable" if missing else ("fail" if reasons else "pass"),
                sources=tuple(sorted(set(sources))),
                reasons=tuple(sorted(set(reasons))),
            )
        )

    binding: list[str] = []
    if assignment.account_id != snapshot.account_id:
        binding.append("RUNTIME_ACCOUNT_MISMATCH")
    if assignment.producer_map_sha256 != producer_map.semantic_sha256:
        binding.append("RUNTIME_PRODUCER_MAP_MISMATCH")
    if assignment.effective_at > evaluated_at:
        binding.append("RUNTIME_ASSIGNMENT_NOT_EFFECTIVE")
    if not assignment.enabled_for_new_exposure:
        binding.append("RUNTIME_ASSIGNMENT_DISABLED")
    if batch.target.configuration_sha256 != assignment.configuration_sha256 or any(
        (item.strategy_id, item.strategy_version, item.strategy_configuration_sha256)
        != (assignment.strategy.name, assignment.strategy.version, assignment.configuration_sha256)
        for item in batch.intents
    ):
        binding.append("RUNTIME_STRATEGY_BINDING_MISMATCH")
    universe = dict(assignment.instrument_symbols)
    referenced_symbols = (
        *((item.instrument_id, item.symbol) for item in snapshot.positions),
        *((item.instrument_id, item.symbol) for item in snapshot.commitments),
        *((item.instrument_id, item.symbol) for item in batch.intents),
        *((item.instrument_id, item.symbol) for item in batch.target.targets),
    )
    if any(universe.get(instrument) != symbol for instrument, symbol in referenced_symbols):
        binding.append("RUNTIME_INSTRUMENT_BINDING_MISMATCH")
    if inputs.assignment_sha256 != assignment.semantic_sha256:
        binding.append("RUNTIME_ASSIGNMENT_BINDING_MISMATCH")
    if (
        inputs.snapshot_sha256 != snapshot.semantic_sha256
        or batch.snapshot_sha256 != snapshot.semantic_sha256
    ):
        binding.append("RUNTIME_SNAPSHOT_BINDING_MISMATCH")
    if not timedelta(0) <= evaluated_at - snapshot.point.knowledge_at < timedelta(seconds=5):
        binding.append("RUNTIME_SNAPSHOT_NOT_CURRENT")
    if (inputs.source_session, inputs.execution_session) != (
        batch.target.trigger.source_session,
        batch.target.trigger.execution_session,
    ):
        binding.append("RUNTIME_SESSION_MISMATCH")
    if (
        inputs.heads.ledger_sha256 != snapshot.journal_sha256
        or inputs.heads.order_sha256 != snapshot.order_sha256
    ):
        binding.append("RUNTIME_ECONOMIC_HEAD_MISMATCH")
    check("binding", binding, (assignment.semantic_sha256, snapshot.semantic_sha256))

    eastern = ZoneInfo("America/New_York")
    opening = datetime.combine(inputs.execution_session, time(9, 35), eastern)
    closing = datetime.combine(inputs.execution_session, time(9, 40), eastern)
    timing: list[str] = []
    if batch.target.not_before != opening or batch.target.expires_at != closing:
        timing.append("RUNTIME_FORWARD_WINDOW_REQUIRED")
    if inputs.phase == "activation":
        if not opening <= evaluated_at < closing:
            timing.append("RUNTIME_EXECUTION_OUTSIDE_WINDOW")
    else:
        attempt = datetime.combine(inputs.source_session, time(20), eastern)
        cutoff = datetime.combine(inputs.execution_session, time(9), eastern)
        if not attempt <= evaluated_at < cutoff:
            timing.append("RUNTIME_DECISION_OUTSIDE_WINDOW")
    check("schedule", timing, (batch.target.semantic_sha256,))

    if inputs.phase == "activation":
        reasons = []
        marks = {mark.instrument_id: mark for mark in snapshot.marks}
        if len(marks) != len(snapshot.marks):
            reasons.append("RUNTIME_DUPLICATE_INSTRUMENT_MARK")
        for intent in batch.intents:
            mark = marks.get(intent.instrument_id)
            basis = "runtime_quote_ask_v1" if intent.side is Side.BUY else "runtime_quote_bid_v1"
            if mark is None:
                reasons.append("RUNTIME_ACTIVATION_QUOTE_MARK_REQUIRED")
            elif mark.basis != basis:
                reasons.append("RUNTIME_ACTIVATION_REQUIRES_SIDE_QUOTE")
            elif (
                mark.quality != "current"
                or mark.symbol != intent.symbol
                or mark.session != inputs.execution_session
                or not timedelta(0) <= evaluated_at - mark.economic_at < timedelta(seconds=5)
                or mark.knowledge_at > evaluated_at
            ):
                reasons.append("RUNTIME_ACTIVATION_QUOTE_MARK_NOT_CURRENT")
        # Exposure arithmetic also values inventory and remaining buys outside this batch.
        exposure_symbols = {
            (position.instrument_id, position.symbol)
            for position in snapshot.positions
            if position.quantity != 0
        } | {
            (commitment.instrument_id, commitment.symbol)
            for commitment in snapshot.commitments
            if commitment.side is Side.BUY and commitment.remaining_quantity > 0
        }
        for instrument_id, symbol in sorted(exposure_symbols):
            mark = marks.get(instrument_id)
            if mark is None:
                reasons.append("RUNTIME_EXPOSURE_QUOTE_MARK_REQUIRED")
            elif mark.basis not in ("runtime_quote_ask_v1", "runtime_quote_bid_v1"):
                reasons.append("RUNTIME_EXPOSURE_REQUIRES_QUOTE_MARK")
            elif (
                mark.quality != "current"
                or mark.symbol != symbol
                or mark.session != inputs.execution_session
                or not timedelta(0) <= evaluated_at - mark.economic_at < timedelta(seconds=5)
                or mark.knowledge_at > evaluated_at
            ):
                reasons.append("RUNTIME_EXPOSURE_QUOTE_MARK_NOT_CURRENT")
        check("quote_marks", reasons, tuple(mark.source_sha256 for mark in snapshot.marks))

    source_map = {item.spec.role: item for item in inputs.sources}
    required = tuple(
        role for role in RUNTIME_ROLES if role != "quotes" or inputs.phase == "activation"
    )
    expected_map = {item.role: item for item in producer_map.producers}
    for role in RUNTIME_ROLES:
        source = source_map.get(role)
        if source is None:
            if role in required:
                check("source:" + role, ["RUNTIME_SOURCE_MISSING:" + role], missing=True)
            continue
        reasons = []
        if source.spec != expected_map[role]:
            reasons.append("RUNTIME_SOURCE_PRODUCER_MISMATCH:" + role)
        if (
            source.account_id != assignment.account_id
            or source.account_binding_sha256 != assignment.account_binding_sha256
        ):
            reasons.append("RUNTIME_SOURCE_ACCOUNT_MISMATCH:" + role)
        if source.value_sha256 != runtime_source_value_sha256(role, snapshot, batch, inputs):
            reasons.append("RUNTIME_SOURCE_VALUE_MISMATCH:" + role)
        if source.received_at > evaluated_at or source.source_at > evaluated_at:
            reasons.append("RUNTIME_SOURCE_FUTURE:" + role)
        if evaluated_at >= source.valid_until:
            reasons.append("RUNTIME_SOURCE_EXPIRED:" + role)
        if source.status != "available":
            reasons.append("RUNTIME_SOURCE_UNAVAILABLE:" + role)
            reasons.extend(source.reasons)
        if role == "clock" and evaluated_at - source.source_at >= timedelta(seconds=30):
            reasons.append("RUNTIME_CLOCK_STALE")
        if role == "quotes" and inputs.phase == "activation":
            if evaluated_at - source.source_at >= timedelta(seconds=5):
                reasons.append("RUNTIME_QUOTE_SOURCE_STALE")
            if evaluated_at - source.received_at >= timedelta(seconds=1):
                reasons.append("RUNTIME_QUOTE_RECEIPT_STALE")
        check(
            "source:" + role,
            reasons,
            (source.source_sha256,),
            missing=source.status == "unavailable",
        )

    obligations = inputs.obligations
    reasons = []
    actual = tuple(sorted(snapshot.commitments, key=lambda item: item.commitment_id))
    expected = tuple(item.commitment for item in obligations.bindings)
    if actual != expected or any(
        item.account_id != snapshot.account_id for item in obligations.bindings
    ):
        reasons.append("RUNTIME_FULL_COMMITMENT_INVENTORY_MISMATCH")
    if inputs.heads.capacity_sha256 != obligations.semantic_sha256:
        reasons.append("RUNTIME_CAPACITY_HEAD_MISMATCH")
    if len({item.intent_id for item in actual}) != len(actual):
        reasons.append("RUNTIME_DUPLICATE_COMMITMENT_INTENT")
    if any(item.state == "unknown" for item in actual):
        reasons.append("RUNTIME_UNKNOWN_OBLIGATION")
    buys = exact_decimal_sum(item.reserved_cash for item in actual if item.side is Side.BUY)
    sells = exact_decimal_sum(item.reserved_cash for item in actual if item.side is Side.SELL)
    if buys != snapshot.buy_reserve or sells != snapshot.sell_fee_reserve:
        reasons.append("RUNTIME_RESERVATION_PROJECTION_MISMATCH")
    if inputs.cash_restrictions is None:
        reasons.append("RUNTIME_CASH_RESTRICTIONS_UNAVAILABLE")
    else:
        available = exact_decimal_subtract(snapshot.settled_cash, snapshot.trade_payable)
        for value in (buys, sells, inputs.cash_restrictions):
            available = exact_decimal_subtract(available, value)
        if available != snapshot.available_cash:
            reasons.append("RUNTIME_AVAILABLE_CASH_MISMATCH")
    check(
        "obligations",
        reasons,
        (obligations.semantic_sha256,),
        missing=inputs.cash_restrictions is None,
    )

    reconciliation = inputs.reconciliation
    reasons = []
    if reconciliation is None:
        reasons.append("RUNTIME_RECONCILIATION_UNAVAILABLE")
    else:
        scope = reconciliation.scope
        if (
            scope.account_id,
            scope.provider_id,
            scope.environment,
            scope.binding_sha256,
            scope.source_class,
        ) != (
            assignment.account_id,
            expected_map["reconciliation"].provider_id,
            "stateful_simulation",
            assignment.account_binding_sha256,
            "stateful_simulation",
        ):
            reasons.append("RUNTIME_RECONCILIATION_SCOPE_MISMATCH")
        if expected_map["reconciliation"].source_environment != scope.environment:
            reasons.append("RUNTIME_RECONCILIATION_PRODUCER_ENVIRONMENT_MISMATCH")
        if reconciliation.heads != inputs.heads:
            reasons.append("RUNTIME_RECONCILIATION_HEADS_CHANGED")
        if reconciliation.policy_sha256 != ReconciliationPolicy().semantic_sha256:
            reasons.append("RUNTIME_RECONCILIATION_POLICY_MISMATCH")
        if reconciliation.status != "converged" or reconciliation.blocking_reasons:
            reasons.append("RUNTIME_RECONCILIATION_NOT_CONVERGED")
        if not timedelta(0) <= evaluated_at - reconciliation.completed_at < timedelta(seconds=60):
            reasons.append("RUNTIME_RECONCILIATION_STALE")
        if (
            not timedelta(0)
            <= evaluated_at - reconciliation.observation_started_at
            < timedelta(seconds=60)
        ):
            reasons.append("RUNTIME_RECONCILIATION_OBSERVATION_STALE")
        if (
            not timedelta(0)
            <= evaluated_at - reconciliation.observation_received_through
            < timedelta(seconds=60)
        ):
            reasons.append("RUNTIME_RECONCILIATION_RECEIPT_STALE")
    check(
        "reconciliation",
        reasons,
        () if reconciliation is None else (reconciliation.semantic_sha256,),
        missing=reconciliation is None,
    )
    return DailyRuntimeRiskEvidence(
        assignment=assignment,
        producer_map=producer_map,
        inputs=inputs,
        batch_sha256=batch.semantic_sha256,
        produced_at=evaluated_at,
        checks=tuple(sorted(checks, key=lambda item: item.rule)),
    )
