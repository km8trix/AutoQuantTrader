"""Pure, fail-closed daily simulation policy over one immutable account image."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from packages.domain.accounting_contracts import AccountSnapshot
from packages.domain.canonical import canonical_persisted_decimal
from packages.domain.decimal_math import (
    exact_decimal_add as add,
)
from packages.domain.decimal_math import (
    exact_decimal_multiply as mul,
)
from packages.domain.decimal_math import (
    exact_decimal_subtract as sub,
)
from packages.domain.decimal_math import (
    exact_decimal_sum as total,
)
from packages.domain.engine_contracts import (
    DailyIntentBatch,
    DailyRiskDecision,
    DailyRiskEvidence,
    DailyRiskPolicy,
)
from packages.domain.models import Side


def evaluate_daily_risk(
    policy: DailyRiskPolicy,
    snapshot: AccountSnapshot,
    target_batch: DailyIntentBatch,
    evidence: DailyRiskEvidence,
    evaluated_at: datetime,
) -> DailyRiskDecision:
    """Approve a whole batch or reserve nothing; never infer missing evidence.

    Activation replaces each evaluated commitment's own hold exactly once.
    Other pending buys retain their cash, quantity and count obligations; pending
    sells never fund a purchase or reduce conservative gross exposure.
    """
    reasons = list(target_batch.reasons) + list(evidence.reasons)
    intents = target_batch.intents
    ids = {intent.intent_id for intent in intents}
    if len(ids) != len(intents):
        reasons.append("DUPLICATE_INTENT")
    if (
        snapshot.semantic_sha256 != target_batch.snapshot_sha256
        or evidence.snapshot_sha256 != snapshot.semantic_sha256
        or evidence.produced_at != evaluated_at
        or snapshot.point.knowledge_at != evaluated_at
    ):
        reasons.append("STALE_OR_UNBOUND_ACCOUNT_EVIDENCE")
    if evidence.producer.name != "engine":
        reasons.append("UNRECOGNIZED_EVIDENCE_PRODUCER")
    for name in (
        "complete_daily_inputs",
        "controls_healthy",
        "session_healthy",
        "time_healthy",
        "cash_semantics_known",
        "request_capacity_available",
        "simulation_reconciled",
    ):
        if not getattr(evidence, name):
            reasons.append(name.upper() + "_REQUIRED")
    if snapshot.halted:
        reasons.append("ACCOUNT_HALTED")
    if snapshot.nav is None or snapshot.nav <= 0 or snapshot.valuation_reasons:
        reasons.append("CURRENT_POSITIVE_NAV_REQUIRED")
    if evidence.daily_return is None or evidence.drawdown is None:
        reasons.append("FLOW_NEUTRAL_LOSS_EVIDENCE_REQUIRED")
    elif evidence.daily_return <= -1 or not Decimal(0) <= evidence.drawdown <= Decimal(1):
        reasons.append("INVALID_FLOW_NEUTRAL_LOSS_EVIDENCE")
    elif (
        evidence.daily_return <= policy.daily_loss_boundary
        or evidence.drawdown >= policy.drawdown_boundary
    ) and not target_batch.target.reduce_only_scope:
        reasons.append("LOSS_CONTROL_BLOCKS_NEW_EXPOSURE")
    if (
        evidence.source_session != target_batch.target.trigger.source_session
        or evidence.execution_session != target_batch.target.trigger.execution_session
    ):
        reasons.append("SESSION_EVIDENCE_MISMATCH")
    if evaluated_at >= target_batch.target.expires_at:
        reasons.append("TARGET_EXPIRED")
    if evidence.phase == "decision" and target_batch.target.trigger.as_of != evaluated_at:
        reasons.append("STALE_DECISION")
    pending = tuple(item for item in snapshot.commitments if item.state != "terminal")
    replaced = tuple(
        item for item in pending if evidence.phase == "activation" and item.intent_id in ids
    )
    others = tuple(item for item in pending if item not in replaced)
    if evidence.phase == "activation" and {item.intent_id for item in replaced} != ids:
        reasons.append("ACTIVATION_COMMITMENT_BINDING_REQUIRED")
    if evidence.phase == "decision" and any(item.intent_id in ids for item in pending):
        reasons.append("INTENT_ALREADY_COMMITTED")
    if len(others) + len(intents) > policy.max_open_intents:
        reasons.append("OPEN_INTENT_LIMIT")
    if len(set(evidence.accepted_intent_ids) | ids) > policy.max_new_intents_per_session:
        reasons.append("SESSION_INTENT_LIMIT")
    positions = {item.instrument_id: item for item in snapshot.positions}
    marks = {item.instrument_id: item for item in snapshot.marks}
    cash: list[tuple[str, Decimal]] = []
    shares: list[tuple[str, Decimal]] = []
    notionals: list[Decimal] = []
    exposure: dict[str, Decimal] = {}
    for position in snapshot.positions:
        if position.quantity < 0:
            reasons.append("SHORT_POSITION_UNSUPPORTED")
        if position.quantity:
            mark = marks.get(position.instrument_id)
            if mark is None or mark.quality != "current":
                reasons.append("CURRENT_POSITION_MARK_REQUIRED")
            else:
                exposure[position.instrument_id] = mul(position.quantity, mark.price)
    for item in others:
        if item.side is Side.BUY:
            mark = marks.get(item.instrument_id)
            if mark is None or mark.quality != "current":
                reasons.append("CURRENT_COMMITMENT_MARK_REQUIRED")
            else:
                exposure[item.instrument_id] = add(
                    exposure.get(item.instrument_id, Decimal(0)),
                    mul(item.remaining_quantity, mark.price),
                )
    for intent in intents:
        mark = marks.get(intent.instrument_id)
        if (
            mark is None
            or mark.quality != "current"
            or mark.symbol != intent.symbol
            or mark.knowledge_at > evaluated_at
        ):
            reasons.append("CURRENT_INTENT_MARK_REQUIRED")
            continue
        expected_session = (
            evidence.execution_session
            if evidence.phase == "activation"
            else evidence.source_session
        )
        if mark.session != expected_session:
            reasons.append("STALE_INTENT_MARK_SESSION")
        if evidence.phase == "activation" and mark.basis != "raw_execution":
            reasons.append("ACTIVATION_REQUIRES_EXECUTION_PRICE")
        if evidence.phase == "decision" and (
            intent.portfolio_snapshot_sha256 != snapshot.semantic_sha256
            or intent.created_at != evaluated_at
            or intent.reference_price != mark.price
        ):
            reasons.append("INTENT_SNAPSHOT_BINDING_MISMATCH")
        own = next((item for item in replaced if item.intent_id == intent.intent_id), None)
        if own is not None and (
            own.remaining_quantity != intent.quantity
            or own.side is not intent.side
            or own.instrument_id != intent.instrument_id
            or own.policy_sha256 != policy.semantic_sha256
            or own.execution_session != evidence.execution_session
        ):
            reasons.append("ACTIVATION_COMMITMENT_MISMATCH")
        if intent.quantity > policy.max_order_quantity:
            reasons.append("ORDER_QUANTITY_LIMIT")
        count = sum(item.instrument_id == intent.instrument_id for item in others) + sum(
            item.instrument_id == intent.instrument_id for item in intents
        )
        if count > policy.max_per_symbol_intents:
            reasons.append("SYMBOL_INTENT_LIMIT")
        notional = mul(intent.quantity, mark.price)
        notionals.append(notional)
        if snapshot.nav is not None and notional > mul(snapshot.nav, policy.max_order_nav_fraction):
            reasons.append("ORDER_NAV_LIMIT")
        fee = mul(intent.quantity, policy.fee_per_share)
        if intent.side is Side.BUY:
            if target_batch.target.reduce_only_scope:
                reasons.append("REDUCE_ONLY_SCOPE_VIOLATION")
            hold = add(mul(notional, add(Decimal(1), policy.adverse_reserve_fraction)), fee)
            exposure[intent.instrument_id] = add(
                exposure.get(intent.instrument_id, Decimal(0)), notional
            )
        else:
            hold = fee
            available = positions.get(intent.instrument_id)
            held_shares = total(
                item.reserved_sell_quantity
                for item in others
                if item.instrument_id == intent.instrument_id
            )
            if available is None or intent.quantity > sub(available.quantity, held_shares):
                reasons.append("SELL_EXCEEDS_UNCOMMITTED_LONG_QUANTITY")
            shares.append((intent.intent_id, intent.quantity))
        try:
            canonical_persisted_decimal(hold, "daily reservation")
        except ValueError:
            reasons.append("RESERVATION_NOT_EXACTLY_REPRESENTABLE")
        cash.append((intent.intent_id, hold))
    spendable = add(snapshot.available_cash, total(item.reserved_cash for item in replaced))
    if total(amount for _, amount in cash) > spendable:
        reasons.append("INSUFFICIENT_SETTLED_UNCOMMITTED_CASH")
    if snapshot.nav is not None:
        if total(notionals) > mul(snapshot.nav, policy.max_batch_nav_fraction):
            reasons.append("BATCH_NAV_LIMIT")
        repairing = target_batch.target.reduce_only_scope and all(
            intent.side is Side.SELL for intent in intents
        )
        if (
            total(exposure.values()) > mul(snapshot.nav, policy.max_gross_nav_fraction)
            and not repairing
        ):
            reasons.append("GROSS_NAV_LIMIT")
        # Reductions can repair an existing concentration; they cannot add to it.
        for amount in exposure.values():
            if amount > mul(snapshot.nav, policy.max_symbol_nav_fraction) and not repairing:
                reasons.append("SYMBOL_NAV_LIMIT")
    approved = not reasons
    return DailyRiskDecision(
        approved,
        target_batch,
        policy.semantic_sha256,
        evidence.semantic_sha256,
        tuple(sorted(cash)) if approved else (),
        tuple(sorted(shares)) if approved else (),
        tuple(sorted(set(reasons))),
    )
