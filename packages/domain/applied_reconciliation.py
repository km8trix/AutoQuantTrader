"""Pure, conservative comparison of separate expected and observed accounts.

This module neither posts facts nor mutates projections, obligations or controls.
Application links and current heads must come from the coordinator's authenticated
transaction. A result is evidence for that exact state, never an execution permit.
The initial version can converge stateful simulation; provider financial identity,
field semantics and retention qualification remain a separate required producer.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal

from packages.domain.accounting_contracts import AccountSnapshot
from packages.domain.decimal_math import exact_decimal_subtract
from packages.domain.personal_contracts import require_utc
from packages.domain.reconciliation_contracts import (
    MAX_RECONCILIATION_ITEMS,
    REQUIRED_CASH_FIELDS,
    REQUIRED_RECONCILIATION_OPERATIONS,
    CoverageAssessment,
    DiscrepancyCode,
    FactApplication,
    FactObservation,
    ObservationRound,
    OrderObservation,
    ReconciliationDiscrepancy,
    ReconciliationHeads,
    ReconciliationObligation,
    ReconciliationOrderBinding,
    ReconciliationPolicy,
    ReconciliationResult,
    require_reconciliation_id,
)

_POLICY = ReconciliationPolicy()


def reconciliation_history_start(
    *,
    opening_boundary: datetime,
    last_reconciled_through: datetime | None,
    earliest_unresolved_prior_session: datetime | None,
    restore_from: datetime | None = None,
    policy: ReconciliationPolicy = _POLICY,
) -> datetime:
    """Compute the required overlap using a caller-verified exchange session.

    No weekend/holiday guess supplies the unresolved attempt's prior session.
    On first enrollment the opening boundary is mandatory; a restore extends the
    requirement through its entire gap even when a newer watermark is retained.
    """
    for name, value in (
        ("opening boundary", opening_boundary),
        ("last watermark", last_reconciled_through),
        ("verified prior session", earliest_unresolved_prior_session),
        ("restore boundary", restore_from),
    ):
        if value is not None:
            require_utc(value, name)
    candidates = [
        opening_boundary
        if last_reconciled_through is None
        else last_reconciled_through - timedelta(days=policy.lookback_calendar_days)
    ]
    candidates.extend(
        value for value in (earliest_unresolved_prior_session, restore_from) if value is not None
    )
    return min(candidates)


def assess_reconciliation_coverage(
    observed: ObservationRound,
    *,
    required_from: datetime,
    required_through: datetime,
    now: datetime,
    policy: ReconciliationPolicy = _POLICY,
) -> CoverageAssessment:
    """Require exact whole-account page chains, query overlap and fresh receipts."""
    for name, value in (("from", required_from), ("through", required_through), ("now", now)):
        require_utc(value, name)
    if required_from > required_through or required_through > now:
        raise ValueError("required history interval is reversed or in the future")
    reasons: set[str] = set(observed.source_blockers)
    if observed.completed_at > now or observed.requested_through > observed.completed_at:
        reasons.add("OBSERVATION_TIME_INVALID")
    if observed.requested_from > required_from or observed.requested_through < required_through:
        reasons.add("REQUIRED_HISTORY_NOT_COVERED")
    receipts = tuple(sorted({page.receipt_id for page in observed.pages}))
    if len(receipts) != len(observed.pages):
        reasons.add("DUPLICATE_PAGE_RECEIPT")
    for page in observed.pages:
        if page.scope_sha256 != observed.scope.semantic_sha256:
            reasons.add("PAGE_SCOPE_MISMATCH")
        if (
            not observed.started_at
            <= page.requested_at
            <= page.received_at
            <= observed.completed_at
        ):
            reasons.add("PAGE_RECEIPT_OUTSIDE_ROUND")
        if not timedelta(0) <= now - page.received_at < timedelta(seconds=policy.freshness_seconds):
            reasons.add("STALE_PAGE_RECEIPT")
        if page.selection != "all_account":
            reasons.add("WHOLE_ACCOUNT_SELECTION_REQUIRED")
    history_starts: list[datetime] = []
    history_ends: list[datetime] = []
    for operation in REQUIRED_RECONCILIATION_OPERATIONS:
        pages = sorted(
            (p for p in observed.pages if p.operation == operation), key=lambda p: p.ordinal
        )
        if not pages:
            reasons.add("MISSING_" + operation.upper())
            continue
        if tuple(p.ordinal for p in pages) != tuple(range(len(pages))):
            reasons.add("PAGE_ORDINAL_GAP_OR_DUPLICATE")
        first = pages[0]
        if first.cursor is not None:
            reasons.add("FIRST_PAGE_CURSOR_PRESENT")
        if len({p.query_sha256 for p in pages}) != 1 or any(
            (p.requested_from, p.requested_through)
            != (first.requested_from, first.requested_through)
            for p in pages
        ):
            reasons.add("PAGE_QUERY_CHANGED")
        if len({p.request_sha256 for p in pages}) != len(pages):
            reasons.add("REPEATED_PAGE_REQUEST")
        if len({p.body_sha256 for p in pages}) != len(pages):
            reasons.add("REPEATED_PAGE_CONTENT")
        cursors = tuple(p.cursor for p in pages if p.cursor is not None)
        if len(set(cursors)) != len(cursors):
            reasons.add("CYCLIC_PAGE_CURSOR")
        for index, page in enumerate(pages):
            if index + 1 < len(pages):
                following = pages[index + 1]
                if (
                    page.termination != "more"
                    or page.next_cursor is None
                    or page.next_cursor != following.cursor
                    or page.terminal_evidence_sha256 is not None
                    or page.received_at > following.requested_at
                ):
                    reasons.add("PAGE_CONTINUATION_UNPROVEN")
            elif (
                page.termination != "documented_end"
                or page.next_cursor is not None
                or page.terminal_evidence_sha256 is None
            ):
                reasons.add("DOCUMENTED_TERMINAL_PAGE_REQUIRED")
        if operation in ("activity", "orders_history"):
            if first.requested_from is None or first.requested_through is None:
                reasons.add("HISTORY_QUERY_BOUNDS_REQUIRED")
            else:
                history_starts.append(first.requested_from)
                history_ends.append(first.requested_through)
                if (
                    first.requested_from > required_from
                    or first.requested_through < required_through
                    or first.requested_through > first.requested_at
                ):
                    reasons.add("REQUIRED_HISTORY_NOT_COVERED")
    # Absent provider sequence stays absent. Without an explicit stream namespace
    # it is never ordered globally or substituted with a local page ordinal.
    return CoverageAssessment(
        max(history_starts) if not reasons else None,
        min(history_ends) if not reasons else None,
        receipts,
        tuple(sorted(reasons)),
    )


class _Differences:
    def __init__(self) -> None:
        self.values: dict[str, ReconciliationDiscrepancy] = {}
        self.reasons: set[str] = set()

    def add(
        self,
        code: DiscrepancyCode,
        subject: str,
        reason: str,
        expected: Decimal | None = None,
        observed: Decimal | None = None,
        evidence_ids: tuple[str, ...] = (),
    ) -> None:
        self.reasons.add(reason)
        value = ReconciliationDiscrepancy(code, subject, reason, expected, observed, evidence_ids)
        if len(self.values) < MAX_RECONCILIATION_ITEMS:
            self.values[value.semantic_sha256] = value
        else:
            self.reasons.add("DISCREPANCY_OUTPUT_BOUND_REACHED")


def _fact_content(fact: FactObservation) -> tuple[object, ...]:
    # Delivery receipt/time can change on an overlap reread, canonical content cannot.
    return (
        fact.fact_sha256,
        fact.kind,
        fact.provider_fact_id,
        fact.provider_revision,
        fact.provider_sequence,
        fact.effective_at,
        fact.origin,
        fact.predecessor_fact_id,
    )


def _compare_facts(
    observed: ObservationRound,
    applications: tuple[FactApplication, ...],
    now: datetime,
    differences: _Differences,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    facts: dict[str, FactObservation] = {}
    applied: dict[str, FactApplication] = {}
    quarantine: set[str] = set()
    unresolved: set[str] = set()
    accepted: set[str] = set()
    provider_keys: dict[tuple[str, str, str | None], str] = {}
    receipts = {p.receipt_id for p in observed.pages}
    for link in applications:
        if link.fact_id in applied and applied[link.fact_id] != link:
            quarantine.add(link.fact_id)
        applied[link.fact_id] = link
    for fact in observed.facts:
        if fact.fact_id in facts and _fact_content(facts[fact.fact_id]) != _fact_content(fact):
            quarantine.add(fact.fact_id)
        facts[fact.fact_id] = fact
        if fact.provider_fact_id is not None:
            category = "execution" if fact.kind == "correction" else fact.kind
            key = (category, fact.provider_fact_id, fact.provider_revision)
            if key in provider_keys and provider_keys[key] != fact.fact_id:
                quarantine.update((fact.fact_id, provider_keys[key]))
            provider_keys[key] = fact.fact_id
        if (
            fact.source_receipt_id not in receipts
            or fact.received_at > observed.completed_at
            or fact.received_at < observed.started_at
            or fact.effective_at is None
        ):
            quarantine.add(fact.fact_id)
            differences.add("COVERAGE_GAP", fact.fact_id, "FACT_SOURCE_OR_TIME_UNPROVEN")
    for fact_id, fact in sorted(facts.items()):
        application = applied.get(fact_id)
        if application is not None and (
            (
                fact.kind in ("execution", "correction")
                and (
                    not application.order_event_ids
                    or (
                        not application.journal_entry_ids
                        and not (
                            fact.kind == "correction"
                            and application.canonical_fact_ids == (fact_id,)
                        )
                    )
                )
            )
            or (fact.kind == "order" and not application.order_event_ids)
            or (
                fact.kind in ("cash_flow", "corporate_action", "settlement")
                and not application.journal_entry_ids
                and not (fact.kind == "settlement" and application.canonical_fact_ids == (fact_id,))
            )
        ):
            unresolved.add(fact_id)
            differences.add("COVERAGE_GAP", fact_id, "CANONICAL_APPLICATION_LINKS_INCOMPLETE")
        if application is not None and (
            application.fact_sha256 != fact.fact_sha256
            or application.applied_at > now
            or (fact.effective_at is not None and application.applied_at < fact.effective_at)
        ):
            quarantine.add(fact_id)
        if fact.kind == "correction" and (
            fact.predecessor_fact_id is None
            or fact.predecessor_fact_id not in applied
            or fact.predecessor_fact_id in quarantine
        ):
            unresolved.add(fact_id)
            differences.add("MISSING_EXECUTION", fact_id, "CORRECTION_PREDECESSOR_NOT_APPLIED")
        if fact.kind == "unsupported":
            quarantine.add(fact_id)
            differences.add("UNSUPPORTED_ACTIVITY", fact_id, "UNSUPPORTED_CANONICAL_FACT")
        if fact_id in quarantine:
            differences.add("DUPLICATE_OR_CONFLICT", fact_id, "CONFLICTING_OR_UNPROVEN_FACT")
        elif application is None or fact_id in unresolved:
            unresolved.add(fact_id)
            code: DiscrepancyCode = (
                "MISSING_EXECUTION"
                if fact.kind in ("execution", "correction")
                else "CORPORATE_ACTION"
                if fact.kind == "corporate_action"
                else "EXTERNAL_CASH_FLOW"
                if fact.kind == "cash_flow"
                else "UNSUPPORTED_ACTIVITY"
            )
            differences.add(code, fact_id, "CANONICAL_FACT_NOT_APPLIED")
        else:
            accepted.add(fact_id)
        if fact.origin == "external":
            # Booking a known fact is mandatory, but it cannot silently adopt an
            # external order into the strategy or clear the exclusive-account halt.
            code = (
                "EXTERNAL_CASH_FLOW"
                if fact.kind == "cash_flow"
                else "CORPORATE_ACTION"
                if fact.kind == "corporate_action"
                else "EXTERNAL_TRADE"
            )
            differences.add(code, fact_id, "EXTERNAL_ACTIVITY_REQUIRES_OWNER_DISPOSITION")
    for fact_id in sorted(quarantine - facts.keys()):
        differences.add("DUPLICATE_OR_CONFLICT", fact_id, "CONFLICTING_APPLICATION_LINKS")
    return (
        tuple(sorted(accepted - quarantine)),
        tuple(sorted(unresolved - quarantine)),
        tuple(sorted(quarantine)),
    )


def _compare_cash(
    expected: AccountSnapshot,
    observed: ObservationRound,
    differences: _Differences,
    *,
    may_use_rounding: bool,
    policy: ReconciliationPolicy,
) -> None:
    if observed.currency != "USD":
        differences.add("UNSUPPORTED_ACTIVITY", "account", "EXPLICIT_USD_REQUIRED")
    modes = tuple(mode for _, mode in observed.account_modes)
    if not modes or any(mode not in ("CASH", "MARGIN") for mode in modes):
        differences.add("UNSUPPORTED_ACTIVITY", "account", "SUPPORTED_ACCOUNT_MODE_REQUIRED")
    elif len(set(modes)) != 1:
        differences.add("UNSUPPORTED_ACTIVITY", "account", "ACCOUNT_MODE_DISAGREEMENT")
    for field in REQUIRED_CASH_FIELDS:
        values = tuple(value for value in observed.cash if value.field == field)
        wanted: Decimal = (
            Decimal(0)
            if field in ("margin_liability", "restricted_cash")
            else getattr(expected, field)
        )
        if len(values) != 1:
            differences.add(
                "UNEXPLAINED_CASH_OR_POSITION", field, "CASH_FIELD_MISSING_OR_DUPLICATE"
            )
            continue
        value = values[0]
        if value.value is None or value.currency != "USD" or value.semantics_sha256 is None:
            differences.add(
                "UNEXPLAINED_CASH_OR_POSITION", field, "CASH_FIELD_SEMANTICS_UNAVAILABLE"
            )
            continue
        delta = exact_decimal_subtract(value.value, wanted).copy_abs()
        tolerance = value.display_tolerance if may_use_rounding else Decimal(0)
        if delta > min(tolerance, policy.maximum_display_tolerance):
            differences.add(
                "UNEXPLAINED_CASH_OR_POSITION", field, "CASH_FIELD_MISMATCH", wanted, value.value
            )


def _compare_positions(
    expected: AccountSnapshot,
    observed: ObservationRound,
    symbols: dict[str, str],
    differences: _Differences,
) -> None:
    actual: dict[str, Decimal] = {}
    wanted: dict[str, Decimal] = {}
    for position in observed.positions:
        instrument = position.instrument_id
        if instrument is None or symbols.get(instrument) != position.symbol:
            differences.add(
                "UNSUPPORTED_ACTIVITY", position.symbol, "POSITION_IDENTITY_UNSUPPORTED"
            )
            continue
        if instrument in actual:
            differences.add("DUPLICATE_OR_CONFLICT", instrument, "DUPLICATE_POSITION")
        actual[instrument] = position.quantity
        if position.quantity < 0 or position.quantity != position.quantity.to_integral_value():
            differences.add("UNSUPPORTED_ACTIVITY", instrument, "POSITION_NOT_LONG_WHOLE_SHARES")
    for expected_position in expected.positions:
        if (
            symbols.get(expected_position.instrument_id) != expected_position.symbol
            or expected_position.instrument_id in wanted
        ):
            differences.add("UNSUPPORTED_ACTIVITY", "account", "EXPECTED_POSITION_IDENTITY_INVALID")
        wanted[expected_position.instrument_id] = expected_position.quantity
    for instrument in sorted(set(wanted) | set(actual)):
        if actual.get(instrument, Decimal(0)) != wanted.get(instrument, Decimal(0)):
            differences.add(
                "UNEXPLAINED_CASH_OR_POSITION",
                instrument,
                "POSITION_QUANTITY_MISMATCH",
                wanted.get(instrument, Decimal(0)),
                actual.get(instrument, Decimal(0)),
            )


def _compare_orders(
    expected: AccountSnapshot,
    observed: ObservationRound,
    obligations: tuple[ReconciliationObligation, ...],
    order_bindings: tuple[ReconciliationOrderBinding, ...],
    symbols: dict[str, str],
    differences: _Differences,
) -> None:
    holds = {hold.order_id: hold for hold in obligations}
    local = {commitment.order_id: commitment for commitment in expected.commitments}
    bindings = {binding.order_id: binding.provider_order_id for binding in order_bindings}
    if len(bindings) != len(order_bindings) or len(set(bindings.values())) != len(bindings):
        differences.add("DUPLICATE_OR_CONFLICT", "orders", "DUPLICATE_ORDER_IDENTITY_BINDING")
    for obligation in obligations:
        if obligation.provider_order_id is not None:
            if (
                obligation.order_id in bindings
                and bindings[obligation.order_id] != obligation.provider_order_id
            ):
                differences.add(
                    "DUPLICATE_OR_CONFLICT", obligation.order_id, "ORDER_IDENTITY_BINDING_CONFLICT"
                )
            bindings[obligation.order_id] = obligation.provider_order_id
    if len(set(bindings.values())) != len(bindings):
        differences.add(
            "DUPLICATE_OR_CONFLICT", "orders", "PROVIDER_IDENTITY_SHARED_BY_LOCAL_ORDERS"
        )
    if len(holds) != len(obligations) or len(local) != len(expected.commitments):
        differences.add("DUPLICATE_OR_CONFLICT", "orders", "DUPLICATE_LOCAL_ORDER_IDENTITY")
    provider_orders: dict[str, OrderObservation] = {}
    covered: set[str] = set()
    for order in observed.orders:
        if provider_orders.get(order.provider_order_id) == order:
            continue  # Exact current/history overlap is one observed identity.
        if order.provider_order_id in provider_orders:
            differences.add(
                "DUPLICATE_OR_CONFLICT", order.provider_order_id, "DUPLICATE_PROVIDER_ORDER"
            )
        provider_orders[order.provider_order_id] = order
        hold = holds.get(order.order_id or "")
        commitment = local.get(order.order_id or "")
        if order.order_id is None or bindings.get(order.order_id) != order.provider_order_id:
            differences.add("EXTERNAL_TRADE", order.provider_order_id, "ORDER_IDENTITY_NOT_MAPPED")
            continue
        order_id = order.order_id
        covered.add(order_id)
        if commitment is None:
            differences.add("UNSUPPORTED_ACTIVITY", order_id, "ORDER_ACCOUNTING_BINDING_REQUIRED")
            continue
        if (
            order.instrument_id is None
            or symbols.get(order.instrument_id) != order.symbol
            or order.instrument_id != commitment.instrument_id
            or order.symbol != commitment.symbol
            or order.side is not commitment.side
        ):
            differences.add("UNSUPPORTED_ACTIVITY", order_id, "ORDER_INSTRUMENT_OR_SIDE_MISMATCH")
        if (
            order.quantity != commitment.original_quantity
            or order.filled_quantity != commitment.filled_quantity
        ):
            differences.add("MISSING_EXECUTION", order_id, "ORDER_CUMULATIVE_QUANTITY_MISMATCH")
        if order.status == "unknown":
            differences.add("UNKNOWN_ORDER", order_id, "OBSERVED_ORDER_UNKNOWN")
        elif order.status in ("filled", "canceled", "rejected"):
            if commitment.state != "terminal":
                differences.add(
                    "COVERAGE_GAP", order_id, "TERMINAL_ORDER_REQUIRES_APPLIED_TRANSITION"
                )
            if order.status == "filled" and order.filled_quantity != order.quantity:
                differences.add("MISSING_EXECUTION", order_id, "FILLED_ORDER_QUANTITY_INCOMPLETE")
        elif commitment.state == "terminal":
            differences.add("UNKNOWN_ORDER", order_id, "TERMINAL_LOCAL_ORDER_STILL_WORKING")
        if hold is not None and hold.state == "approved_unsent":
            differences.add("UNKNOWN_ORDER", order_id, "UNSENT_ORDER_OBSERVED_AT_VENUE")
    for order_id, commitment in sorted(local.items()):
        if commitment.state != "terminal" and order_id not in holds:
            differences.add("COVERAGE_GAP", order_id, "ACTIVE_COMMITMENT_MISSING_DURABLE_HOLD")
    for order_id, hold in sorted(holds.items()):
        if hold.state == "unknown":
            differences.add("UNKNOWN_ORDER", order_id, "DURABLE_UNKNOWN_REQUIRES_DISPOSITION")
        elif hold.state == "terminal_unreleased":
            differences.add("COVERAGE_GAP", order_id, "TERMINAL_HOLD_REQUIRES_SEPARATE_RELEASE")
        elif hold.state != "approved_unsent" and order_id not in covered:
            differences.add("UNKNOWN_ORDER", order_id, "DURABLE_ORDER_NOT_COVERED")


def compare_reconciled_account(
    *,
    expected: AccountSnapshot,
    observed: ObservationRound,
    heads: ReconciliationHeads,
    obligations: tuple[ReconciliationObligation, ...],
    applications: tuple[FactApplication, ...],
    instrument_symbols: tuple[tuple[str, str], ...],
    required_from: datetime,
    required_through: datetime,
    applied_through: datetime | None,
    now: datetime,
    previous: ReconciliationResult | None = None,
    policy: ReconciliationPolicy = _POLICY,
    order_bindings: tuple[ReconciliationOrderBinding, ...] = (),
) -> ReconciliationResult:
    """Compare current applied heads; preserve any unresolved economic obligation.

    This first pure slice does not authenticate a provider qualification or owner
    disposition. It therefore retains those blockers even if amounts happen to
    match. Known canonical facts remain applied when another observation blocks.
    """
    for values in (obligations, applications, instrument_symbols, order_bindings):
        if type(values) is not tuple or len(values) > MAX_RECONCILIATION_ITEMS:
            raise ValueError("comparison input exceeds immutable item bound")
    if (
        len({fact.fact_id for fact in observed.facts} | {link.fact_id for link in applications})
        > MAX_RECONCILIATION_ITEMS
    ):
        raise ValueError("combined fact/application identity inventory exceeds bound")
    if max(len(expected.positions), len(expected.commitments)) > MAX_RECONCILIATION_ITEMS:
        raise ValueError("expected account inventory exceeds comparison bound")
    symbols = dict(instrument_symbols)
    if (
        not symbols
        or len(symbols) != len(instrument_symbols)
        or len(set(symbols.values())) != len(symbols)
    ):
        raise ValueError("instrument mapping requires unique stable identities and symbols")
    for instrument, symbol in symbols.items():
        require_reconciliation_id(instrument, "configured instrument")
        if symbol not in ("DIA", "IWM", "QQQ", "SPY"):
            raise ValueError("instrument is outside the whole-share ETF scope")
    coverage = assess_reconciliation_coverage(
        observed,
        required_from=required_from,
        required_through=required_through,
        now=now,
        policy=policy,
    )
    differences = _Differences()
    for reason in coverage.reasons:
        differences.add("COVERAGE_GAP", "coverage", reason)
    if expected.account_id != observed.scope.account_id:
        differences.add("COVERAGE_GAP", "account", "ACCOUNT_IDENTITY_MISMATCH")
    if (
        heads.ledger_sha256 != expected.journal_sha256
        or heads.order_sha256 != expected.order_sha256
    ):
        differences.add("COVERAGE_GAP", "account", "CURRENT_PROJECTION_HEADS_MISMATCH")
    if expected.point.knowledge_at > now:
        differences.add("COVERAGE_GAP", "account", "FUTURE_ACCOUNT_PROJECTION")
    if observed.scope.source_class == "provider_observation":
        differences.add("COVERAGE_GAP", "account", "PROVIDER_QUALIFICATION_REQUIRED")
    if applied_through is not None:
        require_utc(applied_through, "applied watermark")
    if applied_through is None or applied_through < required_through or applied_through > now:
        differences.add("COVERAGE_GAP", "account", "APPLIED_WATERMARK_INCOMPLETE")
    accepted, unresolved, quarantine = _compare_facts(observed, applications, now, differences)
    _compare_orders(expected, observed, obligations, order_bindings, symbols, differences)
    _compare_positions(expected, observed, symbols, differences)
    _compare_cash(
        expected, observed, differences, may_use_rounding=not differences.reasons, policy=policy
    )
    reasons = differences.reasons
    if not reasons:
        if previous is None:
            reasons.add("CONVERGENCE_ROUND_REQUIRED")
        elif (
            previous.scope != observed.scope
            or previous.policy_sha256 != policy.semantic_sha256
            or previous.round_sha256 == observed.semantic_sha256
            or set(previous.source_receipt_ids) & set(coverage.source_receipt_ids)
            or not previous.source_receipt_ids
            or previous.completed_at > observed.started_at
            or not timedelta(0)
            <= now - previous.observation_started_at
            <= timedelta(seconds=policy.convergence_seconds)
            or previous.coverage_from is None
            or previous.coverage_through is None
            or previous.applied_through is None
            or previous.discrepancies
            or previous.unresolved_fact_ids
            or previous.quarantined_fact_ids
            or previous.blocking_reasons not in ((), ("CONVERGENCE_ROUND_REQUIRED",))
            or previous.heads != heads
        ):
            # A changed durable revision starts another pair. The first view cannot
            # attest to a later send, control change, takeover or applied correction.
            reasons.add("CONVERGENCE_ROUND_REQUIRED")
    received = max((p.received_at for p in observed.pages), default=observed.started_at)
    # Invalid observation timestamps are represented by discrepancies. The result
    # envelope itself remains a truthful bounded local assessment at `now`.
    if not observed.started_at <= received <= now:
        raise ValueError("cannot assess a round whose receipt envelope is in the future")
    return ReconciliationResult(
        scope=observed.scope,
        heads=heads,
        round_sha256=observed.semantic_sha256,
        previous_result_sha256=previous.semantic_sha256 if previous is not None else None,
        observation_started_at=observed.started_at,
        observation_received_through=received,
        coverage_from=coverage.coverage_from,
        coverage_through=coverage.coverage_through,
        applied_through=applied_through
        if applied_through is None or applied_through <= now
        else None,
        completed_at=now,
        status="blocked" if reasons else "converged",
        blocking_reasons=tuple(sorted(reasons)),
        discrepancies=tuple(differences.values[key] for key in sorted(differences.values)),
        applied_fact_ids=accepted,
        unresolved_fact_ids=unresolved,
        quarantined_fact_ids=quarantine,
        source_receipt_ids=coverage.source_receipt_ids,
        policy_sha256=policy.semantic_sha256,
    )
