from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, Inexact, Rounded, localcontext

import pytest

from packages.domain.accounting_contracts import AccountSnapshot, Commitment, PositionState
from packages.domain.applied_reconciliation import (
    assess_reconciliation_coverage,
    compare_reconciled_account,
    reconciliation_history_start,
)
from packages.domain.models import Side
from packages.domain.personal_contracts import ReductionPoint, content_digest
from packages.domain.reconciliation_contracts import (
    MAX_RECONCILIATION_ITEMS,
    REQUIRED_CASH_FIELDS,
    REQUIRED_RECONCILIATION_OPERATIONS,
    CashObservation,
    FactApplication,
    FactObservation,
    ObservationRound,
    OrderObservation,
    PositionObservation,
    ReconciliationHeads,
    ReconciliationObligation,
    ReconciliationOrderBinding,
    ReconciliationPage,
    ReconciliationPolicy,
    ReconciliationResult,
    ReconciliationScope,
)

D = Decimal
BASE = datetime(2025, 2, 4, 14, 30, tzinfo=UTC)
FROM = BASE - timedelta(days=7)
THROUGH = BASE - timedelta(seconds=1)
SHA = "a" * 64
SCOPE = ReconciliationScope(
    "account", "independent-venue", "stateful_simulation", SHA, "stateful_simulation"
)


def account(*, commitments: tuple[Commitment, ...] = ()) -> AccountSnapshot:
    return AccountSnapshot(
        account_id="account",
        point=ReductionPoint(3, 7, THROUGH, 6),
        state_sha256=SHA,
        positions=(PositionState("spy", "SPY", D(8), D(800), ()),),
        commitments=commitments,
        marks=(),
        trade_date_cash=D(200),
        settled_cash=D(200),
        trade_receivable=D(0),
        trade_payable=D(0),
        dividend_receivable=D(0),
        buy_reserve=D(0),
        sell_fee_reserve=D(0),
        available_cash=D(200),
        market_value=D(800),
        nav=D(1000),
        gross_realized_pnl=D(0),
        fees=D(0),
        dividend_income=D(0),
        unrealized_pnl=D(0),
        net_external_flow=D(1000),
        journal_sha256=SHA,
        order_sha256=SHA,
    )


def heads() -> ReconciliationHeads:
    return ReconciliationHeads(SHA, SHA, "b" * 64, 7, "c" * 64, 2, 1)


def observation(index: int = 0) -> ObservationRound:
    start = BASE + timedelta(seconds=10 * index)
    pages = tuple(
        ReconciliationPage(
            operation=operation,
            receipt_id=f"receipt-{index}-{operation}",
            scope_sha256=SCOPE.semantic_sha256,
            query_sha256=content_digest(operation),
            request_sha256=content_digest((operation, "request")),
            body_sha256=content_digest((operation, "body")),
            body_bytes=17,
            ordinal=0,
            requested_at=start + timedelta(seconds=1),
            received_at=start + timedelta(seconds=2),
            requested_from=FROM if operation in ("activity", "orders_history") else None,
            requested_through=THROUGH if operation in ("activity", "orders_history") else None,
            cursor=None,
            next_cursor=None,
            termination="documented_end",
            terminal_evidence_sha256=SHA,
            selection="all_account",
        )
        for operation in REQUIRED_RECONCILIATION_OPERATIONS
    )
    return ObservationRound(
        scope=SCOPE,
        round_id=f"round-{index}",
        started_at=start,
        completed_at=start + timedelta(seconds=3),
        requested_from=FROM,
        requested_through=THROUGH,
        pages=pages,
        cash=tuple(
            CashObservation(
                field, D(200) if field in ("trade_date_cash", "settled_cash") else D(0), "USD", SHA
            )
            for field in REQUIRED_CASH_FIELDS
        ),
        positions=(PositionObservation("spy", "SPY", D(8)),),
        orders=(),
        facts=(),
        currency="USD",
        account_modes=(("balances", "MARGIN"), ("discovery", "MARGIN")),
    )


def compare(
    observed: ObservationRound,
    *,
    expected: AccountSnapshot | None = None,
    current_heads: ReconciliationHeads | None = None,
    previous: ReconciliationResult | None = None,
    applications: tuple[FactApplication, ...] = (),
    obligations: tuple[ReconciliationObligation, ...] = (),
    order_bindings: tuple[ReconciliationOrderBinding, ...] = (),
    now: datetime | None = None,
) -> ReconciliationResult:
    return compare_reconciled_account(
        expected=expected or account(),
        observed=observed,
        heads=current_heads or heads(),
        obligations=obligations,
        applications=applications,
        instrument_symbols=(("spy", "SPY"),),
        required_from=FROM,
        required_through=THROUGH,
        applied_through=THROUGH,
        now=now or observed.completed_at,
        previous=previous,
        order_bindings=order_bindings,
    )


def fact(observed: ObservationRound, *, fact_id: str = "execution-1") -> FactObservation:
    page = next(page for page in observed.pages if page.operation == "activity")
    return FactObservation(
        fact_id,
        SHA,
        "execution",
        "provider-execution-1",
        "revision-1",
        None,
        page.receipt_id,
        THROUGH,
        page.received_at,
    )


def application(fact_id: str = "execution-1") -> FactApplication:
    return FactApplication(fact_id, SHA, THROUGH, ("journal-1",), ("order-event-1",))


def test_two_complete_independent_rounds_converge_without_trading_authority() -> None:
    initial = account()
    first = compare(observation(), expected=initial)
    assert first.status == "blocked"
    assert first.blocking_reasons == ("CONVERGENCE_ROUND_REQUIRED",)
    assert first.discrepancies == ()
    second = compare(observation(1), previous=first, expected=initial)
    assert second.status == "converged" and second.blocking_reasons == ()
    assert second.previous_result_sha256 == first.semantic_sha256
    assert second.heads == heads()
    assert second.coverage_from == FROM and second.coverage_through == THROUGH
    assert second.policy_sha256 == ReconciliationPolicy().semantic_sha256
    assert initial == account()  # immutable expected state was not overwritten
    assert not hasattr(second, "trading_authority")
    with pytest.raises(FrozenInstanceError):
        second.status = "blocked"  # type: ignore[misc]


@pytest.mark.parametrize("field", ["effect_watermark", "control_revision", "lease_generation"])
def test_new_effect_or_control_heads_require_new_pair(field: str) -> None:
    first = compare(observation())
    changed = replace(heads(), **{field: getattr(heads(), field) + 1})
    second = compare(observation(1), previous=first, current_heads=changed)
    assert second.status == "blocked" and second.heads == changed
    assert compare(observation(2), previous=second, current_heads=changed).status == "converged"


@pytest.mark.parametrize("field", ["capacity_sha256", "attempt_sha256"])
def test_new_inventory_or_attempt_hash_cannot_reuse_old_round(field: str) -> None:
    result = compare(
        observation(1),
        previous=compare(observation()),
        current_heads=replace(heads(), **{field: "d" * 64}),
    )
    assert result.blocking_reasons == ("CONVERGENCE_ROUND_REQUIRED",)


def test_relabelled_receipts_and_expired_pair_do_not_converge() -> None:
    old = observation()
    first = compare(old)
    replay = replace(old, round_id="another-name")
    assert compare(replay, previous=first).status == "blocked"
    assert compare(observation(13), previous=first).status == "blocked"


@pytest.mark.parametrize("operation", REQUIRED_RECONCILIATION_OPERATIONS)
def test_matching_balances_do_not_cover_missing_endpoint(operation: str) -> None:
    observed = observation()
    result = compare(
        replace(observed, pages=tuple(p for p in observed.pages if p.operation != operation))
    )
    assert "MISSING_" + operation.upper() in result.blocking_reasons
    assert result.coverage_through is None


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"selection": "filtered"}, "WHOLE_ACCOUNT_SELECTION_REQUIRED"),
        ({"scope_sha256": "b" * 64}, "PAGE_SCOPE_MISMATCH"),
        (
            {"termination": "no_content", "body_bytes": 0, "terminal_evidence_sha256": None},
            "DOCUMENTED_TERMINAL_PAGE_REQUIRED",
        ),
        ({"termination": "unknown"}, "DOCUMENTED_TERMINAL_PAGE_REQUIRED"),
        ({"next_cursor": "next"}, "DOCUMENTED_TERMINAL_PAGE_REQUIRED"),
        ({"ordinal": 1}, "PAGE_ORDINAL_GAP_OR_DUPLICATE"),
        ({"cursor": "opaque+marker/="}, "FIRST_PAGE_CURSOR_PRESENT"),
    ],
)
def test_structural_page_observations_remain_visible_and_block(
    change: dict[str, object], reason: str
) -> None:
    observed = observation()
    observed = replace(observed, pages=(replace(observed.pages[0], **change), *observed.pages[1:]))
    assert reason in compare(observed).blocking_reasons


def test_valid_two_page_chain_and_cycle_missing_repeated_query_failures() -> None:
    observed = observation()
    original = observed.pages[-1]
    first = replace(
        original, next_cursor="opaque+/=", termination="more", terminal_evidence_sha256=None
    )
    last = replace(
        original,
        receipt_id="second-page",
        ordinal=1,
        cursor="opaque+/=",
        request_sha256="b" * 64,
        body_sha256="c" * 64,
        requested_at=original.received_at,
    )
    complete = replace(observed, pages=(*observed.pages[:-1], first, last))
    assert compare(complete).discrepancies == ()
    for bad, reason in (
        (replace(last, cursor="different"), "PAGE_CONTINUATION_UNPROVEN"),
        (replace(last, ordinal=2), "PAGE_ORDINAL_GAP_OR_DUPLICATE"),
        (replace(last, query_sha256="d" * 64), "PAGE_QUERY_CHANGED"),
        (replace(last, body_sha256=first.body_sha256), "REPEATED_PAGE_CONTENT"),
        (replace(last, request_sha256=first.request_sha256), "REPEATED_PAGE_REQUEST"),
    ):
        result = compare(replace(complete, pages=(*complete.pages[:-1], bad)))
        assert reason in result.blocking_reasons


def test_history_bounds_and_receipt_freshness_are_strict() -> None:
    observed = observation()
    result = compare(
        replace(
            observed,
            pages=tuple(
                replace(p, requested_from=FROM + timedelta(seconds=1))
                if p.operation == "activity"
                else p
                for p in observed.pages
            ),
        )
    )
    assert "REQUIRED_HISTORY_NOT_COVERED" in result.blocking_reasons
    last_receipt = observed.pages[0].received_at
    assert (
        "STALE_PAGE_RECEIPT"
        not in compare(
            observed, now=last_receipt + timedelta(seconds=59, microseconds=999999)
        ).blocking_reasons
    )
    assert (
        "STALE_PAGE_RECEIPT"
        in compare(observed, now=last_receipt + timedelta(seconds=60)).blocking_reasons
    )


def test_history_lookback_uses_calendar_days_and_explicit_prior_session_restore_gap() -> None:
    assert (
        reconciliation_history_start(
            opening_boundary=FROM,
            last_reconciled_through=BASE,
            earliest_unresolved_prior_session=None,
        )
        == FROM
    )
    earlier = FROM - timedelta(days=4)
    assert (
        reconciliation_history_start(
            opening_boundary=FROM,
            last_reconciled_through=BASE,
            earliest_unresolved_prior_session=earlier,
        )
        == earlier
    )
    assert (
        reconciliation_history_start(
            opening_boundary=FROM,
            last_reconciled_through=BASE,
            earliest_unresolved_prior_session=None,
            restore_from=earlier,
        )
        == earlier
    )
    assert (
        reconciliation_history_start(
            opening_boundary=earlier,
            last_reconciled_through=None,
            earliest_unresolved_prior_session=None,
        )
        == earlier
    )


@pytest.mark.parametrize("field", REQUIRED_CASH_FIELDS)
def test_missing_cash_or_liability_fields_are_not_zero(field: str) -> None:
    observed = observation()
    result = compare(
        replace(
            observed,
            cash=tuple(replace(c, value=None) if c.field == field else c for c in observed.cash),
        )
    )
    assert "CASH_FIELD_SEMANTICS_UNAVAILABLE" in result.blocking_reasons


def test_documented_cent_tolerance_never_hides_missing_execution() -> None:
    observed = observation()
    cash = tuple(
        replace(c, value=D("200.01"), display_tolerance=D(".01"), rounding_evidence_sha256=SHA)
        if c.field == "settled_cash"
        else c
        for c in observed.cash
    )
    rounded = replace(observed, cash=cash)
    assert compare(rounded).discrepancies == ()
    unknown_fill = replace(rounded, facts=(fact(observed),))
    result = compare(unknown_fill)
    assert result.unresolved_fact_ids == ("execution-1",)
    assert "CASH_FIELD_MISMATCH" in result.blocking_reasons
    assert "CANONICAL_FACT_NOT_APPLIED" in result.blocking_reasons
    too_far = replace(
        rounded,
        cash=tuple(
            replace(c, value=D("200.0100000001")) if c.field == "settled_cash" else c for c in cash
        ),
    )
    assert "CASH_FIELD_MISMATCH" in compare(too_far).blocking_reasons


def test_margin_privilege_is_not_borrowing_or_usd_or_zero_liability_proof() -> None:
    observed = observation()
    assert compare(observed).discrepancies == ()  # explicit MARGIN privileges supported
    modes = replace(observed, account_modes=(("balances", "MARGIN"), ("discovery", "CASH")))
    assert "ACCOUNT_MODE_DISAGREEMENT" in compare(modes).blocking_reasons
    assert "EXPLICIT_USD_REQUIRED" in compare(replace(observed, currency=None)).blocking_reasons
    debit = replace(
        observed,
        cash=tuple(
            replace(c, value=D(1)) if c.field == "margin_liability" else c for c in observed.cash
        ),
    )
    assert "CASH_FIELD_MISMATCH" in compare(debit).blocking_reasons


@pytest.mark.parametrize("quantity", ["8.0000000001", "7", "-8"])
def test_shares_have_no_tolerance(quantity: str) -> None:
    observed = replace(observation(), positions=(PositionObservation("spy", "SPY", D(quantity)),))
    assert "POSITION_QUANTITY_MISMATCH" in compare(observed).blocking_reasons


def test_foreign_positions_and_duplicate_known_rows_are_retained_and_blocked() -> None:
    observed = observation()
    foreign = replace(
        observed, positions=(*observed.positions, PositionObservation(None, "AAPL", D(1)))
    )
    assert "POSITION_IDENTITY_UNSUPPORTED" in compare(foreign).blocking_reasons
    duplicate = replace(observed, positions=observed.positions * 2)
    assert "DUPLICATE_POSITION" in compare(duplicate).blocking_reasons


def test_exact_fact_delivery_deduplicates_and_conflicting_revision_quarantines() -> None:
    observed = observation()
    fill = fact(observed)
    repeat = replace(fill, received_at=observed.completed_at)
    result = compare(replace(observed, facts=(fill, repeat)), applications=(application(),))
    assert result.applied_fact_ids == (fill.fact_id,) and result.discrepancies == ()
    conflict = replace(fill, fact_sha256="b" * 64)
    for facts in ((fill, conflict), (conflict, fill)):
        result = compare(replace(observed, facts=facts), applications=(application(),))
        assert result.applied_fact_ids == () and result.quarantined_fact_ids == (fill.fact_id,)
        assert result.status == "blocked"


def test_application_links_do_not_make_conflicting_or_source_less_facts_valid() -> None:
    observed = observation()
    fill = fact(observed)
    for malformed in (replace(fill, source_receipt_id="absent"), replace(fill, effective_at=None)):
        result = compare(replace(observed, facts=(malformed,)), applications=(application(),))
        assert result.quarantined_fact_ids == (fill.fact_id,)
    result = compare(
        replace(observed, facts=(fill,)),
        applications=(replace(application(), fact_sha256="b" * 64),),
    )
    assert result.quarantined_fact_ids == (fill.fact_id,)


def test_execution_requires_both_order_and_ledger_application_and_no_identity_alias() -> None:
    observed = observation()
    fill = fact(observed)
    incomplete = replace(application(), journal_entry_ids=())
    result = compare(replace(observed, facts=(fill,)), applications=(incomplete,))
    assert "CANONICAL_APPLICATION_LINKS_INCOMPLETE" in result.blocking_reasons
    assert result.unresolved_fact_ids == (fill.fact_id,) and result.applied_fact_ids == ()
    alias = replace(fill, fact_id="alias-execution")
    result = compare(
        replace(observed, facts=(fill, alias)),
        applications=(application(), application("alias-execution")),
    )
    assert result.quarantined_fact_ids == ("alias-execution", "execution-1")


def test_nonposting_canonical_instruction_retains_exact_fact_link_without_invented_journal() -> (
    None
):
    observed = observation()
    instruction = replace(fact(observed, fact_id="instruction-1"), kind="settlement")
    retained = FactApplication("instruction-1", SHA, THROUGH, canonical_fact_ids=("instruction-1",))
    result = compare(replace(observed, facts=(instruction,)), applications=(retained,))
    assert result.applied_fact_ids == ("instruction-1",) and result.discrepancies == ()
    # Applicator/durable resolver must verify this link against an actual retained
    # instruction. An unrelated canonical identity is not structural coverage.
    result = compare(
        replace(observed, facts=(instruction,)),
        applications=(replace(retained, canonical_fact_ids=("other",)),),
    )
    assert "CANONICAL_APPLICATION_LINKS_INCOMPLETE" in result.blocking_reasons


def test_correction_requires_applied_predecessor_and_retains_all_application_ids() -> None:
    observed = observation()
    correction = replace(
        fact(observed, fact_id="correction-1"), kind="correction", predecessor_fact_id="execution-1"
    )
    result = compare(
        replace(observed, facts=(correction,)), applications=(application("correction-1"),)
    )
    assert "CORRECTION_PREDECESSOR_NOT_APPLIED" in result.blocking_reasons
    result = compare(
        replace(observed, facts=(correction,)),
        applications=(application(), application("correction-1")),
    )
    assert result.applied_fact_ids == ("correction-1",) and result.discrepancies == ()


def test_known_external_fact_remains_booked_while_owner_disposition_blocks() -> None:
    observed = observation()
    external = replace(fact(observed), kind="cash_flow", origin="external")
    result = compare(replace(observed, facts=(external,)), applications=(application(),))
    assert result.applied_fact_ids == (external.fact_id,)
    assert "EXTERNAL_ACTIVITY_REQUIRES_OWNER_DISPOSITION" in result.blocking_reasons


def commitment(state: str = "working") -> Commitment:
    return Commitment(
        "commitment",
        "intent",
        "order",
        "spy",
        "SPY",
        Side.BUY,
        D(10),
        D(4),
        D(6),
        D(606),
        D(0),
        D(100),
        D(".06"),
        BASE.date(),
        BASE.date(),
        1,
        BASE,
        BASE + timedelta(hours=6),
        SHA,
        SHA,
        state=state,  # type: ignore[arg-type]
    )


def order(status: str = "partial") -> OrderObservation:
    return OrderObservation("provider-order", "order", "spy", "SPY", Side.BUY, D(10), D(4), status)  # type: ignore[arg-type]


def test_active_order_cumulative_values_are_consistency_only() -> None:
    observed = replace(observation(), orders=(order(),))
    hold = ReconciliationObligation("order", "provider-order", "partial", SHA)
    expected = account(commitments=(commitment("partial"),))
    assert compare(observed, expected=expected, obligations=(hold,)).discrepancies == ()
    assert (
        compare(
            replace(observed, orders=observed.orders * 2), expected=expected, obligations=(hold,)
        ).discrepancies
        == ()
    )
    mismatch = replace(observed, orders=(replace(order(), filled_quantity=D(5)),))
    result = compare(mismatch, expected=expected, obligations=(hold,))
    assert "ORDER_CUMULATIVE_QUANTITY_MISMATCH" in result.blocking_reasons
    assert result.applied_fact_ids == ()  # no invented fifth-share execution
    assert expected.commitments[0].filled_quantity == D(4)


def test_unknown_and_terminal_unreleased_hold_never_clear_on_empty_or_terminal_views() -> None:
    expected = account(commitments=(commitment("unknown"),))
    hold = ReconciliationObligation("order", "provider-order", "unknown", SHA)
    result = compare(observation(), expected=expected, obligations=(hold,))
    assert "DURABLE_UNKNOWN_REQUIRES_DISPOSITION" in result.blocking_reasons
    terminal = replace(commitment(), state="terminal", remaining_quantity=D(0), reserved_cash=D(0))
    terminal_hold = replace(hold, state="terminal_unreleased")
    observed = replace(observation(), orders=(replace(order(), status="canceled"),))
    result = compare(
        observed, expected=account(commitments=(terminal,)), obligations=(terminal_hold,)
    )
    assert "TERMINAL_HOLD_REQUIRES_SEPARATE_RELEASE" in result.blocking_reasons
    assert terminal_hold.state == "terminal_unreleased"


def test_released_historical_order_uses_retained_identity_binding_without_new_hold() -> None:
    terminal = replace(commitment(), state="terminal", remaining_quantity=D(0), reserved_cash=D(0))
    observed = replace(observation(), orders=(replace(order(), status="canceled"),))
    binding = ReconciliationOrderBinding("order", "provider-order", SHA)
    result = compare(observed, expected=account(commitments=(terminal,)), order_bindings=(binding,))
    assert result.discrepancies == ()
    assert (
        "ORDER_IDENTITY_NOT_MAPPED"
        in compare(observed, expected=account(commitments=(terminal,))).blocking_reasons
    )


def test_unrepresented_commitment_and_foreign_orders_block() -> None:
    assert (
        "ACTIVE_COMMITMENT_MISSING_DURABLE_HOLD"
        in compare(observation(), expected=account(commitments=(commitment(),))).blocking_reasons
    )
    observed = replace(observation(), orders=(replace(order(), order_id=None),))
    assert "ORDER_IDENTITY_NOT_MAPPED" in compare(observed).blocking_reasons


def test_provider_observation_cannot_be_promoted_by_matching_data() -> None:
    observed = observation()
    scope = replace(
        SCOPE, provider_id="etrade", environment="production", source_class="provider_observation"
    )
    provider = replace(
        observed,
        scope=scope,
        pages=tuple(replace(p, scope_sha256=scope.semantic_sha256) for p in observed.pages),
    )
    result = compare(provider)
    assert "PROVIDER_QUALIFICATION_REQUIRED" in result.blocking_reasons
    assert all(page.provider_sequence is None for page in provider.pages)
    assert result.scope.environment == "production"
    with pytest.raises(ValueError):
        replace(scope, source_class="stateful_simulation")


def test_decimal_context_cannot_change_comparison_or_digest() -> None:
    observed = observation()
    cash = tuple(
        replace(c, value=D("200.01"), display_tolerance=D(".01"), rounding_evidence_sha256=SHA)
        if c.field == "settled_cash"
        else c
        for c in observed.cash
    )
    observed = replace(observed, cash=cash)
    ordinary = compare(observed)
    with localcontext() as context:
        context.prec = 2
        context.traps[Inexact] = True
        context.traps[Rounded] = True
        assert compare(observed) == ordinary
        assert compare(observed).semantic_sha256 == ordinary.semantic_sha256


def test_constructor_bounds_exact_types_and_policy_are_not_caller_permission_flags() -> None:
    with pytest.raises(ValueError):
        replace(heads(), effect_watermark=True)
    with pytest.raises(ValueError):
        replace(SCOPE, account_id="x" * 129)
    with pytest.raises(ValueError):
        replace(observation(), facts=(fact(observation()),) * (MAX_RECONCILIATION_ITEMS + 1))
    with pytest.raises(ValueError):
        CashObservation("settled_cash", D("NaN"), "USD", SHA)
    with pytest.raises(ValueError):
        CashObservation("settled_cash", D(1), "USD", SHA, D(".01"))
    with pytest.raises(ValueError):
        ReconciliationPolicy(freshness_seconds=61)
    with pytest.raises(ValueError):
        FactApplication("fact", SHA, BASE)
    with pytest.raises(ValueError):
        replace(compare(observation()), status="converged", blocking_reasons=())


def test_invalid_future_required_interval_rejects_without_fabricating_watermark() -> None:
    with pytest.raises(ValueError):
        assess_reconciliation_coverage(
            observation(), required_from=FROM, required_through=BASE + timedelta(days=1), now=BASE
        )
