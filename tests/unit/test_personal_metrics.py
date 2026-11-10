"""Independent financial examples and explicit statistical coverage boundaries."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from decimal import ROUND_DOWN, Decimal, Inexact, localcontext
from fractions import Fraction

import pytest

from packages.domain.accounting_contracts import AccountSnapshot, ExecutionRow, FifoMatchRow
from packages.domain.ledger_reducer import CashFlowKind, create_cash_flow
from packages.domain.metrics import (
    ReportInputError,
    derive_benchmark,
    derive_metrics,
    derive_return_path,
)
from packages.domain.models import Side
from packages.domain.personal_contracts import ReductionPoint
from packages.domain.report_contracts import (
    BenchmarkValuationInput,
    ExternalFlowRow,
    MetricValue,
    ReportConventions,
    ScoredInterval,
    ValuationRow,
)
from packages.domain.wealth import derived_context

HASH = "a" * 64
START = datetime(2025, 1, 1, 21, tzinfo=UTC)
CONVENTIONS = ReportConventions()


def valuation(
    sequence: int,
    nav: str | Decimal | None,
    *,
    day: int = 0,
    roles: tuple = ("daily_close",),
    flow_id: str | None = None,
    paired_id: str | None = None,
    cash: str | None = None,
    market: str = "0",
    net_flow: str = "1000",
    fees: str = "0",
    gross: str = "0",
    dividend: str = "0",
    receivable: str = "0",
    unrealized: str | None = "0",
    reasons: tuple[str, ...] = (),
) -> ValuationRow:
    moment = START + timedelta(days=day)
    amount = Decimal(nav) if nav is not None else None
    cash_amount = Decimal(cash) if cash is not None else amount or Decimal(0)
    return ValuationRow(
        f"v{sequence}",
        AccountSnapshot(
            "account",
            ReductionPoint(day, sequence, moment, 8),
            HASH,
            (),
            (),
            (),
            cash_amount,
            cash_amount,
            Decimal(0),
            Decimal(0),
            Decimal(receivable),
            Decimal(0),
            Decimal(0),
            cash_amount,
            Decimal(market) if nav is not None else None,
            amount,
            Decimal(gross),
            Decimal(fees),
            Decimal(dividend),
            Decimal(unrealized) if unrealized is not None else None,
            Decimal(net_flow),
            HASH,
            HASH,
            reasons,
        ),
        moment,
        moment.date(),
        roles,
        "baseline" not in roles,
        "interval",
        flow_id,
        paired_id,
    )


def interval(
    rows: tuple[ValuationRow, ...], expected: tuple[date, ...] | None = None
) -> ScoredInterval:
    sessions = (
        tuple(row.session for row in rows[1:] if "daily_close" in row.roles)
        if expected is None
        else expected
    )
    return ScoredInterval("interval", "fold", rows[0].row_id, rows[-1].row_id, sessions, (), HASH)


def metrics(
    rows: tuple[ValuationRow, ...],
    *,
    flows: tuple[ExternalFlowRow, ...] = (),
    executions: tuple[ExecutionRow, ...] = (),
    matches: tuple[FifoMatchRow, ...] = (),
    window: ScoredInterval | None = None,
    conventions: ReportConventions = CONVENTIONS,
) -> dict[str, MetricValue]:
    selected = interval(rows) if window is None else window
    returns = derive_return_path(
        valuations=rows, flows=flows, interval=selected, conventions=conventions
    )
    return {
        value.name: value
        for value in derive_metrics(
            valuations=rows,
            flows=flows,
            executions=executions,
            fifo_matches=matches,
            returns=returns,
            interval=selected,
            conventions=conventions,
        )
    }


def flow_case(
    withdrawal: bool = False,
) -> tuple[tuple[ValuationRow, ...], tuple[ExternalFlowRow, ...]]:
    flow = create_cash_flow(
        kind=CashFlowKind.WITHDRAWAL if withdrawal else CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=Decimal(200 if withdrawal else 500),
        effective_at=START + timedelta(days=1),
        recorded_at=START + timedelta(days=1),
        external_reference="external-flow",
    )
    identifier = flow.cash_flow_id
    after, end, cash, net = (
        ("900", "990", "0", "800") if withdrawal else ("1600", "1760", "700", "1500")
    )
    rows = (
        valuation(0, "1000", roles=("baseline",), cash="200", market="800"),
        valuation(
            1,
            "1100",
            day=1,
            roles=("pre_flow",),
            flow_id=identifier,
            paired_id="v2",
            cash="200",
            market="900",
        ),
        valuation(
            2,
            after,
            day=1,
            roles=("post_flow",),
            flow_id=identifier,
            paired_id="v1",
            cash=cash,
            market="900",
            net_flow=net,
        ),
        valuation(
            3,
            end,
            day=2,
            roles=("daily_close", "terminal"),
            cash=cash,
            market="990" if withdrawal else "1060",
            net_flow=net,
        ),
    )
    return rows, (
        ExternalFlowRow(
            flow, Decimal(-200 if withdrawal else 500), 2, "v1", "v2", journal_sha256=HASH
        ),
    )


def benchmark_inputs(
    rows: tuple[ValuationRow, ...], prices: tuple[str | None, ...]
) -> tuple[BenchmarkValuationInput, ...]:
    return tuple(
        BenchmarkValuationInput(
            row.row_id,
            "SPY-total-return" if price is not None else "unavailable",
            Decimal(price) if price is not None else None,
            HASH,
            row.economic_at,
            row.snapshot.point.knowledge_at,
            "synthetic_total_return_units" if price is not None else "adjusted_total_return_units",
            () if price is not None else ("missing_benchmark_mark",),
        )
        for row, price in zip(rows, prices, strict=True)
    )


def benchmark(
    rows: tuple[ValuationRow, ...],
    prices: tuple[str | None, ...],
    flows: tuple[ExternalFlowRow, ...] = (),
):
    return derive_benchmark(
        inputs=benchmark_inputs(rows, prices),
        valuations=rows,
        flows=flows,
        interval=interval(rows),
        conventions=CONVENTIONS,
    )


@pytest.mark.parametrize("withdrawal", [False, True])
def test_e4_e5_have_exact_21_percent_and_identical_benchmark_flow_clock(withdrawal: bool) -> None:
    rows, flows = flow_case(withdrawal)
    values = metrics(rows, flows=flows)
    assert values["total_return"].value == Decimal("0.21")
    assert values["net_pnl"].value == Decimal(190 if withdrawal else 260)
    assert values["maximum_drawdown"].value == 0
    comparison = benchmark(rows, ("100", "110", "110", "121"), flows)
    assert comparison.rows[-1].nav == Decimal(990 if withdrawal else 1760)
    assert comparison.rows[-1].wealth == Decimal("1.21")
    assert {m.name: m.value for m in comparison.metrics}["total_return"] == Decimal("0.21")
    assert comparison.matched_flow_ids == (flows[0].flow.cash_flow_id,)
    assert comparison.cash_rows[-1].nav == Decimal(800 if withdrawal else 1500)
    assert comparison.cash_rows[-1].wealth == 1
    assert "fractional-analytical-units" in comparison.metrics[0].assumptions


@pytest.mark.parametrize("missing_index", [0, 1, 2, 3])
def test_missing_benchmark_placeholder_does_not_reject_valid_series(missing_index: int) -> None:
    rows, flows = flow_case()
    prices: list[str | None] = ["100", "110", "110", "121"]
    prices[missing_index] = None
    comparison = benchmark(rows, tuple(prices), flows)
    total = {m.name: m for m in comparison.metrics}["total_return"]
    assert total.value is None and "missing_benchmark_mark" in total.reasons
    assert comparison.cash_rows[-1].wealth == 1
    assert metrics(rows, flows=flows)["total_return"].value == Decimal("0.21")


def test_missing_strategy_terminal_mark_does_not_damage_known_benchmark() -> None:
    rows, flows = flow_case()
    terminal = replace(
        rows[-1],
        snapshot=replace(
            rows[-1].snapshot,
            nav=None,
            market_value=None,
            unrealized_pnl=None,
            valuation_reasons=("missing_current_session_mark",),
            last_known_nav=Decimal(1600),
        ),
    )
    changed = (*rows[:-1], terminal)
    values = metrics(changed, flows=flows)
    assert values["total_return"].value is None
    assert values["ending_equity"].value is None
    assert values["ending_trade_date_cash"].value == 700
    assert terminal.snapshot.last_known_nav == 1600
    assert benchmark(changed, ("100", "110", "110", "121"), flows).rows[-1].wealth == Decimal(
        "1.21"
    )


def test_omitted_offsetting_flow_pairs_inside_interval_reject() -> None:
    rows, flows = flow_case()
    outgoing = create_cash_flow(
        kind=CashFlowKind.WITHDRAWAL,
        currency="USD",
        amount=Decimal(500),
        effective_at=START + timedelta(days=1),
        recorded_at=START + timedelta(days=1),
        external_reference="offset",
    )
    bad = (
        replace(flows[0], pre_valuation_id="missing-a", post_valuation_id="missing-b", sequence=1),
        ExternalFlowRow(outgoing, Decimal(-500), 2, "missing-c", "missing-d", journal_sha256=HASH),
    )
    remaining = (rows[0], valuation(3, "1100", day=2, roles=("daily_close", "terminal")))
    with pytest.raises(ReportInputError, match="omits both"):
        metrics(remaining, flows=bad)


@pytest.mark.parametrize("change", ["pair", "price", "economic", "knowledge"])
def test_benchmark_requires_exact_flow_and_causal_boundaries(change: str) -> None:
    rows, flows = flow_case()
    inputs = list(benchmark_inputs(rows, ("100", "110", "110", "121")))
    if change == "pair":
        flows = (replace(flows[0], post_valuation_id="missing"),)
    elif change == "price":
        inputs[2] = replace(inputs[2], unit_price=Decimal(111))
    elif change == "economic":
        inputs[2] = replace(inputs[2], economic_at=inputs[2].economic_at - timedelta(seconds=1))
    else:
        inputs[2] = replace(inputs[2], knowledge_at=inputs[2].knowledge_at + timedelta(seconds=1))
    with pytest.raises(ReportInputError):
        derive_benchmark(
            inputs=tuple(inputs),
            valuations=rows,
            flows=flows,
            interval=interval(rows),
            conventions=CONVENTIONS,
        )


def execution(
    identifier: str, sequence: int, quantity: str, price: str, fee: str, side: Side
) -> ExecutionRow:
    return ExecutionRow(
        identifier,
        1,
        "fact-" + identifier,
        HASH,
        "order-" + identifier,
        "intent-" + identifier,
        "SPY",
        "SPY",
        side,
        Decimal(quantity),
        Decimal(price),
        Decimal(fee),
        START,
        START,
        sequence,
        "synthetic-events-v1",
    )


def test_e1_fifo_fees_are_attributed_without_reposting_portfolio_expense() -> None:
    rows = (
        valuation(0, "1000", roles=("baseline",)),
        valuation(
            4,
            "1038",
            day=1,
            roles=("daily_close", "terminal"),
            cash="818",
            market="220",
            fees="2",
            gross="20",
            unrealized="20",
        ),
    )
    buy = execution("buy", 1, "4", "100", "1", Side.BUY)
    sell = execution("sell", 3, "2", "110", "1", Side.SELL)
    match = FifoMatchRow(
        "match",
        "SPY",
        "buy",
        1,
        "sell",
        1,
        buy.order_id,
        sell.order_id,
        Decimal(2),
        Decimal(200),
        Decimal(220),
        Decimal("0.5"),
        Decimal(1),
        START,
        START,
        HASH,
        group_complete=True,
    )
    values = metrics(rows, executions=(buy, sell), matches=(match,))
    assert values["net_pnl"].value == 38
    assert values["realized_pnl"].value == 18
    assert values["closed_trade_net_pnl"].value == Decimal("18.5")
    assert values["total_execution_costs"].value == 2
    assert values["trade_count"].value == 1
    with localcontext(derived_context()):
        assert values["turnover"].value == Decimal(620) / Decimal(1038)
        assert values["average_gross_exposure"].value == Decimal(220) / Decimal(1038)
    assert values["profit_factor"].value is None


def test_partial_fill_fifo_rows_group_by_one_terminal_closing_order() -> None:
    rows = (
        valuation(0, "1000", roles=("baseline",)),
        valuation(9, "1040", day=1, roles=("daily_close", "terminal")),
    )
    buy = execution("buy", 1, "4", "100", "1", Side.BUY)
    sell1 = execution("sell1", 2, "1", "110", "0.5", Side.SELL)
    sell2 = replace(execution("sell2", 3, "1", "110", "0.5", Side.SELL), order_id=sell1.order_id)
    matches = tuple(
        FifoMatchRow(
            "m" + sell.execution_id,
            "SPY",
            buy.execution_id,
            1,
            sell.execution_id,
            1,
            buy.order_id,
            sell.order_id,
            Decimal(1),
            Decimal(100),
            Decimal(110),
            Decimal("0.25"),
            Decimal("0.5"),
            START,
            START,
            HASH,
            group_complete=True,
        )
        for sell in (sell1, sell2)
    )
    values = metrics(rows, executions=(buy, sell1, sell2), matches=matches)
    assert values["trade_count"].value == 1
    assert values["closed_trade_net_pnl"].value == Decimal("18.5")
    pending = metrics(
        rows,
        executions=(buy, sell1, sell2),
        matches=tuple(replace(m, group_complete=False) for m in matches),
    )
    assert pending["trade_count"].value == 0
    assert pending["hit_rate"].reasons == ("no_completed_trades",)
    with pytest.raises(ReportInputError, match="allocation exceeds"):
        metrics(
            rows,
            executions=(buy, sell1, sell2),
            matches=(replace(matches[0], opening_fee=Decimal(2)), matches[1]),
        )


@pytest.mark.parametrize(
    ("nav", "cash", "market", "fees", "gross", "dividend", "receivable", "unrealized", "pnl"),
    [
        ("1000", "600", "392", "0", "0", "8", "8", "-8", "0"),
        ("1000", "608", "392", "0", "0", "8", "0", "-8", "0"),
        ("1039", "764", "275", "1", "15", "0", "0", "25", "39"),
        ("998", "594", "404", "2", "0", "0", "0", "0", "-2"),
        ("1000", "1000", "0", "0", "0", "0", "0", "0", "0"),
        ("1002", "696", "306", "2", "0", "0", "0", "4", "2"),
    ],
)
def test_e2_e3_e6_e7_accounting_checkpoints_preserve_actions_and_fee_semantics(
    nav, cash, market, fees, gross, dividend, receivable, unrealized, pnl
) -> None:
    rows = (
        valuation(0, "1000", roles=("baseline",)),
        valuation(
            2,
            nav,
            day=1,
            roles=("daily_close", "terminal"),
            cash=cash,
            market=market,
            fees=fees,
            gross=gross,
            dividend=dividend,
            receivable=receivable,
            unrealized=unrealized,
        ),
    )
    values = metrics(rows)
    assert values["net_pnl"].value == Decimal(pnl)
    assert values["total_execution_costs"].value == Decimal(fees)
    assert values["dividend_income"].value == Decimal(dividend)
    assert values["ending_dividend_receivable"].value == Decimal(receivable)


def test_open_execution_enters_turnover_without_closed_trade_statistics() -> None:
    rows = (
        valuation(0, "1000", roles=("baseline",)),
        valuation(
            2, "999", day=1, roles=("daily_close", "terminal"), cash="599", market="400", fees="1"
        ),
    )
    buy = execution("buy", 1, "4", "100", "1", Side.BUY)
    values = metrics(rows, executions=(buy,))
    assert values["turnover"].value > 0
    assert values["total_execution_costs"].value == 1
    assert values["trade_count"].value == 0
    assert values["hit_rate"].value is None
    with pytest.raises(ReportInputError, match="effective heads"):
        metrics(rows, executions=(buy, replace(buy, revision=2)))


def flat_rows(count: int) -> tuple[ValuationRow, ...]:
    return tuple(
        valuation(
            i,
            "1000",
            day=i,
            roles=("baseline",)
            if i == 0
            else (("daily_close", "terminal") if i == count else ("daily_close",)),
        )
        for i in range(count + 1)
    )


@pytest.mark.parametrize("count", [5, 251, 252])
def test_annualization_requires_252_complete_daily_returns_plus_baseline(count: int) -> None:
    values = metrics(flat_rows(count))
    assert values["total_return"].value == 0
    assert values["annualized_volatility"].coverage.valid_returns == count
    assert values["annualized_volatility"].coverage.expected_sessions == count
    assert values["annualized_volatility"].value == (Decimal(0) if count == 252 else None)
    assert values["annualized_return"].value == (Decimal(0) if count == 252 else None)
    assert values["sharpe_ratio"].value is None
    assert values["sortino_ratio"].value is None
    assert ("zero_variance" if count == 252 else "insufficient_scored_sessions") in values[
        "sharpe_ratio"
    ].reasons


def test_sample_variance_sharpe_and_sortino_match_independent_fraction_oracle() -> None:
    rows = tuple(
        valuation(
            i,
            "1000" if i % 2 == 0 else "1100",
            day=i,
            roles=("baseline",)
            if i == 0
            else (("daily_close", "terminal") if i == 252 else ("daily_close",)),
        )
        for i in range(253)
    )
    values = metrics(rows)
    # Exactly 126 observations at 1/10 and 126 at -1/11; these fractions are
    # independent of the implementation's returned daily/wealth rows.
    sample = [Fraction(1, 10), Fraction(-1, 11)] * 126
    mean = sum(sample) / 252
    variance = sum((x - mean) ** 2 for x in sample) / 251
    downside = sum(min(x, 0) ** 2 for x in sample) / 252
    with localcontext(derived_context()):

        def d(value: Fraction) -> Decimal:
            return Decimal(value.numerator) / Decimal(value.denominator)

        expected_vol = (d(variance) * 252).sqrt()
        expected_sharpe = Decimal(252).sqrt() * d(mean) / d(variance).sqrt()
        expected_sortino = Decimal(252).sqrt() * d(mean) / d(downside).sqrt()
        for name, expected in (
            ("annualized_volatility", expected_vol),
            ("sharpe_ratio", expected_sharpe),
            ("sortino_ratio", expected_sortino),
        ):
            assert abs(values[name].value - expected) < Decimal("1E-58")
        assert abs(values["total_return"].value) < Decimal("1E-58")


def test_missing_scored_session_latches_path_and_exposes_coverage() -> None:
    complete = flat_rows(252)
    rows = tuple(row for row in complete if row.row_id != "v100")
    values = metrics(rows, window=interval(complete))
    assert values["total_return"].value is None
    assert values["annualized_volatility"].value is None
    coverage = values["annualized_volatility"].coverage
    assert coverage.expected_sessions == 252 and coverage.observed_sessions == 251
    assert coverage.valid_returns == 99
    assert any("missing_expected_session" in reasons for _, reasons in coverage.excluded)
    assert values["ending_equity"].value == 1000


def test_flow_boundaries_are_not_extra_daily_samples() -> None:
    rows, flows = flow_case()
    values = metrics(rows, flows=flows)
    assert values["total_return"].coverage.valid_returns == 1
    assert values["total_return"].coverage.contributing_row_ids == ("v0", "v1", "v2", "v3")
    assert values["average_gross_exposure"].coverage.sample_count == 1
    path = derive_return_path(
        valuations=rows, flows=flows, interval=interval(rows), conventions=CONVENTIONS
    )
    assert path[-1].period_return == Decimal("0.21")


def test_nonpositive_nav_and_missing_risk_free_have_reasoned_null_ratios() -> None:
    rows = (
        valuation(0, "0", roles=("baseline",)),
        valuation(1, "0", day=1, roles=("daily_close", "terminal")),
    )
    values = metrics(rows)
    assert values["total_return"].value is None
    assert "nonpositive_nav" in values["total_return"].reasons
    assert values["turnover"].value is None
    rf = replace(CONVENTIONS, risk_free_daily=None, risk_free_model="unavailable")
    values = metrics(flat_rows(252), conventions=rf)
    assert "missing_risk_free_input" in values["sharpe_ratio"].reasons
    assert values["annualized_volatility"].value == 0


def test_metric_values_and_hashes_ignore_ambient_decimal_settings() -> None:
    rows, flows = flow_case()
    expected = metrics(rows, flows=flows)
    expected_benchmark = benchmark(rows, ("100", "110", "110", "121"), flows)
    with localcontext() as context:
        context.prec = 2
        context.rounding = ROUND_DOWN
        context.traps[Inexact] = True
        assert metrics(rows, flows=flows) == expected
        assert benchmark(rows, ("100", "110", "110", "121"), flows) == expected_benchmark


def test_missing_and_duplicate_daily_rows_cannot_be_disguised_as_252_samples() -> None:
    rows = flat_rows(252)
    duplicated = (
        *rows[:100],
        replace(
            rows[100],
            row_id="duplicate",
            snapshot=replace(
                rows[100].snapshot, point=replace(rows[100].snapshot.point, reduction_sequence=99)
            ),
        ),
        *rows[100:],
    )
    with pytest.raises(ReportInputError):
        metrics(duplicated, window=interval(rows))


def test_variable_positive_returns_have_undefined_zero_downside_sortino() -> None:
    navs = [Decimal(1000)]
    with localcontext(derived_context()):
        for index in range(252):
            navs.append(navs[-1] * (Decimal("1.1") if index % 2 else Decimal("1.2")))
    rows = tuple(
        valuation(
            i,
            nav,
            day=i,
            roles=("baseline",)
            if i == 0
            else (("daily_close", "terminal") if i == 252 else ("daily_close",)),
        )
        for i, nav in enumerate(navs)
    )
    values = metrics(rows)
    assert values["sharpe_ratio"].value is not None
    assert values["annualized_volatility"].value > 0
    assert values["sortino_ratio"].value is None
    assert values["sortino_ratio"].reasons == ("zero_downside_deviation",)


def test_constant_negative_returns_obey_conservative_zero_variance_sortino_rule() -> None:
    rows = tuple(
        valuation(
            i,
            Decimal(f"1E{-i}"),
            day=i,
            roles=("baseline",)
            if i == 0
            else (("daily_close", "terminal") if i == 252 else ("daily_close",)),
        )
        for i in range(253)
    )
    values = metrics(rows)
    assert values["annualized_volatility"].value == 0
    assert values["sortino_ratio"].value is None
    assert values["sortino_ratio"].reasons == ("zero_variance",)


def test_profit_factor_and_hit_rate_use_terminal_group_net_profit() -> None:
    rows = (
        valuation(0, "1000", roles=("baseline",)),
        valuation(5, "1000", day=1, roles=("daily_close", "terminal")),
    )
    buy = execution("buy", 1, "2", "100", "0", Side.BUY)
    sells = (
        execution("win", 2, "1", "110", "0", Side.SELL),
        execution("loss", 3, "1", "90", "0", Side.SELL),
    )
    matches = tuple(
        FifoMatchRow(
            sell.execution_id,
            "SPY",
            "buy",
            1,
            sell.execution_id,
            1,
            buy.order_id,
            sell.order_id,
            Decimal(1),
            Decimal(100),
            sell.price,
            Decimal(0),
            Decimal(0),
            START,
            START,
            HASH,
            group_complete=True,
        )
        for sell in sells
    )
    values = metrics(rows, executions=(buy, *sells), matches=matches)
    assert values["trade_count"].value == 2
    assert values["hit_rate"].value == Decimal("0.5")
    assert values["profit_factor"].value == 1
    assert values["closed_trade_net_pnl"].value == 0


def test_benchmark_cannot_borrow_to_match_a_withdrawal() -> None:
    rows, flows = flow_case(withdrawal=True)
    comparison = benchmark(rows, ("100", "10", "10", "11"), flows)
    assert comparison.rows[-1].nav is None
    assert "benchmark_withdrawal_exceeds_value" in comparison.rows[-1].reasons
    assert comparison.cash_rows[-1].nav == 800
    assert comparison.cash_rows[-1].wealth == 1


def test_initial_funding_zero_nav_is_retained_outside_scored_wealth() -> None:
    funding = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=Decimal(1000),
        effective_at=START,
        recorded_at=START,
        external_reference="initial",
    )
    identifier = funding.cash_flow_id
    before = valuation(
        0, "0", roles=("pre_flow",), flow_id=identifier, paired_id="v1", net_flow="0"
    )
    baseline = valuation(
        1, "1000", roles=("baseline", "post_flow"), flow_id=identifier, paired_id="v0"
    )
    terminal = valuation(2, "1100", day=1, roles=("daily_close", "terminal"))
    flow = ExternalFlowRow(funding, Decimal(1000), 1, "v0", "v1", "initial_capital", HASH)
    window = interval((baseline, terminal))
    values = metrics((before, baseline, terminal), flows=(flow,), window=window)
    assert values["total_return"].value == Decimal("0.1")
    assert values["net_external_flow"].value == 0
    assert values["net_pnl"].value == 100
