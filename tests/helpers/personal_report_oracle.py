"""Independent rational checks for action-free W2 engineering runs.

This verifier reads accepted facts and report outputs. It imports neither the
production wealth kernel nor metric calculators, and does not run another
scheduler. Fraction arithmetic provides a separate numerical implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import (
    ROUND_HALF_EVEN,
    Clamped,
    Context,
    Decimal,
    DivisionByZero,
    FloatOperation,
    InvalidOperation,
    Overflow,
    Subnormal,
    Underflow,
    localcontext,
)
from fractions import Fraction

from packages.domain.ledger_reducer import CashFlowKind
from packages.domain.models import Side
from packages.domain.report_contracts import EngineResult, RunReport, ValuationRow

ZERO = Fraction(0)
ONE = Fraction(1)
_TOLERANCE = Fraction(1, 10**50)


def independent_annual_statistics(
    daily_returns: tuple[Fraction | None, ...],
    terminal_wealth: Fraction | None,
    *,
    annual_sessions: int = 252,
    minimum_sessions: int = 252,
    risk_free_daily: Fraction | None = ZERO,
) -> dict[str, Decimal | None]:
    """Use exact rational moments, then separate 80-digit roots and powers."""
    values: dict[str, Decimal | None] = {
        "annualized_return": None,
        "annualized_volatility": None,
        "sharpe_ratio": None,
        "sortino_ratio": None,
    }
    if (
        len(daily_returns) < minimum_sessions
        or terminal_wealth is None
        or terminal_wealth <= 0
        or any(value is None for value in daily_returns)
    ):
        return values
    returns = tuple(value for value in daily_returns if value is not None)
    n = len(returns)
    mean = sum(returns, ZERO) / n
    variance = sum(((value - mean) ** 2 for value in returns), ZERO) / (n - 1)
    context = Context(
        prec=80,
        rounding=ROUND_HALF_EVEN,
        Emin=-999999,
        Emax=999999,
        capitals=1,
        clamp=0,
        flags=[],
        traps=[
            Clamped,
            DivisionByZero,
            FloatOperation,
            InvalidOperation,
            Overflow,
            Subnormal,
            Underflow,
        ],
    )

    def decimal(value: Fraction) -> Decimal:
        return Decimal(value.numerator) / Decimal(value.denominator)

    with localcontext(context):
        scale = Decimal(annual_sessions).sqrt()
        deviation = decimal(variance).sqrt()
        values["annualized_return"] = decimal(terminal_wealth) ** (Decimal(annual_sessions) / n) - 1
        values["annualized_volatility"] = deviation * scale
        if variance == 0 or risk_free_daily is None:
            return values
        excess_mean = mean - risk_free_daily
        values["sharpe_ratio"] = scale * decimal(excess_mean) / deviation
        downside = sum((min(value - risk_free_daily, ZERO) ** 2 for value in returns), ZERO) / n
        if downside:
            values["sortino_ratio"] = scale * decimal(excess_mean) / decimal(downside).sqrt()
    return values


def _annual_checks(
    report: RunReport,
    rows: tuple[ValuationRow, ...],
    linked: tuple[tuple[Fraction | None, Fraction | None, Fraction | None], ...],
    metrics: dict[str, Decimal | None],
) -> None:
    previous_close: Fraction | None = ONE
    daily: list[Fraction | None] = []
    for row, (_, wealth, _) in zip(rows, linked, strict=True):
        if "daily_close" in row.roles:
            daily.append(
                None if wealth is None or previous_close is None else wealth / previous_close - ONE
            )
            previous_close = wealth
    rate = report.conventions.risk_free_daily
    annual = independent_annual_statistics(
        tuple(daily),
        linked[-1][1],
        annual_sessions=report.conventions.annualization_sessions,
        minimum_sessions=report.conventions.minimum_annualized_sessions,
        risk_free_daily=None if rate is None else Fraction(rate),
    )
    for name, expected in annual.items():
        assert_rational(metrics[name], None if expected is None else Fraction(expected))


def assert_rational(actual: Decimal | None, expected: Fraction | None) -> None:
    """Allow only the documented rounding of derived 64-digit Decimal ratios."""
    if expected is None:
        assert actual is None
    else:
        assert actual is not None
        assert abs(Fraction(actual) - expected) <= max(ONE, abs(expected)) * _TOLERANCE


@dataclass(frozen=True)
class IndependentSummary:
    final_nav: Fraction | None
    net_pnl: Fraction | None
    total_return: Fraction | None
    maximum_drawdown: Fraction | None
    fees: Fraction
    turnover: Fraction | None
    average_gross_exposure: Fraction | None
    benchmark_total_return: Fraction | None


def _facts_at(
    result: EngineResult,
    row: ValuationRow,
) -> tuple[Fraction, dict[str, Fraction], Fraction]:
    """Recompute cash/whole-share holdings from effective fills and flow sequence."""
    point = row.snapshot.point
    posted = {item.flow.cash_flow_id: item.sequence for item in result.flows}
    cash = ZERO
    for flow in result.final_state.cash_flows:
        if flow.cash_flow_id in posted:
            if posted[flow.cash_flow_id] > point.reduction_sequence:
                continue
        else:
            # Pinned pre-funded oracle capital predates the fresh scored baseline.
            assert flow.recorded_at <= point.knowledge_at
        cash += Fraction(flow.amount) * (1 if flow.kind is CashFlowKind.CONTRIBUTION else -1)
    holdings: dict[str, Fraction] = {}
    fees = ZERO
    for fill in result.executions:
        if fill.sequence > point.reduction_sequence:
            continue
        quantity, price, fee = Fraction(fill.quantity), Fraction(fill.price), Fraction(fill.fee)
        sign = 1 if fill.side is Side.BUY else -1
        holdings[fill.instrument_id] = holdings.get(fill.instrument_id, ZERO) + sign * quantity
        cash -= sign * quantity * price + fee
        fees += fee
    assert all(quantity >= 0 for quantity in holdings.values())
    return cash, holdings, fees


def _nav_at(result: EngineResult, row: ValuationRow) -> tuple[Fraction | None, Fraction]:
    cash, holdings, fees = _facts_at(result, row)
    assert Fraction(row.snapshot.trade_date_cash) == cash
    assert Fraction(row.snapshot.fees) == fees
    assert {
        item.instrument_id: Fraction(item.quantity)
        for item in row.snapshot.positions
        if item.quantity
    } == {key: quantity for key, quantity in holdings.items() if quantity}
    marks = {mark.instrument_id: mark for mark in row.snapshot.marks}
    market = sum(
        (
            quantity * Fraction(marks[key].price)
            for key, quantity in holdings.items()
            if quantity and key in marks
        ),
        ZERO,
    )
    complete = all(key in marks for key, quantity in holdings.items() if quantity)
    nav = cash + market if complete else None
    if row.snapshot.valuation_reasons:
        assert row.snapshot.nav is None
        if row.snapshot.last_known_nav is not None and nav is not None:
            assert Fraction(row.snapshot.last_known_nav) == nav
        return None, market
    assert nav is not None
    assert row.snapshot.nav is not None and Fraction(row.snapshot.nav) == nav
    assert row.snapshot.market_value is not None and Fraction(row.snapshot.market_value) == market
    assert (
        Fraction(row.snapshot.settled_cash)
        + Fraction(row.snapshot.trade_receivable)
        - Fraction(row.snapshot.trade_payable)
        == cash
    )
    return nav, market


def _linked(
    rows: tuple[ValuationRow, ...],
    navs: tuple[Fraction | None, ...],
    flows: dict[str, Fraction],
) -> tuple[tuple[Fraction | None, Fraction | None, Fraction | None], ...]:
    """Link elementary returns; post-flow adjustments never create performance."""
    values: list[tuple[Fraction | None, Fraction | None, Fraction | None]] = []
    wealth: Fraction | None = ONE
    peak = ONE
    previous: Fraction | None = None
    for index, (row, nav) in enumerate(zip(rows, navs, strict=True)):
        if nav is None or nav <= 0 or wealth is None:
            wealth = None
            values.append((None, None, None))
            previous = nav
            continue
        if index == 0:
            growth = ONE
        elif "post_flow" in row.roles:
            assert previous is not None and row.flow_id is not None
            assert nav == previous + flows[row.flow_id]
            growth = ONE
        else:
            assert previous is not None and previous > 0
            growth = nav / previous
        wealth *= growth
        peak = max(peak, wealth)
        values.append((growth, wealth, ONE - wealth / peak))
        previous = nav
    return tuple(values)


def verify_personal_report(result: EngineResult, report: RunReport) -> IndependentSummary:
    """Verify exact accounting and rational metrics for flat/regime/flow fixtures.

    Corporate-action accounting and revision-restated historical paths have
    separate oracles; this helper refuses to silently approximate either.
    """
    assert result.status == report.status == "completed"
    assert result.run_id == report.run_id and report.source == result
    assert not result.final_state.stock_splits
    assert not result.final_state.cash_dividends and not result.final_state.dividend_payments
    assert all(fill.revision == 1 for fill in result.executions)
    assert len({fill.execution_id for fill in result.executions}) == len(result.executions)
    rows = tuple(row for row in result.valuations if row.scored)
    assert rows and "baseline" in rows[0].roles and "terminal" in rows[-1].roles
    assert rows[0].row_id == result.interval.baseline_valuation_id
    assert rows[-1].row_id == result.interval.terminal_valuation_id
    assert (
        tuple(row.session for row in rows if "daily_close" in row.roles)
        == result.interval.expected_sessions
    )
    assert len({row.snapshot.point.reduction_sequence for row in rows}) == len(rows)
    computed = tuple(_nav_at(result, row) for row in rows)
    navs = tuple(item[0] for item in computed)
    flows = {
        item.flow.cash_flow_id: Fraction(item.signed_amount)
        for item in result.flows
        if item.origin != "initial_capital"
    }
    linked = _linked(rows, navs, flows)
    assert len(report.returns) == len(rows)
    previous_close: Fraction | None = ONE
    for row, actual, (growth, wealth, drawdown) in zip(rows, report.returns, linked, strict=True):
        assert actual.valuation_id == row.row_id
        assert_rational(actual.growth, growth)
        if "daily_close" in row.roles:
            period = (
                None if wealth is None or previous_close is None else wealth / previous_close - ONE
            )
            previous_close = wealth
        else:
            period = None if growth is None else growth - ONE
        assert_rational(actual.period_return, period)
        assert_rational(actual.wealth, wealth)
        assert_rational(actual.drawdown, drawdown)
    metrics = {item.name: item.value for item in report.metrics}
    total_return = None if linked[-1][1] is None else linked[-1][1] - ONE
    drawdown = (
        None
        if any(item[2] is None for item in linked)
        else max(item[2] for item in linked if item[2] is not None)
    )
    net_flow = sum(flows.values(), ZERO)
    net_pnl = None if navs[-1] is None or navs[0] is None else navs[-1] - navs[0] - net_flow
    baseline_sequence = rows[0].snapshot.point.reduction_sequence
    terminal_sequence = rows[-1].snapshot.point.reduction_sequence
    executions = tuple(
        fill for fill in result.executions if baseline_sequence < fill.sequence <= terminal_sequence
    )
    fees = sum((Fraction(fill.fee) for fill in executions), ZERO)
    daily = tuple(
        (nav, market)
        for row, (nav, market) in zip(rows, computed, strict=True)
        if "daily_close" in row.roles and nav is not None and nav > 0
    )
    mean_nav = (
        sum((nav for nav, _ in daily if nav is not None), ZERO) / len(daily) if daily else None
    )
    turnover = (
        None
        if mean_nav is None
        else sum((Fraction(fill.quantity) * Fraction(fill.price) for fill in executions), ZERO)
        / mean_nav
    )
    exposure = (
        None
        if not daily
        else sum((market / nav for nav, market in daily if nav is not None), ZERO) / len(daily)
    )
    expected = {
        "starting_equity": navs[0],
        "ending_equity": navs[-1],
        "net_pnl": net_pnl,
        "net_external_flow": net_flow,
        "total_return": total_return,
        "maximum_drawdown": drawdown,
        "total_execution_costs": fees,
        "turnover": turnover,
        "average_gross_exposure": exposure,
        "average_net_exposure": exposure,
    }
    for name, value in expected.items():
        assert name in metrics
        assert_rational(metrics[name], value)
    _annual_checks(report, rows, linked, metrics)
    assert Fraction(result.final_snapshot.trade_date_cash) == _facts_at(result, rows[-1])[0]
    assert_rational(result.final_snapshot.nav, navs[-1])
    prices = {item.valuation_id: item for item in result.benchmark_inputs}
    benchmark_navs: list[Fraction | None] = []
    units: Fraction | None = None
    cash_nav = navs[0]
    for index, row in enumerate(rows):
        item = prices.get(row.row_id)
        price = (
            None
            if item is None or item.unit_price is None or item.reasons
            else Fraction(item.unit_price)
        )
        if index == 0:
            units = None if navs[0] is None or price is None else navs[0] / price
        elif "post_flow" in row.roles:
            assert row.flow_id is not None
            if units is not None and price is not None:
                units += flows[row.flow_id] / price
            if cash_nav is not None:
                cash_nav += flows[row.flow_id]
        if price is None:
            units = None
        benchmark_navs.append(None if units is None or price is None else units * price)
        benchmark_actual = report.benchmark.rows[index]
        cash_actual = report.benchmark.cash_rows[index]
        assert benchmark_actual.valuation_id == cash_actual.valuation_id == row.row_id
        assert_rational(benchmark_actual.units, units)
        assert_rational(benchmark_actual.nav, benchmark_navs[-1])
        assert_rational(cash_actual.nav, cash_nav)
        assert_rational(cash_actual.wealth, ONE if cash_nav is not None and cash_nav > 0 else None)
    benchmark_path = _linked(rows, tuple(benchmark_navs), flows)
    for benchmark_actual, (_, wealth, _) in zip(report.benchmark.rows, benchmark_path, strict=True):
        assert_rational(benchmark_actual.wealth, wealth)
    benchmark_return = None if benchmark_path[-1][1] is None else benchmark_path[-1][1] - ONE
    benchmark_metrics = {item.name: item.value for item in report.benchmark.metrics}
    assert_rational(benchmark_metrics["total_return"], benchmark_return)
    bm_drawdown = (
        None
        if any(item[2] is None for item in benchmark_path)
        else max(item[2] for item in benchmark_path if item[2] is not None)
    )
    assert_rational(benchmark_metrics["maximum_drawdown"], bm_drawdown)
    _annual_checks(report, rows, benchmark_path, benchmark_metrics)
    return IndependentSummary(
        navs[-1], net_pnl, total_return, drawdown, fees, turnover, exposure, benchmark_return
    )
