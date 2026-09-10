"""Derived research metrics over immutable accepted engine rows; no accounting replay."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
from decimal import Decimal, localcontext
from itertools import pairwise

from packages.domain.accounting_contracts import ExecutionRow, FifoMatchRow
from packages.domain.models import Side
from packages.domain.personal_contracts import content_digest
from packages.domain.report_contracts import (
    BenchmarkReport,
    BenchmarkRow,
    BenchmarkValuationInput,
    DerivedReturnRow,
    ExternalFlowRow,
    MetricCoverage,
    MetricValue,
    ReportConventions,
    ScoredInterval,
    ValuationRow,
)
from packages.domain.wealth import WealthPoint, WealthValue, derive_wealth_path, derived_context


class ReportInputError(ValueError):
    """Retained report inputs contradict their identities or accepted arithmetic."""


def _sequence(row: ValuationRow) -> int:
    return row.snapshot.point.reduction_sequence


def scored_valuations(
    valuations: tuple[ValuationRow, ...], interval: ScoredInterval
) -> tuple[ValuationRow, ...]:
    """Select the pinned funded baseline through endpoint, retaining flow boundaries."""
    if type(valuations) is not tuple or any(type(row) is not ValuationRow for row in valuations):
        raise ReportInputError("valuation input must contain immutable exact rows")
    if interval.expected_sessions != tuple(sorted(set(interval.expected_sessions))):
        raise ReportInputError("expected sessions must be ordered and unique")
    if interval.warmup_sessions != tuple(sorted(set(interval.warmup_sessions))):
        raise ReportInputError("warmup sessions must be ordered and unique")
    if set(interval.expected_sessions).intersection(interval.warmup_sessions):
        raise ReportInputError("warmup and scored sessions overlap")
    ids = tuple(row.row_id for row in valuations)
    if len(ids) != len(set(ids)):
        raise ReportInputError("valuation IDs must be unique")
    if any(_sequence(b) <= _sequence(a) for a, b in pairwise(valuations)):
        raise ReportInputError("valuation sequences must be strictly increasing")
    if not valuations:
        return ()
    if interval.baseline_valuation_id not in ids:
        raise ReportInputError("valuations omit the pinned baseline")
    start = ids.index(interval.baseline_valuation_id)
    end = (
        ids.index(interval.terminal_valuation_id)
        if interval.terminal_valuation_id in ids
        else len(ids) - 1
    )
    if start > end:
        raise ReportInputError("terminal valuation precedes baseline")
    rows = valuations[start : end + 1]
    if "baseline" not in rows[0].roles or any("baseline" in row.roles for row in rows[1:]):
        raise ReportInputError("scored interval requires one funded baseline")
    if any(row.interval_id != interval.interval_id for row in rows):
        raise ReportInputError("valuation belongs to another scored interval")
    closes = [row.session for row in rows[1:] if row.scored and "daily_close" in row.roles]
    if len(closes) != len(set(closes)) or any(
        day not in interval.expected_sessions for day in closes
    ):
        raise ReportInputError("daily close must uniquely belong to expected scored sessions")
    return rows


def _flow_pairs(
    rows: tuple[ValuationRow, ...], flows: tuple[ExternalFlowRow, ...]
) -> dict[str, ExternalFlowRow]:
    by_id = {row.row_id: row for row in rows}
    selected: dict[str, ExternalFlowRow] = {}
    seen: set[str] = set()
    previous_sequence = -1
    for flow in flows:
        identifier = flow.flow.cash_flow_id
        if identifier in seen or flow.sequence <= previous_sequence:
            raise ReportInputError("flows must be unique and in increasing reduction order")
        seen.add(identifier)
        previous_sequence = flow.sequence
        if flow.origin == "initial_capital":
            if (
                rows
                and flow.post_valuation_id in by_id
                and flow.post_valuation_id != rows[0].row_id
            ):
                raise ReportInputError("initial capital must establish the baseline")
            continue
        pre = by_id.get(flow.pre_valuation_id)
        post = by_id.get(flow.post_valuation_id)
        if pre is None and post is None:
            if rows and _sequence(rows[0]) < flow.sequence <= _sequence(rows[-1]):
                raise ReportInputError("in-interval external flow omits both valuation boundaries")
            continue
        if pre is None or post is None:
            raise ReportInputError("scored interval splits an external flow")
        if not (
            "pre_flow" in pre.roles
            and "post_flow" in post.roles
            and pre.flow_id == post.flow_id == identifier
            and pre.paired_row_id == post.row_id
            and post.paired_row_id == pre.row_id
            and _sequence(pre) < flow.sequence <= _sequence(post)
        ):
            raise ReportInputError("external flow does not bind its ordered valuation pair")
        if pre.economic_at != post.economic_at or pre.economic_at != flow.flow.effective_at:
            raise ReportInputError("external flow valuation has a different economic boundary")
        if (
            pre.snapshot.marks != post.snapshot.marks
            or pre.snapshot.positions != post.snapshot.positions
        ):
            raise ReportInputError("flow pair changes non-flow position or mark facts")
        selected[identifier] = flow
    for row in rows[1:]:
        if ("pre_flow" in row.roles or "post_flow" in row.roles) and row.flow_id not in selected:
            raise ReportInputError("valuation references an absent applied flow")
    return selected


def _nav_reasons(row: ValuationRow) -> tuple[str, ...]:
    reasons = set(row.snapshot.valuation_reasons)
    if row.snapshot.nav is None:
        reasons.add("missing_valuation")
    elif row.snapshot.nav <= 0:
        reasons.add("nonpositive_nav")
    return tuple(sorted(reasons))


def _wealth_points(
    rows: tuple[ValuationRow, ...], flows: tuple[ExternalFlowRow, ...], interval: ScoredInterval
) -> tuple[WealthPoint, ...]:
    pairs = _flow_pairs(rows, flows)
    observed = {r.session for r in rows[1:] if r.scored and "daily_close" in r.roles}
    missing = set(interval.expected_sessions) - observed
    points = []
    for index, row in enumerate(rows):
        role = (
            "baseline"
            if index == 0
            else (
                "pre_flow"
                if "pre_flow" in row.roles
                else "post_flow"
                if "post_flow" in row.roles
                else "valuation"
            )
        )
        reasons = set(_nav_reasons(row))
        # No invented valuation row: invalidate the first real boundary beyond a
        # missing expected close. Exact event-only oracle intervals use no grid.
        if index and any(
            day < row.session or (day == row.session and "terminal" in row.roles) for day in missing
        ):
            reasons.add("missing_expected_session")
        pair = pairs.get(row.flow_id or "")
        points.append(
            WealthPoint(
                row.row_id,
                _sequence(row),
                row.snapshot.nav,
                pair.signed_amount if pair is not None and role == "post_flow" else Decimal(0),
                row.flow_id if role in ("pre_flow", "post_flow") else None,
                role,
                tuple(sorted(reasons)),
            )
        )
    return tuple(points)


def _return_rows(
    rows: tuple[ValuationRow, ...], values: tuple[WealthValue, ...]
) -> tuple[DerivedReturnRow, ...]:
    result = []
    previous_close = values[0].wealth if values else None
    with localcontext(derived_context()):
        for index, (row, value) in enumerate(zip(rows, values, strict=True)):
            daily = index > 0 and row.scored and "daily_close" in row.roles
            period = None if value.growth is None else value.growth - 1
            if daily:
                period = (
                    value.wealth / previous_close - 1
                    if value.wealth is not None and previous_close is not None
                    else None
                )
                previous_close = value.wealth
            result.append(
                DerivedReturnRow(
                    row.row_id,
                    row.session,
                    _sequence(row),
                    value.growth,
                    period,
                    value.wealth,
                    value.drawdown,
                    daily,
                    value.reasons,
                )
            )
    return tuple(result)


def derive_return_path(
    *,
    valuations: tuple[ValuationRow, ...],
    flows: tuple[ExternalFlowRow, ...],
    interval: ScoredInterval,
    conventions: ReportConventions,
) -> tuple[DerivedReturnRow, ...]:
    """Derive event wealth and separately linked daily close returns."""
    del conventions  # The only admitted return/numeric models are frozen literals.
    rows = scored_valuations(valuations, interval)
    if not rows:
        return ()
    try:
        return _return_rows(rows, derive_wealth_path(_wealth_points(rows, flows, interval)))
    except ValueError as error:
        raise ReportInputError(str(error)) from error


def _coverage(
    rows: tuple[ValuationRow, ...],
    returns: tuple[DerivedReturnRow, ...],
    interval: ScoredInterval,
    *,
    input_sha256: str,
    extra_ids: tuple[str, ...] = (),
    sample_count: int | None = None,
) -> MetricCoverage:
    daily = tuple(row for row in rows[1:] if row.scored and "daily_close" in row.roles)
    observed = {row.session for row in daily}
    valid = tuple(row for row in daily if not _nav_reasons(row))
    valid_returns = sum(row.daily_close and row.period_return is not None for row in returns)
    excluded = [(row.valuation_id, row.reasons) for row in returns if row.reasons]
    excluded.extend(
        (f"session:{day.isoformat()}", ("missing_expected_session",))
        for day in interval.expected_sessions
        if day not in observed
    )
    return MetricCoverage(
        interval.interval_id,
        len(interval.expected_sessions),
        len(observed),
        len(valid),
        valid_returns,
        valid_returns if sample_count is None else sample_count,
        input_sha256,
        tuple(row.row_id for row in rows) + extra_ids,
        tuple(excluded),
    )


def _metric(
    name: str,
    value: Decimal | None,
    unit: str,
    coverage: MetricCoverage,
    conventions: ReportConventions,
    reasons: tuple[str, ...] = (),
    assumptions: tuple[str, ...] = (),
) -> MetricValue:
    return MetricValue(
        name,
        value,
        unit,
        "undefined" if value is None else "defined",
        coverage,
        conventions.semantic_sha256,
        tuple(sorted(set(reasons))) if value is None else (),
        assumptions,
    )


def _performance(
    returns: tuple[DerivedReturnRow, ...],
    coverage: MetricCoverage,
    conventions: ReportConventions,
    *,
    complete_endpoint: bool,
) -> tuple[MetricValue, ...]:
    reasons = {reason for row in returns for reason in row.reasons}
    if not returns:
        reasons.add("missing_baseline")
    if not complete_endpoint:
        reasons.add("missing_terminal_valuation")
    if coverage.observed_sessions < coverage.expected_sessions:
        reasons.add("missing_expected_session")
    complete = bool(returns) and not reasons and complete_endpoint
    wealth = returns[-1].wealth if returns else None
    with localcontext(derived_context()):
        total = wealth - 1 if complete and wealth is not None else None
        drawdowns = [r.drawdown for r in returns if r.drawdown is not None]
        max_drawdown = max(drawdowns) if complete and drawdowns else None
        values = [r.period_return for r in returns if r.daily_close and r.period_return is not None]
        annual_reasons = set(reasons)
        if len(values) < conventions.minimum_annualized_sessions:
            annual_reasons.add("insufficient_scored_sessions")
        if len(values) != coverage.expected_sessions:
            annual_reasons.add("incomplete_return_path")
        annual = volatility = sharpe = sortino = None
        sharpe_reasons = set(annual_reasons)
        sortino_reasons = set(annual_reasons)
        if not annual_reasons and wealth is not None:
            n = Decimal(len(values))
            periods = Decimal(conventions.annualization_sessions)
            annual = wealth ** (periods / n) - 1
            mean = sum(values, Decimal(0)) / n
            variance = sum(((value - mean) ** 2 for value in values), Decimal(0)) / (n - 1)
            volatility = variance.sqrt() * periods.sqrt()
            if variance == 0:
                sharpe_reasons.add("zero_variance")
                sortino_reasons.add("zero_variance")
            if conventions.risk_free_daily is None:
                sharpe_reasons.add("missing_risk_free_input")
                sortino_reasons.add("missing_risk_free_input")
            else:
                excess = [value - conventions.risk_free_daily for value in values]
                excess_mean = sum(excess, Decimal(0)) / n
                downside = sum((min(value, Decimal(0)) ** 2 for value in excess), Decimal(0)) / n
                if not sharpe_reasons:
                    sharpe = periods.sqrt() * excess_mean / variance.sqrt()
                if downside == 0:
                    sortino_reasons.add("zero_downside_deviation")
                if not sortino_reasons:
                    sortino = periods.sqrt() * excess_mean / downside.sqrt()
        return (
            _metric(
                "total_return",
                total,
                "fraction",
                coverage,
                conventions,
                tuple(reasons or {"incomplete_return_path"}),
            ),
            _metric(
                "maximum_drawdown",
                max_drawdown,
                "fraction",
                coverage,
                conventions,
                tuple(reasons or {"incomplete_return_path"}),
            ),
            _metric(
                "annualized_return",
                annual,
                "fraction_per_year",
                coverage,
                conventions,
                tuple(annual_reasons),
            ),
            _metric(
                "annualized_volatility",
                volatility,
                "fraction_per_sqrt_year",
                coverage,
                conventions,
                tuple(annual_reasons),
            ),
            _metric(
                "sharpe_ratio",
                sharpe,
                "ratio",
                coverage,
                conventions,
                tuple(sharpe_reasons),
                (conventions.risk_free_model,),
            ),
            _metric(
                "sortino_ratio",
                sortino,
                "ratio",
                coverage,
                conventions,
                tuple(sortino_reasons),
                (conventions.risk_free_model, conventions.sortino_model),
            ),
        )


def _effective_rows(
    executions: tuple[ExecutionRow, ...], matches: tuple[FifoMatchRow, ...]
) -> None:
    by_id = {row.execution_id: row for row in executions}
    if len(by_id) != len(executions) or len({r.fact_id for r in executions}) != len(executions):
        raise ReportInputError("executions must be unique effective heads")
    if len({row.match_id for row in matches}) != len(matches):
        raise ReportInputError("FIFO matches must be unique effective rows")
    allocated: dict[str, Decimal] = defaultdict(Decimal)
    group_status: dict[str, bool] = {}
    with localcontext(derived_context()):
        for row in executions:
            if row.quantity < 0 or row.fee < 0 or row.price <= 0 or row.revision < 1:
                raise ReportInputError("invalid effective execution economics")
        for match in matches:
            opening, closing = (
                by_id.get(match.opening_execution_id),
                by_id.get(match.closing_execution_id),
            )
            if (
                opening is None
                or closing is None
                or (
                    opening.revision != match.opening_revision
                    or closing.revision != match.closing_revision
                    or opening.side is not Side.BUY
                    or closing.side is not Side.SELL
                    or opening.order_id != match.opening_order_id
                    or closing.order_id != match.closing_order_id
                    or opening.instrument_id != closing.instrument_id
                    or match.instrument_id != opening.instrument_id
                )
            ):
                raise ReportInputError("FIFO match is not bound to effective executions")
            if (
                match.quantity <= 0
                or min(match.basis, match.proceeds, match.opening_fee, match.closing_fee) < 0
            ):
                raise ReportInputError("invalid FIFO matched amounts")
            previous = group_status.setdefault(match.closing_order_id, match.group_complete)
            if previous != match.group_complete:
                raise ReportInputError("FIFO closing group has contradictory completion states")
            allocated[opening.execution_id] += match.opening_fee
            allocated[closing.execution_id] += match.closing_fee
        for identifier, amount in allocated.items():
            if amount > by_id[identifier].fee and amount - by_id[identifier].fee > Decimal("1E-60"):
                raise ReportInputError("FIFO fee allocation exceeds execution fee")


def derive_metrics(
    *,
    valuations: tuple[ValuationRow, ...],
    flows: tuple[ExternalFlowRow, ...],
    executions: tuple[ExecutionRow, ...],
    fifo_matches: tuple[FifoMatchRow, ...],
    returns: tuple[DerivedReturnRow, ...],
    interval: ScoredInterval,
    conventions: ReportConventions,
) -> tuple[MetricValue, ...]:
    """Derive metrics from supplied effective economics, without creating accounting facts."""
    rows = scored_valuations(valuations, interval)
    if returns != derive_return_path(
        valuations=valuations, flows=flows, interval=interval, conventions=conventions
    ):
        raise ReportInputError("return rows differ from their bound valuation path")
    _effective_rows(executions, fifo_matches)
    pairs = _flow_pairs(rows, flows)
    digest = content_digest((rows, tuple(pairs.values()), executions, fifo_matches, interval))
    coverage = _coverage(
        rows,
        returns,
        interval,
        input_sha256=digest,
        extra_ids=tuple(r.fact_id for r in executions) + tuple(r.match_id for r in fifo_matches),
    )
    complete_endpoint = bool(rows) and rows[-1].row_id == interval.terminal_valuation_id
    result = list(_performance(returns, coverage, conventions, complete_endpoint=complete_endpoint))
    missing = ("missing_baseline",) if not rows else ("missing_terminal_valuation",)
    baseline = rows[0].snapshot if rows else None
    terminal = rows[-1].snapshot if complete_endpoint else None
    with localcontext(derived_context()):

        def emit(
            name: str,
            value: Decimal | None,
            unit: str = "USD",
            reasons: tuple[str, ...] = missing,
            *,
            metric_coverage: MetricCoverage = coverage,
            assumptions: tuple[str, ...] = (),
        ) -> None:
            result.append(
                _metric(name, value, unit, metric_coverage, conventions, reasons, assumptions)
            )

        start_nav = (
            baseline.nav if baseline is not None and not baseline.valuation_reasons else None
        )
        end_nav = terminal.nav if terminal is not None and not terminal.valuation_reasons else None
        emit(
            "starting_equity",
            start_nav,
            reasons=rows[0].snapshot.valuation_reasons or ("missing_valuation",)
            if rows
            else missing,
        )
        emit(
            "ending_equity",
            end_nav,
            reasons=terminal.valuation_reasons or ("missing_valuation",) if terminal else missing,
        )
        net_flow = sum((f.signed_amount for f in pairs.values()), Decimal(0))
        if (
            baseline is not None
            and terminal is not None
            and terminal.net_external_flow - baseline.net_external_flow != net_flow
        ):
            raise ReportInputError("external flow rows differ from accepted capital change")
        emit(
            "net_external_flow", net_flow if baseline is not None and terminal is not None else None
        )
        emit(
            "net_pnl",
            end_nav - start_nav - net_flow
            if end_nav is not None and start_nav is not None
            else None,
            reasons=tuple(
                sorted(
                    set(
                        (baseline.valuation_reasons if baseline else missing)
                        + (terminal.valuation_reasons if terminal else missing)
                    )
                )
            )
            or ("missing_valuation",),
        )
        for name, field in (
            ("gross_realized_pnl", "gross_realized_pnl"),
            ("total_execution_costs", "fees"),
            ("dividend_income", "dividend_income"),
            ("unrealized_pnl", "unrealized_pnl"),
        ):
            start = getattr(baseline, field) if baseline else None
            end = getattr(terminal, field) if terminal else None
            emit(
                name,
                end - start if start is not None and end is not None else None,
                reasons=("missing_valuation",) if baseline and terminal else missing,
            )
        realized = (
            None
            if baseline is None or terminal is None
            else (
                terminal.gross_realized_pnl
                - terminal.fees
                + terminal.dividend_income
                - baseline.gross_realized_pnl
                + baseline.fees
                - baseline.dividend_income
            )
        )
        emit("realized_pnl", realized)
        for field in (
            "trade_date_cash",
            "settled_cash",
            "available_cash",
            "dividend_receivable",
            "market_value",
        ):
            emit(
                "ending_" + field,
                getattr(terminal, field) if terminal else None,
                reasons=("missing_valuation",) if terminal else missing,
            )
        daily = [
            r for r in rows[1:] if r.scored and "daily_close" in r.roles and not _nav_reasons(r)
        ]
        daily_coverage = replace(coverage, sample_count=len(daily))
        low = _sequence(rows[0]) if rows else 0
        high = _sequence(rows[-1]) if rows else -1
        scored_executions = tuple(e for e in executions if low < e.sequence <= high)
        mean_nav = (
            sum((r.snapshot.nav for r in daily if r.snapshot.nav is not None), Decimal(0))
            / Decimal(len(daily))
            if daily
            else None
        )
        turnover = (
            sum((e.quantity * e.price for e in scored_executions), Decimal(0)) / mean_nav
            if mean_nav is not None and mean_nav > 0
            else None
        )
        emit(
            "turnover",
            turnover,
            "ratio",
            ("no_valid_daily_nav",),
            metric_coverage=daily_coverage,
            assumptions=(conventions.turnover_model,),
        )
        exposure_rows = [r for r in daily if r.snapshot.market_value is not None]
        exposure = (
            sum(
                (
                    r.snapshot.market_value / r.snapshot.nav
                    for r in exposure_rows
                    if r.snapshot.market_value is not None and r.snapshot.nav is not None
                ),
                Decimal(0),
            )
            / Decimal(len(exposure_rows))
            if exposure_rows
            else None
        )
        for name in ("average_gross_exposure", "average_net_exposure"):
            emit(
                name,
                exposure,
                "fraction",
                ("no_valid_daily_nav",),
                metric_coverage=replace(coverage, sample_count=len(exposure_rows)),
                assumptions=("long-only-mean-daily-securities-over-nav-v1",),
            )
        groups: dict[str, Decimal] = defaultdict(Decimal)
        execution_map = {e.execution_id: e for e in executions}
        for match in fifo_matches:
            if (
                match.group_complete
                and low < execution_map[match.closing_execution_id].sequence <= high
            ):
                groups[match.closing_order_id] += (
                    match.proceeds - match.basis - match.opening_fee - match.closing_fee
                )
        trade_coverage = replace(coverage, sample_count=len(groups))
        wins = sum(value > 0 for value in groups.values())
        losses = sum(value < 0 for value in groups.values())
        for name, count in (
            ("trade_count", len(groups)),
            ("winning_trade_count", wins),
            ("losing_trade_count", losses),
            ("breakeven_trade_count", len(groups) - wins - losses),
        ):
            emit(name, Decimal(count), "count", metric_coverage=trade_coverage)
        emit(
            "closed_trade_net_pnl", sum(groups.values(), Decimal(0)), metric_coverage=trade_coverage
        )
        emit(
            "hit_rate",
            Decimal(wins) / Decimal(len(groups)) if groups else None,
            "fraction",
            ("no_completed_trades",),
            metric_coverage=trade_coverage,
        )
        losing_amount = sum((-v for v in groups.values() if v < 0), Decimal(0))
        winning_amount = sum((v for v in groups.values() if v > 0), Decimal(0))
        emit(
            "profit_factor",
            winning_amount / losing_amount if losing_amount > 0 else None,
            "ratio",
            ("no_completed_trades",) if not groups else ("zero_loss_denominator",),
            metric_coverage=trade_coverage,
        )
        emit("capacity_proxy", None, "USD", ("method_not_qualified",))
        emit("confidence_interval", None, "fraction", ("method_not_qualified",))
    return tuple(result)


def derive_benchmark(
    *,
    inputs: tuple[BenchmarkValuationInput, ...],
    valuations: tuple[ValuationRow, ...],
    flows: tuple[ExternalFlowRow, ...],
    interval: ScoredInterval,
    conventions: ReportConventions,
) -> BenchmarkReport:
    """Analytical fractional SPY and idle cash on exactly the strategy flow clock."""
    rows = scored_valuations(valuations, interval)
    pairs = _flow_pairs(rows, flows)
    by_id = {item.valuation_id: item for item in inputs}
    known_inputs = tuple(item for item in inputs if item.unit_price is not None)
    if (
        len(by_id) != len(inputs)
        or len({item.series_id for item in known_inputs}) > 1
        or len({item.representation for item in known_inputs}) > 1
    ):
        raise ReportInputError("benchmark inputs must be unique and use one series/representation")
    unknown = set(by_id) - {row.row_id for row in valuations}
    if unknown:
        raise ReportInputError("benchmark input references an unknown valuation")
    base_points = _wealth_points(rows, flows, interval) if rows else ()
    benchmark_points = []
    cash_points = []
    benchmark_rows = []
    cash_rows = []
    blocked: set[str] = set()
    units = nav = cash = None
    anchor_nav = anchor_price = None
    with localcontext(derived_context()):
        for index, (row, original) in enumerate(zip(rows, base_points, strict=True)):
            item = by_id.get(row.row_id)
            reasons: set[str] = set()
            if item is None or item.unit_price is None:
                reasons.add("missing_benchmark_mark")
            elif (
                item.economic_at != row.economic_at
                or item.knowledge_at > row.snapshot.point.knowledge_at
            ):
                raise ReportInputError("benchmark mark differs from causal valuation boundary")
            if item is not None:
                reasons.update(item.reasons)
            if index == 0:
                cash = row.snapshot.nav if not _nav_reasons(row) else None
                if cash is None:
                    reasons.add("missing_baseline")
                nav = cash
                units = (
                    nav / item.unit_price
                    if nav is not None
                    and item is not None
                    and item.unit_price is not None
                    and not reasons
                    else None
                )
                if units is not None and item is not None:
                    anchor_nav, anchor_price = nav, item.unit_price
            elif original.role == "post_flow":
                cash = cash + original.signed_flow if cash is not None else None
                pre_item = by_id.get(rows[index - 1].row_id)
                if (
                    item is not None
                    and pre_item is not None
                    and item.unit_price is not None
                    and pre_item.unit_price is not None
                    and item.unit_price != pre_item.unit_price
                ):
                    raise ReportInputError("benchmark price changes within an atomic flow pair")
                if nav is not None and not reasons and not blocked:
                    nav = nav + original.signed_flow
                    if nav <= 0:
                        reasons.add(
                            "benchmark_withdrawal_exceeds_value" if nav < 0 else "nonpositive_nav"
                        )
                    units = (
                        nav / item.unit_price
                        if item is not None and item.unit_price is not None
                        else None
                    )
                    anchor_nav = nav
                    anchor_price = item.unit_price if item is not None else None
            elif (
                units is not None
                and item is not None
                and item.unit_price is not None
                and not reasons
                and not blocked
            ):
                assert anchor_nav is not None and anchor_price is not None
                # Delay division until after multiplying the new unit price.
                # Rounding displayed fractional units first can turn the exact
                # E4 value 1760 into 1760 + 1e-60. The flow anchor is report math,
                # not an account lot or a new execution/accounting transition.
                nav = anchor_nav * item.unit_price / anchor_price
            blocked.update(reasons)
            if blocked:
                nav = units = None
            # Strategy mark gaps do not invalidate independently available
            # comparator marks, but missing expected sessions invalidate both.
            clock_reasons = tuple(
                reason for reason in original.reasons if reason == "missing_expected_session"
            )
            benchmark_reason = tuple(sorted(blocked.union(clock_reasons)))
            cash_reasons = clock_reasons + (("missing_baseline",) if cash is None else ())
            benchmark_points.append(replace(original, nav=nav, reasons=benchmark_reason))
            cash_points.append(replace(original, nav=cash, reasons=cash_reasons))
            benchmark_rows.append(
                BenchmarkRow(row.row_id, nav, units, original.signed_flow, None, benchmark_reason)
            )
            cash_rows.append(
                BenchmarkRow(row.row_id, cash, None, original.signed_flow, None, cash_reasons)
            )
    benchmark_values = derive_wealth_path(tuple(benchmark_points)) if benchmark_points else ()
    cash_values = derive_wealth_path(tuple(cash_points)) if cash_points else ()
    benchmark_returns = _return_rows(rows, benchmark_values)
    cash_returns = _return_rows(rows, cash_values)
    series_hash = content_digest(inputs)

    # Coverage of each comparator uses its own known NAVs, not strategy marks.
    def comparator_coverage(
        points: list[WealthPoint], path: tuple[DerivedReturnRow, ...]
    ) -> MetricCoverage:
        shadow = tuple(
            replace(row, snapshot=replace(row.snapshot, nav=p.nav, valuation_reasons=p.reasons))
            for row, p in zip(rows, points, strict=True)
        )
        return _coverage(
            shadow,
            path,
            interval,
            input_sha256=content_digest(
                (series_hash, tuple(pairs.values()), interval, tuple(points))
            ),
        )

    complete = bool(rows) and rows[-1].row_id == interval.terminal_valuation_id
    bm_coverage = comparator_coverage(benchmark_points, benchmark_returns)
    cash_coverage = comparator_coverage(cash_points, cash_returns)
    bm_metrics = _performance(
        benchmark_returns, bm_coverage, conventions, complete_endpoint=complete
    )
    cash_metrics = _performance(
        cash_returns, cash_coverage, conventions, complete_endpoint=complete
    )
    assumptions = (
        conventions.benchmark_model,
        "fractional-analytical-units",
        "zero-analytical-fees",
        *(tuple({item.representation for item in inputs})),
    )
    return BenchmarkReport(
        conventions.benchmark_model,
        series_hash,
        tuple(
            replace(row, wealth=value.wealth, reasons=value.reasons)
            for row, value in zip(benchmark_rows, benchmark_values, strict=True)
        ),
        tuple(
            replace(row, wealth=value.wealth, reasons=value.reasons)
            for row, value in zip(cash_rows, cash_values, strict=True)
        ),
        tuple(
            replace(m, assumptions=tuple(sorted(set(m.assumptions + assumptions))))
            for m in bm_metrics
        ),
        tuple(
            replace(
                m,
                assumptions=tuple(sorted({*m.assumptions, "idle-cash-assumed-zero-interest-v1"})),
            )
            for m in cash_metrics
        ),
        tuple(pairs),
        tuple(sorted(blocked)),
    )
