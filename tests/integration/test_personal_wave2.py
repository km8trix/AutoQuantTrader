"""Actual A+B+C replay and independent rational acceptance, with no services."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, Inexact, localcontext
from fractions import Fraction
from math import prod
from typing import Literal

import pytest

from packages.application.causal_engine import run_causal_engine
from packages.application.personal_inputs import synthetic_engine_inputs
from packages.application.reference_strategy import ReferenceStrategy
from packages.application.run_report import build_report_artifact, build_run_report
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.engine_contracts import EngineInputs
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.domain.report_contracts import EngineResult, ReportConventions, RunReport
from tests.helpers.personal_flow_oracles import NoTarget, flow_inputs
from tests.helpers.personal_report_oracle import (
    assert_rational,
    independent_annual_statistics,
    verify_personal_report,
)

PINS = tuple(
    VersionPin(name, "personal-report/2" if name == "report" else "integration-oracle/1", "a" * 64)
    for name in sorted(
        (
            "engine",
            "source",
            "dependency_lock",
            "tzdata",
            "availability",
            "actions",
            "numeric",
            "benchmark",
            "report",
            "dirty_patch",
        )
    )
)


def _inputs(fixture: Literal["flat", "regime"], kind: str) -> EngineInputs:
    return synthetic_engine_inputs(
        fixture=fixture,
        pins=PINS,
        configuration=ReferenceConfiguration(kind=kind, lookback=3),
        session_count=12,
        warmup_count=3,
    )


def _reference(inputs: EngineInputs) -> tuple[EngineResult, RunReport]:
    result = run_causal_engine(
        inputs, accounting=PersonalAccounting(), strategy=ReferenceStrategy()
    )
    assert result.status == "completed", result.reasons
    report = build_run_report(result, ReportConventions())
    return result, report


@pytest.mark.parametrize("fixture", ["flat", "regime"])
@pytest.mark.parametrize("kind", ["buy_hold", "trend_sma"])
def test_two_reference_strategies_on_two_labelled_datasets(
    fixture: Literal["flat", "regime"],
    kind: str,
) -> None:
    inputs = _inputs(fixture, kind)
    result, report = _reference(inputs)
    verified = verify_personal_report(result, report)
    assert len(result.interval.expected_sessions) == 9
    assert report.status == "completed"
    assert report.source.spec.data_class.value == "synthetic_fixture"
    assert "insufficient_scored_sessions_for_annualization" in report.limitations
    metrics = {item.name: item for item in report.metrics}
    for name in ("annualized_return", "annualized_volatility", "sharpe_ratio", "sortino_ratio"):
        assert metrics[name].status == "undefined" and metrics[name].value is None
        assert "insufficient_scored_sessions" in metrics[name].reasons
    if fixture == "flat" and kind == "buy_hold":
        assert verified.final_nav == Fraction(999856, 100)
        assert verified.net_pnl == Fraction(-144, 100)
        assert verified.total_return == Fraction(-144, 1_000_000)
        assert verified.fees == Fraction(24, 100)
        assert result.final_snapshot.positions[0].quantity == Decimal(24)
    if fixture == "flat" and kind == "trend_sma":
        assert verified.final_nav == 10000 and verified.total_return == 0
        assert verified.fees == 0 and not result.executions
    if fixture == "regime" and kind == "trend_sma":
        assert {fill.side.value for fill in result.executions} == {"buy", "sell"}
        assert result.fifo_matches
        assert verified.maximum_drawdown is not None and verified.maximum_drawdown > 0


def test_data_configuration_and_run_identities_remain_distinct() -> None:
    fixtures: tuple[Literal["flat", "regime"], ...] = ("flat", "regime")
    values = tuple(
        _inputs(fixture, kind) for fixture in fixtures for kind in ("buy_hold", "trend_sma")
    )
    assert len({value.spec.run_id for value in values}) == 4
    assert len({value.spec.dataset_sha256 for value in values}) == 2
    assert len({content_digest(value.spec.strategy_configuration) for value in values}) == 2
    original = values[0]
    tightened = replace(
        original.spec,
        risk_policy=replace(original.spec.risk_policy, max_order_quantity=Decimal(50)),
    )
    changed_cost = replace(
        original.spec,
        execution_policy=replace(original.spec.execution_policy, slippage_bps=Decimal(6)),
    )
    changed_lookback = replace(
        original.spec,
        strategy_configuration=replace(original.spec.strategy_configuration, lookback=4),
    )
    assert (
        len({original.spec.run_id, tightened.run_id, changed_cost.run_id, changed_lookback.run_id})
        == 4
    )


@pytest.mark.parametrize("kind", ["contribution", "withdrawal", "missing-mark"])
def test_actual_flow_oracles_neutralize_deposit_and_withdrawal_and_preserve_unknown(
    kind: Literal["contribution", "withdrawal", "missing-mark"],
) -> None:
    inputs = flow_inputs(kind, pins=PINS)
    result = run_causal_engine(inputs, accounting=PersonalAccounting(), strategy=NoTarget())
    assert result.status == "completed", result.reasons
    report = build_run_report(result, ReportConventions())
    verified = verify_personal_report(result, report)
    assert verified.fees == 0
    assert verified.benchmark_total_return == Fraction(21, 100)
    boundaries = [
        row for row in result.valuations if "pre_flow" in row.roles or "post_flow" in row.roles
    ]
    assert len(boundaries) == 2
    assert len(result.flows) == 1 and result.flows[0].origin == "external_flow"
    assert inputs.spec.initial_cash == 0  # The actual accounting seed is never funded twice.
    if kind == "missing-mark":
        assert verified.total_return is None and verified.maximum_drawdown is None
        assert all(
            row.snapshot.nav is None and row.snapshot.valuation_reasons for row in boundaries
        )
    else:
        assert verified.total_return == Fraction(21, 100)
        assert verified.maximum_drawdown == 0
        assert boundaries[0].snapshot.nav == Decimal(1100)
        assert boundaries[1].snapshot.nav == Decimal(1600 if kind == "contribution" else 900)
        assert verified.final_nav == (1760 if kind == "contribution" else 990)
        assert verified.net_pnl == (260 if kind == "contribution" else 190)


def test_artifact_attempt_metadata_does_not_change_semantic_run_or_report() -> None:
    result, report = _reference(_inputs("flat", "buy_hold"))
    at = datetime(2025, 1, 1, tzinfo=UTC)
    first = build_report_artifact(report, attempt_id="independent-attempt-one", generated_at=at)
    second = build_report_artifact(
        report, attempt_id="independent-attempt-two", generated_at=at + timedelta(seconds=1)
    )
    assert first.semantic_sha256 != second.semantic_sha256
    assert first.report.semantic_sha256 == second.report.semantic_sha256
    assert first.report.run_id == second.report.run_id == result.spec.run_id


def test_independent_verifier_detects_report_metric_not_supported_by_facts() -> None:
    result, report = _reference(_inputs("flat", "buy_hold"))
    changed = tuple(
        replace(metric, value=Decimal(10000)) if metric.name == "ending_equity" else metric
        for metric in report.metrics
    )
    with pytest.raises(AssertionError):
        verify_personal_report(result, replace(report, metrics=changed))


def test_annual_oracle_has_closed_form_volatility_sharpe_and_all_sample_sortino() -> None:
    # One -r return and 251 +2r returns give sample variance (3r)^2/252.
    # Thus annual volatility=3r, Sharpe=167 and all-sample Sortino=501.
    r = Fraction(1, 10000)
    returns = (-r, *(2 * r for _ in range(251)))
    wealth = prod((1 + value for value in returns), start=Fraction(1))
    with localcontext() as ambient:
        ambient.prec = 2
        ambient.traps[Inexact] = True
        values = independent_annual_statistics(returns, wealth)
    assert_rational(values["annualized_volatility"], 3 * r)
    assert_rational(values["sharpe_ratio"], Fraction(167))
    assert_rational(values["sortino_ratio"], Fraction(501))
    assert_rational(values["annualized_return"], wealth - 1)


def test_annual_oracle_fractional_year_power_uses_independent_eighty_digits() -> None:
    returns = (Fraction(21, 100), *(Fraction(0) for _ in range(503)))
    values = independent_annual_statistics(returns, Fraction(121, 100))
    assert_rational(values["annualized_return"], Fraction(1, 10))


@pytest.mark.parametrize("daily", [Fraction(0), Fraction(1, 10000), Fraction(-1, 10000)])
def test_zero_variance_never_produces_sharpe_or_sortino_even_with_downside(daily: Fraction) -> None:
    values = independent_annual_statistics((daily,) * 252, (1 + daily) ** 252)
    assert values["annualized_volatility"] == 0
    assert values["sharpe_ratio"] is None and values["sortino_ratio"] is None


def test_annual_oracle_preserves_insufficient_missing_and_risk_free_undefined_states() -> None:
    assert all(
        value is None
        for value in independent_annual_statistics((Fraction(0),) * 251, Fraction(1)).values()
    )
    assert all(
        value is None
        for value in independent_annual_statistics((None, *((Fraction(0),) * 251)), None).values()
    )
    returns = (Fraction(-1, 10000), *((Fraction(2, 10000),) * 251))
    wealth = prod((1 + value for value in returns), start=Fraction(1))
    values = independent_annual_statistics(returns, wealth, risk_free_daily=None)
    assert values["annualized_return"] is not None and values["annualized_volatility"] is not None
    assert values["sharpe_ratio"] is None and values["sortino_ratio"] is None
