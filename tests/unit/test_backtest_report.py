from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext

import pytest

from packages.domain.backtest_report import (
    NOT_APPLICABLE,
    BacktestContractPins,
    BacktestEquityPoint,
    BacktestLedgerTraceEntry,
    BacktestMetricConventions,
    BacktestMetrics,
    BacktestPosition,
    BacktestReport,
    BacktestReturnFrequency,
    BacktestReturnType,
    BacktestRunManifest,
    BacktestRunResult,
    BacktestRunStatus,
    BacktestRuntimePin,
    BacktestTrade,
    BenchmarkPin,
    DatasetReplayPin,
    ExternalCashFlowTreatment,
    SimulationModelKind,
    SimulationModelPin,
    StrategyRunPin,
    UncertaintyMethod,
)

PERIOD_START = datetime(2026, 7, 15, 13, 31, tzinfo=UTC)
BUY_TIME = PERIOD_START + timedelta(minutes=1)
ACTION_TIME = PERIOD_START + timedelta(minutes=3)
PERIOD_END = PERIOD_START + timedelta(minutes=5)
GENERATED_AT = PERIOD_END + timedelta(minutes=1)
RUN_STARTED_AT = PERIOD_START - timedelta(minutes=1)
RUN_COMPLETED_AT = GENERATED_AT + timedelta(minutes=1)


def _amount(value: str, *, scaled: bool) -> Decimal:
    if not scaled:
        return Decimal(value)
    return Decimal(f"{value}0" if "." in value else f"{value}.0")


def conventions(*, scaled: bool = False) -> BacktestMetricConventions:
    return BacktestMetricConventions(
        convention_id="fixture-event-metrics",
        convention_version="1.0.0",
        currency="USD",
        return_type=BacktestReturnType.SIMPLE,
        return_frequency=BacktestReturnFrequency.EVENT,
        annualization_periods=252,
        annual_risk_free_rate=_amount("0", scaled=scaled),
        risk_free_rate_version="fixture-zero-v1",
        external_cash_flow_treatment=ExternalCashFlowTreatment.EXCLUDED_FROM_RETURN,
        uncertainty_method=UncertaintyMethod.NONE,
        absolute_tolerance=_amount("0.0000000001", scaled=False),
        relative_tolerance=_amount("0", scaled=scaled),
    )


def equity_curve(*, scaled: bool = False) -> tuple[BacktestEquityPoint, ...]:
    def amount(value: str) -> Decimal:
        return _amount(value, scaled=scaled)

    return (
        BacktestEquityPoint(
            sequence=0,
            as_of=PERIOD_START,
            cash=amount("1000"),
            market_value=amount("0"),
            equity=amount("1000"),
            gross_exposure=amount("0"),
            net_exposure=amount("0"),
            cumulative_external_cash_flow=amount("1000"),
            period_return=amount("0"),
            cumulative_return=amount("0"),
            drawdown=amount("0"),
        ),
        BacktestEquityPoint(
            sequence=1,
            as_of=BUY_TIME,
            cash=amount("595.18"),
            market_value=amount("404"),
            equity=amount("999.18"),
            gross_exposure=amount("404"),
            net_exposure=amount("404"),
            cumulative_external_cash_flow=amount("1000"),
            period_return=amount("-0.00082"),
            cumulative_return=amount("-0.00082"),
            drawdown=amount("0.00082"),
        ),
        BacktestEquityPoint(
            sequence=2,
            as_of=ACTION_TIME,
            cash=amount("605.18"),
            market_value=amount("424"),
            equity=amount("1029.18"),
            gross_exposure=amount("424"),
            net_exposure=amount("424"),
            cumulative_external_cash_flow=amount("1000"),
            period_return=amount("0.0300246202"),
            cumulative_return=amount("0.02918"),
            drawdown=amount("0"),
        ),
        BacktestEquityPoint(
            sequence=3,
            as_of=PERIOD_END,
            cash=amount("1044.04"),
            market_value=amount("0"),
            equity=amount("1044.04"),
            gross_exposure=amount("0"),
            net_exposure=amount("0"),
            cumulative_external_cash_flow=amount("1000"),
            period_return=amount("0.0144386793"),
            cumulative_return=amount("0.04404"),
            drawdown=amount("0"),
        ),
    )


def trades(*, scaled: bool = False) -> tuple[BacktestTrade, ...]:
    def amount(value: str) -> Decimal:
        return _amount(value, scaled=scaled)

    return (
        BacktestTrade(
            sequence=0,
            trade_id="spy-round-trip",
            instrument_id="US-ETF-SPY",
            symbol="SPY",
            opened_at=BUY_TIME,
            closed_at=PERIOD_END,
            quantity=amount("8"),
            cost_basis=amount("404.28"),
            proceeds=amount("439.44"),
            gross_pnl=amount("35.16"),
            execution_costs=amount("1.12"),
            net_pnl=amount("34.04"),
            opening_execution_sha256="1" * 64,
            closing_execution_sha256="2" * 64,
        ),
    )


def positions(*, scaled: bool = False) -> tuple[BacktestPosition, ...]:
    def amount(value: str) -> Decimal:
        return _amount(value, scaled=scaled)

    return (
        BacktestPosition(
            sequence=0,
            as_of=BUY_TIME,
            instrument_id="US-ETF-SPY",
            symbol="SPY",
            quantity=amount("4"),
            cost_basis=amount("404.28"),
            mark_price=amount("101"),
            market_value=amount("404"),
            realized_pnl=amount("-0.54"),
            unrealized_pnl=amount("-0.28"),
            execution_costs=amount("0.54"),
            dividend_income=amount("0"),
            source_projection_sha256="3" * 64,
        ),
        BacktestPosition(
            sequence=1,
            as_of=ACTION_TIME,
            instrument_id="US-ETF-SPY",
            symbol="SPY",
            quantity=amount("8"),
            cost_basis=amount("404.28"),
            mark_price=amount("53"),
            market_value=amount("424"),
            realized_pnl=amount("9.46"),
            unrealized_pnl=amount("19.72"),
            execution_costs=amount("0.54"),
            dividend_income=amount("10"),
            source_projection_sha256="4" * 64,
        ),
        BacktestPosition(
            sequence=2,
            as_of=PERIOD_END,
            instrument_id="US-ETF-SPY",
            symbol="SPY",
            quantity=amount("0"),
            cost_basis=amount("0"),
            mark_price=amount("55"),
            market_value=amount("0"),
            realized_pnl=amount("44.04"),
            unrealized_pnl=amount("0"),
            execution_costs=amount("1.12"),
            dividend_income=amount("10"),
            source_projection_sha256="5" * 64,
        ),
    )


def ledger_trace() -> tuple[BacktestLedgerTraceEntry, ...]:
    facts = (
        ("contribution", "funding", PERIOD_START, "6"),
        ("buy-fill", "execution", BUY_TIME, "7"),
        ("split", "stock_split", BUY_TIME + timedelta(seconds=30), "8"),
        ("dividend", "dividend_payment", ACTION_TIME, "9"),
        ("sell-fill", "execution", PERIOD_END, "a"),
    )
    return tuple(
        BacktestLedgerTraceEntry(
            sequence=sequence,
            entry_id=f"entry-{entry_id}",
            entry_kind=entry_kind,
            source_fact_id=f"fact-{entry_id}",
            effective_at=effective_at,
            recorded_at=effective_at + timedelta(seconds=1),
            entry_sha256=character * 64,
        )
        for sequence, (entry_id, entry_kind, effective_at, character) in enumerate(facts)
    )


def metrics(*, scaled: bool = False) -> BacktestMetrics:
    def amount(value: str) -> Decimal:
        return _amount(value, scaled=scaled)

    return BacktestMetrics(
        starting_equity=amount("1000"),
        ending_equity=amount("1044.04"),
        total_return=amount("0.04404"),
        annualized_return=None,
        annualized_volatility=None,
        sharpe_ratio=None,
        sortino_ratio=None,
        maximum_drawdown=amount("0.00082"),
        turnover=amount("0.84372"),
        average_gross_exposure=amount("207"),
        average_net_exposure=amount("207"),
        trade_count=1,
        winning_trade_count=1,
        losing_trade_count=0,
        breakeven_trade_count=0,
        hit_rate=amount("1"),
        profit_factor=None,
        total_execution_costs=amount("1.12"),
        capacity_proxy=None,
        realized_pnl=amount("44.04"),
        unrealized_pnl=amount("0"),
        dividend_income=amount("10"),
    )


def golden_report(*, scaled: bool = False) -> BacktestReport:
    return BacktestReport(
        account_id="fixture-account",
        currency="USD",
        period_start=PERIOD_START,
        period_end=PERIOD_END,
        generated_at=GENERATED_AT,
        conventions=conventions(scaled=scaled),
        equity_curve=equity_curve(scaled=scaled),
        trades=trades(scaled=scaled),
        positions=positions(scaled=scaled),
        ledger_trace=ledger_trace(),
        metrics=metrics(scaled=scaled),
        execution_ledger_sha256="b" * 64,
        corporate_action_ledger_sha256="c" * 64,
        settlement_ledger_sha256="d" * 64,
        account_projection_sha256="e" * 64,
    )


def mixed_trade_report() -> BacktestReport:
    report = golden_report()
    original = report.trades[0]
    gain = replace(
        original,
        trade_id="spy-gain",
        quantity=Decimal("4"),
        cost_basis=Decimal("202.14"),
        proceeds=Decimal("247.30"),
        gross_pnl=Decimal("45.16"),
        execution_costs=Decimal("0.56"),
        net_pnl=Decimal("44.60"),
    )
    loss = replace(
        original,
        sequence=1,
        trade_id="spy-loss",
        quantity=Decimal("4"),
        cost_basis=Decimal("202.14"),
        proceeds=Decimal("192.14"),
        gross_pnl=Decimal("-10"),
        execution_costs=Decimal("0.56"),
        net_pnl=Decimal("-10.56"),
        opening_execution_sha256="3" * 64,
        closing_execution_sha256="4" * 64,
    )
    return replace(
        report,
        trades=(gain, loss),
        metrics=replace(
            report.metrics,
            trade_count=2,
            winning_trade_count=1,
            losing_trade_count=1,
            hit_rate=Decimal("0.5"),
            profit_factor=Decimal("4.2234848485"),
        ),
    )


def external_cash_flow_report() -> BacktestReport:
    curve = (
        BacktestEquityPoint(
            sequence=0,
            as_of=PERIOD_START,
            cash=Decimal("100"),
            market_value=Decimal("0"),
            equity=Decimal("100"),
            gross_exposure=Decimal("0"),
            net_exposure=Decimal("0"),
            cumulative_external_cash_flow=Decimal("100"),
            period_return=Decimal("0"),
            cumulative_return=Decimal("0"),
            drawdown=Decimal("0"),
        ),
        BacktestEquityPoint(
            sequence=1,
            as_of=PERIOD_END,
            cash=Decimal("150"),
            market_value=Decimal("0"),
            equity=Decimal("150"),
            gross_exposure=Decimal("0"),
            net_exposure=Decimal("0"),
            cumulative_external_cash_flow=Decimal("150"),
            period_return=Decimal("0"),
            cumulative_return=Decimal("0"),
            drawdown=Decimal("0"),
        ),
    )
    no_trade_metrics = replace(
        metrics(),
        starting_equity=Decimal("100"),
        ending_equity=Decimal("150"),
        total_return=Decimal("0"),
        maximum_drawdown=Decimal("0"),
        turnover=Decimal("0"),
        average_gross_exposure=Decimal("0"),
        average_net_exposure=Decimal("0"),
        trade_count=0,
        winning_trade_count=0,
        hit_rate=None,
        total_execution_costs=Decimal("0"),
        realized_pnl=Decimal("0"),
        dividend_income=Decimal("0"),
    )
    return BacktestReport(
        account_id="cash-flow-fixture-account",
        currency="USD",
        period_start=PERIOD_START,
        period_end=PERIOD_END,
        generated_at=GENERATED_AT,
        conventions=conventions(),
        equity_curve=curve,
        trades=(),
        positions=(),
        ledger_trace=(),
        metrics=no_trade_metrics,
        execution_ledger_sha256="b" * 64,
        corporate_action_ledger_sha256="c" * 64,
        settlement_ledger_sha256="d" * 64,
        account_projection_sha256="e" * 64,
    )


def dataset_replay_pin() -> DatasetReplayPin:
    return DatasetReplayPin(
        dataset_manifest_sha256="1" * 64,
        source_tape_sha256="2" * 64,
        replay_run_id="3" * 64,
        replay_manifest_sha256="3" * 64,
        replay_input_sha256="4" * 64,
        replay_semantic_sha256="5" * 64,
    )


def strategy_pin(*, completed: bool = True) -> StrategyRunPin:
    return StrategyRunPin(
        strategy_id="fixture-buy-hold-sell",
        strategy_version="1.0.0",
        strategy_configuration_sha256="6" * 64,
        initial_state_sha256="7" * 64,
        strategy_replay_sha256="8" * 64 if completed else None,
        final_state_sha256="9" * 64 if completed else None,
    )


def contract_pins() -> BacktestContractPins:
    return BacktestContractPins(
        strategy_replay_version="phase2-strategy-replay-v1",
        order_reducer_version="phase2-order-reducer-v1",
        simulated_broker_version="phase2-simulated-broker-v1",
        execution_ledger_version="phase2-execution-ledger-v1",
        account_projection_version="phase2-fifo-account-projection-v3",
        corporate_action_ledger_version="phase2-corporate-action-ledger-v1",
        settlement_ledger_version="phase2-execution-settlement-v2",
        batch_risk_version="phase2-atomic-batch-risk-v1",
        account_coordinator_version="phase2-account-coordinator-v1",
        decimal_arithmetic_version="decimal64-e63-exact-v1",
    )


def runtime_pin() -> BacktestRuntimePin:
    return BacktestRuntimePin(
        source_revision="a" * 40,
        dirty_patch_sha256="b" * 64,
        dependency_lock_sha256="c" * 64,
        container_image_sha256=NOT_APPLICABLE,
        schema_revision="fixture-only",
        python_version="3.12.10",
        numerical_runtime_version="decimal64-e63-exact-v1",
        tzdata_version="2026a",
    )


def benchmark_pin() -> BenchmarkPin:
    return BenchmarkPin(
        benchmark_id="SPY-total-return-fixture",
        benchmark_version="2026-07-15-v1",
        content_sha256="d" * 64,
        currency="USD",
        total_return=True,
    )


def model_pin(kind: SimulationModelKind) -> SimulationModelPin:
    return SimulationModelPin(
        kind=kind,
        model_id=f"fixture-{kind.value}-model",
        model_version="1.0.0",
        configuration_sha256=("e" if kind is SimulationModelKind.COST else "f") * 64,
        currency="USD",
    )


def manifest(
    *,
    report: BacktestReport | None = None,
    strategy: StrategyRunPin | None = None,
    benchmark: BenchmarkPin | None = None,
    cost_model: SimulationModelPin | None = None,
    fill_model: SimulationModelPin | None = None,
    completed_at: datetime = RUN_COMPLETED_AT,
    risk_evidence_sha256: str = "2" * 64,
) -> BacktestRunManifest:
    return BacktestRunManifest.completed(
        report=golden_report() if report is None else report,
        dataset_replay=dataset_replay_pin(),
        strategy=strategy_pin() if strategy is None else strategy,
        contracts=contract_pins(),
        runtime=runtime_pin(),
        benchmark=benchmark_pin() if benchmark is None else benchmark,
        cost_model=(model_pin(SimulationModelKind.COST) if cost_model is None else cost_model),
        fill_model=(model_pin(SimulationModelKind.FILL) if fill_model is None else fill_model),
        started_at=RUN_STARTED_AT,
        completed_at=completed_at,
        execution_evidence_sha256="1" * 64,
        risk_evidence_sha256=risk_evidence_sha256,
        coordinator_evidence_sha256="3" * 64,
    )


def test_golden_report_is_reconciled_immutable_and_scale_independent() -> None:
    report = golden_report()
    scaled_report = golden_report(scaled=True)

    assert report == scaled_report
    assert report.canonical_json == scaled_report.canonical_json
    assert report.report_id == report.report_sha256
    assert report.artifact_id == report.artifact_sha256
    assert len(report.report_sha256) == 64
    assert len(report.artifact_sha256) == 64
    assert len(report.accounting_evidence_sha256) == 64
    assert report.equity_curve[-1].equity == Decimal("1044.04")
    assert report.positions[-1].quantity == 0
    assert report.metrics.realized_pnl == Decimal("44.04")
    assert report.metrics.dividend_income == 10
    assert report.trades[0].gross_pnl == Decimal("35.16")
    assert report.trades[0].execution_costs == Decimal("1.12")
    with pytest.raises(FrozenInstanceError):
        report.report_sha256 = "0" * 64  # type: ignore[misc]


def test_generation_metadata_has_a_distinct_artifact_identity() -> None:
    report = golden_report()
    later_artifact = replace(report, generated_at=report.generated_at + timedelta(seconds=1))

    assert later_artifact.report_sha256 == report.report_sha256
    assert later_artifact.canonical_json == report.canonical_json
    assert later_artifact.artifact_sha256 != report.artifact_sha256
    assert later_artifact.artifact_canonical_json != report.artifact_canonical_json


def test_economic_rows_reject_invalid_arithmetic_time_and_identity() -> None:
    point = equity_curve()[1]
    trade = trades()[0]
    position = positions()[0]
    trace = ledger_trace()[0]

    with pytest.raises(ValueError, match="cash plus market value"):
        replace(point, equity=Decimal("999.19"))
    with pytest.raises(ValueError, match="cover absolute net exposure"):
        replace(point, gross_exposure=Decimal("403"))
    with pytest.raises(ValueError, match="gross P&L"):
        replace(trade, gross_pnl=Decimal("35.17"))
    with pytest.raises(ValueError, match="net P&L"):
        replace(trade, net_pnl=Decimal("34.05"))
    with pytest.raises(ValueError, match="quantity times mark price"):
        replace(position, market_value=Decimal("405"))
    with pytest.raises(ValueError, match="unrealized P&L"):
        replace(position, unrealized_pnl=Decimal("0"))
    with pytest.raises(ValueError, match="recorded before"):
        replace(trace, recorded_at=trace.effective_at - timedelta(microseconds=1))
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        replace(trace, entry_sha256="NOT-A-DIGEST")
    with pytest.raises(ValueError, match="timezone-aware"):
        replace(point, as_of=point.as_of.replace(tzinfo=None))
    with pytest.raises(ValueError, match="exact Decimal"):
        replace(point, cash=1000)  # type: ignore[arg-type]


def test_report_rejects_noncanonical_rows_and_inconsistent_metrics() -> None:
    report = golden_report()

    with pytest.raises(ValueError, match="equity curve sequences"):
        replace(report, equity_curve=tuple(reversed(report.equity_curve)))
    with pytest.raises(ValueError, match="maximum drawdown"):
        replace(report, metrics=replace(report.metrics, maximum_drawdown=Decimal("0")))
    with pytest.raises(ValueError, match="trade_count"):
        replace(
            report,
            metrics=replace(
                report.metrics,
                trade_count=2,
                breakeven_trade_count=1,
            ),
        )
    with pytest.raises(ValueError, match="trade outcome metrics"):
        replace(
            report,
            metrics=replace(
                report.metrics,
                winning_trade_count=0,
                losing_trade_count=1,
            ),
        )
    with pytest.raises(ValueError, match="metric conventions"):
        replace(report, currency="EUR")
    with pytest.raises(ValueError, match="period ends"):
        replace(report, generated_at=PERIOD_END - timedelta(microseconds=1))


def test_report_rederives_return_drawdown_and_exposure_paths() -> None:
    report = golden_report()
    cash_flow_report = external_cash_flow_report()

    assert cash_flow_report.metrics.ending_equity == Decimal("150")
    assert cash_flow_report.metrics.total_return == 0
    changed_cash_flow_curve = list(cash_flow_report.equity_curve)
    changed_cash_flow_curve[-1] = replace(
        changed_cash_flow_curve[-1],
        period_return=Decimal("0.5"),
        cumulative_return=Decimal("0.5"),
    )
    with pytest.raises(ValueError, match="period return"):
        replace(cash_flow_report, equity_curve=tuple(changed_cash_flow_curve))

    changed_curve = list(report.equity_curve)
    changed_curve[1] = replace(changed_curve[1], period_return=Decimal("0.1"))
    with pytest.raises(ValueError, match="period return"):
        replace(report, equity_curve=tuple(changed_curve))

    changed_curve = list(report.equity_curve)
    changed_curve[2] = replace(changed_curve[2], cumulative_return=Decimal("0.5"))
    with pytest.raises(ValueError, match="cumulative return"):
        replace(report, equity_curve=tuple(changed_curve))

    changed_curve = list(report.equity_curve)
    changed_curve[1] = replace(changed_curve[1], drawdown=Decimal("0"))
    with pytest.raises(ValueError, match="drawdown"):
        replace(report, equity_curve=tuple(changed_curve))

    for field_name, value, message in (
        ("total_return", Decimal("0.99"), "total return"),
        ("turnover", Decimal("0.99"), "turnover"),
        ("average_gross_exposure", Decimal("999"), "average gross exposure"),
        ("average_net_exposure", Decimal("999"), "average net exposure"),
    ):
        with pytest.raises(ValueError, match=message):
            replace(report, metrics=replace(report.metrics, **{field_name: value}))


def test_report_rederives_trade_and_final_position_metrics() -> None:
    report = golden_report()

    with pytest.raises(ValueError, match="hit rate"):
        replace(report, metrics=replace(report.metrics, hit_rate=Decimal("0")))
    with pytest.raises(ValueError, match="profit factor must be undefined"):
        replace(report, metrics=replace(report.metrics, profit_factor=Decimal("1")))
    for field_name, value, message in (
        ("total_execution_costs", Decimal("9"), "total execution costs"),
        ("realized_pnl", Decimal("9"), "realized P&L"),
        ("unrealized_pnl", Decimal("9"), "unrealized P&L"),
        ("dividend_income", Decimal("9"), "dividend income"),
    ):
        with pytest.raises(ValueError, match=message):
            replace(report, metrics=replace(report.metrics, **{field_name: value}))

    mixed = mixed_trade_report()
    assert mixed.metrics.profit_factor == Decimal("4.2234848485")
    with pytest.raises(ValueError, match="profit factor"):
        replace(mixed, metrics=replace(mixed.metrics, profit_factor=Decimal("4")))

    stale_positions = list(report.positions)
    stale_positions[-1] = replace(stale_positions[-1], as_of=PERIOD_END - timedelta(seconds=1))
    with pytest.raises(ValueError, match="final-period position"):
        replace(report, positions=tuple(stale_positions))
    open_positions = list(report.positions)
    open_positions[-1] = replace(
        open_positions[-1],
        quantity=Decimal("1"),
        cost_basis=Decimal("55"),
        market_value=Decimal("55"),
        unrealized_pnl=Decimal("0"),
    )
    with pytest.raises(ValueError, match="flat final positions"):
        replace(report, positions=tuple(open_positions))

    changed_curve = list(report.equity_curve)
    changed_curve[-1] = replace(
        changed_curve[-1],
        cash=Decimal("1045.04"),
        equity=Decimal("1045.04"),
        period_return=Decimal("0.0154103267"),
        cumulative_return=Decimal("0.04504"),
    )
    with pytest.raises(ValueError, match="ending economic P&L"):
        replace(
            report,
            equity_curve=tuple(changed_curve),
            metrics=replace(
                report.metrics,
                ending_equity=Decimal("1045.04"),
                total_return=Decimal("0.04504"),
            ),
        )


def test_report_rejects_unsupported_statistical_claims() -> None:
    report = golden_report()

    for field_name in (
        "annualized_return",
        "annualized_volatility",
        "sharpe_ratio",
        "sortino_ratio",
        "capacity_proxy",
    ):
        with pytest.raises(ValueError, match=f"{field_name} must be undefined"):
            replace(report, metrics=replace(report.metrics, **{field_name: Decimal("1")}))
    with pytest.raises(ValueError, match="cannot declare uncertainty"):
        replace(
            report,
            conventions=replace(
                report.conventions,
                uncertainty_method=UncertaintyMethod.IID_STANDARD_ERROR,
            ),
        )
    with pytest.raises(ValueError, match="simple returns"):
        replace(
            report,
            conventions=replace(report.conventions, return_type=BacktestReturnType.LOG),
        )
    with pytest.raises(ValueError, match="external cash flows excluded"):
        replace(
            report,
            conventions=replace(
                report.conventions,
                external_cash_flow_treatment=ExternalCashFlowTreatment.TIME_WEIGHTED,
            ),
        )


def test_report_enforces_unique_identities_and_causal_time_bounds() -> None:
    report = golden_report()
    duplicate_trade = replace(report.trades[0], sequence=1)
    with pytest.raises(ValueError, match="trade IDs must be unique"):
        replace(report, trades=(report.trades[0], duplicate_trade))

    changed_trace = list(report.ledger_trace)
    changed_trace[1] = replace(changed_trace[1], entry_id=changed_trace[0].entry_id)
    with pytest.raises(ValueError, match="entry IDs must be unique"):
        replace(report, ledger_trace=tuple(changed_trace))
    changed_trace = list(report.ledger_trace)
    changed_trace[1] = replace(changed_trace[1], entry_sha256=changed_trace[0].entry_sha256)
    with pytest.raises(ValueError, match="entry digests must be unique"):
        replace(report, ledger_trace=tuple(changed_trace))

    with pytest.raises(ValueError, match="trade times"):
        replace(
            report,
            trades=(replace(report.trades[0], opened_at=PERIOD_START - timedelta(seconds=1)),),
        )
    changed_positions = list(report.positions)
    changed_positions[-1] = replace(changed_positions[-1], as_of=PERIOD_END + timedelta(seconds=1))
    with pytest.raises(ValueError, match="position times"):
        replace(report, positions=tuple(changed_positions))
    changed_trace = list(report.ledger_trace)
    changed_trace[0] = replace(
        changed_trace[0],
        effective_at=PERIOD_START - timedelta(seconds=1),
    )
    with pytest.raises(ValueError, match="ledger effective times"):
        replace(report, ledger_trace=tuple(changed_trace))
    changed_trace = list(report.ledger_trace)
    changed_trace[-1] = replace(
        changed_trace[-1],
        recorded_at=GENERATED_AT + timedelta(seconds=1),
    )
    with pytest.raises(ValueError, match="after report generation"):
        replace(report, ledger_trace=tuple(changed_trace))


def test_metric_conventions_and_metrics_fail_closed() -> None:
    declared = conventions()

    with pytest.raises(ValueError, match="positive integer"):
        replace(declared, annualization_periods=0)
    with pytest.raises(ValueError, match="non-negative"):
        replace(declared, absolute_tolerance=Decimal("-0.1"))
    with pytest.raises(ValueError, match="persistence resolution"):
        replace(declared, relative_tolerance=Decimal("0.0000000002"))
    with pytest.raises(ValueError, match="three-letter"):
        replace(declared, currency="usd")
    with pytest.raises(ValueError, match="trade outcome counts"):
        replace(metrics(), trade_count=2)
    with pytest.raises(ValueError, match="hit_rate is required"):
        replace(metrics(), hit_rate=None)
    with pytest.raises(ValueError, match="between zero and one"):
        replace(metrics(), hit_rate=Decimal("1.1"))
    with pytest.raises(ValueError, match="volatility"):
        replace(metrics(), annualized_volatility=Decimal("-0.1"))


def test_run_result_requires_exact_terminal_status_evidence() -> None:
    report = golden_report()
    completed = BacktestRunResult.completed(
        report=report,
        started_at=RUN_STARTED_AT,
        completed_at=RUN_COMPLETED_AT,
    )

    assert completed.status is BacktestRunStatus.COMPLETED
    assert completed.report_sha256 == report.report_sha256
    assert completed.report_artifact_sha256 == report.artifact_sha256
    assert len(completed.semantic_sha256) == 64
    failed = BacktestRunResult.failed(
        started_at=RUN_STARTED_AT,
        completed_at=RUN_COMPLETED_AT,
        terminal_reason_code="callback_error",
        terminal_reason_sha256="4" * 64,
    )
    canceled = BacktestRunResult.canceled(
        started_at=RUN_STARTED_AT,
        completed_at=RUN_COMPLETED_AT,
        terminal_reason_code="operator_cancel",
        terminal_reason_sha256="5" * 64,
    )
    assert failed.report_sha256 is None
    assert failed.report_artifact_sha256 is None
    assert canceled.status is BacktestRunStatus.CANCELED
    with pytest.raises(ValueError, match="after run completion"):
        BacktestRunResult.completed(
            report=report,
            started_at=RUN_STARTED_AT,
            completed_at=GENERATED_AT - timedelta(microseconds=1),
        )
    with pytest.raises(TypeError, match="_construction_proof"):
        BacktestRunResult(
            status=BacktestRunStatus.COMPLETED,
            started_at=RUN_STARTED_AT,
            completed_at=RUN_COMPLETED_AT,
            report_sha256="f" * 64,
            report_artifact_sha256="e" * 64,
        )
    with pytest.raises(ValueError, match="terminal factory"):
        BacktestRunResult(
            status=BacktestRunStatus.COMPLETED,
            started_at=RUN_STARTED_AT,
            completed_at=RUN_COMPLETED_AT,
            report_sha256="f" * 64,
            report_artifact_sha256="e" * 64,
            _construction_proof=object(),
        )
    with pytest.raises(ValueError, match="cannot precede"):
        BacktestRunResult.failed(
            started_at=RUN_COMPLETED_AT,
            completed_at=RUN_STARTED_AT,
            terminal_reason_code="callback_error",
            terminal_reason_sha256="4" * 64,
        )


def test_manifest_binds_inputs_outputs_and_report_digest_deterministically() -> None:
    first = manifest()
    second = manifest()

    assert first == second
    assert first.run_id == first.manifest_sha256
    assert first.idempotency_key == first.input_sha256
    assert first.report_sha256 == golden_report().report_sha256
    assert first.report_artifact_sha256 == golden_report().artifact_sha256
    assert first.accounting_evidence_sha256 == golden_report().accounting_evidence_sha256
    assert len(first.canonical_json) > 0

    later_completion = manifest(completed_at=RUN_COMPLETED_AT + timedelta(seconds=1))
    changed_final_state = manifest(strategy=replace(first.strategy, final_state_sha256="a" * 64))
    changed_benchmark = manifest(
        benchmark=replace(first.benchmark, benchmark_version="2026-07-15-v2")
    )
    later_report_artifact = replace(
        golden_report(),
        generated_at=GENERATED_AT + timedelta(seconds=1),
    )
    changed_artifact = manifest(report=later_report_artifact)

    assert later_completion.input_sha256 == first.input_sha256
    assert later_completion.manifest_sha256 != first.manifest_sha256
    assert changed_final_state.input_sha256 == first.input_sha256
    assert changed_final_state.manifest_sha256 != first.manifest_sha256
    assert changed_benchmark.input_sha256 != first.input_sha256
    assert changed_benchmark.manifest_sha256 != first.manifest_sha256
    assert changed_artifact.report_sha256 == first.report_sha256
    assert changed_artifact.result.report_artifact_sha256 != first.result.report_artifact_sha256
    assert changed_artifact.input_sha256 == first.input_sha256
    assert changed_artifact.manifest_sha256 != first.manifest_sha256


def test_manifest_rejects_inconsistent_models_or_incomplete_success_evidence() -> None:
    completed = manifest()

    with pytest.raises(ValueError, match="cost model kind"):
        manifest(cost_model=model_pin(SimulationModelKind.FILL))
    with pytest.raises(ValueError, match="currencies must match"):
        manifest(benchmark=replace(completed.benchmark, currency="EUR"))
    with pytest.raises(ValueError, match="model currencies must match"):
        manifest(cost_model=replace(model_pin(SimulationModelKind.COST), currency="EUR"))
    with pytest.raises(ValueError, match="terminal strategy evidence"):
        manifest(strategy=strategy_pin(completed=False))
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        manifest(risk_evidence_sha256="not-a-digest")
    with pytest.raises(ValueError, match="content-addressed manifest"):
        replace(dataset_replay_pin(), replay_run_id="f" * 64)
    with pytest.raises(ValueError, match="InitVar"):
        replace(completed, accounting_evidence_sha256="9" * 64)
    with pytest.raises(ValueError, match="terminal factory"):
        BacktestRunManifest(
            dataset_replay=completed.dataset_replay,
            strategy=completed.strategy,
            contracts=completed.contracts,
            runtime=completed.runtime,
            benchmark=completed.benchmark,
            cost_model=completed.cost_model,
            fill_model=completed.fill_model,
            metric_conventions_sha256="0" * 64,
            result=completed.result,
            execution_evidence_sha256="1" * 64,
            accounting_evidence_sha256="9" * 64,
            risk_evidence_sha256="2" * 64,
            coordinator_evidence_sha256="3" * 64,
            _construction_proof=object(),
        )


def test_failed_manifest_retains_pinned_input_without_fabricating_report_evidence() -> None:
    canceled_manifest = BacktestRunManifest.canceled(
        dataset_replay=dataset_replay_pin(),
        strategy=strategy_pin(completed=False),
        contracts=contract_pins(),
        runtime=runtime_pin(),
        benchmark=benchmark_pin(),
        cost_model=model_pin(SimulationModelKind.COST),
        fill_model=model_pin(SimulationModelKind.FILL),
        metric_conventions=conventions(),
        started_at=RUN_STARTED_AT,
        completed_at=RUN_COMPLETED_AT,
        terminal_reason_code="operator_cancel",
        terminal_reason_sha256="4" * 64,
    )
    failed_manifest = BacktestRunManifest.failed(
        dataset_replay=dataset_replay_pin(),
        strategy=strategy_pin(completed=False),
        contracts=contract_pins(),
        runtime=runtime_pin(),
        benchmark=benchmark_pin(),
        cost_model=model_pin(SimulationModelKind.COST),
        fill_model=model_pin(SimulationModelKind.FILL),
        metric_conventions=conventions(),
        started_at=RUN_STARTED_AT,
        completed_at=RUN_COMPLETED_AT,
        terminal_reason_code="callback_error",
        terminal_reason_sha256="5" * 64,
    )

    assert failed_manifest.report_sha256 is None
    assert len(failed_manifest.input_sha256) == 64
    assert failed_manifest.result.status is BacktestRunStatus.FAILED
    assert canceled_manifest.report_sha256 is None
    assert canceled_manifest.result.status is BacktestRunStatus.CANCELED
    assert canceled_manifest.accounting_evidence_sha256 is None


def test_manifest_and_report_digests_ignore_ambient_decimal_context() -> None:
    with localcontext() as decimal_context:
        decimal_context.prec = 3
        low_precision_report = golden_report()
        low_precision_manifest = manifest()
    with localcontext() as decimal_context:
        decimal_context.prec = 40
        high_precision_report = golden_report()
        high_precision_manifest = manifest()

    assert low_precision_report == high_precision_report
    assert low_precision_report.report_sha256 == high_precision_report.report_sha256
    assert low_precision_manifest == high_precision_manifest
    assert low_precision_manifest.manifest_sha256 == high_precision_manifest.manifest_sha256


def test_runtime_randomness_and_digest_pins_are_explicit() -> None:
    deterministic = runtime_pin()

    assert deterministic.rng_algorithm == NOT_APPLICABLE
    assert deterministic.rng_seed is None
    with pytest.raises(ValueError, match="must be None"):
        replace(deterministic, rng_seed=1)
    seeded = replace(deterministic, rng_algorithm="pcg64-v1", rng_seed=0)
    assert seeded.rng_seed == 0
    with pytest.raises(ValueError, match="requires an exact integer seed"):
        replace(deterministic, rng_algorithm="pcg64-v1", rng_seed=None)
    with pytest.raises(ValueError, match="source commit digest"):
        replace(deterministic, source_revision="main")
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        replace(benchmark_pin(), content_sha256="D" * 64)
    with pytest.raises(ValueError, match="total-return series"):
        replace(benchmark_pin(), total_return=False)
