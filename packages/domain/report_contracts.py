"""Additive event-valued report records; legacy report contracts stay unchanged."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Literal

from packages.domain.accounting_contracts import (
    AccountingState,
    AccountSnapshot,
    ExecutionRow,
    FifoMatchRow,
)
from packages.domain.engine_contracts import DailyStrategyState, EngineTraceRow, RunSpec
from packages.domain.ledger_reducer import CanonicalLedgerEntry, CashFlowKind, LedgerCashFlow
from packages.domain.personal_contracts import (
    ContractRecord,
    VersionPin,
    require_amount,
    require_digest,
    require_text,
)

ValuationRole = Literal["baseline", "daily_close", "pre_flow", "post_flow", "terminal"]


@dataclass(frozen=True, slots=True)
class ValuationRow(ContractRecord):
    row_id: str
    snapshot: AccountSnapshot
    economic_at: datetime
    session: date
    roles: tuple[ValuationRole, ...]
    scored: bool
    interval_id: str
    flow_id: str | None = None
    paired_row_id: str | None = None

    def __post_init__(self) -> None:
        super(ValuationRow, self).__post_init__()
        require_text(self.row_id, "valuation ID")
        require_text(self.interval_id, "valuation interval")
        if not self.roles or len(set(self.roles)) != len(self.roles):
            raise ValueError("valuation requires unique roles")
        if self.economic_at > self.snapshot.point.knowledge_at:
            raise ValueError("valuation cannot use future economics")
        is_flow = "pre_flow" in self.roles or "post_flow" in self.roles
        if is_flow != (self.flow_id is not None and self.paired_row_id is not None):
            raise ValueError("flow valuation requires paired identity")
        if "pre_flow" in self.roles and "post_flow" in self.roles:
            raise ValueError("flow sides require distinct valuations")


@dataclass(frozen=True, slots=True)
class ExternalFlowRow(ContractRecord):
    flow: LedgerCashFlow
    signed_amount: Decimal
    sequence: int
    pre_valuation_id: str
    post_valuation_id: str
    origin: Literal["initial_capital", "external_flow"] = "external_flow"
    journal_sha256: str = ""

    def __post_init__(self) -> None:
        super(ExternalFlowRow, self).__post_init__()
        require_amount(self.signed_amount, "external flow")
        if self.signed_amount.copy_abs() != self.flow.amount or self.sequence < 0:
            raise ValueError("flow amount/sequence mismatch")
        expected = (
            self.flow.amount
            if self.flow.kind is CashFlowKind.CONTRIBUTION
            else self.flow.amount.copy_negate()
        )
        if self.signed_amount != expected or self.flow.currency != "USD":
            raise ValueError("flow direction/currency mismatch")
        if self.origin == "initial_capital" and self.flow.kind is not CashFlowKind.CONTRIBUTION:
            raise ValueError("initial capital must be a contribution")
        if self.pre_valuation_id == self.post_valuation_id:
            raise ValueError("flow requires distinct boundary rows")
        require_digest(self.journal_sha256, "flow journal")


@dataclass(frozen=True, slots=True)
class ScoredInterval(ContractRecord):
    interval_id: str
    fold_id: str
    baseline_valuation_id: str
    terminal_valuation_id: str
    expected_sessions: tuple[date, ...]
    warmup_sessions: tuple[date, ...]
    calendar_sha256: str
    reset_mode: Literal["independent"] = "independent"


@dataclass(frozen=True, slots=True)
class BenchmarkValuationInput(ContractRecord):
    valuation_id: str
    series_id: str
    unit_price: Decimal | None
    source_sha256: str
    economic_at: datetime
    knowledge_at: datetime
    representation: Literal["adjusted_total_return_units", "synthetic_total_return_units"]
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super(BenchmarkValuationInput, self).__post_init__()
        require_digest(self.source_sha256, "benchmark source")
        if self.unit_price is not None:
            require_amount(self.unit_price, "benchmark unit price", positive=True)
        if self.economic_at > self.knowledge_at:
            raise ValueError("benchmark mark cannot precede its event")


@dataclass(frozen=True, slots=True)
class ReportConventions(ContractRecord):
    version: Literal["personal-report/2"] = "personal-report/2"
    currency: Literal["USD"] = "USD"
    annualization_sessions: int = 252
    minimum_annualized_sessions: int = 252
    risk_free_daily: Decimal | None = Decimal(0)
    risk_free_model: Literal["assumed-zero-v1", "explicit-constant-daily-v1", "unavailable"] = (
        "assumed-zero-v1"
    )
    numeric_model: Literal["personal-derived-decimal64-half-even-v1"] = (
        "personal-derived-decimal64-half-even-v1"
    )
    returns_model: Literal["event-timed-twr-v1"] = "event-timed-twr-v1"
    trade_group_model: Literal["terminal-closing-order-v1"] = "terminal-closing-order-v1"
    turnover_model: Literal["all-executed-notional-over-mean-daily-nav-v1"] = (
        "all-executed-notional-over-mean-daily-nav-v1"
    )
    sortino_model: Literal["all-sample-downside-second-moment-zero-variance-undefined-v1"] = (
        "all-sample-downside-second-moment-zero-variance-undefined-v1"
    )
    benchmark_model: Literal["analytical-spy-matched-flows-zero-fee-v1"] = (
        "analytical-spy-matched-flows-zero-fee-v1"
    )

    def __post_init__(self) -> None:
        super(ReportConventions, self).__post_init__()
        if self.annualization_sessions != 252 or self.minimum_annualized_sessions < 252:
            raise ValueError("unsupported annualization convention")
        if self.risk_free_model == "assumed-zero-v1" and self.risk_free_daily != 0:
            raise ValueError("zero risk-free convention differs from value")
        if (self.risk_free_daily is None) != (self.risk_free_model == "unavailable"):
            raise ValueError("risk-free availability differs from convention")


@dataclass(frozen=True, slots=True)
class EngineResult(ContractRecord):
    spec: RunSpec
    status: Literal["completed", "cancelled", "failed", "rejected"]
    trace: tuple[EngineTraceRow, ...]
    final_state: AccountingState
    final_snapshot: AccountSnapshot
    final_strategy_state: DailyStrategyState
    valuations: tuple[ValuationRow, ...]
    flows: tuple[ExternalFlowRow, ...]
    executions: tuple[ExecutionRow, ...]
    fifo_matches: tuple[FifoMatchRow, ...]
    journal_entries: tuple[CanonicalLedgerEntry, ...]
    benchmark_inputs: tuple[BenchmarkValuationInput, ...]
    interval: ScoredInterval
    reasons: tuple[str, ...] = ()

    @property
    def run_id(self) -> str:
        return self.spec.run_id


@dataclass(frozen=True, slots=True)
class MetricCoverage(ContractRecord):
    interval_id: str
    expected_sessions: int
    observed_sessions: int
    valid_sessions: int
    valid_returns: int
    sample_count: int
    input_sha256: str
    contributing_row_ids: tuple[str, ...]
    excluded: tuple[tuple[str, tuple[str, ...]], ...] = ()


@dataclass(frozen=True, slots=True)
class MetricValue(ContractRecord):
    name: str
    value: Decimal | None
    unit: str
    status: Literal["defined", "undefined", "approximate"]
    coverage: MetricCoverage
    conventions_sha256: str
    reasons: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super(MetricValue, self).__post_init__()
        if (self.status == "undefined") != (self.value is None):
            raise ValueError("undefined metrics require null value")
        if self.status == "undefined" and not self.reasons:
            raise ValueError("undefined metrics require reasons")
        if self.status == "approximate" and not self.assumptions:
            raise ValueError("approximate metric requires explicit model")


@dataclass(frozen=True, slots=True)
class DerivedReturnRow(ContractRecord):
    valuation_id: str
    session: date
    sequence: int
    growth: Decimal | None
    period_return: Decimal | None
    wealth: Decimal | None
    drawdown: Decimal | None
    daily_close: bool
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BenchmarkRow(ContractRecord):
    valuation_id: str
    nav: Decimal | None
    units: Decimal | None
    signed_flow: Decimal
    wealth: Decimal | None
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BenchmarkReport(ContractRecord):
    model: str
    series_sha256: str
    rows: tuple[BenchmarkRow, ...]
    cash_rows: tuple[BenchmarkRow, ...]
    metrics: tuple[MetricValue, ...]
    cash_metrics: tuple[MetricValue, ...]
    matched_flow_ids: tuple[str, ...]
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RunReport(ContractRecord):
    run_id: str
    result_sha256: str
    conventions: ReportConventions
    status: Literal["completed", "incomplete"]
    interval: ScoredInterval
    metrics: tuple[MetricValue, ...]
    returns: tuple[DerivedReturnRow, ...]
    benchmark: BenchmarkReport
    source: EngineResult
    reasons: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ReportArtifact(ContractRecord):
    report: RunReport
    attempt_id: str
    generated_at: datetime
    restatement_pin: VersionPin | None = None
