"""Pure canonical declaration slice for fixture-backed Phase 2C backtest reports.

The values in this module are immutable declarations and report projections.
They do not discover runtime state, execute a strategy, persist a run, or grant
broker authority.  Callers must supply every provenance pin explicitly.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import InitVar, dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from itertools import pairwise
from typing import Self

from packages.domain.canonical import (
    canonical_json_bytes,
    canonical_json_text,
    canonical_persisted_decimal,
)
from packages.domain.decimal_math import (
    deterministic_decimal_divide,
    exact_decimal_add,
    exact_decimal_multiply,
    exact_decimal_subtract,
    exact_decimal_sum,
)

BACKTEST_REPORT_CONTRACT_VERSION = "phase2-backtest-report-v2"
BACKTEST_RUN_MANIFEST_CONTRACT_VERSION = "phase2-backtest-run-manifest-v2"
NOT_APPLICABLE = "not_applicable"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_FACTORY_CONSTRUCTION_PROOF = object()
_MAX_REPORT_TOLERANCE = Decimal("0.0000000001")


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: str, field_name: str, *, maximum: int = 128) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{field_name} must be non-empty and trimmed")
    if len(value) > maximum or any(ord(character) < 32 for character in value):
        raise ValueError(f"{field_name} contains unsupported text")


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_optional_sha256(value: str | None, field_name: str) -> None:
    if value is not None:
        _require_sha256(value, field_name)


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{field_name} must be UTC")


def _require_currency(value: str, field_name: str = "currency") -> None:
    if (
        type(value) is not str
        or len(value) != 3
        or not value.isascii()
        or not value.isalpha()
        or value != value.upper()
    ):
        raise ValueError(f"{field_name} must be a three-letter uppercase ASCII code")


def _decimal(value: Decimal, field_name: str) -> Decimal:
    if type(value) is not Decimal:
        raise ValueError(f"{field_name} must be an exact Decimal")
    return canonical_persisted_decimal(value, field_name)


def _nonnegative_decimal(value: Decimal, field_name: str) -> Decimal:
    canonical = _decimal(value, field_name)
    if canonical < 0:
        raise ValueError(f"{field_name} must be non-negative")
    return canonical


def _positive_decimal(value: Decimal, field_name: str) -> Decimal:
    canonical = _decimal(value, field_name)
    if canonical <= 0:
        raise ValueError(f"{field_name} must be positive")
    return canonical


def _canonicalize_decimal_fields(value: object, field_names: tuple[str, ...]) -> None:
    for field_name in field_names:
        object.__setattr__(value, field_name, _decimal(getattr(value, field_name), field_name))


def _canonicalize_optional_decimal(value: object, field_name: str) -> None:
    field_value = getattr(value, field_name)
    if field_value is not None:
        object.__setattr__(value, field_name, _decimal(field_value, field_name))


class BacktestRunStatus(StrEnum):
    """Lifecycle vocabulary shared with the future durable worker boundary."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


class BacktestReturnType(StrEnum):
    SIMPLE = "simple"
    LOG = "log"


class BacktestReturnFrequency(StrEnum):
    EVENT = "event"
    DAILY = "daily"


class ExternalCashFlowTreatment(StrEnum):
    EXCLUDED_FROM_RETURN = "excluded_from_return"
    TIME_WEIGHTED = "time_weighted"


class UncertaintyMethod(StrEnum):
    NONE = "none"
    IID_STANDARD_ERROR = "iid_standard_error"


class SimulationModelKind(StrEnum):
    COST = "cost"
    FILL = "fill"


@dataclass(frozen=True, slots=True)
class BacktestMetricConventions:
    """Complete conventions required to interpret every retained metric."""

    convention_id: str
    convention_version: str
    currency: str
    return_type: BacktestReturnType
    return_frequency: BacktestReturnFrequency
    annualization_periods: int
    annual_risk_free_rate: Decimal
    risk_free_rate_version: str
    external_cash_flow_treatment: ExternalCashFlowTreatment
    uncertainty_method: UncertaintyMethod
    absolute_tolerance: Decimal
    relative_tolerance: Decimal

    def __post_init__(self) -> None:
        _require_text(self.convention_id, "metric convention ID")
        _require_text(self.convention_version, "metric convention version")
        _require_currency(self.currency, "metric currency")
        if type(self.return_type) is not BacktestReturnType:
            raise ValueError("return_type must be an exact BacktestReturnType")
        if type(self.return_frequency) is not BacktestReturnFrequency:
            raise ValueError("return_frequency must be an exact BacktestReturnFrequency")
        if type(self.annualization_periods) is not int or self.annualization_periods <= 0:
            raise ValueError("annualization_periods must be a positive integer")
        object.__setattr__(
            self,
            "annual_risk_free_rate",
            _decimal(self.annual_risk_free_rate, "annual risk-free rate"),
        )
        _require_text(self.risk_free_rate_version, "risk-free rate version")
        if type(self.external_cash_flow_treatment) is not ExternalCashFlowTreatment:
            raise ValueError(
                "external_cash_flow_treatment must be an exact ExternalCashFlowTreatment"
            )
        if type(self.uncertainty_method) is not UncertaintyMethod:
            raise ValueError("uncertainty_method must be an exact UncertaintyMethod")
        for field_name in ("absolute_tolerance", "relative_tolerance"):
            tolerance = _nonnegative_decimal(getattr(self, field_name), field_name)
            if tolerance > _MAX_REPORT_TOLERANCE:
                raise ValueError(f"{field_name} cannot exceed the report persistence resolution")
            object.__setattr__(self, field_name, tolerance)

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                BACKTEST_REPORT_CONTRACT_VERSION,
                "metric_conventions",
                self.convention_id,
                self.convention_version,
                self.currency,
                self.return_type.value,
                self.return_frequency.value,
                self.annualization_periods,
                self.annual_risk_free_rate,
                self.risk_free_rate_version,
                self.external_cash_flow_treatment.value,
                self.uncertainty_method.value,
                self.absolute_tolerance,
                self.relative_tolerance,
            )
        )


def _require_close(
    actual: Decimal,
    expected: Decimal,
    conventions: BacktestMetricConventions,
    field_name: str,
) -> None:
    difference = exact_decimal_subtract(actual, expected).copy_abs()
    if difference <= conventions.absolute_tolerance:
        return
    if expected != 0:
        relative_difference = deterministic_decimal_divide(difference, expected.copy_abs())
        if relative_difference <= conventions.relative_tolerance:
            return
    raise ValueError(f"{field_name} does not match retained report evidence")


def _require_ratio_close(
    actual: Decimal,
    numerator: Decimal,
    denominator: Decimal,
    conventions: BacktestMetricConventions,
    field_name: str,
) -> None:
    if denominator == 0:
        raise ValueError(f"{field_name} cannot be derived with a zero denominator")
    residual = exact_decimal_subtract(
        exact_decimal_multiply(actual, denominator),
        numerator,
    ).copy_abs()
    absolute_difference = deterministic_decimal_divide(residual, denominator.copy_abs())
    if absolute_difference <= conventions.absolute_tolerance:
        return
    if numerator != 0:
        relative_difference = deterministic_decimal_divide(residual, numerator.copy_abs())
        if relative_difference <= conventions.relative_tolerance:
            return
    raise ValueError(f"{field_name} does not match retained report evidence")


@dataclass(frozen=True, slots=True)
class BacktestEquityPoint:
    """One causally ordered account valuation on the report curve."""

    sequence: int
    as_of: datetime
    cash: Decimal
    market_value: Decimal
    equity: Decimal
    gross_exposure: Decimal
    net_exposure: Decimal
    cumulative_external_cash_flow: Decimal
    period_return: Decimal
    cumulative_return: Decimal
    drawdown: Decimal

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 0:
            raise ValueError("equity sequence must be a non-negative integer")
        _require_utc(self.as_of, "equity point as_of")
        _canonicalize_decimal_fields(
            self,
            (
                "cash",
                "market_value",
                "equity",
                "gross_exposure",
                "net_exposure",
                "cumulative_external_cash_flow",
                "period_return",
                "cumulative_return",
                "drawdown",
            ),
        )
        if self.equity != exact_decimal_add(self.cash, self.market_value):
            raise ValueError("equity must equal cash plus market value")
        if self.gross_exposure < 0 or self.gross_exposure < self.net_exposure.copy_abs():
            raise ValueError("gross exposure must cover absolute net exposure")
        if self.drawdown < 0 or self.drawdown > 1:
            raise ValueError("drawdown must be between zero and one")

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                BACKTEST_REPORT_CONTRACT_VERSION,
                "equity_point",
                self.sequence,
                self.as_of,
                self.cash,
                self.market_value,
                self.equity,
                self.gross_exposure,
                self.net_exposure,
                self.cumulative_external_cash_flow,
                self.period_return,
                self.cumulative_return,
                self.drawdown,
            )
        )


@dataclass(frozen=True, slots=True)
class BacktestTrade:
    """One closed long FIFO trade with explicit cost attribution."""

    sequence: int
    trade_id: str
    instrument_id: str
    symbol: str
    opened_at: datetime
    closed_at: datetime
    quantity: Decimal
    cost_basis: Decimal
    proceeds: Decimal
    gross_pnl: Decimal
    execution_costs: Decimal
    net_pnl: Decimal
    opening_execution_sha256: str
    closing_execution_sha256: str

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 0:
            raise ValueError("trade sequence must be a non-negative integer")
        for value, field_name in (
            (self.trade_id, "trade ID"),
            (self.instrument_id, "trade instrument ID"),
            (self.symbol, "trade symbol"),
        ):
            _require_text(value, field_name)
        if self.symbol != self.symbol.upper():
            raise ValueError("trade symbol must use its canonical uppercase form")
        _require_utc(self.opened_at, "trade opened_at")
        _require_utc(self.closed_at, "trade closed_at")
        if self.closed_at < self.opened_at:
            raise ValueError("trade cannot close before it opens")
        object.__setattr__(self, "quantity", _positive_decimal(self.quantity, "trade quantity"))
        if self.quantity != self.quantity.to_integral_value():
            raise ValueError("trade quantity must be a whole number of shares")
        for field_name in ("cost_basis", "proceeds", "execution_costs"):
            object.__setattr__(
                self,
                field_name,
                _nonnegative_decimal(getattr(self, field_name), f"trade {field_name}"),
            )
        for field_name in ("gross_pnl", "net_pnl"):
            object.__setattr__(
                self,
                field_name,
                _decimal(getattr(self, field_name), f"trade {field_name}"),
            )
        if self.gross_pnl != exact_decimal_subtract(self.proceeds, self.cost_basis):
            raise ValueError("trade gross P&L must equal proceeds minus cost basis")
        if self.net_pnl != exact_decimal_subtract(self.gross_pnl, self.execution_costs):
            raise ValueError("trade net P&L must equal gross P&L minus execution costs")
        _require_sha256(self.opening_execution_sha256, "opening execution digest")
        _require_sha256(self.closing_execution_sha256, "closing execution digest")

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                BACKTEST_REPORT_CONTRACT_VERSION,
                "trade",
                self.sequence,
                self.trade_id,
                self.instrument_id,
                self.symbol,
                self.opened_at,
                self.closed_at,
                self.quantity,
                self.cost_basis,
                self.proceeds,
                self.gross_pnl,
                self.execution_costs,
                self.net_pnl,
                self.opening_execution_sha256,
                self.closing_execution_sha256,
            )
        )


@dataclass(frozen=True, slots=True)
class BacktestPosition:
    """One instrument projection retained for the position trace."""

    sequence: int
    as_of: datetime
    instrument_id: str
    symbol: str
    quantity: Decimal
    cost_basis: Decimal
    mark_price: Decimal
    market_value: Decimal
    realized_pnl: Decimal
    unrealized_pnl: Decimal
    execution_costs: Decimal
    dividend_income: Decimal
    source_projection_sha256: str

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 0:
            raise ValueError("position sequence must be a non-negative integer")
        _require_utc(self.as_of, "position as_of")
        _require_text(self.instrument_id, "position instrument ID")
        _require_text(self.symbol, "position symbol")
        if self.symbol != self.symbol.upper():
            raise ValueError("position symbol must use its canonical uppercase form")
        for field_name in (
            "quantity",
            "cost_basis",
            "mark_price",
            "market_value",
            "execution_costs",
            "dividend_income",
        ):
            object.__setattr__(
                self,
                field_name,
                _nonnegative_decimal(getattr(self, field_name), f"position {field_name}"),
            )
        for field_name in ("realized_pnl", "unrealized_pnl"):
            object.__setattr__(
                self,
                field_name,
                _decimal(getattr(self, field_name), f"position {field_name}"),
            )
        if self.quantity != self.quantity.to_integral_value():
            raise ValueError("position quantity must be a whole number of shares")
        if self.market_value != exact_decimal_multiply(self.quantity, self.mark_price):
            raise ValueError("position market value must equal quantity times mark price")
        if self.unrealized_pnl != exact_decimal_subtract(self.market_value, self.cost_basis):
            raise ValueError("position unrealized P&L must equal market value minus cost basis")
        _require_sha256(self.source_projection_sha256, "position source projection digest")

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                BACKTEST_REPORT_CONTRACT_VERSION,
                "position",
                self.sequence,
                self.as_of,
                self.instrument_id,
                self.symbol,
                self.quantity,
                self.cost_basis,
                self.mark_price,
                self.market_value,
                self.realized_pnl,
                self.unrealized_pnl,
                self.execution_costs,
                self.dividend_income,
                self.source_projection_sha256,
            )
        )


@dataclass(frozen=True, slots=True)
class BacktestLedgerTraceEntry:
    """Digest-addressed link from a report row to one canonical ledger entry."""

    sequence: int
    entry_id: str
    entry_kind: str
    source_fact_id: str
    effective_at: datetime
    recorded_at: datetime
    entry_sha256: str

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 0:
            raise ValueError("ledger trace sequence must be a non-negative integer")
        for value, field_name in (
            (self.entry_id, "ledger trace entry ID"),
            (self.entry_kind, "ledger trace entry kind"),
            (self.source_fact_id, "ledger trace source fact ID"),
        ):
            _require_text(value, field_name)
        _require_utc(self.effective_at, "ledger trace effective_at")
        _require_utc(self.recorded_at, "ledger trace recorded_at")
        if self.recorded_at < self.effective_at:
            raise ValueError("ledger trace cannot be recorded before it is effective")
        _require_sha256(self.entry_sha256, "ledger trace entry digest")

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                BACKTEST_REPORT_CONTRACT_VERSION,
                "ledger_trace_entry",
                self.sequence,
                self.entry_id,
                self.entry_kind,
                self.source_fact_id,
                self.effective_at,
                self.recorded_at,
                self.entry_sha256,
            )
        )


@dataclass(frozen=True, slots=True)
class BacktestMetrics:
    """Canonical retained metrics; optional values are explicitly undefined."""

    starting_equity: Decimal
    ending_equity: Decimal
    total_return: Decimal
    annualized_return: Decimal | None
    annualized_volatility: Decimal | None
    sharpe_ratio: Decimal | None
    sortino_ratio: Decimal | None
    maximum_drawdown: Decimal
    turnover: Decimal
    average_gross_exposure: Decimal
    average_net_exposure: Decimal
    trade_count: int
    winning_trade_count: int
    losing_trade_count: int
    breakeven_trade_count: int
    hit_rate: Decimal | None
    profit_factor: Decimal | None
    total_execution_costs: Decimal
    capacity_proxy: Decimal | None
    realized_pnl: Decimal
    unrealized_pnl: Decimal
    dividend_income: Decimal

    def __post_init__(self) -> None:
        _canonicalize_decimal_fields(
            self,
            (
                "starting_equity",
                "ending_equity",
                "total_return",
                "maximum_drawdown",
                "turnover",
                "average_gross_exposure",
                "average_net_exposure",
                "total_execution_costs",
                "realized_pnl",
                "unrealized_pnl",
                "dividend_income",
            ),
        )
        for field_name in (
            "annualized_return",
            "annualized_volatility",
            "sharpe_ratio",
            "sortino_ratio",
            "hit_rate",
            "profit_factor",
            "capacity_proxy",
        ):
            _canonicalize_optional_decimal(self, field_name)
        if self.starting_equity <= 0:
            raise ValueError("starting_equity must be positive")
        for field_name in (
            "maximum_drawdown",
            "turnover",
            "average_gross_exposure",
            "total_execution_costs",
            "dividend_income",
        ):
            if getattr(self, field_name) < 0:
                raise ValueError(f"{field_name} must be non-negative")
        if self.maximum_drawdown > 1:
            raise ValueError("maximum_drawdown must not exceed one")
        if self.average_gross_exposure < self.average_net_exposure.copy_abs():
            raise ValueError("average gross exposure must cover absolute average net exposure")
        for field_name in (
            "trade_count",
            "winning_trade_count",
            "losing_trade_count",
            "breakeven_trade_count",
        ):
            if type(getattr(self, field_name)) is not int or getattr(self, field_name) < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        classified_count = (
            self.winning_trade_count + self.losing_trade_count + self.breakeven_trade_count
        )
        if classified_count != self.trade_count:
            raise ValueError("trade outcome counts must cover every trade")
        decisive_count = self.winning_trade_count + self.losing_trade_count
        if decisive_count == 0 and self.hit_rate is not None:
            raise ValueError("hit_rate must be undefined without winning or losing trades")
        if decisive_count > 0 and self.hit_rate is None:
            raise ValueError("hit_rate is required when decisive trades exist")
        if self.hit_rate is not None and (self.hit_rate < 0 or self.hit_rate > 1):
            raise ValueError("hit_rate must be between zero and one")
        if self.profit_factor is not None and self.profit_factor < 0:
            raise ValueError("profit_factor must be non-negative when defined")
        if self.capacity_proxy is not None and self.capacity_proxy < 0:
            raise ValueError("capacity_proxy must be non-negative when defined")
        if self.annualized_volatility is not None and self.annualized_volatility < 0:
            raise ValueError("annualized_volatility must be non-negative when defined")

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                BACKTEST_REPORT_CONTRACT_VERSION,
                "metrics",
                self.starting_equity,
                self.ending_equity,
                self.total_return,
                self.annualized_return,
                self.annualized_volatility,
                self.sharpe_ratio,
                self.sortino_ratio,
                self.maximum_drawdown,
                self.turnover,
                self.average_gross_exposure,
                self.average_net_exposure,
                self.trade_count,
                self.winning_trade_count,
                self.losing_trade_count,
                self.breakeven_trade_count,
                self.hit_rate,
                self.profit_factor,
                self.total_execution_costs,
                self.capacity_proxy,
                self.realized_pnl,
                self.unrealized_pnl,
                self.dividend_income,
            )
        )


@dataclass(frozen=True, slots=True)
class BacktestReport:
    """Self-authenticating economic projection plus attempt-specific artifact identity."""

    account_id: str
    currency: str
    period_start: datetime
    period_end: datetime
    generated_at: datetime
    conventions: BacktestMetricConventions
    equity_curve: tuple[BacktestEquityPoint, ...]
    trades: tuple[BacktestTrade, ...]
    positions: tuple[BacktestPosition, ...]
    ledger_trace: tuple[BacktestLedgerTraceEntry, ...]
    metrics: BacktestMetrics
    execution_ledger_sha256: str
    corporate_action_ledger_sha256: str
    settlement_ledger_sha256: str
    account_projection_sha256: str
    report_sha256: str = field(init=False)
    artifact_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _require_text(self.account_id, "report account ID")
        _require_currency(self.currency, "report currency")
        _require_utc(self.period_start, "report period_start")
        _require_utc(self.period_end, "report period_end")
        _require_utc(self.generated_at, "report generated_at")
        if self.period_end < self.period_start:
            raise ValueError("report period_end cannot precede period_start")
        if self.generated_at < self.period_end:
            raise ValueError("report cannot be generated before its period ends")
        if type(self.conventions) is not BacktestMetricConventions:
            raise ValueError("report requires exact metric conventions")
        if self.currency != self.conventions.currency:
            raise ValueError("report currency must match its metric conventions")
        self._validate_rows()
        if type(self.metrics) is not BacktestMetrics:
            raise ValueError("report requires exact BacktestMetrics")
        self._validate_metrics()
        for digest, field_name in (
            (self.execution_ledger_sha256, "execution ledger digest"),
            (self.corporate_action_ledger_sha256, "corporate-action ledger digest"),
            (self.settlement_ledger_sha256, "settlement ledger digest"),
            (self.account_projection_sha256, "account projection digest"),
        ):
            _require_sha256(digest, field_name)
        report_sha256 = _sha256(self._semantic_material())
        object.__setattr__(self, "report_sha256", report_sha256)
        object.__setattr__(self, "artifact_sha256", _sha256(self._artifact_material(report_sha256)))

    def _validate_rows(self) -> None:
        for values, exact_type, field_name in (
            (self.equity_curve, BacktestEquityPoint, "equity curve"),
            (self.trades, BacktestTrade, "trades"),
            (self.positions, BacktestPosition, "positions"),
            (self.ledger_trace, BacktestLedgerTraceEntry, "ledger trace"),
        ):
            if type(values) is not tuple:
                raise ValueError(f"{field_name} must be an immutable tuple")
            if any(type(value) is not exact_type for value in values):
                raise ValueError(f"{field_name} contains an unsupported value")
            if tuple(value.sequence for value in values) != tuple(range(len(values))):
                raise ValueError(f"{field_name} sequences must be contiguous and ordered")
        if not self.equity_curve:
            raise ValueError("equity curve must contain at least one point")
        equity_times = tuple(point.as_of for point in self.equity_curve)
        if any(current <= previous for previous, current in pairwise(equity_times)):
            raise ValueError("equity curve times must be strictly increasing")
        if equity_times[0] != self.period_start or equity_times[-1] != self.period_end:
            raise ValueError("equity curve must cover the exact report period")
        trade_order = tuple(
            (trade.closed_at, trade.opened_at, trade.trade_id) for trade in self.trades
        )
        if trade_order != tuple(sorted(trade_order)):
            raise ValueError("trades must use canonical close-time order")
        trade_ids = tuple(trade.trade_id for trade in self.trades)
        if len(trade_ids) != len(set(trade_ids)):
            raise ValueError("trade IDs must be unique")
        if any(
            trade.opened_at < self.period_start or trade.closed_at > self.period_end
            for trade in self.trades
        ):
            raise ValueError("trade times must remain inside the report period")
        position_order = tuple(
            (position.as_of, position.instrument_id) for position in self.positions
        )
        if position_order != tuple(sorted(position_order)) or len(position_order) != len(
            set(position_order)
        ):
            raise ValueError("positions must be unique and ordered by time and instrument")
        if any(
            position.as_of < self.period_start or position.as_of > self.period_end
            for position in self.positions
        ):
            raise ValueError("position times must remain inside the report period")
        ledger_order = tuple(
            (entry.recorded_at, entry.effective_at, entry.entry_id) for entry in self.ledger_trace
        )
        if ledger_order != tuple(sorted(ledger_order)):
            raise ValueError("ledger trace must use canonical recorded-time order")
        ledger_entry_ids = tuple(entry.entry_id for entry in self.ledger_trace)
        if len(ledger_entry_ids) != len(set(ledger_entry_ids)):
            raise ValueError("ledger trace entry IDs must be unique")
        ledger_entry_digests = tuple(entry.entry_sha256 for entry in self.ledger_trace)
        if len(ledger_entry_digests) != len(set(ledger_entry_digests)):
            raise ValueError("ledger trace entry digests must be unique")
        if any(
            entry.effective_at < self.period_start or entry.effective_at > self.period_end
            for entry in self.ledger_trace
        ):
            raise ValueError("ledger effective times must remain inside the report period")
        if any(entry.recorded_at > self.generated_at for entry in self.ledger_trace):
            raise ValueError("ledger facts cannot be recorded after report generation")

    def _validate_return_path(self) -> None:
        if self.conventions.return_type is not BacktestReturnType.SIMPLE:
            raise ValueError("the Phase 2 report contract can only validate simple returns")
        if (
            self.conventions.external_cash_flow_treatment
            is not ExternalCashFlowTreatment.EXCLUDED_FROM_RETURN
        ):
            raise ValueError(
                "the Phase 2 report contract requires external cash flows excluded from returns"
            )
        first_point = self.equity_curve[0]
        if first_point.equity <= 0:
            raise ValueError("equity must remain positive for a defined return path")
        for value, field_name in (
            (first_point.period_return, "initial period return"),
            (first_point.cumulative_return, "initial cumulative return"),
            (first_point.drawdown, "initial drawdown"),
        ):
            _require_close(value, Decimal(0), self.conventions, field_name)

        running_peak = Decimal(1)
        for previous, current in pairwise(self.equity_curve):
            if current.equity <= 0:
                raise ValueError("equity must remain positive for a defined return path")
            flow_delta = exact_decimal_subtract(
                current.cumulative_external_cash_flow,
                previous.cumulative_external_cash_flow,
            )
            flow_adjusted_equity = exact_decimal_subtract(current.equity, flow_delta)
            if flow_adjusted_equity <= 0:
                raise ValueError("flow-adjusted equity must remain positive")
            period_growth = exact_decimal_add(Decimal(1), current.period_return)
            if period_growth <= 0:
                raise ValueError("period return must be greater than negative one")
            _require_ratio_close(
                period_growth,
                flow_adjusted_equity,
                previous.equity,
                self.conventions,
                "period return",
            )
            cumulative_growth = exact_decimal_add(Decimal(1), current.cumulative_return)
            expected_growth = exact_decimal_multiply(
                exact_decimal_add(Decimal(1), previous.cumulative_return),
                period_growth,
            )
            _require_close(
                cumulative_growth,
                expected_growth,
                self.conventions,
                "cumulative return",
            )
            if cumulative_growth <= 0:
                raise ValueError("cumulative return must be greater than negative one")
            running_peak = max(running_peak, cumulative_growth)
            drawdown_numerator = exact_decimal_subtract(running_peak, cumulative_growth)
            _require_ratio_close(
                current.drawdown,
                drawdown_numerator,
                running_peak,
                self.conventions,
                "drawdown",
            )

    def _validate_trade_metrics(self) -> None:
        if self.metrics.trade_count != len(self.trades):
            raise ValueError("trade_count must match the retained trades")
        expected_winners = sum(trade.net_pnl > 0 for trade in self.trades)
        expected_losers = sum(trade.net_pnl < 0 for trade in self.trades)
        expected_breakeven = sum(trade.net_pnl == 0 for trade in self.trades)
        if (
            self.metrics.winning_trade_count,
            self.metrics.losing_trade_count,
            self.metrics.breakeven_trade_count,
        ) != (expected_winners, expected_losers, expected_breakeven):
            raise ValueError("trade outcome metrics must match the retained trades")
        decisive_count = expected_winners + expected_losers
        if decisive_count:
            if self.metrics.hit_rate is None:
                raise ValueError("hit rate is required for decisive retained trades")
            _require_ratio_close(
                self.metrics.hit_rate,
                Decimal(expected_winners),
                Decimal(decisive_count),
                self.conventions,
                "hit rate",
            )
        elif self.metrics.hit_rate is not None:
            raise ValueError("hit rate must be undefined without decisive retained trades")

        gross_profit = exact_decimal_sum(
            trade.net_pnl for trade in self.trades if trade.net_pnl > 0
        )
        gross_loss = exact_decimal_sum(
            trade.net_pnl.copy_abs() for trade in self.trades if trade.net_pnl < 0
        )
        if gross_loss == 0:
            if self.metrics.profit_factor is not None:
                raise ValueError("profit factor must be undefined without retained losses")
        else:
            if self.metrics.profit_factor is None:
                raise ValueError("profit factor is required when retained losses exist")
            _require_ratio_close(
                self.metrics.profit_factor,
                gross_profit,
                gross_loss,
                self.conventions,
                "profit factor",
            )

    def _validate_position_metrics(self) -> None:
        final_positions: dict[str, BacktestPosition] = {}
        for position in self.positions:
            final_positions[position.instrument_id] = position
        if any(position.as_of != self.period_end for position in final_positions.values()):
            raise ValueError("every retained instrument requires a final-period position")
        if any(position.quantity != 0 for position in final_positions.values()):
            raise ValueError("the Phase 2 report requires flat final positions")
        missing_trade_positions = {trade.instrument_id for trade in self.trades}.difference(
            final_positions
        )
        if missing_trade_positions:
            raise ValueError("every traded instrument requires retained final position evidence")

        expected_totals = {
            "total execution costs": exact_decimal_sum(
                position.execution_costs for position in final_positions.values()
            ),
            "realized P&L": exact_decimal_sum(
                position.realized_pnl for position in final_positions.values()
            ),
            "unrealized P&L": exact_decimal_sum(
                position.unrealized_pnl for position in final_positions.values()
            ),
            "dividend income": exact_decimal_sum(
                position.dividend_income for position in final_positions.values()
            ),
        }
        for actual, field_name in (
            (self.metrics.total_execution_costs, "total execution costs"),
            (self.metrics.realized_pnl, "realized P&L"),
            (self.metrics.unrealized_pnl, "unrealized P&L"),
            (self.metrics.dividend_income, "dividend income"),
        ):
            _require_close(
                actual,
                expected_totals[field_name],
                self.conventions,
                field_name,
            )
        net_external_flow = exact_decimal_subtract(
            self.equity_curve[-1].cumulative_external_cash_flow,
            self.equity_curve[0].cumulative_external_cash_flow,
        )
        equity_change = exact_decimal_subtract(
            self.metrics.ending_equity,
            self.metrics.starting_equity,
        )
        economic_pnl = exact_decimal_subtract(equity_change, net_external_flow)
        retained_pnl = exact_decimal_add(
            self.metrics.realized_pnl,
            self.metrics.unrealized_pnl,
        )
        _require_close(
            retained_pnl,
            economic_pnl,
            self.conventions,
            "ending economic P&L",
        )
        if final_positions:
            _require_close(
                self.metrics.total_execution_costs,
                exact_decimal_sum(trade.execution_costs for trade in self.trades),
                self.conventions,
                "flat-account execution costs",
            )
            closed_trade_income = exact_decimal_add(
                exact_decimal_sum(trade.net_pnl for trade in self.trades),
                self.metrics.dividend_income,
            )
            _require_close(
                self.metrics.realized_pnl,
                closed_trade_income,
                self.conventions,
                "flat-account realized P&L",
            )

    def _validate_metrics(self) -> None:
        first_point = self.equity_curve[0]
        last_point = self.equity_curve[-1]
        if self.metrics.starting_equity != first_point.equity:
            raise ValueError("starting metric equity must match the first curve point")
        if self.metrics.ending_equity != last_point.equity:
            raise ValueError("ending metric equity must match the final curve point")
        self._validate_return_path()
        _require_close(
            self.metrics.total_return,
            last_point.cumulative_return,
            self.conventions,
            "total return",
        )
        _require_close(
            self.metrics.maximum_drawdown,
            max(point.drawdown for point in self.equity_curve),
            self.conventions,
            "maximum drawdown",
        )
        turnover_numerator = exact_decimal_sum(
            exact_decimal_add(trade.cost_basis, trade.proceeds) for trade in self.trades
        )
        _require_ratio_close(
            self.metrics.turnover,
            turnover_numerator,
            self.metrics.starting_equity,
            self.conventions,
            "turnover",
        )
        point_count = Decimal(len(self.equity_curve))
        _require_ratio_close(
            self.metrics.average_gross_exposure,
            exact_decimal_sum(point.gross_exposure for point in self.equity_curve),
            point_count,
            self.conventions,
            "average gross exposure",
        )
        _require_ratio_close(
            self.metrics.average_net_exposure,
            exact_decimal_sum(point.net_exposure for point in self.equity_curve),
            point_count,
            self.conventions,
            "average net exposure",
        )
        self._validate_trade_metrics()
        self._validate_position_metrics()
        if self.conventions.uncertainty_method is not UncertaintyMethod.NONE:
            raise ValueError("report cannot declare uncertainty without retained estimates")
        for field_name in (
            "annualized_return",
            "annualized_volatility",
            "sharpe_ratio",
            "sortino_ratio",
            "capacity_proxy",
        ):
            if getattr(self.metrics, field_name) is not None:
                raise ValueError(
                    f"{field_name} must be undefined without retained derivation evidence"
                )

    @property
    def accounting_evidence_sha256(self) -> str:
        return _sha256(
            (
                BACKTEST_REPORT_CONTRACT_VERSION,
                "accounting_evidence",
                self.execution_ledger_sha256,
                self.corporate_action_ledger_sha256,
                self.settlement_ledger_sha256,
                self.account_projection_sha256,
                tuple(entry.entry_sha256 for entry in self.ledger_trace),
            )
        )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            BACKTEST_REPORT_CONTRACT_VERSION,
            "report",
            self.account_id,
            self.currency,
            self.period_start,
            self.period_end,
            self.conventions.semantic_sha256,
            tuple(point.semantic_sha256 for point in self.equity_curve),
            tuple(trade.semantic_sha256 for trade in self.trades),
            tuple(position.semantic_sha256 for position in self.positions),
            tuple(entry.semantic_sha256 for entry in self.ledger_trace),
            self.metrics.semantic_sha256,
            self.execution_ledger_sha256,
            self.corporate_action_ledger_sha256,
            self.settlement_ledger_sha256,
            self.account_projection_sha256,
        )

    def _artifact_material(self, report_sha256: str) -> tuple[object, ...]:
        return (
            BACKTEST_REPORT_CONTRACT_VERSION,
            "report_artifact",
            report_sha256,
            self.generated_at,
        )

    @property
    def report_id(self) -> str:
        return self.report_sha256

    @property
    def artifact_id(self) -> str:
        return self.artifact_sha256

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def artifact_canonical_json(self) -> str:
        return canonical_json_text(self._artifact_material(self.report_sha256))


@dataclass(frozen=True, slots=True)
class DatasetReplayPin:
    """Upstream dataset and sealed replay proof consumed by the backtest."""

    dataset_manifest_sha256: str
    source_tape_sha256: str
    replay_run_id: str
    replay_manifest_sha256: str
    replay_input_sha256: str
    replay_semantic_sha256: str

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.dataset_manifest_sha256, "dataset manifest digest"),
            (self.source_tape_sha256, "source tape digest"),
            (self.replay_run_id, "replay run ID"),
            (self.replay_manifest_sha256, "replay manifest digest"),
            (self.replay_input_sha256, "replay input digest"),
            (self.replay_semantic_sha256, "replay semantic digest"),
        ):
            _require_sha256(value, field_name)
        if self.replay_run_id != self.replay_manifest_sha256:
            raise ValueError("replay run ID must equal its content-addressed manifest digest")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            "dataset_replay_pin_v1",
            self.dataset_manifest_sha256,
            self.source_tape_sha256,
            self.replay_run_id,
            self.replay_manifest_sha256,
            self.replay_input_sha256,
            self.replay_semantic_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class StrategyRunPin:
    """Exact strategy/configuration input plus optional terminal state proof."""

    strategy_id: str
    strategy_version: str
    strategy_configuration_sha256: str
    initial_state_sha256: str
    strategy_replay_sha256: str | None
    final_state_sha256: str | None

    def __post_init__(self) -> None:
        _require_text(self.strategy_id, "strategy ID")
        _require_text(self.strategy_version, "strategy version")
        _require_sha256(self.strategy_configuration_sha256, "strategy configuration digest")
        _require_sha256(self.initial_state_sha256, "initial strategy state digest")
        _require_optional_sha256(self.strategy_replay_sha256, "strategy replay digest")
        _require_optional_sha256(self.final_state_sha256, "final strategy state digest")
        if (self.strategy_replay_sha256 is None) != (self.final_state_sha256 is None):
            raise ValueError("strategy replay and final state evidence must appear together")

    def _input_material(self) -> tuple[object, ...]:
        return (
            "strategy_input_pin_v1",
            self.strategy_id,
            self.strategy_version,
            self.strategy_configuration_sha256,
            self.initial_state_sha256,
        )

    def _outcome_material(self) -> tuple[object, ...]:
        return (
            "strategy_outcome_pin_v1",
            self.strategy_replay_sha256,
            self.final_state_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256((self._input_material(), self._outcome_material()))


@dataclass(frozen=True, slots=True)
class BacktestContractPins:
    """Versioned pure-reducer and authority contracts used by one run."""

    strategy_replay_version: str
    order_reducer_version: str
    simulated_broker_version: str
    execution_ledger_version: str
    account_projection_version: str
    corporate_action_ledger_version: str
    settlement_ledger_version: str
    batch_risk_version: str
    account_coordinator_version: str
    decimal_arithmetic_version: str

    def __post_init__(self) -> None:
        for field_name in self.__dataclass_fields__:
            _require_text(getattr(self, field_name), field_name)

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            "backtest_contract_pins_v1",
            self.strategy_replay_version,
            self.order_reducer_version,
            self.simulated_broker_version,
            self.execution_ledger_version,
            self.account_projection_version,
            self.corporate_action_ledger_version,
            self.settlement_ledger_version,
            self.batch_risk_version,
            self.account_coordinator_version,
            self.decimal_arithmetic_version,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class BacktestRuntimePin:
    """Explicit code, dependency, image, schema, and numerical runtime pins."""

    source_revision: str
    dirty_patch_sha256: str
    dependency_lock_sha256: str
    container_image_sha256: str
    schema_revision: str
    python_version: str
    numerical_runtime_version: str
    tzdata_version: str
    rng_algorithm: str = NOT_APPLICABLE
    rng_seed: int | None = None

    def __post_init__(self) -> None:
        if (
            type(self.source_revision) is not str
            or _SOURCE_REVISION.fullmatch(self.source_revision) is None
        ):
            raise ValueError("source_revision must be a lowercase source commit digest")
        _require_sha256(self.dirty_patch_sha256, "dirty patch digest")
        _require_sha256(self.dependency_lock_sha256, "dependency lock digest")
        if self.container_image_sha256 != NOT_APPLICABLE:
            _require_sha256(self.container_image_sha256, "container image digest")
        for value, field_name in (
            (self.schema_revision, "schema revision"),
            (self.python_version, "Python version"),
            (self.numerical_runtime_version, "numerical runtime version"),
            (self.tzdata_version, "tzdata version"),
            (self.rng_algorithm, "RNG algorithm"),
        ):
            _require_text(value, field_name)
        if self.rng_algorithm == NOT_APPLICABLE:
            if self.rng_seed is not None:
                raise ValueError("rng_seed must be None when RNG is not applicable")
        elif type(self.rng_seed) is not int:
            raise ValueError("a declared RNG algorithm requires an exact integer seed")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            "backtest_runtime_pin_v1",
            self.source_revision,
            self.dirty_patch_sha256,
            self.dependency_lock_sha256,
            self.container_image_sha256,
            self.schema_revision,
            self.python_version,
            self.numerical_runtime_version,
            self.tzdata_version,
            self.rng_algorithm,
            self.rng_seed,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class BenchmarkPin:
    """Versioned total-return benchmark input."""

    benchmark_id: str
    benchmark_version: str
    content_sha256: str
    currency: str
    total_return: bool

    def __post_init__(self) -> None:
        _require_text(self.benchmark_id, "benchmark ID")
        _require_text(self.benchmark_version, "benchmark version")
        _require_sha256(self.content_sha256, "benchmark content digest")
        _require_currency(self.currency, "benchmark currency")
        if type(self.total_return) is not bool:
            raise ValueError("benchmark total_return must be a boolean")
        if not self.total_return:
            raise ValueError("backtest benchmarks must use a total-return series")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            "benchmark_pin_v1",
            self.benchmark_id,
            self.benchmark_version,
            self.content_sha256,
            self.currency,
            self.total_return,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class SimulationModelPin:
    """Exact configuration identity for a cost or fill model."""

    kind: SimulationModelKind
    model_id: str
    model_version: str
    configuration_sha256: str
    currency: str

    def __post_init__(self) -> None:
        if type(self.kind) is not SimulationModelKind:
            raise ValueError("simulation model kind must be exact")
        _require_text(self.model_id, "simulation model ID")
        _require_text(self.model_version, "simulation model version")
        _require_sha256(self.configuration_sha256, "simulation model configuration digest")
        _require_currency(self.currency, "simulation model currency")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            "simulation_model_pin_v1",
            self.kind.value,
            self.model_id,
            self.model_version,
            self.configuration_sha256,
            self.currency,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class BacktestRunResult:
    """Factory-constructed terminal worker result without raw exception text."""

    status: BacktestRunStatus
    started_at: datetime
    completed_at: datetime
    report_sha256: str | None
    report_artifact_sha256: str | None
    _construction_proof: InitVar[object]
    terminal_reason_code: str | None = None
    terminal_reason_sha256: str | None = None

    def __post_init__(self, _construction_proof: object) -> None:
        if _construction_proof is not _FACTORY_CONSTRUCTION_PROOF:
            raise ValueError("run results must be constructed by a terminal factory")
        if type(self.status) is not BacktestRunStatus:
            raise ValueError("run result status must be an exact BacktestRunStatus")
        if self.status in (BacktestRunStatus.QUEUED, BacktestRunStatus.RUNNING):
            raise ValueError("run result requires a terminal status")
        _require_utc(self.started_at, "run started_at")
        _require_utc(self.completed_at, "run completed_at")
        if self.completed_at < self.started_at:
            raise ValueError("run completed_at cannot precede started_at")
        _require_optional_sha256(self.report_sha256, "run report digest")
        _require_optional_sha256(self.report_artifact_sha256, "run report artifact digest")
        _require_optional_sha256(self.terminal_reason_sha256, "terminal reason digest")
        if self.status is BacktestRunStatus.COMPLETED:
            if self.report_sha256 is None or self.report_artifact_sha256 is None:
                raise ValueError("completed result requires report and artifact digests")
            if self.terminal_reason_code is not None or self.terminal_reason_sha256 is not None:
                raise ValueError("completed result cannot retain a terminal failure reason")
        else:
            if self.report_sha256 is not None or self.report_artifact_sha256 is not None:
                raise ValueError("failed or canceled result cannot retain report evidence")
            if self.terminal_reason_code is None or self.terminal_reason_sha256 is None:
                raise ValueError("failed or canceled result requires a reason code and digest")
            _require_text(self.terminal_reason_code, "terminal reason code")

    @classmethod
    def completed(
        cls,
        *,
        report: BacktestReport,
        started_at: datetime,
        completed_at: datetime,
    ) -> Self:
        if type(report) is not BacktestReport:
            raise ValueError("completed result requires an exact BacktestReport")
        if report.generated_at > completed_at:
            raise ValueError("report cannot be generated after run completion")
        return cls(
            status=BacktestRunStatus.COMPLETED,
            started_at=started_at,
            completed_at=completed_at,
            report_sha256=report.report_sha256,
            report_artifact_sha256=report.artifact_sha256,
            _construction_proof=_FACTORY_CONSTRUCTION_PROOF,
        )

    @classmethod
    def failed(
        cls,
        *,
        started_at: datetime,
        completed_at: datetime,
        terminal_reason_code: str,
        terminal_reason_sha256: str,
    ) -> Self:
        return cls._unsuccessful(
            status=BacktestRunStatus.FAILED,
            started_at=started_at,
            completed_at=completed_at,
            terminal_reason_code=terminal_reason_code,
            terminal_reason_sha256=terminal_reason_sha256,
        )

    @classmethod
    def canceled(
        cls,
        *,
        started_at: datetime,
        completed_at: datetime,
        terminal_reason_code: str,
        terminal_reason_sha256: str,
    ) -> Self:
        return cls._unsuccessful(
            status=BacktestRunStatus.CANCELED,
            started_at=started_at,
            completed_at=completed_at,
            terminal_reason_code=terminal_reason_code,
            terminal_reason_sha256=terminal_reason_sha256,
        )

    @classmethod
    def _unsuccessful(
        cls,
        *,
        status: BacktestRunStatus,
        started_at: datetime,
        completed_at: datetime,
        terminal_reason_code: str,
        terminal_reason_sha256: str,
    ) -> Self:
        if status not in (BacktestRunStatus.FAILED, BacktestRunStatus.CANCELED):
            raise ValueError("unsuccessful result factory requires failed or canceled status")
        return cls(
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            report_sha256=None,
            report_artifact_sha256=None,
            terminal_reason_code=terminal_reason_code,
            terminal_reason_sha256=terminal_reason_sha256,
            _construction_proof=_FACTORY_CONSTRUCTION_PROOF,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            "backtest_run_result_v2",
            self.status.value,
            self.started_at,
            self.completed_at,
            self.report_sha256,
            self.report_artifact_sha256,
            self.terminal_reason_code,
            self.terminal_reason_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class BacktestRunManifest:
    """Factory-bound provenance for one terminal fixture backtest attempt."""

    dataset_replay: DatasetReplayPin
    strategy: StrategyRunPin
    contracts: BacktestContractPins
    runtime: BacktestRuntimePin
    benchmark: BenchmarkPin
    cost_model: SimulationModelPin
    fill_model: SimulationModelPin
    metric_conventions_sha256: str
    result: BacktestRunResult
    execution_evidence_sha256: str | None
    accounting_evidence_sha256: str | None
    risk_evidence_sha256: str | None
    coordinator_evidence_sha256: str | None
    _construction_proof: InitVar[object]
    input_sha256: str = field(init=False)
    manifest_sha256: str = field(init=False)
    run_id: str = field(init=False)

    def __post_init__(self, _construction_proof: object) -> None:
        if _construction_proof is not _FACTORY_CONSTRUCTION_PROOF:
            raise ValueError("run manifests must be constructed by a terminal factory")
        for value, exact_type, field_name in (
            (self.dataset_replay, DatasetReplayPin, "dataset replay pin"),
            (self.strategy, StrategyRunPin, "strategy pin"),
            (self.contracts, BacktestContractPins, "contract pins"),
            (self.runtime, BacktestRuntimePin, "runtime pin"),
            (self.benchmark, BenchmarkPin, "benchmark pin"),
            (self.cost_model, SimulationModelPin, "cost model pin"),
            (self.fill_model, SimulationModelPin, "fill model pin"),
            (self.result, BacktestRunResult, "run result"),
        ):
            if type(value) is not exact_type:
                raise ValueError(f"manifest requires an exact {field_name}")
        if self.cost_model.kind is not SimulationModelKind.COST:
            raise ValueError("cost_model must carry the cost model kind")
        if self.fill_model.kind is not SimulationModelKind.FILL:
            raise ValueError("fill_model must carry the fill model kind")
        currencies = {
            self.benchmark.currency,
            self.cost_model.currency,
            self.fill_model.currency,
        }
        if len(currencies) != 1:
            raise ValueError("benchmark, cost, and fill model currencies must match")
        _require_sha256(self.metric_conventions_sha256, "metric conventions digest")
        evidence = (
            self.execution_evidence_sha256,
            self.accounting_evidence_sha256,
            self.risk_evidence_sha256,
            self.coordinator_evidence_sha256,
        )
        for evidence_value, field_name in zip(
            evidence,
            (
                "execution evidence digest",
                "accounting evidence digest",
                "risk evidence digest",
                "coordinator evidence digest",
            ),
            strict=True,
        ):
            _require_optional_sha256(evidence_value, field_name)
        if self.result.status is BacktestRunStatus.COMPLETED:
            if any(value is None for value in evidence):
                raise ValueError("completed manifest requires all execution and control evidence")
            if self.strategy.strategy_replay_sha256 is None:
                raise ValueError("completed manifest requires terminal strategy evidence")
        elif any(value is not None for value in evidence):
            raise ValueError("failed or canceled manifests cannot claim completion evidence")

        input_sha256 = _sha256(self._input_material())
        object.__setattr__(self, "input_sha256", input_sha256)
        manifest_sha256 = _sha256(self._manifest_material(input_sha256))
        object.__setattr__(self, "manifest_sha256", manifest_sha256)
        object.__setattr__(self, "run_id", manifest_sha256)

    @classmethod
    def completed(
        cls,
        *,
        report: BacktestReport,
        dataset_replay: DatasetReplayPin,
        strategy: StrategyRunPin,
        contracts: BacktestContractPins,
        runtime: BacktestRuntimePin,
        benchmark: BenchmarkPin,
        cost_model: SimulationModelPin,
        fill_model: SimulationModelPin,
        started_at: datetime,
        completed_at: datetime,
        execution_evidence_sha256: str,
        risk_evidence_sha256: str,
        coordinator_evidence_sha256: str,
    ) -> Self:
        """Bind a completed report to its explicit input and reducer evidence."""

        if type(report) is not BacktestReport:
            raise ValueError("manifest factory requires an exact BacktestReport")
        currencies = {
            report.currency,
            benchmark.currency,
            cost_model.currency,
            fill_model.currency,
        }
        if len(currencies) != 1:
            raise ValueError("report and all model currencies must match")
        result = BacktestRunResult.completed(
            report=report,
            started_at=started_at,
            completed_at=completed_at,
        )
        return cls(
            dataset_replay=dataset_replay,
            strategy=strategy,
            contracts=contracts,
            runtime=runtime,
            benchmark=benchmark,
            cost_model=cost_model,
            fill_model=fill_model,
            metric_conventions_sha256=report.conventions.semantic_sha256,
            result=result,
            execution_evidence_sha256=execution_evidence_sha256,
            accounting_evidence_sha256=report.accounting_evidence_sha256,
            risk_evidence_sha256=risk_evidence_sha256,
            coordinator_evidence_sha256=coordinator_evidence_sha256,
            _construction_proof=_FACTORY_CONSTRUCTION_PROOF,
        )

    @classmethod
    def from_report(
        cls,
        *,
        report: BacktestReport,
        dataset_replay: DatasetReplayPin,
        strategy: StrategyRunPin,
        contracts: BacktestContractPins,
        runtime: BacktestRuntimePin,
        benchmark: BenchmarkPin,
        cost_model: SimulationModelPin,
        fill_model: SimulationModelPin,
        started_at: datetime,
        completed_at: datetime,
        execution_evidence_sha256: str,
        risk_evidence_sha256: str,
        coordinator_evidence_sha256: str,
    ) -> Self:
        """Compatibility alias for the proof-constructing completed factory."""

        return cls.completed(
            report=report,
            dataset_replay=dataset_replay,
            strategy=strategy,
            contracts=contracts,
            runtime=runtime,
            benchmark=benchmark,
            cost_model=cost_model,
            fill_model=fill_model,
            started_at=started_at,
            completed_at=completed_at,
            execution_evidence_sha256=execution_evidence_sha256,
            risk_evidence_sha256=risk_evidence_sha256,
            coordinator_evidence_sha256=coordinator_evidence_sha256,
        )

    @classmethod
    def failed(
        cls,
        *,
        dataset_replay: DatasetReplayPin,
        strategy: StrategyRunPin,
        contracts: BacktestContractPins,
        runtime: BacktestRuntimePin,
        benchmark: BenchmarkPin,
        cost_model: SimulationModelPin,
        fill_model: SimulationModelPin,
        metric_conventions: BacktestMetricConventions,
        started_at: datetime,
        completed_at: datetime,
        terminal_reason_code: str,
        terminal_reason_sha256: str,
    ) -> Self:
        return cls._unsuccessful(
            status=BacktestRunStatus.FAILED,
            dataset_replay=dataset_replay,
            strategy=strategy,
            contracts=contracts,
            runtime=runtime,
            benchmark=benchmark,
            cost_model=cost_model,
            fill_model=fill_model,
            metric_conventions=metric_conventions,
            started_at=started_at,
            completed_at=completed_at,
            terminal_reason_code=terminal_reason_code,
            terminal_reason_sha256=terminal_reason_sha256,
        )

    @classmethod
    def canceled(
        cls,
        *,
        dataset_replay: DatasetReplayPin,
        strategy: StrategyRunPin,
        contracts: BacktestContractPins,
        runtime: BacktestRuntimePin,
        benchmark: BenchmarkPin,
        cost_model: SimulationModelPin,
        fill_model: SimulationModelPin,
        metric_conventions: BacktestMetricConventions,
        started_at: datetime,
        completed_at: datetime,
        terminal_reason_code: str,
        terminal_reason_sha256: str,
    ) -> Self:
        return cls._unsuccessful(
            status=BacktestRunStatus.CANCELED,
            dataset_replay=dataset_replay,
            strategy=strategy,
            contracts=contracts,
            runtime=runtime,
            benchmark=benchmark,
            cost_model=cost_model,
            fill_model=fill_model,
            metric_conventions=metric_conventions,
            started_at=started_at,
            completed_at=completed_at,
            terminal_reason_code=terminal_reason_code,
            terminal_reason_sha256=terminal_reason_sha256,
        )

    @classmethod
    def _unsuccessful(
        cls,
        *,
        status: BacktestRunStatus,
        dataset_replay: DatasetReplayPin,
        strategy: StrategyRunPin,
        contracts: BacktestContractPins,
        runtime: BacktestRuntimePin,
        benchmark: BenchmarkPin,
        cost_model: SimulationModelPin,
        fill_model: SimulationModelPin,
        metric_conventions: BacktestMetricConventions,
        started_at: datetime,
        completed_at: datetime,
        terminal_reason_code: str,
        terminal_reason_sha256: str,
    ) -> Self:
        if status not in (BacktestRunStatus.FAILED, BacktestRunStatus.CANCELED):
            raise ValueError("unsuccessful manifest factory requires failed or canceled status")
        if type(metric_conventions) is not BacktestMetricConventions:
            raise ValueError("terminal manifest requires exact metric conventions")
        currencies = {
            metric_conventions.currency,
            benchmark.currency,
            cost_model.currency,
            fill_model.currency,
        }
        if len(currencies) != 1:
            raise ValueError("metric conventions and all model currencies must match")
        result_factory = (
            BacktestRunResult.failed
            if status is BacktestRunStatus.FAILED
            else BacktestRunResult.canceled
        )
        result = result_factory(
            started_at=started_at,
            completed_at=completed_at,
            terminal_reason_code=terminal_reason_code,
            terminal_reason_sha256=terminal_reason_sha256,
        )
        return cls(
            dataset_replay=dataset_replay,
            strategy=strategy,
            contracts=contracts,
            runtime=runtime,
            benchmark=benchmark,
            cost_model=cost_model,
            fill_model=fill_model,
            metric_conventions_sha256=metric_conventions.semantic_sha256,
            result=result,
            execution_evidence_sha256=None,
            accounting_evidence_sha256=None,
            risk_evidence_sha256=None,
            coordinator_evidence_sha256=None,
            _construction_proof=_FACTORY_CONSTRUCTION_PROOF,
        )

    def _input_material(self) -> tuple[object, ...]:
        return (
            BACKTEST_RUN_MANIFEST_CONTRACT_VERSION,
            "input",
            self.dataset_replay._semantic_material(),
            self.strategy._input_material(),
            self.contracts._semantic_material(),
            self.runtime._semantic_material(),
            self.benchmark._semantic_material(),
            self.cost_model._semantic_material(),
            self.fill_model._semantic_material(),
            self.metric_conventions_sha256,
        )

    def _outcome_material(self) -> tuple[object, ...]:
        return (
            "outcome",
            self.strategy._outcome_material(),
            self.result._semantic_material(),
            self.execution_evidence_sha256,
            self.accounting_evidence_sha256,
            self.risk_evidence_sha256,
            self.coordinator_evidence_sha256,
        )

    def _manifest_material(self, input_sha256: str) -> tuple[object, ...]:
        return (
            BACKTEST_RUN_MANIFEST_CONTRACT_VERSION,
            "manifest",
            self._input_material(),
            input_sha256,
            self._outcome_material(),
        )

    @property
    def idempotency_key(self) -> str:
        return self.input_sha256

    @property
    def report_sha256(self) -> str | None:
        return self.result.report_sha256

    @property
    def report_artifact_sha256(self) -> str | None:
        return self.result.report_artifact_sha256

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._manifest_material(self.input_sha256))
