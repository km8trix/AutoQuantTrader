"""Transactional persistence for the Phase 2C fixture-only research workflow."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum
from typing import Any, cast

import sqlalchemy as sa
from sqlalchemy import Connection, Engine
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import RowMapping

from packages.domain.backtest_job import (
    BACKTEST_JOB_CONTRACT_VERSION,
    BacktestJob,
    BacktestJobConflict,
    BacktestJobEvent,
    BacktestJobInput,
    BacktestJobProjection,
    BacktestJobStatus,
    cancel_queued_backtest_job,
    cancel_running_backtest_job,
    claim_backtest_job,
    complete_backtest_job,
    create_backtest_job,
    fail_backtest_job,
)
from packages.domain.backtest_report import (
    BACKTEST_RUN_MANIFEST_CONTRACT_VERSION,
    BacktestEquityPoint,
    BacktestLedgerTraceEntry,
    BacktestMetricConventions,
    BacktestMetrics,
    BacktestPosition,
    BacktestReport,
    BacktestReturnFrequency,
    BacktestReturnType,
    BacktestRunManifest,
    BacktestRunStatus,
    BacktestTrade,
    ExternalCashFlowTreatment,
    UncertaintyMethod,
)
from packages.domain.canonical import (
    canonical_decimal,
    canonical_json_bytes,
    canonical_json_text,
    canonical_persisted_decimal,
)
from packages.domain.experiment_registry import (
    EXPERIMENT_REGISTRY_CONTRACT_VERSION,
    StrategyConfigurationRecord,
    StrategyConfigurationSchemaMismatch,
    StrategyParameterSchemaError,
    StrategyVersionRecord,
    validate_strategy_configuration_parameters,
)
from packages.persistence.immutable import (
    ImmutableFactConflict,
    as_aware_utc,
    assert_immutable,
    insert_or_verify_atomic,
)
from packages.persistence.schema import (
    phase2_backtest_audit_events,
    phase2_backtest_fixtures,
    phase2_backtest_job_events,
    phase2_backtest_job_heads,
    phase2_backtest_jobs,
    phase2_backtest_reports,
    phase2_backtest_run_manifests,
    phase2_strategy_configurations,
    phase2_strategy_versions,
)

_SUPPORTED_DIALECTS = frozenset({"sqlite", "postgresql"})
WorkflowRow = Mapping[str, Any] | RowMapping


class BacktestWorkflowError(RuntimeError):
    """Durable research evidence is unavailable, malformed, or conflicting."""


class BacktestWorkflowConflict(BacktestWorkflowError):
    """An idempotency key or immutable fact conflicts with prior evidence."""


@dataclass(frozen=True, slots=True)
class StrategyCatalogRecord:
    strategy_version_id: str
    strategy_id: str
    strategy_version: str
    display_name: str
    configuration_sha256: str
    configuration_name: str
    parameter_schema_payload: str
    parameters_payload: str
    fixture_id: str
    fixture_version: str
    dataset_manifest_sha256: str
    replay_run_id: str
    benchmark_sha256: str
    cost_model_sha256: str
    fill_model_sha256: str
    metric_conventions_sha256: str


@dataclass(frozen=True, slots=True)
class BacktestJobEventSnapshot:
    sequence: int
    status: BacktestJobStatus
    occurred_at: datetime
    actor_id: str
    attempt_number: int
    terminal_reason_code: str | None


@dataclass(frozen=True, slots=True)
class BacktestJobSnapshot:
    job_id: str
    input_sha256: str
    fixture_id: str
    fixture_version: str
    strategy_id: str
    strategy_version: str
    strategy_configuration_sha256: str
    requested_by: str
    requested_at: datetime
    status: BacktestJobStatus
    attempt_number: int
    worker_id: str | None
    claim_expires_at: datetime | None
    updated_at: datetime
    run_manifest_sha256: str | None
    report_sha256: str | None
    report_artifact_sha256: str | None
    terminal_reason_code: str | None
    history: tuple[BacktestJobEventSnapshot, ...]


@dataclass(frozen=True, slots=True)
class BacktestReportSnapshot:
    report_sha256: str
    report_artifact_sha256: str
    account_id: str
    currency: str
    period_start: datetime
    period_end: datetime
    generated_at: datetime
    starting_equity: Decimal
    ending_equity: Decimal
    total_return: Decimal
    maximum_drawdown: Decimal
    turnover: Decimal
    trade_count: int
    realized_pnl: Decimal
    unrealized_pnl: Decimal
    dividend_income: Decimal
    total_execution_costs: Decimal
    semantic_payload: str
    query_payload: Mapping[str, object]


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _payload_sha256(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _query_json_value(value: object) -> object:
    if value is None or type(value) in {bool, int, str}:
        return value
    if isinstance(value, Decimal):
        return format(canonical_decimal(value), "f")
    if isinstance(value, datetime):
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, Enum):
        return _query_json_value(value.value)
    if isinstance(value, Mapping):
        return {str(key): _query_json_value(item) for key, item in value.items()}
    if type(value) in {tuple, list}:
        return [_query_json_value(item) for item in cast(list[object] | tuple[object, ...], value)]
    raise BacktestWorkflowError(f"unsupported report query value {type(value).__qualname__}")


def _report_query_payload(report: BacktestReport) -> str:
    payload = {
        "report_sha256": report.report_sha256,
        "report_artifact_sha256": report.artifact_sha256,
        "account_id": report.account_id,
        "currency": report.currency,
        "period_start": report.period_start,
        "period_end": report.period_end,
        "generated_at": report.generated_at,
        "conventions": asdict(report.conventions),
        "metrics": asdict(report.metrics),
        "equity_curve": [asdict(point) for point in report.equity_curve],
        "trades": [asdict(trade) for trade in report.trades],
        "positions": [asdict(position) for position in report.positions],
        "ledger_trace": [asdict(entry) for entry in report.ledger_trace],
        "provenance": {
            "execution_ledger_sha256": report.execution_ledger_sha256,
            "corporate_action_ledger_sha256": report.corporate_action_ledger_sha256,
            "settlement_ledger_sha256": report.settlement_ledger_sha256,
            "account_projection_sha256": report.account_projection_sha256,
            "accounting_evidence_sha256": report.accounting_evidence_sha256,
        },
    }
    return json.dumps(
        _query_json_value(payload),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _canonical_material(payload: str, field_name: str) -> tuple[object, ...]:
    """Decode the small typed-canonical subset used by strategy catalog facts."""

    try:
        node = json.loads(payload)
        material = _canonical_node(node, field_name)
    except (ArithmeticError, TypeError, ValueError) as error:
        raise BacktestWorkflowError(f"persisted {field_name} is malformed") from error
    if type(material) is not tuple or canonical_json_text(material) != payload:
        raise BacktestWorkflowError(f"persisted {field_name} is not canonical")
    return material


def _canonical_node(node: object, field_name: str) -> object:
    if type(node) is not dict:
        raise ValueError(f"{field_name} node must be an object")
    value = cast(dict[str, object], node)
    if set(value) != {"type", "value"} or type(value["type"]) is not str:
        raise ValueError(f"{field_name} node has an unsupported shape")
    kind = value["type"]
    raw = value["value"]
    if kind == "null":
        if raw is not None:
            raise ValueError(f"{field_name} null node is malformed")
        return None
    if kind == "bool":
        if type(raw) is not bool:
            raise ValueError(f"{field_name} bool node is malformed")
        return raw
    if kind == "int":
        if type(raw) is not str:
            raise ValueError(f"{field_name} integer node is malformed")
        return int(raw)
    if kind == "decimal":
        if type(raw) is not str:
            raise ValueError(f"{field_name} decimal node is malformed")
        return Decimal(raw)
    if kind == "string":
        if type(raw) is not str:
            raise ValueError(f"{field_name} string node is malformed")
        return raw
    if kind == "datetime":
        if type(raw) is not str or not raw.endswith("Z"):
            raise ValueError(f"{field_name} datetime node is malformed")
        return datetime.fromisoformat(raw[:-1] + "+00:00").astimezone(UTC)
    if kind == "tuple":
        if type(raw) is not list:
            raise ValueError(f"{field_name} tuple node is malformed")
        return tuple(_canonical_node(item, field_name) for item in cast(list[object], raw))
    raise ValueError(f"{field_name} contains unsupported canonical type {kind!r}")


def _query_object(
    value: object,
    field_name: str,
    expected_fields: frozenset[str],
) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError(f"{field_name} must be an object")
    result = cast(dict[object, object], value)
    if any(type(key) is not str for key in result) or set(result) != expected_fields:
        raise ValueError(f"{field_name} fields do not match the report contract")
    return cast(dict[str, object], result)


def _query_list(value: object, field_name: str) -> list[object]:
    if type(value) is not list:
        raise ValueError(f"{field_name} must be an array")
    return cast(list[object], value)


def _query_text(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise ValueError(f"{field_name} must be text")
    return value


def _query_integer(value: object, field_name: str) -> int:
    if type(value) is not int:
        raise ValueError(f"{field_name} must be an integer")
    return value


def _query_decimal(value: object, field_name: str) -> Decimal:
    if type(value) is not str:
        raise ValueError(f"{field_name} must be decimal text")
    return canonical_persisted_decimal(Decimal(value), field_name)


def _query_optional_decimal(value: object, field_name: str) -> Decimal | None:
    return None if value is None else _query_decimal(value, field_name)


def _query_datetime(value: object, field_name: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise ValueError(f"{field_name} must be a UTC timestamp")
    return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(UTC)


_REPORT_QUERY_FIELDS = frozenset(
    {
        "report_sha256",
        "report_artifact_sha256",
        "account_id",
        "currency",
        "period_start",
        "period_end",
        "generated_at",
        "conventions",
        "metrics",
        "equity_curve",
        "trades",
        "positions",
        "ledger_trace",
        "provenance",
    }
)
_CONVENTION_QUERY_FIELDS = frozenset(
    {
        "convention_id",
        "convention_version",
        "currency",
        "return_type",
        "return_frequency",
        "annualization_periods",
        "annual_risk_free_rate",
        "risk_free_rate_version",
        "external_cash_flow_treatment",
        "uncertainty_method",
        "absolute_tolerance",
        "relative_tolerance",
    }
)
_METRIC_QUERY_FIELDS = frozenset(
    {
        "starting_equity",
        "ending_equity",
        "total_return",
        "annualized_return",
        "annualized_volatility",
        "sharpe_ratio",
        "sortino_ratio",
        "maximum_drawdown",
        "turnover",
        "average_gross_exposure",
        "average_net_exposure",
        "trade_count",
        "winning_trade_count",
        "losing_trade_count",
        "breakeven_trade_count",
        "hit_rate",
        "profit_factor",
        "total_execution_costs",
        "capacity_proxy",
        "realized_pnl",
        "unrealized_pnl",
        "dividend_income",
    }
)
_EQUITY_QUERY_FIELDS = frozenset(
    {
        "sequence",
        "as_of",
        "cash",
        "market_value",
        "equity",
        "gross_exposure",
        "net_exposure",
        "cumulative_external_cash_flow",
        "period_return",
        "cumulative_return",
        "drawdown",
    }
)
_TRADE_QUERY_FIELDS = frozenset(
    {
        "sequence",
        "trade_id",
        "instrument_id",
        "symbol",
        "opened_at",
        "closed_at",
        "quantity",
        "cost_basis",
        "proceeds",
        "gross_pnl",
        "execution_costs",
        "net_pnl",
        "opening_execution_sha256",
        "closing_execution_sha256",
    }
)
_POSITION_QUERY_FIELDS = frozenset(
    {
        "sequence",
        "as_of",
        "instrument_id",
        "symbol",
        "quantity",
        "cost_basis",
        "mark_price",
        "market_value",
        "realized_pnl",
        "unrealized_pnl",
        "execution_costs",
        "dividend_income",
        "source_projection_sha256",
    }
)
_LEDGER_QUERY_FIELDS = frozenset(
    {
        "sequence",
        "entry_id",
        "entry_kind",
        "source_fact_id",
        "effective_at",
        "recorded_at",
        "entry_sha256",
    }
)
_PROVENANCE_QUERY_FIELDS = frozenset(
    {
        "execution_ledger_sha256",
        "corporate_action_ledger_sha256",
        "settlement_ledger_sha256",
        "account_projection_sha256",
        "accounting_evidence_sha256",
    }
)


def _conventions_from_query(value: object) -> BacktestMetricConventions:
    row = _query_object(value, "report conventions", _CONVENTION_QUERY_FIELDS)
    return BacktestMetricConventions(
        convention_id=_query_text(row["convention_id"], "convention ID"),
        convention_version=_query_text(row["convention_version"], "convention version"),
        currency=_query_text(row["currency"], "convention currency"),
        return_type=BacktestReturnType(_query_text(row["return_type"], "return type")),
        return_frequency=BacktestReturnFrequency(
            _query_text(row["return_frequency"], "return frequency")
        ),
        annualization_periods=_query_integer(row["annualization_periods"], "annualization periods"),
        annual_risk_free_rate=_query_decimal(row["annual_risk_free_rate"], "annual risk-free rate"),
        risk_free_rate_version=_query_text(row["risk_free_rate_version"], "risk-free rate version"),
        external_cash_flow_treatment=ExternalCashFlowTreatment(
            _query_text(
                row["external_cash_flow_treatment"],
                "external cash-flow treatment",
            )
        ),
        uncertainty_method=UncertaintyMethod(
            _query_text(row["uncertainty_method"], "uncertainty method")
        ),
        absolute_tolerance=_query_decimal(row["absolute_tolerance"], "absolute tolerance"),
        relative_tolerance=_query_decimal(row["relative_tolerance"], "relative tolerance"),
    )


def _metrics_from_query(value: object) -> BacktestMetrics:
    row = _query_object(value, "report metrics", _METRIC_QUERY_FIELDS)
    return BacktestMetrics(
        starting_equity=_query_decimal(row["starting_equity"], "starting equity"),
        ending_equity=_query_decimal(row["ending_equity"], "ending equity"),
        total_return=_query_decimal(row["total_return"], "total return"),
        annualized_return=_query_optional_decimal(row["annualized_return"], "annualized return"),
        annualized_volatility=_query_optional_decimal(
            row["annualized_volatility"], "annualized volatility"
        ),
        sharpe_ratio=_query_optional_decimal(row["sharpe_ratio"], "Sharpe ratio"),
        sortino_ratio=_query_optional_decimal(row["sortino_ratio"], "Sortino ratio"),
        maximum_drawdown=_query_decimal(row["maximum_drawdown"], "maximum drawdown"),
        turnover=_query_decimal(row["turnover"], "turnover"),
        average_gross_exposure=_query_decimal(
            row["average_gross_exposure"], "average gross exposure"
        ),
        average_net_exposure=_query_decimal(row["average_net_exposure"], "average net exposure"),
        trade_count=_query_integer(row["trade_count"], "trade count"),
        winning_trade_count=_query_integer(row["winning_trade_count"], "winning trade count"),
        losing_trade_count=_query_integer(row["losing_trade_count"], "losing trade count"),
        breakeven_trade_count=_query_integer(row["breakeven_trade_count"], "breakeven trade count"),
        hit_rate=_query_optional_decimal(row["hit_rate"], "hit rate"),
        profit_factor=_query_optional_decimal(row["profit_factor"], "profit factor"),
        total_execution_costs=_query_decimal(row["total_execution_costs"], "total execution costs"),
        capacity_proxy=_query_optional_decimal(row["capacity_proxy"], "capacity proxy"),
        realized_pnl=_query_decimal(row["realized_pnl"], "realized P&L"),
        unrealized_pnl=_query_decimal(row["unrealized_pnl"], "unrealized P&L"),
        dividend_income=_query_decimal(row["dividend_income"], "dividend income"),
    )


def _equity_from_query(value: object) -> BacktestEquityPoint:
    row = _query_object(value, "equity point", _EQUITY_QUERY_FIELDS)
    return BacktestEquityPoint(
        sequence=_query_integer(row["sequence"], "equity sequence"),
        as_of=_query_datetime(row["as_of"], "equity as_of"),
        cash=_query_decimal(row["cash"], "equity cash"),
        market_value=_query_decimal(row["market_value"], "equity market value"),
        equity=_query_decimal(row["equity"], "equity value"),
        gross_exposure=_query_decimal(row["gross_exposure"], "equity gross exposure"),
        net_exposure=_query_decimal(row["net_exposure"], "equity net exposure"),
        cumulative_external_cash_flow=_query_decimal(
            row["cumulative_external_cash_flow"], "cumulative external cash flow"
        ),
        period_return=_query_decimal(row["period_return"], "period return"),
        cumulative_return=_query_decimal(row["cumulative_return"], "cumulative return"),
        drawdown=_query_decimal(row["drawdown"], "drawdown"),
    )


def _trade_from_query(value: object) -> BacktestTrade:
    row = _query_object(value, "trade", _TRADE_QUERY_FIELDS)
    return BacktestTrade(
        sequence=_query_integer(row["sequence"], "trade sequence"),
        trade_id=_query_text(row["trade_id"], "trade ID"),
        instrument_id=_query_text(row["instrument_id"], "trade instrument ID"),
        symbol=_query_text(row["symbol"], "trade symbol"),
        opened_at=_query_datetime(row["opened_at"], "trade opened_at"),
        closed_at=_query_datetime(row["closed_at"], "trade closed_at"),
        quantity=_query_decimal(row["quantity"], "trade quantity"),
        cost_basis=_query_decimal(row["cost_basis"], "trade cost basis"),
        proceeds=_query_decimal(row["proceeds"], "trade proceeds"),
        gross_pnl=_query_decimal(row["gross_pnl"], "trade gross P&L"),
        execution_costs=_query_decimal(row["execution_costs"], "trade execution costs"),
        net_pnl=_query_decimal(row["net_pnl"], "trade net P&L"),
        opening_execution_sha256=_query_text(
            row["opening_execution_sha256"], "opening execution digest"
        ),
        closing_execution_sha256=_query_text(
            row["closing_execution_sha256"], "closing execution digest"
        ),
    )


def _position_from_query(value: object) -> BacktestPosition:
    row = _query_object(value, "position", _POSITION_QUERY_FIELDS)
    return BacktestPosition(
        sequence=_query_integer(row["sequence"], "position sequence"),
        as_of=_query_datetime(row["as_of"], "position as_of"),
        instrument_id=_query_text(row["instrument_id"], "position instrument ID"),
        symbol=_query_text(row["symbol"], "position symbol"),
        quantity=_query_decimal(row["quantity"], "position quantity"),
        cost_basis=_query_decimal(row["cost_basis"], "position cost basis"),
        mark_price=_query_decimal(row["mark_price"], "position mark price"),
        market_value=_query_decimal(row["market_value"], "position market value"),
        realized_pnl=_query_decimal(row["realized_pnl"], "position realized P&L"),
        unrealized_pnl=_query_decimal(row["unrealized_pnl"], "position unrealized P&L"),
        execution_costs=_query_decimal(row["execution_costs"], "position execution costs"),
        dividend_income=_query_decimal(row["dividend_income"], "position dividend income"),
        source_projection_sha256=_query_text(
            row["source_projection_sha256"], "position source projection digest"
        ),
    )


def _ledger_entry_from_query(value: object) -> BacktestLedgerTraceEntry:
    row = _query_object(value, "ledger trace entry", _LEDGER_QUERY_FIELDS)
    return BacktestLedgerTraceEntry(
        sequence=_query_integer(row["sequence"], "ledger trace sequence"),
        entry_id=_query_text(row["entry_id"], "ledger trace entry ID"),
        entry_kind=_query_text(row["entry_kind"], "ledger trace entry kind"),
        source_fact_id=_query_text(row["source_fact_id"], "ledger trace source fact ID"),
        effective_at=_query_datetime(row["effective_at"], "ledger trace effective_at"),
        recorded_at=_query_datetime(row["recorded_at"], "ledger trace recorded_at"),
        entry_sha256=_query_text(row["entry_sha256"], "ledger trace entry digest"),
    )


def _report_from_query(value: object) -> BacktestReport:
    row = _query_object(value, "report query payload", _REPORT_QUERY_FIELDS)
    provenance = _query_object(row["provenance"], "report provenance", _PROVENANCE_QUERY_FIELDS)
    report = BacktestReport(
        account_id=_query_text(row["account_id"], "report account ID"),
        currency=_query_text(row["currency"], "report currency"),
        period_start=_query_datetime(row["period_start"], "report period_start"),
        period_end=_query_datetime(row["period_end"], "report period_end"),
        generated_at=_query_datetime(row["generated_at"], "report generated_at"),
        conventions=_conventions_from_query(row["conventions"]),
        equity_curve=tuple(
            _equity_from_query(item) for item in _query_list(row["equity_curve"], "equity curve")
        ),
        trades=tuple(_trade_from_query(item) for item in _query_list(row["trades"], "trades")),
        positions=tuple(
            _position_from_query(item) for item in _query_list(row["positions"], "positions")
        ),
        ledger_trace=tuple(
            _ledger_entry_from_query(item)
            for item in _query_list(row["ledger_trace"], "ledger trace")
        ),
        metrics=_metrics_from_query(row["metrics"]),
        execution_ledger_sha256=_query_text(
            provenance["execution_ledger_sha256"], "execution ledger digest"
        ),
        corporate_action_ledger_sha256=_query_text(
            provenance["corporate_action_ledger_sha256"],
            "corporate-action ledger digest",
        ),
        settlement_ledger_sha256=_query_text(
            provenance["settlement_ledger_sha256"], "settlement ledger digest"
        ),
        account_projection_sha256=_query_text(
            provenance["account_projection_sha256"], "account projection digest"
        ),
    )
    if _query_text(row["report_sha256"], "report digest") != report.report_sha256:
        raise ValueError("report query identity conflicts with retained economic evidence")
    if (
        _query_text(row["report_artifact_sha256"], "report artifact digest")
        != report.artifact_sha256
    ):
        raise ValueError("report query artifact conflicts with retained report identity")
    if (
        _query_text(
            provenance["accounting_evidence_sha256"],
            "accounting evidence digest",
        )
        != report.accounting_evidence_sha256
    ):
        raise ValueError("report query accounting evidence digest conflicts")
    return report


def _required_text(row: WorkflowRow, field_name: str) -> str:
    value = row[field_name]
    if type(value) is not str or not value or value != value.strip():
        raise BacktestWorkflowError(f"persisted {field_name} is malformed")
    return value


def _optional_text(row: WorkflowRow, field_name: str) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str or not value or value != value.strip():
        raise BacktestWorkflowError(f"persisted {field_name} is malformed")
    return value


def _required_integer(row: WorkflowRow, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise BacktestWorkflowError(f"persisted {field_name} is malformed")
    return value


def _required_datetime(row: WorkflowRow, field_name: str) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise BacktestWorkflowError(f"persisted {field_name} is malformed")
    return as_aware_utc(value)


def _optional_datetime(row: WorkflowRow, field_name: str) -> datetime | None:
    value = row[field_name]
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise BacktestWorkflowError(f"persisted {field_name} is malformed")
    return as_aware_utc(value)


def _required_decimal(row: WorkflowRow, field_name: str) -> Decimal:
    try:
        value = Decimal(str(row[field_name]))
        return canonical_persisted_decimal(value, field_name)
    except (ArithmeticError, TypeError, ValueError) as error:
        raise BacktestWorkflowError(f"persisted {field_name} is malformed") from error


@contextmanager
def _write_transaction(engine: Engine) -> Iterator[Connection]:
    with engine.connect() as connection:
        if connection.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()
            return
        if connection.dialect.name == "postgresql":
            with connection.begin():
                yield connection
            return
        raise BacktestWorkflowError(
            f"backtest workflow does not support SQL dialect {connection.dialect.name!r}"
        )


def _locked(statement: sa.Select[Any], connection: Connection) -> sa.Select[Any]:
    return statement.with_for_update() if connection.dialect.name == "postgresql" else statement


def _insert_job_if_absent(
    connection: Connection,
    values: Mapping[str, Any],
) -> bool:
    """Insert a launch identity without confusing a lost race with a conflict."""

    if connection.dialect.name == "postgresql":
        statement = (
            postgresql_insert(phase2_backtest_jobs)
            .values(**dict(values))
            .on_conflict_do_nothing()
            .returning(sa.literal(True))
        )
    elif connection.dialect.name == "sqlite":
        statement = (
            sqlite_insert(phase2_backtest_jobs)
            .values(**dict(values))
            .on_conflict_do_nothing()
            .returning(sa.literal(True))
        )
    else:
        raise BacktestWorkflowError(
            f"backtest workflow does not support SQL dialect {connection.dialect.name!r}"
        )
    return connection.execute(statement).scalar_one_or_none() is not None


def _version_material(version: StrategyVersionRecord) -> tuple[object, ...]:
    return (
        EXPERIMENT_REGISTRY_CONTRACT_VERSION,
        "strategy_version",
        version.strategy_id,
        version.strategy_version,
        version.code_sha256,
        version.parameter_schema_sha256,
        version.state_schema_version,
        version.source_revision,
        version.registered_at,
        version.registered_by,
    )


def _strategy_presentation_material(
    strategy_version_id: str,
    display_name: str,
) -> tuple[object, ...]:
    return (
        EXPERIMENT_REGISTRY_CONTRACT_VERSION,
        "strategy_presentation",
        strategy_version_id,
        display_name,
    )


def _configuration_material(
    configuration: StrategyConfigurationRecord,
) -> tuple[object, ...]:
    return (
        EXPERIMENT_REGISTRY_CONTRACT_VERSION,
        "strategy_configuration",
        configuration.strategy_version_sha256,
        configuration.configuration_name,
        tuple(sorted(configuration.parameters.items())),
        configuration.registered_at,
        configuration.registered_by,
    )


def _material_text(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise BacktestWorkflowError(f"persisted {field_name} is malformed")
    return value


def _material_datetime(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise BacktestWorkflowError(f"persisted {field_name} is malformed")
    return value


def _strategy_version_from_row(row: WorkflowRow) -> StrategyVersionRecord:
    payload = _required_text(row, "canonical_payload")
    material = _canonical_material(payload, "strategy version canonical payload")
    if (
        len(material) != 10
        or material[0] != EXPERIMENT_REGISTRY_CONTRACT_VERSION
        or material[1] != "strategy_version"
    ):
        raise BacktestWorkflowError("persisted strategy version material is malformed")
    try:
        version = StrategyVersionRecord(
            strategy_id=_material_text(material[2], "strategy ID"),
            strategy_version=_material_text(material[3], "strategy version"),
            code_sha256=_material_text(material[4], "strategy implementation digest"),
            parameter_schema_sha256=_material_text(material[5], "strategy parameter schema digest"),
            state_schema_version=_material_text(material[6], "strategy state schema version"),
            source_revision=_material_text(material[7], "strategy source revision"),
            registered_at=_material_datetime(material[8], "strategy registered_at"),
            registered_by=_material_text(material[9], "strategy registrar"),
        )
    except (TypeError, ValueError) as error:
        raise BacktestWorkflowError("persisted strategy version material is malformed") from error
    expected = {
        "strategy_version_id": version.strategy_version_id,
        "strategy_id": version.strategy_id,
        "strategy_version": version.strategy_version,
        "implementation_sha256": version.code_sha256,
        "parameter_schema_sha256": version.parameter_schema_sha256,
        "canonical_payload": canonical_json_text(_version_material(version)),
        "semantic_sha256": version.semantic_sha256,
    }
    if any(row[field_name] != value for field_name, value in expected.items()):
        raise BacktestWorkflowError(
            "persisted strategy version conflicts with its canonical identity"
        )
    if _required_datetime(row, "created_at") != version.registered_at:
        raise BacktestWorkflowError(
            "persisted strategy version time conflicts with its canonical identity"
        )
    parameter_schema_payload = _required_text(row, "parameter_schema_payload")
    if _payload_sha256(parameter_schema_payload) != version.parameter_schema_sha256:
        raise BacktestWorkflowError(
            "persisted parameter schema payload conflicts with strategy identity"
        )
    display_name = _required_text(row, "display_name")
    presentation_payload = _required_text(row, "presentation_payload")
    presentation_material = _canonical_material(
        presentation_payload,
        "strategy presentation payload",
    )
    if presentation_material != _strategy_presentation_material(
        version.strategy_version_id,
        display_name,
    ):
        raise BacktestWorkflowError(
            "persisted strategy display name conflicts with presentation evidence"
        )
    if _payload_sha256(presentation_payload) != _required_text(row, "presentation_sha256"):
        raise BacktestWorkflowError("persisted strategy presentation digest is invalid")
    return version


def _configuration_parameters(value: object) -> dict[str, object]:
    if type(value) is not tuple:
        raise BacktestWorkflowError("persisted strategy parameters are malformed")
    parameters: dict[str, object] = {}
    for item in value:
        if type(item) is not tuple or len(item) != 2 or type(item[0]) is not str:
            raise BacktestWorkflowError("persisted strategy parameters are malformed")
        key = item[0]
        if key in parameters:
            raise BacktestWorkflowError("persisted strategy parameter keys are duplicated")
        parameters[key] = item[1]
    return parameters


def _strategy_configuration_from_row(
    row: WorkflowRow,
    version: StrategyVersionRecord,
) -> StrategyConfigurationRecord:
    payload = _required_text(row, "canonical_payload")
    material = _canonical_material(payload, "strategy configuration canonical payload")
    if (
        len(material) != 7
        or material[0] != EXPERIMENT_REGISTRY_CONTRACT_VERSION
        or material[1] != "strategy_configuration"
    ):
        raise BacktestWorkflowError("persisted strategy configuration material is malformed")
    parameters = _configuration_parameters(material[4])
    try:
        configuration = StrategyConfigurationRecord(
            strategy_version_sha256=_material_text(
                material[2], "configuration strategy version digest"
            ),
            configuration_name=_material_text(material[3], "configuration name"),
            parameters=parameters,
            registered_at=_material_datetime(material[5], "configuration registered_at"),
            registered_by=_material_text(material[6], "configuration registrar"),
        )
    except (TypeError, ValueError) as error:
        raise BacktestWorkflowError(
            "persisted strategy configuration material is malformed"
        ) from error
    expected = {
        "configuration_sha256": configuration.configuration_sha256,
        "strategy_version_id": version.strategy_version_id,
        "strategy_id": version.strategy_id,
        "strategy_version": version.strategy_version,
        "display_name": configuration.configuration_name,
        "canonical_payload": canonical_json_text(_configuration_material(configuration)),
        "semantic_sha256": configuration.semantic_sha256,
    }
    if any(row[field_name] != value for field_name, value in expected.items()):
        raise BacktestWorkflowError(
            "persisted strategy configuration conflicts with its canonical identity"
        )
    if configuration.strategy_version_sha256 != version.strategy_version_id:
        raise BacktestWorkflowError(
            "persisted strategy configuration belongs to another strategy version"
        )
    if _required_datetime(row, "created_at") != configuration.registered_at:
        raise BacktestWorkflowError(
            "persisted strategy configuration time conflicts with its canonical identity"
        )
    expected_parameters_payload = canonical_json_text(
        tuple(sorted(configuration.parameters.items()))
    )
    if _required_text(row, "parameters_payload") != expected_parameters_payload:
        raise BacktestWorkflowError(
            "persisted parameters payload conflicts with configuration identity"
        )
    return configuration


def _fixture_input_from_row(
    row: WorkflowRow,
    versions: Mapping[str, StrategyVersionRecord],
    configurations: Mapping[str, StrategyConfigurationRecord],
) -> BacktestJobInput:
    payload = _required_text(row, "canonical_payload")
    material = _canonical_material(payload, "backtest fixture canonical payload")
    if (
        len(material) != 17
        or material[0] != BACKTEST_JOB_CONTRACT_VERSION
        or material[1] != "fixture"
    ):
        raise BacktestWorkflowError("persisted backtest fixture material is malformed")
    try:
        fixture_input = BacktestJobInput(
            fixture_id=_material_text(material[2], "fixture ID"),
            fixture_version=_material_text(material[3], "fixture version"),
            dataset_manifest_id=_material_text(material[4], "dataset manifest ID"),
            dataset_manifest_sha256=_material_text(material[4], "dataset manifest digest"),
            replay_run_id=_material_text(material[6], "fixture replay run ID"),
            strategy_id=_material_text(material[10], "fixture strategy ID"),
            strategy_version=_material_text(material[11], "fixture strategy version"),
            strategy_configuration_sha256=_material_text(
                material[12], "fixture strategy configuration digest"
            ),
            benchmark_sha256=_material_text(material[13], "fixture benchmark digest"),
            cost_model_sha256=_material_text(material[14], "fixture cost model digest"),
            fill_model_sha256=_material_text(material[15], "fixture fill model digest"),
            metric_conventions_sha256=_material_text(
                material[16], "fixture metric conventions digest"
            ),
        )
    except (TypeError, ValueError) as error:
        raise BacktestWorkflowError("persisted backtest fixture material is malformed") from error
    strategy_version_id = _required_text(row, "strategy_version_id")
    version = versions.get(strategy_version_id)
    configuration = configurations.get(fixture_input.strategy_configuration_sha256)
    if (
        version is None
        or configuration is None
        or version.strategy_id != fixture_input.strategy_id
        or version.strategy_version != fixture_input.strategy_version
        or configuration.strategy_version_sha256 != strategy_version_id
    ):
        raise BacktestWorkflowError(
            "persisted backtest fixture conflicts with its strategy catalog"
        )
    expected = {
        "fixture_id": fixture_input.fixture_id,
        "fixture_version": fixture_input.fixture_version,
        "dataset_manifest_sha256": fixture_input.dataset_manifest_sha256,
        "source_tape_sha256": _material_text(material[5], "fixture source tape digest"),
        "replay_run_id": fixture_input.replay_run_id,
        "replay_manifest_sha256": _material_text(material[7], "fixture replay manifest digest"),
        "replay_input_sha256": _material_text(material[8], "fixture replay input digest"),
        "replay_semantic_sha256": _material_text(material[9], "fixture replay semantic digest"),
        "strategy_version_id": strategy_version_id,
        "strategy_id": fixture_input.strategy_id,
        "strategy_version": fixture_input.strategy_version,
        "strategy_configuration_sha256": fixture_input.strategy_configuration_sha256,
        "benchmark_sha256": fixture_input.benchmark_sha256,
        "cost_model_sha256": fixture_input.cost_model_sha256,
        "fill_model_sha256": fixture_input.fill_model_sha256,
        "metric_conventions_sha256": fixture_input.metric_conventions_sha256,
        "canonical_payload": canonical_json_text(material),
        "semantic_sha256": _sha256(material),
        "fixture_sha256": _sha256(material),
    }
    if any(row[field_name] != value for field_name, value in expected.items()):
        raise BacktestWorkflowError(
            "persisted backtest fixture conflicts with its canonical identity"
        )
    _required_datetime(row, "registered_at")
    return fixture_input


def _verify_strategy_catalog_integrity(
    connection: Connection,
) -> tuple[
    dict[str, StrategyVersionRecord],
    dict[str, StrategyConfigurationRecord],
    dict[tuple[str, str], BacktestJobInput],
]:
    versions: dict[str, StrategyVersionRecord] = {}
    for row in connection.execute(sa.select(phase2_strategy_versions)).mappings():
        version = _strategy_version_from_row(row)
        if version.strategy_version_id in versions:
            raise BacktestWorkflowError("persisted strategy version identity is duplicated")
        versions[version.strategy_version_id] = version
    configurations: dict[str, StrategyConfigurationRecord] = {}
    for row in connection.execute(sa.select(phase2_strategy_configurations)).mappings():
        strategy_version_id = _required_text(row, "strategy_version_id")
        selected_version = versions.get(strategy_version_id)
        if selected_version is None:
            raise BacktestWorkflowError(
                "persisted strategy configuration lacks its strategy version"
            )
        configuration = _strategy_configuration_from_row(row, selected_version)
        if configuration.configuration_sha256 in configurations:
            raise BacktestWorkflowError("persisted strategy configuration identity is duplicated")
        configurations[configuration.configuration_sha256] = configuration
    fixtures: dict[tuple[str, str], BacktestJobInput] = {}
    for row in connection.execute(sa.select(phase2_backtest_fixtures)).mappings():
        fixture_input = _fixture_input_from_row(row, versions, configurations)
        fixture_key = (fixture_input.fixture_id, fixture_input.fixture_version)
        if fixture_key in fixtures:
            raise BacktestWorkflowError("persisted backtest fixture identity is duplicated")
        fixtures[fixture_key] = fixture_input
    return versions, configurations, fixtures


def _event_values(event: BacktestJobEvent) -> dict[str, Any]:
    return {
        "event_sha256": event.event_sha256,
        "job_id": event.job_id,
        "sequence_number": event.sequence,
        "status": event.status.value,
        "occurred_at": event.occurred_at,
        "actor_id": event.actor_id,
        "attempt_number": event.attempt_number,
        "previous_event_sha256": event.previous_event_sha256,
        "worker_id": event.worker_id,
        "claim_expires_at": event.claim_expires_at,
        "run_manifest_sha256": event.run_manifest_sha256,
        "report_sha256": event.report_sha256,
        "report_artifact_sha256": event.report_artifact_sha256,
        "terminal_reason_code": event.terminal_reason_code,
        "terminal_reason_sha256": event.terminal_reason_sha256,
        "canonical_payload": event.canonical_json,
    }


def _head_values(projection: BacktestJobProjection) -> dict[str, Any]:
    latest = projection.latest
    return {
        "job_id": projection.job_id,
        "last_sequence_number": latest.sequence,
        "last_event_sha256": latest.event_sha256,
        "status": latest.status.value,
        "attempt_number": latest.attempt_number,
        "worker_id": latest.worker_id,
        "claim_expires_at": latest.claim_expires_at,
        "run_manifest_sha256": latest.run_manifest_sha256,
        "report_sha256": latest.report_sha256,
        "report_artifact_sha256": latest.report_artifact_sha256,
        "terminal_reason_code": latest.terminal_reason_code,
        "terminal_reason_sha256": latest.terminal_reason_sha256,
        "updated_at": latest.occurred_at,
    }


def _job_from_row(row: WorkflowRow) -> BacktestJob:
    try:
        job_input = BacktestJobInput(
            fixture_id=_required_text(row, "fixture_id"),
            fixture_version=_required_text(row, "fixture_version"),
            dataset_manifest_id=_required_text(row, "dataset_manifest_id"),
            dataset_manifest_sha256=_required_text(row, "dataset_manifest_sha256"),
            replay_run_id=_required_text(row, "replay_run_id"),
            strategy_id=_required_text(row, "strategy_id"),
            strategy_version=_required_text(row, "strategy_version"),
            strategy_configuration_sha256=_required_text(row, "strategy_configuration_sha256"),
            benchmark_sha256=_required_text(row, "benchmark_sha256"),
            cost_model_sha256=_required_text(row, "cost_model_sha256"),
            fill_model_sha256=_required_text(row, "fill_model_sha256"),
            metric_conventions_sha256=_required_text(row, "metric_conventions_sha256"),
        )
        job = BacktestJob(
            input=job_input,
            requested_by=_required_text(row, "requested_by"),
            idempotency_key=_required_text(row, "idempotency_key"),
            requested_at=_required_datetime(row, "requested_at"),
        )
        expected = {
            "job_id": job.job_id,
            "input_sha256": job.input.input_sha256,
            "canonical_payload": job.canonical_json,
            "semantic_sha256": job.semantic_sha256,
        }
        for field_name, value in expected.items():
            if row[field_name] != value:
                raise BacktestWorkflowError(
                    f"persisted job {field_name} conflicts with canonical evidence"
                )
        return job
    except BacktestWorkflowError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise BacktestWorkflowError("persisted backtest job is malformed") from error


def _event_matches_row(event: BacktestJobEvent, row: WorkflowRow) -> None:
    expected = _event_values(event)
    try:
        for field_name, expected_value in expected.items():
            actual = row[field_name]
            if isinstance(expected_value, datetime):
                if not isinstance(actual, datetime) or as_aware_utc(actual) != expected_value:
                    raise BacktestWorkflowError("persisted job event time conflicts")
            elif actual != expected_value:
                raise BacktestWorkflowError(
                    f"persisted job event {field_name} conflicts with canonical evidence"
                )
    except KeyError as error:
        raise BacktestWorkflowError("persisted job event is malformed") from error


def _projection(connection: Connection, job: BacktestJob) -> BacktestJobProjection:
    rows = connection.execute(
        sa.select(phase2_backtest_job_events)
        .where(phase2_backtest_job_events.c.job_id == job.job_id)
        .order_by(phase2_backtest_job_events.c.sequence_number)
    ).mappings()
    event_rows = tuple(rows)
    if not event_rows:
        raise BacktestWorkflowError("persisted backtest job has no event chain")
    _, projection = create_backtest_job(
        input=job.input,
        requested_by=job.requested_by,
        idempotency_key=job.idempotency_key,
        requested_at=job.requested_at,
    )
    _event_matches_row(projection.latest, event_rows[0])
    for row in event_rows[1:]:
        status = BacktestJobStatus(_required_text(row, "status"))
        occurred_at = _required_datetime(row, "occurred_at")
        actor_id = _required_text(row, "actor_id")
        if status is BacktestJobStatus.RUNNING:
            worker_id = _required_text(row, "worker_id")
            claim_expires_at = _required_datetime(row, "claim_expires_at")
            projection = claim_backtest_job(
                projection,
                worker_id=worker_id,
                claimed_at=occurred_at,
                claim_expires_at=claim_expires_at,
            )
        elif status is BacktestJobStatus.COMPLETED:
            projection = complete_backtest_job(
                projection,
                worker_id=actor_id,
                completed_at=occurred_at,
                run_manifest_sha256=_required_text(row, "run_manifest_sha256"),
                report_sha256=_required_text(row, "report_sha256"),
                report_artifact_sha256=_required_text(row, "report_artifact_sha256"),
            )
        elif status is BacktestJobStatus.FAILED:
            projection = fail_backtest_job(
                projection,
                worker_id=actor_id,
                failed_at=occurred_at,
                terminal_reason_code=_required_text(row, "terminal_reason_code"),
                terminal_reason_sha256=_required_text(row, "terminal_reason_sha256"),
            )
        elif status is BacktestJobStatus.CANCELED:
            reason_sha256 = _required_text(row, "terminal_reason_sha256")
            if projection.status is BacktestJobStatus.QUEUED:
                projection = cancel_queued_backtest_job(
                    projection,
                    operator_id=actor_id,
                    canceled_at=occurred_at,
                    terminal_reason_sha256=reason_sha256,
                )
            else:
                projection = cancel_running_backtest_job(
                    projection,
                    worker_id=actor_id,
                    canceled_at=occurred_at,
                    terminal_reason_sha256=reason_sha256,
                )
        else:
            raise BacktestWorkflowError("queued event may only appear first")
        _event_matches_row(projection.latest, row)
    return projection


def _snapshot(job: BacktestJob, projection: BacktestJobProjection) -> BacktestJobSnapshot:
    latest = projection.latest
    return BacktestJobSnapshot(
        job_id=job.job_id,
        input_sha256=job.input.input_sha256,
        fixture_id=job.input.fixture_id,
        fixture_version=job.input.fixture_version,
        strategy_id=job.input.strategy_id,
        strategy_version=job.input.strategy_version,
        strategy_configuration_sha256=job.input.strategy_configuration_sha256,
        requested_by=job.requested_by,
        requested_at=job.requested_at,
        status=latest.status,
        attempt_number=latest.attempt_number,
        worker_id=latest.worker_id,
        claim_expires_at=latest.claim_expires_at,
        updated_at=latest.occurred_at,
        run_manifest_sha256=latest.run_manifest_sha256,
        report_sha256=latest.report_sha256,
        report_artifact_sha256=latest.report_artifact_sha256,
        terminal_reason_code=latest.terminal_reason_code,
        history=tuple(
            BacktestJobEventSnapshot(
                sequence=event.sequence,
                status=event.status,
                occurred_at=event.occurred_at,
                actor_id=event.actor_id,
                attempt_number=event.attempt_number,
                terminal_reason_code=event.terminal_reason_code,
            )
            for event in projection.events
        ),
    )


def _job_values(job: BacktestJob, strategy_version_id: str) -> dict[str, Any]:
    return {
        "job_id": job.job_id,
        "input_sha256": job.input.input_sha256,
        "fixture_id": job.input.fixture_id,
        "fixture_version": job.input.fixture_version,
        "dataset_manifest_id": job.input.dataset_manifest_id,
        "dataset_manifest_sha256": job.input.dataset_manifest_sha256,
        "replay_run_id": job.input.replay_run_id,
        "strategy_version_id": strategy_version_id,
        "strategy_id": job.input.strategy_id,
        "strategy_version": job.input.strategy_version,
        "strategy_configuration_sha256": job.input.strategy_configuration_sha256,
        "benchmark_sha256": job.input.benchmark_sha256,
        "cost_model_sha256": job.input.cost_model_sha256,
        "fill_model_sha256": job.input.fill_model_sha256,
        "metric_conventions_sha256": job.input.metric_conventions_sha256,
        "requested_by": job.requested_by,
        "idempotency_key": job.idempotency_key,
        "requested_at": job.requested_at,
        "canonical_payload": job.canonical_json,
        "semantic_sha256": job.semantic_sha256,
    }


def _report_values(report: BacktestReport) -> dict[str, Any]:
    query_payload = _report_query_payload(report)
    return {
        "report_artifact_sha256": report.artifact_sha256,
        "report_sha256": report.report_sha256,
        "account_id": report.account_id,
        "currency": report.currency,
        "period_start": report.period_start,
        "period_end": report.period_end,
        "generated_at": report.generated_at,
        "starting_equity": canonical_persisted_decimal(
            report.metrics.starting_equity, "starting equity"
        ),
        "ending_equity": canonical_persisted_decimal(report.metrics.ending_equity, "ending equity"),
        "total_return": canonical_persisted_decimal(report.metrics.total_return, "total return"),
        "maximum_drawdown": canonical_persisted_decimal(
            report.metrics.maximum_drawdown, "maximum drawdown"
        ),
        "turnover": canonical_persisted_decimal(report.metrics.turnover, "turnover"),
        "trade_count": report.metrics.trade_count,
        "realized_pnl": canonical_persisted_decimal(report.metrics.realized_pnl, "realized P&L"),
        "unrealized_pnl": canonical_persisted_decimal(
            report.metrics.unrealized_pnl, "unrealized P&L"
        ),
        "dividend_income": canonical_persisted_decimal(
            report.metrics.dividend_income, "dividend income"
        ),
        "total_execution_costs": canonical_persisted_decimal(
            report.metrics.total_execution_costs, "total execution costs"
        ),
        "semantic_payload": report.canonical_json,
        "artifact_payload": report.artifact_canonical_json,
        "query_payload": query_payload,
        "query_payload_sha256": _payload_sha256(query_payload),
    }


def _report_row_matches(row: WorkflowRow, field_name: str, expected: object) -> bool:
    actual = row[field_name]
    if isinstance(expected, datetime):
        return isinstance(actual, datetime) and as_aware_utc(actual) == expected
    if isinstance(expected, Decimal):
        return _required_decimal(row, field_name) == expected
    return bool(actual == expected)


def _report_from_row(
    row: WorkflowRow,
) -> tuple[BacktestReport, dict[str, object]]:
    semantic_payload = _required_text(row, "semantic_payload")
    artifact_payload = _required_text(row, "artifact_payload")
    query_payload_text = _required_text(row, "query_payload")
    if _payload_sha256(semantic_payload) != _required_text(row, "report_sha256"):
        raise BacktestWorkflowError("persisted report semantic digest is invalid")
    if _payload_sha256(artifact_payload) != _required_text(row, "report_artifact_sha256"):
        raise BacktestWorkflowError("persisted report artifact digest is invalid")
    if _payload_sha256(query_payload_text) != _required_text(row, "query_payload_sha256"):
        raise BacktestWorkflowError("persisted report query payload digest is invalid")
    try:
        query_payload = json.loads(query_payload_text)
        report = _report_from_query(query_payload)
    except (ArithmeticError, KeyError, TypeError, ValueError) as error:
        raise BacktestWorkflowError(
            "persisted report query payload conflicts with immutable report evidence"
        ) from error
    if type(query_payload) is not dict:
        raise BacktestWorkflowError("persisted report query payload must be an object")
    expected_values = _report_values(report)
    if any(
        not _report_row_matches(row, field_name, expected)
        for field_name, expected in expected_values.items()
    ):
        raise BacktestWorkflowError(
            "persisted report columns conflict with immutable report evidence"
        )
    return report, cast(dict[str, object], query_payload)


def _verify_job_audit(
    connection: Connection,
    job: BacktestJob,
) -> None:
    rows = tuple(
        connection.execute(
            sa.select(phase2_backtest_audit_events).where(
                phase2_backtest_audit_events.c.job_id == job.job_id
            )
        ).mappings()
    )
    if len(rows) != 1:
        raise BacktestWorkflowError("persisted backtest job lacks one exact launch audit")
    row = rows[0]
    payload = _required_text(row, "canonical_payload")
    material = _canonical_material(payload, "backtest launch audit canonical payload")
    expected_material = (
        BACKTEST_JOB_CONTRACT_VERSION,
        "audit",
        "launch",
        job.job_id,
        job.input.input_sha256,
        job.requested_by,
        job.idempotency_key,
        job.requested_at,
    )
    digest = _sha256(expected_material)
    expected = {
        "audit_sha256": digest,
        "job_id": job.job_id,
        "action": "launch",
        "actor_id": job.requested_by,
        "idempotency_key": job.idempotency_key,
        "request_sha256": job.input.input_sha256,
        "occurred_at": job.requested_at,
        "canonical_payload": canonical_json_text(expected_material),
        "semantic_sha256": digest,
    }
    if material != expected_material or any(
        not _report_row_matches(row, field_name, value) for field_name, value in expected.items()
    ):
        raise BacktestWorkflowError(
            "persisted backtest launch audit conflicts with immutable job evidence"
        )


def _verify_job_head(
    connection: Connection,
    projection: BacktestJobProjection,
) -> None:
    row = (
        connection.execute(
            sa.select(phase2_backtest_job_heads).where(
                phase2_backtest_job_heads.c.job_id == projection.job_id
            )
        )
        .mappings()
        .one_or_none()
    )
    expected = _head_values(projection)
    if row is None or any(
        not _report_row_matches(row, field_name, value) for field_name, value in expected.items()
    ):
        raise BacktestWorkflowError(
            "persisted backtest job head conflicts with its immutable event chain"
        )


def _manifest_input_for_job(material: tuple[object, ...]) -> BacktestJobInput:
    if (
        len(material) != 10
        or material[0] != BACKTEST_RUN_MANIFEST_CONTRACT_VERSION
        or material[1] != "input"
        or type(material[2]) is not tuple
        or type(material[3]) is not tuple
        or type(material[6]) is not tuple
        or type(material[7]) is not tuple
        or type(material[8]) is not tuple
    ):
        raise BacktestWorkflowError("persisted run-manifest input material is malformed")
    dataset = cast(tuple[object, ...], material[2])
    strategy = cast(tuple[object, ...], material[3])
    if (
        len(dataset) != 7
        or dataset[0] != "dataset_replay_pin_v1"
        or len(strategy) != 5
        or strategy[0] != "strategy_input_pin_v1"
    ):
        raise BacktestWorkflowError("persisted run-manifest input pins are malformed")
    try:
        return BacktestJobInput(
            fixture_id="manifest-fixture-placeholder",
            fixture_version="manifest-fixture-placeholder",
            dataset_manifest_id=_material_text(dataset[1], "manifest dataset ID"),
            dataset_manifest_sha256=_material_text(dataset[1], "manifest dataset digest"),
            replay_run_id=_material_text(dataset[3], "manifest replay run ID"),
            strategy_id=_material_text(strategy[1], "manifest strategy ID"),
            strategy_version=_material_text(strategy[2], "manifest strategy version"),
            strategy_configuration_sha256=_material_text(
                strategy[3], "manifest configuration digest"
            ),
            benchmark_sha256=_sha256(material[6]),
            cost_model_sha256=_sha256(material[7]),
            fill_model_sha256=_sha256(material[8]),
            metric_conventions_sha256=_material_text(
                material[9], "manifest metric conventions digest"
            ),
        )
    except (TypeError, ValueError) as error:
        raise BacktestWorkflowError("persisted run-manifest input pins are malformed") from error


def _verify_manifest_row(
    row: WorkflowRow,
    job: BacktestJob,
    fixture_row: WorkflowRow,
) -> str:
    payload = _required_text(row, "canonical_payload")
    material = _canonical_material(payload, "backtest run manifest canonical payload")
    if (
        len(material) != 5
        or material[0] != BACKTEST_RUN_MANIFEST_CONTRACT_VERSION
        or material[1] != "manifest"
        or type(material[2]) is not tuple
        or type(material[4]) is not tuple
    ):
        raise BacktestWorkflowError("persisted run manifest material is malformed")
    input_material = cast(tuple[object, ...], material[2])
    outcome = cast(tuple[object, ...], material[4])
    if len(outcome) != 7 or outcome[0] != "outcome" or type(outcome[2]) is not tuple:
        raise BacktestWorkflowError("persisted run-manifest outcome is malformed")
    result = cast(tuple[object, ...], outcome[2])
    if len(result) != 8 or result[0] != "backtest_run_result_v2":
        raise BacktestWorkflowError("persisted run-manifest result is malformed")
    manifest_input = _manifest_input_for_job(input_material)
    if (
        manifest_input.dataset_manifest_sha256 != job.input.dataset_manifest_sha256
        or manifest_input.replay_run_id != job.input.replay_run_id
        or manifest_input.strategy_id != job.input.strategy_id
        or manifest_input.strategy_version != job.input.strategy_version
        or manifest_input.strategy_configuration_sha256 != job.input.strategy_configuration_sha256
        or manifest_input.benchmark_sha256 != job.input.benchmark_sha256
        or manifest_input.cost_model_sha256 != job.input.cost_model_sha256
        or manifest_input.fill_model_sha256 != job.input.fill_model_sha256
        or manifest_input.metric_conventions_sha256 != job.input.metric_conventions_sha256
    ):
        raise BacktestWorkflowError("persisted run manifest conflicts with immutable job inputs")
    dataset = cast(tuple[object, ...], input_material[2])
    expected_replay = {
        "dataset_manifest_sha256": dataset[1],
        "source_tape_sha256": dataset[2],
        "replay_run_id": dataset[3],
        "replay_manifest_sha256": dataset[4],
        "replay_input_sha256": dataset[5],
        "replay_semantic_sha256": dataset[6],
    }
    if any(fixture_row[field_name] != value for field_name, value in expected_replay.items()):
        raise BacktestWorkflowError(
            "persisted run manifest conflicts with immutable fixture replay evidence"
        )
    manifest_input_sha256 = _sha256(input_material)
    manifest_sha256 = _sha256(material)
    status = _material_text(result[1], "run-manifest status")
    if status not in {"completed", "failed", "canceled"}:
        raise BacktestWorkflowError("persisted run-manifest status is malformed")
    started_at = _material_datetime(result[2], "run-manifest started_at")
    completed_at = _material_datetime(result[3], "run-manifest completed_at")
    if completed_at < started_at:
        raise BacktestWorkflowError("persisted run-manifest times are malformed")
    expected = {
        "run_id": manifest_sha256,
        "manifest_sha256": manifest_sha256,
        "job_id": job.job_id,
        "manifest_input_sha256": manifest_input_sha256,
        "status": status,
        "started_at": started_at,
        "completed_at": completed_at,
        "report_sha256": result[4],
        "report_artifact_sha256": result[5],
        "terminal_reason_code": result[6],
        "terminal_reason_sha256": result[7],
        "canonical_payload": canonical_json_text(material),
    }
    if material[3] != manifest_input_sha256 or any(
        not _report_row_matches(row, field_name, value) for field_name, value in expected.items()
    ):
        raise BacktestWorkflowError(
            "persisted run-manifest columns conflict with canonical evidence"
        )
    return manifest_sha256


def _verify_backtest_workflow_integrity(connection: Connection) -> None:
    """Strictly reconstruct auxiliary catalog payloads and report projections."""

    _, _, fixtures = _verify_strategy_catalog_integrity(connection)
    for row in connection.execute(sa.select(phase2_backtest_reports)).mappings():
        _report_from_row(row)
    for row in connection.execute(sa.select(phase2_backtest_jobs)).mappings():
        job = _job_from_row(row)
        fixture_key = (job.input.fixture_id, job.input.fixture_version)
        if fixtures.get(fixture_key) != job.input:
            raise BacktestWorkflowError(
                "persisted backtest job conflicts with its immutable fixture"
            )
        try:
            projection = _projection(connection, job)
        except (TypeError, ValueError) as error:
            raise BacktestWorkflowError(
                "persisted backtest job event chain is malformed"
            ) from error
        _verify_job_head(connection, projection)
        _verify_job_audit(connection, job)
        manifest_rows = tuple(
            connection.execute(
                sa.select(phase2_backtest_run_manifests).where(
                    phase2_backtest_run_manifests.c.job_id == job.job_id
                )
            ).mappings()
        )
        expected_manifest_sha256 = projection.latest.run_manifest_sha256
        if expected_manifest_sha256 is None:
            if manifest_rows:
                raise BacktestWorkflowError(
                    "non-completed backtest job unexpectedly retains a run manifest"
                )
            continue
        if len(manifest_rows) != 1:
            raise BacktestWorkflowError("completed backtest job lacks one exact run manifest")
        fixture_row = (
            connection.execute(
                sa.select(phase2_backtest_fixtures).where(
                    phase2_backtest_fixtures.c.fixture_id == job.input.fixture_id,
                    phase2_backtest_fixtures.c.fixture_version == job.input.fixture_version,
                )
            )
            .mappings()
            .one()
        )
        manifest_sha256 = _verify_manifest_row(manifest_rows[0], job, fixture_row)
        if manifest_sha256 != expected_manifest_sha256:
            raise BacktestWorkflowError(
                "persisted run manifest conflicts with completed job evidence"
            )


def _manifest_values(
    job_id: str,
    manifest: BacktestRunManifest,
) -> dict[str, Any]:
    return {
        "run_id": manifest.run_id,
        "manifest_sha256": manifest.manifest_sha256,
        "job_id": job_id,
        "manifest_input_sha256": manifest.input_sha256,
        "status": manifest.result.status.value,
        "started_at": manifest.result.started_at,
        "completed_at": manifest.result.completed_at,
        "report_sha256": manifest.report_sha256,
        "report_artifact_sha256": manifest.report_artifact_sha256,
        "terminal_reason_code": manifest.result.terminal_reason_code,
        "terminal_reason_sha256": manifest.result.terminal_reason_sha256,
        "canonical_payload": manifest.canonical_json,
    }


class SqlBacktestWorkflow:
    """Own durable catalog, launch, claim, result, and query operations."""

    __slots__ = ("_engine",)

    def __init__(self, engine: Engine) -> None:
        if not isinstance(engine, Engine):
            raise BacktestWorkflowError("backtest workflow requires a SQLAlchemy engine")
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise BacktestWorkflowError(
                f"backtest workflow does not support SQL dialect {engine.dialect.name!r}"
            )
        self._engine = engine

    def register_strategy(
        self,
        *,
        version: StrategyVersionRecord,
        configuration: StrategyConfigurationRecord,
        display_name: str,
        parameter_schema_payload: str,
    ) -> None:
        if type(version) is not StrategyVersionRecord:
            raise BacktestWorkflowError("strategy registration requires an exact version")
        if type(configuration) is not StrategyConfigurationRecord:
            raise BacktestWorkflowError("strategy registration requires an exact configuration")
        if configuration.strategy_version_sha256 != version.strategy_version_id:
            raise BacktestWorkflowConflict("configuration belongs to another strategy version")
        if (
            type(display_name) is not str
            or not display_name
            or display_name != display_name.strip()
        ):
            raise BacktestWorkflowError("strategy display name must be non-empty and trimmed")
        if type(parameter_schema_payload) is not str:
            raise BacktestWorkflowError("parameter schema payload must be text")
        if _payload_sha256(parameter_schema_payload) != version.parameter_schema_sha256:
            raise BacktestWorkflowConflict("parameter schema payload digest conflicts")
        try:
            validate_strategy_configuration_parameters(
                parameter_schema_payload,
                configuration.parameters,
            )
        except StrategyParameterSchemaError as error:
            raise BacktestWorkflowError(
                f"strategy parameter schema validation failed: {error}"
            ) from error
        except StrategyConfigurationSchemaMismatch as error:
            raise BacktestWorkflowConflict(
                f"strategy configuration validation failed: {error}"
            ) from error
        version_payload = canonical_json_text(_version_material(version))
        presentation_payload = canonical_json_text(
            _strategy_presentation_material(version.strategy_version_id, display_name)
        )
        configuration_payload = canonical_json_text(_configuration_material(configuration))
        parameters_payload = canonical_json_text(tuple(sorted(configuration.parameters.items())))
        version_values = {
            "strategy_version_id": version.strategy_version_id,
            "strategy_id": version.strategy_id,
            "strategy_version": version.strategy_version,
            "display_name": display_name,
            "presentation_payload": presentation_payload,
            "presentation_sha256": _payload_sha256(presentation_payload),
            "implementation_sha256": version.code_sha256,
            "parameter_schema_sha256": version.parameter_schema_sha256,
            "parameter_schema_payload": parameter_schema_payload,
            "created_at": version.registered_at,
            "canonical_payload": version_payload,
            "semantic_sha256": version.semantic_sha256,
        }
        configuration_values = {
            "configuration_sha256": configuration.configuration_sha256,
            "strategy_version_id": version.strategy_version_id,
            "strategy_id": version.strategy_id,
            "strategy_version": version.strategy_version,
            "display_name": configuration.configuration_name,
            "parameters_payload": parameters_payload,
            "created_at": configuration.registered_at,
            "canonical_payload": configuration_payload,
            "semantic_sha256": configuration.semantic_sha256,
        }
        try:
            with _write_transaction(self._engine) as connection:
                insert_or_verify_atomic(connection, phase2_strategy_versions, version_values)
                insert_or_verify_atomic(
                    connection, phase2_strategy_configurations, configuration_values
                )
        except ImmutableFactConflict as error:
            raise BacktestWorkflowConflict(str(error)) from error

    def register_fixture(
        self,
        *,
        fixture_id: str,
        fixture_version: str,
        reference_manifest: BacktestRunManifest,
        registered_at: datetime,
    ) -> BacktestJobInput:
        """Register one exact built-in fixture template from a proven reference run."""

        if type(reference_manifest) is not BacktestRunManifest:
            raise BacktestWorkflowError("fixture registration requires an exact run manifest")
        if reference_manifest.result.status is not BacktestRunStatus.COMPLETED:
            raise BacktestWorkflowConflict("fixture reference manifest must be completed")
        try:
            job_input = BacktestJobInput(
                fixture_id=fixture_id,
                fixture_version=fixture_version,
                dataset_manifest_id=(reference_manifest.dataset_replay.dataset_manifest_sha256),
                dataset_manifest_sha256=(reference_manifest.dataset_replay.dataset_manifest_sha256),
                replay_run_id=reference_manifest.dataset_replay.replay_run_id,
                strategy_id=reference_manifest.strategy.strategy_id,
                strategy_version=reference_manifest.strategy.strategy_version,
                strategy_configuration_sha256=(
                    reference_manifest.strategy.strategy_configuration_sha256
                ),
                benchmark_sha256=reference_manifest.benchmark.semantic_sha256,
                cost_model_sha256=reference_manifest.cost_model.semantic_sha256,
                fill_model_sha256=reference_manifest.fill_model.semantic_sha256,
                metric_conventions_sha256=(reference_manifest.metric_conventions_sha256),
            )
        except ValueError as error:
            raise BacktestWorkflowError(str(error)) from error
        dataset = reference_manifest.dataset_replay
        material = (
            BACKTEST_JOB_CONTRACT_VERSION,
            "fixture",
            fixture_id,
            fixture_version,
            dataset.dataset_manifest_sha256,
            dataset.source_tape_sha256,
            dataset.replay_run_id,
            dataset.replay_manifest_sha256,
            dataset.replay_input_sha256,
            dataset.replay_semantic_sha256,
            job_input.strategy_id,
            job_input.strategy_version,
            job_input.strategy_configuration_sha256,
            job_input.benchmark_sha256,
            job_input.cost_model_sha256,
            job_input.fill_model_sha256,
            job_input.metric_conventions_sha256,
        )
        payload = canonical_json_text(material)
        fixture_sha256 = _sha256(material)
        with _write_transaction(self._engine) as connection:
            strategy = (
                connection.execute(
                    sa.select(phase2_strategy_versions).where(
                        phase2_strategy_versions.c.strategy_id == job_input.strategy_id,
                        phase2_strategy_versions.c.strategy_version == job_input.strategy_version,
                    )
                )
                .mappings()
                .one_or_none()
            )
            if strategy is None:
                raise BacktestWorkflowConflict("fixture strategy version must be registered first")
            strategy_version_id = _required_text(strategy, "strategy_version_id")
            configuration_exists = connection.scalar(
                sa.select(sa.literal(True)).where(
                    sa.exists(
                        sa.select(phase2_strategy_configurations.c.configuration_sha256).where(
                            phase2_strategy_configurations.c.configuration_sha256
                            == job_input.strategy_configuration_sha256,
                            phase2_strategy_configurations.c.strategy_version_id
                            == strategy_version_id,
                        )
                    )
                )
            )
            if configuration_exists is not True:
                raise BacktestWorkflowConflict(
                    "fixture strategy configuration must be registered first"
                )
            try:
                insert_or_verify_atomic(
                    connection,
                    phase2_backtest_fixtures,
                    {
                        "fixture_sha256": fixture_sha256,
                        "fixture_id": fixture_id,
                        "fixture_version": fixture_version,
                        "dataset_manifest_sha256": dataset.dataset_manifest_sha256,
                        "source_tape_sha256": dataset.source_tape_sha256,
                        "replay_run_id": dataset.replay_run_id,
                        "replay_manifest_sha256": dataset.replay_manifest_sha256,
                        "replay_input_sha256": dataset.replay_input_sha256,
                        "replay_semantic_sha256": dataset.replay_semantic_sha256,
                        "strategy_version_id": strategy_version_id,
                        "strategy_id": job_input.strategy_id,
                        "strategy_version": job_input.strategy_version,
                        "strategy_configuration_sha256": (job_input.strategy_configuration_sha256),
                        "benchmark_sha256": job_input.benchmark_sha256,
                        "cost_model_sha256": job_input.cost_model_sha256,
                        "fill_model_sha256": job_input.fill_model_sha256,
                        "metric_conventions_sha256": (job_input.metric_conventions_sha256),
                        "registered_at": registered_at,
                        "canonical_payload": payload,
                        "semantic_sha256": fixture_sha256,
                    },
                )
            except ImmutableFactConflict as error:
                raise BacktestWorkflowConflict(str(error)) from error
        return job_input

    def strategies(self) -> tuple[StrategyCatalogRecord, ...]:
        statement = (
            sa.select(
                phase2_strategy_versions,
                phase2_strategy_configurations.c.configuration_sha256,
                phase2_strategy_configurations.c.display_name.label("configuration_name"),
                phase2_strategy_configurations.c.parameters_payload,
                phase2_strategy_configurations.c.canonical_payload.label(
                    "configuration_canonical_payload"
                ),
                phase2_strategy_configurations.c.semantic_sha256.label(
                    "configuration_semantic_sha256"
                ),
                phase2_backtest_fixtures.c.fixture_id,
                phase2_backtest_fixtures.c.fixture_version,
                phase2_backtest_fixtures.c.dataset_manifest_sha256,
                phase2_backtest_fixtures.c.replay_run_id,
                phase2_backtest_fixtures.c.benchmark_sha256,
                phase2_backtest_fixtures.c.cost_model_sha256,
                phase2_backtest_fixtures.c.fill_model_sha256,
                phase2_backtest_fixtures.c.metric_conventions_sha256,
            )
            .join(
                phase2_strategy_configurations,
                phase2_strategy_configurations.c.strategy_version_id
                == phase2_strategy_versions.c.strategy_version_id,
            )
            .join(
                phase2_backtest_fixtures,
                sa.and_(
                    phase2_backtest_fixtures.c.strategy_version_id
                    == phase2_strategy_versions.c.strategy_version_id,
                    phase2_backtest_fixtures.c.strategy_configuration_sha256
                    == phase2_strategy_configurations.c.configuration_sha256,
                ),
            )
            .order_by(
                phase2_strategy_versions.c.strategy_id,
                phase2_strategy_versions.c.strategy_version,
                phase2_strategy_configurations.c.configuration_sha256,
            )
        )
        with self._engine.connect() as connection:
            _verify_strategy_catalog_integrity(connection)
            rows = tuple(connection.execute(statement).mappings())
        records: list[StrategyCatalogRecord] = []
        for row in rows:
            version_payload = _required_text(row, "canonical_payload")
            configuration_payload = _required_text(row, "configuration_canonical_payload")
            if _payload_sha256(version_payload) != _required_text(row, "semantic_sha256"):
                raise BacktestWorkflowError("persisted strategy version digest is invalid")
            if _payload_sha256(configuration_payload) != _required_text(
                row, "configuration_semantic_sha256"
            ):
                raise BacktestWorkflowError("persisted strategy configuration digest is invalid")
            records.append(
                StrategyCatalogRecord(
                    strategy_version_id=_required_text(row, "strategy_version_id"),
                    strategy_id=_required_text(row, "strategy_id"),
                    strategy_version=_required_text(row, "strategy_version"),
                    display_name=_required_text(row, "display_name"),
                    configuration_sha256=_required_text(row, "configuration_sha256"),
                    configuration_name=_required_text(row, "configuration_name"),
                    parameter_schema_payload=_required_text(row, "parameter_schema_payload"),
                    parameters_payload=_required_text(row, "parameters_payload"),
                    fixture_id=_required_text(row, "fixture_id"),
                    fixture_version=_required_text(row, "fixture_version"),
                    dataset_manifest_sha256=_required_text(row, "dataset_manifest_sha256"),
                    replay_run_id=_required_text(row, "replay_run_id"),
                    benchmark_sha256=_required_text(row, "benchmark_sha256"),
                    cost_model_sha256=_required_text(row, "cost_model_sha256"),
                    fill_model_sha256=_required_text(row, "fill_model_sha256"),
                    metric_conventions_sha256=_required_text(row, "metric_conventions_sha256"),
                )
            )
        return tuple(records)

    def launch(
        self,
        *,
        input: BacktestJobInput,
        requested_by: str,
        idempotency_key: str,
        requested_at: datetime,
    ) -> BacktestJobSnapshot:
        if type(input) is not BacktestJobInput:
            raise BacktestWorkflowError("launch requires an exact BacktestJobInput")
        try:
            with _write_transaction(self._engine) as connection:
                strategy_version_id = self._validate_launch_catalog(connection, input)
                job, projection = create_backtest_job(
                    input=input,
                    requested_by=requested_by,
                    idempotency_key=idempotency_key,
                    requested_at=requested_at,
                )
                job_values = _job_values(job, strategy_version_id)
                if not _insert_job_if_absent(connection, job_values):
                    # Under PostgreSQL READ COMMITTED, two exact retries can both
                    # observe no prior row.  The losing INSERT waits for the
                    # winner, then reaches this branch.  requested_at belongs to
                    # the winner and is deliberately not part of retry equality.
                    winner_row = (
                        connection.execute(
                            sa.select(phase2_backtest_jobs).where(
                                phase2_backtest_jobs.c.requested_by == requested_by,
                                phase2_backtest_jobs.c.idempotency_key == idempotency_key,
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if winner_row is None:
                        raise BacktestWorkflowConflict(
                            "backtest launch collided with another immutable identity"
                        )
                    winner = _job_from_row(winner_row)
                    if winner.input != input:
                        raise BacktestWorkflowConflict(
                            "idempotency key was already used for different launch inputs"
                        )
                    return _snapshot(winner, _projection(connection, winner))
                persisted_job = (
                    connection.execute(
                        sa.select(phase2_backtest_jobs).where(
                            phase2_backtest_jobs.c.job_id == job.job_id
                        )
                    )
                    .mappings()
                    .one()
                )
                assert_immutable(phase2_backtest_jobs, job.job_id, persisted_job, job_values)
                insert_or_verify_atomic(
                    connection,
                    phase2_backtest_job_events,
                    _event_values(projection.latest),
                )
                connection.execute(
                    sa.insert(phase2_backtest_job_heads).values(**_head_values(projection))
                )
                audit_material = (
                    BACKTEST_JOB_CONTRACT_VERSION,
                    "audit",
                    "launch",
                    job.job_id,
                    job.input.input_sha256,
                    job.requested_by,
                    job.idempotency_key,
                    job.requested_at,
                )
                audit_payload = canonical_json_text(audit_material)
                audit_sha256 = _sha256(audit_material)
                insert_or_verify_atomic(
                    connection,
                    phase2_backtest_audit_events,
                    {
                        "audit_sha256": audit_sha256,
                        "job_id": job.job_id,
                        "action": "launch",
                        "actor_id": job.requested_by,
                        "idempotency_key": job.idempotency_key,
                        "request_sha256": job.input.input_sha256,
                        "occurred_at": job.requested_at,
                        "canonical_payload": audit_payload,
                        "semantic_sha256": audit_sha256,
                    },
                )
                return _snapshot(job, projection)
        except (BacktestJobConflict, ImmutableFactConflict) as error:
            if isinstance(error, BacktestWorkflowConflict):
                raise
            raise BacktestWorkflowConflict(str(error)) from error

    def _validate_launch_catalog(
        self,
        connection: Connection,
        input: BacktestJobInput,
    ) -> str:
        row = (
            connection.execute(
                sa.select(
                    phase2_strategy_versions.c.strategy_version_id,
                    phase2_strategy_configurations.c.configuration_sha256,
                    phase2_backtest_fixtures.c.dataset_manifest_sha256,
                    phase2_backtest_fixtures.c.replay_run_id,
                    phase2_backtest_fixtures.c.benchmark_sha256,
                    phase2_backtest_fixtures.c.cost_model_sha256,
                    phase2_backtest_fixtures.c.fill_model_sha256,
                    phase2_backtest_fixtures.c.metric_conventions_sha256,
                )
                .select_from(phase2_backtest_fixtures)
                .join(
                    phase2_strategy_versions,
                    sa.and_(
                        phase2_strategy_versions.c.strategy_version_id
                        == phase2_backtest_fixtures.c.strategy_version_id,
                        phase2_strategy_versions.c.strategy_id == input.strategy_id,
                        phase2_strategy_versions.c.strategy_version == input.strategy_version,
                    ),
                )
                .join(
                    phase2_strategy_configurations,
                    sa.and_(
                        phase2_strategy_configurations.c.configuration_sha256
                        == input.strategy_configuration_sha256,
                        phase2_strategy_configurations.c.strategy_version_id
                        == phase2_strategy_versions.c.strategy_version_id,
                    ),
                )
                .where(
                    phase2_backtest_fixtures.c.fixture_id == input.fixture_id,
                    phase2_backtest_fixtures.c.fixture_version == input.fixture_version,
                    phase2_backtest_fixtures.c.dataset_manifest_sha256
                    == input.dataset_manifest_sha256,
                    phase2_backtest_fixtures.c.replay_run_id == input.replay_run_id,
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise BacktestWorkflowConflict("launch inputs are not in the immutable fixture catalog")
        if (
            input.dataset_manifest_id != input.dataset_manifest_sha256
            or row["benchmark_sha256"] != input.benchmark_sha256
            or row["cost_model_sha256"] != input.cost_model_sha256
            or row["fill_model_sha256"] != input.fill_model_sha256
            or row["metric_conventions_sha256"] != input.metric_conventions_sha256
        ):
            raise BacktestWorkflowConflict("launch fixture and model pins conflict")
        return _required_text(row, "strategy_version_id")

    def get(self, job_id: str) -> BacktestJobSnapshot:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    sa.select(phase2_backtest_jobs).where(phase2_backtest_jobs.c.job_id == job_id)
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise BacktestWorkflowError(f"unknown backtest job {job_id!r}")
            job = _job_from_row(row)
            return _snapshot(job, _projection(connection, job))

    def jobs(self, *, limit: int = 100) -> tuple[BacktestJobSnapshot, ...]:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise BacktestWorkflowError("job query limit must be between 1 and 500")
        with self._engine.connect() as connection:
            rows = tuple(
                connection.execute(
                    sa.select(phase2_backtest_jobs)
                    .order_by(phase2_backtest_jobs.c.requested_at.desc())
                    .limit(limit)
                ).mappings()
            )
            return tuple(
                _snapshot((job := _job_from_row(row)), _projection(connection, job)) for row in rows
            )

    def claim_next(
        self,
        *,
        worker_id: str,
        claimed_at: datetime,
        claim_expires_at: datetime,
    ) -> BacktestJobSnapshot | None:
        with _write_transaction(self._engine) as connection:
            statement = (
                sa.select(phase2_backtest_jobs)
                .join(
                    phase2_backtest_job_heads,
                    phase2_backtest_job_heads.c.job_id == phase2_backtest_jobs.c.job_id,
                )
                .where(
                    sa.or_(
                        phase2_backtest_job_heads.c.status == BacktestJobStatus.QUEUED.value,
                        sa.and_(
                            phase2_backtest_job_heads.c.status == BacktestJobStatus.RUNNING.value,
                            phase2_backtest_job_heads.c.claim_expires_at < claimed_at,
                        ),
                    )
                )
                .order_by(phase2_backtest_jobs.c.requested_at, phase2_backtest_jobs.c.job_id)
                .limit(1)
            )
            if connection.dialect.name == "postgresql":
                statement = statement.with_for_update(
                    of=phase2_backtest_job_heads,
                    skip_locked=True,
                )
            row = connection.execute(statement).mappings().one_or_none()
            if row is None:
                return None
            job = _job_from_row(row)
            prior = _projection(connection, job)
            updated = claim_backtest_job(
                prior,
                worker_id=worker_id,
                claimed_at=claimed_at,
                claim_expires_at=claim_expires_at,
            )
            self._append_and_advance(connection, prior, updated)
            return _snapshot(job, updated)

    def renew_claim(
        self,
        job_id: str,
        *,
        worker_id: str,
        renewed_at: datetime,
        claim_expires_at: datetime,
    ) -> BacktestJobSnapshot:
        with _write_transaction(self._engine) as connection:
            job, prior = self._locked_job(connection, job_id)
            updated = claim_backtest_job(
                prior,
                worker_id=worker_id,
                claimed_at=renewed_at,
                claim_expires_at=claim_expires_at,
            )
            self._append_and_advance(connection, prior, updated)
            return _snapshot(job, updated)

    def complete(
        self,
        job_id: str,
        *,
        worker_id: str,
        completed_at: datetime,
        report: BacktestReport,
        manifest: BacktestRunManifest,
    ) -> BacktestJobSnapshot:
        if type(report) is not BacktestReport or type(manifest) is not BacktestRunManifest:
            raise BacktestWorkflowError("completion requires exact report and manifest evidence")
        if manifest.result.status is not BacktestRunStatus.COMPLETED:
            raise BacktestWorkflowConflict("successful job requires a completed run manifest")
        if (
            manifest.report_sha256 != report.report_sha256
            or manifest.report_artifact_sha256 != report.artifact_sha256
            or manifest.result.completed_at != completed_at
        ):
            raise BacktestWorkflowConflict("job completion and report manifest do not agree")
        with _write_transaction(self._engine) as connection:
            job, prior = self._locked_job(connection, job_id)
            fixture = (
                connection.execute(
                    sa.select(phase2_backtest_fixtures).where(
                        phase2_backtest_fixtures.c.fixture_id == job.input.fixture_id,
                        phase2_backtest_fixtures.c.fixture_version == job.input.fixture_version,
                    )
                )
                .mappings()
                .one_or_none()
            )
            if fixture is None:
                raise BacktestWorkflowConflict(
                    "completed job no longer resolves to its registered fixture"
                )
            replay = manifest.dataset_replay
            expected_replay = {
                "dataset_manifest_sha256": replay.dataset_manifest_sha256,
                "source_tape_sha256": replay.source_tape_sha256,
                "replay_run_id": replay.replay_run_id,
                "replay_manifest_sha256": replay.replay_manifest_sha256,
                "replay_input_sha256": replay.replay_input_sha256,
                "replay_semantic_sha256": replay.replay_semantic_sha256,
            }
            if any(fixture[field_name] != value for field_name, value in expected_replay.items()):
                raise BacktestWorkflowConflict(
                    "completed manifest does not bind the registered fixture replay evidence"
                )
            expected_input = BacktestJobInput(
                fixture_id=job.input.fixture_id,
                fixture_version=job.input.fixture_version,
                dataset_manifest_id=manifest.dataset_replay.dataset_manifest_sha256,
                dataset_manifest_sha256=manifest.dataset_replay.dataset_manifest_sha256,
                replay_run_id=manifest.dataset_replay.replay_run_id,
                strategy_id=manifest.strategy.strategy_id,
                strategy_version=manifest.strategy.strategy_version,
                strategy_configuration_sha256=(manifest.strategy.strategy_configuration_sha256),
                benchmark_sha256=manifest.benchmark.semantic_sha256,
                cost_model_sha256=manifest.cost_model.semantic_sha256,
                fill_model_sha256=manifest.fill_model.semantic_sha256,
                metric_conventions_sha256=manifest.metric_conventions_sha256,
            )
            if expected_input != job.input:
                raise BacktestWorkflowConflict(
                    "completed manifest does not bind the immutable job inputs"
                )
            updated = complete_backtest_job(
                prior,
                worker_id=worker_id,
                completed_at=completed_at,
                run_manifest_sha256=manifest.manifest_sha256,
                report_sha256=report.report_sha256,
                report_artifact_sha256=report.artifact_sha256,
            )
            try:
                insert_or_verify_atomic(connection, phase2_backtest_reports, _report_values(report))
                insert_or_verify_atomic(
                    connection,
                    phase2_backtest_run_manifests,
                    _manifest_values(job_id, manifest),
                )
                self._append_and_advance(connection, prior, updated)
            except ImmutableFactConflict as error:
                raise BacktestWorkflowConflict(str(error)) from error
            return _snapshot(job, updated)

    def fail(
        self,
        job_id: str,
        *,
        worker_id: str,
        failed_at: datetime,
        terminal_reason_code: str,
        terminal_reason_sha256: str,
    ) -> BacktestJobSnapshot:
        with _write_transaction(self._engine) as connection:
            job, prior = self._locked_job(connection, job_id)
            updated = fail_backtest_job(
                prior,
                worker_id=worker_id,
                failed_at=failed_at,
                terminal_reason_code=terminal_reason_code,
                terminal_reason_sha256=terminal_reason_sha256,
            )
            self._append_and_advance(connection, prior, updated)
            return _snapshot(job, updated)

    def _locked_job(
        self,
        connection: Connection,
        job_id: str,
    ) -> tuple[BacktestJob, BacktestJobProjection]:
        connection.execute(
            _locked(
                sa.select(phase2_backtest_job_heads).where(
                    phase2_backtest_job_heads.c.job_id == job_id
                ),
                connection,
            )
        ).mappings().one_or_none()
        row = (
            connection.execute(
                sa.select(phase2_backtest_jobs).where(phase2_backtest_jobs.c.job_id == job_id)
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise BacktestWorkflowError(f"unknown backtest job {job_id!r}")
        job = _job_from_row(row)
        return job, _projection(connection, job)

    def _append_and_advance(
        self,
        connection: Connection,
        prior: BacktestJobProjection,
        updated: BacktestJobProjection,
    ) -> None:
        if updated.events[:-1] != prior.events:
            raise BacktestWorkflowConflict("job transition does not extend the persisted chain")
        event = updated.latest
        insert_or_verify_atomic(connection, phase2_backtest_job_events, _event_values(event))
        values = _head_values(updated)
        result = connection.execute(
            sa.update(phase2_backtest_job_heads)
            .where(
                phase2_backtest_job_heads.c.job_id == prior.job_id,
                phase2_backtest_job_heads.c.last_sequence_number == prior.latest.sequence,
                phase2_backtest_job_heads.c.last_event_sha256 == prior.latest.event_sha256,
            )
            .values(**{key: value for key, value in values.items() if key != "job_id"})
        )
        if result.rowcount != 1:
            raise BacktestWorkflowConflict("backtest job head changed concurrently")
        persisted = (
            connection.execute(
                sa.select(phase2_backtest_job_heads).where(
                    phase2_backtest_job_heads.c.job_id == updated.job_id
                )
            )
            .mappings()
            .one()
        )
        assert_immutable(phase2_backtest_job_heads, updated.job_id, persisted, values)

    def report(self, report_artifact_sha256: str) -> BacktestReportSnapshot:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    sa.select(phase2_backtest_reports).where(
                        phase2_backtest_reports.c.report_artifact_sha256 == report_artifact_sha256
                    )
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            raise BacktestWorkflowError(f"unknown backtest report {report_artifact_sha256!r}")
        report, query_payload = _report_from_row(row)
        return BacktestReportSnapshot(
            report_sha256=report.report_sha256,
            report_artifact_sha256=report.artifact_sha256,
            account_id=report.account_id,
            currency=report.currency,
            period_start=report.period_start,
            period_end=report.period_end,
            generated_at=report.generated_at,
            starting_equity=report.metrics.starting_equity,
            ending_equity=report.metrics.ending_equity,
            total_return=report.metrics.total_return,
            maximum_drawdown=report.metrics.maximum_drawdown,
            turnover=report.metrics.turnover,
            trade_count=report.metrics.trade_count,
            realized_pnl=report.metrics.realized_pnl,
            unrealized_pnl=report.metrics.unrealized_pnl,
            dividend_income=report.metrics.dividend_income,
            total_execution_costs=report.metrics.total_execution_costs,
            semantic_payload=report.canonical_json,
            query_payload=query_payload,
        )


__all__ = [
    "BacktestJobEventSnapshot",
    "BacktestJobSnapshot",
    "BacktestReportSnapshot",
    "BacktestWorkflowConflict",
    "BacktestWorkflowError",
    "SqlBacktestWorkflow",
    "StrategyCatalogRecord",
]
