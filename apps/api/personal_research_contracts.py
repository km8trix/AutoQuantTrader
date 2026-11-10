"""Bounded browser projections for actual personal research workers.

These records describe HTTP inputs and outputs only. Admission, identities,
accounting, metrics, trial planning and publication belong to the application.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Literal

from pydantic import ConfigDict, Field

from apps.api.contracts import ApiDecimal, ApiModel, Sha256Text

type PersonalText = Annotated[str, Field(min_length=1, max_length=256)]
type PersonalDecimalInput = Annotated[
    str, Field(pattern=r"^-?(0|[1-9]\d*)(\.\d+)?$", max_length=100)
]
type PersonalRunStatus = Literal[
    "queued", "running", "completed", "incomplete", "failed", "cancelled"
]
type PersonalRowsKind = Literal["equity", "executions", "fifo", "journal", "positions"]


class PersonalRequest(ApiModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class PersonalCapability(ApiModel):
    enabled: bool
    reasons: list[str]


class PersonalDatasetView(ApiModel):
    dataset_id: str
    manifest_sha256: Sha256Text
    display_name: str
    data_class: str
    symbols: list[str]
    start_session: date
    end_session: date
    session_count: int
    availability_policy: str
    prior_access: Literal["known_accessed", "unknown"]
    limitations: list[str]


class PersonalConfiguration(PersonalRequest):
    kind: Literal["buy_hold", "trend_sma"]
    lookback: int = Field(ge=1, le=10000)
    allocation: PersonalDecimalInput
    rebalance_sessions: int | None = Field(ge=1, le=10000)


class PersonalStrategyView(ApiModel):
    strategy_id: str
    version: str
    display_name: str
    description: str
    default_configuration: PersonalConfiguration
    minimum_lookback: int
    maximum_lookback: int
    default_warmup_sessions: int
    limitations: list[str]


class PersonalCostScenario(ApiModel):
    scenario_id: str
    display_name: str
    slippage_bps: ApiDecimal
    fee_per_share: ApiDecimal
    assumptions: list[str]


class PersonalResearchCatalog(ApiModel):
    as_of: datetime
    datasets: list[PersonalDatasetView] = Field(max_length=200)
    strategies: list[PersonalStrategyView] = Field(max_length=20)
    cost_scenarios: list[PersonalCostScenario] = Field(max_length=20)
    launch: PersonalCapability
    cancel: PersonalCapability
    experiments: PersonalCapability
    limitations: list[str]


class PersonalRunRequest(PersonalRequest):
    dataset_id: PersonalText
    dataset_manifest_sha256: Sha256Text
    strategy_id: PersonalText
    strategy_version: PersonalText
    configuration: PersonalConfiguration
    initial_cash: PersonalDecimalInput
    warmup_sessions: int = Field(ge=0, le=10000)
    scored_start: date | None
    scored_end: date | None
    cost_scenario_id: PersonalText


class PersonalAttemptView(ApiModel):
    attempt_id: str
    attempt_number: int
    status: Literal["running", "completed", "incomplete", "failed", "cancelled", "abandoned"]
    started_at: datetime
    ended_at: datetime | None
    reasons: list[str]


class PersonalRunView(ApiModel):
    job_id: str
    run_id: str
    spec_sha256: Sha256Text
    dataset_id: str
    dataset_manifest_sha256: Sha256Text
    data_class: str
    strategy_id: str
    strategy_version: str
    configuration: PersonalConfiguration
    cost_scenario_id: str
    status: PersonalRunStatus
    cancel_requested: bool
    requested_at: datetime
    updated_at: datetime
    progress_completed: int | None
    progress_total: int | None
    progress_unit: str | None
    attempts: list[PersonalAttemptView] = Field(max_length=200)
    report_sha256: Sha256Text | None
    result_sha256: Sha256Text | None
    reasons: list[str]
    limitations: list[str]


class PersonalRunList(ApiModel):
    as_of: datetime
    jobs: list[PersonalRunView] = Field(max_length=200)
    truncated: bool


class PersonalCoverageExclusion(ApiModel):
    row_id: str
    reasons: list[str]


class PersonalMetricCoverage(ApiModel):
    interval_id: str
    expected_sessions: int
    observed_sessions: int
    valid_sessions: int
    valid_returns: int
    sample_count: int
    input_sha256: Sha256Text
    contributing_row_ids: list[str] = Field(max_length=200)
    excluded: list[PersonalCoverageExclusion] = Field(max_length=200)
    lineage_truncated: bool


class PersonalMetric(ApiModel):
    name: str
    value: ApiDecimal | None
    unit: str
    status: Literal["defined", "undefined", "approximate"]
    coverage: PersonalMetricCoverage
    conventions_sha256: Sha256Text
    reasons: list[str]
    assumptions: list[str]


class PersonalReportInterval(ApiModel):
    interval_id: str
    fold_id: str
    scored_start: date | None
    scored_end: date | None
    warmup_start: date | None
    warmup_end: date | None
    expected_sessions: int
    reset_mode: str
    baseline_valuation_id: str
    terminal_valuation_id: str


class PersonalNamedValue(ApiModel):
    name: str
    value: str


class PersonalRunReport(ApiModel):
    job_id: str
    run_id: str
    report_sha256: Sha256Text
    result_sha256: Sha256Text
    artifact_sha256: Sha256Text
    attempt_id: str
    generated_at: datetime
    status: Literal["completed", "incomplete"]
    currency: str
    dataset_id: str
    data_class: str
    interval: PersonalReportInterval
    metrics: list[PersonalMetric] = Field(max_length=100)
    benchmark_metrics: list[PersonalMetric] = Field(max_length=100)
    cash_metrics: list[PersonalMetric] = Field(max_length=100)
    benchmark_name: str
    conventions: list[PersonalNamedValue] = Field(max_length=100)
    provenance: list[PersonalNamedValue] = Field(max_length=100)
    assumptions: list[str]
    limitations: list[str]
    reasons: list[str]
    export_url: str | None


class PersonalEquityRow(ApiModel):
    kind: Literal["equity"]
    row_id: str
    sequence: int
    economic_at: datetime
    knowledge_at: datetime
    session: date
    roles: list[str]
    nav: ApiDecimal | None
    wealth: ApiDecimal | None
    drawdown: ApiDecimal | None
    signed_flow: ApiDecimal
    flow_id: str | None
    paired_row_id: str | None
    last_known_nav: ApiDecimal | None
    last_known_at: datetime | None
    benchmark_nav: ApiDecimal | None
    benchmark_wealth: ApiDecimal | None
    cash_nav: ApiDecimal | None
    cash_wealth: ApiDecimal | None
    reasons: list[str]
    benchmark_reasons: list[str]
    cash_reasons: list[str]


class PersonalExecutionRow(ApiModel):
    kind: Literal["executions"]
    execution_id: str
    revision: int
    order_id: str
    intent_id: str
    symbol: str
    side: str
    quantity: ApiDecimal
    price: ApiDecimal
    fee: ApiDecimal
    occurred_at: datetime
    source_row_ids: list[str]


class PersonalFifoRow(ApiModel):
    kind: Literal["fifo"]
    closing_order_id: str
    symbol: str
    completed: bool
    quantity: ApiDecimal
    gross_pnl: ApiDecimal
    buy_fees: ApiDecimal
    sell_fees: ApiDecimal
    net_pnl: ApiDecimal
    match_ids: list[str]
    execution_ids: list[str]
    split_ids: list[str]


class PersonalJournalRow(ApiModel):
    kind: Literal["journal"]
    entry_id: str
    sequence: int
    occurred_at: datetime
    event_type: str
    description: str
    amounts: list[PersonalNamedValue]
    source_row_ids: list[str]


class PersonalPositionRow(ApiModel):
    kind: Literal["positions"]
    symbol: str
    quantity: ApiDecimal
    cost_basis: ApiDecimal
    market_value: ApiDecimal | None
    unrealized_pnl: ApiDecimal | None
    mark: ApiDecimal | None
    mark_at: datetime | None
    reasons: list[str]


type PersonalReportRow = Annotated[
    PersonalEquityRow
    | PersonalExecutionRow
    | PersonalFifoRow
    | PersonalJournalRow
    | PersonalPositionRow,
    Field(discriminator="kind"),
]


class PersonalRunRows(ApiModel):
    job_id: str
    report_sha256: Sha256Text
    kind: PersonalRowsKind
    offset: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    total: int = Field(ge=0)
    rows: list[PersonalReportRow] = Field(max_length=200)


class PersonalComparisonRequest(PersonalRequest):
    job_ids: list[PersonalText] = Field(min_length=2, max_length=8)


class PersonalComparisonItem(ApiModel):
    job_id: str
    run_id: str
    report_sha256: Sha256Text
    dataset_id: str
    data_class: str
    strategy_id: str
    configuration: PersonalConfiguration
    cost_scenario_id: str
    interval: PersonalReportInterval
    metrics: list[PersonalMetric]
    benchmark_metrics: list[PersonalMetric]
    assumptions: list[str]
    limitations: list[str]


class PersonalComparison(ApiModel):
    comparison_sha256: Sha256Text
    comparable: bool
    reasons: list[str]
    differences: list[PersonalNamedValue]
    runs: list[PersonalComparisonItem] = Field(min_length=2, max_length=8)


class PersonalPriorAccess(PersonalRequest):
    status: Literal["known_accessed", "unknown"]
    description: str = Field(min_length=1, max_length=2000)


class PersonalExperimentCandidate(PersonalRequest):
    candidate_id: PersonalText
    configuration: PersonalConfiguration


class PersonalExperimentFold(PersonalRequest):
    fold_id: PersonalText
    train_start: date
    train_end: date
    validation_start: date
    validation_end: date
    test_start: date
    test_end: date


class PersonalExperimentRequest(PersonalRequest):
    name: PersonalText
    hypothesis: str = Field(min_length=1, max_length=2000)
    dataset_id: PersonalText
    candidates: list[PersonalExperimentCandidate] = Field(min_length=1, max_length=8)
    folds: list[PersonalExperimentFold] = Field(min_length=1, max_length=8)
    warmup_sessions: int = Field(ge=0, le=10000)
    prior_access: PersonalPriorAccess


class PersonalExperimentTrial(ApiModel):
    trial_id: str
    candidate_id: str
    fold_id: str
    window: Literal["train", "validation", "test"]
    cost_scenario_id: str
    status: PersonalRunStatus
    job_id: str | None
    report_sha256: Sha256Text | None
    reasons: list[str]
    metrics: list[PersonalMetric]
    benchmark_metrics: list[PersonalMetric]


class PersonalExperimentView(ApiModel):
    experiment_id: str
    protocol_sha256: Sha256Text
    requested_at: datetime
    updated_at: datetime
    request: PersonalExperimentRequest
    status: PersonalRunStatus
    evaluation_mode: Literal["descriptive_only"]
    suitability: Literal["not_assessed"]
    planned_trial_count: int
    cost_scenarios: list[PersonalCostScenario] = Field(min_length=4, max_length=4)
    trials: list[PersonalExperimentTrial] = Field(max_length=1000)
    provenance: list[PersonalNamedValue]
    limitations: list[str]
    reasons: list[str]
    export_url: str | None


class PersonalExperimentList(ApiModel):
    as_of: datetime
    experiments: list[PersonalExperimentView] = Field(max_length=100)
    truncated: bool
