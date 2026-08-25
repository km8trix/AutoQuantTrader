"""Versioned HTTP response contracts for the browser application."""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, PlainSerializer, WithJsonSchema, field_validator

from packages.domain.advanced_risk_policy import AdvancedRiskDisposition
from packages.domain.backtest_job import BacktestJobStatus
from packages.domain.backtest_report import (
    BacktestReturnFrequency,
    BacktestReturnType,
    ExternalCashFlowTreatment,
    UncertaintyMethod,
)
from packages.domain.canonical import canonical_decimal
from packages.domain.critical_alert import CriticalAlertDeliveryState
from packages.domain.decimal_math import exact_decimal_sum
from packages.domain.experiment_governance import ExperimentAttemptStatus
from packages.domain.experiment_registry import EvaluationSegmentKind, PromotionComparison
from packages.domain.fixture_segment_worker import (
    FixtureSegmentJobStatus,
    FixtureTranscriptKind,
)
from packages.domain.models import (
    DecisionStatus,
    LedgerEntry,
    OrderStatus,
    Posting,
    Side,
)
from packages.domain.operational_control import (
    OperationalControlCommandKind,
    OperationalControlOperationKind,
    OperationalControlState,
)
from packages.domain.walking_thread import WalkingThreadResult


class EnvironmentMode(StrEnum):
    LOCAL = "local"
    PAPER = "paper"
    LIVE = "live"


class MarketStatus(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    PRE_MARKET = "pre_market"
    AFTER_HOURS = "after_hours"
    UNKNOWN = "unknown"


class ReadinessStatus(StrEnum):
    READY = "ready"
    NOT_READY = "not_ready"
    RECONCILING = "reconciling"
    HALTED = "halted"
    UNKNOWN = "unknown"


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class DeploymentState(StrEnum):
    DRAFT = "draft"
    APPROVED = "approved"
    STARTING = "starting"
    RECONCILING = "reconciling"
    SHADOW = "shadow"
    RUNNING = "running"
    PAUSED = "paused"
    DRAINING = "draining"
    FLATTENING = "flattening"
    HALTED = "halted"
    STOPPED = "stopped"


class TraceStatus(StrEnum):
    COMPLETED = "completed"
    PENDING = "pending"
    FAILED = "failed"


class PersistenceMode(StrEnum):
    EPHEMERAL = "ephemeral"
    DURABLE = "durable"
    UNAVAILABLE = "unavailable"


class ServiceStatus(StrEnum):
    OK = "ok"
    READY = "ready"
    NOT_READY = "not_ready"


def _fixed_decimal_json(value: Decimal) -> str:
    """Serialize Decimal without consulting the process arithmetic context."""

    return format(canonical_decimal(value), "f")


ApiDecimal = Annotated[
    Decimal,
    PlainSerializer(_fixed_decimal_json, return_type=str, when_used="json"),
    WithJsonSchema(
        {
            "type": "string",
            "pattern": r"^(?!^[-+.]*$)[+-]?0*\d*\.?\d*$",
        },
        mode="serialization",
    ),
]


class ApiModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class ApiErrorResponse(ApiModel):
    detail: str


class UserIdentity(ApiModel):
    id: str
    display_name: str


class EnvironmentIdentity(ApiModel):
    name: str
    mode: EnvironmentMode
    account_id: str


class MarketClock(ApiModel):
    status: MarketStatus
    as_of: datetime
    next_transition_at: datetime | None


class Readiness(ApiModel):
    status: ReadinessStatus
    reasons: list[str]
    as_of: datetime


class BacktestLaunchCapability(ApiModel):
    enabled: bool
    operator_id: str | None
    csrf_token: str | None
    csrf_header: str
    idempotency_header: str
    disabled_reason: str | None


class UiBootstrap(ApiModel):
    user: UserIdentity
    environment: EnvironmentIdentity
    market_clock: MarketClock
    readiness: Readiness
    capabilities: list[str]
    feature_flags: dict[str, bool]
    stream_cursor: str | None
    backtest_launch: BacktestLaunchCapability | None


class AccountSummary(ApiModel):
    equity: ApiDecimal
    cash: ApiDecimal
    currency: str
    realized_pnl: ApiDecimal
    unrealized_pnl: ApiDecimal
    gross_exposure: ApiDecimal
    net_exposure: ApiDecimal


class DeploymentSummary(ApiModel):
    id: str
    name: str
    strategy_name: str
    state: DeploymentState
    mode: EnvironmentMode


class HealthCheck(ApiModel):
    id: str
    label: str
    status: HealthStatus
    as_of: datetime
    detail: str


class AlertCounts(ApiModel):
    critical: int
    warning: int


class TraceStepView(ApiModel):
    id: str
    stage: str
    status: TraceStatus
    occurred_at: datetime
    title: str
    detail: str


class DashboardSummary(ApiModel):
    as_of: datetime
    account: AccountSummary
    deployment: DeploymentSummary | None
    health: list[HealthCheck]
    alerts: AlertCounts
    pending_commands: int
    trace: list[TraceStepView]


class MarketEventView(ApiModel):
    event_id: str
    instrument_id: str
    symbol: str
    event_time: datetime
    available_at: datetime
    close_price: ApiDecimal
    source: str


class PositionTargetView(ApiModel):
    instrument_id: str
    symbol: str
    quantity: ApiDecimal


class TargetPortfolioView(ApiModel):
    target_id: str
    strategy_id: str
    strategy_version: str
    as_of: datetime
    expires_at: datetime
    full_snapshot: bool
    targets: list[PositionTargetView]


class OrderIntentView(ApiModel):
    intent_id: str
    target_id: str
    instrument_id: str
    symbol: str
    side: Side
    quantity: ApiDecimal
    reference_price: ApiDecimal
    decision_event_id: str
    decision_event_time: datetime
    created_at: datetime
    expires_at: datetime
    notional: ApiDecimal


class RiskRuleView(ApiModel):
    rule: str
    passed: bool
    observed: str
    limit: str


class RiskDecisionView(ApiModel):
    decision_id: str
    intent_id: str
    intent_payload_hash: str
    policy_version: str
    status: DecisionStatus
    evaluated_at: datetime
    expires_at: datetime
    reserved_cash: ApiDecimal
    persisted: bool
    persistence_mode: PersistenceMode
    rules: list[RiskRuleView]


class OrderView(ApiModel):
    order_id: str
    client_order_id: str
    intent_id: str
    risk_decision_id: str
    instrument_id: str
    symbol: str
    side: Side
    quantity: ApiDecimal
    filled_quantity: ApiDecimal
    activation_after_event_time: datetime
    submitted_at: datetime
    status: OrderStatus


class FillView(ApiModel):
    fill_id: str
    order_id: str
    instrument_id: str
    symbol: str
    side: Side
    quantity: ApiDecimal
    price: ApiDecimal
    fee: ApiDecimal
    notional: ApiDecimal
    executed_at: datetime


class PostingView(ApiModel):
    account: str
    currency: str
    debit: ApiDecimal
    credit: ApiDecimal
    units_delta: ApiDecimal
    instrument_id: str | None


class LedgerEntryView(ApiModel):
    entry_id: str
    event_type: str
    reference_id: str
    posted_at: datetime
    currency: str
    total: ApiDecimal
    balanced: bool
    postings: list[PostingView]


class PositionView(ApiModel):
    instrument_id: str
    symbol: str
    quantity: ApiDecimal
    average_cost: ApiDecimal
    market_price: ApiDecimal
    market_value: ApiDecimal


class WalkingThreadTrace(ApiModel):
    run_id: str
    started_at: datetime
    completed_at: datetime
    decision_event: MarketEventView
    fill_event: MarketEventView
    target: TargetPortfolioView
    intent: OrderIntentView
    risk_decision: RiskDecisionView
    order: OrderView
    fill: FillView
    ledger_entries: list[LedgerEntryView]
    position: PositionView
    account: AccountSummary
    trace: list[TraceStepView]


class HealthResponse(ApiModel):
    service: str
    status: ServiceStatus


class DataSourceView(ApiModel):
    source_id: str
    name: str
    kind: str
    licensed: bool
    entitlement_status: str
    detail: str


class IngestionJobView(ApiModel):
    job_id: str
    status: str
    source_id: str
    started_at: datetime
    completed_at: datetime | None
    source_record_count: int
    normalized_record_count: int
    published_partition_count: int
    quarantined_record_count: int


class DatasetPartitionView(ApiModel):
    partition_id: str
    ordinal: int
    layer: str
    object_key: str
    checksum: str
    row_count: int
    event_time_start: datetime
    event_time_end: datetime
    available_at_start: datetime
    available_at_end: datetime
    quality_status: str


class DatasetManifestView(ApiModel):
    manifest_id: str
    name: str
    manifest_hash: str
    schema_version: str
    calendar_version: str
    universe_version: str
    corporate_action_version: str
    revision_policy: str
    price_basis: str
    created_at: datetime
    row_count: int
    partitions: list[DatasetPartitionView]


class InstrumentIdentifierView(ApiModel):
    symbol: str
    venue: str
    valid_from: datetime
    valid_to: datetime | None
    available_at: datetime
    tradable: bool


class InstrumentView(ApiModel):
    instrument_id: str
    name: str
    asset_class: str
    currency: str
    status: str
    listed_at: datetime
    delisted_at: datetime | None
    mappings: list[InstrumentIdentifierView]


class CorporateActionView(ApiModel):
    action_revision_id: str
    action_id: str
    instrument_id: str
    symbol: str
    action_type: str
    revision: int
    effective_at: datetime
    available_at: datetime
    detail: str


class EntitlementView(ApiModel):
    source_id: str
    feed: str
    licensed: bool
    status: str
    scope: str
    verified_at: datetime | None


class MarketDataAdmissionCheckView(ApiModel):
    code: str
    status: str
    detail: str
    evidence_digest: str | None
    observed_at: datetime


class MarketDataAdmissionView(ApiModel):
    admission_run_id: str
    profile_id: str
    source_id: str
    manifest_id: str | None
    status: str
    profile_name: str
    adapter_type: str
    identifier_authority: str
    universe_version: str
    calendar_version: str
    corporate_action_version: str
    coverage_start: datetime
    coverage_end: datetime
    required_symbols: list[str]
    specification_digest: str
    evidence_digest: str
    report_digest: str
    executed_at: datetime
    executed_by: str
    reviewed_at: datetime | None
    reviewed_by: str | None
    review_decision: str | None
    passed_check_count: int
    failed_check_count: int
    pending_check_count: int
    detail: str
    checks: list[MarketDataAdmissionCheckView]


class DataCatalogResponse(ApiModel):
    as_of: datetime
    source: DataSourceView | None
    jobs: list[IngestionJobView]
    manifests: list[DatasetManifestView]
    instruments: list[InstrumentView]
    corporate_actions: list[CorporateActionView]
    entitlements: list[EntitlementView]
    admissions: list[MarketDataAdmissionView]


class DataQualityIssueView(ApiModel):
    issue_id: str
    code: str
    severity: str
    status: str
    summary: str
    detail: str
    detected_at: datetime
    partition_id: str | None
    quarantined: bool


class QuarantineView(ApiModel):
    partition_id: str
    reason: str
    quarantined_at: datetime
    row_count: int


class DataQualityResponse(ApiModel):
    as_of: datetime
    issues: list[DataQualityIssueView]
    quarantine: list[QuarantineView]


type Sha256Text = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class OperationsCoordinatorStatus(StrEnum):
    ACTIVE = "active"
    ABSENT = "absent"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class OperationalControlAction(StrEnum):
    PAUSE = "pause"
    DRAIN = "drain"
    FLATTEN = "flatten"
    HALT = "halt"
    REARM = "rearm"

    @property
    def command_kind(self) -> OperationalControlCommandKind:
        return OperationalControlCommandKind(self.value)


class OperationalControlCommandRequest(ApiModel):
    """Only browser-authored control input; proof fields are forbidden."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    reason_code: str = Field(min_length=1, max_length=128)

    @field_validator("reason_code")
    @classmethod
    def validate_reason_code(cls, value: str) -> str:
        if value != value.strip() or any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise ValueError("reason_code must be trimmed visible text")
        return value


class OperationsEnvironmentView(ApiModel):
    name: str = Field(min_length=1, max_length=64)
    mode: EnvironmentMode
    account_id: str = Field(min_length=1, max_length=64)
    loopback_only: bool


class OperationsReadinessView(ApiModel):
    status: ReadinessStatus
    reasons: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(max_length=64)
    as_of: datetime


class OperationsCoordinatorView(ApiModel):
    status: OperationsCoordinatorStatus
    owner_id: Annotated[str, Field(min_length=1, max_length=128)] | None
    fencing_generation: int | None
    lease_expires_at: datetime | None


class OperationalControlOperationView(ApiModel):
    attempt_id: str
    operation: OperationalControlOperationKind
    opened_at: datetime


class OperationalControlTransitionView(ApiModel):
    transition_id: str
    sequence_number: int
    prior_state: OperationalControlState | None
    effective_state: OperationalControlState
    state_changed: bool
    state_epoch_id: str
    blocker_count: int
    blocker_overflowed: bool
    active_operation: OperationalControlOperationView | None
    decided_at: datetime


class OperationalControlMutationResponse(ApiModel):
    action: OperationalControlAction
    control: OperationalControlTransitionView


class AdvancedRiskAssignmentView(ApiModel):
    assignment_id: str
    sequence_number: int
    policy_id: str
    policy_sha256: Sha256Text
    environment: str
    assigned_at: datetime


class AdvancedRiskAssessmentView(ApiModel):
    assessment_id: str
    disposition: AdvancedRiskDisposition
    assessed_at: datetime
    valid_through: datetime


class ActiveCriticalAlertView(ApiModel):
    incident_id: str
    alert_code: str
    recorded_at: datetime
    primary_delivery_state: CriticalAlertDeliveryState
    escalation_delivery_state: CriticalAlertDeliveryState
    primary_deadline_at: datetime
    escalation_deadline_at: datetime


class OperationsOverviewResponse(ApiModel):
    as_of: datetime
    environment: OperationsEnvironmentView
    readiness: OperationsReadinessView
    coordinator: OperationsCoordinatorView
    control: OperationalControlTransitionView | None
    control_history: list[OperationalControlTransitionView] = Field(max_length=512)
    current_risk_assignment: AdvancedRiskAssignmentView | None
    current_risk_assessment: AdvancedRiskAssessmentView | None
    active_alerts: list[ActiveCriticalAlertView] = Field(max_length=512)


class AdvancedRiskAssignmentMutationResponse(ApiModel):
    assignment: AdvancedRiskAssignmentView


class StrategyCatalogView(ApiModel):
    strategy_version_id: Sha256Text
    strategy_id: str
    strategy_version: str
    display_name: str
    configuration_sha256: Sha256Text
    configuration_name: str
    parameter_schema_payload: str
    parameters_payload: str
    fixture_id: str
    fixture_version: str
    dataset_manifest_sha256: Sha256Text
    replay_run_id: Sha256Text
    benchmark_sha256: Sha256Text
    cost_model_sha256: Sha256Text
    fill_model_sha256: Sha256Text
    metric_conventions_sha256: Sha256Text


class StrategyCatalogResponse(ApiModel):
    as_of: datetime
    strategies: list[StrategyCatalogView]


class BacktestJobEventView(ApiModel):
    sequence: int
    status: BacktestJobStatus
    occurred_at: datetime
    actor_id: str
    attempt_number: int
    terminal_reason_code: str | None


class BacktestJobView(ApiModel):
    job_id: Sha256Text
    input_sha256: Sha256Text
    fixture_id: str
    fixture_version: str
    strategy_id: str
    strategy_version: str
    strategy_configuration_sha256: Sha256Text
    requested_by: str
    requested_at: datetime
    status: BacktestJobStatus
    attempt_number: int
    worker_id: str | None
    claim_expires_at: datetime | None
    updated_at: datetime
    run_manifest_sha256: Sha256Text | None
    report_sha256: Sha256Text | None
    report_artifact_sha256: Sha256Text | None
    terminal_reason_code: str | None
    history: list[BacktestJobEventView]


class BacktestJobListResponse(ApiModel):
    as_of: datetime
    jobs: list[BacktestJobView]


class ExperimentHoldoutState(StrEnum):
    SEALED = "sealed"
    REVEALED = "revealed"


class ExperimentSummaryView(ApiModel):
    family_id: Sha256Text
    family_name: str
    hypothesis: str
    owner_id: str
    created_at: datetime
    strategy_id: str
    strategy_version: str
    strategy_version_sha256: Sha256Text
    evaluation_plan_version: str
    evaluation_plan_sha256: Sha256Text
    promotion_criteria_sha256: Sha256Text
    test_commitment_sha256: Sha256Text
    maximum_pre_holdout_trials: int
    pre_holdout_attempt_count: int
    remaining_pre_holdout_attempts: int
    attempt_count: int
    holdout_state: ExperimentHoldoutState
    snapshot_sha256: Sha256Text
    registry_head_sha256: Sha256Text


class ExperimentSegmentView(ApiModel):
    kind: EvaluationSegmentKind
    segment_sha256: Sha256Text | None
    coverage_start: datetime
    coverage_end: datetime
    dataset_replay_sha256: Sha256Text | None
    purge_before: timedelta
    embargo_after: timedelta


class ExperimentPromotionCriterionView(ApiModel):
    metric_name: str
    comparison: PromotionComparison
    threshold: ApiDecimal
    minimum_observations: int


class ExperimentPromotionCriteriaView(ApiModel):
    criteria_sha256: Sha256Text
    criteria_version: str
    criteria: list[ExperimentPromotionCriterionView]
    selection_rule: str
    multiple_testing_method: str
    maximum_pre_holdout_trials: int
    frozen_at: datetime
    frozen_by: str


class ExperimentEvaluationReceiptView(ApiModel):
    evidence_kind: str
    family_id: Sha256Text
    attempt_id: Sha256Text
    receipt_sha256: Sha256Text
    strategy_version_sha256: Sha256Text
    configuration_sha256: Sha256Text
    configuration_validation_sha256: Sha256Text
    segment_kind: EvaluationSegmentKind
    segment_sha256: Sha256Text
    source_evidence_sha256: Sha256Text
    holdout_reveal_sha256: Sha256Text | None
    feature_certification_sha256: Sha256Text
    target_policy_sha256: Sha256Text
    target_runtime_pin_sha256: Sha256Text
    target_certification_sha256: Sha256Text
    batch_result_sha256: Sha256Text
    incremental_result_sha256: Sha256Text
    target_parity_receipt_sha256: Sha256Text
    target_transcript_sha256: Sha256Text
    step_count: int = Field(ge=1, le=100_000)
    target_count: int = Field(ge=0, le=100_000)
    running_event_sha256: Sha256Text
    started_at: datetime
    completed_at: datetime
    evaluated_by: str = Field(min_length=1, max_length=128)


class ExperimentAttemptEventView(ApiModel):
    event_sha256: Sha256Text
    global_sequence_number: int
    attempt_sequence_number: int
    status: ExperimentAttemptStatus
    occurred_at: datetime
    actor_id: str
    terminal_evidence_sha256: Sha256Text | None
    terminal_reason_code: str | None
    evaluation: ExperimentEvaluationReceiptView | None


class ExperimentAttemptView(ApiModel):
    attempt_id: Sha256Text
    attempt_number: int
    configuration_sha256: Sha256Text
    configuration_name: str
    configuration_validation_sha256: Sha256Text
    segment_kind: EvaluationSegmentKind
    segment_sha256: Sha256Text
    requested_at: datetime
    requested_by: str
    holdout_reveal_sha256: Sha256Text | None
    status: ExperimentAttemptStatus
    history: list[ExperimentAttemptEventView]


class ExperimentHoldoutView(ApiModel):
    state: ExperimentHoldoutState
    commitment_sha256: Sha256Text
    authorization_sha256: Sha256Text | None
    reveal_sha256: Sha256Text | None
    selected_configuration_sha256: Sha256Text | None
    pre_reveal_snapshot_sha256: Sha256Text | None
    pre_reveal_registry_head_sha256: Sha256Text | None
    pre_reveal_attempts_sha256: Sha256Text | None
    pre_reveal_attempt_count: int | None
    revealed_at: datetime | None
    revealed_by: str | None
    access_reason: str | None


class ExperimentView(ApiModel):
    summary: ExperimentSummaryView
    segments: list[ExperimentSegmentView]
    promotion_criteria: ExperimentPromotionCriteriaView
    attempts: list[ExperimentAttemptView]
    holdout: ExperimentHoldoutView


class ExperimentListResponse(ApiModel):
    as_of: datetime
    experiments: list[ExperimentSummaryView]


class ExperimentResponse(ApiModel):
    as_of: datetime
    experiment: ExperimentView


class FixtureTranscriptProvenanceView(ApiModel):
    kind: FixtureTranscriptKind
    family_id: Sha256Text
    attempt_id: Sha256Text
    segment_kind: EvaluationSegmentKind
    configuration_sha256: Sha256Text | None
    certification_sha256: Sha256Text
    parity_receipt_sha256: Sha256Text
    transcript_sha256: Sha256Text
    step_count: int = Field(ge=1, le=100_000)
    output_count: int = Field(ge=0, le=5_000_000)


class FixtureSegmentEventProvenanceView(ApiModel):
    sequence: int = Field(ge=0, le=9_999)
    status: FixtureSegmentJobStatus
    occurred_at: datetime
    attempt_number: int = Field(ge=0, le=9_999)
    claim_expires_at: datetime | None
    governance_event_sha256: Sha256Text
    completion_receipt_sha256: Sha256Text | None


class FixtureSegmentJobSummaryView(ApiModel):
    job_id: Sha256Text
    family_id: Sha256Text
    attempt_id: Sha256Text
    configuration_sha256: Sha256Text
    segment_kind: EvaluationSegmentKind
    requested_at: datetime
    status: FixtureSegmentJobStatus
    event_count: int = Field(ge=1, le=10_000)
    latest_sequence: int = Field(ge=0, le=9_999)
    latest_occurred_at: datetime
    completion_receipt_sha256: Sha256Text | None


class FixtureSegmentJobProvenanceView(ApiModel):
    summary: FixtureSegmentJobSummaryView
    configuration_validation_sha256: Sha256Text
    queued_governance_event_sha256: Sha256Text
    feature_certification_sha256: Sha256Text
    feature_artifact: FixtureTranscriptProvenanceView
    target_artifact: FixtureTranscriptProvenanceView | None
    total_event_count: int = Field(ge=1, le=10_000)
    events: list[FixtureSegmentEventProvenanceView] = Field(max_length=100)
    next_before_sequence: int | None = Field(ge=1, le=9_999)


class FixtureSegmentJobListResponse(ApiModel):
    as_of: datetime
    jobs: list[FixtureSegmentJobSummaryView] = Field(max_length=100)
    next_before_job_id: Sha256Text | None


class FixtureSegmentJobResponse(ApiModel):
    as_of: datetime
    job: FixtureSegmentJobProvenanceView


class BacktestLaunchRequest(BaseModel):
    """Strict, bounded transport form of the immutable fixture job input."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    fixture_id: str = Field(min_length=1, max_length=128)
    fixture_version: str = Field(min_length=1, max_length=128)
    dataset_manifest_id: Sha256Text
    dataset_manifest_sha256: Sha256Text
    replay_run_id: Sha256Text
    strategy_id: str = Field(min_length=1, max_length=128)
    strategy_version: str = Field(min_length=1, max_length=128)
    strategy_configuration_sha256: Sha256Text
    benchmark_sha256: Sha256Text
    cost_model_sha256: Sha256Text
    fill_model_sha256: Sha256Text
    metric_conventions_sha256: Sha256Text

    @field_validator("fixture_id", "fixture_version", "strategy_id", "strategy_version")
    @classmethod
    def validate_bounded_identifier(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("identifier must be trimmed text without control characters")
        return value


class BacktestMetricConventionsView(ApiModel):
    convention_id: str
    convention_version: str
    currency: str
    return_type: BacktestReturnType
    return_frequency: BacktestReturnFrequency
    annualization_periods: int
    annual_risk_free_rate: ApiDecimal
    risk_free_rate_version: str
    external_cash_flow_treatment: ExternalCashFlowTreatment
    uncertainty_method: UncertaintyMethod
    absolute_tolerance: ApiDecimal
    relative_tolerance: ApiDecimal


class BacktestMetricsView(ApiModel):
    starting_equity: ApiDecimal
    ending_equity: ApiDecimal
    total_return: ApiDecimal
    annualized_return: ApiDecimal | None
    annualized_volatility: ApiDecimal | None
    sharpe_ratio: ApiDecimal | None
    sortino_ratio: ApiDecimal | None
    maximum_drawdown: ApiDecimal
    turnover: ApiDecimal
    average_gross_exposure: ApiDecimal
    average_net_exposure: ApiDecimal
    trade_count: int
    winning_trade_count: int
    losing_trade_count: int
    breakeven_trade_count: int
    hit_rate: ApiDecimal | None
    profit_factor: ApiDecimal | None
    total_execution_costs: ApiDecimal
    capacity_proxy: ApiDecimal | None
    realized_pnl: ApiDecimal
    unrealized_pnl: ApiDecimal
    dividend_income: ApiDecimal


class BacktestEquityPointView(ApiModel):
    sequence: int
    as_of: datetime
    cash: ApiDecimal
    market_value: ApiDecimal
    equity: ApiDecimal
    gross_exposure: ApiDecimal
    net_exposure: ApiDecimal
    cumulative_external_cash_flow: ApiDecimal
    period_return: ApiDecimal
    cumulative_return: ApiDecimal
    drawdown: ApiDecimal


class BacktestTradeView(ApiModel):
    sequence: int
    trade_id: str
    instrument_id: str
    symbol: str
    opened_at: datetime
    closed_at: datetime
    quantity: ApiDecimal
    cost_basis: ApiDecimal
    proceeds: ApiDecimal
    gross_pnl: ApiDecimal
    execution_costs: ApiDecimal
    net_pnl: ApiDecimal
    opening_execution_sha256: Sha256Text
    closing_execution_sha256: Sha256Text


class BacktestPositionView(ApiModel):
    sequence: int
    as_of: datetime
    instrument_id: str
    symbol: str
    quantity: ApiDecimal
    cost_basis: ApiDecimal
    mark_price: ApiDecimal
    market_value: ApiDecimal
    realized_pnl: ApiDecimal
    unrealized_pnl: ApiDecimal
    execution_costs: ApiDecimal
    dividend_income: ApiDecimal
    source_projection_sha256: Sha256Text


class BacktestLedgerTraceView(ApiModel):
    sequence: int
    entry_id: str
    entry_kind: str
    source_fact_id: str
    effective_at: datetime
    recorded_at: datetime
    entry_sha256: Sha256Text


class BacktestReportProvenanceView(ApiModel):
    execution_ledger_sha256: Sha256Text
    corporate_action_ledger_sha256: Sha256Text
    settlement_ledger_sha256: Sha256Text
    account_projection_sha256: Sha256Text
    accounting_evidence_sha256: Sha256Text


class BacktestReportView(ApiModel):
    report_sha256: Sha256Text
    report_artifact_sha256: Sha256Text
    account_id: str
    currency: str
    period_start: datetime
    period_end: datetime
    generated_at: datetime
    conventions: BacktestMetricConventionsView
    metrics: BacktestMetricsView
    equity_curve: list[BacktestEquityPointView]
    trades: list[BacktestTradeView]
    positions: list[BacktestPositionView]
    ledger_trace: list[BacktestLedgerTraceView]
    provenance: BacktestReportProvenanceView


def posting_view(posting: Posting) -> PostingView:
    return PostingView(
        account=posting.account,
        currency=posting.currency,
        debit=posting.debit,
        credit=posting.credit,
        units_delta=posting.units_delta,
        instrument_id=posting.instrument_id,
    )


def ledger_entry_view(entry: LedgerEntry) -> LedgerEntryView:
    debits = entry.total
    credits = exact_decimal_sum(posting.credit for posting in entry.postings)
    return LedgerEntryView(
        entry_id=entry.entry_id,
        event_type=entry.event_type,
        reference_id=entry.reference_id,
        posted_at=entry.posted_at,
        currency=entry.currency,
        total=entry.total,
        balanced=debits == credits,
        postings=[posting_view(posting) for posting in entry.postings],
    )


def account_summary(result: WalkingThreadResult) -> AccountSummary:
    return AccountSummary(
        equity=result.account.equity,
        cash=result.account.cash,
        currency=result.account.currency,
        realized_pnl=result.account.realized_pnl,
        unrealized_pnl=result.account.unrealized_pnl,
        gross_exposure=result.account.gross_exposure,
        net_exposure=result.account.net_exposure,
    )


def trace_steps(result: WalkingThreadResult) -> list[TraceStepView]:
    return [
        TraceStepView(
            id=step.trace_id,
            stage=step.stage,
            status=TraceStatus(step.status),
            occurred_at=step.occurred_at,
            title=step.title,
            detail=step.detail,
        )
        for step in result.trace
    ]


def walking_thread_view(
    result: WalkingThreadResult, *, persistence_mode: PersistenceMode
) -> WalkingThreadTrace:
    return WalkingThreadTrace(
        run_id=result.run_id,
        started_at=result.started_at,
        completed_at=result.completed_at,
        decision_event=MarketEventView(
            event_id=result.decision_event.event_id,
            instrument_id=result.decision_event.instrument_id,
            symbol=result.decision_event.symbol,
            event_time=result.decision_event.event_time,
            available_at=result.decision_event.available_at,
            close_price=result.decision_event.close_price,
            source=result.decision_event.source,
        ),
        fill_event=MarketEventView(
            event_id=result.fill_event.event_id,
            instrument_id=result.fill_event.instrument_id,
            symbol=result.fill_event.symbol,
            event_time=result.fill_event.event_time,
            available_at=result.fill_event.available_at,
            close_price=result.fill_event.close_price,
            source=result.fill_event.source,
        ),
        target=TargetPortfolioView(
            target_id=result.target.target_id,
            strategy_id=result.target.strategy_id,
            strategy_version=result.target.strategy_version,
            as_of=result.target.as_of,
            expires_at=result.target.expires_at,
            full_snapshot=result.target.full_snapshot,
            targets=[
                PositionTargetView(
                    instrument_id=target.instrument_id,
                    symbol=target.symbol,
                    quantity=target.quantity,
                )
                for target in result.target.targets
            ],
        ),
        intent=OrderIntentView(
            intent_id=result.intent.intent_id,
            target_id=result.intent.target_id,
            instrument_id=result.intent.instrument_id,
            symbol=result.intent.symbol,
            side=result.intent.side,
            quantity=result.intent.quantity,
            reference_price=result.intent.reference_price,
            decision_event_id=result.intent.decision_event_id,
            decision_event_time=result.intent.decision_event_time,
            created_at=result.intent.created_at,
            expires_at=result.intent.expires_at,
            notional=result.intent.notional,
        ),
        risk_decision=RiskDecisionView(
            decision_id=result.risk_decision.decision_id,
            intent_id=result.risk_decision.intent_id,
            intent_payload_hash=result.risk_decision.intent_payload_hash,
            policy_version=result.risk_decision.policy_version,
            status=result.risk_decision.status,
            evaluated_at=result.risk_decision.evaluated_at,
            expires_at=result.risk_decision.expires_at,
            reserved_cash=result.risk_decision.reserved_cash,
            persisted=persistence_mode == "durable",
            persistence_mode=persistence_mode,
            rules=[
                RiskRuleView(
                    rule=rule.rule,
                    passed=rule.passed,
                    observed=rule.observed,
                    limit=rule.limit,
                )
                for rule in result.risk_decision.rules
            ],
        ),
        order=OrderView(
            order_id=result.order.order_id,
            client_order_id=result.order.client_order_id,
            intent_id=result.order.intent_id,
            risk_decision_id=result.order.risk_decision_id,
            instrument_id=result.order.instrument_id,
            symbol=result.order.symbol,
            side=result.order.side,
            quantity=result.order.quantity,
            filled_quantity=result.order.filled_quantity,
            activation_after_event_time=result.order.activation_after_event_time,
            submitted_at=result.order.submitted_at,
            status=result.order.status,
        ),
        fill=FillView(
            fill_id=result.fill.fill_id,
            order_id=result.fill.order_id,
            instrument_id=result.fill.instrument_id,
            symbol=result.fill.symbol,
            side=result.fill.side,
            quantity=result.fill.quantity,
            price=result.fill.price,
            fee=result.fill.fee,
            notional=result.fill.notional,
            executed_at=result.fill.executed_at,
        ),
        ledger_entries=[ledger_entry_view(entry) for entry in result.ledger_entries],
        position=PositionView(
            instrument_id=result.position.instrument_id,
            symbol=result.position.symbol,
            quantity=result.position.quantity,
            average_cost=result.position.average_cost,
            market_price=result.position.market_price,
            market_value=result.position.market_value,
        ),
        account=account_summary(result),
        trace=trace_steps(result),
    )
