"""Versioned HTTP response contracts for the browser application."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from packages.domain.models import (
    DecisionStatus,
    LedgerEntry,
    OrderStatus,
    Posting,
    Side,
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


class ApiModel(BaseModel):
    model_config = ConfigDict(frozen=True)


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


class UiBootstrap(ApiModel):
    user: UserIdentity
    environment: EnvironmentIdentity
    market_clock: MarketClock
    readiness: Readiness
    capabilities: list[str]
    feature_flags: dict[str, bool]
    stream_cursor: str | None


class AccountSummary(ApiModel):
    equity: Decimal
    cash: Decimal
    currency: str
    realized_pnl: Decimal
    unrealized_pnl: Decimal
    gross_exposure: Decimal
    net_exposure: Decimal


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
    close_price: Decimal
    source: str


class PositionTargetView(ApiModel):
    instrument_id: str
    symbol: str
    quantity: Decimal


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
    quantity: Decimal
    reference_price: Decimal
    decision_event_id: str
    decision_event_time: datetime
    created_at: datetime
    expires_at: datetime
    notional: Decimal


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
    reserved_cash: Decimal
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
    quantity: Decimal
    filled_quantity: Decimal
    activation_after_event_time: datetime
    submitted_at: datetime
    status: OrderStatus


class FillView(ApiModel):
    fill_id: str
    order_id: str
    instrument_id: str
    symbol: str
    side: Side
    quantity: Decimal
    price: Decimal
    fee: Decimal
    notional: Decimal
    executed_at: datetime


class PostingView(ApiModel):
    account: str
    currency: str
    debit: Decimal
    credit: Decimal
    units_delta: Decimal
    instrument_id: str | None


class LedgerEntryView(ApiModel):
    entry_id: str
    event_type: str
    reference_id: str
    posted_at: datetime
    currency: str
    total: Decimal
    balanced: bool
    postings: list[PostingView]


class PositionView(ApiModel):
    instrument_id: str
    symbol: str
    quantity: Decimal
    average_cost: Decimal
    market_price: Decimal
    market_value: Decimal


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
    debits = sum((posting.debit for posting in entry.postings), Decimal("0"))
    credits = sum((posting.credit for posting in entry.postings), Decimal("0"))
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
