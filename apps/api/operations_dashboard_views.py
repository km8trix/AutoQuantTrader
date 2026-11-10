"""Read-only HTTP projection for the local Phase 5 operations dashboard."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Final, Literal, Protocol

from fastapi import APIRouter, Header, HTTPException, Response, Security, status
from fastapi.security import APIKeyCookie

from apps.api.backtest_views import CSRF_HEADER, LOCAL_SESSION_COOKIE, LocalOperatorSecurity
from apps.api.contracts import ApiDecimal, ApiErrorResponse, ApiModel
from packages.domain.clock import Clock
from packages.domain.models import require_utc
from packages.domain.walking_thread import WalkingThreadResult

logger = logging.getLogger(__name__)

OPERATIONS_DASHBOARD_SCHEMA_VERSION: Final[Literal["phase5-operations-dashboard-v1"]] = (
    "phase5-operations-dashboard-v1"
)
_NO_STORE_HEADERS: Final = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}
_LOCAL_OPERATIONS_DASHBOARD_SESSION = APIKeyCookie(
    name=LOCAL_SESSION_COOKIE,
    scheme_name="LocalOperatorSession",
    description="URL-safe, server-issued local session value",
    auto_error=False,
)
_CsrfToken = Annotated[
    str,
    Header(
        alias=CSRF_HEADER,
        min_length=32,
        max_length=128,
        pattern=r"^[A-Za-z0-9_-]+$",
    ),
]


class OperationsDashboardError(RuntimeError):
    """Base error for the non-authorizing dashboard projection."""


class OperationsDashboardUnavailable(OperationsDashboardError):
    """Raised when a complete safe dashboard snapshot cannot be produced."""


class FreshnessStatus(StrEnum):
    CURRENT = "current"
    STALE = "stale"
    UNAVAILABLE = "unavailable"


class CoordinatorStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    UNAVAILABLE = "unavailable"


class ReconciliationStatus(StrEnum):
    CLEAN = "clean"
    DIFFERENCES = "differences"
    UNAVAILABLE = "unavailable"


class AlertDeliveryStatus(StrEnum):
    DELIVERED = "delivered"
    PENDING = "pending"
    FAILED = "failed"
    UNKNOWN = "unknown"


class OperationalFreshnessView(ApiModel):
    source_id: str
    label: str
    status: FreshnessStatus
    observed_at: datetime | None
    maximum_age_seconds: int
    detail: str


class CoordinatorOwnershipView(ApiModel):
    status: CoordinatorStatus
    owner_id: str | None
    lease_id: str | None
    fencing_generation: int | None
    heartbeat_at: datetime | None
    expires_at: datetime | None
    detail: str


class StrategyDeploymentView(ApiModel):
    deployment_id: str
    strategy_id: str
    strategy_version: str
    strategy_configuration_sha256: str
    state: str
    mode: str
    updated_at: datetime


class OperationalAccountView(ApiModel):
    currency: str
    equity: ApiDecimal
    cash: ApiDecimal
    realized_pnl: ApiDecimal
    unrealized_pnl: ApiDecimal
    gross_exposure: ApiDecimal
    net_exposure: ApiDecimal


class OperationalOrderView(ApiModel):
    order_id: str
    client_order_id: str
    intent_id: str
    risk_decision_id: str
    symbol: str
    side: str
    quantity: ApiDecimal
    filled_quantity: ApiDecimal
    status: str
    submitted_at: datetime


class OperationalFillView(ApiModel):
    fill_id: str
    order_id: str
    symbol: str
    side: str
    quantity: ApiDecimal
    price: ApiDecimal
    fee: ApiDecimal
    executed_at: datetime


class OperationalPositionView(ApiModel):
    instrument_id: str
    symbol: str
    quantity: ApiDecimal
    average_cost: ApiDecimal
    market_price: ApiDecimal
    market_value: ApiDecimal


class LedgerIntegrityView(ApiModel):
    status: Literal["balanced", "unavailable"]
    entry_count: int
    latest_entry_id: str | None
    latest_posted_at: datetime | None
    detail: str


class RiskRuleObservationView(ApiModel):
    rule: str
    passed: bool
    observed: str
    limit: str


class RiskReservationView(ApiModel):
    decision_id: str
    intent_id: str
    amount: ApiDecimal
    currency: str
    state: str
    expires_at: datetime


class OperationalRiskDecisionView(ApiModel):
    decision_id: str
    policy_version: str
    status: str
    evaluated_at: datetime
    expires_at: datetime
    rules: list[RiskRuleObservationView]


class ReconciliationDifferenceView(ApiModel):
    field: str
    local_value: str
    broker_value: str
    disposition: str


class OperationalReconciliationView(ApiModel):
    status: ReconciliationStatus
    observed_at: datetime | None
    differences: list[ReconciliationDifferenceView]
    detail: str


class OperationalAlertView(ApiModel):
    incident_id: str
    severity: str
    category: str
    opened_at: datetime
    summary: str
    delivery_status: AlertDeliveryStatus
    escalation_due_at: datetime | None


class OperationalControlReceiptView(ApiModel):
    transition_id: str
    sequence_number: int
    state: str
    command_kind: str
    actor_id: str
    decided_at: datetime


class OperationalControlView(ApiModel):
    state: str
    transition_id: str | None
    sequence_number: int | None
    blocking_event_count: int
    pending_operation: str | None
    actions_available: Literal[False]
    history: list[OperationalControlReceiptView]
    detail: str


class OperationsDashboardSnapshot(ApiModel):
    schema_version: Literal["phase5-operations-dashboard-v1"]
    as_of: datetime
    read_only: Literal[True]
    coordinator: CoordinatorOwnershipView
    deployment: StrategyDeploymentView
    freshness: list[OperationalFreshnessView]
    account: OperationalAccountView
    orders: list[OperationalOrderView]
    fills: list[OperationalFillView]
    positions: list[OperationalPositionView]
    ledger: LedgerIntegrityView
    reservations: list[RiskReservationView]
    risk_decisions: list[OperationalRiskDecisionView]
    reconciliation: OperationalReconciliationView
    alerts: list[OperationalAlertView]
    control: OperationalControlView


class OperationsDashboardQuery(Protocol):
    """Port returning one complete, observational dashboard snapshot."""

    def snapshot(self) -> OperationsDashboardSnapshot: ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _trusted_now(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="operations dashboard trusted time is unavailable",
            headers=_NO_STORE_HEADERS,
        )
    return value


def _require_ready(persistence_ready: Callable[[], bool]) -> None:
    try:
        ready = persistence_ready()
    except Exception as error:
        logger.exception("operations dashboard persistence readiness check failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="operations dashboard persistence is unavailable",
            headers=_NO_STORE_HEADERS,
        ) from error
    if ready is not True:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="operations dashboard persistence is unavailable",
            headers=_NO_STORE_HEADERS,
        )


def _freshness(
    *,
    source_id: str,
    label: str,
    observed_at: datetime | None,
    maximum_age: timedelta,
    now: datetime,
    unavailable_detail: str | None = None,
) -> OperationalFreshnessView:
    if observed_at is None:
        return OperationalFreshnessView(
            source_id=source_id,
            label=label,
            status=FreshnessStatus.UNAVAILABLE,
            observed_at=None,
            maximum_age_seconds=int(maximum_age.total_seconds()),
            detail=unavailable_detail or "No authoritative observation is available.",
        )
    age = now - observed_at
    current = timedelta(0) <= age <= maximum_age
    return OperationalFreshnessView(
        source_id=source_id,
        label=label,
        status=FreshnessStatus.CURRENT if current else FreshnessStatus.STALE,
        observed_at=observed_at,
        maximum_age_seconds=int(maximum_age.total_seconds()),
        detail=(
            "Observation is within its declared freshness budget."
            if current
            else "Observation is outside its declared freshness budget."
        ),
    )


class WalkingThreadOperationsDashboardQuery:
    """Project the deterministic local walking thread without granting authority."""

    __slots__ = ("_clock", "_result")

    def __init__(self, *, result: WalkingThreadResult, clock: Clock) -> None:
        if type(result) is not WalkingThreadResult:
            raise OperationsDashboardError(
                "operations dashboard requires an exact WalkingThreadResult"
            )
        if not callable(getattr(clock, "now", None)):
            raise OperationsDashboardError("operations dashboard requires a trusted clock")
        self._result = result
        self._clock = clock

    def snapshot(self) -> OperationsDashboardSnapshot:
        now = self._clock.now()
        require_utc(now, "operations dashboard snapshot time")
        result = self._result
        order = result.order
        fill = result.fill
        position = result.position
        decision = result.risk_decision
        latest_entry = result.ledger_entries[-1] if result.ledger_entries else None

        return OperationsDashboardSnapshot(
            schema_version=OPERATIONS_DASHBOARD_SCHEMA_VERSION,
            as_of=now,
            read_only=True,
            coordinator=CoordinatorOwnershipView(
                status=CoordinatorStatus.UNAVAILABLE,
                owner_id=None,
                lease_id=None,
                fencing_generation=None,
                heartbeat_at=None,
                expires_at=None,
                detail=(
                    "The deterministic local walking thread has no durable account "
                    "coordinator lease."
                ),
            ),
            deployment=StrategyDeploymentView(
                deployment_id="deployment-walking-thread",
                strategy_id=result.target.strategy_id,
                strategy_version=result.target.strategy_version,
                strategy_configuration_sha256=(result.target.strategy_configuration_sha256),
                state="shadow",
                mode="local",
                updated_at=result.target.as_of,
            ),
            freshness=[
                _freshness(
                    source_id="market-data",
                    label="Market data",
                    observed_at=result.fill_event.available_at,
                    maximum_age=timedelta(seconds=15),
                    now=now,
                ),
                _freshness(
                    source_id="risk",
                    label="Risk decision",
                    observed_at=decision.evaluated_at,
                    maximum_age=timedelta(seconds=15),
                    now=now,
                ),
                _freshness(
                    source_id="ledger",
                    label="Ledger projection",
                    observed_at=None if latest_entry is None else latest_entry.posted_at,
                    maximum_age=timedelta(seconds=30),
                    now=now,
                ),
                _freshness(
                    source_id="reconciliation",
                    label="Broker reconciliation",
                    observed_at=None,
                    maximum_age=timedelta(seconds=120),
                    now=now,
                    unavailable_detail=(
                        "The local simulation has no broker-authoritative reconciliation."
                    ),
                ),
            ],
            account=OperationalAccountView(
                currency=result.account.currency,
                equity=result.account.equity,
                cash=result.account.cash,
                realized_pnl=result.account.realized_pnl,
                unrealized_pnl=result.account.unrealized_pnl,
                gross_exposure=result.account.gross_exposure,
                net_exposure=result.account.net_exposure,
            ),
            orders=[
                OperationalOrderView(
                    order_id=order.order_id,
                    client_order_id=order.client_order_id,
                    intent_id=order.intent_id,
                    risk_decision_id=order.risk_decision_id,
                    symbol=order.symbol,
                    side=order.side.value,
                    quantity=order.quantity,
                    filled_quantity=order.filled_quantity,
                    status=order.status.value,
                    submitted_at=order.submitted_at,
                )
            ],
            fills=[
                OperationalFillView(
                    fill_id=fill.fill_id,
                    order_id=fill.order_id,
                    symbol=fill.symbol,
                    side=fill.side.value,
                    quantity=fill.quantity,
                    price=fill.price,
                    fee=fill.fee,
                    executed_at=fill.executed_at,
                )
            ],
            positions=[
                OperationalPositionView(
                    instrument_id=position.instrument_id,
                    symbol=position.symbol,
                    quantity=position.quantity,
                    average_cost=position.average_cost,
                    market_price=position.market_price,
                    market_value=position.market_value,
                )
            ],
            ledger=LedgerIntegrityView(
                status="balanced",
                entry_count=len(result.ledger_entries),
                latest_entry_id=None if latest_entry is None else latest_entry.entry_id,
                latest_posted_at=None if latest_entry is None else latest_entry.posted_at,
                detail="Every projected ledger entry balances exactly.",
            ),
            reservations=[
                RiskReservationView(
                    decision_id=decision.decision_id,
                    intent_id=decision.intent_id,
                    amount=decision.reserved_cash,
                    currency=result.account.currency,
                    state="consumed",
                    expires_at=decision.expires_at,
                )
            ],
            risk_decisions=[
                OperationalRiskDecisionView(
                    decision_id=decision.decision_id,
                    policy_version=decision.policy_version,
                    status=decision.status.value,
                    evaluated_at=decision.evaluated_at,
                    expires_at=decision.expires_at,
                    rules=[
                        RiskRuleObservationView(
                            rule=rule.rule,
                            passed=rule.passed,
                            observed=rule.observed,
                            limit=rule.limit,
                        )
                        for rule in decision.rules
                    ],
                )
            ],
            reconciliation=OperationalReconciliationView(
                status=ReconciliationStatus.UNAVAILABLE,
                observed_at=None,
                differences=[],
                detail=("No broker-authoritative comparison exists for the local walking thread."),
            ),
            alerts=[],
            control=OperationalControlView(
                state="unavailable",
                transition_id=None,
                sequence_number=None,
                blocking_event_count=0,
                pending_operation=None,
                actions_available=False,
                history=[],
                detail=(
                    "Operational controls are not composed into the deterministic local "
                    "walking thread."
                ),
            ),
        )


def create_operations_dashboard_router(
    *,
    query: OperationsDashboardQuery | None,
    security: LocalOperatorSecurity,
    persistence_ready: Callable[[], bool],
    clock: Callable[[], datetime] = _utc_now,
) -> APIRouter:
    """Create the authenticated, GET-only local operations dashboard router."""

    router = APIRouter(prefix="/operations", tags=["operations"])

    def unavailable() -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="operations dashboard projection is unavailable",
            headers=_NO_STORE_HEADERS,
        )

    @router.get(
        "/dashboard",
        response_model=OperationsDashboardSnapshot,
        responses={
            status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse},
            status.HTTP_403_FORBIDDEN: {"model": ApiErrorResponse},
            status.HTTP_503_SERVICE_UNAVAILABLE: {
                "model": ApiErrorResponse,
                "description": "The complete read-only operations projection is unavailable.",
            },
        },
        summary="Read the local operational dashboard",
    )
    def dashboard(
        response: Response,
        session_cookie: Annotated[
            str | None,
            Security(_LOCAL_OPERATIONS_DASHBOARD_SESSION),
        ],
        csrf_token: _CsrfToken,
    ) -> OperationsDashboardSnapshot:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        now = _trusted_now(clock)
        security.authenticate(session_cookie, csrf_token, now=now)
        _require_ready(persistence_ready)
        if query is None:
            raise unavailable()
        try:
            snapshot = query.snapshot()
        except OperationsDashboardError as error:
            logger.exception("operations dashboard projection failed")
            raise unavailable() from error
        if type(snapshot) is not OperationsDashboardSnapshot or not snapshot.read_only:
            raise unavailable()
        return snapshot

    return router
