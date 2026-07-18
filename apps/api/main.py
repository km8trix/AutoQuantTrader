"""FastAPI composition root for the Phase 0 browser/API walking thread."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import uvicorn
from fastapi import APIRouter, FastAPI, HTTPException, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError

from apps.api.config import Environment, Settings
from apps.api.contracts import (
    AlertCounts,
    DashboardSummary,
    DataCatalogResponse,
    DataQualityResponse,
    DeploymentState,
    DeploymentSummary,
    EnvironmentIdentity,
    EnvironmentMode,
    HealthCheck,
    HealthResponse,
    HealthStatus,
    MarketClock,
    MarketStatus,
    PersistenceMode,
    Readiness,
    ReadinessStatus,
    ServiceStatus,
    UiBootstrap,
    UserIdentity,
    WalkingThreadTrace,
    account_summary,
    trace_steps,
    walking_thread_view,
)
from apps.api.data_views import (
    DataCatalogDecodeError,
    catalog_response,
    quality_response,
)
from packages.domain.risk import RiskAuthorizationError
from packages.domain.walking_thread import WalkingThread, WalkingThreadResult
from packages.observability.logging import configure_logging
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    create_database_engine,
    persistence_mode,
    verify_operational_schema,
)
from packages.persistence.immutable import ImmutableFactConflict
from packages.persistence.market_data import SqlMarketDataCatalog
from packages.persistence.risk import SqlRiskDecisionRepository
from packages.persistence.walking_thread import (
    WalkingThreadUnitOfWork,
    initialize_phase_zero_schema,
)

logger = logging.getLogger(__name__)


def _probe_persistence(
    engine: Engine | None, startup_status: PersistenceMode
) -> tuple[PersistenceMode, datetime]:
    """Downgrade cached startup readiness when the database is no longer reachable."""
    if engine is None or startup_status is PersistenceMode.UNAVAILABLE:
        return PersistenceMode.UNAVAILABLE, datetime.now(UTC)
    try:
        if persistence_mode(engine) == "durable":
            verify_operational_schema(engine)
        else:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1")).scalar_one()
    except (SQLAlchemyError, DatabaseSchemaNotReady):
        logger.exception("operational persistence probe failed")
        return PersistenceMode.UNAVAILABLE, datetime.now(UTC)
    return startup_status, datetime.now(UTC)


def _readiness_reason(mode: PersistenceMode) -> list[str]:
    if mode is PersistenceMode.DURABLE:
        return []
    if mode is PersistenceMode.EPHEMERAL:
        return ["operational persistence is ephemeral"]
    return ["operational persistence unavailable"]


def _bootstrap(
    result: WalkingThreadResult,
    *,
    persistence_status: PersistenceMode,
    readiness_as_of: datetime,
) -> UiBootstrap:
    return UiBootstrap(
        user=UserIdentity(id="local-operator", display_name="Local operator"),
        environment=EnvironmentIdentity(
            name="Local simulation",
            mode=EnvironmentMode.LOCAL,
            account_id="simulation-account-001",
        ),
        market_clock=MarketClock(
            status=MarketStatus.OPEN,
            as_of=result.completed_at,
            next_transition_at=datetime(2026, 7, 15, 20, 0, tzinfo=UTC),
        ),
        readiness=Readiness(
            status=(
                ReadinessStatus.READY
                if persistence_status is PersistenceMode.DURABLE
                else ReadinessStatus.NOT_READY
            ),
            reasons=_readiness_reason(persistence_status),
            as_of=readiness_as_of,
        ),
        capabilities=[
            "research",
            "risk-gated-simulation",
            "point-in-time-data-catalog",
            "market-data-admission",
        ],
        feature_flags={
            "walking_thread": True,
            "data_catalog": True,
            "data_admission": True,
            "controls": False,
            "event_stream": False,
        },
        stream_cursor=None,
    )


def _summary(
    result: WalkingThreadResult, *, persistence_status: PersistenceMode
) -> DashboardSummary:
    operational_health = (
        HealthStatus.HEALTHY
        if persistence_status is PersistenceMode.DURABLE
        else HealthStatus.WARNING
        if persistence_status is PersistenceMode.EPHEMERAL
        else HealthStatus.CRITICAL
    )
    return DashboardSummary(
        as_of=result.completed_at,
        account=account_summary(result),
        deployment=DeploymentSummary(
            id="deployment-walking-thread",
            name="Walking thread",
            strategy_name="Fixed quantity fixture",
            state=DeploymentState.SHADOW,
            mode=EnvironmentMode.LOCAL,
        ),
        health=[
            HealthCheck(
                id="market-data",
                label="Market data",
                status=HealthStatus.HEALTHY,
                as_of=result.decision_event.available_at,
                detail="Fixed one-minute tape passed temporal validation.",
            ),
            HealthCheck(
                id="risk",
                label="Risk engine",
                status=operational_health,
                as_of=result.risk_decision.evaluated_at,
                detail=(
                    "Mandatory single-use approval was durably persisted and consumed."
                    if persistence_status is PersistenceMode.DURABLE
                    else "Risk facts are ephemeral; trading readiness is blocked."
                    if persistence_status is PersistenceMode.EPHEMERAL
                    else "Risk facts are unavailable; trading readiness is blocked."
                ),
            ),
            HealthCheck(
                id="execution",
                label="Execution",
                status=operational_health,
                as_of=result.fill.executed_at,
                detail=(
                    "The simulated order and fill are durably integrity-checked."
                    if persistence_status is PersistenceMode.DURABLE
                    else "Execution facts are not durably ready."
                ),
            ),
            HealthCheck(
                id="ledger",
                label="Ledger",
                status=operational_health,
                as_of=result.completed_at,
                detail=(
                    "All durable postings balance and rebuild the account projection."
                    if persistence_status is PersistenceMode.DURABLE
                    else "Ledger facts are not durably ready."
                ),
            ),
        ],
        alerts=AlertCounts(critical=0, warning=0),
        pending_commands=0,
        trace=trace_steps(result),
    )


def create_app(settings: Settings | None = None, engine: Engine | None = None) -> FastAPI:
    resolved_settings = settings or Settings.from_env()
    if resolved_settings.environment is not Environment.LOCAL:
        raise RuntimeError(
            "the Phase 0 fixed-tape application is local-only; paper/live startup requires "
            "real market-data, broker, and reconciliation adapters"
        )
    configure_logging(resolved_settings.log_level)
    expected_result = WalkingThread.run()
    persistence_engine = engine
    persistence_status = PersistenceMode.UNAVAILABLE
    persistence_error: str | None = None
    result: WalkingThreadResult | None = None
    try:
        if persistence_engine is None:
            persistence_engine = create_database_engine(resolved_settings.database_url)
        if persistence_mode(persistence_engine) == "ephemeral":
            initialize_phase_zero_schema(persistence_engine)
        else:
            verify_operational_schema(
                persistence_engine,
                require_phase_zero_facts=False,
            )
        unit_of_work = WalkingThreadUnitOfWork(persistence_engine)
        if unit_of_work.execution_exists(expected_result.order.order_id):
            result = expected_result
        else:
            result = WalkingThread.run(
                SqlRiskDecisionRepository(
                    persistence_engine,
                    WalkingThread.risk_authority(),
                )
            )
        unit_of_work.persist(result)
        if persistence_mode(persistence_engine) == "durable":
            verify_operational_schema(persistence_engine)
        persistence_status = PersistenceMode(persistence_mode(persistence_engine))
    except (
        SQLAlchemyError,
        DatabaseSchemaNotReady,
        ImmutableFactConflict,
        RiskAuthorizationError,
    ):
        persistence_error = "operational persistence unavailable"
        logger.exception("walking-thread persistence bootstrap failed")
    if result is None:
        result = expected_result
    app = FastAPI(
        title="AutoQuantTrader API",
        version="0.1.0",
        description="Safety-first quantitative trading control and query API.",
    )
    app.state.settings = resolved_settings
    app.state.walking_thread = result
    app.state.database_engine = persistence_engine
    app.state.persistence_ready = persistence_status is PersistenceMode.DURABLE
    app.state.persistence_status = persistence_status
    app.state.persistence_error = persistence_error

    if resolved_settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(resolved_settings.cors_origins),
            allow_credentials=True,
            allow_methods=["GET"],
            allow_headers=["Accept", "Content-Type"],
        )

    @app.get("/health/live", response_model=HealthResponse, tags=["health"])
    def live() -> HealthResponse:
        return HealthResponse(service="api", status=ServiceStatus.OK)

    @app.get(
        "/health/ready",
        response_model=HealthResponse,
        responses={
            status.HTTP_503_SERVICE_UNAVAILABLE: {
                "model": HealthResponse,
                "description": "Operational persistence is not durably ready.",
            }
        },
        tags=["health"],
    )
    def ready(response: Response) -> HealthResponse:
        current_status, _ = _probe_persistence(persistence_engine, persistence_status)
        if current_status is not PersistenceMode.DURABLE:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return HealthResponse(service="api", status=ServiceStatus.NOT_READY)
        return HealthResponse(service="api", status=ServiceStatus.READY)

    router = APIRouter(prefix="/api/v1")

    @router.get("/ui/bootstrap", response_model=UiBootstrap, tags=["ui"])
    def ui_bootstrap() -> UiBootstrap:
        current_status, probed_at = _probe_persistence(persistence_engine, persistence_status)
        return _bootstrap(
            result,
            persistence_status=current_status,
            readiness_as_of=probed_at,
        )

    @router.get("/dashboard/summary", response_model=DashboardSummary, tags=["ui"])
    def dashboard_summary() -> DashboardSummary:
        current_status, _ = _probe_persistence(persistence_engine, persistence_status)
        return _summary(result, persistence_status=current_status)

    @router.get(
        "/walking-thread/trace",
        response_model=WalkingThreadTrace,
        tags=["walking-thread"],
    )
    def walking_thread_trace() -> WalkingThreadTrace:
        current_status, _ = _probe_persistence(persistence_engine, persistence_status)
        return walking_thread_view(result, persistence_mode=current_status)

    @router.get("/data/catalog", response_model=DataCatalogResponse, tags=["market-data"])
    def data_catalog() -> DataCatalogResponse:
        current_status, probed_at = _probe_persistence(persistence_engine, persistence_status)
        if persistence_engine is None or current_status is PersistenceMode.UNAVAILABLE:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="market-data catalog persistence is unavailable",
            )
        try:
            rows = SqlMarketDataCatalog(persistence_engine).catalog_rows(as_of=probed_at)
            return catalog_response(rows)
        except (SQLAlchemyError, DataCatalogDecodeError) as error:
            logger.exception("market-data catalog read failed")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="market-data catalog is unavailable or malformed",
            ) from error

    @router.get("/data/quality", response_model=DataQualityResponse, tags=["market-data"])
    def data_quality() -> DataQualityResponse:
        current_status, probed_at = _probe_persistence(persistence_engine, persistence_status)
        if persistence_engine is None or current_status is PersistenceMode.UNAVAILABLE:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="market-data quality catalog persistence is unavailable",
            )
        try:
            rows = SqlMarketDataCatalog(persistence_engine).quality_rows(as_of=probed_at)
            return quality_response(rows)
        except (SQLAlchemyError, DataCatalogDecodeError) as error:
            logger.exception("market-data quality read failed")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="market-data quality catalog is unavailable or malformed",
            ) from error

    app.include_router(router)
    return app


app = create_app()


def run() -> None:
    settings = Settings.from_env()
    uvicorn.run(
        "apps.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=False,
    )


if __name__ == "__main__":
    run()
