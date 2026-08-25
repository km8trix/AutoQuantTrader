"""FastAPI composition root for the Phase 0 browser/API walking thread."""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime

import uvicorn
from fastapi import APIRouter, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError

from apps.api.backtest_views import (
    CSRF_HEADER,
    IDEMPOTENCY_HEADER,
    LOCAL_SESSION_COOKIE,
    LocalOperatorSecurity,
    create_backtest_router,
)
from apps.api.config import Environment, LocalCredentials, Settings
from apps.api.contracts import (
    AlertCounts,
    BacktestLaunchCapability,
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
from apps.api.experiment_views import (
    ExperimentGovernanceQuery,
    create_experiment_router,
)
from apps.api.fixture_segment_views import (
    FixtureSegmentProvenanceQuery,
    create_fixture_segment_router,
)
from apps.api.operations_dashboard_views import (
    WalkingThreadOperationsDashboardQuery,
    create_operations_dashboard_router,
)
from apps.api.operations_views import (
    AdvancedRiskAssignmentCommandService,
    DurableLocalOperationsQuery,
    LocalOperationsQuery,
    OperationalControlCommandService,
    create_operations_router,
)
from packages.application.backtest_worker import ensure_golden_research_catalog
from packages.application.local_operations import (
    DatabaseOnlyOperationalControlService,
)
from packages.domain.canonical import canonical_json_bytes
from packages.domain.clock import SystemClock
from packages.domain.operational_control import OperationalControlCommandKind
from packages.domain.risk import RiskAuthorizationError
from packages.domain.walking_thread import WalkingThread, WalkingThreadResult
from packages.observability.logging import configure_logging
from packages.persistence.backtest_workflow import BacktestWorkflowError, SqlBacktestWorkflow
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    create_database_engine,
    persistence_mode,
    verify_operational_schema,
)
from packages.persistence.experiment_governance import (
    ExperimentGovernanceError,
    SqlExperimentGovernance,
)
from packages.persistence.fixture_segment_worker import (
    FixtureSegmentPersistenceError,
    SqlFixtureSegmentProvenanceQuery,
)
from packages.persistence.immutable import ImmutableFactConflict
from packages.persistence.local_operations import SqlLocalOperationsSnapshotReader
from packages.persistence.market_data import SqlMarketDataCatalog
from packages.persistence.operational_control import SqlOperationalControlRepository
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


def _available_control_actions(
    service: OperationalControlCommandService | None,
) -> frozenset[OperationalControlCommandKind]:
    if service is None:
        return frozenset()
    declared = getattr(service, "available_actions", None)
    if type(declared) is not frozenset or any(
        type(item) is not OperationalControlCommandKind for item in declared
    ):
        return frozenset()
    return declared


def _bootstrap(
    result: WalkingThreadResult,
    *,
    persistence_status: PersistenceMode,
    readiness_as_of: datetime,
    operator_id: str,
    backtest_launch: BacktestLaunchCapability,
    operations_query_available: bool,
    operations_control_available: bool,
    control_actions: frozenset[OperationalControlCommandKind],
) -> UiBootstrap:
    full_control_actions = frozenset(
        {
            OperationalControlCommandKind.PAUSE,
            OperationalControlCommandKind.DRAIN,
            OperationalControlCommandKind.FLATTEN,
            OperationalControlCommandKind.HALT,
            OperationalControlCommandKind.REARM,
        }
    )
    capabilities = [
        "research",
        "risk-gated-simulation",
        "point-in-time-data-catalog",
        "market-data-admission",
    ]
    if persistence_status is PersistenceMode.DURABLE:
        capabilities.append("fixture-backtest-query")
        capabilities.append("experiment-governance-query")
        capabilities.append("fixture-segment-provenance-query")
    if backtest_launch.enabled:
        capabilities.append("fixture-backtest-launch")
    if operations_query_available:
        capabilities.append("durable-operations-query")
    if operations_control_available:
        capabilities.append("authenticated-operational-control")
    if OperationalControlCommandKind.PAUSE in control_actions:
        capabilities.append("operational-control-pause")
    if OperationalControlCommandKind.HALT in control_actions:
        capabilities.append("operational-control-halt")
    return UiBootstrap(
        user=UserIdentity(id=operator_id, display_name="Local operator"),
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
        capabilities=capabilities,
        feature_flags={
            "walking_thread": True,
            "data_catalog": True,
            "data_admission": True,
            "backtest_query": persistence_status is PersistenceMode.DURABLE,
            "experiment_query": persistence_status is PersistenceMode.DURABLE,
            "fixture_segment_query": persistence_status is PersistenceMode.DURABLE,
            "backtest_launch": backtest_launch.enabled,
            "operations_query": operations_query_available,
            "operations_control": operations_control_available,
            "controls": (
                operations_control_available and full_control_actions.issubset(control_actions)
            ),
            "control_pause": OperationalControlCommandKind.PAUSE in control_actions,
            "control_drain": OperationalControlCommandKind.DRAIN in control_actions,
            "control_flatten": OperationalControlCommandKind.FLATTEN in control_actions,
            "control_halt": OperationalControlCommandKind.HALT in control_actions,
            "control_rearm": OperationalControlCommandKind.REARM in control_actions,
            "event_stream": False,
        },
        stream_cursor=None,
        backtest_launch=backtest_launch,
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


def create_app(
    settings: Settings | None = None,
    engine: Engine | None = None,
    *,
    operations_query: LocalOperationsQuery | None = None,
    operations_control: OperationalControlCommandService | None = None,
    operations_assignment: AdvancedRiskAssignmentCommandService | None = None,
) -> FastAPI:
    resolved_settings = settings or Settings.from_env()
    if resolved_settings.environment is not Environment.LOCAL:
        raise RuntimeError(
            "the Phase 0 fixed-tape application is local-only; paper/live startup requires "
            "real market-data, broker, and reconciliation adapters"
        )
    local_credentials = resolved_settings.credentials
    if not isinstance(local_credentials, LocalCredentials):
        raise RuntimeError("the local API requires exact local operator credentials")
    configure_logging(resolved_settings.log_level)
    expected_result = WalkingThread.run()
    persistence_engine = engine
    persistence_status = PersistenceMode.UNAVAILABLE
    persistence_error: str | None = None
    result: WalkingThreadResult | None = None
    backtest_workflow: SqlBacktestWorkflow | None = None
    experiment_governance: ExperimentGovernanceQuery | None = None
    fixture_segment_provenance: FixtureSegmentProvenanceQuery | None = None
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
            backtest_workflow = SqlBacktestWorkflow(persistence_engine)
            ensure_golden_research_catalog(backtest_workflow)
            experiment_governance = SqlExperimentGovernance(persistence_engine)
            fixture_segment_provenance = SqlFixtureSegmentProvenanceQuery(persistence_engine)
            verify_operational_schema(persistence_engine)
        persistence_status = PersistenceMode(persistence_mode(persistence_engine))
    except (
        SQLAlchemyError,
        DatabaseSchemaNotReady,
        BacktestWorkflowError,
        ExperimentGovernanceError,
        FixtureSegmentPersistenceError,
        ImmutableFactConflict,
        RiskAuthorizationError,
    ):
        persistence_error = "operational persistence unavailable"
        logger.exception("walking-thread persistence bootstrap failed")
    if result is None:
        result = expected_result
    resolved_operations_query = operations_query
    resolved_operations_control = operations_control
    secure_local_operations = (
        resolved_settings.local_auth_enabled
        and resolved_settings.local_auth_transport_is_loopback_scoped
    )
    if (
        persistence_status is PersistenceMode.DURABLE
        and persistence_engine is not None
        and secure_local_operations
    ):
        if resolved_operations_query is None:
            operations_reader = SqlLocalOperationsSnapshotReader(persistence_engine)
            resolved_operations_query = DurableLocalOperationsQuery(
                reader=operations_reader,
                environment_name="Local durable operations",
                environment_mode=EnvironmentMode.LOCAL,
                loopback_only=True,
            )
        if resolved_operations_control is None:
            control_clock = SystemClock()
            actor_authority_sha256 = hashlib.sha256(
                canonical_json_bytes(
                    (
                        "phase5f-local-operations-authentication-v1",
                        local_credentials.operator_id,
                        resolved_settings.session_secret,
                    )
                )
            ).hexdigest()
            control_repository = SqlOperationalControlRepository(
                engine=persistence_engine,
                clock=control_clock,
            )
            resolved_operations_control = DatabaseOnlyOperationalControlService(
                repository=control_repository,
                actor_authority_sha256=actor_authority_sha256,
                clock=control_clock.now,
            )
        if (
            type(resolved_operations_query) is DurableLocalOperationsQuery
            and type(resolved_operations_control) is DatabaseOnlyOperationalControlService
            and (
                resolved_operations_query.runtime_store_identity
                != resolved_operations_control.runtime_store_identity
                or resolved_operations_query.runtime_store_identity != id(persistence_engine)
            )
        ):
            raise RuntimeError(
                "local operations query and control require the exact durable SQL engine"
            )
    operations_dashboard_query = WalkingThreadOperationsDashboardQuery(
        result=result,
        clock=SystemClock(),
    )
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
    local_security = LocalOperatorSecurity(
        enabled=resolved_settings.local_auth_enabled,
        transport_is_loopback_scoped=(resolved_settings.local_auth_transport_is_loopback_scoped),
        operator_id=local_credentials.operator_id,
        configured_secret=resolved_settings.session_secret,
    )
    app.state.backtest_workflow = backtest_workflow
    app.state.experiment_governance = experiment_governance
    app.state.operations_query = resolved_operations_query
    app.state.operations_control = resolved_operations_control
    app.state.operations_assignment = operations_assignment
    app.state.operations_dashboard_query = operations_dashboard_query

    if resolved_settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(resolved_settings.cors_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST"],
            allow_headers=["Accept", "Content-Type", CSRF_HEADER, IDEMPOTENCY_HEADER],
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
    def ui_bootstrap(request: Request, response: Response) -> UiBootstrap:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        current_status, probed_at = _probe_persistence(persistence_engine, persistence_status)
        launch_capability = local_security.bootstrap_capability(
            response,
            persistence_ready=current_status is PersistenceMode.DURABLE,
            issued_at=probed_at,
            session_cookie=request.cookies.get(LOCAL_SESSION_COOKIE),
        )
        return _bootstrap(
            result,
            persistence_status=current_status,
            readiness_as_of=probed_at,
            operator_id=local_credentials.operator_id,
            backtest_launch=launch_capability,
            operations_query_available=(
                current_status is PersistenceMode.DURABLE and resolved_operations_query is not None
            ),
            operations_control_available=(
                current_status is PersistenceMode.DURABLE
                and resolved_operations_control is not None
            ),
            control_actions=(
                _available_control_actions(resolved_operations_control)
                if current_status is PersistenceMode.DURABLE
                else frozenset()
            ),
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

    router.include_router(
        create_backtest_router(
            workflow=backtest_workflow,
            security=local_security,
            persistence_ready=lambda: (
                _probe_persistence(persistence_engine, persistence_status)[0]
                is PersistenceMode.DURABLE
            ),
        )
    )
    router.include_router(
        create_experiment_router(
            repository=experiment_governance,
            persistence_ready=lambda: (
                _probe_persistence(persistence_engine, persistence_status)[0]
                is PersistenceMode.DURABLE
            ),
        )
    )
    router.include_router(
        create_fixture_segment_router(
            repository=fixture_segment_provenance,
            persistence_ready=lambda: (
                _probe_persistence(persistence_engine, persistence_status)[0]
                is PersistenceMode.DURABLE
            ),
        )
    )
    router.include_router(
        create_operations_router(
            query=resolved_operations_query,
            control=resolved_operations_control,
            security=local_security,
            persistence_ready=lambda: (
                _probe_persistence(persistence_engine, persistence_status)[0]
                is PersistenceMode.DURABLE
            ),
            assignment=operations_assignment,
        )
    )
    router.include_router(
        create_operations_dashboard_router(
            query=operations_dashboard_query,
            security=local_security,
            persistence_ready=lambda: (
                _probe_persistence(persistence_engine, persistence_status)[0]
                is PersistenceMode.DURABLE
            ),
        )
    )
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
