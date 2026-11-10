"""Read-only health transport for one private, HALTED synthetic readiness owner.

This separate ASGI app starts no owner until its explicit lifespan. Health never
initializes an account, acquires a new lease or grants authentication, financial
authority, execution permission or automatic recovery authority.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import uuid4

from anyio import CancelScope
from fastapi import FastAPI, Response, status
from starlette.concurrency import run_in_threadpool

from apps.api.contracts import HealthResponse, ServiceStatus
from apps.trader.configured_readiness_owner import create_configured_readiness_owner
from apps.trader.continuous_readiness_owner import (
    ReadinessCheckResult,
    ReadinessOwnerLimits,
    ReadinessOwnerStatus,
)

_DEFAULT_LIMITS = ReadinessOwnerLimits()
_SERVICE = "continuous-readiness"


def _uncached(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def create_continuous_readiness_app(
    *,
    configuration_path: str,
    account_id: str,
    instance_lock: str,
    limits: ReadinessOwnerLimits = _DEFAULT_LIMITS,
) -> FastAPI:
    """Construct data only; the lifespan owns bounded startup and shutdown."""
    owner = create_configured_readiness_owner(
        configuration_path=configuration_path,
        account_id=account_id,
        instance_lock=instance_lock,
        limits=limits,
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        primary: BaseException | None = None
        try:
            await run_in_threadpool(owner.start)
            # A bounded unavailable startup still permits static liveness and
            # unavailable readiness. No request can start or replace the owner.
            yield
        except BaseException as error:
            # Preserve cancellation and every other original lifespan failure.
            primary = error
            raise
        finally:
            # Shield the one original stop dispatch from enclosing ASGI cancel
            # scopes. Cancellation itself is not caught or converted to success.
            try:
                with CancelScope(shield=True):
                    stopped = await run_in_threadpool(owner.stop)
                    if (
                        type(stopped) is not ReadinessOwnerStatus
                        or stopped.cleanup_complete is not True
                    ):
                        raise RuntimeError("CONTINUOUS_READINESS_CLEANUP_INCOMPLETE")
            except BaseException as cleanup:
                if primary is not None:
                    raise BaseExceptionGroup(
                        "CONTINUOUS_READINESS_LIFESPAN_AND_CLEANUP_FAILED", [primary, cleanup]
                    ) from None
                raise

    app = FastAPI(
        title="Continuous synthetic readiness",
        lifespan=lifespan,
        openapi_url=None,
        docs_url=None,
        redoc_url=None,
    )

    @app.get("/health/live", response_model=HealthResponse)
    async def live(response: Response) -> HealthResponse:
        _uncached(response)
        return HealthResponse(service=_SERVICE, status=ServiceStatus.OK)

    @app.get("/health/ready", response_model=HealthResponse)
    def ready(response: Response) -> HealthResponse:
        # FastAPI runs this synchronous handler off the event loop. The original
        # owner remains the only proof executor and enforces its one-request slot.
        _uncached(response)
        try:
            request_id = uuid4().hex
            result = owner.check(request_id)
        except Exception:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return HealthResponse(service=_SERVICE, status=ServiceStatus.NOT_READY)
        if (
            type(result) is ReadinessCheckResult
            and result.request_id == request_id
            and result.status == "ready"
            and result.reason == "verified"
        ):
            return HealthResponse(service=_SERVICE, status=ServiceStatus.READY)
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return HealthResponse(service=_SERVICE, status=ServiceStatus.NOT_READY)

    return app
