"""Separate account-scoped HTTP permission for original integrity and metadata.

The caller guarantees the configured local transport; this module binds no
socket. Permission is distinct from actual proof availability and grants no
command, execution, initialization, renewal or shared-session authority.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from threading import Lock
from typing import Annotated

from anyio import CancelScope
from anyio.lowlevel import checkpoint
from fastapi import FastAPI, Header, HTTPException, Request, Response, Security
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyCookie
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from apps.api.configured_readiness_reads import configured_readiness_reads
from apps.api.continuous_read_access import (
    CONTINUOUS_READ_CSRF_HEADER,
    CONTINUOUS_READ_SESSION_COOKIE,
    ContinuousReadAccessConfiguration,
    ContinuousReadAccessSecurity,
)
from apps.api.continuous_selection_projection import continuous_selection_response
from apps.api.contracts import (
    ContinuousOperationalReadCapabilityView,
    ContinuousSelectionResponse,
    HealthResponse,
    ServiceStatus,
)
from apps.api.readiness_read_store import ReadinessReadStore
from apps.trader.continuous_readiness_owner import ReadinessOwnerLimits

_DEFAULT_LIMITS = ReadinessOwnerLimits()
_STORE = ReadinessReadStore
_READ = ReadinessReadStore.read
_SERVICE = "continuous-operational-read"
_UNAVAILABLE = "continuous operational read is unavailable"
_INVALID = "continuous read request is invalid"
_CACHE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}
_SESSION = APIKeyCookie(
    name=CONTINUOUS_READ_SESSION_COOKIE,
    scheme_name="ContinuousReadSession",
    description="One account/composition permission for original proof and fixed metadata",
    auto_error=False,
)
_CsrfToken = Annotated[
    str,
    Header(
        alias=CONTINUOUS_READ_CSRF_HEADER,
        min_length=32,
        max_length=128,
        pattern=r"^[A-Za-z0-9_-]+$",
    ),
]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _uncached(response: Response) -> None:
    response.headers.update(_CACHE_HEADERS)


def _unavailable() -> HTTPException:
    return HTTPException(503, _UNAVAILABLE, headers=dict(_CACHE_HEADERS))


def _read_binding(port: ReadinessReadStore) -> None:
    if type(port) is not _STORE or vars(_STORE).get("read") is not _READ or "read" in vars(port):
        raise RuntimeError("CONTINUOUS_READ_APP_ORIGINAL_READ_REQUIRED")


def _disabled_capability(response: Response) -> ContinuousOperationalReadCapabilityView:
    _uncached(response)
    response.delete_cookie(CONTINUOUS_READ_SESSION_COOKIE, path="/api/v1")
    return ContinuousOperationalReadCapabilityView(
        enabled=False,
        operator_id=None,
        account_id=None,
        csrf_token=None,
        csrf_header=CONTINUOUS_READ_CSRF_HEADER,
        expires_at=None,
        disabled_reason="continuous read permission is unavailable",
    )


def create_configured_readiness_reads_app(
    *,
    configuration_path: str,
    account_id: str,
    instance_lock: str,
    read_access: ContinuousReadAccessConfiguration,
    limits: ReadinessOwnerLimits = _DEFAULT_LIMITS,
) -> FastAPI:
    """Construct data only; the explicit lifespan owns one original L context."""
    security = ContinuousReadAccessSecurity(configuration=read_access, account_id=account_id)
    context = configured_readiness_reads(
        configuration_path=configuration_path,
        account_id=account_id,
        instance_lock=instance_lock,
        limits=limits,
    )
    enter_context, exit_context = context.__enter__, context.__exit__
    state_lock = Lock()
    started = False
    admitting = False
    port: ReadinessReadStore | None = None

    def scope_open() -> bool:
        observed = security.is_open()
        if type(observed) is not bool:
            raise RuntimeError("CONTINUOUS_READ_APP_SCOPE_INVALID")
        return observed

    def active_port() -> ReadinessReadStore:
        with state_lock:
            current = port if admitting else None
        if type(current) is not _STORE or not scope_open():
            raise _unavailable()
        return current

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        nonlocal started, admitting, port
        with state_lock:
            if started:
                raise RuntimeError("CONTINUOUS_READ_APP_ALREADY_STARTED")
            started = True
        entered = False
        primary: BaseException | None = None

        def enter() -> None:
            nonlocal entered, port
            candidate = enter_context()
            # Commit actual completion before the threadpool waiter can lose the
            # returned object. Even invalid returned data still needs one exit.
            with state_lock:
                entered = True
                if type(candidate) is _STORE:
                    port = candidate
            if type(candidate) is not _STORE:
                raise RuntimeError("CONTINUOUS_READ_APP_ORIGINAL_PORT_REQUIRED")

        try:
            with CancelScope(shield=True):
                await run_in_threadpool(enter)
            # Deliver cancellation pending during startup before opening scope
            # or reporting a successfully entered application lifespan.
            await checkpoint()
            security.open()
            if not scope_open():
                raise RuntimeError("CONTINUOUS_READ_APP_SCOPE_INVALID")
            with state_lock:
                admitting = True
            yield
        except BaseException as error:
            primary = error
            raise
        finally:
            with state_lock:
                admitting = False
                actual_entry = entered
            scope_error: BaseException | None = None
            try:
                security.close()
            except BaseException as error:
                scope_error = error
            effective_primary = primary
            if scope_error is not None:
                # Only this additional real cleanup failure changes the primary
                # passed into L. The normal sole primary/traceback stays exact.
                effective_primary = (
                    scope_error
                    if primary is None
                    else BaseExceptionGroup(
                        "CONTINUOUS_READ_SCOPE_AND_OPERATION_FAILED", [primary, scope_error]
                    )
                )
            if actual_entry:
                # L owns its original K-close/G-stop ordering and any resulting
                # group. Propagate it directly, without duplicating its primary.
                with CancelScope(shield=True):
                    await run_in_threadpool(
                        exit_context,
                        None if effective_primary is None else type(effective_primary),
                        effective_primary,
                        None if effective_primary is None else effective_primary.__traceback__,
                    )
            if scope_error is not None and effective_primary is not None:
                raise effective_primary from None

    app = FastAPI(
        title="Continuous operational reads",
        lifespan=lifespan,
        openapi_url=None,
        docs_url=None,
        redoc_url=None,
    )

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request: Request, _error: RequestValidationError) -> JSONResponse:
        # The default validation body can echo an invalid CSRF/header input.
        return JSONResponse(
            status_code=422, content={"detail": _INVALID}, headers=dict(_CACHE_HEADERS)
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, error: StarletteHTTPException) -> Response:
        response = await http_exception_handler(request, error)
        _uncached(response)
        return response

    @app.get("/health/live", response_model=HealthResponse)
    async def live(response: Response) -> HealthResponse:
        _uncached(response)
        return HealthResponse(service=_SERVICE, status=ServiceStatus.OK)

    @app.get(
        "/api/v1/ui/continuous-read-bootstrap",
        response_model=ContinuousOperationalReadCapabilityView,
    )
    def bootstrap(request: Request, response: Response) -> ContinuousOperationalReadCapabilityView:
        _uncached(response)
        with state_lock:
            available = admitting
        if not available:
            return _disabled_capability(response)
        try:
            value = security.bootstrap_capability(
                response,
                issued_at=_utc_now(),
                session_cookie=request.cookies.get(CONTINUOUS_READ_SESSION_COOKIE),
            )
            if type(value) is not ContinuousOperationalReadCapabilityView:
                raise RuntimeError("CONTINUOUS_READ_APP_CAPABILITY_INVALID")
            with state_lock:
                available = admitting
            if not available or not scope_open():
                return _disabled_capability(response)
            return value
        except Exception:
            raise _unavailable() from None

    @app.get("/api/v1/continuous-selection", response_model=ContinuousSelectionResponse)
    def selection(
        response: Response,
        session_cookie: Annotated[str | None, Security(_SESSION)],
        csrf_token: _CsrfToken,
    ) -> ContinuousSelectionResponse:
        _uncached(response)
        try:
            security.authenticate(session_cookie, csrf_token, now=_utc_now())
        except HTTPException as error:
            # Preserve public denial categories without forwarding lower-layer
            # details/headers. Unexpected HTTP errors are backend unavailability.
            if error.status_code == 401:
                raise HTTPException(
                    401,
                    "a current continuous read session is required",
                    headers={**_CACHE_HEADERS, "WWW-Authenticate": "ContinuousReadSession"},
                ) from None
            if error.status_code == 403:
                raise HTTPException(
                    403, "continuous read authentication failed", headers=dict(_CACHE_HEADERS)
                ) from None
            raise _unavailable() from None
        except Exception:
            raise _unavailable() from None
        try:
            current = active_port()
            _read_binding(current)
            snapshot = _READ(current)
            _read_binding(current)
            result = continuous_selection_response(snapshot, account_id=account_id)
            if active_port() is not current:
                raise _unavailable()
            return result
        except Exception:
            raise _unavailable() from None

    return app
