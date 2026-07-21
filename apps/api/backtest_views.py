"""Strict HTTP projections and local mutation security for Phase 2C research."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Path, Query, Response, Security, status
from fastapi.security import APIKeyCookie
from sqlalchemy.exc import SQLAlchemyError

from apps.api.contracts import (
    ApiErrorResponse,
    BacktestJobEventView,
    BacktestJobListResponse,
    BacktestJobView,
    BacktestLaunchCapability,
    BacktestLaunchRequest,
    BacktestReportView,
    StrategyCatalogResponse,
    StrategyCatalogView,
)
from packages.domain.backtest_job import BacktestJobError, BacktestJobInput, BacktestJobStatus
from packages.persistence.backtest_workflow import (
    BacktestJobSnapshot,
    BacktestReportSnapshot,
    BacktestWorkflowConflict,
    BacktestWorkflowError,
    SqlBacktestWorkflow,
    StrategyCatalogRecord,
)

logger = logging.getLogger(__name__)

LOCAL_SESSION_COOKIE = "aqt_local_session"
CSRF_HEADER = "X-CSRF-Token"
IDEMPOTENCY_HEADER = "Idempotency-Key"
_SESSION_VERSION = 1
_SESSION_LIFETIME = timedelta(hours=8)
_TOKEN_PATTERN_DESCRIPTION = "URL-safe, server-issued local session value"
_SAFE_TOKEN_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_LOCAL_SESSION_SCHEME = APIKeyCookie(
    name=LOCAL_SESSION_COOKIE,
    scheme_name="LocalOperatorSession",
    description=_TOKEN_PATTERN_DESCRIPTION,
    auto_error=False,
)


@dataclass(frozen=True, slots=True)
class _AuthenticatedLocalOperator:
    operator_id: str
    csrf_token: str


class LocalOperatorSecurity:
    """Issue and verify short-lived, signed local operator sessions."""

    __slots__ = ("_enabled", "_key", "_operator_id")

    def __init__(
        self,
        *,
        enabled: bool,
        transport_is_loopback_scoped: bool,
        operator_id: str,
        configured_secret: str,
    ) -> None:
        if type(enabled) is not bool:
            raise ValueError("local operator security enabled flag must be exact")
        if type(transport_is_loopback_scoped) is not bool:
            raise ValueError("local operator transport boundary flag must be exact")
        if enabled and not transport_is_loopback_scoped:
            raise ValueError(
                "local operator capability issuance requires a loopback-scoped transport"
            )
        if (
            type(operator_id) is not str
            or not operator_id
            or operator_id != operator_id.strip()
            or len(operator_id) > 128
            or any(ord(character) < 32 for character in operator_id)
        ):
            raise ValueError("local operator ID must be bounded, non-empty trimmed text")
        if type(configured_secret) is not str:
            raise ValueError("configured session secret must be text")
        # A process nonce prevents the documented local-development default from
        # becoming a forgeable credential. Sessions intentionally expire on restart.
        key_material = configured_secret.encode("utf-8") + secrets.token_bytes(32)
        self._key = hashlib.sha256(key_material).digest()
        self._enabled = enabled
        self._operator_id = operator_id

    def bootstrap_capability(
        self,
        response: Response,
        *,
        persistence_ready: bool,
        issued_at: datetime,
        session_cookie: str | None,
    ) -> BacktestLaunchCapability:
        if not self._enabled:
            response.delete_cookie(LOCAL_SESSION_COOKIE, path="/api/v1")
            return self._disabled("local operator authentication is disabled")
        if not persistence_ready:
            response.delete_cookie(LOCAL_SESSION_COOKIE, path="/api/v1")
            return self._disabled("durable backtest persistence is unavailable")

        try:
            current = self._decode(session_cookie, now=issued_at)
        except HTTPException:
            current = None
        if current is not None:
            return BacktestLaunchCapability(
                enabled=True,
                operator_id=current.operator_id,
                csrf_token=current.csrf_token,
                csrf_header=CSRF_HEADER,
                idempotency_header=IDEMPOTENCY_HEADER,
                disabled_reason=None,
            )

        session_cookie, csrf_token = self._issue(issued_at)
        response.set_cookie(
            key=LOCAL_SESSION_COOKIE,
            value=session_cookie,
            max_age=int(_SESSION_LIFETIME.total_seconds()),
            httponly=True,
            secure=False,
            samesite="strict",
            path="/api/v1",
        )
        return BacktestLaunchCapability(
            enabled=True,
            operator_id=self._operator_id,
            csrf_token=csrf_token,
            csrf_header=CSRF_HEADER,
            idempotency_header=IDEMPOTENCY_HEADER,
            disabled_reason=None,
        )

    def authenticate(
        self,
        session_cookie: str | None,
        csrf_token: str,
        *,
        now: datetime,
    ) -> str:
        if not self._enabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="local backtest launch authentication is disabled",
            )
        session = self._decode(session_cookie, now=now)
        if not hmac.compare_digest(session.csrf_token, csrf_token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="backtest launch CSRF validation failed",
            )
        return session.operator_id

    def _disabled(self, reason: str) -> BacktestLaunchCapability:
        return BacktestLaunchCapability(
            enabled=False,
            operator_id=None,
            csrf_token=None,
            csrf_header=CSRF_HEADER,
            idempotency_header=IDEMPOTENCY_HEADER,
            disabled_reason=reason,
        )

    def _issue(self, issued_at: datetime) -> tuple[str, str]:
        issued_epoch = int(issued_at.timestamp())
        csrf_token = secrets.token_urlsafe(32)
        payload = {
            "csrf": csrf_token,
            "exp": issued_epoch + int(_SESSION_LIFETIME.total_seconds()),
            "iat": issued_epoch,
            "sub": self._operator_id,
            "v": _SESSION_VERSION,
        }
        encoded = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).rstrip(b"=")
        signature = hmac.new(self._key, encoded, hashlib.sha256).hexdigest().encode("ascii")
        return f"{encoded.decode('ascii')}.{signature.decode('ascii')}", csrf_token

    def _decode(
        self,
        session_cookie: str | None,
        *,
        now: datetime,
    ) -> _AuthenticatedLocalOperator:
        unauthorized = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="a current local operator session is required",
            headers={"WWW-Authenticate": "LocalOperatorSession"},
        )
        if type(session_cookie) is not str or len(session_cookie) > 2048:
            raise unauthorized
        try:
            encoded_text, supplied_signature = session_cookie.split(".", maxsplit=1)
            if (
                not encoded_text
                or not supplied_signature
                or any(character not in _SAFE_TOKEN_CHARACTERS for character in encoded_text)
            ):
                raise ValueError("session encoding is malformed")
            encoded = encoded_text.encode("ascii")
            expected_signature = hmac.new(self._key, encoded, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_signature, supplied_signature):
                raise ValueError("session signature is invalid")
            padded = encoded + b"=" * (-len(encoded) % 4)
            payload = json.loads(base64.b64decode(padded, altchars=b"-_", validate=True))
            if not isinstance(payload, dict) or set(payload) != {"csrf", "exp", "iat", "sub", "v"}:
                raise ValueError("session payload is malformed")
            csrf = payload["csrf"]
            expires_at = payload["exp"]
            issued_at = payload["iat"]
            operator_id = payload["sub"]
            version = payload["v"]
            if (
                type(csrf) is not str
                or not 32 <= len(csrf) <= 128
                or any(character not in _SAFE_TOKEN_CHARACTERS for character in csrf)
                or type(expires_at) is not int
                or type(issued_at) is not int
                or type(operator_id) is not str
                or type(version) is not int
                or version != _SESSION_VERSION
                or operator_id != self._operator_id
                or issued_at > int(now.timestamp())
                or expires_at <= int(now.timestamp())
                or expires_at - issued_at != int(_SESSION_LIFETIME.total_seconds())
            ):
                raise ValueError("session claims are invalid")
            return _AuthenticatedLocalOperator(operator_id=operator_id, csrf_token=csrf)
        except (
            UnicodeError,
            ValueError,
            binascii.Error,
            json.JSONDecodeError,
            KeyError,
            TypeError,
        ):
            raise unauthorized from None


def strategy_catalog_view(record: StrategyCatalogRecord) -> StrategyCatalogView:
    return StrategyCatalogView(
        strategy_version_id=record.strategy_version_id,
        strategy_id=record.strategy_id,
        strategy_version=record.strategy_version,
        display_name=record.display_name,
        configuration_sha256=record.configuration_sha256,
        configuration_name=record.configuration_name,
        parameter_schema_payload=record.parameter_schema_payload,
        parameters_payload=record.parameters_payload,
        fixture_id=record.fixture_id,
        fixture_version=record.fixture_version,
        dataset_manifest_sha256=record.dataset_manifest_sha256,
        replay_run_id=record.replay_run_id,
        benchmark_sha256=record.benchmark_sha256,
        cost_model_sha256=record.cost_model_sha256,
        fill_model_sha256=record.fill_model_sha256,
        metric_conventions_sha256=record.metric_conventions_sha256,
    )


def backtest_job_view(snapshot: BacktestJobSnapshot) -> BacktestJobView:
    return BacktestJobView(
        job_id=snapshot.job_id,
        input_sha256=snapshot.input_sha256,
        fixture_id=snapshot.fixture_id,
        fixture_version=snapshot.fixture_version,
        strategy_id=snapshot.strategy_id,
        strategy_version=snapshot.strategy_version,
        strategy_configuration_sha256=snapshot.strategy_configuration_sha256,
        requested_by=snapshot.requested_by,
        requested_at=snapshot.requested_at,
        status=snapshot.status,
        attempt_number=snapshot.attempt_number,
        worker_id=snapshot.worker_id,
        claim_expires_at=snapshot.claim_expires_at,
        updated_at=snapshot.updated_at,
        run_manifest_sha256=snapshot.run_manifest_sha256,
        report_sha256=snapshot.report_sha256,
        report_artifact_sha256=snapshot.report_artifact_sha256,
        terminal_reason_code=snapshot.terminal_reason_code,
        history=[
            BacktestJobEventView(
                sequence=event.sequence,
                status=event.status,
                occurred_at=event.occurred_at,
                actor_id=event.actor_id,
                attempt_number=event.attempt_number,
                terminal_reason_code=event.terminal_reason_code,
            )
            for event in snapshot.history
        ],
    )


def backtest_report_view(snapshot: BacktestReportSnapshot) -> BacktestReportView:
    view = BacktestReportView.model_validate(snapshot.query_payload)
    expected: dict[str, object] = {
        "report_sha256": snapshot.report_sha256,
        "report_artifact_sha256": snapshot.report_artifact_sha256,
        "account_id": snapshot.account_id,
        "currency": snapshot.currency,
        "period_start": snapshot.period_start,
        "period_end": snapshot.period_end,
        "generated_at": snapshot.generated_at,
    }
    actual: dict[str, object] = {field_name: getattr(view, field_name) for field_name in expected}
    expected_metrics = {
        "starting_equity": snapshot.starting_equity,
        "ending_equity": snapshot.ending_equity,
        "total_return": snapshot.total_return,
        "maximum_drawdown": snapshot.maximum_drawdown,
        "turnover": snapshot.turnover,
        "trade_count": snapshot.trade_count,
        "realized_pnl": snapshot.realized_pnl,
        "unrealized_pnl": snapshot.unrealized_pnl,
        "dividend_income": snapshot.dividend_income,
        "total_execution_costs": snapshot.total_execution_costs,
    }
    actual_metrics = {
        field_name: getattr(view.metrics, field_name) for field_name in expected_metrics
    }
    if actual != expected or actual_metrics != expected_metrics:
        raise BacktestWorkflowError(
            "persisted report query payload conflicts with its immutable summary"
        )
    return view


def _domain_input(request: BacktestLaunchRequest) -> BacktestJobInput:
    return BacktestJobInput(**request.model_dump())


def _unavailable(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=detail)


def _require_workflow(
    workflow: SqlBacktestWorkflow | None,
    persistence_ready: Callable[[], bool],
) -> SqlBacktestWorkflow:
    if workflow is None or not persistence_ready():
        raise _unavailable("durable backtest persistence is unavailable")
    return workflow


def create_backtest_router(
    *,
    workflow: SqlBacktestWorkflow | None,
    security: LocalOperatorSecurity,
    persistence_ready: Callable[[], bool],
) -> APIRouter:
    """Build the query and local-only launch routes with an explicit auth scheme."""

    router = APIRouter(prefix="/research")

    @router.get(
        "/strategies",
        response_model=StrategyCatalogResponse,
        tags=["research"],
    )
    def strategies() -> StrategyCatalogResponse:
        repository = _require_workflow(workflow, persistence_ready)
        queried_at = datetime.now(UTC)
        try:
            records = repository.strategies()
            return StrategyCatalogResponse(
                as_of=queried_at,
                strategies=[strategy_catalog_view(record) for record in records],
            )
        except (SQLAlchemyError, BacktestWorkflowError, ValueError, TypeError) as error:
            logger.exception("backtest strategy catalog read failed")
            raise _unavailable("backtest strategy catalog is unavailable or malformed") from error

    @router.get(
        "/backtests",
        response_model=BacktestJobListResponse,
        tags=["research"],
    )
    def backtests(
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> BacktestJobListResponse:
        repository = _require_workflow(workflow, persistence_ready)
        queried_at = datetime.now(UTC)
        try:
            snapshots = repository.jobs(limit=limit)
            return BacktestJobListResponse(
                as_of=queried_at,
                jobs=[backtest_job_view(snapshot) for snapshot in snapshots],
            )
        except (SQLAlchemyError, BacktestWorkflowError, ValueError, TypeError) as error:
            logger.exception("backtest job list read failed")
            raise _unavailable("backtest jobs are unavailable or malformed") from error

    @router.get(
        "/backtests/{job_id}",
        response_model=BacktestJobView,
        tags=["research"],
    )
    def backtest(
        job_id: Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")],
    ) -> BacktestJobView:
        repository = _require_workflow(workflow, persistence_ready)
        try:
            return backtest_job_view(repository.get(job_id))
        except BacktestWorkflowError as error:
            if str(error).startswith("unknown backtest job"):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="backtest job was not found",
                ) from error
            logger.exception("backtest job read failed")
            raise _unavailable("backtest job is unavailable or malformed") from error
        except (SQLAlchemyError, ValueError, TypeError) as error:
            logger.exception("backtest job read failed")
            raise _unavailable("backtest job is unavailable or malformed") from error

    @router.get(
        "/backtests/{job_id}/report",
        response_model=BacktestReportView,
        tags=["research"],
    )
    def backtest_report(
        job_id: Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")],
    ) -> BacktestReportView:
        repository = _require_workflow(workflow, persistence_ready)
        try:
            snapshot = repository.get(job_id)
            if (
                snapshot.status is not BacktestJobStatus.COMPLETED
                or snapshot.report_sha256 is None
                or snapshot.report_artifact_sha256 is None
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="backtest report is not available until the job completes",
                )
            report = repository.report(snapshot.report_artifact_sha256)
            if (
                report.report_sha256 != snapshot.report_sha256
                or report.report_artifact_sha256 != snapshot.report_artifact_sha256
            ):
                raise BacktestWorkflowError(
                    "persisted job report reference conflicts with report evidence"
                )
            return backtest_report_view(report)
        except HTTPException:
            raise
        except BacktestWorkflowError as error:
            if str(error).startswith("unknown backtest job"):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="backtest job was not found",
                ) from error
            logger.exception("backtest report read failed")
            raise _unavailable("backtest report is unavailable or malformed") from error
        except (SQLAlchemyError, ValueError, TypeError) as error:
            logger.exception("backtest report read failed")
            raise _unavailable("backtest report is unavailable or malformed") from error

    @router.post(
        "/backtests",
        response_model=BacktestJobView,
        status_code=status.HTTP_202_ACCEPTED,
        responses={
            status.HTTP_400_BAD_REQUEST: {
                "model": ApiErrorResponse,
                "description": "Launch inputs violate the domain contract.",
            },
            status.HTTP_401_UNAUTHORIZED: {
                "model": ApiErrorResponse,
                "description": "Local operator session required.",
            },
            status.HTTP_403_FORBIDDEN: {
                "model": ApiErrorResponse,
                "description": "CSRF validation failed.",
            },
            status.HTTP_409_CONFLICT: {
                "model": ApiErrorResponse,
                "description": "Idempotency conflict.",
            },
            status.HTTP_503_SERVICE_UNAVAILABLE: {
                "model": ApiErrorResponse,
                "description": "Durable backtest persistence unavailable.",
            },
        },
        tags=["research"],
    )
    def launch_backtest(
        request: BacktestLaunchRequest,
        response: Response,
        session_cookie: Annotated[str | None, Security(_LOCAL_SESSION_SCHEME)],
        csrf_token: Annotated[
            str,
            Header(
                alias=CSRF_HEADER,
                min_length=32,
                max_length=128,
                pattern=r"^[A-Za-z0-9_-]+$",
            ),
        ],
        idempotency_key: Annotated[
            str,
            Header(
                alias=IDEMPOTENCY_HEADER,
                min_length=8,
                max_length=128,
                pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$",
            ),
        ],
    ) -> BacktestJobView:
        requested_at = datetime.now(UTC)
        operator_id = security.authenticate(
            session_cookie,
            csrf_token,
            now=requested_at,
        )
        repository = _require_workflow(workflow, persistence_ready)
        try:
            snapshot = repository.launch(
                input=_domain_input(request),
                requested_by=operator_id,
                idempotency_key=idempotency_key,
                requested_at=requested_at,
            )
        except BacktestWorkflowConflict as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="idempotency key conflicts with an existing backtest launch",
            ) from error
        except BacktestJobError as error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="backtest launch input is invalid",
            ) from error
        except (SQLAlchemyError, BacktestWorkflowError, ValueError, TypeError) as error:
            logger.exception("backtest launch persistence failed")
            raise _unavailable("backtest launch persistence is unavailable") from error
        response.headers["Location"] = f"/api/v1/research/backtests/{snapshot.job_id}"
        return backtest_job_view(snapshot)

    return router


__all__ = [
    "CSRF_HEADER",
    "IDEMPOTENCY_HEADER",
    "LOCAL_SESSION_COOKIE",
    "LocalOperatorSecurity",
    "backtest_job_view",
    "backtest_report_view",
    "create_backtest_router",
    "strategy_catalog_view",
]
