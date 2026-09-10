"""Authenticated local research routes, independent of fixture-history routes."""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Annotated, Protocol

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Request, Response
from sqlalchemy.exc import SQLAlchemyError

from apps.api.backtest_views import (
    CSRF_HEADER,
    IDEMPOTENCY_HEADER,
    LOCAL_SESSION_COOKIE,
    LocalOperatorSecurity,
)
from apps.api.personal_research_contracts import (
    PersonalComparison,
    PersonalComparisonRequest,
    PersonalExperimentList,
    PersonalExperimentRequest,
    PersonalExperimentView,
    PersonalResearchCatalog,
    PersonalRowsKind,
    PersonalRunList,
    PersonalRunReport,
    PersonalRunRequest,
    PersonalRunRows,
    PersonalRunView,
)


class ResearchNotFoundError(ValueError):
    """The requested public identity is absent."""


class ResearchConflictError(ValueError):
    """An immutable request or report identity conflicts."""


class PersonalResearchApi(Protocol):
    def catalog(self) -> PersonalResearchCatalog: ...
    def runs(self) -> PersonalRunList: ...
    def run(self, job_id: str) -> PersonalRunView: ...
    def launch(
        self, request: PersonalRunRequest, *, owner_id: str, key: str
    ) -> PersonalRunView: ...
    def cancel(self, job_id: str, *, owner_id: str, key: str) -> PersonalRunView: ...
    def report(self, job_id: str) -> PersonalRunReport: ...
    def rows(
        self, job_id: str, *, kind: PersonalRowsKind, report_sha256: str, offset: int, limit: int
    ) -> PersonalRunRows: ...
    def comparison(self, request: PersonalComparisonRequest) -> PersonalComparison: ...
    def experiments(self) -> PersonalExperimentList: ...
    def experiment(self, experiment_id: str) -> PersonalExperimentView: ...
    def create_experiment(
        self, request: PersonalExperimentRequest, *, owner_id: str, key: str
    ) -> PersonalExperimentView: ...
    def export(self, job_id: str) -> bytes: ...


@contextmanager
def _errors(*, mutation: bool = False) -> Iterator[None]:
    try:
        yield
    except ResearchNotFoundError as error:
        raise HTTPException(404, "research identity was not found") from error
    except ResearchConflictError as error:
        raise HTTPException(
            409, "immutable research identity conflicts or report is unavailable"
        ) from error
    except (ValueError, TypeError, ArithmeticError) as error:
        code = 400 if mutation else 503
        raise HTTPException(
            code, "research input or retained evidence failed validation"
        ) from error
    except (SQLAlchemyError, OSError) as error:
        raise HTTPException(503, "research persistence is unavailable") from error


def create_personal_research_router(
    *,
    service: PersonalResearchApi | None,
    security: LocalOperatorSecurity,
) -> APIRouter:
    router = APIRouter(prefix="/research/personal", tags=["personal research"])

    def repository() -> PersonalResearchApi:
        if service is None:
            raise HTTPException(
                503, "configure a durable research database and private artifact store"
            )
        return service

    def credentials(
        request: Request,
        csrf: Annotated[str, Header(alias=CSRF_HEADER, min_length=1, max_length=128)],
        key: Annotated[
            str,
            Header(
                alias=IDEMPOTENCY_HEADER,
                min_length=8,
                max_length=128,
                pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
            ),
        ],
    ) -> tuple[str, str]:
        owner = security.authenticate(
            request.cookies.get(LOCAL_SESSION_COOKIE), csrf, now=datetime.now(UTC)
        )
        return owner, key

    @router.get("/catalog", response_model=PersonalResearchCatalog)
    def catalog() -> PersonalResearchCatalog:
        with _errors():
            return repository().catalog()

    @router.get("/runs", response_model=PersonalRunList)
    def runs() -> PersonalRunList:
        with _errors():
            return repository().runs()

    @router.get("/runs/{job_id}", response_model=PersonalRunView)
    def run(job_id: Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")]) -> PersonalRunView:
        with _errors():
            return repository().run(job_id)

    @router.post("/runs", response_model=PersonalRunView, status_code=202)
    def launch(
        request: PersonalRunRequest, auth: Annotated[tuple[str, str], Depends(credentials)]
    ) -> PersonalRunView:
        with _errors(mutation=True):
            return repository().launch(request, owner_id=auth[0], key=auth[1])

    @router.post("/runs/{job_id}/cancel", response_model=PersonalRunView, status_code=202)
    def cancel(
        job_id: Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")],
        auth: Annotated[tuple[str, str], Depends(credentials)],
    ) -> PersonalRunView:
        with _errors(mutation=True):
            return repository().cancel(job_id, owner_id=auth[0], key=auth[1])

    @router.get("/runs/{job_id}/report", response_model=PersonalRunReport)
    def report(job_id: Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")]) -> PersonalRunReport:
        with _errors():
            return repository().report(job_id)

    @router.get("/runs/{job_id}/rows", response_model=PersonalRunRows)
    def rows(
        job_id: Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")],
        kind: PersonalRowsKind,
        report_sha256: str,
        offset: int = 0,
        limit: int = 200,
    ) -> PersonalRunRows:
        if not offset >= 0 or not 1 <= limit <= 200:
            raise HTTPException(400, "research page exceeds its bounds")
        with _errors():
            return repository().rows(
                job_id, kind=kind, report_sha256=report_sha256, offset=offset, limit=limit
            )

    @router.post("/comparison", response_model=PersonalComparison)
    def comparison(request: PersonalComparisonRequest) -> PersonalComparison:
        with _errors(mutation=True):
            return repository().comparison(request)

    @router.get("/experiments", response_model=PersonalExperimentList)
    def experiments() -> PersonalExperimentList:
        with _errors():
            return repository().experiments()

    @router.post("/experiments", response_model=PersonalExperimentView, status_code=202)
    def create_experiment(
        request: PersonalExperimentRequest, auth: Annotated[tuple[str, str], Depends(credentials)]
    ) -> PersonalExperimentView:
        with _errors(mutation=True):
            return repository().create_experiment(request, owner_id=auth[0], key=auth[1])

    @router.get("/experiments/{experiment_id}", response_model=PersonalExperimentView)
    def experiment(
        experiment_id: Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")],
    ) -> PersonalExperimentView:
        with _errors():
            return repository().experiment(experiment_id)

    @router.get(
        "/runs/{job_id}/export",
        response_model=None,
        responses={
            200: {
                "content": {
                    "application/json": {
                        "schema": {"type": "object", "additionalProperties": {}},
                    }
                }
            }
        },
    )
    def export(job_id: Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")]) -> Response:
        with _errors():
            payload = repository().export(job_id)
            return Response(
                payload,
                media_type="application/json",
                headers={
                    "Content-Disposition": f'attachment; filename="research-{job_id}.json"',
                    "Cache-Control": "no-store",
                },
            )

    return router
