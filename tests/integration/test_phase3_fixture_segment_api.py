from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import sqlalchemy as sa
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from apps.api.config import Settings
from apps.api.fixture_segment_views import create_fixture_segment_router
from apps.api.main import create_app
from packages.domain.fixture_segment_worker import FixtureSegmentJobStatus
from packages.persistence.fixture_segment_worker import (
    FixtureSegmentJobProvenance,
    FixtureSegmentJobProvenanceSummary,
    SqlFixtureSegmentProvenanceQuery,
)
from packages.persistence.schema import phase3_fixture_segment_transcript_artifacts
from tests.integration.test_fixture_segment_worker_persistence import _queued_workflow
from tests.unit.test_experiment_governance import (
    FIRST_ATTEMPT_AT,
    GovernanceFixture,
    _target_certification,
)


@dataclass(slots=True)
class _QueryStub:
    provenance: FixtureSegmentJobProvenance
    summary: FixtureSegmentJobProvenanceSummary
    malformed: bool = False

    def get(self, job_id: str) -> FixtureSegmentJobProvenance:
        if self.malformed:
            return object()  # type: ignore[return-value]
        return self.provenance

    def jobs(
        self,
        *,
        limit: int = 50,
        before_job_id: str | None = None,
    ) -> tuple[tuple[FixtureSegmentJobProvenanceSummary, ...], str | None]:
        del limit, before_job_id
        if self.malformed:
            return ([self.summary], None)  # type: ignore[return-value]
        return (self.summary,), None


def _query_client(query: object | None, *, ready: bool = True) -> TestClient:
    app = FastAPI()
    router = APIRouter(prefix="/api/v1")
    router.include_router(
        create_fixture_segment_router(
            repository=query,  # type: ignore[arg-type]
            persistence_ready=lambda: ready,
        )
    )
    app.include_router(router)
    return TestClient(app)


def _completed_provenance(
    tmp_path: Path,
) -> tuple[
    GovernanceFixture,
    Engine,
    FixtureSegmentJobProvenance,
    FixtureSegmentJobProvenanceSummary,
    str,
    str,
]:
    fixture, engine, workflow, queued = _queued_workflow(tmp_path)
    claimed = workflow.claim_next(
        worker_id="private-worker-label-must-not-escape",
        claimed_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        claim_expires_at=FIRST_ATTEMPT_AT + timedelta(minutes=6),
    )
    assert claimed is not None and claimed.claim_token is not None
    completed = workflow.complete(
        claimed.job.job_id,
        claimed.claim_token,
        _target_certification(fixture.validation_certification, fixture.configuration),
        completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
    )
    query = SqlFixtureSegmentProvenanceQuery(engine)
    provenance = query.get(completed.job.job_id)
    summaries, cursor = query.jobs()
    assert cursor is None and len(summaries) == 1
    return (
        fixture,
        engine,
        provenance,
        summaries[0],
        queued.feature_artifact.transcript_payload,
        (queued.feature_artifact.output_ids[0]),
    )


def test_routes_are_get_only_bounded_paginated_and_redact_transcript_material(
    tmp_path: Path,
) -> None:
    _fixture, _engine, provenance, summary, transcript_payload, output_id = _completed_provenance(
        tmp_path
    )
    client = _query_client(_QueryStub(provenance, summary))

    listing = client.get("/api/v1/research/fixture-segment-jobs?limit=1")
    assert listing.status_code == 200
    assert listing.json()["next_before_job_id"] is None
    assert [job["job_id"] for job in listing.json()["jobs"]] == [provenance.job_id]

    first = client.get(f"/api/v1/research/fixture-segment-jobs/{provenance.job_id}?event_limit=1")
    assert first.status_code == 200
    job = first.json()["job"]
    assert job["summary"]["status"] == FixtureSegmentJobStatus.COMPLETED.value
    assert job["total_event_count"] == 3
    assert [event["sequence"] for event in job["events"]] == [2]
    assert job["next_before_sequence"] == 2
    second = client.get(
        f"/api/v1/research/fixture-segment-jobs/{provenance.job_id}?event_limit=1&before_sequence=2"
    )
    assert [event["sequence"] for event in second.json()["job"]["events"]] == [1]
    assert second.json()["job"]["next_before_sequence"] == 1
    final = client.get(
        f"/api/v1/research/fixture-segment-jobs/{provenance.job_id}?event_limit=1&before_sequence=1"
    )
    assert [event["sequence"] for event in final.json()["job"]["events"]] == [0]
    assert final.json()["job"]["next_before_sequence"] is None

    encoded = first.text
    assert transcript_payload not in encoded
    assert output_id not in encoded
    assert "phase3f-scheduler" not in encoded
    assert "private-worker-label-must-not-escape" not in encoded
    for forbidden_name in (
        "transcript_payload",
        "step_sha256s",
        "output_ids",
        "requested_by",
        "actor_id",
        "worker_id",
        "segment_sha256",
        "source_evidence_sha256",
        "holdout_reveal_sha256",
        "holdout_commitment",
        "terminal_reason_code",
        "terminal_reason_sha256",
        "positions",
        "returns",
        "pnl",
        "promotion_decision",
    ):
        assert f'"{forbidden_name}"' not in encoded

    assert client.post("/api/v1/research/fixture-segment-jobs", json={}).status_code == 405
    paths = client.app.openapi()["paths"]
    assert set(paths["/api/v1/research/fixture-segment-jobs"]) == {"get"}
    assert set(paths["/api/v1/research/fixture-segment-jobs/{job_id}"]) == {"get"}


def test_validation_missing_records_and_cursors_are_bounded_and_non_oracular(
    tmp_path: Path,
) -> None:
    _fixture, _engine, provenance, _summary, _payload, _output = _completed_provenance(tmp_path)
    query = SqlFixtureSegmentProvenanceQuery(_engine)
    client = _query_client(query)

    assert client.get("/api/v1/research/fixture-segment-jobs?limit=0").status_code == 422
    assert client.get("/api/v1/research/fixture-segment-jobs?limit=101").status_code == 422
    assert (
        client.get("/api/v1/research/fixture-segment-jobs?before_job_id=invalid").status_code == 422
    )
    assert (
        client.get(
            f"/api/v1/research/fixture-segment-jobs/{provenance.job_id}?event_limit=0"
        ).status_code
        == 422
    )

    unknown_cursor = client.get(f"/api/v1/research/fixture-segment-jobs?before_job_id={'f' * 64}")
    unknown_job = client.get(f"/api/v1/research/fixture-segment-jobs/{'e' * 64}")
    unknown_event = client.get(
        f"/api/v1/research/fixture-segment-jobs/{provenance.job_id}?before_sequence=9999"
    )
    assert unknown_cursor.status_code == unknown_job.status_code == unknown_event.status_code == 404
    assert (
        unknown_cursor.json()
        == unknown_job.json()
        == unknown_event.json()
        == {"detail": "fixture-segment provenance was not found"}
    )


def test_malformed_unavailable_and_corrupt_queries_fail_closed(tmp_path: Path) -> None:
    _fixture, engine, provenance, summary, _payload, _output = _completed_provenance(tmp_path)
    assert _query_client(None).get("/api/v1/research/fixture-segment-jobs").status_code == 503
    assert (
        _query_client(_QueryStub(provenance, summary), ready=False)
        .get("/api/v1/research/fixture-segment-jobs")
        .status_code
        == 503
    )
    malformed = _query_client(_QueryStub(provenance, summary, malformed=True))
    assert malformed.get("/api/v1/research/fixture-segment-jobs").status_code == 503
    assert (
        malformed.get(f"/api/v1/research/fixture-segment-jobs/{provenance.job_id}").status_code
        == 503
    )

    with engine.begin() as connection:
        connection.execute(
            sa.update(phase3_fixture_segment_transcript_artifacts)
            .where(
                phase3_fixture_segment_transcript_artifacts.c.artifact_sha256
                == provenance.feature_artifact.artifact_sha256
            )
            .values(transcript_payload="{}")
        )
    corrupt = _query_client(SqlFixtureSegmentProvenanceQuery(engine))
    response = corrupt.get(f"/api/v1/research/fixture-segment-jobs/{provenance.job_id}")
    assert response.status_code == 503
    assert response.json() == {
        "detail": "durable fixture-segment provenance is unavailable or malformed"
    }


def test_durable_main_composes_fixture_provenance_query_capability(tmp_path: Path) -> None:
    _fixture, engine, provenance, _summary, _payload, _output = _completed_provenance(tmp_path)
    client = TestClient(create_app(Settings(), engine=engine))

    bootstrap = client.get("/api/v1/ui/bootstrap")
    assert bootstrap.status_code == 200
    assert "fixture-segment-provenance-query" in bootstrap.json()["capabilities"]
    assert bootstrap.json()["feature_flags"]["fixture_segment_query"] is True
    assert client.get("/api/v1/research/fixture-segment-jobs").status_code == 200
    detail = client.get(f"/api/v1/research/fixture-segment-jobs/{provenance.job_id}")
    assert detail.status_code == 200
