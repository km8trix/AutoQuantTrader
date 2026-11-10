from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from apps.api.config import Settings
from apps.api.fixture_segment_views import create_fixture_segment_router
from apps.api.main import create_app
from packages.domain.fixture_segment_worker import FixtureSegmentJobStatus
from packages.persistence.experiment_governance import ExperimentGovernanceError
from packages.persistence.fixture_segment_worker import (
    FixtureSegmentJobProvenance,
    FixtureSegmentJobProvenanceSummary,
    FixtureSegmentPersistenceError,
    SqlFixtureSegmentProvenanceQuery,
)
from packages.persistence.schema import (
    phase3_experiment_audit_events,
    phase3_fixture_segment_transcript_artifacts,
)
from tests.integration.test_fixture_segment_worker_persistence import (
    _artifact_variant,
    _projection_with_feature_variant,
    _projection_with_target_variant,
    _queued_workflow,
    _replace_persisted_fixture_projection,
)
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


@dataclass(slots=True)
class _GovernanceFailureQuery:
    detail: str

    def get(self, job_id: str) -> FixtureSegmentJobProvenance:
        del job_id
        raise ExperimentGovernanceError(self.detail)

    def jobs(
        self,
        *,
        limit: int = 50,
        before_job_id: str | None = None,
    ) -> tuple[tuple[FixtureSegmentJobProvenanceSummary, ...], str | None]:
        del limit, before_job_id
        raise ExperimentGovernanceError(self.detail)


@dataclass(slots=True)
class _MalformedExactQuery:
    provenance: FixtureSegmentJobProvenance
    summary: FixtureSegmentJobProvenanceSummary

    def get(self, job_id: str) -> FixtureSegmentJobProvenance:
        del job_id
        return replace(self.provenance, events=())

    def jobs(
        self,
        *,
        limit: int = 50,
        before_job_id: str | None = None,
    ) -> tuple[tuple[FixtureSegmentJobProvenanceSummary, ...], str | None]:
        del limit, before_job_id
        return (self.summary,), "stored-detail-must-not-escape"  # type: ignore[return-value]


@dataclass(slots=True)
class _ExactResultQuery:
    provenance: FixtureSegmentJobProvenance
    summaries: tuple[FixtureSegmentJobProvenanceSummary, ...]
    cursor: str | None = None

    def get(self, job_id: str) -> FixtureSegmentJobProvenance:
        del job_id
        return self.provenance

    def jobs(
        self,
        *,
        limit: int = 50,
        before_job_id: str | None = None,
    ) -> tuple[tuple[FixtureSegmentJobProvenanceSummary, ...], str | None]:
        del limit, before_job_id
        return self.summaries, self.cursor


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


def _different_sha256(*excluded: str) -> str:
    for character in "0123456789abcdef":
        candidate = character * 64
        if candidate not in excluded:
            return candidate
    raise AssertionError("test digest universe was unexpectedly exhausted")


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
        "artifact_sha256",
        "transcript_payload_sha256",
        "semantic_sha256",
        "event_sha256",
        "previous_event_sha256",
        "feature_artifact_sha256",
        "target_artifact_sha256",
        "latest_event_sha256",
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
    detail_schema = client.app.openapi()["components"]["schemas"]["FixtureSegmentJobProvenanceView"]
    assert "next_before_sequence" in detail_schema["required"]


def test_same_length_output_substitutions_are_outside_the_public_claim(
    tmp_path: Path,
) -> None:
    fixture, engine, workflow, _queued = _queued_workflow(tmp_path)
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
    assert completed.feature_artifact.output_ids
    assert completed.target_artifact is not None
    assert completed.target_artifact.output_ids
    query = SqlFixtureSegmentProvenanceQuery(engine)
    client = _query_client(query)
    detail_path = f"/api/v1/research/fixture-segment-jobs/{completed.job.job_id}"
    baseline_detail = client.get(detail_path).json()["job"]
    baseline_list = client.get("/api/v1/research/fixture-segment-jobs").json()["jobs"]

    original_feature_output = completed.feature_artifact.output_ids[0]
    replacement_feature_output = "f" * 64 if original_feature_output != "f" * 64 else "e" * 64
    feature_artifact = _artifact_variant(
        completed.feature_artifact,
        output_ids=(
            replacement_feature_output,
            *completed.feature_artifact.output_ids[1:],
        ),
    )
    feature_replacement = _projection_with_feature_variant(completed, feature_artifact)
    _replace_persisted_fixture_projection(engine, completed, feature_replacement)
    feature_detail = client.get(detail_path)
    feature_list = client.get("/api/v1/research/fixture-segment-jobs")
    assert feature_detail.status_code == feature_list.status_code == 200
    assert feature_detail.json()["job"] == baseline_detail
    assert feature_list.json()["jobs"] == baseline_list

    original_target_output = feature_replacement.target_artifact.output_ids[0]
    replacement_target_output = (
        "phase3g-redacted-target-output"
        if original_target_output != "phase3g-redacted-target-output"
        else "phase3g-alternate-redacted-target-output"
    )
    target_artifact = _artifact_variant(
        feature_replacement.target_artifact,
        output_ids=(
            replacement_target_output,
            *feature_replacement.target_artifact.output_ids[1:],
        ),
    )
    target_replacement = _projection_with_target_variant(
        feature_replacement,
        target_artifact,
    )
    _replace_persisted_fixture_projection(engine, feature_replacement, target_replacement)
    target_detail = client.get(detail_path)
    target_list = client.get("/api/v1/research/fixture-segment-jobs")
    assert target_detail.status_code == target_list.status_code == 200
    assert target_detail.json()["job"] == baseline_detail
    assert target_list.json()["jobs"] == baseline_list

    encoded = json.dumps((target_detail.json()["job"], target_list.json()["jobs"]))
    for hidden_value in (
        original_feature_output,
        replacement_feature_output,
        original_target_output,
        replacement_target_output,
    ):
        assert hidden_value not in encoded
    for omitted_member_identity in (
        "artifact_sha256",
        "transcript_payload_sha256",
        "semantic_sha256",
        "event_sha256",
        "previous_event_sha256",
        "feature_artifact_sha256",
        "target_artifact_sha256",
        "latest_event_sha256",
        "step_sha256s",
        "output_ids",
    ):
        assert f'"{omitted_member_identity}"' not in encoded


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


def test_exact_type_malformed_and_governance_failures_return_generic_503(
    tmp_path: Path,
) -> None:
    _fixture, _engine, provenance, summary, _payload, _output = _completed_provenance(tmp_path)
    malformed = _query_client(_MalformedExactQuery(provenance, summary))
    malformed_list = malformed.get("/api/v1/research/fixture-segment-jobs")
    malformed_detail = malformed.get(f"/api/v1/research/fixture-segment-jobs/{provenance.job_id}")

    stored_detail = "governance audit disclosed a private operator label"
    governance = _query_client(_GovernanceFailureQuery(stored_detail))
    governance_list = governance.get("/api/v1/research/fixture-segment-jobs")
    governance_detail = governance.get(f"/api/v1/research/fixture-segment-jobs/{provenance.job_id}")
    for response in (
        malformed_list,
        malformed_detail,
        governance_list,
        governance_detail,
    ):
        assert response.status_code == 503
        assert response.json() == {
            "detail": "durable fixture-segment provenance is unavailable or malformed"
        }
        assert stored_detail not in response.text


def test_exact_detail_dto_chain_substitutions_return_generic_503(tmp_path: Path) -> None:
    _fixture, _engine, provenance, summary, _payload, _output = _completed_provenance(tmp_path)
    events = provenance.events
    assert len(events) == 3 and provenance.target_artifact is not None
    duplicate_running_sha256 = events[0].event_sha256
    renewal_event_sha256 = _different_sha256(*(event.event_sha256 for event in events))
    renewal_governance_sha256 = _different_sha256(
        provenance.queued_governance_event_sha256,
        *(event.governance_event_sha256 for event in events),
    )
    assert events[1].claim_expires_at is not None
    renewal = replace(
        events[1],
        event_sha256=renewal_event_sha256,
        sequence=2,
        previous_event_sha256=events[1].event_sha256,
        occurred_at=events[1].occurred_at + timedelta(seconds=30),
        claim_expires_at=events[1].claim_expires_at + timedelta(minutes=1),
        governance_event_sha256=renewal_governance_sha256,
    )
    terminal_after_renewal = replace(
        events[2],
        sequence=3,
        previous_event_sha256=renewal.event_sha256,
    )
    variants = (
        replace(provenance, events=tuple(reversed(events))),
        replace(provenance, events=(events[0], events[0], events[2])),
        replace(
            provenance,
            events=(
                events[0],
                replace(events[1], event_sha256=duplicate_running_sha256),
                replace(events[2], previous_event_sha256=duplicate_running_sha256),
            ),
        ),
        replace(
            provenance,
            events=(events[0], replace(events[1], sequence=7), events[2]),
        ),
        replace(
            provenance,
            events=(
                events[0],
                replace(events[1], job_id="d" * 64),
                events[2],
            ),
        ),
        replace(
            provenance,
            events=(
                events[0],
                replace(
                    events[1],
                    governance_event_sha256=provenance.queued_governance_event_sha256,
                ),
                events[2],
            ),
        ),
        replace(
            provenance,
            events=(
                events[0],
                events[1],
                replace(
                    events[2],
                    governance_event_sha256=provenance.queued_governance_event_sha256,
                ),
            ),
        ),
        replace(
            provenance,
            events=(events[0], events[1], renewal, terminal_after_renewal),
        ),
        replace(
            provenance,
            events=(
                events[0],
                replace(events[1], feature_artifact_sha256="f" * 64),
                events[2],
            ),
        ),
        replace(
            provenance,
            events=(
                events[0],
                events[1],
                replace(events[2], target_artifact_sha256="e" * 64),
            ),
        ),
        replace(provenance, requested_at=provenance.requested_at + timedelta(seconds=1)),
    )
    for variant in variants:
        response = _query_client(_ExactResultQuery(variant, (summary,))).get(
            f"/api/v1/research/fixture-segment-jobs/{provenance.job_id}"
        )
        assert response.status_code == 503
        assert response.json() == {
            "detail": "durable fixture-segment provenance is unavailable or malformed"
        }
        assert "inconsistent" not in response.text


def test_detail_route_rejects_a_different_internally_consistent_job(
    tmp_path: Path,
) -> None:
    _fixture, _engine, provenance, summary, _payload, _output = _completed_provenance(tmp_path)
    requested_job_id = _different_sha256(provenance.job_id)
    response = _query_client(_ExactResultQuery(provenance, (summary,))).get(
        f"/api/v1/research/fixture-segment-jobs/{requested_job_id}"
    )
    assert response.status_code == 503
    assert response.json() == {
        "detail": "durable fixture-segment provenance is unavailable or malformed"
    }
    assert provenance.job_id not in response.text


def test_exact_summary_dto_order_and_shape_substitutions_return_generic_503(
    tmp_path: Path,
) -> None:
    _fixture, _engine, provenance, summary, _payload, _output = _completed_provenance(tmp_path)
    older = replace(
        summary,
        job_id="f" * 64,
        requested_at=summary.requested_at - timedelta(seconds=1),
    )
    middle_job_id = _different_sha256(summary.job_id)
    middle = replace(
        summary,
        job_id=middle_job_id,
        requested_at=summary.requested_at - timedelta(seconds=1),
        latest_occurred_at=summary.latest_occurred_at - timedelta(seconds=1),
    )
    repeated_later = replace(
        summary,
        requested_at=summary.requested_at - timedelta(seconds=2),
        latest_occurred_at=summary.latest_occurred_at - timedelta(seconds=2),
    )
    tie_larger = replace(summary, job_id="f" * 64)
    tie_smaller = replace(summary, job_id="0" * 64)
    completed_equal_time = replace(summary, latest_occurred_at=summary.requested_at)
    running_equal_time = replace(
        summary,
        status=FixtureSegmentJobStatus.RUNNING,
        event_count=2,
        latest_sequence=1,
        latest_occurred_at=summary.requested_at,
        target_artifact_sha256=None,
        completion_receipt_sha256=None,
    )
    failed_equal_time = replace(
        summary,
        status=FixtureSegmentJobStatus.FAILED,
        latest_occurred_at=summary.requested_at,
        target_artifact_sha256=None,
        completion_receipt_sha256=None,
    )
    pages = (
        (older, summary),
        (summary, summary),
        (summary, middle, repeated_later),
        (tie_larger, tie_smaller),
        (replace(summary, latest_sequence=summary.latest_sequence + 1),),
        (replace(summary, target_artifact_sha256=None),),
        (replace(summary, latest_event_sha256="stored-detail-must-not-escape"),),
        (completed_equal_time,),
        (running_equal_time,),
        (failed_equal_time,),
    )
    for summaries in pages:
        response = _query_client(_ExactResultQuery(provenance, summaries)).get(
            "/api/v1/research/fixture-segment-jobs"
        )
        assert response.status_code == 503
        assert response.json() == {
            "detail": "durable fixture-segment provenance is unavailable or malformed"
        }
        assert "stored-detail-must-not-escape" not in response.text


def test_exact_summary_page_excludes_the_requested_cursor_row(tmp_path: Path) -> None:
    _fixture, _engine, provenance, summary, _payload, _output = _completed_provenance(tmp_path)
    response = _query_client(_ExactResultQuery(provenance, (summary,))).get(
        f"/api/v1/research/fixture-segment-jobs?before_job_id={summary.job_id}"
    )
    assert response.status_code == 503
    assert response.json() == {
        "detail": "durable fixture-segment provenance is unavailable or malformed"
    }
    assert summary.job_id not in response.text


def test_repository_translates_governance_audit_failure_before_api_boundary(
    tmp_path: Path,
) -> None:
    _fixture, engine, provenance, _summary, _payload, _output = _completed_provenance(tmp_path)
    with engine.begin() as connection:
        connection.execute(
            sa.delete(phase3_experiment_audit_events).where(
                phase3_experiment_audit_events.c.family_id == provenance.family_id
            )
        )

    query = SqlFixtureSegmentProvenanceQuery(engine)
    with pytest.raises(
        FixtureSegmentPersistenceError,
        match="governance is unavailable or malformed",
    ) as raised:
        query.get(provenance.job_id)
    assert isinstance(raised.value.__cause__, ExperimentGovernanceError)
    with pytest.raises(
        FixtureSegmentPersistenceError,
        match="governance is unavailable or malformed",
    ) as listed:
        query.jobs()
    assert isinstance(listed.value.__cause__, ExperimentGovernanceError)

    client = _query_client(query)
    responses = (
        client.get("/api/v1/research/fixture-segment-jobs"),
        client.get(f"/api/v1/research/fixture-segment-jobs/{provenance.job_id}"),
    )
    for response in responses:
        assert response.status_code == 503
        assert response.json() == {
            "detail": "durable fixture-segment provenance is unavailable or malformed"
        }
        assert "audit" not in response.text


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
