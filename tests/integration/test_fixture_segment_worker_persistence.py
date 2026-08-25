from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine
from sqlalchemy.dialects import postgresql

from packages.application.fixture_segment_worker import process_one_fixture_segment
from packages.domain.experiment_governance import ExperimentAttemptStatus
from packages.domain.experiment_registry import EvaluationSegmentKind
from packages.domain.feature import CertifiedFeatureReplay
from packages.domain.fixture_segment_worker import (
    FIXTURE_SEGMENT_FAILURE_CODE,
    FIXTURE_SEGMENT_FAILURE_SHA256,
    FixtureSegmentJob,
    FixtureSegmentJobProjection,
    FixtureSegmentJobStatus,
)
from packages.persistence.database import verify_operational_schema
from packages.persistence.fixture_segment_worker import (
    FixtureSegmentPersistenceConflict,
    FixtureSegmentPersistenceError,
    SqlFixtureSegmentWorkflow,
    _job_head_statement,
)
from packages.persistence.schema import (
    phase3_fixture_segment_job_events,
    phase3_fixture_segment_job_heads,
    phase3_fixture_segment_jobs,
    phase3_fixture_segment_transcript_artifacts,
)
from tests.integration.test_experiment_governance_persistence import (
    _persist_attempt,
    _registered_repository,
)
from tests.unit.test_experiment_governance import (
    FIRST_ATTEMPT_AT,
    GovernanceFixture,
    _fixture,
    _request,
    _scoped_certification,
    _target_certification,
)


def _queued_workflow(
    tmp_path: Path,
) -> tuple[GovernanceFixture, Engine, SqlFixtureSegmentWorkflow, FixtureSegmentJobProjection]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    fixture = _fixture()
    engine, governance, initial = _registered_repository(tmp_path, fixture)
    proposed = _request(
        initial,
        fixture,
        kind=EvaluationSegmentKind.VALIDATION,
        requested_at=FIRST_ATTEMPT_AT,
    )
    queued = _persist_attempt(
        governance,
        initial,
        proposed,
        key="phase3f-record-validation-attempt",
    )
    workflow = SqlFixtureSegmentWorkflow(engine)
    job = workflow.enqueue(
        queued,
        queued.attempts[-1].attempt_id,
        fixture.validation_certification,
        requested_at=FIRST_ATTEMPT_AT + timedelta(seconds=1),
        requested_by="phase3f-scheduler",
    )
    return fixture, engine, workflow, job


def test_durable_worker_publishes_transcripts_and_governed_receipt_atomically(
    tmp_path: Path,
) -> None:
    fixture, engine, workflow, queued = _queued_workflow(tmp_path)
    claimed = workflow.claim_next(
        worker_id="phase3f-process-a",
        claimed_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        claim_expires_at=FIRST_ATTEMPT_AT + timedelta(minutes=6),
    )
    assert claimed is not None and claimed.claim_token is not None
    target = _target_certification(fixture.validation_certification, fixture.configuration)
    completed = workflow.complete(
        claimed.job.job_id,
        claimed.claim_token,
        target,
        completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
    )

    assert completed.status is FixtureSegmentJobStatus.COMPLETED
    assert completed.target_artifact is not None
    governed = workflow.governance_snapshot(completed.job.family_id)
    governed_event = governed.latest_event(completed.job.attempt_id)
    assert governed_event.status is ExperimentAttemptStatus.COMPLETED
    assert completed.latest.governance_event_sha256 == governed_event.semantic_sha256
    assert completed.latest.completion_receipt_sha256 == (
        governed_event.terminal_evidence.semantic_sha256  # type: ignore[union-attr]
    )
    with engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase3_fixture_segment_transcript_artifacts)
            )
            == 2
        )

    # The exact terminal command is idempotent and does not append evidence.
    assert (
        workflow.complete(
            claimed.job.job_id,
            claimed.claim_token,
            target,
            completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
        )
        == completed
    )
    assert workflow.get(queued.job.job_id) == completed
    verify_operational_schema(engine, require_phase_zero_facts=False)


def test_enqueue_exact_retry_is_idempotent_and_changed_input_conflicts(tmp_path: Path) -> None:
    fixture, engine, workflow, queued = _queued_workflow(tmp_path)
    snapshot = workflow.governance_snapshot(queued.job.family_id)

    assert (
        workflow.enqueue(
            snapshot,
            queued.job.attempt_id,
            fixture.validation_certification,
            requested_at=FIRST_ATTEMPT_AT + timedelta(seconds=1),
            requested_by="phase3f-scheduler",
        )
        == queued
    )
    with pytest.raises(FixtureSegmentPersistenceConflict):
        workflow.enqueue(
            snapshot,
            queued.job.attempt_id,
            fixture.validation_certification,
            requested_at=FIRST_ATTEMPT_AT + timedelta(seconds=2),
            requested_by="phase3f-scheduler",
        )
    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase3_fixture_segment_jobs))
            == 1
        )


def test_enqueue_exact_retry_returns_running_and_completed_durable_state(tmp_path: Path) -> None:
    fixture, engine, workflow, queued = _queued_workflow(tmp_path)
    original_snapshot = workflow.governance_snapshot(queued.job.family_id)
    claimed = workflow.claim_next(
        worker_id="phase3f-process-a",
        claimed_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        claim_expires_at=FIRST_ATTEMPT_AT + timedelta(minutes=6),
    )
    assert claimed is not None and claimed.claim_token is not None
    running_snapshot = workflow.governance_snapshot(queued.job.family_id)

    for supplied_snapshot in (original_snapshot, running_snapshot):
        assert (
            workflow.enqueue(
                supplied_snapshot,
                queued.job.attempt_id,
                fixture.validation_certification,
                requested_at=FIRST_ATTEMPT_AT + timedelta(seconds=1),
                requested_by="phase3f-scheduler",
            )
            == claimed
        )
    with pytest.raises(FixtureSegmentPersistenceConflict, match="changed its exact input"):
        workflow.enqueue(
            running_snapshot,
            queued.job.attempt_id,
            fixture.validation_certification,
            requested_at=FIRST_ATTEMPT_AT + timedelta(seconds=2),
            requested_by="phase3f-scheduler",
        )

    completed = workflow.complete(
        queued.job.job_id,
        claimed.claim_token,
        _target_certification(fixture.validation_certification, fixture.configuration),
        completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
    )
    completed_snapshot = workflow.governance_snapshot(queued.job.family_id)
    for supplied_snapshot in (original_snapshot, completed_snapshot):
        assert (
            workflow.enqueue(
                supplied_snapshot,
                queued.job.attempt_id,
                fixture.validation_certification,
                requested_at=FIRST_ATTEMPT_AT + timedelta(seconds=1),
                requested_by="phase3f-scheduler",
            )
            == completed
        )
    with pytest.raises(FixtureSegmentPersistenceConflict):
        workflow.enqueue(
            completed_snapshot,
            queued.job.attempt_id,
            _scoped_certification(40),
            requested_at=FIRST_ATTEMPT_AT + timedelta(seconds=1),
            requested_by="phase3f-scheduler",
        )

    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase3_fixture_segment_jobs))
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase3_fixture_segment_job_events)
            )
            == 3
        )


def test_concurrent_exact_enqueue_retry_and_claim_converge(tmp_path: Path) -> None:
    fixture, engine, workflow, queued = _queued_workflow(tmp_path)
    original_snapshot = workflow.governance_snapshot(queued.job.family_id)
    barrier = Barrier(2)

    def retry_enqueue() -> FixtureSegmentJobProjection:
        barrier.wait()
        return workflow.enqueue(
            original_snapshot,
            queued.job.attempt_id,
            fixture.validation_certification,
            requested_at=FIRST_ATTEMPT_AT + timedelta(seconds=1),
            requested_by="phase3f-scheduler",
        )

    def claim() -> FixtureSegmentJobProjection | None:
        barrier.wait()
        return workflow.claim_next(
            worker_id="phase3f-process-a",
            claimed_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
            claim_expires_at=FIRST_ATTEMPT_AT + timedelta(minutes=6),
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        retry_future = executor.submit(retry_enqueue)
        claim_future = executor.submit(claim)
        retry_result = retry_future.result()
        claim_result = claim_future.result()

    assert claim_result is not None
    assert retry_result.status in {
        FixtureSegmentJobStatus.QUEUED,
        FixtureSegmentJobStatus.RUNNING,
    }
    final = workflow.get(queued.job.job_id)
    assert final.status is FixtureSegmentJobStatus.RUNNING
    assert (
        workflow.enqueue(
            workflow.governance_snapshot(queued.job.family_id),
            queued.job.attempt_id,
            fixture.validation_certification,
            requested_at=FIRST_ATTEMPT_AT + timedelta(seconds=1),
            requested_by="phase3f-scheduler",
        )
        == final
    )
    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase3_fixture_segment_jobs))
            == 1
        )


def test_postgresql_retry_head_statement_locks_the_exact_projection_row() -> None:
    statement = _job_head_statement("a" * 64, lock=True)
    compiled = str(statement.compile(dialect=postgresql.dialect()))

    assert "FOR UPDATE OF phase3_fixture_segment_job_heads" in compiled


def test_concurrent_claim_has_one_winner_and_stale_claim_cannot_complete(tmp_path: Path) -> None:
    fixture, _engine, workflow, queued = _queued_workflow(tmp_path)

    def claim(worker: str) -> FixtureSegmentJobProjection | None:
        return workflow.claim_next(
            worker_id=worker,
            claimed_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
            claim_expires_at=FIRST_ATTEMPT_AT + timedelta(minutes=6),
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(claim, ("phase3f-process-a", "phase3f-process-b")))
    winners = tuple(result for result in results if result is not None)
    assert len(winners) == 1
    first = winners[0]
    assert first.claim_token is not None

    takeover = workflow.claim_next(
        worker_id="phase3f-process-c",
        claimed_at=FIRST_ATTEMPT_AT + timedelta(minutes=7),
        claim_expires_at=FIRST_ATTEMPT_AT + timedelta(minutes=12),
    )
    assert takeover is not None and takeover.claim_token is not None
    target = _target_certification(fixture.validation_certification, fixture.configuration)
    with pytest.raises(FixtureSegmentPersistenceConflict, match="stale or substituted"):
        workflow.complete(
            queued.job.job_id,
            first.claim_token,
            target,
            completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=8),
        )
    completed = workflow.complete(
        queued.job.job_id,
        takeover.claim_token,
        target,
        completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=8),
    )
    assert completed.status is FixtureSegmentJobStatus.COMPLETED


def test_substituted_target_and_expired_worker_publish_nothing(tmp_path: Path) -> None:
    fixture, engine, workflow, queued = _queued_workflow(tmp_path)
    claimed = workflow.claim_next(
        worker_id="phase3f-process-a",
        claimed_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        claim_expires_at=FIRST_ATTEMPT_AT + timedelta(minutes=6),
    )
    assert claimed is not None and claimed.claim_token is not None
    substituted = _target_certification(_scoped_certification(40), fixture.configuration)

    with pytest.raises(FixtureSegmentPersistenceConflict):
        workflow.complete(
            queued.job.job_id,
            claimed.claim_token,
            substituted,
            completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
        )
    valid = _target_certification(fixture.validation_certification, fixture.configuration)
    with pytest.raises(FixtureSegmentPersistenceConflict, match="expired"):
        workflow.complete(
            queued.job.job_id,
            claimed.claim_token,
            valid,
            completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=7),
        )
    with engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase3_fixture_segment_transcript_artifacts)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase3_fixture_segment_job_events)
                .where(
                    phase3_fixture_segment_job_events.c.status
                    == FixtureSegmentJobStatus.COMPLETED.value
                )
            )
            == 0
        )
    assert workflow.get(queued.job.job_id).status is FixtureSegmentJobStatus.RUNNING


def test_crash_between_governance_and_job_publication_rolls_back_both(tmp_path: Path) -> None:
    fixture, engine, workflow, queued = _queued_workflow(tmp_path)
    claimed = workflow.claim_next(
        worker_id="phase3f-process-a",
        claimed_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        claim_expires_at=FIRST_ATTEMPT_AT + timedelta(minutes=6),
    )
    assert claimed is not None and claimed.claim_token is not None
    target = _target_certification(fixture.validation_certification, fixture.configuration)

    def crash_after_governance(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        if statement.lstrip().upper().startswith("INSERT INTO PHASE3_FIXTURE_SEGMENT_JOB_EVENTS"):
            raise KeyboardInterrupt("simulated crash boundary")

    sa.event.listen(engine, "before_cursor_execute", crash_after_governance)
    try:
        with pytest.raises(KeyboardInterrupt, match="simulated crash"):
            workflow.complete(
                queued.job.job_id,
                claimed.claim_token,
                target,
                completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
            )
    finally:
        sa.event.remove(engine, "before_cursor_execute", crash_after_governance)

    recovered = workflow.get(queued.job.job_id)
    governed = workflow.governance_snapshot(queued.job.family_id)
    assert recovered.status is FixtureSegmentJobStatus.RUNNING
    assert governed.latest_event(queued.job.attempt_id).status is ExperimentAttemptStatus.RUNNING
    with engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase3_fixture_segment_transcript_artifacts)
            )
            == 1
        )


def test_corrupt_transcript_or_head_fails_closed(tmp_path: Path) -> None:
    _fixture_value, engine, workflow, queued = _queued_workflow(tmp_path / "transcript")
    with engine.begin() as connection:
        connection.execute(
            sa.update(phase3_fixture_segment_transcript_artifacts)
            .where(
                phase3_fixture_segment_transcript_artifacts.c.artifact_sha256
                == queued.feature_artifact.artifact_sha256
            )
            .values(transcript_payload=queued.feature_artifact.transcript_payload + " ")
        )

    with pytest.raises(FixtureSegmentPersistenceError, match="artifact is malformed"):
        workflow.get(queued.job.job_id)

    _fixture_value, engine, workflow, queued = _queued_workflow(tmp_path / "head")
    with engine.begin() as connection:
        connection.execute(
            sa.update(phase3_fixture_segment_job_heads)
            .where(phase3_fixture_segment_job_heads.c.job_id == queued.job.job_id)
            .values(attempt_number=1)
        )

    with pytest.raises(FixtureSegmentPersistenceError, match="head diverges"):
        workflow.get(queued.job.job_id)


def test_application_worker_success_failure_and_uncaught_crash_boundary(tmp_path: Path) -> None:
    fixture, _engine, workflow, queued = _queued_workflow(tmp_path / "success")
    instants = iter(
        (
            FIRST_ATTEMPT_AT + timedelta(minutes=1),
            FIRST_ATTEMPT_AT + timedelta(minutes=2),
        )
    )
    completed = process_one_fixture_segment(
        workflow,
        worker_id="phase3f-process-a",
        resolve_certification=lambda _job: fixture.validation_certification,
        clock=lambda: next(instants),
    )
    assert completed is not None and completed.status is FixtureSegmentJobStatus.COMPLETED

    fixture, _engine, workflow, queued = _queued_workflow(tmp_path / "failure")
    instants = iter(
        (
            FIRST_ATTEMPT_AT + timedelta(minutes=1),
            FIRST_ATTEMPT_AT + timedelta(minutes=2),
        )
    )

    def fail(_job: FixtureSegmentJob) -> CertifiedFeatureReplay:
        raise RuntimeError("secret raw provider-like detail")

    failed = process_one_fixture_segment(
        workflow,
        worker_id="phase3f-process-a",
        resolve_certification=fail,
        clock=lambda: next(instants),
    )
    assert failed is not None and failed.status is FixtureSegmentJobStatus.FAILED
    assert "secret" not in failed.latest.canonical_json

    fixture, _engine, workflow, queued = _queued_workflow(tmp_path / "crash")

    def crash(_job: FixtureSegmentJob) -> CertifiedFeatureReplay:
        raise KeyboardInterrupt("simulated process death")

    with pytest.raises(KeyboardInterrupt, match="simulated process death"):
        process_one_fixture_segment(
            workflow,
            worker_id="phase3f-process-a",
            resolve_certification=crash,
            clock=lambda: FIRST_ATTEMPT_AT + timedelta(minutes=1),
        )
    assert workflow.get(queued.job.job_id).status is FixtureSegmentJobStatus.RUNNING


def test_failure_does_not_publish_target_artifact(tmp_path: Path) -> None:
    _fixture_value, engine, workflow, queued = _queued_workflow(tmp_path)
    claimed = workflow.claim_next(
        worker_id="phase3f-process-a",
        claimed_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        claim_expires_at=FIRST_ATTEMPT_AT + timedelta(minutes=6),
    )
    assert claimed is not None and claimed.claim_token is not None
    failed = workflow.fail(
        queued.job.job_id,
        claimed.claim_token,
        failed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
        reason_code=FIXTURE_SEGMENT_FAILURE_CODE,
        reason_sha256=FIXTURE_SEGMENT_FAILURE_SHA256,
    )
    assert failed.status is FixtureSegmentJobStatus.FAILED
    assert (
        workflow.enqueue(
            workflow.governance_snapshot(queued.job.family_id),
            queued.job.attempt_id,
            _fixture_value.validation_certification,
            requested_at=FIRST_ATTEMPT_AT + timedelta(seconds=1),
            requested_by="phase3f-scheduler",
        )
        == failed
    )
    with engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase3_fixture_segment_transcript_artifacts)
            )
            == 1
        )


def test_failure_rejects_an_open_ended_classification(tmp_path: Path) -> None:
    _fixture_value, _engine, workflow, queued = _queued_workflow(tmp_path)
    claimed = workflow.claim_next(
        worker_id="phase3f-process-a",
        claimed_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        claim_expires_at=FIRST_ATTEMPT_AT + timedelta(minutes=6),
    )
    assert claimed is not None and claimed.claim_token is not None

    with pytest.raises(FixtureSegmentPersistenceConflict, match="classification is not closed"):
        workflow.fail(
            queued.job.job_id,
            claimed.claim_token,
            failed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
            reason_code=FIXTURE_SEGMENT_FAILURE_CODE,
            reason_sha256="a" * 64,
        )

    assert workflow.get(queued.job.job_id).status is FixtureSegmentJobStatus.RUNNING


def test_0037_migration_is_additive_matches_metadata_and_downgrades_only_empty(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "migration.sqlite"
    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(Path(__file__).resolve().parents[2] / "migrations"),
    )
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{database_path}")
    command.upgrade(config, "0036_phase6_time_anchors")
    engine = sa.create_engine(f"sqlite+pysqlite:///{database_path}")
    inspector = sa.inspect(engine)
    new_tables = {
        phase3_fixture_segment_transcript_artifacts.name,
        phase3_fixture_segment_jobs.name,
        phase3_fixture_segment_job_events.name,
        phase3_fixture_segment_job_heads.name,
    }
    assert not (new_tables & set(inspector.get_table_names()))

    command.upgrade(config, "head")
    inspector = sa.inspect(engine)
    assert new_tables <= set(inspector.get_table_names())
    for table in (
        phase3_fixture_segment_transcript_artifacts,
        phase3_fixture_segment_jobs,
        phase3_fixture_segment_job_events,
        phase3_fixture_segment_job_heads,
    ):
        assert tuple(column["name"] for column in inspector.get_columns(table.name)) == tuple(
            table.c.keys()
        )
    command.downgrade(config, "0036_phase6_time_anchors")
    assert not (new_tables & set(sa.inspect(engine).get_table_names()))

    fixture, engine, _workflow, _queued = _queued_workflow(tmp_path / "nonempty")
    config.set_main_option(
        "sqlalchemy.url",
        engine.url.render_as_string(hide_password=False).replace("%", "%%"),
    )
    with pytest.raises(RuntimeError, match="refusing to downgrade nonempty"):
        command.downgrade(config, "0036_phase6_time_anchors")
    assert fixture.family.family_id
