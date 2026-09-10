from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Event, get_ident

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine

from packages.application import personal_codec
from packages.domain.personal_contracts import content_digest
from packages.domain.research_job_contracts import (
    MAX_ATTEMPTS,
    MAX_INPUT_BYTES,
    MAX_JOB_EVENTS,
    MAX_OBJECT_BYTES,
    ObjectRef,
    ResearchClaim,
    ResearchJobEvent,
    ResearchProgress,
    ResearchPublication,
)
from packages.domain.research_job_v2 import ResearchClaimLost, ResearchJobConflict
from packages.persistence import research_workflow_v2
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import ImmutableFactConflict
from packages.persistence.research_schema_v2 import (
    RESEARCH_TABLES_V2,
    research_job_events_v2,
    research_job_heads_v2,
    research_jobs_v2,
    research_objects_v2,
    research_publications_v2,
)
from packages.persistence.research_workflow_v2 import SqlResearchWorkflow
from packages.persistence.schema import metadata
from tests.unit.test_research_job_v2 import NOW, publication, sample_request


def make_workflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Engine, SqlResearchWorkflow, list[datetime]]:
    engine = sa.create_engine(f"sqlite+pysqlite:///{tmp_path}/jobs.sqlite")

    @sa.event.listens_for(engine, "connect")
    def foreign_keys(connection, record):  # type: ignore[no-untyped-def]
        connection.execute("PRAGMA foreign_keys=ON")

    metadata.create_all(engine, tables=RESEARCH_TABLES_V2)
    clock = [NOW]
    monkeypatch.setattr(research_workflow_v2, "database_time", lambda _connection: clock[0])
    return engine, SqlResearchWorkflow(engine, codec=personal_codec), clock


def test_sql_launch_roundtrip_idempotency_and_owner_visibility(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, workflow, clock = make_workflow(tmp_path, monkeypatch)
    request = sample_request()
    accepted = workflow.launch(request)
    clock[0] += timedelta(seconds=10)
    assert workflow.launch(request) == accepted
    assert workflow.get_request(request.job_id) == request
    with pytest.raises(ResearchJobConflict):
        workflow.launch(replace(request, trial_id="trial-other"))
    assert workflow.jobs(owner_id="owner") == (accepted,)
    assert workflow.jobs(owner_id="other") == ()
    with pytest.raises(ResearchJobConflict):
        workflow.request_cancel(request.job_id, owner_id="other", idempotency_key="cancel-0001")
    assert SqlResearchWorkflow(engine, codec=personal_codec).get(request.job_id) == accepted


def test_launch_uses_inserted_row_when_driver_rowcount_is_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, workflow, clock = make_workflow(tmp_path, monkeypatch)
    inserts = 0

    def hide_insert_rowcount(_connection, statement, _multiparams, _params, _options, result):  # type: ignore[no-untyped-def]
        nonlocal inserts
        if isinstance(statement, sa.sql.dml.Insert) and statement.table is research_jobs_v2:
            # INSERT rowcount may be -1 even though the SQL statement succeeded.
            # Preserve the real writes and any RETURNING rows from the database.
            result.rowcount = -1
            inserts += 1

    sa.event.listen(engine, "after_execute", hide_insert_rowcount)
    request = sample_request()
    accepted = workflow.launch(request)
    clock[0] += timedelta(seconds=10)
    assert workflow.launch(request) == accepted
    with pytest.raises(ResearchJobConflict, match="idempotency key conflicts"):
        workflow.launch(replace(request, trial_id="different-trial"))
    assert inserts == 3
    assert workflow.get(request.job_id) == accepted
    assert workflow.get_request(request.job_id) == request
    with engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(research_jobs_v2)) == 1
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(research_job_events_v2)) == 1
        )


def test_parallel_claims_and_recovery_fence_stale_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, workflow, clock = make_workflow(tmp_path, monkeypatch)
    request = sample_request()
    workflow.launch(request)
    with ThreadPoolExecutor(max_workers=2) as pool:
        attempts = tuple(
            pool.map(
                lambda instance: workflow.claim_next(
                    worker_id="worker", worker_instance_id=instance
                ),
                ("one", "two"),
            )
        )
    selected = tuple(item for item in attempts if item is not None)
    assert len(selected) == 1
    old = selected[0].claim
    clock[0] = old.lease_expires_at
    current = workflow.claim_next(worker_id="worker", worker_instance_id="restarted")
    assert current is not None and current.claim.fence == 2
    with engine.connect() as connection:
        state = workflow._load(connection, request.job_id)
    old_publication = replace(publication(state), attempt_id=old.attempt_id)
    with pytest.raises(ResearchClaimLost):
        workflow.publish(old, publication=old_publication)
    assert workflow.get(request.job_id).attempts[0].outcome == "abandoned"


def test_cancel_recovery_never_launches_another_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, workflow, clock = make_workflow(tmp_path, monkeypatch)
    request = sample_request()
    workflow.launch(request)
    selected = workflow.claim_next(worker_id="worker", worker_instance_id="one")
    assert selected is not None
    pending = workflow.request_cancel(
        request.job_id, owner_id="owner", idempotency_key="cancel-0001"
    )
    assert pending.status == "running" and pending.cancel_requested
    assert (
        workflow.request_cancel(request.job_id, owner_id="owner", idempotency_key="cancel-0001")
        == pending
    )
    clock[0] = selected.claim.lease_expires_at
    assert workflow.claim_next(worker_id="worker", worker_instance_id="two") is None
    final = workflow.get(request.job_id)
    assert final.status == "cancelled" and len(final.attempts) == 1


def test_sql_terminal_publication_is_atomic_and_lost_ack_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, workflow, clock = make_workflow(tmp_path, monkeypatch)
    request = sample_request()
    workflow.launch(request)
    selected = workflow.claim_next(worker_id="worker", worker_instance_id="one")
    assert selected is not None
    with engine.connect() as connection:
        state = workflow._load(connection, request.job_id)
    result = publication(state)
    original = workflow._advance

    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("injected failure after publication insert")

    monkeypatch.setattr(workflow, "_advance", broken)
    with pytest.raises(RuntimeError):
        workflow.publish(selected.claim, publication=result)
    with engine.connect() as connection:
        assert (
            connection.execute(
                sa.select(sa.func.count()).select_from(research_publications_v2)
            ).scalar_one()
            == 0
        )
    monkeypatch.setattr(workflow, "_advance", original)
    completed = workflow.publish(selected.claim, publication=result)
    clock[0] += timedelta(hours=1)
    assert workflow.publish(selected.claim, publication=result) == completed
    assert workflow.get(request.job_id) == completed
    with engine.connect() as connection:
        assert (
            connection.execute(
                sa.select(sa.func.count()).select_from(research_publications_v2)
            ).scalar_one()
            == 1
        )


@pytest.mark.parametrize(
    "table,column,value",
    [
        (research_jobs_v2, "run_id", "run-" + "f" * 64),
        (research_job_heads_v2, "status", "failed"),
        (research_job_events_v2, "kind", "failed"),
    ],
)
def test_sql_reconstruction_rejects_query_projection_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, table: sa.Table, column: str, value: str
) -> None:
    engine, workflow, _ = make_workflow(tmp_path, monkeypatch)
    request = sample_request()
    workflow.launch(request)
    with engine.begin() as connection:
        connection.execute(sa.update(table).values(**{column: value}))
    with pytest.raises((ResearchJobConflict, ImmutableFactConflict)):
        workflow.get(request.job_id)


def test_heartbeat_progress_and_shutdown_attempt_survive_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, workflow, clock = make_workflow(tmp_path, monkeypatch)
    request = sample_request()
    workflow.launch(request)
    selected = workflow.claim_next(worker_id="worker", worker_instance_id="one")
    assert selected is not None
    clock[0] += timedelta(seconds=10)
    progress = ResearchProgress("running", 6, 4)
    renewed = workflow.heartbeat(selected.claim, progress=progress)
    assert workflow.get(request.job_id).progress == progress
    stopped = workflow.finish(renewed.claim, outcome="abandoned", reason_code="worker_shutdown")
    assert stopped.status == "queued" and stopped.attempts[-1].outcome == "abandoned"
    restarted = SqlResearchWorkflow(engine, codec=personal_codec).claim_next(
        worker_id="worker", worker_instance_id="two"
    )
    assert restarted is not None and restarted.claim.fence == 2
    assert workflow.get(request.job_id).progress is None


def test_catalog_transaction_seam_rolls_back_all_queued_jobs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, workflow, _ = make_workflow(tmp_path, monkeypatch)
    with pytest.raises(RuntimeError), engine.begin() as connection:
        workflow.launch_in_transaction(connection, sample_request("batch-0001"))
        workflow.launch_in_transaction(connection, sample_request("batch-0002"))
        raise RuntimeError("simulated later trial registration failure")
    assert workflow.jobs(owner_id="owner") == ()
    with engine.connect() as connection, pytest.raises(ResearchJobConflict):
        workflow.launch_in_transaction(connection, sample_request())
    other_engine = sa.create_engine("sqlite+pysqlite:///:memory:")
    with other_engine.begin() as connection, pytest.raises(ResearchJobConflict):
        workflow.launch_in_transaction(connection, sample_request())
    with engine.begin() as connection:
        first = workflow.launch_in_transaction(connection, sample_request("batch-0001"))
        second = workflow.launch_in_transaction(connection, sample_request("batch-0002"))
    assert {item.job_id for item in workflow.jobs(owner_id="owner")} == {
        first.job_id,
        second.job_id,
    }


def test_database_time_regression_cannot_extend_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, workflow, clock = make_workflow(tmp_path, monkeypatch)
    workflow.launch(sample_request())
    selected = workflow.claim_next(worker_id="worker", worker_instance_id="one")
    assert selected is not None
    clock[0] -= timedelta(seconds=1)
    with pytest.raises(ResearchClaimLost):
        workflow.heartbeat(selected.claim, progress=ResearchProgress())
    assert workflow.get(selected.request.job_id).updated_at == NOW


@pytest.mark.parametrize("getter", ["get", "get_request", "jobs"])
def test_readers_do_not_acquire_a_write_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, getter: str
) -> None:
    engine, workflow, _ = make_workflow(tmp_path, monkeypatch)
    request = sample_request()
    original = workflow.launch(request)
    pending = sample_request("pending-writer-0001")

    # A pending real launch holds SQLite's reserved writer lock. Committed rows
    # remain readable; BEGIN IMMEDIATE in a getter would instead time out here.
    with engine.connect() as writer, ThreadPoolExecutor(max_workers=1) as pool:
        writer.exec_driver_sql("BEGIN IMMEDIATE")
        workflow.launch_in_transaction(writer, pending)
        try:
            if getter == "get":
                assert pool.submit(workflow.get, request.job_id).result(timeout=3) == original
            elif getter == "get_request":
                assert (
                    pool.submit(workflow.get_request, request.job_id).result(timeout=3) == request
                )
            else:
                assert pool.submit(workflow.jobs, owner_id="owner").result(timeout=3) == (original,)
        except BaseException:
            writer.rollback()
            raise
        writer.commit()
    assert {job.job_id for job in workflow.jobs(owner_id="owner")} == {
        request.job_id,
        pending.job_id,
    }


@pytest.mark.parametrize("getter", ["get", "get_request", "jobs"])
def test_reader_keeps_one_snapshot_when_heartbeat_commits_between_queries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, getter: str
) -> None:
    engine, workflow, clock = make_workflow(tmp_path, monkeypatch)
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA journal_mode=WAL")
    request = sample_request()
    workflow.launch(request)
    claimed = workflow.claim_next(worker_id="worker", worker_instance_id="one")
    assert claimed is not None
    original = workflow.get(request.job_id)
    progress = ResearchProgress("running", 6, 4)
    clock[0] += timedelta(seconds=10)
    advanced = False

    def advance_after_head(_connection, _cursor, statement, _parameters, _context, _executemany):  # type: ignore[no-untyped-def]
        nonlocal advanced
        if not advanced and "FROM research_job_events_v2" in statement:
            advanced = True
            with ThreadPoolExecutor(max_workers=1) as pool:
                control = pool.submit(workflow.heartbeat, claimed.claim, progress=progress).result(
                    timeout=3
                )
                assert control.claim.lease_revision == 1

    sa.event.listen(engine, "before_cursor_execute", advance_after_head)
    try:
        if getter == "get":
            assert workflow.get(request.job_id) == original
        elif getter == "get_request":
            assert workflow.get_request(request.job_id) == request
        else:
            assert workflow.jobs(owner_id="owner") == (original,)
    finally:
        sa.event.remove(engine, "before_cursor_execute", advance_after_head)
    assert advanced
    assert workflow.get(request.job_id).progress == progress


def test_overlapping_polling_allows_durable_heartbeat_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Keep the default rollback journal: polling must cooperate with a writer
    # without requiring a WAL configuration change or a longer lease/timeout.
    _, workflow, clock = make_workflow(tmp_path, monkeypatch)
    request = sample_request()
    workflow.launch(request)
    claimed = workflow.claim_next(worker_id="worker", worker_instance_id="one")
    assert claimed is not None
    barrier = Barrier(3, timeout=5)

    def poll_detail() -> None:
        for _ in range(6):
            barrier.wait()
            assert workflow.get(request.job_id).status == "running"
            assert workflow.get_request(request.job_id) == request
            barrier.wait()

    def poll_list() -> None:
        for _ in range(6):
            barrier.wait()
            assert tuple(job.job_id for job in workflow.jobs(owner_id="owner")) == (request.job_id,)
            barrier.wait()

    def heartbeat() -> None:
        claim = claimed.claim
        for index in range(1, 7):
            clock[0] += timedelta(seconds=10)
            barrier.wait()
            control = workflow.heartbeat(claim, progress=ResearchProgress("running", index, index))
            claim = control.claim
            assert claim.lease_revision == index
            barrier.wait()

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = tuple(pool.submit(call) for call in (poll_detail, poll_list, heartbeat))
        for future in futures:
            future.result(timeout=15)
    final = workflow.get(request.job_id)
    assert final.progress == ResearchProgress("running", 6, 6)
    assert len(final.attempts) == 1
    assert final.attempts[0].outcome == "running"


@pytest.mark.parametrize("getter", ["get", "get_request", "jobs"])
@pytest.mark.parametrize("phase", ["decode_request_row", "replay_job_snapshot"])
def test_blocked_read_decode_and_replay_do_not_block_writer_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, getter: str, phase: str
) -> None:
    _, workflow, clock = make_workflow(tmp_path, monkeypatch)
    request = sample_request()
    workflow.launch(request)
    claimed = workflow.claim_next(worker_id="worker", worker_instance_id="one")
    assert claimed is not None
    original_view = workflow.get(request.job_id)
    entered, release = Event(), Event()
    reader_identity: list[int | None] = [None]
    original = getattr(workflow, phase)

    def blocked(*args: object, **kwargs: object) -> object:
        if get_ident() == reader_identity[0]:
            entered.set()
            assert release.wait(timeout=5)
        return original(*args, **kwargs)

    monkeypatch.setattr(workflow, phase, blocked)

    def read() -> object:
        reader_identity[0] = get_ident()
        if getter == "jobs":
            return workflow.jobs(owner_id="owner")
        return getattr(workflow, getter)(request.job_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        reader = pool.submit(read)
        try:
            assert entered.wait(timeout=3)
            clock[0] += timedelta(seconds=10)
            control = pool.submit(
                workflow.heartbeat, claimed.claim, progress=ResearchProgress("running", 6, 4)
            ).result(timeout=2)
            assert control.claim.lease_revision == 1
            assert not reader.done()
        finally:
            release.set()
        result = reader.result(timeout=3)
    monkeypatch.setattr(workflow, phase, original)
    current = workflow.get(request.job_id)
    assert current.progress == ResearchProgress("running", 6, 4)
    expected = original_view if phase == "replay_job_snapshot" else current
    if getter == "get_request":
        assert result == request
    elif getter == "jobs":
        assert result == (expected,)
    else:
        assert result == expected


def test_second_phase_rejects_changed_immutable_request_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, workflow, _ = make_workflow(tmp_path, monkeypatch)
    request = sample_request()
    workflow.launch(request)
    original = workflow.decode_request_row

    def change_after_discovery(row):  # type: ignore[no-untyped-def]
        discovered = original(row)
        changed = replace(request, trial_id="changed-trial")
        with engine.begin() as connection:
            connection.execute(
                sa.update(research_jobs_v2).values(
                    trial_id=changed.trial_id,
                    request_sha256=changed.semantic_sha256,
                    request_payload=personal_codec.encode_record(changed),
                )
            )
        return discovered

    monkeypatch.setattr(workflow, "decode_request_row", change_after_discovery)
    with pytest.raises(ResearchJobConflict, match="immutable request changed"):
        workflow.get(request.job_id)


def test_second_phase_verifies_current_object_metadata_without_cached_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, workflow, _ = make_workflow(tmp_path, monkeypatch)
    request = sample_request()
    accepted = workflow.launch(request)
    assert workflow.get(request.job_id) == accepted
    original = workflow.decode_request_row

    def corrupt_after_discovery(row):  # type: ignore[no-untyped-def]
        discovered = original(row)
        with engine.begin() as connection:
            connection.execute(
                sa.update(research_objects_v2).values(byte_count=request.inputs.byte_count + 1)
            )
        return discovered

    monkeypatch.setattr(workflow, "decode_request_row", corrupt_after_discovery)
    with pytest.raises(ImmutableFactConflict, match="byte_count"):
        workflow.get(request.job_id)


def test_detached_snapshot_rejects_corrupted_head_and_publication_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, workflow, _ = make_workflow(tmp_path, monkeypatch)
    request = sample_request()
    workflow.launch(request)
    claimed = workflow.claim_next(worker_id="worker", worker_instance_id="one")
    assert claimed is not None
    with engine.connect() as connection:
        state = workflow._load(connection, request.job_id)
    published = workflow.publish(claimed.claim, publication=publication(state))
    with _repeatable_read_transaction(engine) as connection:
        row = workflow.request_row(connection, request.job_id)
    discovered = workflow.decode_request_row(row)
    with _repeatable_read_transaction(engine) as connection:
        snapshot = workflow.read_job_snapshot(connection, discovered)
    assert workflow.replay_job_snapshot(snapshot).view == published
    with pytest.raises(TypeError):
        snapshot.head["status"] = "failed"  # type: ignore[index]
    with pytest.raises(ImmutableFactConflict, match="status"):
        workflow.replay_job_snapshot(replace(snapshot, head={**snapshot.head, "status": "failed"}))
    assert published.publication is not None
    object_id = published.publication.object.object_sha256
    with engine.begin() as connection:
        connection.execute(
            sa.update(research_objects_v2)
            .where(research_objects_v2.c.object_sha256 == object_id)
            .values(byte_count=11)
        )
    # Detached proof remains its original snapshot; a fresh read must see corruption.
    assert workflow.replay_job_snapshot(snapshot).view == published
    with pytest.raises(ImmutableFactConflict, match="byte_count"):
        workflow.get(request.job_id)


def test_maximal_lifecycle_event_fields_fit_the_snapshot_byte_bound() -> None:
    # Reducer claims start at revision zero and each renewal appends one event
    # and adds exactly one. Thus every valid <=4096-event history has revision
    # <=4096; arbitrary larger syntactic claim values are not valid histories.
    # ASCII identifiers, fixed digests, UTC datetime encodings, bounded counters,
    # and the longest literal values maximize the remaining variable fields.
    # Include every optional field together for a conservative encoding superset.
    digest, identifier = "f" * 64, "z" * 128
    now = datetime(9999, 12, 31, 23, 59, 59, 999998, tzinfo=UTC)
    claim = ResearchClaim(
        digest,
        content_digest(("personal-research-job/2", "attempt", digest, MAX_ATTEMPTS, identifier)),
        MAX_ATTEMPTS,
        MAX_JOB_EVENTS,
        identifier,
        identifier,
        now,
        now + timedelta(microseconds=1),
    )
    event = ResearchJobEvent(
        digest,
        MAX_JOB_EVENTS - 1,
        digest,
        "cancel_requested",
        now,
        identifier,
        claim,
        ResearchPublication(
            digest,
            "run-" + digest,
            digest,
            "incomplete",
            digest,
            digest,
            digest,
            ObjectRef(digest, MAX_OBJECT_BYTES),
        ),
        identifier,
        digest,
        ResearchProgress("publishing", 1_000_000, 1_000_000, now),
    )
    encoded = personal_codec.encode_record(event)
    assert personal_codec.decode_record(encoded, ResearchJobEvent) == event
    assert len(encoded) < 8192
    assert len(encoded) * MAX_JOB_EVENTS < MAX_INPUT_BYTES


@pytest.mark.parametrize("count", [1, 36, 100])
def test_job_page_uses_constant_query_count_inside_its_admitted_page_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, count: int
) -> None:
    engine, workflow, _ = make_workflow(tmp_path, monkeypatch)
    requests = tuple(sample_request(f"batch-query-{index:04d}") for index in range(count))
    with engine.begin() as connection:
        for request in requests:
            workflow.launch_in_transaction(connection, request)
    queries: list[str] = []

    def record(_connection, _cursor, statement, _parameters, _context, _executemany):  # type: ignore[no-untyped-def]
        if statement.lstrip().upper().startswith("SELECT"):
            queries.append(statement)

    sa.event.listen(engine, "before_cursor_execute", record)
    try:
        observed = workflow.jobs(owner_id="owner")
    finally:
        sa.event.remove(engine, "before_cursor_execute", record)
    assert {job.job_id for job in observed} == {request.job_id for request in requests}
    assert len(queries) == 8


def test_bulk_snapshot_chunks_preserve_order_and_every_job_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, workflow, _ = make_workflow(tmp_path, monkeypatch)
    requests = tuple(sample_request(f"batch-boundary-{index:04d}") for index in range(129))
    with engine.begin() as connection:
        for request in requests:
            workflow.launch_in_transaction(connection, request)
    identifiers = tuple(request.job_id for request in reversed(requests))
    queries: list[str] = []

    def record(_connection, _cursor, statement, _parameters, _context, _executemany):  # type: ignore[no-untyped-def]
        if statement.lstrip().upper().startswith("SELECT"):
            queries.append(statement)

    sa.event.listen(engine, "before_cursor_execute", record)
    try:
        with _repeatable_read_transaction(engine) as connection:
            rows = workflow.request_rows(connection, identifiers)
        discovered = tuple(workflow.decode_request_row(row) for row in rows)
        with _repeatable_read_transaction(engine) as connection:
            snapshots = workflow.read_job_snapshots(connection, discovered)
        states = tuple(workflow.replay_job_snapshot(snapshot) for snapshot in snapshots)
    finally:
        sa.event.remove(engine, "before_cursor_execute", record)
    assert tuple(state.request for state in states) == tuple(reversed(requests))
    assert tuple(snapshot.head["job_id"] for snapshot in snapshots) == identifiers
    assert len(queries) == 12
