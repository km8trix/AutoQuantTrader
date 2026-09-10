"""Transactional W3 jobs; immutable payloads back every query and mutable head."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Literal, TypeVar

import sqlalchemy as sa
from sqlalchemy import Connection, Engine
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from packages.domain.personal_contracts import require_digest, require_utc
from packages.domain.research_job_contracts import (
    MAX_INPUT_BYTES,
    MAX_JOB_EVENTS,
    ClaimControl,
    ClaimedResearchJob,
    ObjectRef,
    ResearchClaim,
    ResearchJobEvent,
    ResearchJobView,
    ResearchProgress,
    ResearchPublication,
    ResearchRecordCodec,
    ResearchRunRequest,
    require_identifier,
)
from packages.domain.research_job_v2 import (
    ResearchJobConflict,
    ResearchJobState,
    cancel_research_job,
    claim_research_job,
    finish_research_attempt,
    publish_research_attempt,
    queue_research_job,
    recover_research_job,
    reduce_research_job,
    renew_research_claim,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import assert_immutable, insert_or_verify_atomic
from packages.persistence.research_schema_v2 import (
    research_job_events_v2 as events_table,
)
from packages.persistence.research_schema_v2 import (
    research_job_heads_v2 as heads,
)
from packages.persistence.research_schema_v2 import (
    research_jobs_v2 as jobs_table,
)
from packages.persistence.research_schema_v2 import (
    research_objects_v2 as objects,
)
from packages.persistence.research_schema_v2 import (
    research_publications_v2 as publications,
)

T = TypeVar("T")
_READ_BATCH_SIZE = 128


@dataclass(frozen=True)
class ResearchRequestRead:
    row: Mapping[str, Any]
    request: ResearchRunRequest


@dataclass(frozen=True)
class ResearchJobSnapshot:
    discovered: ResearchRequestRead
    head: Mapping[str, Any]
    events: tuple[Mapping[str, Any], ...]
    publication: Mapping[str, Any] | None
    objects: tuple[Mapping[str, Any], ...]


def database_time(connection: Connection) -> datetime:
    """Sample database authority after locking, never a client-supplied clock."""
    if connection.dialect.name == "postgresql":
        value = connection.execute(sa.select(sa.func.clock_timestamp())).scalar_one()
        if not isinstance(value, datetime):
            raise ResearchJobConflict("database time is unavailable")
        result = value.astimezone(UTC)
    elif connection.dialect.name == "sqlite":
        value = connection.exec_driver_sql(
            "SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')"
        ).scalar_one()
        result = datetime.fromisoformat(value)
    else:
        raise ResearchJobConflict("unsupported research SQL dialect")
    require_utc(result, "database time")
    return result


@contextmanager
def _write(engine: Engine) -> Iterator[Connection]:
    with engine.connect() as connection:
        if connection.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        elif connection.dialect.name == "postgresql":
            with connection.begin():
                yield connection
        else:
            raise ResearchJobConflict("unsupported research SQL dialect")


class SqlResearchWorkflow:
    """One transaction per command; no subprocess or filesystem I/O inside it."""

    def __init__(self, engine: Engine, *, codec: ResearchRecordCodec) -> None:
        self._engine = engine
        self._codec = codec

    def _encode(self, value: object) -> bytes:
        payload = self._codec.encode_record(value)
        if type(payload) is not bytes or not 0 < len(payload) <= MAX_INPUT_BYTES:
            raise ResearchJobConflict("research metadata exceeds its byte bound")
        return payload

    def _decode(self, payload: object, expected: type[T]) -> T:
        if type(payload) is not bytes or not 0 < len(payload) <= MAX_INPUT_BYTES:
            raise ResearchJobConflict("persisted research metadata is malformed")
        value = self._codec.decode_record(payload, expected)
        if type(value) is not expected or self._encode(value) != payload:
            raise ResearchJobConflict("persisted research metadata is not canonical")
        return value

    def _object(self, connection: Connection, reference: ObjectRef) -> None:
        insert_or_verify_atomic(
            connection,
            objects,
            {
                "object_sha256": reference.object_sha256,
                "byte_count": reference.byte_count,
                "codec_version": reference.codec_version,
            },
        )

    def _job_values(self, request: ResearchRunRequest, now: datetime) -> dict[str, Any]:
        return {
            "job_id": request.job_id,
            "run_id": request.run_id,
            "owner_id": request.owner_id,
            "idempotency_key": request.idempotency_key,
            "trial_id": request.trial_id,
            "request_sha256": request.semantic_sha256,
            "request_payload": self._encode(request),
            "requested_at": now,
        }

    def _event_values(self, event: ResearchJobEvent) -> dict[str, Any]:
        return {
            "job_id": event.job_id,
            "sequence": event.sequence,
            "event_sha256": event.semantic_sha256,
            "previous_event_sha256": event.previous_event_sha256,
            "kind": event.kind,
            "occurred_at": event.occurred_at,
            "command_id": event.command_id,
            "payload": self._encode(event),
        }

    @staticmethod
    def _head_values(state: ResearchJobState) -> dict[str, Any]:
        return {
            "job_id": state.request.job_id,
            "last_sequence": len(state.events) - 1,
            "last_event_sha256": state.view.last_event_sha256,
            "status": state.view.status,
            "attempt_count": len(state.view.attempts),
            "lease_expires_at": None if state.claim is None else state.claim.lease_expires_at,
            "cancel_requested": state.view.cancel_requested,
            "updated_at": state.view.updated_at,
        }

    def _publication_values(
        self, publication: ResearchPublication, now: datetime
    ) -> dict[str, Any]:
        return {
            "job_id": publication.job_id,
            "run_id": publication.run_id,
            "attempt_id": publication.attempt_id,
            "outcome": publication.outcome,
            "result_sha256": publication.result_sha256,
            "report_sha256": publication.report_sha256,
            "artifact_sha256": publication.artifact_sha256,
            "object_sha256": publication.object.object_sha256,
            "publication_sha256": publication.semantic_sha256,
            "payload": self._encode(publication),
            "published_at": now,
        }

    def request_rows(
        self, connection: Connection, job_ids: tuple[str, ...]
    ) -> tuple[Mapping[str, Any], ...]:
        """Materialize a caller-bounded selection in bounded SQL batches."""
        for job_id in job_ids:
            require_digest(job_id, "job identifier")
        if len(set(job_ids)) != len(job_ids):
            raise ResearchJobConflict("request selection contains duplicate jobs")
        result: list[Mapping[str, Any]] = []
        for offset in range(0, len(job_ids), _READ_BATCH_SIZE):
            selected = job_ids[offset : offset + _READ_BATCH_SIZE]
            rows = {
                row["job_id"]: MappingProxyType(dict(row))
                for row in connection.execute(
                    sa.select(jobs_table).where(jobs_table.c.job_id.in_(selected))
                ).mappings()
            }
            if set(rows) != set(selected):
                raise ResearchJobConflict("research job does not exist")
            result.extend(rows[job_id] for job_id in selected)
        return tuple(result)

    def request_row(self, connection: Connection, job_id: str) -> Mapping[str, Any]:
        """Copy immutable request bytes without constructing their typed value."""
        return self.request_rows(connection, (job_id,))[0]

    def decode_request_row(self, row: Mapping[str, Any]) -> ResearchRequestRead:
        """Discover exact retained references outside a read transaction."""
        request = self._decode(row["request_payload"], ResearchRunRequest)
        expected = self._job_values(request, row["requested_at"])
        # The authoritative requested time comes from replay's first event.
        del expected["requested_at"]
        assert_immutable(jobs_table, request.job_id, row, expected)
        return ResearchRequestRead(MappingProxyType(dict(row)), request)

    def read_job_snapshots(
        self, connection: Connection, discovered: tuple[ResearchRequestRead, ...]
    ) -> tuple[ResearchJobSnapshot, ...]:
        """Copy coherent current rows in bounded batches, without typed replay."""
        job_ids = tuple(item.request.job_id for item in discovered)
        if len(set(job_ids)) != len(job_ids):
            raise ResearchJobConflict("snapshot selection contains duplicate jobs")
        result: list[ResearchJobSnapshot] = []
        for offset in range(0, len(discovered), _READ_BATCH_SIZE):
            batch = discovered[offset : offset + _READ_BATCH_SIZE]
            identifiers = tuple(item.request.job_id for item in batch)
            current_heads = {
                row["job_id"]: MappingProxyType(dict(row))
                for row in connection.execute(
                    sa.select(heads).where(heads.c.job_id.in_(identifiers))
                ).mappings()
            }
            current_requests = self.request_rows(connection, identifiers)
            for original, current in zip(batch, current_requests, strict=True):
                if current != original.row:
                    raise ResearchJobConflict("immutable request changed during read")
            if set(current_heads) != set(identifiers):
                raise ResearchJobConflict("research job does not exist")
            ranked = (
                sa.select(
                    *events_table.c,
                    sa.func.row_number()
                    .over(partition_by=events_table.c.job_id, order_by=events_table.c.sequence)
                    .label("snapshot_rank"),
                )
                .where(events_table.c.job_id.in_(identifiers))
                .subquery()
            )
            event_rows: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
            event_bytes: dict[str, int] = defaultdict(int)
            for event in connection.execute(
                sa.select(*(ranked.c[column.name] for column in events_table.c))
                .where(ranked.c.snapshot_rank <= MAX_JOB_EVENTS + 1)
                .order_by(ranked.c.job_id, ranked.c.sequence)
            ).mappings():
                if type(event["payload"]) is not bytes:
                    raise ResearchJobConflict("persisted event snapshot exceeds its byte bound")
                event_bytes[event["job_id"]] += len(event["payload"])
                if event_bytes[event["job_id"]] > MAX_INPUT_BYTES:
                    raise ResearchJobConflict("persisted event snapshot exceeds its byte bound")
                event_rows[event["job_id"]].append(MappingProxyType(dict(event)))
            if any(not 0 < len(event_rows[job_id]) <= MAX_JOB_EVENTS for job_id in identifiers):
                raise ResearchJobConflict("persisted event count is invalid")
            publication_rows = {
                row["job_id"]: MappingProxyType(dict(row))
                for row in connection.execute(
                    sa.select(publications).where(publications.c.job_id.in_(identifiers))
                ).mappings()
            }
            references: dict[str, set[str]] = {}
            for item in batch:
                request = item.request
                references[request.job_id] = {
                    reference.object_sha256
                    for reference in (
                        request.inputs,
                        request.dataset_archive,
                        request.settlement_calendar,
                    )
                    if reference is not None
                }
                publication = publication_rows.get(request.job_id)
                if publication is not None:
                    references[request.job_id].add(publication["object_sha256"])
            object_ids = set().union(*references.values())
            object_rows = {
                row["object_sha256"]: MappingProxyType(dict(row))
                for row in connection.execute(
                    sa.select(objects).where(objects.c.object_sha256.in_(sorted(object_ids)))
                ).mappings()
            }
            for item in batch:
                job_id = item.request.job_id
                result.append(
                    ResearchJobSnapshot(
                        item,
                        current_heads[job_id],
                        tuple(event_rows[job_id]),
                        publication_rows.get(job_id),
                        tuple(
                            object_rows[key]
                            for key in sorted(references[job_id])
                            if key in object_rows
                        ),
                    )
                )
        return tuple(result)

    def read_job_snapshot(
        self, connection: Connection, discovered: ResearchRequestRead
    ) -> ResearchJobSnapshot:
        """Copy one coherent raw snapshot; no codec or reducer runs here."""
        return self.read_job_snapshots(connection, (discovered,))[0]

    def _capture_job_snapshot(
        self,
        connection: Connection,
        discovered: ResearchRequestRead,
        head: Mapping[str, Any],
    ) -> ResearchJobSnapshot:
        request = discovered.request
        row = self.request_row(connection, request.job_id)
        if row != discovered.row:
            raise ResearchJobConflict("immutable request changed during read")
        rows = tuple(
            MappingProxyType(dict(event))
            for event in connection.execute(
                sa.select(events_table)
                .where(events_table.c.job_id == request.job_id)
                .order_by(events_table.c.sequence)
                .limit(MAX_JOB_EVENTS + 1)
            ).mappings()
        )
        if not 0 < len(rows) <= MAX_JOB_EVENTS:
            raise ResearchJobConflict("persisted event count is invalid")
        # A maximal-field valid lifecycle event is 2520 canonical bytes; the
        # <=4096-event proof/test keeps supported histories below this 32 MiB cap.
        if (
            any(type(event["payload"]) is not bytes for event in rows)
            or sum(len(event["payload"]) for event in rows) > MAX_INPUT_BYTES
        ):
            raise ResearchJobConflict("persisted event snapshot exceeds its byte bound")
        publication = (
            connection.execute(
                sa.select(publications).where(publications.c.job_id == request.job_id)
            )
            .mappings()
            .one_or_none()
        )
        identifiers = {
            reference.object_sha256
            for reference in (request.inputs, request.dataset_archive, request.settlement_calendar)
            if reference is not None
        }
        if publication is not None:
            identifiers.add(publication["object_sha256"])
        object_rows = tuple(
            MappingProxyType(dict(item))
            for item in connection.execute(
                sa.select(objects)
                .where(objects.c.object_sha256.in_(sorted(identifiers)))
                .order_by(objects.c.object_sha256)
            ).mappings()
        )
        return ResearchJobSnapshot(
            discovered,
            MappingProxyType(dict(head)),
            rows,
            None if publication is None else MappingProxyType(dict(publication)),
            object_rows,
        )

    def replay_job_snapshot(self, snapshot: ResearchJobSnapshot) -> ResearchJobState:
        """Validate copied current rows without database I/O or cached authority."""
        if not 0 < len(snapshot.events) <= MAX_JOB_EVENTS:
            raise ResearchJobConflict("persisted event count is invalid")
        if (
            any(type(event["payload"]) is not bytes for event in snapshot.events)
            or sum(len(event["payload"]) for event in snapshot.events) > MAX_INPUT_BYTES
        ):
            raise ResearchJobConflict("persisted event snapshot exceeds its byte bound")
        request = snapshot.discovered.request
        row = snapshot.discovered.row
        job_id = request.job_id
        events = tuple(
            self._decode(event["payload"], ResearchJobEvent) for event in snapshot.events
        )
        state = reduce_research_job(request, events)
        assert_immutable(
            jobs_table, job_id, row, self._job_values(request, state.view.requested_at)
        )
        for persisted, event in zip(snapshot.events, events, strict=True):
            assert_immutable(
                events_table, event.semantic_sha256, persisted, self._event_values(event)
            )
        assert_immutable(heads, job_id, snapshot.head, self._head_values(state))

        def verify_reference(reference: ObjectRef) -> None:
            selected = tuple(
                item
                for item in snapshot.objects
                if item["object_sha256"] == reference.object_sha256
            )
            if len(selected) != 1:
                raise ResearchJobConflict("retained object metadata is missing")
            assert_immutable(
                objects,
                reference.object_sha256,
                selected[0],
                {
                    "object_sha256": reference.object_sha256,
                    "byte_count": reference.byte_count,
                    "codec_version": reference.codec_version,
                },
            )

        for reference in (request.inputs, request.dataset_archive, request.settlement_calendar):
            if reference is not None:
                verify_reference(reference)
        publication_row = snapshot.publication
        if (publication_row is None) != (state.view.publication is None):
            raise ResearchJobConflict("publication and terminal lifecycle disagree")
        if publication_row is not None and state.view.publication is not None:
            publication = self._decode(publication_row["payload"], ResearchPublication)
            if publication != state.view.publication:
                raise ResearchJobConflict("publication differs from its terminal event")
            assert_immutable(
                publications,
                job_id,
                publication_row,
                self._publication_values(publication, state.view.updated_at),
            )
            verify_reference(publication.object)
        return state

    def _load(
        self, connection: Connection, job_id: str, *, locked: bool = False
    ) -> ResearchJobState:
        # Mutations still acquire the head lock before decoding/capturing, and
        # replay all validations inside their existing fenced write transaction.
        require_digest(job_id, "job identifier")
        statement = sa.select(heads).where(heads.c.job_id == job_id)
        if locked and connection.dialect.name == "postgresql":
            statement = statement.with_for_update()
        head = connection.execute(statement).mappings().one_or_none()
        if head is None:
            raise ResearchJobConflict("research job does not exist")
        discovered = self.decode_request_row(self.request_row(connection, job_id))
        return self.replay_job_snapshot(
            self._capture_job_snapshot(connection, discovered, dict(head))
        )

    def _advance(
        self, connection: Connection, prior: ResearchJobState, updated: ResearchJobState
    ) -> None:
        if prior == updated:
            return
        if updated.events[: len(prior.events)] != prior.events:
            raise ResearchJobConflict("transition did not append immutable history")
        for event in updated.events[len(prior.events) :]:
            insert_or_verify_atomic(connection, events_table, self._event_values(event))
        values = self._head_values(updated)
        result = connection.execute(
            sa.update(heads)
            .where(
                heads.c.job_id == prior.request.job_id,
                heads.c.last_sequence == len(prior.events) - 1,
                heads.c.last_event_sha256 == prior.view.last_event_sha256,
            )
            .values(**{key: value for key, value in values.items() if key != "job_id"})
        )
        if result.rowcount != 1:
            raise ResearchJobConflict("research job head changed concurrently")

    def launch(self, request: ResearchRunRequest) -> ResearchJobView:
        with _write(self._engine) as connection:
            return self.launch_in_transaction(connection, request)

    def launch_in_transaction(
        self, connection: Connection, request: ResearchRunRequest
    ) -> ResearchJobView:
        """Join an existing catalog/trial transaction without committing any part."""
        if (
            connection.engine is not self._engine
            or connection.closed
            or not connection.in_transaction()
            or connection.dialect.name not in ("sqlite", "postgresql")
        ):
            raise ResearchJobConflict("launch requires an active transaction on the bound engine")
        if type(request) is not ResearchRunRequest:
            raise ResearchJobConflict("launch requires an immutable typed request")
        now = database_time(connection)
        insert = sqlite_insert if connection.dialect.name == "sqlite" else pg_insert
        inserted = connection.execute(
            insert(jobs_table).values(**self._job_values(request, now)).on_conflict_do_nothing()
        ).rowcount
        if inserted == 0:
            state = self._load(connection, request.job_id, locked=True)
            if state.request != request:
                raise ResearchJobConflict("launch idempotency key conflicts with immutable request")
            return state.view
        for reference in (request.inputs, request.dataset_archive, request.settlement_calendar):
            if reference is not None:
                self._object(connection, reference)
        state = queue_research_job(request, now)
        insert_or_verify_atomic(connection, events_table, self._event_values(state.events[0]))
        insert_or_verify_atomic(connection, heads, self._head_values(state))
        return state.view

    def _read(self, job_id: str) -> ResearchJobState:
        with _repeatable_read_transaction(self._engine) as connection:
            row = self.request_row(connection, job_id)
        discovered = self.decode_request_row(row)
        with _repeatable_read_transaction(self._engine) as connection:
            snapshot = self.read_job_snapshot(connection, discovered)
        return self.replay_job_snapshot(snapshot)

    def get(self, job_id: str) -> ResearchJobView:
        return self._read(job_id).view

    def get_request(self, job_id: str) -> ResearchRunRequest:
        return self._read(job_id).request

    def jobs(self, *, owner_id: str, limit: int = 100) -> tuple[ResearchJobView, ...]:
        require_identifier(owner_id, "owner identity")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ResearchJobConflict("job list limit must be between one and 100")
        selected = (
            sa.select(jobs_table.c.job_id)
            .where(jobs_table.c.owner_id == owner_id)
            .order_by(jobs_table.c.requested_at.desc(), jobs_table.c.job_id)
            .limit(limit)
        )
        with _repeatable_read_transaction(self._engine) as connection:
            identifiers = tuple(connection.execute(selected).scalars())
            rows = self.request_rows(connection, identifiers)
        discovered = tuple(self.decode_request_row(row) for row in rows)
        with _repeatable_read_transaction(self._engine) as connection:
            if tuple(connection.execute(selected).scalars()) != identifiers:
                raise ResearchJobConflict("job page membership changed during read")
            snapshots = self.read_job_snapshots(connection, discovered)
        return tuple(self.replay_job_snapshot(snapshot).view for snapshot in snapshots)

    def request_cancel(
        self, job_id: str, *, owner_id: str, idempotency_key: str
    ) -> ResearchJobView:
        with _write(self._engine) as connection:
            prior = self._load(connection, job_id, locked=True)
            updated = cancel_research_job(
                prior,
                owner_id=owner_id,
                idempotency_key=idempotency_key,
                now=database_time(connection),
            )
            self._advance(connection, prior, updated)
            return updated.view

    def claim_next(self, *, worker_id: str, worker_instance_id: str) -> ClaimedResearchJob | None:
        require_identifier(worker_id, "worker identity")
        require_identifier(worker_instance_id, "worker process identity")
        with _write(self._engine) as connection:
            # The SQL prefilter is conservative. Authority is resampled after the row lock.
            observed = database_time(connection)
            statement = (
                sa.select(heads.c.job_id)
                .join(jobs_table, jobs_table.c.job_id == heads.c.job_id)
                .where(
                    sa.or_(
                        heads.c.status == "queued",
                        sa.and_(heads.c.status == "running", heads.c.lease_expires_at <= observed),
                    )
                )
                .order_by(jobs_table.c.requested_at, heads.c.job_id)
                .limit(100)
            )
            if connection.dialect.name == "postgresql":
                statement = statement.with_for_update(of=heads, skip_locked=True)
            for job_id in tuple(connection.execute(statement).scalars()):
                prior = self._load(connection, job_id, locked=True)
                now = database_time(connection)
                recovered = recover_research_job(prior, now)
                if recovered.view.status != "queued":
                    self._advance(connection, prior, recovered)
                    continue
                updated = claim_research_job(
                    recovered, worker_id=worker_id, worker_instance_id=worker_instance_id, now=now
                )
                self._advance(connection, prior, updated)
                assert updated.claim is not None
                return ClaimedResearchJob(updated.request, updated.claim)
            return None

    def heartbeat(self, claim: ResearchClaim, *, progress: ResearchProgress) -> ClaimControl:
        with _write(self._engine) as connection:
            prior = self._load(connection, claim.job_id, locked=True)
            updated, control = renew_research_claim(
                prior, claim, progress=progress, now=database_time(connection)
            )
            self._advance(connection, prior, updated)
            return control

    def publish(self, claim: ResearchClaim, *, publication: ResearchPublication) -> ResearchJobView:
        with _write(self._engine) as connection:
            prior = self._load(connection, claim.job_id, locked=True)
            now = database_time(connection)
            updated = publish_research_attempt(prior, claim, publication, now)
            if updated == prior:
                return prior.view
            self._object(connection, publication.object)
            insert_or_verify_atomic(
                connection, publications, self._publication_values(publication, now)
            )
            self._advance(connection, prior, updated)
            return updated.view

    def finish(
        self,
        claim: ResearchClaim,
        *,
        outcome: Literal["failed", "cancelled", "abandoned"],
        reason_code: str,
    ) -> ResearchJobView:
        with _write(self._engine) as connection:
            prior = self._load(connection, claim.job_id, locked=True)
            # Identical lost-ack retry returns the retained terminal/abandonment event.
            last = prior.events[-1]
            if last.kind == outcome and last.claim == claim and last.reason_code == reason_code:
                return prior.view
            updated = finish_research_attempt(
                prior,
                claim,
                outcome=outcome,
                reason_code=reason_code,
                now=database_time(connection),
            )
            self._advance(connection, prior, updated)
            return updated.view
