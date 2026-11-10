"""Transactional immutable research selection and complete trial registration."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

import sqlalchemy as sa
from sqlalchemy.engine import Connection, Engine

from packages.domain.personal_contracts import content_digest
from packages.domain.personal_evaluation import COST_SCENARIOS
from packages.domain.research_catalog import ResearchCatalogEntry
from packages.domain.research_job_contracts import (
    MAX_INPUT_BYTES,
    ResearchRecordCodec,
    ResearchRunRequest,
    require_identifier,
)
from packages.domain.research_registration import ResearchExperimentRegistration
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.research_catalog_schema import (
    research_catalog_entries as entries,
)
from packages.persistence.research_catalog_schema import (
    research_experiments as experiments,
)
from packages.persistence.research_catalog_schema import (
    research_launch_intents as launches,
)
from packages.persistence.research_catalog_schema import (
    research_trial_jobs as trial_jobs,
)
from packages.persistence.research_workflow_v2 import SqlResearchWorkflow, database_time


class ResearchCatalogConflict(ValueError):
    """Same public intent key names different immutable intent."""


class ResearchCatalogMissing(ValueError):
    """Selected public record is absent from the owner's registry."""


@dataclass(frozen=True)
class ResearchCatalogRows:
    """Copied SQL bytes and scalar columns; no decoded domain records."""

    entries: tuple[Mapping[str, Any], ...]
    launches: tuple[Mapping[str, Any], ...]
    experiments: tuple[Mapping[str, Any], ...]
    links: tuple[Mapping[str, Any], ...]


def _rows(connection: Connection, statement: sa.Select[Any]) -> tuple[Mapping[str, Any], ...]:
    return tuple(MappingProxyType(dict(row)) for row in connection.execute(statement).mappings())


@contextmanager
def catalog_transaction(engine: Engine) -> Iterator[Connection]:
    if engine.dialect.name not in ("sqlite", "postgresql"):
        raise ValueError("unsupported research database")
    with engine.connect() as connection:
        try:
            if engine.dialect.name == "sqlite":
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            else:
                connection.begin()
                connection.exec_driver_sql("SET LOCAL lock_timeout = '5s'")
                connection.exec_driver_sql("SET LOCAL statement_timeout = '10s'")
                connection.execute(sa.text("SELECT pg_advisory_xact_lock(1736419023)"))
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise


class SqlResearchCatalog:
    def __init__(
        self, engine: Engine, *, codec: ResearchRecordCodec, workflow: SqlResearchWorkflow
    ) -> None:
        self.engine, self.codec, self.workflow = engine, codec, workflow

    def _payload(self, value: object) -> dict[str, Any]:
        payload = self.codec.encode_record(value)
        if len(payload) > 4 * 1024 * 1024:
            raise ValueError("research registration exceeds SQL envelope")
        return {"payload": payload, "payload_sha256": hashlib.sha256(payload).hexdigest()}

    def _decode[T](self, row: Mapping[Any, Any], expected: type[T]) -> T:
        payload = row["payload"]
        if (
            type(payload) is not bytes
            or len(payload) > 4 * 1024 * 1024
            or hashlib.sha256(payload).hexdigest() != row["payload_sha256"]
        ):
            raise ValueError("research registration bytes differ")
        value = self.codec.decode_record(payload, expected)
        if self.codec.encode_record(value) != payload:
            raise ValueError("research registration encoding differs")
        return value

    def register(self, entry: ResearchCatalogEntry, *, owner_id: str) -> ResearchCatalogEntry:
        require_identifier(owner_id, "catalog owner")
        with catalog_transaction(self.engine) as connection:
            existing = (
                connection.execute(
                    sa.select(entries).where(entries.c.catalog_id == entry.catalog_id)
                )
                .mappings()
                .first()
            )
            if existing is not None:
                if existing["owner_id"] != owner_id or self._entry(existing) != entry:
                    raise ResearchCatalogConflict("catalog identity differs")
                return entry
            connection.execute(
                entries.insert().values(
                    catalog_id=entry.catalog_id,
                    owner_id=owner_id,
                    entry_sha256=entry.semantic_sha256,
                    owner_binding_sha256=content_digest(
                        ("catalog-owner/1", owner_id, entry.semantic_sha256)
                    ),
                    registered_at=database_time(connection),
                    **self._payload(entry),
                )
            )
        return entry

    def _entry(self, row: Mapping[Any, Any]) -> ResearchCatalogEntry:
        entry = self._decode(row, ResearchCatalogEntry)
        require_identifier(row["owner_id"], "catalog owner")
        if (
            entry.catalog_id != row["catalog_id"]
            or entry.semantic_sha256 != row["entry_sha256"]
            or row["owner_binding_sha256"]
            != content_digest(("catalog-owner/1", row["owner_id"], entry.semantic_sha256))
        ):
            raise ValueError("catalog semantic binding differs")
        return entry

    def _selected(
        self, connection: Connection, catalog_id: str, owner_id: str
    ) -> ResearchCatalogEntry:
        row = (
            connection.execute(sa.select(entries).where(entries.c.catalog_id == catalog_id))
            .mappings()
            .one_or_none()
        )
        if row is None or row["owner_id"] != owner_id:
            raise ResearchCatalogMissing("owner catalog selection absent")
        return self._entry(row)

    @staticmethod
    def _request_binding(
        entry: ResearchCatalogEntry, request: ResearchRunRequest, cost_id: str
    ) -> None:
        spec = request.spec
        cost = next((cost for cost in COST_SCENARIOS if cost.scenario_id == cost_id), None)
        if (
            cost is None
            or spec.dataset_id != entry.dataset_id
            or spec.dataset_sha256 != entry.dataset_sha256
            or spec.data_class != entry.data_class
            or spec.availability_mode != entry.availability_mode
            or spec.instruments != entry.instruments
            or content_digest(spec.calendar) != entry.calendar_sha256
            or content_digest(spec.execution_policy.settlement_calendar)
            != entry.settlement_calendar_sha256
            or request.dataset_archive != entry.archive
            or request.settlement_calendar != entry.settlement_calendar
            or spec.execution_policy.slippage_bps != cost.slippage_bps
            or spec.execution_policy.fee_per_share != cost.fee_per_share
        ):
            raise ValueError("job data, retained references or costs differ from catalog selection")

    def _launch(
        self, connection: Connection, row: sa.RowMapping, *, locked: bool = False
    ) -> ResearchRunRequest:
        self._intent(row, row["request_json"])
        request = self.workflow._load(connection, str(row["job_id"]), locked=locked).request
        if (request.owner_id, request.idempotency_key) != (row["owner_id"], row["idempotency_key"]):
            raise ValueError("launch intent differs from linked job")
        self._request_binding(
            self._selected(connection, row["catalog_id"], request.owner_id),
            request,
            row["cost_scenario_id"],
        )
        return request

    def get(self, catalog_id: str, *, owner_id: str) -> ResearchCatalogEntry:
        with _repeatable_read_transaction(self.engine) as connection:
            rows = _rows(
                connection,
                sa.select(entries).where(
                    entries.c.catalog_id == catalog_id, entries.c.owner_id == owner_id
                ),
            )
        if not rows:
            raise ResearchCatalogMissing("catalog selection absent")
        return self._entry(rows[0])

    def datasets(self, *, owner_id: str, limit: int = 200) -> tuple[ResearchCatalogEntry, ...]:
        if not 1 <= limit <= 200:
            raise ValueError("catalog page exceeds its bound")
        with _repeatable_read_transaction(self.engine) as connection:
            rows = _rows(
                connection,
                sa.select(entries)
                .where(entries.c.owner_id == owner_id)
                .order_by(entries.c.catalog_id)
                .limit(limit),
            )
        return tuple(self._entry(row) for row in rows)

    @staticmethod
    def _intent(row: Mapping[Any, Any], request_json: str) -> str:
        retained = row["request_json"]
        if (
            type(retained) is not str
            or not 0 < len(retained) <= 65536
            or hashlib.sha256(retained.encode()).hexdigest() != row["request_sha256"]
        ):
            raise ValueError("launch intent bytes differ")
        if retained != request_json:
            raise ResearchCatalogConflict("launch key already names another request")
        return str(row["job_id"])

    def existing_launch(self, *, owner_id: str, key: str, request_json: str) -> str | None:
        snapshot = self._read_validated(
            sa.select(launches).where(
                launches.c.owner_id == owner_id, launches.c.idempotency_key == key
            ),
            is_experiment=False,
        )
        if not snapshot.launches:
            return None
        return self._intent(snapshot.launches[0], request_json)

    def launch(
        self,
        request: ResearchRunRequest,
        *,
        catalog_id: str,
        cost_scenario_id: str,
        request_json: str,
    ) -> str:
        if not 0 < len(request_json) <= 65536:
            raise ValueError("launch intent exceeds its bound")
        with catalog_transaction(self.engine) as connection:
            row = (
                connection.execute(
                    sa.select(launches).where(
                        launches.c.owner_id == request.owner_id,
                        launches.c.idempotency_key == request.idempotency_key,
                    )
                )
                .mappings()
                .first()
            )
            if row is not None:
                retained = self._launch(connection, row, locked=True)
                if (
                    retained != request
                    or row["catalog_id"] != catalog_id
                    or row["cost_scenario_id"] != cost_scenario_id
                ):
                    raise ResearchCatalogConflict("launch key names different immutable selection")
                return self._intent(row, request_json)
            selected = self._selected(connection, catalog_id, request.owner_id)
            self._request_binding(selected, request, cost_scenario_id)
            job = self.workflow.launch_in_transaction(connection, request)
            connection.execute(
                launches.insert().values(
                    owner_id=request.owner_id,
                    idempotency_key=request.idempotency_key,
                    job_id=job.job_id,
                    catalog_id=catalog_id,
                    cost_scenario_id=cost_scenario_id,
                    request_json=request_json,
                    request_sha256=hashlib.sha256(request_json.encode()).hexdigest(),
                )
            )
            return job.job_id

    def _experiment_record(self, row: Mapping[Any, Any]) -> ResearchExperimentRegistration:
        record = self._decode(row, ResearchExperimentRegistration)
        if (
            record.experiment_id,
            record.owner_id,
            record.idempotency_key,
            record.catalog_id,
            record.semantic_sha256,
        ) != (
            row["experiment_id"],
            row["owner_id"],
            row["idempotency_key"],
            row["catalog_id"],
            row["registration_sha256"],
        ):
            raise ValueError("experiment semantic binding differs")
        return record

    @staticmethod
    def _trial_inventory(
        record: ResearchExperimentRegistration, links: tuple[Mapping[Any, Any], ...]
    ) -> None:
        if tuple((link["ordinal"], link["trial_id"], link["job_id"]) for link in links) != tuple(
            (trial.ordinal, trial.trial_id, job_id)
            for trial, job_id in zip(record.trials, record.job_ids, strict=True)
        ):
            raise ValueError("experiment trial inventory differs")

    def _experiment(
        self, connection: Connection, row: sa.RowMapping, *, locked: bool = False
    ) -> ResearchExperimentRegistration:
        record = self._experiment_record(row)
        links = (
            connection.execute(
                sa.select(trial_jobs)
                .where(trial_jobs.c.experiment_id == record.experiment_id)
                .order_by(trial_jobs.c.ordinal)
            )
            .mappings()
            .all()
        )
        self._trial_inventory(record, tuple(links))
        selected = self._selected(connection, record.catalog_id, record.owner_id)
        requests = tuple(
            self.workflow._load(connection, job_id, locked=locked).request
            for job_id in record.job_ids
        )
        self._experiment_binding(selected, record, requests)
        return record

    @staticmethod
    def _experiment_binding(
        entry: ResearchCatalogEntry,
        record: ResearchExperimentRegistration,
        requests: tuple[ResearchRunRequest, ...],
    ) -> None:
        # SQL checks declared links. The application resolver verifies private
        # source bytes, including permissible build/resource-only source changes.
        protocol = record.protocol
        if (
            protocol.dataset_id != entry.dataset_id
            or protocol.dataset_sha256 != entry.dataset_sha256
            or protocol.data_class != entry.data_class
            or protocol.availability_mode != entry.availability_mode
            or protocol.instruments != entry.instruments
            or protocol.calendar_sha256 != entry.calendar_sha256
            or (
                entry.prior_access.status == "known_accessed"
                and protocol.prior_access.status != "known_accessed"
            )
        ):
            raise ValueError("experiment differs from catalog source")
        if any(
            ref.codec_version != "personal-record/1" or ref.byte_count > MAX_INPUT_BYTES
            for ref in (record.source_inputs, *record.fit_objects)
        ):
            raise ValueError("experiment object reference exceeds input contract")
        expected = tuple(
            (
                fold.fold_id,
                candidate.candidate_id,
                content_digest(candidate.configuration),
                window.kind,
                cost,
            )
            for fold in protocol.folds
            for candidate in protocol.candidates
            for window in fold.windows
            for cost in protocol.costs
        )
        actual = tuple(
            (
                trial.fold_id,
                trial.candidate_id,
                trial.configuration_sha256,
                trial.segment,
                trial.cost,
            )
            for trial in record.trials
        )
        if actual != expected or tuple(request.job_id for request in requests) != record.job_ids:
            raise ValueError("experiment requires the exact declared trial inventory")
        for request, trial in zip(requests, record.trials, strict=True):
            SqlResearchCatalog._request_binding(entry, request, trial.cost.scenario_id)
            spec = request.spec
            pins = {pin.name: pin.sha256 for pin in spec.pins}
            fold = next(fold for fold in protocol.folds if fold.fold_id == trial.fold_id)
            window = fold.window(trial.segment)
            expected_pins = {
                "evaluation_trial": trial.semantic_sha256,
                "evaluation_protocol": protocol.semantic_sha256,
                "evaluation_fit": trial.fit_sha256,
                "evaluation_fold": fold.semantic_sha256,
                "evaluation_cost": trial.cost.semantic_sha256,
                "evaluation_access": protocol.prior_access.semantic_sha256,
            }
            if (
                request.owner_id != record.owner_id
                or request.trial_id != trial.trial_id
                or any(pins.get(name) != digest for name, digest in expected_pins.items())
                or content_digest(spec.strategy_configuration) != trial.configuration_sha256
                or spec.initial_cash != protocol.initial_cash
                or spec.evaluation.warmup_sessions != window.warmup_sessions
                or spec.evaluation.scored_sessions != window.scored_sessions
                or spec.evaluation.prior_access_label
                != f"retrospective-{protocol.prior_access.status}"
                or any(pin not in spec.pins for pin in protocol.implementation_pins)
            ):
                raise ValueError("linked job differs from exact evaluation trial")

    def verify_integrity(self, connection: Connection) -> None:
        """Verify retained SQL payloads and links, without reading private object bytes."""
        for row in connection.execute(sa.select(entries)).mappings():
            self._entry(row)
        for row in connection.execute(sa.select(launches)).mappings():
            self._launch(connection, row)
        for row in connection.execute(sa.select(experiments)).mappings():
            self._experiment(connection, row)

    def read_catalog_rows(self, connection: Connection) -> ResearchCatalogRows:
        """Capture the four catalog tables without codec or financial replay work."""
        return ResearchCatalogRows(
            _rows(connection, sa.select(entries).order_by(entries.c.catalog_id)),
            _rows(
                connection,
                sa.select(launches).order_by(launches.c.owner_id, launches.c.idempotency_key),
            ),
            _rows(connection, sa.select(experiments).order_by(experiments.c.experiment_id)),
            _rows(
                connection,
                sa.select(trial_jobs).order_by(trial_jobs.c.experiment_id, trial_jobs.c.ordinal),
            ),
        )

    def replay_catalog_rows(
        self, snapshot: ResearchCatalogRows, requests: Mapping[str, ResearchRunRequest]
    ) -> None:
        """Validate one captured graph against jobs replayed from the same SQL snapshot."""
        selected = {
            row["catalog_id"]: (row["owner_id"], self._entry(row)) for row in snapshot.entries
        }

        def entry(catalog_id: str, owner_id: str) -> ResearchCatalogEntry:
            retained = selected.get(catalog_id)
            if retained is None or retained[0] != owner_id:
                raise ResearchCatalogMissing("owner catalog selection absent")
            return retained[1]

        def request(job_id: str) -> ResearchRunRequest:
            retained = requests.get(job_id)
            if retained is None or retained.job_id != job_id:
                raise ValueError("catalog linked job absent or different")
            return retained

        for row in snapshot.launches:
            self._intent(row, row["request_json"])
            linked = request(row["job_id"])
            if (linked.owner_id, linked.idempotency_key) != (
                row["owner_id"],
                row["idempotency_key"],
            ):
                raise ValueError("launch intent differs from linked job")
            self._request_binding(
                entry(row["catalog_id"], linked.owner_id), linked, row["cost_scenario_id"]
            )
        for row in snapshot.experiments:
            record = self._experiment_record(row)
            links = tuple(
                link for link in snapshot.links if link["experiment_id"] == record.experiment_id
            )
            self._trial_inventory(record, links)
            self._experiment_binding(
                entry(record.catalog_id, record.owner_id),
                record,
                tuple(request(job_id) for job_id in record.job_ids),
            )

    def _read_graph(
        self, connection: Connection, statement: sa.Select[Any], *, is_experiment: bool
    ) -> ResearchCatalogRows:
        selected = _rows(connection, statement)
        catalog_ids = tuple(sorted({str(row["catalog_id"]) for row in selected}))
        entry_rows = _rows(
            connection,
            sa.select(entries)
            .where(entries.c.catalog_id.in_(catalog_ids))
            .order_by(entries.c.catalog_id),
        )
        links = (
            _rows(
                connection,
                sa.select(trial_jobs)
                .where(
                    trial_jobs.c.experiment_id.in_(tuple(row["experiment_id"] for row in selected))
                )
                .order_by(trial_jobs.c.experiment_id, trial_jobs.c.ordinal),
            )
            if is_experiment
            else ()
        )
        return ResearchCatalogRows(
            entry_rows,
            () if is_experiment else selected,
            selected if is_experiment else (),
            links,
        )

    def _read_validated(
        self, statement: sa.Select[Any], *, is_experiment: bool
    ) -> ResearchCatalogRows:
        # Decode request references outside SQL, then recheck the immutable selection
        # and capture current job heads/events/objects in one final coherent snapshot.
        with _repeatable_read_transaction(self.engine) as connection:
            discovered = self._read_graph(connection, statement, is_experiment=is_experiment)
            job_ids = tuple(
                sorted({str(row["job_id"]) for row in (*discovered.launches, *discovered.links)})
            )
            raw_requests = self.workflow.request_rows(connection, job_ids)
        if not discovered.launches and not discovered.experiments:
            return discovered
        decoded = tuple(self.workflow.decode_request_row(row) for row in raw_requests)
        with _repeatable_read_transaction(self.engine) as connection:
            snapshot = self._read_graph(connection, statement, is_experiment=is_experiment)
            if snapshot != discovered:
                raise ResearchCatalogConflict("catalog selection changed during read; retry")
            jobs = self.workflow.read_job_snapshots(connection, decoded)
        requests = {
            state.request.job_id: state.request
            for state in (self.workflow.replay_job_snapshot(job) for job in jobs)
        }
        self.replay_catalog_rows(snapshot, requests)
        return snapshot

    def existing_experiment(
        self, *, owner_id: str, key: str, request_json: str
    ) -> ResearchExperimentRegistration | None:
        snapshot = self._read_validated(
            sa.select(experiments).where(
                experiments.c.owner_id == owner_id, experiments.c.idempotency_key == key
            ),
            is_experiment=True,
        )
        if not snapshot.experiments:
            return None
        record = self._experiment_record(snapshot.experiments[0])
        if record.request_json != request_json:
            raise ResearchCatalogConflict("experiment key names another declaration")
        return record

    def register_experiment(
        self, record: ResearchExperimentRegistration, requests: tuple[ResearchRunRequest, ...]
    ) -> ResearchExperimentRegistration:
        with catalog_transaction(self.engine) as connection:
            existing = (
                connection.execute(
                    sa.select(experiments).where(
                        experiments.c.experiment_id == record.experiment_id
                    )
                )
                .mappings()
                .first()
            )
            if existing is not None:
                retained = self._experiment(connection, existing, locked=True)
                retained_requests = tuple(
                    self.workflow._load(connection, job_id, locked=True).request
                    for job_id in retained.job_ids
                )
                if retained != record or retained_requests != requests:
                    raise ResearchCatalogConflict(
                        "experiment key names different immutable declaration"
                    )
                return retained
            selected = self._selected(connection, record.catalog_id, record.owner_id)
            self._experiment_binding(selected, record, requests)
            connection.execute(
                experiments.insert().values(
                    experiment_id=record.experiment_id,
                    owner_id=record.owner_id,
                    idempotency_key=record.idempotency_key,
                    catalog_id=record.catalog_id,
                    registration_sha256=record.semantic_sha256,
                    registered_at=database_time(connection),
                    **self._payload(record),
                )
            )
            for trial, request in zip(record.trials, requests, strict=True):
                job = self.workflow.launch_in_transaction(connection, request)
                connection.execute(
                    trial_jobs.insert().values(
                        experiment_id=record.experiment_id,
                        ordinal=trial.ordinal,
                        trial_id=trial.trial_id,
                        job_id=job.job_id,
                    )
                )
            return record

    def experiment(self, experiment_id: str, *, owner_id: str) -> ResearchExperimentRegistration:
        snapshot = self._read_validated(
            sa.select(experiments).where(
                experiments.c.experiment_id == experiment_id,
                experiments.c.owner_id == owner_id,
            ),
            is_experiment=True,
        )
        if not snapshot.experiments:
            raise ResearchCatalogMissing("experiment absent")
        return self._experiment_record(snapshot.experiments[0])

    def experiments(
        self, *, owner_id: str, limit: int = 6
    ) -> tuple[ResearchExperimentRegistration, ...]:
        if not 1 <= limit <= 100:
            raise ValueError("experiment page exceeds its bound")
        snapshot = self._read_validated(
            sa.select(experiments)
            .where(experiments.c.owner_id == owner_id)
            .order_by(experiments.c.registered_at.desc(), experiments.c.experiment_id)
            .limit(limit),
            is_experiment=True,
        )
        return tuple(self._experiment_record(row) for row in snapshot.experiments)
