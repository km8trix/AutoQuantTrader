"""Transactional catalog publication and read models for immutable market data."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Connection, Engine, RowMapping

from packages.persistence.immutable import (
    ImmutableFactConflict,
    as_aware_utc,
    assert_immutable,
)
from packages.persistence.schema import (
    calendar_sessions,
    calendar_versions,
    corporate_action_revisions,
    corporate_action_set_members,
    corporate_action_sets,
    data_objects,
    data_quality_issues,
    data_quality_runs,
    dataset_manifest_partitions,
    dataset_manifests,
    dataset_partitions,
    ingestion_jobs,
    instrument_identifiers,
    instruments,
    market_data_admission_checks,
    market_data_admission_profiles,
    market_data_admission_runs,
    market_data_entitlements,
    market_data_sources,
    partition_quarantines,
    universe_memberships,
    universe_versions,
)


@dataclass(frozen=True, slots=True)
class CatalogPublication:
    source: Mapping[str, Any]
    entitlements: tuple[Mapping[str, Any], ...]
    instruments: tuple[Mapping[str, Any], ...]
    identifiers: tuple[Mapping[str, Any], ...]
    universe: Mapping[str, Any]
    memberships: tuple[Mapping[str, Any], ...]
    calendar: Mapping[str, Any]
    sessions: tuple[Mapping[str, Any], ...]
    corporate_actions: tuple[Mapping[str, Any], ...]
    corporate_action_set: Mapping[str, Any]
    corporate_action_members: tuple[Mapping[str, Any], ...]
    job: Mapping[str, Any]
    objects: tuple[Mapping[str, Any], ...]
    partitions: tuple[Mapping[str, Any], ...]
    quality_run: Mapping[str, Any]
    quality_issues: tuple[Mapping[str, Any], ...]
    quarantines: tuple[Mapping[str, Any], ...]
    manifest: Mapping[str, Any] | None
    manifest_partitions: tuple[Mapping[str, Any], ...]
    admission_profile: Mapping[str, Any] | None = None
    admission_run: Mapping[str, Any] | None = None
    admission_checks: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True, slots=True)
class CatalogRows:
    as_of: datetime
    sources: tuple[dict[str, Any], ...]
    entitlements: tuple[dict[str, Any], ...]
    jobs: tuple[dict[str, Any], ...]
    manifests: tuple[dict[str, Any], ...]
    manifest_partitions: tuple[dict[str, Any], ...]
    instruments: tuple[dict[str, Any], ...]
    identifiers: tuple[dict[str, Any], ...]
    corporate_actions: tuple[dict[str, Any], ...]
    admission_profiles: tuple[dict[str, Any], ...]
    admission_runs: tuple[dict[str, Any], ...]
    admission_checks: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class QualityRows:
    as_of: datetime
    issues: tuple[dict[str, Any], ...]
    quarantines: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class ManifestObjects:
    manifest_id: str
    revision_policy: str
    price_basis: str
    object_keys: tuple[str, ...]


def _row(
    table: sa.Table,
    connection: Connection,
    key_values: Mapping[str, Any],
) -> RowMapping:
    predicate = sa.and_(*(table.c[key_name] == key for key_name, key in key_values.items()))
    existing = connection.execute(sa.select(table).where(predicate)).mappings().one_or_none()
    if existing is None:
        identifier = ",".join(f"{name}={value}" for name, value in key_values.items())
        raise ImmutableFactConflict(
            f"{table.name} rejected fact {identifier!r} through another uniqueness invariant"
        )
    return existing


def _insert_or_verify_atomic(
    connection: Connection,
    table: sa.Table,
    values: Mapping[str, Any],
) -> bool:
    payload = dict(values)
    key_values = {column.name: payload[column.name] for column in table.primary_key.columns}
    dialect = connection.dialect.name
    if dialect == "postgresql":
        statement = (
            postgresql_insert(table)
            .values(**payload)
            .on_conflict_do_nothing()
            .returning(sa.literal(True))
        )
        inserted = connection.execute(statement).scalar_one_or_none() is not None
    elif dialect == "sqlite":
        sqlite_statement = (
            sqlite_insert(table)
            .values(**payload)
            .on_conflict_do_nothing()
            .returning(sa.literal(True))
        )
        inserted = connection.execute(sqlite_statement).scalar_one_or_none() is not None
    else:
        raise RuntimeError(f"market-data catalog does not support SQL dialect {dialect!r}")
    existing = _row(table, connection, key_values)
    identifier = ",".join(f"{name}={value}" for name, value in key_values.items())
    assert_immutable(table, identifier, existing, payload)
    return inserted


def _insert_many(
    connection: Connection,
    table: sa.Table,
    rows: Sequence[Mapping[str, Any]],
) -> None:
    for values in rows:
        _insert_or_verify_atomic(connection, table, values)


def _materialize(row: RowMapping) -> dict[str, Any]:
    return {
        key: as_aware_utc(value) if isinstance(value, datetime) else value
        for key, value in row.items()
    }


class SqlMarketDataCatalog:
    """Publishes a complete manifest transaction after object-store sealing."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def job_for_idempotency_key(self, idempotency_key: str) -> dict[str, Any] | None:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    sa.select(ingestion_jobs).where(
                        ingestion_jobs.c.idempotency_key == idempotency_key
                    )
                )
                .mappings()
                .one_or_none()
            )
            return None if row is None else _materialize(row)

    def manifest_id_for_job(self, job_id: str) -> str | None:
        with self._engine.connect() as connection:
            return connection.scalar(
                sa.select(dataset_manifest_partitions.c.manifest_id)
                .join(
                    dataset_partitions,
                    dataset_partitions.c.partition_id == dataset_manifest_partitions.c.partition_id,
                )
                .where(dataset_partitions.c.job_id == job_id)
                .order_by(dataset_manifest_partitions.c.manifest_id)
                .limit(1)
            )

    def manifest_objects(self, manifest_id: str) -> ManifestObjects:
        with self._engine.connect() as connection:
            manifest = (
                connection.execute(
                    sa.select(dataset_manifests).where(
                        dataset_manifests.c.manifest_id == manifest_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if manifest is None:
                raise KeyError(f"unknown dataset manifest: {manifest_id}")
            rows = (
                connection.execute(
                    sa.select(
                        dataset_manifest_partitions.c.ordinal,
                        dataset_partitions.c.layer,
                        dataset_partitions.c.status,
                        data_objects.c.object_key,
                    )
                    .join(
                        dataset_partitions,
                        dataset_partitions.c.partition_id
                        == dataset_manifest_partitions.c.partition_id,
                    )
                    .join(data_objects, data_objects.c.object_id == dataset_partitions.c.object_id)
                    .where(dataset_manifest_partitions.c.manifest_id == manifest_id)
                    .order_by(dataset_manifest_partitions.c.ordinal)
                )
                .mappings()
                .all()
            )
            if not rows or any(
                row["ordinal"] != ordinal
                or row["layer"] != "normalized"
                or row["status"] != "published"
                for ordinal, row in enumerate(rows)
            ):
                raise ImmutableFactConflict(
                    f"manifest {manifest_id!r} has invalid ordered partition members"
                )
            return ManifestObjects(
                manifest_id=manifest_id,
                revision_policy=str(manifest["revision_policy"]),
                price_basis=str(manifest["price_basis"]),
                object_keys=tuple(str(row["object_key"]) for row in rows),
            )

    def publish(self, publication: CatalogPublication) -> bool:
        """Return true for first publication and false for an identical retry."""

        with self._engine.begin() as connection:
            _insert_or_verify_atomic(
                connection,
                market_data_sources,
                publication.source,
            )
            _insert_many(
                connection,
                market_data_entitlements,
                publication.entitlements,
            )
            _insert_many(
                connection,
                instruments,
                publication.instruments,
            )
            _insert_many(
                connection,
                instrument_identifiers,
                publication.identifiers,
            )
            _insert_or_verify_atomic(
                connection,
                universe_versions,
                publication.universe,
            )
            for membership in publication.memberships:
                _insert_or_verify_atomic(
                    connection,
                    universe_memberships,
                    membership,
                )
            _insert_or_verify_atomic(
                connection,
                calendar_versions,
                publication.calendar,
            )
            for session in publication.sessions:
                _insert_or_verify_atomic(
                    connection,
                    calendar_sessions,
                    session,
                )
            _insert_many(
                connection,
                corporate_action_revisions,
                publication.corporate_actions,
            )
            _insert_or_verify_atomic(
                connection,
                corporate_action_sets,
                publication.corporate_action_set,
            )
            for member in publication.corporate_action_members:
                _insert_or_verify_atomic(
                    connection,
                    corporate_action_set_members,
                    member,
                )
            inserted_job = _insert_or_verify_atomic(
                connection,
                ingestion_jobs,
                publication.job,
            )
            _insert_many(connection, data_objects, publication.objects)
            _insert_many(
                connection,
                dataset_partitions,
                publication.partitions,
            )
            _insert_or_verify_atomic(
                connection,
                data_quality_runs,
                publication.quality_run,
            )
            _insert_many(
                connection,
                data_quality_issues,
                publication.quality_issues,
            )
            _insert_many(
                connection,
                partition_quarantines,
                publication.quarantines,
            )
            if publication.manifest is not None:
                _insert_or_verify_atomic(
                    connection,
                    dataset_manifests,
                    publication.manifest,
                )
                for member in publication.manifest_partitions:
                    _insert_or_verify_atomic(
                        connection,
                        dataset_manifest_partitions,
                        member,
                    )
            elif publication.manifest_partitions:
                raise ValueError("manifest partition members require a manifest")
            if publication.admission_profile is not None:
                _insert_or_verify_atomic(
                    connection,
                    market_data_admission_profiles,
                    publication.admission_profile,
                )
            if publication.admission_run is not None:
                if publication.admission_profile is None:
                    raise ValueError("admission run requires an admission profile")
                inserted_admission = _insert_or_verify_atomic(
                    connection,
                    market_data_admission_runs,
                    publication.admission_run,
                )
                if inserted_admission:
                    _insert_many(
                        connection,
                        market_data_admission_checks,
                        publication.admission_checks,
                    )
            elif publication.admission_checks:
                raise ValueError("admission checks require an admission run")
            return inserted_job

    def catalog_rows(self, *, as_of: datetime) -> CatalogRows:
        with self._engine.connect() as connection:
            sources = connection.execute(
                sa.select(market_data_sources).order_by(market_data_sources.c.source_id)
            ).mappings()
            entitlements = connection.execute(
                sa.select(market_data_entitlements).order_by(
                    market_data_entitlements.c.effective_from.desc(),
                    market_data_entitlements.c.entitlement_id,
                )
            ).mappings()
            jobs = connection.execute(
                sa.select(ingestion_jobs).order_by(
                    ingestion_jobs.c.started_at.desc(), ingestion_jobs.c.job_id
                )
            ).mappings()
            manifests = connection.execute(
                sa.select(dataset_manifests).order_by(
                    dataset_manifests.c.created_at.desc(), dataset_manifests.c.manifest_id
                )
            ).mappings()
            members = connection.execute(
                sa.select(
                    dataset_manifest_partitions.c.manifest_id,
                    dataset_manifest_partitions.c.ordinal,
                    dataset_partitions,
                    data_objects.c.object_key,
                    data_objects.c.byte_checksum,
                )
                .join(
                    dataset_partitions,
                    dataset_partitions.c.partition_id == dataset_manifest_partitions.c.partition_id,
                )
                .join(data_objects, data_objects.c.object_id == dataset_partitions.c.object_id)
                .order_by(
                    dataset_manifest_partitions.c.manifest_id,
                    dataset_manifest_partitions.c.ordinal,
                )
            ).mappings()
            security_rows = connection.execute(
                sa.select(instruments).order_by(instruments.c.instrument_id)
            ).mappings()
            identifier_rows = connection.execute(
                sa.select(instrument_identifiers).order_by(
                    instrument_identifiers.c.instrument_id,
                    instrument_identifiers.c.effective_from,
                    instrument_identifiers.c.revision,
                )
            ).mappings()
            action_rows = connection.execute(
                sa.select(corporate_action_revisions).order_by(
                    corporate_action_revisions.c.effective_at,
                    corporate_action_revisions.c.action_id,
                    corporate_action_revisions.c.revision,
                )
            ).mappings()
            admission_profile_rows = connection.execute(
                sa.select(market_data_admission_profiles).order_by(
                    market_data_admission_profiles.c.created_at.desc(),
                    market_data_admission_profiles.c.profile_id,
                )
            ).mappings()
            admission_run_rows = connection.execute(
                sa.select(market_data_admission_runs).order_by(
                    market_data_admission_runs.c.executed_at.desc(),
                    market_data_admission_runs.c.admission_run_id,
                )
            ).mappings()
            admission_check_rows = connection.execute(
                sa.select(market_data_admission_checks).order_by(
                    market_data_admission_checks.c.admission_run_id,
                    market_data_admission_checks.c.code,
                )
            ).mappings()
            return CatalogRows(
                as_of=as_of,
                sources=tuple(_materialize(row) for row in sources),
                entitlements=tuple(_materialize(row) for row in entitlements),
                jobs=tuple(_materialize(row) for row in jobs),
                manifests=tuple(_materialize(row) for row in manifests),
                manifest_partitions=tuple(_materialize(row) for row in members),
                instruments=tuple(_materialize(row) for row in security_rows),
                identifiers=tuple(_materialize(row) for row in identifier_rows),
                corporate_actions=tuple(_materialize(row) for row in action_rows),
                admission_profiles=tuple(_materialize(row) for row in admission_profile_rows),
                admission_runs=tuple(_materialize(row) for row in admission_run_rows),
                admission_checks=tuple(_materialize(row) for row in admission_check_rows),
            )

    def quality_rows(self, *, as_of: datetime) -> QualityRows:
        with self._engine.connect() as connection:
            issues = connection.execute(
                sa.select(data_quality_issues).order_by(
                    data_quality_issues.c.detected_at.desc(),
                    data_quality_issues.c.issue_id,
                )
            ).mappings()
            quarantines = connection.execute(
                sa.select(partition_quarantines).order_by(
                    partition_quarantines.c.quarantined_at.desc(),
                    partition_quarantines.c.partition_id,
                )
            ).mappings()
            return QualityRows(
                as_of=as_of,
                issues=tuple(_materialize(row) for row in issues),
                quarantines=tuple(_materialize(row) for row in quarantines),
            )
