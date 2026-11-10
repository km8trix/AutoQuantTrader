"""Transactional catalog publication and read models for immutable market data."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any

import sqlalchemy as sa
from sqlalchemy.engine import Connection, Engine, RowMapping

from packages.persistence.immutable import (
    ImmutableFactConflict,
    as_aware_utc,
)
from packages.persistence.immutable import (
    insert_or_verify_atomic as _insert_or_verify_atomic,
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
class ManifestPartitionObject:
    ordinal: int
    partition_id: str
    object_id: str
    object_key: str
    byte_checksum: str
    semantic_checksum: str
    semantic_checksum_version: str
    format: str
    size_bytes: int
    row_count: int
    event_time_start: datetime
    event_time_end: datetime
    available_at_start: datetime
    available_at_end: datetime


@dataclass(frozen=True, slots=True)
class ManifestCalendarSession:
    session_label: date
    opens_at: datetime
    closes_at: datetime
    half_day: bool


@dataclass(frozen=True, slots=True)
class ManifestUniverseMembership:
    instrument_id: str
    included_from: datetime
    included_to: datetime | None
    available_at: datetime


@dataclass(frozen=True, slots=True)
class VerifiedManifestReferences:
    calendar_sessions: tuple[ManifestCalendarSession, ...]
    universe_memberships: tuple[ManifestUniverseMembership, ...]


@dataclass(frozen=True, slots=True)
class ManifestObjects:
    manifest_id: str
    manifest_hash: str
    source_id: str
    source_kind: str
    source_licensed: bool
    entitlement_statuses: tuple[str, ...]
    schema_version: str
    calendar_version: str
    calendar_hash: str
    calendar_hash_version: str
    calendar_name: str
    calendar_timezone: str
    calendar_tzdata_version: str
    universe_version: str
    universe_hash: str
    universe_hash_version: str
    corporate_action_version: str
    corporate_action_hash: str
    corporate_action_hash_version: str
    revision_policy: str
    price_basis: str
    row_count: int
    partitions: tuple[ManifestPartitionObject, ...]
    calendar_sessions: tuple[ManifestCalendarSession, ...]
    universe_memberships: tuple[ManifestUniverseMembership, ...]

    @property
    def object_keys(self) -> tuple[str, ...]:
        return tuple(partition.object_key for partition in self.partitions)


MAX_MANIFEST_PARTITIONS = 256
MAX_MANIFEST_REFERENCE_ROWS = 250_000
_INPUT_SEMANTIC_CHECKSUM_VERSION = "input-v1"
_ARROW_SEMANTIC_CHECKSUM_VERSION = "arrow-v2"
_INPUT_REFERENCE_HASH_VERSION = "input-v1"
_PERSISTED_REFERENCE_HASH_VERSION = "persisted-v2"


def _v1_json_value(value: Any) -> Any:
    """Mirror the ingestion-v1 canonical JSON conversion for catalog proofs."""

    if isinstance(value, datetime):
        return as_aware_utc(value).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {
            str(key): _v1_json_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [_v1_json_value(item) for item in value]
    return value


def _v1_digest(value: object) -> str:
    encoded = json.dumps(
        _v1_json_value(value),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _reference_digest(value: object, version: str) -> str:
    encoded = json.dumps(
        _v1_json_value(value),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256()
    if version == _PERSISTED_REFERENCE_HASH_VERSION:
        digest.update(b"autoquanttrader:reference-hash:persisted-v2\n")
    elif version != _INPUT_REFERENCE_HASH_VERSION:
        raise ImmutableFactConflict("manifest reference hash version is unsupported")
    digest.update(encoded)
    return digest.hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def verify_manifest_reference_content(
    connection: Connection,
    *,
    calendar_version: str,
    calendar_hash: str,
    calendar_hash_version: str,
    universe_version: str,
    universe_hash: str,
    universe_hash_version: str,
    corporate_action_version: str,
    corporate_action_hash: str,
    corporate_action_hash_version: str,
    shared_lock: bool = False,
) -> VerifiedManifestReferences:
    """Recompute versioned reference hashes from the exact persisted facts."""

    if not all(
        _is_sha256(value) for value in (calendar_hash, universe_hash, corporate_action_hash)
    ):
        raise ImmutableFactConflict("manifest reference hashes are not canonical SHA-256 values")
    reference_versions = (
        calendar_hash_version,
        universe_hash_version,
        corporate_action_hash_version,
    )
    if any(
        type(version) is not str
        or version not in {_INPUT_REFERENCE_HASH_VERSION, _PERSISTED_REFERENCE_HASH_VERSION}
        for version in reference_versions
    ):
        raise ImmutableFactConflict("manifest reference hash version is unsupported")

    session_query = (
        sa.select(calendar_sessions)
        .where(calendar_sessions.c.calendar_version == calendar_version)
        .order_by(
            calendar_sessions.c.session_label,
            calendar_sessions.c.opens_at,
            calendar_sessions.c.closes_at,
        )
        .limit(MAX_MANIFEST_REFERENCE_ROWS + 1)
    )
    membership_query = (
        sa.select(universe_memberships)
        .where(universe_memberships.c.universe_version == universe_version)
        .order_by(
            universe_memberships.c.instrument_id,
            universe_memberships.c.included_from,
            universe_memberships.c.included_to,
            universe_memberships.c.available_at,
        )
        .limit(MAX_MANIFEST_REFERENCE_ROWS + 1)
    )
    action_member_query = (
        sa.select(corporate_action_set_members)
        .where(corporate_action_set_members.c.corporate_action_version == corporate_action_version)
        .order_by(corporate_action_set_members.c.ordinal)
        .limit(MAX_MANIFEST_REFERENCE_ROWS + 1)
    )
    if shared_lock:
        session_query = session_query.with_for_update(read=True)
        membership_query = membership_query.with_for_update(read=True)
        action_member_query = action_member_query.with_for_update(read=True)

    session_rows = connection.execute(session_query).mappings().all()
    membership_rows = connection.execute(membership_query).mappings().all()
    action_member_rows = connection.execute(action_member_query).mappings().all()
    if (
        not session_rows
        or not membership_rows
        or len(session_rows) > MAX_MANIFEST_REFERENCE_ROWS
        or len(membership_rows) > MAX_MANIFEST_REFERENCE_ROWS
        or len(action_member_rows) > MAX_MANIFEST_REFERENCE_ROWS
    ):
        raise ImmutableFactConflict("manifest has invalid bounded reference members")

    session_rows = sorted(
        session_rows,
        key=lambda row: (
            str(row["session_label"]),
            as_aware_utc(row["opens_at"]),
            as_aware_utc(row["closes_at"]),
        ),
    )
    membership_rows = sorted(
        membership_rows,
        key=lambda row: (
            str(row["instrument_id"]),
            as_aware_utc(row["included_from"]),
            row["included_to"] is None,
            (
                as_aware_utc(row["included_from"])
                if row["included_to"] is None
                else as_aware_utc(row["included_to"])
            ),
            as_aware_utc(row["available_at"]),
        ),
    )
    action_member_rows = sorted(action_member_rows, key=lambda row: int(row["ordinal"]))

    action_revision_ids: list[str] = []
    for ordinal, row in enumerate(action_member_rows):
        action_revision_id = str(row["action_revision_id"])
        if row["ordinal"] != ordinal or not action_revision_id:
            raise ImmutableFactConflict(
                "manifest has invalid contiguous corporate-action set members"
            )
        action_revision_ids.append(action_revision_id)

    action_facts_by_id: dict[str, RowMapping] = {}
    if action_revision_ids:
        action_fact_query = sa.select(corporate_action_revisions).where(
            corporate_action_revisions.c.action_revision_id.in_(action_revision_ids)
        )
        if shared_lock:
            action_fact_query = action_fact_query.with_for_update(read=True)
        action_fact_rows = connection.execute(action_fact_query).mappings().all()
        action_facts_by_id = {str(row["action_revision_id"]): row for row in action_fact_rows}
        if len(action_facts_by_id) != len(action_revision_ids):
            raise ImmutableFactConflict("manifest corporate-action set has missing facts")

    sessions_list: list[ManifestCalendarSession] = []
    calendar_payload: list[dict[str, object]] = []
    for row in session_rows:
        session_label = date.fromisoformat(str(row["session_label"]))
        opens_at = as_aware_utc(row["opens_at"])
        closes_at = as_aware_utc(row["closes_at"])
        if type(row["half_day"]) is not bool or closes_at <= opens_at:
            raise ImmutableFactConflict("manifest has invalid pinned calendar facts")
        half_day = row["half_day"]
        sessions_list.append(
            ManifestCalendarSession(
                session_label=session_label,
                opens_at=opens_at,
                closes_at=closes_at,
                half_day=half_day,
            )
        )
        calendar_payload.append(
            {
                "label": session_label,
                "opens_at": opens_at,
                "closes_at": closes_at,
                "kind": "half_day" if half_day else "regular",
            }
        )

    memberships_list: list[ManifestUniverseMembership] = []
    universe_payload: list[dict[str, object]] = []
    for row in membership_rows:
        instrument_id = str(row["instrument_id"])
        included_from = as_aware_utc(row["included_from"])
        included_to = None if row["included_to"] is None else as_aware_utc(row["included_to"])
        available_at = as_aware_utc(row["available_at"])
        if not instrument_id or (included_to is not None and included_to <= included_from):
            raise ImmutableFactConflict("manifest has invalid pinned universe facts")
        memberships_list.append(
            ManifestUniverseMembership(
                instrument_id=instrument_id,
                included_from=included_from,
                included_to=included_to,
                available_at=available_at,
            )
        )
        universe_payload.append(
            {
                "security_id": instrument_id,
                "effective_from": included_from,
                "effective_to": included_to,
                "available_at": available_at,
                "included": True,
            }
        )

    action_payload: list[dict[str, object]] = []
    for action_revision_id in action_revision_ids:
        row = action_facts_by_id[action_revision_id]
        action_type = str(row["action_type"])
        revision = row["revision"]
        announced_at = as_aware_utc(row["announced_at"])
        effective_at = as_aware_utc(row["effective_at"])
        available_at = as_aware_utc(row["available_at"])
        terms = row["terms"]
        if type(revision) is not int or revision < 1 or not isinstance(terms, Mapping):
            raise ImmutableFactConflict("manifest has invalid corporate-action facts")
        expected_action_payload_hash = _v1_digest(
            {
                "action_type": action_type,
                "announced_at": announced_at,
                "available_at": available_at,
                "effective_at": effective_at,
                "instrument_id": str(row["instrument_id"]),
                "revision": revision,
                "terms": terms,
            }
        )
        if row["payload_hash"] != expected_action_payload_hash:
            raise ImmutableFactConflict("manifest has invalid corporate-action fact hash")
        action_payload.append(
            {
                "event_revision_id": action_revision_id,
                "type": action_type,
                "effective_at": effective_at,
                "available_at": available_at,
                "terms": terms,
            }
        )

    if (
        _reference_digest(calendar_payload, calendar_hash_version) != calendar_hash
        or _reference_digest(universe_payload, universe_hash_version) != universe_hash
        or _reference_digest(action_payload, corporate_action_hash_version) != corporate_action_hash
    ):
        raise ImmutableFactConflict("manifest reference rows do not match their content hashes")

    return VerifiedManifestReferences(
        calendar_sessions=tuple(sessions_list),
        universe_memberships=tuple(memberships_list),
    )


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

    @property
    def engine(self) -> Engine:
        """Return the engine whose immutable facts this catalog authenticates."""

        return self._engine

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
            manifest_ids = tuple(
                connection.scalars(
                    sa.select(dataset_manifest_partitions.c.manifest_id)
                    .join(
                        dataset_partitions,
                        dataset_partitions.c.partition_id
                        == dataset_manifest_partitions.c.partition_id,
                    )
                    .where(dataset_partitions.c.job_id == job_id)
                    .distinct()
                    .order_by(dataset_manifest_partitions.c.manifest_id)
                    .limit(2)
                )
            )
            if len(manifest_ids) > 1:
                raise ImmutableFactConflict(
                    f"ingestion job {job_id!r} is associated with multiple manifests"
                )
            return None if not manifest_ids else str(manifest_ids[0])

    def manifest_objects(self, manifest_id: str) -> ManifestObjects:
        with self._engine.connect() as connection:
            manifest = (
                connection.execute(
                    sa.select(
                        dataset_manifests.c.manifest_id,
                        dataset_manifests.c.manifest_hash,
                        dataset_manifests.c.source_id,
                        market_data_sources.c.kind.label("source_kind"),
                        market_data_sources.c.licensed.label("source_licensed"),
                        dataset_manifests.c.schema_version,
                        dataset_manifests.c.calendar_version,
                        calendar_versions.c.content_hash.label("calendar_hash"),
                        calendar_versions.c.content_hash_version.label("calendar_hash_version"),
                        calendar_versions.c.name.label("calendar_name"),
                        calendar_versions.c.timezone.label("calendar_timezone"),
                        calendar_versions.c.tzdata_version.label("calendar_tzdata_version"),
                        dataset_manifests.c.universe_version,
                        universe_versions.c.content_hash.label("universe_hash"),
                        universe_versions.c.content_hash_version.label("universe_hash_version"),
                        dataset_manifests.c.corporate_action_version,
                        corporate_action_sets.c.content_hash.label("corporate_action_hash"),
                        corporate_action_sets.c.content_hash_version.label(
                            "corporate_action_hash_version"
                        ),
                        dataset_manifests.c.revision_policy,
                        dataset_manifests.c.price_basis,
                        dataset_manifests.c.row_count,
                    )
                    .join(
                        market_data_sources,
                        market_data_sources.c.source_id == dataset_manifests.c.source_id,
                    )
                    .join(
                        calendar_versions,
                        calendar_versions.c.calendar_version
                        == dataset_manifests.c.calendar_version,
                    )
                    .join(
                        universe_versions,
                        universe_versions.c.universe_version
                        == dataset_manifests.c.universe_version,
                    )
                    .join(
                        corporate_action_sets,
                        corporate_action_sets.c.corporate_action_version
                        == dataset_manifests.c.corporate_action_version,
                    )
                    .where(dataset_manifests.c.manifest_id == manifest_id)
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
                        dataset_manifest_partitions.c.partition_id,
                        dataset_partitions.c.object_id,
                        dataset_partitions.c.layer,
                        dataset_partitions.c.status,
                        dataset_partitions.c.source_id,
                        dataset_partitions.c.schema_version,
                        dataset_partitions.c.price_basis,
                        dataset_partitions.c.row_count,
                        dataset_partitions.c.event_time_start,
                        dataset_partitions.c.event_time_end,
                        dataset_partitions.c.available_at_start,
                        dataset_partitions.c.available_at_end,
                        dataset_partitions.c.semantic_checksum.label("partition_semantic_checksum"),
                        dataset_partitions.c.semantic_checksum_version.label(
                            "partition_semantic_checksum_version"
                        ),
                        data_objects.c.object_key,
                        data_objects.c.byte_checksum,
                        data_objects.c.semantic_checksum.label("object_semantic_checksum"),
                        data_objects.c.semantic_checksum_version.label(
                            "object_semantic_checksum_version"
                        ),
                        data_objects.c.size_bytes,
                        data_objects.c.format,
                        partition_quarantines.c.partition_id.label("quarantine_partition_id"),
                    )
                    .join(
                        dataset_partitions,
                        dataset_partitions.c.partition_id
                        == dataset_manifest_partitions.c.partition_id,
                    )
                    .join(data_objects, data_objects.c.object_id == dataset_partitions.c.object_id)
                    .outerjoin(
                        partition_quarantines,
                        partition_quarantines.c.partition_id == dataset_partitions.c.partition_id,
                    )
                    .where(dataset_manifest_partitions.c.manifest_id == manifest_id)
                    .order_by(dataset_manifest_partitions.c.ordinal)
                    .limit(MAX_MANIFEST_PARTITIONS + 1)
                )
                .mappings()
                .all()
            )
            if not rows or len(rows) > MAX_MANIFEST_PARTITIONS:
                raise ImmutableFactConflict(
                    f"manifest {manifest_id!r} has invalid ordered partition members"
                )
            partition_objects: list[ManifestPartitionObject] = []
            for ordinal, row in enumerate(rows):
                partition_id = str(row["partition_id"])
                object_id = str(row["object_id"])
                byte_checksum = str(row["byte_checksum"])
                semantic_checksum = str(row["partition_semantic_checksum"])
                semantic_checksum_version = str(row["partition_semantic_checksum_version"])
                partition_material = {
                    "layer": "normalized",
                    "object_id": object_id,
                    "schema": str(row["schema_version"]),
                    "semantic_checksum": semantic_checksum,
                    "status": "published",
                }
                if manifest["schema_version"] == "raw-bar-v2":
                    partition_material["semantic_checksum_version"] = semantic_checksum_version
                    valid_checksum_version = (
                        semantic_checksum_version == _ARROW_SEMANTIC_CHECKSUM_VERSION
                    )
                else:
                    valid_checksum_version = (
                        manifest["schema_version"] == "raw-bar-v1"
                        and semantic_checksum_version == _INPUT_SEMANTIC_CHECKSUM_VERSION
                    )
                expected_partition_id = _v1_digest(partition_material)
                expected_object_key = (
                    f"normalized/sha256/{byte_checksum[:2]}/{byte_checksum}.parquet"
                )
                if (
                    row["ordinal"] != ordinal
                    or row["layer"] != "normalized"
                    or row["status"] != "published"
                    or row["source_id"] != manifest["source_id"]
                    or row["schema_version"] != manifest["schema_version"]
                    or row["price_basis"] != manifest["price_basis"]
                    or row["quarantine_partition_id"] is not None
                    or row["format"] != "parquet"
                    or object_id != byte_checksum
                    or row["object_key"] != expected_object_key
                    or semantic_checksum != row["object_semantic_checksum"]
                    or semantic_checksum_version != row["object_semantic_checksum_version"]
                    or not valid_checksum_version
                    or partition_id != expected_partition_id
                    or type(row["row_count"]) is not int
                    or row["row_count"] <= 0
                    or type(row["size_bytes"]) is not int
                    or row["size_bytes"] <= 0
                ):
                    raise ImmutableFactConflict(
                        f"manifest {manifest_id!r} has invalid ordered partition members"
                    )
                event_time_start = as_aware_utc(row["event_time_start"])
                event_time_end = as_aware_utc(row["event_time_end"])
                available_at_start = as_aware_utc(row["available_at_start"])
                available_at_end = as_aware_utc(row["available_at_end"])
                if event_time_end < event_time_start or available_at_end < available_at_start:
                    raise ImmutableFactConflict(
                        f"manifest {manifest_id!r} has invalid partition ranges"
                    )
                partition_objects.append(
                    ManifestPartitionObject(
                        ordinal=ordinal,
                        partition_id=partition_id,
                        object_id=object_id,
                        object_key=str(row["object_key"]),
                        byte_checksum=byte_checksum,
                        semantic_checksum=semantic_checksum,
                        semantic_checksum_version=semantic_checksum_version,
                        format=str(row["format"]),
                        size_bytes=int(row["size_bytes"]),
                        row_count=int(row["row_count"]),
                        event_time_start=event_time_start,
                        event_time_end=event_time_end,
                        available_at_start=available_at_start,
                        available_at_end=available_at_end,
                    )
                )

            ordered_partition_ids = [partition.partition_id for partition in partition_objects]
            expected_manifest_material = {
                "calendar_version": str(manifest["calendar_version"]),
                "corporate_action_version": str(manifest["corporate_action_version"]),
                "ordered_partitions": ordered_partition_ids,
                "price_basis": str(manifest["price_basis"]),
                "revision_policy": str(manifest["revision_policy"]),
                "schema_version": str(manifest["schema_version"]),
                "source_id": str(manifest["source_id"]),
                "universe_version": str(manifest["universe_version"]),
            }
            if manifest["schema_version"] == "raw-bar-v2":
                expected_manifest_material.update(
                    {
                        "calendar_hash": str(manifest["calendar_hash"]),
                        "calendar_hash_version": str(manifest["calendar_hash_version"]),
                        "corporate_action_hash": str(manifest["corporate_action_hash"]),
                        "corporate_action_hash_version": str(
                            manifest["corporate_action_hash_version"]
                        ),
                        "universe_hash": str(manifest["universe_hash"]),
                        "universe_hash_version": str(manifest["universe_hash_version"]),
                    }
                )
                valid_reference_versions = {
                    manifest["calendar_hash_version"],
                    manifest["universe_hash_version"],
                    manifest["corporate_action_hash_version"],
                } == {_PERSISTED_REFERENCE_HASH_VERSION}
            else:
                valid_reference_versions = manifest["schema_version"] == "raw-bar-v1" and {
                    manifest["calendar_hash_version"],
                    manifest["universe_hash_version"],
                    manifest["corporate_action_hash_version"],
                } == {_INPUT_REFERENCE_HASH_VERSION}
            expected_manifest_id = _v1_digest(expected_manifest_material)
            if (
                manifest["manifest_id"] != manifest_id
                or manifest["manifest_hash"] != expected_manifest_id
                or manifest_id != expected_manifest_id
                or not valid_reference_versions
                or not _is_sha256(manifest["calendar_hash"])
                or not _is_sha256(manifest["universe_hash"])
                or not _is_sha256(manifest["corporate_action_hash"])
                or type(manifest["row_count"]) is not int
                or manifest["row_count"] != sum(item.row_count for item in partition_objects)
            ):
                raise ImmutableFactConflict(f"manifest {manifest_id!r} failed its content pins")

            references = verify_manifest_reference_content(
                connection,
                calendar_version=str(manifest["calendar_version"]),
                calendar_hash=str(manifest["calendar_hash"]),
                calendar_hash_version=str(manifest["calendar_hash_version"]),
                universe_version=str(manifest["universe_version"]),
                universe_hash=str(manifest["universe_hash"]),
                universe_hash_version=str(manifest["universe_hash_version"]),
                corporate_action_version=str(manifest["corporate_action_version"]),
                corporate_action_hash=str(manifest["corporate_action_hash"]),
                corporate_action_hash_version=str(manifest["corporate_action_hash_version"]),
            )
            entitlement_statuses = tuple(
                connection.scalars(
                    sa.select(market_data_entitlements.c.status)
                    .where(market_data_entitlements.c.source_id == manifest["source_id"])
                    .order_by(market_data_entitlements.c.entitlement_id)
                    .limit(MAX_MANIFEST_REFERENCE_ROWS + 1)
                )
            )
            if not entitlement_statuses or len(entitlement_statuses) > MAX_MANIFEST_REFERENCE_ROWS:
                raise ImmutableFactConflict(
                    f"manifest {manifest_id!r} has invalid pinned reference data"
                )
            return ManifestObjects(
                manifest_id=manifest_id,
                manifest_hash=str(manifest["manifest_hash"]),
                source_id=str(manifest["source_id"]),
                source_kind=str(manifest["source_kind"]),
                source_licensed=bool(manifest["source_licensed"]),
                entitlement_statuses=tuple(str(status) for status in entitlement_statuses),
                schema_version=str(manifest["schema_version"]),
                calendar_version=str(manifest["calendar_version"]),
                calendar_hash=str(manifest["calendar_hash"]),
                calendar_hash_version=str(manifest["calendar_hash_version"]),
                calendar_name=str(manifest["calendar_name"]),
                calendar_timezone=str(manifest["calendar_timezone"]),
                calendar_tzdata_version=str(manifest["calendar_tzdata_version"]),
                universe_version=str(manifest["universe_version"]),
                universe_hash=str(manifest["universe_hash"]),
                universe_hash_version=str(manifest["universe_hash_version"]),
                corporate_action_version=str(manifest["corporate_action_version"]),
                corporate_action_hash=str(manifest["corporate_action_hash"]),
                corporate_action_hash_version=str(manifest["corporate_action_hash_version"]),
                revision_policy=str(manifest["revision_policy"]),
                price_basis=str(manifest["price_basis"]),
                row_count=int(manifest["row_count"]),
                partitions=tuple(partition_objects),
                calendar_sessions=references.calendar_sessions,
                universe_memberships=references.universe_memberships,
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
