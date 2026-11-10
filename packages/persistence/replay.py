"""Atomic persistence for sealed-success deterministic replay evidence."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import fields
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.engine import Connection, Engine, RowMapping

from packages.datasets.parquet import ObjectIntegrityError
from packages.datasets.replay_tape import (
    MANIFEST_REPLAY_TAPE_CONTRACT_VERSION,
    WATERMARK_POLICY_VERSION,
    ManifestReplayTape,
    ManifestReplayTapeReader,
    ReplayTapePlan,
    build_replay_tape_plan,
    market_event_from_raw_bar,
    replay_manifest_tape,
)
from packages.domain.replay_manifest import (
    DatasetPartitionPin,
    DatasetPin,
    EnginePin,
    ReplayPlanPin,
    ReplayRunManifest,
)
from packages.market_data import BarInterval
from packages.persistence.immutable import (
    ImmutableFactConflict,
    as_aware_utc,
    assert_immutable,
    insert_or_verify_atomic,
)
from packages.persistence.market_data import (
    ManifestObjects,
    ManifestPartitionObject,
    verify_manifest_reference_content,
)
from packages.persistence.schema import (
    calendar_versions,
    corporate_action_sets,
    data_objects,
    dataset_manifest_partitions,
    dataset_manifests,
    dataset_partitions,
    market_data_entitlements,
    market_data_sources,
    partition_quarantines,
    replay_run_manifests,
    universe_versions,
)

_INPUT_SEMANTIC_CHECKSUM_VERSION = "input-v1"
_ARROW_SEMANTIC_CHECKSUM_VERSION = "arrow-v2"
_INPUT_REFERENCE_HASH_VERSION = "input-v1"
_PERSISTED_REFERENCE_HASH_VERSION = "persisted-v2"


def _v1_digest(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _catalog_conflict(detail: str) -> ImmutableFactConflict:
    return ImmutableFactConflict(f"replay dataset pin conflicts with catalog: {detail}")


def _proof_conflict(detail: str) -> ImmutableFactConflict:
    return ImmutableFactConflict(f"replay manifest conflicts with reader tape proof: {detail}")


def _dataset_pin_from_tape(tape: ManifestReplayTape) -> DatasetPin:
    return DatasetPin(
        manifest_id=tape.manifest_id,
        manifest_sha256=tape.manifest_hash,
        source_tape_sha256=tape.semantic_sha256,
        source_id=tape.source_id,
        source_kind=tape.source_kind,
        schema_version=tape.schema_version,
        price_basis=tape.price_basis.value,
        revision_policy=tape.revision_policy,
        calendar_version=tape.plan.calendar_version,
        calendar_sha256=tape.plan.calendar_hash,
        calendar_hash_version=tape.plan.calendar_hash_version,
        tzdata_version=tape.calendar_tzdata_version,
        universe_version=tape.plan.universe_version,
        universe_sha256=tape.plan.universe_hash,
        universe_hash_version=tape.plan.universe_hash_version,
        corporate_action_version=tape.corporate_action_version,
        corporate_action_sha256=tape.corporate_action_hash,
        corporate_action_hash_version=tape.corporate_action_hash_version,
        row_count=tape.row_count,
        partitions=tuple(
            DatasetPartitionPin(
                ordinal=partition.ordinal,
                partition_id=partition.partition_id,
                object_id=partition.object_id,
                object_key=partition.object_key,
                format=partition.format,
                byte_sha256=partition.byte_checksum,
                semantic_sha256=partition.semantic_checksum,
                semantic_checksum_version=partition.semantic_checksum_version,
                size_bytes=partition.size_bytes,
                row_count=partition.row_count,
                event_time_start=partition.event_time_start,
                event_time_end=partition.event_time_end,
                available_at_start=partition.available_at_start,
                available_at_end=partition.available_at_end,
            )
            for partition in tape.partitions
        ),
    )


def _plan_pin(plan: ReplayTapePlan) -> ReplayPlanPin:
    first_watermark = plan.watermarks[0]
    return ReplayPlanPin(
        coverage_start=plan.event_time_start,
        coverage_end=plan.event_time_end,
        interval=plan.interval.value,
        decision_lag=plan.decision_lag,
        revision_policy=plan.revision_policy,
        missing_data_policy=first_watermark.missing_data_policy,
        late_event_policy=first_watermark.late_event_policy,
        expected_instrument_ids=plan.expected_instrument_ids,
        watermark_count=len(plan.watermarks),
        watermarks_sha256=plan.watermarks_sha256,
    )


def _verify_reader_tape_proof(
    manifest: ReplayRunManifest,
    tape: ManifestReplayTape,
    rehydrated_tape: ManifestReplayTape,
) -> None:
    """Bind a sealed manifest to a fresh catalog/object-store reader proof."""

    if type(tape) is not ManifestReplayTape:
        raise _proof_conflict("publish requires an exact ManifestReplayTape")
    if type(rehydrated_tape) is not ManifestReplayTape:
        raise _proof_conflict("rehydration did not return an exact ManifestReplayTape")
    if tape != rehydrated_tape:
        raise _proof_conflict("supplied tape differs from fresh catalog/object rehydration")
    if type(rehydrated_tape.bars) is not tuple or type(rehydrated_tape.events) is not tuple:
        raise _proof_conflict("bars and events must be immutable tuples")
    try:
        mapped_events = tuple(market_event_from_raw_bar(bar) for bar in rehydrated_tape.bars)
        expected_dataset = _dataset_pin_from_tape(rehydrated_tape)
        expected_plan = _plan_pin(rehydrated_tape.plan)
        expected_engine = EnginePin(
            tape_adapter_version=MANIFEST_REPLAY_TAPE_CONTRACT_VERSION,
            watermark_policy_version=WATERMARK_POLICY_VERSION,
        )
        expected_result = replay_manifest_tape(rehydrated_tape)
    except (AttributeError, TypeError, ValueError) as error:
        raise _proof_conflict("tape is not a valid reader-issued proof") from error
    if rehydrated_tape.events != mapped_events:
        raise _proof_conflict("bars and events do not preserve the same causal facts")

    dataset_mismatches = tuple(
        field.name
        for field in fields(DatasetPin)
        if getattr(manifest.dataset, field.name) != getattr(expected_dataset, field.name)
    )
    if dataset_mismatches:
        raise _proof_conflict("dataset fields differ: " + ", ".join(sorted(dataset_mismatches)))
    plan_mismatches = tuple(
        field.name
        for field in fields(ReplayPlanPin)
        if getattr(manifest.plan, field.name) != getattr(expected_plan, field.name)
    )
    if plan_mismatches:
        raise _proof_conflict("plan fields differ: " + ", ".join(sorted(plan_mismatches)))
    engine_mismatches = tuple(
        field.name
        for field in fields(EnginePin)
        if getattr(manifest.engine, field.name) != getattr(expected_engine, field.name)
    )
    if engine_mismatches:
        raise _proof_conflict("engine fields differ: " + ", ".join(sorted(engine_mismatches)))

    expected_outcome: Mapping[str, object] = {
        "started_at": expected_result.started_at,
        "completed_at": expected_result.completed_at,
        "tape_sha256": expected_result.tape_sha256,
        "replay_semantic_sha256": expected_result.semantic_sha256,
        "processed_event_count": len(expected_result.processed_event_ids),
        "batch_count": len(expected_result.batches),
        "complete_batch_count": len(expected_result.complete_batch_ids),
        "skipped_batch_count": len(expected_result.skipped_batch_ids),
    }
    outcome_mismatches = tuple(
        name for name, expected in expected_outcome.items() if getattr(manifest, name) != expected
    )
    if outcome_mismatches:
        raise _proof_conflict(
            "replay outcome fields differ: " + ", ".join(sorted(outcome_mismatches))
        )


def _catalog_manifest(
    connection: Connection,
    manifest_id: str,
    *,
    shared_lock: bool,
) -> RowMapping:
    statement = (
        sa.select(
            dataset_manifests.c.manifest_id,
            dataset_manifests.c.manifest_hash,
            dataset_manifests.c.source_id,
            dataset_manifests.c.schema_version,
            dataset_manifests.c.price_basis,
            dataset_manifests.c.revision_policy,
            dataset_manifests.c.calendar_version,
            dataset_manifests.c.universe_version,
            dataset_manifests.c.corporate_action_version,
            dataset_manifests.c.row_count,
            market_data_sources.c.kind.label("source_kind"),
            market_data_sources.c.licensed.label("source_licensed"),
            calendar_versions.c.content_hash.label("calendar_sha256"),
            calendar_versions.c.content_hash_version.label("calendar_hash_version"),
            calendar_versions.c.name.label("calendar_name"),
            calendar_versions.c.timezone.label("calendar_timezone"),
            calendar_versions.c.tzdata_version,
            universe_versions.c.content_hash.label("universe_sha256"),
            universe_versions.c.content_hash_version.label("universe_hash_version"),
            corporate_action_sets.c.content_hash.label("corporate_action_sha256"),
            corporate_action_sets.c.content_hash_version.label("corporate_action_hash_version"),
        )
        .join(
            market_data_sources,
            market_data_sources.c.source_id == dataset_manifests.c.source_id,
        )
        .join(
            calendar_versions,
            calendar_versions.c.calendar_version == dataset_manifests.c.calendar_version,
        )
        .join(
            universe_versions,
            universe_versions.c.universe_version == dataset_manifests.c.universe_version,
        )
        .join(
            corporate_action_sets,
            corporate_action_sets.c.corporate_action_version
            == dataset_manifests.c.corporate_action_version,
        )
        .where(dataset_manifests.c.manifest_id == manifest_id)
    )
    if shared_lock and connection.dialect.name == "postgresql":
        # Child-table FOR SHARE locks do not prevent FK-compatible phantom
        # inserts. Lock each referenced authority/version parent FOR UPDATE so
        # entitlement, reference-member, and manifest-member sets stay stable
        # until the replay publication transaction commits.
        statement = statement.with_for_update(
            of=(
                dataset_manifests,
                market_data_sources,
                calendar_versions,
                universe_versions,
                corporate_action_sets,
            )
        )
    row = connection.execute(statement).mappings().one_or_none()
    if row is None:
        raise _catalog_conflict("manifest is missing or has broken reference pins")
    return row


def verify_replay_dataset_catalog(
    connection: Connection,
    dataset: DatasetPin,
    plan: ReplayPlanPin,
    *,
    shared_lock: bool = False,
) -> ManifestObjects:
    """Verify every replay dataset pin against its immutable catalog lineage."""

    if type(dataset) is not DatasetPin:
        raise _catalog_conflict("verification requires an exact DatasetPin")
    if type(plan) is not ReplayPlanPin:
        raise _catalog_conflict("verification requires an exact ReplayPlanPin")
    catalog = _catalog_manifest(
        connection,
        dataset.manifest_id,
        shared_lock=shared_lock,
    )
    expected: Mapping[str, object] = {
        "manifest_id": dataset.manifest_id,
        "manifest_hash": dataset.manifest_sha256,
        "source_id": dataset.source_id,
        "source_kind": dataset.source_kind,
        "schema_version": dataset.schema_version,
        "price_basis": dataset.price_basis,
        "revision_policy": dataset.revision_policy.value,
        "calendar_version": dataset.calendar_version,
        "calendar_sha256": dataset.calendar_sha256,
        "calendar_hash_version": dataset.calendar_hash_version,
        "tzdata_version": dataset.tzdata_version,
        "universe_version": dataset.universe_version,
        "universe_sha256": dataset.universe_sha256,
        "universe_hash_version": dataset.universe_hash_version,
        "corporate_action_version": dataset.corporate_action_version,
        "corporate_action_sha256": dataset.corporate_action_sha256,
        "corporate_action_hash_version": dataset.corporate_action_hash_version,
        "row_count": dataset.row_count,
    }
    mismatches = [name for name, value in expected.items() if catalog[name] != value]
    if mismatches:
        raise _catalog_conflict("manifest fields differ: " + ", ".join(sorted(mismatches)))
    if bool(catalog["source_licensed"]):
        raise _catalog_conflict("fixture replay cannot inherit licensed/vendor authority")
    try:
        references = verify_manifest_reference_content(
            connection,
            calendar_version=dataset.calendar_version,
            calendar_hash=dataset.calendar_sha256,
            calendar_hash_version=dataset.calendar_hash_version,
            universe_version=dataset.universe_version,
            universe_hash=dataset.universe_sha256,
            universe_hash_version=dataset.universe_hash_version,
            corporate_action_version=dataset.corporate_action_version,
            corporate_action_hash=dataset.corporate_action_sha256,
            corporate_action_hash_version=dataset.corporate_action_hash_version,
            shared_lock=shared_lock,
        )
    except ImmutableFactConflict as error:
        raise _catalog_conflict(f"reference content differs: {error}") from error

    entitlement_statement = (
        sa.select(market_data_entitlements.c.status)
        .where(market_data_entitlements.c.source_id == dataset.source_id)
        .order_by(market_data_entitlements.c.entitlement_id)
    )
    if shared_lock and connection.dialect.name == "postgresql":
        entitlement_statement = entitlement_statement.with_for_update(read=True)
    entitlement_statuses = tuple(connection.scalars(entitlement_statement))
    if not entitlement_statuses or set(entitlement_statuses) != {"fixture_only"}:
        raise _catalog_conflict("source is not exclusively fixture-only")

    partition_statement = (
        sa.select(
            dataset_manifest_partitions.c.ordinal,
            dataset_manifest_partitions.c.partition_id,
            dataset_partitions.c.object_id,
            dataset_partitions.c.source_id,
            dataset_partitions.c.layer,
            dataset_partitions.c.status,
            dataset_partitions.c.schema_version,
            dataset_partitions.c.price_basis,
            dataset_partitions.c.row_count,
            dataset_partitions.c.event_time_start,
            dataset_partitions.c.event_time_end,
            dataset_partitions.c.available_at_start,
            dataset_partitions.c.available_at_end,
            dataset_partitions.c.semantic_checksum.label("partition_semantic_sha256"),
            dataset_partitions.c.semantic_checksum_version.label(
                "partition_semantic_checksum_version"
            ),
            data_objects.c.object_key,
            data_objects.c.byte_checksum,
            data_objects.c.semantic_checksum.label("object_semantic_sha256"),
            data_objects.c.semantic_checksum_version.label("object_semantic_checksum_version"),
            data_objects.c.format,
            data_objects.c.size_bytes,
        )
        .join(
            dataset_partitions,
            dataset_partitions.c.partition_id == dataset_manifest_partitions.c.partition_id,
        )
        .join(data_objects, data_objects.c.object_id == dataset_partitions.c.object_id)
        .where(dataset_manifest_partitions.c.manifest_id == dataset.manifest_id)
        .order_by(dataset_manifest_partitions.c.ordinal)
    )
    if shared_lock and connection.dialect.name == "postgresql":
        # dataset_partitions is the FK parent for quarantine rows; an exclusive
        # row lock prevents a quarantine phantom after it has been checked.
        partition_statement = partition_statement.with_for_update(
            of=(dataset_manifest_partitions, dataset_partitions, data_objects)
        )
    partition_rows = connection.execute(partition_statement).mappings().all()
    partition_ids = tuple(str(row["partition_id"]) for row in partition_rows)
    quarantine_statement = sa.select(partition_quarantines.c.partition_id).where(
        partition_quarantines.c.partition_id.in_(partition_ids)
    )
    if shared_lock and connection.dialect.name == "postgresql":
        quarantine_statement = quarantine_statement.with_for_update(read=True)
    quarantined_partition_ids = frozenset(connection.scalars(quarantine_statement))
    if len(partition_rows) != len(dataset.partitions):
        raise _catalog_conflict("ordered partition count differs")
    for pin, row in zip(dataset.partitions, partition_rows, strict=True):
        expected_object_key = f"normalized/sha256/{pin.byte_sha256[:2]}/{pin.byte_sha256}.parquet"
        partition_material = {
            "layer": "normalized",
            "object_id": pin.object_id,
            "schema": dataset.schema_version,
            "semantic_checksum": pin.semantic_sha256,
            "status": "published",
        }
        if dataset.schema_version == "raw-bar-v2":
            partition_material["semantic_checksum_version"] = pin.semantic_checksum_version
            valid_checksum_version = (
                pin.semantic_checksum_version == _ARROW_SEMANTIC_CHECKSUM_VERSION
            )
        else:
            valid_checksum_version = (
                dataset.schema_version == "raw-bar-v1"
                and pin.semantic_checksum_version == _INPUT_SEMANTIC_CHECKSUM_VERSION
            )
        expected_partition_id = _v1_digest(partition_material)
        if (
            row["ordinal"] != pin.ordinal
            or row["partition_id"] != pin.partition_id
            or pin.partition_id != expected_partition_id
            or row["object_id"] != pin.object_id
            or row["object_key"] != pin.object_key
            or pin.object_key != expected_object_key
            or row["byte_checksum"] != pin.byte_sha256
            or row["partition_semantic_sha256"] != pin.semantic_sha256
            or row["object_semantic_sha256"] != pin.semantic_sha256
            or row["partition_semantic_checksum_version"] != pin.semantic_checksum_version
            or row["object_semantic_checksum_version"] != pin.semantic_checksum_version
            or not valid_checksum_version
            or row["format"] != pin.format
            or pin.format != "parquet"
            or row["size_bytes"] != pin.size_bytes
            or row["row_count"] != pin.row_count
            or as_aware_utc(row["event_time_start"]) != pin.event_time_start
            or as_aware_utc(row["event_time_end"]) != pin.event_time_end
            or as_aware_utc(row["available_at_start"]) != pin.available_at_start
            or as_aware_utc(row["available_at_end"]) != pin.available_at_end
            or row["source_id"] != dataset.source_id
            or row["schema_version"] != dataset.schema_version
            or row["price_basis"] != dataset.price_basis
            or row["layer"] != "normalized"
            or row["status"] != "published"
            or row["partition_id"] in quarantined_partition_ids
        ):
            raise _catalog_conflict(f"ordered partition {pin.ordinal} differs")

    manifest_material = {
        "calendar_version": dataset.calendar_version,
        "corporate_action_version": dataset.corporate_action_version,
        "ordered_partitions": [pin.partition_id for pin in dataset.partitions],
        "price_basis": dataset.price_basis,
        "revision_policy": dataset.revision_policy.value,
        "schema_version": dataset.schema_version,
        "source_id": dataset.source_id,
        "universe_version": dataset.universe_version,
    }
    if dataset.schema_version == "raw-bar-v2":
        manifest_material.update(
            {
                "calendar_hash": dataset.calendar_sha256,
                "calendar_hash_version": dataset.calendar_hash_version,
                "corporate_action_hash": dataset.corporate_action_sha256,
                "corporate_action_hash_version": (dataset.corporate_action_hash_version),
                "universe_hash": dataset.universe_sha256,
                "universe_hash_version": dataset.universe_hash_version,
            }
        )
        valid_reference_versions = {
            dataset.calendar_hash_version,
            dataset.universe_hash_version,
            dataset.corporate_action_hash_version,
        } == {_PERSISTED_REFERENCE_HASH_VERSION}
    else:
        valid_reference_versions = dataset.schema_version == "raw-bar-v1" and {
            dataset.calendar_hash_version,
            dataset.universe_hash_version,
            dataset.corporate_action_hash_version,
        } == {_INPUT_REFERENCE_HASH_VERSION}
    expected_manifest_id = _v1_digest(manifest_material)
    if not valid_reference_versions or expected_manifest_id != dataset.manifest_id:
        raise _catalog_conflict("manifest identity cannot be reproduced")

    descriptor = ManifestObjects(
        manifest_id=dataset.manifest_id,
        manifest_hash=dataset.manifest_sha256,
        source_id=dataset.source_id,
        source_kind=dataset.source_kind,
        source_licensed=bool(catalog["source_licensed"]),
        entitlement_statuses=tuple(str(status) for status in entitlement_statuses),
        schema_version=dataset.schema_version,
        calendar_version=dataset.calendar_version,
        calendar_hash=dataset.calendar_sha256,
        calendar_hash_version=dataset.calendar_hash_version,
        calendar_name=str(catalog["calendar_name"]),
        calendar_timezone=str(catalog["calendar_timezone"]),
        calendar_tzdata_version=dataset.tzdata_version,
        universe_version=dataset.universe_version,
        universe_hash=dataset.universe_sha256,
        universe_hash_version=dataset.universe_hash_version,
        corporate_action_version=dataset.corporate_action_version,
        corporate_action_hash=dataset.corporate_action_sha256,
        corporate_action_hash_version=dataset.corporate_action_hash_version,
        revision_policy=dataset.revision_policy.value,
        price_basis=dataset.price_basis,
        row_count=dataset.row_count,
        partitions=tuple(
            ManifestPartitionObject(
                ordinal=pin.ordinal,
                partition_id=pin.partition_id,
                object_id=pin.object_id,
                object_key=pin.object_key,
                byte_checksum=pin.byte_sha256,
                semantic_checksum=pin.semantic_sha256,
                semantic_checksum_version=pin.semantic_checksum_version,
                format=pin.format,
                size_bytes=pin.size_bytes,
                row_count=pin.row_count,
                event_time_start=pin.event_time_start,
                event_time_end=pin.event_time_end,
                available_at_start=pin.available_at_start,
                available_at_end=pin.available_at_end,
            )
            for pin in dataset.partitions
        ),
        calendar_sessions=references.calendar_sessions,
        universe_memberships=references.universe_memberships,
    )
    try:
        canonical_plan = build_replay_tape_plan(
            descriptor,
            event_time_start=plan.coverage_start,
            event_time_end=plan.coverage_end,
            interval=BarInterval(plan.interval),
            decision_lag=plan.decision_lag,
        )
    except (TypeError, ValueError) as error:
        raise _catalog_conflict(f"canonical replay plan cannot be derived: {error}") from error
    if _plan_pin(canonical_plan) != plan:
        raise _catalog_conflict("replay plan differs from locked reference facts")
    return descriptor


def _row_values(manifest: ReplayRunManifest) -> dict[str, object]:
    return {
        "run_id": manifest.run_id,
        "idempotency_key": manifest.input_sha256,
        "dataset_manifest_id": manifest.dataset.manifest_id,
        "dataset_manifest_hash": manifest.dataset.manifest_sha256,
        "manifest_sha256": manifest.manifest_sha256,
        "manifest_payload": manifest.canonical_json,
        "tape_sha256": manifest.tape_sha256,
        "replay_semantic_sha256": manifest.replay_semantic_sha256,
        "started_at": manifest.started_at,
        "completed_at": manifest.completed_at,
        "processed_event_count": manifest.processed_event_count,
        "batch_count": manifest.batch_count,
        "complete_batch_count": manifest.complete_batch_count,
        "skipped_batch_count": manifest.skipped_batch_count,
    }


def _decode_row(row: RowMapping) -> ReplayRunManifest:
    manifest = ReplayRunManifest.from_canonical_json(
        str(row["manifest_payload"]),
        expected_run_id=str(row["run_id"]),
        expected_manifest_sha256=str(row["manifest_sha256"]),
    )
    expected = _row_values(manifest)
    persisted = dict(row)
    for field_name in ("started_at", "completed_at"):
        value = persisted[field_name]
        if not isinstance(value, datetime):
            raise ImmutableFactConflict(
                f"replay_run_manifests fact {manifest.run_id!r} has malformed {field_name}"
            )
        persisted[field_name] = as_aware_utc(value)
    assert_immutable(
        replay_run_manifests,
        manifest.run_id,
        persisted,
        expected,
    )
    return manifest


class SqlReplayRunManifestRepository:
    """Seal and read completed replay evidence without mutable run lifecycle."""

    def __init__(
        self,
        engine: Engine,
        *,
        tape_reader: ManifestReplayTapeReader,
    ) -> None:
        if type(tape_reader) is not ManifestReplayTapeReader:
            raise ValueError("repository requires an exact trusted ManifestReplayTapeReader")
        if tape_reader.catalog_engine is not engine:
            raise ValueError("repository and replay reader must share the exact catalog engine")
        self._engine = engine
        self._tape_reader = tape_reader

    def publish(self, manifest: ReplayRunManifest, tape: ManifestReplayTape) -> bool:
        """Return true once, false for an identical retry, and conflict otherwise."""

        if type(manifest) is not ReplayRunManifest:
            raise ValueError("publish requires an exact ReplayRunManifest")
        if type(tape) is not ManifestReplayTape:
            raise _proof_conflict("publish requires an exact ManifestReplayTape")
        values = _row_values(manifest)
        with self._engine.begin() as connection:
            descriptor = verify_replay_dataset_catalog(
                connection,
                manifest.dataset,
                manifest.plan,
                shared_lock=True,
            )
            try:
                rehydrated_tape = self._tape_reader.read_verified_descriptor(
                    tape.plan,
                    descriptor,
                )
            except (
                AttributeError,
                ImmutableFactConflict,
                ObjectIntegrityError,
                OSError,
                TypeError,
                ValueError,
            ) as error:
                raise _proof_conflict("fresh catalog/object rehydration failed") from error
            _verify_reader_tape_proof(manifest, tape, rehydrated_tape)
            inserted = insert_or_verify_atomic(
                connection,
                replay_run_manifests,
                values,
            )
            persisted = (
                connection.execute(
                    sa.select(replay_run_manifests).where(
                        replay_run_manifests.c.run_id == manifest.run_id
                    )
                )
                .mappings()
                .one()
            )
            if _decode_row(persisted) != manifest:
                raise ImmutableFactConflict("replay manifest read-back changed its semantics")
            return inserted

    def get(self, run_id: str) -> ReplayRunManifest | None:
        with self._engine.begin() as connection:
            statement = sa.select(replay_run_manifests).where(
                replay_run_manifests.c.run_id == run_id
            )
            if connection.dialect.name == "postgresql":
                statement = statement.with_for_update(read=True)
            row = connection.execute(statement).mappings().one_or_none()
            if row is None:
                return None
            manifest = _decode_row(row)
            verify_replay_dataset_catalog(
                connection,
                manifest.dataset,
                manifest.plan,
                shared_lock=True,
            )
            return manifest
