"""Provider-neutral historical ingestion and fail-closed Phase 1B admission."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any

from sqlalchemy import Engine

from packages.adapters.market_data.recorded import RecordedHistoricalBarSource
from packages.adapters.market_data.reference_admission import (
    reference_admission_evidence,
    reference_admission_specification,
)
from packages.adapters.market_data.reference_fixture import (
    admission_profile,
    reference_fixture,
)
from packages.datasets import (
    ARROW_SEMANTIC_CHECKSUM_VERSION,
    INPUT_REFERENCE_HASH_VERSION,
    INPUT_SEMANTIC_CHECKSUM_VERSION,
    NORMALIZED_BAR_SCHEMA,
    PERSISTED_REFERENCE_HASH_VERSION,
    QUARANTINED_RAW_SCHEMA,
    RAW_BAR_SCHEMA,
    LocalParquetObjectStore,
    ParquetObject,
)
from packages.datasets.parquet import canonical_row_bytes
from packages.market_data import (
    AdmissionEvidence,
    AdmissionSpecification,
    AdmissionStatus,
    CorporateActionRevision,
    HistoricalBarSource,
    HistoricalSourceBundle,
    QualityIssue,
    QualitySeverity,
    RawBar,
    RevisionPolicy,
    VendorBarRecord,
    check_quality,
    normalize_records,
)
from packages.persistence.immutable import ImmutableFactConflict
from packages.persistence.market_data import (
    CatalogPublication,
    ManifestObjects,
    ManifestPartitionObject,
    SqlMarketDataCatalog,
)

RAW_SCHEMA_VERSION = "vendor-bar-v1"
LEGACY_NORMALIZED_SCHEMA_VERSION = "raw-bar-v1"
NORMALIZED_SCHEMA_VERSION = "raw-bar-v2"
QUALITY_RULESET_VERSION = "market-data-quality-v1"

AdmissionInputFactory = Callable[
    [HistoricalSourceBundle],
    tuple[AdmissionSpecification, AdmissionEvidence],
]


@dataclass(frozen=True, slots=True)
class _IngestionIntegrityContract:
    normalized_schema_version: str
    semantic_checksum_version: str
    reference_hash_version: str
    binds_integrity_versions: bool


@dataclass(frozen=True, slots=True)
class _SelectedIntegrityContract:
    contract: _IngestionIntegrityContract
    legacy_manifest: ManifestObjects | None = None


_LEGACY_INTEGRITY_CONTRACT = _IngestionIntegrityContract(
    normalized_schema_version=LEGACY_NORMALIZED_SCHEMA_VERSION,
    semantic_checksum_version=INPUT_SEMANTIC_CHECKSUM_VERSION,
    reference_hash_version=INPUT_REFERENCE_HASH_VERSION,
    binds_integrity_versions=False,
)
_CURRENT_INTEGRITY_CONTRACT = _IngestionIntegrityContract(
    normalized_schema_version=NORMALIZED_SCHEMA_VERSION,
    semantic_checksum_version=ARROW_SEMANTIC_CHECKSUM_VERSION,
    reference_hash_version=PERSISTED_REFERENCE_HASH_VERSION,
    binds_integrity_versions=True,
)


class HistoricalSourceProfileMismatch(ValueError):
    """A source bundle contains facts attributed to a different bar source."""


@dataclass(frozen=True, slots=True)
class IngestionOutcome:
    job_id: str
    manifest_id: str | None
    first_publication: bool
    source_record_count: int
    normalized_record_count: int
    quarantined_record_count: int
    partition_checksums: tuple[str, ...]
    admission_run_id: str | None
    admission_status: str | None


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            return value.isoformat()
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in sorted(value.items())}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    return value


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _reference_digest(value: Any, version: str) -> str:
    digest = hashlib.sha256()
    if version == PERSISTED_REFERENCE_HASH_VERSION:
        digest.update(b"autoquanttrader:reference-hash:persisted-v2\n")
    elif version != INPUT_REFERENCE_HASH_VERSION:
        raise ValueError("unsupported ingestion reference hash version")
    digest.update(_json_bytes(value))
    return digest.hexdigest()


def _idempotency_key(
    bundle: HistoricalSourceBundle,
    *,
    policy: RevisionPolicy,
    contract: _IngestionIntegrityContract,
) -> str:
    profile = bundle.profile
    material = {
        "calendar_version": bundle.calendar.version,
        "corporate_action_version": profile.corporate_action_version,
        "normalization_schema": contract.normalized_schema_version,
        "policy": policy.value,
        "quality_ruleset": QUALITY_RULESET_VERSION,
        "source_checksum": bundle.source_checksum,
        "source_id": profile.source_id,
        "universe_version": profile.universe_version,
    }
    if contract.binds_integrity_versions:
        material.update(
            {
                "reference_hash_version": contract.reference_hash_version,
                "semantic_checksum_version": contract.semantic_checksum_version,
            }
        )
    return _digest(material)


def _manifest_identity_material(
    bundle: HistoricalSourceBundle,
    *,
    policy: RevisionPolicy,
    contract: _IngestionIntegrityContract,
    ordered_partition_ids: tuple[str, ...],
    reference_hashes: dict[str, str],
) -> dict[str, object]:
    profile = bundle.profile
    material: dict[str, object] = {
        "calendar_version": bundle.calendar.version,
        "corporate_action_version": profile.corporate_action_version,
        "ordered_partitions": list(ordered_partition_ids),
        "price_basis": "raw",
        "revision_policy": policy.value,
        "schema_version": contract.normalized_schema_version,
        "source_id": profile.source_id,
        "universe_version": profile.universe_version,
    }
    if contract.binds_integrity_versions:
        material.update(
            {
                "calendar_hash": reference_hashes["calendar_hash"],
                "calendar_hash_version": contract.reference_hash_version,
                "corporate_action_hash": reference_hashes["action_hash"],
                "corporate_action_hash_version": contract.reference_hash_version,
                "universe_hash": reference_hashes["universe_hash"],
                "universe_hash_version": contract.reference_hash_version,
            }
        )
    return material


def _select_integrity_contract(
    catalog: SqlMarketDataCatalog,
    bundle: HistoricalSourceBundle,
    *,
    policy: RevisionPolicy,
) -> _SelectedIntegrityContract:
    current_key = _idempotency_key(
        bundle,
        policy=policy,
        contract=_CURRENT_INTEGRITY_CONTRACT,
    )
    if catalog.job_for_idempotency_key(current_key) is not None:
        return _SelectedIntegrityContract(_CURRENT_INTEGRITY_CONTRACT)

    legacy_key = _idempotency_key(
        bundle,
        policy=policy,
        contract=_LEGACY_INTEGRITY_CONTRACT,
    )
    legacy_job = catalog.job_for_idempotency_key(legacy_key)
    if legacy_job is None:
        return _SelectedIntegrityContract(_CURRENT_INTEGRITY_CONTRACT)
    if (
        legacy_job["job_id"] != legacy_key
        or legacy_job["source_id"] != bundle.profile.source_id
        or legacy_job["source_checksum"] != bundle.source_checksum
    ):
        raise ImmutableFactConflict("legacy ingestion job failed its identity pins")

    manifest_id = catalog.manifest_id_for_job(legacy_key)
    if manifest_id is None:
        raise ImmutableFactConflict("legacy ingestion job has no verifiable manifest")
    descriptor = catalog.manifest_objects(manifest_id)
    reference_hashes = _reference_values(bundle, contract=_LEGACY_INTEGRITY_CONTRACT)
    expected_manifest_id = _digest(
        _manifest_identity_material(
            bundle,
            policy=policy,
            contract=_LEGACY_INTEGRITY_CONTRACT,
            ordered_partition_ids=tuple(
                partition.partition_id for partition in descriptor.partitions
            ),
            reference_hashes=reference_hashes,
        )
    )
    profile = bundle.profile
    if (
        descriptor.manifest_id != expected_manifest_id
        or descriptor.manifest_hash != expected_manifest_id
        or descriptor.source_id != bundle.profile.source_id
        or descriptor.source_kind != profile.kind.value
        or descriptor.source_licensed != profile.licensed
        or descriptor.entitlement_statuses != (profile.entitlement_status.value,)
        or descriptor.schema_version != LEGACY_NORMALIZED_SCHEMA_VERSION
        or descriptor.calendar_version != bundle.calendar.version
        or descriptor.calendar_hash != reference_hashes["calendar_hash"]
        or descriptor.calendar_name != bundle.calendar.calendar_id
        or descriptor.calendar_timezone != bundle.calendar.timezone
        or descriptor.calendar_tzdata_version != profile.tzdata_version
        or descriptor.universe_version != profile.universe_version
        or descriptor.universe_hash != reference_hashes["universe_hash"]
        or descriptor.corporate_action_version != profile.corporate_action_version
        or descriptor.corporate_action_hash != reference_hashes["action_hash"]
        or descriptor.revision_policy != policy.value
        or descriptor.price_basis != "raw"
        or len(descriptor.partitions) != 1
        or {
            descriptor.calendar_hash_version,
            descriptor.universe_hash_version,
            descriptor.corporate_action_hash_version,
        }
        != {INPUT_REFERENCE_HASH_VERSION}
        or any(
            partition.semantic_checksum_version != INPUT_SEMANTIC_CHECKSUM_VERSION
            for partition in descriptor.partitions
        )
    ):
        raise ImmutableFactConflict("legacy ingestion manifest failed its contract pins")
    return _SelectedIntegrityContract(_LEGACY_INTEGRITY_CONTRACT, descriptor)


def _identifier_id(source_id: str, observation_id: str, revision: int) -> str:
    return _digest((source_id, observation_id, revision))


def _raw_row(record: VendorBarRecord) -> dict[str, Any]:
    base: dict[str, Any] = {
        "source": record.source_id,
        "source_record_id": record.source_record_id,
        "source_sequence": record.source_sequence,
        "revision": record.revision,
        "supersedes_event_revision_id": record.supersedes_event_revision_id,
        "symbol": record.symbol,
        "venue": record.venue,
        "interval_start": record.interval_start,
        "interval_end": record.interval_end,
        "event_time": record.interval_end,
        "vendor_published_at": record.vendor_published_at,
        "received_at": record.received_at,
        "available_at": record.available_at or record.vendor_published_at,
        "open": record.open_price,
        "high": record.high_price,
        "low": record.low_price,
        "close": record.close_price,
        "volume": record.volume,
        "trade_count": record.trade_count,
        "currency": "USD",
        "schema_version": RAW_SCHEMA_VERSION,
    }
    return {**base, "payload_hash": hashlib.sha256(canonical_row_bytes(base)).hexdigest()}


def _normalized_row(bar: RawBar) -> dict[str, Any]:
    return {
        "event_revision_id": bar.event_revision_id,
        "observation_id": bar.observation_id,
        "instrument_id": bar.security_id,
        "source": bar.source_id,
        "source_record_id": bar.source_record_id,
        "source_sequence": bar.source_sequence,
        "revision": bar.revision,
        "supersedes_event_revision_id": bar.supersedes_event_revision_id,
        "symbol": bar.symbol,
        "venue": bar.venue,
        "session_label": bar.session_label.isoformat(),
        "interval": bar.interval.value,
        "interval_start": bar.interval_start,
        "interval_end": bar.interval_end,
        "event_time": bar.event_time,
        "vendor_published_at": bar.vendor_published_at,
        "received_at": bar.received_at,
        "available_at": bar.available_at,
        "ingested_at": bar.ingested_at,
        "open": bar.open_price,
        "high": bar.high_price,
        "low": bar.low_price,
        "close": bar.close_price,
        "volume": bar.volume,
        "trade_count": bar.trade_count,
        "currency": "USD",
        "price_basis": bar.price_basis.value,
        "capture_mode": bar.capture_mode.value,
        "schema_version": bar.schema_version,
        "payload_hash": bar.payload_sha256,
    }


def _quarantined_row(record: VendorBarRecord, codes: tuple[str, ...]) -> dict[str, Any]:
    payload = {
        "available_at": record.available_at,
        "close": record.close_price,
        "declared_session_label": record.declared_session_label,
        "high": record.high_price,
        "ingested_at": record.ingested_at,
        "interval": record.interval,
        "interval_end": record.interval_end,
        "interval_start": record.interval_start,
        "low": record.low_price,
        "observation_key": record.observation_key,
        "open": record.open_price,
        "received_at": record.received_at,
        "revision": record.revision,
        "source_id": record.source_id,
        "source_record_id": record.source_record_id,
        "source_sequence": record.source_sequence,
        "supersedes_event_revision_id": record.supersedes_event_revision_id,
        "symbol": record.symbol,
        "trade_count": record.trade_count,
        "vendor_published_at": record.vendor_published_at,
        "venue": record.venue,
        "volume": record.volume,
    }
    return {
        "source": record.source_id,
        "source_record_id": record.source_record_id,
        "revision": record.revision,
        "payload_json": _json_bytes(payload).decode("ascii"),
        "rejection_codes": ",".join(sorted(codes)),
    }


def _partition_id(
    *,
    layer: str,
    status: str,
    object_: ParquetObject,
    contract: _IngestionIntegrityContract,
) -> str:
    material = {
        "layer": layer,
        "object_id": object_.object_id,
        "schema": (
            contract.normalized_schema_version if layer == "normalized" else RAW_SCHEMA_VERSION
        ),
        "semantic_checksum": object_.semantic_checksum,
        "status": status,
    }
    if contract.binds_integrity_versions:
        material["semantic_checksum_version"] = object_.semantic_checksum_version
    return _digest(material)


def _object_values(object_: ParquetObject, created_at: datetime) -> dict[str, Any]:
    return {
        "object_id": object_.object_id,
        "object_key": object_.object_key,
        "byte_checksum": object_.byte_checksum,
        "semantic_checksum": object_.semantic_checksum,
        "semantic_checksum_version": object_.semantic_checksum_version,
        "format": "parquet",
        "size_bytes": object_.size_bytes,
        "created_at": created_at,
    }


def _partition_values(
    *,
    partition_id: str,
    object_: ParquetObject,
    job_id: str,
    source_id: str,
    layer: str,
    status: str,
    schema_version: str,
    event_times: tuple[datetime, ...],
    availability_times: tuple[datetime, ...],
    created_at: datetime,
) -> dict[str, Any]:
    return {
        "partition_id": partition_id,
        "object_id": object_.object_id,
        "job_id": job_id,
        "source_id": source_id,
        "layer": layer,
        "status": status,
        "schema_version": schema_version,
        "price_basis": "raw",
        "row_count": object_.row_count,
        "event_time_start": min(event_times),
        "event_time_end": max(event_times),
        "available_at_start": min(availability_times),
        "available_at_end": max(availability_times),
        "semantic_checksum": object_.semantic_checksum,
        "semantic_checksum_version": object_.semantic_checksum_version,
        "created_at": created_at,
    }


def _verify_legacy_retry_receipt(
    descriptor: ManifestObjects,
    *,
    manifest_id: str | None,
    normalized_partition_id: str | None,
    normalized_object: ParquetObject | None,
    partition_rows: list[dict[str, Any]],
) -> None:
    """Match the rebuilt v1 object receipt before the immutable retry transaction."""

    partition_row = next(
        (
            row
            for row in partition_rows
            if row["partition_id"] == normalized_partition_id
            and row["layer"] == "normalized"
            and row["status"] == "published"
        ),
        None,
    )
    if (
        manifest_id is None
        or normalized_partition_id is None
        or normalized_object is None
        or partition_row is None
    ):
        raise ImmutableFactConflict("legacy ingestion retry did not rebuild a published manifest")
    expected_partition = ManifestPartitionObject(
        ordinal=0,
        partition_id=normalized_partition_id,
        object_id=normalized_object.object_id,
        object_key=normalized_object.object_key,
        byte_checksum=normalized_object.byte_checksum,
        semantic_checksum=normalized_object.semantic_checksum,
        semantic_checksum_version=normalized_object.semantic_checksum_version,
        format="parquet",
        size_bytes=normalized_object.size_bytes,
        row_count=normalized_object.row_count,
        event_time_start=partition_row["event_time_start"],
        event_time_end=partition_row["event_time_end"],
        available_at_start=partition_row["available_at_start"],
        available_at_end=partition_row["available_at_end"],
    )
    if (
        descriptor.manifest_id != manifest_id
        or descriptor.manifest_hash != manifest_id
        or descriptor.row_count != normalized_object.row_count
        or descriptor.partitions != (expected_partition,)
    ):
        raise ImmutableFactConflict(
            "legacy ingestion manifest differs from the reconstructed object receipt"
        )


def _reference_values(
    bundle: HistoricalSourceBundle,
    *,
    contract: _IngestionIntegrityContract,
) -> dict[str, Any]:
    if contract.binds_integrity_versions:
        sessions = sorted(
            bundle.calendar.sessions,
            key=lambda item: (item.session_label, item.opens_at, item.closes_at),
        )
        memberships = sorted(
            (item for item in bundle.security_master.memberships if item.included),
            key=lambda item: (
                item.security_id,
                item.effective_from,
                item.effective_to is None,
                item.effective_to or item.effective_from,
                item.available_at,
            ),
        )
    else:
        # Reproduce the pre-0006 receipt exactly. It hashed source ordering and
        # included excluded memberships even though only included rows persisted.
        sessions = list(bundle.calendar.sessions)
        memberships = list(bundle.security_master.memberships)
    calendar_payload = [
        {
            "label": session.session_label,
            "opens_at": session.opens_at,
            "closes_at": session.closes_at,
            "kind": session.kind,
        }
        for session in sessions
    ]
    universe_payload = [
        {
            "security_id": membership.security_id,
            "effective_from": membership.effective_from,
            "effective_to": membership.effective_to,
            "available_at": membership.available_at,
            "included": membership.included,
        }
        for membership in memberships
    ]
    action_payload = [
        {
            "event_revision_id": action.event_revision_id,
            "type": action.action_type,
            "effective_at": action.effective_at,
            "available_at": action.available_at,
            "terms": asdict(action.terms),
        }
        for action in bundle.corporate_actions
    ]
    return {
        "calendar_hash": _reference_digest(calendar_payload, contract.reference_hash_version),
        "universe_hash": _reference_digest(universe_payload, contract.reference_hash_version),
        "action_hash": _reference_digest(action_payload, contract.reference_hash_version),
    }


def _corporate_action_values(action: CorporateActionRevision) -> dict[str, Any]:
    terms = _json_value(asdict(action.terms))
    payload = {
        "action_type": action.action_type.value,
        "announced_at": action.announced_at,
        "available_at": action.available_at,
        "effective_at": action.effective_at,
        "instrument_id": action.security_id,
        "revision": action.revision,
        "terms": terms,
    }
    return {
        "action_revision_id": action.event_revision_id,
        "action_id": action.source_record_id,
        "instrument_id": action.security_id,
        "action_type": action.action_type.value,
        "revision": action.revision,
        "announced_at": action.announced_at,
        "effective_at": action.effective_at,
        "available_at": action.available_at,
        "terms": terms,
        "payload_hash": _digest(payload),
    }


def _issue_record_id(issue: QualityIssue) -> str | None:
    return next((value for key, value in issue.details if key == "source_record_id"), None)


def _quality_values(
    issue: QualityIssue,
    *,
    quality_run_id: str,
    quarantine_partition_id: str | None,
    normalized_partition_id: str | None,
    completed_at: datetime,
) -> dict[str, Any]:
    record_id = _issue_record_id(issue)
    quarantined = issue.blocking
    partition_id = (
        quarantine_partition_id
        if record_id is not None and quarantine_partition_id is not None
        else normalized_partition_id
    )
    details = "; ".join(f"{key}={value}" for key, value in issue.details)
    severity = (
        "error"
        if issue.severity in {QualitySeverity.ERROR, QualitySeverity.CRITICAL}
        else issue.severity.value
    )
    return {
        "issue_id": issue.issue_id,
        "quality_run_id": quality_run_id,
        "partition_id": partition_id,
        "instrument_id": issue.security_id,
        "record_key": record_id or issue.observation_id,
        "session_label": None if issue.session_label is None else issue.session_label.isoformat(),
        "code": issue.code.value,
        "severity": severity,
        "status": "open",
        "summary": issue.code.value.replace("_", " ").title(),
        "detail": issue.message if not details else f"{issue.message} ({details})",
        "detected_at": issue.occurred_at or completed_at,
        "quarantined": quarantined,
    }


def ingest_historical_source(
    *,
    engine: Engine,
    data_lake_path: Path,
    source: HistoricalBarSource,
    admission_input_factory: AdmissionInputFactory | None = None,
) -> IngestionOutcome:
    bundle = source.load()
    profile = bundle.profile
    records = bundle.records
    mismatched_source_ids = sorted(
        {record.source_id for record in records if record.source_id != profile.source_id}
    )
    if mismatched_source_ids:
        raise HistoricalSourceProfileMismatch(
            "historical bar records do not match admission profile "
            f"{profile.source_id!r}: {mismatched_source_ids!r}"
        )
    admission_specification: AdmissionSpecification | None = None
    admission_evidence: AdmissionEvidence | None = None
    admission_report = None
    if admission_input_factory is not None:
        admission_specification, admission_evidence = admission_input_factory(bundle)
        if admission_evidence.source_id != profile.source_id:
            raise HistoricalSourceProfileMismatch(
                "admission evidence source_id does not match the historical source profile"
            )
        frozen_profile = (
            admission_specification.source_id,
            admission_specification.identifier_authority,
            admission_specification.universe_version,
            admission_specification.calendar_version,
            admission_specification.corporate_action_version,
        )
        actual_profile = (
            profile.source_id,
            profile.identifier_authority,
            profile.universe_version,
            bundle.calendar.version,
            profile.corporate_action_version,
        )
        if frozen_profile != actual_profile:
            raise HistoricalSourceProfileMismatch(
                "admission specification does not match the historical source profile"
            )
        from packages.market_data import evaluate_admission

        admission_report = evaluate_admission(
            admission_specification,
            admission_evidence,
        )
    source_checksum = bundle.source_checksum
    policy = RevisionPolicy.REVISED_AS_OF
    catalog = SqlMarketDataCatalog(engine)
    selection = _select_integrity_contract(
        catalog,
        bundle,
        policy=policy,
    )
    contract = selection.contract
    idempotency_key = _idempotency_key(
        bundle,
        policy=policy,
        contract=contract,
    )
    job_id = idempotency_key
    normalized = normalize_records(
        records,
        calendar=bundle.calendar,
        security_master=bundle.security_master,
        schema_version=contract.normalized_schema_version,
    )
    as_of = max(
        (bar.available_at for bar in normalized.bars),
        default=profile.captured_at,
    )
    dataset_issues = check_quality(
        normalized.bars,
        calendar=bundle.calendar,
        as_of=as_of,
        revision_policy=policy,
        stale_after=timedelta(minutes=5),
    )
    issues = tuple(sorted((*normalized.issues, *dataset_issues), key=lambda item: item.issue_id))
    normalized_blocked = any(issue.blocking for issue in dataset_issues)

    accepted_keys = {(bar.source_id, bar.source_record_id, bar.revision) for bar in normalized.bars}
    accepted_records = tuple(
        record
        for record in records
        if (record.source_id, record.source_record_id, record.revision) in accepted_keys
    )
    rejected_records = tuple(
        record
        for record in records
        if (record.source_id, record.source_record_id, record.revision) not in accepted_keys
    )
    codes_by_record: dict[str, list[str]] = {}
    for issue in normalized.issues:
        record_id = _issue_record_id(issue)
        if record_id is not None:
            codes_by_record.setdefault(record_id, []).append(issue.code.value)

    object_store = LocalParquetObjectStore(data_lake_path)
    object_entries: list[
        tuple[str, str, ParquetObject, tuple[datetime, ...], tuple[datetime, ...]]
    ] = []
    if accepted_records:
        raw_object = object_store.write(
            layer="raw",
            rows=[_raw_row(record) for record in accepted_records],
            schema=RAW_BAR_SCHEMA,
            semantic_checksum_version=contract.semantic_checksum_version,
        )
        object_store.verify(raw_object)
        object_entries.append(
            (
                "raw",
                "published",
                raw_object,
                tuple(record.interval_end for record in accepted_records),
                tuple(
                    record.available_at or record.vendor_published_at for record in accepted_records
                ),
            )
        )
    normalized_object: ParquetObject | None = None
    if normalized.bars:
        normalized_object = object_store.write(
            layer="normalized",
            rows=[_normalized_row(bar) for bar in normalized.bars],
            schema=NORMALIZED_BAR_SCHEMA,
            semantic_checksum_version=contract.semantic_checksum_version,
        )
        object_store.verify(normalized_object)
        object_entries.append(
            (
                "normalized",
                "quarantined" if normalized_blocked else "published",
                normalized_object,
                tuple(bar.event_time for bar in normalized.bars),
                tuple(bar.available_at for bar in normalized.bars),
            )
        )
    quarantine_object: ParquetObject | None = None
    if rejected_records:
        quarantine_object = object_store.write(
            layer="raw",
            rows=[
                _quarantined_row(
                    record,
                    tuple(codes_by_record.get(record.source_record_id, ["normalization_error"])),
                )
                for record in rejected_records
            ],
            schema=QUARANTINED_RAW_SCHEMA,
            semantic_checksum_version=contract.semantic_checksum_version,
        )
        object_store.verify(quarantine_object)
        object_entries.append(
            (
                "raw",
                "quarantined",
                quarantine_object,
                tuple(record.interval_end for record in rejected_records),
                tuple(
                    record.available_at or record.vendor_published_at for record in rejected_records
                ),
            )
        )

    partition_rows: list[dict[str, Any]] = []
    partition_ids: dict[tuple[str, str], str] = {}
    for layer, status, object_, event_times, availability_times in object_entries:
        partition_id = _partition_id(
            layer=layer,
            status=status,
            object_=object_,
            contract=contract,
        )
        partition_ids[(layer, status)] = partition_id
        partition_rows.append(
            _partition_values(
                partition_id=partition_id,
                object_=object_,
                job_id=job_id,
                source_id=profile.source_id,
                layer=layer,
                status=status,
                schema_version=(
                    contract.normalized_schema_version
                    if layer == "normalized"
                    else RAW_SCHEMA_VERSION
                ),
                event_times=event_times,
                availability_times=availability_times,
                created_at=profile.captured_at,
            )
        )

    normalized_partition_id = partition_ids.get(
        ("normalized", "quarantined" if normalized_blocked else "published")
    )
    quarantine_partition_id = partition_ids.get(("raw", "quarantined"))
    manifest_id: str | None = None
    manifest: dict[str, Any] | None = None
    manifest_members: tuple[dict[str, Any], ...] = ()
    hashes = _reference_values(bundle, contract=contract)
    if normalized_partition_id is not None and not normalized_blocked:
        manifest_material = _manifest_identity_material(
            bundle,
            policy=policy,
            contract=contract,
            ordered_partition_ids=(normalized_partition_id,),
            reference_hashes=hashes,
        )
        manifest_id = _digest(manifest_material)
        manifest = {
            "manifest_id": manifest_id,
            "name": profile.manifest_name,
            "manifest_hash": manifest_id,
            "source_id": profile.source_id,
            "schema_version": contract.normalized_schema_version,
            "calendar_version": bundle.calendar.version,
            "universe_version": profile.universe_version,
            "corporate_action_version": profile.corporate_action_version,
            "revision_policy": policy.value,
            "price_basis": "raw",
            "created_at": profile.captured_at,
            "row_count": len(normalized.bars),
        }
        manifest_members = (
            {
                "manifest_id": manifest_id,
                "ordinal": 0,
                "partition_id": normalized_partition_id,
            },
        )

    if (
        admission_report is not None
        and admission_report.status is AdmissionStatus.ADMITTED
        and manifest_id is None
    ):
        raise HistoricalSourceProfileMismatch(
            "admitted market-data evidence requires a published immutable manifest"
        )

    action_values = tuple(_corporate_action_values(action) for action in bundle.corporate_actions)
    quality_run_id = _digest((QUALITY_RULESET_VERSION, job_id))
    quality_values = tuple(
        _quality_values(
            issue,
            quality_run_id=quality_run_id,
            quarantine_partition_id=quarantine_partition_id,
            normalized_partition_id=normalized_partition_id,
            completed_at=profile.captured_at,
        )
        for issue in issues
    )
    quarantined_rows = tuple(row for row in partition_rows if row["status"] == "quarantined")
    admission_profile_values: dict[str, Any] | None = None
    admission_run_values: dict[str, Any] | None = None
    admission_check_values: tuple[dict[str, Any], ...] = ()
    if (
        admission_specification is not None
        and admission_evidence is not None
        and admission_report is not None
    ):
        specification_digest = _digest(
            {
                "adapter_type": profile.adapter_type,
                "calendar_version": admission_specification.calendar_version,
                "corporate_action_version": admission_specification.corporate_action_version,
                "coverage_end": profile.coverage_end,
                "coverage_start": profile.coverage_start,
                "frozen_at": admission_specification.frozen_at,
                "identifier_authority": admission_specification.identifier_authority,
                "required_checks": sorted(admission_specification.required_checks),
                "required_symbols": profile.required_symbols,
                "source_id": profile.source_id,
                "specification_id": admission_specification.specification_id,
                "universe_version": admission_specification.universe_version,
            }
        )
        admission_profile_values = {
            "profile_id": specification_digest,
            "source_id": profile.source_id,
            "name": admission_specification.specification_id,
            "adapter_type": profile.adapter_type,
            "identifier_authority": admission_specification.identifier_authority,
            "universe_version": admission_specification.universe_version,
            "calendar_version": admission_specification.calendar_version,
            "corporate_action_version": admission_specification.corporate_action_version,
            "coverage_start": profile.coverage_start,
            "coverage_end": profile.coverage_end,
            "required_symbols": list(profile.required_symbols),
            "required_checks": sorted(admission_specification.required_checks),
            "specification_digest": specification_digest,
            "created_at": admission_specification.frozen_at,
        }
        approval = admission_evidence.approval
        passed_check_count = sum(
            check.status.value == "passed" for check in admission_report.checks
        )
        failed_check_count = sum(
            check.status.value == "failed" for check in admission_report.checks
        )
        pending_check_count = sum(
            check.status.value == "pending" for check in admission_report.checks
        )
        status_detail = {
            AdmissionStatus.BLOCKED: (
                "Source is blocked by licensing, entitlement, frozen-profile, or fixture gates."
            ),
            AdmissionStatus.REVIEW_PENDING: (
                "Technical and entitlement gates passed; independent approval is required."
            ),
            AdmissionStatus.ADMITTED: (
                "Licensed source passed all frozen checks and independent review."
            ),
            AdmissionStatus.REJECTED: (
                "Technical evidence or independent review rejected the source."
            ),
        }[admission_report.status]
        admission_run_values = {
            "admission_run_id": admission_report.run_id,
            "profile_id": specification_digest,
            "source_id": profile.source_id,
            "manifest_id": manifest_id,
            "status": admission_report.status.value,
            "executed_at": admission_report.evaluated_at,
            "executed_by": admission_evidence.executor_id,
            "reviewed_at": None if approval is None else approval.reviewed_at,
            "reviewed_by": None if approval is None else approval.reviewer_id,
            "review_decision": None if approval is None else approval.decision.value,
            "evidence_digest": admission_report.evidence_digest,
            "report_digest": admission_report.report_digest,
            "passed_check_count": passed_check_count,
            "failed_check_count": failed_check_count,
            "pending_check_count": pending_check_count,
            "detail": status_detail,
        }
        technical_observed_at = {
            f"technical:{check.check_id}": check.checked_at
            for check in admission_evidence.technical_checks
        }
        admission_check_values = tuple(
            {
                "admission_run_id": admission_report.run_id,
                "code": check.check_id,
                "status": check.status.value,
                "evidence_digest": (
                    check.evidence_digest
                    if check.evidence_digest is not None
                    else admission_report.evidence_digest
                    if check.status.value == "passed"
                    else None
                ),
                "detail": check.detail,
                "observed_at": technical_observed_at.get(
                    check.check_id,
                    (
                        approval.reviewed_at
                        if check.check_id == "independent_approval" and approval is not None
                        else admission_report.evaluated_at
                    ),
                ),
            }
            for check in admission_report.checks
        )
    if selection.legacy_manifest is not None:
        _verify_legacy_retry_receipt(
            selection.legacy_manifest,
            manifest_id=manifest_id,
            normalized_partition_id=normalized_partition_id,
            normalized_object=normalized_object,
            partition_rows=partition_rows,
        )

    publication = CatalogPublication(
        source={
            "source_id": profile.source_id,
            "name": profile.source_name,
            "provider": profile.provider,
            "dataset": profile.dataset,
            "feed": profile.feed,
            "kind": profile.kind.value,
            "licensed": profile.licensed,
            "detail": profile.detail,
            "created_at": profile.captured_at,
        },
        entitlements=(
            {
                "entitlement_id": bundle.entitlement.entitlement_id,
                "source_id": bundle.entitlement.source_id,
                "status": profile.entitlement_status.value,
                "scope": profile.entitlement_scope,
                "effective_from": bundle.entitlement.effective_from,
                "effective_to": bundle.entitlement.effective_to,
                "terms_digest": bundle.entitlement.terms_sha256,
                "observed_at": bundle.entitlement.recorded_at,
            },
        ),
        instruments=tuple(
            {
                "instrument_id": security.security_id,
                "name": security.name,
                "asset_class": security.asset_class.value,
                "currency": security.currency,
                "created_at": profile.captured_at,
            }
            for security in bundle.security_master.securities
        ),
        identifiers=tuple(
            {
                "identifier_id": _identifier_id(
                    identifier.source_id,
                    identifier.observation_id,
                    identifier.revision,
                ),
                "instrument_id": identifier.security_id,
                "source_id": identifier.source_id,
                "symbol": identifier.symbol,
                "venue": identifier.venue,
                "effective_from": identifier.effective_from,
                "effective_to": identifier.effective_to,
                "available_at": identifier.available_at,
                "tradable": identifier.tradable,
                "revision": identifier.revision,
            }
            for identifier in bundle.security_master.identifiers
        ),
        universe={
            "universe_version": profile.universe_version,
            "name": profile.universe_name,
            "effective_as_of": profile.captured_at,
            "created_at": profile.captured_at,
            "content_hash": hashes["universe_hash"],
            "content_hash_version": contract.reference_hash_version,
        },
        memberships=tuple(
            {
                "universe_version": profile.universe_version,
                "instrument_id": membership.security_id,
                "included_from": membership.effective_from,
                "included_to": membership.effective_to,
                "available_at": membership.available_at,
            }
            for membership in bundle.security_master.memberships
            if membership.included
        ),
        calendar={
            "calendar_version": bundle.calendar.version,
            "name": bundle.calendar.calendar_id,
            "timezone": bundle.calendar.timezone,
            "tzdata_version": profile.tzdata_version,
            "content_hash": hashes["calendar_hash"],
            "content_hash_version": contract.reference_hash_version,
            "created_at": profile.captured_at,
        },
        sessions=tuple(
            {
                "calendar_version": bundle.calendar.version,
                "session_label": session.session_label.isoformat(),
                "opens_at": session.opens_at,
                "closes_at": session.closes_at,
                "half_day": session.kind.value == "half_day",
            }
            for session in bundle.calendar.sessions
        ),
        corporate_actions=action_values,
        corporate_action_set={
            "corporate_action_version": profile.corporate_action_version,
            "name": profile.corporate_action_set_name,
            "content_hash": hashes["action_hash"],
            "content_hash_version": contract.reference_hash_version,
            "created_at": profile.captured_at,
        },
        corporate_action_members=tuple(
            {
                "corporate_action_version": profile.corporate_action_version,
                "ordinal": ordinal,
                "action_revision_id": action["action_revision_id"],
            }
            for ordinal, action in enumerate(action_values)
        ),
        job={
            "job_id": job_id,
            "idempotency_key": idempotency_key,
            "source_id": profile.source_id,
            "source_checksum": source_checksum,
            "status": "completed_with_issues" if issues else "completed",
            "started_at": profile.captured_at,
            "completed_at": profile.captured_at,
            "source_record_count": len(records),
            "normalized_record_count": len(normalized.bars),
            "published_partition_count": sum(
                1 for row in partition_rows if row["status"] == "published"
            ),
            "quarantined_record_count": len(rejected_records)
            + (len(normalized.bars) if normalized_blocked else 0),
            "error_message": None,
        },
        objects=tuple(_object_values(entry[2], profile.captured_at) for entry in object_entries),
        partitions=tuple(partition_rows),
        quality_run={
            "quality_run_id": quality_run_id,
            "job_id": job_id,
            "ruleset_version": QUALITY_RULESET_VERSION,
            "status": (
                "failed"
                if any(issue.blocking for issue in issues)
                else "warning"
                if issues
                else "passed"
            ),
            "completed_at": profile.captured_at,
        },
        quality_issues=quality_values,
        quarantines=tuple(
            {
                "partition_id": row["partition_id"],
                "reason": "Blocking quality findings excluded this partition from manifests.",
                "quarantined_at": profile.captured_at,
                "row_count": row["row_count"],
            }
            for row in quarantined_rows
        ),
        manifest=manifest,
        manifest_partitions=manifest_members,
        admission_profile=admission_profile_values,
        admission_run=admission_run_values,
        admission_checks=admission_check_values,
    )
    first_publication = catalog.publish(publication)
    return IngestionOutcome(
        job_id=job_id,
        manifest_id=manifest_id,
        first_publication=first_publication,
        source_record_count=len(records),
        normalized_record_count=len(normalized.bars),
        quarantined_record_count=len(rejected_records),
        partition_checksums=tuple(sorted(entry[2].byte_checksum for entry in object_entries)),
        admission_run_id=None if admission_report is None else admission_report.run_id,
        admission_status=(None if admission_report is None else admission_report.status.value),
    )


def ingest_recorded_fixture(
    *,
    engine: Engine,
    data_lake_path: Path,
    source_path: Path,
) -> IngestionOutcome:
    """Retain the Phase 1A synthetic entry point over the generic workflow."""

    fixture = reference_fixture()
    source = RecordedHistoricalBarSource(
        source_path,
        profile=admission_profile(),
        security_master=fixture.security_master,
        calendar=fixture.calendar,
        corporate_actions=fixture.corporate_actions,
        entitlement=fixture.entitlement,
    )
    return ingest_historical_source(
        engine=engine,
        data_lake_path=data_lake_path,
        source=source,
        admission_input_factory=lambda bundle: (
            reference_admission_specification(bundle),
            reference_admission_evidence(bundle),
        ),
    )
