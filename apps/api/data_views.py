"""Strict Phase 1A data-catalog database-to-HTTP projections."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from apps.api.contracts import (
    CorporateActionView,
    DataCatalogResponse,
    DataQualityIssueView,
    DataQualityResponse,
    DatasetManifestView,
    DatasetPartitionView,
    DataSourceView,
    EntitlementView,
    IngestionJobView,
    InstrumentIdentifierView,
    InstrumentView,
    MarketDataAdmissionCheckView,
    MarketDataAdmissionView,
    QuarantineView,
)
from packages.persistence.market_data import CatalogRows, QualityRows


class DataCatalogDecodeError(ValueError):
    """Persisted catalog metadata does not satisfy its strict read contract."""


def _value[T](row: dict[str, Any], name: str, expected: type[T]) -> T:
    value = row.get(name)
    if not isinstance(value, expected):
        raise DataCatalogDecodeError(f"catalog field {name!r} is malformed")
    return value


def _optional_datetime(row: dict[str, Any], name: str) -> datetime | None:
    value = row.get(name)
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise DataCatalogDecodeError(f"catalog field {name!r} is malformed")
    return value


def _optional_string(row: dict[str, Any], name: str) -> str | None:
    value = row.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise DataCatalogDecodeError(f"catalog field {name!r} is malformed")
    return value


def _string_list(row: dict[str, Any], name: str) -> list[str]:
    value = row.get(name)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise DataCatalogDecodeError(f"catalog field {name!r} is malformed")
    return value


def _integer(row: dict[str, Any], name: str) -> int:
    value = row.get(name)
    if type(value) is not int:
        raise DataCatalogDecodeError(f"catalog field {name!r} is malformed")
    return value


def _boolean(row: dict[str, Any], name: str) -> bool:
    value = row.get(name)
    if type(value) is not bool:
        raise DataCatalogDecodeError(f"catalog field {name!r} is malformed")
    return value


def _action_detail(action_type: str, terms_value: object) -> str:
    if not isinstance(terms_value, dict) or not all(isinstance(key, str) for key in terms_value):
        raise DataCatalogDecodeError("corporate-action terms are malformed")
    terms: dict[str, object] = terms_value
    expected: dict[str, tuple[str, ...]] = {
        "split": ("denominator", "numerator"),
        "cash_dividend": ("amount", "currency"),
        "merger": ("cash_amount", "currency", "share_ratio", "target_security_id"),
        "symbol_change": ("new_symbol", "new_venue"),
        "delisting": ("reason",),
    }
    required = expected.get(action_type)
    if required is None or set(terms) != set(required):
        raise DataCatalogDecodeError("corporate-action type or terms are unsupported")
    if action_type == "split":
        return f"{terms['numerator']} for {terms['denominator']} split"
    if action_type == "cash_dividend":
        return f"{terms['amount']} {terms['currency']} cash dividend"
    if action_type == "merger":
        return (
            f"Merger into {terms['target_security_id']}; share ratio "
            f"{terms['share_ratio']}, cash {terms['cash_amount']} {terms['currency']}"
        )
    if action_type == "symbol_change":
        return f"Symbol changes to {terms['new_symbol']} on {terms['new_venue']}"
    return f"Delisted: {terms['reason']}"


def catalog_response(rows: CatalogRows) -> DataCatalogResponse:
    source_rows = {_value(row, "source_id", str): row for row in rows.sources}
    entitlements = [
        EntitlementView(
            source_id=_value(row, "source_id", str),
            feed=_value(
                source_rows[_value(row, "source_id", str)],
                "feed",
                str,
            ),
            licensed=_boolean(
                source_rows[_value(row, "source_id", str)],
                "licensed",
            ),
            status=_value(row, "status", str),
            scope=_value(row, "scope", str),
            verified_at=_optional_datetime(row, "observed_at"),
        )
        for row in rows.entitlements
    ]
    source: DataSourceView | None = None
    if rows.sources:
        source_row = rows.sources[0]
        source_id = _value(source_row, "source_id", str)
        status = next(
            (
                entitlement.status
                for entitlement in entitlements
                if entitlement.source_id == source_id
            ),
            "not_configured",
        )
        source = DataSourceView(
            source_id=source_id,
            name=_value(source_row, "name", str),
            kind=_value(source_row, "kind", str),
            licensed=_boolean(source_row, "licensed"),
            entitlement_status=status,
            detail=_value(source_row, "detail", str),
        )

    partitions_by_manifest: dict[str, list[DatasetPartitionView]] = defaultdict(list)
    for row in rows.manifest_partitions:
        manifest_id = _value(row, "manifest_id", str)
        partitions_by_manifest[manifest_id].append(
            DatasetPartitionView(
                partition_id=_value(row, "partition_id", str),
                ordinal=_integer(row, "ordinal"),
                layer=_value(row, "layer", str),
                object_key=_value(row, "object_key", str),
                checksum=_value(row, "byte_checksum", str),
                row_count=_integer(row, "row_count"),
                event_time_start=_value(row, "event_time_start", datetime),
                event_time_end=_value(row, "event_time_end", datetime),
                available_at_start=_value(row, "available_at_start", datetime),
                available_at_end=_value(row, "available_at_end", datetime),
                quality_status=(
                    "passed" if _value(row, "status", str) == "published" else "quarantined"
                ),
            )
        )

    identifiers_by_instrument: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows.identifiers:
        identifiers_by_instrument[_value(row, "instrument_id", str)].append(row)
    instruments: list[InstrumentView] = []
    for row in rows.instruments:
        instrument_id = _value(row, "instrument_id", str)
        identifier_rows = identifiers_by_instrument[instrument_id]
        if not identifier_rows:
            raise DataCatalogDecodeError("instrument is missing effective-dated identifiers")
        mappings = [
            InstrumentIdentifierView(
                symbol=_value(identifier, "symbol", str),
                venue=_value(identifier, "venue", str),
                valid_from=_value(identifier, "effective_from", datetime),
                valid_to=_optional_datetime(identifier, "effective_to"),
                available_at=_value(identifier, "available_at", datetime),
                tradable=_boolean(identifier, "tradable"),
            )
            for identifier in identifier_rows
        ]
        non_tradable_starts = [mapping.valid_from for mapping in mappings if not mapping.tradable]
        delisted_at = min(non_tradable_starts) if non_tradable_starts else None
        instruments.append(
            InstrumentView(
                instrument_id=instrument_id,
                name=_value(row, "name", str),
                asset_class=_value(row, "asset_class", str),
                currency=_value(row, "currency", str),
                status="delisted" if delisted_at is not None else "active",
                listed_at=min(mapping.valid_from for mapping in mappings),
                delisted_at=delisted_at,
                mappings=mappings,
            )
        )

    def symbol_for(instrument_id: str, effective_at: datetime) -> str:
        def is_effective(mapping: dict[str, Any]) -> bool:
            effective_to = _optional_datetime(mapping, "effective_to")
            return _value(mapping, "effective_from", datetime) <= effective_at and (
                effective_to is None or effective_at < effective_to
            )

        candidates = [
            mapping for mapping in identifiers_by_instrument[instrument_id] if is_effective(mapping)
        ]
        return _value(candidates[-1], "symbol", str) if candidates else instrument_id

    actions = [
        CorporateActionView(
            action_revision_id=_value(row, "action_revision_id", str),
            action_id=_value(row, "action_id", str),
            instrument_id=_value(row, "instrument_id", str),
            symbol=symbol_for(
                _value(row, "instrument_id", str),
                _value(row, "effective_at", datetime),
            ),
            action_type=_value(row, "action_type", str),
            revision=_integer(row, "revision"),
            effective_at=_value(row, "effective_at", datetime),
            available_at=_value(row, "available_at", datetime),
            detail=_action_detail(
                _value(row, "action_type", str),
                row.get("terms"),
            ),
        )
        for row in rows.corporate_actions
    ]
    profiles_by_id = {_value(row, "profile_id", str): row for row in rows.admission_profiles}
    admission_checks: dict[str, list[MarketDataAdmissionCheckView]] = defaultdict(list)
    for row in rows.admission_checks:
        admission_checks[_value(row, "admission_run_id", str)].append(
            MarketDataAdmissionCheckView(
                code=_value(row, "code", str),
                status=_value(row, "status", str),
                detail=_value(row, "detail", str),
                evidence_digest=_optional_string(row, "evidence_digest"),
                observed_at=_value(row, "observed_at", datetime),
            )
        )
    admissions: list[MarketDataAdmissionView] = []
    for row in rows.admission_runs:
        profile_id = _value(row, "profile_id", str)
        profile = profiles_by_id.get(profile_id)
        if profile is None:
            raise DataCatalogDecodeError("admission run is missing its immutable profile")
        admission_run_id = _value(row, "admission_run_id", str)
        admissions.append(
            MarketDataAdmissionView(
                admission_run_id=admission_run_id,
                profile_id=profile_id,
                source_id=_value(row, "source_id", str),
                manifest_id=_optional_string(row, "manifest_id"),
                status=_value(row, "status", str),
                profile_name=_value(profile, "name", str),
                adapter_type=_value(profile, "adapter_type", str),
                identifier_authority=_value(profile, "identifier_authority", str),
                universe_version=_value(profile, "universe_version", str),
                calendar_version=_value(profile, "calendar_version", str),
                corporate_action_version=_value(
                    profile,
                    "corporate_action_version",
                    str,
                ),
                coverage_start=_value(profile, "coverage_start", datetime),
                coverage_end=_value(profile, "coverage_end", datetime),
                required_symbols=_string_list(profile, "required_symbols"),
                specification_digest=_value(profile, "specification_digest", str),
                evidence_digest=_value(row, "evidence_digest", str),
                report_digest=_value(row, "report_digest", str),
                executed_at=_value(row, "executed_at", datetime),
                executed_by=_value(row, "executed_by", str),
                reviewed_at=_optional_datetime(row, "reviewed_at"),
                reviewed_by=_optional_string(row, "reviewed_by"),
                review_decision=_optional_string(row, "review_decision"),
                passed_check_count=_integer(row, "passed_check_count"),
                failed_check_count=_integer(row, "failed_check_count"),
                pending_check_count=_integer(row, "pending_check_count"),
                detail=_value(row, "detail", str),
                checks=admission_checks[admission_run_id],
            )
        )
    return DataCatalogResponse(
        as_of=rows.as_of,
        source=source,
        jobs=[
            IngestionJobView(
                job_id=_value(row, "job_id", str),
                status=_value(row, "status", str),
                source_id=_value(row, "source_id", str),
                started_at=_value(row, "started_at", datetime),
                completed_at=_optional_datetime(row, "completed_at"),
                source_record_count=_integer(row, "source_record_count"),
                normalized_record_count=_integer(row, "normalized_record_count"),
                published_partition_count=_integer(row, "published_partition_count"),
                quarantined_record_count=_integer(row, "quarantined_record_count"),
            )
            for row in rows.jobs
        ],
        manifests=[
            DatasetManifestView(
                manifest_id=_value(row, "manifest_id", str),
                name=_value(row, "name", str),
                manifest_hash=_value(row, "manifest_hash", str),
                schema_version=_value(row, "schema_version", str),
                calendar_version=_value(row, "calendar_version", str),
                universe_version=_value(row, "universe_version", str),
                corporate_action_version=_value(row, "corporate_action_version", str),
                revision_policy=_value(row, "revision_policy", str),
                price_basis=_value(row, "price_basis", str),
                created_at=_value(row, "created_at", datetime),
                row_count=_integer(row, "row_count"),
                partitions=partitions_by_manifest[_value(row, "manifest_id", str)],
            )
            for row in rows.manifests
        ],
        instruments=instruments,
        corporate_actions=actions,
        entitlements=entitlements,
        admissions=admissions,
    )


def quality_response(rows: QualityRows) -> DataQualityResponse:
    return DataQualityResponse(
        as_of=rows.as_of,
        issues=[
            DataQualityIssueView(
                issue_id=_value(row, "issue_id", str),
                code=_value(row, "code", str),
                severity=_value(row, "severity", str),
                status=_value(row, "status", str),
                summary=_value(row, "summary", str),
                detail=_value(row, "detail", str),
                detected_at=_value(row, "detected_at", datetime),
                partition_id=(
                    None if row.get("partition_id") is None else _value(row, "partition_id", str)
                ),
                quarantined=_boolean(row, "quarantined"),
            )
            for row in rows.issues
        ],
        quarantine=[
            QuarantineView(
                partition_id=_value(row, "partition_id", str),
                reason=_value(row, "reason", str),
                quarantined_at=_value(row, "quarantined_at", datetime),
                row_count=_integer(row, "row_count"),
            )
            for row in rows.quarantines
        ],
    )
