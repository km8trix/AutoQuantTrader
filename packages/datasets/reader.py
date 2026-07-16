"""Manifest-pinned causal reads from normalized Parquet partitions."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Any

from packages.datasets.parquet import LocalParquetObjectStore
from packages.market_data import (
    BarInterval,
    CaptureMode,
    PriceBasis,
    RawBar,
    RevisionPolicy,
    select_as_of,
)
from packages.persistence.market_data import SqlMarketDataCatalog


class DatasetDecodeError(ValueError):
    """A normalized partition does not satisfy the pinned raw-bar schema."""


def _required[T](row: dict[str, Any], name: str, expected: type[T]) -> T:
    value = row.get(name)
    if not isinstance(value, expected):
        raise DatasetDecodeError(f"normalized field {name!r} is malformed")
    return value


def _optional_string(row: dict[str, Any], name: str) -> str | None:
    value = row.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise DatasetDecodeError(f"normalized field {name!r} is malformed")
    return value


def _optional_integer(row: dict[str, Any], name: str) -> int | None:
    value = row.get(name)
    if value is None:
        return None
    if type(value) is not int:
        raise DatasetDecodeError(f"normalized field {name!r} is malformed")
    return value


def _integer(row: dict[str, Any], name: str) -> int:
    value = row.get(name)
    if type(value) is not int:
        raise DatasetDecodeError(f"normalized field {name!r} is malformed")
    return value


def _bar(row: dict[str, Any]) -> RawBar:
    try:
        return RawBar(
            observation_id=_required(row, "observation_id", str),
            event_revision_id=_required(row, "event_revision_id", str),
            security_id=_required(row, "instrument_id", str),
            source_id=_required(row, "source", str),
            source_record_id=_required(row, "source_record_id", str),
            source_sequence=_optional_integer(row, "source_sequence"),
            schema_version=_required(row, "schema_version", str),
            revision=_integer(row, "revision"),
            supersedes_event_revision_id=_optional_string(row, "supersedes_event_revision_id"),
            payload_sha256=_required(row, "payload_hash", str),
            symbol=_required(row, "symbol", str),
            venue=_required(row, "venue", str),
            interval=BarInterval(_required(row, "interval", str)),
            price_basis=PriceBasis(_required(row, "price_basis", str)),
            interval_start=_required(row, "interval_start", datetime),
            interval_end=_required(row, "interval_end", datetime),
            event_time=_required(row, "event_time", datetime),
            vendor_published_at=_required(row, "vendor_published_at", datetime),
            received_at=(
                None if row.get("received_at") is None else _required(row, "received_at", datetime)
            ),
            available_at=_required(row, "available_at", datetime),
            ingested_at=_required(row, "ingested_at", datetime),
            capture_mode=CaptureMode(_required(row, "capture_mode", str)),
            session_label=date.fromisoformat(_required(row, "session_label", str)),
            open_price=Decimal(_required(row, "open", Decimal)),
            high_price=Decimal(_required(row, "high", Decimal)),
            low_price=Decimal(_required(row, "low", Decimal)),
            close_price=Decimal(_required(row, "close", Decimal)),
            volume=_integer(row, "volume"),
            trade_count=_optional_integer(row, "trade_count"),
        )
    except (TypeError, ValueError) as error:
        raise DatasetDecodeError("normalized raw-bar row is malformed") from error


class ManifestBarReader:
    """Requires an immutable manifest and explicit causal clock for every read."""

    def __init__(
        self,
        *,
        catalog: SqlMarketDataCatalog,
        object_store: LocalParquetObjectStore,
    ) -> None:
        self._catalog = catalog
        self._object_store = object_store

    def bars_as_of(self, *, manifest_id: str, as_of: datetime) -> tuple[RawBar, ...]:
        descriptor = self._catalog.manifest_objects(manifest_id)
        if descriptor.price_basis != PriceBasis.RAW.value:
            raise DatasetDecodeError("execution-safe manifest must use raw prices")
        try:
            policy = RevisionPolicy(descriptor.revision_policy)
        except ValueError as error:
            raise DatasetDecodeError("manifest revision policy is unsupported") from error
        facts = tuple(
            _bar(row)
            for object_key in descriptor.object_keys
            for row in self._object_store.read_table(object_key).to_pylist()
        )
        return select_as_of(facts, as_of=as_of, policy=policy)
