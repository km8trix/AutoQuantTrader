"""Deterministic, content-addressed Parquet publication on local storage."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

DECIMAL_TYPE = pa.decimal128(28, 10)
UTC_TIMESTAMP = pa.timestamp("us", tz="UTC")

RAW_BAR_SCHEMA = pa.schema(
    [
        ("source", pa.string()),
        ("source_record_id", pa.string()),
        ("source_sequence", pa.int64()),
        ("revision", pa.int32()),
        ("supersedes_event_revision_id", pa.string()),
        ("symbol", pa.string()),
        ("venue", pa.string()),
        ("interval_start", UTC_TIMESTAMP),
        ("interval_end", UTC_TIMESTAMP),
        ("event_time", UTC_TIMESTAMP),
        ("vendor_published_at", UTC_TIMESTAMP),
        ("received_at", UTC_TIMESTAMP),
        ("available_at", UTC_TIMESTAMP),
        ("open", DECIMAL_TYPE),
        ("high", DECIMAL_TYPE),
        ("low", DECIMAL_TYPE),
        ("close", DECIMAL_TYPE),
        ("volume", pa.int64()),
        ("trade_count", pa.int64()),
        ("currency", pa.string()),
        ("schema_version", pa.string()),
        ("payload_hash", pa.string()),
    ]
)

NORMALIZED_BAR_SCHEMA = pa.schema(
    [
        ("event_revision_id", pa.string()),
        ("observation_id", pa.string()),
        ("instrument_id", pa.string()),
        ("source", pa.string()),
        ("source_record_id", pa.string()),
        ("source_sequence", pa.int64()),
        ("revision", pa.int32()),
        ("supersedes_event_revision_id", pa.string()),
        ("symbol", pa.string()),
        ("venue", pa.string()),
        ("session_label", pa.string()),
        ("interval", pa.string()),
        ("interval_start", UTC_TIMESTAMP),
        ("interval_end", UTC_TIMESTAMP),
        ("event_time", UTC_TIMESTAMP),
        ("vendor_published_at", UTC_TIMESTAMP),
        ("received_at", UTC_TIMESTAMP),
        ("available_at", UTC_TIMESTAMP),
        ("ingested_at", UTC_TIMESTAMP),
        ("open", DECIMAL_TYPE),
        ("high", DECIMAL_TYPE),
        ("low", DECIMAL_TYPE),
        ("close", DECIMAL_TYPE),
        ("volume", pa.int64()),
        ("trade_count", pa.int64()),
        ("currency", pa.string()),
        ("price_basis", pa.string()),
        ("capture_mode", pa.string()),
        ("schema_version", pa.string()),
        ("payload_hash", pa.string()),
    ]
)

QUARANTINED_RAW_SCHEMA = pa.schema(
    [
        ("source", pa.string()),
        ("source_record_id", pa.string()),
        ("revision", pa.int32()),
        ("payload_json", pa.string()),
        ("rejection_codes", pa.string()),
    ]
)


class ObjectIntegrityError(RuntimeError):
    """An existing content-addressed object does not match its key."""


@dataclass(frozen=True, slots=True)
class ParquetObject:
    object_id: str
    object_key: str
    byte_checksum: str
    semantic_checksum: str
    size_bytes: int
    row_count: int


def _canonical_value(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("canonical dataset timestamps must be timezone-aware")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("canonical dataset decimals must be finite")
        return format(value, "f")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(item) for key, item in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise TypeError(f"unsupported canonical dataset value: {type(value).__name__}")


def canonical_row_bytes(row: Mapping[str, Any]) -> bytes:
    return json.dumps(
        _canonical_value(row),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def canonicalize_rows(rows: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    if not rows:
        raise ValueError("a Parquet partition cannot be empty")
    ordered = sorted((dict(row) for row in rows), key=canonical_row_bytes)
    digest = hashlib.sha256()
    for row in ordered:
        digest.update(canonical_row_bytes(row))
        digest.update(b"\n")
    return ordered, digest.hexdigest()


class LocalParquetObjectStore:
    """Writes sealed objects before catalog publication and never mutates them."""

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()

    @property
    def root(self) -> Path:
        return self._root

    def write(
        self,
        *,
        layer: str,
        rows: Sequence[Mapping[str, Any]],
        schema: pa.Schema,
    ) -> ParquetObject:
        if layer not in {"raw", "normalized"}:
            raise ValueError("dataset layer must be raw or normalized")
        ordered_rows, semantic_checksum = canonicalize_rows(rows)
        table = pa.Table.from_pylist(ordered_rows, schema=schema)
        sink = pa.BufferOutputStream()
        pq.write_table(
            table,
            sink,
            compression="zstd",
            compression_level=9,
            data_page_version="2.0",
            use_dictionary=False,
            write_statistics=True,
            version="2.6",
        )
        payload = sink.getvalue().to_pybytes()
        byte_checksum = hashlib.sha256(payload).hexdigest()
        object_key = f"{layer}/sha256/{byte_checksum[:2]}/{byte_checksum}.parquet"
        target = (self._root / object_key).resolve()
        if not target.is_relative_to(self._root):
            raise ValueError("object key escaped the configured dataset root")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            existing_checksum = hashlib.sha256(target.read_bytes()).hexdigest()
            if existing_checksum != byte_checksum:
                raise ObjectIntegrityError(f"existing object {object_key!r} failed checksum")
        else:
            file_descriptor, temporary_name = tempfile.mkstemp(
                dir=target.parent,
                prefix=f".{byte_checksum}.",
                suffix=".tmp",
            )
            temporary_path = Path(temporary_name)
            try:
                with os.fdopen(file_descriptor, "wb") as temporary_file:
                    temporary_file.write(payload)
                    temporary_file.flush()
                    os.fsync(temporary_file.fileno())
                os.replace(temporary_path, target)
            finally:
                temporary_path.unlink(missing_ok=True)
        return ParquetObject(
            object_id=byte_checksum,
            object_key=object_key,
            byte_checksum=byte_checksum,
            semantic_checksum=semantic_checksum,
            size_bytes=len(payload),
            row_count=len(ordered_rows),
        )

    def verify(self, object_: ParquetObject) -> None:
        path = (self._root / object_.object_key).resolve()
        if not path.is_relative_to(self._root) or not path.is_file():
            raise ObjectIntegrityError(f"object {object_.object_key!r} is missing")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != object_.byte_checksum or actual != object_.object_id:
            raise ObjectIntegrityError(f"object {object_.object_key!r} failed checksum")

    def read_table(self, object_key: str) -> pa.Table:
        path = (self._root / object_key).resolve()
        if not path.is_relative_to(self._root) or not path.is_file():
            raise ObjectIntegrityError(f"object {object_key!r} is unavailable")
        expected_checksum = path.stem
        actual_checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        if len(expected_checksum) != 64 or actual_checksum != expected_checksum:
            raise ObjectIntegrityError(f"object {object_key!r} failed checksum")
        return pq.read_table(path)
