"""One bounded journal store for capture, venue and coordinator namespaces."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields
from types import MappingProxyType
from typing import Any, cast
from weakref import WeakValueDictionary, finalize

import sqlalchemy as sa
from sqlalchemy import Connection, Engine
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError

from packages.domain.durable_journal_contracts import (
    MAX_APPEND_RECORDS,
    MAX_PAGE_RECORDS,
    MAX_RECORD_BYTES,
    MAX_SEQUENCE,
    JournalAppend,
    JournalEntry,
    JournalHead,
    JournalKey,
    JournalPage,
    JournalReceipt,
    JournalRecord,
    empty_head,
    journal_identifier,
)
from packages.domain.personal_contracts import require_digest
from packages.domain.research_job_contracts import ResearchRecordCodec
from packages.persistence.continuous_capture_comparison import ContinuousCaptureComparison
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.durable_journal_schema import (
    journal_appends as appends,
)
from packages.persistence.durable_journal_schema import (
    journal_entries as entries,
)
from packages.persistence.durable_journal_schema import (
    journal_streams as streams,
)
from packages.persistence.research_workflow_v2 import _write

_MAX_KEY_BYTES = 16 * 1024


class JournalConflict(ValueError):
    """Sanitized journal admission, identity, integrity or compare-and-swap failure."""


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedJournalAppend:
    """In-process codec preparation, not a portable proof or an account permit."""

    key: JournalKey
    request: JournalAppend
    key_payload: bytes
    receipt: JournalReceipt
    entries: tuple[JournalEntry, ...]
    _owner: object
    _validated_values: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class _ReceiptRows:
    append: Mapping[str, Any]
    entries: tuple[Mapping[str, Any], ...]
    previous: Mapping[str, Any] | None


@dataclass(frozen=True, slots=True)
class _PreparedAppendReadback:
    fields: tuple[object, ...]
    nested_fields: tuple[tuple[object, tuple[tuple[str, object], ...]], ...]
    rows: _ReceiptRows


@dataclass(frozen=True, slots=True)
class JournalReadSnapshot:
    """Bounded detached SQL rows; capture does not decode or grant authority."""

    key: JournalKey
    command_id: str | None
    stream: Mapping[str, Any] | None
    head_anchor: Mapping[str, Any] | None
    head_receipt: _ReceiptRows | None
    requested_receipt: _ReceiptRows | None
    empty_has_records: bool
    missing_receipt_has_entries: bool
    _owner: object


@dataclass(frozen=True, slots=True)
class ResolvedJournalRead:
    """In-process validated read, rechecked against SQL before composition use."""

    snapshot: JournalReadSnapshot
    head: JournalHead
    receipt: JournalReceipt | None
    _owner: object
    _validated_values: tuple[object, ...]


def _copy(row: sa.RowMapping) -> Mapping[str, Any]:
    return MappingProxyType(dict(cast(Mapping[str, Any], row)))


def _columns(table: sa.Table, connection: Connection) -> tuple[Any, ...]:
    """Bound transfer even when SQLite storage types/declared lengths are corrupt."""
    selected = []
    for column in table.c:
        value: Any
        if isinstance(column.type, sa.String) and column.type.length is not None:
            value = sa.func.substr(column, 1, column.type.length + 1)
        elif isinstance(column.type, sa.LargeBinary):
            limit = _MAX_KEY_BYTES if column.name == "key_payload" else MAX_RECORD_BYTES
            value = sa.func.substr(column, 1, limit + 1)
        elif isinstance(column.type, sa.BigInteger):
            value = (
                sa.case((sa.func.typeof(column) == "integer", column), else_=None)
                if connection.dialect.name == "sqlite"
                else column
            )
        else:
            raise JournalConflict("JOURNAL_COLUMN_TRANSFER_UNBOUNDED")
        selected.append(value.label(column.name))
    return tuple(selected)


def _validate_row(row: Mapping[str, Any], table: sa.Table) -> None:
    """Check detached exact types and bounds before interpreting retained fields."""
    try:
        for column in table.c:
            value = row[column.name]
            if isinstance(column.type, sa.String):
                if (
                    type(value) is not str
                    or not value
                    or column.type.length is None
                    or len(value) > column.type.length
                ):
                    raise ValueError("invalid text metadata")
                if column.name.endswith("sha256"):
                    require_digest(value, "retained journal digest")
                else:
                    journal_identifier(value)
            elif isinstance(column.type, sa.BigInteger):
                if type(value) is not int or not 0 <= value <= MAX_SEQUENCE:
                    raise ValueError("invalid numeric metadata")
            elif isinstance(column.type, sa.LargeBinary):
                limit = _MAX_KEY_BYTES if column.name == "key_payload" else MAX_RECORD_BYTES
                if type(value) is not bytes or not 0 < len(value) <= limit:
                    raise ValueError("invalid binary metadata")
            else:
                raise ValueError("unbounded retained column")
    except (KeyError, TypeError, ValueError):
        raise JournalConflict("JOURNAL_RETAINED_ROW_INVALID") from None


def _has_records(connection: Connection, key: str) -> bool:
    return (
        connection.execute(
            sa.select(sa.literal(1)).where(
                sa.exists(sa.select(appends.c.command_id).where(appends.c.key_sha256 == key))
                | sa.exists(sa.select(entries.c.sequence).where(entries.c.key_sha256 == key))
            )
        ).scalar_one_or_none()
        is not None
    )


def _entry_row(connection: Connection, key: str, sequence: int) -> Mapping[str, Any] | None:
    row = (
        connection.execute(
            sa.select(*_columns(entries, connection)).where(
                entries.c.key_sha256 == key,
                entries.c.sequence == sequence,
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _copy(row)


def _stream_row(
    connection: Connection, key: str, *, lock: bool = False
) -> Mapping[str, Any] | None:
    statement = sa.select(*_columns(streams, connection)).where(streams.c.key_sha256 == key)
    if lock:
        statement = statement.with_for_update()
    row = connection.execute(statement).mappings().one_or_none()
    return None if row is None else _copy(row)


def _capture_receipt(connection: Connection, key: str, command: str) -> _ReceiptRows | None:
    row = (
        connection.execute(
            sa.select(*_columns(appends, connection)).where(
                appends.c.key_sha256 == key,
                appends.c.command_id == command,
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    copied = _copy(row)
    records = tuple(
        _copy(item)
        for item in connection.execute(
            sa.select(*_columns(entries, connection))
            .where(
                entries.c.key_sha256 == key,
                entries.c.command_id == command,
            )
            .order_by(entries.c.sequence)
            .limit(MAX_APPEND_RECORDS + 1)
        ).mappings()
    )
    previous_sequence = copied["previous_sequence"]
    previous = (
        _entry_row(connection, key, previous_sequence)
        if type(previous_sequence) is int and 0 < previous_sequence <= MAX_SEQUENCE
        else None
    )
    return _ReceiptRows(copied, records, previous)


class SqlDurableJournal:
    """Append/CAS only; callers own account fencing and economic interpretation.

    Read pages validate a contiguous prefix segment against caller-supplied
    heads. A complete restore must walk from empty_head through its pinned head.
    read_head validates the current append, not an unbounded historical replay.
    """

    def __init__(
        self, engine: Engine, *, codec: ResearchRecordCodec, record_types: Mapping[str, type[Any]]
    ) -> None:
        if engine.dialect.name not in ("sqlite", "postgresql"):
            raise JournalConflict("JOURNAL_DIALECT_UNSUPPORTED")
        if not record_types:
            raise JournalConflict("JOURNAL_TYPE_ALLOWLIST_REQUIRED")
        for schema, expected in record_types.items():
            journal_identifier(schema)
            if not isinstance(expected, type):
                raise JournalConflict("JOURNAL_TYPE_ALLOWLIST_INVALID")
        self._engine, self._codec = engine, codec
        self._types = MappingProxyType(dict(record_types))
        self._preparation_owner = object()
        self._prepared_appends: WeakValueDictionary[int, PreparedJournalAppend] = (
            WeakValueDictionary()
        )
        self._prepared_readbacks: dict[int, _PreparedAppendReadback] = {}

    def _validate_record(self, record: JournalRecord) -> None:
        record.__post_init__()
        expected = self._types.get(record.schema_id)
        if expected is None:
            raise JournalConflict("JOURNAL_SCHEMA_NOT_ALLOWLISTED")
        try:
            value = self._codec.decode_record(record.payload, expected)
            if type(value) is not expected or self._codec.encode_record(value) != record.payload:
                raise ValueError("noncanonical record")
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise JournalConflict("JOURNAL_TYPED_PAYLOAD_INVALID") from None

    def _key_payload(self, key: JournalKey) -> bytes:
        key.__post_init__()
        payload = self._codec.encode_record(key)
        if type(payload) is not bytes or not 0 < len(payload) <= _MAX_KEY_BYTES:
            raise JournalConflict("JOURNAL_KEY_BYTES_INVALID")
        if self._codec.decode_record(payload, JournalKey) != key:
            raise JournalConflict("JOURNAL_KEY_CODEC_MISMATCH")
        return payload

    def prepare_append(self, key: JournalKey, request: JournalAppend) -> PreparedJournalAppend:
        """Complete typed codec work before acquiring any database transaction."""
        request.__post_init__()
        key_payload = self._key_payload(key)
        if request.expected_head.key_sha256 != key.semantic_sha256:
            raise JournalConflict("JOURNAL_EXPECTED_KEY_MISMATCH")
        if request.expected_head.sequence == 0 and request.expected_head != empty_head(key):
            raise JournalConflict("JOURNAL_EMPTY_HEAD_MISMATCH")
        previous = request.expected_head
        built = []
        for record in request.records:
            self._validate_record(record)
            entry = JournalEntry(
                key.semantic_sha256,
                previous.sequence + 1,
                request.command_id,
                record,
                previous.entry_sha256,
            )
            built.append(entry)
            previous = entry.head
        receipt = JournalReceipt(
            request.command_id,
            request.command_sha256,
            request.semantic_sha256,
            request.expected_head,
            previous,
            tuple(r.record_id for r in request.records),
            tuple(r.payload_sha256 for r in request.records),
        )
        values = (key, request, key_payload, receipt, tuple(built))
        prepared = PreparedJournalAppend(
            key, request, key_payload, receipt, tuple(built), self._preparation_owner, values
        )
        self._prepared_appends[id(prepared)] = prepared
        nested = (
            key,
            request,
            receipt,
            request.expected_head,
            receipt.committed_head,
            *built,
            *request.records,
        )
        self._prepared_readbacks[id(prepared)] = _PreparedAppendReadback(
            tuple(getattr(prepared, f.name) for f in fields(prepared)),
            tuple(
                (item, tuple((f.name, getattr(item, f.name)) for f in fields(cast(Any, item))))
                for item in nested
            ),
            _ReceiptRows(
                MappingProxyType(
                    dict(
                        key_sha256=key.semantic_sha256,
                        command_id=request.command_id,
                        command_sha256=request.command_sha256,
                        append_sha256=receipt.append_sha256,
                        previous_sequence=request.expected_head.sequence,
                        previous_entry_sha256=request.expected_head.entry_sha256,
                        last_sequence=receipt.committed_head.sequence,
                        last_entry_sha256=receipt.committed_head.entry_sha256,
                        receipt_sha256=receipt.semantic_sha256,
                    )
                ),
                tuple(
                    MappingProxyType(
                        dict(
                            key_sha256=entry.key_sha256,
                            sequence=entry.sequence,
                            command_id=entry.command_id,
                            record_id=entry.record.record_id,
                            schema_id=entry.record.schema_id,
                            payload=entry.record.payload,
                            payload_sha256=entry.record.payload_sha256,
                            previous_entry_sha256=entry.previous_entry_sha256,
                            entry_sha256=entry.semantic_sha256,
                        )
                    )
                    for entry in built
                ),
                None,
            ),
        )
        finalize(prepared, self._prepared_readbacks.pop, id(prepared), None)
        return prepared

    def recheck_prepared_append_in_transaction(
        self,
        connection: Connection,
        prepared: PreparedJournalAppend,
        *,
        require_current_head: bool = True,
    ) -> JournalReceipt:
        """Read back an original retained append without writing or repairing it.

        Exact rows were encoded before SQL. The only retained-payload hashing is
        the common bounded journal check of the original predecessor anchor.
        No codec, object access or full domain graph validation occurs here.
        """
        self._read_connection(connection)
        if (
            type(prepared) is not PreparedJournalAppend
            or self._prepared_appends.get(id(prepared)) is not prepared
            or type(require_current_head) is not bool
        ):
            raise JournalConflict("JOURNAL_ORIGINAL_PREPARATION_REQUIRED")
        original = self._prepared_readbacks[id(prepared)]
        if any(
            getattr(prepared, f.name) is not value
            for f, value in zip(fields(prepared), original.fields, strict=True)
        ) or any(
            getattr(item, name) is not value
            for item, values in original.nested_fields
            for name, value in values
        ):
            raise JournalConflict("JOURNAL_ORIGINAL_PREPARATION_CHANGED")
        expected = original.rows
        key_hash = expected.append["key_sha256"]
        stream = _stream_row(connection, key_hash)
        rows = _capture_receipt(connection, key_hash, expected.append["command_id"])
        if stream is None or rows is None:
            raise JournalConflict("JOURNAL_RETAINED_APPEND_MISSING")
        _validate_row(stream, streams)
        if (
            stream["key_payload"] != prepared.key_payload
            or stream["key_sha256"] != key_hash
            or stream["last_sequence"] < expected.append["last_sequence"]
            or (
                require_current_head
                and (stream["last_sequence"], stream["last_entry_sha256"])
                != (expected.append["last_sequence"], expected.append["last_entry_sha256"])
            )
        ):
            raise JournalConflict("JOURNAL_RETAINED_APPEND_HEAD_DIFFERS")
        if rows.append != expected.append or rows.entries != expected.entries:
            raise JournalConflict("JOURNAL_RETAINED_APPEND_ROWS_DIFFER")
        if prepared.request.expected_head.sequence:
            if (
                rows.previous is None
                or self._decode_entry(rows.previous, typed=False).head
                != prepared.request.expected_head
            ):
                raise JournalConflict("JOURNAL_RETAINED_APPEND_PREFIX_DIFFERS")
        elif rows.previous is not None:
            raise JournalConflict("JOURNAL_RETAINED_APPEND_PREFIX_DIFFERS")
        return prepared.receipt

    def _decode_entry(self, row: Mapping[str, Any], *, typed: bool = True) -> JournalEntry:
        try:
            _validate_row(row, entries)
            record = JournalRecord(row["record_id"], row["schema_id"], row["payload"])
            entry = JournalEntry(
                row["key_sha256"],
                row["sequence"],
                row["command_id"],
                record,
                row["previous_entry_sha256"],
            )
            if (
                record.payload_sha256 != row["payload_sha256"]
                or entry.semantic_sha256 != row["entry_sha256"]
            ):
                raise ValueError("hash mismatch")
            if typed:
                self._validate_record(record)
            return entry
        except (TypeError, ValueError, KeyError):
            raise JournalConflict("JOURNAL_ENTRY_INVALID") from None

    def _validate_stream(self, key: JournalKey, row: Mapping[str, Any]) -> JournalHead:
        _validate_row(row, streams)
        if row["key_sha256"] != key.semantic_sha256 or row["key_payload"] != self._key_payload(key):
            raise JournalConflict("JOURNAL_STREAM_BINDING_INVALID")
        head = JournalHead(row["key_sha256"], row["last_sequence"], row["last_entry_sha256"])
        if head.sequence == 0 and head != empty_head(key):
            raise JournalConflict("JOURNAL_EMPTY_HEAD_MISMATCH")
        return head

    def _receipt(
        self, key: JournalKey, rows: _ReceiptRows, *, typed: bool = True
    ) -> JournalReceipt:
        try:
            raw = rows.append
            _validate_row(raw, appends)
            previous = JournalHead(
                raw["key_sha256"], raw["previous_sequence"], raw["previous_entry_sha256"]
            )
            if previous.key_sha256 != key.semantic_sha256:
                raise ValueError("receipt key mismatch")
            if previous.sequence == 0:
                if previous != empty_head(key):
                    raise ValueError("empty prefix mismatch")
            elif (
                rows.previous is None
                or self._decode_entry(rows.previous, typed=typed).head != previous
            ):
                raise ValueError("previous prefix mismatch")
            decoded = tuple(self._decode_entry(row, typed=typed) for row in rows.entries)
            if not decoded:
                raise ValueError("missing receipt records")
            head = previous
            for entry in decoded:
                if (
                    entry.key_sha256 != key.semantic_sha256
                    or entry.sequence != head.sequence + 1
                    or entry.previous_entry_sha256 != head.entry_sha256
                    or entry.command_id != raw["command_id"]
                ):
                    raise ValueError("receipt chain mismatch")
                head = entry.head
            request = JournalAppend(
                raw["command_id"],
                raw["command_sha256"],
                previous,
                tuple(entry.record for entry in decoded),
            )
            result = JournalReceipt(
                request.command_id,
                request.command_sha256,
                request.semantic_sha256,
                previous,
                head,
                tuple(r.record_id for r in request.records),
                tuple(r.payload_sha256 for r in request.records),
            )
            if (
                head.sequence != raw["last_sequence"]
                or head.entry_sha256 != raw["last_entry_sha256"]
                or request.semantic_sha256 != raw["append_sha256"]
                or result.semantic_sha256 != raw["receipt_sha256"]
            ):
                raise ValueError("receipt digest mismatch")
            return result
        except (TypeError, ValueError, KeyError):
            raise JournalConflict("JOURNAL_RECEIPT_INVALID") from None

    def append(self, key: JournalKey, request: JournalAppend) -> JournalReceipt:
        prepared = self.prepare_append(key, request)
        with _write(self._engine) as connection:
            return self.append_in_transaction(connection, prepared)

    def append_in_transaction(
        self, connection: Connection, prepared: PreparedJournalAppend
    ) -> JournalReceipt:
        """Use the caller's real transaction; rollback a failed append's savepoint only."""
        if (
            type(prepared) is not PreparedJournalAppend
            or prepared._owner is not self._preparation_owner
        ):
            raise JournalConflict("JOURNAL_PREPARATION_REQUIRED")
        if connection.engine is not self._engine or not connection.in_transaction():
            raise JournalConflict("JOURNAL_CALLER_TRANSACTION_REQUIRED")
        if connection.dialect.name == "sqlite":
            raw_connection = connection.connection.driver_connection
            if not getattr(raw_connection, "in_transaction", False):
                raise JournalConflict("JOURNAL_SQLITE_EXPLICIT_TRANSACTION_REQUIRED")
        # Frozen original values bind this in-process preparation. This is not
        # authentication against a caller able to construct Python objects.
        if (
            prepared.key,
            prepared.request,
            prepared.key_payload,
            prepared.receipt,
            prepared.entries,
        ) != prepared._validated_values:
            raise JournalConflict("JOURNAL_PREPARATION_CHANGED")
        try:
            with connection.begin_nested():
                return self._append_locked(connection, prepared)
        except IntegrityError:
            raise JournalConflict("JOURNAL_SQL_CONFLICT") from None

    def _append_locked(
        self, connection: Connection, prepared: PreparedJournalAppend
    ) -> JournalReceipt:
        key, request, receipt = prepared.key, prepared.request, prepared.receipt
        key_hash = key.semantic_sha256
        insertion = sqlite_insert if connection.dialect.name == "sqlite" else pg_insert
        initial = empty_head(key)
        connection.execute(
            insertion(streams)
            .values(
                key_sha256=key_hash,
                key_payload=prepared.key_payload,
                last_sequence=0,
                last_entry_sha256=initial.entry_sha256,
            )
            .on_conflict_do_nothing()
            .returning(streams.c.key_sha256)
        ).scalar_one_or_none()
        row = _stream_row(connection, key_hash, lock=True)
        if row is None:
            raise JournalConflict("JOURNAL_STREAM_BINDING_INVALID")
        _validate_row(row, streams)
        if row["key_payload"] != prepared.key_payload:
            raise JournalConflict("JOURNAL_STREAM_BINDING_INVALID")
        current = JournalHead(key_hash, row["last_sequence"], row["last_entry_sha256"])
        if current.sequence:
            anchor = _entry_row(connection, key_hash, current.sequence)
            if anchor is None or self._decode_entry(anchor, typed=False).head != current:
                raise JournalConflict("JOURNAL_HEAD_ENTRY_INVALID")
            anchored = _capture_receipt(connection, key_hash, anchor["command_id"])
            if (
                anchored is None
                or self._receipt(key, anchored, typed=False).committed_head != current
            ):
                raise JournalConflict("JOURNAL_HEAD_ENTRY_INVALID")
        elif current != initial:
            raise JournalConflict("JOURNAL_EMPTY_HEAD_MISMATCH")
        elif _has_records(connection, key_hash):
            raise JournalConflict("JOURNAL_EMPTY_HEAD_HAS_RECORDS")
        old = _capture_receipt(connection, key_hash, request.command_id)
        if old is not None:
            existing = self._receipt(key, old, typed=False)
            if existing != receipt or current.sequence < existing.committed_head.sequence:
                raise JournalConflict("JOURNAL_COMMAND_CONFLICT")
            return existing
        if current != request.expected_head:
            raise JournalConflict("JOURNAL_HEAD_CONFLICT")
        inserted = connection.execute(
            insertion(appends)
            .values(
                key_sha256=key_hash,
                command_id=request.command_id,
                command_sha256=request.command_sha256,
                append_sha256=receipt.append_sha256,
                previous_sequence=current.sequence,
                previous_entry_sha256=current.entry_sha256,
                last_sequence=receipt.committed_head.sequence,
                last_entry_sha256=receipt.committed_head.entry_sha256,
                receipt_sha256=receipt.semantic_sha256,
            )
            .on_conflict_do_nothing()
            .returning(appends.c.command_id)
        ).scalar_one_or_none()
        if inserted is None:
            raise JournalConflict("JOURNAL_COMMAND_CONFLICT")
        for entry in prepared.entries:
            result = connection.execute(
                insertion(entries)
                .values(
                    key_sha256=key_hash,
                    sequence=entry.sequence,
                    command_id=entry.command_id,
                    record_id=entry.record.record_id,
                    schema_id=entry.record.schema_id,
                    payload=entry.record.payload,
                    payload_sha256=entry.record.payload_sha256,
                    previous_entry_sha256=entry.previous_entry_sha256,
                    entry_sha256=entry.semantic_sha256,
                )
                .on_conflict_do_nothing()
                .returning(entries.c.sequence)
            ).scalar_one_or_none()
            if result is None:
                raise JournalConflict("JOURNAL_RECORD_CONFLICT")
        changed = connection.execute(
            sa.update(streams)
            .where(
                streams.c.key_sha256 == key_hash,
                streams.c.last_sequence == current.sequence,
                streams.c.last_entry_sha256 == current.entry_sha256,
            )
            .values(
                last_sequence=receipt.committed_head.sequence,
                last_entry_sha256=receipt.committed_head.entry_sha256,
            )
            .returning(streams.c.last_sequence)
        ).scalar_one_or_none()
        if changed != receipt.committed_head.sequence:
            raise JournalConflict("JOURNAL_HEAD_CONFLICT")
        return receipt

    def read_receipt(self, key: JournalKey, command_id: str) -> JournalReceipt | None:
        key.__post_init__()
        journal_identifier(command_id)
        with _repeatable_read_transaction(self._engine) as connection:
            stream = _stream_row(connection, key.semantic_sha256)
            rows = _capture_receipt(connection, key.semantic_sha256, command_id)
        if stream is None:
            if rows is not None:
                raise JournalConflict("JOURNAL_ORPHAN_RECEIPT")
            return None
        head = self._validate_stream(key, stream)
        if rows is None:
            return None
        receipt = self._receipt(key, rows)
        if receipt.committed_head.sequence > head.sequence:
            raise JournalConflict("JOURNAL_RECEIPT_AFTER_HEAD")
        return receipt

    def _read_connection(self, connection: Connection) -> None:
        if connection.engine is not self._engine or not connection.in_transaction():
            raise JournalConflict("JOURNAL_SAME_ENGINE_TRANSACTION_REQUIRED")
        if connection.dialect.name == "sqlite" and (
            getattr(connection.connection.driver_connection, "in_transaction", False) is not True
        ):
            raise JournalConflict("JOURNAL_EXPLICIT_TRANSACTION_REQUIRED")
        if connection.dialect.name == "postgresql" and connection.get_isolation_level() not in (
            "REPEATABLE READ",
            "SERIALIZABLE",
        ):
            raise JournalConflict("JOURNAL_REPEATABLE_SNAPSHOT_REQUIRED")

    def capture_in_transaction(
        self, connection: Connection, key: JournalKey, *, command_id: str | None = None
    ) -> JournalReadSnapshot:
        """Copy bounded rows in the caller's snapshot, with no codec or object I/O.

        SQLite requires a physical BEGIN; PostgreSQL requires REPEATABLE READ
        or SERIALIZABLE. Resolve the snapshot after leaving this transaction. A later
        fenced writer uses recheck_in_transaction for exact immutable bytes and
        metadata plus the required current head. No independent connection is
        opened here, so account composition sees its own uncommitted appends.
        """
        self._read_connection(connection)
        key.__post_init__()
        if command_id is not None:
            journal_identifier(command_id)
        key_hash = key.semantic_sha256
        stream = _stream_row(connection, key_hash)
        anchor = None
        head_rows = None
        empty_has_records = False
        if (
            stream is not None
            and type(stream["last_sequence"]) is int
            and (0 < stream["last_sequence"] <= MAX_SEQUENCE)
        ):
            anchor = _entry_row(connection, key_hash, stream["last_sequence"])
            if (
                anchor is not None
                and type(anchor["command_id"]) is str
                and (0 < len(anchor["command_id"]) <= 128)
            ):
                head_rows = _capture_receipt(connection, key_hash, anchor["command_id"])
        else:
            empty_has_records = _has_records(connection, key_hash)
        requested = (
            _capture_receipt(connection, key_hash, command_id) if command_id is not None else None
        )
        missing_has_entries = (
            command_id is not None
            and requested is None
            and (
                connection.execute(
                    sa.select(sa.literal(1)).where(
                        sa.exists(
                            sa.select(entries.c.sequence).where(
                                entries.c.key_sha256 == key_hash,
                                entries.c.command_id == command_id,
                            )
                        )
                    )
                ).scalar_one_or_none()
                is not None
            )
        )
        return JournalReadSnapshot(
            key,
            command_id,
            stream,
            anchor,
            head_rows,
            requested,
            empty_has_records,
            missing_has_entries,
            self._preparation_owner,
        )

    def resolve_snapshot(self, snapshot: JournalReadSnapshot) -> ResolvedJournalRead:
        """Authenticate typed entries after SQL closes; no current-head claim yet."""
        if type(snapshot) is not JournalReadSnapshot or (
            snapshot._owner is not self._preparation_owner
        ):
            raise JournalConflict("JOURNAL_READ_SNAPSHOT_OWNER_DIFFERS")
        key = snapshot.key
        if snapshot.empty_has_records or snapshot.missing_receipt_has_entries:
            raise JournalConflict("JOURNAL_READ_ORPHAN_ROWS")
        if snapshot.stream is None:
            if any(
                value is not None
                for value in (
                    snapshot.head_anchor,
                    snapshot.head_receipt,
                    snapshot.requested_receipt,
                )
            ):
                raise JournalConflict("JOURNAL_READ_ORPHAN_ROWS")
            head = empty_head(key)
        else:
            head = self._validate_stream(key, snapshot.stream)
            if head.sequence and (
                snapshot.head_anchor is None
                or snapshot.head_receipt is None
                or self._decode_entry(snapshot.head_anchor).head != head
                or self._receipt(key, snapshot.head_receipt).committed_head != head
            ):
                raise JournalConflict("JOURNAL_HEAD_ENTRY_INVALID")
        receipt = (
            self._receipt(key, snapshot.requested_receipt)
            if snapshot.requested_receipt is not None
            else None
        )
        if receipt is not None and (
            receipt.command_id != snapshot.command_id
            or receipt.committed_head.sequence > head.sequence
        ):
            raise JournalConflict("JOURNAL_RECEIPT_AFTER_HEAD")
        return ResolvedJournalRead(
            snapshot,
            head,
            receipt,
            self._preparation_owner,
            (snapshot, head, receipt),
        )

    def require_same_capture(
        self,
        original: JournalReadSnapshot,
        fresh: JournalReadSnapshot,
        *,
        comparison: ContinuousCaptureComparison,
    ) -> None:
        """Compare every captured row, including the then-current journal head.

        Raw journal captures have an original type/owner seal, not an identity
        registry: the legitimate detached row pool also copies them. Enclosing
        source capture ownership and its final structural seal remain required.
        """
        if type(comparison) is not ContinuousCaptureComparison:
            raise JournalConflict("EXACT_CAPTURE_COMPARISON_REQUIRED")
        for value in (original, fresh):
            if (
                type(value) is not JournalReadSnapshot
                or value._owner is not self._preparation_owner
            ):
                raise JournalConflict("JOURNAL_READ_SNAPSHOT_OWNER_DIFFERS")
        comparison.data(
            (
                original.key,
                original.command_id,
                original.stream,
                original.head_anchor,
                original.empty_has_records,
                original.missing_receipt_has_entries,
            ),
            (
                fresh.key,
                fresh.command_id,
                fresh.stream,
                fresh.head_anchor,
                fresh.empty_has_records,
                fresh.missing_receipt_has_entries,
            ),
        )
        for left, right in (
            (original.head_receipt, fresh.head_receipt),
            (original.requested_receipt, fresh.requested_receipt),
        ):
            if left is None or right is None:
                comparison.identity(left, right)
            else:
                if type(left) is not _ReceiptRows or type(right) is not _ReceiptRows:
                    raise JournalConflict("JOURNAL_RECEIPT_ROWS_TYPE_DIFFERS")
                comparison.data(
                    (left.append, left.entries, left.previous),
                    (right.append, right.entries, right.previous),
                )
        for value in (original, fresh):
            if value._owner is not self._preparation_owner:
                raise JournalConflict("JOURNAL_READ_SNAPSHOT_OWNER_DIFFERS")

    def require_same_resolved_read(
        self,
        original: ResolvedJournalRead,
        fresh: ResolvedJournalRead,
        *,
        comparison: ContinuousCaptureComparison,
    ) -> None:
        """Compare owner-sealed original read inputs without another decode/hash."""
        if type(comparison) is not ContinuousCaptureComparison:
            raise JournalConflict("EXACT_CAPTURE_COMPARISON_REQUIRED")
        for value in (original, fresh):
            self._require_same_read_owner(value)
        self.require_same_capture(original.snapshot, fresh.snapshot, comparison=comparison)
        comparison.data((original.head, original.receipt), (fresh.head, fresh.receipt))
        for value in (original, fresh):
            self._require_same_read_owner(value)

    def _require_same_read_owner(self, value: ResolvedJournalRead) -> None:
        if (
            type(value) is not ResolvedJournalRead
            or value._owner is not self._preparation_owner
            or type(value._validated_values) is not tuple
            or len(value._validated_values) != 3
            or any(
                old is not current
                for old, current in zip(
                    value._validated_values,
                    (value.snapshot, value.head, value.receipt),
                    strict=True,
                )
            )
        ):
            raise JournalConflict("JOURNAL_RESOLVED_READ_OWNER_DIFFERS")

    def recheck_in_transaction(
        self,
        connection: Connection,
        resolved: ResolvedJournalRead,
        *,
        require_current_head: bool = True,
    ) -> tuple[JournalHead, JournalReceipt | None]:
        """Authenticate the prepared read without decoding under an account lock.

        Historical lookup may allow later appends, but its original receipt and
        exact retained prefix bytes must still exist. The returned head is the
        resolved historical head in that mode, never a newly certified head.
        """
        self._read_connection(connection)
        if type(resolved) is not ResolvedJournalRead or (
            resolved._owner is not self._preparation_owner
            or resolved._validated_values != (resolved.snapshot, resolved.head, resolved.receipt)
        ):
            raise JournalConflict("JOURNAL_RESOLVED_READ_OWNER_DIFFERS")
        before = resolved.snapshot
        current = self.capture_in_transaction(connection, before.key, command_id=before.command_id)
        if require_current_head:
            if current != before:
                raise JournalConflict("JOURNAL_READ_CHANGED")
        else:
            # Compare original anchors directly, without decoding a later head.
            # A deleted/replaced stream or regressed head is never a valid retry.
            if (current.stream is None) != (before.stream is None) or (
                current.empty_has_records
                or current.missing_receipt_has_entries
                or current.requested_receipt != before.requested_receipt
            ):
                raise JournalConflict("JOURNAL_HISTORICAL_READ_CHANGED")
            if before.stream is not None:
                assert current.stream is not None
                _validate_row(current.stream, streams)
                if (
                    any(
                        current.stream[name] != before.stream[name]
                        for name in (
                            "key_sha256",
                            "key_payload",
                        )
                    )
                    or current.stream["last_sequence"] < resolved.head.sequence
                ):
                    raise JournalConflict("JOURNAL_HISTORICAL_READ_CHANGED")
                if resolved.head.sequence:
                    anchor = _entry_row(
                        connection, before.key.semantic_sha256, resolved.head.sequence
                    )
                    if (
                        anchor != before.head_anchor
                        or before.head_receipt is None
                        or (
                            _capture_receipt(
                                connection,
                                before.key.semantic_sha256,
                                before.head_receipt.append["command_id"],
                            )
                            != before.head_receipt
                        )
                    ):
                        raise JournalConflict("JOURNAL_HISTORICAL_READ_CHANGED")
                elif current.stream["last_sequence"] == 0 and current.stream != before.stream:
                    raise JournalConflict("JOURNAL_HISTORICAL_READ_CHANGED")
        return resolved.head, resolved.receipt

    def read_head(self, key: JournalKey) -> JournalHead:
        key.__post_init__()
        with _repeatable_read_transaction(self._engine) as connection:
            row = _stream_row(connection, key.semantic_sha256)
            anchor = None
            rows = None
            orphaned = False
            if row is not None and row["last_sequence"]:
                anchor = _entry_row(connection, key.semantic_sha256, row["last_sequence"])
                if anchor is not None:
                    rows = _capture_receipt(connection, key.semantic_sha256, anchor["command_id"])
            else:
                orphaned = _has_records(connection, key.semantic_sha256)
        if orphaned:
            raise JournalConflict("JOURNAL_EMPTY_HEAD_HAS_RECORDS")
        if row is None:
            return empty_head(key)
        head = self._validate_stream(key, row)
        if head.sequence and (
            anchor is None or rows is None or self._receipt(key, rows).committed_head != head
        ):
            raise JournalConflict("JOURNAL_HEAD_ENTRY_INVALID")
        return head

    def read_page(
        self,
        key: JournalKey,
        *,
        through_head: JournalHead,
        after_head: JournalHead | None = None,
        limit: int = MAX_PAGE_RECORDS,
    ) -> JournalPage:
        """Read at most 256 bounded records plus two anchors; decode after SQL closes."""
        key.__post_init__()
        through_head.__post_init__()
        previous = empty_head(key) if after_head is None else after_head
        previous.__post_init__()
        if (
            type(limit) is not int
            or not 1 <= limit <= MAX_PAGE_RECORDS
            or previous.key_sha256 != key.semantic_sha256
            or through_head.key_sha256 != key.semantic_sha256
            or previous.sequence > through_head.sequence
        ):
            raise JournalConflict("JOURNAL_PAGE_REQUEST_INVALID")
        if previous.sequence == 0 and previous != empty_head(key):
            raise JournalConflict("JOURNAL_EMPTY_HEAD_MISMATCH")
        with _repeatable_read_transaction(self._engine) as connection:
            stream = _stream_row(connection, key.semantic_sha256)
            orphaned = (
                _has_records(connection, key.semantic_sha256)
                if stream is None or stream["last_sequence"] == 0
                else False
            )
            before_row = (
                _entry_row(connection, key.semantic_sha256, previous.sequence)
                if previous.sequence
                else None
            )
            terminal_row = (
                _entry_row(connection, key.semantic_sha256, through_head.sequence)
                if through_head.sequence
                else None
            )
            records = tuple(
                _copy(row)
                for row in connection.execute(
                    sa.select(*_columns(entries, connection))
                    .where(
                        entries.c.key_sha256 == key.semantic_sha256,
                        entries.c.sequence > previous.sequence,
                        entries.c.sequence <= through_head.sequence,
                    )
                    .order_by(entries.c.sequence)
                    .limit(limit)
                ).mappings()
            )
        if orphaned:
            raise JournalConflict("JOURNAL_EMPTY_HEAD_HAS_RECORDS")
        if stream is None:
            if through_head != empty_head(key) or records:
                raise JournalConflict("JOURNAL_STREAM_MISSING")
        else:
            head = self._validate_stream(key, stream)
            if head.sequence < through_head.sequence:
                raise JournalConflict("JOURNAL_PAGE_AFTER_HEAD")
        if previous.sequence and (
            before_row is None or self._decode_entry(before_row).head != previous
        ):
            raise JournalConflict("JOURNAL_PAGE_PREFIX_INVALID")
        if through_head.sequence:
            if terminal_row is None or self._decode_entry(terminal_row).head != through_head:
                raise JournalConflict("JOURNAL_PAGE_TERMINAL_INVALID")
        elif through_head != empty_head(key):
            raise JournalConflict("JOURNAL_EMPTY_HEAD_MISMATCH")
        if len(records) != min(limit, through_head.sequence - previous.sequence):
            raise JournalConflict("JOURNAL_PAGE_MISSING_RECORDS")
        decoded = tuple(self._decode_entry(row) for row in records)
        next_head = decoded[-1].head if decoded else previous
        try:
            return JournalPage(
                key, through_head, previous, decoded, next_head, next_head == through_head
            )
        except (TypeError, ValueError):
            raise JournalConflict("JOURNAL_PAGE_CHAIN_INVALID") from None
