"""Account composition reads preserve their transaction and detached codec boundary."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from threading import Event
from types import MappingProxyType

import pytest
import sqlalchemy as sa

from packages.application import personal_codec
from packages.domain.durable_journal_contracts import (
    JournalAppend,
    JournalEntry,
    JournalKey,
    JournalReceipt,
    JournalRecord,
    empty_head,
)
from packages.domain.personal_contracts import ContractRecord, content_digest
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal import (
    JournalConflict,
    JournalReadSnapshot,
    SqlDurableJournal,
    _ReceiptRows,
)
from packages.persistence.durable_journal_schema import (
    JOURNAL_TABLES,
    journal_entries,
    journal_streams,
)
from packages.persistence.schema import metadata


@dataclass(frozen=True, slots=True)
class Observation(ContractRecord):
    number: int


def key():
    return JournalKey("capture", "read-seam", "fixture-account", "fixture", "synthetic", "a" * 64)


def append(number=1, head=None):
    return JournalAppend(
        f"command-{number}",
        content_digest(number),
        head or empty_head(key()),
        (
            JournalRecord(
                f"record-{number}",
                "observation/1",
                personal_codec.encode_record(Observation(number)),
            ),
        ),
    )


def store(engine, codec=personal_codec):
    return SqlDurableJournal(engine, codec=codec, record_types={"observation/1": Observation})


@pytest.fixture
def engine(tmp_path):
    value = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/transaction-reads.sqlite")
    metadata.create_all(value, tables=JOURNAL_TABLES)
    yield value
    value.dispose()


def capture(journal, engine, command="command-1"):
    with engine.begin() as connection:
        connection.exec_driver_sql("BEGIN")
        return journal.capture_in_transaction(connection, key(), command_id=command)


def test_empty_and_committed_reads_are_resolved_after_sql_and_rechecked(engine):
    journal = store(engine)
    empty = journal.resolve_snapshot(capture(journal, engine))
    assert empty.head == empty_head(key()) and empty.receipt is None
    receipt = journal.append(key(), append())
    resolved = journal.resolve_snapshot(capture(journal, engine))
    assert resolved.receipt == receipt
    with engine.begin() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        assert journal.recheck_in_transaction(connection, resolved) == (
            receipt.committed_head,
            receipt,
        )
        with pytest.raises(JournalConflict, match="READ_CHANGED"):
            journal.recheck_in_transaction(connection, empty)


def test_capture_and_recheck_never_invoke_codec_inside_caller_transaction(engine):
    journal = store(engine)
    journal.append(key(), append())
    resolved = journal.resolve_snapshot(capture(journal, engine))

    class NoCodec:
        def encode_record(self, value):
            raise AssertionError("codec ran under account lock")

        def decode_record(self, data, expected):
            raise AssertionError("codec ran under account lock")

    journal._codec = NoCodec()
    with engine.begin() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        assert (
            journal.capture_in_transaction(connection, key(), command_id="command-1")
            == resolved.snapshot
        )
        journal.recheck_in_transaction(connection, resolved)


def test_historical_recheck_after_later_append_preserves_original_head(engine):
    journal = store(engine)
    first = journal.append(key(), append())
    resolved = journal.resolve_snapshot(capture(journal, engine))
    second = journal.append(key(), append(2, first.committed_head))
    with engine.begin() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        with pytest.raises(JournalConflict, match="READ_CHANGED"):
            journal.recheck_in_transaction(connection, resolved)
        head, receipt = journal.recheck_in_transaction(
            connection, resolved, require_current_head=False
        )
    assert head == first.committed_head and receipt == first and head != second.committed_head


def test_caller_sees_own_append_and_rollback_is_not_committed_by_capture(engine):
    journal = store(engine)
    prepared = journal.prepare_append(key(), append())
    with engine.connect() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        receipt = journal.append_in_transaction(connection, prepared)
        snapshot = journal.capture_in_transaction(connection, key(), command_id="command-1")
        assert snapshot.requested_receipt is not None
        connection.rollback()
    # Detached decode is historical evidence only; current-row recheck rejects it.
    resolved = journal.resolve_snapshot(snapshot)
    assert resolved.receipt == receipt and journal.read_head(key()) == empty_head(key())
    with engine.begin() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        with pytest.raises(JournalConflict, match="READ_CHANGED"):
            journal.recheck_in_transaction(connection, resolved)


@pytest.mark.parametrize(
    "field,value", [("payload", b"broken"), ("record_id", "replaced"), ("entry_sha256", "b" * 64)]
)
def test_recheck_rejects_changed_original_bytes_or_metadata(engine, field, value):
    journal = store(engine)
    journal.append(key(), append())
    resolved = journal.resolve_snapshot(capture(journal, engine))
    with engine.begin() as connection:
        connection.execute(sa.update(journal_entries).values({field: value}))
    with engine.begin() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        with pytest.raises(JournalConflict, match="READ_CHANGED"):
            journal.recheck_in_transaction(connection, resolved)
        with pytest.raises(JournalConflict, match="HISTORICAL_READ_CHANGED"):
            journal.recheck_in_transaction(connection, resolved, require_current_head=False)


def test_partial_restore_and_oversized_storage_fail_detached_resolution(engine):
    journal = store(engine)
    journal.append(key(), append())
    with engine.begin() as connection:
        connection.execute(sa.update(journal_streams).values(last_sequence=0))
    with pytest.raises(JournalConflict, match="ORPHAN_ROWS"):
        journal.resolve_snapshot(capture(journal, engine))
    with engine.begin() as connection:
        connection.execute(
            sa.update(journal_streams).values(last_sequence=1, key_payload=b"x" * 1000000)
        )
    snapshot = capture(journal, engine)
    assert len(snapshot.stream["key_payload"]) == 16 * 1024 + 1
    with pytest.raises(JournalConflict):
        journal.resolve_snapshot(snapshot)


def test_stalled_detached_decoder_does_not_block_another_writer(engine):
    entered, release = Event(), Event()

    class SlowCodec:
        def encode_record(self, value):
            return personal_codec.encode_record(value)

        def decode_record(self, data, expected):
            entered.set()
            assert release.wait(timeout=5)
            return personal_codec.decode_record(data, expected)

    writer = store(engine)
    first = writer.append(key(), append())
    reader = store(engine, SlowCodec())
    snapshot = capture(reader, engine)
    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(reader.resolve_snapshot, snapshot)
        try:
            assert entered.wait(timeout=5)
            second = pool.submit(writer.append, key(), append(2, first.committed_head)).result(
                timeout=3
            )
            assert second.committed_head.sequence == 2
        finally:
            release.set()
        assert future.result(timeout=3).receipt == first


def test_read_rechecks_require_original_store_and_real_transaction(engine):
    journal = store(engine)
    snapshot = capture(journal, engine)
    resolved = journal.resolve_snapshot(snapshot)
    with pytest.raises(JournalConflict, match="OWNER_DIFFERS"):
        store(engine).resolve_snapshot(snapshot)
    with engine.connect() as connection:
        with pytest.raises(JournalConflict, match="TRANSACTION_REQUIRED"):
            journal.capture_in_transaction(connection, key())
        connection.begin()
        with pytest.raises(JournalConflict, match="EXPLICIT_TRANSACTION_REQUIRED"):
            journal.recheck_in_transaction(connection, resolved)
        with pytest.raises(JournalConflict, match="EXPLICIT_TRANSACTION_REQUIRED"):
            journal.capture_in_transaction(connection, key())
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        with pytest.raises(JournalConflict, match="OWNER_DIFFERS"):
            journal.recheck_in_transaction(
                connection, replace(resolved, head=replace(resolved.head, sequence=1))
            )


def _resolution_facts(previous, command, number):
    """Small real domain values; row authentication is stubbed by the fake below."""
    record = JournalRecord(f"record-{number}", "observation/1", b"synthetic")
    request = JournalAppend(command, content_digest(command), previous, (record,))
    entry = JournalEntry(
        previous.key_sha256, previous.sequence + 1, command, record, previous.entry_sha256
    )
    receipt = JournalReceipt(
        command,
        request.command_sha256,
        request.semantic_sha256,
        previous,
        entry.head,
        (record.record_id,),
        (record.payload_sha256,),
    )
    rows = _ReceiptRows(
        MappingProxyType({"command_id": command}),
        (MappingProxyType({"sequence": entry.sequence}),),
        None,
    )
    return entry, receipt, rows


class _ResolutionJournal(SqlDurableJournal):
    """Exercise the real resolver with no engine, connection, SQL or codec.

    The three detached validators supply bounded synthetic outcomes. Their
    changing outcomes describe a possible dynamic boundary, not codec timings
    or a complete model of production row authentication.
    """

    def __init__(self, journal_key, entry, receipt_rows, receipt_results):
        self._preparation_owner = object()
        self.key = journal_key
        self.entry = entry
        self.head = entry.head
        self.stream = MappingProxyType({"last_sequence": self.head.sequence})
        self.anchor = MappingProxyType({"sequence": entry.sequence})
        self.receipt_rows = receipt_rows
        self.receipt_results = receipt_results
        self.events = []
        self.receipts = 0

    def snapshot(self, command, head_rows, requested_rows):
        return JournalReadSnapshot(
            self.key,
            command,
            self.stream,
            self.anchor,
            head_rows,
            requested_rows,
            False,
            False,
            self._preparation_owner,
        )

    def _validate_stream(self, journal_key, row):
        assert journal_key is self.key and row is self.stream
        self.events.append("stream")
        return self.head

    def _decode_entry(self, row, *, typed=True):
        assert row is self.anchor and typed is True
        self.events.append("anchor")
        return self.entry

    def _receipt(self, journal_key, rows, *, typed=True):
        assert journal_key is self.key and typed is True
        assert rows is self.receipt_rows[self.receipts]
        result = self.receipt_results[self.receipts]
        self.receipts += 1
        self.events.append("receipt")
        if isinstance(result, BaseException):
            raise result
        return result


@pytest.mark.parametrize("distinct_rows", [False, True], ids=["same-object", "equal-distinct"])
def test_detached_resolution_latest_receipt_preserves_second_result_identity(distinct_rows):
    journal_key = key()
    entry, head_receipt, head_rows = _resolution_facts(empty_head(journal_key), "command-1", 1)
    requested_rows = (
        replace(
            head_rows,
            append=MappingProxyType(dict(head_rows.append)),
            entries=tuple(MappingProxyType(dict(row)) for row in head_rows.entries),
        )
        if distinct_rows
        else head_rows
    )
    assert requested_rows == head_rows
    assert (requested_rows is head_rows) is not distinct_rows
    requested_receipt = replace(head_receipt)
    journal = _ResolutionJournal(
        journal_key, entry, (head_rows, requested_rows), (head_receipt, requested_receipt)
    )
    snapshot = journal.snapshot("command-1", head_rows, requested_rows)

    resolved = journal.resolve_snapshot(snapshot)

    assert resolved.snapshot is snapshot
    assert resolved.head is journal.head
    assert resolved.receipt is requested_receipt and resolved.receipt is not head_receipt
    assert resolved._owner is journal._preparation_owner
    assert all(
        original is current
        for original, current in zip(
            resolved._validated_values, (snapshot, journal.head, requested_receipt), strict=True
        )
    )
    assert journal.events == ["stream", "anchor", "receipt", "receipt"]


def test_detached_resolution_historical_receipt_keeps_current_head():
    journal_key = key()
    _, historical, historical_rows = _resolution_facts(empty_head(journal_key), "command-1", 1)
    entry, latest, head_rows = _resolution_facts(historical.committed_head, "command-2", 2)
    journal = _ResolutionJournal(
        journal_key, entry, (head_rows, historical_rows), (latest, historical)
    )
    snapshot = journal.snapshot("command-1", head_rows, historical_rows)

    resolved = journal.resolve_snapshot(snapshot)

    assert resolved.snapshot is snapshot
    assert resolved.head is journal.head and resolved.head == latest.committed_head
    assert resolved.receipt is historical
    assert resolved.receipt.committed_head.sequence < resolved.head.sequence
    assert journal.events == ["stream", "anchor", "receipt", "receipt"]


def test_detached_resolution_without_requested_receipt_still_authenticates_head():
    journal_key = key()
    entry, receipt, head_rows = _resolution_facts(empty_head(journal_key), "command-1", 1)
    journal = _ResolutionJournal(journal_key, entry, (head_rows,), (receipt,))
    snapshot = journal.snapshot(None, head_rows, None)

    resolved = journal.resolve_snapshot(snapshot)

    assert resolved.snapshot is snapshot and resolved.head is journal.head
    assert resolved.receipt is None
    assert journal.events == ["stream", "anchor", "receipt"]


def test_detached_resolution_foreign_owner_fails_before_detached_validators():
    journal_key = key()
    entry, receipt, rows = _resolution_facts(empty_head(journal_key), "command-1", 1)
    journal = _ResolutionJournal(journal_key, entry, (rows,), (receipt,))
    snapshot = replace(journal.snapshot("command-1", rows, rows), _owner=object())

    with pytest.raises(JournalConflict, match="JOURNAL_READ_SNAPSHOT_OWNER_DIFFERS"):
        journal.resolve_snapshot(snapshot)

    assert journal.events == []


@pytest.mark.parametrize("invalid", ["anchor", "head-receipt"])
def test_detached_resolution_invalid_head_precedes_requested_decode(invalid):
    journal_key = key()
    old_entry, old_receipt, _ = _resolution_facts(empty_head(journal_key), "command-1", 1)
    entry, latest, rows = _resolution_facts(old_receipt.committed_head, "command-2", 2)
    never_reached = RuntimeError("requested decoder must not run")
    journal = _ResolutionJournal(journal_key, entry, (rows, rows), (old_receipt, never_reached))
    snapshot = journal.snapshot("command-2", rows, rows)
    if invalid == "anchor":
        journal.entry = old_entry

    with pytest.raises(JournalConflict, match="JOURNAL_HEAD_ENTRY_INVALID"):
        journal.resolve_snapshot(snapshot)

    assert journal.head == latest.committed_head
    assert journal.events == ["stream", "anchor"] + (
        ["receipt"] if invalid == "head-receipt" else []
    )


def test_detached_resolution_second_receipt_fault_is_not_hidden_by_first_success():
    journal_key = key()
    entry, receipt, rows = _resolution_facts(empty_head(journal_key), "command-1", 1)
    fault = JournalConflict("second detached receipt rejected")
    journal = _ResolutionJournal(journal_key, entry, (rows, rows), (receipt, fault))

    with pytest.raises(JournalConflict) as caught:
        journal.resolve_snapshot(journal.snapshot("command-1", rows, rows))

    assert caught.value is fault
    assert journal.events == ["stream", "anchor", "receipt", "receipt"]


@pytest.mark.parametrize("changed", ["command", "future-head"])
def test_detached_resolution_rejects_changed_second_receipt(changed):
    journal_key = key()
    entry, receipt, rows = _resolution_facts(empty_head(journal_key), "command-1", 1)
    if changed == "command":
        second = replace(receipt, command_id="different-command")
    else:
        _, second, _ = _resolution_facts(receipt.committed_head, "command-1", 2)
    journal = _ResolutionJournal(journal_key, entry, (rows, rows), (receipt, second))

    with pytest.raises(JournalConflict, match="JOURNAL_RECEIPT_AFTER_HEAD"):
        journal.resolve_snapshot(journal.snapshot("command-1", rows, rows))

    assert journal.events == ["stream", "anchor", "receipt", "receipt"]


class _MemoryResolutionJournal(SqlDurableJournal):
    """Keep every real detached validator; install no engine or connection."""

    def __init__(self, codec):
        self._preparation_owner = object()
        self._codec = codec
        self._types = MappingProxyType({"observation/1": Observation})


class _ObservationDecodeCodec:
    def __init__(self, *, reject_third=False):
        self.reject_third = reject_third
        self.observations = 0
        self.keys = 0

    def encode_record(self, value):
        return personal_codec.encode_record(value)

    def decode_record(self, payload, expected):
        if expected is JournalKey:
            self.keys += 1
        elif expected is Observation:
            self.observations += 1
            if self.reject_third and self.observations == 3:
                raise ValueError("third Observation decode rejected")
        return personal_codec.decode_record(payload, expected)


def _canonical_resolution_snapshot(journal):
    journal_key = key()
    request = append()
    record = request.records[0]
    previous = request.expected_head
    entry = JournalEntry(
        journal_key.semantic_sha256, 1, request.command_id, record, previous.entry_sha256
    )
    receipt = JournalReceipt(
        request.command_id,
        request.command_sha256,
        request.semantic_sha256,
        previous,
        entry.head,
        (record.record_id,),
        (record.payload_sha256,),
    )
    anchor = MappingProxyType(
        {
            "key_sha256": entry.key_sha256,
            "sequence": entry.sequence,
            "command_id": entry.command_id,
            "record_id": record.record_id,
            "schema_id": record.schema_id,
            "payload": record.payload,
            "payload_sha256": record.payload_sha256,
            "previous_entry_sha256": entry.previous_entry_sha256,
            "entry_sha256": entry.semantic_sha256,
        }
    )
    rows = _ReceiptRows(
        MappingProxyType(
            {
                "key_sha256": entry.key_sha256,
                "command_id": request.command_id,
                "command_sha256": request.command_sha256,
                "append_sha256": request.semantic_sha256,
                "previous_sequence": previous.sequence,
                "previous_entry_sha256": previous.entry_sha256,
                "last_sequence": entry.sequence,
                "last_entry_sha256": entry.semantic_sha256,
                "receipt_sha256": receipt.semantic_sha256,
            }
        ),
        (anchor,),
        None,
    )
    stream = MappingProxyType(
        {
            "key_sha256": journal_key.semantic_sha256,
            "key_payload": personal_codec.encode_record(journal_key),
            "last_sequence": entry.sequence,
            "last_entry_sha256": entry.semantic_sha256,
        }
    )
    return (
        JournalReadSnapshot(
            journal_key,
            request.command_id,
            stream,
            anchor,
            rows,
            rows,
            False,
            False,
            journal._preparation_owner,
        ),
        receipt,
    )


def test_detached_resolution_real_validators_accept_canonical_memory_rows():
    codec = _ObservationDecodeCodec()
    journal = _MemoryResolutionJournal(codec)
    snapshot, expected = _canonical_resolution_snapshot(journal)

    resolved = journal.resolve_snapshot(snapshot)

    assert resolved.snapshot is snapshot
    assert resolved.head == expected.committed_head
    assert resolved.receipt == expected and resolved.receipt is not expected
    assert resolved._owner is journal._preparation_owner
    assert codec.keys == 1 and codec.observations == 3


def test_detached_resolution_real_receipt_rejects_third_observation_decode():
    codec = _ObservationDecodeCodec(reject_third=True)
    journal = _MemoryResolutionJournal(codec)
    snapshot, _ = _canonical_resolution_snapshot(journal)

    with pytest.raises(JournalConflict) as caught:
        journal.resolve_snapshot(snapshot)

    assert str(caught.value) == "JOURNAL_RECEIPT_INVALID"
    assert codec.keys == 1 and codec.observations == 3
