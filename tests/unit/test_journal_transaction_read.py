"""Account composition reads preserve their transaction and detached codec boundary."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from threading import Event

import pytest
import sqlalchemy as sa

from packages.application import personal_codec
from packages.domain.durable_journal_contracts import (
    JournalAppend,
    JournalKey,
    JournalRecord,
    empty_head,
)
from packages.domain.personal_contracts import ContractRecord, content_digest
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal import JournalConflict, SqlDurableJournal
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
