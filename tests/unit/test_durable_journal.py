from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from threading import Barrier, Event

import pytest
import sqlalchemy as sa

from packages.application import personal_codec
from packages.domain.durable_journal_contracts import (
    MAX_APPEND_BYTES,
    MAX_RECORD_BYTES,
    JournalAppend,
    JournalKey,
    JournalRecord,
    empty_head,
)
from packages.domain.personal_contracts import ContractRecord, content_digest
from packages.persistence import durable_journal as journal_module
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal import JournalConflict, SqlDurableJournal
from packages.persistence.durable_journal_schema import (
    JOURNAL_TABLES,
    journal_appends,
    journal_entries,
    journal_streams,
)
from packages.persistence.schema import metadata


@dataclass(frozen=True, slots=True)
class Fact(ContractRecord):
    label: str
    number: int
    parts: tuple[str, ...] = ()


def key(name="test-stream", namespace="capture"):
    return JournalKey(namespace, name, "synthetic-account", "fixture", "synthetic", "a" * 64)


def record(name="record-1", number=1):
    return JournalRecord(name, "fact/1", personal_codec.encode_record(Fact(name, number)))


def request(stream=None, command="command-1", *, head=None, records=None):
    stream = stream or key()
    return JournalAppend(
        command, content_digest(command), head or empty_head(stream), records or (record(),)
    )


def journal(engine, codec=personal_codec):
    return SqlDurableJournal(engine, codec=codec, record_types={"fact/1": Fact})


@pytest.fixture
def engine(tmp_path):
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/journal.sqlite")
    metadata.create_all(engine, tables=JOURNAL_TABLES)
    yield engine
    engine.dispose()


def contents(engine):
    with engine.connect() as connection:
        return tuple(
            tuple(connection.execute(sa.select(table).order_by(*table.primary_key.columns)))
            for table in JOURNAL_TABLES
        )


def test_roundtrip_exact_retry_after_later_append_and_fixed_prefix(engine):
    store = journal(engine)
    stream = key()
    assert store.read_head(stream) == empty_head(stream)
    assert store.read_receipt(stream, "unknown") is None
    first = request(stream, records=(record("one"), record("two")))
    receipt = store.append(stream, first)
    second = store.append(
        stream, request(stream, "second", head=receipt.committed_head, records=(record("three"),))
    )
    assert store.append(stream, first) == receipt
    assert store.read_receipt(stream, first.command_id) == receipt
    assert store.read_head(stream) == second.committed_head
    page = store.read_page(stream, through_head=receipt.committed_head, limit=1)
    assert [e.record.record_id for e in page.entries] == ["one"] and not page.complete
    final = store.read_page(
        stream, through_head=receipt.committed_head, after_head=page.next_head, limit=1
    )
    assert [e.record.record_id for e in final.entries] == ["two"] and final.complete
    assert final.next_head == receipt.committed_head
    assert journal(engine).read_receipt(stream, "command-1") == receipt


@pytest.mark.parametrize("change", ["command_hash", "payload", "order", "expected_head"])
def test_retry_conflicts_do_not_change_any_table(engine, change):
    store = journal(engine)
    original = request(records=(record("one"), record("two")))
    receipt = store.append(key(), original)
    before = contents(engine)
    changed = {
        "command_hash": replace(original, command_sha256="b" * 64),
        "payload": replace(original, records=(record("one", 9), record("two"))),
        "order": replace(original, records=tuple(reversed(original.records))),
        "expected_head": replace(original, expected_head=receipt.committed_head),
    }[change]
    with pytest.raises(JournalConflict):
        store.append(key(), changed)
    assert contents(engine) == before


def test_late_record_conflict_rolls_back_new_records_receipt_and_head(engine):
    store = journal(engine)
    first = store.append(key(), request())
    before = contents(engine)
    failing = request(
        command="new-command", head=first.committed_head, records=(record("new-record"), record())
    )
    with pytest.raises(JournalConflict, match="RECORD_CONFLICT"):
        store.append(key(), failing)
    assert contents(engine) == before
    assert store.read_receipt(key(), "new-command") is None


def test_two_stale_head_writers_have_exactly_one_winner(engine):
    barrier = Barrier(2)

    def write(number):
        store = journal(engine)
        pending = request(command=f"writer-{number}", records=(record(f"record-{number}"),))
        barrier.wait(timeout=5)
        try:
            return store.append(key(), pending)
        except JournalConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(write, (1, 2)))
    assert sum(outcome is not None for outcome in outcomes) == 1
    assert tuple(len(rows) for rows in contents(engine)) == (1, 1, 1)


def test_rowcount_unknown_does_not_repeat_an_insert(engine):
    def unknown(_connection, statement, _multiparams, _params, _options, result):
        if statement.is_insert:
            result.rowcount = -1

    sa.event.listen(engine, "after_execute", unknown)
    try:
        store = journal(engine)
        receipt = store.append(key(), request())
        assert store.append(key(), request()) == receipt
    finally:
        sa.event.remove(engine, "after_execute", unknown)
    assert tuple(len(rows) for rows in contents(engine)) == (1, 1, 1)


def test_outer_rollback_and_caught_append_failure_preserve_outer_atomicity(engine):
    store = journal(engine)
    prepared = store.prepare_append(key(), request())
    with engine.connect() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        store.append_in_transaction(connection, prepared)
        assert connection.in_transaction()
        connection.rollback()
    assert contents(engine) == ((), (), ())
    receipt = store.append(key(), request())
    invalid = store.prepare_append(
        key(),
        request(command="conflict", head=receipt.committed_head, records=(record("new"), record())),
    )
    before = contents(engine)
    with engine.connect() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        with pytest.raises(JournalConflict):
            store.append_in_transaction(connection, invalid)
        assert connection.in_transaction()
        connection.commit()
    assert contents(engine) == before


def test_transaction_requires_prior_preparation_and_real_sqlite_begin(engine):
    store = journal(engine)
    prepared = store.prepare_append(key(), request())
    with engine.connect() as connection:
        with pytest.raises(JournalConflict, match="TRANSACTION_REQUIRED"):
            store.append_in_transaction(connection, prepared)
        connection.begin()
        with pytest.raises(JournalConflict, match="SQLITE_EXPLICIT"):
            store.append_in_transaction(connection, prepared)
        connection.rollback()
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        with pytest.raises(JournalConflict, match="PREPARATION_REQUIRED"):
            journal(engine).append_in_transaction(connection, prepared)
        altered = replace(
            prepared, entries=(replace(prepared.entries[0], record=record("changed")),)
        )
        with pytest.raises(JournalConflict, match="PREPARATION_CHANGED"):
            store.append_in_transaction(connection, altered)
        connection.rollback()


def test_typed_and_canonical_validation_happens_before_any_database_transaction(engine):
    transactions = []
    sa.event.listen(engine, "begin", lambda _: transactions.append(True))
    store = journal(engine)
    for bad in (
        replace(record(), schema_id="not-allowlisted"),
        replace(record(), payload=record().payload + b" "),
        replace(record(), payload=personal_codec.encode_record("wrong type")),
    ):
        with pytest.raises(JournalConflict):
            store.append(key(), request(records=(bad,)))
    assert not transactions


def test_write_transaction_never_calls_codec(engine):
    class Codec:
        inside = False

        def encode_record(self, value):
            assert not self.inside
            return personal_codec.encode_record(value)

        def decode_record(self, payload, expected):
            assert not self.inside
            return personal_codec.decode_record(payload, expected)

    codec = Codec()
    store = journal(engine, codec)
    prepared = store.prepare_append(key(), request())
    with engine.connect() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        codec.inside = True
        receipt = store.append_in_transaction(connection, prepared)
        assert store.append_in_transaction(connection, prepared) == receipt
        connection.commit()


def test_stalled_detached_decode_does_not_block_writer_commit(engine):
    entered, release = Event(), Event()

    class SlowCodec:
        encode_record = staticmethod(personal_codec.encode_record)

        @staticmethod
        def decode_record(payload, expected):
            if expected is Fact:
                entered.set()
                assert release.wait(5)
            return personal_codec.decode_record(payload, expected)

    store = journal(engine)
    first = store.append(key(), request())
    slow = journal(engine, SlowCodec())
    with ThreadPoolExecutor(max_workers=2) as pool:
        reader = pool.submit(slow.read_page, key(), through_head=first.committed_head)
        try:
            assert entered.wait(5)
            writer = pool.submit(
                store.append,
                key(),
                request(command="second", head=first.committed_head, records=(record("second"),)),
            )
            assert writer.result(timeout=2).committed_head.sequence == 2
        finally:
            release.set()
        assert reader.result(timeout=5).through_head == first.committed_head


@pytest.mark.parametrize(
    "table,column,value",
    [
        (journal_entries, "payload", b"invalid"),
        (journal_entries, "entry_sha256", "c" * 64),
        (journal_entries, "previous_entry_sha256", "c" * 64),
        (journal_entries, "schema_id", "unknown-schema"),
        (journal_appends, "receipt_sha256", "c" * 64),
        (journal_streams, "key_payload", b"invalid"),
    ],
)
def test_each_fresh_read_detects_changed_retained_rows(engine, table, column, value):
    store = journal(engine)
    receipt = store.append(key(), request())
    assert store.read_receipt(key(), "command-1") == receipt
    with engine.begin() as connection:
        connection.execute(sa.update(table).values({column: value}))
    with pytest.raises(JournalConflict):
        store.read_receipt(key(), "command-1")


def test_missing_chain_wrong_cursor_and_empty_head_corruption_reject(engine):
    store = journal(engine)
    result = store.append(key(), request(records=(record("one"), record("two"), record("three"))))
    wrong = replace(empty_head(key()), entry_sha256="c" * 64)
    with pytest.raises(JournalConflict):
        store.read_page(key(), through_head=result.committed_head, after_head=wrong)
    with engine.begin() as connection:
        connection.execute(sa.delete(journal_entries).where(journal_entries.c.sequence == 2))
    with pytest.raises(JournalConflict, match="MISSING_RECORDS"):
        store.read_page(key(), through_head=result.committed_head)
    with engine.begin() as connection:
        connection.execute(
            sa.update(journal_streams).values(
                last_sequence=0, last_entry_sha256=empty_head(key()).entry_sha256
            )
        )
    with pytest.raises(JournalConflict, match="EMPTY_HEAD_HAS_RECORDS"):
        store.read_head(key())


def test_size_count_and_cross_scope_boundaries(engine):
    with pytest.raises(ValueError):
        replace(record(), payload=b"x" * (MAX_RECORD_BYTES + 1))
    large = b"x" * MAX_RECORD_BYTES
    four = tuple(JournalRecord(f"large-{i}", "fact/1", large) for i in range(4))
    assert (
        sum(
            len(r.payload)
            for r in JournalAppend("command", "a" * 64, empty_head(key()), four).records
        )
        == MAX_APPEND_BYTES
    )
    with pytest.raises(ValueError):
        JournalAppend("command", "a" * 64, empty_head(key()), (*four, record("extra")))
    with pytest.raises(ValueError):
        request(records=tuple(record(f"r-{i}") for i in range(65)))
    store = journal(engine)
    with pytest.raises(JournalConflict):
        store.prepare_append(key(namespace="venue"), request())
    receipt = store.append(key(), request())
    for limit in (0, 257, True):
        with pytest.raises(JournalConflict):
            store.read_page(key(), through_head=receipt.committed_head, limit=limit)
    assert empty_head(key(namespace="venue")) != empty_head(key(namespace="coordinator"))
    with pytest.raises(ValueError):
        replace(key(), runtime_environment="production")


def test_page_256_boundary_and_current_empty_page(engine):
    store = journal(engine)
    head = empty_head(key())
    for batch in range(5):
        head = store.append(
            key(),
            request(
                command=f"batch-{batch}",
                head=head,
                records=tuple(record(f"row-{batch}-{i}") for i in range(64)),
            ),
        ).committed_head
    page = store.read_page(key(), through_head=head)
    assert len(page.entries) == 256 and not page.complete
    final = store.read_page(key(), through_head=head, after_head=page.next_head)
    assert len(final.entries) == 64 and final.complete
    empty = store.read_page(key(), through_head=head, after_head=head)
    assert not empty.entries and empty.complete


def test_overlong_retained_blob_is_transferred_bounded_then_rejected(engine):
    store = journal(engine)
    receipt = store.append(key(), request())
    with engine.begin() as connection:
        connection.execute(sa.update(journal_entries).values(payload=b"x" * (MAX_RECORD_BYTES * 4)))
    lengths = []
    original = store._decode_entry

    def measured(row, **kwargs):
        lengths.append(len(row["payload"]))
        return original(row, **kwargs)

    store._decode_entry = measured
    with pytest.raises(JournalConflict):
        store.read_page(key(), through_head=receipt.committed_head)
    assert lengths == [MAX_RECORD_BYTES + 1]


def test_concurrent_identical_retry_returns_one_original_receipt(engine):
    barrier = Barrier(2)
    pending = request()

    def write(_number):
        store = journal(engine)
        barrier.wait(timeout=5)
        return store.append(key(), pending)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = tuple(pool.map(write, (1, 2)))
    assert first == second
    assert tuple(len(rows) for rows in contents(engine)) == (1, 1, 1)


def test_retry_validates_current_head_after_subsequent_append(engine):
    store = journal(engine)
    pending = request()
    first = store.append(key(), pending)
    store.append(
        key(), request(command="second", head=first.committed_head, records=(record("second"),))
    )
    with engine.begin() as connection:
        connection.execute(sa.update(journal_streams).values(last_entry_sha256="c" * 64))
    before = contents(engine)
    with pytest.raises(JournalConflict, match="HEAD_ENTRY_INVALID"):
        store.append(key(), pending)
    assert contents(engine) == before


def test_prepared_key_bytes_and_receipt_inventory_remain_original(engine):
    store = journal(engine)
    prepared = store.prepare_append(key(), request())
    with engine.connect() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        for changed in (
            replace(prepared, key_payload=b"altered"),
            replace(prepared, receipt=replace(prepared.receipt, record_hashes=("b" * 64,))),
        ):
            with pytest.raises(JournalConflict, match="PREPARATION_CHANGED"):
                store.append_in_transaction(connection, changed)
        connection.commit()
    assert contents(engine) == ((), (), ())


def test_exact_canonical_aggregate_limit_roundtrips(engine):
    store = journal(engine)
    records = []
    for number in range(4):
        name = f"large-{number}"
        parts = ("x" * 65536,) * 3
        remaining = MAX_RECORD_BYTES - len(
            personal_codec.encode_record(Fact(name, number, (*parts, "")))
        )
        payload = personal_codec.encode_record(Fact(name, number, (*parts, "y" * remaining)))
        assert len(payload) == MAX_RECORD_BYTES
        records.append(JournalRecord(name, "fact/1", payload))
    pending = request(records=tuple(records))
    receipt = store.append(key(), pending)
    page = store.read_page(key(), through_head=receipt.committed_head)
    assert tuple(entry.record for entry in page.entries) == pending.records
    assert sum(len(entry.record.payload) for entry in page.entries) == MAX_APPEND_BYTES


def test_resigned_broken_page_chain_fails_with_sanitized_error(engine):
    store = journal(engine)
    result = store.append(key(), request(records=(record("one"), record("two"), record("three"))))
    page = store.read_page(key(), through_head=result.committed_head)
    changed = replace(page.entries[1], previous_entry_sha256="b" * 64)
    with engine.begin() as connection:
        connection.execute(
            sa.update(journal_entries)
            .where(journal_entries.c.sequence == 2)
            .values(
                previous_entry_sha256=changed.previous_entry_sha256,
                entry_sha256=changed.semantic_sha256,
            )
        )
    with pytest.raises(JournalConflict, match="PAGE_CHAIN_INVALID"):
        store.read_page(key(), through_head=result.committed_head)


_METADATA_COLUMNS = tuple(
    (table, column)
    for table in JOURNAL_TABLES
    for column in table.c
    if isinstance(column.type, (sa.String, sa.BigInteger))
)


@pytest.mark.parametrize(
    "table,column",
    _METADATA_COLUMNS,
    ids=tuple(f"{table.name}.{column.name}" for table, column in _METADATA_COLUMNS),
)
def test_corrupt_sqlite_metadata_transfer_is_bounded_before_detached_validation(
    engine, table, column
):
    journal(engine).append(key(), request())
    # Model damaged/restored rows, including SQLite's permissive storage classes.
    # These pragmas are confined to this disposable corruption-fixture connection.
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.exec_driver_sql("PRAGMA ignore_check_constraints=ON")
        connection.exec_driver_sql(
            f"UPDATE {table.name} SET {column.name} = ?", ("x" * (1024 * 1024),)
        )
        connection.commit()
        connection.exec_driver_sql("PRAGMA ignore_check_constraints=OFF")
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        connection.commit()
        copied = dict(
            connection.execute(sa.select(*journal_module._columns(table, connection)))
            .mappings()
            .one()
        )
    if isinstance(column.type, sa.String):
        assert type(copied[column.name]) is str
        assert len(copied[column.name]) == column.type.length + 1
    else:
        assert copied[column.name] is None
    with pytest.raises(JournalConflict, match="RETAINED_ROW_INVALID"):
        journal_module._validate_row(copied, table)


def test_wrong_sqlite_text_storage_class_is_rejected_exactly(engine):
    store = journal(engine)
    receipt = store.append(key(), request())
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE personal_journal_entries SET schema_id = ?", (b"fact/1",)
        )
    with pytest.raises(JournalConflict, match="ENTRY_INVALID"):
        store.read_page(key(), through_head=receipt.committed_head)


def test_partial_restore_with_empty_head_and_retained_tail_cannot_append_or_publish_empty_page(
    engine,
):
    store = journal(engine)
    first = store.append(key(), request())
    store.append(
        key(), request(command="second", head=first.committed_head, records=(record("second"),))
    )
    with engine.begin() as connection:
        connection.execute(sa.delete(journal_entries).where(journal_entries.c.sequence == 1))
        connection.execute(
            sa.delete(journal_appends).where(journal_appends.c.command_id == "command-1")
        )
        connection.execute(
            sa.update(journal_streams).values(
                last_sequence=0, last_entry_sha256=empty_head(key()).entry_sha256
            )
        )
    before = contents(engine)
    assert tuple(len(rows) for rows in before) == (1, 1, 1)
    for operation in (
        lambda: store.append(key(), request(command="new-first", records=(record("new-first"),))),
        lambda: store.read_head(key()),
        lambda: store.read_page(key(), through_head=empty_head(key())),
    ):
        with pytest.raises(JournalConflict, match="EMPTY_HEAD_HAS_RECORDS"):
            operation()
        assert contents(engine) == before


def test_prepared_append_readback_is_read_only_without_codec_and_allows_original_prefix(
    engine, monkeypatch
):
    store = journal(engine)
    first = store.prepare_append(key(), request())
    second = store.prepare_append(
        key(),
        request(command="second", head=first.receipt.committed_head, records=(record("second"),)),
    )
    with journal_module._write(engine) as connection:
        store.append_in_transaction(connection, first)
        store.append_in_transaction(connection, second)

        def forbidden(*args, **kwargs):
            pytest.fail("prepared append readback must not use a codec or append")

        def only_read(conn, cursor, statement, parameters, context, executemany):
            assert statement.lstrip().upper().startswith("SELECT"), statement

        with monkeypatch.context() as guarded:
            guarded.setattr(personal_codec, "encode_record", forbidden)
            guarded.setattr(personal_codec, "decode_record", forbidden)
            guarded.setattr(store, "append_in_transaction", forbidden)
            sa.event.listen(connection, "before_cursor_execute", only_read)
            try:
                assert (
                    store.recheck_prepared_append_in_transaction(connection, second)
                    is second.receipt
                )
                assert (
                    store.recheck_prepared_append_in_transaction(
                        connection, first, require_current_head=False
                    )
                    is first.receipt
                )
                with pytest.raises(JournalConflict, match="HEAD_DIFFERS"):
                    store.recheck_prepared_append_in_transaction(connection, first)
            finally:
                sa.event.remove(connection, "before_cursor_execute", only_read)


@pytest.mark.parametrize(
    "change", ["deleted_entry", "entry_payload", "append", "key", "head", "previous", "oversize"]
)
def test_prepared_append_readback_rejects_corrupt_rows_without_repair(engine, change, monkeypatch):
    store = journal(engine)
    first = store.append(key(), request())
    prepared = store.prepare_append(
        key(), request(command="second", head=first.committed_head, records=(record("second"),))
    )
    with journal_module._write(engine) as connection:
        store.append_in_transaction(connection, prepared)
        if change == "deleted_entry":
            connection.execute(sa.delete(journal_entries).where(journal_entries.c.sequence == 2))
        elif change in ("entry_payload", "oversize"):
            connection.execute(
                sa.update(journal_entries)
                .where(journal_entries.c.sequence == 2)
                .values(payload=sa.func.zeroblob(2 * 1024 * 1024) if change == "oversize" else b"x")
            )
        elif change == "append":
            connection.execute(
                sa.update(journal_appends)
                .where(journal_appends.c.command_id == "second")
                .values(command_sha256="b" * 64)
            )
        elif change == "key":
            connection.execute(sa.update(journal_streams).values(key_payload=b"different"))
        elif change == "head":
            connection.execute(sa.update(journal_streams).values(last_entry_sha256="d" * 64))
        else:
            connection.execute(
                sa.update(journal_entries)
                .where(journal_entries.c.sequence == 1)
                .values(payload=b"changed predecessor")
            )
    before = contents(engine)

    def forbidden(*args, **kwargs):
        pytest.fail("prepared readback must reject corrupt rows without decoding or repairing")

    monkeypatch.setattr(personal_codec, "decode_record", forbidden)
    monkeypatch.setattr(store, "append_in_transaction", forbidden)
    with journal_module._write(engine) as connection, pytest.raises(JournalConflict):
        store.recheck_prepared_append_in_transaction(connection, prepared)
    assert contents(engine) == before


@pytest.mark.parametrize("change", ["copy", "foreign", "wrapper", "request", "record", "receipt"])
def test_prepared_append_readback_requires_exact_original_owned_graph(engine, change):
    store = journal(engine)
    prepared = store.prepare_append(key(), request())
    with journal_module._write(engine) as connection:
        store.append_in_transaction(connection, prepared)
    before = contents(engine)
    if change == "copy":
        prepared = replace(prepared)
    elif change == "foreign":
        store = journal(engine)
    elif change == "wrapper":
        object.__setattr__(prepared, "key_payload", b"changed")
    elif change == "request":
        object.__setattr__(prepared.request, "command_id", "changed")
    elif change == "record":
        object.__setattr__(prepared.request.records[0], "payload", b"changed")
    else:
        object.__setattr__(prepared.receipt.committed_head, "entry_sha256", "b" * 64)
    with (
        journal_module._write(engine) as connection,
        pytest.raises(JournalConflict, match="ORIGINAL_PREPARATION"),
    ):
        store.recheck_prepared_append_in_transaction(connection, prepared)
    assert contents(engine) == before


def test_prepared_append_readback_does_not_create_a_missing_append(engine):
    store = journal(engine)
    prepared = store.prepare_append(key(), request())
    with (
        journal_module._write(engine) as connection,
        pytest.raises(JournalConflict, match="MISSING"),
    ):
        store.recheck_prepared_append_in_transaction(connection, prepared)
    assert contents(engine) == ((), (), ())


def test_prepared_append_readback_ownership_is_weak(engine):
    import gc
    import weakref

    store = journal(engine)
    prepared = store.prepare_append(key(), request())
    identity = id(prepared)
    reference = weakref.ref(prepared)
    assert identity in store._prepared_appends and identity in store._prepared_readbacks
    del prepared
    gc.collect()
    assert reference() is None
    assert identity not in store._prepared_appends and identity not in store._prepared_readbacks
