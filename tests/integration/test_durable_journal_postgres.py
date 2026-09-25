"""Explicit disposable PostgreSQL journal parity; no ambient service activation."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier
from uuid import uuid4

import pytest
import sqlalchemy as sa

from packages.persistence.durable_journal import JournalConflict
from packages.persistence.durable_journal_schema import JOURNAL_TABLES
from packages.persistence.schema import metadata
from tests.integration.test_phase2_postgres_exit import postgres_engine as postgres_engine
from tests.unit.test_durable_journal import journal, key, record, request


@pytest.fixture
def scoped_journal(postgres_engine):
    metadata.create_all(postgres_engine, tables=JOURNAL_TABLES)
    stream = key("postgres-" + uuid4().hex)
    yield postgres_engine, journal(postgres_engine), stream
    with postgres_engine.begin() as connection:
        for table in reversed(JOURNAL_TABLES):
            connection.execute(sa.delete(table).where(table.c.key_sha256 == stream.semantic_sha256))


def test_postgres_exact_retry_late_conflict_and_outer_rollback(scoped_journal):
    engine, store, stream = scoped_journal
    original = request(stream)
    first = store.append(stream, original)
    second = store.append(
        stream, request(stream, "second", head=first.committed_head, records=(record("second"),))
    )
    assert store.append(stream, original) == first
    assert store.read_receipt(stream, original.command_id) == first
    with engine.connect() as connection:
        before = tuple(
            tuple(
                connection.execute(
                    sa.select(table).where(table.c.key_sha256 == stream.semantic_sha256)
                )
            )
            for table in JOURNAL_TABLES
        )
    conflict = request(
        stream, "conflict", head=second.committed_head, records=(record("uncommitted"), record())
    )
    with pytest.raises(JournalConflict):
        store.append(stream, conflict)
    prepared = store.prepare_append(stream, replace(conflict, records=(record("rolled-back"),)))
    with engine.connect() as connection:
        connection.begin()
        store.append_in_transaction(connection, prepared)
        connection.rollback()
    with engine.connect() as connection:
        after = tuple(
            tuple(
                connection.execute(
                    sa.select(table).where(table.c.key_sha256 == stream.semantic_sha256)
                )
            )
            for table in JOURNAL_TABLES
        )
    assert after == before
    assert store.read_head(stream) == second.committed_head
    assert store.read_page(stream, through_head=first.committed_head).complete


def test_postgres_concurrent_stale_head_has_one_winner(scoped_journal):
    engine, store, stream = scoped_journal
    barrier = Barrier(2)

    def write(number):
        pending = request(stream, f"writer-{number}", records=(record(f"record-{number}"),))
        barrier.wait(timeout=5)
        try:
            return journal(engine).append(stream, pending)
        except JournalConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(write, (1, 2)))
    assert sum(value is not None for value in outcomes) == 1
    assert store.read_head(stream).sequence == 1


def test_postgres_concurrent_identical_retry_returns_original_receipt(scoped_journal):
    engine, store, stream = scoped_journal
    barrier = Barrier(2)
    pending = request(stream)

    def write(_number):
        barrier.wait(timeout=5)
        return journal(engine).append(stream, pending)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = tuple(pool.map(write, (1, 2)))
    assert first == second
    assert store.read_head(stream).sequence == 1
    assert store.read_receipt(stream, pending.command_id) == first
