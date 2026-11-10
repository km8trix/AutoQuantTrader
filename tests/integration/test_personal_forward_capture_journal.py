"""Actual disposable journal/object persistence; all responses are synthetic fixtures."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from threading import Barrier

import pytest
import sqlalchemy as sa

from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.application.personal_forward_capture import (
    ForwardCaptureError,
    capture_forward,
    read_capture,
    replay_capture,
)
from packages.domain.durable_journal_contracts import empty_head
from packages.domain.forward_capture_contracts import CAPTURE_SCHEMA, ForwardCaptureRecord
from packages.domain.forward_contracts import ForwardDataState
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import JOURNAL_TABLES, journal_entries
from packages.persistence.forward_capture_publication import SqlForwardCapturePublication
from packages.persistence.schema import metadata
from tests.unit.test_personal_forward_capture import AT, Clock, Transport, Verifier, request


@pytest.fixture
def retained(tmp_path):
    path = tmp_path / "capture.sqlite"
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    metadata.create_all(engine, tables=JOURNAL_TABLES)
    objects = LocalResearchArtifactStore(tmp_path / "private-objects")
    yield engine, objects, path
    engine.dispose()


def journal(engine):
    return SqlDurableJournal(
        engine, codec=personal_codec, record_types={CAPTURE_SCHEMA: ForwardCaptureRecord}
    )


def capture(req, state, j, objects, *, clock=None, transport=None, head=None):
    return capture_forward(
        req,
        state,
        expected_head=empty_head(req.journal_key) if head is None else head,
        clock=Clock() if clock is None else clock,
        verifier=Verifier(),
        transport=Transport() if transport is None else transport,
        journal=j,
        artifacts=objects,
        codec=personal_codec,
        publisher=SqlForwardCapturePublication(j._engine, journal=j),
    )


def test_durable_restart_retains_exact_receipt_and_raw_bytes(retained):
    engine, objects, path = retained
    req = request()
    state = ForwardDataState((req.source,), "recorded")
    pub = capture(req, state, journal(engine), objects)
    expected = replay_capture(pub.record, state, artifacts=objects)
    engine.dispose()
    restarted = create_database_engine(f"sqlite+pysqlite:///{path}")
    try:
        found = read_capture(
            req, journal=journal(restarted), artifacts=objects, codec=personal_codec
        )
        assert found == pub
        assert replay_capture(found.record, state, artifacts=objects) == expected
        raw = objects.read(found.record.raw_object)
        assert b'"QuoteResponse"' in raw and b'"$record"' not in raw
    finally:
        restarted.dispose()


def test_fixed_through_original_retry_after_later_append_and_tamper(retained):
    engine, objects, _ = retained
    req, j = request(), journal(engine)
    state = ForwardDataState((req.source,), "recorded")
    first = capture(req, state, j, objects)
    next_state = replay_capture(first.record, state, artifacts=objects)
    second = capture(
        replace(req, capture_id="later"),
        next_state,
        j,
        objects,
        clock=Clock(AT + timedelta(seconds=1)),
        head=first.journal_receipt.committed_head,
    )
    assert read_capture(req, journal=j, artifacts=objects, codec=personal_codec) == first
    assert j.read_head(req.journal_key) == second.journal_receipt.committed_head
    with engine.begin() as connection:
        connection.execute(
            sa.update(journal_entries).where(journal_entries.c.sequence == 1).values(payload=b"{}")
        )
    with pytest.raises(ForwardCaptureError):
        read_capture(req, journal=j, artifacts=objects, codec=personal_codec)


def test_failed_metadata_publication_leaves_no_visible_capture(retained):
    engine, objects, _ = retained
    req, real = request(), journal(engine)
    state = ForwardDataState((req.source,), "recorded")

    def fail(*args):
        raise OSError("review-only-private-journal-failure")

    sa.event.listen(engine, "commit", fail, once=True)
    with pytest.raises(ForwardCaptureError) as error:
        capture(req, state, real, objects)
    assert "private" not in str(error.value)
    assert real.read_receipt(req.journal_key, req.capture_id) is None
    assert real.read_head(req.journal_key) == empty_head(req.journal_key)
    # Exact same bytes may remain unreferenced; a later explicit capture can publish.
    assert capture(req, state, real, objects).record.request == req


@pytest.mark.parametrize("same_id", [True, False])
def test_concurrent_cas_has_one_append_or_one_original_exact_ack(retained, same_id):
    engine, objects, _ = retained
    req, j = request(), journal(engine)
    state = ForwardDataState((req.source,), "recorded")
    barrier = Barrier(2)

    class WaitingTransport(Transport):
        def get(self, *args, **kwargs):
            barrier.wait(timeout=5)
            return super().get(*args, **kwargs)

    def run(index):
        value = req if same_id else replace(req, capture_id=f"concurrent-{index}")
        try:
            return capture(value, state, j, objects, transport=WaitingTransport())
        except ForwardCaptureError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, (1, 2)))
    good = [r for r in results if r is not None]
    assert len(good) == (2 if same_id else 1)
    if same_id:
        assert good[0] == good[1]
    assert j.read_head(req.journal_key).sequence == 1
    with engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(journal_entries)) == 1


def test_wrong_raw_bytes_or_non_raw_codec_cannot_replay(retained):
    engine, objects, _ = retained
    req = request()
    state = ForwardDataState((req.source,), "recorded")
    publication = capture(req, state, journal(engine), objects)
    with pytest.raises(ValueError, match="raw object"):
        replace(
            publication.record,
            raw_object=replace(publication.record.raw_object, codec_version="personal-record/1"),
        )

    class WrongBytes:
        def read(self, *args, **kwargs):
            return b"{}"

    with pytest.raises(ForwardCaptureError, match="RAW_OBJECT_DIFFERS"):
        replay_capture(publication.record, state, artifacts=WrongBytes())
