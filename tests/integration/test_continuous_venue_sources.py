"""Retained synthetic venue closure, actual coordinator SQLite and private objects."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
from threading import Event

import pytest
import sqlalchemy as sa

from packages.application import personal_codec
from packages.application.venue_reconciliation import VenueReconciliationResolver
from packages.domain.applied_reconciliation import assess_reconciliation_coverage
from packages.domain.durable_journal_contracts import JournalAppend, JournalRecord
from packages.domain.venue_reconciliation_contracts import VENUE_CAPTURE_SCHEMA
from packages.persistence import continuous_venue_sources as source_module
from packages.persistence.continuous_venue_sources import (
    ContinuousVenueSourceError,
    SqlContinuousVenueSources,
)
from packages.persistence.database import _repeatable_read_transaction, create_database_engine
from packages.persistence.durable_journal_schema import journal_entries
from tests.integration.test_stateful_venue_journal import retained  # noqa: F401
from tests.integration.test_venue_reconciliation_capture import (  # noqa: F401
    TransitionDelegate,
    capture_store,
)


@pytest.fixture
def case(capture_store):  # noqa: F811 - shared disposable fixture
    captures, venue, request, _ = capture_store
    capture = captures.capture(request, venue=venue)
    resolver = VenueReconciliationResolver(transition_resolver=TransitionDelegate())
    sources = SqlContinuousVenueSources(
        captures.engine,
        artifacts=captures.artifacts,
        codec=personal_codec,
        resolver=resolver,
        scope=request.binding.scope,
        model=request.binding.model,
    )
    return captures, venue, capture, sources


def test_original_capture_reconstructs_from_one_coherent_snapshot_without_venue(case, monkeypatch):
    captures, venue, capture, sources = case
    active = set()
    transactions = []

    def begin(connection):
        active.add(id(connection))
        transactions.append(connection)

    sa.event.listen(captures.engine, "begin", begin)
    sa.event.listen(captures.engine, "commit", lambda conn: active.discard(id(conn)))
    sa.event.listen(captures.engine, "rollback", lambda conn: active.discard(id(conn)))
    encode, decode, read = (
        personal_codec.encode_record,
        personal_codec.decode_record,
        captures.artifacts.read,
    )

    class DetachedCodec:
        def encode_record(self, value):
            assert not active, "codec under SQL"
            return encode(value)

        def decode_record(self, payload, expected_type):
            assert not active, "codec under SQL"
            return decode(payload, expected_type)

    def detached_read(*args, **kwargs):
        assert not active, "object IO under SQL"
        return read(*args, **kwargs)

    def forbidden(*args, **kwargs):
        pytest.fail("source closure queried independent venue")

    sources.codec = DetachedCodec()
    sources.journal._codec = sources.codec
    monkeypatch.setattr(captures.artifacts, "read", detached_read)
    monkeypatch.setattr(venue, "read", forbidden)
    monkeypatch.setattr(venue, "facts", forbidden)
    value = sources.resolve(capture)
    sources.require_resolved(value)
    assert value.capture == capture
    assert len(transactions) == 1 and not active
    assert {row.field: row.value for row in value.capture.observed.cash}[
        "trade_date_cash"
    ] == Decimal("799.50")
    assert value.capture.observed.positions[0].quantity == 2
    assert value.capture.source_order == capture.source_order
    # All requested reads share the same detached head row instead of retaining
    # one extra copy of its payload for every page.
    assert all(
        read.snapshot.head_anchor is value.reads[0].snapshot.head_anchor for read in value.reads
    )


def test_restart_and_later_append_preserve_original_receipts_and_staleness(case):
    captures, _, capture, sources = case
    value = sources.resolve(capture)
    original = value.reads[0].head
    page = value.pages[0]
    key = capture.manifest.sources[0].key
    raw = personal_codec.encode_record(page)
    later = sources.journal.append(
        key,
        JournalAppend(
            "later-retained-page",
            page.semantic_sha256,
            original,
            (JournalRecord("later-retained-page", VENUE_CAPTURE_SCHEMA, raw),),
        ),
    )
    assert later.committed_head.sequence > original.sequence
    sources.require_resolved(value)
    with _repeatable_read_transaction(captures.engine) as connection:
        sources.recheck_in_transaction(connection, value)
    restart = SqlContinuousVenueSources(
        captures.engine,
        artifacts=captures.artifacts,
        codec=personal_codec,
        resolver=sources.resolver,
        scope=sources.scope,
        model=sources.model,
    )
    replay = restart.resolve(capture)
    assert replay.capture == capture
    assert tuple(read.receipt for read in replay.reads) == tuple(
        read.receipt for read in value.reads
    )
    assert (
        "STALE_PAGE_RECEIPT"
        in assess_reconciliation_coverage(
            replay.capture.observed,
            required_from=capture.observed.requested_from,
            required_through=capture.observed.requested_through,
            now=capture.observed.completed_at + timedelta(seconds=60),
        ).reasons
    )


def test_omitted_financial_page_cannot_be_published_as_a_complete_capture(case):
    _, _, capture, sources = case
    omitted = next(
        page.receipt_id for page in capture.observed.pages if page.operation == "balances"
    )
    partial = replace(
        capture,
        manifest=replace(
            capture.manifest,
            sources=tuple(
                source for source in capture.manifest.sources if source.page_receipt_id != omitted
            ),
        ),
        observed=replace(
            capture.observed,
            pages=tuple(page for page in capture.observed.pages if page.receipt_id != omitted),
            cash=(),
        ),
    )
    with pytest.raises(ContinuousVenueSourceError):
        sources.resolve(partial)


def test_page_from_another_actual_capture_cannot_replace_original_receipt(case):
    captures, venue, capture, sources = case
    original = sources.resolve(capture)
    later = captures.capture(
        replace(original.pages[0].request, capture_id="other-capture"), venue=venue
    )
    prior_page = next(page for page in capture.observed.pages if page.operation == "balances")
    new_page = next(page for page in later.observed.pages if page.operation == "balances")
    new_source = next(
        source for source in later.manifest.sources if source.page_receipt_id == new_page.receipt_id
    )
    mixed = replace(
        capture,
        manifest=replace(
            capture.manifest,
            sources=tuple(
                sorted(
                    (
                        new_source,
                        *(
                            source
                            for source in capture.manifest.sources
                            if source.page_receipt_id != prior_page.receipt_id
                        ),
                    ),
                    key=lambda source: source.page_receipt_id,
                )
            ),
        ),
        observed=replace(
            capture.observed,
            pages=tuple(
                new_page if page == prior_page else page for page in capture.observed.pages
            ),
        ),
    )
    with pytest.raises(ContinuousVenueSourceError, match="APPEND_BINDING"):
        sources.resolve(mixed)


@pytest.mark.parametrize("change", ["cash", "facts", "order"])
def test_reconstructed_financial_fact_and_source_order_inventory_must_be_exact(case, change):
    _, _, capture, sources = case
    if change == "cash":
        rows = capture.observed.cash
        capture = replace(
            capture,
            observed=replace(
                capture.observed, cash=(replace(rows[0], value=rows[0].value + 1), *rows[1:])
            ),
        )
    elif change == "facts":
        capture = replace(
            capture, facts=(replace(capture.facts[0], source_sha256="f" * 64), *capture.facts[1:])
        )
    else:
        capture = replace(capture, source_order=tuple(reversed(capture.source_order)))
    with pytest.raises(ContinuousVenueSourceError, match="RECONSTRUCTED_CAPTURE"):
        sources.resolve(capture)


@pytest.mark.parametrize("change", ["account", "model"])
def test_constructor_pins_reject_cross_account_or_changed_original_model(case, change):
    captures, _, capture, sources = case
    other = SqlContinuousVenueSources(
        captures.engine,
        artifacts=captures.artifacts,
        codec=personal_codec,
        resolver=sources.resolver,
        scope=replace(sources.scope, account_id="another-account")
        if change == "account"
        else sources.scope,
        model=replace(sources.model, producer=replace(sources.model.producer, sha256="f" * 64))
        if change == "model"
        else sources.model,
    )
    with pytest.raises(ContinuousVenueSourceError, match=r"SCOPE|PAGE_BINDING"):
        other.resolve(capture)


@pytest.mark.parametrize("change", ["delete", "payload", "metadata"])
def test_changed_original_sql_records_block_resolution_and_final_publication(case, change):
    captures, _, capture, sources = case
    value = sources.resolve(capture)
    target = capture.manifest.sources[0]
    with captures.engine.begin() as connection:
        condition = (journal_entries.c.key_sha256 == target.key.semantic_sha256) & (
            journal_entries.c.record_id == target.record_id
        )
        statement = (
            journal_entries.delete().where(condition)
            if change == "delete"
            else journal_entries.update()
            .where(condition)
            .values(
                **({"payload": b"{}"} if change == "payload" else {"schema_id": "changed-schema"})
            )
        )
        connection.execute(statement)
    with (
        _repeatable_read_transaction(captures.engine) as connection,
        pytest.raises(ContinuousVenueSourceError),
    ):
        sources.recheck_in_transaction(connection, value)
    with pytest.raises(ContinuousVenueSourceError):
        sources.resolve(capture)


def test_private_object_mismatch_is_static_and_never_requeries_venue(case, monkeypatch):
    captures, venue, capture, sources = case

    def fail(*args, **kwargs):
        raise RuntimeError("private-path-or-token-sentinel")

    monkeypatch.setattr(captures.artifacts, "read", fail)
    monkeypatch.setattr(venue, "read", lambda: pytest.fail("queried venue"))
    with pytest.raises(ContinuousVenueSourceError) as error:
        sources.resolve(capture)
    assert str(error.value) == "VENUE_SOURCE_RESOLUTION_FAILED"


def test_detached_decoder_can_stall_while_actual_writer_commits_then_recheck_rejects(case):
    captures, _, capture, sources = case
    entered, release = Event(), Event()

    class BlockingCodec:
        def encode_record(self, value):
            return personal_codec.encode_record(value)

        def decode_record(self, payload, expected_type):
            entered.set()
            assert release.wait(10), "decoder release timed out"
            return personal_codec.decode_record(payload, expected_type)

    sources.codec = BlockingCodec()
    sources.journal._codec = sources.codec
    target = capture.manifest.sources[0]

    def corrupt():
        with captures.engine.begin() as connection:
            connection.execute(
                journal_entries.update()
                .where(journal_entries.c.record_id == target.record_id)
                .values(payload=b"{}")
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(sources.resolve, capture)
        try:
            assert entered.wait(5)
            pool.submit(corrupt).result(timeout=3)
        finally:
            release.set()
        value = future.result(timeout=10)
    assert value.capture == capture
    with (
        _repeatable_read_transaction(captures.engine) as connection,
        pytest.raises(ContinuousVenueSourceError),
    ):
        sources.recheck_in_transaction(connection, value)


def test_final_recheck_has_no_codec_object_or_fingerprint_work(case, monkeypatch):
    captures, _, capture, sources = case
    value = sources.resolve(capture)
    sources.require_resolved(value)

    def forbidden(*args, **kwargs):
        pytest.fail("heavy operation under final SQL transaction")

    monkeypatch.setattr(personal_codec, "encode_record", forbidden)
    monkeypatch.setattr(personal_codec, "decode_record", forbidden)
    monkeypatch.setattr(captures.artifacts, "read", forbidden)
    monkeypatch.setattr(source_module, "_fingerprint", forbidden)
    monkeypatch.setattr(sources.resolver, "resolve_observation", forbidden)
    with _repeatable_read_transaction(captures.engine) as connection:
        sources.recheck_in_transaction(connection, value)


def test_resolution_copy_foreign_owner_and_changed_original_fingerprint_reject(case):
    captures, _, capture, sources = case
    value = sources.resolve(capture)
    other = SqlContinuousVenueSources(
        captures.engine,
        artifacts=captures.artifacts,
        codec=personal_codec,
        resolver=sources.resolver,
        scope=sources.scope,
        model=sources.model,
    )
    for owner, supplied in ((sources, replace(value)), (other, value)):
        with pytest.raises(ContinuousVenueSourceError, match="OWNED"):
            owner.require_resolved(supplied)
        with (
            _repeatable_read_transaction(captures.engine) as connection,
            pytest.raises(ContinuousVenueSourceError, match="OWNED"),
        ):
            owner.recheck_in_transaction(connection, supplied)
    object.__setattr__(capture, "source_order", tuple(reversed(capture.source_order)))
    with pytest.raises(ContinuousVenueSourceError, match="FINGERPRINT"):
        sources.require_resolved(value)


def test_final_recheck_requires_same_engine_and_physical_snapshot(case, tmp_path):
    captures, _, capture, sources = case
    value = sources.resolve(capture)
    with (
        captures.engine.connect() as connection,
        connection.begin(),
        pytest.raises(ContinuousVenueSourceError),
    ):
        sources.recheck_in_transaction(connection, value)
    other = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/other.sqlite")
    try:
        with (
            _repeatable_read_transaction(other) as connection,
            pytest.raises(ContinuousVenueSourceError),
        ):
            sources.recheck_in_transaction(connection, value)
    finally:
        other.dispose()


@pytest.mark.parametrize("kind", ["objects", "raw_snapshot", "metadata"])
def test_whole_capture_bounds_fail_before_decode_or_object_io(case, monkeypatch, kind):
    captures, _, capture, sources = case
    name = {
        "objects": "MAX_EVIDENCE_BYTES",
        "raw_snapshot": "MAX_VENUE_SNAPSHOT_BYTES",
        "metadata": "MAX_VENUE_SNAPSHOT_METADATA_BYTES",
    }[kind]
    monkeypatch.setattr(source_module, name, 1)

    def forbidden(*args, **kwargs):
        pytest.fail("bounds must precede source decoding/object IO")

    monkeypatch.setattr(personal_codec, "decode_record", forbidden)
    monkeypatch.setattr(captures.artifacts, "read", forbidden)
    with pytest.raises(ContinuousVenueSourceError, match="LIMIT"):
        sources.resolve(capture)
