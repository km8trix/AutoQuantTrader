"""Independent disposable venue/coordinator SQLite capture; no provider access."""

from dataclasses import replace
from datetime import timedelta

import pytest
import sqlalchemy as sa

from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.application.venue_reconciliation import VenueCaptureError, VenueReconciliationResolver
from packages.domain.applied_reconciliation import assess_reconciliation_coverage
from packages.domain.venue_reconciliation_contracts import VenueCapturePage
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal_schema import JOURNAL_TABLES, journal_entries
from packages.persistence.schema import metadata
from packages.persistence.venue_reconciliation_capture import (
    SqlVenueReconciliationCapture,
)
from tests.integration.test_stateful_venue_journal import fill, retained, store  # noqa: F401
from tests.unit.test_venue_reconciliation import request_for


class Clock:
    def __init__(self, at):
        self.at = at
        self.calls = 0

    def __call__(self):
        self.calls += 1
        self.at += timedelta(microseconds=1)
        return self.at


@pytest.fixture
def capture_store(tmp_path, retained):  # noqa: F811 - shared disposable pytest fixture
    venue = store(retained)
    fill(venue)
    state = venue.read().state
    request = request_for(venue.model, state)
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/coordinator.sqlite")
    metadata.create_all(engine, tables=JOURNAL_TABLES)
    artifacts = LocalResearchArtifactStore(tmp_path / "coordinator-objects")
    clock = Clock(state.as_of + timedelta(seconds=1))
    capture = SqlVenueReconciliationCapture(
        engine, artifacts=artifacts, codec=personal_codec, clock=clock
    )
    yield capture, venue, request, clock
    engine.dispose()


def test_actual_independent_capture_restart_and_duplicate_do_not_refresh(
    capture_store, monkeypatch
):
    capture, venue, request, clock = capture_store
    original_venue = venue.read()
    result = capture.capture(request, venue=venue)
    assert venue.read() == original_venue
    assert result.source_order == tuple(f.fact_id for f in original_venue.state.facts)
    assert {v.field: v.value for v in result.observed.cash}["trade_date_cash"] == 799.5
    assert result.observed.positions[0].quantity == 2
    assert result.manifest.scope.account_id != original_venue.state.accounting.account_id
    calls = clock.calls
    monkeypatch.setattr(venue, "read", lambda **_: pytest.fail("retry queried venue"))
    assert capture.capture(request, venue=venue) == result
    assert clock.calls == calls
    restarted = SqlVenueReconciliationCapture(
        capture.engine,
        artifacts=capture.artifacts,
        codec=personal_codec,
        clock=lambda: pytest.fail("restart refreshed capture"),
    )
    assert restarted.read(request) == result
    assert (
        "STALE_PAGE_RECEIPT"
        in assess_reconciliation_coverage(
            result.observed,
            required_from=request.requested_from,
            required_through=request.requested_through,
            now=result.observed.completed_at + timedelta(seconds=60),
        ).reasons
    )
    with pytest.raises(VenueCaptureError, match="REQUEST_OR_ENCODING"):
        restarted.read(replace(request, requested_from=request.requested_from - timedelta(days=1)))


class TransitionDelegate:
    def resolve_transition(self, reference, value):
        raise AssertionError("source resolution must not inspect coordinator transitions")


def test_concrete_source_resolver_rebuilds_only_retained_bytes(capture_store):
    capture, venue, request, _ = capture_store
    result = capture.capture(request, venue=venue)
    resolver = VenueReconciliationResolver(transition_resolver=TransitionDelegate())
    values = tuple(
        personal_codec.decode_record(
            capture.artifacts.read(source.evidence.object_ref), VenueCapturePage
        )
        for source in result.manifest.sources
    )
    assert resolver.resolve_observation(result.manifest, values) == result.observed
    assert resolver.resolve_source_order(result.manifest, values) == result.source_order
    assert resolver.resolve_source_order(result.manifest, values) != tuple(
        reversed(result.source_order)
    )
    sources = tuple(
        resolver.resolve_source(source, value)
        for source, value in zip(result.manifest.sources, values, strict=True)
    )
    assert sorted(f.observation.fact_id for s in sources for f in s.facts) == sorted(
        f.observation.fact_id for f in result.facts
    )
    with pytest.raises(VenueCaptureError, match="TYPE_OR_HASH"):
        resolver.resolve_source(
            result.manifest.sources[0],
            replace(values[0], received_at=values[0].received_at + timedelta(microseconds=1)),
        )


def test_all_capture_sql_is_preencoded_and_venue_calls_are_detached(capture_store, monkeypatch):
    capture, venue, request, _ = capture_store
    active = set()
    sa.event.listen(capture.engine, "begin", lambda conn: active.add(id(conn)))
    sa.event.listen(capture.engine, "commit", lambda conn: active.discard(id(conn)))
    sa.event.listen(capture.engine, "rollback", lambda conn: active.discard(id(conn)))
    original_read, original_facts = venue.read, venue.facts
    original_encode, original_decode = capture.codec.encode_record, capture.codec.decode_record

    class CheckedCodec:
        def encode_record(self, value):
            assert not active, "codec under coordinator transaction"
            return original_encode(value)

        def decode_record(self, payload, expected_type):
            assert not active, "codec under coordinator transaction"
            return original_decode(payload, expected_type)

    capture.codec = CheckedCodec()
    capture.journal._codec = capture.codec

    def read(**kwargs):
        assert not active, "venue query under coordinator transaction"
        return original_read(**kwargs)

    def facts(**kwargs):
        assert not active, "venue pages under coordinator transaction"
        return original_facts(**kwargs)

    monkeypatch.setattr(venue, "read", read)
    monkeypatch.setattr(venue, "facts", facts)
    assert capture.capture(request, venue=venue).facts
    assert not active


def test_late_append_failure_rolls_back_entire_capture(capture_store, monkeypatch):
    capture, venue, request, _ = capture_store
    append = capture.journal.append_in_transaction
    calls = 0

    def reject(connection, prepared):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise ValueError("fixture rollback")
        return append(connection, prepared)

    monkeypatch.setattr(capture.journal, "append_in_transaction", reject)
    with pytest.raises(VenueCaptureError, match="VENUE_CAPTURE_FAILED"):
        capture.capture(request, venue=venue)
    assert capture.read(request) is None
    with capture.engine.connect() as connection:
        assert all(
            connection.scalar(sa.select(sa.func.count()).select_from(table)) == 0
            for table in JOURNAL_TABLES
        )
    monkeypatch.setattr(capture.journal, "append_in_transaction", append)
    assert capture.capture(request, venue=venue).facts


def test_corrupt_capture_page_rejects_without_requery(capture_store):
    capture, venue, request, _ = capture_store
    capture.capture(request, venue=venue)
    with capture.engine.begin() as connection:
        connection.execute(journal_entries.delete().where(journal_entries.c.sequence == 2))
    with pytest.raises(ValueError):
        capture.read(request)


def test_explicit_old_venue_head_cannot_gain_fresh_coverage(capture_store):
    capture, venue, request, _ = capture_store
    original = venue.read()
    from packages.domain.stateful_venue_contracts import VenueCancel, VenueCommand

    order_id = original.state.accounting.submissions[0].order_id
    venue.execute(
        VenueCommand(
            "later-cancel",
            original.state.as_of + timedelta(microseconds=1),
            VenueCancel(order_id, "owner-cancel"),
        )
    )
    with pytest.raises(VenueCaptureError, match="HISTORICAL_HEAD"):
        capture.capture(replace(request, through_head=original.head), venue=venue)
    assert capture.read(request) is None


def test_source_exception_is_static_and_publishes_nothing(capture_store, monkeypatch):
    capture, venue, request, _ = capture_store

    def fail():
        raise RuntimeError("fixture-private-path-and-token-sentinel")

    monkeypatch.setattr(venue, "read", fail)
    with pytest.raises(VenueCaptureError) as error:
        capture.capture(request, venue=venue)
    assert str(error.value) == "VENUE_CAPTURE_FAILED"
    assert capture.read(request) is None


def test_private_page_size_admission_happens_before_any_sql_publication(capture_store):
    capture, venue, request, _ = capture_store

    class OversizedCodec:
        def encode_record(self, value):
            return b"x" * (256 * 1024 + 1)

        def decode_record(self, payload, expected_type):
            pytest.fail("oversize must be rejected before decode")

    capture.codec = OversizedCodec()
    with pytest.raises(VenueCaptureError, match="ENCODED_BYTE_LIMIT"):
        capture.capture(request, venue=venue)
    with capture.engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(journal_entries)) == 0


def test_halted_venue_is_retained_as_blocked_truth(capture_store):
    from decimal import Decimal

    from packages.domain.stateful_venue_contracts import VenueCommand, VenueCorrect

    capture, venue, request, clock = capture_store
    state = venue.read().state
    execution = next(e for e in state.accounting.broker_events if e.execution_id is not None)
    at = state.as_of + timedelta(seconds=1)
    venue.execute(
        VenueCommand(
            "oversized-truth",
            at,
            VenueCorrect(
                execution.execution_id, Decimal(4), Decimal(400), Decimal(9), "venue-correction"
            ),
        )
    )
    clock.at = at + timedelta(seconds=1)
    result = capture.capture(replace(request, requested_through=at), venue=venue)
    assert "VENUE_ACCOUNT_HALTED" in result.observed.source_blockers
    assert {v.field: v.value for v in result.observed.cash}["trade_date_cash"] == -609


def test_capture_clock_regression_is_not_a_fresh_receipt(capture_store):
    capture, venue, request, clock = capture_store
    values = iter((clock.at, clock.at - timedelta(microseconds=1)))
    capture.clock = lambda: next(values)
    with pytest.raises(VenueCaptureError, match="CLOCK_REGRESSED"):
        capture.capture(request, venue=venue)
    assert capture.read(request) is None
