"""Disposable independent venue databases and synthetic immutable objects only."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from threading import Barrier, Event

import pytest
import sqlalchemy as sa

from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.application.stateful_venue import project_stateful_venue
from packages.domain.stateful_venue_contracts import (
    VenueAccept,
    VenueCancel,
    VenueCommand,
    VenueRunDue,
)
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal import JournalConflict
from packages.persistence.durable_journal_schema import JOURNAL_TABLES, journal_entries
from packages.persistence.schema import metadata
from packages.persistence.stateful_venue import SqlStatefulVenue, VenueStorageError
from tests.unit.test_stateful_venue import SOURCE_BYTES, FixtureVerifier, model, packet, quote


@pytest.fixture
def retained(tmp_path):
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/separate-venue.sqlite")
    metadata.create_all(engine, tables=JOURNAL_TABLES)
    artifacts = LocalResearchArtifactStore(tmp_path / "private-venue-objects")
    for raw in SOURCE_BYTES.values():
        artifacts.put(raw)
    yield engine, artifacts, model()
    engine.dispose()


def store(retained, **kwargs):
    engine, artifacts, m = retained
    return SqlStatefulVenue(
        engine,
        model=m,
        artifacts=artifacts,
        codec=personal_codec,
        verified_sources=FixtureVerifier(),
        **kwargs,
    )


def table_counts(engine):
    with engine.connect() as connection:
        return tuple(
            connection.scalar(sa.select(sa.func.count()).select_from(table))
            for table in JOURNAL_TABLES
        )


def fill(store):
    current = store.initialize()
    outgoing = packet(store.model)
    submit = VenueCommand("submit", outgoing.registration.submission.submitted_at, outgoing)
    first = store.execute(submit)
    order_id = outgoing.registration.submission.order_id
    accepted = VenueCommand(
        "accept", submit.received_at + timedelta(seconds=1), VenueAccept(order_id)
    )
    assert store.execute(accepted).acknowledgment.disposition == "applied"
    at = accepted.received_at + timedelta(seconds=1)
    filled = store.execute(VenueCommand("fill", at, quote(at, budget="2")))
    assert filled.acknowledgment.disposition == "applied"
    return current, submit, first, filled


def test_durable_restart_original_retry_after_fill_cancel_and_fixed_pages(retained):
    venue = store(retained)
    _, submit, original, filled = fill(venue)
    prefix = venue.read()
    first_page = venue.facts(through_head=prefix.head, offset=0, limit=2)
    order = submit.payload.registration.submission.order_id
    cancel = venue.execute(
        VenueCommand(
            "cancel", prefix.state.as_of + timedelta(seconds=1), VenueCancel(order, "owner-cancel")
        )
    )
    assert cancel.acknowledgment.disposition == "applied"
    restarted = store(retained)
    after = restarted.read()
    assert restarted.read_command_receipt(submit) == original
    assert restarted.read_command_receipt(replace(submit, command_id="never-sent")) is None
    with pytest.raises(JournalConflict, match="COMMAND_ID_CONFLICT"):
        restarted.read_command_receipt(
            replace(submit, received_at=submit.received_at + timedelta(microseconds=1))
        )
    assert restarted.read() == after
    assert restarted.execute(submit) == original
    assert restarted.read() == after
    assert restarted.facts(through_head=prefix.head, offset=0, limit=2) == first_page
    next_page = restarted.facts(through_head=prefix.head, offset=first_page.next_offset, limit=2)
    assert next_page.complete
    facts = first_page.facts + next_page.facts
    assert tuple(f.fact_id for f in facts) == tuple(f.fact_id for f in prefix.state.facts)
    snapshot = project_stateful_venue(restarted.model, after.state).snapshot
    assert snapshot.positions[0].quantity == 2 and snapshot.trade_date_cash == 799.5
    assert snapshot.buy_reserve == 0
    assert filled.journal_receipt.committed_head == prefix.head


def test_due_settlement_survives_restart_without_early_cash_effect(retained):
    venue = store(retained)
    fill(venue)
    before = venue.read()
    assert project_stateful_venue(venue.model, before.state).snapshot.settled_cash == 1000
    due_at = before.state.due_settlements[0].due_at
    early = venue.execute(
        VenueCommand("early-due", before.state.as_of + timedelta(seconds=1), VenueRunDue())
    )
    assert early.acknowledgment.disposition == "no_effect"
    restarted = store(retained)
    receipt = restarted.execute(VenueCommand("due", due_at + timedelta(hours=1), VenueRunDue()))
    assert receipt.acknowledgment.disposition == "applied"
    after = restarted.read()
    assert not after.state.due_settlements
    assert project_stateful_venue(venue.model, after.state).snapshot.settled_cash == 799.5
    assert all(
        c.settled_at == due_at + timedelta(hours=1)
        for c in after.state.accounting.settlement_confirmations
    )


def test_same_account_model_change_cannot_silently_start_fresh_funding(retained):
    venue = store(retained)
    first = venue.initialize()
    engine, artifacts, original = retained
    changed = replace(
        original,
        initial_cash_flow=replace(
            original.initial_cash_flow, amount=original.initial_cash_flow.amount * 2
        ),
    )
    other = SqlStatefulVenue(engine, model=changed, artifacts=artifacts, codec=personal_codec)
    assert other.key == venue.key
    with pytest.raises(VenueStorageError, match="MODEL_DIFFERS"):
        other.initialize()
    assert venue.read() == first


def test_conflicting_command_body_and_stale_head_leave_journal_unchanged(retained):
    venue = store(retained)
    initial, submit, _, _ = fill(venue)
    before = table_counts(retained[0])
    with pytest.raises(JournalConflict, match="COMMAND_ID_CONFLICT"):
        venue.execute(replace(submit, received_at=submit.received_at + timedelta(microseconds=1)))
    current = venue.read()
    with pytest.raises(JournalConflict, match="EXPECTED_HEAD_DIFFERS"):
        venue.execute(
            VenueCommand("stale", current.state.as_of, VenueRunDue()), expected_head=initial.head
        )
    assert table_counts(retained[0]) == before


def test_two_concurrent_stale_writers_have_one_account_capacity_winner(retained):
    venue = store(retained)
    initial = venue.initialize()
    barrier = Barrier(2)

    class BlockingVerifier(FixtureVerifier):
        def verify_submission(self, model, submit, *, received_at):
            super().verify_submission(model, submit, received_at=received_at)
            barrier.wait(timeout=10)

    def execute(name):
        concurrent = store(retained)
        concurrent.verified_sources = BlockingVerifier()
        outgoing = packet(concurrent.model, name=name, quantity="6")
        command = VenueCommand(name, outgoing.registration.submission.submitted_at, outgoing)
        try:
            return concurrent.execute(command, expected_head=initial.head)
        except JournalConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(execute, ("one", "two")))
    assert sum(result is not None for result in results) == 1
    state = venue.read().state
    assert len(state.accounting.submissions) == 1
    assert state.accounting.commitments[0].reserved_cash == 661.5
    assert table_counts(retained[0]) == (1, 2, 2)


def test_identical_concurrent_commands_return_one_original_receipt(retained):
    venue = store(retained)
    venue.initialize()
    barrier = Barrier(2)
    outgoing = packet(venue.model)
    command = VenueCommand("submit", outgoing.registration.submission.submitted_at, outgoing)

    class BlockingVerifier(FixtureVerifier):
        def verify_submission(self, model, submit, *, received_at):
            super().verify_submission(model, submit, received_at=received_at)
            barrier.wait(timeout=10)

    def execute(_):
        concurrent = store(retained)
        concurrent.verified_sources = BlockingVerifier()
        return concurrent.execute(command)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(execute, (1, 2)))
    assert results[0] == results[1]
    assert len(venue.read().state.accounting.submissions) == 1
    assert table_counts(retained[0]) == (1, 2, 2)


def test_failure_after_entry_insert_rolls_back_ack_and_financial_state(retained):
    venue = store(retained)
    before = venue.initialize()
    outgoing = packet(venue.model)
    command = VenueCommand("submit", outgoing.registration.submission.submitted_at, outgoing)

    def fail(_connection, statement, _multiparams, _params, _options, _result):
        if statement.is_insert and statement.table.name == journal_entries.name:
            raise RuntimeError("fixture interrupted entry insertion")

    sa.event.listen(retained[0], "after_execute", fail)
    try:
        with pytest.raises(RuntimeError, match="fixture interrupted"):
            venue.execute(command)
    finally:
        sa.event.remove(retained[0], "after_execute", fail)
    assert venue.read() == before and table_counts(retained[0]) == (1, 1, 1)
    assert venue.execute(command).acknowledgment.disposition == "registered"


def test_corrupt_checkpoint_and_missing_outbound_source_fail_without_publication(retained):
    venue = store(retained)
    venue.initialize()
    outgoing = packet(venue.model)
    command = VenueCommand("submit", outgoing.registration.submission.submitted_at, outgoing)
    actual = venue.artifacts

    class BrokenStore:
        def read(self, reference, *, max_bytes):
            if reference == outgoing.risk_source.object_ref:
                return b"wrong source bytes"
            return actual.read(reference, max_bytes=max_bytes)

        def put(self, payload, *, max_bytes):
            return actual.put(payload, max_bytes=max_bytes)

    venue.artifacts = BrokenStore()
    with pytest.raises(VenueStorageError, match="OBJECT_BINDING_DIFFERS"):
        venue.execute(command)
    assert table_counts(retained[0]) == (1, 1, 1)
    venue.artifacts = actual
    venue.execute(command)
    current = venue.read()
    original_read = actual.read

    class CorruptStore:
        def read(self, reference, *, max_bytes):
            return original_read(reference, max_bytes=max_bytes) + b" "

        def put(self, payload, *, max_bytes):
            return actual.put(payload, max_bytes=max_bytes)

    venue.artifacts = CorruptStore()
    with pytest.raises(VenueStorageError, match="OBJECT_BINDING_DIFFERS"):
        venue.read()
    venue.artifacts = actual
    assert venue.read() == current


def test_stalled_checkpoint_decode_does_not_hold_sql_read_transaction(retained):
    venue = store(retained)
    venue.initialize()
    entered, release = Event(), Event()
    base = personal_codec

    class SlowCodec:
        @staticmethod
        def encode_record(value):
            return base.encode_record(value)

        @staticmethod
        def decode_record(payload, expected_type):
            from packages.domain.stateful_venue_contracts import VenueState

            if expected_type is VenueState:
                entered.set()
                assert release.wait(timeout=10)
            return base.decode_record(payload, expected_type)

    slow = SqlStatefulVenue(
        retained[0], model=venue.model, artifacts=retained[1], codec=SlowCodec()
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        reader = pool.submit(slow.read)
        assert entered.wait(timeout=10)
        try:
            outgoing = packet(venue.model)
            receipt = venue.execute(
                VenueCommand("submit", outgoing.registration.submission.submitted_at, outgoing)
            )
            assert receipt.acknowledgment.disposition == "registered"
        finally:
            release.set()
        earlier = reader.result(timeout=10)
    assert earlier.state.sequence == 0 and venue.read().state.sequence == 1


def test_checkpoint_budget_rejects_before_whole_history_encoding_or_publication(
    retained, monkeypatch
):
    from packages.domain.stateful_venue_contracts import VenueState
    from packages.persistence import stateful_venue as module

    calls = []

    class BudgetCodec:
        @staticmethod
        def encode_record(value):
            calls.append(type(value))
            return personal_codec.encode_record(value)

        @staticmethod
        def decode_record(payload, expected_type):
            return personal_codec.decode_record(payload, expected_type)

    monkeypatch.setattr(module, "MAX_VENUE_OBJECT_BYTES", 1024)
    venue = SqlStatefulVenue(
        retained[0], model=retained[2], artifacts=retained[1], codec=BudgetCodec()
    )
    with pytest.raises(VenueStorageError, match="STATE_BUDGET_EXCEEDED"):
        venue.initialize()
    assert VenueState not in calls
    assert table_counts(retained[0]) == (0, 0, 0)


def test_original_retry_does_not_recheck_now_revoked_dispatch_permission(retained):
    venue = store(retained)
    _, original, receipt, _ = fill(venue)

    class RevokedVerifier:
        def verify_submission(self, model, submit, *, received_at):
            raise AssertionError("a historical acknowledgment must not dispatch again")

        def verify_quote(self, model, source, observation):
            raise AssertionError("unused")

    venue.verified_sources = RevokedVerifier()
    before = venue.read()
    assert venue.execute(original) == receipt
    assert venue.read() == before
