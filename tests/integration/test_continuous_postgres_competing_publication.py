"""Competing actual C/B dispatch writes with retained A provenance.

The PostgreSQL gate uses separate RR connections and independent publication
registries over one current fixture lease. It proves SQL exclusivity, not two
simultaneous valid lease owners or process ownership. The independent venue is
temporary SQLite. Delivery preserves the actual account's scoped thread denial.
"""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import copy
from threading import Barrier, Event
from uuid import uuid4

import pytest
import sqlalchemy as sa

from packages.persistence.applied_reconciliation_schema import applied_reconciliation_commits
from packages.persistence.continuous_account import ContinuousAccountConflict
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.continuous_attempt_publication import (
    CommittedSimulationAttemptBatch,
    SqlContinuousAttemptPublication,
)
from packages.persistence.continuous_simulation_delivery import SqlContinuousSimulationDelivery
from packages.persistence.daily_runtime_risk import DailyRuntimeRiskConflict
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_admissions,
    daily_runtime_attempt_events,
    daily_runtime_consumptions,
    daily_runtime_hold_events,
    daily_runtime_hold_heads,
)
from packages.persistence.durable_journal import JournalConflict
from packages.persistence.stateful_venue import SqlStatefulVenue
from tests.integration import test_continuous_composition as composition_fixture
from tests.integration import test_continuous_runtime_attempt_sources as source_fixture
from tests.integration.test_phase2_postgres_exit import postgres_engine as postgres_engine

attempt_case = source_fixture.attempt_case


@pytest.fixture
def pg_attempt_case(postgres_engine, tmp_path, monkeypatch):
    schema = "continuous_dispatch_" + uuid4().hex
    with postgres_engine.begin() as connection:
        connection.execute(sa.schema.CreateSchema(schema))
    engine = postgres_engine.execution_options(schema_translate_map={None: schema})
    try:
        # Only the existing account fixture's engine changes. The separate
        # PublicationCase venue factory still creates its actual SQLite file.
        def account_engine(url):
            assert url == f"sqlite+pysqlite:///{tmp_path}/account.sqlite"
            return engine

        monkeypatch.setattr(composition_fixture, "create_database_engine", account_engine)
        fixture = source_fixture.attempt_case.__wrapped__(tmp_path, monkeypatch)
        try:
            yield next(fixture)
        finally:
            fixture.close()
    finally:
        with postgres_engine.begin() as connection:
            connection.execute(sa.schema.DropSchema(schema, cascade=True))


def _rows(engine, table):
    with engine.connect() as connection:
        return tuple(
            dict(row)
            for row in connection.execute(
                sa.select(table).order_by(*table.primary_key.columns)
            ).mappings()
        )


def _competing_publication(attempt_case, monkeypatch):
    case, service, reader, previous, current, admission, first, descriptor = (
        source_fixture.activation_preparation(attempt_case)
    )
    second = reader.retain_activation(
        coordinator_command_id="activation-competing-parent",
        previous=previous,
        current=current,
        admissions=(admission,),
        descriptor=descriptor,
        attempt_ids=tuple(item.attempt_id for item in current.attempts),
    )
    sources = (first, second)
    publishers = tuple(SqlContinuousAttemptPublication(account=case.store) for _ in sources)
    prepared = tuple(
        publisher.prepare_source(source, sources=reader)
        for publisher, source in zip(publishers, sources, strict=True)
    )
    assert prepared[0].commit.sequence == prepared[1].commit.sequence
    assert prepared[0].commit.transition.command_id != prepared[1].commit.transition.command_id
    assert first.source.heads == second.source.heads
    assert first.previous is second.previous is previous
    assert publishers[0]._dispatch_lock is not publishers[1]._dispatch_lock
    before_a = _rows(case.engine, applied_reconciliation_commits)
    before_admissions = _rows(case.engine, daily_runtime_admissions)
    before_consumptions = _rows(case.engine, daily_runtime_consumptions)
    before_holds = _rows(case.engine, daily_runtime_hold_events)
    before_venue = case.paired_fixture.venue.read()
    barrier = Barrier(2)
    connections = []
    backend_pids = []
    original_write = case.store.write_transaction

    @contextmanager
    def concurrent_write():
        # SQLite serializes at BEGIN IMMEDIATE, so it must rendezvous before
        # entry. PG establishes both original RR snapshots before C takes its
        # real account-row serialization lock. No validation is replaced.
        if case.engine.dialect.name == "sqlite":
            barrier.wait(timeout=15)
        with original_write() as connection:
            connections.append(connection)
            if case.engine.dialect.name == "postgresql":
                assert connection.get_isolation_level() == "REPEATABLE READ"
                connection.exec_driver_sql("SET LOCAL lock_timeout = '15s'")
                connection.exec_driver_sql("SET LOCAL statement_timeout = '30s'")
                backend_pids.append(connection.scalar(sa.text("SELECT pg_backend_pid()")))
                captured = case.store.capture_current_in_transaction(connection, scope=case.scope)
                assert captured.row == previous.snapshot.row
                barrier.wait(timeout=15)
            yield connection

    def publish(index):
        try:
            result = publishers[index].publish_dispatch(prepared[index], fence=case.h.lease.fence)
            return index, result
        except (ContinuousAccountConflict, DailyRuntimeRiskConflict, JournalConflict) as error:
            return index, error
        except sa.exc.OperationalError as error:
            # Never count unrelated connectivity, SQL syntax or timeout errors
            # as a successful concurrency denial.
            assert getattr(error.orig, "sqlstate", None) == "40001"
            return index, error

    with monkeypatch.context() as patch:
        patch.setattr(case.store, "write_transaction", concurrent_write)
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(publish, (0, 1)))
    assert len(connections) == 2 and connections[0] is not connections[1]
    if case.engine.dialect.name == "postgresql":
        assert len(set(backend_pids)) == 2
    winners = tuple(item for item in results if type(item[1]) is CommittedSimulationAttemptBatch)
    assert len(winners) == 1, results
    index, batch = winners[0]
    source, publisher = sources[index], publishers[index]
    loser = 1 - index
    publisher.require_completed(batch)
    for foreign in (publishers[loser], SqlContinuousAttemptPublication(account=case.store)):
        with pytest.raises(ValueError, match="ORIGINAL_SUCCESSFUL_DISPATCH_COMMIT"):
            foreign.require_completed(batch)
    with pytest.raises(ValueError, match="ORIGINAL_SUCCESSFUL_DISPATCH_COMMIT"):
        publisher.require_completed(copy(batch))
    assert not publishers[loser]._completed

    restored = case.store.restore(case.scope)
    after = case.h.resolved()
    assert restored.receipt == batch.receipt
    assert restored.checkpoint.state == batch.attempts.result.accounting_state
    assert after.attempts == batch.attempts.result.attempts
    assert after.obligations == batch.attempts.result.obligations
    assert all(item.state.value == "in_flight" for item in after.attempts)
    assert all(binding.commitment.state == "active" for binding in after.obligations.bindings)
    assert restored.checkpoint.state.submissions == previous.checkpoint.state.submissions
    assert restored.checkpoint.state.broker_events == previous.checkpoint.state.broker_events
    assert _rows(case.engine, applied_reconciliation_commits) == before_a
    assert _rows(case.engine, daily_runtime_admissions) == before_admissions
    assert _rows(case.engine, daily_runtime_consumptions) == before_consumptions
    assert len(_rows(case.engine, daily_runtime_hold_events)) == len(before_holds) + len(
        source.envelopes
    )
    assert len(_rows(case.engine, daily_runtime_hold_heads)) == len(after.obligations.bindings)
    new_parents = tuple(
        row
        for row in _rows(case.engine, continuous_account_commits)
        if row["sequence"] > previous.receipt.commit.sequence
    )
    assert (
        len(new_parents) == 1
        and new_parents[0]["command_id"] == source.source.coordinator_command_id
    )
    events = tuple(
        row
        for row in _rows(case.engine, daily_runtime_attempt_events)
        if row["coordinator_sequence"] > previous.receipt.commit.sequence
    )
    assert len(events) == len(source.envelopes)
    assert {row["coordinator_command_id"] for row in events} == {
        source.source.coordinator_command_id
    }
    assert reader.dispatch_journal.read_head(source.closure.dispatch_keys[0]) == (
        source.dispatch_appends[-1].receipt.committed_head
    )
    assert case.paired_fixture.venue.read() == before_venue

    # Exact receipt retry has no new publisher-issued first-send ownership.
    before_retry = case.paired_fixture.counts(), case.h.counts()
    with case.store.write_transaction() as connection:
        assert (
            case.store.retry_in_transaction(
                connection,
                original=restored,
                command_sha256=batch.receipt.commit.transition.command_sha256,
                fence=case.h.lease.fence,
            )
            == batch.receipt
        )
    assert (case.paired_fixture.counts(), case.h.counts()) == before_retry
    with pytest.raises(ValueError, match="ALREADY_ATTEMPTED"):
        publisher.publish_dispatch(prepared[index], fence=case.h.lease.fence)
    return case, service, reader, source, publisher, batch


def _scoped_delivery_denial_and_original_send(result):
    case, service, reader, source, publisher, batch = result
    deliveries = tuple(
        SqlContinuousSimulationDelivery(publisher=publisher, sources=reader) for _ in range(2)
    )
    independent = case.paired_fixture.venue
    for delivery in deliveries:
        venue = SqlStatefulVenue(
            independent.journal._engine,
            model=delivery.model,
            artifacts=independent.artifacts,
            codec=service.codec,
            accounting=service.accounting,
            verified_sources=delivery,
        )
        delivery.bind_venue(venue)
    before = independent.read()
    counts = case.paired_fixture.counts(), case.h.counts()
    attempt_id = source.envelopes[0].event.attempt_id
    with case.store.cooperative_stop_scope(Event()), ThreadPoolExecutor(max_workers=1) as executor:
        # Both original adapters are allowed by the graph, but an active finite
        # operation's thread-bound account scope denies the peer before SQL or
        # a delivery claim. Do not remove that guard to manufacture a send race.
        with pytest.raises(ContinuousAccountConflict, match="STOP_SCOPE_THREAD_CHANGED"):
            executor.submit(
                deliveries[1].deliver, batch, source=source, attempt_id=attempt_id
            ).result(timeout=30)
        assert independent.read() == before
        assert not publisher._delivery_claims
        receipt = deliveries[0].deliver(batch, source=source, attempt_id=attempt_id)
        assert receipt.acknowledgment.disposition == "registered"
    after = independent.read()
    assert after.state.sequence == before.state.sequence + 1
    with (
        case.store.cooperative_stop_scope(Event()),
        pytest.raises(ValueError, match="ALREADY_CONSUMED"),
    ):
        deliveries[1].deliver(batch, source=source, attempt_id=attempt_id)
    assert independent.read() == after
    assert (case.paired_fixture.counts(), case.h.counts()) == counts
    assert case.h.resolved().obligations == batch.attempts.result.obligations
    assert all(item.state.value == "in_flight" for item in case.h.resolved().attempts)


def test_postgres_actual_competing_activation_and_scoped_first_send(pg_attempt_case, monkeypatch):
    result = _competing_publication(pg_attempt_case, monkeypatch)
    _scoped_delivery_denial_and_original_send(result)


def test_sqlite_competing_publication_fixture_smoke(attempt_case, monkeypatch):
    result = _competing_publication(attempt_case, monkeypatch)
    _scoped_delivery_denial_and_original_send(result)
