"""Fresh HALTED session wiring uses actual owners and grants no send authority."""

from dataclasses import replace
from threading import Event
from types import SimpleNamespace

import pytest
import sqlalchemy as sa

from apps.trader.continuous_session import ContinuousSessionStopped
from apps.trader.synthetic_session_genesis import (
    initialize_synthetic_session,
    reconstruct_synthetic_session_owners,
)
from apps.trader.synthetic_session_graph import build_synthetic_session_graph
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.adapters.runtime_clock_evidence import RuntimeClockSampler
from packages.application import personal_codec as codec
from packages.domain.operational_control import OperationalControlState
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.daily_runtime_risk_schema import DAILY_RUNTIME_TABLES
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal_schema import JOURNAL_TABLES, journal_entries
from packages.persistence.schema import metadata, phase5_operational_control_transitions
from packages.persistence.stateful_venue import SqlStatefulVenue, VenueStorageError
from tests.integration.test_continuous_synthetic_session_genesis import captured as captured


def _reconstruct(genesis, ports, lease):
    """Use the application owner join; this wrapper only supplies a test Stop event."""
    owners = reconstruct_synthetic_session_owners(genesis, lease=lease)
    assert owners.account.engine is ports["account_engine"]
    return SimpleNamespace(
        account=owners.account,
        runtime=owners.runtime,
        daily=owners.daily,
        venue_sources=owners.venue_sources,
        stop_event=Event(),
    )


def _build(graph, ports, **changed):
    arguments = {
        "account": graph.account,
        "runtime": graph.runtime,
        "daily": graph.daily,
        "venue_sources": graph.venue_sources,
        "venue_engine": ports["venue_engine"],
        "venue_artifacts": ports["venue_artifacts"],
        "codec": codec,
        "capture_clock": ports["clock"].now,
        "stop_event": graph.stop_event,
    }
    arguments.update(changed)
    return build_synthetic_session_graph(**arguments)


def _counts(ports):
    with ports["account_engine"].connect() as connection:
        return tuple(
            connection.scalar(sa.select(sa.func.count()).select_from(table))
            for table in (
                continuous_account_commits,
                phase5_operational_control_transitions,
                journal_entries,
                *DAILY_RUNTIME_TABLES,
            )
        )


@pytest.fixture
def fresh(captured):
    bootstrap, ports = captured
    genesis = initialize_synthetic_session(bootstrap, **ports)
    coordinator = genesis.account.coordinator
    # The startup fence is released. The fixture explicitly owns this later fence;
    # the constructor must neither acquire nor renew it implicitly.
    lease = coordinator.acquire("synthetic-session-graph-test")
    try:
        yield genesis, ports, lease, _reconstruct(genesis, ports, lease)
    finally:
        coordinator.release(lease.fence)


def test_original_session_graph_preserves_halted_genesis_without_writes_or_clock_sampling(fresh):
    genesis, ports, lease, graph = fresh
    before = _counts(ports)
    venue_before = genesis.venue.read()
    current = genesis.account.coordinator.current()
    clock_at = ports["clock"].now()

    def forbidden_clock():
        raise AssertionError("construction sampled the supplied capture clock")

    session = _build(graph, ports, capture_clock=forbidden_clock)
    assert session.account is graph.account and session.runtime is graph.runtime
    assert session.daily is graph.daily and session.stop_event is graph.stop_event
    assert graph.runtime.attempt_sources is session.attempts
    assert session.attempts.accounts is graph.account
    assert session.attempts.daily is graph.daily
    assert session.attempts.runtime_sources is graph.runtime
    assert session.outcomes.attempts is session.attempts
    assert session.outcomes.venue is session.delivery.venue
    assert session.delivery.venue.verified_sources is session.delivery
    assert session.delivery.venue.journal._engine is ports["venue_engine"]
    assert session.delivery.venue.artifacts is ports["venue_artifacts"]
    assert session.delivery.venue.accounting is graph.runtime.accounting
    assert session.outcomes.capture.clock is forbidden_clock
    assert graph.runtime.observed_hold_sources.venue_sources is graph.venue_sources
    assert session.outcomes.venue_sources is not graph.venue_sources
    assert session.outcomes.venue_sources.scope.binding_sha256 == (
        graph.runtime.venue_reference.semantic_sha256_ref
    )
    restored = graph.account.restore(genesis.scope)
    assert restored.receipt == genesis.restored.receipt
    assert restored.checkpoint == genesis.restored.checkpoint
    inventory = graph.daily.resolve_snapshot(
        graph.daily.read_snapshot(account_id=genesis.scope.account_id, fence=lease.fence)
    )
    assert inventory.control == genesis.control
    assert inventory.control.effective_state is OperationalControlState.HALTED
    assert inventory.assignment is None
    assert not inventory.attempts and not inventory.obligations.bindings
    assert session.delivery.venue.read() == venue_before
    assert not venue_before.state.commands and not venue_before.state.accounting.submissions
    assert _counts(ports) == before
    assert genesis.account.coordinator.current() == current == lease
    assert ports["clock"].now() == clock_at
    assert genesis.runtime_sources.attempt_sources is None
    assert genesis.runtime_sources.observed_hold_sources is None


@pytest.mark.parametrize(
    "changed",
    ["account", "runtime", "daily", "venue_sources", "codec", "capture_clock", "stop_event"],
)
def test_invalid_ports_fail_before_runtime_binding_or_financial_writes(fresh, changed):
    _genesis, ports, _lease, graph = fresh
    before = _counts(ports)
    with pytest.raises(ValueError):
        _build(graph, ports, **{changed: object()})
    assert graph.runtime.attempt_sources is None and graph.runtime.observed_hold_sources is None
    assert _counts(ports) == before


@pytest.mark.parametrize(
    "changed", ["same_engine", "same_objects", "engine_alias", "objects_alias"]
)
def test_storage_aliases_fail_before_runtime_binding_or_financial_writes(fresh, changed):
    _genesis, ports, _lease, graph = fresh
    before = _counts(ports)
    changed_ports = {}
    alias = None
    if changed == "same_engine":
        changed_ports["venue_engine"] = ports["account_engine"]
    elif changed == "same_objects":
        changed_ports["venue_artifacts"] = ports["account_artifacts"]
    elif changed == "engine_alias":
        alias = create_database_engine(str(ports["account_engine"].url))
        changed_ports["venue_engine"] = alias
    else:
        # A separate original port still names the same private directory.
        changed_ports["venue_artifacts"] = type(ports["account_artifacts"])(
            ports["account_artifacts"]._root
        )
    try:
        with pytest.raises(ValueError, match="EXACT_DISTINCT_SIMULATION_VENUE_REQUIRED"):
            _build(graph, ports, **changed_ports)
    finally:
        if alias is not None:
            alias.dispose()
    assert graph.runtime.attempt_sources is None and graph.runtime.observed_hold_sources is None
    assert _counts(ports) == before


@pytest.mark.parametrize(
    "retained,expected",
    [
        ("empty", "VENUE_HEAD_UNINITIALIZED_OR_OUTSIDE_BOUND"),
        ("wrong_model", "VENUE_COMMIT_MODEL_DIFFERS"),
    ],
)
def test_uninitialized_or_foreign_retained_venue_fails_without_bindings_or_fact_changes(
    fresh, tmp_path, retained, expected
):
    genesis, ports, lease, graph = fresh
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path / 'rejected-venue.sqlite'}")
    try:
        metadata.create_all(engine, tables=JOURNAL_TABLES)
        objects = LocalResearchArtifactStore(tmp_path / "rejected-venue-objects")
        foreign = None
        if retained == "wrong_model":
            model = graph.runtime.venue_model
            foreign = SqlStatefulVenue(
                engine,
                model=replace(model, producer=replace(model.producer, version="foreign-model/1")),
                artifacts=objects,
                codec=codec,
                accounting=graph.runtime.accounting,
            )
            foreign.initialize()

        def rows(selected_engine, tables):
            with selected_engine.connect() as connection:
                return tuple(
                    tuple(
                        tuple(row)
                        for row in connection.execute(
                            sa.select(table).order_by(*table.primary_key.columns)
                        )
                    )
                    for table in tables
                )

        def object_bytes(store):
            return tuple((path.name, path.read_bytes()) for path in sorted(store._root.iterdir()))

        account_tables = (
            continuous_account_commits,
            phase5_operational_control_transitions,
            *JOURNAL_TABLES,
            *DAILY_RUNTIME_TABLES,
        )
        account_before = rows(ports["account_engine"], account_tables)
        original_venue_before = rows(ports["venue_engine"], JOURNAL_TABLES)
        rejected_venue_before = rows(engine, JOURNAL_TABLES)
        stores = (ports["account_artifacts"], ports["venue_artifacts"], objects)
        objects_before = tuple(object_bytes(store) for store in stores)
        restored_before = graph.account.restore(genesis.scope)
        venue_before = genesis.venue.read()
        foreign_before = None if foreign is None else foreign.read()

        with pytest.raises(VenueStorageError, match=f"^{expected}$"):
            _build(graph, ports, venue_engine=engine, venue_artifacts=objects)

        assert graph.runtime.attempt_sources is None
        assert graph.runtime.observed_hold_sources is None
        assert graph.runtime._attempt_sources_binding is None
        assert graph.runtime._observed_sources_binding is None
        assert graph.runtime._observed_sources_pins is None
        assert rows(ports["account_engine"], account_tables) == account_before
        assert rows(ports["venue_engine"], JOURNAL_TABLES) == original_venue_before
        assert rows(engine, JOURNAL_TABLES) == rejected_venue_before
        assert tuple(object_bytes(store) for store in stores) == objects_before
        restored = graph.account.restore(genesis.scope)
        assert restored.receipt == restored_before.receipt
        assert restored.checkpoint == restored_before.checkpoint
        assert genesis.venue.read() == venue_before
        if foreign is not None:
            assert foreign.read() == foreign_before
        assert genesis.account.coordinator.current() == lease
    finally:
        engine.dispose()


def test_nonmodeled_clock_profile_fails_before_binding(fresh, monkeypatch):
    genesis, ports, _lease, graph = fresh
    host = RuntimeClockSampler(scope=genesis.scope)
    monkeypatch.setattr(graph.runtime.operating, "clock_sampler", host)
    before = _counts(ports)
    with pytest.raises(ValueError, match="LIVE_DISABLED_SYNTHETIC_SESSION_PROFILE_REQUIRED"):
        _build(graph, ports)
    assert graph.runtime.attempt_sources is None and graph.runtime.observed_hold_sources is None
    assert _counts(ports) == before


def test_provider_capture_class_cannot_be_used_as_synthetic_session_input(fresh, monkeypatch):
    _genesis, ports, _lease, graph = fresh
    before = _counts(ports)
    monkeypatch.setattr(graph.runtime.forward_sources, "evidence_class", "provider_https_read")
    with pytest.raises(ValueError, match="LIVE_DISABLED_SYNTHETIC_SESSION_PROFILE_REQUIRED"):
        _build(graph, ports)
    assert graph.runtime.attempt_sources is None and graph.runtime.observed_hold_sources is None
    assert _counts(ports) == before


def test_foreign_equal_venue_source_owner_is_rejected_before_binding(fresh):
    _genesis, ports, _lease, graph = fresh
    before = _counts(ports)
    source = graph.venue_sources
    copied = type(source)(
        source.engine,
        artifacts=source.artifacts,
        codec=source.codec,
        resolver=source.resolver,
        scope=replace(source.scope),
        model=source.model,
    )
    with pytest.raises(ValueError, match="ORIGINAL_UNBOUND_SYNTHETIC_SESSION_GRAPH_REQUIRED"):
        _build(graph, ports, venue_sources=copied)
    assert graph.runtime.attempt_sources is None and graph.runtime.observed_hold_sources is None
    assert _counts(ports) == before


def test_existing_session_bindings_are_not_replaced(fresh):
    _genesis, ports, _lease, graph = fresh
    session = _build(graph, ports)
    original = (graph.runtime.attempt_sources, graph.runtime.observed_hold_sources)
    before = _counts(ports)
    with pytest.raises(ValueError, match="ORIGINAL_UNBOUND_SYNTHETIC_SESSION_GRAPH_REQUIRED"):
        _build(graph, ports)
    assert (graph.runtime.attempt_sources, graph.runtime.observed_hold_sources) == original
    assert graph.runtime.attempt_sources is session.attempts
    assert _counts(ports) == before


def test_stopped_construction_and_session_operations_cannot_write_or_clear_stop(fresh):
    _genesis, ports, _lease, graph = fresh
    before = _counts(ports)
    graph.stop_event.set()
    with pytest.raises(ContinuousSessionStopped, match="CONTINUOUS_SESSION_STOPPED"):
        _build(graph, ports)
    assert graph.runtime.attempt_sources is None and graph.runtime.observed_hold_sources is None
    graph.stop_event.clear()
    session = _build(graph, ports)
    graph.stop_event.set()
    with pytest.raises(ContinuousSessionStopped, match="CONTINUOUS_SESSION_STOPPED"):
        session.reconcile(operation_id="stopped-reconcile", capture_id="stopped-capture")
    graph.stop_event.clear()
    with pytest.raises(ContinuousSessionStopped, match="CONTINUOUS_SESSION_STOPPED"):
        session.reconcile(operation_id="stopped-again", capture_id="stopped-again-capture")
    assert _counts(ports) == before


def test_reconstructed_current_owners_restore_same_genesis_without_send(fresh):
    genesis, ports, lease, first = fresh
    session = _build(first, ports)
    before = _counts(ports)
    venue_before = session.delivery.venue.read()
    restarted = _reconstruct(genesis, ports, lease)
    second = _build(restarted, ports)
    assert second.account is not session.account
    assert second.daily is not session.daily and second.runtime is not session.runtime
    assert second.attempts is not session.attempts
    assert second.runtime.owner_dependencies is not session.runtime.owner_dependencies
    assert second.runtime.owner_dependencies.commands is genesis.owners.commands
    restored = second.account.restore(genesis.scope)
    assert restored.receipt == genesis.restored.receipt
    assert restored.checkpoint == genesis.restored.checkpoint
    assert not restored.checkpoint.state.submissions
    assert not restored.checkpoint.state.commitments
    assert second.delivery.venue.read() == venue_before
    assert _counts(ports) == before
