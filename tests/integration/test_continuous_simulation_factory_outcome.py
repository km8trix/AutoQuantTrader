"""Restore original outcomes with a new actual factory and a read-only venue.

Setup uses genuine signed assignment history, explicit synthetic market/time and
modeled re-arm. Factory clocks, leases and runtime checks are never replaced.
"""

from contextlib import contextmanager
from copy import copy

import pytest
import sqlalchemy as sa

from apps.trader.continuous_simulation_factory import (
    ContinuousSimulationFactory,
    ContinuousSimulationFactoryError,
)
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.adapters.runtime_clock_evidence import RuntimeClockSampler
from packages.application import personal_codec as codec
from packages.persistence.continuous_attempt_outcome_sources import (
    SqlContinuousAttemptOutcomeSources,
)
from packages.persistence.continuous_runtime_attempt_sources import (
    SqlContinuousRuntimeAttemptSources,
)
from packages.persistence.continuous_simulation_delivery import SqlContinuousSimulationDelivery
from packages.persistence.stateful_venue import SqlStatefulVenue
from packages.persistence.venue_reconciliation_capture import SqlVenueReconciliationCapture
from tests.integration import test_continuous_simulation_factory as factory_fixture

configured = factory_fixture.configured


def _unexpected(*_args, **_kwargs):
    pytest.fail("restore invoked a new source, artifact write, initialization or delivery")


@contextmanager
def _no_new_sources(monkeypatch):
    with monkeypatch.context() as patch:
        for owner, name in (
            (SqlStatefulVenue, "initialize"),
            (SqlStatefulVenue, "execute"),
            (SqlVenueReconciliationCapture, "capture"),
            (SqlContinuousAttemptOutcomeSources, "observe"),
            (SqlContinuousSimulationDelivery, "deliver"),
            (LocalResearchArtifactStore, "put"),
            (RuntimeClockSampler, "sample"),
        ):
            patch.setattr(owner, name, _unexpected)
        yield


def test_factory_reconstructs_exact_outcome_graph_without_writes(configured, monkeypatch):
    fixture, config = configured
    pair = fixture[0]
    factory_fixture.install_initial_signed_assignment(fixture)
    original = pair.account.restore(pair.base.scope)
    financial = pair.counts()
    independent = pair.venue.read()
    config_bytes = codec.encode_record(config)
    factory_fixture.release(fixture)
    with _no_new_sources(monkeypatch):
        factory = ContinuousSimulationFactory(
            config, account_id=pair.base.scope.account_id, stop_requested=lambda: False
        )
        try:
            factory.outcomes.require_bindings()
            assert factory.outcomes.attempts is factory.delivery.sources
            assert factory.delivery.publisher.account is factory.account
            assert factory.venue.verified_sources is factory.delivery
            assert factory.delivery.venue is factory.venue
            assert factory.outcomes.scope.binding_sha256 == (
                factory.runtime_sources.venue_reference.semantic_sha256_ref
            )
            assert factory.integrity.reconciliation_scope.binding_sha256 == (
                factory.inputs.spec.account_binding_sha256
            )
            assert factory.venue_engine is not factory.engine
            assert all(journal._engine is factory.engine for journal in factory.integrity.journals)
            with factory.venue_engine.connect() as connection:
                assert connection.exec_driver_sql("PRAGMA schema_version").scalar() is not None
                with pytest.raises(sa.exc.OperationalError, match="readonly"):
                    connection.exec_driver_sql("CREATE TABLE forbidden_restore_write (value INT)")
            result = factory.execute(operation_id="retained-owner-graph-restore")
            assert b'"status":"restored"' in result
            assert original.checkpoint.semantic_sha256.encode() in result
            assert codec.encode_record(config) == config_bytes
            assert factory.venue.read() == independent
            changed = copy(factory.delivery)
            factory.venue.verified_sources = changed
            with pytest.raises(ValueError, match="OWNERS_CHANGED"):
                factory.outcomes.require_bindings()
            factory.venue.verified_sources = factory.delivery
            factory.outcomes.require_bindings()
        finally:
            factory.close()
    assert factory.engine is None and factory.venue_engine is None and factory.lease is None
    assert pair.counts() == financial
    assert pair.venue.read() == independent


def test_factory_disposes_both_engines_when_outcome_binding_fails(configured, monkeypatch):
    fixture, config = configured
    pair = fixture[0]
    factory_fixture.release(fixture)
    disposed = []
    original = sa.engine.Engine.dispose

    def dispose(engine, *args, **kwargs):
        disposed.append(engine)
        return original(engine, *args, **kwargs)

    def fail_binding(_self, _value):
        raise ValueError("explicit failure after original owner construction")

    with monkeypatch.context() as patch:
        patch.setattr(sa.engine.Engine, "dispose", dispose)
        patch.setattr(SqlContinuousRuntimeAttemptSources, "bind_outcome_sources", fail_binding)
        with pytest.raises(ContinuousSimulationFactoryError, match="INITIALIZATION_FAILED"):
            ContinuousSimulationFactory(
                config, account_id=pair.base.scope.account_id, stop_requested=lambda: False
            )
    assert len(disposed) == 2 and disposed[0] is not disposed[1]
    assert sorted(str(engine.url.query["mode"]) for engine in disposed) == ["ro", "rw"]
    # Cleanup released the actual acquired lease; a fresh real owner can acquire.
    factory = ContinuousSimulationFactory(
        config, account_id=pair.base.scope.account_id, stop_requested=lambda: False
    )
    factory.close()


def _signed_outcome_history(tmp_path, monkeypatch):
    """Actual signed lineage; only fixture market/time/re-arm are modeled."""
    from datetime import timedelta

    from alembic import command

    from packages.domain.operational_control import (
        OperationalControlCommandKind,
        OperationalControlState,
    )
    from packages.domain.research_dataset import modeled_daily_availability
    from packages.domain.stateful_venue_contracts import VenueAccept, VenueCommand, VenueRunDue
    from packages.persistence.continuous_attempt_publication import SqlContinuousAttemptPublication
    from packages.persistence.database import EXPECTED_SCHEMA_REVISION
    from tests.integration.test_continuous_attempt_outcome_sources import outcome_owner
    from tests.integration.test_continuous_runtime_attempt_sources import activation_preparation
    from tests.integration.test_continuous_session import canonical_accounting, session_for
    from tests.integration.test_continuous_session_owner_startup import genuine_captured_selection
    from tests.integration.test_personal_research_migration import migration_config
    from tests.integration.test_runtime_owner_dependencies import attach

    tmp_path = tmp_path.resolve()
    database = tmp_path / "account.sqlite"
    migration = migration_config(database)
    migration.attributes["aqt_explicit_database_url"] = f"sqlite+pysqlite:///{database}"
    command.upgrade(migration, EXPECTED_SCHEMA_REVISION)
    canonical_accounting(monkeypatch)
    fixture, _prior, enabled, initial_request, enable_request = genuine_captured_selection(
        tmp_path, monkeypatch
    )
    pair = fixture[0]
    case, h = pair.base, pair.base.h
    try:
        day = case.inputs.spec.window.scored_sessions[0]
        at = modeled_daily_availability(day) + timedelta(milliseconds=50)
        h.coordinator.release(h.lease.fence)
        h.clock.instant = h.decision_at = at
        h.lease = h.coordinator.acquire("genuine-outcome-daily-owner")
        _owners, runtime, *_ = attach(pair)
        h.assignment = enabled
        # The signed enabled assignment already exists. Suppress only the old
        # fixture's unsigned install step; its separate re-arm remains explicitly
        # modeled readiness applied through the actual control repository.
        with monkeypatch.context() as patch:
            patch.setattr(h, "install", lambda _assignment: None)
            h.enable()
        assert h.resolved().assignment == enabled
        session = session_for(pair, runtime)
        for index in range(2):
            h.clock.instant += timedelta(milliseconds=1)
            session.delivery.venue.execute(
                VenueCommand(f"genuine-outcome-cash-{index}", h.clock.instant, VenueRunDue())
            )
            session.reconcile(
                operation_id=f"genuine-outcome-observation-{index}",
                capture_id=f"genuine-outcome-capture-{index}",
            )
        h.clock.instant += timedelta(milliseconds=1)
        publication = case.add_capture(day)
        closure = case.closure(
            "genuine-outcome-daily-source",
            h.clock.instant,
            tuple(item.observation_id for item in publication.record.observations),
        )
        market = runtime.forward_sources.resolve(closure)
        operating = runtime.operating
        prepared_clock = operating.prepare_clock_append(
            operating.clock_sampler.sample(),
            expected_head=operating.journal.read_head(operating.clock_key()),
        )
        with pair.account.write_transaction() as connection:
            clock_reference = operating.append_clock_in_transaction(connection, prepared_clock)
        session.publish_daily(
            operation_id="genuine-outcome-daily",
            market=market,
            clock_reference=clock_reference,
        )
        previous, current = pair.account.restore(case.scope), h.resolved()
        (admission,) = h.store.inspect_snapshot_admissions(current)
        assert previous.checkpoint.runtime_decisions[-1].decision.approved, (
            previous.checkpoint.runtime_decisions[-1].decision.reasons
        )
        assert admission.bindings and current.assignment == enabled
        case.paired_fixture = pair
        print("genuine signed daily admission retained", flush=True)
        values = activation_preparation(
            (case, runtime, session.attempts, previous, current, admission)
        )
        case, runtime, reader, _previous, _current, _admission, source, _descriptor = values
        print("genuine original activation source retained", flush=True)
        publisher = SqlContinuousAttemptPublication(account=case.store)
        batch = publisher.publish_dispatch(
            publisher.prepare_source(source, sources=reader), fence=h.lease.fence
        )
        delivery = SqlContinuousSimulationDelivery(publisher=publisher, sources=reader)
        venue = SqlStatefulVenue(
            pair.venue_engine,
            model=runtime.venue_model,
            artifacts=pair.venue.artifacts,
            codec=runtime.codec,
            accounting=runtime.accounting,
            verified_sources=delivery,
        )
        delivery.bind_venue(venue)
        outcomes, capture_clock = outcome_owner(case, delivery, venue)
        attempt_id = source.envelopes[0].event.attempt_id
        delivered = delivery.deliver(batch, source=source, attempt_id=attempt_id)
        assert delivered.acknowledgment.disposition == "registered"
        order_id = source.closure.preparations[0].request.submission.order_id
        venue.execute(
            VenueCommand("genuine-outcome-accept", h.clock.instant, VenueAccept(order_id))
        )
        before, current = case.store.restore(case.scope), h.resolved()
        observation = outcomes.observe(
            previous=before,
            current=current,
            attempt_id=attempt_id,
            capture_id="genuine-retained-outcome",
        )
        assert observation.plan.outcome is not None
        h.clock.instant = max(h.clock.instant, capture_clock.at)
        current = h.resolved()
        outcome = reader.retain_outcome(
            coordinator_command_id="genuine-outcome-confirmed",
            previous=before,
            current=current,
            admissions=source.admissions,
            attempt_id=attempt_id,
            observation=observation,
        )
        receipt = publisher.publish(
            publisher.prepare_source(outcome, sources=reader), fence=h.lease.fence
        )
        print("genuine outcome C/B publication retained", flush=True)
        original, current = case.store.restore(case.scope), h.resolved()
        assert original.receipt == receipt and original.checkpoint.state == before.checkpoint.state
        assert tuple(item.state.value for item in current.attempts) == ("confirmed",)
        assert current.assignment == enabled
        h.decision_at = h.clock.instant
        h.controls.apply(
            h.command(
                OperationalControlCommandKind.HALT,
                "genuine-outcome-restore-halt",
                OperationalControlState.HALTED,
            )
        )
        current = h.resolved()
        assert current.control.effective_state is OperationalControlState.HALTED
        return (
            pair,
            runtime,
            original,
            current,
            batch,
            venue.read(),
            (initial_request, enable_request),
        )
    except BaseException:
        pair.close()
        raise


def _configuration_for_history(pair, runtime):
    from apps.trader.continuous_simulation_factory import (
        CONFIGURATION_SCHEMA,
        PRODUCER_MAP_SCHEMA,
        ContinuousSimulationConfiguration,
    )
    from packages.domain.continuous_persistence_contracts import CONTINUOUS_REQUEST_SCHEMA

    case = pair.base
    root = case.artifacts._root.parent
    for path in (root / "account.sqlite", root / "independent.sqlite"):
        path.chmod(0o600)
    return ContinuousSimulationConfiguration(
        schema_id=CONFIGURATION_SCHEMA,
        operation="restore",
        owner_id="retained-outcome-restorer",
        database_path=str(root / "account.sqlite"),
        artifact_root=str(root / "objects"),
        venue_database_path=str(root / "independent.sqlite"),
        venue_artifact_root=str(root / "independent-objects"),
        inputs=case.put(CONTINUOUS_REQUEST_SCHEMA, case.inputs),
        venue_model=case.put("venue-model/1", pair.model),
        producer_map=case.put(PRODUCER_MAP_SCHEMA, runtime.producer_map),
        benchmark_instrument_id=runtime.benchmark_instrument_id,
        capture_evidence_class=case.forward.evidence_class,
        clock_profile=runtime.operating.clock_sampler.profile,
        lease_policy_id="fixture",
        lease_policy_version="1",
        lease_ttl_microseconds=60_000_000,
        maximum_in_flight_microseconds=5_000_000,
        takeover_safety_microseconds=10_000_000,
    )


def _execute_retained_factory(history, config, monkeypatch):
    """One real-clock attempt; a timeout or lease expiry remains a test failure."""
    import json
    import signal
    from time import perf_counter

    from apps.trader.continuous_simulation_factory import _ActualClock

    pair, _runtime, original, previous_daily, old_batch, independent, _requests = history
    financial = pair.counts()
    old_fence = pair.base.h.lease.fence
    pair.base.h.coordinator.release(old_fence)
    factory = None
    started = perf_counter()
    result = None
    error = None
    cleanup_error = None

    class RestoreDeadline(TimeoutError):
        pass

    def deadline(_signum, _frame):
        raise RestoreDeadline("actual factory restore exceeded 120 seconds")

    old_handler = signal.getsignal(signal.SIGALRM)
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    signal.signal(signal.SIGALRM, deadline)
    signal.setitimer(signal.ITIMER_REAL, 120)
    try:
        with _no_new_sources(monkeypatch):
            factory = ContinuousSimulationFactory(
                config, account_id=pair.base.scope.account_id, stop_requested=lambda: False
            )
            assert type(factory.clock) is _ActualClock
            assert factory.lease.fence != old_fence
            factory.outcomes.require_bindings()
            with pytest.raises(ValueError, match="SUCCESSFUL_DISPATCH_COMMIT"):
                factory.delivery.publisher.require_completed(old_batch)
            print(f"actual factory graph ready: {perf_counter() - started:.3f}s", flush=True)
            result = json.loads(factory.execute(operation_id="restore-original-retained-outcome"))
            assert result["checkpoint_sha256"] == original.checkpoint.semantic_sha256
            assert result["commit_sha256"] == original.receipt.commit.semantic_sha256
            assert result["assignment_sha256"] == previous_daily.assignment.semantic_sha256
            assert result["status"] == "restored"
            assert factory.venue.read() == independent
    except BaseException as caught:
        error = caught
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)
        print(
            f"actual factory restore result: {'completed' if error is None else 'failed'}; "
            f"elapsed={perf_counter() - started:.3f}s",
            flush=True,
        )
        if error is not None:
            _report_static_failure("execute", error)
        try:
            if factory is not None:
                factory.close()
        except BaseException as caught:
            cleanup_error = caught
            _report_static_failure("cleanup", caught)
        finally:
            assert pair.counts() == financial
            assert pair.venue.read() == independent
            if factory is not None:
                assert factory.engine is None and factory.venue_engine is None
    if error is not None and cleanup_error is not None:
        raise BaseExceptionGroup("actual restore and cleanup both failed", [error, cleanup_error])
    if error is not None:
        raise error
    if cleanup_error is not None:
        raise cleanup_error
    assert result is not None


def _report_static_failure(phase, error):
    """Bounded exception codes only; never emit source objects or frame locals."""
    original = error
    seen = set()
    while original is not None and id(original) not in seen and len(seen) < 8:
        seen.add(id(original))
        print(
            f"actual factory {phase} error: {type(original).__name__}: {str(original)[:200]}",
            flush=True,
        )
        original = original.__context__


def test_actual_signed_retained_outcome_restores_with_original_utc_and_lease(tmp_path, monkeypatch):
    from time import perf_counter

    started = perf_counter()
    history = _signed_outcome_history(tmp_path, monkeypatch)
    pair, runtime, *_ = history
    try:
        config = _configuration_for_history(pair, runtime)
        print(
            f"genuine retained-outcome fixture setup: {perf_counter() - started:.3f}s", flush=True
        )
        _execute_retained_factory(history, config, monkeypatch)
    finally:
        pair.close()
