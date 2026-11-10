"""One actual configured-owner/read-port lifecycle over fresh migrated stores.

L creates its own genuine G owner; the earlier fixture's data-only owner never
starts. Original K proofs/queries and G cleanup remain intact. Test-only barriers
qualify the observed incomplete cutoff separately from eventual native cleanup.
"""

import asyncio
import sqlite3
import sys
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy import event
from sqlalchemy.pool import NullPool

from apps.api import configured_readiness_reads as lifecycle_module
from apps.api import readiness_read_store as read_module
from apps.trader import continuous_readiness_owner as owner_module
from tests.integration.test_continuous_synthetic_configured_readiness import _case
from tests.integration.test_continuous_synthetic_factory_partial_cleanup import _snapshot
from tests.integration.test_continuous_synthetic_readiness_http import _paused_original_proof
from tests.integration.test_continuous_synthetic_readiness_read_store import (
    _held_query,
    _read_case,
    _read_in_thread,
    _selected,
)
from tests.integration.test_continuous_synthetic_readiness_store_binding import _no_caller_effects


@contextmanager
def _l_case(tmp_path, monkeypatch, *, changes=None):
    fixture = (
        _read_case(tmp_path, monkeypatch)
        if changes is None
        else _case(tmp_path, monkeypatch, changes=changes)
    )
    with fixture as case:
        unused = case.owner
        build = lifecycle_module.create_configured_readiness_owner
        open_store = lifecycle_module.open_readiness_read_store
        create_engine = sa.create_engine
        case.lifecycle_calls = []
        case.lifecycle_threads = []
        case.lifecycle_builds = []
        case.lifecycle_opens = []
        case.open_errors = []
        case.opening_thread = None
        if changes is not None:
            case.read_engines = []
            case.read_stores = []
            case.query_count = 0

        def construct(**kwargs):
            assert case.lifecycle_builds == []
            assert threading.current_thread() is case.caller_thread
            assert kwargs == {
                "configuration_path": str(case.configuration_path),
                "account_id": case.study.genesis.scope.account_id,
                "instance_lock": str(case.lock_path),
                "limits": owner_module.ReadinessOwnerLimits(),
            }
            actual = build(**kwargs)
            assert type(actual) is owner_module.ContinuousReadinessOwner
            assert actual is not unused and actual._thread is None
            case.lifecycle_builds.append(actual)
            case.owner = actual
            return actual

        def before_sql(connection, cursor, statement, parameters, context, executemany):
            if "FROM alembic_version" not in statement:
                return
            case.query_count += 1
            case.query_connections.append(connection)
            case.query_threads.append(threading.current_thread())
            if case.query_hook is not None:
                case.query_hook(connection, cursor)

        def engine_created(*args, **kwargs):
            # The inherited K observer intentionally ignores noncaller threads.
            # Forward it; observe the actual separate Engine on L's worker here.
            engine = create_engine(*args, **kwargs)
            if threading.current_thread() is case.opening_thread:
                assert changes is None
                assert kwargs["poolclass"] is NullPool
                assert kwargs["connect_args"] == {"timeout": 0.1}
                assert type(args[0]) is sa.URL
                assert dict(args[0].query) == {"mode": "ro", "uri": "true"}
                assert args[0].database == case.study.paths["database_path"].as_uri()
                case.read_engines.append(engine)
                event.listen(engine, "before_cursor_execute", before_sql)
                if case.connect_hook is not None:
                    event.listen(engine, "connect", case.connect_hook)
            return engine

        def opened(owner):
            assert owner is case.owner
            assert threading.current_thread() is not case.caller_thread
            assert threading.current_thread() is not owner._thread
            case.lifecycle_opens.append(owner)
            case.opening_thread = threading.current_thread()
            try:
                actual = open_store(owner)
            except BaseException as error:
                case.open_errors.append(error)
                raise
            finally:
                case.opening_thread = None
            assert type(actual) is read_module.ReadinessReadStore
            case.read_stores.append(actual)
            return actual

        monkeypatch.setattr(lifecycle_module, "create_configured_readiness_owner", construct)
        monkeypatch.setattr(lifecycle_module, "open_readiness_read_store", opened)
        monkeypatch.setattr(sa, "create_engine", engine_created)
        with _no_caller_effects(monkeypatch, case.caller_thread):
            case.manager = lifecycle_module.configured_readiness_reads(
                configuration_path=str(case.configuration_path),
                account_id=case.study.genesis.scope.account_id,
                instance_lock=str(case.lock_path),
            )
            assert case.owner._thread is unused._thread is None
        assert case.lifecycle_builds == [case.owner]
        assert case.trace == case.lifecycle_opens == case.lifecycle_calls == []
        assert not case.lock_path.exists()
        assert _snapshot(case.study).__dict__ == case.before.__dict__
        yield case
        assert unused._thread is None and unused.store_binding() is None
        assert all(thread is not case.caller_thread for thread in case.lifecycle_threads)
        assert all(thread is not case.owner._thread for thread in case.lifecycle_threads)
        # Inherited K and G finalizers retain their complete original facts,
        # actual close-return statuses, one release and engine/guard/Thread checks.


@contextmanager
def _worker(case, body=None, *, manager=None):
    run = SimpleNamespace(
        entered=threading.Event(),
        leave=threading.Event(),
        finished=threading.Event(),
        port=None,
        errors=[],
    )
    manager = case.manager if manager is None else manager
    targets = (
        (owner_module.ContinuousReadinessOwner.start.__code__, "start"),
        (owner_module.ContinuousReadinessOwner.stop.__code__, "stop"),
        (read_module.ReadinessReadStore.close.__code__, "close"),
    )

    def observe(frame, event_name, argument):
        # Native worker-local observation only: retain static labels, never a
        # frame/local/return object. A return event alone is not cleanup success.
        if event_name not in ("call", "return"):
            return
        for code, label in targets:
            if frame.f_code is code:
                expected = run.port if label == "close" else case.owner
                if frame.f_locals.get("self") is expected:
                    case.lifecycle_calls.append((label, event_name))
                return

    def operation():
        previous = sys.getprofile()
        case.lifecycle_threads.append(threading.current_thread())
        try:
            sys.setprofile(observe)
            with manager as port:
                run.port = port
                run.entered.set()
                if body is None:
                    assert run.leave.wait(12), "test did not release lifecycle body"
                else:
                    body(port)
        except BaseException as error:
            run.errors.append(error)
        finally:
            sys.setprofile(previous)
            run.finished.set()

    caller = threading.Thread(target=operation)
    run.caller = caller
    caller.start()
    primary = None
    try:
        yield run
    except BaseException as error:
        primary = error
        raise
    finally:
        run.leave.set()
        caller.join(25)
        if caller.is_alive():
            cleanup = AssertionError("actual lifecycle worker did not finish")
            if primary is not None:
                raise BaseExceptionGroup("lifecycle and test cleanup failed", [primary, cleanup])
            raise cleanup


def _completed(run):
    assert run.finished.wait(25), "actual lifecycle did not reach its bounded return"
    run.caller.join(1)
    assert not run.caller.is_alive()


def _dispatches(case, *, opened=True):
    calls = [name for name, event_name in case.lifecycle_calls if event_name == "call"]
    assert calls == (["start", "close", "stop"] if opened else ["start", "stop"])
    assert len(case.lifecycle_builds) == 1
    assert len(case.lifecycle_opens) == int(opened)


def _complete(case, port):
    # These original returned statuses establish actual completion independently
    # of the profiler and engine_disposed event, which only observe attempts.
    assert port.status() == read_module.ReadinessReadStoreStatus("closed", False, True, None)
    status = case.owner.status()
    assert status.phase == "stopped" and status.busy is False
    assert status.cleanup_complete is True and status.cleanup_failure is None
    assert not case.owner._thread.is_alive()
    assert case.read_disposals == case.read_engines


def _fixed(error, suffix):
    assert type(error) is RuntimeError
    assert str(error) == "CONFIGURED_READINESS_READS_" + suffix


def test_configured_read_lifecycle_owns_two_fresh_reads_and_cannot_recreate(tmp_path, monkeypatch):
    with _l_case(tmp_path, monkeypatch) as case:
        recreated = case.manager._recreate_cm()
        values = []

        def read_twice(port):
            assert case.proofs == case.query_count == 0
            assert case.release_attempts == []
            values.extend((port.read(), port.read()))
            assert case.proofs == case.query_count == 2
            assert _snapshot(case.study).financial == case.before.financial

        with _worker(case, read_twice) as run:
            _completed(run)
        assert run.errors == [] and len(values) == 2
        for value in values:
            _selected(case, value)
        assert values[0] == values[1] and values[0] is not values[1]
        assert len(case.read_ids) == len(set(case.read_ids)) == 2
        assert all(connection.closed for connection in case.query_connections)
        assert len(case.read_engines) == 1
        assert case.read_engines[0] is not case.account_engine
        assert case.read_engines[0] is not case.venue_engine
        _dispatches(case)
        _complete(case, run.port)
        with _worker(case, manager=recreated) as repeated:
            _completed(repeated)
        assert len(repeated.errors) == 1
        _fixed(repeated.errors[0], "ALREADY_ENTERED")
        _dispatches(case)
        assert len(case.acquires) == len(case.releases) == 1


def test_unsupported_actual_configuration_denies_before_read_engine(tmp_path, monkeypatch):
    with _l_case(tmp_path, monkeypatch, changes={"operation": "integrity"}) as case:
        with _worker(case) as run:
            _completed(run)
        assert run.port is None and len(run.errors) == 1
        _fixed(run.errors[0], "STARTUP_UNAVAILABLE")
        _dispatches(case, opened=False)
        assert case.read_engines == case.acquires == []
        assert case.factory is None and case.proofs == case.query_count == 0
        assert case.owner.status().cleanup_complete is True


def test_original_failed_open_disposes_its_partial_engine_then_owner_stops(tmp_path, monkeypatch):
    with _l_case(tmp_path, monkeypatch) as case:
        connected = []

        def temporary_namespace(connection, record):
            connection.execute("CREATE TEMP TABLE controlled_lifecycle_temp (value INTEGER)")
            connected.append(connection)

        case.connect_hook = temporary_namespace
        with _worker(case) as run:
            _completed(run)
        assert run.port is None and len(run.errors) == 1
        assert len(case.open_errors) == 1 and run.errors[0] is case.open_errors[0]
        assert str(run.errors[0]) == "READINESS_READ_STORE_BINDING_CHANGED"
        assert [name for name, kind in case.lifecycle_calls if kind == "call"] == ["start", "stop"]
        assert case.lifecycle_opens == [case.owner]
        assert len(connected) == len(case.read_engines) == len(case.read_disposals) == 1
        assert case.read_stores == [] and case.proofs == case.query_count == 0
        with pytest.raises(sqlite3.ProgrammingError):
            connected[0].execute("SELECT 1")
        assert case.owner.status().cleanup_complete is True


@pytest.mark.parametrize("kind", ["base", "cancel"])
def test_exact_body_interruption_survives_original_resource_cleanup(tmp_path, monkeypatch, kind):
    primary = (
        KeyboardInterrupt("controlled private body interruption")
        if kind == "base"
        else asyncio.CancelledError("controlled synchronous cancellation object")
    )
    with _l_case(tmp_path, monkeypatch) as case:

        def fail(port):
            assert case.proofs == case.query_count == 0
            raise primary

        with _worker(case, fail) as run:
            _completed(run)
        assert len(run.errors) == 1 and run.errors[0] is primary
        _dispatches(case)
        _complete(case, run.port)
        assert case.proofs == case.query_count == 0


def test_active_original_sql_exit_reports_cutoff_then_denies_late_result(tmp_path, monkeypatch):
    with (
        _l_case(tmp_path, monkeypatch) as case,
        _held_query(case) as pause,
        _worker(case) as run,
    ):
        assert run.entered.wait(12)
        assert run.errors == []
        _read_in_thread(run.port, pause)
        assert pause.reached.wait(5)
        run.leave.set()
        _completed(run)
        assert len(run.errors) == 1
        cutoff = run.errors[0]
        _fixed(cutoff, "READ_CLEANUP_INCOMPLETE")
        _dispatches(case)
        assert run.port.status().phase == "closing"
        assert run.port.status().busy is True
        assert run.port.status().cleanup_complete is False
        assert case.read_disposals == []
        assert case.owner.status().cleanup_complete is True
        assert not case.owner._thread.is_alive()
        pause.release.set()
        assert pause.finished.wait(5)
        for caller in pause.callers:
            caller.join(5)
            assert not caller.is_alive()
        assert pause.results == [] and len(pause.errors) == 1
        assert str(pause.errors[0]) == "READINESS_READ_STORE_UNAVAILABLE"
        assert run.errors == [cutoff]
        _fixed(cutoff, "READ_CLEANUP_INCOMPLETE")
        _complete(case, run.port)
        assert case.proofs == case.query_count == 1


def test_body_primary_and_observed_disposal_failure_do_not_expose_private_error(
    tmp_path, monkeypatch
):
    primary = KeyboardInterrupt("private body primary")
    cleanup = OSError("private actual disposal event error")
    with _l_case(tmp_path, monkeypatch) as case:
        case.allow_read_cleanup_failure = True

        def failed_disposal(engine):
            raise cleanup

        def body(port):
            event.listen(case.read_engines[0], "engine_disposed", failed_disposal)
            raise primary

        with _worker(case, body) as run:
            _completed(run)
        assert len(run.errors) == 1
        group = run.errors[0]
        assert isinstance(group, BaseExceptionGroup)
        assert group.message == "CONFIGURED_READINESS_READS_OPERATION_AND_CLEANUP_FAILED"
        assert len(group.exceptions) == 2 and group.exceptions[0] is primary
        _fixed(group.exceptions[1], "READ_CLEANUP_INCOMPLETE")
        assert all(member is not cleanup for member in group.exceptions)
        _dispatches(case)
        assert case.read_disposals == case.read_engines
        assert run.port.status().cleanup_complete is False
        assert case.owner.status().cleanup_complete is True
        assert case.proofs == case.query_count == 0


def test_body_primary_keeps_actual_nested_close_guard_and_cleanup_group(tmp_path, monkeypatch):
    primary = KeyboardInterrupt("private body primary")
    cleanup = OSError("private actual dispose failure")
    foreign_calls = []

    class ForeignPool:
        def dispose(self):
            foreign_calls.append("dispose")
            raise AssertionError("foreign pool must not run")

        def recreate(self):
            foreign_calls.append("recreate")
            raise AssertionError("foreign pool must not run")

    with _l_case(tmp_path, monkeypatch) as case:
        case.allow_read_cleanup_failure = True

        def failed_disposal(engine):
            raise cleanup

        def body(port):
            engine = case.read_engines[0]
            event.listen(engine, "engine_disposed", failed_disposal)
            engine.pool = ForeignPool()
            raise primary

        with _worker(case, body) as run:
            _completed(run)
        assert len(run.errors) == 1
        group = run.errors[0]
        assert isinstance(group, BaseExceptionGroup)
        assert group.message == "CONFIGURED_READINESS_READS_OPERATION_AND_CLEANUP_FAILED"
        assert len(group.exceptions) == 2 and group.exceptions[0] is primary
        nested = group.exceptions[1]
        assert isinstance(nested, BaseExceptionGroup)
        assert nested.message == "READINESS_READ_STORE_OPERATION_AND_CLEANUP_FAILED"
        assert len(nested.exceptions) == 2 and nested.exceptions[1] is cleanup
        assert str(nested.exceptions[0]) == "READINESS_READ_STORE_BINDING_CHANGED"
        assert foreign_calls == [] and type(case.read_engines[0].pool) is NullPool
        _dispatches(case)
        assert run.port.status().cleanup_complete is False
        assert case.read_disposals == case.read_engines
        assert case.owner.status().cleanup_complete is True
        assert case.proofs == case.query_count == 0


def test_held_original_proof_reports_both_incomplete_cutoffs_without_waiting_or_retry(
    tmp_path, monkeypatch
):
    with _l_case(tmp_path, monkeypatch) as case:
        with _paused_original_proof(case, monkeypatch) as pause, _worker(case) as run:
            assert run.entered.wait(12)
            assert run.errors == []

            def read():
                try:
                    pause.responses.append(run.port.read())
                except BaseException as error:
                    pause.errors.append(error)

            caller = threading.Thread(target=read)
            pause.callers.append(caller)
            caller.start()
            assert pause.reached.wait(5)
            run.leave.set()
            _completed(run)
            assert len(run.errors) == 1
            cutoff = run.errors[0]
            assert isinstance(cutoff, BaseExceptionGroup)
            assert cutoff.message == "CONFIGURED_READINESS_READS_OPERATION_AND_CLEANUP_FAILED"
            assert len(cutoff.exceptions) == 2
            _fixed(cutoff.exceptions[0], "READ_CLEANUP_INCOMPLETE")
            _fixed(cutoff.exceptions[1], "OWNER_CLEANUP_INCOMPLETE")
            _dispatches(case)
            assert case.owner._thread.is_alive()
            assert case.owner.status().cleanup_complete is False
            assert case.proofs == 1 and case.query_count == 0
            assert case.release_attempts == []
            # Original check() notices stop even while its owner proof is
            # held. The K caller may already finish its own deferred close;
            # this cannot rewrite L's previously observed K cutoff.
            caller.join(5)
            assert not caller.is_alive()
            assert run.port.status().cleanup_complete is True
            assert case.read_disposals == case.read_engines
            # Only the test's actual proof barrier is released by this finally;
            # L has returned its fixed incomplete result and never retries.
        assert pause.responses == [] and len(pause.errors) == 1
        assert str(pause.errors[0]) == "READINESS_READ_STORE_UNAVAILABLE"
        case.owner._thread.join(8)
        assert not case.owner._thread.is_alive()
        _complete(case, run.port)
        assert run.errors == [cutoff]
        assert len(case.acquires) == len(case.releases) == 1
