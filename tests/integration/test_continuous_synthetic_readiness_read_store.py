"""Fresh original owner proofs and a separate real SQLite read-only query body.

SQLAlchemy events observe the genuine connection/query/disposal, including
test-owned barriers. The pinned owner and SQL read methods are never replaced.
These cases exercise no HTTP, provider, retained history or trading authority.
"""

import sqlite3
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import anyio
import pytest
import sqlalchemy as sa
from sqlalchemy import Engine, event
from sqlalchemy.pool import NullPool

from apps.api import readiness_read_store as read_module
from apps.trader import continuous_readiness_owner as owner_module
from packages.domain.continuous_selection_contracts import ContinuousSelectionSnapshot
from packages.persistence.continuous_selection_read_model import ContinuousSelectionReadError
from tests.integration.test_continuous_synthetic_configured_readiness import _case
from tests.integration.test_continuous_synthetic_readiness_http import _paused_original_proof


@contextmanager
def _read_case(tmp_path, monkeypatch, *, seed=True):
    # G's former dispose forwarding counter must not weaken K's original-method
    # pins. Retain real disposal and record its original event instead.
    dispose = Engine.dispose
    create_engine = sa.create_engine
    uuid4 = read_module.uuid4
    case = None
    listener_installed = False

    def disposed(engine):
        if engine is case.account_engine:
            label = "dispose-account"
        elif engine is case.venue_engine:
            label = "dispose-venue"
        elif engine in case.read_engines:
            case.read_disposals.append(engine)
            assert all(connection.closed for connection in case.query_connections)
            return
        else:
            return
        case.disposals.append(label)
        case.trace.append((label, threading.current_thread()))

    try:
        with _case(tmp_path, monkeypatch, seed=seed) as case:
            case.read_engines = []
            case.read_stores = []
            case.read_disposals = []
            case.query_connections = []
            case.query_threads = []
            case.read_ids = []
            case.query_count = 0
            case.capture_read_engine = False
            case.query_hook = None
            case.connect_hook = None
            case.allow_read_cleanup_failure = False
            monkeypatch.setattr(Engine, "dispose", dispose)
            event.listen(Engine, "engine_disposed", disposed)
            listener_installed = True

            def before_sql(connection, cursor, statement, parameters, context, executemany):
                if "FROM alembic_version" not in statement:
                    return
                case.query_count += 1
                case.query_connections.append(connection)
                case.query_threads.append(threading.current_thread())
                if case.query_hook is not None:
                    case.query_hook(connection, cursor)

            def engine_created(*args, **kwargs):
                engine = create_engine(*args, **kwargs)
                if case.capture_read_engine and threading.current_thread() is case.caller_thread:
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

            def fresh_uuid():
                value = uuid4()
                case.read_ids.append(value.hex)
                return value

            monkeypatch.setattr(sa, "create_engine", engine_created)
            monkeypatch.setattr(read_module, "uuid4", fresh_uuid)
            primary = None
            try:
                yield case
            except BaseException as error:
                primary = error
                raise
            finally:
                failures = []
                for store in case.read_stores:
                    try:
                        status = store.close()
                        assert status.busy is False
                        assert status.phase == "closed"
                        if case.allow_read_cleanup_failure:
                            assert status.cleanup_complete is False
                            assert status.cleanup_failure == "cleanup_failed"
                        else:
                            # Events prove disposal was reached; this requires its return.
                            assert status.cleanup_complete is True
                            assert status.cleanup_failure is None
                    except BaseException as error:
                        failures.append(error)
                if failures:
                    if primary is not None:
                        failures.insert(0, primary)
                    raise BaseExceptionGroup("read store and independent cleanup failed", failures)
        # G independently requires actual owner exit, returned cleanup, its one
        # original R1/release/head, both engine disposals and all financial facts.
    finally:
        if listener_installed:
            event.remove(Engine, "engine_disposed", disposed)


def _open(case):
    case.capture_read_engine = True
    try:
        store = read_module.open_readiness_read_store(case.owner)
    finally:
        case.capture_read_engine = False
    case.read_stores.append(store)
    assert len(case.read_engines) == 1
    assert case.read_engines[0] is not case.account_engine
    assert case.read_engines[0] is not case.venue_engine
    return store


@contextmanager
def _held_query(case, *, cursor_fault=False):
    pause = SimpleNamespace(
        reached=threading.Event(),
        release=threading.Event(),
        callers=[],
        results=[],
        errors=[],
        finished=threading.Event(),
    )

    def hold(connection, cursor):
        pause.reached.set()
        assert pause.release.wait(12), "test did not release original query barrier"
        if cursor_fault:
            # The unchanged original SQL now hits an actually closed DBAPI
            # cursor; the original reader must perform its own error handling.
            cursor.close()

    case.query_hook = hold
    primary = None
    try:
        yield pause
    except BaseException as error:
        primary = error
        raise
    finally:
        pause.release.set()
        failures = []
        for caller in pause.callers:
            try:
                caller.join(12)
                assert not caller.is_alive(), "actual read body did not finish"
            except BaseException as error:
                failures.append(error)
        case.query_hook = None
        if failures:
            if primary is not None:
                failures.insert(0, primary)
            raise BaseExceptionGroup("original query and barrier cleanup failed", failures)


def _read_in_thread(store, pause):
    def read():
        try:
            pause.results.append(store.read())
        except BaseException as error:
            pause.errors.append(error)
        finally:
            pause.finished.set()

    caller = threading.Thread(target=read)
    pause.callers.append(caller)
    caller.start()
    return caller


def _selected(case, snapshot):
    assert type(snapshot) is ContinuousSelectionSnapshot
    snapshot.__post_init__()
    assert snapshot.account_id == case.study.genesis.scope.account_id
    assert snapshot.state == "selected" and snapshot.verification == "row_integrity_only"
    assert snapshot.checkpoint.stream_id == case.study.genesis.scope.stream_id
    assert snapshot.checkpoint.sequence == 1
    assignment = case.study.assignment
    selection = snapshot.selection
    assert selection.generation == assignment.generation == 1
    assert selection.strategy_name == assignment.strategy.name
    assert selection.strategy_version == assignment.strategy.version
    assert selection.configuration_sha256 == assignment.configuration_sha256
    assert selection.instrument_symbols == assignment.instrument_symbols
    assert selection.policy_id == assignment.policy.policy_id
    assert selection.effective_at == assignment.effective_at
    assert selection.enabled_for_new_exposure is selection.live_authorized is False


def test_separate_readonly_store_runs_two_original_proofs_and_exact_selected_queries(
    tmp_path, monkeypatch
):
    with _read_case(tmp_path, monkeypatch) as case:
        assert case.owner.start().phase == "idle"
        store = _open(case)
        engine = case.read_engines[0]
        assert type(engine.pool) is NullPool
        assert store.status().phase == "open" and store.status().cleanup_complete is False
        caller_record = case.owner.store_binding()
        object.__setattr__(caller_record, "account_id", "valid-looking-foreign-account")
        first, second = store.read(), store.read()
        _selected(case, first)
        _selected(case, second)
        assert first == second and first is not second
        assert case.proofs == case.query_count == len(case.read_ids) == 2
        assert len(set(case.read_ids)) == 2
        assert all(len(value) == 32 for value in case.read_ids)
        assert all(connection.closed for connection in case.query_connections)
        with engine.connect() as connection:
            with pytest.raises(sa.exc.OperationalError) as raised:
                connection.exec_driver_sql(
                    "INSERT INTO personal_continuous_account_heads "
                    "SELECT * FROM personal_continuous_account_heads"
                )
            assert type(raised.value.orig) is sqlite3.OperationalError
            assert raised.value.orig.sqlite_errorcode == sqlite3.SQLITE_READONLY
            connection.rollback()
        closed = store.close()
        assert closed.phase == "closed" and closed.cleanup_complete is True
        assert case.read_disposals == [engine]
        assert case.owner.status().phase == "idle" and case.release_attempts == []
    assert case.owner.status().cleanup_complete is True


def test_no_read_engine_is_created_before_original_owner_start(tmp_path, monkeypatch):
    with _read_case(tmp_path, monkeypatch) as case:
        with pytest.raises(RuntimeError, match=r"^READINESS_READ_STORE_UNAVAILABLE$"):
            _open(case)
        assert case.read_engines == [] and case.trace == [] and case.acquires == []
        assert case.owner.start().phase == "idle"
        assert _open(case).close().cleanup_complete is True
        assert case.proofs == case.query_count == 0


def test_missing_phase_zero_denies_before_original_selection_query(tmp_path, monkeypatch):
    with _read_case(tmp_path, monkeypatch, seed=False) as case:
        assert case.owner.start().phase == "idle"
        store = _open(case)
        with pytest.raises(RuntimeError, match=r"^READINESS_READ_STORE_UNAVAILABLE$"):
            store.read()
        assert case.proofs == 1 and len(case.proof_errors) == 1
        assert case.query_count == 0 and len(case.read_ids) == 1


def test_retained_binding_after_owner_stop_cannot_authorize_a_read(tmp_path, monkeypatch):
    with _read_case(tmp_path, monkeypatch) as case:
        assert case.owner.start().phase == "idle"
        store = _open(case)
        binding = case.owner.store_binding()
        case.owner.stop()
        case.owner._thread.join(12)
        assert not case.owner._thread.is_alive()
        assert case.owner.status().cleanup_complete is True
        assert case.owner.store_binding() == binding
        with pytest.raises(RuntimeError, match=r"^READINESS_READ_STORE_UNAVAILABLE$"):
            store.read()
        assert case.proofs == case.query_count == 0
        assert len(case.acquires) == len(case.releases) == 1


def test_original_busy_owner_is_not_replaced_by_a_cached_proof(tmp_path, monkeypatch):
    with _read_case(tmp_path, monkeypatch) as case:
        assert case.owner.start().phase == "idle"
        store = _open(case)
        with _paused_original_proof(case, monkeypatch) as pause:

            def direct_check():
                try:
                    pause.responses.append(case.owner.check("independent-original-proof"))
                except BaseException as error:
                    pause.errors.append(error)

            caller = threading.Thread(target=direct_check)
            pause.callers.append(caller)
            caller.start()
            assert pause.reached.wait(5), "original proof did not reach controlled barrier"
            assert case.owner.status().busy is True
            with pytest.raises(RuntimeError, match=r"^READINESS_READ_STORE_UNAVAILABLE$"):
                store.read()
            assert case.proofs == 1 and case.query_count == 0 and len(case.read_ids) == 1
        assert pause.errors == [] and len(pause.responses) == 1


def test_real_owner_stop_during_sql_withholds_terminal_snapshot(tmp_path, monkeypatch):
    with _read_case(tmp_path, monkeypatch) as case:
        assert case.owner.start().phase == "idle"
        store = _open(case)

        def stop_after_proof(connection, cursor):
            assert case.proofs == 1 and case.query_count == 1
            case.owner.stop()
            case.owner._thread.join(12)
            assert not case.owner._thread.is_alive()
            assert case.owner.status().cleanup_complete is True

        case.query_hook = stop_after_proof
        with pytest.raises(RuntimeError, match=r"^READINESS_READ_STORE_UNAVAILABLE$"):
            store.read()
        assert case.query_count == 1 and all(c.closed for c in case.query_connections)
        assert case.proofs == 1 and len(case.releases) == 1


def test_active_original_sql_retains_slot_until_deferred_close_finishes(tmp_path, monkeypatch):
    with _read_case(tmp_path, monkeypatch) as case:
        assert case.owner.start().phase == "idle"
        store = _open(case)
        with _held_query(case) as pause:
            caller = _read_in_thread(store, pause)
            assert pause.reached.wait(5)
            with pytest.raises(RuntimeError, match=r"^READINESS_READ_STORE_BUSY$"):
                store.read()
            closing = store.close()
            assert closing.phase == "closing" and closing.busy is True
            assert closing.cleanup_complete is False and case.read_disposals == []
            with pytest.raises(RuntimeError, match=r"^READINESS_READ_STORE_CLOSED$"):
                store.read()
            assert caller.is_alive() and case.proofs == case.query_count == 1
        assert pause.results == [] and len(pause.errors) == 1
        assert type(pause.errors[0]) is RuntimeError
        assert str(pause.errors[0]) == "READINESS_READ_STORE_CLOSED"
        assert store.status().cleanup_complete is True
        assert case.read_disposals == case.read_engines


def test_cancelled_async_waiter_does_not_release_the_actual_sql_slot(tmp_path, monkeypatch):
    with _read_case(tmp_path, monkeypatch) as case:
        assert case.owner.start().phase == "idle"
        store = _open(case)
        with _held_query(case) as pause:
            cancelled = []

            def original_body():
                pause.callers.append(threading.current_thread())
                try:
                    pause.results.append(store.read())
                except BaseException as error:
                    pause.errors.append(error)
                finally:
                    pause.finished.set()

            async def exercise():
                async with anyio.create_task_group() as tasks:

                    async def await_read():
                        try:
                            await anyio.to_thread.run_sync(original_body, abandon_on_cancel=True)
                        except BaseException as error:
                            if isinstance(error, anyio.get_cancelled_exc_class()):
                                cancelled.append(error)
                            raise

                    tasks.start_soon(await_read)
                    assert await anyio.to_thread.run_sync(pause.reached.wait, 5)
                    tasks.cancel_scope.cancel()
                assert len(cancelled) == 1 and not pause.finished.is_set()
                assert pause.callers[0].is_alive() and store.status().busy is True
                closed = store.close()
                assert closed.phase == "closing" and closed.cleanup_complete is False
                assert case.read_disposals == []

            anyio.run(exercise)
            assert not pause.finished.is_set() and case.read_disposals == []
        assert pause.finished.is_set() and pause.results == [] and len(pause.errors) == 1
        assert str(pause.errors[0]) == "READINESS_READ_STORE_CLOSED"
        assert store.status().cleanup_complete is True
        assert case.read_disposals == case.read_engines


@pytest.mark.parametrize("cleanup_fault", [False, True], ids=["query-only", "query-and-cleanup"])
def test_original_sql_failure_and_actual_deferred_cleanup_keep_order(
    tmp_path, monkeypatch, cleanup_fault
):
    with _read_case(tmp_path, monkeypatch) as case:
        assert case.owner.start().phase == "idle"
        store = _open(case)
        cleanup = RuntimeError("private controlled disposal event failure")

        def fail_after_disposal(engine):
            raise cleanup

        if cleanup_fault:
            event.listen(case.read_engines[0], "engine_disposed", fail_after_disposal)
            case.allow_read_cleanup_failure = True
        with _held_query(case, cursor_fault=True) as pause:
            _read_in_thread(store, pause)
            assert pause.reached.wait(5)
            assert store.close().cleanup_complete is False
            assert case.read_disposals == []
        assert pause.results == [] and len(pause.errors) == 1
        error = pause.errors[0]
        if cleanup_fault:
            assert isinstance(error, BaseExceptionGroup)
            assert len(error.exceptions) == 2 and error.exceptions[1] is cleanup
            primary = error.exceptions[0]
        else:
            primary = error
        assert type(primary) is ContinuousSelectionReadError
        assert str(primary) == "continuous selection metadata is unavailable or malformed"
        assert case.read_disposals == case.read_engines
        result = store.close()
        assert result.cleanup_complete is (not cleanup_fault)
        assert result.cleanup_failure == ("cleanup_failed" if cleanup_fault else None)
        assert case.proofs == case.query_count == 1


def test_changed_original_binding_after_full_proof_denies_before_query(tmp_path, monkeypatch):
    with _read_case(tmp_path, monkeypatch) as case:
        assert case.owner.start().phase == "idle"
        store = _open(case)
        verify = owner_module.verify_operational_schema
        original = case.owner._store_binding_values

        def changed_after_original(*args, **kwargs):
            result = verify(*args, **kwargs)
            case.owner._store_binding_values = ("different-incarnation", *original[1:])
            return result

        monkeypatch.setattr(owner_module, "verify_operational_schema", changed_after_original)
        try:
            with pytest.raises(RuntimeError, match=r"^READINESS_READ_STORE_BINDING_CHANGED$"):
                store.read()
            assert case.proofs == 1 and case.proof_errors == [] and case.query_count == 0
        finally:
            case.owner._store_binding_values = original


def test_failed_opening_rejects_actual_temp_namespace_and_disposes_once(tmp_path, monkeypatch):
    with _read_case(tmp_path, monkeypatch) as case:
        assert case.owner.start().phase == "idle"
        connected = []

        def temporary_namespace(connection, record):
            connection.execute("CREATE TEMP TABLE controlled_read_store_temp (value INTEGER)")
            connected.append(connection)

        case.connect_hook = temporary_namespace
        with pytest.raises(RuntimeError, match=r"^READINESS_READ_STORE_BINDING_CHANGED$"):
            _open(case)
        assert len(connected) == len(case.read_engines) == len(case.read_disposals) == 1
        assert case.read_stores == [] and case.proofs == case.query_count == 0
        with pytest.raises(sqlite3.ProgrammingError):
            connected[0].execute("SELECT 1")
        assert case.owner.status().phase == "idle" and case.release_attempts == []


def test_foreign_pool_is_never_invoked_during_original_owned_cleanup(tmp_path, monkeypatch):
    with _read_case(tmp_path, monkeypatch) as case:
        assert case.owner.start().phase == "idle"
        store = _open(case)
        engine = case.read_engines[0]
        original_pool = engine.pool
        calls = []

        class ForeignPool:
            def dispose(self):
                calls.append("foreign dispose")
                raise AssertionError("foreign pool must not be invoked")

            def recreate(self):
                calls.append("foreign recreate")
                raise AssertionError("foreign pool must not be invoked")

        engine.pool = ForeignPool()
        with pytest.raises(RuntimeError, match=r"^READINESS_READ_STORE_BINDING_CHANGED$"):
            store.read()
        assert case.proofs == case.query_count == 0 and calls == []
        with pytest.raises(RuntimeError, match=r"^READINESS_READ_STORE_BINDING_CHANGED$"):
            store.close()
        closed = store.status()
        assert calls == [] and case.read_disposals == [engine]
        assert type(engine.pool) is NullPool and engine.pool is not original_pool
        assert closed.phase == "closed"
        # The fixed primary guard failure coexists with genuinely returned
        # original cleanup; the foreign pool is never treated as owned.
        assert closed.cleanup_complete is True and closed.cleanup_failure is None
