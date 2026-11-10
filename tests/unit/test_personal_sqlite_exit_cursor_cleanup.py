"""Opt-in SQLite cursor ownership, without any account or financial protocol.

Each effect case owns a fresh database, Engine and independent native writer
probe. Original faults and tracebacks stay alive through the probe. No failure
cursor/connection rescue, traceback clearing or GC is used in those cases.
"""

import gc
import sqlite3
import sys
import weakref
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy.engine.base import ExceptionContextImpl
from sqlalchemy.pool import NullPool

from packages.persistence import sqlite_exit_cursor_cleanup as policy

_ENGINE = "^SQLITE_EXIT_CURSOR_CLEANUP_ENGINE_REQUIRED$"
_CHANGED = "^SQLITE_EXIT_CURSOR_CLEANUP_CONFIGURATION_CHANGED$"


def _writer_probe(path):
    """Own only this new probe's resources; never touch the failed connection."""
    connection = sqlite3.connect(path, timeout=0, isolation_level=None)
    cursor = connection.cursor()
    began = False
    code = None
    try:
        try:
            cursor.execute("BEGIN IMMEDIATE")
            began = True
        except sqlite3.OperationalError as error:
            code = error.sqlite_errorcode
        cursor.execute("SELECT id, value FROM cleanup_values ORDER BY id")
        rows = tuple(cursor.fetchall())
        return began, code, rows
    finally:
        try:
            if began:
                connection.rollback()
        finally:
            try:
                cursor.close()
            finally:
                connection.close()


@contextmanager
def _case(tmp_path, monkeypatch, *, close_fault=None):
    path = tmp_path / "fresh-exit-cleanup.sqlite3"
    engine = sa.create_engine(
        sa.URL.create("sqlite+pysqlite", database=str(path)),
        poolclass=NullPool,
        connect_args={"timeout": 0},
    )
    metadata = sa.MetaData()
    table = sa.Table(
        "cleanup_values",
        metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("value", sa.String, nullable=False),
    )
    value = SimpleNamespace(
        path=path,
        engine=engine,
        table=table,
        primary=None,
        error=None,
        connection=None,
        raise_at_event=False,
        insert_events=0,
        close_attempts=0,
        close_returns=0,
        cleanup=RuntimeError("native close boundary fault"),
        original_errors=[],
        before_flags=[],
        after_flags=[],
        invalidations=[],
        disposals=0,
        commits=0,
        rollbacks=0,
    )
    original_close = policy._close_cursor

    def close_cursor(cursor):
        assert type(cursor) is sqlite3.Cursor
        assert type(cursor.connection) is sqlite3.Connection
        value.close_attempts += 1
        if close_fault == "before":
            raise value.cleanup
        returned = original_close(cursor)
        value.close_returns += 1
        if close_fault == "after":
            raise value.cleanup
        return returned

    def before_policy(context):
        assert context.engine is engine
        value.original_errors.append(context.original_exception)
        value.before_flags.append((context.is_disconnect, context.invalidate_pool_on_disconnect))

    def after_policy(context):
        assert context.engine is engine
        value.after_flags.append((context.is_disconnect, context.invalidate_pool_on_disconnect))

    def after_sql(connection, cursor, statement, parameters, context, executemany):
        if context.compiled is not None and context.compiled.statement.is_insert:
            assert connection.engine is engine and type(cursor) is sqlite3.Cursor
            value.insert_events += 1
            if value.raise_at_event:
                raise value.primary

    def invalidated(connection, record, error):
        value.invalidations.append(error)

    def disposed(actual):
        assert actual is engine
        value.disposals += 1

    def committed(connection):
        value.commits += 1

    def rolled_back(connection):
        value.rollbacks += 1

    registered = []
    primary = None
    with monkeypatch.context() as patch:
        # An explicitly selected private close-fault seam, never a replacement
        # SQLAlchemy method, cursor or successful financial protocol.
        patch.setattr(policy, "_close_cursor", close_cursor)
        try:
            sa.event.listen(engine, "handle_error", before_policy)
            registered.append((engine, "handle_error", before_policy))
            assert policy.configure_sqlite_exit_cursor_cleanup(engine) is engine
            sa.event.listen(engine, "handle_error", after_policy)
            registered.append((engine, "handle_error", after_policy))
            with engine.begin() as connection:
                metadata.create_all(connection)
            for target, name, callback in (
                (engine, "after_cursor_execute", after_sql),
                (engine.pool, "invalidate", invalidated),
                (engine, "engine_disposed", disposed),
                (engine, "commit", committed),
                (engine, "rollback", rolled_back),
            ):
                sa.event.listen(target, name, callback)
                registered.append((target, name, callback))
            yield value
        except BaseException as error:
            primary = error
            raise
        finally:
            errors = []
            for target, name, callback in reversed(registered):
                try:
                    sa.event.remove(target, name, callback)
                except BaseException as error:
                    errors.append(error)
            try:
                engine.dispose()  # Only the fixture owns Engine disposal.
            except BaseException as error:
                errors.append(error)
            if errors:
                if primary is not None:
                    errors.insert(0, primary)
                raise BaseExceptionGroup("cleanup policy test and fixture cleanup failed", errors)


def _execute(case, *, primary=None, returning=True, consume=False, bad_value=False):
    case.primary = primary
    case.raise_at_event = primary is not None and not consume
    try:
        with case.engine.begin() as connection:
            case.connection = connection
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            statement = sa.insert(case.table).values(id=1, value=None if bad_value else "fresh")
            if returning:
                statement = statement.returning(case.table.c.id)
            result = connection.execute(statement)
            if returning:
                assert result.scalar_one() == 1
                assert result.closed
            if primary is not None:
                raise primary
    except BaseException as error:
        case.error = error
    assert case.connection is not None and case.connection.closed
    assert case.disposals == 0


def test_handler_does_not_retain_an_unused_engine(tmp_path):
    # This isolated registration-lifetime check precedes all fault cases. It has
    # no Connection, fault, traceback or failure cursor to repair or collect.
    def configured_handler():
        engine = sa.create_engine(
            sa.URL.create("sqlite+pysqlite", database=str(tmp_path / "unused.sqlite3")),
            poolclass=NullPool,
        )
        assert policy.configure_sqlite_exit_cursor_cleanup(engine) is engine
        registration = getattr(engine, policy._MARKER)
        assert type(registration.engine) is weakref.ReferenceType
        assert type(registration.dialect) is weakref.ReferenceType
        assert registration.engine() is engine
        assert registration.dialect() is engine.dialect
        return weakref.ref(engine), registration.handler

    engine_reference, retained_handler = configured_handler()
    gc.collect()
    assert engine_reference() is None
    assert callable(retained_handler)
    assert not (tmp_path / "unused.sqlite3").exists()


@pytest.mark.parametrize("kind", ["keyboard", "system"])
def test_pending_returning_exit_keeps_original_fault_and_releases_native_writer(
    tmp_path, monkeypatch, kind
):
    with _case(tmp_path, monkeypatch) as case:
        primary = (
            KeyboardInterrupt("original pending exit")
            if kind == "keyboard"
            else SystemExit("original pending exit")
        )
        _execute(case, primary=primary)
        assert case.error is primary and primary.__traceback__ is not None
        assert case.original_errors == [primary]
        assert case.before_flags == case.after_flags == [(True, False)]
        assert case.invalidations == [primary]
        assert case.close_attempts == case.close_returns == 1
        assert case.insert_events == case.rollbacks == 1 and case.commits == 0
        assert _writer_probe(case.path) == (True, None, ())
        assert primary.__traceback__ is not None and case.disposals == 0


def test_successful_original_commit_is_untouched(tmp_path, monkeypatch):
    with _case(tmp_path, monkeypatch) as case:
        _execute(case)
        assert case.error is None
        assert case.original_errors == case.before_flags == case.after_flags == []
        assert case.invalidations == [] and case.close_attempts == case.close_returns == 0
        assert case.commits == 1 and case.rollbacks == 0
        assert _writer_probe(case.path) == (True, None, ((1, "fresh"),))


def test_ordinary_event_exception_keeps_original_cursor_and_rollback_ownership(
    tmp_path, monkeypatch
):
    with _case(tmp_path, monkeypatch) as case:
        primary = RuntimeError("original ordinary event failure")
        _execute(case, primary=primary)
        assert case.error is primary and primary.__traceback__ is not None
        assert case.original_errors == [primary]
        assert case.before_flags == case.after_flags == [(False, True)]
        assert case.invalidations == [] and case.close_attempts == case.close_returns == 0
        assert case.rollbacks == 1 and case.commits == 0
        assert _writer_probe(case.path) == (True, None, ())


def test_ordinary_timeout_keeps_upstream_disconnect_behavior_without_policy_close(
    tmp_path, monkeypatch
):
    # SQLAlchemy's selected classifier differs with optional greenlet support.
    # Capture that original policy, independently of the new cleanup handler.
    # Our policy still closes only actual non-Exception BaseExceptions.
    with _case(tmp_path, monkeypatch) as case:
        primary = TimeoutError("original ordinary timeout")
        upstream_exit = sa.util.is_exit_exception(primary)
        assert type(upstream_exit) is bool
        _execute(case, primary=primary)
        assert case.error is primary and primary.__traceback__ is not None
        assert case.original_errors == [primary]
        assert case.before_flags == case.after_flags == [(upstream_exit, not upstream_exit)]
        assert case.invalidations == ([primary] if upstream_exit else [])
        assert case.close_attempts == case.close_returns == 0
        assert case.rollbacks == 1 and case.commits == 0
        expected = (False, sqlite3.SQLITE_BUSY, ()) if upstream_exit else (True, None, ())
        assert _writer_probe(case.path) == expected


def test_native_dbapi_error_keeps_original_sqlalchemy_wrapper(tmp_path, monkeypatch):
    with _case(tmp_path, monkeypatch) as case:
        _execute(case, bad_value=True)
        assert type(case.error) is sa.exc.IntegrityError
        assert type(case.error.orig) is sqlite3.IntegrityError
        assert case.original_errors == [case.error.orig]
        assert case.error.__traceback__ is not None and case.error.orig.__traceback__ is not None
        assert case.before_flags == case.after_flags == [(False, True)]
        assert case.invalidations == [] and case.close_attempts == case.close_returns == 0
        assert case.insert_events == 0 and case.rollbacks == 1 and case.commits == 0
        assert _writer_probe(case.path) == (True, None, ())


def test_no_returning_exit_still_closes_once_before_original_invalidation(tmp_path, monkeypatch):
    with _case(tmp_path, monkeypatch) as case:
        primary = KeyboardInterrupt("original no-returning exit")
        _execute(case, primary=primary, returning=False)
        assert case.error is primary and primary.__traceback__ is not None
        assert case.before_flags == case.after_flags == [(True, False)]
        assert case.invalidations == [primary]
        assert case.close_attempts == case.close_returns == 1
        assert _writer_probe(case.path) == (True, None, ())


def test_consumed_result_then_exit_never_enters_the_error_handler(tmp_path, monkeypatch):
    with _case(tmp_path, monkeypatch) as case:
        primary = KeyboardInterrupt("original post-result exit")
        _execute(case, primary=primary, consume=True)
        assert case.error is primary and primary.__traceback__ is not None
        assert case.original_errors == case.before_flags == case.after_flags == []
        assert case.invalidations == [] and case.close_attempts == case.close_returns == 0
        assert case.rollbacks == 1 and case.commits == 0
        assert _writer_probe(case.path) == (True, None, ())


@pytest.mark.parametrize("phase", ["before", "after"])
def test_real_close_boundary_failure_preserves_order_and_honest_writer_state(
    tmp_path, monkeypatch, phase
):
    with _case(tmp_path, monkeypatch, close_fault=phase) as case:
        primary = KeyboardInterrupt("original retained primary")
        _execute(case, primary=primary)
        assert type(case.error) is BaseExceptionGroup
        assert case.error.message == "sqlite original exit and cursor cleanup failed"
        assert len(case.error.exceptions) == 2
        assert case.error.exceptions[0] is primary
        assert case.error.exceptions[1] is case.cleanup
        assert primary.__traceback__ is not None and case.cleanup.__traceback__ is not None
        assert case.original_errors == [primary]
        assert case.before_flags == [(True, False)] and case.after_flags == []
        assert case.invalidations == [primary]
        assert case.close_attempts == 1 and case.close_returns == int(phase == "after")
        assert case.rollbacks == 1 and case.commits == 0
        expected = (False, sqlite3.SQLITE_BUSY, ()) if phase == "before" else (True, None, ())
        assert _writer_probe(case.path) == expected
        # Retain both complete faults through the independent probe; no retry or
        # closing the failed cursor is used to turn the before-fault case green.
        assert case.error.exceptions[0] is primary and case.disposals == 0


def test_an_unconfigured_engine_keeps_original_pending_cursor_behavior(tmp_path, monkeypatch):
    with _case(tmp_path, monkeypatch) as configured:
        path = tmp_path / "unconfigured.sqlite3"
        engine = sa.create_engine(
            sa.URL.create("sqlite+pysqlite", database=str(path)),
            poolclass=NullPool,
            connect_args={"timeout": 0},
        )
        primary = KeyboardInterrupt("unconfigured original exit")
        caught = None

        def after_sql(connection, cursor, statement, parameters, context, executemany):
            if context.compiled is not None and context.compiled.statement.is_insert:
                raise primary

        try:
            with engine.begin() as connection:
                configured.table.metadata.create_all(connection)
            sa.event.listen(engine, "after_cursor_execute", after_sql)
            try:
                try:
                    with engine.begin() as connection:
                        connection.exec_driver_sql("BEGIN IMMEDIATE")
                        connection.execute(
                            sa.insert(configured.table)
                            .values(id=1, value="fresh")
                            .returning(configured.table.c.id)
                        )
                except BaseException as error:
                    caught = error
                assert caught is primary and primary.__traceback__ is not None
                assert connection.closed
                assert not hasattr(engine, policy._MARKER)
                assert configured.close_attempts == configured.close_returns == 0
                assert _writer_probe(path) == (False, sqlite3.SQLITE_BUSY, ())
                assert _writer_probe(configured.path) == (True, None, ())
            finally:
                sa.event.remove(engine, "after_cursor_execute", after_sql)
        finally:
            engine.dispose()  # Own only this unconfigured test Engine.


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (KeyboardInterrupt("native exit"), True),
        (SystemExit("native exit"), True),
        (BaseException("native base"), True),
        (RuntimeError("ordinary"), False),
        (TimeoutError("ordinary timeout"), False),
        (sqlite3.OperationalError("native ordinary"), False),
        (ExceptionGroup("ordinary group", [RuntimeError("ordinary")]), False),
        (BaseExceptionGroup("exit group", [KeyboardInterrupt("exit")]), True),
        (object(), False),
    ],
)
def test_policy_classifier_uses_actual_exception_type(error, expected):
    assert policy._is_exit_exception(error) is expected


@pytest.mark.parametrize("kind", ["base", "ordinary", "foreign"])
def test_pure_classifier_never_invokes_an_instance_class_hook(kind):
    # Original SQLAlchemy has a separate isinstance-based classifier before our
    # handler; this is explicitly our pure policy boundary, not end-to-end proof
    # for a hostile exception through that unchanged upstream classifier.
    calls = []

    def forbidden(self):
        calls.append("class")
        raise AssertionError("instance class hook was invoked")

    class HostileBase(BaseException):
        __class__ = property(forbidden)

    class HostileOrdinary(Exception):
        __class__ = property(forbidden)

    class HostileForeign:
        __class__ = property(forbidden)

    error = {"base": HostileBase, "ordinary": HostileOrdinary, "foreign": HostileForeign}[kind]()
    assert policy._is_exit_exception(error) is (kind == "base")
    assert calls == []


@contextmanager
def _unused_engine(tmp_path, *, name="unused.sqlite3"):
    path = tmp_path / name
    engine = sa.create_engine(
        sa.URL.create("sqlite+pysqlite", database=str(path)),
        poolclass=NullPool,
    )
    calls = []

    def connected(connection):
        calls.append("connect")

    sa.event.listen(engine, "engine_connect", connected)
    try:
        yield engine, path, calls
    finally:
        sa.event.remove(engine, "engine_connect", connected)
        engine.dispose()


def test_explicit_configuration_is_data_only_idempotent_and_engine_owned(tmp_path):
    with _unused_engine(tmp_path) as (engine, path, calls):
        assert not hasattr(engine, policy._MARKER)
        assert policy.configure_sqlite_exit_cursor_cleanup(engine) is engine
        registration = getattr(engine, policy._MARKER)
        assert registration.engine() is engine
        assert registration.dialect() is engine.dialect
        assert sa.event.contains(engine, "handle_error", registration.handler)
        for _ in range(3):
            assert policy.configure_sqlite_exit_cursor_cleanup(engine) is engine
            assert getattr(engine, policy._MARKER) is registration
        assert calls == [] and not path.exists()


@pytest.mark.parametrize("bad", [None, True, object(), "sqlite"])
def test_non_engine_configuration_denies_without_adapting_or_connecting(bad):
    with pytest.raises(ValueError, match=_ENGINE):
        policy.configure_sqlite_exit_cursor_cleanup(bad)


def test_foreign_engine_getters_are_not_borrowed():
    calls = []

    class Foreign:
        def __getattribute__(self, name):
            calls.append(name)
            raise AssertionError("foreign Engine getter was invoked")

    with pytest.raises(ValueError, match=_ENGINE):
        policy.configure_sqlite_exit_cursor_cleanup(Foreign())
    assert calls == []


@pytest.mark.parametrize("kind", ["missing", "foreign", "sqlite-shaped"])
def test_non_native_sqlite_dialect_denies_before_io(tmp_path, kind):
    with _unused_engine(tmp_path) as (engine, path, calls):
        original = engine.dialect
        engine.dialect = (
            None
            if kind == "missing"
            else SimpleNamespace(name="postgresql", driver="psycopg")
            if kind == "foreign"
            else SimpleNamespace(name="sqlite", driver="pysqlite")
        )
        try:
            with pytest.raises(ValueError, match=_ENGINE):
                policy.configure_sqlite_exit_cursor_cleanup(engine)
            assert calls == [] and not path.exists()
        finally:
            engine.dialect = original  # Only restore this admission fixture.


@pytest.mark.parametrize("kind", ["deleted", "none", "foreign"])
def test_changed_registration_marker_denies_without_reinstall_or_io(tmp_path, kind):
    with _unused_engine(tmp_path) as (engine, path, calls):
        policy.configure_sqlite_exit_cursor_cleanup(engine)
        registration = getattr(engine, policy._MARKER)
        if kind == "deleted":
            delattr(engine, policy._MARKER)
        else:
            setattr(engine, policy._MARKER, None if kind == "none" else object())
        with pytest.raises(ValueError, match=_CHANGED):
            policy.configure_sqlite_exit_cursor_cleanup(engine)
        assert sa.event.contains(engine, "handle_error", registration.handler)
        assert calls == [] and not path.exists()


def test_removed_owned_handler_is_not_automatically_reinstalled(tmp_path):
    with _unused_engine(tmp_path) as (engine, path, calls):
        policy.configure_sqlite_exit_cursor_cleanup(engine)
        registration = getattr(engine, policy._MARKER)
        sa.event.remove(engine, "handle_error", registration.handler)
        with pytest.raises(ValueError, match=_CHANGED):
            policy.configure_sqlite_exit_cursor_cleanup(engine)
        assert not sa.event.contains(engine, "handle_error", registration.handler)
        assert getattr(engine, policy._MARKER) is registration
        assert calls == [] and not path.exists()


def test_another_engines_registration_cannot_be_adopted(tmp_path):
    with (
        _unused_engine(tmp_path, name="one.sqlite3") as (first, first_path, first_calls),
        _unused_engine(tmp_path, name="two.sqlite3") as (second, second_path, second_calls),
    ):
        policy.configure_sqlite_exit_cursor_cleanup(first)
        foreign = getattr(first, policy._MARKER)
        setattr(second, policy._MARKER, foreign)
        with pytest.raises(ValueError, match=_CHANGED):
            policy.configure_sqlite_exit_cursor_cleanup(second)
        assert getattr(second, policy._MARKER) is foreign
        assert not sa.event.contains(second, "handle_error", foreign.handler)
        assert first_calls == second_calls == []
        assert not first_path.exists() and not second_path.exists()


@pytest.mark.parametrize("field", ["engine", "dialect", "handler"])
def test_corrupt_registration_leaf_denies_without_borrowing_it(tmp_path, field):
    with _unused_engine(tmp_path) as (engine, path, calls):
        policy.configure_sqlite_exit_cursor_cleanup(engine)
        registration = getattr(engine, policy._MARKER)
        substituted = []

        def forbidden(*args, **kwargs):
            substituted.append(field)
            raise AssertionError("foreign registration callback was invoked")

        object.__setattr__(registration, field, forbidden)
        with pytest.raises(ValueError, match=_CHANGED):
            policy.configure_sqlite_exit_cursor_cleanup(engine)
        assert substituted == []
        assert calls == [] and not path.exists()


def test_changed_original_dialect_binding_denies_before_io(tmp_path):
    with _unused_engine(tmp_path) as (engine, path, calls):
        policy.configure_sqlite_exit_cursor_cleanup(engine)
        original = engine.dialect
        other = sa.create_engine("sqlite+pysqlite:///:memory:", poolclass=NullPool)
        try:
            engine.dialect = other.dialect
            with pytest.raises(ValueError, match=_CHANGED):
                policy.configure_sqlite_exit_cursor_cleanup(engine)
            assert calls == [] and not path.exists()
        finally:
            engine.dialect = original
            other.dispose()


def test_lost_independent_registration_entry_cannot_reinstall_from_marker(tmp_path):
    with _unused_engine(tmp_path) as (engine, path, calls):
        policy.configure_sqlite_exit_cursor_cleanup(engine)
        registration = getattr(engine, policy._MARKER)
        del policy._REGISTRATIONS[engine]
        with pytest.raises(ValueError, match=_CHANGED):
            policy.configure_sqlite_exit_cursor_cleanup(engine)
        assert getattr(engine, policy._MARKER) is registration
        assert sa.event.contains(engine, "handle_error", registration.handler)
        assert calls == [] and not path.exists()


def test_interrupted_listener_registration_retains_attempt_and_does_not_retry(tmp_path):
    with _unused_engine(tmp_path) as (engine, path, calls):
        primary = KeyboardInterrupt("original registration interruption")
        original_code = sa.event.listen.__code__
        observed = []
        previous_profile = sys.getprofile()

        def observe(frame, event, arg):
            if (
                event == "call"
                and frame.f_code is original_code
                and frame.f_locals["target"] is engine
                and frame.f_locals["identifier"] == "handle_error"
            ):
                observed.append("original listener entry")
                raise primary
            if previous_profile is not None:
                previous_profile(frame, event, arg)

        sys.setprofile(observe)
        try:
            with pytest.raises(KeyboardInterrupt) as caught:
                policy.configure_sqlite_exit_cursor_cleanup(engine)
        finally:
            sys.setprofile(previous_profile)
        assert caught.value is primary and primary.__traceback__ is not None
        assert observed == ["original listener entry"]
        registration = getattr(engine, policy._MARKER)
        assert policy._REGISTRATIONS[engine] is registration
        assert not sa.event.contains(engine, "handle_error", registration.handler)
        with pytest.raises(ValueError, match=_CHANGED):
            policy.configure_sqlite_exit_cursor_cleanup(engine)
        assert not sa.event.contains(engine, "handle_error", registration.handler)
        assert calls == [] and not path.exists()


@pytest.mark.parametrize(
    "kind", ["foreign", "missing", "disconnect", "non-native-flag", "other-engine"]
)
def test_unsupported_handler_context_delegates_without_cursor_or_connection_io(
    tmp_path,
    monkeypatch,
    kind,
):
    # Exact-class but incomplete carriers test denial/delegation only. They are
    # not fabricated positive execution contexts or successful SQL operations.
    with _unused_engine(tmp_path) as (engine, path, calls):
        policy.configure_sqlite_exit_cursor_cleanup(engine)
        handler = getattr(engine, policy._MARKER).handler
        close_calls = []
        getters = []

        class Foreign:
            def __getattribute__(self, name):
                getters.append(name)
                raise AssertionError("unsupported context getter was borrowed")

        def forbidden(cursor):
            close_calls.append("close")
            raise AssertionError("unsupported cursor was closed")

        context = object.__new__(ExceptionContextImpl)
        context.engine = engine
        context.dialect = engine.dialect
        context.connection = None
        context.execution_context = None
        context.original_exception = KeyboardInterrupt("unsupported context")
        context.is_disconnect = True
        context.invalidate_pool_on_disconnect = False
        if kind == "foreign":
            context = Foreign()
        elif kind == "disconnect":
            context.is_disconnect = False
        elif kind == "non-native-flag":
            context.invalidate_pool_on_disconnect = 0
        elif kind == "other-engine":
            context.engine = object()
        with monkeypatch.context() as patch:
            patch.setattr(policy, "_close_cursor", forbidden)
            assert handler(context) is None
        assert close_calls == getters == calls == []
        assert not path.exists()
