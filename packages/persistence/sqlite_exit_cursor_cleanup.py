"""Opt-in SQLite exit-cursor finalization before original disconnect handling.

The caller configures a new Engine before first use; this module does not attest
its history. It owns only the failing native cursor close, never a transaction,
connection, Engine, retry or lease. Unsupported error contexts retain SQLAlchemy's
default behavior, without a new cleanup guarantee.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from types import FunctionType
from typing import TypeGuard
from weakref import ReferenceType, WeakKeyDictionary, ref

from sqlalchemy import Connection, Engine, event
from sqlalchemy.dialects.sqlite.base import SQLiteExecutionContext
from sqlalchemy.dialects.sqlite.pysqlite import SQLiteDialect_pysqlite
from sqlalchemy.engine.base import ExceptionContextImpl
from sqlalchemy.engine.interfaces import ExceptionContext
from sqlalchemy.pool.base import _ConnectionFairy

_UNSUPPORTED = "SQLITE_EXIT_CURSOR_CLEANUP_ENGINE_REQUIRED"
_CHANGED = "SQLITE_EXIT_CURSOR_CLEANUP_CONFIGURATION_CHANGED"
_GROUP = "sqlite original exit and cursor cleanup failed"
_MARKER = "_aqt_sqlite_exit_cursor_cleanup"
_CURSOR_CLOSE = sqlite3.Cursor.close


@dataclass(frozen=True, slots=True)
class _Registration:
    engine: ReferenceType[Engine]
    dialect: ReferenceType[SQLiteDialect_pysqlite]
    handler: Callable[[ExceptionContext], None]


# Neither values nor handler closures keep an Engine alive. The independent weak
# entry detects a deleted/foreign instance marker instead of reinstalling a hook.
_REGISTRATIONS: WeakKeyDictionary[Engine, _Registration] = WeakKeyDictionary()
_CONFIGURATION_LOCK = Lock()


def _is_exit_exception(error: object) -> TypeGuard[BaseException]:
    """Classify the actual type without consulting an instance __class__ hook."""
    kind = type(error)
    return issubclass(kind, BaseException) and not issubclass(kind, Exception)


def _close_cursor(cursor: sqlite3.Cursor) -> None:
    """The sole native close boundary; no fetch, SQL or transaction operation."""
    _CURSOR_CLOSE(cursor)


def _native_cursor(
    engine: Engine,
    dialect: SQLiteDialect_pysqlite,
    context: ExceptionContextImpl,
) -> sqlite3.Cursor | None:
    if (
        getattr(context, "engine", None) is not engine
        or getattr(context, "dialect", None) is not dialect
        or getattr(engine, "dialect", None) is not dialect
        or getattr(context, "is_disconnect", None) is not True
        or type(getattr(context, "invalidate_pool_on_disconnect", None)) is not bool
    ):
        return None
    connection = getattr(context, "connection", None)
    execution = getattr(context, "execution_context", None)
    if type(connection) is not Connection or type(execution) is not SQLiteExecutionContext:
        return None
    if (
        getattr(connection, "engine", None) is not engine
        or getattr(connection, "dialect", None) is not dialect
        or getattr(execution, "root_connection", None) is not connection
        or getattr(execution, "dialect", None) is not dialect
    ):
        return None
    # Read the existing proxy directly. Connection.connection could reconnect;
    # this policy must never invoke it or manufacture a replacement owner.
    proxy = getattr(execution, "_dbapi_connection", None)
    if (
        type(proxy) is not _ConnectionFairy
        or getattr(connection, "_dbapi_connection", None) is not proxy
    ):
        return None
    native = getattr(proxy, "dbapi_connection", None)
    cursor = getattr(execution, "cursor", None)
    if type(native) is not sqlite3.Connection or type(cursor) is not sqlite3.Cursor:
        return None
    if cursor.connection is not native:
        return None
    return cursor


def _make_handler(
    engine_reference: ReferenceType[Engine],
    dialect_reference: ReferenceType[SQLiteDialect_pysqlite],
) -> Callable[[ExceptionContext], None]:
    def handle_error(context: ExceptionContext) -> None:
        # ExceptionContext.cursor is not populated by the qualified installed
        # SQLAlchemy constructor. Admit its actual execution context instead.
        if type(context) is not ExceptionContextImpl:
            return None
        original = getattr(context, "original_exception", None)
        if not _is_exit_exception(original):
            return None
        engine, dialect = engine_reference(), dialect_reference()
        if type(engine) is not Engine or type(dialect) is not SQLiteDialect_pysqlite:
            return None
        cursor = _native_cursor(engine, dialect, context)
        if cursor is None:
            return None
        try:
            _close_cursor(cursor)
        except BaseException as cleanup:
            raise BaseExceptionGroup(_GROUP, [original, cleanup]) from None
        finally:
            del cursor
        # Default classification, primary identity, traceback, invalidation and
        # original context unwind remain SQLAlchemy's responsibility.
        return None

    return handle_error


def _supported_engine(engine: Engine) -> SQLiteDialect_pysqlite:
    if type(engine) is not Engine:
        raise ValueError(_UNSUPPORTED)
    dialect = getattr(engine, "dialect", None)
    if (
        type(dialect) is not SQLiteDialect_pysqlite
        or type(dialect.name) is not str
        or dialect.name != "sqlite"
        or type(dialect.driver) is not str
        or dialect.driver != "pysqlite"
        or dialect.execution_ctx_cls is not SQLiteExecutionContext
    ):
        raise ValueError(_UNSUPPORTED)
    return dialect


def configure_sqlite_exit_cursor_cleanup(engine: Engine) -> Engine:
    """Configure one caller-owned SQLite Engine before use, without opening it.

    Repeating an intact configuration is harmless. Removed listeners, missing or
    foreign markers and changed ownership deny; they are never repaired here.
    No statement, connection, transaction or Engine lifecycle is taken over.
    """
    dialect = _supported_engine(engine)
    with _CONFIGURATION_LOCK:
        registration = _REGISTRATIONS.get(engine)
        attributes = vars(engine)
        if registration is not None:
            if type(registration) is not _Registration:
                raise ValueError(_CHANGED)
            # Engine.__dict__ values are Any. Keep the marker opaque so an
            # identity comparison cannot narrow the registration to Any | None.
            marker: object = attributes.get(_MARKER)
            # Save native-type facts separately so static narrowing does not
            # erase the weak references' Engine/dialect type parameters.
            native_engine_reference = type(registration.engine) is ReferenceType
            native_dialect_reference = type(registration.dialect) is ReferenceType
            native_handler = type(registration.handler) is FunctionType
            if (
                marker is not registration
                or not native_engine_reference
                or not native_dialect_reference
                or registration.engine() is not engine
                or registration.dialect() is not dialect
                or not native_handler
                or not event.contains(engine, "handle_error", registration.handler)
            ):
                raise ValueError(_CHANGED)
            return engine
        if _MARKER in attributes:
            raise ValueError(_CHANGED)
        engine_reference, dialect_reference = ref(engine), ref(dialect)
        handler = _make_handler(engine_reference, dialect_reference)
        registration = _Registration(engine_reference, dialect_reference, handler)
        # Retain the attempted configuration before listener registration. A
        # partial failure remains visible and cannot cause an automatic retry.
        _REGISTRATIONS[engine] = registration
        attributes[_MARKER] = registration
        event.listen(engine, "handle_error", handler)
    return engine
