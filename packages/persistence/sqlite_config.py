"""SQLite connection invariants shared by local and test database engines."""

from __future__ import annotations

import re

from sqlalchemy import Engine, event
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import ConnectionPoolEntry


class ResearchSQLiteConfigurationError(SQLAlchemyError):
    """The explicitly selected research SQLite durability policy is unavailable."""


def _supports_research_wal(version: str) -> bool:
    """Admit the fixed releases documented at https://sqlite.org/wal.html."""

    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        return False
    parts = tuple(int(part) for part in version.split("."))
    return (
        parts >= (3, 51, 3)
        or (parts[:2] == (3, 50) and parts[2] >= 7)
        or (parts[:2] == (3, 44) and parts[2] >= 6)
    )


def _enable_research_wal(
    dbapi_connection: DBAPIConnection,
    _connection_record: ConnectionPoolEntry,
) -> None:
    cursor = dbapi_connection.cursor()
    try:
        # The actual main filename also distinguishes SQLite URI memory databases.
        cursor.execute("PRAGMA database_list")
        main = next((row for row in cursor.fetchall() if row[1] == "main"), None)
        if main is None:
            raise ResearchSQLiteConfigurationError("SQLite main database is unavailable")
        if not main[2]:
            return
        cursor.execute("SELECT sqlite_version()")
        version = cursor.fetchone()
        if version is None or not _supports_research_wal(str(version[0])):
            raise ResearchSQLiteConfigurationError("SQLite runtime does not support research WAL")
        cursor.execute("PRAGMA journal_mode=WAL")
        mode = cursor.fetchone()
        if mode is None or str(mode[0]).lower() != "wal":
            raise ResearchSQLiteConfigurationError("SQLite research WAL mode is unavailable")
        cursor.execute("PRAGMA synchronous=FULL")
        cursor.execute("PRAGMA synchronous")
        synchronous = cursor.fetchone()
        if synchronous is None or synchronous[0] != 2:
            raise ResearchSQLiteConfigurationError("SQLite research FULL synchronization failed")
        cursor.execute("PRAGMA foreign_keys")
        foreign_keys = cursor.fetchone()
        if foreign_keys is None or foreign_keys[0] != 1:
            raise ResearchSQLiteConfigurationError("SQLite research foreign keys are unavailable")
    finally:
        cursor.close()


def _enable_foreign_keys(
    dbapi_connection: DBAPIConnection,
    _connection_record: ConnectionPoolEntry,
) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


def enforce_sqlite_foreign_keys(engine: Engine) -> Engine:
    """Enable SQLite's per-connection foreign-key enforcement before first use."""

    if engine.dialect.name == "sqlite":
        event.listen(engine, "connect", _enable_foreign_keys)
    return engine


def configure_research_sqlite(engine: Engine) -> Engine:
    """Require WAL/FULL on each new file-backed SQLite research connection.

    Call before first use, after foreign-key enforcement is installed. The caller
    selects a local filesystem and coordinates any first conversion. Memory and
    non-SQLite engines retain their original behavior. Busy timeout and automatic
    checkpoint settings are unchanged.
    """

    if engine.dialect.name == "sqlite":
        event.listen(engine, "connect", _enable_research_wal)
    return engine
