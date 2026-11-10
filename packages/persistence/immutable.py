"""Shared immutable-fact insert and comparison helpers."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Connection, RowMapping


class ImmutableFactConflict(RuntimeError):
    """A deterministic ID already exists with different fact content."""


def same_value(actual: Any, expected: Any) -> bool:
    if isinstance(expected, Decimal):
        return Decimal(str(actual)) == expected
    if isinstance(expected, datetime):
        if not isinstance(actual, datetime):
            return False
        normalized_actual = actual.replace(tzinfo=UTC) if actual.tzinfo is None else actual
        return normalized_actual.astimezone(UTC) == expected.astimezone(UTC)
    return bool(actual == expected)


def assert_immutable(
    table: sa.Table,
    identifier: str,
    actual: Mapping[str, Any] | RowMapping,
    expected: Mapping[str, Any],
) -> None:
    mismatches = [
        field
        for field, expected_value in expected.items()
        if not same_value(actual[field], expected_value)
    ]
    if mismatches:
        fields = ", ".join(sorted(mismatches))
        raise ImmutableFactConflict(
            f"{table.name} fact {identifier!r} conflicts in immutable fields: {fields}"
        )


def insert_or_verify(
    connection: Connection,
    table: sa.Table,
    key_name: str,
    values: dict[str, Any],
) -> bool:
    identifier = str(values[key_name])
    existing: RowMapping | None = (
        connection.execute(sa.select(table).where(table.c[key_name] == values[key_name]))
        .mappings()
        .one_or_none()
    )
    if existing is None:
        connection.execute(sa.insert(table).values(**values))
        persisted = (
            connection.execute(sa.select(table).where(table.c[key_name] == values[key_name]))
            .mappings()
            .one()
        )
        assert_immutable(table, identifier, persisted, values)
        return True
    assert_immutable(table, identifier, existing, values)
    return False


def row_for_primary_key(
    connection: Connection,
    table: sa.Table,
    key_values: Mapping[str, Any],
) -> RowMapping:
    """Return one immutable fact or explain a competing uniqueness conflict."""

    predicate = sa.and_(*(table.c[key_name] == key for key_name, key in key_values.items()))
    existing = connection.execute(sa.select(table).where(predicate)).mappings().one_or_none()
    if existing is None:
        identifier = ",".join(f"{name}={value}" for name, value in key_values.items())
        raise ImmutableFactConflict(
            f"{table.name} rejected fact {identifier!r} through another uniqueness invariant"
        )
    return existing


def insert_or_verify_atomic(
    connection: Connection,
    table: sa.Table,
    values: Mapping[str, Any],
) -> bool:
    """Atomically insert an immutable fact or verify an identical retry.

    The dialect-specific conflict clause closes the select-then-insert race.
    Exact read-back comparison also catches conflicts through secondary unique
    constraints instead of treating them as successful idempotent retries.
    """

    payload = dict(values)
    key_values = {column.name: payload[column.name] for column in table.primary_key.columns}
    dialect = connection.dialect.name
    if dialect == "postgresql":
        statement = (
            postgresql_insert(table)
            .values(**payload)
            .on_conflict_do_nothing()
            .returning(sa.literal(True))
        )
    elif dialect == "sqlite":
        statement = (
            sqlite_insert(table)
            .values(**payload)
            .on_conflict_do_nothing()
            .returning(sa.literal(True))
        )
    else:
        raise RuntimeError(f"immutable facts do not support SQL dialect {dialect!r}")
    inserted = connection.execute(statement).scalar_one_or_none() is not None
    existing = row_for_primary_key(connection, table, key_values)
    identifier = ",".join(f"{name}={value}" for name, value in key_values.items())
    assert_immutable(table, identifier, existing, payload)
    return inserted


def as_aware_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
