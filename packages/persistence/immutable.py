"""Shared immutable-fact insert and comparison helpers."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import sqlalchemy as sa
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
        return True
    assert_immutable(table, identifier, existing, values)
    return False


def as_aware_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
