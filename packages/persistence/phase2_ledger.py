"""Canonical SQL persistence for Phase 2 ledger entries and postings."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from decimal import Decimal
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Connection, RowMapping

from packages.domain.canonical import canonical_json_text, canonical_persisted_decimal
from packages.domain.ledger_reducer import (
    LEDGER_REDUCER_CONTRACT_VERSION,
    CanonicalLedgerEntry,
    CanonicalLedgerPosting,
    LedgerEntryKind,
    LedgerReductionError,
)
from packages.persistence.immutable import (
    ImmutableFactConflict,
    as_aware_utc,
    assert_immutable,
    insert_or_verify_atomic,
    same_value,
)
from packages.persistence.schema import phase2_ledger_entries, phase2_ledger_postings

PHASE2_LEDGER_PERSISTENCE_VERSION = "phase2-canonical-ledger-v2"
LedgerRow = Mapping[str, object] | RowMapping


class Phase2LedgerPersistenceError(LedgerReductionError):
    """A persisted Phase 2 ledger fact is malformed or unauthenticated."""


def _required_text(value: object, field_name: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise Phase2LedgerPersistenceError(
            f"persisted Phase 2 ledger {field_name} must be non-empty trimmed text"
        )
    return value


def _optional_text(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _required_text(value, field_name)


def _required_integer(value: object, field_name: str) -> int:
    if type(value) is not int or value <= 0:
        raise Phase2LedgerPersistenceError(
            f"persisted Phase 2 ledger {field_name} must be a positive integer"
        )
    return value


def _required_datetime(value: object, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise Phase2LedgerPersistenceError(
            f"persisted Phase 2 ledger {field_name} must be a datetime"
        )
    return as_aware_utc(value)


def _required_decimal(value: object, field_name: str) -> Decimal:
    if type(value) is not Decimal:
        raise Phase2LedgerPersistenceError(
            f"persisted Phase 2 ledger {field_name} must be an exact Decimal"
        )
    try:
        canonical = canonical_persisted_decimal(
            value,
            f"persisted Phase 2 ledger {field_name}",
        )
    except ValueError as error:
        raise Phase2LedgerPersistenceError(str(error)) from error
    # SQLite's NUMERIC affinity transports Decimal values through an IEEE-754
    # float before SQLAlchemy restores the declared ten-place scale.  Restrict
    # the shared Phase 2 ledger contract to values that survive that path
    # exactly so a fixture database and PostgreSQL cannot authenticate different
    # economics from the same canonical entry.
    try:
        sqlite_round_trip = canonical_persisted_decimal(
            Decimal(format(float(canonical), ".10f")),
            f"persisted Phase 2 ledger {field_name}",
        )
    except ValueError:
        sqlite_round_trip = None
    if sqlite_round_trip != canonical:
        raise Phase2LedgerPersistenceError(
            f"persisted Phase 2 ledger {field_name} must round-trip exactly "
            "through SQLite NUMERIC(28, 10)"
        )
    return canonical


def _entry_payload(account_id: str, entry: CanonicalLedgerEntry) -> str:
    return canonical_json_text(
        (
            PHASE2_LEDGER_PERSISTENCE_VERSION,
            LEDGER_REDUCER_CONTRACT_VERSION,
            "ledger_entry",
            account_id,
            entry.semantic_sha256,
            tuple(posting.semantic_sha256 for posting in entry.postings),
        )
    )


def immutable_phase2_ledger_entry_values(
    account_id: str,
    entry: CanonicalLedgerEntry,
) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
    """Return the exact normalized SQL rows for one canonical ledger entry."""

    account_id = _required_text(account_id, "account ID")
    if type(entry) is not CanonicalLedgerEntry:
        raise Phase2LedgerPersistenceError(
            "Phase 2 ledger persistence requires an exact CanonicalLedgerEntry"
        )
    try:
        entry.__post_init__()
    except (TypeError, ValueError) as error:
        raise Phase2LedgerPersistenceError("Phase 2 ledger entry is malformed") from error
    entry_values = {
        "entry_id": entry.entry_id,
        "account_id": account_id,
        "kind": entry.kind.value,
        "reference_id": entry.reference_id,
        "source_sha256": entry.source_sha256,
        "effective_at": entry.effective_at,
        "recorded_at": entry.recorded_at,
        "canonical_payload": _entry_payload(account_id, entry),
        "semantic_sha256": entry.semantic_sha256,
    }
    posting_values = tuple(
        {
            "entry_id": entry.entry_id,
            "line_number": line_number,
            "account": posting.account,
            "currency": posting.currency,
            "debit": _required_decimal(posting.debit, "posting debit"),
            "credit": _required_decimal(posting.credit, "posting credit"),
            "units_delta": _required_decimal(
                posting.units_delta,
                "posting units delta",
            ),
            "instrument_id": posting.instrument_id,
            "semantic_sha256": posting.semantic_sha256,
        }
        for line_number, posting in enumerate(entry.postings, start=1)
    )
    return entry_values, posting_values


def phase2_ledger_entry_from_rows(
    entry_row: LedgerRow,
    posting_rows: Sequence[LedgerRow],
) -> tuple[str, CanonicalLedgerEntry]:
    """Strictly reconstruct and authenticate one normalized ledger entry."""

    try:
        account_id = _required_text(entry_row["account_id"], "account ID")
        postings: list[CanonicalLedgerPosting] = []
        for expected_line_number, row in enumerate(posting_rows, start=1):
            _required_integer(row["posting_id"], "posting ID")
            if _required_integer(row["line_number"], "line number") != expected_line_number:
                raise Phase2LedgerPersistenceError(
                    "persisted Phase 2 ledger posting lines are not contiguous"
                )
            if _required_text(row["entry_id"], "posting entry ID") != entry_row["entry_id"]:
                raise Phase2LedgerPersistenceError(
                    "persisted Phase 2 ledger posting belongs to another entry"
                )
            posting = CanonicalLedgerPosting(
                account=_required_text(row["account"], "posting account"),
                currency=_required_text(row["currency"], "posting currency"),
                debit=_required_decimal(row["debit"], "posting debit"),
                credit=_required_decimal(row["credit"], "posting credit"),
                units_delta=_required_decimal(row["units_delta"], "posting units delta"),
                instrument_id=_optional_text(row["instrument_id"], "posting instrument ID"),
            )
            if _required_text(row["semantic_sha256"], "posting digest") != posting.semantic_sha256:
                raise Phase2LedgerPersistenceError(
                    "persisted Phase 2 ledger posting digest conflicts"
                )
            postings.append(posting)
        entry = CanonicalLedgerEntry(
            entry_id=_required_text(entry_row["entry_id"], "entry ID"),
            kind=LedgerEntryKind(_required_text(entry_row["kind"], "entry kind")),
            reference_id=_required_text(entry_row["reference_id"], "entry reference ID"),
            source_sha256=_required_text(entry_row["source_sha256"], "entry source digest"),
            effective_at=_required_datetime(entry_row["effective_at"], "entry effective_at"),
            recorded_at=_required_datetime(entry_row["recorded_at"], "entry recorded_at"),
            postings=tuple(postings),
        )
        expected_entry, expected_postings = immutable_phase2_ledger_entry_values(
            account_id,
            entry,
        )
    except Phase2LedgerPersistenceError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise Phase2LedgerPersistenceError("persisted Phase 2 ledger entry is malformed") from error
    if any(
        not same_value(entry_row[field_name], expected_value)
        for field_name, expected_value in expected_entry.items()
    ):
        raise Phase2LedgerPersistenceError(
            "persisted Phase 2 ledger entry conflicts with canonical evidence"
        )
    if len(posting_rows) != len(expected_postings) or any(
        any(
            not same_value(row[field_name], expected_value)
            for field_name, expected_value in expected.items()
        )
        for row, expected in zip(posting_rows, expected_postings, strict=True)
    ):
        raise Phase2LedgerPersistenceError(
            "persisted Phase 2 ledger postings conflict with canonical evidence"
        )
    return account_id, entry


def load_phase2_ledger_entry(
    connection: Connection,
    entry_id: str,
) -> tuple[str, CanonicalLedgerEntry] | None:
    """Load one complete canonical ledger entry and all of its postings."""

    row = (
        connection.execute(
            sa.select(phase2_ledger_entries).where(phase2_ledger_entries.c.entry_id == entry_id)
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    postings = tuple(
        connection.execute(
            sa.select(phase2_ledger_postings)
            .where(phase2_ledger_postings.c.entry_id == entry_id)
            .order_by(phase2_ledger_postings.c.line_number)
        ).mappings()
    )
    return phase2_ledger_entry_from_rows(row, postings)


def _insert_or_verify_posting(
    connection: Connection,
    values: Mapping[str, Any],
) -> None:
    payload = dict(values)
    if connection.dialect.name == "postgresql":
        connection.execute(
            postgresql_insert(phase2_ledger_postings).values(**payload).on_conflict_do_nothing()
        )
    elif connection.dialect.name == "sqlite":
        connection.execute(
            sqlite_insert(phase2_ledger_postings).values(**payload).on_conflict_do_nothing()
        )
    else:
        raise Phase2LedgerPersistenceError(
            f"Phase 2 ledger does not support SQL dialect {connection.dialect.name!r}"
        )
    row = (
        connection.execute(
            sa.select(phase2_ledger_postings).where(
                phase2_ledger_postings.c.entry_id == payload["entry_id"],
                phase2_ledger_postings.c.line_number == payload["line_number"],
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise Phase2LedgerPersistenceError("Phase 2 ledger posting insert did not persist")
    try:
        assert_immutable(
            phase2_ledger_postings,
            f"{payload['entry_id']}:{payload['line_number']}",
            row,
            payload,
        )
    except ImmutableFactConflict as error:
        raise Phase2LedgerPersistenceError(str(error)) from error


def persist_phase2_ledger_entry(
    connection: Connection,
    *,
    account_id: str,
    entry: CanonicalLedgerEntry,
) -> bool:
    """Persist one canonical entry and exact postings inside a caller transaction."""

    entry_values, posting_values = immutable_phase2_ledger_entry_values(account_id, entry)
    try:
        inserted = insert_or_verify_atomic(connection, phase2_ledger_entries, entry_values)
        for values in posting_values:
            _insert_or_verify_posting(connection, values)
    except ImmutableFactConflict as error:
        raise Phase2LedgerPersistenceError(str(error)) from error
    persisted = load_phase2_ledger_entry(connection, entry.entry_id)
    if persisted != (account_id, entry):
        raise Phase2LedgerPersistenceError(
            "persisted Phase 2 ledger entry differs from canonical input"
        )
    return inserted


def verify_phase2_ledger_integrity(connection: Connection) -> None:
    """Strictly decode every Phase 2 ledger entry and reject orphan postings."""

    orphan = connection.scalar(
        sa.select(phase2_ledger_postings.c.posting_id)
        .outerjoin(
            phase2_ledger_entries,
            phase2_ledger_entries.c.entry_id == phase2_ledger_postings.c.entry_id,
        )
        .where(phase2_ledger_entries.c.entry_id.is_(None))
        .limit(1)
    )
    if orphan is not None:
        raise Phase2LedgerPersistenceError("Phase 2 ledger contains an orphan posting")
    entry_ids = tuple(connection.scalars(sa.select(phase2_ledger_entries.c.entry_id)))
    for entry_id in entry_ids:
        if load_phase2_ledger_entry(connection, entry_id) is None:
            raise Phase2LedgerPersistenceError("Phase 2 ledger entry disappeared during verify")


__all__ = [
    "PHASE2_LEDGER_PERSISTENCE_VERSION",
    "Phase2LedgerPersistenceError",
    "immutable_phase2_ledger_entry_values",
    "load_phase2_ledger_entry",
    "persist_phase2_ledger_entry",
    "phase2_ledger_entry_from_rows",
    "verify_phase2_ledger_integrity",
]
