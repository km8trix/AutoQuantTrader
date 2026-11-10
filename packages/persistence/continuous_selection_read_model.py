"""Bounded retained C/B row metadata, without replay or current authority.

Only the current compact C record and selected B assignment are decoded. Their
head, canonical bytes, scalar mirrors and account binding must agree at one SQL
snapshot. Historical requests, signatures, private checkpoint objects, control
history, leases and clocks are deliberately outside this read model.
"""

from collections.abc import Mapping
from datetime import datetime
from hashlib import sha256
from typing import Any

import sqlalchemy as sa
from sqlalchemy import Connection, Engine
from sqlalchemy.sql.elements import ColumnElement

from packages.application import personal_codec as codec
from packages.domain.continuous_persistence_contracts import (
    MAX_CONTINUOUS_COMMIT_BYTES,
    ContinuousAccountReceipt,
    ContinuousAccountRecord,
    ContinuousFenceReference,
)
from packages.domain.continuous_selection_contracts import (
    ContinuousSelectionCheckpoint,
    ContinuousSelectionSnapshot,
    RetainedContinuousSelection,
)
from packages.domain.daily_runtime_contracts import RuntimeRiskAssignment
from packages.domain.durable_journal_contracts import JournalKey, journal_identifier
from packages.persistence.database import EXPECTED_SCHEMA_REVISION, _repeatable_read_transaction
from packages.persistence.immutable import as_aware_utc

_ASSIGNMENT_BYTES = 1024 * 1024
_MESSAGE = "continuous selection metadata is unavailable or malformed"
_ASSIGNMENT_COLUMNS = (
    "account_id",
    "generation",
    "recorded_at",
    "previous_sha256",
    "semantic_sha256",
    "payload_sha256",
    "payload",
)


class ContinuousSelectionReadError(RuntimeError):
    """No partial metadata is returned from an unavailable or inconsistent read."""


def _require_metadata_schema(
    connection: Connection, columns: tuple[tuple[sa.Table, tuple[str, ...]], ...]
) -> None:
    """Check metadata compatibility in the same snapshot, without history replay.

    Only two tiny revision validity flags can cross the SQL boundary; an
    oversized, duplicate or non-text revision is never returned to Python.
    Zero-row column probes transfer four booleans, not retained record data.
    This is not the operational database readiness/integrity verification.
    """
    revisions = sa.table("alembic_version", sa.column("version_num", sa.String(32)))
    version = revisions.c.version_num
    valid = sa.and_(
        version == EXPECTED_SCHEMA_REVISION,
        sa.cast(version, sa.LargeBinary()) == EXPECTED_SCHEMA_REVISION.encode("utf-8"),
        sa.func.length(version) == len(EXPECTED_SCHEMA_REVISION),
        (
            sa.func.length(sa.cast(version, sa.LargeBinary()))
            if connection.dialect.name == "sqlite"
            else sa.func.octet_length(version)
        )
        == len(EXPECTED_SCHEMA_REVISION.encode("utf-8")),
    )
    if connection.dialect.name == "sqlite":
        valid = sa.and_(sa.func.typeof(version) == "text", valid)
    flags = tuple(
        connection.execute(
            sa.select(sa.case((valid, 1), else_=0)).select_from(revisions).limit(2)
        ).scalars()
    )
    if flags != (1,):
        raise ValueError(_MESSAGE)
    probes = (
        sa.select(*(table.c[name] for name in names)).where(sa.false()).exists()
        for table, names in columns
    )
    connection.execute(sa.select(*probes)).one()


def _bounded_row(
    connection: Connection,
    table: sa.Table,
    predicate: ColumnElement[bool],
    names: tuple[str, ...],
    *,
    payload_limit: int,
) -> Mapping[str, Any] | None:
    """Transfer tiny validity flags first, then at most one bounded row.

    SQLite does not enforce VARCHAR or integer column types. No unchecked
    locator, scalar or payload is fetched into Python, including head rows.
    PostgreSQL supplies native column types; both dialects enforce lengths here.
    """
    sqlite = connection.dialect.name == "sqlite"
    guards: list[ColumnElement[bool]] = []
    for name in names:
        column = table.c[name]
        if isinstance(column.type, sa.String):
            maximum = column.type.length
            if maximum is None:
                raise ValueError(_MESSAGE)
            valid = sa.and_(
                sa.func.length(column).between(1, maximum),
                (
                    sa.func.length(sa.cast(column, sa.LargeBinary()))
                    if sqlite
                    else sa.func.octet_length(column)
                )
                <= 4 * maximum,
            )
            if sqlite:
                valid = sa.and_(sa.func.typeof(column) == "text", valid)
        elif isinstance(column.type, sa.Integer):
            valid = column.between(1, 2**63 - 1)
            if sqlite:
                valid = sa.and_(sa.func.typeof(column) == "integer", valid)
        elif isinstance(column.type, sa.LargeBinary):
            valid = sa.func.length(column).between(1, payload_limit)
            if sqlite:
                valid = sa.and_(sa.func.typeof(column) == "blob", valid)
        elif isinstance(column.type, sa.DateTime):
            byte_length = (
                sa.func.length(sa.cast(column, sa.LargeBinary()))
                if sqlite
                else sa.func.octet_length(sa.cast(column, sa.Text()))
            )
            valid = sa.and_(column.is_not(None), byte_length.between(1, 64))
            if sqlite:
                valid = sa.and_(
                    valid,
                    sa.func.typeof(column) == "text",
                    sa.func.length(column).between(1, 64),
                )
        else:
            raise ValueError(_MESSAGE)
        guards.append(sa.or_(column.is_(None), valid) if column.nullable else valid)
    flags = tuple(
        connection.execute(
            sa.select(sa.case((sa.and_(*guards), 1), else_=0)).where(predicate).limit(2)
        ).scalars()
    )
    if not flags:
        return None
    if flags != (1,):
        raise ValueError(_MESSAGE)
    rows = tuple(
        connection.execute(
            sa.select(*(table.c[name] for name in names)).where(predicate).limit(2)
        ).mappings()
    )
    if len(rows) != 1:
        raise ValueError(_MESSAGE)
    return {name: rows[0][name] for name in names}


def _exists(connection: Connection, table: sa.Table, predicate: ColumnElement[bool]) -> bool:
    return (
        connection.execute(
            sa.select(sa.literal(1)).select_from(table).where(predicate).limit(1)
        ).first()
        is not None
    )


def _checkpoint(
    row: Mapping[str, Any], head: Mapping[str, Any]
) -> tuple[ContinuousAccountRecord, ContinuousSelectionCheckpoint]:
    payload = row["canonical_payload"]
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_CONTINUOUS_COMMIT_BYTES:
        raise ValueError(_MESSAGE)
    record = codec.decode_record(payload, ContinuousAccountRecord)
    if codec.encode_record(record) != payload:
        raise ValueError(_MESSAGE)
    commit, journal = record.commit, record.journal
    key = JournalKey(
        "coordinator",
        commit.scope.stream_id,
        commit.scope.account_id,
        "continuous-account/1",
        "synthetic",
        commit.scope.semantic_sha256,
    )
    if journal.previous_head.key_sha256 != key.semantic_sha256 or journal.record_hashes != (
        sha256(codec.encode_record(commit)).hexdigest(),
    ):
        raise ValueError(_MESSAGE)
    receipt = ContinuousAccountReceipt(
        commit,
        journal,
        datetime.fromisoformat(row["recorded_at"]),
        ContinuousFenceReference(
            row["owner_id"],
            row["lease_id"],
            row["fencing_generation"],
            row["lease_sha256"],
            row["policy_sha256"],
            datetime.fromisoformat(row["valid_until"]),
        ),
    )
    expected = {
        "account_id": commit.scope.account_id,
        "command_id": commit.transition.command_id,
        "scope_sha256": commit.scope.semantic_sha256,
        "sequence": commit.sequence,
        "commit_sha256": commit.semantic_sha256,
        "previous_commit_sha256": commit.previous_commit_sha256,
        "checkpoint_sha256": commit.transition.checkpoint_sha256,
        "journal_key_sha256": journal.previous_head.key_sha256,
        "journal_receipt_sha256": journal.semantic_sha256,
        "canonical_payload": payload,
        "recorded_at": receipt.recorded_at.isoformat(),
        "owner_id": receipt.fence_reference.owner_id,
        "lease_id": receipt.fence_reference.lease_id,
        "fencing_generation": receipt.fence_reference.fencing_generation,
        "lease_sha256": receipt.fence_reference.lease_sha256,
        "policy_sha256": receipt.fence_reference.policy_sha256,
        "valid_until": receipt.fence_reference.valid_until.isoformat(),
        "receipt_sha256": receipt.semantic_sha256,
    }
    if dict(row) != expected or dict(head) != {name: expected[name] for name in head}:
        raise ValueError(_MESSAGE)
    return record, ContinuousSelectionCheckpoint(
        commit.scope.stream_id, commit.sequence, receipt.recorded_at
    )


def _selection(
    row: Mapping[str, Any],
    head: Mapping[str, Any],
    record: ContinuousAccountRecord,
) -> RetainedContinuousSelection:
    payload = row["payload"]
    if type(payload) is not bytes or not 0 < len(payload) <= _ASSIGNMENT_BYTES:
        raise ValueError(_MESSAGE)
    assignment = codec.decode_record(payload, RuntimeRiskAssignment)
    if (
        codec.encode_record(assignment) != payload
        or sha256(payload).hexdigest() != row["payload_sha256"]
    ):
        raise ValueError(_MESSAGE)
    if (
        assignment.account_id != record.commit.scope.account_id
        or assignment.account_binding_sha256 != record.commit.scope.account_binding_sha256
        or row["account_id"] != assignment.account_id
        or type(row["generation"]) is not int
        or row["generation"] != assignment.generation
        or row["previous_sha256"] != assignment.previous_assignment_sha256
        or row["semantic_sha256"] != assignment.semantic_sha256
        or dict(head)
        != {
            "account_id": assignment.account_id,
            "generation": assignment.generation,
            "semantic_sha256": assignment.semantic_sha256,
        }
        or type(row["recorded_at"]) is not datetime
    ):
        raise ValueError(_MESSAGE)
    return RetainedContinuousSelection(
        assignment.generation,
        assignment.strategy.name,
        assignment.strategy.version,
        assignment.configuration_sha256,
        assignment.instrument_symbols,
        assignment.policy.policy_id,
        assignment.enabled_for_new_exposure,
        assignment.live_authorized,
        as_aware_utc(row["recorded_at"]),
        assignment.effective_at,
    )


class SqlContinuousSelectionReadModel:
    """Read at most two heads and their selected rows; never write a watermark.

    Existence probes detect orphan history and hidden tails without scanning or
    authenticating histories. The selected assignment's command/request payload
    is not fetched: row integrity is not evidence of authenticated permission.
    """

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def read(self, account_id: str) -> ContinuousSelectionSnapshot:
        try:
            journal_identifier(account_id)
            if self.engine.dialect.name not in ("sqlite", "postgresql"):
                raise ValueError(_MESSAGE)
            # Importing the API must not register a partial W4 schema before
            # phase-zero ephemeral startup. This query checks its metadata
            # schema inside its own read-only SQL snapshot.
            from packages.persistence.continuous_account_schema import (
                continuous_account_commits as commits,
            )
            from packages.persistence.continuous_account_schema import (
                continuous_account_heads as heads,
            )
            from packages.persistence.daily_runtime_risk_schema import (
                daily_runtime_assignment_heads as assignment_heads,
            )
            from packages.persistence.daily_runtime_risk_schema import (
                daily_runtime_assignments as assignments,
            )

            with _repeatable_read_transaction(self.engine) as connection:
                _require_metadata_schema(
                    connection,
                    (
                        (heads, tuple(heads.c.keys())),
                        (commits, tuple(commits.c.keys())),
                        (assignment_heads, tuple(assignment_heads.c.keys())),
                        (assignments, _ASSIGNMENT_COLUMNS),
                    ),
                )
                c_head = _bounded_row(
                    connection,
                    heads,
                    heads.c.account_id == account_id,
                    tuple(heads.c.keys()),
                    payload_limit=MAX_CONTINUOUS_COMMIT_BYTES,
                )
                b_head = _bounded_row(
                    connection,
                    assignment_heads,
                    assignment_heads.c.account_id == account_id,
                    tuple(assignment_heads.c.keys()),
                    payload_limit=_ASSIGNMENT_BYTES,
                )
                if c_head is None:
                    if (
                        b_head is not None
                        or _exists(connection, commits, commits.c.account_id == account_id)
                        or _exists(connection, assignments, assignments.c.account_id == account_id)
                    ):
                        raise ValueError(_MESSAGE)
                    return ContinuousSelectionSnapshot(account_id, "absent", None, None)
                c_row = _bounded_row(
                    connection,
                    commits,
                    sa.and_(
                        commits.c.account_id == account_id,
                        commits.c.command_id == c_head["command_id"],
                    ),
                    tuple(commits.c.keys()),
                    payload_limit=MAX_CONTINUOUS_COMMIT_BYTES,
                )
                if c_row is None or _exists(
                    connection,
                    commits,
                    sa.and_(
                        commits.c.account_id == account_id, commits.c.sequence > c_head["sequence"]
                    ),
                ):
                    raise ValueError(_MESSAGE)
                record, checkpoint = _checkpoint(c_row, c_head)
                if record.commit.scope.account_id != account_id:
                    raise ValueError(_MESSAGE)
                if b_head is None:
                    if _exists(connection, assignments, assignments.c.account_id == account_id):
                        raise ValueError(_MESSAGE)
                    return ContinuousSelectionSnapshot(account_id, "unselected", checkpoint, None)
                b_row = _bounded_row(
                    connection,
                    assignments,
                    sa.and_(
                        assignments.c.account_id == account_id,
                        assignments.c.generation == b_head["generation"],
                    ),
                    _ASSIGNMENT_COLUMNS,
                    payload_limit=_ASSIGNMENT_BYTES,
                )
                if b_row is None or _exists(
                    connection,
                    assignments,
                    sa.and_(
                        assignments.c.account_id == account_id,
                        assignments.c.generation > b_head["generation"],
                    ),
                ):
                    raise ValueError(_MESSAGE)
                return ContinuousSelectionSnapshot(
                    account_id, "selected", checkpoint, _selection(b_row, b_head, record)
                )
        except Exception:
            raise ContinuousSelectionReadError(_MESSAGE) from None
